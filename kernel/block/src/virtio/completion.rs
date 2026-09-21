//! Request completion owns payloads; no caller address survives in-flight I/O.

use super::{blk_status, BlockError};

pub(super) enum RequestKind<B> {
    Read { data_dma: B, data_len: usize },
    Write { data_dma: B, data_len: usize },
    Flush,
}

pub(super) enum CompletedIo<B> {
    Read { data_dma: B, data_len: usize },
    Write(usize),
}

pub(super) enum RequestCompletion<B> {
    Io(Result<CompletedIo<B>, BlockError>),
    Flush(Result<(), BlockError>),
}

fn status_result(status: u8) -> Result<(), BlockError> {
    match status {
        blk_status::VIRTIO_BLK_S_OK => Ok(()),
        blk_status::VIRTIO_BLK_S_UNSUPP => {
            // R189-1: a device-side rejection must be attributable in release
            // serial logs; `kprintln!` diagnostics are compiled out there.
            klog!(Error, "[virtio-blk] device rejected request status=UNSUPP");
            Err(BlockError::NotSupported)
        }
        _ => {
            klog!(
                Error,
                "[virtio-blk] device reported request failure status={}",
                status
            );
            Err(BlockError::Io)
        }
    }
}

/// Used only after the device has completed this descriptor chain. Abandoned
/// requests are reclaimed without producing caller-visible data or completion.
pub(super) fn finish_request<B>(
    kind: RequestKind<B>,
    status: u8,
    abandoned: bool,
) -> Option<RequestCompletion<B>> {
    if abandoned {
        return None;
    }
    Some(match kind {
        RequestKind::Read { data_dma, data_len } => RequestCompletion::Io(
            status_result(status).map(|()| CompletedIo::Read { data_dma, data_len }),
        ),
        RequestKind::Write { data_dma, data_len } => {
            drop(data_dma);
            RequestCompletion::Io(status_result(status).map(|()| CompletedIo::Write(data_len)))
        }
        RequestKind::Flush => RequestCompletion::Flush(status_result(status)),
    })
}

/// Copy only from owned completed storage into a currently borrowed destination.
pub(super) fn copy_read_result(destination: &mut [u8], data: &[u8]) -> Result<usize, BlockError> {
    if destination.len() != data.len() {
        return Err(BlockError::Io);
    }
    destination.copy_from_slice(data);
    Ok(data.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{sync::Arc, vec, vec::Vec};
    use core::sync::atomic::{AtomicUsize, Ordering};

    struct OwnedPayload {
        bytes: Vec<u8>,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for OwnedPayload {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn delayed_abandoned_completion_reclaims_without_returning_data() {
        let drops = Arc::new(AtomicUsize::new(0));
        let pending = RequestKind::Read {
            data_dma: OwnedPayload {
                bytes: vec![7; 512],
                drops: drops.clone(),
            },
            data_len: 512,
        };
        // The earlier caller's buffer is gone; metadata has no address for it.
        let reused_destination = [0xa5; 512];
        assert!(finish_request(pending, blk_status::VIRTIO_BLK_S_OK, true).is_none());
        assert_eq!(reused_destination, [0xa5; 512]);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_read_reclaims_payload_without_copying_to_caller() {
        for status in [
            blk_status::VIRTIO_BLK_S_IOERR,
            blk_status::VIRTIO_BLK_S_UNSUPP,
            0xff,
        ] {
            let drops = Arc::new(AtomicUsize::new(0));
            let kind = RequestKind::Read {
                data_dma: OwnedPayload {
                    bytes: vec![7; 512],
                    drops: drops.clone(),
                },
                data_len: 512,
            };
            assert!(matches!(
                finish_request(kind, status, false),
                Some(RequestCompletion::Io(Err(_)))
            ));
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn successful_read_transfers_ownership_through_live_destination() {
        let drops = Arc::new(AtomicUsize::new(0));
        let kind = RequestKind::Read {
            data_dma: OwnedPayload {
                bytes: vec![7; 512],
                drops: drops.clone(),
            },
            data_len: 512,
        };
        let Some(RequestCompletion::Io(Ok(CompletedIo::Read { data_dma, data_len }))) =
            finish_request(kind, blk_status::VIRTIO_BLK_S_OK, false)
        else {
            panic!("successful read lost its owner")
        };
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let mut wrong_length = [0xa5; 511];
        assert_eq!(
            copy_read_result(&mut wrong_length, &data_dma.bytes[..data_len]),
            Err(BlockError::Io)
        );
        assert_eq!(wrong_length, [0xa5; 511]);
        let mut destination = [0xa5; 512];
        assert_eq!(
            copy_read_result(&mut destination, &data_dma.bytes[..data_len]),
            Ok(512)
        );
        assert_eq!(destination, [7; 512]);
        drop(data_dma);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}
