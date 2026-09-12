//! Process-lifetime identities shared by every filesystem implementation.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::types::FsError;

static NEXT_FS_ID: AtomicU64 = AtomicU64::new(1);
// Ext2 page-cache keys pack fs_id and its 32-bit inode number into one u64.
// Reserve 2^32 as a permanent exhaustion sentinel rather than losing high bits.
const MAX_FS_ID: u64 = u32::MAX as u64;

/// Never reuse an ID, even when a constructor subsequently fails. Delayed inode
/// and capability references must not alias a newly mounted filesystem.
pub(crate) fn allocate_fs_id() -> Result<u64, FsError> {
    allocate_from(&NEXT_FS_ID)
}

fn allocate_from(next: &AtomicU64) -> Result<u64, FsError> {
    // KSA-007: one atomic sequence for all filesystem types. Publication of the
    // filesystem itself uses its Arc/locks; this atomic only establishes uniqueness.
    next.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
        (id <= MAX_FS_ID).then(|| id + 1)
    })
    .map_err(|_| FsError::NoSpace)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn exhaustion_never_wraps_or_reuses_identity() {
        let next = AtomicU64::new(MAX_FS_ID);
        assert_eq!(allocate_from(&next), Ok(MAX_FS_ID));
        assert_eq!(allocate_from(&next), Err(FsError::NoSpace));
        assert_eq!(allocate_from(&next), Err(FsError::NoSpace));
        assert_eq!(next.load(Ordering::Relaxed), MAX_FS_ID + 1);
    }

    #[test]
    fn concurrent_allocations_never_alias() {
        let next = AtomicU64::new(1);
        std::thread::scope(|scope| {
            let workers: alloc::vec::Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        (0..256)
                            .map(|_| allocate_from(&next).unwrap())
                            .collect::<alloc::vec::Vec<_>>()
                    })
                })
                .collect();
            let mut ids: alloc::vec::Vec<_> = workers
                .into_iter()
                .flat_map(|worker| worker.join().unwrap())
                .collect();
            ids.sort_unstable();
            assert_eq!(ids, (1..=1024).collect::<alloc::vec::Vec<_>>());
        });
    }

    #[test]
    fn mixed_ramfs_ext2_mutation_routes_to_owner() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        crate::ext2::run_ext2_create_self_test();
    }

    #[test]
    fn mixed_filesystem_instances_have_distinct_identities() {
        use crate::traits::FileSystem;
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let ram = crate::ramfs::RamFs::try_new().unwrap();
        let proc = crate::procfs::ProcFs::try_new().unwrap();
        let dev = crate::devfs::DevFs::new();
        let cgroup = crate::cgroupfs::CgroupFs::new();
        let initramfs = crate::initramfs::Initramfs::from_cpio(&[]).unwrap();
        let before_failure = NEXT_FS_ID.load(Ordering::Relaxed);
        assert!(crate::initramfs::Initramfs::from_cpio(&[0; 110]).is_err());
        assert_eq!(NEXT_FS_ID.load(Ordering::Relaxed), before_failure + 1);
        let second_ram = crate::ramfs::RamFs::try_new().unwrap();
        assert_eq!(
            second_ram.fs_id(),
            before_failure + 1,
            "failed construction must burn its ID"
        );
        let ids = [
            ram.fs_id(),
            proc.fs_id(),
            dev.fs_id(),
            cgroup.fs_id(),
            initramfs.fs_id(),
            second_ram.fs_id(),
        ];
        for (index, id) in ids.iter().enumerate() {
            assert!(*id != 0);
            assert!(!ids[..index].contains(id));
        }
        assert_eq!(ram.root_inode().fs_id(), ram.fs_id());
        assert_eq!(proc.root_inode().fs_id(), proc.fs_id());
        assert_eq!(dev.root_inode().fs_id(), dev.fs_id());
        assert_eq!(cgroup.root_inode().fs_id(), cgroup.fs_id());
        assert_eq!(initramfs.root_inode().fs_id(), initramfs.fs_id());
    }
}
