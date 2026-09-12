//! Default-off, per-open failure selection for the KSA-004 Ring-3 fixture.

use super::*;
use kernel_core::syscall::OpenFaultProbe;

pub(super) fn select(path: &str, flags: OpenFlags) -> OpenFaultProbe {
    if !flags.is_truncate() || !flags.is_writable() {
        return OpenFaultProbe::None;
    }
    match path {
        "/ksa-open-allocation" => OpenFaultProbe::DescriptorAllocation,
        "/ksa-open-capability" => OpenFaultProbe::CapabilityAllocation,
        "/ksa-open-lsm" => OpenFaultProbe::LsmDenial,
        "/ksa-open-credential" => OpenFaultProbe::StaleCredentials,
        "/ksa-open-success" => OpenFaultProbe::Success,
        _ => OpenFaultProbe::None,
    }
}

fn resources() -> (usize, usize) {
    let snapshot = mm::heap_class_snapshot(mm::HeapClass::Vfs);
    (snapshot.committed_bytes, snapshot.reserved_bytes)
}

pub(super) fn prepare(probe: OpenFaultProbe) -> Result<PreparedFileHandle, FsError> {
    if probe != OpenFaultProbe::DescriptorAllocation {
        return PreparedFileHandle::try_new();
    }
    let baseline = resources();
    let limit = mm::HeapClass::Vfs.limit_bytes();
    let headroom = limit.checked_sub(baseline.0 + baseline.1).unwrap();
    let pressure = mm::try_reserve_heap(mm::HeapClass::Vfs, headroom)
        .expect("VFS probe must reserve remaining class budget");
    assert_eq!(resources(), (baseline.0, baseline.1 + headroom));
    assert_eq!(resources().0 + resources().1, limit);
    // Execute the production allocator/admission path while this class is full.
    assert_eq!(PreparedFileHandle::try_new().err(), Some(FsError::NoMem));
    assert_eq!(resources(), (baseline.0, baseline.1 + headroom));
    drop(pressure);
    assert_eq!(resources(), baseline);
    klog::klog_always!("KSA-004-INJECT stage=descriptor errno=12 heap=restored");
    Err(FsError::NoMem)
}

pub(super) fn finalizer(
    probe: OpenFaultProbe,
) -> fn(&dyn kernel_core::process::FileOps) -> Result<(), SyscallError> {
    match probe {
        OpenFaultProbe::LsmDenial => finish_denied,
        OpenFaultProbe::Success => finish_success,
        _ => finish_syscall_open,
    }
}

fn deny_truncate(_: &LsmProcessCtx, _: u64, _: u64) -> lsm::LsmResult {
    klog::klog_always!("KSA-004-INJECT stage=lsm errno=13 cap_reserved=1");
    Err(lsm::LsmError::Denied)
}

fn finish_denied(descriptor: &dyn kernel_core::process::FileOps) -> Result<(), SyscallError> {
    assert!(
        descriptor.cap_id().is_some(),
        "LSM probe must follow cap reservation"
    );
    finish_open_using(descriptor, deny_truncate)
        .map(|_| ())
        .map_err(fs_error_to_syscall)
}

fn finish_success(descriptor: &dyn kernel_core::process::FileOps) -> Result<(), SyscallError> {
    assert!(descriptor.cap_id().is_some());
    let truncated =
        finish_open_using(descriptor, lsm::hook_file_truncate).map_err(fs_error_to_syscall)?;
    assert!(
        truncated,
        "positive probe must reach the actual inode truncate"
    );
    klog::klog_always!("KSA-004-TRUNCATE DONE");
    Ok(())
}
