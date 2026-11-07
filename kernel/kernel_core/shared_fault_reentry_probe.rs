//! ST-K2-P2(a) probe image: take a fresh shared-anonymous fault while this CPU
//! holds a lock the fault path try-locks.
//!
//! A repaired kernel stops with `same-CPU <lock> reentry during shared fault`;
//! a regressed one returns `Busy` forever and the guest spins until the gate's
//! timeout. Built only into the dedicated `shared_fault_reentry_probe` image.

use crate::process::{current_pid, get_process, PROCESS_TABLE};
use crate::syscall::SyscallError;
use crate::usercopy::{fault_in_user_page, UserAddr};
use alloc::sync::Arc;

pub const PR_SHARED_FAULT_REENTRY_PROBE: i32 = 0x5a53_4652;

/// prctl(PR_SHARED_FAULT_REENTRY_PROBE, lock, page): 0 holds `PROCESS_TABLE`,
/// 1 the caller's PCB, 2 its `MmState`. `page` is an untouched page of a
/// `MAP_SHARED|MAP_ANONYMOUS` mapping.
pub fn run(lock: u64, page: u64) -> Result<usize, SyscallError> {
    if page < 0x10000 || page >= 0x0000_8000_0000_0000 || page & 0xfff != 0 {
        return Err(SyscallError::EINVAL);
    }
    let page = UserAddr::new(page as usize);
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
    match lock {
        0 => {
            let _held = PROCESS_TABLE.lock();
            fault_while_holding("PROCESS_TABLE", page)
        }
        1 => {
            let _held = process.lock();
            fault_while_holding("PCB", page)
        }
        2 => {
            let mm = Arc::clone(&process.lock().mm);
            let _held = mm.lock();
            fault_while_holding("MmState", page)
        }
        _ => Err(SyscallError::EINVAL),
    }
}

fn fault_while_holding(lock: &str, page: UserAddr) -> Result<usize, SyscallError> {
    klog_always!("ST-K2-REENTRY-PROBE HOLD lock={}", lock);
    let resolved = fault_in_user_page(page, false).is_ok();
    // Unreachable on a repaired kernel: the fault fail-stops first.
    klog_always!(
        "ST-K2-REENTRY-PROBE RETURNED lock={} resolved={}",
        lock,
        resolved
    );
    Ok(0)
}
