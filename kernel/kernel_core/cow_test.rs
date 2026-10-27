//! LEAD-G8-CHILDREN-SEGV-1 guest-only oracle. Pause after copying a shared
//! COW frame, before replacing its leaf, while a sibling performs a cold read.

use core::sync::atomic::{AtomicUsize, Ordering};

pub const PR_COW_TEST: i32 = 0x5a43_4f57;
const IDLE: usize = 0;
const CONFIGURING: usize = 1;
const ARMED: usize = 2;
const PAUSED: usize = 3;
const OBSERVED: usize = 4;
const COMPLETE: usize = 5;
const FAILED: usize = 6;
static STATE: AtomicUsize = AtomicUsize::new(IDLE);
static OWNER: AtomicUsize = AtomicUsize::new(0);
static ROOT: AtomicUsize = AtomicUsize::new(0);
static PAGE: AtomicUsize = AtomicUsize::new(0);

/// prctl operations: 0=online mask, 1=arm(page), 2=poll + local TLB flush,
/// 3=acknowledge the successful user read, 4=result, 5=disarm.
pub fn command(op: u64, addr: u64, pid: usize, root: usize) -> Result<u64, ()> {
    if op == 0 {
        return Ok(cpu_local::online_cpu_mask());
    }
    if op == 1 {
        if root == 0 || addr < 0x10000 || addr >= 0x0000_8000_0000_0000 || addr & 0xfff != 0 {
            return Err(());
        }
        STATE
            .compare_exchange(IDLE, CONFIGURING, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ())?;
        OWNER.store(pid, Ordering::Relaxed);
        ROOT.store(root, Ordering::Relaxed);
        PAGE.store(addr as usize, Ordering::Relaxed);
        STATE.store(ARMED, Ordering::Release);
        return Ok(0);
    }
    let state = STATE.load(Ordering::Acquire);
    if state <= CONFIGURING || ROOT.load(Ordering::Relaxed) != root {
        return Err(());
    }
    match op {
        2 if OWNER.load(Ordering::Relaxed) != pid => {
            if state == PAUSED {
                // No PT lock or remote shootdown: the writer holds PT_LOCK
                // with IRQs masked. Force this CPU's next user load to walk
                // the leaf at precisely the paused point. Flush all local
                // PCIDs too: syscall entry may use a different KPTI root.
                mm::tlb_shootdown::flush_all_local();
            }
            Ok(state as u64)
        }
        3 if OWNER.load(Ordering::Relaxed) != pid => {
            STATE
                .compare_exchange(PAUSED, OBSERVED, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| ())?;
            Ok(0)
        }
        4 => Ok(state as u64),
        5 if OWNER.load(Ordering::Relaxed) == pid => {
            clear(pid);
            Ok(0)
        }
        _ => Err(()),
    }
}

pub fn before_replace(pid: usize, page: usize) {
    if STATE.load(Ordering::Acquire) != ARMED
        || OWNER.load(Ordering::Relaxed) != pid
        || PAGE.load(Ordering::Relaxed) != page
    {
        return;
    }
    STATE.store(PAUSED, Ordering::Release);
    let start = crate::time::read_tsc();
    // No unbounded wait with PT_LOCK/IRQs held, including if the reader dies
    // on a deliberately regressed kernel. Timeout is a failing guest verdict.
    while STATE.load(Ordering::Acquire) == PAUSED {
        if crate::time::read_tsc().wrapping_sub(start) >= 10_000_000_000 {
            break;
        }
        core::hint::spin_loop();
    }
    let observed = STATE.load(Ordering::Acquire) == OBSERVED;
    STATE.store(if observed { COMPLETE } else { FAILED }, Ordering::Release);
}

/// Called by the teardown winner before its PID can be recycled.
pub fn clear(pid: usize) {
    if OWNER.load(Ordering::Acquire) == pid {
        OWNER.store(0, Ordering::Relaxed);
        STATE.store(IDLE, Ordering::Release);
    }
}
