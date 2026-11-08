//! ST-K2-P2 guest-only race oracles (`syscall_test` builds).
//!
//! (b) Cross-CPU page-table holder: munmap pauses in Phase 2, holding PT_LOCK
//! with IF=0 just before its range shootdown, until a CLONE_VM sibling on
//! another CPU has taken a Busy shared fault on a cold page from an IF=0
//! usercopy. The sibling cannot take the shootdown IPI, so the holder's wait
//! completes only through the mailbox drain of the sibling's #PF Busy arm,
//! which `mm::tlb_shootdown` counts.
//!
//! (c) Exact memory baselines: the page tables `allocate_kernel_stack` builds
//! for a fresh kernel-stack slot stay linked after the stack is freed (a
//! recycled PID reuses them), so buddy free pages fall by exactly that count
//! as new PIDs reach new 2 MiB slots. The count lets a guest compare buddy free
//! pages with zero tolerance.
//!
//! (d) Private rollback reclamation: the next private population of exactly
//! N pages in the arming address space fails at its last data frame, as the
//! boot-armed R192-RES-2 probe does, but re-armable and below that probe's
//! report size. Optionally it first pauses, with no lock held and IF=1, so a
//! sibling can unmap a neighbouring shared page while the population still
//! has leaves in the shared fault's page table.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

pub const PR_SHARED_FAULT_TEST: i32 = 0x5a53_4654;

const IDLE: usize = 0;
const CONFIGURING: usize = 1;
const ARMED: usize = 2;
const PAUSED: usize = 3;
const RELEASED: usize = 4;
const COMPLETE: usize = 5;
const FAILED: usize = 6;
static STATE: AtomicUsize = AtomicUsize::new(IDLE);
static OWNER: AtomicUsize = AtomicUsize::new(0);
static ROOT: AtomicUsize = AtomicUsize::new(0);
static UNMAP_BASE: AtomicUsize = AtomicUsize::new(0);
static COLD_PAGE: AtomicUsize = AtomicUsize::new(0);
static BUSY_HITS: AtomicU64 = AtomicU64::new(0);
static ACK_BASE: AtomicU64 = AtomicU64::new(0);
static KERNEL_STACK_TABLES: AtomicU64 = AtomicU64::new(0);

const POP_IDLE: usize = 0;
const POP_ARMED: usize = 1;
const POP_FIRED: usize = 2;
const POP_PAUSED: usize = 3;
const POP_RELEASED: usize = 4;
const POP_DONE: usize = 5;
const POP_TIMEOUT: usize = 6;
/// Largest armable population: well below `POPULATE_REPORT_PAGES`, so these
/// failures never print an R192-RES-2 marker.
const POP_MAX_PAGES: u64 = 4096;
static POP_STATE: AtomicUsize = AtomicUsize::new(POP_IDLE);
static POP_OWNER: AtomicUsize = AtomicUsize::new(0);
static POP_ROOT: AtomicUsize = AtomicUsize::new(0);
static POP_PAGES: AtomicUsize = AtomicUsize::new(0);
static POP_PAUSE: AtomicBool = AtomicBool::new(false);

/// Bound on any pause, as in `cow_test`: a regressed kernel or a dead sibling
/// must end in a failing verdict, never an unbounded wait under a lock.
const PAUSE_TSC: u64 = 10_000_000_000;

fn user_page(addr: u64) -> bool {
    (0x10000..0x0000_8000_0000_0000).contains(&addr) && addr & 0xfff == 0
}

fn active_root() -> usize {
    x86_64::registers::control::Cr3::read()
        .0
        .start_address()
        .as_u64() as usize
}

/// prctl operations: 0 = online CPU mask; 1 = arm(unmap base, cold shared
/// page); 2 = state; 3 = ACKs delivered by #PF mailbox drains since arming;
/// 4 = Busy faults counted on the cold page; 5 = disarm; 6 = kernel-stack page
/// tables built since boot; 7 = arm a population failure(pages, pause);
/// 8 = population probe state; 9 = release a paused population; 17 = current CPU.
/// Operations 10..=16 belong to shared_release_test.
pub fn command(op: u64, a: u64, b: u64, pid: usize, root: usize) -> Result<u64, ()> {
    match op {
        0 => Ok(cpu_local::online_cpu_mask()),
        17 => Ok(cpu_local::current_cpu_id() as u64),
        6 => Ok(KERNEL_STACK_TABLES.load(Ordering::Acquire)),
        7 => {
            if root == 0 || a == 0 || a > POP_MAX_PAGES || b > 1 {
                return Err(());
            }
            let state = POP_STATE.load(Ordering::Acquire);
            if !matches!(state, POP_IDLE | POP_DONE | POP_TIMEOUT) {
                return Err(());
            }
            POP_STATE
                .compare_exchange(state, POP_FIRED, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| ())?;
            POP_OWNER.store(pid, Ordering::Relaxed);
            POP_ROOT.store(root, Ordering::Relaxed);
            POP_PAGES.store(a as usize, Ordering::Relaxed);
            POP_PAUSE.store(b == 1, Ordering::Relaxed);
            POP_STATE.store(POP_ARMED, Ordering::Release);
            Ok(0)
        }
        8 | 9 if POP_ROOT.load(Ordering::Relaxed) == root => {
            if op == 8 {
                return Ok(POP_STATE.load(Ordering::Acquire) as u64);
            }
            POP_STATE
                .compare_exchange(
                    POP_PAUSED,
                    POP_RELEASED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map(|_| 0)
                .map_err(|_| ())
        }
        1 => {
            if root == 0 || !user_page(a) || !user_page(b) || a == b {
                return Err(());
            }
            STATE
                .compare_exchange(IDLE, CONFIGURING, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| ())?;
            OWNER.store(pid, Ordering::Relaxed);
            ROOT.store(root, Ordering::Relaxed);
            UNMAP_BASE.store(a as usize, Ordering::Relaxed);
            COLD_PAGE.store(b as usize, Ordering::Relaxed);
            BUSY_HITS.store(0, Ordering::Relaxed);
            ACK_BASE.store(
                mm::tlb_shootdown::acks_from_fault_drain(),
                Ordering::Relaxed,
            );
            STATE.store(ARMED, Ordering::Release);
            Ok(0)
        }
        2..=5 => {
            let state = STATE.load(Ordering::Acquire);
            if state <= CONFIGURING || ROOT.load(Ordering::Relaxed) != root {
                return Err(());
            }
            match op {
                2 => Ok(state as u64),
                3 => Ok(mm::tlb_shootdown::acks_from_fault_drain()
                    .saturating_sub(ACK_BASE.load(Ordering::Relaxed))),
                4 => Ok(BUSY_HITS.load(Ordering::Acquire)),
                _ if OWNER.load(Ordering::Relaxed) == pid => {
                    clear(pid);
                    Ok(0)
                }
                _ => Err(()),
            }
        }
        _ => Err(()),
    }
}

/// munmap Phase 2, under PT_LOCK with IF=0, before the range shootdown.
pub fn before_unmap_flush(pid: usize, base: usize) {
    if STATE.load(Ordering::Acquire) != ARMED
        || OWNER.load(Ordering::Relaxed) != pid
        || UNMAP_BASE.load(Ordering::Relaxed) != base
        || ROOT.load(Ordering::Relaxed) != active_root()
    {
        return;
    }
    STATE.store(PAUSED, Ordering::Release);
    let start = crate::time::read_tsc();
    while BUSY_HITS.load(Ordering::Acquire) == 0 {
        if crate::time::read_tsc().wrapping_sub(start) >= PAUSE_TSC {
            STATE.store(FAILED, Ordering::Release);
            return;
        }
        core::hint::spin_loop();
    }
    STATE.store(RELEASED, Ordering::Release);
}

/// munmap Phase 2, after the range shootdown returned.
pub fn after_unmap_flush(pid: usize, base: usize) {
    if OWNER.load(Ordering::Relaxed) == pid && UNMAP_BASE.load(Ordering::Relaxed) == base {
        let _ = STATE.compare_exchange(RELEASED, COMPLETE, Ordering::AcqRel, Ordering::Acquire);
    }
}

/// #PF shared Busy arm: count a Busy on the armed cold page while another CPU
/// holds PT_LOCK, which is what releases the paused munmap.
pub fn note_busy(fault_addr: usize) {
    if STATE.load(Ordering::Acquire) != PAUSED
        || fault_addr & !0xfff != COLD_PAGE.load(Ordering::Relaxed)
        || ROOT.load(Ordering::Relaxed) != active_root()
    {
        return;
    }
    match mm::pt_lock_owner_cpu() {
        Some(owner) if owner != cpu_local::current_cpu_id() => {
            // lint-fetch-add: allow (test-only counter; a u64 cannot wrap here)
            BUSY_HITS.fetch_add(1, Ordering::AcqRel);
        }
        _ => {}
    }
}

/// `EagerPopulator::new`: whether this population of `pages` pages is the armed
/// one, in the arming address space. Consumes the arming.
pub fn take_population_failure(pages: usize) -> bool {
    POP_STATE.load(Ordering::Acquire) == POP_ARMED
        && POP_PAGES.load(Ordering::Relaxed) == pages
        && POP_ROOT.load(Ordering::Relaxed) == active_root()
        && POP_STATE
            .compare_exchange(POP_ARMED, POP_FIRED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
}

/// The armed population's failing data-frame allocation, with no lock held:
/// pause first if asked, until a sibling releases it (or the bound passes).
pub fn before_population_failure() {
    if POP_STATE.load(Ordering::Acquire) != POP_FIRED {
        return;
    }
    if !POP_PAUSE.load(Ordering::Relaxed) {
        POP_STATE.store(POP_DONE, Ordering::Release);
        return;
    }
    POP_STATE.store(POP_PAUSED, Ordering::Release);
    let start = crate::time::read_tsc();
    while POP_STATE.load(Ordering::Acquire) == POP_PAUSED {
        if crate::time::read_tsc().wrapping_sub(start) >= PAUSE_TSC {
            let _ = POP_STATE.compare_exchange(
                POP_PAUSED,
                POP_TIMEOUT,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return;
        }
        core::hint::spin_loop();
    }
    POP_STATE.store(POP_DONE, Ordering::Release);
}

/// `allocate_kernel_stack` linked `tables` new page tables for a stack slot.
pub fn note_kernel_stack_tables(tables: usize) {
    if tables != 0 {
        KERNEL_STACK_TABLES.fetch_add(tables as u64, Ordering::AcqRel);
    }
}

/// Called by the teardown winner before its PID can be recycled.
pub fn clear(pid: usize) {
    if OWNER.load(Ordering::Acquire) == pid {
        OWNER.store(0, Ordering::Relaxed);
        STATE.store(IDLE, Ordering::Release);
    }
    if POP_OWNER.load(Ordering::Acquire) == pid {
        POP_OWNER.store(0, Ordering::Relaxed);
        POP_STATE.store(POP_IDLE, Ordering::Release);
    }
}
