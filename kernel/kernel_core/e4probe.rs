//! C3 E4 (#90) DIAGNOSTIC, not for merge: what do the LAPIC-ID CPU lookup and
//! the polling blocked wait cost?
//!
//! One kernel, several behaviours. From the first `/proc/schedstat` read on,
//! the kernel changes its mode every [`MODE_WINDOW_TICKS`], in a fixed cycle
//! ([`MODE_CYCLE`]), so the modes are compared within one boot:
//!
//! - `0` base: as merged. `cpu_local::current_cpu_id()` reads the LAPIC ID
//!   register through MMIO, and a blocked waiter whose CPU has nothing else to
//!   run polls (`WaitQueue::block_until_resolved`).
//! - `1` fast_id: the lookup reads IA32_TSC_AUX, which each CPU sets to its
//!   logical id plus one in `init_syscall_percpu`.
//! - `2` halt: such a blocked waiter halts until the next interrupt.
//! - `3` fast_id_halt: both.
//! - `4` try_locks: the work-stealing scan (`Scheduler::steal_one`,
//!   `steal_from`) skips a ready queue whose lock is held instead of waiting
//!   for it, and `SocketTable::drain_deferred_port_uncharges` skips a pass
//!   when one of its two locks is held.
//! - `5` fast_id_try_locks, `7` fast_id_halt_try_locks: the combinations.
//!
//! The first task exit in a new window switches the mode and prints
//! `E4_MODE <mode> <window> lookups=<per mode> polls=<per mode>` with the
//! cumulative CPU lookups and blocked-wait passes of each of the eight modes.

use core::sync::atomic::{AtomicU64, Ordering};
use cpu_local::e4;

const MODE_WINDOW_TICKS: u64 = 10_000;
/// The modes this branch cycles through.
const MODE_CYCLE: [usize; 5] = [
    e4::BASE,
    e4::FAST_ID,
    e4::TRY_LOCKS,
    e4::FAST_ID | e4::TRY_LOCKS,
    e4::FAST_ID | e4::HALT | e4::TRY_LOCKS,
];

/// The tick of the first `/proc/schedstat` read; 0 until then (base mode).
static MODE_BASE_TICK: AtomicU64 = AtomicU64::new(0);
/// The last window entered, plus one (0: none yet).
static ENTERED_WINDOW: AtomicU64 = AtomicU64::new(0);
/// Passes of the blocked-wait loop that found the task still blocked, by mode.
static BLOCKED_POLLS: [AtomicU64; e4::MODES] = [const { AtomicU64::new(0) }; e4::MODES];

/// Start the mode cycle. Called on every `/proc/schedstat` read; the first counts.
pub fn arm() {
    let _ = MODE_BASE_TICK.compare_exchange(
        0,
        crate::get_ticks().max(1),
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
}

fn window(now_tick: u64) -> Option<u64> {
    match MODE_BASE_TICK.load(Ordering::Relaxed) {
        0 => None,
        base => Some(now_tick.saturating_sub(base) / MODE_WINDOW_TICKS),
    }
}

/// Process context, console allowed: enter a new window once.
pub fn poll() {
    let Some(window) = window(crate::get_ticks()) else {
        return;
    };
    if ENTERED_WINDOW.load(Ordering::Relaxed) == window + 1
        || ENTERED_WINDOW.swap(window + 1, Ordering::Relaxed) == window + 1
    {
        return;
    }
    let mode = MODE_CYCLE[(window % MODE_CYCLE.len() as u64) as usize];
    e4::set_mode(mode);
    let polls = |mode: usize| BLOCKED_POLLS[mode].load(Ordering::Relaxed);
    klog::klog_force!(
        "E4_MODE {} {} lookups={}/{}/{}/{}/{}/{}/{}/{} polls={}/{}/{}/{}/{}/{}/{}/{}",
        mode,
        window,
        e4::lookups(0),
        e4::lookups(1),
        e4::lookups(2),
        e4::lookups(3),
        e4::lookups(4),
        e4::lookups(5),
        e4::lookups(6),
        e4::lookups(7),
        polls(0),
        polls(1),
        polls(2),
        polls(3),
        polls(4),
        polls(5),
        polls(6),
        polls(7)
    );
}

/// A blocked waiter found itself still blocked with nothing to switch to: count
/// the pass, and say whether it halts until the next interrupt.
pub fn blocked_wait_halts() -> bool {
    let mode = e4::mode();
    // Diagnostic counter only; wrap is harmless. lint-fetch-add: allow
    BLOCKED_POLLS[mode % e4::MODES].fetch_add(1, Ordering::Relaxed);
    mode & e4::HALT != 0
}
