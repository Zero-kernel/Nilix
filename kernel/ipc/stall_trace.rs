//! Stall diagnostic (not for merge): the futex events that led to a stall.
//!
//! A ring of the most recent futex events, written without a lock: each writer
//! claims a slot by index and stores four words. The dump runs once, when the
//! guest has been silent for ten seconds, so nothing is being written then.
//! It prints, newest first, the last events that mention each Blocked task and
//! then the newest events of all tasks.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use kernel_core::process::{self, ProcessId, ProcessState};

const SLOTS: usize = 16384;
/// Events printed for each Blocked task.
const PER_TASK: usize = 20;
/// Newest events printed regardless of task.
const NEWEST: usize = 96;
/// Blocked tasks covered.
const TASKS: usize = 12;

struct Slot {
    tsc: AtomicU64,
    /// event << 56 | pid of the task that recorded it.
    who: AtomicU64,
    addr: AtomicU64,
    value: AtomicU64,
}

static NEXT: AtomicUsize = AtomicUsize::new(0);
static RING: [Slot; SLOTS] = [const {
    Slot {
        tsc: AtomicU64::new(0),
        who: AtomicU64::new(0),
        addr: AtomicU64::new(0),
        value: AtomicU64::new(0),
    }
}; SLOTS];

/// Bit 32 of `value` in the events that name a target task.
pub(crate) const FLAG_A: u64 = 1 << 32;
/// Bit 33 of `value` in the events that name a target task.
pub(crate) const FLAG_B: u64 = 1 << 33;

#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum Event {
    /// addr = uaddr, value = expected | current << 32.
    WaitEnter = 1,
    /// The record is in the bucket. addr = uaddr.
    WaitPublished = 2,
    /// The task is on the queue and Blocked. addr = uaddr.
    WaitArmed = 3,
    /// addr = uaddr, value = 1 wake mark seen, 2 immediate outcome, 3 no capacity.
    WaitNotArmed = 4,
    /// The epilogue. addr = uaddr, value = taken_by_waker | outcome << 8.
    WaitDone = 5,
    /// addr = uaddr, value = count.
    WakeEnter = 6,
    /// addr = uaddr1, value = uaddr2.
    RequeueEnter = 7,
    /// A futex syscall returns. addr = uaddr, value = result, or bit 63 | errno.
    OpExit = 8,
    /// A waker removed a record. addr = home uaddr, value = target pid,
    /// FLAG_A when the task sleeps on this bucket's queue.
    TakeRecord = 9,
    /// A waker readied (or failed to ready) a task. addr = origin uaddr,
    /// value = target pid, FLAG_A when the task was readied, FLAG_B when the
    /// origin bucket was found.
    WakeTask = 10,
    /// A requeue moved a record. addr = source uaddr, value = target pid.
    RequeueMove = 11,
    /// The clear_child_tid wake of an exiting task. addr = uaddr, value = woken.
    ExitWake = 12,
}

fn name(event: u64) -> &'static str {
    match event {
        1 => "wait-enter",
        2 => "wait-published",
        3 => "wait-armed",
        4 => "wait-not-armed",
        5 => "wait-done",
        6 => "wake-enter",
        7 => "requeue-enter",
        8 => "op-exit",
        9 => "take-record",
        10 => "wake-task",
        11 => "requeue-move",
        12 => "exit-wake",
        _ => "?",
    }
}

pub(crate) fn record(event: Event, addr: usize, value: u64) {
    let pid = process::current_pid().unwrap_or(0) as u64;
    // Diagnostic ring index; wrap is intended. lint-fetch-add: allow
    let index = NEXT.fetch_add(1, Ordering::Relaxed) % SLOTS;
    let slot = &RING[index];
    // SAFETY: RDTSC is unprivileged here and has no memory effects.
    slot.tsc
        .store(unsafe { core::arch::x86_64::_rdtsc() }, Ordering::Relaxed);
    slot.who
        .store((event as u64) << 56 | pid, Ordering::Relaxed);
    slot.addr.store(addr as u64, Ordering::Relaxed);
    slot.value.store(value, Ordering::Relaxed);
}

fn names_target(event: u64) -> bool {
    matches!(event, 9..=11)
}

fn mentions(slot: &Slot, pid: ProcessId) -> bool {
    let who = slot.who.load(Ordering::Relaxed);
    let event = who >> 56;
    who & 0xffff_ffff == pid as u64
        || (names_target(event) && slot.value.load(Ordering::Relaxed) & 0xffff_ffff == pid as u64)
}

fn print(slot: &Slot, back: usize) {
    let who = slot.who.load(Ordering::Relaxed);
    klog_always!(
        "STALL-DUMP trace   -{} tsc={} pid={} {} addr={:#x} value={:#x}",
        back,
        slot.tsc.load(Ordering::Relaxed),
        who & 0xffff_ffff,
        name(who >> 56),
        slot.addr.load(Ordering::Relaxed),
        slot.value.load(Ordering::Relaxed)
    );
}

/// The second word of the newest FUTEX_REQUEUE: in the thread profile, the
/// futex word of the wave's mutex, which a condition-variable broadcast
/// requeues its waiters to.
pub(crate) fn newest_requeue_target() -> Option<usize> {
    let end = NEXT.load(Ordering::Relaxed);
    for back in 1..=end.min(SLOTS) {
        let slot = &RING[end.wrapping_sub(back) % SLOTS];
        if slot.who.load(Ordering::Relaxed) >> 56 == Event::RequeueEnter as u64 {
            return Some(slot.value.load(Ordering::Relaxed) as usize);
        }
    }
    None
}

pub(crate) fn dump() {
    let end = NEXT.load(Ordering::Relaxed);
    let count = end.min(SLOTS);
    let slot = |back: usize| &RING[end.wrapping_sub(back) % SLOTS];

    let mut blocked = [0 as ProcessId; TASKS];
    let mut tasks = 0;
    for pid in 1..=process::PID_MAX {
        if tasks == TASKS {
            break;
        }
        let is_blocked = process::get_process(pid).is_some_and(|process| {
            process
                .try_lock()
                .is_some_and(|proc| proc.state == ProcessState::Blocked)
        });
        if is_blocked {
            blocked[tasks] = pid;
            tasks += 1;
        }
    }
    klog_always!(
        "STALL-DUMP trace begin: {} events recorded, ring of {}, newest first",
        end,
        SLOTS
    );
    for &pid in &blocked[..tasks] {
        klog_always!("STALL-DUMP trace blocked pid={}", pid);
        let mut shown = 0;
        for back in 1..=count {
            if shown == PER_TASK {
                break;
            }
            if mentions(slot(back), pid) {
                print(slot(back), back);
                shown += 1;
            }
        }
    }
    klog_always!("STALL-DUMP trace newest {}", count.min(NEWEST));
    for back in 1..=count.min(NEWEST) {
        print(slot(back), back);
    }
    klog_always!("STALL-DUMP trace end");
}
