//! C3 (#90): the hint that lets a work-stealing scan skip a ready queue
//! without taking its lock.
//!
//! A ready queue holds every task placed on its CPU, in every state, so its
//! length says little about whether it has work for another CPU. The scan used
//! to lock every other queue twice to find out, and under multi-threaded TCG
//! each wait for such a lock costs a round trip through QEMU's global lock.
//!
//! The hint is a wake sequence per queue. Every event that can make a task in
//! the queue dispatchable for some CPU is a *publication* and increments the
//! queue's sequence. A scanning CPU remembers, per source queue, the sequence
//! under which it last examined every entry and found nothing for itself; while
//! the sequence is unchanged, it skips that queue and touches no lock.
//!
//! "Seen" is kept per scanning CPU, not per queue. A queue can hold a Ready
//! task that only CPU 3 may run; CPU 5 finding nothing there for itself says
//! nothing about CPU 3 (GAP-6 F11).
//!
//! # Why no publication is missed
//!
//! The scanner reads the sequence before it examines any entry, and it
//! examines an entry under that entry's PCB lock. A publisher changes the
//! task under the same PCB lock and increments the sequence before it
//! releases the lock (or, for a queue insert, under the queue's lock, which
//! the scanner holds for its whole examination).
//!
//! - If the scanner examines the entry after the change, it sees the change.
//! - If it examines the entry before, the increment comes after its read of
//!   the sequence, so what it stores is stale and the next pass scans again.
//! - If it cannot take the PCB lock, its scan is not conclusive and it stores
//!   nothing.
//!
//! Three things make a task dispatchable with no event at all: its PCB lock is
//! released, the cpuset registry's lock is released, and a CPU quota throttle
//! expires. A scan that rejected an entry for one of them is not conclusive.
//!
//! A publication that the kernel fails to make is a defect, not a hang: once
//! per period of its own ticks (the scheduler's balance interval) a CPU makes
//! one pass that ignores what it has seen.
//!
//! The state is pure over the CPU and PID counts, so the hosted tests drive
//! small instances of it; the kernel's instance is [`hint`].

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};

/// One value on its own cache line: every waker of a queue's tasks writes the
/// queue's sequence, and every CPU counts its own scans.
#[repr(align(64))]
struct Line<T>(T);

/// `queue_cpu` holds the queue's CPU plus one, so that zero-initialised
/// storage means "in no queue".
const NO_QUEUE: u8 = 0;

#[derive(Default)]
struct ScanCounters {
    scans: AtomicU64,
    hint_skips: AtomicU64,
    lock_skips: AtomicU64,
    stolen: AtomicU64,
    full_passes: AtomicU64,
}

impl ScanCounters {
    const fn new() -> Self {
        Self {
            scans: AtomicU64::new(0),
            hint_skips: AtomicU64::new(0),
            lock_skips: AtomicU64::new(0),
            stolen: AtomicU64::new(0),
            full_passes: AtomicU64::new(0),
        }
    }
}

#[inline]
fn count(counter: &AtomicU64) {
    // lint-fetch-add: allow (statistics counter)
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Scan counters summed over the CPUs, for `/proc/schedstat`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StealStats {
    /// Source queues examined under their lock.
    pub scans: u64,
    /// Source queues ruled out without touching their lock.
    pub hint_skips: u64,
    /// Source queues skipped because their lock was held.
    pub lock_skips: u64,
    /// Tasks taken from a source queue.
    pub stolen: u64,
    /// Passes that ignored the seen marks.
    pub full_passes: u64,
}

/// How one examination of a source queue ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanOutcome {
    /// The published length was zero; the queue's lock was not taken.
    Empty,
    /// The queue's lock was held; nothing was examined.
    LockHeld,
    /// A task was removed from the queue.
    Stolen,
    /// Nothing was taken, and some entry was not examined, or was rejected for
    /// a reason that ends without a publication.
    Inconclusive,
    /// Every entry was examined in one hold of the lock and none can run on
    /// the scanning CPU until the queue publishes again.
    Conclusive,
}

/// The hint's state for `CPUS` ready queues and PIDs below `PIDS`.
///
/// All of it is lock-free and starts as zeroes, so the kernel's instance
/// costs no image space.
pub struct StealHint<const CPUS: usize, const PIDS: usize> {
    /// CPU plus one of the queue that holds the task, written under that
    /// queue's lock; `NO_QUEUE` while the task is in none.
    queue_cpu: [AtomicU8; PIDS],
    /// Publications for the tasks of each queue.
    wake_seq: [Line<AtomicU64>; CPUS],
    /// `seen[thief][source]`: the source's sequence plus one at the thief's
    /// last conclusive scan; zero before the first. Only the thief touches it.
    seen: [[AtomicU64; CPUS]; CPUS],
    /// Residents of each queue, written under its lock.
    queue_len: [Line<AtomicUsize>; CPUS],
    /// The CPU's next scan ignores `seen`.
    full_due: [AtomicBool; CPUS],
    ticks: [AtomicU64; CPUS],
    counters: [Line<ScanCounters>; CPUS],
}

impl<const CPUS: usize, const PIDS: usize> StealHint<CPUS, PIDS> {
    pub const fn new() -> Self {
        assert!(CPUS < u8::MAX as usize, "queue CPU must fit its u8 record");
        Self {
            queue_cpu: [const { AtomicU8::new(NO_QUEUE) }; PIDS],
            wake_seq: [const { Line(AtomicU64::new(0)) }; CPUS],
            seen: [const { [const { AtomicU64::new(0) }; CPUS] }; CPUS],
            queue_len: [const { Line(AtomicUsize::new(0)) }; CPUS],
            full_due: [const { AtomicBool::new(false) }; CPUS],
            ticks: [const { AtomicU64::new(0) }; CPUS],
            counters: [const { Line(ScanCounters::new()) }; CPUS],
        }
    }

    // ------------------------------------------------------------------
    // Publications
    // ------------------------------------------------------------------

    /// Something in `cpu`'s queue may have become dispatchable.
    #[inline]
    pub fn publish_cpu(&self, cpu: usize) {
        if let Some(seq) = self.wake_seq.get(cpu) {
            // A wrap would need 2^64 wakes. lint-fetch-add: allow
            seq.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The task `pid` may have become dispatchable for some CPU. One load,
    /// and one increment unless the task is in no queue. No lock: safe under
    /// a PCB lock and in the timer interrupt.
    #[inline]
    pub fn publish_pid(&self, pid: usize) {
        if let Some(cpu) = self.queue_cpu(pid) {
            self.publish_cpu(cpu);
        }
    }

    /// A change that can make any task dispatchable somewhere else, such as a
    /// cpuset's mask.
    pub fn publish_all(&self) {
        for cpu in 0..CPUS {
            self.publish_cpu(cpu);
        }
    }

    // ------------------------------------------------------------------
    // Membership, under the lock of the queue involved
    // ------------------------------------------------------------------

    /// `pid` entered `cpu`'s queue, which now holds `len` tasks. The insert
    /// is itself a publication: the task may be Ready.
    pub fn note_enqueued(&self, pid: usize, cpu: usize, len: usize) {
        if cpu >= CPUS {
            return;
        }
        if let Some(slot) = self.queue_cpu.get(pid) {
            slot.store(cpu as u8 + 1, Ordering::Release);
        }
        self.queue_len[cpu].0.store(len, Ordering::SeqCst);
        self.publish_cpu(cpu);
    }

    /// `pid` left `cpu`'s queue, which now holds `len` tasks.
    ///
    /// `same_pid_resident` is set when the queue still holds another entry
    /// under this PID: a reaped task's PID can be allocated again before the
    /// scheduler has dropped the old entry. The record then stays with the
    /// successor. It also stays if it already names another queue, for the
    /// same reason; hence the compare-and-swap.
    pub fn note_removed(&self, pid: usize, cpu: usize, len: usize, same_pid_resident: bool) {
        if cpu >= CPUS {
            return;
        }
        self.queue_len[cpu].0.store(len, Ordering::SeqCst);
        if same_pid_resident {
            return;
        }
        if let Some(slot) = self.queue_cpu.get(pid) {
            let _ =
                slot.compare_exchange(cpu as u8 + 1, NO_QUEUE, Ordering::AcqRel, Ordering::Acquire);
        }
    }

    /// The CPU whose queue holds `pid`, if it is in one.
    #[inline]
    pub fn queue_cpu(&self, pid: usize) -> Option<usize> {
        match self.queue_cpu.get(pid)?.load(Ordering::Acquire) {
            NO_QUEUE => None,
            raw => Some(raw as usize - 1),
        }
    }

    /// Residents of `cpu`'s queue as last published. One step stale at most
    /// while that queue's lock is held elsewhere; a heuristic input only.
    #[inline]
    pub fn queue_len(&self, cpu: usize) -> usize {
        self.queue_len
            .get(cpu)
            .map(|len| len.0.load(Ordering::SeqCst))
            .unwrap_or(0)
    }

    // ------------------------------------------------------------------
    // The scan
    // ------------------------------------------------------------------

    /// First step of `thief`'s look at `source`: read the queue's sequence.
    ///
    /// `None` means the thief has already seen this sequence and found
    /// nothing, and the pass is not a full one: skip the queue. Otherwise the
    /// value goes to [`Self::scan_end`], and must have been read before any
    /// entry is examined.
    #[inline]
    pub fn scan_begin(&self, thief: usize, source: usize, full_pass: bool) -> Option<u64> {
        let seq = self.wake_seq[source].0.load(Ordering::SeqCst);
        if !full_pass && self.seen[thief][source].load(Ordering::Relaxed) == seq.wrapping_add(1) {
            count(&self.counters[thief].0.hint_skips);
            return None;
        }
        Some(seq)
    }

    /// Last step: record how the examination that began at `seq` ended. Only
    /// an outcome that proves the queue holds nothing for `thief` is stored.
    #[inline]
    pub fn scan_end(&self, thief: usize, source: usize, seq: u64, outcome: ScanOutcome) {
        let counters = &self.counters[thief].0;
        let seen = &self.seen[thief][source];
        match outcome {
            // An insert stores the length before it increments the sequence,
            // so a zero read after `seq` is as good as an empty scan.
            ScanOutcome::Empty => {
                count(&counters.hint_skips);
                seen.store(seq.wrapping_add(1), Ordering::Relaxed);
            }
            ScanOutcome::LockHeld => count(&counters.lock_skips),
            ScanOutcome::Stolen => {
                count(&counters.scans);
                count(&counters.stolen);
            }
            ScanOutcome::Inconclusive => count(&counters.scans),
            ScanOutcome::Conclusive => {
                count(&counters.scans);
                seen.store(seq.wrapping_add(1), Ordering::Relaxed);
            }
        }
    }

    /// Whether `thief`'s next ordinary pass would skip `source`.
    pub fn would_skip(&self, thief: usize, source: usize) -> bool {
        let seq = self.wake_seq[source].0.load(Ordering::SeqCst);
        self.seen[thief][source].load(Ordering::Relaxed) == seq.wrapping_add(1)
    }

    // ------------------------------------------------------------------
    // The full pass
    // ------------------------------------------------------------------

    /// One timer tick on `cpu`: an atomic add and, every `period` ticks, a
    /// store. No lock and no allocation (M4-1).
    #[inline]
    pub fn tick(&self, cpu: usize, period: u64) {
        let Some(ticks) = self.ticks.get(cpu) else {
            return;
        };
        // lint-fetch-add: allow (per-CPU cadence, wrap is harmless)
        let elapsed = ticks.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        if period != 0 && elapsed % period == 0 {
            self.full_due[cpu].store(true, Ordering::Release);
        }
    }

    /// Whether `cpu`'s next pass must ignore its seen marks. It stays so
    /// until [`Self::complete_full_pass`]: a pass that ends early, at a steal
    /// or at a held lock, has not looked at every queue.
    #[inline]
    pub fn full_pass_due(&self, cpu: usize) -> bool {
        self.full_due
            .get(cpu)
            .is_some_and(|due| due.load(Ordering::Acquire))
    }

    /// `cpu` finished a pass that examined every source it did not skip for
    /// being empty.
    #[inline]
    pub fn complete_full_pass(&self, cpu: usize) {
        if let Some(due) = self.full_due.get(cpu) {
            due.store(false, Ordering::Release);
            count(&self.counters[cpu].0.full_passes);
        }
    }

    /// The counters of every CPU, summed.
    pub fn stats(&self) -> StealStats {
        let mut total = StealStats::default();
        for line in &self.counters {
            let counters = &line.0;
            total.scans = total
                .scans
                .wrapping_add(counters.scans.load(Ordering::Relaxed));
            total.hint_skips = total
                .hint_skips
                .wrapping_add(counters.hint_skips.load(Ordering::Relaxed));
            total.lock_skips = total
                .lock_skips
                .wrapping_add(counters.lock_skips.load(Ordering::Relaxed));
            total.stolen = total
                .stolen
                .wrapping_add(counters.stolen.load(Ordering::Relaxed));
            total.full_passes = total
                .full_passes
                .wrapping_add(counters.full_passes.load(Ordering::Relaxed));
        }
        total
    }
}

/// One record past the PID range [1, PID_MAX], so no task can ever hold it.
/// The scheduler's runtime probe queues a bare PCB under this PID.
pub const PROBE_PID: usize = crate::process::PID_MAX + 1;

/// The kernel's hint: one queue per possible CPU, one record per PID, and
/// the probe's record.
pub type KernelStealHint = StealHint<{ cpu_local::max_cpus() }, { PROBE_PID + 1 }>;

static HINT: KernelStealHint = StealHint::new();

/// The hint of the kernel's ready queues.
#[inline]
pub fn hint() -> &'static KernelStealHint {
    &HINT
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::process::{Process, ProcessState};
    use std::string::String;
    use std::vec::Vec;

    type SmallHint = StealHint<4, 64>;

    /// The scheduler's period (`LOAD_BALANCE_INTERVAL_TICKS`).
    const PERIOD: u64 = 64;

    #[test]
    fn steal_hint_a_first_look_is_never_skipped() {
        let hint = SmallHint::new();
        for thief in 0..4 {
            for source in 0..4 {
                assert!(!hint.would_skip(thief, source));
                assert_eq!(hint.scan_begin(thief, source, false), Some(0));
            }
        }
        assert_eq!(hint.stats(), StealStats::default());
    }

    #[test]
    fn steal_hint_a_publication_before_during_or_after_a_scan_is_scanned_again() {
        // Before: the scan reads the new sequence and may store it.
        let hint = SmallHint::new();
        hint.note_enqueued(7, 1, 1);
        let seq = hint.scan_begin(0, 1, false).expect("first look");
        hint.scan_end(0, 1, seq, ScanOutcome::Conclusive);
        assert!(hint.would_skip(0, 1));
        assert_eq!(hint.scan_begin(0, 1, false), None);

        // After: the stored mark is stale.
        hint.publish_pid(7);
        assert!(!hint.would_skip(0, 1));
        let seq = hint.scan_begin(0, 1, false).expect("published since");

        // During: the mark stored at the end names the sequence read at the
        // start, so the queue is examined once more.
        hint.publish_pid(7);
        hint.scan_end(0, 1, seq, ScanOutcome::Conclusive);
        assert!(!hint.would_skip(0, 1));
        let seq = hint
            .scan_begin(0, 1, false)
            .expect("published during the scan");
        hint.scan_end(0, 1, seq, ScanOutcome::Conclusive);
        assert!(hint.would_skip(0, 1));

        // Another thief has its own mark.
        assert!(!hint.would_skip(2, 1));
        // A publication for another queue changes nothing here.
        hint.publish_cpu(3);
        assert!(hint.would_skip(0, 1));
    }

    #[test]
    fn steal_hint_only_a_conclusive_or_empty_scan_is_remembered() {
        for (outcome, remembered) in [
            (ScanOutcome::LockHeld, false),
            (ScanOutcome::Stolen, false),
            (ScanOutcome::Inconclusive, false),
            (ScanOutcome::Conclusive, true),
            (ScanOutcome::Empty, true),
        ] {
            let hint = SmallHint::new();
            let seq = hint.scan_begin(2, 3, false).expect("first look");
            hint.scan_end(2, 3, seq, outcome);
            assert_eq!(hint.would_skip(2, 3), remembered, "{outcome:?}");
        }
    }

    #[test]
    fn steal_hint_counters_follow_the_outcomes() {
        let hint = SmallHint::new();
        for outcome in [
            ScanOutcome::LockHeld,
            ScanOutcome::Stolen,
            ScanOutcome::Inconclusive,
            ScanOutcome::Conclusive,
        ] {
            let seq = hint.scan_begin(1, 0, true).expect("full pass");
            hint.scan_end(1, 0, seq, outcome);
        }
        assert_eq!(hint.scan_begin(1, 0, false), None);
        let seq = hint.scan_begin(3, 2, false).expect("first look");
        hint.scan_end(3, 2, seq, ScanOutcome::Empty);
        assert_eq!(
            hint.stats(),
            StealStats {
                scans: 3,
                hint_skips: 2,
                lock_skips: 1,
                stolen: 1,
                full_passes: 0,
            }
        );
    }

    #[test]
    fn steal_hint_full_pass_comes_once_per_period_and_ignores_the_mark() {
        let hint = SmallHint::new();
        let seq = hint.scan_begin(0, 1, false).expect("first look");
        hint.scan_end(0, 1, seq, ScanOutcome::Conclusive);

        for _ in 0..PERIOD - 1 {
            hint.tick(0, PERIOD);
            assert!(!hint.full_pass_due(0));
        }
        hint.tick(0, PERIOD);
        // Another CPU's ticks are its own.
        assert!(!hint.full_pass_due(1));
        assert!(hint.full_pass_due(0));

        // The mark is still there, and a full pass looks past it.
        assert_eq!(hint.scan_begin(0, 1, false), None);
        let seq = hint
            .scan_begin(0, 1, true)
            .expect("a full pass looks again");
        // A full pass stores a conclusive result like any other.
        hint.scan_end(0, 1, seq, ScanOutcome::Conclusive);
        assert!(hint.would_skip(0, 1));

        // A pass that did not get through stays due; a finished one does not.
        assert!(hint.full_pass_due(0));
        assert_eq!(hint.stats().full_passes, 0);
        hint.complete_full_pass(0);
        assert!(!hint.full_pass_due(0));
        assert_eq!(hint.stats().full_passes, 1);
        for _ in 0..PERIOD {
            hint.tick(0, PERIOD);
        }
        assert!(hint.full_pass_due(0));

        // Out-of-range CPUs are ignored, not indexed.
        hint.tick(99, PERIOD);
        hint.complete_full_pass(99);
        assert!(!hint.full_pass_due(99));
        assert_eq!(hint.stats().full_passes, 1);
    }

    #[test]
    fn steal_hint_membership_follows_insert_steal_rollback_cancel_and_reap() {
        let hint = SmallHint::new();
        let pid = 9;
        assert_eq!(hint.queue_cpu(pid), None);
        hint.publish_pid(pid); // in no queue: nothing to publish
        assert!((0..4).all(|cpu| hint.scan_begin(0, cpu, false) == Some(0)));

        // Insert on CPU 2.
        hint.note_enqueued(pid, 2, 1);
        assert_eq!((hint.queue_cpu(pid), hint.queue_len(2)), (Some(2), 1));
        // A steal removes it; the rollback restores it.
        hint.note_removed(pid, 2, 0, false);
        assert_eq!((hint.queue_cpu(pid), hint.queue_len(2)), (None, 0));
        hint.note_enqueued(pid, 2, 1);
        assert_eq!(hint.queue_cpu(pid), Some(2));
        // A committed steal: out of 2, into 1.
        hint.note_removed(pid, 2, 0, false);
        hint.note_enqueued(pid, 1, 3);
        assert_eq!(
            (hint.queue_cpu(pid), hint.queue_len(1), hint.queue_len(2)),
            (Some(1), 3, 0)
        );
        // Cancel or reap.
        hint.note_removed(pid, 1, 2, false);
        assert_eq!((hint.queue_cpu(pid), hint.queue_len(1)), (None, 2));

        // PIDs and CPUs outside the tables are ignored.
        hint.note_enqueued(64, 1, 3);
        hint.note_enqueued(pid, 4, 1);
        hint.note_removed(pid, 4, 0, false);
        assert_eq!((hint.queue_cpu(64), hint.queue_cpu(pid)), (None, None));
        assert_eq!(hint.queue_len(4), 0);
    }

    #[test]
    fn steal_hint_recycled_pid_keeps_the_successors_record() {
        let pid = 5;

        // The successor is in another queue when the old entry is dropped.
        let hint = SmallHint::new();
        hint.note_enqueued(pid, 0, 1); // old identity
        hint.note_enqueued(pid, 3, 1); // successor
        hint.note_removed(pid, 0, 0, false);
        assert_eq!(hint.queue_cpu(pid), Some(3));

        // The successor is in the same queue under another priority.
        let hint = SmallHint::new();
        hint.note_enqueued(pid, 0, 1);
        hint.note_enqueued(pid, 0, 2);
        hint.note_removed(pid, 0, 1, true);
        assert_eq!(hint.queue_cpu(pid), Some(0));
        hint.note_removed(pid, 0, 0, false);
        assert_eq!(hint.queue_cpu(pid), None);
    }

    #[test]
    fn steal_hint_publish_all_reaches_every_queue() {
        let hint = SmallHint::new();
        for source in 1..4 {
            let seq = hint.scan_begin(0, source, false).expect("first look");
            hint.scan_end(0, source, seq, ScanOutcome::Conclusive);
            assert!(hint.would_skip(0, source));
        }
        hint.publish_all();
        assert!((1..4).all(|source| !hint.would_skip(0, source)));
    }

    // ------------------------------------------------------------------
    // The model
    //
    // Four CPUs and a handful of tasks on the kernel's own hint, changed
    // through the kernel's own hooks (`Process::enter_ready_at`,
    // `process::note_publication`), so that a hook that stops publishing
    // fails here. No other hosted test enqueues a PID, so none can publish
    // into these queues.
    // ------------------------------------------------------------------

    const MODEL_CPUS: usize = 4;
    const MODEL_FIRST_PID: usize = 31_000;

    struct ModelTask {
        proc: Process,
        /// The queue that holds the task; `None` while a thief carries it.
        queue: Option<usize>,
        /// Another CPU holds the PCB lock: a scanner's try-lock fails.
        pcb_locked: bool,
    }

    struct Hold {
        source: usize,
        seq: u64,
        /// Residents not yet examined, in queue order.
        remaining: Vec<usize>,
        transient: bool,
    }

    struct Model {
        tasks: Vec<ModelTask>,
        /// Which thief holds each queue's lock.
        queue_lock: [Option<usize>; MODEL_CPUS],
        holds: [Option<Hold>; MODEL_CPUS],
        /// A task each thief has removed and not yet inserted.
        carried: [Option<usize>; MODEL_CPUS],
        rng: u64,
        steals: u64,
        skips: u64,
    }

    impl Model {
        fn new(seed: u64, tasks: usize) -> Self {
            let mut model = Self {
                tasks: Vec::new(),
                queue_lock: [None; MODEL_CPUS],
                holds: [const { None }; MODEL_CPUS],
                carried: [None; MODEL_CPUS],
                rng: seed | 1,
                steals: 0,
                skips: 0,
            };
            for index in 0..tasks {
                let mut proc =
                    Process::new(MODEL_FIRST_PID + index, 1, String::from("steal-model"), 120);
                proc.enter_blocked_at(0);
                let queue = index % MODEL_CPUS;
                proc.allowed_cpus = model.next_mask();
                model.tasks.push(ModelTask {
                    proc,
                    queue: None,
                    pcb_locked: false,
                });
                model.insert(index, queue);
            }
            model
        }

        fn next(&mut self) -> u64 {
            // xorshift64*: deterministic, so a failure names its seed.
            self.rng ^= self.rng >> 12;
            self.rng ^= self.rng << 25;
            self.rng ^= self.rng >> 27;
            self.rng.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 16
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.next() % bound as u64) as usize
        }

        /// No restriction, or one or two CPUs.
        fn next_mask(&mut self) -> u64 {
            match self.below(4) {
                0 => 0,
                1 => 1 << self.below(MODEL_CPUS),
                _ => (1 << self.below(MODEL_CPUS)) | (1 << self.below(MODEL_CPUS)),
            }
        }

        fn residents(&self, cpu: usize) -> Vec<usize> {
            (0..self.tasks.len())
                .filter(|&task| self.tasks[task].queue == Some(cpu))
                .collect()
        }

        fn allowed(&self, task: usize, cpu: usize) -> bool {
            let mask = self.tasks[task].proc.allowed_cpus;
            mask == 0 || mask & (1 << cpu) != 0
        }

        fn dispatchable(&self, task: usize, cpu: usize) -> bool {
            let proc = &self.tasks[task].proc;
            proc.state == ProcessState::Ready
                && !proc.stopped
                && !proc.on_cpu.load(Ordering::Acquire)
                && self.allowed(task, cpu)
        }

        /// The scheduler's insert: under the queue's lock.
        fn insert(&mut self, task: usize, cpu: usize) {
            self.tasks[task].queue = Some(cpu);
            let len = self.residents(cpu).len();
            hint().note_enqueued(self.tasks[task].proc.pid, cpu, len);
        }

        fn remove(&mut self, task: usize, cpu: usize) {
            self.tasks[task].queue = None;
            let len = self.residents(cpu).len();
            hint().note_removed(self.tasks[task].proc.pid, cpu, len, false);
        }

        /// One step of thief `cpu`'s pass over `source`.
        fn scan_step(&mut self, cpu: usize) {
            if let Some(task) = self.carried[cpu].take() {
                // Commit the steal into the thief's own queue.
                self.insert(task, cpu);
                return;
            }
            let Some(mut hold) = self.holds[cpu].take() else {
                let source = (cpu + 1 + self.below(MODEL_CPUS - 1)) % MODEL_CPUS;
                let full = self.below(40) == 0;
                let Some(seq) = hint().scan_begin(cpu, source, full) else {
                    self.skips += 1;
                    return;
                };
                if hint().queue_len(source) == 0 {
                    hint().scan_end(cpu, source, seq, ScanOutcome::Empty);
                    return;
                }
                if self.queue_lock[source].is_some() {
                    hint().scan_end(cpu, source, seq, ScanOutcome::LockHeld);
                    return;
                }
                self.queue_lock[source] = Some(cpu);
                self.holds[cpu] = Some(Hold {
                    source,
                    seq,
                    remaining: self.residents(source),
                    transient: false,
                });
                return;
            };

            let source = hold.source;
            let outcome = if hold.remaining.is_empty() {
                Some(if hold.transient {
                    ScanOutcome::Inconclusive
                } else {
                    ScanOutcome::Conclusive
                })
            } else if self.below(12) == 0 {
                // The visit bound ends the hold with entries unexamined.
                Some(ScanOutcome::Inconclusive)
            } else {
                let task = hold.remaining.remove(0);
                if self.tasks[task].pcb_locked {
                    hold.transient = true;
                    None
                } else if self.dispatchable(task, cpu) {
                    self.remove(task, source);
                    self.carried[cpu] = Some(task);
                    self.steals += 1;
                    Some(ScanOutcome::Stolen)
                } else {
                    None
                }
            };
            match outcome {
                Some(outcome) => {
                    self.queue_lock[source] = None;
                    hint().scan_end(cpu, source, hold.seq, outcome);
                }
                None => self.holds[cpu] = Some(hold),
            }
        }

        /// One event on a task, as the kernel makes it: under the PCB lock,
        /// through the hooks.
        fn task_step(&mut self, task: usize) {
            if self.tasks[task].pcb_locked {
                self.tasks[task].pcb_locked = false;
                return;
            }
            let event = self.below(8);
            let new_mask = self.next_mask();
            let entry = &mut self.tasks[task];
            let proc = &mut entry.proc;
            let on_cpu = proc.on_cpu.load(Ordering::Acquire);
            match (event, proc.state) {
                // A wake.
                (0 | 1, ProcessState::Blocked) => proc.enter_ready_at(1),
                // The queue's own CPU dispatches the task.
                (2, ProcessState::Ready) if !on_cpu && !proc.stopped && entry.queue.is_some() => {
                    let cpu = entry.queue.unwrap_or(0);
                    let mask = proc.allowed_cpus;
                    if mask == 0 || mask & (1 << cpu) != 0 {
                        proc.enter_running_at(1);
                        proc.on_cpu.store(true, Ordering::Release);
                    }
                }
                // Its slice ends: Ready, still on the CPU. Not stealable yet.
                (2, ProcessState::Running) => proc.enter_ready_at(1),
                // It blocks.
                (3, ProcessState::Running) => proc.enter_blocked_at(1),
                // The switch away completes (`finish_pending_prev`).
                (3 | 4, _) if on_cpu && proc.state != ProcessState::Running => {
                    proc.on_cpu.store(false, Ordering::Release);
                    if proc.state == ProcessState::Ready {
                        crate::process::note_publication(proc.pid);
                    }
                }
                // sched_setaffinity.
                (5, _) => {
                    proc.allowed_cpus = new_mask;
                    crate::process::note_publication(proc.pid);
                }
                // A job-control stop and its SIGCONT.
                (6, ProcessState::Ready) if !on_cpu => {
                    if proc.stopped {
                        let (pid, generation) = (proc.pid, proc.generation);
                        assert!(crate::process::resume_job_control_locked(
                            proc, pid, generation
                        ));
                    } else {
                        proc.stopped = true;
                    }
                }
                // Another CPU takes the PCB lock for a while.
                (7, _) => entry.pcb_locked = true,
                _ => {}
            }
        }

        /// The hint must not rule out a queue that holds a task its CPU can
        /// run now. A thief in the middle of its look at the queue has not
        /// stored anything yet.
        fn check(&self, step: usize, seed: u64) {
            for thief in 0..MODEL_CPUS {
                for source in 0..MODEL_CPUS {
                    if source == thief
                        || self.holds[thief]
                            .as_ref()
                            .is_some_and(|hold| hold.source == source)
                        || !hint().would_skip(thief, source)
                    {
                        continue;
                    }
                    for task in self.residents(source) {
                        assert!(
                            !self.dispatchable(task, thief),
                            "seed {seed:#x} step {step}: CPU {thief} would skip queue {source}, \
                             which holds dispatchable pid {}",
                            self.tasks[task].proc.pid
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn steal_hint_model_no_dispatchable_task_stays_unseen() {
        let mut steals = 0;
        let mut skips = 0;
        for seed in [0x5eed_c3a1, 0x9e37_79b9_7f4a_7c15, 0x1234_5678_9abc_def1, 7] {
            let mut model = Model::new(seed, 6);
            for step in 0..60_000 {
                let actor = model.below(MODEL_CPUS + model.tasks.len());
                if actor < MODEL_CPUS {
                    model.scan_step(actor);
                } else {
                    model.task_step(actor - MODEL_CPUS);
                }
                model.check(step, seed);
            }
            steals += model.steals;
            skips += model.skips;
            // Leave the kernel's hint as it was found.
            for task in 0..model.tasks.len() {
                if let Some(cpu) = model.tasks[task].queue {
                    model.remove(task, cpu);
                }
                assert_eq!(hint().queue_cpu(model.tasks[task].proc.pid), None);
            }
        }
        // The run must have exercised both sides of the hint.
        assert!(steals > 1_000, "only {steals} steals");
        assert!(skips > 1_000, "only {skips} hint skips");
    }
}
