//! C3 repair 3 (#90): a blocked waiter halts, and a wake kicks the CPU that
//! holds the task.
//!
//! A task that blocks while its CPU has nothing else to run keeps the CPU.
//! It used to poll: every pass a full reschedule attempt, a steal pass and
//! the deferred drains, many times per tick. Now, once a pass finds the wait
//! still standing, the CPU halts until an interrupt. The periodic tick ends
//! every halt, so a wake is never lost for longer than a tick; a wake of a
//! task whose CPU is halted also sends that CPU one reschedule IPI, so it
//! is not delayed at all.
//!
//! # State, per CPU
//!
//! - `ready_seq`: publications for tasks in this CPU's queue, the current one
//!   included. (Repair 1's wake sequence leaves out a task that is on a CPU,
//!   because nobody can steal it; here that is the main case.)
//! - `halted`: this CPU is between its last check and the end of its halt.
//! - `pending`: CPUs that code on this CPU found halted when it published,
//!   not yet kicked.
//! - `published`: queue CPUs that code on this CPU published for since its
//!   last flush.
//!
//! # Why no wake is lost
//!
//! The halting CPU stores `halted` and then reads `ready_seq`; the waker
//! increments `ready_seq` and then reads `halted`. All four operations are
//! sequentially consistent, so either the halting CPU sees the new sequence
//! and does not halt, or the waker sees `halted` and records a kick. The
//! sequence the halting CPU compares with was read before its last pass, and
//! that pass re-read the task's state: a wake before the pass was seen by it,
//! a wake after it moved the sequence. Interrupts are masked from before the
//! store to the halt, and the halt unmasks them in the same instruction pair
//! (`sti; hlt`), so a kick that arrives in between ends the halt at once.
//!
//! # Where the IPIs are sent
//!
//! Never from the publication itself: it runs under PCB locks and in the
//! timer interrupt, and RF178-35 forbids an IPI there. [`flush_wake_kicks`]
//! sends the recorded kicks at points that hold no lock by construction: the
//! syscall-return hook and the scheduler's process-context entry.
//! [`kick_published`] replaces the broadcast kick of the wakes that notified
//! every CPU before: it notifies only the CPUs whose queues the wake touched.
//!
//! The state is pure over the CPU count, so the hosted tests drive small
//! instances of it, and the halt is [`halt_sequence`] over [`HaltOps`], which
//! the kernel implements with `cli` / `sti; hlt` and the model with a
//! simulated CPU.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// One value on its own cache line: every waker of a queue's tasks writes
/// that queue's sequence, and each CPU writes its own masks and counters.
#[repr(align(64))]
struct Line<T>(T);

#[inline]
fn bit(cpu: usize) -> u64 {
    1u64 << cpu
}

/// Set bits of `mask`, lowest first.
fn cpus_of(mut mask: u64) -> impl Iterator<Item = usize> {
    core::iter::from_fn(move || {
        if mask == 0 {
            return None;
        }
        let cpu = mask.trailing_zeros() as usize;
        mask &= mask - 1;
        Some(cpu)
    })
}

#[derive(Default)]
struct Counters {
    halts: AtomicU64,
    seq_aborts: AtomicU64,
    kicks: AtomicU64,
    targeted: AtomicU64,
    notified: AtomicU64,
}

impl Counters {
    const fn new() -> Self {
        Self {
            halts: AtomicU64::new(0),
            seq_aborts: AtomicU64::new(0),
            kicks: AtomicU64::new(0),
            targeted: AtomicU64::new(0),
            notified: AtomicU64::new(0),
        }
    }
}

/// The `/proc/schedstat` `wait` line, summed over the CPUs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WaitStats {
    /// Halts taken in blocked waits.
    pub halts: u64,
    /// Halts in blocked waits not taken because the sequence had moved.
    pub seq_aborts: u64,
    /// IPIs sent by [`flush_wake_kicks`] to halted CPUs.
    pub kicks: u64,
    /// IPIs sent by [`kick_published`].
    pub targeted: u64,
    /// Calls of [`kick_published`]: wakes that notify, such as a child's exit.
    pub notified: u64,
}

/// Why [`halt_sequence`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HaltOutcome {
    /// The CPU halted, and an interrupt ended the halt.
    Halted,
    /// A publication for this CPU's queue came after the caller's snapshot.
    SeqMoved,
    /// The caller's own check found work.
    WorkPending,
}

/// The wait-and-kick state for `CPUS` CPUs. All of it is lock-free and starts
/// as zeroes.
pub struct WaitKicks<const CPUS: usize> {
    ready_seq: [Line<AtomicU64>; CPUS],
    halted: [Line<AtomicBool>; CPUS],
    pending: [Line<AtomicU64>; CPUS],
    published: [Line<AtomicU64>; CPUS],
    /// Halts of each CPU that an interrupt ended, at every site.
    exits: [Line<AtomicU64>; CPUS],
    counters: [Line<Counters>; CPUS],
}

impl<const CPUS: usize> WaitKicks<CPUS> {
    pub const fn new() -> Self {
        assert!(CPUS <= 64, "CPU masks are 64 bits wide");
        Self {
            ready_seq: [const { Line(AtomicU64::new(0)) }; CPUS],
            halted: [const { Line(AtomicBool::new(false)) }; CPUS],
            pending: [const { Line(AtomicU64::new(0)) }; CPUS],
            published: [const { Line(AtomicU64::new(0)) }; CPUS],
            exits: [const { Line(AtomicU64::new(0)) }; CPUS],
            counters: [const { Line(Counters::new()) }; CPUS],
        }
    }

    /// Code on CPU `this` made a task in `queue`'s queue Ready. Sends
    /// nothing and takes no lock: safe under a PCB lock and in the timer
    /// interrupt.
    #[inline]
    pub fn publish(&self, this: usize, queue: usize) {
        let Some(seq) = self.ready_seq.get(queue) else {
            return;
        };
        // A wrap would need 2^64 wakes. lint-fetch-add: allow
        seq.0.fetch_add(1, Ordering::SeqCst);
        let Some(published) = self.published.get(this) else {
            return;
        };
        published.0.fetch_or(bit(queue), Ordering::SeqCst);
        if self.halted[queue].0.load(Ordering::SeqCst) {
            self.pending[this].0.fetch_or(bit(queue), Ordering::SeqCst);
        }
    }

    /// Publications for `cpu`'s queue so far.
    #[inline]
    pub fn ready_seq(&self, cpu: usize) -> u64 {
        self.ready_seq
            .get(cpu)
            .map_or(0, |seq| seq.0.load(Ordering::SeqCst))
    }

    /// First step of a halt: from here on, a waker records a kick.
    #[inline]
    pub fn mark_halted(&self, cpu: usize) {
        self.halted[cpu].0.store(true, Ordering::SeqCst);
    }

    /// Second step: nothing was published for `cpu`'s queue since `seq`.
    #[inline]
    pub fn seq_unchanged(&self, cpu: usize, seq: u64) -> bool {
        self.ready_seq[cpu].0.load(Ordering::SeqCst) == seq
    }

    #[inline]
    pub fn clear_halted(&self, cpu: usize) {
        self.halted[cpu].0.store(false, Ordering::SeqCst);
    }

    /// Halts of `cpu` that ended so far, at every site.
    #[inline]
    pub fn halt_exits(&self, cpu: usize) -> u64 {
        self.exits
            .get(cpu)
            .map_or(0, |exits| exits.0.load(Ordering::SeqCst))
    }

    #[inline]
    pub fn is_halted(&self, cpu: usize) -> bool {
        self.halted
            .get(cpu)
            .is_some_and(|halted| halted.0.load(Ordering::SeqCst))
    }

    /// Advisory halt-state read for wake-affine / new-work CPU placement.
    /// Uses `Acquire` rather than `SeqCst`; correctness never depends on it
    /// (the Dekker handshake in `publish` / `halt_sequence` stays `SeqCst`).
    #[inline]
    pub fn is_halted_hint(&self, cpu: usize) -> bool {
        self.halted
            .get(cpu)
            .is_some_and(|halted| halted.0.load(Ordering::Acquire))
    }

    /// The kicks CPU `this` recorded; its published mask is cleared too.
    pub fn take_pending(&self, this: usize) -> u64 {
        if this >= CPUS {
            return 0;
        }
        self.published[this].0.swap(0, Ordering::AcqRel);
        self.pending[this].0.swap(0, Ordering::AcqRel)
    }

    /// The queue CPUs CPU `this` published for; their recorded kicks are
    /// dropped, because the caller notifies them all.
    pub fn take_published(&self, this: usize) -> u64 {
        if this >= CPUS {
            return 0;
        }
        let mask = self.published[this].0.swap(0, Ordering::AcqRel);
        self.pending[this].0.fetch_and(!mask, Ordering::AcqRel);
        mask
    }

    fn count(&self, cpu: usize, pick: impl FnOnce(&Counters) -> &AtomicU64) {
        if let Some(counters) = self.counters.get(cpu) {
            // Statistics only; wrap is harmless. lint-fetch-add: allow
            pick(&counters.0).fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn stats(&self) -> WaitStats {
        let mut stats = WaitStats::default();
        for counters in &self.counters {
            let c = &counters.0;
            stats.halts = stats.halts.wrapping_add(c.halts.load(Ordering::Relaxed));
            stats.seq_aborts = stats
                .seq_aborts
                .wrapping_add(c.seq_aborts.load(Ordering::Relaxed));
            stats.kicks = stats.kicks.wrapping_add(c.kicks.load(Ordering::Relaxed));
            stats.targeted = stats
                .targeted
                .wrapping_add(c.targeted.load(Ordering::Relaxed));
            stats.notified = stats
                .notified
                .wrapping_add(c.notified.load(Ordering::Relaxed));
        }
        stats
    }
}

/// What a halt needs from the CPU. The kernel's implementation masks and
/// unmasks interrupts; the hosted model simulates a CPU and lets a waker act
/// at every [`HaltOps::step`].
pub trait HaltOps {
    /// Mask interrupts on this CPU.
    fn disable_interrupts(&mut self);
    /// Unmask interrupts without halting.
    fn enable_interrupts(&mut self);
    /// Unmask interrupts and halt in one step: an interrupt pending at the
    /// unmask ends the halt at once.
    fn enable_interrupts_and_halt(&mut self);
    /// The caller's own reasons not to halt (a reschedule request, deferred
    /// work), read with interrupts masked.
    fn work_pending(&mut self) -> bool;
    /// A point between two steps. A no-op in the kernel.
    #[inline]
    fn step(&mut self) {}
}

/// Halt `cpu` unless something was published for its queue since `seq` or
/// the caller has work. Interrupts are masked only from the first step to
/// the halt, with no lock and no drain inside (W7); the last check and the
/// halt are atomic (W5).
pub fn halt_sequence<const CPUS: usize, H: HaltOps>(
    kicks: &WaitKicks<CPUS>,
    cpu: usize,
    seq: u64,
    ops: &mut H,
) -> HaltOutcome {
    ops.disable_interrupts();
    ops.step();
    kicks.mark_halted(cpu);
    ops.step();
    if !kicks.seq_unchanged(cpu, seq) {
        kicks.clear_halted(cpu);
        ops.enable_interrupts();
        return HaltOutcome::SeqMoved;
    }
    ops.step();
    if ops.work_pending() {
        kicks.clear_halted(cpu);
        ops.enable_interrupts();
        return HaltOutcome::WorkPending;
    }
    ops.step();
    ops.enable_interrupts_and_halt();
    kicks.clear_halted(cpu);
    ops.step();
    // Statistics only; wrap is harmless. lint-fetch-add: allow
    kicks.exits[cpu].0.fetch_add(1, Ordering::SeqCst);
    HaltOutcome::Halted
}

// ----------------------------------------------------------------------
// The kernel's instance
// ----------------------------------------------------------------------

pub type KernelWaitKicks = WaitKicks<{ cpu_local::max_cpus() }>;

static KICKS: KernelWaitKicks = WaitKicks::new();

/// Sends one reschedule IPI to a CPU; registered by the scheduler.
static KICK_CPU: spin::Once<fn(usize)> = spin::Once::new();

/// Optional wake-affine placement hook registered by the scheduler.
/// Runs in IF-on process context with no futex/waitqueue/PCB lock held after
/// a task becomes Ready, placing it on an allowed idle CPU when its home CPU
/// is busy or disallowed while preserving cache locality when its home CPU is
/// free and permitted (or the system is saturated). Carries `(pid, generation)`
/// captured at wake time so a recycled PID is rejected.
static WAKE_AFFINE_HOOK: spin::Once<fn(usize, u64)> = spin::Once::new();

/// The kernel's wait-and-kick state.
#[inline]
pub fn kicks() -> &'static KernelWaitKicks {
    &KICKS
}

/// Register the scheduler's reschedule IPI. Kicks are recorded before it is
/// registered and sent only after.
pub fn register_cpu_kick(kick: fn(usize)) {
    KICK_CPU.call_once(|| kick);
}

/// Register the scheduler's wake-affine placement hook.
pub fn register_wake_affine_hook(hook: fn(usize, u64)) {
    WAKE_AFFINE_HOOK.call_once(|| hook);
}

/// Ask the scheduler to apply wake-affine placement for a freshly readied task
/// identified by `(pid, generation)`. Callers must hold no lock and run in
/// process context with interrupts enabled.
#[inline]
pub fn note_wake_affine(pid: usize, generation: u64) {
    if let Some(hook) = WAKE_AFFINE_HOOK.get() {
        hook(pid, generation);
    }
}

/// Compute the intersection of online CPUs with `allowed_cpus` (where `0` means
/// unrestricted, matching `Scheduler::cpu_allowed`).
#[inline]
fn eligible_cpu_mask(online_mask: u64, allowed_cpus: u64) -> u64 {
    if allowed_cpus == 0 {
        online_mask
    } else {
        online_mask & allowed_cpus
    }
}

/// Visit every set bit in `mask` in staggered ring order starting immediately
/// after `start_after` (wrapping around modulo 64). Staggering prevents
/// concurrent spawns or wakes from colliding on the lowest-numbered idle CPU.
#[inline]
fn for_each_staggered_cpu(mask: u64, start_after: usize, mut visit: impl FnMut(usize)) {
    if mask == 0 {
        return;
    }
    let shift = ((start_after.wrapping_add(1)) & 63) as u32;
    let mut rotated = mask.rotate_right(shift);
    while rotated != 0 {
        let tz = rotated.trailing_zeros();
        let cpu = ((tz + shift) & 63) as usize;
        visit(cpu);
        rotated &= rotated - 1;
    }
}

/// Gate process-context work-stealing in `reschedule_now`.
///
/// Only CPUs that are idle, explicitly rescheduling (`force`: blocking wait,
/// task exit, `sched_yield`, pending IRQ resched), or already flagged with
/// `need_resched` should scan and steal from remote queues. A running task
/// returning from an ordinary syscall (`futex_wake`, `clone`, `write`, etc.)
/// must not steal remote work and preempt itself.
#[inline]
pub fn should_try_steal_on_process_resched(
    cpu_is_idle: bool,
    force: bool,
    need_resched: bool,
) -> bool {
    cpu_is_idle || force || need_resched
}

/// Idle-aware, staggered CPU selection for newly spawned work (`fork`/`clone`).
///
/// Priority:
/// 1. `preferred_cpu` if allowed and currently idle (e.g. BSP boot).
/// 2. An allowed idle CPU with an empty queue (`is_idle && queue_len == 0`),
///    scanned in staggered ring order after `preferred_cpu`.
/// 3. An allowed idle or halted CPU with minimum `queue_len` (breaking ties
///    in favor of truly idle CPUs over halted-waiter CPUs, then staggered).
/// 4. Saturated fallback: least-loaded allowed CPU when `least_len + threshold
///    < preferred_len` (or when `preferred_cpu` is disallowed), otherwise
///    `preferred_cpu`.
pub fn select_target_cpu_for_new_work(
    online_mask: u64,
    preferred_cpu: usize,
    allowed_cpus: u64,
    load_imbalance_threshold: usize,
    is_idle: impl Fn(usize) -> bool,
    is_halted: impl Fn(usize) -> bool,
    queue_len: impl Fn(usize) -> usize,
) -> Option<usize> {
    let eligible = eligible_cpu_mask(online_mask, allowed_cpus);
    if eligible == 0 {
        return None;
    }

    let preferred_allowed = preferred_cpu < 64 && (eligible & bit(preferred_cpu)) != 0;
    if preferred_allowed && is_idle(preferred_cpu) {
        return Some(preferred_cpu);
    }

    let mut first_empty_idle: Option<usize> = None;
    let mut best_idle_or_halted: Option<(usize, usize, bool)> = None;
    let mut least: Option<(usize, usize)> = None;

    for_each_staggered_cpu(eligible, preferred_cpu, |cpu| {
        let len = queue_len(cpu);
        if least.is_none_or(|(_, best_len)| len < best_len) {
            least = Some((cpu, len));
        }
        if cpu == preferred_cpu {
            return;
        }
        let idle = is_idle(cpu);
        let halted = !idle && is_halted(cpu);
        if idle && len == 0 && first_empty_idle.is_none() {
            first_empty_idle = Some(cpu);
        }
        if idle || halted {
            let better = match best_idle_or_halted {
                None => true,
                Some((_, best_len, best_idle)) => {
                    len < best_len || (len == best_len && idle && !best_idle)
                }
            };
            if better {
                best_idle_or_halted = Some((cpu, len, idle));
            }
        }
    });

    if let Some(cpu) = first_empty_idle {
        return Some(cpu);
    }
    if let Some((cpu, _, _)) = best_idle_or_halted {
        return Some(cpu);
    }

    let (least_cpu, least_len) = least?;
    if !preferred_allowed {
        return Some(least_cpu);
    }
    let preferred_len = queue_len(preferred_cpu);
    if least_cpu != preferred_cpu
        && least_len.saturating_add(load_imbalance_threshold) < preferred_len
    {
        Some(least_cpu)
    } else {
        Some(preferred_cpu)
    }
}

/// Wake-affine CPU selection for a freshly readied task (e.g. `futex_wake`).
///
/// Priority:
/// 1. Keep `home_cpu` (zero migration, warm cache/TLB) if allowed and free
///    (`is_idle(home_cpu) || is_halted(home_cpu)`).
/// 2. When `home_cpu` is busy running another task (or disallowed), pick an
///    allowed free CPU in staggered ring order after `home_cpu`: empty idle
///    -> non-empty idle (min queue_len) -> halted CPU (min queue_len).
/// 3. Under saturation (no allowed CPU is idle or halted), keep `home_cpu` if
///    allowed to avoid pointless migration churn.
/// 4. If `home_cpu` is disallowed (affinity/cpuset changed while blocked),
///    fall back to the least-loaded allowed CPU.
pub fn select_wake_affine_cpu(
    online_mask: u64,
    home_cpu: usize,
    allowed_cpus: u64,
    is_idle: impl Fn(usize) -> bool,
    is_halted: impl Fn(usize) -> bool,
    queue_len: impl Fn(usize) -> usize,
) -> Option<usize> {
    let eligible = eligible_cpu_mask(online_mask, allowed_cpus);
    if eligible == 0 {
        return None;
    }

    let home_allowed = home_cpu < 64 && (eligible & bit(home_cpu)) != 0;
    if home_allowed && (is_idle(home_cpu) || is_halted(home_cpu)) {
        return Some(home_cpu);
    }

    let mut first_empty_idle: Option<usize> = None;
    let mut best_idle: Option<(usize, usize)> = None;
    let mut best_halted: Option<(usize, usize)> = None;
    let mut least: Option<(usize, usize)> = None;

    for_each_staggered_cpu(eligible, home_cpu, |cpu| {
        let len = queue_len(cpu);
        if least.is_none_or(|(_, best_len)| len < best_len) {
            least = Some((cpu, len));
        }
        if cpu == home_cpu {
            return;
        }
        if is_idle(cpu) {
            if len == 0 && first_empty_idle.is_none() {
                first_empty_idle = Some(cpu);
            }
            if best_idle.is_none_or(|(_, best_len)| len < best_len) {
                best_idle = Some((cpu, len));
            }
        } else if is_halted(cpu) && best_halted.is_none_or(|(_, best_len)| len < best_len) {
            best_halted = Some((cpu, len));
        }
    });

    if let Some(cpu) = first_empty_idle {
        return Some(cpu);
    }
    if let Some((cpu, _)) = best_idle {
        return Some(cpu);
    }
    if let Some((cpu, _)) = best_halted {
        return Some(cpu);
    }
    if home_allowed {
        return Some(home_cpu);
    }
    least.map(|(cpu, _)| cpu)
}

/// The publication hook: the task `pid` became Ready (`Process::enter_ready_at`
/// for a task that is on its CPU, otherwise through `note_publication`).
#[inline]
pub fn note_ready(pid: usize) {
    if let Some(queue) = crate::steal_hint::hint().queue_cpu(pid) {
        note_ready_on(queue);
    }
}

/// A task in `queue`'s queue became Ready.
#[inline]
pub fn note_ready_on(queue: usize) {
    KICKS.publish(cpu_local::current_cpu_id(), queue);
}

/// This CPU's sequence before a pass, for [`halt_until_event`].
#[derive(Debug, Clone, Copy)]
pub struct WaitSnapshot {
    cpu: usize,
    seq: u64,
}

/// Read this CPU's sequence. Call it before the pass whose outcome decides
/// whether to halt.
#[inline]
pub fn snapshot() -> WaitSnapshot {
    let cpu = cpu_local::current_cpu_id();
    WaitSnapshot {
        cpu,
        seq: KICKS.ready_seq(cpu),
    }
}

/// Which loop halts. Only blocked waits are counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HaltSite {
    /// `block_until_resolved` and the waitpid loops.
    Wait,
    /// The idle loops.
    Idle,
}

struct KernelHalt<F: FnMut() -> bool> {
    work_pending: F,
}

impl<F: FnMut() -> bool> HaltOps for KernelHalt<F> {
    #[inline]
    fn disable_interrupts(&mut self) {
        x86_64::instructions::interrupts::disable();
    }

    #[inline]
    fn enable_interrupts(&mut self) {
        x86_64::instructions::interrupts::enable();
    }

    #[inline]
    fn enable_interrupts_and_halt(&mut self) {
        // SAFETY: STI takes effect after the next instruction, so an
        // interrupt that became pending while they were masked ends the HLT
        // at once. Ring 0 only. Not `nomem`: the compiler must keep the
        // stores to `halted` on their sides of the halt.
        unsafe {
            core::arch::asm!("sti", "hlt", options(nostack, preserves_flags));
        }
    }

    #[inline]
    fn work_pending(&mut self) -> bool {
        (self.work_pending)()
    }
}

/// Halt this CPU until an interrupt, unless something was published for its
/// queue since `snap` or `work_pending` (read with interrupts masked) is
/// true. Returns at once if interrupts are masked on entry or the caller has
/// moved to another CPU since `snap`, and always in a hosted build, where a
/// wait loop then polls as it did before.
pub fn halt_until_event(
    snap: WaitSnapshot,
    site: HaltSite,
    work_pending: impl FnMut() -> bool,
) -> HaltOutcome {
    if cfg!(not(target_os = "none")) || !x86_64::instructions::interrupts::are_enabled() {
        return HaltOutcome::WorkPending;
    }
    // A switch is the only way to change CPU, and none can happen between
    // this check and the halt.
    if cpu_local::current_cpu_id() != snap.cpu {
        return HaltOutcome::SeqMoved;
    }
    let outcome = halt_sequence(&KICKS, snap.cpu, snap.seq, &mut KernelHalt { work_pending });
    if site == HaltSite::Wait {
        match outcome {
            HaltOutcome::Halted => KICKS.count(snap.cpu, |c| &c.halts),
            HaltOutcome::SeqMoved => KICKS.count(snap.cpu, |c| &c.seq_aborts),
            HaltOutcome::WorkPending => {}
        }
    }
    outcome
}

/// The halt of a blocked wait (`block_until_resolved`, the waitpid loops):
/// not while a reschedule is requested or a drain the waiter may depend on is
/// flagged (`run_blocked_wait_drains`).
pub fn halt_blocked_wait(snap: WaitSnapshot) -> HaltOutcome {
    halt_until_event(snap, HaltSite::Wait, || {
        cpu_local::current_cpu().need_resched.load(Ordering::SeqCst)
            || crate::process::blocked_wait_work_pending()
    })
}

fn set_need_resched(cpu: usize) {
    if let Some(data) = cpu_local::PER_CPU_DATA.get_cpu(cpu) {
        data.need_resched.store(true, Ordering::Release);
    }
}

/// Send the kicks this CPU recorded to the CPUs that are still halted. Call
/// only where no lock is held and not from an interrupt (RF178-35).
pub fn flush_wake_kicks() {
    let Some(kick) = KICK_CPU.get() else {
        return;
    };
    let this = cpu_local::current_cpu_id();
    let pending = KICKS.take_pending(this);
    for cpu in cpus_of(pending) {
        if cpu == this {
            cpu_local::current_cpu().set_need_resched();
        } else if KICKS.is_halted(cpu) {
            set_need_resched(cpu);
            kick(cpu);
            KICKS.count(this, |c| &c.kicks);
        }
    }
}

/// After a wake that notifies (a signal with a handler, SIGCONT, a kill or
/// exit request, a child's exit, the reaper wake), with every lock released:
/// set `need_resched` on this CPU (R172-27) and on every CPU whose queue the
/// wake published for, and send each of the others one IPI, halted or not.
/// The broadcast this replaces did the same to every CPU. If the wake
/// published for no queue at all, it falls back to that broadcast.
///
/// Returns the CPUs sent an IPI, or `None` before the scheduler registered
/// its kick.
pub fn kick_published() -> Option<u64> {
    let kick = KICK_CPU.get()?;
    let this = cpu_local::current_cpu_id();
    let mask = KICKS.take_published(this);
    KICKS.count(this, |c| &c.notified);
    if mask == 0 {
        return crate::signal::kernel_kick_reschedule().then_some(!bit(this));
    }
    cpu_local::current_cpu().set_need_resched();
    let others = mask & !bit(this);
    for cpu in cpus_of(others) {
        set_need_resched(cpu);
        kick(cpu);
        KICKS.count(this, |c| &c.targeted);
    }
    Some(others)
}

/// Broadcast a reschedule kick after a notifying wake that could not resolve
/// every target's queue CPU (e.g. a `Provisioning` or transiently migrating
/// task). Drains this CPU's `published` mask first so stale bits do not linger.
pub fn kick_broadcast() -> bool {
    let this = cpu_local::current_cpu_id();
    let _ = KICKS.take_published(this);
    KICKS.count(this, |c| &c.notified);
    crate::signal::kernel_kick_reschedule()
}

/// The `/proc/schedstat` `wait` line's values.
pub fn stats() -> WaitStats {
    KICKS.stats()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    #[test]
    fn wait_kick_publish_moves_sequence_and_records_halted_queues_only() {
        let kicks = WaitKicks::<4>::new();
        kicks.publish(0, 2);
        assert_eq!(kicks.ready_seq(2), 1);
        assert_eq!(kicks.take_pending(0), 0, "a running CPU needs no kick");

        kicks.mark_halted(3);
        kicks.publish(1, 3);
        assert_eq!(kicks.ready_seq(3), 1);
        assert_eq!(kicks.take_pending(1), bit(3));
        assert_eq!(kicks.take_pending(1), 0, "taken once");
    }

    #[test]
    fn wait_kick_published_mask_covers_a_multi_task_wake() {
        let kicks = WaitKicks::<8>::new();
        kicks.mark_halted(5);
        kicks.publish(2, 1);
        kicks.publish(2, 5);
        kicks.publish(2, 5);
        kicks.publish(2, 2);
        assert_eq!(kicks.take_published(2), bit(1) | bit(2) | bit(5));
        assert_eq!(
            kicks.take_pending(2),
            0,
            "CPUs notified as published are not kicked again"
        );
        assert_eq!(kicks.take_published(2), 0);
    }

    #[test]
    fn wait_kick_flush_clears_the_published_mask() {
        let kicks = WaitKicks::<4>::new();
        kicks.publish(0, 1);
        assert_eq!(kicks.take_pending(0), 0);
        assert_eq!(
            kicks.take_published(0),
            0,
            "a flush starts a new published mask"
        );
    }

    #[test]
    fn wait_kick_out_of_range_cpus_are_ignored() {
        let kicks = WaitKicks::<2>::new();
        kicks.publish(0, 7);
        kicks.publish(9, 1);
        assert_eq!(kicks.ready_seq(1), 1, "the queue's sequence still moves");
        assert_eq!(kicks.take_pending(9), 0);
        assert_eq!(kicks.take_published(9), 0);
        assert!(!kicks.is_halted(7));
    }

    struct Scripted {
        irq: bool,
        halted_in_hlt: bool,
        work: bool,
        log: Vec<&'static str>,
    }

    impl HaltOps for Scripted {
        fn disable_interrupts(&mut self) {
            self.irq = false;
            self.log.push("cli");
        }
        fn enable_interrupts(&mut self) {
            self.irq = true;
            self.log.push("sti");
        }
        fn enable_interrupts_and_halt(&mut self) {
            self.irq = true;
            self.halted_in_hlt = true;
            self.log.push("sti;hlt");
        }
        fn work_pending(&mut self) -> bool {
            self.log.push("check");
            self.work
        }
    }

    fn scripted(work: bool) -> Scripted {
        Scripted {
            irq: true,
            halted_in_hlt: false,
            work,
            log: Vec::new(),
        }
    }

    #[test]
    fn wait_kick_halt_decision() {
        let kicks = WaitKicks::<2>::new();
        let seq = kicks.ready_seq(0);

        let mut ops = scripted(false);
        assert_eq!(halt_sequence(&kicks, 0, seq, &mut ops), HaltOutcome::Halted);
        assert_eq!(ops.log, ["cli", "check", "sti;hlt"]);
        assert!(ops.irq && ops.halted_in_hlt);
        assert!(!kicks.is_halted(0), "the flag ends with the halt");
        assert_eq!(kicks.halt_exits(0), 1);

        let mut ops = scripted(true);
        assert_eq!(
            halt_sequence(&kicks, 0, seq, &mut ops),
            HaltOutcome::WorkPending
        );
        assert_eq!(ops.log, ["cli", "check", "sti"]);
        assert!(ops.irq && !ops.halted_in_hlt && !kicks.is_halted(0));

        kicks.publish(1, 0);
        let mut ops = scripted(false);
        assert_eq!(
            halt_sequence(&kicks, 0, seq, &mut ops),
            HaltOutcome::SeqMoved
        );
        assert_eq!(ops.log, ["cli", "sti"]);
        assert!(ops.irq && !ops.halted_in_hlt && !kicks.is_halted(0));
    }

    // ------------------------------------------------------------------
    // The model: one waiter on CPU 0, one waker on CPU 1.
    // ------------------------------------------------------------------

    /// The waker's operations, in order.
    #[derive(Clone, Copy, Debug)]
    enum WakerOp {
        /// Under the waiter's PCB lock: the task becomes Ready, and the hook
        /// publishes it for queue 0.
        Wake,
        /// At the waker's next safe point: send the recorded kicks.
        Flush,
    }

    const WAKER: [WakerOp; 2] = [WakerOp::Wake, WakerOp::Flush];

    struct Model<'a> {
        kicks: &'a WaitKicks<2>,
        task_ready: bool,
        need_resched: bool,
        irq: bool,
        /// An interrupt arrived while masked and waits for the unmask.
        irq_pending: bool,
        /// The waiter is in HLT.
        asleep: bool,
        /// The waiter slept with its task Ready and no interrupt coming
        /// before the next tick.
        lost: bool,
        /// Waiter step points so far; the waker's op `i` runs at point `at[i]`.
        point: usize,
        at: [usize; 2],
        next: usize,
    }

    impl Model<'_> {
        fn interrupt(&mut self) {
            // The reschedule IPI's handler sets need_resched (as the flush
            // already did) and returns.
            self.need_resched = true;
            if !self.irq {
                self.irq_pending = true;
            } else if self.asleep {
                self.asleep = false;
            }
        }

        fn run_waker(&mut self, op: WakerOp) {
            match op {
                WakerOp::Wake => {
                    self.task_ready = true;
                    self.kicks.publish(1, 0);
                }
                WakerOp::Flush => {
                    let pending = self.kicks.take_pending(1);
                    if pending & bit(0) != 0 && self.kicks.is_halted(0) {
                        self.interrupt();
                    }
                }
            }
        }

        /// Run the waker's operations scheduled at the current point.
        fn advance(&mut self) {
            while self.next < WAKER.len() && self.at[self.next] <= self.point {
                let op = WAKER[self.next];
                self.next += 1;
                self.run_waker(op);
            }
            self.point += 1;
        }

        /// The waker finishes while the waiter sleeps.
        fn finish(&mut self) {
            while self.next < WAKER.len() {
                let op = WAKER[self.next];
                self.next += 1;
                self.run_waker(op);
            }
        }
    }

    impl HaltOps for Model<'_> {
        fn disable_interrupts(&mut self) {
            self.irq = false;
        }
        fn enable_interrupts(&mut self) {
            self.irq = true;
            self.irq_pending = false;
        }
        fn enable_interrupts_and_halt(&mut self) {
            self.irq = true;
            if core::mem::replace(&mut self.irq_pending, false) {
                return;
            }
            self.asleep = true;
            self.finish();
            if self.asleep && self.task_ready {
                self.lost = true;
            }
            self.asleep = false;
        }
        fn work_pending(&mut self) -> bool {
            self.need_resched
        }
        fn step(&mut self) {
            self.advance();
        }
    }

    /// The waiter's pass and halt with the waker's two operations at points
    /// `at`. Returns whether a wake was lost.
    fn run_model(at: [usize; 2]) -> bool {
        let kicks = WaitKicks::<2>::new();
        let mut model = Model {
            kicks: &kicks,
            task_ready: false,
            need_resched: false,
            irq: true,
            irq_pending: false,
            asleep: false,
            lost: false,
            point: 0,
            at,
            next: 0,
        };
        model.advance();
        let seq = kicks.ready_seq(0);
        model.advance();
        // The pass: the scheduler leaves the Blocked task current and clears
        // need_resched; the waiter re-reads its state.
        model.need_resched = false;
        if model.task_ready {
            return false;
        }
        model.advance();
        halt_sequence(&kicks, 0, seq, &mut model);
        model.finish();
        model.lost
    }

    #[test]
    fn wait_kick_model_loses_no_wake_in_any_interleaving() {
        // Points: before the snapshot, before the pass, before the halt,
        // the four steps inside the halt, and after it.
        const POINTS: usize = 8;
        let mut runs = 0;
        for wake in 0..POINTS {
            for flush in wake..POINTS {
                runs += 1;
                assert!(
                    !run_model([wake, flush]),
                    "wake at point {}, flush at point {}: the waiter slept through the wake",
                    wake,
                    flush
                );
            }
        }
        assert_eq!(runs, POINTS * (POINTS + 1) / 2);
    }

    // ------------------------------------------------------------------
    // The kernel's instance
    // ------------------------------------------------------------------
    //
    // It is global, and hosted process tests publish into it for low CPU
    // numbers through the real `Process` methods (the steal-hint model). These
    // tests run one at a time, use CPUs from 40 up, and check only those.

    static KERNEL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static KICKED: AtomicU64 = AtomicU64::new(0);
    const MINE: u64 = !((1u64 << 40) - 1);

    fn record_kick(cpu: usize) {
        KICKED.fetch_or(bit(cpu), Ordering::SeqCst);
    }

    fn kicked() -> u64 {
        KICKED.load(Ordering::SeqCst) & MINE
    }

    #[test]
    fn wait_kick_is_sent_at_safe_points_only() {
        let _serial = KERNEL_STATE.lock().unwrap_or_else(|e| e.into_inner());
        register_cpu_kick(record_kick);
        KICKED.store(0, Ordering::SeqCst);
        kicks().mark_halted(43);
        note_ready_on(43);
        assert_eq!(kicked(), 0, "the hook sends nothing");
        flush_wake_kicks();
        assert_eq!(kicked(), bit(43));
        kicks().clear_halted(43);

        // A CPU that stopped halting before the flush is not kicked.
        KICKED.store(0, Ordering::SeqCst);
        kicks().mark_halted(42);
        note_ready_on(42);
        kicks().clear_halted(42);
        flush_wake_kicks();
        assert_eq!(kicked(), 0);
    }

    #[test]
    fn wait_kick_syscall_return_flushes() {
        let _serial = KERNEL_STATE.lock().unwrap_or_else(|e| e.into_inner());
        register_cpu_kick(record_kick);
        KICKED.store(0, Ordering::SeqCst);
        kicks().mark_halted(44);
        note_ready_on(44);
        crate::reschedule_if_needed();
        assert_eq!(
            kicked(),
            bit(44),
            "the syscall-return hook sends the recorded kick"
        );
        kicks().clear_halted(44);
    }

    #[test]
    fn wait_kick_published_notifies_the_published_cpus_once() {
        let _serial = KERNEL_STATE.lock().unwrap_or_else(|e| e.into_inner());
        register_cpu_kick(record_kick);
        KICKED.store(0, Ordering::SeqCst);
        let before = stats();
        note_ready_on(45);
        note_ready_on(46);
        note_ready_on(45);
        note_ready_on(0);
        let sent = kick_published().expect("the kick is registered");
        assert_eq!(sent & MINE, bit(45) | bit(46));
        assert_eq!(sent & bit(0), 0, "this CPU gets need_resched, not an IPI");
        assert_eq!(kicked(), bit(45) | bit(46), "one IPI to each published CPU");
        let after = stats();
        assert!(after.notified > before.notified);
        assert!(after.targeted >= before.targeted + 2);
    }

    #[test]
    fn wait_kick_halt_clears_halted_before_advancing_exits() {
        struct Observer<'a> {
            kicks: &'a WaitKicks<2>,
            after_hlt: bool,
            saw_cleared_before_exit: bool,
            saw_exit_while_halted: bool,
        }
        impl HaltOps for Observer<'_> {
            fn disable_interrupts(&mut self) {}
            fn enable_interrupts(&mut self) {}
            fn enable_interrupts_and_halt(&mut self) {
                assert!(self.kicks.is_halted(0));
                assert_eq!(self.kicks.halt_exits(0), 0);
                self.after_hlt = true;
            }
            fn work_pending(&mut self) -> bool {
                false
            }
            fn step(&mut self) {
                if self.after_hlt {
                    let halted = self.kicks.is_halted(0);
                    let exits = self.kicks.halt_exits(0);
                    if !halted && exits == 0 {
                        self.saw_cleared_before_exit = true;
                    }
                    if halted && exits > 0 {
                        self.saw_exit_while_halted = true;
                    }
                }
            }
        }

        let kicks = WaitKicks::<2>::new();
        let seq = kicks.ready_seq(0);
        let mut obs = Observer {
            kicks: &kicks,
            after_hlt: false,
            saw_cleared_before_exit: false,
            saw_exit_while_halted: false,
        };
        assert_eq!(halt_sequence(&kicks, 0, seq, &mut obs), HaltOutcome::Halted);
        assert!(
            obs.saw_cleared_before_exit,
            "halted must be cleared before exits advances"
        );
        assert!(
            !obs.saw_exit_while_halted,
            "exits must never advance while halted is still set"
        );
        assert!(!kicks.is_halted(0));
        assert_eq!(kicks.halt_exits(0), 1);
    }

    #[test]
    fn wait_kick_fatal_exit_records_running_queue_and_broadcasts_if_unqueued() {
        use crate::process::{request_process_exit_locked, FatalExitPost, Process, ProcessState};
        let _serial = KERNEL_STATE.lock().unwrap_or_else(|e| e.into_inner());
        register_cpu_kick(record_kick);
        KICKED.store(0, Ordering::SeqCst);
        let _ = kicks().take_published(0);

        // Case 1: Running target on CPU 48 — must record CPU 48 even when
        // another unrelated CPU (47) is already in `published[0]`.
        let pid = 4010;
        crate::steal_hint::hint().note_enqueued(pid, 48, 1);
        note_ready_on(47);
        let mut running = Process::new(pid, 1, alloc::string::String::from("run-kill"), 120);
        running.state = ProcessState::Running;
        running.on_cpu.store(true, Ordering::Release);
        let post = request_process_exit_locked(&mut running, 137, 10);
        assert_eq!(post, FatalExitPost::Kick);
        let sent = kick_published().expect("the kick is registered");
        assert_eq!(
            sent & MINE,
            bit(47) | bit(48),
            "running target's queue CPU must be kicked alongside prior wakes"
        );
        crate::steal_hint::hint().note_removed(pid, 48, 0, false);

        // Case 2: Unqueued target (e.g. Provisioning or migrating) must request
        // Broadcast even if merged with a targeted Kick from another sibling.
        let mut unqueued =
            Process::new(0x178_3502, 1, alloc::string::String::from("unq-kill"), 120);
        unqueued.state = ProcessState::Provisioning;
        let post_unq = request_process_exit_locked(&mut unqueued, 137, 11);
        assert_eq!(post_unq, FatalExitPost::Broadcast);
        assert_eq!(
            FatalExitPost::Kick.merge(post_unq),
            FatalExitPost::Broadcast
        );
        assert_eq!(
            post_unq.merge(FatalExitPost::Kick),
            FatalExitPost::Broadcast
        );
    }

    #[test]
    fn wake_affine_keeps_home_cpu_when_idle_or_halted() {
        let online = 0b1111u64;
        // Home CPU 2 is halted (e.g. parked on the blocked waiter) while CPU 3 is empty idle.
        // Wake-affine must keep CPU 2 for warm cache/TLB and zero migration.
        let picked = select_wake_affine_cpu(
            online,
            2,
            0,
            |cpu| cpu == 3,
            |cpu| cpu == 2,
            |cpu| usize::from(cpu != 3),
        );
        assert_eq!(picked, Some(2));

        // Home CPU 1 is truly idle: must stay on CPU 1.
        let picked_idle =
            select_wake_affine_cpu(online, 1, 0, |cpu| cpu == 1 || cpu == 3, |_| false, |_| 0);
        assert_eq!(picked_idle, Some(1));
    }

    #[test]
    fn wake_affine_migrates_to_idle_cpu_when_home_cpu_busy() {
        let online = 0b1111_1111u64;
        // Home CPU 2 is busy. CPUs 0 and 5 are empty idle; staggered scan after 2
        // must pick CPU 5 first instead of colliding on CPU 0.
        let picked = select_wake_affine_cpu(
            online,
            2,
            0,
            |cpu| cpu == 0 || cpu == 5,
            |cpu| cpu == 3,
            |cpu| if cpu == 0 || cpu == 5 { 0 } else { 1 },
        );
        assert_eq!(picked, Some(5));

        // No empty idle CPU: prefer non-empty idle (CPU 4) over halted CPU (CPU 3).
        let picked_idle = select_wake_affine_cpu(
            online,
            2,
            0,
            |cpu| cpu == 4,
            |cpu| cpu == 3,
            |cpu| if cpu == 4 { 2 } else { 1 },
        );
        assert_eq!(picked_idle, Some(4));

        // No truly idle CPU: fall back to halted CPU with shortest queue (CPU 6).
        let picked_halted = select_wake_affine_cpu(
            online,
            2,
            0,
            |_| false,
            |cpu| cpu == 3 || cpu == 6,
            |cpu| if cpu == 6 { 1 } else { 3 },
        );
        assert_eq!(picked_halted, Some(6));
    }

    #[test]
    fn wake_affine_stays_on_home_cpu_when_all_cpus_busy() {
        let online = 0b1111u64;
        // Every CPU is busy running tasks; home CPU 1 has queue_len 3 while CPU 0 has 1.
        // Saturated wake-affine must keep home CPU 1 to prevent migration churn.
        let picked = select_wake_affine_cpu(
            online,
            1,
            0,
            |_| false,
            |_| false,
            |cpu| if cpu == 1 { 3 } else { 1 },
        );
        assert_eq!(picked, Some(1));
    }

    #[test]
    fn wake_affine_respects_allowed_cpus_and_cpuset_isolation() {
        let online = 0b1111_1111u64;
        // Only CPUs 4 and 6 are allowed. Even though CPU 3 is empty idle and CPU 2
        // is halted, selection must never escape {4, 6}; halted CPU 6 wins.
        let allowed = bit(4) | bit(6);
        let picked = select_wake_affine_cpu(
            online,
            2,
            allowed,
            |cpu| cpu == 3,
            |cpu| cpu == 2 || cpu == 6,
            |cpu| if cpu == 4 { 1 } else { 2 },
        );
        assert_eq!(picked, Some(6));

        // Saturated and home CPU 2 disallowed: must pick least-loaded allowed CPU (4).
        let picked_sat = select_wake_affine_cpu(
            online,
            2,
            allowed,
            |_| false,
            |_| false,
            |cpu| if cpu == 4 { 1 } else { 3 },
        );
        assert_eq!(picked_sat, Some(4));

        // Disjoint affinity mask: returns None (fail closed).
        assert_eq!(
            select_wake_affine_cpu(online, 2, bit(10), |_| true, |_| false, |_| 0),
            None
        );
    }

    #[test]
    fn new_work_spreads_across_idle_cpus_before_packing_preferred() {
        let online = 0b1111u64;
        // Parent running on busy CPU 0 (queue_len=1); CPUs 1..3 are idle with len=0.
        // Successive spawns must land on CPUs 1, 2, 3 instead of stacking on CPU 0.
        let mut lens = [1usize, 0, 0, 0];
        let mut picked = [0usize; 3];
        for slot in &mut picked {
            let cpu =
                select_target_cpu_for_new_work(online, 0, 0, 1, |c| c != 0, |_| false, |c| lens[c])
                    .expect("eligible idle CPU");
            lens[cpu] += 1;
            *slot = cpu;
        }
        assert_eq!(picked, [1, 2, 3]);

        // When preferred CPU itself is idle (e.g. boot), stay on preferred CPU.
        let boot_pick = select_target_cpu_for_new_work(online, 0, 0, 1, |_| true, |_| false, |_| 0);
        assert_eq!(boot_pick, Some(0));

        // When all CPUs are busy within LOAD_IMBALANCE_THRESHOLD (1), preserve preferred CPU.
        let sat_keep = select_target_cpu_for_new_work(
            online,
            2,
            0,
            1,
            |_| false,
            |_| false,
            |c| if c == 2 { 2 } else { 1 },
        );
        assert_eq!(sat_keep, Some(2));

        // When imbalance exceeds threshold, move to least-loaded allowed CPU (staggered after 2 -> 3).
        let sat_spread = select_target_cpu_for_new_work(
            online,
            2,
            0,
            1,
            |_| false,
            |_| false,
            |c| if c == 2 { 3 } else { 1 },
        );
        assert_eq!(sat_spread, Some(3));
    }

    #[test]
    fn process_resched_steal_gate_skips_running_syscall_returns() {
        assert!(!should_try_steal_on_process_resched(false, false, false));
        assert!(should_try_steal_on_process_resched(true, false, false));
        assert!(should_try_steal_on_process_resched(false, true, false));
        assert!(should_try_steal_on_process_resched(false, false, true));
    }

    #[test]
    fn wake_affine_relocates_disallowed_idle_home_cpu() {
        // Regression test (Codex audit Finding 1): waiter sits on idle CPU 0
        // after its affinity narrowed to busy CPU 1 only. Placement must NOT
        // keep idle CPU 0; it must select allowed CPU 1 so the waiter is
        // migrated and armed there instead of stranding on CPU 0.
        let online = bit(0) | bit(1);
        let picked = select_wake_affine_cpu(online, 0, bit(1), |cpu| cpu == 0, |_| false, |_| 1);
        assert_eq!(picked, Some(1));
    }

    #[test]
    fn wake_affine_hook_dispatches_registered_pid() {
        static SEEN_PID: AtomicU64 = AtomicU64::new(0);
        static SEEN_GEN: AtomicU64 = AtomicU64::new(0);
        fn record_wake(pid: usize, generation: u64) {
            SEEN_PID.store(pid as u64, Ordering::SeqCst);
            SEEN_GEN.store(generation, Ordering::SeqCst);
        }

        let _serial = KERNEL_STATE.lock().unwrap_or_else(|e| e.into_inner());
        SEEN_PID.store(0, Ordering::SeqCst);
        SEEN_GEN.store(0, Ordering::SeqCst);
        register_wake_affine_hook(record_wake);
        note_wake_affine(4242, 99);
        assert_eq!(SEEN_PID.load(Ordering::SeqCst), 4242);
        assert_eq!(SEEN_GEN.load(Ordering::SeqCst), 99);
    }
}
