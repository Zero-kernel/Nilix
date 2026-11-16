//! C3 E3 (#90) DIAGNOSTIC, not for merge: what did the per-stack broadcast of
//! kernel-stack reclaim do besides flushing?
//!
//! One kernel, several behaviours. From the first `/proc/schedstat` read on,
//! the reclaim path changes its [`mode`] every [`MODE_WINDOW_TICKS`], in a
//! fixed cycle, so the modes are compared within one boot:
//!
//! - `BATCH`: the flush batch as merged in the change under test.
//! - `PARENT`: one broadcast flush per stack inside the `PT_LOCK` section and
//!   a direct free, as before the batch.
//! - `KICK_ALL`: the batch, plus a reschedule IPI to every other CPU and a
//!   local reschedule request for each deferred stack.
//! - `KICK_HALTED`: the batch, plus a reschedule IPI to each other CPU that
//!   is halted at that moment.
//! - `KICK_RUNNING`: the batch, plus a local reschedule request and a
//!   reschedule IPI to each other CPU that is not halted.
//! - `FLUSH_EACH`: the batch's code path, but every RCU drain pass completes
//!   whatever waits: about one broadcast flush per stack again, outside the
//!   `PT_LOCK` section.
//!
//! This branch is for 16 vCPUs with E2's diagnostic runner (a schedstat copy
//! after every round, which takes about 5 s there): a window is 40000 ticks
//! and the cycle is [`MODE_CYCLE`]. The kernel also prints `E3_MODE <mode>
//! <window>` on the console at each window change.
//!
//! `/proc/schedstat` gets `e3_mode <mode> <window>` on every read and, at most
//! once per [`REPORT_INTERVAL_TICKS`], three cumulative tables per mode:
//!
//! - `e3_ready <mode>`: Ready publications by source.
//! - `e3_halt <mode> <site>`: completed halts by the interrupt that ended
//!   them, as `count/tsc` for tick, reschedule IPI, TLB IPI and other.
//! - `e3_disp <mode> <source> <context> <stolen> <count> <latency> <halted>`:
//!   task dispatches by the source that made the task Ready, by what the
//!   dispatching CPU was doing, and by whether the task was stolen in the same
//!   pass. `latency` is Ready-to-dispatch; `halted` is the part of it that the
//!   dispatching CPU spent in its last halt.
//!
//! TSC sums are printed in units of 1024 cycles. Everything is lock-free and
//! callable from interrupt context.

use core::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use cpu_local::current_cpu_id;
use spin::Once;

/// How kernel-stack reclaim behaves in the current window.
pub mod mode {
    pub const BATCH: usize = 0;
    pub const PARENT: usize = 1;
    pub const KICK_ALL: usize = 2;
    pub const KICK_HALTED: usize = 3;
    pub const KICK_RUNNING: usize = 4;
    pub const FLUSH_EACH: usize = 5;
    pub const COUNT: usize = 6;
}

/// What made a task Ready.
pub mod src {
    pub const NONE: u8 = 0;
    /// A `WaitQueue` wake: futex, pipe, socket.
    pub const WAITQ: u8 = 1;
    /// A child-exit wake of a waiting parent.
    pub const CHILD: u8 = 2;
    /// Any other Blocked-to-Ready wake.
    pub const WAKE: u8 = 3;
    /// A running task that was switched out or lost its time slice.
    pub const PREEMPT: u8 = 4;
    /// A new or explicitly re-published task.
    pub const NEW: u8 = 5;
    pub const OTHER: u8 = 6;
    pub const COUNT: usize = 7;
}

/// Where a CPU halts.
pub mod site {
    pub const IDLE_AP: u8 = 1;
    pub const IDLE_BSP: u8 = 2;
    /// `terminate_self_and_halt`: an exited task retrying its last switch.
    pub const EXIT: u8 = 3;
    /// The timer-interrupt exit path's retry loop.
    pub const IRQ_EXIT: u8 = 4;
    /// `yield_and_halt`: a killable kernel-side polling wait.
    pub const YIELD: u8 = 5;
    pub const COUNT: usize = 6;
}

/// The interrupt that ended a halt.
pub mod irq {
    pub const TICK: u8 = 1;
    pub const RESCHED: u8 = 2;
    pub const TLB: u8 = 3;
    pub const OTHER: u8 = 4;
    pub const COUNT: usize = 5;
}

/// What the dispatching CPU ran before the dispatch.
pub mod old {
    pub const IDLE: u8 = 0;
    pub const BLOCKED: u8 = 1;
    pub const TERMINAL: u8 = 2;
    pub const RUNNABLE: u8 = 3;
}

/// Dispatch contexts: idle by wake vector (0 = no halt), a blocked task, a
/// terminal task by wake vector, a runnable task.
const CTX_BLOCKED: usize = irq::COUNT;
const CTX_TERMINAL: usize = CTX_BLOCKED + 1;
const CTX_RUNNABLE: usize = CTX_TERMINAL + irq::COUNT;
const CTX_COUNT: usize = CTX_RUNNABLE + 1;

const CPUS: usize = cpu_local::max_cpus();
const PIDS: usize = crate::process::PID_MAX + 1;
const MODE_WINDOW_TICKS: u64 = 40_000;
/// The modes this branch cycles through.
const MODE_CYCLE: [usize; 3] = [mode::BATCH, mode::PARENT, mode::KICK_ALL];
const REPORT_INTERVAL_TICKS: u64 = 100_000;

/// Whether the current window completes the flush batch in every drain pass.
pub fn completes_every_drain() -> bool {
    matches!(current_mode(), mode::PARENT | mode::FLUSH_EACH)
}

/// The tick of the first `/proc/schedstat` read; 0 until then (`BATCH`).
static MODE_BASE_TICK: AtomicU64 = AtomicU64::new(0);
static KICK_HOOK: Once<fn(usize)> = Once::new();

static READY_TSC: [AtomicU64; PIDS] = [const { AtomicU64::new(0) }; PIDS];
static READY_SRC: [AtomicU8; PIDS] = [const { AtomicU8::new(0) }; PIDS];
static SRC_HINT: [AtomicU8; CPUS] = [const { AtomicU8::new(0) }; CPUS];

static HALT_SITE: [AtomicU8; CPUS] = [const { AtomicU8::new(0) }; CPUS];
static HALT_START: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];
static HALT_PREV: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];
static HALT_BEST_GAP: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];
static HALT_BEST_KIND: [AtomicU8; CPUS] = [const { AtomicU8::new(0) }; CPUS];

/// The last completed halt of each CPU, until a dispatch consumes it.
static LAST_START: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];
static LAST_END: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];
static LAST_VEC: [AtomicU8; CPUS] = [const { AtomicU8::new(0) }; CPUS];
static STOLEN: [AtomicUsize; CPUS] = [const { AtomicUsize::new(0) }; CPUS];

type ReadyTable = [[AtomicU64; src::COUNT]; mode::COUNT];
static READY_COUNT: ReadyTable = [const { [const { AtomicU64::new(0) }; src::COUNT] }; mode::COUNT];
type HaltTable = [[[AtomicU64; irq::COUNT]; site::COUNT]; mode::COUNT];
static HALT_COUNT: HaltTable =
    [const { [const { [const { AtomicU64::new(0) }; irq::COUNT] }; site::COUNT] }; mode::COUNT];
static HALT_TSC: HaltTable =
    [const { [const { [const { AtomicU64::new(0) }; irq::COUNT] }; site::COUNT] }; mode::COUNT];
type DispatchTable = [[[[AtomicU64; 2]; CTX_COUNT]; src::COUNT]; mode::COUNT];
static DISP_COUNT: DispatchTable = [const {
    [const { [const { [const { AtomicU64::new(0) }; 2] }; CTX_COUNT] }; src::COUNT]
}; mode::COUNT];
static DISP_LATENCY: DispatchTable = [const {
    [const { [const { [const { AtomicU64::new(0) }; 2] }; CTX_COUNT] }; src::COUNT]
}; mode::COUNT];
static DISP_HALTED: DispatchTable = [const {
    [const { [const { [const { AtomicU64::new(0) }; 2] }; CTX_COUNT] }; src::COUNT]
}; mode::COUNT];
static LAST_REPORT_TICK: AtomicU64 = AtomicU64::new(0);

#[inline]
fn tsc() -> u64 {
    // SAFETY: RDTSC has no preconditions.
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[inline]
fn add(counter: &AtomicU64, value: u64) {
    // Diagnostic counter only; wrap is harmless. lint-fetch-add: allow
    counter.fetch_add(value, Ordering::Relaxed);
}

/// The window since the first `/proc/schedstat` read, if there was one.
fn window(now_tick: u64) -> Option<u64> {
    match MODE_BASE_TICK.load(Ordering::Relaxed) {
        0 => None,
        base => Some(now_tick.saturating_sub(base) / MODE_WINDOW_TICKS),
    }
}

/// The reclaim mode of the current window.
pub fn current_mode() -> usize {
    window(crate::get_ticks()).map_or(mode::BATCH, mode_of_window)
}

fn mode_of_window(window: u64) -> usize {
    MODE_CYCLE[(window % MODE_CYCLE.len() as u64) as usize]
}

/// The last window announced on the console, plus one (0: none yet).
static ANNOUNCED_WINDOW: AtomicU64 = AtomicU64::new(0);

/// Process context, interrupts enabled: announce a new window once.
pub fn announce_window() {
    let Some(window) = window(crate::get_ticks()) else {
        return;
    };
    if ANNOUNCED_WINDOW.load(Ordering::Relaxed) == window + 1
        || ANNOUNCED_WINDOW.swap(window + 1, Ordering::Relaxed) == window + 1
    {
        return;
    }
    klog::klog_force!("E3_MODE {} {}", mode_of_window(window), window);
}

/// Register the scheduler's selective reschedule kick.
pub fn register_kick(hook: fn(usize)) {
    KICK_HOOK.call_once(|| hook);
}

/// A stack joined the flush batch: send the current mode's kicks, if any.
pub fn kick_after_defer() {
    let mode = current_mode();
    if (mode::KICK_ALL..=mode::KICK_RUNNING).contains(&mode) {
        if let Some(hook) = KICK_HOOK.get() {
            hook(mode);
        }
    }
}

/// Whether `cpu` is between `halt_begin` and `halt_end`.
pub fn is_halted(cpu: usize) -> bool {
    HALT_SITE
        .get(cpu)
        .is_some_and(|site| site.load(Ordering::Acquire) != 0)
}

/// Name the source of the wakes this CPU performs until the hint is reset to
/// [`src::NONE`]. Call with interrupts disabled.
pub fn src_hint(source: u8) {
    if let Some(hint) = SRC_HINT.get(current_cpu_id()) {
        hint.store(source, Ordering::Relaxed);
    }
}

/// A task starts a Ready epoch. A hint replaces only the generic wake source.
pub fn note_ready(pid: usize, default: u8) {
    let hint = SRC_HINT
        .get(current_cpu_id())
        .map_or(src::NONE, |hint| hint.load(Ordering::Relaxed));
    let source = if default == src::WAKE && hint != src::NONE {
        hint
    } else {
        default
    };
    if let (Some(stamp), Some(slot)) = (READY_TSC.get(pid), READY_SRC.get(pid)) {
        stamp.store(tsc(), Ordering::Relaxed);
        slot.store(source, Ordering::Relaxed);
    }
    add(&READY_COUNT[current_mode()][source as usize % src::COUNT], 1);
}

/// This CPU is about to halt at `site`.
pub fn halt_begin(site: u8) {
    let cpu = current_cpu_id();
    if cpu >= CPUS {
        return;
    }
    let now = tsc();
    HALT_START[cpu].store(now, Ordering::Relaxed);
    HALT_PREV[cpu].store(now, Ordering::Relaxed);
    HALT_BEST_GAP[cpu].store(0, Ordering::Relaxed);
    HALT_BEST_KIND[cpu].store(0, Ordering::Relaxed);
    HALT_SITE[cpu].store(site, Ordering::Release);
}

/// An interrupt of `kind` arrived. While this CPU is between `halt_begin` and
/// `halt_end`, the interrupt after the longest quiet interval is the one that
/// ended the halt (an interrupt can also arrive just before HLT executes).
pub fn note_irq(kind: u8) {
    let cpu = current_cpu_id();
    if cpu >= CPUS || HALT_SITE[cpu].load(Ordering::Acquire) == 0 {
        return;
    }
    let now = tsc();
    let gap = now.saturating_sub(HALT_PREV[cpu].swap(now, Ordering::Relaxed));
    if gap > HALT_BEST_GAP[cpu].load(Ordering::Relaxed) {
        HALT_BEST_GAP[cpu].store(gap, Ordering::Relaxed);
        HALT_BEST_KIND[cpu].store(kind, Ordering::Relaxed);
    }
}

/// HLT returned on this CPU.
pub fn halt_end() {
    let cpu = current_cpu_id();
    if cpu >= CPUS {
        return;
    }
    let site = HALT_SITE[cpu].swap(0, Ordering::AcqRel) as usize;
    if site == 0 || site >= site::COUNT {
        return;
    }
    let now = tsc();
    let start = HALT_START[cpu].load(Ordering::Relaxed);
    let kind = match HALT_BEST_KIND[cpu].load(Ordering::Relaxed) {
        0 => irq::OTHER,
        kind => kind,
    };
    let mode = current_mode();
    add(&HALT_COUNT[mode][site][kind as usize % irq::COUNT], 1);
    add(
        &HALT_TSC[mode][site][kind as usize % irq::COUNT],
        now.saturating_sub(start),
    );
    LAST_START[cpu].store(start, Ordering::Relaxed);
    LAST_VEC[cpu].store(kind, Ordering::Relaxed);
    LAST_END[cpu].store(now, Ordering::Relaxed);
}

/// This CPU's idle loop goes round again without halting.
pub fn halt_skip() {
    if let Some(end) = LAST_END.get(current_cpu_id()) {
        end.store(0, Ordering::Relaxed);
    }
}

/// This CPU stole `pid` into its own queue.
pub fn note_stolen(pid: usize) {
    if let Some(stolen) = STOLEN.get(current_cpu_id()) {
        stolen.store(pid, Ordering::Relaxed);
    }
}

/// This CPU dispatches `pid`; `old` says what it ran until now.
pub fn note_dispatch(pid: usize, old: u8) {
    let cpu = current_cpu_id();
    if cpu >= CPUS || pid >= PIDS {
        return;
    }
    let now = tsc();
    let source = READY_SRC[pid].swap(src::NONE, Ordering::Relaxed) as usize % src::COUNT;
    let ready = READY_TSC[pid].load(Ordering::Relaxed);
    let stolen = usize::from(STOLEN[cpu].swap(0, Ordering::Relaxed) == pid);
    let end = LAST_END[cpu].swap(0, Ordering::Relaxed);
    let halted_context = old == old::IDLE || old == old::TERMINAL;
    let (vector, halted) = if end != 0 && halted_context {
        let from = ready.max(LAST_START[cpu].load(Ordering::Relaxed));
        (
            LAST_VEC[cpu].load(Ordering::Relaxed) as usize % irq::COUNT,
            end.saturating_sub(from),
        )
    } else {
        (0, 0)
    };
    let context = match old {
        old::IDLE => vector,
        old::BLOCKED => CTX_BLOCKED,
        old::TERMINAL => CTX_TERMINAL + vector,
        _ => CTX_RUNNABLE,
    };
    let mode = current_mode();
    add(&DISP_COUNT[mode][source][context][stolen], 1);
    if source != src::NONE as usize {
        add(
            &DISP_LATENCY[mode][source][context][stolen],
            now.saturating_sub(ready),
        );
        add(&DISP_HALTED[mode][source][context][stolen], halted);
    }
}

/// Append the mode line, and the tables at most once per interval, to
/// `/proc/schedstat`. The first call starts the mode cycle.
pub fn write_report(out: &mut impl core::fmt::Write, now_tick: u64) -> core::fmt::Result {
    let _ = MODE_BASE_TICK.compare_exchange(
        0,
        now_tick.max(1),
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
    let window = window(now_tick).unwrap_or(0);
    writeln!(out, "e3_mode {} {}", mode_of_window(window), window)?;

    let last = LAST_REPORT_TICK.load(Ordering::Relaxed);
    if now_tick.saturating_sub(last) < REPORT_INTERVAL_TICKS
        || LAST_REPORT_TICK
            .compare_exchange(last, now_tick, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return Ok(());
    }
    for mode in 0..mode::COUNT {
        write!(out, "e3_ready {}", mode)?;
        for count in &READY_COUNT[mode][1..] {
            write!(out, " {}", count.load(Ordering::Relaxed))?;
        }
        out.write_str("\n")?;
        for site in 1..site::COUNT {
            if HALT_COUNT[mode][site]
                .iter()
                .all(|count| count.load(Ordering::Relaxed) == 0)
            {
                continue;
            }
            write!(out, "e3_halt {} {}", mode, site)?;
            for kind in 1..irq::COUNT {
                write!(
                    out,
                    " {}/{}",
                    HALT_COUNT[mode][site][kind].load(Ordering::Relaxed),
                    HALT_TSC[mode][site][kind].load(Ordering::Relaxed) >> 10
                )?;
            }
            out.write_str("\n")?;
        }
        for source in 0..src::COUNT {
            for context in 0..CTX_COUNT {
                for stolen in 0..2 {
                    let count = DISP_COUNT[mode][source][context][stolen].load(Ordering::Relaxed);
                    if count == 0 {
                        continue;
                    }
                    writeln!(
                        out,
                        "e3_disp {} {} {} {} {} {} {}",
                        mode,
                        source,
                        context,
                        stolen,
                        count,
                        DISP_LATENCY[mode][source][context][stolen].load(Ordering::Relaxed) >> 10,
                        DISP_HALTED[mode][source][context][stolen].load(Ordering::Relaxed) >> 10
                    )?;
                }
            }
        }
    }
    Ok(())
}
