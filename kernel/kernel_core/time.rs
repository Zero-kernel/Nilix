//! 简单时间管理模块
//!
//! 提供基于时钟中断的时间戳支持

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::{Mutex, Once};

/// 全局时钟计数器（每次时钟中断递增）
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// 系统启动时间的 TSC 值（用于更精确的时间测量）
static BOOT_TSC: AtomicU64 = AtomicU64::new(0);

/// N2.6b: Optional high-resolution monotonic nanosecond clock callback
/// (registered by `arch::hpet` when a 64-bit HPET counter is present).
type MonotonicNsProvider = fn() -> Option<u64>;
static MONOTONIC_NS_PROVIDER: Once<MonotonicNsProvider> = Once::new();

/// Effective high-resolution clock period in nanoseconds (defaults to 1 ms
/// PIT tick resolution until HPET registers its finer period).
static HIGHRES_RESOLUTION_NS: AtomicU64 = AtomicU64::new(1_000_000);

/// Monotonicity floor: guarantees `monotonic_ns()` never regresses across CPUs
/// or across provider activation.
static LAST_MONOTONIC_NS: AtomicU64 = AtomicU64::new(0);

/// N2.6b: Offset added to `monotonic_ns()` to produce Unix epoch nanoseconds
/// for `CLOCK_REALTIME` / `gettimeofday` (seeded from CMOS RTC at boot).
static WALL_CLOCK_OFFSET_NS: AtomicU64 = AtomicU64::new(0);

/// N2.6b: Earliest armed process timer (ITIMER_REAL or POSIX timer) expiry in
/// monotonic nanoseconds (`u64::MAX` when no timers are armed).
static NEXT_TIMER_EXPIRY_NS: AtomicU64 = AtomicU64::new(u64::MAX);

/// N2.6b: Set from `on_timer_tick()` when `monotonic_ns() >= NEXT_TIMER_EXPIRY_NS`;
/// drained in safe process context by `drain_deferred_process_timers()`.
static PROCESS_TIMER_DEFERRED: AtomicBool = AtomicBool::new(false);

/// Last TIME_WAIT sweep timestamp (ms)
static LAST_TIME_WAIT_SWEEP: AtomicU64 = AtomicU64::new(0);

/// Last TCP timer sweep timestamp (ms) for retransmission/FIN timers.
static LAST_TCP_TIMER_SWEEP: AtomicU64 = AtomicU64::new(0);

/// R65-6 FIX: Deferred TCP timer work pending flag.
///
/// Set when IRQ-time timer processing is incomplete (lock contention or
/// exceeded socket budget). Cleared when work is drained in safe context.
static TCP_TIMER_DEFERRED: AtomicBool = AtomicBool::new(false);

/// R65-6 FIX: Deferred timestamp for retry.
static TCP_TIMER_DEFERRED_TS: AtomicU64 = AtomicU64::new(0);

/// R65-6 FIX: Whether TIME_WAIT sweep is deferred.
static TCP_TIMER_DEFERRED_TW: AtomicBool = AtomicBool::new(false);
/// Monotonic publication generation for deferred timer work.  A drain may run
/// concurrently with an IRQ producer; clearing the flag is valid only if no
/// newer generation was published in the meantime.
static TCP_TIMER_DEFERRED_GEN: AtomicU64 = AtomicU64::new(0);

/// TCP timer sweep interval in milliseconds (data/FIN retransmission).
///
/// R53-3 FIX: Reduced from 5s to 200ms to support RFC 6298 retransmission.
/// With TCP_MIN_RTO_MS = 1000ms, a 200ms sweep interval means retransmissions
/// fire within 200ms of RTO expiry (worst case 1200ms from segment send).
///
/// 200ms balances:
/// - Responsiveness: 5x faster than previous 1s minimum
/// - CPU overhead: 25x less frequent than Codex-suggested 100ms
/// - Alignment: Matches RTO_CLOCK_GRANULARITY_US (100ms) reasonably well
const TCP_TIMER_SWEEP_INTERVAL_MS: u64 = 200;

/// TIME_WAIT sweep interval in milliseconds (coarse cleanup).
///
/// TIME_WAIT expiry is 120s (2MSL), so a 1s cadence is sufficient
/// while reducing load compared to the fast retransmission timer.
const TIME_WAIT_SWEEP_INTERVAL_MS: u64 = 1000;

/// 初始化时间子系统
pub fn init() {
    // 记录启动时的 TSC 值
    let tsc = read_tsc();
    BOOT_TSC.store(tsc, Ordering::SeqCst);
}

/// N2.6b: Register a lock-free high-resolution monotonic nanosecond clock source
/// (e.g. 64-bit HPET main counter) and its effective resolution in nanoseconds.
pub fn register_monotonic_ns_provider(provider: MonotonicNsProvider, resolution_ns: u64) {
    let clamped_res = resolution_ns.max(1);
    HIGHRES_RESOLUTION_NS.store(clamped_res, Ordering::Release);
    MONOTONIC_NS_PROVIDER.call_once(|| provider);
    // Advance floor so monotonic_ns() stays smooth after registration.
    let _ = monotonic_ns();
}

/// N2.6b: Seed the wall-clock offset for `CLOCK_REALTIME` / `gettimeofday`
/// from the boot-time CMOS RTC reading (UTC Unix epoch seconds).
pub fn set_wall_clock_epoch_secs(unix_secs: u64) {
    let epoch_ns = unix_secs.saturating_mul(1_000_000_000);
    let mono = monotonic_ns();
    WALL_CLOCK_OFFSET_NS.store(epoch_ns.saturating_sub(mono), Ordering::Release);
}

/// N2.6b: Current wall-clock offset (`realtime_ns - monotonic_ns`).
#[inline]
pub fn wall_clock_offset_ns() -> u64 {
    WALL_CLOCK_OFFSET_NS.load(Ordering::Acquire)
}

/// N2.6b: Current monotonic uptime in nanoseconds.
///
/// Uses the registered 64-bit HPET provider when available, falling back to
/// `get_ticks() * 1_000_000`. Enforces strict cross-CPU monotonicity via
/// `fetch_max`.
#[inline]
pub fn monotonic_ns() -> u64 {
    let raw = MONOTONIC_NS_PROVIDER
        .get()
        .and_then(|f| f())
        .unwrap_or_else(|| get_ticks().saturating_mul(1_000_000));
    let prev = LAST_MONOTONIC_NS.fetch_max(raw, Ordering::AcqRel);
    raw.max(prev)
}

/// N2.6b: Current wall-clock Unix epoch time in nanoseconds (`CLOCK_REALTIME`).
#[inline]
pub fn realtime_ns() -> u64 {
    WALL_CLOCK_OFFSET_NS
        .load(Ordering::Acquire)
        .saturating_add(monotonic_ns())
}

/// N2.6b: Effective clock resolution in nanoseconds for `clock_getres(2)`.
#[inline]
pub fn clock_resolution_ns(coarse: bool) -> u64 {
    if coarse {
        1_000_000
    } else {
        HIGHRES_RESOLUTION_NS.load(Ordering::Acquire).max(1)
    }
}

/// 时钟中断处理 - 递增时钟计数器
///
/// 应由定时器中断处理程序调用
#[inline]
pub fn on_timer_tick() {
    let current = TICK_COUNT.fetch_add(1, Ordering::SeqCst) + 1; // lint-fetch-add: allow (monotonic counter)

    // N2.6b: Lock-free single-load check for expired process itimers / POSIX timers.
    // Delivery runs in safe process context via `drain_deferred_process_timers()`.
    let next_exp = NEXT_TIMER_EXPIRY_NS.load(Ordering::Acquire);
    if next_exp != u64::MAX && monotonic_ns() >= next_exp {
        PROCESS_TIMER_DEFERRED.store(true, Ordering::Release);
        crate::request_resched_from_irq();
    }

    // R53-3 FIX: Drive TCP timers at two frequencies:
    // - Fast timer (200ms): Data/FIN retransmission checks
    // - Slow timer (1s): TIME_WAIT cleanup
    //
    // This enables responsive retransmission (within 200ms of RTO expiry)
    // while avoiding excessive TIME_WAIT iteration overhead.

    let last_rto = LAST_TCP_TIMER_SWEEP.load(Ordering::Relaxed);
    let last_tw = LAST_TIME_WAIT_SWEEP.load(Ordering::Relaxed);

    let need_rto = current.saturating_sub(last_rto) >= TCP_TIMER_SWEEP_INTERVAL_MS;
    let need_tw = current.saturating_sub(last_tw) >= TIME_WAIT_SWEEP_INTERVAL_MS;

    // R65-6 FIX: Check if deferred work is pending from previous tick
    let had_deferred = TCP_TIMER_DEFERRED.load(Ordering::Acquire);

    // Early exit if neither timer has fired and no deferred work
    if !need_rto && !need_tw && !had_deferred {
        return;
    }

    let mut run_rto = false;
    let mut run_tw = false;

    // Claim the RTO timer (CAS to avoid concurrent sweeps)
    if need_rto
        && LAST_TCP_TIMER_SWEEP
            .compare_exchange(last_rto, current, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        run_rto = true;
    }

    // Claim the TIME_WAIT timer
    if need_tw
        && LAST_TIME_WAIT_SWEEP
            .compare_exchange(last_tw, current, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        run_tw = true;
    }

    // R65-6 FIX: Include deferred TIME_WAIT sweep
    if had_deferred && TCP_TIMER_DEFERRED_TW.load(Ordering::Relaxed) {
        run_tw = true;
    }

    // R150-1 FIX: Never run TCP timers from timer IRQ context.
    //
    // run_tcp_timers() allocates heap memory (Vec, build_tcp_segment → Vec<u8>)
    // and transmits packets (transmit_tcp_segment → device spinlock + DMA alloc).
    // If the timer IRQ fires while the interrupted CPU holds the heap allocator
    // lock or the net device lock, the IRQ spins forever on the same lock
    // (single-CPU deadlock, no interrupt nesting possible).
    //
    // All TCP timer work (retransmit, FIN, keepalive, SYN sweep, cleanup) is
    // deferred to process context via drain_deferred_tcp_timers() which is called
    // from reschedule_if_needed() at every syscall return.
    if run_rto || run_tw || had_deferred {
        // Store timestamp and TW flag before setting the DEFERRED flag (Release)
        // so drain_deferred_tcp_timers() sees consistent values when it loads
        // DEFERRED with Acquire.
        TCP_TIMER_DEFERRED_TS.store(current, Ordering::Relaxed);
        if run_tw {
            TCP_TIMER_DEFERRED_TW.store(true, Ordering::Relaxed);
        }
        TCP_TIMER_DEFERRED_GEN
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                generation.checked_add(1)
            })
            .ok();
        TCP_TIMER_DEFERRED.store(true, Ordering::Release);
        crate::request_resched_from_irq();
    }
}

/// 获取当前时钟计数（自启动以来的时钟周期数）
#[inline]
pub fn get_ticks() -> u64 {
    TICK_COUNT.load(Ordering::SeqCst)
}

/// 获取当前时间戳（毫秒）
///
/// BSP PIT channel 0 is programmed for a nominal 1000 Hz; AP ticks do not
/// advance this counter. This is serviced-tick time, not an independent wall
/// clock: long IRQ-disabled intervals can coalesce hardware ticks.
#[inline]
pub fn current_timestamp_ms() -> u64 {
    get_ticks()
}

/// 读取 CPU 的时间戳计数器 (TSC)
#[inline]
pub fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let low: u32;
        let high: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nostack, nomem)
        );
        ((high as u64) << 32) | (low as u64)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// 获取自启动以来的 TSC 差值
pub fn tsc_since_boot() -> u64 {
    let current = read_tsc();
    let boot = BOOT_TSC.load(Ordering::SeqCst);
    current.saturating_sub(boot)
}

/// R65-6 FIX: Drain deferred TCP timer work in safe (non-IRQ) context.
///
/// Called from syscall return path to ensure timer work is not starved when
/// IRQ-time processing was incomplete due to lock contention or exceeded
/// socket budget.
///
/// This provides a safety net: even if IRQ-time timer processing is repeatedly
/// blocked, the work will eventually complete when a process makes a syscall.
pub fn drain_deferred_tcp_timers() {
    // Fast path: nothing deferred
    if !TCP_TIMER_DEFERRED.load(Ordering::Acquire) {
        return;
    }

    // Get deferred parameters
    let ts = TCP_TIMER_DEFERRED_TS.load(Ordering::Relaxed);
    let sweep_tw = TCP_TIMER_DEFERRED_TW.load(Ordering::Relaxed);
    let generation = TCP_TIMER_DEFERRED_GEN.load(Ordering::Acquire);
    let current = if ts == 0 { current_timestamp_ms() } else { ts };

    // R151-9 FIX: Drive fragment reassembly cleanup from the slow TCP timer sweep.
    // cleanup_expired_fragments() is never called from the timer IRQ infrastructure
    // (handle_timer_tick in stack.rs is not wired to kernel/kernel_core/time.rs).
    // Without periodic cleanup, expired fragment queues persist indefinitely,
    // pinning up to 64 MB (GLOBAL_MAX_FRAG_BYTES) and disabling reassembly.
    if sweep_tw {
        let _ = net::handle_timer_tick(current);
    }

    // Use blocking variant which will wait for locks
    let completed = net::socket_table().run_tcp_timers_blocking(current, sweep_tw);

    if completed {
        // Claim the flag only after taking a generation snapshot, then verify
        // the generation again after the claim.  A timer IRQ can publish a
        // newer generation between the first load and the flag CAS; without
        // this second check that publication could be cleared accidentally.
        let before = TCP_TIMER_DEFERRED_GEN.load(Ordering::Acquire);
        if before == generation
            && TCP_TIMER_DEFERRED
                .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            let after = TCP_TIMER_DEFERRED_GEN.load(Ordering::Acquire);
            if after == before {
                // No publisher raced the claim.  Leave the timestamp/TW
                // metadata untouched: a publisher may begin its metadata
                // stores immediately after this check, and clearing either
                // field here would overwrite that newer publication.  The
                // fields are consumed only while DEFERRED is true and are
                // refreshed by every producer before it sets that flag.
            } else {
                // A publisher raced after the claim.  Keep the work visible;
                // the publisher may still be between its metadata stores and
                // the Release flag store, so re-arming here is required.
                TCP_TIMER_DEFERRED.store(true, Ordering::Release);
            }
        }
    }
    // If still incomplete, leave deferred flag set for next opportunity
}

/// D3-NETNS-DATAPLANE RX-INGRESS: bring-up process-context RX drain, sibling of
/// `drain_deferred_tcp_timers` at the same deferred-work drain site.
///
/// Unconditional per-pass call is safe: all rate limiting lives in the net
/// crate (`rx_ingress_poll_throttled` — quiesce flag, ~10ms window claimed by
/// CAS, non-reentrant guard), and the drain site's `process_deferred_work_ready`
/// gate guarantees `kernel_core::init` (which registers the netns device hooks)
/// completed before the first call, satisfying the RX-WIRING start-gate the
/// poll asserts. Uses the same process-context clock as the TCP drain.
pub fn poll_net_rx_ingress() {
    let _ = net::rx_ingress_poll_throttled(current_timestamp_ms());
}

// ============================================================================
// N2.6b: Bounded Process Interval Timers (`ITIMER_REAL`/`alarm`) & POSIX Timers
// ============================================================================
//
// Stored out-of-line in a global lock-protected registry keyed by `tgid` so
// `Process` and `ThreadGroup` incur ZERO per-PCB memory overhead. IRQ context
// never acquires `TIMER_REGISTRY`; it only reads `NEXT_TIMER_EXPIRY_NS` and
// sets `PROCESS_TIMER_DEFERRED` for process-context delivery.

/// Maximum number of active POSIX `timer_create` timers per process (thread group).
pub const MAX_POSIX_TIMERS_PER_PROCESS: usize = 32;
/// Global safety cap on `ITIMER_REAL` entries to prevent unbounded kernel heap growth.
const MAX_GLOBAL_ITIMERS: usize = 512;
/// Maximum expired timers dispatched per single deferred-drain pass (stack-allocated).
const TIMER_DRAIN_BATCH: usize = 16;

/// How a POSIX timer notifies its owning process/thread on expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosixTimerNotify {
    /// `SIGEV_NONE`: record expiry/overrun without sending a signal.
    None,
    /// `SIGEV_SIGNAL`: process-directed signal to `tgid`.
    Signal {
        sig: crate::signal::Signal,
        sival: u64,
    },
    /// `SIGEV_THREAD_ID`: thread-directed signal to specific `tid` in `tgid`.
    ThreadSignal {
        tid: crate::process::ProcessId,
        sig: crate::signal::Signal,
        sival: u64,
    },
}

/// Clock base recorded for a POSIX timer (`timer_create`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerClock {
    Realtime,
    Monotonic,
    Boottime,
}

#[derive(Debug, Clone, Copy)]
struct RealITimerEntry {
    tgid: crate::process::ProcessId,
    /// Armed monotonic deadline in ns (`None` when disarmed).
    expiry_ns: Option<u64>,
    /// Periodic reload interval in ns (`0` for one-shot).
    interval_ns: u64,
}

#[derive(Debug, Clone, Copy)]
struct PosixTimerEntry {
    tgid: crate::process::ProcessId,
    timer_id: i32,
    clock: TimerClock,
    notify: PosixTimerNotify,
    /// Armed monotonic deadline in ns (`None` when disarmed).
    expiry_ns: Option<u64>,
    /// Periodic reload interval in ns (`0` for one-shot).
    interval_ns: u64,
    /// Overrun count from the most recent expiration.
    overrun: i32,
}

#[derive(Debug, Clone, Copy)]
enum TimerFireEvent {
    Process {
        tgid: crate::process::ProcessId,
        sig: crate::signal::Signal,
        info: crate::signal::SigInfo,
    },
    Thread {
        tid: crate::process::ProcessId,
        sig: crate::signal::Signal,
        info: crate::signal::SigInfo,
    },
}

struct TimerRegistry {
    itimers: Vec<RealITimerEntry>,
    posix: Vec<PosixTimerEntry>,
    next_timer_id: i32,
}

impl TimerRegistry {
    const fn new() -> Self {
        Self {
            itimers: Vec::new(),
            posix: Vec::new(),
            next_timer_id: 1,
        }
    }

    fn recompute_next_expiry(&self) -> u64 {
        let mut min_ns = u64::MAX;
        for t in &self.itimers {
            if let Some(exp) = t.expiry_ns {
                if exp < min_ns {
                    min_ns = exp;
                }
            }
        }
        for t in &self.posix {
            if let Some(exp) = t.expiry_ns {
                if exp < min_ns {
                    min_ns = exp;
                }
            }
        }
        min_ns
    }

    fn publish_next_expiry(&self) {
        let min_ns = self.recompute_next_expiry();
        NEXT_TIMER_EXPIRY_NS.store(min_ns, Ordering::Release);
        if min_ns != u64::MAX && monotonic_ns() >= min_ns {
            PROCESS_TIMER_DEFERRED.store(true, Ordering::Release);
        }
    }
}

static TIMER_REGISTRY: Mutex<TimerRegistry> = Mutex::new(TimerRegistry::new());

/// Compute `(interval_ns, remaining_ns)` for a timer at monotonic time `now_ns`.
#[inline]
fn remaining_pair(expiry_ns: Option<u64>, interval_ns: u64, now_ns: u64) -> (u64, u64) {
    match expiry_ns {
        Some(exp) => (interval_ns, exp.saturating_sub(now_ns).max(1)),
        None => (interval_ns, 0),
    }
}

/// Convert a `(value_ns, interval_ns, abstime, clock)` request into an armed
/// monotonic deadline (`None` when `value_ns == 0`).
#[inline]
pub(crate) fn compute_timer_deadline_ns(
    value_ns: u64,
    abstime: bool,
    clock: TimerClock,
    now_mono_ns: u64,
    wall_offset_ns: u64,
) -> Option<u64> {
    if value_ns == 0 {
        return None;
    }
    if abstime {
        let target_mono = match clock {
            TimerClock::Realtime => value_ns.saturating_sub(wall_offset_ns),
            TimerClock::Monotonic | TimerClock::Boottime => value_ns,
        };
        Some(target_mono)
    } else {
        Some(now_mono_ns.saturating_add(value_ns))
    }
}

/// Read the current `ITIMER_REAL` `(interval_ns, remaining_ns)` for `tgid`.
pub(crate) fn get_real_itimer(tgid: crate::process::ProcessId) -> (u64, u64) {
    let now = monotonic_ns();
    let reg = TIMER_REGISTRY.lock();
    match reg.itimers.iter().find(|e| e.tgid == tgid) {
        Some(e) => remaining_pair(e.expiry_ns, e.interval_ns, now),
        None => (0, 0),
    }
}

/// Set `ITIMER_REAL` for `tgid` to `(interval_ns, value_ns)` (`value_ns == 0` disarms).
/// Returns the previous `(interval_ns, remaining_ns)`.
pub(crate) fn set_real_itimer(
    tgid: crate::process::ProcessId,
    interval_ns: u64,
    value_ns: u64,
) -> Result<(u64, u64), crate::syscall::SyscallError> {
    let now = monotonic_ns();
    let new_expiry = if value_ns == 0 {
        None
    } else {
        Some(now.saturating_add(value_ns))
    };
    let mut reg = TIMER_REGISTRY.lock();
    let prev = if let Some(pos) = reg.itimers.iter().position(|e| e.tgid == tgid) {
        let old = remaining_pair(
            reg.itimers[pos].expiry_ns,
            reg.itimers[pos].interval_ns,
            now,
        );
        if new_expiry.is_none() {
            reg.itimers.swap_remove(pos);
        } else {
            reg.itimers[pos].expiry_ns = new_expiry;
            reg.itimers[pos].interval_ns = interval_ns;
        }
        old
    } else {
        if let Some(exp) = new_expiry {
            if reg.itimers.len() >= MAX_GLOBAL_ITIMERS {
                return Err(crate::syscall::SyscallError::ENOMEM);
            }
            reg.itimers
                .try_reserve(1)
                .map_err(|_| crate::syscall::SyscallError::ENOMEM)?;
            reg.itimers.push(RealITimerEntry {
                tgid,
                expiry_ns: Some(exp),
                interval_ns,
            });
        }
        (0, 0)
    };
    reg.publish_next_expiry();
    Ok(prev)
}

/// Create a POSIX per-process timer owned by `tgid` and return its `timer_id`.
pub(crate) fn create_posix_timer(
    tgid: crate::process::ProcessId,
    clock: TimerClock,
    notify_opt: Option<PosixTimerNotify>,
) -> Result<i32, crate::syscall::SyscallError> {
    let mut reg = TIMER_REGISTRY.lock();
    let owned = reg.posix.iter().filter(|e| e.tgid == tgid).count();
    if owned >= MAX_POSIX_TIMERS_PER_PROCESS {
        return Err(crate::syscall::SyscallError::EAGAIN);
    }
    reg.posix
        .try_reserve(1)
        .map_err(|_| crate::syscall::SyscallError::ENOMEM)?;

    // Allocate a unique positive timer_id not currently held by `tgid`.
    let mut id = reg.next_timer_id.max(1);
    while reg.posix.iter().any(|e| e.tgid == tgid && e.timer_id == id) {
        id = id.checked_add(1).unwrap_or(1);
    }
    reg.next_timer_id = id.checked_add(1).unwrap_or(1);

    let notify = notify_opt.unwrap_or(PosixTimerNotify::Signal {
        sig: crate::signal::Signal::SIGALRM,
        sival: id as u64,
    });
    reg.posix.push(PosixTimerEntry {
        tgid,
        timer_id: id,
        clock,
        notify,
        expiry_ns: None,
        interval_ns: 0,
        overrun: 0,
    });
    Ok(id)
}

/// Arm or disarm a POSIX timer owned by `tgid`. Returns previous `(interval_ns, remaining_ns)`.
pub(crate) fn settime_posix_timer(
    tgid: crate::process::ProcessId,
    timer_id: i32,
    abstime: bool,
    interval_ns: u64,
    value_ns: u64,
) -> Result<(u64, u64), crate::syscall::SyscallError> {
    let now = monotonic_ns();
    let offset = wall_clock_offset_ns();
    let mut reg = TIMER_REGISTRY.lock();
    let entry = reg
        .posix
        .iter_mut()
        .find(|e| e.tgid == tgid && e.timer_id == timer_id)
        .ok_or(crate::syscall::SyscallError::EINVAL)?;
    let prev = remaining_pair(entry.expiry_ns, entry.interval_ns, now);
    entry.expiry_ns = compute_timer_deadline_ns(value_ns, abstime, entry.clock, now, offset);
    entry.interval_ns = if entry.expiry_ns.is_some() {
        interval_ns
    } else {
        0
    };
    entry.overrun = 0;
    reg.publish_next_expiry();
    Ok(prev)
}

/// Query `(interval_ns, remaining_ns)` of a POSIX timer owned by `tgid`.
pub(crate) fn gettime_posix_timer(
    tgid: crate::process::ProcessId,
    timer_id: i32,
) -> Result<(u64, u64), crate::syscall::SyscallError> {
    let now = monotonic_ns();
    let reg = TIMER_REGISTRY.lock();
    let entry = reg
        .posix
        .iter()
        .find(|e| e.tgid == tgid && e.timer_id == timer_id)
        .ok_or(crate::syscall::SyscallError::EINVAL)?;
    Ok(remaining_pair(entry.expiry_ns, entry.interval_ns, now))
}

/// Query the overrun count of a POSIX timer owned by `tgid`.
pub(crate) fn getoverrun_posix_timer(
    tgid: crate::process::ProcessId,
    timer_id: i32,
) -> Result<i32, crate::syscall::SyscallError> {
    let reg = TIMER_REGISTRY.lock();
    let entry = reg
        .posix
        .iter()
        .find(|e| e.tgid == tgid && e.timer_id == timer_id)
        .ok_or(crate::syscall::SyscallError::EINVAL)?;
    Ok(entry.overrun)
}

/// Delete a POSIX timer owned by `tgid`.
pub(crate) fn delete_posix_timer(
    tgid: crate::process::ProcessId,
    timer_id: i32,
) -> Result<(), crate::syscall::SyscallError> {
    let mut reg = TIMER_REGISTRY.lock();
    let pos = reg
        .posix
        .iter()
        .position(|e| e.tgid == tgid && e.timer_id == timer_id)
        .ok_or(crate::syscall::SyscallError::EINVAL)?;
    reg.posix.swap_remove(pos);
    reg.publish_next_expiry();
    Ok(())
}

/// POSIX `execve(2)`: delete all POSIX `timer_create` timers owned by `tgid`
/// while preserving `ITIMER_REAL` (`alarm`/`setitimer`).
pub(crate) fn cleanup_posix_timers_for_exec(tgid: crate::process::ProcessId) {
    let mut reg = TIMER_REGISTRY.lock();
    let before = reg.posix.len();
    reg.posix.retain(|e| e.tgid != tgid);
    if reg.posix.len() != before {
        reg.publish_next_expiry();
    }
}

/// Process exit (last live thread of `tgid`): reclaim both `ITIMER_REAL` and
/// all POSIX timers owned by `tgid`.
pub(crate) fn cleanup_all_timers_for_process(tgid: crate::process::ProcessId) {
    let mut reg = TIMER_REGISTRY.lock();
    let before_i = reg.itimers.len();
    let before_p = reg.posix.len();
    reg.itimers.retain(|e| e.tgid != tgid);
    reg.posix.retain(|e| e.tgid != tgid);
    if reg.itimers.len() != before_i || reg.posix.len() != before_p {
        reg.publish_next_expiry();
    }
}

/// Advance a single expired timer entry at `now_ns`, returning `(next_expiry, overrun)`.
#[inline]
pub(crate) fn advance_expired_timer(
    expiry_ns: u64,
    interval_ns: u64,
    now_ns: u64,
) -> (Option<u64>, i32) {
    if interval_ns == 0 {
        (None, 0)
    } else {
        let elapsed = now_ns.saturating_sub(expiry_ns);
        let missed = elapsed / interval_ns;
        let overrun = missed.min(i32::MAX as u64) as i32;
        let next = expiry_ns.saturating_add(missed.saturating_add(1).saturating_mul(interval_ns));
        (Some(next), overrun)
    }
}

/// Process-context drain of expired `ITIMER_REAL` and POSIX timers.
///
/// Called from `scheduler_hook::process_deferred_work()` right next to
/// `drain_deferred_tcp_timers()`. Never allocates on the heap and always drops
/// `TIMER_REGISTRY` before delivering signals.
pub fn drain_deferred_process_timers() {
    if !PROCESS_TIMER_DEFERRED.swap(false, Ordering::AcqRel) {
        return;
    }
    let now = monotonic_ns();
    let mut batch: [Option<TimerFireEvent>; TIMER_DRAIN_BATCH] = [None; TIMER_DRAIN_BATCH];
    let mut count = 0usize;
    let mut more_pending = false;

    {
        let mut reg = TIMER_REGISTRY.lock();

        // 1. Scan ITIMER_REAL entries (removing disarmed one-shots).
        let mut idx = 0usize;
        while idx < reg.itimers.len() {
            let Some(exp) = reg.itimers[idx].expiry_ns else {
                reg.itimers.swap_remove(idx);
                continue;
            };
            if now < exp {
                idx += 1;
                continue;
            }
            if count >= TIMER_DRAIN_BATCH {
                more_pending = true;
                break;
            }
            let tgid = reg.itimers[idx].tgid;
            let interval_ns = reg.itimers[idx].interval_ns;
            let (next_exp, _overrun) = advance_expired_timer(exp, interval_ns, now);
            batch[count] = Some(TimerFireEvent::Process {
                tgid,
                sig: crate::signal::Signal::SIGALRM,
                info: crate::signal::SigInfo::from_sender(
                    crate::signal::Signal::SIGALRM,
                    crate::signal::SI_KERNEL,
                    0,
                    0,
                ),
            });
            count += 1;
            if let Some(next) = next_exp {
                reg.itimers[idx].expiry_ns = Some(next);
                idx += 1;
            } else {
                reg.itimers.swap_remove(idx);
            }
        }

        // 2. Scan POSIX timers.
        for t in reg.posix.iter_mut() {
            let Some(exp) = t.expiry_ns else {
                continue;
            };
            if now < exp {
                continue;
            }
            if count >= TIMER_DRAIN_BATCH {
                more_pending = true;
                break;
            }
            let (next_exp, overrun) = advance_expired_timer(exp, t.interval_ns, now);
            t.expiry_ns = next_exp;
            t.overrun = overrun;
            match t.notify {
                PosixTimerNotify::None => {}
                PosixTimerNotify::Signal { sig, sival } => {
                    batch[count] = Some(TimerFireEvent::Process {
                        tgid: t.tgid,
                        sig,
                        info: crate::signal::SigInfo {
                            signo: sig.as_i32(),
                            errno: 0,
                            code: crate::signal::SI_TIMER,
                            pid: t.timer_id,
                            uid: overrun as u32,
                            value: sival,
                        },
                    });
                    count += 1;
                }
                PosixTimerNotify::ThreadSignal { tid, sig, sival } => {
                    batch[count] = Some(TimerFireEvent::Thread {
                        tid,
                        sig,
                        info: crate::signal::SigInfo {
                            signo: sig.as_i32(),
                            errno: 0,
                            code: crate::signal::SI_TIMER,
                            pid: t.timer_id,
                            uid: overrun as u32,
                            value: sival,
                        },
                    });
                    count += 1;
                }
            }
        }

        let min_ns = reg.recompute_next_expiry();
        NEXT_TIMER_EXPIRY_NS.store(min_ns, Ordering::Release);
        if more_pending {
            PROCESS_TIMER_DEFERRED.store(true, Ordering::Release);
        }
    }

    // Deliver all due signals outside `TIMER_REGISTRY`.
    for slot in batch.iter().take(count) {
        if let Some(event) = *slot {
            match event {
                TimerFireEvent::Process { tgid, sig, info } => {
                    let _ = crate::signal::send_signal_kernel_with_info(tgid, sig, info);
                }
                TimerFireEvent::Thread { tid, sig, info } => {
                    let _ = crate::signal::send_signal_kernel_thread_with_info(tid, sig, info);
                }
            }
        }
    }
}
