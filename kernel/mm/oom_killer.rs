//! Out-Of-Memory killer for Zero-OS
//!
//! Uses buddy allocator watermarks and page cache pressure to trigger, reclaims cache pages,
//! then selects and terminates the worst offender, emitting an audit event.

use core::cmp;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

use crate::buddy_allocator;
use crate::page_cache::{MemoryPressureHandler, PRESSURE_HANDLER};

/// Process identifier type (kept local to avoid kernel_core dependency)
pub type ProcessId = usize;

/// Snapshot of a process for OOM scoring
#[derive(Clone, Copy, Debug)]
pub struct OomProcessInfo {
    /// Process ID
    pub pid: ProcessId,
    /// Monotonic process generation, binding the snapshot to one PID lifetime
    pub generation: u64,
    /// Thread group ID (leader PID)
    pub tgid: ProcessId,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Resident set size in pages
    pub rss_pages: u64,
    /// Nice value (-20 to 19)
    pub nice: i32,
    /// OOM score adjustment (-1000 to 1000)
    pub oom_score_adj: i32,
    /// Whether process has a memory map
    pub has_mm: bool,
    /// Whether this is a kernel thread
    pub is_kernel_thread: bool,
}

type SnapshotFn = fn() -> Option<OomProcessInfo>;
type KillFn = fn(ProcessId, u64, i32) -> bool;
type TimestampFn = fn() -> u64;
/// R106-8: Callback for emitting tamper-evident audit events.
/// Args: (pid: u32, uid: u32, nr_pages_needed: u64, rss_pages: u64, oom_score_adj: i64, timestamp: u64)
type AuditEmitFn = fn(u32, u32, u64, u64, i64, u64);

struct Callbacks {
    snapshot: Option<SnapshotFn>,
    kill: Option<KillFn>,
    timestamp: Option<TimestampFn>,
    /// R106-8: Audit callback for tamper-evident OOM event recording.
    audit_emit: Option<AuditEmitFn>,
}

static CALLBACKS: Mutex<Callbacks> = Mutex::new(Callbacks {
    snapshot: None,
    kill: None,
    timestamp: None,
    audit_emit: None,
});

/// Prevent re-entrant OOM handling
static OOM_RUNNING: AtomicBool = AtomicBool::new(false);

/// Pending allocation request. The allocator publishes this while its lock may
/// still be held; process-context OOM work consumes it only after that lock is
/// released.
static OOM_PENDING: AtomicUsize = AtomicUsize::new(0);

/// Free pages below this percentage of total trigger the OOM path
const LOW_WATERMARK_PCT: usize = 5;
/// Minimum pages we try to reclaim from cache before killing
const MIN_RECLAIM_PAGES: usize = 64;
/// Exit code used for OOM terminations (SIGKILL style)
const OOM_EXIT_CODE: i32 = -9;

/// Register callbacks from kernel_core for process enumeration and termination
pub fn register_callbacks(snapshot: SnapshotFn, kill: KillFn, timestamp: TimestampFn) {
    let mut cb = CALLBACKS.lock();
    cb.snapshot = Some(snapshot);
    cb.kill = Some(kill);
    cb.timestamp = Some(timestamp);
}

/// R106-8: Register the tamper-evident audit callback separately.
/// Called after audit subsystem is initialized (may be later than process callbacks).
pub fn register_audit_callback(audit_emit: AuditEmitFn) {
    let mut cb = CALLBACKS.lock();
    cb.audit_emit = Some(audit_emit);
}

/// Allocation-free phase-1 entry point used by the physical allocator.
pub fn on_allocation_failure(nr_pages_needed: usize) {
    if nr_pages_needed == 0 {
        return;
    }

    rearm_pending(nr_pages_needed);
}

/// Retain the largest outstanding request when failures race or a handler must
/// defer. This is lock-free and allocation-free, so it is safe under the buddy
/// allocator lock.
fn rearm_pending(nr_pages_needed: usize) {
    let mut pending = OOM_PENDING.load(Ordering::Relaxed);
    while pending < nr_pages_needed {
        match OOM_PENDING.compare_exchange_weak(
            pending,
            nr_pages_needed,
            Ordering::Release,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(observed) => pending = observed,
        }
    }
}

/// Execute pending OOM work after the allocator lock has been released.
pub fn poll_and_handle_oom() {
    let nr_pages_needed = OOM_PENDING.swap(0, Ordering::AcqRel);
    if nr_pages_needed == 0 {
        return;
    }

    // Prevent recursive OOM handling
    if OOM_RUNNING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        rearm_pending(nr_pages_needed);
        return;
    }

    // Try to reclaim from the page cache first
    let reclaim_target = cmp::max(nr_pages_needed, MIN_RECLAIM_PAGES);
    let reclaimed = PRESSURE_HANDLER.on_memory_pressure(reclaim_target);

    if !still_under_pressure(nr_pages_needed) {
        OOM_RUNNING.store(false, Ordering::Release);
        return;
    }

    klog!(
        Error,
        "OOM: cache reclaim insufficient (reclaimed {} pages, needed {})",
        reclaimed,
        nr_pages_needed
    );

    if !kill_best_candidate(nr_pages_needed) {
        // A nonblocking process-table/PCB/mm/credential acquisition may have
        // contended, or the generation-bound kill may have lost a race. Retry
        // at the next allocator-failure poll instead of dropping the request.
        rearm_pending(nr_pages_needed);
    }
    OOM_RUNNING.store(false, Ordering::Release);
}

/// Check if system is still under memory pressure
fn still_under_pressure(nr_pages_needed: usize) -> bool {
    match buddy_allocator::get_allocator_stats() {
        Some(stats) => {
            stats.free_pages < nr_pages_needed
                || (stats.free_pages * 100 / stats.total_pages.max(1)) < LOW_WATERMARK_PCT
        }
        None => true,
    }
}

/// Select and kill the best victim process
fn kill_best_candidate(nr_pages_needed: usize) -> bool {
    let (snapshot_cb, kill_cb, ts_cb, audit_cb) = {
        let cb = CALLBACKS.lock();
        (cb.snapshot, cb.kill, cb.timestamp, cb.audit_emit)
    };

    let victim = match snapshot_cb {
        Some(f) => f(),
        None => {
            klog!(Error, "OOM: no snapshot provider registered");
            return false;
        }
    };

    let victim = match victim {
        Some(victim) => victim,
        None => {
            klog!(
                Warn,
                "OOM: victim selection deferred or found no eligible process"
            );
            return false;
        }
    };

    klog!(
        Error,
        "OOM: killing pid={} generation={} tgid={} rss={} pages nice={} adj={}",
        victim.pid,
        victim.generation,
        victim.tgid,
        victim.rss_pages,
        victim.nice,
        victim.oom_score_adj
    );

    let killed = match kill_cb {
        Some(kill) => kill(victim.pid, victim.generation, OOM_EXIT_CODE),
        None => {
            klog!(Error, "OOM: no kill provider registered");
            false
        }
    };
    if !killed {
        klog!(
            Warn,
            "OOM: victim pid={} generation={} changed or was contended; deferring",
            victim.pid,
            victim.generation
        );
        return false;
    }

    emit_audit(&victim, nr_pages_needed, ts_cb, audit_cb);
    true
}

/// Calculate OOM score for a process
/// Higher score = more likely to be killed
pub fn score_process(info: &OomProcessInfo) -> i64 {
    // Immune tasks (oom_score_adj <= -1000)
    if info.oom_score_adj <= -1000 {
        return i64::MIN;
    }

    // R28-10 Fix: Never kill init (pid 1 or tgid 1) to keep the system alive
    // Killing init would crash the entire system.
    if info.pid == 1 || info.tgid == 1 {
        return i64::MIN;
    }

    // Never target kernel threads or tasks without an mm; killing them
    // would not reclaim user memory and can destabilize the kernel.
    if info.is_kernel_thread || !info.has_mm {
        return i64::MIN;
    }

    // Base score is RSS * 100
    let mut score = (info.rss_pages as i64).saturating_mul(100);

    // Add oom_score_adj directly
    score = score.saturating_add(info.oom_score_adj as i64);

    // Higher nice (more positive) should be killed first
    let nice_penalty = info.nice.clamp(-20, 19) as i64 * 10;
    score = score.saturating_add(nice_penalty);

    score
}

/// Emit audit event for OOM kill
///
/// R106-8 FIX: In addition to klog!(Error, ...) (for console visibility), invoke the
/// tamper-evident audit subsystem via the registered callback. This ensures OOM
/// kill events are included in the hash-chained audit trail and cannot be silently
/// dropped or tampered with.
fn emit_audit(
    victim: &OomProcessInfo,
    needed: usize,
    ts_cb: Option<TimestampFn>,
    audit_cb: Option<AuditEmitFn>,
) {
    let timestamp = ts_cb.map(|f| f()).unwrap_or(0);

    // Console log for immediate visibility (retained for operational monitoring)
    klog!(
        Error,
        "OOM AUDIT: timestamp={} pid={} needed={} rss={} adj={} nice={}",
        timestamp,
        victim.pid,
        needed,
        victim.rss_pages,
        victim.oom_score_adj,
        victim.nice
    );

    // R106-8: Emit tamper-evident audit event via registered callback.
    // This feeds into the hash-chained audit ring buffer that can be exported
    // and verified for integrity via sys_audit_export.
    if let Some(emit) = audit_cb {
        emit(
            victim.pid as u32,
            victim.uid,
            needed as u64,
            victim.rss_pages,
            victim.oom_score_adj as i64,
            timestamp,
        );
    }
}

#[allow(dead_code)]
/// Encode nice value to unsigned for audit args
fn encode_nice(nice: i32) -> u64 {
    nice.clamp(-20, 19).saturating_add(20) as u64
}

/// Get OOM killer statistics
#[derive(Debug, Clone)]
pub struct OomStats {
    /// Whether OOM killer is currently running
    pub is_running: bool,
    /// Low watermark percentage
    pub low_watermark_pct: usize,
    /// Minimum reclaim pages
    pub min_reclaim_pages: usize,
}

/// Get current OOM killer statistics
pub fn get_stats() -> OomStats {
    OomStats {
        is_running: OOM_RUNNING.load(Ordering::Relaxed),
        low_watermark_pct: LOW_WATERMARK_PCT,
        min_reclaim_pages: MIN_RECLAIM_PAGES,
    }
}

#[cfg(test)]
mod tests {
    use super::{score_process, OomProcessInfo};

    fn candidate() -> OomProcessInfo {
        OomProcessInfo {
            pid: 2,
            generation: 7,
            tgid: 2,
            uid: 1000,
            gid: 1000,
            rss_pages: 10,
            nice: 0,
            oom_score_adj: 0,
            has_mm: true,
            is_kernel_thread: false,
        }
    }

    #[test]
    fn score_rejects_protected_targets() {
        let mut info = candidate();
        info.pid = 1;
        assert_eq!(score_process(&info), i64::MIN);

        let mut info = candidate();
        info.oom_score_adj = -1000;
        assert_eq!(score_process(&info), i64::MIN);

        let mut info = candidate();
        info.is_kernel_thread = true;
        assert_eq!(score_process(&info), i64::MIN);
    }

    #[test]
    fn score_prefers_rss_adjustment_and_nice() {
        let base = candidate();

        let mut more_rss = base;
        more_rss.rss_pages += 1;
        assert!(score_process(&more_rss) > score_process(&base));

        let mut adjusted = base;
        adjusted.oom_score_adj = 100;
        assert!(score_process(&adjusted) > score_process(&base));

        let mut nicer = base;
        nicer.nice = 1;
        assert!(score_process(&nicer) > score_process(&base));
    }
}
