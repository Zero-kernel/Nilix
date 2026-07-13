//! 增强型调度器
//!
//! 实现多级反馈队列调度和时钟中断集成
//!
//! 使用 Arc<Mutex<Process>> 共享引用与 PROCESS_TABLE 同步状态
//!
//! 就绪队列使用优先级分桶：BTreeMap<Priority, BTreeMap<Pid, PCB>>
//! - 外层按优先级排序（数值越小优先级越高）
//! - 内层按 PID 排序实现同优先级的 FIFO
//!
//! # R67-4 FIX: Per-CPU Scheduler State
//!
//! CURRENT_PROCESS and need_resched are now per-CPU to prevent cross-CPU races:
//! - Each CPU tracks its own current process via CpuLocal
//! - Reschedule flag uses cpu_local::current_cpu().need_resched
//!
//! # R69-1 FIX: Per-CPU Run Queues
//!
//! Ready queues are now per-CPU (CpuLocal<Mutex<...>>) with work stealing and
//! periodic load balancing to avoid global lock contention. This improves SMP
//! scalability by eliminating the global queue lock as a bottleneck.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::cell::UnsafeCell;
use core::ops::Bound::{Excluded, Unbounded};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cpu_local::{current_cpu, current_cpu_id, max_cpus, CpuLocal, NO_FPU_OWNER};
use kernel_core::cgroup;
use kernel_core::process::{self, Priority, Process, ProcessId, ProcessState};
use lazy_static::lazy_static;
use spin::{Mutex, Once};
use x86_64::instructions::interrupts;

// E.5 Cpuset: Import cpuset module for effective CPU mask computation
use crate::cpuset::{self, CpusetId};

// 导入arch模块的上下文切换功能
use arch::ipi::{send_ipi, IpiType};
use arch::Context as ArchContext;
use arch::{assert_kernel_context, stage_pending_tls_bases, switch_context, switch_to_user};
use arch::{default_kernel_stack_top, set_kernel_stack};

// G.1 Observability: Per-CPU counter integration
use trace::counters::{increment_counter, TraceCounter};
// G.1 Observability: Watchdog heartbeat for hung-task detection
use trace::watchdog::{heartbeat, WatchdogHandle};

/// RF178-23 FIX: Security owns the mitigation implementation; the scheduler
/// owns the switch point. Root wiring bridges them without a crate cycle.
static SECURITY_SWITCH_HOOK: Once<fn(bool)> = Once::new();

pub fn register_security_switch_hook(callback: fn(bool)) {
    SECURITY_SWITCH_HOOK.call_once(|| callback);
}

/// 调度器调试输出开关
///
/// 设置为 true 启用详细调度日志，设置为 false 禁用
/// 在生产环境或使用 shell 时应设置为 false
const SCHED_DEBUG: bool = false;

/// Work-stealing and load balancing tunables
///
/// LOAD_BALANCE_INTERVAL_TICKS: How often (in timer ticks) to run the load balancer.
/// LOAD_IMBALANCE_THRESHOLD: Minimum difference in queue lengths before migrating.
const LOAD_BALANCE_INTERVAL_TICKS: u64 = 64;
const LOAD_IMBALANCE_THRESHOLD: usize = 1;

/// F.2 Cgroup: Timer tick duration in nanoseconds
///
/// Assumes 1ms tick interval (PIT/APIC timer). Used for cgroup CPU accounting.
const TICK_NS: u64 = 1_000_000;

/// RF178-33: hard cap on PCB observations in one scheduling decision.
///
/// Timer-return scheduling runs with IF=0, so this bound is a security
/// invariant rather than a tuning hint. A rotating cursor guarantees progress
/// across a queue containing arbitrarily many blocked or contended PCBs.
const SELECT_VISIT_BUDGET: usize = 16;

/// 调度器调试输出宏
macro_rules! sched_debug {
    ($($arg:tt)*) => {
        if SCHED_DEBUG {
            kprintln!($($arg)*);
        }
    };
}

// 类型别名以保持兼容性
pub type Pid = ProcessId;
pub type ProcessControlBlock = Arc<Mutex<Process>>;

/// 优先级分桶的就绪队列类型
///
/// 结构: Priority -> (Pid -> ProcessControlBlock)
/// - 按优先级从低到高排序（优先级数值越小越优先）
/// - 同优先级内按 PID 先入先出
type ReadyQueues = BTreeMap<Priority, BTreeMap<Pid, ProcessControlBlock>>;

/// R70-4 FIX: Shadow buffer for the next task's context.
///
/// Per-CPU storage to hold a copy of the target task's Context while the PCB
/// lock is released. This prevents use-after-unlock when calling enter_usermode
/// or switch_context, fixing the root cause of kick IPI double-fault.
///
/// Safety: Each CPU only mutates its own slot in reschedule_now() with
/// interrupts disabled, so cross-CPU aliasing cannot occur.
///
/// Note: Uses kernel_core::process::Context which is ABI-compatible with
/// arch::Context (same #[repr(C, align(64))] layout). Cast to ArchContext
/// pointer when passing to context switch functions.
struct ContextShadow {
    buf: UnsafeCell<process::Context>,
}

unsafe impl Send for ContextShadow {}
unsafe impl Sync for ContextShadow {}

impl ContextShadow {
    fn new() -> Self {
        Self {
            buf: UnsafeCell::new(process::Context::default()),
        }
    }

    /// Copy the context into the shadow buffer and return a stable pointer.
    ///
    /// Must be called with interrupts disabled to prevent preemption.
    /// Returns pointer cast to ArchContext for use with context switch functions.
    #[inline]
    fn store(&self, ctx: &process::Context) -> *const ArchContext {
        // Safety: We have exclusive access (per-CPU, interrupts disabled)
        // process::Context and arch::Context have identical ABI layout
        unsafe {
            *self.buf.get() = *ctx;
            self.buf.get() as *const ArchContext
        }
    }
}

/// Per-CPU scratch space for staging the next task's Context before the PCB
/// lock is released. Prevents use-after-unlock when calling enter_usermode.
static NEXT_CONTEXT_SHADOW: CpuLocal<ContextShadow> = CpuLocal::new(ContextShadow::new);

// Static assert: ensure process::Context and arch::Context have identical size/align
// This guards against future drift between the two types which would cause UB.
const _: () = {
    use core::mem::{align_of, size_of};
    assert!(size_of::<process::Context>() == size_of::<ArchContext>());
    assert!(align_of::<process::Context>() == align_of::<ArchContext>());
};

/// 用于首次调度的哑上下文（内核启动上下文的保存位置，无需恢复）
static BOOTSTRAP_CONTEXT: Mutex<ArchContext> = Mutex::new(ArchContext::new());

/// R67-4 FIX: Per-CPU current process tracking.
///
/// Each CPU tracks its own current process. This prevents races where
/// multiple CPUs could believe they own the same process.
static CURRENT_PROCESS: CpuLocal<Mutex<Option<Pid>>> = CpuLocal::new(|| Mutex::new(None));

/// R172-03 FIX: per-CPU "previous task whose outgoing context save just completed but
/// whose `on_cpu` gate has not yet been cleared" — the Linux `finish_task_switch` model.
/// Identified by (pid, generation), NOT a raw pointer: a self-exiting/killed outgoing
/// task can become `Zombie` and be REAPED (its PCB freed) before the next
/// `reschedule_now`, so a raw `*const Process::on_cpu` would dangle (UAF). Resolving via
/// `get_process(pid)` returns `None` for a reaped task (no UAF), and the generation guard
/// rejects a recycled pid (so a NEW task that reused the pid and is genuinely running is
/// never wrongly un-gated → no double-run). STAGED right before the actual
/// `switch_to_user`/`switch_context`; CLEARED at the TOP of the next `reschedule_now` on
/// this CPU (by which point the previous switch has fully completed). pid 0 = empty.
struct PrevOnCpu {
    pid: AtomicU64,
    generation: AtomicU64,
}
static PENDING_PREV_ON_CPU: CpuLocal<PrevOnCpu> = CpuLocal::new(|| PrevOnCpu {
    pid: AtomicU64::new(0),
    generation: AtomicU64::new(0),
});

/// R172-03: record the outgoing (pid, generation) to be cleared at the next
/// `reschedule_now` on this CPU. Called (IRQs off) right before the actual switch.
/// `pid == 0` (the bootstrap path) stages nothing.
#[inline]
fn stage_prev_on_cpu(pid: u64, generation: u64) {
    PENDING_PREV_ON_CPU.with(|s| {
        // generation first, pid last (pid != 0 publishes a valid pair on this CPU; same-CPU
        // IRQs-off single-writer so ordering vs concurrent readers is moot, but keep it tidy).
        s.generation.store(generation, Ordering::Relaxed);
        s.pid.store(pid, Ordering::Release);
    });
}

/// Complete a reaper wake that could not become final until the exiting task's
/// context save published `on_cpu=false`.
fn wake_reaper_after_switch(
    parent_pid: Pid,
    child_pid: Pid,
    generation: u64,
    child: &ProcessControlBlock,
    origin: kernel_core::ReschedOrigin,
) -> bool {
    let parent = if parent_pid == 0 {
        None
    } else {
        match origin {
            kernel_core::ReschedOrigin::Process => process::get_process(parent_pid),
            kernel_core::ReschedOrigin::IrqReturn => match process::try_get_process(parent_pid) {
                None => return false,
                Some(parent) => parent,
            },
        }
    };
    let Some(parent) = parent else {
        let Some(child) = child.try_lock() else { return false };
        if child.generation == generation {
            child.switch_reap_pending.store(false, Ordering::Release);
        }
        return true;
    };
    // Use try locks for both origins: this is a cross-PCB handoff and must not
    // introduce a parent<->child lock-order cycle. The pending-prev slot retries.
    let Some(mut parent) = parent.try_lock() else { return false };
    let Some(child) = child.try_lock() else { return false };
    if child.generation != generation {
        return true;
    }
    // Publish reappability while the parent's guard still prevents it from
    // running. A parent made Ready below can therefore never observe the old
    // on_cpu/reap-pending state and re-block without a matching wake.
    child.switch_reap_pending.store(false, Ordering::Release);
    let waiting = parent.waiting_child;
    let woke = parent.state == ProcessState::Blocked
        && (waiting == Some(0) || waiting == Some(child_pid));
    if woke {
        parent.enter_ready_at(kernel_core::get_ticks());
        parent.waiting_child = None;
    }
    drop(child);
    drop(parent);
    if woke {
        Scheduler::kick_all_for_reschedule();
    }
    true
}

/// R172-03: clear the previously-switched-out task's `on_cpu` gate (Linux
/// `finish_task_switch`). Runs at the TOP of `reschedule_now` on the switching CPU, after
/// the previous switch has fully completed — so the outgoing task is now truly off-CPU
/// (its context durable, its kernel stack no longer aliased) and becomes claimable.
/// Runs in PROCESS context (IRQs off, no other lock held), so `get_process` (PROCESS_TABLE
/// lock) + the PCB lock are safe. Idempotent: a no-switch `reschedule_now` finds pid 0.
///
/// TRACKED RESIDUAL (R172-03, liveness-only — NOT a safety gap; Codex-converged
/// not-UNSAFE): this clear runs ONLY at a `reschedule_now` entry. It cannot run from the
/// timer IRQ because the pid+generation resolution needs PROCESS_TABLE/PCB locks (unsafe
/// in IRQ) and adding a lock to `on_clock_tick` would regress the M4-1 no-lock-in-IRQ
/// invariant. So a task switched out on a CPU that then runs a NEW task in an infinite
/// syscall-free ring-3 loop (which already monopolizes that CPU — there is no preemptive
/// reschedule for syscall-free loops in this kernel) stays `on_cpu`-gated and thus
/// un-stealable by OTHER CPUs until the switching CPU next re-enters process-context
/// scheduling. The double-run / torn-context / privesc classes are fully closed; this is
/// purely a cross-CPU load-balancing delay under a degenerate runaway workload. A prompt
/// IRQ-safe clear (a lifetime-pinned PCB handle + lock-free `on_cpu` store from the timer
/// IRQ, with the Arc drop deferred to process context) is the future full convergence.
#[inline]
fn finish_pending_prev(origin: kernel_core::ReschedOrigin) -> bool {
    let (pid, generation) = PENDING_PREV_ON_CPU.with(|s| {
        (
            s.pid.load(Ordering::Acquire),
            s.generation.load(Ordering::Relaxed),
        )
    });
    if pid == 0 {
        return true;
    }
    let pcb = match origin {
        kernel_core::ReschedOrigin::Process => process::get_process(pid as usize),
        kernel_core::ReschedOrigin::IrqReturn => match process::try_get_process(pid as usize) {
            None => return false,
            Some(pcb) => pcb,
        },
    };
    let mut reaper = None;
    let mut reap_pcb = None;
    if let Some(pcb) = pcb {
        let proc = match origin {
            kernel_core::ReschedOrigin::Process => pcb.lock(),
            kernel_core::ReschedOrigin::IrqReturn => match pcb.try_lock() {
                Some(proc) => proc,
                None => return false,
            },
        };
        // Generation guard: a reaped+recycled pid now names a DIFFERENT task; clearing its
        // on_cpu while it runs would re-open the double-run hole. Only clear if it is still
        // the same task instance whose save we just completed.
        if proc.generation == generation {
            if proc.state == ProcessState::Zombie
                && proc.teardown_done.load(Ordering::Acquire)
            {
                proc.switch_reap_pending.store(true, Ordering::Release);
                reaper = Some(proc.ppid);
                reap_pcb = Some(pcb.clone());
            }
            proc.on_cpu.store(false, Ordering::Release);
        }
    }
    if let Some(parent_pid) = reaper {
        let Some(pcb) = reap_pcb.as_ref() else { return false };
        if !wake_reaper_after_switch(parent_pid, pid as Pid, generation, pcb, origin) {
            return false;
        }
    }
    PENDING_PREV_ON_CPU.with(|s| {
        if s.pid.load(Ordering::Acquire) == pid {
            s.pid.store(0, Ordering::Release);
        }
    });
    // get_process == None => the outgoing task was already reaped; its on_cpu is gone with
    // its PCB, nothing to clear (and definitely no UAF).
    true
}

/// R69-1 FIX: Per-CPU ready queues - each CPU has its own priority-bucketed queue.
///
/// Using CpuLocal splits the lock across CPUs, reducing cross-CPU contention and
/// enabling work stealing for load balancing.
pub static READY_QUEUE: CpuLocal<Mutex<ReadyQueues>> =
    CpuLocal::new(|| Mutex::new(BTreeMap::new()));

lazy_static! {
    pub static ref SCHEDULER_STATS: Mutex<SchedulerStats> = Mutex::new(SchedulerStats::new());
}

/// Load balancing tick counter (only driven on CPU0 to reduce contention)
static BALANCE_TICKER: AtomicU64 = AtomicU64::new(0);

/// RF178-3 FIX: Preserve ticks when PROCESS_TABLE or the current PCB is
/// contended. Each slot is owned by one CPU and accessed with IRQs disabled.
/// The generation is load-bearing: a raw PID can be reaped and reused before
/// the process-context drain runs.
struct TickDebt(UnsafeCell<(Pid, u64, u64)>);
unsafe impl Send for TickDebt {}
unsafe impl Sync for TickDebt {}
impl TickDebt {
    const fn new() -> Self {
        Self(UnsafeCell::new((0, 0, 0)))
    }
}
static TICK_DEBT: [TickDebt; cpu_local::max_cpus()] =
    [const { TickDebt::new() }; cpu_local::max_cpus()];

/// Generation paired with the scheduler's per-CPU current PID. A fixed array
/// avoids lazy allocation on the timer IRQ's first touch.
static CURRENT_GENERATION: [AtomicU64; cpu_local::max_cpus()] =
    [const { AtomicU64::new(0) }; cpu_local::max_cpus()];

/// RF178-33: persistent bounded-scan state for one physical ready queue.
///
/// `cycle_start` survives across scheduling entries, allowing a 17/32/N-entry
/// empty scan to prove completion after multiple bounded windows.
struct SelectionCursorState {
    after: Option<(Priority, Pid)>,
    cycle_start: Option<(Priority, Pid)>,
    observed_epoch: u64,
}
impl SelectionCursorState {
    const fn new() -> Self {
        Self {
            after: None,
            cycle_start: None,
            observed_epoch: 0,
        }
    }
}

/// Every access to slot C is serialized by ready queue C's lock.
struct QueueSelectionCursor(UnsafeCell<SelectionCursorState>);
unsafe impl Send for QueueSelectionCursor {}
unsafe impl Sync for QueueSelectionCursor {}
impl QueueSelectionCursor {
    const fn new() -> Self {
        Self(UnsafeCell::new(SelectionCursorState::new()))
    }
}
static OWNER_SELECTION_CURSOR: [QueueSelectionCursor; cpu_local::max_cpus()] =
    [const { QueueSelectionCursor::new() }; cpu_local::max_cpus()];
/// Thieves/migration filter candidates for another CPU and therefore must not
/// advance the owner-dispatch continuation past owner-affine work.
static MIGRATION_SELECTION_CURSOR: [QueueSelectionCursor; cpu_local::max_cpus()] =
    [const { QueueSelectionCursor::new() }; cpu_local::max_cpus()];
/// Structural mutation generation for each physical ready queue. Enqueue,
/// removal, and migration increment this while holding that queue's lock.
static QUEUE_MUTATION_EPOCH: [AtomicU64; cpu_local::max_cpus()] =
    [const { AtomicU64::new(0) }; cpu_local::max_cpus()];

struct SelectionResult {
    candidate: Option<(Pid, ProcessControlBlock, Priority)>,
    visited: usize,
    complete_cycle: bool,
}

/// Fully prepared IRQ-return switch. PCB/table/cpuset locks have all been
/// released. The outgoing PCB remains pinned by PROCESS_TABLE while `on_cpu`
/// is true; deferred teardown now refuses to proceed until finish-task-switch
/// clears that publication. The incoming context is copied to a per-CPU shadow.
struct PreparedIrqSwitch {
    old_pid: Pid,
    old_generation: u64,
    old_space: usize,
    old_ctx_ptr: *mut ArchContext,
    next_space: usize,
    next_user_space: usize,
    next_ctx_ptr: *const ArchContext,
    next_kstack_top: u64,
    next_cs: u64,
    next_fs_base: u64,
    next_gs_base: u64,
    next_wd_handle: Option<WatchdogHandle>,
}

#[inline]
fn defer_current_tick(pid: Pid) {
    let generation = CURRENT_GENERATION[current_cpu_id()].load(Ordering::Acquire);
    if generation == 0 {
        current_cpu().set_need_resched();
        return;
    }
    let slot = unsafe { &mut *TICK_DEBT[current_cpu_id()].0.get() };
    if slot.0 == 0 || (slot.0 == pid && slot.1 == generation) {
        slot.0 = pid;
        slot.1 = generation;
        slot.2 = slot.2.saturating_add(1);
    } else {
        // A switch with debt outstanding is handled by the process-context
        // drain before the next scheduling decision. Preserve the older debt.
        current_cpu().set_need_resched();
    }
}

#[inline]
fn take_current_tick_debt(pid: Pid, generation: u64) -> u64 {
    let slot = unsafe { &mut *TICK_DEBT[current_cpu_id()].0.get() };
    if slot.0 == pid && slot.1 == generation {
        let ticks = slot.2;
        *slot = (0, 0, 0);
        ticks
    } else {
        0
    }
}

/// Fold any tick that could not acquire the current PCB before switching away.
///
/// A false return means the identity is still live but contended. The caller
/// must not switch and overwrite the single per-CPU debt slot in that case.
fn drain_tick_debt_before_switch() -> bool {
    let slot = unsafe { &mut *TICK_DEBT[current_cpu_id()].0.get() };
    let (pid, generation, ticks) = *slot;
    if pid == 0 || ticks == 0 {
        return true;
    }
    let pcb = match process::try_get_process(pid) {
        None => {
            current_cpu().set_need_resched();
            return false;
        }
        Some(None) => {
            *slot = (0, 0, 0);
            return true;
        }
        Some(Some(pcb)) => pcb,
    };
    let Some(mut proc) = pcb.try_lock() else {
        current_cpu().set_need_resched();
        return false;
    };
    if proc.generation != generation
        || matches!(proc.state, ProcessState::Zombie | ProcessState::Terminated)
    {
        *slot = (0, 0, 0);
        return true;
    }
    // Consume only after identity and lifecycle validation. Nothing below may
    // re-resolve the PID or resurrect a teardown state.
    *slot = (0, 0, 0);
    let ns = TICK_NS.saturating_mul(ticks);
    proc.cpu_time = proc.cpu_time.saturating_add(ticks);
    cgroup::account_cpu_time(proc.cgroup_id, ns);
    if proc.cpu_quota_debt_ns == 0 || proc.cpu_quota_debt_cgid == proc.cgroup_id {
        proc.cpu_quota_debt_cgid = proc.cgroup_id;
        proc.cpu_quota_debt_ns = proc.cpu_quota_debt_ns.saturating_add(ns);
    }
    proc.time_slice = proc
        .time_slice
        .saturating_sub(ticks.min(u32::MAX as u64) as u32);
    if proc.time_slice == 0 {
        if proc.state == ProcessState::Running {
            proc.enter_ready_at(kernel_core::get_ticks());
        }
        proc.decrease_dynamic_priority();
        proc.reset_time_slice();
        if proc.state == ProcessState::Ready {
            current_cpu().set_need_resched();
        }
    }
    true
}

/// M4-1: set on CPU0 by the timer tick when the 64-tick load-balance interval elapses;
/// consumed (`swap(false)`) in `reschedule_now`'s prologue, where the allocating
/// `balance_queues` now runs in process context instead of in the IRQ tick.
static BALANCE_DUE: AtomicBool = AtomicBool::new(false);

/// 调度器统计信息
pub struct SchedulerStats {
    pub total_switches: u64,
    pub total_ticks: u64,
    pub processes_created: u64,
    pub processes_terminated: u64,
}

impl SchedulerStats {
    pub fn new() -> Self {
        SchedulerStats {
            total_switches: 0,
            total_ticks: 0,
            processes_created: 0,
            processes_terminated: 0,
        }
    }

    pub fn print(&self) {
        klog!(Info, "=== Scheduler Statistics ===");
        klog!(Info, "Context switches: {}", self.total_switches);
        klog!(Info, "Total ticks:      {}", self.total_ticks);
        klog!(Info, "Processes created: {}", self.processes_created);
        klog!(Info, "Processes terminated: {}", self.processes_terminated);
    }
}

/// 调度器
pub struct Scheduler;

impl Scheduler {
    // ========================================================================
    // 内部辅助函数
    // ========================================================================

    /// 在优先级分桶中查找指定 PID 的进程
    fn find_pcb(queue: &ReadyQueues, pid: Pid) -> Option<ProcessControlBlock> {
        for bucket in queue.values() {
            if let Some(pcb) = bucket.get(&pid) {
                return Some(pcb.clone());
            }
        }
        None
    }

    /// 选择优先级最高的就绪进程（内部实现，需要队列锁）
    ///
    /// # Arguments
    /// * `queue` - 就绪队列引用
    /// * `skip_pid` - 要跳过的进程 PID（用于 yield 时避免选中自己）
    ///
    /// # R70-3 FIX: Use cpu_allowed() for consistent affinity semantics
    ///
    /// # F.2: Skip processes in throttled cgroups (cpu.max enforcement)
    #[allow(dead_code)]
    fn select_next_legacy_bounded(queue: &ReadyQueues, skip_pid: Option<Pid>) -> Option<Pid> {
        // Get current CPU ID for affinity check
        let cpu_id = current_cpu_id();

        // F.2 Cgroup: Calculate current time for CPU quota checks
        let now_tick = kernel_core::get_ticks();
        let now_ns = now_tick.saturating_mul(TICK_NS);

        // RF178-5 FIX: Bucket keys are membership hints, not priority truth.
        // PI, yield, quantum expiry, and aging all mutate the live PCB priority.
        // Select globally by live priority, then longest wait, then PID.
        let mut best: Option<(Priority, u64, Pid)> = None;
        let mut visits = 0usize;
        'queue_scan: for (_priority, bucket) in queue.iter() {
            for (&pid, pcb) in bucket.iter() {
                if visits == SELECT_VISIT_BUDGET {
                    break 'queue_scan;
                }
                visits += 1;
                // 跳过指定的进程（用于 yield 场景）
                if Some(pid) == skip_pid {
                    continue;
                }
                let Some(mut proc) = pcb.try_lock() else {
                    continue;
                };
                if proc.state == ProcessState::Ready && !proc.stopped {
                    proc.age_wait_ticks_to(now_tick);
                    proc.check_and_boost_starved();
                }
                // R70-3 FIX: Check both state AND CPU affinity using cpu_allowed()
                // E.5: Use effective_allowed_cpus for cpuset-aware scheduling
                let effective_mask = Self::effective_allowed_cpus(&proc);

                // F.2 Cgroup: Skip processes in throttled cgroups
                let throttled = cgroup::cpu_quota_is_throttled(proc.cgroup_id, now_ns).is_some();

                if proc.state == ProcessState::Ready
                    && !proc.on_cpu.load(Ordering::Acquire) // R172-03: skip a task whose outgoing save is not yet durable
                    && !proc.stopped // R98-1 FIX: Skip job-control stopped processes
                    && !process::is_pending_irq_kill(pid) // R169-9 FIX: skip IRQ-killed tasks
                    && Self::cpu_allowed(cpu_id, effective_mask)
                    && !throttled
                {
                    let candidate = (proc.dynamic_priority, proc.wait_ticks, pid);
                    let better = match best {
                        None => true,
                        Some((priority, waited, best_pid)) => {
                            candidate.0 < priority
                                || (candidate.0 == priority && candidate.1 > waited)
                                || (candidate.0 == priority
                                    && candidate.1 == waited
                                    && candidate.2 < best_pid)
                        }
                    };
                    if better {
                        best = Some(candidate);
                    }
                }
            }
        }
        if let Some((_, _, pid)) = best {
            sched_debug!("[SCHED] selected pid={}", pid);
            return Some(pid);
        }

        // 如果没有其他就绪进程，回退到被跳过的进程（如果它是就绪的且允许在此CPU运行）
        if let Some(skip) = skip_pid {
            if let Some(pcb) = Self::find_pcb(queue, skip) {
                let Some(proc) = pcb.try_lock() else {
                    return None;
                };
                // R70-3 FIX: Use cpu_allowed() for consistent semantics
                // E.5: Use effective_allowed_cpus for cpuset-aware scheduling
                let effective_mask = Self::effective_allowed_cpus(&proc);

                // F.2 Cgroup: Skip processes in throttled cgroups
                let throttled = cgroup::cpu_quota_is_throttled(proc.cgroup_id, now_ns).is_some();

                if proc.state == ProcessState::Ready
                    && !proc.on_cpu.load(Ordering::Acquire)
                    && !proc.stopped // R98-1 FIX: Skip job-control stopped processes
                    && !process::is_pending_irq_kill(skip) // R169-9 FIX: skip IRQ-killed tasks
                    && Self::cpu_allowed(cpu_id, effective_mask)
                    && !throttled
                {
                    sched_debug!("[SCHED] fallback to skipped pid={}", skip);
                    return Some(skip);
                }
            }
        }

        sched_debug!("[SCHED] no ready process found");
        None
    }

    /// Return the queue entry immediately after `after`, wrapping at the end.
    /// Tree lookups are O(log N); the caller imposes the hard PCB-visit bound.
    fn next_queue_entry<'a, T>(
        queue: &'a BTreeMap<Priority, BTreeMap<Pid, T>>,
        after: Option<(Priority, Pid)>,
    ) -> Option<((Priority, Pid), &'a T)> {
        if let Some((priority, pid)) = after {
            if let Some(bucket) = queue.get(&priority) {
                if let Some((&next_pid, pcb)) = bucket.range((Excluded(pid), Unbounded)).next() {
                    return Some(((priority, next_pid), pcb));
                }
            }
            for (&next_priority, bucket) in queue.range((Excluded(priority), Unbounded)) {
                if let Some((&next_pid, pcb)) = bucket.iter().next() {
                    return Some(((next_priority, next_pid), pcb));
                }
            }
        }

        for (&priority, bucket) in queue.iter() {
            if let Some((&pid, pcb)) = bucket.iter().next() {
                return Some(((priority, pid), pcb));
            }
        }
        None
    }

    /// Advance one persistent, bounded window over a queue.
    ///
    /// This contains the cursor/epoch contract shared by production selection
    /// and the allocation-light executable probes. `visit` decides whether an
    /// observed value is runnable; every callback invocation consumes exactly
    /// one unit of the hard visit budget.
    fn scan_queue_window<T, F>(
        queue: &BTreeMap<Priority, BTreeMap<Pid, T>>,
        cursor: &mut SelectionCursorState,
        queue_epoch: u64,
        visit_budget: usize,
        mut visit: F,
    ) -> (usize, bool)
    where
        F: FnMut((Priority, Pid), &T),
    {
        let mut visited = 0usize;
        let mut complete_cycle = false;

        if cursor.observed_epoch != queue_epoch {
            cursor.observed_epoch = queue_epoch;
            cursor.cycle_start = None;
        }

        if let Some((priority, pid)) = cursor.cycle_start {
            if !queue
                .get(&priority)
                .map(|bucket| bucket.contains_key(&pid))
                .unwrap_or(false)
            {
                cursor.cycle_start = None;
            }
        }

        while visited < visit_budget {
            let Some((key, value)) = Self::next_queue_entry(queue, cursor.after) else {
                complete_cycle = true;
                break;
            };
            if cursor.cycle_start == Some(key) {
                complete_cycle = true;
                break;
            }
            if cursor.cycle_start.is_none() {
                cursor.cycle_start = Some(key);
            }
            cursor.after = Some(key);
            visited += 1;
            visit(key, value);
        }

        // A successor peek proves exact-budget completion without consuming an
        // extra PCB observation.
        if !complete_cycle && visited == visit_budget {
            complete_cycle = Self::next_queue_entry(queue, cursor.after)
                .map(|(entry, _)| Some(entry) == cursor.cycle_start)
                .unwrap_or(true);
        }
        if complete_cycle {
            cursor.cycle_start = None;
        }
        (visited, complete_cycle)
    }

    /// RF178-33 bounded selection core. `cursor` belongs to this queue.
    fn select_next_with_cursor(
        queue: &ReadyQueues,
        target_cpu: usize,
        skip_pid: Option<Pid>,
        cursor: &mut SelectionCursorState,
        queue_epoch: u64,
        visit_budget: usize,
    ) -> SelectionResult {
        let now_tick = kernel_core::get_ticks();
        let now_ns = now_tick.saturating_mul(TICK_NS);
        let mut best: Option<(Priority, u64, Pid, ProcessControlBlock)> = None;
        let (visited, complete_cycle) = Self::scan_queue_window(
            queue,
            cursor,
            queue_epoch,
            visit_budget,
            |key, pcb| {
            let pid = key.1;
            if Some(pid) == skip_pid || process::is_pending_irq_kill(pid) {
                return;
            }

            // Timer-return scheduling has IF=0. Contention consumes one bounded
            // visit and advances the cursor; it can never spin on a PCB lock.
            let Some(mut proc) = pcb.try_lock() else {
                return;
            };
            if proc.state != ProcessState::Ready
                || proc.stopped
                || proc.on_cpu.load(Ordering::Acquire)
            {
                return;
            }

            proc.age_wait_ticks_to(now_tick);
            proc.check_and_boost_starved();
            let Some(effective_mask) = Self::try_effective_allowed_cpus(&proc) else {
                return;
            };
            if !Self::cpu_allowed(target_cpu, effective_mask)
                || cgroup::cpu_quota_is_throttled(proc.cgroup_id, now_ns).is_some()
            {
                return;
            }

            let candidate = (proc.dynamic_priority, proc.wait_ticks, pid);
            let better = match best.as_ref() {
                None => true,
                Some((priority, waited, best_pid, _)) => {
                    candidate.0 < *priority
                        || (candidate.0 == *priority && candidate.1 > *waited)
                        || (candidate.0 == *priority
                            && candidate.1 == *waited
                            && candidate.2 < *best_pid)
                }
            };
            drop(proc);
            if better {
                best = Some((candidate.0, candidate.1, candidate.2, Arc::clone(pcb)));
            }
            },
        );

        let candidate = best.map(|(priority, _, pid, pcb)| (pid, pcb, priority));
        if candidate.is_some() {
            cursor.cycle_start = None;
        }

        SelectionResult {
            candidate,
            visited,
            complete_cycle,
        }
    }

    /// Select from queue `queue_cpu` for execution on `target_cpu`.
    ///
    /// The caller holds queue `queue_cpu`'s lock, which also serializes its
    /// continuation cursor. The target is explicit so migration and stealing
    /// never accidentally apply the executing CPU's affinity mask.
    fn select_next_result_locked(
        queue: &ReadyQueues,
        queue_cpu: usize,
        target_cpu: usize,
        skip_pid: Option<Pid>,
    ) -> SelectionResult {
        debug_assert!(queue_cpu < max_cpus());
        let cursor = unsafe { &mut *OWNER_SELECTION_CURSOR[queue_cpu].0.get() };
        let queue_epoch = QUEUE_MUTATION_EPOCH[queue_cpu].load(Ordering::Acquire);
        let result = Self::select_next_with_cursor(
            queue,
            target_cpu,
            skip_pid,
            cursor,
            queue_epoch,
            SELECT_VISIT_BUDGET,
        );
        if let Some((_pid, _, _)) = result.candidate.as_ref() {
            sched_debug!("[SCHED] selected pid={} after {} visits", _pid, result.visited);
        } else {
            sched_debug!("[SCHED] no ready process in {} bounded visits", result.visited);
        }
        result
    }

    fn select_next_locked(
        queue: &ReadyQueues,
        queue_cpu: usize,
        target_cpu: usize,
        skip_pid: Option<Pid>,
    ) -> Option<(Pid, ProcessControlBlock, Priority)> {
        Self::select_next_result_locked(queue, queue_cpu, target_cpu, skip_pid).candidate
    }

    fn select_next_for_migration_locked(
        queue: &ReadyQueues,
        queue_cpu: usize,
        target_cpu: usize,
        skip_pid: Option<Pid>,
    ) -> Option<(Pid, ProcessControlBlock, Priority)> {
        debug_assert!(queue_cpu < max_cpus());
        let cursor = unsafe { &mut *MIGRATION_SELECTION_CURSOR[queue_cpu].0.get() };
        let queue_epoch = QUEUE_MUTATION_EPOCH[queue_cpu].load(Ordering::Acquire);
        Self::select_next_with_cursor(
            queue,
            target_cpu,
            skip_pid,
            cursor,
            queue_epoch,
            SELECT_VISIT_BUDGET,
        )
        .candidate
    }

    // ========================================================================
    // R69-1 FIX: Per-CPU Queue Helper Functions
    // ========================================================================

    /// Get the current CPU's ready queue
    #[inline]
    fn current_ready_queue() -> &'static Mutex<ReadyQueues> {
        READY_QUEUE.with(|q: &Mutex<ReadyQueues>| unsafe { &*(q as *const Mutex<ReadyQueues>) })
    }

    #[inline]
    fn current_process_slot() -> &'static Mutex<Option<Pid>> {
        CURRENT_PROCESS.with(|slot| unsafe { &*(slot as *const Mutex<Option<Pid>>) })
    }

    /// Get a specific CPU's ready queue
    #[inline]
    fn ready_queue_for_cpu(cpu_id: usize) -> Option<&'static Mutex<ReadyQueues>> {
        READY_QUEUE.get_cpu(cpu_id)
    }

    /// Calculate the length of a ready queue
    #[inline]
    fn queue_len(queue: &ReadyQueues) -> usize {
        queue.values().map(|bucket| bucket.len()).sum()
    }

    /// Get queue length for a specific CPU
    #[inline]
    fn queue_len_for_cpu(cpu_id: usize) -> usize {
        Self::ready_queue_for_cpu(cpu_id)
            .map(|q| Self::queue_len(&q.lock()))
            .unwrap_or(0)
    }

    // ========================================================================
    // R70-2 FIX: SMP Kick Mechanism
    //
    // When new work becomes runnable, wake idle CPUs so they can pick it up
    // immediately rather than waiting for the next timer tick.
    // ========================================================================

    /// E.5 Cpuset: Compute effective affinity: online CPUs ∩ cpuset mask ∩ task affinity.
    ///
    /// This function combines the process's cpuset membership with its personal
    /// CPU affinity mask to determine which CPUs the task can actually run on.
    /// The result respects both CPU isolation (cpuset) and user-set affinity.
    ///
    /// # R95-6 FIX: Cpuset isolation guarantee
    ///
    /// If the task's affinity mask is disjoint from its cpuset, the intersection
    /// would be empty (0). Since `cpu_allowed()` treats 0 as "all CPUs allowed",
    /// this would create a cpuset escape. To prevent this, an empty intersection
    /// falls back to the cpuset-only mask (ignoring the invalid affinity).
    ///
    /// Edge case: If the cpuset itself has no online CPUs (misconfiguration or
    /// hotplug), the fallback would also be 0. We handle this by returning 1
    /// (only CPU 0 allowed) as a fail-safe - the task will be constrained to
    /// CPU 0 rather than escaping to all CPUs.
    #[inline]
    fn effective_allowed_cpus(proc: &process::Process) -> u64 {
        let cpuset_id = CpusetId(proc.cpuset_id);
        let effective = cpuset::effective_cpus(cpuset_id, proc.allowed_cpus);

        // R95-6 FIX: Never return 0 from a non-empty cpuset constraint.
        // If affinity is disjoint from cpuset, ignore affinity and use cpuset-only.
        if effective == 0 {
            let cpuset_only = cpuset::effective_cpus(cpuset_id, 0);
            // Edge case: If cpuset itself is empty (misconfiguration), clamp to CPU 0
            // rather than allowing all CPUs. This is fail-closed behavior.
            if cpuset_only == 0 {
                return 1; // Only CPU 0 allowed as fail-safe
            }
            return cpuset_only;
        }

        effective
    }

    /// RF178-33: fail-closed, nonblocking affinity lookup for IRQ return.
    #[inline]
    fn try_effective_allowed_cpus(proc: &process::Process) -> Option<u64> {
        let cpuset_id = CpusetId(proc.cpuset_id);
        let effective = cpuset::try_effective_cpus(cpuset_id, proc.allowed_cpus)?;
        if effective != 0 {
            return Some(effective);
        }

        let cpuset_only = cpuset::try_effective_cpus(cpuset_id, 0)?;
        Some(if cpuset_only == 0 { 1 } else { cpuset_only })
    }

    /// Check whether a CPU is permitted by the affinity mask (bit N = CPU N).
    ///
    /// # R70-3 FIX: Consistent "allowed_cpus == 0" semantics
    ///
    /// Throughout the scheduler, `allowed_cpus == 0` is used to mean "no restriction"
    /// (all CPUs allowed). However, `select_next_locked` was using a direct bitmask
    /// check `(allowed_cpus & cpu_mask) != 0` which returns false when allowed_cpus == 0,
    /// making those tasks unschedulable.
    ///
    /// Fix: Treat `allowed_cpus == 0` as "allowed on all CPUs".
    ///
    /// Guards against CPU IDs >= 64 to avoid undefined behavior from shift overflow.
    #[inline]
    fn cpu_allowed(cpu_id: usize, allowed_cpus: u64) -> bool {
        // allowed_cpus == 0 means "no restriction" (all CPUs allowed)
        // Otherwise, check if the bit for this CPU is set
        allowed_cpus == 0 || (cpu_id < 64 && (allowed_cpus & (1u64 << cpu_id)) != 0)
    }

    /// Public wrapper for `cpu_allowed()` used by runtime tests.
    ///
    /// This allows testing the CPU affinity logic (R70-3 fix) without exposing
    /// internal scheduler implementation details.
    #[inline]
    pub fn cpu_allowed_for_test(cpu_id: usize, allowed_cpus: u64) -> bool {
        Self::cpu_allowed(cpu_id, allowed_cpus)
    }

    /// Send a reschedule IPI to the target CPU.
    ///
    /// This wakes the CPU from its idle HLT loop, causing it to check for
    /// runnable work in its ready queue.
    ///
    /// R70-7: Re-enabled after R70-4 (context shadow buffer) and R70-5 (AP stack
    /// allocation fix) resolved the double fault issue.
    #[inline]
    fn kick_cpu(cpu_id: usize) {
        send_ipi(cpu_id, IpiType::Reschedule);
    }

    /// Wake idle CPUs that are allowed to run the given work.
    ///
    /// Iterates through online CPUs (excluding self) and sends a reschedule IPI
    /// to any CPU that:
    /// 1. Is allowed by the process's CPU affinity mask
    /// 2. Has an empty ready queue (likely idle in HLT)
    ///
    /// This enables rapid work distribution when multiple idle CPUs exist.
    ///
    /// R70-4: Re-enabled after fixing use-after-unlock race in reschedule_now()
    /// via per-CPU context shadow buffer.
    fn kick_idle_cpus(allowed_cpus: u64) {
        let self_cpu = current_cpu_id();
        for cpu_id in Self::online_cpu_ids() {
            if cpu_id == self_cpu {
                continue;
            }
            // Skip CPUs not in affinity mask (0 means all allowed)
            if allowed_cpus != 0 && !Self::cpu_allowed(cpu_id, allowed_cpus) {
                continue;
            }
            // Only kick if queue is empty (CPU likely idle in HLT)
            let queue_empty = Self::ready_queue_for_cpu(cpu_id)
                .map(|q| q.lock().is_empty())
                .unwrap_or(false);
            if queue_empty {
                Self::kick_cpu(cpu_id);
            }
        }
    }

    /// Send a reschedule IPI to a specific CPU.
    #[allow(dead_code)]
    fn kick_cpu_impl(cpu_id: usize) {
        send_ipi(cpu_id, IpiType::Reschedule);
    }

    /// M0-5 sub-slice 1b: broadcast a reschedule IPI to ALL other online CPUs.
    ///
    /// Registered as `kernel_core::signal`'s kick callback and invoked after a signal-wake
    /// flips a blocked target `Blocked -> Ready`. Unlike `kick_idle_cpus`, this does NOT gate
    /// on an empty ready queue: a blocked task's PCB stays resident in its owning CPU's
    /// (non-empty) ready queue with state-filtered selection, so the empty-queue heuristic
    /// would skip exactly the CPU that must re-select the now-Ready task. Bounded — only ever
    /// called on an actual wake (a deliverable handler signal to a Blocked task).
    pub fn kick_all_for_reschedule() {
        let self_cpu = current_cpu_id();
        // R172-27 FIX: also flag the LOCAL CPU's need_resched. A signal that wakes a Blocked
        // sibling on THIS CPU (the dominant path on UP) was previously re-selected only at the
        // next unrelated reschedule (<=1 timeslice latency) because this broadcast only IPI'd
        // OTHER CPUs. Setting the local flag makes the woken task picked up at the next safe
        // point on this CPU too.
        current_cpu().set_need_resched();
        for cpu_id in Self::online_cpu_ids() {
            if cpu_id != self_cpu {
                Self::kick_cpu(cpu_id);
            }
        }
    }

    /// RF178-24: snapshot the authoritative online-ID bitmap and iterate set
    /// bits. A population count is not an ID ceiling when topology is sparse.
    #[inline]
    fn online_cpu_ids() -> impl Iterator<Item = usize> {
        let mask = cpu_local::online_cpu_mask();
        (0..max_cpus().min(64)).filter(move |&cpu_id| (mask & (1u64 << cpu_id)) != 0)
    }

    /// Find the least loaded CPU and its queue length
    ///
    /// # Arguments
    /// * `exclude` - Optional CPU to exclude from search
    /// * `allowed_cpus` - Affinity mask (bit N = CPU N allowed). If 0, all CPUs are considered.
    fn least_loaded_cpu(exclude: Option<usize>, allowed_cpus: u64) -> (usize, usize) {
        let mut best_cpu = current_cpu_id();
        let mut best_len = usize::MAX;
        for cpu_id in Self::online_cpu_ids() {
            if Some(cpu_id) == exclude {
                continue;
            }
            // R70-2 FIX: Filter by affinity mask (0 means no restriction)
            if allowed_cpus != 0 && !Self::cpu_allowed(cpu_id, allowed_cpus) {
                continue;
            }
            if let Some(q) = Self::ready_queue_for_cpu(cpu_id) {
                let len = Self::queue_len(&q.lock());
                if len < best_len {
                    best_len = len;
                    best_cpu = cpu_id;
                }
            }
        }
        (best_cpu, best_len)
    }

    /// Select target CPU for new/resumed work (load-aware placement)
    ///
    /// # Arguments
    /// * `preferred_cpu` - Default CPU (usually current CPU)
    /// * `allowed_cpus` - Affinity mask (bit N = CPU N allowed). If 0, all CPUs are considered.
    fn target_cpu_for_new_work(preferred_cpu: usize, allowed_cpus: u64) -> usize {
        // R70-2 FIX: Pass affinity mask to least_loaded_cpu
        let (least_cpu, least_len) = Self::least_loaded_cpu(None, allowed_cpus);
        let preferred_len = Self::queue_len_for_cpu(preferred_cpu);

        // If preferred CPU is not allowed, always use least_cpu
        if allowed_cpus != 0 && !Self::cpu_allowed(preferred_cpu, allowed_cpus) {
            return least_cpu;
        }

        if least_len != usize::MAX
            && least_cpu != preferred_cpu
            && least_len + LOAD_IMBALANCE_THRESHOLD < preferred_len
        {
            least_cpu
        } else {
            preferred_cpu
        }
    }

    #[inline]
    fn mark_queue_mutated(cpu_id: usize) {
        if let Some(epoch) = QUEUE_MUTATION_EPOCH.get(cpu_id) {
            epoch.fetch_add(1, Ordering::Release); // lint-fetch-add: allow (queue generation)
        }
    }

    /// Remove a PID from all CPU queues
    fn remove_from_all_queues(pid: Pid) {
        // Cleanup scans every bounded slot, including a queue left behind by a
        // failed/offline CPU, rather than deriving an ID ceiling from a count.
        for cpu_id in 0..max_cpus() {
            if let Some(queue) = Self::ready_queue_for_cpu(cpu_id) {
                let mut guard = queue.lock();
                let mut changed = false;
                for bucket in guard.values_mut() {
                    changed |= bucket.remove(&pid).is_some();
                }
                guard.retain(|_, bucket| !bucket.is_empty());
                if changed {
                    Self::mark_queue_mutated(cpu_id);
                }
            }
        }
    }

    /// Remove `pid` from whichever priority bucket of `queue` actually holds it — MEMBERSHIP
    /// based. NEVER key the removal off `pcb.dynamic_priority`: a futex PI boost
    /// (`Process::apply_pi_boost`) mutates `dynamic_priority` WITHOUT rebucketing the ready
    /// task (it only `request_resched`es — see ipc/futex.rs), so the live priority can drift
    /// away from the bucket key the task was inserted under. A priority-keyed remove would
    /// then silently miss the real bucket; if the caller still enqueues the task elsewhere
    /// (work-stealing), the SAME PCB ends up double-queued across two CPUs.
    /// Returns the removed PCB (the queue's own `Arc`), or `None` if `pid` was not present.
    fn remove_pid_from_queue(
        queue: &mut ReadyQueues,
        queue_cpu: Option<usize>,
        pid: Pid,
    ) -> Option<ProcessControlBlock> {
        let key = queue.iter().find_map(|(&k, bucket)| {
            if bucket.contains_key(&pid) {
                Some(k)
            } else {
                None
            }
        })?;
        let bucket = queue.get_mut(&key)?;
        let pcb = bucket.remove(&pid);
        if bucket.is_empty() {
            queue.remove(&key);
        }
        if pcb.is_some() {
            if let Some(cpu_id) = queue_cpu {
                Self::mark_queue_mutated(cpu_id);
            }
        }
        pcb
    }

    /// Enqueue a process on a specific CPU's queue
    fn enqueue_on_cpu(pcb: ProcessControlBlock, priority: Priority, cpu_id: usize) {
        let queue =
            Self::ready_queue_for_cpu(cpu_id).unwrap_or_else(|| Self::current_ready_queue());
        let pid = {
            let mut proc = pcb.lock();
            proc.publish_ready_at(kernel_core::get_ticks());
            proc.pid
        };
        let mut guard = queue.lock();
        guard.entry(priority).or_default().insert(pid, pcb);
        Self::mark_queue_mutated(cpu_id);
    }

    /// Pop a ready process from a queue (for migration)
    fn pop_ready_process(
        queue: &mut ReadyQueues,
        queue_cpu: usize,
        target_cpu: usize,
    ) -> Option<(Pid, ProcessControlBlock, Priority)> {
        let (pid, _selected, priority) =
            Self::select_next_for_migration_locked(queue, queue_cpu, target_cpu, None)?;
        let removed = Self::remove_pid_from_queue(queue, Some(queue_cpu), pid)?;
        Some((pid, removed, priority))
    }

    /// Try to steal a ready process from another CPU
    fn steal_one(current_pid: Option<Pid>) -> Option<(Pid, ProcessControlBlock, usize, Priority)> {
        let local_cpu = current_cpu_id();
        let online_mask = cpu_local::online_cpu_mask();
        if online_mask.count_ones() < 2 {
            return None;
        }

        // Find the most loaded CPU (potential victim)
        let mut source_cpu = None;
        let mut source_len = 0usize;
        for cpu_id in Self::online_cpu_ids() {
            if cpu_id == local_cpu {
                continue;
            }
            let len = Self::queue_len_for_cpu(cpu_id);
            if len > source_len {
                source_len = len;
                source_cpu = Some(cpu_id);
            }
        }

        let source_cpu = source_cpu?;
        if source_len == 0 {
            return None;
        }

        let queue = Self::ready_queue_for_cpu(source_cpu)?;
        let mut guard = queue.lock();
        let mut retries = 0usize;
        let mut candidate = Self::select_next_for_migration_locked(
            &guard,
            source_cpu,
            local_cpu,
            current_pid,
        );
        while let Some((pid, proc_arc, _selected_priority)) = candidate {
            if retries == 2 {
                return None;
            }
            retries += 1;
            // Skip if this is the current process
            if Some(pid) == current_pid {
                candidate = Self::select_next_for_migration_locked(
                    &guard,
                    source_cpu,
                    local_cpu,
                    Some(pid),
                );
                continue;
            }
            if let Some(mut pcb) = proc_arc.try_lock() {
                let effective_mask = Self::effective_allowed_cpus(&pcb);
                let now_ns = kernel_core::get_ticks().saturating_mul(TICK_NS);
                if pcb.state != ProcessState::Ready
                    || pcb.on_cpu.load(Ordering::Acquire) // R172-03: outgoing save not yet durable
                    || pcb.stopped // R98-1 FIX: Also skip job-control stopped processes
                    || process::is_pending_irq_kill(pid)
                    || !Self::cpu_allowed(local_cpu, effective_mask)
                    || cgroup::cpu_quota_is_throttled(pcb.cgroup_id, now_ns).is_some()
                // R169-9 FIX: don't steal IRQ-killed tasks
                {
                    drop(pcb);
                    candidate = Self::select_next_for_migration_locked(
                        &guard,
                        source_cpu,
                        local_cpu,
                        Some(pid),
                    );
                    continue;
                }
                let priority = pcb.dynamic_priority;
                pcb.enter_running_at(kernel_core::get_ticks());
                pcb.on_cpu.store(true, Ordering::Release); // R172-03: now executing -> gate steal/select until its next switch-out save completes
                pcb.reset_time_slice();
                let mem_space = pcb.memory_space;
                drop(pcb);
                // R171-M4-1 FIX: remove from the source queue by MEMBERSHIP, NOT by the
                // (possibly PI-drifted) `priority` above. Keying the remove off
                // `pcb.dynamic_priority` could miss the real bucket and leave the PCB in the
                // source queue while the caller (`select_next_process`) inserts it locally —
                // double-queuing one PCB across two CPUs. Only steal if the remove succeeded.
                if let Some(stolen) =
                    Self::remove_pid_from_queue(&mut guard, Some(source_cpu), pid)
                {
                    drop(guard);
                    // The stolen task lands on the destination at its CURRENT effective
                    // priority (`priority`), which is the correct fresh bucket key there.
                    return Some((pid, stolen, mem_space, priority));
                }
                // Unreachable under the held queue lock (we just selected `pid` from it), but
                // fail safe: never report a steal we could not actually remove.
                candidate = Self::select_next_for_migration_locked(
                    &guard,
                    source_cpu,
                    local_cpu,
                    Some(pid),
                );
            } else {
                candidate = Self::select_next_for_migration_locked(
                    &guard,
                    source_cpu,
                    local_cpu,
                    Some(pid),
                );
            }
        }
        None
    }

    // M4-1: `maybe_balance` was REMOVED — its cheap CPU0 cadence check is inlined into
    // on_clock_tick (which now only sets BALANCE_DUE), and the allocating `balance_queues`
    // it called runs from reschedule_now's prologue in process context (off the IRQ tick).

    /// Migrate a ready task from the busiest CPU to the idlest CPU
    fn balance_queues() {
        if cpu_local::online_cpu_mask().count_ones() < 2 {
            return;
        }

        let mut busiest = None;
        let mut busiest_len = 0usize;
        let mut idlest = None;
        let mut idlest_len = usize::MAX;
        for cpu_id in Self::online_cpu_ids() {
            let len = Self::queue_len_for_cpu(cpu_id);
            if len > busiest_len {
                busiest_len = len;
                busiest = Some(cpu_id);
            }
            if len < idlest_len {
                idlest_len = len;
                idlest = Some(cpu_id);
            }
        }

        if let (Some(src), Some(dst)) = (busiest, idlest) {
            if src != dst && busiest_len > idlest_len + LOAD_IMBALANCE_THRESHOLD {
                Self::migrate_one_ready(src, dst);
            }
        }
    }

    /// Migrate one ready process from source to destination CPU
    ///
    /// # R69-3 FIX: Respect CPU Affinity Mask
    ///
    /// Before migrating, checks if the destination CPU is in the task's effective affinity
    /// mask (cpuset ∩ task affinity). If not permitted, the task is put back in the source
    /// queue and migration is skipped. This prevents violating CPU isolation constraints.
    fn migrate_one_ready(src_cpu: usize, dst_cpu: usize) {
        let Some(src_queue) = Self::ready_queue_for_cpu(src_cpu) else {
            return;
        };

        let candidate = {
            let mut guard = src_queue.lock();
            Self::pop_ready_process(&mut guard, src_cpu, dst_cpu)
        };

        if let Some((pid, pcb, _priority)) = candidate {
            // R69-3 FIX: Check CPU affinity before migration
            // E.5: Use effective_allowed_cpus for cpuset-aware migration
            let Some(proc) = pcb.try_lock() else {
                let mut src_guard = src_queue.lock();
                src_guard.entry(_priority).or_default().insert(pid, pcb);
                Self::mark_queue_mutated(src_cpu);
                return;
            };
            let allowed_cpus = Self::effective_allowed_cpus(&proc);
            let eff_prio = proc.dynamic_priority;
            let still_ready = proc.state == ProcessState::Ready
                && !proc.stopped
                && !proc.on_cpu.load(Ordering::Acquire);
            drop(proc);

            // Check if destination CPU is allowed by effective mask
            if !still_ready || !Self::cpu_allowed(dst_cpu, allowed_cpus) {
                // Destination CPU not in affinity mask, put task back (at its effective prio)
                let mut src_guard = src_queue.lock();
                src_guard.entry(eff_prio).or_default().insert(pid, pcb);
                Self::mark_queue_mutated(src_cpu);
                return;
            }

            let target =
                Self::ready_queue_for_cpu(dst_cpu).unwrap_or_else(|| Self::current_ready_queue());
            let mut dst_guard = target.lock();
            dst_guard.entry(eff_prio).or_default().insert(pid, pcb);
            Self::mark_queue_mutated(dst_cpu);
        }
    }

    /// Select next process from local queue or via work stealing
    fn select_next_process(
        current_pid: Option<Pid>,
        origin: kernel_core::ReschedOrigin,
    ) -> Option<(
        Option<Pid>,
        Option<ProcessControlBlock>,
        Option<ProcessControlBlock>,
        usize,
    )> {
        let queue_ref = Self::current_ready_queue();
        let queue = match origin {
            kernel_core::ReschedOrigin::Process => queue_ref.lock(),
            kernel_core::ReschedOrigin::IrqReturn => match queue_ref.try_lock() {
                Some(queue) => queue,
                None => {
                    current_cpu().set_need_resched();
                    return None;
                }
            },
        };
        let local_cpu = current_cpu_id();
        let current_proc = current_pid.and_then(|pid| Self::find_pcb(&queue, pid));

        let selection =
            Self::select_next_result_locked(&queue, local_cpu, local_cpu, current_pid);
        let complete_cycle = selection.complete_cycle;
        let selected_was_present = selection.candidate.is_some();
        let selected = selection.candidate;
        let mut candidate = selected.as_ref().map(|(pid, _, _)| *pid);
        let mut claimed_proc = None;
        let mut claimed_memory_space = 0usize;

        if let Some((pid, proc_arc, _selected_priority)) = selected {
            if Some(pid) != current_pid {
                if let Some(mut pcb) = proc_arc.try_lock() {
                    let effective_mask = Self::effective_allowed_cpus(&pcb);
                    let now_ns = kernel_core::get_ticks().saturating_mul(TICK_NS);
                    if pcb.state == ProcessState::Ready
                        && !pcb.on_cpu.load(Ordering::Acquire) // R172-03: outgoing save not yet durable
                        && !pcb.stopped
                        && !process::is_pending_irq_kill(pid)
                        && Self::cpu_allowed(local_cpu, effective_mask)
                        && cgroup::cpu_quota_is_throttled(pcb.cgroup_id, now_ns).is_none()
                    {
                        // R98-1 FIX: Only transition to Running if truly runnable
                        // R169-9 FIX: re-validate the IRQ-kill set after re-locking
                        pcb.enter_running_at(kernel_core::get_ticks());
                        pcb.on_cpu.store(true, Ordering::Release); // R172-03: now executing
                        pcb.reset_time_slice();
                        claimed_memory_space = pcb.memory_space;
                        drop(pcb);
                        claimed_proc = Some(proc_arc.clone());
                    } else {
                        candidate = None;
                    }
                } else {
                    candidate = None;
                }
            }
        }

        drop(queue);

        // RF178-33: IRQ return is local-only. Work stealing scans CPU queues
        // and may block on remote locks, so it remains process-context work.
        if candidate.is_none() && origin == kernel_core::ReschedOrigin::Process {
            if let Some((pid, proc_arc, mem_space, priority)) = Self::steal_one(current_pid) {
                // Add stolen process to local queue
                let mut queue = queue_ref.lock();
                queue
                    .entry(priority)
                    .or_default()
                    .insert(pid, proc_arc.clone());
                Self::mark_queue_mutated(local_cpu);
                return Some((Some(pid), current_proc, Some(proc_arc), mem_space));
            }
            // A blocking/yielding caller may halt immediately after this
            // scheduling point. Preserve a level-triggered request whenever
            // the bounded local scan was incomplete or its chosen PCB raced.
            if !complete_cycle || selected_was_present {
                current_cpu().set_need_resched();
            }
        }

        if candidate.is_none() && origin == kernel_core::ReschedOrigin::IrqReturn {
            if !complete_cycle || selected_was_present {
                // The cursor advanced across a bounded window, or the chosen
                // PCB changed before claim. Continue instead of declaring idle.
                current_cpu().set_need_resched();
            }
        }

        Some((candidate, current_proc, claimed_proc, claimed_memory_space))
    }

    // ========================================================================
    // 公开 API
    // ========================================================================

    /// 添加进程到就绪队列
    ///
    /// R69-1 FIX: Uses load-aware CPU placement. The process is added to the
    /// least-loaded CPU's queue to balance work across cores.
    ///
    /// R70-2 FIX: Kicks idle CPUs when new work is added so they can pick it up
    /// immediately rather than waiting for the next timer tick.
    ///
    /// E.5: Uses effective_allowed_cpus for cpuset-aware CPU placement.
    ///
    /// 锁顺序：READY_QUEUE -> SCHEDULER_STATS
    pub fn add_process(pcb: ProcessControlBlock) {
        interrupts::without_interrupts(|| {
            // E.5: Use effective_allowed_cpus for cpuset-aware scheduling
            let (pid, priority, allowed_cpus) = {
                let mut proc = pcb.lock();
                proc.enter_ready_at(kernel_core::get_ticks());
                (
                    proc.pid,
                    proc.dynamic_priority,
                    Self::effective_allowed_cpus(&proc),
                )
            };
            // R70-2 FIX: Pass affinity mask to target selection
            let target_cpu = Self::target_cpu_for_new_work(current_cpu_id(), allowed_cpus);
            sched_debug!(
                "[SCHED] add_process: pid={}, priority={}, target_cpu={}",
                pid,
                priority,
                target_cpu
            );

            // Remove from all queues first (prevent duplicates across CPUs)
            Self::remove_from_all_queues(pid);

            // R70-2 FIX: Check if target CPU's queue was empty before enqueue
            let target_was_idle = Self::ready_queue_for_cpu(target_cpu)
                .map(|q| q.lock().is_empty())
                .unwrap_or(false);

            // Add to target CPU's queue
            Self::enqueue_on_cpu(pcb, priority, target_cpu);

            {
                let mut stats = SCHEDULER_STATS.lock();
                stats.processes_created += 1;
            }

            // R70-7: Kick target CPU to pick up new work immediately.
            // Fixed: R70-4 (context shadow buffer) + R70-5 (AP stack allocation)
            // resolved the double fault issue.
            if target_was_idle
                && target_cpu != current_cpu_id()
                && Self::cpu_allowed(target_cpu, allowed_cpus)
            {
                Self::kick_cpu(target_cpu);
            }
        });
    }

    /// 移除进程
    ///
    /// R69-1 FIX: Removes process from all per-CPU queues.
    ///
    /// 锁顺序：READY_QUEUE -> SCHEDULER_STATS
    pub fn remove_process(pid: Pid) {
        interrupts::without_interrupts(|| {
            Self::remove_from_all_queues(pid);

            let mut stats = SCHEDULER_STATS.lock();
            stats.processes_terminated += 1;
        });
    }

    /// RF178-36 identity-bound resume state machine.
    ///
    /// Every process remains resident in one scheduler queue while blocked or
    /// stopped. Resuming therefore mutates the exact supplied PCB in place. It
    /// must never re-resolve or remove by reusable PID.
    fn resume_stopped_locked(
        proc: &mut Process,
        expected_pid: Pid,
        expected_generation: u64,
    ) -> bool {
        if proc.pid != expected_pid
            || proc.generation != expected_generation
            || matches!(proc.state, ProcessState::Zombie | ProcessState::Terminated)
        {
            return false;
        }

        let was_stopped = proc.stopped || proc.state == ProcessState::Stopped;
        if !was_stopped {
            return false;
        }

        let make_ready = matches!(proc.state, ProcessState::Ready | ProcessState::Stopped)
            || (proc.state == ProcessState::Blocked
                && kernel_core::signal::should_abort_pending_block(proc));
        if make_ready {
            // Keep `stopped` set through enter_ready_at so the Ready residence
            // starts a fresh starvation-aging epoch.
            proc.enter_ready_at(kernel_core::get_ticks());
        }
        proc.stopped = false;
        make_ready
    }

    pub fn resume_stopped(
        pcb: ProcessControlBlock,
        expected_pid: Pid,
        expected_generation: u64,
    ) -> bool {
        let mut proc = pcb.lock();
        Self::resume_stopped_locked(&mut proc, expected_pid, expected_generation)
    }

    /// 选择下一个要运行的进程
    ///
    /// R69-1 FIX: Uses current CPU's queue.
    pub fn select_next() -> Option<Pid> {
        interrupts::without_interrupts(|| {
            let queue = Self::current_ready_queue();
            let queue = queue.lock();
            let cpu = current_cpu_id();
            Self::select_next_locked(&queue, cpu, cpu, None).map(|(pid, _, _)| pid)
        })
    }

    /// 更新当前运行的进程
    ///
    /// R67-4 FIX: Uses per-CPU storage.
    pub fn set_current(pid: Option<Pid>, generation: u64) {
        *Self::current_process_slot().lock() = pid;
        CURRENT_GENERATION[current_cpu_id()].store(generation, Ordering::Release);
    }

    /// 获取当前运行的进程
    ///
    /// R67-4 FIX: Reads from per-CPU storage.
    pub fn get_current() -> Option<Pid> {
        *Self::current_process_slot().lock()
    }

    /// RF178-33: Only a task that still owns this CPU may consume timer
    /// accounting. `Ready + on_cpu` is a legitimate transient while an IRQ
    /// switch is being retried; every other non-Running lifecycle state must
    /// reach the scheduler without time-slice mutation.
    #[inline]
    fn current_task_may_consume_tick(proc: &Process) -> bool {
        proc.on_cpu.load(Ordering::Acquire)
            && !proc.stopped
            && matches!(proc.state, ProcessState::Running | ProcessState::Ready)
    }

    /// 处理时钟中断 - 更新时间片并设置重调度标志
    ///
    /// 锁顺序：CURRENT_PROCESS -> READY_QUEUE -> SCHEDULER_STATS
    /// 所有调度器函数必须遵循此顺序以避免死锁
    ///
    /// **重要**: 此函数在中断上下文中运行，只设置当前 CPU 的 need_resched 标志，
    /// 不执行实际的调度/CR3切换。这避免了在中断返回时运行在错误地址空间的问题。
    ///
    /// # R65-19 FIX: 饥饿防止
    ///
    /// 每次tick时，遍历所有就绪进程，增加等待计数器，并在超过阈值时
    /// 提升其优先级。这确保了即使低优先级进程被高优先级进程持续抢占，
    /// 也能在合理时间内获得CPU时间。
    ///
    /// # R67-4 FIX: Per-CPU State
    ///
    /// Uses per-CPU CURRENT_PROCESS and need_resched to avoid cross-CPU races.
    ///
    /// # R69-1 FIX: Per-CPU Queues
    ///
    /// Uses current CPU's ready queue for time slice management.
    pub fn on_clock_tick() {
        // 使用 without_interrupts 确保在持有锁期间不会被嵌套中断打断
        interrupts::without_interrupts(|| {
            // R67-4 FIX: Use per-CPU current process
            let current_pid = process::current_pid();
            if current_pid
                .map(process::is_pending_irq_kill)
                .unwrap_or(false)
            {
                // The timer-kill handoff owns this still-on-CPU task until a
                // replacement context is saved. Do not let quantum expiry
                // resurrect its provisional Zombie/Blocked state.
                current_cpu().set_need_resched();
                return;
            }
            // 获取当前进程的 Arc 引用并更新时间片
            let current_pcb = current_pid.and_then(|pid| process::try_get_process(pid).flatten());
            if current_pid.is_some() && current_pcb.is_none() {
                defer_current_tick(current_pid.unwrap());
                return;
            }
            if let Some(pcb) = current_pcb {
                // R178-3 FIX: Use try_lock() to avoid deadlock if timer IRQ fires while
                // the interrupted task holds its own PCB lock (e.g., during sys_fork COW
                // walk with IRQs enabled at arch/syscall.rs:1055). On contention, skip
                // this tick's accounting — accuracy loss is acceptable vs. hard deadlock.
                //
                // SAFETY: Graceful degradation. Skipped ticks mean:
                // - Time slice not decremented (task runs longer this quantum)
                // - CPU time not charged to cgroup (undercounting, safe direction)
                // - Quota not enforced this tick (benign — enforced next uncontended tick)
                //
                // Precedent: R173 (pending-kill), R174-A4 (COW_FAULT_LOCK) use try_lock.
                let mut proc = match pcb.try_lock() {
                    Some(guard) => guard,
                    None => {
                        defer_current_tick(current_pid.unwrap());
                        return;
                    }
                };

                // RF178-33 FIX: A synchronous self-exit retries IRQ scheduling
                // with timer interrupts enabled from boot CR3. Its PCB remains
                // current/on-CPU but is already Zombie. Never let repeated ticks
                // expire that stale time slice and resurrect it through
                // enter_ready_at(). Blocked/stopped and stale-current tasks use
                // the same fail-closed path.
                if !Self::current_task_may_consume_tick(&proc) {
                    current_cpu().set_need_resched();
                    return;
                }

                let accounted_ticks =
                    1u64.saturating_add(take_current_tick_debt(proc.pid, proc.generation));
                let accounted_ns = TICK_NS.saturating_mul(accounted_ticks);

                // 减少时间片
                if proc.time_slice > 0 {
                    proc.time_slice = proc
                        .time_slice
                        .saturating_sub(accounted_ticks.min(u32::MAX as u64) as u32);

                    // F.2 Cgroup: Account CPU time for per-process stats
                    proc.cpu_time = proc.cpu_time.saturating_add(accounted_ticks);

                    // F.2 Cgroup: Account CPU time for cgroup controller
                    // This feeds into cgroup statistics and future cpu.stat accounting
                    cgroup::account_cpu_time(proc.cgroup_id, accounted_ns);

                    // F.2 Cgroup: Enforce cpu.max quota and throttle if exceeded
                    // Calculate current time in nanoseconds for quota accounting
                    let now_ns = kernel_core::get_ticks().saturating_mul(TICK_NS);
                    // R170-3 FIX: fold any contention-deferred quota debt into
                    // this tick's charge. The debt is tagged with the cgroup
                    // it was accrued against; attach/cgroup.procs/exit all
                    // take-and-flush it synchronously under this same PCB
                    // lock, so a tag mismatch is unreachable — dropped
                    // defensively rather than mis-charged to a different
                    // cgroup.
                    let debt_ns = if proc.cpu_quota_debt_cgid == proc.cgroup_id {
                        proc.cpu_quota_debt_ns
                    } else {
                        proc.cpu_quota_debt_ns = 0;
                        0
                    };
                    match cgroup::charge_cpu_quota(
                        proc.cgroup_id,
                        accounted_ns.saturating_add(debt_ns),
                        now_ns,
                    ) {
                        cgroup::CpuQuotaStatus::ContentionDeferred(_) => {
                            // NOTHING was accumulated (guaranteed by
                            // charge_cpu_quota's snapshot-first phases): keep
                            // the prior debt, defer this tick too, and
                            // PREEMPT exactly like Throttled — without the
                            // preempt, farming registry/limits contention
                            // would keep the task running while accounting
                            // merely defers (the R170-3 evasion).
                            proc.cpu_quota_debt_ns = debt_ns.saturating_add(accounted_ns);
                            proc.cpu_quota_debt_cgid = proc.cgroup_id;
                            proc.enter_ready_at(kernel_core::get_ticks());
                            proc.reset_time_slice();
                            current_cpu().set_need_resched();
                        }
                        cgroup::CpuQuotaStatus::Throttled(_) => {
                            // Accumulation ran (the folded debt landed too)
                            // — clear the debt and preempt as before.
                            proc.cpu_quota_debt_ns = 0;
                            proc.enter_ready_at(kernel_core::get_ticks());
                            proc.reset_time_slice();
                            current_cpu().set_need_resched();
                        }
                        cgroup::CpuQuotaStatus::Allowed | cgroup::CpuQuotaStatus::Unlimited => {
                            // Accumulation ran (or no quota exists anywhere
                            // in the chain) — the debt is consumed/moot.
                            proc.cpu_quota_debt_ns = 0;
                        }
                    }
                }

                // 时间片已用完，标记为就绪态并降低优先级
                if proc.time_slice == 0 {
                    proc.enter_ready_at(kernel_core::get_ticks());

                    proc.decrease_dynamic_priority(); // 惩罚 CPU 密集型进程

                    proc.reset_time_slice();
                    // R67-4 FIX: Set this CPU's reschedule flag
                    current_cpu().set_need_resched();
                }
            }

            // 最后更新 SCHEDULER_STATS
            {
                if let Some(mut stats) = SCHEDULER_STATS.try_lock() {
                    stats.total_ticks = stats.total_ticks.saturating_add(1);
                }
            }

            // M4-1 (PART B): keep the cheap, IRQ-safe load-balance CADENCE on the tick; the
            // ALLOCATING work (balance_queues Vec + migrate_one_ready BTreeMap inserts) now
            // runs from reschedule_now's prologue in process context. Just flag CPU0 when the
            // 64-tick interval elapses (wall-clock cadence preserved).
            if current_cpu_id() == 0 {
                let t = BALANCE_TICKER.fetch_add(1, Ordering::Relaxed) + 1; // lint-fetch-add: allow (coarse cadence)
                if t % LOAD_BALANCE_INTERVAL_TICKS == 0 {
                    BALANCE_DUE.store(true, Ordering::Relaxed);
                }
            }
        });
        // 注意：不再在中断上下文中调用 schedule()
        // 真正的上下文切换需要在受控路径中执行（如系统调用返回或显式调度点）
    }

    /// 查询是否需要重新调度
    ///
    /// R67-4 FIX: Reads from per-CPU need_resched flag.
    pub fn need_resched() -> bool {
        current_cpu().need_resched.load(Ordering::SeqCst)
    }

    /// 清除重调度标志
    ///
    /// R67-4 FIX: Clears this CPU's need_resched flag.
    pub fn clear_resched() {
        current_cpu().need_resched.store(false, Ordering::SeqCst);
    }

    /// RF178-33: prepare one timer-IRQ-return switch without a blocking lock.
    ///
    /// The local queue plus candidate/current PCB locks are all try-only. The
    /// candidate window is strictly bounded, and every datum needed after the
    /// locks drop is copied into this CPU's stable context shadow or the result.
    fn prepare_irq_switch() -> Option<PreparedIrqSwitch> {
        let current_slot = Self::current_process_slot();
        let Some(mut current_guard) = current_slot.try_lock() else {
            current_cpu().set_need_resched();
            return None;
        };
        let old_pid = (*current_guard)?;
        let local_cpu = current_cpu_id();
        let queue_ref = Self::current_ready_queue();
        let queue = match queue_ref.try_lock() {
            Some(queue) => queue,
            None => {
                current_cpu().set_need_resched();
                return None;
            }
        };

        let old_pcb = match process::try_get_process(old_pid) {
            None => {
                current_cpu().set_need_resched();
                return None;
            }
            Some(Some(pcb)) => pcb,
            Some(None) => return None,
        };

        let selection =
            Self::select_next_result_locked(&queue, local_cpu, local_cpu, Some(old_pid));
        let Some((next_pid, next_pcb, _priority)) = selection.candidate else {
            if let Some(mut old) = old_pcb.try_lock() {
                if old.state == ProcessState::Ready && old.on_cpu.load(Ordering::Acquire) {
                    old.enter_running_at(kernel_core::get_ticks());
                }
            } else {
                current_cpu().set_need_resched();
                return None;
            }
            if !selection.complete_cycle {
                current_cpu().set_need_resched();
            }
            return None;
        };

        let Some(mut next) = next_pcb.try_lock() else {
            current_cpu().set_need_resched();
            return None;
        };
        let Some(mut old) = old_pcb.try_lock() else {
            current_cpu().set_need_resched();
            return None;
        };

        let Some(effective_mask) = Self::try_effective_allowed_cpus(&next) else {
            current_cpu().set_need_resched();
            return None;
        };
        let now_tick = kernel_core::get_ticks();
        let now_ns = now_tick.saturating_mul(TICK_NS);
        if next.state != ProcessState::Ready
            || next.stopped
            || next.on_cpu.load(Ordering::Acquire)
            || process::is_pending_irq_kill(next_pid)
            || !Self::cpu_allowed(local_cpu, effective_mask)
            || cgroup::cpu_quota_is_throttled(next.cgroup_id, now_ns).is_some()
        {
            current_cpu().set_need_resched();
            return None;
        }

        #[cfg(target_arch = "x86_64")]
        {
            use x86_64::registers::model_specific::Msr;
            const MSR_FS_BASE: u32 = 0xC000_0100;
            const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;
            unsafe {
                old.fs_base = Msr::new(MSR_FS_BASE).read();
                old.gs_base = Msr::new(MSR_KERNEL_GS_BASE).read();
            }
        }

        let per_cpu = current_cpu();
        if per_cpu.get_fpu_owner() == old_pid {
            unsafe {
                use x86_64::registers::control::{Cr0, Cr0Flags};
                let cr0 = Cr0::read();
                if cr0.contains(Cr0Flags::TASK_SWITCHED) {
                    let mut new_cr0 = cr0;
                    new_cr0.remove(Cr0Flags::TASK_SWITCHED);
                    Cr0::write(new_cr0);
                }
                core::arch::asm!(
                    "fxsave64 [{}]",
                    in(reg) old.context.fx.data.as_mut_ptr(),
                    options(nostack)
                );
            }
            old.fpu_used = true;
            per_cpu.set_fpu_owner(NO_FPU_OWNER);
        }

        let old_ctx_ptr = &mut old.context as *mut _ as *mut ArchContext;
        let old_generation = old.generation;
        let old_space = old.memory_space;
        let next_ctx_ptr = NEXT_CONTEXT_SHADOW.with(|shadow| shadow.store(&next.context));
        let next_space = next.memory_space;
        let next_user_space = next.user_memory_space;
        let next_kstack_top = next.kernel_stack_top.as_u64();
        let next_cs = next.context.cs;
        let next_fs_base = next.fs_base;
        let next_gs_base = next.gs_base;
        let next_wd_handle = next.watchdog_handle;
        let next_generation = next.generation;

        if matches!(old.state, ProcessState::Running | ProcessState::Ready) {
            old.enter_ready_at(now_tick);
        }
        next.enter_running_at(now_tick);
        next.on_cpu.store(true, Ordering::Release);
        next.reset_time_slice();

        drop(old);
        drop(next);
        drop(queue);

        *current_guard = Some(next_pid);
        CURRENT_GENERATION[local_cpu].store(next_generation, Ordering::Release);
        drop(current_guard);
        process::set_current_pid(Some(next_pid));
        if let Some(mut stats) = SCHEDULER_STATS.try_lock() {
            stats.total_switches = stats.total_switches.saturating_add(1);
        }

        Some(PreparedIrqSwitch {
            old_pid,
            old_generation,
            old_space,
            old_ctx_ptr,
            next_space,
            next_user_space,
            next_ctx_ptr,
            next_kstack_top,
            next_cs,
            next_fs_base,
            next_gs_base,
            next_wd_handle,
        })
    }

    /// Complete a switch prepared by `prepare_irq_switch`; no PCB/cpuset/table
    /// lock is acquired on this path.
    fn execute_irq_switch(prepared: PreparedIrqSwitch) {
        let effective_kstack_top = if prepared.next_kstack_top != 0 {
            prepared.next_kstack_top
        } else {
            default_kernel_stack_top()
        };
        unsafe {
            set_kernel_stack(effective_kstack_top);
        }

        increment_counter(TraceCounter::ContextSwitches, 1);
        if let Some(ref handle) = prepared.next_wd_handle {
            let _ = heartbeat(handle, kernel_core::time::current_timestamp_ms());
        }

        process::activate_memory_space(prepared.next_space, Some(prepared.next_user_space));
        stage_pending_tls_bases(prepared.next_fs_base, prepared.next_gs_base);
        stage_prev_on_cpu(prepared.old_pid as u64, prepared.old_generation);
        let switch_hook = SECURITY_SWITCH_HOOK
            .get()
            .copied()
            .expect("scheduler security switch hook not registered");
        switch_hook(prepared.old_space != prepared.next_space);

        let next_is_user = (prepared.next_cs & 0x3) == 0x3;
        if next_is_user {
            unsafe {
                use x86_64::registers::model_specific::Msr;
                const MSR_FS_BASE: u32 = 0xC000_0100;
                const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;
                Msr::new(MSR_FS_BASE).write(prepared.next_fs_base);
                Msr::new(MSR_KERNEL_GS_BASE).write(prepared.next_gs_base);
                switch_to_user(prepared.old_ctx_ptr, prepared.next_ctx_ptr);
            }
        } else {
            unsafe {
                assert_kernel_context(prepared.next_ctx_ptr);
                switch_context(prepared.old_ctx_ptr, prepared.next_ctx_ptr);
            }
        }
    }

    /// 执行调度 - 选择下一个进程并更新状态
    ///
    /// 锁顺序：CURRENT_PROCESS -> READY_QUEUE -> SCHEDULER_STATS
    ///
    /// **重要**: 此函数只更新进程状态和当前进程标识，不切换CR3。
    /// CR3切换必须与完整的寄存器上下文切换（switch_context）配合执行。
    /// 当前内核尚未实现真正的进程切换，所有"进程"共享内核地址空间。
    ///
    /// # R67-4 FIX: Per-CPU State
    ///
    /// Uses per-CPU CURRENT_PROCESS and need_resched to avoid cross-CPU races.
    ///
    /// # R68-3 FIX: Atomic State Transition
    ///
    /// State transition from Ready to Running is now done atomically within the
    /// queue lock to prevent two CPUs from selecting the same process. If another
    /// CPU has already claimed the selected process (state != Ready), we re-select.
    ///
    /// # R69-1 FIX: Per-CPU Run Queues with Work Stealing
    ///
    /// Uses per-CPU ready queues to reduce lock contention. If the local queue is
    /// empty, attempts to steal a ready process from another CPU's queue.
    ///
    /// 返回值：如果发生进程切换，返回 (新进程PID, 新进程地址空间)
    pub fn schedule(origin: kernel_core::ReschedOrigin) -> Option<(Pid, usize)> {
        interrupts::without_interrupts(|| {
            // R67-4 FIX: Clear this CPU's reschedule flag
            current_cpu().need_resched.store(false, Ordering::SeqCst);

            // R67-4 FIX: Use per-CPU current process
            let current_pid = Self::get_current();
            sched_debug!("[SCHED] schedule: current_pid={:?}", current_pid);

            // R69-1 FIX: Use select_next_process which handles per-CPU queues and work stealing
            let Some((next_pid, current_proc, next_proc, next_memory_space)) =
                Self::select_next_process(current_pid, origin)
            else {
                return None;
            };

            sched_debug!("[SCHED] schedule: next_pid={:?}", next_pid);

            // 选择下一个要运行的进程
            if let Some(next_pid) = next_pid {
                if Some(next_pid) != current_pid {
                    sched_debug!("[SCHED] switching from {:?} to {}", current_pid, next_pid);
                    // 保存当前进程状态
                    if let Some(proc) = current_proc {
                        let mut pcb = proc.lock();
                        if pcb.state == ProcessState::Running {
                            pcb.enter_ready_at(kernel_core::get_ticks());
                        }
                    }

                    // R68-3: State transition already done inside the lock above
                    // next_proc and next_memory_space are already set

                    // 注意：不在此处切换 CR3
                    // CR3 切换必须与 switch_context 配合执行，否则会导致：
                    // 1. 中断返回后运行在错误的地址空间
                    // 2. 被中断的代码访问错误的内存映射
                    //
                    // TODO: 实现完整的上下文切换路径后，在此处或调用方处理 CR3
                    // process::activate_memory_space(next_memory_space);

                    // 更新当前进程 (both scheduler and kernel_core trackers)
                    let next_generation = next_proc
                        .as_ref()
                        .map(|pcb| pcb.lock().generation)
                        .expect("claimed scheduler task must carry a PCB");
                    Self::set_current(Some(next_pid), next_generation);
                    process::set_current_pid(Some(next_pid));

                    let mut stats = SCHEDULER_STATS.lock();
                    stats.total_switches += 1;

                    return Some((next_pid, next_memory_space));
                }
            }
            // R172-03 FIX: no switch (no other runnable task, or re-selected self). If a
            // timer tick flipped this still-running task Running->Ready (deferred preempt)
            // but we are NOT switching away from it, restore Running — its live registers
            // ARE its durable state; leaving it Ready would mis-feed the starvation scan.
            // `on_cpu` stays true (it genuinely occupies this CPU) and is cleared only when
            // the task is actually switched out (via finish_pending_prev).
            if let Some(proc) = current_proc {
                let mut pcb = proc.lock();
                if pcb.state == ProcessState::Ready && pcb.on_cpu.load(Ordering::Acquire) {
                    pcb.enter_running_at(kernel_core::get_ticks());
                }
            }
            None
        })
    }

    /// 主动让出CPU
    ///
    /// R69-1 FIX: Uses current CPU's ready queue.
    ///
    /// 返回值：如果发生进程切换，返回 (新进程PID, 新进程地址空间)
    pub fn yield_cpu() -> Option<(Pid, usize)> {
        interrupts::without_interrupts(|| {
            if let Some(pid) = Self::get_current() {
                if let Some(pcb) = {
                    let queue = Self::current_ready_queue();
                    let queue = queue.lock();
                    Self::find_pcb(&queue, pid)
                } {
                    let mut proc = pcb.lock();
                    proc.enter_ready_at(kernel_core::get_ticks());
                    proc.update_dynamic_priority(); // 奖励主动让出的进程
                }
            }
        });

        Self::schedule(kernel_core::ReschedOrigin::Process)
    }

    /// 获取进程数量
    ///
    /// R69-1 FIX: Sums across all per-CPU queues.
    pub fn process_count() -> usize {
        interrupts::without_interrupts(|| {
            let mut total = 0;
            for cpu_id in Self::online_cpu_ids() {
                if let Some(queue) = Self::ready_queue_for_cpu(cpu_id) {
                    total += Self::queue_len(&queue.lock());
                }
            }
            total
        })
    }

    /// 打印调度统计信息
    pub fn print_stats() {
        interrupts::without_interrupts(|| {
            SCHEDULER_STATS.lock().print();
        });
    }

    /// 在安全上下文中执行完整上下文切换（含 CR3）
    ///
    /// # Arguments
    /// * `force` - true 无视 need_resched 立即尝试切换（用于 sys_yield）
    ///           - false 只有 need_resched 置位时才切换（用于系统调用返回点）
    ///
    /// 此函数是调度器的核心入口点，负责：
    /// 1. 检查是否需要调度
    /// 2. 选择下一个进程
    /// 3. 保存旧进程上下文（在旧地址空间中）
    /// 4. 切换地址空间（CR3）
    /// 5. 根据目标进程特权级选择切换方式：
    ///    - Ring 0：使用 switch_context 直接切换
    ///    - Ring 3：使用 save_context + enter_usermode (IRETQ)
    ///
    /// # R67-4 FIX: Per-CPU State
    ///
    /// Uses per-CPU need_resched and CURRENT_PROCESS to avoid cross-CPU races.
    ///
    /// # R69-3 FIX: Preemptibility Check
    ///
    /// Checks if preemption is allowed (irq_count and preempt_count must be zero).
    /// If not preemptible, defers the reschedule by setting need_resched flag.
    ///
    /// **警告**: 此函数可能不会返回（如果发生上下文切换）
    pub fn reschedule_now(force: bool, origin: kernel_core::ReschedOrigin) {
        if origin == kernel_core::ReschedOrigin::IrqReturn {
            interrupts::without_interrupts(|| {
                if !drain_tick_debt_before_switch() || !finish_pending_prev(origin) {
                    current_cpu().set_need_resched();
                    return;
                }
                if !force && !current_cpu().clear_need_resched() {
                    return;
                }
                if !current_cpu().preemptible() {
                    current_cpu().set_need_resched();
                    return;
                }
                current_cpu().need_resched.store(false, Ordering::SeqCst);
                if let Some(prepared) = Self::prepare_irq_switch() {
                    Self::execute_irq_switch(prepared);
                }
            });
            return;
        }

        // RF178-33: load balancing is deferred until a genuine process-context
        // entry with IF enabled. Timer IRQ return leaves BALANCE_DUE armed.
        if origin == kernel_core::ReschedOrigin::Process
            && interrupts::are_enabled()
            && BALANCE_DUE.swap(false, Ordering::Relaxed)
        {
            interrupts::without_interrupts(Self::balance_queues);
        }

        interrupts::without_interrupts(|| {
            // RF178-3: fold contention-deferred ticks before any switch. The
            // drain uses tri-state table lookup, PCB try_lock, and generation
            // validation, so the IRQ-return path never blocks on process locks
            // and cannot mutate a reaped/reused PID.
            if !drain_tick_debt_before_switch() {
                current_cpu().set_need_resched();
                return;
            }

            // R172-03 FIX: clear the previously-switched-out task's on_cpu gate (Linux
            // finish_task_switch). Runs on EVERY reschedule_now entry — including the idle
            // loop and the no-switch early-returns below — so a task switched out on this
            // CPU becomes claimable within at most one reschedule cycle, and a CPU that
            // IRETQ'd to a fresh user task clears the previous task's gate at its next
            // kernel re-entry (timer preempt -> force_reschedule -> here). Placed BEFORE the
            // need_resched early-return so the clear is never skipped.
            if !finish_pending_prev(origin) {
                current_cpu().set_need_resched();
                return;
            }
            // R67-4 FIX: Check and clear this CPU's need_resched flag
            if !force && !current_cpu().clear_need_resched() {
                return;
            }

            // R69-3 FIX: Check if we can preempt (not in IRQ context, preemption enabled)
            // If not preemptible, set need_resched and defer until a safe point
            if !current_cpu().preemptible() {
                current_cpu().set_need_resched();
                return;
            }

            // R67-4 FIX: Use per-CPU current process
            let old_pid = Self::get_current();

            // 执行调度决策
            let sched_decision = Self::schedule(origin);
            let (next_pid, next_space) = match sched_decision {
                Some(v) => v,
                None => return, // 没有可调度的进程
            };

            // 如果新旧进程相同，无需切换
            if old_pid == Some(next_pid) {
                return;
            }

            // 获取新进程的 PCB（必须存在）
            let next_pcb = match process::get_process(next_pid) {
                Some(p) => p,
                None => return,
            };

            // 获取旧进程的上下文指针
            // 首次调度时 old_pid 为 None，使用哑上下文保存内核启动状态
            // R172-03: also capture the outgoing task's generation, staged below (with its
            // pid) as the PENDING_PREV to be cleared at the next reschedule_now (after the
            // switch-out save completes). (pid, generation) — NOT a raw on_cpu pointer —
            // so a self-exiting/reaped outgoing task can never leave a dangling clear (UAF);
            // the bootstrap path (no PCB) yields generation 0 and is staged with pid 0 below.
            let (old_ctx_ptr, old_generation, old_space): (*mut ArchContext, u64, usize) =
                match old_pid.and_then(process::get_process) {
                    Some(old_pcb) => {
                        let mut guard = old_pcb.lock();

                        // R24-6 fix: 保存当前硬件 FS/GS base 到 PCB
                        // 用户态可能通过 wrfsbase/wrgsbase 指令修改了 TLS 基址，
                        // 必须在切换前读取 MSR 并保存，否则下次恢复时会使用旧值
                        #[cfg(target_arch = "x86_64")]
                        {
                            use x86_64::registers::model_specific::Msr;
                            const MSR_FS_BASE: u32 = 0xC000_0100;
                            // R100-2 FIX: 调度器在 SWAPGS 后运行，此时：
                            //   IA32_GS_BASE (0xC0000101) = 内核 per-CPU 指针
                            //   IA32_KERNEL_GS_BASE (0xC0000102) = 用户态 GS 基址
                            // 必须读写 0xC0000102 以保存/恢复用户态 GS
                            const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

                            unsafe {
                                let fs_msr = Msr::new(MSR_FS_BASE);
                                let gs_msr = Msr::new(MSR_KERNEL_GS_BASE);
                                guard.fs_base = fs_msr.read();
                                guard.gs_base = gs_msr.read();
                            }
                        }

                        let generation = guard.generation;
                        let memory_space = guard.memory_space;
                        (
                            &mut guard.context as *mut _ as *mut ArchContext,
                            generation,
                            memory_space,
                        )
                    }
                    None => {
                        // 首次调度：保存到哑上下文（不会被恢复）
                        let mut bootstrap = BOOTSTRAP_CONTEXT.lock();
                        (&mut *bootstrap as *mut ArchContext, 0u64, 0usize)
                    }
                };

            // R69-2 FIX: Save lazy FPU state before context switch.
            //
            // The lazy FPU implementation tracks FPU owner per-CPU. When a task is
            // switched out, we must save its FPU state and clear ownership to prevent:
            // 1. Cross-CPU stale state: If task migrates to CPU1, CPU0 still thinks
            //    it owns the task's FPU. New task on CPU0 would overwrite migrated
            //    task's FPU state in its PCB.
            // 2. State corruption: Migrated task's current FPU work on CPU1 would
            //    be clobbered when next #NM occurs on CPU0.
            //
            // By saving and clearing before switch, each CPU starts fresh and
            // migrations always restore from saved PCB state via #NM handler.
            if let Some(opid) = old_pid {
                let per_cpu = current_cpu();
                let owner = per_cpu.get_fpu_owner();
                if owner != NO_FPU_OWNER && owner == opid {
                    if let Some(proc_arc) = process::get_process(opid) {
                        let mut pcb = proc_arc.lock();
                        // R69-2 FIX (codex review): Clear CR0.TS before fxsave64.
                        //
                        // Under lazy FPU, CR0.TS may be set if the task never touched
                        // FPU since its last switch-in. Executing fxsave64 with TS=1
                        // would trigger #NM fault inside reschedule_now (with IF=0),
                        // causing re-entry into lazy-FPU handler and potential panic.
                        //
                        // By clearing TS first, we ensure fxsave64 can safely execute.
                        // After the context switch, the next task will have TS set by
                        // switch_context() to enable lazy FPU for the new task.
                        unsafe {
                            use x86_64::registers::control::{Cr0, Cr0Flags};
                            let cr0 = Cr0::read();
                            if cr0.contains(Cr0Flags::TASK_SWITCHED) {
                                let mut new_cr0 = cr0;
                                new_cr0.remove(Cr0Flags::TASK_SWITCHED);
                                Cr0::write(new_cr0);
                            }
                        }
                        // Save current FPU hardware state to PCB
                        let fx_ptr = pcb.context.fx.data.as_mut_ptr();
                        unsafe {
                            core::arch::asm!("fxsave64 [{}]", in(reg) fx_ptr, options(nostack));
                        }
                        pcb.fpu_used = true;
                    }
                    // Clear ownership so this CPU doesn't claim stale state
                    per_cpu.set_fpu_owner(NO_FPU_OWNER);
                }
            }

            // 获取新进程的上下文指针、内核栈顶、CS（用于判断 Ring 3）和 FS/GS base（TLS）
            // R70-4 FIX: Copy context to per-CPU shadow buffer to prevent use-after-unlock.
            // The PCB lock is released at the end of the closure, but we use the shadow
            // buffer's stable pointer for enter_usermode/switch_context.
            // R118-6 FIX: Also extract user_memory_space to pass directly to
            // activate_memory_space(), avoiding PROCESS_TABLE scan in the hot path.
            let (
                new_ctx_ptr,
                next_kstack_top,
                next_cs,
                next_user_space,
                next_fs_base,
                next_gs_base,
                next_wd_handle,
            ): (
                *const ArchContext,
                u64,
                u64,
                usize,
                u64,
                u64,
                Option<WatchdogHandle>,
            ) = NEXT_CONTEXT_SHADOW.with(|shadow| {
                let guard = next_pcb.lock();
                // Copy full context (176 bytes + FPU) to per-CPU shadow while holding lock
                let ctx_ptr = shadow.store(&guard.context);
                let kstack_top = guard.kernel_stack_top.as_u64();
                let cs = guard.context.cs;
                let user_space = guard.user_memory_space;
                let fs_base = guard.fs_base;
                let gs_base = guard.gs_base;
                let wd_handle = guard.watchdog_handle;
                (
                    ctx_ptr, kstack_top, cs, user_space, fs_base, gs_base, wd_handle,
                )
            });
            // The shadow owns every incoming datum used below. Drop the lookup
            // Arc before a non-returning switch so an exiting outgoing task
            // cannot strand that reference on its abandoned kernel stack.
            // PROCESS_TABLE plus next.on_cpu pin the actual PCB lifecycle.
            drop(next_pcb);

            // 判断下一个进程是否为用户态进程（Ring 3）
            // CS 的低 2 位是 RPL（Request Privilege Level）
            // RPL == 3 表示用户态（Ring 3）
            let next_is_user = (next_cs & 0x3) == 0x3;

            // 执行上下文切换
            // switch_context 内部流程：
            // 1. 保存当前寄存器到 old_ctx（在当前/旧地址空间中完成）
            // 2. 恢复新进程寄存器（包括 rsp）
            // 3. 跳转到新进程的 rip
            //
            // 注意：CR3 切换在 switch_context 之后执行会有问题，因为跳转后
            // 已在新进程的执行路径中。因此我们在切换前激活新地址空间。
            //
            // 安全性说明：当前内核使用共享内核地址空间模型，所有进程的
            // 内核映射（高地址半区）相同，因此 CR3 切换后仍能访问所有 PCB。

            // 更新 TSS.rsp0 为新进程的内核栈顶
            // 这确保从用户态中断/异常返回时使用正确的内核栈
            // 如果进程没有专用内核栈，回退到默认内核栈以避免使用旧进程的栈
            let effective_kstack_top = if next_kstack_top != 0 {
                next_kstack_top
            } else {
                default_kernel_stack_top()
            };
            unsafe {
                set_kernel_stack(effective_kstack_top);
            }

            // Debug output for Ring 3 transition (minimal)
            // Uncomment for debugging: kprintln!("[SCHED] -> PID {} (Ring {})", next_pid, if next_is_user { 3 } else { 0 });

            // G.1: Track context switches in per-CPU observability counters
            increment_counter(TraceCounter::ContextSwitches, 1);

            // G.1 Observability: Send heartbeat for hung-task detection.
            // This indicates the process is actively being scheduled (not hung).
            // Lock-free operation - safe even with interrupts disabled.
            if let Some(ref handle) = next_wd_handle {
                let now_ms = kernel_core::time::current_timestamp_ms();
                heartbeat(handle, now_ms);
            }

            process::activate_memory_space(next_space, Some(next_user_space));

            // R172-04 W1: stage the incoming task's FS/GS for the SYSRET-epilogue commit
            // (the switch_context resume path's only TLS-restore site). Covers BOTH
            // branches: a user task resumed mid-syscall via switch_context commits these in
            // its epilogue; a fresh user task entered via switch_to_user gets the direct MSR
            // write below for its IRETQ AND staged here for its first syscall's epilogue.
            stage_pending_tls_bases(next_fs_base, next_gs_base);
            // R172-03: stage the outgoing task as PENDING_PREV — its on_cpu gate is cleared
            // at the NEXT reschedule_now on this CPU (after this switch's save completes),
            // keeping it unclaimable by any CPU until then. Closes the steal-before-save
            // TOCTOU that made switch_to_user's per-CPU save unsafe on SMP.
            stage_prev_on_cpu(old_pid.map(|p| p as u64).unwrap_or(0), old_generation);

            let switch_hook = SECURITY_SWITCH_HOOK
                .get()
                .copied()
                .expect("scheduler security switch hook not registered");
            switch_hook(old_space != next_space);

            // 执行上下文切换
            // 根据目标进程的特权级选择不同的切换方式：
            //
            // - Ring 0（内核进程）：使用 switch_context 直接切换寄存器和栈
            // - Ring 3（用户进程）：使用 switch_to_user（保存内核上下文 + IRETQ 进入用户态）
            //
            // R172-01 FIX: switch_to_user replaces the unsound save_context(old)+enter_usermode(new)
            // pairing — its save-half captures the outgoing kernel rip/rflags/truthful-cs so a
            // later resume via switch_context can never `ret` into stale user .text at CPL0.
            unsafe {
                if next_is_user {
                    // Debug: 打印进入用户态前的上下文（必须在 MSR 写入之前）
                    {
                        let ctx = &*new_ctx_ptr;
                        sched_debug!(
                            "[SCHED] switch_to_user PID={}: rax=0x{:x}, rip=0x{:x}, rsp=0x{:x}, fs_base=0x{:x}",
                            next_pid, ctx.rax, ctx.rip, ctx.rsp, next_fs_base
                        );
                    }

                    // 恢复用户进程的 FS/GS base (TLS 支持) — switch_to_user 的 enter-half 通过
                    // SWAPGS 将 KERNEL_GS_BASE 交换为用户 GS。必须在切换前的最后一步写入 MSR
                    // （kprintln! 等内核代码可能覆盖 FS_BASE MSR）。
                    {
                        use x86_64::registers::model_specific::Msr;
                        const MSR_FS_BASE: u32 = 0xC000_0100;
                        const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

                        let mut fs_msr = Msr::new(MSR_FS_BASE);
                        fs_msr.write(next_fs_base);

                        let mut gs_msr = Msr::new(MSR_KERNEL_GS_BASE);
                        gs_msr.write(next_gs_base);
                    }

                    switch_to_user(old_ctx_ptr, new_ctx_ptr);
                    // 不会到达这里（IRETQ 跳转到用户态；旧任务在下次被 switch_context 调度时
                    // 从 switch_to_user 调用点之后恢复）。
                } else {
                    // 内核态进程：使用标准的 switch_context
                    // 对于旧进程，函数会在下次被调度时从这里"返回"
                    // R65-16 FIX: Validate target context has kernel-mode segments before switching.
                    // This prevents a critical privilege escalation vulnerability.
                    assert_kernel_context(new_ctx_ptr);
                    switch_context(old_ctx_ptr, new_ctx_ptr);
                }
            }
        });
    }
}

/// RF178-33 executable probes for the bounded rotating selector.
pub fn run_bounded_selector_self_test() {
    #[derive(Clone, Copy)]
    struct ProbeEntry {
        runnable: bool,
        contended: bool,
        allowed_cpus: u64,
    }
    type ProbeQueues = BTreeMap<Priority, BTreeMap<Pid, ProbeEntry>>;

    const BLOCKED: ProbeEntry = ProbeEntry {
        runnable: false,
        contended: false,
        allowed_cpus: 0,
    };
    const READY: ProbeEntry = ProbeEntry {
        runnable: true,
        contended: false,
        allowed_cpus: 0,
    };

    fn insert(queue: &mut ProbeQueues, pid: Pid, entry: ProbeEntry) {
        queue.entry(120).or_default().insert(pid, entry);
    }

    fn scan(
        queue: &ProbeQueues,
        target_cpu: usize,
        skip_pid: Option<Pid>,
        cursor: &mut SelectionCursorState,
        epoch: u64,
        budget: usize,
    ) -> (Option<Pid>, usize, bool) {
        let mut best: Option<(Priority, Pid)> = None;
        let (visited, complete) = Scheduler::scan_queue_window(
            queue,
            cursor,
            epoch,
            budget,
            |key, entry| {
                if Some(key.1) == skip_pid
                    || entry.contended
                    || !entry.runnable
                    || !Scheduler::cpu_allowed(target_cpu, entry.allowed_cpus)
                {
                    return;
                }
                if best.map(|current| key < current).unwrap_or(true) {
                    best = Some(key);
                }
            },
        );
        if best.is_some() {
            cursor.cycle_start = None;
        }
        (best.map(|key| key.1), visited, complete)
    }

    // A runnable tail beyond two bounded windows must eventually be observed.
    {
        let mut queue = ProbeQueues::new();
        let blocked_count = SELECT_VISIT_BUDGET * 2 + 2;
        for offset in 0..blocked_count {
            insert(&mut queue, 0x178_3300usize + offset, BLOCKED);
        }
        let tail_pid = 0x178_3300usize + blocked_count;
        insert(&mut queue, tail_pid, READY);
        let mut cursor = SelectionCursorState::new();
        let mut found = false;
        for _ in 0..4 {
            let (candidate, visited, _) =
                scan(&queue, 0, None, &mut cursor, 0, SELECT_VISIT_BUDGET);
            assert!(visited <= SELECT_VISIT_BUDGET);
            if candidate == Some(tail_pid) {
                found = true;
                break;
            }
        }
        assert!(found, "rotating cursor must reach a runnable tail entry");
    }

    // Exact-budget and two-window empty queues must prove a complete cycle.
    {
        let mut queue = ProbeQueues::new();
        for offset in 0..SELECT_VISIT_BUDGET {
            insert(&mut queue, 0x178_3380usize + offset, BLOCKED);
        }
        let mut cursor = SelectionCursorState::new();
        let (candidate, visited, complete) =
            scan(&queue, 0, None, &mut cursor, 0, SELECT_VISIT_BUDGET);
        assert!(candidate.is_none());
        assert_eq!(visited, SELECT_VISIT_BUDGET);
        assert!(complete, "exact-budget queue completes one cycle");
    }
    {
        let mut queue = ProbeQueues::new();
        for offset in 0..(SELECT_VISIT_BUDGET * 2) {
            insert(&mut queue, 0x178_33a0usize + offset, BLOCKED);
        }
        let mut cursor = SelectionCursorState::new();
        assert!(!scan(&queue, 0, None, &mut cursor, 0, SELECT_VISIT_BUDGET).2);
        assert!(scan(&queue, 0, None, &mut cursor, 0, SELECT_VISIT_BUDGET).2);
    }

    // Mutation invalidates the old anchor, including a new key in the already
    // visited range. The persistent cursor reaches it after wrapping.
    {
        let mut queue = ProbeQueues::new();
        for offset in 0..(SELECT_VISIT_BUDGET * 2) {
            insert(&mut queue, 0x178_33c0usize + offset * 2, BLOCKED);
        }
        let mut cursor = SelectionCursorState::new();
        assert!(!scan(&queue, 0, None, &mut cursor, 0, SELECT_VISIT_BUDGET).2);
        let inserted_pid = 0x178_33c1usize;
        insert(&mut queue, inserted_pid, READY);
        assert!(!scan(&queue, 0, None, &mut cursor, 1, SELECT_VISIT_BUDGET).2);
        assert_eq!(
            scan(&queue, 0, None, &mut cursor, 1, SELECT_VISIT_BUDGET).0,
            Some(inserted_pid)
        );
    }

    // Current-only, contention, affinity, and independent owner/thief cursors.
    {
        let pid = 0x178_33f0usize;
        let mut queue = ProbeQueues::new();
        insert(&mut queue, pid, READY);
        let mut cursor = SelectionCursorState::new();
        let result = scan(&queue, 0, Some(pid), &mut cursor, 0, SELECT_VISIT_BUDGET);
        assert!(result.0.is_none() && result.2);
    }
    {
        let owner_pid = 0x178_33f8usize;
        let mut queue = ProbeQueues::new();
        insert(
            &mut queue,
            owner_pid,
            ProbeEntry {
                allowed_cpus: 1,
                ..READY
            },
        );
        for offset in 1..(SELECT_VISIT_BUDGET * 2) {
            insert(&mut queue, owner_pid + offset, BLOCKED);
        }
        let mut thief_cursor = SelectionCursorState::new();
        assert!(scan(
            &queue,
            1,
            None,
            &mut thief_cursor,
            0,
            SELECT_VISIT_BUDGET,
        )
        .0
        .is_none());
        let mut owner_cursor = SelectionCursorState::new();
        assert_eq!(
            scan(
                &queue,
                0,
                None,
                &mut owner_cursor,
                0,
                SELECT_VISIT_BUDGET,
            )
            .0,
            Some(owner_pid)
        );
    }
    {
        let held_pid = 0x178_3400usize;
        let ready_pid = held_pid + 1;
        let mut queue = ProbeQueues::new();
        insert(
            &mut queue,
            held_pid,
            ProbeEntry {
                contended: true,
                ..READY
            },
        );
        insert(&mut queue, ready_pid, READY);
        let mut cursor = SelectionCursorState::new();
        let result = scan(&queue, 0, None, &mut cursor, 0, 2);
        assert_eq!((result.0, result.1), (Some(ready_pid), 2));
    }
    {
        let pid = 0x178_3500usize;
        let mut queue = ProbeQueues::new();
        insert(
            &mut queue,
            pid,
            ProbeEntry {
                allowed_cpus: 1,
                ..READY
            },
        );
        let mut cursor = SelectionCursorState::new();
        assert!(scan(&queue, 1, None, &mut cursor, 0, 1).0.is_none());
        cursor.after = Some((u8::MAX, usize::MAX));
        cursor.cycle_start = None;
        assert_eq!(scan(&queue, 0, None, &mut cursor, 0, 1).0, Some(pid));
    }

    // Synchronous exit can wait indefinitely for another runnable task while
    // timer IRQs wake its boot-CR3 retry loop. More than the maximum quantum of
    // such wakes must never make the Zombie eligible for tick mutation.
    let mut exiting = Process::new(
        0x178_3700,
        1,
        alloc::string::String::from("rf178-33-sync-exit"),
        139,
    );
    exiting.enter_running_at(0);
    exiting.on_cpu.store(true, Ordering::Release);
    exiting.state = ProcessState::Zombie;
    let exit_slice = exiting.time_slice;
    for _ in 0..=300 {
        assert!(!Scheduler::current_task_may_consume_tick(&exiting));
    }
    assert_eq!(exiting.state, ProcessState::Zombie);
    assert_eq!(exiting.time_slice, exit_slice);
}

/// RF178-36 executable probe for identity-bound stopped/fatal resume.
pub fn run_identity_resume_self_test() {
    let mut proc = Process::new(
        0x178_3601,
        1,
        alloc::string::String::from("rf178-36-resume"),
        120,
    );
    let pid = proc.pid;
    let generation = proc.generation;

    proc.enter_ready_at(10);
    proc.stopped = true;
    assert!(Scheduler::resume_stopped_locked(&mut proc, pid, generation));
    assert_eq!(proc.state, ProcessState::Ready);
    assert!(!proc.stopped);

    // Neither half of the identity tuple is advisory.
    proc.stopped = true;
    assert!(!Scheduler::resume_stopped_locked(
        &mut proc,
        pid + 1,
        generation,
    ));
    assert!(proc.stopped);
    assert!(!Scheduler::resume_stopped_locked(
        &mut proc,
        pid,
        generation.wrapping_add(1),
    ));
    assert!(proc.stopped);

    // Plain SIGCONT releases job control but preserves an unrelated block.
    proc.enter_blocked_at(20);
    proc.stopped = true;
    assert!(!Scheduler::resume_stopped_locked(&mut proc, pid, generation));
    assert_eq!(proc.state, ProcessState::Blocked);
    assert!(!proc.stopped);

    // RF178-35: fatal publication performs its own normalization. A stale
    // SIGCONT callback observed before that publication is now a no-op.
    proc.enter_ready_at(30);
    proc.pending_kill.store(true, Ordering::Release);
    assert!(!Scheduler::resume_stopped_locked(&mut proc, pid, generation));
    assert_eq!(proc.state, ProcessState::Ready);
    proc.pending_kill.store(false, Ordering::Release);

    proc.enter_running_at(40);
    proc.stopped = true;
    assert!(!Scheduler::resume_stopped_locked(&mut proc, pid, generation));
    assert_eq!(proc.state, ProcessState::Running);
    assert!(!proc.stopped);

    for terminal in [ProcessState::Zombie, ProcessState::Terminated] {
        proc.state = terminal;
        proc.stopped = true;
        assert!(!Scheduler::resume_stopped_locked(&mut proc, pid, generation));
        assert_eq!(proc.state, terminal);
    }
}

/// M4-1: force-init the scheduler's per-CPU CpuLocal statics (READY_QUEUE,
/// CURRENT_PROCESS, NEXT_CONTEXT_SHADOW) so the first AP timer tick never lazily
/// heap-allocates a slab in IRQ (the R151-5 deadlock class). Called from init() BEFORE
/// register_timer_callback wires on_clock_tick — the only path that touches these statics.
fn force_init_sched_locals() {
    READY_QUEUE.force_init();
    CURRENT_PROCESS.force_init();
    NEXT_CONTEXT_SHADOW.force_init();
    PENDING_PREV_ON_CPU.force_init(); // R172-03: per-CPU finish_task_switch slot
}

/// 初始化调度器
pub fn init() {
    // M4-1 (force-init): pre-allocate the scheduler per-CPU statics BEFORE
    // register_timer_callback (below) wires on_clock_tick into the timer ISR.
    force_init_sched_locals();

    // 注册进程清理回调，确保进程终止时调度器同步更新
    process::register_cleanup_notifier(Scheduler::remove_process);

    // 注册调度器添加进程回调，用于 clone/fork 时添加新进程
    process::register_scheduler_add(Scheduler::add_process);

    // 注册定时器回调，让 arch 模块的定时器中断能调用调度器
    kernel_core::register_timer_callback(Scheduler::on_clock_tick);

    // 注册重调度回调，让系统调用返回时能触发调度
    kernel_core::register_resched_callback(Scheduler::reschedule_now);

    // 注册信号恢复回调，让 SIGCONT 能正确恢复暂停的进程
    kernel_core::register_resume_callback(Scheduler::resume_stopped);

    // M0-5 1b: register the cross-CPU reschedule-kick so a signal-wake's Blocked->Ready flip
    // promptly re-selects the target on the (idle, non-empty-queue) CPU that owns it.
    kernel_core::register_kick_callback(Scheduler::kick_all_for_reschedule);

    klog_always!("Enhanced scheduler initialized");
    klog_always!("  Ready queue: per-CPU with work stealing (R69-1)");
    klog_always!("  Scheduling algorithm: Priority-based with time slice");
    klog_always!("  SMP kick: IPI wake on new work (R70-2)");
    klog_always!("  Context switch: Enabled with CR3 switching + Ring 3 IRETQ support");
}
