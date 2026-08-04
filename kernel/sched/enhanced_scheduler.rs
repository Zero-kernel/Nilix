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

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::ops::Bound;
use core::ops::Bound::{Excluded, Included, Unbounded};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cpu_local::{current_cpu, current_cpu_id, max_cpus, CpuLocal, NO_FPU_OWNER, PER_CPU_DATA};
use kernel_core::cgroup;
use kernel_core::process::{
    self, Priority, Process, ProcessArc, ProcessId, ProcessNameSnapshot, ProcessState,
};
use lazy_static::lazy_static;
use mm::{AdmittedMap, HeapClass, PreparedAdmittedMapCapacity, RetiredAdmittedMapCapacity};
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
pub type ProcessControlBlock = ProcessArc;

/// 优先级分桶的就绪队列类型
///
/// 结构: Priority -> (Pid -> ProcessControlBlock)
/// - 按优先级从低到高排序（优先级数值越小越优先）
/// - 同优先级内按 PID 先入先出
/// One lexicographically ordered `(priority, pid)` map preserves priority/PID
/// traversal without embedding 256 heap-owning map headers in every per-CPU
/// slot. The old representation forced CpuLocal to infallibly allocate at
/// least 512 KiB of uncharged empty headers across MAX_CPUS before one task was
/// queued. Runtime backing remains fallibly admitted and detached-prepared.
const PRIORITY_BUCKETS: usize = u8::MAX as usize + 1;
type ReadyMapKey = (Priority, Pid);
type PreparedReadyBacking<T> = PreparedAdmittedMapCapacity<ReadyMapKey, T>;
type RetiredReadyBacking<T> = RetiredAdmittedMapCapacity<ReadyMapKey, T>;

#[derive(Clone, Copy)]
struct PriorityBucketRef<'a, T> {
    entries: &'a AdmittedMap<ReadyMapKey, T>,
    priority: Priority,
}

impl<'a, T> PriorityBucketRef<'a, T> {
    fn get(self, pid: &Pid) -> Option<&'a T> {
        self.entries.get(&(self.priority, *pid))
    }

    fn contains_key(self, pid: &Pid) -> bool {
        self.entries.get(&(self.priority, *pid)).is_some()
    }

    fn iter(self) -> impl DoubleEndedIterator<Item = (&'a Pid, &'a T)> + 'a {
        self.entries
            .range((self.priority, 0)..=(self.priority, Pid::MAX))
            .map(|(key, value)| (&key.1, value))
    }

    fn range(
        self,
        bounds: (Bound<Pid>, Bound<Pid>),
    ) -> impl DoubleEndedIterator<Item = (&'a Pid, &'a T)> + 'a {
        let lower = match bounds.0 {
            Included(pid) => Included((self.priority, pid)),
            Excluded(pid) => Excluded((self.priority, pid)),
            Unbounded => Included((self.priority, 0)),
        };
        let upper = match bounds.1 {
            Included(pid) => Included((self.priority, pid)),
            Excluded(pid) => Excluded((self.priority, pid)),
            Unbounded => Included((self.priority, Pid::MAX)),
        };
        self.entries
            .range((lower, upper))
            .map(|(key, value)| (&key.1, value))
    }

    fn len(self) -> usize {
        self.iter().count()
    }

    fn is_empty(self) -> bool {
        self.iter().next().is_none()
    }

    /// Capacity belongs to the compact aggregate map, not one priority view.
    fn capacity(self) -> usize {
        self.entries.capacity()
    }
}

struct PriorityBucketMut<'a, T> {
    entries: &'a mut AdmittedMap<ReadyMapKey, T>,
    priority: Priority,
}

impl<T> PriorityBucketMut<'_, T> {
    fn try_insert(&mut self, pid: Pid, value: T) -> Result<Option<T>, mm::AdmittedAllocError> {
        self.entries.try_insert((self.priority, pid), value)
    }

    fn insert_unique_reserved(&mut self, pid: Pid, value: T) -> Result<(), (Pid, T)> {
        self.entries
            .insert_unique_reserved((self.priority, pid), value)
            .map_err(|((_priority, pid), value)| (pid, value))
    }

    fn remove_retaining_capacity(&mut self, pid: &Pid) -> Option<T> {
        self.entries
            .remove_retaining_capacity(&(self.priority, *pid))
    }

    fn install_prepared_deferred(
        &mut self,
        prepared: PreparedReadyBacking<T>,
    ) -> Result<RetiredReadyBacking<T>, mm::AdmittedAllocError> {
        self.entries.install_prepared_deferred(prepared)
    }
}

struct PriorityQueues<T> {
    entries: AdmittedMap<ReadyMapKey, T>,
    /// Capacity slots held exclusively for remove-then-publish rollback.
    /// The compact aggregate map allows any retained slot to restore any
    /// priority/PID key, so one count is both sufficient and exact. Ordinary
    /// enqueue/removal paths preserve this count until migration
    /// either restores the source membership or commits its removal.
    rollback_slots: usize,
}

impl<T> PriorityQueues<T> {
    const fn new() -> Self {
        Self {
            entries: AdmittedMap::new(HeapClass::Scheduler),
            rollback_slots: 0,
        }
    }

    #[inline]
    fn bucket(&self, priority: Priority) -> PriorityBucketRef<'_, T> {
        PriorityBucketRef {
            entries: &self.entries,
            priority,
        }
    }

    #[inline]
    fn bucket_mut(&mut self, priority: Priority) -> PriorityBucketMut<'_, T> {
        PriorityBucketMut {
            entries: &mut self.entries,
            priority,
        }
    }

    #[inline]
    fn iter(&self) -> impl Iterator<Item = (Priority, PriorityBucketRef<'_, T>)> {
        (0..PRIORITY_BUCKETS).map(move |priority| {
            let priority = priority as Priority;
            (priority, self.bucket(priority))
        })
    }

    #[inline]
    fn values(&self) -> impl Iterator<Item = PriorityBucketRef<'_, T>> {
        (0..PRIORITY_BUCKETS).map(move |priority| self.bucket(priority as Priority))
    }

    #[inline]
    fn protected_slots(&self, _priority: Priority) -> usize {
        self.rollback_slots
    }

    #[inline]
    fn capacity(&self) -> usize {
        self.entries.capacity()
    }

    /// Remove one membership without destroying either its value or an empty
    /// allocator backing while the ready-queue lock is held. The caller owns
    /// both returned values and must drop them after releasing the lock.
    #[must_use = "removed values and retired backing must leave the ready-queue lock"]
    fn remove_ordinary(
        &mut self,
        priority: Priority,
        pid: &Pid,
    ) -> (Option<T>, Option<RetiredReadyBacking<T>>) {
        let protected = self.rollback_slots != 0;
        let removed = self.bucket_mut(priority).remove_retaining_capacity(pid);
        let retired = if removed.is_some() && !protected {
            self.entries.take_empty_capacity()
        } else {
            None
        };
        (removed, retired)
    }

    fn remove_for_migration(&mut self, priority: Priority, pid: &Pid) -> Option<T> {
        let removed = self.bucket_mut(priority).remove_retaining_capacity(pid)?;
        self.rollback_slots = self
            .rollback_slots
            .checked_add(1)
            .expect("scheduler rollback-slot count overflow");
        Some(removed)
    }

    fn restore_migration(
        &mut self,
        priority: Priority,
        pid: Pid,
        value: T,
    ) -> Result<(), (Pid, T)> {
        assert!(
            self.rollback_slots != 0,
            "scheduler migration restore without protected source slot"
        );
        self.bucket_mut(priority)
            .insert_unique_reserved(pid, value)?;
        self.rollback_slots -= 1;
        Ok(())
    }

    /// Commit a remove-then-publish transaction without physically retiring an
    /// empty source backing under the source queue lock.
    #[must_use = "retired scheduler backing must be dropped outside the source lock"]
    fn commit_migration_removal(&mut self, priority: Priority) -> Option<RetiredReadyBacking<T>> {
        let _ = priority;
        assert!(
            self.rollback_slots != 0,
            "scheduler migration commit without protected source slot"
        );
        self.rollback_slots -= 1;
        if self.rollback_slots == 0 {
            self.entries.take_empty_capacity()
        } else {
            None
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

type ReadyQueues = PriorityQueues<ProcessControlBlock>;

const _: () = assert!(
    core::mem::size_of::<Mutex<ReadyQueues>>() * cpu_local::MAX_CPUS
        + 2 * core::mem::size_of::<usize>()
        <= mm::NORMAL_UNADMITTED_RESERVE_BYTES / 8
);

const READY_INSERT_RETRY_LIMIT: usize = 4;

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

/// Per-CPU first-switch save slot. Concurrent first dispatches on the BSP and
/// APs must never alias one writable bootstrap context.
struct BootstrapContext {
    buf: UnsafeCell<ArchContext>,
}

unsafe impl Send for BootstrapContext {}
unsafe impl Sync for BootstrapContext {}

impl BootstrapContext {
    fn new() -> Self {
        Self {
            buf: UnsafeCell::new(ArchContext::new()),
        }
    }

    /// The caller owns this CPU and has IF clear for the complete save window.
    #[inline]
    fn as_mut_ptr(&self) -> *mut ArchContext {
        self.buf.get()
    }
}

static BOOTSTRAP_CONTEXT: CpuLocal<BootstrapContext> = CpuLocal::new(BootstrapContext::new);

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
) -> bool {
    let parent = if parent_pid == 0 {
        None
    } else {
        match process::try_get_process(parent_pid) {
            None => return false,
            Some(parent) => parent,
        }
    };
    let Some(parent) = parent else {
        let Some(child) = child.try_lock() else {
            return false;
        };
        if child.generation == generation {
            child.switch_reap_pending.store(false, Ordering::Release);
        }
        return true;
    };
    // Use try locks for both origins: this is a cross-PCB handoff and must not
    // introduce a parent<->child lock-order cycle. The pending-prev slot retries.
    let Some(mut parent) = parent.try_lock() else {
        return false;
    };
    let Some(child) = child.try_lock() else {
        return false;
    };
    if child.generation != generation {
        return true;
    }
    // Publish reappability while the parent's guard still prevents it from
    // running. A parent made Ready below can therefore never observe the old
    // on_cpu/reap-pending state and re-block without a matching wake.
    child.switch_reap_pending.store(false, Ordering::Release);
    let waiting = parent.waiting_child;
    let woke =
        parent.state == ProcessState::Blocked && (waiting == Some(0) || waiting == Some(child_pid));
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
fn finish_pending_prev() -> bool {
    let (pid, generation) = PENDING_PREV_ON_CPU.with(|s| {
        (
            s.pid.load(Ordering::Acquire),
            s.generation.load(Ordering::Relaxed),
        )
    });
    if pid == 0 {
        return true;
    }
    let pcb = match process::try_get_process(pid as usize) {
        None => return false,
        Some(pcb) => pcb,
    };
    let mut reaper = None;
    let mut reap_pcb = None;
    if let Some(pcb) = pcb {
        let proc = match pcb.try_lock() {
            Some(proc) => proc,
            None => return false,
        };
        // Generation guard: a reaped+recycled pid now names a DIFFERENT task; clearing its
        // on_cpu while it runs would re-open the double-run hole. Only clear if it is still
        // the same task instance whose save we just completed.
        if proc.generation == generation {
            if proc.state == ProcessState::Zombie && proc.teardown_done.load(Ordering::Acquire) {
                proc.switch_reap_pending.store(true, Ordering::Release);
                reaper = Some(proc.ppid);
                reap_pcb = Some(pcb.clone());
            }
            proc.on_cpu.store(false, Ordering::Release);
        }
    }
    if let Some(parent_pid) = reaper {
        let Some(pcb) = reap_pcb.as_ref() else {
            return false;
        };
        if !wake_reaper_after_switch(parent_pid, pid as Pid, generation, pcb) {
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
    CpuLocal::new(|| Mutex::new(ReadyQueues::new()));

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

/// Fully prepared context switch. PCB/table/cpuset locks have all been
/// released. The outgoing PCB remains pinned by PROCESS_TABLE while `on_cpu`
/// is true; deferred teardown now refuses to proceed until finish-task-switch
/// clears that publication. The incoming context is copied to a per-CPU shadow.
struct PreparedSwitch {
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
    next_kcov_token: usize,
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

    /// Return the queue entry immediately after `after`, wrapping at the end.
    /// Tree lookups are O(log N); the caller imposes the hard PCB-visit bound.
    fn next_queue_entry<'a, T>(
        queue: &'a PriorityQueues<T>,
        after: Option<(Priority, Pid)>,
    ) -> Option<((Priority, Pid), &'a T)> {
        if let Some((priority, pid)) = after {
            let bucket = queue.bucket(priority);
            if let Some((&next_pid, pcb)) = bucket.range((Excluded(pid), Unbounded)).next() {
                return Some(((priority, next_pid), pcb));
            }
            for next_priority_raw in (priority as usize + 1)..PRIORITY_BUCKETS {
                let next_priority = next_priority_raw as Priority;
                let bucket = queue.bucket(next_priority);
                if let Some((&next_pid, pcb)) = bucket.iter().next() {
                    return Some(((next_priority, next_pid), pcb));
                }
            }
        }

        for (priority, bucket) in queue.iter() {
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
        queue: &PriorityQueues<T>,
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
            if !queue.bucket(priority).contains_key(&pid) {
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
        let (visited, complete_cycle) =
            Self::scan_queue_window(queue, cursor, queue_epoch, visit_budget, |key, pcb| {
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
            });

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
            sched_debug!(
                "[SCHED] selected pid={} after {} visits",
                _pid,
                result.visited
            );
        } else {
            sched_debug!(
                "[SCHED] no ready process in {} bounded visits",
                result.visited
            );
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

    /// RF180-46: a ready-queue owner may be performing an attacker-scaled
    /// sorted-map mutation with interrupts enabled. Never spin behind that
    /// owner after IF has been cleared: defer the scheduling point instead so
    /// the local CPU can restore IF and make forward progress.
    #[inline]
    fn lock_ready_queue_or_defer<'a>(
        queue: &'a Mutex<ReadyQueues>,
    ) -> Option<spin::MutexGuard<'a, ReadyQueues>> {
        if interrupts::are_enabled() {
            return Some(queue.lock());
        }

        match queue.try_lock() {
            Some(queue) => Some(queue),
            None => {
                current_cpu().set_need_resched();
                None
            }
        }
    }

    /// Calculate the length of a ready queue
    #[inline]
    fn queue_len(queue: &ReadyQueues) -> usize {
        queue.len()
    }

    /// Get queue length for a specific CPU
    #[inline]
    fn queue_len_for_cpu(cpu_id: usize) -> usize {
        let Some(queue) = Self::ready_queue_for_cpu(cpu_id) else {
            return 0;
        };
        let Some(queue) = Self::lock_ready_queue_or_defer(queue) else {
            return 0;
        };
        Self::queue_len(&queue)
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
    fn effective_allowed_cpus(proc: &process::Process) -> Option<u64> {
        let cpuset_id = CpusetId(proc.cpuset_id);
        let effective = cpuset::effective_cpus(cpuset_id, proc.allowed_cpus);

        // If affinity is disjoint from cpuset, ignore affinity and use the
        // cpuset itself. An empty cpuset has no safe CPU fallback: manufacturing
        // CPU 0 would cross the isolation boundary it is supposed to enforce.
        if effective == 0 {
            let cpuset_only = cpuset::effective_cpus(cpuset_id, 0);
            if cpuset_only == 0 {
                return None;
            }
            return Some(cpuset_only);
        }

        Some(effective)
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
        (cpuset_only != 0).then_some(cpuset_only)
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

    #[inline]
    fn publish_ready_signal<F>(need_resched: &AtomicBool, remote: bool, kick: F)
    where
        F: FnOnce(),
    {
        // Queue publication is level-triggered. The target must observe the
        // pending bit before an IPI can make it enter the scheduling path.
        need_resched.store(true, Ordering::Release);
        if remote {
            kick();
        }
    }

    /// Arm the CPU that owns newly published runnable work. Remote publication
    /// sets the level bit first and sends the edge-triggered IPI last.
    fn arm_ready_cpu(cpu_id: usize) {
        assert!(
            cpu_local::is_cpu_online(cpu_id),
            "runnable work published to an offline CPU"
        );
        let target = PER_CPU_DATA
            .get_cpu(cpu_id)
            .expect("online CPU lacks initialized scheduler state");
        let remote = cpu_id != current_cpu_id();
        Self::publish_ready_signal(&target.need_resched, remote, || Self::kick_cpu(cpu_id));
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
                .and_then(|queue| Self::lock_ready_queue_or_defer(queue))
                .map(|queue| queue.is_empty())
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
    fn least_loaded_cpu(exclude: Option<usize>, allowed_cpus: u64) -> Option<(usize, usize)> {
        let mut best_cpu = None;
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
                let Some(queue) = Self::lock_ready_queue_or_defer(q) else {
                    continue;
                };
                let len = Self::queue_len(&queue);
                if len < best_len {
                    best_len = len;
                    best_cpu = Some(cpu_id);
                }
            }
        }
        best_cpu.map(|cpu_id| (cpu_id, best_len))
    }

    /// Select target CPU for new/resumed work (load-aware placement)
    ///
    /// # Arguments
    /// * `preferred_cpu` - Default CPU (usually current CPU)
    /// * `allowed_cpus` - Affinity mask (bit N = CPU N allowed). If 0, all CPUs are considered.
    fn target_cpu_for_new_work(preferred_cpu: usize, allowed_cpus: u64) -> Option<usize> {
        // R70-2 FIX: Pass affinity mask to least_loaded_cpu
        let (least_cpu, least_len) = Self::least_loaded_cpu(None, allowed_cpus)?;
        let preferred_len = Self::queue_len_for_cpu(preferred_cpu);

        // If preferred CPU is not allowed, always use least_cpu
        if allowed_cpus != 0 && !Self::cpu_allowed(preferred_cpu, allowed_cpus) {
            return Some(least_cpu);
        }

        if least_len != usize::MAX
            && least_cpu != preferred_cpu
            && least_len + LOAD_IMBALANCE_THRESHOLD < preferred_len
        {
            Some(least_cpu)
        } else {
            Some(preferred_cpu)
        }
    }

    #[inline]
    fn mark_queue_mutated(cpu_id: usize) {
        if let Some(epoch) = QUEUE_MUTATION_EPOCH.get(cpu_id) {
            epoch.fetch_add(1, Ordering::Release); // lint-fetch-add: allow (queue generation)
        }
    }

    /// RF180-46 REVIEW FIX: publish one ready membership with detached backing
    /// preparation. Snapshot/recheck makes concurrent queue growth harmless:
    /// an undersized candidate is discarded outside the lock and retried. Both
    /// obsolete and unused backings leave the ready-queue critical section
    /// before their destructors run.
    fn try_insert_ready(
        queue_ref: &Mutex<ReadyQueues>,
        queue_cpu: usize,
        priority: Priority,
        pid: Pid,
        pcb: ProcessControlBlock,
    ) -> Result<(), process::SchedulerAddError> {
        if !interrupts::are_enabled() {
            return Err(process::SchedulerAddError::Unavailable);
        }
        let mut value = Some(pcb);
        let mut prepared: Option<PreparedReadyBacking<ProcessControlBlock>> = None;

        for _ in 0..READY_INSERT_RETRY_LIMIT {
            let candidate = prepared.take();
            let mut unused = None;
            let mut retired = None;
            // Process-context queue mutation deliberately runs with IF enabled.
            // AdmittedMap is Vec-backed, so backing replacement and sorted
            // insertion can move attacker-scaled entries.
            let step = (|| {
                let Some(mut queue) = Self::lock_ready_queue_or_defer(queue_ref) else {
                    unused = candidate;
                    return Err(process::SchedulerAddError::Unavailable);
                };
                if queue.bucket(priority).contains_key(&pid) {
                    unused = candidate;
                    return Err(process::SchedulerAddError::InvalidState);
                }

                let Some(required) = queue
                    .len()
                    .checked_add(queue.protected_slots(priority))
                    .and_then(|needed| needed.checked_add(1))
                else {
                    unused = candidate;
                    return Err(process::SchedulerAddError::NoMemory);
                };

                if required > queue.capacity() {
                    let Some(doubled) = queue.capacity().max(4).checked_mul(2) else {
                        unused = candidate;
                        return Err(process::SchedulerAddError::NoMemory);
                    };
                    let preferred = doubled.max(required);
                    match candidate {
                        Some(candidate) if candidate.capacity() >= required => {
                            retired = Some(
                                queue
                                    .bucket_mut(priority)
                                    .install_prepared_deferred(candidate)
                                    .expect("RF180-46 prepared scheduler backing invariant"),
                            );
                        }
                        stale => {
                            unused = stale;
                            return Ok(Some((preferred, required)));
                        }
                    }
                } else {
                    unused = candidate;
                }

                let entry = value
                    .take()
                    .expect("RF180-46 scheduler insert retried after publication");
                if let Err((_pid, returned)) = queue
                    .bucket_mut(priority)
                    .insert_unique_reserved(pid, entry)
                {
                    value = Some(returned);
                    return Err(process::SchedulerAddError::InvalidState);
                }
                Self::mark_queue_mutated(queue_cpu);
                Ok(None)
            })();

            // Dropping a prepared candidate rolls back its reservation; dropping
            // a retired backing frees storage before releasing its committed
            // charge. Neither destructor may run under a ready-queue lock.
            drop(unused);
            drop(retired);

            match step? {
                None => return Ok(()),
                Some((preferred, required)) => {
                    prepared =
                        match PreparedAdmittedMapCapacity::try_new(HeapClass::Scheduler, preferred)
                        {
                            Ok(candidate) => Some(candidate),
                            Err(_) if preferred != required => Some(
                                PreparedAdmittedMapCapacity::try_new(
                                    HeapClass::Scheduler,
                                    required,
                                )
                                .map_err(|_| process::SchedulerAddError::NoMemory)?,
                            ),
                            Err(_) => return Err(process::SchedulerAddError::NoMemory),
                        };
                }
            }
        }

        Err(process::SchedulerAddError::NoMemory)
    }

    /// RF178-33 / P1-B: identity-bound membership remove on one ready queue.
    ///
    /// Drops the PID slot only when the queued PCB's generation matches.
    /// Generation mismatch (recycled PID) or missing entry → no-op.
    /// Zero heap allocation; process-context only (holds PCB lock briefly).
    fn remove_identity_from_ready_queues(
        queue: &mut ReadyQueues,
        queue_cpu: Option<usize>,
        pid: Pid,
        generation: u64,
    ) -> (
        Option<ProcessControlBlock>,
        Option<RetiredReadyBacking<ProcessControlBlock>>,
    ) {
        // Membership scan: PI boost can drift dynamic_priority from the bucket key.
        let match_priority = queue.iter().find_map(|(priority, bucket)| {
            let pcb = bucket.get(&pid)?;
            let proc = pcb.lock();
            if proc.pid == pid && proc.generation == generation {
                Some(priority)
            } else {
                None
            }
        });
        let Some(priority) = match_priority else {
            return (None, None);
        };
        let removed = queue.remove_ordinary(priority, &pid);
        if removed.0.is_some() {
            if let Some(cpu_id) = queue_cpu {
                Self::mark_queue_mutated(cpu_id);
            }
        }
        removed
    }

    /// RF178-33 / P1-B: identity-bound queue purge for reaped tasks.
    ///
    /// `cleanup_zombie` clears the PROCESS_TABLE slot before the scheduler
    /// notifier runs. A recycled PID may already be live and enqueued under the
    /// same numeric id with a *new* generation. Removing by PID alone would
    /// orphan that successor (task-resurrection / ABA class).
    ///
    /// Contract:
    /// - Drop the slot only when the queued PCB's `(pid, generation)` matches.
    /// - Missing entry / generation mismatch: no-op (idempotent double-remove).
    /// - Process-context only (cleanup_zombie / reaper); may take PCB locks.
    fn remove_identity_from_all_queues(pid: Pid, generation: u64) {
        for cpu_id in 0..max_cpus() {
            if let Some(queue) = Self::ready_queue_for_cpu(cpu_id) {
                let (removed, retired) = {
                    let mut guard = queue.lock();
                    Self::remove_identity_from_ready_queues(
                        &mut guard,
                        Some(cpu_id),
                        pid,
                        generation,
                    )
                };
                drop(removed);
                drop(retired);
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
    ) -> Option<(ProcessControlBlock, Priority)> {
        let key = queue.iter().find_map(|(k, bucket)| {
            if bucket.contains_key(&pid) {
                Some(k)
            } else {
                None
            }
        })?;
        // Migration is a remove-then-publish transaction. Protect the exact
        // admitted source slot from every competing enqueue until destination
        // publication succeeds or rollback restores this membership.
        let pcb = queue.remove_for_migration(key, &pid);
        if pcb.is_some() {
            if let Some(cpu_id) = queue_cpu {
                Self::mark_queue_mutated(cpu_id);
            }
        }
        pcb.map(|pcb| (pcb, key))
    }

    /// Pop a ready process from a queue (for migration)
    fn pop_ready_process(
        queue: &mut ReadyQueues,
        queue_cpu: usize,
        target_cpu: usize,
    ) -> Option<(Pid, ProcessControlBlock, Priority)> {
        let (pid, _selected, priority) =
            Self::select_next_for_migration_locked(queue, queue_cpu, target_cpu, None)?;
        let (removed, membership_priority) =
            Self::remove_pid_from_queue(queue, Some(queue_cpu), pid)
                .expect("selected migration candidate disappeared under its queue lock");
        let _ = priority;
        Some((pid, removed, membership_priority))
    }

    /// Try to steal a ready process from another CPU
    fn steal_one(
        current_pid: Option<Pid>,
    ) -> Option<(Pid, ProcessControlBlock, Priority, usize, Priority)> {
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
        let mut guard = Self::lock_ready_queue_or_defer(queue)?;
        let mut retries = 0usize;
        let mut candidate =
            Self::select_next_for_migration_locked(&guard, source_cpu, local_cpu, current_pid);
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
            if let Some(pcb) = proc_arc.try_lock() {
                let Some(effective_mask) = Self::effective_allowed_cpus(&pcb) else {
                    candidate = Self::select_next_for_migration_locked(
                        &guard,
                        source_cpu,
                        local_cpu,
                        Some(pid),
                    );
                    continue;
                };
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
                drop(pcb);
                // R171-M4-1 FIX: remove from the source queue by MEMBERSHIP, NOT by the
                // (possibly PI-drifted) `priority` above. Keying the remove off
                // `pcb.dynamic_priority` could miss the real bucket and leave the PCB in the
                // source queue while the caller (`select_next_process`) inserts it locally —
                // double-queuing one PCB across two CPUs. Only steal if the remove succeeded.
                let (stolen, membership_priority) =
                    Self::remove_pid_from_queue(&mut guard, Some(source_cpu), pid)
                        .expect("selected steal candidate disappeared under its queue lock");
                drop(guard);
                // RF180-46: stealing is a Ready-to-Ready migration. The normal
                // local selection transaction claims Running/on_cpu only after
                // destination publication has completed.
                return Some((pid, stolen, priority, source_cpu, membership_priority));
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

    /// RF180-46 REVIEW FIX: pull one remote runnable task into the local queue
    /// while process-context detached allocation is legal. The source retains
    /// an exact rollback slot until destination publication commits.
    fn try_steal_to_local_queue(current_pid: Option<Pid>) -> bool {
        let local_cpu = current_cpu_id();
        let local = Self::current_ready_queue();
        let local_has_candidate = {
            let Some(queue) = Self::lock_ready_queue_or_defer(local) else {
                return false;
            };
            Self::select_next_result_locked(&queue, local_cpu, local_cpu, current_pid)
                .candidate
                .is_some()
        };
        if local_has_candidate {
            return false;
        }

        let stolen = Self::steal_one(current_pid);
        let Some((pid, pcb, priority, source_cpu, source_priority)) = stolen else {
            return false;
        };

        if Self::try_insert_ready(local, local_cpu, priority, pid, Arc::clone(&pcb)).is_ok() {
            let retired = {
                Self::ready_queue_for_cpu(source_cpu)
                    .expect("steal source queue disappeared after publication")
                    .lock()
                    .commit_migration_removal(source_priority)
            };
            drop(retired);
            drop(pcb);
            Self::arm_ready_cpu(local_cpu);
            true
        } else {
            {
                let source = Self::ready_queue_for_cpu(source_cpu)
                    .expect("steal source queue disappeared before rollback");
                let mut source = source.lock();
                let restored = source.restore_migration(source_priority, pid, pcb);
                assert!(
                    restored.is_ok(),
                    "failed steal must restore retained source slot"
                );
                Self::mark_queue_mutated(source_cpu);
            }
            Self::arm_ready_cpu(source_cpu);
            false
        }
    }

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
                {
                    let mut src_guard = src_queue.lock();
                    // The source bucket retained its capacity when `pid` was
                    // removed, so restoration is allocation-free and exact.
                    let restored = src_guard.restore_migration(_priority, pid, pcb);
                    assert!(
                        restored.is_ok(),
                        "source queue restoration must be reserved"
                    );
                    Self::mark_queue_mutated(src_cpu);
                }
                Self::arm_ready_cpu(src_cpu);
                return;
            };
            let Some(allowed_cpus) = Self::effective_allowed_cpus(&proc) else {
                drop(proc);
                let mut src_guard = src_queue.lock();
                let restored = src_guard.restore_migration(_priority, pid, pcb);
                assert!(restored.is_ok(), "empty cpuset restore must be reserved");
                Self::mark_queue_mutated(src_cpu);
                drop(src_guard);
                Self::arm_ready_cpu(src_cpu);
                return;
            };
            let eff_prio = proc.dynamic_priority;
            let still_ready = proc.state == ProcessState::Ready
                && !proc.stopped
                && !proc.on_cpu.load(Ordering::Acquire);
            drop(proc);

            // Check if destination CPU is allowed by effective mask
            if !still_ready || !Self::cpu_allowed(dst_cpu, allowed_cpus) {
                // Put the task back in its original retained-capacity bucket.
                {
                    let mut src_guard = src_queue.lock();
                    let restored = src_guard.restore_migration(_priority, pid, pcb);
                    assert!(
                        restored.is_ok(),
                        "source queue restoration must be reserved"
                    );
                    Self::mark_queue_mutated(src_cpu);
                }
                Self::arm_ready_cpu(src_cpu);
                return;
            }

            let (target, target_cpu) = match Self::ready_queue_for_cpu(dst_cpu) {
                Some(target) => (target, dst_cpu),
                None => (Self::current_ready_queue(), current_cpu_id()),
            };
            match Self::try_insert_ready(target, target_cpu, eff_prio, pid, Arc::clone(&pcb)) {
                Ok(()) => {
                    let retired = { src_queue.lock().commit_migration_removal(_priority) };
                    drop(retired);
                    drop(pcb);
                    Self::arm_ready_cpu(target_cpu);
                }
                Err(_) => {
                    {
                        let mut src_guard = src_queue.lock();
                        let restored = src_guard.restore_migration(_priority, pid, pcb);
                        assert!(
                            restored.is_ok(),
                            "failed migration must restore retained source slot"
                        );
                        Self::mark_queue_mutated(src_cpu);
                    }
                    Self::arm_ready_cpu(src_cpu);
                }
            }
        }
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
    /// R180-19 PREPARE: reserve the exact queue slot while the child is
    /// non-runnable. All allocation is confined to this method.
    pub fn reserve_process(
        pcb: ProcessControlBlock,
    ) -> Result<process::SchedulerAddToken, process::SchedulerAddError> {
        if !interrupts::are_enabled() {
            return Err(process::SchedulerAddError::Unavailable);
        }

        let (pid, generation, priority, allowed_cpus) = {
            let mut proc = pcb.lock();
            if proc.state != ProcessState::Ready || proc.stopped {
                return Err(process::SchedulerAddError::InvalidState);
            }
            let allowed_cpus = Self::effective_allowed_cpus(&proc)
                .ok_or(process::SchedulerAddError::NoEligibleCpu)?;
            proc.state = ProcessState::Provisioning;
            (
                proc.pid,
                proc.generation,
                proc.dynamic_priority,
                allowed_cpus,
            )
        };
        // Target selection takes only ready-queue locks and performs no heap
        // work. Detached queue backing is prepared afterward, with no lock held.
        let target_cpu = Self::target_cpu_for_new_work(current_cpu_id(), allowed_cpus)
            .ok_or(process::SchedulerAddError::NoEligibleCpu)?;
        sched_debug!(
            "[SCHED] add_process: pid={}, priority={}, target_cpu={}",
            pid,
            priority,
            target_cpu
        );

        let queue =
            Self::ready_queue_for_cpu(target_cpu).ok_or(process::SchedulerAddError::Unavailable)?;
        let queue_cpu = target_cpu;
        match Self::try_insert_ready(queue, queue_cpu, priority, pid, Arc::clone(&pcb)) {
            Ok(()) => Ok(process::SchedulerAddToken {
                cpu_id: queue_cpu,
                priority,
                pid,
                generation,
                process: pcb,
            }),
            Err(error) => Err(error),
        }
    }

    /// R180-19 COMMIT: publish a prepared child with zero allocation.
    pub fn commit_reserved_process(token: process::SchedulerAddToken) {
        // This is post-COW publication. reserve_process established every
        // condition below and rollback is no longer possible, so an invariant
        // violation must fail-stop instead of silently stranding the child.
        assert!(
            interrupts::are_enabled(),
            "scheduler admission commit requires IF-on process context"
        );
        let allowed_cpus = {
            let mut proc = token.process.lock();
            assert!(
                proc.pid == token.pid && proc.generation == token.generation,
                "scheduler reservation identity mismatch at commit"
            );
            assert!(
                proc.state == ProcessState::Provisioning,
                "scheduler reservation left Provisioning before commit"
            );
            let allowed_cpus = Self::effective_allowed_cpus(&proc)
                .expect("reserved process lost every eligible CPU before commit");
            assert!(
                Self::cpu_allowed(token.cpu_id, allowed_cpus),
                "reserved scheduler CPU left the process affinity before commit"
            );
            proc.publish_ready_at(kernel_core::get_ticks());
            allowed_cpus
        };
        Self::mark_queue_mutated(token.cpu_id);

        {
            let mut stats = SCHEDULER_STATS.lock();
            stats.processes_created = stats.processes_created.saturating_add(1);
        }
        let _ = allowed_cpus;
        Self::arm_ready_cpu(token.cpu_id);
    }

    /// R180-19 rollback: remove only the exact reserved generation.
    pub fn cancel_reserved_process(token: process::SchedulerAddToken) {
        assert!(
            interrupts::are_enabled(),
            "scheduler admission cancel requires IF-on process context"
        );
        let removal = (|| {
            let Some(queue) = Self::ready_queue_for_cpu(token.cpu_id) else {
                return (None, None);
            };
            let mut queue = queue.lock();
            let exact = queue
                .bucket(token.priority)
                .get(&token.pid)
                .map(|pcb| Arc::ptr_eq(pcb, &token.process))
                .unwrap_or(false);
            assert!(exact, "scheduler cancellation lost its exact reserved PCB");
            let removed = queue.remove_ordinary(token.priority, &token.pid);
            if removed.0.is_some() {
                Self::mark_queue_mutated(token.cpu_id);
            }
            removed
        })();
        drop(removal.0);
        drop(removal.1);
    }

    /// Convenience path for kernel-created tasks that do not need to hold the
    /// permit across additional preparation.
    #[must_use]
    pub fn add_process(pcb: ProcessControlBlock) -> Result<(), process::SchedulerAddError> {
        let token = Self::reserve_process(pcb)?;
        Self::commit_reserved_process(token);
        Ok(())
    }

    /// 移除进程（reap-time; identity-bound）
    ///
    /// R69-1 FIX: Removes process from all per-CPU queues.
    /// RF178-33 / P1-B: generation is load-bearing — see
    /// [`remove_identity_from_all_queues`].
    ///
    /// 锁顺序：READY_QUEUE -> SCHEDULER_STATS
    pub fn remove_process(pid: Pid, generation: u64) {
        Self::remove_identity_from_all_queues(pid, generation);
        interrupts::without_interrupts(|| {
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
        let queue = Self::lock_ready_queue_or_defer(Self::current_ready_queue())?;
        let cpu = current_cpu_id();
        Self::select_next_locked(&queue, cpu, cpu, None).map(|(pid, _, _)| pid)
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

    /// RF178-33 / RF180-46: prepare one switch without a blocking lock.
    ///
    /// Both process-origin and IRQ-return scheduling enter here with IF clear.
    /// Every potentially contended lock is therefore try-only. A failed
    /// acquisition leaves all task/current publications unchanged and rearms
    /// the level-triggered reschedule request.
    fn prepare_switch() -> Option<PreparedSwitch> {
        let current_slot = Self::current_process_slot();
        let Some(mut current_guard) = current_slot.try_lock() else {
            current_cpu().set_need_resched();
            return None;
        };
        let old_pid = *current_guard;
        let local_cpu = current_cpu_id();
        let queue_ref = Self::current_ready_queue();
        let queue = Self::lock_ready_queue_or_defer(queue_ref)?;

        let old_pcb = match old_pid {
            Some(pid) => match process::try_get_process(pid) {
                None => {
                    current_cpu().set_need_resched();
                    return None;
                }
                Some(Some(pcb)) => Some(pcb),
                Some(None) => {
                    current_cpu().set_need_resched();
                    return None;
                }
            },
            None => None,
        };

        let selection = Self::select_next_result_locked(&queue, local_cpu, local_cpu, old_pid);
        let Some((next_pid, next_pcb, _priority)) = selection.candidate else {
            if let Some(old_pcb) = old_pcb {
                if let Some(mut old) = old_pcb.try_lock() {
                    if old.state == ProcessState::Ready && old.on_cpu.load(Ordering::Acquire) {
                        old.enter_running_at(kernel_core::get_ticks());
                    }
                } else {
                    current_cpu().set_need_resched();
                    return None;
                }
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
        let mut old = match old_pcb.as_ref() {
            Some(old_pcb) => match old_pcb.try_lock() {
                Some(old) => Some(old),
                None => {
                    current_cpu().set_need_resched();
                    return None;
                }
            },
            None => None,
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
        if let Some(old) = old.as_mut() {
            use x86_64::registers::model_specific::Msr;
            const MSR_FS_BASE: u32 = 0xC000_0100;
            const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;
            unsafe {
                old.fs_base = Msr::new(MSR_FS_BASE).read();
                old.gs_base = Msr::new(MSR_KERNEL_GS_BASE).read();
            }
        }

        let per_cpu = current_cpu();
        if old_pid
            .map(|pid| per_cpu.get_fpu_owner() == pid)
            .unwrap_or(false)
        {
            let old = old
                .as_mut()
                .expect("current PID with FPU ownership must retain its PCB");
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

        let (old_ctx_ptr, old_generation, old_space) = if let Some(old) = old.as_mut() {
            (
                &mut old.context as *mut _ as *mut ArchContext,
                old.generation,
                old.memory_space,
            )
        } else {
            (BOOTSTRAP_CONTEXT.with(BootstrapContext::as_mut_ptr), 0, 0)
        };
        let next_ctx_ptr = NEXT_CONTEXT_SHADOW.with(|shadow| shadow.store(&next.context));
        let next_space = next.memory_space;
        let next_user_space = next.user_memory_space;
        let next_kstack_top = next.kernel_stack_top.as_u64();
        let next_cs = next.context.cs;
        let next_fs_base = next.fs_base;
        let next_gs_base = next.gs_base;
        let next_wd_handle = next.watchdog_handle;
        let next_kcov_token = process::task_kcov_switch_token(&next);
        let next_generation = next.generation;

        if let Some(old) = old.as_mut() {
            if matches!(old.state, ProcessState::Running | ProcessState::Ready) {
                old.enter_ready_at(now_tick);
            }
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

        Some(PreparedSwitch {
            old_pid: old_pid.unwrap_or(0),
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
            next_kcov_token,
        })
    }

    /// Complete a switch prepared by `prepare_switch`; no PCB/cpuset/table
    /// lock is acquired on this path.
    fn execute_switch(prepared: PreparedSwitch) {
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
                process::publish_current_kcov_token(prepared.next_kcov_token);
                switch_to_user(prepared.old_ctx_ptr, prepared.next_ctx_ptr);
            }
        } else {
            unsafe {
                assert_kernel_context(prepared.next_ctx_ptr);
                process::publish_current_kcov_token(prepared.next_kcov_token);
                switch_context(prepared.old_ctx_ptr, prepared.next_ctx_ptr);
            }
        }
    }

    /// 主动让出CPU
    ///
    /// R69-1 FIX: Uses current CPU's ready queue.
    ///
    /// 返回值：如果发生进程切换，返回 (新进程PID, 新进程地址空间)
    pub fn yield_cpu() -> Option<(Pid, usize)> {
        Self::reschedule_now(true, kernel_core::ReschedOrigin::Process);
        None
    }

    /// 获取进程数量
    ///
    /// R69-1 FIX: Sums across all per-CPU queues.
    pub fn process_count() -> Result<usize, SchedulerSnapshotError> {
        if !interrupts::are_enabled() {
            return Err(SchedulerSnapshotError::InterruptsDisabled);
        }

        let mut guards = core::array::from_fn::<_, { cpu_local::max_cpus() }, _>(|_| None);
        for cpu_id in Self::online_cpu_ids() {
            let queue = Self::ready_queue_for_cpu(cpu_id)
                .ok_or(SchedulerSnapshotError::QueueUnavailable)?;
            let Some(guard) = queue.try_lock() else {
                return Err(SchedulerSnapshotError::Contended);
            };
            guards[cpu_id] = Some(guard);
        }

        let mut total = 0usize;
        for guard in guards.iter().flatten() {
            total = total
                .checked_add(Self::queue_len(guard))
                .ok_or(SchedulerSnapshotError::Overflow)?;
        }
        Ok(total)
    }

    /// 打印调度统计信息
    pub fn print_stats() {
        SCHEDULER_STATS.lock().print();
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
        // RF180-46: allocating load distribution stays in IF-on process
        // context. The actual claim/save transaction below is shared with IRQ
        // return and is entirely try-only once IF is cleared.
        if origin == kernel_core::ReschedOrigin::Process && interrupts::are_enabled() {
            if BALANCE_DUE.swap(false, Ordering::Relaxed) {
                Self::balance_queues();
            }
            let current_pid = Self::get_current();
            let _ = Self::try_steal_to_local_queue(current_pid);
        }

        interrupts::without_interrupts(|| {
            if !drain_tick_debt_before_switch() || !finish_pending_prev() {
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
            if let Some(prepared) = Self::prepare_switch() {
                Self::execute_switch(prepared);
            }
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerSnapshotError {
    InterruptsDisabled,
    QueueUnavailable,
    Contended,
    Overflow,
}

/// RF178-33 executable probes for the bounded rotating selector.
pub fn run_bounded_selector_self_test() {
    #[derive(Clone, Copy)]
    struct ProbeEntry {
        runnable: bool,
        contended: bool,
        allowed_cpus: u64,
    }
    type ProbeQueues = PriorityQueues<ProbeEntry>;

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
        insert_at(queue, 120, pid, entry);
    }

    fn insert_at(queue: &mut ProbeQueues, priority: Priority, pid: Pid, entry: ProbeEntry) {
        queue
            .bucket_mut(priority)
            .try_insert(pid, entry)
            .expect("bounded-selector probe insert");
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
        let (visited, complete) =
            Scheduler::scan_queue_window(queue, cursor, epoch, budget, |key, entry| {
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
            });
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
        assert!(
            scan(&queue, 1, None, &mut thief_cursor, 0, SELECT_VISIT_BUDGET,)
                .0
                .is_none()
        );
        let mut owner_cursor = SelectionCursorState::new();
        assert_eq!(
            scan(&queue, 0, None, &mut owner_cursor, 0, SELECT_VISIT_BUDGET,).0,
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
    {
        let mut queue = ProbeQueues::new();
        insert_at(&mut queue, 0, 0x180_4600, READY);
        insert_at(&mut queue, 120, 0x180_4601, BLOCKED);
        insert_at(&mut queue, u8::MAX, 0x180_4602, READY);
        let mut cursor = SelectionCursorState::new();
        assert_eq!(scan(&queue, 0, None, &mut cursor, 0, 1).0, Some(0x180_4600));
        assert_eq!(scan(&queue, 0, None, &mut cursor, 0, 2).0, Some(0x180_4602));
        assert!(scan(&queue, 0, None, &mut cursor, 0, 3).2);
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

/// RF178-33 / P1-B: executable probe for identity-bound reap cleanup.
///
/// Builds a local ready queue with two PCBs sharing the same PID (recycled)
/// and proves only the matching generation is removed.
pub fn run_identity_cleanup_self_test() {
    let old_pcb = Process::try_new_pcb(
        0x178_33c1,
        1,
        ProcessNameSnapshot::from_parts("rf178-33-old", ""),
        120,
    )
    .expect("RF178-33 old PCB fixture");
    let (old_pid, old_gen) = {
        let old = old_pcb.lock();
        (old.pid, old.generation)
    };

    let new_pcb = Process::try_new_pcb(
        0x178_33c1, // same numeric PID (recycle)
        1,
        ProcessNameSnapshot::from_parts("rf178-33-new", ""),
        120,
    )
    .expect("RF178-33 successor PCB fixture");
    let new_gen = {
        let mut successor = new_pcb.lock();
        assert_eq!(successor.pid, old_pid);
        assert_ne!(
            successor.generation, old_gen,
            "NEXT_GENERATION must mint distinct generations"
        );
        successor.enter_ready_at(10);
        successor.generation
    };

    let mut queue = ReadyQueues::new();
    // Only the successor is queued (the reaped task may still appear if exit
    // raced with a stale Ready mark — cover both present and absent cases).
    queue
        .bucket_mut(120)
        .try_insert(old_pid, Arc::clone(&new_pcb))
        .expect("successor queue insert");

    // Reaper of the OLD identity must NOT remove the successor.
    let (removed, retired) =
        Scheduler::remove_identity_from_ready_queues(&mut queue, None, old_pid, old_gen);
    assert!(removed.is_none());
    assert!(retired.is_none());
    assert!(
        queue.bucket(120).get(&old_pid).is_some(),
        "recycled-PID successor must survive old-generation cleanup"
    );

    // Matching identity removes exactly once; second call is idempotent.
    let (removed, retired) =
        Scheduler::remove_identity_from_ready_queues(&mut queue, None, old_pid, new_gen);
    assert!(removed.is_some());
    drop(removed);
    drop(retired);
    assert!(queue.bucket(120).get(&old_pid).is_none());
    let (removed, retired) =
        Scheduler::remove_identity_from_ready_queues(&mut queue, None, old_pid, new_gen);
    assert!(removed.is_none());
    assert!(retired.is_none());

    // Stale reaped PCB still in queue (zombie residual) is removed by old gen.
    queue
        .bucket_mut(120)
        .try_insert(old_pid, Arc::clone(&old_pcb))
        .expect("stale queue insert");
    let (removed, retired) =
        Scheduler::remove_identity_from_ready_queues(&mut queue, None, old_pid, old_gen);
    assert!(removed.is_some());
    drop(removed);
    drop(retired);
    assert!(queue.bucket(120).get(&old_pid).is_none());

    let _ = (old_pcb, new_pcb);
}

/// R180-19 executable probe for the scheduler admission invariant: queue
/// storage is acquired during PREPARE; publishing Provisioning->Ready changes
/// no container length or capacity and therefore cannot allocate.
pub fn run_scheduler_admission_self_test() {
    let pcb = Process::try_new_pcb(
        0x180_1901,
        1,
        ProcessNameSnapshot::from_parts("r180-19-admission", ""),
        120,
    )
    .expect("R180-19 scheduler-admission PCB fixture");
    assert!(matches!(
        Scheduler::reserve_process(Arc::clone(&pcb)),
        Err(process::SchedulerAddError::Unavailable)
    ));
    assert_eq!(
        Scheduler::process_count(),
        Err(SchedulerSnapshotError::InterruptsDisabled)
    );

    let ordered = AtomicBool::new(false);
    Scheduler::publish_ready_signal(&ordered, true, || {
        assert!(ordered.load(Ordering::Acquire));
    });
    assert!(ordered.load(Ordering::Acquire));
    let local = AtomicBool::new(false);
    Scheduler::publish_ready_signal(&local, false, || {
        panic!("local ready publication must not emit an IPI")
    });
    assert!(local.load(Ordering::Acquire));
    let pid = {
        let mut proc = pcb.lock();
        proc.state = ProcessState::Provisioning;
        proc.pid
    };

    let mut queue = ReadyQueues::new();
    let prepared = PreparedAdmittedMapCapacity::try_new(HeapClass::Scheduler, 3)
        .expect("detached scheduler admission reserve");
    let retired = queue
        .bucket_mut(120)
        .install_prepared_deferred(prepared)
        .expect("detached scheduler admission install");
    drop(retired);
    let prepared_insert = queue
        .bucket_mut(120)
        .insert_unique_reserved(pid, Arc::clone(&pcb));
    assert!(prepared_insert.is_ok(), "prepared admission insert");
    let capacity = queue.bucket(120).capacity();
    let len = queue.bucket(120).len();

    pcb.lock().publish_ready_at(1);
    assert_eq!(queue.bucket(120).capacity(), capacity);
    assert_eq!(queue.bucket(120).len(), len);
    assert_eq!(pcb.lock().state, ProcessState::Ready);

    // RF180-46 rollback probe: two detached memberships at different priority
    // boundaries reserve two aggregate slots. Ordinary publication must size
    // around both reservations, and both restores remain allocation-free.
    let edge_low = pid + 1;
    let edge_high = pid + 2;
    queue
        .bucket_mut(0)
        .insert_unique_reserved(edge_low, Arc::clone(&pcb))
        .expect("low-priority boundary insert");
    queue
        .bucket_mut(u8::MAX)
        .insert_unique_reserved(edge_high, Arc::clone(&pcb))
        .expect("high-priority boundary insert");
    let low = queue
        .remove_for_migration(0, &edge_low)
        .expect("low-priority migration remove");
    let high = queue
        .remove_for_migration(u8::MAX, &edge_high)
        .expect("high-priority migration remove");
    assert_eq!(queue.protected_slots(120), 2);
    let required = queue
        .len()
        .checked_add(queue.protected_slots(120))
        .and_then(|needed| needed.checked_add(1))
        .expect("scheduler test capacity arithmetic");
    assert!(required > queue.capacity());
    let growth = PreparedAdmittedMapCapacity::try_new(HeapClass::Scheduler, required)
        .expect("multi-slot scheduler growth preparation");
    let retired = queue
        .bucket_mut(120)
        .install_prepared_deferred(growth)
        .expect("multi-slot scheduler growth install");
    drop(retired);
    assert!(required <= queue.capacity());
    let grown_capacity = queue.bucket(120).capacity();
    queue
        .restore_migration(0, edge_low, low)
        .expect("low-priority retained slot restore");
    queue
        .restore_migration(u8::MAX, edge_high, high)
        .expect("high-priority retained slot restore");
    assert_eq!(queue.protected_slots(120), 0);

    let (removed, membership_priority) =
        Scheduler::remove_pid_from_queue(&mut queue, None, pid).expect("migration remove");
    assert_eq!(membership_priority, 120);
    assert!(queue.bucket(120).is_empty());
    assert_eq!(queue.bucket(120).capacity(), grown_capacity);
    assert_eq!(queue.protected_slots(120), 1);

    // A competing enqueue must grow around, never consume, the protected
    // rollback slot.
    let competing_pid = pid + 3;
    let competing_insert = queue
        .bucket_mut(120)
        .insert_unique_reserved(competing_pid, Arc::clone(&pcb));
    assert!(
        competing_insert.is_ok(),
        "competing enqueue preserves rollback capacity"
    );

    let mut unprepared_destination = ReadyQueues::new();
    let (pid, removed) = unprepared_destination
        .bucket_mut(120)
        .insert_unique_reserved(pid, removed)
        .expect_err("unprepared destination must reject without allocating");
    queue
        .restore_migration(membership_priority, pid, removed)
        .expect("retained source slot must restore allocation-free");
    assert_eq!(queue.protected_slots(120), 0);
    assert!(queue.bucket(120).contains_key(&pid));
    assert!(queue.bucket(120).contains_key(&competing_pid));
    let (removed, retired) = queue.remove_ordinary(0, &edge_low);
    drop(removed);
    drop(retired);
    let (removed, retired) = queue.remove_ordinary(u8::MAX, &edge_high);
    drop(removed);
    drop(retired);

    // RF180-46: removals detach, rather than destroy, the final backing while
    // the caller conceptually owns the queue lock. Its lifetime charge remains
    // committed until the retirement owner is dropped in the safe context.
    let (removed, retired) = queue.remove_ordinary(120, &competing_pid);
    assert!(removed.is_some());
    assert!(retired.is_none());
    drop(removed);
    let (removed, retired) = queue.remove_ordinary(120, &pid);
    assert!(removed.is_some());
    let retired = retired.expect("final scheduler backing must detach");
    assert_eq!(queue.bucket(120).capacity(), 0);
    drop(removed);
    drop(retired);
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
    assert!(!Scheduler::resume_stopped_locked(
        &mut proc, pid, generation
    ));
    assert_eq!(proc.state, ProcessState::Blocked);
    assert!(!proc.stopped);

    // RF178-35: fatal publication performs its own normalization. A stale
    // SIGCONT callback observed before that publication is now a no-op.
    proc.enter_ready_at(30);
    proc.pending_kill.store(true, Ordering::Release);
    assert!(!Scheduler::resume_stopped_locked(
        &mut proc, pid, generation
    ));
    assert_eq!(proc.state, ProcessState::Ready);
    proc.pending_kill.store(false, Ordering::Release);

    proc.enter_running_at(40);
    proc.stopped = true;
    assert!(!Scheduler::resume_stopped_locked(
        &mut proc, pid, generation
    ));
    assert_eq!(proc.state, ProcessState::Running);
    assert!(!proc.stopped);

    for terminal in [ProcessState::Zombie, ProcessState::Terminated] {
        proc.state = terminal;
        proc.stopped = true;
        assert!(!Scheduler::resume_stopped_locked(
            &mut proc, pid, generation
        ));
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

    // R180-19: register the transactional scheduler admission API. Reserve is
    // the sole fallible phase; commit/cancel mutate an already-backed slot.
    process::register_scheduler_admission(
        Scheduler::reserve_process,
        Scheduler::commit_reserved_process,
        Scheduler::cancel_reserved_process,
    );

    // 注册定时器回调，让 arch 模块的定时器中断能调用调度器
    kernel_core::register_timer_callback(Scheduler::on_clock_tick)
        .expect("scheduler timer callback slots exhausted");

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
