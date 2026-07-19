//! 调度器回调钩子
//!
//! 提供调度器与其他模块之间的解耦接口，避免循环依赖。
//! - arch 模块通过此钩子调用调度器的定时器处理
//! - syscall 模块通过此钩子触发重调度检查

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use cpu_local::{current_cpu, CpuLocal};
use spin::{Mutex, Once};

/// 定时器回调类型：在定时器中断时调用
pub type TimerCallback = fn();
/// Bounded callback runnable at an IRQ-return soft progress point after
/// `irq_exit` with IF=1. It must not sleep, schedule, allocate, or retain a lock
/// across a context switch. Spin/blocking MMIO work is permitted because the
/// interrupted CPL3 context holds no kernel lock and nested CPL0 timers do not
/// recurse into the progress point.
pub type SoftProgressCallback = fn();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallbackRegistrationError {
    Full,
}

struct CallbackSlots<const N: usize> {
    slots: [Option<fn()>; N],
}

impl<const N: usize> CallbackSlots<N> {
    const fn new() -> Self {
        Self { slots: [None; N] }
    }

    fn register(&mut self, callback: fn()) -> Result<(), CallbackRegistrationError> {
        if self
            .slots
            .iter()
            .flatten()
            .any(|registered| core::ptr::fn_addr_eq(*registered, callback))
        {
            return Ok(());
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(CallbackRegistrationError::Full)?;
        *slot = Some(callback);
        Ok(())
    }

    fn snapshot(&self) -> [Option<fn()>; N] {
        self.slots
    }
}

/// RF178-33: Distinguish a normal process-context scheduling point from the
/// timer IRQ-return fast path. The latter must remain strictly bounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReschedOrigin {
    Process,
    IrqReturn,
}

/// 重调度回调类型：force=true 强制调度，false 仅在需要时调度
pub type ReschedCallback = fn(force: bool, origin: ReschedOrigin);

/// R39-6 FIX: 全局定时器回调列表（支持多个回调，按注册顺序依次调用）
const MAX_TIMER_CALLBACKS: usize = 4;
const MAX_DEFERRED_CALLBACKS: usize = 4;
static TIMER_CBS: Mutex<CallbackSlots<MAX_TIMER_CALLBACKS>> = Mutex::new(CallbackSlots::new());
static SOFT_PROGRESS_CBS: Mutex<CallbackSlots<MAX_DEFERRED_CALLBACKS>> =
    Mutex::new(CallbackSlots::new());

/// 全局重调度回调
/// RF178-33: immutable after early scheduler initialization. IRQ-return
/// scheduling reads this without acquiring a spin lock while IF=0.
static RESCHED_CB: Once<ReschedCallback> = Once::new();

/// P1-A D1-ARC-ENTRY-STATE: optional kernel-GS assertion registered by `arch`
/// after `init_syscall_percpu` (avoids arch ↔ kernel_core crate cycle).
static KERNEL_GS_ASSERT: Once<fn()> = Once::new();

/// Register the P1-A kernel-GS entry-state checker (call once from arch init).
pub fn register_kernel_gs_assert(f: fn()) {
    let _ = KERNEL_GS_ASSERT.call_once(|| f);
}

#[inline]
fn assert_kernel_entry_state() {
    if let Some(f) = KERNEL_GS_ASSERT.get().copied() {
        f();
    }
}

/// 【关键修复】从中断上下文延迟的抢占请求标志
///
/// 在中断上下文中不能直接调用 switch_context（会导致栈和特权级问题），
/// 只设置此标志，由安全路径（syscall 返回）消费
///
/// R67-4 FIX: Now per-CPU to avoid cross-CPU races where one CPU
/// sets the flag and another clears it.
static IRQ_RESCHED_PENDING: CpuLocal<AtomicBool> = CpuLocal::new(|| AtomicBool::new(false));

/// Level-triggered request for process-safe deferred callbacks. IRQ producers
/// set it; a CPL3-return soft progress point or ordinary process scheduling
/// swaps it clear before taking the callback snapshot. Racing producers re-arm
/// the level and are never overwritten after callback execution.
static IRQ_SOFT_PROGRESS_PENDING: AtomicBool = AtomicBool::new(false);

/// RF180-52 FIX: one-way publication barrier for process-context deferred work.
///
/// APs become interrupt-capable during SMP bring-up, before the scheduler,
/// IPC callbacks, IOMMU soft-progress callbacks, and network/socket globals are
/// fully initialized. No process-context drain may cross this gate until the
/// BSP has published every dependency. A Release publication paired with the
/// Acquire reads below also makes those initialization writes visible to APs.
static PROCESS_DEFERRED_WORK_READY: AtomicBool = AtomicBool::new(false);

/// R169-L9/L10/L11: cadence of the global stranded-port-charge sweep. One
/// `sweep_stranded_port_charges()` pass runs every `PORT_CHARGE_SWEEP_INTERVAL`
/// full process-context deferred-work drains, amortizing its full-map scan. A
/// global counter (a coarse rate gate; exact per-CPU accuracy is unnecessary)
/// drives it. The sweep is enqueue-only and the correctness backstop for dead-
/// `Weak` port-charge reclamation, so the interval only affects RECLAIM LATENCY,
/// never correctness (`delete_cgroup` sweeps synchronously before its gate).
const PORT_CHARGE_SWEEP_INTERVAL: u32 = 256;
static PORT_CHARGE_SWEEP_TICK: AtomicU32 = AtomicU32::new(0);

/// R151-5 FIX: Force-initialize the per-CPU resched flag before IRQs are enabled.
///
/// `IRQ_RESCHED_PENDING` is accessed from `request_resched_from_irq()` in timer
/// and keyboard interrupt handlers. Without pre-initialization, the first IRQ on
/// a CPU can deadlock inside `Once::call_once()` heap allocation.
pub fn force_init_resched_locals() {
    IRQ_RESCHED_PENDING.force_init();
}

/// 注册定时器回调
///
/// R39-6 FIX: 支持多个回调注册，调度器和超时处理可以同时注册
/// 调度器在初始化时调用此函数注册 on_clock_tick 处理器
///
/// R148-I6 FIX: Disable interrupts while holding TIMER_CBS lock to prevent
/// deadlock if a timer IRQ fires during registration and on_scheduler_tick()
/// tries to acquire the same lock.
pub fn register_timer_callback(cb: TimerCallback) -> Result<(), CallbackRegistrationError> {
    x86_64::instructions::interrupts::without_interrupts(|| TIMER_CBS.lock().register(cb))
}

/// Register fixed-capacity process-context deferred work. Registration is
/// checked and allocation-free; callbacks are copied out before invocation.
pub fn register_soft_progress_callback(
    cb: SoftProgressCallback,
) -> Result<(), CallbackRegistrationError> {
    x86_64::instructions::interrupts::without_interrupts(|| SOFT_PROGRESS_CBS.lock().register(cb))
}

/// Request process-safe deferred work from IRQ context.
#[inline]
pub fn request_soft_progress_from_irq() {
    IRQ_SOFT_PROGRESS_PENDING.store(true, Ordering::Release);
}

/// Publish that every dependency of the process-context deferred-work drain is
/// initialized. This is a one-way boot transition and must be called only by
/// the BSP after all callback registrations and subsystem globals are complete.
#[inline]
pub fn mark_process_deferred_work_ready() {
    PROCESS_DEFERRED_WORK_READY.store(true, Ordering::Release);
}

/// Whether process-context deferred work may run on this CPU.
#[inline]
pub fn process_deferred_work_ready() -> bool {
    PROCESS_DEFERRED_WORK_READY.load(Ordering::Acquire)
}

fn drain_level_triggered_deferred(pending: &AtomicBool, mut invoke_snapshot: impl FnMut()) -> bool {
    if !pending.swap(false, Ordering::AcqRel) {
        return false;
    }
    invoke_snapshot();
    true
}

/// Run the fixed deferred callback snapshot at a safe process-context progress
/// point. Callers must have completed IRQ accounting and enabled interrupts.
pub fn drain_requested_soft_progress() {
    debug_assert!(
        x86_64::instructions::interrupts::are_enabled(),
        "deferred callbacks require IF=1"
    );
    debug_assert!(
        !current_cpu().in_irq(),
        "deferred callbacks require irq_count=0"
    );

    // RF180-52: retain the level-triggered pending bit until the BSP has
    // published every callback dependency. This also protects the direct
    // CPL3 IRQ-return progress point, not only reschedule_if_needed().
    if !process_deferred_work_ready() {
        return;
    }
    assert_kernel_entry_state();

    let _ = drain_level_triggered_deferred(&IRQ_SOFT_PROGRESS_PENDING, || {
        let deferred_callbacks = SOFT_PROGRESS_CBS.lock().snapshot();
        for callback in deferred_callbacks.iter().flatten() {
            callback();
        }
    });
}

/// 注册重调度回调
///
/// 调度器在初始化时调用此函数注册 reschedule_now 处理器
pub fn register_resched_callback(cb: ReschedCallback) {
    RESCHED_CB.call_once(|| cb);
}

/// 调用定时器回调
///
/// R39-6 FIX: 遍历所有注册的回调并依次调用
/// 由 arch 模块的定时器中断处理器调用
///
/// # Codex Review Fix
///
/// Use fixed-size stack array instead of Vec::clone() to avoid heap
/// allocation in IRQ context. MAX_TIMER_CALLBACKS limits the number
/// of callbacks (typically just scheduler tick + waitqueue timeout).
///
/// # E.4 RCU Integration
///
/// Marks a quiescent state after processing callbacks. The timer tick
/// is a natural quiescent point since no RCU readers should be active
/// in IRQ context.
#[inline]
pub fn on_scheduler_tick() {
    // Copy callbacks to fixed stack array (no heap allocation in IRQ context)
    // R148-I6 FIX: Blocking lock() is safe here because register_timer_callback()
    // now wraps its lock acquisition in without_interrupts(), preventing timer IRQ
    // from firing while the registration lock is held.  Using try_lock() here would
    // skip ticks and break per-CPU scheduler time-slice accounting and timeout progress.
    let callbacks = TIMER_CBS.lock().snapshot();

    // Call callbacks outside of lock
    for cb in callbacks.iter() {
        if let Some(f) = cb {
            f();
        }
    }

    // R72: Use rcu_timer_tick() instead of just rcu_quiescent_state().
    // This not only marks quiescent state but also tries to advance
    // COMPLETED_EPOCH, enabling callback progress on idle CPUs.
    crate::rcu::rcu_timer_tick();
}

/// 检查并执行重调度（如果需要）
///
/// 由系统调用返回路径调用，仅在 NEED_RESCHED 或 IRQ_RESCHED_PENDING 标志置位时执行调度
///
/// R65-6 FIX: Also drains any deferred TCP timer work that couldn't complete
/// in IRQ context due to lock contention.
///
/// R67-4 FIX: Uses per-CPU IRQ_RESCHED_PENDING flag.
///
/// # E.4 RCU Integration
///
/// Drains RCU callbacks whose grace period has completed. This is the main
/// process-context path where deferred destruction work gets done.
#[inline]
pub fn reschedule_if_needed() {
    reschedule_if_needed_inner(None);
}

/// Run the full process-context deferred drain, invoke `post_drain`, and only
/// then enter the scheduler callback.
///
/// RF180-54: the AP bootstrap acknowledgement must be published after every
/// deferred-work dependency has been exercised, but before the reschedule
/// callback can context-switch and delay the AP's return indefinitely. The
/// hook must therefore be allocation-free, nonblocking, and safe with IRQs
/// enabled.
#[inline]
pub fn reschedule_if_needed_with_post_drain(post_drain: fn()) {
    reschedule_if_needed_inner(Some(post_drain));
}

fn reschedule_if_needed_inner(post_drain: Option<fn()>) {
    // R169-5 FIX (D1-CGROUP-IRQ-L5): This is the full process-context
    // deferred-work drain — it performs BLOCKING Level-8 (sockets/tcp_conns
    // teardown) and non-IRQ-safe Level-5 (CGROUP_REGISTRY port-uncharge,
    // Process) acquisitions plus a context-switch callback, so it MUST be
    // entered with interrupts ENABLED. An idle loop that needs a race-free arm
    // window must disable IRQs ONLY across the need_resched check + sti;hlt,
    // NEVER across this drain (see arch/smp.rs `ap_idle_loop`). `force_reschedule()`
    // is the deliberately drain-free, IRQ-adjacent-safe variant. This converts
    // the previously comment-only contract into a machine-checked invariant.
    debug_assert!(
        x86_64::instructions::interrupts::are_enabled(),
        "reschedule_if_needed() (full L8 + L5 deferred-work drain) must run with \
         interrupts ENABLED — never from an IRQ-off context (R169-5)"
    );
    // RF180-52: APs are online and interrupt-capable before the scheduler and
    // every deferred-work dependency are initialized. Fail closed until the
    // BSP's Release publication; otherwise the first AP idle iteration can
    // enter callback, network, cgroup, and scheduler paths against incomplete
    // boot-time registration and publication state.
    if !process_deferred_work_ready() {
        return;
    }
    // P1-A D1-ARC-ENTRY-STATE: process-context schedule must run with kernel GS.
    assert_kernel_entry_state();

    // Share the same level-triggered handoff as the CPL3 IRQ-return soft
    // progress point. The swap happens before snapshot/invocation, so a racing
    // producer remains armed for the next safe point.
    drain_requested_soft_progress();

    // R65-6 FIX: Drain deferred TCP timer work before scheduling check
    crate::time::drain_deferred_tcp_timers();

    // R169-L9/L10/L11: rate-gated ns-agnostic stranded-port-charge sweep. The
    // alloc-time `reap_dead_bindings` only visits the namespace of an active
    // ephemeral allocation, so a socket dropped without close(), a charge stranded
    // in a quiescent sibling netns, or a binding pinned by a zombie process would
    // never be revisited and its port charge would leak toward ports.max. This
    // sweep generalizes the proven dead-`Weak` reap across both binding maps and
    // ALL namespaces (the maps are the single source of truth — no per-socket
    // mirror, hence no ABA-prone side state). It only ENQUEUES to the deferred
    // queue drained just below (so reclaimed charges apply this same pass) and
    // never crosses L8 -> L5 under a lock. Rate-gated (1 pass per
    // PORT_CHARGE_SWEEP_INTERVAL drains) to amortize the full-map scan.
    {
        // Coarse wrapping rate-gate tick, not an ID/refcount — wraparound is benign.
        let prev = PORT_CHARGE_SWEEP_TICK.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow
        if prev % PORT_CHARGE_SWEEP_INTERVAL == 0 {
            net::socket_table().sweep_stranded_port_charges();
        }
    }

    // J2-8: Drain deferred per-cgroup port uncharges in process context. Placed
    // AFTER the TCP-timer drain and the rate-gated sweep because both can tear
    // down ESTABLISHED connections / reap dead bindings, which ENQUEUE port
    // uncharges in this same pass. The cgroup uncharge takes CGROUP_REGISTRY
    // (Level 5) and so must run here (process context, IRQs ENABLED, no
    // net-binding lock held), never under the binding lock or in IRQ. NOT wired
    // into force_reschedule(): that hook is reachable from IRQ-adjacent paths
    // where a Level-5 acquire is illegal. R169-5: every caller of this function
    // (syscall return, nanosleep, BSP idle, and now the AP idle loop after its
    // restructure) runs with IRQs enabled, so this drain is genuinely
    // process-context on all paths — the debug_assert above enforces it. The
    // fold-by-cgid queue bounds any transient overshoot until this drain runs.
    net::socket_table().drain_deferred_port_uncharges();

    // R149-1 FIX: Drain deferred stdin wakes from keyboard/serial IRQ.
    crate::syscall::drain_deferred_stdin_wakes();

    // M4-1c: reap empty socket wait-queue BTreeMap nodes that the timer IRQ
    // (check_timeouts) deferred out of IRQ context (R151-5 dealloc class). Lock-free
    // fast-path + try_lock, so this is cheap when nothing emptied and never blocks.
    crate::syscall::drain_socket_waiter_cleanup();

    // R155-6 FIX: Drain deferred IRQ terminations in process context.
    crate::process::drain_deferred_irq_terminates();

    // E.4 RCU: Drain callbacks in process context.
    crate::rcu::poll();

    // R67-4 FIX: Consume this CPU's IRQ-triggered reschedule request
    let irq_pending = IRQ_RESCHED_PENDING.with(|flag| flag.swap(false, Ordering::SeqCst));

    // RF180-54: this is the exact completion boundary for one full deferred
    // drain. Run the AP acknowledgement before a scheduler callback can switch
    // away and prevent this kernel frame from returning.
    if let Some(post_drain) = post_drain {
        post_drain();
    }

    // R160-3 FIX: Copy callback out of lock before invoking. The previous
    // `if let Some(cb) = *RESCHED_CB.lock() { cb(...); }` pattern held the
    // MutexGuard across the callback (Rust 2021 temporary lifetime rules).
    // The callback triggers context switches — holding a global spinlock
    // across switch_context corrupts the lock when the resumed task drops
    // its own stale MutexGuard. Same copy-then-call pattern as on_scheduler_tick().
    if let Some(cb) = RESCHED_CB.get().copied() {
        cb(irq_pending, ReschedOrigin::Process);
    }
}

/// 强制执行重调度
///
/// 由 sys_yield 调用，无论 NEED_RESCHED 标志如何都执行调度
#[inline]
pub fn force_reschedule() {
    // P1-A D1-ARC-ENTRY-STATE: must not schedule with user GS (R178-1 class).
    assert_kernel_entry_state();
    // R160-3 FIX: Copy callback out of lock before invoking (same fix as reschedule_if_needed).
    if let Some(cb) = RESCHED_CB.get().copied() {
        cb(true, ReschedOrigin::Process);
    }
}

/// RF178-33: IRQ-return scheduling entry. This deliberately skips every
/// process-context deferred-work drain and tells the scheduler to use only its
/// bounded, nonblocking local selector.
#[inline]
pub fn force_reschedule_from_irq() {
    // P1-A: IRQ-return schedule is only legal after CS-RPL-gated swapgs (timer)
    // or enter_kernel_state_from_user_exception / syscall kernel GS.
    assert_kernel_entry_state();
    if let Some(cb) = RESCHED_CB.get().copied() {
        cb(true, ReschedOrigin::IrqReturn);
    }
}

/// 【新增】从中断上下文请求抢占
///
/// 仅设置标志，不执行实际的上下文切换。
/// 实际切换在安全路径（syscall 返回或下一个调度点）执行。
///
/// R67-4 FIX: Sets this CPU's IRQ_RESCHED_PENDING flag.
///
/// # Safety
///
/// 此函数可从中断上下文安全调用
#[inline]
pub fn request_resched_from_irq() {
    IRQ_RESCHED_PENDING.with(|flag| flag.store(true, Ordering::SeqCst));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rf180_deferred_level_rearms_when_producer_races_callback() {
        let pending = AtomicBool::new(true);
        let mut callbacks = 0usize;
        assert!(drain_level_triggered_deferred(&pending, || {
            callbacks += 1;
            pending.store(true, Ordering::Release);
        }));
        assert_eq!(callbacks, 1);
        assert!(pending.load(Ordering::Acquire));

        assert!(drain_level_triggered_deferred(&pending, || callbacks += 1));
        assert_eq!(callbacks, 2);
        assert!(!pending.load(Ordering::Acquire));
        assert!(!drain_level_triggered_deferred(&pending, || callbacks += 1));
        assert_eq!(callbacks, 2);
    }
}
