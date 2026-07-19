//! 同步原语
//!
//! 提供内核空间的同步机制，包括：
//! - 等待队列（WaitQueue）：用于进程阻塞/唤醒
//! - 互斥锁（KMutex）：内核互斥锁（可阻塞）
//! - 信号量（Semaphore）：计数信号量
//!
//! 这些原语是管道、消息队列阻塞操作的基础

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use kernel_core::process::{self, ProcessId, ProcessState};
use mm::{
    AdmittedAllocError, AdmittedDeque, HeapAdmissionError, HeapClass,
    PreparedAdmittedDequeCapacity, RetiredAdmittedDequeCapacity,
};
use spin::Mutex;
use x86_64::instructions::interrupts;

/// R39-6 FIX: 纳秒到毫秒 Tick 的转换常量（时钟频率 1kHz）
const NS_PER_MS: u64 = 1_000_000;

/// P3-A: high bit tags a WaitQueue entry generation as a **process** generation
/// (`Process.generation`) rather than a per-queue wait counter.
///
/// `prepare_to_wait` (pipe / condvar path — the R171 residual producer) stamps
/// `(Process.generation | PROCESS_GEN_TAG)`. `wait_with_timeout` keeps plain
/// queue-local gens (tag clear). Wake paths that see the tag require
/// `pcb.generation == stamped` before readying — closing PID-recycling
/// misdirect when a stale non-Blocked entry lingers and the PID is reused.
const PROCESS_GEN_TAG: u64 = 1u64 << 63;

#[inline]
fn stamp_process_generation(process_gen: u64) -> u64 {
    (process_gen & !PROCESS_GEN_TAG) | PROCESS_GEN_TAG
}

#[inline]
fn is_process_generation_stamp(entry_gen: u64) -> bool {
    (entry_gen & PROCESS_GEN_TAG) != 0
}

#[inline]
fn unstamp_process_generation(entry_gen: u64) -> u64 {
    entry_gen & !PROCESS_GEN_TAG
}

/// R39-6 FIX: 等待结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// 被正常唤醒
    Woken,
    /// 等待超时
    TimedOut,
    /// 队列已关闭
    Closed,
    /// 无当前进程
    NoProcess,
    /// R171 (F3): 等待期间检测到挂起的 kill —— 以 EINTR 中断阻塞，而非重新挂起。
    Interrupted,
    /// RF178-8: waiter or timer metadata admission failed without publishing
    /// a partial wait transaction.
    ResourceExhausted,
}

/// RF178-8: linear token for one fully published queue/timer wait. The exact
/// generation and sequence make finish/cancel unable to consume a newer wait.
pub(crate) struct WaitTicket {
    pid: ProcessId,
    generation: u64,
    wait_seq: Option<u64>,
}

pub(crate) enum PrepareWait {
    Immediate(WaitOutcome),
    Armed(WaitTicket),
}

type WaitQueueEntry = (ProcessId, u64);

/// Backing prepared outside resource locks for one possible WaitQueue enqueue.
///
/// Both unused prepared backing and retired installed backing remain owned by
/// this token.  Callers that hold another resource lock (notably `Pipe.inner`)
/// keep the token alive until that lock is released, so neither allocation nor
/// deallocation can recurse into the global heap from the critical section.
#[must_use = "prepared wait capacity owns heap state until it is dropped safely"]
pub(crate) struct PreparedWaitQueueCapacity {
    pid: Option<ProcessId>,
    prepared: Option<PreparedAdmittedDequeCapacity<WaitQueueEntry>>,
    retired_replaced: Option<RetiredAdmittedDequeCapacity<WaitQueueEntry>>,
    retired_empty: Option<RetiredAdmittedDequeCapacity<WaitQueueEntry>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrepareToWaitCapacityOutcome {
    Prepared(bool),
    RetryCapacity,
}

struct PreparedWaitTransactionCapacity {
    queue: PreparedWaitQueueCapacity,
    timer_prepared: Option<PreparedAdmittedDequeCapacity<TimedWaiter>>,
    timer_retired_replaced: Option<RetiredAdmittedDequeCapacity<TimedWaiter>>,
    timer_retired_empty: Option<RetiredAdmittedDequeCapacity<TimedWaiter>>,
}

/// R39-6 FIX: 定时等待者记录
#[derive(Debug, Clone, Copy)]
struct TimedWaiter {
    /// 等待的进程ID
    pid: ProcessId,
    /// 超时截止时间（tick）
    deadline_tick: u64,
    /// M1-02: the globally-unique wait sequence (`process::alloc_wait_seq`) this
    /// timer belongs to. The timer IRQ matches it against the PCB's
    /// `active_wait_seq` to wake EXACTLY this wait WITHOUT dereferencing a
    /// `WaitQueue` — replacing the former `queue: usize` pointer that was the SMP
    /// use-after-free (the IRQ could deref it after a concurrent `WaitQueue` free).
    seq: u64,
    /// R165-4 FIX: The exact `wait_with_timeout` generation this timer belongs to.
    /// Carried into the per-PCB `wq_timeout_marker` (via `wq_timeout_wake_by_seq`)
    /// so the wait epilogue's exact-gen `consume_wq_timeout` can match it and reject
    /// stale flags.
    generation: u64,
}

/// R39-6 FIX: 全局定时等待者列表
static TIMED_WAITERS: Mutex<AdmittedDeque<TimedWaiter>> =
    // Futex is the sole production timed-wait producer. Keep the global timer
    // registry inside the same named aggregate budget as its bucket/PI state.
    Mutex::new(AdmittedDeque::new(HeapClass::Futex));

#[cfg(test)]
pub(crate) fn timed_waiter_heap_class_for_test() -> HeapClass {
    TIMED_WAITERS.lock().class()
}

/// Deterministic, single-shot admission failure used by the boot/hosted
/// convergence probe below. It is false in production and is consumed before
/// any waiter state is published.
static FAIL_NEXT_WAIT_CAPACITY: AtomicBool = AtomicBool::new(false);

/// R39-6 FIX: 定时器回调是否已注册
static WAITQUEUE_TIMER_INIT: AtomicBool = AtomicBool::new(false);

fn prepare_deque_growth<T>(
    class: HeapClass,
    len: usize,
    capacity: usize,
) -> Result<Option<PreparedAdmittedDequeCapacity<T>>, AdmittedAllocError> {
    let required = len.checked_add(1).ok_or(AdmittedAllocError::Admission(
        HeapAdmissionError::ArithmeticOverflow,
    ))?;
    if required <= capacity {
        return Ok(None);
    }
    let preferred = capacity
        .max(4)
        .checked_mul(2)
        .map(|doubled| doubled.max(required))
        .ok_or(AdmittedAllocError::Admission(
            HeapAdmissionError::ArithmeticOverflow,
        ))?;
    match PreparedAdmittedDequeCapacity::try_new(class, preferred) {
        Ok(prepared) => Ok(Some(prepared)),
        Err(_) if preferred != required => {
            PreparedAdmittedDequeCapacity::try_new(class, required).map(Some)
        }
        Err(error) => Err(error),
    }
}

/// 等待队列
///
/// 用于进程阻塞和唤醒。当资源不可用时，进程加入等待队列；
/// 当资源可用时，唤醒等待队列中的进程。
///
/// # X-6 安全增强
///
/// 添加 `closed` 标志防止在端点销毁后新的等待者加入，
/// 避免永久阻塞和资源泄漏。
///
/// # R39-6 FIX: 超时支持
///
/// 超时唤醒与正常唤醒的区分通过每-PCB 的 `Process.wq_timeout_marker`
/// 标记完成（M4-1b：取代了原先在定时器 IRQ 中分配堆节点的 `timed_out`
/// 集合）。标记在 `process::wq_timeout_wake_by_seq` 的 Blocked->Ready 过程中、
/// 持有 proc 锁时写入，由等待者自身的 epilogue 经 `process::consume_wq_timeout`
/// 消费。M1-02：定时器 IRQ 不再解引用 WaitQueue —— 它仅凭每-PCB 的
/// `active_wait_seq` 唤醒，从根本上消除了原 `timeout_wake` 的 SMP use-after-free。
pub struct WaitQueue {
    /// 等待的进程ID列表
    /// R165-4 FIX: Each waiter is tagged with the `wait_with_timeout` generation
    /// that enqueued it (or a fresh generation for the condvar prepare_to_wait
    /// path); the epilogue's exact-gen `consume_wq_timeout` uses it to reject a
    /// stale timeout marker. M1-02: the timer IRQ no longer matches against this
    /// deque at all (that membership check was the freed-queue deref) — it wakes by
    /// the per-PCB `active_wait_seq`, and the timed-out waiter self-dequeues here in
    /// its own epilogue.
    waiters: Mutex<AdmittedDeque<(ProcessId, u64)>>,
    /// 当为 true 时不再接受新的等待者（用于端点销毁时取消阻塞）
    closed: AtomicBool,
    // M4-1b: the former `timed_out: Mutex<BTreeMap<ProcessId, u64>>` was removed —
    // its `insert` allocated a node in TIMER-IRQ context (`timeout_wake`, the
    // R151-5 deadlock class). The timeout marker now lives per-PCB in
    // `Process.wq_timeout_marker`, set under the proc lock at the Blocked->Ready
    // transition and consumed by the waiter's epilogue via
    // `process::consume_wq_timeout`. The marker dies with the PCB, so no per-queue
    // map and no exit-time prune are needed.
    /// Monotonic generation counter, incremented on each wait_with_timeout call.
    wait_generation: AtomicU64,
}

impl WaitQueue {
    /// 创建新的等待队列
    pub const fn new(class: HeapClass) -> Self {
        WaitQueue {
            waiters: Mutex::new(AdmittedDeque::new(class)),
            closed: AtomicBool::new(false),
            wait_generation: AtomicU64::new(0),
        }
    }

    fn prepare_queue_capacity_for_pid(
        &self,
        pid: Option<ProcessId>,
    ) -> Result<PreparedWaitQueueCapacity, AdmittedAllocError> {
        let (class, len, capacity, already_queued) = interrupts::without_interrupts(|| {
            let waiters = self.waiters.lock();
            (
                waiters.class(),
                waiters.len(),
                waiters.capacity(),
                pid.is_some_and(|pid| waiters.iter().any(|&(queued, _)| queued == pid)),
            )
        });
        let prepared = if already_queued {
            None
        } else {
            prepare_deque_growth(class, len, capacity)?
        };
        Ok(PreparedWaitQueueCapacity {
            pid,
            prepared,
            retired_replaced: None,
            retired_empty: None,
        })
    }

    /// RF180-42: prepare possible queue growth before a caller takes the
    /// resource lock that protects its blocking condition.
    pub(crate) fn prepare_current_wait_capacity(
        &self,
    ) -> Result<PreparedWaitQueueCapacity, AdmittedAllocError> {
        if FAIL_NEXT_WAIT_CAPACITY.swap(false, Ordering::AcqRel) {
            return Err(AdmittedAllocError::AllocationFailed);
        }
        self.prepare_queue_capacity_for_pid(process::current_pid())
    }

    /// Ensure a new entry can be published without allocating or freeing.
    /// Returns false when the detached snapshot lost a race and the caller must
    /// leave its resource lock, prepare again, and recheck the condition.
    fn ensure_queue_capacity_locked(
        queue: &mut AdmittedDeque<WaitQueueEntry>,
        prepared: &mut PreparedWaitQueueCapacity,
    ) -> bool {
        if queue.len() < queue.capacity() {
            return true;
        }
        let Some(candidate) = prepared.prepared.take() else {
            return false;
        };
        if candidate.class() != queue.class() || candidate.capacity() <= queue.len() {
            prepared.prepared = Some(candidate);
            return false;
        }
        debug_assert!(prepared.retired_replaced.is_none());
        prepared.retired_replaced = Some(
            queue
                .install_prepared_deferred(candidate)
                .expect("RF180-42 WaitQueue prepared-capacity invariant"),
        );
        true
    }

    fn retire_empty_queue_locked(
        queue: &mut AdmittedDeque<WaitQueueEntry>,
        prepared: &mut PreparedWaitQueueCapacity,
    ) {
        if prepared.retired_empty.is_none() {
            prepared.retired_empty = queue.take_empty_capacity();
        }
    }

    fn prepare_transaction_capacity(
        &self,
        pid: ProcessId,
        timed: bool,
    ) -> Result<PreparedWaitTransactionCapacity, AdmittedAllocError> {
        let queue = self.prepare_queue_capacity_for_pid(Some(pid))?;
        let timer_prepared = if timed {
            let (class, len, capacity, already_registered) = interrupts::without_interrupts(|| {
                let timers = TIMED_WAITERS.lock();
                (
                    timers.class(),
                    timers.len(),
                    timers.capacity(),
                    timers.iter().any(|timer| timer.pid == pid),
                )
            });
            if already_registered {
                None
            } else {
                prepare_deque_growth(class, len, capacity)?
            }
        } else {
            None
        };
        Ok(PreparedWaitTransactionCapacity {
            queue,
            timer_prepared,
            timer_retired_replaced: None,
            timer_retired_empty: None,
        })
    }

    fn ensure_timer_capacity_locked(
        timers: &mut AdmittedDeque<TimedWaiter>,
        prepared: &mut PreparedWaitTransactionCapacity,
    ) -> bool {
        if timers.len() < timers.capacity() {
            return true;
        }
        let Some(candidate) = prepared.timer_prepared.take() else {
            return false;
        };
        if candidate.class() != timers.class() || candidate.capacity() <= timers.len() {
            prepared.timer_prepared = Some(candidate);
            return false;
        }
        debug_assert!(prepared.timer_retired_replaced.is_none());
        prepared.timer_retired_replaced = Some(
            timers
                .install_prepared_deferred(candidate)
                .expect("RF180-42 timed-wait prepared-capacity invariant"),
        );
        true
    }

    fn retire_empty_timer_locked(
        timers: &mut AdmittedDeque<TimedWaiter>,
        prepared: &mut PreparedWaitTransactionCapacity,
    ) {
        if prepared.timer_retired_empty.is_none() {
            prepared.timer_retired_empty = timers.take_empty_capacity();
        }
    }

    fn reclaim_empty_waiter_capacity(&self) {
        let retired = interrupts::without_interrupts(|| self.waiters.lock().take_empty_capacity());
        drop(retired);
    }

    fn reclaim_empty_timer_capacity() {
        let retired = interrupts::without_interrupts(|| TIMED_WAITERS.lock().take_empty_capacity());
        drop(retired);
    }

    /// 将当前进程加入等待队列并阻塞
    ///
    /// 返回true表示成功阻塞后被唤醒，false表示无当前进程或队列已关闭
    ///
    /// # X-6 安全增强
    ///
    /// 如果队列已关闭（如端点被销毁），立即返回 false 而不阻塞，
    /// 防止进程在已销毁的端点上永久阻塞。
    pub fn wait(&self) -> bool {
        matches!(self.wait_with_timeout(None), WaitOutcome::Woken)
    }

    /// R39-6 FIX: 将当前进程加入等待队列并阻塞（可选超时）
    ///
    /// # Arguments
    ///
    /// * `timeout_ns` - 超时时间（纳秒），None 表示无限等待
    ///
    /// # Returns
    ///
    /// 返回等待结果，用于区分正常唤醒与超时唤醒。
    pub fn wait_with_timeout(&self, timeout_ns: Option<u64>) -> WaitOutcome {
        match self
            .try_prepare_with_timeout_after(timeout_ns, || Ok::<(), core::convert::Infallible>(()))
        {
            Ok(Ok(PrepareWait::Immediate(outcome))) => outcome,
            Ok(Ok(PrepareWait::Armed(ticket))) => self.finish_prepared(ticket),
            Ok(Err(never)) => match never {},
            Err(_) => WaitOutcome::ResourceExhausted,
        }
    }
    /// RF178-8 / P2-B: fallibly publish a complete queue/timer transaction without
    /// yielding, with a **caller-supplied recheck under `waiters` lock**.
    ///
    /// # Lost-wake class elimination (P2-B / R172 residual)
    ///
    /// Classic futex lost-wake: value-check → (race: store+wake) → enqueue+block.
    /// This API closes that class for any caller that supplies a recheck of the
    /// wait condition:
    ///
    /// 1. Take `waiters` under IRQs-off (all normal wakers take the same lock first).
    /// 2. Run `check` **while still holding `waiters`** (before any enqueue).
    /// 3. Only if `check` returns `Ok(())`: publish waiter + `Blocked` (+ timer).
    ///
    /// A concurrent wake either (a) runs before we take `waiters` — then the under-
    /// lock recheck observes the store and aborts without blocking, or (b) runs
    /// while/after we hold `waiters` — then it observes the published waiter.
    ///
    /// Callers that need to sleep after a successful arm use [`finish_prepared`].
    /// Callers that arm and then discover the condition elsewhere must use
    /// [`cancel_wait`] / exact remove — do **not** recheck only *after* publish and
    /// then sleep without cancel (that would re-open a different lost-wake shape).
    pub(crate) fn try_prepare_with_timeout_after<F, E>(
        &self,
        timeout_ns: Option<u64>,
        mut check: F,
    ) -> Result<Result<PrepareWait, E>, AdmittedAllocError>
    where
        F: FnMut() -> Result<(), E>,
    {
        enum ArmAttempt<E> {
            RetryCapacity,
            Complete(Result<PrepareWait, E>),
        }

        let pid = match process::current_pid() {
            Some(pid) => pid,
            None => return Ok(Ok(PrepareWait::Immediate(WaitOutcome::NoProcess))),
        };
        if self.closed.load(Ordering::Acquire) {
            return Ok(Ok(PrepareWait::Immediate(WaitOutcome::Closed)));
        }
        if matches!(timeout_ns, Some(0)) {
            return Ok(Ok(PrepareWait::Immediate(WaitOutcome::TimedOut)));
        }

        let deadline_tick = timeout_ns.map(|ns| {
            let ticks = ns.checked_add(NS_PER_MS - 1).unwrap_or(u64::MAX) / NS_PER_MS;
            kernel_core::get_ticks().saturating_add(ticks.max(1))
        });
        let wait_seq = deadline_tick.map(|_| process::alloc_wait_seq());
        if wait_seq.is_some() && !WAITQUEUE_TIMER_INIT.load(Ordering::Acquire) {
            return Ok(Ok(PrepareWait::Immediate(WaitOutcome::ResourceExhausted)));
        }
        let process = match process::get_process(pid) {
            Some(process) => process,
            None => return Ok(Ok(PrepareWait::Immediate(WaitOutcome::NoProcess))),
        };
        let generation = self.wait_generation.fetch_add(1, Ordering::Relaxed);

        loop {
            // RF180-42 FIX: reserve and physically allocate both possible
            // backings before taking WaitQueue/TIMED_WAITERS/PCB locks. A race
            // can consume the snapshot capacity; that case publishes nothing,
            // drops the detached owners after IRQs are restored, and retries.
            let mut capacity = self.prepare_transaction_capacity(pid, deadline_tick.is_some())?;
            debug_assert_eq!(capacity.queue.pid, Some(pid));

            let attempt = interrupts::without_interrupts(|| {
                if self.closed.load(Ordering::Relaxed) {
                    return ArmAttempt::Complete(Ok(PrepareWait::Immediate(WaitOutcome::Closed)));
                }

                let mut queue = self.waiters.lock();
                let queue_pos = queue.iter().position(|&(queued_pid, _)| queued_pid == pid);
                if queue_pos.is_none()
                    && !Self::ensure_queue_capacity_locked(&mut queue, &mut capacity.queue)
                {
                    Self::retire_empty_queue_locked(&mut queue, &mut capacity.queue);
                    return ArmAttempt::RetryCapacity;
                }

                // The futex condition must remain serialized against ordinary
                // wakers by queue, but must run before TIMED_WAITERS is taken:
                // user-memory revalidation may take PT_LOCK and timer IRQ takes
                // TIMED_WAITERS, so the reverse order would deadlock.
                if let Err(error) = check() {
                    Self::retire_empty_queue_locked(&mut queue, &mut capacity.queue);
                    return ArmAttempt::Complete(Err(error));
                }

                if let (Some(deadline_tick), Some(seq)) = (deadline_tick, wait_seq) {
                    let mut timers = TIMED_WAITERS.lock();
                    let timer_pos = timers.iter().position(|timer| timer.pid == pid);
                    if timer_pos.is_none()
                        && !Self::ensure_timer_capacity_locked(&mut timers, &mut capacity)
                    {
                        Self::retire_empty_queue_locked(&mut queue, &mut capacity.queue);
                        Self::retire_empty_timer_locked(&mut timers, &mut capacity);
                        return ArmAttempt::RetryCapacity;
                    }

                    let mut proc = process.lock();
                    if kernel_core::signal::should_abort_pending_block(&proc) {
                        Self::retire_empty_queue_locked(&mut queue, &mut capacity.queue);
                        Self::retire_empty_timer_locked(&mut timers, &mut capacity);
                        return ArmAttempt::Complete(Ok(PrepareWait::Immediate(
                            WaitOutcome::Interrupted,
                        )));
                    }

                    if let Some(pos) = queue_pos {
                        queue[pos].1 = generation;
                    } else {
                        queue
                            .push_back_reserved((pid, generation))
                            .unwrap_or_else(|_| {
                                panic!("RF180-42 queue capacity vanished under lock")
                            });
                    }
                    proc.wq_timeout_marker.store(0, Ordering::Relaxed);
                    proc.active_wait_seq.store(seq, Ordering::Relaxed);
                    proc.enter_blocked_at(kernel_core::get_ticks());

                    let timer = TimedWaiter {
                        pid,
                        deadline_tick,
                        seq,
                        generation,
                    };
                    if let Some(pos) = timer_pos {
                        timers[pos] = timer;
                    } else {
                        timers.push_back_reserved(timer).unwrap_or_else(|_| {
                            panic!("RF180-42 timer capacity vanished under lock")
                        });
                    }
                    ArmAttempt::Complete(Ok(PrepareWait::Armed(WaitTicket {
                        pid,
                        generation,
                        wait_seq: Some(seq),
                    })))
                } else {
                    let mut proc = process.lock();
                    if kernel_core::signal::should_abort_pending_block(&proc) {
                        Self::retire_empty_queue_locked(&mut queue, &mut capacity.queue);
                        return ArmAttempt::Complete(Ok(PrepareWait::Immediate(
                            WaitOutcome::Interrupted,
                        )));
                    }
                    if let Some(pos) = queue_pos {
                        queue[pos].1 = generation;
                    } else {
                        queue
                            .push_back_reserved((pid, generation))
                            .unwrap_or_else(|_| {
                                panic!("RF180-42 queue capacity vanished under lock")
                            });
                    }
                    proc.wq_timeout_marker.store(0, Ordering::Relaxed);
                    proc.enter_blocked_at(kernel_core::get_ticks());
                    ArmAttempt::Complete(Ok(PrepareWait::Armed(WaitTicket {
                        pid,
                        generation,
                        wait_seq: None,
                    })))
                }
            });

            // Detached prepared/retired allocations are destroyed only after
            // IRQs and every live queue/timer/PCB lock have been released.
            drop(capacity);
            match attempt {
                ArmAttempt::RetryCapacity => continue,
                ArmAttempt::Complete(result) => return Ok(result),
            }
        }
    }

    fn remove_waiter_exact(&self, pid: ProcessId, generation: u64) {
        self.waiters
            .lock()
            .retain_capacity(|&(queued_pid, queued_gen)| {
                queued_pid != pid || queued_gen != generation
            });
    }

    fn disarm_ticket_timer(&self, ticket: &WaitTicket) {
        if let Some(seq) = ticket.wait_seq {
            interrupts::without_interrupts(|| {
                cancel_timed_wait_exact(ticket.pid, seq);
            });
            Self::reclaim_empty_timer_capacity();
            if let Some(process) = process::get_process(ticket.pid) {
                let proc = process.lock();
                if proc.active_wait_seq.load(Ordering::Relaxed) == seq {
                    proc.active_wait_seq.store(0, Ordering::Relaxed);
                }
            }
        }
    }

    pub(crate) fn finish_prepared(&self, ticket: WaitTicket) -> WaitOutcome {
        kernel_core::force_reschedule();
        self.disarm_ticket_timer(&ticket);

        let outcome = if process::wait_should_abort(ticket.pid)
            || kernel_core::signal::has_deliverable_signal(ticket.pid)
        {
            interrupts::without_interrupts(|| {
                self.remove_waiter_exact(ticket.pid, ticket.generation);
            });
            self.consume_timeout_flag(ticket.pid, ticket.generation);
            WaitOutcome::Interrupted
        } else if self.consume_timeout_flag(ticket.pid, ticket.generation) {
            interrupts::without_interrupts(|| {
                self.remove_waiter_exact(ticket.pid, ticket.generation);
            });
            WaitOutcome::TimedOut
        } else {
            WaitOutcome::Woken
        };
        self.reclaim_empty_waiter_capacity();
        outcome
    }

    // R165-4 FIX: Consume the timeout flag only on an EXACT generation match.
    // A stored generation strictly less than `expected_gen` is a stale leftover
    // from an earlier wait by this PID (its consumer raced a normal wake); drop
    // it without reporting a timeout. A stored generation greater than expected
    // is impossible (a single PID cannot have two concurrent waits). Tightening
    // R164-10's `>=` to `==` closes the spurious-ETIMEDOUT path.
    //
    // M4-1b: the marker now lives per-PCB in `Process.wq_timeout_marker`;
    // `process::consume_wq_timeout` does the swap-to-clear with the SAME exact-gen
    // semantics (stored != expected => false + cleared; == => true). It is
    // process-context-only (blocking PROCESS_TABLE); all callers below are wait
    // epilogues. The proc lock it takes is the synchronizing edge that pairs with
    // the IRQ-side store-under-proc-lock.
    fn consume_timeout_flag(&self, pid: ProcessId, expected_gen: u64) -> bool {
        process::consume_wq_timeout(pid, expected_gen)
    }

    /// R156-6 FIX: Remove stale entries for an exiting process.
    pub fn cleanup_for_pid(&self, pid: ProcessId) {
        interrupts::without_interrupts(|| {
            let mut waiters = self.waiters.lock();
            waiters.retain_capacity(|&(p, _)| p != pid);
            // M4-1b: no `timed_out` map to prune — the per-PCB `wq_timeout_marker`
            // dies with the PCB. The `waiters` membership retain stays (a stale
            // deque entry for a dead PID is still reachable by `wake_one`/`wake_n`).
        });
        self.reclaim_empty_waiter_capacity();
    }

    /// R180-5 FIX: identity-bound wait-queue cleanup for a reaped process.
    ///
    /// Removes entries for `pid` only when they belong to the reaped generation:
    /// - Process-generation stamps (`PROCESS_GEN_TAG`): remove on exact match.
    /// - Plain wait-counter stamps: remove only if no live PCB owns `pid` with a
    ///   different generation (successor already published → leave its entries).
    pub fn cleanup_for_identity(&self, pid: ProcessId, generation: u64) {
        let live_gen = process::get_process(pid).map(|p| p.lock().generation);
        interrupts::without_interrupts(|| {
            let mut waiters = self.waiters.lock();
            waiters.retain_capacity(|&(p, entry_gen)| {
                if p != pid {
                    return true;
                }
                if is_process_generation_stamp(entry_gen) {
                    let stamped = unstamp_process_generation(entry_gen);
                    // Keep only if stamp is NOT the reaped generation.
                    return stamped != generation;
                }
                // Untagged (wait-counter) entry: drop if no live successor, or
                // if the live PCB is still the reaped identity (should not
                // happen after slot take — belt-and-suspenders).
                match live_gen {
                    Some(g) if g != generation => true, // successor — keep
                    _ => false,                         // reaped or empty slot — drop
                }
            });
        });
        self.reclaim_empty_waiter_capacity();
    }

    /// 唤醒等待队列中的一个进程
    ///
    /// 返回被唤醒的进程ID，如果队列为空返回None
    ///
    /// # P3-A (R171 residual)
    ///
    /// Skip non-Blocked entries (M1-02). Additionally, if the entry was stamped
    /// with a **process** generation (`PROCESS_GEN_TAG`), require
    /// `pcb.generation == stamped` so a recycled PID cannot be readied by a
    /// stale queue entry left after signal/kill interrupt of a pipe wait.
    pub fn wake_one(&self) -> Option<ProcessId> {
        interrupts::without_interrupts(|| {
            let mut waiters = self.waiters.lock();
            while let Some((pid, entry_gen)) = waiters.pop_front_retaining_capacity() {
                if let Some(proc_arc) = process::get_process(pid) {
                    let mut proc = proc_arc.lock();
                    if proc.state != ProcessState::Blocked {
                        continue;
                    }
                    if is_process_generation_stamp(entry_gen) {
                        let stamped = unstamp_process_generation(entry_gen);
                        if stamped != proc.generation {
                            // Stale recycled-PID entry — drop, do not ready.
                            continue;
                        }
                    }
                    proc.enter_ready_at(kernel_core::get_ticks());
                    return Some(pid);
                }
            }
            None
        })
    }

    /// 唤醒等待队列中的所有进程
    ///
    /// 返回被唤醒的进程数量
    pub fn wake_all(&self) -> usize {
        interrupts::without_interrupts(|| {
            let mut waiters = self.waiters.lock();
            let mut woken = 0usize;

            while let Some((pid, entry_gen)) = waiters.pop_front_retaining_capacity() {
                // M1-02: no PID-only timer cancel here.
                // P3-A: process-generation identity gate (same as wake_one).
                if let Some(proc_arc) = process::get_process(pid) {
                    let mut proc = proc_arc.lock();
                    if proc.state != ProcessState::Blocked {
                        continue;
                    }
                    if is_process_generation_stamp(entry_gen) {
                        let stamped = unstamp_process_generation(entry_gen);
                        if stamped != proc.generation {
                            continue;
                        }
                    }
                    proc.enter_ready_at(kernel_core::get_ticks());
                    woken += 1;
                }
            }

            woken
        })
    }

    /// 唤醒等待队列中的最多 n 个进程
    ///
    /// 用于 futex FUTEX_WAKE 操作，只唤醒指定数量的等待者
    ///
    /// # Arguments
    ///
    /// * `n` - 最多唤醒的进程数量
    ///
    /// # Returns
    ///
    /// 实际唤醒的进程数量
    pub fn wake_n(&self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }

        interrupts::without_interrupts(|| {
            let mut waiters = self.waiters.lock();
            let mut woken = 0;

            while woken < n {
                if let Some((pid, entry_gen)) = waiters.pop_front_retaining_capacity() {
                    // M1-02: no PID-only timer cancel here.
                    // P3-A: process-generation identity gate.
                    if let Some(proc_arc) = process::get_process(pid) {
                        let mut proc = proc_arc.lock();
                        if proc.state != ProcessState::Blocked {
                            continue;
                        }
                        if is_process_generation_stamp(entry_gen) {
                            let stamped = unstamp_process_generation(entry_gen);
                            if stamped != proc.generation {
                                continue;
                            }
                        }
                        proc.enter_ready_at(kernel_core::get_ticks());
                        woken += 1;
                    }
                } else {
                    break;
                }
            }

            woken
        })
    }

    /// E.4 PI: 唤醒指定的等待者（如果存在）
    ///
    /// 用于需要精确唤醒特定进程的场景（例如 FUTEX_LOCK_PI 选择最高优先级等待者）。
    ///
    /// # Arguments
    ///
    /// * `pid` - 要唤醒的进程 ID
    ///
    /// # Returns
    ///
    /// 如果成功唤醒该进程返回 true，否则返回 false
    pub fn wake_specific(&self, pid: ProcessId) -> bool {
        interrupts::without_interrupts(|| {
            let mut waiters = self.waiters.lock();
            if let Some(pos) = waiters.iter().position(|&(p, _)| p == pid) {
                let entry_gen = waiters[pos].1;
                waiters.remove_retaining_capacity(pos);
                // M1-02: no PID-only timer cancel here.
                // P3-A: process-generation identity gate.
                if let Some(proc_arc) = process::get_process(pid) {
                    let mut proc = proc_arc.lock();
                    if proc.state != ProcessState::Blocked {
                        return false;
                    }
                    if is_process_generation_stamp(entry_gen) {
                        let stamped = unstamp_process_generation(entry_gen);
                        if stamped != proc.generation {
                            return false;
                        }
                    }
                    proc.enter_ready_at(kernel_core::get_ticks());
                }
                true
            } else {
                false
            }
        })
    }

    /// 检查等待队列是否为空
    pub fn is_empty(&self) -> bool {
        self.waiters.lock().is_empty()
    }

    /// 获取等待队列中的进程数量
    pub fn len(&self) -> usize {
        self.waiters.lock().len()
    }

    /// Z-11 fix: 准备等待（添加到队列但不立即阻塞）
    ///
    /// 用于实现条件变量语义，避免 lost-wakeup 竞态条件。
    /// 调用者应在持有相关锁的情况下调用此函数，然后释放锁，
    /// 最后调用 `finish_wait()` 来实际阻塞。
    ///
    /// # Returns
    ///
    /// 如果成功加入队列返回 true，如果无当前进程或队列已关闭返回 false
    pub fn prepare_to_wait(&self) -> Result<(), WaitOutcome> {
        match self.try_prepare_to_wait() {
            Ok(true) => Ok(()),
            Err(_) => Err(WaitOutcome::ResourceExhausted),
            Ok(false) => {
                if self.is_closed() {
                    return Err(WaitOutcome::Closed);
                }
                let Some(pid) = process::current_pid() else {
                    return Err(WaitOutcome::NoProcess);
                };
                if process::wait_should_abort(pid)
                    || kernel_core::signal::has_deliverable_signal(pid)
                {
                    Err(WaitOutcome::Interrupted)
                } else {
                    // The current PCB disappeared or changed between detached
                    // preparation and the locked publication recheck.
                    Err(WaitOutcome::NoProcess)
                }
            }
        }
    }

    /// RF178-8: fallible form of `prepare_to_wait`.
    ///
    /// Reservation and enqueue share the waiters lock, so capacity cannot be
    /// consumed by another producer between `try_reserve` and `push_back`.
    pub fn try_prepare_to_wait(&self) -> Result<bool, AdmittedAllocError> {
        loop {
            let mut capacity = self.prepare_current_wait_capacity()?;
            let outcome = self.try_prepare_to_wait_with_capacity(&mut capacity);
            // Any unused detached backing or retired live backing is destroyed
            // only after IRQs and the WaitQueue lock are released.
            drop(capacity);
            match outcome {
                PrepareToWaitCapacityOutcome::Prepared(prepared) => return Ok(prepared),
                PrepareToWaitCapacityOutcome::RetryCapacity => continue,
            }
        }
    }

    /// RF180-42: allocation/deallocation-free arm operation for callers that
    /// already hold the lock protecting their blocking condition.
    pub(crate) fn try_prepare_to_wait_with_capacity(
        &self,
        capacity: &mut PreparedWaitQueueCapacity,
    ) -> PrepareToWaitCapacityOutcome {
        let pid = match capacity.pid {
            Some(pid) if process::current_pid() == Some(pid) => pid,
            _ => return PrepareToWaitCapacityOutcome::Prepared(false),
        };

        interrupts::without_interrupts(|| {
            let mut waiters = self.waiters.lock();
            if self.closed.load(Ordering::Relaxed)
                || process::wait_should_abort(pid)
                || kernel_core::signal::has_deliverable_signal(pid)
            {
                Self::retire_empty_queue_locked(&mut waiters, capacity);
                return PrepareToWaitCapacityOutcome::Prepared(false);
            }

            if let Some(entry) = waiters.iter_mut().find(|(queued, _)| *queued == pid) {
                if let Some(proc_arc) = process::get_process(pid) {
                    let mut proc = proc_arc.lock();
                    if kernel_core::signal::should_abort_pending_block(&proc) {
                        waiters.retain_capacity(|&(queued, _)| queued != pid);
                        Self::retire_empty_queue_locked(&mut waiters, capacity);
                        return PrepareToWaitCapacityOutcome::Prepared(false);
                    }
                    entry.1 = stamp_process_generation(proc.generation);
                    if proc.state != ProcessState::Blocked {
                        proc.enter_blocked_at(kernel_core::get_ticks());
                    }
                    return PrepareToWaitCapacityOutcome::Prepared(true);
                }
                waiters.retain_capacity(|&(queued, _)| queued != pid);
                Self::retire_empty_queue_locked(&mut waiters, capacity);
                return PrepareToWaitCapacityOutcome::Prepared(false);
            }

            if !Self::ensure_queue_capacity_locked(&mut waiters, capacity) {
                return PrepareToWaitCapacityOutcome::RetryCapacity;
            }

            let Some(proc_arc) = process::get_process(pid) else {
                Self::retire_empty_queue_locked(&mut waiters, capacity);
                return PrepareToWaitCapacityOutcome::Prepared(false);
            };
            let mut proc = proc_arc.lock();
            if kernel_core::signal::should_abort_pending_block(&proc) {
                Self::retire_empty_queue_locked(&mut waiters, capacity);
                return PrepareToWaitCapacityOutcome::Prepared(false);
            }
            let generation = stamp_process_generation(proc.generation);
            waiters
                .push_back_reserved((pid, generation))
                .unwrap_or_else(|_| panic!("RF180-42 queue capacity vanished under lock"));
            proc.enter_blocked_at(kernel_core::get_ticks());
            PrepareToWaitCapacityOutcome::Prepared(true)
        })
    }

    /// Z-11 fix: 完成等待（实际阻塞）
    ///
    /// 必须在 `prepare_to_wait()` 返回 true 之后调用。
    /// 在调用此函数之前应释放相关锁。
    pub fn finish_wait(&self) {
        // 触发调度，让出CPU
        kernel_core::force_reschedule();
        self.reclaim_empty_waiter_capacity();
    }

    /// Z-11 fix: 取消等待（从队列移除）
    ///
    /// 如果在 `prepare_to_wait()` 后发现条件已满足，
    /// 调用此函数取消等待而不阻塞。
    ///
    /// # Returns
    ///
    /// 如果成功从队列移除返回 true
    pub fn cancel_wait(&self) -> bool {
        let pid = match process::current_pid() {
            Some(p) => p,
            None => return false,
        };

        let removed = interrupts::without_interrupts(|| {
            let mut waiters = self.waiters.lock();

            // 从队列中移除当前进程
            if let Some(pos) = waiters.iter().position(|&(p, _)| p == pid) {
                waiters.remove_retaining_capacity(pos);
                // R39-6 FIX: 取消定时等待
                // 恢复进程状态为就绪
                //
                // R170-4 FIX: restore Ready ONLY when the state is still the
                // `Blocked` our own prepare_to_wait() wrote (the exact undo).
                // cancel_wait is also reached from paths where the caller has
                // already RESUMED and is Running (the futex_lock_pi success /
                // EAGAIN exits after a non-dequeuing wake): tasks stay in the
                // ready queue while Running, and `state == Ready` is the
                // scheduler's claim gate, so an unconditional Ready re-stamp
                // would let another CPU's pick/steal claim a task that is
                // still executing here (same-task-on-two-CPUs). The guard
                // also stops resurrecting a Zombie/Terminated task to Ready.
                // Every legacy caller cancels immediately after
                // prepare_to_wait (state IS Blocked), so their behavior is
                // byte-identical.
                if let Some(proc_arc) = process::get_process(pid) {
                    let mut proc = proc_arc.lock();
                    if proc.state == ProcessState::Blocked {
                        proc.enter_ready_at(kernel_core::get_ticks());
                    }
                }

                true
            } else {
                false
            }
        });
        self.reclaim_empty_waiter_capacity();
        removed
    }

    /// 检查队列是否已关闭（例如端点被销毁）
    ///
    /// # X-6 安全增强
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// 关闭队列并唤醒所有等待者
    ///
    /// 用于端点销毁时，确保所有等待者被唤醒并得到错误返回。
    /// 关闭后的队列不再接受新的等待者。
    ///
    /// # X-6 安全增强
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.wake_all();
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new(HeapClass::Scheduler)
    }
}

/// 内核互斥锁
///
/// 可阻塞的互斥锁，当锁不可用时进程会被阻塞。
/// 适用于需要长时间持有锁的场景。
pub struct KMutex {
    /// 锁状态：true表示已锁定
    locked: AtomicBool,
    /// 等待队列
    wait_queue: WaitQueue,
    /// 当前持有锁的进程ID（调试用）
    owner: Mutex<Option<ProcessId>>,
}

impl KMutex {
    /// 创建新的互斥锁
    pub fn new() -> Self {
        KMutex {
            locked: AtomicBool::new(false),
            wait_queue: WaitQueue::new(HeapClass::Scheduler),
            owner: Mutex::new(None),
        }
    }

    /// R155-7 FIX: Use prepare_to_wait/cancel_wait pattern (same as R154-6 Semaphore)
    /// to prevent lost-wakeup race where unlock() calls wake_one() between our
    /// CAS failure and enqueue, seeing an empty queue.
    pub fn lock(&self) -> Result<(), WaitOutcome> {
        loop {
            if self
                .locked
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                if let Some(pid) = process::current_pid() {
                    *self.owner.lock() = Some(pid);
                }
                return Ok(());
            }

            self.wait_queue.prepare_to_wait()?;

            if self
                .locked
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                self.wait_queue.cancel_wait();
                if let Some(pid) = process::current_pid() {
                    *self.owner.lock() = Some(pid);
                }
                return Ok(());
            }

            self.wait_queue.finish_wait();
        }
    }

    /// 尝试获取锁（非阻塞）
    ///
    /// 如果锁可用，获取锁并返回true；否则返回false
    pub fn try_lock(&self) -> bool {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            if let Some(pid) = process::current_pid() {
                *self.owner.lock() = Some(pid);
            }
            true
        } else {
            false
        }
    }

    /// Condvar return invariant: once the associated mutex has been released,
    /// every return to the caller must hold it again. This allocation-free
    /// fallback cannot fail because it performs only the ownership CAS and a
    /// scheduler yield; it deliberately ignores interruptible wait admission.
    fn reacquire_after_condvar(&self) {
        while !self.try_lock() {
            kernel_core::force_reschedule();
        }
    }

    /// 释放锁
    ///
    /// R154-16 FIX: Debug assertion verifying caller owns the lock.
    pub fn unlock(&self) {
        debug_assert!(
            {
                let owner = self.owner.lock();
                owner.is_none() || *owner == process::current_pid()
            },
            "KMutex::unlock() called by non-owner"
        );
        *self.owner.lock() = None;
        self.locked.store(false, Ordering::Release);

        // 唤醒一个等待者
        self.wait_queue.wake_one();
    }

    /// 检查锁是否被持有
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

impl Default for KMutex {
    fn default() -> Self {
        Self::new()
    }
}

/// 计数信号量
///
/// 用于控制对有限资源的并发访问
pub struct Semaphore {
    /// 当前计数
    count: AtomicU32,
    /// 等待队列
    wait_queue: WaitQueue,
}

impl Semaphore {
    /// 创建新的信号量
    ///
    /// # Arguments
    ///
    /// * `initial` - 初始计数值
    pub fn new(initial: u32) -> Self {
        Semaphore {
            count: AtomicU32::new(initial),
            wait_queue: WaitQueue::new(HeapClass::Scheduler),
        }
    }

    /// P操作（等待/获取）
    ///
    /// 如果计数大于0，减1并继续；否则阻塞直到计数大于0
    ///
    /// # R154-6 FIX: Use prepare_to_wait/cancel_wait pattern to prevent lost wakeup.
    ///
    /// The old sequence had a classic lost-wakeup race: (1) load count=0,
    /// (2) signal() fires — count becomes 1, wake_one() sees empty queue,
    /// (3) process enters wait_queue.wait() and blocks forever.
    /// Now we register in the wait queue BEFORE checking count, so any
    /// signal() between check and block will find us in the queue.
    pub fn wait(&self) -> Result<(), WaitOutcome> {
        loop {
            // Fast path: try to decrement without blocking
            let current = self.count.load(Ordering::SeqCst);
            if current > 0 {
                if self
                    .count
                    .compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    return Ok(());
                }
                continue;
            }

            // R154-6 FIX: Register in wait queue BEFORE re-checking count.
            self.wait_queue.prepare_to_wait()?;

            // Re-check count after registration: a signal() between our
            // initial load and prepare_to_wait would have incremented count
            // AND called wake_one (which now sees us in the queue).
            let current = self.count.load(Ordering::SeqCst);
            if current > 0 {
                if self
                    .count
                    .compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    // Got the permit — cancel the wait, don't block.
                    self.wait_queue.cancel_wait();
                    return Ok(());
                }
                // CAS failed — someone else grabbed it. Stay in queue and block.
            }

            // Block until woken by signal()
            self.wait_queue.finish_wait();
        }
    }

    /// P操作（非阻塞）
    ///
    /// 如果计数大于0，减1并返回true；否则返回false
    pub fn try_wait(&self) -> bool {
        loop {
            let current = self.count.load(Ordering::SeqCst);
            if current == 0 {
                return false;
            }
            if self
                .count
                .compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// V操作（发布/释放）
    ///
    /// 增加计数并唤醒一个等待者
    ///
    /// R154-17 FIX: Use saturating increment to prevent u32 wrap-around
    /// that would clear all permits (count wraps from MAX to 0).
    pub fn signal(&self) {
        let _ = self
            .count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(v.saturating_add(1))
            });
        self.wait_queue.wake_one();
    }

    /// 获取当前计数
    pub fn count(&self) -> u32 {
        self.count.load(Ordering::Relaxed)
    }
}

/// 条件变量
///
/// 用于等待特定条件成立
pub struct CondVar {
    /// 等待队列
    wait_queue: WaitQueue,
}

impl CondVar {
    /// 创建新的条件变量
    pub fn new() -> Self {
        CondVar {
            wait_queue: WaitQueue::new(HeapClass::Scheduler),
        }
    }

    /// 等待条件成立
    ///
    /// 调用者必须在持有相关锁的情况下调用此函数。
    /// 此函数会释放锁、等待唤醒、然后重新获取锁。
    ///
    /// # R153-7 FIX: Use prepare_to_wait/finish_wait pattern.
    ///
    /// The old sequence (unlock → wait) had a lost-wakeup window: if
    /// notify_one() fires between mutex.unlock() and wait_queue enqueue,
    /// the wake signal is lost because the waiter is not yet registered.
    /// Now we register BEFORE releasing the mutex, so the wake cannot
    /// be missed.
    ///
    /// # Arguments
    ///
    /// * `mutex` - 保护条件的互斥锁
    pub fn wait(&self, mutex: &KMutex) -> Result<(), WaitOutcome> {
        // R153-7 FIX: Register in wait queue BEFORE releasing mutex.
        // If notify_one() fires after mutex release, our PID is already
        // in the queue and the wake signal will be delivered.
        self.wait_queue.prepare_to_wait()?;

        // 释放锁 — notifiers can now run
        mutex.unlock();

        // 实际阻塞
        self.wait_queue.finish_wait();

        // 重新获取锁
        mutex.reacquire_after_condvar();
        Ok(())
    }

    /// 唤醒一个等待者
    pub fn notify_one(&self) {
        self.wait_queue.wake_one();
    }

    /// 唤醒所有等待者
    pub fn notify_all(&self) {
        self.wait_queue.wake_all();
    }
}

impl Default for CondVar {
    fn default() -> Self {
        Self::new()
    }
}

/// RF180-42 executable convergence probe for fallible synchronization waits.
/// Admission failure must never be reported as successful lock/permit
/// acquisition, and a condvar failure before release must leave its mutex held.
pub fn run_blocking_sync_failure_self_test() {
    let mutex = KMutex::new();
    mutex.lock().expect("RF180-42 mutex fixture lock");
    FAIL_NEXT_WAIT_CAPACITY.store(true, Ordering::Release);
    assert_eq!(mutex.lock(), Err(WaitOutcome::ResourceExhausted));
    assert!(mutex.is_locked());

    let condvar = CondVar::new();
    FAIL_NEXT_WAIT_CAPACITY.store(true, Ordering::Release);
    assert_eq!(condvar.wait(&mutex), Err(WaitOutcome::ResourceExhausted));
    assert!(
        mutex.is_locked(),
        "RF180-42 condvar prepare failure released its mutex"
    );
    mutex.unlock();

    let semaphore = Semaphore::new(0);
    FAIL_NEXT_WAIT_CAPACITY.store(true, Ordering::Release);
    assert_eq!(semaphore.wait(), Err(WaitOutcome::ResourceExhausted));
    assert_eq!(semaphore.count(), 0);
}

// =============================================================================
// R39-6 FIX: WaitQueue 超时支持辅助函数
// =============================================================================

/// R39-6 FIX: 初始化 WaitQueue 定时器回调
///
/// 在 IPC 模块初始化时调用，注册定时器回调以处理超时唤醒。
pub fn init_waitqueue_timers() {
    ensure_waitqueue_timer_registered();
}

fn reclaim_empty_timed_waiter_backing() {
    WaitQueue::reclaim_empty_timer_capacity();
}

/// 确保定时器回调已注册（只注册一次）
fn ensure_waitqueue_timer_registered() {
    if WAITQUEUE_TIMER_INIT
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        kernel_core::register_soft_progress_callback(reclaim_empty_timed_waiter_backing)
            .expect("waitqueue deferred-reclaim callback slots exhausted");
        kernel_core::register_timer_callback(waitqueue_timer_tick)
            .expect("waitqueue timer callback slots exhausted");
    }
}

/// 注册定时等待
///
/// M1-02: keyed by `pid` (the per-PCB `active_wait_seq` is the timer-IRQ
/// disambiguator; NO queue pointer is stored — that pointer was the SMP
/// use-after-free). The old R143-5 `queue >= 0xFFFF_FFFF_8000_0000` debug_assert is
/// DELETED: it was ineffective (the sole timed registrant, futex, is a HEAP
/// `Arc<WaitQueue>` whose address IS in the high-half range, so the assert never
/// fired) and was release-stripped anyway.
///
/// INVARIANT VII: at most ONE in-flight timed wait per PCB — a suspended PID is
/// blocked in exactly one `wait_with_timeout`, and futex (`futex.rs:203`) is the
/// ONLY `ipc::sync::WaitQueue` timed producer. Dedup/replace by `pid` alone is
/// therefore exact. A future SECOND timed-wait producer for an already-timed-waiting
/// PID would need a richer key here (it would otherwise silently drop one timer — a
/// missed timeout, NOT a UAF).
/// 取消定时等待 (M1-02: keyed by `pid`, one in-flight timed wait per PCB)
fn cancel_timed_wait_exact(pid: ProcessId, seq: u64) {
    let mut waits = TIMED_WAITERS.lock();
    waits.retain_capacity(|w| w.pid != pid || w.seq != seq);
}

/// Maximum number of timeouts to process per tick (prevents allocation in IRQ context)
const MAX_TIMEOUTS_PER_TICK: usize = 16;

/// M4-1c: rotating scan cursor for `drain_expired_timeouts`.
///
/// Round-robin starting offset so that under sustained timeout-wake contention
/// the same front-of-`TIMED_WAITERS` entries are not re-tried every tick while
/// later expired waiters starve. This preserves the fairness the old
/// remove-then-repush-to-tail had (Codex requirement-align A2), without the
/// IRQ-context `Vec::push`. Accessed ONLY under the `TIMED_WAITERS` lock (Phase 1),
/// so plain `Relaxed` is sound (the lock orders it). Kept bounded < 2*len by the
/// `% len` on load and the `start + examined` store (both < len each).
static WQ_TIMEOUT_SCAN_CURSOR: AtomicUsize = AtomicUsize::new(0);

/// M4-1c: pure, testable core of the WaitQueue timeout drain (copy-don't-remove).
///
/// # Codex Review Fix (M4-1b) + M4-1c CLOSURE
///
/// Uses fixed-size stack arrays (`expired` / `woke`) instead of a per-tick Vec to
/// bound IRQ work; `MAX_TIMEOUTS_PER_TICK` caps timeouts per tick (excess is caught
/// the next tick). M4-1c closes the last IRQ heap residual: the former Phase-3
/// retry `waits.push(*w)` could grow-REALLOC `TIMED_WAITERS: Vec` under the global
/// heap lock in the timer IRQ (R151-5 alloc-in-IRQ). The drain now COPIES expired
/// entries (no removal) in Phase 1, wakes them in Phase 2, and removes ONLY the
/// completed ones by exact `(pid, seq)` via `Vec::retain` in Phase 3.
/// The timer-IRQ path therefore performs NO `Vec::push` and NO dealloc —
/// `Vec::retain`/`Vec::remove` never shrink capacity (std guarantee) and
/// `TimedWaiter` is `Copy`. The only Vec growth is the process-context
/// `register_timed_wait` push.
///
/// `wake(tw) -> true` means the waiter completed (woken / stale / process-gone) and
/// must be removed; `false` means defer (proc-lock / PROCESS_TABLE contention) — the
/// entry is left in place and re-evaluated next tick (deadline still <= now).
///
/// # Lock order (LOAD-BEARING)
///
/// `TIMED_WAITERS` MUST be DROPPED across the `wake` call. M1-02: the wake
/// (`wq_timeout_wake_by_seq`) now takes ONLY the proc lock — it NEVER touches
/// `WaitQueue.waiters`, so the timer path can no longer form the
/// `self.waiters <-> TIMED_WAITERS` ABBA at all (the structural win). The drop is
/// still required because the process-context wake/cancel paths nest
/// `WaitQueue.waiters -> TIMED_WAITERS` (`wake_one`/`wake_all`/`wake_n`/`cancel_wait`
/// hold `self.waiters` across `cancel_timed_wait`, which takes `TIMED_WAITERS`):
/// holding `TIMED_WAITERS` across `wake` while another CPU holds `self.waiters` and
/// reaches for `TIMED_WAITERS` would still invert that order. Phase 1 scopes the
/// lock to the copy block and releases BEFORE Phase 2; Phase 3 re-acquires ALONE and
/// its `retain` closure touches ONLY the Vec — never `WaitQueue.waiters` / `proc`.
fn drain_expired_timeouts(
    waits: &Mutex<AdmittedDeque<TimedWaiter>>,
    cursor: &AtomicUsize,
    now_ticks: u64,
    mut wake: impl FnMut(&TimedWaiter) -> bool,
) -> bool {
    // Phase 1: COPY up to MAX expired entries (rotating start), no removal.
    let mut expired: [Option<TimedWaiter>; MAX_TIMEOUTS_PER_TICK] = [None; MAX_TIMEOUTS_PER_TICK];
    let count = {
        let waits = waits.lock();
        let len = waits.len();
        if len == 0 {
            return false;
        }
        let start = cursor.load(Ordering::Relaxed) % len;
        let mut n = 0;
        let mut examined = 0;
        while examined < len && n < MAX_TIMEOUTS_PER_TICK {
            let waiter = waits[(start + examined) % len];
            examined += 1;
            if waiter.deadline_tick <= now_ticks {
                expired[n] = Some(waiter);
                n += 1;
            }
        }
        // Advance the cursor past the examined window so the next tick continues the
        // round-robin sweep (bounded latency for every waiter even under contention).
        cursor.store(start + examined, Ordering::Relaxed);
        n
    };

    // Phase 2: wake each expired waiter WITHOUT holding TIMED_WAITERS; record the
    // completed ones (woke_count <= count <= MAX, so the stack array never overflows).
    let mut woke: [Option<TimedWaiter>; MAX_TIMEOUTS_PER_TICK] = [None; MAX_TIMEOUTS_PER_TICK];
    let mut woke_count = 0;
    for waiter in expired.iter().take(count).flatten() {
        if wake(waiter) {
            woke[woke_count] = Some(*waiter);
            woke_count += 1;
        }
    }

    // Phase 3: remove the completed waiters by EXACT (pid, seq). `seq` is globally
    // unique per wait, so a concurrent process-context `register_timed_wait` for a
    // NEW wait of the same PID pushes a NEW seq (replace-semantics) that this retain
    // never drops. `Vec::retain` never reallocs/deallocs (capacity untouched), so
    // this stays alloc-free in IRQ.
    if woke_count > 0 {
        let done = &woke[..woke_count];
        let mut waits = waits.lock();
        waits.retain_capacity(|tw| {
            !done
                .iter()
                .flatten()
                .any(|d| d.pid == tw.pid && d.seq == tw.seq)
        });
        waits.is_empty()
    } else {
        false
    }
}

fn process_waitqueue_timeouts(now_ticks: u64) {
    // M1-02: the wake closure NO LONGER dereferences any WaitQueue — it wakes purely
    // by per-PCB state (`process::wq_timeout_wake_by_seq`), so the timer IRQ can never
    // touch a freed WaitQueue (the SMP use-after-free this fix closes). `seq` selects
    // THE exact pending wait; `generation` is carried into the per-PCB marker for the
    // epilogue's exact-gen consume.
    let needs_reclaim = drain_expired_timeouts(
        &TIMED_WAITERS,
        &WQ_TIMEOUT_SCAN_CURSOR,
        now_ticks,
        |waiter| process::wq_timeout_wake_by_seq(waiter.pid, waiter.seq, waiter.generation),
    );
    if needs_reclaim {
        // RF180-42: the IRQ path only detaches logical entries and raises a
        // level-triggered process-context request. The callback performs the
        // allocator free and exact admission release with IF=1 and irq_count=0.
        kernel_core::request_soft_progress_from_irq();
    }
}

/// M4-1c self-test: the WaitQueue timeout drain core (copy-don't-remove + rotating
/// cursor + exact-(pid,seq) retain). Drives a LOCAL `Vec` + cursor with
/// a test-controlled fake `wake` — NEVER the global `TIMED_WAITERS` static. Catches
/// the mis-wires a green build/boot cannot: an IRQ `Vec` realloc, a dropped fresh
/// re-registered wait, a missed/over-cap timeout, and lost round-robin fairness.
pub fn run_wq_timeout_drain_self_test() {
    use core::cell::Cell;
    mm::publish_heap_budgets();

    fn registry_with_capacity(capacity: usize) -> Mutex<AdmittedDeque<TimedWaiter>> {
        let mut waits = AdmittedDeque::new(HeapClass::Futex);
        waits
            .try_reserve_exact(capacity)
            .expect("RF180-42 timed-wait test backing");
        Mutex::new(waits)
    }
    // M1-02: q1/q2 are now distinct `seq` values (the queue pointer is gone). The
    // fake `wake` stays a pure `FnMut(&TimedWaiter) -> bool`, now FAITHFUL to
    // production (`wq_timeout_wake_by_seq` is also a pure per-PCB callback with no
    // queue deref).
    let q1: u64 = 0x1000;
    let q2: u64 = 0x2000;
    let mk = |seq: u64, pid: ProcessId, generation: u64, deadline_tick: u64| TimedWaiter {
        pid,
        deadline_tick,
        seq,
        generation,
    };

    // (1) NO-REALLOC AT IRQ HIGH-WATER: fill to MAX live entries, force every wake to
    // FAIL (full retry path), assert capacity unchanged. The ONLY assertion that
    // proves the former IRQ Vec::push realloc is gone.
    {
        let waits = registry_with_capacity(MAX_TIMEOUTS_PER_TICK);
        for i in 0..MAX_TIMEOUTS_PER_TICK {
            waits
                .lock()
                .push_back_reserved(mk(q1, i, i as u64, 1))
                .expect("preallocated timeout slot");
        }
        let cap0 = waits.lock().capacity();
        let cur = AtomicUsize::new(0);
        drain_expired_timeouts(&waits, &cur, 100, |_| false); // all contended
        assert!(
            waits.lock().capacity() == cap0,
            "M4-1c: TIMED_WAITERS realloc'd in the IRQ drain path"
        );
        assert!(
            waits.lock().len() == MAX_TIMEOUTS_PER_TICK,
            "M4-1c: contended waiters must be retained (defer-not-drop)"
        );
    }

    // (2) RETRY-PRESERVES-MEMBERSHIP: a failed wake leaves the entry with its
    // ORIGINAL generation + deadline.
    {
        let waits = registry_with_capacity(1);
        waits
            .lock()
            .push_back_reserved(mk(q1, 7, 5, 10))
            .expect("preallocated timeout slot");
        let cur = AtomicUsize::new(0);
        drain_expired_timeouts(&waits, &cur, 100, |_| false);
        let v = waits.lock();
        assert!(
            v.len() == 1 && v[0].generation == 5 && v[0].deadline_tick == 10,
            "M4-1c: contended retry must preserve the original entry"
        );
    }

    // (3) EXACT-SEQ RETRY (headline): a concurrent re-register during the wake
    // replaces the PID's entry with a NEW seq; Phase 3 (keyed by pid+seq) must remove
    // ONLY the completed original seq and NOT drop the fresh re-registered wait.
    {
        let waits = registry_with_capacity(1);
        waits
            .lock()
            .push_back_reserved(mk(q1, 7, 5, 10))
            .expect("preallocated timeout slot"); // seq=q1, pid=7, gen=5
        let cur = AtomicUsize::new(0);
        drain_expired_timeouts(&waits, &cur, 100, |w| {
            // Simulate register_timed_wait replace-semantics (retain-by-pid + push a
            // NEW seq) racing between the Phase-1 copy and the Phase-3 retain.
            let mut v = waits.lock();
            v.retain_capacity(|t| t.pid != w.pid);
            v.push_back_reserved(TimedWaiter {
                pid: w.pid,
                deadline_tick: 999,
                seq: 9999, // a fresh, distinct seq for the re-registered wait
                generation: 7,
            })
            .expect("retained timeout capacity");
            true // the original (seq=q1) wake completes
        });
        let v = waits.lock();
        assert!(
            v.iter()
                .any(|t| t.pid == 7 && t.seq == 9999 && t.generation == 7),
            "M1-02: fresh re-registered (new seq) wait must survive the drain"
        );
        assert!(
            !v.iter().any(|t| t.seq == q1),
            "M1-02: the completed original-seq entry must be removed (retain by pid+seq)"
        );
    }

    // (4) CAP HONORED + REMAINDER SURVIVES: MAX+3 expired, all wake succeed; one tick
    // removes exactly MAX, 3 remain (caught next tick).
    {
        let waits = registry_with_capacity(MAX_TIMEOUTS_PER_TICK + 3);
        for i in 0..(MAX_TIMEOUTS_PER_TICK + 3) {
            waits
                .lock()
                .push_back_reserved(mk(q1, i, i as u64, 1))
                .expect("preallocated timeout slot");
        }
        let cur = AtomicUsize::new(0);
        let woke = Cell::new(0usize);
        drain_expired_timeouts(&waits, &cur, 100, |_| {
            woke.set(woke.get() + 1);
            true
        });
        assert!(
            woke.get() == MAX_TIMEOUTS_PER_TICK,
            "M4-1c: must cap wakes per tick at MAX_TIMEOUTS_PER_TICK"
        );
        assert!(
            waits.lock().len() == 3,
            "M4-1c: the over-cap expired remainder must survive for the next tick"
        );
    }

    // (5) NON-EXPIRED UNTOUCHED: a future-deadline entry is neither woken nor removed.
    {
        let waits = registry_with_capacity(2);
        waits
            .lock()
            .push_back_reserved(mk(q1, 1, 1, 1))
            .expect("preallocated timeout slot"); // expired
        waits
            .lock()
            .push_back_reserved(mk(q2, 2, 2, 1_000))
            .expect("preallocated timeout slot"); // future
        let cur = AtomicUsize::new(0);
        let woke = Cell::new(0usize);
        drain_expired_timeouts(&waits, &cur, 100, |_| {
            woke.set(woke.get() + 1);
            true
        });
        let v = waits.lock();
        assert!(woke.get() == 1, "M4-1c: only the expired entry should wake");
        assert!(
            v.len() == 1 && v[0].pid == 2,
            "M4-1c: the future-deadline entry must remain"
        );
    }

    // (6) ROUND-ROBIN FAIRNESS: MAX+4 expired, all-contended; over ceil(n/MAX) ticks
    // the rotating cursor examines EVERY entry (no permanent front starvation).
    {
        let total = MAX_TIMEOUTS_PER_TICK + 4;
        let waits = registry_with_capacity(total);
        for i in 0..total {
            waits
                .lock()
                .push_back_reserved(mk(q1, i, i as u64, 1))
                .expect("preallocated timeout slot");
        }
        let cur = AtomicUsize::new(0);
        let seen = Cell::new(0u64); // bitmask of examined pids (total < 64)
        for _ in 0..2 {
            drain_expired_timeouts(&waits, &cur, 100, |w| {
                seen.set(seen.get() | (1u64 << w.pid));
                false // all contended -> nothing removed, Vec stable across ticks
            });
        }
        let full = (1u64 << total) - 1;
        assert!(
            seen.get() == full,
            "M4-1c: the rotating cursor must examine every waiter within ceil(n/MAX) ticks"
        );
    }
}

/// P2-B: pure structural self-test for the under-lock recheck-before-publish
/// contract that closes the futex compare/enqueue lost-wake class.
///
/// Drives a LOCAL WaitQueue only. Proves:
/// (1) a failing recheck never Arms a ticket and leaves the queue empty;
/// (2) a passing recheck (with a current process) Arms and publishes one waiter;
/// (3) cancel_wait undoes a published waiter.
///
/// Concurrent wake serialization is by construction (all wake_* take `waiters`
/// first). This test pins the prepare/check/publish shape a green boot cannot
/// exercise alone.
pub fn run_futex_lost_wake_prepare_self_test() {
    let q = WaitQueue::new(HeapClass::Scheduler);

    // (1) Failing recheck → never Armed; queue stays empty.
    {
        let r = q.try_prepare_with_timeout_after(None, || Err(()));
        let prepared = r.expect("empty-queue reserve must succeed");
        // Outer Result: Ok = reservation ok; inner Result: Ok(PrepareWait) or Err(check).
        match prepared {
            Ok(PrepareWait::Armed(_)) => {
                panic!("P2-B: failing recheck (or no-process path) must not Arm")
            }
            Ok(PrepareWait::Immediate(_)) => {
                // No current process / closed — still not Armed.
            }
            Err(()) => {
                // check ran under waiters lock and rejected — the closed shape.
            }
        }
        assert!(
            q.is_empty(),
            "P2-B: non-Arm prepare path must leave waiters empty"
        );
    }

    // (2) Passing recheck with a current process → Armed + published; cancel undoes.
    if process::current_pid().is_some() {
        let r = q
            .try_prepare_with_timeout_after(None, || Ok(()))
            .expect("reserve must not fail");
        match r {
            Ok(PrepareWait::Armed(_ticket)) => {
                assert!(
                    !q.is_empty(),
                    "P2-B: successful recheck must publish a waiter"
                );
                assert!(
                    q.cancel_wait(),
                    "P2-B: cancel_wait must remove the published waiter"
                );
                assert!(
                    q.is_empty(),
                    "P2-B: after cancel_wait the queue must be empty"
                );
            }
            Ok(PrepareWait::Immediate(WaitOutcome::Interrupted))
            | Ok(PrepareWait::Immediate(WaitOutcome::Closed))
            | Ok(PrepareWait::Immediate(WaitOutcome::NoProcess)) => {
                // Benign races (pending kill/signal).
            }
            Ok(PrepareWait::Immediate(other)) => {
                panic!("P2-B: unexpected Immediate outcome: {:?}", other)
            }
            Err(()) => {
                panic!("P2-B: passing check must not return Err")
            }
        }
    }
}

/// P3-A: pure structural self-test for process-generation identity on wake.
///
/// Proves the tag helpers and that a process-stamped entry whose generation
/// does not match would be refused by the wake gate (logic only — no real PCB
/// table mutations beyond helpers).
pub fn run_process_gen_stamp_self_test() {
    let g = 42u64;
    let stamped = stamp_process_generation(g);
    assert!(is_process_generation_stamp(stamped));
    assert_eq!(unstamp_process_generation(stamped), g);
    assert!(!is_process_generation_stamp(7)); // plain queue gen
    assert!(!is_process_generation_stamp(0));
    // Tag bit must not collide with unstamped value for normal generations
    // (NEXT_GENERATION is far below 2^63).
    assert_ne!(stamped, g);
    // Mismatch simulation: stamped for gen 42, live gen 99 → refuse.
    let live = 99u64;
    assert!(is_process_generation_stamp(stamped));
    assert_ne!(unstamp_process_generation(stamped), live);
}

/// 定时器回调：每个 tick 检查超时
fn waitqueue_timer_tick() {
    let now = kernel_core::get_ticks();
    process_waitqueue_timeouts(now);
}
