//! Read-Copy-Update (RCU) Synchronization Primitive
//!
//! RCU provides a synchronization mechanism optimized for read-mostly data
//! structures. Readers can access shared data without taking any locks,
//! while writers defer destruction until all pre-existing readers are done.
//!
//! # Architecture
//!
//! This implementation uses:
//! - Global epoch counter for grace period tracking
//! - Per-CPU reader nesting counters
//! - Per-CPU quiescent state tracking via `rcu_epoch`
//! - A fixed static callback arena and FIFO index ring (no callback heap use)
//!
//! # Grace Period Detection
//!
//! A grace period is a duration during which all CPUs have passed through
//! at least one quiescent state (a point where no RCU read-side critical
//! sections are active). When `synchronize_rcu()` returns, all pre-existing
//! readers have completed.
//!
//! # API
//!
//! ```rust,ignore
//! use kernel_core::rcu;
//!
//! // Read-side critical section
//! rcu::rcu_read_lock();
//! // Access RCU-protected data...
//! rcu::rcu_read_unlock();
//!
//! // Writer side
//! // Update RCU-protected pointer
//! // old_value = swap_pointer(...)
//! rcu::synchronize_rcu();  // Wait for all readers
//! // Safe to free old_value
//!
//! // Or reserve callback capacity before publishing a resource, then defer
//! // its allocation-free reclamation.
//! let permit = rcu::try_reserve_callback()?;
//! rcu::call_rcu(permit, reclaim_old_value, [old_value_addr, 0]);
//! ```
//!
//! # Integration Points
//!
//! - `rcu_quiescent_state()` is called from scheduler tick and context switch
//! - `poll()` drains callbacks in process context (syscall return path)

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use cpu_local::{current_cpu, current_cpu_id, online_cpu_mask, CpuLocal, PER_CPU_DATA};
use spin::Mutex;

/// Global epoch counter (monotonically increasing).
///
/// Incremented by `synchronize_rcu()` to begin a new grace period.
/// Writers waiting for readers use this to track when it's safe to proceed.
static GLOBAL_EPOCH: AtomicU64 = AtomicU64::new(1);

/// Highest grace period that has fully completed.
///
/// Updated only after all CPUs report quiescence so callbacks never run
/// ahead of an in-flight grace period. This prevents `poll()` from running
/// callbacks before `synchronize_rcu()` has verified all readers are done.
static COMPLETED_EPOCH: AtomicU64 = AtomicU64::new(1);

/// R108-4 FIX: Lock-free approximate callback count for adaptive budget.
///
/// Incremented when a reserved slot is queued and decremented after its
/// callback finishes. This avoids locking `CALLBACKS` in
/// `callback_drain_budget()` on the hot
/// syscall-return path.  The value may be slightly out of date due to
/// relaxed ordering, but that only causes a momentary under- or over-drain
/// which is harmless.
static CALLBACK_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Per-CPU reader nesting counter.
///
/// Non-zero means the CPU is in an RCU read-side critical section.
/// Nested calls are supported via reference counting.
static RCU_READERS: CpuLocal<AtomicUsize> = CpuLocal::new(|| AtomicUsize::new(0));

/// M4-1 (force-init): pre-allocate the `RCU_READERS` per-CPU slab before IRQs are
/// enabled. `on_scheduler_tick` (the timer-IRQ scheduler hook) UNCONDITIONALLY calls
/// `rcu_timer_tick() -> rcu_quiescent_state() -> RCU_READERS.with(...)` every tick;
/// without this the first AP timer IRQ would lazily heap-allocate the CpuLocal slab in
/// IRQ and deadlock on the heap lock (the R151-5 class). Call on the BSP before
/// `start_aps()`; the single global `Once` covers every CPU.
pub fn force_init_rcu_locals() {
    RCU_READERS.force_init();
}

/// R180-12 FIX: Hard bound for allocation-free deferred callbacks.
///
/// Every valid process PID has a dedicated stack slot, so RCU admission does
/// not reduce the existing 32,768-task capability. A separate 256-entry class
/// is reserved for non-stack callbacks. The arena is static (about 1.4 MiB),
/// consumes none of the 1 MiB kernel heap, and cannot grow under user pressure.
pub const RCU_STACK_CALLBACK_CAPACITY: usize = 32_768;
pub const RCU_GENERAL_CALLBACK_CAPACITY: usize = 256;
pub const RCU_CALLBACK_CAPACITY: usize =
    RCU_STACK_CALLBACK_CAPACITY + RCU_GENERAL_CALLBACK_CAPACITY;

const _: () = assert!(RCU_CALLBACK_CAPACITY > 0);
const _: () = assert!(RCU_GENERAL_CALLBACK_CAPACITY > 0);
const _: () = assert!(RCU_CALLBACK_CAPACITY <= u16::MAX as usize);

/// Backpressure returned before a resource that needs deferred reclamation is
/// allocated or published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RcuBackpressure {
    /// Every fixed callback slot is Reserved, Queued, or Running.
    CallbackPoolExhausted,
    /// The stack-resource class reached its global admission limit.
    StackCallbackLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallbackClass {
    General,
    KernelStack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallbackState {
    Free,
    Reserved,
    Queued,
    Running,
    /// A stack callback detected an invariant violation after dequeue.  The
    /// dedicated PID slot remains permanently occupied so that PID/VA reuse
    /// cannot alias a mapping or physical block whose reclamation was not
    /// proven safe.
    Quarantined,
}

#[derive(Clone, Copy)]
struct CallbackSlot {
    state: CallbackState,
    class: CallbackClass,
    target_epoch: u64,
    callback: Option<fn([usize; 2])>,
    args: [usize; 2],
}

impl CallbackSlot {
    const EMPTY: Self = Self {
        state: CallbackState::Free,
        class: CallbackClass::General,
        target_epoch: 0,
        callback: None,
        args: [0; 2],
    };
}

struct ReadyCallback {
    slot_index: usize,
    callback: fn([usize; 2]),
    args: [usize; 2],
}

/// Fixed callback arena plus a ring of slot indices in publication order.
/// All state transitions happen under `CALLBACKS`; callback code runs after
/// the mutex is released.
struct CallbackPool<const CAPACITY: usize> {
    slots: [CallbackSlot; CAPACITY],
    queue: [u16; CAPACITY],
    queue_head: usize,
    queue_len: usize,
    reserve_cursor: usize,
    stack_slots: usize,
}

impl<const CAPACITY: usize> CallbackPool<CAPACITY> {
    const fn new() -> Self {
        Self {
            slots: [CallbackSlot::EMPTY; CAPACITY],
            queue: [0; CAPACITY],
            queue_head: 0,
            queue_len: 0,
            reserve_cursor: 0,
            stack_slots: 0,
        }
    }

    fn reserve_in_range(
        &mut self,
        class: CallbackClass,
        range_start: usize,
        range_end: usize,
    ) -> Option<usize> {
        assert!(range_start < range_end && range_end <= CAPACITY);
        let range_len = range_end - range_start;
        let cursor = if (range_start..range_end).contains(&self.reserve_cursor) {
            self.reserve_cursor
        } else {
            range_start
        };
        for offset in 0..range_len {
            let index = range_start + ((cursor - range_start + offset) % range_len);
            if self.slots[index].state == CallbackState::Free {
                self.slots[index].state = CallbackState::Reserved;
                self.slots[index].class = class;
                self.reserve_cursor = range_start + ((index - range_start + 1) % range_len);
                if class == CallbackClass::KernelStack {
                    self.stack_slots += 1;
                }
                return Some(index);
            }
        }
        None
    }

    fn reserve_exact(&mut self, class: CallbackClass, index: usize) -> bool {
        if index >= CAPACITY || self.slots[index].state != CallbackState::Free {
            return false;
        }
        self.slots[index].state = CallbackState::Reserved;
        self.slots[index].class = class;
        if class == CallbackClass::KernelStack {
            self.stack_slots += 1;
        }
        true
    }

    /// Release only an unconsumed reservation. A state mismatch fails closed:
    /// a queued/running slot is never recycled by a stale permit.
    fn release_reserved(&mut self, index: usize) -> bool {
        let Some(slot) = self.slots.get(index) else {
            return false;
        };
        if slot.state != CallbackState::Reserved {
            return false;
        }
        let class = slot.class;
        self.slots[index] = CallbackSlot::EMPTY;
        if class == CallbackClass::KernelStack {
            assert!(self.stack_slots > 0, "RCU: stack slot count underflow");
            self.stack_slots -= 1;
        }
        true
    }

    fn enqueue_reserved(
        &mut self,
        index: usize,
        target_epoch: u64,
        callback: fn([usize; 2]),
        args: [usize; 2],
    ) {
        assert!(index < CAPACITY, "RCU: invalid callback permit");
        assert_eq!(
            self.slots[index].state,
            CallbackState::Reserved,
            "RCU: callback permit is not Reserved"
        );

        // A valid Reserved slot contributes to the same fixed capacity as the
        // queue, so this cannot fail unless the pool invariants are corrupt.
        assert!(self.queue_len < CAPACITY, "RCU: callback ring overflow");
        self.slots[index] = CallbackSlot {
            state: CallbackState::Queued,
            class: self.slots[index].class,
            target_epoch,
            callback: Some(callback),
            args,
        };
        let tail = (self.queue_head + self.queue_len) % CAPACITY;
        self.queue[tail] = index as u16;
        self.queue_len += 1;
    }

    fn pop_ready(&mut self, done_epoch: u64) -> Option<ReadyCallback> {
        if self.queue_len == 0 {
            return None;
        }

        let index = usize::from(self.queue[self.queue_head]);
        assert!(index < CAPACITY, "RCU: corrupt callback ring");
        let slot = &self.slots[index];
        assert_eq!(
            slot.state,
            CallbackState::Queued,
            "RCU: callback ring references a non-Queued slot"
        );
        if slot.target_epoch > done_epoch {
            return None;
        }

        self.queue_head = (self.queue_head + 1) % CAPACITY;
        self.queue_len -= 1;

        let slot = &mut self.slots[index];
        let callback = slot
            .callback
            .take()
            .expect("RCU: Queued callback slot has no function");
        let args = slot.args;
        slot.state = CallbackState::Running;
        slot.target_epoch = 0;
        slot.args = [0; 2];

        Some(ReadyCallback {
            slot_index: index,
            callback,
            args,
        })
    }

    fn finish_running(&mut self, index: usize) {
        assert!(index < CAPACITY, "RCU: invalid running slot");
        if self.slots[index].state == CallbackState::Quarantined {
            // R180-12 FIX: a failed stack reclaim must pin its PID-indexed slot
            // forever.  Releasing it here would allow the same virtual stack
            // slot to be reused while an old PTE or physical block is still
            // live.  `stack_slots` deliberately remains charged.
            return;
        }
        assert_eq!(
            self.slots[index].state,
            CallbackState::Running,
            "RCU: callback slot did not remain Running"
        );
        let class = self.slots[index].class;
        self.slots[index] = CallbackSlot::EMPTY;
        if class == CallbackClass::KernelStack {
            assert!(self.stack_slots > 0, "RCU: stack slot count underflow");
            self.stack_slots -= 1;
        }
    }

    /// Permanently pin a dequeued kernel-stack callback slot after a reclaim
    /// invariant fails.  Only `Running -> Quarantined` is accepted; a stale or
    /// wrong-class request must not mutate pool state.
    fn quarantine_running_stack(&mut self, index: usize) -> bool {
        let Some(slot) = self.slots.get_mut(index) else {
            return false;
        };
        if slot.state != CallbackState::Running || slot.class != CallbackClass::KernelStack {
            return false;
        }
        slot.state = CallbackState::Quarantined;
        slot.target_epoch = 0;
        slot.callback = None;
        slot.args = [0; 2];
        true
    }

    fn is_pristine(&self) -> bool {
        self.queue_len == 0
            && self.stack_slots == 0
            && self
                .slots
                .iter()
                .all(|slot| slot.state == CallbackState::Free)
    }
}

/// R180-12 FIX: Static callback storage; no operation on this pool allocates.
static CALLBACKS: Mutex<CallbackPool<RCU_CALLBACK_CAPACITY>> = Mutex::new(CallbackPool::new());

/// Proof that one callback slot was admitted before a resource was allocated.
///
/// This type is deliberately non-`Clone`. Dropping an unconsumed permit returns
/// only its Reserved slot; consuming it in `call_rcu` disarms `Drop` after the
/// slot has transitioned to Queued.
#[derive(Debug)]
#[must_use = "dropping the permit cancels the RCU callback reservation"]
pub struct RcuCallbackPermit {
    slot_index: usize,
    armed: bool,
}

impl Drop for RcuCallbackPermit {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        let released = CALLBACKS.lock().release_reserved(self.slot_index);
        assert!(released, "RCU: armed permit did not own a Reserved slot");
    }
}

/// Reserve callback capacity without allocating.
///
/// Callers that publish resources requiring deferred destruction must obtain
/// this permit first and propagate backpressure if the fixed pool is full.
pub fn try_reserve_callback() -> Result<RcuCallbackPermit, RcuBackpressure> {
    let mut callbacks = CALLBACKS.lock();
    callbacks
        .reserve_in_range(
            CallbackClass::General,
            RCU_STACK_CALLBACK_CAPACITY,
            RCU_CALLBACK_CAPACITY,
        )
        .map(|slot_index| RcuCallbackPermit {
            slot_index,
            armed: true,
        })
        .ok_or(RcuBackpressure::CallbackPoolExhausted)
}

/// Reserve one callback slot for a kernel-stack resource.
///
/// `pid` maps directly to its dedicated slot. Stack admission therefore covers
/// the complete valid PID range while remaining disjoint from general slots.
pub(crate) fn try_reserve_stack_callback(pid: usize) -> Result<RcuCallbackPermit, RcuBackpressure> {
    if pid == 0 || pid > RCU_STACK_CALLBACK_CAPACITY {
        return Err(RcuBackpressure::StackCallbackLimit);
    }
    let mut callbacks = CALLBACKS.lock();
    let slot_index = pid - 1;
    if !callbacks.reserve_exact(CallbackClass::KernelStack, slot_index) {
        return Err(RcuBackpressure::StackCallbackLimit);
    }
    Ok(RcuCallbackPermit {
        slot_index,
        armed: true,
    })
}

/// R109-2 FIX: Single-consumer drain serialization to preserve FIFO ordering.
///
/// Without serialization, multiple concurrent drainers (`poll()` on different
/// CPUs + `synchronize_rcu()`) could pop A then B but execute B first while the
/// A drainer is descheduled. This flag ensures only one drainer is active at
/// a time.  `poll()` callers yield immediately if another drain is in progress
/// (non-blocking); `synchronize_rcu()` spins briefly to acquire ownership.
static DRAIN_OWNER: AtomicBool = AtomicBool::new(false);

/// RAII guard for drain ownership.  Releases ownership on drop.
struct DrainOwnerGuard;

impl DrainOwnerGuard {
    /// Try to acquire drain ownership (non-blocking).
    /// Returns `Some(Self)` on success, `None` if another drainer is active.
    #[inline]
    fn try_acquire() -> Option<Self> {
        DRAIN_OWNER
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self)
    }

    /// Acquire drain ownership, spinning until available.
    /// Used by `synchronize_rcu()` which must drain all completed callbacks.
    #[inline]
    fn acquire_spin() -> Self {
        loop {
            if let Some(guard) = Self::try_acquire() {
                return guard;
            }
            core::hint::spin_loop();
        }
    }
}

impl Drop for DrainOwnerGuard {
    #[inline]
    fn drop(&mut self) {
        DRAIN_OWNER.store(false, Ordering::Release);
    }
}

/// Maximum number of callbacks to drain per `poll()` invocation.
///
/// This prevents a ready callback backlog from monopolizing the CPU.
/// R108-4 FIX: Used as the baseline budget; actual budget scales with backlog.
const CALLBACK_DRAIN_BUDGET_LOW: usize = 16;

/// R108-4 FIX: Callback backlog thresholds and scaled drain budgets.
///
/// When callback backlog grows (e.g., rapid process churn deferring kernel stack
/// frees via `call_rcu()`), `poll()` increases its drain budget to release
/// fixed-pool capacity before producers encounter backpressure.
///
/// | Backlog | Budget | Rationale |
/// |---------|--------|-----------|
/// | < 256   | 16     | Normal: minimal syscall-return overhead |
/// | < 1024  | 64     | Medium: backlog building, drain faster |
/// | >= 1024 | 256    | High: free admitted capacity promptly |
const CALLBACK_BACKLOG_MEDIUM: usize = 256;
const CALLBACK_BACKLOG_HIGH: usize = 1024;
const CALLBACK_DRAIN_BUDGET_MEDIUM: usize = 64;
const CALLBACK_DRAIN_BUDGET_HIGH: usize = 256;

/// R72: One-time guard for timer registration.
///
/// Ensures the RCU timer callback is only registered once even if
/// init_rcu_timer() is called multiple times.
static RCU_TIMER_REGISTERED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Read-Side API
// ============================================================================

/// Disable preemption and return a stable CPU ID.
///
/// This helper ensures that the CPU ID sampled at the start is still valid
/// after preemption is disabled. Under eventual preemption/migration support,
/// a task could migrate between reading the LAPIC ID and disabling preemption.
/// The retry loop detects this race and re-pins to the new CPU.
///
/// # Returns
///
/// The CPU ID that preemption was disabled on. Caller MUST use this ID for
/// all subsequent per-CPU state access within the critical section.
#[inline]
fn rcu_preempt_disable_stable_cpu() -> usize {
    loop {
        let cpu_id = current_cpu_id();

        // Narrow the race window: if we were already migrated after sampling
        // cpu_id, retry without touching the stale CPU's preemption counter.
        if current_cpu_id() != cpu_id {
            core::hint::spin_loop();
            continue;
        }

        let per_cpu = PER_CPU_DATA
            .get_cpu(cpu_id)
            .unwrap_or_else(|| panic!("RCU: missing per-CPU slot for CPU {}", cpu_id));

        per_cpu.preempt_disable();

        // Compiler fence prevents reordering of the CPU ID read across the
        // preemption disable boundary. This is critical: without it, the
        // compiler could hoist per-CPU accesses above preempt_disable().
        core::sync::atomic::compiler_fence(Ordering::SeqCst);

        if current_cpu_id() == cpu_id {
            return cpu_id;
        }

        // Migration detected between sampling cpu_id and disabling preemption.
        // Undo the preempt_disable on the (now stale) CPU and retry.
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        per_cpu.preempt_enable();
        core::hint::spin_loop();
    }
}

/// Enter an RCU read-side critical section.
///
/// This must be paired with a call to `rcu_read_unlock()`. Nested calls
/// are allowed (reference counted).
///
/// # Performance
///
/// This is very cheap: just an atomic increment. No locks, no memory barriers
/// that would stall the pipeline.
///
/// # Note
///
/// Read-side critical sections should be short. Don't sleep, block, or
/// do anything that could cause a context switch while in an RCU read-side
/// critical section.
///
/// # P2-7 Migration Safety
///
/// Uses `rcu_preempt_disable_stable_cpu()` to bind both preemption disable
/// and reader counter increment to the same CPU ID, preventing counter
/// mismatch under eventual preemption/migration support.
#[inline]
pub fn rcu_read_lock() {
    // Disable preemption and bind reader accounting to a stable CPU slot.
    let cpu_id = rcu_preempt_disable_stable_cpu();
    RCU_READERS
        .with_cpu(cpu_id, |counter| {
            counter.fetch_add(1, Ordering::Acquire); // lint-fetch-add: allow (per-CPU depth counter)
        })
        .expect("RCU: cpu_id out of range for RCU_READERS");
}

/// Exit an RCU read-side critical section.
///
/// Must be called once for each call to `rcu_read_lock()`.
///
/// When the reader count drops to zero, this CPU's quiescent state is
/// updated to allow pending grace periods to complete.
///
/// # P2-7 Migration Safety
///
/// Preemption is still disabled from `rcu_read_lock()`, so the CPU ID is
/// stable. All per-CPU accesses use explicit `cpu_id` rather than implicit
/// `current_cpu()` to prevent any window for counter mismatch.
#[inline]
pub fn rcu_read_unlock() {
    // Preemption is still disabled from rcu_read_lock(), so CPU ID is stable.
    let cpu_id = current_cpu_id();
    let per_cpu = PER_CPU_DATA
        .get_cpu(cpu_id)
        .unwrap_or_else(|| panic!("RCU: missing per-CPU slot for CPU {}", cpu_id));

    let remaining = RCU_READERS
        .with_cpu(cpu_id, |counter| {
            let old = counter.fetch_sub(1, Ordering::Release);
            if old == 0 {
                // Underflow - caller bug
                panic!("RCU: rcu_read_unlock called without matching rcu_read_lock");
            }
            old - 1
        })
        .expect("RCU: cpu_id out of range for RCU_READERS");

    // If all readers on this CPU are done, mark quiescent state
    if remaining == 0 {
        // R71-2 FIX: Use Acquire to synchronize with SeqCst increment in synchronize_rcu().
        // This ensures we see the latest epoch value and don't store a stale epoch
        // that could cause synchronize_rcu() to block indefinitely.
        let epoch = GLOBAL_EPOCH.load(Ordering::Acquire);
        per_cpu.rcu_epoch.store(epoch, Ordering::Release);
    }

    // Compiler fence ensures all per-CPU operations complete before re-enabling.
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    per_cpu.preempt_enable();
}

/// Check if the current CPU is in an RCU read-side critical section.
#[inline]
pub fn rcu_read_lock_held() -> bool {
    RCU_READERS.with(|counter| counter.load(Ordering::Relaxed) > 0)
}

// ============================================================================
// Quiescent State API
// ============================================================================

/// Mark that this CPU has passed through a quiescent state.
///
/// A quiescent state is a point where no RCU read-side critical sections
/// are active on this CPU. This should be called from:
/// - Scheduler tick (when not in an RCU read-side section)
/// - Context switch
/// - Idle loop
///
/// This function is cheap when already quiescent (just a store).
#[inline]
pub fn rcu_quiescent_state() {
    // Only update if not currently in a read-side critical section
    let readers = RCU_READERS.with(|counter| counter.load(Ordering::Relaxed));
    if readers == 0 {
        // R71-2 FIX: Use Acquire ordering to synchronize with SeqCst increment
        // in synchronize_rcu(). This prevents storing a stale epoch value that
        // could cause grace period detection to fail.
        let epoch = GLOBAL_EPOCH.load(Ordering::Acquire);
        current_cpu().rcu_epoch.store(epoch, Ordering::Release);
    }
}

/// Force a quiescent state on this CPU.
///
/// This is used when we know we're not in an RCU read-side critical section
/// and want to expedite grace period completion. Unlike `rcu_quiescent_state()`,
/// this doesn't check the reader count - caller must ensure it's zero.
///
/// # Safety
///
/// Caller must ensure no RCU read-side critical section is active on this CPU.
///
/// # R72-3 FIX: Memory Ordering
///
/// Uses `Ordering::Acquire` to synchronize with the `Ordering::SeqCst` increment
/// in `synchronize_rcu()`. This ensures we never store a stale epoch value that
/// would cause grace period detection to stall indefinitely. A CPU that stores
/// an old epoch and then halts (e.g., during shutdown) would otherwise block
/// all future grace periods since `all_cpus_quiescent()` would never see it
/// reach the target epoch.
#[inline]
pub unsafe fn rcu_quiescent_state_force() {
    // R72-3 FIX: Use Acquire ordering to pair with SeqCst increment in synchronize_rcu().
    // This prevents storing a stale epoch that would stall grace periods.
    let epoch = GLOBAL_EPOCH.load(Ordering::Acquire);
    current_cpu().rcu_epoch.store(epoch, Ordering::Release);
}

// ============================================================================
// Writer-Side API
// ============================================================================

/// Atomically allocate the next epoch without ever wrapping the counter.
///
/// Returning `None` leaves `counter` unchanged at `u64::MAX`.  Keeping the
/// primitive parameterized lets the boot self-test exercise the exhaustion
/// boundary without perturbing the production epoch.
fn try_allocate_epoch(counter: &AtomicU64) -> Option<u64> {
    loop {
        let current = counter.load(Ordering::Acquire);
        let next = current.checked_add(1)?;
        match counter.compare_exchange(current, next, Ordering::SeqCst, Ordering::Acquire) {
            Ok(_) => return Some(next),
            Err(_) => core::hint::spin_loop(),
        }
    }
}

#[inline]
fn allocate_epoch_or_panic() -> u64 {
    try_allocate_epoch(&GLOBAL_EPOCH)
        .unwrap_or_else(|| panic!("RCU: global epoch exhausted; refusing to wrap"))
}

/// Wait until all pre-existing RCU readers have completed.
///
/// This function blocks (busy-waits) until a full grace period has elapsed.
/// After it returns, any reader that was in an RCU read-side critical section
/// when this function was called has now exited that section.
///
/// # Usage
///
/// Typically used after updating an RCU-protected pointer to wait before
/// freeing the old data:
///
/// ```rust,ignore
/// // Swap in the new data
/// let old = RCU_DATA.swap(new, Ordering::Release);
///
/// // Wait for all readers of old data to finish
/// synchronize_rcu();
///
/// // Now safe to free old data
/// drop(old);
/// ```
///
/// # Note
///
/// This function busy-waits and should not be called from interrupt context.
/// For non-blocking operation, use `call_rcu()` instead.
pub fn synchronize_rcu() {
    // R180-12 FIX: use the same checked CAS allocator as asynchronous
    // callbacks.  `fetch_add` mutates before overflow can be detected; at
    // u64::MAX that wrapped GLOBAL_EPOCH while COMPLETED_EPOCH remained high,
    // making later callbacks appear prematurely complete.  Exhaustion now
    // fails stop without changing the counter.
    let target = allocate_epoch_or_panic();

    // Mark our own CPU as quiescent (we're not in a read-side section here)
    rcu_quiescent_state();

    // Wait until all CPUs have passed through a quiescent state
    // at or after the target epoch
    while !all_cpus_quiescent(target) {
        core::hint::spin_loop();
    }

    // Publish completion BEFORE running callbacks so concurrent pollers
    // cannot race ahead and see callbacks as ready before the grace period
    // ends. `fetch_max` prevents a slower concurrent synchronizer from
    // regressing the highest completed epoch after a later one finishes.
    let completed = COMPLETED_EPOCH
        .fetch_max(target, Ordering::AcqRel)
        .max(target);

    // Drain any callbacks that are now safe to run.
    // R108-4 FIX: Writers expect `synchronize_rcu()` to leave no completed
    // callbacks behind, so drain without a budget limit.
    //
    // R109-2 FIX: Acquire exclusive drain ownership before draining to
    // preserve FIFO ordering.  synchronize_rcu() must guarantee all
    // completed callbacks are drained, so spin until ownership is acquired.
    let _drain_owner = DrainOwnerGuard::acquire_spin();
    drain_callbacks_inner(completed, usize::MAX);
}

/// Queue a previously admitted callback to run after a new grace period.
///
/// The callback will be invoked in process context after all pre-existing
/// RCU readers have completed. Both the callback function and its two machine-
/// word arguments fit directly in the fixed slot, so enqueue cannot allocate
/// or fail after the caller has published the resource.
///
/// # Example
///
/// ```rust,ignore
/// fn reclaim(args: [usize; 2]) {
///     // Reconstruct and reclaim the retired object from args[0].
/// }
/// let permit = try_reserve_callback()?;
/// let old = RCU_DATA.swap(new, Ordering::Release);
/// call_rcu(permit, reclaim, [old as usize, 0]);
/// ```
///
/// # Note
///
/// The callback runs in process context from `reschedule_if_needed()`.
/// It must not sleep or take locks that could cause deadlock.
///
/// # Epoch Ordering
///
/// Every callback advances `GLOBAL_EPOCH` itself rather than sampling the two
/// independent global/completed atomics and piggybacking on a possibly stale
/// epoch. This guarantees the callback's target was initiated after the
/// caller's retirement operation. Fixed class capacities also bound the extra
/// epochs and the work needed to catch up.
pub fn call_rcu(permit: RcuCallbackPermit, callback: fn([usize; 2]), args: [usize; 2]) {
    call_rcu_class(permit, CallbackClass::General, callback, args);
}

/// Consume the dedicated permit for `pid` and enqueue its stack callback.
/// Class and PID binding are checked before publication so a generic or
/// different PID's permit can never authorize stack destruction.
pub(crate) fn call_rcu_stack(
    permit: RcuCallbackPermit,
    pid: usize,
    callback: fn([usize; 2]),
    args: [usize; 2],
) {
    assert!(pid > 0 && pid <= RCU_STACK_CALLBACK_CAPACITY);
    assert_eq!(
        permit.slot_index,
        pid - 1,
        "RCU: stack permit does not belong to PID"
    );
    call_rcu_class(permit, CallbackClass::KernelStack, callback, args);
}

/// Pin the currently running PID-indexed stack callback after reclamation
/// cannot be proven safe.
///
/// The callback has already left the FIFO, so ordinary callback completion
/// would otherwise recycle its slot.  Quarantining preserves the stack
/// admission charge and makes every future reservation for this PID fail
/// closed.  Failure to perform the transition is itself fatal: returning from
/// the callback would reopen PID/virtual-address reuse.
pub(crate) fn quarantine_running_stack_callback(pid: usize) {
    let index = pid
        .checked_sub(1)
        .filter(|index| *index < RCU_STACK_CALLBACK_CAPACITY)
        .unwrap_or_else(|| panic!("RCU: invalid PID for stack quarantine"));
    let quarantined = CALLBACKS.lock().quarantine_running_stack(index);
    assert!(
        quarantined,
        "RCU: failed to quarantine the running kernel-stack callback"
    );
}

fn call_rcu_class(
    mut permit: RcuCallbackPermit,
    expected_class: CallbackClass,
    callback: fn([usize; 2]),
    args: [usize; 2],
) {
    // Serialize target assignment with FIFO publication. This keeps target
    // epochs monotonic in ring order and makes a ready prefix sufficient.
    let mut callbacks = CALLBACKS.lock();
    assert!(permit.slot_index < RCU_CALLBACK_CAPACITY);
    assert_eq!(
        callbacks.slots[permit.slot_index].class, expected_class,
        "RCU: callback permit class mismatch"
    );
    let target = allocate_epoch_or_panic();

    callbacks.enqueue_reserved(permit.slot_index, target, callback, args);
    CALLBACK_COUNT.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (bounded statistics counter)
    permit.armed = false;
}

/// Poll for and run any callbacks whose grace period has completed.
///
/// This should be called from process context (e.g., syscall return path)
/// to drain pending callbacks. It's non-blocking and runs an adaptive
/// number of callbacks per invocation (see R108-4 FIX below).
///
/// # Safety
///
/// Only drains callbacks whose target epoch is <= COMPLETED_EPOCH,
/// ensuring we never run callbacks before their grace period has
/// actually finished (which would cause use-after-free).
///
/// # R71-1 FIX (Part 2): Grace Period Completion
///
/// Before draining callbacks, this function checks if any pending grace
/// periods can be completed. If `GLOBAL_EPOCH > COMPLETED_EPOCH` and all
/// CPUs have passed through a quiescent state, we advance `COMPLETED_EPOCH`.
/// This ensures `call_rcu()` callbacks make forward progress even without
/// explicit `synchronize_rcu()` calls.
///
/// # R108-4 FIX: Adaptive Drain Budget
///
/// Uses an adaptive drain budget based on callback backlog depth.  Under
/// normal load (backlog < 256), drains at most 16 callbacks per invocation.
/// At 1,024 pending callbacks the budget scales to 256 per poll.
///
/// # Returns
///
/// The number of callbacks that were executed.
pub fn poll() -> usize {
    // R71-1 FIX (Part 2): Try to complete any pending grace periods.
    // This is the key addition that makes call_rcu() actually work without
    // synchronize_rcu() - we check if grace periods can complete on each poll.
    try_advance_completed_epoch();

    // Only drain callbacks whose grace period has actually finished.
    // Using COMPLETED_EPOCH (not GLOBAL_EPOCH) prevents racing ahead
    // of an in-progress synchronize_rcu().
    let completed_epoch = COMPLETED_EPOCH.load(Ordering::Acquire);
    let budget = callback_drain_budget();
    drain_callbacks(completed_epoch, budget)
}

/// Get the current global RCU epoch (for debugging).
pub fn current_epoch() -> u64 {
    GLOBAL_EPOCH.load(Ordering::Relaxed)
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Try to advance `COMPLETED_EPOCH` to the highest epoch every online CPU has
/// already crossed.
///
/// R180-12 FIX: the old implementation walked every integer epoch between the
/// completed and global counters.  A wave of admitted callbacks therefore made
/// one timer interrupt perform tens of thousands of epoch-by-CPU checks.  RCU
/// epochs are monotonic, so the safe frontier is simply the minimum published
/// per-CPU quiescent epoch, clamped to `GLOBAL_EPOCH`.  One O(CPU) scan advances
/// across an arbitrary callback wave.
fn try_advance_completed_epoch() {
    let global = GLOBAL_EPOCH.load(Ordering::Acquire);
    let safe = highest_quiescent_epoch(global);
    COMPLETED_EPOCH.fetch_max(safe, Ordering::AcqRel);
}

/// Return the highest epoch known safe on every CPU in `online_cpu_mask()`.
///
/// A CPU only publishes `rcu_epoch` while it has no pre-existing readers.  A
/// later reader may coexist with an older target: if `target <= rcu_epoch`, that
/// reader began after the recorded quiescent state and cannot protect retired
/// data from that target.  Consequently the minimum published epoch is the
/// exact monotonic completion frontier; no per-epoch loop or reader-count scan
/// is necessary.
fn highest_quiescent_epoch(global: u64) -> u64 {
    let mut online = online_cpu_mask();
    if online == 0 {
        online = 1; // Early BSP-only fallback.
    }

    let mut safe = global;
    while online != 0 {
        let cpu_id = online.trailing_zeros() as usize;
        online &= online - 1;
        let Some(per_cpu) = PER_CPU_DATA.get_cpu(cpu_id) else {
            // An online bit without initialized per-CPU state is inconsistent.
            // Refuse to advance rather than guessing that the CPU is quiescent.
            return COMPLETED_EPOCH.load(Ordering::Acquire).min(global);
        };
        safe = safe.min(per_cpu.rcu_epoch.load(Ordering::Acquire));
    }
    safe
}

/// Check if all CPUs have reached a quiescent state at or after the target epoch.
///
/// # Important
///
/// Only checks online CPUs (via `online_cpu_mask()`), not all `max_cpus()` slots.
/// Uninitialized CPU slots have `rcu_epoch == 0` which would cause deadlock
/// if we waited for them. We must use `.max(1)` to handle the BSP-only case
/// before any APs have come online.
fn all_cpus_quiescent(target: u64) -> bool {
    highest_quiescent_epoch(GLOBAL_EPOCH.load(Ordering::Acquire)) >= target
}

/// R108-4 FIX: Compute the callback drain budget for `poll()`.
///
/// Uses the lock-free `CALLBACK_COUNT` atomic to determine queue depth and
/// selects a drain budget via coarse thresholds.  This keeps the hot
/// syscall-return path free of `CALLBACKS` lock acquisitions when there are
/// no callbacks to drain (the common case).
#[inline]
fn callback_drain_budget() -> usize {
    let backlog = CALLBACK_COUNT.load(Ordering::Relaxed);
    if backlog >= CALLBACK_BACKLOG_HIGH {
        CALLBACK_DRAIN_BUDGET_HIGH
    } else if backlog >= CALLBACK_BACKLOG_MEDIUM {
        CALLBACK_DRAIN_BUDGET_MEDIUM
    } else {
        CALLBACK_DRAIN_BUDGET_LOW
    }
}

/// Drain callbacks whose grace period has completed.
///
/// # R108-4 FIX: Parameterized drain budget
///
/// `max_callbacks` bounds the amount of work per invocation.  `poll()` passes
/// an adaptive budget based on backlog depth; `synchronize_rcu()` passes
/// `usize::MAX` to drain all completed callbacks before returning.
///
/// # R109-2 FIX: Single-consumer serialization
///
/// Only one drainer can be active at a time to preserve FIFO ordering.
/// `poll()` callers yield immediately if another drain is in progress.
/// `synchronize_rcu()` uses `DrainOwnerGuard::acquire_spin()` directly
/// and calls `drain_callbacks_inner()` to guarantee completion.
///
/// Returns the number of callbacks executed.
fn drain_callbacks(done_epoch: u64, max_callbacks: usize) -> usize {
    // R109-2 FIX: Try to acquire exclusive drain ownership.
    // If another drainer is active, return immediately to avoid FIFO violations.
    let _drain_owner = match DrainOwnerGuard::try_acquire() {
        Some(guard) => guard,
        None => return 0,
    };

    drain_callbacks_inner(done_epoch, max_callbacks)
}

/// Inner drain loop, called with drain ownership already held.
///
/// # Reentrancy Warning
///
/// Callbacks execute with `DRAIN_OWNER` held but without `CALLBACKS` held, so
/// they may reserve and enqueue a later callback. A reentrant `poll()` simply
/// observes the busy owner and drains nothing. A callback must not call
/// `synchronize_rcu()`, which would spin forever trying to reacquire its own
/// drain ownership; this matches the usual kernel RCU callback constraint.
fn drain_callbacks_inner(done_epoch: u64, max_callbacks: usize) -> usize {
    let mut count = 0;

    while count < max_callbacks {
        // Queued -> Running under the pool lock, then execute outside it. A
        // callback may reserve/enqueue another callback reentrantly; that new
        // entry lands at the ring tail and targets a later epoch.
        let Some(ready) = CALLBACKS.lock().pop_ready(done_epoch) else {
            break;
        };

        (ready.callback)(ready.args);

        CALLBACKS.lock().finish_running(ready.slot_index);
        let previous = CALLBACK_COUNT.fetch_sub(1, Ordering::Relaxed);
        assert!(previous > 0, "RCU: callback count underflow");
        count += 1;
    }

    count
}

/// Get the number of pending callbacks (for debugging/monitoring).
///
/// Reserved slots and the one callback that may currently be Running are not
/// included; this is the exact FIFO depth at the instant the pool lock is held.
pub fn pending_callbacks() -> usize {
    CALLBACKS.lock().queue_len
}

fn rcu_callback_self_test_noop(_args: [usize; 2]) {}

/// Boot-callable fixed-pool invariant test.
///
/// Uses a six-slot local const-generic pool, so it is safe even after producers
/// start and does not place the 1.4 MiB production arena on the 16 KiB kernel
/// stack. Covers class capacity exhaustion, Reserved cancellation (the same
/// primitive used by permit `Drop`), double-release refusal, physical ring
/// wrap, epoch readiness, FIFO, and Queued -> Running -> Free balance.
pub fn run_rcu_callback_pool_self_test() {
    const TEST_CAPACITY: usize = 6;
    const TEST_STACK_END: usize = 2;
    let mut pool = CallbackPool::<TEST_CAPACITY>::new();

    assert!(pool.reserve_exact(CallbackClass::KernelStack, 0));
    assert!(
        !pool.reserve_exact(CallbackClass::KernelStack, 0),
        "RCU self-test reused an occupied PID-indexed slot"
    );
    assert!(pool.reserve_exact(CallbackClass::KernelStack, 1));
    let stack_a = 0;
    let stack_b = 1;
    assert!(
        pool.reserve_in_range(CallbackClass::KernelStack, 0, TEST_STACK_END)
            .is_none(),
        "RCU self-test stack class exceeded its partition"
    );

    let mut general = [0usize; TEST_CAPACITY - TEST_STACK_END];
    for slot in &mut general {
        *slot = pool
            .reserve_in_range(CallbackClass::General, TEST_STACK_END, TEST_CAPACITY)
            .expect("RCU self-test general reservation");
    }
    assert!(
        pool.reserve_in_range(CallbackClass::General, TEST_STACK_END, TEST_CAPACITY)
            .is_none(),
        "RCU self-test general class exceeded its partition"
    );
    assert_eq!(pool.stack_slots, 2);
    assert!(pool.release_reserved(stack_a));
    assert!(
        !pool.release_reserved(stack_a),
        "RCU double release accepted"
    );
    assert_eq!(pool.stack_slots, 1);
    assert!(pool.reserve_exact(CallbackClass::KernelStack, stack_a));
    assert!(pool.release_reserved(stack_a));
    assert!(pool.release_reserved(stack_b));
    for slot in general {
        assert!(pool.release_reserved(slot));
    }
    assert!(pool.is_pristine());

    // Start at the final physical ring element, then enqueue three entries at
    // positions 5, 0, and 1. Slots themselves come from the full local range.
    pool.queue_head = TEST_CAPACITY - 1;
    let mut queued_slots = [0usize; 3];
    for (sequence, slot_index) in queued_slots.iter_mut().enumerate() {
        let slot = pool
            .reserve_in_range(CallbackClass::General, 0, TEST_CAPACITY)
            .expect("RCU self-test FIFO reserve");
        pool.enqueue_reserved(
            slot,
            10 + sequence as u64,
            rcu_callback_self_test_noop,
            [sequence, 0x5243_5531],
        );
        *slot_index = slot;
    }
    assert_eq!(pool.queue_len, 3);
    assert!(!pool.release_reserved(queued_slots[0]));
    assert!(pool.pop_ready(9).is_none(), "RCU ran before target epoch");

    let first = pool.pop_ready(10).expect("RCU self-test first ready");
    assert_eq!(first.args, [0, 0x5243_5531]);
    assert_eq!(pool.slots[first.slot_index].state, CallbackState::Running);
    assert!(!pool.release_reserved(first.slot_index));
    pool.finish_running(first.slot_index);
    assert!(pool.pop_ready(10).is_none(), "RCU skipped epoch ordering");

    for expected in 1..3 {
        let ready = pool.pop_ready(12).expect("RCU self-test FIFO ready");
        assert_eq!(ready.args, [expected, 0x5243_5531]);
        pool.finish_running(ready.slot_index);
    }
    assert!(pool.is_pristine(), "RCU self-test did not balance pool");

    // A failed stack reclaim is a permanent fail-closed admission pin.  The
    // normal drain epilogue must not recycle the quarantined PID slot.
    assert!(pool.reserve_exact(CallbackClass::KernelStack, 0));
    pool.enqueue_reserved(0, 20, rcu_callback_self_test_noop, [1, 0]);
    let quarantined = pool
        .pop_ready(20)
        .expect("RCU self-test quarantined callback ready");
    assert!(pool.quarantine_running_stack(quarantined.slot_index));
    pool.finish_running(quarantined.slot_index);
    assert_eq!(pool.slots[0].state, CallbackState::Quarantined);
    assert_eq!(pool.stack_slots, 1);
    assert!(
        !pool.reserve_exact(CallbackClass::KernelStack, 0),
        "RCU self-test recycled a quarantined PID slot"
    );

    // Epoch exhaustion must never mutate through u64::MAX.  Exercise a local
    // atomic so the production epoch remains untouched.
    let epoch = AtomicU64::new(u64::MAX - 1);
    assert_eq!(try_allocate_epoch(&epoch), Some(u64::MAX));
    assert_eq!(try_allocate_epoch(&epoch), None);
    assert_eq!(
        epoch.load(Ordering::Acquire),
        u64::MAX,
        "RCU epoch allocator wrapped or mutated on exhaustion"
    );
}

// ============================================================================
// RAII Guard for Read-Side Critical Sections
// ============================================================================

/// RAII guard for RCU read-side critical sections.
///
/// Automatically calls `rcu_read_unlock()` when dropped.
///
/// # Example
///
/// ```rust,ignore
/// fn read_data() -> Data {
///     let _guard = RcuReadGuard::new();
///     // Data is protected while guard is held
///     RCU_DATA.load(Ordering::Acquire).clone()
/// }
/// ```
pub struct RcuReadGuard(());

impl RcuReadGuard {
    /// Enter an RCU read-side critical section.
    #[inline]
    pub fn new() -> Self {
        rcu_read_lock();
        Self(())
    }
}

impl Default for RcuReadGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RcuReadGuard {
    #[inline]
    fn drop(&mut self) {
        rcu_read_unlock();
    }
}

// Safety: RcuReadGuard is !Send because dropping it on a different CPU than
// where it was created would corrupt the per-CPU reader count.
impl !Send for RcuReadGuard {}

// ============================================================================
// R72: Timer-Driven Grace Period Advancement
// ============================================================================

/// Initialize RCU timer integration.
///
/// Registers a timer callback to periodically advance grace periods on idle
/// CPUs. This ensures callbacks make forward progress even when no explicit
/// `synchronize_rcu()` calls are made.
///
/// # Safety
///
/// Safe to call multiple times; registration only happens once.
///
/// # Note
///
/// This is already integrated via scheduler_hook::on_scheduler_tick() which
/// calls rcu_quiescent_state(). This function provides an additional explicit
/// registration point if needed.
pub fn init_rcu_timer() {
    if RCU_TIMER_REGISTERED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
        .is_ok()
    {
        // The timer callback is already registered in scheduler_hook::on_scheduler_tick()
        // which calls rcu_quiescent_state(). No additional registration needed.
        // This function serves as an explicit initialization point if needed.
    }
}

/// R72: Timer-driven hook to keep grace periods moving.
///
/// Called from timer interrupt context to:
/// 1. Mark quiescent state (if not in RCU read section)
/// 2. Attempt to advance COMPLETED_EPOCH if all CPUs are quiescent
///
/// This ensures callbacks make forward progress even on idle CPUs that
/// aren't actively calling poll().
///
/// # Note
///
/// This is already called via scheduler_hook::on_scheduler_tick() which
/// invokes rcu_quiescent_state(). For additional timer-driven epoch
/// advancement, this function can be called from other timer contexts.
#[inline]
pub fn rcu_timer_tick() {
    // Mark quiescent state (if not in RCU read section)
    rcu_quiescent_state();

    // Try to advance COMPLETED_EPOCH toward GLOBAL_EPOCH
    // This allows callbacks to make progress without explicit poll() calls
    try_advance_completed_epoch();
}
