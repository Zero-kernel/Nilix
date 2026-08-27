//! Minimal per-CPU storage for SMP support
//!
//! Provides a bounded per-CPU storage abstraction indexed by logical CPU IDs.
//! Early bootstrap retains a narrow CPU-0 fallback, but normal SMP operation
//! resolves registered LAPIC identities and fails closed for unknown topology.
//! Topology-sensitive users should use the strict registered-and-online APIs.
//!
//! # Usage
//!
//! ```rust,ignore
//! use cpu_local::CpuLocal;
//! use core::sync::atomic::AtomicUsize;
//!
//! static MY_DATA: CpuLocal<AtomicUsize> = CpuLocal::new(|| AtomicUsize::new(0));
//!
//! MY_DATA.with(|d| d.fetch_add(1, Ordering::SeqCst));
//! ```

#![no_std]

#[cfg(all(feature = "host_harness", target_os = "none"))]
compile_error!(
    "cpu_local/host_harness is test-only and must never be enabled for a bare-metal kernel build"
);

extern crate alloc;

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, Once};

/// Maximum number of CPUs supported
pub const MAX_CPUS: usize = 64;

// The online-CPU topology is represented by one u64. Keep the capacity and
// its bitmap representation coupled at compile time so a future capacity bump
// cannot turn a shift below into undefined topology admission.
const _: () = assert!(MAX_CPUS <= u64::BITS as usize);

/// Invalid LAPIC ID marker
const INVALID_LAPIC_ID: u32 = u32::MAX;

/// Invalid CPU ID marker for reverse mapping
const INVALID_CPU_ID: usize = usize::MAX;

/// Size of LAPIC ID reverse mapping table (covers all 8-bit LAPIC IDs)
const LAPIC_ID_REVERSE_MAP_SIZE: usize = 256;

/// Architected xAPIC MMIO base address (Intel SDM reset default).
///
/// R169-L7 FIX: the single named source for the LAPIC MMIO base. The kernel runs
/// the local APIC in xAPIC mode at this base, and the identity-map hardening
/// carve-out preserves exactly this page, so `current_cpu_id()` and `arch::apic`
/// must agree on it. `arch::apic::LAPIC_DEFAULT_BASE` and `arch::ipi::LAPIC_BASE`
/// are derived from this constant rather than re-declaring the literal.
pub const LAPIC_MMIO_DEFAULT_BASE: u32 = 0xFEE0_0000;

/// R151-6 FIX: Flag set when SMP bring-up is complete.
///
/// After this point, `current_cpu_id()` must not silently fall back to CPU 0
/// because doing so aliases per-CPU slots and corrupts TLB shootdown mailboxes,
/// IRQ nesting counters, FPU save areas, and scheduler state.
static CPU_LOCAL_SMP_DONE: AtomicBool = AtomicBool::new(false);

/// Global NMI nesting depth used by no-allocation asynchronous-context gates.
///
/// This is intentionally global rather than CPU-local: an NMI can arrive
/// before the heap-backed `CpuLocal` storage is initialized, when consulting a
/// per-CPU slot would itself be unsafe. Best-effort facilities conservatively
/// drop work on every CPU while any NMI is active; that trades a negligible
/// sampling gap for an early-boot-safe, allocation-free fail-closed policy.
static NMI_CONTEXT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Mark SMP initialization complete for the cpu_local subsystem.
///
/// Called by arch SMP bring-up code once all CPU registrations are finished.
/// After this call, `current_cpu_id()` will panic instead of returning 0 for
/// unregistered LAPIC IDs.
#[inline]
pub fn set_smp_init_done() {
    CPU_LOCAL_SMP_DONE.store(true, Ordering::Release);
}

/// Enter an NMI context without consulting heap-backed CPU-local storage.
///
/// The architecture entry stub calls this before any work that may reach an
/// allocator, lock, or KCOV tracepoint. Nested NMIs are supported.
#[inline]
pub fn nmi_enter() {
    NMI_CONTEXT_COUNT
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            count.checked_add(1)
        })
        .expect("NMI nesting counter overflow");
}

/// Leave an NMI context entered through [`nmi_enter`].
#[inline]
pub fn nmi_exit() {
    let result = NMI_CONTEXT_COUNT.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
        count.checked_sub(1)
    });
    assert!(result.is_ok(), "nmi_exit called with count already 0");
}

/// Return whether any CPU is currently executing an NMI handler.
///
/// This global answer deliberately makes best-effort tracing conservative on
/// another CPU as well, which is necessary before per-CPU storage exists.
#[inline]
pub fn nmi_active() -> bool {
    NMI_CONTEXT_COUNT.load(Ordering::Acquire) > 0
}

/// Authoritative LAPIC MMIO base shared by `current_cpu_id()` and `arch::apic`.
///
/// R169-L7 FIX: single runtime source of truth for the LAPIC MMIO base. Both the
/// per-CPU-id lookup in `current_cpu_id()` and `arch::apic::{lapic_read,
/// lapic_write}` read this one atomic, replacing the three previously-duplicated
/// hard-coded `0xFEE0_0000` copies (the old `apic::LAPIC_BASE` static, the
/// `current_cpu_id()` literal, and the dead `ipi::LAPIC_BASE` const). `arch::apic`
/// is the sole publisher — it validates the base against IA32_APIC_BASE at LAPIC
/// init — so the value is never out of sync with the hardware or the consumers.
static LAPIC_MMIO_BASE: AtomicU32 = AtomicU32::new(LAPIC_MMIO_DEFAULT_BASE);

/// True once the platform is operating the local APIC in x2APIC mode.
///
/// R169-L7 FIX: in x2APIC mode the APIC ID is delivered via an MSR, can exceed
/// 8 bits (overflowing the 256-entry `LAPIC_ID_REVERSE_MAP`), and the xAPIC MMIO
/// ID register is invalid. `current_cpu_id()` fails closed when this is set rather
/// than read a bogus ID and alias another CPU's per-CPU slot. Published by
/// `arch::apic` at LAPIC init; the current kernel never enables x2APIC.
static X2APIC_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Read the authoritative LAPIC MMIO base (see [`LAPIC_MMIO_BASE`]).
#[inline]
pub fn lapic_mmio_base() -> u32 {
    LAPIC_MMIO_BASE.load(Ordering::Acquire)
}

/// Publish the LAPIC MMIO base. Called by `arch::apic` at LAPIC init.
///
/// # Panics
///
/// Panics if `base` is not 4 KiB aligned (a malformed APIC base would desync the
/// register reads from the page tables).
#[inline]
pub fn set_lapic_mmio_base(base: u32) {
    assert_eq!(
        base & 0xFFF,
        0,
        "LAPIC MMIO base {:#x} must be 4 KiB aligned",
        base
    );
    LAPIC_MMIO_BASE.store(base, Ordering::Release);
}

/// Report whether the local APIC is operating in x2APIC mode.
#[inline]
pub fn x2apic_active() -> bool {
    X2APIC_ACTIVE.load(Ordering::Acquire)
}

/// Publish the x2APIC-mode flag. Called by `arch::apic` at LAPIC init.
#[inline]
pub fn set_x2apic_active(active: bool) {
    X2APIC_ACTIVE.store(active, Ordering::Release);
}

/// Marker for "no FPU owner" in per-CPU lazy FPU tracking
pub const NO_FPU_OWNER: usize = usize::MAX;

/// LAPIC ID to CPU index mapping table.
///
/// Index = CPU logical index, Value = hardware LAPIC ID.
/// Used by `current_cpu_id()` to map LAPIC ID to CPU index.
#[allow(clippy::declare_interior_mutable_const)]
static LAPIC_ID_MAP: [AtomicU32; MAX_CPUS] = {
    const INIT: AtomicU32 = AtomicU32::new(0xFFFF_FFFF);
    [INIT; MAX_CPUS]
};

/// R67-8 FIX: Reverse mapping for O(1) LAPIC ID to CPU index lookup.
///
/// Index = hardware LAPIC ID (0..255), Value = CPU logical index.
/// This enables fast CPU ID lookup in syscall entry without linear search.
#[allow(clippy::declare_interior_mutable_const)]
static LAPIC_ID_REVERSE_MAP: [AtomicUsize; LAPIC_ID_REVERSE_MAP_SIZE] = {
    const INIT: AtomicUsize = AtomicUsize::new(usize::MAX);
    [INIT; LAPIC_ID_REVERSE_MAP_SIZE]
};

/// Serializes LAPIC-ID registration so the forward and reverse maps remain a
/// bijection while AP topology is being admitted. Registration runs only
/// during BSP/AP bring-up, before ordinary interrupt traffic begins.
static CPU_ID_REGISTRATION_LOCK: Mutex<()> = Mutex::new(());

// ============================================================================
// Per-CPU Data Structure for SMP Support (Phase E)
// ============================================================================

/// Raw task pointer used to avoid circular dependencies with the scheduler.
pub type RawTaskPtr = *mut ();

/// Depth of the per-CPU TLB shootdown queue.
///
/// This allows batching multiple TLB shootdown requests without
/// serializing on a single slot. A depth of 4 is sufficient for
/// most workloads while keeping memory overhead low.
pub const TLB_SHOOTDOWN_QUEUE_LEN: usize = 4;

/// A single TLB shootdown request stored in the per-CPU queue.
///
/// Each entry represents a pending TLB invalidation request that
/// the IPI handler will process in FIFO order.
#[repr(C)]
pub struct TlbShootdownEntry {
    /// Request generation (0 = empty/processed slot)
    pub generation: AtomicU64,
    /// Target CR3 (0 means flush regardless of CR3)
    pub cr3: AtomicU64,
    /// Page-aligned virtual start address (0 for full flush)
    pub start: AtomicU64,
    /// Length in bytes, page-aligned (0 for full flush)
    pub len: AtomicU64,
}

impl TlbShootdownEntry {
    pub const fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            cr3: AtomicU64::new(0),
            start: AtomicU64::new(0),
            len: AtomicU64::new(0),
        }
    }
}

impl Default for TlbShootdownEntry {
    fn default() -> Self {
        Self::new()
    }
}

// Manual Clone impl since AtomicU64 doesn't implement Clone
impl Clone for TlbShootdownEntry {
    fn clone(&self) -> Self {
        Self {
            generation: AtomicU64::new(self.generation.load(Ordering::Relaxed)),
            cr3: AtomicU64::new(self.cr3.load(Ordering::Relaxed)),
            start: AtomicU64::new(self.start.load(Ordering::Relaxed)),
            len: AtomicU64::new(self.len.load(Ordering::Relaxed)),
        }
    }
}

/// Per-CPU mailbox for TLB shootdown IPIs (small FIFO queue).
///
/// # R72: Queue-Based Design
///
/// Instead of a single-slot mailbox that requires serialization before posting,
/// this uses a bounded ring buffer (depth 4) allowing multiple requests to be
/// queued. This reduces contention and IPI overhead for high-frequency shootdowns.
///
/// # Memory Ordering
///
/// - Requester: writes entry fields Relaxed, then publishes entry.generation with Release,
///   then updates request_gen with Release
/// - Handler: loads entry.generation with Acquire, reads fields Relaxed, acks via ack_gen Release,
///   then clears entry.generation with Release and advances head
/// - Waiter: loads ack_gen with Acquire to ensure flush completion is visible
#[repr(C)]
pub struct TlbShootdownMailbox {
    /// Monotonic generation number for the most recent request (for compat/fast path)
    pub request_gen: AtomicU64,
    /// Last generation this CPU has processed
    pub ack_gen: AtomicU64,
    /// Queue head (next entry to consume), wraps via modulo
    pub head: AtomicU64,
    /// Queue tail (next slot to publish), wraps via modulo
    pub tail: AtomicU64,
    /// Fixed-size ring buffer of pending shootdown requests
    pub entries: [TlbShootdownEntry; TLB_SHOOTDOWN_QUEUE_LEN],
}

impl TlbShootdownMailbox {
    pub const fn new() -> Self {
        Self {
            request_gen: AtomicU64::new(0),
            ack_gen: AtomicU64::new(0),
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            entries: [
                TlbShootdownEntry::new(),
                TlbShootdownEntry::new(),
                TlbShootdownEntry::new(),
                TlbShootdownEntry::new(),
            ],
        }
    }
}

impl Default for TlbShootdownMailbox {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-CPU data required for SMP operation.
///
/// This structure contains all per-CPU metadata needed by the scheduler,
/// interrupt handlers, and RCU subsystem. All fields use atomics for
/// safe access from interrupt handlers and cross-CPU visibility.
///
/// # Memory Layout
///
/// Fields are ordered to minimize padding and optimize cache line usage.
/// The structure is designed to fit within a single cache line (64 bytes)
/// for the core fields.
#[repr(C)]
pub struct PerCpuData {
    /// Logical CPU index in the OS scheduler (0-based)
    pub cpu_id: AtomicUsize,
    /// Local APIC ID read from hardware
    pub lapic_id: AtomicU32,
    /// Preemption disable nesting counter (non-zero = preemption disabled)
    pub preempt_count: AtomicU32,
    /// Interrupt disable nesting counter
    pub irq_count: AtomicU32,
    /// True while a bounded callback drain runs on the IRQ-return path.
    ///
    /// IRQ return temporarily enables IF after `irq_exit()` so deferred work
    /// can use its process-context locks.  It is still not an ordinary task
    /// execution point: KCOV must not attribute callback tracepoints to the
    /// interrupted task.  Keeping this bit in already-initialized per-CPU
    /// storage avoids a lazy allocation in the very path it protects.
    pub soft_progress_active: AtomicBool,
    /// Last task (PID) that owns the FPU on this CPU (NO_FPU_OWNER if none).
    ///
    /// Used for lazy FPU save/restore: when a #NM exception fires, we save
    /// the previous owner's state before restoring the new owner's state.
    pub fpu_owner: AtomicUsize,
    /// Set by scheduler/interrupts to trigger a reschedule
    pub need_resched: AtomicBool,
    /// Padding for alignment
    _pad: [u8; 3],
    /// Currently running task (raw pointer to avoid scheduler dependency)
    pub current_task: AtomicPtr<()>,
    /// Top of the privilege 0 kernel stack
    pub kernel_stack_top: AtomicUsize,
    /// Top of the interrupt stack (IST1)
    pub irq_stack_top: AtomicUsize,
    /// Top of the syscall entry stack
    pub syscall_stack_top: AtomicUsize,
    /// Epoch counter for RCU/quiescent state tracking
    pub rcu_epoch: AtomicU64,
    /// Per-CPU TLB shootdown mailbox for cross-CPU invalidation
    pub tlb_mailbox: TlbShootdownMailbox,
    // ---- KPTI per-CPU context (H.3) ----
    /// Seqlock sequence counter for KPTI context consistency.
    /// Even = no write in progress; odd = write in progress.
    pub kpti_seq: AtomicU64,
    /// KPTI user-mode CR3 value for this CPU's current process.
    pub kpti_user_cr3: AtomicU64,
    /// KPTI kernel-mode CR3 value for this CPU's current process.
    pub kpti_kernel_cr3: AtomicU64,
    /// KPTI PCID value for this CPU's current process.
    pub kpti_pcid: AtomicU64,
}

// Safety: PerCpuData uses only atomics, so it's Send+Sync
unsafe impl Send for PerCpuData {}
unsafe impl Sync for PerCpuData {}

impl Default for PerCpuData {
    fn default() -> Self {
        Self::new()
    }
}

impl PerCpuData {
    /// Construct a zeroed per-CPU record.
    pub const fn new() -> Self {
        Self {
            cpu_id: AtomicUsize::new(0),
            lapic_id: AtomicU32::new(0),
            preempt_count: AtomicU32::new(0),
            irq_count: AtomicU32::new(0),
            soft_progress_active: AtomicBool::new(false),
            fpu_owner: AtomicUsize::new(NO_FPU_OWNER),
            need_resched: AtomicBool::new(false),
            _pad: [0; 3],
            current_task: AtomicPtr::new(null_mut()),
            kernel_stack_top: AtomicUsize::new(0),
            irq_stack_top: AtomicUsize::new(0),
            syscall_stack_top: AtomicUsize::new(0),
            rcu_epoch: AtomicU64::new(0),
            tlb_mailbox: TlbShootdownMailbox::new(),
            kpti_seq: AtomicU64::new(0),
            kpti_user_cr3: AtomicU64::new(0),
            kpti_kernel_cr3: AtomicU64::new(0),
            kpti_pcid: AtomicU64::new(0),
        }
    }

    /// Initialize this CPU slot with identity and stack metadata.
    ///
    /// # Arguments
    ///
    /// * `cpu_id` - Logical CPU index (0 = BSP, 1+ = APs)
    /// * `lapic_id` - Hardware Local APIC ID
    /// * `kernel_stack_top` - Top of kernel privilege stack
    /// * `irq_stack_top` - Top of interrupt stack (IST1)
    /// * `syscall_stack_top` - Top of syscall entry stack
    pub fn init(
        &self,
        cpu_id: usize,
        lapic_id: u32,
        kernel_stack_top: usize,
        irq_stack_top: usize,
        syscall_stack_top: usize,
    ) {
        self.cpu_id.store(cpu_id, Ordering::Relaxed);
        self.lapic_id.store(lapic_id, Ordering::Relaxed);
        self.current_task.store(null_mut(), Ordering::Relaxed);
        self.need_resched.store(false, Ordering::Relaxed);
        self.kernel_stack_top
            .store(kernel_stack_top, Ordering::Relaxed);
        self.irq_stack_top.store(irq_stack_top, Ordering::Relaxed);
        self.syscall_stack_top
            .store(syscall_stack_top, Ordering::Relaxed);
        self.preempt_count.store(0, Ordering::Relaxed);
        self.irq_count.store(0, Ordering::Relaxed);
        self.soft_progress_active.store(false, Ordering::Relaxed);
        self.fpu_owner.store(NO_FPU_OWNER, Ordering::Relaxed);
        self.rcu_epoch.store(0, Ordering::Relaxed);
    }

    /// Disable preemption on this CPU.
    ///
    /// Returns the new preemption count. Preemption is disabled when count > 0.
    #[inline]
    pub fn preempt_disable(&self) -> u32 {
        self.preempt_count.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Enable preemption on this CPU.
    ///
    /// Returns the new preemption count. Panics if count would go negative.
    #[inline]
    pub fn preempt_enable(&self) -> u32 {
        let old = self.preempt_count.fetch_sub(1, Ordering::Relaxed);
        assert!(old > 0, "preempt_enable called with count already 0");
        old - 1
    }

    /// Check if preemption is enabled on this CPU.
    #[inline]
    pub fn preemptible(&self) -> bool {
        self.preempt_count.load(Ordering::Relaxed) == 0
            && self.irq_count.load(Ordering::Relaxed) == 0
    }

    /// Enter an IRQ handler context.
    #[inline]
    pub fn irq_enter(&self) {
        self.irq_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Exit an IRQ handler context.
    #[inline]
    pub fn irq_exit(&self) {
        let old = self.irq_count.fetch_sub(1, Ordering::Relaxed);
        assert!(old > 0, "irq_exit called with count already 0");
    }

    /// Check if we're currently in an IRQ handler.
    #[inline]
    pub fn in_irq(&self) -> bool {
        self.irq_count.load(Ordering::Relaxed) > 0
    }

    /// Return whether this CPU is executing the bounded IRQ-return soft drain.
    #[inline]
    pub fn in_soft_progress(&self) -> bool {
        self.soft_progress_active.load(Ordering::Acquire)
    }

    /// Enter the IRQ-return soft-progress context exactly once.
    ///
    /// The guard is non-blocking and allocation-free.  A nested attempt is
    /// rejected so a callback cannot recursively re-enter the drain while its
    /// caller's task attribution is still ambiguous.
    #[inline]
    pub fn try_enter_soft_progress(&'static self) -> Option<SoftProgressGuard> {
        self.soft_progress_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(SoftProgressGuard { per_cpu: self })
    }

    /// Mark that a reschedule is needed on this CPU.
    #[inline]
    pub fn set_need_resched(&self) {
        self.need_resched.store(true, Ordering::Release);
    }

    /// Clear and return the need_resched flag.
    #[inline]
    pub fn clear_need_resched(&self) -> bool {
        self.need_resched.swap(false, Ordering::AcqRel)
    }

    /// Get the current task pointer.
    #[inline]
    pub fn get_current_task(&self) -> RawTaskPtr {
        self.current_task.load(Ordering::Acquire)
    }

    /// Set the current task pointer.
    ///
    /// # Safety
    ///
    /// Caller must ensure the task pointer is valid for the duration it's set.
    #[inline]
    pub unsafe fn set_current_task(&self, task: RawTaskPtr) {
        self.current_task.store(task, Ordering::Release);
    }

    /// Get the FPU owner (PID) on this CPU.
    ///
    /// Returns NO_FPU_OWNER if no process owns the FPU state on this CPU.
    #[inline]
    pub fn get_fpu_owner(&self) -> usize {
        self.fpu_owner.load(Ordering::Acquire)
    }

    /// Set the FPU owner on this CPU.
    ///
    /// Called by the #NM handler after restoring a process's FPU state.
    #[inline]
    pub fn set_fpu_owner(&self, pid: usize) {
        self.fpu_owner.store(pid, Ordering::Release);
    }

    /// Clear the FPU owner if it matches the given PID.
    ///
    /// Called when a process exits to prevent #NM from trying to save
    /// state to freed memory. Uses compare-exchange to handle races.
    ///
    /// # Returns
    ///
    /// `true` if the owner was cleared, `false` if it was already different.
    #[inline]
    pub fn clear_fpu_owner_if(&self, pid: usize) -> bool {
        self.fpu_owner
            .compare_exchange(pid, NO_FPU_OWNER, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    /// Access this CPU's TLB shootdown mailbox.
    ///
    /// Used by both the requesting CPU (to set up shootdown request) and
    /// the IPI handler (to read request and write ACK).
    #[inline]
    pub fn tlb_mailbox(&self) -> &TlbShootdownMailbox {
        &self.tlb_mailbox
    }
}

/// Per-CPU storage wrapper
///
/// Stores one instance of T per CPU, lazily initialized on first access.
/// Safe to use from interrupt context as long as T's operations are safe.
///
/// R91-2 FIX: Slots are heap-allocated via `Box<[MaybeUninit<T>]>` to avoid
/// placing `[MaybeUninit<T>; MAX_CPUS]` on the stack during `call_once`.
/// For large per-CPU types like `SampleRing` (~41KB), the previous stack-based
/// approach would allocate ~2.6MB on the stack (64 * 41KB), causing a
/// deterministic stack overflow on first access.
pub struct CpuLocal<T> {
    /// Initialization function for each CPU's slot
    init: fn() -> T,
    /// Per-CPU slots, heap-allocated and initialized lazily via Once
    slots: Once<UnsafeCell<Box<[MaybeUninit<T>]>>>,
}

// Safety: CpuLocal is Send+Sync because each CPU only accesses its own slot
unsafe impl<T: Send> Send for CpuLocal<T> {}
unsafe impl<T: Send + Sync> Sync for CpuLocal<T> {}

impl<T> CpuLocal<T> {
    /// Create a new per-CPU storage with the given initializer
    ///
    /// The initializer is called once per CPU slot on first access.
    pub const fn new(init: fn() -> T) -> Self {
        Self {
            init,
            slots: Once::new(),
        }
    }

    /// Get or initialize the slots array.
    ///
    /// R91-2 FIX: Allocates on the heap instead of the stack to prevent
    /// stack overflow for large per-CPU types (e.g., SampleRing ~41KB * 64 CPUs).
    fn get_slots(&self) -> &UnsafeCell<Box<[MaybeUninit<T>]>> {
        self.slots.call_once(|| {
            // Heap-allocate the slot array. Box::new_uninit_slice creates the
            // allocation directly on the heap without an intermediate stack copy.
            let mut arr = Box::new_uninit_slice(MAX_CPUS);
            for slot in arr.iter_mut() {
                slot.write((self.init)());
            }
            UnsafeCell::new(arr)
        })
    }

    /// Force-initialize the backing heap allocation in non-IRQ context.
    ///
    /// R151-5 FIX: `CpuLocal` lazily heap-allocates via `Once::call_once()`.
    /// If the first access occurs in IRQ context while another code path holds
    /// the heap allocator lock, the IRQ handler deadlocks. Call this during
    /// BSP/AP init before enabling interrupts.
    #[inline]
    pub fn force_init(&self) {
        let _ = self.get_slots();
    }

    /// Access the current CPU's slot immutably
    ///
    /// # Safety
    ///
    /// This is safe because each CPU only accesses its own slot, and we
    /// use interior mutability (e.g., atomics) for any mutations.
    #[inline]
    pub fn with<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        let id = current_cpu_id();
        // Hard bound check to prevent UB with non-zero-based APIC IDs
        assert!(
            id < MAX_CPUS,
            "CPU ID {} out of range (max {})",
            id,
            MAX_CPUS
        );
        // Safety: bound check above guarantees the slot exists and was initialized in get_slots()
        let slot = unsafe {
            let arr = &*self.get_slots().get();
            arr.get(id)
                .expect("CPU slot missing after bounds check")
                .assume_init_ref()
        };
        f(slot)
    }

    /// Access a specific CPU's slot immutably.
    ///
    /// Used for cross-CPU operations like TLB shootdown where we need to
    /// access another CPU's mailbox.
    ///
    /// # Safety
    ///
    /// This is safe only when `T` supports concurrent access (e.g., uses atomics).
    /// The caller must ensure proper synchronization for non-atomic operations.
    ///
    /// # Returns
    ///
    /// None if cpu_id is out of range (>= MAX_CPUS).
    #[inline]
    pub fn with_cpu<R>(&self, cpu_id: usize, f: impl FnOnce(&T) -> R) -> Option<R> {
        if cpu_id >= MAX_CPUS {
            return None;
        }

        // Safety: slots are initialized in get_slots(); cpu_id bounds checked above
        let slot = unsafe {
            let arr = &*self.get_slots().get();
            match arr.get(cpu_id) {
                Some(s) => s.assume_init_ref(),
                None => return None,
            }
        };
        Some(f(slot))
    }

    /// Get a static reference to a specific CPU's slot.
    ///
    /// Unlike `with_cpu`, this returns the reference directly instead of via
    /// a closure. The returned reference is `'static` because the underlying
    /// storage is owned by a static `Once` (and the heap allocation is never freed).
    ///
    /// # Safety
    ///
    /// This is safe only when `T` supports concurrent access (e.g., uses atomics).
    /// The caller must ensure proper synchronization for non-atomic operations.
    ///
    /// # Returns
    ///
    /// None if cpu_id is out of range (>= MAX_CPUS).
    #[inline]
    pub fn get_cpu(&self, cpu_id: usize) -> Option<&'static T> {
        if cpu_id >= MAX_CPUS {
            return None;
        }

        // Safety:
        // - slots are initialized in get_slots() before first access
        // - cpu_id bounds checked above
        // - The underlying storage is in a static Once, so references are 'static
        // - We transmute the lifetime because the storage truly is 'static
        unsafe {
            let arr = &*self.get_slots().get();
            match arr.get(cpu_id) {
                Some(s) => {
                    let ref_with_lifetime = s.assume_init_ref();
                    // Safety: The backing storage is owned by a static Once
                    // (heap-allocated Box never freed), so the data lives for
                    // 'static. The borrow checker can't see this, so we
                    // transmute the lifetime.
                    Some(core::mem::transmute::<&T, &'static T>(ref_with_lifetime))
                }
                None => None,
            }
        }
    }
}

/// Get the current CPU ID
///
/// # R67-8 FIX: O(1) Lookup
///
/// Uses a reverse mapping table (LAPIC ID → CPU index) for constant-time lookup.
/// This is critical for syscall entry performance where the CPU ID must be
/// determined very early without a stack.
///
/// # Implementation
///
/// 1. Read LAPIC ID from hardware (0xFEE00020, bits 31:24)
/// 2. O(1) lookup in LAPIC_ID_REVERSE_MAP
/// 3. Fallback to CPU 0 only during early boot (before registration)
///
/// # Panics (in debug builds)
///
/// Once SMP is enabled, falling back to CPU 0 would be a critical bug that
/// could cause slot aliasing. In debug builds, this generates a warning.
#[inline]
pub fn current_cpu_id() -> usize {
    current_cpu_id_impl()
}

/// Resolve the current CPU only when its LAPIC ID has an explicit logical-CPU
/// registration.
///
/// Unlike [`current_cpu_id`], this never applies the early-boot CPU-0 fallback.
/// Best-effort facilities such as KCOV use it to fail closed rather than
/// attributing work from a not-yet-admitted AP to the BSP's per-CPU state.
#[inline]
pub fn try_current_registered_cpu_id() -> Option<usize> {
    #[cfg(feature = "host_harness")]
    {
        Some(0)
    }

    #[cfg(not(feature = "host_harness"))]
    {
        match current_cpu_lookup() {
            CurrentCpuLookup::Registered(cpu_id) => Some(cpu_id),
            CurrentCpuLookup::X2ApicActive | CurrentCpuLookup::Unregistered(_) => None,
        }
    }
}

/// Hosted tests have one deterministic logical CPU and no LAPIC MMIO mapping.
///
/// RF180 hosted-verification fix: keep hardware discovery entirely out of the
/// hosted execution path. This is feature-gated rather than target-gated so an
/// accidental non-kernel target never silently changes production semantics.
#[cfg(feature = "host_harness")]
#[inline]
fn current_cpu_id_impl() -> usize {
    0
}

/// Result of a hardware LAPIC-to-logical-CPU lookup.
#[cfg(not(feature = "host_harness"))]
enum CurrentCpuLookup {
    Registered(usize),
    X2ApicActive,
    Unregistered(u32),
}

/// Verify that a reverse-map candidate still agrees with the authoritative
/// logical-CPU-to-LAPIC map.
///
/// A reverse entry alone is not a registration proof: firmware or a buggy
/// re-registration could otherwise leave a stale entry that aliases KCOV (and
/// other per-CPU state) to an unrelated online CPU.
#[inline]
fn registered_cpu_mapping_matches(cpu_id: usize, lapic_id: u32) -> bool {
    cpu_id < MAX_CPUS && LAPIC_ID_MAP[cpu_id].load(Ordering::Acquire) == lapic_id
}

/// Production CPU identification through the registered LAPIC-to-logical map.
#[cfg(not(feature = "host_harness"))]
#[inline]
fn current_cpu_lookup() -> CurrentCpuLookup {
    // R169-L7 FIX: in x2APIC mode the APIC ID comes from an MSR, can exceed 8 bits
    // (overflowing the 256-entry reverse map), and the xAPIC MMIO ID register read
    // below is invalid. Reading it would alias another CPU's per-CPU slot, so fail
    // closed. `arch::apic` publishes this flag at LAPIC init (it is xAPIC-MMIO
    // only); the kernel never enables x2APIC, so on supported hardware this branch
    // is never taken.
    if X2APIC_ACTIVE.load(Ordering::Acquire) {
        return CurrentCpuLookup::X2ApicActive;
    }

    // R169-L7 FIX: read the LAPIC ID register (offset 0x20, bits 31:24) through the
    // single authoritative MMIO base shared with `arch::apic::lapic_read`, not a
    // hard-coded `0xFEE0_0020` literal. The base is validated to be the architected
    // `LAPIC_MMIO_DEFAULT_BASE` at LAPIC init, so this read targets the same page
    // the identity-map hardening carve-out preserves.
    let apic_id = unsafe {
        let id_reg = (lapic_mmio_base() as usize + 0x20) as *const u32;
        core::ptr::read_volatile(id_reg) >> 24
    };

    // R67-8 FIX: O(1) reverse lookup instead of linear search
    let cpu_idx = if (apic_id as usize) < LAPIC_ID_REVERSE_MAP_SIZE {
        LAPIC_ID_REVERSE_MAP[apic_id as usize].load(Ordering::Acquire)
    } else {
        INVALID_CPU_ID
    };

    // R187-7 FIX: a valid reverse entry must also agree with the forward map.
    // This rejects stale/reassigned LAPIC mappings instead of aliasing their
    // per-CPU KCOV state to a currently online logical slot.
    if registered_cpu_mapping_matches(cpu_idx, apic_id) {
        return CurrentCpuLookup::Registered(cpu_idx);
    }

    CurrentCpuLookup::Unregistered(apic_id)
}

/// Production CPU identification through the registered LAPIC-to-logical map.
#[cfg(not(feature = "host_harness"))]
#[inline]
fn current_cpu_id_impl() -> usize {
    match current_cpu_lookup() {
        CurrentCpuLookup::Registered(cpu_id) => cpu_id,
        CurrentCpuLookup::X2ApicActive => {
            panic!("current_cpu_id: x2APIC mode is unsupported (would alias per-CPU data)");
        }
        CurrentCpuLookup::Unregistered(apic_id) => {
            // R151-6 FIX: After SMP init, an unregistered LAPIC ID is a critical bug
            // that would silently alias CPU 0's per-CPU data. Panic immediately.
            if CPU_LOCAL_SMP_DONE.load(Ordering::Acquire) {
                panic!(
                    "current_cpu_id: LAPIC ID {} not registered after SMP init complete",
                    apic_id
                );
            }

            // Fallback to CPU 0 - only safe during early boot before registration.
            0
        }
    }
}

/// Register the LAPIC ID to CPU index mapping.
///
/// This must be called for each CPU during bring-up to enable
/// proper `current_cpu_id()` operation.
///
/// # R67-8 FIX
///
/// Also populates the reverse mapping table for O(1) lookup in syscall entry.
///
/// # Arguments
///
/// * `cpu_id` - Logical CPU index (0 = BSP, 1+ = APs)
/// * `lapic_id` - Hardware LAPIC ID
///
/// # Panics
///
/// Panics if `cpu_id` is out of range.
pub fn register_cpu_id(cpu_id: usize, lapic_id: u32) {
    assert!(cpu_id < MAX_CPUS, "CPU ID {} out of range", cpu_id);
    assert!(
        (lapic_id as usize) < LAPIC_ID_REVERSE_MAP_SIZE,
        "LAPIC ID {} exceeds the xAPIC reverse-map capacity",
        lapic_id
    );

    let _registration = CPU_ID_REGISTRATION_LOCK.lock();
    let previous_lapic = LAPIC_ID_MAP[cpu_id].load(Ordering::Acquire);
    assert!(
        previous_lapic == INVALID_LAPIC_ID || previous_lapic == lapic_id || !is_cpu_online(cpu_id),
        "CPU {} is online and cannot change LAPIC ID {} to {}",
        cpu_id,
        previous_lapic,
        lapic_id
    );
    let claimed_by = LAPIC_ID_REVERSE_MAP[lapic_id as usize].load(Ordering::Acquire);
    assert!(
        claimed_by == INVALID_CPU_ID || claimed_by == cpu_id,
        "LAPIC ID {} is already registered to CPU {}",
        lapic_id,
        claimed_by
    );
    assert!(
        claimed_by == INVALID_CPU_ID || previous_lapic == lapic_id,
        "LAPIC ID {} has a stale reverse mapping for CPU {}",
        lapic_id,
        cpu_id
    );

    if previous_lapic != INVALID_LAPIC_ID && previous_lapic != lapic_id {
        assert!(
            (previous_lapic as usize) < LAPIC_ID_REVERSE_MAP_SIZE,
            "CPU {} had an out-of-range prior LAPIC ID {}",
            cpu_id,
            previous_lapic
        );
        let old_owner = LAPIC_ID_REVERSE_MAP[previous_lapic as usize].load(Ordering::Acquire);
        assert_eq!(
            old_owner, cpu_id,
            "CPU {} had a non-bijective LAPIC mapping for ID {}",
            cpu_id, previous_lapic
        );
        LAPIC_ID_REVERSE_MAP[previous_lapic as usize].store(INVALID_CPU_ID, Ordering::Release);
    }

    // Publish forward first and reverse second. A concurrent reader can only
    // observe an incomplete mapping and fail closed because it validates both
    // directions in `registered_cpu_mapping_matches`.
    LAPIC_ID_MAP[cpu_id].store(lapic_id, Ordering::Release);
    LAPIC_ID_REVERSE_MAP[lapic_id as usize].store(cpu_id, Ordering::Release);
}

/// Get the maximum number of supported CPUs
pub const fn max_cpus() -> usize {
    MAX_CPUS
}

/// Get the LAPIC ID for a CPU index if it has been registered.
///
/// Returns None if:
/// - cpu_id is out of range (>= MAX_CPUS)
/// - cpu_id has not been registered yet (LAPIC ID is INVALID_LAPIC_ID)
///
/// # Usage
///
/// Used by IPI sending code to map logical CPU index to hardware LAPIC ID.
#[inline]
pub fn lapic_id_for_cpu(cpu_id: usize) -> Option<u32> {
    if cpu_id >= MAX_CPUS {
        return None;
    }
    let lapic_id = LAPIC_ID_MAP[cpu_id].load(Ordering::Acquire);
    if lapic_id == INVALID_LAPIC_ID || (lapic_id as usize) >= LAPIC_ID_REVERSE_MAP_SIZE {
        None
    } else if LAPIC_ID_REVERSE_MAP[lapic_id as usize].load(Ordering::Acquire) == cpu_id {
        Some(lapic_id)
    } else {
        // Registration publishes a forward/reverse pair. Returning a forward
        // entry without its reciprocal reverse entry could target a stale or
        // reassigned LAPIC during AP topology changes, so fail closed.
        None
    }
}

// ============================================================================
// Global Per-CPU Data Access
// ============================================================================

/// Global per-CPU data block for scheduler and IRQ metadata.
///
/// This is the primary per-CPU data structure used by the kernel.
/// Access it via `current_cpu()` or `PER_CPU_DATA.with()`.
pub static PER_CPU_DATA: CpuLocal<PerCpuData> = CpuLocal::new(PerCpuData::new);

/// Access the current CPU's `PerCpuData`.
///
/// This is the primary way to access per-CPU state. The returned reference
/// is valid for the duration of the current CPU's execution (i.e., until
/// migration to another CPU, which is not yet supported).
///
/// # Example
///
/// ```rust,ignore
/// use cpu_local::current_cpu;
///
/// current_cpu().set_need_resched();
/// if current_cpu().preemptible() {
///     // Safe to reschedule
/// }
/// ```
#[inline]
pub fn current_cpu() -> &'static PerCpuData {
    // We use a closure that returns the reference directly since
    // the underlying storage is static
    PER_CPU_DATA.with(|d| {
        // Safety: The PerCpuData is stored in static memory with 'static lifetime
        unsafe { &*(d as *const PerCpuData) }
    })
}

/// Allocation-free guard for the IRQ-return deferred callback drain.
pub struct SoftProgressGuard {
    per_cpu: &'static PerCpuData,
}

impl Drop for SoftProgressGuard {
    #[inline]
    fn drop(&mut self) {
        let was_active = self
            .per_cpu
            .soft_progress_active
            .swap(false, Ordering::Release);
        assert!(was_active, "soft-progress guard was not active");
    }
}

/// Try to enter the current CPU's IRQ-return soft-progress context.
#[inline]
pub fn try_enter_soft_progress() -> Option<SoftProgressGuard> {
    current_cpu().try_enter_soft_progress()
}

/// Initialize the bootstrap processor's per-CPU slot.
///
/// Must be invoked during early boot before interrupts are enabled.
/// The BSP (CPU 0) is initialized with the provided stack addresses.
///
/// # Arguments
///
/// * `lapic_id` - Hardware Local APIC ID of the BSP
/// * `kernel_stack_top` - Top of the kernel privilege stack
/// * `irq_stack_top` - Top of the interrupt stack (IST1)
/// * `syscall_stack_top` - Top of the syscall entry stack
///
/// # Panics
///
/// Panics if called when not on CPU 0.
pub fn init_bsp(
    lapic_id: u32,
    kernel_stack_top: usize,
    irq_stack_top: usize,
    syscall_stack_top: usize,
) {
    // Register BSP's LAPIC ID mapping first
    register_cpu_id(0, lapic_id);

    current_cpu().init(
        0,
        lapic_id,
        kernel_stack_top,
        irq_stack_top,
        syscall_stack_top,
    );
}

/// Initialize an application processor's per-CPU slot.
///
/// Called by AP bootstrap code after the AP has started executing.
///
/// # Arguments
///
/// * `cpu_id` - Logical CPU index (1+ for APs)
/// * `lapic_id` - Hardware Local APIC ID of this AP
/// * `kernel_stack_top` - Top of the kernel privilege stack
/// * `irq_stack_top` - Top of the interrupt stack (IST1)
/// * `syscall_stack_top` - Top of the syscall entry stack
///
/// # Panics
///
/// Panics if cpu_id is 0 (BSP) or out of range.
pub fn init_ap(
    cpu_id: usize,
    lapic_id: u32,
    kernel_stack_top: usize,
    irq_stack_top: usize,
    syscall_stack_top: usize,
) {
    assert!(cpu_id > 0, "init_ap must not be called for BSP (CPU 0)");
    assert!(cpu_id < MAX_CPUS, "CPU ID {} out of range", cpu_id);

    // Register AP's LAPIC ID mapping
    register_cpu_id(cpu_id, lapic_id);

    // Initialize this CPU's PerCpuData
    // Note: We access via PER_CPU_DATA since current_cpu_id() now uses LAPIC map
    PER_CPU_DATA.with(|d| {
        d.init(
            cpu_id,
            lapic_id,
            kernel_stack_top,
            irq_stack_top,
            syscall_stack_top,
        );
    });
}

/// R178-28 FIX: Bitmap of online CPU IDs (bit N = CPU N is online).
///
/// Authoritative mask for scheduler affinity and cpuset validation. Only bits
/// corresponding to registered CPUs (via `register_cpu_id`) that have called
/// `mark_cpu_online` are set. BSP (CPU 0) is marked online at init.
static ONLINE_CPU_MASK: AtomicU64 = AtomicU64::new(1); // Bit 0 set for BSP

/// Get the number of online CPUs.
///
/// # R69-1 FIX: Accurate Online CPU Count
///
/// Derives the count from the authoritative ID bitmap so count and mask cannot
/// diverge when logical IDs are sparse.
#[inline]
pub fn num_online_cpus() -> usize {
    ONLINE_CPU_MASK.load(Ordering::Acquire).count_ones() as usize
}

/// R178-28 FIX: Get the online CPU mask (bit N = CPU N is online).
///
/// Returns a bitmap of online CPU IDs. Used by scheduler affinity and cpuset
/// code to validate that requested CPUs are actually online. Only CPUs that
/// have both registered their LAPIC ID and completed AP initialization are set.
#[inline]
pub fn online_cpu_mask() -> u64 {
    ONLINE_CPU_MASK.load(Ordering::Acquire)
}

/// Test one logical CPU ID against the same authoritative bitmap.
#[inline]
pub fn is_cpu_online(cpu_id: usize) -> bool {
    cpu_id < MAX_CPUS && (online_cpu_mask() & (1u64 << cpu_id)) != 0
}

/// Compute the online mask after admitting one logical CPU.
///
/// The transition is intentionally idempotent: repeated lifecycle callbacks
/// cannot inflate a separate count because the count is always derived from
/// the resulting bitmap. Keeping this small transition pure also lets the host
/// topology harness exercise duplicate-publication behavior without mutating
/// the global boot topology.
#[inline]
fn online_mask_after_publish(current_mask: u64, cpu_id: usize) -> Option<u64> {
    if cpu_id >= MAX_CPUS {
        return None;
    }
    Some(current_mask | (1u64 << cpu_id))
}

/// Admit a logical CPU only when a prior LAPIC lookup produced a valid ID and
/// that ID is currently online.
///
/// Keeping the capacity check ahead of the shift makes this helper safe for
/// every caller, including best-effort KCOV paths that must fail closed rather
/// than turn an unknown topology result into a static-array index.
#[inline]
fn registered_online_cpu_id(registered_cpu_id: Option<usize>, online_mask: u64) -> Option<usize> {
    let cpu_id = registered_cpu_id?;
    if cpu_id >= MAX_CPUS || (online_mask & (1u64 << cpu_id)) == 0 {
        return None;
    }
    Some(cpu_id)
}

/// Resolve the current CPU only when it is both LAPIC-registered and online.
///
/// This is the strict admission boundary for fixed-capacity per-CPU state.
/// Unlike [`current_cpu_id`], it never applies the early-boot CPU-0 fallback.
#[inline]
pub fn try_current_registered_online_cpu_id() -> Option<usize> {
    registered_online_cpu_id(try_current_registered_cpu_id(), online_cpu_mask())
}

/// Read the architectural interrupt-enable flag without depending on the arch
/// crate (which itself depends on `cpu_local`).
///
/// KCOV treats every IF-masked context conservatively as non-task context. On
/// x86-64 this covers interrupt-gate entries and ordinary task critical
/// sections; NMI is additionally accounted explicitly because its entry does
/// not reliably clear IF. Other architectures currently retain the existing
/// IRQ/NMI accounting until they provide an equivalent flag reader.
#[inline]
fn interrupts_enabled() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let rflags: usize;
        // SAFETY: PUSHFQ/POP only read the current CPU's RFLAGS and restore the
        // stack pointer before returning. They do not alter interrupt state.
        unsafe {
            core::arch::asm!("pushfq", "pop {}", out(reg) rflags, options(preserves_flags));
        }
        (rflags & (1 << 9)) != 0
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        true
    }
}

#[inline]
fn is_non_task_context(in_irq: bool, in_nmi: bool, interrupts_enabled: bool) -> bool {
    in_irq || in_nmi || !interrupts_enabled
}

/// Return whether the current, registered, online CPU is in non-task context.
///
/// `None` is deliberately fail-closed: callers must not attribute work to an
/// unregistered or offline CPU. This is a pre-admission filter only; a caller
/// that needs a stable CPU must re-check through [`CurrentCpuPin`] after pinning.
#[inline]
pub fn try_current_online_cpu_in_non_task_context() -> Option<bool> {
    // Check the allocation-free global NMI gate first. An NMI can arrive
    // before CPU-local storage and LAPIC registration are initialized, so no
    // CPU-local lookup is safe on that path.
    if nmi_active() {
        return Some(true);
    }

    let cpu_id = try_current_registered_online_cpu_id()?;
    // Hardware interrupt gates clear IF. Check it before consulting the
    // heap-backed per-CPU slab so the common asynchronous path cannot make
    // its first allocation while rejecting KCOV work.
    let interrupts_enabled = interrupts_enabled();
    if !interrupts_enabled {
        return Some(true);
    }
    let per_cpu = PER_CPU_DATA.get_cpu(cpu_id)?;
    Some(
        per_cpu.in_soft_progress()
            || is_non_task_context(per_cpu.in_irq(), nmi_active(), interrupts_enabled),
    )
}

/// Return whether the current, registered, online CPU is servicing an
/// accounted hard IRQ.
///
/// This deliberately does not inspect IF. Scheduler switch code publishes a
/// task token with IF masked, which is ordinary scheduler context rather than
/// an IRQ handler. Callers that must reject every asynchronous context should
/// use [`try_current_online_cpu_in_non_task_context`] instead.
#[inline]
pub fn try_current_online_cpu_in_irq_context() -> Option<bool> {
    let cpu_id = try_current_registered_online_cpu_id()?;
    Some(PER_CPU_DATA.get_cpu(cpu_id)?.in_irq())
}

/// A non-sendable preemption pin for a registered, online CPU.
///
/// The pin holds the validated per-CPU reference so dropping it never repeats
/// CPU lookup or indexes a caller-owned per-CPU array. KCOV uses this to keep
/// topology admission and preemption restoration fail-closed.
pub struct CurrentCpuPin {
    cpu_id: usize,
    per_cpu: &'static PerCpuData,
    _not_send: core::marker::PhantomData<*const ()>,
}

impl CurrentCpuPin {
    /// Return the validated logical CPU ID associated with this pin.
    #[inline]
    pub fn cpu_id(&self) -> usize {
        self.cpu_id
    }

    /// Return whether this pinned CPU is in a non-task context.
    #[inline]
    pub fn in_non_task_context(&self) -> bool {
        self.per_cpu.in_soft_progress()
            || is_non_task_context(self.per_cpu.in_irq(), nmi_active(), interrupts_enabled())
    }

    /// Return whether the pinned CPU is servicing an accounted hard IRQ.
    ///
    /// Unlike [`Self::in_non_task_context`], this intentionally permits a
    /// scheduler critical section with IF masked.
    #[inline]
    pub fn in_irq(&self) -> bool {
        self.per_cpu.in_irq()
    }
}

impl Drop for CurrentCpuPin {
    #[inline]
    fn drop(&mut self) {
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        self.per_cpu.preempt_enable();
    }
}

/// Try to pin the current CPU only after strict topology admission.
///
/// R187-7 FIX: KCOV must never use the legacy pre-SMP CPU-0 fallback for
/// per-CPU tracing state. The retry closes the sample-before-disable migration
/// window, while every unavailable/offline topology state drops the caller's
/// best-effort operation without indexing a static array.
#[inline]
pub fn try_pin_current_online_cpu() -> Option<CurrentCpuPin> {
    loop {
        let cpu_id = try_current_registered_online_cpu_id()?;

        let per_cpu = PER_CPU_DATA.get_cpu(cpu_id)?;
        per_cpu.preempt_disable();
        core::sync::atomic::compiler_fence(Ordering::SeqCst);

        if try_current_registered_online_cpu_id() == Some(cpu_id) {
            return Some(CurrentCpuPin {
                cpu_id,
                per_cpu,
                _not_send: core::marker::PhantomData,
            });
        }

        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        per_cpu.preempt_enable();
        core::hint::spin_loop();
    }
}

/// Mark a CPU as online (call this from AP initialization).
///
/// Sets the corresponding bit in the online mask. Should be called once per AP
/// after it has completed initialization.
///
/// # Safety
///
/// Should only be called once per CPU during SMP initialization.
///
/// # R178-28 FIX
///
/// Now also updates the authoritative online-CPU mask so affinity/cpuset
/// validation can distinguish registered-but-offline from truly online CPUs.
#[inline]
pub fn mark_cpu_online() {
    let cpu_id = try_current_registered_cpu_id()
        .expect("cannot publish online topology for an unregistered LAPIC identity");
    mark_cpu_online_with_id(cpu_id);
}

/// Publish a registered logical CPU as online.
///
/// Registration and online publication share `CPU_ID_REGISTRATION_LOCK`, so a
/// re-registration cannot pass an offline check while this bit is being set.
/// The reciprocal LAPIC map is validated again under the same lock, and the
/// bitmap transition is idempotent for duplicate callbacks.
#[inline]
pub fn mark_cpu_online_with_id(cpu_id: usize) {
    assert!(cpu_id < MAX_CPUS, "CPU ID {} out of range", cpu_id);
    let _registration = CPU_ID_REGISTRATION_LOCK.lock();
    let lapic_id = LAPIC_ID_MAP[cpu_id].load(Ordering::Acquire);
    assert!(
        lapic_id != INVALID_LAPIC_ID
            && (lapic_id as usize) < LAPIC_ID_REVERSE_MAP_SIZE
            && LAPIC_ID_REVERSE_MAP[lapic_id as usize].load(Ordering::Acquire) == cpu_id,
        "CPU {} cannot become online before reciprocal LAPIC registration",
        cpu_id
    );

    // The idempotent transition is serialized under the lifecycle lock.
    // Readers derive their count from this authoritative mask, so no second
    // counter can diverge.
    let current = ONLINE_CPU_MASK.load(Ordering::Relaxed);
    let next = online_mask_after_publish(current, cpu_id)
        .expect("validated CPU ID unexpectedly exceeded online-mask capacity");
    ONLINE_CPU_MASK.store(next, Ordering::Release);
}

/// Clear FPU ownership for a process across all CPUs.
///
/// Called when a process exits to ensure no CPU holds a stale FPU owner
/// reference that would cause #NM to save state to freed memory.
///
/// This function iterates all CPU slots and uses compare-exchange to
/// atomically clear any slot that matches the given PID.
pub fn clear_fpu_owner_all_cpus(pid: usize) {
    for cpu_id in 0..MAX_CPUS {
        if let Some(per_cpu) = PER_CPU_DATA.get_cpu(cpu_id) {
            per_cpu.clear_fpu_owner_if(pid);
        }
    }
}

#[cfg(all(test, feature = "host_harness"))]
mod host_harness_tests {
    use core::sync::atomic::Ordering;

    static TOPOLOGY_TEST_LOCK: spin::Mutex<()> = spin::Mutex::new(());

    #[test]
    fn current_cpu_id_is_deterministic_without_lapic_mmio() {
        assert_eq!(super::current_cpu_id(), 0);
    }

    #[test]
    fn strict_cpu_pin_is_registered_online_and_restores_preemption() {
        assert_eq!(super::try_current_registered_cpu_id(), Some(0));
        assert_eq!(super::try_current_registered_online_cpu_id(), Some(0));
        assert_eq!(
            super::try_current_online_cpu_in_non_task_context(),
            Some(false)
        );
        assert_eq!(super::try_current_online_cpu_in_irq_context(), Some(false));
        assert!(super::is_cpu_online(0));
        assert!(!super::is_cpu_online(super::MAX_CPUS));
        assert!(!super::is_cpu_online(usize::MAX));

        let before = super::current_cpu().preempt_count.load(Ordering::Relaxed);
        let pin = super::try_pin_current_online_cpu().expect("host CPU 0 is admitted");
        assert_eq!(pin.cpu_id(), 0);
        assert!(!pin.in_non_task_context());
        assert_eq!(
            super::current_cpu().preempt_count.load(Ordering::Relaxed),
            before + 1
        );
        drop(pin);
        assert_eq!(
            super::current_cpu().preempt_count.load(Ordering::Relaxed),
            before
        );
    }

    #[test]
    fn strict_topology_admission_rejects_unregistered_offline_and_out_of_range_ids() {
        let highest = super::MAX_CPUS - 1;
        let online = (1u64 << 0) | (1u64 << highest);

        assert_eq!(super::registered_online_cpu_id(None, online), None);
        assert_eq!(super::registered_online_cpu_id(Some(1), online), None);
        assert_eq!(
            super::registered_online_cpu_id(Some(super::MAX_CPUS), online),
            None
        );
        assert_eq!(
            super::registered_online_cpu_id(Some(usize::MAX), online),
            None
        );
        assert_eq!(super::registered_online_cpu_id(Some(0), online), Some(0));
        assert_eq!(
            super::registered_online_cpu_id(Some(highest), online),
            Some(highest)
        );
    }

    #[test]
    fn non_task_context_classifier_rejects_irq_and_interrupt_masking() {
        assert!(!super::is_non_task_context(false, false, true));
        assert!(super::is_non_task_context(true, false, true));
        assert!(super::is_non_task_context(false, true, true));
        assert!(super::is_non_task_context(false, false, false));
        assert!(super::is_non_task_context(true, true, false));

        super::current_cpu().irq_enter();
        assert_eq!(super::try_current_online_cpu_in_irq_context(), Some(true));
        super::current_cpu().irq_exit();
        super::nmi_enter();
        assert_eq!(
            super::try_current_online_cpu_in_non_task_context(),
            Some(true)
        );
        super::nmi_exit();
    }

    #[test]
    fn soft_progress_context_is_fail_closed_and_non_reentrant() {
        let _serial = TOPOLOGY_TEST_LOCK.lock();

        assert_eq!(
            super::try_current_online_cpu_in_non_task_context(),
            Some(false)
        );
        let guard = super::try_enter_soft_progress().expect("outer soft-progress entry");
        assert_eq!(
            super::try_current_online_cpu_in_non_task_context(),
            Some(true)
        );
        let pin = super::try_pin_current_online_cpu().expect("host CPU 0 is admitted");
        assert!(pin.in_non_task_context());
        assert!(super::try_enter_soft_progress().is_none());
        drop(pin);
        drop(guard);
        assert_eq!(
            super::try_current_online_cpu_in_non_task_context(),
            Some(false)
        );
    }

    #[test]
    fn registration_reassignment_clears_stale_reverse_entry() {
        let _serial = TOPOLOGY_TEST_LOCK.lock();
        let cpu_id = super::MAX_CPUS - 2;
        let first_lapic = 250;
        let second_lapic = 251;

        super::register_cpu_id(cpu_id, first_lapic);
        assert!(super::registered_cpu_mapping_matches(cpu_id, first_lapic));
        super::register_cpu_id(cpu_id, second_lapic);

        assert_eq!(super::lapic_id_for_cpu(cpu_id), Some(second_lapic));
        assert!(!super::registered_cpu_mapping_matches(cpu_id, first_lapic));
        assert!(super::registered_cpu_mapping_matches(cpu_id, second_lapic));
        assert_eq!(
            super::LAPIC_ID_REVERSE_MAP[first_lapic as usize].load(Ordering::Acquire),
            super::INVALID_CPU_ID
        );
        assert_eq!(
            super::LAPIC_ID_REVERSE_MAP[second_lapic as usize].load(Ordering::Acquire),
            cpu_id
        );

        // A forward entry alone is never enough to target a LAPIC. This
        // models an interrupted/externally-corrupted registration and proves
        // forward-map consumers fail closed until reciprocity is restored.
        super::LAPIC_ID_REVERSE_MAP[second_lapic as usize]
            .store(super::INVALID_CPU_ID, Ordering::Release);
        assert_eq!(super::lapic_id_for_cpu(cpu_id), None);
        super::LAPIC_ID_REVERSE_MAP[second_lapic as usize].store(cpu_id, Ordering::Release);
        assert_eq!(super::lapic_id_for_cpu(cpu_id), Some(second_lapic));
    }

    #[test]
    #[should_panic(expected = "already registered")]
    fn registration_rejects_duplicate_lapic_identity() {
        let _serial = TOPOLOGY_TEST_LOCK.lock();
        let lapic_id = 249;
        super::register_cpu_id(super::MAX_CPUS - 4, lapic_id);
        super::register_cpu_id(super::MAX_CPUS - 3, lapic_id);
    }

    #[test]
    fn duplicate_online_publication_is_idempotent() {
        let mask = 1u64 | (1u64 << (super::MAX_CPUS - 1));
        assert_eq!(
            super::online_mask_after_publish(mask, super::MAX_CPUS - 1),
            Some(mask)
        );
        assert_eq!(
            super::online_mask_after_publish(mask, super::MAX_CPUS),
            None
        );
    }
}
