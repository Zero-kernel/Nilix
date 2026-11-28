//! TLB Shootdown Infrastructure
//!
//! Provides cross-CPU TLB invalidation for SMP systems.
//!
//! # R23-1/R23-3 Fix
//!
//! This module addresses the TLB coherency issues identified in Round 23 audit:
//! - R23-1: COW page table modifications need TLB shootdown on all CPUs
//! - R23-3: munmap needs TLB shootdown before frame deallocation
//!
//! # IPI-Based Implementation (SMP)
//!
//! When multiple CPUs are online, TLB shootdown works as follows:
//! 1. Requesting CPU writes request to each target CPU's per-CPU mailbox
//! 2. Requesting CPU sends TLB shootdown IPI (vector 0xFE) to all targets
//! 3. Requesting CPU flushes its own TLB locally
//! 4. Each target CPU's IPI handler reads mailbox, flushes TLB, writes ACK
//! 5. Requesting CPU waits for all ACKs with bounded timeout
//!
//! # Memory Ordering
//!
//! - Requester: writes fields Relaxed, then `request_gen` Release
//! - Handler: loads `request_gen` Acquire, reads fields Relaxed, writes `ack_gen` Release
//! - Waiter: loads `ack_gen` Acquire to ensure flush completion is visible
//!
//! # Safety Guard
//!
//! The `assert_single_core_mode()` function panics if multiple CPUs are online
//! but the IPI sender is not registered, ensuring we never silently skip shootdown.

use core::hint::spin_loop;
use core::mem;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use cpu_local::{
    current_cpu, current_cpu_id, lapic_id_for_cpu, max_cpus, try_current_registered_cpu_id,
    TlbShootdownMailbox, PER_CPU_DATA, TLB_SHOOTDOWN_QUEUE_LEN,
};
use x86_64::instructions::tlb;
use x86_64::registers::control::{Cr3, Cr3Flags, Cr4, Cr4Flags};
use x86_64::VirtAddr;

// INVPCID support for efficient TLB invalidation
use tlb_ops::{invpcid_all_nonglobal, invpcid_supported};

/// Statistics for TLB shootdown operations (for debugging/profiling)
/// Uses atomics for SMP-safety (relaxed ordering is sufficient for stats)
#[derive(Debug)]
pub struct TlbShootdownStats {
    /// Number of full address space flushes
    pub full_flushes: u64,
    /// Number of range flushes
    pub range_flushes: u64,
    /// Number of pages flushed in range operations
    pub pages_flushed: u64,
    /// R106-5: Number of times mailbox saturation forced a full-flush fallback
    pub coalesced_fallbacks: u64,
    /// C3 E1 (#90): target scans that found a CPU running the modified CR3
    /// (Issue #109 §1.2: also counts targeted scans that proved 0 remote CPUs
    /// hold the modified CR3 and therefore skipped all remote IPIs).
    pub targeted_shootdowns: u64,
    /// Issue #109 §1.2: subset of `targeted_shootdowns` where every other online
    /// CPU was tracked on a different CR3, so 0 remote IPIs were sent.
    pub targeted_zero_ipi: u64,
    /// C3 E1: target scans that fell back to every other online CPU (CR3=0,
    /// kernel-half VA, unresolved KPTI/CR3 mismatch, or non-zero PCID active).
    pub broadcast_fallbacks: u64,
    /// C3 E1: shootdown IPIs sent, including ACK-timeout resends
    pub shootdown_ipis: u64,
}

// Atomic statistics for SMP-safe updates
static STATS_FULL_FLUSHES: AtomicU64 = AtomicU64::new(0);
static STATS_RANGE_FLUSHES: AtomicU64 = AtomicU64::new(0);
static STATS_PAGES_FLUSHED: AtomicU64 = AtomicU64::new(0);
/// R106-5: Counter for mailbox saturation fallbacks
static STATS_COALESCED_FALLBACKS: AtomicU64 = AtomicU64::new(0);

#[allow(dead_code)]
/// SMP support flag - now true since IPI-based shootdown is implemented
static SMP_SHOOTDOWN_IMPLEMENTED: bool = true;

/// Next generation number for TLB shootdown requests (monotonic, starts at 1).
/// Zero is the unpublished queue-slot sentinel and may never be issued.
static NEXT_SHOOTDOWN_GEN: AtomicU64 = AtomicU64::new(1);

#[inline]
fn next_shootdown_generation() -> u64 {
    // R180-12 FIX: never wrap the generation into the queue's zero sentinel.
    // A wrapped value would remain indistinguishable from an unpublished entry
    // and could wedge the IPI handler or make completion accounting ambiguous.
    NEXT_SHOOTDOWN_GEN
        .fetch_update(Ordering::SeqCst, Ordering::Acquire, |current| {
            current.checked_add(1).filter(|next| *next != 0)
        })
        .unwrap_or_else(|_| panic!("TLB shootdown generation space exhausted"))
}

// ============================================================================
// Per-Address-Space TLB Tracking (R68 Architecture Improvement)
// ============================================================================

/// Issue #109 §1.2: cache-line-isolated active CR3 slot for one CPU.
///
/// Packing 8 CPUs per 64-byte line caused cross-CPU false sharing on every
/// context switch (`SeqCst` store emits `xchg` on x86-64). Giving each CPU its
/// own 64-byte line keeps remote `CPU_ACTIVE_CR3` lines clean when idle CPUs
/// are scanned by `collect_target_cpus`.
#[repr(align(64))]
struct AlignedActiveCr3(AtomicU64);

impl AlignedActiveCr3 {
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
}

/// RF178-33: allocation-free record of the canonical kernel CR3 root currently
/// active on each CPU.
///
/// A fixed array avoids `CpuLocal` first-touch initialization in IRQ-return
/// context. Context switch publishes with `SeqCst` BEFORE loading CR3 (with
/// `IF=0`), and shootdown scans with a preceding `SeqCst` fence plus `SeqCst`
/// loads. This replaces the global CR3->mask BTreeMap, whose write lock and
/// insertion were illegal on the timer-return path.
static CPU_ACTIVE_CR3: [AlignedActiveCr3; cpu_local::max_cpus()] =
    [const { AlignedActiveCr3::new() }; cpu_local::max_cpus()];

/// H4 fail-closed guard (Issue #109 §1.2): latched true if any non-zero PCID
/// (1..=4095) is ever allocated or observed in hardware CR3.
///
/// Under `CR4.PCIDE == 1`, skipping a remote CPU whose `CPU_ACTIVE_CR3` differs
/// from `target_cr3` is sound only while every address space uses PCID 0
/// (`NOFLUSH == 0`), so switching CR3 flushes all non-global TLB entries on
/// that CPU. If non-zero PCIDs are ever activated without per-PCID residency
/// tracking, this latch forces broadcast fallback.
static NONZERO_PCID_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Exclusive upper bound of the canonical x86-64 user address space.
///
/// High-half mappings (and the non-canonical hole / overflow) are shared across
/// all kernel CR3 roots and must always broadcast rather than target one CR3.
const USER_HALF_END: u64 = 0x0000_8000_0000_0000;

/// Statistics for optimized TLB shootdowns
static STATS_TARGETED_SHOOTDOWNS: AtomicU64 = AtomicU64::new(0);
static STATS_TARGETED_ZERO_IPI: AtomicU64 = AtomicU64::new(0);
static STATS_BROADCAST_FALLBACK: AtomicU64 = AtomicU64::new(0);
/// C3 E1 (#90): shootdown IPIs sent; divided by the two counters above, the
/// mean fanout of a remote dispatch.
static STATS_SHOOTDOWN_IPIS: AtomicU64 = AtomicU64::new(0);

/// Registered function used to send the TLB shootdown IPI
/// Stored as usize to avoid function pointer in static
static TLB_IPI_SENDER: AtomicUsize = AtomicUsize::new(0);

/// Spin iterations to wait for ACKs before timing out
/// At ~2GHz, 1M iterations is roughly 0.5-1ms
const IPI_ACK_TIMEOUT_SPINS: usize = 1_000_000;

/// Page size used for alignment
const PAGE_SIZE: u64 = 4096;

/// If more than this many pages are affected, fall back to full flush
const FULL_FLUSH_THRESHOLD: u64 = 16;

/// Type alias for IPI sender function
type TlbIpiSender = fn(usize);

/// Allocation-free set of logical CPU IDs.
///
/// `cpu_local` supports at most 64 CPUs, so a single word can carry target,
/// fallback, and unacknowledged CPU sets through the entire shootdown path.
/// Keeping this type private also preserves the existing public API while
/// making page-table teardown safe when the heap is unavailable.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct CpuMask(u64);

impl CpuMask {
    #[inline]
    const fn empty() -> Self {
        Self(0)
    }

    #[inline]
    fn insert(&mut self, cpu_id: usize) {
        assert!(
            cpu_id < u64::BITS as usize,
            "TLB shootdown CPU ID {} exceeds fixed mask width",
            cpu_id
        );
        self.0 |= 1u64 << cpu_id;
    }

    #[inline]
    const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[inline]
    const fn iter(self) -> CpuMaskIter {
        CpuMaskIter { remaining: self.0 }
    }
}

impl core::fmt::Debug for CpuMask {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_list().entries(self.iter()).finish()
    }
}

struct CpuMaskIter {
    remaining: u64,
}

impl Iterator for CpuMaskIter {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        let cpu_id = self.remaining.trailing_zeros() as usize;
        self.remaining &= self.remaining - 1;
        Some(cpu_id)
    }
}

/// Cached INVPCID support flag (initialized once, never changes)
///
/// Using a static to cache the CPUID result avoids repeated CPUID calls
/// in the hot path.
static INVPCID_SUPPORTED: AtomicBool = AtomicBool::new(false);

/// Initialize INVPCID support flag.
///
/// Must be called once during boot before any TLB shootdown operations.
/// After initialization, `is_invpcid_available()` returns the cached value.
pub fn init_invpcid_support() {
    let supported = invpcid_supported();
    INVPCID_SUPPORTED.store(supported, Ordering::Release);
    if supported {
        kprintln!("[TLB] INVPCID instruction available - using efficient flushes");
    }
}

/// Check if INVPCID instruction is available (cached).
///
/// Uses Acquire ordering to pair with the Release store in init_invpcid_support().
#[inline]
fn is_invpcid_available() -> bool {
    INVPCID_SUPPORTED.load(Ordering::Acquire)
}

/// Check if CR4.PCIDE is enabled on the current CPU (CR4 bit 17).
///
/// R74-1 Enhancement: The `mm` crate cannot depend on the `security` crate's
/// `is_pcid_enabled()` helper (would create cyclic dependency), so we read
/// CR4 directly. This is a CPU-local check and doesn't require synchronization.
#[inline]
fn is_pcid_enabled() -> bool {
    Cr4::read().contains(Cr4Flags::PCID)
}

/// Flush all PCID-tagged TLB translations on CPUs without INVPCID.
///
/// # R74-1 Enhancement: Non-INVPCID PCID-Wide Flush
///
/// When PCID is enabled but INVPCID is not available, a standard CR3 reload
/// only flushes TLB entries for the *current* PCID. Stale entries for other
/// PCIDs may remain, creating a security vulnerability where:
///
/// 1. CPU1 runs process A (PCID=5), caches TLB entry for 0x1000
/// 2. CPU1 switches to process B (PCID=3), TLB entry for PCID=5 retained
/// 3. Process A unmaps 0x1000, sends TLB shootdown to CPU1
/// 4. CPU1 does CR3 reload, but only flushes PCID=3 (current), not PCID=5
/// 5. CPU1 switches back to process A (PCID=5), stale TLB entry active
/// 6. Process A can access freed memory → Use-after-free
///
/// # Intel SDM Vol. 3A Section 4.10.4.1 Fix
///
/// Clearing CR4.PCIDE invalidates ALL TLB entries for ALL PCIDs. The sequence:
/// 1. Save original CR3 (with PCID in bits [11:0]) and CR4
/// 2. Write CR3 with [11:0]=0 (required before toggling PCIDE)
/// 3. Clear CR4.PCIDE → invalidates all TLB entries for all PCIDs
/// 4. Reload CR3 to serialize the flush
/// 5. Restore CR4.PCIDE (safe now: CR3[11:0]=0)
/// 6. Restore CR3 with original PCID
///
/// # Safety
///
/// - Must be called with interrupts disabled (IPI handler context or wrapped
///   in `without_interrupts()`)
/// - Modifies CR3/CR4 which affects page translation
/// - All kernel mappings must remain valid throughout
/// - Intel SDM requirement: CR3[11:0] must be 0 when toggling CR4.PCIDE
///
/// R114-4 FIX: Callers MUST ensure interrupts are disabled. An interrupt between
/// CR4.PCIDE clear (step 2) and restore (step 4) would find inconsistent CR3/CR4
/// state, potentially corrupting page translation or causing a context switch with
/// PCID disabled. Debug assertion enforces this contract.
///
/// NOTE: This function is NOT NMI-safe. A non-maskable interrupt during CR4.PCIDE
/// manipulation could observe inconsistent page translation state. NMI handlers
/// must only access kernel-space mappings, which remain valid throughout this
/// sequence. The window is extremely small (4 control register writes).
#[inline]
unsafe fn flush_all_pcid_without_invpcid() {
    // R114-4 FIX: Assert interrupts are disabled to catch contract violations in debug builds.
    debug_assert!(
        !x86_64::instructions::interrupts::are_enabled(),
        "flush_all_pcid_without_invpcid: interrupts must be disabled during CR3/CR4 manipulation"
    );
    // Read current CR3 with PCID bits preserved (u16 contains PCID value 0-4095)
    let (frame, raw_pcid) = Cr3::read_raw();

    // Read current CR4
    let cr4 = Cr4::read();

    // Step 1: Ensure CR3[11:0]=0 before touching PCIDE (Intel SDM requirement)
    // Using empty() flags - no cache flags when PCID is in use
    Cr3::write(frame, Cr3Flags::empty());

    // Step 2: Clear CR4.PCIDE
    // Intel SDM: "If CR4.PCIDE was 1 before the MOV to CR4, any TLB entries
    // established with any PCID are invalidated."
    let mut cr4_no_pcid = cr4;
    cr4_no_pcid.remove(Cr4Flags::PCID);
    Cr4::write(cr4_no_pcid);

    // Step 3: Reload CR3 to serialize the invalidation (PCIDE=0, low bits=0)
    Cr3::write(frame, Cr3Flags::empty());

    // Step 4: Restore CR4.PCIDE
    // Intel SDM: "Software can set CR4.PCIDE to 1 only if CR3[11:0] = 000H"
    // CR3[11:0] is 0 from the write above, so this is safe
    Cr4::write(cr4);

    // Step 5: Restore original CR3 with PCID
    // This sets up the correct PCID for the current execution context
    Cr3::write_raw(frame, raw_pcid);
}

/// Flush all non-global TLB entries locally, using INVPCID if available.
///
/// This is more efficient than CR3 reload when INVPCID type 2 is available,
/// as it doesn't require reading/writing CR3.
///
/// # R74-1 Enhancement: PCID-Aware Flush
///
/// Three code paths:
/// 1. **INVPCID available**: Use INVPCID type 2 (most efficient, flushes all PCIDs)
/// 2. **PCID enabled, no INVPCID**: Toggle CR4.PCIDE to flush all PCIDs
/// 3. **No PCID**: Standard CR3 reload (fastest, no PCID tracking overhead)
///
///    R115-4 FIX: Made `pub` to allow other kernel crates (security, arch) to use
///    the PCID-aware flush path instead of raw `tlb::flush_all()`.
///
/// This is the **single flush API** that all kernel code should use for local
/// TLB invalidation. Direct calls to `x86_64::instructions::tlb::flush_all()`
/// bypass PCID generation tracking and may leave stale entries.
#[inline]
pub fn flush_all_local() {
    if is_invpcid_available() {
        // INVPCID type 2: flush all non-global entries for all PCIDs
        // Most efficient path - single instruction
        unsafe { invpcid_all_nonglobal() };
    } else if is_pcid_enabled() {
        // R74-1 Enhancement: PCID without INVPCID
        // Toggle CR4.PCIDE to invalidate all PCID-tagged translations
        // More expensive (4 control register writes) but necessary for correctness
        //
        // R114-4 FIX: Wrap in without_interrupts() to satisfy the IRQ-disabled contract.
        // An interrupt during CR3/CR4 manipulation would find inconsistent page translation
        // state, potentially causing page faults or TLB corruption in the interrupt handler.
        x86_64::instructions::interrupts::without_interrupts(|| {
            unsafe { flush_all_pcid_without_invpcid() };
        });
    } else {
        // No PCID: standard CR3 reload flushes all non-global TLB entries
        // This is the legacy path for older CPUs
        tlb::flush_all();
    }
}

/// Register a CPU as online (legacy interface, uses current CPU ID).
///
/// This function MUST be called by the SMP bring-up code when each AP (Application Processor)
/// is initialized. The BSP (Boot Strap Processor) is already counted (initial value is 1).
///
/// # Safety
///
/// This function is safe to call from any context, but should only be called once per CPU
/// during SMP initialization.
pub fn register_cpu_online() {
    let cpu_id = try_current_registered_cpu_id()
        .expect("cannot publish TLB online state for an unregistered LAPIC identity");
    register_cpu_online_with_id(cpu_id);
}

/// Register a specific CPU as online by its ID.
///
/// This is the preferred interface when the CPU ID is known (e.g., from AP trampoline data).
/// Delegates the corresponding online publication to cpu_local's authoritative
/// mask with its serialized lifecycle ordering.
///
/// # Arguments
///
/// * `cpu_id` - The logical CPU index (0 = BSP, 1+ = APs)
pub fn register_cpu_online_with_id(cpu_id: usize) {
    // `cpu_local` owns the lifecycle transaction and validates the reciprocal
    // LAPIC registration under its topology lock. Keeping this compatibility
    // entry point as a delegation prevents TLB/IPI and KCOV from observing
    // different online masks or a duplicate-only count increment.
    cpu_local::mark_cpu_online_with_id(cpu_id);
}

/// Check if a specific CPU is marked as online.
///
/// Reads cpu_local's authoritative registered-and-online bitmap.
///
/// # R68-6 FIX: Made public for IPI layer
///
/// The IPI layer needs to check online status before sending IPIs to avoid targeting
/// CPUs that have LAPIC IDs registered but haven't completed initialization yet.
#[inline]
pub fn is_cpu_online(cpu_id: usize) -> bool {
    cpu_local::is_cpu_online(cpu_id)
}

/// Get the number of online CPUs.
///
/// Returns the current count of online CPUs. Useful for debugging and SMP validation.
pub fn online_cpu_count() -> u64 {
    cpu_local::num_online_cpus() as u64
}

// ============================================================================
// CR3 Tracking for Optimized TLB Shootdown
// ============================================================================

/// Record that a non-zero PCID (1..=4095) has been allocated or loaded.
///
/// Fail-closed H4 gate: once latched, `collect_target_cpus` falls back to
/// broadcast shootdowns so stale TLB entries retained under another PCID on a
/// remote CPU can never be skipped.
#[inline]
pub fn note_nonzero_pcid_in_use() {
    NONZERO_PCID_ACTIVE.store(true, Ordering::Release);
}

#[inline]
fn is_nonzero_pcid_active() -> bool {
    NONZERO_PCID_ACTIVE.load(Ordering::Acquire)
}

#[inline]
fn current_cr3_pcid() -> u16 {
    if is_pcid_enabled() {
        Cr3::read_raw().1 & 0x0FFF
    } else {
        0
    }
}

/// Publish the next CR3 BEFORE loading it, with interrupts disabled. The
/// serializing CR3 write flushes translations after publication; until then no
/// user address may be accessed. Paired with the target scan's fence, either
/// the requester sees this CPU or the new root load sees its PTE changes.
/// No lock, allocation, or lazy initialization is reachable here.
pub fn track_cr3_switch(new_cr3: u64) {
    if (new_cr3 & 0x0FFF) != 0 {
        note_nonzero_pcid_in_use();
    }
    let canonical = new_cr3 & !0x0FFF;
    let cpu_id = current_cpu_id();
    if let Some(slot) = CPU_ACTIVE_CR3.get(cpu_id) {
        slot.0.store(canonical, Ordering::SeqCst);
    }
}

/// Publish this CPU's currently active CR3 root and serialize with a local
/// CR3 reload (flushing any pre-publication non-global TLB entries).
///
/// Must be called on the BSP before SMP bring-up and on each AP with `IF=0`
/// strictly before `register_cpu_online()` so no online CPU lingers in the
/// untracked `0` state.
pub fn track_current_cr3() {
    x86_64::instructions::interrupts::without_interrupts(|| {
        if is_pcid_enabled() {
            let (frame, raw) = Cr3::read_raw();
            let pcid = raw & 0x0FFF;
            if pcid != 0 {
                note_nonzero_pcid_in_use();
            }
            track_cr3_switch(frame.start_address().as_u64());
            unsafe {
                Cr3::write_raw(frame, pcid);
            }
        } else {
            let (frame, flags) = Cr3::read();
            track_cr3_switch(frame.start_address().as_u64());
            unsafe {
                Cr3::write(frame, flags);
            }
        }
    });
}

/// Run bounded usercopy in a retained foreign address space, tracking both
/// entry and restoration. Long callbacks must service the shootdown mailbox
/// while interrupts are disabled, and must not take locks that require IRQs.
///
/// # Safety
/// The target root must remain alive throughout the callback. Both roots must
/// map the kernel and current stack identically. The callback must not schedule.
pub unsafe fn with_temporary_address_space<R>(
    target: x86_64::structures::paging::PhysFrame,
    f: impl FnOnce() -> R,
) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| {
        struct RestoreRoot(x86_64::structures::paging::PhysFrame, Cr3Flags);
        impl Drop for RestoreRoot {
            fn drop(&mut self) {
                track_cr3_switch(self.0.start_address().as_u64());
                unsafe {
                    Cr3::write(self.0, self.1);
                }
                // A request queued while IF=0 must be acknowledged before the
                // caller resumes; this also handles foreign-root COW faults.
                handle_shootdown_ipi();
            }
        }
        let (saved, flags) = Cr3::read();
        let _restore = RestoreRoot(saved, flags);
        track_cr3_switch(target.start_address().as_u64());
        // Flush even for an equal root: a previously untracked CPU must not
        // carry translations from before its publication into the callback.
        unsafe {
            Cr3::write(target, flags);
        }
        handle_shootdown_ipi();
        f()
    })
}

/// Get the current CPU's tracked CR3 value.
///
/// Returns 0 if no CR3 has been tracked for this CPU yet.
#[inline]
pub fn current_cpu_cr3() -> u64 {
    tracked_cr3_for_cpu(current_cpu_id())
}

/// Issue #109 §4.2: read a specific CPU's tracked canonical CR3 root directly
/// without re-querying `current_cpu_id()`.
#[inline]
pub fn tracked_cr3_for_cpu(cpu_id: usize) -> u64 {
    CPU_ACTIVE_CR3
        .get(cpu_id)
        .map(|slot| slot.0.load(Ordering::Acquire))
        .unwrap_or(0)
}

/// Register the function used to send the TLB shootdown IPI.
///
/// This is called by the arch IPI layer to avoid a circular dependency from `mm` to `arch`.
/// Must be called during early boot before any TLB shootdown operations with SMP.
pub fn register_ipi_sender(sender: TlbIpiSender) {
    TLB_IPI_SENDER.store(sender as usize, Ordering::Release);
}

/// Get the registered IPI sender function, if any.
fn tlb_ipi_sender() -> Option<TlbIpiSender> {
    let ptr = TLB_IPI_SENDER.load(Ordering::Acquire);
    if ptr == 0 {
        None
    } else {
        // Safety: pointer was written from a real function in register_ipi_sender()
        Some(unsafe { mem::transmute::<usize, fn(usize)>(ptr) })
    }
}

/// Assert that we're in single-core mode or have IPI sender registered.
///
/// This function should be called at boot time or before any TLB shootdown
/// operation to ensure we don't silently run with broken SMP support.
///
/// # Panics
///
/// Panics if multiple CPUs are online but IPI sender is not registered.
#[inline]
fn assert_single_core_mode() {
    let cpu_count = cpu_local::num_online_cpus() as u64;
    if cpu_count > 1 && tlb_ipi_sender().is_none() {
        panic!(
            "TLB shootdown called with {} CPUs online but IPI sender not registered! \
             This is a critical bug - stale TLB entries may cause memory corruption. \
             Register the TLB IPI sender before enabling SMP.",
            cpu_count
        );
    }

    // Also check current CPU ID as a secondary guard
    let cpu_id = current_cpu_id();
    if cpu_id != 0 && tlb_ipi_sender().is_none() {
        panic!(
            "TLB shootdown called on CPU {} but IPI sender not registered! \
             This is a critical bug - stale TLB entries may cause memory corruption.",
            cpu_id
        );
    }
}

/// Get the current CR3 value (page table base)
#[inline]
fn current_cr3_value() -> u64 {
    Cr3::read().0.start_address().as_u64()
}

/// Get a reference to a specific CPU's TLB shootdown mailbox
fn mailbox_for_cpu(cpu_id: usize) -> Option<&'static TlbShootdownMailbox> {
    PER_CPU_DATA.get_cpu(cpu_id).map(|data| data.tlb_mailbox())
}

/// Force-initialize the per-CPU mailbox storage used by every shootdown path.
///
/// `CpuLocal` allocates its fixed slot array on first access. Callers that must
/// guarantee an allocation-free TLB flush after committing page-table state
/// invoke this in process/boot context before beginning that transaction.
pub fn force_init_tlb_shootdown_locals() {
    PER_CPU_DATA.force_init();
}

/// H1 (Issue #109 §1.2): resolve the canonical address-space root (`kernel_cr3`)
/// for a shootdown initiated on `self_id`.
///
/// Returns `0` (forcing a fail-closed broadcast) if hardware CR3 disagrees with
/// `CPU_ACTIVE_CR3[self_id]` in any way other than a consistent KPTI dual-root
/// Ring-3 `#PF` (where hardware CR3 is `kpti_user_cr3` while the tracked
/// canonical root is `kpti_kernel_cr3`).
#[inline]
fn resolve_canonical_shootdown_cr3(
    hw_cr3: u64,
    tracked_cr3: u64,
    kpti_snapshot: Option<(u64, u64)>,
) -> u64 {
    let hw = hw_cr3 & !0x0FFF;
    let tracked = tracked_cr3 & !0x0FFF;
    if hw == 0 {
        return 0;
    }
    if hw == tracked {
        return hw;
    }
    if tracked != 0 {
        if let Some((user_cr3, kernel_cr3)) = kpti_snapshot {
            if hw == (user_cr3 & !0x0FFF) && tracked == (kernel_cr3 & !0x0FFF) {
                return tracked;
            }
        }
    }
    0
}

/// Resolve the canonical shootdown CR3 on the pinned current CPU `self_id`.
///
/// Fast path (`hw_cr3 == tracked_cr3 != 0`) avoids touching `PER_CPU_DATA`.
/// On mismatch (e.g. Ring-3 `#PF` CoW running on KPTI `user_cr3`), takes a
/// single non-blocking seqlock snapshot of `(kpti_user_cr3, kpti_kernel_cr3)`;
/// any concurrent update or unexpected mismatch fails closed to `0` (broadcast).
#[inline]
fn canonical_shootdown_cr3(self_id: usize) -> u64 {
    let hw_cr3 = current_cr3_value();
    let tracked_cr3 = CPU_ACTIVE_CR3
        .get(self_id)
        .map(|slot| slot.0.load(Ordering::SeqCst))
        .unwrap_or(0);
    if hw_cr3 != 0 && hw_cr3 == tracked_cr3 {
        return hw_cr3;
    }
    let kpti_snapshot = PER_CPU_DATA.get_cpu(self_id).and_then(|pcpu| {
        let seq1 = pcpu.kpti_seq.load(Ordering::Acquire);
        if (seq1 & 1) != 0 {
            return None;
        }
        let user_cr3 = pcpu.kpti_user_cr3.load(Ordering::Acquire);
        let kernel_cr3 = pcpu.kpti_kernel_cr3.load(Ordering::Acquire);
        let seq2 = pcpu.kpti_seq.load(Ordering::Acquire);
        if seq1 == seq2 {
            Some((user_cr3, kernel_cr3))
        } else {
            None
        }
    });
    resolve_canonical_shootdown_cr3(hw_cr3, tracked_cr3, kpti_snapshot)
}

/// H3 (Issue #109 §1.2): return true if `[start, start + len)` touches the
/// non-canonical hole, overflows, or overlaps the shared kernel high-half.
#[inline]
fn range_touches_kernel_half(start: VirtAddr, len: usize) -> bool {
    let s = start.as_u64();
    if s >= USER_HALF_END {
        return true;
    }
    match s.checked_add(len as u64) {
        Some(end) => end > USER_HALF_END,
        None => true,
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TargetSelectionKind {
    TargetedIpi,
    TargetedZeroIpi,
    BroadcastFallback,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct TargetSelection {
    targets: CpuMask,
    kind: TargetSelectionKind,
}

/// Pure target-CPU selection logic shared by production shootdowns and hosted
/// unit tests (Issue #109 §1.2).
///
/// # Safety Contract (RF178-33)
///
/// Caller must have issued `fence(Ordering::SeqCst)` after mutating PTEs and
/// before invoking `read_active_cr3` (which must load with `Ordering::SeqCst`).
fn select_target_cpus_from_state(
    target_cr3: u64,
    self_id: usize,
    online_mask: u64,
    max_tracked: usize,
    nonzero_pcid_active: bool,
    mut has_lapic: impl FnMut(usize) -> bool,
    mut read_active_cr3: impl FnMut(usize) -> u64,
) -> TargetSelection {
    let mut targets = CpuMask::empty();
    let remote_online = if self_id < u64::BITS as usize {
        online_mask & !(1u64 << self_id)
    } else {
        online_mask
    };

    // Broadcast when requested explicitly (CR3=0, e.g. shared kernel mappings
    // or fail-closed canonical CR3 resolution) or when non-zero PCIDs are in
    // use (H4 fail-closed guard).
    if target_cr3 == 0 || nonzero_pcid_active {
        let mut remaining = remote_online;
        while remaining != 0 {
            let cpu = remaining.trailing_zeros() as usize;
            remaining &= remaining - 1;
            if cpu < max_tracked && has_lapic(cpu) {
                targets.insert(cpu);
            }
        }
        return TargetSelection {
            targets,
            kind: TargetSelectionKind::BroadcastFallback,
        };
    }

    // Targeted sparse scan over online remote CPUs only.
    // Fail-closed (H2): any online remote CPU with tracked CR3 == 0 (untracked)
    // is conservatively included. Only CPUs proven to hold a different non-zero
    // CR3 (`seen != 0 && seen != target_cr3`) are skipped.
    let mut remaining = remote_online;
    while remaining != 0 {
        let cpu = remaining.trailing_zeros() as usize;
        remaining &= remaining - 1;
        if cpu >= max_tracked || !has_lapic(cpu) {
            continue;
        }
        let seen = read_active_cr3(cpu);
        if seen == 0 || seen == target_cr3 {
            targets.insert(cpu);
        }
    }

    let kind = if targets.is_empty() {
        TargetSelectionKind::TargetedZeroIpi
    } else {
        TargetSelectionKind::TargetedIpi
    };
    TargetSelection { targets, kind }
}

/// Collect target CPUs for TLB shootdown based on address space tracking.
///
/// RF178-33 + Issue #109 §1.2: Uses a sparse scan over `online_cpu_mask()` of
/// 64B-aligned per-CPU `SeqCst` CR3 snapshots. When every remote online CPU is
/// tracked on a different non-zero CR3 (and PCID=0/NOFLUSH=0 holds), returns an
/// empty `CpuMask` (0 remote IPIs) instead of broadcasting. Untracked (`0`)
/// remote CPUs, `target_cr3 == 0`, and non-zero PCIDs all fail closed.
fn collect_target_cpus(target_cr3: u64) -> CpuMask {
    core::sync::atomic::fence(Ordering::SeqCst);
    let self_id = current_cpu_id();
    let online = cpu_local::online_cpu_mask();
    let max_tracked = core::cmp::min(max_cpus(), 64);

    let mut nonzero_pcid = is_nonzero_pcid_active();
    if !nonzero_pcid && current_cr3_pcid() != 0 {
        note_nonzero_pcid_in_use();
        nonzero_pcid = true;
    }

    let selection = select_target_cpus_from_state(
        target_cr3,
        self_id,
        online,
        max_tracked,
        nonzero_pcid,
        |cpu| lapic_id_for_cpu(cpu).is_some(),
        |cpu| CPU_ACTIVE_CR3[cpu].0.load(Ordering::SeqCst),
    );

    match selection.kind {
        TargetSelectionKind::TargetedIpi => {
            STATS_TARGETED_SHOOTDOWNS.fetch_add(1, Ordering::Relaxed);
        }
        TargetSelectionKind::TargetedZeroIpi => {
            STATS_TARGETED_SHOOTDOWNS.fetch_add(1, Ordering::Relaxed);
            STATS_TARGETED_ZERO_IPI.fetch_add(1, Ordering::Relaxed);
        }
        TargetSelectionKind::BroadcastFallback => {
            STATS_BROADCAST_FALLBACK.fetch_add(1, Ordering::Relaxed);
        }
    }

    selection.targets
}

/// Enqueue a TLB shootdown request into a CPU's mailbox queue.
///
/// # R72: Queue-Based Mailbox
///
/// Instead of spin-waiting for the previous request to be ACKed before posting,
/// this enqueues the request into a bounded ring buffer. The queue allows multiple
/// requests to be batched, reducing serialization and IPI overhead.
///
/// # Issue #109 §1.1 (H2): Per-Mailbox FIFO Completion Ticket
///
/// Under split per-address-space page-table locks, multiple CPUs can enqueue
/// shootdowns to the same target mailbox concurrently. Returning the target
/// mailbox's strictly monotonic FIFO ticket (`tail + 1`) from the CAS ensures
/// `wait_for_acks` waits until `mailbox.head >= ticket`, preventing an
/// out-of-order global generation from prematurely acknowledging an entry
/// that the consumer has not yet flushed.
///
/// # R106-5 FIX: Graceful Fallback on Saturation
///
/// Returns `Some(ticket)` on enqueue, or `None` when the queue is saturated so
/// the caller falls back to a full-flush `request_gen` epoch.
/// Issue #109 rollup audit (ASTRA-2): Drain any pending shootdown requests
/// targeting this CPU while spinning on a remote mailbox or ACK wait.
///
/// Under split page-table locks (`AS_PT_LOCKS` + `KERNEL_PT_LOCK`), two CPUs
/// can concurrently execute `IF=0` page-table transactions and shoot down each
/// other (e.g., per-AS CoW fault vs shared kernel-stack rollback). Masking
/// interrupts around [`handle_shootdown_ipi`] preserves its single-consumer
/// invariant whether the caller entered with `IF=0` or `IF=1`, without ever
/// enabling interrupts inside a protected page-table critical section.
#[inline]
fn drain_local_mailbox_while_waiting() {
    #[cfg(not(test))]
    {
        x86_64::instructions::interrupts::without_interrupts(|| {
            handle_shootdown_ipi();
        });
    }
}

fn enqueue_mailbox(mailbox: &TlbShootdownMailbox, cr3: u64, start: u64, len: u64) -> Option<u64> {
    const MAILBOX_WAIT_SPINS: usize = 500_000;
    let mut spins = 0usize;

    loop {
        let head = mailbox.head.load(Ordering::Acquire);
        let tail = mailbox.tail.load(Ordering::Acquire);

        // Check if queue has space: tail - head < queue_len
        if tail.wrapping_sub(head) < TLB_SHOOTDOWN_QUEUE_LEN as u64 {
            // Try to claim a slot with CAS on tail
            if mailbox
                .tail
                .compare_exchange_weak(tail, tail + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                let ticket = tail.wrapping_add(1);
                let pub_marker = if ticket == 0 { 1 } else { ticket };
                // Successfully claimed slot, write entry
                let slot = (tail as usize) % TLB_SHOOTDOWN_QUEUE_LEN;
                let entry = &mailbox.entries[slot];

                // Write entry fields with Relaxed ordering
                entry.cr3.store(cr3, Ordering::Relaxed);
                entry.start.store(start, Ordering::Relaxed);
                entry.len.store(len, Ordering::Relaxed);

                // Publish entry by storing non-zero marker with Release
                entry.generation.store(pub_marker, Ordering::Release);
                return Some(ticket);
            }
            // CAS failed, retry
        } else {
            // Queue is full, need to wait — service our own mailbox first so a
            // reciprocal IF=0 shootdown sender waiting on us can make progress.
            drain_local_mailbox_while_waiting();
            spins += 1;
            if spins.is_multiple_of(100_000) {
                kprintln!(
                    "[TLB] CPU shootdown queue full, waiting (head={}, tail={}, spins={})",
                    head,
                    tail,
                    spins
                );
            }
            if spins >= MAILBOX_WAIT_SPINS {
                // R106-5 FIX: Graceful fallback instead of panic.
                // Under runtime pressure (rapid mmap/munmap), signal the caller
                // to perform a full TLB flush rather than crashing the kernel.
                klog!(
                    Warn,
                    "[TLB][R106-5] shootdown mailbox saturated (head={}, tail={}) after {} spins; falling back to full flush",
                    head,
                    tail,
                    MAILBOX_WAIT_SPINS
                );
                return None;
            }
        }

        spin_loop();
    }
}

/// Post shootdown requests to all target CPUs' mailboxes.
///
/// Returns `(fallback_cpus, target_tickets)` where `target_tickets[cpu]` holds:
/// - for normal queued entries (`cpu` not in `fallback_cpus`): the per-mailbox
///   FIFO completion ticket (`tail + 1`), completed when `head >= ticket`;
/// - for saturated-mailbox fallbacks (`cpu` in `fallback_cpus`): the per-mailbox
///   atomic fallback epoch (`request_gen.fetch_add(1) + 1`), completed when
///   `ack_gen >= ticket`.
fn post_requests(targets: CpuMask, cr3: u64, start: u64, len: u64) -> (CpuMask, [u64; 64]) {
    let mut fallback_cpus = CpuMask::empty();
    let mut target_tickets = [0u64; 64];
    for cpu in targets.iter() {
        // R94-8 FIX: A target CPU MUST have an initialized mailbox. If it doesn't,
        // this is a critical per-CPU initialization failure that would silently skip
        // TLB flushes, risking use-after-free from stale TLB entries.
        let mailbox = mailbox_for_cpu(cpu).unwrap_or_else(|| {
            panic!(
                "TLB shootdown: CPU {} is in target set but has no mailbox. \
                 This indicates a critical per-CPU initialization failure.",
                cpu
            )
        });
        if let Some(ticket) = enqueue_mailbox(mailbox, cr3, start, len) {
            target_tickets[cpu] = ticket;
        } else {
            // R106-5 + Issue #109 §1.1 (H2): Queue saturated for this CPU.
            // Atomically mint a strictly-increasing per-mailbox fallback epoch
            // so concurrent MPSC saturated senders can never suffer an
            // out-of-order global generation race on `ack_gen`.
            let fallback_ticket = mailbox.request_gen.fetch_add(1, Ordering::AcqRel) + 1;
            target_tickets[cpu] = fallback_ticket;
            STATS_COALESCED_FALLBACKS.fetch_add(1, Ordering::Relaxed);
            fallback_cpus.insert(cpu);
        }
    }
    (fallback_cpus, target_tickets)
}

/// Send TLB shootdown IPIs to all target CPUs
fn send_ipis(targets: CpuMask, sender: TlbIpiSender) {
    for cpu in targets.iter() {
        sender(cpu);
        STATS_SHOOTDOWN_IPIS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Number of retry attempts for ACK timeout before panicking
const ACK_TIMEOUT_RETRIES: usize = 3;

/// Issue #109 §1.1 (H2): Check whether `mailbox` has completed this sender's
/// shootdown request. Normal queued requests complete strictly when `head >= ticket`;
/// saturated-mailbox fallbacks complete strictly when `ack_gen >= ticket`.
#[inline]
fn target_mailbox_completed(mailbox: &TlbShootdownMailbox, ticket: u64, is_fallback: bool) -> bool {
    if is_fallback {
        mailbox.ack_gen.load(Ordering::Acquire) >= ticket
    } else {
        mailbox.head.load(Ordering::Acquire) >= ticket
    }
}

/// Wait for all target CPUs to acknowledge the shootdown request
///
/// Returns true if all ACKs received, false on timeout.
///
/// # R93-9 FIX: Fail-Closed ACK Handling
///
/// Missing mailboxes return `false` (fail-closed) so no target CPU is ever skipped.
fn wait_for_acks(dispatch: &ShootdownDispatch) -> bool {
    for _ in 0..IPI_ACK_TIMEOUT_SPINS {
        let all_acked = dispatch.targets.iter().all(|cpu| {
            let is_fallback = (dispatch.fallback_cpus.0 & (1u64 << cpu)) != 0;
            mailbox_for_cpu(cpu)
                .map(|m| target_mailbox_completed(m, dispatch.target_tickets[cpu], is_fallback))
                // R93-9 FIX: Fail-closed - missing mailbox means NOT acked
                .unwrap_or(false)
        });
        if all_acked {
            // R175 D0-CROSS-2 FIX: Explicit Release fence ensures all prior writes
            // (including the Acquire-synchronized TLB flush side effects) are visible
            // globally before caller proceeds to deallocate frames. Required for
            // non-TSO architectures (ARM, RISC-V) and formal verification soundness.
            // On x86-64 TSO this is a no-op but documents the happens-before contract.
            core::sync::atomic::fence(Ordering::Release);
            return true;
        }
        // ASTRA-2 FIX: Service pending shootdowns targeting this CPU so
        // concurrent IF=0 holders of disjoint PT locks (e.g. AS_PT_LOCKS vs
        // KERNEL_PT_LOCK) never deadlock waiting on each other's ACKs.
        drain_local_mailbox_while_waiting();
        spin_loop();
    }
    false
}

/// Get a mask of CPUs that haven't ACKed yet
fn get_unacked_cpus(dispatch: &ShootdownDispatch) -> CpuMask {
    let mut unacked = CpuMask::empty();
    for cpu in dispatch.targets.iter() {
        let is_fallback = (dispatch.fallback_cpus.0 & (1u64 << cpu)) != 0;
        let done = mailbox_for_cpu(cpu)
            .map(|m| target_mailbox_completed(m, dispatch.target_tickets[cpu], is_fallback))
            // R93-9 FIX: Fail-closed - missing mailbox means NOT acked
            .unwrap_or(false);
        if !done {
            unacked.insert(cpu);
        }
    }
    unacked
}

/// Wait for ACKs with retry support
///
/// Codex review fix: On timeout, resends IPIs and retries before failing.
/// After ACK_TIMEOUT_RETRIES attempts, panics in debug builds or warns in release.
fn wait_for_acks_with_retry(dispatch: &ShootdownDispatch, sender: TlbIpiSender) -> bool {
    for attempt in 0..=ACK_TIMEOUT_RETRIES {
        if wait_for_acks(dispatch) {
            return true;
        }

        // Get unacked CPUs for retry/logging
        let unacked = get_unacked_cpus(dispatch);
        if unacked.is_empty() {
            return true; // All acked now
        }

        if attempt < ACK_TIMEOUT_RETRIES {
            // Resend IPIs to unacked CPUs
            send_ipis(unacked, sender);
        } else {
            // Final timeout - this is a critical error
            kprintln!(
                "[CRITICAL] TLB shootdown gen {} failed after {} retries. CPUs not responding: {:?}",
                dispatch.generation,
                ACK_TIMEOUT_RETRIES,
                unacked
            );

            // In debug builds, panic to catch the issue early
            #[cfg(debug_assertions)]
            panic!(
                "TLB shootdown timeout: CPUs {:?} not responding. \
                 This is a critical SMP bug - stale TLB entries may cause memory corruption.",
                unacked
            );

            // In release builds, continue with warning (safer than hard panic)
            // The TLB may be stale on some CPUs, but panicking could cause worse issues
            #[cfg(not(debug_assertions))]
            return false;
        }
    }
    false
}

#[allow(dead_code)]
/// Warn about timeout waiting for ACKs (non-fatal, for debugging)
fn warn_timeout(dispatch: &ShootdownDispatch) {
    #[allow(unused_variables)]
    let missing = get_unacked_cpus(dispatch);

    kprintln!(
        "[WARN] TLB shootdown gen {} timed out waiting for ACK from CPUs {:?}",
        dispatch.generation,
        missing
    );
}

/// Dispatch a TLB shootdown to remote CPUs
struct ShootdownDispatch {
    targets: CpuMask,
    generation: u64,
    /// R106-5: CPUs that couldn't be enqueued (mailbox full); need full-flush fallback
    fallback_cpus: CpuMask,
    /// Issue #109 §1.1 (H2): per-target completion ticket (`head >= ticket` for
    /// queued entries, `ack_gen >= ticket` for saturated fallbacks).
    target_tickets: [u64; 64],
}

fn dispatch_shootdown_for_cr3(target_cr3: u64, start: u64, len: u64) -> Option<ShootdownDispatch> {
    // R68 optimization: Use per-address-space tracking to target only relevant CPUs.
    // target_cr3 == 0 deliberately broadcasts to every online CPU for shared
    // kernel mappings that are reachable through multiple distinct CR3 roots.
    let targets = collect_target_cpus(target_cr3);
    if targets.is_empty() {
        return None;
    }

    let sender = tlb_ipi_sender().unwrap_or_else(|| {
        panic!(
            "TLB shootdown requested for CPUs {:?} but no IPI sender registered",
            targets
        )
    });

    let generation = next_shootdown_generation();

    // Post requests to all target mailboxes. Under mailbox saturation this may
    // return a list of CPUs that need a full-flush fallback (R106-5).
    let (fallback_cpus, target_tickets) = post_requests(targets, target_cr3, start, len);

    // Send IPIs to wake up targets
    send_ipis(targets, sender);

    Some(ShootdownDispatch {
        targets,
        generation,
        fallback_cpus,
        target_tickets,
    })
}

#[inline]
fn dispatch_shootdown(self_id: usize, start: u64, len: u64) -> Option<ShootdownDispatch> {
    dispatch_shootdown_for_cr3(canonical_shootdown_cr3(self_id), start, len)
}

/// Range operation type for flush optimization
enum RangeOp {
    /// Full TLB flush
    Full,
    /// Range flush with specific pages
    Pages { start: u64, len: u64, pages: u64 },
}

/// Normalize a virtual address range for TLB flushing
fn normalize_range(start: VirtAddr, len: usize) -> RangeOp {
    let start_aligned = start.align_down(PAGE_SIZE);
    let end = match start.as_u64().checked_add(len as u64) {
        Some(e) => e,
        None => return RangeOp::Full, // Overflow: full flush
    };

    let end_aligned = (end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let bytes = end_aligned.saturating_sub(start_aligned.as_u64());
    let pages = bytes / PAGE_SIZE;

    if pages == 0 || pages > FULL_FLUSH_THRESHOLD {
        RangeOp::Full
    } else {
        RangeOp::Pages {
            start: start_aligned.as_u64(),
            len: bytes,
            pages,
        }
    }
}

/// Flush a range of pages locally
fn flush_range_local(start: u64, len: u64) {
    if len == 0 {
        return;
    }
    // R188-U26-3 FIX: normalize at the callee boundary.  Release callers may
    // provide an unaligned start/length; a debug-only assertion previously
    // caused the final partial page to be skipped in production.
    let aligned_start = start & !(PAGE_SIZE - 1);
    let Some(end) = start.checked_add(len) else {
        flush_all_local();
        return;
    };
    let Some(aligned_end) = end.checked_add(PAGE_SIZE - 1) else {
        flush_all_local();
        return;
    };
    let aligned_end = aligned_end & !(PAGE_SIZE - 1);
    let mut addr_raw = aligned_start;
    while addr_raw < aligned_end {
        let addr = VirtAddr::new(addr_raw);
        tlb::flush(addr);
        addr_raw = match addr_raw.checked_add(PAGE_SIZE) {
            Some(next) => next,
            None => break,
        };
    }
}

/// P2-7 FIX: Pin execution to a stable CPU for TLB shootdown operations.
///
/// Under eventual preemption/migration support, a task performing a TLB
/// shootdown could migrate between dispatching IPIs and ACKing its own
/// mailbox. This would cause:
/// - Target set computed on CPU A but self-ACK on CPU B (wrong mailbox)
/// - Missed local TLB flush if range partially completed before migration
/// - Stale per-CPU mailbox reference pointing to wrong CPU's data
///
/// The pin guard disables preemption after verifying the CPU ID is stable,
/// using a retry loop to handle the race window between LAPIC ID read and
/// preempt_disable(). Preemption is re-enabled on drop.
struct ShootdownCpuPin {
    cpu_id: usize,
    /// PhantomData<*const ()> makes this type !Send + !Sync, preventing
    /// accidental cross-thread/cross-CPU movement or drop.
    _not_send: core::marker::PhantomData<*const ()>,
}

impl ShootdownCpuPin {
    #[inline]
    fn new() -> Self {
        loop {
            let cpu_id = current_cpu_id();

            // Narrow the race window: if we were already migrated after
            // sampling cpu_id, retry without touching the stale CPU's
            // preemption counter.
            if current_cpu_id() != cpu_id {
                spin_loop();
                continue;
            }

            let per_cpu = PER_CPU_DATA.get_cpu(cpu_id).unwrap_or_else(|| {
                panic!("TLB shootdown: missing per-CPU slot for CPU {}", cpu_id)
            });

            per_cpu.preempt_disable();
            core::sync::atomic::compiler_fence(Ordering::SeqCst);

            if current_cpu_id() == cpu_id {
                return Self {
                    cpu_id,
                    _not_send: core::marker::PhantomData,
                };
            }

            // Migration detected — undo and retry on the correct CPU.
            core::sync::atomic::compiler_fence(Ordering::SeqCst);
            per_cpu.preempt_enable();
            spin_loop();
        }
    }

    #[inline]
    fn cpu_id(&self) -> usize {
        self.cpu_id
    }
}

impl Drop for ShootdownCpuPin {
    #[inline]
    fn drop(&mut self) {
        let per_cpu = PER_CPU_DATA.get_cpu(self.cpu_id).unwrap_or_else(|| {
            panic!(
                "TLB shootdown: missing per-CPU slot for CPU {}",
                self.cpu_id
            )
        });
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        per_cpu.preempt_enable();
    }
}

/// Flush the entire TLB for the current address space on all CPUs.
///
/// This function should be called after modifying page table entries that
/// affect multiple pages or when the specific pages are not known.
///
/// # R23-1 Fix
///
/// Used in `copy_page_table_cow()` after marking parent PTEs as read-only.
/// Ensures all CPUs (in SMP) see the updated COW mappings.
///
/// # Safety
///
/// Safe to call from any context. In SMP mode, this may block waiting for
/// IPI acknowledgments.
#[inline]
pub fn flush_current_as_all() {
    flush_all_impl(false);
}

/// Flush non-global translations on every online CPU, independent of the CR3
/// currently active on that CPU.
///
/// R180-12 FIX: per-process kernel stacks live in shared high-half page-table
/// subtrees copied into many kernel and KPTI roots. Targeting only CPUs whose
/// active CR3 equals the caller's root can leave a stale translation under a
/// different root. A `target_cr3 == 0` mailbox request makes every receiver do
/// a full non-global flush and ACK before shared frames are reused.
#[inline]
pub fn flush_all_address_spaces() {
    flush_all_impl(true);
}

fn flush_all_impl(broadcast: bool) {
    // P2-7 FIX: Pin to a stable CPU for the entire shootdown operation.
    let _pin = ShootdownCpuPin::new();

    assert_single_core_mode();

    // Dispatch to remote CPUs (if any). Shared kernel mappings use CR3=0 to
    // force a true broadcast; ordinary callers resolve their canonical kernel
    // CR3 root (handling KPTI Ring-3 #PF dual roots and failing closed to 0 on
    // any unexpected mismatch).
    let target_cr3 = if broadcast {
        0
    } else {
        canonical_shootdown_cr3(_pin.cpu_id())
    };
    let shoot = dispatch_shootdown_for_cr3(target_cr3, 0, 0);

    // Flush local TLB immediately using INVPCID if available
    flush_all_local();

    // Wait for remote ACKs with retry support
    if let Some(ref dispatch) = shoot {
        // Get sender for retry
        if let Some(sender) = tlb_ipi_sender() {
            // R68-5 FIX: TLB shootdown failure is FATAL - stale TLB entries are unacceptable.
            if !wait_for_acks_with_retry(dispatch, sender) {
                let unacked = get_unacked_cpus(dispatch);
                panic!(
                    "CRITICAL: TLB shootdown gen {} failed! CPUs {:?} did not ACK. \
                     Cannot continue - stale TLB entries would cause memory corruption.",
                    dispatch.generation, unacked
                );
            }
        }
    }

    STATS_FULL_FLUSHES.fetch_add(1, Ordering::Relaxed);
}

/// Flush a range of pages from the TLB on all CPUs.
///
/// This function should be called after unmapping a range of pages,
/// before deallocating the underlying physical frames.
///
/// # Arguments
///
/// * `start` - Starting virtual address (will be page-aligned down)
/// * `len` - Length in bytes (will be rounded up to page boundary)
///
/// # R23-3 Fix
///
/// Used in `sys_munmap()` after unmapping pages but before freeing frames.
/// Ensures no CPU (in SMP) retains stale TLB entries pointing to freed frames.
///
/// # Safety
///
/// Safe to call from any context. In SMP mode, this may block waiting for
/// IPI acknowledgments.
pub fn flush_current_as_range(start: VirtAddr, len: usize) {
    assert_single_core_mode();

    // Issue #109 §1.2 (H3 defense-in-depth): shared kernel high-half mappings
    // (as well as non-canonical or overflowing ranges) are reachable through
    // every CR3 root and must always broadcast across all online CPUs, even
    // before `normalize_range` decides between page-range and full flush.
    if range_touches_kernel_half(start, len) {
        flush_all_address_spaces();
        return;
    }

    match normalize_range(start, len) {
        RangeOp::Full => {
            flush_current_as_all();
        }
        RangeOp::Pages {
            start: aligned_start,
            len: aligned_len,
            pages,
        } => {
            // P2-7 FIX: Pin to a stable CPU for the entire range shootdown.
            let _pin = ShootdownCpuPin::new();

            // Dispatch to remote CPUs
            let shoot = dispatch_shootdown(_pin.cpu_id(), aligned_start, aligned_len);

            // R106-5: Check if any target CPU's mailbox was saturated
            let needs_full_flush_fallback = shoot
                .as_ref()
                .map(|s| !s.fallback_cpus.is_empty())
                .unwrap_or(false);

            // Flush local TLB — use full flush if any mailbox was saturated
            if needs_full_flush_fallback {
                flush_all_local();
            } else {
                flush_range_local(aligned_start, aligned_len);
            }

            // Wait for remote ACKs with retry support
            if let Some(ref dispatch) = shoot {
                // Get sender for retry
                if let Some(sender) = tlb_ipi_sender() {
                    // R68-5 FIX: Range flush ACK failure is also fatal.
                    // Same reasoning as flush_current_as_all - cannot allow stale TLB.
                    if !wait_for_acks_with_retry(dispatch, sender) {
                        let unacked = get_unacked_cpus(dispatch);
                        panic!(
                            "CRITICAL: TLB shootdown gen {} (range 0x{:x}+0x{:x}) failed! \
                             CPUs {:?} did not ACK. Cannot continue.",
                            dispatch.generation, aligned_start, aligned_len, unacked
                        );
                    }
                }
            }

            // R106-5: Track stats based on whether fallback was used
            if needs_full_flush_fallback {
                STATS_FULL_FLUSHES.fetch_add(1, Ordering::Relaxed);
            } else {
                STATS_RANGE_FLUSHES.fetch_add(1, Ordering::Relaxed);
                STATS_PAGES_FLUSHED.fetch_add(pages, Ordering::Relaxed);
            }
        }
    }
}

/// Flush a single page from the TLB on all CPUs.
///
/// Convenience wrapper around `flush_current_as_range` for single pages.
///
/// # Arguments
///
/// * `addr` - Virtual address of the page to flush
#[inline]
pub fn flush_current_as_page(addr: VirtAddr) {
    flush_current_as_range(addr, 4096);
}

/// Flush a small batch of non-contiguous user pages in the current address
/// space with ONE `collect_target_cpus()` scan instead of one per page.
///
/// On single-threaded `fork()` (where no remote CPU runs the parent's CR3),
/// this cuts `N` cross-CPU `SeqCst` CR3-table scans down to 1 and runs only
/// local `invlpg`s. When any remote CPU shares the current CR3 (multi-threaded
/// `CLONE_VM` parent), falls back to a single batched `flush_current_as_all()`
/// so each remote target receives at most 1 shootdown IPI instead of `N`.
pub fn flush_current_as_pages(addrs: &[VirtAddr]) {
    if addrs.is_empty() {
        return;
    }
    if addrs.len() == 1 {
        flush_current_as_page(addrs[0]);
        return;
    }
    assert_single_core_mode();

    for &va in addrs {
        if range_touches_kernel_half(va, PAGE_SIZE as usize) {
            flush_all_address_spaces();
            return;
        }
    }

    let _pin = ShootdownCpuPin::new();
    let target_cr3 = canonical_shootdown_cr3(_pin.cpu_id());
    let targets = collect_target_cpus(target_cr3);
    if targets.is_empty() {
        for &va in addrs {
            let aligned = VirtAddr::new(va.as_u64() & !(PAGE_SIZE - 1));
            tlb::flush(aligned);
        }
        STATS_RANGE_FLUSHES.fetch_add(1, Ordering::Relaxed);
        STATS_PAGES_FLUSHED.fetch_add(addrs.len() as u64, Ordering::Relaxed);
        return;
    }

    // Remote CPUs share this CR3: one full-AS shootdown sends 1 IPI per target
    // CPU instead of `addrs.len()` separate range shootdowns.
    drop(_pin);
    flush_current_as_all();
}

/// Get TLB shootdown statistics.
///
/// Returns a snapshot of the current statistics. Thread-safe due to atomic loads.
pub fn get_stats() -> TlbShootdownStats {
    TlbShootdownStats {
        full_flushes: STATS_FULL_FLUSHES.load(Ordering::Relaxed),
        range_flushes: STATS_RANGE_FLUSHES.load(Ordering::Relaxed),
        pages_flushed: STATS_PAGES_FLUSHED.load(Ordering::Relaxed),
        coalesced_fallbacks: STATS_COALESCED_FALLBACKS.load(Ordering::Relaxed),
        targeted_shootdowns: STATS_TARGETED_SHOOTDOWNS.load(Ordering::Relaxed),
        targeted_zero_ipi: STATS_TARGETED_ZERO_IPI.load(Ordering::Relaxed),
        broadcast_fallbacks: STATS_BROADCAST_FALLBACK.load(Ordering::Relaxed),
        shootdown_ipis: STATS_SHOOTDOWN_IPIS.load(Ordering::Relaxed),
    }
}

/// Handle an incoming TLB shootdown IPI on the current CPU.
///
/// # R72: Queue-Based Draining
///
/// Drains the per-CPU mailbox queue in FIFO order. For each entry:
/// 1. Loads the entry generation with Acquire
/// 2. Reads flush parameters (CR3, start, len)
/// 3. Performs the appropriate TLB flush if CR3 matches
/// 4. ACKs the generation and clears the entry
/// 5. Advances the queue head
///
/// This processes all pending requests, not just the latest, ensuring
/// no flush is dropped.
///
/// Lock-free check whether this CPU's shootdown mailbox has pending work
/// (queued entries or a saturated-mailbox fallback generation gap).
#[inline]
pub fn has_pending_shootdown() -> bool {
    let mailbox = current_cpu().tlb_mailbox();
    mailbox.head.load(Ordering::Acquire) < mailbox.tail.load(Ordering::Acquire)
        || mailbox.ack_gen.load(Ordering::Acquire) < mailbox.request_gen.load(Ordering::Acquire)
}

/// # Safety
///
/// Must be called with interrupts disabled (including bounded foreign-root
/// usercopy). This preserves the mailbox's single-consumer contract.
pub fn handle_shootdown_ipi() {
    let mailbox = current_cpu().tlb_mailbox();
    let this_cr3 = current_cr3_value();

    // Drain all pending requests from the queue
    loop {
        let head = mailbox.head.load(Ordering::Acquire);
        let tail = mailbox.tail.load(Ordering::Acquire);

        // Check if queue is empty
        if head >= tail {
            break; // Queue drained — fall through to the request_gen gap check
        }

        let slot = (head as usize) % TLB_SHOOTDOWN_QUEUE_LEN;
        let entry = &mailbox.entries[slot];

        // Load generation with Acquire to synchronize with producer's Release
        let generation = entry.generation.load(Ordering::Acquire);
        if generation == 0 {
            // Entry not yet published, spin briefly and retry
            spin_loop();
            continue;
        }

        // Read flush parameters (Relaxed is fine, synchronized by generation Acquire)
        let target_cr3 = entry.cr3.load(Ordering::Relaxed);
        let len = entry.len.load(Ordering::Relaxed);
        let start = entry.start.load(Ordering::Relaxed);

        // R74-1 FIX: Always invalidate TLB before ACKing.
        //
        // With PCID enabled, a CPU may have stale TLB entries for an address space
        // it previously ran but is not currently running. If we only flush when
        // target_cr3 == this_cr3, we leave stale entries intact that become active
        // on context switch back to that CR3, enabling use-after-free and W^X bypass.
        //
        // Security fix: Always perform a flush. When the target address space is not
        // currently active, fall back to flushing all non-global entries to ensure
        // any cached entries for target_cr3 are invalidated.
        if len == 0 || target_cr3 == 0 {
            // Full TLB flush requested or unconditional flush
            flush_all_local();
        } else if target_cr3 == this_cr3 {
            // Target address space is currently active - range flush is safe
            flush_range_local(start, len);
        } else {
            // R74-1 FIX: Target address space not currently running here.
            // We may have stale entries from a previous execution of this CR3.
            // Flush all non-global entries (all PCIDs) to ensure no stale
            // translations survive. This is more expensive but necessary for
            // security when PCID is enabled.
            flush_all_local();
        }

        // Issue #109 §1.1 (H2): clear entry and advance head (Release) so senders
        // waiting on `mailbox.head >= ticket` unblock strictly AFTER this slot's
        // TLB invalidation has completed. `ack_gen` is reserved for R106-5
        // saturated-mailbox fallback epochs (global generation space).
        entry.generation.store(0, Ordering::Release);
        mailbox.head.store(head + 1, Ordering::Release);
    }

    // R106-5 FIX: Implicit full-flush fallback for saturated mailbox.
    // When a requester couldn't enqueue (queue full), it advanced request_gen
    // without a queue entry. Detect this case and perform a full flush.
    let requested = mailbox.request_gen.load(Ordering::Acquire);
    let acked = mailbox.ack_gen.load(Ordering::Acquire);
    if requested > acked {
        flush_all_local();
        mailbox.ack_gen.store(requested, Ordering::Release);
    }
}

/// ST-K2-P2(b): drains that delivered at least one acknowledgement from a #PF
/// Busy return (guest oracle builds only).
#[cfg(feature = "syscall_test")]
static ACKS_FROM_FAULT_DRAIN: AtomicU64 = AtomicU64::new(0);

/// Drain this CPU's mailbox from a page fault's Busy return.
///
/// Guarded usercopy retries its fault with the saved IF=0, so the shootdown IPI
/// of a remote page-table holder cannot arrive while it spins; this drain is
/// how that holder gets its acknowledgement. #PF has cleared AC and keeps IRQs
/// disabled, which satisfies [`handle_shootdown_ipi`]'s single-consumer rule.
pub fn drain_from_fault() {
    #[cfg(feature = "syscall_test")]
    let (head_before, acked_before) = {
        let mailbox = current_cpu().tlb_mailbox();
        (
            mailbox.head.load(Ordering::Acquire),
            mailbox.ack_gen.load(Ordering::Acquire),
        )
    };
    handle_shootdown_ipi();
    #[cfg(feature = "syscall_test")]
    {
        let mailbox = current_cpu().tlb_mailbox();
        if mailbox.head.load(Ordering::Acquire) != head_before
            || mailbox.ack_gen.load(Ordering::Acquire) != acked_before
        {
            ACKS_FROM_FAULT_DRAIN.fetch_add(1, Ordering::AcqRel);
        }
    }
}

/// ST-K2-P2(b): see [`drain_from_fault`].
#[cfg(feature = "syscall_test")]
pub fn acks_from_fault_drain() -> u64 {
    ACKS_FROM_FAULT_DRAIN.load(Ordering::Acquire)
}

const _: () = assert!(core::mem::align_of::<AlignedActiveCr3>() == 64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targeted_hits_only_matching_cr3() {
        let active = [0x1000u64, 0x1000, 0x2000, 0x3000];
        let sel =
            select_target_cpus_from_state(0x1000, 0, 0b1111, 4, false, |_| true, |cpu| active[cpu]);
        assert_eq!(sel.kind, TargetSelectionKind::TargetedIpi);
        assert_eq!(sel.targets.0, 1u64 << 1);
    }

    #[test]
    fn targeted_zero_ipi_when_no_remote_matches() {
        let active = [0x1000u64, 0x2000, 0x3000, 0x4000];
        let sel =
            select_target_cpus_from_state(0x1000, 0, 0b1111, 4, false, |_| true, |cpu| active[cpu]);
        assert_eq!(sel.kind, TargetSelectionKind::TargetedZeroIpi);
        assert!(sel.targets.is_empty());
    }

    #[test]
    fn untracked_zero_slot_fails_closed_included() {
        // CPU 1 matches, CPU 2 is untracked (0 -> must be included), CPU 3 is on
        // another tracked CR3 (safely skipped).
        let active = [0x1000u64, 0x1000, 0, 0x3000];
        let sel =
            select_target_cpus_from_state(0x1000, 0, 0b1111, 4, false, |_| true, |cpu| active[cpu]);
        assert_eq!(sel.kind, TargetSelectionKind::TargetedIpi);
        assert_eq!(sel.targets.0, (1u64 << 1) | (1u64 << 2));
    }

    #[test]
    fn all_untracked_zero_slots_fails_closed() {
        let active = [0x1000u64, 0, 0, 0];
        let sel =
            select_target_cpus_from_state(0x1000, 0, 0b1111, 4, false, |_| true, |cpu| active[cpu]);
        assert_eq!(sel.kind, TargetSelectionKind::TargetedIpi);
        assert_eq!(sel.targets.0, 0b1110);
    }

    #[test]
    fn target_cr3_zero_forces_broadcast() {
        let active = [0x1000u64, 0x2000, 0x3000, 0x4000];
        let sel =
            select_target_cpus_from_state(0, 0, 0b1111, 4, false, |_| true, |cpu| active[cpu]);
        assert_eq!(sel.kind, TargetSelectionKind::BroadcastFallback);
        assert_eq!(sel.targets.0, 0b1110);
    }

    #[test]
    fn kernel_half_range_forces_broadcast() {
        assert!(!range_touches_kernel_half(VirtAddr::new(0x1000), 4096));
        assert!(!range_touches_kernel_half(
            VirtAddr::new(USER_HALF_END - 4096),
            4096
        ));
        // Crossing into the non-canonical hole / kernel half fails closed.
        assert!(range_touches_kernel_half(
            VirtAddr::new(USER_HALF_END - 4096),
            8192
        ));
        // Non-canonical boundary and canonical high-half start both fail closed.
        assert!(range_touches_kernel_half(
            unsafe { VirtAddr::new_unsafe(USER_HALF_END) },
            4096
        ));
        assert!(range_touches_kernel_half(
            VirtAddr::new(0xFFFF_8000_0000_0000),
            4096
        ));
        assert!(range_touches_kernel_half(
            VirtAddr::new(crate::page_table::PHYSICAL_MEMORY_OFFSET),
            4096
        ));
        // Address arithmetic overflow fails closed.
        assert!(range_touches_kernel_half(
            VirtAddr::new(u64::MAX - 4095),
            8192
        ));
    }

    #[test]
    fn nonzero_pcid_active_forces_broadcast() {
        let active = [0x1000u64, 0x2000, 0x3000, 0x4000];
        let sel =
            select_target_cpus_from_state(0x1000, 0, 0b1111, 4, true, |_| true, |cpu| active[cpu]);
        assert_eq!(sel.kind, TargetSelectionKind::BroadcastFallback);
        assert_eq!(sel.targets.0, 0b1110);
    }

    #[test]
    fn canonical_cr3_kpti_dual_root_resolution() {
        // Normal Ring-0 fast path: hw == tracked != 0.
        assert_eq!(
            resolve_canonical_shootdown_cr3(0xA000, 0xA000, None),
            0xA000
        );
        // KPTI Ring-3 #PF CoW path: hw == user_cr3, tracked == kernel_cr3.
        assert_eq!(
            resolve_canonical_shootdown_cr3(0xB000, 0xA000, Some((0xB000, 0xA000))),
            0xA000
        );
        // Unexpected CR3 mismatch fails closed to 0 (broadcast).
        assert_eq!(
            resolve_canonical_shootdown_cr3(0xC000, 0xA000, Some((0xB000, 0xA000))),
            0
        );
        // Torn/odd seqlock snapshot (None) with hw != tracked fails closed to 0.
        assert_eq!(resolve_canonical_shootdown_cr3(0xB000, 0xA000, None), 0);
        // Untracked local slot (0) fails closed to 0.
        assert_eq!(
            resolve_canonical_shootdown_cr3(0xA000, 0, Some((0xA000, 0xA000))),
            0
        );
    }

    /// Issue #109 §1.1 (H2) negative-control test: reproduce the MPSC out-of-order
    /// global-generation race where Sender B (global gen=11) wins `mailbox.tail`
    /// slot 0 and is drained BEFORE Sender A (global gen=10) enqueues slot 1.
    ///
    /// Under the old `ack_gen >= global_gen` check, Sender A would falsely observe
    /// `11 >= 10` and free frames before the target CPU ever flushed slot 1.
    /// Under the per-mailbox FIFO `head >= ticket` contract, Sender A stays blocked
    /// until the consumer actually processes slot 1 and advances `head` to 2.
    #[test]
    fn mpsc_out_of_order_enqueue_ticket_prevents_premature_ack() {
        let mailbox = TlbShootdownMailbox::new();

        // Sender B (global gen=11) claims slot 0 first -> ticket 1.
        let ticket_b = enqueue_mailbox(&mailbox, 0x2000, 0x4000, 4096).expect("slot 0");
        assert_eq!(ticket_b, 1);

        // Target CPU drains slot 0 (head: 0 -> 1). Suppose a fallback also
        // advanced ack_gen to 11 (higher than Sender A's global gen=10).
        let slot0 = &mailbox.entries[0];
        assert_ne!(slot0.generation.load(Ordering::Acquire), 0);
        slot0.generation.store(0, Ordering::Release);
        mailbox.head.store(1, Ordering::Release);
        mailbox.ack_gen.store(11, Ordering::Release);

        // Sender B (ticket 1) is now genuinely complete.
        assert!(target_mailbox_completed(&mailbox, ticket_b, false));

        // Now Sender A (global gen=10 < ack_gen=11) claims slot 1 -> ticket 2.
        let ticket_a = enqueue_mailbox(&mailbox, 0x1000, 0x8000, 4096).expect("slot 1");
        assert_eq!(ticket_a, 2);

        // Old buggy check (`ack_gen >= 10`) would falsely return true here!
        assert!(mailbox.ack_gen.load(Ordering::Acquire) >= 10);
        // New FIFO ticket check (`head >= 2`) MUST remain false until slot 1 is drained.
        assert!(
            !target_mailbox_completed(&mailbox, ticket_a, false),
            "H2: out-of-order MPSC sender must NOT observe completion before its slot is drained"
        );

        // Consumer drains slot 1 (head: 1 -> 2): NOW Sender A completes.
        let slot1 = &mailbox.entries[1];
        assert_ne!(slot1.generation.load(Ordering::Acquire), 0);
        slot1.generation.store(0, Ordering::Release);
        mailbox.head.store(2, Ordering::Release);
        assert!(target_mailbox_completed(&mailbox, ticket_a, false));

        // Saturated-mailbox fallback path mints an atomic per-mailbox epoch and
        // waits strictly on `ack_gen >= fallback_ticket`.
        mailbox.request_gen.store(11, Ordering::Release);
        let fallback_ticket = mailbox.request_gen.fetch_add(1, Ordering::AcqRel) + 1;
        assert_eq!(fallback_ticket, 12);
        assert!(!target_mailbox_completed(&mailbox, fallback_ticket, true));
        mailbox.ack_gen.store(12, Ordering::Release);
        assert!(target_mailbox_completed(&mailbox, fallback_ticket, true));
    }

    /// Issue #109 rollup audit (ASTRA-2): Two concurrent IF=0 shootdown senders
    /// targeting each other (e.g. `AS_PT_LOCKS` vs `KERNEL_PT_LOCK`) must both
    /// converge without deadlock when each drains its own mailbox while polling.
    #[test]
    fn reciprocal_if0_shootdown_drains_local_mailbox_and_converges() {
        use std::sync::{Arc, Barrier};
        use std::thread;
        use std::time::{Duration, Instant};

        fn drain_simulated(mailbox: &TlbShootdownMailbox) {
            loop {
                let head = mailbox.head.load(Ordering::Acquire);
                let tail = mailbox.tail.load(Ordering::Acquire);
                if head >= tail {
                    break;
                }
                let slot = (head as usize) % TLB_SHOOTDOWN_QUEUE_LEN;
                let entry = &mailbox.entries[slot];
                if entry.generation.load(Ordering::Acquire) == 0 {
                    spin_loop();
                    continue;
                }
                entry.generation.store(0, Ordering::Release);
                mailbox.head.store(head + 1, Ordering::Release);
            }
            let req = mailbox.request_gen.load(Ordering::Acquire);
            if req > mailbox.ack_gen.load(Ordering::Acquire) {
                mailbox.ack_gen.store(req, Ordering::Release);
            }
        }

        let mb_a = Arc::new(TlbShootdownMailbox::new());
        let mb_b = Arc::new(TlbShootdownMailbox::new());
        let start = Arc::new(Barrier::new(2));

        // Both CPUs enqueue shootdowns targeting each other before waiting.
        let ticket_on_b = enqueue_mailbox(&mb_b, 0x1000, 0x4000, 4096).expect("enqueue B");
        let ticket_on_a = enqueue_mailbox(&mb_a, 0, 0, 0).expect("enqueue A");

        let mb_a2 = Arc::clone(&mb_a);
        let mb_b2 = Arc::clone(&mb_b);
        let start2 = Arc::clone(&start);
        let t_b = thread::spawn(move || {
            start2.wait();
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                // Drain local mailbox on each poll (and upon exiting IF=0,
                // mirroring pending 0xFE IPI delivery when interrupts re-enable).
                drain_simulated(&mb_b2);
                if target_mailbox_completed(&mb_a2, ticket_on_a, false) {
                    drain_simulated(&mb_b2);
                    return true;
                }
                thread::yield_now();
            }
            false
        });

        start.wait();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut a_done = false;
        while Instant::now() < deadline {
            drain_simulated(&mb_a);
            if target_mailbox_completed(&mb_b, ticket_on_b, false) {
                drain_simulated(&mb_a);
                a_done = true;
                break;
            }
            thread::yield_now();
        }
        let b_done = t_b.join().expect("thread B joined");
        assert!(a_done && b_done, "reciprocal shootdown failed to converge");
    }
}
