//! KCOV: Kernel Code Coverage Infrastructure for Fuzzing
//!
//! This module provides coverage tracking for Nilix to support coverage-guided
//! fuzzing. Unlike Linux KCOV which uses LLVM SanitizerCoverage automatic
//! instrumentation, this implementation uses manual instrumentation via the
//! `record_edge!()` macro to avoid bare-metal/no_std compatibility issues.
//!
//! # Architecture
//!
//! - **Per-task coverage buffer**: Each process has a requested `1..=4096` byte bitmap
//! - **Edge-based coverage**: Tracks occupied coverage bitmap slots for control-flow edges
//! - **Manual instrumentation**: Use `record_edge!()` at strategic points
//! - **IRQ-safe**: Uses `try_lock()`, never blocks
//! - **SMAP-compliant**: Userspace access via proper copy primitives
//!
//! # Build and access requirements
//!
//! The kernel must be built with the `kcov` feature. Without that feature, the
//! KCOV syscalls return `ENOSYS`. KCOV is a privileged observability interface:
//! callers must be host root or hold the dedicated KCOV capability before they
//! can allocate, control, reset, or export a task's bitmap.
//!
//! # Bitmap semantics
//!
//! The bitmap has `8 * configured_byte_length` observable slots. An
//! instrumentation identifier maps to `edge_id % slot_count`; therefore two
//! distinct identifiers can collide and set the same slot. The syscall return
//! value and [`CoverageBuffer::edge_count`] report the number of occupied
//! bitmap slots (the bitmap popcount), not the number of globally unique
//! control-flow edges. Consumers must treat saturation and collisions as
//! normal lossy-coverage behavior.
//!
//! # Usage
//!
//! ## Kernel Side
//!
//! ```rust,no_run
//! use coverage::record_edge;
//!
//! fn some_kernel_function() {
//!     record_edge!();  // Records this code path was executed
//!     // ... rest of function
//! }
//! ```
//!
//! ## Userspace Side
//!
//! ```c
//! // Initialize coverage for this process
//! syscall(520, 4096);  // sys_kcov_init
//!
//! // Enable collection
//! syscall(521);  // sys_kcov_enable
//!
//! // Execute syscalls under test
//! open("/foo", O_RDONLY);
//! read(fd, buf, 100);
//! close(fd);
//!
//! // Dump coverage and get the occupied bitmap-slot count.
//! uint8_t coverage[4096];
//! long occupied_slots = syscall(523, coverage, 4096);  // sys_kcov_dump
//! printf("Hit %ld occupied coverage slots\n", occupied_slots);
//! ```
//!
//! # Safety
//!
//! - Buffer overflow saturates silently (no crash)
//! - IRQ-safe: no blocking, no allocations in hot path
//! - SMAP-compliant: all userspace access gated

#![no_std]
extern crate alloc;
extern crate spin;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Once;

/// Maximum coverage buffer size (4KB = 32,768 observable bitmap slots).
pub const KCOV_BUFFER_SIZE: usize = 4096;

/// Failure returned while constructing a task-owned coverage bitmap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageAllocError {
    /// The requested byte length is outside the supported `1..=4096` range.
    InvalidSize,
    /// The global allocator could not provide the bitmap backing allocation.
    AllocationFailed,
}

/// Failure returned when a caller requests a partial KCOV bitmap snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageCopyError {
    /// The destination length does not exactly match the configured bitmap.
    LengthMismatch,
}

/// Coverage buffer: bitmap tracking which edges have been hit
#[derive(Debug)]
pub struct CoverageBuffer {
    /// Fixed-size, lossy coverage bitmap (one bit per observable slot).
    bitmap: Vec<u8>,
    /// Saturating count of occupied bitmap slots (always the bitmap popcount).
    edge_count: u32,
    /// Whether coverage collection is active
    enabled: bool,
}

impl CoverageBuffer {
    /// Create a coverage buffer with an explicit byte length.
    ///
    /// The length is immutable and bounded by [`KCOV_BUFFER_SIZE`], which keeps
    /// per-task memory consumption predictable even for hostile callers.
    pub fn try_new(buffer_size: usize) -> Result<Self, CoverageAllocError> {
        if buffer_size == 0 || buffer_size > KCOV_BUFFER_SIZE {
            return Err(CoverageAllocError::InvalidSize);
        }

        let mut bitmap = Vec::new();
        bitmap
            .try_reserve_exact(buffer_size)
            .map_err(|_| CoverageAllocError::AllocationFailed)?;
        bitmap.resize(buffer_size, 0);
        Ok(Self {
            bitmap,
            edge_count: 0,
            enabled: false,
        })
    }

    /// Enable coverage collection
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable coverage collection (preserves data)
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Record that an instrumentation identifier was hit.
    ///
    /// # Arguments
    /// - `edge_id`: Deterministic identifier for this edge (typically a
    ///   file-and-line hash). IDs alias modulo the bitmap slot count.
    ///
    /// # Safety
    /// IRQ-safe, no allocations, no blocking
    #[inline]
    pub fn record_edge(&mut self, edge_id: u32) {
        if !self.enabled {
            return;
        }

        let byte_idx = (edge_id as usize / 8) % self.bitmap.len();
        let bit_idx = edge_id % 8;

        // Check whether this bitmap slot was already occupied. Distinct IDs
        // that alias this slot intentionally do not increase the count.
        let byte = &mut self.bitmap[byte_idx];
        let mask = 1u8 << bit_idx;

        if (*byte & mask) == 0 {
            // First hit for this observable bitmap slot.
            *byte |= mask;
            self.edge_count = self.edge_count.saturating_add(1);
        }
    }

    /// Copy a complete bitmap snapshot into an exactly sized destination.
    ///
    /// R187-3 FIX: partial snapshots are rejected before mutating `dst`, which
    /// makes a staging-buffer length mismatch fail closed even if a future
    /// caller bypasses the syscall's outer length validation.
    pub fn copy_to_slice_exact(&self, dst: &mut [u8]) -> Result<(), CoverageCopyError> {
        if dst.len() != self.bitmap.len() {
            return Err(CoverageCopyError::LengthMismatch);
        }
        dst.copy_from_slice(&self.bitmap);
        Ok(())
    }

    /// Get the number of occupied coverage bitmap slots.
    ///
    /// This value is the snapshot bitmap popcount, not a count of globally
    /// unique instrumentation identifiers because IDs may collide modulo the
    /// configured slot count.
    pub fn edge_count(&self) -> usize {
        self.edge_count as usize
    }

    /// Configured bitmap length in bytes.
    #[inline]
    pub fn bitmap_len(&self) -> usize {
        self.bitmap.len()
    }

    /// Allocator capacity whose complete backing allocation must be accounted.
    #[inline]
    pub fn bitmap_capacity(&self) -> usize {
        self.bitmap.capacity()
    }

    /// Reset coverage data
    pub fn reset(&mut self) {
        self.bitmap.fill(0);
        self.edge_count = 0;
    }
}

/// Global coverage enabled flag
static COVERAGE_ENABLED: AtomicBool = AtomicBool::new(false);

/// Kernel-owned bridge that resolves the current task and records into its buffer.
pub type CurrentTaskRecorder = fn(u32);

static CURRENT_TASK_RECORDER: Once<CurrentTaskRecorder> = Once::new();

/// Suppresses recursive tracepoints on the same CPU while the recorder bridge runs.
///
/// A fixed array is deliberate: tracing must never be the first user of a lazy,
/// heap-backed `CpuLocal` slab while the allocator or a kernel lock is held.
/// R187-7 FIX: every access below obtains a checked slot reference after strict
/// CPU-topology admission; the fixed capacity is never indexed directly.
static RECORDER_ACTIVE: [AtomicBool; cpu_local::MAX_CPUS] =
    [const { AtomicBool::new(false) }; cpu_local::MAX_CPUS];

/// Return the static recursion slot only after a capacity check.
///
/// The caller must still obtain its CPU ID from `CurrentCpuPin`; this helper
/// prevents an invalid topology result from ever becoming an array index.
#[inline]
fn recorder_active_slot(cpu_id: usize) -> Option<&'static AtomicBool> {
    RECORDER_ACTIVE.get(cpu_id)
}

#[cfg(test)]
static RECORDER_PIN_ATTEMPTS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Acquire the shared CPU pin for the recorder.
///
/// Keeping this wrapper local makes the IRQ admission invariant observable in
/// the regression test without adding any production-state instrumentation.
#[inline]
fn try_pin_recorder_cpu() -> Option<cpu_local::CurrentCpuPin> {
    #[cfg(test)]
    RECORDER_PIN_ATTEMPTS.fetch_add(1, Ordering::Relaxed);

    cpu_local::try_pin_current_online_cpu()
}

struct RecorderGuard {
    active: &'static AtomicBool,
    _pin: cpu_local::CurrentCpuPin,
}

impl RecorderGuard {
    #[inline]
    fn try_enter() -> Option<Self> {
        // R187-2 FIX: reject a known IRQ/NMI or other IF-masked context before
        // disabling preemption or touching recorder state. The stable post-pin
        // check below closes the race with async entry or CPU migration after
        // this first observation.
        if cpu_local::try_current_online_cpu_in_non_task_context() != Some(false) {
            return None;
        }

        // R187-7 FIX: only a registered, online CPU can obtain a pin. An
        // unavailable AP or invalid mapping drops this best-effort edge rather
        // than borrowing CPU 0's state or indexing the static array.
        let pin = try_pin_recorder_cpu()?;
        if pin.in_non_task_context() {
            return None;
        }

        let active = recorder_active_slot(pin.cpu_id())?;
        active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(Self { active, _pin: pin })
    }
}

impl Drop for RecorderGuard {
    #[inline]
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

/// Initialize the coverage subsystem
pub fn init_coverage(recorder: CurrentTaskRecorder) {
    let installed = *CURRENT_TASK_RECORDER.call_once(|| recorder);
    assert!(
        core::ptr::fn_addr_eq(installed, recorder),
        "KCOV current-task recorder registered more than once"
    );

    // The recursion state itself is static. Pre-initialize only the shared
    // preemption metadata used by the stable-CPU guard, while still in boot
    // process context, so the first tracepoint cannot allocate.
    cpu_local::PER_CPU_DATA.force_init();
    COVERAGE_ENABLED.store(true, Ordering::Release);
}

/// Check if coverage is enabled globally
#[inline]
pub fn is_coverage_enabled() -> bool {
    COVERAGE_ENABLED.load(Ordering::Acquire)
}

/// Record an edge hit for the current task
///
/// This is the hot path, called from `record_edge!()` macro.
/// Must be IRQ-safe, no allocations, no blocking.
#[inline]
pub fn record_edge_for_current(edge_id: u32) {
    if !is_coverage_enabled() {
        return;
    }

    let Some(_guard) = RecorderGuard::try_enter() else {
        return;
    };

    if let Some(recorder) = CURRENT_TASK_RECORDER.get().copied() {
        recorder(edge_id);
    }
}

/// Manual trace point for testing coverage infrastructure
///
/// This is a simplified version that can be called directly with a manual edge ID.
/// Used for Phase 2 testing before full LLVM instrumentation is enabled.
///
/// # Arguments
/// - `edge_id`: Manual edge identifier (e.g., 1, 2, 3 for different code locations)
///
/// # Safety
/// IRQ-safe, no allocations. Returns silently if coverage not enabled or buffer unavailable.
#[inline]
pub fn trace_pc(edge_id: u32) {
    // Fast path: check if coverage is globally enabled
    if !is_coverage_enabled() {
        return;
    }

    record_edge_for_current(edge_id);
}

/// Macro to record coverage at a specific code location
///
/// Generates a deterministic edge ID from file and line number.
///
/// # Example
///
/// ```rust,no_run
/// use coverage::record_edge;
///
/// fn my_function() {
///     record_edge!();  // Records this location
///     // ...
/// }
/// ```
#[macro_export]
macro_rules! record_edge {
    () => {{
        #[cfg(feature = "kcov")]
        {
            // Generate deterministic edge ID from file:line.
            const EDGE_ID: u32 = {
                let file_hash = $crate::const_fnv1a_hash(file!().as_bytes());
                let line_hash = line!();
                file_hash.wrapping_mul(31).wrapping_add(line_hash)
            };
            $crate::record_edge_for_current(EDGE_ID);
        }
    }};
}

/// Compile-time FNV-1a hash for generating deterministic edge IDs.
#[doc(hidden)]
pub const fn const_fnv1a_hash(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 2166136261; // FNV offset basis
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u32;
        hash = hash.wrapping_mul(16777619); // FNV prime
        i += 1;
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU32;

    static RECORDED_EDGE: AtomicU32 = AtomicU32::new(0);

    fn recursive_test_recorder(edge_id: u32) {
        RECORDED_EDGE.store(edge_id, Ordering::Relaxed);
        record_edge_for_current(edge_id.wrapping_add(1));
    }

    #[test]
    fn test_coverage_buffer_basic() {
        let mut buf = CoverageBuffer::try_new(KCOV_BUFFER_SIZE).expect("KCOV test buffer");
        assert_eq!(buf.edge_count(), 0);

        buf.enable();
        buf.record_edge(0);
        assert_eq!(buf.edge_count(), 1);

        // Recording same edge again shouldn't increment
        buf.record_edge(0);
        assert_eq!(buf.edge_count(), 1);

        // Recording different edge should increment
        buf.record_edge(1);
        assert_eq!(buf.edge_count(), 2);
    }

    #[test]
    fn test_coverage_buffer_disabled() {
        let mut buf = CoverageBuffer::try_new(KCOV_BUFFER_SIZE).expect("KCOV test buffer");
        buf.record_edge(0);
        assert_eq!(buf.edge_count(), 0); // Should be 0 when disabled
    }

    #[test]
    fn test_coverage_buffer_reset() {
        let mut buf = CoverageBuffer::try_new(KCOV_BUFFER_SIZE).expect("KCOV test buffer");
        buf.enable();
        buf.record_edge(0);
        buf.record_edge(1);
        assert_eq!(buf.edge_count(), 2);

        buf.reset();
        assert_eq!(buf.edge_count(), 0);
    }

    #[test]
    fn test_explicit_buffer_size_is_enforced() {
        assert!(matches!(
            CoverageBuffer::try_new(0),
            Err(CoverageAllocError::InvalidSize)
        ));
        assert!(matches!(
            CoverageBuffer::try_new(KCOV_BUFFER_SIZE + 1),
            Err(CoverageAllocError::InvalidSize)
        ));

        let mut buf = CoverageBuffer::try_new(17).expect("small KCOV buffer");
        assert_eq!(buf.bitmap_len(), 17);
        assert!(buf.bitmap_capacity() >= buf.bitmap_len());
        let mut snapshot = [0u8; 17];
        buf.enable();
        buf.record_edge(0);
        buf.record_edge((17 * 8 - 1) as u32);
        assert_eq!(buf.copy_to_slice_exact(&mut snapshot), Ok(()));
        assert_eq!(buf.edge_count(), 2);
        assert_eq!(
            snapshot.iter().map(|byte| byte.count_ones()).sum::<u32>(),
            2
        );
    }

    #[test]
    fn exact_snapshot_rejects_length_mismatch_without_partial_copy() {
        let mut buf = CoverageBuffer::try_new(2).expect("small KCOV buffer");
        buf.enable();
        buf.record_edge(0);
        buf.record_edge(15);

        let mut too_short = [0xa5u8; 1];
        assert_eq!(
            buf.copy_to_slice_exact(&mut too_short),
            Err(CoverageCopyError::LengthMismatch)
        );
        assert_eq!(too_short, [0xa5], "short destination must remain untouched");

        let mut too_long = [0x5au8; 3];
        assert_eq!(
            buf.copy_to_slice_exact(&mut too_long),
            Err(CoverageCopyError::LengthMismatch)
        );
        assert_eq!(
            too_long, [0x5a; 3],
            "long destination must remain untouched"
        );

        let mut exact = [0u8; 2];
        assert_eq!(buf.copy_to_slice_exact(&mut exact), Ok(()));
        assert_eq!(exact, [0b0000_0001, 0b1000_0000]);
    }

    #[test]
    fn colliding_identifiers_count_one_occupied_slot() {
        let mut buf = CoverageBuffer::try_new(1).expect("one-byte KCOV buffer");
        buf.enable();

        // Both identifiers map to slot 3 because the bitmap has only eight
        // slots. The count is bitmap occupancy, not source-ID cardinality.
        buf.record_edge(3);
        buf.record_edge(3 + 8);
        assert_eq!(buf.edge_count(), 1);

        // A different slot contributes exactly one more occupied bit.
        buf.record_edge(4);
        assert_eq!(buf.edge_count(), 2);
        let mut snapshot = [0u8; 1];
        assert_eq!(buf.copy_to_slice_exact(&mut snapshot), Ok(()));
        assert_eq!(snapshot[0].count_ones() as usize, buf.edge_count());
    }

    #[test]
    fn test_const_fnv1a_hash() {
        let hash1 = const_fnv1a_hash(b"test");
        let hash2 = const_fnv1a_hash(b"test");
        let hash3 = const_fnv1a_hash(b"different");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_current_task_recorder_suppresses_recursion_restores_preemption_and_rejects_async_context(
    ) {
        init_coverage(recursive_test_recorder);
        let before = cpu_local::current_cpu()
            .preempt_count
            .load(Ordering::Relaxed);
        record_edge_for_current(0x1234_5678);
        assert_eq!(RECORDED_EDGE.load(Ordering::Relaxed), 0x1234_5678);
        assert_eq!(
            cpu_local::current_cpu()
                .preempt_count
                .load(Ordering::Relaxed),
            before
        );

        RECORDED_EDGE.store(0, Ordering::Relaxed);
        let pin_attempts_before_irq = RECORDER_PIN_ATTEMPTS.load(Ordering::Relaxed);
        cpu_local::current_cpu().irq_enter();
        assert!(RecorderGuard::try_enter().is_none());
        assert_eq!(
            RECORDER_PIN_ATTEMPTS.load(Ordering::Relaxed),
            pin_attempts_before_irq,
            "IRQ rejection must not attempt to acquire the KCOV CPU pin"
        );
        assert_eq!(
            cpu_local::current_cpu()
                .preempt_count
                .load(Ordering::Relaxed),
            before,
            "IRQ rejection must happen before KCOV takes a preemption pin"
        );
        record_edge_for_current(0xfeed_beef);
        cpu_local::current_cpu().irq_exit();
        assert_eq!(RECORDED_EDGE.load(Ordering::Relaxed), 0);
        assert_eq!(
            cpu_local::current_cpu()
                .preempt_count
                .load(Ordering::Relaxed),
            before
        );

        // R187-2: NMI does not necessarily clear IF or increment irq_count.
        // The allocation-free global NMI counter must nevertheless reject the
        // outer recorder before it attempts a CPU pin or invokes the bridge.
        RECORDED_EDGE.store(0, Ordering::Relaxed);
        let pin_attempts_before_nmi = RECORDER_PIN_ATTEMPTS.load(Ordering::Relaxed);
        cpu_local::nmi_enter();
        let nmi_guard_rejected = RecorderGuard::try_enter().is_none();
        let nmi_pin_attempts = RECORDER_PIN_ATTEMPTS.load(Ordering::Relaxed);
        let nmi_preempt_count = cpu_local::current_cpu()
            .preempt_count
            .load(Ordering::Relaxed);
        record_edge_for_current(0xfeed_c0de);
        let nmi_recorded_edge = RECORDED_EDGE.load(Ordering::Relaxed);
        let nmi_pin_attempts_after_record = RECORDER_PIN_ATTEMPTS.load(Ordering::Relaxed);
        let nmi_preempt_after_record = cpu_local::current_cpu()
            .preempt_count
            .load(Ordering::Relaxed);
        cpu_local::nmi_exit();

        assert!(nmi_guard_rejected);
        assert_eq!(
            nmi_pin_attempts, pin_attempts_before_nmi,
            "NMI rejection must not attempt to acquire the KCOV CPU pin"
        );
        assert_eq!(
            nmi_pin_attempts_after_record, pin_attempts_before_nmi,
            "the public NMI recording path must not attempt to acquire the KCOV CPU pin"
        );
        assert_eq!(
            nmi_preempt_count, before,
            "NMI rejection must happen before KCOV takes a preemption pin"
        );
        assert_eq!(
            nmi_preempt_after_record, before,
            "the public NMI recording path must not take a KCOV preemption pin"
        );
        assert_eq!(
            nmi_recorded_edge, 0,
            "NMI recording must be dropped before entering the task bridge"
        );
    }

    #[test]
    fn recorder_active_slots_are_capacity_bounded() {
        assert!(recorder_active_slot(0).is_some());
        assert!(recorder_active_slot(cpu_local::MAX_CPUS - 1).is_some());
        assert!(recorder_active_slot(cpu_local::MAX_CPUS).is_none());
        assert!(recorder_active_slot(usize::MAX).is_none());
    }
}
