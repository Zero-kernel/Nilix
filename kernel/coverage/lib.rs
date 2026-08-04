//! KCOV: Kernel Code Coverage Infrastructure for Fuzzing
//!
//! This module provides coverage tracking for Nilix to support coverage-guided
//! fuzzing. Unlike Linux KCOV which uses LLVM SanitizerCoverage automatic
//! instrumentation, this implementation uses manual instrumentation via the
//! `record_edge!()` macro to avoid bare-metal/no_std compatibility issues.
//!
//! # Architecture
//!
//! - **Per-task coverage buffer**: Each process has its own 4KB bitmap
//! - **Edge-based coverage**: Tracks unique control-flow edges, not just blocks
//! - **Manual instrumentation**: Use `record_edge!()` at strategic points
//! - **IRQ-safe**: Uses `try_lock()`, never blocks
//! - **SMAP-compliant**: Userspace access via proper copy primitives
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
//! // Dump coverage and get edge count
//! uint8_t coverage[4096];
//! long edges = syscall(523, coverage, 4096);  // sys_kcov_dump
//! printf("Hit %ld unique edges\n", edges);
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
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Once;

/// Maximum coverage buffer size (4KB = 32K edges).
pub const KCOV_BUFFER_SIZE: usize = 4096;

/// Failure returned while constructing a task-owned coverage bitmap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageAllocError {
    /// The requested byte length is outside the supported `1..=4096` range.
    InvalidSize,
    /// The global allocator could not provide the bitmap backing allocation.
    AllocationFailed,
}

/// Coverage buffer: bitmap tracking which edges have been hit
#[derive(Debug)]
pub struct CoverageBuffer {
    /// The coverage bitmap (1 bit per edge)
    bitmap: Vec<u8>,
    /// Number of unique edges hit
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

    /// Record that an edge was hit
    ///
    /// # Arguments
    /// - `edge_id`: Unique identifier for this edge (typically file:line hash)
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

        // Check if this edge was already hit
        let byte = &mut self.bitmap[byte_idx];
        let mask = 1u8 << bit_idx;

        if (*byte & mask) == 0 {
            // First time hitting this edge
            *byte |= mask;
            self.edge_count = self.edge_count.saturating_add(1);
        }
    }

    /// Copy coverage data to userspace buffer
    ///
    /// # Returns
    /// Number of bytes actually copied
    pub fn copy_to_user(&self, dst: &mut [u8]) -> usize {
        let len = core::cmp::min(dst.len(), self.bitmap.len());
        dst[..len].copy_from_slice(&self.bitmap[..len]);
        len
    }

    /// Get number of unique edges hit
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
static RECORDER_ACTIVE: [AtomicBool; cpu_local::MAX_CPUS] =
    [const { AtomicBool::new(false) }; cpu_local::MAX_CPUS];

/// Preemption pin binding all per-CPU accesses in one recorder invocation to a
/// stable logical CPU. The retry closes the sample-before-disable migration
/// window; dropping the guard restores the exact prior nesting depth.
struct StableCpuPin {
    cpu_id: usize,
    _not_send: PhantomData<*const ()>,
}

impl StableCpuPin {
    #[inline]
    fn new() -> Self {
        loop {
            let cpu_id = cpu_local::current_cpu_id();
            if cpu_local::current_cpu_id() != cpu_id {
                core::hint::spin_loop();
                continue;
            }

            let per_cpu = cpu_local::PER_CPU_DATA
                .get_cpu(cpu_id)
                .unwrap_or_else(|| panic!("KCOV: missing per-CPU slot for CPU {cpu_id}"));
            per_cpu.preempt_disable();
            core::sync::atomic::compiler_fence(Ordering::SeqCst);

            if cpu_local::current_cpu_id() == cpu_id {
                return Self {
                    cpu_id,
                    _not_send: PhantomData,
                };
            }

            core::sync::atomic::compiler_fence(Ordering::SeqCst);
            per_cpu.preempt_enable();
            core::hint::spin_loop();
        }
    }

    #[inline]
    fn per_cpu(&self) -> &'static cpu_local::PerCpuData {
        cpu_local::PER_CPU_DATA
            .get_cpu(self.cpu_id)
            .unwrap_or_else(|| panic!("KCOV: missing pinned per-CPU slot for CPU {}", self.cpu_id))
    }
}

impl Drop for StableCpuPin {
    #[inline]
    fn drop(&mut self) {
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        self.per_cpu().preempt_enable();
    }
}

struct RecorderGuard {
    cpu_id: usize,
    _pin: StableCpuPin,
}

impl RecorderGuard {
    #[inline]
    fn try_enter() -> Option<Self> {
        let pin = StableCpuPin::new();
        if pin.per_cpu().in_irq() {
            return None;
        }

        let cpu_id = pin.cpu_id;
        RECORDER_ACTIVE[cpu_id]
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(Self { cpu_id, _pin: pin })
    }
}

impl Drop for RecorderGuard {
    #[inline]
    fn drop(&mut self) {
        RECORDER_ACTIVE[self.cpu_id].store(false, Ordering::Release);
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
/// Generates a unique edge ID from file and line number.
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
            // Generate unique edge ID from file:line
            const EDGE_ID: u32 = {
                let file_hash = $crate::const_fnv1a_hash(file!().as_bytes());
                let line_hash = line!();
                file_hash.wrapping_mul(31).wrapping_add(line_hash)
            };
            $crate::record_edge_for_current(EDGE_ID);
        }
    }};
}

/// Compile-time FNV-1a hash for generating edge IDs
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
        assert_eq!(buf.copy_to_user(&mut snapshot), snapshot.len());
        assert_eq!(buf.edge_count(), 2);
        assert_eq!(
            snapshot.iter().map(|byte| byte.count_ones()).sum::<u32>(),
            2
        );
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
    fn test_current_task_recorder_suppresses_recursion_restores_preemption_and_rejects_irq() {
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
        cpu_local::current_cpu().irq_enter();
        record_edge_for_current(0xfeed_beef);
        cpu_local::current_cpu().irq_exit();
        assert_eq!(RECORDED_EDGE.load(Ordering::Relaxed), 0);
        assert_eq!(
            cpu_local::current_cpu()
                .preempt_count
                .load(Ordering::Relaxed),
            before
        );
    }
}
