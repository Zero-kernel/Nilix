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
#![feature(allocator_api)]

extern crate alloc;
extern crate spin;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use cpu_local::CpuLocal;
use spin::{Mutex, Once};

/// Maximum coverage buffer size (4KB = 32K edges).
pub const KCOV_BUFFER_SIZE: usize = 4096;

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
    pub fn try_new(buffer_size: usize) -> Option<Self> {
        if buffer_size == 0 || buffer_size > KCOV_BUFFER_SIZE {
            return None;
        }

        let mut bitmap = Vec::new();
        bitmap.try_reserve_exact(buffer_size).ok()?;
        bitmap.resize(buffer_size, 0);
        Some(Self {
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
static RECORDER_ACTIVE: CpuLocal<AtomicBool> = CpuLocal::new(|| AtomicBool::new(false));

struct RecorderGuard;

impl RecorderGuard {
    #[inline]
    fn try_enter() -> Option<Self> {
        let already_active = RECORDER_ACTIVE.with(|active| active.swap(true, Ordering::Relaxed));
        if already_active {
            None
        } else {
            Some(Self)
        }
    }
}

impl Drop for RecorderGuard {
    #[inline]
    fn drop(&mut self) {
        RECORDER_ACTIVE.with(|active| active.store(false, Ordering::Relaxed));
    }
}

/// Initialize the coverage subsystem
pub fn init_coverage(recorder: CurrentTaskRecorder) {
    let installed = *CURRENT_TASK_RECORDER.call_once(|| recorder);
    assert!(
        core::ptr::fn_addr_eq(installed, recorder),
        "KCOV current-task recorder registered more than once"
    );

    // CpuLocal allocates and initializes the complete MAX_CPUS slot array through
    // one global Once. The BSP call therefore prepares every future AP slot too.
    RECORDER_ACTIVE.force_init();
    COVERAGE_ENABLED.store(true, Ordering::Release);
}

/// Check if coverage is enabled globally
#[inline]
pub fn is_coverage_enabled() -> bool {
    COVERAGE_ENABLED.load(Ordering::Acquire)
}

/// Enable coverage for the current task (allocates buffer)
///
/// # Returns
/// - `Some(buffer)`: Successfully allocated
/// - `None`: Allocation failed
pub fn enable_coverage(buffer_size: usize) -> Option<Arc<Mutex<CoverageBuffer>>> {
    if !is_coverage_enabled() {
        return None;
    }

    let buffer = CoverageBuffer::try_new(buffer_size)?;
    Arc::try_new(Mutex::new(buffer)).ok()
}

/// Record an edge hit for the current task
///
/// This is the hot path, called from `record_edge!()` macro.
/// Must be IRQ-safe, no allocations, no blocking.
#[inline]
pub fn record_edge_for_current(edge_id: u32) {
    if !is_coverage_enabled() || cpu_local::current_cpu().in_irq() {
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
        assert!(CoverageBuffer::try_new(0).is_none());
        assert!(CoverageBuffer::try_new(KCOV_BUFFER_SIZE + 1).is_none());

        let mut buf = CoverageBuffer::try_new(17).expect("small KCOV buffer");
        assert_eq!(buf.bitmap_len(), 17);
        let mut snapshot = [0u8; 17];
        buf.enable();
        buf.record_edge(0);
        buf.record_edge((17 * 8 - 1) as u32);
        assert_eq!(buf.copy_to_user(&mut snapshot), snapshot.len());
        assert_eq!(buf.edge_count(), 2);
        assert_eq!(snapshot.iter().map(|byte| byte.count_ones()).sum::<u32>(), 2);
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
    fn test_current_task_recorder_suppresses_recursion() {
        init_coverage(recursive_test_recorder);
        record_edge_for_current(0x1234_5678);
        assert_eq!(RECORDED_EDGE.load(Ordering::Relaxed), 0x1234_5678);
    }
}
