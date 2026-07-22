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

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

/// Maximum coverage buffer size (4KB = 32K edges)
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

impl Default for CoverageBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl CoverageBuffer {
    /// Create a new coverage buffer
    pub fn new() -> Self {
        CoverageBuffer {
            bitmap: vec![0u8; KCOV_BUFFER_SIZE],
            edge_count: 0,
            enabled: false,
        }
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

        let byte_idx = (edge_id as usize / 8) % KCOV_BUFFER_SIZE;
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

    /// Reset coverage data
    pub fn reset(&mut self) {
        self.bitmap.fill(0);
        self.edge_count = 0;
    }
}

/// Global coverage enabled flag
static COVERAGE_ENABLED: AtomicBool = AtomicBool::new(false);

/// Initialize the coverage subsystem
pub fn init_coverage() {
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
pub fn enable_coverage() -> Option<Arc<Mutex<CoverageBuffer>>> {
    if !is_coverage_enabled() {
        return None;
    }

    // Allocate coverage buffer
    let buffer = CoverageBuffer::new();
    Some(Arc::new(Mutex::new(buffer)))
}

/// Record an edge hit for the current task
///
/// This is the hot path, called from `record_edge!()` macro.
/// Must be IRQ-safe, no allocations, no blocking.
#[inline]
pub fn record_edge_for_current(_edge_id: u32) {
    // Fast path: check if coverage is globally enabled
    if is_coverage_enabled() {
        // Get current process's coverage buffer
        // This will be integrated with kernel_core::process::with_current_process
        // For now, this is a no-op until the full integration is complete
    }

    // TODO: Integrate with kernel_core to access current process:
    // with_current_process(|proc| {
    //     if let Some(ref buffer) = proc.coverage_buffer {
    //         if let Some(mut buf) = buffer.try_lock() {
    //             buf.record_edge(edge_id);
    //         }
    //     }
    // });
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

    // This will be completed when kernel_core integration is done
    // For now, this ensures the code compiles and can be called
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
                let file_hash = const_fnv1a_hash(file!().as_bytes());
                let line_hash = line!();
                file_hash.wrapping_mul(31).wrapping_add(line_hash)
            };
            $crate::record_edge_for_current(EDGE_ID);
        }
    }};
}

/// Compile-time FNV-1a hash for generating edge IDs
#[allow(dead_code)]
const fn const_fnv1a_hash(bytes: &[u8]) -> u32 {
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

    #[test]
    fn test_coverage_buffer_basic() {
        let mut buf = CoverageBuffer::new();
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
        let mut buf = CoverageBuffer::new();
        buf.record_edge(0);
        assert_eq!(buf.edge_count(), 0); // Should be 0 when disabled
    }

    #[test]
    fn test_coverage_buffer_reset() {
        let mut buf = CoverageBuffer::new();
        buf.enable();
        buf.record_edge(0);
        buf.record_edge(1);
        assert_eq!(buf.edge_count(), 2);

        buf.reset();
        assert_eq!(buf.edge_count(), 0);
    }

    #[test]
    fn test_const_fnv1a_hash() {
        let hash1 = const_fnv1a_hash(b"test");
        let hash2 = const_fnv1a_hash(b"test");
        let hash3 = const_fnv1a_hash(b"different");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
}
