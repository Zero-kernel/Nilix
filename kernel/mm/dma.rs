//! Unified DMA Buffer Allocation with On-Demand IOMMU Mappings
//!
//! This module provides a unified API for allocating DMA-capable memory with
//! automatic IOMMU mapping support. When an IOMMU is initialized and registered,
//! DMA mappings are installed on-demand for each allocated buffer (instead of
//! pre-mapping large physical regions like 0-1GiB).
//!
//! When no IOMMU is present or initialized, the module falls back to legacy mode
//! where DMA address == physical address with no explicit mapping.
//!
//! # Security Benefits
//!
//! - **On-demand mapping**: Only explicitly allocated DMA buffers are accessible
//!   to devices, preventing DMA attacks against unmapped memory regions.
//! - **Defense-in-depth scrubbing**: Buffers are zeroed on allocation and free
//!   to prevent information leakage.
//! - **Fail-safe behavior**: On mapping failures, memory is scrubbed and leaked
//!   rather than reused under an unknown DMA state.
//!
//! # Usage
//!
//! ```ignore
//! use mm::dma::{alloc_dma_buffer, DmaBuffer};
//!
//! // Allocate a 4KB DMA buffer
//! let buf = alloc_dma_buffer(4096)?;
//!
//! // Get IOVA for device programming
//! let device_addr = buf.iova();
//!
//! // Get CPU-accessible pointer
//! let cpu_ptr = buf.virt_ptr();
//!
//! // Buffer is automatically unmapped and freed on drop
//! drop(buf);
//! ```
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +------------------+
//! | VirtIO Driver    |     | Network Driver   |
//! +--------+---------+     +--------+---------+
//!          |                        |
//!          v                        v
//! +-------------------------------------------+
//! |            mm::dma::alloc_dma_buffer()    |
//! |   - Allocates physical pages              |
//! |   - Calls IOMMU hooks if registered       |
//! |   - Returns DmaBuffer with iova/phys      |
//! +-------------------------------------------+
//!          |
//!          v (if IOMMU enabled)
//! +-------------------------------------------+
//! |          iommu::map_range()               |
//! |   - Installs SLPT entry for buffer        |
//! |   - Invalidates IOTLB                     |
//! +-------------------------------------------+
//! ```

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};
use spin::{Mutex, Once};
use x86_64::{structures::paging::PhysFrame, PhysAddr};

use crate::{buddy_allocator, PHYSICAL_MEMORY_OFFSET};

// ============================================================================
// Constants
// ============================================================================

/// IOMMU domain identifier type (matches iommu::DomainId without dependency).
pub type DomainId = u16;

/// DMA page size (4KiB, matching x86_64 page size).
pub const DMA_PAGE_SIZE: usize = 4096;

/// Maximum physical address reachable via the kernel direct-map (1 GiB).
///
/// The kernel's high-half direct map (PHYSICAL_MEMORY_OFFSET) only covers
/// physical addresses 0-1GiB. Allocations beyond this range cannot be accessed
/// by the CPU via `phys_to_virt`, so we reject them.
const MAX_DIRECT_MAP_PHYS: u64 = 1 << 30; // 1 GiB

// ============================================================================
// Error Types
// ============================================================================

/// DMA allocation and mapping errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    /// Requested size is zero or would overflow alignment calculations.
    InvalidSize,
    /// Physical memory allocation failed (out of memory).
    NoMem,
    /// Allocated memory landed outside the CPU direct-map window (0-1GiB).
    OutOfDirectMapRange,
    /// IOMMU mapping failed (second-level page table error).
    /// The mapping state is uncertain - pages should be leaked to prevent
    /// a device from accessing reused memory.
    IommuMapFailed,
    /// R95-4 FIX: IOMMU mapping was rejected before any mapping was installed.
    /// This is a "safe" failure where pages can be safely freed because
    /// no IOMMU mapping was ever created. Examples:
    /// - IOMMU not initialized
    /// - Domain not found
    /// - Invalid address range (validation rejected)
    IommuMapRejected,
    /// IOMMU unmapping failed.
    IommuUnmapFailed,
}

// ============================================================================
// IOMMU Hooks (Dependency Inversion)
// ============================================================================

/// IOMMU operations registered by the IOMMU subsystem during fail-closed probe.
///
/// This struct uses function pointers to avoid a circular dependency between
/// the `mm` and `iommu` crates. The IOMMU crate registers these hooks during
/// initialization, and the DMA allocator calls them when allocating buffers.
pub struct IommuOps {
    /// Kernel IOMMU domain ID used for DMA isolation.
    pub kernel_domain_id: DomainId,
    /// Map an IOVA range to physical memory in a domain.
    /// Parameters: (domain_id, iova, phys, size, write_allowed)
    pub map_range: fn(DomainId, u64, u64, usize, bool) -> Result<(), DmaError>,
    /// Unmap an IOVA range from a domain.
    /// Parameters: (domain_id, iova, size)
    pub unmap_range: fn(DomainId, u64, usize) -> Result<(), DmaError>,
}

impl IommuOps {
    fn same_identity(&self, other: &Self) -> bool {
        self.kernel_domain_id == other.kernel_domain_id
            && ptr::fn_addr_eq(self.map_range, other.map_range)
            && ptr::fn_addr_eq(self.unmap_range, other.unmap_range)
    }
}

impl Clone for IommuOps {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for IommuOps {}

/// RF180-31: DMA allocation must not fall back to legacy identity DMA while
/// VT-d discovery or publication is in flight. The state transition and the
/// allocator's final disposition are serialized by `IOMMU_GATE`, closing the
/// check-to-return race that an atomic-only post-allocation recheck leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IommuGateState {
    Legacy,
    Probing,
    Active,
    Failed,
}

impl IommuGateState {
    const fn begin_probe(self) -> Option<Self> {
        match self {
            Self::Legacy => Some(Self::Probing),
            Self::Probing | Self::Active | Self::Failed => None,
        }
    }

    const fn finish_without_hardware(self, ops_registered: bool) -> Option<Self> {
        match (self, ops_registered) {
            (Self::Probing, false) => Some(Self::Legacy),
            _ => None,
        }
    }

    const fn fail_probe(self) -> Self {
        match self {
            Self::Active => Self::Active,
            Self::Legacy | Self::Probing | Self::Failed => Self::Failed,
        }
    }

    const fn can_register_ops(self) -> bool {
        matches!(self, Self::Probing)
    }

    const fn can_commit_active(self, ops_registered: bool) -> bool {
        matches!(self, Self::Probing) && ops_registered
    }
}

struct IommuGate {
    state: IommuGateState,
}

static IOMMU_GATE: Mutex<IommuGate> = Mutex::new(IommuGate {
    state: IommuGateState::Legacy,
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IommuGateError {
    InvalidTransition,
    ConflictingOps,
}

/// Global IOMMU operations registered by the IOMMU subsystem.
///
/// `None` is valid only in the `Legacy` or early `Probing` states. Allocation
/// consults `IOMMU_GATE`; absence never implies legacy mode by itself.
static IOMMU_OPS: Once<IommuOps> = Once::new();

/// Enter the fail-closed IOMMU probing state before reading firmware tables.
pub fn begin_iommu_probe() -> Result<(), IommuGateError> {
    let mut gate = IOMMU_GATE.lock();
    gate.state = gate
        .state
        .begin_probe()
        .ok_or(IommuGateError::InvalidTransition)?;
    Ok(())
}

/// Roll back to legacy DMA only when firmware proves that no IOMMU exists and
/// no hooks were installed. Malformed/present hardware must use `fail_iommu_probe`.
pub fn finish_iommu_probe_without_hardware() -> Result<(), IommuGateError> {
    let mut gate = IOMMU_GATE.lock();
    gate.state = gate
        .state
        .finish_without_hardware(IOMMU_OPS.get().is_some())
        .ok_or(IommuGateError::InvalidTransition)?;
    Ok(())
}

/// Make every subsequent DMA allocation fail closed after an initialization
/// error. Active IOMMU operation is never downgraded by this init-only API.
pub fn fail_iommu_probe() {
    let mut gate = IOMMU_GATE.lock();
    gate.state = gate.state.fail_probe();
}

/// Register and identity-verify the dependency-inversion hooks while probing.
/// A conflicting prior registration is terminal rather than first-wins silent.
pub fn register_iommu_ops(ops: IommuOps) -> Result<(), IommuGateError> {
    let gate = IOMMU_GATE.lock();
    if !gate.state.can_register_ops() {
        return Err(IommuGateError::InvalidTransition);
    }
    let expected = ops;
    let installed = IOMMU_OPS.call_once(|| ops);
    if !installed.same_identity(&expected) {
        return Err(IommuGateError::ConflictingOps);
    }
    Ok(())
}

/// True once the expected hook identity has been installed, even while the
/// allocation gate remains in `Probing`.
#[inline]
pub fn iommu_ops_registered() -> bool {
    IOMMU_OPS.get().is_some()
}

/// Publish the caller's core-IOMMU readiness atomics and the DMA `Active` edge
/// under the same gate that serializes final legacy allocation disposition.
pub fn commit_iommu_probe(publish_core_readiness: impl FnOnce()) -> Result<(), IommuGateError> {
    let mut gate = IOMMU_GATE.lock();
    if !gate.state.can_commit_active(IOMMU_OPS.get().is_some()) {
        return Err(IommuGateError::InvalidTransition);
    }
    publish_core_readiness();
    gate.state = IommuGateState::Active;
    Ok(())
}

/// Check if IOMMU operations are registered.
#[inline]
pub fn is_iommu_enabled() -> bool {
    let gate = IOMMU_GATE.lock();
    matches!(gate.state, IommuGateState::Active) && IOMMU_OPS.get().is_some()
}

// ============================================================================
// DmaBuffer
// ============================================================================

/// A physically-contiguous DMA buffer with an (optional) IOMMU mapping.
///
/// When dropped, the buffer is automatically:
/// 1. Unmapped from the IOMMU domain (only if this buffer owns a mapping)
/// 2. Securely zeroed (defense-in-depth against info leaks)
/// 3. Returned to the physical page allocator
///
/// # Safety
///
/// The buffer owns its physical memory and IOMMU mapping. Callers must not
/// use the physical/IOVA addresses after the buffer is dropped.
///
/// # R95-8 FIX: Device Quiescence Requirement
///
/// **IMPORTANT**: Drivers MUST quiesce their devices before dropping DmaBuffer.
///
/// The Drop implementation unmaps the IOMMU pages, but this only prevents
/// **new** DMA transactions. It does NOT guarantee that **in-flight** DMA
/// transactions have completed. If a device has pending DMA operations when
/// the buffer is dropped:
///
/// 1. In-flight reads may complete after unmap but during scrub (defeating scrub)
/// 2. In-flight writes may corrupt newly-reused memory
///
/// To safely drop a DmaBuffer:
///
/// ```ignore
/// // 1. Disable device DMA (e.g., clear bus master enable, reset device)
/// device.disable_dma();
/// // or
/// device.reset();
///
/// // 2. Memory fence to ensure writes are visible
/// core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
///
/// // 3. Now safe to drop the buffer
/// drop(dma_buffer);
/// ```
///
/// Failure to quiesce the device before dropping DmaBuffer is a driver bug
/// that may result in memory corruption or security vulnerabilities.
#[derive(Debug)]
pub struct DmaBuffer {
    /// Physical address of the buffer (for tracking).
    phys: u64,
    /// IO Virtual Address (device-visible address).
    /// For identity mapping, iova == phys.
    iova: u64,
    /// Allocated size in bytes (page-aligned).
    size: usize,
    /// Domain ID this buffer is mapped in.
    domain_id: DomainId,
    /// Exact ownership proof for the IOMMU mapping. A legacy buffer may outlive
    /// later hook installation and must never unmap an entry it did not create.
    iommu_mapped: bool,
}

impl DmaBuffer {
    /// Physical address of the buffer.
    #[inline]
    pub fn phys(&self) -> u64 {
        self.phys
    }

    /// IO Virtual Address (device-visible address).
    ///
    /// Use this address when programming device DMA descriptors.
    #[inline]
    pub fn iova(&self) -> u64 {
        self.iova
    }

    /// Allocated size in bytes.
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Domain ID this buffer is mapped in.
    #[inline]
    pub fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    /// CPU-accessible pointer to the start of the buffer.
    ///
    /// This uses the kernel's direct-map (PHYSICAL_MEMORY_OFFSET) to convert
    /// the physical address to a virtual address.
    ///
    /// # Safety
    ///
    /// The returned pointer is valid only while the DmaBuffer is alive.
    /// Callers must not dereference the pointer after drop().
    #[inline]
    pub fn virt_ptr(&self) -> *mut u8 {
        (self.phys + PHYSICAL_MEMORY_OFFSET) as *mut u8
    }

    /// Get a mutable slice covering the entire buffer.
    ///
    /// # Safety
    ///
    /// Caller must ensure no concurrent device DMA is accessing the buffer.
    #[inline]
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        core::slice::from_raw_parts_mut(self.virt_ptr(), self.size)
    }

    /// Get a slice covering the entire buffer.
    ///
    /// # Safety
    ///
    /// Caller must ensure no concurrent device DMA is writing to the buffer.
    #[inline]
    pub unsafe fn as_slice(&self) -> &[u8] {
        core::slice::from_raw_parts(self.virt_ptr(), self.size)
    }
}

impl Drop for DmaBuffer {
    fn drop(&mut self) {
        if self.size == 0 {
            return;
        }

        let pages = self.size / DMA_PAGE_SIZE;
        if pages == 0 {
            return;
        }

        // Calculate actual allocation size (buddy allocator rounds up to power-of-two).
        // R153-I5 FIX: Use checked_next_power_of_two to match buddy_allocator pattern
        // and avoid debug-mode panic on overflow.
        let alloc_pages = match pages.checked_next_power_of_two() {
            Some(p) => p,
            None => {
                // Overflow — should never happen with valid buffers.
                // Scrub and leak pages to be safe.
                scrub_range(self.phys, self.size);
                return;
            }
        };
        let alloc_bytes = match alloc_pages.checked_mul(DMA_PAGE_SIZE) {
            Some(b) => b,
            None => return, // Overflow - leak the pages (shouldn't happen)
        };

        // Step 1: Unmap from IOMMU domain first (prevents DMA into freed memory).
        // RF180-31: consult hooks only when this exact buffer successfully
        // published a mapping. Legacy buffers can outlive later hook install.
        if self.iommu_mapped {
            let Some(ops) = IOMMU_OPS.get() else {
                scrub_range(self.phys, alloc_bytes);
                kprintln!(
                    "[DMA] WARNING: mapped buffer lost IOMMU ops for iova={:#x} size={}, leaking pages",
                    self.iova,
                    self.size
                );
                return;
            };
            if (ops.unmap_range)(self.domain_id, self.iova, self.size).is_err() {
                // IOMMU unmap failed - scrub and leak pages to prevent reuse
                // under an unknown DMA state. This is fail-safe behavior.
                scrub_range(self.phys, alloc_bytes);
                kprintln!(
                    "[DMA] WARNING: IOMMU unmap failed for iova={:#x} size={}, leaking pages",
                    self.iova,
                    self.size
                );
                return;
            }
        }

        // Step 2: Scrub the buffer (defense-in-depth against info leaks).
        scrub_range(self.phys, alloc_bytes);

        // Step 3: Return pages to the allocator.
        let frame = PhysFrame::containing_address(PhysAddr::new(self.phys));
        buddy_allocator::free_physical_pages(frame, pages);
    }
}

// ============================================================================
// Allocation API
// ============================================================================

/// Align a value up to the specified alignment.
#[inline]
fn align_up(value: usize, align: usize) -> Option<usize> {
    let mask = align.checked_sub(1)?;
    value.checked_add(mask).map(|v| v & !mask)
}

/// Securely zero a physical memory range using volatile writes.
///
/// Uses volatile writes and a compiler fence to ensure the zeroing is not
/// optimized away by the compiler.
#[inline]
fn scrub_range(phys: u64, bytes: usize) {
    let virt = (phys + PHYSICAL_MEMORY_OFFSET) as *mut u8;
    unsafe {
        for i in 0..bytes {
            ptr::write_volatile(virt.add(i), 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Allocate a DMA buffer of at least `size` bytes.
///
/// The returned buffer:
/// - Has its size rounded up to 4KiB alignment
/// - Is zeroed (defense-in-depth)
/// - Is mapped into the kernel IOMMU domain (if IOMMU is enabled)
/// - Uses identity IOVA mapping (iova == phys) for simplicity
///
/// # Arguments
///
/// * `size` - Minimum buffer size in bytes (must be > 0)
///
/// # Returns
///
/// * `Ok(DmaBuffer)` - Successfully allocated and mapped buffer
/// * `Err(DmaError)` - Allocation or mapping failed
///
/// # Security
///
/// - On-demand mapping: Only this buffer is accessible to devices, not all
///   of the 0-1GiB region.
/// - Fail-safe: On mapping failure, memory is scrubbed and leaked (not reused).
/// - Scrubbed: Buffer is always zeroed before returning.
pub fn alloc_dma_buffer(size: usize) -> Result<DmaBuffer, DmaError> {
    if size == 0 {
        return Err(DmaError::InvalidSize);
    }

    // Round up to page alignment.
    let size = align_up(size, DMA_PAGE_SIZE).ok_or(DmaError::InvalidSize)?;
    let pages = size / DMA_PAGE_SIZE;
    if pages == 0 {
        return Err(DmaError::InvalidSize);
    }

    // Fast rejection before touching the buddy allocator. The final decision
    // is repeated under the same gate after allocation to close Legacy->Probing
    // races; this first check avoids needless allocation/scrubbing in steady
    // Probing/Failed states.
    {
        let gate = IOMMU_GATE.lock();
        if matches!(gate.state, IommuGateState::Probing | IommuGateState::Failed) {
            return Err(DmaError::IommuMapRejected);
        }
        if matches!(gate.state, IommuGateState::Active) && IOMMU_OPS.get().is_none() {
            return Err(DmaError::IommuMapRejected);
        }
    }

    // Allocate physical pages from the buddy allocator.
    let frame = buddy_allocator::alloc_physical_pages(pages).ok_or(DmaError::NoMem)?;
    let phys = frame.start_address().as_u64();

    // Buddy allocator rounds up to power-of-two pages.
    // R153-I5 FIX: Use checked_next_power_of_two to match buddy_allocator pattern
    // and avoid debug-mode panic on overflow.
    let alloc_pages = match pages.checked_next_power_of_two() {
        Some(p) => p,
        None => {
            // Overflow — free and fail.
            buddy_allocator::free_physical_pages(frame, pages);
            return Err(DmaError::InvalidSize);
        }
    };
    let alloc_bytes = alloc_pages.checked_mul(DMA_PAGE_SIZE).ok_or_else(|| {
        buddy_allocator::free_physical_pages(frame, pages);
        DmaError::InvalidSize
    })?;

    // Verify the allocation is within the CPU direct-map range.
    let end = phys
        .checked_add(alloc_bytes as u64 - 1)
        .ok_or(DmaError::InvalidSize)?;
    if end >= MAX_DIRECT_MAP_PHYS {
        // Allocation landed outside direct-map window - free and fail.
        buddy_allocator::free_physical_pages(frame, pages);
        return Err(DmaError::OutOfDirectMapRange);
    }

    // Always zero the buffer on allocation (defense-in-depth).
    scrub_range(phys, alloc_bytes);

    // Identity IOVA strategy: keep driver-facing DMA addresses unchanged.
    // This simplifies driver code since iova == phys.
    let iova = phys;

    // Linearize the final legacy-vs-IOMMU disposition against begin/commit/fail
    // transitions. A buffer constructed under Legacy is committed before the
    // gate is released; a transition that wins first makes this allocation fail.
    let active_ops = {
        let gate = IOMMU_GATE.lock();
        match gate.state {
            IommuGateState::Legacy => {
                if IOMMU_OPS.get().is_some() {
                    drop(gate);
                    scrub_range(phys, alloc_bytes);
                    buddy_allocator::free_physical_pages(frame, pages);
                    return Err(DmaError::IommuMapRejected);
                }
                let buffer = DmaBuffer {
                    phys,
                    iova,
                    size,
                    domain_id: 0,
                    iommu_mapped: false,
                };
                drop(gate);
                return Ok(buffer);
            }
            IommuGateState::Probing | IommuGateState::Failed => {
                drop(gate);
                scrub_range(phys, alloc_bytes);
                buddy_allocator::free_physical_pages(frame, pages);
                return Err(DmaError::IommuMapRejected);
            }
            IommuGateState::Active => match IOMMU_OPS.get() {
                Some(ops) => ops,
                None => {
                    drop(gate);
                    scrub_range(phys, alloc_bytes);
                    buddy_allocator::free_physical_pages(frame, pages);
                    return Err(DmaError::IommuMapRejected);
                }
            },
        }
    };
    let domain_id = active_ops.kernel_domain_id;

    // Active mode requires an on-demand IOMMU mapping. Only a successful map
    // sets the buffer's ownership bit used by Drop.
    if let Err(e) = (active_ops.map_range)(domain_id, iova, phys, size, true) {
        // Always scrub before handling error
        scrub_range(phys, alloc_bytes);

        // R95-4 FIX: Classify error and decide whether to free or leak pages
        match e {
            DmaError::IommuMapRejected => {
                // Safe error: no mapping was installed, we can free the pages
                kprintln!(
                    "[DMA] INFO: IOMMU map rejected for phys={:#x} size={}, freeing pages",
                    phys,
                    size
                );
                buddy_allocator::free_physical_pages(frame, pages);
            }
            _ => {
                // Only IommuMapRejected proves that no mapping was installed.
                // Every other (including future) error has uncertain mapping
                // state, so leak the pages to prevent DMA into reused memory.
                kprintln!(
                    "[DMA] WARNING: IOMMU map failed for phys={:#x} size={}, leaking pages",
                    phys,
                    size
                );
            }
        }
        return Err(e);
    }

    Ok(DmaBuffer {
        phys,
        iova,
        size,
        domain_id,
        iommu_mapped: true,
    })
}

/// Explicit free API for callers that prefer it over implicit drop.
///
/// This is equivalent to `drop(buf)`.
#[inline]
pub fn free_dma_buffer(buf: DmaBuffer) {
    drop(buf);
}

// ============================================================================
// Statistics
// ============================================================================

/// Get statistics about DMA allocation.
pub fn stats() -> DmaStats {
    DmaStats {
        iommu_enabled: is_iommu_enabled(),
    }
}

/// DMA subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct DmaStats {
    /// Whether IOMMU-backed allocation is active.
    pub iommu_enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_a(_: DomainId, _: u64, _: u64, _: usize, _: bool) -> Result<(), DmaError> {
        Ok(())
    }

    fn map_b(_: DomainId, _: u64, _: u64, _: usize, _: bool) -> Result<(), DmaError> {
        Ok(())
    }

    fn unmap_a(_: DomainId, _: u64, _: usize) -> Result<(), DmaError> {
        Ok(())
    }

    #[test]
    fn rf180_dma_gate_allows_only_absent_hardware_to_restore_legacy() {
        let probing = IommuGateState::Legacy
            .begin_probe()
            .expect("legacy begins probing");
        assert_eq!(
            probing.finish_without_hardware(false),
            Some(IommuGateState::Legacy)
        );
        assert_eq!(probing.finish_without_hardware(true), None);
        assert_eq!(IommuGateState::Failed.finish_without_hardware(false), None);
    }

    #[test]
    fn rf180_dma_gate_requires_verified_hooks_before_active_commit() {
        let probing = IommuGateState::Legacy
            .begin_probe()
            .expect("legacy begins probing");
        assert!(probing.can_register_ops());
        assert!(!probing.can_commit_active(false));
        assert!(probing.can_commit_active(true));
        assert_eq!(probing.fail_probe(), IommuGateState::Failed);
        assert_eq!(IommuGateState::Failed.fail_probe(), IommuGateState::Failed);
        assert_eq!(IommuGateState::Active.fail_probe(), IommuGateState::Active);
    }

    #[test]
    fn rf180_dma_hook_registration_rejects_conflicting_identity() {
        let expected = IommuOps {
            kernel_domain_id: 0,
            map_range: map_a,
            unmap_range: unmap_a,
        };
        let same = IommuOps {
            kernel_domain_id: 0,
            map_range: map_a,
            unmap_range: unmap_a,
        };
        let wrong_domain = IommuOps {
            kernel_domain_id: 1,
            map_range: map_a,
            unmap_range: unmap_a,
        };
        let wrong_map = IommuOps {
            kernel_domain_id: 0,
            map_range: map_b,
            unmap_range: unmap_a,
        };
        assert!(expected.same_identity(&same));
        assert!(!expected.same_identity(&wrong_domain));
        assert!(!expected.same_identity(&wrong_map));
    }
}
