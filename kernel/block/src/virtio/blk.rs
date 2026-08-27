//! VirtIO Block Device Driver for Zero-OS
//!
//! This module implements a virtio-blk driver supporting both MMIO and PCI transports.
//! It provides a simple synchronous interface for block I/O.
//!
//! # Features
//! - MMIO transport for embedded/virtio-mmio setups
//! - PCI modern transport for standard x86 VMs
//! - Synchronous read/write operations
//! - Proper feature negotiation
//! - Integration with Block Layer

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use spin::Mutex;

use iommu::PciDeviceId;
use mm::dma::{alloc_dma_buffer, DmaBuffer};
use mm::{arc_charge_bytes, try_reserve_heap, vec_charge_bytes, HeapCharge, HeapClass};

use super::{
    blk_features, blk_status, blk_types, mb, rmb, wmb, MmioTransport, VirtioBlkReqHeader,
    VirtioPciAddrs, VirtioPciTransport, VirtioTransport, VringAvail, VringDesc, VringUsed,
    VringUsedElem, VIRTIO_DEVICE_BLK, VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE,
    VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK, VIRTIO_STATUS_FAILED, VIRTIO_STATUS_FEATURES_OK,
    VIRTIO_VERSION_LEGACY, VIRTIO_VERSION_MODERN, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE,
};
use crate::{Bio, BioOp, BioResult, BlockDevice, BlockError};

// ============================================================================
// Constants
// ============================================================================

/// Default queue size.
const DEFAULT_QUEUE_SIZE: u16 = 128;

/// Maximum pending requests.
const MAX_PENDING: usize = 64;

// ============================================================================
// R37-3 FIX (Codex review): Timeout Resource Tracking
// ============================================================================
//
// When a request times out, we keep DMA buffers pinned to prevent UAF (the
// device may complete later, DMAing into freed memory). R106-3 adds a reset &
// recovery path to reclaim the descriptors and buffers by quiescing the device
// and re-initializing it.
//
// This counter tracks how many request resources are currently pinned due to
// timeouts (should return to 0 after successful recovery).
use core::sync::atomic::AtomicUsize;
static TIMEOUT_LEAKED_REQUESTS: AtomicUsize = AtomicUsize::new(0);

/// Get the number of requests that have leaked due to timeouts.
/// Each leaked request holds: 3 descriptors + header buffer + status buffer + data buffer.
pub fn timeout_leaked_count() -> usize {
    TIMEOUT_LEAKED_REQUESTS.load(Ordering::Relaxed)
}

// ============================================================================
// DMA Address Translation (R28-1 Fix)
// ============================================================================

/// Translate a kernel virtual address to a DMA-safe physical address.
///
/// **NOTE**: This function only works correctly for addresses in the direct-mapped
/// kernel region (PHYSICAL_MEMORY_OFFSET). It does NOT work for heap allocations
/// which are mapped via the page table at different physical addresses.
/// For heap buffers, use `alloc_dma_memory` to get physically contiguous DMA-safe memory.
///
/// # Arguments
/// * `ptr` - Virtual address pointer
/// * `len` - Length of the buffer (must be > 0)
///
/// # Returns
/// Physical address suitable for DMA, or BlockError::Invalid if translation fails.
///
/// # Safety
/// The caller must ensure the buffer is in kernel address space (high-half direct map).
#[allow(dead_code)]
fn virt_to_phys_dma(ptr: *const u8, len: usize) -> Result<u64, BlockError> {
    if len == 0 {
        return Err(BlockError::Invalid);
    }

    let virt = ptr as u64;

    // Kernel high-half direct map: 0xffffffff80000000 -> physical 0x0
    // This covers the first 1GB of physical memory where kernel allocations reside.
    const PHYSICAL_MEMORY_OFFSET: u64 = 0xffff_ffff_8000_0000;

    // Verify the address is in the expected kernel range
    if virt < PHYSICAL_MEMORY_OFFSET {
        // Address is not in kernel direct map - this is a programming error
        // User-space buffers should never reach here
        return Err(BlockError::Invalid);
    }

    let phys = virt - PHYSICAL_MEMORY_OFFSET;

    // Overflow check: ensure the entire buffer is within valid physical memory
    // The direct map covers 0-1GB (0x0 to 0x40000000)
    let end = phys
        .checked_add(len as u64 - 1)
        .ok_or(BlockError::Invalid)?;
    if end >= 0x4000_0000 {
        // Beyond direct map coverage - likely an error
        return Err(BlockError::Invalid);
    }

    Ok(phys)
}

// ============================================================================
// VirtQueue Implementation
// ============================================================================

/// A single virtqueue for the device.
pub struct VirtQueue {
    /// Queue size (number of descriptors).
    size: u16,
    /// Queue notify offset (for PCI transport).
    notify_off: u16,
    /// Descriptor table (DMA-able memory).
    desc: *mut VringDesc,
    /// Available ring.
    avail: *mut VringAvail,
    /// Used ring.
    used: *mut VringUsed,
    /// Free descriptor list (simple stack).
    free_head: AtomicU16,
    /// Free descriptor stack.
    free_list: Mutex<Vec<u16>>,
    /// R66-6 FIX: Allocation bitmap for double-free detection.
    /// True = descriptor is allocated, False = descriptor is free.
    alloc_bitmap: Mutex<Vec<bool>>,
    /// Last seen used index.
    last_used_idx: AtomicU16,
    /// Physical address of descriptor table.
    desc_phys: u64,
    /// Physical address of available ring.
    avail_phys: u64,
    /// Physical address of used ring.
    used_phys: u64,
    /// Malformed device-controlled ring state quarantines the queue until a
    /// full reset/reinitialization; this prevents forward-jump resync from
    /// orphaning in-flight descriptor chains.
    fatal: AtomicBool,
}

// SAFETY: VirtQueue contains raw pointers to DMA-able memory
// which is only accessed within synchronized contexts.
unsafe impl Send for VirtQueue {}
unsafe impl Sync for VirtQueue {}

impl VirtQueue {
    /// Calculate the size needed for a virtqueue.
    fn calc_size(queue_size: u16) -> usize {
        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        // R152-18 FIX: Include +2 for used_event/avail_event per VirtIO spec
        let avail_size = 4 + 2 * queue_size as usize + 2; // flags + idx + ring + used_event
        let used_size = 4 + 8 * queue_size as usize + 2; // flags + idx + ring + avail_event

        // Align each section to 4KB for DMA
        let desc_pages = (desc_size + 4095) / 4096;
        let avail_pages = (avail_size + 4095) / 4096;
        let used_pages = (used_size + 4095) / 4096;

        (desc_pages + avail_pages + used_pages) * 4096
    }

    /// Actual ordinary-heap capacity retained by queue-side indices.
    fn heap_charge_bytes(&self) -> Result<usize, BlockError> {
        let free_capacity = self.free_list.lock().capacity();
        let bitmap_capacity = self.alloc_bitmap.lock().capacity();
        let free = vec_charge_bytes::<u16>(free_capacity).map_err(|_| BlockError::NoMem)?;
        let bitmap = vec_charge_bytes::<bool>(bitmap_capacity).map_err(|_| BlockError::NoMem)?;
        free.checked_add(bitmap).ok_or(BlockError::NoMem)
    }

    /// Create a new virtqueue at the given physical address.
    ///
    /// # Safety
    /// The caller must ensure the memory region is valid and DMA-able.
    /// DMA memory is accessed via the kernel's high-half mapping (PHYSICAL_MEMORY_OFFSET).
    unsafe fn try_new(
        base_phys: u64,
        queue_size: u16,
        _virt_offset: u64,
        notify_off: u16,
    ) -> Result<Self, BlockError> {
        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        // R152-18 FIX: Include +2 for used_event per VirtIO spec
        let avail_size = 4 + 2 * queue_size as usize + 2;

        // Calculate aligned offsets
        let desc_pages = (desc_size + 4095) / 4096;
        let avail_pages = (avail_size + 4095) / 4096;

        let desc_phys = base_phys;
        let avail_phys = desc_phys + (desc_pages * 4096) as u64;
        let used_phys = avail_phys + (avail_pages * 4096) as u64;

        // Convert to virtual addresses using kernel's high-half mapping
        // DMA memory from buddy allocator uses PHYSICAL_MEMORY_OFFSET, not the MMIO virt_offset
        let desc = (desc_phys + mm::PHYSICAL_MEMORY_OFFSET) as *mut VringDesc;
        let avail = (avail_phys + mm::PHYSICAL_MEMORY_OFFSET) as *mut VringAvail;
        let used = (used_phys + mm::PHYSICAL_MEMORY_OFFSET) as *mut VringUsed;

        // R180-27 FIX: construct every heap-backed queue index before device
        // publication. Length/capacity are then fixed for the queue lifetime.
        let mut free_list = Vec::new();
        free_list
            .try_reserve_exact(queue_size as usize)
            .map_err(|_| BlockError::NoMem)?;
        for i in (0..queue_size).rev() {
            free_list.push(i);
        }

        let mut alloc_bitmap = Vec::new();
        alloc_bitmap
            .try_reserve_exact(queue_size as usize)
            .map_err(|_| BlockError::NoMem)?;
        alloc_bitmap.resize(queue_size as usize, false);

        // R66-3 FIX: Zero out entire ring structures, not just 1 byte.
        // Previously only 1 byte was zeroed, leaving uninitialized memory
        // exposed to device DMA (info leak) and causing random ring state.
        core::ptr::write_bytes(desc, 0, queue_size as usize);
        // avail ring: flags(2) + idx(2) + ring[queue_size](2*N) + used_event(2)
        let avail_bytes = 4 + 2 * queue_size as usize + 2;
        core::ptr::write_bytes(avail as *mut u8, 0, avail_bytes);
        // used ring: flags(2) + idx(2) + ring[queue_size](8*N) + avail_event(2)
        let used_bytes = 4 + 8 * queue_size as usize + 2;
        core::ptr::write_bytes(used as *mut u8, 0, used_bytes);

        Ok(Self {
            size: queue_size,
            notify_off,
            desc,
            avail,
            used,
            free_head: AtomicU16::new(0),
            free_list: Mutex::new(free_list),
            alloc_bitmap: Mutex::new(alloc_bitmap),
            last_used_idx: AtomicU16::new(0),
            desc_phys,
            avail_phys,
            used_phys,
            fatal: AtomicBool::new(false),
        })
    }

    /// Allocate a descriptor from the free list.
    /// R66-6 FIX: Track allocation in bitmap for double-free detection.
    fn alloc_desc(&self) -> Option<u16> {
        if self.fatal.load(Ordering::Acquire) {
            return None;
        }
        let mut alloc = self.alloc_bitmap.lock();
        let mut free = self.free_list.lock();
        let idx = free.pop()?;
        // Mark as allocated
        if let Some(slot) = alloc.get_mut(idx as usize) {
            *slot = true;
        }
        Some(idx)
    }

    /// Free a descriptor back to the free list.
    /// R66-6 FIX: Check bitmap to detect and prevent double-free.
    fn free_desc(&self, idx: u16) {
        // Bounds check
        if idx >= self.size {
            kprintln!(
                "[virtio-blk] R66-6: free_desc called with OOB index {}",
                idx
            );
            return;
        }

        // Keep the established alloc_bitmap -> free_list lock order used by
        // alloc_desc. Preflight fixed capacity before changing allocation state
        // so even metadata corruption cannot make the final push allocate or
        // leave the descriptor lost.
        let mut alloc = self.alloc_bitmap.lock();
        let mut free = self.free_list.lock();
        if free.len() >= self.size as usize || free.len() >= free.capacity() {
            kprintln!(
                "[virtio-blk] descriptor free-list invariant violated for {}",
                idx
            );
            return;
        }
        let Some(slot) = alloc.get_mut(idx as usize) else {
            return;
        };
        if !*slot {
            kprintln!(
                "[virtio-blk] R66-6 SECURITY: double-free detected for descriptor {}",
                idx
            );
            return;
        }
        *slot = false;
        free.push(idx);
    }

    /// Get available descriptor count.
    fn available_descs(&self) -> usize {
        self.free_list.lock().len()
    }

    /// Push a descriptor chain to the available ring.
    unsafe fn push_avail(&self, head: u16) {
        // R156-15 + R157-8 FIX: Runtime bounds check (defense-in-depth).
        if self.fatal.load(Ordering::Acquire) || self.size == 0 || head >= self.size {
            return;
        }
        let avail = &mut *self.avail;
        let idx = read_volatile(&avail.idx);
        let ring_idx = (idx % self.size) as usize;

        // Write to ring
        let ring_ptr = avail.ring.as_mut_ptr();
        write_volatile(ring_ptr.add(ring_idx), head);

        // Memory barrier before updating idx
        wmb();

        // Update index
        write_volatile(&mut avail.idx, idx.wrapping_add(1));
    }

    /// Check if there are used entries to process.
    fn has_used(&self) -> bool {
        if self.fatal.load(Ordering::Acquire) {
            return false;
        }
        unsafe {
            let used = &*self.used;
            let used_idx = read_volatile(&used.idx);
            let last = self.last_used_idx.load(Ordering::Relaxed);
            used_idx != last
        }
    }

    /// Pop a used entry.
    /// R66-5 FIX: Validate used.idx to detect malicious device behavior:
    /// - Large jumps (more entries than queue size)
    /// - Rollback attacks (used_idx going backwards)
    fn pop_used(&self) -> Option<VringUsedElem> {
        unsafe {
            let used = &*self.used;
            let used_idx = read_volatile(&used.idx);
            let last = self.last_used_idx.load(Ordering::Relaxed);

            if used_idx == last {
                return None;
            }

            // R66-5 FIX: Calculate pending entries with wrapping arithmetic
            // pending = used_idx - last (handling u16 wrap)
            let pending = used_idx.wrapping_sub(last);

            // R66-5 FIX: Validate that pending entries don't exceed queue size
            // A malicious device could set used_idx to arbitrary values
            if pending > self.size {
                // Possible attack: device reported too many completions or rolled back
                kprintln!(
                    "[virtio-blk] R66-5 SECURITY: invalid used.idx jump detected! \
                     used_idx={}, last={}, pending={}, size={}",
                    used_idx,
                    last,
                    pending,
                    self.size
                );
                // Do not resynchronize past the skipped entries: that would
                // strand every descriptor in the interval.  Quarantine until
                // reset_device rebuilds the complete software state.
                self.fatal.store(true, Ordering::Release);
                return None;
            }

            rmb();

            let ring_idx = (last % self.size) as usize;
            let ring_ptr = used.ring.as_ptr();
            let elem = read_volatile(ring_ptr.add(ring_idx));

            // R66-5 FIX: Validate that the returned descriptor ID is within bounds
            if elem.id >= self.size as u32 {
                kprintln!(
                    "[virtio-blk] R66-5 SECURITY: invalid used.id={} exceeds queue size={}",
                    elem.id,
                    self.size
                );
                // Skip this invalid entry
                self.last_used_idx
                    .store(last.wrapping_add(1), Ordering::Relaxed);
                return None;
            }

            self.last_used_idx
                .store(last.wrapping_add(1), Ordering::Relaxed);

            Some(elem)
        }
    }

    /// Get descriptor at index.
    #[allow(clippy::mut_from_ref)] // virtio ring descriptor: &self->&mut via raw pointer is the deliberate unsafe contract
    unsafe fn desc(&self, idx: u16) -> &mut VringDesc {
        if idx >= self.size || self.fatal.load(Ordering::Acquire) {
            panic!("virtio-blk descriptor index outside a live queue");
        }
        &mut *self.desc.add(idx as usize)
    }

    #[inline]
    fn clear_fatal(&self) {
        self.fatal.store(false, Ordering::Release);
    }
}

// ============================================================================
// VirtIO Block Device
// ============================================================================

/// VirtIO block device.
pub struct VirtioBlkDevice {
    /// Device name.
    name: String,
    /// Transport layer (MMIO or PCI).
    transport: VirtioTransport,
    /// PCI identity retained for fail-closed bus-master shutdown on reset failure.
    /// MMIO transports have no PCI command register and store `None`.
    pci_id: Option<PciDeviceId>,
    /// R105-3 FIX: Owned DMA buffer for virtqueue memory.
    /// Keeps the IOMMU mapping alive for the device's lifetime without mem::forget.
    /// Field is intentionally never read — held purely for RAII lifetime management.
    #[allow(dead_code)]
    virtqueue_dma: DmaBuffer,
    /// Virtqueue for requests.
    queue: VirtQueue,
    /// Device capacity in sectors.
    capacity: u64,
    /// Sector size.
    sector_size: u32,
    /// Read-only flag.
    read_only: bool,
    /// Negotiated features.
    features: u64,
    /// Lock for synchronous operations.
    lock: Mutex<()>,
    /// R106-3: Set when the device has failed or is being reset to reject new I/O quickly.
    device_failed: AtomicBool,
    /// Request buffers (header + status).
    req_buffers: Mutex<Vec<RequestBuffer>>,
    /// R180-27/D1: aggregate charge for every ordinary-heap allocation owned
    /// by this device. Kept last so owned buffers are destroyed first.
    _heap_charge: HeapCharge,
}

/// Buffer for a single request.
struct RequestBuffer {
    /// Request header.
    header: VirtioBlkReqHeader,
    /// Status byte.
    status: u8,
    /// In use flag.
    in_use: bool,
    /// R39-1 FIX: In-flight tracking metadata for safe completion handling.
    pending: Option<RequestMeta>,
}

/// R39-1 FIX: Metadata tracked per in-flight request to safely pair completions.
///
/// This structure stores all information needed to correctly free resources
/// when a completion arrives, preventing UAF on stale completions.
///
/// R94-13 Enhancement: Uses DmaBuffer for automatic IOMMU mapping management.
/// When DmaBuffer is dropped, the IOMMU mapping is automatically removed.
struct RequestMeta {
    /// Head descriptor index (matches used.id from the device).
    head: u16,
    /// Descriptor indices used by this request.
    desc_chain: [u16; 3],
    /// Number of valid descriptors in desc_chain.
    desc_count: usize,
    /// DMA buffer for header + status (replaces raw phys/virt addresses).
    header_status_dma: DmaBuffer,
    /// Size of the request header in bytes.
    header_size: usize,
    /// Request kind (I/O or flush) with data buffer tracking.
    kind: RequestKind,
    /// Marked when timed out so late completions are treated as stale.
    abandoned: bool,
}

/// R39-1 FIX: Type of request for proper resource cleanup.
/// R94-13 Enhancement: Uses DmaBuffer for automatic IOMMU unmapping on drop.
enum RequestKind {
    /// Read request with a caller destination for synchronous copy-back.
    Read {
        /// DMA buffer for data (with automatic IOMMU mapping).
        data_dma: DmaBuffer,
        /// Actual data length in bytes (may be less than data_dma.size() which is page-aligned).
        /// R94-13 FIX: Must track separately to avoid OOB copy on completion.
        data_len: usize,
        /// Pointer to caller's buffer for copy-back on read completion.
        data_buf: *mut u8,
    },
    /// Write request. Caller bytes have already been copied into `data_dma`,
    /// so no mutable caller pointer is retained across device execution.
    Write {
        data_dma: DmaBuffer,
        data_len: usize,
    },
    /// Flush request (no data buffer).
    Flush,
}

/// RF178-39 FIX: direction-safe borrowed payload for synchronous I/O.
/// Writes stay immutable and no longer require an infallible caller-buffer clone.
enum SyncRequestData<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

impl SyncRequestData<'_> {
    #[inline]
    fn len(&self) -> usize {
        match self {
            Self::Read(buf) => buf.len(),
            Self::Write(buf) => buf.len(),
        }
    }

    #[inline]
    fn is_write(&self) -> bool {
        matches!(self, Self::Write(_))
    }
}

/// R39-1 FIX: Completion result types.
enum RequestCompletion {
    /// I/O request completed with result.
    Io(Result<usize, BlockError>),
    /// Flush request completed with result.
    Flush(Result<(), BlockError>),
}

// SAFETY: VirtioBlkDevice is designed for single-threaded access
// with internal locking for synchronization.
unsafe impl Send for VirtioBlkDevice {}
unsafe impl Sync for VirtioBlkDevice {}

impl VirtioBlkDevice {
    /// Probe for a virtio-blk device using MMIO transport.
    ///
    /// # Arguments
    /// * `mmio_phys` - Physical address of the MMIO region
    /// * `virt_offset` - Offset to add for virtual address conversion
    /// * `name` - Device name (e.g., "vda")
    ///
    /// # Safety
    /// Caller must ensure the MMIO address is valid and mapped.
    pub unsafe fn probe_mmio(
        mmio_phys: u64,
        virt_offset: u64,
        name: &str,
    ) -> Result<Arc<Self>, BlockError> {
        let transport = MmioTransport::probe(mmio_phys, virt_offset).ok_or(BlockError::NotFound)?;
        Self::probe_with_transport(VirtioTransport::Mmio(transport), None, virt_offset, name)
    }

    /// Probe for a virtio-blk device using virtio-pci modern transport.
    ///
    /// # Arguments
    /// * `pci_id` - PCI bus/device/function identity used for fail-closed shutdown
    /// * `pci_addrs` - Parsed PCI capability addresses
    /// * `virt_offset` - Offset to add for virtual address conversion
    /// * `name` - Device name (e.g., "vda")
    ///
    /// # Safety
    /// Caller must ensure the MMIO windows are mapped (identity mapped low memory).
    pub unsafe fn probe_pci(
        pci_id: PciDeviceId,
        pci_addrs: VirtioPciAddrs,
        virt_offset: u64,
        name: &str,
    ) -> Result<Arc<Self>, BlockError> {
        let transport = VirtioPciTransport::from_addrs(pci_addrs, virt_offset)
            .ok_or(BlockError::NotSupported)?;
        Self::probe_with_transport(
            VirtioTransport::Pci(transport),
            Some(pci_id),
            virt_offset,
            name,
        )
    }

    /// Common probe logic for any transport.
    unsafe fn probe_with_transport(
        transport: VirtioTransport,
        pci_id: Option<PciDeviceId>,
        virt_offset: u64,
        name: &str,
    ) -> Result<Arc<Self>, BlockError> {
        // Check device type
        let device_id = transport.device_id();
        if device_id != VIRTIO_DEVICE_BLK {
            return Err(BlockError::NotFound);
        }

        // Check version
        let version = transport.version();
        if version != VIRTIO_VERSION_LEGACY && version != VIRTIO_VERSION_MODERN {
            return Err(BlockError::NotSupported);
        }

        Self::init_device(transport, pci_id, virt_offset, name)
    }

    /// Initialize the device.
    unsafe fn init_device(
        transport: VirtioTransport,
        pci_id: Option<PciDeviceId>,
        virt_offset: u64,
        name: &str,
    ) -> Result<Arc<Self>, BlockError> {
        // RF180-21 FIX: BME is already enabled when PCI probing reaches this
        // function.  Do not negotiate against a device that merely accepted a
        // one-shot status=0 write: require the reset acknowledgement before any
        // queue ownership is constructed or published.
        Self::reset_probe_transport(transport, pci_id, "initialization")?;

        // Acknowledge device
        transport.set_status(VIRTIO_STATUS_ACKNOWLEDGE);

        // Set DRIVER status
        let status = transport.status();
        transport.set_status(status | VIRTIO_STATUS_DRIVER);

        // Read device features
        let device_features = transport.device_features();

        // Select features we want
        let mut driver_features = 0u64;
        // Modern virtio devices (1.0+) require VIRTIO_F_VERSION_1 to be acknowledged
        if device_features & VIRTIO_F_VERSION_1 != 0 {
            driver_features |= VIRTIO_F_VERSION_1;
        }
        if device_features & blk_features::VIRTIO_BLK_F_RO != 0 {
            driver_features |= blk_features::VIRTIO_BLK_F_RO;
        }
        if device_features & blk_features::VIRTIO_BLK_F_FLUSH != 0 {
            driver_features |= blk_features::VIRTIO_BLK_F_FLUSH;
        }
        if device_features & blk_features::VIRTIO_BLK_F_BLK_SIZE != 0 {
            driver_features |= blk_features::VIRTIO_BLK_F_BLK_SIZE;
        }

        // Write driver features
        transport.write_driver_features(driver_features);

        // Set FEATURES_OK
        let status = transport.status();
        transport.set_status(status | VIRTIO_STATUS_FEATURES_OK);

        // Verify FEATURES_OK
        let status = transport.status();
        if status & VIRTIO_STATUS_FEATURES_OK == 0 {
            Self::reset_probe_transport(transport, pci_id, "FEATURES_OK refusal")?;
            return Err(BlockError::NotSupported);
        }

        // R186-6: capacity is the only mandatory virtio-blk config field. Read
        // exactly its eight bytes so a spec-valid minimal device-config window is
        // accepted. `blk_size` lives at offset 20 and is required/read only when
        // VIRTIO_BLK_F_BLK_SIZE was actually negotiated.
        let mut capacity_bytes = [0u8; 8];
        if !transport.read_config_bytes(0, &mut capacity_bytes) {
            Self::reset_probe_transport(transport, pci_id, "capacity window too small")?;
            return Err(BlockError::NotSupported);
        }
        let capacity = u64::from_le_bytes(capacity_bytes);
        let sector_size = if driver_features & blk_features::VIRTIO_BLK_F_BLK_SIZE != 0 {
            let mut block_size_bytes = [0u8; 4];
            if !transport.read_config_bytes(20, &mut block_size_bytes) {
                Self::reset_probe_transport(transport, pci_id, "block-size window too small")?;
                return Err(BlockError::NotSupported);
            }
            let block_size = u32::from_le_bytes(block_size_bytes);
            if block_size != 0 {
                block_size
            } else {
                512
            }
        } else {
            512
        };
        let read_only = driver_features & blk_features::VIRTIO_BLK_F_RO != 0;

        // Setup queue 0
        let queue_size_max = transport.queue_max(0);
        let queue_size = queue_size_max.min(DEFAULT_QUEUE_SIZE);

        if queue_size == 0 {
            Self::reset_probe_transport(transport, pci_id, "invalid queue size")?;
            return Err(BlockError::NotSupported);
        }

        // R180-27/D1 FIX: reserve the complete ordinary-heap ownership set
        // before the first allocation. The estimate is reconciled with actual
        // allocator capacities while every object is still private.
        let estimated_heap_bytes = arc_charge_bytes::<Self>()
            .and_then(|total| {
                vec_charge_bytes::<u8>(name.len()).and_then(|name_bytes| {
                    total
                        .checked_add(name_bytes)
                        .ok_or(mm::HeapAdmissionError::ArithmeticOverflow)
                })
            })
            .and_then(|total| {
                vec_charge_bytes::<RequestBuffer>(MAX_PENDING).and_then(|request_bytes| {
                    total
                        .checked_add(request_bytes)
                        .ok_or(mm::HeapAdmissionError::ArithmeticOverflow)
                })
            })
            .and_then(|total| {
                vec_charge_bytes::<u16>(queue_size as usize).and_then(|free_bytes| {
                    total
                        .checked_add(free_bytes)
                        .ok_or(mm::HeapAdmissionError::ArithmeticOverflow)
                })
            })
            .and_then(|total| {
                vec_charge_bytes::<bool>(queue_size as usize).and_then(|bitmap_bytes| {
                    total
                        .checked_add(bitmap_bytes)
                        .ok_or(mm::HeapAdmissionError::ArithmeticOverflow)
                })
            });
        let estimated_heap_bytes = match estimated_heap_bytes {
            Ok(bytes) => bytes,
            Err(_) => {
                Self::reset_probe_transport(transport, pci_id, "heap estimate failure")?;
                return Err(BlockError::NoMem);
            }
        };
        let mut heap_reservation = match try_reserve_heap(HeapClass::Device, estimated_heap_bytes) {
            Ok(reservation) => reservation,
            Err(_) => {
                Self::reset_probe_transport(transport, pci_id, "heap admission failure")?;
                return Err(BlockError::NoMem);
            }
        };

        // R180-27: Finish every fallible ordinary-heap allocation before the
        // queue is published to the device.  Both containers retain fixed
        // capacity for the device lifetime, so request completion and
        // descriptor return never need to grow them under pressure.
        let mut owned_name = String::new();
        if owned_name.try_reserve_exact(name.len()).is_err() {
            Self::reset_probe_transport(transport, pci_id, "name allocation failure")?;
            return Err(BlockError::NoMem);
        }
        owned_name.push_str(name);

        let mut req_buffers = Vec::new();
        if req_buffers.try_reserve_exact(MAX_PENDING).is_err() {
            Self::reset_probe_transport(transport, pci_id, "request allocation failure")?;
            return Err(BlockError::NoMem);
        }
        for _ in 0..MAX_PENDING {
            req_buffers.push(RequestBuffer {
                header: VirtioBlkReqHeader::default(),
                status: 0,
                in_use: false,
                pending: None,
            });
        }

        // Allocate queue memory (simplified: use high physical memory)
        // In a real implementation, this would use a proper DMA allocator
        let queue_mem_size = VirtQueue::calc_size(queue_size);
        // R105-3 FIX: Keep DmaBuffer ownership instead of extracting phys + forget.
        let virtqueue_dma = match Self::alloc_dma_memory(queue_mem_size) {
            Ok(dma) => dma,
            Err(error) => {
                Self::reset_probe_transport(transport, pci_id, "queue DMA allocation failure")?;
                return Err(error);
            }
        };
        let queue_phys = virtqueue_dma.phys();

        // Get notify offset for PCI transport
        let notify_off = transport.queue_notify_off(0);

        // Create virtqueue
        let queue = match VirtQueue::try_new(queue_phys, queue_size, virt_offset, notify_off) {
            Ok(queue) => queue,
            Err(error) => {
                Self::reset_probe_transport(transport, pci_id, "virtqueue construction failure")?;
                return Err(error);
            }
        };

        let actual_heap_bytes = arc_charge_bytes::<Self>()
            .and_then(|total| {
                vec_charge_bytes::<u8>(owned_name.capacity()).and_then(|name_bytes| {
                    total
                        .checked_add(name_bytes)
                        .ok_or(mm::HeapAdmissionError::ArithmeticOverflow)
                })
            })
            .and_then(|total| {
                vec_charge_bytes::<RequestBuffer>(req_buffers.capacity()).and_then(
                    |request_bytes| {
                        total
                            .checked_add(request_bytes)
                            .ok_or(mm::HeapAdmissionError::ArithmeticOverflow)
                    },
                )
            })
            .map_err(|_| BlockError::NoMem)
            .and_then(|total| {
                queue
                    .heap_charge_bytes()
                    .and_then(|queue_bytes| total.checked_add(queue_bytes).ok_or(BlockError::NoMem))
            });
        let actual_heap_bytes = match actual_heap_bytes {
            Ok(bytes) => bytes,
            Err(error) => {
                Self::reset_probe_transport(transport, pci_id, "heap reconciliation failure")?;
                return Err(error);
            }
        };
        if heap_reservation.resize(actual_heap_bytes).is_err() {
            Self::reset_probe_transport(transport, pci_id, "heap reservation resize failure")?;
            return Err(BlockError::NoMem);
        }
        let heap_charge = match heap_reservation.commit() {
            Ok(charge) => charge,
            Err(_) => {
                Self::reset_probe_transport(transport, pci_id, "heap reservation commit failure")?;
                return Err(BlockError::NoMem);
            }
        };

        // Allocate the published owner before exposing any DMA address or
        // setting DRIVER_OK. VirtioTransport is a copyable MMIO capability, so
        // retain a reset handle for the allocation-failure path after the value
        // itself has moved into `Self`.
        let reset_transport = transport;
        let device = match Arc::try_new(Self {
            name: owned_name,
            transport,
            pci_id,
            virtqueue_dma,
            queue,
            capacity,
            sector_size,
            read_only,
            features: driver_features,
            lock: Mutex::new(()),
            device_failed: AtomicBool::new(false),
            req_buffers: Mutex::new(req_buffers),
            _heap_charge: heap_charge,
        }) {
            Ok(device) => device,
            Err(_) => {
                Self::reset_probe_transport(
                    reset_transport,
                    pci_id,
                    "device owner allocation failure",
                )?;
                return Err(BlockError::NoMem);
            }
        };

        // Only now publish queue addresses and readiness to the device.
        device.transport.setup_queue(
            0,
            queue_size,
            device.queue.desc_phys,
            device.queue.avail_phys,
            device.queue.used_phys,
        );
        device.transport.queue_ready(0, true);

        // DRIVER_OK is the final publication step. Read it back so a transport
        // or device that refuses the transition cannot escape as a usable block
        // device. If reset is not acknowledged, quarantine the Arc (and thus
        // its DMA/IOMMU mapping) rather than returning those pages to the buddy.
        let status = device.transport.status();
        device
            .transport
            .set_status(status | VIRTIO_STATUS_DRIVER_OK);
        mb();
        let final_status = device.transport.status();
        if final_status & VIRTIO_STATUS_DRIVER_OK == 0 || final_status & VIRTIO_STATUS_FAILED != 0 {
            device.device_failed.store(true, Ordering::Release);
            const INIT_RESET_ACK_SPINS: u32 = 1_000_000;
            let reset_acked = device.transport.reset_and_await_ack(INIT_RESET_ACK_SPINS);
            mb();
            if !reset_acked {
                if let Some(pci_id) = device.pci_id {
                    if !crate::pci::disable_bus_master(pci_id) {
                        panic!(
                            "R180-27: cannot fail closed: PCI BME remains set for {:02x}:{:02x}.{} after init reset timeout",
                            pci_id.bus, pci_id.device, pci_id.function
                        );
                    }
                }
                core::mem::forget(device);
            }
            return Err(BlockError::Io);
        }

        Ok(device)
    }

    /// Quiesce a probe that has not returned a published device owner.
    ///
    /// A failed reset on PCI is contained by disabling and read-back verifying
    /// bus mastering before any staged allocation is allowed to drop.  MMIO
    /// transports have no equivalent DMA gate, so continuing after an
    /// unacknowledged reset cannot be made memory-safe and is terminal.
    unsafe fn reset_probe_transport(
        transport: VirtioTransport,
        pci_id: Option<PciDeviceId>,
        phase: &'static str,
    ) -> Result<(), BlockError> {
        const PROBE_RESET_ACK_SPINS: u32 = 1_000_000;

        if unsafe { transport.reset_and_await_ack(PROBE_RESET_ACK_SPINS) } {
            mb();
            return Ok(());
        }

        if let Some(pci_id) = pci_id {
            if !crate::pci::disable_bus_master(pci_id) {
                panic!(
                    "RF180-21: cannot fail closed: PCI BME remains set for {:02x}:{:02x}.{} after {} reset timeout",
                    pci_id.bus, pci_id.device, pci_id.function, phase
                );
            }
            mb();
            return Err(BlockError::Io);
        }

        panic!(
            "RF180-21: MMIO virtio-blk {} reset was not acknowledged and no DMA gate exists",
            phase
        );
    }

    /// Allocate DMA-able memory using the unified DMA allocator with IOMMU mapping.
    ///
    /// R105-3 FIX: Returns the `DmaBuffer` directly so ownership can be retained
    /// by the caller, avoiding `core::mem::forget` and ensuring the IOMMU mapping
    /// is automatically cleaned up when the device is dropped.
    fn alloc_dma_memory(size: usize) -> Result<DmaBuffer, BlockError> {
        alloc_dma_buffer(size).map_err(|_| BlockError::NoMem)
    }

    /// Notify the device of new available descriptors.
    fn notify(&self) {
        unsafe {
            self.transport.notify(0, self.queue.notify_off);
        }
    }

    /// R39-1 FIX: Match a used ring entry to the correct request and complete it.
    ///
    /// This method finds the request that corresponds to the given `used.id`,
    /// frees its resources correctly, and returns the completion result.
    /// For abandoned (timed-out) requests, it cleans up silently and returns None.
    ///
    /// R94-13 Enhancement: DmaBuffer is now dropped automatically when RequestMeta
    /// goes out of scope, ensuring IOMMU mappings are cleaned up properly.
    fn complete_used_entry(&self, used: VringUsedElem) -> Option<RequestCompletion> {
        let mut buffers = self.req_buffers.lock();

        // Find the request buffer matching this completion's head descriptor
        let (_idx, buffer) = match buffers.iter_mut().enumerate().find(|(_, b)| {
            b.in_use
                && b.pending
                    .as_ref()
                    .map(|meta| meta.head as u32 == used.id)
                    .unwrap_or(false)
        }) {
            Some(entry) => entry,
            None => {
                kprintln!(
                    "[virtio-blk] completion for unknown descriptor head={} ignored",
                    used.id
                );
                return None;
            }
        };

        // Take ownership of the metadata (DmaBuffers will be dropped when meta goes out of scope)
        let meta = match buffer.pending.take() {
            Some(m) => m,
            None => {
                kprintln!(
                    "[virtio-blk] completion for descriptor head={} without metadata",
                    used.id
                );
                return None;
            }
        };

        let RequestMeta {
            head,
            desc_chain,
            desc_count,
            header_status_dma,
            header_size,
            kind,
            abandoned,
        } = meta;

        // Read status from DMA buffer
        let status = unsafe { core::ptr::read(header_status_dma.virt_ptr().add(header_size)) };

        // Process based on request kind
        let completion = match kind {
            RequestKind::Read {
                data_dma,
                data_len,
                data_buf,
            } => {
                // For successful reads on non-abandoned requests, copy data back.
                // R94-13 FIX: Use data_len (actual buffer size) not data_dma.size() (page-aligned)
                if !abandoned && status == blk_status::VIRTIO_BLK_S_OK && data_len > 0 {
                    unsafe {
                        core::ptr::copy_nonoverlapping(data_dma.virt_ptr(), data_buf, data_len);
                    }
                }

                if abandoned {
                    None
                } else {
                    Some(RequestCompletion::Io(match status {
                        blk_status::VIRTIO_BLK_S_OK => Ok(data_len),
                        blk_status::VIRTIO_BLK_S_IOERR => Err(BlockError::Io),
                        blk_status::VIRTIO_BLK_S_UNSUPP => Err(BlockError::NotSupported),
                        _ => Err(BlockError::Io),
                    }))
                }
                // data_dma is dropped here, automatically unmapping from IOMMU
            }
            RequestKind::Write { data_len, .. } => {
                if abandoned {
                    None
                } else {
                    Some(RequestCompletion::Io(match status {
                        blk_status::VIRTIO_BLK_S_OK => Ok(data_len),
                        blk_status::VIRTIO_BLK_S_IOERR => Err(BlockError::Io),
                        blk_status::VIRTIO_BLK_S_UNSUPP => Err(BlockError::NotSupported),
                        _ => Err(BlockError::Io),
                    }))
                }
            }
            RequestKind::Flush => {
                if abandoned {
                    None
                } else {
                    Some(RequestCompletion::Flush(match status {
                        blk_status::VIRTIO_BLK_S_OK => Ok(()),
                        blk_status::VIRTIO_BLK_S_UNSUPP => Err(BlockError::NotSupported),
                        _ => Err(BlockError::Io),
                    }))
                }
            }
        };

        // Free descriptors back to the pool
        for idx in desc_chain.iter().take(desc_count) {
            self.queue.free_desc(*idx);
        }

        // DmaBuffers (header_status_dma and data_dma if I/O) are automatically
        // dropped here, which triggers IOMMU unmapping via DmaBuffer::drop()

        // Release the request buffer slot
        buffer.in_use = false;

        // Handle abandoned requests (late completions)
        if abandoned {
            // Decrement leaked counter since we've now recovered the resources
            let _ =
                TIMEOUT_LEAKED_REQUESTS
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
            kprintln!(
                "[virtio-blk] late completion for abandoned request head={} status={}",
                head,
                status
            );
            return None;
        }

        completion
    }

    /// R106-3: Reset and reinitialize the virtio-blk device to recover from timeouts.
    ///
    /// This is called when an I/O request times out. It:
    /// 1. Sets `device_failed` to block new I/O
    /// 2. Resets the device via VirtIO status register (writing 0)
    /// 3. Reclaims all in-flight DMA buffers (scrubbed for security)
    /// 4. Resets virtqueue descriptor/ring state
    /// 5. Re-initializes the device through the standard VirtIO init sequence
    /// 6. Clears `device_failed` on successful recovery
    ///
    /// Caller must hold `self.lock` (enforced by the guard parameter).
    fn reset_device(&self, _lock_proof: &spin::MutexGuard<'_, ()>) -> Result<(), BlockError> {
        // Block new I/O immediately.
        self.device_failed.store(true, Ordering::Release);

        kprintln!(
            "[virtio-blk] R106-3: initiating device reset for {}",
            self.name
        );

        // R180-16 FIX: VirtIO reset must be acknowledged before DMA pages are
        // scrubbed/dropped. The DMA contract (mm/dma.rs) states unmap does not
        // drain in-flight device writes — freeing after a one-shot status=0
        // write races a slow device. Poll status==0 with a bounded spin; if
        // quiescence cannot be proven, leave buffers abandoned (leaked) rather
        // than reusable, and keep device_failed sticky.
        const RESET_ACK_SPINS: u32 = 1_000_000;
        let reset_acked = unsafe { self.transport.reset_and_await_ack(RESET_ACK_SPINS) };
        mb();
        if !reset_acked {
            // A PCI device that ignores the VirtIO reset may remain capable of
            // DMA. Clear and read back BME before quarantining the buffers so
            // the failed device cannot issue new transactions into them.
            if let Some(pci_id) = self.pci_id {
                if !crate::pci::disable_bus_master(pci_id) {
                    panic!(
                        "R180-16/17: cannot fail closed: PCI BME remains set for {:02x}:{:02x}.{} after reset timeout",
                        pci_id.bus, pci_id.device, pci_id.function
                    );
                }
            }
            kprintln!(
                "[virtio-blk] R180-16: reset not acknowledged for {} — quarantining in-flight DMA",
                self.name
            );
            // Quarantine: forget RequestMeta so DmaBuffers are never Drop'd into
            // the buddy. Leave in_use=true so slots are not refilled while the
            // device is sticky-failed (descriptor indices stay allocated too —
            // correct because device_failed blocks new I/O permanently here).
            let mut buffers = self.req_buffers.lock();
            for buffer in buffers.iter_mut() {
                if !buffer.in_use {
                    continue;
                }
                if let Some(m) = buffer.pending.take() {
                    // Intentionally leak DmaBuffers + descriptor accounting.
                    core::mem::forget(m);
                }
                // Keep in_use=true: slot must not look free while descs/DMA are
                // quarantined. device_failed stays sticky (no re-init below).
            }
            // Leave device_failed set and do not re-init. For PCI transports BME
            // is now verified clear; leaked DMA remains the conservative floor
            // because reset acknowledgement (and thus full quiescence) failed.
            return Err(BlockError::Io);
        }

        // Reclaim all in-use request buffers and their DMA resources.
        let mut recovered_leaked = 0usize;
        {
            let mut buffers = self.req_buffers.lock();
            for buffer in buffers.iter_mut() {
                if !buffer.in_use {
                    continue;
                }

                let meta = match buffer.pending.take() {
                    Some(m) => m,
                    None => {
                        // No metadata — just release the slot.
                        buffer.in_use = false;
                        continue;
                    }
                };

                let RequestMeta {
                    desc_chain,
                    desc_count,
                    header_status_dma,
                    kind,
                    abandoned,
                    ..
                } = meta;

                if abandoned {
                    recovered_leaked += 1;
                }

                // Scrub DMA buffers before dropping (prevent data leakage).
                unsafe {
                    core::ptr::write_bytes(
                        header_status_dma.virt_ptr(),
                        0,
                        header_status_dma.size(),
                    );
                }

                match kind {
                    RequestKind::Read { data_dma, .. } | RequestKind::Write { data_dma, .. } => unsafe {
                        core::ptr::write_bytes(data_dma.virt_ptr(), 0, data_dma.size());
                        // data_dma dropped here → IOMMU unmap
                    },
                    RequestKind::Flush => {}
                }
                // header_status_dma dropped here → IOMMU unmap

                // Free descriptors back to the queue pool.
                for idx in desc_chain.iter().take(desc_count) {
                    self.queue.free_desc(*idx);
                }

                buffer.in_use = false;
            }
        }

        // Reset virtqueue software state: used index, descriptor allocation.
        self.queue.last_used_idx.store(0, Ordering::Relaxed);
        self.queue.clear_fatal();

        {
            let qsz = self.queue.size as usize;

            // Lock ordering: alloc_bitmap → free_list (consistent with alloc/free paths).
            let mut alloc = self.queue.alloc_bitmap.lock();
            alloc.clear();
            alloc.resize(qsz, false);

            let mut free = self.queue.free_list.lock();
            free.clear();
            free.reserve(qsz);
            for i in (0..self.queue.size).rev() {
                free.push(i);
            }
        }

        // Clear ring memory so used/avail indices restart from 0.
        unsafe {
            let qsz = self.queue.size;
            core::ptr::write_bytes(self.queue.desc, 0, qsz as usize);
            let avail_bytes = 4 + 2 * qsz as usize + 2;
            core::ptr::write_bytes(self.queue.avail as *mut u8, 0, avail_bytes);
            let used_bytes = 4 + 8 * qsz as usize + 2;
            core::ptr::write_bytes(self.queue.used as *mut u8, 0, used_bytes);
        }

        // Decrement global leaked counter for resources we recovered.
        if recovered_leaked != 0 {
            let _ =
                TIMEOUT_LEAKED_REQUESTS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    v.checked_sub(recovered_leaked)
                });
        }

        // Re-initialize the device: ACKNOWLEDGE → DRIVER → features → FEATURES_OK → queue → DRIVER_OK.
        let driver_features = self.features;
        unsafe {
            self.transport.set_status(VIRTIO_STATUS_ACKNOWLEDGE);

            let status = self.transport.status();
            self.transport.set_status(status | VIRTIO_STATUS_DRIVER);

            self.transport.write_driver_features(driver_features);

            let status = self.transport.status();
            self.transport
                .set_status(status | VIRTIO_STATUS_FEATURES_OK);

            let status = self.transport.status();
            if status & VIRTIO_STATUS_FEATURES_OK == 0 {
                self.transport.set_status(status | VIRTIO_STATUS_FAILED);
                kprintln!("[virtio-blk] R106-3: FEATURES_OK not accepted after reset");
                return Err(BlockError::NotSupported);
            }

            // U41-3 FIX: device configuration is not immutable across a
            // reset. Re-read the authoritative capacity and negotiated block
            // size before publishing DRIVER_OK; if geometry changed, keep the
            // device failed rather than issuing requests with stale bounds.
            let mut capacity_bytes = [0u8; 8];
            if !self.transport.read_config_bytes(0, &mut capacity_bytes) {
                self.transport.set_status(VIRTIO_STATUS_FAILED);
                return Err(BlockError::NotSupported);
            }
            let reset_capacity = u64::from_le_bytes(capacity_bytes);
            let reset_sector_size = if driver_features & blk_features::VIRTIO_BLK_F_BLK_SIZE != 0 {
                let mut block_size_bytes = [0u8; 4];
                if !self.transport.read_config_bytes(20, &mut block_size_bytes) {
                    self.transport.set_status(VIRTIO_STATUS_FAILED);
                    return Err(BlockError::NotSupported);
                }
                let block_size = u32::from_le_bytes(block_size_bytes);
                if block_size == 0 {
                    512
                } else {
                    block_size
                }
            } else {
                512
            };
            if reset_capacity != self.capacity || reset_sector_size != self.sector_size {
                self.transport.set_status(VIRTIO_STATUS_FAILED);
                kprintln!(
                    "[virtio-blk] U41-3: geometry changed across reset (capacity {}->{}, sector {}->{})",
                    self.capacity,
                    reset_capacity,
                    self.sector_size,
                    reset_sector_size
                );
                return Err(BlockError::Offline);
            }

            // Validate queue size is still compatible.
            let queue_size_max = self.transport.queue_max(0);
            if self.queue.size == 0 || self.queue.size > queue_size_max {
                let status = self.transport.status();
                self.transport.set_status(status | VIRTIO_STATUS_FAILED);
                kprintln!(
                    "[virtio-blk] R106-3: queue size {} exceeds max {} after reset",
                    self.queue.size,
                    queue_size_max
                );
                return Err(BlockError::NotSupported);
            }

            self.transport.setup_queue(
                0,
                self.queue.size,
                self.queue.desc_phys,
                self.queue.avail_phys,
                self.queue.used_phys,
            );
            self.transport.queue_ready(0, true);

            let status = self.transport.status();
            self.transport.set_status(status | VIRTIO_STATUS_DRIVER_OK);
        }

        // RF180-21 FIX: the status write is a request, not evidence that the
        // device accepted the recovered queue. Keep failure sticky unless a
        // readback proves DRIVER_OK and proves FAILED clear.
        mb();
        let recovered_status = unsafe { self.transport.status() };
        if recovered_status & VIRTIO_STATUS_DRIVER_OK == 0
            || recovered_status & VIRTIO_STATUS_FAILED != 0
        {
            if recovered_status & VIRTIO_STATUS_FAILED == 0 {
                unsafe {
                    self.transport
                        .set_status(recovered_status | VIRTIO_STATUS_FAILED);
                }
            }
            kprintln!(
                "[virtio-blk] RF180-21: device {} rejected DRIVER_OK after reset (status={:#x})",
                self.name,
                recovered_status
            );
            return Err(BlockError::Io);
        }

        // Recovery is hardware-acknowledged; only this point may reopen I/O.
        self.device_failed.store(false, Ordering::Release);
        kprintln!(
            "[virtio-blk] R106-3: device {} reset successful, recovered {} abandoned requests",
            self.name,
            recovered_leaked
        );
        Ok(())
    }

    /// Process a single synchronous request.
    fn do_request(&self, sector: u64, mut data: SyncRequestData<'_>) -> Result<usize, BlockError> {
        // R106-3: Reject I/O immediately if device is failed/resetting.
        if self.device_failed.load(Ordering::Acquire) {
            return Err(BlockError::Offline);
        }
        let is_write = data.is_write();
        let buf_len = data.len();
        if is_write && self.read_only {
            return Err(BlockError::ReadOnly);
        }

        // R28-2 Fix: Validate buffer alignment and capacity bounds
        // R32-BLK-1 FIX: Use consistent byte-based bounds checking
        // VirtIO spec: capacity is always in 512-byte sectors, but blk_size may differ
        if buf_len == 0 {
            return Err(BlockError::Invalid);
        }
        // R32-BLK-1 additional hardening: prevent u32 wrap in descriptor length
        if buf_len > u32::MAX as usize {
            return Err(BlockError::Invalid);
        }
        const VIRTIO_CAPACITY_SECTOR_SIZE: u64 = 512;
        let sector_size = self.sector_size as u64;
        let buf_len_u64 = buf_len as u64;

        // Buffer must be aligned to logical sector size
        if buf_len_u64 % sector_size != 0 {
            return Err(BlockError::Invalid);
        }

        // Convert to byte offsets for consistent bounds checking
        let start_byte = sector.checked_mul(sector_size).ok_or(BlockError::Invalid)?;
        let end_byte = start_byte
            .checked_add(buf_len_u64)
            .ok_or(BlockError::Invalid)?;
        let capacity_bytes = self
            .capacity
            .checked_mul(VIRTIO_CAPACITY_SECTOR_SIZE)
            .ok_or(BlockError::Invalid)?;

        // Start must be aligned to 512-byte boundary for VirtIO header
        if start_byte % VIRTIO_CAPACITY_SECTOR_SIZE != 0 {
            return Err(BlockError::Invalid);
        }

        // End must not exceed device capacity
        if end_byte > capacity_bytes {
            return Err(BlockError::Invalid);
        }

        // Calculate sector in 512-byte units for VirtIO request header
        let header_sector = start_byte / VIRTIO_CAPACITY_SECTOR_SIZE;

        let _lock = self.lock.lock();
        // Pair the optimistic fast rejection above with a serialized check.
        // A publication rollback/reset can set the sticky failure bit while a
        // request waits for this lock; it must not submit after reset completes.
        if self.device_failed.load(Ordering::Acquire) {
            return Err(BlockError::Offline);
        }

        // Get a request buffer
        let buf_idx = {
            let mut buffers = self.req_buffers.lock();
            let idx = buffers.iter().position(|b| !b.in_use);
            match idx {
                Some(i) => {
                    buffers[i].in_use = true;
                    buffers[i].header.req_type = if is_write {
                        blk_types::VIRTIO_BLK_T_OUT
                    } else {
                        blk_types::VIRTIO_BLK_T_IN
                    };
                    buffers[i].header.reserved = 0;
                    buffers[i].header.sector = header_sector; // R32-BLK-1: Use 512-byte sector units
                    buffers[i].status = 0xFF; // Invalid status
                    i
                }
                None => return Err(BlockError::Busy),
            }
        };

        // DMA bounce buffer for header/status with on-demand IOMMU mapping (R94-13)
        let header_size = core::mem::size_of::<VirtioBlkReqHeader>();
        let header_status_dma_size = if header_size + 1 < 32 {
            32
        } else {
            header_size + 1
        };
        let header_status_dma = match alloc_dma_buffer(header_status_dma_size) {
            Ok(buf) => buf,
            Err(_) => {
                self.req_buffers.lock()[buf_idx].in_use = false;
                return Err(BlockError::NoMem);
            }
        };

        // Copy header to DMA buffer and initialize status to 0xFF (invalid)
        unsafe {
            let header = {
                let buffers = self.req_buffers.lock();
                buffers[buf_idx].header
            };
            core::ptr::write(
                header_status_dma.virt_ptr() as *mut VirtioBlkReqHeader,
                header,
            );
            core::ptr::write(header_status_dma.virt_ptr().add(header_size), 0xFFu8);
        }
        let header_phys = header_status_dma.phys();
        let status_phys = header_status_dma.phys() + header_size as u64;

        // DMA bounce buffer for data with on-demand IOMMU mapping (R94-13)
        let data_dma = match alloc_dma_buffer(buf_len) {
            Ok(dma) => dma,
            Err(_) => {
                // header_status_dma is dropped automatically here, unmapping from IOMMU
                self.req_buffers.lock()[buf_idx].in_use = false;
                return Err(BlockError::NoMem);
            }
        };

        // For writes: copy from caller buffer into DMA buffer before I/O
        if let SyncRequestData::Write(buf) = &data {
            unsafe {
                core::ptr::copy_nonoverlapping(buf.as_ptr(), data_dma.virt_ptr(), buf_len);
            }
        }

        // Allocate 3 descriptors
        let desc0 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => {
                // DmaBuffers are dropped automatically here
                self.req_buffers.lock()[buf_idx].in_use = false;
                return Err(BlockError::Busy);
            }
        };
        let desc1 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => {
                self.queue.free_desc(desc0);
                // DmaBuffers are dropped automatically here
                self.req_buffers.lock()[buf_idx].in_use = false;
                return Err(BlockError::Busy);
            }
        };
        let desc2 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => {
                self.queue.free_desc(desc0);
                self.queue.free_desc(desc1);
                // DmaBuffers are dropped automatically here
                self.req_buffers.lock()[buf_idx].in_use = false;
                return Err(BlockError::Busy);
            }
        };

        unsafe {
            // Descriptor 0: Header (device reads)
            let d0 = self.queue.desc(desc0);
            d0.addr = header_phys;
            d0.len = core::mem::size_of::<VirtioBlkReqHeader>() as u32;
            d0.flags = VRING_DESC_F_NEXT;
            d0.next = desc1;

            // Descriptor 1: Data buffer (use DMA bounce buffer)
            let d1 = self.queue.desc(desc1);
            d1.addr = data_dma.phys();
            d1.len = buf_len as u32;
            d1.flags = VRING_DESC_F_NEXT | if is_write { 0 } else { VRING_DESC_F_WRITE };
            d1.next = desc2;

            // Descriptor 2: Status (device writes)
            let d2 = self.queue.desc(desc2);
            d2.addr = status_phys;
            d2.len = 1;
            d2.flags = VRING_DESC_F_WRITE;
            d2.next = 0;
        }

        let request_kind = match &mut data {
            SyncRequestData::Read(buf) => RequestKind::Read {
                data_dma,
                data_len: buf_len,
                data_buf: buf.as_mut_ptr(),
            },
            SyncRequestData::Write(_) => RequestKind::Write {
                data_dma,
                data_len: buf_len,
            },
        };

        // R39-1 FIX: Store request metadata BEFORE pushing to available ring.
        // R94-13: DmaBuffers are moved into RequestMeta, ownership transferred.
        {
            let mut buffers = self.req_buffers.lock();
            buffers[buf_idx].pending = Some(RequestMeta {
                head: desc0,
                desc_chain: [desc0, desc1, desc2],
                desc_count: 3,
                header_status_dma,
                header_size,
                kind: request_kind,
                abandoned: false,
            });
        }

        unsafe {
            // Push to available ring
            self.queue.push_avail(desc0);
        }

        // Notify device
        mb();
        self.notify();

        // R39-1 FIX: Poll for completion using proper request matching
        let mut timeout = 1_000_000u32;
        let mut completion: Option<Result<usize, BlockError>> = None;

        while timeout > 0 && completion.is_none() {
            // Process all pending completions
            while let Some(used) = self.queue.pop_used() {
                match self.complete_used_entry(used) {
                    Some(RequestCompletion::Io(res)) => {
                        completion = Some(res);
                        break;
                    }
                    Some(RequestCompletion::Flush(_)) => {
                        // Unexpected flush completion during I/O wait
                        kprintln!(
                            "[virtio-blk] unexpected flush completion while waiting for I/O head={}",
                            desc0
                        );
                    }
                    None => {
                        // Stale completion handled, continue polling
                    }
                }
            }

            if completion.is_some() {
                break;
            }

            if !self.queue.has_used() {
                core::hint::spin_loop();
                timeout -= 1;
            }
        }

        // R39-1 FIX: Handle timeout by marking request as abandoned
        let result = match completion {
            Some(res) => res,
            None => {
                // Timeout - mark request as abandoned (resources freed on late completion)
                let leaked = TIMEOUT_LEAKED_REQUESTS.fetch_add(1, Ordering::Relaxed) + 1;
                {
                    let mut buffers = self.req_buffers.lock();
                    if let Some(meta) = buffers[buf_idx].pending.as_mut() {
                        meta.abandoned = true;
                    }
                }
                kprintln!(
                    "[virtio-blk] timeout waiting for request head={} sector={} bytes={}, \
                     buffers pinned (reset required, total leaked={})",
                    desc0,
                    sector,
                    buf_len,
                    leaked
                );
                // Leave req_buffers[buf_idx].in_use = true to prevent reuse until device completes
                // R106-3: Attempt device reset to recover resources.
                let _ = self.reset_device(&_lock);
                return Err(BlockError::Io);
            }
        };

        // R39-1 FIX: Resources are now freed by complete_used_entry()
        // No need to free DMA buffers or release buffer slot here

        result
    }
}

impl BlockDevice for VirtioBlkDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn max_sectors_per_bio(&self) -> u32 {
        // Conservative limit for now
        128
    }

    fn capacity_sectors(&self) -> u64 {
        self.capacity
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn submit_bio(&self, mut bio: Bio) -> Result<(), BlockError> {
        // U41-1: a BIO security tag is part of the device boundary, not
        // advisory metadata.  Enforce the same file-permission hook used by
        // VFS before touching DMA buffers or issuing a device request.  A
        // missing tag is treated as an internal/kernel-originated BIO and is
        // left to the caller's higher-level authorization contract; a present
        // tag must never be silently ignored.
        if let Some(tag) = bio.sec_tag {
            let task = lsm::ProcessCtx::new(
                tag.pid as usize,
                tag.pid as usize,
                tag.uid,
                tag.uid,
                tag.uid,
                tag.uid,
            );
            let access_mask = match bio.op {
                BioOp::Read => 0x04,                                  // MAY_READ
                BioOp::Write | BioOp::Discard | BioOp::Flush => 0x02, // MAY_WRITE
            };
            let file_ctx = lsm::FileCtx::new(tag.ino, tag.mode, tag.path_hash);
            if lsm::hook_file_permission(&task, file_ctx.inode, access_mask).is_err() {
                bio.complete(Err(BlockError::PermissionDenied));
                return Err(BlockError::PermissionDenied);
            }
        }

        // Synchronous fallback: process the BIO immediately using do_request/flush.
        // A proper async implementation would queue the BIO and use interrupt-driven
        // completion. This fallback enables page cache writeback and basic BIO users.
        let result: BioResult = match bio.op {
            BioOp::Read => {
                if bio.vecs.is_empty() {
                    Err(BlockError::Invalid)
                } else if bio.vecs.len() == 1 {
                    // Single vector - use directly
                    // SAFETY: Caller ensures the buffer is valid and writable for read data
                    let buf = unsafe { bio.vecs[0].as_mut_slice() };
                    self.do_request(bio.sector, SyncRequestData::Read(buf))
                } else {
                    // Multi-vector scatter-gather: process sequentially
                    let mut current_sector = bio.sector;
                    let sector_size = self.sector_size as u64;
                    let mut total_bytes = 0usize;
                    let mut err: Option<BlockError> = None;

                    for bv in bio.vecs.iter_mut() {
                        // Read len before mutable borrow
                        let bv_len = bv.len as u64;
                        let sectors = match bv_len.checked_div(sector_size) {
                            Some(s) if s > 0 => s,
                            _ => {
                                err = Some(BlockError::Invalid);
                                break;
                            }
                        };

                        // SAFETY: Caller ensures each buffer is valid
                        let buf = unsafe { bv.as_mut_slice() };
                        match self.do_request(current_sector, SyncRequestData::Read(buf)) {
                            Ok(n) => {
                                total_bytes += n;
                                match current_sector.checked_add(sectors) {
                                    Some(next) => current_sector = next,
                                    None => {
                                        err = Some(BlockError::Invalid);
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                err = Some(e);
                                break;
                            }
                        }
                    }

                    err.map_or(Ok(total_bytes), Err)
                }
            }
            BioOp::Write => {
                if bio.vecs.is_empty() {
                    Err(BlockError::Invalid)
                } else if bio.vecs.len() == 1 {
                    // SAFETY: Caller ensures the buffer is valid and contains write data.
                    let buf = unsafe { bio.vecs[0].as_slice() };
                    self.do_request(bio.sector, SyncRequestData::Write(buf))
                } else {
                    // Multi-vector scatter-gather: process sequentially
                    let mut current_sector = bio.sector;
                    let sector_size = self.sector_size as u64;
                    let mut total_bytes = 0usize;
                    let mut err: Option<BlockError> = None;

                    for bv in bio.vecs.iter_mut() {
                        // Read len before mutable borrow
                        let bv_len = bv.len as u64;
                        let sectors = match bv_len.checked_div(sector_size) {
                            Some(s) if s > 0 => s,
                            _ => {
                                err = Some(BlockError::Invalid);
                                break;
                            }
                        };

                        // SAFETY: Caller ensures each buffer is valid and readable.
                        let buf = unsafe { bv.as_slice() };
                        match self.do_request(current_sector, SyncRequestData::Write(buf)) {
                            Ok(n) => {
                                total_bytes += n;
                                match current_sector.checked_add(sectors) {
                                    Some(next) => current_sector = next,
                                    None => {
                                        err = Some(BlockError::Invalid);
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                err = Some(e);
                                break;
                            }
                        }
                    }

                    err.map_or(Ok(total_bytes), Err)
                }
            }
            BioOp::Flush => self.flush().map(|_| 0),
            BioOp::Discard => {
                // TRIM/Discard not supported by this driver
                Err(BlockError::NotSupported)
            }
        };

        // Complete the BIO (calls completion callback if set)
        bio.complete(result);

        // Convert BioResult to submit_bio result
        result.map(|_| ())
    }

    fn read_sync(&self, sector: u64, buf: &mut [u8]) -> Result<usize, BlockError> {
        self.do_request(sector, SyncRequestData::Read(buf))
    }

    fn write_sync(&self, sector: u64, buf: &[u8]) -> Result<usize, BlockError> {
        self.do_request(sector, SyncRequestData::Write(buf))
    }

    fn flush(&self) -> Result<(), BlockError> {
        // R106-3: Reject I/O immediately if device is failed/resetting.
        if self.device_failed.load(Ordering::Acquire) {
            return Err(BlockError::Offline);
        }

        if self.features & blk_features::VIRTIO_BLK_F_FLUSH == 0 {
            return Ok(()); // No flush support, assume write-through
        }

        let _lock = self.lock.lock();
        if self.device_failed.load(Ordering::Acquire) {
            return Err(BlockError::Offline);
        }

        // Acquire a request buffer slot
        let buf_idx = {
            let mut buffers = self.req_buffers.lock();
            let idx = buffers.iter().position(|b| !b.in_use);
            match idx {
                Some(i) => {
                    buffers[i].in_use = true;
                    buffers[i].header.req_type = blk_types::VIRTIO_BLK_T_FLUSH;
                    buffers[i].header.reserved = 0;
                    buffers[i].header.sector = 0; // Sector is ignored for flush
                    buffers[i].status = 0xFF;
                    i
                }
                None => return Err(BlockError::Busy),
            }
        };

        // DMA buffer for header + status with on-demand IOMMU mapping (R94-13)
        let header_size = core::mem::size_of::<VirtioBlkReqHeader>();
        let header_status_dma_size = if header_size + 1 < 32 {
            32
        } else {
            header_size + 1
        };
        let header_status_dma = match alloc_dma_buffer(header_status_dma_size) {
            Ok(buf) => buf,
            Err(_) => {
                self.req_buffers.lock()[buf_idx].in_use = false;
                return Err(BlockError::NoMem);
            }
        };

        // Write header and initialize status byte
        unsafe {
            let header = {
                let buffers = self.req_buffers.lock();
                buffers[buf_idx].header
            };
            core::ptr::write(
                header_status_dma.virt_ptr() as *mut VirtioBlkReqHeader,
                header,
            );
            core::ptr::write(header_status_dma.virt_ptr().add(header_size), 0xFFu8);
        }
        let header_phys = header_status_dma.phys();
        let status_phys = header_status_dma.phys() + header_size as u64;

        // Allocate descriptors (header + status, no data buffer for flush)
        let desc0 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => {
                // DmaBuffer is dropped automatically here
                self.req_buffers.lock()[buf_idx].in_use = false;
                return Err(BlockError::Busy);
            }
        };
        let desc1 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => {
                self.queue.free_desc(desc0);
                // DmaBuffer is dropped automatically here
                self.req_buffers.lock()[buf_idx].in_use = false;
                return Err(BlockError::Busy);
            }
        };

        unsafe {
            // Descriptor 0: Header (device reads)
            let d0 = self.queue.desc(desc0);
            d0.addr = header_phys;
            d0.len = core::mem::size_of::<VirtioBlkReqHeader>() as u32;
            d0.flags = VRING_DESC_F_NEXT;
            d0.next = desc1;

            // Descriptor 1: Status (device writes)
            let d1 = self.queue.desc(desc1);
            d1.addr = status_phys;
            d1.len = 1;
            d1.flags = VRING_DESC_F_WRITE;
            d1.next = 0;
        }

        // R39-1 FIX: Store request metadata BEFORE pushing to available ring
        // R94-13: DmaBuffer is moved into RequestMeta, ownership transferred
        {
            let mut buffers = self.req_buffers.lock();
            buffers[buf_idx].pending = Some(RequestMeta {
                head: desc0,
                desc_chain: [desc0, desc1, 0], // Only 2 descriptors for flush
                desc_count: 2,
                header_status_dma,
                header_size,
                kind: RequestKind::Flush,
                abandoned: false,
            });
        }

        unsafe {
            // Push to available ring
            self.queue.push_avail(desc0);
        }

        // Notify device
        mb();
        self.notify();

        // R39-1 FIX: Poll for completion using proper request matching
        let mut timeout = 1_000_000u32;
        let mut completion: Option<Result<(), BlockError>> = None;

        while timeout > 0 && completion.is_none() {
            // Process all pending completions
            while let Some(used) = self.queue.pop_used() {
                match self.complete_used_entry(used) {
                    Some(RequestCompletion::Flush(res)) => {
                        completion = Some(res);
                        break;
                    }
                    Some(RequestCompletion::Io(_)) => {
                        // Unexpected I/O completion during flush wait
                        kprintln!(
                            "[virtio-blk] unexpected I/O completion while waiting for flush head={}",
                            desc0
                        );
                    }
                    None => {
                        // Stale completion handled, continue polling
                    }
                }
            }

            if completion.is_some() {
                break;
            }

            if !self.queue.has_used() {
                core::hint::spin_loop();
                timeout -= 1;
            }
        }

        // R39-1 FIX: Handle timeout by marking request as abandoned
        let result = match completion {
            Some(res) => res,
            None => {
                // Timeout - mark request as abandoned (resources freed on late completion)
                let leaked = TIMEOUT_LEAKED_REQUESTS.fetch_add(1, Ordering::Relaxed) + 1;
                {
                    let mut buffers = self.req_buffers.lock();
                    if let Some(meta) = buffers[buf_idx].pending.as_mut() {
                        meta.abandoned = true;
                    }
                }
                kprintln!(
                    "[virtio-blk] flush timeout head={}, buffers pinned (reset required, total leaked={})",
                    desc0, leaked
                );
                // R106-3: Attempt device reset to recover resources.
                let _ = self.reset_device(&_lock);
                return Err(BlockError::Io);
            }
        };

        // R39-1 FIX: Resources are now freed by complete_used_entry()
        // No need to free DMA buffers or release buffer slot here

        result
    }

    fn rollback_unpublished(&self) -> Result<(), BlockError> {
        // R180-27 FIX: a probe result is not a completed kernel publication.
        // If block-registry or devfs admission fails after DRIVER_OK, serialize
        // against I/O, make failure sticky, and prove DMA quiescence before the
        // RAII probe guard releases queue/IOMMU ownership.
        let _lock = self.lock.lock();
        self.device_failed.store(true, Ordering::Release);

        const PUBLICATION_RESET_ACK_SPINS: u32 = 1_000_000;
        let reset_acked = unsafe {
            self.transport
                .reset_and_await_ack(PUBLICATION_RESET_ACK_SPINS)
        };
        mb();
        if reset_acked {
            return Ok(());
        }

        // RF180-22 FIX: BME clear stops new transactions but cannot prove that
        // posted DMA writes have drained. Reset acknowledgement is the only
        // ownership-release proof, so every unacknowledged reset returns an
        // error and makes the probe guard quarantine the final Arc. We still
        // disable BME as defense in depth to stop further bus-master traffic.
        if let Some(pci_id) = self.pci_id {
            let _ = crate::pci::disable_bus_master(pci_id);
        }

        Err(BlockError::Offline)
    }
}
