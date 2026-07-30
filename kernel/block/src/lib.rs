//! Block Layer for Zero-OS
//!
//! This module provides the core abstractions for block device I/O operations.
//! It follows a layered design similar to Linux's block layer:
//!
//! ```text
//! +----------------+     +----------------+
//! | File System    |     | Page Cache     |
//! +--------+-------+     +-------+--------+
//!          |                     |
//!          v                     v
//!      +---+---------------------+---+
//!      |       Block Layer           |
//!      | (Bio, RequestQueue, etc.)   |
//!      +-------------+---------------+
//!                    |
//!          +---------+---------+
//!          |                   |
//!          v                   v
//!    +-----------+       +-----------+
//!    | virtio-blk|       | AHCI      |
//!    +-----------+       +-----------+
//! ```
//!
//! # Key Components
//!
//! - [`BlockDevice`]: Trait for block device drivers
//! - [`Bio`]: Block I/O request structure
//! - [`BioVec`]: Scatter-gather vector for DMA
//! - [`RequestQueue`]: Per-device request queue with FIFO scheduling
//! - [`BlockDeviceRegistry`]: Global registry for block devices
//!
//! # Security Integration
//!
//! Each BIO can carry a [`SecurityTag`] containing inode/path information
//! for LSM policy enforcement at the block layer.

#![no_std]
#![allow(unused_variables)]
#![allow(unused_assignments)]
#![allow(dead_code)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::new_without_default)]
#![feature(allocator_api)]

extern crate alloc;

extern crate drivers;
#[macro_use]
extern crate klog;
extern crate mm;

pub mod pci;
pub mod virtio;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, RwLock};

// ============================================================================
// Constants
// ============================================================================

/// Default logical sector size in bytes.
pub const DEFAULT_SECTOR_SIZE: u32 = 512;

/// Maximum sectors per BIO (512 KB with 512-byte sectors).
pub const MAX_BIO_SECTORS: u32 = 1024;

/// Maximum BIO payload size in bytes.
pub const MAX_BIO_BYTES: usize = (MAX_BIO_SECTORS as usize) * (DEFAULT_SECTOR_SIZE as usize);

/// Maximum number of scatter-gather vectors per BIO.
pub const MAX_BIO_VECS: usize = 256;

/// Maximum number of registered block devices.
pub const MAX_BLOCK_DEVICES: usize = 64;

// ============================================================================
// Error Types
// ============================================================================

/// Block layer error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    /// Generic I/O failure.
    Io,
    /// Invalid arguments (alignment, overflow, etc.).
    Invalid,
    /// Request size exceeds device or global limits.
    TooLarge,
    /// Device is busy or queue is full.
    Busy,
    /// Memory allocation failed.
    NoMem,
    /// Operation not supported by device.
    NotSupported,
    /// Device not found.
    NotFound,
    /// Device offline or removed.
    Offline,
    /// Read-only device.
    ReadOnly,
    /// Media error (bad sector, etc.).
    MediaError,
    /// Permission denied (LSM policy).
    PermissionDenied,
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockError::Io => write!(f, "I/O error"),
            BlockError::Invalid => write!(f, "invalid argument"),
            BlockError::TooLarge => write!(f, "request too large"),
            BlockError::Busy => write!(f, "device busy"),
            BlockError::NoMem => write!(f, "out of memory"),
            BlockError::NotSupported => write!(f, "operation not supported"),
            BlockError::NotFound => write!(f, "device not found"),
            BlockError::Offline => write!(f, "device offline"),
            BlockError::ReadOnly => write!(f, "read-only device"),
            BlockError::MediaError => write!(f, "media error"),
            BlockError::PermissionDenied => write!(f, "permission denied"),
        }
    }
}

// ============================================================================
// BIO Types
// ============================================================================

/// Block I/O operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioOp {
    /// Read data from device.
    Read,
    /// Write data to device.
    Write,
    /// Flush device write cache.
    Flush,
    /// Discard (TRIM) sectors.
    Discard,
}

impl fmt::Display for BioOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BioOp::Read => write!(f, "READ"),
            BioOp::Write => write!(f, "WRITE"),
            BioOp::Flush => write!(f, "FLUSH"),
            BioOp::Discard => write!(f, "DISCARD"),
        }
    }
}

/// Scatter-gather vector for BIO data transfer.
///
/// Each vector points to a contiguous memory region. For DMA-capable
/// devices, the physical address should also be provided.
///
/// # Safety Invariants
///
/// A `BioVec` is valid only if ALL of the following hold:
/// - `ptr` is non-null and points to a valid, allocated memory region of at least `len` bytes
/// - `ptr` is properly aligned for `u8` access (trivially true, but stricter alignment may be required by device)
/// - The memory region `[ptr, ptr + len)` does not wrap around the address space
/// - The referenced memory remains valid for the lifetime of the `BioVec` and any slices derived from it
/// - For read operations: the memory is readable
/// - For write operations: the memory is writable
/// - For DMA operations: the memory is not concurrently accessed by CPU during device transfer
/// - If `phys` is `Some`, it must be the correct physical address mapping for `ptr`
///
/// **Aliasing hazard:** Creating a mutable slice via `as_mut_slice()` while a DMA device
/// concurrently accesses the same buffer is undefined behavior. Callers must ensure:
/// - Device transfer is complete before CPU accesses the buffer, OR
/// - Appropriate memory barriers/cache invalidation are used
#[derive(Clone, Copy)]
pub struct BioVec {
    /// Virtual address of the buffer.
    pub ptr: *mut u8,
    /// Length in bytes (must be sector-aligned for most operations).
    pub len: usize,
    /// Physical address for DMA (None if not applicable).
    pub phys: Option<u64>,
}

// SAFETY: BioVec contains raw pointers but is only used within the kernel
// where we control memory safety.
unsafe impl Send for BioVec {}
unsafe impl Sync for BioVec {}

impl BioVec {
    /// Create a new BioVec with virtual address only.
    ///
    /// # Safety
    ///
    /// Caller must ensure:
    /// - `ptr` is non-null and points to a valid, allocated memory region of at least `len` bytes
    /// - The memory region remains valid for the lifetime of the `BioVec` and any derived slices
    /// - `ptr + len` does not overflow the address space
    /// - The memory is readable/writable as required by subsequent operations
    /// - For DMA operations: no concurrent CPU access during device transfer
    pub const unsafe fn new(ptr: *mut u8, len: usize) -> Self {
        Self {
            ptr,
            len,
            phys: None,
        }
    }

    /// Create a new BioVec with both virtual and physical addresses.
    ///
    /// # Safety
    ///
    /// Caller must ensure all invariants from [`BioVec::new`], plus:
    /// - `phys` is the correct physical address mapping for `ptr`
    /// - The physical mapping remains stable for the lifetime of the `BioVec`
    pub const unsafe fn with_phys(ptr: *mut u8, len: usize, phys: u64) -> Self {
        Self {
            ptr,
            len,
            phys: Some(phys),
        }
    }

    /// Create a BioVec from a byte slice (safe constructor).
    ///
    /// This is the preferred constructor when the buffer is already a valid slice.
    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            ptr: slice.as_ptr() as *mut u8,
            len: slice.len(),
            phys: None,
        }
    }

    /// Create a BioVec from a mutable byte slice (safe constructor).
    ///
    /// This is the preferred constructor when the buffer is already a valid mutable slice.
    pub fn from_mut_slice(slice: &mut [u8]) -> Self {
        Self {
            ptr: slice.as_mut_ptr(),
            len: slice.len(),
            phys: None,
        }
    }

    /// Check if the buffer is aligned to the given sector size.
    #[inline]
    pub fn is_aligned(&self, sector_size: u32) -> bool {
        let sz = sector_size as usize;
        (self.len % sz == 0) && ((self.ptr as usize) % sz == 0)
    }

    /// Get the buffer as a byte slice (for read operations).
    ///
    /// # Safety
    ///
    /// Caller must ensure ALL of the following hold:
    /// - The `BioVec` was constructed with valid pointer and length (see type-level invariants)
    /// - The referenced memory region is currently valid and readable
    /// - The memory will remain valid for the lifetime `'a` of the returned slice
    /// - The memory is properly initialized (contains valid `u8` values)
    /// - No mutable references to overlapping memory exist during the slice's lifetime
    /// - If used for DMA: device transfer has completed and appropriate barriers/invalidation performed
    #[inline]
    pub unsafe fn as_slice(&self) -> &[u8] {
        core::slice::from_raw_parts(self.ptr, self.len)
    }

    /// Get the buffer as a mutable byte slice (for write operations).
    ///
    /// # Safety
    ///
    /// Caller must ensure ALL of the following hold:
    /// - The `BioVec` was constructed with valid pointer and length (see type-level invariants)
    /// - The referenced memory region is currently valid and writable
    /// - The memory will remain valid for the lifetime `'a` of the returned slice
    /// - No other references (mutable or immutable) to overlapping memory exist during the slice's lifetime
    /// - For DMA write (device → memory): CPU must not access the buffer until transfer completes
    /// - For DMA read (memory → device): the slice content must be initialized before device access
    #[inline]
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        core::slice::from_raw_parts_mut(self.ptr, self.len)
    }
}

impl fmt::Debug for BioVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BioVec")
            .field("ptr", &format_args!("{:p}", self.ptr))
            .field("len", &self.len)
            .field("phys", &self.phys)
            .finish()
    }
}

/// Security context tag for LSM integration.
///
/// This tag carries file/inode context through the block layer,
/// allowing LSM policies to be enforced at the device level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecurityTag {
    /// Inode number (0 if not applicable).
    pub ino: u64,
    /// File mode bits (type + permissions).
    pub mode: u32,
    /// Path hash for policy lookup (FNV-1a hash).
    pub path_hash: u64,
    /// Process ID that initiated the I/O.
    pub pid: u32,
    /// User ID that initiated the I/O.
    pub uid: u32,
}

impl SecurityTag {
    /// Create a new security tag with the given parameters.
    pub const fn new(ino: u64, mode: u32, path_hash: u64, pid: u32, uid: u32) -> Self {
        Self {
            ino,
            mode,
            path_hash,
            pid,
            uid,
        }
    }
}

/// BIO completion result.
pub type BioResult = Result<usize, BlockError>;

/// Asynchronous completion callback for BIO.
pub type BioComplete = Box<dyn FnOnce(BioResult) + Send + 'static>;

/// Block I/O request.
///
/// A Bio represents a single block I/O operation. It contains:
/// - The operation type (read/write/flush/discard)
/// - The starting sector (LBA)
/// - Scatter-gather list of buffers
/// - Optional completion callback for async operations
/// - Optional security tag for LSM integration
pub struct Bio {
    /// Unique BIO ID for tracking.
    pub id: u64,
    /// Operation type.
    pub op: BioOp,
    /// Starting sector (logical block address).
    pub sector: u64,
    /// Number of sectors (used for Discard operations).
    /// For Read/Write, this is derived from vecs.
    pub num_sectors: u64,
    /// Scatter-gather buffer list.
    pub vecs: Vec<BioVec>,
    /// Completion callback (called when I/O finishes).
    pub completion: Option<BioComplete>,
    /// Security context for LSM.
    pub sec_tag: Option<SecurityTag>,
    /// Device-private data (e.g., virtio descriptor index).
    pub private: u64,
    /// Timestamp when BIO was created (for latency tracking).
    pub timestamp: u64,
}

// Global BIO ID counter
static BIO_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

impl Bio {
    /// Create a new BIO for the given operation and starting sector.
    ///
    /// P2-8 FIX: Use fetch_update + checked_add to prevent ID wrapping on u64
    /// overflow, following the R105-5 pattern.
    pub fn new(op: BioOp, sector: u64) -> Result<Self, BlockError> {
        let id = BIO_ID_COUNTER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| BlockError::NoMem)?;

        Ok(Self {
            id,
            op,
            sector,
            num_sectors: 0,
            vecs: Vec::new(),
            completion: None,
            sec_tag: None,
            private: 0,
            timestamp: 0, // Will be set by request queue
        })
    }

    /// Create a new Discard BIO with explicit sector count.
    pub fn new_discard(sector: u64, num_sectors: u64) -> Result<Self, BlockError> {
        let id = BIO_ID_COUNTER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| BlockError::NoMem)?;

        Ok(Self {
            id,
            op: BioOp::Discard,
            sector,
            num_sectors,
            vecs: Vec::new(),
            completion: None,
            sec_tag: None,
            private: 0,
            timestamp: 0,
        })
    }

    /// Set the completion callback.
    pub fn with_completion(mut self, cb: BioComplete) -> Self {
        self.completion = Some(cb);
        self
    }

    /// Set the security tag.
    pub fn with_security_tag(mut self, tag: SecurityTag) -> Self {
        self.sec_tag = Some(tag);
        self
    }

    /// Add a scatter-gather vector to the BIO.
    pub fn push_vec(&mut self, bv: BioVec) -> Result<(), BlockError> {
        if self.vecs.len() >= MAX_BIO_VECS {
            return Err(BlockError::TooLarge);
        }
        self.vecs.push(bv);
        Ok(())
    }

    /// Get the total payload length in bytes.
    #[inline]
    pub fn total_len(&self) -> usize {
        self.vecs.iter().map(|v| v.len).sum()
    }

    /// Get the total number of sectors (rounded up).
    #[inline]
    pub fn total_sectors(&self, sector_size: u32) -> u64 {
        let bytes = self.total_len() as u64;
        if bytes == 0 {
            return 0;
        }
        (bytes + sector_size as u64 - 1) / sector_size as u64
    }

    /// Validate the BIO against device constraints.
    ///
    /// # Arguments
    /// * `sector_size` - Device sector size in bytes
    /// * `max_sectors` - Maximum sectors per BIO
    /// * `device_capacity` - Total device capacity in sectors (for bounds check)
    pub fn validate(
        &self,
        sector_size: u32,
        max_sectors: u32,
        device_capacity: u64,
    ) -> Result<(), BlockError> {
        // Flush operations don't need data buffers or bounds check
        if self.op == BioOp::Flush {
            return Ok(());
        }

        // Discard operations use explicit num_sectors
        if self.op == BioOp::Discard {
            if self.num_sectors == 0 || self.num_sectors > max_sectors as u64 {
                return Err(BlockError::TooLarge);
            }
            // Bounds check: sector + num_sectors must not overflow or exceed capacity
            let end_sector = self
                .sector
                .checked_add(self.num_sectors)
                .ok_or(BlockError::Invalid)?;
            if end_sector > device_capacity {
                return Err(BlockError::Invalid);
            }
            return Ok(());
        }

        // Read/Write operations need at least one buffer
        if self.vecs.is_empty() {
            return Err(BlockError::Invalid);
        }

        // Check alignment for all vectors
        for v in &self.vecs {
            if !v.is_aligned(sector_size) {
                return Err(BlockError::Invalid);
            }
        }

        // Check total size
        let sectors = self.total_sectors(sector_size);
        if sectors == 0 || sectors > max_sectors as u64 {
            return Err(BlockError::TooLarge);
        }

        // Bounds check: sector + total_sectors must not overflow or exceed capacity
        let end_sector = self
            .sector
            .checked_add(sectors)
            .ok_or(BlockError::Invalid)?;
        if end_sector > device_capacity {
            return Err(BlockError::Invalid);
        }

        Ok(())
    }

    /// Complete the BIO with the given result.
    ///
    /// This consumes the BIO and invokes the completion callback if set.
    pub fn complete(self, result: BioResult) {
        if let Some(cb) = self.completion {
            cb(result);
        }
    }

    /// Check if this is a read operation.
    #[inline]
    pub fn is_read(&self) -> bool {
        self.op == BioOp::Read
    }

    /// Check if this is a write operation.
    #[inline]
    pub fn is_write(&self) -> bool {
        self.op == BioOp::Write
    }
}

impl fmt::Debug for Bio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bio")
            .field("id", &self.id)
            .field("op", &self.op)
            .field("sector", &self.sector)
            .field("vecs", &self.vecs.len())
            .field("total_len", &self.total_len())
            .field("has_completion", &self.completion.is_some())
            .field("sec_tag", &self.sec_tag)
            .finish()
    }
}

// ============================================================================
// Block Device Trait
// ============================================================================

/// Block device abstraction trait.
///
/// All block device drivers must implement this trait. It provides the
/// interface for submitting I/O requests and querying device properties.
pub trait BlockDevice: Send + Sync {
    /// Get the device name (e.g., "vda", "sda").
    fn name(&self) -> &str;

    /// Get the logical sector size in bytes.
    fn sector_size(&self) -> u32 {
        DEFAULT_SECTOR_SIZE
    }

    /// Get the maximum sectors per BIO for this device.
    fn max_sectors_per_bio(&self) -> u32 {
        MAX_BIO_SECTORS
    }

    /// Get the total device capacity in sectors.
    fn capacity_sectors(&self) -> u64;

    /// Check if the device is read-only.
    fn is_read_only(&self) -> bool {
        false
    }

    /// Submit a BIO for asynchronous processing.
    ///
    /// The driver should queue the BIO and return immediately.
    /// When the I/O completes, the driver calls `bio.complete(result)`.
    fn submit_bio(&self, bio: Bio) -> Result<(), BlockError>;

    /// Synchronously read sectors from the device.
    ///
    /// This is a convenience method that creates a BIO and waits for completion.
    /// Not all devices support synchronous I/O.
    fn read_sync(&self, sector: u64, buf: &mut [u8]) -> Result<usize, BlockError> {
        let _ = (sector, buf);
        Err(BlockError::NotSupported)
    }

    /// Synchronously write sectors to the device.
    ///
    /// This is a convenience method that creates a BIO and waits for completion.
    /// Not all devices support synchronous I/O.
    fn write_sync(&self, sector: u64, buf: &[u8]) -> Result<usize, BlockError> {
        let _ = (sector, buf);
        Err(BlockError::NotSupported)
    }

    /// Flush the device write cache.
    fn flush(&self) -> Result<(), BlockError> {
        Err(BlockError::NotSupported)
    }

    /// Quiesce a newly probed device whose publication transaction failed.
    ///
    /// The caller must invoke this only before the device becomes reachable by
    /// I/O clients. DMA-capable implementations must prove that the device can
    /// no longer access owned buffers before returning `Ok(())`. Returning an
    /// error requests quarantine: the caller must retain the final `Arc` and
    /// all DMA ownership rather than releasing potentially live memory.
    fn rollback_unpublished(&self) -> Result<(), BlockError> {
        Ok(())
    }
}

// ============================================================================
// Request Queue
// ============================================================================

/// Per-device request queue with FIFO scheduling.
///
/// The request queue provides:
/// - Thread-safe BIO enqueueing
/// - FIFO scheduling (simple but fair)
/// - Optional request merging (future enhancement)
/// - Back-pressure through queue depth limits
///
/// # Completion Semantics
///
/// On enqueue failure, the BIO's completion callback is automatically invoked
/// with the error, ensuring callers never hang waiting for completion.
pub struct RequestQueue {
    /// Queued BIOs waiting for processing (VecDeque for O(1) pop).
    queue: Mutex<VecDeque<Bio>>,
    /// Maximum queue depth.
    max_depth: usize,
    /// Sector size for validation.
    sector_size: u32,
    /// Maximum sectors per BIO.
    max_sectors: u32,
    /// Device capacity in sectors (for bounds checking).
    device_capacity: u64,
    /// Statistics: total BIOs submitted.
    stats_submitted: AtomicU64,
    /// Statistics: total BIOs completed.
    stats_completed: AtomicU64,
    /// Statistics: total bytes transferred.
    stats_bytes: AtomicU64,
    /// Statistics: total BIOs rejected.
    stats_rejected: AtomicU64,
}

impl RequestQueue {
    /// Create a new request queue with the given parameters.
    pub fn new(sector_size: u32, max_sectors: u32, max_depth: usize, device_capacity: u64) -> Self {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(max_depth)),
            max_depth,
            sector_size,
            max_sectors,
            device_capacity,
            stats_submitted: AtomicU64::new(0),
            stats_completed: AtomicU64::new(0),
            stats_bytes: AtomicU64::new(0),
            stats_rejected: AtomicU64::new(0),
        }
    }

    /// Enqueue a BIO for processing.
    ///
    /// On failure, the BIO's completion callback is invoked with the error.
    /// Returns `Err(BlockError::Busy)` if the queue is full.
    pub fn enqueue(&self, bio: Bio) -> Result<(), BlockError> {
        // Validate the BIO first
        if let Err(e) = bio.validate(self.sector_size, self.max_sectors, self.device_capacity) {
            self.stats_rejected.fetch_add(1, Ordering::Relaxed);
            // Invoke completion with error so caller doesn't hang
            bio.complete(Err(e));
            return Err(e);
        }

        let mut q = self.queue.lock();
        if q.len() >= self.max_depth {
            self.stats_rejected.fetch_add(1, Ordering::Relaxed);
            // Invoke completion with error so caller doesn't hang
            bio.complete(Err(BlockError::Busy));
            return Err(BlockError::Busy);
        }

        self.stats_submitted.fetch_add(1, Ordering::Relaxed);
        q.push_back(bio);
        Ok(())
    }

    /// Pop the next BIO from the queue (FIFO order, O(1)).
    pub fn pop(&self) -> Option<Bio> {
        self.queue.lock().pop_front()
    }

    /// Get the current queue depth.
    #[inline]
    pub fn len(&self) -> usize {
        self.queue.lock().len()
    }

    /// Check if the queue is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if the queue is full.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len() >= self.max_depth
    }

    /// Record a completed BIO (for statistics).
    pub fn record_completion(&self, bytes: usize) {
        self.stats_completed.fetch_add(1, Ordering::Relaxed);
        self.stats_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Get queue statistics.
    pub fn stats(&self) -> RequestQueueStats {
        RequestQueueStats {
            submitted: self.stats_submitted.load(Ordering::Relaxed),
            completed: self.stats_completed.load(Ordering::Relaxed),
            rejected: self.stats_rejected.load(Ordering::Relaxed),
            bytes_transferred: self.stats_bytes.load(Ordering::Relaxed),
            current_depth: self.len(),
            max_depth: self.max_depth,
        }
    }
}

/// Request queue statistics.
#[derive(Debug, Clone, Copy)]
pub struct RequestQueueStats {
    /// Total BIOs submitted successfully.
    pub submitted: u64,
    /// Total BIOs completed.
    pub completed: u64,
    /// Total BIOs rejected (validation failed or queue full).
    pub rejected: u64,
    /// Total bytes transferred.
    pub bytes_transferred: u64,
    /// Current queue depth.
    pub current_depth: usize,
    /// Maximum queue depth.
    pub max_depth: usize,
}

// ============================================================================
// Block Device Registry
// ============================================================================

/// Registered block device entry.
struct RegisteredDevice {
    /// Device instance.
    device: Arc<dyn BlockDevice>,
    /// Minor device number.
    minor: u32,
}

/// Global block device registry.
///
/// Provides device registration, lookup by name/minor number,
/// and integration with devfs.
pub struct BlockDeviceRegistry {
    /// Registered devices. Fixed storage makes publication allocation-free;
    /// device names remain owned by the device itself.
    devices: RwLock<[Option<RegisteredDevice>; MAX_BLOCK_DEVICES]>,
    /// Next minor number to assign.
    next_minor: AtomicU64,
}

impl BlockDeviceRegistry {
    /// Create a new registry.
    pub const fn new() -> Self {
        Self {
            devices: RwLock::new([const { None }; MAX_BLOCK_DEVICES]),
            next_minor: AtomicU64::new(0),
        }
    }

    /// Register a new block device.
    ///
    /// Returns the assigned minor number on success.
    pub fn register(&self, device: Arc<dyn BlockDevice>) -> Result<u32, BlockError> {
        // R180-27 FIX: fixed slots and device-owned names make the complete
        // registry mutation allocation-free after DRIVER_OK.
        let mut devices = self.devices.write();

        // Check for duplicate name
        if devices
            .iter()
            .flatten()
            .any(|registered| registered.device.name() == device.name())
        {
            return Err(BlockError::Invalid);
        }

        let slot = devices
            .iter()
            .position(Option::is_none)
            .ok_or(BlockError::NoMem)?;

        // P2-8 FIX: Use fetch_update + checked_add to prevent minor number
        // wrapping on overflow, following the R105-5 pattern.
        let minor = self
            .next_minor
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |id| {
                (id <= u32::MAX as u64).then(|| id + 1)
            })
            .map_err(|_| BlockError::NoMem)?;
        let minor = u32::try_from(minor).map_err(|_| BlockError::NoMem)?;

        devices[slot] = Some(RegisteredDevice { device, minor });

        Ok(minor)
    }

    /// Unregister a block device by name.
    pub fn unregister(&self, name: &str) -> Result<(), BlockError> {
        let mut devices = self.devices.write();
        let pos = devices
            .iter()
            .position(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|registered| registered.device.name() == name)
            })
            .ok_or(BlockError::NotFound)?;
        devices[pos] = None;
        Ok(())
    }

    /// Look up a device by name.
    pub fn get_by_name(&self, name: &str) -> Option<Arc<dyn BlockDevice>> {
        let devices = self.devices.read();
        devices
            .iter()
            .flatten()
            .find(|registered| registered.device.name() == name)
            .map(|registered| Arc::clone(&registered.device))
    }

    /// Look up a device by minor number.
    pub fn get_by_minor(&self, minor: u32) -> Option<Arc<dyn BlockDevice>> {
        let devices = self.devices.read();
        devices
            .iter()
            .flatten()
            .find(|registered| registered.minor == minor)
            .map(|registered| Arc::clone(&registered.device))
    }

    /// Get list of all registered device names.
    pub fn list_devices(&self) -> Result<Vec<String>, BlockError> {
        let devices = self.devices.read();
        let mut names = Vec::new();
        let count = devices.iter().flatten().count();
        names
            .try_reserve_exact(count)
            .map_err(|_| BlockError::NoMem)?;
        for registered in devices.iter().flatten() {
            let source_name = registered.device.name();
            let mut name = String::new();
            name.try_reserve_exact(source_name.len())
                .map_err(|_| BlockError::NoMem)?;
            name.push_str(source_name);
            names.push(name);
        }
        Ok(names)
    }

    /// Get the number of registered devices.
    pub fn count(&self) -> usize {
        self.devices.read().iter().flatten().count()
    }
}

// Global registry instance
lazy_static::lazy_static! {
    /// Global block device registry.
    pub static ref BLOCK_REGISTRY: BlockDeviceRegistry = BlockDeviceRegistry::new();
}

// ============================================================================
// Public API
// ============================================================================

/// Register a block device.
pub fn register_device(device: Arc<dyn BlockDevice>) -> Result<u32, BlockError> {
    let minor = BLOCK_REGISTRY.register(device.clone())?;
    klog!(
        Info,
        "  Block device registered: {} (minor={}, capacity={}MB)",
        device.name(),
        minor,
        device.capacity_sectors() * device.sector_size() as u64 / (1024 * 1024)
    );
    Ok(minor)
}

/// Unregister a block device.
pub fn unregister_device(name: &str) -> Result<(), BlockError> {
    BLOCK_REGISTRY.unregister(name)
}

/// Get a block device by name.
pub fn get_device(name: &str) -> Option<Arc<dyn BlockDevice>> {
    BLOCK_REGISTRY.get_by_name(name)
}

/// Get a block device by minor number.
pub fn get_device_by_minor(minor: u32) -> Option<Arc<dyn BlockDevice>> {
    BLOCK_REGISTRY.get_by_minor(minor)
}

/// List all registered block devices.
pub fn list_devices() -> Result<Vec<String>, BlockError> {
    BLOCK_REGISTRY.list_devices()
}

/// A ready VirtIO block device that has not completed kernel publication.
///
/// Dropping this guard rolls back `DRIVER_OK`. If hardware quiescence cannot be
/// proven, the final Arc is deliberately quarantined so DMA-owned memory is
/// never returned to the allocator. `commit` is the only way to disarm it.
pub struct ProbedBlockDevice {
    pending: Option<(Arc<dyn BlockDevice>, &'static str)>,
    mmio_mapping: Option<BlockPciMmioMapping>,
}

impl ProbedBlockDevice {
    fn new(device: Arc<dyn BlockDevice>, name: &'static str) -> Self {
        Self {
            pending: Some((device, name)),
            mmio_mapping: None,
        }
    }

    fn new_pci(
        device: Arc<dyn BlockDevice>,
        name: &'static str,
        mmio_mapping: BlockPciMmioMapping,
    ) -> Self {
        Self {
            pending: Some((device, name)),
            mmio_mapping: Some(mmio_mapping),
        }
    }

    pub fn name(&self) -> &'static str {
        self.pending
            .as_ref()
            .map(|(_, name)| *name)
            .expect("probed block device already committed")
    }

    pub fn device(&self) -> Arc<dyn BlockDevice> {
        Arc::clone(
            &self
                .pending
                .as_ref()
                .expect("probed block device already committed")
                .0,
        )
    }

    /// Finish publication after every registry has committed successfully.
    pub fn commit(mut self) -> (Arc<dyn BlockDevice>, &'static str) {
        if let Some(mapping) = self.mmio_mapping.take() {
            mapping.commit();
        }
        self.pending
            .take()
            .expect("probed block device committed twice")
    }
}

impl Drop for ProbedBlockDevice {
    fn drop(&mut self) {
        let Some((device, name)) = self.pending.take() else {
            return;
        };

        if let Err(error) = device.rollback_unpublished() {
            #[cfg(not(test))]
            klog_force!(
                "R180-27: /dev/{} publication rollback could not prove DMA quiescence: {:?}; quarantining device ownership",
                name,
                error
            );
            #[cfg(test)]
            let _ = (name, error);
            core::mem::forget(device);
            if let Some(mapping) = self.mmio_mapping.take() {
                // Quarantine the VA reservation/mapping with the device whose
                // quiescence could not be proven. Reusing it would let a later
                // device inherit an alias still associated with failed hardware.
                mapping.quarantine();
            }
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the block layer subsystem.
pub fn init() {
    klog_always!("  Block layer initialized");
    klog_always!("    Max BIO size: {} KB", MAX_BIO_BYTES / 1024);
    klog_always!("    Default sector size: {} bytes", DEFAULT_SECTOR_SIZE);
}

// ============================================================================
// High Address MMIO Mapping
// ============================================================================

/// Base virtual address for mapping MMIO regions above 4GB.
/// This is in the kernel's higher-half address space, separate from the kernel image.
const HIGH_MMIO_VIRT_BASE: u64 = 0xffff_ffff_4000_0000;

/// Maximum size of the high MMIO virtual address region (256 MB).
const HIGH_MMIO_VIRT_SIZE: u64 = 256 * 1024 * 1024;

/// Serialized VA allocator. Its guard remains held until the probed block
/// device either commits publication or rolls back, making the bump rewindable.
static HIGH_MMIO_OFFSET: Mutex<u64> = Mutex::new(0);

#[derive(Clone, Copy, Debug, Default)]
struct BlockMmioWindow {
    phys: u64,
    len: usize,
}

struct BlockPciMmioMapping {
    allocator: Option<spin::MutexGuard<'static, u64>>,
    reservation_start: u64,
    phys_anchor: u64,
    virt_anchor: u64,
    windows: [BlockMmioWindow; 4],
    window_count: usize,
    virt_offset: u64,
    committed: bool,
}

impl BlockPciMmioMapping {
    fn commit(mut self) {
        self.committed = true;
        drop(self.allocator.take());
    }

    /// Preserve the VA reservation and live mappings for hardware whose DMA
    /// quiescence is ambiguous, but release the allocator serialization guard.
    /// Forgetting `self` would also forget that guard and permanently deadlock
    /// every later block-device probe.
    fn quarantine(mut self) {
        self.committed = true;
        drop(self.allocator.take());
    }
}

impl Drop for BlockPciMmioMapping {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut frame_allocator = mm::FrameAllocator::new();
        for window in self.windows[..self.window_count].iter().rev() {
            let virt = self
                .virt_anchor
                .checked_add(window.phys - self.phys_anchor)
                .expect("validated virtio-blk MMIO reservation overflowed");
            unsafe {
                mm::unmap_mmio(
                    x86_64::VirtAddr::new(virt),
                    window.len,
                    &mut frame_allocator,
                )
                .unwrap_or_else(|_| panic!("RF186-4: virtio-blk MMIO rollback failed"));
            }
        }
        if let Some(offset) = self.allocator.as_mut() {
            **offset = self.reservation_start;
        }
    }
}

fn block_mmio_windows(
    addrs: &virtio::VirtioPciAddrs,
) -> Result<([BlockMmioWindow; 4], usize), BlockError> {
    let declared = [addrs.common_cfg, addrs.notify, addrs.isr, addrs.device_cfg];
    let mut pages = [BlockMmioWindow::default(); 4];
    let mut count = 0usize;
    for authority in declared {
        if !authority.is_present() {
            continue;
        }
        let (page_start, page_len) = authority.page_cover().ok_or(BlockError::Invalid)?;
        mm::checked_physical_range(page_start, page_len).ok_or(BlockError::Invalid)?;
        let page_len = usize::try_from(page_len)
            .ok()
            .filter(|value| *value != 0)
            .ok_or(BlockError::Invalid)?;
        pages[count] = BlockMmioWindow {
            phys: page_start,
            len: page_len,
        };
        count += 1;
    }
    if count == 0 {
        return Err(BlockError::Invalid);
    }
    for left in 0..count {
        for right in (left + 1)..count {
            if pages[right].phys < pages[left].phys {
                pages.swap(left, right);
            }
        }
    }
    let mut merged = [BlockMmioWindow::default(); 4];
    let mut merged_count = 0usize;
    for window in pages[..count].iter().copied() {
        if merged_count != 0 {
            let previous = &mut merged[merged_count - 1];
            let previous_end = previous
                .phys
                .checked_add(previous.len as u64)
                .ok_or(BlockError::Invalid)?;
            if window.phys <= previous_end {
                let window_end = window
                    .phys
                    .checked_add(window.len as u64)
                    .ok_or(BlockError::Invalid)?;
                previous.len = usize::try_from(previous_end.max(window_end) - previous.phys)
                    .map_err(|_| BlockError::Invalid)?;
                continue;
            }
        }
        merged[merged_count] = window;
        merged_count += 1;
    }
    Ok((merged, merged_count))
}

/// Map only validated capability pages while reserving a uniform virtual span.
/// Physical holes between windows remain unmapped, and Drop unwinds both page
/// tables and the serialized VA reservation until publication commits.
unsafe fn map_block_pci_mmio(
    addrs: &virtio::VirtioPciAddrs,
) -> Result<BlockPciMmioMapping, BlockError> {
    let (windows, window_count) = block_mmio_windows(addrs)?;
    let phys_anchor = windows[0].phys;
    let last = windows[window_count - 1];
    let span_end = last
        .phys
        .checked_add(last.len as u64)
        .ok_or(BlockError::Invalid)?;
    let span = span_end
        .checked_sub(phys_anchor)
        .ok_or(BlockError::Invalid)?;
    let allocator = HIGH_MMIO_OFFSET.lock();
    let reservation_start = *allocator;
    let reservation_end = reservation_start
        .checked_add(span)
        .filter(|end| *end <= HIGH_MMIO_VIRT_SIZE)
        .ok_or(BlockError::NoMem)?;
    let virt_anchor = HIGH_MMIO_VIRT_BASE
        .checked_add(reservation_start)
        .ok_or(BlockError::NoMem)?;
    HIGH_MMIO_VIRT_BASE
        .checked_add(reservation_end)
        .ok_or(BlockError::NoMem)?;
    let virt_offset = virt_anchor
        .checked_sub(phys_anchor)
        .ok_or(BlockError::Invalid)?;
    let mut transaction = BlockPciMmioMapping {
        allocator: Some(allocator),
        reservation_start,
        phys_anchor,
        virt_anchor,
        windows,
        window_count: 0,
        virt_offset,
        committed: false,
    };
    let mut frame_allocator = mm::FrameAllocator::new();
    for window in windows[..window_count].iter().copied() {
        let virt = virt_anchor
            .checked_add(window.phys - phys_anchor)
            .ok_or(BlockError::NoMem)?;
        let phys = x86_64::PhysAddr::try_new(window.phys).map_err(|_| BlockError::Invalid)?;
        let last_phys = window
            .phys
            .checked_add(window.len.saturating_sub(1) as u64)
            .ok_or(BlockError::Invalid)?;
        x86_64::PhysAddr::try_new(last_phys).map_err(|_| BlockError::Invalid)?;
        mm::map_mmio(
            x86_64::VirtAddr::new(virt),
            phys,
            window.len,
            &mut frame_allocator,
        )
        .map_err(|_| BlockError::NoMem)?;
        transaction.windows[transaction.window_count] = window;
        transaction.window_count += 1;
    }
    **transaction
        .allocator
        .as_mut()
        .expect("MMIO allocator guard") = reservation_end;
    Ok(transaction)
}

/// Probe for block devices and register them with VFS.
///
/// This function:
/// 1. Tries known virtio-mmio addresses (for embedded/VM configurations)
/// 2. Scans PCI bus 0 for virtio-blk devices (modern transport)
/// 3. Initializes found devices
/// 4. Returns an RAII publication guard for the caller to register atomically
///
/// # Returns
/// A pending device guard if found. Dropping it resets/quarantines the device.
pub fn probe_devices(iommu_required: bool) -> Option<ProbedBlockDevice> {
    // Known virtio-mmio addresses to try (used by some VMs)
    // These use identity mapping (virt == phys for first 4GB)
    const VIRTIO_MMIO_BASES: [u64; 2] = [
        0x10001000, // Common virtio-mmio base
        0x10002000, // Secondary virtio-mmio base
    ];
    let mmio_virt_offset = 0u64; // Identity mapped for low addresses

    // R171-G5-01-C FIX: the virtio-MMIO block transport allocates DMA buffers
    // (probe_mmio) with NO IOMMU attach/isolation path, so in the Secure profile
    // it must be refused (fail closed) — there is no per-device bus-master gate to
    // fall back on for MMIO. Balanced/Performance keep the legacy MMIO probe.
    if iommu_required {
        klog_force!("    ! [SECURE] Refusing virtio-mmio block transport — no IOMMU isolation");
    } else {
        // First, try MMIO transport at known addresses
        for (idx, &base) in VIRTIO_MMIO_BASES.iter().enumerate() {
            let name = match idx {
                0 => "vda",
                1 => "vdb",
                _ => "vdx",
            };
            match unsafe { virtio::VirtioBlkDevice::probe_mmio(base, mmio_virt_offset, name) } {
                Ok(device) => {
                    let capacity = device.capacity_sectors();
                    let sector_size = device.sector_size();
                    let size_mb = (capacity * sector_size as u64) / (1024 * 1024);
                    klog!(
                        Info,
                        "    virtio-blk (mmio) /dev/{}: {} MB ({} sectors x {} bytes)",
                        name,
                        size_mb,
                        capacity,
                        sector_size
                    );
                    return Some(ProbedBlockDevice::new(device, name));
                }
                Err(BlockError::NotFound) => {
                    // No device at this address, continue silently
                }
                Err(e) => {
                    klog!(Warn, "    MMIO virtio-blk at {:#x} failed: {:?}", base, e);
                }
            }
        }
    }

    // Then, try PCI transport (virtio-pci modern)
    if let Some((pci_id, pci_addrs, name)) = pci::probe_virtio_blk(iommu_required) {
        let mapping = match unsafe { map_block_pci_mmio(&pci_addrs) } {
            Ok(mapping) => mapping,
            Err(e) => {
                if !pci::disable_memory_and_bus_master(pci_id) {
                    panic!("RF186-4: cannot fail closed after virtio-blk MMIO mapping failure");
                }
                klog!(
                    Error,
                    "    Failed to map validated virtio-blk MMIO windows: {:?} (MSE/BME disabled)",
                    e
                );
                return None;
            }
        };
        let virt_offset = mapping.virt_offset;

        match unsafe { virtio::VirtioBlkDevice::probe_pci(pci_id, pci_addrs, virt_offset, name) } {
            Ok(device) => {
                let capacity = device.capacity_sectors();
                let sector_size = device.sector_size();
                let size_mb = (capacity * sector_size as u64) / (1024 * 1024);
                klog!(Info,
                    "    virtio-blk (pci) /dev/{} @ {:02x}:{:02x}.{}: {} MB ({} sectors x {} bytes)",
                    name,
                    pci_id.bus,
                    pci_id.device,
                    pci_id.function,
                    size_mb,
                    capacity,
                    sector_size
                );
                return Some(ProbedBlockDevice::new_pci(device, name, mapping));
            }
            Err(e) => {
                if !pci::disable_memory_and_bus_master(pci_id) {
                    panic!("RF186-4: cannot fail closed after virtio-blk probe failure");
                }
                klog!(Warn,
                    "    Failed to probe virtio-blk /dev/{} @ {:02x}:{:02x}.{} (pci caps @ {:#x}): {:?} (bus master disabled)",
                    name,
                    pci_id.bus,
                    pci_id.device,
                    pci_id.function,
                    pci_addrs.common_cfg.phys(),
                    e
                );
            }
        }
    } else {
        klog_always!("    No virtio-blk devices found on PCI buses");
    }

    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    #[test]
    fn block_mmio_preflight_rejects_page_above_architectural_width() {
        let above_width = 1u64 << 52;
        let window = virtio::VirtioPciBarWindow::try_new(
            above_width,
            0x1000,
            0,
            8,
            virtio::VirtioPciWindowAccess::Device,
        )
        .expect("synthetic window is internally BAR-contained");
        let addrs = virtio::VirtioPciAddrs {
            device_cfg: window,
            ..virtio::VirtioPciAddrs::default()
        };
        assert!(matches!(
            block_mmio_windows(&addrs),
            Err(BlockError::Invalid)
        ));
    }

    /// Host stack alignment is otherwise ABI-dependent. The second 512-byte
    /// half is always sector-aligned and never 1024-byte aligned, which makes
    /// the BIO alignment assertions deterministic.
    #[repr(align(1024))]
    struct AlignedDmaBuf([u8; 1024]);

    impl AlignedDmaBuf {
        fn sector_ptr(&self) -> *mut u8 {
            // SAFETY: the backing is 1024 bytes and the 512-byte offset remains
            // within the allocation for every 512-byte test vector below.
            unsafe { self.0.as_ptr().add(512) as *mut u8 }
        }
    }

    struct RollbackTestDevice {
        rollbacks: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        fail_rollback: bool,
    }

    impl Drop for RollbackTestDevice {
        fn drop(&mut self) {
            self.drops.fetch_add(1, AtomicOrdering::SeqCst);
        }
    }

    impl BlockDevice for RollbackTestDevice {
        fn name(&self) -> &str {
            "rollback-test"
        }

        fn capacity_sectors(&self) -> u64 {
            1
        }

        fn submit_bio(&self, _bio: Bio) -> Result<(), BlockError> {
            Err(BlockError::NotSupported)
        }

        fn rollback_unpublished(&self) -> Result<(), BlockError> {
            self.rollbacks.fetch_add(1, AtomicOrdering::SeqCst);
            if self.fail_rollback {
                Err(BlockError::Offline)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn probed_device_rolls_back_uncommitted_publication() {
        let rollbacks = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let device: Arc<dyn BlockDevice> = Arc::new(RollbackTestDevice {
            rollbacks: Arc::clone(&rollbacks),
            drops: Arc::clone(&drops),
            fail_rollback: false,
        });
        drop(ProbedBlockDevice::new(device, "vdt"));
        assert_eq!(rollbacks.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(drops.load(AtomicOrdering::SeqCst), 1);
    }

    #[test]
    fn probed_device_commit_disarms_rollback() {
        let rollbacks = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let device: Arc<dyn BlockDevice> = Arc::new(RollbackTestDevice {
            rollbacks: Arc::clone(&rollbacks),
            drops: Arc::clone(&drops),
            fail_rollback: false,
        });
        let (published, name) = ProbedBlockDevice::new(device, "vdt").commit();
        assert_eq!(name, "vdt");
        drop(published);
        assert_eq!(rollbacks.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(drops.load(AtomicOrdering::SeqCst), 1);
    }

    #[test]
    fn rf180_22_failed_publication_rollback_quarantines_owner() {
        let rollbacks = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let device: Arc<dyn BlockDevice> = Arc::new(RollbackTestDevice {
            rollbacks: Arc::clone(&rollbacks),
            drops: Arc::clone(&drops),
            fail_rollback: true,
        });

        drop(ProbedBlockDevice::new(device, "vdt"));

        assert_eq!(rollbacks.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(
            drops.load(AtomicOrdering::SeqCst),
            0,
            "unproven DMA quiescence must retain the final Arc"
        );
    }

    #[test]
    fn test_bio_vec_alignment() {
        let buf = AlignedDmaBuf([0; 1024]);
        // SAFETY: sector_ptr exposes a valid 512-byte suffix.
        let bv = unsafe { BioVec::new(buf.sector_ptr(), 512) };
        assert!(bv.is_aligned(512));
        assert!(!bv.is_aligned(1024));
    }

    #[test]
    fn test_bio_creation() {
        let bio = Bio::new(BioOp::Read, 0).unwrap();
        assert!(bio.is_read());
        assert!(!bio.is_write());
        assert_eq!(bio.total_len(), 0);
    }

    #[test]
    fn test_bio_validation() {
        let mut bio = Bio::new(BioOp::Read, 0).unwrap();
        let buf = AlignedDmaBuf([0; 1024]);
        // SAFETY: sector_ptr exposes a valid 512-byte suffix.
        bio.push_vec(unsafe { BioVec::new(buf.sector_ptr(), 512) })
            .unwrap();

        // Should pass with matching sector size and sufficient capacity
        assert!(bio.validate(512, 1024, 1000).is_ok());

        // Should fail with larger sector size (not aligned)
        assert!(bio.validate(1024, 1024, 1000).is_err());

        // Should fail if exceeds device capacity
        let mut bio2 = Bio::new(BioOp::Read, 999).unwrap();
        bio2.push_vec(unsafe { BioVec::new(buf.sector_ptr(), 512) })
            .unwrap();
        assert!(bio2.validate(512, 1024, 1000).is_ok()); // sector 999 + 1 = 1000, OK

        let mut bio3 = Bio::new(BioOp::Read, 1000).unwrap();
        bio3.push_vec(unsafe { BioVec::new(buf.sector_ptr(), 512) })
            .unwrap();
        assert!(bio3.validate(512, 1024, 1000).is_err()); // sector 1000 + 1 = 1001, exceeds
    }

    #[test]
    fn test_discard_bio() {
        let bio = Bio::new_discard(0, 100).unwrap();
        assert_eq!(bio.op, BioOp::Discard);
        assert_eq!(bio.num_sectors, 100);

        // Should pass validation
        assert!(bio.validate(512, 1024, 1000).is_ok());

        // Should fail if exceeds capacity
        let bio2 = Bio::new_discard(950, 100).unwrap();
        assert!(bio2.validate(512, 1024, 1000).is_err()); // 950 + 100 = 1050 > 1000
    }

    #[test]
    fn test_request_queue() {
        let queue = RequestQueue::new(512, 1024, 16, 10000);
        assert!(queue.is_empty());

        let mut bio = Bio::new(BioOp::Read, 0).unwrap();
        let buf = AlignedDmaBuf([0; 1024]);
        // SAFETY: sector_ptr exposes a valid 512-byte suffix.
        bio.push_vec(unsafe { BioVec::new(buf.sector_ptr(), 512) })
            .unwrap();

        queue.enqueue(bio).unwrap();
        assert_eq!(queue.len(), 1);

        let popped = queue.pop();
        assert!(popped.is_some());
        assert!(queue.is_empty());
    }
}
