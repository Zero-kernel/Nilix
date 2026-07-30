//! Shared VirtIO support for Zero-OS
//!
//! This crate provides common VirtIO primitives shared across device drivers:
//! - Constants (device IDs, status bits, feature flags)
//! - Ring structures (VringDesc, VringAvail, VringUsed)
//! - MMIO register offsets
//! - Memory barriers
//! - Transport abstraction (MMIO and PCI)
//! - VirtQueue implementation
//!
//! # References
//! - VirtIO Spec 1.2: https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html

#![no_std]

extern crate alloc;

pub mod queue;
pub mod transport;

pub use queue::VirtQueue;
pub use transport::{
    MmioTransport, VirtioPciAddrs, VirtioPciBarWindow, VirtioPciCommonCfg, VirtioPciTransport,
    VirtioPciWindowAccess, VirtioTransport,
};

use core::sync::atomic::{fence, Ordering};

// ============================================================================
// VirtIO Constants
// ============================================================================

/// VirtIO magic value (little-endian "virt").
pub const VIRTIO_MAGIC: u32 = 0x74726976;

/// VirtIO version (legacy = 1, modern = 2).
pub const VIRTIO_VERSION_LEGACY: u32 = 1;
pub const VIRTIO_VERSION_MODERN: u32 = 2;

/// VirtIO device IDs.
pub const VIRTIO_DEVICE_NET: u32 = 1;
pub const VIRTIO_DEVICE_BLK: u32 = 2;
pub const VIRTIO_DEVICE_CONSOLE: u32 = 3;
pub const VIRTIO_DEVICE_RNG: u32 = 4;

/// VirtIO device status bits.
pub const VIRTIO_STATUS_ACKNOWLEDGE: u32 = 1;
pub const VIRTIO_STATUS_DRIVER: u32 = 2;
pub const VIRTIO_STATUS_DRIVER_OK: u32 = 4;
pub const VIRTIO_STATUS_FEATURES_OK: u32 = 8;
pub const VIRTIO_STATUS_DEVICE_NEEDS_RESET: u32 = 64;
pub const VIRTIO_STATUS_FAILED: u32 = 128;

/// VirtIO feature bits.
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
pub const VIRTIO_F_RING_INDIRECT_DESC: u64 = 1 << 28;
pub const VIRTIO_F_RING_EVENT_IDX: u64 = 1 << 29;

/// Descriptor flags.
pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;
pub const VRING_DESC_F_INDIRECT: u16 = 4;

// ============================================================================
// VirtIO Ring Structures
// ============================================================================

/// VirtIO descriptor.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VringDesc {
    /// Physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer.
    pub len: u32,
    /// Descriptor flags.
    pub flags: u16,
    /// Next descriptor index (if VRING_DESC_F_NEXT is set).
    pub next: u16,
}

/// VirtIO available ring.
#[repr(C)]
pub struct VringAvail {
    /// Flags (used for event suppression).
    pub flags: u16,
    /// Next index to write.
    pub idx: u16,
    /// Ring of descriptor indices (variable length).
    pub ring: [u16; 0],
}

/// VirtIO used ring element.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VringUsedElem {
    /// Descriptor chain head.
    pub id: u32,
    /// Total bytes written (for device-writable descriptors).
    pub len: u32,
}

/// VirtIO used ring.
#[repr(C)]
pub struct VringUsed {
    /// Flags.
    pub flags: u16,
    /// Next index to read.
    pub idx: u16,
    /// Ring of used elements (variable length).
    pub ring: [VringUsedElem; 0],
}

// ============================================================================
// MMIO Register Offsets
// ============================================================================

/// VirtIO MMIO register offsets (virtio 1.0+).
pub mod mmio {
    /// Magic value (0x74726976 = "virt").
    pub const MAGIC_VALUE: usize = 0x000;
    /// Version (1 = legacy, 2 = modern).
    pub const VERSION: usize = 0x004;
    /// Device ID.
    pub const DEVICE_ID: usize = 0x008;
    /// Vendor ID.
    pub const VENDOR_ID: usize = 0x00C;
    /// Device features (low 32 bits selected by FeaturesSel).
    pub const DEVICE_FEATURES: usize = 0x010;
    /// Device features selector.
    pub const DEVICE_FEATURES_SEL: usize = 0x014;
    /// Driver features (low 32 bits selected by FeaturesSel).
    pub const DRIVER_FEATURES: usize = 0x020;
    /// Driver features selector.
    pub const DRIVER_FEATURES_SEL: usize = 0x024;
    /// Queue selector.
    pub const QUEUE_SEL: usize = 0x030;
    /// Maximum queue size.
    pub const QUEUE_NUM_MAX: usize = 0x034;
    /// Queue size.
    pub const QUEUE_NUM: usize = 0x038;
    /// Queue ready.
    pub const QUEUE_READY: usize = 0x044;
    /// Queue notify.
    pub const QUEUE_NOTIFY: usize = 0x050;
    /// Interrupt status.
    pub const INTERRUPT_STATUS: usize = 0x060;
    /// Interrupt acknowledge.
    pub const INTERRUPT_ACK: usize = 0x064;
    /// Device status.
    pub const STATUS: usize = 0x070;
    /// Queue descriptor table address (low).
    pub const QUEUE_DESC_LOW: usize = 0x080;
    /// Queue descriptor table address (high).
    pub const QUEUE_DESC_HIGH: usize = 0x084;
    /// Queue available ring address (low).
    pub const QUEUE_AVAIL_LOW: usize = 0x090;
    /// Queue available ring address (high).
    pub const QUEUE_AVAIL_HIGH: usize = 0x094;
    /// Queue used ring address (low).
    pub const QUEUE_USED_LOW: usize = 0x0A0;
    /// Queue used ring address (high).
    pub const QUEUE_USED_HIGH: usize = 0x0A4;
    /// Config space starts here.
    pub const CONFIG: usize = 0x100;
}

// ============================================================================
// Memory Barriers
// ============================================================================

/// Full memory barrier.
#[inline]
pub fn mb() {
    fence(Ordering::SeqCst);
}

/// Write memory barrier.
#[inline]
pub fn wmb() {
    fence(Ordering::Release);
}

/// Read memory barrier.
#[inline]
pub fn rmb() {
    fence(Ordering::Acquire);
}
