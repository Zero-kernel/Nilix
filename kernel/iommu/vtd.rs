//! Intel VT-d (Virtualization Technology for Directed I/O) Driver
//!
//! Implements the Intel VT-d IOMMU hardware interface for DMA remapping.
//! This driver manages VT-d hardware units, their translation structures,
//! and provides DMA isolation for PCI devices.
//!
//! # Hardware Structures
//!
//! VT-d uses a two-level lookup for address translation:
//!
//! 1. **Root Table**: Indexed by PCI bus number (256 entries)
//!    - Points to Context Tables for each bus
//!
//! 2. **Context Table**: Indexed by device/function (256 entries per bus)
//!    - Contains domain ID and pointer to second-level page table
//!
//! 3. **Second-Level Page Table**: 4-level structure like x86_64 page tables
//!    - Translates IOVA to physical address
//!
//! # Registers
//!
//! Key VT-d registers (offsets from DRHD base):
//! - 0x00: Version Register
//! - 0x08: Capability Register
//! - 0x10: Extended Capability Register
//! - 0x18: Global Command Register
//! - 0x1C: Global Status Register
//! - 0x20: Root Table Address Register
//! - 0x24: Context Command Register
//! - 0x28: Fault Status Register
//! - 0x100+: IOTLB Registers
//!
//! # References
//!
//! - Intel VT-d Specification, Chapter 10 (Register Descriptions)
//! - Intel VT-d Specification, Chapter 3 (DMA Remapping)

use alloc::sync::Arc;
use core::mem::size_of;
use core::ptr::{self, read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;
use x86_64::PhysAddr;

use crate::dmar::DrhdEntry;
use crate::domain::{Domain, DomainId, DomainType};
use crate::fault::FaultRecord;
use crate::interrupt::{InterruptRemappingTable, DEFAULT_IR_ENTRIES};
use crate::{IommuError, IommuResult, PciDeviceId};
use mm::{
    arc_charge_bytes, buddy_allocator, phys_to_virt, try_reserve_heap, AdmittedMap, AdmittedVec,
    HeapCharge, HeapClass,
};

// ============================================================================
// Register Offsets
// ============================================================================

/// Version Register (32-bit, RO).
const VTD_REG_VER: usize = 0x00;

/// Capability Register (64-bit, RO).
const VTD_REG_CAP: usize = 0x08;

/// Extended Capability Register (64-bit, RO).
const VTD_REG_ECAP: usize = 0x10;

/// Global Command Register (32-bit, R/W).
const VTD_REG_GCMD: usize = 0x18;

/// Global Status Register (32-bit, RO).
const VTD_REG_GSTS: usize = 0x1C;

/// Root Table Address Register (64-bit, R/W).
const VTD_REG_RTADDR: usize = 0x20;

/// Context Command Register (64-bit, R/W).
const VTD_REG_CCMD: usize = 0x28;

/// Fault Status Register (32-bit, R/W1C).
const VTD_REG_FSTS: usize = 0x34;

/// Fault Event Control Register (32-bit, R/W).
const VTD_REG_FECTL: usize = 0x38;

/// Fault Event Data Register (32-bit, R/W).
const VTD_REG_FEDATA: usize = 0x3C;

/// Fault Event Address Register (32-bit, R/W).
const VTD_REG_FEADDR: usize = 0x40;
/// Invalidation Queue Head/Tail/Address registers.
const VTD_REG_IQH: usize = 0x80;
const VTD_REG_IQT: usize = 0x88;
const VTD_REG_IQA: usize = 0x90;

/// Interrupt Remapping Table Address Register (64-bit, R/W).
const VTD_REG_IRTA: usize = 0xB8;

/// IOTLB Registers offset (varies by capability).
const VTD_REG_IOTLB_BASE: usize = 0x100;

// ============================================================================
// Global Command/Status Bits
// ============================================================================

/// Translation Enable (GCMD.TE).
const GCMD_TE: u32 = 1 << 31;

/// Set Root Table Pointer (GCMD.SRTP).
const GCMD_SRTP: u32 = 1 << 30;

/// Write Buffer Flush (GCMD.WBF).
const GCMD_WBF: u32 = 1 << 27;

/// Queued Invalidation Enable (GCMD.QIE).
const GCMD_QIE: u32 = 1 << 26;

/// Interrupt Remapping Enable (GCMD.IRE).
const GCMD_IRE: u32 = 1 << 25;

/// Translation Enable Status (GSTS.TES).
const GSTS_TES: u32 = 1 << 31;

/// Root Table Pointer Status (GSTS.RTPS).
const GSTS_RTPS: u32 = 1 << 30;

/// Write Buffer Flush Status (GSTS.WBFS).
const GSTS_WBFS: u32 = 1 << 27;

/// Interrupt Remapping Enable Status (GSTS.IRES).
const GSTS_IRES: u32 = 1 << 25;

/// Queued Invalidation Enable Status (GSTS.QIES) — mirror of GCMD.QIE.
const GSTS_QIES: u32 = 1 << 26;

/// R180-18: map persistent GSTS feature status bits back to GCMD enables.
///
/// GCMD is write-only; software must reconstruct the desired command from GSTS
/// before OR-ing new bits, or previously enabled features (IRE) are cleared.
/// One-shot commands such as SRTP and WBF must never be reconstructed from
/// acknowledgement bits and silently resubmitted by a later GCMD update.
#[inline]
fn gsts_to_gcmd(gsts: u32) -> u32 {
    let mut gcmd = 0u32;
    if gsts & GSTS_TES != 0 {
        gcmd |= GCMD_TE;
    }
    if gsts & GSTS_IRES != 0 {
        gcmd |= GCMD_IRE;
    }
    if gsts & GSTS_QIES != 0 {
        gcmd |= GCMD_QIE;
    }
    gcmd
}

/// GCMD bit update performed by [`VtdUnit::write_gcmd_and_wait`].
enum GcmdUpdate {
    Set(u32),
    Clear(u32),
}

/// GSTS acknowledgement expected for a GCMD update.
enum GcmdAck {
    Set(u32),
    Clear(u32),
}

// ============================================================================
// Capability Bits
// ============================================================================

/// Number of domains supported (CAP.ND).
const CAP_ND_MASK: u64 = 0x7;

/// Required Write Buffer Flushing (CAP.RWBF).
const CAP_RWBF: u64 = 1 << 4;

/// Maximum Guest Address Width (CAP.MGAW) - bits 37:32.
const CAP_MGAW_SHIFT: u64 = 16;
const CAP_MGAW_MASK: u64 = 0x3F;

/// Supported Adjusted Guest Address Width (CAP.SAGAW) - bits 12:8.
const CAP_SAGAW_SHIFT: u64 = 8;
const CAP_SAGAW_MASK: u64 = 0x1F;

/// Fault Recording Register offset (CAP.FRO) - bits 23:20, in 16-byte units.
const CAP_FRO_SHIFT: u64 = 24;
const CAP_FRO_MASK: u64 = 0x3FF;

/// Number of Fault Recording Registers (CAP.NFR) - bits 47:40.
const CAP_NFR_SHIFT: u64 = 40;
const CAP_NFR_MASK: u64 = 0xFF;

// ============================================================================
// Extended Capability Bits
// ============================================================================

/// IOTLB Register Offset (ECAP.IRO) - bits 17:8, in 16-byte units.
const ECAP_IRO_SHIFT: u64 = 8;
const ECAP_IRO_MASK: u64 = 0x3FF;

/// Queued Invalidation Support (ECAP.QI).
const ECAP_QI: u64 = 1 << 1;

/// Device-TLB Support (ECAP.DT).
const ECAP_DT: u64 = 1 << 2;

/// Interrupt Remapping Support (ECAP.IR).
const ECAP_IR: u64 = 1 << 3;

/// Pass Through Support (ECAP.PT).
const ECAP_PT: u64 = 1 << 6;

// ============================================================================
// IOTLB Command Bits
// ============================================================================

/// IOTLB Invalidate (IVT).
const IOTLB_IVT: u64 = 1 << 63;

/// IOTLB Invalidation Request Granularity.
const IOTLB_IIRG_GLOBAL: u64 = 1 << 60;
const IOTLB_IIRG_DOMAIN: u64 = 2 << 60;
const IOTLB_IIRG_PAGE: u64 = 3 << 60;

/// Drain Reads (DR).
const IOTLB_DR: u64 = 1 << 49;

/// Drain Writes (DW).
const IOTLB_DW: u64 = 1 << 48;

// ============================================================================
// Context Command Bits
// ============================================================================

/// Context Invalidation Command (ICC).
const CCMD_ICC: u64 = 1 << 63;

/// Context Invalidation Request Granularity.
const CCMD_CIRG_GLOBAL: u64 = 1 << 61;
const CCMD_CIRG_DOMAIN: u64 = 2 << 61;
const CCMD_CIRG_DEVICE: u64 = 3 << 61;

const QI_DESCRIPTOR_BYTES: usize = 16;
const QI_QUEUE_BYTES: usize = 4096;
const QI_QUEUE_ENTRIES: usize = QI_QUEUE_BYTES / QI_DESCRIPTOR_BYTES;
const QI_POINTER_MASK: u64 = (QI_QUEUE_BYTES - QI_DESCRIPTOR_BYTES) as u64;
const FAULT_SOURCE_WORDS: usize = (u16::MAX as usize + 1) / 64;
const FAULT_DETAIL_SLOTS: usize = 32;
pub(crate) const MAX_FAULT_DRAIN_PER_PASS: usize = 1;
const FAULT_SLOT_EMPTY: u32 = 0;
const FAULT_SLOT_WRITING: u32 = 1;
const FAULT_SLOT_READY_BASE: u32 = 2;
/// Architectural IQH/IQT head/tail pointer field (bits 18:4). The queue used
/// here is only 4 KiB, so any decoded offset above `QI_POINTER_MASK` is invalid.
const QI_REGISTER_POINTER_MASK: u64 = 0x7_FFF0;
const QI_COMPLETION_POLL_LIMIT: usize = 1000;
const QI_DESC_IEC_GLOBAL: u64 = 0x4;

fn qi_decode_pointer(register: u64) -> Option<u16> {
    let pointer = register & QI_REGISTER_POINTER_MASK;
    if pointer > QI_POINTER_MASK || pointer as usize % QI_DESCRIPTOR_BYTES != 0 {
        None
    } else {
        Some(pointer as u16)
    }
}

fn qi_descriptor_index(tail: u16) -> Option<usize> {
    let tail = tail as usize;
    if tail >= QI_QUEUE_BYTES || tail % QI_DESCRIPTOR_BYTES != 0 {
        None
    } else {
        Some(tail / QI_DESCRIPTOR_BYTES)
    }
}

fn qi_next_tail(tail: u16) -> Option<u16> {
    qi_descriptor_index(tail)?;
    let next = (tail as usize + QI_DESCRIPTOR_BYTES) % QI_QUEUE_BYTES;
    Some(next as u16)
}

fn qi_poll_head_exact<F>(expected: u16, mut read_head: F) -> bool
where
    F: FnMut() -> u64,
{
    for _ in 0..QI_COMPLETION_POLL_LIMIT {
        match qi_decode_pointer(read_head()) {
            Some(observed) if observed == expected => return true,
            Some(_) => core::hint::spin_loop(),
            None => return false,
        }
    }
    false
}

fn qi_complete_or_poison(poisoned: &AtomicBool, completed: bool) -> IommuResult<()> {
    if completed {
        Ok(())
    } else {
        poisoned.store(true, Ordering::Release);
        Err(IommuError::HardwareInitFailed)
    }
}

// ============================================================================
// Root/Context Table Structures
// ============================================================================

/// Root table entry (128-bit, but only lower 64 bits used).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RootEntry {
    /// Lower 64 bits: present bit + context table pointer.
    lo: u64,
    /// Upper 64 bits: reserved.
    hi: u64,
}

impl RootEntry {
    /// Present bit.
    const PRESENT: u64 = 1 << 0;
    /// Context table address mask (12-bit aligned).
    const CTP_MASK: u64 = !0xFFF;

    /// Create an empty (not present) entry.
    pub const fn empty() -> Self {
        Self { lo: 0, hi: 0 }
    }

    /// Create an entry pointing to a context table.
    pub const fn new(context_table_phys: u64) -> Self {
        Self {
            lo: (context_table_phys & Self::CTP_MASK) | Self::PRESENT,
            hi: 0,
        }
    }

    /// Check if present.
    pub const fn is_present(&self) -> bool {
        self.lo & Self::PRESENT != 0
    }

    /// Get context table physical address.
    pub const fn context_table_addr(&self) -> u64 {
        self.lo & Self::CTP_MASK
    }
}

/// Context table entry (128-bit).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ContextEntry {
    /// Lower 64 bits: present, fault processing, translation type, address width, second-level page table pointer.
    lo: u64,
    /// Upper 64 bits: domain ID, reserved.
    hi: u64,
}

impl ContextEntry {
    /// Present bit.
    const PRESENT: u64 = 1 << 0;
    /// Fault Processing Disable.
    const FPD: u64 = 1 << 1;
    /// Translation Type (bits 3:2).
    const TT_SHIFT: u64 = 2;
    /// Address Width (bits 6:4) - encodes AGAW.
    const AW_SHIFT: u64 = 4;
    /// Second-level page table pointer mask.
    const SLPTPTR_MASK: u64 = !0xFFF;
    /// Domain ID shift in hi.
    const DID_SHIFT: u64 = 8;
    /// Domain ID mask.
    const DID_MASK: u64 = 0xFFFF;

    /// Translation Type: Untranslated requests only.
    const TT_UNTRANSLATED: u64 = 0;
    /// Translation Type: All requests translated.
    const TT_ALL: u64 = 1;
    /// Translation Type: Pass-through.
    const TT_PASSTHROUGH: u64 = 2;

    /// Create an empty (not present) entry.
    pub const fn empty() -> Self {
        Self { lo: 0, hi: 0 }
    }

    /// Create a context entry with second-level translation.
    ///
    /// # Arguments
    ///
    /// * `domain_id` - Domain identifier
    /// * `slpt_phys` - Second-level page table physical address
    /// * `agaw` - Adjusted Guest Address Width (3 = 39-bit, 4 = 48-bit)
    pub fn new_translated(domain_id: DomainId, slpt_phys: u64, agaw: u8) -> Self {
        let aw = match agaw {
            39 => 1, // 3-level page table
            48 => 2, // 4-level page table
            57 => 3, // 5-level page table
            _ => 2,  // Default to 48-bit
        };

        Self {
            lo: Self::PRESENT
                | (Self::TT_ALL << Self::TT_SHIFT)
                | ((aw as u64) << Self::AW_SHIFT)
                | (slpt_phys & Self::SLPTPTR_MASK),
            hi: (domain_id as u64) << Self::DID_SHIFT,
        }
    }

    /// Create a pass-through context entry (identity mapping).
    pub fn new_passthrough(domain_id: DomainId) -> Self {
        Self {
            lo: Self::PRESENT | (Self::TT_PASSTHROUGH << Self::TT_SHIFT),
            hi: (domain_id as u64) << Self::DID_SHIFT,
        }
    }

    /// Check if present.
    pub const fn is_present(&self) -> bool {
        self.lo & Self::PRESENT != 0
    }

    /// Get domain ID.
    pub const fn domain_id(&self) -> DomainId {
        ((self.hi >> Self::DID_SHIFT) & Self::DID_MASK) as DomainId
    }
}

/// Root table (256 entries, 4KB).
#[repr(C, align(4096))]
pub struct RootTable {
    entries: [RootEntry; 256],
}

impl RootTable {
    /// Create a new empty root table.
    pub const fn new() -> Self {
        Self {
            entries: [RootEntry::empty(); 256],
        }
    }
}

/// Context table (256 entries, 4KB).
#[repr(C, align(4096))]
pub struct ContextTable {
    entries: [ContextEntry; 256],
}

impl ContextTable {
    /// Create a new empty context table.
    pub const fn new() -> Self {
        Self {
            entries: [ContextEntry::empty(); 256],
        }
    }
}

// ============================================================================
// Memory Safety Limits
// ============================================================================

/// Maximum physical address reachable via the direct map (1 GB).
/// Frames above this cannot be safely accessed via phys_to_virt.
const MAX_DIRECT_MAP_PHYS: u64 = 1 << 30;

// ============================================================================
// VT-d Error Types
// ============================================================================

/// VT-d specific errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtdError {
    /// Hardware not responding.
    HardwareTimeout,
    /// Unsupported hardware version.
    UnsupportedVersion,
    /// Required capability not present.
    MissingCapability,
    /// Translation enable failed.
    TranslationEnableFailed,
    /// Invalidation failed.
    InvalidationFailed,
    /// Root table allocation failed.
    RootTableAllocFailed,
    /// Context table allocation failed.
    ContextTableAllocFailed,
    /// Hardware initialization failed.
    HardwareInitFailed,
    /// Interrupt remapping table allocation failed.
    InterruptRemapAllocFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextDisposition {
    /// The context may still be present or cached by hardware.
    PresentOrUnknown,
    /// The table entry is absent, but cache retirement was not acknowledged.
    ClearedNeedsFlush,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachmentState {
    Preparing,
    Live,
    DetachingPresent,
    DetachingCleared,
    /// The context-present bit has been cleared as a fault-containment action.
    /// The record and Domain Arc remain durable until an explicit detach proves
    /// cache retirement and removes the quarantine tombstone.
    FaultQuarantined,
    Poisoned(ContextDisposition),
}

struct AttachmentRecord {
    domain_id: DomainId,
    /// Keeps the domain page tables alive until hardware ownership retires.
    /// Recovered firmware/unknown contexts cannot be tied to a registry Arc.
    domain: Option<Arc<Domain>>,
    state: AttachmentState,
}

struct AttachmentRegistry {
    records: AdmittedMap<u16, AttachmentRecord>,
    /// True only while software can prove that every hardware-present context
    /// was published in `records`. Once lost, completeness is never restored by
    /// opportunistically discovering or detaching one context.
    complete: bool,
}

impl AttachmentRegistry {
    const fn new() -> Self {
        Self {
            records: AdmittedMap::new(HeapClass::Device),
            complete: true,
        }
    }

    fn mark_incomplete(&mut self) {
        self.complete = false;
    }
}

struct PendingFaultDetail {
    state: AtomicU32,
    lo: AtomicU64,
    hi: AtomicU64,
}

impl PendingFaultDetail {
    const fn new() -> Self {
        Self {
            state: AtomicU32::new(FAULT_SLOT_EMPTY),
            lo: AtomicU64::new(0),
            hi: AtomicU64::new(0),
        }
    }
}

struct PendingFaultQueue {
    claimed: [AtomicU64; FAULT_SOURCE_WORDS],
    pending: [AtomicU64; FAULT_SOURCE_WORDS],
    details: [PendingFaultDetail; FAULT_DETAIL_SLOTS],
    overflow: AtomicBool,
    work_pending: AtomicBool,
    /// Serializes the hardware-capture producer against process-context
    /// completion. IRQ capture never waits: while drain owns the pipeline the
    /// FRCD F bits remain the durable queue and are retried on the next tick.
    pipeline_claim: AtomicBool,
    recapture_needed: AtomicBool,
    interrupt_masked: AtomicBool,
    cursor: AtomicU32,
}

impl PendingFaultQueue {
    const fn new() -> Self {
        Self {
            claimed: [const { AtomicU64::new(0) }; FAULT_SOURCE_WORDS],
            pending: [const { AtomicU64::new(0) }; FAULT_SOURCE_WORDS],
            details: [const { PendingFaultDetail::new() }; FAULT_DETAIL_SLOTS],
            overflow: AtomicBool::new(false),
            work_pending: AtomicBool::new(false),
            pipeline_claim: AtomicBool::new(false),
            recapture_needed: AtomicBool::new(false),
            interrupt_masked: AtomicBool::new(false),
            cursor: AtomicU32::new(0),
        }
    }

    #[inline]
    fn source_word(source_id: u16) -> (usize, u64) {
        let source = usize::from(source_id);
        (source / 64, 1u64 << (source % 64))
    }

    fn publish(&self, record: FaultRecord, lo: u64, hi: u64) -> bool {
        let (word, bit) = Self::source_word(record.source_id);
        if self.claimed[word].fetch_or(bit, Ordering::AcqRel) & bit != 0 {
            // Capture and drain share `pipeline_claim`, so completion cannot run
            // concurrently. Repeated SIDs within one hardware scan coalesce into
            // the already-owned pending isolation transaction.
            self.pending[word].fetch_or(bit, Ordering::Release);
            self.work_pending.store(true, Ordering::Release);
            return true;
        }

        let ready_state = u32::from(record.source_id) + FAULT_SLOT_READY_BASE;
        let mut detail_published = false;
        for slot in &self.details {
            if slot
                .state
                .compare_exchange(
                    FAULT_SLOT_EMPTY,
                    FAULT_SLOT_WRITING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                slot.lo.store(lo, Ordering::Relaxed);
                slot.hi.store(hi, Ordering::Relaxed);
                slot.state.store(ready_state, Ordering::Release);
                detail_published = true;
                break;
            }
        }
        if !detail_published {
            // SID remains durable in the bitmaps. Process context can still
            // quarantine it, but detail loss escalates the whole unit.
            self.mark_overflow();
        }
        self.pending[word].fetch_or(bit, Ordering::Release);
        self.work_pending.store(true, Ordering::Release);
        detail_published
    }

    fn mark_overflow(&self) {
        self.overflow.store(true, Ordering::Release);
        self.work_pending.store(true, Ordering::Release);
    }

    fn mark_interrupt_masked(&self) {
        self.interrupt_masked.store(true, Ordering::Release);
    }

    fn try_claim_capture(&self) -> bool {
        self.pipeline_claim
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn release_capture(&self) {
        self.pipeline_claim.store(false, Ordering::Release);
    }

    fn begin_capture(&self) {
        // Clear first. Any contender arriving during this scan sets the level
        // back to true, and release_capture never overwrites it.
        self.recapture_needed.store(false, Ordering::Release);
    }

    fn request_recapture(&self) {
        self.recapture_needed.store(true, Ordering::Release);
        self.work_pending.store(true, Ordering::Release);
    }

    fn try_claim_drain(&self) -> bool {
        self.pipeline_claim
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn begin_drain(&self) {
        // Clear first. Any IRQ publication racing after this point sets the bit
        // back to true and therefore cannot have its wakeup overwritten.
        self.work_pending.store(false, Ordering::Release);
    }

    fn release_drain(&self) {
        if self.has_pending_sources()
            || self.overflow.load(Ordering::Acquire)
            || self.recapture_needed.load(Ordering::Acquire)
        {
            self.work_pending.store(true, Ordering::Release);
        }
        self.pipeline_claim.store(false, Ordering::Release);
    }

    fn take_overflow(&self) -> bool {
        self.overflow.swap(false, Ordering::AcqRel)
    }

    fn has_pending_sources(&self) -> bool {
        self.pending
            .iter()
            .any(|word| word.load(Ordering::Acquire) != 0)
    }

    fn has_work(&self) -> bool {
        self.work_pending.load(Ordering::Acquire)
            || self.overflow.load(Ordering::Acquire)
            || self.recapture_needed.load(Ordering::Acquire)
            || self.has_pending_sources()
    }

    fn detail(&self, source_id: u16) -> Option<FaultRecord> {
        let ready_state = u32::from(source_id) + FAULT_SLOT_READY_BASE;
        for slot in &self.details {
            if slot.state.load(Ordering::Acquire) == ready_state {
                return FaultRecord::from_raw(
                    slot.lo.load(Ordering::Relaxed),
                    slot.hi.load(Ordering::Relaxed),
                );
            }
        }
        None
    }

    fn claim_pending_attempt(&self, source_id: u16) -> bool {
        let (word, bit) = Self::source_word(source_id);
        self.pending[word].fetch_and(!bit, Ordering::AcqRel) & bit != 0
    }

    fn retry(&self, source_id: u16) {
        let (word, bit) = Self::source_word(source_id);
        self.pending[word].fetch_or(bit, Ordering::Release);
        self.work_pending.store(true, Ordering::Release);
    }

    fn complete(&self, source_id: u16) {
        let ready_state = u32::from(source_id) + FAULT_SLOT_READY_BASE;
        for slot in &self.details {
            if slot
                .state
                .compare_exchange(
                    ready_state,
                    FAULT_SLOT_EMPTY,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                break;
            }
        }
        let (word, bit) = Self::source_word(source_id);
        self.claimed[word].fetch_and(!bit, Ordering::AcqRel);
    }

    fn drain_with<F>(&self, max_attempts: usize, mut consume: F) -> usize
    where
        F: FnMut(u16, Option<FaultRecord>) -> bool,
    {
        if max_attempts == 0 {
            return 0;
        }
        // RF180-29 FIX: the drain budget is intentionally one SID per unit and
        // progress pass. A word-granular cursor therefore lets a repeatedly
        // republished low SID starve every higher SID in the same word. Keep a
        // source-granular round-robin cursor and visit the starting word in two
        // pieces so each SID is considered exactly once per invocation.
        const FAULT_SOURCE_COUNT: usize = FAULT_SOURCE_WORDS * 64;
        let start_source =
            usize::try_from(self.cursor.load(Ordering::Relaxed)).unwrap_or(0) % FAULT_SOURCE_COUNT;
        let start_word = start_source / 64;
        let start_bit = start_source % 64;
        let mut attempts = 0usize;
        let mut completed = 0usize;

        let mut drain_bits = |word: usize, mut bits: u64| -> bool {
            while bits != 0 && attempts < max_attempts {
                let bit_index = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let source = word * 64 + bit_index;
                let source_id = u16::try_from(source).expect("fault SID bitmap is 16-bit");
                if !self.claim_pending_attempt(source_id) {
                    continue;
                }
                attempts += 1;
                self.cursor.store(
                    u32::try_from((source + 1) % FAULT_SOURCE_COUNT)
                        .expect("fault cursor fits u32"),
                    Ordering::Relaxed,
                );
                if consume(source_id, self.detail(source_id)) {
                    self.complete(source_id);
                    completed += 1;
                } else {
                    self.retry(source_id);
                }
            }
            attempts >= max_attempts
        };

        let start_suffix =
            self.pending[start_word].load(Ordering::Acquire) & (u64::MAX << start_bit);
        if drain_bits(start_word, start_suffix) {
            return completed;
        }

        for offset in 1..FAULT_SOURCE_WORDS {
            let word = (start_word + offset) % FAULT_SOURCE_WORDS;
            if drain_bits(word, self.pending[word].load(Ordering::Acquire)) {
                return completed;
            }
        }

        if start_bit != 0 {
            let start_prefix =
                self.pending[start_word].load(Ordering::Acquire) & ((1u64 << start_bit) - 1);
            let _ = drain_bits(start_word, start_prefix);
        }
        completed
    }
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct QiDescriptor {
    lo: u64,
    hi: u64,
}

struct QueuedInvalidationQueue {
    phys: u64,
    virt: *mut QiDescriptor,
    tail: u16,
}

unsafe impl Send for QueuedInvalidationQueue {}

impl Drop for QueuedInvalidationQueue {
    fn drop(&mut self) {
        if self.phys != 0 {
            buddy_allocator::free_physical_pages(
                x86_64::structures::paging::PhysFrame::containing_address(PhysAddr::new(self.phys)),
                1,
            );
        }
    }
}

fn begin_detach_state(state: AttachmentState) -> Option<(AttachmentState, bool)> {
    match state {
        AttachmentState::Live | AttachmentState::Poisoned(ContextDisposition::PresentOrUnknown) => {
            Some((AttachmentState::DetachingPresent, false))
        }
        AttachmentState::Poisoned(ContextDisposition::ClearedNeedsFlush) => {
            Some((AttachmentState::DetachingCleared, true))
        }
        AttachmentState::FaultQuarantined => Some((AttachmentState::DetachingCleared, true)),
        AttachmentState::Preparing
        | AttachmentState::DetachingPresent
        | AttachmentState::DetachingCleared => None,
    }
}

fn attach_completion_state(context_ok: bool, iotlb_ok: bool) -> AttachmentState {
    if context_ok && iotlb_ok {
        AttachmentState::Live
    } else {
        AttachmentState::Poisoned(ContextDisposition::PresentOrUnknown)
    }
}

fn detach_completion_state(context_ok: bool, iotlb_ok: bool) -> Option<AttachmentState> {
    if context_ok && iotlb_ok {
        None
    } else {
        Some(AttachmentState::Poisoned(
            ContextDisposition::ClearedNeedsFlush,
        ))
    }
}

fn attachment_records_have_domain<'a>(
    mut records: impl Iterator<Item = &'a AttachmentRecord>,
    domain_id: DomainId,
) -> bool {
    records.any(|record| record.domain_id == domain_id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IotlbRetirementScope {
    Skip,
    Domain,
    Global,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TranslationDisableAction {
    AlreadyDisabled,
    ClearTe,
    Reject,
}

fn translation_disable_action(
    registry_complete: bool,
    registry_empty: bool,
    command_state_healthy: bool,
    software_enabled: bool,
    hardware_tes: bool,
) -> TranslationDisableAction {
    if !registry_complete
        || !registry_empty
        || !command_state_healthy
        || software_enabled != hardware_tes
    {
        TranslationDisableAction::Reject
    } else if software_enabled {
        TranslationDisableAction::ClearTe
    } else {
        TranslationDisableAction::AlreadyDisabled
    }
}

fn iotlb_retirement_scope(registry_complete: bool, domain_attached: bool) -> IotlbRetirementScope {
    if !registry_complete {
        IotlbRetirementScope::Global
    } else if domain_attached {
        IotlbRetirementScope::Domain
    } else {
        IotlbRetirementScope::Skip
    }
}

#[inline]
fn valid_context_table_phys(phys: u64) -> bool {
    phys != 0 && phys < MAX_DIRECT_MAP_PHYS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TranslationEnableAction {
    AlreadyEnabled,
    SetTe,
    Reject,
}

fn translation_enable_action(
    software_enabled: bool,
    hardware_tes: bool,
) -> TranslationEnableAction {
    match (software_enabled, hardware_tes) {
        (true, true) => TranslationEnableAction::AlreadyEnabled,
        (false, false) => TranslationEnableAction::SetTe,
        _ => TranslationEnableAction::Reject,
    }
}

#[inline]
fn fault_interrupt_update_allowed(enable: bool, sticky_overflow_mask: bool) -> bool {
    !enable || !sticky_overflow_mask
}

// ============================================================================
// VT-d Unit
// ============================================================================

/// Intel VT-d hardware unit driver.
///
/// Manages a single VT-d IOMMU unit discovered via ACPI DMAR table.
pub struct VtdUnit {
    /// Register base virtual address.
    reg_base: u64,

    /// PCI segment this unit handles.
    segment: u16,

    /// Whether this unit handles all PCI devices.
    include_pci_all: bool,

    /// Specific devices handled (if not include_pci_all).
    device_scopes: AdmittedVec<(u8, u8, u8)>, // (bus, device, function)

    /// Hardware version.
    version: (u8, u8),

    /// Capability register value.
    cap: u64,

    /// Extended capability register value.
    ecap: u64,

    /// Root table physical address.
    root_table_phys: AtomicU64,

    /// Lock protecting root/context table programming.
    /// Prevents data races when concurrent operations modify translation tables.
    table_lock: Mutex<()>,

    /// Whether translation is enabled.
    translation_enabled: AtomicBool,

    /// Whether the one-shot SRTP command for the immutable root-table address
    /// has been acknowledged by hardware.
    root_pointer_loaded: AtomicBool,

    /// An SRTP timeout leaves command retirement ambiguous; never resubmit or
    /// enable translation for this unit after that point.
    root_pointer_poisoned: AtomicBool,

    /// Interrupt remapping table (if enabled).
    /// Wrapped in Arc for safe sharing and Mutex for interior mutability.
    ir_table: Mutex<Option<Arc<InterruptRemappingTable>>>,

    /// Ambiguous IRE command state. Once set, IRTA and any retained table are
    /// quarantined for this unit's lifetime and all setup/retry paths fail closed.
    ir_poisoned: AtomicBool,

    /// Driver-owned queued-invalidation ring. Retained on QIE or completion
    /// ambiguity because hardware may continue fetching descriptors from it.
    qi_queue: Mutex<Option<QueuedInvalidationQueue>>,
    qi_poisoned: AtomicBool,

    /// Attached devices (source ID -> domain ID).
    ///
    /// RF180-20: this is the authoritative software ownership record. An entry
    /// is published before the hardware context-present bit and is removed only
    /// after both cache invalidations have completed. Thus `has_domain()` also
    /// covers in-progress and poisoned hardware state.
    attached_devices: Mutex<AttachmentRegistry>,

    /// A command timeout makes cache retirement ambiguous. Once poisoned, new
    /// mapping/attachment work is rejected and attachment ownership is retained
    /// so callers quarantine rather than reuse DMA-visible memory.
    cache_poisoned: AtomicBool,

    /// IOTLB register offset.
    iotlb_offset: usize,

    /// Fault recording register offset.
    fault_offset: usize,

    /// IRQ-safe fault ownership. The source bitmap is the durable minimum;
    /// bounded detail slots retain raw FRCD words when capacity permits.
    pending_faults: PendingFaultQueue,

    /// R180-15/RF180-12: serializes complete IOTLB, CCMD, and GCMD
    /// command/acknowledgement transactions so one completion cannot satisfy a
    /// competing submitter and pending GCMD commands cannot clobber each other.
    cmd_lock: Mutex<()>,

    /// Whole-heap charge for the production `Arc<VtdUnit>` allocation.
    _arc_heap_charge: Option<HeapCharge>,
}

impl VtdUnit {
    /// Create a new VT-d unit from DRHD information.
    ///
    /// # Arguments
    ///
    /// * `drhd` - DRHD entry from ACPI DMAR table
    ///
    /// # Returns
    ///
    /// Initialized VT-d unit or error
    pub fn new(drhd: &DrhdEntry) -> Result<Self, VtdError> {
        let reg_base = drhd.register_base();

        // Read version register
        let ver = unsafe { Self::read_reg32(reg_base, VTD_REG_VER) };
        let version = ((ver >> 4) as u8, (ver & 0xF) as u8);

        // Read capability registers
        let cap = unsafe { Self::read_reg64(reg_base, VTD_REG_CAP) };
        let ecap = unsafe { Self::read_reg64(reg_base, VTD_REG_ECAP) };

        // Polling is the only wired fault producer today. Explicitly mask the
        // unconfigured fault vector before any later unit publication instead
        // of relying on firmware/reset state.
        unsafe { crate::fault::set_fault_interrupt_enabled(reg_base, false) };

        // Calculate IOTLB register offset
        let iro = ((ecap >> ECAP_IRO_SHIFT) & ECAP_IRO_MASK) as usize;
        let iotlb_offset = iro * 16;

        // Calculate fault recording register offset
        let fro = ((cap >> CAP_FRO_SHIFT) & CAP_FRO_MASK) as usize;
        let fault_offset = fro * 16;

        // Extract device scopes
        let mut device_scopes = AdmittedVec::new(HeapClass::Device);
        device_scopes
            .try_reserve_exact(drhd.device_scopes().len())
            .map_err(|_| VtdError::HardwareInitFailed)?;
        for scope in drhd.device_scopes() {
            if let Some(&(dev, func)) = scope.path.last() {
                device_scopes
                    .push_reserved((scope.start_bus, dev, func))
                    .map_err(|_| VtdError::HardwareInitFailed)?;
            }
        }

        Ok(Self {
            reg_base,
            segment: drhd.segment(),
            include_pci_all: drhd.include_pci_all(),
            device_scopes,
            version,
            cap,
            ecap,
            root_table_phys: AtomicU64::new(0),
            table_lock: Mutex::new(()),
            translation_enabled: AtomicBool::new(false),
            root_pointer_loaded: AtomicBool::new(false),
            root_pointer_poisoned: AtomicBool::new(false),
            ir_table: Mutex::new(None),
            ir_poisoned: AtomicBool::new(false),
            qi_queue: Mutex::new(None),
            qi_poisoned: AtomicBool::new(false),
            attached_devices: Mutex::new(AttachmentRegistry::new()),
            cache_poisoned: AtomicBool::new(false),
            iotlb_offset,
            fault_offset,
            pending_faults: PendingFaultQueue::new(),
            cmd_lock: Mutex::new(()),
            _arc_heap_charge: None,
        })
    }

    pub fn try_new_arc(drhd: &DrhdEntry) -> Result<Arc<Self>, VtdError> {
        let bytes = arc_charge_bytes::<Self>().map_err(|_| VtdError::HardwareInitFailed)?;
        let reservation =
            try_reserve_heap(HeapClass::Device, bytes).map_err(|_| VtdError::HardwareInitFailed)?;
        let mut unit = Self::new(drhd)?;
        let charge = reservation
            .commit()
            .map_err(|_| VtdError::HardwareInitFailed)?;
        unit._arc_heap_charge = Some(charge);
        Arc::try_new(unit).map_err(|_| VtdError::HardwareInitFailed)
    }

    /// Get PCI segment.
    #[inline]
    pub fn segment(&self) -> u16 {
        self.segment
    }

    /// Check if this unit handles a specific device.
    pub fn handles_device(&self, device: &PciDeviceId) -> bool {
        if device.segment != self.segment {
            return false;
        }

        if self.include_pci_all {
            return true;
        }

        self.device_scopes.iter().any(|&(bus, dev, func)| {
            bus == device.bus && dev == device.device && func == device.function
        })
    }

    /// Check if a domain is attached to this unit.
    pub fn has_domain(&self, domain_id: DomainId) -> bool {
        let devices = self.attached_devices.lock();
        attachment_records_have_domain(devices.records.values(), domain_id)
    }

    fn attachment_registry_state(&self, domain_id: DomainId) -> (bool, bool) {
        let devices = self.attached_devices.lock();
        (
            devices.complete,
            attachment_records_have_domain(devices.records.values(), domain_id),
        )
    }

    /// Whether invalidation state is known-good for new map/unmap work.
    #[inline]
    pub fn cache_healthy(&self) -> bool {
        !self.cache_poisoned.load(Ordering::Acquire)
    }

    /// True when hardware may still dereference an IR table owned by this unit.
    /// Callers must retain the unit even if initialization is being aborted.
    pub(crate) fn owns_ambiguous_ir_table(&self) -> bool {
        self.ir_table.lock().is_some() || self.qi_queue.lock().is_some()
    }

    fn setup_queued_invalidation(&self) -> Result<(), VtdError> {
        let mut slot = self.qi_queue.lock();
        if self.qi_poisoned.load(Ordering::Acquire) {
            return Err(VtdError::HardwareInitFailed);
        }
        let _cmd_guard = self.cmd_lock.lock();
        let gsts = unsafe { Self::read_reg32(self.reg_base, VTD_REG_GSTS) };
        if slot.is_some() {
            return if gsts & GSTS_QIES != 0 {
                Ok(())
            } else {
                self.qi_poisoned.store(true, Ordering::Release);
                Err(VtdError::HardwareInitFailed)
            };
        }
        if self.ecap & ECAP_QI == 0 {
            return Err(VtdError::MissingCapability);
        }
        if gsts & GSTS_QIES != 0 {
            self.qi_poisoned.store(true, Ordering::Release);
            return Err(VtdError::HardwareInitFailed);
        }

        let frame =
            buddy_allocator::alloc_physical_pages(1).ok_or(VtdError::InterruptRemapAllocFailed)?;
        let phys = frame.start_address().as_u64();
        if phys >= MAX_DIRECT_MAP_PHYS {
            buddy_allocator::free_physical_pages(frame, 1);
            return Err(VtdError::InterruptRemapAllocFailed);
        }
        let virt = phys_to_virt(frame.start_address());
        unsafe { ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, QI_QUEUE_BYTES) };
        *slot = Some(QueuedInvalidationQueue {
            phys,
            virt: virt.as_mut_ptr::<QiDescriptor>(),
            tail: 0,
        });

        unsafe {
            Self::write_reg64(self.reg_base, VTD_REG_IQA, phys);
            Self::write_reg64(self.reg_base, VTD_REG_IQT, 0);
        }
        if let Err(error) =
            self.write_gcmd_and_wait_locked(GcmdUpdate::Set(GCMD_QIE), GcmdAck::Set(GSTS_QIES))
        {
            self.qi_poisoned.store(true, Ordering::Release);
            return Err(error);
        }
        let head = qi_decode_pointer(unsafe { Self::read_reg64(self.reg_base, VTD_REG_IQH) });
        if head != Some(0) {
            self.qi_poisoned.store(true, Ordering::Release);
            return Err(VtdError::HardwareInitFailed);
        }
        Ok(())
    }

    pub(crate) fn invalidate_interrupt_entry_cache(&self) -> IommuResult<()> {
        if self.qi_poisoned.load(Ordering::Acquire) {
            return Err(IommuError::HardwareInitFailed);
        }
        let mut slot = self.qi_queue.lock();
        let queue = slot.as_mut().ok_or(IommuError::NotInitialized)?;
        let gsts = unsafe { Self::read_reg32(self.reg_base, VTD_REG_GSTS) };
        if gsts & GSTS_QIES == 0 {
            self.qi_poisoned.store(true, Ordering::Release);
            return Err(IommuError::HardwareInitFailed);
        }
        let head = qi_decode_pointer(unsafe { Self::read_reg64(self.reg_base, VTD_REG_IQH) })
            .ok_or_else(|| {
                self.qi_poisoned.store(true, Ordering::Release);
                IommuError::HardwareInitFailed
            })?;
        if head != queue.tail {
            self.qi_poisoned.store(true, Ordering::Release);
            return Err(IommuError::HardwareInitFailed);
        }
        let index = qi_descriptor_index(queue.tail).ok_or_else(|| {
            self.qi_poisoned.store(true, Ordering::Release);
            IommuError::HardwareInitFailed
        })?;
        debug_assert!(index < QI_QUEUE_ENTRIES);
        unsafe {
            let descriptor = queue.virt.add(index);
            write_volatile(&mut (*descriptor).hi, 0);
            core::sync::atomic::fence(Ordering::Release);
            write_volatile(&mut (*descriptor).lo, QI_DESC_IEC_GLOBAL);
        }
        core::sync::atomic::fence(Ordering::SeqCst);
        let next = qi_next_tail(queue.tail).ok_or_else(|| {
            self.qi_poisoned.store(true, Ordering::Release);
            IommuError::HardwareInitFailed
        })?;
        queue.tail = next;
        unsafe { Self::write_reg64(self.reg_base, VTD_REG_IQT, next as u64) };
        // RF180-23 FIX: completion is the exact architectural head pointer,
        // not a masked/ordered approximation. Invalid or timed-out IQH state
        // quarantines the queue and its hardware-owned storage permanently.
        let completed = qi_poll_head_exact(next, || unsafe {
            Self::read_reg64(self.reg_base, VTD_REG_IQH)
        });
        qi_complete_or_poison(&self.qi_poisoned, completed)
    }

    /// Allocation-free state update used by attach/detach rollback paths.
    fn set_attachment_state(
        &self,
        source_id: u16,
        domain_id: DomainId,
        state: AttachmentState,
    ) -> IommuResult<()> {
        let mut devices = self.attached_devices.lock();
        match devices.records.get_mut(&source_id) {
            Some(record) if record.domain_id == domain_id => {
                record.state = state;
                Ok(())
            }
            _ => {
                devices.mark_incomplete();
                self.cache_poisoned.store(true, Ordering::Release);
                Err(IommuError::HardwareInitFailed)
            }
        }
    }

    fn poison_attachment(
        &self,
        source_id: u16,
        domain_id: DomainId,
        disposition: ContextDisposition,
    ) {
        self.cache_poisoned.store(true, Ordering::Release);
        let _ =
            self.set_attachment_state(source_id, domain_id, AttachmentState::Poisoned(disposition));
    }

    /// Get the domain ID for a device given its source ID.
    ///
    /// # Arguments
    ///
    /// * `source_id` - PCI source ID (bus << 8 | device << 3 | function)
    ///
    /// # Returns
    ///
    /// Domain ID if the device is attached, None otherwise.
    pub fn get_device_domain(&self, source_id: u16) -> Option<DomainId> {
        self.attached_devices
            .lock()
            .records
            .get(&source_id)
            .map(|record| record.domain_id)
    }

    pub fn try_get_device_domain(&self, source_id: u16) -> Result<Option<DomainId>, IommuError> {
        let devices = self
            .attached_devices
            .try_lock()
            .ok_or(IommuError::WouldBlock)?;
        Ok(devices
            .records
            .get(&source_id)
            .map(|record| record.domain_id))
    }

    /// Check whether translation is currently enabled for this unit.
    #[inline]
    pub fn translation_enabled(&self) -> bool {
        self.translation_enabled.load(Ordering::Acquire)
    }

    /// Check whether interrupt remapping is supported by hardware.
    #[inline]
    pub fn supports_interrupt_remapping(&self) -> bool {
        self.ecap & ECAP_IR != 0
    }

    /// Set up interrupt remapping for this VT-d unit.
    ///
    /// Interrupt remapping is critical for secure device passthrough as it prevents
    /// malicious devices from injecting arbitrary interrupts to the host. Without IR,
    /// a compromised device could trigger arbitrary interrupt vectors, potentially
    /// escaping VM isolation.
    ///
    /// # Arguments
    ///
    /// * `required` - If true, failure to enable IR is a fatal error
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Interrupt remapping successfully enabled
    /// * `Ok(false)` - IR not supported and not required (safe to continue without)
    /// * `Err(VtdError)` - IR required but setup failed (fail-closed)
    ///
    /// # Security
    ///
    /// - Fail-closed when `required=true`: if platform requires IR, failure aborts initialization
    /// - Table allocation failure with `required=false` gracefully degrades
    /// - Ambiguous GCMD.IRE failure retains IRTA/table and poisons retries
    ///
    /// # Hardware Flow
    ///
    /// 1. Check ECAP.IR for hardware support
    /// 2. Allocate interrupt remapping table (256 entries default)
    /// 3. Program IRTA register with table address
    /// 4. Set GCMD.IRE to enable interrupt remapping
    /// 5. Poll GSTS.IRES until set (hardware acknowledgment)
    pub fn setup_interrupt_remapping(&self, required: bool) -> Result<bool, VtdError> {
        // R84-1 FIX: Serialize setup to avoid double-programming IRTA/GCMD
        // and dropping a live table while hardware is racing.
        // Hold the mutex across the entire setup to prevent concurrent callers.
        let mut ir_slot = self.ir_table.lock();
        if self.ir_poisoned.load(Ordering::Acquire) {
            return Err(VtdError::HardwareInitFailed);
        }
        if ir_slot.is_some() {
            self.setup_queued_invalidation()?;
            // Table presence proves lifetime only; GSTS.IRES is hardware truth.
            let _cmd_guard = self.cmd_lock.lock();
            let gsts = unsafe { Self::read_reg32(self.reg_base, VTD_REG_GSTS) };
            if gsts & GSTS_IRES != 0 {
                return Ok(true);
            }
            self.ir_poisoned.store(true, Ordering::Release);
            return Err(VtdError::HardwareInitFailed);
        }

        // Check hardware support
        if !self.supports_interrupt_remapping() {
            return if required {
                // Platform requires IR but hardware doesn't support it - fail closed
                Err(VtdError::MissingCapability)
            } else {
                // IR not supported but not required - continue without
                Ok(false)
            };
        }

        // Firmware-enabled IR without a driver-owned table is not a reusable
        // starting state. Overwriting IRTA while IRE is live could redirect
        // hardware to an incompletely initialized table.
        {
            let _cmd_guard = self.cmd_lock.lock();
            let gsts = unsafe { Self::read_reg32(self.reg_base, VTD_REG_GSTS) };
            if gsts & GSTS_IRES != 0 {
                self.ir_poisoned.store(true, Ordering::Release);
                return Err(VtdError::HardwareInitFailed);
            }
        }

        // IRTE reuse is safe only with an acknowledged IEC invalidation. Do
        // not enable interrupt remapping on hardware without queued invalidation.
        self.setup_queued_invalidation()?;

        // Allocate interrupt remapping table
        // Default 256 entries (4KB, fits in one page)
        let table = match InterruptRemappingTable::try_allocate_arc(DEFAULT_IR_ENTRIES) {
            Ok(t) => t,
            Err(_) => {
                return if required {
                    Err(VtdError::HardwareInitFailed)
                } else {
                    // Allocation failed but not required - degrade gracefully
                    Ok(false)
                };
            }
        };

        // Program IRTA and submit IRE while retaining cmd_lock through both the
        // acknowledgement and software-state publication. A timeout is
        // ambiguous: IRES may change later, so never issue a stale-status
        // rollback or free/overwrite the table. Publish it as quarantined and
        // permanently reject retries for this unit.
        let _cmd_guard = self.cmd_lock.lock();
        let gsts = unsafe { Self::read_reg32(self.reg_base, VTD_REG_GSTS) };
        if gsts & GSTS_IRES != 0 {
            self.ir_poisoned.store(true, Ordering::Release);
            return Err(VtdError::HardwareInitFailed);
        }
        let irta = table.irta_value(false);
        unsafe {
            Self::write_reg64(self.reg_base, VTD_REG_IRTA, irta);
        }
        let enable_result =
            self.write_gcmd_and_wait_locked(GcmdUpdate::Set(GCMD_IRE), GcmdAck::Set(GSTS_IRES));
        *ir_slot = Some(table);
        if let Err(error) = enable_result {
            self.ir_poisoned.store(true, Ordering::Release);
            return Err(error);
        }

        Ok(true)
    }

    /// Allocate and initialize the root table if not already present.
    ///
    /// This method uses CAS to handle concurrent allocation attempts, ensuring
    /// only one root table is installed even with multiple CPUs racing.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Root table is ready (either already existed or was allocated)
    /// * `Err(VtdError)` - Allocation failed
    pub fn init_root_table(&self) -> Result<(), VtdError> {
        // Fast path: check if already allocated
        let current = self.root_table_phys.load(Ordering::Acquire);
        if current != 0 {
            // Validate existing root table is within direct map
            if current >= MAX_DIRECT_MAP_PHYS {
                return Err(VtdError::RootTableAllocFailed);
            }
            return Ok(());
        }

        // Allocate a physical frame for the root table
        let frame =
            buddy_allocator::alloc_physical_pages(1).ok_or(VtdError::RootTableAllocFailed)?;
        let phys = frame.start_address().as_u64();

        // Validate frame is within direct map range
        if phys >= MAX_DIRECT_MAP_PHYS {
            buddy_allocator::free_physical_pages(frame, 1);
            return Err(VtdError::RootTableAllocFailed);
        }

        // Zero the root table before publishing
        let virt = phys_to_virt(frame.start_address());
        unsafe {
            ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, size_of::<RootTable>());
        }

        // Atomically install the root table (only if still zero)
        match self
            .root_table_phys
            .compare_exchange(0, phys, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Ok(()),
            Err(existing) => {
                // Another CPU installed a table; free our redundant allocation
                buddy_allocator::free_physical_pages(frame, 1);
                // Validate the table installed by the other CPU
                if existing >= MAX_DIRECT_MAP_PHYS {
                    Err(VtdError::RootTableAllocFailed)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Ensure a context table exists for the given bus.
    ///
    /// This method allocates a context table if one doesn't exist for the specified
    /// PCI bus. Uses CAS to handle concurrent allocation attempts.
    ///
    /// # Arguments
    ///
    /// * `bus` - PCI bus number (0-255)
    ///
    /// # Returns
    ///
    /// * `Ok(&mut ContextTable)` - Reference to the context table
    /// * `Err(IommuError)` - Allocation failed or root table not initialized
    ///
    /// # Safety
    ///
    /// Caller must hold `table_lock` to serialize table updates.
    fn ensure_context_table(&self, bus: u8) -> IommuResult<&'static mut ContextTable> {
        let root_phys = self.root_table_phys.load(Ordering::Acquire);
        if root_phys == 0 {
            return Err(IommuError::NotInitialized);
        }
        if root_phys >= MAX_DIRECT_MAP_PHYS {
            return Err(IommuError::HardwareInitFailed);
        }

        // Get reference to root table
        let root_virt = phys_to_virt(PhysAddr::new(root_phys));
        let root_table = unsafe { &mut *root_virt.as_mut_ptr::<RootTable>() };

        // Check if context table already exists for this bus
        // We use atomic operations on the root entry's lo field to handle races
        let entry_ptr = unsafe { root_table.entries.as_mut_ptr().add(bus as usize) };
        let entry_lo_ptr = entry_ptr as *mut u64;
        let entry_atomic: &AtomicU64 = unsafe { &*(entry_lo_ptr as *const AtomicU64) };

        let current = entry_atomic.load(Ordering::Acquire);
        if current & RootEntry::PRESENT != 0 {
            // Context table already exists
            let ctx_phys = current & RootEntry::CTP_MASK;
            if !valid_context_table_phys(ctx_phys) {
                return Err(IommuError::HardwareInitFailed);
            }
            let ctx_virt = phys_to_virt(PhysAddr::new(ctx_phys));
            return Ok(unsafe { &mut *ctx_virt.as_mut_ptr::<ContextTable>() });
        }

        // Allocate a new context table
        let frame =
            buddy_allocator::alloc_physical_pages(1).ok_or(IommuError::PageTableAllocFailed)?;
        let ctx_phys = frame.start_address().as_u64();

        // Validate frame is within direct map range
        if !valid_context_table_phys(ctx_phys) {
            buddy_allocator::free_physical_pages(frame, 1);
            return Err(IommuError::PageTableAllocFailed);
        }

        // Zero the context table before publishing
        let ctx_virt = phys_to_virt(frame.start_address());
        unsafe {
            ptr::write_bytes(ctx_virt.as_mut_ptr::<u8>(), 0, size_of::<ContextTable>());
        }

        // Atomically install the root entry (only if still zero)
        let new_entry = RootEntry::new(ctx_phys);
        match entry_atomic.compare_exchange(0, new_entry.lo, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(unsafe { &mut *ctx_virt.as_mut_ptr::<ContextTable>() }),
            Err(existing) => {
                // Another CPU installed an entry; free our allocation
                buddy_allocator::free_physical_pages(frame, 1);

                // Validate the entry installed by the other CPU
                if existing & RootEntry::PRESENT == 0 {
                    return Err(IommuError::HardwareInitFailed);
                }
                let ctx_phys_existing = existing & RootEntry::CTP_MASK;
                if !valid_context_table_phys(ctx_phys_existing) {
                    return Err(IommuError::HardwareInitFailed);
                }
                let ctx_virt_existing = phys_to_virt(PhysAddr::new(ctx_phys_existing));
                Ok(unsafe { &mut *ctx_virt_existing.as_mut_ptr::<ContextTable>() })
            }
        }
    }

    /// Attach a device to a domain.
    ///
    /// Sets up the context table entry for the device. This configures the IOMMU
    /// to translate DMA requests from the device using the domain's address space.
    ///
    /// # Arguments
    ///
    /// * `device` - PCI device identifier (bus:device.function)
    /// * `domain` - Target domain for DMA isolation
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Device successfully attached
    /// * `Err(IommuError)` - Attachment failed
    ///
    /// # Security
    ///
    /// - Requires root table and translation to be enabled (fail-closed)
    /// - Rejects duplicate attachments
    /// - Validates domain page table root is within direct map
    /// - Uses proper memory ordering for context entry publication
    pub fn attach_device(&self, device: &PciDeviceId, domain: &Arc<Domain>) -> IommuResult<()> {
        let source_id = device.source_id();

        // Fail-closed: require root table, translation, and cache state to be
        // healthy before admitting new hardware ownership.
        if self.root_table_phys.load(Ordering::Acquire) == 0 || !self.translation_enabled() {
            return Err(IommuError::NotInitialized);
        }
        if !self.cache_healthy() {
            return Err(IommuError::HardwareInitFailed);
        }

        // Serialize context publication with detach and translation lifecycle.
        let _table_guard = self.table_lock.lock();
        if !self.translation_enabled() || !self.cache_healthy() {
            return Err(IommuError::HardwareInitFailed);
        }

        // Admission happens before even inspecting a possibly-live hardware
        // entry, so recovery publication cannot fail after ambiguity is found.
        {
            let mut devices = self.attached_devices.lock();
            if devices.records.contains_key(&source_id) {
                return Err(IommuError::DeviceAlreadyAttached);
            }
            if devices.records.ensure_capacity_for(1).is_err() {
                // We have not inspected the context yet; firmware or an earlier
                // owner may already have left it present. Poison before return
                // so map/unmap can never treat this unit as safely untracked.
                devices.mark_incomplete();
                self.cache_poisoned.store(true, Ordering::Release);
                return Err(IommuError::PageTableAllocFailed);
            }
        }

        // Get or allocate context table for this bus
        let context_table = match self.ensure_context_table(device.bus) {
            Ok(table) => table,
            Err(error) => {
                if matches!(
                    error,
                    IommuError::HardwareInitFailed | IommuError::NotInitialized
                ) {
                    // A structurally invalid or unexpectedly absent published
                    // root/context pointer means software can no longer prove
                    // it has enumerated every hardware-visible context.
                    let mut devices = self.attached_devices.lock();
                    devices.mark_incomplete();
                    self.cache_poisoned.store(true, Ordering::Release);
                }
                return Err(error);
            }
        };

        // Calculate context table index: (device << 3) | function
        let ctx_index = ((device.device as usize) << 3) | (device.function as usize);
        let entry = &mut context_table.entries[ctx_index];

        // An untracked present entry is already hardware-visible. Recover its
        // ownership into the software registry if possible, poison the unit,
        // and fail closed rather than allowing map/unmap to skip it.
        if entry.is_present() {
            let hardware_domain = entry.domain_id();
            let mut devices = self.attached_devices.lock();
            devices.mark_incomplete();
            if devices.records.contains_key(&source_id) {
                return Err(IommuError::DeviceAlreadyAttached);
            }
            let recorded = devices
                .records
                .insert_unique_reserved(
                    source_id,
                    AttachmentRecord {
                        domain_id: hardware_domain,
                        domain: None,
                        state: AttachmentState::Poisoned(ContextDisposition::PresentOrUnknown),
                    },
                )
                .is_ok();

            // An untracked firmware/previous-owner context must not remain live
            // merely because the requested attach is rejected. Revoke PRESENT
            // first, retain a tombstone when publication succeeded, and retire
            // both device-context and global translation caches before return.
            unsafe {
                write_volatile(&mut entry.lo, ContextEntry::empty().lo);
                core::sync::atomic::fence(Ordering::Release);
                write_volatile(&mut entry.hi, 0);
            }
            if recorded {
                if let Some(record) = devices.records.get_mut(&source_id) {
                    record.state = AttachmentState::FaultQuarantined;
                }
            }
            let context_result = self.invalidate_context_device_raw(device);
            let iotlb_result = self.invalidate_iotlb_global_raw();
            self.cache_poisoned.store(true, Ordering::Release);
            let _ = context_result.and(iotlb_result);
            return Err(IommuError::HardwareInitFailed);
        }

        // R169-13 FIX (Layer 2, authoritative DMA-isolation boundary): The
        // domain id is written into the context-entry hi dword
        // (new_translated/new_passthrough below) and into IOTLB/context
        // invalidation commands. It MUST be < THIS unit's hardware-supported
        // domain count (CAP.ND via num_domains()), or two distinct kernel
        // DomainIds alias the same hardware DID on constrained units (ND=0->16,
        // ND=1->64), breaking DMA isolation and mis-steering IOTLB flushes.
        // REJECT (never clamp — clamping would itself collapse two ids into one
        // hw DID). Gating here transitively closes the IOTLB/context-invalidation
        // path, since those commands run only after a successful attach. Mirrors
        // the sibling CAP.SAGAW/AGAW check in the PageTable branch below; applies
        // to BOTH the passthrough and translated branches.
        if (domain.id() as u32) >= self.num_domains() {
            return Err(IommuError::InvalidRange);
        }

        // Build context entry based on domain type
        let ctx_entry = match domain.domain_type() {
            DomainType::Identity => {
                // R94-13 FIX: Identity domains use VT-d pass-through translation,
                // which allows devices to DMA into arbitrary physical memory.
                // Only permit this when explicitly opted in via feature flag.
                #[cfg(not(feature = "unsafe_identity_passthrough"))]
                {
                    return Err(IommuError::PermissionDenied);
                }

                #[cfg(feature = "unsafe_identity_passthrough")]
                {
                    // R81-2 FIX: Check pass-through support before using TT_PASSTHROUGH
                    // If hardware doesn't support pass-through, fail closed
                    if !self.supports_passthrough() {
                        return Err(IommuError::HardwareInitFailed);
                    }
                    // Pass-through mode: IOVA == physical address
                    ContextEntry::new_passthrough(domain.id())
                }
            }
            DomainType::PageTable => {
                // R83-4 FIX: Validate domain AGAW against hardware CAP.SAGAW
                //
                // SAGAW bits in Capability Register:
                //   bit 0: 39-bit AGAW (3-level page table)
                //   bit 1: 48-bit AGAW (4-level page table)
                //   bit 2: 57-bit AGAW (5-level page table)
                //
                // If the domain's address width is not supported by hardware, the context
                // entry's AW field would be undefined, leading to DMA faults or translation
                // bypass. Fail-closed to prevent isolation bypass.
                //
                // NOTE: This check is only for PageTable domains. Identity domains use
                // pass-through mode and don't use the AW field.
                let sagaw_bits = self.supported_agaw();
                let domain_agaw_bit = match domain.address_width() {
                    39 => 1u8 << 0,
                    48 => 1u8 << 1,
                    57 => 1u8 << 2,
                    _ => 0u8, // Unknown/invalid address width
                };
                if domain_agaw_bit == 0 || (sagaw_bits & domain_agaw_bit) == 0 {
                    return Err(IommuError::InvalidRange);
                }

                // Full translation mode: use domain's second-level page table
                let slpt = domain.page_table_root();
                if slpt == 0 {
                    // Domain has no page table - fail closed
                    return Err(IommuError::NotInitialized);
                }
                if slpt >= MAX_DIRECT_MAP_PHYS {
                    return Err(IommuError::HardwareInitFailed);
                }
                ContextEntry::new_translated(domain.id(), slpt, domain.address_width())
            }
        };

        // Reserve and publish software ownership before making the context
        // present. Preparing is visible to concurrent map/unmap scans; those
        // invalidations may run early, while the post-publication invalidations
        // below provide the corresponding late-side ordering guarantee.
        {
            let mut devices = self.attached_devices.lock();
            if devices.records.contains_key(&source_id) {
                return Err(IommuError::DeviceAlreadyAttached);
            }
            if devices
                .records
                .insert_unique_reserved(
                    source_id,
                    AttachmentRecord {
                        domain_id: domain.id(),
                        domain: Some(Arc::clone(domain)),
                        state: AttachmentState::Preparing,
                    },
                )
                .is_err()
            {
                devices.mark_incomplete();
                self.cache_poisoned.store(true, Ordering::Release);
                return Err(IommuError::HardwareInitFailed);
            }
        }

        // Write context entry: upper dword first, then publish via low dword
        // This ensures the present bit is set last with full entry visible
        unsafe {
            write_volatile(&mut entry.hi, ctx_entry.hi);
            core::sync::atomic::fence(Ordering::Release);
            write_volatile(&mut entry.lo, ctx_entry.lo);
        }

        // Run both invalidations even if the first one fails. They use distinct
        // hardware command registers; attempting the second can still reduce
        // exposure, while any missing acknowledgement poisons the attachment.
        let context_result = self.invalidate_context_device_raw(device);
        let iotlb_result = self.invalidate_iotlb_domain_raw(domain.id());
        let completion = attach_completion_state(context_result.is_ok(), iotlb_result.is_ok());
        if let AttachmentState::Poisoned(disposition) = completion {
            self.poison_attachment(source_id, domain.id(), disposition);
            return context_result.and(iotlb_result);
        }

        self.set_attachment_state(source_id, domain.id(), completion)?;

        Ok(())
    }

    /// Detach a device from a domain.
    ///
    /// Clears the device's context entry, invalidates caches, and updates
    /// tracking structures. Bus mastering is disabled before tearing down
    /// the context to prevent post-detach DMA.
    ///
    /// # Arguments
    ///
    /// * `device` - PCI device identifier
    /// * `domain_id` - Domain the device is expected to be attached to
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Device successfully detached
    /// * `Err(IommuError)` - Detachment failed
    ///
    /// # Security
    ///
    /// - Bus mastering is disabled BEFORE clearing context (prevents post-detach DMA)
    /// - Context cache and IOTLB are invalidated after clearing entry
    /// - Validates device is actually attached to the specified domain
    /// - Fail-closed: returns error if any validation fails
    pub fn detach_device(&self, device: &PciDeviceId, domain_id: DomainId) -> IommuResult<()> {
        let source_id = device.source_id();

        // Fail-closed: require root table and translation to be enabled
        if self.root_table_phys.load(Ordering::Acquire) == 0 || !self.translation_enabled() {
            return Err(IommuError::NotInitialized);
        }

        // Allocation-free transition into a state that remains visible to
        // concurrent map/unmap scans. A prior ClearedNeedsFlush state is a
        // retry: skip table mutation and only repeat cache retirement.
        let (previous_state, context_already_cleared) = {
            let mut devices = self.attached_devices.lock();
            let record = devices
                .records
                .get_mut(&source_id)
                .ok_or(IommuError::DeviceNotAttached)?;
            if record.domain_id != domain_id {
                return Err(IommuError::DeviceNotAttached);
            }
            let previous = record.state;
            let (next, already_cleared) =
                begin_detach_state(previous).ok_or(IommuError::HardwareInitFailed)?;
            record.state = next;
            (previous, already_cleared)
        };

        // Disable bus mastering BEFORE clearing the context entry
        // This prevents any DMA from completing after we remove the translation
        // R87-2 FIX: Continue with detach even if bus mastering disable fails on non-zero segments
        let _bus_master_disabled = match self.disable_bus_mastering(device) {
            Ok(()) => true,
            Err(error) => {
                // Context retirement is the alternate containment boundary.
                // Never abandon teardown merely because PCI config access or
                // BME read-back failed.
                kprintln!(
                    "[IOMMU] WARNING: BME disable failed for {:02x}:{:02x}.{}: {:?}; proceeding with context retirement",
                    device.bus, device.device, device.function, error
                );
                false
            }
        };

        // Program tables under the same lifecycle lock used by enable/disable.
        let _table_guard = self.table_lock.lock();
        if !self.translation_enabled() {
            self.set_attachment_state(source_id, domain_id, previous_state)?;
            return Err(IommuError::NotInitialized);
        }

        if !context_already_cleared {
            // Locate and validate the hardware context before the point of no
            // return. Structural inconsistency is itself ambiguous and poisonable.
            let root_phys = self.root_table_phys.load(Ordering::Acquire);
            if root_phys == 0 || root_phys >= MAX_DIRECT_MAP_PHYS {
                self.poison_attachment(source_id, domain_id, ContextDisposition::PresentOrUnknown);
                return Err(IommuError::HardwareInitFailed);
            }
            let root_virt = phys_to_virt(PhysAddr::new(root_phys));
            let root_table = unsafe { &mut *root_virt.as_mut_ptr::<RootTable>() };
            let root_entry = &root_table.entries[device.bus as usize];
            if root_entry.is_present() {
                let ctx_phys = root_entry.context_table_addr();
                if !valid_context_table_phys(ctx_phys) {
                    self.poison_attachment(
                        source_id,
                        domain_id,
                        ContextDisposition::PresentOrUnknown,
                    );
                    return Err(IommuError::HardwareInitFailed);
                }
                let ctx_virt = phys_to_virt(PhysAddr::new(ctx_phys));
                let context_table = unsafe { &mut *ctx_virt.as_mut_ptr::<ContextTable>() };
                let ctx_index = ((device.device as usize) << 3) | (device.function as usize);
                let entry = &mut context_table.entries[ctx_index];
                if entry.is_present() {
                    if entry.domain_id() != domain_id {
                        self.poison_attachment(
                            source_id,
                            domain_id,
                            ContextDisposition::PresentOrUnknown,
                        );
                        return Err(IommuError::HardwareInitFailed);
                    }

                    // Clear PRESENT first, then metadata. The old hi-first order
                    // briefly exposed a present context with zeroed metadata.
                    unsafe {
                        write_volatile(&mut entry.lo, ContextEntry::empty().lo);
                        core::sync::atomic::fence(Ordering::Release);
                        write_volatile(&mut entry.hi, 0);
                    }
                }
            }
            // An absent root/context entry is already in the cleared disposition;
            // the mandatory invalidations below retire any stale cached context.
        }

        self.set_attachment_state(source_id, domain_id, AttachmentState::DetachingCleared)?;

        // Cache commands are retryable after a prior timeout once the command
        // register becomes idle. Run both and retain ClearedNeedsFlush on any
        // ambiguous acknowledgement.
        let context_result = self.invalidate_context_device_raw(device);
        let iotlb_result = self.invalidate_iotlb_domain_raw(domain_id);
        if let Some(AttachmentState::Poisoned(disposition)) =
            detach_completion_state(context_result.is_ok(), iotlb_result.is_ok())
        {
            self.poison_attachment(source_id, domain_id, disposition);
            return context_result.and(iotlb_result);
        }

        // Software ownership is forgotten only after hardware can no longer use
        // either the context or stale translations. Removal is allocation-free;
        // every earlier error returns with the exact tracking entry retained.
        {
            let mut devices = self.attached_devices.lock();
            match devices.records.remove_retaining_capacity(&source_id) {
                Some(record) if record.domain_id == domain_id => {
                    devices.records.reclaim_empty_capacity();
                }
                _ => {
                    devices.mark_incomplete();
                    self.cache_poisoned.store(true, Ordering::Release);
                    return Err(IommuError::HardwareInitFailed);
                }
            }
        }

        Ok(())
    }

    /// Disable PCI bus mastering for a device using legacy config space.
    ///
    /// This function uses legacy PCI I/O port access (0xCF8/0xCFC) which only
    /// supports segment 0. Multi-segment systems require ECAM support.
    ///
    /// # Arguments
    ///
    /// * `device` - PCI device to disable bus mastering for
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Bus mastering successfully disabled
    /// * `Err(IommuError::PermissionDenied)` - Device on unsupported segment
    /// * `Err(IommuError::DeviceNotFound)` - No device at this address
    /// * `Err(IommuError::HardwareInitFailed)` - Failed to disable bus mastering
    ///
    /// # Security
    ///
    /// - Validates device segment (legacy I/O only supports segment 0)
    /// - Uses global PCI config lock to serialize access
    /// - Verifies bus mastering was actually disabled via read-back
    pub(crate) fn disable_bus_mastering(&self, device: &PciDeviceId) -> IommuResult<()> {
        // Legacy PCI I/O only supports segment 0
        if device.segment != self.segment || device.segment != 0 {
            return Err(IommuError::PermissionDenied);
        }

        // Serialize PCI config space access
        let _pci_lock = crate::PCI_CONFIG_LOCK.lock();

        // Validate device exists by checking vendor ID
        let vendor_device = crate::pci_cfg_read32(device.bus, device.device, device.function, 0x00);
        let vendor = (vendor_device & 0xFFFF) as u16;
        if vendor == crate::PCI_VENDOR_INVALID {
            return Err(IommuError::DeviceNotFound);
        }

        // Read current command register
        let command = crate::pci_cfg_read16(
            device.bus,
            device.device,
            device.function,
            crate::PCI_COMMAND_OFFSET,
        );

        // Clear bus master enable bit
        let new_command = command & !crate::PCI_COMMAND_BUS_MASTER;
        crate::pci_cfg_write16(
            device.bus,
            device.device,
            device.function,
            crate::PCI_COMMAND_OFFSET,
            new_command,
        );

        // Verify the write took effect (read-back check)
        let verify = crate::pci_cfg_read16(
            device.bus,
            device.device,
            device.function,
            crate::PCI_COMMAND_OFFSET,
        );

        drop(_pci_lock);

        if verify & crate::PCI_COMMAND_BUS_MASTER == 0 {
            Ok(())
        } else {
            Err(IommuError::HardwareInitFailed)
        }
    }

    /// Clear one context entry without allocating. `table_lock` must be held.
    /// Returns the hardware DID when a present entry was retired.
    fn clear_context_for_source_locked(&self, source_id: u16) -> IommuResult<Option<DomainId>> {
        let root_phys = self.root_table_phys.load(Ordering::Acquire);
        if root_phys == 0 || root_phys >= MAX_DIRECT_MAP_PHYS {
            return Err(IommuError::HardwareInitFailed);
        }
        let root_virt = phys_to_virt(PhysAddr::new(root_phys));
        let root_table = unsafe { &mut *root_virt.as_mut_ptr::<RootTable>() };
        let bus = usize::from(source_id >> 8);
        let root_entry = &root_table.entries[bus];
        if !root_entry.is_present() {
            return Ok(None);
        }
        let context_phys = root_entry.context_table_addr();
        if !valid_context_table_phys(context_phys) {
            return Err(IommuError::HardwareInitFailed);
        }
        let context_virt = phys_to_virt(PhysAddr::new(context_phys));
        let context_table = unsafe { &mut *context_virt.as_mut_ptr::<ContextTable>() };
        let index = usize::from(source_id & 0xff);
        let entry = &mut context_table.entries[index];
        if !entry.is_present() {
            return Ok(None);
        }
        let domain_id = entry.domain_id();
        unsafe {
            write_volatile(&mut entry.lo, ContextEntry::empty().lo);
            core::sync::atomic::fence(Ordering::Release);
            write_volatile(&mut entry.hi, 0);
        }
        Ok(Some(domain_id))
    }

    /// Revoke an entire bus root when its child context pointer cannot be
    /// trusted. `table_lock` must be held. Global cache retirement is still
    /// required by the caller before the revocation is complete.
    fn clear_root_for_source_bus_locked(&self, source_id: u16) -> IommuResult<()> {
        let root_phys = self.root_table_phys.load(Ordering::Acquire);
        if root_phys == 0 || root_phys >= MAX_DIRECT_MAP_PHYS {
            return Err(IommuError::HardwareInitFailed);
        }
        let root_virt = phys_to_virt(PhysAddr::new(root_phys));
        let root_table = unsafe { &mut *root_virt.as_mut_ptr::<RootTable>() };
        let root_entry = &mut root_table.entries[usize::from(source_id >> 8)];
        if root_entry.is_present() {
            unsafe {
                write_volatile(&mut root_entry.lo, RootEntry::empty().lo);
                core::sync::atomic::fence(Ordering::Release);
                write_volatile(&mut root_entry.hi, 0);
            }
        }
        Ok(())
    }

    /// Process-context containment for one durable fault SID. The context is
    /// cleared even when PCI BME could not be disabled (including non-zero
    /// segments), then device-context and global-IOTLB retirement are required.
    pub(crate) fn quarantine_fault_source(&self, source_id: u16) -> IommuResult<()> {
        let device = PciDeviceId::new(
            self.segment,
            (source_id >> 8) as u8,
            ((source_id >> 3) & 0x1f) as u8,
            (source_id & 0x7) as u8,
        );
        let _table_guard = self.table_lock.lock();
        if !self.translation_enabled.load(Ordering::Acquire) {
            return Err(IommuError::NotInitialized);
        }
        let mut registry = self.attached_devices.lock();
        let hardware_domain = match self.clear_context_for_source_locked(source_id) {
            Ok(domain) => domain,
            Err(error) => {
                registry.mark_incomplete();
                self.cache_poisoned.store(true, Ordering::Release);
                if self.clear_root_for_source_bus_locked(source_id).is_err() {
                    return Err(error);
                }
                let source_bus = source_id >> 8;
                for (&record_source, record) in registry.records.iter_mut() {
                    if record_source >> 8 == source_bus {
                        record.state = AttachmentState::FaultQuarantined;
                    }
                }
                let retirement = self.invalidate_global_caches_raw();
                if retirement.is_err() {
                    self.cache_poisoned.store(true, Ordering::Release);
                }
                return retirement;
            }
        };
        let ownership_mismatch = match registry.records.get_mut(&source_id) {
            Some(record) => {
                let mismatch = hardware_domain.is_some_and(|domain| domain != record.domain_id);
                record.state = AttachmentState::FaultQuarantined;
                mismatch
            }
            None => true,
        };
        if ownership_mismatch {
            registry.mark_incomplete();
        }

        let context_result = self.invalidate_context_device_raw(&device);
        let iotlb_result = self.invalidate_iotlb_global_raw();
        let result = context_result.and(iotlb_result);
        if result.is_err() {
            self.cache_poisoned.store(true, Ordering::Release);
        }
        result
    }

    /// Overflow loses source identity, so contain the complete unit without
    /// disabling TE. All contexts are cleared and retained registry records are
    /// converted to quarantine tombstones before global cache retirement.
    pub(crate) fn quarantine_all_fault_contexts(&self) -> IommuResult<()> {
        let _table_guard = self.table_lock.lock();
        if !self.translation_enabled.load(Ordering::Acquire) {
            return Err(IommuError::NotInitialized);
        }
        let mut registry = self.attached_devices.lock();
        let root_phys = self.root_table_phys.load(Ordering::Acquire);
        if root_phys == 0 || root_phys >= MAX_DIRECT_MAP_PHYS {
            registry.mark_incomplete();
            self.cache_poisoned.store(true, Ordering::Release);
            return Err(IommuError::HardwareInitFailed);
        }
        let root_virt = phys_to_virt(PhysAddr::new(root_phys));
        let root_table = unsafe { &mut *root_virt.as_mut_ptr::<RootTable>() };
        for bus in 0..root_table.entries.len() {
            let root_entry = &mut root_table.entries[bus];
            if !root_entry.is_present() {
                continue;
            }
            let context_phys = root_entry.context_table_addr();
            if !valid_context_table_phys(context_phys) {
                registry.mark_incomplete();
                self.cache_poisoned.store(true, Ordering::Release);
                // The child table cannot be walked safely, so revoke the whole
                // bus at its root entry and continue. Returning here would skip
                // global retirement forever on every retry after partially
                // clearing earlier buses.
                unsafe {
                    write_volatile(&mut root_entry.lo, RootEntry::empty().lo);
                    core::sync::atomic::fence(Ordering::Release);
                    write_volatile(&mut root_entry.hi, 0);
                }
                continue;
            }
            let context_virt = phys_to_virt(PhysAddr::new(context_phys));
            let context_table = unsafe { &mut *context_virt.as_mut_ptr::<ContextTable>() };
            for index in 0..context_table.entries.len() {
                let entry = &mut context_table.entries[index];
                if !entry.is_present() {
                    continue;
                }
                let source_id = ((bus as u16) << 8) | index as u16;
                let hardware_domain = entry.domain_id();
                let ownership_mismatch = match registry.records.get(&source_id) {
                    Some(record) => record.domain_id != hardware_domain,
                    None => true,
                };
                // Revoke hardware PRESENT before metadata claims the context is
                // quarantined. The table/registry locks exclude lifecycle peers,
                // and the ordering remains explicit for future lockless readers.
                unsafe {
                    write_volatile(&mut entry.lo, ContextEntry::empty().lo);
                    core::sync::atomic::fence(Ordering::Release);
                    write_volatile(&mut entry.hi, 0);
                }
                if let Some(record) = registry.records.get_mut(&source_id) {
                    record.state = AttachmentState::FaultQuarantined;
                }
                if ownership_mismatch {
                    registry.mark_incomplete();
                }
            }
        }
        for record in registry.records.values_mut() {
            record.state = AttachmentState::FaultQuarantined;
        }

        let result = self.invalidate_global_caches_raw();
        if result.is_ok() {
            // A complete table walk plus both global acknowledgements restores
            // the proof that every remaining record is an explicit tombstone.
            registry.complete = true;
        } else {
            registry.mark_incomplete();
            self.cache_poisoned.store(true, Ordering::Release);
        }
        result
    }

    /// Invalidate IOTLB entries for a domain.
    ///
    /// R180-15 FIX: IOTLB command register is single-submission. Concurrent
    /// writers can both observe the same IVT completion and free DMA pages
    /// while a device still holds a stale translation. Serialize under
    /// `cmd_lock` and poll busy (IVT clear) before every write.
    pub fn invalidate_iotlb_domain(&self, domain_id: DomainId) -> IommuResult<()> {
        if !self.cache_healthy() {
            return Err(IommuError::HardwareInitFailed);
        }
        let _table_guard = self.table_lock.lock();
        if !self.cache_healthy() {
            return Err(IommuError::HardwareInitFailed);
        }
        let result = self.invalidate_iotlb_domain_raw(domain_id);
        if result.is_err() {
            self.cache_poisoned.store(true, Ordering::Release);
        }
        result
    }

    /// Command body used by attachment recovery even after a prior poison. A
    /// successful retry proves this command retired; callers still retain the
    /// global poison unless every ambiguous ownership record is resolved.
    fn invalidate_iotlb_domain_raw(&self, domain_id: DomainId) -> IommuResult<()> {
        if !self.translation_enabled.load(Ordering::Acquire) {
            return Err(IommuError::NotInitialized);
        }

        let _cmd = self.cmd_lock.lock();
        let result = (|| {
            // Wait for any in-flight command before issuing a new one.
            self.wait_iotlb_complete()?;

            // Build invalidation command
            let cmd =
                IOTLB_IVT | IOTLB_IIRG_DOMAIN | IOTLB_DR | IOTLB_DW | ((domain_id as u64) << 32);

            // Write to IOTLB register
            unsafe {
                Self::write_reg64(self.reg_base, self.iotlb_offset + 8, cmd);
            }

            // Wait for THIS command's completion (IVT bit clears)
            self.wait_iotlb_complete()
        })();
        result
    }

    /// Conservative fallback when attachment ownership is incomplete. A global
    /// invalidation is required because an untracked context may reference any
    /// domain ID; skipping or issuing only the requested DID would be unsound.
    fn invalidate_iotlb_global_raw(&self) -> IommuResult<()> {
        if !self.translation_enabled.load(Ordering::Acquire) {
            return Err(IommuError::NotInitialized);
        }

        let _cmd = self.cmd_lock.lock();
        let result = (|| {
            self.wait_iotlb_complete()?;
            let cmd = IOTLB_IVT | IOTLB_IIRG_GLOBAL | IOTLB_DR | IOTLB_DW;
            unsafe { Self::write_reg64(self.reg_base, self.iotlb_offset + 8, cmd) };
            self.wait_iotlb_complete()
        })();
        result
    }

    /// Retire every cached context and translation when software ownership is
    /// incomplete. Both commands are attempted even if the first acknowledgement
    /// is ambiguous, because they use distinct architectural command registers.
    fn invalidate_global_caches_raw(&self) -> IommuResult<()> {
        let context_result = self.invalidate_context_global_raw();
        let iotlb_result = self.invalidate_iotlb_global_raw();
        context_result.and(iotlb_result)
    }

    /// Invalidate IOTLB entries for a specific range.
    pub fn invalidate_iotlb_range(
        &self,
        domain_id: DomainId,
        _iova: u64,
        _size: usize,
    ) -> IommuResult<()> {
        // Domain-wide invalidation is the conservative fallback even when PSI
        // exists. Delegating unconditionally also preserves poison/TE checks.
        self.invalidate_iotlb_domain(domain_id)
    }

    /// Atomically decide attachment participation and invalidate under the
    /// context lifecycle lock. A concurrent attach that has not published
    /// tracking yet must perform its own post-publication invalidation; one that
    /// has published `Preparing` is observed here. A completed detach is safely
    /// skipped only after context retirement and both invalidations.
    pub fn invalidate_iotlb_range_if_attached(
        &self,
        domain_id: DomainId,
        _iova: u64,
        _size: usize,
    ) -> IommuResult<()> {
        let _table_guard = self.table_lock.lock();
        if !self.cache_healthy() {
            return Err(IommuError::HardwareInitFailed);
        }
        let (complete, attached) = self.attachment_registry_state(domain_id);
        let result = match iotlb_retirement_scope(complete, attached) {
            IotlbRetirementScope::Skip => return Ok(()),
            IotlbRetirementScope::Domain => self.invalidate_iotlb_domain_raw(domain_id),
            IotlbRetirementScope::Global => self.invalidate_global_caches_raw(),
        };
        if result.is_err() {
            self.cache_poisoned.store(true, Ordering::Release);
        }
        result
    }

    pub fn try_invalidate_iotlb_domain(&self, domain_id: DomainId) -> IommuResult<()> {
        let _table_guard = self.table_lock.try_lock().ok_or(IommuError::WouldBlock)?;
        if !self.cache_healthy() {
            return Err(IommuError::HardwareInitFailed);
        }
        if !self.translation_enabled.load(Ordering::Acquire) {
            return Err(IommuError::NotInitialized);
        }
        let _cmd = self.cmd_lock.try_lock().ok_or(IommuError::WouldBlock)?;
        // RF180-20 FIX: the pre-submit busy drain is part of the same hardware
        // transaction as the post-submit acknowledgement. Either timeout is
        // ambiguous and must poison all later cache-dependent work.
        let result = (|| {
            self.wait_iotlb_complete()?;
            let cmd =
                IOTLB_IVT | IOTLB_IIRG_DOMAIN | IOTLB_DR | IOTLB_DW | ((domain_id as u64) << 32);
            unsafe { Self::write_reg64(self.reg_base, self.iotlb_offset + 8, cmd) };
            self.wait_iotlb_complete()
        })();
        if result.is_err() {
            self.cache_poisoned.store(true, Ordering::Release);
        }
        result
    }

    /// Cleanup-side variant used by retryable unmap. It deliberately attempts
    /// a fresh domain invalidation even after sticky poison; failure retains the
    /// mapping tombstone, while success permits that one ownership transaction
    /// to retire without declaring the whole unit healthy again.
    pub fn retire_iotlb_range_if_attached(
        &self,
        domain_id: DomainId,
        _iova: u64,
        _size: usize,
    ) -> IommuResult<()> {
        let _table_guard = self.table_lock.lock();
        let (complete, attached) = self.attachment_registry_state(domain_id);
        let result = match iotlb_retirement_scope(complete, attached) {
            IotlbRetirementScope::Skip => return Ok(()),
            IotlbRetirementScope::Domain => self.invalidate_iotlb_domain_raw(domain_id),
            IotlbRetirementScope::Global => self.invalidate_global_caches_raw(),
        };
        if result.is_err() {
            self.cache_poisoned.store(true, Ordering::Release);
        }
        result
    }

    /// Invalidate context cache for a specific device.
    ///
    /// R180-15 class extension: CCMD is single-submission like IOTLB. Serialize
    /// under `cmd_lock` and drain busy before write so concurrent attach/detach
    /// cannot both observe one ICC completion.
    pub fn invalidate_context_device(&self, device: &PciDeviceId) -> IommuResult<()> {
        if !self.cache_healthy() {
            return Err(IommuError::HardwareInitFailed);
        }
        let _table_guard = self.table_lock.lock();
        if !self.cache_healthy() {
            return Err(IommuError::HardwareInitFailed);
        }
        let result = self.invalidate_context_device_raw(device);
        if result.is_err() {
            self.cache_poisoned.store(true, Ordering::Release);
        }
        result
    }

    pub fn try_invalidate_context_device(&self, device: &PciDeviceId) -> IommuResult<()> {
        let _table_guard = self.table_lock.try_lock().ok_or(IommuError::WouldBlock)?;
        if !self.cache_healthy() {
            return Err(IommuError::HardwareInitFailed);
        }
        if !self.translation_enabled.load(Ordering::Acquire) {
            return Err(IommuError::NotInitialized);
        }
        let _cmd = self.cmd_lock.try_lock().ok_or(IommuError::WouldBlock)?;
        // RF180-20 FIX: poison on both the pre-submit and post-submit timeout;
        // returning early from the initial drain previously left IRQ callers
        // able to continue after an already-ambiguous command stream.
        let result = (|| {
            self.wait_context_complete()?;
            let cmd = CCMD_ICC | CCMD_CIRG_DEVICE | ((device.source_id() as u64) << 16);
            unsafe { Self::write_reg64(self.reg_base, VTD_REG_CCMD, cmd) };
            self.wait_context_complete()
        })();
        if result.is_err() {
            self.cache_poisoned.store(true, Ordering::Release);
        }
        result
    }

    fn invalidate_context_device_raw(&self, device: &PciDeviceId) -> IommuResult<()> {
        if !self.translation_enabled.load(Ordering::Acquire) {
            return Err(IommuError::NotInitialized);
        }

        let _cmd = self.cmd_lock.lock();
        let result = (|| {
            self.wait_context_complete()?;

            // Build context invalidation command for device granularity
            // CIRG = 11b (device), SID = source_id, FM = 0 (exact match)
            let source_id = device.source_id() as u64;
            let cmd = CCMD_ICC | CCMD_CIRG_DEVICE | (source_id << 16);

            // Write to context command register
            unsafe {
                Self::write_reg64(self.reg_base, VTD_REG_CCMD, cmd);
            }

            // Wait for THIS command's completion (ICC bit clears)
            self.wait_context_complete()
        })();
        result
    }

    fn invalidate_context_global_raw(&self) -> IommuResult<()> {
        if !self.translation_enabled.load(Ordering::Acquire) {
            return Err(IommuError::NotInitialized);
        }

        let _cmd = self.cmd_lock.lock();
        let result = (|| {
            self.wait_context_complete()?;
            unsafe {
                Self::write_reg64(self.reg_base, VTD_REG_CCMD, CCMD_ICC | CCMD_CIRG_GLOBAL);
            }
            self.wait_context_complete()
        })();
        result
    }

    /// Wait for context cache invalidation to complete.
    fn wait_context_complete(&self) -> IommuResult<()> {
        for _ in 0..1000 {
            let val = unsafe { Self::read_reg64(self.reg_base, VTD_REG_CCMD) };
            if val & CCMD_ICC == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(IommuError::HardwareInitFailed)
    }

    /// Enable DMA translation.
    ///
    /// This activates the IOMMU to enforce DMA isolation. Before calling this,
    /// the root table must be allocated (via init_root_table).
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Translation enabled
    /// * `Err(VtdError)` - Hardware error or allocation failed
    /// Enable DMA translation.
    ///
    /// R180-18 FIX: every GCMD write is built from GSTS so previously-enabled
    /// features (notably IRE from `setup_interrupt_remapping`) are preserved.
    /// The prior code wrote `GCMD_SRTP | GCMD_TE` alone and silently cleared IRE.
    pub fn enable_translation(&self) -> Result<(), VtdError> {
        let _table_guard = self.table_lock.lock();
        if !self.cache_healthy() {
            return Err(VtdError::HardwareInitFailed);
        }
        let software_enabled = self.translation_enabled.load(Ordering::Acquire);
        let hardware_tes = unsafe { Self::read_reg32(self.reg_base, VTD_REG_GSTS) } & GSTS_TES != 0;
        match translation_enable_action(software_enabled, hardware_tes) {
            TranslationEnableAction::AlreadyEnabled => return Ok(()),
            TranslationEnableAction::SetTe => {}
            TranslationEnableAction::Reject => {
                // Never install a new RTADDR while firmware or an ambiguous
                // prior command still has translation live. Clearing TE would
                // permit bypass; retain the unknown hardware root and fail shut.
                self.cache_poisoned.store(true, Ordering::Release);
                if hardware_tes {
                    self.root_pointer_poisoned.store(true, Ordering::Release);
                }
                return Err(VtdError::HardwareInitFailed);
            }
        }
        if self.ir_poisoned.load(Ordering::Acquire) {
            return Err(VtdError::HardwareInitFailed);
        }
        if self.root_pointer_poisoned.load(Ordering::Acquire) {
            return Err(VtdError::HardwareInitFailed);
        }

        // Ensure root table is allocated and valid
        self.init_root_table()?;
        let root_phys = self.root_table_phys.load(Ordering::Acquire);
        if root_phys == 0 || root_phys >= MAX_DIRECT_MAP_PHYS {
            return Err(VtdError::RootTableAllocFailed);
        }

        // Serialize setup/enable/disable state transitions with IR setup. The
        // common order is ir_table -> cmd_lock; no path takes the reverse pair.
        let ir_guard = self.ir_table.lock();
        let software_enabled = self.translation_enabled.load(Ordering::Acquire);
        let hardware_tes = unsafe { Self::read_reg32(self.reg_base, VTD_REG_GSTS) } & GSTS_TES != 0;
        match translation_enable_action(software_enabled, hardware_tes) {
            TranslationEnableAction::AlreadyEnabled => return Ok(()),
            TranslationEnableAction::SetTe => {}
            TranslationEnableAction::Reject => {
                self.cache_poisoned.store(true, Ordering::Release);
                if hardware_tes {
                    self.root_pointer_poisoned.store(true, Ordering::Release);
                }
                return Err(VtdError::HardwareInitFailed);
            }
        }
        if self.ir_poisoned.load(Ordering::Acquire) {
            return Err(VtdError::HardwareInitFailed);
        }
        if self.root_pointer_poisoned.load(Ordering::Acquire) {
            return Err(VtdError::HardwareInitFailed);
        }

        // SRTP is a one-shot command, not persistent GCMD state. Submit it only
        // until this immutable root pointer has been acknowledged; never fold
        // GSTS.RTPS into later WBF/TE updates.
        if !self.root_pointer_loaded.load(Ordering::Acquire) {
            let _cmd_guard = self.cmd_lock.lock();
            if !self.root_pointer_loaded.load(Ordering::Acquire) {
                unsafe {
                    Self::write_reg64(self.reg_base, VTD_REG_RTADDR, root_phys);
                }
                if let Err(error) = self
                    .write_gcmd_and_wait_locked(GcmdUpdate::Set(GCMD_SRTP), GcmdAck::Set(GSTS_RTPS))
                {
                    self.root_pointer_poisoned.store(true, Ordering::Release);
                    return Err(error);
                }
                self.root_pointer_loaded.store(true, Ordering::Release);
            }
        }

        // Flush write buffer if required
        if self.cap & CAP_RWBF != 0 {
            if let Err(error) =
                self.write_gcmd_and_wait(GcmdUpdate::Set(GCMD_WBF), GcmdAck::Clear(GSTS_WBFS))
            {
                self.cache_poisoned.store(true, Ordering::Release);
                return Err(error);
            }
        }

        // Enable translation while preserving IRE, serialized through TES.
        if let Err(error) =
            self.write_gcmd_and_wait(GcmdUpdate::Set(GCMD_TE), GcmdAck::Set(GSTS_TES))
        {
            // TES may assert after the timeout. Retain every table and reject all
            // later lifecycle/map work; init will keep this unit allocation alive.
            self.cache_poisoned.store(true, Ordering::Release);
            return Err(error);
        }
        self.translation_enabled.store(true, Ordering::Release);

        // R180-18 defense-in-depth: if IR was previously enabled, re-assert IRES.
        let gsts = unsafe { Self::read_reg32(self.reg_base, VTD_REG_GSTS) };
        let ir_was_desired = ir_guard.is_some();
        if ir_was_desired && (gsts & GSTS_IRES) == 0 {
            // IRE was dropped or never latched — re-enable and verify.
            if let Err(error) =
                self.write_gcmd_and_wait(GcmdUpdate::Set(GCMD_IRE), GcmdAck::Set(GSTS_IRES))
            {
                self.ir_poisoned.store(true, Ordering::Release);
                self.cache_poisoned.store(true, Ordering::Release);
                return Err(error);
            }
        }

        Ok(())
    }

    /// Disable DMA translation (preserves IRE if still desired).
    pub fn disable_translation(&self) -> Result<(), VtdError> {
        let _table_guard = self.table_lock.lock();
        let (registry_complete, registry_empty) = {
            let registry = self.attached_devices.lock();
            (registry.complete, registry.records.is_empty())
        };
        let command_state_healthy = self.cache_healthy()
            && !self.root_pointer_poisoned.load(Ordering::Acquire)
            && !self.ir_poisoned.load(Ordering::Acquire)
            && !self.qi_poisoned.load(Ordering::Acquire);
        let software_enabled = self.translation_enabled.load(Ordering::Acquire);
        let hardware_tes = unsafe { Self::read_reg32(self.reg_base, VTD_REG_GSTS) } & GSTS_TES != 0;
        match translation_disable_action(
            registry_complete,
            registry_empty,
            command_state_healthy,
            software_enabled,
            hardware_tes,
        ) {
            TranslationDisableAction::AlreadyDisabled => return Ok(()),
            TranslationDisableAction::ClearTe => {}
            TranslationDisableAction::Reject => {
                if software_enabled != hardware_tes {
                    self.cache_poisoned.store(true, Ordering::Release);
                }
                return Err(VtdError::HardwareInitFailed);
            }
        }

        let _ir_guard = self.ir_table.lock();
        let software_enabled = self.translation_enabled.load(Ordering::Acquire);
        let hardware_tes = unsafe { Self::read_reg32(self.reg_base, VTD_REG_GSTS) } & GSTS_TES != 0;
        if !software_enabled || !hardware_tes || !self.cache_healthy() {
            self.cache_poisoned.store(true, Ordering::Release);
            return Err(VtdError::HardwareInitFailed);
        }

        // Clear TE while preserving other features, serialized through TES clear.
        if let Err(error) =
            self.write_gcmd_and_wait(GcmdUpdate::Clear(GCMD_TE), GcmdAck::Clear(GSTS_TES))
        {
            // TE may clear later; keep software ownership conservative and
            // permanently reject re-enable/use of this lifecycle.
            self.cache_poisoned.store(true, Ordering::Release);
            return Err(error);
        }

        self.translation_enabled.store(false, Ordering::Release);
        Ok(())
    }

    /// RF180-12 FIX: update GCMD and retain `cmd_lock` until GSTS acknowledges
    /// that exact command. GCMD is write-only, so updates are reconstructed from
    /// the current GSTS feature state before the requested bits are changed.
    fn write_gcmd_and_wait(&self, update: GcmdUpdate, ack: GcmdAck) -> Result<(), VtdError> {
        let _cmd_guard = self.cmd_lock.lock();
        self.write_gcmd_and_wait_locked(update, ack)
    }

    /// GCMD transaction body for callers that already hold `cmd_lock` across
    /// adjacent state publication (notably IRE quarantine).
    fn write_gcmd_and_wait_locked(&self, update: GcmdUpdate, ack: GcmdAck) -> Result<(), VtdError> {
        let gsts = unsafe { Self::read_reg32(self.reg_base, VTD_REG_GSTS) };
        let gcmd = match update {
            GcmdUpdate::Set(bits) => gsts_to_gcmd(gsts) | bits,
            GcmdUpdate::Clear(bits) => gsts_to_gcmd(gsts) & !bits,
        };
        unsafe {
            Self::write_reg32(self.reg_base, VTD_REG_GCMD, gcmd);
        }

        match ack {
            GcmdAck::Set(bit) => self.wait_status(bit),
            GcmdAck::Clear(bit) => self.wait_status_clear(bit),
        }
    }

    /// Wait for IOTLB invalidation to complete.
    fn wait_iotlb_complete(&self) -> IommuResult<()> {
        for _ in 0..1000 {
            let val = unsafe { Self::read_reg64(self.reg_base, self.iotlb_offset + 8) };
            if val & IOTLB_IVT == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(IommuError::HardwareInitFailed)
    }

    /// Wait for status bit to be set.
    fn wait_status(&self, bit: u32) -> Result<(), VtdError> {
        for _ in 0..1000 {
            let status = unsafe { Self::read_reg32(self.reg_base, VTD_REG_GSTS) };
            if status & bit != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(VtdError::HardwareTimeout)
    }

    /// Wait for status bit to clear.
    fn wait_status_clear(&self, bit: u32) -> Result<(), VtdError> {
        for _ in 0..1000 {
            let status = unsafe { Self::read_reg32(self.reg_base, VTD_REG_GSTS) };
            if status & bit == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(VtdError::HardwareTimeout)
    }

    /// Get hardware version.
    pub fn version(&self) -> (u8, u8) {
        self.version
    }

    /// Get maximum guest address width.
    pub fn max_guest_addr_width(&self) -> u8 {
        (((self.cap >> CAP_MGAW_SHIFT) & CAP_MGAW_MASK) as u8) + 1
    }

    /// Get supported adjusted guest address widths.
    pub fn supported_agaw(&self) -> u8 {
        ((self.cap >> CAP_SAGAW_SHIFT) & CAP_SAGAW_MASK) as u8
    }

    /// Get number of domains supported.
    pub fn num_domains(&self) -> u32 {
        let nd = (self.cap & CAP_ND_MASK) as u32;
        match nd {
            0 => 16,
            1 => 64,
            2 => 256,
            3 => 1024,
            4 => 4096,
            5 => 16384,
            6 => 65536,
            _ => 256,
        }
    }

    /// Check if queued invalidation is supported.
    pub fn supports_qi(&self) -> bool {
        self.ecap & ECAP_QI != 0
    }

    /// Check if pass-through is supported.
    pub fn supports_passthrough(&self) -> bool {
        self.ecap & ECAP_PT != 0
    }

    /// Get a reference to the interrupt remapping table (if enabled).
    ///
    /// Returns `Some(Arc<InterruptRemappingTable>)` if interrupt remapping has been
    /// set up for this unit, `None` otherwise.
    pub fn interrupt_remapping_table(&self) -> Option<Arc<InterruptRemappingTable>> {
        if self.ir_poisoned.load(Ordering::Acquire) || self.qi_poisoned.load(Ordering::Acquire) {
            return None;
        }
        let slot = self.ir_table.lock();
        let table = slot.as_ref()?.clone();
        let _cmd_guard = self.cmd_lock.lock();
        let gsts = unsafe { Self::read_reg32(self.reg_base, VTD_REG_GSTS) };
        if gsts & GSTS_IRES == 0 || gsts & GSTS_QIES == 0 {
            self.ir_poisoned.store(true, Ordering::Release);
            self.qi_poisoned.store(true, Ordering::Release);
            return None;
        }
        Some(table)
    }

    /// Get the number of fault recording registers.
    pub fn num_fault_regs(&self) -> usize {
        // CAP.NFR is zero-based, so add 1
        (((self.cap >> CAP_NFR_SHIFT) & CAP_NFR_MASK) as usize) + 1
    }

    /// Allocation-free timer/IRQ capture. Hardware records are acknowledged
    /// only after the source bitmap (and, when available, raw detail slot) has
    /// been published with Release ordering.
    pub(crate) fn capture_faults_irq(&self) -> bool {
        if !self.pending_faults.try_claim_capture() {
            self.pending_faults.request_recapture();
            return true;
        }
        self.pending_faults.begin_capture();
        let summary = unsafe {
            crate::fault::capture_fault_records_mmio(
                self.reg_base,
                self.fault_offset,
                self.num_fault_regs(),
                |record, lo, hi| self.pending_faults.publish(record, lo, hi),
                || {
                    self.pending_faults.mark_overflow();
                    self.pending_faults.mark_interrupt_masked();
                },
            )
        };
        self.pending_faults.release_capture();
        summary.captured != 0
            || summary.overflow
            || summary.incomplete
            || self.pending_faults.has_work()
    }

    /// Bounded process-context drain. A failed consumer keeps the SID claimed
    /// and pending for the next pass; overflow is re-published when complete-unit
    /// quarantine cannot be acknowledged.
    pub(crate) fn drain_fault_work<O, F>(
        &self,
        max_attempts: usize,
        mut contain_overflow: O,
        consume: F,
    ) -> usize
    where
        O: FnMut() -> bool,
        F: FnMut(u16, Option<FaultRecord>) -> bool,
    {
        if !self.pending_faults.try_claim_drain() {
            return 0;
        }
        self.pending_faults.begin_drain();
        if self.pending_faults.take_overflow() && !contain_overflow() {
            self.pending_faults.mark_overflow();
        }
        let completed = self.pending_faults.drain_with(max_attempts, consume);
        self.pending_faults.release_drain();
        completed
    }

    pub(crate) fn has_pending_fault_work(&self) -> bool {
        self.pending_faults.has_work()
    }

    pub(crate) fn fault_interrupt_masked(&self) -> bool {
        self.pending_faults.interrupt_masked.load(Ordering::Acquire)
    }

    /// Enable or disable fault event interrupts.
    ///
    /// When enabled, the IOMMU will generate an interrupt when a DMA fault occurs.
    /// The interrupt vector and destination should be configured in the Fault Event
    /// registers (FEDATA, FEADDR) before enabling.
    ///
    /// # Arguments
    ///
    /// * `enable` - True to enable fault interrupts, false to disable
    pub fn set_fault_interrupt_enabled(&self, enable: bool) -> IommuResult<()> {
        // Serialize the FECTL RMW with capture's overflow masking. IRQ capture
        // never waits on this owner; process callers receive a retryable error.
        if !self.pending_faults.try_claim_capture() {
            return Err(IommuError::WouldBlock);
        }
        let result = if fault_interrupt_update_allowed(
            enable,
            self.pending_faults.interrupt_masked.load(Ordering::Acquire),
        ) {
            unsafe { crate::fault::set_fault_interrupt_enabled(self.reg_base, enable) };
            Ok(())
        } else {
            // Overflow/detail loss destroys source identity. Its mask is sticky
            // for the unit lifetime; re-enabling would recreate an IRQ storm
            // before full containment can be proven.
            Err(IommuError::PermissionDenied)
        };
        self.pending_faults.release_capture();
        result
    }

    // ========================================================================
    // Register Access
    // ========================================================================

    #[inline]
    unsafe fn read_reg32(base: u64, offset: usize) -> u32 {
        read_volatile((base + offset as u64) as *const u32)
    }

    #[inline]
    unsafe fn read_reg64(base: u64, offset: usize) -> u64 {
        read_volatile((base + offset as u64) as *const u64)
    }

    #[inline]
    unsafe fn write_reg32(base: u64, offset: usize, value: u32) {
        write_volatile((base + offset as u64) as *mut u32, value);
    }

    #[inline]
    unsafe fn write_reg64(base: u64, offset: usize, value: u64) {
        write_volatile((base + offset as u64) as *mut u64, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fault(source_id: u16) -> (FaultRecord, u64, u64) {
        let lo = 0x4000;
        let hi = (1u64 << 63) | u64::from(source_id) | (5u64 << 52);
        (
            FaultRecord::from_raw(lo, hi).expect("valid test FRCD"),
            lo,
            hi,
        )
    }

    #[test]
    fn rf180_attach_invalidation_faults_never_commit_live() {
        assert_eq!(
            attach_completion_state(false, true),
            AttachmentState::Poisoned(ContextDisposition::PresentOrUnknown)
        );
        assert_eq!(
            attach_completion_state(true, false),
            AttachmentState::Poisoned(ContextDisposition::PresentOrUnknown)
        );
        assert_eq!(
            attach_completion_state(false, false),
            AttachmentState::Poisoned(ContextDisposition::PresentOrUnknown)
        );
        assert_eq!(attach_completion_state(true, true), AttachmentState::Live);
    }

    #[test]
    fn rf180_detach_retry_preserves_cleared_ownership() {
        assert_eq!(
            detach_completion_state(false, true),
            Some(AttachmentState::Poisoned(
                ContextDisposition::ClearedNeedsFlush
            ))
        );
        let retry = begin_detach_state(AttachmentState::Poisoned(
            ContextDisposition::ClearedNeedsFlush,
        ));
        assert_eq!(retry, Some((AttachmentState::DetachingCleared, true)));
        assert_eq!(detach_completion_state(true, true), None);
    }

    #[test]
    fn rf180_only_stable_or_poisoned_records_can_begin_detach() {
        assert_eq!(
            begin_detach_state(AttachmentState::Live),
            Some((AttachmentState::DetachingPresent, false))
        );
        assert_eq!(begin_detach_state(AttachmentState::Preparing), None);
        assert_eq!(begin_detach_state(AttachmentState::DetachingPresent), None);
        assert_eq!(begin_detach_state(AttachmentState::DetachingCleared), None);
        assert_eq!(
            begin_detach_state(AttachmentState::FaultQuarantined),
            Some((AttachmentState::DetachingCleared, true))
        );
    }

    #[test]
    fn rf180_all_transitional_records_participate_in_domain_scans() {
        let domain_id = 9;
        let records = [
            AttachmentRecord {
                domain_id,
                domain: None,
                state: AttachmentState::Preparing,
            },
            AttachmentRecord {
                domain_id,
                domain: None,
                state: AttachmentState::DetachingPresent,
            },
            AttachmentRecord {
                domain_id,
                domain: None,
                state: AttachmentState::Poisoned(ContextDisposition::ClearedNeedsFlush),
            },
        ];
        assert!(attachment_records_have_domain(records.iter(), domain_id));
        assert!(!attachment_records_have_domain(
            records.iter(),
            domain_id + 1
        ));
    }

    #[test]
    fn rf180_qi_tail_wraps_at_the_owned_queue_extent() {
        assert_eq!(qi_descriptor_index(0), Some(0));
        assert_eq!(qi_descriptor_index(4080), Some(QI_QUEUE_ENTRIES - 1));
        assert_eq!(qi_next_tail(4080), Some(0));
        assert_eq!(qi_next_tail(1), None);
        assert_eq!(qi_next_tail(QI_QUEUE_BYTES as u16), None);
    }

    #[test]
    fn rf180_qi_completion_requires_an_exact_legal_head() {
        assert_eq!(qi_decode_pointer(0x20), Some(0x20));
        assert_eq!(qi_decode_pointer(0x1000), None);
        assert!(qi_poll_head_exact(0x20, || 0x20));
        assert!(!qi_poll_head_exact(0x20, || 0x30));
        // A larger architectural pointer must not be truncated into a false
        // match for this 4 KiB queue.
        assert!(!qi_poll_head_exact(0, || 0x1000));
    }

    #[test]
    fn rf180_qi_timeout_sets_sticky_poison() {
        let poisoned = AtomicBool::new(false);
        assert_eq!(
            qi_complete_or_poison(&poisoned, false),
            Err(IommuError::HardwareInitFailed)
        );
        assert!(poisoned.load(Ordering::Acquire));
        assert_eq!(qi_complete_or_poison(&poisoned, true), Ok(()));
        assert!(poisoned.load(Ordering::Acquire));
    }

    #[test]
    fn rf180_repeated_fault_sid_coalesces_without_losing_pending_ownership() {
        let queue = PendingFaultQueue::new();
        let (record, lo, hi) = test_fault(0x4321);
        assert!(queue.publish(record, lo, hi));
        assert!(queue.publish(record, lo + 0x1000, hi));
        queue.begin_drain();
        let mut seen = 0usize;
        let completed = queue.drain_with(4, |source_id, detail| {
            assert_eq!(source_id, 0x4321);
            assert_eq!(detail.expect("retained detail").source_id, source_id);
            seen += 1;
            true
        });
        queue.release_drain();
        assert_eq!(completed, 1);
        assert_eq!(seen, 1);
        assert!(!queue.has_work());
    }

    #[test]
    fn rf180_capture_and_drain_share_one_nonblocking_pipeline_owner() {
        let queue = PendingFaultQueue::new();
        assert!(queue.try_claim_capture());
        assert!(!queue.try_claim_drain());
        queue.release_capture();

        assert!(queue.try_claim_drain());
        assert!(!queue.try_claim_capture());
        queue.release_drain();
        assert!(queue.try_claim_capture());
        queue.release_capture();
    }

    #[test]
    fn rf180_capture_contention_rearms_level_triggered_recapture() {
        let queue = PendingFaultQueue::new();
        assert!(queue.try_claim_drain());
        queue.request_recapture();
        queue.release_drain();
        assert!(queue.has_work());

        assert!(queue.try_claim_capture());
        queue.begin_capture();
        queue.release_capture();
        // The soft progress callback performs capture then drain. The drain's
        // clear-first level handoff consumes the recapture-only wake only after
        // the capture owner has had a chance to inspect hardware.
        assert!(queue.try_claim_drain());
        queue.begin_drain();
        queue.release_drain();
        assert!(!queue.has_work());
    }

    #[test]
    fn rf180_failed_fault_consumer_retries_without_republication() {
        let queue = PendingFaultQueue::new();
        let (record, lo, hi) = test_fault(9);
        assert!(queue.publish(record, lo, hi));

        queue.begin_drain();
        assert_eq!(queue.drain_with(1, |_, _| false), 0);
        queue.release_drain();
        assert!(queue.has_work());

        queue.begin_drain();
        assert_eq!(queue.drain_with(1, |source_id, _| source_id == 9), 1);
        queue.release_drain();
        assert!(!queue.has_work());
    }

    #[test]
    fn rf180_fault_drain_cursor_prevents_same_word_republication_starvation() {
        let queue = PendingFaultQueue::new();
        let (low, low_lo, low_hi) = test_fault(1);
        let (high, high_lo, high_hi) = test_fault(2);
        assert!(queue.publish(low, low_lo, low_hi));
        assert!(queue.publish(high, high_lo, high_hi));

        queue.begin_drain();
        assert_eq!(queue.drain_with(1, |source_id, _| source_id == 1), 1);
        queue.release_drain();

        assert!(queue.publish(low, low_lo, low_hi));
        let mut second = None;
        queue.begin_drain();
        assert_eq!(
            queue.drain_with(1, |source_id, _| {
                second = Some(source_id);
                true
            }),
            1
        );
        queue.release_drain();
        assert_eq!(second, Some(2));
    }

    #[test]
    fn rf180_failed_lower_sid_retry_does_not_starve_same_word_peer() {
        let queue = PendingFaultQueue::new();
        let (low, low_lo, low_hi) = test_fault(1);
        let (high, high_lo, high_hi) = test_fault(2);
        assert!(queue.publish(low, low_lo, low_hi));
        assert!(queue.publish(high, high_lo, high_hi));

        queue.begin_drain();
        assert_eq!(queue.drain_with(1, |source_id, _| source_id != 1), 0);
        queue.release_drain();

        let mut second = None;
        queue.begin_drain();
        assert_eq!(
            queue.drain_with(1, |source_id, _| {
                second = Some(source_id);
                true
            }),
            1
        );
        queue.release_drain();
        assert_eq!(second, Some(2));

        queue.begin_drain();
        assert_eq!(queue.drain_with(1, |source_id, _| source_id == 1), 1);
        queue.release_drain();
        assert!(!queue.has_work());
    }

    #[test]
    fn rf180_detail_exhaustion_escalates_to_unit_overflow_quarantine() {
        let queue = PendingFaultQueue::new();
        for source_id in 0..FAULT_DETAIL_SLOTS as u16 {
            let (record, lo, hi) = test_fault(source_id);
            assert!(queue.publish(record, lo, hi));
        }
        let source_id = FAULT_DETAIL_SLOTS as u16;
        let (record, lo, hi) = test_fault(source_id);
        assert!(
            !queue.publish(record, lo, hi),
            "detail loss must prevent FRCD W1C and force capture masking"
        );
        assert!(queue.take_overflow());
        assert!(queue.has_pending_sources());
    }

    #[test]
    fn rf180_incomplete_registry_never_skips_global_retirement() {
        assert_eq!(
            iotlb_retirement_scope(false, false),
            IotlbRetirementScope::Global
        );
        assert_eq!(
            iotlb_retirement_scope(false, true),
            IotlbRetirementScope::Global
        );
        assert_eq!(
            iotlb_retirement_scope(true, false),
            IotlbRetirementScope::Skip
        );
        assert_eq!(
            iotlb_retirement_scope(true, true),
            IotlbRetirementScope::Domain
        );
    }

    #[test]
    fn rf180_translation_disable_state_machine_is_fail_closed() {
        assert_eq!(
            translation_disable_action(true, true, true, false, false),
            TranslationDisableAction::AlreadyDisabled
        );
        assert_eq!(
            translation_disable_action(true, true, true, true, true),
            TranslationDisableAction::ClearTe
        );
        for rejected in [
            translation_disable_action(false, true, true, true, true),
            translation_disable_action(true, false, true, true, true),
            translation_disable_action(true, true, false, true, true),
            translation_disable_action(true, true, true, true, false),
            translation_disable_action(true, true, true, false, true),
        ] {
            assert_eq!(rejected, TranslationDisableAction::Reject);
        }
    }

    #[test]
    fn rf180_translation_enable_rejects_software_hardware_divergence() {
        assert_eq!(
            translation_enable_action(false, false),
            TranslationEnableAction::SetTe
        );
        assert_eq!(
            translation_enable_action(true, true),
            TranslationEnableAction::AlreadyEnabled
        );
        assert_eq!(
            translation_enable_action(false, true),
            TranslationEnableAction::Reject
        );
        assert_eq!(
            translation_enable_action(true, false),
            TranslationEnableAction::Reject
        );
    }

    #[test]
    fn rf180_context_table_pointer_rejects_null_and_out_of_window() {
        assert!(!valid_context_table_phys(0));
        assert!(valid_context_table_phys(0x1000));
        assert!(!valid_context_table_phys(MAX_DIRECT_MAP_PHYS));
        assert!(!valid_context_table_phys(u64::MAX - 0xfff));
    }

    #[test]
    fn rf180_sticky_fault_mask_cannot_be_reenabled() {
        assert!(fault_interrupt_update_allowed(true, false));
        assert!(fault_interrupt_update_allowed(false, false));
        assert!(fault_interrupt_update_allowed(false, true));
        assert!(!fault_interrupt_update_allowed(true, true));
    }
}
