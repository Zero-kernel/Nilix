//! VT-d Fault Handling and Recovery for Zero-OS
//!
//! This module provides IOMMU fault detection, logging, and device isolation
//! capabilities. DMA faults indicate potential security issues such as:
//! - Misconfigured device drivers
//! - Malicious devices attempting to access unauthorized memory
//! - Translation table corruption
//!
//! # Architecture
//!
//! ```text
//! +------------------+
//! |   DMA Request    |
//! +--------+---------+
//!          |
//!          v
//! +------------------+     Fault
//! |   VT-d IOMMU     |------------+
//! | (Translation)    |            |
//! +--------+---------+            |
//!          |                      v
//!          | Success     +------------------+
//!          v             | Fault Recording  |
//! +------------------+   | Registers (FRCD) |
//! | Physical Memory  |   +------------------+
//! +------------------+            |
//!                                 v
//!                        +------------------+
//!                        | Fault Handler    |
//!                        | - Log to audit   |
//!                        | - Isolate device |
//!                        +------------------+
//! ```
//!
//! # Security Model
//!
//! - **Audit logging**: All faults are logged with device ID, domain, address
//! - **Device isolation**: Option to disable bus mastering on faulting device
//! - **Bounded processing**: Complete CAP.NFR scan, bounded to 256 records
//! - **Fail-closed**: Faults default to audit + warn, optionally isolate
//!
//! # References
//!
//! - Intel VT-d Specification, Chapter 7 (Fault Logging)
//! - Intel VT-d Specification, Section 10.4.7 (Fault Recording Registers)

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Architectural maximum number of primary fault-recording registers.
/// CAP.NFR is an eight-bit zero-based count, so a complete bounded scan is at
/// most 256 entries. Scanning the complete hardware-owned set avoids clearing
/// PPF while an unvisited record still contains the sole durable source ID.
pub const MAX_FAULT_RECORDS: usize = 256;

/// Fault Recording entry size (128 bits = 16 bytes).
const FRCD_ENTRY_SIZE: usize = 16;

/// Fault-record valid / W1C bit in the high 64-bit word.
const FRCD_FAULT_VALID: u64 = 1 << 63;

/// Fault Status Register - Primary Fault Overflow (PFO) bit.
const FSTS_PFO: u32 = 1 << 0;

/// Fault Status Register - Primary Pending Fault (PPF) bit.
const FSTS_PPF: u32 = 1 << 1;

/// Fault Status Register - Fault Record Index mask (bits 15:8).
const FSTS_FRI_MASK: u32 = 0xFF << 8;
const FSTS_FRI_SHIFT: u32 = 8;

/// Fault Event Control Register - Interrupt Mask (IM) bit.
const FECTL_IM: u32 = 1 << 31;

// ============================================================================
// Fault Record Structure
// ============================================================================

/// VT-d fault reason codes.
///
/// These correspond to the FR (Fault Reason) field in fault recording registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultReason {
    /// Reserved or unknown fault code.
    Reserved,
    /// Root table entry not present.
    RootEntryNotPresent,
    /// Context entry not present.
    ContextEntryNotPresent,
    /// Context entry invalid.
    ContextEntryInvalid,
    /// Address beyond MGAW (Maximum Guest Address Width).
    AddressBeyondMgaw,
    /// Write request to read-only page.
    WriteToReadOnly,
    /// Read request to no-read page.
    ReadNotPermitted,
    /// Page table entry invalid.
    PageEntryInvalid,
    /// Root table entry reserved bit set.
    RootEntryReserved,
    /// Context entry reserved bit set.
    ContextEntryReserved,
    /// Page table entry reserved bit set.
    PageEntryReserved,
    /// Invalid translation type.
    InvalidTranslationType,
    /// Unknown fault reason.
    Unknown(u8),
}

impl FaultReason {
    /// Decode fault reason from hardware code.
    pub fn from_code(code: u8) -> Self {
        match code {
            0x0 => Self::Reserved,
            0x1 => Self::RootEntryNotPresent,
            0x2 => Self::ContextEntryNotPresent,
            0x3 => Self::ContextEntryInvalid,
            0x4 => Self::AddressBeyondMgaw,
            0x5 => Self::WriteToReadOnly,
            0x6 => Self::ReadNotPermitted,
            0x7 => Self::PageEntryInvalid,
            0x8 => Self::RootEntryReserved,
            0x9 => Self::ContextEntryReserved,
            0xA => Self::PageEntryReserved,
            0xB => Self::InvalidTranslationType,
            other => Self::Unknown(other),
        }
    }

    /// Check if this fault indicates a potential security issue.
    pub fn is_security_relevant(&self) -> bool {
        matches!(
            self,
            Self::WriteToReadOnly
                | Self::ReadNotPermitted
                | Self::AddressBeyondMgaw
                | Self::InvalidTranslationType
        )
    }
}

/// Fault type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultType {
    /// Primary (DMA) fault.
    Primary,
    /// Page request fault (ATS).
    PageRequest,
    /// Interrupt remapping fault.
    InterruptRemap,
    /// Unknown fault type.
    Unknown(u8),
}

impl FaultType {
    /// Decode fault type from hardware code.
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Primary,
            1 => Self::PageRequest,
            2 => Self::InterruptRemap,
            other => Self::Unknown(other),
        }
    }
}

/// Parsed VT-d fault record.
///
/// Contains all relevant information extracted from a fault recording register.
#[derive(Debug, Clone, Copy)]
pub struct FaultRecord {
    /// PCI Source ID (bus << 8 | device << 3 | function).
    pub source_id: u16,
    /// Domain ID associated with the fault.
    pub domain_id: u16,
    /// Fault reason code.
    pub fault_reason: FaultReason,
    /// Faulting address (page-aligned).
    pub fault_address: u64,
    /// Fault type (Primary, PageRequest, InterruptRemap).
    pub fault_type: FaultType,
    /// Whether this was a read (false) or write (true) request.
    pub is_write: bool,
    /// Whether the request was an execute request.
    pub is_execute: bool,
    /// Pasid present (for scalable mode).
    pub pasid_present: bool,
    /// PASID value (if present).
    pub pasid: u32,
}

impl FaultRecord {
    /// Decode one architecturally valid FRCD entry. The caller must retain the
    /// raw words until any required durable publication is complete; clearing
    /// the hardware F bit before publication loses the only source identity.
    pub fn from_raw(lo: u64, hi: u64) -> Option<Self> {
        if hi & FRCD_FAULT_VALID == 0 {
            return None;
        }
        let source_id = (hi & 0xFFFF) as u16;
        let is_execute = (hi >> 23) & 1 != 0;
        let pasid_present = (hi >> 24) & 1 != 0;
        let fault_type_bits = ((hi >> 28) & 0x3) | (((hi >> 21) & 1) << 2);
        let pasid = ((hi >> 32) & 0xFFFFF) as u32;
        let fault_reason = FaultReason::from_code(((hi >> 52) & 0xFF) as u8);
        Some(Self {
            source_id,
            domain_id: 0,
            fault_reason,
            fault_address: lo & !0xFFF,
            fault_type: FaultType::from_code(fault_type_bits as u8),
            is_write: matches!(fault_reason, FaultReason::WriteToReadOnly),
            is_execute,
            pasid_present,
            pasid,
        })
    }

    /// Get the PCI bus number from source ID.
    #[inline]
    pub fn bus(&self) -> u8 {
        (self.source_id >> 8) as u8
    }

    /// Get the PCI device number from source ID.
    #[inline]
    pub fn device(&self) -> u8 {
        ((self.source_id >> 3) & 0x1F) as u8
    }

    /// Get the PCI function number from source ID.
    #[inline]
    pub fn function(&self) -> u8 {
        (self.source_id & 0x7) as u8
    }

    /// Format as BDF string for logging.
    pub fn bdf_string(&self) -> ([u8; 10], usize) {
        let mut buf = [0u8; 10];
        let bus = self.bus();
        let device_num = self.device();
        let func = self.function();

        buf[0] = hex_char((bus >> 4) & 0xF);
        buf[1] = hex_char(bus & 0xF);
        buf[2] = b':';
        buf[3] = hex_char((device_num >> 4) & 0xF);
        buf[4] = hex_char(device_num & 0xF);
        buf[5] = b'.';
        buf[6] = hex_char(func & 0xF);

        (buf, 7)
    }
}

/// Convert nibble to hex character.
fn hex_char(n: u8) -> u8 {
    if n < 10 {
        b'0' + n
    } else {
        b'a' + (n - 10)
    }
}

// ============================================================================
// Fault Handler Implementation
// ============================================================================

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FaultCaptureSummary {
    pub captured: usize,
    pub overflow: bool,
    pub incomplete: bool,
}

/// Backend seam used by the IRQ capture path and deterministic hosted tests.
/// Implementations must preserve program order for MMIO reads/W1C writes.
pub(crate) trait FaultRegisterBackend {
    fn read_status(&mut self) -> u32;
    /// Return one stable record snapshot. MMIO implementations must inspect the
    /// high word first: hardware publishes the F bit last and retains the entry
    /// until software clears it, so reading the low word first can pair stale
    /// address bits with a newly-arrived high word.
    fn read_record(&mut self, index: usize) -> Option<(u64, u64)>;
    fn clear_record(&mut self, index: usize);
    fn clear_status(&mut self, mask: u32);
    fn mask_interrupts(&mut self);
}

struct MmioFaultBackend {
    reg_base: u64,
    fault_offset: usize,
}

impl MmioFaultBackend {
    fn record_base(&self, index: usize) -> Option<u64> {
        self.reg_base
            .checked_add(self.fault_offset as u64)
            .and_then(|base| {
                index
                    .checked_mul(FRCD_ENTRY_SIZE)
                    .and_then(|offset| base.checked_add(offset as u64))
            })
    }
}

impl FaultRegisterBackend for MmioFaultBackend {
    fn read_status(&mut self) -> u32 {
        unsafe { read_volatile((self.reg_base + 0x34) as *const u32) }
    }

    fn read_record(&mut self, index: usize) -> Option<(u64, u64)> {
        let base = self.record_base(index)?;
        let hi = unsafe { read_volatile((base + 8) as *const u64) };
        if hi & FRCD_FAULT_VALID == 0 {
            return Some((0, hi));
        }

        // Once F is observed, hardware owns an immutable record until the W1C.
        // Re-reading the high word rejects a malformed/torn aperture rather
        // than acknowledging a source ID paired with the wrong address.
        let lo = unsafe { read_volatile(base as *const u64) };
        let verify_hi = unsafe { read_volatile((base + 8) as *const u64) };
        if verify_hi != hi {
            return None;
        }
        Some((lo, hi))
    }

    fn clear_record(&mut self, index: usize) {
        if let Some(base) = self.record_base(index) {
            unsafe { write_volatile((base + 8) as *mut u64, FRCD_FAULT_VALID) };
        }
    }

    fn clear_status(&mut self, mask: u32) {
        if mask != 0 {
            unsafe { write_volatile((self.reg_base + 0x34) as *mut u32, mask) };
        }
    }

    fn mask_interrupts(&mut self) {
        unsafe { set_fault_interrupt_enabled(self.reg_base, false) };
    }
}

/// Capture bounded FRCD state without allocation or locks. Every accepted
/// source/detail publication happens before the corresponding FRCD F-bit W1C,
/// and FSTS is acknowledged only after all records selected by this pass have
/// either been durably published or the unit has been interrupt-masked.
pub(crate) fn capture_fault_records_with_backend<B, P, O>(
    backend: &mut B,
    num_fault_regs: usize,
    mut publish: P,
    mut publish_overflow: O,
) -> FaultCaptureSummary
where
    B: FaultRegisterBackend,
    P: FnMut(FaultRecord, u64, u64) -> bool,
    O: FnMut(),
{
    let status = backend.read_status();
    let status_overflow = status & FSTS_PFO != 0;
    let pending = status & FSTS_PPF != 0;
    if !status_overflow && !pending {
        return FaultCaptureSummary::default();
    }
    if num_fault_regs == 0 {
        publish_overflow();
        backend.mask_interrupts();
        return FaultCaptureSummary {
            captured: 0,
            overflow: true,
            incomplete: true,
        };
    }

    let mut summary = FaultCaptureSummary {
        captured: 0,
        overflow: status_overflow || num_fault_regs > MAX_FAULT_RECORDS,
        incomplete: num_fault_regs > MAX_FAULT_RECORDS,
    };
    let mut interrupts_masked = false;
    // Publish the sticky software quarantine before any record/status W1C.
    // A PFO means source identities have already been lost in hardware.
    if summary.overflow {
        publish_overflow();
        // Make the software quarantine globally visible before suppressing the
        // hardware interrupt/status evidence.
        fence(Ordering::SeqCst);
        backend.mask_interrupts();
        interrupts_masked = true;
    }
    let mut index = ((status & FSTS_FRI_MASK) >> FSTS_FRI_SHIFT) as usize % num_fault_regs;
    let scan_count = num_fault_regs.min(MAX_FAULT_RECORDS);
    for _ in 0..scan_count {
        let Some((lo, hi)) = backend.read_record(index) else {
            summary.overflow = true;
            summary.incomplete = true;
            publish_overflow();
            break;
        };
        if let Some(record) = FaultRecord::from_raw(lo, hi) {
            if !publish(record, lo, hi) {
                summary.overflow = true;
                summary.incomplete = true;
                publish_overflow();
                break;
            }
            // Publication is Release-ordered by the pending queue. Only now is
            // it safe to destroy the sole hardware copy of SID/details.
            fence(Ordering::SeqCst);
            backend.clear_record(index);
            summary.captured += 1;
        }
        index = (index + 1) % num_fault_regs;
    }

    if (summary.overflow || summary.incomplete) && !interrupts_masked {
        publish_overflow();
        fence(Ordering::SeqCst);
        backend.mask_interrupts();
    }

    // PPF and FRI are read-only, derived from the FRCD array; clearing each F
    // bit above retires them. PFO is the only writable primary-fault status bit
    // and may be acknowledged only after sticky software overflow publication.
    let clear_mask = status & FSTS_PFO;
    if clear_mask != 0 {
        // Pair the queue's Release publications with a full store/MMIO barrier
        // before any FSTS W1C can erase the hardware-side evidence.
        fence(Ordering::SeqCst);
        backend.clear_status(clear_mask);
    }
    summary
}

/// MMIO entry for [`capture_fault_records_with_backend`].
///
/// # Safety
/// `reg_base`, `fault_offset`, and the CAP-derived register count must describe
/// one mapped VT-d register aperture that remains valid for the call.
pub(crate) unsafe fn capture_fault_records_mmio<P, O>(
    reg_base: u64,
    fault_offset: usize,
    num_fault_regs: usize,
    publish: P,
    publish_overflow: O,
) -> FaultCaptureSummary
where
    P: FnMut(FaultRecord, u64, u64) -> bool,
    O: FnMut(),
{
    let mut backend = MmioFaultBackend {
        reg_base,
        fault_offset,
    };
    capture_fault_records_with_backend(&mut backend, num_fault_regs, publish, publish_overflow)
}

/// Fault handler configuration.
#[derive(Debug, Clone, Copy)]
pub struct FaultConfig {
    /// Whether to isolate (disable bus mastering) faulting devices.
    pub isolate_devices: bool,
    /// Whether to log faults to audit subsystem.
    pub audit_logging: bool,
    /// Whether to print faults to console.
    pub console_logging: bool,
}

impl Default for FaultConfig {
    fn default() -> Self {
        Self {
            isolate_devices: false,
            audit_logging: true,
            console_logging: true,
        }
    }
}

/// Enable or disable fault event interrupts.
///
/// # Arguments
///
/// * `reg_base` - VT-d register base address
/// * `enable` - true to enable interrupts, false to disable
///
/// # Safety
///
/// Caller must ensure `reg_base` is a valid MMIO address.
pub(crate) unsafe fn set_fault_interrupt_enabled(reg_base: u64, enable: bool) {
    const VTD_REG_FECTL: usize = 0x38;

    let mut ctl = read_volatile((reg_base + VTD_REG_FECTL as u64) as *const u32);

    if enable {
        ctl &= !FECTL_IM; // Clear interrupt mask
    } else {
        ctl |= FECTL_IM; // Set interrupt mask
    }

    write_volatile((reg_base + VTD_REG_FECTL as u64) as *mut u32, ctl);
}

/// Log a fault record to the kernel console.
pub fn log_fault_to_console(record: &FaultRecord, unit_index: usize) {
    let (bdf, _len) = record.bdf_string();
    let bdf_str = core::str::from_utf8(&bdf[..7]).unwrap_or("??:??.?");

    kprintln!(
        "[IOMMU] Unit {}: DMA fault from {} addr={:#x} reason={:?} type={:?}{}{}",
        unit_index,
        bdf_str,
        record.fault_address,
        record.fault_reason,
        record.fault_type,
        if record.is_write { " [W]" } else { " [R]" },
        if record.fault_reason.is_security_relevant() {
            " [SECURITY]"
        } else {
            ""
        }
    );
}

/// Log a fault record to the audit subsystem.
#[cfg(feature = "audit")]
pub fn log_fault_to_audit(record: &FaultRecord, unit_index: usize) {
    use audit::{emit_security_event, AuditEventType, AuditSecurityClass};

    emit_security_event(
        AuditEventType::IommuFault,
        AuditSecurityClass::DmaViolation,
        record.source_id as u64,
        record.fault_address,
        unit_index as u64,
    );
}

#[cfg(not(feature = "audit"))]
pub fn log_fault_to_audit(_record: &FaultRecord, _unit_index: usize) {
    // Audit disabled at compile time
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use alloc::vec;
    use core::cell::RefCell;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Published(u16),
        OverflowPublished,
        RecordCleared(usize),
        InterruptMasked,
        StatusCleared(u32),
    }

    struct FakeBackend {
        status: u32,
        records: alloc::vec::Vec<(u64, u64)>,
        events: Rc<RefCell<alloc::vec::Vec<Event>>>,
    }

    impl FaultRegisterBackend for FakeBackend {
        fn read_status(&mut self) -> u32 {
            self.status
        }

        fn read_record(&mut self, index: usize) -> Option<(u64, u64)> {
            self.records.get(index).copied()
        }

        fn clear_record(&mut self, index: usize) {
            self.events.borrow_mut().push(Event::RecordCleared(index));
        }

        fn clear_status(&mut self, mask: u32) {
            self.events.borrow_mut().push(Event::StatusCleared(mask));
        }

        fn mask_interrupts(&mut self) {
            self.events.borrow_mut().push(Event::InterruptMasked);
        }
    }

    fn raw_fault(source_id: u16) -> (u64, u64) {
        (
            0x1234_5000,
            (1u64 << 63) | u64::from(source_id) | (5u64 << 52),
        )
    }

    #[test]
    fn test_fault_reason_decode() {
        assert_eq!(
            FaultReason::from_code(0x1),
            FaultReason::RootEntryNotPresent
        );
        assert_eq!(FaultReason::from_code(0x5), FaultReason::WriteToReadOnly);
        assert!(matches!(
            FaultReason::from_code(0xFF),
            FaultReason::Unknown(0xFF)
        ));
    }

    #[test]
    fn test_fault_record_bdf() {
        let record = FaultRecord {
            source_id: 0x1234, // bus=0x12, dev=0x06, func=0x4
            domain_id: 0,
            fault_reason: FaultReason::WriteToReadOnly,
            fault_address: 0x1000,
            fault_type: FaultType::Primary,
            is_write: true,
            is_execute: false,
            pasid_present: false,
            pasid: 0,
        };

        assert_eq!(record.bus(), 0x12);
        assert_eq!(record.device(), 0x06);
        assert_eq!(record.function(), 0x04);
    }

    #[test]
    fn test_security_relevant() {
        assert!(FaultReason::WriteToReadOnly.is_security_relevant());
        assert!(FaultReason::AddressBeyondMgaw.is_security_relevant());
        assert!(!FaultReason::RootEntryNotPresent.is_security_relevant());
    }

    #[test]
    fn rf180_fault_publication_precedes_record_w1c() {
        let events = Rc::new(RefCell::new(alloc::vec::Vec::new()));
        let mut backend = FakeBackend {
            status: FSTS_PPF,
            records: vec![raw_fault(0x1234)],
            events: Rc::clone(&events),
        };
        let publish_events = Rc::clone(&events);
        let overflow_events = Rc::clone(&events);
        let summary = capture_fault_records_with_backend(
            &mut backend,
            1,
            move |record, _, _| {
                publish_events
                    .borrow_mut()
                    .push(Event::Published(record.source_id));
                true
            },
            move || {
                overflow_events.borrow_mut().push(Event::OverflowPublished);
            },
        );
        assert_eq!(summary.captured, 1);
        let events = events.borrow();
        let published = events
            .iter()
            .position(|event| *event == Event::Published(0x1234))
            .expect("publication event");
        let cleared = events
            .iter()
            .position(|event| *event == Event::RecordCleared(0))
            .expect("record W1C event");
        assert!(published < cleared);
    }

    #[test]
    fn rf180_overflow_is_published_and_masked_before_status_w1c() {
        let events = Rc::new(RefCell::new(alloc::vec::Vec::new()));
        let mut backend = FakeBackend {
            status: FSTS_PFO | FSTS_PPF,
            records: vec![raw_fault(7)],
            events: Rc::clone(&events),
        };
        let overflow_events = Rc::clone(&events);
        let summary = capture_fault_records_with_backend(
            &mut backend,
            1,
            |_, _, _| true,
            move || {
                overflow_events.borrow_mut().push(Event::OverflowPublished);
            },
        );
        assert!(summary.overflow);
        let events = events.borrow();
        let published = events
            .iter()
            .position(|event| *event == Event::OverflowPublished)
            .expect("overflow publication");
        let masked = events
            .iter()
            .position(|event| *event == Event::InterruptMasked)
            .expect("interrupt mask");
        let status_cleared = events
            .iter()
            .position(|event| matches!(event, Event::StatusCleared(_)))
            .expect("status W1C");
        assert!(published < masked);
        assert!(masked < status_cleared);
    }

    #[test]
    fn rf180_rejected_publication_retains_frcd_and_masks_capture() {
        let events = Rc::new(RefCell::new(alloc::vec::Vec::new()));
        let mut backend = FakeBackend {
            status: FSTS_PPF,
            records: vec![raw_fault(0x55aa)],
            events: Rc::clone(&events),
        };
        let overflow_events = Rc::clone(&events);
        let summary = capture_fault_records_with_backend(
            &mut backend,
            1,
            |_, _, _| false,
            move || {
                overflow_events.borrow_mut().push(Event::OverflowPublished);
            },
        );
        assert!(summary.overflow);
        assert!(summary.incomplete);
        assert_eq!(summary.captured, 0);

        let events = events.borrow();
        assert!(events.contains(&Event::OverflowPublished));
        assert!(events.contains(&Event::InterruptMasked));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::RecordCleared(_))),
            "failed publication must retain the sole hardware record"
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::StatusCleared(_))),
            "PPF/FRI evidence must survive an incomplete scan"
        );
    }
}
