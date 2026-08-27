//! ACPI DMAR (DMA Remapping) Table Parser
//!
//! Parses the DMAR table from ACPI to discover IOMMU hardware units and their
//! associated device scopes.
//!
//! # DMAR Table Structure
//!
//! The DMAR table contains:
//! - Header (standard ACPI header + host address width + flags)
//! - Remapping structures:
//!   - DRHD (DMA Remapping Hardware Unit Definition)
//!   - RMRR (Reserved Memory Region Reporting)
//!   - ATSR (ACPI Namespace Device Declaration)
//!   - RHSA (Remapping Hardware Status Affinity)
//!
//! # References
//!
//! - Intel VT-d Specification, Chapter 8 (BIOS Considerations)
//! - ACPI Specification, Section 8 (DMAR)

use core::ptr;
use mm::{AdmittedVec, HeapClass, PHYSICAL_MEMORY_OFFSET};

use crate::MAX_IOMMU_UNITS;

// ============================================================================
// Constants
// ============================================================================

/// DMAR table signature ("DMAR").
const DMAR_SIGNATURE: [u8; 4] = *b"DMAR";

/// R171-G5-01-B FIX: the kernel high-half direct map covers only physical
/// `[0, 1 GiB)` (mm `HIGH_HALF_MAP_LIMIT`). Any ACPI table physical address whose
/// `[phys, phys+len)` is not fully inside this window cannot be read through the
/// direct map and MUST fail CLOSED (`InvalidStructure`), never be silently treated
/// as "no DMAR" (`NotFound`). Mirrors `vtd.rs` MAX_DIRECT_MAP_PHYS; do NOT use the
/// (latently-wrong) 4 GiB `smp::MAX_PHYS_MAPPED`.
const MAX_DIRECT_MAP_PHYS: u64 = 1 << 30;

/// Legacy BIOS RSDP scan window (used only when the bootloader provides no RSDP).
const RSDP_SEARCH_START: u64 = 0xE_0000;
const RSDP_SEARCH_END: u64 = 0x10_0000;

/// ACPI permits later RSDP revisions to extend the 36-byte v2 structure. Bound
/// firmware-controlled checksum work while retaining ample forward-compatibility.
const MAX_RSDP_BYTES: usize = 4096;

/// Bound checksum work and root-entry traversal before following any RSDT/XSDT
/// child pointer. Real systems are orders of magnitude smaller than 1 MiB.
const MAX_ACPI_ROOT_TABLE_BYTES: usize = 1024 * 1024;
const MAX_ACPI_ROOT_TABLE_ENTRIES: usize =
    (MAX_ACPI_ROOT_TABLE_BYTES - core::mem::size_of::<AcpiHeader>()) / 4;

/// DRHD structure type.
const DMAR_TYPE_DRHD: u16 = 0;

/// RMRR structure type.
const DMAR_TYPE_RMRR: u16 = 1;

/// ATSR structure type.
const DMAR_TYPE_ATSR: u16 = 2;

/// RHSA structure type.
const DMAR_TYPE_RHSA: u16 = 3;

/// ANDD structure type (ACPI Namespace Device Declaration).
const DMAR_TYPE_ANDD: u16 = 4;

/// SATC structure type (SoC Integrated Address Translation Cache Reporting).
const DMAR_TYPE_SATC: u16 = 5;

/// SIDP structure type (SoC Integrated Device Property Reporting).
const DMAR_TYPE_SIDP: u16 = 6;

/// Device scope entry type: PCI Endpoint Device.
const DEVICE_SCOPE_PCI_ENDPOINT: u8 = 0x01;

/// Device scope entry type: PCI Sub-hierarchy (bridge).
const DEVICE_SCOPE_PCI_BRIDGE: u8 = 0x02;

/// Device scope entry type: IOAPIC.
const DEVICE_SCOPE_IOAPIC: u8 = 0x03;

/// Device scope entry type: MSI Capable HPET.
const DEVICE_SCOPE_HPET: u8 = 0x04;

/// Device scope entry type: ACPI Namespace Device.
const DEVICE_SCOPE_ACPI_NAMESPACE: u8 = 0x05;

// R180-28 FIX: ACPI is firmware-controlled input processed before the general
// heap has much slack. Bound both scan work and every dimension that can create
// parsed heap state before pass two performs any allocation.
const MAX_DMAR_TABLE_BYTES: usize = 64 * 1024;
const MAX_DMAR_STRUCTURES: usize = 256;
const MAX_DMAR_RMRR_ENTRIES: usize = 64;
const MAX_DEVICE_SCOPES_PER_STRUCTURE: usize = 256;
const MAX_TOTAL_DEVICE_SCOPES: usize = 4096;
const MAX_PATH_PAIRS_PER_SCOPE: usize = 64;
const MAX_TOTAL_PATH_PAIRS: usize = 8192;

/// The parsed table is transient during boot, but it competes with all other
/// heap users. Limit the complete allocator-rounded representation to 64 KiB
/// (one sixteenth of the kernel's 1 MiB heap).
const MAX_DMAR_PARSED_BYTES: usize = 64 * 1024;
/// Peak heap retained while materializing: immutable raw-table snapshot plus
/// the complete parsed representation.
const MAX_DMAR_PARSE_PEAK_BYTES: usize = 128 * 1024;

const _: () = assert!(MAX_DMAR_PARSED_BYTES > 0);
const _: () = assert!(MAX_DMAR_PARSE_PEAK_BYTES >= MAX_DMAR_PARSED_BYTES);

// ============================================================================
// Errors
// ============================================================================

/// DMAR parsing errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarError {
    /// DMAR table not found in ACPI.
    NotFound,
    /// Invalid DMAR table signature.
    InvalidSignature,
    /// Invalid DMAR table checksum.
    InvalidChecksum,
    /// Invalid DMAR table structure.
    InvalidStructure,
    /// Unsupported DMAR table version.
    UnsupportedVersion,
    /// A checksum-valid table exceeds a parser count, byte, or work limit.
    ResourceLimit,
    /// Exact reservation for the validated parsed representation failed.
    OutOfMemory,
}

// ============================================================================
// Raw Structures (packed for ACPI table parsing)
// ============================================================================

/// ACPI standard table header.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct AcpiHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

/// ACPI RSDP v1 structure (20 bytes; ACPI 1.0).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct RsdpV1 {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
}

/// ACPI RSDP v2 structure (36 bytes; ACPI 2.0+, supersedes v1 with XSDT).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct RsdpV2 {
    v1: RsdpV1,
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

/// DMAR table header (after ACPI header).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct DmarHeader {
    /// Host Address Width (number of bits - 1).
    host_address_width: u8,
    /// Flags.
    flags: u8,
    /// Reserved.
    reserved: [u8; 10],
}

/// DMAR remapping structure header.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct DmarStructureHeader {
    /// Structure type.
    structure_type: u16,
    /// Structure length.
    length: u16,
}

/// DRHD (DMA Remapping Hardware Unit Definition) structure.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct DrhdRaw {
    header: DmarStructureHeader,
    /// Flags (bit 0: INCLUDE_PCI_ALL).
    flags: u8,
    /// Reserved.
    reserved: u8,
    /// PCI segment number.
    segment: u16,
    /// Register base address.
    register_base: u64,
    // Followed by device scope entries
}

/// RMRR (Reserved Memory Region Reporting) structure.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct RmrrRaw {
    header: DmarStructureHeader,
    /// Reserved.
    reserved: u16,
    /// PCI segment number.
    segment: u16,
    /// Reserved memory region base address.
    base_address: u64,
    /// Reserved memory region limit address.
    limit_address: u64,
    // Followed by device scope entries
}

/// ATSR (Root Port ATS Capability Reporting) structure prefix.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct AtsrRaw {
    header: DmarStructureHeader,
    flags: u8,
    reserved: u8,
    segment: u16,
    // Followed by device scope entries
}

/// RHSA (Remapping Hardware Static Affinity) fixed structure.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct RhsaRaw {
    header: DmarStructureHeader,
    reserved: u32,
    register_base: u64,
    proximity_domain: u32,
}

/// ANDD (ACPI Namespace Device Declaration) fixed prefix.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct AnddRaw {
    header: DmarStructureHeader,
    reserved: [u8; 3],
    acpi_device_number: u8,
    // Followed by a NUL-terminated ACPI object name.
}

/// SATC fixed prefix; followed by device scope entries.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct SatcRaw {
    header: DmarStructureHeader,
    flags: u8,
    reserved: u8,
    segment: u16,
}

/// SIDP fixed prefix; followed by device scope entries.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct SidpRaw {
    header: DmarStructureHeader,
    reserved: u16,
    segment: u16,
}

/// Device scope entry.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct DeviceScopeRaw {
    /// Device scope type.
    scope_type: u8,
    /// Length of this entry.
    length: u8,
    /// Reserved.
    reserved: u16,
    /// Enumeration ID (for IOAPIC/HPET).
    enumeration_id: u8,
    /// Start bus number.
    start_bus: u8,
    // Followed by path entries (device:function pairs)
}

// ============================================================================
// Parsed Structures
// ============================================================================

/// Parsed DMAR table.
pub struct DmarTable {
    /// Host address width (number of address bits supported).
    host_address_width: u8,
    /// Whether interrupt remapping is required.
    interrupt_remap_required: bool,
    /// Whether x2APIC mode requires opt-in.
    x2apic_opt_out: bool,
    /// DRHD (DMA Remapping Hardware Unit) entries.
    drhd_entries: AdmittedVec<DrhdEntry>,
    /// RMRR (Reserved Memory Region) entries.
    rmrr_entries: AdmittedVec<RmrrEntry>,
}

/// DRHD (DMA Remapping Hardware Unit Definition) entry.
pub struct DrhdEntry {
    /// Whether this unit handles all PCI devices not in other units' scope.
    include_pci_all: bool,
    /// PCI segment number.
    segment: u16,
    /// Register base physical address.
    register_base: u64,
    /// Device scopes handled by this unit.
    device_scopes: AdmittedVec<DeviceScope>,
}

/// RMRR (Reserved Memory Region) entry.
pub struct RmrrEntry {
    /// PCI segment number.
    segment: u16,
    /// Reserved region base address (physical).
    base_address: u64,
    /// Reserved region limit address (physical).
    limit_address: u64,
    /// Devices that may DMA to this region.
    device_scopes: AdmittedVec<DeviceScope>,
}

/// Device scope entry.
#[derive(Debug)]
pub struct DeviceScope {
    /// Scope type.
    pub scope_type: DeviceScopeType,
    /// Start bus number.
    pub start_bus: u8,
    /// Path to device (series of device:function pairs).
    pub path: AdmittedVec<(u8, u8)>,
}

/// Device scope type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceScopeType {
    /// PCI endpoint device.
    PciEndpoint,
    /// PCI-to-PCI bridge (sub-hierarchy).
    PciBridge,
    /// IOAPIC.
    Ioapic(u8), // enumeration ID
    /// HPET.
    Hpet(u8), // enumeration ID
    /// ACPI namespace device.
    AcpiNamespace,
}

// ============================================================================
// Implementation
// ============================================================================

impl DmarTable {
    /// Get host address width (number of address bits).
    pub fn host_address_width(&self) -> u8 {
        self.host_address_width + 1
    }

    /// Check if interrupt remapping is required.
    pub fn interrupt_remap_required(&self) -> bool {
        self.interrupt_remap_required
    }

    /// Get number of DRHD units.
    pub fn drhd_count(&self) -> usize {
        self.drhd_entries.len()
    }

    /// Get number of RMRR regions.
    pub fn rmrr_count(&self) -> usize {
        self.rmrr_entries.len()
    }

    /// Iterate over DRHD entries.
    pub fn drhd_iter(&self) -> impl Iterator<Item = &DrhdEntry> {
        self.drhd_entries.iter()
    }

    /// Iterate over RMRR entries.
    pub fn rmrr_iter(&self) -> impl Iterator<Item = &RmrrEntry> {
        self.rmrr_entries.iter()
    }
}

impl DrhdEntry {
    /// Check if this unit handles all PCI devices.
    pub fn include_pci_all(&self) -> bool {
        self.include_pci_all
    }

    /// Get PCI segment number.
    pub fn segment(&self) -> u16 {
        self.segment
    }

    /// Get register base address.
    pub fn register_base(&self) -> u64 {
        self.register_base
    }

    /// Get device scopes.
    pub fn device_scopes(&self) -> &[DeviceScope] {
        &self.device_scopes
    }

    /// Check if this unit handles a specific device.
    pub fn handles_device(&self, bus: u8, device: u8, function: u8) -> bool {
        if self.include_pci_all {
            return true;
        }

        for scope in &self.device_scopes {
            if scope.matches_device(bus, device, function) {
                return true;
            }
        }

        false
    }
}

impl RmrrEntry {
    /// Get PCI segment number.
    pub fn segment(&self) -> u16 {
        self.segment
    }

    /// Get base address.
    pub fn base(&self) -> u64 {
        self.base_address
    }

    /// Get limit address.
    pub fn limit(&self) -> u64 {
        self.limit_address
    }

    /// Get size in bytes.
    pub fn size(&self) -> u64 {
        // U28-2 FIX: RMRR addresses come from firmware.  Never let an
        // inverted/overflowing inclusive range wrap into a huge allocation or
        // mapping request; zero is the fail-closed representation for an
        // invalid range and callers can use `checked_size` when they need to
        // distinguish it from a legitimate zero-length rejection.
        self.limit_address
            .checked_sub(self.base_address)
            .and_then(|span| span.checked_add(1))
            .unwrap_or(0)
    }

    /// Return the inclusive RMRR size only when `base..=limit` is valid.
    pub fn checked_size(&self) -> Option<u64> {
        self.limit_address
            .checked_sub(self.base_address)
            .and_then(|span| span.checked_add(1))
    }
}

impl DeviceScope {
    /// Check if this scope matches a specific device.
    pub fn matches_device(&self, bus: u8, device: u8, function: u8) -> bool {
        // For PCI endpoint, the path must lead to exactly this device
        // For PCI bridge, all devices under the bridge are included
        if self.path.is_empty() {
            return false;
        }

        // Walk the path from start_bus
        let current_bus = self.start_bus;

        // For endpoint, check if path leads to exact device
        if matches!(self.scope_type, DeviceScopeType::PciEndpoint) {
            if let Some(&(last_dev, last_fn)) = self.path.last() {
                // TODO: Proper path walking through bridges
                return current_bus == bus && last_dev == device && last_fn == function;
            }
        }

        // For bridge, check if device is under this bridge hierarchy
        if matches!(self.scope_type, DeviceScopeType::PciBridge) {
            // TODO: Implement bridge sub-hierarchy checking
            return false;
        }

        false
    }
}

// ============================================================================
// Parsing
// ============================================================================

#[derive(Clone, Copy)]
struct ValidatedDmarWindow {
    ptr: *const u8,
    len: usize,
}

/// Parse the DMAR table from ACPI.
///
/// This function searches for the DMAR table in ACPI and parses its contents.
///
/// # Returns
///
/// * `Ok(DmarTable)` - Successfully parsed DMAR table
/// * `Err(DmarError)` - Parsing failed
pub fn parse_dmar_table(rsdp_phys: u64) -> Result<DmarTable, DmarError> {
    // Find DMAR table in ACPI
    let table = find_dmar_table(rsdp_phys)?;

    unsafe { parse_dmar_at(table.ptr, table.len) }
}

/// R171-G5-01-B FIX: bound a firmware-advertised physical region to the kernel
/// direct map and return a CPU-readable high-half pointer, or `None` if it is not
/// fully inside `[0, 1 GiB)`. EVERY read of a firmware-controlled ACPI address goes
/// through this so a malformed/out-of-range table can never fault the kernel or be
/// blindly dereferenced. `None` for an address the firmware CLAIMS exists is the
/// caller's signal to fail CLOSED (`InvalidStructure`).
fn phys_window(phys: u64, len: usize) -> Option<*const u8> {
    if phys == 0 {
        return None;
    }
    let end = phys.checked_add(len as u64)?; // no u64 wrap
    if end > MAX_DIRECT_MAP_PHYS {
        return None; // above the 1 GiB direct map
    }
    Some((PHYSICAL_MEMORY_OFFSET + phys) as *const u8)
}

/// Outcome of validating a candidate RSDP. The `Unreadable` vs `Invalid`
/// distinction is the fail-closed hinge (R171-G5-01-B): a firmware-advertised RSDP
/// that lies (even partially) above the 1 GiB direct map is present-but-
/// uninspectable → the caller must fail CLOSED; a merely garbage/corrupt readable
/// hint may fall back to a legacy BIOS scan without weakening isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RsdpResult {
    /// Valid RSDP → (rsdt_phys, xsdt_phys); xsdt 0 if ACPI 1.0.
    Valid(u64, u64),
    /// Readable but not a valid RSDP (bad signature / checksum / length).
    Invalid,
    /// A required window lies above the 1 GiB direct map — cannot be inspected.
    Unreadable,
    /// A checksum/work extent exceeds the parser's forward-compatible cap.
    ResourceLimit,
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(core::mem::size_of::<u32>())?;
    let raw: [u8; 4] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn read_le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(core::mem::size_of::<u64>())?;
    let raw: [u8; 8] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(raw))
}

fn validate_rsdp_v1_prefix(bytes: &[u8]) -> Result<(u8, u64), DmarError> {
    let v1_len = core::mem::size_of::<RsdpV1>();
    if bytes.len() < v1_len {
        return Err(DmarError::InvalidStructure);
    }
    if bytes.get(..8) != Some(b"RSD PTR ") {
        return Err(DmarError::InvalidSignature);
    }
    if !verify_checksum_bytes(&bytes[..v1_len]) {
        return Err(DmarError::InvalidChecksum);
    }
    let revision = bytes[15];
    let rsdt = read_le_u32(bytes, 16).ok_or(DmarError::InvalidStructure)? as u64;
    Ok((revision, rsdt))
}

fn validate_rsdp_bytes(bytes: &[u8]) -> Result<(u64, u64), DmarError> {
    let (revision, rsdt) = validate_rsdp_v1_prefix(bytes)?;
    if revision < 2 {
        return Ok((rsdt, 0));
    }

    let v2_len = core::mem::size_of::<RsdpV2>();
    if bytes.len() < v2_len {
        return Err(DmarError::InvalidStructure);
    }
    let declared = read_le_u32(bytes, 20).ok_or(DmarError::InvalidStructure)? as usize;
    if declared < v2_len {
        return Err(DmarError::InvalidStructure);
    }
    if declared > MAX_RSDP_BYTES {
        return Err(DmarError::ResourceLimit);
    }
    if declared != bytes.len() {
        return Err(DmarError::InvalidStructure);
    }
    if !verify_checksum_bytes(bytes) {
        return Err(DmarError::InvalidChecksum);
    }
    let xsdt = read_le_u64(bytes, 24).ok_or(DmarError::InvalidStructure)?;
    Ok((rsdt, xsdt))
}

/// Validate an RSDP at `phys`.
///
/// # Safety
/// All reads are bounded by `phys_window`; `phys` need not be pre-validated.
unsafe fn validate_rsdp(phys: u64) -> RsdpResult {
    let v1_len = core::mem::size_of::<RsdpV1>();
    let rsdp_ptr = match phys_window(phys, v1_len) {
        Some(p) => p,
        None => return RsdpResult::Unreadable,
    };
    let v1_bytes = core::slice::from_raw_parts(rsdp_ptr, v1_len);
    let (revision, rsdt) = match validate_rsdp_v1_prefix(v1_bytes) {
        Ok(fields) => fields,
        Err(_) => return RsdpResult::Invalid,
    };
    if revision < 2 {
        return RsdpResult::Valid(rsdt, 0);
    }

    // RF180-20 FIX: XSDT is consumed only after the complete fixed v2 prefix is
    // inside the declared/checksummed extent. Later ACPI revisions may extend
    // the RSDP, so accept bounded lengths above 36 instead of rejecting them.
    let fixed_v2_len = core::mem::size_of::<RsdpV2>();
    let v2_ptr = match phys_window(phys, fixed_v2_len) {
        Some(p) => p,
        None => return RsdpResult::Unreadable,
    };
    let fixed_v2 = core::slice::from_raw_parts(v2_ptr, fixed_v2_len);
    let v2_len = match read_le_u32(fixed_v2, 20) {
        Some(length) => length as usize,
        None => return RsdpResult::Invalid,
    };
    if v2_len < fixed_v2_len {
        return RsdpResult::Invalid;
    }
    if v2_len > MAX_RSDP_BYTES {
        return RsdpResult::ResourceLimit;
    }
    let v2_full = match phys_window(phys, v2_len) {
        Some(p) => p,
        None => return RsdpResult::Unreadable,
    };
    let v2_bytes = core::slice::from_raw_parts(v2_full, v2_len);
    match validate_rsdp_bytes(v2_bytes) {
        Ok((validated_rsdt, xsdt)) => RsdpResult::Valid(validated_rsdt, xsdt),
        Err(DmarError::ResourceLimit) => RsdpResult::ResourceLimit,
        Err(_) => RsdpResult::Invalid,
    }
}

fn validate_root_table_layout(total_len: usize, entry_width: usize) -> Result<usize, DmarError> {
    if entry_width != 4 && entry_width != 8 {
        return Err(DmarError::InvalidStructure);
    }
    let header_len = core::mem::size_of::<AcpiHeader>();
    if total_len < header_len {
        return Err(DmarError::InvalidStructure);
    }
    if total_len > MAX_ACPI_ROOT_TABLE_BYTES {
        return Err(DmarError::ResourceLimit);
    }
    let body_len = total_len - header_len;
    if body_len % entry_width != 0 {
        return Err(DmarError::InvalidStructure);
    }
    let entries = body_len / entry_width;
    if entries > MAX_ACPI_ROOT_TABLE_ENTRIES {
        return Err(DmarError::ResourceLimit);
    }
    Ok(entries)
}

/// Walk an RSDT (`entry_width==4`) or XSDT (`entry_width==8`) looking for the DMAR
/// entry. Returns `Ok(Some(dmar_phys))`, `Ok(None)` if not present, or
/// `Err(InvalidStructure)` for any malformed / out-of-direct-map table.
///
/// # Safety
/// `sdt_phys` is a firmware pointer; all reads are bounded via `phys_window`.
unsafe fn find_dmar_in_sdt(
    sdt_phys: u64,
    entry_width: usize,
    expect_sig: &[u8; 4],
) -> Result<Option<u64>, DmarError> {
    if entry_width != 4 && entry_width != 8 {
        return Err(DmarError::InvalidStructure);
    }
    let hdr_size = core::mem::size_of::<AcpiHeader>();
    let header_ptr = phys_window(sdt_phys, hdr_size).ok_or(DmarError::InvalidStructure)?;
    let header = ptr::read_unaligned(header_ptr as *const AcpiHeader);
    if &header.signature != expect_sig {
        return Err(DmarError::InvalidStructure);
    }
    let total_len = header.length as usize;
    // RF180-20 FIX: cap both checksum bytes and child-pointer work before
    // windowing or traversing the firmware-controlled root table.
    let entry_count = validate_root_table_layout(total_len, entry_width)?;
    // Re-window the whole table and checksum it before trusting any entry.
    let table_ptr = phys_window(sdt_phys, total_len).ok_or(DmarError::InvalidStructure)?;
    if !verify_checksum(table_ptr, total_len) {
        return Err(DmarError::InvalidStructure);
    }
    for i in 0..entry_count {
        let off = hdr_size + i * entry_width;
        let entry_phys = match entry_width {
            4 => u32::from_le(ptr::read_unaligned(table_ptr.add(off) as *const u32)) as u64,
            _ => u64::from_le(ptr::read_unaligned(table_ptr.add(off) as *const u64)),
        };
        // A real-but-unreadable (>1 GiB) entry is "present yet uninspectable" → fail closed.
        let entry_hdr_ptr = phys_window(entry_phys, hdr_size).ok_or(DmarError::InvalidStructure)?;
        let entry_hdr = ptr::read_unaligned(entry_hdr_ptr as *const AcpiHeader);
        if entry_hdr.signature == DMAR_SIGNATURE {
            return Ok(Some(entry_phys));
        }
    }
    Ok(None)
}

/// Scan the legacy BIOS area for an RSDP (used when the bootloader supplies none,
/// or supplied a readable-but-invalid hint). The scan window is wholly below 1 MiB,
/// so `Unreadable` never arises here; only a `Valid` RSDP terminates the scan.
unsafe fn scan_bios_rsdp() -> Result<Option<(u64, u64)>, DmarError> {
    let mut phys = RSDP_SEARCH_START;
    while phys < RSDP_SEARCH_END {
        match validate_rsdp(phys) {
            RsdpResult::Valid(rsdt, xsdt) => return Ok(Some((rsdt, xsdt))),
            RsdpResult::ResourceLimit => return Err(DmarError::ResourceLimit),
            RsdpResult::Unreadable => return Err(DmarError::InvalidStructure),
            RsdpResult::Invalid => {}
        }
        phys += 16;
    }
    Ok(None)
}

// RF180-39 FIX: keep the distinction between an absent bootloader hint and a
// present-but-invalid one after the optional BIOS recovery scan. Only genuine
// absence may authorize the caller's legacy-DMA path; an advertised ACPI root
// that cannot be recovered must fail closed.
fn resolve_rsdp_roots(
    advertised: Option<RsdpResult>,
    bios_fallback: Option<(u64, u64)>,
) -> Result<(u64, u64), DmarError> {
    match advertised {
        Some(RsdpResult::Valid(rsdt, xsdt)) => Ok((rsdt, xsdt)),
        Some(RsdpResult::Invalid) => bios_fallback.ok_or(DmarError::InvalidStructure),
        Some(RsdpResult::Unreadable) => Err(DmarError::InvalidStructure),
        Some(RsdpResult::ResourceLimit) => Err(DmarError::ResourceLimit),
        None => bios_fallback.ok_or(DmarError::NotFound),
    }
}

/// Find the DMAR table in ACPI. `rsdp_phys` is the bootloader-supplied RSDP
/// physical address (0 if none → BIOS scan).
///
/// FAILURE TAXONOMY (the fail-open → fail-closed hinge, R171-G5-01-B):
/// - `NotFound`: no bootloader RSDP was advertised and the BIOS scan found none,
///   or valid ACPI contains no DMAR → legacy bypass is permitted by the caller.
/// - `InvalidStructure`: ACPI exists but is uninspectable/malformed — a non-zero
///   RSDP (including a readable-invalid hint with no valid BIOS fallback) or any
///   RSDT/XSDT/entry/DMAR at phys ≥ 1 GiB, a length/overflow, or a bad checksum →
///   the caller fails CLOSED (no legacy DMA). A real DMAR above the direct map is
///   therefore refused, NEVER silently treated as "no IOMMU".
fn find_dmar_table(rsdp_phys: u64) -> Result<ValidatedDmarWindow, DmarError> {
    unsafe {
        let advertised = if rsdp_phys != 0 {
            Some(validate_rsdp(rsdp_phys))
        } else {
            None
        };
        // A BIOS scan is recovery for absence or a readable-invalid hint only.
        // Unreadable and resource-limit outcomes remain immediate fail-closed
        // errors and must never be masked by a legacy candidate.
        let bios_fallback = if matches!(advertised, None | Some(RsdpResult::Invalid)) {
            scan_bios_rsdp()?
        } else {
            None
        };
        let (rsdt_phys, xsdt_phys) = resolve_rsdp_roots(advertised, bios_fallback)?;

        if rsdt_phys == 0 && xsdt_phys == 0 {
            return Err(DmarError::InvalidStructure);
        }

        // Prefer the 64-bit XSDT; fall back to the 32-bit RSDT.
        let dmar_phys = if xsdt_phys != 0 {
            match find_dmar_in_sdt(xsdt_phys, 8, b"XSDT")? {
                Some(p) => Some(p),
                None if rsdt_phys != 0 => find_dmar_in_sdt(rsdt_phys, 4, b"RSDT")?,
                None => None,
            }
        } else {
            find_dmar_in_sdt(rsdt_phys, 4, b"RSDT")?
        }
        .ok_or(DmarError::NotFound)?;

        // Bound the DMAR body itself before handing the pointer to parse_dmar_at.
        let dmar_hdr_ptr = phys_window(dmar_phys, core::mem::size_of::<AcpiHeader>())
            .ok_or(DmarError::InvalidStructure)?;
        let dmar_hdr = ptr::read_unaligned(dmar_hdr_ptr as *const AcpiHeader);
        let dmar_len = dmar_hdr.length as usize;
        if dmar_len < core::mem::size_of::<AcpiHeader>() + core::mem::size_of::<DmarHeader>() {
            return Err(DmarError::InvalidStructure);
        }
        if dmar_len > MAX_DMAR_TABLE_BYTES {
            return Err(DmarError::ResourceLimit);
        }
        let ptr = phys_window(dmar_phys, dmar_len).ok_or(DmarError::InvalidStructure)?;
        Ok(ValidatedDmarWindow { ptr, len: dmar_len })
    }
}

/// Parse DMAR table at a given physical address.
///
/// # Safety
///
/// The caller must ensure that `[table_ptr, table_ptr + validated_len)` is a
/// readable extent whose size was independently validated by the ACPI walker.
unsafe fn parse_dmar_at(
    table_ptr: *const u8,
    validated_len: usize,
) -> Result<DmarTable, DmarError> {
    if table_ptr.is_null() {
        return Err(DmarError::InvalidStructure);
    }

    let fixed_header_len = core::mem::size_of::<AcpiHeader>() + core::mem::size_of::<DmarHeader>();
    if validated_len < fixed_header_len {
        return Err(DmarError::InvalidStructure);
    }
    if validated_len > MAX_DMAR_TABLE_BYTES {
        return Err(DmarError::ResourceLimit);
    }

    // Read only the fixed ACPI header before creating a slice. The encoded
    // length may have changed after discovery; it never controls a read here.
    let acpi_header = ptr::read_unaligned(table_ptr as *const AcpiHeader);

    if acpi_header.signature != DMAR_SIGNATURE {
        return Err(DmarError::InvalidSignature);
    }

    if acpi_header.length as usize != validated_len {
        return Err(DmarError::InvalidStructure);
    }

    if !verify_checksum(table_ptr, validated_len) {
        return Err(DmarError::InvalidChecksum);
    }

    let table = core::slice::from_raw_parts(table_ptr, validated_len);

    // R180-28 FIX, pass 1: validate the complete structure graph, enforce all
    // count/work limits, and calculate the full requested Vec backing storage.
    // This pass performs no heap allocation.
    let plan = scan_dmar_layout(table)?;

    // A firmware table is not an immutable Rust allocation. Counts plus the
    // 8-bit ACPI checksum cannot detect a checksum-preserving mutation between
    // passes. Budget and take one exact snapshot after pass 1, validate the
    // copied bytes again, and materialize only from that owned snapshot.
    let snapshot_bytes = allocator_vec_storage_bytes(validated_len, 1)?;
    let peak_bytes = plan
        .parsed_bytes
        .checked_add(snapshot_bytes)
        .ok_or(DmarError::ResourceLimit)?;
    if peak_bytes > MAX_DMAR_PARSE_PEAK_BYTES {
        return Err(DmarError::ResourceLimit);
    }
    let snapshot = AdmittedVec::try_copy_from_slice(HeapClass::Device, table)
        .map_err(|_| DmarError::OutOfMemory)?;
    validate_dmar_snapshot(&snapshot, validated_len)?;
    if scan_dmar_layout(&snapshot)? != plan {
        return Err(DmarError::InvalidStructure);
    }

    // Pass 2 revalidates every byte range while materializing. Every Vec is
    // reserved fallibly to its exact validated element count before any push.
    materialize_dmar(&snapshot, plan)
}

fn validate_dmar_snapshot(snapshot: &[u8], validated_len: usize) -> Result<(), DmarError> {
    let fixed_header_len = core::mem::size_of::<AcpiHeader>() + core::mem::size_of::<DmarHeader>();
    if snapshot.len() != validated_len || snapshot.len() < fixed_header_len {
        return Err(DmarError::InvalidStructure);
    }
    if snapshot.get(..DMAR_SIGNATURE.len()) != Some(DMAR_SIGNATURE.as_slice()) {
        return Err(DmarError::InvalidSignature);
    }
    let encoded_len = read_le_u32(snapshot, 4).ok_or(DmarError::InvalidStructure)? as usize;
    if encoded_len != validated_len {
        return Err(DmarError::InvalidStructure);
    }
    if !verify_checksum_bytes(snapshot) {
        return Err(DmarError::InvalidChecksum);
    }
    Ok(())
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct DmarParseStats {
    structures: usize,
    drhd_entries: usize,
    rmrr_entries: usize,
    total_scopes: usize,
    total_path_pairs: usize,
    parsed_bytes: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ScopeParseStats {
    materialized_scopes: usize,
    materialized_path_pairs: usize,
}

#[derive(Debug, Clone, Copy)]
enum InspectedStructureKind {
    Drhd {
        length: usize,
        scopes: ScopeParseStats,
    },
    Rmrr {
        length: usize,
        scopes: ScopeParseStats,
    },
    Ignored,
}

#[derive(Debug, Clone, Copy)]
struct InspectedStructure {
    end: usize,
    kind: InspectedStructureKind,
}

fn add_limited(value: &mut usize, additional: usize, limit: usize) -> Result<(), DmarError> {
    let next = value
        .checked_add(additional)
        .ok_or(DmarError::ResourceLimit)?;
    if next > limit {
        return Err(DmarError::ResourceLimit);
    }
    *value = next;
    Ok(())
}

/// Account for the backing allocation that `Vec::try_reserve_exact` will ask
/// from the kernel's `linked_list_allocator`. That allocator raises every
/// non-empty request to at least two machine words and rounds its size to a
/// machine-word boundary; counting only element bytes would understate tables
/// containing many short device paths.
fn allocator_vec_storage_bytes(elements: usize, element_size: usize) -> Result<usize, DmarError> {
    if elements == 0 {
        return Ok(0);
    }

    let requested = elements
        .checked_mul(element_size)
        .ok_or(DmarError::ResourceLimit)?;
    let minimum = 2 * core::mem::size_of::<usize>();
    let alignment = core::mem::align_of::<usize>();
    requested
        .max(minimum)
        .checked_add(alignment - 1)
        .ok_or(DmarError::ResourceLimit)?
        .checked_div(alignment)
        .and_then(|words| words.checked_mul(alignment))
        .ok_or(DmarError::ResourceLimit)
}

fn add_vec_storage(
    stats: &mut DmarParseStats,
    elements: usize,
    element_size: usize,
) -> Result<(), DmarError> {
    let bytes = allocator_vec_storage_bytes(elements, element_size)?;
    add_limited(&mut stats.parsed_bytes, bytes, MAX_DMAR_PARSED_BYTES)
}

fn add_top_level_storage(
    stats: &mut DmarParseStats,
    drhd_entries: usize,
    rmrr_entries: usize,
) -> Result<(), DmarError> {
    add_vec_storage(stats, drhd_entries, core::mem::size_of::<DrhdEntry>())?;
    add_vec_storage(stats, rmrr_entries, core::mem::size_of::<RmrrEntry>())
}

fn read_u16(table: &[u8], offset: usize) -> Result<u16, DmarError> {
    let end = offset
        .checked_add(core::mem::size_of::<u16>())
        .ok_or(DmarError::InvalidStructure)?;
    if end > table.len() {
        return Err(DmarError::InvalidStructure);
    }
    Ok(u16::from_le_bytes([table[offset], table[offset + 1]]))
}

fn read_u64(table: &[u8], offset: usize) -> Result<u64, DmarError> {
    let end = offset
        .checked_add(core::mem::size_of::<u64>())
        .ok_or(DmarError::InvalidStructure)?;
    if end > table.len() {
        return Err(DmarError::InvalidStructure);
    }
    Ok(u64::from_le_bytes([
        table[offset],
        table[offset + 1],
        table[offset + 2],
        table[offset + 3],
        table[offset + 4],
        table[offset + 5],
        table[offset + 6],
        table[offset + 7],
    ]))
}

fn structure_bounds(table: &[u8], start: usize) -> Result<(u16, usize, usize), DmarError> {
    let header_end = start
        .checked_add(core::mem::size_of::<DmarStructureHeader>())
        .ok_or(DmarError::InvalidStructure)?;
    if header_end > table.len() {
        return Err(DmarError::InvalidStructure);
    }

    let structure_type = read_u16(table, start)?;
    let length = read_u16(table, start + core::mem::size_of::<u16>())? as usize;
    if length < core::mem::size_of::<DmarStructureHeader>() {
        return Err(DmarError::InvalidStructure);
    }

    let end = start
        .checked_add(length)
        .ok_or(DmarError::InvalidStructure)?;
    if end > table.len() {
        return Err(DmarError::InvalidStructure);
    }

    Ok((structure_type, length, end))
}

fn decode_scope_type(scope_type: u8, enumeration_id: u8) -> Option<DeviceScopeType> {
    match scope_type {
        DEVICE_SCOPE_PCI_ENDPOINT => Some(DeviceScopeType::PciEndpoint),
        DEVICE_SCOPE_PCI_BRIDGE => Some(DeviceScopeType::PciBridge),
        DEVICE_SCOPE_IOAPIC => Some(DeviceScopeType::Ioapic(enumeration_id)),
        DEVICE_SCOPE_HPET => Some(DeviceScopeType::Hpet(enumeration_id)),
        DEVICE_SCOPE_ACPI_NAMESPACE => Some(DeviceScopeType::AcpiNamespace),
        _ => None,
    }
}

/// Validate and count one structure's device-scope stream without allocating.
fn scan_device_scopes(
    table: &[u8],
    start: usize,
    length: usize,
    materialize: bool,
    stats: &mut DmarParseStats,
) -> Result<ScopeParseStats, DmarError> {
    let end = start
        .checked_add(length)
        .ok_or(DmarError::InvalidStructure)?;
    if end > table.len() {
        return Err(DmarError::InvalidStructure);
    }

    let scope_header_len = core::mem::size_of::<DeviceScopeRaw>();
    let mut current = start;
    let mut structure_scope_count = 0usize;
    let mut result = ScopeParseStats::default();

    while current < end {
        let header_end = current
            .checked_add(scope_header_len)
            .ok_or(DmarError::InvalidStructure)?;
        if header_end > end {
            return Err(DmarError::InvalidStructure);
        }

        let scope_len = table[current + 1] as usize;
        if scope_len < scope_header_len {
            return Err(DmarError::InvalidStructure);
        }
        let scope_end = current
            .checked_add(scope_len)
            .ok_or(DmarError::InvalidStructure)?;
        if scope_end > end {
            return Err(DmarError::InvalidStructure);
        }

        let path_bytes = scope_len - scope_header_len;
        if path_bytes % 2 != 0 {
            return Err(DmarError::InvalidStructure);
        }
        let path_pairs = path_bytes / 2;
        if path_pairs > MAX_PATH_PAIRS_PER_SCOPE {
            return Err(DmarError::ResourceLimit);
        }
        if table[current + 2] != 0 || table[current + 3] != 0 {
            return Err(DmarError::InvalidStructure);
        }
        let path_start = current + scope_header_len;
        for pair in 0..path_pairs {
            let device = table[path_start + pair * 2];
            let function = table[path_start + pair * 2 + 1];
            if device > 31 || function > 7 {
                return Err(DmarError::InvalidStructure);
            }
        }

        add_limited(
            &mut structure_scope_count,
            1,
            MAX_DEVICE_SCOPES_PER_STRUCTURE,
        )?;
        add_limited(&mut stats.total_scopes, 1, MAX_TOTAL_DEVICE_SCOPES)?;
        add_limited(
            &mut stats.total_path_pairs,
            path_pairs,
            MAX_TOTAL_PATH_PAIRS,
        )?;

        if materialize && decode_scope_type(table[current], table[current + 4]).is_some() {
            result.materialized_scopes = result
                .materialized_scopes
                .checked_add(1)
                .ok_or(DmarError::ResourceLimit)?;
            result.materialized_path_pairs = result
                .materialized_path_pairs
                .checked_add(path_pairs)
                .ok_or(DmarError::ResourceLimit)?;
            add_vec_storage(stats, path_pairs, core::mem::size_of::<(u8, u8)>())?;
        }

        current = scope_end;
    }

    if materialize {
        add_vec_storage(
            stats,
            result.materialized_scopes,
            core::mem::size_of::<DeviceScope>(),
        )?;
    }

    Ok(result)
}

fn inspect_structure(
    table: &[u8],
    start: usize,
    stats: &mut DmarParseStats,
) -> Result<InspectedStructure, DmarError> {
    let (structure_type, length, end) = structure_bounds(table, start)?;
    add_limited(&mut stats.structures, 1, MAX_DMAR_STRUCTURES)?;

    let kind = match structure_type {
        DMAR_TYPE_DRHD => {
            let fixed_len = core::mem::size_of::<DrhdRaw>();
            if length < fixed_len {
                return Err(DmarError::InvalidStructure);
            }
            let flags = table[start + 4];
            let register_base = read_u64(table, start + 8)?;
            if flags & !0x01 != 0
                || table[start + 5] != 0
                || register_base == 0
                || register_base & 0xfff != 0
            {
                return Err(DmarError::InvalidStructure);
            }
            add_limited(&mut stats.drhd_entries, 1, MAX_IOMMU_UNITS)?;
            let scopes =
                scan_device_scopes(table, start + fixed_len, length - fixed_len, true, stats)?;
            InspectedStructureKind::Drhd { length, scopes }
        }
        DMAR_TYPE_RMRR => {
            let fixed_len = core::mem::size_of::<RmrrRaw>();
            if length < fixed_len {
                return Err(DmarError::InvalidStructure);
            }
            let base = read_u64(table, start + 8)?;
            let limit = read_u64(table, start + 16)?;
            if table[start + 4] != 0
                || table[start + 5] != 0
                || base > limit
                || base & 0xfff != 0
                || limit & 0xfff != 0xfff
            {
                return Err(DmarError::InvalidStructure);
            }
            add_limited(&mut stats.rmrr_entries, 1, MAX_DMAR_RMRR_ENTRIES)?;
            let scopes =
                scan_device_scopes(table, start + fixed_len, length - fixed_len, true, stats)?;
            InspectedStructureKind::Rmrr { length, scopes }
        }
        DMAR_TYPE_ATSR => {
            let fixed_len = core::mem::size_of::<AtsrRaw>();
            if length < fixed_len {
                return Err(DmarError::InvalidStructure);
            }
            // ATSR is not materialized yet, but its scope stream is still
            // firmware syntax and must be validated and work-bounded.
            scan_device_scopes(table, start + fixed_len, length - fixed_len, false, stats)?;
            InspectedStructureKind::Ignored
        }
        DMAR_TYPE_RHSA => {
            if length != core::mem::size_of::<RhsaRaw>() {
                return Err(DmarError::InvalidStructure);
            }
            InspectedStructureKind::Ignored
        }
        DMAR_TYPE_ANDD => {
            let fixed_len = core::mem::size_of::<AnddRaw>();
            // The fixed prefix must be followed by a NUL-terminated ACPI name.
            if length <= fixed_len || !table[start + fixed_len..end].contains(&0) {
                return Err(DmarError::InvalidStructure);
            }
            InspectedStructureKind::Ignored
        }
        DMAR_TYPE_SATC => {
            let fixed_len = core::mem::size_of::<SatcRaw>();
            if length < fixed_len {
                return Err(DmarError::InvalidStructure);
            }
            scan_device_scopes(table, start + fixed_len, length - fixed_len, false, stats)?;
            InspectedStructureKind::Ignored
        }
        DMAR_TYPE_SIDP => {
            let fixed_len = core::mem::size_of::<SidpRaw>();
            if length < fixed_len {
                return Err(DmarError::InvalidStructure);
            }
            scan_device_scopes(table, start + fixed_len, length - fixed_len, false, stats)?;
            InspectedStructureKind::Ignored
        }
        _ => InspectedStructureKind::Ignored,
    };

    Ok(InspectedStructure { end, kind })
}

fn scan_dmar_layout(table: &[u8]) -> Result<DmarParseStats, DmarError> {
    let fixed_header_len = core::mem::size_of::<AcpiHeader>() + core::mem::size_of::<DmarHeader>();
    if table.len() < fixed_header_len {
        return Err(DmarError::InvalidStructure);
    }

    let dmar_offset = core::mem::size_of::<AcpiHeader>();
    let host_address_width = table[dmar_offset];
    let flags = table[dmar_offset + 1];
    if !(31..=63).contains(&host_address_width)
        || flags & !0x03 != 0
        || table[dmar_offset + 2..fixed_header_len]
            .iter()
            .any(|&byte| byte != 0)
    {
        return Err(DmarError::InvalidStructure);
    }

    let mut stats = DmarParseStats::default();
    let mut current = fixed_header_len;
    while current < table.len() {
        current = inspect_structure(table, current, &mut stats)?.end;
    }
    let drhd_entries = stats.drhd_entries;
    let rmrr_entries = stats.rmrr_entries;
    add_top_level_storage(&mut stats, drhd_entries, rmrr_entries)?;
    Ok(stats)
}

fn parse_device_scopes(
    table: &[u8],
    start: usize,
    length: usize,
    expected: ScopeParseStats,
) -> Result<AdmittedVec<DeviceScope>, DmarError> {
    let end = start
        .checked_add(length)
        .ok_or(DmarError::InvalidStructure)?;
    if end > table.len() {
        return Err(DmarError::InvalidStructure);
    }

    let mut scopes = AdmittedVec::new(HeapClass::Device);
    scopes
        .try_reserve_exact(expected.materialized_scopes)
        .map_err(|_| DmarError::OutOfMemory)?;

    let scope_header_len = core::mem::size_of::<DeviceScopeRaw>();
    let mut current = start;
    let mut structure_scope_count = 0usize;
    let mut structure_path_pairs = 0usize;
    let mut materialized_path_pairs = 0usize;

    while current < end {
        let header_end = current
            .checked_add(scope_header_len)
            .ok_or(DmarError::InvalidStructure)?;
        if header_end > end {
            return Err(DmarError::InvalidStructure);
        }

        let scope_len = table[current + 1] as usize;
        if scope_len < scope_header_len {
            return Err(DmarError::InvalidStructure);
        }
        let scope_end = current
            .checked_add(scope_len)
            .ok_or(DmarError::InvalidStructure)?;
        if scope_end > end {
            return Err(DmarError::InvalidStructure);
        }

        let path_bytes = scope_len - scope_header_len;
        if path_bytes % 2 != 0 {
            return Err(DmarError::InvalidStructure);
        }
        let path_pairs = path_bytes / 2;
        if path_pairs > MAX_PATH_PAIRS_PER_SCOPE {
            return Err(DmarError::ResourceLimit);
        }
        add_limited(
            &mut structure_scope_count,
            1,
            MAX_DEVICE_SCOPES_PER_STRUCTURE,
        )?;
        add_limited(&mut structure_path_pairs, path_pairs, MAX_TOTAL_PATH_PAIRS)?;

        if let Some(scope_type) = decode_scope_type(table[current], table[current + 4]) {
            if scopes.len() >= expected.materialized_scopes {
                return Err(DmarError::InvalidStructure);
            }
            materialized_path_pairs = materialized_path_pairs
                .checked_add(path_pairs)
                .ok_or(DmarError::ResourceLimit)?;
            if materialized_path_pairs > expected.materialized_path_pairs {
                return Err(DmarError::InvalidStructure);
            }

            let mut path = AdmittedVec::new(HeapClass::Device);
            path.try_reserve_exact(path_pairs)
                .map_err(|_| DmarError::OutOfMemory)?;
            let path_start = current + scope_header_len;
            for i in 0..path_pairs {
                path.push_reserved((table[path_start + i * 2], table[path_start + i * 2 + 1]))
                    .map_err(|_| DmarError::InvalidStructure)?;
            }

            scopes
                .push_reserved(DeviceScope {
                    scope_type,
                    start_bus: table[current + 5],
                    path,
                })
                .map_err(|_| DmarError::InvalidStructure)?;
        }

        current = scope_end;
    }

    if scopes.len() != expected.materialized_scopes
        || materialized_path_pairs != expected.materialized_path_pairs
    {
        return Err(DmarError::InvalidStructure);
    }

    Ok(scopes)
}

fn parse_drhd(
    table: &[u8],
    start: usize,
    length: usize,
    scopes: ScopeParseStats,
) -> Result<DrhdEntry, DmarError> {
    let fixed_len = core::mem::size_of::<DrhdRaw>();
    if length < fixed_len {
        return Err(DmarError::InvalidStructure);
    }

    Ok(DrhdEntry {
        include_pci_all: (table[start + 4] & 0x01) != 0,
        segment: read_u16(table, start + 6)?,
        register_base: read_u64(table, start + 8)?,
        device_scopes: parse_device_scopes(table, start + fixed_len, length - fixed_len, scopes)?,
    })
}

fn parse_rmrr(
    table: &[u8],
    start: usize,
    length: usize,
    scopes: ScopeParseStats,
) -> Result<RmrrEntry, DmarError> {
    let fixed_len = core::mem::size_of::<RmrrRaw>();
    if length < fixed_len {
        return Err(DmarError::InvalidStructure);
    }

    Ok(RmrrEntry {
        segment: read_u16(table, start + 6)?,
        base_address: read_u64(table, start + 8)?,
        limit_address: read_u64(table, start + 16)?,
        device_scopes: parse_device_scopes(table, start + fixed_len, length - fixed_len, scopes)?,
    })
}

fn materialize_dmar(table: &[u8], plan: DmarParseStats) -> Result<DmarTable, DmarError> {
    let mut drhd_entries = AdmittedVec::new(HeapClass::Device);
    drhd_entries
        .try_reserve_exact(plan.drhd_entries)
        .map_err(|_| DmarError::OutOfMemory)?;
    let mut rmrr_entries = AdmittedVec::new(HeapClass::Device);
    rmrr_entries
        .try_reserve_exact(plan.rmrr_entries)
        .map_err(|_| DmarError::OutOfMemory)?;

    let fixed_header_len = core::mem::size_of::<AcpiHeader>() + core::mem::size_of::<DmarHeader>();
    let mut second_pass = DmarParseStats::default();
    // These allocations have already occurred, so charge their validated
    // footprint before any nested pass-two reservation.
    add_top_level_storage(&mut second_pass, plan.drhd_entries, plan.rmrr_entries)?;
    let mut current = fixed_header_len;

    while current < table.len() {
        let inspected = inspect_structure(table, current, &mut second_pass)?;
        match inspected.kind {
            InspectedStructureKind::Drhd { length, scopes } => {
                if drhd_entries.len() >= plan.drhd_entries {
                    return Err(DmarError::InvalidStructure);
                }
                drhd_entries
                    .push_reserved(parse_drhd(table, current, length, scopes)?)
                    .map_err(|_| DmarError::InvalidStructure)?;
            }
            InspectedStructureKind::Rmrr { length, scopes } => {
                if rmrr_entries.len() >= plan.rmrr_entries {
                    return Err(DmarError::InvalidStructure);
                }
                rmrr_entries
                    .push_reserved(parse_rmrr(table, current, length, scopes)?)
                    .map_err(|_| DmarError::InvalidStructure)?;
            }
            InspectedStructureKind::Ignored => {}
        }
        current = inspected.end;
    }

    // Refuse a table that changed between validation and materialization. The
    // partially built value is still local and is dropped on every error path.
    if second_pass != plan
        || drhd_entries.len() != plan.drhd_entries
        || rmrr_entries.len() != plan.rmrr_entries
        || !verify_checksum(table.as_ptr(), table.len())
    {
        return Err(DmarError::InvalidStructure);
    }

    let dmar_header_offset = core::mem::size_of::<AcpiHeader>();
    let host_address_width = table[dmar_header_offset];
    let flags = table[dmar_header_offset + 1];

    Ok(DmarTable {
        host_address_width,
        interrupt_remap_required: (flags & 0x01) != 0,
        x2apic_opt_out: (flags & 0x02) != 0,
        drhd_entries,
        rmrr_entries,
    })
}

/// Verify ACPI table checksum.
fn verify_checksum(ptr: *const u8, len: usize) -> bool {
    verify_checksum_bytes(unsafe { core::slice::from_raw_parts(ptr, len) })
}

fn verify_checksum_bytes(bytes: &[u8]) -> bool {
    bytes.iter().copied().fold(0u8, u8::wrapping_add) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    const ACPI_CHECKSUM_OFFSET: usize = 9;

    fn finish_table(mut table: Vec<u8>) -> Vec<u8> {
        let length = table.len() as u32;
        table[4..8].copy_from_slice(&length.to_le_bytes());
        table[ACPI_CHECKSUM_OFFSET] = 0;
        let sum = table
            .iter()
            .copied()
            .fold(0u8, |acc, byte| acc.wrapping_add(byte));
        table[ACPI_CHECKSUM_OFFSET] = 0u8.wrapping_sub(sum);
        assert_eq!(
            table
                .iter()
                .copied()
                .fold(0u8, |acc, byte| acc.wrapping_add(byte)),
            0
        );
        table
    }

    fn table_with_structures(structures: Vec<Vec<u8>>) -> Vec<u8> {
        let fixed_header_len =
            core::mem::size_of::<AcpiHeader>() + core::mem::size_of::<DmarHeader>();
        let mut table = vec![0; fixed_header_len];
        table[0..4].copy_from_slice(&DMAR_SIGNATURE);
        table[8] = 1;
        table[core::mem::size_of::<AcpiHeader>()] = 47;
        table[core::mem::size_of::<AcpiHeader>() + 1] = 0x01;
        for structure in structures {
            table.extend_from_slice(&structure);
        }
        finish_table(table)
    }

    fn structure(structure_type: u16, body: &[u8]) -> Vec<u8> {
        let length = core::mem::size_of::<DmarStructureHeader>() + body.len();
        assert!(length <= u16::MAX as usize);
        let mut result = Vec::new();
        result.extend_from_slice(&structure_type.to_le_bytes());
        result.extend_from_slice(&(length as u16).to_le_bytes());
        result.extend_from_slice(body);
        result
    }

    fn fixed_length_structure(structure_type: u16, length: usize) -> Vec<u8> {
        assert!(length >= core::mem::size_of::<DmarStructureHeader>());
        let mut result = vec![0; length];
        result[0..2].copy_from_slice(&structure_type.to_le_bytes());
        result[2..4].copy_from_slice(&(length as u16).to_le_bytes());
        result
    }

    fn declared_structure(structure_type: u16, declared_length: u16, body: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&structure_type.to_le_bytes());
        result.extend_from_slice(&declared_length.to_le_bytes());
        result.extend_from_slice(body);
        result
    }

    fn device_scope(
        scope_type: u8,
        enumeration_id: u8,
        start_bus: u8,
        path: &[(u8, u8)],
    ) -> Vec<u8> {
        let length = core::mem::size_of::<DeviceScopeRaw>() + path.len() * 2;
        assert!(length <= u8::MAX as usize);
        let mut result = vec![scope_type, length as u8, 0, 0, enumeration_id, start_bus];
        for &(device, function) in path {
            result.push(device);
            result.push(function);
        }
        result
    }

    fn drhd_with_scope_bytes(scope_bytes: &[u8]) -> Vec<u8> {
        let mut body = vec![1, 0];
        body.extend_from_slice(&2u16.to_le_bytes());
        body.extend_from_slice(&0xfee0_0000u64.to_le_bytes());
        body.extend_from_slice(scope_bytes);
        structure(DMAR_TYPE_DRHD, &body)
    }

    fn drhd_with_repeated_scope(count: usize) -> Vec<u8> {
        let scope = device_scope(DEVICE_SCOPE_PCI_ENDPOINT, 0, 0, &[]);
        let mut scopes = Vec::new();
        for _ in 0..count {
            scopes.extend_from_slice(&scope);
        }
        drhd_with_scope_bytes(&scopes)
    }

    fn rmrr_with_scope_bytes(scope_bytes: &[u8]) -> Vec<u8> {
        let mut body = vec![0, 0];
        body.extend_from_slice(&3u16.to_le_bytes());
        body.extend_from_slice(&0x1000u64.to_le_bytes());
        body.extend_from_slice(&0x1fffu64.to_le_bytes());
        body.extend_from_slice(scope_bytes);
        structure(DMAR_TYPE_RMRR, &body)
    }

    fn atsr_with_scope_bytes(scope_bytes: &[u8]) -> Vec<u8> {
        let mut body = vec![0, 0];
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(scope_bytes);
        structure(DMAR_TYPE_ATSR, &body)
    }

    fn satc_with_scope_bytes(scope_bytes: &[u8]) -> Vec<u8> {
        let mut body = vec![0, 0];
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(scope_bytes);
        structure(DMAR_TYPE_SATC, &body)
    }

    fn sidp_with_scope_bytes(scope_bytes: &[u8]) -> Vec<u8> {
        let mut body = vec![0, 0];
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(scope_bytes);
        structure(DMAR_TYPE_SIDP, &body)
    }

    fn rhsa() -> Vec<u8> {
        let mut body = vec![0; 4];
        body.extend_from_slice(&0xfed9_0000u64.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        structure(DMAR_TYPE_RHSA, &body)
    }

    fn andd() -> Vec<u8> {
        let mut body = vec![0, 0, 0, 1];
        body.extend_from_slice(b"\\_SB.PCI0\0");
        structure(DMAR_TYPE_ANDD, &body)
    }

    fn parse(table: &[u8]) -> Result<DmarTable, DmarError> {
        static TEST_ADMISSION: spin::Once<()> = spin::Once::new();
        TEST_ADMISSION.call_once(mm::publish_heap_budgets);
        unsafe { parse_dmar_at(table.as_ptr(), table.len()) }
    }

    fn rsdp_v2_bytes(length: usize) -> Vec<u8> {
        assert!(length >= 33);
        let mut rsdp = vec![0; length];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        rsdp[15] = 2;
        rsdp[16..20].copy_from_slice(&0x1234u32.to_le_bytes());
        rsdp[20..24].copy_from_slice(&(length as u32).to_le_bytes());
        rsdp[24..32].copy_from_slice(&0x5678u64.to_le_bytes());

        rsdp[8] = 0;
        let v1_sum = rsdp[..core::mem::size_of::<RsdpV1>()]
            .iter()
            .copied()
            .fold(0u8, u8::wrapping_add);
        rsdp[8] = 0u8.wrapping_sub(v1_sum);

        rsdp[32] = 0;
        let full_sum = rsdp.iter().copied().fold(0u8, u8::wrapping_add);
        rsdp[32] = 0u8.wrapping_sub(full_sum);
        rsdp
    }

    #[test]
    fn dmar_declared_length_must_equal_validated_extent() {
        let table = table_with_structures(Vec::new());

        assert!(matches!(
            unsafe { parse_dmar_at(table.as_ptr(), table.len() - 1) },
            Err(DmarError::InvalidStructure)
        ));

        let mut larger_extent = table;
        larger_extent.push(0);
        assert!(matches!(
            unsafe { parse_dmar_at(larger_extent.as_ptr(), larger_extent.len()) },
            Err(DmarError::InvalidStructure)
        ));
    }

    #[test]
    fn immutable_snapshot_revalidates_signature_and_length() {
        let table = table_with_structures(Vec::new());
        assert_eq!(validate_dmar_snapshot(&table, table.len()), Ok(()));

        let mut bad_signature = table.clone();
        bad_signature[..4].copy_from_slice(b"FACP");
        assert_eq!(
            validate_dmar_snapshot(&bad_signature, bad_signature.len()),
            Err(DmarError::InvalidSignature)
        );

        let mut bad_length = table;
        let shorter = (bad_length.len() - 1) as u32;
        bad_length[4..8].copy_from_slice(&shorter.to_le_bytes());
        assert_eq!(
            validate_dmar_snapshot(&bad_length, bad_length.len()),
            Err(DmarError::InvalidStructure)
        );
    }

    #[test]
    fn rsdp_v2_length_bounds_are_enforced() {
        assert!(matches!(
            validate_rsdp_bytes(&rsdp_v2_bytes(35)),
            Err(DmarError::InvalidStructure)
        ));
        assert_eq!(
            validate_rsdp_bytes(&rsdp_v2_bytes(36)),
            Ok((0x1234, 0x5678))
        );
        assert_eq!(
            validate_rsdp_bytes(&rsdp_v2_bytes(64)),
            Ok((0x1234, 0x5678))
        );
        assert!(matches!(
            validate_rsdp_bytes(&rsdp_v2_bytes(MAX_RSDP_BYTES + 1)),
            Err(DmarError::ResourceLimit)
        ));
    }

    #[test]
    fn rf180_39_rsdp_recovery_preserves_fail_closed_provenance() {
        let fallback = (0x1234, 0x5678);

        assert_eq!(
            resolve_rsdp_roots(Some(RsdpResult::Invalid), Some(fallback)),
            Ok(fallback)
        );
        assert_eq!(
            resolve_rsdp_roots(Some(RsdpResult::Invalid), None),
            Err(DmarError::InvalidStructure)
        );
        assert_eq!(resolve_rsdp_roots(None, None), Err(DmarError::NotFound));

        // Recovery is deliberately unavailable for stronger failure classes.
        assert_eq!(
            resolve_rsdp_roots(Some(RsdpResult::Unreadable), Some(fallback)),
            Err(DmarError::InvalidStructure)
        );
        assert_eq!(
            resolve_rsdp_roots(Some(RsdpResult::ResourceLimit), Some(fallback)),
            Err(DmarError::ResourceLimit)
        );
    }

    #[test]
    fn root_table_layout_enforces_byte_cap_and_alignment() {
        let header_len = core::mem::size_of::<AcpiHeader>();
        assert_eq!(
            validate_root_table_layout(MAX_ACPI_ROOT_TABLE_BYTES, 4),
            Ok((MAX_ACPI_ROOT_TABLE_BYTES - header_len) / 4)
        );
        assert!(matches!(
            validate_root_table_layout(MAX_ACPI_ROOT_TABLE_BYTES + 1, 4),
            Err(DmarError::ResourceLimit)
        ));
        assert!(matches!(
            validate_root_table_layout(header_len + 1, 4),
            Err(DmarError::InvalidStructure)
        ));
    }

    #[test]
    fn valid_mixed_table_parses_after_two_pass_reservation() {
        let drhd_scope = device_scope(DEVICE_SCOPE_PCI_ENDPOINT, 0, 4, &[(1, 0), (2, 3)]);
        let rmrr_scope = device_scope(DEVICE_SCOPE_IOAPIC, 7, 0, &[(3, 1)]);
        let atsr_scope = device_scope(DEVICE_SCOPE_PCI_BRIDGE, 0, 0, &[(4, 0)]);
        let table = table_with_structures(vec![
            drhd_with_scope_bytes(&drhd_scope),
            rmrr_with_scope_bytes(&rmrr_scope),
            atsr_with_scope_bytes(&atsr_scope),
            satc_with_scope_bytes(&atsr_scope),
            sidp_with_scope_bytes(&atsr_scope),
            rhsa(),
            andd(),
        ]);

        let parsed = parse(&table).expect("valid mixed DMAR");
        assert_eq!(parsed.host_address_width(), 48);
        assert!(parsed.interrupt_remap_required());
        assert_eq!(parsed.drhd_count(), 1);
        assert_eq!(parsed.rmrr_count(), 1);

        let drhd = parsed.drhd_iter().next().unwrap();
        assert!(drhd.include_pci_all());
        assert_eq!(drhd.segment(), 2);
        assert_eq!(drhd.register_base(), 0xfee0_0000);
        assert_eq!(drhd.device_scopes().len(), 1);
        assert_eq!(drhd.device_scopes()[0].start_bus, 4);
        assert_eq!(drhd.device_scopes()[0].path.as_slice(), &[(1, 0), (2, 3)]);

        let rmrr = parsed.rmrr_iter().next().unwrap();
        assert_eq!(rmrr.segment(), 3);
        assert_eq!(rmrr.base(), 0x1000);
        assert_eq!(rmrr.limit(), 0x1fff);
        assert_eq!(rmrr.device_scopes.len(), 1);
        assert_eq!(rmrr.device_scopes[0].scope_type, DeviceScopeType::Ioapic(7));
    }

    #[test]
    fn drhd_count_over_cap_is_rejected_before_allocation() {
        let mut structures = Vec::new();
        for _ in 0..=MAX_IOMMU_UNITS {
            structures.push(drhd_with_scope_bytes(&[]));
        }
        let table = table_with_structures(structures);
        assert!(matches!(parse(&table), Err(DmarError::ResourceLimit)));
    }

    #[test]
    fn rmrr_count_over_cap_is_rejected_before_allocation() {
        let mut structures = Vec::new();
        for _ in 0..=MAX_DMAR_RMRR_ENTRIES {
            structures.push(rmrr_with_scope_bytes(&[]));
        }
        let table = table_with_structures(structures);
        assert!(matches!(parse(&table), Err(DmarError::ResourceLimit)));
    }

    #[test]
    fn structure_and_scope_counts_are_hard_capped() {
        let mut unknown_structures = Vec::new();
        for _ in 0..=MAX_DMAR_STRUCTURES {
            unknown_structures.push(fixed_length_structure(0x7fff, 4));
        }
        let table = table_with_structures(unknown_structures);
        assert!(matches!(parse(&table), Err(DmarError::ResourceLimit)));

        let table = table_with_structures(vec![drhd_with_repeated_scope(
            MAX_DEVICE_SCOPES_PER_STRUCTURE + 1,
        )]);
        assert!(matches!(parse(&table), Err(DmarError::ResourceLimit)));
    }

    #[test]
    fn path_pair_count_over_cap_is_rejected() {
        let path = vec![(1, 0); MAX_PATH_PAIRS_PER_SCOPE + 1];
        let scope = device_scope(DEVICE_SCOPE_PCI_ENDPOINT, 0, 0, &path);
        let table = table_with_structures(vec![drhd_with_scope_bytes(&scope)]);
        assert!(matches!(parse(&table), Err(DmarError::ResourceLimit)));
    }

    #[test]
    fn total_scope_and_path_counts_include_skipped_structures() {
        let minimal_scope = device_scope(DEVICE_SCOPE_PCI_ENDPOINT, 0, 0, &[]);
        let mut full_scope_body = Vec::new();
        for _ in 0..MAX_DEVICE_SCOPES_PER_STRUCTURE {
            full_scope_body.extend_from_slice(&minimal_scope);
        }
        let mut structures = Vec::new();
        for _ in 0..(MAX_TOTAL_DEVICE_SCOPES / MAX_DEVICE_SCOPES_PER_STRUCTURE) {
            structures.push(atsr_with_scope_bytes(&full_scope_body));
        }
        structures.push(atsr_with_scope_bytes(&minimal_scope));
        let table = table_with_structures(structures);
        assert!(matches!(parse(&table), Err(DmarError::ResourceLimit)));

        let max_path = vec![(1, 0); MAX_PATH_PAIRS_PER_SCOPE];
        let max_path_scope = device_scope(DEVICE_SCOPE_PCI_ENDPOINT, 0, 0, &max_path);
        let scope_count = MAX_TOTAL_PATH_PAIRS / MAX_PATH_PAIRS_PER_SCOPE + 1;
        let mut scope_body = Vec::new();
        for _ in 0..scope_count {
            scope_body.extend_from_slice(&max_path_scope);
        }
        let table = table_with_structures(vec![atsr_with_scope_bytes(&scope_body)]);
        assert!(matches!(parse(&table), Err(DmarError::ResourceLimit)));
    }

    #[test]
    fn odd_path_bytes_are_rejected() {
        let malformed_scope = vec![DEVICE_SCOPE_PCI_ENDPOINT, 7, 0, 0, 0, 0, 1];
        let table = table_with_structures(vec![drhd_with_scope_bytes(&malformed_scope)]);
        assert!(matches!(parse(&table), Err(DmarError::InvalidStructure)));
    }

    #[test]
    fn invalid_header_address_and_path_encodings_are_rejected() {
        let mut table = table_with_structures(vec![drhd_with_scope_bytes(&[])]);
        let dmar_offset = core::mem::size_of::<AcpiHeader>();
        table[dmar_offset] = 0;
        table = finish_table(table);
        assert!(matches!(parse(&table), Err(DmarError::InvalidStructure)));

        let mut table = table_with_structures(vec![drhd_with_scope_bytes(&[])]);
        table[dmar_offset + 1] = 0x80;
        table = finish_table(table);
        assert!(matches!(parse(&table), Err(DmarError::InvalidStructure)));

        let bad_path = device_scope(DEVICE_SCOPE_PCI_ENDPOINT, 0, 0, &[(32, 0)]);
        let table = table_with_structures(vec![drhd_with_scope_bytes(&bad_path)]);
        assert!(matches!(parse(&table), Err(DmarError::InvalidStructure)));

        let bad_path = device_scope(DEVICE_SCOPE_PCI_ENDPOINT, 0, 0, &[(1, 8)]);
        let table = table_with_structures(vec![drhd_with_scope_bytes(&bad_path)]);
        assert!(matches!(parse(&table), Err(DmarError::InvalidStructure)));
    }

    #[test]
    fn malformed_drhd_and_rmrr_addresses_are_rejected() {
        let mut drhd = drhd_with_scope_bytes(&[]);
        drhd[8..16].copy_from_slice(&0xfee0_0001u64.to_le_bytes());
        let table = table_with_structures(vec![drhd]);
        assert!(matches!(parse(&table), Err(DmarError::InvalidStructure)));

        let mut rmrr = rmrr_with_scope_bytes(&[]);
        rmrr[8..16].copy_from_slice(&0x3000u64.to_le_bytes());
        rmrr[16..24].copy_from_slice(&0x1fffu64.to_le_bytes());
        let table = table_with_structures(vec![rmrr]);
        assert!(matches!(parse(&table), Err(DmarError::InvalidStructure)));

        let mut rmrr = rmrr_with_scope_bytes(&[]);
        rmrr[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        let table = table_with_structures(vec![rmrr]);
        assert!(matches!(parse(&table), Err(DmarError::InvalidStructure)));
    }

    #[test]
    fn truncated_scope_header_and_body_are_rejected() {
        let short_header = vec![DEVICE_SCOPE_PCI_ENDPOINT, 6, 0, 0, 0];
        let table = table_with_structures(vec![drhd_with_scope_bytes(&short_header)]);
        assert!(matches!(parse(&table), Err(DmarError::InvalidStructure)));

        let truncated_body = vec![DEVICE_SCOPE_PCI_ENDPOINT, 8, 0, 0, 0, 0];
        let table = table_with_structures(vec![drhd_with_scope_bytes(&truncated_body)]);
        assert!(matches!(parse(&table), Err(DmarError::InvalidStructure)));
    }

    #[test]
    fn truncated_remapping_header_and_body_are_rejected() {
        let mut table = table_with_structures(Vec::new());
        table.extend_from_slice(&[0, 0, 4]);
        table = finish_table(table);
        assert!(matches!(parse(&table), Err(DmarError::InvalidStructure)));

        let truncated = declared_structure(0x7fff, 8, &[]);
        let table = table_with_structures(vec![truncated]);
        assert!(matches!(parse(&table), Err(DmarError::InvalidStructure)));
    }

    #[test]
    fn too_short_known_structures_are_rejected() {
        let malformed = [
            fixed_length_structure(DMAR_TYPE_DRHD, core::mem::size_of::<DrhdRaw>() - 1),
            fixed_length_structure(DMAR_TYPE_RMRR, core::mem::size_of::<RmrrRaw>() - 1),
            fixed_length_structure(DMAR_TYPE_ATSR, core::mem::size_of::<AtsrRaw>() - 1),
            fixed_length_structure(DMAR_TYPE_SATC, core::mem::size_of::<SatcRaw>() - 1),
            fixed_length_structure(DMAR_TYPE_SIDP, core::mem::size_of::<SidpRaw>() - 1),
            fixed_length_structure(DMAR_TYPE_RHSA, core::mem::size_of::<RhsaRaw>() - 1),
            fixed_length_structure(DMAR_TYPE_RHSA, core::mem::size_of::<RhsaRaw>() + 1),
            fixed_length_structure(DMAR_TYPE_ANDD, core::mem::size_of::<AnddRaw>()),
        ];
        for structure in malformed {
            let table = table_with_structures(vec![structure]);
            assert!(matches!(parse(&table), Err(DmarError::InvalidStructure)));
        }

        let mut unterminated_andd =
            fixed_length_structure(DMAR_TYPE_ANDD, core::mem::size_of::<AnddRaw>() + 1);
        *unterminated_andd.last_mut().unwrap() = b'A';
        let table = table_with_structures(vec![unterminated_andd]);
        assert!(matches!(parse(&table), Err(DmarError::InvalidStructure)));
    }

    #[test]
    fn parsed_memory_budget_is_enforced_before_materialization() {
        let requested_bytes = MAX_IOMMU_UNITS * core::mem::size_of::<DrhdEntry>()
            + MAX_IOMMU_UNITS
                * MAX_DEVICE_SCOPES_PER_STRUCTURE
                * core::mem::size_of::<DeviceScope>();
        assert!(requested_bytes > MAX_DMAR_PARSED_BYTES);

        let mut structures = Vec::new();
        for _ in 0..MAX_IOMMU_UNITS {
            structures.push(drhd_with_repeated_scope(MAX_DEVICE_SCOPES_PER_STRUCTURE));
        }
        let table = table_with_structures(structures);
        assert!(matches!(parse(&table), Err(DmarError::ResourceLimit)));
    }

    #[test]
    fn raw_table_byte_budget_is_enforced() {
        let fixed_header_len =
            core::mem::size_of::<AcpiHeader>() + core::mem::size_of::<DmarHeader>();
        let mut table = vec![0; MAX_DMAR_TABLE_BYTES + 1];
        table[0..4].copy_from_slice(&DMAR_SIGNATURE);
        table[8] = 1;
        table[core::mem::size_of::<AcpiHeader>()] = 47;
        assert!(table.len() > fixed_header_len);
        let table = finish_table(table);
        assert!(matches!(parse(&table), Err(DmarError::ResourceLimit)));
    }
}
