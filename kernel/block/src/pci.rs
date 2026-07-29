//! Minimal PCI helper for virtio-blk probing (CF8/CFC)
//!
//! Provides:
//! - pci_config_read32 / pci_config_write16 using legacy I/O ports
//! - probe_virtio_blk: scan PCI buses for virtio-blk (transitional 0x1001 / modern 0x1042)
//! - PCI capability parsing for virtio-pci modern transport

use core::arch::asm;

use crate::virtio::VirtioPciAddrs;
use iommu::{attach_device, PciDeviceId};

const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

const VIRTIO_VENDOR: u16 = 0x1af4;
// 0x1001 is transitional (QEMU default) - may expose modern PCI capabilities
const VIRTIO_BLK_TRANSITIONAL: u16 = 0x1001;
const VIRTIO_BLK_MODERN: u16 = 0x1042;

const PCI_COMMAND_OFFSET: u8 = 0x04;
const PCI_COMMAND_MEMORY_SPACE: u16 = 0x02;
const PCI_COMMAND_BUS_MASTER: u16 = 0x04;
const PCI_BAR0_OFFSET: u8 = 0x10;
const PCI_SUBSYSTEM_ID: u8 = 0x2E; // Subsystem ID (contains virtio device type)
const PCI_CAP_PTR: u8 = 0x34;

/// VirtIO PCI capability types (VirtIO 1.1 Section 4.1.4)
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

/// Vendor-specific capability ID for VirtIO
const PCI_CAP_ID_VNDR: u8 = 0x09;

/// Write 32-bit value to an I/O port
#[inline]
unsafe fn outl(port: u16, val: u32) {
    asm!("out dx, eax", in("dx") port, in("eax") val, options(nostack, preserves_flags));
}

/// Read 32-bit value from an I/O port
#[inline]
unsafe fn inl(port: u16) -> u32 {
    let val: u32;
    asm!("in eax, dx", out("eax") val, in("dx") port, options(nostack, preserves_flags));
    val
}

/// Build config address and read 32 bits from PCI configuration space.
///
/// # Arguments
/// * `bus` - PCI bus number (0-255)
/// * `dev` - Device number on the bus (0-31)
/// * `func` - Function number (0-7)
/// * `offset` - Register offset in configuration space (must be 4-byte aligned)
pub fn pci_config_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let aligned = (offset & 0xFC) as u32;
    let address = 0x8000_0000u32
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | aligned;
    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        inl(PCI_CONFIG_DATA)
    }
}

/// Write 16 bits into PCI configuration space (read-modify-write).
///
/// # Arguments
/// * `bus` - PCI bus number
/// * `dev` - Device number
/// * `func` - Function number
/// * `offset` - Register offset (2-byte aligned)
/// * `val` - Value to write
pub fn pci_config_write16(bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
    let aligned = offset & 0xFC;
    let shift = ((offset & 2) * 8) as u32;
    let mut dword = pci_config_read32(bus, dev, func, aligned);
    let mask = !(0xFFFFu32 << shift);
    dword = (dword & mask) | ((val as u32) << shift);
    let address = 0x8000_0000u32
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | (aligned as u32);
    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        outl(PCI_CONFIG_DATA, dword);
    }
}

/// Read 8-bit value from PCI configuration space.
#[inline]
fn pci_config_read8(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    let shift = (offset & 3) * 8;
    (pci_config_read32(bus, dev, func, offset & 0xFC) >> shift) as u8
}

/// Read 16-bit value from PCI configuration space.
#[inline]
fn pci_config_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let shift = (offset & 2) * 8;
    (pci_config_read32(bus, dev, func, offset & 0xFC) >> shift) as u16
}

/// R180-17 FIX: clear and verify PCI bus-master enable on refusal paths.
///
/// Firmware/warm-boot may leave BME set. Skipping a device without clearing
/// BME leaves it capable of untranslated DMA when IOMMU attach failed. The
/// caller must hold [`iommu::PCI_CONFIG_LOCK`] across this operation so the
/// command-register RMW and readback are one atomic PCI-config transaction.
#[must_use = "failure to clear PCI bus mastering must be handled fail-closed"]
fn clear_bus_master(bus: u8, dev: u8, func: u8) -> bool {
    let cmd = (pci_config_read32(bus, dev, func, PCI_COMMAND_OFFSET) & 0xFFFF) as u16;
    pci_config_write16(
        bus,
        dev,
        func,
        PCI_COMMAND_OFFSET,
        cmd & !PCI_COMMAND_BUS_MASTER,
    );
    let verify = (pci_config_read32(bus, dev, func, PCI_COMMAND_OFFSET) & 0xFFFF) as u16;
    let cleared = verify & PCI_COMMAND_BUS_MASTER == 0;
    if !cleared {
        klog!(
            Warn,
            "    ! BME still set after clear for {:02x}:{:02x}.{}",
            bus,
            dev,
            func
        );
    }
    cleared
}

/// R186-6: disable both address decode and DMA before a BAR sizing probe.
///
/// Firmware may leave Memory Space Enable set across a warm boot. BAR sizing
/// temporarily writes all-ones into the address registers, so probing with MSE
/// set can make the device claim the probe address. The caller holds the global
/// PCI config lock; keep the clear and readback in that same transaction.
#[must_use = "failure to disable PCI decoders must be handled fail-closed"]
fn clear_memory_and_bus_master(bus: u8, dev: u8, func: u8) -> bool {
    let cmd = (pci_config_read32(bus, dev, func, PCI_COMMAND_OFFSET) & 0xFFFF) as u16;
    let disabled = PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER;
    pci_config_write16(bus, dev, func, PCI_COMMAND_OFFSET, cmd & !disabled);
    let verify = (pci_config_read32(bus, dev, func, PCI_COMMAND_OFFSET) & 0xFFFF) as u16;
    let cleared = verify & disabled == 0;
    if !cleared {
        klog!(
            Warn,
            "    ! MSE/BME still set after clear for {:02x}:{:02x}.{}",
            bus,
            dev,
            func
        );
    }
    cleared
}

/// Disable and verify PCI bus mastering for a discovered block device.
///
/// This wrapper owns the shared PCI-config lock and is safe to call from
/// driver failure/recovery paths that are outside the initial PCI scan.
#[must_use = "failure to clear PCI bus mastering must be handled fail-closed"]
pub fn disable_bus_master(pci_id: PciDeviceId) -> bool {
    // Legacy CF8/CFC configuration access can address only segment zero. Do
    // not report success after accidentally touching the same BDF elsewhere.
    if pci_id.segment != 0 {
        klog!(
            Warn,
            "    ! Cannot clear BME for unsupported PCI segment {}",
            pci_id.segment
        );
        return false;
    }
    let _pci_lock = iommu::PCI_CONFIG_LOCK.lock();
    clear_bus_master(pci_id.bus, pci_id.device, pci_id.function)
}

/// Read a BAR (Base Address Register) and return the physical address.
///
/// Handles both 32-bit and 64-bit BARs. Returns None for I/O BARs.
/// R186-6: minimum bytes the block driver actually accesses in each window.
/// `VirtioPciCommonCfg` is 56 bytes; notify is a `u16`; ISR is one byte; the
/// virtio-blk config carries at least the 8-byte capacity field.
const VIRTIO_COMMON_CFG_MIN_LEN: u64 = 56;
const VIRTIO_NOTIFY_MIN_LEN: u64 = 2;
const VIRTIO_ISR_MIN_LEN: u64 = 1;
const VIRTIO_BLK_DEVICE_CFG_MIN_LEN: u64 = 8;

/// R186-6: a memory BAR whose base AND SIZE are both known.
///
/// Mirrors `net::pci::ValidatedBar`. The two drivers keep separate config-space
/// accessors (this one runs with `PCI_CONFIG_LOCK` held across the whole scan,
/// the net one locks per access), so the type is duplicated rather than shared;
/// the containment rule they enforce is identical.
#[derive(Clone, Copy, Debug)]
struct ValidatedBar {
    base: u64,
    len: u64,
}

impl ValidatedBar {
    /// Is `[offset, offset + len)` wholly inside this aperture? All arithmetic is
    /// checked — the release profile enables no overflow checks, so an unchecked
    /// sum on device-supplied values wraps silently and passes a naive compare.
    fn phys_for(&self, offset: u64, len: u64) -> Option<u64> {
        if len == 0 {
            return None;
        }
        let end = offset.checked_add(len)?;
        if end > self.len {
            return None;
        }
        self.base.checked_add(offset)
    }
}

/// R186-6: determine a memory BAR's base and size via the spec write-all-ones
/// probe. See `net::pci::size_bar` for the full rationale; the ordering
/// requirements are the same — Memory Space decode must be OFF, and the original
/// BAR value is restored on every path.
///
/// NOTE: unlike the net driver, callers here already hold `PCI_CONFIG_LOCK` for
/// the whole bus scan, so this must NOT take it again (it is not reentrant).
fn size_bar(bus: u8, dev: u8, func: u8, bar: u8) -> Option<ValidatedBar> {
    if bar >= 6 {
        return None;
    }
    let off = PCI_BAR0_OFFSET + bar * 4;
    let low = pci_config_read32(bus, dev, func, off);

    // Check if this is an I/O BAR (bit 0 = 1)
    if low & 1 != 0 {
        return None;
    }

    // Check BAR type (bits 1-2). 1 and 3 are reserved encodings; treating them as
    // 32-bit (as the old code did) invents an aperture width for a malformed BAR.
    let bar_type = (low >> 1) & 0x3;
    let is_64bit = match bar_type {
        0 => false,
        2 => true,
        _ => return None,
    };
    if is_64bit && bar >= 5 {
        return None; // No room for the high dword
    }

    let high = if is_64bit {
        pci_config_read32(bus, dev, func, off + 4)
    } else {
        0
    };
    let base = ((low & !0xFu32) as u64) | ((high as u64) << 32);
    if base == 0 {
        return None;
    }

    let (size_low, size_high) = probe_bar(bus, dev, func, off, low, is_64bit.then_some(high));

    let mask = ((size_low & !0xFu32) as u64) | ((size_high as u64) << 32);
    if mask == 0 {
        return None; // Unimplemented BAR
    }
    let len = (!mask).wrapping_add(1);
    if len == 0 || !len.is_power_of_two() || base % len != 0 {
        return None;
    }
    base.checked_add(len)?;

    Some(ValidatedBar { base, len })
}

/// R186-6: perform one atomic BAR sizing transaction and restore the BAR.
///
/// A 64-bit BAR is one resource, so both halves must contain all-ones before
/// either mask half is read. Probing each dword independently can return a mask
/// that never existed as one device resource. The caller already holds
/// `PCI_CONFIG_LOCK`, and Memory Space decode has been verified off.
fn probe_bar(
    bus: u8,
    dev: u8,
    func: u8,
    offset: u8,
    original_low: u32,
    original_high: Option<u32>,
) -> (u32, u32) {
    let low_address = 0x8000_0000u32
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset & 0xFC) as u32);
    let high_address = low_address + 4;
    unsafe {
        outl(PCI_CONFIG_ADDRESS, low_address);
        outl(PCI_CONFIG_DATA, u32::MAX);
        if original_high.is_some() {
            outl(PCI_CONFIG_ADDRESS, high_address);
            outl(PCI_CONFIG_DATA, u32::MAX);
        }

        outl(PCI_CONFIG_ADDRESS, low_address);
        let readback_low = inl(PCI_CONFIG_DATA);
        let readback_high = if original_high.is_some() {
            outl(PCI_CONFIG_ADDRESS, high_address);
            inl(PCI_CONFIG_DATA)
        } else {
            u32::MAX
        };

        // Restore the high half first and the low half last. Decode is disabled,
        // but this ordering also avoids exposing an original low half paired with
        // an all-ones high half if the device observes config writes internally.
        if let Some(high) = original_high {
            outl(PCI_CONFIG_ADDRESS, high_address);
            outl(PCI_CONFIG_DATA, high);
        }
        outl(PCI_CONFIG_ADDRESS, low_address);
        outl(PCI_CONFIG_DATA, original_low);
        (readback_low, readback_high)
    }
}

/// Parse VirtIO PCI capabilities from the capability list.
///
/// Walks the PCI capability list looking for VirtIO-specific capabilities
/// (vendor ID 0x09) and extracts the addresses for common config, notify,
/// ISR, and device-specific config regions.
fn read_virtio_pci_caps(bus: u8, dev: u8, func: u8) -> Option<VirtioPciAddrs> {
    let mut caps = VirtioPciAddrs::default();
    let mut found_caps = 0u8;
    // R186-6: inventory BARs sequentially before trusting a capability's BAR
    // index. A 64-bit BAR consumes two slots; leaving the high slot lazily
    // probeable would let a hostile capability reinterpret it as an independent
    // 32-bit aperture.
    let mut bar_cache: [Option<ValidatedBar>; 6] = [None; 6];
    let mut bar = 0u8;
    while bar < 6 {
        let low = pci_config_read32(bus, dev, func, PCI_BAR0_OFFSET + bar * 4);
        let consumes_pair = low & 1 == 0 && ((low >> 1) & 0x3) == 2;
        bar_cache[usize::from(bar)] = size_bar(bus, dev, func, bar);
        bar = bar.saturating_add(if consumes_pair { 2 } else { 1 });
    }

    // Start from the capability pointer
    let mut ptr = pci_config_read8(bus, dev, func, PCI_CAP_PTR);

    // Walk the capability list (max 48 iterations to prevent infinite loop)
    for _ in 0..48 {
        // R169-L8 FIX: `ptr` is driven by the device-controlled `next` byte and
        // the per-cap reads compute `ptr + N` as a u8 (config offsets are u8). A
        // virtio cap is processed only when cap_len >= 16 (it occupies
        // ptr..ptr+15), so a valid start cannot exceed 0xF0 (ptr+15 <= 0xFF).
        // Reject ptr outside [0x40, 0xF0] so the base + notify-len reads (up to
        // ptr+12) never wrap u8 and never read outside the 256-byte config
        // space; the deeper ptr+16 notify-multiplier read is bounded separately
        // below. Without this a malicious device advertising a cap pointer in
        // 0xF1..=0xFF wraps the u8 add (release: misread offset; with
        // overflow-checks: panic-DoS).
        if !(0x40..=0xF0).contains(&ptr) {
            break;
        }

        let cap_id = pci_config_read8(bus, dev, func, ptr);
        let next = pci_config_read8(bus, dev, func, ptr + 1);
        let cap_len = pci_config_read8(bus, dev, func, ptr + 2);

        // Check for VirtIO vendor-specific capability
        if cap_id == PCI_CAP_ID_VNDR && cap_len >= 16 {
            // VirtIO PCI capability structure:
            // offset 0: cap_vndr (0x09)
            // offset 1: cap_next
            // offset 2: cap_len
            // offset 3: cfg_type (1=common, 2=notify, 3=isr, 4=device)
            // offset 4: bar
            // offset 5-7: padding
            // offset 8-11: offset within BAR
            // offset 12-15: length
            let cfg_type = pci_config_read8(bus, dev, func, ptr + 3);
            let bar = pci_config_read8(bus, dev, func, ptr + 4);
            let offset = pci_config_read32(bus, dev, func, ptr + 8);
            // R186-6: the capability's declared length, previously read only for
            // the notify cap. Every window needs a recorded extent to validate.
            let cap_window_len = pci_config_read32(bus, dev, func, ptr + 12);

            found_caps += 1;

            // R186-6: prove the FULL declared window lies inside a SIZED BAR
            // aperture before deriving a physical address from it. The old
            // `bar_base + offset` had no length and no bound, so a hostile device
            // could point CPU MMIO writes anywhere — outside IOMMU DMA containment.
            let required_len = match cfg_type {
                VIRTIO_PCI_CAP_COMMON_CFG => VIRTIO_COMMON_CFG_MIN_LEN,
                VIRTIO_PCI_CAP_NOTIFY_CFG => VIRTIO_NOTIFY_MIN_LEN,
                VIRTIO_PCI_CAP_ISR_CFG => VIRTIO_ISR_MIN_LEN,
                VIRTIO_PCI_CAP_DEVICE_CFG => VIRTIO_BLK_DEVICE_CFG_MIN_LEN,
                _ => 0,
            };

            if required_len != 0 && (cap_window_len as u64) >= required_len {
                let resource = bar_cache.get(usize::from(bar)).copied().flatten();

                if let Some(phys) =
                    resource.and_then(|res| res.phys_for(offset as u64, cap_window_len as u64))
                {
                    match cfg_type {
                        VIRTIO_PCI_CAP_COMMON_CFG => {
                            caps.common_cfg = phys;
                            caps.common_cfg_len = cap_window_len;
                        }
                        VIRTIO_PCI_CAP_NOTIFY_CFG => {
                            caps.notify_base = phys;
                            // R34-VIRTIO-1 FIX: notify length for bounds checking.
                            caps.notify_len = cap_window_len;
                            // Notify capability has extra field at offset 16
                            // R169-L8 FIX: ptr+16 must not wrap the u8 add; only read
                            // it when ptr <= 0xEF (0xEF+16 == 0xFF). A cap claiming
                            // length >= 20 at a higher start is malformed — skip the
                            // optional multiplier rather than overflow.
                            if cap_len >= 20 && ptr <= 0xEF {
                                caps.notify_off_multiplier =
                                    pci_config_read32(bus, dev, func, ptr + 16);
                            }
                        }
                        VIRTIO_PCI_CAP_ISR_CFG => {
                            caps.isr = phys;
                            caps.isr_len = cap_window_len;
                        }
                        VIRTIO_PCI_CAP_DEVICE_CFG => {
                            caps.device_cfg = phys;
                            caps.device_cfg_len = cap_window_len;
                        }
                        _ => {}
                    }
                }
            }
        }

        if next == 0 {
            break;
        }
        ptr = next;
    }

    // Validate that we have the required capabilities
    if caps.common_cfg != 0 && caps.notify_base != 0 && caps.device_cfg != 0 {
        Some(caps)
    } else {
        None
    }
}

/// Probe PCI buses for the first virtio-blk device.
///
/// Scans all device slots on buses 0-255 looking for a virtio-blk device
/// (vendor 0x1af4, device 0x1001 transitional or 0x1042 modern).
///
/// When found, disables device decoders, validates and sizes all capability
/// windows, then enables memory access and bus mastering.
///
/// # Returns
/// * `Some((pci_id, pci_addrs, device_name))` - Found device with modern virtio-pci capabilities
/// * `None` - No compatible virtio-blk device found
pub fn probe_virtio_blk(
    iommu_required: bool,
) -> Option<(PciDeviceId, VirtioPciAddrs, &'static str)> {
    // R161-15 FIX: Acquire shared PCI config lock to prevent concurrent
    // access with IOMMU's PCI operations on SMP.
    let _pci_lock = iommu::PCI_CONFIG_LOCK.lock();

    // Scan all PCI buses (0-255)
    for bus in 0u8..=255 {
        for dev in 0u8..32 {
            // Check function 0 first
            let header_type = pci_config_read8(bus, dev, 0, 0x0E);
            let max_func = if header_type & 0x80 != 0 { 8 } else { 1 };

            for func in 0u8..max_func {
                let id = pci_config_read32(bus, dev, func, 0x00);

                // Check for valid device (0xFFFF vendor = no device)
                let vendor = (id & 0xFFFF) as u16;
                if vendor == 0xFFFF {
                    if func == 0 {
                        break; // No device at this slot
                    }
                    continue;
                }

                let device = ((id >> 16) & 0xFFFF) as u16;

                if vendor != VIRTIO_VENDOR {
                    continue;
                }
                if device != VIRTIO_BLK_TRANSITIONAL && device != VIRTIO_BLK_MODERN {
                    continue;
                }

                // R186-6: firmware may leave both DMA and memory decode active.
                // Disable and verify both before IOMMU attach and, critically,
                // before the write-all-ones BAR sizing transaction below.
                if !clear_memory_and_bus_master(bus, dev, func) {
                    panic!(
                        "R186-6: cannot fail closed: PCI MSE/BME remains set for {:02x}:{:02x}.{}",
                        bus, dev, func
                    );
                }

                // Attach device to IOMMU before enabling bus mastering (fail-closed)
                // R94-14 FIX: Handle NotAvailable explicitly - proceed with warning
                // for legacy systems without IOMMU, but fail on other errors.
                let pci_id = PciDeviceId::from_bdf(bus, dev, func);
                match attach_device(pci_id) {
                    Ok(()) => {}
                    Err(iommu::IommuError::NotAvailable) => {
                        // R171-G5-01-C FIX: Secure profile refuses bus-master for a
                        // device that cannot be IOMMU-isolated (fail closed).
                        // klog_force! pierces the Secure diagnostic blackout.
                        if iommu_required {
                            klog_force!(
                                "    ! [SECURE] Refusing bus-master for {:02x}:{:02x}.{} — no IOMMU isolation",
                                bus, dev, func
                            );
                            // BME already cleared above.
                            continue;
                        }
                        // IOMMU not present - proceed without DMA isolation (legacy mode)
                        // This is an explicit acknowledgment of the security tradeoff.
                        klog!(
                            Warn,
                            "    ! WARNING: No IOMMU - {:02x}:{:02x}.{} has unprotected DMA access",
                            bus,
                            dev,
                            func
                        );
                    }
                    Err(err) => {
                        // Other IOMMU errors - fail closed (skip device)
                        klog!(
                            Warn,
                            "    ! IOMMU attach failed for {:02x}:{:02x}.{}: {:?}",
                            bus,
                            dev,
                            func,
                            err
                        );
                        // BME already cleared above.
                        continue;
                    }
                }

                // Size BARs and validate every declared capability window while
                // Memory Space decode is still off. Enable decode/DMA only after
                // that containment proof succeeds.
                if let Some(mut caps) = read_virtio_pci_caps(bus, dev, func) {
                    let mut cmd =
                        (pci_config_read32(bus, dev, func, PCI_COMMAND_OFFSET) & 0xFFFF) as u16;
                    cmd |= PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER;
                    pci_config_write16(bus, dev, func, PCI_COMMAND_OFFSET, cmd);

                    // Read subsystem ID which contains the virtio device type
                    let subsystem_id = pci_config_read16(bus, dev, func, PCI_SUBSYSTEM_ID);
                    caps.virtio_device_type = subsystem_id;

                    let dev_type = if device == VIRTIO_BLK_MODERN {
                        "modern"
                    } else {
                        "transitional"
                    };
                    klog!(Info,
                        "    Found virtio-blk ({}) at PCI {:02x}:{:02x}.{}, type={}, common_cfg={:#x}",
                        dev_type, bus, dev, func, subsystem_id, caps.common_cfg
                    );
                    return Some((pci_id, caps, "vda"));
                } else {
                    // Keep both decoders disabled when capability validation
                    // fails; verify the fail-closed state before continuing.
                    if !clear_memory_and_bus_master(bus, dev, func) {
                        panic!(
                            "R186-6: cannot fail closed: PCI MSE/BME remains set for {:02x}:{:02x}.{}",
                            bus, dev, func
                        );
                    }
                    let dev_type = if device == VIRTIO_BLK_MODERN {
                        "modern"
                    } else {
                        "transitional"
                    };
                    klog!(Warn,
                        "    virtio-blk ({}) at PCI {:02x}:{:02x}.{} lacks modern capabilities (bus master disabled)",
                        dev_type, bus, dev, func
                    );
                }
            }
        }
    }
    None
}
