//! PCI scanning for network devices.
//!
//! This module provides PCI bus scanning to discover virtio-net devices.

use alloc::vec::Vec;
use core::arch::asm;
// R165-20 FIX: Share the IOMMU's PCI config lock so this module's CF8/CFC
// accesses are serialized against the IOMMU isolation code (the only other
// PCI config-space user). Without it, an RMW here could interleave with an
// IOMMU config access on another CPU and corrupt the CF8 address latch.
use iommu::{attach_device, PciDeviceId, PCI_CONFIG_LOCK};
use virtio::{VirtioPciAddrs, VirtioPciBarWindow};

// ============================================================================
// PCI Constants
// ============================================================================

const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

const VIRTIO_VENDOR: u16 = 0x1AF4;
const VIRTIO_NET_TRANSITIONAL: u16 = 0x1000; // Legacy/transitional device ID
const VIRTIO_NET_MODERN: u16 = 0x1041; // Modern device ID

const PCI_COMMAND: u8 = 0x04;
const PCI_COMMAND_MEMORY_SPACE: u16 = 0x02;
const PCI_COMMAND_BUS_MASTER: u16 = 0x04;
const PCI_BAR0: u8 = 0x10;
const PCI_SUBSYSTEM_ID: u8 = 0x2E;
const PCI_CAP_PTR: u8 = 0x34;

// VirtIO PCI capability types
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

const PCI_CAP_ID_VNDR: u8 = 0x09; // Vendor-specific capability

// ============================================================================
// PCI Device Info
// ============================================================================

/// PCI slot location.
#[derive(Debug, Clone, Copy)]
pub struct PciSlot {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

/// Discovered virtio-net PCI device.
#[derive(Debug, Clone, Copy)]
pub struct VirtioNetPciDevice {
    pub slot: PciSlot,
    pub addrs: VirtioPciAddrs,
}

// ============================================================================
// PCI Probing
// ============================================================================

/// Probe PCI buses for virtio-net devices.
pub fn probe_virtio_net(iommu_required: bool) -> Vec<VirtioNetPciDevice> {
    let mut devices = Vec::new();
    let mut total_pci_devices = 0;

    // Scan all PCI buses (only scan first few buses for speed)
    for bus in 0u8..8 {
        for dev in 0u8..32 {
            // Check if multi-function device
            let header_type = pci_read8(bus, dev, 0, 0x0E);
            let max_func = if header_type & 0x80 != 0 { 8 } else { 1 };

            for func in 0u8..max_func {
                let vendor_device = pci_read32(bus, dev, func, 0x00);
                let vendor = (vendor_device & 0xFFFF) as u16;

                if vendor == 0xFFFF {
                    if func == 0 {
                        break; // No device at this slot
                    }
                    continue;
                }

                total_pci_devices += 1;
                let device_id = ((vendor_device >> 16) & 0xFFFF) as u16;

                // Debug: Show all PCI devices found
                if vendor == VIRTIO_VENDOR {
                    klog!(Info,
                        "    [DEBUG] VirtIO device @ {:02x}:{:02x}.{}: device_id={:#x} subsystem_id={:#x}",
                        bus, dev, func, device_id, pci_read16(bus, dev, func, PCI_SUBSYSTEM_ID)
                    );
                }

                // Check for VirtIO vendor
                if vendor != VIRTIO_VENDOR {
                    continue;
                }

                // VirtIO device ID detection:
                // - Transitional network: device_id = 0x1000 (with subsystem_id = 1)
                // - Modern network: device_id = 0x1041
                // - Legacy scheme: device_id = 0x1000-0x103F with subsystem_id encoding type
                //
                // QEMU typically uses:
                // - 0x1000 for transitional network (subsystem_id = 1)
                // - 0x1001 for transitional block (subsystem_id = 2)

                let subsystem_id = pci_read16(bus, dev, func, PCI_SUBSYSTEM_ID);

                // Check if this is a network device
                let is_net = match device_id {
                    // Transitional virtio-net (QEMU uses this)
                    0x1000 => subsystem_id == 1,
                    // Modern virtio-net
                    0x1041 => true,
                    // Not a network device
                    _ => false,
                };

                if !is_net {
                    continue;
                }

                klog!(
                    Info,
                    "    Probing virtio-net candidate: {:02x}:{:02x}.{} device={:#x} subsys={:#x}",
                    bus,
                    dev,
                    func,
                    device_id,
                    subsystem_id
                );

                // R186-6: firmware may leave both MSE and BME set. Disable and
                // verify both before the write-all-ones BAR sizing transaction.
                disable_memory_and_bus_master_bdf(bus, dev, func);

                // Attach device to IOMMU before enabling bus mastering (fail-closed)
                // R94-14 FIX: Handle NotAvailable explicitly - proceed with warning
                // for legacy systems without IOMMU, but fail on other errors.
                let pci_id = PciDeviceId::from_bdf(bus, dev, func);
                match attach_device(pci_id) {
                    Ok(()) => {}
                    Err(iommu::IommuError::NotAvailable) => {
                        // R171-G5-01-C FIX: in the Secure profile, REFUSE bus-master
                        // for a device that cannot be IOMMU-isolated (fail closed)
                        // rather than enabling unprotected DMA. klog_force! so the
                        // refusal is visible under the Secure diagnostic blackout.
                        if iommu_required {
                            klog_force!(
                                "    ! [SECURE] Refusing bus-master for {:02x}:{:02x}.{} — no IOMMU isolation",
                                bus,
                                dev,
                                func
                            );
                            // BME already cleared above.
                            continue;
                        }
                        // IOMMU not present - proceed without DMA isolation (legacy mode)
                        // This is an explicit acknowledgment of the security tradeoff.
                        klog!(
                            Info,
                            "    ! WARNING: No IOMMU - {:02x}:{:02x}.{} has unprotected DMA access",
                            bus,
                            dev,
                            func
                        );
                    }
                    Err(err) => {
                        // Other IOMMU errors - fail closed (skip device)
                        klog!(
                            Info,
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

                // R186-6: parse and VALIDATE the capability windows BEFORE enabling
                // Memory Space decode.
                //
                // Ordering is a correctness requirement, not a preference. BAR
                // sizing writes all-ones into each BAR and reads back the mask; a
                // device that is actively decoding would claim that bogus range for
                // the duration of the probe. Bus Master was already cleared above
                // (R180-17), and Memory Space is still off here, so the probe is
                // safe. Enabling decode only after validation also means a device
                // whose windows fail containment never gets its decoders turned on
                // at all.
                let caps = read_virtio_caps(bus, dev, func);

                // RF186-4: enumeration returns authority only, never an active
                // DMA function. MSE is enabled only after the MMIO rollback
                // guard exists; BME is enabled only after every fallible queue
                // and publication resource has been prepared.

                // Try to read modern capabilities
                if let Some(mut addrs) = caps {
                    addrs.virtio_device_type = 1; // Network device

                    klog!(
                        Info,
                        "    Found virtio-net (PCI {:02x}:{:02x}.{}) common_cfg={:#x}",
                        bus,
                        dev,
                        func,
                        addrs.common_cfg.phys()
                    );

                    devices.push(VirtioNetPciDevice {
                        slot: PciSlot {
                            bus,
                            device: dev,
                            function: func,
                        },
                        addrs,
                    });
                } else {
                    // R82-1 FIX: Disable bus mastering if device lacks modern caps
                    // to prevent orphaned DMA-capable device
                    // R165-20 FIX: atomic RMW (see pci_update16).
                    disable_memory_and_bus_master_bdf(bus, dev, func);
                    klog!(Info,
                        "    ! virtio-net @ {:02x}:{:02x}.{} lacks modern capabilities (bus master disabled)",
                        bus,
                        dev,
                        func
                    );
                }
            }
        }
    }

    devices
}

/// R186-6: minimum bytes the driver actually accesses in each virtio window.
///
/// A device may declare a LARGER window; it may not declare a smaller one and
/// still be trusted, because the transport reads fixed-layout registers at fixed
/// offsets. `VirtioPciCommonCfg` is 56 bytes; the notify register is a `u16`; the
/// ISR is one byte; virtio-net's device config carries at least the 6-byte MAC.
const VIRTIO_COMMON_CFG_MIN_LEN: u64 = 56;
const VIRTIO_NOTIFY_MIN_LEN: u64 = 2;
const VIRTIO_ISR_MIN_LEN: u64 = 1;
const VIRTIO_DEVICE_CFG_MIN_LEN: u64 = 6;

/// R186-6: inventory BARs in slot order while Memory Space decode is off.
///
/// A 64-bit BAR consumes the next slot even when its aperture is malformed. A
/// lazy cache keyed only by a capability-supplied BAR index could otherwise
/// probe that high dword as an independent 32-bit BAR.
fn inventory_bars(bus: u8, dev: u8, func: u8) -> [Option<ValidatedBar>; 6] {
    let mut cache = [None; 6];
    let mut bar = 0u8;
    while bar < 6 {
        let low = pci_read32(bus, dev, func, PCI_BAR0 + bar * 4);
        let consumes_pair = low & 1 == 0 && ((low >> 1) & 0x3) == 2;
        cache[usize::from(bar)] = size_bar(bus, dev, func, bar);
        bar = bar.saturating_add(if consumes_pair { 2 } else { 1 });
    }
    cache
}

/// Read VirtIO PCI capabilities from the capability list.
///
/// R186-6: this now yields windows whose full declared extent has been proven to
/// lie inside a sized BAR aperture. It must be called while the device's Memory
/// Space decode is DISABLED, because sizing temporarily writes all-ones into each
/// BAR (see `size_bar`).
fn read_virtio_caps(bus: u8, dev: u8, func: u8) -> Option<VirtioPciAddrs> {
    let mut addrs = VirtioPciAddrs::default();
    let bar_cache = inventory_bars(bus, dev, func);
    let mut ptr = pci_read8(bus, dev, func, PCI_CAP_PTR);

    // Walk capability list (limit iterations to prevent infinite loop)
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

        let cap_id = pci_read8(bus, dev, func, ptr);
        let next = pci_read8(bus, dev, func, ptr + 1);
        let cap_len = pci_read8(bus, dev, func, ptr + 2);

        // Check for vendor-specific capability (virtio uses this)
        if cap_id == PCI_CAP_ID_VNDR && cap_len >= 16 {
            let cfg_type = pci_read8(bus, dev, func, ptr + 3);
            let bar = pci_read8(bus, dev, func, ptr + 4);
            let offset = pci_read32(bus, dev, func, ptr + 8);
            // R186-6: the capability's own declared length. Previously read ONLY
            // for the notify cap, so common/isr/device windows had no recorded
            // extent at all and nothing to validate against.
            let cap_window_len = pci_read32(bus, dev, func, ptr + 12);

            // R186-6: every window must be proven to lie wholly inside a SIZED
            // BAR aperture before its physical address is derived, let alone
            // mapped and written. `bar_base + offset` with no length and no bound
            // let a hostile device redirect CPU MMIO writes into RAM or unrelated
            // device registers — which IOMMU translation does NOT contain,
            // because the IOMMU governs DMA, not CPU page tables.
            //
            // Each window is also required to be at least as large as what the
            // driver actually touches, so a device cannot shrink a window to
            // sidestep the bound and still be read past its end.
            let required_len = match cfg_type {
                VIRTIO_PCI_CAP_COMMON_CFG => VIRTIO_COMMON_CFG_MIN_LEN,
                VIRTIO_PCI_CAP_NOTIFY_CFG => VIRTIO_NOTIFY_MIN_LEN,
                VIRTIO_PCI_CAP_ISR_CFG => VIRTIO_ISR_MIN_LEN,
                VIRTIO_PCI_CAP_DEVICE_CFG => VIRTIO_DEVICE_CFG_MIN_LEN,
                _ => {
                    // Unknown cap type: nothing to validate or record.
                    if next == 0 {
                        break;
                    }
                    ptr = next;
                    continue;
                }
            };

            if (cap_window_len as u64) < required_len {
                // Declared window cannot hold the registers the driver reads.
                if next == 0 {
                    break;
                }
                ptr = next;
                continue;
            }

            if let Some(resource) = bar_cache.get(usize::from(bar)).copied().flatten() {
                // Validate the FULL declared length, not just the first byte.
                if let Some(window) = VirtioPciBarWindow::try_new(
                    resource.base,
                    resource.len,
                    offset as u64,
                    cap_window_len,
                    match cfg_type {
                        VIRTIO_PCI_CAP_COMMON_CFG => virtio::VirtioPciWindowAccess::Common,
                        VIRTIO_PCI_CAP_NOTIFY_CFG => virtio::VirtioPciWindowAccess::Notify,
                        VIRTIO_PCI_CAP_ISR_CFG => virtio::VirtioPciWindowAccess::Isr,
                        _ => virtio::VirtioPciWindowAccess::Device,
                    },
                ) {
                    match cfg_type {
                        VIRTIO_PCI_CAP_COMMON_CFG => {
                            addrs.common_cfg = window;
                        }
                        VIRTIO_PCI_CAP_NOTIFY_CFG => {
                            addrs.notify = window;
                            // R169-L8 FIX: ptr+16 must not wrap the u8 add; only read
                            // it when ptr <= 0xEF (0xEF+16 == 0xFF). A cap claiming
                            // length >= 20 at a higher start is malformed — skip the
                            // optional multiplier rather than overflow.
                            if cap_len >= 20 && ptr <= 0xEF {
                                addrs.notify_off_multiplier = pci_read32(bus, dev, func, ptr + 16);
                            }
                        }
                        VIRTIO_PCI_CAP_ISR_CFG => {
                            addrs.isr = window;
                        }
                        VIRTIO_PCI_CAP_DEVICE_CFG => {
                            addrs.device_cfg = window;
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

    // Require at least common_cfg, notify, and device_cfg for modern device
    if addrs.common_cfg.is_present() && addrs.notify.is_present() && addrs.device_cfg.is_present() {
        Some(addrs)
    } else {
        None
    }
}

/// R186-6: a memory BAR whose base AND SIZE have both been determined.
///
/// The previous `read_bar` returned only a base, so `bar_base + cap_offset` had
/// nothing to be checked against: a device could name any offset and the driver
/// would map and write there. A window is only usable once its extent is known,
/// so base and length travel together and are never separated.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ValidatedBar {
    /// Physical base address, low flag bits masked off.
    pub(crate) base: u64,
    /// Aperture size in bytes, from the write-all-ones/read-back probe.
    pub(crate) len: u64,
    /// True when this BAR is the low half of a 64-bit pair (so `bar + 1` is
    /// consumed and must not be decoded as an independent BAR).
    pub(crate) is_64bit: bool,
}

impl ValidatedBar {
    /// R186-6: does `[offset, offset + len)` lie wholly inside this aperture?
    ///
    /// All arithmetic is checked. The release profile enables no overflow checks,
    /// so a plain `offset + len` on device-supplied `u32`/`u64` values wraps
    /// silently and a wrapped sum trivially passes any naive comparison.
    fn contains(&self, offset: u64, len: u64) -> bool {
        if len == 0 {
            return false;
        }
        match offset.checked_add(len) {
            Some(end) => end <= self.len,
            None => false,
        }
    }

    /// Physical address of `offset` within this BAR, or `None` if `offset + len`
    /// is not fully contained.
    fn phys_for(&self, offset: u64, len: u64) -> Option<u64> {
        if !self.contains(offset, len) {
            return None;
        }
        self.base.checked_add(offset)
    }
}

/// R186-6: determine a memory BAR's base and size.
///
/// Sizing is the write-all-ones/read-back probe mandated by the PCI spec: the
/// device returns zeros in the address bits it does not decode, so the size is
/// `!(readback & !flag_bits) + 1`. Nothing in the tree did this, which is why no
/// containment check was possible.
///
/// Two ordering requirements are load-bearing:
///
/// 1. **Memory decode must be OFF while probing.** Writing all-ones to a BAR of a
///    device that is still decoding makes it claim a bogus address range for the
///    duration. The caller performs sizing after clearing the Command register and
///    before enabling Memory Space + Bus Master.
/// 2. **The original value must be restored** whether or not sizing succeeds,
///    otherwise the device is left decoding at the probe address.
///
/// Returns `None` for anything not usable as a 32/64-bit memory aperture: I/O
/// BARs, reserved type encodings, a zero base, a zero or non-power-of-two size, an
/// unaligned base, or a 64-bit BAR in the last slot with no room for its pair.
fn size_bar(bus: u8, dev: u8, func: u8, bar: u8) -> Option<ValidatedBar> {
    if bar >= 6 {
        return None;
    }
    // One lock covers the original-value reads, both all-ones writes, both mask
    // reads, and both restores. A 64-bit BAR is one config-space transaction.
    let _guard = PCI_CONFIG_LOCK.lock();
    let offset = PCI_BAR0 + bar * 4;
    let low = raw_pci_read32(bus, dev, func, offset);

    // I/O space BAR (bit 0 set) - not supported
    if low & 1 != 0 {
        return None;
    }

    // Type field (bits 2:1): 0 = 32-bit, 2 = 64-bit. 1 and 3 are reserved and
    // were previously decoded as 32-bit; a reserved encoding is malformed, so
    // fail closed rather than guess an aperture width.
    let bar_type = (low >> 1) & 0x3;
    let is_64bit = match bar_type {
        0 => false,
        2 => true,
        _ => return None,
    };
    // A 64-bit BAR consumes the following slot for its high dword.
    if is_64bit && bar >= 5 {
        return None;
    }

    let high = if is_64bit {
        raw_pci_read32(bus, dev, func, offset + 4)
    } else {
        0
    };
    let base = ((low & !0xF) as u64) | ((high as u64) << 32);
    if base == 0 {
        return None;
    }

    // --- sizing probe, original values restored on every path ---
    let (size_low, size_high) =
        raw_probe_bar(bus, dev, func, offset, low, is_64bit.then_some(high))?;

    // Assemble the decoded-address mask, then invert to get the size.
    let mask = ((size_low & !0xF) as u64) | ((size_high as u64) << 32);
    if mask == 0 {
        // Device decodes no address bits: the BAR is unimplemented.
        return None;
    }
    let len = (!mask).wrapping_add(1);
    // A real aperture is a non-zero power of two, and the base must be aligned to
    // it. Anything else means the readback was not a valid size mask.
    if len == 0 || !len.is_power_of_two() || base % len != 0 {
        return None;
    }
    // The window must not wrap the physical address space.
    mm::checked_physical_range(base, len)?;

    Some(ValidatedBar {
        base,
        len,
        is_64bit,
    })
}

/// R186-6: perform one paired BAR sizing transaction and restore the resource.
///
/// The caller holds `PCI_CONFIG_LOCK`. For a 64-bit resource, both halves contain
/// all-ones before either mask half is read; probing them independently produces
/// a mask that is not a valid PCI sizing result.
fn raw_probe_bar(
    bus: u8,
    dev: u8,
    func: u8,
    offset: u8,
    original_low: u32,
    original_high: Option<u32>,
) -> Option<(u32, u32)> {
    unsafe {
        let low_address = pci_config_address(bus, dev, func, offset);
        let high_address = pci_config_address(bus, dev, func, offset + 4);
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

        if let Some(high) = original_high {
            outl(PCI_CONFIG_ADDRESS, high_address);
            outl(PCI_CONFIG_DATA, high);
        }
        outl(PCI_CONFIG_ADDRESS, low_address);
        outl(PCI_CONFIG_DATA, original_low);
        outl(PCI_CONFIG_ADDRESS, low_address);
        let restored_low = inl(PCI_CONFIG_DATA);
        if restored_low != original_low {
            return None;
        }
        if let Some(high) = original_high {
            outl(PCI_CONFIG_ADDRESS, high_address);
            if inl(PCI_CONFIG_DATA) != high {
                return None;
            }
        }
        Some((readback_low, readback_high))
    }
}

// ============================================================================
// PCI Config Space Access
// ============================================================================

/// Raw (non-locking) 32-bit PCI config read.
///
/// R165-20 FIX: This performs the CF8/CFC port pair WITHOUT taking
/// `PCI_CONFIG_LOCK`. It must only be called by a public helper that already
/// holds the lock (otherwise the address/data pair is not atomic). Keeping the
/// raw form separate lets `pci_update16`'s read-modify-write run entirely under
/// a single lock acquisition — `spin::Mutex` is non-reentrant, so a public
/// helper calling another public helper while holding the lock would deadlock.
/// R186-6: the CONFIG_ADDRESS word for one dword-aligned config offset.
///
/// Factored out so the BAR sizing probe (which must write, read back, and restore
/// through the SAME address under one lock acquisition) shares the exact encoding
/// used by every read helper.
#[inline]
fn pci_config_address(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let aligned = (offset & 0xFC) as u32;
    0x8000_0000u32 | ((bus as u32) << 16) | ((dev as u32) << 11) | ((func as u32) << 8) | aligned
}

#[inline]
fn raw_pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let address = pci_config_address(bus, dev, func, offset);

    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        inl(PCI_CONFIG_DATA)
    }
}

#[inline]
fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let _guard = PCI_CONFIG_LOCK.lock();
    raw_pci_read32(bus, dev, func, offset)
}

#[inline]
fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let _guard = PCI_CONFIG_LOCK.lock();
    let shift = (offset & 2) * 8;
    (raw_pci_read32(bus, dev, func, offset & 0xFC) >> shift) as u16
}

#[inline]
fn pci_read8(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    let _guard = PCI_CONFIG_LOCK.lock();
    let shift = (offset & 3) * 8;
    (raw_pci_read32(bus, dev, func, offset & 0xFC) >> shift) as u8
}

/// Atomically read-modify-write a 16-bit PCI config register under a single
/// lock acquisition.
///
/// R165-20 FIX: callers enable/disable bus mastering and memory space by
/// read-modify-writing PCI_COMMAND. Doing that as a separate `pci_read16`
/// followed by a 16-bit write would release `PCI_CONFIG_LOCK` between the read
/// and the write, so the IOMMU isolation path on another CPU could change the
/// register in the gap and then be clobbered by our stale value. This helper
/// performs the whole read-modify-write while holding the lock, eliminating the
/// command-register RMW race at the API level (there is intentionally no
/// stale-value `pci_write16`, which invited that footgun).
///
/// `f` receives the current 16-bit value and returns the new value to store.
/// The returned value is a readback captured before the PCI-config lock is
/// released, allowing callers to verify security-sensitive command changes.
#[inline]
fn pci_update16(bus: u8, dev: u8, func: u8, offset: u8, f: impl FnOnce(u16) -> u16) -> u16 {
    let _guard = PCI_CONFIG_LOCK.lock();
    let aligned = offset & 0xFC;
    let shift = ((offset & 2) * 8) as u32;
    let cur = raw_pci_read32(bus, dev, func, aligned);
    let old = ((cur >> shift) & 0xFFFF) as u16;
    let new = f(old);
    let dword = (cur & !(0xFFFFu32 << shift)) | ((new as u32) << shift);

    let address = 0x8000_0000u32
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | (aligned as u32);

    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        outl(PCI_CONFIG_DATA, dword);
    }

    // Keep verification within the same lock acquisition as the RMW. This is
    // especially important for fail-closed BME clears: another CF8/CFC user
    // cannot interleave between the write and its readback.
    let verify = raw_pci_read32(bus, dev, func, aligned);
    ((verify >> shift) & 0xFFFF) as u16
}

#[inline]
unsafe fn outl(port: u16, val: u32) {
    asm!("out dx, eax", in("dx") port, in("eax") val, options(nostack, preserves_flags));
}

#[inline]
unsafe fn inl(port: u16) -> u32 {
    let val: u32;
    asm!("in eax, dx", out("eax") val, in("dx") port, options(nostack, preserves_flags));
    val
}

/// Disable bus mastering for a PCI device.
///
/// This should be called when a device fails to initialize properly after
/// bus mastering was enabled, to prevent orphaned DMA-capable devices.
pub fn disable_bus_master(slot: &PciSlot) {
    if !try_disable_memory_and_bus_master(slot) {
        panic!(
            "R186-6: cannot fail closed: PCI MSE/BME remains set for {:02x}:{:02x}.{}",
            slot.bus, slot.device, slot.function
        );
    }
}

/// Clear and read-back both PCI DMA and MMIO-decode authority without
/// panicking. Probe guards use this form so they can quarantine all live
/// ownership before escalating a device that refuses containment.
pub fn try_disable_memory_and_bus_master(slot: &PciSlot) -> bool {
    let bits = PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER;
    let verify = pci_update16(slot.bus, slot.device, slot.function, PCI_COMMAND, |cmd| {
        cmd & !bits
    });
    verify & bits == 0
}

/// Enable MMIO decoding while keeping DMA authority disabled. The read-back is
/// serialized with the update so a failed activation is fail-closed.
pub fn enable_memory_space(slot: &PciSlot) -> bool {
    let verify = pci_update16(slot.bus, slot.device, slot.function, PCI_COMMAND, |cmd| {
        (cmd | PCI_COMMAND_MEMORY_SPACE) & !PCI_COMMAND_BUS_MASTER
    });
    verify & (PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER) == PCI_COMMAND_MEMORY_SPACE
}

/// Grant DMA authority only after the caller owns a complete unpublished-device
/// rollback transaction. MSE must remain enabled for reset acknowledgement.
pub fn enable_bus_master(slot: &PciSlot) -> bool {
    let required = PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER;
    let verify = pci_update16(slot.bus, slot.device, slot.function, PCI_COMMAND, |cmd| {
        cmd | required
    });
    verify & required == required
}

/// R180-17: clear BME by BDF (probe/refusal path before a PciSlot exists).
fn disable_bus_master_bdf(bus: u8, device: u8, function: u8) {
    disable_command_bits_bdf(bus, device, function, PCI_COMMAND_BUS_MASTER, "BME");
}

/// R186-6: clear both Memory Space decode and bus mastering before BAR sizing.
fn disable_memory_and_bus_master_bdf(bus: u8, device: u8, function: u8) {
    disable_command_bits_bdf(
        bus,
        device,
        function,
        PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER,
        "MSE/BME",
    );
}

fn disable_command_bits_bdf(bus: u8, device: u8, function: u8, bits: u16, label: &str) {
    let verify = pci_update16(bus, device, function, PCI_COMMAND, |cmd| cmd & !bits);
    if verify & bits != 0 {
        klog_force!(
            "    ! R186-6: {} still set after clear for {:02x}:{:02x}.{}",
            label,
            bus,
            device,
            function
        );
        panic!(
            "R186-6: cannot fail closed: PCI {} remains set for {:02x}:{:02x}.{}",
            label, bus, device, function
        );
    }
}
