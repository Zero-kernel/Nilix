//! F9: read firmware tables (ACPI) wherever the firmware placed them.
//!
//! The kernel's high-half direct map covers physical `[0, 1 GiB)`. UEFI
//! firmware puts the RSDP and the ACPI tables near the top of low RAM, which
//! is above that window once a guest has 2 GiB or more. Reading such a table
//! through `PHYSICAL_MEMORY_OFFSET + phys` faulted on an unmapped address.
//!
//! Bytes inside the direct map are returned in place, as before. Bytes outside
//! it are copied, one page at a time, through a transient single-page window
//! into a static bump arena, so callers keep their `&'static [u8]` view and no
//! firmware page stays mapped. The window is read-only, non-executable and
//! write-back, the same memory type as the kernel's other views of that RAM
//! (an uncached alias of write-back RAM is architecturally undefined). It is
//! mapped and unmapped under one lock, and each map invalidates the local TLB
//! entry, so a translation another CPU cached for an earlier page is never used.
//! Any mapping failure, an exhausted arena or an out-of-range address returns
//! `None`, which every caller already treats as unreadable.
//!
//! Only ranges the UEFI memory map marks as firmware-owned (reserved,
//! runtime-services data, ACPI reclaim, ACPI NVS) are copied from outside the
//! direct map, so a corrupt table pointer naming device memory above 1 GiB is
//! refused rather than read through a write-back alias.
//!
//! R191-4: bytes inside the direct map are NOT checked against those ranges.
//! Every caller reads firmware-supplied pointers (RSDP, RSDT/XSDT entries,
//! MADT, HPET, DMAR) at boot, and the legacy-BIOS RSDP scan (the fallback
//! when the bootloader supplies no valid RSDP) reads `0xE0000..0x100000`,
//! which a UEFI memory map need not describe as firmware-owned; refusing an
//! unlisted low range would break that boot path. A corrupt table pointer
//! below 1 GiB is therefore read through the direct map as before F9. That is
//! firmware input, which already controls the boot image; no user-reachable
//! path may pass an address to this reader.

use core::cell::UnsafeCell;

use spin::Mutex;
use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::FrameAllocator;
use crate::page_table::{with_current_manager, PHYSICAL_MEMORY_OFFSET};

/// Physical bytes the high-half direct map covers.
const DIRECT_MAP_LIMIT: u64 = 1 << 30;

/// One-page transient window, in PML4[511]/PDPT[511] beside the HPET
/// (`0xffff_ffff_fed0_0000`) and LAPIC (`0xffff_ffff_fee0_0000`) windows, and
/// in a PD slot of its own.
const FIRMWARE_WINDOW: u64 = 0xffff_ffff_fe00_0000;

const PAGE_BYTES: u64 = 4096;

/// Copies outside the direct map. The boot-time readers (RSDP, RSDT/XSDT,
/// MADT, HPET, DMAR and their headers) need a few KiB.
const ARENA_BYTES: usize = 64 * 1024;

struct Arena(UnsafeCell<[u8; ARENA_BYTES]>);

// SAFETY: bytes are written only through raw pointers while `ARENA_USED` is
// held, and only into the range that call reserves; a reserved range is never
// written again, so shared views of earlier ranges stay valid.
unsafe impl Sync for Arena {}

static ARENA: Arena = Arena(UnsafeCell::new([0; ARENA_BYTES]));

/// Bytes of `ARENA` handed out. The lock also serializes use of the window.
static ARENA_USED: Mutex<usize> = Mutex::new(0);

/// Firmware-owned ranges recorded from the boot memory map (merged when
/// adjacent). Fixed-size and allocation-free; a map with more such ranges than
/// fit leaves the excess unreadable (fail closed).
const MAX_FIRMWARE_RANGES: usize = 128;

struct FirmwareRanges {
    ranges: [(u64, u64); MAX_FIRMWARE_RANGES],
    len: usize,
}

static FIRMWARE_RANGES: Mutex<FirmwareRanges> = Mutex::new(FirmwareRanges {
    ranges: [(0, 0); MAX_FIRMWARE_RANGES],
    len: 0,
});

/// `EFI_MEMORY_WB`: the range supports write-back caching.
const EFI_MEMORY_WB: u64 = 0x8;

/// UEFI memory ranges that may hold firmware tables: EfiRuntimeServicesData,
/// EfiACPIReclaimMemory and EfiACPIMemoryNVS, and EfiReservedMemoryType only
/// when the firmware marks it write-back capable (review D4: reserved ranges
/// also cover device memory such as flash or TPM registers, which must not be
/// read through the window's write-back mapping).
pub(crate) fn is_firmware_table_range(typ: u32, attribute: u64) -> bool {
    match typ {
        6 | 9 | 10 => true,
        0 => attribute & EFI_MEMORY_WB != 0,
        _ => false,
    }
}

/// Record `[start, end)` as firmware-owned (boot-time memory-map scan).
pub(crate) fn record_firmware_range(start: u64, end: u64) {
    if end <= start {
        return;
    }
    let mut table = FIRMWARE_RANGES.lock();
    let len = table.len;
    if let Some(last) = table.ranges[..len].last_mut() {
        if last.1 == start {
            last.1 = end;
            return;
        }
    }
    if len < MAX_FIRMWARE_RANGES {
        table.ranges[len] = (start, end);
        table.len = len + 1;
    }
}

fn firmware_range_contains(start: u64, end: u64) -> bool {
    let table = FIRMWARE_RANGES.lock();
    table.ranges[..table.len]
        .iter()
        .any(|&(lo, hi)| lo <= start && end <= hi)
}

/// Return `len` bytes of firmware memory at physical `phys`, or `None` when the
/// range is empty, wraps, is not a valid physical range, or cannot be copied.
pub fn read_firmware_bytes(phys: u64, len: usize) -> Option<&'static [u8]> {
    if phys == 0 || len == 0 {
        return None;
    }
    let end = phys.checked_add(u64::try_from(len).ok()?)?;
    if end <= DIRECT_MAP_LIMIT {
        // R191-4: no firmware-range check here (see the module documentation).
        let virt = (PHYSICAL_MEMORY_OFFSET + phys) as *const u8;
        // SAFETY: the range lies inside the always-present direct map.
        return Some(unsafe { core::slice::from_raw_parts(virt, len) });
    }
    crate::page_table::checked_physical_range(phys, len as u64)?;
    if !firmware_range_contains(phys, end) {
        return None;
    }

    let mut used = ARENA_USED.lock();
    let start = *used;
    let stop = start.checked_add(len)?;
    if stop > ARENA_BYTES {
        return None;
    }
    // SAFETY: `[start, stop)` is reserved to this call under the lock.
    let dst = unsafe { (ARENA.0.get() as *mut u8).add(start) };
    let window = Page::<Size4KiB>::containing_address(VirtAddr::new(FIRMWARE_WINDOW));
    let flags = PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE;
    let mut frames = FrameAllocator::new();
    let mut copied = 0usize;
    while copied < len {
        let cursor = phys + copied as u64;
        let page = cursor & !(PAGE_BYTES - 1);
        let offset = (cursor - page) as usize;
        let chunk = core::cmp::min(len - copied, PAGE_BYTES as usize - offset);
        let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(page));
        // SAFETY: the window is private to this module and used only under the
        // lock; it is vacant between calls because every map is undone below.
        // A window that cannot be unmapped stays mapped; every later map then
        // fails and reads outside the direct map return None.
        unsafe {
            with_current_manager(VirtAddr::new(PHYSICAL_MEMORY_OFFSET), |manager| {
                manager.map_page(window, frame, flags, &mut frames)
            })
            .ok()?;
            core::ptr::copy_nonoverlapping(
                (FIRMWARE_WINDOW as *const u8).add(offset),
                dst.add(copied),
                chunk,
            );
            with_current_manager(VirtAddr::new(PHYSICAL_MEMORY_OFFSET), |manager| {
                manager.unmap_page(window)
            })
            .ok()?;
        }
        copied += chunk;
    }
    *used = stop;
    // SAFETY: the range is initialized and never written again.
    Some(unsafe { core::slice::from_raw_parts(dst, len) })
}
