use crate::buddy_allocator::{self, MAX_BUDDY_ZONES};
use crate::page_table::{
    direct_map_limit, set_direct_map_limit, DEFAULT_DIRECT_MAP_LIMIT, KERNEL_VIRT_BASE,
    PHYSICAL_MEMORY_OFFSET,
};
use alloc::boxed::Box;
use core::alloc::{AllocError, Allocator, GlobalAlloc, Layout};
use core::hint::spin_loop;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use linked_list_allocator::LockedHeap;
use x86_64::{
    structures::paging::{FrameAllocator as X64FrameAllocator, PhysFrame, Size4KiB},
    PhysAddr,
};

// ============================================================================
// BootInfo 结构定义（与 bootloader 保持一致）
// ============================================================================

/// Bootloader 传入的内存映射信息
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryMapInfo {
    pub buffer: u64,
    pub size: usize,
    pub descriptor_size: usize,
    pub descriptor_version: u32,
}

/// 像素格式（与 bootloader 保持一致）
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// RGB (8位红, 8位绿, 8位蓝, 8位保留)
    Rgb = 0,
    /// BGR (8位蓝, 8位绿, 8位红, 8位保留)
    Bgr = 1,
    /// 未知格式
    Unknown = 2,
}

/// 帧缓冲区信息 (GOP framebuffer)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    /// 帧缓冲区物理地址
    pub base: u64,
    /// 帧缓冲区大小（字节）
    pub size: usize,
    /// 水平分辨率（像素）
    pub width: u32,
    /// 垂直分辨率（像素）
    pub height: u32,
    /// 每行的字节数（stride）
    pub stride: u32,
    /// 像素格式
    pub pixel_format: PixelFormat,
}

/// Bootloader 传入的启动信息
#[repr(C)]
#[derive(Debug)]
pub struct BootInfo {
    pub memory_map: MemoryMapInfo,
    pub framebuffer: FramebufferInfo,
    /// R39-7/RF180-32: relocation slide. Randomization is reported separately
    /// in `kaslr_flags`; zero is a valid randomly selected slot.
    pub kaslr_slide: u64,
    /// ACPI RSDP physical address (from UEFI configuration table)
    pub rsdp_address: u64,
    /// P1-1: UEFI boot command line length in bytes (ASCII, max 256).
    pub cmdline_len: usize,
    /// P1-1: UEFI boot command line buffer (ASCII, NUL-padded).
    pub cmdline: [u8; 256],
    /// R167-C: physical base where the bootloader loaded the kernel image
    /// (`KERNEL_PHYS_BASE + kaslr_slide`). Used to reserve the kernel image out
    /// of the buddy pool defensively, even if a mis-typed UEFI map reported it
    /// as conventional memory.
    pub kernel_phys_base: u64,
    /// R167-C: in-memory size of the kernel image in bytes.
    pub kernel_phys_size: u64,
    /// R167-C: BootInfo ABI version (must equal `BOOT_INFO_VERSION`). A mismatch
    /// means a stale bootloader; the kernel must stop before using its image
    /// fields above and still applies the always-valid heap + UEFI reservations.
    pub version: u64,
    /// RF180-32: placement provenance flags, appended after the v1 layout so a
    /// v2 kernel can inspect the stable `version` offset before trusting them.
    pub kaslr_flags: u64,
    /// N3.1a (#67): virtual base of the linear physical direct map (`PML4[273]`).
    pub direct_map_base: u64,
    /// N3.1a (#67): exclusive upper physical bound covered by `PML4[273]`.
    pub direct_map_limit: u64,
}

/// Validate that a firmware-provided framebuffer range is wholly contained in
/// one descriptor of the handoff memory map.  GOP may place the framebuffer in
/// conventional memory or an MMIO descriptor; accepting only those two types
/// prevents an arbitrary physical pointer from being treated as writable
/// video memory.  The check is allocation-free and fail-closed on malformed
/// descriptor strides/ranges.
pub fn validate_framebuffer_region(
    framebuffer: &FramebufferInfo,
    map_info: &MemoryMapInfo,
) -> bool {
    if framebuffer.base == 0
        || framebuffer.size == 0
        || framebuffer.base % 0x1000 != 0
        || validate_memory_map(map_info).is_none()
    {
        return false;
    }
    let fb_end = match framebuffer
        .base
        .checked_add(u64::try_from(framebuffer.size).ok().unwrap_or(0))
    {
        Some(end) if end > framebuffer.base => end,
        _ => return false,
    };
    let count = map_info.size / map_info.descriptor_size;
    for index in 0..count {
        let offset = match index.checked_mul(map_info.descriptor_size) {
            Some(offset) => offset,
            None => return false,
        };
        let ptr = match map_info.buffer.checked_add(offset as u64) {
            Some(ptr) => ptr as *const EfiMemoryDescriptor,
            None => return false,
        };
        // SAFETY: validate_memory_map proved the fixed descriptor prefix fits
        // inside the bounded firmware buffer and the caller has not modified
        // the handoff map since boot.
        let descriptor = unsafe { core::ptr::read_unaligned(ptr) };
        let region_end = match descriptor
            .phys_start
            .checked_add(descriptor.page_count.checked_mul(0x1000).unwrap_or(0))
        {
            Some(end) if end > descriptor.phys_start => end,
            _ => continue,
        };
        let type_allowed = matches!(descriptor.typ, EFI_CONVENTIONAL_MEMORY | 11 | 12);
        if type_allowed && framebuffer.base >= descriptor.phys_start && fb_end <= region_end {
            return true;
        }
    }
    false
}

impl BootInfo {
    /// True only when a matching bootloader attests that the complete exact-
    /// address candidate order was uniformly randomized. A non-zero slide by
    /// itself may be deterministic availability relocation and is not KASLR.
    pub fn kaslr_randomized(&self) -> bool {
        self.version == BOOT_INFO_VERSION && self.kaslr_flags == BOOT_INFO_KASLR_RANDOMIZED
    }
}

/// UEFI 内存描述符（按 UEFI 规范布局）
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct EfiMemoryDescriptor {
    pub typ: u32,
    pub pad: u32,
    pub phys_start: u64,
    pub virt_start: u64,
    pub page_count: u64,
    pub attribute: u64,
}

/// Validate the common UEFI memory-map ABI before any descriptor is
/// dereferenced.  Firmware controls all four fields, so every parser must
/// enforce the same minimum size, alignment, version, and pointer-range
/// contract.  Returning the bounded descriptor count keeps callers from
/// re-implementing subtly different checks.
#[inline]
fn validate_memory_map(map_info: &MemoryMapInfo) -> Option<usize> {
    let descriptor_len = core::mem::size_of::<EfiMemoryDescriptor>();
    let descriptor_align = core::mem::align_of::<EfiMemoryDescriptor>();
    if map_info.buffer == 0
        || map_info.size == 0
        || map_info.descriptor_version != 1
        || map_info.descriptor_size < descriptor_len
        || map_info.descriptor_size % descriptor_align != 0
    {
        return None;
    }
    let end = map_info
        .buffer
        .checked_add(u64::try_from(map_info.size).ok()?)?;
    let count = map_info.size / map_info.descriptor_size;
    if count == 0 {
        return None;
    }
    // The final descriptor's fixed-size prefix must fit even when firmware
    // advertises an extension-sized descriptor stride.
    let last_offset = (count - 1).checked_mul(map_info.descriptor_size)?;
    let last_addr = map_info
        .buffer
        .checked_add(u64::try_from(last_offset).ok()?)?;
    let last_end = last_addr.checked_add(u64::try_from(descriptor_len).ok()?)?;
    if last_end > end {
        None
    } else {
        Some(count)
    }
}

/// UEFI 内存类型常量
///
/// R167-A: Only `EFI_CONVENTIONAL_MEMORY` is admitted to the buddy frame
/// allocator. Boot-Services Code/Data (types 3/4) are NOT admitted: although
/// nominally free after `ExitBootServices`, firmware commonly leaves
/// runtime-needed data in those regions, so handing them to the buddy risks
/// corrupting live firmware memory. Only type 7 is reliably ownable.
const EFI_CONVENTIONAL_MEMORY: u32 = 7;

/// R167-C: BootInfo ABI version shared with the bootloader mirror. Bump on any
/// layout change to `BootInfo`.
const BOOT_INFO_VERSION: u64 = 3;

fn require_boot_info_version(version: u64) {
    assert_eq!(
        version, BOOT_INFO_VERSION,
        "BootInfo ABI mismatch: cannot safely reserve the live kernel image"
    );
}

/// Must match `BOOT_INFO_KASLR_RANDOMIZED` in the bootloader mirror.
const BOOT_INFO_KASLR_RANDOMIZED: u64 = 1 << 0;

/// R167-C: Upper bound on the number of physical reservations passed to the
/// buddy allocator at init. Bounded to avoid heap allocation during early MM
/// bring-up; overflow is logged (never silently truncated).
const MAX_RESERVED_RANGES: usize = 64;

/// GAP-6 F8: reservation slots kept free for the boot metadata ranges (COW
/// refcount table and buddy allocator metadata) appended after the builder.
const BOOT_METADATA_RESERVATIONS: usize = 2;

// ============================================================================
// 内存配置
// ============================================================================

// The `#[global_allocator]` registration is compiled out under the
// `host_harness` feature so `mm` (and every crate that transitively depends on
// it) can link into a hosted `std` binary — e.g. the cargo-fuzz harness, which
// already carries std's global allocator; two registrations is a hard link
// error. The static itself is kept in BOTH configs (init_heap_allocator_at and
// the heap-stats path reference it), so only the global registration is gated.
// The kernel build never enables `host_harness`, so its allocator is unchanged.
//
// D1-RES R4: the global registration is the `InstrumentedKernelHeap` ZST shim
// below (not `ALLOCATOR` directly) so every allocation updates the monotone
// `HEAP_PEAK_USED_BYTES` high-water under the SAME lock it already takes.
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// D1-RES R4: monotone high-water of normal-arena USED bytes
/// (`early_used + slab_live`), updated on every allocation. Normal arena only;
/// excludes the emergency arena.
static HEAP_PEAK_USED_BYTES: AtomicUsize = AtomicUsize::new(0);

/// N3.1b: live used bytes currently held inside the early boot `ALLOCATOR`
/// (`PML4[511]/PDPT[510]`). Updated inside `ALLOCATOR`'s lock so post-boot
/// slab allocations can read `early_used` lock-free without touching `ALLOCATOR`.
static EARLY_USED_BYTES: AtomicUsize = AtomicUsize::new(0);

#[cfg_attr(feature = "host_harness", allow(dead_code))]
#[inline]
fn with_early_allocator_lock<R>(f: impl FnOnce(&mut linked_list_allocator::Heap) -> R) -> R {
    #[cfg(feature = "host_harness")]
    {
        let mut heap = ALLOCATOR.lock();
        f(&mut heap)
    }
    #[cfg(not(feature = "host_harness"))]
    {
        x86_64::instructions::interrupts::without_interrupts(|| {
            let mut heap = ALLOCATOR.lock();
            f(&mut heap)
        })
    }
}

/// D1-RES R4 + N3.1b (`HEAP-SCALE`): Global kernel heap dispatcher.
///
/// Before buddy publication, serves early boot allocations from the static 2 MiB
/// `linked_list_allocator` in `PML4[511]/PDPT[510]`. Once buddy + `PML4[273]`
/// are ready, routes all new allocations to the buddy-backed [`crate::slab`]
/// allocator (up to `runtime_normal_heap_size_bytes()`). `dealloc` dispatches
/// cleanly by disjoint address range (`[early_base, early_end)` vs `PML4[273]`).
#[cfg_attr(feature = "host_harness", allow(dead_code))]
struct InstrumentedKernelHeap;

unsafe impl GlobalAlloc for InstrumentedKernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 {
            return layout.align() as *mut u8;
        }
        if crate::slab::is_active() {
            let early_used = EARLY_USED_BYTES.load(Ordering::Acquire);
            match crate::slab::alloc(layout, early_used) {
                Some(ptr) => {
                    let used = early_used.saturating_add(crate::slab::live_bytes());
                    HEAP_PEAK_USED_BYTES.fetch_max(used, Ordering::Relaxed);
                    ptr.as_ptr()
                }
                None => core::ptr::null_mut(),
            }
        } else {
            with_early_allocator_lock(|heap| match heap.allocate_first_fit(layout) {
                Ok(ptr) => {
                    let used = NORMAL_HEAP_SIZE_BYTES.saturating_sub(heap.free());
                    EARLY_USED_BYTES.store(used, Ordering::Release);
                    HEAP_PEAK_USED_BYTES.fetch_max(used, Ordering::Relaxed);
                    ptr.as_ptr()
                }
                Err(_) => core::ptr::null_mut(),
            })
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() == 0 {
            return;
        }
        let addr = ptr as usize;
        let early_base = HEAP_BASE.load(Ordering::Acquire);
        let early_end = early_base.saturating_add(NORMAL_HEAP_SIZE_BYTES);
        if addr >= early_base && addr < early_end {
            with_early_allocator_lock(|heap| {
                heap.deallocate(NonNull::new_unchecked(ptr), layout);
                let used = NORMAL_HEAP_SIZE_BYTES.saturating_sub(heap.free());
                EARLY_USED_BYTES.store(used, Ordering::Release);
            });
        } else {
            crate::slab::dealloc(ptr, layout);
        }
    }
}

#[cfg_attr(feature = "host_harness", allow(dead_code))]
#[cfg_attr(not(feature = "host_harness"), global_allocator)]
static GLOBAL_HEAP: InstrumentedKernelHeap = InstrumentedKernelHeap;

/// R180-7..13 FIX: physically disjoint recovery allocator.
///
/// The normal global allocator is never initialized over this tail region, so
/// ordinary `Vec`/`Box`/`Arc` growth cannot consume the bytes needed by an
/// explicitly emergency-allocated recovery object.  Emergency allocations are
/// opt-in through [`EmergencyAllocator`] and remain fallible.
static EMERGENCY_ALLOCATOR: LockedHeap = LockedHeap::empty();
static EMERGENCY_ALLOCATOR_READY: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Partial KASLR: Heap Randomization Configuration
// ============================================================================
//
// The heap address must reside within the bootloader's mapped region.
// Bootloader maps physical 0x0-0x40000000 (0-1GB) to high-half starting at
// 0xffffffff80000000. To avoid overlapping with kernel text/data sections,
// the minimum heap address is 0xffffffff80400000 (4MB offset, 2MB aligned).
//
// Randomization window: [HEAP_DEFAULT_BASE, HEAP_WINDOW_END)
// Alignment: 2MB for huge page compatibility

/// Default (fallback) heap base address when randomization is unavailable
pub const HEAP_DEFAULT_BASE: usize = 0xffffffff80400000;
// LEAD-KSTACK-WINDOW-1: fixed windows stay above the kernel-stack region.
const _: () = assert!(HEAP_DEFAULT_BASE as u64 >= crate::page_table::KSTACK_REGION_END);

/// Upper bound of heap randomization window (exclusive)
/// This leaves room for the heap itself within the 1GB mapped region
const HEAP_WINDOW_END: usize = 0xffffffff90000000;

/// Heap alignment (2MB for huge page compatibility)
const HEAP_ALIGNMENT: usize = 2 * 1024 * 1024;

/// Heap size in bytes.
///
/// R180-10 FIX: the previous 1 MiB arena could not hold one valid maximum
/// exec transaction (image + argv/env + initial-stack staging) together with
/// the registered hard floors. The heap is dynamically placed in verified
/// conventional memory, so use a 2 MiB arena and let `heap_admission` enforce
/// the runtime coexistence partition within it.
const HEAP_SIZE: usize = 2 * 1024 * 1024;

/// Public constant for external modules
pub const HEAP_SIZE_BYTES: usize = HEAP_SIZE;

/// Physically isolated tail of the kernel heap mapping.  General allocations
/// cannot enter this arena.
pub const EMERGENCY_HEAP_SIZE_BYTES: usize = 64 * 1024;

/// Bytes owned by the normal global allocator after carving the emergency
/// arena.  Both sizes are page multiples so the split cannot create an
/// alignment-dependent overlap.
pub const NORMAL_HEAP_SIZE_BYTES: usize = HEAP_SIZE_BYTES - EMERGENCY_HEAP_SIZE_BYTES;

/// N3.1b (`HEAP-SCALE`, #67): maximum runtime heap scaling multiplier
/// (`128 * 2 MiB = 256 MiB` total kernel heap cap on `>= 16 GiB` systems).
pub const MAX_HEAP_SCALE: usize = 128;

/// Maximum runtime kernel heap byte ceiling (`256 MiB`).
pub const MAX_RUNTIME_HEAP_SIZE_BYTES: usize = HEAP_SIZE_BYTES * MAX_HEAP_SCALE;

/// Managed RAM increment per `2 MiB` heap scaling step (`1/64` of RAM).
/// Yields `1x` (2 MiB) on `<=256 MiB`, `3x` (6 MiB) on `512 MiB`, `7x` (14 MiB)
/// on `1 GiB`, `15x` (30 MiB) on `2 GiB`, `31x` (62 MiB) on `4 GiB`, and caps
/// at `128x` (256 MiB) at `>= 16 GiB`.
const HEAP_SCALE_RAM_STEP_BYTES: u64 = 128 * 1024 * 1024;

/// Pure RAM -> heap scale factor formula (`1..=MAX_HEAP_SCALE`).
#[inline]
pub const fn compute_heap_scale_for_ram(managed_bytes: u64) -> usize {
    let raw = (managed_bytes / HEAP_SCALE_RAM_STEP_BYTES) as usize;
    if raw < 1 {
        1
    } else if raw > MAX_HEAP_SCALE {
        MAX_HEAP_SCALE
    } else {
        raw
    }
}

/// Active runtime heap scale factor (`1..=MAX_HEAP_SCALE`).
#[inline]
pub fn heap_scale_factor() -> usize {
    crate::heap_admission::admission_scale()
}

/// Runtime total kernel heap capacity (normal + emergency), scaled from RAM.
#[inline]
pub fn runtime_heap_size_bytes() -> usize {
    HEAP_SIZE_BYTES * heap_scale_factor()
}

/// Runtime normal kernel heap capacity (excluding the 64 KiB emergency arena).
#[inline]
pub fn runtime_normal_heap_size_bytes() -> usize {
    runtime_heap_size_bytes() - EMERGENCY_HEAP_SIZE_BYTES
}

const _: () = assert!(EMERGENCY_HEAP_SIZE_BYTES >= 16 * 1024);
const _: () = assert!(EMERGENCY_HEAP_SIZE_BYTES < HEAP_SIZE_BYTES);
const _: () = assert!(EMERGENCY_HEAP_SIZE_BYTES % 4096 == 0);
const _: () = assert!(NORMAL_HEAP_SIZE_BYTES % 4096 == 0);

/// Allocator handle for explicitly admitted recovery objects.
///
/// The handle is a ZST; all instances use the same locked emergency arena.
/// Callers should prefer fixed/static pools where a strict bound is known and
/// use this allocator only for recovery paths that genuinely require dynamic
/// shape.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmergencyAllocator;

unsafe impl Allocator for EmergencyAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        if layout.size() == 0 {
            return Ok(NonNull::slice_from_raw_parts(NonNull::dangling(), 0));
        }
        if !EMERGENCY_ALLOCATOR_READY.load(Ordering::Acquire) {
            return Err(AllocError);
        }
        EMERGENCY_ALLOCATOR
            .lock()
            .allocate_first_fit(layout)
            .map(|ptr| NonNull::slice_from_raw_parts(ptr, layout.size()))
            .map_err(|_| AllocError)
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        if layout.size() != 0 {
            debug_assert!(EMERGENCY_ALLOCATOR_READY.load(Ordering::Acquire));
            EMERGENCY_ALLOCATOR.lock().deallocate(ptr, layout);
        }
    }
}

/// Actual heap base address (set during init via randomization or fallback)
static HEAP_BASE: AtomicUsize = AtomicUsize::new(HEAP_DEFAULT_BASE);

/// Whether heap was successfully randomized using early entropy
static HEAP_RANDOMIZED: AtomicBool = AtomicBool::new(false);

/// Whether heap address was validated against UEFI memory map
static HEAP_VALIDATED: AtomicBool = AtomicBool::new(false);

/// 物理内存管理起始地址（硬编码后备值，在256MB处）
const FALLBACK_PHYS_MEM_START: u64 = 0x10000000;
/// 物理内存管理大小（硬编码后备值，64MB）
const FALLBACK_PHYS_MEM_SIZE: usize = 64 * 1024 * 1024;

// RF178-31 / R178-6 FIX: The previous 256 MiB `MAX_MANAGED_PHYS_BYTES` cap existed
// solely to size a static COW refcount table. That is rejected: usable RAM is
// limited only by the architectural high-half direct map (`HIGH_HALF_MAP_LIMIT`).
// COW metadata is boot-reserved physical frames sized from the discovered window
// (NOT the 1 MiB heap), published once, and never grown after the first PTE
// mutation.

/// Published after the buddy allocator has accepted its physical zones.
/// Readers load the page count with Acquire before using the base.
static MANAGED_PHYS_BASE: AtomicU64 = AtomicU64::new(0);
static MANAGED_PHYS_PAGES: AtomicUsize = AtomicUsize::new(0);
static MANAGED_PHYS_TOTAL_PAGES: AtomicUsize = AtomicUsize::new(0);

/// N3.1a (#67): per-zone COW refcount table descriptor (boot-reserved physical
/// frames mapped via `PML4[273]`). Published once before AP bring-up.
struct CowZoneEntry {
    base: AtomicU64,
    pages: AtomicUsize,
    virt: AtomicUsize,
}

impl CowZoneEntry {
    const fn empty() -> Self {
        Self {
            base: AtomicU64::new(0),
            pages: AtomicUsize::new(0),
            virt: AtomicUsize::new(0),
        }
    }
}

static COW_ZONES: [CowZoneEntry; MAX_BUDDY_ZONES] =
    [const { CowZoneEntry::empty() }; MAX_BUDDY_ZONES];
static COW_ZONE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// 页大小
const PAGE_SIZE: u64 = 0x1000;
/// 最小可用区域（跳过小于 2MB 的碎片区域）
const MIN_USABLE_REGION: u64 = 2 * 1024 * 1024;
/// 跳过低于 1MB 的区域（保护 BIOS/VGA 等）
const MIN_SAFE_ADDRESS: u64 = 0x100000;
/// Kernel image / early-heap high-half window (`PML4[511]/PDPT[510]`, 0..1 GiB).
const KERNEL_IMAGE_WINDOW_LIMIT: u64 = DEFAULT_DIRECT_MAP_LIMIT;

// ============================================================================
// 初始化函数
// ============================================================================

/// 使用 BootInfo 初始化内存管理
///
/// # Arguments
/// * `boot_info` - Bootloader 传递的启动信息，包含 UEFI 内存映射
///
/// # R72-4 FIX: Memory Map Validation
/// Heap base is now validated against the UEFI memory map before selection,
/// ensuring the chosen address falls within EFI_CONVENTIONAL_MEMORY regions.
pub fn init_with_bootinfo(boot_info: &BootInfo) {
    require_boot_info_version(boot_info.version);
    assert_eq!(
        boot_info.direct_map_base, PHYSICAL_MEMORY_OFFSET,
        "N3.1a: bootloader direct_map_base mismatch"
    );
    set_direct_map_limit(boot_info.direct_map_limit);
    let dm_limit = direct_map_limit();

    // F9 (review D4): remember which physical ranges hold firmware tables, so
    // ACPI reads above the direct map are confined to them.
    record_firmware_ranges(boot_info);
    // R72-4 FIX: Select heap base with UEFI memory map validation FIRST
    // This ensures the heap doesn't overlap with reserved ACPI/runtime regions
    let (heap_base, randomized, validated) =
        if let Some((base, rand)) = select_heap_base_from_bootinfo(boot_info) {
            (base, rand, true)
        } else {
            klog!(
            Warn,
            "  Warning: BootInfo memory map unavailable for heap validation, using default window"
        );
            let (base, rand) = select_heap_base();
            (base, rand, false)
        };

    HEAP_VALIDATED.store(validated, Ordering::SeqCst);
    let heap_base = init_heap_allocator_at(heap_base, randomized);

    // Build accurate status message
    let status = match (randomized, validated) {
        (true, true) => " (randomized, validated)",
        (true, false) => " (randomized, UNVALIDATED)",
        (false, true) => " (static, validated)",
        (false, false) => " (static)",
    };
    #[cfg(debug_assertions)]
    klog!(
        Info,
        "Heap allocator initialized: {} KB at 0x{:x}{}",
        HEAP_SIZE / 1024,
        heap_base,
        status
    );
    #[cfg(not(debug_assertions))]
    klog!(
        Info,
        "Heap allocator initialized: {} KB{}",
        HEAP_SIZE / 1024,
        status
    );

    // N3.1a (#67): Discover up to MAX_BUDDY_ZONES disjoint EFI_CONVENTIONAL_MEMORY
    // regions across the full linear direct map (0..dm_limit), spanning both low
    // RAM (<3 GiB) and high RAM (>=4 GiB) without wasting metadata on PCI holes.
    let (mut regions, mut region_count) = select_regions_from_bootinfo(boot_info, dm_limit);
    if region_count == 0 {
        klog!(
            Warn,
            "  Warning: BootInfo memory map unavailable, using fallback region"
        );
        regions[0] = (FALLBACK_PHYS_MEM_START, FALLBACK_PHYS_MEM_SIZE);
        region_count = 1;
    }

    // Early 2 MiB heap lives inside PML4[511]/PDPT[510] (KERNEL_VIRT_BASE).
    let heap_phys = (heap_base as u64).wrapping_sub(KERNEL_VIRT_BASE);

    let mut zone_allocators: [Option<buddy_allocator::BuddyAllocator>; MAX_BUDDY_ZONES] =
        [const { None }; MAX_BUDDY_ZONES];
    let mut published_zones = 0usize;
    let mut total_managed_bytes: u64 = 0;

    for &(zone_base, zone_size) in &regions[..region_count] {
        let mut reserved_ranges = [(0u64, 0u64); MAX_RESERVED_RANGES];
        let reserved_count = build_buddy_reservations(
            boot_info,
            zone_base,
            zone_size,
            heap_phys,
            &mut reserved_ranges,
        );

        let (meta_phys, meta_bytes) =
            place_cow_refcount_metadata(zone_base, zone_size, &reserved_ranges[..reserved_count]);
        let reserved_count = push_cow_metadata_reservation(
            &mut reserved_ranges,
            reserved_count,
            meta_phys,
            meta_bytes,
        );
        let (buddy_meta_phys, buddy_meta_bytes) =
            place_buddy_metadata(zone_base, zone_size, &reserved_ranges[..reserved_count]);
        let reserved_count = push_boot_metadata_reservation(
            &mut reserved_ranges,
            reserved_count,
            buddy_meta_phys,
            buddy_meta_bytes,
            BUDDY_METADATA_LABEL,
        );
        let reserved_slice = &reserved_ranges[..reserved_count];

        #[cfg(debug_assertions)]
        klog!(
            Info,
            "  Zone {}: 0x{:x} - 0x{:x} ({} MB, COW {} KB, buddy {} KB)",
            published_zones,
            zone_base,
            zone_base + zone_size as u64,
            zone_size / (1024 * 1024),
            meta_bytes / 1024,
            buddy_meta_bytes / 1024
        );
        #[cfg(not(debug_assertions))]
        klog!(
            Info,
            "  Zone {}: {} MB (COW {} KB, buddy {} KB)",
            published_zones,
            zone_size / (1024 * 1024),
            meta_bytes / 1024,
            buddy_meta_bytes / 1024
        );

        // SAFETY: placed inside this zone, reserved above, used only here.
        let buddy_storage = unsafe { boot_metadata_storage(buddy_meta_phys, buddy_meta_bytes) };
        let allocator = buddy_allocator::BuddyAllocator::new_with_reservations_in(
            PhysAddr::new(zone_base),
            zone_size,
            reserved_slice,
            buddy_storage,
        )
        .unwrap_or_else(|error| {
            panic!(
                "buddy allocator zone {} initialization failed before publication: {:?}",
                published_zones, error
            )
        });

        let zone_pages = zone_size / PAGE_SIZE as usize;
        stage_cow_refcount_zone(published_zones, zone_base, meta_phys, zone_pages);
        zone_allocators[published_zones] = Some(allocator);
        published_zones += 1;
        total_managed_bytes = total_managed_bytes.saturating_add(zone_size as u64);
    }

    buddy_allocator::init_buddy_allocator_zones(&mut zone_allocators[..published_zones])
        .unwrap_or_else(|error| {
            panic!("buddy allocator multi-zone publication failed: {:?}", error)
        });
    publish_cow_zones(published_zones);
    publish_managed_phys_windows(
        regions[0].0,
        regions[0].1,
        (total_managed_bytes / PAGE_SIZE) as usize,
    );

    klog_always!(
        "N3.1a: Direct map 0..{} GiB, managed {} zone(s), total {} MB",
        dm_limit / (1024 * 1024 * 1024),
        published_zones,
        total_managed_bytes / (1024 * 1024)
    );

    activate_scaled_slab_heap(total_managed_bytes);

    // 运行自测（可选）
    #[cfg(debug_assertions)]
    {
        buddy_allocator::run_self_test();
        buddy_allocator::run_reservation_self_test();
    }

    klog_always!("Memory manager fully initialized (using BootInfo)");
}

/// 后备初始化函数（无 BootInfo 时使用）
pub fn init() {
    // 初始化堆分配器（包含 Partial KASLR 堆随机化，但无法验证内存映射）
    let (heap_base, randomized) = select_heap_base();
    let heap_base = init_heap_allocator_at(heap_base, randomized);
    let status = if heap_randomized() {
        " (randomized, unvalidated)"
    } else {
        " (static)"
    };
    // R148-8 FIX: Gate raw address logging behind debug_assertions.
    #[cfg(debug_assertions)]
    klog!(
        Info,
        "Heap allocator initialized: {} KB at 0x{:x}{}",
        HEAP_SIZE / 1024,
        heap_base,
        status
    );
    #[cfg(not(debug_assertions))]
    klog!(
        Info,
        "Heap allocator initialized: {} KB{}",
        HEAP_SIZE / 1024,
        status
    );

    // 使用硬编码区域
    klog!(
        Warn,
        "  Warning: No BootInfo, using hardcoded memory region"
    );
    // R167-B: reserve the heap out of the buddy region (same physical-overlap
    // exclusion as the BootInfo path, but via reservation so the full fallback
    // region minus the heap hole is managed). No UEFI map here, so the heap is
    // the only non-metadata reservation.
    let heap_phys = (heap_base as u64).wrapping_sub(KERNEL_VIRT_BASE);
    let mut reserved_ranges = [(0u64, 0u64); MAX_RESERVED_RANGES];
    reserved_ranges[0] = (heap_phys, HEAP_SIZE as u64);
    let (meta_phys, meta_bytes) = place_cow_refcount_metadata(
        FALLBACK_PHYS_MEM_START,
        FALLBACK_PHYS_MEM_SIZE,
        &reserved_ranges[..1],
    );
    let reserved_count =
        push_cow_metadata_reservation(&mut reserved_ranges, 1, meta_phys, meta_bytes);
    // GAP-6 F8: same boot-reserved buddy metadata as the BootInfo path.
    let (buddy_meta_phys, buddy_meta_bytes) = place_buddy_metadata(
        FALLBACK_PHYS_MEM_START,
        FALLBACK_PHYS_MEM_SIZE,
        &reserved_ranges[..reserved_count],
    );
    let reserved_count = push_boot_metadata_reservation(
        &mut reserved_ranges,
        reserved_count,
        buddy_meta_phys,
        buddy_meta_bytes,
        BUDDY_METADATA_LABEL,
    );
    // SAFETY: placed inside the fallback window, reserved above, used only here.
    let buddy_storage = unsafe { boot_metadata_storage(buddy_meta_phys, buddy_meta_bytes) };
    buddy_allocator::init_buddy_allocator_in(
        PhysAddr::new(FALLBACK_PHYS_MEM_START),
        FALLBACK_PHYS_MEM_SIZE,
        &reserved_ranges[..reserved_count],
        buddy_storage,
    )
    .unwrap_or_else(|error| {
        panic!(
            "fallback buddy allocator metadata initialization failed before publication: {:?}",
            error
        )
    });
    let fallback_pages = FALLBACK_PHYS_MEM_SIZE / PAGE_SIZE as usize;
    stage_cow_refcount_zone(0, FALLBACK_PHYS_MEM_START, meta_phys, fallback_pages);
    publish_cow_zones(1);
    publish_managed_phys_windows(
        FALLBACK_PHYS_MEM_START,
        FALLBACK_PHYS_MEM_SIZE,
        fallback_pages,
    );

    activate_scaled_slab_heap(FALLBACK_PHYS_MEM_SIZE as u64);

    // 运行自测（可选）
    #[cfg(debug_assertions)]
    {
        buddy_allocator::run_self_test();
        buddy_allocator::run_reservation_self_test();
    }

    klog_always!("Memory manager fully initialized (fallback mode)");
}

// ============================================================================
// Partial KASLR: Heap Base Randomization
// ============================================================================

/// N3.1c (#67): Buddy low-watermark reclaim hook — evicts clean LRU page-cache
/// pages first, then flushes cached empty slab pages if more frames are needed.
fn buddy_low_watermark_reclaim(target_pages: usize) -> usize {
    let mut freed = crate::page_cache::reclaim_pages(target_pages);
    if freed < target_pages {
        freed = freed.saturating_add(crate::slab::reclaim_empty_slabs());
    }
    freed
}

/// N3.1b + N3.1c (`HEAP-SCALE`, #67): scale kernel heap admission ceilings and
/// page cache capacity from total managed physical RAM, activate the
/// buddy-backed slab + large-page heap, and wire buddy low-watermark reclaim.
fn activate_scaled_slab_heap(total_managed_bytes: u64) {
    let scale = compute_heap_scale_for_ram(total_managed_bytes);
    crate::heap_admission::configure_for_scale(scale);
    let runtime_total = runtime_heap_size_bytes();
    let runtime_normal = runtime_normal_heap_size_bytes();
    let runtime_admitted = crate::heap_admission::runtime_admitted_heap_bytes();
    crate::slab::activate(runtime_normal);
    let pc_max_pages = crate::page_cache::configure_for_ram(total_managed_bytes, scale);
    crate::buddy_allocator::register_low_watermark_reclaim_hook(buddy_low_watermark_reclaim);
    let low_wm = crate::buddy_allocator::low_watermark_pages();
    klog_always!(
        "N3.1b: Buddy-backed slab heap active: total={} MiB (scale={}x, normal={} KiB, admitted={} KiB)",
        runtime_total / (1024 * 1024),
        scale,
        runtime_normal / 1024,
        runtime_admitted / 1024
    );
    klog_always!(
        "N3.1c: Page cache max_pages={} ({} MiB), buddy low_watermark={} pages",
        pc_max_pages,
        (pc_max_pages * 4) / 1024,
        low_wm
    );
}

/// Initialize the heap allocator at a pre-selected address.
///
/// # R72-4 FIX: Separated selection from initialization
/// This allows the caller to validate the heap address against the UEFI
/// memory map before committing to it.
fn init_heap_allocator_at(heap_base: usize, randomized: bool) -> usize {
    HEAP_BASE.store(heap_base, Ordering::SeqCst);
    HEAP_RANDOMIZED.store(randomized, Ordering::SeqCst);

    unsafe {
        ALLOCATOR
            .lock()
            .init(heap_base as *mut u8, NORMAL_HEAP_SIZE_BYTES);
        let emergency_base = heap_base
            .checked_add(NORMAL_HEAP_SIZE_BYTES)
            .expect("emergency heap base overflow");
        EMERGENCY_ALLOCATOR
            .lock()
            .init(emergency_base as *mut u8, EMERGENCY_HEAP_SIZE_BYTES);
    }
    EMERGENCY_ALLOCATOR_READY.store(true, Ordering::Release);

    heap_base
}

/// Select a randomized heap base address using early RDRAND entropy.
///
/// The randomization window is [HEAP_DEFAULT_BASE, HEAP_WINDOW_END), with
/// 2MB alignment to maintain huge page compatibility.
///
/// # Returns
///
/// Tuple of (heap_base, was_randomized)
fn select_heap_base() -> (usize, bool) {
    // Calculate the maximum allowable heap base (ensuring heap fits within window)
    let max_base = HEAP_WINDOW_END.saturating_sub(HEAP_SIZE);
    let max_base_aligned = align_down(max_base as u64, HEAP_ALIGNMENT as u64) as usize;

    // Validate we have room for randomization
    if max_base_aligned < HEAP_DEFAULT_BASE {
        return (HEAP_DEFAULT_BASE, false);
    }

    // Calculate number of possible slots
    let slot_count = (max_base_aligned - HEAP_DEFAULT_BASE) / HEAP_ALIGNMENT;
    if slot_count == 0 {
        return (HEAP_DEFAULT_BASE, false);
    }

    // Attempt to get early entropy from RDRAND
    if let Some(rand) = rdrand64_early() {
        // Select a random slot (0 to slot_count inclusive)
        let slot = (rand as usize) % (slot_count + 1);
        let base = HEAP_DEFAULT_BASE + slot * HEAP_ALIGNMENT;
        return (base, true);
    }

    // Fallback to default if RDRAND unavailable
    (HEAP_DEFAULT_BASE, false)
}

/// Select a randomized heap base address with UEFI memory map validation.
///
/// # R72-4 FIX: Memory Map Aware Heap Selection
/// This function validates that the chosen heap address falls entirely within
/// EFI_CONVENTIONAL_MEMORY regions, preventing placement over ACPI tables,
/// EFI runtime services, or other reserved memory.
///
/// # Algorithm
/// 1. Attempt RDRAND to get entropy for random slot selection
/// 2. Try the random slot first, if it lands in usable memory, use it
/// 3. If not, iterate through all slots to find one in usable memory
/// 4. Return None if no valid slot exists (caller falls back to unvalidated selection)
fn select_heap_base_from_bootinfo(boot_info: &BootInfo) -> Option<(usize, bool)> {
    let map_info = &boot_info.memory_map;

    // Validate memory map is present
    if validate_memory_map(map_info).is_none() {
        return None;
    }

    // Calculate slot parameters (same as select_heap_base)
    let max_base = HEAP_WINDOW_END.saturating_sub(HEAP_SIZE);
    let max_base_aligned = align_down(max_base as u64, HEAP_ALIGNMENT as u64) as usize;
    if max_base_aligned < HEAP_DEFAULT_BASE {
        return None;
    }

    let slot_count = (max_base_aligned - HEAP_DEFAULT_BASE) / HEAP_ALIGNMENT;
    if slot_count == 0 {
        return None;
    }

    // Get optional entropy for random starting slot
    let rand_slot = rdrand64_early().map(|r| (r as usize) % (slot_count + 1));
    let start_slot = rand_slot.unwrap_or(0);

    // Iterate through all slots, starting from the random one
    for offset in 0..=slot_count {
        let slot_idx = (start_slot + offset) % (slot_count + 1);
        let heap_base = HEAP_DEFAULT_BASE + slot_idx * HEAP_ALIGNMENT;

        // Convert virtual address to physical (early heap lives in PML4[511]/PDPT[510])
        let phys_base = heap_base as u64 - KERNEL_VIRT_BASE;

        if heap_range_usable(phys_base, HEAP_SIZE, map_info) {
            let randomized = rand_slot.is_some();
            return Some((heap_base, randomized));
        }
    }

    // No valid slot found in UEFI memory map
    None
}

/// Check if a candidate heap physical range is entirely within usable UEFI memory.
///
/// A range is usable if:
/// 1. It's within the kernel image high-half window (1 GiB, `PML4[511]/PDPT[510]`)
/// 2. It's above MIN_SAFE_ADDRESS (1MB, protecting legacy hardware)
/// 3. It's fully contained within an EFI_CONVENTIONAL_MEMORY region (R167-A:
///    Boot-Services regions are no longer treated as usable)
fn heap_range_usable(phys_base: u64, len: usize, map_info: &MemoryMapInfo) -> bool {
    let Some(desc_count) = validate_memory_map(map_info) else {
        return false;
    };
    let Some(phys_end) = phys_base.checked_add(len as u64) else {
        return false;
    };

    // Must be within PML4[511]/PDPT[510] early-heap window
    if phys_end > KERNEL_IMAGE_WINDOW_LIMIT {
        return false;
    }

    // Must be above MIN_SAFE_ADDRESS
    if phys_base < MIN_SAFE_ADDRESS {
        return false;
    }

    for i in 0..desc_count {
        let Some(offset) = i.checked_mul(map_info.descriptor_size) else {
            return false;
        };
        let Some(addr) = map_info.buffer.checked_add(offset as u64) else {
            return false;
        };
        let desc = unsafe { &*(addr as *const EfiMemoryDescriptor) };

        // R167-A: Only EFI_CONVENTIONAL_MEMORY is a safe home for the heap.
        if desc.typ != EFI_CONVENTIONAL_MEMORY || desc.page_count == 0 {
            continue;
        }

        let region_start = align_up(desc.phys_start, PAGE_SIZE);
        let region_end = desc
            .phys_start
            .saturating_add(desc.page_count.saturating_mul(PAGE_SIZE));

        // Check if heap range is fully contained within this region
        if region_start <= phys_base && phys_end <= region_end {
            return true;
        }
    }

    false
}

/// Early RDRAND access for heap randomization (no CSPRNG dependency).
///
/// This function directly accesses the RDRAND instruction without relying
/// on the ChaCha20 CSPRNG, which is initialized after the heap.
fn rdrand64_early() -> Option<u64> {
    if !rdrand_supported_early() {
        return None;
    }

    // Retry up to 32 times (RDRAND may fail if entropy pool is depleted)
    for _ in 0..32 {
        let mut value: u64 = 0;
        let ok: u8;

        unsafe {
            core::arch::asm!(
                "rdrand {0}",
                "setc {1}",
                out(reg) value,
                out(reg_byte) ok,
                options(nomem, nostack)
            );
        }

        if ok == 1 {
            return Some(value);
        }

        spin_loop();
    }

    None
}

/// Check if CPU supports RDRAND (early boot, no allocations).
///
/// R72-4 FIX: Properly handle CPUID's rbx clobbering without UB.
/// LLVM uses rbx internally, so we must save and restore it via the stack.
/// Since we use push/pop, we cannot use `nostack` or `nomem` options
/// (push/pop both use stack memory).
fn rdrand_supported_early() -> bool {
    // CPUID.01H:ECX.RDRAND[bit 30]
    let ecx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 1u32 => _,
            lateout("ecx") ecx,
            lateout("edx") _,
            // No options - push/pop uses both stack and memory
        );
    }
    (ecx & (1 << 30)) != 0
}

/// F9 (review D4): record the firmware-table ranges of the boot memory map.
fn record_firmware_ranges(boot_info: &BootInfo) {
    let map_info = &boot_info.memory_map;
    let Some(desc_count) = validate_memory_map(map_info) else {
        return;
    };
    for i in 0..desc_count {
        let Some(offset) = i.checked_mul(map_info.descriptor_size) else {
            return;
        };
        let Some(addr) = map_info.buffer.checked_add(offset as u64) else {
            return;
        };
        // SAFETY: validate_memory_map proved every descriptor prefix fits.
        let desc = unsafe { core::ptr::read_unaligned(addr as *const EfiMemoryDescriptor) };
        if !crate::firmware::is_firmware_table_range(desc.typ, desc.attribute) {
            continue;
        }
        let Some(bytes) = desc.page_count.checked_mul(PAGE_SIZE) else {
            continue;
        };
        if let Some(end) = desc.phys_start.checked_add(bytes) {
            crate::firmware::record_firmware_range(desc.phys_start, end);
        }
    }
}

/// N3.1a (#67): Discover up to `MAX_BUDDY_ZONES` disjoint `EFI_CONVENTIONAL_MEMORY`
/// regions inside `[MIN_SAFE_ADDRESS, map_limit)`.
///
/// Adjacent conventional descriptors are merged before ranking so contiguous RAM
/// stays in one buddy zone; the largest `MAX_BUDDY_ZONES` regions >= `MIN_USABLE_REGION`
/// are returned sorted by ascending physical address (Zone 0 = low RAM `<3 GiB`,
/// Zone 1+ = high RAM `>=4 GiB` across the PCI MMIO hole). Allocation-free.
fn select_regions_from_bootinfo(
    boot_info: &BootInfo,
    map_limit: u64,
) -> ([(u64, usize); MAX_BUDDY_ZONES], usize) {
    let mut out = [(0u64, 0usize); MAX_BUDDY_ZONES];
    let map_info = &boot_info.memory_map;
    let Some(desc_count) = validate_memory_map(map_info) else {
        return (out, 0);
    };

    const MAX_CANDIDATE_SPANS: usize = 128;
    let mut spans = [(0u64, 0u64); MAX_CANDIDATE_SPANS];
    let mut span_count = 0usize;

    klog_always!("  Scanning UEFI memory map ({} descriptors)...", desc_count);

    for i in 0..desc_count {
        let Some(offset) = i.checked_mul(map_info.descriptor_size) else {
            break;
        };
        let Some(addr) = map_info.buffer.checked_add(offset as u64) else {
            break;
        };
        // SAFETY: validate_memory_map proved every descriptor prefix fits.
        let desc = unsafe { core::ptr::read_unaligned(addr as *const EfiMemoryDescriptor) };

        // R167-A: Only EFI_CONVENTIONAL_MEMORY is admitted to the buddy frame allocator.
        if desc.typ != EFI_CONVENTIONAL_MEMORY || desc.page_count == 0 {
            continue;
        }

        let raw_start = align_up(desc.phys_start, PAGE_SIZE);
        let raw_length = desc.page_count.saturating_mul(PAGE_SIZE);
        let usable_length = raw_length.saturating_sub(raw_start.saturating_sub(desc.phys_start));
        let start = raw_start.max(MIN_SAFE_ADDRESS);
        if start >= map_limit {
            continue;
        }
        let end = raw_start.saturating_add(usable_length).min(map_limit);
        let end = align_down(end, PAGE_SIZE);
        if end <= start {
            continue;
        }

        // Insert into sorted-by-start span list and merge adjacent/overlapping spans.
        let mut insert_at = span_count;
        for idx in 0..span_count {
            if start < spans[idx].0 {
                insert_at = idx;
                break;
            }
        }
        if span_count < MAX_CANDIDATE_SPANS {
            let mut j = span_count;
            while j > insert_at {
                spans[j] = spans[j - 1];
                j -= 1;
            }
            spans[insert_at] = (start, end);
            span_count += 1;
            // Coalesce adjacent/overlapping spans in-place.
            let mut write = 0usize;
            for read in 1..span_count {
                if spans[read].0 <= spans[write].1 {
                    if spans[read].1 > spans[write].1 {
                        spans[write].1 = spans[read].1;
                    }
                } else {
                    write += 1;
                    spans[write] = spans[read];
                }
            }
            span_count = write + 1;
        } else {
            // Table full: try merging into an existing adjacent span or replace smallest.
            let mut merged = false;
            for idx in 0..span_count {
                if start <= spans[idx].1 && end >= spans[idx].0 {
                    spans[idx].0 = spans[idx].0.min(start);
                    spans[idx].1 = spans[idx].1.max(end);
                    merged = true;
                    break;
                }
            }
            if !merged {
                let len = end - start;
                let mut smallest = 0usize;
                for idx in 1..span_count {
                    if (spans[idx].1 - spans[idx].0) < (spans[smallest].1 - spans[smallest].0) {
                        smallest = idx;
                    }
                }
                if len > (spans[smallest].1 - spans[smallest].0) {
                    spans[smallest] = (start, end);
                }
            }
        }
    }

    // Filter to spans >= MIN_USABLE_REGION and keep the largest MAX_BUDDY_ZONES.
    let mut selected = [(0u64, 0u64); MAX_BUDDY_ZONES];
    let mut selected_count = 0usize;
    let mut total_conventional: u64 = 0;

    for &(start, end) in &spans[..span_count] {
        let len = end.saturating_sub(start);
        if len < MIN_USABLE_REGION {
            continue;
        }
        total_conventional = total_conventional.saturating_add(len);
        if selected_count < MAX_BUDDY_ZONES {
            selected[selected_count] = (start, len);
            selected_count += 1;
        } else {
            let mut smallest = 0usize;
            for idx in 1..selected_count {
                if selected[idx].1 < selected[smallest].1 {
                    smallest = idx;
                }
            }
            if len > selected[smallest].1 {
                selected[smallest] = (start, len);
            }
        }
    }

    // Sort selected zones by ascending physical base so Zone 0 is low RAM.
    for i in 1..selected_count {
        let key = selected[i];
        let mut j = i;
        while j > 0 && selected[j - 1].0 > key.0 {
            selected[j] = selected[j - 1];
            j -= 1;
        }
        selected[j] = key;
    }

    for i in 0..selected_count {
        out[i] = (selected[i].0, selected[i].1 as usize);
    }

    klog!(
        Info,
        "  Total usable memory: {} MB across {} zone(s)",
        total_conventional / (1024 * 1024),
        selected_count
    );

    (out, selected_count)
}

/// Bytes required for an O(1) AtomicU32 COW table covering `managed_pages`.
#[inline]
fn cow_refcount_table_bytes(managed_pages: usize) -> usize {
    managed_pages
        .checked_mul(core::mem::size_of::<core::sync::atomic::AtomicU32>())
        .expect("COW refcount table byte count overflow")
}

/// Return the page-rounded intersection of a reservation with the managed
/// physical window. This mirrors the buddy allocator's outward rounding: even a
/// one-byte overlap with a frame withholds the whole frame.
fn normalized_reservation(
    start: u64,
    len: u64,
    window_start: u64,
    window_end: u64,
) -> Option<(u64, u64)> {
    if len == 0 || window_end <= window_start {
        return None;
    }
    let raw_end = start.saturating_add(len);
    if raw_end <= window_start || start >= window_end {
        return None;
    }

    let rounded_start = align_down(start.max(window_start), PAGE_SIZE);
    let bounded_start = rounded_start.max(window_start);
    let bounded_raw_end = raw_end.min(window_end);
    let remainder = bounded_raw_end % PAGE_SIZE;
    let rounded_end = if remainder == 0 {
        bounded_raw_end
    } else {
        bounded_raw_end.saturating_add(PAGE_SIZE - remainder)
    }
    .min(window_end);

    (bounded_start < rounded_end).then_some((bounded_start, rounded_end))
}

#[inline]
fn half_open_ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

/// Choose a page-aligned physical placement for the COW refcount table that
/// lies entirely inside the managed window and is disjoint from every existing
/// boot reservation.
fn place_cow_refcount_metadata(
    pmm_base: u64,
    pmm_size: usize,
    reservations: &[(u64, u64)],
) -> (u64, usize) {
    assert!(pmm_size > 0, "managed window must be non-empty");
    let managed_pages = pmm_size / PAGE_SIZE as usize;
    place_boot_metadata(
        pmm_base,
        pmm_size,
        cow_refcount_table_bytes(managed_pages),
        reservations,
        COW_METADATA_LABEL,
    )
}

const COW_METADATA_LABEL: &str = "COW refcount metadata";
const BUDDY_METADATA_LABEL: &str = "buddy allocator metadata";

/// GAP-6 F8: place the buddy allocator's per-page state and order bitmaps the
/// same way as the COW table. Both scale with the managed window; on the 2 MiB
/// kernel heap the buddy metadata alone approached the boot unledgered ceiling
/// once a guest had about 1 GiB of RAM.
fn place_buddy_metadata(
    pmm_base: u64,
    pmm_size: usize,
    reservations: &[(u64, u64)],
) -> (u64, usize) {
    let raw = buddy_allocator::BuddyAllocator::metadata_bytes(pmm_size).unwrap_or_else(|error| {
        panic!(
            "GAP-6 F8: buddy metadata size for the managed window: {:?}",
            error
        )
    });
    place_boot_metadata(pmm_base, pmm_size, raw, reservations, BUDDY_METADATA_LABEL)
}

/// Choose a page-aligned placement for `raw_bytes` of boot metadata that lies
/// entirely inside the managed window and is disjoint from every existing boot
/// reservation. Returns the base and the page-rounded length.
///
/// Search downward from the high end to preserve a large low free span. On a
/// collision, jump below the lowest overlapping reservation rather than walking
/// page-by-page. The bounded reservation array therefore limits this to at most
/// `reservations.len() + 1` probes and the early-boot path allocates no heap.
fn place_boot_metadata(
    pmm_base: u64,
    pmm_size: usize,
    raw_bytes: usize,
    reservations: &[(u64, u64)],
    label: &str,
) -> (u64, usize) {
    assert!(pmm_size > 0, "managed window must be non-empty");
    assert_eq!(pmm_base % PAGE_SIZE, 0, "managed base must be page aligned");
    assert_eq!(
        pmm_size % PAGE_SIZE as usize,
        0,
        "managed size must be page aligned"
    );

    let meta_bytes = align_up(raw_bytes as u64, PAGE_SIZE) as usize;
    assert!(
        meta_bytes > 0 && meta_bytes < pmm_size,
        "{} ({} B) must fit strictly inside managed window ({} B)",
        label,
        meta_bytes,
        pmm_size
    );

    let pmm_end = pmm_base
        .checked_add(pmm_size as u64)
        .expect("managed window end overflow");

    let meta_len = meta_bytes as u64;
    let mut candidate_end = pmm_end;
    for _ in 0..=reservations.len() {
        let Some(candidate_start) = candidate_end.checked_sub(meta_len) else {
            break;
        };
        if candidate_start < pmm_base {
            break;
        }

        let mut move_below: Option<u64> = None;
        for &(reserved_start, reserved_len) in reservations {
            let Some((reserved_start, reserved_end)) =
                normalized_reservation(reserved_start, reserved_len, pmm_base, pmm_end)
            else {
                continue;
            };
            if half_open_ranges_overlap(
                candidate_start,
                candidate_end,
                reserved_start,
                reserved_end,
            ) {
                move_below = Some(match move_below {
                    Some(previous) => previous.min(reserved_start),
                    None => reserved_start,
                });
            }
        }

        match move_below {
            None => return (candidate_start, meta_bytes),
            Some(next_end) if next_end < candidate_end => candidate_end = next_end,
            Some(_) => break,
        }
    }

    panic!(
        "R180-29: cannot place {} ({} KB) inside managed window without colliding with boot reservations",
        label,
        meta_bytes / 1024
    );
}

/// Append the COW metadata reservation; fail closed if the bounded set is full
/// (same R167 overflow discipline — never silently drop a live reservation).
fn push_cow_metadata_reservation(
    out: &mut [(u64, u64); MAX_RESERVED_RANGES],
    count: usize,
    meta_phys: u64,
    meta_bytes: usize,
) -> usize {
    push_boot_metadata_reservation(out, count, meta_phys, meta_bytes, COW_METADATA_LABEL)
}

/// Append a boot metadata reservation; fail closed if the bounded set is full
/// or the range overlaps an existing reservation.
fn push_boot_metadata_reservation(
    out: &mut [(u64, u64); MAX_RESERVED_RANGES],
    count: usize,
    meta_phys: u64,
    meta_bytes: usize,
    label: &str,
) -> usize {
    if count >= MAX_RESERVED_RANGES {
        panic!(
            "RF178-31: reservation list full; cannot permanently reserve {}",
            label
        );
    }
    assert_eq!(meta_phys % PAGE_SIZE, 0, "{} must be page aligned", label);
    assert!(meta_bytes > 0, "{} reservation must be non-empty", label);
    let meta_end = meta_phys
        .checked_add(meta_bytes as u64)
        .expect("boot metadata reservation end overflow");
    for &(reserved_start, reserved_len) in &out[..count] {
        if reserved_len == 0 {
            continue;
        }
        let reserved_end = reserved_start.saturating_add(reserved_len);
        assert!(
            !half_open_ranges_overlap(meta_phys, meta_end, reserved_start, reserved_end),
            "R180-29: {} overlaps an existing boot reservation",
            label
        );
    }
    out[count] = (meta_phys, meta_bytes as u64);
    count + 1
}

/// GAP-6 F8: view a boot-reserved metadata range through the direct map.
///
/// # Safety
///
/// `phys..phys + bytes` must be page aligned, inside the managed window (which
/// is clamped to the high-half direct map), already in the reservation set
/// handed to the buddy allocator, and referenced by nothing else. Call once per
/// range, single-threaded, before any AP starts.
unsafe fn boot_metadata_storage(phys: u64, bytes: usize) -> &'static mut [u8] {
    assert_eq!(
        phys % PAGE_SIZE,
        0,
        "boot metadata base must be page aligned"
    );
    assert!(
        phys.checked_add(bytes as u64)
            .is_some_and(|end| end <= direct_map_limit()),
        "boot metadata must lie inside the high-half direct map"
    );
    let virt = phys
        .checked_add(PHYSICAL_MEMORY_OFFSET)
        .expect("boot metadata direct-map address overflow");
    // SAFETY: guaranteed by the caller contract above; the range is mapped by
    // the direct map and exclusively owned from here on.
    unsafe { core::slice::from_raw_parts_mut(virt as *mut u8, bytes) }
}

/// Zero and stage one zone's boot-reserved COW refcount table via `PML4[273]`.
///
/// Called single-threaded during boot before [`publish_cow_zones`] releases
/// `COW_ZONE_COUNT`.
fn stage_cow_refcount_zone(zone_idx: usize, zone_base: u64, meta_phys: u64, managed_pages: usize) {
    assert!(zone_idx < MAX_BUDDY_ZONES, "COW zone index out of range");
    assert_eq!(
        zone_base % PAGE_SIZE,
        0,
        "COW zone physical base must be page aligned"
    );
    assert_eq!(
        meta_phys % PAGE_SIZE,
        0,
        "COW metadata physical base must be page aligned"
    );
    assert!(managed_pages > 0, "managed page count must be non-zero");
    assert_eq!(
        COW_ZONE_COUNT.load(Ordering::Acquire),
        0,
        "COW refcount tables must be staged before publication"
    );

    let meta_bytes = cow_refcount_table_bytes(managed_pages);
    assert!(
        meta_phys
            .checked_add(meta_bytes as u64)
            .is_some_and(|end| end <= direct_map_limit()),
        "COW metadata must lie inside the high-half direct map"
    );
    let virt = meta_phys
        .checked_add(PHYSICAL_MEMORY_OFFSET)
        .expect("COW metadata direct-map address overflow");
    let ptr = virt as *mut u8;

    // SAFETY: meta_phys is permanently reserved inside the direct-mapped zone
    // and exclusively owned during single-threaded early boot.
    unsafe {
        core::ptr::write_bytes(ptr, 0, meta_bytes);
    }

    COW_ZONES[zone_idx].base.store(zone_base, Ordering::Relaxed);
    COW_ZONES[zone_idx]
        .pages
        .store(managed_pages, Ordering::Relaxed);
    COW_ZONES[zone_idx]
        .virt
        .store(virt as usize, Ordering::Relaxed);

    klog!(
        Info,
        "  COW refcount table zone {} staged: {} entries ({} KB)",
        zone_idx,
        managed_pages,
        meta_bytes / 1024
    );
}

/// Publish all staged COW refcount zones atomically with Release ordering.
fn publish_cow_zones(zone_count: usize) {
    assert!(
        zone_count > 0 && zone_count <= MAX_BUDDY_ZONES,
        "invalid COW zone count"
    );
    assert_eq!(
        COW_ZONE_COUNT.load(Ordering::Acquire),
        0,
        "COW refcount tables must be published exactly once"
    );
    COW_ZONE_COUNT.store(zone_count, Ordering::Release);
}

/// Publish the managed physical page windows (Zone 0 + aggregate total).
fn publish_managed_phys_windows(zone0_base: u64, zone0_size: usize, total_pages: usize) {
    assert_eq!(
        zone0_base % PAGE_SIZE,
        0,
        "managed physical base must be page aligned"
    );
    assert_eq!(
        zone0_size % PAGE_SIZE as usize,
        0,
        "managed physical size must be page aligned"
    );
    assert!(zone0_size > 0 && (zone0_size as u64) <= direct_map_limit());
    assert!(total_pages >= zone0_size / PAGE_SIZE as usize);
    assert_eq!(
        MANAGED_PHYS_PAGES.load(Ordering::Acquire),
        0,
        "managed physical window must be published exactly once"
    );
    assert_eq!(
        COW_ZONES[0].pages.load(Ordering::Acquire),
        zone0_size / PAGE_SIZE as usize,
        "COW refcount zone 0 length must match managed zone 0 page count"
    );

    MANAGED_PHYS_BASE.store(zone0_base, Ordering::Relaxed);
    MANAGED_PHYS_TOTAL_PAGES.store(total_pages, Ordering::Relaxed);
    MANAGED_PHYS_PAGES.store(zone0_size / PAGE_SIZE as usize, Ordering::Release);
}

/// Return Zone 0's buddy-owned physical page window after initialization.
#[inline]
pub fn managed_physical_page_window() -> Option<(u64, usize)> {
    let page_count = MANAGED_PHYS_PAGES.load(Ordering::Acquire);
    if page_count == 0 {
        return None;
    }
    Some((MANAGED_PHYS_BASE.load(Ordering::Relaxed), page_count))
}

/// Total physical pages managed across all published buddy zones.
#[inline]
pub fn managed_physical_total_pages() -> usize {
    if MANAGED_PHYS_PAGES.load(Ordering::Acquire) == 0 {
        return 0;
    }
    MANAGED_PHYS_TOTAL_PAGES.load(Ordering::Relaxed)
}

/// Number of published physical memory zones.
#[inline]
pub fn managed_physical_zone_count() -> usize {
    COW_ZONE_COUNT.load(Ordering::Acquire)
}

/// RF178-31: return the boot-reserved COW refcount slot for a Zone-0 page index.
#[inline]
pub fn cow_refcount_slot(index: usize) -> Option<&'static core::sync::atomic::AtomicU32> {
    if COW_ZONE_COUNT.load(Ordering::Acquire) == 0 {
        return None;
    }
    let len = COW_ZONES[0].pages.load(Ordering::Relaxed);
    if len == 0 || index >= len {
        return None;
    }
    let base = COW_ZONES[0].virt.load(Ordering::Relaxed);
    if base == 0 {
        return None;
    }
    // SAFETY: base/len published once after zeroing reserved frames; index < len.
    let slot = unsafe { &*(base as *const core::sync::atomic::AtomicU32).add(index) };
    Some(slot)
}

/// N3.1a (#67): O(zones) lock-free lookup of the COW refcount slot for any
/// managed physical page address across all published zones.
#[inline]
pub fn cow_refcount_slot_for_phys(phys: u64) -> Option<&'static core::sync::atomic::AtomicU32> {
    if phys & (PAGE_SIZE - 1) != 0 {
        return None;
    }
    let count = COW_ZONE_COUNT.load(Ordering::Acquire);
    for z in 0..count {
        let zone_base = COW_ZONES[z].base.load(Ordering::Relaxed);
        let len = COW_ZONES[z].pages.load(Ordering::Relaxed);
        if phys >= zone_base {
            let idx = ((phys - zone_base) / PAGE_SIZE) as usize;
            if idx < len {
                let virt = COW_ZONES[z].virt.load(Ordering::Relaxed);
                if virt == 0 {
                    return None;
                }
                // SAFETY: staged and zeroed before `COW_ZONE_COUNT` Release; idx < len.
                return Some(unsafe { &*(virt as *const core::sync::atomic::AtomicU32).add(idx) });
            }
        }
    }
    None
}

/// R167-C: Bounded accumulator for the buddy allocator's physical reservation
/// set. Ranges that do not intersect the managed window `[pmm_base, pmm_end)`
/// are dropped early (they would be clamped away by the buddy anyway), keeping
/// the bounded array focused on relevant reservations. On overflow it logs once
/// and drops further ranges — never silently, so a truncated reservation set is
/// always visible in the boot log.
struct ReservedRangeBuilder<'a> {
    ranges: &'a mut [(u64, u64); MAX_RESERVED_RANGES],
    count: usize,
    /// Set if any window-intersecting range could not be recorded (cap hit). The
    /// caller MUST then fail closed — see `build_buddy_reservations`.
    overflowed: bool,
    window_start: u64,
    window_end: u64,
}

impl<'a> ReservedRangeBuilder<'a> {
    fn new(
        ranges: &'a mut [(u64, u64); MAX_RESERVED_RANGES],
        pmm_base: u64,
        pmm_size: usize,
    ) -> Self {
        Self {
            ranges,
            count: 0,
            overflowed: false,
            window_start: pmm_base,
            window_end: pmm_base.saturating_add(pmm_size as u64),
        }
    }

    /// Record `[phys_start, phys_start + len_bytes)` if it is non-empty and
    /// intersects the managed window. If the bounded array is full, flag
    /// `overflowed` so the caller can fail closed instead of silently dropping a
    /// range that might be live.
    fn push(&mut self, phys_start: u64, len_bytes: u64) {
        if len_bytes == 0 || self.window_end <= self.window_start {
            return;
        }
        let phys_end = phys_start.saturating_add(len_bytes);
        if phys_end <= self.window_start || phys_start >= self.window_end {
            return; // disjoint from the buddy window
        }

        // GAP-6 F8 review: keep the last slots for the COW and buddy
        // metadata reservations pushed after this builder finishes.
        if self.count >= MAX_RESERVED_RANGES - BOOT_METADATA_RESERVATIONS {
            self.overflowed = true;
            return;
        }

        self.ranges[self.count] = (phys_start, len_bytes);
        self.count += 1;
    }
}

/// R167-B/C: Build the buddy allocator's permanent reservation set.
///
/// Replaces R166's `carve_region_around_heap`. Reserves, within the selected
/// buddy window `[pmm_base, pmm_base + pmm_size)`:
///   1. the kernel heap `[heap_phys, HEAP_SIZE)` — kernel-computed, ALWAYS valid;
///   2. the framebuffer `[base, size)` — an existing BootInfo field, always valid;
///   3. the kernel image `[kernel_phys_base, kernel_phys_size)` — an ABI mismatch
///      stops boot before any frames may enter the free pool;
///   4. every non-`CONVENTIONAL` UEFI descriptor that intersects the window —
///      defends against a mis-typed UEFI map and covers boot-services / loader /
///      ACPI / framebuffer-MMIO / page-table frames implicitly.
///
/// On a correctly-typed map the window is a single conventional region, so #2–#4
/// are clamped away and only the heap is actually reserved — but the protection
/// is robust if any live range is mis-reported as conventional.
fn build_buddy_reservations(
    boot_info: &BootInfo,
    pmm_base: u64,
    pmm_size: usize,
    heap_phys: u64,
    out: &mut [(u64, u64); MAX_RESERVED_RANGES],
) -> usize {
    require_boot_info_version(boot_info.version);

    // Build the reservation set inside a scope so the builder's borrow of `out`
    // ends before the fail-closed path may overwrite `out`.
    let (count, overflowed) = {
        let mut builder = ReservedRangeBuilder::new(out, pmm_base, pmm_size);

        // (1) Heap — always valid (kernel-computed); the core R166 guarantee.
        builder.push(heap_phys, HEAP_SIZE as u64);
        // (2) Framebuffer — pre-existing field, valid even with a stale bootloader.
        builder.push(
            boot_info.framebuffer.base,
            boot_info.framebuffer.size as u64,
        );
        // (3) The running kernel image must never enter the free-frame pool.
        builder.push(boot_info.kernel_phys_base, boot_info.kernel_phys_size);
        // (4) Every non-conventional UEFI range intersecting the window.
        add_non_conventional_uefi_reservations(&mut builder, &boot_info.memory_map);

        (builder.count, builder.overflowed)
    };

    // FAIL-CLOSED (R167 Codex review): if more than MAX_RESERVED_RANGES live
    // ranges intersect the window, we cannot prove every live frame is withheld.
    // Rather than silently drop a range (which could let the buddy hand out live
    // firmware/kernel memory — the exact class R167 closes), withhold the ENTIRE
    // window. Unreachable on a well-formed UEFI map (a single conventional window
    // is intersected by ~0 non-conventional ranges), so this only triggers on a
    // malformed/adversarial map, where refusing the window beats corruption.
    if overflowed {
        klog!(
            Warn,
            "  Warning: buddy reservation list exceeded {} entries; withholding the ENTIRE window (fail-closed)",
            MAX_RESERVED_RANGES
        );
        out[0] = (pmm_base, pmm_size as u64);
        return 1;
    }

    count
}

/// R167-C: Reserve every non-`EFI_CONVENTIONAL_MEMORY` descriptor that intersects
/// the buddy window. The builder's `push` discards disjoint ranges, so this only
/// adds entries when a live/firmware range actually overlaps the managed region.
fn add_non_conventional_uefi_reservations(
    builder: &mut ReservedRangeBuilder<'_>,
    map_info: &MemoryMapInfo,
) {
    let Some(desc_count) = validate_memory_map(map_info) else {
        return;
    };
    for i in 0..desc_count {
        let Some(offset) = i.checked_mul(map_info.descriptor_size) else {
            return;
        };
        let Some(addr) = map_info.buffer.checked_add(offset as u64) else {
            return;
        };
        let desc = unsafe { &*(addr as *const EfiMemoryDescriptor) };

        if desc.typ == EFI_CONVENTIONAL_MEMORY || desc.page_count == 0 {
            continue;
        }
        builder.push(desc.phys_start, desc.page_count.saturating_mul(PAGE_SIZE));
    }
}

/// 对齐到页边界（向上取整）
#[inline]
const fn align_up(val: u64, align: u64) -> u64 {
    (val + align - 1) & !(align - 1)
}

/// 对齐到页边界（向下取整）
#[inline]
const fn align_down(val: u64, align: u64) -> u64 {
    val & !(align - 1)
}

/// 改进的物理帧分配器（使用Buddy分配器）
pub struct FrameAllocator;

impl Default for FrameAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameAllocator {
    pub fn new() -> Self {
        FrameAllocator
    }

    /// 分配单个物理帧
    pub fn allocate_frame(&mut self) -> Option<PhysFrame> {
        buddy_allocator::alloc_physical_pages(1)
    }

    /// 分配连续的多个物理帧
    pub fn allocate_contiguous_frames(&mut self, count: usize) -> Option<PhysFrame> {
        buddy_allocator::alloc_physical_pages(count)
    }

    /// 释放物理帧
    pub fn deallocate_frame(&mut self, frame: PhysFrame) {
        buddy_allocator::free_physical_pages(frame, 1);
    }

    pub fn try_deallocate_frame(
        &mut self,
        frame: PhysFrame,
    ) -> Result<(), buddy_allocator::FreeError> {
        buddy_allocator::try_free_physical_pages(frame, 1)
    }

    /// 释放连续的多个物理帧
    pub fn deallocate_contiguous_frames(&mut self, frame: PhysFrame, count: usize) {
        buddy_allocator::free_physical_pages(frame, count);
    }

    /// Checked contiguous deallocation for security-sensitive rollback and
    /// deferred-reclaim paths. Success proves the exact original buddy block
    /// was accepted; callers can quarantine identity state on any error.
    pub fn try_deallocate_contiguous_frames(
        &mut self,
        frame: PhysFrame,
        count: usize,
    ) -> Result<(), buddy_allocator::FreeError> {
        buddy_allocator::try_free_physical_pages(frame, count)
    }

    /// 获取内存统计信息
    pub fn stats(&self) -> MemoryStats {
        let buddy_stats =
            buddy_allocator::get_allocator_stats().unwrap_or(buddy_allocator::AllocatorStats {
                total_pages: 0,
                free_pages: 0,
                reserved_pages: 0,
                used_pages: 0,
                fragmentation: 0.0,
            });

        MemoryStats {
            total_physical_pages: buddy_stats.total_pages,
            free_physical_pages: buddy_stats.free_pages,
            used_physical_pages: buddy_stats.used_pages,
            fragmentation_percent: (buddy_stats.fragmentation * 100.0) as u32,
            heap_used_bytes: heap_used_bytes()
                + (EMERGENCY_HEAP_SIZE_BYTES - emergency_heap_free_bytes()),
            heap_total_bytes: runtime_heap_size_bytes(),
        }
    }
}

/// N3.1b: Live used bytes across the normal kernel heap (early boot arena +
/// buddy-backed slab and large-page allocations). Lock-free.
#[inline]
pub fn heap_used_bytes() -> usize {
    EARLY_USED_BYTES
        .load(Ordering::Acquire)
        .saturating_add(crate::slab::live_bytes())
}

/// R178-11 / N3.1b: remaining normal-arena heap headroom within the runtime
/// RAM-scaled heap capacity (`runtime_normal_heap_size_bytes() - heap_used_bytes()`).
#[inline]
pub fn heap_free_bytes() -> usize {
    runtime_normal_heap_size_bytes().saturating_sub(heap_used_bytes())
}

/// N3.1b: observability snapshot of the buddy-backed slab allocator.
#[inline]
pub fn slab_stats() -> crate::slab::SlabStats {
    crate::slab::stats()
}

/// N3.1b: flush cached empty slab pages back to the buddy allocator.
#[inline]
pub fn reclaim_slab_caches() -> usize {
    crate::slab::reclaim_empty_slabs()
}

/// D1-RES R4: monotone peak of normal-arena USED bytes since allocator init.
/// Normal arena only; excludes the emergency arena. The first real peak evidence
/// for the boot-path residual (R4) — the integration checkpoint logs it as the
/// calibration source and asserts it under `BOOT_PEAK_USED_MAX_BYTES`.
#[inline]
pub fn heap_peak_used_bytes() -> usize {
    HEAP_PEAK_USED_BYTES.load(Ordering::Relaxed)
}

/// Free bytes in the physically isolated emergency arena.
#[inline]
pub fn emergency_heap_free_bytes() -> usize {
    if !EMERGENCY_ALLOCATOR_READY.load(Ordering::Acquire) {
        return 0;
    }
    EMERGENCY_ALLOCATOR.lock().free()
}

/// First virtual byte owned by the isolated emergency allocator.
#[inline]
pub fn emergency_heap_base() -> usize {
    heap_base() + NORMAL_HEAP_SIZE_BYTES
}

/// Boot-visible proof that the two allocators cannot return overlapping memory.
/// Both allocations are fallible and are released before return.
pub fn run_emergency_heap_self_test() {
    assert!(EMERGENCY_ALLOCATOR_READY.load(Ordering::Acquire));
    let emergency_before = emergency_heap_free_bytes();

    let normal = Box::try_new(0x4e4f_524du64).expect("normal heap self-test allocation");
    let emergency = Box::try_new_in(0x454d_4552u64, EmergencyAllocator)
        .expect("emergency heap self-test allocation");

    let normal_ptr = (&*normal as *const u64) as usize;
    let emergency_ptr = (&*emergency as *const u64) as usize;
    let emergency_base = emergency_heap_base();
    let heap_end = heap_base()
        .checked_add(HEAP_SIZE_BYTES)
        .expect("heap end overflow");

    let in_early_normal = normal_ptr >= heap_base() && normal_ptr < emergency_base;
    let dm_base = PHYSICAL_MEMORY_OFFSET as usize;
    let dm_end = dm_base.saturating_add(direct_map_limit() as usize);
    let in_slab_direct_map = normal_ptr >= dm_base && normal_ptr < dm_end;
    assert!(
        in_early_normal || in_slab_direct_map,
        "normal allocation 0x{:x} outside early normal heap and PML4[273] slab arena",
        normal_ptr
    );
    assert!(
        !(normal_ptr >= emergency_base && normal_ptr < heap_end),
        "normal allocation must never enter the isolated emergency arena"
    );
    assert!(emergency_ptr >= emergency_base && emergency_ptr < heap_end);
    assert_ne!(normal_ptr, emergency_ptr);

    // N3.1b: verify buddy-backed slab allocator is active and exercises both
    // small-object slab and large-page buddy paths cleanly.
    if crate::slab::is_active() {
        assert!(
            in_slab_direct_map,
            "active buddy-backed slab must serve post-boot allocations via PML4[273]"
        );
        let large: alloc::vec::Vec<u8> = {
            let mut v = alloc::vec::Vec::new();
            v.try_reserve_exact(8192)
                .expect("N3.1b large-page slab self-test allocation");
            v.resize(8192, 0xA5);
            v
        };
        let large_ptr = large.as_ptr() as usize;
        assert!(large_ptr >= dm_base && large_ptr < dm_end);
        assert_eq!(large[0], 0xA5);
        assert_eq!(large[8191], 0xA5);
        drop(large);
    }

    drop(emergency);
    drop(normal);
    assert_eq!(
        emergency_heap_free_bytes(),
        emergency_before,
        "emergency allocation must return to the isolated arena"
    );
}

/// 实现 x86_64 FrameAllocator trait 以便与页表管理器配合使用
unsafe impl X64FrameAllocator<Size4KiB> for FrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.allocate_frame()
    }
}

impl x86_64::structures::paging::FrameDeallocator<Size4KiB> for FrameAllocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        self.deallocate_frame(frame);
    }
}

/// 内存统计信息
#[derive(Debug, Clone, Copy)]
pub struct MemoryStats {
    pub total_physical_pages: usize,
    pub free_physical_pages: usize,
    pub used_physical_pages: usize,
    pub fragmentation_percent: u32,
    pub heap_used_bytes: usize,
    pub heap_total_bytes: usize,
}

impl MemoryStats {
    /// 打印内存统计信息
    pub fn print(&self) {
        klog!(Info, "=== Memory Statistics ===");
        klog!(Info, "Physical Memory:");
        klog!(
            Info,
            "  Total: {} pages ({} MB)",
            self.total_physical_pages,
            self.total_physical_pages * 4 / 1024
        );
        klog!(
            Info,
            "  Free:  {} pages ({} MB)",
            self.free_physical_pages,
            self.free_physical_pages * 4 / 1024
        );
        klog!(
            Info,
            "  Used:  {} pages ({} MB)",
            self.used_physical_pages,
            self.used_physical_pages * 4 / 1024
        );
        klog!(Info, "  Fragmentation: {}%", self.fragmentation_percent);
        klog!(Info, "Kernel Heap:");
        klog!(
            Info,
            "  Used:  {} KB / {} KB",
            self.heap_used_bytes / 1024,
            self.heap_total_bytes / 1024
        );
    }
}

// ============================================================================
// Partial KASLR: Public Accessors
// ============================================================================

/// Return the current heap base address.
///
/// This may differ from `HEAP_DEFAULT_BASE` if heap randomization was successful.
#[inline]
pub fn heap_base() -> usize {
    HEAP_BASE.load(Ordering::SeqCst)
}

/// Return the runtime kernel heap size in bytes (scaled from managed RAM).
#[inline]
pub fn heap_size() -> usize {
    runtime_heap_size_bytes()
}

/// Check if the heap was successfully randomized using early entropy.
///
/// Returns `true` if RDRAND was available and produced entropy during boot,
/// allowing the heap to be placed at a random address within the safe window.
#[inline]
pub fn heap_randomized() -> bool {
    HEAP_RANDOMIZED.load(Ordering::SeqCst)
}

/// Check if the heap address was validated against UEFI memory map.
///
/// Returns `true` if the heap base was verified to fall within
/// EFI_CONVENTIONAL_MEMORY regions during boot, ensuring it doesn't
/// overlap with ACPI tables or other reserved memory.
#[inline]
pub fn heap_validated() -> bool {
    HEAP_VALIDATED.load(Ordering::SeqCst)
}

#[cfg(all(test, feature = "host_harness"))]
mod tests {
    #[test]
    #[should_panic(expected = "BootInfo ABI mismatch")]
    fn stale_bootinfo_cannot_drop_the_live_kernel_reservation() {
        super::require_boot_info_version(super::BOOT_INFO_VERSION - 1);
    }

    use super::*;

    fn descriptor(typ: u32, phys_start: u64, page_count: u64) -> EfiMemoryDescriptor {
        EfiMemoryDescriptor {
            typ,
            pad: 0,
            phys_start,
            virt_start: 0,
            page_count,
            attribute: 0,
        }
    }

    #[test]
    fn cow_metadata_avoids_complete_boot_reservation_set() {
        const BASE: u64 = 0x0100_0000;
        const SIZE: usize = 16 * 1024 * 1024;
        let descriptors = [
            descriptor(EFI_CONVENTIONAL_MEMORY, BASE, SIZE as u64 / PAGE_SIZE),
            // Deliberately overlap a nominal conventional window with a
            // firmware-owned range to model the malformed map R180-29 covers.
            descriptor(3, BASE + SIZE as u64 - 0x2_0000, 8),
        ];
        let boot_info = BootInfo {
            memory_map: MemoryMapInfo {
                buffer: descriptors.as_ptr() as u64,
                size: core::mem::size_of_val(&descriptors),
                descriptor_size: core::mem::size_of::<EfiMemoryDescriptor>(),
                descriptor_version: 1,
            },
            framebuffer: FramebufferInfo {
                base: BASE + SIZE as u64 - 0x1_0000,
                size: 0x4000,
                width: 1,
                height: 1,
                stride: 4,
                pixel_format: PixelFormat::Rgb,
            },
            kaslr_slide: 0,
            rsdp_address: 0,
            cmdline_len: 0,
            cmdline: [0; 256],
            kernel_phys_base: BASE + SIZE as u64 - 0x4_0000,
            kernel_phys_size: 0x1_0000,
            version: BOOT_INFO_VERSION,
            kaslr_flags: 0,
            direct_map_base: PHYSICAL_MEMORY_OFFSET,
            direct_map_limit: DEFAULT_DIRECT_MAP_LIMIT,
        };

        let heap_phys = BASE + 0x20_0000;
        let mut reservations = [(0u64, 0u64); MAX_RESERVED_RANGES];
        let count = build_buddy_reservations(&boot_info, BASE, SIZE, heap_phys, &mut reservations);
        assert_eq!(count, 4, "heap, framebuffer, kernel, and firmware range");

        let (meta_phys, meta_bytes) =
            place_cow_refcount_metadata(BASE, SIZE, &reservations[..count]);
        let meta_end = meta_phys + meta_bytes as u64;
        for &(start, len) in &reservations[..count] {
            let Some((reserved_start, reserved_end)) =
                normalized_reservation(start, len, BASE, BASE + SIZE as u64)
            else {
                continue;
            };
            assert!(!half_open_ranges_overlap(
                meta_phys,
                meta_end,
                reserved_start,
                reserved_end
            ));
        }

        let new_count =
            push_cow_metadata_reservation(&mut reservations, count, meta_phys, meta_bytes);
        assert_eq!(new_count, count + 1);
    }

    #[test]
    fn cow_metadata_honors_outward_page_rounding() {
        const BASE: u64 = 0x0200_0000;
        const SIZE: usize = 4 * 1024 * 1024;
        let end = BASE + SIZE as u64;
        let reservations = [(end - PAGE_SIZE / 2, PAGE_SIZE / 2)];

        let (meta_phys, meta_bytes) = place_cow_refcount_metadata(BASE, SIZE, &reservations);
        assert!(meta_phys + meta_bytes as u64 <= end - PAGE_SIZE);
    }

    #[test]
    fn f8_buddy_metadata_is_reserved_beside_cow_metadata() {
        const BASE: u64 = 0x0500_0000;
        const SIZE: usize = 16 * 1024 * 1024;
        let end = BASE + SIZE as u64;
        let mut reservations = [(0u64, 0u64); MAX_RESERVED_RANGES];
        reservations[0] = (BASE + 0x20_0000, 0x20_0000);
        let (cow_phys, cow_bytes) = place_cow_refcount_metadata(BASE, SIZE, &reservations[..1]);
        let count = push_cow_metadata_reservation(&mut reservations, 1, cow_phys, cow_bytes);

        let (buddy_phys, buddy_bytes) = place_buddy_metadata(BASE, SIZE, &reservations[..count]);
        let buddy_end = buddy_phys + buddy_bytes as u64;
        assert_eq!(buddy_phys % PAGE_SIZE, 0);
        assert!(buddy_bytes >= buddy_allocator::BuddyAllocator::metadata_bytes(SIZE).unwrap());
        assert!(buddy_phys >= BASE && buddy_end <= end);
        for &(start, len) in &reservations[..count] {
            assert!(!half_open_ranges_overlap(
                buddy_phys,
                buddy_end,
                start,
                start + len
            ));
        }
        let count = push_boot_metadata_reservation(
            &mut reservations,
            count,
            buddy_phys,
            buddy_bytes,
            BUDDY_METADATA_LABEL,
        );

        // An allocator over this window never hands out a metadata frame.
        let mut allocator = buddy_allocator::BuddyAllocator::new_with_reservations(
            PhysAddr::new(BASE),
            SIZE,
            &reservations[..count],
        )
        .expect("allocator over reserved window");
        let cow_end = cow_phys + cow_bytes as u64;
        let mut handed_out = 0usize;
        while let Ok(frame) = allocator.try_alloc_pages(0) {
            let addr = frame.start_address().as_u64();
            assert!(!half_open_ranges_overlap(
                addr,
                addr + PAGE_SIZE,
                buddy_phys,
                buddy_end
            ));
            assert!(!half_open_ranges_overlap(
                addr,
                addr + PAGE_SIZE,
                cow_phys,
                cow_end
            ));
            handed_out += 1;
        }
        assert!(handed_out > 0);
    }

    #[test]
    #[should_panic(expected = "R180-29")]
    fn cow_metadata_fails_closed_when_window_is_fully_reserved() {
        const BASE: u64 = 0x0300_0000;
        const SIZE: usize = 4 * 1024 * 1024;
        let _ = place_cow_refcount_metadata(BASE, SIZE, &[(BASE, SIZE as u64)]);
    }

    #[test]
    fn r188_framebuffer_region_must_be_aligned_and_map_contained() {
        const BASE: u64 = 0x0400_0000;
        let descriptors = [descriptor(EFI_CONVENTIONAL_MEMORY, BASE, 16)];
        let map = MemoryMapInfo {
            buffer: descriptors.as_ptr() as u64,
            size: core::mem::size_of_val(&descriptors),
            descriptor_size: core::mem::size_of::<EfiMemoryDescriptor>(),
            descriptor_version: 1,
        };
        let valid = FramebufferInfo {
            base: BASE + 0x1000,
            size: 0x2000,
            width: 1,
            height: 1,
            stride: 4,
            pixel_format: PixelFormat::Rgb,
        };
        assert!(validate_framebuffer_region(&valid, &map));

        let misaligned = FramebufferInfo {
            base: valid.base + 1,
            ..valid
        };
        assert!(!validate_framebuffer_region(&misaligned, &map));
        let outside = FramebufferInfo {
            base: BASE + 0xF000,
            size: 0x2000,
            ..valid
        };
        assert!(!validate_framebuffer_region(&outside, &map));
    }

    #[test]
    fn n3_1a_select_regions_merges_adjacent_and_spans_pci_hole_above_1gib() {
        let gib = 1024u64 * 1024 * 1024;
        // Simulated 4 GiB Q35 UEFI map:
        // - two adjacent conventional spans in low RAM (16 MiB..1 GiB + 1 GiB..3 GiB)
        // - 3 GiB..4 GiB PCI MMIO hole (not conventional)
        // - 4 GiB..5 GiB high RAM
        let descriptors = [
            descriptor(
                EFI_CONVENTIONAL_MEMORY,
                0x0100_0000,
                (gib - 0x0100_0000) / PAGE_SIZE,
            ),
            descriptor(EFI_CONVENTIONAL_MEMORY, gib, (2 * gib) / PAGE_SIZE),
            descriptor(11, 3 * gib, gib / PAGE_SIZE), // MMIO hole
            descriptor(EFI_CONVENTIONAL_MEMORY, 4 * gib, gib / PAGE_SIZE),
        ];
        let boot_info = BootInfo {
            memory_map: MemoryMapInfo {
                buffer: descriptors.as_ptr() as u64,
                size: core::mem::size_of_val(&descriptors),
                descriptor_size: core::mem::size_of::<EfiMemoryDescriptor>(),
                descriptor_version: 1,
            },
            framebuffer: FramebufferInfo {
                base: 0,
                size: 0,
                width: 0,
                height: 0,
                stride: 0,
                pixel_format: PixelFormat::Unknown,
            },
            kaslr_slide: 0,
            rsdp_address: 0,
            cmdline_len: 0,
            cmdline: [0; 256],
            kernel_phys_base: 0x10_0000,
            kernel_phys_size: 0x40_0000,
            version: BOOT_INFO_VERSION,
            kaslr_flags: 0,
            direct_map_base: PHYSICAL_MEMORY_OFFSET,
            direct_map_limit: 5 * gib,
        };

        let (regions, count) = select_regions_from_bootinfo(&boot_info, 5 * gib);
        assert_eq!(
            count, 2,
            "expected merged low RAM zone + high RAM zone across PCI hole"
        );
        assert_eq!(regions[0], (0x0100_0000, (3 * gib - 0x0100_0000) as usize));
        assert_eq!(regions[1], (4 * gib, gib as usize));
    }
}
