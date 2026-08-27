use crate::buddy_allocator;
use crate::page_table::PHYSICAL_MEMORY_OFFSET;
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
    /// means a stale bootloader; the kernel then ignores the version-gated image
    /// fields above and still applies the always-valid heap + UEFI reservations.
    pub version: u64,
    /// RF180-32: placement provenance flags, appended after the v1 layout so a
    /// v2 kernel can inspect the stable `version` offset before trusting them.
    pub kaslr_flags: u64,
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
const BOOT_INFO_VERSION: u64 = 2;

/// Must match `BOOT_INFO_KASLR_RANDOMIZED` in the bootloader mirror.
const BOOT_INFO_KASLR_RANDOMIZED: u64 = 1 << 0;

/// R167-C: Upper bound on the number of physical reservations passed to the
/// buddy allocator at init. Bounded to avoid heap allocation during early MM
/// bring-up; overflow is logged (never silently truncated).
const MAX_RESERVED_RANGES: usize = 64;

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
/// (`NORMAL_HEAP_SIZE_BYTES - free`), updated inside the single allocator lock
/// every `alloc` already holds. Normal arena only; excludes the emergency arena.
static HEAP_PEAK_USED_BYTES: AtomicUsize = AtomicUsize::new(0);

/// D1-RES R4: ZST `#[global_allocator]` shim over `ALLOCATOR`. Semantics are
/// IDENTICAL to `linked_list_allocator::LockedHeap`'s own `GlobalAlloc` impl
/// (delegate to `allocate_first_fit` / `deallocate` on the same inner `Heap`)
/// plus one `fetch_max` of the used-bytes peak computed under the single
/// already-held lock — exact, no double-acquire, no new lock-order edge. The
/// shim itself never allocates or logs. A pre-init or OOM alloc returns
/// `Err → null`, which `handle_alloc_error` turns into the same fail-closed halt
/// as before this shim existed.
struct InstrumentedKernelHeap;

unsafe impl GlobalAlloc for InstrumentedKernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut heap = ALLOCATOR.lock();
        match heap.allocate_first_fit(layout) {
            Ok(ptr) => {
                let used = NORMAL_HEAP_SIZE_BYTES.saturating_sub(heap.free());
                HEAP_PEAK_USED_BYTES.fetch_max(used, Ordering::Relaxed);
                ptr.as_ptr()
            }
            Err(_) => core::ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        ALLOCATOR
            .lock()
            .deallocate(NonNull::new_unchecked(ptr), layout);
    }
}

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

/// Published after the buddy allocator has accepted its one contiguous window.
/// Readers load the page count with Acquire before using the base.
static MANAGED_PHYS_BASE: AtomicU64 = AtomicU64::new(0);
static MANAGED_PHYS_PAGES: AtomicUsize = AtomicUsize::new(0);

/// RF178-31: virtual address of the boot-reserved `[AtomicU32; managed_pages]`
/// table (direct-map of permanently reserved physical frames). Zero until
/// `publish_cow_refcount_table` runs exactly once during MM init.
static COW_REFCOUNT_TABLE_VIRT: AtomicUsize = AtomicUsize::new(0);
/// Length of the published table in entries (== managed page count).
static COW_REFCOUNT_TABLE_LEN: AtomicUsize = AtomicUsize::new(0);

/// 页大小
const PAGE_SIZE: u64 = 0x1000;
/// 最小可用区域（跳过小于 2MB 的碎片区域）
const MIN_USABLE_REGION: u64 = 2 * 1024 * 1024;
/// 跳过低于 1MB 的区域（保护 BIOS/VGA 等）
const MIN_SAFE_ADDRESS: u64 = 0x100000;
/// 高半区直映上限（Bootloader 映射了物理 0-1GB 到 0xffffffff80000000-...）
/// 只能使用此范围内的物理内存（超出范围将不可访问）
const HIGH_HALF_MAP_LIMIT: u64 = 1024 * 1024 * 1024; // 1GB

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
    // R148-8 FIX: Gate raw address logging behind debug_assertions to prevent
    // KASLR bypass via heap base address leak in Performance profile (where
    // KptrGuard is disabled).
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

    // 从 BootInfo 解析内存映射
    let (pmm_base, pmm_size) = select_region_from_bootinfo(boot_info).unwrap_or_else(|| {
        klog!(
            Warn,
            "  Warning: BootInfo memory map unavailable, using fallback region"
        );
        (FALLBACK_PHYS_MEM_START, FALLBACK_PHYS_MEM_SIZE)
    });

    // R167-B/C: build the buddy allocator's permanent reservation set instead of
    // R166's "carve the larger half" heuristic. The buddy now manages the FULL
    // selected region minus precise per-page holes, reclaiming the memory the
    // carve discarded. The heap reservation preserves R166's core guarantee — the
    // KASLR-randomized linked-list heap and the buddy frame allocator never share
    // a physical frame (which previously let the buddy hand out a live heap frame
    // whose DMA/page-zeroing consumer corrupted the TIMER_CBS buffer → RIP=0).
    let heap_phys = (heap_base as u64).wrapping_sub(PHYSICAL_MEMORY_OFFSET);
    let mut reserved_ranges = [(0u64, 0u64); MAX_RESERVED_RANGES];
    let reserved_count = build_buddy_reservations(
        boot_info,
        pmm_base,
        pmm_size,
        heap_phys,
        &mut reserved_ranges,
    );

    // RF178-31 / R180-29: reserve exact-sized COW refcount metadata from the
    // discovered physical window (not the 1 MiB heap). Placement is computed
    // against the COMPLETE boot reservation set before the metadata is zeroed,
    // including framebuffer, kernel image, and non-conventional UEFI ranges.
    let (meta_phys, meta_bytes) =
        place_cow_refcount_metadata(pmm_base, pmm_size, &reserved_ranges[..reserved_count]);
    let reserved_count =
        push_cow_metadata_reservation(&mut reserved_ranges, reserved_count, meta_phys, meta_bytes);
    let reserved_ranges = &reserved_ranges[..reserved_count];

    // R148-8 FIX: Physical memory region bounds also leak information.
    #[cfg(debug_assertions)]
    klog!(
        Info,
        "  Physical memory region: 0x{:x} - 0x{:x} ({} MB)",
        pmm_base,
        pmm_base + pmm_size as u64,
        pmm_size / (1024 * 1024)
    );
    #[cfg(not(debug_assertions))]
    klog!(
        Info,
        "  Physical memory region: {} MB",
        pmm_size / (1024 * 1024)
    );
    klog!(
        Info,
        "  COW refcount metadata: {} KB (boot-reserved frames)",
        meta_bytes / 1024
    );

    // 初始化 Buddy 物理页分配器
    buddy_allocator::init_buddy_allocator(PhysAddr::new(pmm_base), pmm_size, reserved_ranges)
        .unwrap_or_else(|error| {
            panic!(
                "buddy allocator metadata initialization failed before publication: {:?}",
                error
            )
        });
    publish_cow_refcount_table(meta_phys, pmm_size / PAGE_SIZE as usize);
    publish_managed_phys_window(pmm_base, pmm_size);

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
    let heap_phys = (heap_base as u64).wrapping_sub(PHYSICAL_MEMORY_OFFSET);
    let mut reserved_ranges = [(0u64, 0u64); MAX_RESERVED_RANGES];
    reserved_ranges[0] = (heap_phys, HEAP_SIZE as u64);
    let (meta_phys, meta_bytes) = place_cow_refcount_metadata(
        FALLBACK_PHYS_MEM_START,
        FALLBACK_PHYS_MEM_SIZE,
        &reserved_ranges[..1],
    );
    let reserved_count =
        push_cow_metadata_reservation(&mut reserved_ranges, 1, meta_phys, meta_bytes);
    buddy_allocator::init_buddy_allocator(
        PhysAddr::new(FALLBACK_PHYS_MEM_START),
        FALLBACK_PHYS_MEM_SIZE,
        &reserved_ranges[..reserved_count],
    )
    .unwrap_or_else(|error| {
        panic!(
            "fallback buddy allocator metadata initialization failed before publication: {:?}",
            error
        )
    });
    publish_cow_refcount_table(meta_phys, FALLBACK_PHYS_MEM_SIZE / PAGE_SIZE as usize);
    publish_managed_phys_window(FALLBACK_PHYS_MEM_START, FALLBACK_PHYS_MEM_SIZE);

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

        // Convert virtual address to physical (bootloader maps phys 0-1GB to 0xffffffff80000000)
        let phys_base = heap_base as u64 - PHYSICAL_MEMORY_OFFSET;

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
/// 1. It's within the bootloader's direct-map limit (1GB)
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

    // Must be within bootloader's direct-map range
    if phys_end > HIGH_HALF_MAP_LIMIT {
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

/// 从 BootInfo 选择最大的可用内存区域
///
/// 遍历 UEFI 内存映射，找到最大的 EfiConventionalMemory 区域
fn select_region_from_bootinfo(boot_info: &BootInfo) -> Option<(u64, usize)> {
    let map_info = &boot_info.memory_map;

    // 验证内存映射有效性
    let desc_count = validate_memory_map(map_info)?;
    let mut best: Option<(u64, u64)> = None;
    let mut total_conventional: u64 = 0;

    klog_always!("  Scanning UEFI memory map ({} descriptors)...", desc_count);

    for i in 0..desc_count {
        let offset = i.checked_mul(map_info.descriptor_size)?;
        let addr = map_info.buffer.checked_add(offset as u64)?;
        let desc = unsafe { &*(addr as *const EfiMemoryDescriptor) };

        // R167-A: 只接纳 EFI_CONVENTIONAL_MEMORY 作为 buddy 分配器内存。
        // Boot-Services Code/Data 在 ExitBootServices 后名义上可用，但固件常在
        // 其中保留运行期数据，交给 buddy 会破坏存活固件内存——故不再接纳。
        if desc.typ != EFI_CONVENTIONAL_MEMORY || desc.page_count == 0 {
            continue;
        }

        let start = align_up(desc.phys_start, PAGE_SIZE);
        let raw_length = desc.page_count.saturating_mul(PAGE_SIZE);
        let usable_length = raw_length.saturating_sub(start.saturating_sub(desc.phys_start));

        // 跳过超出高半区直映范围的区域（>1GB）
        if start >= HIGH_HALF_MAP_LIMIT {
            continue;
        }

        // 如果区域跨越 1GB 边界，截断到 1GB
        let end = start.saturating_add(usable_length);
        let clamped_end = end.min(HIGH_HALF_MAP_LIMIT);
        let clamped_length = clamped_end.saturating_sub(start);

        // 跳过太小或地址太低的区域
        if clamped_length < MIN_USABLE_REGION || start < MIN_SAFE_ADDRESS {
            continue;
        }

        total_conventional += clamped_length;

        // 记录最大区域
        if best.is_none_or(|(_, size)| clamped_length > size) {
            best = Some((start, clamped_length));
        }
    }

    klog!(
        Info,
        "  Total usable memory: {} MB",
        total_conventional / (1024 * 1024)
    );

    // RF178-31: manage the full discovered conventional window up to the
    // architectural high-half direct-map limit only. No artificial RAM cap.
    best.map(|(base, size)| (base, size as usize))
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
///
/// Search downward from the high end to preserve a large low free span. On a
/// collision, jump below the lowest overlapping reservation rather than walking
/// page-by-page. The bounded reservation array therefore limits this to at most
/// `reservations.len() + 1` probes and the early-boot path allocates no heap.
fn place_cow_refcount_metadata(
    pmm_base: u64,
    pmm_size: usize,
    reservations: &[(u64, u64)],
) -> (u64, usize) {
    assert!(pmm_size > 0, "managed window must be non-empty");
    assert_eq!(pmm_base % PAGE_SIZE, 0, "managed base must be page aligned");
    assert_eq!(
        pmm_size % PAGE_SIZE as usize,
        0,
        "managed size must be page aligned"
    );

    let managed_pages = pmm_size / PAGE_SIZE as usize;
    let meta_bytes_raw = cow_refcount_table_bytes(managed_pages);
    let meta_bytes = align_up(meta_bytes_raw as u64, PAGE_SIZE) as usize;
    assert!(
        meta_bytes > 0 && meta_bytes < pmm_size,
        "COW metadata ({} B) must fit strictly inside managed window ({} B)",
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
        "R180-29: cannot place COW refcount metadata ({} KB) inside managed window without colliding with boot reservations",
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
    if count >= MAX_RESERVED_RANGES {
        panic!("RF178-31: reservation list full; cannot permanently reserve COW metadata");
    }
    assert_eq!(
        meta_phys % PAGE_SIZE,
        0,
        "COW metadata must be page aligned"
    );
    assert!(meta_bytes > 0, "COW metadata reservation must be non-empty");
    let meta_end = meta_phys
        .checked_add(meta_bytes as u64)
        .expect("COW metadata reservation end overflow");
    for &(reserved_start, reserved_len) in &out[..count] {
        if reserved_len == 0 {
            continue;
        }
        let reserved_end = reserved_start.saturating_add(reserved_len);
        assert!(
            !half_open_ranges_overlap(meta_phys, meta_end, reserved_start, reserved_end),
            "R180-29: COW metadata overlaps an existing boot reservation"
        );
    }
    out[count] = (meta_phys, meta_bytes as u64);
    count + 1
}

/// Zero and publish the boot-reserved COW refcount table via the direct map.
///
/// # Safety contract
///
/// `meta_phys` must be page-aligned, permanently reserved out of the buddy free
/// pool, and fully covered by the high-half direct map. Called exactly once,
/// single-threaded, before any AP is launched and before any fork/COW path runs.
fn publish_cow_refcount_table(meta_phys: u64, managed_pages: usize) {
    assert_eq!(
        meta_phys % PAGE_SIZE,
        0,
        "COW metadata physical base must be page aligned"
    );
    assert!(managed_pages > 0, "managed page count must be non-zero");
    assert_eq!(
        COW_REFCOUNT_TABLE_LEN.load(Ordering::Acquire),
        0,
        "COW refcount table must be published exactly once"
    );

    let meta_bytes = cow_refcount_table_bytes(managed_pages);
    let virt = meta_phys
        .checked_add(PHYSICAL_MEMORY_OFFSET)
        .expect("COW metadata direct-map address overflow");
    let ptr = virt as *mut u8;

    // SAFETY: meta_phys is inside the managed window which is clamped to the
    // high-half direct map; the frames are permanently reserved and not yet
    // used by any other subsystem.
    unsafe {
        core::ptr::write_bytes(ptr, 0, meta_bytes);
    }

    // Publish base first, then length with Release. Readers Acquire-load length
    // and only then read the base; if length != 0 they observe this base.
    COW_REFCOUNT_TABLE_VIRT.store(virt as usize, Ordering::Release);
    COW_REFCOUNT_TABLE_LEN.store(managed_pages, Ordering::Release);

    klog!(
        Info,
        "  COW refcount table published: {} entries ({} KB)",
        managed_pages,
        meta_bytes / 1024
    );
}

/// Publish the exact physical-page index domain used by the buddy allocator.
fn publish_managed_phys_window(base: u64, size: usize) {
    assert_eq!(
        base % PAGE_SIZE,
        0,
        "managed physical base must be page aligned"
    );
    assert_eq!(
        size % PAGE_SIZE as usize,
        0,
        "managed physical size must be page aligned"
    );
    // RF178-31: only the architectural direct-map limit bounds the window.
    assert!(size > 0 && (size as u64) <= HIGH_HALF_MAP_LIMIT);
    assert_eq!(
        MANAGED_PHYS_PAGES.load(Ordering::Acquire),
        0,
        "managed physical window must be published exactly once"
    );
    // Metadata table must already cover the full window (same page count).
    assert_eq!(
        COW_REFCOUNT_TABLE_LEN.load(Ordering::Acquire),
        size / PAGE_SIZE as usize,
        "COW refcount table length must match managed page count"
    );

    MANAGED_PHYS_BASE.store(base, Ordering::Relaxed);
    MANAGED_PHYS_PAGES.store(size / PAGE_SIZE as usize, Ordering::Release);
}

/// Return the buddy-owned physical page window after initialization.
#[inline]
pub fn managed_physical_page_window() -> Option<(u64, usize)> {
    let page_count = MANAGED_PHYS_PAGES.load(Ordering::Acquire);
    if page_count == 0 {
        return None;
    }
    Some((MANAGED_PHYS_BASE.load(Ordering::Relaxed), page_count))
}

/// RF178-31: return the boot-reserved COW refcount slot for a managed page index.
///
/// Returns `None` when the table is unpublished or `index` is out of range.
/// The table lives in permanently reserved physical frames (not the heap); every
/// access is O(1) and allocation-free.
#[inline]
pub fn cow_refcount_slot(index: usize) -> Option<&'static core::sync::atomic::AtomicU32> {
    let len = COW_REFCOUNT_TABLE_LEN.load(Ordering::Acquire);
    if len == 0 || index >= len {
        return None;
    }
    let base = COW_REFCOUNT_TABLE_VIRT.load(Ordering::Relaxed);
    if base == 0 {
        return None;
    }
    // SAFETY: base/len published once after zeroing reserved frames; index < len.
    let slot = unsafe { &*(base as *const core::sync::atomic::AtomicU32).add(index) };
    Some(slot)
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

        if self.count >= MAX_RESERVED_RANGES {
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
///   3. the kernel image `[kernel_phys_base, kernel_phys_size)` — only when the
///      BootInfo version matches (the field is otherwise from a stale bootloader);
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
    let version_ok = boot_info.version == BOOT_INFO_VERSION;
    if !version_ok {
        klog!(
            Warn,
            "  Warning: BootInfo version {} != expected {}; ignoring kernel-image reservation",
            boot_info.version,
            BOOT_INFO_VERSION
        );
    }

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
        // (3) Kernel image — only trust the new fields when the ABI version matches.
        if version_ok {
            builder.push(boot_info.kernel_phys_base, boot_info.kernel_phys_size);
        }
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
            heap_used_bytes: (NORMAL_HEAP_SIZE_BYTES - ALLOCATOR.lock().free())
                + (EMERGENCY_HEAP_SIZE_BYTES - EMERGENCY_ALLOCATOR.lock().free()),
            heap_total_bytes: HEAP_SIZE,
        }
    }
}

/// R178-11: current free bytes in the kernel heap (`linked_list_allocator`).
///
/// Leaf call: locks `ALLOCATOR` only to read `free()` and releases immediately —
/// the same lock every allocation already takes (and that `get_memory_stats`
/// above reads at line ~834), so it adds no new lock-ordering hazard. Used by
/// the page cache to refuse a metadata allocation before it can drive the
/// 1 MiB heap to `handle_alloc_error`. Returns TOTAL free bytes, not the
/// largest contiguous run — a necessary-not-sufficient headroom check.
#[inline]
pub fn heap_free_bytes() -> usize {
    ALLOCATOR.lock().free()
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

    assert!(normal_ptr >= heap_base() && normal_ptr < emergency_base);
    assert!(emergency_ptr >= emergency_base && emergency_ptr < heap_end);
    assert_ne!(normal_ptr, emergency_ptr);

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

/// Return the heap size in bytes.
#[inline]
pub fn heap_size() -> usize {
    HEAP_SIZE
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
}
