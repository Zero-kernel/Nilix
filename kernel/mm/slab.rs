//! N3.1b (`HEAP-SCALE`, #67): Buddy-backed slab + large-page kernel heap allocator.
//!
//! Replaces the fixed 2 MiB early `linked_list_allocator` after the multi-zone
//! buddy allocator is published. Small allocations (`<= 2016 B`) are served
//! from 14 per-size-class 4 KiB slabs backed by buddy pages mapped via the
//! `PML4[273]` linear direct map; larger allocations route directly to
//! power-of-two buddy blocks (up to 4 MiB, order 10).
//!
//! # Locking & IRQ Safety
//!
//! Each size class owns an independent `spin::Mutex<SlabBin>` acquired with
//! interrupts disabled on bare-metal (`without_interrupts`). Page allocation
//! and deallocation against the buddy allocator always run **outside** the bin
//! lock, so `SlabBin` and `BuddyAllocator` locks never nest.
//!
//! # Memory Safety Invariants
//!
//! - Every slab page carries a 64-byte [`SlabPageHeader`] at page offset 0 with
//!   a 256-bit allocation bitmap (`[u64; 4]`) and magic/class tag.
//! - `dealloc` validates the magic, class index, slot alignment, slot bounds,
//!   and bitmap occupancy bit (fail-closed double-free and cross-class guard).
//! - Live allocations are bounded by a runtime RAM-scaled capacity ceiling
//!   (`capacity_bytes`), enforced lock-free before allocating backing pages.
//! - Empty slabs above [`MAX_CACHED_EMPTY_SLABS`] are immediately returned to
//!   the buddy allocator, and [`reclaim_empty_slabs`] flushes all cached empty
//!   slabs on demand under memory pressure.

use core::alloc::Layout;
use core::mem::size_of;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

/// Base page size (4 KiB).
pub const SLAB_PAGE_SIZE: usize = 4096;

/// Maximum contiguous buddy block order supported by the large-page path
/// (`2^10 * 4 KiB = 4 MiB`, matching `buddy_allocator::ORDER_COUNT - 1`).
pub const MAX_LARGE_BUDDY_ORDER: usize = 10;
pub const MAX_LARGE_BUDDY_PAGES: usize = 1 << MAX_LARGE_BUDDY_ORDER;

/// Number of slab size classes (all 4 KiB single-page slabs).
pub const SLAB_CLASS_COUNT: usize = 14;

/// Hysteresis limit of empty slabs retained per size class before returning
/// pages directly to the buddy allocator.
pub const MAX_CACHED_EMPTY_SLABS: usize = 2;

const SLAB_MAGIC: u32 = 0x534C_4142; // "SLAB"

const LIST_DETACHED: u16 = 0;
const LIST_PARTIAL: u16 = 1;
const LIST_FULL: u16 = 2;
const LIST_EMPTY: u16 = 3;

/// Geometry descriptor for one slab size class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlabClassSpec {
    pub slot_size: usize,
    pub slot_align: usize,
    pub pages_per_slab: usize,
    pub first_slot_off: usize,
    pub capacity: usize,
}

impl SlabClassSpec {
    const fn new(slot_size: usize, slot_align: usize, pages_per_slab: usize) -> Self {
        let header = size_of::<SlabPageHeader>();
        let first_slot_off = if header >= slot_align {
            (header + slot_align - 1) & !(slot_align - 1)
        } else {
            slot_align
        };
        let slab_bytes = pages_per_slab * SLAB_PAGE_SIZE;
        let capacity = (slab_bytes - first_slot_off) / slot_size;
        Self {
            slot_size,
            slot_align,
            pages_per_slab,
            first_slot_off,
            capacity,
        }
    }

    #[inline]
    pub const fn slab_bytes(&self) -> usize {
        self.pages_per_slab * SLAB_PAGE_SIZE
    }
}

/// Ordered table of 4 KiB slab size classes (`16 B` .. `2016 B`).
/// Intermediate classes (`48, 96, 192, 384, 768, 1344, 2016`) keep internal
/// fragmentation low (<= 33% up to 1 KiB, 2–3 objects/page up to 2016 B).
/// Keeping every slab strictly 1 page (4 KiB) guarantees `ptr & !0xFFF`
/// locates the [`SlabPageHeader`] in O(1) regardless of buddy zone base
/// parity; larger or higher-aligned allocations route directly to buddy pages.
pub const SLAB_CLASSES: [SlabClassSpec; SLAB_CLASS_COUNT] = [
    SlabClassSpec::new(16, 16, 1),
    SlabClassSpec::new(32, 32, 1),
    SlabClassSpec::new(48, 16, 1),
    SlabClassSpec::new(64, 64, 1),
    SlabClassSpec::new(96, 32, 1),
    SlabClassSpec::new(128, 128, 1),
    SlabClassSpec::new(192, 64, 1),
    SlabClassSpec::new(256, 256, 1),
    SlabClassSpec::new(384, 64, 1),
    SlabClassSpec::new(512, 512, 1),
    SlabClassSpec::new(768, 64, 1),
    SlabClassSpec::new(1024, 1024, 1),
    SlabClassSpec::new(1344, 64, 1),
    SlabClassSpec::new(2016, 32, 1),
];

/// Exact 64-byte intrusive slab page header placed at offset 0 of every slab.
#[repr(C, align(64))]
struct SlabPageHeader {
    prev: *mut SlabPageHeader,
    next: *mut SlabPageHeader,
    /// Occupancy bitmap: bit `i` == 1 iff slot `i` is currently allocated.
    alloc_bitmap: [u64; 4],
    magic: u32,
    class_idx: u16,
    in_use: u16,
    capacity: u16,
    slot_size: u16,
    first_slot_off: u16,
    list_state: u16,
}

const _: () = assert!(size_of::<SlabPageHeader>() == 64);

const _: () = {
    let mut i = 0;
    while i < SLAB_CLASS_COUNT {
        let spec = SLAB_CLASSES[i];
        assert!(spec.slot_align.is_power_of_two());
        assert!(spec.pages_per_slab.is_power_of_two());
        assert!(spec.first_slot_off >= size_of::<SlabPageHeader>());
        assert!(spec.first_slot_off % spec.slot_align == 0);
        assert!(spec.slot_size % spec.slot_align == 0);
        assert!(spec.capacity > 0 && spec.capacity <= 256);
        assert!(spec.first_slot_off + spec.capacity * spec.slot_size <= spec.slab_bytes());
        i += 1;
    }
};

/// Select the slab size class index for `layout`, or `None` if `layout` must
/// be served by the large-page buddy path.
#[inline]
pub const fn slab_class_index(layout: Layout) -> Option<usize> {
    let size = layout.size();
    let align = layout.align();
    let mut i = 0;
    while i < SLAB_CLASS_COUNT {
        let spec = SLAB_CLASSES[i];
        if size <= spec.slot_size && align <= spec.slot_align {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Compute `(requested_pages, buddy_pages)` for a large allocation (`> 2016 B`
/// or alignment exceeding slab classes), returning `None` if it exceeds buddy
/// `MAX_ORDER`.
///
/// `requested_pages` is the exact 4 KiB page count needed for the layout (used
/// for logical `live_bytes` accounting so power-of-two buddy order rounding
/// does not look like unattributed heap drift), while `buddy_pages` is the
/// power-of-two contiguous page count allocated from and freed back to buddy.
#[inline]
pub const fn large_alloc_pages(layout: Layout) -> Option<(usize, usize)> {
    let size = layout.size();
    let align = layout.align();
    let needed = if size >= align { size } else { align };
    let Some(rounded) = needed.checked_add(SLAB_PAGE_SIZE - 1) else {
        return None;
    };
    let raw_pages = rounded / SLAB_PAGE_SIZE;
    if raw_pages == 0 || raw_pages > MAX_LARGE_BUDDY_PAGES {
        return None;
    }
    let buddy_pages = raw_pages.next_power_of_two();
    if buddy_pages > MAX_LARGE_BUDDY_PAGES {
        return None;
    }
    Some((raw_pages, buddy_pages))
}

/// Backing page allocator abstraction (buddy in production, `std::alloc` in host tests).
pub trait PageBackend: Sync {
    /// Allocate `pages` (power of two) contiguous pages aligned to `pages * 4096`.
    fn alloc_pages(&self, pages: usize) -> Option<NonNull<u8>>;
    /// Free `pages` previously returned by [`Self::alloc_pages`].
    unsafe fn free_pages(&self, ptr: NonNull<u8>, pages: usize);
}

/// Production backend backed by the multi-zone buddy allocator via `PML4[273]`.
pub struct BuddyPageBackend;

impl PageBackend for BuddyPageBackend {
    fn alloc_pages(&self, pages: usize) -> Option<NonNull<u8>> {
        debug_assert!(pages > 0 && pages.is_power_of_two());
        let frame = crate::buddy_allocator::alloc_physical_pages(pages)?;
        let len = (pages * SLAB_PAGE_SIZE) as u64;
        let virt = crate::page_table::try_phys_to_virt(frame.start_address(), len)?;
        NonNull::new(virt.as_mut_ptr())
    }

    unsafe fn free_pages(&self, ptr: NonNull<u8>, pages: usize) {
        debug_assert!(pages > 0 && pages.is_power_of_two());
        let len = (pages * SLAB_PAGE_SIZE) as u64;
        let virt = x86_64::VirtAddr::new(ptr.as_ptr() as u64);
        let phys = crate::page_table::virt_to_phys_direct(virt, len)
            .expect("N3.1b slab: freed page pointer outside PML4[273] direct map");
        let frame = x86_64::structures::paging::PhysFrame::containing_address(phys);
        crate::buddy_allocator::free_physical_pages(frame, pages);
    }
}

/// Intrusive doubly-linked list head for slab pages of one state.
struct SlabList {
    head: *mut SlabPageHeader,
}

impl SlabList {
    const fn new() -> Self {
        Self {
            head: ptr::null_mut(),
        }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.head.is_null()
    }

    unsafe fn push_front(&mut self, node: *mut SlabPageHeader, state: u16) {
        debug_assert!((*node).prev.is_null() && (*node).next.is_null());
        (*node).prev = ptr::null_mut();
        (*node).next = self.head;
        (*node).list_state = state;
        if !self.head.is_null() {
            (*self.head).prev = node;
        }
        self.head = node;
    }

    unsafe fn pop_front(&mut self) -> Option<*mut SlabPageHeader> {
        let node = self.head;
        if node.is_null() {
            return None;
        }
        self.remove(node);
        Some(node)
    }

    unsafe fn remove(&mut self, node: *mut SlabPageHeader) {
        let prev = (*node).prev;
        let next = (*node).next;
        if !prev.is_null() {
            (*prev).next = next;
        } else {
            self.head = next;
        }
        if !next.is_null() {
            (*next).prev = prev;
        }
        (*node).prev = ptr::null_mut();
        (*node).next = ptr::null_mut();
        (*node).list_state = LIST_DETACHED;
    }
}

/// Per-size-class slab bin protected by its own IRQ-safe spinlock.
struct SlabBin {
    partial: SlabList,
    full: SlabList,
    empty: SlabList,
    empty_count: usize,
    total_slabs: usize,
    live_objects: usize,
}

// SAFETY: `SlabBin` owns the raw pointers in its intrusive lists exclusively
// under its surrounding `Mutex`.
unsafe impl Send for SlabBin {}

impl SlabBin {
    const fn new() -> Self {
        Self {
            partial: SlabList::new(),
            full: SlabList::new(),
            empty: SlabList::new(),
            empty_count: 0,
            total_slabs: 0,
            live_objects: 0,
        }
    }

    /// Allocate one slot from an existing partial or cached-empty slab.
    unsafe fn try_alloc_fast(&mut self) -> Option<NonNull<u8>> {
        let page = if !self.partial.is_empty() {
            self.partial.head
        } else if let Some(empty_page) = self.empty.pop_front() {
            self.empty_count -= 1;
            self.partial.push_front(empty_page, LIST_PARTIAL);
            empty_page
        } else {
            return None;
        };

        let ptr = alloc_slot_from_page(page);
        self.live_objects += 1;
        if (*page).in_use == (*page).capacity {
            self.partial.remove(page);
            self.full.push_front(page, LIST_FULL);
        }
        Some(ptr)
    }

    /// Insert a newly initialized slab page and immediately allocate slot 0.
    unsafe fn insert_and_alloc(&mut self, page: *mut SlabPageHeader) -> NonNull<u8> {
        self.total_slabs += 1;
        self.partial.push_front(page, LIST_PARTIAL);
        let ptr = alloc_slot_from_page(page);
        self.live_objects += 1;
        if (*page).in_use == (*page).capacity {
            self.partial.remove(page);
            self.full.push_front(page, LIST_FULL);
        }
        ptr
    }

    /// Free `ptr` belonging to `class_idx`. Returns `Some(page_ptr)` if the
    /// slab became empty and exceeded [`MAX_CACHED_EMPTY_SLABS`], so the caller
    /// can return the page to the backend **outside** the bin lock.
    unsafe fn free_slot(&mut self, ptr: *mut u8, class_idx: usize) -> Option<NonNull<u8>> {
        let spec = SLAB_CLASSES[class_idx];
        let slab_mask = !(spec.slab_bytes() - 1);
        let page_addr = (ptr as usize) & slab_mask;
        let header = page_addr as *mut SlabPageHeader;

        assert_eq!(
            (*header).magic,
            SLAB_MAGIC,
            "N3.1b slab corruption: invalid page magic on dealloc (ptr={:p})",
            ptr
        );
        assert_eq!(
            (*header).class_idx as usize,
            class_idx,
            "N3.1b slab corruption: cross-class dealloc (expected class {}, header class {})",
            class_idx,
            (*header).class_idx
        );

        let offset = (ptr as usize)
            .checked_sub(page_addr)
            .expect("slab ptr below page base");
        assert!(
            offset >= spec.first_slot_off,
            "N3.1b slab corruption: pointer inside slab header (offset={})",
            offset
        );
        let rel = offset - spec.first_slot_off;
        assert_eq!(
            rel % spec.slot_size,
            0,
            "N3.1b slab corruption: misaligned slot pointer (rel={}, slot_size={})",
            rel,
            spec.slot_size
        );
        let slot_idx = rel / spec.slot_size;
        assert!(
            slot_idx < spec.capacity,
            "N3.1b slab corruption: slot index {} >= capacity {}",
            slot_idx,
            spec.capacity
        );

        let word_idx = slot_idx / 64;
        let bit_mask = 1u64 << (slot_idx % 64);
        assert!(
            ((*header).alloc_bitmap[word_idx] & bit_mask) != 0,
            "N3.1b slab double free detected (class={}, slot={})",
            class_idx,
            slot_idx
        );
        (*header).alloc_bitmap[word_idx] &= !bit_mask;
        assert!(
            (*header).in_use > 0 && self.live_objects > 0,
            "N3.1b slab in_use counter underflow"
        );
        (*header).in_use -= 1;
        self.live_objects -= 1;

        let state = (*header).list_state;
        if (*header).in_use == 0 {
            match state {
                LIST_PARTIAL => self.partial.remove(header),
                LIST_FULL => self.full.remove(header),
                other => panic!("N3.1b slab corrupt list_state {} on last free", other),
            }
            if self.empty_count < MAX_CACHED_EMPTY_SLABS {
                self.empty.push_front(header, LIST_EMPTY);
                self.empty_count += 1;
                None
            } else {
                self.total_slabs -= 1;
                (*header).magic = 0;
                NonNull::new(header as *mut u8)
            }
        } else if state == LIST_FULL {
            self.full.remove(header);
            self.partial.push_front(header, LIST_PARTIAL);
            None
        } else {
            debug_assert_eq!(state, LIST_PARTIAL);
            None
        }
    }

    /// Pop one cached empty slab to return to the page backend.
    unsafe fn pop_empty_slab(&mut self) -> Option<NonNull<u8>> {
        let header = self.empty.pop_front()?;
        self.empty_count -= 1;
        self.total_slabs -= 1;
        (*header).magic = 0;
        NonNull::new(header as *mut u8)
    }
}

/// Initialize a freshly allocated slab page header at `page`.
unsafe fn init_slab_page(page: NonNull<u8>, class_idx: usize) -> *mut SlabPageHeader {
    let spec = SLAB_CLASSES[class_idx];
    let header = page.as_ptr() as *mut SlabPageHeader;
    ptr::write(
        header,
        SlabPageHeader {
            prev: ptr::null_mut(),
            next: ptr::null_mut(),
            alloc_bitmap: [0; 4],
            magic: SLAB_MAGIC,
            class_idx: class_idx as u16,
            in_use: 0,
            capacity: spec.capacity as u16,
            slot_size: spec.slot_size as u16,
            first_slot_off: spec.first_slot_off as u16,
            list_state: LIST_DETACHED,
        },
    );
    header
}

/// Claim one free slot from `header` using its 256-bit occupancy bitmap.
unsafe fn alloc_slot_from_page(header: *mut SlabPageHeader) -> NonNull<u8> {
    let cap = (*header).capacity as usize;
    for (word_idx, word) in (*header).alloc_bitmap.iter_mut().enumerate() {
        let free_bits = !*word;
        if free_bits != 0 {
            let bit = free_bits.trailing_zeros() as usize;
            let slot_idx = word_idx * 64 + bit;
            if slot_idx < cap {
                *word |= 1u64 << bit;
                (*header).in_use += 1;
                let off =
                    (*header).first_slot_off as usize + slot_idx * (*header).slot_size as usize;
                let ptr = (header as *mut u8).add(off);
                return NonNull::new_unchecked(ptr);
            }
        }
    }
    panic!("N3.1b slab: partial slab had no free slot in bitmap");
}

#[inline]
fn with_bin_lock<R>(bin: &Mutex<SlabBin>, f: impl FnOnce(&mut SlabBin) -> R) -> R {
    #[cfg(feature = "host_harness")]
    {
        let mut guard = bin.lock();
        f(&mut guard)
    }
    #[cfg(not(feature = "host_harness"))]
    {
        x86_64::instructions::interrupts::without_interrupts(|| {
            let mut guard = bin.lock();
            f(&mut guard)
        })
    }
}

/// Observability snapshot of the buddy-backed slab + large-page kernel heap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlabStats {
    pub active: bool,
    pub capacity_bytes: usize,
    pub live_bytes: usize,
    pub large_live_bytes: usize,
    pub backing_pages: usize,
    pub reclaimed_pages: usize,
    pub class_live_objects: [usize; SLAB_CLASS_COUNT],
    pub class_pages: [usize; SLAB_CLASS_COUNT],
}

/// Buddy-backed slab + large-page allocator parameterized over [`PageBackend`].
pub struct SlabHeap<B: PageBackend> {
    backend: B,
    active: AtomicBool,
    capacity_bytes: AtomicUsize,
    live_bytes: AtomicUsize,
    large_live_bytes: AtomicUsize,
    backing_pages: AtomicUsize,
    reclaimed_pages: AtomicUsize,
    bins: [Mutex<SlabBin>; SLAB_CLASS_COUNT],
}

impl<B: PageBackend> SlabHeap<B> {
    pub const fn new(backend: B) -> Self {
        Self {
            backend,
            active: AtomicBool::new(false),
            capacity_bytes: AtomicUsize::new(0),
            live_bytes: AtomicUsize::new(0),
            large_live_bytes: AtomicUsize::new(0),
            backing_pages: AtomicUsize::new(0),
            reclaimed_pages: AtomicUsize::new(0),
            bins: [const { Mutex::new(SlabBin::new()) }; SLAB_CLASS_COUNT],
        }
    }

    /// Activate the slab heap with `capacity_bytes` total normal-arena ceiling.
    pub fn activate(&self, capacity_bytes: usize) {
        assert!(capacity_bytes > 0, "N3.1b slab capacity must be non-zero");
        self.capacity_bytes.store(capacity_bytes, Ordering::Relaxed);
        self.active.store(true, Ordering::Release);
    }

    #[inline]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    #[inline]
    pub fn capacity_bytes(&self) -> usize {
        self.capacity_bytes.load(Ordering::Acquire)
    }

    #[inline]
    pub fn live_bytes(&self) -> usize {
        self.live_bytes.load(Ordering::Acquire)
    }

    #[inline]
    pub fn backing_pages(&self) -> usize {
        self.backing_pages.load(Ordering::Acquire)
    }

    /// Reserve `bytes` against the runtime normal-heap cap (accounting for
    /// `early_used_bytes` still live in the boot `linked_list_allocator`).
    fn try_reserve_live(&self, bytes: usize, early_used_bytes: usize) -> bool {
        let cap = self.capacity_bytes.load(Ordering::Acquire);
        let mut cur = self.live_bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = cur.checked_add(bytes) else {
                return false;
            };
            let Some(total) = next.checked_add(early_used_bytes) else {
                return false;
            };
            if total > cap {
                return false;
            }
            match self.live_bytes.compare_exchange_weak(
                cur,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => cur = observed,
            }
        }
    }

    fn release_live(&self, bytes: usize) {
        let prev = self.live_bytes.fetch_sub(bytes, Ordering::AcqRel);
        assert!(
            prev >= bytes,
            "N3.1b slab live_bytes underflow: prev={} sub={}",
            prev,
            bytes
        );
    }

    /// Allocate `layout` from either a slab class or the large-page buddy path.
    pub fn alloc(&self, layout: Layout, early_used_bytes: usize) -> Option<NonNull<u8>> {
        if layout.size() == 0 {
            return NonNull::new(layout.align() as *mut u8);
        }
        if !self.is_active() {
            return None;
        }

        if let Some(class_idx) = slab_class_index(layout) {
            let spec = SLAB_CLASSES[class_idx];
            if !self.try_reserve_live(spec.slot_size, early_used_bytes) {
                return None;
            }

            // Fast path: reuse an existing partial or cached empty slab.
            if let Some(ptr) =
                with_bin_lock(&self.bins[class_idx], |bin| unsafe { bin.try_alloc_fast() })
            {
                return Some(ptr);
            }

            // Slow path: refill a fresh slab page OUTSIDE the bin lock so
            // SlabBin and BuddyAllocator locks never nest.
            let Some(raw_page) = self.backend.alloc_pages(spec.pages_per_slab) else {
                self.release_live(spec.slot_size);
                return None;
            };
            self.backing_pages
                .fetch_add(spec.pages_per_slab, Ordering::Relaxed);
            let header = unsafe { init_slab_page(raw_page, class_idx) };
            let ptr = with_bin_lock(&self.bins[class_idx], |bin| unsafe {
                bin.insert_and_alloc(header)
            });
            Some(ptr)
        } else {
            let (raw_pages, buddy_pages) = large_alloc_pages(layout)?;
            let logical_bytes = raw_pages * SLAB_PAGE_SIZE;
            if !self.try_reserve_live(logical_bytes, early_used_bytes) {
                return None;
            }
            let Some(ptr) = self.backend.alloc_pages(buddy_pages) else {
                self.release_live(logical_bytes);
                return None;
            };
            self.backing_pages.fetch_add(buddy_pages, Ordering::Relaxed);
            self.large_live_bytes
                .fetch_add(logical_bytes, Ordering::Relaxed);
            Some(ptr)
        }
    }

    /// Free `ptr` previously returned by [`Self::alloc`] with identical `layout`.
    pub unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() == 0 {
            return;
        }
        if let Some(class_idx) = slab_class_index(layout) {
            let spec = SLAB_CLASSES[class_idx];
            let reclaim_page =
                with_bin_lock(&self.bins[class_idx], |bin| bin.free_slot(ptr, class_idx));
            self.release_live(spec.slot_size);
            if let Some(page) = reclaim_page {
                self.backend.free_pages(page, spec.pages_per_slab);
                self.backing_pages
                    .fetch_sub(spec.pages_per_slab, Ordering::Relaxed);
                self.reclaimed_pages
                    .fetch_add(spec.pages_per_slab, Ordering::Relaxed);
            }
        } else {
            let (raw_pages, buddy_pages) =
                large_alloc_pages(layout).expect("N3.1b slab: invalid large layout on dealloc");
            let logical_bytes = raw_pages * SLAB_PAGE_SIZE;
            let nn = NonNull::new(ptr).expect("N3.1b slab: null pointer on large dealloc");
            self.backend.free_pages(nn, buddy_pages);
            self.backing_pages.fetch_sub(buddy_pages, Ordering::Relaxed);
            self.large_live_bytes
                .fetch_sub(logical_bytes, Ordering::Relaxed);
            self.release_live(logical_bytes);
        }
    }

    /// Return all cached empty slabs across all classes back to the page backend.
    /// Returns the number of 4 KiB pages reclaimed.
    pub fn reclaim_empty_slabs(&self) -> usize {
        if !self.is_active() {
            return 0;
        }
        let mut reclaimed = 0usize;
        for (class_idx, bin) in self.bins.iter().enumerate() {
            let pages = SLAB_CLASSES[class_idx].pages_per_slab;
            loop {
                let maybe_page = with_bin_lock(bin, |b| unsafe { b.pop_empty_slab() });
                match maybe_page {
                    Some(page) => {
                        unsafe {
                            self.backend.free_pages(page, pages);
                        }
                        self.backing_pages.fetch_sub(pages, Ordering::Relaxed);
                        self.reclaimed_pages.fetch_add(pages, Ordering::Relaxed);
                        reclaimed += pages;
                    }
                    None => break,
                }
            }
        }
        reclaimed
    }

    /// Capture a lock-bounded snapshot of slab usage across all classes.
    pub fn stats(&self) -> SlabStats {
        let mut class_live_objects = [0usize; SLAB_CLASS_COUNT];
        let mut class_pages = [0usize; SLAB_CLASS_COUNT];
        for (i, bin) in self.bins.iter().enumerate() {
            let pages_per_slab = SLAB_CLASSES[i].pages_per_slab;
            let (objs, slabs) = with_bin_lock(bin, |b| (b.live_objects, b.total_slabs));
            class_live_objects[i] = objs;
            class_pages[i] = slabs * pages_per_slab;
        }
        SlabStats {
            active: self.is_active(),
            capacity_bytes: self.capacity_bytes(),
            live_bytes: self.live_bytes(),
            large_live_bytes: self.large_live_bytes.load(Ordering::Acquire),
            backing_pages: self.backing_pages(),
            reclaimed_pages: self.reclaimed_pages.load(Ordering::Acquire),
            class_live_objects,
            class_pages,
        }
    }
}

/// Global production buddy-backed kernel slab heap.
static KERNEL_SLAB: SlabHeap<BuddyPageBackend> = SlabHeap::new(BuddyPageBackend);

/// Activate the global buddy-backed slab heap with runtime capacity `capacity_bytes`.
pub fn activate(capacity_bytes: usize) {
    KERNEL_SLAB.activate(capacity_bytes);
}

#[inline]
pub fn is_active() -> bool {
    KERNEL_SLAB.is_active()
}

#[inline]
pub fn live_bytes() -> usize {
    KERNEL_SLAB.live_bytes()
}

#[inline]
pub fn backing_pages() -> usize {
    KERNEL_SLAB.backing_pages()
}

#[inline]
pub fn alloc(layout: Layout, early_used_bytes: usize) -> Option<NonNull<u8>> {
    KERNEL_SLAB.alloc(layout, early_used_bytes)
}

#[inline]
pub unsafe fn dealloc(ptr: *mut u8, layout: Layout) {
    KERNEL_SLAB.dealloc(ptr, layout);
}

pub fn reclaim_empty_slabs() -> usize {
    KERNEL_SLAB.reclaim_empty_slabs()
}

pub fn stats() -> SlabStats {
    KERNEL_SLAB.stats()
}

#[cfg(all(test, feature = "host_harness"))]
mod tests {
    use super::*;
    use std::vec::Vec;

    struct HostPageBackend {
        allocated_pages: AtomicUsize,
        fail_alloc: AtomicBool,
    }

    impl HostPageBackend {
        const fn new() -> Self {
            Self {
                allocated_pages: AtomicUsize::new(0),
                fail_alloc: AtomicBool::new(false),
            }
        }
    }

    impl PageBackend for HostPageBackend {
        fn alloc_pages(&self, pages: usize) -> Option<NonNull<u8>> {
            if self.fail_alloc.load(Ordering::Acquire) {
                return None;
            }
            let bytes = pages * SLAB_PAGE_SIZE;
            let layout = Layout::from_size_align(bytes, bytes).ok()?;
            let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
            let nn = NonNull::new(ptr)?;
            self.allocated_pages.fetch_add(pages, Ordering::AcqRel);
            Some(nn)
        }

        unsafe fn free_pages(&self, ptr: NonNull<u8>, pages: usize) {
            let bytes = pages * SLAB_PAGE_SIZE;
            let layout = Layout::from_size_align(bytes, bytes).expect("host page layout");
            std::alloc::dealloc(ptr.as_ptr(), layout);
            let prev = self.allocated_pages.fetch_sub(pages, Ordering::AcqRel);
            assert!(prev >= pages, "host page backend underflow");
        }
    }

    #[test]
    fn n3_1b_slab_alloc_free_all_classes_alignment_and_reclaim() {
        let heap = SlabHeap::new(HostPageBackend::new());
        heap.activate(16 * 1024 * 1024);

        for (class_idx, spec) in SLAB_CLASSES.iter().enumerate() {
            let layout = Layout::from_size_align(spec.slot_size, spec.slot_align).unwrap();
            assert_eq!(slab_class_index(layout), Some(class_idx));

            // Allocate across 4 full slabs so partial -> full -> empty and
            // hysteresis eviction (> MAX_CACHED_EMPTY_SLABS) are all exercised.
            let total_objs = spec.capacity * 4;
            let mut ptrs = Vec::with_capacity(total_objs);
            for i in 0..total_objs {
                let p = heap.alloc(layout, 0).expect("slab alloc must succeed");
                assert_eq!(
                    (p.as_ptr() as usize) % spec.slot_align,
                    0,
                    "class {} alignment violated",
                    class_idx
                );
                // Stamp unique byte pattern into first & last byte to prove no overlap.
                unsafe {
                    let tag = ((i ^ class_idx) & 0xff) as u8;
                    p.as_ptr().write(tag);
                    p.as_ptr().add(spec.slot_size - 1).write(!tag);
                }
                ptrs.push((p, ((i ^ class_idx) & 0xff) as u8));
            }
            assert_eq!(heap.live_bytes(), total_objs * spec.slot_size);
            let snap = heap.stats();
            assert_eq!(snap.class_live_objects[class_idx], total_objs);
            assert_eq!(snap.class_pages[class_idx], 4 * spec.pages_per_slab);

            // Verify every object remained intact and free them all.
            for (p, tag) in ptrs {
                unsafe {
                    assert_eq!(p.as_ptr().read(), tag);
                    assert_eq!(p.as_ptr().add(spec.slot_size - 1).read(), !tag);
                    heap.dealloc(p.as_ptr(), layout);
                }
            }
            assert_eq!(heap.live_bytes(), 0);
            // At most MAX_CACHED_EMPTY_SLABS remain cached; excess were reclaimed.
            let after_free = heap.stats();
            assert_eq!(after_free.class_live_objects[class_idx], 0);
            assert_eq!(
                after_free.class_pages[class_idx],
                MAX_CACHED_EMPTY_SLABS * spec.pages_per_slab
            );
            assert!(after_free.reclaimed_pages > 0);
        }

        // Flushing cached empty slabs returns 100% of backing pages (zero leak).
        let flushed = heap.reclaim_empty_slabs();
        assert!(flushed > 0);
        assert_eq!(heap.backing_pages(), 0);
        assert_eq!(heap.backend.allocated_pages.load(Ordering::Acquire), 0);
    }

    #[test]
    fn n3_1b_slab_large_page_alloc_free_and_cap_enforcement() {
        let heap = SlabHeap::new(HostPageBackend::new());
        // 2 MiB capacity with 512 KiB already accounted in early boot arena.
        heap.activate(2 * 1024 * 1024);
        let early_used = 512 * 1024;

        // 1 MiB contiguous allocation succeeds and aligns to 4 KiB+.
        let one_mib = Layout::from_size_align(1024 * 1024, 4096).unwrap();
        assert_eq!(slab_class_index(one_mib), None);
        assert_eq!(large_alloc_pages(one_mib), Some((256, 256)));
        let p1 = heap.alloc(one_mib, early_used).expect("1 MiB alloc");
        assert_eq!((p1.as_ptr() as usize) % 4096, 0);
        assert_eq!(heap.live_bytes(), 1024 * 1024);
        assert_eq!(heap.backing_pages(), 256);

        // Second 1 MiB allocation exceeds 2 MiB - 512 KiB = 1.5 MiB cap -> None.
        assert!(heap.alloc(one_mib, early_used).is_none());
        assert_eq!(heap.live_bytes(), 1024 * 1024);
        assert_eq!(heap.backing_pages(), 256);

        // 10 KiB allocation needs 3 logical pages (12 KiB) backed by 4 buddy pages (16 KiB).
        let ten_k = Layout::from_size_align(10 * 1024, 16).unwrap();
        assert_eq!(slab_class_index(ten_k), None);
        assert_eq!(large_alloc_pages(ten_k), Some((3, 4)));
        let p2 = heap.alloc(ten_k, early_used).expect("10 KiB alloc");
        assert_eq!(heap.live_bytes(), 1024 * 1024 + 12 * 1024);
        assert_eq!(heap.backing_pages(), 256 + 4);

        // Backend OOM rolls back live_bytes cleanly.
        heap.backend.fail_alloc.store(true, Ordering::Release);
        let four_k = Layout::from_size_align(4096, 4096).unwrap();
        assert!(heap.alloc(four_k, early_used).is_none());
        assert_eq!(heap.live_bytes(), 1024 * 1024 + 12 * 1024);
        heap.backend.fail_alloc.store(false, Ordering::Release);

        unsafe {
            heap.dealloc(p2.as_ptr(), ten_k);
            heap.dealloc(p1.as_ptr(), one_mib);
        }
        assert_eq!(heap.live_bytes(), 0);
        assert_eq!(heap.backing_pages(), 0);
        assert_eq!(heap.backend.allocated_pages.load(Ordering::Acquire), 0);
    }

    #[test]
    #[should_panic(expected = "double free")]
    fn n3_1b_slab_rejects_double_free() {
        let heap = SlabHeap::new(HostPageBackend::new());
        heap.activate(4 * 1024 * 1024);
        let layout = Layout::from_size_align(64, 64).unwrap();
        let p = heap.alloc(layout, 0).expect("alloc 64B");
        unsafe {
            heap.dealloc(p.as_ptr(), layout);
            heap.dealloc(p.as_ptr(), layout);
        }
    }
}
