//! Buddy内存分配器实现
//!
//! Buddy分配器是一种高效的内存管理算法，通过将内存分割成2的幂次大小的块来管理。
//! 当需要分配内存时，找到最小的能满足需求的块；释放时尝试与相邻的块合并。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::{structures::paging::PhysFrame, PhysAddr};

use crate::oom_killer;

/// Number of supported buddy orders. Valid allocation orders are 0..=10,
/// making the largest block 2^10 * 4 KiB = 4 MiB.
const ORDER_COUNT: usize = 11;
/// 页面大小（4KB）
const PAGE_SIZE: usize = 4096;

const PAGE_FREE: u8 = 0;
const PAGE_ALLOC_START_BASE: u8 = 1;
const PAGE_ALLOC_ORDER0: u8 = PAGE_ALLOC_START_BASE;
const PAGE_ALLOC_TAIL_BASE: u8 = 0x40;
/// Issue #109 §1.3: order-0 frame exclusively owned by one CPU's PCP magazine.
///
/// Disjoint from `PAGE_FREE` (0), `PAGE_ALLOC_START` (1..=11), `PAGE_ALLOC_TAIL`
/// (0x40..=0x4A), and `PAGE_RESERVED` (0xFF), allowing lock-free atomic CAS
/// transitions (`0x01 <-> 0x80`) on the PCP fast path without weakening R74-4
/// order-mismatch, double-free, or reserved-page checks.
const PAGE_PCP_CACHED: u8 = 0x80;
/// Issue #109 §1.3: free page returned from PCP whose 4 KiB contents were
/// already scrubbed to all zeros before leaving PCP. Cleared to `PAGE_FREE`
/// (dirty) whenever allocated and later freed through any non-PCP path, so
/// PCP refill skips redundant 4 KiB memsets without weakening Invariant S2.
const PAGE_FREE_ZEROED: u8 = 0x81;
const PAGE_RESERVED: u8 = u8::MAX;

#[inline]
fn is_free_page_state(state: u8) -> bool {
    state == PAGE_FREE || state == PAGE_FREE_ZEROED
}

/// Per-CPU page cache tuning (Issue #109 §1.3).
///
/// Hysteresis band (`REFILL=16`, `DRAIN=32`, `HIGH=64`) prevents refill/drain
/// oscillation while bounding idle per-CPU memory to 256 KiB (reclaimed
/// synchronously across all CPUs before any allocation fails or enters OOM).
const PCP_HIGH_WATERMARK: usize = 64;
const PCP_REFILL_BATCH: usize = 16;
const PCP_DRAIN_BATCH: usize = 32;
const _: () = assert!(PCP_REFILL_BATCH <= 32);

#[inline]
fn allocation_start_state(order: usize) -> Option<u8> {
    (order < ORDER_COUNT).then_some(PAGE_ALLOC_START_BASE + order as u8)
}

#[inline]
fn allocation_tail_state(order: usize) -> Option<u8> {
    (order < ORDER_COUNT).then_some(PAGE_ALLOC_TAIL_BASE + order as u8)
}

#[inline]
fn decode_allocation_start(state: u8) -> Option<usize> {
    let order = state.checked_sub(PAGE_ALLOC_START_BASE)? as usize;
    (order < ORDER_COUNT).then_some(order)
}

#[inline]
fn decode_allocation_tail(state: u8) -> Option<usize> {
    let order = state.checked_sub(PAGE_ALLOC_TAIL_BASE)? as usize;
    (order < ORDER_COUNT).then_some(order)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuddyInitError {
    EmptyRegion,
    RegionMisaligned,
    AddressOverflow,
    MetadataSizeOverflow,
    MetadataAllocationFailed,
    MetadataCorrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocError {
    InvalidOrder,
    Exhausted,
    /// Allocation or transient-cache reclaim saw lock contention while
    /// reclaimable frames remained; fault callers should retry (`Busy`/`EAGAIN`).
    Busy,
    AllocatorUnavailable,
    AddressOverflow,
    MetadataCorrupt,
    AllocatorPoisoned,
}

/// Buddy分配器的核心结构
/// Fail-closed reason returned by checked physical-block deallocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreeError {
    InvalidCount,
    OrderTooLarge,
    AllocatorUnavailable,
    AddressBelowBase,
    AddressMisaligned,
    RangeOutOfBounds,
    NotAllocationStart,
    OrderMismatch,
    PageNotAllocated,
    ReservedPage,
    /// Issue #109 §1.3: COW/shared-anon `PAGE_REF_COUNT` slot is still non-zero;
    /// refusing reclamation closes any UAF window before the frame can enter PCP.
    PageStillReferenced,
    /// Non-blocking free could not acquire the buddy allocator lock without spinning.
    Busy,
    MetadataCorrupt,
    AllocatorPoisoned,
}

impl FreeError {
    /// Whether a rejected free proves allocator metadata corruption.  Caller
    /// misuse (wrong order, duplicate free, or an out-of-range frame) must be
    /// rejected and logged without poisoning unrelated live allocations; only
    /// an internally inconsistent ledger warrants quarantine.
    #[inline]
    fn is_metadata_corruption(self) -> bool {
        matches!(self, Self::MetadataCorrupt | Self::AllocatorPoisoned)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FreeBit {
    word_index: usize,
    mask: u64,
    order: usize,
    block_idx: usize,
}

/// Fixed-length atomic per-page state storage (Issue #109 §1.3).
///
/// Unlike `MetadataStore<T>`, `PageStateStore` intentionally does NOT implement
/// `DerefMut`: both `BuddyAllocator` and the lock-free PCP fast path access
/// elements strictly through shared `&[AtomicU8]` references, avoiding any
/// `&mut` aliasing UB under Stacked/Tree Borrows while keeping exact 1 B/page
/// storage size (`size_of::<AtomicU8>() == 1`).
enum PageStateStore {
    Heap(Vec<AtomicU8>),
    Boot(&'static [AtomicU8]),
}

impl PageStateStore {
    fn try_heap(len: usize, fill: u8) -> Result<Self, BuddyInitError> {
        let mut storage = Vec::new();
        storage
            .try_reserve_exact(len)
            .map_err(|_| BuddyInitError::MetadataAllocationFailed)?;
        for _ in 0..len {
            storage.push(AtomicU8::new(fill));
        }
        Ok(Self::Heap(storage))
    }

    #[inline]
    fn load(&self, index: usize) -> u8 {
        self[index].load(Ordering::Acquire)
    }

    #[inline]
    fn store(&self, index: usize, value: u8) {
        self[index].store(value, Ordering::Release);
    }

    #[cfg(test)]
    fn capacity(&self) -> usize {
        match self {
            Self::Heap(storage) => storage.capacity(),
            Self::Boot(storage) => storage.len(),
        }
    }

    #[cfg(test)]
    fn snapshot_bytes(&self) -> Vec<u8> {
        self.iter()
            .map(|slot| slot.load(Ordering::Acquire))
            .collect()
    }
}

impl core::ops::Deref for PageStateStore {
    type Target = [AtomicU8];

    fn deref(&self) -> &[AtomicU8] {
        match self {
            Self::Heap(storage) => storage,
            Self::Boot(storage) => storage,
        }
    }
}

#[cfg(test)]
impl PartialEq for PageStateStore {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len()
            && self
                .iter()
                .zip(other.iter())
                .all(|(a, b)| a.load(Ordering::Acquire) == b.load(Ordering::Acquire))
    }
}

#[cfg(test)]
impl core::fmt::Debug for PageStateStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list()
            .entries(self.iter().map(|slot| slot.load(Ordering::Acquire)))
            .finish()
    }
}

/// GAP-6 F8: fixed-length buddy metadata storage. A boot allocator uses
/// frames reserved out of its own managed window (`Boot`), so metadata that
/// scales with physical memory never occupies the kernel heap. Hosted tests and
/// the boot self-test own a fallibly allocated vector (`Heap`). Neither form
/// changes length after construction.
enum MetadataStore<T: 'static> {
    Heap(Vec<T>),
    Boot(&'static mut [T]),
}

impl<T> MetadataStore<T> {
    fn try_heap(len: usize, fill: T) -> Result<Self, BuddyInitError>
    where
        T: Clone,
    {
        let mut storage = Vec::new();
        storage
            .try_reserve_exact(len)
            .map_err(|_| BuddyInitError::MetadataAllocationFailed)?;
        storage.resize(len, fill);
        Ok(Self::Heap(storage))
    }

    #[cfg(test)]
    fn capacity(&self) -> usize {
        match self {
            Self::Heap(storage) => storage.capacity(),
            Self::Boot(storage) => storage.len(),
        }
    }
}

impl<T> core::ops::Deref for MetadataStore<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        match self {
            Self::Heap(storage) => storage,
            Self::Boot(storage) => storage,
        }
    }
}

impl<T> core::ops::DerefMut for MetadataStore<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        match self {
            Self::Heap(storage) => storage,
            Self::Boot(storage) => storage,
        }
    }
}

/// Test snapshots compare metadata by content regardless of where it lives.
#[cfg(test)]
impl<T: Clone> Clone for MetadataStore<T> {
    fn clone(&self) -> Self {
        Self::Heap(self.to_vec())
    }
}

#[cfg(test)]
impl<T: PartialEq> PartialEq for MetadataStore<T> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

#[cfg(test)]
impl<T: core::fmt::Debug> core::fmt::Debug for MetadataStore<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        (**self).fmt(f)
    }
}

/// Per-order bitmap geometry for `total_pages`: word offsets, valid block
/// counts and the total word count.
struct FreeMapLayout {
    word_base: [usize; ORDER_COUNT + 1],
    valid_blocks: [usize; ORDER_COUNT],
    total_words: usize,
}

impl FreeMapLayout {
    fn new(total_pages: usize) -> Result<Self, BuddyInitError> {
        let mut word_base = [0usize; ORDER_COUNT + 1];
        let mut valid_blocks = [0usize; ORDER_COUNT];
        let mut total_words = 0usize;

        for order in 0..ORDER_COUNT {
            let block_pages = 1usize << order;
            let blocks = total_pages / block_pages;
            let words = blocks / u64::BITS as usize
                + usize::from(!blocks.is_multiple_of(u64::BITS as usize));
            valid_blocks[order] = blocks;
            word_base[order] = total_words;
            total_words = total_words
                .checked_add(words)
                .ok_or(BuddyInitError::MetadataSizeOverflow)?;
        }
        word_base[ORDER_COUNT] = total_words;
        Ok(Self {
            word_base,
            valid_blocks,
            total_words,
        })
    }
}

/// Fixed-size, allocation-free-after-init representation of every free buddy
/// block.  Order `o`, block `b` represents the exact page range
/// `[b << o, (b + 1) << o)`.  All order bitmaps live in one word array whose
/// length never changes after construction.
struct FixedFreeMap {
    words: MetadataStore<u64>,
    word_base: [usize; ORDER_COUNT + 1],
    valid_blocks: [usize; ORDER_COUNT],
    block_count: [usize; ORDER_COUNT],
    search_cursor: [usize; ORDER_COUNT],
}

impl FixedFreeMap {
    /// Build over zeroed storage of exactly `layout.total_words` words.
    fn from_storage(
        layout: FreeMapLayout,
        words: MetadataStore<u64>,
    ) -> Result<Self, BuddyInitError> {
        if words.len() != layout.total_words || words.iter().any(|word| *word != 0) {
            return Err(BuddyInitError::MetadataCorrupt);
        }
        Ok(Self {
            words,
            word_base: layout.word_base,
            valid_blocks: layout.valid_blocks,
            block_count: [0; ORDER_COUNT],
            search_cursor: [0; ORDER_COUNT],
        })
    }

    #[inline]
    fn location(&self, order: usize, block_idx: usize) -> Option<FreeBit> {
        if order >= ORDER_COUNT {
            return None;
        }
        let block_pages = 1usize << order;
        if block_idx & (block_pages - 1) != 0 {
            return None;
        }
        let block_no = block_idx >> order;
        if block_no >= self.valid_blocks[order] {
            return None;
        }
        let word_offset = block_no / u64::BITS as usize;
        let word_index = self.word_base[order].checked_add(word_offset)?;
        if word_index >= self.word_base[order + 1] || word_index >= self.words.len() {
            return None;
        }
        Some(FreeBit {
            word_index,
            mask: 1u64 << (block_no % u64::BITS as usize),
            order,
            block_idx,
        })
    }

    #[inline]
    fn is_set(&self, bit: FreeBit) -> bool {
        self.words
            .get(bit.word_index)
            .is_some_and(|word| word & bit.mask != 0)
    }

    #[inline]
    fn first_set_in_word(
        &self,
        order: usize,
        word_offset: usize,
        search_mask: u64,
    ) -> Option<FreeBit> {
        let word_index = self.word_base.get(order)?.checked_add(word_offset)?;
        if word_index >= *self.word_base.get(order + 1)? {
            return None;
        }

        let block_word = *self.words.get(word_index)? & search_mask;
        if block_word == 0 {
            return None;
        }

        let bit_in_word = block_word.trailing_zeros() as usize;
        let block_no = word_offset
            .checked_mul(u64::BITS as usize)?
            .checked_add(bit_in_word)?;
        if block_no >= *self.valid_blocks.get(order)? {
            return None;
        }
        let block_idx = block_no.checked_shl(order as u32)?;
        Some(FreeBit {
            word_index,
            mask: 1u64 << bit_in_word,
            order,
            block_idx,
        })
    }

    /// Find a free block by scanning bitmap words from the per-order cursor.
    ///
    /// This deliberately never walks individual zero bits: the allocator lock
    /// is global, and a sparse order-0 map can contain hundreds of thousands of
    /// blocks.  Each bitmap word is examined at most once (apart from splitting
    /// the cursor word into suffix/prefix masks), and `trailing_zeros` locates
    /// the first candidate in constant time.  Bits beyond `valid_blocks` are
    /// masked out so malformed tail storage can never yield an out-of-range
    /// block.
    fn find_first(&self, order: usize) -> Option<FreeBit> {
        let blocks = *self.valid_blocks.get(order)?;
        if blocks == 0 || self.block_count.get(order).copied()? == 0 {
            return None;
        }

        let word_start = *self.word_base.get(order)?;
        let word_end = *self.word_base.get(order + 1)?;
        let word_count = word_end.checked_sub(word_start)?;
        if word_count == 0 {
            return None;
        }

        let start_block = self.search_cursor[order].min(blocks - 1);
        let start_word = start_block / u64::BITS as usize;
        let start_bit = start_block % u64::BITS as usize;

        let valid_mask = |word_offset: usize| {
            let first_block = word_offset.saturating_mul(u64::BITS as usize);
            let remaining = blocks.saturating_sub(first_block);
            match remaining {
                0 => 0,
                n if n >= u64::BITS as usize => u64::MAX,
                n => (1u64 << n) - 1,
            }
        };

        // Cursor word, from the cursor bit to the end.
        let suffix_mask = u64::MAX << start_bit;
        if let Some(bit) =
            self.first_set_in_word(order, start_word, suffix_mask & valid_mask(start_word))
        {
            return Some(bit);
        }

        // Remaining whole words through the end of this order's bitmap.
        for word_offset in start_word + 1..word_count {
            if let Some(bit) = self.first_set_in_word(order, word_offset, valid_mask(word_offset)) {
                return Some(bit);
            }
        }

        // Wrap to whole words before the cursor word.
        for word_offset in 0..start_word {
            if let Some(bit) = self.first_set_in_word(order, word_offset, valid_mask(word_offset)) {
                return Some(bit);
            }
        }

        // Finally inspect the prefix of the cursor word.  Avoid a shift by 64.
        if start_bit != 0 {
            let prefix_mask = (1u64 << start_bit) - 1;
            if let Some(bit) =
                self.first_set_in_word(order, start_word, prefix_mask & valid_mask(start_word))
            {
                return Some(bit);
            }
        }
        None
    }

    #[inline]
    fn count_for_order(&self, order: usize) -> Option<usize> {
        self.block_count.get(order).copied()
    }

    /// Commit-only primitive. Every location and bit transition is preflighted
    /// before callers enter their mutation phase, so this performs no allocation
    /// and cannot change vector length/capacity.
    fn commit_set(&mut self, bit: FreeBit, value: bool) {
        let word = &mut self.words[bit.word_index];
        if value {
            *word |= bit.mask;
            self.block_count[bit.order] += 1;
            let block_no = bit.block_idx >> bit.order;
            if self.block_count[bit.order] == 1 || block_no < self.search_cursor[bit.order] {
                self.search_cursor[bit.order] = block_no;
            }
        } else {
            *word &= !bit.mask;
            self.block_count[bit.order] -= 1;
            let blocks = self.valid_blocks[bit.order];
            if blocks != 0 {
                self.search_cursor[bit.order] = ((bit.block_idx >> bit.order) + 1) % blocks;
            }
        }
    }

    fn count_actual(&self, order: usize) -> Option<usize> {
        if order >= ORDER_COUNT {
            return None;
        }
        Some(
            self.words[self.word_base[order]..self.word_base[order + 1]]
                .iter()
                .map(|word| word.count_ones() as usize)
                .sum(),
        )
    }
}

pub struct BuddyAllocator {
    /// Fixed post-init free-block index. Runtime alloc/free only toggles bits.
    free_map: FixedFreeMap,

    /// Exact per-page ownership state: free, reserved, PCP-cached, allocation
    /// start(order), or allocation tail(order). Shared atomic storage allows
    /// lock-free order-0 PCP CAS transitions alongside buddy metadata checks.
    page_state: PageStateStore,

    /// 内存起始物理地址
    base_addr: PhysAddr,

    /// 总页数
    total_pages: usize,

    /// 空闲页数
    free_pages: usize,

    /// R167-B: pages permanently reserved out of the allocator.
    ///
    /// Reserved pages are marked allocated in `bitmap` with `alloc_order == 0`,
    /// so they are never placed in a free list, never handed out by
    /// `alloc_pages`, and never accepted by `free_pages`. They model physical
    /// frames owned by another subsystem (the kernel heap, the kernel image,
    /// the framebuffer, firmware/boot-services ranges) that must never enter
    /// the buddy free pool. `free_pages == total_pages - reserved_pages` at init.
    reserved_pages: usize,

    /// Sticky fail-closed state set only for internal metadata contradictions.
    /// Invalid caller frees do not poison an otherwise sound allocator.
    poisoned: bool,
}

impl BuddyAllocator {
    /// 创建新的Buddy分配器
    ///
    /// # 参数
    /// * `base_addr` - 管理的内存区域起始地址
    /// * `size` - 管理的内存区域大小（字节）
    pub fn new(base_addr: PhysAddr, size: usize) -> Result<Self, BuddyInitError> {
        // An allocator with no reservations manages the whole region.
        Self::new_with_reservations(base_addr, size, &[])
    }

    /// R167-B: Create a Buddy allocator with permanent physical reservations.
    ///
    /// Each `reserved` entry is `(absolute_phys_start, len_bytes)`. Reserved
    /// ranges are clamped to the managed window `[base_addr, base_addr + size)`
    /// and rounded **outward** to whole pages, so any 4 KiB frame even partially
    /// overlapping a reservation is withheld from the allocator. This replaces
    /// the R166 "carve the larger half" heuristic: the buddy keeps the entire
    /// region minus precise per-page holes, reclaiming the memory the carve
    /// discarded while still guaranteeing the two physical-memory owners (heap
    /// and buddy) never share a frame.
    pub fn new_with_reservations(
        base_addr: PhysAddr,
        size: usize,
        reserved: &[(u64, u64)],
    ) -> Result<Self, BuddyInitError> {
        let total_pages = Self::validated_page_count(base_addr, size)?;
        let layout = FreeMapLayout::new(total_pages)?;
        let page_state = PageStateStore::try_heap(total_pages, PAGE_FREE)?;
        let words = MetadataStore::try_heap(layout.total_words, 0u64)?;
        Self::from_metadata(base_addr, total_pages, reserved, layout, page_state, words)
    }

    /// GAP-6 F8: bytes of boot storage `new_with_reservations_in` needs for a
    /// managed window of `size` bytes: one state byte per page, padded to a
    /// word boundary, followed by the order bitmaps.
    pub fn metadata_bytes(size: usize) -> Result<usize, BuddyInitError> {
        let total_pages = size / PAGE_SIZE;
        let layout = FreeMapLayout::new(total_pages)?;
        Self::state_bytes(total_pages)?
            .checked_add(Self::word_bytes(&layout)?)
            .ok_or(BuddyInitError::MetadataSizeOverflow)
    }

    /// GAP-6 F8: build the allocator over caller-provided `'static` storage of
    /// at least `metadata_bytes(size)` bytes, starting 8-byte aligned. Boot
    /// passes frames it has reserved out of the managed window, so the
    /// per-page state and order bitmaps never come from the kernel heap. The
    /// storage contents are overwritten.
    pub fn new_with_reservations_in(
        base_addr: PhysAddr,
        size: usize,
        reserved: &[(u64, u64)],
        storage: &'static mut [u8],
    ) -> Result<Self, BuddyInitError> {
        let total_pages = Self::validated_page_count(base_addr, size)?;
        let layout = FreeMapLayout::new(total_pages)?;
        let state_bytes = Self::state_bytes(total_pages)?;
        let word_bytes = Self::word_bytes(&layout)?;
        let required = state_bytes
            .checked_add(word_bytes)
            .ok_or(BuddyInitError::MetadataSizeOverflow)?;
        if storage.len() < required {
            return Err(BuddyInitError::MetadataAllocationFailed);
        }

        let (state_region, word_region) = storage.split_at_mut(state_bytes);
        let page_state_bytes = state_region.split_at_mut(total_pages).0;
        page_state_bytes.fill(PAGE_FREE);
        let page_state_ptr = page_state_bytes.as_ptr().cast::<AtomicU8>();
        // SAFETY: `page_state_bytes` is exclusively owned `'static` storage of
        // `total_pages` initialized `PAGE_FREE` bytes; `AtomicU8` has identical
        // size (1) and alignment (1) to `u8`. Converting immediately to a shared
        // `&'static [AtomicU8]` drops the `&mut [u8]` borrow so all subsequent
        // accesses are exclusively shared atomic operations.
        let page_state: &'static [AtomicU8] =
            unsafe { core::slice::from_raw_parts(page_state_ptr, total_pages) };
        let word_region = word_region.split_at_mut(word_bytes).0;
        word_region.fill(0);
        let word_ptr = word_region.as_mut_ptr();
        if (word_ptr as usize) % core::mem::align_of::<u64>() != 0 {
            return Err(BuddyInitError::RegionMisaligned);
        }
        // SAFETY: `word_region` is an exclusively owned `'static` byte range of
        // exactly `total_words * 8` bytes, 8-byte aligned (checked above) and
        // zero-filled; every bit pattern is a valid `u64`. The byte slice is
        // not used again, so this is the only reference to the range.
        let words: &'static mut [u64] =
            unsafe { core::slice::from_raw_parts_mut(word_ptr.cast::<u64>(), layout.total_words) };

        Self::from_metadata(
            base_addr,
            total_pages,
            reserved,
            layout,
            PageStateStore::Boot(page_state),
            MetadataStore::Boot(words),
        )
    }

    fn validated_page_count(base_addr: PhysAddr, size: usize) -> Result<usize, BuddyInitError> {
        if size == 0 {
            return Err(BuddyInitError::EmptyRegion);
        }
        if !size.is_multiple_of(PAGE_SIZE) || !base_addr.as_u64().is_multiple_of(PAGE_SIZE as u64) {
            return Err(BuddyInitError::RegionMisaligned);
        }
        let size_u64 = u64::try_from(size).map_err(|_| BuddyInitError::AddressOverflow)?;
        let region_end = base_addr
            .as_u64()
            .checked_add(size_u64)
            .ok_or(BuddyInitError::AddressOverflow)?;
        if region_end == 0 || PhysAddr::try_new(region_end - 1).is_err() {
            return Err(BuddyInitError::AddressOverflow);
        }
        Ok(size / PAGE_SIZE)
    }

    /// Page-state bytes rounded up so the bitmap words that follow stay
    /// 8-byte aligned.
    fn state_bytes(total_pages: usize) -> Result<usize, BuddyInitError> {
        total_pages
            .checked_next_multiple_of(core::mem::size_of::<u64>())
            .ok_or(BuddyInitError::MetadataSizeOverflow)
    }

    fn word_bytes(layout: &FreeMapLayout) -> Result<usize, BuddyInitError> {
        layout
            .total_words
            .checked_mul(core::mem::size_of::<u64>())
            .ok_or(BuddyInitError::MetadataSizeOverflow)
    }

    fn from_metadata(
        base_addr: PhysAddr,
        total_pages: usize,
        reserved: &[(u64, u64)],
        layout: FreeMapLayout,
        page_state: PageStateStore,
        words: MetadataStore<u64>,
    ) -> Result<Self, BuddyInitError> {
        if page_state.len() != total_pages
            || page_state
                .iter()
                .any(|state| state.load(Ordering::Acquire) != PAGE_FREE)
        {
            return Err(BuddyInitError::MetadataCorrupt);
        }

        let mut allocator = BuddyAllocator {
            free_map: FixedFreeMap::from_storage(layout, words)?,
            page_state,
            base_addr,
            total_pages,
            // Set to the true free count after reservations are marked below.
            free_pages: 0,
            reserved_pages: 0,
            poisoned: false,
        };

        // Mark reserved pages BEFORE building the free lists so the free-list
        // construction skips them entirely.
        allocator.mark_reserved_ranges(reserved);
        allocator.free_pages = total_pages.saturating_sub(allocator.reserved_pages);
        debug_assert!(
            allocator.reserved_pages <= total_pages,
            "reserved pages exceed total pages"
        );

        // 初始化：仅用未保留的连续区段构建空闲链表
        allocator.init_memory_region()?;
        allocator.validate_metadata().map_err(|_| {
            allocator.poisoned = true;
            BuddyInitError::MetadataCorrupt
        })?;
        Ok(allocator)
    }

    /// R167-B: Permanently withhold reserved physical ranges from the allocator.
    ///
    /// Marks each reserved page allocated in `bitmap` while leaving its
    /// `alloc_order` at 0. The combination means a reserved page is (a) never
    /// added to a free list by `init_memory_region`, (b) never the buddy of a
    /// mergeable block (`is_buddy_free` rejects any page with `bitmap == true`),
    /// and (c) rejected by `free_pages` (which requires `alloc_order != 0`). The
    /// page is therefore unreachable by allocation for the allocator's lifetime.
    fn mark_reserved_ranges(&mut self, reserved: &[(u64, u64)]) {
        let region_start = self.base_addr.as_u64();
        // Multiply in u64 space so the byte count cannot wrap in usize for a
        // pathological total_pages (R167 review hardening). total_pages is bounded
        // by the selected region size in practice, but this keeps the public
        // constructor robust for any caller.
        let region_bytes = self.total_pages as u64 * PAGE_SIZE as u64;
        let region_end = region_start.saturating_add(region_bytes);
        let page = PAGE_SIZE as u64;

        for &(phys_start, len_bytes) in reserved {
            if len_bytes == 0 {
                continue;
            }
            let phys_end = phys_start.saturating_add(len_bytes);

            // Skip ranges that do not intersect the managed window.
            if phys_end <= region_start || phys_start >= region_end {
                continue;
            }

            // Intersect with the window and convert to in-window byte OFFSETS.
            // Both offsets lie in [0, region_bytes], so the page math below is
            // overflow-free and avoids the absolute-address `align_up` saturation
            // edge near u64::MAX (R167 Codex review). The intersection is
            // non-empty, so rel_start < rel_end.
            let rel_start = phys_start.max(region_start) - region_start;
            let rel_end = phys_end.min(region_end) - region_start;

            // Round OUTWARD to whole pages: floor(start), ceil(end), so any frame
            // even partially covered by the reservation is fully withheld. The
            // ceil is written as div + remainder-bump (not `rel_end + page - 1`)
            // so it cannot wrap even if rel_end were near u64::MAX (R167 review).
            let start_idx = (rel_start / page) as usize;
            let end_idx = ((rel_end / page) as usize + usize::from(!rel_end.is_multiple_of(page)))
                .min(self.total_pages);

            for page_idx in start_idx..end_idx {
                // De-duplicate overlapping reservations. Bounds are guaranteed by
                // construction: start_idx < total_pages and end_idx <= total_pages.
                if self.page_state.load(page_idx) == PAGE_FREE {
                    self.page_state.store(page_idx, PAGE_RESERVED);
                    self.reserved_pages += 1;
                }
            }
        }
    }

    /// 初始化内存区域
    ///
    /// R167-B: builds the free lists from the maximal runs of **non-reserved**
    /// pages. Each run is decomposed into buddy-aligned power-of-two blocks, so
    /// no free block ever spans a reserved page. With no reservations this
    /// reproduces the original greedy decomposition exactly.
    fn init_memory_region(&mut self) -> Result<(), BuddyInitError> {
        let mut run_start: Option<usize> = None;

        for page_idx in 0..self.total_pages {
            if self.page_state.load(page_idx) == PAGE_RESERVED {
                // Reserved/allocated page: close any open free run before it.
                if let Some(start) = run_start.take() {
                    self.add_free_run(start, page_idx)?;
                }
            } else if run_start.is_none() {
                run_start = Some(page_idx);
            }
        }

        if let Some(start) = run_start {
            self.add_free_run(start, self.total_pages)?;
        }
        Ok(())
    }

    /// R167-B: decompose a non-reserved page run `[start_idx, end_idx)` into
    /// buddy-aligned power-of-two blocks and push them onto the free lists.
    fn add_free_run(&mut self, mut start_idx: usize, end_idx: usize) -> Result<(), BuddyInitError> {
        while start_idx < end_idx {
            let remaining = end_idx - start_idx;
            let order = largest_aligned_order(start_idx, remaining);
            let bit = self
                .free_map
                .location(order, start_idx)
                .ok_or(BuddyInitError::MetadataCorrupt)?;
            if self.free_map.is_set(bit) || self.free_map.block_count[order] == usize::MAX {
                return Err(BuddyInitError::MetadataCorrupt);
            }
            self.free_map.commit_set(bit, true);
            start_idx += 1 << order;
        }
        Ok(())
    }

    /// 分配指定阶数的内存块
    ///
    /// # 参数
    /// * `order` - 需要分配的块的阶数（2^order * PAGE_SIZE）
    ///
    /// # 返回
    /// 成功返回分配的物理帧，失败返回None
    pub fn alloc_pages(&mut self, order: usize) -> Option<PhysFrame> {
        self.try_alloc_pages(order).ok()
    }

    /// Transactional physical allocation. Every bitmap/state/counter change is
    /// preflighted before the first mutation; the commit phase only toggles
    /// fixed-size metadata and therefore cannot allocate or partially fail.
    pub fn try_alloc_pages(&mut self, order: usize) -> Result<PhysFrame, AllocError> {
        self.try_alloc_pages_internal(order).map(|(frame, _)| frame)
    }

    fn try_alloc_pages_internal(&mut self, order: usize) -> Result<(PhysFrame, bool), AllocError> {
        if self.poisoned {
            return Err(AllocError::AllocatorPoisoned);
        }
        if order >= ORDER_COUNT {
            return Err(AllocError::InvalidOrder);
        }

        let mut source = None;
        for current_order in order..ORDER_COUNT {
            let recorded = self.free_map.count_for_order(current_order).unwrap_or(0);
            if recorded == 0 {
                continue;
            }
            let found = self.free_map.find_first(current_order);
            match found {
                None => {
                    self.poisoned = true;
                    return Err(AllocError::MetadataCorrupt);
                }
                Some(bit) => {
                    source = Some(bit);
                    break;
                }
            }
        }
        let source = source.ok_or(AllocError::Exhausted)?;
        let source_pages = 1usize << source.order;
        if !self.range_is_free(source.block_idx, source_pages) {
            self.poisoned = true;
            return Err(AllocError::MetadataCorrupt);
        }

        let mut allowed = [None; ORDER_COUNT];
        allowed[0] = Some(source);
        if self.has_unexpected_free_overlap(source.block_idx, source_pages, &allowed) {
            self.poisoned = true;
            return Err(AllocError::MetadataCorrupt);
        }

        let target_pages = 1usize << order;
        let new_free_pages = self.free_pages.checked_sub(target_pages).ok_or_else(|| {
            self.poisoned = true;
            AllocError::MetadataCorrupt
        })?;
        let byte_offset = source
            .block_idx
            .checked_mul(PAGE_SIZE)
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or(AllocError::AddressOverflow)?;
        let phys_u64 = self
            .base_addr
            .as_u64()
            .checked_add(byte_offset)
            .ok_or(AllocError::AddressOverflow)?;
        let phys = PhysAddr::try_new(phys_u64).map_err(|_| AllocError::AddressOverflow)?;
        let frame = PhysFrame::from_start_address(phys).map_err(|_| AllocError::AddressOverflow)?;

        let mut split_bits = [None; ORDER_COUNT];
        let mut split_count = 0usize;
        let mut current_order = source.order;
        while current_order > order {
            current_order -= 1;
            let buddy_idx = source
                .block_idx
                .checked_add(1usize << current_order)
                .ok_or(AllocError::MetadataCorrupt)?;
            let bit = self
                .free_map
                .location(current_order, buddy_idx)
                .ok_or(AllocError::MetadataCorrupt)?;
            if self.free_map.is_set(bit) || self.free_map.block_count[current_order] == usize::MAX {
                self.poisoned = true;
                return Err(AllocError::MetadataCorrupt);
            }
            split_bits[split_count] = Some(bit);
            split_count += 1;
        }
        if self.free_map.block_count[source.order] == 0 {
            self.poisoned = true;
            return Err(AllocError::MetadataCorrupt);
        }

        // Commit: all vector indices, bit transitions, state ranges, and
        // counter arithmetic above are now proven.
        self.free_map.commit_set(source, false);
        for bit in split_bits.iter().take(split_count).flatten().copied() {
            self.free_map.commit_set(bit, true);
        }
        let start_state = allocation_start_state(order).ok_or(AllocError::InvalidOrder)?;
        let tail_state = allocation_tail_state(order).ok_or(AllocError::InvalidOrder)?;
        let was_zeroed = order == 0 && self.page_state.load(source.block_idx) == PAGE_FREE_ZEROED;
        self.page_state.store(source.block_idx, start_state);
        for index in source.block_idx + 1..source.block_idx + target_pages {
            self.page_state.store(index, tail_state);
        }
        self.free_pages = new_free_pages;
        Ok((frame, was_zeroed))
    }

    /// Issue #109 §1.3: allocate a batch of up to `out.len()` order-0 frames
    /// under a single buddy-lock hold for PCP refill.
    ///
    /// `out[0]` is marked `PAGE_ALLOC_ORDER0` (returned immediately to the
    /// caller), while `out[1..count]` are marked `PAGE_PCP_CACHED` (exclusive to
    /// the refilling CPU's PCP magazine). Returns `(count, zeroed_mask)` where
    /// bit `i` of `zeroed_mask` is set iff `out[i]` was in `PAGE_FREE_ZEROED`
    /// (already scrubbed when drained from PCP). Returns `Err(AllocError::Exhausted)`
    /// only if zero frames could be allocated.
    fn try_alloc_pcp_batch(&mut self, out: &mut [PhysFrame]) -> Result<(usize, u32), AllocError> {
        if out.is_empty() || out.len() > 32 {
            return Err(AllocError::InvalidOrder);
        }
        let mut count = 0usize;
        let mut zeroed_mask = 0u32;
        while count < out.len() {
            match self.try_alloc_pages_internal(0) {
                Ok((frame, was_zeroed)) => {
                    if was_zeroed {
                        zeroed_mask |= 1u32 << count;
                    }
                    if count > 0 {
                        let idx = ((frame.start_address().as_u64() - self.base_addr.as_u64())
                            / PAGE_SIZE as u64) as usize;
                        self.page_state.store(idx, PAGE_PCP_CACHED);
                    }
                    out[count] = frame;
                    count += 1;
                }
                Err(AllocError::Exhausted) if count > 0 => break,
                Err(err) => return Err(err),
            }
        }
        Ok((count, zeroed_mask))
    }

    /// Allocate up to `out.len()` (max 32) order-0 frames directly in
    /// `PAGE_ALLOC_ORDER0` state in a single buddy-lock acquisition.
    /// Bit `i` of `zeroed_mask` is set iff `out[i]` was in `PAGE_FREE_ZEROED`
    /// (already scrubbed when drained from PCP). Returns `Err(AllocError::Exhausted)`
    /// only if zero frames could be allocated.
    fn try_alloc_direct_batch(
        &mut self,
        out: &mut [PhysFrame],
    ) -> Result<(usize, u32), AllocError> {
        if out.is_empty() || out.len() > 32 {
            return Err(AllocError::InvalidOrder);
        }
        let mut count = 0usize;
        let mut zeroed_mask = 0u32;
        while count < out.len() {
            match self.try_alloc_pages_internal(0) {
                Ok((frame, was_zeroed)) => {
                    if was_zeroed {
                        zeroed_mask |= 1u32 << count;
                    }
                    out[count] = frame;
                    count += 1;
                }
                Err(AllocError::Exhausted) if count > 0 => break,
                Err(err) => return Err(err),
            }
        }
        Ok((count, zeroed_mask))
    }

    /// 释放内存块
    ///
    /// # Arguments
    /// * `frame` - 要释放的物理帧
    /// * `order` - 块的阶数
    ///
    /// # Safety
    /// 调用者必须确保该帧确实是之前分配的，且未被双重释放
    pub fn free_pages(&mut self, frame: PhysFrame, order: usize) {
        if let Err(error) = self.try_free_pages(frame, order) {
            // R188-U26-2 FIX: never silently discard a failed deallocation.
            // Quarantine only when the allocator's own metadata is corrupt;
            // a caller-supplied wrong order/address is a rejected request and
            // must not strand every otherwise-valid allocation.
            if error.is_metadata_corruption() {
                self.poisoned = true;
            }
            kprintln!(
                "[buddy] rejected free_pages: {:?}{}",
                error,
                if error.is_metadata_corruption() {
                    "; allocator quarantined"
                } else {
                    "; allocator remains available"
                }
            );
        }
    }

    /// 合并相邻的buddy块
    /// Checked deallocation used when a caller must prove that a physical
    /// block really returned to the buddy allocator before releasing related
    /// admission or identity state.
    pub fn try_free_pages(&mut self, frame: PhysFrame, order: usize) -> Result<(), FreeError> {
        self.try_free_pages_internal(frame, order, false)
    }

    /// Issue #109 §1.3: return a PCP-cached order-0 frame (`PAGE_PCP_CACHED`)
    /// back to the global buddy free lists and coalesce buddies.
    fn try_free_pcp_page(&mut self, frame: PhysFrame) -> Result<(), FreeError> {
        self.try_free_pages_internal(frame, 0, true)
    }

    fn try_free_pages_internal(
        &mut self,
        frame: PhysFrame,
        order: usize,
        from_pcp: bool,
    ) -> Result<(), FreeError> {
        if self.poisoned {
            return Err(FreeError::AllocatorPoisoned);
        }
        if order >= ORDER_COUNT {
            return Err(FreeError::OrderTooLarge);
        }

        let addr = frame.start_address();
        if addr < self.base_addr {
            return Err(FreeError::AddressBelowBase);
        }
        let offset = addr.as_u64() - self.base_addr.as_u64();
        if offset % PAGE_SIZE as u64 != 0 {
            return Err(FreeError::AddressMisaligned);
        }

        let block_idx = (offset / PAGE_SIZE as u64) as usize;
        let pages = 1usize << order;
        // Buddy alignment is relative to the managed-region base, not physical
        // address zero.
        if block_idx & (pages - 1) != 0 {
            return Err(FreeError::AddressMisaligned);
        }
        if block_idx
            .checked_add(pages)
            .is_none_or(|end| end > self.total_pages)
        {
            return Err(FreeError::RangeOutOfBounds);
        }

        let start_state = self
            .page_state
            .get(block_idx)
            .map(|slot| slot.load(Ordering::Acquire))
            .ok_or(FreeError::RangeOutOfBounds)?;
        if from_pcp {
            if order != 0 || start_state != PAGE_PCP_CACHED {
                self.poisoned = true;
                return Err(FreeError::MetadataCorrupt);
            }
        } else {
            if start_state == PAGE_RESERVED {
                return Err(FreeError::ReservedPage);
            }
            if is_free_page_state(start_state)
                || start_state == PAGE_PCP_CACHED
                || decode_allocation_tail(start_state).is_some()
            {
                return Err(FreeError::NotAllocationStart);
            }
            let recorded_order =
                decode_allocation_start(start_state).ok_or(FreeError::NotAllocationStart)?;
            if recorded_order != order {
                return Err(FreeError::OrderMismatch);
            }
            let expected_tail = allocation_tail_state(order).ok_or(FreeError::OrderTooLarge)?;
            if (block_idx + 1..block_idx + pages).any(|index| {
                self.page_state
                    .get(index)
                    .map(|slot| slot.load(Ordering::Acquire))
                    != Some(expected_tail)
            }) {
                self.poisoned = true;
                return Err(FreeError::MetadataCorrupt);
            }
        }

        let no_allowed_bits = [None; ORDER_COUNT];
        if self.has_unexpected_free_overlap(block_idx, pages, &no_allowed_bits) {
            self.poisoned = true;
            return Err(FreeError::MetadataCorrupt);
        }

        let mut merge_bits = [None; ORDER_COUNT];
        let mut merge_count = 0usize;
        let mut merged_start = block_idx;
        let mut final_order = order;
        while final_order < ORDER_COUNT - 1 {
            let buddy_pages = 1usize << final_order;
            let buddy_idx = merged_start ^ buddy_pages;
            if buddy_idx
                .checked_add(buddy_pages)
                .is_none_or(|end| end > self.total_pages)
            {
                break;
            }
            let bit = self
                .free_map
                .location(final_order, buddy_idx)
                .ok_or_else(|| {
                    self.poisoned = true;
                    FreeError::MetadataCorrupt
                })?;
            if self.free_map.is_set(bit) {
                if !self.range_is_free(buddy_idx, buddy_pages)
                    || self.free_map.block_count[final_order] == 0
                {
                    self.poisoned = true;
                    return Err(FreeError::MetadataCorrupt);
                }
                merge_bits[merge_count] = Some(bit);
                merge_count += 1;
                merged_start = core::cmp::min(merged_start, buddy_idx);
                final_order += 1;
            } else {
                // A wholly-free buddy must have one exact maximal bit. If all
                // of its pages are free but that bit is absent, free space is
                // multiply split, lost, or otherwise inconsistently indexed.
                if self.range_is_free(buddy_idx, buddy_pages) {
                    self.poisoned = true;
                    return Err(FreeError::MetadataCorrupt);
                }
                break;
            }
        }

        if self.has_unexpected_free_overlap(merged_start, 1usize << final_order, &merge_bits) {
            self.poisoned = true;
            return Err(FreeError::MetadataCorrupt);
        }
        let final_bit = self
            .free_map
            .location(final_order, merged_start)
            .ok_or_else(|| {
                self.poisoned = true;
                FreeError::MetadataCorrupt
            })?;
        if self.free_map.is_set(final_bit) || self.free_map.block_count[final_order] == usize::MAX {
            self.poisoned = true;
            return Err(FreeError::MetadataCorrupt);
        }
        let new_free_pages = self.free_pages.checked_add(pages).ok_or_else(|| {
            self.poisoned = true;
            FreeError::MetadataCorrupt
        })?;
        if new_free_pages > self.total_pages.saturating_sub(self.reserved_pages) {
            self.poisoned = true;
            return Err(FreeError::MetadataCorrupt);
        }

        // Commit only after the entire merge chain and final destination are
        // proven. No operation below allocates or can return an error.
        for bit in merge_bits.iter().take(merge_count).flatten().copied() {
            self.free_map.commit_set(bit, false);
        }
        let free_state = if from_pcp {
            PAGE_FREE_ZEROED
        } else {
            PAGE_FREE
        };
        for index in block_idx..block_idx + pages {
            self.page_state.store(index, free_state);
        }
        self.free_map.commit_set(final_bit, true);
        self.free_pages = new_free_pages;
        Ok(())
    }

    #[inline]
    fn range_is_free(&self, start_idx: usize, pages: usize) -> bool {
        start_idx
            .checked_add(pages)
            .filter(|end| *end <= self.page_state.len())
            .is_some_and(|end| {
                self.page_state[start_idx..end]
                    .iter()
                    .all(|state| is_free_page_state(state.load(Ordering::Acquire)))
            })
    }

    fn bit_is_allowed(bit: FreeBit, allowed: &[Option<FreeBit>; ORDER_COUNT]) -> bool {
        allowed
            .iter()
            .flatten()
            .any(|candidate| candidate.order == bit.order && candidate.block_idx == bit.block_idx)
    }

    /// Check every free-map order for any block overlapping `[start, start+pages)`
    /// except the exact fixed set explicitly allowed by the transaction.
    fn has_unexpected_free_overlap(
        &self,
        start_idx: usize,
        pages: usize,
        allowed: &[Option<FreeBit>; ORDER_COUNT],
    ) -> bool {
        let Some(end_idx) = start_idx.checked_add(pages) else {
            return true;
        };
        if pages == 0 || end_idx > self.total_pages {
            return true;
        }

        for order in 0..ORDER_COUNT {
            let block_pages = 1usize << order;
            let first = start_idx / block_pages;
            let last = (end_idx - 1) / block_pages;
            for block_no in first..=last {
                let Some(block_idx) = block_no.checked_mul(block_pages) else {
                    return true;
                };
                let Some(bit) = self.free_map.location(order, block_idx) else {
                    continue;
                };
                if self.free_map.is_set(bit) && !Self::bit_is_allowed(bit, allowed) {
                    return true;
                }
            }
        }
        false
    }

    /// Full invariant audit used at construction and by regression tests. The
    /// runtime fast path still preflights every region it mutates; this global
    /// pass additionally proves count/coverage/maximal-coalescing consistency.
    fn validate_metadata(&self) -> Result<(), ()> {
        if self.page_state.len() != self.total_pages {
            return Err(());
        }

        let mut weighted_free = 0usize;
        for order in 0..ORDER_COUNT {
            let actual = self.free_map.count_actual(order).ok_or(())?;
            if actual != self.free_map.block_count[order] {
                return Err(());
            }
            weighted_free = weighted_free
                .checked_add(actual.checked_mul(1usize << order).ok_or(())?)
                .ok_or(())?;

            if order + 1 < ORDER_COUNT {
                for block_no in 0..self.free_map.valid_blocks[order] {
                    let block_idx = block_no << order;
                    let bit = self.free_map.location(order, block_idx).ok_or(())?;
                    if self.free_map.is_set(bit) {
                        let buddy_idx = block_idx ^ (1usize << order);
                        if let Some(buddy) = self.free_map.location(order, buddy_idx) {
                            if self.free_map.is_set(buddy) {
                                return Err(());
                            }
                        }
                    }
                }
            }
        }
        if weighted_free != self.free_pages {
            return Err(());
        }

        let mut reserved = 0usize;
        let mut page = 0usize;
        while page < self.total_pages {
            let state = self.page_state.load(page);
            if state == PAGE_RESERVED {
                let none = [None; ORDER_COUNT];
                if self.has_unexpected_free_overlap(page, 1, &none) {
                    return Err(());
                }
                reserved = reserved.checked_add(1).ok_or(())?;
                page += 1;
                continue;
            }
            if state == PAGE_PCP_CACHED {
                let none = [None; ORDER_COUNT];
                if self.has_unexpected_free_overlap(page, 1, &none) {
                    return Err(());
                }
                page += 1;
                continue;
            }
            if is_free_page_state(state) {
                let mut covering = 0usize;
                for order in 0..ORDER_COUNT {
                    let block_pages = 1usize << order;
                    let block_idx = (page / block_pages) * block_pages;
                    if let Some(bit) = self.free_map.location(order, block_idx) {
                        covering += usize::from(self.free_map.is_set(bit));
                    }
                }
                if covering != 1 {
                    return Err(());
                }
                page += 1;
                continue;
            }

            let Some(order) = decode_allocation_start(state) else {
                return Err(());
            };
            let pages = 1usize << order;
            if page & (pages - 1) != 0
                || page
                    .checked_add(pages)
                    .is_none_or(|end| end > self.total_pages)
            {
                return Err(());
            }
            let tail = allocation_tail_state(order).ok_or(())?;
            if (page + 1..page + pages).any(|index| self.page_state.load(index) != tail) {
                return Err(());
            }
            let none = [None; ORDER_COUNT];
            if self.has_unexpected_free_overlap(page, pages, &none) {
                return Err(());
            }
            page += pages;
        }
        if reserved != self.reserved_pages {
            return Err(());
        }
        Ok(())
    }

    /// 获取统计信息
    pub fn stats(&self) -> AllocatorStats {
        AllocatorStats {
            total_pages: self.total_pages,
            free_pages: self.free_pages,
            // R167-B: reserved pages are unavailable, so they count as "used"
            // (used_pages == total - free). Consumers reading used/free as
            // capacity therefore see reserved frames as occupied, which is
            // accurate — they can never be allocated.
            reserved_pages: self.reserved_pages,
            used_pages: self.total_pages - self.free_pages,
            fragmentation: self.calculate_fragmentation(),
        }
    }

    /// 计算内存碎片率
    fn calculate_fragmentation(&self) -> f32 {
        let mut largest_free_block = 0;

        for order in 0..ORDER_COUNT {
            let block_size = 1 << order;
            if self.free_map.block_count[order] != 0 && block_size > largest_free_block {
                largest_free_block = block_size;
            }
        }

        if self.free_pages == 0 {
            return 0.0;
        }

        1.0 - (largest_free_block as f32 / self.free_pages as f32)
    }
}

/// R167-B: largest buddy order whose block both fits in `remaining` pages and
/// is aligned at `start_idx`. Caps at `ORDER_COUNT - 1`. Always returns a valid
/// order (0 fits because `remaining >= 1` and every index is 1-aligned).
fn largest_aligned_order(start_idx: usize, remaining: usize) -> usize {
    let mut order = ORDER_COUNT - 1;
    while order > 0 {
        let block_pages = 1usize << order;
        if block_pages <= remaining && (start_idx & (block_pages - 1)) == 0 {
            return order;
        }
        order -= 1;
    }
    0
}

/// 分配器统计信息
#[derive(Debug, Clone, Copy)]
pub struct AllocatorStats {
    pub total_pages: usize,
    pub free_pages: usize,
    /// R167-B: pages permanently withheld from allocation (heap, kernel image,
    /// framebuffer, firmware ranges). Included in `used_pages`.
    pub reserved_pages: usize,
    pub used_pages: usize,
    pub fragmentation: f32,
}

/// Issue #109 §1.3: observability counters for the Per-CPU Page Cache (PCP).
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct PcpStats {
    pub hits: u64,
    pub misses: u64,
    pub refills: u64,
    pub drains: u64,
    pub frees_cached: u64,
    pub cross_cpu_drains: u64,
    pub refcount_rejections: u64,
    pub cached_pages: usize,
}

#[inline]
fn with_irqs_disabled<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(not(feature = "host_harness"))]
    {
        x86_64::instructions::interrupts::without_interrupts(f)
    }
    #[cfg(feature = "host_harness")]
    {
        f()
    }
}

/// Zero all 4096 bytes of an exclusively owned physical frame before it enters
/// PCP or is returned to an order-0 caller (Issue #109 §1.3 Invariant S2).
#[inline]
fn scrub_frame_phys(frame: PhysFrame) {
    #[cfg(not(feature = "host_harness"))]
    {
        let virt = crate::page_table::phys_to_virt(frame.start_address());
        // SAFETY: caller proved exclusive ownership (`PAGE_PCP_CACHED` or
        // `PAGE_ALLOC_ORDER0`, unmapped on all CPUs after TLB shootdown ACK)
        // and the managed buddy window lies inside the high-half direct map.
        unsafe {
            core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, PAGE_SIZE);
        }
    }
    #[cfg(feature = "host_harness")]
    {
        let _ = frame;
    }
}

#[inline]
fn read_production_cow_refcount(page_idx: usize) -> u32 {
    crate::memory::cow_refcount_slot(page_idx)
        .map(|slot| slot.load(Ordering::Acquire))
        .unwrap_or(0)
}

#[inline]
fn current_pcp_cpu_id() -> usize {
    cpu_local::current_cpu_id() % cpu_local::max_cpus()
}

struct PcpMagazine {
    frames: [u64; PCP_HIGH_WATERMARK],
    len: usize,
}

impl PcpMagazine {
    const fn new() -> Self {
        Self {
            frames: [0; PCP_HIGH_WATERMARK],
            len: 0,
        }
    }
}

/// Cache-line-isolated per-CPU order-0 page magazine and hot counters (Issue #109 §1.3).
///
/// Keeping `cached_count`, `hits`, and `frees_cached` inside the CPU's own
/// 64-byte-aligned slot guarantees ZERO global atomic RMWs on the PCP alloc/free
/// hot path, eliminating cross-CPU cache-line bouncing.
///
/// Lock ordering rule L1: `pcp[c].lock` and `buddy` are NEVER held simultaneously,
/// making deadlock impossible even under concurrent cross-CPU drains or nested
/// `#PF` faults (hot path uses `try_lock` under `IF=0` and falls back to `buddy`
/// without spinning).
#[repr(align(64))]
struct CacheAlignedPcp {
    lock: Mutex<PcpMagazine>,
    /// Pages currently owned by this CPU's PCP (cached in `lock` + in-flight
    /// refill/drain batches accounted under `buddy` lock). Summed across CPUs
    /// under `buddy` lock in `stats()` for exact `free_pages` conservation.
    cached_count: AtomicUsize,
    hits: AtomicU64,
    frees_cached: AtomicU64,
}

impl CacheAlignedPcp {
    const fn new() -> Self {
        Self {
            lock: Mutex::new(PcpMagazine::new()),
            cached_count: AtomicUsize::new(0),
            hits: AtomicU64::new(0),
            frees_cached: AtomicU64::new(0),
        }
    }
}

const _: () = assert!(core::mem::align_of::<CacheAlignedPcp>() == 64);

/// Self-contained Buddy + Per-CPU Page Cache pool (Issue #109 §1.3).
///
/// Production uses the single static `GLOBAL_BUDDY`; hosted unit tests
/// instantiate isolated `PcpBuddyPool` values so parallel test execution never
/// races on global allocator state while still exercising the exact production
/// fast path, state machine, conservation accounting, and cross-CPU drain.
struct PcpBuddyPool {
    buddy: Mutex<Option<BuddyAllocator>>,
    pcp: [CacheAlignedPcp; cpu_local::max_cpus()],
    window_base: AtomicU64,
    window_pages: AtomicUsize,
    page_state_ptr: AtomicUsize,
    poisoned: AtomicBool,
    stat_misses: AtomicU64,
    stat_refills: AtomicU64,
    stat_drains: AtomicU64,
    stat_cross_cpu_drains: AtomicU64,
    stat_refcount_rejections: AtomicU64,
}

impl PcpBuddyPool {
    const fn new() -> Self {
        Self {
            buddy: Mutex::new(None),
            pcp: [const { CacheAlignedPcp::new() }; cpu_local::max_cpus()],
            window_base: AtomicU64::new(0),
            window_pages: AtomicUsize::new(0),
            page_state_ptr: AtomicUsize::new(0),
            poisoned: AtomicBool::new(false),
            stat_misses: AtomicU64::new(0),
            stat_refills: AtomicU64::new(0),
            stat_drains: AtomicU64::new(0),
            stat_cross_cpu_drains: AtomicU64::new(0),
            stat_refcount_rejections: AtomicU64::new(0),
        }
    }

    fn publish(&self, allocator: BuddyAllocator) {
        self.window_pages.store(0, Ordering::Release);
        for slot in &self.pcp {
            with_irqs_disabled(|| {
                slot.lock.lock().len = 0;
                slot.cached_count.store(0, Ordering::Release);
            });
        }
        self.poisoned.store(allocator.poisoned, Ordering::Release);

        let base = allocator.base_addr.as_u64();
        let total_pages = allocator.total_pages;
        let ptr = allocator.page_state.as_ptr() as usize;

        let mut guard = self.buddy.lock();
        *guard = Some(allocator);
        self.window_base.store(base, Ordering::Relaxed);
        self.page_state_ptr.store(ptr, Ordering::Relaxed);
        self.window_pages.store(total_pages, Ordering::Release);
    }

    #[inline]
    fn page_state_view(&self) -> Option<(u64, &[AtomicU8])> {
        let len = self.window_pages.load(Ordering::Acquire);
        if len == 0 {
            return None;
        }
        let ptr = self.page_state_ptr.load(Ordering::Relaxed) as *const AtomicU8;
        if ptr.is_null() {
            return None;
        }
        let base = self.window_base.load(Ordering::Relaxed);
        // SAFETY: `publish` stores `page_state` (backed by fixed non-moving
        // boot-reserved frames or fixed-capacity `BuddyAllocator` storage) and
        // releases `window_pages` after setting `page_state_ptr` and `base`.
        // The slice is tied to `&self` and accessed exclusively via shared
        // atomic operations (`&[AtomicU8]`).
        let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
        Some((base, slice))
    }

    #[inline]
    fn mark_poisoned(&self) {
        self.poisoned.store(true, Ordering::Release);
        if let Some(allocator) = self.buddy.try_lock().and_then(|mut g| {
            if let Some(a) = g.as_mut() {
                a.poisoned = true;
                Some(())
            } else {
                None
            }
        }) {
            let _ = allocator;
        }
    }

    fn return_pcp_frames_to_buddy(&self, cpu: usize, frames: &[u64], count_already_in_total: bool) {
        if frames.is_empty() {
            return;
        }
        let mut guard = self.buddy.lock();
        if count_already_in_total {
            self.pcp[cpu]
                .cached_count
                .fetch_sub(frames.len(), Ordering::AcqRel);
        }
        if let Some(allocator) = guard.as_mut() {
            for &phys in frames {
                let frame = PhysFrame::containing_address(PhysAddr::new(phys));
                if let Err(err) = allocator.try_free_pcp_page(frame) {
                    if err.is_metadata_corruption() {
                        allocator.poisoned = true;
                        self.poisoned.store(true, Ordering::Release);
                    }
                    kprintln!("[buddy][pcp] drain return failed: {:?}", err);
                }
            }
        }
    }

    /// Synchronously drain every CPU's PCP magazine back to the global buddy
    /// allocator so cached order-0 frames coalesce into higher-order blocks.
    ///
    /// Lock ordering: acquires at most one `pcp[cpu]` lock at a time in
    /// ascending CPU index order, copies frames into a stack buffer, releases
    /// `pcp[cpu]`, and only then acquires `self.buddy`.
    fn drain_all_pcp(&self, cpu_limit: usize) -> usize {
        let mut total_drained = 0usize;
        let limit = core::cmp::min(cpu_limit, self.pcp.len());
        let mut buf = [0u64; PCP_HIGH_WATERMARK];

        for cpu in 0..limit {
            let drained = with_irqs_disabled(|| {
                let mut mag = self.pcp[cpu].lock.lock();
                let n = mag.len;
                if n > 0 {
                    buf[..n].copy_from_slice(&mag.frames[..n]);
                    mag.len = 0;
                }
                n
            });
            if drained > 0 {
                self.return_pcp_frames_to_buddy(cpu, &buf[..drained], true);
                total_drained += drained;
            }
        }
        if total_drained > 0 {
            self.stat_cross_cpu_drains.fetch_add(1, Ordering::Relaxed);
        }
        total_drained
    }

    fn try_alloc_order0_with<FScrub>(
        &self,
        cpu_id: usize,
        cpu_limit: usize,
        scrub: FScrub,
        run_oom: bool,
    ) -> Result<PhysFrame, AllocError>
    where
        FScrub: Fn(PhysFrame),
    {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(AllocError::AllocatorPoisoned);
        }

        let cpu = cpu_id % self.pcp.len();

        // Fast path: pop one pre-zeroed frame from this CPU's PCP magazine
        // touching ONLY this CPU's 64B cache line (zero global atomics).
        if let Some((base, states)) = self.page_state_view() {
            let popped = with_irqs_disabled(|| {
                let mut mag = self.pcp[cpu].lock.try_lock()?;
                if mag.len == 0 {
                    return None;
                }
                mag.len -= 1;
                let idx = mag.len;
                let phys = mag.frames[idx];
                self.pcp[cpu].cached_count.fetch_sub(1, Ordering::AcqRel);
                let prev_hits = self.pcp[cpu].hits.load(Ordering::Relaxed);
                self.pcp[cpu]
                    .hits
                    .store(prev_hits.wrapping_add(1), Ordering::Relaxed);
                Some(phys)
            });

            if let Some(phys) = popped {
                let idx = ((phys - base) / PAGE_SIZE as u64) as usize;
                match states[idx].compare_exchange(
                    PAGE_PCP_CACHED,
                    PAGE_ALLOC_ORDER0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        return Ok(PhysFrame::containing_address(PhysAddr::new(phys)));
                    }
                    Err(_) => {
                        self.mark_poisoned();
                        return Err(AllocError::MetadataCorrupt);
                    }
                }
            }
        }

        // Cold path: refill up to PCP_REFILL_BATCH order-0 frames in a single
        // buddy-lock acquisition.
        self.stat_misses.fetch_add(1, Ordering::Relaxed);
        let mut batch = [PhysFrame::containing_address(PhysAddr::new(0)); PCP_REFILL_BATCH];

        let mut refill_result = self.refill_batch_from_buddy(cpu, &mut batch);
        let mut transient_busy = false;
        let mut saw_busy = false;
        for _ in 0..8 {
            if !matches!(refill_result, Err(AllocError::Exhausted)) {
                break;
            }
            let pcp_reclaimed = self.drain_all_pcp(cpu_limit);
            let transient = oom_killer::reclaim_transient_caches_nonblocking();
            transient_busy = transient.busy;
            if transient.busy {
                saw_busy = true;
            }
            if pcp_reclaimed > 0 || transient.reclaimed_pages > 0 {
                if !transient.busy {
                    saw_busy = false;
                }
                refill_result = self.refill_batch_from_buddy(cpu, &mut batch);
            } else if transient.busy {
                core::hint::spin_loop();
            } else {
                if saw_busy {
                    // A concurrent drain finished while we waited; re-check
                    // Buddy once before escalating to OOM.
                    let _ = self.drain_all_pcp(cpu_limit);
                    refill_result = self.refill_batch_from_buddy(cpu, &mut batch);
                }
                break;
            }
        }
        if matches!(refill_result, Err(AllocError::Exhausted)) && transient_busy {
            return Err(AllocError::Busy);
        }
        if matches!(refill_result, Err(AllocError::Exhausted)) && run_oom {
            oom_killer::on_allocation_failure(1);
            oom_killer::poll_and_handle_oom();
            let _ = self.drain_all_pcp(cpu_limit);
            refill_result = self.refill_batch_from_buddy(cpu, &mut batch);
        }

        let (count, zeroed_mask) = refill_result?;
        self.stat_refills.fetch_add(1, Ordering::Relaxed);

        // Invariant S2: scrub every unzeroed frame pulled from buddy before
        // reuse or caching in PCP. Frames drained earlier from PCP already carry
        // `PAGE_FREE_ZEROED` and skip redundant 4 KiB memsets.
        for (i, &frame) in batch[..count].iter().enumerate() {
            if (zeroed_mask & (1u32 << i)) == 0 {
                scrub(frame);
            }
        }

        if count > 1 {
            let extra = count - 1;
            let mut extra_phys = [0u64; PCP_REFILL_BATCH];
            for (i, frame) in batch[1..count].iter().enumerate() {
                extra_phys[i] = frame.start_address().as_u64();
            }

            let pushed = with_irqs_disabled(|| {
                let Some(mut mag) = self.pcp[cpu].lock.try_lock() else {
                    return 0;
                };
                let space = PCP_HIGH_WATERMARK.saturating_sub(mag.len);
                let to_push = core::cmp::min(extra, space);
                let mut idx = mag.len;
                for &phys in &extra_phys[..to_push] {
                    mag.frames[idx] = phys;
                    idx += 1;
                }
                mag.len = idx;
                to_push
            });

            if pushed < extra {
                self.return_pcp_frames_to_buddy(cpu, &extra_phys[pushed..extra], true);
            }
        }

        Ok(batch[0])
    }

    /// Allocate up to `out.len()` pre-zeroed order-0 frames in batched PCP and
    /// buddy holds, returning the number of frames filled (`0..=out.len()`).
    ///
    /// Preserves Invariant S2 (every returned frame is zeroed) and Invariant S3
    /// (`buddy.free_pages + sum(pcp.cached_count)` conservation). On metadata
    /// corruption or poisoned allocator, returns `Err(...)` immediately.
    fn try_alloc_order0_batch_with<FScrub>(
        &self,
        out: &mut [PhysFrame],
        cpu_id: usize,
        cpu_limit: usize,
        scrub: FScrub,
        run_oom: bool,
    ) -> Result<usize, AllocError>
    where
        FScrub: Fn(PhysFrame) + Copy,
    {
        if out.is_empty() {
            return Ok(0);
        }
        if self.poisoned.load(Ordering::Acquire) {
            return Err(AllocError::AllocatorPoisoned);
        }

        let cpu = cpu_id % self.pcp.len();
        let mut filled = 0usize;

        // Fast path: pop as many pre-zeroed frames as possible from this CPU's
        // PCP magazine in a single lock hold (zero global atomics per frame).
        if let Some((base, states)) = self.page_state_view() {
            let mut popped_phys = [0u64; PCP_HIGH_WATERMARK];
            let max_pop = out.len().min(PCP_HIGH_WATERMARK);
            let popped = with_irqs_disabled(|| {
                let Some(mut mag) = self.pcp[cpu].lock.try_lock() else {
                    return 0;
                };
                let take = mag.len.min(max_pop);
                if take == 0 {
                    return 0;
                }
                let start = mag.len - take;
                popped_phys[..take].copy_from_slice(&mag.frames[start..mag.len]);
                mag.len = start;
                self.pcp[cpu].cached_count.fetch_sub(take, Ordering::AcqRel);
                let prev_hits = self.pcp[cpu].hits.load(Ordering::Relaxed);
                self.pcp[cpu]
                    .hits
                    .store(prev_hits.wrapping_add(take as u64), Ordering::Relaxed);
                take
            });

            for &phys in &popped_phys[..popped] {
                let idx = ((phys - base) / PAGE_SIZE as u64) as usize;
                if states[idx]
                    .compare_exchange(
                        PAGE_PCP_CACHED,
                        PAGE_ALLOC_ORDER0,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    self.mark_poisoned();
                    return Err(AllocError::MetadataCorrupt);
                }
                out[filled] = PhysFrame::containing_address(PhysAddr::new(phys));
                filled += 1;
            }
        }

        // Fill any remainder directly from buddy in up to `PCP_REFILL_BATCH`
        // chunks (single buddy lock per chunk), delegating single-page tails
        // to `try_alloc_order0_with` so the PCP magazine also gets topped up.
        while filled < out.len() {
            let remaining = out.len() - filled;
            if remaining == 1 {
                match self.try_alloc_order0_with(cpu_id, cpu_limit, scrub, run_oom) {
                    Ok(frame) => {
                        out[filled] = frame;
                        filled += 1;
                    }
                    Err(AllocError::MetadataCorrupt | AllocError::AllocatorPoisoned) => {
                        return Err(AllocError::MetadataCorrupt);
                    }
                    Err(_) => break,
                }
                break;
            }

            let chunk_len = remaining.min(PCP_REFILL_BATCH);
            let alloc_direct = |buf: &mut [PhysFrame]| -> Result<(usize, u32), AllocError> {
                let mut guard = self.buddy.lock();
                let allocator = guard.as_mut().ok_or(AllocError::AllocatorUnavailable)?;
                let res = allocator.try_alloc_direct_batch(buf);
                if matches!(
                    res,
                    Err(AllocError::MetadataCorrupt | AllocError::AllocatorPoisoned)
                ) {
                    self.poisoned.store(true, Ordering::Release);
                }
                res
            };

            let target = &mut out[filled..filled + chunk_len];
            let mut result = alloc_direct(target);
            let mut transient_busy = false;
            let mut saw_busy = false;
            for _ in 0..8 {
                if !matches!(result, Err(AllocError::Exhausted)) {
                    break;
                }
                let pcp_reclaimed = self.drain_all_pcp(cpu_limit);
                let transient = oom_killer::reclaim_transient_caches_nonblocking();
                transient_busy = transient.busy;
                if transient.busy {
                    saw_busy = true;
                }
                if pcp_reclaimed > 0 || transient.reclaimed_pages > 0 {
                    if !transient.busy {
                        saw_busy = false;
                    }
                    result = alloc_direct(target);
                } else if transient.busy {
                    core::hint::spin_loop();
                } else {
                    if saw_busy {
                        let _ = self.drain_all_pcp(cpu_limit);
                        result = alloc_direct(target);
                    }
                    break;
                }
            }
            if matches!(result, Err(AllocError::Exhausted)) && transient_busy {
                break;
            }
            if matches!(result, Err(AllocError::Exhausted)) && run_oom {
                oom_killer::on_allocation_failure(remaining);
                oom_killer::poll_and_handle_oom();
                let _ = self.drain_all_pcp(cpu_limit);
                result = alloc_direct(target);
            }

            match result {
                Ok((got, zeroed_mask)) => {
                    for (i, &frame) in target[..got].iter().enumerate() {
                        if (zeroed_mask & (1u32 << i)) == 0 {
                            scrub(frame);
                        }
                    }
                    filled += got;
                }
                Err(AllocError::MetadataCorrupt | AllocError::AllocatorPoisoned) => {
                    return Err(AllocError::MetadataCorrupt);
                }
                Err(_) => break,
            }
        }

        Ok(filled)
    }

    /// Free a slice of order-0 frames in batched PCP and buddy holds.
    ///
    /// Preserves Invariant S1 (refcount == 0 circuit-breaker), Invariant S2
    /// (4 KiB scrub after claiming `PAGE_PCP_CACHED` and before exposing to
    /// PCP/buddy), and Invariant S3 (`cached_count` conservation). Invalid
    /// frames are rejected individually without poisoning unrelated allocations.
    fn free_order0_batch_with<FRef, FScrub>(
        &self,
        frames: &[PhysFrame],
        cpu_id: usize,
        read_refcount: FRef,
        scrub: FScrub,
    ) where
        FRef: Fn(usize) -> u32,
        FScrub: Fn(PhysFrame),
    {
        if frames.is_empty() || self.poisoned.load(Ordering::Acquire) {
            return;
        }
        let Some((base, states)) = self.page_state_view() else {
            return;
        };

        let cpu = cpu_id % self.pcp.len();
        let mut claimed = [0u64; PCP_HIGH_WATERMARK];

        for chunk in frames.chunks(PCP_HIGH_WATERMARK) {
            let mut claimed_len = 0usize;
            for &frame in chunk {
                let addr = frame.start_address().as_u64();
                if addr < base {
                    continue;
                }
                let offset = addr - base;
                if offset % PAGE_SIZE as u64 != 0 {
                    continue;
                }
                let idx = (offset / PAGE_SIZE as u64) as usize;
                if idx >= states.len() {
                    continue;
                }
                if read_refcount(idx) != 0 {
                    self.stat_refcount_rejections
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if states[idx]
                    .compare_exchange(
                        PAGE_ALLOC_ORDER0,
                        PAGE_PCP_CACHED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    continue;
                }
                // Invariant S2: zero before exposing to PCP or buddy.
                scrub(frame);
                claimed[claimed_len] = addr;
                claimed_len += 1;
            }

            if claimed_len == 0 {
                continue;
            }

            let pushed = with_irqs_disabled(|| {
                let Some(mut mag) = self.pcp[cpu].lock.try_lock() else {
                    return 0;
                };
                let space = PCP_HIGH_WATERMARK.saturating_sub(mag.len);
                let to_push = claimed_len.min(space);
                if to_push > 0 {
                    let start = mag.len;
                    mag.frames[start..start + to_push].copy_from_slice(&claimed[..to_push]);
                    mag.len = start + to_push;
                    self.pcp[cpu]
                        .cached_count
                        .fetch_add(to_push, Ordering::AcqRel);
                    let prev_frees = self.pcp[cpu].frees_cached.load(Ordering::Relaxed);
                    self.pcp[cpu]
                        .frees_cached
                        .store(prev_frees.wrapping_add(to_push as u64), Ordering::Relaxed);
                }
                to_push
            });

            if pushed < claimed_len {
                // Overflow (or contended PCP lock): return the remaining
                // pre-scrubbed `PAGE_PCP_CACHED` frames directly to buddy in
                // one lock hold (`from_cached_count = false` since they were
                // never added to `cached_count`).
                self.return_pcp_frames_to_buddy(cpu, &claimed[pushed..claimed_len], false);
            }
        }
    }

    fn refill_batch_from_buddy(
        &self,
        cpu: usize,
        batch: &mut [PhysFrame],
    ) -> Result<(usize, u32), AllocError> {
        let mut guard = self.buddy.lock();
        let allocator = guard.as_mut().ok_or(AllocError::AllocatorUnavailable)?;
        let res = allocator.try_alloc_pcp_batch(batch);
        match res {
            Ok((count, zeroed_mask)) => {
                // Conserve `buddy.free_pages + sum(pcp[c].cached_count)`
                // atomically under the buddy lock (Invariant S3).
                if count > 1 {
                    self.pcp[cpu]
                        .cached_count
                        .fetch_add(count - 1, Ordering::AcqRel);
                }
                Ok((count, zeroed_mask))
            }
            Err(err) => {
                if matches!(
                    err,
                    AllocError::MetadataCorrupt | AllocError::AllocatorPoisoned
                ) {
                    self.poisoned.store(true, Ordering::Release);
                }
                Err(err)
            }
        }
    }

    fn try_alloc_multi_with(
        &self,
        order: usize,
        pages_needed: usize,
        cpu_limit: usize,
        run_oom: bool,
    ) -> Result<PhysFrame, AllocError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(AllocError::AllocatorPoisoned);
        }
        let alloc_once = || -> Result<PhysFrame, AllocError> {
            let mut guard = self.buddy.lock();
            let allocator = guard.as_mut().ok_or(AllocError::AllocatorUnavailable)?;
            let res = allocator.try_alloc_pages(order);
            if matches!(
                res,
                Err(AllocError::MetadataCorrupt | AllocError::AllocatorPoisoned)
            ) {
                self.poisoned.store(true, Ordering::Release);
            }
            res
        };

        match alloc_once() {
            Ok(frame) => return Ok(frame),
            Err(AllocError::Exhausted) => {}
            Err(err) => return Err(err),
        }

        // Drain all CPUs' PCP caches and registered transient frame caches
        // (e.g. post-shootdown kstack reuse cache) first so cached blocks can
        // satisfy or coalesce into the request before triggering OOM.
        let mut transient_busy = false;
        let mut saw_busy = false;
        for _ in 0..8 {
            let pcp_reclaimed = self.drain_all_pcp(cpu_limit);
            let transient = oom_killer::reclaim_transient_caches_nonblocking();
            transient_busy = transient.busy;
            if transient.busy {
                saw_busy = true;
            }
            if pcp_reclaimed > 0 || transient.reclaimed_pages > 0 {
                if !transient.busy {
                    saw_busy = false;
                }
                match alloc_once() {
                    Ok(frame) => return Ok(frame),
                    Err(AllocError::Exhausted) => {}
                    Err(err) => return Err(err),
                }
            } else if transient.busy {
                core::hint::spin_loop();
            } else {
                if saw_busy {
                    // A concurrent drain finished while we waited; re-check
                    // Buddy once before escalating to OOM.
                    let _ = self.drain_all_pcp(cpu_limit);
                    match alloc_once() {
                        Ok(frame) => return Ok(frame),
                        Err(AllocError::Exhausted) => {}
                        Err(err) => return Err(err),
                    }
                }
                break;
            }
        }
        if transient_busy {
            return Err(AllocError::Busy);
        }

        if !run_oom {
            return Err(AllocError::Exhausted);
        }

        oom_killer::on_allocation_failure(pages_needed);
        // RF178-4: run reclaim only after releasing BUDDY_ALLOCATOR so recovery
        // cannot recursively acquire the allocator guard.
        oom_killer::poll_and_handle_oom();
        let _ = self.drain_all_pcp(cpu_limit);

        alloc_once()
    }

    fn try_free_order0_with<FRef, FScrub>(
        &self,
        frame: PhysFrame,
        cpu_id: usize,
        read_refcount: FRef,
        scrub: FScrub,
    ) -> Result<(), FreeError>
    where
        FRef: Fn(usize) -> u32,
        FScrub: Fn(PhysFrame),
    {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(FreeError::AllocatorPoisoned);
        }
        let Some((base, states)) = self.page_state_view() else {
            return Err(FreeError::AllocatorUnavailable);
        };

        let addr = frame.start_address().as_u64();
        if addr < base {
            return Err(FreeError::AddressBelowBase);
        }
        let offset = addr - base;
        if offset % PAGE_SIZE as u64 != 0 {
            return Err(FreeError::AddressMisaligned);
        }
        let idx = (offset / PAGE_SIZE as u64) as usize;
        if idx >= states.len() {
            return Err(FreeError::RangeOutOfBounds);
        }

        // Invariant S1 circuit-breaker: refuse freeing any frame whose COW or
        // shared-anonymous `PAGE_REF_COUNT` slot is still non-zero.
        if read_refcount(idx) != 0 {
            self.stat_refcount_rejections
                .fetch_add(1, Ordering::Relaxed);
            return Err(FreeError::PageStillReferenced);
        }

        // Lock-free atomic state claim: proves `frame` is a live order-0 block
        // (rejecting double-free, partial free of order > 0, interior tails,
        // and reserved pages without taking the global buddy lock).
        if let Err(old) = states[idx].compare_exchange(
            PAGE_ALLOC_ORDER0,
            PAGE_PCP_CACHED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            if self.poisoned.load(Ordering::Acquire) {
                return Err(FreeError::AllocatorPoisoned);
            }
            if old == PAGE_RESERVED {
                return Err(FreeError::ReservedPage);
            }
            if is_free_page_state(old)
                || old == PAGE_PCP_CACHED
                || decode_allocation_tail(old).is_some()
            {
                return Err(FreeError::NotAllocationStart);
            }
            if let Some(recorded_order) = decode_allocation_start(old) {
                if recorded_order != 0 {
                    return Err(FreeError::OrderMismatch);
                }
            }
            return Err(FreeError::NotAllocationStart);
        }

        // Invariant S2: zero all 4096 bytes after claiming exclusive ownership
        // (`PAGE_PCP_CACHED`) and before exposing the frame to PCP or buddy.
        scrub(frame);

        let cpu = cpu_id % self.pcp.len();
        let mut drain_buf = [0u64; PCP_DRAIN_BATCH];
        let mut drained_count = 0usize;
        let cached = with_irqs_disabled(|| {
            let Some(mut mag) = self.pcp[cpu].lock.try_lock() else {
                return false;
            };
            if mag.len >= PCP_HIGH_WATERMARK {
                let start = mag.len - PCP_DRAIN_BATCH;
                drain_buf.copy_from_slice(&mag.frames[start..mag.len]);
                mag.len = start;
                drained_count = PCP_DRAIN_BATCH;
            }
            let idx = mag.len;
            mag.frames[idx] = addr;
            mag.len = idx + 1;
            self.pcp[cpu].cached_count.fetch_add(1, Ordering::AcqRel);
            let prev_frees = self.pcp[cpu].frees_cached.load(Ordering::Relaxed);
            self.pcp[cpu]
                .frees_cached
                .store(prev_frees.wrapping_add(1), Ordering::Relaxed);
            true
        });

        if !cached {
            // Contended with a remote `drain_all_pcp`: return directly to buddy.
            // `frame` was never added to `cached_count`.
            let one = [addr];
            self.return_pcp_frames_to_buddy(cpu, &one, false);
            return Ok(());
        }

        if drained_count > 0 {
            self.stat_drains.fetch_add(1, Ordering::Relaxed);
            self.return_pcp_frames_to_buddy(cpu, &drain_buf[..drained_count], true);
        }
        Ok(())
    }

    fn try_free_multi_with<FRef>(
        &self,
        frame: PhysFrame,
        order: usize,
        read_refcount: FRef,
    ) -> Result<(), FreeError>
    where
        FRef: Fn(usize) -> u32,
    {
        self.try_free_multi_impl(frame, order, read_refcount, false)
    }

    fn try_free_multi_nonblocking_with<FRef>(
        &self,
        frame: PhysFrame,
        order: usize,
        read_refcount: FRef,
    ) -> Result<(), FreeError>
    where
        FRef: Fn(usize) -> u32,
    {
        self.try_free_multi_impl(frame, order, read_refcount, true)
    }

    fn try_free_multi_impl<FRef>(
        &self,
        frame: PhysFrame,
        order: usize,
        read_refcount: FRef,
        nonblocking: bool,
    ) -> Result<(), FreeError>
    where
        FRef: Fn(usize) -> u32,
    {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(FreeError::AllocatorPoisoned);
        }
        if let Some((base, states)) = self.page_state_view() {
            let addr = frame.start_address().as_u64();
            let pages = 1usize << order;
            if addr >= base && (addr - base) % PAGE_SIZE as u64 == 0 {
                let start_idx = ((addr - base) / PAGE_SIZE as u64) as usize;
                if start_idx
                    .checked_add(pages)
                    .is_some_and(|end| end <= states.len())
                {
                    for idx in start_idx..start_idx + pages {
                        if read_refcount(idx) != 0 {
                            self.stat_refcount_rejections
                                .fetch_add(1, Ordering::Relaxed);
                            return Err(FreeError::PageStillReferenced);
                        }
                    }
                }
            }
        }
        let mut guard = if nonblocking {
            self.buddy.try_lock().ok_or(FreeError::Busy)?
        } else {
            self.buddy.lock()
        };
        let allocator = guard.as_mut().ok_or(FreeError::AllocatorUnavailable)?;
        let res = allocator.try_free_pages(frame, order);
        if let Err(err) = res {
            if err.is_metadata_corruption() {
                allocator.poisoned = true;
                self.poisoned.store(true, Ordering::Release);
            }
        }
        res
    }

    fn total_cached_pages(&self) -> usize {
        self.pcp
            .iter()
            .map(|slot| slot.cached_count.load(Ordering::Acquire))
            .sum()
    }

    fn stats(&self) -> Option<AllocatorStats> {
        let guard = self.buddy.lock();
        let allocator = guard.as_ref()?;
        let cached = self.total_cached_pages();
        let mut s = allocator.stats();
        // Invariant S3: `buddy.free_pages + sum(pcp[c].cached_count)` is exact
        // under the buddy lock (refill and drain update both together inside it).
        s.free_pages = s.free_pages.saturating_add(cached).min(s.total_pages);
        s.used_pages = s.total_pages.saturating_sub(s.free_pages);
        Some(s)
    }

    fn pcp_stats(&self) -> PcpStats {
        let mut hits = 0u64;
        let mut frees_cached = 0u64;
        let mut cached_pages = 0usize;
        for slot in &self.pcp {
            hits = hits.wrapping_add(slot.hits.load(Ordering::Relaxed));
            frees_cached = frees_cached.wrapping_add(slot.frees_cached.load(Ordering::Relaxed));
            cached_pages = cached_pages.saturating_add(slot.cached_count.load(Ordering::Acquire));
        }
        PcpStats {
            hits,
            misses: self.stat_misses.load(Ordering::Relaxed),
            refills: self.stat_refills.load(Ordering::Relaxed),
            drains: self.stat_drains.load(Ordering::Relaxed),
            frees_cached,
            cross_cpu_drains: self.stat_cross_cpu_drains.load(Ordering::Relaxed),
            refcount_rejections: self.stat_refcount_rejections.load(Ordering::Relaxed),
            cached_pages,
        }
    }

    /// Issue #109 rollup audit (ASTRA-3): Non-blocking fault-safe borrow of the
    /// underlying [`BuddyAllocator`] with bounded PCP recovery.
    ///
    /// Fault allocators (`handle_shared_anonymous_fault`, `try_grow_user_stack`,
    /// `map_hold` spare staging) call this directly on `BuddyAllocator`. If the
    /// buddy is low/empty while order-0 frames are cached in PCP magazines,
    /// drain any uncontended magazines back into `allocator` using strictly
    /// non-blocking `try_lock` (preserving deadlock freedom because no path
    /// holds a PCP magazine lock while acquiring `buddy`). If magazines were
    /// contended and buddy remains below `PCP_REFILL_BATCH`, fail closed with
    /// `None` (`Busy`/`EAGAIN`) rather than reporting spurious `ENOMEM`.
    /// Non-blocking bounded PCP recovery while `allocator` is held under
    /// `self.buddy`. Returns `true` when contention or in-flight PCP pages
    /// remain while `allocator.free_pages < PCP_REFILL_BATCH`, signaling the
    /// caller to fail closed with `None` (`Busy`/`EAGAIN`).
    fn drain_pcp_into_locked_buddy(
        &self,
        allocator: &mut BuddyAllocator,
        cpu_limit: usize,
    ) -> bool {
        if allocator.free_pages >= PCP_HIGH_WATERMARK || self.total_cached_pages() == 0 {
            return false;
        }
        let limit = core::cmp::min(cpu_limit, self.pcp.len());
        let mut buf = [0u64; PCP_HIGH_WATERMARK];
        let mut total_drained = 0usize;
        let mut saw_contention = false;

        for cpu in 0..limit {
            if self.pcp[cpu].cached_count.load(Ordering::Acquire) == 0 {
                continue;
            }
            let drained = with_irqs_disabled(|| {
                let Some(mut mag) = self.pcp[cpu].lock.try_lock() else {
                    return None;
                };
                let n = mag.len;
                if n > 0 {
                    buf[..n].copy_from_slice(&mag.frames[..n]);
                    mag.len = 0;
                }
                Some(n)
            });
            match drained {
                None => {
                    saw_contention = true;
                }
                Some(0) => {}
                Some(n) => {
                    self.pcp[cpu].cached_count.fetch_sub(n, Ordering::AcqRel);
                    for &phys in &buf[..n] {
                        let frame = PhysFrame::containing_address(PhysAddr::new(phys));
                        if let Err(err) = allocator.try_free_pcp_page(frame) {
                            if err.is_metadata_corruption() {
                                allocator.poisoned = true;
                                self.poisoned.store(true, Ordering::Release);
                            }
                            kprintln!("[buddy][pcp] fault drain return failed: {:?}", err);
                        }
                    }
                    total_drained += n;
                }
            }
        }

        if total_drained > 0 {
            self.stat_cross_cpu_drains.fetch_add(1, Ordering::Relaxed);
        }
        // Also treat still-nonzero `total_cached_pages()` (frames in flight
        // inside another CPU's `drain_all_pcp` or `refill_batch_from_buddy`
        // awaiting `buddy.lock`) as retryable contention when buddy remains
        // below `PCP_REFILL_BATCH`, releasing `buddy` so they can land.
        (saw_contention || self.total_cached_pages() > 0) && allocator.free_pages < PCP_REFILL_BATCH
    }

    /// Strictly non-blocking order-0 frame allocation for interrupt/exception
    /// paths (e.g. CoW `#PF`). Pops from the local PCP magazine with `try_lock`
    /// on the fast path; on miss, borrows Buddy via `try_with_allocator_with`
    /// (performing non-blocking PCP and transient-cache recovery outside the
    /// buddy lock) and reports any contention as `Err(AllocError::Busy)`.
    fn try_alloc_order0_nonblocking_with<FScrub>(
        &self,
        cpu_id: usize,
        cpu_limit: usize,
        scrub: FScrub,
    ) -> Result<PhysFrame, AllocError>
    where
        FScrub: Fn(PhysFrame),
    {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(AllocError::AllocatorPoisoned);
        }
        let cpu = cpu_id % self.pcp.len();
        if let Some((base, states)) = self.page_state_view() {
            let popped = with_irqs_disabled(|| {
                let mut mag = self.pcp[cpu].lock.try_lock()?;
                if mag.len == 0 {
                    return None;
                }
                mag.len -= 1;
                let idx = mag.len;
                let phys = mag.frames[idx];
                self.pcp[cpu].cached_count.fetch_sub(1, Ordering::AcqRel);
                let prev_hits = self.pcp[cpu].hits.load(Ordering::Relaxed);
                self.pcp[cpu]
                    .hits
                    .store(prev_hits.wrapping_add(1), Ordering::Relaxed);
                Some(phys)
            });
            if let Some(phys) = popped {
                let idx = ((phys - base) / PAGE_SIZE as u64) as usize;
                match states[idx].compare_exchange(
                    PAGE_PCP_CACHED,
                    PAGE_ALLOC_ORDER0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return Ok(PhysFrame::containing_address(PhysAddr::new(phys))),
                    Err(_) => {
                        self.mark_poisoned();
                        return Err(AllocError::MetadataCorrupt);
                    }
                }
            }
        }

        let res = match self.try_with_allocator_with(cpu_limit, |alloc| alloc.try_alloc_pages(0)) {
            None => return Err(AllocError::Busy),
            Some(res) => res,
        };
        match res {
            Ok(frame) => {
                scrub(frame);
                Ok(frame)
            }
            Err(err) => {
                if matches!(
                    err,
                    AllocError::MetadataCorrupt | AllocError::AllocatorPoisoned
                ) {
                    self.mark_poisoned();
                }
                Err(err)
            }
        }
    }

    fn try_with_allocator_with<T, F>(&self, cpu_limit: usize, f: F) -> Option<T>
    where
        F: FnOnce(&mut BuddyAllocator) -> T,
    {
        let mut guard = self.buddy.try_lock()?;
        let allocator = guard.as_mut()?;
        if self.drain_pcp_into_locked_buddy(allocator, cpu_limit) {
            return None;
        }
        // If buddy is still below `PCP_REFILL_BATCH` and a transient cache
        // reclaim hook (e.g. post-shootdown kstack reuse cache) is registered,
        // drop the buddy guard first, run strictly non-blocking cache reclaim
        // outside the buddy lock, then re-try-lock buddy and repeat bounded
        // PCP recovery (closing the race where another CPU refills its PCP
        // from the reclaimed pages before we reacquire buddy).
        if allocator.free_pages < PCP_REFILL_BATCH && oom_killer::has_transient_cache_reclaim() {
            drop(guard);
            let reclaim = oom_killer::reclaim_transient_caches_nonblocking();
            if reclaim.busy {
                return None;
            }
            let mut retry_guard = self.buddy.try_lock()?;
            let retry_allocator = retry_guard.as_mut()?;
            if self.drain_pcp_into_locked_buddy(retry_allocator, cpu_limit) {
                return None;
            }
            return Some(f(retry_allocator));
        }
        Some(f(allocator))
    }
}

/// 全局 Buddy + PCP 物理页分配器实例
static GLOBAL_BUDDY: PcpBuddyPool = PcpBuddyPool::new();

/// RF178-12: borrow the physical allocator without waiting or invoking OOM
/// recovery. Intended for bounded synchronous exception work that must either
/// complete with one allocator ownership interval or fail closed. Keeping the
/// guard across the callback also makes rollback frees infallible with respect
/// to allocator-lock contention.
pub fn try_with_allocator<T, F>(f: F) -> Option<T>
where
    F: FnOnce(&mut BuddyAllocator) -> T,
{
    GLOBAL_BUDDY.try_with_allocator_with(cpu_local::max_cpus(), f)
}

/// 初始化全局Buddy分配器
///
/// # 参数
/// * `base_addr` - 物理内存起始地址
/// * `size` - 管理的内存大小
/// * `reserved` - R167-B: permanent physical reservations `(phys_start, len_bytes)`
///   to withhold from the free pool (kernel heap, kernel image, framebuffer,
///   firmware/boot-services ranges that fall inside the managed window).
pub fn init_buddy_allocator(
    base_addr: PhysAddr,
    size: usize,
    reserved: &[(u64, u64)],
) -> Result<(), BuddyInitError> {
    let allocator = BuddyAllocator::new_with_reservations(base_addr, size, reserved)?;
    publish_buddy_allocator(allocator)
}

/// GAP-6 F8: initialize the global allocator with metadata in boot-reserved
/// `storage` (see `BuddyAllocator::new_with_reservations_in`) instead of the
/// kernel heap. `storage` must lie inside a `reserved` range so the allocator
/// never hands its own metadata frames out.
pub fn init_buddy_allocator_in(
    base_addr: PhysAddr,
    size: usize,
    reserved: &[(u64, u64)],
    storage: &'static mut [u8],
) -> Result<(), BuddyInitError> {
    let allocator = BuddyAllocator::new_with_reservations_in(base_addr, size, reserved, storage)?;
    publish_buddy_allocator(allocator)
}

fn publish_buddy_allocator(allocator: BuddyAllocator) -> Result<(), BuddyInitError> {
    // Snapshot stats before the allocator is moved under the lock.
    #[cfg(debug_assertions)]
    let base_addr = allocator.base_addr;
    let size = allocator.total_pages * PAGE_SIZE;
    let total_pages = allocator.total_pages;
    let reserved_pages = allocator.reserved_pages;
    let free_pages = allocator.free_pages;
    GLOBAL_BUDDY.publish(allocator);

    klog_always!("Buddy allocator initialized:");
    // R132-3 FIX: Use kprintln! (debug-only) to avoid leaking physical memory base
    // address in release builds. Same kptr-safety policy as R130-5 and R131-8.
    kprintln!("  Base address: 0x{:x}", base_addr);
    klog_always!("  Size: {} MB", size / (1024 * 1024));
    klog_always!("  Total pages: {}", total_pages);
    // R167-B: surface the reservation accounting so a misconfigured reservation
    // (e.g. the whole region withheld) is visible in the boot log.
    klog_always!("  Reserved pages: {}", reserved_pages);
    klog_always!("  Free pages: {}", free_pages);
    Ok(())
}

/// 分配物理页面
///
/// # Arguments
/// * `count` - 需要分配的页面数量（必须 > 0）
///
/// # Returns
/// 成功返回物理帧，失败返回 None
///
/// # OOM Handling
/// 如果分配失败，会先排空各核 PCP 缓存，若仍不足再触发 OOM killer 尝试回收内存并重试一次
pub fn alloc_physical_pages(count: usize) -> Option<PhysFrame> {
    match try_alloc_physical_pages(count) {
        Ok(frame) => Some(frame),
        Err(AllocError::MetadataCorrupt | AllocError::AllocatorPoisoned) => {
            panic!("physical allocator metadata is corrupt/poisoned")
        }
        Err(_) => None,
    }
}

/// Allocate up to `out.len()` pre-zeroed order-0 physical frames in batched
/// PCP and buddy holds, returning how many slots in `out` were filled.
pub fn alloc_physical_pages_batch(out: &mut [PhysFrame]) -> usize {
    match GLOBAL_BUDDY.try_alloc_order0_batch_with(
        out,
        current_pcp_cpu_id(),
        cpu_local::max_cpus(),
        scrub_frame_phys,
        true,
    ) {
        Ok(count) => count,
        Err(AllocError::MetadataCorrupt | AllocError::AllocatorPoisoned) => {
            panic!("physical allocator metadata is corrupt/poisoned")
        }
        Err(_) => 0,
    }
}

/// Free a batch of order-0 physical frames, scrubbing each frame (Invariant S2)
/// and returning them through this CPU's PCP magazine in batched lock holds.
pub fn free_physical_pages_batch(frames: &[PhysFrame]) {
    GLOBAL_BUDDY.free_order0_batch_with(
        frames,
        current_pcp_cpu_id(),
        read_production_cow_refcount,
        scrub_frame_phys,
    );
}

/// Fallible physical allocation with error classification. OOM recovery runs
/// only for genuine free-space exhaustion (after draining all CPUs' PCP caches);
/// invalid orders and poisoned metadata never masquerade as memory pressure.
pub fn try_alloc_physical_pages(count: usize) -> Result<PhysFrame, AllocError> {
    if count == 0 {
        return Err(AllocError::InvalidOrder);
    }
    let pages_needed = count
        .checked_next_power_of_two()
        .ok_or(AllocError::InvalidOrder)?;
    let order = pages_needed.trailing_zeros() as usize;
    if order >= ORDER_COUNT {
        return Err(AllocError::InvalidOrder);
    }

    if order == 0 {
        return GLOBAL_BUDDY.try_alloc_order0_with(
            current_pcp_cpu_id(),
            cpu_local::max_cpus(),
            scrub_frame_phys,
            true,
        );
    }

    GLOBAL_BUDDY.try_alloc_multi_with(order, pages_needed, cpu_local::max_cpus(), true)
}

/// Strictly non-blocking order-0 allocation for exception paths (such as CoW
/// `#PF`). Never spins on PCP, buddy, or transient-cache locks and propagates
/// contention as `Err(AllocError::Busy)` so fault handlers can retry via `IRETQ`.
pub fn try_alloc_order0_nonblocking() -> Result<PhysFrame, AllocError> {
    GLOBAL_BUDDY.try_alloc_order0_nonblocking_with(
        current_pcp_cpu_id(),
        cpu_local::max_cpus(),
        scrub_frame_phys,
    )
}

/// Checked counterpart to `free_physical_pages`.
///
/// Validates exact buddy-relative base, allocation order, `PAGE_REF_COUNT == 0`,
/// and allocation state of every page. Order-0 frames are scrubbed and cached in
/// the local CPU's PCP magazine without touching the global buddy lock.
pub fn try_free_physical_pages(frame: PhysFrame, count: usize) -> Result<(), FreeError> {
    if count == 0 {
        return Err(FreeError::InvalidCount);
    }
    let pages = count
        .checked_next_power_of_two()
        .ok_or(FreeError::InvalidCount)?;
    if pages != count {
        return Err(FreeError::InvalidCount);
    }
    let order = pages.trailing_zeros() as usize;
    if order == 0 {
        return GLOBAL_BUDDY.try_free_order0_with(
            frame,
            current_pcp_cpu_id(),
            read_production_cow_refcount,
            scrub_frame_phys,
        );
    }
    GLOBAL_BUDDY.try_free_multi_with(frame, order, read_production_cow_refcount)
}

/// Strictly non-blocking checked deallocation for interrupt-masked or
/// fault-path transient-cache reclaim. Returns `Err(FreeError::Busy)` without
/// spinning whenever the global buddy lock is contended.
pub fn try_free_physical_pages_nonblocking(
    frame: PhysFrame,
    count: usize,
) -> Result<(), FreeError> {
    if count == 0 {
        return Err(FreeError::InvalidCount);
    }
    let pages = count
        .checked_next_power_of_two()
        .ok_or(FreeError::InvalidCount)?;
    if pages != count {
        return Err(FreeError::InvalidCount);
    }
    let order = pages.trailing_zeros() as usize;
    GLOBAL_BUDDY.try_free_multi_nonblocking_with(frame, order, read_production_cow_refcount)
}

pub fn free_physical_pages(frame: PhysFrame, count: usize) {
    // R100-4 FIX: count=0 must be a no-op; 0.next_power_of_two() == 1
    // which would silently free 1 page.
    if count == 0 {
        return;
    }

    // Use checked variant to avoid panic on overflow in debug builds
    let pages = match count.checked_next_power_of_two() {
        Some(p) => p,
        None => return, // count too large to represent as power-of-two order
    };
    let order = pages.trailing_zeros() as usize;

    let result = if order == 0 {
        GLOBAL_BUDDY.try_free_order0_with(
            frame,
            current_pcp_cpu_id(),
            read_production_cow_refcount,
            scrub_frame_phys,
        )
    } else {
        GLOBAL_BUDDY.try_free_multi_with(frame, order, read_production_cow_refcount)
    };

    if let Err(_error) = result {
        kprintln!(
            "[buddy] rejected free_physical_pages: {:?}{}",
            _error,
            if _error.is_metadata_corruption() {
                "; allocator quarantined"
            } else {
                "; allocator remains available"
            }
        );
    }
}

/// Synchronously drain every CPU's PCP cache back to the global buddy allocator.
pub fn drain_all_pcp_caches() -> usize {
    GLOBAL_BUDDY.drain_all_pcp(cpu_local::max_cpus())
}

/// Snapshot Per-CPU Page Cache statistics.
pub fn pcp_stats() -> PcpStats {
    GLOBAL_BUDDY.pcp_stats()
}

/// 获取分配器统计信息
pub fn get_allocator_stats() -> Option<AllocatorStats> {
    GLOBAL_BUDDY.stats()
}

// 测试代码已移除（no_std环境不支持标准测试框架）
// 可以在内核初始化时运行自测函数

/// 运行Buddy分配器自测
pub fn run_self_test() {
    kprintln!("Running Buddy allocator self-test...");

    let base = PhysAddr::new(0x10000000); // 256MB处
    let size = 16 * 1024 * 1024; // 16MB测试区域
    let mut allocator =
        BuddyAllocator::new(base, size).expect("Test setup failed: buddy metadata allocation");

    // 测试1: 基础分配
    let frame1 = allocator
        .alloc_pages(0)
        .expect("Test 1 failed: Cannot allocate 1 page");
    assert!(
        frame1.start_address() == base,
        "Test 1 failed: Wrong address"
    );
    kprintln!("  Test 1 passed: Basic allocation");

    // 测试2: 分配和释放
    let initial_free = allocator.free_pages;
    let frame2 = allocator
        .alloc_pages(3)
        .expect("Test 2 failed: Cannot allocate 8 pages");
    assert!(
        allocator.free_pages == initial_free - 8,
        "Test 2 failed: Wrong free count"
    );
    allocator.free_pages(frame2, 3);
    assert!(
        allocator.free_pages == initial_free,
        "Test 2 failed: Free count not restored"
    );
    kprintln!("  Test 2 passed: Allocation and free");

    // 测试3: Buddy合并
    let frame3 = allocator.alloc_pages(0).unwrap();
    let frame4 = allocator.alloc_pages(0).unwrap();
    allocator.free_pages(frame3, 0);
    allocator.free_pages(frame4, 0);
    let frame5 = allocator.alloc_pages(1); // 应该能分配大小为2的块
    assert!(frame5.is_some(), "Test 3 failed: Buddy merge failed");
    kprintln!("  Test 3 passed: Buddy merge");

    kprintln!("All Buddy allocator tests passed!");
}

/// R167-B: Self-test for reservation-aware construction.
///
/// Builds an allocator over a 1 MiB region with a 256 KiB reserved hole in the
/// middle, then drains every allocatable single page. Verifies, order-
/// independently (no assumption about which block is handed out first):
///   1. `reserved_pages` and `free_pages` accounting is exact;
///   2. no allocated frame ever falls inside the reserved hole;
///   3. the number of allocatable pages equals `total - reserved`.
/// This proves reserved frames are never placed in a free list nor split out of
/// a larger block.
pub fn run_reservation_self_test() {
    kprintln!("Running Buddy reservation self-test...");

    let base_u64: u64 = 0x2000_0000; // 512 MiB, distinct from run_self_test's region
    let base = PhysAddr::new(base_u64);
    let size = 1024 * 1024; // 1 MiB = 256 pages
    let total_pages = size / PAGE_SIZE;

    // Reserve pages [64, 128) of the region: a 256 KiB hole in the middle.
    let resv_pages = 64usize;
    let resv_phys = base_u64 + (64 * PAGE_SIZE) as u64;
    let resv_len = (resv_pages * PAGE_SIZE) as u64;

    let mut allocator = BuddyAllocator::new_with_reservations(base, size, &[(resv_phys, resv_len)])
        .expect("Reservation test setup failed: buddy metadata allocation");

    assert!(
        allocator.reserved_pages == resv_pages,
        "Reservation test failed: wrong reserved_pages count"
    );
    assert!(
        allocator.free_pages == total_pages - resv_pages,
        "Reservation test failed: wrong free_pages count"
    );

    // Drain all single-page allocations; none may land in the reserved hole.
    let resv_lo = resv_phys;
    let resv_hi = resv_phys + resv_len;
    let region_hi = base_u64 + size as u64;
    let mut allocated = 0usize;
    while let Some(frame) = allocator.alloc_pages(0) {
        let a = frame.start_address().as_u64();
        assert!(
            a < resv_lo || a >= resv_hi,
            "Reservation test failed: allocated a reserved frame"
        );
        assert!(
            a >= base_u64 && a < region_hi,
            "Reservation test failed: allocated frame outside region"
        );
        allocated += 1;
        assert!(
            allocated <= total_pages,
            "Reservation test failed: allocator overran region"
        );
    }
    assert!(
        allocated == total_pages - resv_pages,
        "Reservation test failed: allocatable count != total - reserved"
    );

    kprintln!(
        "  Reservation self-test passed: {} pages allocatable, {} reserved",
        allocated,
        resv_pages
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn metadata_shape(
        allocator: &BuddyAllocator,
    ) -> (*const AtomicU8, usize, usize, *const u64, usize, usize) {
        (
            allocator.page_state.as_ptr(),
            allocator.page_state.len(),
            allocator.page_state.capacity(),
            allocator.free_map.words.as_ptr(),
            allocator.free_map.words.len(),
            allocator.free_map.words.capacity(),
        )
    }

    #[test]
    fn fixed_metadata_does_not_grow_during_split_and_merge() {
        let base = PhysAddr::new(0x3000_0000);
        let mut allocator = BuddyAllocator::new(base, 16 * 1024 * 1024).expect("construct");
        let shape = metadata_shape(&allocator);
        let initial_free = allocator.free_pages;

        let mut frames = Vec::new();
        frames.try_reserve_exact(1024).expect("test frame ledger");
        for _ in 0..1024 {
            frames.push(allocator.try_alloc_pages(0).expect("order-0 split"));
        }
        for frame in frames.into_iter().rev() {
            allocator.try_free_pages(frame, 0).expect("order-0 merge");
        }

        assert_eq!(allocator.free_pages, initial_free);
        assert_eq!(metadata_shape(&allocator), shape);
        assert_eq!(allocator.validate_metadata(), Ok(()));
    }

    /// Leak `bytes` of 8-byte-aligned storage pre-filled with `fill`, standing
    /// in for boot-reserved frames reached through the direct map.
    fn leaked_storage(bytes: usize, fill: u64) -> &'static mut [u8] {
        let words = bytes.div_ceil(8);
        let mut backing = Vec::new();
        backing.try_reserve_exact(words).expect("test storage");
        backing.resize(words, fill);
        let backing: &'static mut [u64] = backing.leak();
        // SAFETY: the leaked words are exclusively owned for 'static and every
        // byte of a u64 is a valid u8.
        unsafe { core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), words * 8) }
    }

    #[test]
    fn f8_boot_storage_matches_heap_allocator_and_overwrites_storage() {
        let base = PhysAddr::new(0x3800_0000);
        let size = 16 * 1024 * 1024;
        let reserved = [(0x3800_0000 + 0x10_0000, 0x3000u64)];
        let bytes = BuddyAllocator::metadata_bytes(size).expect("metadata size");
        // 4096 pages of state plus the order bitmaps.
        assert!(bytes >= size / PAGE_SIZE);

        // Garbage-filled storage must be fully reinitialized, not trusted.
        let storage = leaked_storage(bytes, u64::MAX);
        let mut boot = BuddyAllocator::new_with_reservations_in(base, size, &reserved, storage)
            .expect("boot-storage allocator");
        let mut heap =
            BuddyAllocator::new_with_reservations(base, size, &reserved).expect("heap allocator");
        assert!(matches!(boot.page_state, PageStateStore::Boot(_)));
        assert!(matches!(boot.free_map.words, MetadataStore::Boot(_)));
        assert_eq!(boot.page_state, heap.page_state);
        assert_eq!(boot.free_map.words, heap.free_map.words);
        assert_eq!(boot.free_pages, heap.free_pages);
        assert_eq!(boot.reserved_pages, heap.reserved_pages);

        let mut frames = Vec::new();
        frames.try_reserve_exact(32).expect("test frame ledger");
        for order in [0usize, 3, 10, 0, 5, 1] {
            let frame = boot.try_alloc_pages(order).expect("boot alloc");
            assert_eq!(heap.try_alloc_pages(order), Ok(frame));
            frames.push((frame, order));
        }
        for (frame, order) in frames.into_iter().rev() {
            assert_eq!(boot.try_free_pages(frame, order), Ok(()));
            assert_eq!(heap.try_free_pages(frame, order), Ok(()));
        }
        assert_eq!(boot.page_state, heap.page_state);
        assert_eq!(boot.free_map.words, heap.free_map.words);
        assert_eq!(boot.validate_metadata(), Ok(()));
    }

    #[test]
    fn f8_boot_storage_rejects_short_or_misaligned_storage() {
        let base = PhysAddr::new(0x3c00_0000);
        let size = 2 * 1024 * 1024;
        let bytes = BuddyAllocator::metadata_bytes(size).expect("metadata size");

        let short = leaked_storage(bytes, 0);
        let short = short.split_at_mut(bytes - 1).0;
        assert_eq!(
            BuddyAllocator::new_with_reservations_in(base, size, &[], short).err(),
            Some(BuddyInitError::MetadataAllocationFailed)
        );

        // Shift the start by one byte: the state bytes are still long enough,
        // but the bitmap words would be misaligned.
        let shifted = leaked_storage(bytes + 8, 0).split_at_mut(1).1;
        assert_eq!(
            BuddyAllocator::new_with_reservations_in(base, size, &[], shifted).err(),
            Some(BuddyInitError::RegionMisaligned)
        );
    }

    #[test]
    fn rejected_frees_leave_metadata_byte_exact() {
        let base = PhysAddr::new(0x3400_0000);
        let mut allocator = BuddyAllocator::new(base, 2 * 1024 * 1024).expect("construct");
        let frame = allocator.try_alloc_pages(2).expect("allocate order 2");

        let words = allocator.free_map.words.clone();
        let states = allocator.page_state.snapshot_bytes();
        let counts = allocator.free_map.block_count;
        let cursors = allocator.free_map.search_cursor;
        let free_pages = allocator.free_pages;
        assert_eq!(
            allocator.try_free_pages(frame, 1),
            Err(FreeError::OrderMismatch)
        );
        assert_eq!(allocator.free_map.words, words);
        assert_eq!(allocator.page_state.snapshot_bytes(), states);
        assert_eq!(allocator.free_map.block_count, counts);
        assert_eq!(allocator.free_map.search_cursor, cursors);
        assert_eq!(allocator.free_pages, free_pages);
        assert!(!allocator.poisoned);

        let interior = PhysFrame::from_start_address(frame.start_address() + PAGE_SIZE as u64)
            .expect("aligned interior frame");
        assert_eq!(
            allocator.try_free_pages(interior, 2),
            Err(FreeError::AddressMisaligned)
        );
        assert_eq!(allocator.free_map.words, words);
        assert_eq!(allocator.page_state.snapshot_bytes(), states);
        assert_eq!(allocator.free_pages, free_pages);

        allocator.try_free_pages(frame, 2).expect("valid free");
        let words = allocator.free_map.words.clone();
        let states = allocator.page_state.snapshot_bytes();
        let counts = allocator.free_map.block_count;
        let free_pages = allocator.free_pages;
        assert_eq!(
            allocator.try_free_pages(frame, 2),
            Err(FreeError::NotAllocationStart)
        );
        assert_eq!(allocator.free_map.words, words);
        assert_eq!(allocator.page_state.snapshot_bytes(), states);
        assert_eq!(allocator.free_map.block_count, counts);
        assert_eq!(allocator.free_pages, free_pages);
        assert!(!allocator.poisoned);
    }

    #[test]
    fn overlapping_free_metadata_poison_is_fail_closed() {
        let base = PhysAddr::new(0x3800_0000);
        let mut allocator = BuddyAllocator::new(base, 2 * 1024 * 1024).expect("construct");
        let frame = allocator.try_alloc_pages(0).expect("allocate");
        let block_idx = ((frame.start_address() - base) / PAGE_SIZE as u64) as usize;
        let injected = allocator
            .free_map
            .location(0, block_idx)
            .expect("in-range free bit");
        assert!(!allocator.free_map.is_set(injected));
        allocator.free_map.commit_set(injected, true);

        let words = allocator.free_map.words.clone();
        let states = allocator.page_state.snapshot_bytes();
        let free_pages = allocator.free_pages;
        assert_eq!(
            allocator.try_free_pages(frame, 0),
            Err(FreeError::MetadataCorrupt)
        );
        assert!(allocator.poisoned);
        assert_eq!(allocator.free_map.words, words);
        assert_eq!(allocator.page_state.snapshot_bytes(), states);
        assert_eq!(allocator.free_pages, free_pages);
        assert_eq!(
            allocator.try_alloc_pages(0),
            Err(AllocError::AllocatorPoisoned)
        );
    }

    #[test]
    fn constructor_handles_holes_and_rejects_truncated_regions() {
        let base = PhysAddr::new(0x3c00_0000);
        assert_eq!(
            BuddyAllocator::new(base, PAGE_SIZE - 1).err(),
            Some(BuddyInitError::RegionMisaligned)
        );

        let size = 13 * PAGE_SIZE;
        let reservations = [
            (base.as_u64() + PAGE_SIZE as u64 / 2, PAGE_SIZE as u64),
            (base.as_u64() + 11 * PAGE_SIZE as u64, 4 * PAGE_SIZE as u64),
        ];
        let allocator =
            BuddyAllocator::new_with_reservations(base, size, &reservations).expect("holes");
        assert_eq!(allocator.reserved_pages, 4);
        assert_eq!(allocator.free_pages, 9);
        assert_eq!(allocator.validate_metadata(), Ok(()));
    }

    fn make_test_pool(base: u64, size: usize, reserved: &[(u64, u64)]) -> PcpBuddyPool {
        let pool = PcpBuddyPool::new();
        let allocator = BuddyAllocator::new_with_reservations(PhysAddr::new(base), size, reserved)
            .expect("test buddy pool");
        pool.publish(allocator);
        pool
    }

    #[test]
    fn pcp_hit_and_lifo_reuse_without_buddy_drift() {
        let pool = make_test_pool(0x4000_0000, 4 * 1024 * 1024, &[]);
        let initial_free = pool.stats().unwrap().free_pages;

        let f1 = pool
            .try_alloc_order0_with(0, 4, |_| {}, false)
            .expect("first order-0 alloc refills PCP");
        assert_eq!(pool.stats().unwrap().free_pages, initial_free - 1);
        assert_eq!(pool.pcp_stats().refills, 1);

        pool.try_free_order0_with(f1, 0, |_| 0, |_| {})
            .expect("free into PCP");
        assert_eq!(pool.stats().unwrap().free_pages, initial_free);

        let f2 = pool
            .try_alloc_order0_with(0, 4, |_| {}, false)
            .expect("LIFO PCP hit");
        assert_eq!(f2, f1, "PCP must LIFO-reuse the most recently freed frame");
        assert_eq!(pool.pcp_stats().hits, 1);
        assert_eq!(pool.stats().unwrap().free_pages, initial_free - 1);

        pool.try_free_order0_with(f2, 0, |_| 0, |_| {})
            .expect("final free");
        assert_eq!(pool.stats().unwrap().free_pages, initial_free);
        pool.drain_all_pcp(4);
        assert_eq!(pool.pcp_stats().cached_pages, 0);
        assert_eq!(pool.stats().unwrap().free_pages, initial_free);
        assert_eq!(
            pool.buddy.lock().as_ref().unwrap().validate_metadata(),
            Ok(())
        );
    }

    #[test]
    fn pcp_scrub_before_reuse_on_refill_and_free() {
        let pool = make_test_pool(0x4100_0000, 2 * 1024 * 1024, &[]);
        let scrubs = AtomicUsize::new(0);

        // Cold miss refills PCP_REFILL_BATCH (16) pages -> all 16 scrubbed.
        let f1 = pool
            .try_alloc_order0_with(
                0,
                4,
                |_| {
                    scrubs.fetch_add(1, Ordering::Relaxed);
                },
                false,
            )
            .expect("cold alloc");
        assert_eq!(scrubs.load(Ordering::Relaxed), PCP_REFILL_BATCH);

        // Freeing f1 scrubs before pushing into PCP (+1).
        pool.try_free_order0_with(
            f1,
            0,
            |_| 0,
            |_| {
                scrubs.fetch_add(1, Ordering::Relaxed);
            },
        )
        .expect("free scrubs");
        assert_eq!(scrubs.load(Ordering::Relaxed), PCP_REFILL_BATCH + 1);

        // Popping f1 from PCP reuses the already-scrubbed frame (0 extra scrubs).
        let f2 = pool
            .try_alloc_order0_with(
                0,
                4,
                |_| {
                    scrubs.fetch_add(1, Ordering::Relaxed);
                },
                false,
            )
            .expect("hot hit");
        assert_eq!(f2, f1);
        assert_eq!(scrubs.load(Ordering::Relaxed), PCP_REFILL_BATCH + 1);

        // Return f2 to PCP (+1 scrub), drain all 16 zeroed frames back to buddy
        // (`PAGE_FREE_ZEROED`), then refill again: zero extra scrubs because
        // buddy remembers every drained PCP frame is already zeroed.
        pool.try_free_order0_with(
            f2,
            0,
            |_| 0,
            |_| {
                scrubs.fetch_add(1, Ordering::Relaxed);
            },
        )
        .expect("free f2");
        assert_eq!(scrubs.load(Ordering::Relaxed), PCP_REFILL_BATCH + 2);
        assert_eq!(pool.drain_all_pcp(4), PCP_REFILL_BATCH);
        let f3 = pool
            .try_alloc_order0_with(
                0,
                4,
                |_| {
                    scrubs.fetch_add(1, Ordering::Relaxed);
                },
                false,
            )
            .expect("refill of already-zeroed buddy frames");
        assert_eq!(
            scrubs.load(Ordering::Relaxed),
            PCP_REFILL_BATCH + 2,
            "drained PCP frames marked PAGE_FREE_ZEROED must not be double-scrubbed on refill"
        );
        pool.try_free_order0_with(f3, 0, |_| 0, |_| {})
            .expect("cleanup f3");
        pool.drain_all_pcp(4);

        // Allocate and free an order-1 block directly via buddy (marks both
        // frames dirty `PAGE_FREE`); subsequent order-0 refill MUST scrub those
        // dirty frames again.
        let dirty_block = pool
            .try_alloc_multi_with(1, 2, 4, false)
            .expect("order-1 alloc");
        pool.try_free_multi_with(dirty_block, 1, |_| 0)
            .expect("order-1 dirty free");
        let dirty_scrubs = AtomicUsize::new(0);
        let _ = pool
            .try_alloc_order0_with(
                0,
                4,
                |_| {
                    dirty_scrubs.fetch_add(1, Ordering::Relaxed);
                },
                false,
            )
            .expect("refill after dirty multi-order free");
        assert!(
            dirty_scrubs.load(Ordering::Relaxed) >= 2,
            "unscrubbed higher-order buddy frames must be scrubbed on order-0 refill"
        );
    }

    #[test]
    fn pcp_rejects_partial_free_of_higher_order_block() {
        let pool = make_test_pool(0x4200_0000, 2 * 1024 * 1024, &[]);
        let frame = pool
            .try_alloc_multi_with(3, 8, 4, false)
            .expect("order-3 alloc");
        let free_after_alloc = pool.stats().unwrap().free_pages;

        // Attempting order-0 PCP free on an order-3 block must fail closed with
        // OrderMismatch without poisoning the allocator or altering free_pages.
        assert_eq!(
            pool.try_free_order0_with(frame, 0, |_| 0, |_| {}),
            Err(FreeError::OrderMismatch)
        );
        assert_eq!(pool.stats().unwrap().free_pages, free_after_alloc);
        assert_eq!(pool.pcp_stats().cached_pages, 0);
        assert!(!pool.poisoned.load(Ordering::Acquire));

        // Tail page of the order-3 block must also be rejected.
        let tail = PhysFrame::containing_address(frame.start_address() + PAGE_SIZE as u64);
        assert_eq!(
            pool.try_free_order0_with(tail, 0, |_| 0, |_| {}),
            Err(FreeError::NotAllocationStart)
        );
        assert_eq!(pool.stats().unwrap().free_pages, free_after_alloc);

        // Proper order-3 free succeeds.
        assert_eq!(pool.try_free_multi_with(frame, 3, |_| 0), Ok(()));
    }

    #[test]
    fn pcp_rejects_double_free_and_reserved_frame() {
        let reserved_phys = 0x4300_0000 + 4 * PAGE_SIZE as u64;
        let pool = make_test_pool(
            0x4300_0000,
            2 * 1024 * 1024,
            &[(reserved_phys, PAGE_SIZE as u64)],
        );
        let initial_free = pool.stats().unwrap().free_pages;

        let reserved_frame = PhysFrame::containing_address(PhysAddr::new(reserved_phys));
        assert_eq!(
            pool.try_free_order0_with(reserved_frame, 0, |_| 0, |_| {}),
            Err(FreeError::ReservedPage)
        );
        assert_eq!(pool.stats().unwrap().free_pages, initial_free);

        let f = pool
            .try_alloc_order0_with(0, 4, |_| {}, false)
            .expect("alloc");
        assert_eq!(pool.try_free_order0_with(f, 0, |_| 0, |_| {}), Ok(()));
        let free_after_first = pool.stats().unwrap().free_pages;
        assert_eq!(free_after_first, initial_free);

        // Second free hits PAGE_PCP_CACHED -> rejected cleanly.
        assert_eq!(
            pool.try_free_order0_with(f, 0, |_| 0, |_| {}),
            Err(FreeError::NotAllocationStart)
        );
        assert_eq!(pool.stats().unwrap().free_pages, initial_free);
        assert!(!pool.poisoned.load(Ordering::Acquire));
    }

    #[test]
    fn pcp_rejects_frame_with_nonzero_cow_refcount() {
        let pool = make_test_pool(0x4400_0000, 2 * 1024 * 1024, &[]);
        let f = pool
            .try_alloc_order0_with(0, 4, |_| {}, false)
            .expect("alloc");
        let free_after_alloc = pool.stats().unwrap().free_pages;

        // Simulate active COW/shared mapping reference (refcount = 2).
        assert_eq!(
            pool.try_free_order0_with(f, 0, |_| 2, |_| {}),
            Err(FreeError::PageStillReferenced)
        );
        assert_eq!(pool.pcp_stats().refcount_rejections, 1);
        assert_eq!(pool.stats().unwrap().free_pages, free_after_alloc);

        // Once refcount drops to 0, reclamation succeeds.
        assert_eq!(pool.try_free_order0_with(f, 0, |_| 0, |_| {}), Ok(()));
        assert_eq!(pool.stats().unwrap().free_pages, free_after_alloc + 1);
    }

    #[test]
    fn pcp_overflow_drains_batch_and_coalesces() {
        let pool = make_test_pool(0x4500_0000, 4 * 1024 * 1024, &[]);
        let initial_free = pool.stats().unwrap().free_pages;
        let total = PCP_HIGH_WATERMARK + 16;

        let mut frames = Vec::new();
        for _ in 0..total {
            frames.push(
                pool.try_alloc_order0_with(0, 4, |_| {}, false)
                    .expect("alloc"),
            );
        }
        assert_eq!(pool.stats().unwrap().free_pages, initial_free - total);

        for frame in frames {
            pool.try_free_order0_with(frame, 0, |_| 0, |_| {})
                .expect("free");
        }
        assert_eq!(pool.stats().unwrap().free_pages, initial_free);
        assert!(
            pool.pcp_stats().drains >= 1,
            "overflowing PCP_HIGH_WATERMARK must trigger batch drain to buddy"
        );
        assert!(pool.pcp_stats().cached_pages <= PCP_HIGH_WATERMARK);

        pool.drain_all_pcp(4);
        assert_eq!(pool.pcp_stats().cached_pages, 0);
        assert_eq!(pool.stats().unwrap().free_pages, initial_free);
        assert_eq!(
            pool.buddy.lock().as_ref().unwrap().validate_metadata(),
            Ok(())
        );
    }

    #[test]
    fn pcp_cross_cpu_drain_prevents_false_exhaustion() {
        // Tiny 16-page (64 KiB) buddy window: CPU 1 caches all 15 remaining
        // pages during refill + free, leaving buddy with 0 free pages.
        let pool = make_test_pool(0x4600_0000, 16 * PAGE_SIZE, &[]);
        let f = pool
            .try_alloc_order0_with(1, 4, |_| {}, false)
            .expect("cpu 1 refill");
        pool.try_free_order0_with(f, 1, |_| 0, |_| {})
            .expect("cpu 1 free back to PCP");
        assert_eq!(pool.pcp_stats().cached_pages, 16);
        assert_eq!(pool.buddy.lock().as_ref().unwrap().free_pages, 0);

        // CPU 0 requests an order-2 (4 contiguous pages) block: must drain
        // CPU 1's PCP, coalesce in buddy, and succeed instead of Exhausted.
        let block = pool
            .try_alloc_multi_with(2, 4, 4, false)
            .expect("cross-CPU PCP drain must satisfy higher-order alloc");
        assert_eq!(pool.pcp_stats().cross_cpu_drains, 1);
        assert_eq!(pool.stats().unwrap().free_pages, 12);

        assert_eq!(pool.try_free_multi_with(block, 2, |_| 0), Ok(()));
        assert_eq!(pool.stats().unwrap().free_pages, 16);
        assert_eq!(
            pool.buddy.lock().as_ref().unwrap().validate_metadata(),
            Ok(())
        );
    }

    #[cfg(feature = "host_harness")]
    #[test]
    fn pcp_multithread_concurrent_alloc_free_stress() {
        use std::sync::Arc;
        use std::thread;

        let pool = Arc::new(make_test_pool(0x4700_0000, 16 * 1024 * 1024, &[]));
        let initial_free = pool.stats().unwrap().free_pages;
        let threads = 8usize;
        let iters = 1_500usize;

        let mut handles = Vec::new();
        for tid in 0..threads {
            let p = Arc::clone(&pool);
            handles.push(thread::spawn(move || {
                let mut held = [None; 8];
                for iter in 0..iters {
                    let slot = iter & 7;
                    if let Some(old) = held[slot].take() {
                        p.try_free_order0_with(old, tid, |_| 0, |_| {})
                            .expect("concurrent order-0 free");
                    }
                    let f = p
                        .try_alloc_order0_with(tid, threads, |_| {}, false)
                        .expect("concurrent order-0 alloc");
                    held[slot] = Some(f);

                    if iter % 64 == 0 {
                        if let Ok(multi) = p.try_alloc_multi_with(2, 4, threads, false) {
                            p.try_free_multi_with(multi, 2, |_| 0)
                                .expect("concurrent order-2 free");
                        }
                    }
                }
                for frame in held.into_iter().flatten() {
                    p.try_free_order0_with(frame, tid, |_| 0, |_| {})
                        .expect("final thread free");
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread panicked");
        }

        assert_eq!(pool.stats().unwrap().free_pages, initial_free);
        pool.drain_all_pcp(threads);
        assert_eq!(pool.pcp_stats().cached_pages, 0);
        assert_eq!(pool.stats().unwrap().free_pages, initial_free);
        assert!(pool.pcp_stats().hits > 0, "concurrent stress must hit PCP");
        assert_eq!(
            pool.buddy.lock().as_ref().unwrap().validate_metadata(),
            Ok(())
        );
    }

    /// Issue #109 rollup audit (ASTRA-3): `try_with_allocator` must recover
    /// order-0 frames cached in PCP magazines when buddy is empty, and fail
    /// closed (`None` / Busy) if the magazine holding the only free frames is
    /// contended instead of returning spurious OOM.
    #[test]
    fn try_with_allocator_recovers_pcp_frames_when_buddy_empty() {
        let pool = make_test_pool(0x4800_0000, 16 * PAGE_SIZE, &[]);
        let f = pool
            .try_alloc_order0_with(1, 4, |_| {}, false)
            .expect("cpu 1 refill");
        pool.try_free_order0_with(f, 1, |_| 0, |_| {})
            .expect("cpu 1 free back to PCP");
        assert_eq!(pool.pcp_stats().cached_pages, 16);
        assert_eq!(pool.buddy.lock().as_ref().unwrap().free_pages, 0);

        // When CPU 1's PCP magazine is contended and buddy is empty, must fail
        // closed with `None` (Busy/EAGAIN) rather than spurious `Some(None)` OOM.
        {
            let _held = pool.pcp[1].lock.lock();
            assert!(pool
                .try_with_allocator_with(4, |buddy| buddy.alloc_pages(0))
                .is_none());
        }

        // Once uncontended, `try_with_allocator_with` drains PCP and allocates.
        let frame = pool
            .try_with_allocator_with(4, |buddy| buddy.alloc_pages(0))
            .expect("try_with_allocator must succeed")
            .expect("fault allocator must recover cached PCP frame");
        assert_eq!(pool.pcp_stats().cached_pages, 0);
        assert_eq!(pool.stats().unwrap().free_pages, 15);
        pool.buddy.lock().as_mut().unwrap().free_pages(frame, 0);
        assert_eq!(pool.stats().unwrap().free_pages, 16);

        // Simulate in-flight `drain_all_pcp` (magazine already emptied, `cached_count > 0`
        // awaiting buddy lock) while buddy has 0 free pages: must return retryable `None`.
        let mut drained_frames = [PhysFrame::containing_address(PhysAddr::new(0)); 16];
        {
            let mut b = pool.buddy.lock();
            for slot in &mut drained_frames {
                *slot = b.as_mut().unwrap().alloc_pages(0).expect("drain buddy");
            }
            assert_eq!(b.as_ref().unwrap().free_pages, 0);
        }
        pool.pcp[1].cached_count.store(1, Ordering::Release);
        assert!(
            pool.try_with_allocator_with(4, |buddy| buddy.alloc_pages(0))
                .is_none(),
            "in-flight PCP frames must fail closed with Busy (None) instead of spurious OOM"
        );
        pool.pcp[1].cached_count.store(0, Ordering::Release);
        {
            let mut b = pool.buddy.lock();
            for frame in drained_frames {
                b.as_mut().unwrap().free_pages(frame, 0);
            }
        }
        assert_eq!(
            pool.buddy.lock().as_ref().unwrap().validate_metadata(),
            Ok(())
        );
    }

    #[test]
    fn pcp_batch_alloc_and_free_preserves_zeroing_and_conservation() {
        let pool = make_test_pool(0x5000_0000, 128 * PAGE_SIZE, &[]);
        let initial_free = pool.stats().unwrap().free_pages;
        assert_eq!(initial_free, 128);

        let mut frames = [PhysFrame::containing_address(PhysAddr::new(0)); 80];
        let scrubbed = AtomicUsize::new(0);
        let got = pool
            .try_alloc_order0_batch_with(
                &mut frames,
                0,
                4,
                |_| {
                    scrubbed.fetch_add(1, Ordering::Relaxed);
                },
                false,
            )
            .expect("batch alloc 80 frames");
        assert_eq!(got, 80);
        assert_eq!(scrubbed.load(Ordering::Relaxed), 80);
        assert_eq!(pool.stats().unwrap().free_pages, initial_free - 80);

        // Batch-free all 80 frames: 64 enter PCP, 16 overflow directly to buddy
        // as PAGE_FREE_ZEROED. Keep one frame referenced to verify Invariant S1.
        let ref_frame = frames[10];
        let ref_idx =
            ((ref_frame.start_address().as_u64() - 0x5000_0000) / PAGE_SIZE as u64) as usize;
        let free_scrubs = AtomicUsize::new(0);
        pool.free_order0_batch_with(
            &frames,
            0,
            |idx| if idx == ref_idx { 1 } else { 0 },
            |_| {
                free_scrubs.fetch_add(1, Ordering::Relaxed);
            },
        );
        assert_eq!(free_scrubs.load(Ordering::Relaxed), 79);
        assert_eq!(pool.pcp_stats().cached_pages, PCP_HIGH_WATERMARK);
        assert_eq!(pool.stats().unwrap().free_pages, initial_free - 1);

        // Re-allocating 79 frames hits PCP for 64 + buddy PAGE_FREE_ZEROED for 15:
        // ZERO redundant scrubs needed!
        let mut again = [PhysFrame::containing_address(PhysAddr::new(0)); 79];
        let second_scrubs = AtomicUsize::new(0);
        let got2 = pool
            .try_alloc_order0_batch_with(
                &mut again,
                0,
                4,
                |_| {
                    second_scrubs.fetch_add(1, Ordering::Relaxed);
                },
                false,
            )
            .expect("second batch alloc 79 frames");
        assert_eq!(got2, 79);
        assert_eq!(
            second_scrubs.load(Ordering::Relaxed),
            0,
            "PCP hits and PCP-drained PAGE_FREE_ZEROED frames must skip redundant scrubs"
        );
        assert_eq!(pool.stats().unwrap().free_pages, initial_free - 80);

        // Free everything cleanly (refcount now 0) and verify full conservation.
        pool.free_order0_batch_with(&again, 0, |_| 0, |_| {});
        pool.free_order0_batch_with(&[ref_frame], 0, |_| 0, |_| {});
        assert_eq!(pool.stats().unwrap().free_pages, initial_free);
        pool.drain_all_pcp(4);
        assert_eq!(pool.pcp_stats().cached_pages, 0);
        assert_eq!(pool.stats().unwrap().free_pages, initial_free);
        assert_eq!(
            pool.buddy.lock().as_ref().unwrap().validate_metadata(),
            Ok(())
        );
    }
}
