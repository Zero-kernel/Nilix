//! Buddy内存分配器实现
//!
//! Buddy分配器是一种高效的内存管理算法，通过将内存分割成2的幂次大小的块来管理。
//! 当需要分配内存时，找到最小的能满足需求的块；释放时尝试与相邻的块合并。

use alloc::vec::Vec;
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
const PAGE_ALLOC_TAIL_BASE: u8 = 0x40;
const PAGE_RESERVED: u8 = u8::MAX;

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

/// Fixed-size, allocation-free-after-init representation of every free buddy
/// block.  Order `o`, block `b` represents the exact page range
/// `[b << o, (b + 1) << o)`.  All order bitmaps live in one fallibly allocated
/// word vector whose length and capacity never change after construction.
struct FixedFreeMap {
    words: Vec<u64>,
    word_base: [usize; ORDER_COUNT + 1],
    valid_blocks: [usize; ORDER_COUNT],
    block_count: [usize; ORDER_COUNT],
    search_cursor: [usize; ORDER_COUNT],
}

impl FixedFreeMap {
    fn try_new(total_pages: usize) -> Result<Self, BuddyInitError> {
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

        let mut storage = Vec::new();
        storage
            .try_reserve_exact(total_words)
            .map_err(|_| BuddyInitError::MetadataAllocationFailed)?;
        storage.resize(total_words, 0);

        Ok(Self {
            words: storage,
            word_base,
            valid_blocks,
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

    /// Exact per-page ownership state: free, reserved, allocation start(order),
    /// or allocation tail(order). This makes interior/wrong-order/double frees
    /// distinguishable without trusting caller-supplied sizes.
    page_state: Vec<u8>,

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

        let total_pages = size / PAGE_SIZE;

        let mut page_state = Vec::new();
        page_state
            .try_reserve_exact(total_pages)
            .map_err(|_| BuddyInitError::MetadataAllocationFailed)?;
        page_state.resize(total_pages, PAGE_FREE);

        let mut allocator = BuddyAllocator {
            free_map: FixedFreeMap::try_new(total_pages)?,
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
                if self.page_state[page_idx] == PAGE_FREE {
                    self.page_state[page_idx] = PAGE_RESERVED;
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
            if self.page_state[page_idx] == PAGE_RESERVED {
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
        self.page_state[source.block_idx] = start_state;
        for index in source.block_idx + 1..source.block_idx + target_pages {
            self.page_state[index] = tail_state;
        }
        self.free_pages = new_free_pages;
        Ok(frame)
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

        let start_state = *self
            .page_state
            .get(block_idx)
            .ok_or(FreeError::RangeOutOfBounds)?;
        if start_state == PAGE_RESERVED {
            return Err(FreeError::ReservedPage);
        }
        if start_state == PAGE_FREE || decode_allocation_tail(start_state).is_some() {
            return Err(FreeError::NotAllocationStart);
        }
        let recorded_order =
            decode_allocation_start(start_state).ok_or(FreeError::NotAllocationStart)?;
        if recorded_order != order {
            return Err(FreeError::OrderMismatch);
        }
        let expected_tail = allocation_tail_state(order).ok_or(FreeError::OrderTooLarge)?;
        if (block_idx + 1..block_idx + pages)
            .any(|index| self.page_state.get(index).copied() != Some(expected_tail))
        {
            self.poisoned = true;
            return Err(FreeError::MetadataCorrupt);
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
        for index in block_idx..block_idx + pages {
            self.page_state[index] = PAGE_FREE;
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
                    .all(|state| *state == PAGE_FREE)
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
            let state = self.page_state[page];
            if state == PAGE_RESERVED {
                let none = [None; ORDER_COUNT];
                if self.has_unexpected_free_overlap(page, 1, &none) {
                    return Err(());
                }
                reserved = reserved.checked_add(1).ok_or(())?;
                page += 1;
                continue;
            }
            if state == PAGE_FREE {
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
            if (page + 1..page + pages).any(|index| self.page_state[index] != tail) {
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

/// 全局Buddy分配器实例
static BUDDY_ALLOCATOR: Mutex<Option<BuddyAllocator>> = Mutex::new(None);

/// RF178-12: borrow the physical allocator without waiting or invoking OOM
/// recovery. Intended for bounded synchronous exception work that must either
/// complete with one allocator ownership interval or fail closed. Keeping the
/// guard across the callback also makes rollback frees infallible with respect
/// to allocator-lock contention.
pub fn try_with_allocator<T, F>(f: F) -> Option<T>
where
    F: FnOnce(&mut BuddyAllocator) -> T,
{
    let mut guard = BUDDY_ALLOCATOR.try_lock()?;
    let allocator = guard.as_mut()?;
    Some(f(allocator))
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
    // Snapshot stats before the allocator is moved under the lock.
    let total_pages = allocator.total_pages;
    let reserved_pages = allocator.reserved_pages;
    let free_pages = allocator.free_pages;
    *BUDDY_ALLOCATOR.lock() = Some(allocator);

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
/// 如果分配失败，会触发 OOM killer 尝试回收内存，然后重试一次
pub fn alloc_physical_pages(count: usize) -> Option<PhysFrame> {
    match try_alloc_physical_pages(count) {
        Ok(frame) => Some(frame),
        Err(AllocError::MetadataCorrupt | AllocError::AllocatorPoisoned) => {
            panic!("physical allocator metadata is corrupt/poisoned")
        }
        Err(_) => None,
    }
}

/// Fallible physical allocation with error classification. OOM recovery runs
/// only for genuine free-space exhaustion; invalid orders and poisoned
/// metadata never masquerade as memory pressure.
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

    let first = {
        let mut guard = BUDDY_ALLOCATOR.lock();
        let allocator = guard.as_mut().ok_or(AllocError::AllocatorUnavailable)?;
        allocator.try_alloc_pages(order)
    };
    match first {
        Ok(frame) => return Ok(frame),
        Err(AllocError::Exhausted) => {}
        Err(error) => return Err(error),
    }

    oom_killer::on_allocation_failure(pages_needed);
    // RF178-4: run reclaim only after releasing BUDDY_ALLOCATOR so recovery
    // cannot recursively acquire the allocator guard.
    oom_killer::poll_and_handle_oom();

    let mut guard = BUDDY_ALLOCATOR.lock();
    let allocator = guard.as_mut().ok_or(AllocError::AllocatorUnavailable)?;
    allocator.try_alloc_pages(order)
}

/// 释放物理页面
///
/// # 参数
/// * `frame` - 要释放的物理帧
/// * `count` - 页面数量
/// Checked counterpart to `free_physical_pages`.
///
/// The operation validates the exact buddy-relative base, allocation order,
/// and allocation state of every page. It returns only after the block has
/// actually re-entered the free lists.
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
    let mut guard = BUDDY_ALLOCATOR.lock();
    let allocator = guard.as_mut().ok_or(FreeError::AllocatorUnavailable)?;
    allocator.try_free_pages(frame, order)
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

    if let Some(allocator) = BUDDY_ALLOCATOR.lock().as_mut() {
        if let Err(error) = allocator.try_free_pages(frame, order) {
            if error.is_metadata_corruption() {
                allocator.poisoned = true;
            }
            kprintln!(
                "[buddy] rejected free_physical_pages: {:?}{}",
                error,
                if error.is_metadata_corruption() {
                    "; allocator quarantined"
                } else {
                    "; allocator remains available"
                }
            );
        }
    }
}

/// 获取分配器统计信息
pub fn get_allocator_stats() -> Option<AllocatorStats> {
    BUDDY_ALLOCATOR
        .lock()
        .as_ref()
        .map(|allocator| allocator.stats())
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
    ) -> (*const u8, usize, usize, *const u64, usize, usize) {
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

    #[test]
    fn rejected_frees_leave_metadata_byte_exact() {
        let base = PhysAddr::new(0x3400_0000);
        let mut allocator = BuddyAllocator::new(base, 2 * 1024 * 1024).expect("construct");
        let frame = allocator.try_alloc_pages(2).expect("allocate order 2");

        let words = allocator.free_map.words.clone();
        let states = allocator.page_state.clone();
        let counts = allocator.free_map.block_count;
        let cursors = allocator.free_map.search_cursor;
        let free_pages = allocator.free_pages;
        assert_eq!(
            allocator.try_free_pages(frame, 1),
            Err(FreeError::OrderMismatch)
        );
        assert_eq!(allocator.free_map.words, words);
        assert_eq!(allocator.page_state, states);
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
        assert_eq!(allocator.page_state, states);
        assert_eq!(allocator.free_pages, free_pages);

        allocator.try_free_pages(frame, 2).expect("valid free");
        let words = allocator.free_map.words.clone();
        let states = allocator.page_state.clone();
        let counts = allocator.free_map.block_count;
        let free_pages = allocator.free_pages;
        assert_eq!(
            allocator.try_free_pages(frame, 2),
            Err(FreeError::NotAllocationStart)
        );
        assert_eq!(allocator.free_map.words, words);
        assert_eq!(allocator.page_state, states);
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
        let states = allocator.page_state.clone();
        let free_pages = allocator.free_pages;
        assert_eq!(
            allocator.try_free_pages(frame, 0),
            Err(FreeError::MetadataCorrupt)
        );
        assert!(allocator.poisoned);
        assert_eq!(allocator.free_map.words, words);
        assert_eq!(allocator.page_state, states);
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
}
