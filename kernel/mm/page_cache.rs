//! Page Cache Implementation for Zero-OS
//!
//! Provides a global page cache for file-backed pages with:
//! - One globally bounded allocation-fallible ordered index
//! - LRU list for page reclamation
//! - Dirty page tracking for writeback
//!
//! # Architecture
//!
//! ```text
//! GlobalPageCache
//!   - index: RwLock<FallibleOrderedMap<(InodeId, PageIndex), Arc<PageCacheEntry>>>
//!   - lru: Mutex<LruList>
//! ```

use alloc::collections::TryReserveError;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};
use x86_64::{structures::paging::PhysFrame, PhysAddr};

use crate::buddy_allocator;
use crate::fallible_map::FallibleOrderedMap;
use crate::memory::HEAP_SIZE_BYTES;

/// Page size constant (4KB)
pub const PAGE_SIZE: usize = 4096;

/// RF178-11 FIX: Reserve only one eighth of the 1 MiB kernel heap for page-cache
/// metadata. `256` bytes per resident deliberately covers the Arc allocation,
/// one index record, one LRU record, and allocator/vector slack. The physical
/// 4 KiB data frame is not heap-backed.
const PAGE_CACHE_METADATA_BUDGET_BYTES: usize = HEAP_SIZE_BYTES / 8;
const PAGE_CACHE_METADATA_BYTES_PER_PAGE: usize = 256;

/// Heap-derived hard ceiling. With the current heap this is 512 pages, not the
/// old 16,384-page policy whose eager LRU alone could consume the heap.
pub const PAGE_CACHE_MAX_PAGES: u64 =
    (PAGE_CACHE_METADATA_BUDGET_BYTES / PAGE_CACHE_METADATA_BYTES_PER_PAGE) as u64;

/// The origin cgroup owns the physical page plus its conservative metadata
/// allowance until the final `PageCacheEntry` reference is dropped.
pub const PAGE_CACHE_CGROUP_CHARGE_BYTES: u64 =
    PAGE_SIZE as u64 + PAGE_CACHE_METADATA_BYTES_PER_PAGE as u64;

/// Allocation-free callback retained by each entry for exact lifetime uncharge.
pub type PageCacheUnchargeFn = fn(u64, u64);

/// Inode identifier type
pub type InodeId = u64;

/// Page index within an inode (file offset / PAGE_SIZE)
pub type PageIndex = u64;

// ============================================================================
// Page Cache Entry
// ============================================================================

/// Flags for page state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PageState {
    /// Page is invalid/not yet loaded
    Invalid = 0,
    /// Page data is valid and up-to-date
    Uptodate = 1,
    /// Page is currently being read from disk
    Reading = 2,
    /// Page is currently being written to disk
    Writeback = 3,
    /// Page has an I/O error
    Error = 4,
}

/// A cached page entry
///
/// Contains a physical page frame along with metadata for cache management.
pub struct PageCacheEntry {
    /// Physical frame number (PFN) of the page
    pub pfn: u64,

    /// Inode this page belongs to
    pub inode_id: InodeId,

    /// Page index within the inode
    pub index: PageIndex,

    /// Whether the page has been modified since last writeback
    dirty: AtomicBool,

    /// Reference count (number of active users)
    refcount: AtomicU32,

    /// Page state
    state: AtomicU32,

    /// Lock for I/O serialization (only one I/O operation at a time)
    io_lock: Mutex<()>,

    /// LRU list node index (for O(1) removal)
    lru_index: AtomicU64,

    /// RF178-11: cgroup that caused this cache page to be allocated. Ownership
    /// is origin-bound rather than re-read during eviction.
    owner_cgroup_id: u64,

    /// Exact amount paired with `uncharge_cgroup` in `Drop`.
    cgroup_charge_bytes: u64,

    /// Stored callback avoids an `mm -> kernel_core` dependency cycle.
    uncharge_cgroup: PageCacheUnchargeFn,
}

impl PageCacheEntry {
    /// Create a new page cache entry
    ///
    /// R42-4 FIX: Refcount now starts at 0 (no active pins).
    /// The Arc wrapper provides the actual reference counting for the cache.
    /// Callers who need to pin a page should use get()/put() explicitly.
    fn new_charged(
        pfn: u64,
        inode_id: InodeId,
        index: PageIndex,
        owner_cgroup_id: u64,
        cgroup_charge_bytes: u64,
        uncharge_cgroup: PageCacheUnchargeFn,
    ) -> Self {
        Self {
            pfn,
            inode_id,
            index,
            dirty: AtomicBool::new(false),
            refcount: AtomicU32::new(0), // R42-4 FIX: Start with 0 (no active pins)
            state: AtomicU32::new(PageState::Invalid as u32),
            io_lock: Mutex::new(()),
            lru_index: AtomicU64::new(u64::MAX),
            owner_cgroup_id,
            cgroup_charge_bytes,
            uncharge_cgroup,
        }
    }

    /// Return the cgroup whose allocation populated this entry.
    #[inline]
    pub fn owner_cgroup_id(&self) -> u64 {
        self.owner_cgroup_id
    }

    /// Get the physical frame number
    #[inline]
    pub fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Get the physical address of this page
    #[inline]
    pub fn physical_address(&self) -> u64 {
        self.pfn * PAGE_SIZE as u64
    }

    /// Check if the page is dirty
    #[inline]
    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Acquire)
    }

    /// Mark the page as dirty
    #[inline]
    pub fn set_dirty(&self) {
        self.dirty.store(true, Ordering::Release);
    }

    /// Clear the dirty flag
    #[inline]
    pub fn clear_dirty(&self) {
        self.dirty.store(false, Ordering::Release);
    }

    /// Get the current reference count
    #[inline]
    pub fn refcount(&self) -> u32 {
        self.refcount.load(Ordering::Acquire)
    }

    /// Increment reference count
    #[inline]
    pub fn get(&self) -> u32 {
        self.refcount.fetch_add(1, Ordering::AcqRel) // lint-fetch-add: allow (page refcount)
    }

    /// Decrement reference count, returns true if this was the last reference
    ///
    /// R178-L3 FIX: Prevent underflow when refcount is already 0. Since R42-4 made
    /// the internal refcount field "only used for explicit pinning", it can fall
    /// out of sync with Arc's strong count. Use fetch_update to atomically
    /// check-and-decrement, returning false if already 0 instead of underflowing.
    #[inline]
    pub fn put(&self) -> bool {
        match self
            .refcount
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |val| {
                if val > 0 {
                    Some(val - 1)
                } else {
                    None // Already 0, don't decrement
                }
            }) {
            Ok(prev) => prev == 1, // True if we decremented from 1 to 0 (last ref)
            Err(_) => false,       // Was already 0, not last ref
        }
    }

    /// Get the page state
    #[inline]
    pub fn state(&self) -> PageState {
        match self.state.load(Ordering::Acquire) {
            0 => PageState::Invalid,
            1 => PageState::Uptodate,
            2 => PageState::Reading,
            3 => PageState::Writeback,
            _ => PageState::Error,
        }
    }

    /// Set the page state
    #[inline]
    pub fn set_state(&self, state: PageState) {
        self.state.store(state as u32, Ordering::Release);
    }

    /// Check if page data is valid
    #[inline]
    pub fn is_uptodate(&self) -> bool {
        self.state() == PageState::Uptodate
    }

    /// Lock the page for I/O operations
    #[inline]
    pub fn lock_io(&self) -> spin::MutexGuard<'_, ()> {
        self.io_lock.lock()
    }

    /// Check if the page can be reclaimed
    ///
    /// R42-4 FIX: Use Arc::strong_count instead of internal refcount to determine
    /// reclaimability. A page can be reclaimed when:
    /// 1. Only the cache index and caller hold references (strong_count == 2)
    ///    - After detach_tail: one ref in the index and one in the local variable
    /// 2. The page is not dirty (no pending writeback needed)
    /// 3. The page is not locked for I/O
    ///
    /// This fixes the issue where the internal refcount was only incremented
    /// but never decremented, preventing any page from ever being reclaimed.
    ///
    /// Note: Called from shrink() after the page has been removed from LRU.
    /// At that point, only the index and the local variable hold Arc references.
    pub fn can_reclaim(page: &alloc::sync::Arc<PageCacheEntry>) -> bool {
        // After LRU pop: index(1) + local var(1) = 2
        // Any external user would add more refs
        alloc::sync::Arc::strong_count(page) == 2
            && !page.is_dirty()
            && page.io_lock.try_lock().is_some()
    }
}

// R36-FIX: Implement Drop to free physical frame when page cache entry is dropped.
// This prevents memory leaks when pages are evicted from the cache during shrink().
impl Drop for PageCacheEntry {
    fn drop(&mut self) {
        // Free the physical frame back to the buddy allocator
        let phys_addr = self.pfn * PAGE_SIZE as u64;
        let frame = PhysFrame::containing_address(PhysAddr::new(phys_addr));
        buddy_allocator::free_physical_pages(frame, 1);

        // RF178-11 FIX: Charge lifetime follows the object, not just map
        // residency. A reader may retain an Arc after eviction; uncharging at
        // map removal would let that detached physical page bypass memory.max.
        (self.uncharge_cgroup)(self.owner_cgroup_id, self.cgroup_charge_bytes);
    }
}

// ============================================================================
// LRU List for Page Reclamation
// ============================================================================

/// LRU list entry
struct LruEntry {
    /// Reference to the page cache entry
    entry: Option<Arc<PageCacheEntry>>,
    /// Previous entry index
    prev: u64,
    /// Next entry index
    next: u64,
}

/// LRU list for tracking page access order
struct LruList {
    /// Array of LRU entries
    entries: Vec<LruEntry>,
    /// Head of the list (most recently used)
    head: u64,
    /// Tail of the list (least recently used)
    tail: u64,
    /// Number of active entries
    count: usize,
    /// Free list head
    free_head: u64,
    /// Hard bound inherited from the heap-derived cache limit.
    max_entries: usize,
}

impl LruList {
    /// Create an empty LRU. RF178-11 deliberately does not preallocate the
    /// policy maximum; each later growth is guarded by `try_reserve`.
    fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            head: u64::MAX,
            tail: u64::MAX,
            count: 0,
            free_head: u64::MAX,
            max_entries,
        }
    }

    /// Add a page to the front of the LRU list (most recently used)
    ///
    /// New backing storage is reserved fallibly before mutation. Reusing a
    /// removed node is allocation-free, which is important when `shrink`
    /// requeues a dirty or pinned candidate under memory pressure.
    fn try_push_front(
        &mut self,
        page: Arc<PageCacheEntry>,
    ) -> Result<Option<u64>, TryReserveError> {
        let idx = if self.free_head != u64::MAX {
            let idx = self.free_head;
            self.free_head = self.entries[idx as usize].next;
            idx
        } else {
            if self.entries.len() >= self.max_entries {
                return Ok(None);
            }
            self.entries.try_reserve_exact(1)?;
            let idx = self.entries.len() as u64;
            self.entries.push(LruEntry {
                entry: None,
                prev: u64::MAX,
                next: u64::MAX,
            });
            idx
        };

        // Initialize entry
        self.entries[idx as usize].prev = u64::MAX;
        self.entries[idx as usize].next = self.head;

        // Update old head
        if self.head != u64::MAX {
            self.entries[self.head as usize].prev = idx;
        }

        // Update head
        self.head = idx;

        // Update tail if this is the first entry
        if self.tail == u64::MAX {
            self.tail = idx;
        }

        self.count += 1;

        // Store index in page entry
        page.lru_index.store(idx, Ordering::Release);
        self.entries[idx as usize].entry = Some(page);

        Ok(Some(idx))
    }

    /// Move an existing entry to the front (mark as recently used)
    fn touch(&mut self, idx: u64) {
        if idx == u64::MAX
            || idx == self.head
            || idx as usize >= self.entries.len()
            || self.entries[idx as usize].entry.is_none()
        {
            return;
        }

        let idx_usize = idx as usize;

        // Remove from current position
        let prev = self.entries[idx_usize].prev;
        let next = self.entries[idx_usize].next;

        if prev != u64::MAX {
            self.entries[prev as usize].next = next;
        }
        if next != u64::MAX {
            self.entries[next as usize].prev = prev;
        }
        if self.tail == idx {
            self.tail = prev;
        }

        // Insert at front
        self.entries[idx_usize].prev = u64::MAX;
        self.entries[idx_usize].next = self.head;

        if self.head != u64::MAX {
            self.entries[self.head as usize].prev = idx;
        }
        self.head = idx;
    }

    /// Detach an entry from the active list while reserving its exact backing
    /// node. The node is deliberately NOT put on `free_head`: a shrinker drops
    /// the LRU lock before taking the index lock, and concurrent admission must
    /// not consume the node needed for an allocation-free requeue.
    fn detach(&mut self, idx: u64) -> Option<Arc<PageCacheEntry>> {
        if idx == u64::MAX || idx as usize >= self.entries.len() {
            return None;
        }

        let idx_usize = idx as usize;
        let entry = self.entries[idx_usize].entry.take()?;

        // Update links
        let prev = self.entries[idx_usize].prev;
        let next = self.entries[idx_usize].next;

        if prev != u64::MAX {
            self.entries[prev as usize].next = next;
        } else {
            self.head = next;
        }

        if next != u64::MAX {
            self.entries[next as usize].prev = prev;
        } else {
            self.tail = prev;
        }

        // Mark the reserved node detached, but do not publish it to free_head.
        self.entries[idx_usize].prev = u64::MAX;
        self.entries[idx_usize].next = u64::MAX;

        self.count -= 1;

        // Clear index in page entry
        entry.lru_index.store(u64::MAX, Ordering::Release);

        Some(entry)
    }

    /// Restore a node reserved by `detach` to the active LRU, infallibly.
    fn restore_detached(&mut self, idx: u64, page: Arc<PageCacheEntry>) {
        let idx = idx as usize;
        assert!(idx < self.entries.len());
        assert!(self.entries[idx].entry.is_none());

        self.entries[idx].prev = u64::MAX;
        self.entries[idx].next = self.head;
        if self.head != u64::MAX {
            self.entries[self.head as usize].prev = idx as u64;
        }
        self.head = idx as u64;
        if self.tail == u64::MAX {
            self.tail = idx as u64;
        }
        self.count += 1;
        page.lru_index.store(idx as u64, Ordering::Release);
        self.entries[idx].entry = Some(page);
    }

    /// Publish a detached node to the allocation-free free list after reclaim.
    fn recycle_detached(&mut self, idx: u64) {
        let idx_usize = idx as usize;
        assert!(idx_usize < self.entries.len());
        assert!(self.entries[idx_usize].entry.is_none());
        self.entries[idx_usize].prev = u64::MAX;
        self.entries[idx_usize].next = self.free_head;
        self.free_head = idx;
    }

    /// Remove an entry and make its node immediately reusable.
    fn remove(&mut self, idx: u64) -> Option<Arc<PageCacheEntry>> {
        let page = self.detach(idx)?;
        self.recycle_detached(idx);
        Some(page)
    }

    /// Detach the tail while reserving its node for the shrink transaction.
    fn detach_tail(&mut self) -> Option<(u64, Arc<PageCacheEntry>)> {
        if self.tail == u64::MAX {
            return None;
        }
        let idx = self.tail;
        self.detach(idx).map(|page| (idx, page))
    }

    /// Get the number of entries
    fn len(&self) -> usize {
        self.count
    }
}

// ============================================================================
// Global Page Cache
// ============================================================================

/// Global page cache
pub struct GlobalPageCache {
    /// Single bounded index. The former sharded design retained one Vec
    /// high-water allocation per bucket, so churn could outgrow the live-page
    /// metadata budget even after every page was reclaimed.
    index: RwLock<FallibleOrderedMap<(InodeId, PageIndex), Arc<PageCacheEntry>>>,
    /// LRU list for reclamation
    lru: Mutex<LruList>,
    /// Total number of cached pages
    nr_pages: AtomicU64,
    /// Total number of dirty pages
    nr_dirty: AtomicU64,
    /// Maximum number of pages to cache
    max_pages: u64,
    /// Resident pages plus in-flight admissions. Unlike a total-free heap
    /// probe, this is a real atomic reservation and cannot be oversubscribed by
    /// concurrent readers.
    allocated_slots: AtomicU64,
}

/// RAII slot reservation acquired after cgroup admission and before frame/Arc
/// allocation. A successful publication commits the slot; every error path
/// releases it automatically.
struct CacheAdmission<'a> {
    cache: &'a GlobalPageCache,
    committed: bool,
}

impl CacheAdmission<'_> {
    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for CacheAdmission<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.cache.release_slot();
        }
    }
}

/// RF178-11 FIX: RAII ownership for one successful cgroup charge. Ownership
/// moves into `PageCacheEntry` before its fallible Arc allocation; every other
/// exit uncharges automatically.
#[must_use = "a successful page-cache charge must be transferred or refunded"]
struct CacheCharge {
    owner_cgroup_id: u64,
    bytes: u64,
    uncharge_cgroup: PageCacheUnchargeFn,
    armed: bool,
}

impl CacheCharge {
    fn new(owner_cgroup_id: u64, uncharge_cgroup: PageCacheUnchargeFn) -> Self {
        Self {
            owner_cgroup_id,
            bytes: PAGE_CACHE_CGROUP_CHARGE_BYTES,
            uncharge_cgroup,
            armed: true,
        }
    }

    fn into_entry(mut self, pfn: u64, inode_id: InodeId, index: PageIndex) -> PageCacheEntry {
        self.armed = false;
        PageCacheEntry::new_charged(
            pfn,
            inode_id,
            index,
            self.owner_cgroup_id,
            self.bytes,
            self.uncharge_cgroup,
        )
    }
}

impl Drop for CacheCharge {
    fn drop(&mut self) {
        if self.armed {
            (self.uncharge_cgroup)(self.owner_cgroup_id, self.bytes);
        }
    }
}

enum CacheInsertResult {
    Inserted(Arc<PageCacheEntry>),
    Existing(Arc<PageCacheEntry>),
    OutOfMemory,
}

impl GlobalPageCache {
    /// Create a new global page cache
    pub fn new(requested_max_pages: u64) -> Self {
        let max_pages = requested_max_pages.min(PAGE_CACHE_MAX_PAGES);
        Self {
            index: RwLock::new(FallibleOrderedMap::new()),
            lru: Mutex::new(LruList::new(max_pages as usize)),
            nr_pages: AtomicU64::new(0),
            nr_dirty: AtomicU64::new(0),
            max_pages,
            allocated_slots: AtomicU64::new(0),
        }
    }

    fn try_hold_slot(&self) -> bool {
        self.allocated_slots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                if used < self.max_pages {
                    Some(used + 1)
                } else {
                    None
                }
            })
            .is_ok()
    }

    /// Reserve capacity, reclaiming a clean unpinned page before refusing an
    /// admission at the hard cap. No current-total-free observation is used as
    /// a reservation: `allocated_slots` is the concurrency-safe authority.
    fn reserve_admission(&self, _charge: &CacheCharge) -> Option<CacheAdmission<'_>> {
        if self.try_hold_slot() {
            return Some(CacheAdmission {
                cache: self,
                committed: false,
            });
        }

        if self.shrink(1) == 0 || !self.try_hold_slot() {
            return None;
        }

        Some(CacheAdmission {
            cache: self,
            committed: false,
        })
    }

    fn release_slot(&self) {
        let result =
            self.allocated_slots
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_sub(1)
                });
        debug_assert!(result.is_ok(), "page-cache slot accounting underflow");
    }

    /// Find a page in the cache
    ///
    /// R42-4 FIX: Removed redundant page.get() call. The Arc clone already
    /// increments the reference count. The internal refcount field is now
    /// only used for explicit pinning by callers who need it.
    pub fn find_get_page(
        &self,
        inode_id: InodeId,
        index: PageIndex,
    ) -> Option<Arc<PageCacheEntry>> {
        let cache_index = self.index.read();

        if let Some(page) = cache_index.get(&(inode_id, index)) {
            // Touch LRU (mark as recently used)
            let lru_idx = page.lru_index.load(Ordering::Acquire);
            if lru_idx != u64::MAX {
                let mut lru = self.lru.lock();
                lru.touch(lru_idx);
            }

            Some(page.clone())
        } else {
            None
        }
    }

    /// Publish a pre-charged page after an admission slot has been reserved.
    /// Every growth point reserves fallibly before the cache is mutated.
    fn add_to_cache(
        &self,
        inode_id: InodeId,
        index: PageIndex,
        page: Arc<PageCacheEntry>,
    ) -> CacheInsertResult {
        let mut cache_index = self.index.write();

        // Check if page already exists
        if let Some(existing) = cache_index.get(&(inode_id, index)) {
            let existing = existing.clone();
            drop(cache_index);
            drop(page); // exact cgroup/frame rollback via PageCacheEntry::drop
            return CacheInsertResult::Existing(existing);
        }

        if cache_index.len() >= self.max_pages as usize {
            drop(cache_index);
            drop(page);
            return CacheInsertResult::OutOfMemory;
        }

        // Exact growth on the one global index keeps retained capacity tied to
        // the live-page ceiling. A failed reserve leaves both indexes unchanged.
        if cache_index.try_reserve_exact(1).is_err() {
            drop(cache_index);
            drop(page);
            return CacheInsertResult::OutOfMemory;
        }

        // Lock order remains index -> LRU. LRU growth is fallible and occurs
        // before index publication, so rollback cannot expose a half-indexed page.
        let mut lru = self.lru.lock();
        let lru_idx = match lru.try_push_front(page.clone()) {
            Ok(Some(idx)) => idx,
            Ok(None) | Err(_) => {
                drop(lru);
                drop(cache_index);
                drop(page);
                return CacheInsertResult::OutOfMemory;
            }
        };

        match cache_index.try_insert((inode_id, index), page.clone()) {
            Ok(None) => {
                self.nr_pages.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
                drop(lru);
                drop(cache_index);
                CacheInsertResult::Inserted(page)
            }
            // Exclusive index ownership plus the duplicate check above makes
            // replacement impossible. Restore defensively without allocation.
            Ok(Some(existing)) => {
                let _ = cache_index.try_insert((inode_id, index), existing.clone());
                let _ = lru.remove(lru_idx);
                drop(lru);
                drop(cache_index);
                drop(page);
                CacheInsertResult::Existing(existing)
            }
            Err(_) => {
                // The preceding try_reserve guarantees this branch should be
                // unreachable, but retain transactional rollback if the map's
                // implementation changes.
                let _ = lru.remove(lru_idx);
                drop(lru);
                drop(cache_index);
                drop(page);
                CacheInsertResult::OutOfMemory
            }
        }
    }

    /// Remove a clean, unlocked page from the cache.
    ///
    /// Returns false while any external Arc exists. This preserves the hard
    /// metadata bound: a slot is never reused before the removed entry dies.
    pub fn remove_from_cache(&self, inode_id: InodeId, index: PageIndex) -> bool {
        let mut cache_index = self.index.write();

        // A metadata slot cannot be released while an external Arc still keeps
        // that allocation alive. Explicit invalidation therefore succeeds only
        // for the same clean, unlocked, unpinned state accepted by reclaim.
        let Some(indexed) = cache_index.get(&(inode_id, index)) else {
            return false;
        };
        let lru_idx = indexed.lru_index.load(Ordering::Acquire);
        if lru_idx == u64::MAX {
            // A shrinker has popped this entry and owns the transient Arc. It
            // alone will either requeue or release the slot.
            return false;
        }
        let mut lru = self.lru.lock();
        let lru_matches = lru
            .entries
            .get(lru_idx as usize)
            .and_then(|entry| entry.entry.as_ref())
            .map(|entry| Arc::ptr_eq(entry, indexed))
            .unwrap_or(false);
        if !lru_matches || !PageCacheEntry::can_reclaim(indexed) {
            return false;
        }

        let page = match cache_index.remove(&(inode_id, index)) {
            Some(page) => page,
            None => return false,
        };
        let lru_page = lru.remove(lru_idx);
        drop(lru);
        drop(cache_index);

        self.nr_pages.fetch_sub(1, Ordering::Relaxed);
        drop(lru_page);
        drop(page);
        self.release_slot();

        true
    }

    /// Mark a page as dirty
    pub fn mark_dirty(&self, page: &PageCacheEntry) {
        if !page.is_dirty() {
            page.set_dirty();
            self.nr_dirty.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
        }
    }

    /// Clear dirty flag on a page
    pub fn clear_dirty(&self, page: &PageCacheEntry) {
        if page.is_dirty() {
            page.clear_dirty();
            self.nr_dirty.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Try to reclaim pages to free memory
    ///
    /// Returns the number of pages reclaimed.
    ///
    /// R42-5 FIX: Continue scanning LRU instead of stopping at first non-reclaimable page.
    /// An attacker could keep pages dirty/pinned to block reclamation if we stopped early.
    ///
    /// Lock ordering: index lock -> LRU lock (same as find_get_page/add_to_cache).
    /// To avoid deadlock, we release LRU before acquiring the index lock.
    pub fn shrink(&self, nr_to_reclaim: usize) -> usize {
        self.shrink_matching(nr_to_reclaim, None)
    }

    /// Reclaim only pages charged to one origin cgroup. Used after a memory.max
    /// refusal so a tenant can replace its own clean working set without
    /// evicting another tenant merely to retry the same charge.
    fn shrink_owner(&self, owner_cgroup_id: u64, nr_to_reclaim: usize) -> usize {
        self.shrink_matching(nr_to_reclaim, Some(owner_cgroup_id))
    }

    fn shrink_matching(&self, nr_to_reclaim: usize, owner_cgroup_id: Option<u64>) -> usize {
        let mut reclaimed = 0;
        let mut scanned = 0usize;
        let max_scan = self.nr_pages.load(Ordering::Relaxed) as usize;

        while reclaimed < nr_to_reclaim && scanned < max_scan {
            // Phase 1: Pop candidate from LRU (with LRU lock)
            let (detached_idx, page) = {
                let mut lru = self.lru.lock();
                match lru.detach_tail() {
                    Some(detached) => detached,
                    None => break,
                }
            };
            // LRU lock released here
            scanned += 1;

            // Phase 2: under the index write lock, verify both identity and
            // reclaimability. The latter must be checked while new lookup
            // clones are excluded, or detached Arcs could outlive a slot that
            // has already been reused by another admission.
            let mut cache_index = self.index.write();
            let still_indexed = cache_index
                .get(&(page.inode_id, page.index))
                .map(|indexed| Arc::ptr_eq(indexed, &page))
                .unwrap_or(false);

            if !still_indexed {
                // A concurrent explicit removal won the race and performed all
                // accounting. Never remove a newer same-key page by key alone.
                let mut lru = self.lru.lock();
                lru.recycle_detached(detached_idx);
                drop(lru);
                drop(cache_index);
                continue;
            }

            let owner_matches = owner_cgroup_id
                .map(|owner| page.owner_cgroup_id == owner)
                .unwrap_or(true);
            if !owner_matches || !PageCacheEntry::can_reclaim(&page) {
                // Keep index -> LRU order while restoring the reserved node so
                // explicit removal cannot detach the index entry between
                // validation and publication. No allocation can occur here.
                let mut lru = self.lru.lock();
                lru.restore_detached(detached_idx, page);
                drop(lru);
                drop(cache_index);
                continue;
            }

            let removed = cache_index.remove(&(page.inode_id, page.index));
            debug_assert!(removed.is_some());
            let mut lru = self.lru.lock();
            lru.recycle_detached(detached_idx);
            drop(lru);
            drop(cache_index);

            // Destroy both cache-owned Arcs (and therefore the entry/frame/
            // cgroup charge) before making the metadata slot reusable.
            drop(removed);
            drop(page);
            self.nr_pages.fetch_sub(1, Ordering::Relaxed);
            self.release_slot();
            reclaimed += 1;

            // R36-FIX: Physical frame is freed by Drop impl when Arc refcount reaches 0
        }

        reclaimed
    }

    /// Get cache statistics
    pub fn stats(&self) -> PageCacheStats {
        let index_capacity = self.index.read().capacity() as u64;
        PageCacheStats {
            nr_pages: self.nr_pages.load(Ordering::Relaxed),
            nr_dirty: self.nr_dirty.load(Ordering::Relaxed),
            max_pages: self.max_pages,
            lru_len: self.lru.lock().len() as u64,
            index_capacity,
        }
    }

    /// Check if cache is under memory pressure
    pub fn under_pressure(&self) -> bool {
        self.max_pages == 0 || self.nr_pages.load(Ordering::Relaxed) >= self.max_pages * 90 / 100
    }
}

/// Page cache statistics
#[derive(Debug, Clone, Copy)]
pub struct PageCacheStats {
    /// Total number of cached pages
    pub nr_pages: u64,
    /// Number of dirty pages
    pub nr_dirty: u64,
    /// Maximum cache size
    pub max_pages: u64,
    /// LRU list length
    pub lru_len: u64,
    /// Retained slots in the single global index.
    pub index_capacity: u64,
}

// ============================================================================
// Global Instance
// ============================================================================

use lazy_static::lazy_static;

lazy_static! {
    /// RF178-11: heap-derived metadata bound (512 pages with the 1 MiB heap).
    pub static ref PAGE_CACHE: GlobalPageCache = GlobalPageCache::new(PAGE_CACHE_MAX_PAGES);
}

/// Initialize the page cache
pub fn init() {
    // Force lazy static initialization
    let stats = PAGE_CACHE.stats();
    klog!(
        Info,
        "Page cache initialized: max_pages={}, current={}",
        stats.max_pages,
        stats.nr_pages
    );
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Find or create a page in the cache
pub fn find_or_create_page<C, A>(
    inode_id: InodeId,
    index: PageIndex,
    owner_cgroup_id: u64,
    try_charge_cgroup: C,
    uncharge_cgroup: PageCacheUnchargeFn,
    alloc_pfn: A,
) -> Option<Arc<PageCacheEntry>>
where
    C: FnMut(u64, u64) -> bool,
    A: FnOnce() -> Option<u64>,
{
    find_or_create_page_in(
        &PAGE_CACHE,
        inode_id,
        index,
        owner_cgroup_id,
        try_charge_cgroup,
        uncharge_cgroup,
        alloc_pfn,
    )
}

fn find_or_create_page_in<C, A>(
    cache: &GlobalPageCache,
    inode_id: InodeId,
    index: PageIndex,
    owner_cgroup_id: u64,
    mut try_charge_cgroup: C,
    uncharge_cgroup: PageCacheUnchargeFn,
    alloc_pfn: A,
) -> Option<Arc<PageCacheEntry>>
where
    C: FnMut(u64, u64) -> bool,
    A: FnOnce() -> Option<u64>,
{
    // Try to find existing page
    if let Some(page) = cache.find_get_page(inode_id, index) {
        return Some(page);
    }

    // RF178-11 FIX: cgroup admission precedes unrestricted global reclaim. A
    // denied tenant may replace its own clean pages, but cannot evict another
    // tenant and then fail its charge. Recheck after refusal because a racing
    // publisher may already have satisfied this key without a new charge.
    let mut owner_reclaims = 0u64;
    while !try_charge_cgroup(owner_cgroup_id, PAGE_CACHE_CGROUP_CHARGE_BYTES) {
        if let Some(page) = cache.find_get_page(inode_id, index) {
            return Some(page);
        }
        if owner_reclaims >= cache.max_pages {
            return None;
        }
        if cache.shrink_owner(owner_cgroup_id, 1) == 0 {
            return None;
        }
        owner_reclaims += 1;
    }
    let charge = CacheCharge::new(owner_cgroup_id, uncharge_cgroup);

    if let Some(page) = cache.find_get_page(inode_id, index) {
        return Some(page);
    }

    // The live charge token is a compile-time ordering witness: only an
    // admitted requester may trigger global-cap reclaim. Recheck after the
    // slot reservation because another CPU may have won the same key.
    let admission = cache.reserve_admission(&charge)?;
    if let Some(page) = cache.find_get_page(inode_id, index) {
        return Some(page);
    }

    let pfn = alloc_pfn()?;

    // `Arc::try_new` makes the last heap birth recoverable. On allocation
    // failure it drops the value, whose Drop frees the frame and reverses the
    // cgroup charge; the admission guard independently releases the slot.
    let page = Arc::try_new(charge.into_entry(pfn, inode_id, index)).ok()?;

    // Try to add to cache
    match cache.add_to_cache(inode_id, index, page) {
        CacheInsertResult::Inserted(page) => {
            admission.commit();
            Some(page)
        }
        CacheInsertResult::Existing(existing) => Some(existing),
        CacheInsertResult::OutOfMemory => None,
    }
}

/// Read a page from cache, or load from disk if not cached
pub fn read_page<F, C, A>(
    inode_id: InodeId,
    index: PageIndex,
    owner_cgroup_id: u64,
    try_charge_cgroup: C,
    uncharge_cgroup: PageCacheUnchargeFn,
    alloc_pfn: A,
    read_from_disk: F,
) -> Option<Arc<PageCacheEntry>>
where
    F: FnOnce(&PageCacheEntry) -> Result<(), ()>,
    C: FnMut(u64, u64) -> bool,
    A: FnOnce() -> Option<u64>,
{
    // Find or create the page
    let page = find_or_create_page(
        inode_id,
        index,
        owner_cgroup_id,
        try_charge_cgroup,
        uncharge_cgroup,
        alloc_pfn,
    )?;

    // If page is already up-to-date, return it
    if page.is_uptodate() {
        return Some(page);
    }

    // Perform I/O with lock held in a block scope
    let success = {
        // Lock page for I/O
        let _io_lock = page.lock_io();

        // Double-check after acquiring lock
        if page.is_uptodate() {
            true
        } else {
            // Set state to reading
            page.set_state(PageState::Reading);

            // Read from disk
            if read_from_disk(&page).is_ok() {
                page.set_state(PageState::Uptodate);
                true
            } else {
                page.set_state(PageState::Error);
                false
            }
        }
    };

    if success {
        Some(page)
    } else {
        None
    }
}

/// Write a page to disk (for writeback)
pub fn writeback_page<F>(page: &PageCacheEntry, write_to_disk: F) -> Result<(), ()>
where
    F: FnOnce(&PageCacheEntry) -> Result<(), ()>,
{
    if !page.is_dirty() {
        return Ok(());
    }

    // Lock page for I/O
    let _io_lock = page.lock_io();

    // Double-check dirty flag
    if !page.is_dirty() {
        return Ok(());
    }

    // Set state to writeback
    page.set_state(PageState::Writeback);

    // Write to disk
    let result = write_to_disk(page);

    if result.is_ok() {
        PAGE_CACHE.clear_dirty(page);
        page.set_state(PageState::Uptodate);
    } else {
        page.set_state(PageState::Error);
    }

    result
}

// ============================================================================
// Writeback and Reclaim
// ============================================================================

/// Writeback statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct WritebackStats {
    /// Number of pages written back
    pub pages_written: u64,
    /// Number of pages that failed writeback
    pub pages_failed: u64,
    /// Number of pages skipped (already clean)
    pub pages_skipped: u64,
}

/// Scan the LRU list and writeback dirty pages
///
/// Returns writeback statistics.
pub fn writeback_dirty_pages<F>(max_pages: usize, write_fn: F) -> WritebackStats
where
    F: Fn(&PageCacheEntry) -> Result<(), ()>,
{
    let mut stats = WritebackStats::default();
    let mut pages_to_writeback = Vec::new();
    // No cache instance can contain more than the heap-derived hard cap. Reserve
    // that bounded collection fallibly before taking/cloning any page Arcs.
    let collect_cap = max_pages.min(PAGE_CACHE_MAX_PAGES as usize);
    if pages_to_writeback.try_reserve_exact(collect_cap).is_err() {
        stats.pages_skipped = collect_cap as u64;
        return stats;
    }

    // Phase 1: Collect dirty pages from LRU (with LRU lock)
    {
        let lru = PAGE_CACHE.lru.lock();

        // Walk the LRU from tail (oldest) to head
        let mut idx = lru.tail;
        while idx != u64::MAX && pages_to_writeback.len() < max_pages {
            if let Some(entry) = &lru.entries[idx as usize].entry {
                if entry.is_dirty() {
                    pages_to_writeback.push(entry.clone());
                }
            }
            // Move toward head
            idx = lru.entries[idx as usize].prev;
        }
    }
    // LRU lock released

    // Phase 2: Write back each dirty page (no global locks held)
    for page in pages_to_writeback {
        if !page.is_dirty() {
            stats.pages_skipped += 1;
            continue;
        }

        // Try to lock page for I/O
        if let Some(_io_lock) = page.io_lock.try_lock() {
            // Double-check dirty flag
            if !page.is_dirty() {
                stats.pages_skipped += 1;
                continue;
            }

            // Set state to writeback
            page.set_state(PageState::Writeback);

            // Write to disk
            if write_fn(&page).is_ok() {
                PAGE_CACHE.clear_dirty(&page);
                page.set_state(PageState::Uptodate);
                stats.pages_written += 1;
            } else {
                page.set_state(PageState::Error);
                stats.pages_failed += 1;
            }
        } else {
            // Page is locked by another I/O operation, skip it
            stats.pages_skipped += 1;
        }
    }

    stats
}

/// Reclaim memory by evicting clean pages
///
/// This function is called when memory pressure is high.
/// Returns the number of pages freed.
pub fn reclaim_pages(nr_to_reclaim: usize) -> usize {
    PAGE_CACHE.shrink(nr_to_reclaim)
}

// RF178-11 focused policy probes. These callbacks deliberately contain no heap
// work so the test exercises the same lifetime protocol as cgroup accounting.
static PAGE_CACHE_TEST_CHARGES: AtomicU64 = AtomicU64::new(0);
static PAGE_CACHE_TEST_UNCHARGES: AtomicU64 = AtomicU64::new(0);
static PAGE_CACHE_TEST_CHARGED_BYTES: AtomicU64 = AtomicU64::new(0);
static PAGE_CACHE_TEST_UNCHARGED_BYTES: AtomicU64 = AtomicU64::new(0);
static PAGE_CACHE_TEST_ALLOCS: AtomicU64 = AtomicU64::new(0);
static PAGE_CACHE_TEST_PRESSURE_ATTEMPTS: AtomicU64 = AtomicU64::new(0);

fn page_cache_test_charge(_owner: u64, bytes: u64) -> bool {
    PAGE_CACHE_TEST_CHARGES.fetch_add(1, Ordering::SeqCst); // lint-fetch-add: allow (self-test counter)
    PAGE_CACHE_TEST_CHARGED_BYTES.fetch_add(bytes, Ordering::SeqCst);
    true
}

fn page_cache_test_reject(_owner: u64, _bytes: u64) -> bool {
    false
}

fn page_cache_test_reject_once(owner: u64, bytes: u64) -> bool {
    let attempt = PAGE_CACHE_TEST_PRESSURE_ATTEMPTS.fetch_add(1, Ordering::SeqCst); // lint-fetch-add: allow (self-test counter)
    attempt != 0 && page_cache_test_charge(owner, bytes)
}

fn page_cache_test_uncharge(_owner: u64, bytes: u64) {
    PAGE_CACHE_TEST_UNCHARGES.fetch_add(1, Ordering::SeqCst); // lint-fetch-add: allow (self-test counter)
    PAGE_CACHE_TEST_UNCHARGED_BYTES.fetch_add(bytes, Ordering::SeqCst);
}

/// Boot-time regression test for RF178-11's non-allocating initialization,
/// hard-cap clamp, pre-allocation charge gate, duplicate-race accounting, and
/// reclaim/drop uncharge symmetry.
pub fn run_page_cache_policy_self_test() {
    PAGE_CACHE_TEST_CHARGES.store(0, Ordering::SeqCst);
    PAGE_CACHE_TEST_UNCHARGES.store(0, Ordering::SeqCst);
    PAGE_CACHE_TEST_CHARGED_BYTES.store(0, Ordering::SeqCst);
    PAGE_CACHE_TEST_UNCHARGED_BYTES.store(0, Ordering::SeqCst);
    PAGE_CACHE_TEST_ALLOCS.store(0, Ordering::SeqCst);
    PAGE_CACHE_TEST_PRESSURE_ATTEMPTS.store(0, Ordering::SeqCst);

    {
        let capped = GlobalPageCache::new(u64::MAX);
        assert_eq!(capped.stats().max_pages, PAGE_CACHE_MAX_PAGES);
        let structural_bytes = core::mem::size_of::<PageCacheEntry>()
            + 2 * core::mem::size_of::<usize>() // Arc strong/weak header
            + 2 * core::mem::size_of::<((InodeId, PageIndex), Arc<PageCacheEntry>)>()
            + 2 * core::mem::size_of::<LruEntry>();
        assert!(
            structural_bytes <= PAGE_CACHE_METADATA_BYTES_PER_PAGE,
            "per-page metadata estimate must cover structures plus 2x Vec slack"
        );
        assert_eq!(
            capped.lru.lock().entries.capacity(),
            0,
            "LRU construction must not preallocate heap metadata"
        );
        assert_eq!(
            capped.stats().index_capacity,
            0,
            "page-cache index construction must not preallocate metadata"
        );
    }

    // A rejected memory.max charge must happen before the frame allocator.
    {
        let rejected = GlobalPageCache::new(1);
        let result = find_or_create_page_in(
            &rejected,
            1,
            0,
            77,
            page_cache_test_reject,
            page_cache_test_uncharge,
            || {
                PAGE_CACHE_TEST_ALLOCS.fetch_add(1, Ordering::SeqCst); // lint-fetch-add: allow (self-test counter)
                buddy_allocator::alloc_physical_pages(1)
                    .map(|frame| frame.start_address().as_u64() / PAGE_SIZE as u64)
            },
        );
        assert!(result.is_none());
        assert_eq!(PAGE_CACHE_TEST_ALLOCS.load(Ordering::SeqCst), 0);
        assert_eq!(rejected.stats().nr_pages, 0);
        assert_eq!(rejected.allocated_slots.load(Ordering::SeqCst), 0);
    }

    // A successful charge followed by either metadata-admission failure or
    // frame-allocation failure is refunded exactly once by the RAII token.
    {
        let charges = PAGE_CACHE_TEST_CHARGES.load(Ordering::SeqCst);
        let uncharges = PAGE_CACHE_TEST_UNCHARGES.load(Ordering::SeqCst);
        let zero_capacity = GlobalPageCache::new(0);
        assert!(find_or_create_page_in(
            &zero_capacity,
            10,
            0,
            80,
            page_cache_test_charge,
            page_cache_test_uncharge,
            || None,
        )
        .is_none());
        assert_eq!(PAGE_CACHE_TEST_CHARGES.load(Ordering::SeqCst), charges + 1);
        assert_eq!(
            PAGE_CACHE_TEST_UNCHARGES.load(Ordering::SeqCst),
            uncharges + 1
        );
        assert_eq!(zero_capacity.allocated_slots.load(Ordering::SeqCst), 0);
    }
    {
        let charges = PAGE_CACHE_TEST_CHARGES.load(Ordering::SeqCst);
        let uncharges = PAGE_CACHE_TEST_UNCHARGES.load(Ordering::SeqCst);
        let no_frame = GlobalPageCache::new(1);
        assert!(find_or_create_page_in(
            &no_frame,
            11,
            0,
            81,
            page_cache_test_charge,
            page_cache_test_uncharge,
            || None,
        )
        .is_none());
        assert_eq!(PAGE_CACHE_TEST_CHARGES.load(Ordering::SeqCst), charges + 1);
        assert_eq!(
            PAGE_CACHE_TEST_UNCHARGES.load(Ordering::SeqCst),
            uncharges + 1
        );
        assert_eq!(no_frame.allocated_slots.load(Ordering::SeqCst), 0);
    }

    // A denied tenant at the global cap may scan only its own pages. It must
    // neither evict another owner nor reach the frame allocator.
    {
        let cache = GlobalPageCache::new(1);
        let seed = find_or_create_page_in(
            &cache,
            12,
            0,
            90,
            page_cache_test_charge,
            page_cache_test_uncharge,
            || {
                PAGE_CACHE_TEST_ALLOCS.fetch_add(1, Ordering::SeqCst); // lint-fetch-add: allow (self-test counter)
                buddy_allocator::alloc_physical_pages(1)
                    .map(|frame| frame.start_address().as_u64() / PAGE_SIZE as u64)
            },
        )
        .expect("cross-tenant ordering seed");
        drop(seed);
        let allocs = PAGE_CACHE_TEST_ALLOCS.load(Ordering::SeqCst);
        let uncharges = PAGE_CACHE_TEST_UNCHARGES.load(Ordering::SeqCst);
        let denied = find_or_create_page_in(
            &cache,
            13,
            0,
            91,
            page_cache_test_reject,
            page_cache_test_uncharge,
            || {
                PAGE_CACHE_TEST_ALLOCS.fetch_add(1, Ordering::SeqCst); // lint-fetch-add: allow (self-test counter)
                None
            },
        );
        assert!(denied.is_none());
        assert_eq!(PAGE_CACHE_TEST_ALLOCS.load(Ordering::SeqCst), allocs);
        assert_eq!(PAGE_CACHE_TEST_UNCHARGES.load(Ordering::SeqCst), uncharges);
        assert!(cache.find_get_page(12, 0).is_some());
        assert_eq!(cache.stats().nr_pages, 1);
        assert_eq!(cache.allocated_slots.load(Ordering::SeqCst), 1);
        drop(cache);
    }

    // Deterministic shrink/admission interleaving: the detached tail node is
    // reserved, so a concurrent-style admission must use another node and the
    // old page can be restored without allocation or capacity growth.
    {
        let cache = GlobalPageCache::new(2);
        let seed = find_or_create_page_in(
            &cache,
            14,
            0,
            92,
            page_cache_test_charge,
            page_cache_test_uncharge,
            || {
                PAGE_CACHE_TEST_ALLOCS.fetch_add(1, Ordering::SeqCst); // lint-fetch-add: allow (self-test counter)
                buddy_allocator::alloc_physical_pages(1)
                    .map(|frame| frame.start_address().as_u64() / PAGE_SIZE as u64)
            },
        )
        .expect("detached-node interleaving seed");
        drop(seed);

        let (detached_idx, detached_page) =
            cache.lru.lock().detach_tail().expect("detach seeded tail");
        {
            let lru = cache.lru.lock();
            assert_ne!(lru.free_head, detached_idx);
            assert!(lru.entries[detached_idx as usize].entry.is_none());
        }

        let admitted = find_or_create_page_in(
            &cache,
            15,
            0,
            93,
            page_cache_test_charge,
            page_cache_test_uncharge,
            || {
                PAGE_CACHE_TEST_ALLOCS.fetch_add(1, Ordering::SeqCst); // lint-fetch-add: allow (self-test counter)
                buddy_allocator::alloc_physical_pages(1)
                    .map(|frame| frame.start_address().as_u64() / PAGE_SIZE as u64)
            },
        )
        .expect("admission while old LRU node is reserved");

        let cache_index = cache.index.write();
        assert!(cache_index
            .get(&(14, 0))
            .map(|indexed| Arc::ptr_eq(indexed, &detached_page))
            .unwrap_or(false));
        let mut lru = cache.lru.lock();
        let capacity_before_restore = lru.entries.capacity();
        lru.restore_detached(detached_idx, detached_page);
        assert_eq!(lru.entries.capacity(), capacity_before_restore);
        assert_eq!(lru.len(), 2);
        drop(lru);
        drop(cache_index);

        assert!(cache.find_get_page(14, 0).is_some());
        assert_eq!(cache.stats().nr_pages, 2);
        drop(admitted);
        drop(cache);
    }

    {
        let base_charges = PAGE_CACHE_TEST_CHARGES.load(Ordering::SeqCst);
        let base_uncharges = PAGE_CACHE_TEST_UNCHARGES.load(Ordering::SeqCst);
        let base_allocs = PAGE_CACHE_TEST_ALLOCS.load(Ordering::SeqCst);
        let cache = GlobalPageCache::new(1);
        let alloc_page = || {
            PAGE_CACHE_TEST_ALLOCS.fetch_add(1, Ordering::SeqCst); // lint-fetch-add: allow (self-test counter)
            buddy_allocator::alloc_physical_pages(1)
                .map(|frame| frame.start_address().as_u64() / PAGE_SIZE as u64)
        };
        let first = find_or_create_page_in(
            &cache,
            2,
            0,
            42,
            page_cache_test_charge,
            page_cache_test_uncharge,
            alloc_page,
        )
        .expect("page-cache test first admission");
        assert_eq!(first.owner_cgroup_id(), 42);
        let retained_index_capacity = cache.stats().index_capacity;
        assert!(retained_index_capacity >= 1);

        let duplicate = find_or_create_page_in(
            &cache,
            2,
            0,
            99,
            page_cache_test_charge,
            page_cache_test_uncharge,
            || {
                PAGE_CACHE_TEST_ALLOCS.fetch_add(1, Ordering::SeqCst); // lint-fetch-add: allow (self-test counter)
                None
            },
        )
        .expect("page-cache duplicate lookup");
        assert!(Arc::ptr_eq(&first, &duplicate));
        assert_eq!(
            PAGE_CACHE_TEST_CHARGES.load(Ordering::SeqCst),
            base_charges + 1
        );
        assert_eq!(
            PAGE_CACHE_TEST_ALLOCS.load(Ordering::SeqCst),
            base_allocs + 1
        );
        assert_eq!(cache.allocated_slots.load(Ordering::SeqCst), 1);
        assert!(
            !cache.remove_from_cache(2, 0),
            "external Arcs must prevent early slot/accounting release"
        );
        assert_eq!(cache.allocated_slots.load(Ordering::SeqCst), 1);
        drop(first);
        drop(duplicate);

        // Capacity one forces reclaim before the second admission. The first
        // origin is uncharged before the second page is published.
        let replacement = find_or_create_page_in(
            &cache,
            2,
            1,
            43,
            page_cache_test_charge,
            page_cache_test_uncharge,
            || {
                PAGE_CACHE_TEST_ALLOCS.fetch_add(1, Ordering::SeqCst); // lint-fetch-add: allow (self-test counter)
                buddy_allocator::alloc_physical_pages(1)
                    .map(|frame| frame.start_address().as_u64() / PAGE_SIZE as u64)
            },
        )
        .expect("page-cache reclaim-first replacement");
        assert_eq!(replacement.owner_cgroup_id(), 43);
        assert_eq!(cache.stats().nr_pages, 1);
        assert_eq!(cache.stats().lru_len, 1);
        assert_eq!(cache.stats().index_capacity, retained_index_capacity);
        assert_eq!(cache.allocated_slots.load(Ordering::SeqCst), 1);
        assert_eq!(
            PAGE_CACHE_TEST_UNCHARGES.load(Ordering::SeqCst),
            base_uncharges + 1
        );
        drop(replacement);
        drop(cache);
    }

    // A memory.max refusal below the global cap reclaims only the same owner's
    // clean page, retries the atomic charge, and then admits the replacement.
    {
        let cache = GlobalPageCache::new(2);
        let old = find_or_create_page_in(
            &cache,
            3,
            0,
            55,
            page_cache_test_charge,
            page_cache_test_uncharge,
            || {
                PAGE_CACHE_TEST_ALLOCS.fetch_add(1, Ordering::SeqCst); // lint-fetch-add: allow (self-test counter)
                buddy_allocator::alloc_physical_pages(1)
                    .map(|frame| frame.start_address().as_u64() / PAGE_SIZE as u64)
            },
        )
        .expect("page-cache owner-pressure seed");
        drop(old);

        let replacement = find_or_create_page_in(
            &cache,
            3,
            1,
            55,
            page_cache_test_reject_once,
            page_cache_test_uncharge,
            || {
                PAGE_CACHE_TEST_ALLOCS.fetch_add(1, Ordering::SeqCst); // lint-fetch-add: allow (self-test counter)
                buddy_allocator::alloc_physical_pages(1)
                    .map(|frame| frame.start_address().as_u64() / PAGE_SIZE as u64)
            },
        )
        .expect("page-cache owner-pressure replacement");
        assert_eq!(PAGE_CACHE_TEST_PRESSURE_ATTEMPTS.load(Ordering::SeqCst), 2);
        assert!(cache.find_get_page(3, 0).is_none());
        assert_eq!(cache.stats().nr_pages, 1);
        drop(replacement);
        drop(cache);
    }

    assert_eq!(PAGE_CACHE_TEST_CHARGES.load(Ordering::SeqCst), 9);
    assert_eq!(PAGE_CACHE_TEST_UNCHARGES.load(Ordering::SeqCst), 9);
    assert_eq!(
        PAGE_CACHE_TEST_CHARGED_BYTES.load(Ordering::SeqCst),
        PAGE_CACHE_TEST_UNCHARGED_BYTES.load(Ordering::SeqCst),
        "every accepted page-cache cgroup charge must telescope exactly"
    );
}

/// Memory pressure callback interface
///
/// Called by the memory allocator when memory is low.
pub trait MemoryPressureHandler: Send + Sync {
    /// Called when memory pressure is detected
    fn on_memory_pressure(&self, nr_pages_needed: usize) -> usize;
}

/// Page cache memory pressure handler
pub struct PageCachePressureHandler;

impl MemoryPressureHandler for PageCachePressureHandler {
    fn on_memory_pressure(&self, nr_pages_needed: usize) -> usize {
        // First, try to reclaim clean pages
        let freed = reclaim_pages(nr_pages_needed);

        if freed < nr_pages_needed {
            // Not enough clean pages, need to writeback dirty pages first
            // In a real implementation, this would trigger async writeback
            // For now, we just report how many we could free
            klog!(
                Warn,
                "Page cache: memory pressure, freed {} pages (needed {})",
                freed,
                nr_pages_needed
            );
        }

        freed
    }
}

/// Global memory pressure handler instance
pub static PRESSURE_HANDLER: PageCachePressureHandler = PageCachePressureHandler;
