//! Bounded memory-management capability primitives.
//!
//! These are deliberately small, allocation-fallible building blocks for the
//! 3.3 roadmap slice.  They keep ownership and admission explicit while the
//! architecture-specific page-table integration is added by later consumers.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use crate::{try_reserve_heap, vec_charge_bytes, AdmittedVec, HeapCharge, HeapClass};
use spin::Mutex;

/// Slab object lifecycle error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlabError {
    Full,
    InvalidIndex,
    QuarantineFull,
    Contended,
    Admission,
}

/// A bounded slab cache with admitted storage and a release quarantine.
///
/// `try_free` never blocks: an IRQ or fault path that cannot acquire either
/// lock returns `Contended` and retries from process context.  Freed objects
/// remain quarantined until `drain_quarantine`, preventing immediate reuse of
/// stale pointers while retaining a hard object bound.
pub struct SlabCache<T> {
    slots: Mutex<AdmittedVec<Option<T>>>,
    quarantine: Mutex<AdmittedVec<T>>,
    max_objects: usize,
    allocated: AtomicUsize,
}

impl<T> SlabCache<T> {
    pub fn new(class: HeapClass, max_objects: usize) -> Result<Self, SlabError> {
        if max_objects == 0 {
            return Err(SlabError::Full);
        }
        let mut slots = AdmittedVec::new(class);
        let mut quarantine = AdmittedVec::new(class);
        slots
            .try_reserve(max_objects)
            .map_err(|_| SlabError::Admission)?;
        quarantine
            .try_reserve(max_objects)
            .map_err(|_| SlabError::Admission)?;
        Ok(Self {
            slots: Mutex::new(slots),
            quarantine: Mutex::new(quarantine),
            max_objects,
            allocated: AtomicUsize::new(0),
        })
    }

    pub fn try_alloc(&self, value: T) -> Result<usize, SlabError> {
        let mut slots = self.slots.try_lock().ok_or(SlabError::Contended)?;
        for index in 0..slots.len() {
            if slots.get(index).is_some_and(Option::is_none) {
                *slots.get_mut(index).ok_or(SlabError::InvalidIndex)? = Some(value);
                self.allocated.fetch_add(1, Ordering::Relaxed);
                return Ok(index);
            }
        }
        if slots.len() >= self.max_objects {
            return Err(SlabError::Full);
        }
        slots
            .try_push(Some(value))
            .map_err(|_| SlabError::Admission)?;
        self.allocated.fetch_add(1, Ordering::Relaxed);
        Ok(slots.len() - 1)
    }

    pub fn try_free(&self, index: usize) -> Result<(), SlabError> {
        // Both backings are pre-reserved at construction, so this fixed lock
        // order remains nonblocking and allocation-free for IRQ callers.
        let mut quarantine = self.quarantine.try_lock().ok_or(SlabError::Contended)?;
        let mut slots = self.slots.try_lock().ok_or(SlabError::Contended)?;
        let slot = slots.get_mut(index).ok_or(SlabError::InvalidIndex)?;
        let value = slot.take().ok_or(SlabError::InvalidIndex)?;
        match quarantine.try_push(value) {
            Ok(()) => {
                self.allocated.fetch_sub(1, Ordering::Relaxed);
                Ok(())
            }
            Err((_error, value)) => {
                *slot = Some(value);
                Err(SlabError::QuarantineFull)
            }
        }
    }

    pub fn drain_quarantine(&self, budget: usize) -> usize {
        let Some(mut quarantine) = self.quarantine.try_lock() else {
            return 0;
        };
        let mut drained = 0;
        while drained < budget && quarantine.pop().is_some() {
            drained += 1;
        }
        drained
    }

    pub fn allocated(&self) -> usize {
        self.allocated.load(Ordering::Acquire)
    }

    pub fn capacity(&self) -> usize {
        self.max_objects
    }
}

/// Fixed-size node-aware page accounting.
pub const MAX_NUMA_NODES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NumaAllocation {
    pub node: u16,
    pub pages: usize,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NumaError {
    InvalidNode,
    OutOfMemory,
    StaleAllocation,
}

pub struct NumaAllocator {
    free: [AtomicUsize; MAX_NUMA_NODES],
    generation: AtomicUsize,
}

impl NumaAllocator {
    pub fn new(node_pages: &[usize]) -> Result<Self, NumaError> {
        if node_pages.len() > MAX_NUMA_NODES {
            return Err(NumaError::InvalidNode);
        }
        let allocator = Self {
            free: [const { AtomicUsize::new(0) }; MAX_NUMA_NODES],
            generation: AtomicUsize::new(1),
        };
        for (index, pages) in node_pages.iter().copied().enumerate() {
            allocator.free[index].store(pages, Ordering::Release);
        }
        Ok(allocator)
    }

    pub fn try_alloc(&self, node: usize, pages: usize) -> Result<NumaAllocation, NumaError> {
        if node >= MAX_NUMA_NODES || pages == 0 {
            return Err(NumaError::InvalidNode);
        }
        let cell = &self.free[node];
        let mut current = cell.load(Ordering::Acquire);
        loop {
            let next = current.checked_sub(pages).ok_or(NumaError::OutOfMemory)?;
            match cell.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    let generation = self.generation.fetch_add(1, Ordering::AcqRel) as u64;
                    return Ok(NumaAllocation {
                        node: node as u16,
                        pages,
                        generation,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    pub fn free(&self, allocation: NumaAllocation) -> Result<(), NumaError> {
        let node = allocation.node as usize;
        if node >= MAX_NUMA_NODES || allocation.pages == 0 {
            return Err(NumaError::InvalidNode);
        }
        self.free[node].fetch_add(allocation.pages, Ordering::AcqRel);
        Ok(())
    }

    /// Reserve destination pages before releasing the source, so migration
    /// cannot strand an allocation between nodes.
    pub fn migrate(&self, allocation: &mut NumaAllocation, target: usize) -> Result<(), NumaError> {
        if target >= MAX_NUMA_NODES || allocation.pages == 0 {
            return Err(NumaError::InvalidNode);
        }
        if target == allocation.node as usize {
            return Ok(());
        }
        let destination = self.try_alloc(target, allocation.pages)?;
        self.free(*allocation)?;
        *allocation = destination;
        Ok(())
    }

    pub fn free_pages(&self, node: usize) -> Option<usize> {
        self.free.get(node).map(|cell| cell.load(Ordering::Acquire))
    }
}

const SWAP_FREE: u8 = 0;
const SWAP_RESERVED: u8 = 1;
const SWAP_COMMITTED: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SwapEntry {
    pub slot: u32,
    pub offset: u16,
}

impl SwapEntry {
    pub fn new(slot: u32, offset: u16) -> Option<Self> {
        (offset < 512).then_some(Self { slot, offset })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwapError {
    Invalid,
    Full,
    Stale,
    Admission,
}

/// Slot ownership table for future swap-in/swap-out PTE transitions.
pub struct SwapSlotTable {
    slots: Vec<AtomicU8>,
    _charge: HeapCharge,
}

impl SwapSlotTable {
    pub fn try_new(class: HeapClass, slot_count: usize) -> Result<Self, SwapError> {
        if slot_count == 0 {
            return Err(SwapError::Invalid);
        }
        let bytes = vec_charge_bytes::<AtomicU8>(slot_count).map_err(|_| SwapError::Admission)?;
        let reservation = try_reserve_heap(class, bytes).map_err(|_| SwapError::Admission)?;
        let mut slots = Vec::new();
        if slots.try_reserve_exact(slot_count).is_err() {
            drop(reservation);
            return Err(SwapError::Admission);
        }
        slots.resize_with(slot_count, || AtomicU8::new(SWAP_FREE));
        let mut reservation = reservation;
        let actual =
            vec_charge_bytes::<AtomicU8>(slots.capacity()).map_err(|_| SwapError::Admission)?;
        reservation
            .resize(actual)
            .map_err(|_| SwapError::Admission)?;
        let charge = reservation.commit().map_err(|_| SwapError::Admission)?;
        Ok(Self {
            slots,
            _charge: charge,
        })
    }

    pub fn reserve(&self) -> Result<u32, SwapError> {
        for (index, slot) in self.slots.iter().enumerate() {
            if slot
                .compare_exchange(
                    SWAP_FREE,
                    SWAP_RESERVED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Ok(index as u32);
            }
        }
        Err(SwapError::Full)
    }

    pub fn commit(&self, slot: u32) -> Result<SwapEntry, SwapError> {
        let cell = self.slots.get(slot as usize).ok_or(SwapError::Stale)?;
        cell.compare_exchange(
            SWAP_RESERVED,
            SWAP_COMMITTED,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map_err(|_| SwapError::Stale)?;
        SwapEntry::new(slot, 0).ok_or(SwapError::Invalid)
    }

    pub fn release(&self, entry: SwapEntry) -> Result<(), SwapError> {
        let cell = self
            .slots
            .get(entry.slot as usize)
            .ok_or(SwapError::Stale)?;
        cell.compare_exchange(
            SWAP_COMMITTED,
            SWAP_FREE,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map_err(|_| SwapError::Stale)
        .map(|_| ())
    }

    pub fn committed(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.load(Ordering::Acquire) == SWAP_COMMITTED)
            .count()
    }
}

/// Transparent huge-page geometry and split/merge proof helpers.
pub const THP_SIZE: usize = 2 * 1024 * 1024;
pub const THP_PAGE_COUNT: usize = THP_SIZE / 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThpError {
    Unaligned,
    InvalidLength,
    NotContiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThpMapping {
    pub base: usize,
    pub pages: usize,
}

impl ThpMapping {
    pub fn new(base: usize, length: usize) -> Result<Self, ThpError> {
        if base & (THP_SIZE - 1) != 0 {
            return Err(ThpError::Unaligned);
        }
        if length != THP_SIZE {
            return Err(ThpError::InvalidLength);
        }
        Ok(Self {
            base,
            pages: THP_PAGE_COUNT,
        })
    }

    pub fn split(self) -> [usize; 2] {
        [self.base, self.base + THP_SIZE / 2]
    }

    pub fn can_merge(left: Self, right: Self) -> bool {
        left.pages == THP_PAGE_COUNT
            && right.pages == THP_PAGE_COUNT
            && left.base.checked_add(THP_SIZE) == Some(right.base)
    }
}

/// Focused host oracle for all 3.3 capability primitives.
pub fn run_memory_capability_self_test() {
    let slab = SlabCache::new(HeapClass::CoreProcess, 2).expect("slab setup");
    let first = slab.try_alloc(1u32).expect("slab alloc");
    slab.try_free(first).expect("slab free");
    assert_eq!(slab.drain_quarantine(1), 1);

    let numa = NumaAllocator::new(&[8, 8]).expect("numa setup");
    let mut allocation = numa.try_alloc(0, 4).expect("numa alloc");
    numa.migrate(&mut allocation, 1).expect("numa migrate");
    assert_eq!(allocation.node, 1);

    let swap = SwapSlotTable::try_new(HeapClass::CoreProcess, 2).expect("swap setup");
    let slot = swap.reserve().expect("swap reserve");
    let entry = swap.commit(slot).expect("swap commit");
    assert_eq!(swap.committed(), 1);
    swap.release(entry).expect("swap release");

    let huge = ThpMapping::new(THP_SIZE, THP_SIZE).expect("thp setup");
    let pair = ThpMapping::new(THP_SIZE * 2, THP_SIZE).expect("thp setup");
    assert!(ThpMapping::can_merge(huge, pair));
    assert_eq!(huge.split()[1] - huge.split()[0], THP_SIZE / 2);
}
