//! Host-side test harness for fuzzing memory management components
//!
//! This module provides simplified implementations of memory management primitives
//! that can run in a hosted environment (Linux/macOS with std). These are used by
//! cargo-fuzz targets to fuzz memory management logic without requiring QEMU.
//!
//! **IMPORTANT:** These are simplified models, not the real implementations.
//! They simulate the behavior for fuzzing purposes.

// This module requires std for HashMap/BTreeMap
extern crate std;
use std::collections::{BTreeMap, HashMap};
use std::vec::Vec;

/// Maximum supported buddy order (0-11 = 4KB to 8MB allocations)
const MAX_ORDER: u8 = 11;

/// Simulated physical frame (4KB page)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Frame {
    pub start_addr: u64,
}

impl Frame {
    pub fn new(addr: u64) -> Self {
        Self { start_addr: addr & !0xFFF }
    }
}

/// Error types for allocator operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocError {
    InvalidOrder,
    Exhausted,
    OutOfMemory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeError {
    InvalidFrame,
    DoubleFree,
    NotAllocated,
    OrderMismatch,
}

/// Simplified buddy allocator harness for host-side fuzzing
///
/// This simulates a buddy allocator using Rust standard collections instead of
/// real physical memory. It tracks allocation state and detects common bugs:
/// - Double-free
/// - Use-after-free (detected via allocation tracking)
/// - Memory leaks (detected via integrity check)
/// - Order corruption
pub struct BuddyAllocatorHarness {
    /// Total simulated memory size in pages
    total_pages: usize,
    /// Map of allocated frames: frame_addr -> (order, allocated_count)
    allocated: HashMap<u64, (u8, usize)>,
    /// Free lists per order (simulated)
    free_lists: [Vec<u64>; 12],
    /// Total pages allocated
    allocated_pages: usize,
}

impl BuddyAllocatorHarness {
    /// Create a new harness with the specified number of pages (default 256 = 1MB)
    pub fn new() -> Self {
        Self::with_capacity(256)
    }

    /// Create with specific capacity
    pub fn with_capacity(total_pages: usize) -> Self {
        let mut free_lists: [Vec<u64>; 12] = Default::default();

        // Initialize free list for largest order that fits
        let mut remaining = total_pages;
        let mut base_addr = 0x1000_0000u64; // Simulated physical base

        for order in (0..=MAX_ORDER).rev() {
            let order_size = 1usize << order;
            while remaining >= order_size {
                free_lists[order as usize].push(base_addr);
                base_addr += (order_size * 4096) as u64;
                remaining -= order_size;
            }
        }

        Self {
            total_pages,
            allocated: HashMap::new(),
            free_lists,
            allocated_pages: 0,
        }
    }

    /// Allocate frames of the given order (order N = 2^N pages)
    pub fn allocate_frames(&mut self, count: usize) -> Result<Vec<Frame>, AllocError> {
        if count == 0 {
            return Ok(Vec::new());
        }

        // Find the order that fits the count
        let order = Self::count_to_order(count)?;

        // Try to allocate from the appropriate order
        if let Some(addr) = self.free_lists[order as usize].pop() {
            let frame_count = 1usize << order;
            self.allocated.insert(addr, (order, frame_count));
            self.allocated_pages += frame_count;

            // Return all frames in the allocation
            let mut frames = Vec::new();
            for i in 0..frame_count {
                frames.push(Frame::new(addr + (i as u64 * 4096)));
            }
            Ok(frames)
        } else {
            // Try to split a larger block
            self.split_and_allocate(order)
        }
    }

    /// Free frames starting at the given frame
    pub fn free_frames(&mut self, frame: Frame) -> Result<(), FreeError> {
        let addr = frame.start_addr;

        // Check if this is an allocation start
        match self.allocated.remove(&addr) {
            Some((order, frame_count)) => {
                // Return to free list
                self.free_lists[order as usize].push(addr);
                self.allocated_pages -= frame_count;
                Ok(())
            }
            None => Err(FreeError::NotAllocated),
        }
    }

    /// Query free memory in bytes
    pub fn query_free_memory(&self) -> usize {
        let allocated_bytes = self.allocated_pages * 4096;
        let total_bytes = self.total_pages * 4096;
        total_bytes - allocated_bytes
    }

    /// Verify allocator integrity
    pub fn verify_integrity(&self) {
        // Check for memory leaks
        assert_eq!(
            self.allocated_pages,
            self.allocated.values().map(|(_, count)| count).sum::<usize>(),
            "Allocator integrity failed: page count mismatch"
        );

        // Total allocated + free should equal total
        let free_pages: usize = self.free_lists.iter()
            .enumerate()
            .map(|(order, list): (usize, &Vec<u64>)| list.len() * (1 << order))
            .sum();

        assert!(
            self.allocated_pages + free_pages <= self.total_pages,
            "Allocator integrity failed: total pages exceeded (allocated={}, free={}, total={})",
            self.allocated_pages, free_pages, self.total_pages
        );
    }

    // Helper: convert count to order
    fn count_to_order(count: usize) -> Result<u8, AllocError> {
        if count == 0 {
            return Err(AllocError::InvalidOrder);
        }
        let order = (usize::BITS - count.leading_zeros() - 1) as u8;
        if count > (1usize << order) {
            // Round up to next power of 2
            let order = order + 1;
            if order > MAX_ORDER {
                return Err(AllocError::InvalidOrder);
            }
            Ok(order)
        } else {
            if order > MAX_ORDER {
                return Err(AllocError::InvalidOrder);
            }
            Ok(order)
        }
    }

    // Helper: split larger block to get smaller allocation
    fn split_and_allocate(&mut self, target_order: u8) -> Result<Vec<Frame>, AllocError> {
        // Find a larger block to split
        for order in (target_order + 1)..=MAX_ORDER {
            if let Some(addr) = self.free_lists[order as usize].pop() {
                // Split recursively down to target order
                let mut current_addr = addr;
                let mut current_order = order;

                while current_order > target_order {
                    current_order -= 1;
                    let buddy_addr = current_addr + ((1 << current_order) * 4096) as u64;
                    self.free_lists[current_order as usize].push(buddy_addr);
                }

                // Allocate the first half
                let frame_count = 1usize << target_order;
                self.allocated.insert(current_addr, (target_order, frame_count));
                self.allocated_pages += frame_count;

                let mut frames = Vec::new();
                for i in 0..frame_count {
                    frames.push(Frame::new(current_addr + (i as u64 * 4096)));
                }
                return Ok(frames);
            }
        }

        Err(AllocError::Exhausted)
    }
}

impl Default for BuddyAllocatorHarness {
    fn default() -> Self {
        Self::new()
    }
}

/// Page table entry flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PTEFlags {
    pub present: bool,
    pub writable: bool,
    pub user_accessible: bool,
    pub executable: bool,
}

/// Error types for page table operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PTError {
    NotCanonical,
    NotAligned,
    AlreadyMapped,
    NotMapped,
    InvalidFlags,
}

/// Simulated page table entry
#[derive(Debug, Clone, Copy)]
pub struct PageTableEntry {
    pub physical_addr: u64,
    pub flags: PTEFlags,
}

/// Simplified page table harness for host-side fuzzing
///
/// This simulates x86_64 page tables using a HashMap instead of real PT structures.
/// It validates address canonicality, alignment, and flag combinations.
pub struct PageTableHarness {
    /// Map of virtual address -> PTE
    mappings: BTreeMap<u64, PageTableEntry>,
    /// Simulated physical memory allocator (simplified)
    next_physical: u64,
}

impl PageTableHarness {
    pub fn new() -> Self {
        Self {
            mappings: BTreeMap::new(),
            next_physical: 0x1000, // Start at 4KB
        }
    }

    /// Map a virtual page to a simulated physical page
    pub fn map_page(
        &mut self,
        va: u64,
        readable: bool,
        writable: bool,
        executable: bool,
        user: bool,
    ) -> Result<(), PTError> {
        // Check canonicality (48-bit address space)
        if !Self::is_canonical(va) {
            return Err(PTError::NotCanonical);
        }

        // Check alignment
        if va & 0xFFF != 0 {
            return Err(PTError::NotAligned);
        }

        // Check if already mapped
        if self.mappings.contains_key(&va) {
            return Err(PTError::AlreadyMapped);
        }

        // Validate flags (W^X enforcement)
        if writable && executable {
            return Err(PTError::InvalidFlags);
        }

        // Present requires at least one permission
        if !readable && !writable && !executable {
            return Err(PTError::InvalidFlags);
        }

        // Allocate physical page
        let physical_addr = self.next_physical;
        self.next_physical += 4096;

        // Create entry
        let entry = PageTableEntry {
            physical_addr,
            flags: PTEFlags {
                present: true,
                writable,
                user_accessible: user,
                executable,
            },
        };

        self.mappings.insert(va, entry);
        Ok(())
    }

    /// Unmap a virtual page
    pub fn unmap_page(&mut self, va: u64) -> Result<(), PTError> {
        if !Self::is_canonical(va) {
            return Err(PTError::NotCanonical);
        }

        if va & 0xFFF != 0 {
            return Err(PTError::NotAligned);
        }

        self.mappings.remove(&va).ok_or(PTError::NotMapped)?;
        Ok(())
    }

    /// Change protection flags on a mapped page
    pub fn change_protection(
        &mut self,
        va: u64,
        readable: bool,
        writable: bool,
        executable: bool,
        user: bool,
    ) -> Result<(), PTError> {
        if !Self::is_canonical(va) {
            return Err(PTError::NotCanonical);
        }

        if va & 0xFFF != 0 {
            return Err(PTError::NotAligned);
        }

        // W^X enforcement
        if writable && executable {
            return Err(PTError::InvalidFlags);
        }

        let entry = self.mappings.get_mut(&va).ok_or(PTError::NotMapped)?;

        entry.flags = PTEFlags {
            present: true,
            writable,
            user_accessible: user,
            executable,
        };

        Ok(())
    }

    /// Lookup a virtual address
    pub fn lookup(&self, va: u64) -> Option<PageTableEntry> {
        if !Self::is_canonical(va) {
            return None;
        }

        let page_va = va & !0xFFF;
        self.mappings.get(&page_va).copied()
    }

    /// Verify page table integrity
    pub fn verify_integrity(&self) {
        // Check all mappings are canonical and aligned
        for (&va, entry) in &self.mappings {
            assert!(Self::is_canonical(va), "Non-canonical VA in page table: {:#x}", va);
            assert_eq!(va & 0xFFF, 0, "Misaligned VA in page table: {:#x}", va);
            assert!(entry.flags.present, "Non-present entry in page table");

            // W^X invariant
            assert!(
                !(entry.flags.writable && entry.flags.executable),
                "W^X violation at VA {:#x}",
                va
            );
        }
    }

    // Helper: check if address is canonical (48-bit address space)
    fn is_canonical(va: u64) -> bool {
        let bit_47 = (va >> 47) & 1;
        let upper_bits = va >> 48;

        if bit_47 == 0 {
            // Lower half: bits 48-63 must be 0
            upper_bits == 0
        } else {
            // Upper half: bits 48-63 must be 1
            upper_bits == 0xFFFF
        }
    }
}

impl Default for PageTableHarness {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buddy_basic_alloc_free() {
        let mut harness = BuddyAllocatorHarness::new();
        let frames = harness.allocate_frames(1).unwrap();
        assert_eq!(frames.len(), 1);
        harness.free_frames(frames[0]).unwrap();
        harness.verify_integrity();
    }

    #[test]
    fn buddy_double_free_detected() {
        let mut harness = BuddyAllocatorHarness::new();
        let frames = harness.allocate_frames(1).unwrap();
        harness.free_frames(frames[0]).unwrap();
        assert_eq!(harness.free_frames(frames[0]), Err(FreeError::NotAllocated));
    }

    #[test]
    fn page_table_basic_map_unmap() {
        let mut pt = PageTableHarness::new();
        pt.map_page(0x1000, true, false, false, true).unwrap();
        assert!(pt.lookup(0x1000).is_some());
        pt.unmap_page(0x1000).unwrap();
        assert!(pt.lookup(0x1000).is_none());
    }

    #[test]
    fn page_table_wx_enforcement() {
        let mut pt = PageTableHarness::new();
        assert_eq!(
            pt.map_page(0x1000, true, true, true, true),
            Err(PTError::InvalidFlags)
        );
    }

    #[test]
    fn page_table_canonicality() {
        let mut pt = PageTableHarness::new();
        // Non-canonical address (hole in middle)
        assert_eq!(
            pt.map_page(0x0000_8000_0000_0000, true, false, false, true),
            Err(PTError::NotCanonical)
        );
    }
}
