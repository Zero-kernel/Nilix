//! R192-RES-2: eager population of a reserved user range in bounded
//! page-table holds.
//!
//! `brk` grow, private `mmap`, `mprotect` Path A and the `mremap` grow tail
//! back every page of their range before they return. They used to allocate,
//! zero and map the whole range in one `PT_LOCK` hold with interrupts off,
//! bounded only by the kernel heap of the rollback list, and the buddy
//! allocator's OOM handling ran inside that hold. This driver allocates and
//! zeroes frames with no lock held and maps at most [`POPULATE_CHUNK_PAGES`]
//! pages per hold. A failure, or a fatal signal between chunks, unmaps the
//! mapped prefix in holds of the same size, so the operation stays
//! all-or-nothing.
//!
//! The caller owns the range exclusively while the lock is dropped between
//! holds (`PENDING_MAP`, `PENDING_MPROTECT`, the brk reservation or the mremap
//! claim; fork refuses all of them), so the mapped pages are exactly the
//! prefix `0..done` and nothing else maps, unmaps or reprotects them.
//!
//! The driver is pure. The kernel backend is `syscall::EagerPopulator`; the
//! hosted tests drive a model.

/// Most pages one page-table hold maps or unmaps.
pub const POPULATE_CHUNK_PAGES: usize = 64;

/// Where an eager population ran out of memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PopulateStage {
    /// The request exceeds the free frames; refused before any allocation.
    Precheck,
    /// A data-frame allocation failed.
    DataFrame,
    /// `map_page` failed: no frame for a page table, or an occupied page.
    MapPage,
}

/// Why an eager population did not complete. Every mapped page is unmapped
/// again before the error is returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PopulateError {
    NoMemory(PopulateStage),
    /// A fatal signal arrived between chunks.
    Interrupted,
}

/// The page-table side of an eager population. Page indexes are relative to
/// the start of the range.
pub trait PopulateBackend {
    type Frame: Copy;

    /// Free physical pages now, for the fail-fast precheck; `None` skips it.
    fn free_pages(&mut self) -> Option<usize>;
    /// Whether the calling task has to die. Called between chunks, with no
    /// page-table lock held.
    fn fatal_signal_pending(&mut self) -> bool;
    /// One zeroed data frame, allocated with no page-table lock held.
    fn alloc_zeroed(&mut self) -> Option<Self::Frame>;
    /// Return a data frame that never became reachable through a PTE.
    fn free_unmapped(&mut self, frame: Self::Frame);
    /// Map `frames[i]` at page `first + i`, in holds of at most this chunk
    /// (usually one). On `Err(k)` the frame at index `k` is not mapped, and
    /// before returning the backend has unmapped pages `first..first + k`,
    /// flushed them, freed their frames and pruned the tables of
    /// `first..=first + k` (`map_page` may have built tables for the failing
    /// page). Frames `k..` stay the caller's.
    fn map_hold(&mut self, first: usize, frames: &[Self::Frame]) -> Result<(), usize>;
    /// Unmap pages `first..first + count`, all mapped by this population, in
    /// one hold: flush them, free their frames and prune the tables of the
    /// range.
    fn unmap_hold(&mut self, first: usize, count: usize);
}

/// Back pages `0..pages` with fresh zeroed frames, at most
/// [`POPULATE_CHUNK_PAGES`] per hold. On error nothing stays mapped.
pub fn populate<B: PopulateBackend>(backend: &mut B, pages: usize) -> Result<(), PopulateError> {
    if backend.free_pages().is_some_and(|free| pages > free) {
        return Err(PopulateError::NoMemory(PopulateStage::Precheck));
    }

    let mut done = 0;
    while done < pages {
        if done != 0 && backend.fatal_signal_pending() {
            rollback(backend, done);
            return Err(PopulateError::Interrupted);
        }

        let count = (pages - done).min(POPULATE_CHUNK_PAGES);
        let Some(head) = backend.alloc_zeroed() else {
            rollback(backend, done);
            return Err(PopulateError::NoMemory(PopulateStage::DataFrame));
        };
        // Staged on the stack: the forward path takes no kernel heap.
        let mut staged = [head; POPULATE_CHUNK_PAGES];
        for index in 1..count {
            match backend.alloc_zeroed() {
                Some(frame) => staged[index] = frame,
                None => {
                    for &frame in &staged[..index] {
                        backend.free_unmapped(frame);
                    }
                    rollback(backend, done);
                    return Err(PopulateError::NoMemory(PopulateStage::DataFrame));
                }
            }
        }

        if let Err(mapped) = backend.map_hold(done, &staged[..count]) {
            for &frame in &staged[mapped.min(count)..count] {
                backend.free_unmapped(frame);
            }
            rollback(backend, done);
            return Err(PopulateError::NoMemory(PopulateStage::MapPage));
        }
        done += count;
    }
    Ok(())
}

/// Unmap pages `0..mapped`, all mapped by this population, from the top down
/// in the chunks that mapped them, at most [`POPULATE_CHUNK_PAGES`] pages per
/// hold. Each hold prunes the spans of its own pages, so a table is pruned by
/// the hold that removes the last of this population's leaves under it.
pub fn rollback<B: PopulateBackend>(backend: &mut B, mapped: usize) {
    let mut end = mapped;
    while end > 0 {
        let start = (end - 1) / POPULATE_CHUNK_PAGES * POPULATE_CHUNK_PAGES;
        backend.unmap_hold(start, end - start);
        end = start;
    }
}

/// How many of `recorded` are not in `pruned`: the page-table frames a failed
/// population built and its rollback left in place. Sorts both slices, so it
/// is `O(n log n)` and is meant to run with no lock held.
pub fn count_unpruned<T: Ord>(recorded: &mut [T], pruned: &mut [T]) -> usize {
    recorded.sort_unstable();
    pruned.sort_unstable();
    let mut pruned = pruned.iter().peekable();
    recorded
        .iter()
        .filter(|frame| {
            while pruned.next_if(|candidate| candidate < frame).is_some() {}
            pruned.peek() != Some(frame)
        })
        .count()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// A model address range: which frame each page maps, every frame handed
    /// out and returned, every hold and every pruned span.
    struct Model {
        mapped: Vec<Option<u32>>,
        next_frame: u32,
        allocated: Vec<u32>,
        freed: Vec<u32>,
        holds: usize,
        largest_hold: usize,
        pruned: Vec<(usize, usize)>,
        free_pages: Option<usize>,
        fail_alloc_at: Option<usize>,
        fail_map_at: Option<usize>,
        signal_after_holds: Option<usize>,
    }

    impl Model {
        fn new(pages: usize) -> Self {
            Self {
                mapped: vec![None; pages],
                next_frame: 0,
                allocated: Vec::new(),
                freed: Vec::new(),
                holds: 0,
                largest_hold: 0,
                pruned: Vec::new(),
                free_pages: None,
                fail_alloc_at: None,
                fail_map_at: None,
                signal_after_holds: None,
            }
        }

        fn hold(&mut self, pages: usize) {
            assert!(
                pages <= POPULATE_CHUNK_PAGES,
                "a hold touched {pages} pages"
            );
            self.holds += 1;
            self.largest_hold = self.largest_hold.max(pages);
        }

        fn unmap(&mut self, page: usize) {
            let frame = self.mapped[page]
                .take()
                .expect("rollback of an unmapped page");
            self.freed.push(frame);
        }

        /// Whether the pruned spans cover pages `0..end`.
        fn pruned_covers(&self, end: usize) -> bool {
            (0..end).all(|page| {
                self.pruned
                    .iter()
                    .any(|&(first, count)| (first..first + count).contains(&page))
            })
        }

        /// Nothing mapped, and every frame handed out came back exactly once.
        fn assert_rolled_back(&self) {
            assert!(self.mapped.iter().all(Option::is_none));
            let mut allocated = self.allocated.clone();
            let mut freed = self.freed.clone();
            allocated.sort_unstable();
            freed.sort_unstable();
            assert_eq!(allocated, freed, "every frame must be freed exactly once");
        }
    }

    impl PopulateBackend for Model {
        type Frame = u32;

        fn free_pages(&mut self) -> Option<usize> {
            self.free_pages
        }

        fn fatal_signal_pending(&mut self) -> bool {
            self.signal_after_holds
                .is_some_and(|holds| self.holds >= holds)
        }

        fn alloc_zeroed(&mut self) -> Option<u32> {
            if self.fail_alloc_at == Some(self.allocated.len()) {
                return None;
            }
            let frame = self.next_frame;
            self.next_frame += 1;
            self.allocated.push(frame);
            Some(frame)
        }

        fn free_unmapped(&mut self, frame: u32) {
            assert!(self.allocated.contains(&frame));
            self.freed.push(frame);
        }

        fn map_hold(&mut self, first: usize, frames: &[u32]) -> Result<(), usize> {
            self.hold(frames.len());
            for (index, &frame) in frames.iter().enumerate() {
                let page = first + index;
                if self.fail_map_at == Some(page) {
                    for undo in first..page {
                        self.unmap(undo);
                    }
                    self.pruned.push((first, index + 1));
                    return Err(index);
                }
                assert!(self.mapped[page].is_none(), "page {page} mapped twice");
                self.mapped[page] = Some(frame);
            }
            Ok(())
        }

        fn unmap_hold(&mut self, first: usize, count: usize) {
            self.hold(count);
            for page in first..first + count {
                self.unmap(page);
            }
            self.pruned.push((first, count));
        }
    }

    const PAGES: usize = 200;
    const EDGES: [usize; 5] = [
        0,
        POPULATE_CHUNK_PAGES - 1,
        POPULATE_CHUNK_PAGES,
        POPULATE_CHUNK_PAGES + 1,
        PAGES - 1,
    ];

    #[test]
    fn r192_res_2_populate_maps_every_page_in_bounded_holds() {
        for pages in [
            0,
            1,
            POPULATE_CHUNK_PAGES - 1,
            POPULATE_CHUNK_PAGES,
            POPULATE_CHUNK_PAGES + 1,
            PAGES,
        ] {
            let mut model = Model::new(pages);
            model.free_pages = Some(pages);
            assert_eq!(populate(&mut model, pages), Ok(()));
            let mut frames: Vec<u32> = model.mapped.iter().map(|frame| frame.unwrap()).collect();
            frames.sort_unstable();
            frames.dedup();
            assert_eq!(frames.len(), pages, "each page gets its own frame");
            assert!(model.freed.is_empty());
            assert_eq!(model.holds, pages.div_ceil(POPULATE_CHUNK_PAGES));
            assert!(model.largest_hold <= POPULATE_CHUNK_PAGES);
        }
    }

    #[test]
    fn r192_res_2_data_frame_failure_rolls_back_the_mapped_prefix() {
        for fail in EDGES {
            let mut model = Model::new(PAGES);
            model.fail_alloc_at = Some(fail);
            assert_eq!(
                populate(&mut model, PAGES),
                Err(PopulateError::NoMemory(PopulateStage::DataFrame))
            );
            model.assert_rolled_back();
            // The chunks before the failing one were mapped, then pruned.
            let mapped = fail / POPULATE_CHUNK_PAGES * POPULATE_CHUNK_PAGES;
            assert!(model.pruned_covers(mapped), "fail at {fail}");
            assert!(model.largest_hold <= POPULATE_CHUNK_PAGES);
        }
    }

    #[test]
    fn r192_res_2_map_failure_rolls_back_and_prunes_the_failing_page() {
        for fail in EDGES {
            let mut model = Model::new(PAGES);
            model.fail_map_at = Some(fail);
            assert_eq!(
                populate(&mut model, PAGES),
                Err(PopulateError::NoMemory(PopulateStage::MapPage))
            );
            model.assert_rolled_back();
            assert!(model.pruned_covers(fail + 1), "fail at {fail}");
            assert!(model.largest_hold <= POPULATE_CHUNK_PAGES);
        }
    }

    #[test]
    fn r192_res_2_precheck_refuses_before_any_allocation() {
        let mut model = Model::new(PAGES);
        model.free_pages = Some(PAGES - 1);
        assert_eq!(
            populate(&mut model, PAGES),
            Err(PopulateError::NoMemory(PopulateStage::Precheck))
        );
        assert!(model.allocated.is_empty());
        assert_eq!(model.holds, 0);
    }

    #[test]
    fn r192_res_2_fatal_signal_between_chunks_rolls_back() {
        let mut model = Model::new(PAGES);
        model.signal_after_holds = Some(1);
        assert_eq!(populate(&mut model, PAGES), Err(PopulateError::Interrupted));
        model.assert_rolled_back();
        assert_eq!(model.allocated.len(), POPULATE_CHUNK_PAGES);
        assert!(model.pruned_covers(POPULATE_CHUNK_PAGES));

        // A signal that is already pending never stops the first chunk: the
        // poll runs between chunks only.
        let mut model = Model::new(POPULATE_CHUNK_PAGES);
        model.signal_after_holds = Some(0);
        assert_eq!(populate(&mut model, POPULATE_CHUNK_PAGES), Ok(()));
    }

    #[test]
    fn r192_res_2_count_unpruned_matches_a_set_difference() {
        let mut recorded = [9u32, 3, 7, 1, 5];
        let mut pruned = [4u32, 7, 1, 8];
        assert_eq!(count_unpruned(&mut recorded, &mut pruned), 3);
        assert_eq!(count_unpruned::<u32>(&mut [], &mut [1, 2]), 0);
        assert_eq!(count_unpruned(&mut [2u32, 6], &mut []), 2);
        let mut all = [6u32, 2];
        assert_eq!(count_unpruned(&mut [2u32, 6], &mut all), 0);
    }

    #[test]
    fn r192_res_2_rollback_unmaps_top_down_in_bounded_holds() {
        let mut model = Model::new(PAGES);
        assert_eq!(populate(&mut model, PAGES), Ok(()));
        rollback(&mut model, PAGES);
        model.assert_rolled_back();
        assert_eq!(
            model.pruned.first(),
            Some(&(3 * POPULATE_CHUNK_PAGES, PAGES - 3 * POPULATE_CHUNK_PAGES))
        );
        assert_eq!(model.pruned.last(), Some(&(0, POPULATE_CHUNK_PAGES)));
        assert!(model.largest_hold <= POPULATE_CHUNK_PAGES);
    }
}
