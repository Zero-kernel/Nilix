//! C3 (#90): batched TLB invalidation for kernel-stack reclaim.
//!
//! `process::reclaim_kernel_stack` used to end every stack's RCU callback with
//! a CR3-0 flush: one IPI to every other online CPU, and a wait for each
//! acknowledgement, once per thread lifetime. The callback still validates and
//! clears the stack's leaves under `PT_LOCK`, but it now hands the stack to
//! this queue, and one flush covers up to [`KSTACK_FLUSH_BATCH_CAPACITY`]
//! stacks.
//!
//! Until that flush another CPU may still hold a translation to the stack's
//! frames, so the queue keeps both of the stack's resources:
//! - the frames stay allocated, and return to the buddy allocator only after
//!   the flush;
//! - the PID's RCU stack slot stays `FlushPending`, so the PID, and with it
//!   the stack's virtual slot, cannot be allocated again.
//!
//! A batch completes in the order flush, free, release. It completes only
//! under RCU drain ownership: in a stack callback that finds the batch full,
//! in the drain epilogue once the batch is full or its oldest stack is
//! [`KSTACK_FLUSH_BATCH_MAX_AGE_TICKS`] old, or in [`complete_now`]. The
//! drainer is single-owner, so no completion can release a slot between its
//! callback's hand-off and the drainer's `finish_running`.
//!
//! The queue is pure over [`KstackFlushBackend`]. The kernel backend is at the
//! end of this file; the hosted tests drive a model.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;

/// Most stacks one flush covers: 4 MiB of frames (128 × 32 KiB) and 128 PIDs
/// held at once (0.39% of `PID_MAX`), cutting 16-vCPU broadcast CR3=0 TLB
/// shootdowns by 8× while keeping bounded memory and OOM-drain recovery.
pub const KSTACK_FLUSH_BATCH_CAPACITY: usize = 128;

/// A batch completes once its oldest stack has waited this many timer ticks,
/// about one second at the BSP's nominal 1000 Hz.
pub const KSTACK_FLUSH_BATCH_MAX_AGE_TICKS: u64 = 1000;

/// A reclaimed kernel stack whose leaves are cleared but not yet flushed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingStack {
    pub pid: usize,
    /// Physical address of the first frame of the stack's buddy block.
    pub phys: u64,
}

impl PendingStack {
    const EMPTY: Self = Self { pid: 0, phys: 0 };
}

/// What completing a batch does to the machine.
pub trait KstackFlushBackend {
    /// Invalidate the non-global translations of every online CPU; returns
    /// only once each has acknowledged.
    fn flush_all_address_spaces(&mut self);
    /// Return the stack's block to the frame allocator. `false` if the
    /// allocator rejected it.
    fn free_stack(&mut self, stack: PendingStack) -> bool;
    /// Make the PID's stack slot allocatable again.
    fn release_slot(&mut self, pid: usize);
    /// Pin the PID's stack slot for good: its block could not be returned.
    fn quarantine_slot(&mut self, pid: usize);
}

/// Completion counters, for `/proc/schedstat`. `batches - by_count - by_age`
/// is the number of explicit completions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KstackFlushStats {
    /// Completed batches: one CR3-0 flush each.
    pub batches: u64,
    /// Stacks those batches covered.
    pub stacks: u64,
    /// Batches completed because they were full.
    pub by_count: u64,
    /// Batches completed because their oldest stack reached the age bound.
    pub by_age: u64,
    /// Stacks whose block the frame allocator rejected after the flush.
    pub quarantined: u64,
    /// Stacks waiting for their flush now.
    pub pending: usize,
}

#[derive(Clone, Copy)]
enum Trigger {
    Count,
    Age,
    Explicit,
}

struct Batch<const K: usize> {
    stacks: [PendingStack; K],
    len: usize,
    /// Tick at which the oldest stack was added; meaningful while `len != 0`.
    oldest_tick: u64,
}

/// The stacks waiting for one flush, and the counters of completed batches.
///
/// Every mutating call must come from the RCU drain owner; see the module
/// documentation.
pub struct KstackFlushQueue<const K: usize> {
    batch: Mutex<Batch<K>>,
    /// The batch's length, for lock-free empty/capacity checks.
    pending: AtomicUsize,
    /// Tick of the oldest waiting stack; published before `pending` transitions 0 -> 1.
    oldest_tick: AtomicU64,
    max_age_ticks: u64,
    batches: AtomicU64,
    stacks: AtomicU64,
    by_count: AtomicU64,
    by_age: AtomicU64,
    quarantined: AtomicU64,
}

impl<const K: usize> KstackFlushQueue<K> {
    pub const fn new(max_age_ticks: u64) -> Self {
        Self {
            batch: Mutex::new(Batch {
                stacks: [PendingStack::EMPTY; K],
                len: 0,
                oldest_tick: 0,
            }),
            pending: AtomicUsize::new(0),
            oldest_tick: AtomicU64::new(0),
            max_age_ticks,
            batches: AtomicU64::new(0),
            stacks: AtomicU64::new(0),
            by_count: AtomicU64::new(0),
            by_age: AtomicU64::new(0),
            quarantined: AtomicU64::new(0),
        }
    }

    /// Lock-free check whether `drain_epilogue` has a full or age-expired batch
    /// to complete at tick `now`. False positives are harmless (the locked check
    /// re-validates); false negatives are prevented by Release/Acquire ordering
    /// on `oldest_tick` -> `pending`.
    #[inline]
    pub fn needs_epilogue(&self, now: u64) -> bool {
        let count = self.pending.load(Ordering::Acquire);
        if count == 0 {
            return false;
        }
        count >= K
            || now.saturating_sub(self.oldest_tick.load(Ordering::Acquire)) >= self.max_age_ticks
    }

    /// Add a stack whose leaves were cleared at tick `now`. A full batch is
    /// completed first, so `stack` itself is never part of that completion:
    /// its callback is still running.
    pub fn defer<B: KstackFlushBackend>(&self, stack: PendingStack, now: u64, backend: &mut B) {
        let mut full = TakenBatch::EMPTY;
        {
            let mut batch = self.batch.lock();
            if batch.len < K {
                self.push(&mut batch, stack, now);
                return;
            }
            self.take_into(&mut batch, &mut full);
        }
        self.complete(&full, Trigger::Count, backend);
        self.push(&mut self.batch.lock(), stack, now);
    }

    /// Complete the batch if it is full, or if its oldest stack is at least
    /// the age bound old at tick `now`. Takes no lock when nothing is waiting.
    pub fn drain_epilogue<B: KstackFlushBackend>(&self, now: u64, backend: &mut B) {
        if self.pending.load(Ordering::Relaxed) == 0 {
            return;
        }
        let mut due = TakenBatch::EMPTY;
        let trigger = {
            let mut batch = self.batch.lock();
            let trigger = if batch.len == K {
                Trigger::Count
            } else if batch.len != 0 && now.saturating_sub(batch.oldest_tick) >= self.max_age_ticks
            {
                Trigger::Age
            } else {
                return;
            };
            self.take_into(&mut batch, &mut due);
            trigger
        };
        self.complete(&due, trigger, backend);
    }

    /// Complete the batch whatever its size and age. An empty batch does not
    /// flush.
    pub fn complete_now<B: KstackFlushBackend>(&self, backend: &mut B) {
        let mut waiting = TakenBatch::EMPTY;
        self.take_into(&mut self.batch.lock(), &mut waiting);
        if !waiting.is_empty() {
            self.complete(&waiting, Trigger::Explicit, backend);
        }
    }

    pub fn stats(&self) -> KstackFlushStats {
        KstackFlushStats {
            batches: self.batches.load(Ordering::Relaxed),
            stacks: self.stacks.load(Ordering::Relaxed),
            by_count: self.by_count.load(Ordering::Relaxed),
            by_age: self.by_age.load(Ordering::Relaxed),
            quarantined: self.quarantined.load(Ordering::Relaxed),
            pending: self.pending.load(Ordering::Relaxed),
        }
    }

    fn push(&self, batch: &mut Batch<K>, stack: PendingStack, now: u64) {
        assert!(
            batch.len < K,
            "kernel-stack flush batch overflow: a push ran outside drain ownership"
        );
        if batch.len == 0 {
            batch.oldest_tick = now;
            // Publish `oldest_tick` BEFORE `pending` becomes non-zero so lock-free
            // `needs_epilogue()` readers always observe a valid timestamp.
            self.oldest_tick.store(now, Ordering::Release);
        }
        batch.stacks[batch.len] = stack;
        batch.len += 1;
        self.pending.store(batch.len, Ordering::Release);
    }

    /// Empty the batch into a caller-provided stack buffer, so that it
    /// completes with the batch lock dropped and avoids an extra by-value copy.
    fn take_into(&self, batch: &mut Batch<K>, out: &mut TakenBatch<K>) {
        let len = batch.len;
        out.stacks[..len].copy_from_slice(&batch.stacks[..len]);
        out.len = len;
        batch.len = 0;
        self.pending.store(0, Ordering::Release);
    }

    fn complete<B: KstackFlushBackend>(
        &self,
        taken: &TakenBatch<K>,
        trigger: Trigger,
        backend: &mut B,
    ) {
        // No frame returns to the allocator, and no slot becomes allocatable,
        // before every CPU has dropped its translations of these stacks.
        backend.flush_all_address_spaces();
        let mut quarantined = 0u64;
        for &stack in taken.stacks() {
            if backend.free_stack(stack) {
                backend.release_slot(stack.pid);
            } else {
                backend.quarantine_slot(stack.pid);
                quarantined += 1;
            }
        }

        // Statistics only: Relaxed, and a wrap is harmless.
        // lint-fetch-add: allow (statistics counter)
        self.batches.fetch_add(1, Ordering::Relaxed);
        self.stacks.fetch_add(taken.len as u64, Ordering::Relaxed);
        self.quarantined.fetch_add(quarantined, Ordering::Relaxed);
        let by_trigger = match trigger {
            Trigger::Count => &self.by_count,
            Trigger::Age => &self.by_age,
            Trigger::Explicit => return,
        };
        // lint-fetch-add: allow (statistics counter)
        by_trigger.fetch_add(1, Ordering::Relaxed);
    }
}

struct TakenBatch<const K: usize> {
    stacks: [PendingStack; K],
    len: usize,
}

impl<const K: usize> TakenBatch<K> {
    const EMPTY: Self = Self {
        stacks: [PendingStack::EMPTY; K],
        len: 0,
    };

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn stacks(&self) -> &[PendingStack] {
        &self.stacks[..self.len]
    }
}

// ============================================================================
// Kernel backend
// ============================================================================

static KSTACK_FLUSH: KstackFlushQueue<KSTACK_FLUSH_BATCH_CAPACITY> =
    KstackFlushQueue::new(KSTACK_FLUSH_BATCH_MAX_AGE_TICKS);

/// Bounded cache of post-TLB-shootdown, pre-zeroed order-3 kernel-stack blocks.
///
/// Reclaimed kernel stacks are scrubbed to all zeros off the `fork()` critical
/// path (immediately after `flush_all_address_spaces()` completes) and parked
/// here so steady-state `allocate_kernel_stack()` pops an already-zeroed
/// 32 KiB block without acquiring `BUDDY_ALLOCATOR` or zeroing 32 KiB on the
/// parent thread. Sized to match `KSTACK_FLUSH_BATCH_CAPACITY` (128 stacks =
/// 4 MiB) so a full completed flush batch can be retained without spilling 75%
/// of its frames back to Buddy. Drained back to Buddy on `complete_now()` or
/// OOM pressure.
const KSTACK_FRAME_CACHE_CAP: usize = KSTACK_FLUSH_BATCH_CAPACITY;

struct KstackFrameCache {
    frames: [u64; KSTACK_FRAME_CACHE_CAP],
    len: usize,
}

impl KstackFrameCache {
    const fn new() -> Self {
        Self {
            frames: [0; KSTACK_FRAME_CACHE_CAP],
            len: 0,
        }
    }

    /// Try to insert a scrubbed order-3 block base physical address.
    /// Returns `false` if the cache is full or already contains `phys`.
    fn try_push(&mut self, phys: u64) -> bool {
        if self.len >= KSTACK_FRAME_CACHE_CAP {
            return false;
        }
        if self.frames[..self.len].contains(&phys) {
            return false;
        }
        self.frames[self.len] = phys;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<u64> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        let phys = self.frames[self.len];
        self.frames[self.len] = 0;
        Some(phys)
    }

    fn drain_into(&mut self, out: &mut [u64; KSTACK_FRAME_CACHE_CAP]) -> usize {
        let n = self.len;
        out[..n].copy_from_slice(&self.frames[..n]);
        self.frames[..n].fill(0);
        self.len = 0;
        n
    }
}

static KSTACK_FRAME_CACHE: Mutex<KstackFrameCache> = Mutex::new(KstackFrameCache::new());
static KSTACK_FRAME_CACHE_LEN: AtomicUsize = AtomicUsize::new(0);
/// Number of blocks detached from `KSTACK_FRAME_CACHE` by `drain_kstack_frame_cache()`
/// that are currently in flight awaiting return to the buddy allocator.
static KSTACK_FRAME_CACHE_DRAINING: AtomicUsize = AtomicUsize::new(0);

/// Number of pre-zeroed order-3 kernel-stack blocks currently cached or in flight.
#[inline]
pub(crate) fn cached_frame_count() -> usize {
    KSTACK_FRAME_CACHE_LEN
        .load(Ordering::Acquire)
        .saturating_add(KSTACK_FRAME_CACHE_DRAINING.load(Ordering::Acquire))
}

/// Pop one post-shootdown, pre-zeroed order-3 kernel-stack physical block, if cached.
pub(crate) fn try_pop_zeroed_kstack_frame(
) -> Option<x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB>> {
    if KSTACK_FRAME_CACHE_LEN.load(Ordering::Acquire) == 0 {
        return None;
    }
    let phys = x86_64::instructions::interrupts::without_interrupts(|| {
        let mut cache = KSTACK_FRAME_CACHE.lock();
        let phys = cache.pop();
        KSTACK_FRAME_CACHE_LEN.store(cache.len, Ordering::Release);
        phys
    })?;
    x86_64::structures::paging::PhysFrame::from_start_address(x86_64::PhysAddr::new(phys)).ok()
}

/// Return all cached pre-zeroed kernel-stack blocks back to the buddy allocator.
pub(crate) fn drain_kstack_frame_cache() -> usize {
    if KSTACK_FRAME_CACHE_LEN.load(Ordering::Acquire) == 0 {
        return 0;
    }
    let mut drained = [0u64; KSTACK_FRAME_CACHE_CAP];
    let count = x86_64::instructions::interrupts::without_interrupts(|| {
        let mut cache = KSTACK_FRAME_CACHE.lock();
        let n = cache.drain_into(&mut drained);
        if n > 0 {
            // Publish in-flight blocks BEFORE clearing `KSTACK_FRAME_CACHE_LEN` so
            // concurrent reclaim/OOM observers never see an empty cache while blocks
            // are still en route to Buddy.
            // lint-fetch-add: allow (bounded in-flight drain count <= KSTACK_FRAME_CACHE_CAP)
            KSTACK_FRAME_CACHE_DRAINING.fetch_add(n, Ordering::SeqCst);
        }
        KSTACK_FRAME_CACHE_LEN.store(0, Ordering::Release);
        n
    });
    free_drained_kstack_frames(&drained[..count])
}

/// Non-blocking cache-only reclaim hook registered with `mm::oom_killer`.
///
/// Uses `try_lock()` on BOTH `KSTACK_FRAME_CACHE` and Buddy
/// (`try_free_physical_pages_nonblocking`), so it can be invoked safely from
/// general frame-allocation exhaustion and fault paths (`#PF` CoW, shared-anon
/// fault, demand stack growth) with IRQs disabled and zero spinning. Any block
/// rejected with `FreeError::Busy` remains owned by `KSTACK_FRAME_CACHE` and
/// sets `busy = true` even if earlier blocks were freed (preventing partial
/// reclaim from masking contention). In-flight `drain_kstack_frame_cache()`
/// blocks likewise keep `busy = true` until returned to Buddy.
pub(crate) fn reclaim_cached_kstack_pages() -> mm::oom_killer::CacheReclaimResult {
    if KSTACK_FRAME_CACHE_LEN.load(Ordering::Acquire) == 0 {
        return if KSTACK_FRAME_CACHE_DRAINING.load(Ordering::Acquire) > 0 {
            mm::oom_killer::CacheReclaimResult::BUSY
        } else {
            mm::oom_killer::CacheReclaimResult::EMPTY
        };
    }
    x86_64::instructions::interrupts::without_interrupts(|| {
        let Some(mut cache) = KSTACK_FRAME_CACHE.try_lock() else {
            return mm::oom_killer::CacheReclaimResult::BUSY;
        };
        let mut freed_blocks = 0usize;
        let mut saw_busy = false;
        while cache.len > 0 {
            let phys = cache.frames[cache.len - 1];
            let Ok(frame) = x86_64::structures::paging::PhysFrame::from_start_address(
                x86_64::PhysAddr::new(phys),
            ) else {
                let _ = cache.pop();
                continue;
            };
            match mm::buddy_allocator::try_free_physical_pages_nonblocking(
                frame,
                crate::process::KSTACK_PAGES,
            ) {
                Ok(()) => {
                    let _ = cache.pop();
                    freed_blocks += 1;
                }
                Err(mm::buddy_allocator::FreeError::Busy) => {
                    // Retain block ownership in `cache` and propagate contention.
                    saw_busy = true;
                    break;
                }
                Err(_) => {
                    // Reject invalid/unfreeable entry without looping forever.
                    let _ = cache.pop();
                }
            }
        }
        KSTACK_FRAME_CACHE_LEN.store(cache.len, Ordering::Release);
        mm::oom_killer::CacheReclaimResult {
            reclaimed_pages: freed_blocks * crate::process::KSTACK_PAGES,
            busy: saw_busy || KSTACK_FRAME_CACHE_DRAINING.load(Ordering::Acquire) > 0,
        }
    })
}

fn free_drained_kstack_frames(drained: &[u64]) -> usize {
    if drained.is_empty() {
        return 0;
    }
    let mut alloc = mm::memory::FrameAllocator::new();
    let mut freed = 0usize;
    for &phys in drained {
        if let Ok(frame) =
            x86_64::structures::paging::PhysFrame::from_start_address(x86_64::PhysAddr::new(phys))
        {
            if alloc
                .try_deallocate_contiguous_frames(frame, crate::process::KSTACK_PAGES)
                .is_ok()
            {
                freed += 1;
            }
        }
        KSTACK_FRAME_CACHE_DRAINING.fetch_sub(1, Ordering::AcqRel);
    }
    freed
}

struct KernelBackend;

impl KstackFlushBackend for KernelBackend {
    fn flush_all_address_spaces(&mut self) {
        // Kernel-stack mappings are shared through many distinct CR3 roots.
        // An unacknowledged request panics inside the flush.
        mm::flush_all_address_spaces();
    }

    fn free_stack(&mut self, stack: PendingStack) -> bool {
        use x86_64::structures::paging::{PhysFrame, Size4KiB};
        let Ok(frame) =
            PhysFrame::<Size4KiB>::from_start_address(x86_64::PhysAddr::new(stack.phys))
        else {
            return false;
        };

        // Fast path (bare-metal): when the pre-zeroed kstack cache has room,
        // scrub the 32 KiB physical block right here (after shootdown, off the
        // `fork()` critical path) and park it for immediate reuse.
        #[cfg(target_os = "none")]
        if KSTACK_FRAME_CACHE_LEN.load(Ordering::Acquire) < KSTACK_FRAME_CACHE_CAP {
            let stack_bytes = crate::process::KSTACK_PAGES * 4096;
            let direct_virt = mm::page_table::phys_to_virt(frame.start_address());
            // SAFETY: `flush_all_address_spaces()` has already completed for this
            // unmapped order-3 stack block, so no CPU holds any live reference to
            // its physical pages; direct physical map covers all RAM.
            unsafe {
                core::ptr::write_bytes(direct_virt.as_mut_ptr::<u8>(), 0, stack_bytes);
            }
            let cached = x86_64::instructions::interrupts::without_interrupts(|| {
                let mut cache = KSTACK_FRAME_CACHE.lock();
                let pushed = cache.try_push(stack.phys);
                if pushed {
                    KSTACK_FRAME_CACHE_LEN.store(cache.len, Ordering::Release);
                }
                pushed
            });
            if cached {
                return true;
            }
        }

        mm::memory::FrameAllocator::new()
            .try_deallocate_contiguous_frames(frame, crate::process::KSTACK_PAGES)
            .is_ok()
    }

    fn release_slot(&mut self, pid: usize) {
        crate::rcu::release_flush_pending_stack(pid);
        kprintln!("  Released kernel stack for PID {}", pid);
    }

    fn quarantine_slot(&mut self, pid: usize) {
        kprintln!(
            "  CRITICAL: buddy rejected kernel-stack block for PID {}; quarantining slot",
            pid
        );
        crate::rcu::quarantine_flush_pending_stack(pid);
    }
}

/// Hand a stack to the flush batch. For the stack's RCU callback only, after
/// it has validated and cleared every leaf of PID `pid`'s stack, whose buddy
/// block starts at `phys`.
///
/// The callback's PID slot becomes `FlushPending` and outlives the callback.
/// The stack's frames and that slot are released by a later completion.
pub(crate) fn defer_reclaimed_stack(pid: usize, phys: u64) {
    crate::rcu::defer_running_stack_release(pid);
    KSTACK_FLUSH.defer(
        PendingStack { pid, phys },
        crate::time::get_ticks(),
        &mut KernelBackend,
    );
}

/// The RCU drain epilogue: complete the batch if it is full or old enough.
/// The caller holds drain ownership.
pub(crate) fn drain_epilogue() {
    KSTACK_FLUSH.drain_epilogue(crate::time::get_ticks(), &mut KernelBackend);
}

/// Lock-free check whether `drain_epilogue()` needs RCU drain ownership right now.
#[inline]
pub(crate) fn needs_epilogue() -> bool {
    KSTACK_FLUSH.needs_epilogue(crate::time::get_ticks())
}

/// Complete the batch now, for a caller that needs the waiting stacks' frames
/// or PIDs back.
///
/// Spins for RCU drain ownership as `synchronize_rcu()` does, so it must run
/// in process context and never from an RCU callback. Once other CPUs drain,
/// it also needs interrupts enabled: the drain owner it waits for may itself
/// be waiting for this CPU to acknowledge a flush. Stacks whose callbacks
/// have not run yet are not waited for.
pub fn complete_now() {
    crate::rcu::with_drain_ownership(|| KSTACK_FLUSH.complete_now(&mut KernelBackend));
    drain_kstack_frame_cache();
}

/// Completion counters and the number of stacks waiting; every field is read
/// independently and lock-free.
pub fn stats() -> KstackFlushStats {
    KSTACK_FLUSH.stats()
}

/// Pages of reclaimed kernel stacks that wait for their flush or sit in the
/// pre-zeroed kstack reuse cache and so are not back in the buddy allocator yet
/// (the ST-K2-P2 exact memory baseline).
#[cfg(feature = "syscall_test")]
pub fn pending_pages() -> u64 {
    ((KSTACK_FLUSH.stats().pending
        + KSTACK_FRAME_CACHE_LEN.load(Ordering::Acquire)
        + KSTACK_FRAME_CACHE_DRAINING.load(Ordering::Acquire))
        * crate::process::KSTACK_PAGES) as u64
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;
    use std::vec::Vec;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Flush,
        Free(usize),
        Release(usize),
        Quarantine(usize),
    }
    use Event::{Flush, Free, Quarantine, Release};

    /// Logs every backend call in order; rejects the blocks of `rejected` PIDs.
    #[derive(Default)]
    struct Model {
        events: Vec<Event>,
        rejected: Vec<usize>,
    }

    impl Model {
        /// The calls since the last `take`.
        fn take(&mut self) -> Vec<Event> {
            core::mem::take(&mut self.events)
        }
    }

    impl KstackFlushBackend for Model {
        fn flush_all_address_spaces(&mut self) {
            self.events.push(Flush);
        }

        fn free_stack(&mut self, stack: PendingStack) -> bool {
            assert_eq!(stack.phys, phys_of(stack.pid), "PID {}", stack.pid);
            self.events.push(Free(stack.pid));
            !self.rejected.contains(&stack.pid)
        }

        fn release_slot(&mut self, pid: usize) {
            self.events.push(Release(pid));
        }

        fn quarantine_slot(&mut self, pid: usize) {
            self.events.push(Quarantine(pid));
        }
    }

    fn phys_of(pid: usize) -> u64 {
        0x10_0000 + pid as u64 * 0x8000
    }

    fn stack(pid: usize) -> PendingStack {
        PendingStack {
            pid,
            phys: phys_of(pid),
        }
    }

    /// One completion of the stacks `pids`, none rejected.
    fn completion(pids: core::ops::RangeInclusive<usize>) -> Vec<Event> {
        let mut events = vec![Flush];
        for pid in pids {
            events.extend([Free(pid), Release(pid)]);
        }
        events
    }

    #[test]
    fn c3_push_into_a_full_batch_completes_only_the_earlier_stacks() {
        const K: usize = KSTACK_FLUSH_BATCH_CAPACITY;
        let queue = KstackFlushQueue::<K>::new(KSTACK_FLUSH_BATCH_MAX_AGE_TICKS);
        let mut model = Model::default();
        for pid in 1..=K {
            queue.defer(stack(pid), 0, &mut model);
        }
        assert!(
            model.take().is_empty(),
            "a batch that only fills does not flush"
        );
        assert_eq!(queue.stats().pending, K);

        // The stack whose callback is still running is not in the completion
        // its own push triggers.
        queue.defer(stack(K + 1), 0, &mut model);
        assert_eq!(model.take(), completion(1..=K));
        assert_eq!(
            queue.stats(),
            KstackFlushStats {
                batches: 1,
                stacks: K as u64,
                by_count: 1,
                pending: 1,
                ..Default::default()
            }
        );

        // It is released by a later completion.
        queue.complete_now(&mut model);
        assert_eq!(model.take(), completion(K + 1..=K + 1));
        assert_eq!(queue.stats().pending, 0);
    }

    #[test]
    fn c3_epilogue_completes_a_full_or_old_batch_and_not_before() {
        let queue = KstackFlushQueue::<3>::new(10);
        let mut model = Model::default();

        // Age runs from the oldest stack.
        queue.defer(stack(1), 100, &mut model);
        queue.defer(stack(2), 105, &mut model);
        for now in [0, 100, 105, 109] {
            queue.drain_epilogue(now, &mut model);
        }
        assert!(model.take().is_empty(), "neither full nor old enough");
        queue.drain_epilogue(110, &mut model);
        assert_eq!(model.take(), completion(1..=2));
        assert_eq!(queue.stats().by_age, 1);

        // A later stack starts a new age.
        queue.defer(stack(3), 111, &mut model);
        queue.drain_epilogue(120, &mut model);
        assert!(model.take().is_empty());
        queue.drain_epilogue(121, &mut model);
        assert_eq!(model.take(), completion(3..=3));
        assert_eq!(queue.stats().by_age, 2);

        // A full batch completes at once, whatever its age.
        for pid in 4..=5 {
            queue.defer(stack(pid), 200, &mut model);
        }
        queue.drain_epilogue(200, &mut model);
        assert!(model.take().is_empty(), "two of three");
        queue.defer(stack(6), 200, &mut model);
        queue.drain_epilogue(200, &mut model);
        assert_eq!(model.take(), completion(4..=6));
        assert_eq!(
            queue.stats(),
            KstackFlushStats {
                batches: 3,
                stacks: 6,
                by_count: 1,
                by_age: 2,
                ..Default::default()
            }
        );
    }

    #[test]
    fn c3_completion_flushes_then_frees_then_releases_each_stack() {
        let queue = KstackFlushQueue::<4>::new(10);
        let mut model = Model::default();
        for pid in [7, 8, 9] {
            queue.defer(stack(pid), 0, &mut model);
        }
        queue.complete_now(&mut model);
        // One flush, before any frame is returned or any slot released; a
        // slot is released only after its own block went back.
        assert_eq!(
            model.take(),
            [
                Flush,
                Free(7),
                Release(7),
                Free(8),
                Release(8),
                Free(9),
                Release(9)
            ]
        );
        assert_eq!(
            queue.stats(),
            KstackFlushStats {
                batches: 1,
                stacks: 3,
                ..Default::default()
            },
            "an explicit completion counts under neither trigger"
        );
    }

    #[test]
    fn c3_buddy_rejection_quarantines_the_slot_instead_of_releasing_it() {
        let queue = KstackFlushQueue::<4>::new(10);
        let mut model = Model {
            rejected: vec![2],
            ..Default::default()
        };
        for pid in 1..=3 {
            queue.defer(stack(pid), 0, &mut model);
        }
        queue.complete_now(&mut model);
        assert_eq!(
            model.take(),
            [
                Flush,
                Free(1),
                Release(1),
                Free(2),
                Quarantine(2),
                Free(3),
                Release(3)
            ]
        );
        let stats = queue.stats();
        assert_eq!((stats.stacks, stats.quarantined), (3, 1));
    }

    #[test]
    fn c3_an_empty_queue_never_flushes() {
        let queue = KstackFlushQueue::<2>::new(10);
        let mut model = Model::default();
        queue.drain_epilogue(u64::MAX, &mut model);
        queue.complete_now(&mut model);
        assert!(model.take().is_empty());

        // Nor does a queue that a completion has just emptied.
        queue.defer(stack(1), 0, &mut model);
        queue.complete_now(&mut model);
        assert_eq!(model.take(), completion(1..=1));
        queue.drain_epilogue(u64::MAX, &mut model);
        queue.complete_now(&mut model);
        assert!(model.take().is_empty());
        assert_eq!(queue.stats().batches, 1);
    }

    #[test]
    fn c3_batch_capacity_absorbs_multi_wave_16_cpu_reclaims_in_one_flush() {
        const K: usize = KSTACK_FLUSH_BATCH_CAPACITY;
        assert!(
            K >= 128,
            "expected batch capacity >= 128 for 16c amortization"
        );
        let queue = KstackFlushQueue::<K>::new(KSTACK_FLUSH_BATCH_MAX_AGE_TICKS);
        let mut model = Model::default();
        // Seven full 16-CPU waves (112 stacks) fit without triggering a flush.
        for pid in 1..=(16 * 7) {
            queue.defer(stack(pid), 10, &mut model);
        }
        queue.drain_epilogue(10, &mut model);
        assert!(model.take().is_empty());
        assert_eq!(queue.stats().pending, 112);

        // Completing the 8th wave fills K=128 and flushes once in drain_epilogue.
        for pid in (16 * 7 + 1)..=K {
            queue.defer(stack(pid), 10, &mut model);
        }
        queue.drain_epilogue(10, &mut model);
        assert_eq!(model.take(), completion(1..=K));
        assert_eq!(queue.stats().batches, 1);
        assert_eq!(queue.stats().by_count, 1);
        assert_eq!(queue.stats().pending, 0);
    }

    #[test]
    fn kstack_flush_needs_epilogue_tracks_empty_count_and_age() {
        let queue = KstackFlushQueue::<3>::new(10);
        let mut model = Model::default();
        assert!(!queue.needs_epilogue(0));
        assert!(!queue.needs_epilogue(u64::MAX));

        queue.defer(stack(1), 100, &mut model);
        assert!(!queue.needs_epilogue(100));
        assert!(!queue.needs_epilogue(109));
        assert!(queue.needs_epilogue(110));

        // Reaching capacity triggers needs_epilogue regardless of age.
        queue.defer(stack(2), 100, &mut model);
        assert!(!queue.needs_epilogue(100));
        queue.defer(stack(3), 100, &mut model);
        assert!(queue.needs_epilogue(100));

        queue.drain_epilogue(100, &mut model);
        assert_eq!(model.take(), completion(1..=3));
        assert!(!queue.needs_epilogue(1000));
    }

    #[test]
    fn kstack_frame_cache_push_dedup_capacity_pop_and_drain() {
        assert_eq!(KSTACK_FRAME_CACHE_CAP, KSTACK_FLUSH_BATCH_CAPACITY);
        let mut cache = KstackFrameCache::new();
        assert_eq!(cache.pop(), None);

        // Push up to capacity; duplicates and overflow must be rejected.
        for i in 0..KSTACK_FRAME_CACHE_CAP {
            let phys = 0x100_0000 + (i as u64) * 0x8000;
            assert!(cache.try_push(phys), "slot {i}");
        }
        assert!(!cache.try_push(0x100_0000), "duplicate must be rejected");
        assert!(!cache.try_push(0x900_0000), "full cache must reject");

        // LIFO pop returns the newest pushed block.
        let last_phys = 0x100_0000 + ((KSTACK_FRAME_CACHE_CAP - 1) as u64) * 0x8000;
        assert_eq!(cache.pop(), Some(last_phys));
        assert!(cache.try_push(0x900_0000));

        let mut drained = [0u64; KSTACK_FRAME_CACHE_CAP];
        let n = cache.drain_into(&mut drained);
        assert_eq!(n, KSTACK_FRAME_CACHE_CAP);
        assert_eq!(drained[0], 0x100_0000);
        assert_eq!(drained[n - 1], 0x900_0000);
        assert_eq!(cache.pop(), None);
    }
}
