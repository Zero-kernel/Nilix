//! Hosted-only observation of one selected real allocation's deallocation.
extern crate std;
use core::cell::Cell;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::alloc::{GlobalAlloc, Layout, System};

std::thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
    static FAIL_AFTER: Cell<Option<usize>> = const { Cell::new(None) };
    static FAILED: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn fail_allocations_from(index: usize) {
    FAILED.with(|failed| failed.set(false));
    FAIL_AFTER.with(|remaining| remaining.set(Some(index)));
}

pub(crate) fn finish_failure() -> bool {
    FAIL_AFTER.with(|remaining| remaining.set(None));
    FAILED.with(|failed| failed.take())
}

pub(crate) fn begin_counting() {
    ALLOCATIONS.with(|count| count.set(Some(0)));
}
pub(crate) fn end_counting() -> usize {
    ALLOCATIONS.with(|count| count.take().unwrap())
}

pub(crate) static TRACKED: AtomicUsize = AtomicUsize::new(0);
pub(crate) static FREED: AtomicUsize = AtomicUsize::new(0);
pub(crate) static CHARGED_AT_FREE: AtomicUsize = AtomicUsize::new(0);

struct Allocator;

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|count| {
            if let Some(previous) = count.get() {
                count.set(Some(previous + 1));
            }
        });
        let fail = FAIL_AFTER
            .try_with(|remaining| match remaining.get() {
                Some(0) => true,
                Some(count) => {
                    remaining.set(Some(count - 1));
                    false
                }
                None => false,
            })
            .unwrap_or(false);
        if fail {
            let _ = FAILED.try_with(|failed| failed.set(true));
            return core::ptr::null_mut();
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if TRACKED
            .compare_exchange(pointer as usize, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // The selected edge is freed by its drainer with no ledger lock.
            // This observer allocates nothing and records the pre-release charge.
            CHARGED_AT_FREE.store(
                mm::heap_class_snapshot(mm::HeapClass::Vfs).committed_bytes,
                Ordering::Release,
            );
            FREED.store(1, Ordering::Release);
        }
        System.dealloc(pointer, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;
