#![no_std]
#![feature(abi_x86_interrupt)]
#![feature(allocator_api)]
extern crate alloc;

// 导入 drivers crate 的宏
extern crate drivers;
#[macro_use]
extern crate klog;

pub mod buddy_allocator;
pub mod dma;
/// R169-11: `FallibleOrderedMap` lives in `mm` (a leaf crate both `kernel_core`
/// and `net` depend on) so the `net` fragment reassembler can use it for an
/// allocation-fallible per-fragment map without a `net -> kernel_core` dependency
/// cycle. Re-exported from `kernel_core::fallible_map` for source compatibility.
pub mod fallible_map;
/// P2-A: single registry of kernel-heap hard floors / transient peaks / headroom.
pub mod heap_budget;
pub mod memory;
pub mod oom_killer;
pub mod page_cache;
pub mod page_table;
pub mod tlb_shootdown;

pub use heap_budget::{
    budget_bytes, general_residual_bytes, hard_floor_bytes, hard_floors_sum_bytes,
    is_published as heap_budgets_published, publish_and_assert as publish_heap_budgets,
    reserved_headroom_bytes, run_heap_budget_self_test, snapshot as heap_budget_snapshot,
    transient_peak_bytes, transient_peak_holders, HeapBudgetId, HeapBudgetSnapshot,
    TransientPeakGuard, AUDIT_RING_HARD_BYTES, CONNTRACK_HARD_BYTES, EXEC_IMAGE_PEAK_BYTES,
    FUTEX_HARD_BYTES, HARD_FLOORS_SUM_BYTES, HARD_FLOOR_BYTES, HARD_FLOOR_COUNT, HARD_FLOOR_NAMES,
    PAGE_CACHE_META_HARD_BYTES, RESERVED_HEADROOM_BYTES, TRANSIENT_PEAK_BYTES,
};
pub use memory::{BootInfo, FrameAllocator, MemoryMapInfo};
pub use oom_killer::{
    get_stats as get_oom_stats, on_allocation_failure as oom_allocation_failed,
    register_audit_callback as register_oom_audit_callback,
    register_callbacks as register_oom_callbacks, score_process as score_oom_process,
    OomProcessInfo, OomStats,
};
pub use page_cache::{
    find_or_create_page, init as init_page_cache, read_page, reclaim_pages,
    run_page_cache_policy_self_test, writeback_dirty_pages, writeback_page, GlobalPageCache,
    InodeId, MemoryPressureHandler, PageCacheEntry, PageCacheStats, PageCacheUnchargeFn, PageIndex,
    PageState, WritebackStats, PAGE_CACHE, PAGE_CACHE_CGROUP_CHARGE_BYTES, PAGE_CACHE_MAX_PAGES,
    PAGE_SIZE, PRESSURE_HANDLER,
};
pub use page_table::{
    map_mmio, phys_to_virt, with_current_manager, MapError, PageTableManager, UnmapError,
    UpdateFlagsError, PHYSICAL_MEMORY_OFFSET,
};
pub use tlb_shootdown::{
    flush_current_as_all, flush_current_as_page, flush_current_as_range, get_stats as get_tlb_stats,
};

pub fn init() {
    klog_always!("Memory management module initialized");
}
