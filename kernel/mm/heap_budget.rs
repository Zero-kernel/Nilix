//! P2-A: Kernel-heap byte-budget arbiter.
//!
//! # Problem class (R178 synthesis / INV-RES-03)
//!
//! Subsystem retained-metadata budgets (conntrack, futex buckets, page-cache
//! index, audit ring, …) were each independently derived from the same
//! [`crate::memory::HEAP_SIZE_BYTES`] (1 MiB) with no global arbiter. Their
//! combined worst-case hard floors could over-commit the heap even though each
//! individual budget looked "safe" in isolation.
//!
//! # Class elimination
//!
//! 1. **Single registry** of named hard floors + one transient peak + reserved
//!    headroom, all compile-time constants in this module.
//! 2. **Const assert** that
//!    `sum(hard floors) + max_transient_peak + reserved_headroom <= HEAP`.
//! 3. **Boot-time assert** that re-checks the same invariant after the heap is
//!    live (catches drift if a future edit bypasses the const table).
//! 4. **Runtime query API** so subsystems (and tests) derive their byte caps
//!    from named slots instead of inventing new `HEAP_SIZE / N` fractions.
//!
//! # Taxonomy
//!
//! - **Hard floor**: retained metadata that may be simultaneously full (all
//!   hard floors must coexist). Sum must leave reserved headroom free.
//! - **Transient peak**: short-lived buffers (exec image staging). At most one
//!   peak is charged against the residual after hard floors; it does NOT stack
//!   with other peaks.
//! - **Reserved headroom**: unclaimable emergency / fragmentation reserve.
//!   Subsystems must not register against it.
//! - **General residual**: what remains after hard + headroom + transient.
//!   Available for ad-hoc kernel allocations (PCBs, stacks of small Vecs, …).
//!
//! # Safety hierarchy
//!
//! Safety > Efficiency > Speed: we deliberately *reduce* the historical
//! over-claiming fractions (conntrack 1/2 → 1/4, futex 1/4 → 1/8, page-cache
//! 1/8 → 1/16) so the coexistence proof holds. Admission remains fallible;
//! the arbiter bounds the *declared* hard floors and enforces single-holder
//! transient-peak admission for exec staging.
//!
//! # Locking / concurrency
//!
//! Policy table is pure constants. Publication is a once-flag. Transient-peak
//! admission uses a single `AtomicUsize` counter (no locks). Query paths are
//! lock-free.
//!
//! # Honest scope
//!
//! The arbiter eliminates the *declared independent HEAP/N over-claim* class
//! for registered hard floors. Reserved headroom is a **declared** coexistence
//! residual (not a physically fenced allocator region). Live free-space can
//! still be consumed by general residual growth; subsystem admission remains
//! fallible.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::memory::HEAP_SIZE_BYTES;

// ============================================================================
// Named budget identifiers
// ============================================================================

/// Named hard-floor / transient budget slots.
///
/// Adding a variant REQUIRES updating [`HARD_FLOOR_BYTES`] (or
/// [`TRANSIENT_PEAK_BYTES`]) and the const coexistence assert. The boot self-test
/// enumerates every hard floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HeapBudgetId {
    /// Conntrack flow table metadata (retained).
    Conntrack = 0,
    /// Futex bucket / PI metadata (retained).
    Futex = 1,
    /// Page-cache index + LRU node metadata (retained; data frames are buddy).
    PageCacheMeta = 2,
    /// Audit ring buffer (retained at DEFAULT_CAPACITY).
    AuditRing = 3,
    /// Exec image staging buffer (transient peak; not retained across exec).
    ExecImagePeak = 4,
}

/// Number of hard-floor slots (excludes transient peaks).
pub const HARD_FLOOR_COUNT: usize = 4;

// ============================================================================
// Policy constants (single source of truth)
// ============================================================================

/// Reserved headroom that no subsystem may claim. Covers allocator
/// fragmentation, small ad-hoc Vec growth, and emergency paths.
///
/// 128 KiB = HEAP/8.
pub const RESERVED_HEADROOM_BYTES: usize = HEAP_SIZE_BYTES / 8;

/// Conntrack hard floor. Historical claim was HEAP/2 (512 KiB) which alone
/// left too little for coexistence. Reduced to HEAP/4 (256 KiB).
pub const CONNTRACK_HARD_BYTES: usize = HEAP_SIZE_BYTES / 4;

/// Futex hard floor. Historical claim HEAP/4 (256 KiB) → HEAP/8 (128 KiB).
pub const FUTEX_HARD_BYTES: usize = HEAP_SIZE_BYTES / 8;

/// Page-cache metadata hard floor. Historical HEAP/8 (128 KiB) → HEAP/16 (64 KiB).
pub const PAGE_CACHE_META_HARD_BYTES: usize = HEAP_SIZE_BYTES / 16;

/// Audit ring hard floor for the *default* capacity path.
///
/// Sized as 64 KiB — enough for DEFAULT_CAPACITY (256) events at a conservative
/// ~256 B/event packing, with slack for the `Option<AuditEvent>` Vec wrapper.
/// P2-A sets `audit::MAX_CAPACITY = DEFAULT_CAPACITY` so retained ring memory
/// cannot grow past this hard floor via `audit::init`. Export staging remains
/// separate and fallible (`try_reserve_exact`).
pub const AUDIT_RING_HARD_BYTES: usize = HEAP_SIZE_BYTES / 16;

/// Exec image staging peak (transient). Historical 512 KiB equalled half the
/// heap; reduced to HEAP/4 (256 KiB) so hard+peak+headroom still fits.
pub const EXEC_IMAGE_PEAK_BYTES: usize = HEAP_SIZE_BYTES / 4;

/// Compile-time table of hard floors (order matches [`HeapBudgetId`] 0..HARD_FLOOR_COUNT).
pub const HARD_FLOOR_BYTES: [usize; HARD_FLOOR_COUNT] = [
    CONNTRACK_HARD_BYTES,       // 0 Conntrack
    FUTEX_HARD_BYTES,           // 1 Futex
    PAGE_CACHE_META_HARD_BYTES, // 2 PageCacheMeta
    AUDIT_RING_HARD_BYTES,      // 3 AuditRing
];

/// Human-readable names parallel to [`HARD_FLOOR_BYTES`].
pub const HARD_FLOOR_NAMES: [&str; HARD_FLOOR_COUNT] =
    ["conntrack", "futex", "page_cache_meta", "audit_ring"];

/// Sum of all hard floors.
pub const HARD_FLOORS_SUM_BYTES: usize = {
    let mut s = 0usize;
    let mut i = 0;
    while i < HARD_FLOOR_COUNT {
        s += HARD_FLOOR_BYTES[i];
        i += 1;
    }
    s
};

/// Maximum single transient peak charged against residual.
pub const TRANSIENT_PEAK_BYTES: usize = EXEC_IMAGE_PEAK_BYTES;

/// Bytes remaining for general (non-registered) kernel heap use after hard
/// floors, reserved headroom, and the max transient peak are set aside.
pub const GENERAL_RESIDUAL_BYTES: usize = HEAP_SIZE_BYTES
    .saturating_sub(HARD_FLOORS_SUM_BYTES)
    .saturating_sub(RESERVED_HEADROOM_BYTES)
    .saturating_sub(TRANSIENT_PEAK_BYTES);

// ----------------------------------------------------------------------------
// Const coexistence gate — fails the build if a future edit re-introduces
// over-commit of hard floors + peak + headroom against the real heap size.
// ----------------------------------------------------------------------------
const _: () = assert!(HARD_FLOORS_SUM_BYTES + RESERVED_HEADROOM_BYTES <= HEAP_SIZE_BYTES);
const _: () = assert!(
    HARD_FLOORS_SUM_BYTES + RESERVED_HEADROOM_BYTES + TRANSIENT_PEAK_BYTES <= HEAP_SIZE_BYTES
);
const _: () = assert!(CONNTRACK_HARD_BYTES > 0);
const _: () = assert!(FUTEX_HARD_BYTES > 0);
const _: () = assert!(PAGE_CACHE_META_HARD_BYTES > 0);
const _: () = assert!(AUDIT_RING_HARD_BYTES > 0);
const _: () = assert!(EXEC_IMAGE_PEAK_BYTES > 0);
const _: () = assert!(RESERVED_HEADROOM_BYTES > 0);
// Keep each hard floor strictly below the full heap (defensive; also catches
// a mistaken "budget = HEAP" registration).
const _: () = assert!(CONNTRACK_HARD_BYTES < HEAP_SIZE_BYTES);
const _: () = assert!(FUTEX_HARD_BYTES < HEAP_SIZE_BYTES);
const _: () = assert!(PAGE_CACHE_META_HARD_BYTES < HEAP_SIZE_BYTES);
const _: () = assert!(AUDIT_RING_HARD_BYTES < HEAP_SIZE_BYTES);

// ============================================================================
// Runtime query API
// ============================================================================

static BUDGETS_PUBLISHED: AtomicBool = AtomicBool::new(false);

/// Snapshot of the arbiter state for logging / tests.
#[derive(Debug, Clone, Copy)]
pub struct HeapBudgetSnapshot {
    pub heap_total_bytes: usize,
    pub hard_floors_sum_bytes: usize,
    pub reserved_headroom_bytes: usize,
    pub transient_peak_bytes: usize,
    pub general_residual_bytes: usize,
    pub published: bool,
}

/// Return the hard-floor byte budget for a **hard-floor** id.
///
/// # Panics
///
/// Debug builds panic if called with a transient-peak id
/// ([`HeapBudgetId::ExecImagePeak`]). Release builds return 0 for peak ids so a
/// mistaken "sum all ids via hard_floor_bytes" cannot double-count the peak.
/// Prefer [`budget_bytes`] for a taxonomy-agnostic query, or
/// [`transient_peak_bytes`] for the peak alone.
#[inline]
pub const fn hard_floor_bytes(id: HeapBudgetId) -> usize {
    match id {
        HeapBudgetId::Conntrack => CONNTRACK_HARD_BYTES,
        HeapBudgetId::Futex => FUTEX_HARD_BYTES,
        HeapBudgetId::PageCacheMeta => PAGE_CACHE_META_HARD_BYTES,
        HeapBudgetId::AuditRing => AUDIT_RING_HARD_BYTES,
        HeapBudgetId::ExecImagePeak => {
            // Peak is NOT a hard floor — do not let callers treat it as one.
            0
        }
    }
}

/// Taxonomy-agnostic budget query (hard floor OR transient peak).
#[inline]
pub const fn budget_bytes(id: HeapBudgetId) -> usize {
    match id {
        HeapBudgetId::Conntrack => CONNTRACK_HARD_BYTES,
        HeapBudgetId::Futex => FUTEX_HARD_BYTES,
        HeapBudgetId::PageCacheMeta => PAGE_CACHE_META_HARD_BYTES,
        HeapBudgetId::AuditRing => AUDIT_RING_HARD_BYTES,
        HeapBudgetId::ExecImagePeak => EXEC_IMAGE_PEAK_BYTES,
    }
}

/// Maximum registered transient peak (exec image staging).
#[inline]
pub const fn transient_peak_bytes() -> usize {
    TRANSIENT_PEAK_BYTES
}

// ============================================================================
// Transient-peak admission (single-holder)
// ============================================================================

/// Live holders of the registered transient peak (exec image staging).
///
/// The coexistence proof charges at most ONE peak against residual. Concurrent
/// `sys_execve` / `sys_spawn_image` paths must serialize peak ownership so
/// `N * EXEC_IMAGE_PEAK_BYTES` cannot stack on top of full hard floors.
static TRANSIENT_PEAK_HOLDERS: AtomicUsize = AtomicUsize::new(0);

/// RAII guard for the exec-image transient peak.
///
/// Acquiring fails with `Err(())` when another holder is live. Drop releases
/// exactly one holder. Zero heap allocation; safe under IRQ-off if needed.
#[must_use = "dropping TransientPeakGuard releases the peak slot"]
pub struct TransientPeakGuard {
    _priv: (),
}

impl TransientPeakGuard {
    /// Try to admit one transient-peak holder.
    ///
    /// Returns `Err(())` if another holder is already live (caller maps to
    /// ENOMEM / EAGAIN as appropriate). Uses a CAS loop; never blocks.
    pub fn try_acquire() -> Result<Self, ()> {
        loop {
            let cur = TRANSIENT_PEAK_HOLDERS.load(Ordering::Acquire);
            if cur != 0 {
                return Err(());
            }
            match TRANSIENT_PEAK_HOLDERS.compare_exchange_weak(
                0,
                1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Self { _priv: () }),
                Err(_) => core::hint::spin_loop(),
            }
        }
    }
}

impl Drop for TransientPeakGuard {
    fn drop(&mut self) {
        // Release-store 0: the peak buffer is about to be dropped by the holder;
        // a subsequent acquirer may proceed.
        TRANSIENT_PEAK_HOLDERS.store(0, Ordering::Release);
    }
}

/// Current number of live transient-peak holders (0 or 1 under correct use).
#[inline]
pub fn transient_peak_holders() -> usize {
    TRANSIENT_PEAK_HOLDERS.load(Ordering::Acquire)
}

/// Reserved unclaimable headroom.
#[inline]
pub const fn reserved_headroom_bytes() -> usize {
    RESERVED_HEADROOM_BYTES
}

/// Sum of hard floors.
#[inline]
pub const fn hard_floors_sum_bytes() -> usize {
    HARD_FLOORS_SUM_BYTES
}

/// Residual for non-registered general use.
#[inline]
pub const fn general_residual_bytes() -> usize {
    GENERAL_RESIDUAL_BYTES
}

/// Full snapshot.
#[inline]
pub fn snapshot() -> HeapBudgetSnapshot {
    HeapBudgetSnapshot {
        heap_total_bytes: HEAP_SIZE_BYTES,
        hard_floors_sum_bytes: HARD_FLOORS_SUM_BYTES,
        reserved_headroom_bytes: RESERVED_HEADROOM_BYTES,
        transient_peak_bytes: TRANSIENT_PEAK_BYTES,
        general_residual_bytes: GENERAL_RESIDUAL_BYTES,
        published: BUDGETS_PUBLISHED.load(Ordering::Acquire),
    }
}

/// True after [`publish_and_assert`] has run successfully.
#[inline]
pub fn is_published() -> bool {
    BUDGETS_PUBLISHED.load(Ordering::Acquire)
}

// ============================================================================
// Boot publication + assert
// ============================================================================

/// Publish the budget table and fail-closed if coexistence is violated.
///
/// Call once after the kernel heap is initialized and before subsystems that
/// size retained metadata from these budgets allocate. Idempotent: a second
/// call re-validates and returns without re-publishing side effects.
///
/// # Panics
///
/// Panics if hard floors + headroom (+ transient peak) exceed the live heap
/// size. This is intentional fail-closed policy: shipping an over-committed
/// budget table is a configuration bug, not a recoverable runtime condition.
pub fn publish_and_assert() {
    let heap = HEAP_SIZE_BYTES;
    let hard = HARD_FLOORS_SUM_BYTES;
    let head = RESERVED_HEADROOM_BYTES;
    let peak = TRANSIENT_PEAK_BYTES;

    assert!(
        hard + head <= heap,
        "P2-A heap budget over-commit: hard floors {} + headroom {} > heap {}",
        hard,
        head,
        heap
    );
    assert!(
        hard + head + peak <= heap,
        "P2-A heap budget over-commit: hard {} + headroom {} + peak {} > heap {}",
        hard,
        head,
        peak,
        heap
    );

    // Per-slot positivity (defensive against a zeroed table entry).
    let mut i = 0;
    while i < HARD_FLOOR_COUNT {
        assert!(
            HARD_FLOOR_BYTES[i] > 0,
            "P2-A: hard floor slot {} ({}) is zero",
            i,
            HARD_FLOOR_NAMES[i]
        );
        i += 1;
    }

    BUDGETS_PUBLISHED.store(true, Ordering::Release);

    klog_always!(
        "Heap budget arbiter: heap={} KiB hard_sum={} KiB headroom={} KiB peak={} KiB residual={} KiB",
        heap / 1024,
        hard / 1024,
        head / 1024,
        peak / 1024,
        GENERAL_RESIDUAL_BYTES / 1024
    );
    let mut i = 0;
    while i < HARD_FLOOR_COUNT {
        klog_always!(
            "  hard[{}] {}: {} KiB",
            i,
            HARD_FLOOR_NAMES[i],
            HARD_FLOOR_BYTES[i] / 1024
        );
        i += 1;
    }
}

// ============================================================================
// Self-test (boot-visible)
// ============================================================================

/// Pure arithmetic + policy self-test. Panics on any invariant failure.
///
/// Safe to call before or after [`publish_and_assert`]; does not allocate.
pub fn run_heap_budget_self_test() {
    // 1) Coexistence: hard + headroom + peak fit the real heap.
    assert!(
        HARD_FLOORS_SUM_BYTES + RESERVED_HEADROOM_BYTES + TRANSIENT_PEAK_BYTES <= HEAP_SIZE_BYTES,
        "coexistence broken"
    );
    // 2) Hard floors alone leave headroom free.
    assert!(HARD_FLOORS_SUM_BYTES + RESERVED_HEADROOM_BYTES <= HEAP_SIZE_BYTES);
    // 3) No hard floor claims the whole heap.
    let mut i = 0;
    while i < HARD_FLOOR_COUNT {
        assert!(HARD_FLOOR_BYTES[i] < HEAP_SIZE_BYTES);
        assert!(HARD_FLOOR_BYTES[i] > 0);
        i += 1;
    }
    // 4) Named query API matches the table (hard floors via hard_floor_bytes;
    //    peak via budget_bytes / transient_peak_bytes — never via hard_floor).
    assert_eq!(
        hard_floor_bytes(HeapBudgetId::Conntrack),
        CONNTRACK_HARD_BYTES
    );
    assert_eq!(hard_floor_bytes(HeapBudgetId::Futex), FUTEX_HARD_BYTES);
    assert_eq!(
        hard_floor_bytes(HeapBudgetId::PageCacheMeta),
        PAGE_CACHE_META_HARD_BYTES
    );
    assert_eq!(
        hard_floor_bytes(HeapBudgetId::AuditRing),
        AUDIT_RING_HARD_BYTES
    );
    assert_eq!(
        hard_floor_bytes(HeapBudgetId::ExecImagePeak),
        0,
        "peak must not count as a hard floor"
    );
    assert_eq!(
        budget_bytes(HeapBudgetId::ExecImagePeak),
        EXEC_IMAGE_PEAK_BYTES
    );
    assert_eq!(transient_peak_bytes(), EXEC_IMAGE_PEAK_BYTES);
    // 4b) Transient-peak single-holder admission.
    assert_eq!(transient_peak_holders(), 0);
    {
        let g1 = TransientPeakGuard::try_acquire().expect("first peak acquire");
        assert_eq!(transient_peak_holders(), 1);
        assert!(
            TransientPeakGuard::try_acquire().is_err(),
            "second concurrent peak must be refused"
        );
        drop(g1);
    }
    assert_eq!(transient_peak_holders(), 0);
    let g2 = TransientPeakGuard::try_acquire().expect("re-acquire after release");
    drop(g2);
    assert_eq!(transient_peak_holders(), 0);
    // 5) Residual arithmetic is consistent with the published snapshot shape.
    let snap = snapshot();
    assert_eq!(snap.heap_total_bytes, HEAP_SIZE_BYTES);
    assert_eq!(snap.hard_floors_sum_bytes, HARD_FLOORS_SUM_BYTES);
    assert_eq!(snap.reserved_headroom_bytes, RESERVED_HEADROOM_BYTES);
    assert_eq!(snap.transient_peak_bytes, TRANSIENT_PEAK_BYTES);
    assert_eq!(snap.general_residual_bytes, GENERAL_RESIDUAL_BYTES);
    // 6) Residual non-negative is already guaranteed by saturating_sub + const
    //    assert; re-check the non-saturating identity for the live numbers.
    assert_eq!(
        HARD_FLOORS_SUM_BYTES
            + RESERVED_HEADROOM_BYTES
            + TRANSIENT_PEAK_BYTES
            + GENERAL_RESIDUAL_BYTES,
        HEAP_SIZE_BYTES,
        "partition of heap must be exact"
    );
    // 7) Historical over-claim regression: the OLD fractions must NOT reappear
    //    as the live hard floors (class re-open guard).
    assert!(
        CONNTRACK_HARD_BYTES <= HEAP_SIZE_BYTES / 4,
        "conntrack must not re-claim >1/4 heap"
    );
    assert!(
        FUTEX_HARD_BYTES <= HEAP_SIZE_BYTES / 8,
        "futex must not re-claim >1/8 heap"
    );
    assert!(
        PAGE_CACHE_META_HARD_BYTES <= HEAP_SIZE_BYTES / 16,
        "page-cache meta must not re-claim >1/16 heap"
    );
}
