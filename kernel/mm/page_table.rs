//! 页表管理器
//!
//! 提供对x86_64页表的完整管理功能

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::{
    instructions::interrupts,
    structures::paging::{
        page_table::PageTableEntry, FrameAllocator, Mapper, OffsetPageTable, Page, PageTable,
        PageTableFlags, PhysFrame, Size4KiB, Translate,
    },
    PhysAddr, VirtAddr,
};

/// 物理内存高半区偏移（bootloader 映射 0xffffffff80000000 -> 0）
/// 覆盖物理地址 0-1GB
pub const PHYSICAL_MEMORY_OFFSET: u64 = 0xffff_ffff_8000_0000;

/// VGA text buffer (phys 0xB8000) high-half alias
pub const VGA_PHYS_ADDR: u64 = 0x000b_8000;
pub const VGA_VIRT_ADDR: u64 = PHYSICAL_MEMORY_OFFSET + VGA_PHYS_ADDR;

/// Local APIC MMIO window (4 KiB at phys 0xFEE0_0000) dedicated high-half alias
pub const APIC_PHYS_ADDR: u64 = 0xfee0_0000;
pub const APIC_MMIO_SIZE: usize = 0x1000;
pub const APIC_VIRT_ADDR: u64 = 0xffff_ffff_fee0_0000; // PML4[511] unused slot

/// LEAD-KSTACK-WINDOW-1: the per-PID kernel-stack region, PML4[511]
/// PDPT[506..=507]: `[KSTACK_REGION_BASE, KSTACK_REGION_END)`. The fixed
/// high-half windows (MMIO, framebuffer, boot and per-CPU stacks, kernel image,
/// heap and direct map, HPET, APIC, firmware) all start at or above
/// `KSTACK_REGION_END` (PDPT[508] onwards); each asserts it where it is defined.
pub const KSTACK_REGION_BASE: u64 = 0xffff_fffe_8000_0000;
pub const KSTACK_REGION_END: u64 = 0xffff_ffff_0000_0000;
const _: () = assert!(KSTACK_REGION_END <= PHYSICAL_MEMORY_OFFSET);
const _: () = assert!(KSTACK_REGION_END <= APIC_VIRT_ADDR);

/// Issue #109 §1.1: Cache-line-isolated page-table lock slot.
///
/// Each slot holds its spin mutex and holding CPU ID on a dedicated 64-byte
/// cache line so concurrent operations on disjoint address spaces never false-share.
#[repr(align(64))]
struct PtLockSlot {
    lock: Mutex<()>,
    owner_cpu: AtomicUsize,
}

const _: () = assert!(core::mem::size_of::<PtLockSlot>() == 64);
const _: () = assert!(core::mem::align_of::<PtLockSlot>() == 64);

const NO_PT_LOCK_OWNER: usize = usize::MAX;

impl PtLockSlot {
    const fn new() -> Self {
        Self {
            lock: Mutex::new(()),
            owner_cpu: AtomicUsize::new(NO_PT_LOCK_OWNER),
        }
    }
}

/// Issue #109 §1.1: Number of per-address-space page-table lock shards (8 KiB in `.bss`).
const AS_PT_LOCK_SHARD_BITS: u32 = 7;
pub const AS_PT_LOCK_SHARDS: usize = 1 << AS_PT_LOCK_SHARD_BITS;

/// Issue #109 §1.1: Dedicated lock for shared kernel high-half page tables
/// (`PML4[256..512]`, `KSTACK_REGION`, MMIO, firmware window, IST guards, and
/// boot-root identity-map/trampoline edits).
///
/// Strict lock order: `AS_PT_LOCKS[shard]` → `KERNEL_PT_LOCK` (never reverse).
static KERNEL_PT_LOCK: PtLockSlot = PtLockSlot::new();

/// Issue #109 §1.1: Striped per-address-space page-table lock table indexed by
/// the canonical kernel CR3 root PFN (`as_pt_lock_shard(root)`).
///
/// Immortal static storage eliminates teardown/reclaim lock UAF windows and
/// preserves lock-free `#PF` CoW entry even when `current_pid() == None`.
static AS_PT_LOCKS: [PtLockSlot; AS_PT_LOCK_SHARDS] =
    [const { PtLockSlot::new() }; AS_PT_LOCK_SHARDS];

/// Physical address of the boot PML4 root (registered by `process::init()`).
/// Zero until registered (early boot and hosted unit tests); roots matching
/// `BOOT_ROOT_PHYS` route to `KERNEL_PT_LOCK`.
static BOOT_ROOT_PHYS: AtomicU64 = AtomicU64::new(0);

/// Register the canonical physical address of the boot PML4 root so
/// `with_current_manager` / `try_with_current_manager` distinguish shared
/// boot-root operations from per-address-space user operations.
#[inline]
pub fn register_boot_root(boot_root_phys: u64) {
    BOOT_ROOT_PHYS.store(boot_root_phys & PTE_ADDR_MASK, Ordering::Release);
}

#[inline]
fn is_boot_or_unregistered_root(root_phys: u64) -> bool {
    let boot = BOOT_ROOT_PHYS.load(Ordering::Acquire);
    boot == 0 || (root_phys & PTE_ADDR_MASK) == boot || root_phys == 0
}

/// Issue #109 §1.1: Map a canonical kernel CR3 physical address to its shard
/// index in `0..AS_PT_LOCK_SHARDS` using mixed Fibonacci hashing on the PFN
/// so both consecutive and power-of-2-strided buddy PFNs distribute uniformly.
#[inline]
pub const fn as_pt_lock_shard(root_phys: u64) -> usize {
    let pfn = (root_phys & PTE_ADDR_MASK) >> 12;
    let mixed = (pfn ^ (pfn >> 16)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let folded = mixed ^ (mixed >> 32);
    ((folded >> (32 - AS_PT_LOCK_SHARD_BITS)) as usize) & (AS_PT_LOCK_SHARDS - 1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PtLockKind {
    UserAs,
    KernelShared,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PtDomain {
    /// Holds `AS_PT_LOCKS[shard(root)]`: permitted to mutate lower-half user
    /// entries (`< USER_HALF_END`) only.
    UserAddressSpace,
    /// Holds `KERNEL_PT_LOCK`: permitted to mutate shared kernel high-half
    /// entries (and lower-half entries on the boot root).
    KernelShared,
}

/// Per-CPU `PT_LOCK` observability accumulators and lock-hierarchy hold depth (#109).
///
/// Each CPU writes only to its own 64-byte cache line on lock acquire/drop,
/// eliminating cross-CPU false sharing between contented waiters, `#PF` busy
/// probes, and lock holders. `as_lock_held` and `kernel_lock_held` occupy the
/// final 8 bytes of the same cache line (zero extra memory).
#[repr(align(64))]
struct PtLockCpuCounters {
    acquired: AtomicU64,
    contended: AtomicU64,
    busy: AtomicU64,
    wait_tsc: AtomicU64,
    wait_tsc_max: AtomicU64,
    hold_tsc: AtomicU64,
    hold_tsc_max: AtomicU64,
    #[cfg_attr(test, allow(dead_code))]
    as_lock_held: AtomicU32,
    #[cfg_attr(test, allow(dead_code))]
    kernel_lock_held: AtomicU32,
}

const _: () = assert!(core::mem::size_of::<PtLockCpuCounters>() == 64);
const _: () = assert!(core::mem::align_of::<PtLockCpuCounters>() == 64);

impl PtLockCpuCounters {
    const fn new() -> Self {
        Self {
            acquired: AtomicU64::new(0),
            contended: AtomicU64::new(0),
            busy: AtomicU64::new(0),
            wait_tsc: AtomicU64::new(0),
            wait_tsc_max: AtomicU64::new(0),
            hold_tsc: AtomicU64::new(0),
            hold_tsc_max: AtomicU64::new(0),
            as_lock_held: AtomicU32::new(0),
            kernel_lock_held: AtomicU32::new(0),
        }
    }
}

/// C3 E1 (#90) + #109: per-CPU `PT_LOCK` statistics for `/proc/schedstat`.
static PT_LOCK_COUNTERS: [PtLockCpuCounters; cpu_local::max_cpus()] =
    [const { PtLockCpuCounters::new() }; cpu_local::max_cpus()];

#[inline]
fn pt_lock_counters_for(cpu: usize) -> &'static PtLockCpuCounters {
    PT_LOCK_COUNTERS.get(cpu).unwrap_or(&PT_LOCK_COUNTERS[0])
}

fn aggregate_pt_lock_stats(per_cpu: &[PtLockCpuCounters]) -> PtLockStats {
    let mut stats = PtLockStats {
        acquired: 0,
        contended: 0,
        busy: 0,
        wait_tsc: 0,
        wait_tsc_max: 0,
        hold_tsc: 0,
        hold_tsc_max: 0,
    };
    for counters in per_cpu {
        stats.acquired = stats
            .acquired
            .wrapping_add(counters.acquired.load(Ordering::Relaxed));
        stats.contended = stats
            .contended
            .wrapping_add(counters.contended.load(Ordering::Relaxed));
        stats.busy = stats
            .busy
            .wrapping_add(counters.busy.load(Ordering::Relaxed));
        stats.wait_tsc = stats
            .wait_tsc
            .wrapping_add(counters.wait_tsc.load(Ordering::Relaxed));
        stats.wait_tsc_max = stats
            .wait_tsc_max
            .max(counters.wait_tsc_max.load(Ordering::Relaxed));
        stats.hold_tsc = stats
            .hold_tsc
            .wrapping_add(counters.hold_tsc.load(Ordering::Relaxed));
        stats.hold_tsc_max = stats
            .hold_tsc_max
            .max(counters.hold_tsc_max.load(Ordering::Relaxed));
    }
    stats
}

/// Snapshot of the `PT_LOCK` statistics (see [`pt_lock_stats`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtLockStats {
    /// Acquisitions by blocking and non-blocking PT lock entrypoints.
    pub acquired: u64,
    /// Blocking lock calls that found the target slot held (counted before spinning).
    pub contended: u64,
    /// Non-blocking `try_lock` calls that found the target slot held (the #PF Busy path).
    pub busy: u64,
    /// Sum and maximum of contended wait time, in TSC cycles.
    pub wait_tsc: u64,
    pub wait_tsc_max: u64,
    /// Sum and maximum of hold time, in TSC cycles.
    pub hold_tsc: u64,
    pub hold_tsc_max: u64,
}

/// Current `PT_LOCK` statistics aggregated across CPUs; each field is read
/// independently.
pub fn pt_lock_stats() -> PtLockStats {
    aggregate_pt_lock_stats(&PT_LOCK_COUNTERS)
}

#[inline]
fn read_tsc() -> u64 {
    // SAFETY: RDTSC only reads the time-stamp counter.
    unsafe { core::arch::x86_64::_rdtsc() }
}

struct PtLockGuard {
    slot: &'static PtLockSlot,
    _guard: spin::MutexGuard<'static, ()>,
    kind: PtLockKind,
    owner_cpu: usize,
    since_tsc: u64,
}

#[cfg(test)]
std::thread_local! {
    static TEST_AS_LOCK_HELD: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
    static TEST_KERNEL_LOCK_HELD: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
}

#[inline]
fn pt_hold_depths(cpu: usize) -> (u32, u32) {
    #[cfg(not(test))]
    {
        let counters = pt_lock_counters_for(cpu);
        (
            counters.as_lock_held.load(Ordering::Relaxed),
            counters.kernel_lock_held.load(Ordering::Relaxed),
        )
    }
    #[cfg(test)]
    {
        let _ = cpu;
        (
            TEST_AS_LOCK_HELD.with(|c| c.get()),
            TEST_KERNEL_LOCK_HELD.with(|c| c.get()),
        )
    }
}

#[inline]
fn inc_pt_hold_depth(kind: PtLockKind, cpu: usize) {
    #[cfg(not(test))]
    {
        let counters = pt_lock_counters_for(cpu);
        match kind {
            PtLockKind::UserAs => {
                counters.as_lock_held.fetch_add(1, Ordering::Relaxed);
            }
            PtLockKind::KernelShared => {
                counters.kernel_lock_held.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[cfg(test)]
    {
        let _ = cpu;
        match kind {
            PtLockKind::UserAs => TEST_AS_LOCK_HELD.with(|c| c.set(c.get() + 1)),
            PtLockKind::KernelShared => TEST_KERNEL_LOCK_HELD.with(|c| c.set(c.get() + 1)),
        }
    }
}

#[inline]
fn dec_pt_hold_depth(kind: PtLockKind, cpu: usize) {
    #[cfg(not(test))]
    {
        let counters = pt_lock_counters_for(cpu);
        match kind {
            PtLockKind::UserAs => {
                let prev = counters.as_lock_held.fetch_sub(1, Ordering::Relaxed);
                debug_assert!(prev > 0, "as_lock_held underflow");
            }
            PtLockKind::KernelShared => {
                let prev = counters.kernel_lock_held.fetch_sub(1, Ordering::Relaxed);
                debug_assert!(prev > 0, "kernel_lock_held underflow");
            }
        }
    }
    #[cfg(test)]
    {
        let _ = cpu;
        match kind {
            PtLockKind::UserAs => TEST_AS_LOCK_HELD.with(|c| {
                let prev = c.get();
                debug_assert!(prev > 0, "as_lock_held underflow");
                c.set(prev.saturating_sub(1));
            }),
            PtLockKind::KernelShared => TEST_KERNEL_LOCK_HELD.with(|c| {
                let prev = c.get();
                debug_assert!(prev > 0, "kernel_lock_held underflow");
                c.set(prev.saturating_sub(1));
            }),
        }
    }
}

impl PtLockGuard {
    #[inline]
    fn new_on_cpu(
        slot: &'static PtLockSlot,
        guard: spin::MutexGuard<'static, ()>,
        kind: PtLockKind,
        cpu: usize,
    ) -> Self {
        slot.owner_cpu.store(cpu, Ordering::Release);
        inc_pt_hold_depth(kind, cpu);
        pt_lock_counters_for(cpu)
            .acquired
            .fetch_add(1, Ordering::Relaxed);
        Self {
            slot,
            _guard: guard,
            kind,
            owner_cpu: cpu,
            since_tsc: read_tsc(),
        }
    }
}

impl Drop for PtLockGuard {
    fn drop(&mut self) {
        // Still the holder: `_guard` is released after this body.
        let held = read_tsc().saturating_sub(self.since_tsc);
        let counters = pt_lock_counters_for(self.owner_cpu);
        counters.hold_tsc.fetch_add(held, Ordering::Relaxed);
        counters.hold_tsc_max.fetch_max(held, Ordering::Relaxed);
        dec_pt_hold_depth(self.kind, self.owner_cpu);
        self.slot
            .owner_cpu
            .store(NO_PT_LOCK_OWNER, Ordering::Release);
    }
}

#[inline]
fn assert_lock_order_before_acquire(kind: PtLockKind, cpu: usize) {
    let (as_held, kernel_held) = pt_hold_depths(cpu);
    match kind {
        PtLockKind::UserAs => {
            assert_eq!(
                as_held, 0,
                "Issue #109 §1.1: nested AS_PT_LOCKS acquisition forbidden on CPU {}",
                cpu
            );
            assert_eq!(
                kernel_held, 0,
                "Issue #109 §1.1: lock-order violation KERNEL_PT_LOCK -> AS_PT_LOCKS on CPU {}",
                cpu
            );
        }
        PtLockKind::KernelShared => {
            // AS_PT_LOCKS -> KERNEL_PT_LOCK is permitted (e.g. fork high-half copy);
            // KERNEL_PT_LOCK -> KERNEL_PT_LOCK is forbidden.
            assert_eq!(
                kernel_held, 0,
                "Issue #109 §1.1: nested KERNEL_PT_LOCK acquisition forbidden on CPU {}",
                cpu
            );
        }
    }
}

#[inline]
fn lock_slot(slot: &'static PtLockSlot, kind: PtLockKind) -> PtLockGuard {
    let cpu = cpu_local::current_cpu_id();
    assert_lock_order_before_acquire(kind, cpu);
    if let Some(guard) = slot.lock.try_lock() {
        return PtLockGuard::new_on_cpu(slot, guard, kind, cpu);
    }
    let counters = pt_lock_counters_for(cpu);
    counters.contended.fetch_add(1, Ordering::Relaxed);
    let start = read_tsc();
    let guard = slot.lock.lock();
    let waited = read_tsc().saturating_sub(start);
    counters.wait_tsc.fetch_add(waited, Ordering::Relaxed);
    counters.wait_tsc_max.fetch_max(waited, Ordering::Relaxed);
    PtLockGuard::new_on_cpu(slot, guard, kind, cpu)
}

#[inline]
fn try_lock_slot(slot: &'static PtLockSlot, kind: PtLockKind) -> Option<PtLockGuard> {
    let cpu = cpu_local::current_cpu_id();
    let counters = pt_lock_counters_for(cpu);
    // Reject same-CPU reentry fail-closed before touching the mutex (also guards
    // against KERNEL_PT_LOCK -> try_lock(AS) or cross-shard reentry in #PF).
    let (as_held, kernel_held) = pt_hold_depths(cpu);
    let already_held = match kind {
        PtLockKind::UserAs => as_held != 0 || kernel_held != 0,
        PtLockKind::KernelShared => kernel_held != 0,
    };
    if already_held {
        counters.busy.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let Some(guard) = slot.lock.try_lock() else {
        counters.busy.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    Some(PtLockGuard::new_on_cpu(slot, guard, kind, cpu))
}

#[inline]
fn lock_kernel_pt() -> PtLockGuard {
    lock_slot(&KERNEL_PT_LOCK, PtLockKind::KernelShared)
}

#[inline]
fn try_lock_kernel_pt() -> Option<PtLockGuard> {
    try_lock_slot(&KERNEL_PT_LOCK, PtLockKind::KernelShared)
}

#[inline]
fn lock_as_pt(root_phys: u64) -> PtLockGuard {
    if is_boot_or_unregistered_root(root_phys) {
        lock_kernel_pt()
    } else {
        let slot = &AS_PT_LOCKS[as_pt_lock_shard(root_phys)];
        lock_slot(slot, PtLockKind::UserAs)
    }
}

#[inline]
fn try_lock_as_pt(root_phys: u64) -> Option<PtLockGuard> {
    if is_boot_or_unregistered_root(root_phys) {
        try_lock_kernel_pt()
    } else {
        let slot = &AS_PT_LOCKS[as_pt_lock_shard(root_phys)];
        try_lock_slot(slot, PtLockKind::UserAs)
    }
}

/// Kept as an internal alias for `lock_kernel_pt()` for `mmio_access.rs` and tests.
#[inline]
fn lock_pt() -> PtLockGuard {
    lock_kernel_pt()
}

#[cfg(test)]
#[inline]
fn try_lock_pt() -> Option<PtLockGuard> {
    try_lock_kernel_pt()
}

#[inline]
fn current_cpu_holds_any_pt_lock(cpu: usize) -> bool {
    let (as_held, kernel_held) = pt_hold_depths(cpu);
    as_held != 0 || kernel_held != 0
}

/// CPU that currently owns the relevant page-table lock, if any.
///
/// 1. If the executing CPU holds **any** page-table lock (`AS_PT_LOCKS` or
///    `KERNEL_PT_LOCK`), returns `Some(self_cpu)` immediately — preserving
///    RF186-6, ST-K2-P2(a), and `usercopy` same-CPU reentry assertions.
/// 2. Otherwise returns the owner of the active address space's lock shard
///    (preserving ST-K2-P2(b) cross-CPU remote-holder detection in `#PF`).
#[inline]
pub fn pt_lock_owner_cpu() -> Option<usize> {
    let self_cpu = cpu_local::current_cpu_id();
    if current_cpu_holds_any_pt_lock(self_cpu) {
        return Some(self_cpu);
    }
    #[cfg(not(test))]
    let slot = {
        let root = interrupts::without_interrupts(|| edit_root(kpti_root_pair()));
        if is_boot_or_unregistered_root(root) {
            &KERNEL_PT_LOCK
        } else {
            &AS_PT_LOCKS[as_pt_lock_shard(root)]
        }
    };
    #[cfg(test)]
    let slot = &KERNEL_PT_LOCK;
    match slot.owner_cpu.load(Ordering::Acquire) {
        NO_PT_LOCK_OWNER => None,
        cpu => Some(cpu),
    }
}

/// Issue #109 §1.1: Acquire the dedicated shared kernel page-table lock
/// (`KERNEL_PT_LOCK`) for high-half or boot-root page-table mutations.
#[inline]
pub fn with_kernel_pt_lock<T, F>(f: F) -> T
where
    F: FnOnce() -> T,
{
    let _guard = lock_kernel_pt();
    f()
}

/// Compatibility alias for [`with_kernel_pt_lock`].
#[inline]
pub fn with_pt_lock<T, F>(f: F) -> T
where
    F: FnOnce() -> T,
{
    with_kernel_pt_lock(f)
}

/// Issue #109 §1.1: Acquire the per-address-space page-table lock shard for an
/// explicit canonical kernel CR3 physical root `root_phys` (e.g., `fork` CoW
/// cloning of `parent_page_table`).
#[inline]
pub fn with_as_pt_lock<T, F>(root_phys: u64, f: F) -> T
where
    F: FnOnce() -> T,
{
    let _guard = lock_as_pt(root_phys);
    f()
}

#[inline]
fn get_phys_offset() -> VirtAddr {
    VirtAddr::new(PHYSICAL_MEMORY_OFFSET)
}

/// 将物理地址转换为可访问的虚拟地址（通过高半区直映）
///
/// # Safety
///
/// 调用者必须确保物理地址在 0-1GB 范围内（高半区直映覆盖的范围）
/// 超出此范围的物理地址将导致无效的虚拟地址
#[inline]
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(phys.as_u64() + PHYSICAL_MEMORY_OFFSET)
}

/// Physical memory the [`PHYSICAL_MEMORY_OFFSET`] direct map covers (the
/// bootloader allocates every page-table frame below it).
const DIRECT_MAP_LIMIT: u64 = 1 << 30;

#[path = "mmio_access.rs"]
mod mmio_access;
pub use mmio_access::{with_kernel_mmio_mapping, MmioAccessError};
/// Physical-address field of a page-table entry (bits 12..=51).
const PTE_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
/// End of the lower canonical half, the user half of every address space.
const USER_HALF_END: u64 = 0x0000_8000_0000_0000;

/// R192-1/R192-2 FIX (D0-ISO-1): who owns the translation of a lower-half page.
///
/// User address spaces used to keep the boot identity map of physical 0-4 GiB
/// as supervisor-only entries in the lower half; since D0-ISO-1 Approach A only
/// the boot page table has it, and this check stays as defense in depth. Ring 0
/// may use a supervisor leaf whatever its U/S bit. An address below
/// the user-space top therefore proves nothing; only the U/S bit of every present
/// entry on the walk does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserPageAccess {
    /// No present translation: an access faults and the #PF path decides.
    NotPresent,
    /// Present with `USER_ACCESSIBLE` at every level; the leaf's `WRITABLE`
    /// and copy-on-write (`BIT_9`) flags.
    User { writable: bool, copy_on_write: bool },
    /// Reached through a present entry without `USER_ACCESSIBLE` (the identity
    /// map and the MMIO leaves split out of it), outside the user half, or not
    /// walkable through the direct map. No user request may read, write, map,
    /// remap, reprotect or unmap it.
    Kernel,
}

/// Classify `addr` in the hierarchy rooted at the PML4 frame `root`, reading
/// entry `index` of the table at physical `table` with `read`. Also returns
/// the end of the span the deciding entry covers, so a range walk skips an
/// absent or kernel-owned subtree in one step.
fn classify_user_page<R>(root: u64, addr: u64, read: &R) -> (UserPageAccess, u64)
where
    R: Fn(u64, usize) -> Option<u64>,
{
    let page_end = (addr & !0xfff).saturating_add(0x1000);
    if addr >= USER_HALF_END {
        return (UserPageAccess::Kernel, page_end);
    }
    let mut table = root;
    for (level, shift) in [(4u8, 39u32), (3, 30), (2, 21), (1, 12)] {
        let span_end = (addr | ((1u64 << shift) - 1)).saturating_add(1);
        let Some(raw) = read(table, ((addr >> shift) & 0x1ff) as usize) else {
            return (UserPageAccess::Kernel, page_end);
        };
        let flags = PageTableFlags::from_bits_truncate(raw);
        if !flags.contains(PageTableFlags::PRESENT) {
            return (UserPageAccess::NotPresent, span_end);
        }
        if !flags.contains(PageTableFlags::USER_ACCESSIBLE) {
            return (UserPageAccess::Kernel, span_end);
        }
        if level == 1 || (level < 4 && flags.contains(PageTableFlags::HUGE_PAGE)) {
            let access = UserPageAccess::User {
                writable: flags.contains(PageTableFlags::WRITABLE),
                copy_on_write: flags.contains(PageTableFlags::BIT_9),
            };
            return (access, span_end);
        }
        table = raw & PTE_ADDR_MASK;
    }
    (UserPageAccess::Kernel, page_end)
}

/// First page of `[start, start + len)` whose classification `stop` accepts,
/// skipping each deciding span in one step.
fn first_page_in<R, S>(root: u64, start: u64, len: u64, read: &R, stop: S) -> Option<u64>
where
    R: Fn(u64, usize) -> Option<u64>,
    S: Fn(UserPageAccess) -> bool,
{
    let end = start.saturating_add(len);
    let mut cursor = start & !0xfff;
    while cursor < end {
        let (access, next) = classify_user_page(root, cursor, read);
        if stop(access) || next <= cursor {
            return Some(cursor);
        }
        cursor = next;
    }
    None
}

/// First page of `[start, start + len)` that `classify_user_page` reports as
/// kernel-owned, skipping absent and user subtrees span by span.
fn first_kernel_owned_in<R>(root: u64, start: u64, len: u64, read: &R) -> Option<u64>
where
    R: Fn(u64, usize) -> Option<u64>,
{
    first_page_in(root, start, len, read, |access| {
        access == UserPageAccess::Kernel
    })
}

/// First page of `[start, start + len)` with any translation (user or kernel),
/// skipping absent subtrees span by span.
fn first_occupied_in<R>(root: u64, start: u64, len: u64, read: &R) -> Option<u64>
where
    R: Fn(u64, usize) -> Option<u64>,
{
    first_page_in(root, start, len, read, |access| {
        access != UserPageAccess::NotPresent
    })
}

/// Entry `index` of the page table at physical `table`, read through an offset
/// map at `phys_offset`; `None` (fail closed) for a frame outside the direct map.
#[inline]
fn read_offset_map_entry(phys_offset: u64, table: u64, index: usize) -> Option<u64> {
    if table >= DIRECT_MAP_LIMIT || index >= 512 {
        return None;
    }
    let entry = (phys_offset
        .wrapping_add(table)
        .wrapping_add(index as u64 * 8)) as *const u64;
    // SAFETY: `table` is a 4 KiB-aligned frame below the direct-map limit, so
    // the entry is mapped kernel memory. Another CPU may rewrite it; a volatile
    // word load observes one value (see `user_page_access`).
    Some(unsafe { core::ptr::read_volatile(entry) })
}

/// Entry `index` of the page table at physical `table`, read through the
/// direct map; `None` (fail closed) for a frame the direct map does not cover.
fn read_direct_map_entry(table: u64, index: usize) -> Option<u64> {
    read_offset_map_entry(PHYSICAL_MEMORY_OFFSET, table, index)
}

fn active_root() -> u64 {
    use x86_64::registers::control::Cr3;
    Cr3::read().0.start_address().as_u64()
}

/// PML4 entries of the lower (user) half.
const USER_PML4_ENTRIES: usize = 256;

/// LEAD-KPTI-PML4-1 FIX: the (kernel root, user root) pair this CPU registered
/// for the address space it runs, when KPTI gave that space two roots.
///
/// `activate_memory_space` writes the pair on this CPU only, with interrupts
/// off, so a reader with interrupts off never races the writer; a write in
/// progress means this CPU interrupted it, and the pair is unusable.
fn kpti_root_pair() -> Option<(u64, u64)> {
    let pcpu = cpu_local::current_cpu();
    let seq = pcpu.kpti_seq.load(Ordering::Acquire);
    let user = pcpu.kpti_user_cr3.load(Ordering::Acquire) & PTE_ADDR_MASK;
    let kernel = pcpu.kpti_kernel_cr3.load(Ordering::Acquire) & PTE_ADDR_MASK;
    if seq & 1 != 0 || pcpu.kpti_seq.load(Ordering::Acquire) != seq {
        return None;
    }
    let usable = |root: u64| root != 0 && root < DIRECT_MAP_LIMIT;
    (usable(kernel) && usable(user) && kernel != user).then_some((kernel, user))
}

/// LEAD-KPTI-PML4-1 FIX: the root an edit of the running address space goes
/// to. The kernel root is the master copy of the lower half: munmap, fork and
/// teardown walk it. A ring-3 page fault runs on the user root, and tables it
/// built there were invisible to all of them.
fn edit_root(pair: Option<(u64, u64)>) -> u64 {
    let cr3 = active_root();
    match pair {
        Some((kernel, user)) if cr3 == user => kernel,
        _ => cr3,
    }
}

/// The PML4 at physical `root`, through the direct map.
///
/// # Safety
///
/// `root` must be a live PML4 below [`DIRECT_MAP_LIMIT`], and the caller must
/// hold `PT_LOCK` for as long as it edits the table.
unsafe fn table_at(root: u64) -> &'static mut PageTable {
    &mut *((PHYSICAL_MEMORY_OFFSET + root) as *mut PageTable)
}

/// What [`mirror_user_half`] changed in a user root.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct MirrorOutcome {
    /// Entries the user root lacked: a PDPT created after it was built.
    linked: usize,
    /// Same PDPT, new permission bits.
    updated: usize,
    /// Entries that pointed elsewhere or vanished from the kernel root.
    diverged: usize,
}

/// The bits of a PML4 entry that decide a translation; the accessed bit the
/// hardware sets in each copy, and the software bits, do not.
fn link_bits(entry: &PageTableEntry) -> (PhysAddr, PageTableFlags) {
    let decisive = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::WRITE_THROUGH
        | PageTableFlags::NO_CACHE
        | PageTableFlags::NO_EXECUTE;
    (entry.addr(), entry.flags() & decisive)
}

/// LEAD-KPTI-PML4-1 FIX: make the user root's lower half match the kernel
/// root's.
///
/// Both roots share every lower-half PDPT; only their PML4 entries are copies,
/// taken when the user root was built (`create_kpti_user_pml4`). An entry an
/// edit created afterwards existed in the kernel root alone, so ring 3 faulted
/// (err=0x6) on every page under it, e.g. a mapping past PML4[0]. A changed or
/// vanished entry would mean a lower-half PDPT was replaced while the space is
/// live, which nothing does; the kernel root still wins, and it is reported.
fn mirror_user_half(kernel: &PageTable, user: &mut PageTable) -> MirrorOutcome {
    let mut outcome = MirrorOutcome::default();
    for index in 0..USER_PML4_ENTRIES {
        let (want_addr, want_flags) = link_bits(&kernel[index]);
        let (have_addr, have_flags) = link_bits(&user[index]);
        if (want_addr, want_flags) == (have_addr, have_flags) {
            continue;
        }
        let present = PageTableFlags::PRESENT;
        if user[index].is_unused() && want_flags.contains(present) {
            outcome.linked += 1;
        } else if want_addr == have_addr
            && want_flags.contains(present)
            && have_flags.contains(present)
        {
            outcome.updated += 1;
        } else {
            outcome.diverged += 1;
        }
        user[index] = kernel[index].clone();
    }
    outcome
}

/// LEAD-KPTI-PML4-1 FIX: after an edit of `edited`, bring the KPTI user root
/// of the running address space in line, if `edited` is its kernel root.
///
/// No shootdown is needed for a new entry: no CPU caches a non-present one.
/// Lower-half user parents are created final (`map_page`), so a rights change
/// means a regression, and is reported like a replaced or vanished entry; it
/// only ever adds rights, so a CPU holding the old entry takes one more fault.
///
/// # Safety
///
/// The caller holds `PT_LOCK` with interrupts off.
unsafe fn sync_kpti_user_root(edited: u64, pair: Option<(u64, u64)>) {
    let Some((kernel, user)) = pair else {
        return;
    };
    if edited != kernel {
        return;
    }
    let outcome = mirror_user_half(table_at(kernel), table_at(user));
    if outcome.updated != 0 || outcome.diverged != 0 {
        klog_always!(
            "[MM] KPTI user root 0x{:x} diverged from kernel root 0x{:x}: {} rights changes, {} replaced or vanished lower-half PML4 entries; resynced",
            user,
            kernel,
            outcome.updated,
            outcome.diverged
        );
    }
}

/// R192-1 FIX (D0-ISO-1): lock-free classification of the lower-half page at
/// `addr` in the active address space, for the user-memory primitives.
///
/// It takes no lock, so it is usable under any lock and with interrupts off. A
/// concurrent unmap may free and reuse a *user* page-table frame this walk is
/// reading, which can misreport a user translation but cannot hide a
/// kernel-owned one: every entry on the path to a kernel-owned translation is in
/// tables built with the address space (the identity map), which the guards
/// below keep any user request from changing or freeing, and runtime MMIO is
/// mapped in the higher half. The caller's access still goes through the MMU
/// and the exception table.
pub fn user_page_access(addr: VirtAddr) -> UserPageAccess {
    classify_user_page(active_root(), addr.as_u64(), &read_direct_map_entry).0
}

/// R192-2 FIX (D0-ISO-1): the address of the first kernel-owned page of
/// `[start, start + len)` in the active address space, or `None`. A user
/// mapping, heap or remap target must not contain one. Lock-free, with the same
/// argument as [`user_page_access`].
pub fn first_kernel_owned_user_page(start: u64, len: u64) -> Option<u64> {
    first_kernel_owned_in(active_root(), start, len, &read_direct_map_entry)
}

/// R192 FIX (LEAD-MMAP-OWN-1): the address of the first page of
/// `[start, start + len)` that has any translation in the active address
/// space, or `None`. A new mapping, heap grow or remap target is checked
/// against the VMA records first; a translation the records do not cover is
/// the ELF image, the committed heap, the stack or the kernel's identity map,
/// none of which a new VMA may claim (`munmap` would then remove it). Lock-free,
/// with the same argument as [`user_page_access`]: a stale walk can only
/// misreport pages of user tables, and the caller holds the VMA lock that
/// orders user mappings of this range.
pub fn first_occupied_user_page(start: u64, len: u64) -> Option<u64> {
    first_occupied_in(active_root(), start, len, &read_direct_map_entry)
}

/// R192-2: boot self-test of the `PageTableManager` guards on the boot root,
/// whose whole lower half is the supervisor identity map. Probes are chosen so
/// a kernel without the guards fails with a different, harmless error instead
/// of changing the map: `map_page` with `PRESENT` alone at a present identity
/// page (no flag to OR in; `PageAlreadyMapped` or `ParentEntryHugePage`), and
/// `unmap_page`/`update_flags` at 64 GiB, which the boot root does not map.
/// Returns `false` without probing when the boot root has no lower-half map
/// (an identity-unmap hardening profile); panics on failure.
///
/// # Safety
///
/// Call on the BSP during boot, with the boot root active and no user address
/// space loaded.
pub unsafe fn run_kernel_owned_guard_self_test() -> bool {
    const IDENTITY: u64 = 0x60_0000;
    const UNMAPPED_LOW: u64 = 0x10_0000_0000;
    if user_page_access(VirtAddr::new(IDENTITY)) == UserPageAccess::NotPresent {
        return false;
    }
    assert_eq!(
        user_page_access(VirtAddr::new(IDENTITY)),
        UserPageAccess::Kernel,
        "R192: the boot identity map must classify as kernel-owned"
    );
    assert_eq!(
        user_page_access(VirtAddr::new(UNMAPPED_LOW)),
        UserPageAccess::Kernel,
        "R192: the boot root's supervisor PML4[0] must own its whole span"
    );
    assert_eq!(
        first_kernel_owned_user_page(0x40_0000, 0x40_0000),
        Some(0x40_0000)
    );
    // The probes allocate no table: the guard refuses first, and without it
    // every parent of the identity page already exists.
    struct NoFrames;
    unsafe impl FrameAllocator<Size4KiB> for NoFrames {
        fn allocate_frame(&mut self) -> Option<PhysFrame> {
            None
        }
    }
    let (mapped, unmapped, updated) = with_kernel_manager(VirtAddr::new(0), |manager| {
        let mapped = manager.map_page(
            Page::containing_address(VirtAddr::new(IDENTITY)),
            PhysFrame::containing_address(PhysAddr::new(IDENTITY)),
            PageTableFlags::PRESENT,
            &mut NoFrames,
        );
        let low = Page::containing_address(VirtAddr::new(UNMAPPED_LOW));
        let unmapped = manager.unmap_page(low).map(|_| ());
        let updated = manager.update_flags(low, PageTableFlags::PRESENT);
        (mapped, unmapped, updated)
    });
    assert!(
        matches!(mapped, Err(MapError::KernelOwned)),
        "R192: map_page under the identity map returned {mapped:?}"
    );
    assert!(
        matches!(unmapped, Err(UnmapError::KernelOwned)),
        "R192: unmap_page in a supervisor span returned {unmapped:?}"
    );
    assert!(
        matches!(updated, Err(UpdateFlagsError::KernelOwned)),
        "R192: update_flags in a supervisor span returned {updated:?}"
    );
    true
}

/// 页表管理器
pub struct PageTableManager {
    mapper: OffsetPageTable<'static>,
    domain: PtDomain,
    root_phys: u64,
}

/// LEAD-PT-ZERO-LINK-1: the page-table frame source `map_page` hands to
/// `map_to`. x86_64's `create_next_table` links a new table into its parent
/// entry and only then zeroes it, and buddy frames are not zeroed, so in that
/// window another CPU walking the same address space could load whatever the
/// frame last held as live entries and keep them in its TLB. Each frame is
/// zeroed here, before it can be linked.
struct ZeroedTableFrames<'a, A> {
    inner: &'a mut A,
    phys_offset: VirtAddr,
}

unsafe impl<A: FrameAllocator<Size4KiB>> FrameAllocator<Size4KiB> for ZeroedTableFrames<'_, A> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let frame = self.inner.allocate_frame()?;
        // SAFETY: the allocator handed out a free frame that no table links
        // yet; page tables are reached through this same offset map.
        unsafe {
            let ptr = self
                .phys_offset
                .as_u64()
                .wrapping_add(frame.start_address().as_u64()) as *mut u8;
            core::ptr::write_bytes(ptr, 0, 4096);
        }
        Some(frame)
    }
}

/// Result of allocation-free rollback accounting for page-table frames that a
/// failed `map_to` operation allocated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrackedTableRollback {
    /// Empty leaf page tables detached and safe to return after this method's
    /// synchronous paging-structure flush.
    pub reclaimed_count: usize,
    /// Empty upper tables deliberately left reachable for reuse.  Kernel KPTI
    /// roots copy upper entry-island entries by value, so detaching those tables
    /// without a global root registry would leave stale aliases.
    pub retained_count: usize,
    /// Every tracked allocation was either reclaimed or proven reachable with
    /// no data leaves, including retained child tables. `false` requires
    /// fail-closed quarantine by the caller.
    pub all_accounted: bool,
}

/// 基于当前活动的 CR3 构建临时页表管理器（用户地址空间分片锁）。
///
/// Issue #109 §1.1: Resolves the canonical kernel CR3 root via `edit_root(kpti_root_pair())`,
/// acquires `AS_PT_LOCKS[as_pt_lock_shard(root)]` (or `KERNEL_PT_LOCK` for the boot root)
/// with the caller's original interrupt state intact (so incoming TLB shootdown IPIs from
/// the current holder are serviced while spinning), and executes `f` with interrupts disabled.
pub unsafe fn with_current_manager<T, F>(physical_memory_offset: VirtAddr, f: F) -> T
where
    F: FnOnce(&mut PageTableManager) -> T,
{
    // Sample canonical kernel root coherently before spinning on the lock with
    // the caller's original IF state (preserving shootdown IPI responsiveness).
    let root = interrupts::without_interrupts(|| edit_root(kpti_root_pair()));
    let _pt_guard = lock_as_pt(root);
    let domain = if is_boot_or_unregistered_root(root) {
        PtDomain::KernelShared
    } else {
        PtDomain::UserAddressSpace
    };

    // R32-MM-1 FIX: Disable interrupts to prevent CR3 switch during page table operations
    interrupts::without_interrupts(|| {
        let _ = physical_memory_offset;
        // LEAD-KPTI-PML4-1 FIX: edit the kernel root, then mirror it.
        let pair = kpti_root_pair();
        let live_root = edit_root(pair);
        debug_assert_eq!(
            live_root, root,
            "Issue #109 §1.1: CR3 changed while non-preemptible Ring-0 acquired AS PT lock"
        );
        let mapper = OffsetPageTable::new(table_at(live_root), get_phys_offset());
        let mut manager = PageTableManager {
            mapper,
            domain,
            root_phys: live_root,
        };
        let result = f(&mut manager);
        sync_kpti_user_root(live_root, pair);
        result
    })
}

/// Issue #109 §1.1 (H3): Build a [`PageTableManager`] under the dedicated shared
/// kernel high-half lock (`KERNEL_PT_LOCK`), regardless of which user CR3 is
/// currently loaded on this CPU.
///
/// Mandatory for all shared high-half mutations (`KSTACK_REGION`, MMIO, firmware
/// window, IST guard pages, boot probes).
pub unsafe fn with_kernel_manager<T, F>(physical_memory_offset: VirtAddr, f: F) -> T
where
    F: FnOnce(&mut PageTableManager) -> T,
{
    let _pt_guard = lock_kernel_pt();
    interrupts::without_interrupts(|| {
        let _ = physical_memory_offset;
        let pair = kpti_root_pair();
        let root = edit_root(pair);
        let mapper = OffsetPageTable::new(table_at(root), get_phys_offset());
        let mut manager = PageTableManager {
            mapper,
            domain: PtDomain::KernelShared,
            root_phys: root,
        };
        f(&mut manager)
    })
}

/// RF178-12: nonblocking `with_current_manager` variant for synchronous #PF.
///
/// # Safety
///
/// Caller must ensure `physical_memory_offset` is valid. A contended PT lock—
/// including same-CPU re-entry on any shard or `KERNEL_PT_LOCK`—returns `None`;
/// the exception dispatcher distinguishes proven same-CPU ownership from
/// ordinary cross-CPU contention via [`pt_lock_owner_cpu`].
pub unsafe fn try_with_current_manager<T, F>(physical_memory_offset: VirtAddr, f: F) -> Option<T>
where
    F: FnOnce(&mut PageTableManager) -> T,
{
    let self_cpu = cpu_local::current_cpu_id();
    // Fail closed before touching CR3 if this CPU already holds any PT lock
    // (preserves hosted reentry tests and forbids cross-shard/#PF self-reentry).
    if current_cpu_holds_any_pt_lock(self_cpu) {
        pt_lock_counters_for(self_cpu)
            .busy
            .fetch_add(1, Ordering::Relaxed);
        return None;
    }

    let root = interrupts::without_interrupts(|| edit_root(kpti_root_pair()));
    let _pt_guard = try_lock_as_pt(root)?;
    let domain = if is_boot_or_unregistered_root(root) {
        PtDomain::KernelShared
    } else {
        PtDomain::UserAddressSpace
    };
    Some(interrupts::without_interrupts(|| {
        let _ = physical_memory_offset;
        // LEAD-KPTI-PML4-1 FIX: a ring-3 fault runs on the user root; edit the
        // kernel root, then mirror it.
        let pair = kpti_root_pair();
        let live_root = edit_root(pair);
        let mapper = OffsetPageTable::new(table_at(live_root), get_phys_offset());
        let mut manager = PageTableManager {
            mapper,
            domain,
            root_phys: live_root,
        };
        let result = f(&mut manager);
        sync_kpti_user_root(live_root, pair);
        result
    }))
}

impl PageTableManager {
    /// 创建新的页表管理器
    ///
    /// # Safety
    ///
    /// 调用者必须确保物理内存偏移量是正确的
    pub unsafe fn new(physical_memory_offset: VirtAddr) -> Self {
        let _ = physical_memory_offset; // 保持接口兼容
        let phys_offset = get_phys_offset();
        let root_phys = active_root();
        let level_4_table = active_level_4_table(phys_offset);
        let mapper = OffsetPageTable::new(level_4_table, phys_offset);

        PageTableManager {
            mapper,
            domain: PtDomain::KernelShared,
            root_phys,
        }
    }

    /// Issue #109 §1.1 (H3): Enforce lock-domain isolation on every page-table
    /// mutation so a caller holding only a per-AS shard can never mutate shared
    /// kernel high-half mappings (and a `KERNEL_PT_LOCK`-only holder cannot
    /// mutate a live user address space's private lower half).
    #[inline]
    fn assert_domain_allows_mutation(&self, page: Page) {
        let addr = page.start_address().as_u64();
        if addr >= USER_HALF_END {
            assert_eq!(
                self.domain,
                PtDomain::KernelShared,
                "Issue #109 §1.1: high-half page-table mutation ({:#x}) requires KERNEL_PT_LOCK (use with_kernel_manager)",
                addr
            );
        } else if self.domain == PtDomain::KernelShared
            && !is_boot_or_unregistered_root(self.root_phys)
        {
            panic!(
                "Issue #109 §1.1: lower-half user page-table mutation ({:#x}) on root {:#x} requires per-AS lock (use with_current_manager)",
                addr, self.root_phys
            );
        }
    }

    /// R192-2 FIX (D0-ISO-1): whether `page` is in the lower half and owned by
    /// the kernel in this manager's hierarchy. The user-range operations below
    /// refuse such a page: no syscall may map a user page under, reprotect,
    /// unmap or reclaim the identity map shared with the kernel.
    #[inline]
    fn lower_half_kernel_owned(&mut self, page: Page) -> bool {
        let addr = page.start_address().as_u64();
        let phys_offset = self.mapper.phys_offset().as_u64();
        // The mapper reaches its PML4 through its offset map (`active_level_4_table`).
        let root =
            (self.mapper.level_4_table_mut() as *mut PageTable as u64).wrapping_sub(phys_offset);
        addr < USER_HALF_END
            && classify_user_page(root, addr, &|table, index| {
                read_offset_map_entry(phys_offset, table, index)
            })
            .0 == UserPageAccess::Kernel
    }

    /// How many page tables `map_page` would create for `page` (0-3): `map_to`
    /// allocates one for each empty entry on the walk below the PML4. A huge
    /// leaf, a non-present but used entry or an unreachable table counts as
    /// none, since `map_page` then refuses the page without allocating.
    pub fn missing_tables(&mut self, page: Page) -> usize {
        const PRESENT: u64 = 1;
        const HUGE: u64 = 1 << 7;
        let addr = page.start_address().as_u64();
        let mut table = (self.mapper.level_4_table_mut() as *mut PageTable as u64)
            .wrapping_sub(PHYSICAL_MEMORY_OFFSET);
        for (missing, shift) in [(3usize, 39u32), (2, 30), (1, 21)] {
            let index = ((addr >> shift) & 0x1ff) as usize;
            let Some(entry) = read_direct_map_entry(table, index) else {
                return 0;
            };
            if entry == 0 {
                return missing;
            }
            if entry & PRESENT == 0 || (missing < 3 && entry & HUGE != 0) {
                return 0;
            }
            table = entry & PTE_ADDR_MASK;
        }
        0
    }

    /// Whether a present 1 GiB or 2 MiB leaf maps `page`. A table the direct
    /// map cannot reach counts as one (fail closed).
    fn under_huge_leaf(&mut self, page: Page) -> bool {
        const PRESENT: u64 = 1;
        const HUGE: u64 = 1 << 7;
        let addr = page.start_address().as_u64();
        let mut table = (self.mapper.level_4_table_mut() as *mut PageTable as u64)
            .wrapping_sub(PHYSICAL_MEMORY_OFFSET);
        for (level, shift) in [(4u8, 39u32), (3, 30), (2, 21)] {
            let index = ((addr >> shift) & 0x1ff) as usize;
            let Some(entry) = read_direct_map_entry(table, index) else {
                return true;
            };
            if entry & PRESENT == 0 {
                return false;
            }
            if level < 4 && entry & HUGE != 0 {
                return true;
            }
            table = entry & PTE_ADDR_MASK;
        }
        false
    }

    /// 映射虚拟页到物理帧
    /// Return whether every 4 KiB leaf slot in `[start_page, start_page + count)`
    /// is structurally unused, walking each 2 MiB leaf PT at most once.
    ///
    /// Preserves the exact fail-closed semantics of [`Self::page_slot_is_unused`]:
    /// non-present entries retaining metadata, huge-page parents, invalid frame
    /// addresses, or virtual address overflow return `false`.
    pub fn page_range_slots_unused(&mut self, start_page: Page<Size4KiB>, count: usize) -> bool {
        if count == 0 {
            return true;
        }
        let start_u = start_page.start_address().as_u64();
        let Some(span_bytes) = (count as u64)
            .checked_sub(1)
            .and_then(|n| n.checked_mul(4096))
        else {
            return false;
        };
        if start_u.checked_add(span_bytes).is_none() {
            return false;
        }

        let phys_offset = self.mapper.phys_offset().as_u64();
        let pml4 = self.mapper.level_4_table_mut();
        let mut remaining = count;
        let mut cur = start_u;

        while remaining > 0 {
            let addr = VirtAddr::new(cur);
            let p4 = usize::from(addr.p4_index());
            let p3 = usize::from(addr.p3_index());
            let p2 = usize::from(addr.p2_index());
            let p1 = usize::from(addr.p1_index());

            let pml4e = &pml4[p4];
            if pml4e.is_unused() {
                let pages_in_p4 = ((512 - p3) * 512 - p2) * 512 - p1;
                let step = remaining.min(pages_in_p4);
                remaining -= step;
                cur = cur.wrapping_add((step as u64) * 4096);
                continue;
            }
            if !pml4e.flags().contains(PageTableFlags::PRESENT)
                || !page_table_frame_address_valid(pml4e.addr().as_u64())
            {
                return false;
            }

            let pdpt =
                unsafe { &*(phys_offset.wrapping_add(pml4e.addr().as_u64()) as *const PageTable) };
            let pdpte = &pdpt[p3];
            if pdpte.is_unused() {
                let pages_in_p3 = (512 - p2) * 512 - p1;
                let step = remaining.min(pages_in_p3);
                remaining -= step;
                cur = cur.wrapping_add((step as u64) * 4096);
                continue;
            }
            let pdpte_flags = pdpte.flags();
            if !pdpte_flags.contains(PageTableFlags::PRESENT)
                || pdpte_flags.contains(PageTableFlags::HUGE_PAGE)
                || !page_table_frame_address_valid(pdpte.addr().as_u64())
            {
                return false;
            }

            let pd =
                unsafe { &*(phys_offset.wrapping_add(pdpte.addr().as_u64()) as *const PageTable) };
            let pde = &pd[p2];
            let chunk = remaining.min(512 - p1);
            if pde.is_unused() {
                remaining -= chunk;
                cur = cur.wrapping_add((chunk as u64) * 4096);
                continue;
            }
            let pde_flags = pde.flags();
            if !pde_flags.contains(PageTableFlags::PRESENT)
                || pde_flags.contains(PageTableFlags::HUGE_PAGE)
                || !page_table_frame_address_valid(pde.addr().as_u64())
            {
                return false;
            }

            let pt =
                unsafe { &*(phys_offset.wrapping_add(pde.addr().as_u64()) as *const PageTable) };
            for idx in p1..p1 + chunk {
                if !pt[idx].is_unused() {
                    return false;
                }
            }
            remaining -= chunk;
            cur = cur.wrapping_add((chunk as u64) * 4096);
        }

        true
    }

    /// Map a contiguous range of supervisor-only 4 KiB pages into previously-unused
    /// leaf slots without per-page `invlpg`.
    ///
    /// Walks PML4 -> PDPT -> PD -> PT once per 2 MiB PT chunk instead of once per page.
    /// Newly allocated intermediate tables are zeroed before linking (LEAD-PT-ZERO-LINK-1).
    /// Because every target leaf is verified `is_unused()` (non-present) prior to
    /// writing, x86_64 hardware cannot hold a stale TLB entry for it (Intel SDM Vol. 3A
    /// §4.10.2.3).
    ///
    /// On failure, returns `Err((mapped_pages, err))` where `mapped_pages` is the exact
    /// prefix already installed so callers can run deterministic rollback.
    pub fn map_contiguous_kernel_pages_no_flush(
        &mut self,
        start_page: Page<Size4KiB>,
        start_frame: PhysFrame<Size4KiB>,
        count: usize,
        flags: PageTableFlags,
        frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    ) -> Result<(), (usize, MapError)> {
        if count == 0 {
            return Ok(());
        }
        if !flags.contains(PageTableFlags::PRESENT)
            || flags.contains(PageTableFlags::USER_ACCESSIBLE)
            || flags.contains(PageTableFlags::HUGE_PAGE)
        {
            return Err((0, MapError::InvalidRange));
        }

        let start_u = start_page.start_address().as_u64();
        let phys_start_u = start_frame.start_address().as_u64();
        let Some(span_bytes) = (count as u64)
            .checked_sub(1)
            .and_then(|n| n.checked_mul(4096))
        else {
            return Err((0, MapError::InvalidRange));
        };
        let Some(last_u) = start_u.checked_add(span_bytes) else {
            return Err((0, MapError::InvalidRange));
        };
        if phys_start_u.checked_add(span_bytes).is_none() {
            return Err((0, MapError::InvalidRange));
        }
        let last_page = Page::containing_address(VirtAddr::new(last_u));
        self.assert_domain_allows_mutation(start_page);
        self.assert_domain_allows_mutation(last_page);
        if start_u < USER_HALF_END || last_u < USER_HALF_END {
            return Err((0, MapError::KernelOwned));
        }

        let parent_flags = flags & (PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
        let phys_offset = self.mapper.phys_offset();
        let mut zeroed_alloc = ZeroedTableFrames {
            inner: frame_allocator,
            phys_offset,
        };
        let pml4 = self.mapper.level_4_table_mut();

        #[inline]
        fn ensure_child_table<'a, A: FrameAllocator<Size4KiB>>(
            entry: &mut PageTableEntry,
            parent_flags: PageTableFlags,
            alloc: &mut ZeroedTableFrames<'_, A>,
        ) -> Result<&'a mut PageTable, MapError> {
            let phys_offset = alloc.phys_offset.as_u64();
            if entry.is_unused() {
                let frame = alloc
                    .allocate_frame()
                    .ok_or(MapError::FrameAllocationFailed)?;
                entry.set_frame(frame, parent_flags);
                // SAFETY: `ZeroedTableFrames` zeroed the fresh offset-mapped frame.
                return Ok(unsafe {
                    &mut *(phys_offset.wrapping_add(frame.start_address().as_u64())
                        as *mut PageTable)
                });
            }
            let ef = entry.flags();
            if !ef.contains(PageTableFlags::PRESENT) {
                return Err(MapError::PageAlreadyMapped);
            }
            if ef.contains(PageTableFlags::HUGE_PAGE) {
                return Err(MapError::ParentEntryHugePage);
            }
            if !page_table_frame_address_valid(entry.addr().as_u64()) {
                return Err(MapError::InvalidRange);
            }
            if !ef.contains(parent_flags) {
                entry.set_addr(entry.addr(), ef | parent_flags);
            }
            // SAFETY: caller holds `KERNEL_PT_LOCK`; address validated above.
            Ok(
                unsafe {
                    &mut *(phys_offset.wrapping_add(entry.addr().as_u64()) as *mut PageTable)
                },
            )
        }

        let mut mapped = 0usize;
        let mut cur_v = start_u;
        let mut cur_p = phys_start_u;
        let leaf_bits = flags.bits();

        while mapped < count {
            let addr = VirtAddr::new(cur_v);
            let p4 = usize::from(addr.p4_index());
            let p3 = usize::from(addr.p3_index());
            let p2 = usize::from(addr.p2_index());
            let p1 = usize::from(addr.p1_index());

            let pdpt = ensure_child_table(&mut pml4[p4], parent_flags, &mut zeroed_alloc)
                .map_err(|e| (mapped, e))?;
            let pd = ensure_child_table(&mut pdpt[p3], parent_flags, &mut zeroed_alloc)
                .map_err(|e| (mapped, e))?;
            let pt = ensure_child_table(&mut pd[p2], parent_flags, &mut zeroed_alloc)
                .map_err(|e| (mapped, e))?;

            let chunk = (count - mapped).min(512 - p1);
            for offset in 0..chunk {
                let slot = &mut pt[p1 + offset];
                if !slot.is_unused() {
                    return Err((mapped, MapError::PageAlreadyMapped));
                }
                const _: () = assert!(core::mem::size_of::<PageTableEntry>() == 8);
                const _: () = assert!(core::mem::align_of::<PageTableEntry>() >= 8);
                let atomic_slot = unsafe { &*(slot as *mut PageTableEntry).cast::<AtomicU64>() };
                atomic_slot.store(cur_p | leaf_bits, Ordering::Release);
                mapped += 1;
                cur_v = cur_v.wrapping_add(4096);
                cur_p = cur_p.wrapping_add(4096);
            }
        }

        Ok(())
    }

    /// Prevalidate and clear a contiguous range of 4 KiB leaves in one walk per 2 MiB PT,
    /// without local `invlpg` (caller must ensure cross-CPU TLB invalidation before reuse).
    ///
    /// Phase 1 validates every leaf against `expected_start_frame + i * 4 KiB` without
    /// modifying any PTE. Phase 2 clears the validated leaves in reverse order.
    pub fn verify_and_unmap_contiguous_4k_no_flush(
        &mut self,
        start_page: Page<Size4KiB>,
        expected_start_frame: PhysFrame<Size4KiB>,
        count: usize,
    ) -> ContiguousUnmapOutcome {
        if count == 0 {
            return ContiguousUnmapOutcome::Verified;
        }
        let start_u = start_page.start_address().as_u64();
        let phys_start_u = expected_start_frame.start_address().as_u64();
        let Some(span_bytes) = (count as u64)
            .checked_sub(1)
            .and_then(|n| n.checked_mul(4096))
        else {
            return ContiguousUnmapOutcome::PrecheckFailed;
        };
        let Some(last_u) = start_u.checked_add(span_bytes) else {
            return ContiguousUnmapOutcome::PrecheckFailed;
        };
        if phys_start_u.checked_add(span_bytes).is_none() {
            return ContiguousUnmapOutcome::PrecheckFailed;
        }
        let last_page = Page::containing_address(VirtAddr::new(last_u));
        self.assert_domain_allows_mutation(start_page);
        self.assert_domain_allows_mutation(last_page);
        if self.lower_half_kernel_owned(start_page) || self.lower_half_kernel_owned(last_page) {
            return ContiguousUnmapOutcome::PrecheckFailed;
        }

        // Fast path covers any range spanning at most 2 leaf PTs (up to 2 MiB, e.g. all
        // kernel stacks even when straddling a 2 MiB boundary) with zero heap allocation.
        #[derive(Clone, Copy)]
        struct PtSpan {
            pt: *mut PageTable,
            p1_start: usize,
            len: usize,
            phys_start: u64,
        }
        let mut spans = [PtSpan {
            pt: core::ptr::null_mut(),
            p1_start: 0,
            len: 0,
            phys_start: 0,
        }; 2];
        let mut span_count = 0usize;

        let phys_offset = self.mapper.phys_offset().as_u64();
        let pml4 = self.mapper.level_4_table_mut();
        let mut checked = 0usize;
        let mut cur_v = start_u;
        let mut cur_p = phys_start_u;

        // Phase 1: read-only prevalidation across all `count` leaves.
        while checked < count {
            let addr = VirtAddr::new(cur_v);
            let pml4e = &pml4[usize::from(addr.p4_index())];
            if !pml4e.flags().contains(PageTableFlags::PRESENT)
                || !page_table_frame_address_valid(pml4e.addr().as_u64())
            {
                return ContiguousUnmapOutcome::PrecheckFailed;
            }
            let pdpt =
                unsafe { &*(phys_offset.wrapping_add(pml4e.addr().as_u64()) as *const PageTable) };
            let pdpte = &pdpt[usize::from(addr.p3_index())];
            let pdpte_flags = pdpte.flags();
            if !pdpte_flags.contains(PageTableFlags::PRESENT)
                || pdpte_flags.contains(PageTableFlags::HUGE_PAGE)
                || !page_table_frame_address_valid(pdpte.addr().as_u64())
            {
                return ContiguousUnmapOutcome::PrecheckFailed;
            }
            let pd =
                unsafe { &*(phys_offset.wrapping_add(pdpte.addr().as_u64()) as *const PageTable) };
            let pde = &pd[usize::from(addr.p2_index())];
            let pde_flags = pde.flags();
            if !pde_flags.contains(PageTableFlags::PRESENT)
                || pde_flags.contains(PageTableFlags::HUGE_PAGE)
                || !page_table_frame_address_valid(pde.addr().as_u64())
            {
                return ContiguousUnmapOutcome::PrecheckFailed;
            }
            let pt_ptr = phys_offset.wrapping_add(pde.addr().as_u64()) as *mut PageTable;
            let pt = unsafe { &*pt_ptr };
            let p1 = usize::from(addr.p1_index());
            let chunk = (count - checked).min(512 - p1);
            let chunk_phys_start = cur_p;

            for offset in 0..chunk {
                let entry = &pt[p1 + offset];
                if !entry.flags().contains(PageTableFlags::PRESENT)
                    || entry.addr().as_u64() != cur_p
                {
                    return ContiguousUnmapOutcome::PrecheckFailed;
                }
                cur_p = cur_p.wrapping_add(4096);
            }

            if span_count < spans.len() {
                spans[span_count] = PtSpan {
                    pt: pt_ptr,
                    p1_start: p1,
                    len: chunk,
                    phys_start: chunk_phys_start,
                };
            }
            span_count += 1;
            checked += chunk;
            cur_v = cur_v.wrapping_add((chunk as u64) * 4096);
        }

        // Phase 2: clear validated leaves in reverse order with zero local invlpg.
        let mut cleared = 0usize;
        let mut matched = 0usize;
        if span_count <= spans.len() {
            for s in (0..span_count).rev() {
                let span = spans[s];
                let pt = unsafe { &mut *span.pt };
                for offset in (0..span.len).rev() {
                    let expected = span.phys_start + (offset as u64) * 4096;
                    let entry = &mut pt[span.p1_start + offset];
                    let actual_flags = entry.flags();
                    let actual_phys = entry.addr().as_u64();
                    if !actual_flags.contains(PageTableFlags::PRESENT) {
                        return ContiguousUnmapOutcome::PartialMismatch { cleared, matched };
                    }
                    const _: () = assert!(core::mem::size_of::<PageTableEntry>() == 8);
                    const _: () = assert!(core::mem::align_of::<PageTableEntry>() >= 8);
                    let atomic_slot =
                        unsafe { &*(entry as *mut PageTableEntry).cast::<AtomicU64>() };
                    atomic_slot.store(0, Ordering::Release);
                    cleared += 1;
                    if actual_phys == expected {
                        matched += 1;
                    } else {
                        return ContiguousUnmapOutcome::PartialMismatch { cleared, matched };
                    }
                }
            }
        } else {
            // General fallback for ranges spanning >2 leaf PTs (>2 MiB).
            for index in (0..count).rev() {
                let page = Page::containing_address(VirtAddr::new(start_u + (index as u64) * 4096));
                let expected = PhysFrame::containing_address(PhysAddr::new(
                    phys_start_u + (index as u64) * 4096,
                ));
                match self.unmap_page(page) {
                    Ok(actual) => {
                        cleared += 1;
                        if actual == expected {
                            matched += 1;
                        } else {
                            return ContiguousUnmapOutcome::PartialMismatch { cleared, matched };
                        }
                    }
                    Err(_) => {
                        return ContiguousUnmapOutcome::PartialMismatch { cleared, matched };
                    }
                }
            }
        }

        debug_assert_eq!(cleared, count);
        debug_assert_eq!(matched, count);
        ContiguousUnmapOutcome::Verified
    }

    /// Resolve one present 4 KiB leaf in a single 4-level walk for atomic in-place
    /// inspection and replacement (e.g. CoW page fault handling).
    ///
    /// Enforces domain mutation checks and rejects lower-half kernel-owned mappings,
    /// huge parents, and invalid intermediate frame addresses.
    pub fn lookup_present_leaf_mut(
        &mut self,
        page: Page<Size4KiB>,
    ) -> Result<PresentLeafMut<'_>, ReplacePageError> {
        self.assert_domain_allows_mutation(page);
        if self.lower_half_kernel_owned(page) {
            return Err(ReplacePageError::KernelOwned);
        }
        let addr = page.start_address();
        let phys_offset = self.mapper.phys_offset().as_u64();
        let mut table = self.mapper.level_4_table_mut();
        for index in [addr.p4_index(), addr.p3_index(), addr.p2_index()] {
            let entry = &table[index];
            if !entry.flags().contains(PageTableFlags::PRESENT) {
                return Err(ReplacePageError::PageNotMapped);
            }
            if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                return Err(ReplacePageError::ParentEntryHugePage);
            }
            if !page_table_frame_address_valid(entry.addr().as_u64()) {
                return Err(ReplacePageError::InvalidFrameAddress);
            }
            // SAFETY: AS PT lock protects this present, offset-mapped table.
            table = unsafe {
                &mut *(phys_offset.wrapping_add(entry.addr().as_u64()) as *mut PageTable)
            };
        }
        let entry = &mut table[addr.p1_index()];
        if !entry.flags().contains(PageTableFlags::PRESENT) {
            return Err(ReplacePageError::PageNotMapped);
        }
        Ok(PresentLeafMut { entry })
    }

    /// Return whether the exact 4 KiB leaf slot is structurally unused.
    ///
    /// Unlike `translate_addr`, this treats a non-present PTE that still
    /// contains flags or a physical address as occupied. Mapping over such an
    /// entry would discard hidden ownership metadata or make rollback reason
    /// about a leaf it did not create.
    pub fn page_slot_is_unused(&mut self, page: Page<Size4KiB>) -> bool {
        let addr = page.start_address();
        let pml4 = self.mapper.level_4_table_mut();
        let pml4e = &pml4[usize::from(addr.p4_index())];
        if pml4e.is_unused() {
            return true;
        }
        if !pml4e.flags().contains(PageTableFlags::PRESENT) {
            return false;
        }

        let pdpt = unsafe { &*phys_to_virt(pml4e.addr()).as_ptr::<PageTable>() };
        let pdpte = &pdpt[usize::from(addr.p3_index())];
        if pdpte.is_unused() {
            return true;
        }
        let pdpte_flags = pdpte.flags();
        if !pdpte_flags.contains(PageTableFlags::PRESENT)
            || pdpte_flags.contains(PageTableFlags::HUGE_PAGE)
        {
            return false;
        }

        let pd = unsafe { &*phys_to_virt(pdpte.addr()).as_ptr::<PageTable>() };
        let pde = &pd[usize::from(addr.p2_index())];
        if pde.is_unused() {
            return true;
        }
        let pde_flags = pde.flags();
        if !pde_flags.contains(PageTableFlags::PRESENT)
            || pde_flags.contains(PageTableFlags::HUGE_PAGE)
        {
            return false;
        }

        let pt = unsafe { &*phys_to_virt(pde.addr()).as_ptr::<PageTable>() };
        pt[usize::from(addr.p1_index())].is_unused()
    }

    /// Return whether the complete 512 GiB PML4 slot containing `addr` is
    /// structurally unused.
    ///
    /// This is stronger than [`Self::page_slot_is_unused`]: a vacant leaf in an
    /// already-populated hierarchy is not sufficient for tests or transactions
    /// that need a deterministic number of intermediate-table allocations.
    /// `PageTableEntry::is_unused` also rejects non-present entries that retain
    /// flags or an address, so callers never overwrite hidden ownership state.
    pub fn pml4_slot_is_unused(&mut self, addr: VirtAddr) -> bool {
        let pml4 = self.mapper.level_4_table_mut();
        pml4[usize::from(addr.p4_index())].is_unused()
    }

    /// Translate one exact 4 KiB page. Huge-parent mappings are rejected.
    #[inline]
    pub fn translate_page_4k(&self, page: Page<Size4KiB>) -> Option<PhysFrame<Size4KiB>> {
        self.mapper.translate_page(page).ok()
    }

    pub fn map_page(
        &mut self,
        page: Page,
        frame: PhysFrame,
        flags: PageTableFlags,
        frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    ) -> Result<(), MapError> {
        use x86_64::structures::paging::mapper::MapToError;

        self.assert_domain_allows_mutation(page);

        // R192-2 FIX: `map_to` ORs the leaf's flags into every existing parent
        // entry before it checks for a huge page, so a map under the identity
        // map would make its supervisor entries (or a 2 MiB leaf) user-accessible
        // or writable, and could install the leaf into a page table shared with
        // the kernel. Every legitimate caller maps user pages outside it or
        // kernel pages in the higher half; the hardening code edits the
        // identity map's entries directly.
        if self.lower_half_kernel_owned(page) {
            return Err(MapError::KernelOwned);
        }

        // LEAD-KPTI-PML4-1 FIX: a lower-half user page's parents are created
        // final (P|W|U; the leaf decides access, as on Linux). `map_to` ORs the
        // leaf's W/U into an existing parent instead, and a read-only page
        // followed by a writable one in the same 512 GiB slot then changed a
        // PML4 entry the KPTI user root holds a copy of, and that other CPUs
        // may cache.
        let mut parent_flags = flags
            & (PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::USER_ACCESSIBLE);
        if page.start_address().as_u64() < USER_HALF_END
            && flags.contains(PageTableFlags::USER_ACCESSIBLE)
        {
            // `map_to` ORs the parent flags into a huge leaf before it reports
            // `ParentEntryHugePage`; with W forced, that would make a read-only
            // huge leaf writable. Refuse first.
            if self.under_huge_leaf(page) {
                return Err(MapError::ParentEntryHugePage);
            }
            parent_flags = PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::USER_ACCESSIBLE;
        }

        // LEAD-PT-ZERO-LINK-1 FIX: tables are zeroed before `map_to` links them.
        let mut frame_allocator = ZeroedTableFrames {
            inner: frame_allocator,
            phys_offset: self.mapper.phys_offset(),
        };
        unsafe {
            self.mapper
                .map_to_with_table_flags(page, frame, flags, parent_flags, &mut frame_allocator)
                .map_err(|e| match e {
                    MapToError::FrameAllocationFailed => MapError::FrameAllocationFailed,
                    MapToError::ParentEntryHugePage => MapError::ParentEntryHugePage,
                    MapToError::PageAlreadyMapped(_) => MapError::PageAlreadyMapped,
                })?
                .flush();
        }

        Ok(())
    }

    /// Map a contiguous range of fresh lower-half user 4 KiB pages to `frames`
    /// in a single 4-level walk per 2 MiB PT, without per-page `invlpg`.
    ///
    /// Preserves every security and rollback invariant of [`Self::map_page`]:
    /// - R192-2: refuses any supervisor-owned lower-half entry (`KernelOwned`)
    ///   and any 1 GiB / 2 MiB huge-page parent (`ParentEntryHugePage`).
    /// - LEAD-KPTI-PML4-1: creates lower-half parent entries with final
    ///   `PRESENT | WRITABLE | USER_ACCESSIBLE` flags.
    /// - LEAD-PT-ZERO-LINK-1: zeroes every newly allocated table frame before
    ///   linking it (`ZeroedTableFrames`).
    /// - R192-RES-2: checks missing table count against `available_tables`
    ///   before linking any table for a 2 MiB span, returning
    ///   `BatchMapUserError::Starved` with zero partially linked empty tables.
    /// - Skips per-page `invlpg` because x86_64 never caches non-present PTEs
    ///   in the TLB (Intel SDM Vol. 3A §4.10.2.3) and every target slot is
    ///   verified unused before publishing with an atomic `Release` store.
    pub fn map_user_pages_no_flush(
        &mut self,
        start_page: Page<Size4KiB>,
        frames: &[PhysFrame<Size4KiB>],
        flags: PageTableFlags,
        available_tables: usize,
        frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    ) -> Result<(), BatchMapUserError> {
        if frames.is_empty() {
            return Ok(());
        }
        if !flags.contains(PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE)
            || flags.contains(PageTableFlags::HUGE_PAGE)
        {
            return Err(BatchMapUserError::Failed {
                mapped: 0,
                error: MapError::InvalidRange,
            });
        }

        let start_u = start_page.start_address().as_u64();
        let Some(span_bytes) = (frames.len() as u64)
            .checked_sub(1)
            .and_then(|n| n.checked_mul(4096))
        else {
            return Err(BatchMapUserError::Failed {
                mapped: 0,
                error: MapError::InvalidRange,
            });
        };
        let Some(last_u) = start_u.checked_add(span_bytes) else {
            return Err(BatchMapUserError::Failed {
                mapped: 0,
                error: MapError::InvalidRange,
            });
        };
        if start_u >= USER_HALF_END || last_u >= USER_HALF_END {
            return Err(BatchMapUserError::Failed {
                mapped: 0,
                error: MapError::KernelOwned,
            });
        }
        let last_page = Page::containing_address(VirtAddr::new(last_u));
        self.assert_domain_allows_mutation(start_page);
        self.assert_domain_allows_mutation(last_page);

        let parent_flags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
        let phys_offset = self.mapper.phys_offset();
        let phys_offset_u = phys_offset.as_u64();
        let mut zeroed_alloc = ZeroedTableFrames {
            inner: frame_allocator,
            phys_offset,
        };
        let pml4 = self.mapper.level_4_table_mut();

        #[inline]
        fn ensure_user_child_table<'a, A: FrameAllocator<Size4KiB>>(
            entry: &mut PageTableEntry,
            parent_flags: PageTableFlags,
            alloc: &mut ZeroedTableFrames<'_, A>,
        ) -> Result<&'a mut PageTable, MapError> {
            let phys_offset = alloc.phys_offset.as_u64();
            if entry.is_unused() {
                let frame = alloc
                    .allocate_frame()
                    .ok_or(MapError::FrameAllocationFailed)?;
                entry.set_frame(frame, parent_flags);
                // SAFETY: `ZeroedTableFrames` zeroed the fresh offset-mapped frame.
                return Ok(unsafe {
                    &mut *(phys_offset.wrapping_add(frame.start_address().as_u64())
                        as *mut PageTable)
                });
            }
            let ef = entry.flags();
            if !ef.contains(parent_flags) {
                entry.set_addr(entry.addr(), ef | parent_flags);
            }
            // SAFETY: caller holds AS PT_LOCK; parent presence/address already validated.
            Ok(
                unsafe {
                    &mut *(phys_offset.wrapping_add(entry.addr().as_u64()) as *mut PageTable)
                },
            )
        }

        let mut mapped = 0usize;
        let mut cur_v = start_u;
        let mut remaining_tables = available_tables;
        let leaf_bits = flags.bits();

        while mapped < frames.len() {
            let addr = VirtAddr::new(cur_v);
            let p4 = usize::from(addr.p4_index());
            let p3 = usize::from(addr.p3_index());
            let p2 = usize::from(addr.p2_index());
            let p1 = usize::from(addr.p1_index());

            // Pre-validate existing parents and count exact missing tables
            // before allocating or linking any intermediate table.
            let missing = {
                let pml4e = &pml4[p4];
                if pml4e.is_unused() {
                    3usize
                } else {
                    let f4 = pml4e.flags();
                    if !f4.contains(PageTableFlags::PRESENT) {
                        return Err(BatchMapUserError::Failed {
                            mapped,
                            error: MapError::PageAlreadyMapped,
                        });
                    }
                    if !f4.contains(PageTableFlags::USER_ACCESSIBLE) {
                        return Err(BatchMapUserError::Failed {
                            mapped,
                            error: MapError::KernelOwned,
                        });
                    }
                    if !page_table_frame_address_valid(pml4e.addr().as_u64()) {
                        return Err(BatchMapUserError::Failed {
                            mapped,
                            error: MapError::InvalidRange,
                        });
                    }
                    let pdpt = unsafe {
                        &*(phys_offset_u.wrapping_add(pml4e.addr().as_u64()) as *const PageTable)
                    };
                    let pdpte = &pdpt[p3];
                    if pdpte.is_unused() {
                        2usize
                    } else {
                        let f3 = pdpte.flags();
                        if !f3.contains(PageTableFlags::PRESENT) {
                            return Err(BatchMapUserError::Failed {
                                mapped,
                                error: MapError::PageAlreadyMapped,
                            });
                        }
                        if !f3.contains(PageTableFlags::USER_ACCESSIBLE) {
                            return Err(BatchMapUserError::Failed {
                                mapped,
                                error: MapError::KernelOwned,
                            });
                        }
                        if f3.contains(PageTableFlags::HUGE_PAGE) {
                            return Err(BatchMapUserError::Failed {
                                mapped,
                                error: MapError::ParentEntryHugePage,
                            });
                        }
                        if !page_table_frame_address_valid(pdpte.addr().as_u64()) {
                            return Err(BatchMapUserError::Failed {
                                mapped,
                                error: MapError::InvalidRange,
                            });
                        }
                        let pd = unsafe {
                            &*(phys_offset_u.wrapping_add(pdpte.addr().as_u64())
                                as *const PageTable)
                        };
                        let pde = &pd[p2];
                        if pde.is_unused() {
                            1usize
                        } else {
                            let f2 = pde.flags();
                            if !f2.contains(PageTableFlags::PRESENT) {
                                return Err(BatchMapUserError::Failed {
                                    mapped,
                                    error: MapError::PageAlreadyMapped,
                                });
                            }
                            if !f2.contains(PageTableFlags::USER_ACCESSIBLE) {
                                return Err(BatchMapUserError::Failed {
                                    mapped,
                                    error: MapError::KernelOwned,
                                });
                            }
                            if f2.contains(PageTableFlags::HUGE_PAGE) {
                                return Err(BatchMapUserError::Failed {
                                    mapped,
                                    error: MapError::ParentEntryHugePage,
                                });
                            }
                            if !page_table_frame_address_valid(pde.addr().as_u64()) {
                                return Err(BatchMapUserError::Failed {
                                    mapped,
                                    error: MapError::InvalidRange,
                                });
                            }
                            0usize
                        }
                    }
                }
            };

            if missing > remaining_tables {
                return Err(BatchMapUserError::Starved {
                    mapped,
                    shortfall: missing - remaining_tables,
                });
            }

            let pdpt = ensure_user_child_table(&mut pml4[p4], parent_flags, &mut zeroed_alloc)
                .map_err(|error| BatchMapUserError::Failed { mapped, error })?;
            let pd = ensure_user_child_table(&mut pdpt[p3], parent_flags, &mut zeroed_alloc)
                .map_err(|error| BatchMapUserError::Failed { mapped, error })?;
            let pt = ensure_user_child_table(&mut pd[p2], parent_flags, &mut zeroed_alloc)
                .map_err(|error| BatchMapUserError::Failed { mapped, error })?;
            remaining_tables -= missing;

            let chunk = (frames.len() - mapped).min(512 - p1);
            for offset in 0..chunk {
                let slot = &mut pt[p1 + offset];
                if !slot.is_unused() {
                    return Err(BatchMapUserError::Failed {
                        mapped,
                        error: MapError::PageAlreadyMapped,
                    });
                }
                const _: () = assert!(core::mem::size_of::<PageTableEntry>() == 8);
                const _: () = assert!(core::mem::align_of::<PageTableEntry>() >= 8);
                let phys = frames[mapped].start_address().as_u64();
                let atomic_slot = unsafe { &*(slot as *mut PageTableEntry).cast::<AtomicU64>() };
                atomic_slot.store(phys | leaf_bits, Ordering::Release);
                mapped += 1;
                cur_v = cur_v.wrapping_add(4096);
            }
        }

        Ok(())
    }

    /// Clear all present user 4 KiB leaves and R141-9 non-present `PROT_NONE`
    /// leaves in `[start, start + len)` in one walk per 2 MiB PT, without
    /// per-page `invlpg`.
    ///
    /// Invokes `on_frame(page, frame)` for every reclaimed leaf frame. Callers
    /// MUST issue a cross-CPU TLB shootdown before decrementing refcounts or
    /// freeing any returned frame. Skips any supervisor-owned or huge-page
    /// subtree (R192-2).
    pub fn unmap_user_range_no_flush<F>(&mut self, start: VirtAddr, len: usize, mut on_frame: F)
    where
        F: FnMut(Page<Size4KiB>, PhysFrame<Size4KiB>),
    {
        if len == 0 || (start.as_u64() & 0xfff) != 0 || (len & 0xfff) != 0 {
            return;
        }
        let start_u = start.as_u64();
        let Some(end_u) = start_u.checked_add(len as u64) else {
            return;
        };
        if end_u > USER_HALF_END {
            return;
        }
        let first_page = Page::containing_address(start);
        let last_page = Page::containing_address(VirtAddr::new(end_u - 4096));
        self.assert_domain_allows_mutation(first_page);
        self.assert_domain_allows_mutation(last_page);

        #[inline]
        fn user_parent(flags: PageTableFlags) -> bool {
            flags.contains(PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE)
        }

        const PT_SPAN: u64 = 0x20_0000;
        let phys_offset = self.mapper.phys_offset().as_u64();
        let pml4 = self.mapper.level_4_table_mut();

        let mut cur_v = start_u;
        while cur_v < end_u {
            let addr = VirtAddr::new(cur_v);
            let p4 = usize::from(addr.p4_index());
            let p3 = usize::from(addr.p3_index());
            let p2 = usize::from(addr.p2_index());
            let p1 = usize::from(addr.p1_index());
            let pt_end = ((cur_v & !(PT_SPAN - 1)).saturating_add(PT_SPAN)).min(end_u);
            let chunk = ((pt_end - cur_v) / 4096) as usize;

            let pml4e = &pml4[p4];
            if user_parent(pml4e.flags()) && page_table_frame_address_valid(pml4e.addr().as_u64()) {
                let pdpt = unsafe {
                    &mut *(phys_offset.wrapping_add(pml4e.addr().as_u64()) as *mut PageTable)
                };
                let pdpte = &pdpt[p3];
                let f3 = pdpte.flags();
                if user_parent(f3)
                    && !f3.contains(PageTableFlags::HUGE_PAGE)
                    && page_table_frame_address_valid(pdpte.addr().as_u64())
                {
                    let pd = unsafe {
                        &mut *(phys_offset.wrapping_add(pdpte.addr().as_u64()) as *mut PageTable)
                    };
                    let pde = &pd[p2];
                    let f2 = pde.flags();
                    if user_parent(f2)
                        && !f2.contains(PageTableFlags::HUGE_PAGE)
                        && page_table_frame_address_valid(pde.addr().as_u64())
                    {
                        let pt = unsafe {
                            &mut *(phys_offset.wrapping_add(pde.addr().as_u64()) as *mut PageTable)
                        };
                        for offset in 0..chunk {
                            let pte = &mut pt[p1 + offset];
                            let flags = pte.flags();
                            if flags.contains(PageTableFlags::PRESENT) {
                                if !flags.contains(PageTableFlags::USER_ACCESSIBLE) {
                                    continue;
                                }
                                let frame = PhysFrame::containing_address(pte.addr());
                                pte.set_unused();
                                let page = Page::containing_address(VirtAddr::new(
                                    cur_v + (offset as u64) * 4096,
                                ));
                                on_frame(page, frame);
                            } else {
                                let phys = pte.addr();
                                if phys.as_u64() != 0 {
                                    let frame = PhysFrame::containing_address(phys);
                                    pte.set_unused();
                                    let page = Page::containing_address(VirtAddr::new(
                                        cur_v + (offset as u64) * 4096,
                                    ));
                                    on_frame(page, frame);
                                }
                            }
                        }
                    }
                }
            }

            cur_v = pt_end;
        }
    }

    /// Replace a present 4 KiB leaf without ever making it non-present.
    ///
    /// LEAD-G8-CHILDREN-SEGV-1: readers do not acquire PT_LOCK. An unmap/map
    /// pair therefore kills a sibling that walks the page during the gap.
    /// Validate the entire walk first, then publish frame and flags with one
    /// aligned atomic store. No allocation or fallible work follows the store.
    ///
    /// The caller holds the address-space PT lock, owns `new_frame`, and must
    /// synchronously flush all CPUs sharing this address space BEFORE releasing
    /// `expected_frame`. On error the old mapping and both frames' ownership are unchanged.
    pub fn replace_page(
        &mut self,
        page: Page<Size4KiB>,
        expected_frame: PhysFrame<Size4KiB>,
        new_frame: PhysFrame<Size4KiB>,
        flags: PageTableFlags,
    ) -> Result<(), ReplacePageError> {
        self.assert_domain_allows_mutation(page);
        if self.lower_half_kernel_owned(page) {
            return Err(ReplacePageError::KernelOwned);
        }
        let addr = page.start_address();
        let mut table = self.mapper.level_4_table_mut();
        for index in [addr.p4_index(), addr.p3_index(), addr.p2_index()] {
            let entry = &table[index];
            if !entry.flags().contains(PageTableFlags::PRESENT) {
                return Err(ReplacePageError::PageNotMapped);
            }
            if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                return Err(ReplacePageError::ParentEntryHugePage);
            }
            if !page_table_frame_address_valid(entry.addr().as_u64()) {
                return Err(ReplacePageError::InvalidFrameAddress);
            }
            // SAFETY: AS PT lock protects this present, direct-mapped table.
            table = unsafe { &mut *phys_to_virt(entry.addr()).as_mut_ptr::<PageTable>() };
        }
        replace_present_leaf(
            &mut table[addr.p1_index()],
            expected_frame,
            new_frame,
            flags,
        )
    }

    /// 取消映射虚拟页
    pub fn unmap_page(&mut self, page: Page) -> Result<PhysFrame, UnmapError> {
        use x86_64::structures::paging::mapper::UnmapError as X64UnmapError;

        self.assert_domain_allows_mutation(page);

        // R192-2 FIX: never clear an identity-map or split-MMIO leaf.
        if self.lower_half_kernel_owned(page) {
            return Err(UnmapError::KernelOwned);
        }

        let (frame, flush) = self.mapper.unmap(page).map_err(|e| match e {
            X64UnmapError::PageNotMapped => UnmapError::PageNotMapped,
            X64UnmapError::ParentEntryHugePage => UnmapError::ParentEntryHugePage,
            X64UnmapError::InvalidFrameAddress(_) => UnmapError::InvalidFrameAddress,
        })?;

        flush.flush();
        Ok(frame)
    }

    /// R141-9 FIX: Reclaim a physical frame referenced by a non-present leaf PTE.
    ///
    /// When `mprotect(PROT_NONE)` clears the PRESENT bit, the physical frame
    /// address remains encoded in the PTE.  Standard `unmap_page()` returns
    /// `PageNotMapped` for such entries, causing `sys_munmap` to silently skip
    /// the frame — a memory leak that also breaks cgroup charge-balance.
    ///
    /// This method walks from the manager's existing PML4 reference (avoiding
    /// a second `&mut` alias from re-reading CR3) and, if the leaf PTE is
    /// non-present but contains a non-zero physical address, extracts the
    /// frame, clears the PTE, and returns it.
    ///
    /// Must be called while the address-space PT lock is held (inside `with_current_manager`).
    pub fn take_nonpresent_leaf_frame(&mut self, page: Page) -> Option<PhysFrame> {
        self.assert_domain_allows_mutation(page);
        // R192-2 FIX: a non-present entry under a supervisor parent is kernel
        // state, not a frame a user mapping left behind.
        if self.lower_half_kernel_owned(page) {
            return None;
        }
        let addr = page.start_address();
        let pml4_idx = usize::from(addr.p4_index());
        let pdpt_idx = usize::from(addr.p3_index());
        let pd_idx = usize::from(addr.p2_index());
        let pt_idx = usize::from(addr.p1_index());

        // Walk from the mapper's PML4 — no aliasing, no second CR3 read.
        let pml4 = self.mapper.level_4_table_mut();

        // PML4 → PDPT
        let pml4e = &pml4[pml4_idx];
        if !pml4e.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }
        let pdpt: &mut PageTable = unsafe { &mut *phys_to_virt(pml4e.addr()).as_mut_ptr() };

        // PDPT → PD
        let pdpte = &pdpt[pdpt_idx];
        let pdpte_flags = pdpte.flags();
        if !pdpte_flags.contains(PageTableFlags::PRESENT) {
            return None;
        }
        if pdpte_flags.contains(PageTableFlags::HUGE_PAGE) {
            return None; // 1GiB huge page — not a 4KiB leaf
        }
        let pd: &mut PageTable = unsafe { &mut *phys_to_virt(pdpte.addr()).as_mut_ptr() };

        // PD → PT
        let pde = &pd[pd_idx];
        let pde_flags = pde.flags();
        if !pde_flags.contains(PageTableFlags::PRESENT) {
            return None;
        }
        if pde_flags.contains(PageTableFlags::HUGE_PAGE) {
            return None; // 2MiB huge page — not a 4KiB leaf
        }
        let pt: &mut PageTable = unsafe { &mut *phys_to_virt(pde.addr()).as_mut_ptr() };

        // Read leaf PTE
        let pte = &mut pt[pt_idx];

        // Only interested in non-present entries with a non-zero physical address.
        if pte.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }

        let phys = pte.addr();
        if phys.as_u64() == 0 {
            return None; // Truly empty — nothing to reclaim
        }

        // Reclaim: extract frame and clear PTE
        let frame = PhysFrame::containing_address(phys);
        pte.set_unused();
        Some(frame)
    }

    /// R169-L2 FIX: reclaim now-empty intermediate page tables after a rollback
    /// has cleared this operation's leaf PTEs.
    ///
    /// `map_page`/`map_to` pulls intermediate PT/PD frames from the supplied
    /// allocator (`create_next_table`). When an mmap / mprotect-Path-A commit
    /// OOMs partway, the unwind unmaps the leaf PTEs and frees the DATA frames,
    /// but the intermediate tables it created are orphaned until address-space
    /// teardown. This walks `[start, start+len)` and, for every PT and PD table
    /// that is now **entirely empty**, clears the parent entry pointing at it and
    /// queues the freed frame into `frames_to_free`.
    ///
    /// # Scope
    ///
    /// Only the **PT** and **PD** levels are pruned. These clear a PDE / PDPTE in
    /// a PDPT/PD that is *shared by value* between the kernel root and the KPTI
    /// user root (only PML4 entries are copied per-root — see `fork.rs`), so the
    /// change is visible through both roots with no mirroring. The PDPT level is
    /// intentionally **not** pruned: freeing a PDPT means clearing a PML4E, which
    /// would have to be mirrored into the KPTI user root. A tracked PDPT that is
    /// still referenced by the exact PML4E is explicitly accounted as retained;
    /// the residual is at most one frame per fresh 512-GiB region and remains
    /// reachable for reuse/exit reclamation.
    ///
    /// # Safety invariant
    ///
    /// A table is freed **iff all 512 entries are unused**. Under `PT_LOCK` (held
    /// via `with_current_manager`) writers are serialized, so a table still
    /// reachable by any other live mapping retains at least one present entry and
    /// is never freed; an all-empty table can only be one this operation created
    /// (or one whose last mapping this rollback removed) → safe to free. HUGE_PAGE
    /// parents are leaf mappings, never walked or freed.
    ///
    /// The parent entry is cleared **only if the frame is successfully queued**;
    /// otherwise the table is left present (and reclaimed at teardown), so a frame
    /// is never orphaned by a clear-without-free.
    ///
    /// # Caller contract
    ///
    /// - Hold `PT_LOCK` (inside `with_current_manager`).
    /// - Have already cleared every leaf PTE this operation mapped in the range.
    /// - Pass the SAME `len` used for the post-rollback `flush_current_as_range`,
    ///   and free `frames_to_free` only AFTER that flush — so the paging-structure
    ///   caches referencing the freed tables are invalidated before reuse (the
    ///   freed frames ride the existing 3-phase data-frame free).
    pub unsafe fn prune_empty_tables_in_range(
        &mut self,
        start: VirtAddr,
        len: usize,
        frames_to_free: &mut Vec<PhysFrame>,
    ) {
        if self.prune_empty_tables_in_range_no_flush(start, len, frames_to_free) {
            // R169-L2 FIX: a collapsed PDE/PDPTE removes a paging-structure entry that
            // spans up to 2 MiB / 1 GiB — beyond the caller's leaf-range flush. Issue a
            // full TLB + paging-structure-cache shootdown (all CPUs) so no stale cached
            // parent translation can reference a freed table frame once the caller
            // returns it to the allocator.
            crate::tlb_shootdown::flush_current_as_all();
        }
    }

    /// Detach now-empty PT/PD tables in `[start, start + len)` without issuing
    /// the post-prune TLB shootdown, returning `true` iff any parent PDE/PDPTE
    /// was cleared.
    ///
    /// # Safety
    /// Same caller contract as [`Self::prune_empty_tables_in_range`], plus:
    /// whenever this returns `true`, the caller MUST invoke
    /// `flush_current_as_all()` before releasing `PT_LOCK` or freeing any
    /// frame in `frames_to_free`.
    pub unsafe fn prune_empty_tables_in_range_no_flush(
        &mut self,
        start: VirtAddr,
        len: usize,
        frames_to_free: &mut Vec<PhysFrame>,
    ) -> bool {
        if len == 0 {
            return false;
        }

        /// 2 MiB — virtual span covered by one PT (512 × 4 KiB).
        const PT_SPAN: u64 = 0x20_0000;
        /// 1 GiB — virtual span covered by one PD (512 × 2 MiB).
        const PD_SPAN: u64 = 0x4000_0000;

        #[inline]
        fn table_empty(table: &PageTable) -> bool {
            table.iter().all(|entry| entry.is_unused())
        }

        // R192-2 FIX (D0-ISO-1): every caller prunes a user range. A table
        // reached through a supervisor-only entry belongs to the kernel's
        // identity map, which other address spaces share; freeing it would
        // leave their entries pointing at a reused frame. Only tables whose
        // whole path is USER_ACCESSIBLE are candidates.
        #[inline]
        fn user_parent(flags: PageTableFlags) -> bool {
            flags.contains(PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE)
        }

        let start_u = start.as_u64();
        let end_u = start_u.saturating_add((len as u64).saturating_sub(1));
        // Set when any parent entry is collapsed; drives the post-pass full flush.
        let mut reclaimed_any = false;
        // PML4 reference (matches take_nonpresent_leaf_frame). We only READ PML4
        // entries here (never clear them), so no per-root KPTI mirroring is needed;
        // the lower PDPT/PD/PT frames are shared by value between both roots.
        let pml4 = self.mapper.level_4_table_mut();

        // ── PT pass: free empty PTs, clear their PDEs (in the shared PD). ──
        let mut cursor = start_u & !(PT_SPAN - 1);
        loop {
            let addr = VirtAddr::new(cursor);
            let p4 = usize::from(addr.p4_index());
            let p3 = usize::from(addr.p3_index());
            let p2 = usize::from(addr.p2_index());

            let pml4e = &pml4[p4];
            if user_parent(pml4e.flags()) {
                let pdpt = &mut *phys_to_virt(pml4e.addr()).as_mut_ptr::<PageTable>();
                let pdpte_flags = pdpt[p3].flags();
                if user_parent(pdpte_flags) && !pdpte_flags.contains(PageTableFlags::HUGE_PAGE) {
                    let pd = &mut *phys_to_virt(pdpt[p3].addr()).as_mut_ptr::<PageTable>();
                    let pde = &mut pd[p2];
                    let pde_flags = pde.flags();
                    if user_parent(pde_flags) && !pde_flags.contains(PageTableFlags::HUGE_PAGE) {
                        let pt = &*phys_to_virt(pde.addr()).as_ptr::<PageTable>();
                        if table_empty(pt) && frames_to_free.try_reserve(1).is_ok() {
                            frames_to_free.push(PhysFrame::containing_address(pde.addr()));
                            pde.set_unused();
                            reclaimed_any = true;
                        }
                    }
                }
            }

            match cursor.checked_add(PT_SPAN) {
                Some(next) if next <= end_u => cursor = next,
                _ => break,
            }
        }

        // ── PD pass: free empty PDs, clear their PDPTEs (in the shared PDPT). ──
        cursor = start_u & !(PD_SPAN - 1);
        loop {
            let addr = VirtAddr::new(cursor);
            let p4 = usize::from(addr.p4_index());
            let p3 = usize::from(addr.p3_index());

            let pml4e = &pml4[p4];
            if user_parent(pml4e.flags()) {
                let pdpt = &mut *phys_to_virt(pml4e.addr()).as_mut_ptr::<PageTable>();
                let pdpte = &mut pdpt[p3];
                let pdpte_flags = pdpte.flags();
                if user_parent(pdpte_flags) && !pdpte_flags.contains(PageTableFlags::HUGE_PAGE) {
                    let pd = &*phys_to_virt(pdpte.addr()).as_ptr::<PageTable>();
                    if table_empty(pd) && frames_to_free.try_reserve(1).is_ok() {
                        frames_to_free.push(PhysFrame::containing_address(pdpte.addr()));
                        pdpte.set_unused();
                        reclaimed_any = true;
                    }
                }
            }

            match cursor.checked_add(PD_SPAN) {
                Some(next) if next <= end_u => cursor = next,
                _ => break,
            }
        }

        reclaimed_any
    }

    /// 转换虚拟地址到物理地址
    /// R180-12 FIX: allocation-free accounting for intermediate frames created
    /// by a failed fixed-size mapping transaction.
    ///
    /// After the caller clears every leaf PTE it installed, this detaches tracked
    /// empty PT frames. Runtime callers pass `detach_upper_tables = false`, so
    /// empty PD/PDPT frames remain linked: KPTI roots may copy upper entries by
    /// value. A pre-KPTI boot-exclusive caller may pass `true` only when it proves
    /// that the active PML4 is the sole root containing the transaction's entries;
    /// that mode detaches every tracked empty level bottom-up.
    ///
    /// Any detached PT is followed by a synchronous full cross-CPU flush before
    /// return. The caller may free the returned frames after dropping PT_LOCK.
    ///
    /// # Safety
    ///
    /// The caller must hold PT_LOCK, must have removed all leaves installed by
    /// this transaction, and must pass only frames allocated by the transaction's
    /// recording frame allocator. `detach_upper_tables = true` additionally
    /// requires exclusive ownership of the active root and absence of peer roots.
    pub unsafe fn rollback_tracked_leaf_tables<const TRACKED: usize, const RECLAIMED: usize>(
        &mut self,
        start: VirtAddr,
        len: usize,
        tracked: &[Option<PhysFrame<Size4KiB>>; TRACKED],
        tracked_len: usize,
        reclaimed: &mut [Option<PhysFrame<Size4KiB>>; RECLAIMED],
        detach_upper_tables: bool,
    ) -> TrackedTableRollback {
        const PT_SPAN: u64 = 0x20_0000;
        const PD_SPAN: u64 = 0x4000_0000;
        const PML4_SPAN: u64 = 0x80_0000_0000;

        #[inline]
        fn empty(table: &PageTable) -> bool {
            table.iter().all(|entry| entry.is_unused())
        }

        #[inline]
        fn tracked_index<const N: usize>(
            tracked: &[Option<PhysFrame<Size4KiB>>; N],
            tracked_len: usize,
            frame: PhysFrame<Size4KiB>,
        ) -> Option<usize> {
            (0..tracked_len).find(|index| tracked[*index] == Some(frame))
        }

        // KSA-001: a retained parent need not be structurally empty. Prove that
        // each occupied entry names a retained, leaf-free child from the earlier
        // pass at the correct level. Never follow or bless an unknown child,
        // huge leaf, hidden non-present ownership, or a detached frame.
        fn retained_children_only<const N: usize>(
            table: &PageTable,
            tracked: &[Option<PhysFrame<Size4KiB>>; N],
            tracked_len: usize,
            retained_levels: &[u8; N],
            child_level: u8,
        ) -> bool {
            table.iter().all(|entry| {
                entry.is_unused()
                    || (entry.flags().contains(PageTableFlags::PRESENT)
                        && !entry.flags().contains(PageTableFlags::HUGE_PAGE)
                        && tracked_index(
                            tracked,
                            tracked_len,
                            PhysFrame::containing_address(entry.addr()),
                        )
                        .is_some_and(|index| retained_levels[index] == child_level))
            })
        }

        if tracked_len > TRACKED || len == 0 || reclaimed.iter().any(Option::is_some) {
            return TrackedTableRollback {
                reclaimed_count: 0,
                retained_count: 0,
                all_accounted: tracked_len == 0 && len != 0,
            };
        }

        let mut valid = true;
        for index in 0..tracked_len {
            let Some(frame) = tracked[index] else {
                valid = false;
                continue;
            };
            if tracked[..index]
                .iter()
                .any(|candidate| *candidate == Some(frame))
            {
                valid = false;
            }
        }
        if !valid {
            return TrackedTableRollback {
                reclaimed_count: 0,
                retained_count: 0,
                all_accounted: false,
            };
        }

        let start_u = start.as_u64();
        let Some(end_u) = (len as u64)
            .checked_sub(1)
            .and_then(|tail| start_u.checked_add(tail))
        else {
            return TrackedTableRollback {
                reclaimed_count: 0,
                retained_count: 0,
                all_accounted: false,
            };
        };

        let mut accounted = [false; TRACKED];
        let mut retained_levels = [0u8; TRACKED];
        let mut reclaimed_count = 0usize;
        let mut retained_count = 0usize;
        let mut detached_any = false;
        let pml4 = self.mapper.level_4_table_mut();

        // Bottom-up PT pass. The range iterator visits each possible PT parent
        // once even when the four-page stack straddles a 2 MiB boundary.
        let mut cursor = start_u & !(PT_SPAN - 1);
        loop {
            let addr = VirtAddr::new(cursor);
            let pml4e = &pml4[usize::from(addr.p4_index())];
            if pml4e.flags().contains(PageTableFlags::PRESENT) {
                let pdpt = &mut *phys_to_virt(pml4e.addr()).as_mut_ptr::<PageTable>();
                let pdpte = &pdpt[usize::from(addr.p3_index())];
                let pdpte_flags = pdpte.flags();
                if pdpte_flags.contains(PageTableFlags::PRESENT)
                    && !pdpte_flags.contains(PageTableFlags::HUGE_PAGE)
                {
                    let pd = &mut *phys_to_virt(pdpte.addr()).as_mut_ptr::<PageTable>();
                    let pde = &mut pd[usize::from(addr.p2_index())];
                    let pde_flags = pde.flags();
                    if pde_flags.contains(PageTableFlags::PRESENT)
                        && !pde_flags.contains(PageTableFlags::HUGE_PAGE)
                    {
                        let frame = PhysFrame::containing_address(pde.addr());
                        if let Some(index) = tracked_index(tracked, tracked_len, frame) {
                            let pt = &*phys_to_virt(pde.addr()).as_ptr::<PageTable>();
                            if accounted[index] || !empty(pt) {
                                valid = false;
                            } else if let Some(output) =
                                reclaimed.iter_mut().find(|slot| slot.is_none())
                            {
                                *output = Some(frame);
                                accounted[index] = true;
                                reclaimed_count += 1;
                                pde.set_unused();
                                detached_any = true;
                            } else {
                                // Still fully accounted: it remains reachable
                                // and empty, and later stack mappings reuse it.
                                accounted[index] = true;
                                retained_levels[index] = 1;
                                retained_count += 1;
                            }
                        }
                    }
                }
            }

            match cursor.checked_add(PT_SPAN) {
                Some(next) if next <= end_u => cursor = next,
                _ => break,
            }
        }

        // Account newly created PDs after their tracked PT children have been
        // detached. Runtime callers retain them for KPTI alias safety. A
        // pre-KPTI boot-exclusive caller may prove that no peer root exists and
        // request complete bottom-up detachment.
        cursor = start_u & !(PD_SPAN - 1);
        loop {
            let addr = VirtAddr::new(cursor);
            let pml4e = &pml4[usize::from(addr.p4_index())];
            if pml4e.flags().contains(PageTableFlags::PRESENT) {
                let pdpt = &mut *phys_to_virt(pml4e.addr()).as_mut_ptr::<PageTable>();
                let pdpte = &mut pdpt[usize::from(addr.p3_index())];
                let flags = pdpte.flags();
                if flags.contains(PageTableFlags::PRESENT)
                    && !flags.contains(PageTableFlags::HUGE_PAGE)
                {
                    let frame = PhysFrame::containing_address(pdpte.addr());
                    if let Some(index) = tracked_index(tracked, tracked_len, frame) {
                        let pd = &*phys_to_virt(pdpte.addr()).as_ptr::<PageTable>();
                        if empty(pd)
                            || (!detach_upper_tables
                                && retained_children_only(
                                    pd,
                                    tracked,
                                    tracked_len,
                                    &retained_levels,
                                    1,
                                ))
                        {
                            if !accounted[index] {
                                if detach_upper_tables {
                                    if let Some(output) =
                                        reclaimed.iter_mut().find(|slot| slot.is_none())
                                    {
                                        *output = Some(frame);
                                        accounted[index] = true;
                                        reclaimed_count += 1;
                                        pdpte.set_unused();
                                        detached_any = true;
                                    } else {
                                        valid = false;
                                    }
                                } else {
                                    accounted[index] = true;
                                    retained_levels[index] = 2;
                                    retained_count += 1;
                                }
                            } else {
                                valid = false;
                            }
                        } else {
                            valid = false;
                        }
                    }
                }
            }

            match cursor.checked_add(PD_SPAN) {
                Some(next) if next <= end_u => cursor = next,
                _ => break,
            }
        }

        // Account newly allocated PDPTs last. Runtime callers retain them because
        // a KPTI peer root may carry the same PML4 entry by value. The guarded
        // boot-stack caller runs before peer roots exist and can detach the now-
        // empty tracked PDPT from the sole live PML4.
        cursor = start_u & !(PML4_SPAN - 1);
        loop {
            let addr = VirtAddr::new(cursor);
            let pml4e = &mut pml4[usize::from(addr.p4_index())];
            if pml4e.flags().contains(PageTableFlags::PRESENT) {
                let frame = PhysFrame::containing_address(pml4e.addr());
                if let Some(index) = tracked_index(tracked, tracked_len, frame) {
                    let pdpt = &*phys_to_virt(pml4e.addr()).as_ptr::<PageTable>();
                    if !empty(pdpt)
                        && (detach_upper_tables
                            || !retained_children_only(
                                pdpt,
                                tracked,
                                tracked_len,
                                &retained_levels,
                                2,
                            ))
                    {
                        valid = false;
                    } else if !accounted[index] {
                        if detach_upper_tables {
                            if let Some(output) = reclaimed.iter_mut().find(|slot| slot.is_none()) {
                                *output = Some(frame);
                                accounted[index] = true;
                                reclaimed_count += 1;
                                pml4e.set_unused();
                                detached_any = true;
                            } else {
                                valid = false;
                            }
                        } else {
                            accounted[index] = true;
                            retained_levels[index] = 3;
                            retained_count += 1;
                        }
                    } else {
                        valid = false;
                    }
                }
            }

            match cursor.checked_add(PML4_SPAN) {
                Some(next) if next <= end_u => cursor = next,
                _ => break,
            }
        }

        if detached_any {
            crate::tlb_shootdown::flush_all_address_spaces();
        }

        TrackedTableRollback {
            reclaimed_count,
            retained_count,
            all_accounted: valid && accounted[..tracked_len].iter().all(|entry| *entry),
        }
    }

    pub fn translate_addr(&self, addr: VirtAddr) -> Option<PhysAddr> {
        use x86_64::structures::paging::mapper::TranslateResult;

        match self.mapper.translate(addr) {
            TranslateResult::Mapped { frame, offset, .. } => Some(frame.start_address() + offset),
            TranslateResult::NotMapped | TranslateResult::InvalidFrameAddress(_) => None,
        }
    }

    /// 转换虚拟地址到物理地址并返回页表标志
    pub fn translate_with_flags(&self, addr: VirtAddr) -> Option<(PhysAddr, PageTableFlags)> {
        use x86_64::structures::paging::mapper::TranslateResult;

        match self.mapper.translate(addr) {
            TranslateResult::Mapped {
                frame,
                offset,
                flags,
                ..
            } => Some((frame.start_address() + offset, flags)),
            TranslateResult::NotMapped | TranslateResult::InvalidFrameAddress(_) => None,
        }
    }

    /// 修改页的标志位
    pub fn update_flags(
        &mut self,
        page: Page,
        flags: PageTableFlags,
    ) -> Result<(), UpdateFlagsError> {
        use x86_64::structures::paging::mapper::FlagUpdateError;

        self.assert_domain_allows_mutation(page);

        // R192-2 FIX: never reprotect an identity-map or split-MMIO leaf.
        if self.lower_half_kernel_owned(page) {
            return Err(UpdateFlagsError::KernelOwned);
        }

        unsafe {
            self.mapper
                .update_flags(page, flags)
                .map_err(|e| match e {
                    FlagUpdateError::PageNotMapped => UpdateFlagsError::PageNotMapped,
                    FlagUpdateError::ParentEntryHugePage => UpdateFlagsError::ParentEntryHugePage,
                })?
                .flush();
        }

        Ok(())
    }

    /// 映射一个连续的虚拟地址范围
    ///
    /// R32-MM-2 FIX: Uses checked arithmetic to prevent integer overflow
    /// R34-MM-1 FIX: Rolls back partial mappings on failure to prevent orphaned pages
    pub fn map_range(
        &mut self,
        start_virt: VirtAddr,
        start_phys: PhysAddr,
        size: usize,
        flags: PageTableFlags,
        frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    ) -> Result<(), MapError> {
        // R32-MM-2 FIX: Use checked_add to prevent overflow when rounding up
        let page_count = size.checked_add(0xfff).ok_or(MapError::InvalidRange)? / 0x1000;

        // R34-MM-1 FIX: Track successfully mapped pages for rollback on error
        let mut mapped_pages: Vec<Page<Size4KiB>> = Vec::with_capacity(page_count);

        for i in 0..page_count {
            // R32-MM-2 FIX: Use checked arithmetic for offset calculation
            let offset = (i as u64)
                .checked_mul(0x1000)
                .ok_or(MapError::InvalidRange)?;
            let virt_u64 = start_virt
                .as_u64()
                .checked_add(offset)
                .ok_or(MapError::InvalidRange)?;
            let phys_u64 = start_phys
                .as_u64()
                .checked_add(offset)
                .ok_or(MapError::InvalidRange)?;
            let page = Page::containing_address(VirtAddr::new(virt_u64));
            let frame = PhysFrame::containing_address(PhysAddr::new(phys_u64));

            // R34-MM-1 FIX: On error, roll back all previously mapped pages in this call
            if let Err(e) = self.map_page(page, frame, flags, frame_allocator) {
                // Unmap all pages that were successfully mapped before the failure
                for rollback_page in mapped_pages.drain(..) {
                    // Best effort: ignore errors during rollback
                    let _ = self.unmap_page(rollback_page);
                }
                return Err(e);
            }
            mapped_pages.push(page);
        }

        Ok(())
    }

    /// 取消映射一个连续的虚拟地址范围
    ///
    /// R35-MM-2 FIX: Uses checked arithmetic to prevent integer overflow,
    /// mirroring the safety measures in map_range().
    pub fn unmap_range(&mut self, start_virt: VirtAddr, size: usize) -> Result<(), UnmapError> {
        // R35-MM-2 FIX: Use checked_add to prevent overflow when rounding up
        let page_count = size.checked_add(0xfff).ok_or(UnmapError::InvalidRange)? / 0x1000;

        for i in 0..page_count {
            // R35-MM-2 FIX: Use checked arithmetic for offset calculation
            let offset = (i as u64)
                .checked_mul(0x1000)
                .ok_or(UnmapError::InvalidRange)?;
            let virt_u64 = start_virt
                .as_u64()
                .checked_add(offset)
                .ok_or(UnmapError::InvalidRange)?;
            let page = Page::containing_address(VirtAddr::new(virt_u64));
            self.unmap_page(page)?;
        }

        Ok(())
    }
}

/// 获取活动的4级页表
///
/// # Safety
///
/// 调用者必须确保物理内存偏移量是正确的
unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    use x86_64::registers::control::Cr3;

    let (level_4_table_frame, _) = Cr3::read();
    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    &mut *page_table_ptr
}

/// 以闭包方式访问当前活动的 PML4 页表
///
/// 此函数用于安全模块进行页表遍历和验证。
/// 它直接读取 CR3 获取当前活动的页表根。
///
/// # Safety
///
/// - 调用者必须确保在闭包执行期间 CR3 不会被切换
/// - 物理偏移量必须正确
/// - 不应在闭包中修改会导致当前执行路径无法访问的映射
///
/// # Example
///
/// ```rust,ignore
/// unsafe {
///     with_active_level_4_table(|pml4| {
///         for entry in pml4.iter() {
///             // Process entries...
///         }
///     });
/// }
/// ```
/// R153-10 NOTE: This function bypasses PT_LOCK and is restricted to single-CPU
/// early boot via the num_online_cpus() assertion. Post-SMP callers MUST use
/// with_pt_lock() or with_current_manager() instead. All current call sites
/// (memory_hardening::cleanup_identity_mapping, enforce_nx) are early-boot only.
pub unsafe fn with_active_level_4_table<T, F>(f: F) -> T
where
    F: FnOnce(&mut PageTable) -> T,
{
    // R152-16 FIX: This function bypasses PT_LOCK and uses no interrupt guard.
    // It is only safe before SMP bring-up. Assert single-CPU to prevent
    // concurrent page table mutation if called post-SMP.
    assert!(
        cpu_local::num_online_cpus() <= 1,
        "with_active_level_4_table: must be called before SMP bring-up (PT_LOCK bypass)"
    );

    let phys_offset = get_phys_offset();
    let level_4_table = active_level_4_table(phys_offset);
    f(level_4_table)
}

/// 获取物理内存偏移量
///
/// 返回高半区直映的物理内存偏移量，用于安全模块访问页表。
#[inline]
pub fn get_physical_memory_offset() -> VirtAddr {
    get_phys_offset()
}

/// 页表映射错误
#[derive(Debug, PartialEq, Eq)]
pub enum MapError {
    FrameAllocationFailed,
    ParentEntryHugePage,
    PageAlreadyMapped,
    /// R32-MM-2 FIX: Invalid range (overflow in size or offset calculation)
    InvalidRange,
    /// R192-2 FIX: a leaf under a kernel-owned (supervisor) lower-half entry.
    KernelOwned,
}

/// Outcome error of [`PageTableManager::map_user_pages_no_flush`].
#[derive(Debug, PartialEq, Eq)]
pub enum BatchMapUserError {
    /// Stopped at `mapped` pages because the next 2 MiB span needs `shortfall`
    /// more intermediate page-table frames than `available_tables`. Zero
    /// partial empty tables were linked for the starving span.
    Starved { mapped: usize, shortfall: usize },
    /// Mapping failed at page `mapped`.
    Failed { mapped: usize, error: MapError },
}

/// Outcome of [`PageTableManager::verify_and_unmap_contiguous_4k_no_flush`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContiguousUnmapOutcome {
    /// Every leaf matched its expected physical frame and was cleared.
    Verified,
    /// Prevalidation failed before any PTE was mutated.
    PrecheckFailed,
    /// A mismatch or error occurred after clearing `cleared` leaves; caller must
    /// broadcast a TLB flush and quarantine the slot.
    PartialMismatch { cleared: usize, matched: usize },
}

/// Exclusive handle to a present 4 KiB leaf entry resolved under PT_LOCK.
///
/// Allows reading frame/flags and performing an atomic in-place replacement
/// without a second 4-level walk or exposing raw `PageTableEntry` writes.
pub struct PresentLeafMut<'a> {
    entry: &'a mut PageTableEntry,
}

impl PresentLeafMut<'_> {
    #[inline]
    pub fn frame(&self) -> PhysFrame<Size4KiB> {
        PhysFrame::containing_address(self.entry.addr())
    }

    #[inline]
    pub fn flags(&self) -> PageTableFlags {
        self.entry.flags()
    }

    #[inline]
    pub fn replace(
        self,
        expected_frame: PhysFrame<Size4KiB>,
        new_frame: PhysFrame<Size4KiB>,
        flags: PageTableFlags,
    ) -> Result<(), ReplacePageError> {
        replace_present_leaf(self.entry, expected_frame, new_frame, flags)
    }
}

/// Errors from replacing a present leaf; none changes the mapping.
#[derive(Debug, PartialEq, Eq)]
pub enum ReplacePageError {
    PageNotMapped,
    ParentEntryHugePage,
    InvalidFrameAddress,
    FrameMismatch,
    InvalidFlags,
    KernelOwned,
}

/// A page-table frame must be nonzero and wholly reachable by the direct map.
pub fn page_table_frame_address_valid(addr: u64) -> bool {
    addr != 0 && addr & 0xfff == 0 && addr < DIRECT_MAP_LIMIT
}

fn replace_present_leaf(
    entry: &mut PageTableEntry,
    expected_frame: PhysFrame<Size4KiB>,
    new_frame: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), ReplacePageError> {
    if !flags.contains(PageTableFlags::PRESENT) || flags.contains(PageTableFlags::HUGE_PAGE) {
        return Err(ReplacePageError::InvalidFlags);
    }
    if !entry.flags().contains(PageTableFlags::PRESENT) {
        return Err(ReplacePageError::PageNotMapped);
    }
    if entry.addr() != expected_frame.start_address() {
        return Err(ReplacePageError::FrameMismatch);
    }
    // PageTableEntry is repr(transparent) over u64. The Release store also
    // publishes the copied data before a hardware walk can reach the new frame.
    const _: () = assert!(core::mem::size_of::<PageTableEntry>() == 8);
    const _: () = assert!(core::mem::align_of::<PageTableEntry>() >= 8);
    let slot = unsafe { &*(entry as *mut PageTableEntry).cast::<AtomicU64>() };
    slot.store(
        new_frame.start_address().as_u64() | flags.bits(),
        Ordering::Release,
    );
    Ok(())
}

/// 页表取消映射错误
#[derive(Debug)]
pub enum UnmapError {
    PageNotMapped,
    ParentEntryHugePage,
    InvalidFrameAddress,
    /// R35-MM-2 FIX: Overflow or invalid range in unmap_range offset calculation
    InvalidRange,
    /// R192-2 FIX: a kernel-owned (supervisor) lower-half translation.
    KernelOwned,
}

/// 更新标志位错误
#[derive(Debug)]
pub enum UpdateFlagsError {
    PageNotMapped,
    ParentEntryHugePage,
    /// R192-2 FIX: a kernel-owned (supervisor) lower-half translation.
    KernelOwned,
}

lazy_static::lazy_static! {
    pub static ref PAGE_TABLE_MANAGER: Mutex<Option<PageTableManager>> = Mutex::new(None);
}

/// 初始化页表管理器
///
/// # Safety
///
/// 只能调用一次，且必须在内核初始化早期调用
pub unsafe fn init(physical_memory_offset: VirtAddr) {
    let _ = physical_memory_offset; // 保持接口兼容
    let manager = PageTableManager::new(get_phys_offset());
    *PAGE_TABLE_MANAGER.lock() = Some(manager);

    klog!(
        Info,
        "Page table manager initialized (PHYS_OFFSET: 0x{:x})",
        PHYSICAL_MEMORY_OFFSET
    );
}

/// 获取全局页表管理器
pub fn get_manager() -> Option<spin::MutexGuard<'static, Option<PageTableManager>>> {
    let guard = PAGE_TABLE_MANAGER.lock();
    if guard.is_some() {
        Some(guard)
    } else {
        None
    }
}

// ============================================================================
// 递归页表访问 - 用于访问任意物理地址的页表帧
// ============================================================================

/// 递归页表槽索引 (PML4[510] 指向 PML4 自身)
pub const RECURSIVE_INDEX: usize = 510;

/// 通过递归映射计算的 PML4 虚拟地址
/// 地址计算: sign_extend(510 << 39 | 510 << 30 | 510 << 21 | 510 << 12)
pub const RECURSIVE_PML4_ADDR: u64 = 0xFFFF_FF7F_BFDF_E000;

/// 通过递归映射计算的 PDPT 基地址
/// 地址计算: sign_extend(510 << 39 | 510 << 30 | 510 << 21)
pub const RECURSIVE_PDPT_BASE: u64 = 0xFFFF_FF7F_BFC0_0000;

/// 通过递归映射计算的 PD 基地址
/// 地址计算: sign_extend(510 << 39 | 510 << 30)
pub const RECURSIVE_PD_BASE: u64 = 0xFFFF_FF7F_8000_0000;

/// 通过递归映射计算的 PT 基地址
/// 地址计算: sign_extend(510 << 39)
pub const RECURSIVE_PT_BASE: u64 = 0xFFFF_FF00_0000_0000;

/// 获取当前活动的 PML4 表（通过递归映射）
///
/// # Safety
///
/// 需要递归页表槽已正确设置
#[inline]
pub unsafe fn recursive_pml4() -> &'static mut PageTable {
    &mut *(RECURSIVE_PML4_ADDR as *mut PageTable)
}

/// 获取指定 PML4 索引的 PDPT（通过递归映射）
///
/// # Safety
///
/// 调用者必须确保该 PML4 条目存在且指向有效的 PDPT
#[inline]
pub unsafe fn recursive_pdpt(pml4_idx: usize) -> &'static mut PageTable {
    if pml4_idx >= 512 {
        panic!("recursive_pdpt index outside page-table bounds");
    }
    let addr = RECURSIVE_PDPT_BASE
        .checked_add((pml4_idx as u64) * 0x1000)
        .expect("recursive_pdpt address overflow");
    &mut *(addr as *mut PageTable)
}

/// 获取指定索引的 PD（通过递归映射）
///
/// # Safety
///
/// 调用者必须确保对应的页表条目存在且有效
#[inline]
pub unsafe fn recursive_pd(pml4_idx: usize, pdpt_idx: usize) -> &'static mut PageTable {
    if pml4_idx >= 512 || pdpt_idx >= 512 {
        panic!("recursive_pd index outside page-table bounds");
    }
    let addr = RECURSIVE_PD_BASE
        .checked_add((pml4_idx as u64) * 0x20_0000)
        .and_then(|addr| addr.checked_add((pdpt_idx as u64) * 0x1000))
        .expect("recursive_pd address overflow");
    &mut *(addr as *mut PageTable)
}

/// 获取指定索引的 PT（通过递归映射）
///
/// # Safety
///
/// 调用者必须确保对应的页表条目存在且有效
#[inline]
pub unsafe fn recursive_pt(
    pml4_idx: usize,
    pdpt_idx: usize,
    pd_idx: usize,
) -> &'static mut PageTable {
    if pml4_idx >= 512 || pdpt_idx >= 512 || pd_idx >= 512 {
        panic!("recursive_pt index outside page-table bounds");
    }
    let addr = RECURSIVE_PT_BASE
        .checked_add((pml4_idx as u64) * 0x4000_0000)
        .and_then(|addr| addr.checked_add((pdpt_idx as u64) * 0x20_0000))
        .and_then(|addr| addr.checked_add((pd_idx as u64) * 0x1000))
        .expect("recursive_pt address overflow");
    &mut *(addr as *mut PageTable)
}

// ============================================================================
// 4KB 页粒度支持 - 用于 MMIO 隔离和 W^X/NX 强制
// ============================================================================

/// Default flags for device MMIO mappings: RW, NX, uncached, write-through
#[inline]
pub fn mmio_flags() -> PageTableFlags {
    PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE
        | PageTableFlags::NO_CACHE
        | PageTableFlags::WRITE_THROUGH
}

/// Demote a 2 MB PD huge page into a 4 KB page table, cloning flags.
///
/// This function splits a 2MB huge page entry into 512 4KB page entries,
/// preserving the original flags (minus HUGE_PAGE).
///
/// # Safety
///
/// - Caller must flush TLB after this operation if mappings are in use
/// - The pd_entry must point to a valid huge page entry
///
/// # Arguments
///
/// * `pd_entry` - Mutable reference to the PD entry to split
/// * `frame_allocator` - Allocator for the new page table frame
pub unsafe fn split_2m_entry(
    pd_entry: &mut PageTableEntry,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<&'static mut PageTable, MapError> {
    // Only split huge pages
    if !pd_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        // Already a PT pointer, get the table
        let pt_virt = get_phys_offset() + pd_entry.addr().as_u64();
        return Ok(&mut *(pt_virt.as_mut_ptr::<PageTable>()));
    }

    // Allocate a new page table frame
    let pt_frame = frame_allocator
        .allocate_frame()
        .ok_or(MapError::FrameAllocationFailed)?;
    let pt_virt = get_phys_offset() + pt_frame.start_address().as_u64();
    let pt_ptr: *mut PageTable = pt_virt.as_mut_ptr();

    // Zero the new page table
    core::ptr::write_bytes(pt_ptr as *mut u8, 0, 4096);

    // Get base physical address from the huge page entry
    let base = pd_entry.addr().as_u64();

    // Prepare flags: remove HUGE_PAGE, ensure PRESENT
    let mut flags = pd_entry.flags();
    flags.remove(PageTableFlags::HUGE_PAGE);
    flags.insert(PageTableFlags::PRESENT);

    // Fill 512 PTEs, each mapping a 4KB page
    let pt = &mut *pt_ptr;
    for i in 0..512usize {
        let phys = PhysAddr::new(base + (i as u64) * 0x1000);
        pt[i].set_addr(phys, flags);
    }

    // Update PD entry to point to new page table (not a huge page anymore)
    // Preserve original flags (USER, NO_CACHE, etc.) minus leaf-only bits
    // HUGE_PAGE and DIRTY are leaf-only - must remove for PDE pointing to PT
    let mut pd_flags = pd_entry.flags();
    pd_flags.remove(PageTableFlags::HUGE_PAGE);
    pd_flags.remove(PageTableFlags::DIRTY);
    pd_flags.insert(PageTableFlags::PRESENT);
    pd_entry.set_addr(pt_frame.start_address(), pd_flags);

    Ok(&mut *pt_ptr)
}

/// Create the two kernel-stack page directories transactionally, before
/// any user root copies these PDPT entries into its KPTI entry island.
/// On error no entry is changed and every newly allocated frame is returned.
///
/// # Safety
/// Runs on the boot root before any user root exists; CR3 must not change.
pub unsafe fn ensure_kernel_stack_directories(
    frame_allocator: &mut (impl FrameAllocator<Size4KiB>
              + x86_64::structures::paging::FrameDeallocator<Size4KiB>),
) -> Result<usize, MapError> {
    let _pt_guard = lock_pt();
    let pml4 = active_level_4_table(get_phys_offset());
    let entry = &pml4[VirtAddr::new(KSTACK_REGION_BASE).p4_index()];
    let flags = entry.flags();
    if !flags.contains(PageTableFlags::PRESENT | PageTableFlags::WRITABLE)
        || flags.intersects(PageTableFlags::USER_ACCESSIBLE | PageTableFlags::HUGE_PAGE)
        || !page_table_frame_address_valid(entry.addr().as_u64())
    {
        return Err(MapError::InvalidRange);
    }
    let pdpt = &mut *phys_to_virt(entry.addr()).as_mut_ptr::<PageTable>();
    stage_kernel_stack_directories(pdpt, frame_allocator, |frame| {
        core::ptr::write_bytes(
            phys_to_virt(frame.start_address()).as_mut_ptr::<u8>(),
            0,
            4096,
        );
    })
}

/// Validate first, allocate all missing directories, zero all of them, then
/// publish. Keeping the staging fixed to the stack region bounds boot-stack
/// usage and avoids a heap allocation while PT_LOCK is held.
fn stage_kernel_stack_directories(
    pdpt: &mut PageTable,
    allocator: &mut (impl FrameAllocator<Size4KiB>
              + x86_64::structures::paging::FrameDeallocator<Size4KiB>),
    mut zero: impl FnMut(PhysFrame<Size4KiB>),
) -> Result<usize, MapError> {
    const FIRST: usize = ((KSTACK_REGION_BASE >> 30) & 0x1ff) as usize;
    const COUNT: usize = ((KSTACK_REGION_END - KSTACK_REGION_BASE) >> 30) as usize;
    const _: () = assert!(COUNT == 2 && FIRST + COUNT <= 512);
    for entry in pdpt
        .iter()
        .skip(FIRST)
        .take(COUNT)
        .filter(|entry| !entry.is_unused())
    {
        let flags = entry.flags();
        if flags.contains(PageTableFlags::HUGE_PAGE) {
            return Err(MapError::ParentEntryHugePage);
        }
        if !flags.contains(PageTableFlags::PRESENT | PageTableFlags::WRITABLE)
            || flags.contains(PageTableFlags::USER_ACCESSIBLE)
            || !page_table_frame_address_valid(entry.addr().as_u64())
        {
            return Err(MapError::PageAlreadyMapped);
        }
    }
    let mut staged = [None; COUNT];
    for (entry, slot) in pdpt.iter().skip(FIRST).take(COUNT).zip(staged.iter_mut()) {
        if entry.is_unused() {
            *slot = allocator.allocate_frame();
            if slot.is_none() {
                for frame in staged.into_iter().flatten() {
                    // No staged directory has been linked yet.
                    unsafe { allocator.deallocate_frame(frame) };
                }
                return Err(MapError::FrameAllocationFailed);
            }
        }
    }
    if staged
        .iter()
        .flatten()
        .any(|frame| !page_table_frame_address_valid(frame.start_address().as_u64()))
    {
        for frame in staged.into_iter().flatten() {
            unsafe { allocator.deallocate_frame(frame) };
        }
        return Err(MapError::InvalidRange);
    }
    for frame in staged.iter().flatten() {
        zero(*frame);
    }
    let mut created = 0;
    for (entry, frame) in pdpt.iter_mut().skip(FIRST).take(COUNT).zip(staged) {
        if let Some(frame) = frame {
            entry.set_frame(frame, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
            created += 1;
        }
    }
    Ok(created)
}

/// Ensure a virtual page is backed by a 4 KB PTE (allocate tables or demote 2 MB leaves).
///
/// # Safety
///
/// Caller must ensure the virtual address is valid and CR3 won't change during operation.
///
/// # Note
///
/// This is an internal helper. Callers must hold PT_LOCK (see ensure_pte_range).
pub unsafe fn ensure_pte_level(
    page: Page<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapError> {
    let phys_offset = get_phys_offset();
    let pml4 = active_level_4_table(phys_offset);

    // PML4 entry
    let pml4_idx = page.p4_index();
    let pml4e = &mut pml4[pml4_idx];
    if pml4e.is_unused() {
        return Err(MapError::ParentEntryHugePage);
    }

    // PDPT
    let pdpt_ptr: *mut PageTable = (phys_offset + pml4e.addr().as_u64()).as_mut_ptr();
    let pdpt = &mut *pdpt_ptr;
    let pdpt_idx = page.p3_index();
    let pdpte = &mut pdpt[pdpt_idx];

    // Check for 1GB huge page (not supported for demotion)
    if pdpte.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Err(MapError::ParentEntryHugePage);
    }

    // Allocate PD if needed
    if pdpte.is_unused() {
        let pd_frame = frame_allocator
            .allocate_frame()
            .ok_or(MapError::FrameAllocationFailed)?;
        let pd_virt = phys_offset + pd_frame.start_address().as_u64();
        core::ptr::write_bytes(pd_virt.as_mut_ptr::<u8>(), 0, 4096);
        pdpte.set_addr(
            pd_frame.start_address(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );
    }

    // PD
    let pd_ptr: *mut PageTable = (phys_offset + pdpte.addr().as_u64()).as_mut_ptr();
    let pd = &mut *pd_ptr;
    let pd_idx = page.p2_index();
    let pde = &mut pd[pd_idx];

    // Demote 2MB huge page to 4KB pages if needed
    if pde.flags().contains(PageTableFlags::HUGE_PAGE) {
        split_2m_entry(pde, frame_allocator)?;
        // X-7 & R68-2 FIX: Flush the entire 2MB range on ALL CPUs.
        //
        // After splitting a huge page, remote CPUs may still have the original
        // 2MB TLB entry cached with (potentially) RWX permissions. If we only
        // flush locally, those CPUs will bypass any 4KB-level permission changes
        // (e.g., W^X enforcement) until the TLB entry naturally expires.
        //
        // We flush the entire 2MB region because TLB entries for huge pages
        // cover the whole range, not individual 4KB pages.
        let huge_base = page.start_address().as_u64() & !0x1f_ffffu64; // Align to 2MB

        // Issue #109 §1.2 (H3): kernel high-half huge pages are shared across
        // every CR3 root and must broadcast to all online CPUs.
        if huge_base >= USER_HALF_END {
            crate::tlb_shootdown::flush_all_address_spaces();
        } else {
            crate::tlb_shootdown::flush_current_as_range(VirtAddr::new(huge_base), 0x20_0000);
        }
    } else if pde.is_unused() {
        // Allocate new PT
        let pt_frame = frame_allocator
            .allocate_frame()
            .ok_or(MapError::FrameAllocationFailed)?;
        let pt_virt = phys_offset + pt_frame.start_address().as_u64();
        core::ptr::write_bytes(pt_virt.as_mut_ptr::<u8>(), 0, 4096);
        pde.set_addr(
            pt_frame.start_address(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );
    }

    Ok(())
}

/// R67-5 FIX: Internal lock-free version of ensure_pte_range.
///
/// # Safety
///
/// - Caller must hold PT_LOCK
/// - Caller must ensure addresses are valid and CR3 won't change
unsafe fn ensure_pte_range_unlocked(
    start: VirtAddr,
    size: usize,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapError> {
    // R32-MM-2 FIX: Use checked_add to prevent overflow when rounding up
    let pages = size.checked_add(0xfff).ok_or(MapError::InvalidRange)? / 0x1000;
    for i in 0..pages {
        // R32-MM-2 FIX: Use checked arithmetic for offset calculation
        let offset = (i as u64)
            .checked_mul(0x1000)
            .ok_or(MapError::InvalidRange)?;
        let addr_u64 = start
            .as_u64()
            .checked_add(offset)
            .ok_or(MapError::InvalidRange)?;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(addr_u64));
        ensure_pte_level(page, frame_allocator)?;
    }
    Ok(())
}

/// Ensure a range is mapped at PTE granularity (4KB pages).
///
/// # Safety
///
/// Caller must ensure addresses are valid and CR3 won't change.
///
/// R32-MM-2 FIX: Uses checked arithmetic to prevent integer overflow
///
/// # Security (R67-5 fix)
///
/// Acquires global PT_LOCK to serialize cross-CPU page table modifications.
pub unsafe fn ensure_pte_range(
    start: VirtAddr,
    size: usize,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapError> {
    // R67-5 FIX: Acquire global page table lock
    let _pt_guard = lock_pt();
    ensure_pte_range_unlocked(start, size, frame_allocator)
}

const MMIO_PAGE_BYTES: usize = 0x1000;
const MAX_MMIO_MAP_BYTES: usize = 256 * 1024 * 1024;
// One 256-MiB range needs at most 128 PTs + one PD + one PDPT. Keep three
// spare slots for boundary crossings and defensive accounting.
const MAX_MMIO_TRACKED_TABLES: usize = 132;

struct MmioPtRecorder<'a> {
    inner: &'a mut crate::memory::FrameAllocator,
    tracked: &'a mut [Option<PhysFrame<Size4KiB>>; MAX_MMIO_TRACKED_TABLES],
    tracked_len: &'a mut usize,
    fault: &'a mut MmioMapFault,
}

#[derive(Default)]
struct MmioMapFault {
    fail_after: Option<usize>,
    allocations: usize,
    injected: bool,
    #[cfg(feature = "mmio_probe")]
    rollback: Option<TrackedTableRollback>,
}

unsafe impl FrameAllocator<Size4KiB> for MmioPtRecorder<'_> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        if self.fault.fail_after == Some(self.fault.allocations) {
            self.fault.injected = true;
            return None;
        }
        let frame = self.inner.allocate_frame()?;
        if *self.tracked_len >= self.tracked.len() {
            self.inner.deallocate_frame(frame);
            return None;
        }
        self.tracked[*self.tracked_len] = Some(frame);
        *self.tracked_len += 1;
        self.fault.allocations += 1;
        Some(frame)
    }
}

/// Serializes the hosted tests that take `PT_LOCK`: the other asserts the lock
/// is free at its start and end.
#[cfg(test)]
static PT_LOCK_TEST_SERIAL: spin::Mutex<()> = spin::Mutex::new(());

#[cfg(test)]
mod pt_lock_stats_tests {
    use super::*;
    use std::{
        thread,
        time::{Duration, Instant},
    };

    /// C3 E1 (#90): a held `PT_LOCK` makes `try_lock_pt` busy and `lock_pt`
    /// contended, and the wait and both holds are timed.
    #[test]
    fn busy_contention_wait_and_hold_are_counted() {
        let _serial = PT_LOCK_TEST_SERIAL.lock();
        let before = pt_lock_stats();
        let holder = lock_pt();
        assert!(thread::spawn(|| try_lock_pt().is_none()).join().unwrap());
        let waiter = thread::spawn(|| drop(lock_pt()));
        let deadline = Instant::now() + Duration::from_secs(5);
        while pt_lock_stats().contended == before.contended && Instant::now() < deadline {
            thread::yield_now();
        }
        thread::sleep(Duration::from_millis(5));
        drop(holder);
        waiter.join().unwrap();

        let after = pt_lock_stats();
        assert!(after.acquired >= before.acquired + 2);
        assert!(after.contended > before.contended);
        assert!(after.busy > before.busy);
        assert!(after.wait_tsc > before.wait_tsc && after.wait_tsc_max > 0);
        assert!(after.hold_tsc > before.hold_tsc && after.hold_tsc_max > 0);
    }

    #[test]
    fn per_cpu_counters_are_cache_line_isolated() {
        assert_eq!(core::mem::size_of::<PtLockCpuCounters>(), 64);
        assert_eq!(core::mem::align_of::<PtLockCpuCounters>(), 64);
        assert_eq!(core::mem::size_of::<PtLockSlot>(), 64);
        assert_eq!(core::mem::align_of::<PtLockSlot>(), 64);

        let kernel_line = (&KERNEL_PT_LOCK as *const _ as usize) / 64;
        let shard0_line = (&AS_PT_LOCKS[0] as *const _ as usize) / 64;
        let shard1_line = (&AS_PT_LOCKS[1] as *const _ as usize) / 64;
        let c0_line = (&PT_LOCK_COUNTERS[0] as *const _ as usize) / 64;
        let c1_line = (&PT_LOCK_COUNTERS[1] as *const _ as usize) / 64;
        assert_ne!(kernel_line, shard0_line);
        assert_ne!(kernel_line, c0_line);
        assert_ne!(shard0_line, c0_line);
        assert_eq!(shard1_line, shard0_line + 1);
        assert_eq!(c1_line, c0_line + 1);
    }

    struct TestBootRootGuard(u64);
    impl TestBootRootGuard {
        fn set(root: u64) -> Self {
            let prev = BOOT_ROOT_PHYS.swap(root, Ordering::AcqRel);
            Self(prev)
        }
    }
    impl Drop for TestBootRootGuard {
        fn drop(&mut self) {
            BOOT_ROOT_PHYS.store(self.0, Ordering::Release);
        }
    }

    /// Issue #109 §1.1: holding one per-AS shard must NOT block another disjoint shard.
    #[test]
    fn split_pt_lock_disjoint_shards_do_not_block() {
        let _serial = PT_LOCK_TEST_SERIAL.lock();
        let _boot = TestBootRootGuard::set(0x1000);

        let root_a = 0x20_0000u64;
        let mut root_b = 0x20_1000u64;
        while as_pt_lock_shard(root_b) == as_pt_lock_shard(root_a) {
            root_b += 0x1000;
        }
        assert_ne!(as_pt_lock_shard(root_a), as_pt_lock_shard(root_b));

        let before = pt_lock_stats();
        let guard_a = lock_as_pt(root_a);
        // A second thread acquiring a disjoint shard must succeed without spinning.
        let acquired_b = thread::spawn(move || {
            let g = try_lock_as_pt(root_b);
            g.is_some()
        })
        .join()
        .unwrap();
        assert!(acquired_b, "disjoint AS shards must not block each other");

        // Same-thread cross-shard reentry is still rejected by try_lock_as_pt.
        assert!(try_lock_as_pt(root_b).is_none());
        drop(guard_a);

        let after = pt_lock_stats();
        assert!(after.acquired >= before.acquired + 2);
        assert!(after.busy >= before.busy + 1);
    }

    /// Issue #109 §1.1: two threads targeting the same AS root serialize cleanly and
    /// record owner/busy/contention statistics.
    #[test]
    fn split_pt_lock_same_shard_serializes_and_records_owner() {
        let _serial = PT_LOCK_TEST_SERIAL.lock();
        let _boot = TestBootRootGuard::set(0x1000);

        let root = 0x30_0000u64;
        let shard = as_pt_lock_shard(root);
        let before = pt_lock_stats();

        let holder = lock_as_pt(root);
        assert_eq!(
            AS_PT_LOCKS[shard].owner_cpu.load(Ordering::Acquire),
            cpu_local::current_cpu_id()
        );
        assert!(thread::spawn(move || try_lock_as_pt(root).is_none())
            .join()
            .unwrap());

        let waiter = thread::spawn(move || drop(lock_as_pt(root)));
        let deadline = Instant::now() + Duration::from_secs(5);
        while pt_lock_stats().contended == before.contended && Instant::now() < deadline {
            thread::yield_now();
        }
        thread::sleep(Duration::from_millis(2));
        drop(holder);
        waiter.join().unwrap();

        assert_eq!(
            AS_PT_LOCKS[shard].owner_cpu.load(Ordering::Acquire),
            NO_PT_LOCK_OWNER
        );
        let after = pt_lock_stats();
        assert!(after.acquired >= before.acquired + 2);
        assert!(after.contended > before.contended);
        assert!(after.busy > before.busy);
    }

    /// Issue #109 §1.1: Fibonacci shard hash spreads consecutive and power-of-2-stride
    /// CR3 physical roots across the 128-shard table without degenerate clustering.
    #[test]
    fn split_pt_lock_hash_distribution_and_alignment() {
        let mut seen_consecutive = [false; AS_PT_LOCK_SHARDS];
        for i in 0..AS_PT_LOCK_SHARDS {
            let root = ((i as u64) + 1) << 12;
            seen_consecutive[as_pt_lock_shard(root)] = true;
        }
        let distinct_consecutive = seen_consecutive.iter().filter(|&&b| b).count();
        assert!(
            distinct_consecutive >= AS_PT_LOCK_SHARDS / 2,
            "consecutive PFNs clustered into only {distinct_consecutive}/{AS_PT_LOCK_SHARDS} shards"
        );

        let mut seen_stride = [false; AS_PT_LOCK_SHARDS];
        for i in 0..AS_PT_LOCK_SHARDS {
            // 2 MiB stride (common buddy/large allocation alignment)
            let root = ((i as u64) + 1) << 21;
            seen_stride[as_pt_lock_shard(root)] = true;
        }
        let distinct_stride = seen_stride.iter().filter(|&&b| b).count();
        assert!(
            distinct_stride >= AS_PT_LOCK_SHARDS / 2,
            "2MiB-strided PFNs clustered into only {distinct_stride}/{AS_PT_LOCK_SHARDS} shards"
        );
    }

    /// Issue #109 §1.1: valid hierarchy `AS_PT_LOCKS -> KERNEL_PT_LOCK` succeeds
    /// (fork high-half PML4 copy path) and leaves hold depths balanced at zero;
    /// reverse `KERNEL_PT_LOCK -> try_lock_as_pt` is rejected fail-closed.
    #[test]
    fn split_pt_lock_hierarchy_allows_as_to_kernel() {
        let _serial = PT_LOCK_TEST_SERIAL.lock();
        let _boot = TestBootRootGuard::set(0x1000);

        let root = 0x40_0000u64;
        let nested_ok = with_as_pt_lock(root, || {
            let (as_d, k_d) = pt_hold_depths(cpu_local::current_cpu_id());
            assert_eq!((as_d, k_d), (1, 0));
            with_kernel_pt_lock(|| {
                let (as_d2, k_d2) = pt_hold_depths(cpu_local::current_cpu_id());
                assert_eq!((as_d2, k_d2), (1, 1));
                true
            })
        });
        assert!(nested_ok);
        assert_eq!(pt_hold_depths(cpu_local::current_cpu_id()), (0, 0));

        // Reverse order (KERNEL_PT_LOCK -> AS_PT_LOCKS) must be rejected by try_lock_as_pt.
        with_kernel_pt_lock(|| {
            assert!(try_lock_as_pt(root).is_none());
        });
        assert_eq!(pt_hold_depths(cpu_local::current_cpu_id()), (0, 0));
    }

    #[test]
    fn per_cpu_aggregation_sums_totals_and_takes_maxima() {
        let per_cpu = [const { PtLockCpuCounters::new() }; 4];
        per_cpu[0].acquired.store(10, Ordering::Relaxed);
        per_cpu[0].contended.store(2, Ordering::Relaxed);
        per_cpu[0].busy.store(1, Ordering::Relaxed);
        per_cpu[0].wait_tsc.store(100, Ordering::Relaxed);
        per_cpu[0].wait_tsc_max.store(75, Ordering::Relaxed);
        per_cpu[0].hold_tsc.store(500, Ordering::Relaxed);
        per_cpu[0].hold_tsc_max.store(120, Ordering::Relaxed);

        per_cpu[2].acquired.store(25, Ordering::Relaxed);
        per_cpu[2].contended.store(4, Ordering::Relaxed);
        per_cpu[2].busy.store(3, Ordering::Relaxed);
        per_cpu[2].wait_tsc.store(400, Ordering::Relaxed);
        per_cpu[2].wait_tsc_max.store(250, Ordering::Relaxed);
        per_cpu[2].hold_tsc.store(900, Ordering::Relaxed);
        per_cpu[2].hold_tsc_max.store(80, Ordering::Relaxed);

        let stats = aggregate_pt_lock_stats(&per_cpu);
        assert_eq!(
            stats,
            PtLockStats {
                acquired: 35,
                contended: 6,
                busy: 4,
                wait_tsc: 500,
                wait_tsc_max: 250,
                hold_tsc: 1400,
                hold_tsc_max: 120,
            }
        );
    }
}

#[cfg(test)]
mod cow_replace_tests {
    use super::*;

    fn frame(addr: u64) -> PhysFrame {
        PhysFrame::from_start_address(PhysAddr::new(addr)).unwrap()
    }

    #[test]
    fn present_replacement_publishes_frame_and_final_permissions() {
        let mut entry = PageTableEntry::new();
        let old = PageTableFlags::PRESENT
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::BIT_9;
        let new = (old & !PageTableFlags::BIT_9) | PageTableFlags::WRITABLE;
        entry.set_frame(frame(0x1000), old);
        replace_present_leaf(&mut entry, frame(0x1000), frame(0x2000), new).unwrap();
        assert_eq!(entry.frame().unwrap(), frame(0x2000));
        assert_eq!(entry.flags(), new);
    }

    #[test]
    fn replacement_errors_leave_the_old_leaf_untouched() {
        let flags =
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::BIT_9;
        for (old_flags, expected, new_flags, error) in [
            (flags, 0x3000, flags, ReplacePageError::FrameMismatch),
            (
                flags,
                0x1000,
                PageTableFlags::WRITABLE,
                ReplacePageError::InvalidFlags,
            ),
            (
                flags,
                0x1000,
                flags | PageTableFlags::HUGE_PAGE,
                ReplacePageError::InvalidFlags,
            ),
            (
                flags & !PageTableFlags::PRESENT,
                0x1000,
                flags,
                ReplacePageError::PageNotMapped,
            ),
        ] {
            let mut entry = PageTableEntry::new();
            entry.set_addr(PhysAddr::new(0x1000), old_flags);
            assert_eq!(
                replace_present_leaf(&mut entry, frame(expected), frame(0x2000), new_flags),
                Err(error)
            );
            assert_eq!(entry.addr(), PhysAddr::new(0x1000));
            assert_eq!(entry.flags(), old_flags);
        }
    }
}

#[cfg(test)]
mod kernel_stack_directory_tests {
    use super::*;
    use x86_64::structures::paging::FrameDeallocator;

    struct Frames {
        remaining: usize,
        allocated: usize,
        freed: usize,
    }
    // Synthetic frame identities; the injected zero callback never dereferences them.
    unsafe impl FrameAllocator<Size4KiB> for Frames {
        fn allocate_frame(&mut self) -> Option<PhysFrame> {
            if self.remaining == 0 {
                return None;
            }
            self.remaining -= 1;
            self.allocated += 1;
            Some(
                PhysFrame::from_start_address(PhysAddr::new((self.allocated as u64) << 12))
                    .unwrap(),
            )
        }
    }
    impl FrameDeallocator<Size4KiB> for Frames {
        unsafe fn deallocate_frame(&mut self, _: PhysFrame) {
            self.freed += 1;
        }
    }

    #[test]
    fn directory_allocation_failure_rolls_back_before_publication() {
        for budget in 0..=2 {
            let mut pdpt = PageTable::new();
            let mut frames = Frames {
                remaining: budget,
                allocated: 0,
                freed: 0,
            };
            let mut zeroed = 0;
            let result = stage_kernel_stack_directories(&mut pdpt, &mut frames, |_| zeroed += 1);
            if budget < 2 {
                assert!(matches!(result, Err(MapError::FrameAllocationFailed)));
                assert!(pdpt.iter().all(PageTableEntry::is_unused));
                assert_eq!(frames.freed, frames.allocated);
                assert_eq!(zeroed, 0);
            } else {
                assert_eq!(result.unwrap(), 2);
                assert_eq!(zeroed, 2);
                assert_eq!(frames.freed, 0);
                assert_eq!(pdpt[506].addr(), PhysAddr::new(0x1000));
                assert_eq!(pdpt[507].addr(), PhysAddr::new(0x2000));
            }
        }
    }

    #[test]
    fn directory_validation_precedes_allocation_and_preserves_existing_entries() {
        let mut pdpt = PageTable::new();
        let mut frames = Frames {
            remaining: 2,
            allocated: 0,
            freed: 0,
        };
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        for bad_addr in [0, DIRECT_MAP_LIMIT] {
            pdpt[507].set_addr(PhysAddr::new(bad_addr), flags);
            assert!(
                stage_kernel_stack_directories(&mut pdpt, &mut frames, |_| panic!(
                    "zero before validation"
                ))
                .is_err()
            );
            assert!(pdpt[506].is_unused());
            assert_eq!(frames.allocated, 0);
        }
        pdpt[507].set_addr(PhysAddr::new(0x8000), flags);
        assert_eq!(
            stage_kernel_stack_directories(&mut pdpt, &mut frames, |_| {}).unwrap(),
            1
        );
        assert_eq!(pdpt[507].addr(), PhysAddr::new(0x8000));
        assert_eq!(frames.allocated, 1);
    }
}

#[cfg(test)]
mod pt_lock_tests {
    use super::{pt_lock_owner_cpu, try_with_current_manager, with_pt_lock, PT_LOCK_TEST_SERIAL};
    use x86_64::VirtAddr;

    #[test]
    fn try_manager_rejects_same_cpu_reentry() {
        let _serial = PT_LOCK_TEST_SERIAL.lock();
        assert_eq!(pt_lock_owner_cpu(), None);
        with_pt_lock(|| {
            let owner = pt_lock_owner_cpu();
            assert_eq!(owner, Some(cpu_local::current_cpu_id()));
            let nested = unsafe { try_with_current_manager(VirtAddr::new(0), |_| ()) };
            assert!(
                nested.is_none(),
                "same-CPU PT lock reentry must be nonblocking"
            );
        });
        assert_eq!(pt_lock_owner_cpu(), None);
    }
}
#[cfg(test)]
mod user_page_access_tests {
    use super::{
        classify_user_page, first_kernel_owned_in, first_occupied_in, UserPageAccess,
        DIRECT_MAP_LIMIT, USER_HALF_END,
    };
    use alloc::collections::BTreeMap;
    use x86_64::structures::paging::PageTableFlags as F;

    const ROOT: u64 = 0x1000;
    const PDPT: u64 = 0x2000;
    const PD_LOW: u64 = 0x3000;
    const PD_SHARED: u64 = 0x4000;
    const PT_SPLIT: u64 = 0x5000;
    const PT_USER: u64 = 0x6000;
    const BEYOND_DIRECT_MAP: u64 = DIRECT_MAP_LIMIT;

    /// The pre-Approach-A R192 layout of a user address space (the boot root
    /// still looks like this): PML4[0] and PDPT[0] are
    /// user-accessible branches; the rest of the low identity map is
    /// supervisor-only (a split 4 KiB PT, 2 MiB leaves, a supervisor PDPT entry
    /// whose shared PD leaves say USER), and PD[2] is the ELF window's user PT.
    fn layout() -> BTreeMap<(u64, usize), u64> {
        let p = F::PRESENT | F::WRITABLE;
        let u = p | F::USER_ACCESSIBLE;
        let mut tables = BTreeMap::new();
        let mut set = |table: u64, index: usize, value: u64, flags: F| {
            tables.insert((table, index), value | flags.bits());
        };
        set(ROOT, 0, PDPT, u);
        set(PDPT, 0, PD_LOW, u);
        set(PDPT, 1, PD_SHARED, p);
        set(PDPT, 2, PD_SHARED, p);
        set(PDPT, 3, BEYOND_DIRECT_MAP, u);
        set(PD_LOW, 0, PT_SPLIT, p);
        set(PD_LOW, 1, 0x20_0000, p | F::HUGE_PAGE);
        set(PD_LOW, 2, PT_USER, u);
        set(PD_LOW, 3, 0x60_0000, p | F::HUGE_PAGE);
        set(PD_SHARED, 0, 0x4000_0000, u | F::HUGE_PAGE);
        set(PT_SPLIT, 0x100, 0x10_0000, p);
        set(PT_USER, 0, 0x7000, u);
        set(
            PT_USER,
            1,
            0x8000,
            F::PRESENT | F::USER_ACCESSIBLE | F::BIT_9,
        );
        tables
    }

    fn reader(tables: &BTreeMap<(u64, usize), u64>) -> impl Fn(u64, usize) -> Option<u64> + '_ {
        move |table, index| {
            if table >= DIRECT_MAP_LIMIT {
                return None;
            }
            Some(tables.get(&(table, index)).copied().unwrap_or(0))
        }
    }

    #[test]
    fn r192_lower_half_ownership_follows_every_level() {
        let tables = layout();
        let read = reader(&tables);
        let access = |addr: u64| classify_user_page(ROOT, addr, &read).0;
        assert_eq!(
            access(0x40_0000),
            UserPageAccess::User {
                writable: true,
                copy_on_write: false
            }
        );
        assert_eq!(
            access(0x40_1234),
            UserPageAccess::User {
                writable: false,
                copy_on_write: true
            }
        );
        assert_eq!(access(0x40_2000), UserPageAccess::NotPresent);
        // Split identity PT, 2 MiB identity leaf, and a supervisor PDPT entry
        // whose shared PD leaf carries USER: all kernel-owned.
        assert_eq!(access(0x10_0000), UserPageAccess::Kernel);
        assert_eq!(access(0x0B_8000), UserPageAccess::Kernel);
        assert_eq!(access(0x20_0000), UserPageAccess::Kernel);
        assert_eq!(access(0x4000_0000), UserPageAccess::Kernel);
        // A table the direct map cannot reach fails closed.
        assert_eq!(access(0xC000_0000), UserPageAccess::Kernel);
        // Fresh user regions (the 64 GiB mmap window, the stack PML4 slot).
        assert_eq!(access(0x10_0000_0000), UserPageAccess::NotPresent);
        assert_eq!(access(0x7FFF_FFFF_E000), UserPageAccess::NotPresent);
        assert_eq!(access(USER_HALF_END), UserPageAccess::Kernel);
    }

    #[test]
    fn r192_range_walk_reports_the_first_kernel_owned_page() {
        let tables = layout();
        let read = reader(&tables);
        let first = |start: u64, len: u64| first_kernel_owned_in(ROOT, start, len, &read);
        assert_eq!(first(0x40_0000, 0x20_0000), None);
        assert_eq!(first(0x40_0000, 0x20_0001), Some(0x60_0000));
        assert_eq!(first(0x5F_F000, 0x1000_0000), Some(0x60_0000));
        assert_eq!(first(0x8000_0000, 0x20_0000), Some(0x8000_0000));
        assert_eq!(first(0x10_0000, 1), Some(0x10_0000));
        assert_eq!(first(0x40_0000, 0), None);
        // Absent subtrees are skipped span by span: a 64 TiB walk terminates.
        assert_eq!(first(0x10_0000_0000, 0x4000_0000_0000), None);
        assert_eq!(first(USER_HALF_END - 0x2000, 0x4000), Some(USER_HALF_END));

        // LEAD-MMAP-OWN-1: any translation occupies a page, user or kernel.
        let occupied = |start: u64, len: u64| first_occupied_in(ROOT, start, len, &read);
        assert_eq!(occupied(0x40_0000, 0x1000), Some(0x40_0000));
        assert_eq!(occupied(0x40_1000, 0x1000), Some(0x40_1000));
        assert_eq!(occupied(0x40_2000, 0x1F_E000), None);
        assert_eq!(occupied(0x40_2000, 0x1F_E001), Some(0x60_0000));
        assert_eq!(occupied(0x10_0000_0000, 0x4000_0000_0000), None);
    }
}

#[cfg(test)]
mod kpti_mirror_tests {
    use super::{mirror_user_half, MirrorOutcome};
    use x86_64::structures::paging::{PageTable, PageTableFlags as F};
    use x86_64::PhysAddr;

    fn root(entries: &[(usize, u64, F)]) -> PageTable {
        let mut table = PageTable::new();
        for &(index, addr, flags) in entries {
            table[index].set_addr(PhysAddr::new(addr), flags);
        }
        table
    }

    #[test]
    fn lead_kpti_pml4_1_mirror_links_new_slots_and_ignores_accessed_bits() {
        let parent = F::PRESENT | F::WRITABLE | F::USER_ACCESSIBLE;
        // The user root was copied with PML4[0] and the stack slot.
        let mut user = root(&[(0, 0x1000, parent), (255, 0x2000, parent)]);
        // Since then the kernel root gained PML4[1] (an mmap at 512 GiB) and
        // PML4[192]; the hardware set the accessed bit in its PML4[0] copy.
        let kernel = root(&[
            (0, 0x1000, parent | F::ACCESSED),
            (1, 0x3000, parent),
            (192, 0x4000, parent),
            (255, 0x2000, parent),
            // The upper half is the entry island's business, never mirrored.
            (300, 0x5000, F::PRESENT | F::WRITABLE),
        ]);
        let outcome = mirror_user_half(&kernel, &mut user);
        assert_eq!(
            outcome,
            MirrorOutcome {
                linked: 2,
                updated: 0,
                diverged: 0
            }
        );
        assert_eq!(user[1].addr(), PhysAddr::new(0x3000));
        assert_eq!(user[192].flags(), parent);
        assert!(!user[0].flags().contains(F::ACCESSED), "copy left alone");
        assert!(user[300].is_unused());
        // A second pass finds nothing to do.
        assert_eq!(
            mirror_user_half(&kernel, &mut user),
            MirrorOutcome::default()
        );
    }

    #[test]
    fn lead_kpti_pml4_1_mirror_follows_rights_and_reports_divergence() {
        let read_only = F::PRESENT | F::USER_ACCESSIBLE;
        let parent = read_only | F::WRITABLE;
        let mut user = root(&[
            (1, 0x3000, read_only),
            (2, 0x6000, parent),
            (3, 0x7000, parent),
        ]);
        // PML4[1] gained W; PML4[2] points at another PDPT; PML4[3] vanished.
        let kernel = root(&[(1, 0x3000, parent), (2, 0x8000, parent)]);
        let outcome = mirror_user_half(&kernel, &mut user);
        assert_eq!(
            outcome,
            MirrorOutcome {
                linked: 0,
                updated: 1,
                diverged: 2
            }
        );
        assert_eq!(user[1].flags(), parent);
        assert_eq!(user[2].addr(), PhysAddr::new(0x8000));
        assert!(user[3].is_unused(), "the kernel root wins");
    }
}

#[cfg(test)]
mod physical_range_tests {
    use super::{
        checked_mmio_page_count, checked_physical_range_for_bits, cpu_physical_address_bits,
        MapError,
    };
    use x86_64::{PhysAddr, VirtAddr};

    #[test]
    fn runtime_physical_width_bounds_complete_range() {
        let limit36 = 1u64 << 36;
        assert!(checked_physical_range_for_bits(limit36 - 0x1000, 0x1000, 36).is_some());
        assert!(checked_physical_range_for_bits(limit36, 1, 36).is_none());
        assert!(checked_physical_range_for_bits(limit36 - 0x1000, 0x1001, 36).is_none());

        let limit52 = 1u64 << 52;
        assert!(checked_physical_range_for_bits(limit52 - 0x1000, 0x1000, 52).is_some());
        assert!(checked_physical_range_for_bits(0, 0, 52).is_none());
        assert!(checked_physical_range_for_bits(u64::MAX, 2, 52).is_none());
        assert!(checked_physical_range_for_bits(0, 1, 0).is_none());
        assert!(checked_physical_range_for_bits(0, 1, 53).is_none());
    }

    #[test]
    fn central_mmio_page_count_rejects_rounded_range_crossing_maxphyaddr() {
        let bits = cpu_physical_address_bits().unwrap_or(52);
        let limit = 1u64 << bits;
        let start = limit - 0x1000;
        let phys = PhysAddr::try_new(start).expect("last in-width page is architectural");
        assert!(matches!(
            checked_mmio_page_count(VirtAddr::new(0x1000), phys, 0x1001),
            Err(MapError::InvalidRange)
        ));
    }
}

static CPU_PHYSICAL_ADDRESS_BITS: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(0);

fn cpu_physical_address_bits() -> Option<u8> {
    use core::sync::atomic::Ordering;

    let cached = CPU_PHYSICAL_ADDRESS_BITS.load(Ordering::Acquire);
    if cached != 0 {
        return Some(cached);
    }
    let max_extended = unsafe { core::arch::x86_64::__cpuid(0x8000_0000) }.eax;
    if max_extended < 0x8000_0008 {
        return None;
    }
    let bits = (unsafe { core::arch::x86_64::__cpuid(0x8000_0008) }.eax & 0xff) as u8;
    if bits == 0 || bits > 52 {
        return None;
    }
    let _ =
        CPU_PHYSICAL_ADDRESS_BITS.compare_exchange(0, bits, Ordering::AcqRel, Ordering::Acquire);
    Some(bits)
}

fn checked_physical_range_for_bits(start: u64, len: u64, bits: u8) -> Option<PhysAddr> {
    if len == 0 || bits == 0 || bits > 52 {
        return None;
    }
    let last = start.checked_add(len - 1)?;
    let limit = 1u64.checked_shl(u32::from(bits))?;
    if start >= limit || last >= limit {
        return None;
    }
    let start = PhysAddr::try_new(start).ok()?;
    PhysAddr::try_new(last).ok()?;
    Some(start)
}

/// Validate a complete CPU physical range against arithmetic overflow, the
/// x86_64 architectural ceiling, and this CPU's runtime MAXPHYADDR.
pub fn checked_physical_range(start: u64, len: u64) -> Option<PhysAddr> {
    checked_physical_range_for_bits(start, len, cpu_physical_address_bits()?)
}

fn checked_mmio_page_count(virt: VirtAddr, phys: PhysAddr, size: usize) -> Result<usize, MapError> {
    if size == 0
        || virt.as_u64() & (MMIO_PAGE_BYTES as u64 - 1) != 0
        || phys.as_u64() & (MMIO_PAGE_BYTES as u64 - 1) != 0
    {
        return Err(MapError::InvalidRange);
    }
    let mapped_len = size
        .checked_add(MMIO_PAGE_BYTES - 1)
        .map(|value| value & !(MMIO_PAGE_BYTES - 1))
        .ok_or(MapError::InvalidRange)?;
    if mapped_len == 0 || mapped_len > MAX_MMIO_MAP_BYTES {
        return Err(MapError::InvalidRange);
    }
    let tail = (mapped_len - 1) as u64;
    virt.as_u64()
        .checked_add(tail)
        .ok_or(MapError::InvalidRange)?;
    checked_physical_range(phys.as_u64(), mapped_len as u64).ok_or(MapError::InvalidRange)?;
    Ok(mapped_len / MMIO_PAGE_BYTES)
}

/// Map a previously vacant, page-aligned MMIO region with RW+NX+uncached flags.
///
/// RF186-4: this is a strict transaction. Existing/non-present ownership state
/// is rejected; every leaf mapped by a failed call is removed, every page-table
/// frame allocated by the call is reclaimed or retained with a leaf-free
/// hierarchy proof. Upper tables stay linked for peer-root safety; remote
/// translation caches are invalidated before reclaimed frames can be reused.
///
/// # Safety
///
/// The caller must own the complete virtual range as a private MMIO reservation
/// and prove the physical range is a validated device aperture.
pub unsafe fn map_mmio(
    virt: VirtAddr,
    phys: PhysAddr,
    size: usize,
    frame_allocator: &mut crate::memory::FrameAllocator,
) -> Result<(), MapError> {
    map_mmio_with_fault(
        virt,
        phys,
        size,
        frame_allocator,
        &mut MmioMapFault::default(),
    )
}

// The production entrypoint always supplies no fault. Keep injection local to
// this call so unrelated allocators/CPUs cannot observe a global failure switch.
unsafe fn map_mmio_with_fault(
    virt: VirtAddr,
    phys: PhysAddr,
    size: usize,
    frame_allocator: &mut crate::memory::FrameAllocator,
    fault: &mut MmioMapFault,
) -> Result<(), MapError> {
    let pages = checked_mmio_page_count(virt, phys, size)?;
    let mapped_len = pages * MMIO_PAGE_BYTES;
    let _pt_guard = lock_pt();
    let mut tracked = [None; MAX_MMIO_TRACKED_TABLES];
    let mut tracked_len = 0usize;
    let mut reclaimed = [None; MAX_MMIO_TRACKED_TABLES];
    let mut mapped_pages = 0usize;

    let result = interrupts::without_interrupts(|| {
        let phys_offset = get_phys_offset();
        let root_phys = active_root();
        let level_4_table = active_level_4_table(phys_offset);
        let mapper = OffsetPageTable::new(level_4_table, phys_offset);
        let mut mgr = PageTableManager {
            mapper,
            domain: PtDomain::KernelShared,
            root_phys,
        };

        // Preflight the complete virtual reservation before allocating a single
        // paging structure. Hidden non-present PTE ownership and huge parents
        // both fail closed through page_slot_is_unused().
        for index in 0..pages {
            let offset = (index * MMIO_PAGE_BYTES) as u64;
            let page = Page::<Size4KiB>::from_start_address(VirtAddr::new(virt.as_u64() + offset))
                .map_err(|_| MapError::InvalidRange)?;
            if !mgr.page_slot_is_unused(page) {
                return Err(MapError::PageAlreadyMapped);
            }
        }

        let failure = {
            let mut recorder = MmioPtRecorder {
                inner: frame_allocator,
                tracked: &mut tracked,
                tracked_len: &mut tracked_len,
                fault,
            };
            let mut failure = None;
            for index in 0..pages {
                let offset = (index * MMIO_PAGE_BYTES) as u64;
                let page =
                    Page::<Size4KiB>::from_start_address(VirtAddr::new(virt.as_u64() + offset))
                        .map_err(|_| MapError::InvalidRange)?;
                let frame = PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(
                    phys.as_u64() + offset,
                ))
                .map_err(|_| MapError::InvalidRange)?;
                if let Err(error) = mgr.map_page(page, frame, mmio_flags(), &mut recorder) {
                    failure = Some(error);
                    break;
                }
                mapped_pages += 1;
            }
            failure
        };

        if let Some(error) = failure {
            for index in 0..mapped_pages {
                let offset = (index * MMIO_PAGE_BYTES) as u64;
                let page =
                    Page::<Size4KiB>::from_start_address(VirtAddr::new(virt.as_u64() + offset))
                        .expect("validated MMIO rollback page");
                mgr.unmap_page(page)
                    .unwrap_or_else(|_| panic!("RF186-4: MMIO leaf rollback failed"));
            }
            let rollback = mgr.rollback_tracked_leaf_tables(
                virt,
                mapped_len,
                &tracked,
                tracked_len,
                &mut reclaimed,
                false,
            );
            #[cfg(feature = "mmio_probe")]
            {
                fault.rollback = Some(rollback);
            }
            if !rollback.all_accounted {
                panic!("RF186-4: MMIO page-table rollback accounting failed");
            }
            return Err(error);
        }

        Ok(())
    });

    // rollback_tracked_leaf_tables issued the paging-structure shootdown before
    // returning reclaimed frames. Return them only while PT_LOCK still excludes
    // another mapper from observing/reusing the detached hierarchy.
    for frame in reclaimed.into_iter().flatten() {
        frame_allocator.deallocate_frame(frame);
    }
    drop(_pt_guard);
    // Issue #109 §1.2 (H3): MMIO lives in the shared kernel high-half; match
    // `unmap_mmio` by broadcasting across all address spaces.
    crate::tlb_shootdown::flush_all_address_spaces();
    result
}

#[cfg(feature = "mmio_probe")]
#[path = "mmio_probes.rs"]
mod mmio_probes;
#[cfg(feature = "mmio_probe")]
pub use mmio_probes::run_mmio_rollback_self_test;

/// Remove a complete MMIO transaction created by [`map_mmio`].
///
/// The range is preflighted before mutation and empty paging structures are
/// reclaimed bottom-up without heap allocation. This is used by driver mapping
/// transactions to unwind earlier windows when a later window fails.
pub unsafe fn unmap_mmio(
    virt: VirtAddr,
    size: usize,
    frame_allocator: &mut crate::memory::FrameAllocator,
) -> Result<(), UnmapError> {
    let pages = checked_mmio_page_count(virt, PhysAddr::new(0), size)
        .map_err(|_| UnmapError::InvalidRange)?;
    let mapped_len = pages * MMIO_PAGE_BYTES;
    let _pt_guard = lock_pt();
    let mut reclaimed = [None; MAX_MMIO_TRACKED_TABLES];
    let mut reclaimed_len = 0usize;

    interrupts::without_interrupts(|| {
        let phys_offset = get_phys_offset();
        let root_phys = active_root();
        let level_4_table = active_level_4_table(phys_offset);
        let mapper = OffsetPageTable::new(level_4_table, phys_offset);
        let mut mgr = PageTableManager {
            mapper,
            domain: PtDomain::KernelShared,
            root_phys,
        };
        for index in 0..pages {
            let address = VirtAddr::new(virt.as_u64() + (index * MMIO_PAGE_BYTES) as u64);
            let Some((_, flags)) = mgr.translate_with_flags(address) else {
                return Err(UnmapError::PageNotMapped);
            };
            let required = PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::NO_CACHE;
            if !flags.contains(required) {
                return Err(UnmapError::InvalidRange);
            }
        }
        for index in 0..pages {
            let page = Page::<Size4KiB>::from_start_address(VirtAddr::new(
                virt.as_u64() + (index * MMIO_PAGE_BYTES) as u64,
            ))
            .map_err(|_| UnmapError::InvalidRange)?;
            mgr.unmap_page(page)?;
        }

        detach_empty_mmio_tables(
            &mut mgr,
            virt,
            mapped_len,
            &mut reclaimed,
            &mut reclaimed_len,
        );
        Ok(())
    })?;

    crate::tlb_shootdown::flush_all_address_spaces();
    for frame in reclaimed.into_iter().take(reclaimed_len).flatten() {
        frame_allocator.deallocate_frame(frame);
    }
    drop(_pt_guard);
    Ok(())
}

unsafe fn detach_empty_mmio_tables(
    manager: &mut PageTableManager,
    start: VirtAddr,
    len: usize,
    reclaimed: &mut [Option<PhysFrame<Size4KiB>>; MAX_MMIO_TRACKED_TABLES],
    reclaimed_len: &mut usize,
) {
    const PT_SPAN: u64 = 0x20_0000;
    fn empty(table: &PageTable) -> bool {
        table.iter().all(|entry| entry.is_unused())
    }
    fn record(
        output: &mut [Option<PhysFrame<Size4KiB>>; MAX_MMIO_TRACKED_TABLES],
        len: &mut usize,
        frame: PhysFrame<Size4KiB>,
    ) {
        if *len >= output.len() {
            panic!("RF186-4: MMIO table reclaim capacity exceeded");
        }
        output[*len] = Some(frame);
        *len += 1;
    }

    let start_u = start.as_u64();
    let end_u = start_u + (len as u64 - 1);
    let pml4 = manager.mapper.level_4_table_mut();

    let mut cursor = start_u & !(PT_SPAN - 1);
    loop {
        let addr = VirtAddr::new(cursor);
        let pml4e = &pml4[usize::from(addr.p4_index())];
        if pml4e.flags().contains(PageTableFlags::PRESENT) {
            let pdpt = &mut *phys_to_virt(pml4e.addr()).as_mut_ptr::<PageTable>();
            let pdpte = &pdpt[usize::from(addr.p3_index())];
            if pdpte.flags().contains(PageTableFlags::PRESENT)
                && !pdpte.flags().contains(PageTableFlags::HUGE_PAGE)
            {
                let pd = &mut *phys_to_virt(pdpte.addr()).as_mut_ptr::<PageTable>();
                let pde = &mut pd[usize::from(addr.p2_index())];
                if pde.flags().contains(PageTableFlags::PRESENT)
                    && !pde.flags().contains(PageTableFlags::HUGE_PAGE)
                {
                    let table = &*phys_to_virt(pde.addr()).as_ptr::<PageTable>();
                    if empty(table) {
                        let frame = PhysFrame::containing_address(pde.addr());
                        pde.set_unused();
                        record(reclaimed, reclaimed_len, frame);
                    }
                }
            }
        }
        match cursor.checked_add(PT_SPAN) {
            Some(next) if next <= end_u => cursor = next,
            _ => break,
        }
    }

    // Empty PD/PDPT frames remain reachable for reuse. Runtime KPTI roots may
    // carry upper paging-structure entries by value; detaching those tables
    // without a global root registry could leave a stale peer-root alias.
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;

    /// Local heap-backed page-table arena (`tables[0]` unused so valid frames
    /// start at physical `0x1000`, `tables[1]` is the PML4 root).
    struct HostedPtArena {
        tables: Box<[PageTable; 10]>,
    }

    struct HostedFrameAlloc {
        next_idx: usize,
        limit_idx: usize,
    }

    unsafe impl FrameAllocator<Size4KiB> for HostedFrameAlloc {
        fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
            if self.next_idx >= self.limit_idx {
                return None;
            }
            let idx = self.next_idx;
            self.next_idx += 1;
            Some(PhysFrame::containing_address(PhysAddr::new(
                (idx as u64) * 4096,
            )))
        }
    }

    impl HostedPtArena {
        fn new() -> Self {
            Self {
                tables: Box::new([const { PageTable::new() }; 10]),
            }
        }

        /// Build a `PageTableManager` pointing into `self.tables` (root = frame 1).
        /// SAFETY: caller must drop the returned `PageTableManager` before `self`.
        unsafe fn manager(&mut self, domain: PtDomain) -> PageTableManager {
            let base = self.tables.as_mut_ptr() as u64;
            let pml4: &'static mut PageTable = &mut *self.tables.as_mut_ptr().add(1);
            let mapper = OffsetPageTable::new(pml4, VirtAddr::new(base));
            PageTableManager {
                mapper,
                domain,
                root_phys: 0x1000,
            }
        }
    }

    #[test]
    fn page_range_slots_unused_handles_empty_straddle_and_occupied_entries() {
        let mut arena = HostedPtArena::new();
        let mut alloc = HostedFrameAlloc {
            next_idx: 2,
            limit_idx: 10,
        };
        let straddle_base = KSTACK_REGION_BASE + 0x1fc000; // 4 pages before 2 MiB boundary
        let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(straddle_base));
        let kflags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

        let mut mgr = unsafe { arena.manager(PtDomain::KernelShared) };
        assert!(mgr.page_range_slots_unused(start_page, 8));
        assert!(mgr.page_range_slots_unused(start_page, 0));

        // Map one page in the second PT of the 2 MiB straddle; range must become occupied.
        let fifth_page =
            Page::<Size4KiB>::containing_address(VirtAddr::new(straddle_base + 4 * 4096));
        let phys = PhysFrame::containing_address(PhysAddr::new(0x20_0000));
        assert!(mgr
            .map_contiguous_kernel_pages_no_flush(fifth_page, phys, 1, kflags, &mut alloc)
            .is_ok());
        assert!(!mgr.page_range_slots_unused(start_page, 8));
        assert!(mgr.page_range_slots_unused(start_page, 4));

        // Non-present PTE retaining hidden metadata must still be treated as occupied.
        let p4 = usize::from(fifth_page.start_address().p4_index());
        let p3 = usize::from(fifth_page.start_address().p3_index());
        let p2 = usize::from(fifth_page.start_address().p2_index());
        let p1 = usize::from(fifth_page.start_address().p1_index());
        let off = mgr.mapper.phys_offset().as_u64();
        let pt = unsafe {
            let pml4 = mgr.mapper.level_4_table_mut();
            let pdpt = &*(off.wrapping_add(pml4[p4].addr().as_u64()) as *const PageTable);
            let pd = &*(off.wrapping_add(pdpt[p3].addr().as_u64()) as *const PageTable);
            &mut *(off.wrapping_add(pd[p2].addr().as_u64()) as *mut PageTable)
        };
        pt[p1].set_addr(PhysAddr::new(0x20_0000), PageTableFlags::BIT_9);
        assert!(!mgr.page_range_slots_unused(start_page, 8));
        pt[p1].set_unused();
        assert!(mgr.page_range_slots_unused(start_page, 8));

        // Overflowing range fails closed.
        let top_page = Page::<Size4KiB>::containing_address(VirtAddr::new(0xffff_ffff_ffff_f000));
        assert!(!mgr.page_range_slots_unused(top_page, 2));
    }

    #[test]
    fn map_contiguous_kernel_pages_no_flush_maps_and_straddles_2m() {
        let mut arena = HostedPtArena::new();
        let mut alloc = HostedFrameAlloc {
            next_idx: 2,
            limit_idx: 10,
        };
        let straddle_base = KSTACK_REGION_BASE + 0x1fc000;
        let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(straddle_base));
        let start_frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x30_0000));
        let kflags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

        let mut mgr = unsafe { arena.manager(PtDomain::KernelShared) };

        // Reject user-accessible flags and lower-half virtual addresses.
        assert_eq!(
            mgr.map_contiguous_kernel_pages_no_flush(
                start_page,
                start_frame,
                1,
                kflags | PageTableFlags::USER_ACCESSIBLE,
                &mut alloc,
            ),
            Err((0, MapError::InvalidRange))
        );
        let user_page = Page::<Size4KiB>::containing_address(VirtAddr::new(0x40_0000));
        assert_eq!(
            mgr.map_contiguous_kernel_pages_no_flush(user_page, start_frame, 1, kflags, &mut alloc),
            Err((0, MapError::KernelOwned))
        );

        // Map 8 contiguous pages across a 2 MiB boundary (4 in PT0 + 4 in PT1).
        assert!(mgr
            .map_contiguous_kernel_pages_no_flush(start_page, start_frame, 8, kflags, &mut alloc)
            .is_ok());
        assert!(!mgr.page_range_slots_unused(start_page, 8));
        for i in 0..8u64 {
            let va = VirtAddr::new(straddle_base + i * 4096);
            let (pa, flags) = mgr.translate_with_flags(va).expect("mapped kstack leaf");
            assert_eq!(pa.as_u64(), 0x30_0000 + i * 4096);
            assert_eq!(flags, kflags);
        }
    }

    #[test]
    fn map_contiguous_kernel_pages_no_flush_reports_exact_partial_prefix_on_oom_and_collision() {
        let mut arena = HostedPtArena::new();
        // Exactly 3 frames available: PDPT + PD + PT0; PT1 allocation for page 4 must fail OOM.
        let mut tight_alloc = HostedFrameAlloc {
            next_idx: 2,
            limit_idx: 5,
        };
        let straddle_base = KSTACK_REGION_BASE + 0x1fc000;
        let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(straddle_base));
        let start_frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x40_0000));
        let kflags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

        let mut mgr = unsafe { arena.manager(PtDomain::KernelShared) };
        assert_eq!(
            mgr.map_contiguous_kernel_pages_no_flush(
                start_page,
                start_frame,
                8,
                kflags,
                &mut tight_alloc,
            ),
            Err((4, MapError::FrameAllocationFailed))
        );
        // Pages 0..4 were mapped; re-mapping from page 0 collides immediately at prefix 0.
        assert_eq!(
            mgr.map_contiguous_kernel_pages_no_flush(
                start_page,
                start_frame,
                4,
                kflags,
                &mut tight_alloc,
            ),
            Err((0, MapError::PageAlreadyMapped))
        );
        // Re-mapping starting 2 pages earlier collides at exact prefix 2.
        let earlier = Page::<Size4KiB>::containing_address(VirtAddr::new(straddle_base - 2 * 4096));
        assert_eq!(
            mgr.map_contiguous_kernel_pages_no_flush(
                earlier,
                start_frame,
                4,
                kflags,
                &mut tight_alloc,
            ),
            Err((2, MapError::PageAlreadyMapped))
        );
    }

    #[test]
    fn verify_and_unmap_contiguous_4k_no_flush_prevalidates_and_clears_straddle() {
        let mut arena = HostedPtArena::new();
        let mut alloc = HostedFrameAlloc {
            next_idx: 2,
            limit_idx: 10,
        };
        let straddle_base = KSTACK_REGION_BASE + 0x1fc000;
        let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(straddle_base));
        let start_frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x50_0000));
        let wrong_frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x60_0000));
        let kflags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

        let mut mgr = unsafe { arena.manager(PtDomain::KernelShared) };
        mgr.map_contiguous_kernel_pages_no_flush(start_page, start_frame, 8, kflags, &mut alloc)
            .expect("map straddle");

        // Wrong expected physical frame fails Phase 1 without modifying ANY leaf.
        assert_eq!(
            mgr.verify_and_unmap_contiguous_4k_no_flush(start_page, wrong_frame, 8),
            ContiguousUnmapOutcome::PrecheckFailed
        );
        for i in 0..8u64 {
            assert_eq!(
                mgr.translate_addr(VirtAddr::new(straddle_base + i * 4096)),
                Some(PhysAddr::new(0x50_0000 + i * 4096))
            );
        }

        // Exact frame match verifies and clears all 8 straddling leaves.
        assert_eq!(
            mgr.verify_and_unmap_contiguous_4k_no_flush(start_page, start_frame, 8),
            ContiguousUnmapOutcome::Verified
        );
        assert!(mgr.page_range_slots_unused(start_page, 8));
        // Second call sees absent leaves and fails Phase 1 cleanly.
        assert_eq!(
            mgr.verify_and_unmap_contiguous_4k_no_flush(start_page, start_frame, 8),
            ContiguousUnmapOutcome::PrecheckFailed
        );
    }

    #[test]
    fn lookup_present_leaf_mut_replaces_user_leaf_and_rejects_kernel_huge_absent() {
        let mut arena = HostedPtArena::new();
        let off = arena.tables.as_mut_ptr() as u64;
        // Build user hierarchy: PML4[0] -> PDPT(frame 2)[0] -> PD(frame 3)[2] -> PT(frame 4)[3]
        // and a 2 MiB huge entry at PD[4], plus a supervisor-only lower-half entry at PD[5].
        let user_parent =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
        let user_ro =
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::BIT_9;
        let user_rw =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

        arena.tables[1][0].set_addr(PhysAddr::new(0x2000), user_parent);
        arena.tables[2][0].set_addr(PhysAddr::new(0x3000), user_parent);
        arena.tables[3][2].set_addr(PhysAddr::new(0x4000), user_parent);
        arena.tables[4][3].set_addr(PhysAddr::new(0x11_0000), user_ro);
        arena.tables[3][4].set_addr(
            PhysAddr::new(0x80_0000),
            user_parent | PageTableFlags::HUGE_PAGE,
        );
        arena.tables[3][5].set_addr(
            PhysAddr::new(0x5000),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );
        arena.tables[5][0].set_addr(
            PhysAddr::new(0x22_0000),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );

        let mut mgr = unsafe { arena.manager(PtDomain::UserAddressSpace) };
        assert_eq!(mgr.mapper.phys_offset().as_u64(), off);

        let mapped_page = Page::<Size4KiB>::containing_address(VirtAddr::new(0x40_3000));
        {
            let leaf = mgr
                .lookup_present_leaf_mut(mapped_page)
                .expect("present user leaf");
            assert_eq!(leaf.frame().start_address().as_u64(), 0x11_0000);
            assert_eq!(leaf.flags(), user_ro);
            let old_frame = leaf.frame();
            leaf.replace(
                old_frame,
                PhysFrame::containing_address(PhysAddr::new(0x12_0000)),
                user_rw,
            )
            .expect("atomic leaf replacement");
        }
        assert_eq!(
            mgr.translate_with_flags(VirtAddr::new(0x40_3000)),
            Some((PhysAddr::new(0x12_0000), user_rw))
        );

        let absent_page = Page::<Size4KiB>::containing_address(VirtAddr::new(0x40_4000));
        assert_eq!(
            mgr.lookup_present_leaf_mut(absent_page).err(),
            Some(ReplacePageError::PageNotMapped)
        );
        let huge_page = Page::<Size4KiB>::containing_address(VirtAddr::new(0x80_0000));
        assert_eq!(
            mgr.lookup_present_leaf_mut(huge_page).err(),
            Some(ReplacePageError::ParentEntryHugePage)
        );
        let kernel_low_page = Page::<Size4KiB>::containing_address(VirtAddr::new(0xa0_0000));
        assert_eq!(
            mgr.lookup_present_leaf_mut(kernel_low_page).err(),
            Some(ReplacePageError::KernelOwned)
        );
    }

    #[test]
    fn map_user_pages_no_flush_maps_straddling_2m_and_reports_starvation_without_linking() {
        let mut arena = HostedPtArena::new();
        let mut alloc = HostedFrameAlloc {
            next_idx: 2,
            limit_idx: 6,
        }; // 4 table frames (frames 2,3,4,5)
        let straddle_base: u64 = 0x20_0000 - 3 * 4096;
        let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(straddle_base));
        let mut frames = [PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0)); 7];
        for (i, slot) in frames.iter_mut().enumerate() {
            *slot = PhysFrame::containing_address(PhysAddr::new(0x10_0000 + (i as u64) * 4096));
        }
        let uflags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE;

        let mut mgr = unsafe { arena.manager(PtDomain::UserAddressSpace) };
        // Available = 3 covers PML4->PDPT->PD->PT0 (3 tables), then starves on PT1
        // after mapping the first 3 pages without linking any table for PT1.
        assert_eq!(
            mgr.map_user_pages_no_flush(start_page, &frames, uflags, 3, &mut alloc),
            Err(BatchMapUserError::Starved {
                mapped: 3,
                shortfall: 1,
            })
        );
        for i in 0..3u64 {
            assert_eq!(
                mgr.translate_with_flags(VirtAddr::new(straddle_base + i * 4096)),
                Some((PhysAddr::new(0x10_0000 + i * 4096), uflags))
            );
        }
        assert_eq!(mgr.translate_addr(VirtAddr::new(0x20_0000)), None);

        // Provide the remaining 1 table and finish the tail [3..7].
        let tail_page = Page::<Size4KiB>::containing_address(VirtAddr::new(0x20_0000));
        mgr.map_user_pages_no_flush(tail_page, &frames[3..], uflags, 1, &mut alloc)
            .expect("finish straddling user map");
        for i in 0..7u64 {
            assert_eq!(
                mgr.translate_with_flags(VirtAddr::new(straddle_base + i * 4096)),
                Some((PhysAddr::new(0x10_0000 + i * 4096), uflags))
            );
        }
        // LEAD-KPTI-PML4-1: lower-half PML4E must have final P|W|U flags.
        let pml4_flags = arena.tables[1][0].flags();
        assert!(pml4_flags.contains(
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE
        ));
    }

    #[test]
    fn map_user_pages_no_flush_rejects_kernel_owned_huge_and_occupied() {
        let mut arena = HostedPtArena::new();
        let user_parent =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
        let uflags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        // PML4[0] -> PDPT(2)[0] -> PD(3):
        //   PD[1] = supervisor-only PT(4)
        //   PD[2] = 2 MiB user huge leaf
        //   PD[3] = user PT(5) with slot 1 occupied
        arena.tables[1][0].set_addr(PhysAddr::new(0x2000), user_parent);
        arena.tables[2][0].set_addr(PhysAddr::new(0x3000), user_parent);
        arena.tables[3][1].set_addr(
            PhysAddr::new(0x4000),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );
        arena.tables[3][2].set_addr(
            PhysAddr::new(0x40_0000),
            user_parent | PageTableFlags::HUGE_PAGE,
        );
        arena.tables[3][3].set_addr(PhysAddr::new(0x5000), user_parent);
        arena.tables[5][1].set_addr(PhysAddr::new(0x99_0000), uflags);

        let frames = [
            PhysFrame::containing_address(PhysAddr::new(0x10_0000)),
            PhysFrame::containing_address(PhysAddr::new(0x10_1000)),
        ];
        let mut alloc = HostedFrameAlloc {
            next_idx: 6,
            limit_idx: 10,
        };
        let mut mgr = unsafe { arena.manager(PtDomain::UserAddressSpace) };

        assert_eq!(
            mgr.map_user_pages_no_flush(
                Page::containing_address(VirtAddr::new(0x20_0000)),
                &frames,
                uflags,
                3,
                &mut alloc,
            ),
            Err(BatchMapUserError::Failed {
                mapped: 0,
                error: MapError::KernelOwned,
            })
        );
        assert_eq!(
            mgr.map_user_pages_no_flush(
                Page::containing_address(VirtAddr::new(0x40_0000)),
                &frames,
                uflags,
                3,
                &mut alloc,
            ),
            Err(BatchMapUserError::Failed {
                mapped: 0,
                error: MapError::ParentEntryHugePage,
            })
        );
        assert_eq!(
            mgr.map_user_pages_no_flush(
                Page::containing_address(VirtAddr::new(0x60_0000)),
                &frames,
                uflags,
                3,
                &mut alloc,
            ),
            Err(BatchMapUserError::Failed {
                mapped: 1,
                error: MapError::PageAlreadyMapped,
            })
        );
    }

    #[test]
    fn unmap_user_range_no_flush_reclaims_present_and_nonpresent_leaves_across_2m() {
        let mut arena = HostedPtArena::new();
        let user_parent =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
        let uflags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
        // PML4[0] -> PDPT(2)[0] -> PD(3):
        //   PD[0] = PT(4): slot 510 present user, slot 511 PROT_NONE (non-present with phys)
        //   PD[1] = PT(5): slot 0 present user, slot 1 supervisor-only (must NOT be cleared!)
        arena.tables[1][0].set_addr(PhysAddr::new(0x2000), user_parent);
        arena.tables[2][0].set_addr(PhysAddr::new(0x3000), user_parent);
        arena.tables[3][0].set_addr(PhysAddr::new(0x4000), user_parent);
        arena.tables[3][1].set_addr(PhysAddr::new(0x5000), user_parent);
        arena.tables[4][510].set_addr(PhysAddr::new(0x11_0000), uflags);
        arena.tables[4][511].set_addr(PhysAddr::new(0x12_0000), PageTableFlags::NO_EXECUTE);
        arena.tables[5][0].set_addr(PhysAddr::new(0x13_0000), uflags);
        arena.tables[5][1].set_addr(
            PhysAddr::new(0x14_0000),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );

        let mut mgr = unsafe { arena.manager(PtDomain::UserAddressSpace) };
        let start = VirtAddr::new(0x20_0000 - 2 * 4096);
        let mut reclaimed = alloc::vec::Vec::new();
        mgr.unmap_user_range_no_flush(start, 4 * 4096, |page, frame| {
            reclaimed.push((
                page.start_address().as_u64(),
                frame.start_address().as_u64(),
            ));
        });
        assert_eq!(
            reclaimed,
            alloc::vec![
                (0x1f_e000, 0x11_0000),
                (0x1f_f000, 0x12_0000),
                (0x20_0000, 0x13_0000),
            ]
        );
        assert!(arena.tables[4][510].is_unused());
        assert!(arena.tables[4][511].is_unused());
        assert!(arena.tables[5][0].is_unused());
        // Supervisor leaf must remain untouched (R192-2).
        assert_eq!(arena.tables[5][1].addr(), PhysAddr::new(0x14_0000));
    }
}
