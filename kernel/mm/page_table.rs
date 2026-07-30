//! 页表管理器
//!
//! 提供对x86_64页表的完整管理功能

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
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

/// R67-5 FIX: Global page table lock for cross-CPU serialization.
///
/// This lock ensures that page table modifications from different CPUs are serialized.
/// Without this, concurrent calls to map_page/unmap_page from multiple CPUs could
/// cause torn PTE updates, partially written flags (W^X bypass), or frame reuse
/// while another CPU still has a stale TLB entry.
///
/// Long-term solution: Per-address-space locks + TLB shootdown with ACK.
static PT_LOCK: Mutex<()> = Mutex::new(());
const NO_PT_LOCK_OWNER: usize = usize::MAX;
static PT_LOCK_OWNER_CPU: AtomicUsize = AtomicUsize::new(NO_PT_LOCK_OWNER);

struct PtLockGuard {
    _guard: spin::MutexGuard<'static, ()>,
}

impl Drop for PtLockGuard {
    fn drop(&mut self) {
        PT_LOCK_OWNER_CPU.store(NO_PT_LOCK_OWNER, Ordering::Release);
    }
}

#[inline]
fn lock_pt() -> PtLockGuard {
    let guard = PT_LOCK.lock();
    PT_LOCK_OWNER_CPU.store(cpu_local::current_cpu_id(), Ordering::Release);
    PtLockGuard { _guard: guard }
}

#[inline]
fn try_lock_pt() -> Option<PtLockGuard> {
    let guard = PT_LOCK.try_lock()?;
    PT_LOCK_OWNER_CPU.store(cpu_local::current_cpu_id(), Ordering::Release);
    Some(PtLockGuard { _guard: guard })
}

/// CPU that currently owns the global page-table lock, if any.
#[inline]
pub fn pt_lock_owner_cpu() -> Option<usize> {
    match PT_LOCK_OWNER_CPU.load(Ordering::Acquire) {
        NO_PT_LOCK_OWNER => None,
        cpu => Some(cpu),
    }
}

/// R67-5 FIX: Public helper to acquire the global page table lock.
///
/// Use this when touching page tables directly (not via `with_current_manager`)
/// to ensure modifications remain serialized across CPUs.
///
/// # Example
///
/// ```rust,ignore
/// use mm::page_table::with_pt_lock;
///
/// with_pt_lock(|| {
///     // Safe to modify page tables here
///     recursive_pd(0, 0)[0].set_flags(...);
/// });
/// ```
#[inline]
pub fn with_pt_lock<T, F>(f: F) -> T
where
    F: FnOnce() -> T,
{
    let _guard = lock_pt();
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

/// 页表管理器
pub struct PageTableManager {
    mapper: OffsetPageTable<'static>,
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
    /// Every tracked allocation was either reclaimed or proven reachable and
    /// empty.  `false` requires fail-closed quarantine by the caller.
    pub all_accounted: bool,
}

/// 基于当前活动的 CR3 构建临时页表管理器
///
/// 此函数在每次调用时从当前 CR3 读取页表根地址，确保始终操作正确的地址空间。
/// 这对于 COW 故障处理和 mmap/munmap 在多进程环境下正确工作至关重要。
///
/// # Safety
///
/// 调用者必须提供正确的物理内存偏移量。
/// 在回调函数执行期间，不得发生导致 CR3 切换的上下文切换。
///
/// # Security (R32-MM-1 fix)
///
/// 此函数在执行期间禁用中断，防止上下文切换导致操作错误的地址空间。
/// 这可以避免跨进程内存破坏漏洞。
///
/// # Security (R67-5 fix)
///
/// 此函数获取全局页表锁，防止多 CPU 并发修改页表导致的数据竞争。
pub unsafe fn with_current_manager<T, F>(physical_memory_offset: VirtAddr, f: F) -> T
where
    F: FnOnce(&mut PageTableManager) -> T,
{
    // R67-5 FIX: Acquire global page table lock to serialize cross-CPU modifications
    let _pt_guard = lock_pt();

    // R32-MM-1 FIX: Disable interrupts to prevent CR3 switch during page table operations
    interrupts::without_interrupts(|| {
        let _ = physical_memory_offset; // 调用方参数保持兼容，实际使用固定偏移
        let phys_offset = get_phys_offset();
        let level_4_table = active_level_4_table(phys_offset);
        let mapper = OffsetPageTable::new(level_4_table, phys_offset);
        let mut manager = PageTableManager { mapper };
        f(&mut manager)
    })
}

/// RF178-12: nonblocking `with_current_manager` variant for synchronous #PF.
///
/// # Safety
///
/// Caller must ensure `physical_memory_offset` is valid. A contended global PT
/// lock—including same-CPU re-entry—returns `None`; the exception dispatcher
/// distinguishes proven same-CPU ownership from ordinary cross-CPU contention.
/// This function itself never spins on a holder that may need the faulting CPU
/// to make forward progress.
pub unsafe fn try_with_current_manager<T, F>(physical_memory_offset: VirtAddr, f: F) -> Option<T>
where
    F: FnOnce(&mut PageTableManager) -> T,
{
    let _pt_guard = try_lock_pt()?;
    Some(interrupts::without_interrupts(|| {
        let _ = physical_memory_offset;
        let phys_offset = get_phys_offset();
        let level_4_table = active_level_4_table(phys_offset);
        let mapper = OffsetPageTable::new(level_4_table, phys_offset);
        let mut manager = PageTableManager { mapper };
        f(&mut manager)
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
        let level_4_table = active_level_4_table(phys_offset);
        let mapper = OffsetPageTable::new(level_4_table, phys_offset);

        PageTableManager { mapper }
    }

    /// 映射虚拟页到物理帧
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

        unsafe {
            self.mapper
                .map_to(page, frame, flags, frame_allocator)
                .map_err(|e| match e {
                    MapToError::FrameAllocationFailed => MapError::FrameAllocationFailed,
                    MapToError::ParentEntryHugePage => MapError::ParentEntryHugePage,
                    MapToError::PageAlreadyMapped(_) => MapError::PageAlreadyMapped,
                })?
                .flush();
        }

        Ok(())
    }

    /// 取消映射虚拟页
    pub fn unmap_page(&mut self, page: Page) -> Result<PhysFrame, UnmapError> {
        use x86_64::structures::paging::mapper::UnmapError as X64UnmapError;

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
    /// Must be called while PT_LOCK is held (i.e. inside `with_current_manager`).
    pub fn take_nonpresent_leaf_frame(&mut self, page: Page) -> Option<PhysFrame> {
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
        if len == 0 {
            return;
        }

        /// 2 MiB — virtual span covered by one PT (512 × 4 KiB).
        const PT_SPAN: u64 = 0x20_0000;
        /// 1 GiB — virtual span covered by one PD (512 × 2 MiB).
        const PD_SPAN: u64 = 0x4000_0000;

        #[inline]
        fn table_empty(table: &PageTable) -> bool {
            table.iter().all(|entry| entry.is_unused())
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
            if pml4e.flags().contains(PageTableFlags::PRESENT) {
                let pdpt = &mut *phys_to_virt(pml4e.addr()).as_mut_ptr::<PageTable>();
                let pdpte_flags = pdpt[p3].flags();
                if pdpte_flags.contains(PageTableFlags::PRESENT)
                    && !pdpte_flags.contains(PageTableFlags::HUGE_PAGE)
                {
                    let pd = &mut *phys_to_virt(pdpt[p3].addr()).as_mut_ptr::<PageTable>();
                    let pde = &mut pd[p2];
                    let pde_flags = pde.flags();
                    if pde_flags.contains(PageTableFlags::PRESENT)
                        && !pde_flags.contains(PageTableFlags::HUGE_PAGE)
                    {
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
            if pml4e.flags().contains(PageTableFlags::PRESENT) {
                let pdpt = &mut *phys_to_virt(pml4e.addr()).as_mut_ptr::<PageTable>();
                let pdpte = &mut pdpt[p3];
                let pdpte_flags = pdpte.flags();
                if pdpte_flags.contains(PageTableFlags::PRESENT)
                    && !pdpte_flags.contains(PageTableFlags::HUGE_PAGE)
                {
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

        // R169-L2 FIX: a collapsed PDE/PDPTE removes a paging-structure entry that
        // spans up to 2 MiB / 1 GiB — beyond the caller's leaf-range flush. Issue a
        // full TLB + paging-structure-cache shootdown (all CPUs) so no stale cached
        // parent translation can reference a freed table frame once the caller
        // returns it to the allocator. Runs under PT_LOCK like the caller's range
        // flush; only on the rare OOM-rollback-that-reclaimed-a-table path, so the
        // extra shootdown cost is irrelevant (Safety > Speed). The caller still
        // frees `frames_to_free` after this returns, so the clear→flush→free order
        // holds for the freed table frames too.
        if reclaimed_any {
            crate::tlb_shootdown::flush_current_as_all();
        }
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
                            if !empty(pt) {
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
                        if empty(pd) {
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
                                    retained_count += 1;
                                }
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
                    if !empty(pdpt) {
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
                            retained_count += 1;
                        }
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
#[derive(Debug)]
pub enum MapError {
    FrameAllocationFailed,
    ParentEntryHugePage,
    PageAlreadyMapped,
    /// R32-MM-2 FIX: Invalid range (overflow in size or offset calculation)
    InvalidRange,
}

/// 页表取消映射错误
#[derive(Debug)]
pub enum UnmapError {
    PageNotMapped,
    ParentEntryHugePage,
    InvalidFrameAddress,
    /// R35-MM-2 FIX: Overflow or invalid range in unmap_range offset calculation
    InvalidRange,
}

/// 更新标志位错误
#[derive(Debug)]
pub enum UpdateFlagsError {
    PageNotMapped,
    ParentEntryHugePage,
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
    let addr = RECURSIVE_PDPT_BASE + (pml4_idx as u64) * 0x1000;
    &mut *(addr as *mut PageTable)
}

/// 获取指定索引的 PD（通过递归映射）
///
/// # Safety
///
/// 调用者必须确保对应的页表条目存在且有效
#[inline]
pub unsafe fn recursive_pd(pml4_idx: usize, pdpt_idx: usize) -> &'static mut PageTable {
    let addr = RECURSIVE_PD_BASE + (pml4_idx as u64) * 0x20_0000 + (pdpt_idx as u64) * 0x1000;
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
    let addr = RECURSIVE_PT_BASE
        + (pml4_idx as u64) * 0x4000_0000
        + (pdpt_idx as u64) * 0x20_0000
        + (pd_idx as u64) * 0x1000;
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
        crate::tlb_shootdown::flush_current_as_range(VirtAddr::new(huge_base), 0x20_0000);
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
}

unsafe impl FrameAllocator<Size4KiB> for MmioPtRecorder<'_> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let frame = self.inner.allocate_frame()?;
        if *self.tracked_len >= self.tracked.len() {
            self.inner.deallocate_frame(frame);
            return None;
        }
        self.tracked[*self.tracked_len] = Some(frame);
        *self.tracked_len += 1;
        Some(frame)
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
/// frame allocated by the call is detached and returned, and remote translation
/// caches are invalidated before any reclaimed frame can be reused.
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
    let pages = checked_mmio_page_count(virt, phys, size)?;
    let mapped_len = pages * MMIO_PAGE_BYTES;
    let _pt_guard = lock_pt();
    let mut tracked = [None; MAX_MMIO_TRACKED_TABLES];
    let mut tracked_len = 0usize;
    let mut reclaimed = [None; MAX_MMIO_TRACKED_TABLES];
    let mut mapped_pages = 0usize;

    let result = interrupts::without_interrupts(|| {
        let phys_offset = get_phys_offset();
        let level_4_table = active_level_4_table(phys_offset);
        let mapper = OffsetPageTable::new(level_4_table, phys_offset);
        let mut mgr = PageTableManager { mapper };

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
    crate::tlb_shootdown::flush_current_as_range(virt, mapped_len);
    result
}

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
        let level_4_table = active_level_4_table(phys_offset);
        let mapper = OffsetPageTable::new(level_4_table, phys_offset);
        let mut mgr = PageTableManager { mapper };
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
