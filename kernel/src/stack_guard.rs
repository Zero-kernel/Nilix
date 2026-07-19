//! 内核栈守护页
//!
//! 为内核栈和双重错误 IST 栈分配带守护页的新栈区域，
//! 防止栈溢出导致静默内存损坏。
//!
//! ## 工作原理
//!
//! - 在高半区选择一段未映射的虚拟地址区域
//! - 使用 4KB 页映射，第一页保留为守护页（不映射）
//! - 实际栈从第二页开始
//! - 栈溢出时触发页错误（#PF），而非静默损坏
//!
//! ## 初始化顺序
//!
//! 必须在以下条件满足后调用：
//! 1. 内存管理（mm）已初始化
//! 2. 页表管理器已初始化
//! 3. 中断尚未启用（sti 之前）

use x86_64::{
    structures::paging::{
        FrameAllocator as X64FrameAllocator, Page, PageTableFlags, PhysFrame, Size4KiB,
    },
    PhysAddr, VirtAddr,
};

use mm::page_table::TrackedTableRollback;

/// 页大小
const PAGE_SIZE: usize = 4096;

/// A single 4 KiB mapping can allocate at most one frame at each of the three
/// intermediate levels below PML4. Keep a fixed provenance ledger so rollback
/// never needs a heap allocation after physical frames are committed.
const MAX_GUARDED_STACK_PAGES: usize = arch::KERNEL_STACK_SIZE / PAGE_SIZE;
const STACK_PT_LEDGER_CAPACITY: usize = MAX_GUARDED_STACK_PAGES * 3;
const _: () = assert!(arch::KERNEL_STACK_SIZE % PAGE_SIZE == 0);
const _: () = assert!(arch::DOUBLE_FAULT_STACK_SIZE % PAGE_SIZE == 0);
const _: () = assert!(arch::DOUBLE_FAULT_STACK_SIZE <= arch::KERNEL_STACK_SIZE);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct GuardStackFaultObservation {
    requested_boundary: Option<usize>,
    successful_table_allocations: usize,
    fault_injected: bool,
}

struct GuardStackPtRecorder<'a, 'b> {
    inner: &'a mut mm::FrameAllocator,
    frames: [Option<PhysFrame<Size4KiB>>; STACK_PT_LEDGER_CAPACITY],
    len: usize,
    fail_after: Option<usize>,
    observation: Option<&'b mut GuardStackFaultObservation>,
}

impl<'a, 'b> GuardStackPtRecorder<'a, 'b> {
    fn new(
        inner: &'a mut mm::FrameAllocator,
        fail_after: Option<usize>,
        observation: Option<&'b mut GuardStackFaultObservation>,
    ) -> Self {
        Self {
            inner,
            frames: [None; STACK_PT_LEDGER_CAPACITY],
            len: 0,
            fail_after,
            observation,
        }
    }

    fn into_record(
        self,
    ) -> (
        [Option<PhysFrame<Size4KiB>>; STACK_PT_LEDGER_CAPACITY],
        usize,
    ) {
        (self.frames, self.len)
    }
}

unsafe impl X64FrameAllocator<Size4KiB> for GuardStackPtRecorder<'_, '_> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        if self.fail_after == Some(self.len) {
            if let Some(observation) = self.observation.as_deref_mut() {
                observation.fault_injected = true;
                observation.successful_table_allocations = self.len;
            }
            return None;
        }
        if self.len == STACK_PT_LEDGER_CAPACITY {
            return None;
        }
        let frame = self.inner.allocate_frame()?;
        self.frames[self.len] = Some(frame);
        self.len += 1;
        if let Some(observation) = self.observation.as_deref_mut() {
            observation.successful_table_allocations = self.len;
        }
        Some(frame)
    }
}

#[inline]
fn checked_virt_add(base: VirtAddr, offset: u64) -> Option<VirtAddr> {
    let raw = base.as_u64().checked_add(offset)?;
    VirtAddr::try_new(raw).ok()
}

#[inline]
fn checked_phys_add(base: PhysAddr, offset: u64) -> Option<PhysAddr> {
    let raw = base.as_u64().checked_add(offset)?;
    PhysAddr::try_new(raw).ok()
}

/// 内核栈区域基址（高半区未映射区域）
/// 位于 PML4[511] 但不在内核代码所在的 PDPT[510] 中
/// Bootloader 只映射了 PDPT[510]，其他 PDPT 槽位未使用
const KERNEL_STACK_REGION_BASE: u64 = 0xFFFF_FFFF_7000_0000;

/// 双重错误栈区域基址
/// 同样位于 PML4[511] 的未映射 PDPT 槽位中
const DOUBLE_FAULT_STACK_REGION_BASE: u64 = 0xFFFF_FFFF_6F00_0000;

/// 栈守护页安装错误
#[derive(Debug)]
pub enum GuardPageError {
    /// 无法分配物理内存
    AllocationFailed,
    /// 页表映射失败
    MappingFailed,
    /// 虚拟地址区域已被映射
    RegionAlreadyMapped,
    /// Mapping failed and ownership could not be completely rolled back. The
    /// affected frames remain quarantined instead of being reused unsafely.
    RollbackIncomplete,
}

/// RF180-24: exercise the production guarded-stack transaction against real
/// page tables and the global buddy allocator before KPTI creates peer roots.
///
/// The probes cover every no-leaf upper-table boundary (0, 1, and 2 successful
/// allocations) plus one leaf mapping followed by a cross-2MiB PT allocation.
/// Every case attests that the requested injector fired and restores the exact
/// buddy free-page count.
pub unsafe fn run_rollback_self_test() {
    const HIGH_HALF_PREFIX: u64 = 0xFFFF_0000_0000_0000;
    const PML4_INDEX_SHIFT: u32 = 39;
    // PML4[511] contains the kernel/direct map and PML4[510] is the recursive
    // page-table window. Search lower high-half entries for four completely
    // unused roots so every injected allocation boundary is deterministic.
    const FIRST_PROBE_PML4: u16 = 480;
    const LAST_PROBE_PML4: u16 = 509;
    const TEST_STACK_SIZE: usize = 4 * PAGE_SIZE;
    const CASES: [(u64, usize); 4] = [
        (0x1000_0000, 0),
        (0x2000_0000, 1),
        (0x3000_0000, 2),
        // Guard + first stack page end at a 2 MiB boundary. The first leaf
        // consumes three fresh upper frames; the next PT allocation fails.
        (0x0040_0000 - (2 * PAGE_SIZE) as u64, 3),
    ];

    // The rollback path performs a cross-address-space flush. Its per-CPU
    // mailbox is heap-backed on first access, so pre-initialize it before any
    // physical frame or page-table state belongs to the test transaction.
    mm::force_init_tlb_shootdown_locals();

    let probe_roots = unsafe {
        mm::with_current_manager(VirtAddr::new(0), |mgr| {
            let mut roots = [None; CASES.len()];
            let mut found = 0usize;
            for p4_index in (FIRST_PROBE_PML4..=LAST_PROBE_PML4).rev() {
                let root = HIGH_HALF_PREFIX | ((p4_index as u64) << PML4_INDEX_SHIFT);
                let root_addr = VirtAddr::new(root);
                if mgr.pml4_slot_is_unused(root_addr) {
                    roots[found] = Some(root);
                    found += 1;
                    if found == roots.len() {
                        break;
                    }
                }
            }
            assert_eq!(
                found,
                roots.len(),
                "RF180-24 requires four unused high-half PML4 probe slots"
            );
            roots.map(|root| root.expect("RF180-24 probe-root count was prevalidated"))
        })
    };

    for ((offset, fail_after), probe_root) in CASES.into_iter().zip(probe_roots) {
        let base = probe_root
            .checked_add(offset)
            .expect("RF180-24 probe offset remains inside one PML4 slot");
        let before = mm::buddy_allocator::get_allocator_stats()
            .expect("RF180-24 buddy allocator unavailable before guard-stack probe")
            .free_pages;
        let mut observation = GuardStackFaultObservation::default();
        let result = unsafe {
            mm::with_current_manager(VirtAddr::new(0), |mgr| {
                assert!(
                    mgr.pml4_slot_is_unused(VirtAddr::new(probe_root)),
                    "RF180-24 probe PML4 slot became occupied before injection"
                );
                let mut allocator = mm::FrameAllocator::new();
                let result = map_guarded_stack_with_fault(
                    mgr,
                    &mut allocator,
                    VirtAddr::new(base),
                    TEST_STACK_SIZE,
                    Some(fail_after),
                    Some(&mut observation),
                );
                assert!(
                    mgr.pml4_slot_is_unused(VirtAddr::new(probe_root)),
                    "RF180-24 guarded-stack rollback retained its probe PML4 slot"
                );
                result
            })
        };
        assert_eq!(
            observation.requested_boundary,
            Some(fail_after),
            "RF180-24 guarded-stack probe lost its requested injection boundary"
        );
        assert!(
            observation.fault_injected,
            "RF180-24 guarded-stack probe failed before injector boundary {}: {:?}",
            fail_after, observation
        );
        assert_eq!(
            observation.successful_table_allocations, fail_after,
            "RF180-24 guarded-stack probe observed the wrong allocation boundary"
        );
        assert!(
            matches!(result, Err(GuardPageError::MappingFailed)),
            "RF180-24 guarded-stack probe did not fail at table allocation {}: {:?}",
            fail_after,
            result
        );
        let after = mm::buddy_allocator::get_allocator_stats()
            .expect("RF180-24 buddy allocator unavailable after guard-stack probe")
            .free_pages;
        assert_eq!(
            after, before,
            "RF180-24 guarded-stack rollback leaked frames at injection point {}",
            fail_after
        );
    }

    klog_always!("      RF180-24 guarded-stack rollback probes: 4/4 passed");
}

/// 安装内核栈守护页
///
/// 为 TSS 的 RSP0（特权级切换栈）和 IST0（双重错误栈）分配带守护页的新栈。
///
/// # Safety
///
/// - 必须在 mm 和 page_table 初始化后调用
/// - 必须在启用中断前调用
/// - 只能调用一次
pub unsafe fn install() -> Result<(), GuardPageError> {
    // Production must not rely on the self-test having run first. Rollback can
    // broadcast a TLB flush after page-table state is committed, so eliminate
    // the CpuLocal first-touch allocation before entering the transaction.
    mm::force_init_tlb_shootdown_locals();

    // 使用当前页表管理器分配和映射栈
    mm::with_current_manager(VirtAddr::new(0), |mgr| {
        let mut frame_alloc = mm::FrameAllocator::new();

        // 1. 安装内核栈（RSP0）
        let kernel_stack_result = map_guarded_stack(
            mgr,
            &mut frame_alloc,
            VirtAddr::new(KERNEL_STACK_REGION_BASE),
            arch::KERNEL_STACK_SIZE,
        );

        let kernel_stack_top = match kernel_stack_result {
            Ok(top) => top,
            Err(e) => return Err(e),
        };

        // 立即更新 RSP0，即使后续 IST 设置失败也能保护内核栈
        arch::set_kernel_stack(kernel_stack_top.as_u64());

        // 2. 安装双重错误栈（IST0）
        let double_fault_stack_result = map_guarded_stack(
            mgr,
            &mut frame_alloc,
            VirtAddr::new(DOUBLE_FAULT_STACK_REGION_BASE),
            arch::DOUBLE_FAULT_STACK_SIZE,
        );

        let double_fault_stack_top = match double_fault_stack_result {
            Ok(top) => top,
            Err(e) => {
                // 内核栈已设置，IST 设置失败
                // 打印警告但继续运行（内核栈仍受保护）
                klog!(Warn, "  Warning: Failed to set up IST guard stack: {:?}", e);
                klog!(
                    Warn,
                    "  Double-fault handler will use static stack (less safe)"
                );
                // 仍然返回成功，因为内核栈已设置
                klog!(Info, "  Guard page stack installed (partial):");
                klog!(
                    Info,
                    "    - Kernel stack: 0x{:x} ({}KB + 4KB guard)",
                    kernel_stack_top.as_u64(),
                    arch::KERNEL_STACK_SIZE / 1024
                );
                return Ok(());
            }
        };

        // 3. 更新 IST0
        arch::set_ist_stack(
            arch::DOUBLE_FAULT_IST_INDEX as usize,
            double_fault_stack_top,
        );

        klog!(Info, "  Guard page stacks installed:");
        klog!(
            Info,
            "    - Kernel stack: 0x{:x} ({}KB + 4KB guard)",
            kernel_stack_top.as_u64(),
            arch::KERNEL_STACK_SIZE / 1024
        );
        klog!(
            Info,
            "    - Double-fault IST: 0x{:x} ({}KB + 4KB guard)",
            double_fault_stack_top.as_u64(),
            arch::DOUBLE_FAULT_STACK_SIZE / 1024
        );

        Ok(())
    })
}

/// 映射带守护页的栈
///
/// 布局：[守护页 (未映射)] [栈空间 (映射)]
///       base             base+PAGE_SIZE
///
/// 返回栈顶地址（向下生长，所以是 base + PAGE_SIZE + size）
fn map_guarded_stack(
    mgr: &mut mm::PageTableManager,
    frame_alloc: &mut mm::FrameAllocator,
    base: VirtAddr,
    size: usize,
) -> Result<VirtAddr, GuardPageError> {
    map_guarded_stack_with_fault(mgr, frame_alloc, base, size, None, None)
}

fn map_guarded_stack_with_fault(
    mgr: &mut mm::PageTableManager,
    frame_alloc: &mut mm::FrameAllocator,
    base: VirtAddr,
    size: usize,
    fail_after_table_frames: Option<usize>,
    mut fault_observation: Option<&mut GuardStackFaultObservation>,
) -> Result<VirtAddr, GuardPageError> {
    if let Some(observation) = fault_observation.as_deref_mut() {
        *observation = GuardStackFaultObservation {
            requested_boundary: fail_after_table_frames,
            ..GuardStackFaultObservation::default()
        };
    }
    // 验证大小是页对齐的
    if size == 0 || size % PAGE_SIZE != 0 {
        return Err(GuardPageError::AllocationFailed);
    }

    let page_count = size / PAGE_SIZE;
    if page_count > MAX_GUARDED_STACK_PAGES {
        return Err(GuardPageError::AllocationFailed);
    }
    let total_pages = page_count
        .checked_add(1)
        .ok_or(GuardPageError::AllocationFailed)?;

    // 验证整个区域（守护页 + 栈页）都未被映射
    for i in 0..total_pages {
        let offset = i
            .checked_mul(PAGE_SIZE)
            .ok_or(GuardPageError::AllocationFailed)?;
        let addr = checked_virt_add(base, offset as u64).ok_or(GuardPageError::AllocationFailed)?;
        if !mgr.page_slot_is_unused(Page::containing_address(addr)) {
            return Err(GuardPageError::RegionAlreadyMapped);
        }
    }

    // 实际栈从守护页之后开始
    let stack_base =
        checked_virt_add(base, PAGE_SIZE as u64).ok_or(GuardPageError::AllocationFailed)?;
    let stack_top =
        checked_virt_add(stack_base, size as u64).ok_or(GuardPageError::AllocationFailed)?;

    // 分配连续的物理帧
    let phys_start_frame = frame_alloc
        .allocate_contiguous_frames(page_count)
        .ok_or(GuardPageError::AllocationFailed)?;
    let phys_start = phys_start_frame.start_address();
    if checked_phys_add(phys_start, (size - 1) as u64).is_none() {
        return match frame_alloc.try_deallocate_contiguous_frames(phys_start_frame, page_count) {
            Ok(()) => Err(GuardPageError::AllocationFailed),
            Err(_) => Err(GuardPageError::RollbackIncomplete),
        };
    }

    // 映射栈页面（不映射守护页）
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

    // R180-L3: use a fixed provenance recorder. The generic range helper owns
    // heap-backed rollback state and cannot account for every intermediate
    // table frame allocated before a mapping failure.
    let mut mapped_pages = 0usize;
    let mut recorder =
        GuardStackPtRecorder::new(frame_alloc, fail_after_table_frames, fault_observation);
    for index in 0..page_count {
        let offset = index
            .checked_mul(PAGE_SIZE)
            .expect("guarded-stack offset bounded by fixed page count");
        // Both complete ranges were preflighted before the first PTE mutation.
        let page = Page::containing_address(VirtAddr::new(stack_base.as_u64() + offset as u64));
        let frame =
            PhysFrame::containing_address(PhysAddr::new(phys_start.as_u64() + offset as u64));

        if mgr.map_page(page, frame, flags, &mut recorder).is_err() {
            let (tracked_tables, tracked_len) = recorder.into_record();
            let mut reclaimed_tables = [None; STACK_PT_LEDGER_CAPACITY];

            // Prove every leaf still has the exact physical identity installed
            // by this transaction before the first PTE is cleared.
            let mut leaves_valid = true;
            for rollback in 0..mapped_pages {
                let rollback_offset = rollback * PAGE_SIZE;
                let rollback_page = Page::containing_address(stack_base + rollback_offset as u64);
                let expected = PhysFrame::containing_address(phys_start + rollback_offset as u64);
                if mgr.translate_page_4k(rollback_page) != Some(expected) {
                    leaves_valid = false;
                    break;
                }
            }

            let mut cleared = 0usize;
            let mut matched = 0usize;
            if leaves_valid {
                for rollback in (0..mapped_pages).rev() {
                    let rollback_offset = rollback * PAGE_SIZE;
                    let rollback_page =
                        Page::containing_address(stack_base + rollback_offset as u64);
                    let expected =
                        PhysFrame::containing_address(phys_start + rollback_offset as u64);
                    match mgr.unmap_page(rollback_page) {
                        Ok(actual) => {
                            cleared += 1;
                            if actual == expected {
                                matched += 1;
                            } else {
                                leaves_valid = false;
                                break;
                            }
                        }
                        Err(_) => {
                            leaves_valid = false;
                            break;
                        }
                    }
                }
            }

            // These mappings are deliberately non-global. Broadcast before a
            // detached data or page-table frame can return to the buddy.
            if cleared != 0 {
                mm::flush_all_address_spaces();
            }

            let rollback = if leaves_valid && matched == mapped_pages {
                unsafe {
                    mgr.rollback_tracked_leaf_tables(
                        stack_base,
                        size,
                        &tracked_tables,
                        tracked_len,
                        &mut reclaimed_tables,
                        true,
                    )
                }
            } else {
                TrackedTableRollback {
                    reclaimed_count: 0,
                    retained_count: 0,
                    all_accounted: false,
                }
            };

            if !rollback.all_accounted || rollback.retained_count != 0 {
                // Frame handles are plain values. Omitting deallocation here
                // quarantines both the contiguous block and any detached table
                // whose complete ownership cannot be proven.
                klog!(
                    Error,
                    "R180-L3: guarded-stack rollback incomplete; quarantining frames"
                );
                return Err(GuardPageError::RollbackIncomplete);
            }

            let mut release_failed = false;
            for table_frame in reclaimed_tables
                .iter()
                .take(rollback.reclaimed_count)
                .flatten()
                .copied()
            {
                if frame_alloc.try_deallocate_frame(table_frame).is_err() {
                    release_failed = true;
                }
            }
            if frame_alloc
                .try_deallocate_contiguous_frames(phys_start_frame, page_count)
                .is_err()
            {
                release_failed = true;
            }
            if release_failed {
                klog!(
                    Error,
                    "R180-L3: guarded-stack rollback deallocation failed; frames retained"
                );
                return Err(GuardPageError::RollbackIncomplete);
            }
            return Err(GuardPageError::MappingFailed);
        }
        mapped_pages += 1;
    }

    // 清零新栈
    unsafe {
        core::ptr::write_bytes(stack_base.as_mut_ptr::<u8>(), 0, size);
    }

    // 返回栈顶（x86 栈向下生长）
    Ok(stack_top)
}
