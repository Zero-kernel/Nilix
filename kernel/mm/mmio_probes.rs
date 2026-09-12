//! Guest probes of the production mapping transaction; no scratch UC data access.

use super::*;

const FIXTURE_SPAN: usize = 1 << 30;
const FIXTURE_TABLES: usize = 8;

fn free_pages() -> usize {
    crate::buddy_allocator::get_allocator_stats()
        .unwrap()
        .free_pages
}

// Enumerate only the fixture-owned first GiB of an otherwise unused PML4 slot.
// Numeric provenance is kept independently from rollback's accounting result.
unsafe fn fixture_tables(
    manager: &mut PageTableManager,
    root: VirtAddr,
) -> ([Option<PhysFrame<Size4KiB>>; FIXTURE_TABLES], usize) {
    let mut tables = [None; FIXTURE_TABLES];
    let mut count = 0;
    let mut record = |address| {
        assert!(count < FIXTURE_TABLES);
        tables[count] = Some(PhysFrame::containing_address(address));
        count += 1;
    };
    let entry = &manager.mapper.level_4_table()[usize::from(root.p4_index())];
    if !entry.is_unused() {
        assert!(entry.flags().contains(PageTableFlags::PRESENT));
        record(entry.addr());
        let pdpt = &*phys_to_virt(entry.addr()).as_ptr::<PageTable>();
        assert!(pdpt.iter().skip(1).all(|entry| entry.is_unused()));
        if !pdpt[0].is_unused() {
            assert!(pdpt[0].flags().contains(PageTableFlags::PRESENT));
            assert!(!pdpt[0].flags().contains(PageTableFlags::HUGE_PAGE));
            record(pdpt[0].addr());
            let pd = &*phys_to_virt(pdpt[0].addr()).as_ptr::<PageTable>();
            for entry in pd.iter().filter(|entry| !entry.is_unused()) {
                assert!(entry.flags().contains(PageTableFlags::PRESENT));
                assert!(!entry.flags().contains(PageTableFlags::HUGE_PAGE));
                record(entry.addr());
            }
        }
    }
    (tables, count)
}

unsafe fn cleanup_fixture(root: VirtAddr, allocator: &mut crate::memory::FrameAllocator) {
    let mut reclaimed = [None; FIXTURE_TABLES];
    crate::with_current_manager(VirtAddr::new(0), |manager| {
        let (tracked, count) = fixture_tables(manager, root);
        let result = manager.rollback_tracked_leaf_tables(
            root,
            FIXTURE_SPAN,
            &tracked,
            count,
            &mut reclaimed,
            true,
        );
        assert!(
            result.all_accounted,
            "fixture cleanup found a live/unknown table"
        );
        assert_eq!(result.reclaimed_count, count);
        assert_eq!(result.retained_count, 0);
        assert!(manager.pml4_slot_is_unused(root));
    });
    // The exclusive-root rollback clears and synchronously flushes first.
    for frame in reclaimed.into_iter().flatten() {
        allocator.deallocate_frame(frame);
    }
}

unsafe fn retention_rejections(
    root: VirtAddr,
    backing: PhysFrame<Size4KiB>,
    allocator: &mut crate::memory::FrameAllocator,
) {
    let before = free_pages();
    let virt = root + 0x1000u64;
    map_mmio(virt, backing.start_address(), 4096, allocator).unwrap();
    crate::with_current_manager(VirtAddr::new(0), |manager| {
        let (tracked, count) = fixture_tables(manager, root);
        assert_eq!(count, 3);
        let mut no_output = [];
        let live = manager.rollback_tracked_leaf_tables(
            root,
            FIXTURE_SPAN,
            &tracked,
            count,
            &mut no_output,
            false,
        );
        assert!(!live.all_accounted, "live leaf was accepted as empty");
        assert!(manager.translate_with_flags(virt).is_some());
        manager.unmap_page(Page::containing_address(virt)).unwrap();

        let retained = manager.rollback_tracked_leaf_tables(
            root,
            FIXTURE_SPAN,
            &tracked,
            count,
            &mut no_output,
            false,
        );
        assert_eq!(
            retained,
            TrackedTableRollback {
                reclaimed_count: 0,
                retained_count: 3,
                all_accounted: true,
            }
        );
        // The empty PT remains reachable, but it has no transaction provenance.
        let unknown = manager.rollback_tracked_leaf_tables(
            root,
            FIXTURE_SPAN,
            &tracked,
            count - 1,
            &mut no_output,
            false,
        );
        assert!(!unknown.all_accounted, "unknown child was accepted");
        for malformed in [
            [tracked[0], tracked[0], tracked[2]],
            [tracked[0], None, tracked[2]],
        ] {
            let mut malformed_output = [None; FIXTURE_TABLES];
            let result = manager.rollback_tracked_leaf_tables(
                root,
                FIXTURE_SPAN,
                &malformed,
                3,
                &mut malformed_output,
                false,
            );
            assert!(!result.all_accounted, "invalid provenance was accepted");
            assert!(malformed_output.iter().all(Option::is_none));
            assert_eq!(fixture_tables(manager, root), (tracked, count));
        }
        for flags in [
            PageTableFlags::WRITABLE,
            PageTableFlags::PRESENT | PageTableFlags::HUGE_PAGE,
        ] {
            // Outside the mapped PT: hidden ownership or a huge data leaf must
            // invalidate the entire retained-parent proof. Never access it.
            let pd = phys_to_virt(tracked[1].unwrap().start_address()).as_mut_ptr::<PageTable>();
            (&mut *pd)[1].set_addr(PhysAddr::new(0), flags);
            let result = manager.rollback_tracked_leaf_tables(
                root,
                FIXTURE_SPAN,
                &tracked,
                count,
                &mut no_output,
                false,
            );
            assert!(!result.all_accounted, "hidden/huge ownership was accepted");
            (&mut *pd)[1].set_unused();
            crate::tlb_shootdown::flush_all_address_spaces();
        }
        let exclusive = manager.rollback_tracked_leaf_tables(
            root,
            FIXTURE_SPAN,
            &tracked,
            count,
            &mut no_output,
            true,
        );
        assert!(
            !exclusive.all_accounted,
            "exclusive mode accepted nonempty parents"
        );
    });
    cleanup_fixture(root, allocator);
    assert_eq!(free_pages(), before);
}

/// # Safety
/// Run on the BSP before KPTI/AP startup, with interrupts disabled and MM ready.
/// Every scratch frame is retained until all aliases and paging frames retire.
pub unsafe fn run_mmio_rollback_self_test() {
    crate::force_init_tlb_shootdown_locals();
    let root = crate::with_current_manager(VirtAddr::new(0), |manager| {
        (480u64..=509)
            .rev()
            .map(|index| 0xffff_0000_0000_0000 | (index << 39))
            .map(VirtAddr::new)
            .find(|&root| manager.pml4_slot_is_unused(root))
            .expect("MMIO probe needs an unused high-half root")
    });
    let baseline = free_pages();
    let mut allocator = crate::memory::FrameAllocator::new();
    let backing = allocator
        .allocate_contiguous_frames(2)
        .expect("MMIO probe backing");
    for fail_after in 0..4 {
        // Case 3 maps the first leaf, then fails the PT allocation across 2 MiB.
        let virt = root + 0x003f_f000u64;
        let before = free_pages();
        let mut fault = MmioMapFault {
            fail_after: Some(fail_after),
            ..Default::default()
        };
        let result = map_mmio_with_fault(
            virt,
            backing.start_address(),
            8192,
            &mut allocator,
            &mut fault,
        );
        assert!(fault.injected, "MMIO allocation injector did not fire");
        assert_eq!(fault.allocations, fail_after);
        assert!(matches!(result, Err(MapError::FrameAllocationFailed)));
        let rollback = fault.rollback.expect("production rollback did not execute");
        assert!(rollback.all_accounted);
        assert_eq!(rollback.retained_count, fail_after.min(2));
        assert_eq!(rollback.reclaimed_count, usize::from(fail_after == 3));
        crate::with_current_manager(VirtAddr::new(0), |manager| {
            assert_eq!(manager.pml4_slot_is_unused(root), fail_after == 0);
            assert!(manager.translate_with_flags(virt).is_none());
            assert!(manager.translate_with_flags(virt + 4096u64).is_none());
        });
        assert_eq!(free_pages() + rollback.retained_count, before);
        cleanup_fixture(root, &mut allocator);
        assert_eq!(free_pages(), before, "fixture cleanup leaked paging frames");
    }
    retention_rejections(root, backing, &mut allocator);
    let virt = root + 0x1000_0000u64;
    assert!(matches!(
        unmap_mmio(virt, 4096, &mut allocator),
        Err(UnmapError::PageNotMapped)
    ));
    assert!(matches!(
        map_mmio(virt, backing.start_address() + 1u64, 4096, &mut allocator),
        Err(MapError::InvalidRange)
    ));
    map_mmio(virt, backing.start_address(), 8192, &mut allocator).expect("vacant MMIO mapping");
    let readonly = mmio_flags() & !PageTableFlags::WRITABLE;
    crate::with_current_manager(VirtAddr::new(0), |manager| {
        let (phys, flags) = manager.translate_with_flags(virt).unwrap();
        assert_eq!(phys, backing.start_address());
        assert!(flags.contains(mmio_flags()));
        assert!(!flags.contains(PageTableFlags::USER_ACCESSIBLE));
        manager
            .update_flags(Page::containing_address(virt), readonly)
            .unwrap();
    });
    let before = free_pages();
    assert!(matches!(
        map_mmio(virt, backing.start_address(), 4096, &mut allocator),
        Err(MapError::PageAlreadyMapped)
    ));
    assert!(matches!(
        unmap_mmio(virt, 8192, &mut allocator),
        Err(UnmapError::InvalidRange)
    ));
    crate::with_current_manager(VirtAddr::new(0), |manager| {
        let (phys, flags) = manager.translate_with_flags(virt).unwrap();
        assert_eq!(phys, backing.start_address());
        assert_eq!(flags, readonly);
        assert!(
            manager.translate_with_flags(virt + 4096u64).is_some(),
            "failed unmap removed a suffix"
        );
        manager
            .update_flags(Page::containing_address(virt), mmio_flags())
            .unwrap();
    });
    assert_eq!(free_pages(), before);
    unmap_mmio(virt, 8192, &mut allocator).expect("MMIO probe cleanup");
    cleanup_fixture(root, &mut allocator);
    allocator.deallocate_contiguous_frames(backing, 2);
    assert_eq!(
        free_pages(),
        baseline,
        "MMIO probe did not restore buddy ownership"
    );
    klog::klog_always!("KSA-001-MMIO-PROBES PASS allocation_boundaries=4 retained_capacity=1 invalid_ownership=5 exclusive=1 occupied_readonly=1 unmapped=1 restoration=exact");
}
