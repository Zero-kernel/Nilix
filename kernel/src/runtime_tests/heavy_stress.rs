// Heavy Contention & Extended Runtime Stress Tests (STRICT-Q S3 + S8).
//
// Per STRICT-Q Decision D4:
// - `r175_heavy_tlb_contention`, `r175_rapid_signal_migration`, and
//   `r175_namespace_teardown_storm` are implemented as bounded SMP runtime
//   probes (`TestScope::NeedsCpus(2)`).
// - `r175_extended_runtime_1hour` is covered by the external STRESS-7 gate
//   (`TestScope::CoveredBy { gate: "stress", marker: "STRESS-TEST STABLE:" }`).

use crate::runtime_tests::{RuntimeTest, TestResult, TestScope};
use alloc::string::String;
use core::hint::spin_loop;
use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// 1. Bounded Heavy TLB Shootdown Contention (R175 D0-CROSS-2)
// ============================================================================

mod heavy_tlb_state {
    use core::sync::atomic::AtomicU64;

    pub const VA_STRESS: u64 = 0x0000_0081_0000_0000; // PML4[1], PDPT[4], PD[0], PT[0]
    pub const VA_STRESS_AP: u64 = VA_STRESS + 0x1000; // PML4[1], PDPT[4], PD[0], PT[1]
    pub const ROUNDS: u64 = 128;
    pub const CONC_ROUNDS: u64 = 64;

    pub static SCRATCH_CR3_PHYS: AtomicU64 = AtomicU64::new(0);
    pub static PT_FRAME_PHYS: AtomicU64 = AtomicU64::new(0);
    pub static AP_FRAME_0_PHYS: AtomicU64 = AtomicU64::new(0);
    pub static AP_FRAME_1_PHYS: AtomicU64 = AtomicU64::new(0);
    // Phase 1: 0 = idle, 1..=ROUNDS = sequential BSP->AP round, u64::MAX = enter Phase 2
    pub static ROUND: AtomicU64 = AtomicU64::new(0);
    pub static AP_READY: AtomicU64 = AtomicU64::new(0);
    pub static AP_ACK_ROUND: AtomicU64 = AtomicU64::new(0);
    pub static AP_OBSERVED: AtomicU64 = AtomicU64::new(0);
    // Phase 2: overlapping concurrent BSP + AP shootdowns on VA_STRESS & VA_STRESS_AP.
    // 0 = idle, 1..=CONC_ROUNDS = active concurrent round, u64::MAX = exit
    pub static CONC_ROUND: AtomicU64 = AtomicU64::new(0);
    pub static CONC_BSP_FLUSHED: AtomicU64 = AtomicU64::new(0);
    pub static CONC_AP_FLUSHED: AtomicU64 = AtomicU64::new(0);
    pub static CONC_AP_DONE: AtomicU64 = AtomicU64::new(0);
    pub static CONC_AP_SAW_BSP: AtomicU64 = AtomicU64::new(0);
    pub static CONC_AP_SAW_OWN: AtomicU64 = AtomicU64::new(0);
    pub static AP_EXITED: AtomicU64 = AtomicU64::new(0);

    #[inline]
    pub const fn ap_sentinel(cround: u64) -> u64 {
        0xA9C2_0000_0000_0000u64 ^ cround.wrapping_mul(0xBF58_476D_1CE4_E5B9)
    }
}

fn heavy_tlb_ap_worker() {
    use heavy_tlb_state::*;
    use mm::page_table::phys_to_virt;
    use mm::tlb_shootdown::{flush_current_as_page, handle_shootdown_ipi, track_cr3_switch};
    use x86_64::registers::control::Cr3;
    use x86_64::structures::paging::{PageTable, PageTableFlags, PhysFrame, Size4KiB};
    use x86_64::{PhysAddr, VirtAddr};

    let scratch_phys = SCRATCH_CR3_PHYS.load(Ordering::Acquire);
    let pt_phys = PT_FRAME_PHYS.load(Ordering::Acquire);
    let ap_f0 = AP_FRAME_0_PHYS.load(Ordering::Acquire);
    let ap_f1 = AP_FRAME_1_PHYS.load(Ordering::Acquire);
    if scratch_phys == 0 || pt_phys == 0 || ap_f0 == 0 || ap_f1 == 0 {
        AP_EXITED.store(1, Ordering::Release);
        return;
    }

    let (saved_frame, saved_raw) = Cr3::read_raw();
    let scratch_frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(scratch_phys));

    x86_64::instructions::interrupts::without_interrupts(|| {
        track_cr3_switch(scratch_phys);
        unsafe {
            Cr3::write_raw(scratch_frame, saved_raw & 0x0FFF);
        }
    });

    // Prime TLB for both scratch pages and signal BSP we entered scratch CR3.
    let _ = unsafe { core::ptr::read_volatile(VA_STRESS as *const u64) };
    let _ = unsafe { core::ptr::read_volatile(VA_STRESS_AP as *const u64) };
    AP_READY.store(1, Ordering::Release);

    // Phase 1: BSP-initiated shootdowns (128 rounds).
    let mut last_round = 0u64;
    loop {
        let round = ROUND.load(Ordering::Acquire);
        if round == u64::MAX {
            break;
        }
        if round == last_round {
            spin_loop();
            continue;
        }
        last_round = round;
        let val = unsafe { core::ptr::read_volatile(VA_STRESS as *const u64) };
        AP_OBSERVED.store(val, Ordering::Release);
        AP_ACK_ROUND.store(round, Ordering::Release);
    }

    // Phase 2: overlapping concurrent BSP + AP shootdowns (64 rounds).
    // BSP remaps/flushes PT[0] (VA_STRESS) while AP simultaneously remaps/flushes
    // PT[1] (VA_STRESS_AP), then both CPUs verify both pages after both flushes.
    let leaf_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    let mut last_cround = 0u64;
    loop {
        let cround = CONC_ROUND.load(Ordering::Acquire);
        if cround == u64::MAX {
            break;
        }
        if cround == last_cround {
            spin_loop();
            continue;
        }
        last_cround = cround;

        let target_phys = if cround & 1 == 1 { ap_f1 } else { ap_f0 };
        let sentinel = ap_sentinel(cround);
        unsafe {
            core::ptr::write_volatile(
                phys_to_virt(PhysAddr::new(target_phys)).as_mut_ptr::<u64>(),
                sentinel,
            );
            let pt = &mut *phys_to_virt(PhysAddr::new(pt_phys)).as_mut_ptr::<PageTable>();
            pt[1].set_addr(PhysAddr::new(target_phys), leaf_flags);
        }

        // Overlapping shootdown concurrently with BSP's flush_current_as_page(VA_STRESS).
        flush_current_as_page(VirtAddr::new(VA_STRESS_AP));
        CONC_AP_FLUSHED.store(cround, Ordering::Release);

        // Wait until BSP has also finished its concurrent shootdown (or abort),
        // servicing any pending incoming shootdown IPI if IRQs are masked.
        while CONC_BSP_FLUSHED.load(Ordering::Acquire) < cround {
            x86_64::instructions::interrupts::without_interrupts(handle_shootdown_ipi);
            if CONC_ROUND.load(Ordering::Acquire) == u64::MAX {
                break;
            }
            spin_loop();
        }
        if CONC_ROUND.load(Ordering::Acquire) == u64::MAX {
            break;
        }

        let saw_own = unsafe { core::ptr::read_volatile(VA_STRESS_AP as *const u64) };
        let saw_bsp = unsafe { core::ptr::read_volatile(VA_STRESS as *const u64) };
        CONC_AP_SAW_OWN.store(saw_own, Ordering::Release);
        CONC_AP_SAW_BSP.store(saw_bsp, Ordering::Release);
        CONC_AP_DONE.store(cround, Ordering::Release);
    }

    x86_64::instructions::interrupts::without_interrupts(|| {
        track_cr3_switch(saved_frame.start_address().as_u64());
        unsafe {
            Cr3::write_raw(saved_frame, saved_raw & 0x0FFF);
        }
    });
    AP_EXITED.store(1, Ordering::Release);
}

/// Heavy TLB Shootdown Contention Test (R175 D0-CROSS-2, bounded SMP probe).
///
/// Shares a scratch user-half page table between BSP and an online AP, then
/// runs 128 alternating frame remaps + targeted `flush_current_as_page`
/// shootdowns with a unique per-round 64-bit sentinel written into each fresh
/// mapping. Asserts that after every shootdown the remote AP immediately
/// observes the exact new sentinel (zero stale reads, monotonic shootdown IPIs)
/// and frees all scratch frames only after the AP restores `BOOT_CR3`.
struct HeavyTlbShootdownContentionTest;

impl RuntimeTest for HeavyTlbShootdownContentionTest {
    fn name(&self) -> &'static str {
        "r175_heavy_tlb_contention"
    }

    // STRICT-Q S8 (D1 + D4): bounded SMP contention probe requires 2+ CPUs.
    fn scope(&self) -> TestScope {
        TestScope::NeedsCpus(2)
    }

    fn description(&self) -> &'static str {
        "R175 D0-CROSS-2: Bounded multi-CPU TLB shootdown contention and coherency oracle"
    }

    fn run(&self) -> TestResult {
        use arch::ipi::{send_ipi, IpiType};
        use arch::{current_cpu_id, max_cpus, num_online_cpus, set_ap_test_probe};
        use heavy_tlb_state::*;
        use mm::memory::FrameAllocator;
        use mm::page_table::phys_to_virt;
        use mm::tlb_shootdown::{
            flush_current_as_page, get_stats, handle_shootdown_ipi, is_cpu_online, track_cr3_switch,
        };
        use x86_64::registers::control::Cr3;
        use x86_64::structures::paging::{PageTable, PageTableFlags, PhysFrame, Size4KiB};
        use x86_64::VirtAddr;

        if num_online_cpus() <= 1 {
            return TestResult::Deferred(String::from(
                "Single-core; heavy TLB contention requires 2+ CPUs",
            ));
        }

        let self_cpu = current_cpu_id();
        let Some(target) = (0..max_cpus()).find(|&id| id != self_cpu && is_cpu_online(id)) else {
            return TestResult::Fail(String::from("No online AP found for heavy TLB contention"));
        };

        let mut allocator = FrameAllocator::new();
        let alloc_zeroed = |alloc: &mut FrameAllocator| -> Option<PhysFrame<Size4KiB>> {
            let frame = alloc.allocate_frame()?;
            let ptr = phys_to_virt(frame.start_address()).as_mut_ptr::<u8>();
            unsafe { core::ptr::write_bytes(ptr, 0, 4096) };
            Some(frame)
        };

        let Some(f0) = alloc_zeroed(&mut allocator) else {
            return TestResult::Fail(String::from("Failed to allocate F0 frame"));
        };
        let Some(f1) = alloc_zeroed(&mut allocator) else {
            allocator.deallocate_frame(f0);
            return TestResult::Fail(String::from("Failed to allocate F1 frame"));
        };
        let Some(ap_f0) = alloc_zeroed(&mut allocator) else {
            allocator.deallocate_frame(f1);
            allocator.deallocate_frame(f0);
            return TestResult::Fail(String::from("Failed to allocate AP F0 frame"));
        };
        let Some(ap_f1) = alloc_zeroed(&mut allocator) else {
            allocator.deallocate_frame(ap_f0);
            allocator.deallocate_frame(f1);
            allocator.deallocate_frame(f0);
            return TestResult::Fail(String::from("Failed to allocate AP F1 frame"));
        };
        let Some(pml4_frame) = alloc_zeroed(&mut allocator) else {
            allocator.deallocate_frame(ap_f1);
            allocator.deallocate_frame(ap_f0);
            allocator.deallocate_frame(f1);
            allocator.deallocate_frame(f0);
            return TestResult::Fail(String::from("Failed to allocate scratch PML4"));
        };
        let Some(pdpt_frame) = alloc_zeroed(&mut allocator) else {
            allocator.deallocate_frame(pml4_frame);
            allocator.deallocate_frame(ap_f1);
            allocator.deallocate_frame(ap_f0);
            allocator.deallocate_frame(f1);
            allocator.deallocate_frame(f0);
            return TestResult::Fail(String::from("Failed to allocate scratch PDPT"));
        };
        let Some(pd_frame) = alloc_zeroed(&mut allocator) else {
            allocator.deallocate_frame(pdpt_frame);
            allocator.deallocate_frame(pml4_frame);
            allocator.deallocate_frame(ap_f1);
            allocator.deallocate_frame(ap_f0);
            allocator.deallocate_frame(f1);
            allocator.deallocate_frame(f0);
            return TestResult::Fail(String::from("Failed to allocate scratch PD"));
        };
        let Some(pt_frame) = alloc_zeroed(&mut allocator) else {
            allocator.deallocate_frame(pd_frame);
            allocator.deallocate_frame(pdpt_frame);
            allocator.deallocate_frame(pml4_frame);
            allocator.deallocate_frame(ap_f1);
            allocator.deallocate_frame(ap_f0);
            allocator.deallocate_frame(f1);
            allocator.deallocate_frame(f0);
            return TestResult::Fail(String::from("Failed to allocate scratch PT"));
        };

        let (boot_frame, boot_raw) = Cr3::read_raw();
        let boot_cr3_phys = boot_frame.start_address().as_u64();
        let scratch_phys = pml4_frame.start_address().as_u64();

        // VA_STRESS = 0x0000_0081_0000_0000 -> PML4[1], PDPT[4], PD[0], PT[0]
        // VA_STRESS_AP = VA_STRESS + 0x1000 -> PML4[1], PDPT[4], PD[0], PT[1]
        let parent_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        let leaf_flags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
        unsafe {
            let boot_pml4 = &*phys_to_virt(boot_frame.start_address()).as_ptr::<PageTable>();
            let scratch_pml4 =
                &mut *phys_to_virt(pml4_frame.start_address()).as_mut_ptr::<PageTable>();
            scratch_pml4[0] = boot_pml4[0].clone();
            for i in 256..512 {
                scratch_pml4[i] = boot_pml4[i].clone();
            }
            scratch_pml4[1].set_addr(pdpt_frame.start_address(), parent_flags);

            let pdpt = &mut *phys_to_virt(pdpt_frame.start_address()).as_mut_ptr::<PageTable>();
            pdpt[4].set_addr(pd_frame.start_address(), parent_flags);

            let pd = &mut *phys_to_virt(pd_frame.start_address()).as_mut_ptr::<PageTable>();
            pd[0].set_addr(pt_frame.start_address(), parent_flags);

            let pt = &mut *phys_to_virt(pt_frame.start_address()).as_mut_ptr::<PageTable>();
            pt[0].set_addr(f0.start_address(), leaf_flags);
            pt[1].set_addr(ap_f0.start_address(), leaf_flags);

            core::ptr::write_volatile(
                phys_to_virt(f0.start_address()).as_mut_ptr::<u64>(),
                0x5A5A_0000_0000_0000,
            );
            core::ptr::write_volatile(
                phys_to_virt(ap_f0.start_address()).as_mut_ptr::<u64>(),
                0xA5A5_0000_0000_0000,
            );
        }

        x86_64::instructions::interrupts::without_interrupts(|| {
            track_cr3_switch(scratch_phys);
            unsafe {
                Cr3::write_raw(pml4_frame, boot_raw & 0x0FFF);
            }
        });

        AP_READY.store(0, Ordering::Release);
        AP_ACK_ROUND.store(0, Ordering::Release);
        AP_OBSERVED.store(0, Ordering::Release);
        CONC_ROUND.store(0, Ordering::Release);
        CONC_BSP_FLUSHED.store(0, Ordering::Release);
        CONC_AP_FLUSHED.store(0, Ordering::Release);
        CONC_AP_DONE.store(0, Ordering::Release);
        CONC_AP_SAW_BSP.store(0, Ordering::Release);
        CONC_AP_SAW_OWN.store(0, Ordering::Release);
        AP_EXITED.store(0, Ordering::Release);
        ROUND.store(0, Ordering::Release);
        PT_FRAME_PHYS.store(pt_frame.start_address().as_u64(), Ordering::Release);
        AP_FRAME_0_PHYS.store(ap_f0.start_address().as_u64(), Ordering::Release);
        AP_FRAME_1_PHYS.store(ap_f1.start_address().as_u64(), Ordering::Release);
        SCRATCH_CR3_PHYS.store(scratch_phys, Ordering::Release);

        let mut ap_may_hold_scratch = true;
        let _ = set_ap_test_probe(target, Some(heavy_tlb_ap_worker));
        send_ipi(target, IpiType::Reschedule);

        let outcome: Result<(), String> = (|| {
            let mut ready = false;
            for _ in 0..100_000_000usize {
                if AP_READY.load(Ordering::Acquire) != 0 {
                    ready = true;
                    break;
                }
                spin_loop();
            }
            if !ready {
                return Err(alloc::format!(
                    "AP {} timed out entering scratch CR3",
                    target
                ));
            }

            let stats_before = get_stats();
            for round in 1..=ROUNDS {
                let target_frame = if round & 1 == 1 { f1 } else { f0 };
                let sentinel =
                    0xD0C2_0000_0000_0000u64 ^ (round.wrapping_mul(0x9E37_79B9_7F4A_7C15));
                unsafe {
                    core::ptr::write_volatile(
                        phys_to_virt(target_frame.start_address()).as_mut_ptr::<u64>(),
                        sentinel,
                    );
                    let pt = &mut *phys_to_virt(pt_frame.start_address()).as_mut_ptr::<PageTable>();
                    pt[0].set_addr(target_frame.start_address(), leaf_flags);
                }

                flush_current_as_page(VirtAddr::new(VA_STRESS));

                // Verify local CPU observes updated mapping after shootdown.
                let local = unsafe { core::ptr::read_volatile(VA_STRESS as *const u64) };
                if local != sentinel {
                    return Err(alloc::format!(
                        "BSP stale TLB read on round {}: got {:#x}, expected {:#x}",
                        round,
                        local,
                        sentinel
                    ));
                }

                // Signal AP to read VA_STRESS and verify remote coherency.
                ROUND.store(round, Ordering::Release);
                let mut acked = false;
                for _ in 0..100_000_000usize {
                    if AP_ACK_ROUND.load(Ordering::Acquire) == round {
                        acked = true;
                        break;
                    }
                    spin_loop();
                }
                if !acked {
                    return Err(alloc::format!(
                        "AP {} timed out acknowledging round {}",
                        target,
                        round
                    ));
                }
                let observed = AP_OBSERVED.load(Ordering::Acquire);
                if observed != sentinel {
                    return Err(alloc::format!(
                        "AP {} stale TLB read on round {}: got {:#x}, expected {:#x}",
                        target,
                        round,
                        observed,
                        sentinel
                    ));
                }
            }

            // Phase 2: overlapping concurrent shootdown requests from BOTH BSP
            // (VA_STRESS / PT[0]) and AP (VA_STRESS_AP / PT[1]) to catch lost
            // acknowledgements between concurrent senders.
            ROUND.store(u64::MAX, Ordering::Release);
            for cround in 1..=CONC_ROUNDS {
                let target_frame = if cround & 1 == 1 { f1 } else { f0 };
                let bsp_sentinel =
                    0xB5C2_0000_0000_0000u64 ^ cround.wrapping_mul(0x9E37_79B9_7F4A_7C15);
                let exp_ap = ap_sentinel(cround);
                unsafe {
                    core::ptr::write_volatile(
                        phys_to_virt(target_frame.start_address()).as_mut_ptr::<u64>(),
                        bsp_sentinel,
                    );
                    let pt = &mut *phys_to_virt(pt_frame.start_address()).as_mut_ptr::<PageTable>();
                    pt[0].set_addr(target_frame.start_address(), leaf_flags);
                }

                // Release AP so both CPUs issue flush_current_as_page concurrently.
                CONC_ROUND.store(cround, Ordering::Release);
                flush_current_as_page(VirtAddr::new(VA_STRESS));
                CONC_BSP_FLUSHED.store(cround, Ordering::Release);

                // Wait until AP also completes its overlapping shootdown.
                // Boot-time BSP tests run with IF=0, so drain BSP's shootdown
                // mailbox while spinning to ACK AP's overlapping shootdown IPI.
                let mut ap_flushed = false;
                for _ in 0..100_000_000usize {
                    x86_64::instructions::interrupts::without_interrupts(handle_shootdown_ipi);
                    if CONC_AP_FLUSHED.load(Ordering::Acquire) == cround {
                        ap_flushed = true;
                        break;
                    }
                    spin_loop();
                }
                if !ap_flushed {
                    return Err(alloc::format!(
                        "AP {} timed out completing concurrent shootdown round {}",
                        target,
                        cround
                    ));
                }

                // Verify BSP sees BOTH its own remap and AP's concurrent remap.
                let bsp_saw_own = unsafe { core::ptr::read_volatile(VA_STRESS as *const u64) };
                let bsp_saw_ap = unsafe { core::ptr::read_volatile(VA_STRESS_AP as *const u64) };
                if bsp_saw_own != bsp_sentinel {
                    return Err(alloc::format!(
                        "BSP stale own TLB read on concurrent round {}: got {:#x}, expected {:#x}",
                        cround,
                        bsp_saw_own,
                        bsp_sentinel
                    ));
                }
                if bsp_saw_ap != exp_ap {
                    return Err(alloc::format!(
                        "BSP stale AP-page TLB read on concurrent round {}: got {:#x}, expected {:#x}",
                        cround,
                        bsp_saw_ap,
                        exp_ap
                    ));
                }

                // Wait for AP to verify BOTH mappings as well.
                let mut ap_done = false;
                for _ in 0..100_000_000usize {
                    if CONC_AP_DONE.load(Ordering::Acquire) == cround {
                        ap_done = true;
                        break;
                    }
                    spin_loop();
                }
                if !ap_done {
                    return Err(alloc::format!(
                        "AP {} timed out verifying concurrent round {}",
                        target,
                        cround
                    ));
                }
                let ap_saw_own = CONC_AP_SAW_OWN.load(Ordering::Acquire);
                let ap_saw_bsp = CONC_AP_SAW_BSP.load(Ordering::Acquire);
                if ap_saw_own != exp_ap {
                    return Err(alloc::format!(
                        "AP {} stale own TLB read on concurrent round {}: got {:#x}, expected {:#x}",
                        target,
                        cround,
                        ap_saw_own,
                        exp_ap
                    ));
                }
                if ap_saw_bsp != bsp_sentinel {
                    return Err(alloc::format!(
                        "AP {} stale BSP-page TLB read on concurrent round {}: got {:#x}, expected {:#x}",
                        target,
                        cround,
                        ap_saw_bsp,
                        bsp_sentinel
                    ));
                }
            }

            let stats_after = get_stats();
            let ipi_delta = stats_after.shootdown_ipis - stats_before.shootdown_ipis;
            let expected_ipis = ROUNDS + 2 * CONC_ROUNDS;
            if ipi_delta < expected_ipis {
                return Err(alloc::format!(
                    "expected >= {} shootdown IPIs, observed {}",
                    expected_ipis,
                    ipi_delta
                ));
            }
            Ok(())
        })();

        ROUND.store(u64::MAX, Ordering::Release);
        CONC_ROUND.store(u64::MAX, Ordering::Release);
        let cancelled = set_ap_test_probe(target, None);
        if cancelled {
            ap_may_hold_scratch = false;
        } else {
            for _ in 0..100_000_000usize {
                if AP_EXITED.load(Ordering::Acquire) != 0 {
                    ap_may_hold_scratch = false;
                    break;
                }
                spin_loop();
            }
        }
        SCRATCH_CR3_PHYS.store(0, Ordering::Release);
        PT_FRAME_PHYS.store(0, Ordering::Release);
        AP_FRAME_0_PHYS.store(0, Ordering::Release);
        AP_FRAME_1_PHYS.store(0, Ordering::Release);

        x86_64::instructions::interrupts::without_interrupts(|| {
            track_cr3_switch(boot_cr3_phys);
            unsafe {
                Cr3::write_raw(boot_frame, boot_raw & 0x0FFF);
            }
        });

        if !ap_may_hold_scratch {
            allocator.deallocate_frame(pt_frame);
            allocator.deallocate_frame(pd_frame);
            allocator.deallocate_frame(pdpt_frame);
            allocator.deallocate_frame(pml4_frame);
            allocator.deallocate_frame(ap_f1);
            allocator.deallocate_frame(ap_f0);
            allocator.deallocate_frame(f1);
            allocator.deallocate_frame(f0);
        } else {
            return TestResult::Fail(alloc::format!(
                "AP {} timed out restoring BOOT_CR3 (retained scratch frames to avoid UAF)",
                target
            ));
        }

        match outcome {
            Ok(()) => TestResult::Pass,
            Err(msg) => TestResult::Fail(msg),
        }
    }
}

// ============================================================================
// 2. Rapid Signal Delivery During Task Migration (R175 D0-CROSS-1, Ring-3)
// ============================================================================

/// Rapid Signal Delivery During Task Migration Test (R175 D0-CROSS-1).
///
/// Covered by the Ring-3 `test_rapid_signal_migration` leg in `ring3-mm`, which
/// delivers real `SIGUSR1` handlers on an mmap'd stack while migrating the
/// target thread across online CPUs via `sched_setaffinity` and verifying
/// register canary preservation.
struct RapidSignalMigrationContentionTest;

impl RuntimeTest for RapidSignalMigrationContentionTest {
    fn name(&self) -> &'static str {
        "r175_rapid_signal_migration"
    }

    // STRICT-Q S8 (D5): real Ring-3 signal + cross-CPU migration leg verified by ring3-mm.
    fn scope(&self) -> TestScope {
        TestScope::CoveredBy {
            gate: "ring3-mm",
            marker: "rapid signal delivery during cross-CPU task migration preserves registers and handler state",
        }
    }

    fn description(&self) -> &'static str {
        "R175 D0-CROSS-1: Concurrent signals + task migration (Ring-3 leg)"
    }

    fn run(&self) -> TestResult {
        TestResult::Deferred(String::from(
            "Covered by Ring-3 concurrent signal + CPU migration leg in ring3-mm",
        ))
    }
}

// ============================================================================
// 3. Namespace Teardown Storm (R175 D0-CROSS-3, Ring-3)
// ============================================================================

/// Namespace Teardown Storm Test (R175 D0-CROSS-3).
///
/// Covered by the Ring-3 `test_namespace_teardown_storm` leg in `ring3-mm`,
/// which repeatedly runs `unshare(CLONE_NEWPID)`, forks a namespace-init with
/// stopped (`SIGSTOP`) and running descendants, and sends `SIGKILL` to the
/// namespace-init to verify cascade teardown and clean scheduler reaping.
struct NamespaceTeardownStormTest;

impl RuntimeTest for NamespaceTeardownStormTest {
    fn name(&self) -> &'static str {
        "r175_namespace_teardown_storm"
    }

    // STRICT-Q S8 (D5): real Ring-3 CLONE_NEWPID init SIGKILL cascade storm verified by ring3-mm.
    fn scope(&self) -> TestScope {
        TestScope::CoveredBy {
            gate: "ring3-mm",
            marker: "namespace teardown storm: unshare CLONE_NEWPID init SIGKILL cascades to stopped and running members across waves",
        }
    }

    fn description(&self) -> &'static str {
        "R175 D0-CROSS-3: Concurrent namespace teardown storm (Ring-3 leg)"
    }

    fn run(&self) -> TestResult {
        TestResult::Deferred(String::from(
            "Covered by Ring-3 CLONE_NEWPID SIGKILL cascade storm leg in ring3-mm",
        ))
    }
}

// ============================================================================
// 4. Combined Extended Runtime Stress Test (COVERED-BY STRESS-7, Decision D4)
// ============================================================================

/// Combined Multi-Hour Stress Test — covered by the external STRESS-7 gate.
struct ExtendedRuntimeStressTest;

impl RuntimeTest for ExtendedRuntimeStressTest {
    fn name(&self) -> &'static str {
        "r175_extended_runtime_1hour"
    }

    // STRICT-Q S3 (D4 + D5): sustained multi-profile stress covered by full STRESS-7.
    fn scope(&self) -> TestScope {
        TestScope::CoveredBy {
            gate: "stress",
            marker: "STRESS-7 FULL-SUITE STABLE: 7/7 profiles duration>=900s cpus>=4",
        }
    }

    fn description(&self) -> &'static str {
        "R175 Combined: All D0 fixes under 1-hour sustained load"
    }

    fn run(&self) -> TestResult {
        use arch::num_online_cpus;

        let cpus = num_online_cpus();
        if cpus < 4 {
            return TestResult::Deferred(String::from(
                "Extended runtime stress test requires 4+ CPUs",
            ));
        }

        // Covered by STRESS-7 (`scripts/gates/stress/stress_test.sh`).
        TestResult::Deferred(String::from(
            "Covered by external STRESS-7 sustained multi-profile stress gate",
        ))
    }
}

/// Register all heavy contention and extended runtime tests
pub fn get_all_heavy_stress_tests(
) -> alloc::vec::Vec<&'static dyn crate::runtime_tests::RuntimeTest> {
    alloc::vec![
        &HeavyTlbShootdownContentionTest,
        &RapidSignalMigrationContentionTest,
        &NamespaceTeardownStormTest,
        &ExtendedRuntimeStressTest,
    ]
}
