//! P0 Security-Critical Regression Tests
//!
//! This module registers 25 checks for R172-R174 QA findings; individual cases may be deferred.
//! These tests validate critical kernel subsystems that can lead to privilege
//! escalation, data corruption, or system instability if broken.
//!
//! # Test Categories
//!
//! 1. **Architecture Tests (5)**: Context switch, TLS isolation, IRQ state
//! 2. **Memory Management Tests (5)**: COW, TLB shootdown, PT charge tracking
//! 3. **IPC Tests (5)**: Futex correctness, signals, pipes
//! 4. **Scheduler Tests (5)**: Work stealing, migration, CPU affinity
//! 5. **VFS Tests (5)**: RAMFS operations, rename safety, path resolution
//!
//! # Implementation Status
//!
//! Each check reports its actual execution status and any missing workload or prerequisite.

extern crate alloc;

use crate::runtime_tests::{RuntimeTest, TestResult, TestScope};
use alloc::string::String;
use alloc::vec::Vec;

// ============================================================================
// CATEGORY 1: ARCHITECTURE TESTS (5 tests)
// ============================================================================

/// R172-01: Verifies that RIP and RFLAGS are correctly saved and restored
/// across context switches. Regression test for privilege escalation bug where
/// save_context() omitted these registers, causing child processes to resume
/// in Ring 0 at the parent's instruction pointer.
struct ContextSwitchRipRflagsTest;

impl RuntimeTest for ContextSwitchRipRflagsTest {
    fn name(&self) -> &'static str {
        "r172_01_context_switch_rip_rflags"
    }

    fn description(&self) -> &'static str {
        "R172-01: Verify RIP/RFLAGS/CS/SS preserved across clone+yield (prevents privilege escalation)"
    }

    fn run(&self) -> TestResult {
        TestResult::Deferred(String::from(
            "The named guest regression workload and assertion oracle are not implemented",
        ))
    }
}

/// R172-04: Verifies that FS_BASE and GS_BASE segment registers maintain
/// proper isolation across process context switches. Without correct save/restore,
/// TLS data can leak between processes, causing data corruption.
struct TlsIsolationTest;

impl RuntimeTest for TlsIsolationTest {
    fn name(&self) -> &'static str {
        "r172_04_tls_isolation"
    }

    fn description(&self) -> &'static str {
        "R172-04: Verify FS_BASE/GS_BASE TLS isolation across context switches"
    }

    fn run(&self) -> TestResult {
        TestResult::Deferred(String::from(
            "The named guest regression workload and assertion oracle are not implemented",
        ))
    }
}

/// R172-05: Verifies that the per-CPU syscall_active flag is properly cleared
/// on context switch. If leaked, subsequent syscalls on that CPU return EBUSY,
/// effectively wedging the CPU for userspace.
struct SyscallActiveLeakTest;

impl RuntimeTest for SyscallActiveLeakTest {
    fn name(&self) -> &'static str {
        "r172_05_syscall_active_leak"
    }

    fn description(&self) -> &'static str {
        "R172-05: Verify syscall_active per-CPU flag cleared on switch_out"
    }

    fn run(&self) -> TestResult {
        use arch::max_cpus;

        // Verify per-CPU infrastructure exists
        let cpu_id = arch::current_cpu_id();

        // This is a compile-time / boot-time structural test
        // Runtime testing requires process creation (deferred)

        let max = max_cpus();
        if cpu_id >= max {
            return TestResult::Fail(alloc::format!(
                "Invalid CPU ID: {} >= max_cpus() ({})",
                cpu_id,
                max
            ));
        }

        TestResult::Deferred(String::from(
            "Per-CPU infrastructure validated; full test requires process context switching",
        ))
    }
}

/// R172-03: Verifies that the scheduler's work-stealing logic correctly checks
/// the on_cpu and switch_in_progress flags before stealing a task. Without these
/// guards, a task can be stolen and executed on CPU B before its context is fully
/// saved on CPU A, causing register corruption or double-execution.
struct WorkStealingOnCpuGateTest;

impl RuntimeTest for WorkStealingOnCpuGateTest {
    fn name(&self) -> &'static str {
        "r172_03_work_stealing_on_cpu_gate"
    }

    fn description(&self) -> &'static str {
        "R172-03: Verify on_cpu gate prevents steal-before-context-save race"
    }

    fn run(&self) -> TestResult {
        use arch::num_online_cpus;

        // Verify SMP is configured
        let num_cpus = num_online_cpus();
        if num_cpus < 2 {
            return TestResult::Deferred(String::from(
                "Work-stealing test requires 2+ CPUs (only 1 online)",
            ));
        }

        TestResult::Deferred(alloc::format!(
            "SMP configured ({} CPUs); full test requires process stress testing",
            num_cpus
        ))
    }
}

/// R174-A1: Verifies that FPU state is properly saved and isolated when a timer
/// IRQ interrupts a process. Without proper FPU context save in the IRQ path,
/// nested IRQs or preemption can corrupt floating-point registers.
struct FpuStateIrqIsolationTest;

impl RuntimeTest for FpuStateIrqIsolationTest {
    fn name(&self) -> &'static str {
        "r174_a1_fpu_state_irq_isolation"
    }

    fn description(&self) -> &'static str {
        "R174-A1: Verify FPU state isolation during timer IRQ nesting"
    }

    fn run(&self) -> TestResult {
        // Verify FPU is available - architecture dependent check
        // Most x86-64 systems have FPU, this is a placeholder for actual check

        // Test FPU state save/restore infrastructure exists
        // Full test requires IRQ injection during FPU operations (deferred)

        TestResult::Deferred(String::from(
            "FPU subsystem placeholder; full isolation test requires IRQ simulation",
        ))
    }
}

// ============================================================================
// CATEGORY 2: MEMORY MANAGEMENT TESTS (5 tests)
// ============================================================================

/// Shared SMP state for `r23_1_cow_tlb_shootdown` (STRICT-Q S5).
mod cow_tlb_state {
    use core::sync::atomic::AtomicU64;

    // Distinct user-half VA from `heavy_stress::heavy_tlb_state::VA_STRESS`
    // (0x0000_0081_0000_0000): PML4[1], PDPT[8], PD[0], PT[0].
    pub const VA_COW: u64 = 0x0000_0082_0000_0000;
    pub const ROUNDS: u64 = 16;

    pub static SCRATCH_CR3_PHYS: AtomicU64 = AtomicU64::new(0);
    // Monotonic command counter: odd = (2*r - 1) prime RO TLB on shared frame;
    // even = (2*r) verify post-COW RW remap on private frame & write AP sentinel;
    // u64::MAX = exit worker and restore BOOT_CR3.
    pub static STEP: AtomicU64 = AtomicU64::new(0);
    pub static AP_READY: AtomicU64 = AtomicU64::new(0);
    pub static AP_ACK_STEP: AtomicU64 = AtomicU64::new(0);
    pub static AP_OBSERVED: AtomicU64 = AtomicU64::new(0);
    pub static AP_WRITE_VAL: AtomicU64 = AtomicU64::new(0);
    // Monotonic per-invocation run IDs (never reset to 0) so a late exit from a
    // timed-out AP callback can never satisfy a subsequent rerun's exit check.
    pub static ACTIVE_RUN_ID: AtomicU64 = AtomicU64::new(0);
    pub static EXITED_RUN_ID: AtomicU64 = AtomicU64::new(0);
}

fn cow_tlb_ap_worker() {
    use core::hint::spin_loop;
    use core::sync::atomic::Ordering;
    use cow_tlb_state::*;
    use mm::tlb_shootdown::track_cr3_switch;
    use x86_64::registers::control::Cr3;
    use x86_64::structures::paging::{PhysFrame, Size4KiB};
    use x86_64::PhysAddr;

    let my_run_id = ACTIVE_RUN_ID.load(Ordering::Acquire);
    let scratch_phys = SCRATCH_CR3_PHYS.load(Ordering::Acquire);
    if scratch_phys == 0 {
        EXITED_RUN_ID.store(my_run_id, Ordering::Release);
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

    // Prime TLB with initial read-only mapping and notify BSP.
    let _ = unsafe { core::ptr::read_volatile(VA_COW as *const u64) };
    AP_READY.store(1, Ordering::Release);

    let mut last_step = 0u64;
    loop {
        let step = STEP.load(Ordering::Acquire);
        if step == u64::MAX {
            break;
        }
        if step == last_step {
            spin_loop();
            continue;
        }
        last_step = step;

        let val = unsafe { core::ptr::read_volatile(VA_COW as *const u64) };
        AP_OBSERVED.store(val, Ordering::Release);

        // Even steps follow a COW RO->RW remap + shootdown: write through VA_COW
        // to prove stale RO TLB permissions were invalidated and the write lands
        // exclusively in the new private frame.
        if step & 1 == 0 {
            let write_val = AP_WRITE_VAL.load(Ordering::Acquire);
            unsafe {
                core::ptr::write_volatile(VA_COW as *mut u64, write_val);
            }
        }
        AP_ACK_STEP.store(step, Ordering::Release);
    }

    x86_64::instructions::interrupts::without_interrupts(|| {
        track_cr3_switch(saved_frame.start_address().as_u64());
        unsafe {
            Cr3::write_raw(saved_frame, saved_raw & 0x0FFF);
        }
    });
    EXITED_RUN_ID.store(my_run_id, Ordering::Release);
}

/// R23-1: Verifies that TLB shootdown IPIs are sent to all CPUs when a COW
/// page is modified. Without proper shootdown, remote CPUs cache stale TLB
/// entries pointing to the old (shared) physical frame, allowing reads or
/// writes to bypass copy-on-write isolation.
struct CowTlbShootdownTest;

impl RuntimeTest for CowTlbShootdownTest {
    fn name(&self) -> &'static str {
        "r23_1_cow_tlb_shootdown"
    }

    // STRICT-Q S5 (D1): cross-CPU COW TLB shootdown requires 2+ online CPUs.
    fn scope(&self) -> TestScope {
        TestScope::NeedsCpus(2)
    }

    fn description(&self) -> &'static str {
        "R23-1: Verify TLB shootdown on COW modification (prevents stale permission bypass)"
    }

    fn run(&self) -> TestResult {
        use arch::ipi::{send_ipi, IpiType};
        use arch::{current_cpu_id, max_cpus, num_online_cpus, set_ap_test_probe};
        use core::hint::spin_loop;
        use core::sync::atomic::Ordering;
        use cow_tlb_state::*;
        use mm::memory::FrameAllocator;
        use mm::page_table::phys_to_virt;
        use mm::tlb_shootdown::{
            flush_current_as_page, get_stats, handle_shootdown_ipi, is_cpu_online, track_cr3_switch,
        };
        use x86_64::registers::control::Cr3;
        use x86_64::structures::paging::{PageTable, PageTableFlags, PhysFrame, Size4KiB};
        use x86_64::VirtAddr;

        if num_online_cpus() < 2 {
            return TestResult::Deferred(String::from(
                "TLB shootdown test requires 2+ CPUs (only 1 online)",
            ));
        }

        let self_cpu = current_cpu_id();
        let Some(target) = (0..max_cpus()).find(|&id| id != self_cpu && is_cpu_online(id)) else {
            return TestResult::Fail(String::from("No online AP found for COW TLB shootdown"));
        };

        // Never reuse shared COW probe state while an earlier timed-out AP
        // callback has not yet acknowledged exit.
        if ACTIVE_RUN_ID.load(Ordering::Acquire) != EXITED_RUN_ID.load(Ordering::Acquire) {
            return TestResult::Fail(String::from(
                "previous COW TLB shootdown AP callback has not exited yet",
            ));
        }

        let mut allocator = FrameAllocator::new();
        let alloc_zeroed = |alloc: &mut FrameAllocator| -> Option<PhysFrame<Size4KiB>> {
            let frame = alloc.allocate_frame()?;
            let ptr = phys_to_virt(frame.start_address()).as_mut_ptr::<u8>();
            unsafe { core::ptr::write_bytes(ptr, 0, 4096) };
            Some(frame)
        };

        let Some(shared_frame) = alloc_zeroed(&mut allocator) else {
            return TestResult::Fail(String::from("Failed to allocate COW shared frame"));
        };
        let Some(private_frame) = alloc_zeroed(&mut allocator) else {
            allocator.deallocate_frame(shared_frame);
            return TestResult::Fail(String::from("Failed to allocate COW private frame"));
        };
        let Some(pml4_frame) = alloc_zeroed(&mut allocator) else {
            allocator.deallocate_frame(private_frame);
            allocator.deallocate_frame(shared_frame);
            return TestResult::Fail(String::from("Failed to allocate COW scratch PML4"));
        };
        let Some(pdpt_frame) = alloc_zeroed(&mut allocator) else {
            allocator.deallocate_frame(pml4_frame);
            allocator.deallocate_frame(private_frame);
            allocator.deallocate_frame(shared_frame);
            return TestResult::Fail(String::from("Failed to allocate COW scratch PDPT"));
        };
        let Some(pd_frame) = alloc_zeroed(&mut allocator) else {
            allocator.deallocate_frame(pdpt_frame);
            allocator.deallocate_frame(pml4_frame);
            allocator.deallocate_frame(private_frame);
            allocator.deallocate_frame(shared_frame);
            return TestResult::Fail(String::from("Failed to allocate COW scratch PD"));
        };
        let Some(pt_frame) = alloc_zeroed(&mut allocator) else {
            allocator.deallocate_frame(pd_frame);
            allocator.deallocate_frame(pdpt_frame);
            allocator.deallocate_frame(pml4_frame);
            allocator.deallocate_frame(private_frame);
            allocator.deallocate_frame(shared_frame);
            return TestResult::Fail(String::from("Failed to allocate COW scratch PT"));
        };

        let (boot_frame, boot_raw) = Cr3::read_raw();
        let boot_cr3_phys = boot_frame.start_address().as_u64();
        let scratch_phys = pml4_frame.start_address().as_u64();

        // VA_COW = 0x0000_0082_0000_0000 -> PML4[1], PDPT[8], PD[0], PT[0]
        let parent_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        let ro_cow_flags = PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE;
        let rw_private_flags =
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
            pdpt[8].set_addr(pd_frame.start_address(), parent_flags);

            let pd = &mut *phys_to_virt(pd_frame.start_address()).as_mut_ptr::<PageTable>();
            pd[0].set_addr(pt_frame.start_address(), parent_flags);

            let pt = &mut *phys_to_virt(pt_frame.start_address()).as_mut_ptr::<PageTable>();
            pt[0].set_addr(shared_frame.start_address(), ro_cow_flags);

            core::ptr::write_volatile(
                phys_to_virt(shared_frame.start_address()).as_mut_ptr::<u64>(),
                0xC000_0000_0000_0001,
            );
        }

        x86_64::instructions::interrupts::without_interrupts(|| {
            track_cr3_switch(scratch_phys);
            unsafe {
                Cr3::write_raw(pml4_frame, boot_raw & 0x0FFF);
            }
        });

        AP_READY.store(0, Ordering::Release);
        AP_ACK_STEP.store(0, Ordering::Release);
        AP_OBSERVED.store(0, Ordering::Release);
        AP_WRITE_VAL.store(0, Ordering::Release);
        STEP.store(0, Ordering::Release);
        SCRATCH_CR3_PHYS.store(scratch_phys, Ordering::Release);
        let run_id = ACTIVE_RUN_ID.fetch_add(1, Ordering::AcqRel) + 1;

        let mut ap_may_hold_scratch = true;
        let _ = set_ap_test_probe(target, Some(cow_tlb_ap_worker));
        send_ipi(target, IpiType::Reschedule);

        let wait_ap_step = |expected_step: u64| -> bool {
            for _ in 0..100_000_000usize {
                if AP_ACK_STEP.load(Ordering::Acquire) == expected_step {
                    return true;
                }
                spin_loop();
            }
            false
        };

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
                    "AP {} timed out entering COW scratch CR3",
                    target
                ));
            }

            let stats_before = get_stats();
            for round in 1..=ROUNDS {
                let old_pattern =
                    0xC05A_0000_0000_0000u64 ^ round.wrapping_mul(0x9E37_79B9_7F4A_7C15);
                let new_pattern =
                    0xC0A5_0000_0000_0000u64 ^ round.wrapping_mul(0xBF58_476D_1CE4_E5B9);
                let ap_write = 0xC0F0_0000_0000_0000u64 ^ round.wrapping_mul(0x94D0_49BB_1331_11EB);

                // Phase A (fork COW arm): map VA_COW read-only to shared_frame
                // and shoot down remote TLBs so AP populates a fresh RO entry.
                unsafe {
                    core::ptr::write_volatile(
                        phys_to_virt(shared_frame.start_address()).as_mut_ptr::<u64>(),
                        old_pattern,
                    );
                    let pt = &mut *phys_to_virt(pt_frame.start_address()).as_mut_ptr::<PageTable>();
                    pt[0].set_addr(shared_frame.start_address(), ro_cow_flags);
                }
                flush_current_as_page(VirtAddr::new(VA_COW));

                let ro_step = 2 * round - 1;
                STEP.store(ro_step, Ordering::Release);
                if !wait_ap_step(ro_step) {
                    return Err(alloc::format!(
                        "AP {} timed out priming RO COW TLB on round {}",
                        target,
                        round
                    ));
                }
                let ap_saw_ro = AP_OBSERVED.load(Ordering::Acquire);
                if ap_saw_ro != old_pattern {
                    return Err(alloc::format!(
                        "AP {} stale TLB read on RO arm round {}: got {:#x}, expected {:#x}",
                        target,
                        round,
                        ap_saw_ro,
                        old_pattern
                    ));
                }

                // Phase B (COW break): populate private_frame, replace PTE with
                // writable private_frame, and issue targeted TLB shootdown.
                unsafe {
                    core::ptr::write_volatile(
                        phys_to_virt(private_frame.start_address()).as_mut_ptr::<u64>(),
                        new_pattern,
                    );
                    let pt = &mut *phys_to_virt(pt_frame.start_address()).as_mut_ptr::<PageTable>();
                    pt[0].set_addr(private_frame.start_address(), rw_private_flags);
                }
                flush_current_as_page(VirtAddr::new(VA_COW));

                let local_after = unsafe { core::ptr::read_volatile(VA_COW as *const u64) };
                if local_after != new_pattern {
                    return Err(alloc::format!(
                        "BSP stale TLB read after COW break round {}: got {:#x}, expected {:#x}",
                        round,
                        local_after,
                        new_pattern
                    ));
                }

                // AP reads VA_COW (must see new_pattern, never stale old_pattern)
                // and writes ap_write through the newly writable PTE.
                AP_WRITE_VAL.store(ap_write, Ordering::Release);
                let rw_step = 2 * round;
                STEP.store(rw_step, Ordering::Release);
                if !wait_ap_step(rw_step) {
                    return Err(alloc::format!(
                        "AP {} timed out verifying COW break on round {}",
                        target,
                        round
                    ));
                }
                let ap_saw_rw = AP_OBSERVED.load(Ordering::Acquire);
                if ap_saw_rw != new_pattern {
                    return Err(alloc::format!(
                        "AP {} stale TLB read after COW shootdown round {}: got {:#x}, expected {:#x}",
                        target,
                        round,
                        ap_saw_rw,
                        new_pattern
                    ));
                }

                let priv_after = unsafe {
                    core::ptr::read_volatile(
                        phys_to_virt(private_frame.start_address()).as_ptr::<u64>(),
                    )
                };
                let shared_after = unsafe {
                    core::ptr::read_volatile(
                        phys_to_virt(shared_frame.start_address()).as_ptr::<u64>(),
                    )
                };
                if priv_after != ap_write {
                    return Err(alloc::format!(
                        "COW private frame missed AP write on round {}: got {:#x}, expected {:#x}",
                        round,
                        priv_after,
                        ap_write
                    ));
                }
                if shared_after != old_pattern {
                    return Err(alloc::format!(
                        "COW isolation breach on round {}: shared frame mutated to {:#x}, expected {:#x}",
                        round,
                        shared_after,
                        old_pattern
                    ));
                }
            }

            let stats_after = get_stats();
            let ipi_delta = stats_after.shootdown_ipis - stats_before.shootdown_ipis;
            let expected_ipis = 2 * ROUNDS;
            if ipi_delta < expected_ipis {
                return Err(alloc::format!(
                    "expected >= {} COW shootdown IPIs, observed {}",
                    expected_ipis,
                    ipi_delta
                ));
            }
            Ok(())
        })();

        STEP.store(u64::MAX, Ordering::Release);
        let cancelled = set_ap_test_probe(target, None);
        if cancelled {
            EXITED_RUN_ID.store(run_id, Ordering::Release);
            ap_may_hold_scratch = false;
        } else {
            for _ in 0..100_000_000usize {
                x86_64::instructions::interrupts::without_interrupts(handle_shootdown_ipi);
                if EXITED_RUN_ID.load(Ordering::Acquire) == run_id {
                    ap_may_hold_scratch = false;
                    break;
                }
                spin_loop();
            }
        }
        SCRATCH_CR3_PHYS.store(0, Ordering::Release);

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
            allocator.deallocate_frame(private_frame);
            allocator.deallocate_frame(shared_frame);
        } else {
            return TestResult::Fail(alloc::format!(
                "AP {} timed out restoring BOOT_CR3 (retained COW scratch frames to avoid UAF)",
                target
            ));
        }

        match outcome {
            Ok(()) => TestResult::Pass,
            Err(msg) => TestResult::Fail(msg),
        }
    }
}

/// R174-B3: Verifies that page table charge tracking maintains symmetry between
/// allocations and deallocations. Untracked PT frames bypass cgroup memory limits,
/// allowing privilege escalation via unbounded kernel memory consumption.
struct PtChargeTrackingTest;

impl RuntimeTest for PtChargeTrackingTest {
    fn name(&self) -> &'static str {
        "r174_b3_pt_charge_tracking"
    }

    // STRICT-Q S3 (D5): exact memory.current and pruned PT charge symmetry verified in ring3-mm.
    fn scope(&self) -> TestScope {
        TestScope::CoveredBy {
            gate: "ring3-mm",
            marker:
                "private rollback beside a shared-fault page table: exact ENOMEM and memory.current",
        }
    }

    fn description(&self) -> &'static str {
        "R174-B3: Verify page table frame charge/uncharge symmetry"
    }

    fn run(&self) -> TestResult {
        use mm::buddy_allocator;

        // Verify buddy allocator is initialized
        let stats = match buddy_allocator::get_allocator_stats() {
            Some(s) => s,
            None => {
                return TestResult::Fail(String::from("Buddy allocator not initialized"));
            }
        };

        // Basic sanity check
        if stats.total_pages == 0 {
            return TestResult::Fail(String::from("Buddy allocator reports 0 total pages"));
        }

        TestResult::Deferred(String::from(
            "Buddy allocator operational; full PT charge test requires mmap/munmap operations",
        ))
    }
}

/// R174-B4: Verifies that brk() VA reservation checks are atomic and prevent
/// TOCTOU races where concurrent brk() calls can create overlapping regions,
/// leading to heap corruption.
struct BrkVaReservationToctouTest;

impl RuntimeTest for BrkVaReservationToctouTest {
    fn name(&self) -> &'static str {
        "r174_b4_brk_va_reservation_toctou"
    }

    // STRICT-Q S5 (D5): Ring-3 concurrent CLONE_VM brk + MAP_FIXED_NOREPLACE leg in ring3-mm.
    fn scope(&self) -> TestScope {
        TestScope::CoveredBy {
            gate: "ring3-mm",
            marker: "brk VA reservation TOCTOU: concurrent CLONE_VM brk and MAP_FIXED_NOREPLACE never overlap",
        }
    }

    fn description(&self) -> &'static str {
        "R174-B4: Verify brk() VA reservation atomicity (prevents heap overlap)"
    }

    fn run(&self) -> TestResult {
        TestResult::Deferred(String::from(
            "Covered by Ring-3 concurrent CLONE_VM brk VA reservation TOCTOU leg in ring3-mm",
        ))
    }
}

/// M0-7 SLICE-1: Verifies that stack guard pages are properly installed and
/// trigger SIGSEGV on overflow. Without guard pages, stack overflow silently
/// corrupts adjacent memory regions.
struct StackGuardPageTest;

impl RuntimeTest for StackGuardPageTest {
    fn name(&self) -> &'static str {
        "m0_7_stack_guard_page"
    }

    // STRICT-Q S3 (D5): Ring-3 guard-page SIGSEGV and lazy stack growth verified in ring3-mm.
    // Keep the marker free of the bare substring "page fault" so
    // nilix-syz-fuzzer's boot serial fatal classifier does not trip on it;
    // "user stack guard page" uniquely pins the ring3-mm stack-guard leg.
    fn scope(&self) -> TestScope {
        TestScope::CoveredBy {
            gate: "ring3-mm",
            marker: "user stack guard page",
        }
    }

    fn description(&self) -> &'static str {
        "M0-7 SLICE-1: Verify stack overflow detection via guard page"
    }

    fn run(&self) -> TestResult {
        TestResult::Deferred(String::from(
            "Test requires process creation + recursive stack overflow - placeholder",
        ))
    }
}

/// OOM Handling: Verifies that the kernel gracefully handles out-of-memory
/// conditions without panicking. Proper OOM handling returns -ENOMEM to
/// userspace rather than crashing the kernel.
struct OomGracefulHandlingTest;

impl RuntimeTest for OomGracefulHandlingTest {
    fn name(&self) -> &'static str {
        "oom_graceful_handling"
    }

    fn description(&self) -> &'static str {
        "Verify kernel handles OOM conditions gracefully without panic"
    }

    fn run(&self) -> TestResult {
        use kernel_core::{
            create_cgroup, delete_cgroup, try_charge_memory, uncharge_memory, CgroupControllers,
            CgroupError, CgroupLimits,
        };
        use mm::buddy_allocator::{
            alloc_physical_pages, free_physical_pages, get_allocator_stats,
            try_alloc_physical_pages, AllocError,
        };
        use mm::{get_oom_stats, score_oom_process, OomProcessInfo};

        let stats = match get_allocator_stats() {
            Some(s) => s,
            None => {
                return TestResult::Fail(String::from("Buddy allocator not initialized"));
            }
        };
        if stats.total_pages == 0 || stats.free_pages == 0 {
            return TestResult::Fail(alloc::format!(
                "Invalid buddy allocator state: total={} free={}",
                stats.total_pages,
                stats.free_pages
            ));
        }

        // 1. Oversized / invalid physical allocations must fail cleanly without
        // panicking or wedging the OOM killer state machine.
        for bad_count in [0usize, usize::MAX, 1usize << 20] {
            match try_alloc_physical_pages(bad_count) {
                Err(AllocError::InvalidOrder) => {}
                other => {
                    return TestResult::Fail(alloc::format!(
                        "try_alloc_physical_pages({}) returned {:?}, expected InvalidOrder",
                        bad_count,
                        other
                    ));
                }
            }
        }
        if alloc_physical_pages(usize::MAX).is_some() {
            return TestResult::Fail(String::from(
                "alloc_physical_pages(usize::MAX) unexpectedly succeeded",
            ));
        }
        if get_oom_stats().is_running {
            return TestResult::Fail(String::from(
                "OOM killer unexpectedly stuck in is_running=true",
            ));
        }

        // 2. OOM victim scoring invariants: PID 1, TGID 1, kernel threads,
        // mm-less tasks, and oom_score_adj=-1000 must remain immune (i64::MIN),
        // while eligible user tasks rank strictly by RSS, oom_score_adj, and nice.
        let base = OomProcessInfo {
            pid: 100,
            generation: 1,
            tgid: 100,
            uid: 1000,
            gid: 1000,
            rss_pages: 64,
            nice: 0,
            oom_score_adj: 0,
            has_mm: true,
            is_kernel_thread: false,
        };
        let immune_cases = [
            OomProcessInfo {
                pid: 1,
                tgid: 1,
                rss_pages: 100_000,
                oom_score_adj: 1000,
                ..base
            },
            OomProcessInfo {
                pid: 42,
                tgid: 1,
                rss_pages: 100_000,
                oom_score_adj: 1000,
                ..base
            },
            OomProcessInfo {
                is_kernel_thread: true,
                rss_pages: 100_000,
                ..base
            },
            OomProcessInfo {
                has_mm: false,
                rss_pages: 100_000,
                ..base
            },
            OomProcessInfo {
                oom_score_adj: -1000,
                rss_pages: 100_000,
                ..base
            },
        ];
        for (idx, info) in immune_cases.iter().enumerate() {
            let score = score_oom_process(info);
            if score != i64::MIN {
                return TestResult::Fail(alloc::format!(
                    "immune OOM case {} scored {}, expected i64::MIN",
                    idx,
                    score
                ));
            }
        }
        let s_base = score_oom_process(&base);
        let s_big_rss = score_oom_process(&OomProcessInfo {
            rss_pages: 512,
            ..base
        });
        let s_high_adj = score_oom_process(&OomProcessInfo {
            oom_score_adj: 250,
            ..base
        });
        let s_high_nice = score_oom_process(&OomProcessInfo { nice: 15, ..base });
        if !(s_base > i64::MIN && s_big_rss > s_base && s_high_adj > s_base && s_high_nice > s_base)
        {
            return TestResult::Fail(alloc::format!(
                "OOM victim ranking violated: base={} big_rss={} high_adj={} high_nice={}",
                s_base,
                s_big_rss,
                s_high_adj,
                s_high_nice
            ));
        }

        // 3. Cgroup v2 memory.max enforcement: verify bounded charge succeeds,
        // over-limit charge fails cleanly with MemoryLimitExceeded (no partial
        // charge leak, memory_events_max incremented), and uncharge + delete
        // restore zero state.
        let cg = match create_cgroup(0, CgroupControllers::MEMORY) {
            Ok(c) => c,
            Err(e) => {
                return TestResult::Fail(alloc::format!(
                    "failed to create ephemeral OOM test cgroup: {:?}",
                    e
                ));
            }
        };
        let cg_id = cg.id();
        let mut charged = 0u64;
        let cg_outcome: Result<(), String> = (|| {
            cg.set_limit(CgroupLimits {
                memory_max: Some(8192),
                ..CgroupLimits::default()
            })
            .map_err(|e| alloc::format!("failed to set memory.max on test cgroup: {:?}", e))?;

            try_charge_memory(cg_id, 4096)
                .map_err(|e| alloc::format!("in-budget 4 KiB charge failed: {:?}", e))?;
            charged = 4096;

            let snap_mid = cg.get_stats();
            if snap_mid.memory_current != 4096 {
                return Err(alloc::format!(
                    "expected memory_current=4096 after first charge, got {}",
                    snap_mid.memory_current
                ));
            }

            match try_charge_memory(cg_id, 8192) {
                Err(CgroupError::MemoryLimitExceeded) => {}
                other => {
                    return Err(alloc::format!(
                        "over-limit charge returned {:?}, expected MemoryLimitExceeded",
                        other
                    ));
                }
            }

            let snap_after = cg.get_stats();
            if snap_after.memory_current != 4096 {
                return Err(alloc::format!(
                    "over-limit rejection leaked charge: memory_current={}, expected 4096",
                    snap_after.memory_current
                ));
            }
            if snap_after.memory_events_max == 0 {
                return Err(String::from(
                    "memory.max OOM rejection did not increment memory_events_max",
                ));
            }

            uncharge_memory(cg_id, charged);
            charged = 0;

            let snap_zero = cg.get_stats();
            if snap_zero.memory_current != 0 {
                return Err(alloc::format!(
                    "expected memory_current=0 after uncharge, got {}",
                    snap_zero.memory_current
                ));
            }
            Ok(())
        })();

        if charged > 0 {
            uncharge_memory(cg_id, charged);
        }
        drop(cg);
        if let Err(e) = delete_cgroup(cg_id) {
            return TestResult::Fail(alloc::format!(
                "failed to delete ephemeral OOM test cgroup {}: {:?}",
                cg_id,
                e
            ));
        }
        if let Err(msg) = cg_outcome {
            return TestResult::Fail(msg);
        }

        // 4. Verify physical allocator remains healthy after OOM negative checks.
        let Some(probe_frame) = alloc_physical_pages(1) else {
            return TestResult::Fail(String::from(
                "buddy allocator failed 1-page allocation after OOM checks",
            ));
        };
        free_physical_pages(probe_frame, 1);

        TestResult::Pass
    }
}

// ============================================================================
// CATEGORY 3: IPC TESTS (5 tests)
// ============================================================================

/// R24-5: Verifies basic futex WAIT/WAKE operations. Tests that FUTEX_WAIT
/// blocks when the futex value matches expected, FUTEX_WAKE unblocks exactly
/// N waiters, and no lost-wakeup race occurs.
struct FutexWaitWakeCorrectnessTest;

impl RuntimeTest for FutexWaitWakeCorrectnessTest {
    fn name(&self) -> &'static str {
        "futex_wait_wake_correctness"
    }

    // STRICT-Q S3 (D5): FUTEX_WAIT/WAKE/WAKE_OP/REQUEUE/BITSET/CLONE_VM verified in ring3-mm.
    fn scope(&self) -> TestScope {
        TestScope::CoveredBy {
            gate: "ring3-mm",
            marker: "futex WAKE_OP, requeue, partial bitsets and CLONE_VM keys match Linux",
        }
    }

    fn description(&self) -> &'static str {
        "R24-5: Verify FUTEX_WAIT blocks and FUTEX_WAKE unblocks (prevents deadlock)"
    }

    fn run(&self) -> TestResult {
        TestResult::Deferred(String::from(
            "Test requires sys_futex() with fork - placeholder for future implementation",
        ))
    }
}

/// E.4: Verifies PI futex priority inheritance. When a high-priority task
/// blocks on a futex held by a low-priority task, the low-priority task's
/// priority is boosted to prevent priority inversion.
struct FutexLockPiPriorityInheritanceTest;

impl RuntimeTest for FutexLockPiPriorityInheritanceTest {
    fn name(&self) -> &'static str {
        "futex_lock_pi_priority_inheritance"
    }

    fn description(&self) -> &'static str {
        "E.4: Verify PI futex owner inherits waiter priority (prevents priority inversion)"
    }

    fn run(&self) -> TestResult {
        match ipc::futex::run_pi_priority_inheritance_self_test() {
            Ok(()) => TestResult::Pass,
            Err(msg) => TestResult::Fail(String::from(msg)),
        }
    }
}

/// R172-08: Verifies that futex bucket allocation is performed under the
/// FUTEX_TABLE lock to prevent TOCTOU races where two threads claim the
/// same bucket concurrently, leading to waiter list corruption.
struct FutexBucketToctouTest;

impl RuntimeTest for FutexBucketToctouTest {
    fn name(&self) -> &'static str {
        "r172_08_futex_bucket_toctou"
    }

    // STRICT-Q S4 (D5): Ring-3 concurrent futex bucket TOCTOU stress leg in ring3-mm.
    fn scope(&self) -> TestScope {
        TestScope::CoveredBy {
            gate: "ring3-mm",
            marker: "futex bucket TOCTOU: concurrent wait/wake/requeue across rotating words loses no wakeups",
        }
    }

    fn description(&self) -> &'static str {
        "R172-08: Verify futex bucket claim under FUTEX_TABLE lock (no TOCTOU)"
    }

    fn run(&self) -> TestResult {
        TestResult::Deferred(String::from(
            "Covered by Ring-3 concurrent futex bucket TOCTOU leg in ring3-mm",
        ))
    }
}

/// R41-3: Verifies that pipe read() correctly handles EINTR when a signal
/// arrives during blocking read. The syscall should return -EINTR and allow
/// signal delivery, not deadlock or lose the signal.
struct PipeEintrWakeTest;

impl RuntimeTest for PipeEintrWakeTest {
    fn name(&self) -> &'static str {
        "r41_3_pipe_eintr_wake"
    }

    // STRICT-Q S4 (D5): Ring-3 blocking pipe read + SIGUSR1 EINTR leg in ring3-mm.
    fn scope(&self) -> TestScope {
        TestScope::CoveredBy {
            gate: "ring3-mm",
            marker: "pipe read wakes with EINTR on SIGUSR1 delivery and remains usable afterward",
        }
    }

    fn description(&self) -> &'static str {
        "R41-3: Verify pipe read() wakes with -EINTR on signal delivery"
    }

    fn run(&self) -> TestResult {
        TestResult::Deferred(String::from(
            "Covered by Ring-3 pipe EINTR signal wake leg in ring3-mm",
        ))
    }
}

/// M0-5: Verifies that signals are correctly delivered to blocked syscalls.
/// When a process is blocked in a syscall and a signal arrives, the syscall
/// should be interrupted and the signal handler invoked.
struct SignalDeliveryToBlockedSyscallTest;

impl RuntimeTest for SignalDeliveryToBlockedSyscallTest {
    fn name(&self) -> &'static str {
        "m0_5_signal_delivery_blocked_syscall"
    }

    // STRICT-Q S4 (D5): Ring-3 blocked nanosleep + futex_wait SIGUSR2 leg in ring3-mm.
    fn scope(&self) -> TestScope {
        TestScope::CoveredBy {
            gate: "ring3-mm",
            marker: "signal delivery interrupts blocked nanosleep and futex_wait with EINTR and runs handler",
        }
    }

    fn description(&self) -> &'static str {
        "M0-5: Verify signal delivery interrupts blocked syscalls (prevents signal loss)"
    }

    fn run(&self) -> TestResult {
        TestResult::Deferred(String::from(
            "Covered by Ring-3 blocked-syscall signal delivery leg in ring3-mm",
        ))
    }
}

// ============================================================================
// CATEGORY 4: SCHEDULER TESTS (5 tests)
// ============================================================================

/// R172-03: Comprehensive SMP work stealing safety test. Creates many
/// short-lived processes to trigger work stealing and verifies that per-task
/// state (TLS, registers) is never corrupted by steal-before-save races.
struct SmpWorkStealingSafetyTest;

impl RuntimeTest for SmpWorkStealingSafetyTest {
    fn name(&self) -> &'static str {
        "r172_03_smp_work_stealing_safety"
    }

    fn description(&self) -> &'static str {
        "R172-03: Comprehensive SMP work stealing safety under load"
    }

    fn run(&self) -> TestResult {
        use arch::num_online_cpus;

        if num_online_cpus() < 2 {
            return TestResult::Deferred(String::from(
                "Work stealing test requires 2+ CPUs (only 1 online)",
            ));
        }

        TestResult::Deferred(String::from(
            "SMP available; full test requires 100+ concurrent processes with TLS verification",
        ))
    }
}

/// R171-G5-1: Verifies that get_process() uses non-blocking operations when
/// called from IRQ context. Blocking in IRQ context leads to deadlock.
struct NonBlockingGetProcessInIrqTest;

impl RuntimeTest for NonBlockingGetProcessInIrqTest {
    fn name(&self) -> &'static str {
        "r171_g5_1_non_blocking_get_process_irq"
    }

    fn description(&self) -> &'static str {
        "R171-G5-1: Verify get_process() non-blocking in IRQ context (prevents deadlock)"
    }

    fn run(&self) -> TestResult {
        TestResult::Deferred(String::from(
            "Test requires IRQ context verification - placeholder",
        ))
    }
}

/// Migration Safety: Verifies that process migration between CPUs maintains
/// per-CPU state consistency. Stale per-CPU references after migration can
/// cause use-after-free or state corruption.
struct ProcessMigrationSafetyTest;

impl RuntimeTest for ProcessMigrationSafetyTest {
    fn name(&self) -> &'static str {
        "process_migration_safety"
    }

    fn description(&self) -> &'static str {
        "Verify process migration maintains per-CPU state consistency"
    }

    fn run(&self) -> TestResult {
        use arch::num_online_cpus;

        if num_online_cpus() < 2 {
            return TestResult::Deferred(String::from(
                "Migration test requires 2+ CPUs (only 1 online)",
            ));
        }

        TestResult::Deferred(String::from(
            "SMP available; full test requires forced migration with state verification",
        ))
    }
}

/// Load Balancing: Verifies that the scheduler distributes work fairly across
/// CPUs. Unfair distribution can lead to CPU starvation or denial of service.
struct SchedulerLoadBalancingTest;

impl RuntimeTest for SchedulerLoadBalancingTest {
    fn name(&self) -> &'static str {
        "scheduler_load_balancing"
    }

    fn description(&self) -> &'static str {
        "Verify scheduler distributes work fairly across CPUs"
    }

    fn run(&self) -> TestResult {
        use arch::num_online_cpus;

        if num_online_cpus() < 2 {
            return TestResult::Deferred(String::from(
                "Load balancing test requires 2+ CPUs (only 1 online)",
            ));
        }

        TestResult::Deferred(String::from(
            "SMP available; full test requires workload distribution metrics",
        ))
    }
}

/// CPU Affinity: Verifies that sched_setaffinity() correctly restricts a
/// process to run only on specified CPUs. Broken affinity can violate
/// isolation guarantees.
struct CpuAffinityEnforcementTest;

impl RuntimeTest for CpuAffinityEnforcementTest {
    fn name(&self) -> &'static str {
        "cpu_affinity_enforcement"
    }

    fn description(&self) -> &'static str {
        "Verify sched_setaffinity() restricts process to specified CPUs"
    }

    fn run(&self) -> TestResult {
        use arch::num_online_cpus;

        if num_online_cpus() < 2 {
            return TestResult::Deferred(String::from(
                "Affinity test requires 2+ CPUs (only 1 online)",
            ));
        }

        TestResult::Deferred(String::from(
            "SMP available; full test requires sys_sched_setaffinity() + CPU pinning verification",
        ))
    }
}

// ============================================================================
// CATEGORY 5: VFS TESTS (5 tests) — STRICT-Q S7
// ============================================================================

/// Shared synchronization state for SMP concurrent VFS rename / directory tests.
mod vfs_smp_race_state {
    use core::sync::atomic::AtomicU64;

    pub static RENAME_ACTIVE_RUN_ID: AtomicU64 = AtomicU64::new(0);
    pub static RENAME_EXITED_RUN_ID: AtomicU64 = AtomicU64::new(0);
    pub static RENAME_ROUND: AtomicU64 = AtomicU64::new(0);
    pub static RENAME_AP_DONE: AtomicU64 = AtomicU64::new(0);
    pub static RENAME_AP_RESULT: AtomicU64 = AtomicU64::new(0); // 1 = Ok, 2 = expected Err, 3 = unexpected

    pub static DIR_ACTIVE_RUN_ID: AtomicU64 = AtomicU64::new(0);
    pub static DIR_EXITED_RUN_ID: AtomicU64 = AtomicU64::new(0);
    pub static DIR_AP_STARTED: AtomicU64 = AtomicU64::new(0);
    // Synchronized two-phase competing create / unlink protocol per round.
    // u64::MAX in either round atomic signals immediate abort/exit.
    pub static DIR_CREATE_ROUND: AtomicU64 = AtomicU64::new(0);
    pub static DIR_AP_CREATE_RES: AtomicU64 = AtomicU64::new(0); // 1 = Ok, 2 = Exists, 3 = unexpected
    pub static DIR_AP_CREATE_DONE: AtomicU64 = AtomicU64::new(0);
    pub static DIR_UNLINK_ROUND: AtomicU64 = AtomicU64::new(0);
    pub static DIR_AP_UNLINK_RES: AtomicU64 = AtomicU64::new(0); // 1 = Ok, 2 = NotFound, 3 = unexpected
    pub static DIR_AP_UNLINK_DONE: AtomicU64 = AtomicU64::new(0);
}

fn vfs_rename_race_ap_worker() {
    use core::hint::spin_loop;
    use core::sync::atomic::Ordering;
    use vfs::{FsError, VFS};
    use vfs_smp_race_state::*;

    let my_run_id = RENAME_ACTIVE_RUN_ID.load(Ordering::Acquire);
    let mut seen = 0u64;
    loop {
        let round = RENAME_ROUND.load(Ordering::Acquire);
        if round == u64::MAX {
            break;
        }
        if round == seen {
            spin_loop();
            continue;
        }
        seen = round;
        // Opposing rename against BSP's `a -> b/a`: try `b -> a/b`.
        let res = VFS.rename_trusted("/__sq_r172_15/b", "/__sq_r172_15/a/b", false);
        let code = match res {
            Ok(()) => 1,
            Err(FsError::Invalid | FsError::NotFound | FsError::Again | FsError::Exists) => 2,
            Err(_) => 3,
        };
        RENAME_AP_RESULT.store(code, Ordering::Release);
        RENAME_AP_DONE.store(round, Ordering::Release);
    }
    RENAME_EXITED_RUN_ID.store(my_run_id, Ordering::Release);
}

fn vfs_dir_atomicity_ap_worker() {
    use core::hint::spin_loop;
    use core::sync::atomic::Ordering;
    use vfs::{FileMode, FsError, VFS};
    use vfs_smp_race_state::*;

    let my_run_id = DIR_ACTIVE_RUN_ID.load(Ordering::Acquire);
    DIR_AP_STARTED.store(my_run_id, Ordering::Release);

    let mut last_round = 0u64;
    loop {
        let round = DIR_CREATE_ROUND.load(Ordering::Acquire);
        if round == u64::MAX {
            break;
        }
        if round == last_round {
            spin_loop();
            continue;
        }
        last_round = round;

        let name = alloc::format!("/__sq_dir_atom/race_{}", round % 4);
        let create_code = match VFS.create_trusted(&name, FileMode::regular(0o644)) {
            Ok(_) => 1,
            Err(FsError::Exists) => 2,
            Err(_) => 3,
        };
        DIR_AP_CREATE_RES.store(create_code, Ordering::Release);
        DIR_AP_CREATE_DONE.store(round, Ordering::Release);

        // Wait for BSP to verify Phase A create exclusivity and arm Phase B unlink.
        loop {
            let uround = DIR_UNLINK_ROUND.load(Ordering::Acquire);
            if uround == u64::MAX {
                DIR_EXITED_RUN_ID.store(my_run_id, Ordering::Release);
                return;
            }
            if uround >= round {
                break;
            }
            spin_loop();
        }

        let unlink_code = match VFS.unlink_trusted(&name, Some(false)) {
            Ok(()) => 1,
            Err(FsError::NotFound) => 2,
            Err(_) => 3,
        };
        DIR_AP_UNLINK_RES.store(unlink_code, Ordering::Release);
        DIR_AP_UNLINK_DONE.store(round, Ordering::Release);
    }
    DIR_EXITED_RUN_ID.store(my_run_id, Ordering::Release);
}

/// VFS Data Plane: Verifies basic RAMFS create/write/read/truncate/unlink operations.
struct RamfsBasicOperationsTest;

impl RuntimeTest for RamfsBasicOperationsTest {
    fn name(&self) -> &'static str {
        "ramfs_basic_operations"
    }

    fn description(&self) -> &'static str {
        "Verify RAMFS create/write/read operations (VFS data plane)"
    }

    fn run(&self) -> TestResult {
        use kernel_core::FileOps;
        use vfs::{FileHandle, FileMode, FileType, FsError, OpenFlags, VFS};

        const DIR: &str = "/__sq_ramfs_basic";
        const FILE: &str = "/__sq_ramfs_basic/payload.bin";

        // Exclusively claim the fixture root; if it already exists (or mkdir
        // fails), abort immediately without touching any pre-existing entries.
        if let Err(e) = VFS.create_trusted(DIR, FileMode::directory(0o755)) {
            return TestResult::Fail(alloc::format!("mkdir {} failed: {:?}", DIR, e));
        }

        let mut created_file = false;
        let outcome: Result<(), String> = (|| {
            // Negative control: opening a missing file without O_CREAT must return NotFound.
            match VFS.open_trusted(FILE, OpenFlags::new(OpenFlags::O_RDONLY), 0) {
                Err(FsError::NotFound) => {}
                other => {
                    return Err(alloc::format!(
                        "missing file open expected NotFound, got {:?}",
                        other.is_ok()
                    ));
                }
            }

            let inode = VFS
                .create_trusted(FILE, FileMode::regular(0o644))
                .map_err(|e| alloc::format!("create {} failed: {:?}", FILE, e))?;
            created_file = true;

            // Negative control: duplicate create must return Exists.
            match VFS.create_trusted(FILE, FileMode::regular(0o644)) {
                Err(FsError::Exists) => {}
                other => {
                    return Err(alloc::format!(
                        "duplicate create expected Exists, got {:?}",
                        other.is_ok()
                    ));
                }
            }

            // Write via VFS FileHandle, then verify via direct read_at and a second open handle.
            let payload = b"STRICT-Q S7 RAMFS data-plane verification payload!";
            {
                let fd = VFS
                    .open_trusted(FILE, OpenFlags::new(OpenFlags::O_WRONLY), 0)
                    .map_err(|e| alloc::format!("open WRONLY failed: {:?}", e))?;
                let handle = fd
                    .as_any()
                    .downcast_ref::<FileHandle>()
                    .ok_or_else(|| String::from("FileDescriptor is not FileHandle"))?;
                let written = handle
                    .write(payload)
                    .map_err(|e| alloc::format!("FileHandle::write failed: {:?}", e))?;
                if written != payload.len() {
                    return Err(alloc::format!(
                        "short write: {} != {}",
                        written,
                        payload.len()
                    ));
                }
            }

            let st = VFS
                .stat_trusted(FILE)
                .map_err(|e| alloc::format!("stat {} failed: {:?}", FILE, e))?;
            if st.mode.file_type != FileType::Regular || st.size as usize != payload.len() {
                return Err(alloc::format!(
                    "unexpected stat: type={:?} size={}",
                    st.mode.file_type,
                    st.size
                ));
            }

            {
                let fd = VFS
                    .open_trusted(FILE, OpenFlags::new(OpenFlags::O_RDONLY), 0)
                    .map_err(|e| alloc::format!("open RDONLY failed: {:?}", e))?;
                let handle = fd
                    .as_any()
                    .downcast_ref::<FileHandle>()
                    .ok_or_else(|| String::from("FileDescriptor is not FileHandle"))?;
                let mut buf = [0u8; 64];
                let n = handle
                    .read(&mut buf)
                    .map_err(|e| alloc::format!("FileHandle::read failed: {:?}", e))?;
                if n != payload.len() || &buf[..n] != payload {
                    return Err(alloc::format!(
                        "readback mismatch: len={} (exp {})",
                        n,
                        payload.len()
                    ));
                }
            }

            // Overwrite at non-zero offset + shrink truncate + extend zero-fill.
            inode
                .write_at(7, b"VFS")
                .map_err(|e| alloc::format!("write_at offset failed: {:?}", e))?;
            inode
                .truncate(12)
                .map_err(|e| alloc::format!("truncate shrink failed: {:?}", e))?;
            inode
                .truncate(16)
                .map_err(|e| alloc::format!("truncate extend failed: {:?}", e))?;
            let mut extended = [0xAAu8; 16];
            let n = inode
                .read_at(0, &mut extended)
                .map_err(|e| alloc::format!("read_at after truncate failed: {:?}", e))?;
            if n != 16 || &extended[7..10] != b"VFS" || extended[12..16] != [0, 0, 0, 0] {
                return Err(String::from(
                    "offset overwrite or truncate zero-fill mismatch",
                ));
            }

            Ok(())
        })();

        let unlink_file = if created_file {
            Some(VFS.unlink_trusted(FILE, Some(false)))
        } else {
            None
        };
        let unlink_dir = VFS.unlink_trusted(DIR, Some(true));
        if let Err(msg) = outcome {
            return TestResult::Fail(msg);
        }
        if let Some(Err(e)) = unlink_file {
            return TestResult::Fail(alloc::format!("cleanup unlink {} failed: {:?}", FILE, e));
        }
        if let Err(e) = unlink_dir {
            return TestResult::Fail(alloc::format!("cleanup rmdir {} failed: {:?}", DIR, e));
        }
        if !matches!(VFS.stat_trusted(DIR), Err(FsError::NotFound)) {
            return TestResult::Fail(String::from("removed fixture directory still visible"));
        }
        TestResult::Pass
    }
}

/// R172-14: Verifies that rename() prevents self-rename deadlock. Renaming a
/// directory to a child of itself would create a cycle in the directory tree.
struct RamfsRenameSelfDeadlockTest;

impl RuntimeTest for RamfsRenameSelfDeadlockTest {
    fn name(&self) -> &'static str {
        "r172_14_ramfs_rename_self_deadlock"
    }

    fn description(&self) -> &'static str {
        "R172-14: Verify rename() prevents self-deadlock (e.g., mv /a /a/b)"
    }

    fn run(&self) -> TestResult {
        use vfs::{FileMode, FsError, VFS};

        const ROOT: &str = "/__sq_r172_14";
        const A: &str = "/__sq_r172_14/a";
        const B: &str = "/__sq_r172_14/a/b";
        const C: &str = "/__sq_r172_14/a/b/c";

        // Exclusively claim the fixture root without touching any pre-existing entries.
        if let Err(e) = VFS.create_trusted(ROOT, FileMode::directory(0o755)) {
            return TestResult::Fail(alloc::format!("mkdir {} failed: {:?}", ROOT, e));
        }

        let subdirs = [A, B, C];
        let mut created = [false; 3];
        let outcome: Result<(), String> = (|| {
            for (idx, d) in subdirs.iter().enumerate() {
                VFS.create_trusted(d, FileMode::directory(0o755))
                    .map_err(|e| alloc::format!("mkdir {} failed: {:?}", d, e))?;
                created[idx] = true;
            }

            let a_ino = VFS
                .stat_trusted(A)
                .map_err(|e| alloc::format!("stat {} failed: {:?}", A, e))?
                .ino;
            let b_ino = VFS
                .stat_trusted(B)
                .map_err(|e| alloc::format!("stat {} failed: {:?}", B, e))?
                .ino;

            // 1. Direct child cycle: rename(a -> a/sub) must fail with Invalid (EINVAL).
            match VFS.rename_trusted(A, "/__sq_r172_14/a/sub", false) {
                Err(FsError::Invalid) => {}
                other => {
                    return Err(alloc::format!(
                        "direct self-subtree rename expected Invalid, got {:?}",
                        other
                    ));
                }
            }

            // 2. Deep descendant cycle: rename(a -> a/b/c/loop) must fail with Invalid.
            match VFS.rename_trusted(A, "/__sq_r172_14/a/b/c/loop", false) {
                Err(FsError::Invalid) => {}
                other => {
                    return Err(alloc::format!(
                        "deep descendant rename expected Invalid, got {:?}",
                        other
                    ));
                }
            }

            // 3. Parent-overwrite check (R172-14 `rename_decide` parent identity guard):
            //    renaming existing child `B` onto its parent `A` must fail with Invalid
            //    (not NotEmpty) and leave both inodes intact.
            match VFS.rename_trusted(B, A, false) {
                Err(FsError::Invalid) => {}
                other => {
                    return Err(alloc::format!(
                        "parent-overwrite rename(b -> a) expected Invalid, got {:?}",
                        other
                    ));
                }
            }

            // 4. Same-path rename(a -> a) must succeed as a no-op without deadlocking.
            VFS.rename_trusted(A, A, false)
                .map_err(|e| alloc::format!("same-path rename(a -> a) failed: {:?}", e))?;

            // 5. All original nodes must remain intact and reachable with unchanged inodes.
            let a_after = VFS
                .stat_trusted(A)
                .map_err(|e| alloc::format!("tree node {} lost after cycle guard: {:?}", A, e))?;
            let b_after = VFS
                .stat_trusted(B)
                .map_err(|e| alloc::format!("tree node {} lost after cycle guard: {:?}", B, e))?;
            VFS.stat_trusted(C)
                .map_err(|e| alloc::format!("tree node {} lost after cycle guard: {:?}", C, e))?;
            if a_after.ino != a_ino || b_after.ino != b_ino {
                return Err(String::from(
                    "parent-overwrite guard altered inode identity of A or B",
                ));
            }
            Ok(())
        })();

        for idx in (0..subdirs.len()).rev() {
            if created[idx] {
                let _ = VFS.unlink_trusted(subdirs[idx], Some(true));
            }
        }
        let cleanup = VFS.unlink_trusted(ROOT, Some(true));

        match (outcome, cleanup) {
            (Err(msg), _) => TestResult::Fail(msg),
            (Ok(()), Err(e)) => {
                TestResult::Fail(alloc::format!("cleanup {} failed: {:?}", ROOT, e))
            }
            (Ok(()), Ok(())) => TestResult::Pass,
        }
    }
}

/// R172-15: Verifies that rename() prevents ancestor TOCTOU race where
/// concurrent operations can bypass ancestor checks, allowing directory
/// cycles to be created.
struct RamfsRenameAncestorToctouTest;

impl RuntimeTest for RamfsRenameAncestorToctouTest {
    fn name(&self) -> &'static str {
        "r172_15_ramfs_rename_ancestor_toctou"
    }

    fn description(&self) -> &'static str {
        "R172-15: Verify rename() ancestor check under lock (no TOCTOU)"
    }

    fn run(&self) -> TestResult {
        use arch::ipi::{send_ipi, IpiType};
        use arch::{current_cpu_id, max_cpus, num_online_cpus, set_ap_test_probe};
        use core::hint::spin_loop;
        use core::sync::atomic::Ordering;
        use mm::tlb_shootdown::is_cpu_online;
        use vfs::{FileMode, FsError, VFS};
        use vfs_smp_race_state::*;

        const ROOT: &str = "/__sq_r172_15";
        const A: &str = "/__sq_r172_15/a";
        const B: &str = "/__sq_r172_15/b";
        const A_IN_B: &str = "/__sq_r172_15/b/a";
        const B_IN_A: &str = "/__sq_r172_15/a/b";

        // Exclusively claim the fixture root without touching any pre-existing entries.
        if let Err(e) = VFS.create_trusted(ROOT, FileMode::directory(0o755)) {
            return TestResult::Fail(alloc::format!("mkdir {} failed: {:?}", ROOT, e));
        }

        let mut created_a = false;
        let mut created_b = false;
        let mut ap_still_active = false;
        let outcome: Result<(), String> = (|| {
            VFS.create_trusted(A, FileMode::directory(0o755))
                .map_err(|e| alloc::format!("mkdir {} failed: {:?}", A, e))?;
            created_a = true;
            VFS.create_trusted(B, FileMode::directory(0o755))
                .map_err(|e| alloc::format!("mkdir {} failed: {:?}", B, e))?;
            created_b = true;

            // 1. Sequential ancestor inversion guard: move a -> b/a, then attempt b -> b/a/b.
            VFS.rename_trusted(A, A_IN_B, false)
                .map_err(|e| alloc::format!("rename a -> b/a failed: {:?}", e))?;
            match VFS.rename_trusted(B, "/__sq_r172_15/b/a/b", false) {
                Err(FsError::Invalid) => {}
                other => {
                    return Err(alloc::format!(
                        "inverted ancestor rename expected Invalid, got {:?}",
                        other
                    ));
                }
            }
            VFS.rename_trusted(A_IN_B, A, false)
                .map_err(|e| alloc::format!("restore b/a -> a failed: {:?}", e))?;

            // 2. On SMP (2+ CPUs), race BSP `rename(a -> b/a)` directly against AP
            //    `rename(b -> a/b)` across 24 rounds. Under RAMFS_TOPOLOGY_LOCK at most
            //    one opposing rename may win; if both ever succeeded, a disconnected
            //    a <-> b directory cycle would form.
            if num_online_cpus() >= 2 {
                let self_cpu = current_cpu_id();
                if let Some(target) =
                    (0..max_cpus()).find(|&id| id != self_cpu && is_cpu_online(id))
                {
                    if RENAME_ACTIVE_RUN_ID.load(Ordering::Acquire)
                        != RENAME_EXITED_RUN_ID.load(Ordering::Acquire)
                    {
                        return Err(String::from(
                            "previous rename race AP worker has not exited yet",
                        ));
                    }
                    RENAME_ROUND.store(0, Ordering::Release);
                    RENAME_AP_DONE.store(0, Ordering::Release);
                    RENAME_AP_RESULT.store(0, Ordering::Release);
                    let run_id = RENAME_ACTIVE_RUN_ID.fetch_add(1, Ordering::AcqRel) + 1;

                    ap_still_active = true;
                    let _ = set_ap_test_probe(target, Some(vfs_rename_race_ap_worker));
                    send_ipi(target, IpiType::Reschedule);

                    let mut race_err: Option<String> = None;
                    for round in 1..=24u64 {
                        RENAME_AP_RESULT.store(0, Ordering::Release);
                        RENAME_ROUND.store(round, Ordering::Release);

                        let bsp_res = VFS.rename_trusted(A, A_IN_B, false);
                        let mut done = false;
                        for _ in 0..50_000_000usize {
                            if RENAME_AP_DONE.load(Ordering::Acquire) == round {
                                done = true;
                                break;
                            }
                            spin_loop();
                        }
                        if !done {
                            race_err = Some(alloc::format!(
                                "AP {} timed out on opposing rename round {}",
                                target,
                                round
                            ));
                            break;
                        }
                        let ap_code = RENAME_AP_RESULT.load(Ordering::Acquire);
                        if ap_code == 3 {
                            race_err = Some(alloc::format!(
                                "AP {} hit unexpected rename error on round {}",
                                target,
                                round
                            ));
                            break;
                        }
                        let bsp_won = bsp_res.is_ok();
                        let ap_won = ap_code == 1;
                        if bsp_won && ap_won {
                            race_err = Some(alloc::format!(
                                "R172-15 VIOLATION: opposing renames BOTH succeeded on round {} (directory cycle!)",
                                round
                            ));
                            break;
                        }
                        if !bsp_won {
                            match bsp_res {
                                Err(
                                    FsError::Invalid
                                    | FsError::NotFound
                                    | FsError::Again
                                    | FsError::Exists,
                                ) => {}
                                Err(e) => {
                                    race_err = Some(alloc::format!(
                                        "BSP unexpected rename error on round {}: {:?}",
                                        round,
                                        e
                                    ));
                                    break;
                                }
                                Ok(()) => unreachable!(),
                            }
                        }
                        // Restore canonical layout for next round and prove both directories stay reachable.
                        if bsp_won {
                            if let Err(e) = VFS.rename_trusted(A_IN_B, A, false) {
                                race_err = Some(alloc::format!(
                                    "restore b/a -> a failed after round {}: {:?}",
                                    round,
                                    e
                                ));
                                break;
                            }
                        } else if ap_won {
                            if let Err(e) = VFS.rename_trusted(B_IN_A, B, false) {
                                race_err = Some(alloc::format!(
                                    "restore a/b -> b failed after round {}: {:?}",
                                    round,
                                    e
                                ));
                                break;
                            }
                        }
                        if VFS.stat_trusted(A).is_err() || VFS.stat_trusted(B).is_err() {
                            race_err = Some(alloc::format!(
                                "directory tree broken after round {}",
                                round
                            ));
                            break;
                        }
                    }

                    RENAME_ROUND.store(u64::MAX, Ordering::Release);
                    let cancelled = set_ap_test_probe(target, None);
                    if cancelled {
                        RENAME_EXITED_RUN_ID.store(run_id, Ordering::Release);
                        ap_still_active = false;
                    } else {
                        for _ in 0..50_000_000usize {
                            if RENAME_EXITED_RUN_ID.load(Ordering::Acquire) == run_id {
                                ap_still_active = false;
                                break;
                            }
                            spin_loop();
                        }
                    }
                    if let Some(msg) = race_err {
                        return Err(msg);
                    }
                    if ap_still_active {
                        return Err(alloc::format!(
                            "AP {} timed out exiting rename race worker",
                            target
                        ));
                    }
                }
            }
            Ok(())
        })();

        // Never unlink the fixture directory while a timed-out AP worker may
        // still be executing rename operations inside it.
        if ap_still_active {
            return match outcome {
                Err(msg) => TestResult::Fail(msg),
                Ok(()) => TestResult::Fail(String::from(
                    "rename race AP worker still active; fixture retained",
                )),
            };
        }

        if created_a && created_b {
            let _ = VFS.unlink_trusted(A_IN_B, Some(true));
            let _ = VFS.unlink_trusted(B_IN_A, Some(true));
        }
        if created_a {
            let _ = VFS.unlink_trusted(A, Some(true));
        }
        if created_b {
            let _ = VFS.unlink_trusted(B, Some(true));
        }
        let _ = VFS.unlink_trusted(ROOT, Some(true));
        if let Err(msg) = outcome {
            return TestResult::Fail(msg);
        }
        if !matches!(VFS.stat_trusted(ROOT), Err(FsError::NotFound)) {
            return TestResult::Fail(String::from(
                "rename ancestor TOCTOU cleanup left fixture directory behind",
            ));
        }
        TestResult::Pass
    }
}

/// Path Resolution: Verifies that VFS path resolution correctly handles
/// symlinks, . and .. components, and absolute vs relative paths.
struct VfsPathResolutionTest;

impl RuntimeTest for VfsPathResolutionTest {
    fn name(&self) -> &'static str {
        "vfs_path_resolution"
    }

    fn description(&self) -> &'static str {
        "Verify VFS path resolution correctness (symlinks, ., .., absolute paths)"
    }

    fn run(&self) -> TestResult {
        use vfs::{normalize_path, FileMode, FileType, FsError, VFS};

        const ROOT: &str = "/__sq_path_res";
        const SUB: &str = "/__sq_path_res/sub";
        const TARGET: &str = "/__sq_path_res/sub/target.txt";
        const LINK_ABS: &str = "/__sq_path_res/link_abs";
        const LINK_REL: &str = "/__sq_path_res/sub/link_rel";
        const LINK_CHAIN: &str = "/__sq_path_res/link_chain";
        const LOOP_A: &str = "/__sq_path_res/loop_a";
        const LOOP_B: &str = "/__sq_path_res/loop_b";

        // 1. Path normalization & root-escape negative control (R32-VFS-1).
        if normalize_path("///a//./b/../c").ok().as_deref() != Some("/a/c") {
            return TestResult::Fail(String::from("normalize_path failed on ///a//./b/../c"));
        }
        if !matches!(
            normalize_path("/../../etc/passwd"),
            Err(FsError::PermDenied)
        ) {
            return TestResult::Fail(String::from(
                "normalize_path failed to reject root traversal /../../etc/passwd",
            ));
        }

        // Exclusively claim the fixture root without touching any pre-existing entries.
        if let Err(e) = VFS.create_trusted(ROOT, FileMode::directory(0o755)) {
            return TestResult::Fail(alloc::format!("mkdir {} failed: {:?}", ROOT, e));
        }

        let mut created_sub = false;
        let mut created_target = false;
        let mut created_link_abs = false;
        let mut created_link_rel = false;
        let mut created_link_chain = false;
        let mut created_loop_a = false;
        let mut created_loop_b = false;

        let outcome: Result<(), String> = (|| {
            // 2. Build directory + target file + absolute, relative, chained, and cyclic symlinks.
            VFS.create_trusted(SUB, FileMode::directory(0o755))
                .map_err(|e| alloc::format!("mkdir {} failed: {:?}", SUB, e))?;
            created_sub = true;
            let target_inode = VFS
                .create_trusted(TARGET, FileMode::regular(0o644))
                .map_err(|e| alloc::format!("create {} failed: {:?}", TARGET, e))?;
            created_target = true;
            target_inode
                .write_at(0, b"path-target")
                .map_err(|e| alloc::format!("write target failed: {:?}", e))?;
            let target_ino = target_inode.ino();

            // Traversal with redundant slashes, `.` and `..` resolves to the exact target inode.
            let dotdot_stat = VFS
                .stat_trusted("/__sq_path_res///sub/./../sub/target.txt")
                .map_err(|e| alloc::format!("dot/dotdot stat failed: {:?}", e))?;
            if dotdot_stat.ino != target_ino || dotdot_stat.size != 11 {
                return Err(String::from("dot/dotdot stat resolved to wrong inode"));
            }

            // Absolute symlink -> target.
            VFS.symlink_trusted(LINK_ABS, TARGET)
                .map_err(|e| alloc::format!("symlink {} failed: {:?}", LINK_ABS, e))?;
            created_link_abs = true;
            let abs_stat = VFS
                .stat_trusted(LINK_ABS)
                .map_err(|e| alloc::format!("stat absolute symlink failed: {:?}", e))?;
            if abs_stat.ino != target_ino || abs_stat.mode.file_type != FileType::Regular {
                return Err(String::from("absolute symlink did not resolve to target"));
            }

            // Relative symlink -> ../sub/target.txt.
            VFS.symlink_trusted(LINK_REL, "../sub/target.txt")
                .map_err(|e| alloc::format!("symlink {} failed: {:?}", LINK_REL, e))?;
            created_link_rel = true;
            let rel_stat = VFS
                .stat_trusted(LINK_REL)
                .map_err(|e| alloc::format!("stat relative symlink failed: {:?}", e))?;
            if rel_stat.ino != target_ino {
                return Err(String::from("relative symlink did not resolve to target"));
            }

            // Chained symlink -> LINK_ABS -> TARGET.
            VFS.symlink_trusted(LINK_CHAIN, LINK_ABS)
                .map_err(|e| alloc::format!("symlink {} failed: {:?}", LINK_CHAIN, e))?;
            created_link_chain = true;
            let chain_stat = VFS
                .stat_trusted(LINK_CHAIN)
                .map_err(|e| alloc::format!("stat chained symlink failed: {:?}", e))?;
            if chain_stat.ino != target_ino {
                return Err(String::from("chained symlink did not resolve to target"));
            }

            // Negative control: symlink cycle must return SymlinkLoop (ELOOP).
            VFS.symlink_trusted(LOOP_A, LOOP_B)
                .map_err(|e| alloc::format!("symlink {} failed: {:?}", LOOP_A, e))?;
            created_loop_a = true;
            VFS.symlink_trusted(LOOP_B, LOOP_A)
                .map_err(|e| alloc::format!("symlink {} failed: {:?}", LOOP_B, e))?;
            created_loop_b = true;
            match VFS.stat_trusted(LOOP_A) {
                Err(FsError::SymlinkLoop) => {}
                other => {
                    return Err(alloc::format!(
                        "symlink loop expected SymlinkLoop, got {:?}",
                        other
                    ));
                }
            }

            Ok(())
        })();

        for (created, path) in [
            (created_loop_b, LOOP_B),
            (created_loop_a, LOOP_A),
            (created_link_chain, LINK_CHAIN),
            (created_link_rel, LINK_REL),
            (created_link_abs, LINK_ABS),
            (created_target, TARGET),
        ] {
            if created {
                let _ = VFS.unlink_trusted(path, Some(false));
            }
        }
        if created_sub {
            let _ = VFS.unlink_trusted(SUB, Some(true));
        }
        let _ = VFS.unlink_trusted(ROOT, Some(true));
        if let Err(msg) = outcome {
            return TestResult::Fail(msg);
        }
        if !matches!(VFS.stat_trusted(ROOT), Err(FsError::NotFound)) {
            return TestResult::Fail(String::from(
                "VFS path resolution cleanup left fixture directory behind",
            ));
        }
        TestResult::Pass
    }
}

/// Directory Operations: Verifies atomicity of directory operations like
/// mkdir/rmdir/unlink. Non-atomic operations can lead to directory corruption
/// or orphaned inodes.
struct VfsDirectoryAtomicityTest;

impl RuntimeTest for VfsDirectoryAtomicityTest {
    fn name(&self) -> &'static str {
        "vfs_directory_atomicity"
    }

    fn description(&self) -> &'static str {
        "Verify directory operations (mkdir/rmdir/unlink) are atomic"
    }

    fn run(&self) -> TestResult {
        use arch::ipi::{send_ipi, IpiType};
        use arch::{current_cpu_id, max_cpus, num_online_cpus, set_ap_test_probe};
        use core::hint::spin_loop;
        use core::sync::atomic::Ordering;
        use mm::tlb_shootdown::is_cpu_online;
        use vfs::{FileMode, FsError, VFS};
        use vfs_smp_race_state::*;

        const ROOT: &str = "/__sq_dir_atom";
        const SUB: &str = "/__sq_dir_atom/sub";
        const FILE_A: &str = "/__sq_dir_atom/a";
        const FILE_B: &str = "/__sq_dir_atom/b";

        // Exclusively claim the fixture root without touching any pre-existing entries.
        if let Err(e) = VFS.create_trusted(ROOT, FileMode::directory(0o755)) {
            return TestResult::Fail(alloc::format!("mkdir {} failed: {:?}", ROOT, e));
        }

        let mut created_sub = false;
        let mut created_file_a = false;
        let mut created_file_b = false;
        let mut ran_smp_race = false;
        let mut ap_still_active = false;

        let outcome: Result<(), String> = (|| {
            VFS.create_trusted(SUB, FileMode::directory(0o755))
                .map_err(|e| alloc::format!("mkdir {} failed: {:?}", SUB, e))?;
            created_sub = true;
            let f_a = VFS
                .create_trusted(FILE_A, FileMode::regular(0o644))
                .map_err(|e| alloc::format!("create {} failed: {:?}", FILE_A, e))?;
            created_file_a = true;
            f_a.write_at(0, b"AAA")
                .map_err(|e| alloc::format!("write a failed: {:?}", e))?;
            let f_b = VFS
                .create_trusted(FILE_B, FileMode::regular(0o644))
                .map_err(|e| alloc::format!("create {} failed: {:?}", FILE_B, e))?;
            created_file_b = true;
            f_b.write_at(0, b"BBBBB")
                .map_err(|e| alloc::format!("write b failed: {:?}", e))?;

            // 1. Non-empty rmdir must fail with NotEmpty and preserve children.
            match VFS.unlink_trusted(ROOT, Some(true)) {
                Err(FsError::NotEmpty) => {}
                other => {
                    return Err(alloc::format!(
                        "rmdir on non-empty dir expected NotEmpty, got {:?}",
                        other
                    ));
                }
            }
            // 2. Type enforcement on unlink vs rmdir.
            match VFS.unlink_trusted(FILE_A, Some(true)) {
                Err(FsError::NotDir) => {}
                other => {
                    return Err(alloc::format!(
                        "rmdir on regular file expected NotDir, got {:?}",
                        other
                    ));
                }
            }
            match VFS.unlink_trusted(SUB, Some(false)) {
                Err(FsError::IsDir) => {}
                other => {
                    return Err(alloc::format!(
                        "unlink on directory expected IsDir, got {:?}",
                        other
                    ));
                }
            }
            // 3. RENAME_NOREPLACE refuses overwrite without disturbing either file;
            //    atomic replace swaps dst cleanly to src's inode/contents.
            match VFS.rename_trusted(FILE_A, FILE_B, true) {
                Err(FsError::Exists) => {}
                other => {
                    return Err(alloc::format!(
                        "rename_noreplace over existing expected Exists, got {:?}",
                        other
                    ));
                }
            }
            let a_ino = f_a.ino();
            VFS.rename_trusted(FILE_A, FILE_B, false)
                .map_err(|e| alloc::format!("atomic rename replace failed: {:?}", e))?;
            if !matches!(VFS.stat_trusted(FILE_A), Err(FsError::NotFound)) {
                return Err(String::from("source entry survived atomic rename"));
            }
            let replaced = VFS
                .stat_trusted(FILE_B)
                .map_err(|e| alloc::format!("stat replaced {} failed: {:?}", FILE_B, e))?;
            if replaced.ino != a_ino || replaced.size != 3 {
                return Err(String::from(
                    "atomic rename destination inode/size mismatch",
                ));
            }

            // 4. On SMP (2+ CPUs), run 32 synchronized two-phase competing
            //    BSP + AP create/unlink rounds on the same absent name:
            //    - Phase A: both compete on create; exactly one succeeds, the
            //      other gets Exists, and stat confirms the entry is present.
            //    - Phase B: both compete on unlink; exactly one succeeds, the
            //      other gets NotFound, and stat confirms the entry is absent.
            if num_online_cpus() >= 2 {
                let self_cpu = current_cpu_id();
                if let Some(target) =
                    (0..max_cpus()).find(|&id| id != self_cpu && is_cpu_online(id))
                {
                    if DIR_ACTIVE_RUN_ID.load(Ordering::Acquire)
                        != DIR_EXITED_RUN_ID.load(Ordering::Acquire)
                    {
                        return Err(String::from(
                            "previous directory atomicity AP worker has not exited yet",
                        ));
                    }

                    DIR_AP_STARTED.store(0, Ordering::Release);
                    DIR_CREATE_ROUND.store(0, Ordering::Release);
                    DIR_AP_CREATE_RES.store(0, Ordering::Release);
                    DIR_AP_CREATE_DONE.store(0, Ordering::Release);
                    DIR_UNLINK_ROUND.store(0, Ordering::Release);
                    DIR_AP_UNLINK_RES.store(0, Ordering::Release);
                    DIR_AP_UNLINK_DONE.store(0, Ordering::Release);
                    let run_id = DIR_ACTIVE_RUN_ID.fetch_add(1, Ordering::AcqRel) + 1;

                    ran_smp_race = true;
                    ap_still_active = true;
                    let _ = set_ap_test_probe(target, Some(vfs_dir_atomicity_ap_worker));
                    send_ipi(target, IpiType::Reschedule);

                    let mut ap_started = false;
                    for _ in 0..50_000_000usize {
                        if DIR_AP_STARTED.load(Ordering::Acquire) == run_id {
                            ap_started = true;
                            break;
                        }
                        spin_loop();
                    }

                    let mut race_err: Option<String> = None;
                    if !ap_started {
                        race_err = Some(alloc::format!(
                            "AP {} failed to start directory atomicity worker",
                            target
                        ));
                    } else {
                        for round in 1..=32u64 {
                            let name = alloc::format!("/__sq_dir_atom/race_{}", round % 4);

                            // Phase A: competing create of the same absent entry.
                            DIR_AP_CREATE_RES.store(0, Ordering::Release);
                            DIR_CREATE_ROUND.store(round, Ordering::Release);
                            let bsp_create = VFS.create_trusted(&name, FileMode::regular(0o644));

                            let mut ap_create_done = false;
                            for _ in 0..50_000_000usize {
                                if DIR_AP_CREATE_DONE.load(Ordering::Acquire) == round {
                                    ap_create_done = true;
                                    break;
                                }
                                spin_loop();
                            }
                            if !ap_create_done {
                                race_err = Some(alloc::format!(
                                    "AP {} timed out on competing create round {}",
                                    target,
                                    round
                                ));
                                break;
                            }
                            let ap_create = DIR_AP_CREATE_RES.load(Ordering::Acquire);
                            let bsp_created = match bsp_create {
                                Ok(_) => true,
                                Err(FsError::Exists) => false,
                                Err(e) => {
                                    race_err = Some(alloc::format!(
                                        "BSP unexpected create error on round {}: {:?}",
                                        round,
                                        e
                                    ));
                                    break;
                                }
                            };
                            let ap_created = match ap_create {
                                1 => true,
                                2 => false,
                                _ => {
                                    race_err = Some(alloc::format!(
                                        "AP unexpected create error on round {}",
                                        round
                                    ));
                                    break;
                                }
                            };
                            if bsp_created == ap_created {
                                race_err = Some(alloc::format!(
                                    "directory create atomicity violation on round {}: bsp={} ap={}",
                                    round,
                                    bsp_created,
                                    ap_created
                                ));
                                break;
                            }
                            if VFS.stat_trusted(&name).is_err() {
                                race_err = Some(alloc::format!(
                                    "created entry {} missing at Phase A boundary (round {})",
                                    name,
                                    round
                                ));
                                break;
                            }

                            // Phase B: competing unlink of the created entry.
                            DIR_AP_UNLINK_RES.store(0, Ordering::Release);
                            DIR_UNLINK_ROUND.store(round, Ordering::Release);
                            let bsp_unlink = VFS.unlink_trusted(&name, Some(false));

                            let mut ap_unlink_done = false;
                            for _ in 0..50_000_000usize {
                                if DIR_AP_UNLINK_DONE.load(Ordering::Acquire) == round {
                                    ap_unlink_done = true;
                                    break;
                                }
                                spin_loop();
                            }
                            if !ap_unlink_done {
                                race_err = Some(alloc::format!(
                                    "AP {} timed out on competing unlink round {}",
                                    target,
                                    round
                                ));
                                break;
                            }
                            let ap_unlink = DIR_AP_UNLINK_RES.load(Ordering::Acquire);
                            let bsp_unlinked = match bsp_unlink {
                                Ok(()) => true,
                                Err(FsError::NotFound) => false,
                                Err(e) => {
                                    race_err = Some(alloc::format!(
                                        "BSP unexpected unlink error on round {}: {:?}",
                                        round,
                                        e
                                    ));
                                    break;
                                }
                            };
                            let ap_unlinked = match ap_unlink {
                                1 => true,
                                2 => false,
                                _ => {
                                    race_err = Some(alloc::format!(
                                        "AP unexpected unlink error on round {}",
                                        round
                                    ));
                                    break;
                                }
                            };
                            if bsp_unlinked == ap_unlinked {
                                race_err = Some(alloc::format!(
                                    "directory unlink atomicity violation on round {}: bsp={} ap={}",
                                    round,
                                    bsp_unlinked,
                                    ap_unlinked
                                ));
                                break;
                            }
                            if !matches!(VFS.stat_trusted(&name), Err(FsError::NotFound)) {
                                race_err = Some(alloc::format!(
                                    "unlinked entry {} still present at Phase B boundary (round {})",
                                    name,
                                    round
                                ));
                                break;
                            }
                        }
                    }

                    // Signal abort/exit to AP and require either probe cancellation
                    // or a matching run-ID exit ack before releasing the fixture.
                    DIR_CREATE_ROUND.store(u64::MAX, Ordering::Release);
                    DIR_UNLINK_ROUND.store(u64::MAX, Ordering::Release);
                    let cancelled = set_ap_test_probe(target, None);
                    if cancelled {
                        DIR_EXITED_RUN_ID.store(run_id, Ordering::Release);
                        ap_still_active = false;
                    } else {
                        for _ in 0..50_000_000usize {
                            if DIR_EXITED_RUN_ID.load(Ordering::Acquire) == run_id {
                                ap_still_active = false;
                                break;
                            }
                            spin_loop();
                        }
                    }
                    if let Some(msg) = race_err {
                        return Err(msg);
                    }
                    if ap_still_active {
                        return Err(alloc::format!(
                            "AP {} timed out exiting directory atomicity worker",
                            target
                        ));
                    }
                }
            }

            Ok(())
        })();

        // Never remove the fixture directory while a timed-out AP worker may
        // still be operating on entries inside it.
        if ap_still_active {
            return match outcome {
                Err(msg) => TestResult::Fail(msg),
                Ok(()) => TestResult::Fail(String::from(
                    "directory atomicity AP worker still active; fixture retained",
                )),
            };
        }

        if ran_smp_race {
            for i in 0..4usize {
                let p = alloc::format!("/__sq_dir_atom/race_{}", i);
                let _ = VFS.unlink_trusted(&p, Some(false));
            }
        }
        if created_file_a {
            let _ = VFS.unlink_trusted(FILE_A, Some(false));
        }
        if created_file_b {
            let _ = VFS.unlink_trusted(FILE_B, Some(false));
        }
        if created_sub {
            let _ = VFS.unlink_trusted(SUB, Some(true));
        }
        let _ = VFS.unlink_trusted(ROOT, Some(true));
        if let Err(msg) = outcome {
            return TestResult::Fail(msg);
        }
        if !matches!(VFS.stat_trusted(ROOT), Err(FsError::NotFound)) {
            return TestResult::Fail(String::from("directory atomicity cleanup left root behind"));
        }
        TestResult::Pass
    }
}

// ============================================================================
// TEST REGISTRY
// ============================================================================

/// Returns all 25 P0 regression tests for registration
pub fn get_all_p0_regression_tests() -> Vec<&'static dyn RuntimeTest> {
    alloc::vec![
        // Category 1: Architecture (5 tests)
        &ContextSwitchRipRflagsTest as &dyn RuntimeTest,
        &TlsIsolationTest,
        &SyscallActiveLeakTest,
        &WorkStealingOnCpuGateTest,
        &FpuStateIrqIsolationTest,
        // Category 2: Memory Management (5 tests)
        &CowTlbShootdownTest,
        &PtChargeTrackingTest,
        &BrkVaReservationToctouTest,
        &StackGuardPageTest,
        &OomGracefulHandlingTest,
        // Category 3: IPC (5 tests)
        &FutexWaitWakeCorrectnessTest,
        &FutexLockPiPriorityInheritanceTest,
        &FutexBucketToctouTest,
        &PipeEintrWakeTest,
        &SignalDeliveryToBlockedSyscallTest,
        // Category 4: Scheduler (5 tests)
        &SmpWorkStealingSafetyTest,
        &NonBlockingGetProcessInIrqTest,
        &ProcessMigrationSafetyTest,
        &SchedulerLoadBalancingTest,
        &CpuAffinityEnforcementTest,
        // Category 5: VFS (5 tests)
        &RamfsBasicOperationsTest,
        &RamfsRenameSelfDeadlockTest,
        &RamfsRenameAncestorToctouTest,
        &VfsPathResolutionTest,
        &VfsDirectoryAtomicityTest,
    ]
}
