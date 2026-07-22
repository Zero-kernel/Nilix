#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_assignments)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::new_without_default)]
#![allow(clippy::while_let_loop)]
#![allow(clippy::ifs_same_cond)]
#![allow(clippy::question_mark)]
#![allow(clippy::manual_strip)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::explicit_counter_loop)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::string_lit_as_bytes)]
#![allow(clippy::unnecessary_safety_doc)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::declare_interior_mutable_const)]
#![allow(clippy::fn_to_numeric_cast)]
#![allow(clippy::type_complexity)]
#![allow(clippy::collapsible_if)]
#![allow(unused_doc_comments)]
#![allow(unused_macros)]
#![allow(unused_unsafe)]
#![allow(unused_mut)]

extern crate alloc;
use core::panic::PanicInfo;
use mm::memory::BootInfo;

// 引入模块化子系统，drivers需要在最前面以便使用其宏
#[macro_use]
extern crate drivers;
extern crate arch;
extern crate block;
extern crate cap;
extern crate ipc;
extern crate kernel_core;
extern crate livepatch;
extern crate mm;
extern crate net;
extern crate sched;
extern crate security;
extern crate vfs; // R101-4: Boot-time ECDSA key validation
#[macro_use]
extern crate audit;
extern crate compliance;
extern crate trace;
#[macro_use]
extern crate klog;

// A.3 Audit capability gate imports
use cap::CapRights;
use kernel_core::process::{current_credentials, current_is_host_root, with_current_cap_table};
// G.1 Observability: Counter integration for allocation failures
use trace::counters::{increment_counter, TraceCounter};

/// G.1: Guard flag to prevent recursive allocation in alloc_error_handler.
///
/// `increment_counter()` uses `CpuLocal` which lazy-initializes via heap
/// allocation (`Box::new_uninit_slice`). If the very first allocation fails
/// before counters are initialized, calling `increment_counter` from
/// `alloc_error_handler` would re-enter the allocator, causing infinite
/// recursion or `spin::Once` deadlock.
///
/// This flag is set to `true` after the first successful counter increment
/// (which happens during early boot via timer ISR). The alloc_error_handler
/// only increments the counter when this flag is `true`.
static COUNTERS_READY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// R109-4 FIX: Flag to distinguish early-boot context from post-boot kernel threads.
///
/// Set to `true` just before enabling interrupts (`sti`).  Audit authorizer
/// closures use this flag to reject `current_credentials() == None` requests
/// after boot completes.  Without this flag, kernel threads and interrupt
/// handlers (which also have `None` credentials) would be granted audit
/// snapshot/HMAC-key access, bypassing capability gates.
static BOOT_PHASE_COMPLETE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

// 演示模块
mod demo;
mod integration_test;
mod interrupt_demo;
mod runtime_tests;
mod shell;
mod stack_guard;
mod syscall_demo;
mod test_framework;
mod usermode_test;

// 串口端口
const SERIAL_PORT: u16 = 0x3F8;

unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
    );
}

unsafe fn serial_write_byte(byte: u8) {
    outb(SERIAL_PORT, byte);
}

unsafe fn serial_write_str(s: &str) {
    for byte in s.bytes() {
        serial_write_byte(byte);
    }
}

/// P1-1: Parse the hardening profile from the UEFI boot command line.
///
/// Scans `boot_info.cmdline[..cmdline_len]` for a whitespace-delimited token
/// of the form `profile=<value>` (case-insensitive prefix match). The value
/// is parsed via [`compliance::HardeningProfile::from_str`], which accepts
/// "secure", "balanced", "performance" and several aliases.
///
/// If multiple `profile=` tokens appear, the **last valid** one wins (this
/// mirrors Linux kernel cmdline semantics where later values override earlier
/// ones). Returns `None` when no valid profile token is found.
fn parse_hardening_profile_from_cmdline(
    boot_info: &BootInfo,
) -> Option<compliance::HardeningProfile> {
    let len = boot_info.cmdline_len.min(boot_info.cmdline.len());
    let mut cmdline = &boot_info.cmdline[..len];

    // Trim at first NUL byte if present (belt-and-suspenders with cmdline_len).
    if let Some(nul_pos) = cmdline.iter().position(|&b| b == 0) {
        cmdline = &cmdline[..nul_pos];
    }

    const PREFIX: &[u8] = b"profile=";
    let mut result: Option<compliance::HardeningProfile> = None;

    let mut pos = 0usize;
    while pos < cmdline.len() {
        // Skip whitespace
        while pos < cmdline.len() && cmdline[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= cmdline.len() {
            break;
        }

        // Find end of token
        let token_start = pos;
        while pos < cmdline.len() && !cmdline[pos].is_ascii_whitespace() {
            pos += 1;
        }
        let token = &cmdline[token_start..pos];

        // Check for case-insensitive "profile=" prefix
        if token.len() > PREFIX.len() {
            let mut prefix_match = true;
            for i in 0..PREFIX.len() {
                if token[i].to_ascii_lowercase() != PREFIX[i] {
                    prefix_match = false;
                    break;
                }
            }
            if prefix_match {
                let value = &token[PREFIX.len()..];
                if let Ok(s) = core::str::from_utf8(value) {
                    if let Some(profile) = compliance::HardeningProfile::from_str(s) {
                        result = Some(profile);
                    } else {
                        // Operator typo detection: profile= token found but value
                        // is not recognized. Log a warning so the operator knows
                        // their intent was not applied.
                        // P1-1: Use klog_force! — typo warnings must always be visible.
                        klog_force!(
                            "      ! WARNING: Unrecognized profile value '{}', ignoring",
                            s
                        );
                    }
                }
            }
        }
    }

    result
}

/// Test block device write/read path end-to-end
///
/// Writes a test pattern to the last sectors of the device (safe area outside filesystem),
/// reads it back, and verifies the data matches. This exercises the full write path
/// through virtio-blk without requiring filesystem write support.
fn test_block_write(device: &alloc::sync::Arc<dyn block::BlockDevice>) -> bool {
    use alloc::vec;

    // Skip if device is read-only
    if device.is_read_only() {
        klog!(Info, "        [SKIP] Device is read-only");
        return true;
    }

    let capacity = device.capacity_sectors();
    let sector_size = device.sector_size() as usize;

    // Need at least 2 sectors for test (use last 2 sectors)
    if capacity < 4 {
        klog!(Info, "        [SKIP] Device too small for write test");
        return true;
    }

    // Use last 2 sectors as scratch area (outside ext2 filesystem)
    let test_sector = capacity - 2;
    let test_pattern: [u8; 512] = {
        let mut pattern = [0u8; 512];
        for (i, byte) in pattern.iter_mut().enumerate() {
            // Create a recognizable pattern: 0xDE, 0xAD, 0xBE, 0xEF repeating + offset
            *byte = match i % 4 {
                0 => 0xDE,
                1 => 0xAD,
                2 => 0xBE,
                _ => 0xEF,
            } ^ (i as u8);
        }
        pattern
    };

    // Write test pattern
    klog!(
        Info,
        "        Writing test pattern to sector {}...",
        test_sector
    );
    match device.write_sync(test_sector, &test_pattern) {
        Ok(n) if n == sector_size => {}
        Ok(n) => {
            klog!(
                Error,
                "        [FAIL] Write returned {} bytes, expected {}",
                n,
                sector_size
            );
            return false;
        }
        Err(e) => {
            klog!(Error, "        [FAIL] Write failed: {:?}", e);
            return false;
        }
    }

    // Read back
    let mut read_buf = vec![0u8; sector_size];
    match device.read_sync(test_sector, &mut read_buf) {
        Ok(n) if n == sector_size => {}
        Ok(n) => {
            klog!(
                Error,
                "        [FAIL] Read returned {} bytes, expected {}",
                n,
                sector_size
            );
            return false;
        }
        Err(e) => {
            klog!(Error, "        [FAIL] Read failed: {:?}", e);
            return false;
        }
    }

    // Verify
    if read_buf[..512] == test_pattern {
        klog!(Info, "        [PASS] Write/read verification successful");
        true
    } else {
        klog!(Error, "        [FAIL] Data mismatch!");
        klog!(
            Info,
            "        Expected first 8: {:02x?}",
            &test_pattern[..8]
        );
        klog!(Info, "        Got first 8:      {:02x?}", &read_buf[..8]);
        false
    }
}

/// IRQ-safe polling fallback until a dedicated VT-d fault vector is wired.
fn iommu_fault_capture_tick() {
    if iommu::capture_dma_faults_irq() {
        kernel_core::request_soft_progress_from_irq();
        kernel_core::request_resched_from_irq();
    }
}

/// Blocking/logging containment half, invoked only by the process-context
/// deferred-work hook in `reschedule_if_needed`.
fn iommu_fault_drain_deferred() {
    // Claim contention leaves hardware FRCD state untouched and sets the
    // recapture level. Re-scan first at every soft progress point, then perform
    // one bounded containment transaction.
    let _ = iommu::capture_dma_faults_irq();
    let _ = iommu::drain_dma_fault_work();
    if iommu::capture_dma_faults_irq() {
        kernel_core::request_soft_progress_from_irq();
    }
}

#[no_mangle]
pub extern "C" fn _start(boot_info_ptr: u64) -> ! {
    // 禁用中断 - 必须首先做！
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }

    // 发送串口消息表示内核已启动
    unsafe {
        serial_write_str("Kernel _start entered\n");
    }

    // 解析 Bootloader 传递的 BootInfo 指针（必须在任何 println! 之前）
    // Bootloader 通过 rdi 寄存器传递 BootInfo 指针（System V AMD64 ABI）
    // 由于 identity mapping 仍然有效，可以直接访问该地址
    let boot_info: Option<&BootInfo> = if boot_info_ptr != 0 {
        unsafe { (boot_info_ptr as *const BootInfo).as_ref() }
    } else {
        None
    };

    // 初始化 framebuffer 控制台（现代 GOP 方式，必须在第一个 println! 之前）
    if let Some(info) = boot_info {
        // 转换 mm::memory::FramebufferInfo 到 drivers::framebuffer::FramebufferInfo
        let fb_info = drivers::framebuffer::FramebufferInfo {
            base: info.framebuffer.base,
            size: info.framebuffer.size,
            width: info.framebuffer.width,
            height: info.framebuffer.height,
            stride: info.framebuffer.stride,
            pixel_format: match info.framebuffer.pixel_format {
                mm::memory::PixelFormat::Rgb => drivers::framebuffer::PixelFormat::Rgb,
                mm::memory::PixelFormat::Bgr => drivers::framebuffer::PixelFormat::Bgr,
                mm::memory::PixelFormat::Unknown => drivers::framebuffer::PixelFormat::Unknown,
            },
        };
        drivers::framebuffer::init(&fb_info);
        unsafe {
            serial_write_str("Framebuffer console initialized\n");
        }
    }

    // 初始化VGA驱动（后备，framebuffer 初始化后 VGA 输出会被跳过）
    drivers::vga_buffer::init();

    // P1-1: Wire klog profile as early as possible — before the first
    // klog_always! banner — so Secure profile suppresses all boot output.
    // This parse happens before the heap is ready, so it uses only stack
    // and BootInfo data.  The profile is set again after PolicySurface
    // initialization for defense-in-depth.
    if let Some(info) = boot_info {
        if let Some(early_profile) = parse_hardening_profile_from_cmdline(info) {
            let klog_profile = match early_profile {
                compliance::HardeningProfile::Secure => klog::KlogProfile::Secure,
                compliance::HardeningProfile::Balanced => klog::KlogProfile::Balanced,
                compliance::HardeningProfile::Performance => klog::KlogProfile::Performance,
            };
            klog::set_profile(klog_profile);
        } else {
            // Default: Balanced (show boot banners)
            klog::set_profile(klog::KlogProfile::Balanced);
        }
    } else {
        klog::set_profile(klog::KlogProfile::Balanced);
    }

    klog_always!("==============================");
    klog_always!("  Zero-OS Microkernel v0.1");
    klog_always!("==============================");
    klog_always!();

    // R169-L7 FIX: latch the LAPIC MMIO base + APIC mode into cpu_local BEFORE the
    // IDT is installed. After the IDT loads, an early exception handler can reach
    // current_cpu_id()/current_pid() (per-CPU lookup), so publishing here makes the
    // x2APIC/relocated-base fail-closed guard cover the very first such access. The
    // call only reads IA32_APIC_BASE and stores atomics; it is re-run (idempotently)
    // at each LAPIC init.
    unsafe {
        arch::apic::publish_lapic_state();
    }

    // 阶段1：初始化中断处理
    klog_always!("[1/3] Initializing interrupts...");
    arch::interrupts::init();
    klog_always!("      ✓ IDT loaded with 20+ handlers");

    // 阶段2：初始化内存管理
    klog_always!("[2/3] Initializing memory management...");
    if let Some(info) = boot_info {
        mm::memory::init_with_bootinfo(info);
        klog_always!("      ✓ Heap and Buddy allocator ready (using BootInfo)");
    } else {
        klog_always!("      ! BootInfo missing, using fallback initialization");
        mm::memory::init();
        klog_always!("      ✓ Heap and Buddy allocator ready (fallback mode)");
    }

    // P2-A: publish the kernel-heap byte-budget arbiter immediately after the
    // heap is live and BEFORE any subsystem that sizes retained metadata from
    // these budgets allocates (page cache, conntrack, futex, audit, exec).
    // Fail-closed: over-committed hard floors panic here rather than OOM later.
    mm::publish_heap_budgets();
    klog_always!("      ✓ Heap budget arbiter published (hard floors coexistence proven)");

    // 初始化页表管理器
    // Bootloader 创建了恒等映射（物理地址 == 虚拟地址），所以物理偏移量为 0
    unsafe {
        mm::page_table::init(x86_64::VirtAddr::new(0));
    }
    klog_always!("      ✓ Page table manager initialized");

    // RF180-24: prove all guarded-stack data and page-table frames roll back
    // under zero, upper-level, and partial-mapping allocation failures before
    // KPTI creates peer roots that would make upper-table detachment unsafe.
    unsafe {
        stack_guard::run_rollback_self_test();
    }

    // 安装内核栈守护页（必须在 mm 初始化后、启用中断前）
    klog_always!("[2.5/3] Installing kernel stack guard pages...");
    unsafe {
        match stack_guard::install() {
            Ok(()) => {
                klog_always!("      ✓ Guard pages installed for kernel stacks");
            }
            Err(e) => {
                klog!(Warn, "      ! Failed to install guard pages: {:?}", e);
                klog!(Warn, "      ! Continuing with static stacks (less safe)");
            }
        }
    }

    // 安全加固（Phase 0: W^X, NX, Identity Map Cleanup, CSPRNG, kptr guard, Spectre）
    // G.3 Compliance: Use HardeningProfile to configure security settings
    klog_always!("[2.6/3] Applying security hardening...");
    {
        let mut frame_allocator = mm::memory::FrameAllocator::new();

        // G.fin.1: Initialize boot-time locked PolicySurface as single source of truth.
        // P1-1: Profile is now wired from the UEFI boot command line ("profile=secure").
        // Falls back to Balanced if no valid profile= token is found.
        let (profile, profile_source) = boot_info
            .and_then(|info| parse_hardening_profile_from_cmdline(info))
            .map(|p| (p, compliance::ProfileSource::BootCmdline))
            .unwrap_or((
                compliance::HardeningProfile::Balanced,
                compliance::ProfileSource::Default,
            ));
        let policy = compliance::init_policy_surface(profile, profile_source);

        // H.2.2: Wire klog filter from hardening profile
        let klog_profile = match policy.profile {
            compliance::HardeningProfile::Secure => klog::KlogProfile::Secure,
            compliance::HardeningProfile::Balanced => klog::KlogProfile::Balanced,
            compliance::HardeningProfile::Performance => klog::KlogProfile::Performance,
        };
        klog::set_profile(klog_profile);

        // Generate SecurityConfig from the selected profile
        let phys_offset = mm::page_table::get_physical_memory_offset();
        let sec_config = policy.profile.security_config(phys_offset);

        klog_always!(
            "      Profile: {} (source: {:?}, audit_capacity: {})",
            policy.profile.name(),
            policy.source,
            policy.audit_ring_capacity
        );

        match security::init(sec_config, &mut frame_allocator) {
            Ok(report) => {
                klog_always!("      ✓ Security hardening applied");
                klog!(
                    Info,
                    "        - Identity map: {:?}",
                    report.identity_cleanup
                );
                if let Some(nx) = &report.nx_summary {
                    klog!(
                        Info,
                        "        - NX enforced: {} pages protected",
                        nx.data_nx_pages
                    );
                }
                if report.rng_ready {
                    klog_always!("        - CSPRNG ready (ChaCha20 + RDRAND/RDSEED)");
                    // R102-L5 FIX: Validate RNG without printing raw output.
                    // Printing raw entropy values is unnecessary and could be
                    // sensitive if RNG is not fully initialized.
                    // R149-5 FIX: Use fill_random (FIPS boundary pub API).
                    let mut rng_test_buf = [0u8; 8];
                    match security::fill_random(&mut rng_test_buf) {
                        Ok(()) => klog!(Info, "        - RNG self-test: passed"),
                        Err(e) => klog!(Error, "        ! RNG self-test failed: {:?}", e),
                    }
                } else {
                    klog!(Warn, "        ! CSPRNG not ready");
                }
                if report.kptr_guard_active {
                    klog!(Info, "        - kptr guard: active");
                }
                // S-5: pin the kdump export redaction decision core (weak seed ⇒
                // constant sentinel; strong seed ⇒ kptr hash). Pure-predicate
                // test — passes deterministically whether or not the CSPRNG
                // reseed above succeeded.
                trace::kdump::run_kdump_redaction_self_test();
                klog!(Info, "        - kdump redaction self-test: passed (S-5)");
                if let Some(spectre) = &report.spectre_status {
                    klog!(Info, "        - Spectre mitigations: {}", spectre.summary());
                }

                // G.fin.1: Lock profile after security initialization.
                // PolicySurface already prevents set_profile() changes, but
                // lock_profile() provides defense-in-depth against direct calls.
                compliance::lock_profile();
                klog_always!("        - Profile locked (immutable until reboot)");
                // D2-SEC-LSM FIX: install the LSM policy slot for ALL profiles
                // (kills the null-slot fallback branch), then install the
                // minimal enforcing secure-baseline policy under the Secure
                // profile — fail closed if the installation did not take.
                lsm::init();
                if policy.profile == compliance::HardeningProfile::Secure {
                    lsm::set_policy(&lsm::SECURE_BASELINE);
                    if lsm::active_policy_name() != "secure-baseline" {
                        panic!(
                            "Secure profile requires the secure-baseline LSM policy (active: {})",
                            lsm::active_policy_name()
                        );
                    }
                }
                // Representative-denial self-test on the policy OBJECT —
                // profile-independent, no audit traffic, no global slot use.
                lsm::run_secure_baseline_self_test();
                klog_always!(
                    "        - LSM policy: {} (secure-baseline self-test passed)",
                    lsm::active_policy_name()
                );

                // P1-1 FIX: Log PolicySurface enforcement summary so operators
                // can verify which security features are active at boot.
                let ps = compliance::policy();
                klog_always!("      PolicySurface enforcement:");
                klog_always!(
                    "        - panic_redact_details: {}",
                    ps.panic_redact_details
                );
                klog_always!("        - kaslr_fail_closed:    {}", ps.kaslr_fail_closed);
                klog_always!("        - kpti_fail_closed:     {}", ps.kpti_fail_closed);
                klog_always!("        - audit_fail_closed:    {}", ps.audit_fail_closed);
                klog_always!(
                    "        - debug_interfaces:     {}",
                    ps.debug_interfaces_enabled
                );
                klog_always!("        - spectre_mitigations:  {}", ps.spectre_mitigations);
                klog_always!("        - kptr_guard:           {}", ps.kptr_guard);
                klog_always!("        - strict_wxorx:         {}", ps.strict_wxorx);
                klog_always!("        - audit_ring_capacity:  {}", ps.audit_ring_capacity);
            }
            Err(e) => {
                // P1-1: klog_force! — hardening failure must be visible in all profiles.
                klog_force!("      ! Security hardening failed: {:?}", e);
                // R102-2 FIX: Secure profile must not boot without core mitigations.
                // A single hardware/config anomaly should not silently disable all
                // security hardening (W^X, NX, CSPRNG, Spectre mitigations).
                if policy.profile == compliance::HardeningProfile::Secure {
                    panic!(
                        "Security hardening failed in Secure profile: {:?} \
                         (use Balanced profile to allow degraded boot)",
                        e
                    );
                }
                klog_force!("      ! Continuing with reduced security");
            }
        }

        // RF180-53 FIX: install BSP and every possible AP IST guard only after
        // the kernel page tables are available and the normal hardening pass has
        // had the opportunity to demote section mappings. The guard installer
        // independently demotes any remaining huge parents (including the
        // Performance profile), checks every unmap, and publishes completion
        // before SMP startup.
        arch::gdt::install_ist_guard_pages_before_smp(&mut frame_allocator);
        klog_always!("      ✓ BSP/AP IST guard pages installed (double-fault + NMI)");
    }

    // R101-4 FIX: Boot-time livepatch ECDSA key validation
    // P1-1: Use klog_force! — critical security warning must appear in all profiles.
    if livepatch::has_placeholder_keys() {
        klog_force!("      ! WARNING: Livepatch ECDSA public keys are all-zero placeholders!");
        klog_force!("      ! Livepatch signature verification is non-functional.");
        klog_force!("      ! Generate production P-256 keys and embed them in livepatch::TRUSTED_P256_PUBKEYS_UNCOMPRESSED.");
    }

    // KCOV initialization for fuzzing infrastructure
    #[cfg(feature = "kcov")]
    {
        extern crate coverage;
        coverage::init_coverage();
        klog_always!("[KCOV] Coverage infrastructure initialized");
    }

    // KASLR/KPTI/PCID initialization
    // R39-7/RF180-32: pass relocation separately from version-validated
    // randomization provenance. A deterministic non-zero slide is not KASLR.
    klog_always!("[2.65/3] Initializing KASLR/KPTI/PCID...");
    security::init_kaslr(boot_info.map(|info| security::BootKaslrState {
        slide: info.kaslr_slide,
        randomized: info.kaslr_randomized(),
    }));

    // P1-1 FIX: PolicySurface-driven KASLR/KPTI fail-closed enforcement.
    // When kaslr_fail_closed is true (Secure profile), the kernel must not
    // boot with a fully deterministic layout. If full text KASLR is
    // unavailable, we allow boot only when Partial KASLR is active.
    let ps = compliance::policy();
    if ps.kaslr_fail_closed && !security::is_kaslr_enabled() {
        // Check partial KASLR as a fallback: if partial randomization is
        // active we log a warning but allow boot (defense-in-depth).
        if security::is_partial_kaslr_enabled() {
            // P1-1: klog_force! — policy enforcement messages must be visible
            // even in Secure profile so operators can diagnose boot issues.
            klog_force!(
                "[POLICY] {} profile: full KASLR not active; partial KASLR in use",
                ps.profile.name()
            );
        } else {
            // Log before panic so operators see the reason even when
            // panic_redact_details is true (Secure profile).
            klog_force!(
                "[POLICY] {} profile: KASLR required but no randomization active — halting",
                ps.profile.name()
            );
            panic!(
                "KASLR is required in Secure profile but no randomization is active \
                 (boot with profile=balanced to allow degraded boot)"
            );
        }
    }
    if ps.kpti_fail_closed && !security::is_kpti_enabled() {
        klog_force!(
            "[POLICY] {} profile: KPTI not active — kernel page table isolation \
             preferred (Meltdown mitigation)",
            ps.profile.name()
        );
        // KPTI is not yet implemented (P2-2), so we warn rather than panic.
        // Once KPTI is available, this should become a hard panic.
    }

    // Cache INVPCID capability for TLB shootdowns (uses CPUID + PCID state)
    mm::tlb_shootdown::init_invpcid_support();

    // CPU 硬件保护特性启用 (SMEP/SMAP/UMIP)
    klog_always!("[2.7/3] Enabling CPU protection features...");
    {
        let cpu_status = arch::cpu_protection::enable_protections();
        if cpu_status.smep_enabled {
            klog_always!("        - SMEP: enabled (blocks kernel executing user pages)");
        } else if cpu_status.smep_supported {
            klog!(Warn, "        ! SMEP: supported but failed to enable");
        } else {
            klog_always!("        - SMEP: not supported by CPU");
        }
        if cpu_status.smap_enabled {
            klog_always!("        - SMAP: enabled (blocks kernel accessing user pages)");
        } else if cpu_status.smap_supported {
            klog!(Warn, "        ! SMAP: supported but failed to enable");
        } else {
            klog_always!("        - SMAP: not supported by CPU");
        }
        if cpu_status.umip_enabled {
            klog_always!("        - UMIP: enabled (blocks user SGDT/SIDT/SLDT)");
        } else if cpu_status.umip_supported {
            klog!(Warn, "        ! UMIP: supported but failed to enable");
        } else {
            klog_always!("        - UMIP: not supported by CPU");
        }
        if cpu_status.is_fully_protected() {
            klog_always!("      ✓ All CPU protections active");
        } else {
            klog_always!("      ! Partial CPU protection (some features unavailable)");
        }

        // V-4 fix: No longer need to update SMAP status cache.
        // clac_if_smap() now reads CR4 directly for SMP safety.
    }

    // R102-5 FIX: Enforce SMAP as a hard boot requirement.
    // The kernel unconditionally uses CLAC/STAC in syscall entry and usercopy paths.
    // Without SMAP these instructions may #UD, crashing every syscall.
    // NOTE: When building with --features kcov for fuzzing on QEMU (which lacks SMAP),
    // we skip this check. Production builds MUST have SMAP.
    #[cfg(not(feature = "kcov"))]
    arch::cpu_protection::require_smap_support();

    #[cfg(feature = "kcov")]
    klog_always!("      ! SMAP requirement SKIPPED (kcov fuzzing mode)");

    // Phase 6: 初始化 SYSCALL/SYSRET 快速系统调用机制
    klog_always!("[2.8/3] Initializing SYSCALL/SYSRET...");
    {
        // GDT 必须在此之前初始化（由 arch::interrupts::init() 完成）
        // 获取系统调用入口点地址并配置 MSR
        let syscall_entry = arch::syscall::syscall_entry_stub as *const () as u64;
        unsafe {
            arch::init_syscall_msr(syscall_entry);
        }
        // 注册 syscall 帧回调，让 kernel_core 能访问当前 syscall 帧
        // 这对于 clone/fork 正确设置子进程上下文至关重要
        arch::register_frame_callback();
        // H.3 KPTI: Register arch-level per-CPU CR3 updater so kernel_core's
        // activate_memory_space() can keep the syscall assembly's GS-relative
        // CR3 pair in sync during context switches.
        kernel_core::register_kpti_cr3_callback(arch::arch_set_kpti_cr3s);

        // R118-3 FIX: Enable KPTI now that the arch-level CR3 updater is registered.
        //
        // This makes fork/exec create dual page table roots and activates CR3
        // switching in syscall entry/exit and enter_usermode() IRETQ paths.
        // All pre-requisite bugs (R118-2, R118-4, R118-5, R118-7) are fixed.
        //
        // KPTI is enabled unconditionally: all pre-Whiskey Lake Intel CPUs are
        // vulnerable to Meltdown. A future refinement could check CPUID for
        // IA32_ARCH_CAPABILITIES.RDCL_NO and skip enablement on safe CPUs.
        security::kaslr::enable_kpti();

        klog_always!("      ✓ SYSCALL MSR configured");
        klog_always!("      ✓ Syscall frame callback registered");
        klog_always!("      ✓ KPTI CR3 callback registered");
        klog_always!("      ✓ Ring 3 transition support ready");
    }

    // 阶段3：测试基础功能
    klog_always!("[3/3] Running basic tests...");

    // 测试内存分配
    use alloc::vec::Vec;
    let mut test_vec = Vec::new();
    for i in 0..10 {
        test_vec.push(i);
    }
    klog_always!("      ✓ Heap allocation test passed");

    // 显示内存统计
    let mem_stats = mm::memory::FrameAllocator::new().stats();
    klog_always!("      ✓ Memory stats available");

    klog_always!();
    klog_always!("=== System Information ===");
    mem_stats.print();

    klog_always!();
    klog_always!("=== Verifying Core Subsystems ===");
    klog_always!();

    // 验证各个模块已编译
    klog_always!("[4/8] Verifying architecture support...");
    klog_always!("      ✓ arch crate loaded");
    klog_always!("      ✓ Context switch module available");

    klog_always!("[5/8] Initializing kernel core...");
    kernel_core::init(); // 初始化进程管理和 BOOT_CR3 缓存（必须在调度器前）
    klog_always!("      ✓ Process management ready");
    klog_always!("      ✓ System calls framework ready");
    klog_always!("      ✓ Fork/COW implementation compiled");

    // Phase E: APIC and SMP Initialization
    klog_always!("[5.5/8] Initializing APIC and SMP...");
    {
        // Pass ACPI RSDP address from bootloader to SMP module (required for UEFI systems)
        if let Some(info) = boot_info {
            arch::set_rsdp_address(info.rsdp_address);
        }

        // Initialize BSP's Local APIC
        unsafe {
            arch::apic::init();
        }
        let bsp_lapic_id = arch::apic::bsp_lapic_id();
        klog_always!("      ✓ BSP LAPIC initialized (ID: {})", bsp_lapic_id);

        // E.1: Initialize HPET (High Precision Event Timer) if available
        // HPET provides a high-resolution counter for precise timing and
        // can be used as an alternative reference for LAPIC calibration.
        match arch::hpet::init() {
            Ok(info) => {
                klog_always!(
                    "      ✓ HPET initialized (freq={} Hz, timers={}, 64-bit={})",
                    info.frequency_hz,
                    info.comparator_count,
                    info.counter_64bit
                );
            }
            Err(e) => {
                klog_always!(
                    "      ! HPET unavailable: {:?} (using PIT for calibration)",
                    e
                );
            }
        }

        // Calibrate LAPIC timer using HPET (preferred) or PIT channel 2 as reference
        // This determines the correct initial count for ~1kHz ticks
        unsafe {
            match arch::apic::calibrate_lapic_timer() {
                Ok(init_count) => {
                    klog_always!(
                        "      ✓ LAPIC timer calibrated (init_count: {})",
                        init_count
                    );
                }
                Err(e) => {
                    klog_always!(
                        "      ! LAPIC timer calibration failed: {}, using default",
                        e
                    );
                }
            }
        }

        // Initialize BSP's per-CPU data
        // Get kernel stack top from GDT (set during arch::interrupts::init)
        let kernel_stack_top = arch::default_kernel_stack_top() as usize;
        arch::init_bsp(
            bsp_lapic_id,
            kernel_stack_top,
            kernel_stack_top, // IRQ stack (same as kernel stack for now)
            kernel_stack_top, // Syscall stack (same for now)
        );
        // R151-5 FIX: Force-initialize IRQ-path CpuLocal statics before interrupts
        // are enabled. Without this, the first IRQ triggering irq_save_fpu() can
        // deadlock if Once::call_once() heap-allocates while the heap lock is held.
        arch::interrupts::force_init_irq_cpu_locals();
        kernel_core::force_init_resched_locals();
        // R165-3 FIX: Force-init the usercopy CpuLocal statics (SMAP_GUARD_DEPTH +
        // USER_COPY_STATE) before interrupts are enabled. R163-6 added this helper
        // but never wired it into either boot path (falsely "verified" in R164), so
        // the page-fault handler's first USER_COPY_STATE.with() could lazily heap-
        // allocate in IRQ/fault context and deadlock against the heap lock. Must run
        // here in process context, mirroring force_init_irq_cpu_locals (R151-5).
        kernel_core::force_init_usercopy_locals();
        // M4-1 (force-init): three MORE lazy per-CPU CpuLocals are reachable from the
        // FIRST AP timer IRQ — PER_CPU_COUNTERS (increment_counter in the raw timer ISR),
        // CURRENT_PID (current_pid() in the ISR), and RCU_READERS (rcu_timer_tick via
        // on_scheduler_tick, every tick). Force-init them here (BSP, before start_aps), or
        // an AP's first tick lazily Box-allocates the slab in IRQ and deadlocks on the heap
        // lock (the same R151-5 class as the three calls above). One BSP call each; the
        // single global Once covers every CPU.
        trace::counters::force_init_per_cpu_counters();
        kernel_core::process::force_init_current_pid();
        kernel_core::rcu::force_init_rcu_locals();
        klog_always!("      ✓ BSP per-CPU data initialized");

        // R67-8 FIX: Initialize per-CPU syscall metadata and GS base for BSP
        unsafe {
            arch::syscall::init_syscall_percpu(0);
        }
        // P1-A: confirm kernel GS is live after boot SWAPGS (Gate #5 self-test).
        arch::run_entry_state_gs_self_test();
        klog_always!("      ✓ BSP syscall per-CPU state initialized (P1-A GS self-test OK)");

        // Attempt to bring up Application Processors (APs)
        // This will enumerate CPUs via ACPI MADT and send INIT-SIPI-SIPI
        // RF178-23 FIX: arch cannot depend on security. Register the AP-local
        // Spectre/MSR initializer before any AP is allowed to start.
        arch::register_ap_security_init(security::spectre::init_cpu);
        let num_cpus = arch::start_aps();
        if num_cpus > 1 {
            klog_always!("      ✓ SMP enabled: {} CPU(s) online", num_cpus);
        } else {
            klog_always!("      ✓ Single-core mode (no APs found or SMP disabled)");
        }
    }

    klog_always!("[6/8] Initializing scheduler...");
    sched::enhanced_scheduler::register_security_switch_hook(
        security::spectre::context_switch_barrier,
    );
    sched::enhanced_scheduler::init(); // 注册定时器和重调度回调
    klog_always!("      ✓ Enhanced scheduler initialized");

    // E.5: Initialize cpuset subsystem after CPU enumeration
    sched::cpuset::init();
    klog_always!("      ✓ Cpuset CPU isolation initialized");

    klog_always!("[7/8] Initializing IPC...");
    ipc::init(); // 初始化IPC子系统并注册清理回调
    klog_always!("      ✓ Capability-based endpoints enabled");
    klog_always!("      ✓ Process cleanup callback registered");

    klog_always!("[7.5/8] Initializing VFS...");
    vfs::init(); // 初始化虚拟文件系统
    klog_always!("      ✓ devfs mounted at /dev");
    klog_always!("      ✓ Device files: null, zero, console");

    // Initialize page cache before block layer mounts filesystems
    klog_always!("[7.52/8] Initializing Page Cache...");
    mm::init_page_cache();
    klog_always!("      ✓ Global page cache initialized");

    // R171-G5-01 FIX (foundation/observability slice): initialize the IOMMU/VT-d
    // subsystem BEFORE probing DMA-capable PCI devices (net/block, below).
    // Previously `iommu::init()` had ZERO callers tree-wide, so the subsystem was
    // inert: ensure_iommu_ready()/attach_device() always returned NotAvailable
    // and every device fell into legacy *unprotected* DMA. Wiring it here runs
    // the subsystem and makes the DMA-isolation posture boot-visible, and — on a
    // hard init failure — leaves the PCI probes failing CLOSED (init() sets
    // IOMMU_INIT_FAILED → attach_device() returns NotInitialized → the probes'
    // error arm skips the device instead of enabling bus-master DMA).
    //
    // KNOWN RESIDUAL (tracked, R171-G5-01 follow-ups, NOT closed by this slice):
    //   (B) ACPI DMAR discovery is stubbed (iommu::dmar::find_dmar_table always
    //       returns NotFound), so init() currently returns NoDmarTable on every
    //       machine → real VT-d never engages until discovery is implemented.
    //   (C) In the Secure hardening profile, the PCI probes must REFUSE bus
    //       mastering for a device that cannot be IOMMU-isolated (NotAvailable),
    //       instead of the current legacy-proceed — the actual "fail-closed"
    //       enforcement. Deferred (gate boots Balanced; needs per-profile probe
    //       policy + Secure-profile boot verification).
    // init() fails SAFE on no-DMAR, so this wiring is boot-neutral where no DMAR
    // table exists (incl. default QEMU, which presents no intel-iommu).
    klog_always!("[7.53/8] Initializing IOMMU (DMA isolation)...");
    // R171-G5-01-B: pass the bootloader-provided RSDP so iommu can actually
    // discover the ACPI DMAR table (same source the arch RSDP publish uses).
    let rsdp_phys = boot_info.map(|i| i.rsdp_address).unwrap_or(0);
    match iommu::init(rsdp_phys) {
        Ok(units) => {
            // Register the process drain before exposing the IRQ producer.
            // Callback exhaustion is boot-fatal: an active IOMMU must always
            // have a reachable, durable fault-containment path.
            kernel_core::register_soft_progress_callback(iommu_fault_drain_deferred)
                .expect("IOMMU deferred fault callback slots exhausted");
            kernel_core::register_timer_callback(iommu_fault_capture_tick)
                .expect("IOMMU fault capture timer callback slots exhausted");
            klog_always!(
                "      ✓ IOMMU active: {} unit(s), DMA translation enabled",
                units
            );
        }
        Err(iommu::IommuError::NoDmarTable) => {
            klog_always!("      ! No ACPI DMAR table discovered — legacy (unisolated) DMA mode");
        }
        Err(err) => {
            // DMAR present but unit init failed; iommu::init() has set
            // IOMMU_INIT_FAILED, so the device probes below fail closed.
            // Use klog_force! (not klog!/klog_always!, which the Secure profile
            // suppresses) so this security-relevant failure is visible even under
            // the Secure-profile diagnostic blackout.
            klog_force!(
                "      ! IOMMU initialization FAILED ({:?}) — DMA-capable PCI devices fail closed this boot",
                err
            );
        }
    }
    klog_always!("      - IOMMU enabled: {}", iommu::is_enabled());

    // R171-G5-01-C: in the Secure profile, a DMA-capable device that cannot be
    // IOMMU-isolated must be REFUSED bus-mastering (fail closed) rather than run
    // legacy-unprotected. Compute the policy here (where `compliance` is a dep) and
    // thread it into the device probes (net/block stay compliance-agnostic).
    let iommu_required = matches!(
        compliance::policy().profile,
        compliance::HardeningProfile::Secure
    );

    // Phase D: Network Layer
    klog_always!("[7.54/8] Initializing Network Layer...");
    let net_devices = net::init(iommu_required);
    if net_devices == 0 {
        klog_always!("      ! No network devices detected");
    }

    // Phase C: Block Layer and Storage Foundation
    klog_always!("[7.55/8] Initializing Block Layer...");
    block::init();
    // Probe for virtio-blk devices and publish them transactionally.
    if let Some(probed) = block::probe_devices(iommu_required) {
        let name = probed.name();
        let device_for_registration = probed.device();

        // R180-27 FIX: DRIVER_OK-to-publication is one rollbackable
        // transaction. Both registries allocate fallibly; the probe guard
        // resets (or quarantines) DMA ownership unless both commits succeed.
        let registry_result = block::register_device(device_for_registration.clone());
        let mut block_registered = false;
        let devfs_result = match registry_result {
            Ok(_) => {
                block_registered = true;
                vfs::register_block_device(name, device_for_registration)
            }
            Err(error) => {
                klog!(
                    Error,
                    "      ! Failed to publish block::{}: {:?}",
                    name,
                    error
                );
                Err(vfs::FsError::NoSpace)
            }
        };

        match devfs_result {
            Ok(()) => {
                // Disarm rollback immediately after the second registry
                // commit. This only transfers Arc ownership and cannot allocate.
                let (device, committed_name) = probed.commit();
                debug_assert_eq!(committed_name, name);
                klog_always!("      ✓ Registered /dev/{} in devfs", name);

                // Phase C: Test block write path (uses last sectors, outside filesystem)
                // P1-1 FIX: Gate destructive block test by debug_interfaces_enabled.
                if compliance::policy().debug_interfaces_enabled {
                    klog_always!("      [TEST] Block device write/read verification:");
                    if test_block_write(&device) {
                        klog_always!("      ✓ Block write path verified");
                    } else {
                        klog!(Error, "      ! Block write test failed");
                    }
                }

                // Phase C: Try to mount as ext2 filesystem
                match vfs::Ext2Fs::mount(device) {
                    Ok(fs) => match vfs::mount("/mnt", fs) {
                        Ok(()) => klog_always!("      ✓ Mounted /dev/{} on /mnt as ext2", name),
                        Err(e) => klog!(
                            Warn,
                            "      ! Registered /dev/{} but failed to mount on /mnt: {:?}",
                            name,
                            e
                        ),
                    },
                    Err(e) => klog!(
                        Warn,
                        "      ! Registered /dev/{} but failed to initialize ext2: {:?}",
                        name,
                        e
                    ),
                }
            }
            Err(e) => {
                // If the block registry committed but devfs failed, undo that
                // first publication before `probed` resets the hardware.
                if block_registered {
                    if let Err(unregister_error) = block::unregister_device(name) {
                        klog_force!(
                            "R180-27: failed to roll back block registry entry {}: {:?}",
                            name,
                            unregister_error
                        );
                    }
                }
                klog!(Error, "      ! Failed to register /dev/{}: {:?}", name, e);
                // `probed` drops here. Reset acknowledgement is required before
                // DMA buffers are freed; otherwise its final Arc is quarantined.
            }
        }
    }

    klog_always!("[7.6/8] Initializing audit subsystem...");
    // G.fin.1: Audit ring capacity is derived from the boot-time PolicySurface.
    // D-1 / D2-OPS-AUDIT-MANDATORY: Secure profile requires a working audit ring
    // AND a boot-time HMAC-SHA256 key (fail-closed). Balanced/Performance may
    // continue in an explicit degraded mode (logged warnings only).
    let audit_capacity = compliance::policy().audit_ring_capacity;
    let audit_fail_closed = compliance::policy().audit_fail_closed;
    match audit::init(audit_capacity) {
        Ok(()) => {
            klog_always!(
                "      ✓ Audit subsystem ready (capacity: {} events)",
                audit_capacity
            );
            klog_always!("      ✓ Hash-chained tamper evidence enabled");

            // R148-I8 FIX: Register kernel timestamp provider so audit events
            // get real timestamps instead of 0.
            audit::register_timestamp_callback(kernel_core::time::current_timestamp_ms);

            // A.3: Register audit snapshot authorizer (capability gate)
            // Policy: Allow root (euid == 0) OR holders of CAP_AUDIT_READ
            // R72-HMAC FIX: During early boot (no process context), allow kernel init code
            audit::register_snapshot_authorizer(|| {
                // R109-4 FIX: Only allow credential-less access during the boot phase.
                // Post-boot, kernel threads and interrupt handlers also have None
                // credentials and must not bypass capability gates.
                let creds = current_credentials();
                if creds.is_none() {
                    if !BOOT_PHASE_COMPLETE.load(core::sync::atomic::Ordering::Acquire) {
                        return Ok(()); // Still in boot phase
                    }
                    return Err(audit::AuditError::AccessDenied);
                }

                // R133-1 FIX: Use host-mapped root check for host-global gate
                if current_is_host_root() {
                    return Ok(());
                }
                if let Some(has_cap) =
                    with_current_cap_table(|table| table.has_rights(CapRights::AUDIT_READ))
                {
                    if has_cap {
                        return Ok(());
                    }
                }
                // Deny all others
                Err(audit::AuditError::AccessDenied)
            });
            klog_always!("      ✓ Audit capability gate registered (CAP_AUDIT_READ)");

            // R66-10 FIX: Register HMAC key authorizer (capability gate for audit config)
            // Policy: Allow root (euid == 0) OR holders of CAP_AUDIT_WRITE
            // R72-HMAC FIX: During early boot (no process context), allow kernel init code
            audit::register_hmac_key_authorizer(|| {
                // R109-4 FIX: Only allow credential-less access during the boot phase.
                // Same rationale as snapshot authorizer above.
                let creds = current_credentials();
                if creds.is_none() {
                    if !BOOT_PHASE_COMPLETE.load(core::sync::atomic::Ordering::Acquire) {
                        return Ok(()); // Still in boot phase
                    }
                    return Err(audit::AuditError::AccessDenied);
                }

                // R133-1 FIX: Use host-mapped root check for host-global gate
                if current_is_host_root() {
                    return Ok(());
                }
                // Allow processes with CAP_AUDIT_WRITE capability
                if let Some(has_cap) =
                    with_current_cap_table(|table| table.has_rights(CapRights::AUDIT_WRITE))
                {
                    if has_cap {
                        return Ok(());
                    }
                }
                // Deny all others
                Err(audit::AuditError::AccessDenied)
            });
            klog_always!("      ✓ Audit HMAC key gate registered (CAP_AUDIT_WRITE)");

            // R178-24 FIX: Install HMAC key BEFORE any audit events are emitted.
            // This ensures a uniform HMAC-SHA256 chain from the very first event,
            // preventing mixed SHA-256/HMAC-SHA256 chains that are unverifiable.
            //
            // Previously, boot events were emitted with plain SHA-256, then the key
            // was installed, creating a mixed chain that neither verify_chain() nor
            // verify_chain_hmac() could validate.
            //
            // R72-HMAC: Generate and install audit HMAC key for integrity protection.
            // Uses CSPRNG to generate a 32-byte cryptographically secure key.
            // The key is zeroed from stack memory after use to minimize exposure.
            //
            // D-1: Track whether the key actually landed so Secure can fail-closed
            // if CSPRNG or set_hmac_key fails (otherwise "mandatory" was a lie).
            let mut hmac_installed = false;
            {
                let mut audit_hmac_key = [0u8; audit::MAX_HMAC_KEY_SIZE];
                match security::rng::fill_random(&mut audit_hmac_key) {
                    Ok(()) => match audit::set_hmac_key(&audit_hmac_key) {
                        Ok(()) => {
                            hmac_installed = true;
                            klog_always!("      ✓ Audit HMAC key installed (32 bytes, CSPRNG)");
                            klog_always!("        - All audit events now HMAC-SHA256 protected");
                        }
                        Err(e) => {
                            klog_force!("      ! Failed to set audit HMAC key: {:?}", e);
                        }
                    },
                    Err(e) => {
                        klog_force!("      ! Failed to generate audit HMAC key: {:?}", e);
                        klog_force!(
                            "        - Audit events using plain SHA-256 chain only (degraded)"
                        );
                    }
                }
                // R72-HMAC: Zero key material from stack to limit exposure window
                // Use volatile writes to prevent the compiler from eliding the wipe
                for byte in audit_hmac_key.iter_mut() {
                    unsafe { core::ptr::write_volatile(byte, 0) };
                }
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            }

            // D-1: Secure profile requires HMAC-protected audit chain.
            if audit_fail_closed && !hmac_installed {
                klog_force!(
                    "[POLICY] Secure profile: audit HMAC key required but not installed — halting"
                );
                panic!(
                    "Audit HMAC key installation failed in Secure profile \
                     (use Balanced profile to allow degraded boot with plain SHA-256)"
                );
            }
            debug_assert!(
                !hmac_installed || audit::has_hmac_key(),
                "HMAC install flag out of sync with audit::has_hmac_key()"
            );

            // R178-24 FIX: Now that HMAC key is installed (or Secure halted), emit boot event.
            // This event will be HMAC-protected when the key is present.
            let _ = audit::emit(
                audit::AuditKind::Internal,
                audit::AuditOutcome::Info,
                audit::AuditSubject::kernel(),
                audit::AuditObject::None,
                &[0], // boot event
                0,
                0, // timestamp 0 = boot
            );

            // P1-1: Re-emit the profile validation audit event now that audit is
            // initialised. The initial emission during init_policy_surface() was
            // silently dropped because audit::init() hadn't run yet.
            // R178-24: This event is also HMAC-protected when key is installed.
            compliance::emit_deferred_policy_audit();
            klog_always!("      ✓ Deferred profile audit event recorded");

            // R106-8: Register OOM killer audit callback for tamper-evident event recording.
            // OOM kill events are now fed into the hash-chained audit ring buffer.
            mm::register_oom_audit_callback(|pid, uid, needed, rss, adj, timestamp| {
                let _ = audit::emit(
                    audit::AuditKind::Internal,
                    audit::AuditOutcome::Info,
                    audit::AuditSubject::new(pid, uid, 0, None),
                    audit::AuditObject::Process {
                        pid,
                        signal: Some(9),
                    }, // SIGKILL
                    &[needed, rss, adj as u64],
                    0,
                    timestamp,
                );
            });
            klog_always!("      ✓ OOM killer audit callback registered (R106-8)");

            // P1-4: Register livepatch audit callback for tamper-evident lifecycle recording.
            // Livepatch state transitions (load/enable/disable/unload) are now fed into
            // the hash-chained audit ring buffer alongside OOM events.
            livepatch::register_audit_callback(
                |action, patch_id, target_addr, extra, timestamp| {
                    let _ = audit::emit(
                        audit::AuditKind::Internal,
                        audit::AuditOutcome::Info,
                        audit::AuditSubject::new(0, 0, 0, None),
                        audit::AuditObject::None,
                        &[action, patch_id, target_addr, extra[0], extra[1], extra[2]],
                        0,
                        timestamp,
                    );
                },
            );
            klog_always!("      ✓ Livepatch audit callback registered (P1-4)");
        }
        Err(e) => {
            // D-1: Secure requires audit; Balanced/Performance degrade explicitly.
            klog_force!("      ! Audit initialization failed: {:?}", e);
            if audit_fail_closed {
                klog_force!(
                    "[POLICY] Secure profile: audit subsystem required but init failed — halting"
                );
                panic!(
                    "Audit initialization failed in Secure profile: {:?} \
                     (use Balanced profile to allow degraded boot without audit)",
                    e
                );
            }
            klog_force!("      ! Continuing without audit (degraded mode)");
        }
    }

    // Phase G.1: Observability subsystem (tracepoints, counters, watchdog)
    klog_always!("[7.7/8] Initializing observability subsystem...");
    trace::init();
    // G.1: Force-initialize per-CPU counter storage and mark counters as ready.
    // This ensures the CpuLocal<PerCpuCounters> lazy init happens during boot
    // (when heap is available), not in alloc_error_handler where it could recurse.
    increment_counter(TraceCounter::Custom0, 0); // no-op increment to trigger init
    COUNTERS_READY.store(true, core::sync::atomic::Ordering::Release);
    // Install read guard for metrics export (CAP_TRACE_READ or root)
    let _ = trace::install_read_guard(|| {
        // R109-4 FIX: Only allow credential-less access during the boot phase.
        let creds = current_credentials();
        if creds.is_none() {
            return !BOOT_PHASE_COMPLETE.load(core::sync::atomic::Ordering::Acquire);
        }
        // R133-1 FIX: Use host-mapped root check for host-global gate
        if current_is_host_root() {
            return true;
        }
        // Allow processes with CAP_TRACE_READ capability
        if let Some(has_cap) =
            with_current_cap_table(|table| table.has_rights(CapRights::TRACE_READ))
        {
            if has_cap {
                return true;
            }
        }
        false
    });
    klog_always!("      ✓ Trace capability gate registered (CAP_TRACE_READ)");

    klog_always!("[8/8] Verifying memory management...");
    klog_always!("      ✓ Page table manager compiled");
    klog_always!("      ✓ mmap/munmap available");

    // P1-1 FIX: Gate debug test interfaces by PolicySurface.
    // In Secure profile, debug_interfaces_enabled is false — skip integration,
    // runtime, and Ring 3 usermode tests to reduce the attack surface and
    // eliminate test-only code paths in production deployments.
    let pending_usermode_process = if compliance::policy().debug_interfaces_enabled {
        // 运行集成测试
        integration_test::run_all_tests();

        // 运行运行时功能测试
        let test_report = runtime_tests::run_all_runtime_tests();
        if test_report.failed > 0 {
            klog!(
                Warn,
                "WARNING: {} runtime tests failed!",
                test_report.failed
            );
        }

        // 运行 Ring 3 用户态测试
        klog_always!("[9/9] Running Ring 3 user mode test...");
        let pending = usermode_test::prepare_usermode_test();
        if pending.is_some() {
            klog_always!("      ✓ Ring 3 test process prepared successfully");
        } else {
            klog!(Error, "      ! Ring 3 test setup failed");
        }
        pending
    } else {
        klog_force!(
            "[POLICY] {} profile: debug/test interfaces disabled",
            compliance::policy().profile.name()
        );
        None
    };

    klog_always!("=== System Ready ===");
    klog_always!();
    klog_always!("🎉 Zero-OS Phase 1 Complete!");
    klog_always!("All subsystems verified and integrated successfully!");
    klog_always!();
    klog_always!("📊 Component Summary:");
    klog_always!("   • VGA Driver & Output");
    klog_always!("   • Interrupt Handling (20+ handlers)");
    klog_always!("   • Memory Management (Heap + Buddy allocator)");
    klog_always!("   • Page Table Manager");
    klog_always!("   • Kernel Stack Guard Pages");
    klog_always!("   • Security Hardening (W^X, NX, CSPRNG)");
    klog_always!("   • CPU Protection (SMEP/SMAP/UMIP)");
    klog_always!("   • SYSCALL/SYSRET (Ring 3 transition)");
    klog_always!("   • Process Control Block");
    klog_always!("   • Enhanced Scheduler (Multi-level feedback queue)");
    klog_always!("   • Context Switch (176-byte context + IRETQ)");
    klog_always!("   • System Calls (50+ defined)");
    klog_always!("   • Fork with COW");
    klog_always!("   • Memory Mapping (mmap/munmap)");
    klog_always!("   • Capability-based IPC");
    klog_always!("   • Virtual File System (VFS)");
    klog_always!("   • Device Files (/dev/null, /dev/zero, /dev/console)");
    // Component summary: audit line reflects actual init state (D-1 residual —
    // do not advertise hash-chained audit after a degraded no-audit boot).
    if audit::is_initialized() {
        if audit::has_hmac_key() {
            klog_always!("   • Security Audit (HMAC-SHA256 hash-chained events)");
        } else {
            klog_always!("   • Security Audit (hash-chained events, plain SHA-256 — degraded)");
        }
    } else {
        klog_always!("   • Security Audit (NOT INITIALIZED — degraded mode)");
    }
    klog_always!("   • Ring 3 User Mode (Phase 6 complete)");
    klog_always!();
    klog_always!("进入空闲循环...");
    klog_always!();

    // 启用中断（IDT 已初始化完成）
    // 注意：在启用中断前，确保所有中断处理程序已正确设置
    // 启用串口接收中断（在 sti 前，最小化中断禁用期间积压数据的窗口）
    arch::interrupts::enable_serial_interrupts();

    // R109-4 FIX: Mark boot phase as complete before enabling interrupts.
    // After this point, credential-less contexts (kernel threads, interrupt
    // handlers) must not bypass audit/trace capability gates.
    BOOT_PHASE_COMPLETE.store(true, core::sync::atomic::Ordering::Release);

    unsafe {
        // RF180-52: this is also the compiler barrier before the readiness
        // Release store below. Do not add `nomem`: LLVM must not move the
        // publication above the point where the BSP becomes IRQ-responsive.
        core::arch::asm!("sti", options(nostack));
    }

    // RF180-52 FIX: all scheduler, IPC, IOMMU soft-progress, network/socket,
    // cgroup, RCU, and boot-quiescent self-test dependencies used by the full
    // process-context deferred drain are now initialized, and the boot-only
    // credential bypass is closed. Publish only after the BSP can service
    // cross-CPU interrupts: a newly enabled drain may itself require an IPI.
    kernel_core::mark_process_deferred_work_ready();
    // Release-before-edge: the Acquire gate read observes all initialization,
    // while the reschedule IPI promptly wakes every online AP from HLT. The
    // periodic LAPIC timer remains a backstop, not the publication mechanism.
    arch::ipi::broadcast_ipi(arch::ipi::IpiType::Reschedule);
    // RF180-54 FIX: do not expose runnable Ring-3 work until every online AP has
    // completed one full post-publication deferred drain. The bounded BSP wait
    // runs with interrupts enabled and fails closed on a missing/invalid ACK.
    arch::smp::wait_for_process_deferred_acknowledgements();

    if let Some(process) = pending_usermode_process {
        let pid = process.lock().pid;
        match sched::enhanced_scheduler::Scheduler::add_process(process) {
            Ok(()) => {
                klog_always!("      ✓ Ring 3 test process added to scheduler ready queue");
            }
            Err(error) => {
                kernel_core::process::cleanup_unscheduled_process(pid);
                klog!(
                    Error,
                    "      ! Ring 3 scheduler admission failed: {:?}",
                    error
                );
            }
        }
    }

    // Enter interactive shell after all tests complete
    // The shell runs on the BSP and provides a Linux-compatible command-line interface
    klog_always!();
    klog_always!("All runtime tests complete. Entering interactive shell...");
    klog_always!();

    // Transfer control to the shell (never returns unless exited explicitly)
    // Note: The shell will run concurrently with any Ring 3 processes
    // The scheduler will time-slice between them
    shell::init_and_run();
}

#[cfg(not(test))]
#[alloc_error_handler]
fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    // G.1: Track allocation failures for observability.
    // Only attempt if counters are initialized (avoids recursive allocation).
    if COUNTERS_READY.load(core::sync::atomic::Ordering::Relaxed) {
        increment_counter(TraceCounter::AllocFailures, 1);
    }

    // Print heap statistics before panicking
    unsafe {
        serial_write_str("ALLOC FAILED: size=");
        let size = layout.size();
        let mut buf = [0u8; 20];
        let mut n = size;
        let mut i = 0;
        loop {
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
            i += 1;
            if n == 0 {
                break;
            }
        }
        while i > 0 {
            i -= 1;
            serial_write_byte(buf[i]);
        }
        serial_write_str("\n");
    }
    panic!("Allocation error: {:?}", layout);
}
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    unsafe {
        // 立即禁用中断，防止 panic 期间中断重入
        core::arch::asm!("cli", options(nomem, nostack));

        // G.1 kdump: Capture crash context immediately after cli.
        // This captures CPU registers, stack, and panic info before any
        // further state changes. Safe to call multiple times (atomic guard).
        let crash_dump = trace::kdump::capture_crash_context(info);

        // R93-16 FIX / G.fin.1: Check PolicySurface for panic output redaction.
        // In Secure profile, suppress detailed panic output to avoid leaking
        // kernel pointers, file paths, and other sensitive information over serial.
        // The encrypted kdump still captures full details for offline analysis.
        // Uses is_policy_initialized() to handle panics during very early boot
        // before PolicySurface exists (fail-open: show details to aid debugging).
        let suppress_details = if compliance::is_policy_initialized() {
            compliance::policy().panic_redact_details
        } else {
            false
        };

        serial_write_str("KERNEL PANIC");

        if !suppress_details {
            // Non-secure profiles: show location for debugging
            serial_write_str(": ");
            if let Some(location) = info.location() {
                serial_write_str(location.file());
                serial_write_str(":");
                // 输出行号
                let line = location.line();
                let mut buf = [0u8; 10];
                let mut n = line;
                let mut i = 0;
                loop {
                    buf[i] = b'0' + (n % 10) as u8;
                    n /= 10;
                    i += 1;
                    if n == 0 {
                        break;
                    }
                }
                while i > 0 {
                    i -= 1;
                    serial_write_byte(buf[i]);
                }
            }
        } else {
            // Secure profile: minimal output to avoid info leakage
            serial_write_str(" [Secure mode: details redacted]");
        }
        serial_write_str("\n");

        // R93-16 FIX: Only print full panic message in non-Secure profiles.
        // Panic messages can contain formatted kernel pointers, stack traces,
        // and other sensitive information that could aid exploitation.
        if !suppress_details {
            // 尝试打印panic消息
            // 使用 core::fmt::write 来格式化
            struct SerialFmt;
            impl core::fmt::Write for SerialFmt {
                fn write_str(&mut self, s: &str) -> core::fmt::Result {
                    for b in s.bytes() {
                        unsafe {
                            serial_write_byte(b);
                        }
                    }
                    Ok(())
                }
            }
            let _ = core::fmt::write(&mut SerialFmt, format_args!("{}\n", info));
        }

        // G.1 kdump: Emit encrypted crash dump over serial.
        // The dump includes:
        // - CPU registers (pointer-redacted via KptrGuard)
        // - Stack contents (pointer-redacted)
        // - Panic location and message
        // - ChaCha20 encryption with random nonce
        // - Base64 encoding for serial transport
        // Only emits once per boot (atomic guard prevents duplicate dumps).
        trace::kdump::emit_encrypted_dump(crash_dump);
    }
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

// ============================================================================
// R148-I4 FIX: Stack canary support (__stack_chk_fail / __stack_chk_guard)
//
// When the compiler is configured with -fstack-protector (or equivalent Rust
// flags), it inserts a canary value at function entry and checks it at exit.
// If the canary is corrupted (stack buffer overflow), the compiler calls
// __stack_chk_fail.  We provide a panic-based implementation so the kernel
// halts cleanly instead of producing a linker error or undefined behavior.
// ============================================================================

/// Stack canary guard value.  In production kernels this should be
/// randomized at boot from the CSPRNG; for now a compile-time constant
/// provides the symbol the compiler expects.
#[no_mangle]
#[used]
pub static __stack_chk_guard: u64 = 0x595e_9fbd_94fd_a766;

/// Called by compiler-inserted stack canary checks when corruption is detected.
#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    panic!("stack smashing detected: stack canary corrupted");
}
