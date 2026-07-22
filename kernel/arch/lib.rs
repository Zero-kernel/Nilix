#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::manual_contains)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::type_complexity)]
#![allow(clippy::declare_interior_mutable_const)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::fn_to_numeric_cast)]
#![allow(unused_unsafe)]
#![allow(unused_assignments)]
#![allow(clippy::fn_to_numeric_cast_any)]
#![allow(function_casts_as_integer)]
#![no_std]
#![feature(abi_x86_interrupt)]
extern crate alloc;

// 导入 drivers crate 的宏
#[macro_use]
extern crate drivers;
#[macro_use]
extern crate klog;

pub mod apic;
pub mod context_switch;
pub mod cpu_protection;
pub mod gdt;
pub mod hpet;
pub mod interrupts;
pub mod invpcid;
pub mod ipi;
pub mod smp;
pub mod syscall;

pub use context_switch::{
    assert_kernel_context, enter_usermode, init_fpu, jump_to_usermode, switch_context,
    switch_to_user, validate_kernel_context, Context, FxSaveArea, USER_CODE_SELECTOR,
    USER_DATA_SELECTOR,
};
pub use cpu_protection::{
    check_cpu_features, enable_protections, require_smap_support, CpuProtectionStatus,
};
pub use cpu_protection::{
    detect_hypervisor, hypervisor_present, is_software_emulated, is_virtualized, HypervisorType,
};
pub use gdt::{
    default_kernel_stack_top, get_kernel_stack, init as init_gdt, init_for_ap as init_gdt_for_ap,
    selectors, set_ist_stack, set_kernel_stack, Selectors, DOUBLE_FAULT_IST_INDEX,
    DOUBLE_FAULT_STACK_SIZE, KERNEL_STACK_SIZE,
};
pub use syscall::{
    arch_set_kpti_cr3s, assert_kernel_gs_base, init_syscall_msr,
    is_initialized as syscall_initialized, register_frame_callback, run_entry_state_gs_self_test,
    stage_pending_tls_bases, with_current_syscall_frame, SyscallFrame,
};

// Re-export cpu_local from the cpu_local crate for backwards compatibility
pub use cpu_local::{current_cpu_id, max_cpus, CpuLocal};

// Re-export PerCpuData and related functions for SMP support
pub use cpu_local::{
    current_cpu, init_bsp, num_online_cpus, register_cpu_id, PerCpuData, RawTaskPtr, PER_CPU_DATA,
};

// Re-export SMP bring-up functions
pub use smp::{
    ap_rust_entry, online_cpus, register_ap_security_init, set_rsdp_address, smp_initialized,
    start_aps,
};

// Re-export INVPCID instruction wrappers
pub use invpcid::{
    flush_address, flush_all_nonglobal, flush_pcid, invpcid_address, invpcid_all_global,
    invpcid_all_nonglobal, invpcid_single_context, invpcid_supported,
};

pub fn init() {
    gdt::init();
    context_switch::init_fpu();
    syscall::register_frame_callback(); // 注册 syscall 帧回调
    klog_always!("Arch module initialized (FPU/SIMD enabled)");
}

/// Try to read a character from serial input (non-blocking)
///
/// This function checks the keyboard buffer which is populated by serial interrupts.
/// Returns `Some(ch)` if a character is available, `None` otherwise.
///
/// # Multi-core Safety
///
/// This function is lock-free and safe to call from any CPU.
pub fn try_read_serial_char() -> Option<u8> {
    drivers::keyboard::try_pop_char()
}

/// Write a single byte to serial output (no newline added)
///
/// This is for interactive I/O where character-by-character output is needed.
pub fn serial_write_byte(byte: u8) {
    unsafe {
        use x86_64::instructions::port::Port;
        let mut port = Port::new(0x3F8);
        port.write(byte);
    }
}

/// Write a string to serial output (no newline added)
///
/// This is for interactive I/O where precise control over output is needed.
pub fn serial_write_str(s: &str) {
    for byte in s.bytes() {
        serial_write_byte(byte);
    }
}

/// System reboot via keyboard controller
pub fn reboot() -> ! {
    unsafe {
        // Method 1: Keyboard controller reset
        core::arch::asm!("mov al, 0xFE", "out 0x64, al", options(nostack, nomem));

        // Method 2: Triple fault (if keyboard controller fails)
        core::arch::asm!("cli");

        // Load invalid IDT to trigger triple fault
        #[repr(C, packed)]
        struct IdtPtr {
            limit: u16,
            base: u64,
        }
        let invalid_idt = IdtPtr { limit: 0, base: 0 };
        core::arch::asm!(
            "lidt [{}]",
            "int3",
            in(reg) &invalid_idt,
            options(nostack)
        );
    }

    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}

/// System shutdown via ACPI
pub fn shutdown() -> ! {
    unsafe {
        // Try QEMU/Bochs magic port shutdown
        core::arch::asm!(
            "mov dx, 0x604",
            "mov ax, 0x2000",
            "out dx, ax",
            options(nostack, nomem)
        );

        // Try ACPI shutdown (simplified)
        core::arch::asm!(
            "mov dx, 0xB004",
            "mov ax, 0x3400",
            "out dx, ax",
            options(nostack, nomem)
        );
    }

    // Fallback: halt forever
    klog_always!("Shutdown failed, halting...");
    loop {
        unsafe { core::arch::asm!("cli; hlt") }
    }
}
