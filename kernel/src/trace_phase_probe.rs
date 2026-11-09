//! THREAD-HB C1 trace-phase probe (diagnostic image only).
//!
//! QEMU gates may reduce their interrupt trace to `cpu_reset` once the serial log
//! shows the AP acknowledgement marker (`scripts/ci/qemu_trace.py`). This image
//! raises one kernel-mode fault class, chosen at build time by
//! `NILIX_TRACE_PHASE_PROBE`, so `scripts/gates/qemu/trace_phase_probe.py` can
//! prove the class is still detected: `nx-boot` before the marker, while the full
//! trace is on; `ud`, `gp`, `nx` and `triple` a few seconds after it.

use core::arch::asm;

const KIND: &str = match option_env!("NILIX_TRACE_PHASE_PROBE") {
    Some(kind) => kind,
    None => "",
};

/// Host-side switch time after the marker, in serviced BSP timer ticks (ms).
const SETTLE_MS: u64 = 3000;

/// Kernel data holding `ret`; present but non-executable under W^X.
static NX_TARGET: [u8; 16] = [0xC3; 16];

/// Faults before the marker, while the host still traces every interrupt.
pub fn before_marker() {
    if KIND == "nx-boot" {
        armed();
        nx_fetch();
    }
}

/// Waits for the host to reduce the trace, then faults. IRQs are enabled here.
pub fn after_marker() {
    let start = kernel_core::time::current_timestamp_ms();
    while kernel_core::time::current_timestamp_ms().wrapping_sub(start) < SETTLE_MS {
        x86_64::instructions::hlt();
    }
    armed();
    match KIND {
        "ud" => {
            // SAFETY: deliberate #UD; the handler panics for a kernel origin.
            unsafe { asm!("ud2", options(nomem, nostack)) };
        }
        "gp" => {
            // SAFETY: deliberate #GP from a non-canonical load; the handler panics.
            unsafe {
                asm!("mov {value}, qword ptr [{address}]",
                     address = in(reg) 0x8000_0000_0000_0000u64,
                     value = out(reg) _,
                     options(nostack, readonly));
            }
        }
        "nx" => nx_fetch(),
        "triple" => {
            let empty = [0u16; 5];
            // SAFETY: deliberate triple fault. A zero-limit IDT turns int3 into
            // #GP, then #DF, then a CPU reset that QEMU logs under `cpu_reset`.
            unsafe {
                asm!("cli", "lidt [{idtr}]", "int3", idtr = in(reg) empty.as_ptr(), options(nostack));
            }
        }
        _ => klog_always!("TRACE-PHASE-PROBE BLOCKED kind={}", KIND),
    }
    klog_always!("TRACE-PHASE-PROBE RETURNED kind={}", KIND);
}

fn armed() {
    klog_always!("TRACE-PHASE-PROBE ARMED kind={}", KIND);
}

fn nx_fetch() {
    // SAFETY: deliberate supervisor instruction fetch from a present NX page
    // (#PF error 0x11); no handler path resolves it, so the kernel panics.
    unsafe {
        let target: extern "C" fn() = core::mem::transmute(NX_TARGET.as_ptr());
        target();
    }
}
