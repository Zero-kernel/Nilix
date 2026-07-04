#![no_main]

use libfuzzer_sys::fuzz_target;

// Drives the REAL kernel ELF pre-flight validator, `kernel_core::validate_elf_image`
// — the exact header + program-header-table parse that execve(59)/spawn_image(517)
// run on untrusted bytes before mapping any segment. It is the pure slice of
// `load_elf` (no page tables, no frame allocator, no cgroup charge).
//
// R172-02 hardened this path against a crafted-ELF program-header OOB-slice
// panic=abort DoS (a ~100-byte ELF with a bad e_phoff/e_phnum/e_phentsize or an
// unaligned e_phoff). This target feeds arbitrary bytes straight in and asserts
// the parser never panics — a regression guard for that fix. A crash here is a
// real finding: the validator must return Err, never abort.
fuzz_target!(|data: &[u8]| {
    let _ = kernel_core::validate_elf_image(data);
});
