#![no_main]

//! cargo fuzz run fuzz_syscall_qemu --features qemu-executor -- -timeout=120
//! Requires `make build-syz-kcov`, QEMU, OVMF, and e2fsprogs.

use libfuzzer_sys::fuzz_target;
use nilix_fuzz::qemu_executor::{
    configured_executor, parse_fuzzer_input, ExecutionResult, QemuExecutor,
};
use std::sync::OnceLock;

static EXECUTOR: OnceLock<QemuExecutor> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let executor = EXECUTOR.get_or_init(|| {
        configured_executor().unwrap_or_else(|error| panic!("executor setup failed: {error:#}"))
    });
    let Ok(program) = parse_fuzzer_input(data) else {
        return;
    };
    match executor.execute(&program) {
        Ok(ExecutionResult::Success(_coverage)) => {
            // Guest coverage is authenticated, but libFuzzer currently guides
            // mutations using host instrumentation, not this guest bitmap.
            // Zero coverage is valid for allowlisted syscalls that do not reach
            // a manually instrumented path; qemu_smoke still enforces nonzero
            // coverage for the seeds that prove the KCOV data path.
        }
        Ok(ExecutionResult::Crash(info)) => {
            eprintln!("{}\n{}", info.serial_log, info.qemu_stderr);
            panic!("kernel/QEMU crash: {}", info.classification);
        }
        Ok(ExecutionResult::Timeout) => panic!("QEMU boot timeout before guest BEGIN"),
        Ok(ExecutionResult::Hang) => panic!("guest hung after BEGIN"),
        Err(error) => panic!("QEMU execution failed: {error:#}"),
    }
});
