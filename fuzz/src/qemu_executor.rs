//! The real syz executor and the byte decoder shared by cargo-fuzz and its gate.
//!
//! Enabling `qemu-executor` uses the authenticated guest protocol. There is no
//! success-producing fallback when QEMU or its guest image is unavailable.

use anyhow::{ensure, Context, Result};
pub use nilix_syz_fuzzer::disk::Ext3Tools;
pub use nilix_syz_fuzzer::executor::{CrashInfo, ExecutionResult, QemuExecutor};
pub use nilix_syz_fuzzer::program::{Argument, Syscall, SyscallProgram};
use std::path::PathBuf;

pub const GUEST_TIMEOUT_SECS: u64 = 900;

// Same non-destructive contract validated by the shared program/guest protocol.
const SYSCALLS: &[u32] = &[
    24, 39, 102, 104, 107, 108, 110, 186, 12, 21, 4, 6, 63, 96, 97, 79, 89, 204, 228, 318,
];

pub const SMOKE_INPUTS: &[(&str, &[u8])] = &[
    ("getpid", &[1, 1, 0]),
    ("uname", &[1, 12, 1, 3, 0x86, 0x01]),
];

/// One allowlisted syscall that has no manual KCOV probe. This is the exact
/// three-byte class found by the bounded campaign at revision `0788e60`;
/// the header byte 120 maps to `sched_yield` via the target allowlist.
pub const ZERO_COVERAGE_INPUT: (&str, &[u8]) = ("sched_yield", &[1, 120, 0]);

pub fn configured_executor() -> Result<QemuExecutor> {
    let kernel = std::env::var_os("NILIX_FUZZ_KERNEL")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../esp-syz/kernel.elf"));
    let qemu = std::env::var_os("NILIX_FUZZ_QEMU")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("qemu-system-x86_64"));
    let ovmf = std::env::var_os("OVMF_PATH").map(PathBuf::from);
    let executor = QemuExecutor::new(
        &qemu,
        &kernel,
        ovmf.as_deref(),
        GUEST_TIMEOUT_SECS,
        128,
        Ext3Tools::default(),
    )
    .context("QEMU executor setup failed; build the guest with make build-syz-kcov")?;
    Ok(match std::env::var_os("NILIX_FUZZ_ARTIFACTS") {
        Some(root) => executor.with_artifact_dir(PathBuf::from(root)),
        None => executor,
    })
}

/// count:u8, then (syscall-index:u8, argc:u8, arguments...). Argument tags:
/// 0 = immediate:u64 LE; 1 = null; 2 = length:u8 + 1 bytes; 3 = capacity:u16 LE.
/// Reject incomplete programs before launching a guest, including partial tails.
pub fn parse_fuzzer_input(mut data: &[u8]) -> Result<SyscallProgram> {
    let count = take(&mut data, 1)?[0] as usize;
    ensure!((1..=10).contains(&count), "syscall count must be 1..=10");
    let mut program = SyscallProgram::new();
    for _ in 0..count {
        let header = take(&mut data, 2)?;
        let number = SYSCALLS[header[0] as usize % SYSCALLS.len()];
        let count = header[1] as usize;
        ensure!(count <= 6, "too many arguments");
        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            let tag = take(&mut data, 1)?[0];
            let arg = match tag {
                0 => Argument::Immediate(u64::from_le_bytes(take(&mut data, 8)?.try_into()?)),
                1 => Argument::Null,
                2 => {
                    let length = usize::from(take(&mut data, 1)?[0]) + 1;
                    Argument::Buffer(take(&mut data, length)?.to_vec())
                }
                3 => Argument::Output {
                    capacity: u32::from(u16::from_le_bytes(take(&mut data, 2)?.try_into()?)),
                },
                _ => anyhow::bail!("unknown argument tag"),
            };
            args.push(arg);
        }
        program.add_syscall(Syscall { number, args })?;
    }
    ensure!(data.is_empty(), "trailing incomplete program data");
    program.validate()?;
    Ok(program)
}

fn take<'a>(data: &mut &'a [u8], count: usize) -> Result<&'a [u8]> {
    ensure!(data.len() >= count, "truncated program");
    let (head, tail) = data.split_at(count);
    *data = tail;
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_seeds_decode_to_real_guest_contracts() {
        let pid = parse_fuzzer_input(SMOKE_INPUTS[0].1).unwrap();
        assert_eq!(
            pid.syscalls[0],
            Syscall {
                number: 39,
                args: vec![]
            }
        );
        let uname = parse_fuzzer_input(SMOKE_INPUTS[1].1).unwrap();
        assert_eq!(uname.syscalls[0].number, 63);
        assert_eq!(
            uname.syscalls[0].args,
            vec![Argument::Output { capacity: 390 }]
        );
    }

    #[test]
    fn zero_coverage_seed_maps_to_sched_yield() {
        let program = parse_fuzzer_input(ZERO_COVERAGE_INPUT.1).unwrap();
        assert_eq!(program.syscalls[0].number, 24);
        assert!(program.syscalls[0].args.is_empty());
        for length in 0..ZERO_COVERAGE_INPUT.1.len() {
            assert!(parse_fuzzer_input(&ZERO_COVERAGE_INPUT.1[..length]).is_err());
        }
    }

    #[test]
    fn truncation_and_invalid_output_are_rejected_before_execution() {
        for (_, seed) in SMOKE_INPUTS {
            for length in 0..seed.len() {
                assert!(parse_fuzzer_input(&seed[..length]).is_err());
            }
        }
        assert!(parse_fuzzer_input(&[1, 12, 1, 3, 1, 0]).is_err());
        assert!(parse_fuzzer_input(&[1, 1, 0, 0]).is_err());
        assert!(parse_fuzzer_input(&[2, 1, 0, 1]).is_err());
        assert!(parse_fuzzer_input(&[1, 1, 7]).is_err());
    }

    #[test]
    fn immediate_and_path_arguments_use_the_shared_validation() {
        let mut access = vec![1, 9, 2, 2, 1, b'/', 0, 0];
        access.extend_from_slice(&4u64.to_le_bytes());
        let program = parse_fuzzer_input(&access).unwrap();
        assert_eq!(program.syscalls[0].number, 21);
        access[8..].copy_from_slice(&8u64.to_le_bytes());
        assert!(parse_fuzzer_input(&access).is_err());
        for length in 0..access.len() {
            assert!(parse_fuzzer_input(&access[..length]).is_err());
        }
    }

    #[test]
    #[cfg(unix)]
    fn real_adapter_launches_configured_process_and_propagates_failure() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let source = root.join("source");
        std::fs::create_dir_all(source.join("EFI/BOOT")).unwrap();
        let kernel = source.join("kernel.elf");
        std::fs::write(&kernel, b"sentinel kernel").unwrap();
        std::fs::write(source.join("EFI/BOOT/BOOTX64.EFI"), b"sentinel bootloader").unwrap();
        std::fs::write(source.join("NvVars"), b"preserve source firmware state").unwrap();
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"sentinel firmware").unwrap();
        let sentinel = root.join("qemu-sentinel");
        std::fs::write(
            &sentinel,
            b"#!/bin/sh\nprintf 'launched\\n' > \"${0%/*}/started\"\nexit 7\n",
        )
        .unwrap();
        std::fs::set_permissions(&sentinel, std::fs::Permissions::from_mode(0o700)).unwrap();
        let executor = QemuExecutor::new(
            &sentinel,
            &kernel,
            Some(&firmware),
            1,
            16,
            Ext3Tools::default(),
        )
        .unwrap()
        .with_artifact_dir(root.join("artifacts"));
        let program = parse_fuzzer_input(SMOKE_INPUTS[0].1).unwrap();
        let result = executor.execute(&program).unwrap();
        assert_eq!(std::fs::read(root.join("started")).unwrap(), b"launched\n");
        assert!(
            matches!(result, ExecutionResult::Crash(info) if info.classification.contains("exit status: 7"))
        );
        assert_eq!(
            std::fs::read(source.join("NvVars")).unwrap(),
            b"preserve source firmware state"
        );
        let missing = QemuExecutor::new(
            &root.join("missing-qemu"),
            &kernel,
            Some(&firmware),
            1,
            16,
            Ext3Tools::default(),
        )
        .unwrap();
        assert!(missing
            .execute(&program)
            .unwrap_err()
            .to_string()
            .contains("failed to spawn"));
    }
}
