//! Single-program replay harness for the syzkaller-style fuzzer.
//!
//! Loads a serialized `SyscallProgram` (the `crash-*.bin` / `prog-*.bin` JSON
//! files written by nilix-syz-fuzzer), re-executes it against the KCOV kernel
//! through the *real* `QemuExecutor`, and prints the classification plus the
//! full serial log and QEMU stderr. Pass `--repeat N` to expose
//! non-determinism (the same program may sometimes PASS and sometimes CRASH).
//!
//! This is a triage tool, not a fuzzer: it never mutates the program.

use std::path::PathBuf;
use std::process::ExitCode;

use nilix_syz_fuzzer::disk::Ext3Tools;
use nilix_syz_fuzzer::executor::{ExecutionResult, QemuExecutor};
use nilix_syz_fuzzer::program::SyscallProgram;

fn parse_args() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let program_path = match args.next() {
        Some(p) => PathBuf::from(p),
        None => {
            return Err(format!(
                "usage: replay <program.bin> [--kernel PATH] [--ovmf PATH] \
                 [--qemu PATH] [--timeout SECS] [--repeat N]"
            ));
        }
    };
    let mut a = Args {
        program_path,
        kernel: PathBuf::from("esp-kcov/kernel.elf"),
        ovmf: None,
        qemu: PathBuf::from("qemu-system-x86_64"),
        timeout: 30,
        repeat: 1,
    };
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--kernel" => a.kernel = PathBuf::from(args.next().ok_or("--kernel needs a value")?),
            "--ovmf" => a.ovmf = Some(PathBuf::from(args.next().ok_or("--ovmf needs a value")?)),
            "--qemu" => a.qemu = PathBuf::from(args.next().ok_or("--qemu needs a value")?),
            "--timeout" => {
                a.timeout = args
                    .next()
                    .ok_or("--timeout needs a value")?
                    .parse()
                    .map_err(|_| "invalid --timeout")?;
            }
            "--repeat" => {
                a.repeat = args
                    .next()
                    .ok_or("--repeat needs a value")?
                    .parse()
                    .map_err(|_| "invalid --repeat")?;
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }
    Ok(a)
}

struct Args {
    program_path: PathBuf,
    kernel: PathBuf,
    ovmf: Option<PathBuf>,
    qemu: PathBuf,
    timeout: u64,
    repeat: usize,
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };

    let program = match SyscallProgram::load_from_file(&args.program_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "failed to load program {}: {e:#}",
                args.program_path.display()
            );
            return ExitCode::from(1);
        }
    };

    println!(
        "Program: {}",
        program.to_json().unwrap_or_else(|_| "<unprintable>".into())
    );
    println!("Kernel:  {}", args.kernel.display());
    println!(
        "Repeat:  {}, per-run timeout: {}s\n",
        args.repeat, args.timeout
    );

    let mut crashes = 0usize;
    let mut timeouts = 0usize;
    let mut hangs = 0usize;
    let mut successes = 0usize;
    let mut errors = 0usize;

    for i in 1..=args.repeat {
        // A fresh executor per run builds a fresh ext3 disk + tempdir, so each
        // iteration is independent (the only shared state is the kernel binary).
        let executor = match QemuExecutor::new(
            &args.qemu,
            &args.kernel,
            args.ovmf.as_deref(),
            args.timeout,
            128,
            Ext3Tools::default(),
        ) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[{i}/{}] executor setup failed: {e:#}", args.repeat);
                errors += 1;
                continue;
            }
        };
        match executor.execute(&program) {
            Ok(ExecutionResult::Success(cov)) => {
                successes += 1;
                println!(
                    "[{i}/{}] SUCCESS (coverage {} bytes)",
                    args.repeat,
                    cov.len()
                );
            }
            Ok(ExecutionResult::Crash(info)) => {
                crashes += 1;
                println!(
                    "[{i}/{}] CRASH classification={}",
                    args.repeat, info.classification
                );
                println!("----- serial log -----");
                println!("{}", info.serial_log);
                println!("----- qemu stderr -----");
                println!("{}", info.qemu_stderr);
                println!("----------------------");
            }
            Ok(ExecutionResult::Timeout) => {
                timeouts += 1;
                println!("[{i}/{}] TIMEOUT (no BEGIN marker observed)", args.repeat);
            }
            Ok(ExecutionResult::Hang) => {
                hangs += 1;
                println!(
                    "[{i}/{}] HANG (began but never reached PASS/FAIL)",
                    args.repeat
                );
            }
            Err(e) => {
                errors += 1;
                println!("[{i}/{}] EXECUTOR ERROR: {e:#}", args.repeat);
            }
        }
    }

    println!(
        "\nSummary over {} runs: success={} crash={} timeout={} hang={} error={}",
        args.repeat, successes, crashes, timeouts, hangs, errors
    );
    if crashes > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
