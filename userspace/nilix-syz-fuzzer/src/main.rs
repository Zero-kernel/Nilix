use anyhow::{Context, Result};
use clap::Parser;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use nilix_syz_fuzzer::corpus::Corpus;
use nilix_syz_fuzzer::coverage::CoverageTracker;
use nilix_syz_fuzzer::disk::Ext3Tools;
use nilix_syz_fuzzer::executor::{ExecutionResult, QemuExecutor};
use nilix_syz_fuzzer::mutator::SyscallMutator;
use nilix_syz_fuzzer::program::SyscallProgram;
use nilix_syz_fuzzer::stats::FuzzStats;

#[derive(Parser, Debug)]
#[command(name = "nilix-syz-fuzzer")]
#[command(about = "Syzkaller-style coverage-guided fuzzer for Nilix kernel")]
struct Args {
    /// Path to corpus directory
    #[arg(long, default_value = "syz-corpus")]
    corpus_dir: PathBuf,

    /// Path to crash directory
    #[arg(long, default_value = "syz-crashes")]
    crash_dir: PathBuf,

    /// Path to KCOV-enabled kernel
    #[arg(long, default_value = "esp-kcov/kernel.elf")]
    kernel: PathBuf,

    /// Total fuzzing timeout in seconds
    #[arg(long, default_value = "3600")]
    timeout: u64,

    /// Number of parallel workers
    #[arg(long, default_value = "4")]
    workers: usize,

    /// QEMU binary path
    #[arg(long, default_value = "qemu-system-x86_64")]
    qemu: PathBuf,

    /// OVMF firmware path
    #[arg(long)]
    ovmf: Option<PathBuf>,

    /// Per-program timeout in seconds
    #[arg(long, default_value = "30")]
    program_timeout: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Validate paths
    if !args.kernel.exists() {
        anyhow::bail!("Kernel not found: {}", args.kernel.display());
    }

    std::fs::create_dir_all(&args.corpus_dir).context("Failed to create corpus directory")?;
    std::fs::create_dir_all(&args.crash_dir).context("Failed to create crash directory")?;

    println!("=== Nilix Syzkaller-Style Fuzzer ===");
    println!("Kernel:       {}", args.kernel.display());
    println!("Corpus:       {}", args.corpus_dir.display());
    println!("Crashes:      {}", args.crash_dir.display());
    println!("Workers:      {}", args.workers);
    println!("Timeout:      {}s", args.timeout);
    println!("Program timeout: {}s", args.program_timeout);
    println!();

    // Initialize components
    let mut corpus = Corpus::new(&args.corpus_dir)?;
    let mut mutator = SyscallMutator::new();
    let mut coverage = CoverageTracker::new();
    let mut stats = FuzzStats::new();

    // Create initial seed if corpus is empty
    if corpus.is_empty() {
        println!("Corpus is empty, generating initial seed...");
        let seed = mutator.generate_seed()?;
        corpus.add(seed, vec![0; 4096])?;
    }

    println!("Starting fuzzing with {} corpus entries...\n", corpus.len());

    let start_time = std::time::Instant::now();
    let deadline = start_time + std::time::Duration::from_secs(args.timeout);
    // QEMU setup is invariant across iterations.  Construct it once so a
    // transient per-program failure does not tear down the whole session.
    let executor = QemuExecutor::new(
        &args.qemu,
        &args.kernel,
        args.ovmf.as_deref(),
        args.program_timeout,
        128,
        Ext3Tools::default(),
    )?;
    let mut consecutive_errors = 0u32;
    const MAX_CONSECUTIVE_ERRORS: u32 = 64;

    // Main fuzzing loop
    while std::time::Instant::now() < deadline {
        stats.iterations += 1;

        // Select seed from corpus
        let seed = match corpus.select_seed(&stats) {
            Ok(seed) => seed,
            Err(error) => {
                stats.errors += 1;
                consecutive_errors = consecutive_errors.saturating_add(1);
                eprintln!("[!] seed selection failed (continuing): {error:#}");
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    anyhow::bail!("too many consecutive fuzzer errors: {error:#}");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
        };

        // Mutate to generate new program
        let program = match mutator.mutate(&seed) {
            Ok(program) => program,
            Err(error) => {
                stats.errors += 1;
                consecutive_errors = consecutive_errors.saturating_add(1);
                eprintln!("[!] mutation failed (continuing): {error:#}");
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    anyhow::bail!("too many consecutive fuzzer errors: {error:#}");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
        };

        // A failed execution is normally transient (QEMU startup, transport,
        // or guest protocol).  Count and continue instead of aborting the
        // entire fuzzing session on the first such fault (U58-2).
        let execution = match executor.execute(&program) {
            Ok(execution) => execution,
            Err(error) => {
                stats.errors += 1;
                consecutive_errors = consecutive_errors.saturating_add(1);
                eprintln!("[!] execution failed (continuing): {error:#}");
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    anyhow::bail!("too many consecutive fuzzer errors: {error:#}");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
        };
        consecutive_errors = 0;

        match execution {
            ExecutionResult::Success(cov) => {
                if coverage.is_new(&cov) {
                    if let Err(error) = corpus.add(program, cov.clone()) {
                        stats.errors += 1;
                        eprintln!("[!] failed to persist new corpus entry: {error:#}");
                        continue;
                    }
                    coverage.update(&cov);
                    println!(
                        "[+] New coverage discovered! Total occupied slots: {}",
                        coverage.total_occupied_slots()
                    );
                    stats.new_coverage += 1;
                }
                stats.successes += 1;
            }
            ExecutionResult::Crash(info) => {
                println!("[!] CRASH detected: {}", info.classification);
                match save_crash_program(&args.crash_dir, &program) {
                    Ok(crash_file) => {
                        println!("[!] Crash reproducer saved: {}", crash_file.display());
                        stats.crashes += 1;
                    }
                    Err(error) => {
                        stats.errors += 1;
                        eprintln!("[!] failed to save crash reproducer (continuing): {error:#}");
                    }
                }
            }
            ExecutionResult::Timeout => {
                stats.timeouts += 1;
            }
            ExecutionResult::Hang => {
                println!("[!] HANG detected");
                stats.hangs += 1;
            }
        }

        // Report progress every 100 iterations
        if stats.iterations % 100 == 0 {
            stats.print_progress();
        }
    }

    println!("\n=== Fuzzing Complete ===");
    stats.print_final();
    println!("Corpus entries: {}", corpus.len());
    println!("Total occupied slots: {}", coverage.total_occupied_slots());

    Ok(())
}

static NEXT_CRASH_ID: AtomicU64 = AtomicU64::new(1);

/// Persist a crash reproducer without ever replacing an existing artifact.
/// Timestamp seconds are not unique enough for a fast fuzzer; an atomic
/// sequence plus `create_new` gives both readable names and a race-safe
/// no-clobber guarantee (U58-3).
fn save_crash_program(crash_dir: &std::path::Path, program: &SyscallProgram) -> Result<PathBuf> {
    let data = program.canonical_json()?;
    let timestamp_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    for _ in 0..1024u16 {
        let sequence = NEXT_CRASH_ID.fetch_add(1, Ordering::Relaxed);
        let path = crash_dir.join(format!("crash-{timestamp_nanos}-{sequence}.bin"));
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("failed to create {}", path.display()));
            }
        };
        file.write_all(&data)
            .with_context(|| format!("failed to write {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync {}", path.display()))?;
        return Ok(path);
    }

    anyhow::bail!("could not allocate a unique crash filename")
}
