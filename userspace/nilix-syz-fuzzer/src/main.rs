use anyhow::{Context, Result};
use std::path::PathBuf;
use clap::Parser;

use nilix_syz_fuzzer::executor::{QemuExecutor, ExecutionResult};
use nilix_syz_fuzzer::program::SyscallProgram;
use nilix_syz_fuzzer::coverage::CoverageTracker;
use nilix_syz_fuzzer::mutator::SyscallMutator;
use nilix_syz_fuzzer::corpus::Corpus;
use nilix_syz_fuzzer::stats::FuzzStats;
use nilix_syz_fuzzer::disk::Ext3Tools;

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

    std::fs::create_dir_all(&args.corpus_dir)
        .context("Failed to create corpus directory")?;
    std::fs::create_dir_all(&args.crash_dir)
        .context("Failed to create crash directory")?;

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

    // Main fuzzing loop
    while std::time::Instant::now() < deadline {
        stats.iterations += 1;

        // Select seed from corpus
        let seed = corpus.select_seed(&stats)?;

        // Mutate to generate new program
        let program = mutator.mutate(&seed)?;

        // Execute in QEMU
        let executor = QemuExecutor::new(
            &args.qemu,
            &args.kernel,
            args.ovmf.as_deref(),
            args.program_timeout,
            128,  // 128 MiB disk
            Ext3Tools::default(),
        )?;

        match executor.execute(&program)? {
            ExecutionResult::Success(cov) => {
                if coverage.is_new(&cov) {
                    corpus.add(program, cov.clone())?;
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
                let crash_file = args.crash_dir.join(format!(
                    "crash-{}.bin",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                ));
                program.save_to_file(&crash_file)?;
                stats.crashes += 1;
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
    println!(
        "Total occupied slots: {}",
        coverage.total_occupied_slots()
    );

    Ok(())
}
