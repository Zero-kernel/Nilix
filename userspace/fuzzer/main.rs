// Coverage-guided fuzzer main loop
// Phase 4: Corpus management + mutation + coverage feedback

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

mod corpus;
mod mutator;
mod executor;
mod seeds;

use corpus::{Corpus, CorpusEntry, has_new_coverage};
use mutator::Mutator;
use executor::Executor;

// Syscall numbers
const SYS_WRITE: usize = 1;
const SYS_EXIT: usize = 60;

// Configuration
const MAX_ITERATIONS: usize = 10_000;
const CORPUS_MAX_SIZE: usize = 1000;
const ENERGY_UPDATE_INTERVAL: usize = 100;
const STATS_INTERVAL: usize = 1000;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    write_str("=== Phase 4: Coverage-Guided Fuzzer ===\n\n");

    // Initialize
    let mut corpus = Corpus::new(CORPUS_MAX_SIZE);
    let mut mutator = Mutator::new(12345);
    let mut executor = Executor::new();

    // Initialize KCOV
    if !executor.init() {
        write_str("ERROR: KCOV initialization failed\n");
        exit(1);
    }
    write_str("[OK] KCOV initialized\n\n");

    // Load seed corpus
    write_str("Loading seed corpus...\n");
    let seeds = seeds::get_seeds();

    for (i, seed) in seeds.iter().enumerate() {
        let result = executor.execute(seed);

        if result.success {
            let entry = CorpusEntry::new(seed.clone(), result.edges, result.exec_time_us);
            corpus.add(entry);

            write_str("  Seed ");
            write_num(i + 1);
            write_str(": ");
            write_num(result.edges.len());
            write_str(" edges\n");
        }
    }

    write_str("\nSeed corpus: ");
    write_num(corpus.len());
    write_str(" entries, ");
    write_num(corpus.total_edges());
    write_str(" total edges\n\n");

    write_str("Starting fuzzing loop...\n");
    write_str("Target: >25 edges (>67% coverage)\n\n");

    // Fuzzing loop
    let mut new_coverage_count = 0;
    let mut last_new_iteration = 0;

    for iteration in 0..MAX_ITERATIONS {
        // Update energy periodically
        if iteration % ENERGY_UPDATE_INTERVAL == 0 && iteration > 0 {
            corpus.update_energy();
        }

        // Select input from corpus
        let mut seed_val = (iteration as u64) * 7919;
        let entry_idx = if let Some(entry) = corpus.select(&mut seed_val) {
            // Mutate selected entry
            let parent_sequence = entry.sequence.clone();
            entry.descendant_count += 1;

            let mutant = mutator.mutate(&parent_sequence);

            // Execute mutant
            let result = executor.execute(&mutant);

            if !result.success {
                continue;
            }

            // Check for new coverage
            let (has_new, new_edges) = has_new_coverage(&result.edges, corpus.get_coverage());

            if has_new {
                // Update parent's productivity
                entry.productive_descendants += 1;

                // Add to corpus
                let new_entry = CorpusEntry::new(mutant, result.edges.clone(), result.exec_time_us);
                corpus.add(new_entry);

                new_coverage_count += 1;
                last_new_iteration = iteration;

                write_str("[+] Iter ");
                write_num(iteration);
                write_str(": ");
                write_num(new_edges.len());
                write_str(" new edges (total: ");
                write_num(corpus.total_edges());
                write_str(", corpus: ");
                write_num(corpus.len());
                write_str(")\n");
            }

            Some(0)  // Placeholder
        } else {
            None
        };

        // Print stats periodically
        if iteration % STATS_INTERVAL == 0 && iteration > 0 {
            print_stats(iteration, &corpus, new_coverage_count, last_new_iteration);
        }

        // Check saturation (no new coverage in 2000 iterations)
        if iteration > last_new_iteration + 2000 {
            write_str("\n[!] Coverage saturated (no new edges in 2000 iterations)\n");
            write_str("    Stopping early at iteration ");
            write_num(iteration);
            write_str("\n\n");
            break;
        }
    }

    // Final report
    write_str("\n=== Final Report ===\n\n");
    write_str("Total iterations: ");
    write_num(MAX_ITERATIONS.min(last_new_iteration + 2001));
    write_str("\n");

    write_str("New coverage discoveries: ");
    write_num(new_coverage_count);
    write_str("\n");

    write_str("Final corpus size: ");
    write_num(corpus.len());
    write_str("\n");

    write_str("Total unique edges: ");
    write_num(corpus.total_edges());
    write_str("\n");

    let coverage_rate = (corpus.total_edges() * 100) / 37;  // 37 total instrumented edges
    write_str("Coverage rate: ");
    write_num(coverage_rate);
    write_str("%\n\n");

    // Success criteria check
    if corpus.total_edges() >= 25 {
        write_str("✓ SUCCESS: Coverage target achieved (>=25 edges)\n");
        exit(0);
    } else {
        write_str("✗ Target not reached (target: >=25 edges)\n");
        exit(1);
    }
}

fn print_stats(iteration: usize, corpus: &Corpus, new_coverage_count: usize, last_new: usize) {
    write_str("\n--- Stats (iteration ");
    write_num(iteration);
    write_str(") ---\n");

    write_str("  Corpus size: ");
    write_num(corpus.len());
    write_str("\n");

    write_str("  Total edges: ");
    write_num(corpus.total_edges());
    write_str("\n");

    write_str("  New coverage events: ");
    write_num(new_coverage_count);
    write_str("\n");

    write_str("  Iterations since last: ");
    write_num(iteration - last_new);
    write_str("\n\n");
}

// Helper: Write string to stdout (fd=1)
fn write_str(s: &str) {
    syscall3(SYS_WRITE, 1, s.as_ptr() as usize, s.len());
}

// Helper: Write number as decimal
fn write_num(mut n: usize) {
    if n == 0 {
        write_str("0");
        return;
    }

    let mut buf = [0u8; 20];
    let mut i = 0;

    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }

    // Reverse
    for j in 0..i/2 {
        buf.swap(j, i - 1 - j);
    }

    let s = core::str::from_utf8(&buf[..i]).unwrap_or("?");
    write_str(s);
}

fn syscall3(n: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") n,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    ret
}

fn exit(code: i32) -> ! {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_EXIT,
            in("rdi") code,
            lateout("rax") ret,
            options(noreturn)
        );
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str("\nPANIC\n");
    exit(1);
}
