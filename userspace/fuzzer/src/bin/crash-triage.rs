// Crash triage binary for CI integration
// Implements Phase 7 crash deduplication and minimization

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about = "Nilix crash triage tool")]
struct Args {
    /// Directory containing all crashes
    #[clap(long)]
    crash_dir: PathBuf,

    /// Output directory for triaged crashes
    #[clap(long)]
    output_dir: PathBuf,

    /// Enable deduplication
    #[clap(long)]
    dedup: bool,

    /// Enable minimization
    #[clap(long)]
    minimize: bool,
}

#[derive(Debug, Clone)]
struct Crash {
    file_path: PathBuf,
    crash_type: String,
    message: String,
    signature: String,
}

fn main() {
    let args = Args::parse();

    println!("=== Nilix Crash Triage ===");
    println!("Input: {:?}", args.crash_dir);
    println!("Output: {:?}", args.output_dir);
    println!("Dedup: {}", args.dedup);
    println!("Minimize: {}", args.minimize);

    // Create output directory
    fs::create_dir_all(&args.output_dir).expect("Failed to create output dir");

    // Collect all crash files
    let crashes = collect_crashes(&args.crash_dir);
    println!("\n[TRIAGE] Total crashes: {}", crashes.len());

    if crashes.is_empty() {
        println!("[TRIAGE] No crashes to triage");
        return;
    }

    // Deduplicate crashes
    let unique_crashes = if args.dedup {
        deduplicate_crashes(&crashes)
    } else {
        crashes
    };

    println!("[TRIAGE] Unique crashes: {}", unique_crashes.len());

    if !unique_crashes.is_empty() {
        let dedup_rate = (1.0 - (unique_crashes.len() as f64 / crashes.len() as f64)) * 100.0;
        println!("[TRIAGE] Deduplication rate: {:.1}%", dedup_rate);
    }

    // Minimize crashes
    let final_crashes = if args.minimize {
        minimize_crashes(&unique_crashes)
    } else {
        unique_crashes
    };

    // Write triaged crashes
    for (idx, crash) in final_crashes.iter().enumerate() {
        let output_file = args.output_dir.join(format!("unique-{:03}.txt", idx + 1));
        let content = format!(
            "Type: {}\nMessage: {}\nSignature: \nOriginal: {:?}\n\n--- Details ---\n\n{}",
            crash.crash_type,
            crash.message,
            crash.signature,
            crash.file_path,
            fs::read_to_string(&crash.file_path).unwrap_or_else(|_| "Unable to read crash file".to_string())
        );
        fs::write(&output_file, content).ok();
    }

    println!("\n[TRIAGE] Triage complete");
    println!("[TRIAGE] Unique crashes written to: {:?}", args.output_dir);
}

fn collect_crashes(dir: &PathBuf) -> Vec<Crash> {
    let mut crashes = Vec::new();

    if !dir.exists() {
        return crashes;
    }

    // Recursively find crash files
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Look for crash files (crash-*, timeout-*, oom-*, or .txt files)
        if filename.starts_with("crash-") || filename.starts_with("timeout-") ||
           filename.starts_with("oom-") || filename.ends_with(".txt") {

            if let Ok(content) = fs::read_to_string(path) {
                let crash = parse_crash(path.to_path_buf(), &content);
                crashes.push(crash);
            }
        }
    }

    crashes
}

fn parse_crash(path: PathBuf, content: &str) -> Crash {
    // Extract crash type (panic, page_fault, etc.)
    let crash_type = if content.contains("panic") {
        "panic"
    } else if content.contains("page fault") || content.contains("segfault") {
        "page_fault"
    } else if content.contains("timeout") {
        "timeout"
    } else if content.contains("oom") || content.contains("out of memory") {
        "oom"
    } else {
        "unknown"
    }.to_string();

    // Extract panic message (first line with "panic" or error message)
    let message = content.lines()
        .find(|line| line.contains("panic") || line.contains("error") || line.contains("ERROR"))
        .map(|line| line.trim().to_string())
        .unwrap_or_else(|| "No error message".to_string());

    // Generate signature (hash of crash type + message)
    let signature = format!("{:x}", md5::compute(format!("{}{}", crash_type, message)));

    Crash {
        file_path: path,
        crash_type,
        message,
        signature,
    }
}

fn deduplicate_crashes(crashes: &[Crash]) -> Vec<Crash> {
    let mut unique: HashMap<String, Crash> = HashMap::new();

    for crash in crashes {
        // Use signature as dedup key
        unique.entry(crash.signature.clone())
            .or_insert_with(|| crash.clone());
    }

    unique.into_values().collect()
}

fn minimize_crashes(crashes: &[Crash]) -> Vec<Crash> {
    // For now, just return as-is
    // TODO: Implement actual minimization using delta debugging
    println!("[TRIAGE] Minimization: keeping original crashes (minimization not yet implemented)");
    crashes.to_vec()
}
