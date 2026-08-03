//! Fuzz-pipeline smoke simulator for CI plumbing.
//!
//! This binary deliberately does not execute Nilix or generate fuzz inputs.  It
//! exists only to exercise long-running process handling and dashboard uploads
//! in the workflow.  In particular, it must never create corpus, coverage, or
//! crash artifacts: those are evidence produced only by a real fuzz target.

use clap::Parser;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[clap(
    author,
    version,
    about = "Nilix fuzz-pipeline smoke simulator (does not execute the kernel)"
)]
struct Args {
    /// Dashboard output directory
    #[clap(long, default_value = "dashboard")]
    dashboard_dir: PathBuf,

    /// Worker ID shown in smoke-test output
    #[clap(long, default_value = "1")]
    worker_id: u32,

    /// Maximum runtime in seconds
    #[clap(long)]
    max_time: Option<u64>,

    /// Report interval in seconds
    #[clap(long, default_value = "300")]
    report_interval: u64,

    /// Maximum heartbeat iterations
    #[clap(long)]
    max_iterations: Option<u64>,

    /// Delay between heartbeats (test-only tuning knob)
    #[clap(long, default_value = "10", hide = true)]
    iteration_delay_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct SmokeStats {
    heartbeats: u64,
    elapsed: Duration,
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    run(&args).map(|_| ())
}

fn run(args: &Args) -> io::Result<SmokeStats> {
    println!("=== Nilix Fuzz-Pipeline Smoke Simulator ===");
    println!("Worker ID: {}", args.worker_id);
    println!("Dashboard: {:?}", args.dashboard_dir);
    println!("[SIMULATOR] No kernel code or fuzz input is executed.");

    fs::create_dir_all(&args.dashboard_dir)?;

    let mut heartbeats = 0u64;
    let start_time = Instant::now();
    let mut last_report = Instant::now();

    loop {
        if let Some(max_time) = args.max_time {
            if start_time.elapsed().as_secs() >= max_time {
                println!("[SIMULATOR] Max time reached, stopping");
                break;
            }
        }

        if let Some(max_iter) = args.max_iterations {
            if heartbeats >= max_iter {
                println!("[SIMULATOR] Max heartbeats reached, stopping");
                break;
            }
        }

        heartbeats += 1;

        if last_report.elapsed().as_secs() >= args.report_interval {
            let stats = SmokeStats {
                heartbeats,
                elapsed: start_time.elapsed(),
            };
            print_stats(stats);
            write_dashboard(&args.dashboard_dir, stats)?;
            last_report = Instant::now();
        }

        if args.iteration_delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(args.iteration_delay_ms));
        }
    }

    let stats = SmokeStats {
        heartbeats,
        elapsed: start_time.elapsed(),
    };
    println!("\n=== Final Smoke Statistics ===");
    print_stats(stats);
    write_dashboard(&args.dashboard_dir, stats)?;
    println!("[SIMULATOR] Smoke test completed");

    Ok(stats)
}

fn print_stats(stats: SmokeStats) {
    let elapsed_secs = stats.elapsed.as_secs();
    let heartbeats_per_sec = if elapsed_secs > 0 {
        stats.heartbeats as f64 / elapsed_secs as f64
    } else {
        0.0
    };

    println!("[SMOKE] Heartbeats: {}", stats.heartbeats);
    println!("[SMOKE] Kernel executions: 0");
    println!("[SMOKE] Runtime: {elapsed_secs}s");
    println!("[SMOKE] Heartbeats/sec: {heartbeats_per_sec:.2}");
}

fn write_dashboard(dir: &Path, stats: SmokeStats) -> io::Result<()> {
    let elapsed_secs = stats.elapsed.as_secs();
    let heartbeats_per_sec = if elapsed_secs > 0 {
        stats.heartbeats as f64 / elapsed_secs as f64
    } else {
        0.0
    };

    let json_content = format!(
        r#"{{
  "mode": "simulator",
  "kernel_executions": 0,
  "heartbeats": {},
  "runtime_secs": {},
  "heartbeats_per_sec": {:.2}
}}"#,
        stats.heartbeats, elapsed_secs, heartbeats_per_sec
    );
    fs::write(dir.join("dashboard.json"), json_content)?;

    let html_content = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Nilix Fuzz-Pipeline Smoke Simulator</title>
    <style>
        body {{ font-family: monospace; margin: 20px; background: #1e1e1e; color: #d4d4d4; }}
        h1 {{ color: #4ec9b0; }}
        .warning {{ color: #f0c674; }}
        .metric {{ margin: 10px 0; padding: 10px; background: #252526; border-left: 3px solid #007acc; }}
        .label {{ color: #9cdcfe; font-weight: bold; }}
        .value {{ color: #ce9178; }}
    </style>
</head>
<body>
    <h1>Nilix Fuzz-Pipeline Smoke Simulator</h1>
    <p class="warning">This smoke test does not execute the kernel or produce fuzz evidence.</p>
    <div class="metric"><span class="label">Kernel executions:</span> <span class="value">0</span></div>
    <div class="metric"><span class="label">Heartbeats:</span> <span class="value">{}</span></div>
    <div class="metric"><span class="label">Runtime:</span> <span class="value">{}s</span></div>
    <div class="metric"><span class="label">Heartbeats/sec:</span> <span class="value">{:.2}</span></div>
</body>
</html>"#,
        stats.heartbeats, elapsed_secs, heartbeats_per_sec
    );
    fs::write(dir.join("dashboard.html"), html_content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn smoke_run_never_creates_fuzz_evidence() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("nilix-fuzz-smoke-{}-{nonce}", std::process::id()));
        let dashboard_dir = root.join("dashboard");
        let args = Args {
            dashboard_dir: dashboard_dir.clone(),
            worker_id: 1,
            max_time: None,
            report_interval: u64::MAX,
            max_iterations: Some(10_001),
            iteration_delay_ms: 0,
        };

        let stats = run(&args).unwrap();
        assert_eq!(stats.heartbeats, 10_001);
        assert!(dashboard_dir.join("dashboard.json").is_file());

        let mut files = fs::read_dir(&dashboard_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        files.sort();
        assert_eq!(files, vec!["dashboard.html", "dashboard.json"]);

        let dashboard: Value =
            serde_json::from_slice(&fs::read(dashboard_dir.join("dashboard.json")).unwrap())
                .unwrap();
        assert_eq!(dashboard["mode"], "simulator");
        assert_eq!(dashboard["kernel_executions"], 0);
        for forbidden in ["corpus", "coverage", "crashes", "findings"] {
            assert!(dashboard.get(forbidden).is_none());
        }

        fs::remove_dir_all(root).unwrap();
    }
}
