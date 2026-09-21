#!/usr/bin/env python3
"""Generate comprehensive fuzz report from collected statistics."""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any


def load_stats(stats_dir: Path) -> list[Dict[str, Any]]:
    """Load all JSON stats files from directory."""
    all_stats = []
    for json_file in sorted(stats_dir.glob("*.json")):
        try:
            stats = json.loads(json_file.read_text())
            all_stats.append(stats)
        except Exception as e:
            print(f"Warning: Failed to parse {json_file}: {e}", file=sys.stderr)
    return all_stats


def format_markdown_report(all_stats: list[Dict[str, Any]], run_id: str) -> str:
    """Generate markdown report from parsed statistics."""

    report = []
    report.append(f"# Fuzz Test Report — {run_id}")
    report.append("")
    report.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    report.append("")

    # Summary table
    report.append("## Summary")
    report.append("")
    report.append("| Target | Status | Coverage | New Units | Exec/sec | Peak RSS | Warnings |")
    report.append("|--------|--------|----------|-----------|----------|----------|----------|")

    for stats in all_stats:
        target = stats["target"]
        status = "✅ PASS" if stats["success"] else "❌ FAIL"

        cov = stats["coverage"].get("edges", "?")
        new_units = stats["performance"].get("new_units_added", "?")
        exec_sec = stats["performance"].get("avg_exec_per_sec", "?")
        if isinstance(exec_sec, int):
            exec_sec = f"{exec_sec:,}"
        rss = stats["performance"].get("peak_rss_mb", "?")
        warn_count = len(stats["warnings"])

        report.append(f"| `{target}` | {status} | {cov} | {new_units} | {exec_sec} | {rss} MB | {warn_count} |")

    report.append("")

    # Quality issues
    quality_issues = [s for s in all_stats if "quality_issues" in s or s["warnings"]]
    if quality_issues:
        report.append("## ⚠️ Quality Issues")
        report.append("")
        for stats in quality_issues:
            report.append(f"### {stats['target']}")
            if "quality_issues" in stats:
                for issue in stats["quality_issues"]:
                    report.append(f"- **{issue.replace('_', ' ').title()}**")
            if stats["warnings"]:
                report.append("**Warnings:**")
                for warn in stats["warnings"]:
                    report.append(f"- {warn}")
            report.append("")

    # Crashes
    crashes = [s for s in all_stats if s["artifacts"].get("crashes", 0) > 0]
    if crashes:
        report.append("## 🚨 Crashes Found")
        report.append("")
        for stats in crashes:
            count = stats["artifacts"]["crashes"]
            report.append(f"- **{stats['target']}**: {count} crash(es)")
        report.append("")

    # Detailed stats
    report.append("## Detailed Statistics")
    report.append("")
    for stats in all_stats:
        report.append(f"### {stats['target']}")
        report.append("")

        if stats["coverage"]:
            report.append("**Coverage:**")
            report.append(f"- Edges: {stats['coverage'].get('edges', 'N/A')}")
            report.append(f"- Features: {stats['coverage'].get('features', 'N/A')}")
            report.append(f"- Corpus count: {stats['coverage'].get('corpus_count', 'N/A')}")
            report.append(f"- Corpus size: {stats['coverage'].get('corpus_size_bytes', 'N/A')} bytes")
            report.append("")

        if stats["performance"]:
            report.append("**Performance:**")
            for key, value in stats["performance"].items():
                label = key.replace("_", " ").title()
                if isinstance(value, int) and "per_sec" in key:
                    report.append(f"- {label}: {value:,}")
                else:
                    report.append(f"- {label}: {value}")
            report.append("")

    # Recommendations
    report.append("## Recommendations")
    report.append("")

    no_growth = [s["target"] for s in all_stats if "quality_issues" in s]
    if no_growth:
        report.append("### Targets with No Coverage Growth")
        report.append("")
        report.append("The following targets show minimal coverage growth, indicating they may be:")
        report.append("- Hitting stub implementations (`host_harness` feature gates)")
        report.append("- Lacking semantic structure in generated inputs")
        report.append("- Missing state machine context (isolated subsystems)")
        report.append("")
        for target in no_growth:
            report.append(f"- `{target}`")
        report.append("")
        report.append("**Action:** Consider one of:")
        report.append("1. Implement stateful harness with mock kernel context")
        report.append("2. Mark as `#[ignore]` until stateful infrastructure is ready")
        report.append("3. Switch to QEMU-based AFL++ fuzzing for full-kernel state")
        report.append("")

    # High-performance targets
    high_perf = sorted(
        [s for s in all_stats if s["performance"].get("avg_exec_per_sec", 0) > 500000],
        key=lambda s: s["performance"].get("avg_exec_per_sec", 0),
        reverse=True
    )
    if high_perf:
        report.append("### High-Performance Targets")
        report.append("")
        report.append("Targets with >500k exec/sec indicate shallow fuzzing (hitting early returns):")
        report.append("")
        for stats in high_perf:
            exec_sec = stats["performance"]["avg_exec_per_sec"]
            report.append(f"- `{stats['target']}`: {exec_sec:,} exec/sec")
        report.append("")

    return "\n".join(report)


def main():
    if len(sys.argv) < 3:
        print("Usage: generate_fuzz_report.py <stats_dir> <output_md> [run_id]", file=sys.stderr)
        sys.exit(1)

    stats_dir = Path(sys.argv[1])
    output_md = Path(sys.argv[2])
    run_id = sys.argv[3] if len(sys.argv) > 3 else datetime.utcnow().strftime("R%Y%m%d-%H%M%S")

    if not stats_dir.exists():
        print(f"Error: {stats_dir} not found", file=sys.stderr)
        sys.exit(1)

    all_stats = load_stats(stats_dir)
    if not all_stats:
        print(f"Error: No stats files found in {stats_dir}", file=sys.stderr)
        sys.exit(1)

    report = format_markdown_report(all_stats, run_id)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text(report)
    print(f"Report written to: {output_md}")


if __name__ == "__main__":
    main()
