#!/usr/bin/env python3
"""Generate GitHub Actions summary from fuzz test statistics."""

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


def generate_summary(all_stats: list[Dict[str, Any]]) -> str:
    """Generate GitHub Actions summary markdown."""

    lines = []

    # Title and date
    lines.append("# Kernel Fuzz Test Results")
    lines.append("")
    lines.append(f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")

    # Check for crashes
    crashes = [s for s in all_stats if s["artifacts"].get("crashes", 0) > 0]
    if crashes:
        lines.append("## ⚠️ Crashes Found")
        lines.append("")
        for stats in crashes:
            count = stats["artifacts"]["crashes"]
            lines.append(f"- **{stats['target']}**: {count} crash(es)")
        lines.append("")
    else:
        lines.append("## ✅ No Crashes Found")
        lines.append("")
        lines.append("All fuzz targets completed successfully!")
        lines.append("")

    # Summary table
    lines.append("## Test Summary")
    lines.append("")
    lines.append("| Target | Status | Coverage (edges) | New Units | Exec/sec | Peak RSS | Warnings |")
    lines.append("|--------|--------|------------------|-----------|----------|----------|----------|")

    for stats in all_stats:
        target = stats["target"]
        status = "✅" if stats["success"] else "❌"

        cov = stats["coverage"].get("edges", "?")
        new_units = stats["performance"].get("new_units_added", "?")
        exec_sec = stats["performance"].get("avg_exec_per_sec", "?")
        if isinstance(exec_sec, int):
            exec_sec = f"{exec_sec:,}"
        rss = stats["performance"].get("peak_rss_mb", "?")
        if isinstance(rss, int):
            rss = f"{rss}"
        warn_count = len(stats["warnings"])

        lines.append(f"| `{target}` | {status} | {cov} | {new_units} | {exec_sec} | {rss} MB | {warn_count} |")

    lines.append("")

    # Coverage details
    total_edges = sum(s["coverage"].get("edges", 0) for s in all_stats)
    total_features = sum(s["coverage"].get("features", 0) for s in all_stats)
    total_corpus = sum(s["coverage"].get("corpus_count", 0) for s in all_stats)

    lines.append("## Coverage Metrics")
    lines.append("")
    lines.append(f"- **Total edges covered:** {total_edges:,}")
    lines.append(f"- **Total features:** {total_features:,}")
    lines.append(f"- **Total corpus entries:** {total_corpus:,}")
    lines.append("")

    # Quality issues
    quality_issues = [s for s in all_stats if "quality_issues" in s or s["warnings"]]
    if quality_issues:
        lines.append("## ⚠️ Quality Warnings")
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>Click to expand quality issues</summary>")
        lines.append("")
        for stats in quality_issues:
            lines.append(f"### `{stats['target']}`")
            lines.append("")
            if "quality_issues" in stats:
                for issue in stats["quality_issues"]:
                    lines.append(f"- **{issue.replace('_', ' ').title()}**")
            if stats["warnings"]:
                for warn in stats["warnings"]:
                    lines.append(f"- {warn}")
            lines.append("")
        lines.append("</details>")
        lines.append("")

    # Performance insights
    high_perf = [s for s in all_stats if s["performance"].get("avg_exec_per_sec", 0) > 500000]
    low_perf = [s for s in all_stats if 0 < s["performance"].get("avg_exec_per_sec", 0) < 10000]

    if high_perf or low_perf:
        lines.append("## Performance Insights")
        lines.append("")

        if high_perf:
            lines.append("### 🚀 High-Throughput Targets (>500k exec/sec)")
            lines.append("")
            lines.append("These targets may be hitting early returns or shallow code paths:")
            lines.append("")
            for stats in sorted(high_perf, key=lambda s: s["performance"]["avg_exec_per_sec"], reverse=True):
                exec_sec = stats["performance"]["avg_exec_per_sec"]
                lines.append(f"- `{stats['target']}`: {exec_sec:,} exec/sec")
            lines.append("")

        if low_perf:
            lines.append("### 🐢 Low-Throughput Targets (<10k exec/sec)")
            lines.append("")
            lines.append("These targets may have expensive operations or deep call stacks:")
            lines.append("")
            for stats in sorted(low_perf, key=lambda s: s["performance"]["avg_exec_per_sec"]):
                exec_sec = stats["performance"]["avg_exec_per_sec"]
                lines.append(f"- `{stats['target']}`: {exec_sec:,} exec/sec")
            lines.append("")

    # Footer
    lines.append("---")
    lines.append("")
    lines.append("Full report available in artifacts.")
    lines.append("")
    lines.append("*Job summary generated at run-time*")
    lines.append("")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: generate_fuzz_summary.py <stats_dir>", file=sys.stderr)
        sys.exit(1)

    stats_dir = Path(sys.argv[1])

    if not stats_dir.exists():
        print(f"Error: {stats_dir} not found", file=sys.stderr)
        sys.exit(1)

    all_stats = load_stats(stats_dir)
    if not all_stats:
        print(f"Error: No stats files found in {stats_dir}", file=sys.stderr)
        sys.exit(1)

    summary = generate_summary(all_stats)
    print(summary)


if __name__ == "__main__":
    main()
