#!/usr/bin/env python3
"""Parse libFuzzer output and extract structured statistics."""

import re
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional


def parse_libfuzzer_output(output: str, target: str) -> Dict[str, Any]:
    """Parse libFuzzer stdout and extract key metrics."""

    stats = {
        "target": target,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "success": False,
        "warnings": [],
        "errors": [],
        "coverage": {},
        "performance": {},
        "corpus": {},
        "artifacts": {},
    }

    # Check for overall success
    if "DONE" in output:
        stats["success"] = True

    # Extract warnings
    warning_pattern = r"WARNING: (.+)"
    for match in re.finditer(warning_pattern, output):
        stats["warnings"].append(match.group(1))

    # Extract errors
    error_pattern = r"ERROR: (.+)"
    for match in re.finditer(error_pattern, output):
        stats["errors"].append(match.group(1))

    # Extract final coverage stats (last occurrence before DONE)
    # Format: "cov: 38 ft: 40 corp: 3/115b"
    cov_pattern = r"cov:\s*(\d+)\s+ft:\s*(\d+)\s+corp:\s*(\d+)/(\d+)([KMb]*)"
    cov_matches = list(re.finditer(cov_pattern, output))
    if cov_matches:
        last_match = cov_matches[-1]
        stats["coverage"] = {
            "edges": int(last_match.group(1)),
            "features": int(last_match.group(2)),
            "corpus_count": int(last_match.group(3)),
            "corpus_size_bytes": int(last_match.group(4)),
        }

    # Extract final statistics
    stat_patterns = {
        "executed_units": r"stat::number_of_executed_units:\s*(\d+)",
        "avg_exec_per_sec": r"stat::average_exec_per_sec:\s*(\d+)",
        "new_units_added": r"stat::new_units_added:\s*(\d+)",
        "slowest_unit_sec": r"stat::slowest_unit_time_sec:\s*(\d+)",
        "peak_rss_mb": r"stat::peak_rss_mb:\s*(\d+)",
    }

    for key, pattern in stat_patterns.items():
        match = re.search(pattern, output)
        if match:
            stats["performance"][key] = int(match.group(1))

    # Extract runtime
    runtime_pattern = r"Done \d+ runs in (\d+) second"
    match = re.search(runtime_pattern, output)
    if match:
        stats["performance"]["runtime_seconds"] = int(match.group(1))

    # Check for crashes/timeouts/OOMs mentioned
    artifact_patterns = {
        "crashes": r"crash-",
        "timeouts": r"timeout-",
        "ooms": r"oom-",
    }

    for artifact_type, pattern in artifact_patterns.items():
        count = len(re.findall(pattern, output))
        if count > 0:
            stats["artifacts"][artifact_type] = count

    # Check for "no interesting inputs" warning
    if "no interesting inputs were found" in output:
        stats["quality_issues"] = ["no_coverage_growth"]

    return stats


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
        rss = stats["performance"].get("peak_rss_mb", "?")
        warn_count = len(stats["warnings"])

        report.append(f"| `{target}` | {status} | {cov} | {new_units} | {exec_sec:,} | {rss} MB | {warn_count} |")

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
                if "per_sec" in key:
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
        report.append("- Hitting stub implementations")
        report.append("- Lacking semantic structure in generated inputs")
        report.append("- Missing state machine context")
        report.append("")
        for target in no_growth:
            report.append(f"- `{target}`")
        report.append("")
        report.append("**Action:** Consider marking these as `#[ignore]` or implementing stateful harness.")
        report.append("")

    return "\n".join(report)


def main():
    if len(sys.argv) < 3:
        print("Usage: parse_fuzz_output.py <target_name> <output_file> [output_json]", file=sys.stderr)
        sys.exit(1)

    target = sys.argv[1]
    output_file = Path(sys.argv[2])
    output_json = Path(sys.argv[3]) if len(sys.argv) > 3 else None

    if not output_file.exists():
        print(f"Error: {output_file} not found", file=sys.stderr)
        sys.exit(1)

    output_text = output_file.read_text()
    stats = parse_libfuzzer_output(output_text, target)

    # Output JSON
    if output_json:
        output_json.write_text(json.dumps(stats, indent=2))
    else:
        print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
