#!/usr/bin/env python3
"""Fail-closed completion checks for bounded QEMU boot and SMP gates."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import sys


SUMMARY = re.compile(
    r"=== Test Summary: ([0-9]+) passed, ([0-9]+) deferred"
    r"(?: \([^()\r\n]*\))?, ([0-9]+) failed ==="
)
PID1_EXIT = re.compile(r"Process 1 exited with code (-?[1-9][0-9]*|0)")
SERIAL_FATAL = re.compile(
    r"\bKERNEL PANIC\b|\bpanicked at\b|\bPANIC:|"
    r"\[(?:PF ENTRY|PAGE FAULT|DOUBLE FAULT|GPF|#UD|FATAL)\]|\btriple fault\b",
    re.IGNORECASE,
)
INTERRUPT_FATAL = re.compile(
    r"^\s*[0-9]+: v=(?:06|08|0d|0e) .*cpl=0 "
    r"IP=0008:(?:ffffffff[0-9a-f]{8}|0000000000008[0-9a-f]{3})|"
    r"\bv=0e e=0011\b|\bcpu_reset\b|\btriple fault\b",
    re.IGNORECASE | re.MULTILINE,
)
FAILED_TEST = re.compile(r"\bFAIL(?:ED)?\b")
WARNING = re.compile(
    r"\[(?:WARN|WARNING)\]|\bWARN(?:ING)?:|\b[1-9][0-9]* warnings?\b",
    re.IGNORECASE,
)
SKIPPED = re.compile(
    r"\[(?:SKIP|SKIPPED|DEFERRED)\]|\b(?:SKIP|SKIPPED|DEFERRED):|"
    r"\b[1-9][0-9]* skipped\b",
    re.IGNORECASE,
)
IOMMU_ACTIVE = re.compile(
    r"\s*✓ IOMMU active: ([1-9][0-9]*) unit\(s\), DMA translation enabled"
)
TERM_EVENT = "timeout: sending signal TERM to command"
KILL_EVENT = "timeout: sending signal KILL to command"
LABELS = {0: "PASS (diagnostic)", 1: "FAIL", 2: "INCOMPLETE", 3: "QUALIFIED (not a strict pass)"}
OUTCOME_KEYS = ("passed", "warning", "deferred", "skipped", "failed")
COUNTS = re.compile(r"(RUNTIME|SECURITY|SECURITY-BOOT)-COUNTS " + " ".join(rf"{key}=([0-9]+)" for key in OUTCOME_KEYS))
CASE = re.compile(r'(RUNTIME|SECURITY|SECURITY-BOOT)-CASE name=(\S+) status=(pass|warning|deferred|skipped|failed) owner=(\S+) reason=(".*")')


def outcome_evidence(lines, legacy_counts, strict):
    """Reconcile final counters with unique, owned per-test observations."""
    errors, cases, suites = [], [], {}
    for position, line in enumerate(lines):
        if line.startswith(("RUNTIME-COUNTS", "SECURITY-COUNTS", "SECURITY-BOOT-COUNTS")):
            match = COUNTS.fullmatch(line)
            if not match or match[1] in suites:
                errors.append("malformed or duplicate structured suite counts")
                continue
            counts = dict(zip(OUTCOME_KEYS, map(int, match.groups()[1:])))
            suites[match[1]] = (position, counts)
            if not sum(counts.values()):
                errors.append("structured suite has no tests")
        elif line.startswith(("RUNTIME-CASE", "SECURITY-CASE", "SECURITY-BOOT-CASE")):
            match = CASE.fullmatch(line)
            try:
                if not match:
                    raise ValueError("bad case fields")
                reason = json.loads(match[5])
                if not isinstance(reason, str) or (match[3] != "pass" and not reason.strip()):
                    raise ValueError("missing reason")
                cases.append(dict(position=position, suite=match[1], name=match[2], status=match[3], owner=match[4], reason=reason))
            except (ValueError, TypeError):
                errors.append("malformed test case or missing reason/owner")
    completion = next((pos for pos, line in enumerate(lines) if PID1_EXIT.fullmatch(line)), len(lines))
    summary = next((pos for pos, line in enumerate(lines) if SUMMARY.fullmatch(line)), len(lines))
    for suite, (position, counts) in suites.items():
        if position >= completion:
            errors.append("structured counts must precede PID 1 completion")
        if suite == "RUNTIME" and position <= summary:
            errors.append("runtime counts must follow the legacy summary")
        observed = dict.fromkeys(OUTCOME_KEYS, 0)
        names = set()
        for case in (case for case in cases if case["suite"] == suite):
            if case["name"] in names or case["position"] >= min(position, summary):
                errors.append("duplicate test or case after final summary/counts")
            names.add(case["name"])
            observed["passed" if case["status"] == "pass" else case["status"]] += 1
        if observed != counts:
            errors.append(f"{suite} outcome counts do not match per-test evidence")
        if suite == "RUNTIME" and legacy_counts != (counts["passed"], counts["deferred"], counts["failed"]):
            errors.append("legacy and structured runtime counts disagree")
    if any(case["suite"] not in suites for case in cases):
        errors.append("test cases lack their structured suite counts")
    if strict and "RUNTIME" not in suites:
        errors.append("missing structured runtime counts")
    if strict and "SECURITY" not in suites:
        errors.append("strict mode requires structured security-suite evidence")
    details = {"strict_requested": strict, "suites": {name: counts for name, (_, counts) in suites.items()}, "cases": cases}
    return details, errors


@dataclass(frozen=True)
class GateResult:
    status: int
    counts: tuple[int, int, int] | None
    warning_markers: int
    skipped_markers: int
    reasons: tuple[str, ...]
    details: dict | None = None

    def render(self) -> str:
        if self.counts is None:
            summary = "summary=unavailable"
        else:
            passed, deferred, failed = self.counts
            summary = f"passed={passed} deferred={deferred} failed={failed}"
        label = "STRICT PASS" if self.status == 0 and self.details and self.details["strict_requested"] else LABELS[self.status]
        output = (
            f"GATE-LOG {label}: {summary} "
            f"warning_markers={self.warning_markers} skipped_markers={self.skipped_markers}"
        )
        return "\n".join([output, *(f"  {reason}" for reason in self.reasons)])


def evaluate(
    serial: str,
    interrupts: str,
    qemu_stderr: str,
    timeout_stderr: str,
    qemu_status: int,
    *,
    require_iommu: bool = False,
    strict: bool = False,
) -> GateResult:
    failures = []
    incomplete = []
    lines = serial.splitlines()
    # Structured counters have their own exact parser: "passed=9 warning=0"
    # must not be mistaken for a prose "9 warnings" observation.
    diagnostic_lines = [line for line in lines if not line.startswith(("RUNTIME-", "SECURITY-"))]
    warning_markers = sum(bool(WARNING.search(line)) for line in diagnostic_lines)
    skipped_markers = sum(bool(SKIPPED.search(line)) for line in diagnostic_lines)

    if SERIAL_FATAL.search(serial) or SERIAL_FATAL.search(qemu_stderr):
        failures.append("fatal serial/QEMU marker (including markers after completion)")
    if INTERRUPT_FATAL.search(interrupts):
        failures.append("NX, reset or fatal kernel/AP-trampoline exception in interrupt log")
    if FAILED_TEST.search(serial):
        failures.append("explicit FAIL/FAILED marker in serial log")

    term_events = timeout_stderr.count(TERM_EVENT)
    kill_events = timeout_stderr.count(KILL_EVENT)
    if qemu_status in (125, 126, 127):
        incomplete.append(f"QEMU/timeout could not run (status={qemu_status})")
    elif qemu_status != 124 or term_events != 1 or kill_events != 0:
        failures.append(
            f"QEMU timeout contract: status={qemu_status}/124 "
            f"TERM={term_events}/1 KILL={kill_events}/0"
        )

    summaries = []
    candidates = []
    for line_number, line in enumerate(lines):
        if "Test Summary" in line:
            candidates.append(line_number)
        match = SUMMARY.fullmatch(line)
        if match:
            summary_counts = tuple(int(value) for value in match.groups())
            summaries.append((line_number, summary_counts))
            if summary_counts[2] != 0:
                failures.append(f"runtime Test Summary reports failed={summary_counts[2]}")

    counts = summaries[0][1] if len(summaries) == len(candidates) == 1 else None
    if counts is None:
        incomplete.append("expected exactly one complete, well-formed runtime Test Summary")

    exits = []
    exit_candidates = []
    for line_number, line in enumerate(lines):
        if "Process 1 exited" in line:
            exit_candidates.append(line_number)
        match = PID1_EXIT.fullmatch(line)
        if match:
            exit_status = int(match[1])
            exits.append((line_number, exit_status))
            if exit_status != 0:
                failures.append(f"PID 1 exited with code {exit_status}")
    if len(exits) != 1 or len(exit_candidates) != 1:
        incomplete.append("expected exactly one 'Process 1 exited with code 0' completion")
    elif counts is not None and exits[0][0] <= summaries[0][0]:
        incomplete.append("PID 1 completion must follow the runtime Test Summary")

    if require_iommu:
        active = [index for index, line in enumerate(lines) if IOMMU_ACTIVE.fullmatch(line)]
        enabled = [index for index, line in enumerate(lines) if line.strip() == "- IOMMU enabled: true"]
        states = [line for line in lines if "IOMMU enabled:" in line]
        if len(active) != 1 or len(enabled) != 1 or len(states) != 1:
            failures.append("expected one active IOMMU unit summary and 'IOMMU enabled: true'")
        elif active[0] >= enabled[0] or (counts is not None and enabled[0] >= summaries[0][0]):
            failures.append("IOMMU activation and enabled state must precede runtime completion")

    details, evidence_errors = outcome_evidence(lines, counts, strict)
    incomplete.extend(evidence_errors)
    runtime_counts = details["suites"].get("RUNTIME")
    if counts is not None and not sum(runtime_counts.values() if runtime_counts else counts):
        incomplete.append("runtime Test Summary contains no tests")
    if any(suite["failed"] for suite in details["suites"].values()):
        failures.append("structured suite reports failed tests")
    qualified_counts = any(
        suite[key] for suite in details["suites"].values()
        for key in ("warning", "deferred", "skipped")
    )

    if failures:
        status = 1
    elif incomplete:
        status = 2
    elif counts[1] or warning_markers or skipped_markers or qualified_counts:
        status = 3
    else:
        status = 0
    reasons = failures + incomplete
    if status == 3:
        reasons.append("warnings/deferred/skipped checks remain; no strict qualification")
        if strict:
            status = 1
            reasons.append("strict mode rejects warnings, deferred tests and skips")
    return GateResult(status, counts, warning_markers, skipped_markers, tuple(reasons), details)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True, type=Path)
    parser.add_argument("--intlog", required=True, type=Path)
    parser.add_argument("--qemu-stderr", required=True, type=Path)
    parser.add_argument("--timeout-stderr", required=True, type=Path)
    parser.add_argument("--qemu-status", required=True, type=int)
    parser.add_argument("--require-iommu", action="store_true")
    parser.add_argument("--strict", action="store_true", default=os.environ.get("ZERO_OS_STRICT_TESTS") == "1")
    parser.add_argument("--json-output", type=Path)
    arguments = parser.parse_args()
    contents = []
    missing = []
    for path in (arguments.serial, arguments.intlog, arguments.qemu_stderr, arguments.timeout_stderr):
        try:
            contents.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError as error:
            contents.append("")
            missing.append(f"cannot read {path}: {error}")
    result = evaluate(*contents, arguments.qemu_status, require_iommu=arguments.require_iommu, strict=arguments.strict)
    if missing:
        result = GateResult(
            1 if result.status == 1 else 2,
            result.counts,
            result.warning_markers,
            result.skipped_markers,
            (*result.reasons, *missing),
            result.details,
        )
    if arguments.json_output:
        payload = {"scope": "serial-and-process-policy; final caller status is recorded separately", **asdict(result)}
        arguments.json_output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(result.render())
    return result.status


if __name__ == "__main__":
    sys.exit(main())
