#!/usr/bin/env python3
"""Fail-closed completion checks for bounded QEMU boot and SMP gates."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys

try:
    from qemu_run import termination_errors
    from qemu_trace import POLICIES, load_receipt, verify as verify_trace
except ModuleNotFoundError:
    from scripts.ci.qemu_run import termination_errors
    from scripts.ci.qemu_trace import POLICIES, load_receipt, verify as verify_trace


SUMMARY = re.compile(
    r"=== Test Summary: ([0-9]+) passed, ([0-9]+) deferred"
    r"(?: \([^()\r\n]*\))?, ([0-9]+) failed ==="
)
# The interactive guest shell may print its prompt before this marker on the
# same serial line. Accept that prefix, but require the exit record to end the
# line so appended garbage cannot satisfy completion.
PID1_EXIT = re.compile(r"Process 1 exited with code (-?[1-9][0-9]*|0)\s*$")
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
# STRICT-Q (#64) declared-scope outcomes (kernel `TestScope`). Each status must
# carry a scope of its own kind. Non-strict mode keeps them QUALIFIED; strict
# mode accepts exactly the (suite, name, status, scope) tuples in STRICT_SCOPE.
SCOPE_KEYS = ("not_applicable", "out_of_scope", "covered")
SCOPE_PREFIX = {"not_applicable": "needs_cpus:", "out_of_scope": "out_of_scope:", "covered": "covered_by:"}
QUALIFIED_KEYS = ("warning", "deferred", "skipped")
STRICT_SCOPE = Path(__file__).with_name("strict_scope.txt")
COUNTS = re.compile(
    r"(RUNTIME|SECURITY|SECURITY-BOOT)-COUNTS " + " ".join(rf"{key}=([0-9]+)" for key in OUTCOME_KEYS)
    + "(?: " + " ".join(rf"{key}=([0-9]+)" for key in SCOPE_KEYS) + ")?"
)
CASE = re.compile(
    r"(RUNTIME|SECURITY|SECURITY-BOOT)-CASE name=(\S+) "
    r"status=(pass|warning|deferred|skipped|failed|not_applicable|out_of_scope|covered)"
    r'(?: scope=(\S+))? owner=(\S+) reason=(".*")'
)


def valid_declared_scope(status: str, scope: str | None) -> bool:
    """Match a nonempty scope token, including the kernel's positive u8 CPU bound."""
    prefix = SCOPE_PREFIX.get(status)
    if not prefix or not scope or not scope.startswith(prefix):
        return False
    value = scope[len(prefix):]
    if status == "not_applicable":
        return bool(re.fullmatch(r"[1-9][0-9]{0,2}", value)) and int(value) <= 255
    return bool(value)


def load_strict_scope(path: Path = STRICT_SCOPE) -> frozenset[tuple[str, str, str, str]]:
    """Read the declared strict scope: one `suite name status scope` per line."""
    entries = set()
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        fields = raw.split("#", 1)[0].split()
        if not fields:
            continue
        if (len(fields) != 4 or fields[0] not in ("RUNTIME", "SECURITY", "SECURITY-BOOT")
                or not valid_declared_scope(fields[2], fields[3])
                or tuple(fields) in entries):
            raise ValueError(f"{path.name}:{number}: malformed or duplicate strict-scope entry")
        entries.add(tuple(fields))
    return frozenset(entries)


def qualifying_keys(strict: bool) -> tuple[str, ...]:
    """Outcome counters that qualify a result; declared scope counts only outside strict mode."""
    return QUALIFIED_KEYS if strict else QUALIFIED_KEYS + SCOPE_KEYS


def outcome_evidence(lines, legacy_counts, strict, strict_scope=None):
    """Reconcile final counters with unique, owned per-test observations."""
    errors, cases, suites = [], [], {}
    for position, line in enumerate(lines):
        # A leading space must not hide a malformed structured result. Detect
        # the candidate after whitespace, but validate the original exact line.
        candidate = line.lstrip()
        if candidate.startswith(("RUNTIME-COUNTS", "SECURITY-COUNTS", "SECURITY-BOOT-COUNTS")):
            match = COUNTS.fullmatch(line)
            if not match or match[1] in suites:
                errors.append("malformed or duplicate structured suite counts")
                continue
            counts = dict(zip(OUTCOME_KEYS + SCOPE_KEYS, (int(value or 0) for value in match.groups()[1:])))
            suites[match[1]] = (position, counts)
            if not sum(counts.values()):
                errors.append("structured suite has no tests")
        elif candidate.startswith(("RUNTIME-CASE", "SECURITY-CASE", "SECURITY-BOOT-CASE")):
            match = CASE.fullmatch(line)
            try:
                if not match:
                    raise ValueError("bad case fields")
                reason = json.loads(match[6])
                if not isinstance(reason, str) or (match[3] != "pass" and not reason.strip()):
                    raise ValueError("missing reason")
                if match[3] in SCOPE_KEYS and not valid_declared_scope(match[3], match[4]):
                    raise ValueError("declared-scope status without its scope")
                cases.append(dict(position=position, suite=match[1], name=match[2], status=match[3],
                                  scope=match[4], owner=match[5], reason=reason))
            except (ValueError, TypeError):
                errors.append("malformed test case or missing reason/owner")
    completion = next((pos for pos, line in enumerate(lines) if PID1_EXIT.fullmatch(line)), len(lines))
    summary = next((pos for pos, line in enumerate(lines) if SUMMARY.fullmatch(line)), len(lines))
    for suite, (position, counts) in suites.items():
        if position >= completion:
            errors.append("structured counts must precede PID 1 completion")
        if suite == "RUNTIME" and position <= summary:
            errors.append("runtime counts must follow the legacy summary")
        observed = dict.fromkeys(OUTCOME_KEYS + SCOPE_KEYS, 0)
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
    scoped = [(case["suite"], case["name"], case["status"], case["scope"]) for case in cases if case["status"] in SCOPE_KEYS]
    violations = []
    if strict and scoped:
        try:
            allowed = load_strict_scope() if strict_scope is None else strict_scope
        except (OSError, ValueError) as error:
            allowed = frozenset()
            errors.append(f"strict scope list unavailable: {error}")
        violations = [" ".join(entry) for entry in scoped if entry not in allowed]
    details = {"strict_requested": strict, "suites": {name: counts for name, (_, counts) in suites.items()},
               "cases": cases, "scope_violations": violations}
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
    termination_mode: str = "window",
    termination_receipt: dict | None = None,
    strict_scope: frozenset | None = None,
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
    if termination_mode == "completion":
        failures.extend(termination_errors(serial, termination_mode, termination_receipt, qemu_status))
    elif termination_mode != "window":
        failures.append("unknown termination mode")
    elif qemu_status in (125, 126, 127):
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
        match = PID1_EXIT.search(line)
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

    details, evidence_errors = outcome_evidence(lines, counts, strict, strict_scope)
    incomplete.extend(evidence_errors)
    failures.extend(f"strict mode: undeclared scope {entry}" for entry in details["scope_violations"])
    runtime_counts = details["suites"].get("RUNTIME")
    if counts is not None and not sum(runtime_counts.values() if runtime_counts else counts):
        incomplete.append("runtime Test Summary contains no tests")
    if any(suite["failed"] for suite in details["suites"].values()):
        failures.append("structured suite reports failed tests")
    qualified_counts = any(
        suite[key] for suite in details["suites"].values()
        for key in qualifying_keys(strict)
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
    details["termination_mode"] = termination_mode
    details["observation_scope"] = ("completion plus bounded tail" if termination_mode == "completion"
                                    else "full configured window")
    return GateResult(status, counts, warning_markers, skipped_markers, tuple(reasons), details)


INTERRUPT_FATAL_BYTES = re.compile(
    INTERRUPT_FATAL.pattern.encode(), re.IGNORECASE | re.MULTILINE
)
# Every INTERRUPT_FATAL alternative contains one of these lowercase literals.
INTERRUPT_FATAL_NEEDLES = (b"v=06 ", b"v=08 ", b"v=0d ", b"v=0e ", b"cpu_reset", b"triple fault")


ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


class _Drain:
    """Read a decompressor's output and remember whether it reached EOF."""

    def __init__(self, stream):
        self.stream, self.eof = stream, False

    def read(self, size: int) -> bytes:
        data = self.stream.read(size)
        self.eof = self.eof or not data
        return data


@contextmanager
def open_trace(path: Path):
    """Open an interrupt trace, decompressing a QEMU_TRACE_COMPRESS=zstd stream.

    A stream read to its end must decompress cleanly, so a truncated or corrupt
    trace is unreadable (OSError) rather than silently short. A reader that
    stops early already has what it needs, and the decompressor is stopped.
    """
    with path.open("rb") as raw:
        if raw.read(len(ZSTD_MAGIC)) != ZSTD_MAGIC and path.suffix != ".zst":
            raw.seek(0)
            yield raw
            return
    process = subprocess.Popen(["zstd", "-dcq", "--", str(path)], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    stream = _Drain(process.stdout)
    try:
        yield stream
    finally:
        if not stream.eof:
            process.kill()
        process.stdout.close()
        status = process.wait()
    if stream.eof and status != 0:
        raise OSError(f"zstd could not decompress {path} (status {status})")


def fatal_interrupt_lines(path: Path, limit: int = 64, chunk_size: int = 64 << 20) -> str:
    # Scan whole line-aligned chunks with the C regex engine; a per-line
    # Python loop takes many minutes on multi-GiB logs.
    matches: list[bytes] = []
    carry = b""
    with open_trace(path) as stream:
        while len(matches) < limit:
            block = stream.read(chunk_size)
            if not block:
                data, carry = carry, b""
            else:
                data = carry + block
                cut = data.rfind(b"\n") + 1
                if cut == 0:
                    carry = data
                    continue
                data, carry = data[:cut], data[cut:]
            lowered = data.lower()
            starts = set()
            for needle in INTERRUPT_FATAL_NEEDLES:
                at = lowered.find(needle)
                while at >= 0:
                    starts.add(lowered.rfind(b"\n", 0, at) + 1)
                    at = lowered.find(needle, at + len(needle))
            for start in sorted(starts):
                end = data.find(b"\n", start)
                line = data[start : len(data) if end < 0 else end + 1]
                if INTERRUPT_FATAL_BYTES.search(line):
                    matches.append(line)
                    if len(matches) >= limit:
                        break
            if not block:
                break
    return b"".join(matches).decode("utf-8", errors="replace")


# Combine verdicts: failure, then incompleteness, then qualification, then pass.
SEVERITY = {0: 0, 3: 1, 2: 2, 1: 3}


def apply_trace(result: GateResult, policy: str, default: str, receipt: object,
                serial: bytes, strict: bool) -> GateResult:
    """Fold a THREAD-HB C1 interrupt-trace receipt into the gate verdict."""
    trace_status, scope, reasons = verify_trace(policy, default, receipt, serial)
    status = max(result.status, trace_status, key=SEVERITY.__getitem__)
    reasons = [*result.reasons, *reasons]
    if strict and status == 3:
        status = 1
        reasons.append("strict mode rejects a diagnostic interrupt-trace scope")
    details = dict(result.details or {}, trace_policy=policy, trace_default=default, trace_scope=scope)
    return GateResult(status, result.counts, result.warning_markers, result.skipped_markers,
                      tuple(reasons), details)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True, type=Path)
    parser.add_argument("--intlog", required=True, type=Path)
    parser.add_argument("--qemu-stderr", required=True, type=Path)
    parser.add_argument("--timeout-stderr", required=True, type=Path)
    parser.add_argument("--qemu-status", required=True, type=int)
    parser.add_argument("--termination-mode", choices=("window", "completion"), default="window")
    parser.add_argument("--termination-receipt", type=Path)
    parser.add_argument("--require-iommu", action="store_true")
    parser.add_argument("--strict", action="store_true", default=os.environ.get("ZERO_OS_STRICT_TESTS") == "1")
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--trace-policy", choices=POLICIES)
    parser.add_argument("--trace-default", choices=POLICIES, default="full")
    parser.add_argument("--trace-receipt", type=Path)
    arguments = parser.parse_args()
    contents = []
    missing = []
    for path in (arguments.serial, arguments.intlog, arguments.qemu_stderr, arguments.timeout_stderr):
        try:
            if path == arguments.intlog:
                # `-d int` logs reach several GiB on 4+ CPU runs; only the
                # line-anchored INTERRUPT_FATAL scan consumes them, so stream.
                contents.append(fatal_interrupt_lines(path))
                continue
            contents.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError as error:
            contents.append("")
            missing.append(f"cannot read {path}: {error}")
    receipt = None
    if arguments.termination_mode == "completion":
        try:
            receipt = json.loads(arguments.termination_receipt.read_text())
        except (AttributeError, OSError, ValueError) as error:
            missing.append(f"cannot read termination receipt: {error}")
    result = evaluate(*contents, arguments.qemu_status, require_iommu=arguments.require_iommu,
                      strict=arguments.strict, termination_mode=arguments.termination_mode,
                      termination_receipt=receipt)
    if missing:
        result = GateResult(
            1 if result.status == 1 else 2,
            result.counts,
            result.warning_markers,
            result.skipped_markers,
            (*result.reasons, *missing),
            result.details,
        )
    if arguments.trace_policy is not None:
        try:
            serial_bytes = arguments.serial.read_bytes()
        except OSError:
            serial_bytes = b""
        result = apply_trace(result, arguments.trace_policy, arguments.trace_default,
                             load_receipt(arguments.trace_receipt), serial_bytes, arguments.strict)
    if arguments.json_output:
        payload = {"scope": "serial-and-process-policy; final caller status is recorded separately", **asdict(result)}
        arguments.json_output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(result.render())
    return result.status


if __name__ == "__main__":
    sys.exit(main())
