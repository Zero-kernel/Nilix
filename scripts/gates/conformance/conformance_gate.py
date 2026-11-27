#!/usr/bin/env python3
"""Nilix N2.2 (#66) external conformance gate (libc-test / LTP).

Boots the isolated `esp-conformance` kernel image with a freshly generated ext3
conformance disk, parses structured `CONF-CASE` and `CONF-SUMMARY` records from
the serial log, and compares them against a count-pinned pass list:
  - Any case in `<suite>.pass` that does not report `status=PASS` fails (exit 1).
  - Any case outside `<suite>.pass` that reports `status=PASS` prints
    `NEW-PASS suite=<suite> name=<name>` and fails (exit 1) so the pass list
    grows in the same PR.
  - Kernel panics, missing summaries, or non-zero PID 1 exit fail (exit 1).
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
CPU_MODEL = "qemu64,+smep,+smap,+umip,+rdrand,+rdtscp"

CASE_RE = re.compile(
    r"^CONF-CASE suite=(\S+) name=(\S+) status=(PASS|FAIL|TIMEOUT|EXECFAIL) exit=(-?[0-9]+)\s*$"
)
SUMMARY_RE = re.compile(
    r"^CONF-SUMMARY suite=(\S+) total=([0-9]+) pass=([0-9]+) fail=([0-9]+) "
    r"timeout=([0-9]+) execfail=([0-9]+)\s*$"
)
PID1_EXIT_RE = re.compile(
    r"Process 1 (?:exited with code|terminated with exit code) (-?[0-9]+)\s*$",
    re.MULTILINE,
)
FATAL_RE = re.compile(
    r"\bKERNEL PANIC\b|\bpanicked at\b|\bPANIC:|\btriple fault\b|^CONF-ERROR ",
    re.MULTILINE,
)
COUNT_HEADER_RE = re.compile(r"^#\s*count:\s*([0-9]+)\s*$")
NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


@dataclass(frozen=True)
class ConformanceEval:
    ok: bool
    passed: tuple[str, ...]
    failed: tuple[str, ...]
    timed_out: tuple[str, ...]
    exec_failed: tuple[str, ...]
    regressions: tuple[str, ...]
    new_passes: tuple[str, ...]
    errors: tuple[str, ...]


def parse_passlist(path: Path) -> list[str]:
    """Read a count-pinned `<suite>.pass` file and enforce `# count: N`."""
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ValueError(f"{path}: empty pass list (missing '# count: N' header)")
    header = COUNT_HEADER_RE.match(lines[0])
    if not header:
        raise ValueError(f"{path}:1: first line must be '# count: N'")
    declared_count = int(header.group(1))
    entries: list[str] = []
    seen: set[str] = set()
    for lineno, raw in enumerate(lines[1:], 2):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not NAME_RE.fullmatch(stripped):
            raise ValueError(f"{path}:{lineno}: invalid case name {stripped!r}")
        if stripped in seen:
            raise ValueError(f"{path}:{lineno}: duplicate case name {stripped!r}")
        seen.add(stripped)
        entries.append(stripped)
    if entries != sorted(entries):
        raise ValueError(f"{path}: pass list entries must be sorted in C/lexicographical order")
    if len(entries) != declared_count:
        raise ValueError(
            f"{path}: declared '# count: {declared_count}' does not match actual entry count {len(entries)}"
        )
    return entries


def parse_removed(path: Path) -> dict[str, str]:
    """Read `<suite>.removed` mapping intentionally removed cases to reasons."""
    if not path.exists():
        return {}
    reasons: dict[str, str] = {}
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "|" not in stripped:
            raise ValueError(f"{path}:{lineno}: expected '<name> | <reason>'")
        name, reason = (part.strip() for part in stripped.split("|", 1))
        if not NAME_RE.fullmatch(name) or not reason:
            raise ValueError(f"{path}:{lineno}: empty name or reason")
        reasons[name] = reason
    return reasons


def check_passlist_removals(
    old_entries: list[str],
    new_entries: list[str],
    removed_reasons: dict[str, str],
) -> list[str]:
    """Return any removed case names lacking an explanation in `<suite>.removed`."""
    new_set = set(new_entries)
    return [name for name in old_entries if name not in new_set and name not in removed_reasons]


def write_passlist(path: Path, suite: str, names: list[str]) -> None:
    ordered = sorted(set(names))
    header = [
        f"# count: {len(ordered)}",
        f"# Count-pinned {suite} conformance pass list (N2.2, #66).",
        "# Sorted lexicographically; any deletion must record a reason in "
        f"{suite}.removed.",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(header + ordered) + "\n", encoding="utf-8")


def evaluate_conformance(
    serial_text: str,
    suite: str,
    expected_pass: list[str],
    manifest_names: list[str] | None = None,
    removed_names: set[str] | None = None,
) -> ConformanceEval:
    """Validate guest serial output against the count-pinned pass list."""
    errors: list[str] = []
    if FATAL_RE.search(serial_text):
        errors.append("fatal kernel panic or CONF-ERROR observed in serial output")

    cases: dict[str, tuple[str, int]] = {}
    summaries: list[tuple[str, int, int, int, int, int]] = []
    pid1_exits: list[int] = []

    for raw in serial_text.splitlines():
        line = raw.rstrip("\r")
        m_case = CASE_RE.match(line)
        if m_case:
            c_suite, name, status, exit_s = m_case.groups()
            if c_suite != suite:
                errors.append(f"unexpected suite {c_suite!r} for case {name!r} (expected {suite!r})")
                continue
            if name in cases:
                errors.append(f"duplicate CONF-CASE record for {name!r}")
                continue
            cases[name] = (status, int(exit_s))
            continue
        m_sum = SUMMARY_RE.match(line)
        if m_sum:
            summaries.append(
                (
                    m_sum.group(1),
                    int(m_sum.group(2)),
                    int(m_sum.group(3)),
                    int(m_sum.group(4)),
                    int(m_sum.group(5)),
                    int(m_sum.group(6)),
                )
            )
            continue
        m_exit = PID1_EXIT_RE.search(line)
        if m_exit:
            pid1_exits.append(int(m_exit.group(1)))

    if len(summaries) != 1:
        errors.append(f"expected exactly one CONF-SUMMARY line, found {len(summaries)}")
    else:
        s_suite, total, s_pass, s_fail, s_to, s_ef = summaries[0]
        if s_suite != suite:
            errors.append(f"CONF-SUMMARY suite {s_suite!r} does not match {suite!r}")
        if total != len(cases):
            errors.append(f"CONF-SUMMARY total={total} does not match {len(cases)} CONF-CASE records")
        obs_pass = sum(1 for st, _ in cases.values() if st == "PASS")
        obs_fail = sum(1 for st, _ in cases.values() if st == "FAIL")
        obs_to = sum(1 for st, _ in cases.values() if st == "TIMEOUT")
        obs_ef = sum(1 for st, _ in cases.values() if st == "EXECFAIL")
        if (obs_pass, obs_fail, obs_to, obs_ef) != (s_pass, s_fail, s_to, s_ef):
            errors.append(
                f"CONF-SUMMARY counts ({s_pass},{s_fail},{s_to},{s_ef}) disagree with "
                f"observed ({obs_pass},{obs_fail},{obs_to},{obs_ef})"
            )

    if pid1_exits != [0]:
        errors.append(f"expected single PID 1 exit 0, observed {pid1_exits}")

    if manifest_names is not None:
        missing_from_run = [name for name in manifest_names if name not in cases]
        if missing_from_run:
            errors.append(f"manifest cases missing from guest run: {', '.join(missing_from_run[:10])}")

    passed = tuple(sorted(name for name, (st, _) in cases.items() if st == "PASS"))
    failed = tuple(sorted(name for name, (st, _) in cases.items() if st == "FAIL"))
    timed_out = tuple(sorted(name for name, (st, _) in cases.items() if st == "TIMEOUT"))
    exec_failed = tuple(sorted(name for name, (st, _) in cases.items() if st == "EXECFAIL"))

    expected_set = set(expected_pass)
    removed_set = removed_names or set()
    passed_set = set(passed)
    regressions = tuple(sorted(name for name in expected_pass if name not in passed_set))
    new_passes = tuple(
        sorted(name for name in passed if name not in expected_set and name not in removed_set)
    )

    ok = not errors and not regressions and not new_passes
    return ConformanceEval(
        ok=ok,
        passed=passed,
        failed=failed,
        timed_out=timed_out,
        exec_failed=exec_failed,
        regressions=regressions,
        new_passes=new_passes,
        errors=tuple(errors),
    )


def find_ovmf(override: str | None) -> Path:
    candidates = [
        override or "",
        os.environ.get("OVMF_PATH", ""),
        "/usr/share/qemu/OVMF.fd",
        "/usr/share/ovmf/OVMF.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
    ]
    for item in candidates:
        if item and Path(item).is_file():
            return Path(item)
    raise RuntimeError("OVMF firmware not found (set OVMF_PATH or --ovmf)")


def load_manifest_names(manifest: Path | None) -> list[str] | None:
    if manifest is None:
        return None
    names: list[str] = []
    for raw in manifest.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            names.append(parts[1])
    return names


def run_guest(
    esp: Path,
    disk: Path,
    ovmf: Path,
    cpus: int,
    timeout_sec: int,
    artifact_dir: Path,
) -> tuple[str, int]:
    qemu = shutil.which("qemu-system-x86_64")
    if not qemu:
        raise RuntimeError("qemu-system-x86_64 not found in PATH")
    if not (esp / "kernel.elf").is_file():
        raise RuntimeError(f"missing kernel image: {esp / 'kernel.elf'}")
    if not disk.is_file():
        raise RuntimeError(f"missing conformance disk image: {disk}")

    artifact_dir.mkdir(parents=True, exist_ok=True)
    serial_path = artifact_dir / "serial.log"
    stderr_path = artifact_dir / "qemu.stderr"
    # Work on a disposable copy of the disk so repeated runs stay identical.
    disk_copy = artifact_dir / "disk-run.img"
    shutil.copyfile(disk, disk_copy)

    cmd = [
        qemu,
        "-bios",
        str(ovmf),
        "-drive",
        f"format=raw,file=fat:{esp},snapshot=on",
        "-drive",
        f"if=none,file={disk_copy},format=raw,id=vdisk0,cache=writeback",
        "-device",
        "virtio-blk-pci,drive=vdisk0,logical_block_size=512,physical_block_size=512",
        "-m",
        "512M",
        "-smp",
        str(cpus),
        "-vga",
        "std",
        "-no-reboot",
        "-no-shutdown",
        "-cpu",
        CPU_MODEL,
        "-netdev",
        "user,id=net0,restrict=on,ipv6=off",
        "-device",
        "virtio-net-pci,netdev=net0,romfile=",
        "-display",
        "none",
        "-serial",
        f"file:{serial_path}",
    ]

    with stderr_path.open("wb") as errf:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=errf)
        deadline = time.monotonic() + timeout_sec
        completed = False
        try:
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    break
                if serial_path.exists():
                    text = serial_path.read_text(errors="replace")
                    if PID1_EXIT_RE.search(text) or FATAL_RE.search(text):
                        # Give serial TX a brief drain window before stopping QEMU.
                        time.sleep(0.3)
                        completed = True
                        break
                time.sleep(0.2)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            disk_copy.unlink(missing_ok=True)

    serial_text = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    return serial_text, 0 if completed else (proc.returncode if proc.returncode is not None else 124)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", default="libc-test")
    parser.add_argument("--esp", type=Path, default=ROOT / "esp-conformance")
    parser.add_argument("--disk", type=Path, default=ROOT / "target/conformance/libc-test.img")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "target/conformance/build/libc-test/manifest.txt",
    )
    parser.add_argument(
        "--passlist",
        type=Path,
        default=ROOT / "scripts/conformance/libc-test.pass",
    )
    parser.add_argument("--ovmf", default=None)
    parser.add_argument("--cpus", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--artifacts", type=Path, default=ROOT / "target/conformance/artifacts")
    parser.add_argument(
        "--update-passlist",
        action="store_true",
        help="Write the observed PASS set into --passlist (curation only, never in CI).",
    )
    args = parser.parse_args()

    try:
        ovmf = find_ovmf(args.ovmf)
        manifest_names = load_manifest_names(args.manifest) if args.manifest.is_file() else None
        removed_path = args.passlist.with_suffix(".removed")
        removed_reasons = parse_removed(removed_path)
        expected_pass = [] if args.update_passlist else parse_passlist(args.passlist)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"CONFORMANCE-GATE BLOCKED: {error}", file=sys.stderr)
        return 2

    args.artifacts.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix=f"{args.suite}-", dir=args.artifacts))
    try:
        serial_text, _ = run_guest(
            args.esp.resolve(),
            args.disk.resolve(),
            ovmf,
            args.cpus,
            args.timeout,
            run_dir,
        )
    except RuntimeError as error:
        print(f"CONFORMANCE-GATE BLOCKED: {error}", file=sys.stderr)
        return 2

    result = evaluate_conformance(
        serial_text,
        args.suite,
        expected_pass,
        manifest_names,
        removed_names=set(removed_reasons),
    )
    report = {
        "suite": args.suite,
        "ok": result.ok,
        "passed_count": len(result.passed),
        "failed_count": len(result.failed),
        "timeout_count": len(result.timed_out),
        "execfail_count": len(result.exec_failed),
        "regressions": list(result.regressions),
        "new_passes": list(result.new_passes),
        "errors": list(result.errors),
        "passed": list(result.passed),
        "failed": list(result.failed),
        "timed_out": list(result.timed_out),
        "exec_failed": list(result.exec_failed),
        "artifacts": str(run_dir),
    }
    (run_dir / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if args.update_passlist:
        if result.errors:
            for err in result.errors:
                print(f"CONFORMANCE-ERROR: {err}", file=sys.stderr)
            return 1
        write_passlist(args.passlist, args.suite, list(result.passed))
        print(
            f"CONFORMANCE-PASSLIST UPDATED suite={args.suite} pass={len(result.passed)} "
            f"fail={len(result.failed)} timeout={len(result.timed_out)} "
            f"execfail={len(result.exec_failed)} file={args.passlist}"
        )
        return 0

    for name in result.regressions:
        print(f"REGRESSION suite={args.suite} name={name}", file=sys.stderr)
    for name in result.new_passes:
        print(f"NEW-PASS suite={args.suite} name={name}")
    for err in result.errors:
        print(f"CONFORMANCE-ERROR: {err}", file=sys.stderr)

    if result.ok:
        print(
            f"CONFORMANCE-GATE PASS suite={args.suite} pass={len(result.passed)} "
            f"fail={len(result.failed)} timeout={len(result.timed_out)} "
            f"execfail={len(result.exec_failed)} artifacts={run_dir}"
        )
        return 0

    print(
        f"CONFORMANCE-GATE FAIL suite={args.suite} pass={len(result.passed)} "
        f"regressions={len(result.regressions)} new_passes={len(result.new_passes)} "
        f"errors={len(result.errors)} artifacts={run_dir}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
