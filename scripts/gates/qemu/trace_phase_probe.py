#!/usr/bin/env python3
"""Negative controls for phased interrupt tracing (THREAD-HB C1).

Each case builds the kernel with the `trace_phase_probe` feature and one fault
class (`NILIX_TRACE_PHASE_PROBE`), boots it through the real completion
supervisor with `--trace-policy phased`, and checks two things:

* the fault happened in the intended trace phase: `nx-boot` before the switch
  marker (full trace), every other case after QEMU confirmed `log cpu_reset`;
* each verdict that may run phased still rejects it: the stress diagnostics,
  the Ring-3 oracle's serial check or completion contract, and gate_log.py.

Exit 0 only when every selected case passes both.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from scripts.ci import gate_log, qemu_trace  # noqa: E402
from scripts.gates.stress import stress_protocol  # noqa: E402

RING3_FATAL = re.compile(r"KERNEL PANIC|panicked at|PANIC:|\[(PAGE FAULT|DOUBLE FAULT|GPF|#UD|FATAL)\]|triple fault")
# case -> serial marker that must follow ARMED (None: QEMU logs the fault instead)
CASES = {
    "ud": "[#UD]",
    "gp": "[GPF] error=",
    "nx": "[PF ENTRY] err=0x0000000000000011",
    "triple": None,
    "nx-boot": "[PF ENTRY] err=0x0000000000000011",
}
NX_SIGNATURE = b"v=0e e=0011"
# vCPU threads may finish an interrupt record already in flight when QEMU applies
# the switch; one record is about 1.5 KiB, so 16 vCPUs fit well inside this.
SWITCH_GRACE_BYTES = 65536
SCAN_CHUNK_BYTES = 1 << 20
MAX_TRACE_LINE_BYTES = 65536
INTERRUPT_RECORD = re.compile(rb"^\s*[0-9]+: v=", re.MULTILINE)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def trace_contains(path: Path, pattern: re.Pattern, start: int = 0) -> bool:
    """Scan bounded, line-aligned blocks, including matches at block boundaries."""
    carry = b""
    with path.open("rb") as stream:
        stream.seek(start)
        while True:
            block = stream.read(SCAN_CHUNK_BYTES)
            data = carry + block
            if not block:
                return pattern.search(data) is not None
            cut = data.rfind(b"\n") + 1
            carry = data[cut:]
            if len(carry) > MAX_TRACE_LINE_BYTES:
                raise ValueError("interrupt log contains an overlong line")
            if pattern.search(data[:cut]):
                return True


def retain_interrupt_tail(source: Path, target: Path) -> None:
    with source.open("rb") as stream:
        stream.seek(max(0, source.stat().st_size - 262144))
        target.write_bytes(stream.read(262144))


def phase_failures(case: str, serial: bytes, intlog: Path, receipt: dict | None) -> list[str]:
    """Every reason the run did not fault in the intended trace phase."""
    failures = []
    text = serial.decode("utf-8", errors="replace")
    armed = text.find(f"TRACE-PHASE-PROBE ARMED kind={case}\n")
    if armed < 0:
        return ["missing ARMED marker"]
    if "TRACE-PHASE-PROBE RETURNED" in text or "TRACE-PHASE-PROBE BLOCKED" in text:
        failures.append("the probed fault returned or the kind was not built")
    armed_offset = len(text[:armed].encode("utf-8"))
    expected = CASES[case]
    if expected is not None and text.find(expected, armed) < 0:
        failures.append(f"missing {expected!r} after ARMED")
    if not isinstance(receipt, dict):
        return failures + ["missing trace receipt"]
    if case == "nx-boot":
        if receipt.get("outcome") != "marker-missing":
            failures.append(f"boot-phase fault ran with trace outcome {receipt.get('outcome')!r}")
        try:
            if not trace_contains(intlog, re.compile(re.escape(NX_SIGNATURE))):
                failures.append("full boot trace lacks the NX signature")
        except (OSError, ValueError) as error:
            failures.append(f"cannot scan interrupt log: {error}")
        return failures
    if receipt.get("outcome") != "switched":
        return failures + [f"trace outcome {receipt.get('outcome')!r}, expected switched"]
    status, _, reasons = qemu_trace.verify("phased", "phased", receipt, serial)
    if status:
        return failures + reasons
    if armed_offset < receipt.get("serial_bytes_at_switch", len(serial) + 1):
        failures.append("ARMED was written before QEMU confirmed the switch")
    start = receipt["intlog_bytes_at_switch"]
    try:
        if case == "triple" and not trace_contains(intlog, re.compile(b"Triple fault"), start):
            failures.append("the steady-phase log lacks QEMU's Triple fault")
        if trace_contains(intlog, INTERRUPT_RECORD, start + SWITCH_GRACE_BYTES):
            failures.append("interrupts were still traced after the switch")
    except (OSError, ValueError) as error:
        failures.append(f"cannot scan interrupt log: {error}")
    return failures


def verdict_detections(serial: Path, intlog: Path, stderr: Path, run: dict) -> dict:
    """How each verdict that may run phased rejects this faulting run (None: it accepts)."""
    text = serial.read_text(encoding="utf-8", errors="replace")
    detections = {}
    try:
        stress_protocol.validate_diagnostics(serial, intlog, stderr)
        detections["stress"] = None
    except stress_protocol.StressProtocolError as error:
        detections["stress"] = str(error)
    detections["ring3"] = ("serial fatal marker" if RING3_FATAL.search(text)
                           else None if run.get("reason") == "completed" else f"no completion ({run.get('reason')})")
    result = gate_log.evaluate(text, gate_log.fatal_interrupt_lines(intlog),
                               stderr.read_text(encoding="utf-8", errors="replace"), "",
                               run.get("runner_status", 1), termination_mode="completion", termination_receipt=run)
    detections["gate_log"] = "; ".join(result.reasons) if result.status == 1 else None
    return detections


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--cases", nargs="+", choices=tuple(CASES), default=list(CASES))
    parser.add_argument("--cpus", type=int, choices=(2, 4, 8, 16), default=4)
    parser.add_argument("--timeout", type=int, choices=range(60, 1801), default=300, metavar="60..1800")
    args = parser.parse_args()
    firmware = next((Path(path) for path in (
        os.environ.get("OVMF_PATH", ""), "/usr/share/qemu/OVMF.fd",
        "/usr/share/ovmf/OVMF.fd", "/usr/share/OVMF/OVMF_CODE.fd",
    ) if path and Path(path).is_file()), None)
    qemu_path = shutil.which("qemu-system-x86_64")
    bootloader = ROOT / "bootloader-target/x86_64-unknown-uefi/release/bootloader.efi"
    if firmware is None or qemu_path is None or not bootloader.is_file():
        raise SystemExit("TRACE-PHASE-PROBE BLOCKED: OVMF, QEMU or the built bootloader is unavailable")
    args.artifacts.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="trace-phase-", dir=args.artifacts.resolve()))
    print(f"ARTIFACTS {run_dir}", flush=True)
    (run_dir / "qemu.version").write_text(subprocess.run([qemu_path, "--version"], capture_output=True,
                                                         text=True, check=True).stdout)
    tools = {"qemu": {"path": qemu_path, "sha256": digest(Path(qemu_path))},
             "firmware": {"path": str(firmware.resolve()), "sha256": digest(firmware)}}
    results = []
    for case in args.cases:
        case_dir = run_dir / case
        esp = case_dir / "esp"
        (esp / "EFI/BOOT").mkdir(parents=True)
        result = {"case": case, "cpus": args.cpus, "tools": tools, "pass": False}
        environment = dict(os.environ, NILIX_TRACE_PHASE_PROBE=case,
                           CARGO_TARGET_DIR=str(ROOT / "kernel-target/trace-phase-probe"),
                           RUSTFLAGS=f"-C link-arg=-T{ROOT}/kernel/kernel.ld -C link-arg=-nostdlib "
                                     "-C link-arg=-static -C link-arg=-pie -C relocation-model=pie "
                                     "-C code-model=kernel -C panic=abort")
        build = ["cargo", "build", "--release", "--target", "x86_64-unknown-none",
                 "-Z", "build-std=core,alloc,compiler_builtins", "--features", "trace_phase_probe"]
        with (case_dir / "kernel-build.log").open("wb") as log:
            result["build_status"] = subprocess.run(build, cwd=ROOT / "kernel", env=environment,
                                                    stdout=log, stderr=subprocess.STDOUT).returncode
        if result["build_status"] == 0:
            shutil.copyfile(ROOT / "kernel-target/trace-phase-probe/x86_64-unknown-none/release/kernel",
                            esp / "kernel.elf")
            shutil.copyfile(bootloader, esp / "EFI/BOOT/BOOTX64.EFI")
            result["kernel_sha256"] = digest(esp / "kernel.elf")
            serial, intlog, stderr = case_dir / "serial.log", case_dir / "interrupts.log", case_dir / "qemu.stderr"
            receipt_path, trace_path = case_dir / "run.json", case_dir / "trace.json"
            qemu = [qemu_path, "-bios", str(firmware), "-drive", f"format=raw,file=fat:{esp},snapshot=on",
                    "-netdev", "user,id=net0,restrict=on,ipv6=off", "-device", "virtio-net-pci,netdev=net0,romfile=",
                    "-m", "256M", "-smp", str(args.cpus), "-vga", "std", "-no-reboot", "-no-shutdown",
                    "-cpu", "qemu64,+smep,+smap,+umip,+rdrand", "-display", "none",
                    "-serial", f"file:{serial}", "-d", "int,cpu_reset", "-D", str(intlog)]
            supervisor = [sys.executable, str(ROOT / "scripts/ci/qemu_run.py"), "--serial", str(serial),
                          "--qemu-stderr", str(stderr), "--receipt", str(receipt_path), "--profile", "runtime",
                          "--timeout", str(args.timeout), "--trace-policy", "phased", "--intlog", str(intlog),
                          "--trace-cpus", str(args.cpus), "--trace-receipt", str(trace_path), "--", *qemu]
            (case_dir / "supervisor.command.json").write_text(json.dumps(supervisor) + "\n")
            with (case_dir / "supervisor.log").open("wb") as log:
                result["supervisor_status"] = subprocess.run(supervisor, stdout=log, stderr=subprocess.STDOUT).returncode
            serial_bytes = serial.read_bytes() if serial.exists() else b""
            intlog_size = intlog.stat().st_size if intlog.exists() else 0
            run = qemu_trace.load_receipt(receipt_path) or {}
            trace = qemu_trace.load_receipt(trace_path)
            result.update(run_reason=run.get("reason"), trace=trace,
                          serial_sha256=hashlib.sha256(serial_bytes).hexdigest(), intlog_bytes=intlog_size,
                          phase_failures=phase_failures(case, serial_bytes, intlog, trace),
                          detections=verdict_detections(serial, intlog, stderr, run))
            result["pass"] = not result["phase_failures"] and all(result["detections"].values())
            # Keep the decision-relevant log tail; the full boot trace can reach GBs.
            if intlog_size:
                retain_interrupt_tail(intlog, case_dir / "interrupts.tail.log")
                intlog.unlink()
        results.append(result)
        (case_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({key: result.get(key) for key in (
            "case", "pass", "build_status", "run_reason", "phase_failures", "detections")}), flush=True)
    passed = all(result["pass"] for result in results)
    (run_dir / "summary.json").write_text(json.dumps({"pass": passed, "cases": [
        {"case": result["case"], "pass": result["pass"]} for result in results]}, indent=2) + "\n")
    print(f"TRACE-PHASE-PROBE {'PASS' if passed else 'FAIL'}: {sum(r['pass'] for r in results)}/{len(results)} cases")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
