#!/usr/bin/env python3
"""Run the ST-K2-P2(a) same-CPU shared-fault reentry probe, one fresh guest per lock.

Each case builds the musl guest with the lock selected, embeds it in a kernel
built with the `shared_fault_reentry_probe` feature, and boots it. The guest
asks the kernel to fault in an untouched shared-anonymous page while holding
the lock. A repaired kernel panics with "same-CPU <lock> reentry during shared
fault" and the probe image leaves QEMU through isa-debug-exit (status 35). A
kernel that retries the fault as ordinary contention spins until the timeout.
"""

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

try:
    from gate_log import SERIAL_FATAL
except ModuleNotFoundError:  # direct execution from the repository root
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from scripts.ci.gate_log import SERIAL_FATAL


# case -> (prctl lock argument, lock name in the kernel's markers)
CASES = {"table": (0, "PROCESS_TABLE"), "pcb": (1, "PCB"), "mm": (2, "MmState")}
# isa-debug-exit value 0x11 written by the probe image's panic handler.
PANIC_EXIT_STATUS = 35
PANIC_SITE = "kernel/arch/interrupts.rs:"
MESSAGE = re.compile(
    r"^same-CPU (PROCESS_TABLE|PCB|MmState) reentry during shared fault "
    r"at 0x[0-9a-f]+ \(pid [0-9]+\)$")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def evidence_failures(serial, stderr, status, case):
    """Every reason the serial log, QEMU stderr and exit status fail `case`."""
    lock = CASES[case][1]
    lines = serial.splitlines()
    failures = []
    if status != PANIC_EXIT_STATUS:
        failures.append(f"QEMU status {status!r}, expected {PANIC_EXIT_STATUS}")
    hold = [i for i, line in enumerate(lines) if line.startswith("ST-K2-REENTRY-PROBE HOLD ")]
    if [lines[i] for i in hold] != [f"ST-K2-REENTRY-PROBE HOLD lock={lock}"]:
        failures.append("expected exactly one HOLD marker for " + lock)
    if any("ST-K2-REENTRY-PROBE GUEST-RETURNED" in line
           or "ST-K2-REENTRY-PROBE RETURNED" in line for line in lines):
        failures.append("the probed fault returned")
    panics = [i for i, line in enumerate(lines) if "KERNEL PANIC" in line]
    if len(panics) != 1 or not lines[panics[0]].startswith("KERNEL PANIC: " + PANIC_SITE):
        failures.append("expected exactly one KERNEL PANIC from the page-fault handler")
    elif not hold or panics[0] < hold[0]:
        failures.append("the panic did not follow the HOLD marker")
    messages = [MESSAGE.match(line) for line in lines]
    named = [match.group(1) for match in messages if match]
    if named != [lock]:
        failures.append(f"expected exactly one reentry message for {lock}, saw {named}")
    # The expected panic is the only terminal marker allowed: drop its own lines
    # and require the rest of the log, and QEMU's stderr, to be clean.
    rest = [line for line in lines if not (
        line.startswith("KERNEL PANIC: " + PANIC_SITE)
        or line.startswith("panicked at " + PANIC_SITE))]
    if SERIAL_FATAL.search("\n".join(rest)) or SERIAL_FATAL.search(stderr):
        failures.append("an unexpected terminal fault marker")
    return failures


def evidence_passes(serial, stderr, status, case):
    return not evidence_failures(serial, stderr, status, case)


def identity_errors(root, expected_inputs, manifest, manifest_hash, tools):
    errors = []
    paths = [(root / name, expected) for name, expected in expected_inputs.items()]
    paths += [(manifest, manifest_hash)]
    paths += [(Path(tool["path"]), tool["sha256"]) for tool in tools.values()]
    for path, expected in paths:
        try:
            if digest(path) != expected:
                errors.append(f"changed input: {path}")
        except OSError as error:
            errors.append(f"unreadable input: {path}: {error}")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-manifest", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--cases", nargs="+", choices=tuple(CASES), default=list(CASES))
    parser.add_argument("--timeout", type=int, choices=range(1, 901), default=600,
                        metavar="1..900", help="maximum seconds per QEMU case")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    manifest_bytes = args.input_manifest.read_bytes()
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    expected_inputs = {}
    for line in manifest_bytes.decode().splitlines():
        expected, name = line.split("  ", 1)
        expected_inputs[name] = expected
        if digest(root / name) != expected:
            raise SystemExit(f"Input differs from manifest: {name}")
    firmware = next((Path(path) for path in (
        os.environ.get("OVMF_PATH", ""), "/usr/share/qemu/OVMF.fd",
        "/usr/share/ovmf/OVMF.fd", "/usr/share/OVMF/OVMF_CODE.fd",
    ) if path and Path(path).is_file()), None)
    if firmware is None:
        raise SystemExit("OVMF firmware unavailable")
    qemu_path = shutil.which("qemu-system-x86_64")
    if qemu_path is None:
        raise SystemExit("QEMU unavailable")
    args.artifacts.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="shared-reentry-", dir=args.artifacts.resolve()))
    print(f"ARTIFACTS {run}", flush=True)
    tools = {"qemu": {"path": qemu_path, "sha256": digest(Path(qemu_path))},
             "firmware": {"path": str(firmware.resolve()), "sha256": digest(firmware)}}
    for name, command in (("qemu", [qemu_path, "--version"]), ("rustc", ["rustc", "-vV"]),
                          ("musl-gcc", ["musl-gcc", "--version"])):
        with (run / (name + ".version")).open("wb") as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    results = []
    for case in args.cases:
        lock_arg, lock = CASES[case]
        case_dir = run / case
        esp = case_dir / "esp"
        (esp / "EFI/BOOT").mkdir(parents=True)
        result = {"case": case, "lock": lock, "manifest_sha256": manifest_hash,
                  "revision": args.revision, "tools": tools, "pass": False}

        def command(name, argv, cwd, env=None):
            (case_dir / f"{name}.command.json").write_text(json.dumps(argv) + "\n")
            with (case_dir / f"{name}.log").open("wb") as log:
                status = subprocess.run(argv, cwd=cwd, env=env, stdout=log,
                                        stderr=subprocess.STDOUT).returncode
            (case_dir / f"{name}.status").write_text(f"{status}\n")
            result[f"{name}_status"] = status
            return status

        guest = case_dir / "shared_fault_reentry_probe.elf"
        environment = os.environ.copy()
        environment.update({
            "ZERO_OS_SHARED_REENTRY_PROBE_ELF": str(guest),
            "CARGO_TARGET_DIR": str(root / "kernel-target/shared-fault-reentry-probe"),
            "RUSTFLAGS": f"-C link-arg=-T{root}/kernel/kernel.ld -C link-arg=-nostdlib "
                         "-C link-arg=-static -C link-arg=-pie -C relocation-model=pie "
                         "-C code-model=kernel -C panic=abort",
        })
        build = ["cargo", "build", "--release", "--target", "x86_64-unknown-none",
                 "-Z", "build-std=core,alloc,compiler_builtins",
                 "--features", "shared_fault_reentry_probe"]
        built = (command("guest-build", ["musl-gcc", "-static", f"-DST_K2_REENTRY_LOCK={lock_arg}",
                                         "-o", str(guest), "shared_fault_reentry_probe.c"],
                         root / "userspace") == 0
                 and command("kernel-build", build, root / "kernel", environment) == 0)
        result["identity_errors_after_build"] = identity_errors(
            root, expected_inputs, args.input_manifest, manifest_hash, tools)
        if built and not result["identity_errors_after_build"]:
            result["guest_sha256"] = digest(guest)
            shutil.copyfile(
                root / "kernel-target/shared-fault-reentry-probe/x86_64-unknown-none/release/kernel",
                esp / "kernel.elf")
            shutil.copyfile(root / "bootloader-target/x86_64-unknown-uefi/release/bootloader.efi",
                            esp / "EFI/BOOT/BOOTX64.EFI")
            serial = case_dir / "serial.log"
            before = {name: digest(esp / name) for name in ("kernel.elf", "EFI/BOOT/BOOTX64.EFI")}
            result["images_before"] = before
            qemu = [qemu_path, "-bios", str(firmware),
                    "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
                    "-drive", f"format=raw,file=fat:{esp},snapshot=on", "-m", "256M",
                    "-vga", "std", "-no-reboot", "-no-shutdown",
                    "-cpu", "qemu64,+smep,+smap,+umip,+rdrand",
                    "-display", "none", "-serial", f"file:{serial}"]
            (case_dir / "qemu.command.json").write_text(json.dumps(qemu) + "\n")
            with (case_dir / "qemu.stderr").open("wb") as log:
                try:
                    status = subprocess.run(qemu, stdout=subprocess.DEVNULL, stderr=log,
                                            timeout=args.timeout).returncode
                except subprocess.TimeoutExpired:
                    status = "timeout"
            content = serial.read_text(errors="replace") if serial.exists() else ""
            stderr = (case_dir / "qemu.stderr").read_text(errors="replace")
            after = {name: digest(esp / name) for name in before}
            errors = identity_errors(root, expected_inputs, args.input_manifest, manifest_hash, tools)
            failures = evidence_failures(content, stderr, status, case)
            result.update({"qemu_status": status, "evidence_failures": failures,
                           "identity_errors_after_guest": errors, "images_after": after,
                           "pass": before == after and not errors and not failures,
                           "serial_sha256": digest(serial) if serial.exists() else None})
        results.append(result)
        (case_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({key: result.get(key) for key in (
            "case", "qemu_status", "evidence_failures", "pass")}), flush=True)
    (run / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    final_errors = identity_errors(root, expected_inputs, args.input_manifest, manifest_hash, tools)
    (run / "final-identity-errors.json").write_text(json.dumps(final_errors, indent=2) + "\n")
    return 0 if results and all(r["pass"] for r in results) and not final_errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
