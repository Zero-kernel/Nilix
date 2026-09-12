#!/usr/bin/env python3
"""Retain a gate's exact inputs, process status, diagnostics and parsed evidence."""
import argparse
import json
import os
from pathlib import Path
from collections import deque
import subprocess
import sys
import tempfile
import time

try:
    from qemu_fuzz_smoke import sha256, source_identity
except ModuleNotFoundError:  # direct execution from the repository root
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from scripts.gates.qemu.qemu_fuzz_smoke import sha256, source_identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--input-manifest", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--name", help="human-readable gate name in reports")
    parser.add_argument("--allow-qualified", action="store_true",
                        help="accept exit 3 for diagnostic CI while retaining its qualified status")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a gate command is required after --")
    if args.input_manifest and not args.revision:
        parser.error("--input-manifest requires --revision")
    root = Path(__file__).resolve().parents[2]
    args.artifacts.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=args.artifacts.resolve()))
    temp = output / "logs"
    temp.mkdir()
    environment = os.environ.copy()
    environment.update({
        "TMPDIR": str(temp), "BOOT_CHECK_KEEP_LOGS": "1", "KERNEL_TEST_KEEP_LOGS": "1",
        "SMP_TEST_KEEP_LOGS": "1", "SMP_4CORE_TEST_KEEP_LOGS": "1", "EXTENDED_SMP_KEEP_LOGS": "1",
        "IOMMU_Q35_LOG_DIR": str(temp), "MUSL_CHECK_LOG_DIR": str(temp),
    })
    status, command_status, error = 2, None, None
    started = time.monotonic()
    (output / "command.json").write_text(json.dumps(command) + "\n")
    try:
        identity = source_identity(root, args.input_manifest, args.revision)
        identity["profile_environment"] = {key: value for key, value in environment.items()
                                           if key.startswith(("ZERO_OS_", "CI_GUEST_", "KERNEL_TEST_", "SMP_", "IOMMU_Q35_", "BOOT_CHECK_", "MUSL_CHECK_"))}
        binaries = tuple(f"{esp}/{name}" for esp in (
            "esp", "kernel-target/musl/esp", "kernel-target/mitigation/esp", "esp-kcov", "esp-syz", "esp-stress")
            for name in ("kernel.elf", "EFI/BOOT/BOOTX64.EFI"))
        identity["binaries_before"] = {name: sha256(root / name) for name in binaries if (root / name).is_file()}
        (output / "inputs.json").write_text(json.dumps(identity, indent=2) + "\n")
        for name, version_command in (("qemu", ["qemu-system-x86_64", "--version"]), ("rustc", ["rustc", "-vV"])):
            try:
                version = subprocess.run(version_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                         env={**environment, "RUSTUP_AUTO_INSTALL": "0"}, timeout=10)
                (output / (name + ".version")).write_bytes(version.stdout)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                (output / (name + ".version")).write_text("unavailable\n")
        with (output / "gate.log").open("wb") as log:
            result = subprocess.run(command, cwd=root, env=environment, stdout=log, stderr=subprocess.STDOUT)
        status = result.returncode
        command_status = status
        (output / "binaries-after.json").write_text(json.dumps({name: sha256(root / name) for name in binaries if (root / name).is_file()}, indent=2) + "\n")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exception:
        error = str(exception)
        status = 2
    (output / "gate.status").write_text(f"{status}\n")
    summary = {"status": status, "command_status": command_status,
               "name": args.name or args.artifacts.name,
               "scope": "command process; nested make recipe outcomes are in retained gate sidecars/logs",
               "classification": ("incomplete-evidence" if error else "command-complete" if status == 0 else "command-nonzero"),
               "error": error, "elapsed_seconds": time.monotonic() - started}
    qualified_accepted = (status == 3 and not error and args.allow_qualified
                          and environment.get("ZERO_OS_STRICT_TESTS") != "1")
    summary["allow_qualified"] = args.allow_qualified
    summary["qualified_accepted"] = qualified_accepted
    (output / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
    (output / "artifacts.sha256.json").write_text(json.dumps({str(path.relative_to(output)): sha256(path) for path in sorted(output.rglob("*")) if path.is_file()}, indent=2) + "\n")
    print(f"GATE-ARTIFACTS {output}: status={status} ({summary['classification']})")
    if error:
        print(error)
    if status and not qualified_accepted and (output / "gate.log").is_file():
        print("Last gate diagnostics (full log retained in artifacts):")
        with (output / "gate.log").open(encoding="utf8", errors="replace") as log:
            for line in deque(log, maxlen=40):
                # Prefix output so a child log cannot emit a workflow command.
                print("  " + line.rstrip()[:2000])
    if qualified_accepted:
        print("GATE-QUALIFIED: accepted for diagnostic CI; strict qualification remains open")
        return 0
    return status if 0 <= status <= 255 else 1


if __name__ == "__main__":
    raise SystemExit(main())
