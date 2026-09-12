#!/usr/bin/env python3
"""Run KSA-004 allocation/LSM/credential failures through real musl syscalls."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from iommu_failure_probe import digest


# musl exercises COW and robust-usercopy recovery, which announce [PF ENTRY]
# even when the fault is handled. Require terminal fault outcomes and clean
# completion; the boot/SMP parser's ban on all page-fault entries is inapplicable.
FATAL = re.compile(
    r"\bKERNEL PANIC\b|\bpanicked at\b|\bPANIC:|"
    r"\[(?:PAGE FAULT|DOUBLE FAULT|GPF|#UD|FATAL)\]|\btriple fault\b",
    re.IGNORECASE,
)


def expected_markers():
    markers = []
    cases = (
        ("allocation", 12, "KSA-004-INJECT stage=descriptor errno=12 heap=restored"),
        ("capability", 12, "KSA-004-INJECT stage=capability errno=12"),
        ("lsm", 13, "KSA-004-INJECT stage=lsm errno=13 cap_reserved=1"),
        ("credential", 11, "KSA-004-INJECT stage=credential errno=11"),
        ("success", 0, "KSA-004-TRUNCATE DONE"),
    )
    for family in ("open", "openat2"):
        for case, error, observation in cases:
            for attempt in range(4 if error else 1):
                identity = f"family={family} case={case} attempt={attempt}"
                markers.extend([
                    f"KSA-004-CASE BEGIN {identity}", observation,
                    f"KSA-004-CASE PASS {identity} errno={error} "
                    f"data={'preserved' if error else 'truncated'} fd=reused",
                ])
    markers.append("KSA-004-PROBES PASS families=2 negative=32 success=2")
    return markers


def evidence_passes(serial, gate_status):
    observed = [line for line in serial.splitlines() if "KSA-004-" in line]
    exits = re.findall(r"^Process 1 (?:exited with code|terminated with exit code) (-?[0-9]+)$",
                       serial, re.MULTILINE)
    return (gate_status == 0 and observed == expected_markers()
            and not FATAL.search(serial)
            and serial.splitlines().count("musl libc test passed!") == 1
            and exits == ["0"])


def check_inputs(root, manifest):
    for line in manifest.read_text().splitlines():
        expected, name = line.split("  ", 1)
        if digest(root / name) != expected:
            raise RuntimeError(f"Input differs from manifest: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-manifest", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    check_inputs(root, args.input_manifest)
    args.artifacts.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="open-fault-", dir=args.artifacts.resolve()))
    print(f"ARTIFACTS {run}", flush=True)
    result = {"manifest_sha256": digest(args.input_manifest), "pass": False}

    def command(name, argv, cwd, env=None):
        (run / f"{name}.command.json").write_text(json.dumps(argv) + "\n")
        with (run / f"{name}.log").open("wb") as log:
            status = subprocess.run(argv, cwd=cwd, env=env, stdout=log,
                                    stderr=subprocess.STDOUT).returncode
        (run / f"{name}.status").write_text(f"{status}\n")
        result[f"{name}_status"] = status
        return status

    def finish():
        check_inputs(root, args.input_manifest)
        result["final_inputs_match"] = True
        (run / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), flush=True)
        return 0 if result["pass"] else 1

    guest_elf = run / "open_fault_musl.elf"
    if command("guest-build", ["musl-gcc", "-static", "-DKSA_OPEN_FAULT_PROBE",
                              "-o", str(guest_elf), "hello_musl.c"], root / "userspace"):
        return finish()
    result["guest_sha256"] = digest(guest_elf)
    env = os.environ.copy()
    env.update({
        "ZERO_OS_OPEN_PROBE_ELF": str(guest_elf),
        "CARGO_TARGET_DIR": str(root / "kernel-target/open-fault-probe"),
        "RUSTFLAGS": f"-C link-arg=-T{root}/kernel/kernel.ld -C link-arg=-nostdlib "
                     "-C link-arg=-static -C link-arg=-pie -C relocation-model=pie "
                     "-C code-model=kernel -C panic=abort",
    })
    build = ["cargo", "build", "--release", "--target", "x86_64-unknown-none",
             "-Z", "build-std=core,alloc,compiler_builtins", "--features", "open_fault_probe"]
    if command("kernel-build", build, root / "kernel", env):
        return finish()
    esp = run / "esp"
    (esp / "EFI/BOOT").mkdir(parents=True)
    shutil.copyfile(root / "kernel-target/open-fault-probe/x86_64-unknown-none/release/kernel",
                    esp / "kernel.elf")
    shutil.copyfile(root / "bootloader-target/x86_64-unknown-uefi/release/bootloader.efi",
                    esp / "EFI/BOOT/BOOTX64.EFI")
    result["kernel_sha256"] = digest(esp / "kernel.elf")
    result["bootloader_sha256"] = digest(esp / "EFI/BOOT/BOOTX64.EFI")
    env["MUSL_CHECK_LOG_DIR"] = str(run)
    gate_status = command("musl", ["bash", "scripts/musl_check.sh", str(esp)], root, env)
    output = (run / "musl.log").read_text(errors="replace")
    directories = re.findall(r"^MUSL-CHECK ARTIFACTS: (.+)$", output, re.MULTILINE)
    if len(directories) == 1:
        serial_path = Path(directories[0]) / "serial.log"
        serial = serial_path.read_text(errors="replace")
        result["serial_sha256"] = digest(serial_path)
        result["pass"] = evidence_passes(serial, gate_status)
    result["images_unchanged"] = (
        result["kernel_sha256"] == digest(esp / "kernel.elf")
        and result["bootloader_sha256"] == digest(esp / "EFI/BOOT/BOOTX64.EFI")
        and result["guest_sha256"] == digest(guest_elf))
    result["pass"] = result["pass"] and result["images_unchanged"]
    return finish()


if __name__ == "__main__":
    raise SystemExit(main())
