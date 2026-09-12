#!/usr/bin/env python3
"""Run default-off namespace resource probes through the real four-core gate."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from gate_log import SERIAL_FATAL
from gate_inputs import verify as verify_guest_inputs
from iommu_failure_probe import digest, identity_errors


def evidence_passes(serial, status):
    expected = []
    for kind in range(3):
        expected.extend([
            f"KSA-003-RESOURCE PASS kind={kind} boundaries={5 if kind == 0 else 4} attempts=4 rejected_arc=1 admission_pressure=1 last_reference=1 counts=exact heap=exact",
            f"KSA-003-SMP PASS kind={kind} cpu_mask=0xf rounds=8 limit=4 winners=3 rejected=1 counts=exact heap=exact",
        ])
    expected.append("KSA-003-PROBES PASS types=3 cpus=4 rounds=24 counts=exact heap=exact")
    observed = [line for line in serial.splitlines() if "KSA-003-" in line]
    vfs = [line for line in serial.splitlines() if "KSA-VFS-RESOURCE" in line]
    if status not in (0, 3) or observed != expected or len(vfs) != 1 or SERIAL_FATAL.search(serial):
        return False
    match = re.fullmatch(
        r"KSA-VFS-RESOURCE PASS depth=600 path_bytes=4200 cases=last-cwd,final-namespace "
        r"stack_bytes=([0-9]+) stack_touched=([0-9]+) stack_restored=true "
        r"tables=exact heap_vfs=exact heap_ramfs=exact heap_core=exact frames=exact "
        r"admission_exhausted_at_entry=true", vfs[0])
    if match is None:
        return False
    size, touched = map(int, match.groups())
    return 16 * 1024 <= size <= 64 * 1024 and size % 4096 == 0 and 0 < touched <= size - 4096


def collect_guest_evidence(output, run, status):
    records = re.findall(
        r"^SMP-4CORE-TEST ARTIFACTS: serial=(\S+) intlog=(\S+) qemuerr=(\S+) "
        r"timeoutlog=(\S+) counts=(\S+) gate_status=(\S+)$", output, re.MULTILINE)
    if len(records) != 1:
        return {"pass": False, "evidence_error": "missing or ambiguous SMP artifact record"}
    try:
        names = ("serial.log", "interrupts.log", "qemu.stderr", "timeout.stderr", "counts.json", "platform.status")
        for original, name in zip(records[0], names):
            shutil.copyfile(original, run / name)
        bundle = Path(records[0][0] + ".inputs")
        verify_guest_inputs(bundle)
        shutil.copytree(bundle, run / "guest-inputs")
        platform_status = (run / "platform.status").read_text().strip()
        json.loads((run / "counts.json").read_text())
        serial = (run / "serial.log").read_text(errors="replace")
        return {"pass": platform_status == str(status) and evidence_passes(serial, status),
                "serial_sha256": digest(run / "serial.log"),
                "platform_status_sidecar": platform_status,
                "guest_input_record_sha256": digest(run / "guest-inputs/inputs.json")}
    except (OSError, ValueError, KeyError, TypeError) as error:
        return {"pass": False, "evidence_error": str(error)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-manifest", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    manifest_bytes = args.input_manifest.read_bytes()
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    expected_inputs = {}
    for line in manifest_bytes.decode().splitlines():
        expected, name = line.split("  ", 1)
        expected_inputs[name] = expected
        if digest(root / name) != expected:
            raise SystemExit(f"Input differs from manifest: {name}")
    args.artifacts.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="namespace-resource-", dir=args.artifacts.resolve()))
    print(f"ARTIFACTS {run}", flush=True)
    esp = run / "esp"
    (esp / "EFI/BOOT").mkdir(parents=True)
    env = os.environ.copy()
    env.update({
        "CARGO_TARGET_DIR": str(root / "kernel-target/namespace-probe"),
        "RUSTFLAGS": f"-C link-arg=-T{root}/kernel/kernel.ld -C link-arg=-nostdlib "
                     "-C link-arg=-static -C link-arg=-pie -C relocation-model=pie "
                     "-C code-model=kernel -C panic=abort",
    })
    build = ["cargo", "build", "--release", "--target", "x86_64-unknown-none",
             "-Z", "build-std=core,alloc,compiler_builtins", "--features", "namespace_probe"]
    with (run / "build.log").open("wb") as log:
        status = subprocess.run(build, cwd=root / "kernel", env=env,
                                stdout=log, stderr=subprocess.STDOUT).returncode
    (run / "build.status").write_text(f"{status}\n")
    result = {"build_command": build, "build_status": status, "pass": False,
              "build_environment": {key: env[key] for key in ("CARGO_TARGET_DIR", "RUSTFLAGS")},
              "export_base_revision_declared": args.revision,
              "source_identity_authority": "sha256_manifest", "manifest_sha256": manifest_hash}
    (run / "inputs.sha256").write_bytes(manifest_bytes)
    result["identity_errors_after_build"] = identity_errors(
        root, expected_inputs, args.input_manifest, manifest_hash, {})
    if status == 0 and not result["identity_errors_after_build"]:
        shutil.copyfile(root / "kernel-target/namespace-probe/x86_64-unknown-none/release/kernel", esp / "kernel.elf")
        shutil.copyfile(root / "bootloader-target/x86_64-unknown-uefi/release/bootloader.efi", esp / "EFI/BOOT/BOOTX64.EFI")
        # Capture the inputs before QEMU can write firmware state into the ESP.
        # A previously booted ESP is not a source for a fresh bootloader image.
        result["kernel_sha256"] = digest(esp / "kernel.elf")
        result["bootloader_sha256"] = digest(esp / "EFI/BOOT/BOOTX64.EFI")
        env["SMP_4CORE_TEST_KEEP_LOGS"] = "1"
        gate_command = ["bash", str(root / "scripts/smp_test_4core.sh"), str(esp)]
        with (run / "smp.log").open("wb") as log:
            gate_status = subprocess.run(gate_command, env=env, stdout=log,
                                         stderr=subprocess.STDOUT).returncode
        (run / "smp.status").write_text(f"{gate_status}\n")
        output = (run / "smp.log").read_text(errors="replace")
        result.update(collect_guest_evidence(output, run, gate_status))
        result.update({"smp_command": gate_command, "platform_status": gate_status,
                       "kernel_after_sha256": digest(esp / "kernel.elf"),
                       "bootloader_after_sha256": digest(esp / "EFI/BOOT/BOOTX64.EFI")})
        result["pass"] = (result["pass"] and result["kernel_sha256"] == result["kernel_after_sha256"]
                          and result["bootloader_sha256"] == result["bootloader_after_sha256"])
    result["identity_errors_final"] = identity_errors(
        root, expected_inputs, args.input_manifest, manifest_hash, {})
    result["pass"] = bool(result["pass"] and not result["identity_errors_final"])
    (run / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    (run / "gate.status").write_text("0\n" if result["pass"] else "1\n")
    print(json.dumps(result), flush=True)
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
