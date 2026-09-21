#!/usr/bin/env python3
"""Build and run terminal Q35 constructor/SIRTP/IR/TE probes in fresh guests."""

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


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def evidence_passes(content, stderr, status, case):
    expected = [
        "KSA-001-MMIO-PROBES PASS allocation_boundaries=4 retained_capacity=1 invalid_ownership=5 exclusive=1 occupied_readonly=1 unmapped=1 restoration=exact",
        "KSA-001-REGISTER-OWNER PASS prefix_removed=1 foreign_suffix_preserved=1 slots_restored=1 scratch_reclaimed=1",
        f"KSA-001-INIT BEGIN case={case}",
        f"KSA-001-INIT PASS case={case} published=0 snapshot=0 dma_rejected=1 attach_rejected=1 sticky=1 retained=1",
    ]
    observed = [line for line in content.splitlines() if "KSA-001-" in line]
    constructor_error = case != "constructor" or re.search(
        r"^\[IOMMU\]   Failed to initialize unit at 0x[0-9a-f]+: RegisterMappingFailed$",
        content, re.MULTILINE,
    )
    return bool(status == 33 and observed == expected and constructor_error
                and not SERIAL_FATAL.search(content) and not SERIAL_FATAL.search(stderr))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-manifest", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--cases", nargs="+", choices=("constructor", "sirtp", "ir", "te"),
                        default=["constructor", "sirtp", "ir", "te"])
    parser.add_argument("--timeout", type=int, choices=range(1, 901), default=900,
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
    args.artifacts.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="iommu-failure-", dir=args.artifacts.resolve()))
    print(f"ARTIFACTS {run}", flush=True)
    qemu_path = shutil.which("qemu-system-x86_64")
    if qemu_path is None:
        raise SystemExit("QEMU unavailable")
    tools = {"qemu": {"path": qemu_path, "sha256": digest(Path(qemu_path))},
             "firmware": {"path": str(firmware.resolve()), "sha256": digest(firmware)}}
    for name, command in (("qemu", [qemu_path, "--version"]), ("rustc", ["rustc", "-vV"])):
        with (run / (name + ".version")).open("wb") as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    results = []
    for case in args.cases:
        case_dir = run / case
        esp = case_dir / "esp"
        (esp / "EFI/BOOT").mkdir(parents=True)
        environment = os.environ.copy()
        environment.update({
            "ZERO_OS_IOMMU_PROBE": case,
            "CARGO_TARGET_DIR": str(root / "kernel-target/iommu-probe"),
            "RUSTFLAGS": f"-C link-arg=-T{root}/kernel/kernel.ld -C link-arg=-nostdlib "
                         "-C link-arg=-static -C link-arg=-pie -C relocation-model=pie "
                         "-C code-model=kernel -C panic=abort",
        })
        build = ["cargo", "build", "--release", "--target", "x86_64-unknown-none",
                 "-Z", "build-std=core,alloc,compiler_builtins", "--features", "iommu_init_probe"]
        with (case_dir / "build.log").open("wb") as log:
            build_status = subprocess.run(build, cwd=root / "kernel", env=environment,
                                          stdout=log, stderr=subprocess.STDOUT).returncode
        (case_dir / "build.status").write_text(f"{build_status}\n")
        result = {"case": case, "build_command": build, "build_status": build_status,
                  "manifest_sha256": manifest_hash, "revision": args.revision,
                  "tools": tools, "pass": False}
        result["identity_errors_after_build"] = identity_errors(
            root, expected_inputs, args.input_manifest, manifest_hash, tools)
        if build_status == 0 and not result["identity_errors_after_build"]:
            shutil.copyfile(root / "kernel-target/iommu-probe/x86_64-unknown-none/release/kernel",
                            esp / "kernel.elf")
            shutil.copyfile(root / "bootloader-target/x86_64-unknown-uefi/release/bootloader.efi",
                            esp / "EFI/BOOT/BOOTX64.EFI")
            serial = case_dir / "serial.log"
            before = {name: digest(esp / name) for name in ("kernel.elf", "EFI/BOOT/BOOTX64.EFI")}
            result["images_before"] = before
            command = [qemu_path, "-bios", str(firmware), "-machine", "q35",
                       "-device", "intel-iommu,intremap=on", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
                       "-drive", f"format=raw,file=fat:{esp},snapshot=on", "-m", "256M", "-vga", "std",
                       "-no-reboot", "-no-shutdown", "-cpu", "qemu64,+smep,+smap,+umip,+rdrand",
                       "-display", "none", "-serial", f"file:{serial}"]
            with (case_dir / "qemu.stderr").open("wb") as log:
                try:
                    status = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=log,
                                            timeout=args.timeout).returncode
                except subprocess.TimeoutExpired:
                    status = "timeout"
            content = serial.read_text(errors="replace") if serial.exists() else ""
            after = {name: digest(esp / name) for name in before}
            errors = identity_errors(root, expected_inputs, args.input_manifest, manifest_hash, tools)
            passed = before == after and not errors and evidence_passes(content, (case_dir / "qemu.stderr").read_text(errors="replace"), status, case)
            result.update({"qemu_command": command, "qemu_status": status, "pass": bool(passed),
                           "identity_errors_after_guest": errors,
                           "images_after": after,
                           "kernel_sha256": digest(esp / "kernel.elf"),
                           "bootloader_sha256": digest(esp / "EFI/BOOT/BOOTX64.EFI"),
                           "serial_sha256": digest(serial) if serial.exists() else None})
        results.append(result)
        (case_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), flush=True)
    (run / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    final_errors = identity_errors(root, expected_inputs, args.input_manifest, manifest_hash, tools)
    (run / "final-identity-errors.json").write_text(json.dumps(final_errors, indent=2) + "\n")
    return 0 if not final_errors and len(results) == len(args.cases) and all(item["pass"] for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
