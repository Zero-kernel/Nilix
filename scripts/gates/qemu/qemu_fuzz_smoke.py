#!/usr/bin/env python3
"""Require real process/guest evidence from the cargo-fuzz QEMU adapter."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_identity(root, manifest, revision):
    if manifest:
        entries = manifest.read_text().splitlines()
        for entry in entries:
            digest, name = entry.split("  ", 1)
            path = (root / name).resolve()
            if not path.is_relative_to(root) or sha256(path) != digest:
                raise RuntimeError(f"source manifest mismatch: {name}")
        return {"revision": revision, "input_manifest_sha256": sha256(manifest)}
    top = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], cwd=root, text=True
    ).strip()
    if Path(top).resolve() != root:
        raise RuntimeError("snapshot requires --input-manifest and --revision")
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    paths = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root
    ).decode().split("\0")
    return {
        "revision": revision,
        "files": {name: sha256(root / name) for name in paths if name and (root / name).is_file()},
    }


def check_guest_evidence(artifact_root, output):
    runs = sorted(artifact_root.glob("nilix-syz-v2-*"))
    launched = re.findall(r"^NILIX_SYZ_QEMU_STARTED pid=([1-9][0-9]*) artifacts=(.+)$", output, re.M)
    if len(runs) != 2 or len(launched) != 2:
        raise RuntimeError("expected exactly two real QEMU launches and retained runs")
    if {Path(path).resolve() for _, path in launched} != {run.resolve() for run in runs}:
        raise RuntimeError("process launch records do not match the retained runs")
    if output.count("QEMU-FUZZ-SMOKE PASS seeds=2") != 1:
        raise RuntimeError("missing or ambiguous adapter completion")
    for seed in ("getpid", "uname"):
        if len(re.findall(rf"^QEMU-FUZZ-SEED PASS name={seed} occupied=[1-9][0-9]*$", output, re.M)) != 1:
            raise RuntimeError(f"missing nonempty authenticated coverage for {seed}")
    for run in runs:
        serial = (run / "serial.log").read_text(errors="replace")
        begins = re.findall(r"^NILIX_SYZ_V2_BEGIN (seq=\w+ run=\w+ program=\w+)\r?$", serial, re.M)
        passes = re.findall(r"^NILIX_SYZ_V2_PASS (seq=\w+ run=\w+ program=\w+) slots=[1-9][0-9]* tag=[0-9a-f]{64}\r?$", serial, re.M)
        if len(begins) != 1 or passes != begins:
            raise RuntimeError(f"missing/mismatched guest completion: {run}")
        if "KERNEL PANIC" in serial or "NILIX_SYZ_V2_FAIL" in serial:
            raise RuntimeError(f"guest failure: {run}")
        if not (run / "syz-result.host.bin").is_file():
            raise RuntimeError(f"missing authenticated result artifact: {run}")
        disk_evidence = (run / "extraction-disk.sha256").read_text()
        hashes = re.fullmatch(r"before=([0-9a-f]{64})\nafter=([0-9a-f]{64})\n", disk_evidence)
        if not hashes or hashes[1] != hashes[2] or hashes[2] != sha256(run / "syz-disk.img"):
            raise RuntimeError(f"guest disk changed during or after extraction: {run}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--input-manifest", type=Path)
    parser.add_argument("--revision")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    artifact_root = (args.artifacts or root / "target/qemu-fuzz-smoke").resolve()
    artifact_root.mkdir(parents=True, exist_ok=True)
    run_root = Path(tempfile.mkdtemp(prefix="gate-", dir=artifact_root))
    status = 1
    start = time.monotonic()
    try:
        if args.input_manifest and not args.revision:
            raise RuntimeError("--input-manifest requires its source --revision")
        identity = source_identity(root, args.input_manifest, args.revision)
        kernel = (args.kernel or root / "esp-syz/kernel.elf").resolve()
        bootloader = kernel.parent / "EFI/BOOT/BOOTX64.EFI"
        identity["kernel_sha256"] = sha256(kernel)
        identity["bootloader_sha256"] = sha256(bootloader)
        (run_root / "inputs.json").write_text(json.dumps(identity, indent=2) + "\n")
        env = os.environ.copy()
        env["NILIX_FUZZ_KERNEL"] = str(kernel)
        env["NILIX_FUZZ_ARTIFACTS"] = str(run_root / "guests")
        command = ["cargo", "+nightly-2025-12-08", "run", "--manifest-path", str(root / "fuzz/Cargo.toml"),
                   "--target", "x86_64-unknown-linux-gnu", "--locked", "--features", "qemu-executor", "--example", "qemu_smoke"]
        (run_root / "command.json").write_text(json.dumps(command) + "\n")
        with (run_root / "adapter.log").open("w") as log:
            result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
        (run_root / "adapter.status").write_text(f"{result.returncode}\n")
        if result.returncode != 0:
            raise RuntimeError(f"adapter exited {result.returncode}; see adapter.log")
        output = (run_root / "adapter.log").read_text(errors="replace")
        check_guest_evidence(run_root / "guests", output)
        for run in (run_root / "guests").glob("nilix-syz-v2-*"):
            if sha256(run / "esp/kernel.elf") != identity["kernel_sha256"]:
                raise RuntimeError("executed kernel identity changed")
            if sha256(run / "esp/EFI/BOOT/BOOTX64.EFI") != identity["bootloader_sha256"]:
                raise RuntimeError("executed bootloader identity changed")
        status = 0
        print("QEMU-FUZZ-GATE PASS: 2 process launches, 2 authenticated guest completions")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"QEMU-FUZZ-GATE FAIL: {error}")
    finally:
        (run_root / "status").write_text(f"{status}\n")
        (run_root / "elapsed-seconds").write_text(f"{time.monotonic() - start:.3f}\n")
        hashes = {str(path.relative_to(run_root)): sha256(path)
                  for path in sorted(run_root.rglob("*")) if path.is_file()}
        (run_root / "artifacts.sha256.json").write_text(json.dumps(hashes, indent=2) + "\n")
        print(f"QEMU-FUZZ-GATE ARTIFACTS: {run_root}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
