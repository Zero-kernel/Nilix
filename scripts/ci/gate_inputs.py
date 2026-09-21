#!/usr/bin/env python3
"""Capture a fresh firmware ESP and verify guest/tool inputs after a gate."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys


BOOT_FILES = ("kernel.elf", "EFI/BOOT/BOOTX64.EFI")


def digest(path):
    checksum = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def prepare(source, output, firmware, qemu):
    output.mkdir(parents=True, exist_ok=False)
    entries = []
    # Select exactly these two files. Persisted NvVars/firmware boot entries from
    # another machine profile must never enter a new guest's ESP.
    for name in BOOT_FILES:
        original = (source / name).resolve(strict=True)
        captured = output / "esp" / name
        captured.parent.mkdir(parents=True, exist_ok=True)
        expected = digest(original)
        shutil.copyfile(original, captured)
        if digest(captured) != expected or digest(original) != expected:
            raise ValueError(f"input changed during capture: {name}")
        entries.extend({"path": str(path.resolve()), "sha256": expected}
                       for path in (original, captured))
    for path in (firmware, qemu, Path(sys.executable)):
        path = path.resolve(strict=True)
        entries.append({"path": str(path), "sha256": digest(path)})
    (output / "inputs.json").write_text(json.dumps({
        "schema": 1, "files": entries, "python": sys.version,
        "scope": "actual boot inputs and tools; source tree identity is recorded by the gate runner",
    }, indent=2) + "\n", encoding="utf-8")


def verify(output):
    records = json.loads((output / "inputs.json").read_text(encoding="utf-8"))
    if records.get("schema") != 1 or len(records.get("files", [])) != 7:
        raise ValueError("incomplete gate input record")
    for entry in records["files"]:
        if digest(entry["path"]) != entry["sha256"]:
            raise ValueError(f"gate input changed: {entry['path']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--firmware", type=Path)
    parser.add_argument("--qemu", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            if not all((args.source, args.firmware, args.qemu)):
                parser.error("prepare requires --source, --firmware and --qemu")
            prepare(args.source, args.output, args.firmware, args.qemu)
        else:
            verify(args.output)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"GATE-INPUTS FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
