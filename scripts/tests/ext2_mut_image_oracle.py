#!/usr/bin/env python3
"""Run the EXT2-MUT image helper and e2fsck on disposable Ext3 images.

Build the helper with:
 cargo +nightly-2025-12-08 build -p vfs --example ext2_mut_image \
   --target x86_64-unknown-linux-gnu --features host_harness
Then pass its path and an empty evidence directory to this script. Every input
is generated in that directory; no mounted filesystem or external image changes.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gates/stress"))
from stress_protocol import probe_journal, strip_private_journal_bits


def run(command: list[str], log: Path) -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    text = result.stdout + result.stderr
    log.write_text(text)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}: {log}\n{text[-3000:]}")
    return text


def pack(path: Path) -> dict:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with path.open("rb") as src, gzip.open(str(path) + ".gz", "wb", compresslevel=1) as dst:
        shutil.copyfileobj(src, dst)
    size = path.stat().st_size
    path.unlink()
    return {"path": path.name + ".gz", "bytes": size, "sha256": digest}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    out = args.evidence_dir.resolve()
    if out.exists() and any(out.iterdir()):
        parser.error("evidence directory must be empty")
    out.mkdir(parents=True, exist_ok=True)
    helper = str(args.oracle.resolve())
    records = []
    kinds = set()
    root_only = False
    scratch = out / "fsck-scratch.img"

    def fsck(path: Path, name: str) -> None:
        shutil.copyfile(path, scratch)
        strip_private_journal_bits(scratch)
        run(["e2fsck", "-fn", str(scratch)], out / f"{name}-fsck.log")
        scratch.unlink()

    for block_size in (1024, 4096):
        base = out / f"base-{block_size}.img"
        with base.open("wb") as image:
            image.truncate(32 * 1024**2)
        run(["mke2fs", "-q", "-t", "ext3", "-F", "-b", str(block_size), "-I", "256",
             "-N", "512", "-J", "size=4", str(base)], out / f"mkfs-{block_size}.log")
        payload = out / "fixture.txt"
        payload.write_text("nonzero extended inode from e2fsprogs\n")
        run(["debugfs", "-w", "-R", f"write {payload} /fixture.bin", str(base)], out / f"fixture-{block_size}.log")
        for scenario in ("exercise", "symlink-bounds"):
            name = f"{block_size}-{scenario}"
            image = out / f"{name}.img"
            run([helper, str(base), str(image), scenario], out / f"{name}.log")
            fsck(image, name)
            records.append({"name": name, "image": pack(image), "fsck": 0})
        for scenario in ("mkdir", "symlink", "unlink", "indirect", "truncate"):
            for persist in (0, 1):
                for boundary in (1, 8, 12, 16, 22, 28, 38, 52, 70, 92):
                    name = f"{block_size}-{scenario}-{persist}-{boundary}"
                    crash = out / f"{name}-crash.img"
                    recovered = out / f"{name}-recovered.img"
                    run([helper, str(base), str(crash), scenario, str(boundary), str(persist)], out / f"{name}-inject.log")
                    probe = probe_journal(crash)
                    if probe["journal_start"]:
                        data = crash.read_bytes()
                        first = probe["journal_first_block"] * block_size
                        for count in range(1, 7):
                            commit = first + (count + 2) * block_size
                            header = data[commit:commit + block_size]
                            sequence = data[first + 24:first + 28]
                            if (header[:8] != struct.pack(">II", 0xC03B3998, 2)
                                    or header[8:12] != sequence
                                    or header[12:18] != b"ZJ01\x00\x01"
                                    or header[19] != count):
                                continue
                            digest = hashlib.sha256(b"Zero-OS ext3 journal intent v1\x00")
                            digest.update(data[first + 48:first + 64])
                            digest.update(sequence)
                            digest.update(data[first + block_size:commit])
                            digest.update(header[:352] + bytes(32) + header[384:])
                            if digest.digest() == header[352:384]:
                                kinds.add(header[18])
                    text = run([helper, str(crash), str(recovered), "recover"], out / f"{name}-recover.log")
                    root_only |= f"VISIBLE size=0 blocks={block_size // 512} " in text
                    fsck(recovered, name)
                    records.append({"name": name, "crash": pack(crash), "recovered": pack(recovered), "fsck": 0})
                    (out / "receipts.json").write_text(json.dumps(records, indent=2) + "\n")
        pack(base)
    base = out / "base-no-filetype.img"
    with base.open("wb") as image:
        image.truncate(32 * 1024**2)
    run(["mke2fs", "-q", "-t", "ext3", "-F", "-b", "4096", "-I", "256",
         "-N", "512", "-J", "size=4", "-O", "^filetype", str(base)], out / "mkfs-no-filetype.log")
    image = out / "no-filetype-exercise.img"
    run([helper, str(base), str(image), "exercise"], out / "no-filetype-exercise.log")
    fsck(image, "no-filetype-exercise")
    records.append({"name": "no-filetype-exercise", "image": pack(image), "fsck": 0})
    pack(base)
    (out / "receipts.json").write_text(json.dumps(records, indent=2) + "\n")
    if not {7, 8, 9, 10, 11, 12, 13, 14}.issubset(kinds):
        raise RuntimeError(f"missing real-image transaction coverage: {kinds}")
    if not root_only:
        raise RuntimeError("no actual root-only crash image was recovered and checked")
    summary = {"images": len(records), "transaction_kinds": sorted(kinds), "root_only": root_only, "fsck": 0}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
