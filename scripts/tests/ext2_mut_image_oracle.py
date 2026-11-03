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
import concurrent.futures
import threading
import gzip
import hashlib
import json
import re
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
    parser.add_argument("--growth-only", action="store_true", help="run deep block and directory growth crash scenarios")
    parser.add_argument("--jobs", type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 8:
        parser.error("jobs must be between 1 and 8")
    out = args.evidence_dir.resolve()
    if out.exists() and any(out.iterdir()):
        parser.error("evidence directory must be empty")
    out.mkdir(parents=True, exist_ok=True)
    helper = str(args.oracle.resolve())
    (out / "run.json").write_text(json.dumps({
        "argv": sys.argv, "helper_sha256": hashlib.sha256(Path(helper).read_bytes()).hexdigest(),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }, indent=2) + "\n")
    records = []
    kinds = set()
    root_only = False
    representative_lock = threading.Lock()

    def fsck(path: Path, name: str) -> None:
        scratch = out / f"{name}-fsck-scratch.img"
        shutil.copyfile(path, scratch)
        strip_private_journal_bits(scratch)
        run(["e2fsck", "-fn", str(scratch)], out / f"{name}-fsck.log")
        scratch.unlink()

    def fault_case(block_size, scenario, prepared, persist, boundary):
        case_kinds = set()
        name = f"{block_size}-{scenario}-{persist}-{boundary}"
        crash = out / f"{name}-crash.img"
        recovered = out / f"{name}-recovered.img"
        run([helper, str(prepared), str(crash), scenario, str(boundary), str(persist), "prepared"], out / f"{name}-inject.log")
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
                    case_kinds.add(header[18])
                    representative = out / f"kind-{block_size}-{header[18]}-active.img"
                    # Keep a sealed, wholly pre-checkpoint representative. A
                    # worker completing first may otherwise have checkpointed
                    # some homes, making inverse-transition proofs ambiguous.
                    tag = first + block_size + 12
                    untouched = True
                    for index in range(count):
                        home = struct.unpack_from(">I", data, tag)[0]
                        expected = header[32 + index * 32:64 + index * 32]
                        untouched &= hashlib.sha256(data[home * block_size:(home + 1) * block_size]).digest() == expected
                        tag += 8 + (16 if index == 0 else 0)
                    if untouched:
                        with representative_lock:
                            if not representative.exists():
                                shutil.copyfile(crash, representative)
        text = run([helper, str(crash), str(recovered), "recover"], out / f"{name}-recover.log")
        case_root_only = f"VISIBLE size=0 blocks={block_size // 512} " in text
        fsck(recovered, name)
        record = {"name": name, "crash": pack(crash), "recovered": pack(recovered), "fsck": 0}
        return record, case_kinds, case_root_only

    for block_size in (1024, 4096):
        base = out / f"base-{block_size}.img"
        with base.open("wb") as image:
            image.truncate(32 * 1024**2)
        run(["mke2fs", "-q", "-t", "ext3", "-F", "-b", str(block_size), "-I", "256",
             "-N", "512", "-J", "size=4", str(base)], out / f"mkfs-{block_size}.log")
        payload = out / "fixture.txt"
        payload.write_text("nonzero extended inode from e2fsprogs\n")
        run(["debugfs", "-w", "-R", f"write {payload} /fixture.bin", str(base)], out / f"fixture-{block_size}.log")
        for scenario in ("exercise", "symlink-bounds", "size-bounds"):
            name = f"{block_size}-{scenario}"
            image = out / f"{name}.img"
            run([helper, str(base), str(image), scenario], out / f"{name}.log")
            fsck(image, name)
            records.append({"name": name, "image": pack(image), "fsck": 0})
        scenarios = (("double", "triple", "triple-carry", "deep-truncate", "deep-unlink", "directory", "directory-rename", "directory-unlink", "directory-rmdir")
                     if args.growth_only else ("mkdir", "symlink", "unlink", "indirect", "truncate"))
        for scenario in scenarios:
            prepared = out / f"prepared-{block_size}-{scenario}.img"
            run([helper, str(base), str(prepared), "prepare-" + scenario], out / f"prepare-{block_size}-{scenario}.log")
            name = f"{block_size}-{scenario}-complete"
            completed = out / f"{name}.img"
            text = run([helper, str(prepared), str(completed), scenario, "0", "0", "prepared"], out / f"{name}.log")
            operations = int(re.search(r"MUTATION_OPERATIONS=(\d+)", text).group(1))
            fsck(completed, name)
            records.append({"name": name, "image": pack(completed), "fsck": 0,
                            "mutation_operations": operations})
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
                futures = [pool.submit(fault_case, block_size, scenario, prepared, persist, boundary)
                           for persist in (0, 1) for boundary in range(1, operations + 2)]
                for future in concurrent.futures.as_completed(futures):
                    record, case_kinds, case_root_only = future.result()
                    records.append(record)
                    kinds.update(case_kinds)
                    root_only |= case_root_only
                    if len(records) % 20 == 0:
                        (out / "receipts.json").write_text(json.dumps(records, indent=2) + "\n")
            pack(prepared)
        pack(base)
    base = out / "base-no-filetype.img"
    with base.open("wb") as image:
        image.truncate(32 * 1024**2)
    run(["mke2fs", "-q", "-t", "ext3", "-F", "-b", "4096", "-I", "256",
         "-N", "512", "-J", "size=4", "-O", "^filetype", str(base)], out / "mkfs-no-filetype.log")
    for scenario in (("exercise", "directory", "triple-carry") if args.growth_only else ("exercise",)):
        name = f"no-filetype-{scenario}"
        image = out / f"{name}.img"
        run([helper, str(base), str(image), scenario], out / f"{name}.log")
        fsck(image, name)
        records.append({"name": name, "image": pack(image), "fsck": 0})
    pack(base)
    (out / "receipts.json").write_text(json.dumps(records, indent=2) + "\n")
    required = {15, 16, 17, 18} if args.growth_only else {7, 8, 9, 10, 11, 12, 13, 14}
    if not required.issubset(kinds):
        raise RuntimeError(f"missing real-image transaction coverage: {kinds}")
    if not root_only:
        raise RuntimeError("no actual root-only crash image was recovered and checked")
    summary = {"images": len(records), "transaction_kinds": sorted(kinds), "root_only": root_only, "fsck": 0}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
