#!/usr/bin/env python3
"""Check regular creation over deleted inodes and every persistence boundary.

Use the ext2_mut_image Cargo example. All images and logs are confined to a new
evidence directory; e2fsprogs creates the deleted inode independently of Nilix.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
from pathlib import Path
import re
import shutil
import struct

from ext2_mut_image_oracle import pack, run
from stress_protocol import probe_journal, strip_private_journal_bits


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 8:
        parser.error("jobs must be between 1 and 8")
    out = args.evidence_dir.resolve()
    if out.exists() and any(out.iterdir()):
        parser.error("evidence directory must be empty")
    out.mkdir(parents=True, exist_ok=True)
    helper = str(args.oracle.resolve())
    records = []

    def fsck(image: Path, name: str) -> None:
        scratch = out / f"{name}-fsck.img"
        shutil.copyfile(image, scratch)
        strip_private_journal_bits(scratch)
        run(["e2fsck", "-fn", str(scratch)], out / f"{name}-fsck.log")
        scratch.unlink()

    def recover(crash: Path, name: str) -> dict:
        recovered = out / f"{name}-recovered.img"
        run([helper, str(crash), str(recovered), "recover"], out / f"{name}-recover.log")
        assert probe_journal(recovered)["journal_start"] == 0
        fsck(recovered, name)
        return {"name": name, "crash": pack(crash), "recovered": pack(recovered), "fsck": 0}

    for block_size in (1024, 4096):
        for inode_size in (128, 256):
            prefix = f"{block_size}-{inode_size}"
            base = out / f"{prefix}-base.img"
            with base.open("wb") as stream:
                stream.truncate(32 * 1024**2)
            run(["mke2fs", "-q", "-t", "ext3", "-F", "-b", str(block_size),
                 "-I", str(inode_size), "-N", "512", "-J", "size=4", str(base)],
                out / f"{prefix}-mkfs.log")
            payload = out / "deleted-payload.txt"
            payload.write_text("old inode data must not survive reuse\n")
            commands = out / f"{prefix}-debugfs.txt"
            # Deleting in a different directory leaves the root's clean tail
            # eligible for FILE_CREATE, exposing its nonzero-free-inode limit.
            commands.write_text(f"mkdir /sub\nwrite {payload} /sub/deleted\nrm /sub/deleted\n")
            text = run(["debugfs", "-w", "-f", str(commands), str(base)],
                       out / f"{prefix}-delete.log")
            ino = int(re.search(r"Allocated inode:\s+(\d+)", text).group(1))
            data = base.read_bytes()
            group, index = divmod(ino - 1, struct.unpack_from("<I", data, 1064)[0])
            descriptor = (2 if block_size == 1024 else 1) * block_size + group * 32
            bitmap, table = struct.unpack_from("<II", data, descriptor + 4)
            offset = table * block_size + index * inode_size
            assert data[bitmap * block_size + index // 8] & (1 << (index % 8)) == 0
            assert any(data[offset:offset + inode_size]), "fixture needs a nonzero free slot"
            del data
            fsck(base, prefix + "-base")
            prepared = out / f"{prefix}-prepared.img"
            run([helper, str(base), str(prepared), "prepare-create"],
                out / f"{prefix}-prepare.log")
            complete = out / f"{prefix}-complete.img"
            text = run([helper, str(prepared), str(complete), "create"],
                       out / f"{prefix}-complete.log")
            assert "VISIBLE size=0 blocks=0 nlink=1" in text
            operations = int(re.search(r"MUTATION_OPERATIONS=(\d+)", text).group(1))
            data = complete.read_bytes()
            assert struct.unpack_from("<H", data, offset)[0] == 0o100600
            assert struct.unpack_from("<I", data, offset + 4)[0] == 0
            assert struct.unpack_from("<H", data, offset + 26)[0] == 1
            assert not any(data[offset + 40:offset + 100]), "stale block pointers survived"
            assert not any(data[offset + 128:offset + inode_size]), "stale extended inode survived"
            del data
            fsck(complete, prefix + "-complete")
            records.append({"name": prefix + "-complete", "image": pack(complete), "fsck": 0})

            def fault_case(persist: int, boundary: int) -> dict:
                name = f"{prefix}-persist-{persist}-boundary-{boundary}"
                crash = out / f"{name}.img"
                run([helper, str(prepared), str(crash), "create", str(boundary), str(persist)],
                    out / f"{name}-inject.log")
                return recover(crash, name)

            with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
                futures = [pool.submit(fault_case, persist, boundary)
                           for persist in (0, 1) for boundary in range(1, operations + 2)]
                for future in concurrent.futures.as_completed(futures):
                    records.append(future.result())
            records.append({"name": prefix + "-base", "image": pack(base), "fsck": 0})
            records.append({"name": prefix + "-prepared", "image": pack(prepared)})
            (out / "receipts.json").write_text(json.dumps(records, indent=2) + "\n")
            print(f"{prefix}: all {operations} write/flush boundaries passed", flush=True)
    print(json.dumps({"cases": len(records), "fsck": 0}))


if __name__ == "__main__":
    main()
