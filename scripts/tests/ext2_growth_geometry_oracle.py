#!/usr/bin/env python3
"""Verify directory double/triple boundaries and valid dirty slack with e2fsprogs.

Only explicitly created evidence files are written. The large 1 KiB fixture has
65,804 directory blocks, making its next append use the triple-indirect root.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import shutil
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ext2_mut_image_oracle import pack, run
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'gates/stress'))
from stress_protocol import strip_private_journal_bits


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    args = parser.parse_args()
    out = args.evidence_dir.resolve()
    if out.exists() and any(out.iterdir()):
        parser.error('evidence directory must be empty')
    out.mkdir(parents=True, exist_ok=True)
    helper = str(args.oracle.resolve())
    records = []

    def fsck(image, name):
        scratch = out / 'fsck.img'
        shutil.copyfile(image, scratch)
        strip_private_journal_bits(scratch)
        run(['e2fsck', '-fn', str(scratch)], out / (name + '-fsck.log'))
        scratch.unlink()

    for size, depth in [(1024, 2), (4096, 2), (1024, 3)]:
        name = f'directory-{size}-level-{depth}'
        base = out / (name + '-base.img')
        pointers = size // 4
        blocks = 12 + pointers + (pointers * pointers if depth == 3 else 0)
        with base.open('wb') as stream:
            stream.truncate(128 * 1024**2 if depth == 3 else 32 * 1024**2)
        run(['mke2fs', '-q', '-t', 'ext3', '-F', '-b', str(size), '-I', '256', '-N', '512',
             '-J', 'size=4', '-O', '^dir_index', str(base)], out / (name + '-mkfs.log'))
        commands = out / (name + '-debugfs.txt')
        commands.write_text('mkdir /mutation\n' + 'expand_dir /mutation\n' * (blocks - 1))
        run(['debugfs', '-w', '-f', str(commands), str(base)], out / (name + '-expand.log'))
        stat = run(['debugfs', '-R', 'stat /mutation', str(base)], out / (name + '-stat.log'))
        ino = int(re.search(r'Inode:\s+(\d+)', stat).group(1))
        data = bytearray(base.read_bytes())
        u32 = lambda off: struct.unpack_from('<I', data, off)[0]
        group, index = divmod(ino - 1, u32(1064))
        gd = (2 if size == 1024 else 1) * size + group * 32
        inode = u32(gd + 8) * size + index * struct.unpack_from('<H', data, 1112)[0]
        assert u32(inode + 4) == blocks * size
        assert u32(inode + 32) & 0x1000 == 0

        def mapped(logical):
            if logical < 12:
                return u32(inode + 40 + logical * 4)
            logical -= 12
            for level in range(1, 4):
                if logical >= pointers ** level:
                    logical -= pointers ** level
                    continue
                physical = u32(inode + 40 + (11 + level) * 4)
                for remaining in reversed(range(level)):
                    index, logical = divmod(logical, pointers ** remaining)
                    physical = u32(physical * size + index * 4)
                    assert physical
                return physical
            raise AssertionError('unmapped fixture')

        # Empty records and live-entry slack may legally contain stale bytes.
        # Fill only slack; preserve every record header, dot/dotdot and link count.
        for logical in range(blocks):
            home = mapped(logical) * size
            off = home
            while off < home + size:
                length = struct.unpack_from('<H', data, off + 4)[0]
                assert length >= 8 and off + length <= home + size
                name_len = data[off + 6]
                used = (8 + name_len + 3) & ~3
                if u32(off) == 0:
                    data[off + 8] = 0xA5
                elif used < length:
                    data[off + used] = 0xA5
                off += length
        base.write_bytes(data)
        del data
        fsck(base, name + '-before')
        completed = out / (name + '-complete.img')
        text = run([helper, str(base), str(completed), 'directory', '0', '0', 'prepared'], out / (name + '-complete.log'))
        assert f'VISIBLE size={(blocks + 1) * size} ' in text
        fsck(completed, name + '-complete')
        records.append({'name': name, 'complete': pack(completed), 'fsck': 0})
        for boundary in (13, 32, 53, 74):
            case = name + f'-crash-{boundary}'
            crash, recovered = out / (case + '.img'), out / (case + '-recovered.img')
            run([helper, str(base), str(crash), 'directory', str(boundary), '0', 'prepared'], out / (case + '-inject.log'))
            run([helper, str(crash), str(recovered), 'recover'], out / (case + '-recover.log'))
            fsck(recovered, case)
            records.append({'name': case, 'crash': pack(crash), 'recovered': pack(recovered), 'fsck': 0})
        records.append({'name': name + '-base', 'base': pack(base), 'fsck': 0})
        (out / 'receipts.json').write_text(json.dumps(records, indent=2) + '\n')
        print(name, 'passed', flush=True)
    print(json.dumps({'cases': len(records), 'fsck': 0}))


if __name__ == '__main__':
    main()
