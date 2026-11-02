#!/usr/bin/env python3
"""Recover a typed edit beside an unchanged inode above the local scan budget.

A sparse neighbor shares the edited inode-table block and has over 16 MiB of
mapping blocks, within the full ownership proof's 64 MiB admission limit.
All output is confined to a new evidence directory; the source is never changed.
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
    base = out / 'neighbor-base.img'
    size, pointers, leaves = 4096, 1024, 4097
    with base.open('wb') as stream:
        stream.truncate(64 * 1024**2)
    run(['mke2fs', '-q', '-t', 'ext3', '-F', '-b', str(size), '-I', '256', '-N', '512',
         '-J', 'size=4', '-O', '^dir_index', str(base)], out / 'mkfs.log')
    commands = out / 'debugfs.txt'
    logical = [12 + pointers + index * pointers for index in range(leaves)]
    commands.write_text('write /dev/null /mutation\nwrite /dev/null /neighbor\n'
                       + ''.join(f'fallocate /neighbor {block} {block}\n' for block in logical)
                       + f'set_inode_field /neighbor size {(logical[-1] + 1) * size}\n')
    run(['debugfs', '-w', '-f', str(commands), str(base)], out / 'allocate.log')
    data = base.read_bytes()
    u32 = lambda off: struct.unpack_from('<I', data, off)[0]

    def inode(name):
        text = run(['debugfs', '-R', f'stat /{name}', str(base)], out / (name + '-stat.log'))
        ino = int(re.search(r'Inode:\s+(\d+)', text).group(1))
        group, index = divmod(ino - 1, u32(1064))
        table = u32(size + group * 32 + 8)
        return table * size + index * struct.unpack_from('<H', data, 1112)[0]

    neighbor, mutation = inode('neighbor'), inode('mutation')
    assert neighbor // size == mutation // size, 'fixture must share the inode-table home'
    mappings = set()

    def count(physical, level):
        if not physical or not level:
            return
        assert physical not in mappings
        mappings.add(physical)
        for off in range(physical * size, (physical + 1) * size, 4):
            count(u32(off), level - 1)

    for level in (1, 2, 3):
        count(u32(neighbor + 40 + (11 + level) * 4), level)
    assert 16 * 1024**2 < len(mappings) * size < 64 * 1024**2
    del data
    records = []

    def fsck(image, name):
        scratch = out / 'fsck.img'
        shutil.copyfile(image, scratch)
        strip_private_journal_bits(scratch)
        run(['e2fsck', '-fn', str(scratch)], out / (name + '-fsck.log'))
        scratch.unlink()

    fsck(base, 'base')
    complete = out / 'complete.img'
    run([helper, str(base), str(complete), 'double', '0', '0', 'prepared'], out / 'complete.log')
    fsck(complete, 'complete')
    records.append({'name': 'complete', 'image': pack(complete), 'fsck': 0})
    # The first mapping attach has a durable commit but no completed checkpoint.
    crash, recovered = out / 'crash.img', out / 'recovered.img'
    text = run([helper, str(base), str(crash), 'double', '13', '0', 'prepared'], out / 'inject.log')
    assert 'FAILED=true' in text
    text = run([helper, str(crash), str(recovered), 'recover'], out / 'recover.log')
    operations = int(re.search(r'OPERATIONS=(\d+)', text).group(1))
    assert operations > 0, 'fixture must require replay'
    fsck(recovered, 'recover')
    records.append({'name': 'recover', 'image': pack(recovered), 'fsck': 0})
    for persist in (0, 1):
        for boundary in range(1, operations + 1):
            name = f'replay-{boundary}-persist-{persist}'
            interrupted = out / (name + '.img')
            result = out / (name + '-recovered.img')
            run([helper, str(crash), str(interrupted), 'recover', str(boundary), str(persist)], out / (name + '.log'))
            run([helper, str(interrupted), str(result), 'recover'], out / (name + '-recover.log'))
            fsck(result, name)
            records.append({'name': name, 'interrupted': pack(interrupted), 'recovered': pack(result), 'fsck': 0})
    records.append({'name': 'base', 'image': pack(base), 'fsck': 0})
    records.append({'name': 'crash', 'image': pack(crash)})
    receipt = {'cases': len(records), 'neighbor_mapping_blocks': len(mappings),
               'neighbor_mapping_bytes': len(mappings) * size, 'records': records}
    (out / 'receipts.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({key: value for key, value in receipt.items() if key != 'records'}))


if __name__ == '__main__':
    main()
