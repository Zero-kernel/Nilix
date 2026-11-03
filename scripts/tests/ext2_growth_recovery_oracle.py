#!/usr/bin/env python3
"""Re-sign semantically invalid EXT2-MUT logs and require rejection before I/O.

Consumes representative active logs produced by ext2_mut_image_oracle.py
--growth-only. All edits are confined to new disposable evidence images.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import re
import gzip
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ext2_mut_image_oracle import pack, run
from stress_protocol import strip_private_journal_bits
import shutil


def le32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def be32(data, off):
    return struct.unpack_from('>I', data, off)[0]


class Image:
    def __init__(self, data):
        self.data = bytearray(data)
        self.block = 1024 << le32(data, 1048)
        self.ptrs = self.block // 4
        journal = le32(data, 1024 + 224)
        raw = self.inode(journal)
        self.journal = [self.map(raw, index) for index in range(9)]
        self.super = self.journal[0] * self.block
        self.descriptor = self.journal[1] * self.block
        if not be32(data, self.super + 28):
            raise ValueError('inactive journal')
        sequence = be32(data, self.super + 24)
        for count in range(1, 7):
            commit = self.journal[count + 2] * self.block
            if (be32(data, commit) == 0xC03B3998 and be32(data, commit + 4) == 2
                    and be32(data, commit + 8) == sequence and data[commit + 19] == count):
                self.count, self.commit = count, commit
                if self.digest() == data[commit + 352:commit + 384]:
                    break
        else:
            raise ValueError('no sealed active transaction')
        self.kind = self.data[self.commit + 18]
        self.homes = []
        tag = self.descriptor + 12
        for index in range(self.count):
            home = be32(self.data, tag)
            flags = struct.unpack_from('>H', self.data, tag + 6)[0]
            self.homes.append((home, flags))
            tag += 8 + (16 if index == 0 else 0)

    def inode_offset(self, ino):
        per_group = le32(self.data, 1064)
        group, index = divmod(ino - 1, per_group)
        gd = (2 if self.block == 1024 else 1) * self.block + group * 32
        table = le32(self.data, gd + 8)
        stride = struct.unpack_from('<H', self.data, 1112)[0]
        return table * self.block + index * stride

    def inode(self, ino):
        offset = self.inode_offset(ino)
        return bytes(self.data[offset:offset + 128])

    def map(self, raw, logical):
        if logical < 12:
            return le32(raw, 40 + logical * 4)
        logical -= 12
        for level in range(1, 4):
            if logical >= self.ptrs ** level:
                logical -= self.ptrs ** level
                continue
            physical = le32(raw, 40 + (11 + level) * 4)
            for remaining in reversed(range(level)):
                index, logical = divmod(logical, self.ptrs ** remaining)
                physical = le32(self.data, physical * self.block + index * 4)
                if not physical:
                    return 0
            return physical
        raise ValueError('out of tree')

    def digest(self):
        digest = hashlib.sha256(b'Zero-OS ext3 journal intent v1\0')
        digest.update(self.data[self.super + 48:self.super + 64])
        digest.update(self.data[self.super + 24:self.super + 28])
        for logical in range(1, self.count + 2):
            off = self.journal[logical] * self.block
            digest.update(self.data[off:off + self.block])
        c = self.commit
        digest.update(self.data[c:c + 352] + bytes(32) + self.data[c + 384:c + self.block])
        return digest.digest()

    def seal(self):
        self.data[self.commit + 352:self.commit + 384] = self.digest()

    def post(self, index):
        off = self.journal[index + 2] * self.block
        block = bytearray(self.data[off:off + self.block])
        if self.homes[index][1] & 1:
            struct.pack_into('>I', block, 0, 0xC03B3998)
        return block

    def put_post(self, index, block):
        block = bytearray(block)
        if self.homes[index][1] & 1:
            assert be32(block, 0) == 0xC03B3998
            block[:4] = bytes(4)
        off = self.journal[index + 2] * self.block
        self.data[off:off + self.block] = block


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--matrix-dir', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    args = parser.parse_args()
    out = args.evidence_dir.resolve()
    if out.exists() and any(out.iterdir()):
        parser.error('evidence directory must be empty')
    out.mkdir(parents=True, exist_ok=True)
    records = []

    def reject(name, image):
        image.seal()
        candidate, result = out / (name + '.img'), out / (name + '-result.img')
        candidate.write_bytes(image.data)
        text = run([str(args.oracle.resolve()), str(candidate), str(result), 'reject'], out / (name + '.log'))
        assert 'OPERATIONS=0' in text
        assert result.read_bytes() == image.data
        result.unlink()
        records.append({'name': name, 'writes': 0, 'image': pack(candidate)})
        (out / 'receipts.json').write_text(json.dumps(records, indent=2) + '\n')
        print(name, 'rejected before I/O', flush=True)

    for size in (1024, 4096):
        for kind in (15, 16, 17, 18):
            original = (args.matrix_dir / f'kind-{size}-{kind}-active.img').read_bytes()
            base = Image(original)
            assert base.kind == kind
            # Recovery itself is a persistent mutation. Interrupt every one of
            # its writes/flushes, then require a second mount and fsck to finish.
            candidate = out / f'{size}-{kind}-recovery-input.img'
            candidate.write_bytes(original)
            recovered = out / f'{size}-{kind}-recovery-complete.img'
            text = run([str(args.oracle.resolve()), str(candidate), str(recovered), 'recover'],
                       out / f'{size}-{kind}-recovery-complete.log')
            operations = int(re.search(r'OPERATIONS=(\d+)', text).group(1))
            for persist in (0, 1):
                for boundary in range(1, operations + 2):
                    name = f'{size}-{kind}-recovery-{persist}-{boundary}'
                    interrupted = out / (name + '.img')
                    final = out / (name + '-final.img')
                    run([str(args.oracle.resolve()), str(candidate), str(interrupted), 'recover',
                         str(boundary), str(persist)], out / (name + '-interrupt.log'))
                    run([str(args.oracle.resolve()), str(interrupted), str(final), 'recover'],
                        out / (name + '-recover.log'))
                    scratch = out / (name + '-fsck.img')
                    shutil.copyfile(final, scratch)
                    strip_private_journal_bits(scratch)
                    run(['e2fsck', '-fn', str(scratch)], out / (name + '-fsck.log'))
                    scratch.unlink()
                    records.append({'name': name, 'fsck': 0, 'interrupted': pack(interrupted),
                                    'recovered': pack(final)})
            candidate.unlink()
            pack(recovered)
            if kind in (15, 16):
                for case in ('logical', 'level', 'journal-block'):
                    image = Image(original)
                    c = image.commit
                    if case == 'logical':
                        struct.pack_into('>I', image.data, c + 24, be32(image.data, c + 24) + 1)
                    elif case == 'level':
                        image.data[c + 384] = 1 if image.data[c + 384] != 1 else 2
                    else:
                        struct.pack_into('>I', image.data, c + 28, image.journal[0])
                    reject(f'{size}-{kind}-{case}', image)
            if kind == 17:
                image = Image(original)
                physical = be32(image.data, image.commit + 28)
                # Parses as a directory record but is not the canonical empty block.
                struct.pack_into('<I', image.data, physical * size, 2)
                image.data[physical * size + 6:physical * size + 9] = bytes([1, 2, ord('.')])
                reject(f'{size}-nonempty-dir-grow', image)
                image = Image(original)
                parent = be32(image.data, image.commit + 20)
                inode_off = image.inode_offset(parent)
                # Invert a valid DIR_GROW into an otherwise-consistent live DIR
                # DETACH. Start from fully checkpointed allocation post-images;
                # reverse every one of the original edits and re-hash all homes.
                old_inode = None
                for index, (home, _) in enumerate(image.homes):
                    pre = image.data[home * size:(home + 1) * size]
                    expected = image.data[image.commit + 32 + index * 32:image.commit + 64 + index * 32]
                    assert hashlib.sha256(pre).digest() == expected, 'representative must precede checkpoint'
                    post = image.post(index)
                    if home == inode_off // size:
                        old_inode = post[inode_off % size:inode_off % size + 128]
                    image.data[home * size:(home + 1) * size] = post
                    image.put_post(index, pre)
                    image.data[image.commit + 32 + index * 32:image.commit + 64 + index * 32] = hashlib.sha256(post).digest()
                assert old_inode is not None
                image.data[image.commit + 224:image.commit + 352] = old_inode
                image.data[image.commit + 18] = 16
                reject(f'{size}-linked-directory-detach', image)
            if kind == 18:
                ino = be32(base.data, base.commit + 20)
                inode_off = base.inode_offset(ino)
                order = next(i for i, (home, _) in enumerate(base.homes) if home == inode_off // size)
                for field, offset in [('uid', 2), ('mode', 0)]:
                    image = Image(original)
                    post = image.post(order)
                    post[inode_off % size + offset] ^= 1
                    image.put_post(order, post)
                    reject(f'{size}-rename-parent-{field}', image)
                image = Image(original)
                directory_order = next(i for i, (_, _) in enumerate(image.homes) if i != order)
                post = image.post(directory_order)
                off = be32(image.data, image.commit + 392)
                name = post[off + 8:off + 8 + post[off + 6]]
                old = image.data[image.commit + 224:image.commit + 352]
                home = image.map(old, 0)
                assert home != image.homes[directory_order][0]
                off = home * size
                while image.data[off + 6] < len(name):
                    off += struct.unpack_from('<H', image.data, off + 4)[0]
                image.data[off + 6] = len(name)
                image.data[off + 8:off + 8 + len(name)] = name
                reject(f'{size}-rename-existing-name-in-other-block', image)
        # Derive representatives for each mapping level from the complete
        # persist=0 truncation matrix; coverage is required, never optional.
        levels = {}
        for path in sorted(args.matrix_dir.glob(f'{size}-deep-truncate-0-*-crash.img.gz')):
            with gzip.open(path, 'rb') as stream:
                data = stream.read()
            try:
                image = Image(data)
            except ValueError:
                continue
            level = image.data[image.commit + 384]
            if image.kind == 16 and level in (1, 2, 3):
                levels.setdefault(level, data)
            if len(levels) == 3:
                break
        assert set(levels) == {1, 2, 3}, 'matrix omitted mapping-node detach levels'
        for level, data in sorted(levels.items()):
            image = Image(data)
            physical = be32(image.data, image.commit + 28)
            struct.pack_into('<I', image.data, physical * size, physical)
            reject(f'{size}-free-nonempty-level-{level}', image)
    # Reclaim a file whose triple-indirect root uses top-level slot 1, not
    # only slot 0. Reuse the independently checked write result as the fixture.
    for size in (1024, 4096):
        prepared = out / f'{size}-carry-prepared.img'
        with gzip.open(args.matrix_dir / f'{size}-triple-carry-complete.img.gz', 'rb') as src:
            prepared.write_bytes(src.read())
        for scenario in ('deep-truncate', 'deep-unlink'):
            name = f'{size}-carry-{scenario}'
            complete = out / (name + '-complete.img')
            text = run([str(args.oracle.resolve()), str(prepared), str(complete), scenario,
                        '0', '0', 'prepared'], out / (name + '-complete.log'))
            operations = int(re.search(r'MUTATION_OPERATIONS=(\d+)', text).group(1))
            scratch = out / (name + '-fsck.img')
            shutil.copyfile(complete, scratch)
            strip_private_journal_bits(scratch)
            run(['e2fsck', '-fn', str(scratch)], out / (name + '-fsck.log'))
            scratch.unlink()
            records.append({'name': name, 'fsck': 0, 'image': pack(complete)})

            def carry_fault(pair):
                persist, boundary = pair
                case = f'{name}-{persist}-{boundary}'
                crash, final = out / (case + '.img'), out / (case + '-final.img')
                run([str(args.oracle.resolve()), str(prepared), str(crash), scenario,
                     str(boundary), str(persist), 'prepared'], out / (case + '-inject.log'))
                run([str(args.oracle.resolve()), str(crash), str(final), 'recover'],
                    out / (case + '-recover.log'))
                scratch = out / (case + '-fsck.img')
                shutil.copyfile(final, scratch)
                strip_private_journal_bits(scratch)
                run(['e2fsck', '-fn', str(scratch)], out / (case + '-fsck.log'))
                scratch.unlink()
                return {'name': case, 'carry_reclaim': True, 'fsck': 0,
                        'crash': pack(crash), 'recovered': pack(final)}

            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                futures = [pool.submit(carry_fault, (persist, boundary))
                           for persist in (0, 1) for boundary in range(1, operations + 2)]
                for future in concurrent.futures.as_completed(futures):
                    records.append(future.result())
            (out / 'receipts.json').write_text(json.dumps(records, indent=2) + '\n')
        prepared.unlink()
    summary = {'rejected': sum('writes' in r for r in records),
               'recovery_interruptions': sum('interrupted' in r for r in records),
               'carry_reclaim_boundaries': sum('carry_reclaim' in r for r in records), 'fsck': 0}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
