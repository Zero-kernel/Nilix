#!/usr/bin/env python3
"""Strict host-side protocol tooling for the Zero-OS stress-v2 suite.

The shell harness deliberately owns QEMU and temporary-file lifecycle.  This
module owns binary configuration, exact marker parsing, heartbeat timestamps,
QMP vCPU progress, and read-only Ext3/JBD2 crash-state inspection.  Keeping
those operations here avoids Bash integer-width and regular-expression drift.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import hmac
import json
import os
import re
import signal
import socket
import struct
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable, Sequence


CONFIG_MAGIC = b"NILSTR2\0"
CONFIG_END_MAGIC = b"NILEND2\0"
CONFIG_VERSION = 2
CONFIG_HEADER_BYTES = 40
CONFIG_TOTAL_BYTES = 256
CONFIG_DIGEST_OFFSET = 216

PROFILE_IDS = {
    "memory": 1,
    "cpu": 2,
    "smp": 3,
    "process": 4,
    "block": 5,
    "combined": 6,
}
PROFILE_NAMES = {value: key for key, value in PROFILE_IDS.items()}

FLAG_REQUIRE_OOM = 1 << 0
FLAG_PIN_WORKERS = 1 << 1
FLAG_BLOCK_CRASH_AUTO = 1 << 2
FLAG_HOST_TERMINATED = 1 << 3
FLAG_REQUIRE_QMP_VCPUS = 1 << 4
KNOWN_FLAGS = (
    FLAG_REQUIRE_OOM
    | FLAG_PIN_WORKERS
    | FLAG_BLOCK_CRASH_AUTO
    | FLAG_HOST_TERMINATED
    | FLAG_REQUIRE_QMP_VCPUS
)

FLAG_NAMES = {
    "require_oom": FLAG_REQUIRE_OOM,
    "pin_workers": FLAG_PIN_WORKERS,
    "block_crash_auto": FLAG_BLOCK_CRASH_AUTO,
    "host_terminated": FLAG_HOST_TERMINATED,
    "require_qmp_vcpus": FLAG_REQUIRE_QMP_VCPUS,
}

KNOB_NAMES = (
    "vcpus",
    "workers",
    "heartbeat_max_ms",
    "rounds_per_heartbeat",
    "memory_limit_delta",
    "memory_chunk_bytes",
    "cpu_iterations",
    "contention_iterations",
    "churn_fanout",
    "churn_waves",
    "io_block_bytes",
    "io_slots",
    "io_writes_per_round",
    "reclaim_percent",
)

CONFIG_STRUCT = struct.Struct("<8sHHIIIQQIIIIQQQQIIIIII104s32s8s")
assert CONFIG_STRUCT.size == CONFIG_TOTAL_BYTES

U64_MAX = (1 << 64) - 1
I64_MIN = -(1 << 63)
I64_MAX = (1 << 63) - 1
PAGE_BYTES = 4096

JBD2_MAGIC = 0xC03B3998
JBD2_SUPERBLOCK_V2 = 4
JBD2_FEATURE_INCOMPAT_ZERO_INTENT = 0x80000000
EXT3_FEATURE_COMPAT_HAS_JOURNAL = 0x00000004
EXT3_FEATURE_INCOMPAT_RECOVER = 0x00000004


class StressProtocolError(RuntimeError):
    """Raised when any fail-closed stress contract check fails."""


def checked_u64(value: int, label: str) -> int:
    if not 0 <= value <= U64_MAX:
        raise StressProtocolError(f"{label} is outside uint64 range")
    return value


def checked_mul_u64(left: int, right: int, label: str) -> int:
    value = left * right
    return checked_u64(value, label)


def parse_uint(text: str) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]*", text):
        raise argparse.ArgumentTypeError("expected an unsigned decimal integer")
    value = int(text, 10)
    if value > U64_MAX:
        raise argparse.ArgumentTypeError("integer exceeds uint64")
    return value


def parse_u64_auto(text: str) -> int:
    try:
        value = int(text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a uint64 integer") from error
    if not 0 <= value <= U64_MAX:
        raise argparse.ArgumentTypeError("integer exceeds uint64")
    return value


def parse_hex_u64(text: str) -> int:
    if not re.fullmatch(r"[0-9a-fA-F]{1,16}", text):
        raise argparse.ArgumentTypeError("expected one to sixteen hexadecimal digits")
    return int(text, 16)


def parse_flags(text: str) -> int:
    if re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]+", text):
        value = int(text, 0)
    else:
        value = 0
        for name in text.split(","):
            try:
                value |= FLAG_NAMES[name.strip()]
            except KeyError as error:
                raise argparse.ArgumentTypeError(f"unknown flag name: {name}") from error
    if value & ~KNOWN_FLAGS:
        raise argparse.ArgumentTypeError("unknown stress flag bit")
    return value


@dataclasses.dataclass(frozen=True)
class StressKnobs:
    vcpus: int
    workers: int
    heartbeat_max_ms: int
    rounds_per_heartbeat: int
    memory_limit_delta: int = 0
    memory_chunk_bytes: int = 0
    cpu_iterations: int = 0
    contention_iterations: int = 0
    churn_fanout: int = 0
    churn_waves: int = 0
    io_block_bytes: int = 0
    io_slots: int = 0
    io_writes_per_round: int = 0
    reclaim_percent: int = 0

    def as_tuple(self) -> tuple[int, ...]:
        return tuple(getattr(self, name) for name in KNOB_NAMES)


@dataclasses.dataclass(frozen=True)
class StressConfig:
    profile: int
    flags: int
    run_id: int
    seed: int
    knobs: StressKnobs
    digest: bytes = b""

    @property
    def profile_name(self) -> str:
        try:
            return PROFILE_NAMES[self.profile]
        except KeyError as error:
            raise StressProtocolError(f"unknown profile id {self.profile}") from error

    @property
    def run_hex(self) -> str:
        return f"{self.run_id:016x}"

    @property
    def digest_hex(self) -> str:
        if len(self.digest) != 32:
            raise StressProtocolError("configuration digest is unavailable")
        return self.digest.hex()

    def validate(self) -> None:
        if self.profile not in PROFILE_NAMES:
            raise StressProtocolError("profile must be in the range 1..6")
        if self.flags & ~KNOWN_FLAGS:
            raise StressProtocolError("configuration contains unknown flag bits")
        checked_u64(self.run_id, "run_id")
        checked_u64(self.seed, "seed")

        knobs = self.knobs
        if not 1 <= knobs.vcpus <= 64:
            raise StressProtocolError("vcpus must be in the range 1..64")
        if not 1 <= knobs.workers <= 64:
            raise StressProtocolError("workers must be in the range 1..64")
        if not 100 <= knobs.heartbeat_max_ms <= 60000:
            raise StressProtocolError("heartbeat_max_ms must be in the range 100..60000")
        if not 1 <= knobs.rounds_per_heartbeat <= 1024:
            raise StressProtocolError("rounds_per_heartbeat must be in the range 1..1024")

        allowed_knobs = {
            "memory": {"memory_limit_delta", "memory_chunk_bytes", "reclaim_percent"},
            "cpu": {"cpu_iterations"},
            "smp": {"contention_iterations"},
            "process": {"churn_fanout", "churn_waves"},
            "block": {"io_block_bytes", "io_slots", "io_writes_per_round"},
            "combined": {
                "memory_limit_delta",
                "memory_chunk_bytes",
                "cpu_iterations",
                "contention_iterations",
                "churn_fanout",
                "churn_waves",
                "io_block_bytes",
                "io_slots",
                "io_writes_per_round",
                "reclaim_percent",
            },
        }[self.profile_name]
        always = {"vcpus", "workers", "heartbeat_max_ms", "rounds_per_heartbeat"}
        for name in KNOB_NAMES:
            if name not in always and name not in allowed_knobs and getattr(knobs, name) != 0:
                raise StressProtocolError(
                    f"irrelevant knob {name} must be zero for profile {self.profile_name}"
                )

        uses_memory = self.profile_name in {"memory", "combined"}
        if uses_memory:
            if knobs.memory_limit_delta % PAGE_BYTES != 0:
                raise StressProtocolError("memory_limit_delta must be page aligned")
            if knobs.memory_chunk_bytes % PAGE_BYTES != 0:
                raise StressProtocolError("memory_chunk_bytes must be page aligned")
            if not 64 * 1024 <= knobs.memory_chunk_bytes <= 8 * 1024 * 1024:
                raise StressProtocolError("memory_chunk_bytes must be between 64 KiB and 8 MiB")
            if knobs.memory_limit_delta < 2 * knobs.memory_chunk_bytes:
                raise StressProtocolError("memory_limit_delta must hold at least two chunks")
            if knobs.memory_limit_delta > 1024 * 1024 * 1024:
                raise StressProtocolError("memory_limit_delta exceeds the bounded 1 GiB maximum")
            if not 1 <= knobs.reclaim_percent <= 100:
                raise StressProtocolError("reclaim_percent must be in the range 1..100")

        if self.profile_name in {"cpu", "combined"}:
            if not 1 <= knobs.cpu_iterations <= 10**12:
                raise StressProtocolError("cpu_iterations must be in the range 1..10^12")

        if self.profile_name in {"smp", "combined"}:
            if knobs.vcpus < 2 or knobs.workers < 2:
                raise StressProtocolError("SMP workloads require at least two vCPUs/workers")
            if knobs.workers != knobs.vcpus:
                raise StressProtocolError("SMP workers must exactly match configured vCPUs")
            if not 1 <= knobs.contention_iterations <= 10**9:
                raise StressProtocolError("contention_iterations must be in the range 1..10^9")
            checked_mul_u64(knobs.workers, knobs.contention_iterations, "SMP expected count")

        if self.profile_name == "cpu" and knobs.workers != knobs.vcpus:
            raise StressProtocolError("CPU workers must exactly match configured vCPUs")

        if self.profile_name in {"process", "combined"}:
            if not 1 <= knobs.churn_fanout <= 32:
                raise StressProtocolError("churn_fanout must be in the range 1..32")
            if not 1 <= knobs.churn_waves <= 1024:
                raise StressProtocolError("churn_waves must be in the range 1..1024")
            checked_mul_u64(knobs.churn_fanout, knobs.churn_waves, "process child count")

        if self.profile_name in {"block", "combined"}:
            if knobs.io_block_bytes != PAGE_BYTES:
                raise StressProtocolError("io_block_bytes must be exactly 4096")
            if not 2 <= knobs.io_slots <= 12:
                raise StressProtocolError("io_slots must be in the range 2..12")
            if knobs.io_slots * knobs.io_block_bytes > 12 * PAGE_BYTES:
                raise StressProtocolError("I/O file exceeds the twelve-direct-block bound")
            if not 1 <= knobs.io_writes_per_round <= 1_000_000:
                raise StressProtocolError("io_writes_per_round must be in the range 1..1000000")

        allowed_flags = {
            "memory": FLAG_REQUIRE_OOM | FLAG_HOST_TERMINATED,
            "cpu": FLAG_PIN_WORKERS | FLAG_HOST_TERMINATED | FLAG_REQUIRE_QMP_VCPUS,
            "smp": FLAG_PIN_WORKERS | FLAG_HOST_TERMINATED | FLAG_REQUIRE_QMP_VCPUS,
            "process": FLAG_HOST_TERMINATED,
            "block": FLAG_BLOCK_CRASH_AUTO | FLAG_HOST_TERMINATED,
            "combined": (
                FLAG_REQUIRE_OOM
                | FLAG_PIN_WORKERS
                | FLAG_HOST_TERMINATED
                | FLAG_REQUIRE_QMP_VCPUS
            ),
        }[self.profile_name]
        if self.flags & ~allowed_flags:
            raise StressProtocolError(f"irrelevant flag set for profile {self.profile_name}")
        if self.profile_name in {"memory", "combined"} and not self.flags & FLAG_REQUIRE_OOM:
            raise StressProtocolError("memory pressure profiles must require the OOM boundary")
        if self.profile_name in {"cpu", "smp", "combined"}:
            required = FLAG_PIN_WORKERS | FLAG_REQUIRE_QMP_VCPUS
            if self.flags & required != required:
                raise StressProtocolError("CPU/SMP profiles must require pinning and QMP proof")
        if self.profile_name == "block" and not self.flags & FLAG_BLOCK_CRASH_AUTO:
            raise StressProtocolError("block profile must enable automatic writer/recovery selection")
        if not self.flags & FLAG_HOST_TERMINATED:
            raise StressProtocolError("host-terminated stress runs must set STRESS_F_HOST_TERMINATED")

    def to_bytes(self) -> bytes:
        self.validate()
        prefix = CONFIG_STRUCT.pack(
            CONFIG_MAGIC,
            CONFIG_VERSION,
            CONFIG_HEADER_BYTES,
            CONFIG_TOTAL_BYTES,
            self.profile,
            self.flags,
            self.run_id,
            self.seed,
            *self.knobs.as_tuple(),
            bytes(104),
            bytes(32),
            CONFIG_END_MAGIC,
        )
        digest = hashlib.sha256(prefix[:CONFIG_DIGEST_OFFSET]).digest()
        encoded = bytearray(prefix)
        encoded[CONFIG_DIGEST_OFFSET : CONFIG_DIGEST_OFFSET + 32] = digest
        return bytes(encoded)

    @classmethod
    def from_bytes(cls, data: bytes) -> "StressConfig":
        if len(data) != CONFIG_TOTAL_BYTES:
            raise StressProtocolError(
                f"configuration must be exactly {CONFIG_TOTAL_BYTES} bytes (got {len(data)})"
            )
        values = CONFIG_STRUCT.unpack(data)
        magic, version, header_bytes, total_bytes, profile, flags, run_id, seed = values[:8]
        knobs_raw = values[8:22]
        reserved, digest, end_magic = values[22:]
        if magic != CONFIG_MAGIC:
            raise StressProtocolError("configuration magic mismatch")
        if version != CONFIG_VERSION:
            raise StressProtocolError("configuration version mismatch")
        if header_bytes != CONFIG_HEADER_BYTES or total_bytes != CONFIG_TOTAL_BYTES:
            raise StressProtocolError("configuration size fields mismatch")
        if end_magic != CONFIG_END_MAGIC:
            raise StressProtocolError("configuration end magic mismatch")
        if any(reserved):
            raise StressProtocolError("configuration reserved bytes are nonzero")
        actual = hashlib.sha256(data[:CONFIG_DIGEST_OFFSET]).digest()
        if not hmac.compare_digest(actual, digest):
            raise StressProtocolError("configuration SHA-256 mismatch")
        config = cls(
            profile=profile,
            flags=flags,
            run_id=run_id,
            seed=seed,
            knobs=StressKnobs(**dict(zip(KNOB_NAMES, knobs_raw, strict=True))),
            digest=digest,
        )
        config.validate()
        return config


DEFAULT_KNOBS: dict[str, dict[str, int]] = {
    "memory": {
        "vcpus": 1,
        "workers": 1,
        "heartbeat_max_ms": 15000,
        "rounds_per_heartbeat": 1,
        "memory_limit_delta": 32 * 1024 * 1024,
        "memory_chunk_bytes": 1024 * 1024,
        "reclaim_percent": 100,
    },
    "cpu": {
        "vcpus": 4,
        "workers": 4,
        "heartbeat_max_ms": 15000,
        "rounds_per_heartbeat": 1,
        "cpu_iterations": 500_000,
    },
    "smp": {
        "vcpus": 4,
        "workers": 4,
        "heartbeat_max_ms": 15000,
        "rounds_per_heartbeat": 1,
        "contention_iterations": 20_000,
    },
    "process": {
        "vcpus": 1,
        "workers": 1,
        "heartbeat_max_ms": 15000,
        "rounds_per_heartbeat": 1,
        "churn_fanout": 8,
        "churn_waves": 4,
    },
    "block": {
        "vcpus": 2,
        "workers": 1,
        "heartbeat_max_ms": 15000,
        "rounds_per_heartbeat": 1,
        "io_block_bytes": PAGE_BYTES,
        "io_slots": 12,
        "io_writes_per_round": 64,
    },
    "combined": {
        "vcpus": 4,
        "workers": 4,
        "heartbeat_max_ms": 30000,
        "rounds_per_heartbeat": 1,
        "memory_limit_delta": 16 * 1024 * 1024,
        "memory_chunk_bytes": 512 * 1024,
        "cpu_iterations": 200_000,
        "contention_iterations": 5_000,
        "churn_fanout": 4,
        "churn_waves": 2,
        "io_block_bytes": PAGE_BYTES,
        "io_slots": 12,
        "io_writes_per_round": 16,
        "reclaim_percent": 100,
    },
}

DEFAULT_FLAGS = {
    "memory": FLAG_REQUIRE_OOM | FLAG_HOST_TERMINATED,
    "cpu": FLAG_PIN_WORKERS | FLAG_HOST_TERMINATED | FLAG_REQUIRE_QMP_VCPUS,
    "smp": FLAG_PIN_WORKERS | FLAG_HOST_TERMINATED | FLAG_REQUIRE_QMP_VCPUS,
    "process": FLAG_HOST_TERMINATED,
    "block": FLAG_BLOCK_CRASH_AUTO | FLAG_HOST_TERMINATED,
    "combined": (
        FLAG_REQUIRE_OOM | FLAG_PIN_WORKERS | FLAG_HOST_TERMINATED | FLAG_REQUIRE_QMP_VCPUS
    ),
}


def load_config(path: str | os.PathLike[str]) -> StressConfig:
    return StressConfig.from_bytes(Path(path).read_bytes())


def config_to_json(config: StressConfig) -> dict[str, Any]:
    return {
        "version": CONFIG_VERSION,
        "profile": config.profile_name,
        "profile_id": config.profile,
        "flags": config.flags,
        "run_id": config.run_hex,
        "seed": f"{config.seed:016x}",
        "sha256": config.digest_hex,
        "knobs": dataclasses.asdict(config.knobs),
    }


def command_make_config(args: argparse.Namespace) -> int:
    values = {name: 0 for name in KNOB_NAMES}
    values.update(DEFAULT_KNOBS[args.profile])
    for name in KNOB_NAMES:
        override = getattr(args, name, None)
        if override is not None:
            values[name] = override
    if args.profile in {"cpu", "smp", "combined"}:
        if args.vcpus is not None and args.workers is None:
            values["workers"] = args.vcpus
        if args.workers is not None and args.vcpus is None:
            values["vcpus"] = args.workers
    config = StressConfig(
        profile=PROFILE_IDS[args.profile],
        flags=DEFAULT_FLAGS[args.profile] if args.flags is None else args.flags,
        run_id=args.run_id,
        seed=args.seed,
        knobs=StressKnobs(**values),
    )
    encoded = config.to_bytes()
    parsed = StressConfig.from_bytes(encoded)
    output = Path(args.output)
    output.write_bytes(encoded)
    print(parsed.digest_hex)
    return 0


def command_inspect_config(args: argparse.Namespace) -> int:
    print(json.dumps(config_to_json(load_config(args.config)), sort_keys=True))
    return 0


def read_le_u16(data: bytes, offset: int, label: str) -> int:
    try:
        return struct.unpack_from("<H", data, offset)[0]
    except struct.error as error:
        raise StressProtocolError(f"truncated {label}") from error


def read_le_u32(data: bytes, offset: int, label: str) -> int:
    try:
        return struct.unpack_from("<I", data, offset)[0]
    except struct.error as error:
        raise StressProtocolError(f"truncated {label}") from error


def read_be_u32(data: bytes, offset: int, label: str) -> int:
    try:
        return struct.unpack_from(">I", data, offset)[0]
    except struct.error as error:
        raise StressProtocolError(f"truncated {label}") from error


def probe_journal(image_path: str | os.PathLike[str]) -> dict[str, Any]:
    path = Path(image_path)
    stat_result = path.stat()
    with path.open("rb", buffering=0) as image:
        image.seek(1024)
        superblock = image.read(1024)
        if len(superblock) != 1024:
            raise StressProtocolError("disk image has a truncated Ext superblock")
        if read_le_u16(superblock, 56, "Ext magic") != 0xEF53:
            raise StressProtocolError("disk image is not an Ext filesystem")
        log_block_size = read_le_u32(superblock, 24, "Ext block size")
        if log_block_size > 6:
            raise StressProtocolError("unsupported Ext block-size shift")
        block_size = 1024 << log_block_size
        if block_size < 1024 or block_size > 65536 or block_size & (block_size - 1):
            raise StressProtocolError("invalid Ext block size")
        inodes_per_group = read_le_u32(superblock, 40, "inodes per group")
        if inodes_per_group == 0:
            raise StressProtocolError("Ext inodes_per_group is zero")
        revision = read_le_u32(superblock, 76, "Ext revision")
        inode_size = 128 if revision == 0 else read_le_u16(superblock, 88, "inode size")
        if inode_size < 128 or inode_size > block_size or inode_size % 4 != 0:
            raise StressProtocolError("invalid Ext inode size")
        feature_compat = read_le_u32(superblock, 92, "Ext feature_compat")
        feature_incompat = read_le_u32(superblock, 96, "Ext feature_incompat")
        fs_uuid = superblock[104:120]
        journal_inode = read_le_u32(superblock, 224, "Ext journal inode")
        if not feature_compat & EXT3_FEATURE_COMPAT_HAS_JOURNAL:
            raise StressProtocolError("Ext image has no internal journal")
        if journal_inode != 8:
            raise StressProtocolError(f"expected internal journal inode 8, got {journal_inode}")

        inode_group = (journal_inode - 1) // inodes_per_group
        inode_index = (journal_inode - 1) % inodes_per_group
        descriptor_size = 32
        if revision != 0:
            raw_desc_size = read_le_u16(superblock, 254, "group descriptor size")
            if raw_desc_size >= 32:
                descriptor_size = raw_desc_size
        bgdt_offset = 2 * 1024 if block_size == 1024 else block_size
        descriptor_offset = bgdt_offset + inode_group * descriptor_size
        if descriptor_offset + 32 > stat_result.st_size:
            raise StressProtocolError("journal inode group descriptor is outside the image")
        image.seek(descriptor_offset)
        descriptor = image.read(32)
        if len(descriptor) != 32:
            raise StressProtocolError("truncated Ext group descriptor")
        inode_table = read_le_u32(descriptor, 8, "inode-table block")
        inode_offset = inode_table * block_size + inode_index * inode_size
        if inode_offset + inode_size > stat_result.st_size:
            raise StressProtocolError("journal inode lies outside the image")
        image.seek(inode_offset)
        inode = image.read(inode_size)
        if len(inode) != inode_size:
            raise StressProtocolError("truncated journal inode")
        first_journal_block = read_le_u32(inode, 40, "journal first direct block")
        if first_journal_block == 0:
            raise StressProtocolError("journal inode has no first direct block")
        journal_offset = first_journal_block * block_size
        if journal_offset + block_size > stat_result.st_size:
            raise StressProtocolError("JBD2 superblock lies outside the image")
        image.seek(journal_offset)
        journal = image.read(block_size)
        if len(journal) != block_size:
            raise StressProtocolError("truncated JBD2 superblock")

    if read_be_u32(journal, 0, "JBD2 magic") != JBD2_MAGIC:
        raise StressProtocolError("JBD2 magic mismatch")
    if read_be_u32(journal, 4, "JBD2 block type") != JBD2_SUPERBLOCK_V2:
        raise StressProtocolError("JBD2 logical block zero is not a v2 superblock")
    journal_block_size = read_be_u32(journal, 12, "JBD2 block size")
    if journal_block_size != block_size:
        raise StressProtocolError("Ext and JBD2 block sizes differ")
    journal_start = read_be_u32(journal, 28, "JBD2 start")
    journal_features = read_be_u32(journal, 40, "JBD2 incompat features")

    return {
        "path": str(path.resolve()),
        "device": stat_result.st_dev,
        "inode": stat_result.st_ino,
        "size": stat_result.st_size,
        "block_size": block_size,
        "fs_uuid": fs_uuid.hex(),
        "journal_inode": journal_inode,
        "journal_first_block": first_journal_block,
        "ext_feature_compat": feature_compat,
        "ext_feature_incompat": feature_incompat,
        "recover": bool(feature_incompat & EXT3_FEATURE_INCOMPAT_RECOVER),
        "jbd2_feature_incompat": journal_features,
        "zero_intent": bool(journal_features & JBD2_FEATURE_INCOMPAT_ZERO_INTENT),
        "journal_start": journal_start,
        "active": bool(
            feature_incompat & EXT3_FEATURE_INCOMPAT_RECOVER
            and journal_features & JBD2_FEATURE_INCOMPAT_ZERO_INTENT
            and journal_start != 0
        ),
    }


def command_journal_probe(args: argparse.Namespace) -> int:
    probe = probe_journal(args.image)
    if args.require_active and not probe["active"]:
        raise StressProtocolError("image does not contain an active Zero-Intent JBD2 tail")
    if args.require_clean:
        if probe["journal_start"] != 0:
            raise StressProtocolError("JBD2 s_start is nonzero after recovery")
        if probe["recover"]:
            raise StressProtocolError("Ext3 RECOVER remains set after recovery")
    if args.output:
        Path(args.output).write_text(json.dumps(probe, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(probe, sort_keys=True))
    return 0


def command_wait_journal_active(args: argparse.Namespace) -> int:
    deadline = time.monotonic() + args.timeout_ms / 1000.0
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            probe = probe_journal(args.image)
            if probe["active"]:
                print(json.dumps(probe, sort_keys=True))
                return 0
        except (OSError, StressProtocolError) as error:
            last_error = error
        time.sleep(args.poll_us / 1_000_000.0)
    if last_error is not None:
        raise StressProtocolError(f"active journal tail not observed: {last_error}")
    raise StressProtocolError("active journal tail was not observed before the deadline")


def command_assert_identity(args: argparse.Namespace) -> int:
    expected = json.loads(Path(args.identity).read_text(encoding="utf-8"))
    current = probe_journal(args.image)
    for field in ("device", "inode", "size", "fs_uuid", "journal_inode", "journal_first_block"):
        if current.get(field) != expected.get(field):
            raise StressProtocolError(
                f"disk identity changed at {field}: expected {expected.get(field)!r}, "
                f"got {current.get(field)!r}"
            )
    print(json.dumps(current, sort_keys=True))
    return 0


class QmpClient:
    def __init__(self, socket_path: str, timeout: float):
        self.socket_path = socket_path
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.buffer = b""

    def __enter__(self) -> "QmpClient":
        deadline = time.monotonic() + self.timeout
        last_error: OSError | None = None
        while time.monotonic() < deadline:
            candidate = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            candidate.settimeout(min(1.0, max(0.05, deadline - time.monotonic())))
            try:
                candidate.connect(self.socket_path)
                self.sock = candidate
                greeting = self._receive_response(allow_greeting=True)
                if "QMP" not in greeting:
                    raise StressProtocolError("QMP greeting is malformed")
                self.execute("qmp_capabilities")
                return self
            except (OSError, StressProtocolError) as error:
                candidate.close()
                self.sock = None
                if isinstance(error, OSError):
                    last_error = error
                time.sleep(0.05)
        raise StressProtocolError(f"unable to connect to QMP socket: {last_error}")

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        if self.sock is not None:
            self.sock.close()

    def _receive_object(self) -> dict[str, Any]:
        if self.sock is None:
            raise StressProtocolError("QMP client is disconnected")
        while True:
            if b"\n" in self.buffer:
                raw, self.buffer = self.buffer.split(b"\n", 1)
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    value = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise StressProtocolError("QMP returned invalid JSON") from error
                if not isinstance(value, dict):
                    raise StressProtocolError("QMP response is not an object")
                return value
            chunk = self.sock.recv(65536)
            if not chunk:
                raise StressProtocolError("QMP socket closed unexpectedly")
            self.buffer += chunk
            if len(self.buffer) > 1024 * 1024:
                raise StressProtocolError("QMP response exceeded one MiB")

    def _receive_response(self, allow_greeting: bool = False) -> dict[str, Any]:
        while True:
            value = self._receive_object()
            if allow_greeting and "QMP" in value:
                return value
            if "event" in value:
                continue
            if "error" in value:
                raise StressProtocolError(f"QMP command failed: {value['error']!r}")
            if "return" in value:
                return value
            raise StressProtocolError("QMP returned an unexpected object")

    def execute(self, name: str) -> Any:
        if self.sock is None:
            raise StressProtocolError("QMP client is disconnected")
        request = json.dumps({"execute": name}, separators=(",", ":")).encode("ascii") + b"\n"
        self.sock.sendall(request)
        return self._receive_response()["return"]


def read_linux_thread_ticks(thread_id: int) -> int:
    if thread_id <= 0:
        raise StressProtocolError("QMP returned a non-positive thread id")
    raw = Path(f"/proc/{thread_id}/stat").read_text(encoding="ascii")
    closing = raw.rfind(")")
    if closing < 0:
        raise StressProtocolError(f"/proc/{thread_id}/stat has no command terminator")
    fields = raw[closing + 2 :].split()
    if len(fields) < 13:
        raise StressProtocolError(f"/proc/{thread_id}/stat is truncated")
    return int(fields[11], 10) + int(fields[12], 10)


def qmp_snapshot(socket_path: str, timeout: float) -> dict[str, Any]:
    with QmpClient(socket_path, timeout) as qmp:
        raw_cpus = qmp.execute("query-cpus-fast")
    if not isinstance(raw_cpus, list):
        raise StressProtocolError("query-cpus-fast did not return a list")
    cpus: list[dict[str, int]] = []
    seen_indices: set[int] = set()
    seen_threads: set[int] = set()
    for item in raw_cpus:
        if not isinstance(item, dict):
            raise StressProtocolError("query-cpus-fast entry is not an object")
        try:
            index = int(item["cpu-index"])
            thread_id = int(item["thread-id"])
        except (KeyError, TypeError, ValueError) as error:
            raise StressProtocolError("query-cpus-fast entry lacks integer ids") from error
        if index < 0 or index in seen_indices:
            raise StressProtocolError("QMP returned duplicate/negative CPU indices")
        if thread_id <= 0 or thread_id in seen_threads:
            raise StressProtocolError("QMP returned duplicate/non-positive vCPU thread ids")
        seen_indices.add(index)
        seen_threads.add(thread_id)
        cpus.append(
            {"cpu_index": index, "thread_id": thread_id, "ticks": read_linux_thread_ticks(thread_id)}
        )
    cpus.sort(key=lambda item: item["cpu_index"])
    return {"captured_ns": time.time_ns(), "cpus": cpus}


def command_qmp_snapshot(args: argparse.Namespace) -> int:
    snapshot = qmp_snapshot(args.socket, args.timeout)
    Path(args.output).write_text(json.dumps(snapshot, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(snapshot, sort_keys=True))
    return 0


def validate_qmp_progress(before: dict[str, Any], after: dict[str, Any], expected_vcpus: int) -> None:
    before_cpus = before.get("cpus")
    after_cpus = after.get("cpus")
    if not isinstance(before_cpus, list) or not isinstance(after_cpus, list):
        raise StressProtocolError("QMP snapshots do not contain CPU lists")
    if len(before_cpus) != expected_vcpus or len(after_cpus) != expected_vcpus:
        raise StressProtocolError(
            f"QMP vCPU count mismatch: expected {expected_vcpus}, "
            f"got {len(before_cpus)} then {len(after_cpus)}"
        )
    before_by_index = {int(item["cpu_index"]): item for item in before_cpus}
    after_by_index = {int(item["cpu_index"]): item for item in after_cpus}
    if set(before_by_index) != set(range(expected_vcpus)) or set(after_by_index) != set(
        range(expected_vcpus)
    ):
        raise StressProtocolError("QMP CPU indices are incomplete or non-contiguous")
    for index in range(expected_vcpus):
        first = before_by_index[index]
        second = after_by_index[index]
        if int(first["thread_id"]) != int(second["thread_id"]):
            raise StressProtocolError(f"vCPU {index} thread id changed during the run")
        if int(second["ticks"]) <= int(first["ticks"]):
            raise StressProtocolError(f"vCPU {index} made no host-scheduler progress")


def command_validate_qmp(args: argparse.Namespace) -> int:
    before = json.loads(Path(args.before).read_text(encoding="utf-8"))
    after = json.loads(Path(args.after).read_text(encoding="utf-8"))
    validate_qmp_progress(before, after, args.expected_vcpus)
    print(f"QMP progress valid for {args.expected_vcpus} vCPUs")
    return 0


UINT_RE = r"(?:0|[1-9][0-9]{0,19})"
POS_UINT_RE = r"(?:[1-9][0-9]{0,19})"
HEX16_RE = r"[0-9a-f]{16}"
HEX64_RE = r"[0-9a-f]{64}"
PROFILE_RE = r"(?:memory|cpu|smp|process|block|combined)"


@dataclasses.dataclass(frozen=True)
class Marker:
    kind: str
    line: str
    fields: dict[str, Any]


def marker_pattern(kind: str, expression: str) -> tuple[str, re.Pattern[str]]:
    return kind, re.compile(r"^" + expression + r"$")


MARKER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    marker_pattern(
        "begin",
        rf"NILIX_STRESS_V2_BEGIN run=(?P<run>{HEX16_RE}) "
        rf"profile=(?P<profile>{PROFILE_RE}) config_sha256=(?P<config_sha256>{HEX64_RE}) "
        rf"vcpus=(?P<vcpus>{POS_UINT_RE}) workers=(?P<workers>{POS_UINT_RE})",
    ),
    marker_pattern(
        "ready",
        rf"NILIX_STRESS_V2_READY run=(?P<run>{HEX16_RE}) "
        rf"profile=(?P<profile>{PROFILE_RE}) mode=(?P<mode>normal|writer|recovery)",
    ),
    marker_pattern(
        "pass",
        rf"NILIX_STRESS_V2_PASS run=(?P<run>{HEX16_RE}) "
        rf"profile=(?P<profile>{PROFILE_RE}) cycles=(?P<cycles>{POS_UINT_RE}) "
        rf"ops=(?P<ops>{POS_UINT_RE}) checksum=(?P<checksum>{HEX16_RE})",
    ),
    marker_pattern(
        "heartbeat",
        rf"NILIX_STRESS_V2_HEARTBEAT run=(?P<run>{HEX16_RE}) "
        rf"profile=(?P<profile>{PROFILE_RE}) seq=(?P<seq>{POS_UINT_RE}) "
        rf"cycles=(?P<cycles>{POS_UINT_RE}) ops=(?P<ops>{POS_UINT_RE}) "
        rf"checksum=(?P<checksum>{HEX16_RE})",
    ),
    marker_pattern(
        "fail",
        rf"NILIX_STRESS_V2_FAIL run=(?P<run>{HEX16_RE}) "
        rf"profile=(?P<profile>{PROFILE_RE}) seq=(?P<seq>{UINT_RE}) "
        rf"stage=(?P<stage>[a-z][a-z0-9_]{{0,63}}) errno=(?P<errno>-?{UINT_RE}) "
        rf"detail=(?P<detail>{UINT_RE})",
    ),
    marker_pattern(
        "memory",
        rf"NILIX_STRESS_V2_MEMORY run=(?P<run>{HEX16_RE}) seq=(?P<seq>{POS_UINT_RE}) "
        rf"baseline=(?P<baseline>{UINT_RE}) limit=(?P<limit>{POS_UINT_RE}) "
        rf"peak=(?P<peak>{POS_UINT_RE}) recovered=(?P<recovered>{UINT_RE}) "
        rf"oom_events=(?P<oom_events>{POS_UINT_RE}) checksum=(?P<checksum>{HEX16_RE})",
    ),
    marker_pattern(
        "cpu",
        rf"NILIX_STRESS_V2_CPU run=(?P<run>{HEX16_RE}) seq=(?P<seq>{POS_UINT_RE}) "
        rf"workers=(?P<workers>{POS_UINT_RE}) iterations=(?P<iterations>{POS_UINT_RE}) "
        rf"wall_ns=(?P<wall_ns>{POS_UINT_RE}) cpu_ns=(?P<cpu_ns>{POS_UINT_RE}) "
        rf"checksum=(?P<checksum>{HEX16_RE})",
    ),
    marker_pattern(
        "smp",
        rf"NILIX_STRESS_V2_SMP run=(?P<run>{HEX16_RE}) seq=(?P<seq>{POS_UINT_RE}) "
        rf"workers=(?P<workers>{POS_UINT_RE}) iterations=(?P<iterations>{POS_UINT_RE}) "
        rf"counter=(?P<counter>{UINT_RE}) expected=(?P<expected>{POS_UINT_RE}) "
        rf"spins=(?P<spins>{UINT_RE}) done_mask=(?P<done_mask>{HEX16_RE}) "
        rf"checksum=(?P<checksum>{HEX16_RE})",
    ),
    marker_pattern(
        "process",
        rf"NILIX_STRESS_V2_PROCESS run=(?P<run>{HEX16_RE}) seq=(?P<seq>{POS_UINT_RE}) "
        rf"waves=(?P<waves>{POS_UINT_RE}) spawned=(?P<spawned>{POS_UINT_RE}) "
        rf"reaped=(?P<reaped>{POS_UINT_RE}) limit_hits=(?P<limit_hits>{POS_UINT_RE}) "
        rf"recovered_forks=(?P<recovered_forks>{POS_UINT_RE}) "
        rf"checksum=(?P<checksum>{HEX16_RE})",
    ),
    marker_pattern(
        "block",
        rf"NILIX_STRESS_V2_BLOCK run=(?P<run>{HEX16_RE}) seq=(?P<seq>{POS_UINT_RE}) "
        rf"generation=(?P<generation>{POS_UINT_RE}) valid_slots=(?P<valid_slots>{POS_UINT_RE}) "
        rf"read_bytes=(?P<read_bytes>{POS_UINT_RE}) write_bytes=(?P<write_bytes>{UINT_RE}) "
        rf"checksum=(?P<checksum>{HEX16_RE})",
    ),
    marker_pattern(
        "combined",
        rf"NILIX_STRESS_V2_COMBINED run=(?P<run>{HEX16_RE}) seq=(?P<seq>{POS_UINT_RE}) "
        rf"memory_ops=(?P<memory_ops>{POS_UINT_RE}) cpu_ops=(?P<cpu_ops>{POS_UINT_RE}) "
        rf"smp_ops=(?P<smp_ops>{POS_UINT_RE}) process_ops=(?P<process_ops>{POS_UINT_RE}) "
        rf"io_ops=(?P<io_ops>{POS_UINT_RE}) checksum=(?P<checksum>{HEX16_RE})",
    ),
    marker_pattern(
        "block_baseline",
        rf"NILIX_STRESS_V2_BLOCK_BASELINE run=(?P<run>{HEX16_RE}) "
        rf"generation=(?P<generation>{POS_UINT_RE}) checksum=(?P<checksum>{HEX16_RE})",
    ),
    marker_pattern(
        "block_crash_armed",
        rf"NILIX_STRESS_V2_BLOCK_CRASH_ARMED run=(?P<run>{HEX16_RE}) "
        rf"generation=(?P<generation>{POS_UINT_RE})",
    ),
    marker_pattern(
        "block_commit",
        rf"NILIX_STRESS_V2_BLOCK_COMMIT run=(?P<run>{HEX16_RE}) "
        rf"generation=(?P<generation>{POS_UINT_RE}) slot=(?P<slot>{UINT_RE}) "
        rf"checksum=(?P<checksum>{HEX16_RE})",
    ),
    marker_pattern(
        "block_recovered",
        rf"NILIX_STRESS_V2_BLOCK_RECOVERED run=(?P<run>{HEX16_RE}) "
        rf"generation=(?P<generation>{POS_UINT_RE}) valid_slots=(?P<valid_slots>{POS_UINT_RE}) "
        rf"invalid_slots=(?P<invalid_slots>{UINT_RE}) checksum=(?P<checksum>{HEX16_RE})",
    ),
    marker_pattern(
        "block_recovery_write",
        rf"NILIX_STRESS_V2_BLOCK_RECOVERY_WRITE run=(?P<run>{HEX16_RE}) "
        rf"generation=(?P<generation>{POS_UINT_RE}) slot=(?P<slot>{UINT_RE}) "
        rf"checksum=(?P<checksum>{HEX16_RE})",
    ),
)

STRING_MARKER_FIELDS = {"run", "profile", "config_sha256", "mode", "stage", "checksum"}


def parse_marker(line: str) -> Marker:
    for kind, pattern in MARKER_PATTERNS:
        match = pattern.fullmatch(line)
        if match is None:
            continue
        fields: dict[str, Any] = {}
        for name, raw in match.groupdict().items():
            if name in STRING_MARKER_FIELDS:
                fields[name] = raw
            elif name == "errno":
                value = int(raw, 10)
                if not I64_MIN <= value <= I64_MAX:
                    raise StressProtocolError("FAIL errno exceeds int64")
                fields[name] = value
            elif name == "done_mask":
                fields[name] = int(raw, 16)
            else:
                fields[name] = checked_u64(int(raw, 10), f"marker field {name}")
        return Marker(kind=kind, line=line, fields=fields)
    raise StressProtocolError(f"malformed or unknown stress-v2 marker: {line!r}")


def protocol_lines(path: str | os.PathLike[str]) -> list[str]:
    raw = Path(path).read_bytes()
    text = raw.decode("utf-8", errors="replace")
    return [line.rstrip("\r") for line in text.splitlines() if line.startswith("NILIX_STRESS_V2_")]


def parse_protocol_log(path: str | os.PathLike[str]) -> list[Marker]:
    return [parse_marker(line) for line in protocol_lines(path)]


def require_marker_identity(marker: Marker, config: StressConfig) -> None:
    if marker.fields.get("run") != config.run_hex:
        raise StressProtocolError(f"{marker.kind} marker has the wrong run id")
    if "profile" in marker.fields and marker.fields["profile"] != config.profile_name:
        raise StressProtocolError(f"{marker.kind} marker has the wrong profile")
    checksum = marker.fields.get("checksum")
    if checksum == "0000000000000000":
        raise StressProtocolError(f"{marker.kind} marker has a zero checksum")


def validate_profile_marker(marker: Marker, config: StressConfig) -> None:
    fields = marker.fields
    knobs = config.knobs
    if marker.kind == "memory":
        expected_limit = checked_u64(fields["baseline"] + knobs.memory_limit_delta, "memory limit")
        if fields["limit"] != expected_limit:
            raise StressProtocolError("memory limit does not equal baseline + configured delta")
        if fields["recovered"] != fields["baseline"]:
            raise StressProtocolError("memory_current did not return to the exact baseline")
        if fields["peak"] < fields["limit"] - knobs.memory_chunk_bytes:
            raise StressProtocolError("memory peak did not reach the configured pressure boundary")
        chunk_count = knobs.memory_limit_delta // knobs.memory_chunk_bytes
        page_table_allowance = min(8 * 1024 * 1024, max(512 * 1024, chunk_count * 16 * 1024))
        upper = checked_u64(
            fields["limit"] + knobs.memory_chunk_bytes + page_table_allowance,
            "memory peak allowance",
        )
        if fields["peak"] > upper:
            raise StressProtocolError("memory peak exceeded the bounded chunk/page-table allowance")
        if fields["oom_events"] < 1:
            raise StressProtocolError("memory profile did not observe a cgroup OOM/max event")
    elif marker.kind == "cpu":
        if fields["workers"] != knobs.workers or fields["iterations"] != knobs.cpu_iterations:
            raise StressProtocolError("CPU marker does not match configured workers/iterations")
        if fields["cpu_ns"] > fields["wall_ns"] * knobs.workers * 2:
            raise StressProtocolError("CPU accounting exceeds its conservative wall-time bound")
    elif marker.kind == "smp":
        expected = checked_mul_u64(knobs.workers, knobs.contention_iterations, "SMP expected")
        if fields["workers"] != knobs.workers:
            raise StressProtocolError("SMP marker worker count mismatch")
        if fields["iterations"] != knobs.contention_iterations:
            raise StressProtocolError("SMP marker iteration count mismatch")
        if fields["expected"] != expected or fields["counter"] != expected:
            raise StressProtocolError("SMP protected counter/expected arithmetic mismatch")
        expected_mask = U64_MAX if knobs.workers == 64 else (1 << knobs.workers) - 1
        if fields["done_mask"] != expected_mask:
            raise StressProtocolError("SMP done mask is incomplete")
        if knobs.workers >= 2 and fields["spins"] == 0:
            raise StressProtocolError("SMP workload reported no lock contention")
    elif marker.kind == "process":
        expected_children = checked_mul_u64(knobs.churn_fanout, knobs.churn_waves, "churn children")
        if fields["waves"] != knobs.churn_waves:
            raise StressProtocolError("process marker wave count mismatch")
        if fields["spawned"] != expected_children or fields["reaped"] != expected_children:
            raise StressProtocolError("process churn did not spawn/reap the exact child set")
        if fields["limit_hits"] != knobs.churn_waves:
            raise StressProtocolError("process churn did not hit pids.max once per wave")
        if fields["recovered_forks"] != knobs.churn_waves:
            raise StressProtocolError("process churn did not prove fork recovery once per wave")
    elif marker.kind == "block":
        if fields["valid_slots"] != knobs.io_slots:
            raise StressProtocolError("block profile did not validate every configured slot")
        if fields["read_bytes"] % PAGE_BYTES or fields["write_bytes"] % PAGE_BYTES:
            raise StressProtocolError("block byte counts are not whole records")
        if fields["read_bytes"] < knobs.io_slots * PAGE_BYTES:
            raise StressProtocolError("block profile read fewer than one full slot scan")
    elif marker.kind == "combined":
        total = 0
        for name in ("memory_ops", "cpu_ops", "smp_ops", "process_ops", "io_ops"):
            total = checked_u64(total + fields[name], "combined operation count")
        if total == 0:
            raise StressProtocolError("combined profile reported no subsystem operations")
    else:
        raise StressProtocolError(f"unexpected profile marker kind {marker.kind}")


def validate_header(markers: Sequence[Marker], config: StressConfig, mode: str) -> None:
    if len(markers) < 2:
        raise StressProtocolError("stress log does not contain BEGIN and READY")
    if markers[0].kind != "begin" or markers[1].kind != "ready":
        raise StressProtocolError("BEGIN and READY must be the first two stress-v2 markers")
    begin = markers[0]
    ready = markers[1]
    for marker in (begin, ready):
        require_marker_identity(marker, config)
    if begin.fields["config_sha256"] != config.digest_hex:
        raise StressProtocolError("BEGIN marker has the wrong configuration digest")
    if begin.fields["vcpus"] != config.knobs.vcpus:
        raise StressProtocolError("BEGIN marker has the wrong vCPU count")
    if begin.fields["workers"] != config.knobs.workers:
        raise StressProtocolError("BEGIN marker has the wrong worker count")
    if ready.fields["mode"] != mode:
        raise StressProtocolError(
            f"READY mode mismatch: expected {mode}, got {ready.fields['mode']}"
        )
    if sum(marker.kind == "begin" for marker in markers) != 1:
        raise StressProtocolError("stress log must contain exactly one BEGIN marker")
    if sum(marker.kind == "ready" for marker in markers) != 1:
        raise StressProtocolError("stress log must contain exactly one READY marker")


def validate_normal_markers(
    markers: Sequence[Marker], config: StressConfig, minimum_heartbeats: int, recovery: bool = False
) -> list[Marker]:
    expected_kind = config.profile_name
    next_sequence = 1
    previous_cycles = 0
    previous_ops = 0
    pending_round: Marker | None = None
    first_round: Marker | None = None
    pass_marker: Marker | None = None
    heartbeats: list[Marker] = []
    recovery_seen = False
    recovery_write: Marker | None = None

    for marker in markers[2:]:
        require_marker_identity(marker, config)
        if marker.kind == "fail":
            raise StressProtocolError(
                f"guest FAIL stage={marker.fields['stage']} errno={marker.fields['errno']} "
                f"detail={marker.fields['detail']}"
            )
        if recovery and marker.kind == "block_recovered":
            if recovery_seen or pending_round is not None or pass_marker is not None:
                raise StressProtocolError("BLOCK_RECOVERED is duplicate or out of order")
            if marker.fields["valid_slots"] + marker.fields["invalid_slots"] != config.knobs.io_slots:
                raise StressProtocolError("recovery slot counts do not equal configured io_slots")
            if marker.fields["valid_slots"] < 1:
                raise StressProtocolError("recovery found no valid record")
            recovery_seen = True
            continue
        if recovery and marker.kind == "block_recovery_write":
            if not recovery_seen or recovery_write is not None or pending_round is not None:
                raise StressProtocolError("BLOCK_RECOVERY_WRITE is duplicate or out of order")
            recovered = next(item for item in markers if item.kind == "block_recovered")
            if marker.fields["generation"] != recovered.fields["generation"] + 1:
                raise StressProtocolError("recovery successor generation is not contiguous")
            if marker.fields["slot"] != marker.fields["generation"] % config.knobs.io_slots:
                raise StressProtocolError("recovery successor slot does not match generation rotation")
            recovery_write = marker
            continue
        if marker.kind == expected_kind:
            if pending_round is not None:
                raise StressProtocolError("profile emitted another round before its heartbeat")
            if marker.fields["seq"] != next_sequence:
                raise StressProtocolError("profile round sequence is gapped or out of order")
            if recovery and (not recovery_seen or recovery_write is None):
                raise StressProtocolError("recovery BLOCK round is missing its recovery proofs")
            validate_profile_marker(marker, config)
            if recovery:
                if marker.fields["generation"] != recovery_write.fields["generation"]:
                    raise StressProtocolError("recovery BLOCK generation differs from successor")
                if marker.fields["checksum"] != recovery_write.fields["checksum"]:
                    raise StressProtocolError("recovery BLOCK checksum differs from successor")
                if next_sequence == 1:
                    if marker.fields["write_bytes"] != PAGE_BYTES:
                        raise StressProtocolError("first recovery round did not account one successor write")
                elif marker.fields["write_bytes"] != 0:
                    raise StressProtocolError("recovery performed disk writes after the successor proof")
            pending_round = marker
            if first_round is None:
                first_round = marker
            continue
        if marker.kind == "pass":
            if pass_marker is not None:
                raise StressProtocolError("stress log contains more than one PASS")
            if pending_round is None or pending_round.fields["seq"] != 1:
                raise StressProtocolError("PASS must follow the first verified profile round")
            if marker.fields["checksum"] != pending_round.fields["checksum"]:
                raise StressProtocolError("PASS checksum does not echo the first round checksum")
            pass_marker = marker
            continue
        if marker.kind == "heartbeat":
            if pending_round is None:
                raise StressProtocolError("HEARTBEAT does not follow a profile round")
            if marker.fields["seq"] != pending_round.fields["seq"]:
                raise StressProtocolError("HEARTBEAT sequence differs from its profile round")
            expected_cycles = checked_mul_u64(
                marker.fields["seq"], config.knobs.rounds_per_heartbeat, "heartbeat cycles"
            )
            if marker.fields["cycles"] != expected_cycles:
                raise StressProtocolError("HEARTBEAT cycles do not match configured round count")
            if marker.fields["cycles"] <= previous_cycles or marker.fields["ops"] <= previous_ops:
                raise StressProtocolError("HEARTBEAT cycles/ops did not strictly increase")
            if marker.fields["checksum"] != pending_round.fields["checksum"]:
                raise StressProtocolError("HEARTBEAT checksum does not echo its profile round")
            if marker.fields["seq"] == 1:
                if pass_marker is None:
                    raise StressProtocolError("first HEARTBEAT appeared before PASS")
                if (
                    pass_marker.fields["cycles"] != marker.fields["cycles"]
                    or pass_marker.fields["ops"] != marker.fields["ops"]
                ):
                    raise StressProtocolError("PASS counters differ from the first HEARTBEAT")
            elif pass_marker is None:
                raise StressProtocolError("later HEARTBEAT appeared without PASS")
            previous_cycles = marker.fields["cycles"]
            previous_ops = marker.fields["ops"]
            heartbeats.append(marker)
            pending_round = None
            next_sequence += 1
            continue
        raise StressProtocolError(f"unexpected {marker.kind} marker in {config.profile_name} run")

    if pending_round is not None:
        raise StressProtocolError("last profile round has no HEARTBEAT")
    if first_round is None or pass_marker is None:
        raise StressProtocolError("stress run did not complete its first verified round and PASS")
    if len(heartbeats) < minimum_heartbeats:
        raise StressProtocolError(
            f"stress run emitted {len(heartbeats)} heartbeats; need {minimum_heartbeats}"
        )
    if recovery and (not recovery_seen or recovery_write is None):
        raise StressProtocolError("block recovery proofs are incomplete")
    return heartbeats


def validate_writer_markers(markers: Sequence[Marker], config: StressConfig) -> list[Marker]:
    if config.profile_name != "block":
        raise StressProtocolError("writer mode is only valid for the block profile")
    baseline: Marker | None = None
    armed: Marker | None = None
    last_generation = 0
    commits: list[Marker] = []
    for marker in markers[2:]:
        require_marker_identity(marker, config)
        if marker.kind == "fail":
            raise StressProtocolError(
                f"block writer FAIL stage={marker.fields['stage']} errno={marker.fields['errno']}"
            )
        if marker.kind == "block_baseline":
            if baseline is not None or armed is not None:
                raise StressProtocolError("BLOCK_BASELINE is duplicate or out of order")
            baseline = marker
            last_generation = marker.fields["generation"]
            continue
        if marker.kind == "block_crash_armed":
            if baseline is None or armed is not None:
                raise StressProtocolError("BLOCK_CRASH_ARMED is duplicate or out of order")
            if marker.fields["generation"] != baseline.fields["generation"]:
                raise StressProtocolError("BLOCK_CRASH_ARMED generation differs from baseline")
            armed = marker
            continue
        if marker.kind == "block_commit":
            if armed is None:
                raise StressProtocolError("BLOCK_COMMIT appeared before crash arming")
            if marker.fields["generation"] != last_generation + 1:
                raise StressProtocolError("BLOCK_COMMIT generation is not contiguous")
            if marker.fields["slot"] != marker.fields["generation"] % config.knobs.io_slots:
                raise StressProtocolError("BLOCK_COMMIT slot does not match generation rotation")
            last_generation = marker.fields["generation"]
            commits.append(marker)
            continue
        if marker.kind == "pass":
            raise StressProtocolError("block writer boot emitted an unexpected PASS")
        raise StressProtocolError(f"unexpected {marker.kind} marker in block writer boot")
    if baseline is None or armed is None:
        raise StressProtocolError("block writer did not establish a baseline and arm crash injection")
    return commits


SUMMARY_RE = re.compile(
    r"Test Summary:\s*([0-9]+) passed,\s*([0-9]+) deferred[^,]*,\s*([0-9]+) failed"
)


def validate_runtime_summary(serial_path: str | os.PathLike[str]) -> tuple[int, int, int]:
    text = Path(serial_path).read_bytes().decode("utf-8", errors="replace")
    summaries = [tuple(int(value) for value in match.groups()) for match in SUMMARY_RE.finditer(text)]
    if not summaries:
        raise StressProtocolError("no parseable kernel Test Summary was emitted")
    passed, deferred, failed = summaries[-1]
    if failed != 0:
        raise StressProtocolError(f"kernel runtime summary reported {failed} failed tests")
    return passed, deferred, failed


def validate_diagnostics(
    serial_path: str | os.PathLike[str],
    interrupt_path: str | os.PathLike[str] | None,
    qemu_stderr_path: str | os.PathLike[str] | None,
) -> None:
    serial = Path(serial_path).read_bytes().decode("utf-8", errors="replace")
    if "KERNEL PANIC" in serial:
        raise StressProtocolError("kernel panic detected")
    diagnostics = ""
    for path in (interrupt_path, qemu_stderr_path):
        if path:
            diagnostics += Path(path).read_bytes().decode("utf-8", errors="replace")
            diagnostics += "\n"
    if re.search(r"triple fault", diagnostics, re.IGNORECASE):
        raise StressProtocolError("QEMU reported a triple fault")
    if re.search(r"v=0e e=0011", diagnostics):
        raise StressProtocolError("NX-violation page-fault signature detected")


def read_event_ledger(path: str | os.PathLike[str]) -> list[tuple[int, Marker]]:
    events: list[tuple[int, Marker]] = []
    for line_number, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        try:
            value = json.loads(raw)
            event_time = int(value["time_ns"])
            marker = parse_marker(str(value["line"]))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError, StressProtocolError) as error:
            raise StressProtocolError(f"invalid monitor event at line {line_number}") from error
        if event_time <= 0:
            raise StressProtocolError("monitor event has a non-positive timestamp")
        if events and event_time < events[-1][0]:
            raise StressProtocolError("monitor event timestamps moved backwards")
        events.append((event_time, marker))
    return events


def validate_heartbeat_freshness(
    markers: Sequence[Marker],
    events_path: str | os.PathLike[str],
    config: StressConfig,
    end_ns: int,
    grace_ms: int,
) -> None:
    events = read_event_ledger(events_path)
    ready_events = [(stamp, marker) for stamp, marker in events if marker.kind == "ready"]
    heartbeat_events = [(stamp, marker) for stamp, marker in events if marker.kind == "heartbeat"]
    serial_heartbeats = [marker for marker in markers if marker.kind == "heartbeat"]
    if len(ready_events) != 1:
        raise StressProtocolError("monitor did not observe exactly one READY marker")
    if [marker.line for _, marker in heartbeat_events] != [marker.line for marker in serial_heartbeats]:
        raise StressProtocolError("monitor heartbeat ledger differs from the final serial log")
    if not heartbeat_events:
        raise StressProtocolError("monitor observed no heartbeats")
    maximum_gap = (config.knobs.heartbeat_max_ms + grace_ms) * 1_000_000
    previous = ready_events[0][0]
    for stamp, marker in heartbeat_events:
        if stamp - previous > maximum_gap:
            raise StressProtocolError(
                f"heartbeat {marker.fields['seq']} arrived stale after {(stamp - previous) / 1e6:.0f} ms"
            )
        previous = stamp
    if end_ns < previous:
        raise StressProtocolError("validation end timestamp precedes the last heartbeat")
    if end_ns - previous > maximum_gap:
        raise StressProtocolError(
            f"last heartbeat was stale by run end ({(end_ns - previous) / 1e6:.0f} ms)"
        )


def validate_log(
    config: StressConfig,
    serial_path: str,
    mode: str,
    minimum_heartbeats: int,
    events_path: str | None = None,
    end_ns: int | None = None,
    heartbeat_grace_ms: int = 0,
    interrupt_path: str | None = None,
    qemu_stderr_path: str | None = None,
    qmp_before_path: str | None = None,
    qmp_after_path: str | None = None,
) -> dict[str, Any]:
    markers = parse_protocol_log(serial_path)
    validate_header(markers, config, mode)
    validate_runtime_summary(serial_path)
    validate_diagnostics(serial_path, interrupt_path, qemu_stderr_path)
    if mode == "writer":
        commits = validate_writer_markers(markers, config)
        heartbeats: list[Marker] = []
    elif mode == "normal":
        commits = []
        heartbeats = validate_normal_markers(markers, config, minimum_heartbeats)
    elif mode == "recovery":
        commits = []
        heartbeats = validate_normal_markers(
            markers, config, minimum_heartbeats, recovery=True
        )
    else:
        raise StressProtocolError(f"unknown validation mode {mode}")

    if events_path is not None:
        if end_ns is None:
            raise StressProtocolError("end_ns is required with an event ledger")
        validate_heartbeat_freshness(
            markers, events_path, config, end_ns, heartbeat_grace_ms
        )
    requires_qmp = bool(config.flags & FLAG_REQUIRE_QMP_VCPUS)
    if requires_qmp:
        if not qmp_before_path or not qmp_after_path:
            raise StressProtocolError("profile requires two QMP vCPU snapshots")
        before = json.loads(Path(qmp_before_path).read_text(encoding="utf-8"))
        after = json.loads(Path(qmp_after_path).read_text(encoding="utf-8"))
        validate_qmp_progress(before, after, config.knobs.vcpus)
    elif qmp_before_path or qmp_after_path:
        raise StressProtocolError("unexpected QMP proof supplied for a profile that does not require it")

    return {
        "profile": config.profile_name,
        "mode": mode,
        "run_id": config.run_hex,
        "heartbeats": len(heartbeats),
        "commits": len(commits),
    }


def command_validate_log(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    result = validate_log(
        config=config,
        serial_path=args.serial,
        mode=args.mode,
        minimum_heartbeats=args.minimum_heartbeats,
        events_path=args.events,
        end_ns=args.end_ns,
        heartbeat_grace_ms=args.heartbeat_grace_ms,
        interrupt_path=args.interrupt_log,
        qemu_stderr_path=args.qemu_stderr,
        qmp_before_path=args.qmp_before,
        qmp_after_path=args.qmp_after,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


def scan_new_protocol_lines(
    serial_path: Path, offset: int, pending: bytes
) -> tuple[int, bytes, list[str]]:
    try:
        with serial_path.open("rb") as stream:
            stream.seek(offset)
            chunk = stream.read()
            new_offset = stream.tell()
    except FileNotFoundError:
        return offset, pending, []
    data = pending + chunk
    parts = data.split(b"\n")
    pending = parts.pop()
    lines: list[str] = []
    for raw in parts:
        line = raw.rstrip(b"\r").decode("utf-8", errors="replace")
        if line.startswith("NILIX_STRESS_V2_"):
            lines.append(line)
    return new_offset, pending, lines


def command_monitor(args: argparse.Namespace) -> int:
    serial_path = Path(args.serial)
    events_path = Path(args.events)
    stop = False

    def request_stop(_signal_number: int, _frame: Any) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    offset = 0
    pending = b""
    with events_path.open("w", encoding="utf-8", buffering=1) as events:
        while True:
            offset, pending, lines = scan_new_protocol_lines(serial_path, offset, pending)
            for line in lines:
                events.write(
                    json.dumps({"time_ns": time.time_ns(), "line": line}, separators=(",", ":"))
                    + "\n"
                )
            events.flush()
            if stop:
                # One final scan closes the race between SIGTERM and the last
                # QEMU serial write.  A non-newline tail remains invalid in the
                # final serial parser and is intentionally not fabricated here.
                offset, pending, lines = scan_new_protocol_lines(serial_path, offset, pending)
                for line in lines:
                    events.write(
                        json.dumps(
                            {"time_ns": time.time_ns(), "line": line}, separators=(",", ":")
                        )
                        + "\n"
                    )
                events.flush()
                return 0
            time.sleep(args.poll_ms / 1000.0)


def command_wait_marker(args: argparse.Namespace) -> int:
    if len(args.regex) > 1024:
        raise StressProtocolError("wait-marker regular expression is too long")
    try:
        pattern = re.compile(args.regex)
    except re.error as error:
        raise StressProtocolError(f"invalid wait-marker expression: {error}") from error
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        if args.pid is not None:
            try:
                os.kill(args.pid, 0)
            except ProcessLookupError as error:
                raise StressProtocolError("QEMU supervisor exited before the required marker") from error
            except PermissionError:
                pass
        try:
            lines = protocol_lines(args.serial)
        except FileNotFoundError:
            lines = []
        for line in lines:
            marker = parse_marker(line)
            if marker.kind == "fail":
                raise StressProtocolError(f"guest failed while waiting: {line}")
            if pattern.fullmatch(line):
                print(line)
                return 0
        time.sleep(args.poll_ms / 1000.0)
    raise StressProtocolError("timed out waiting for the required guest marker")


def command_now_ns(_args: argparse.Namespace) -> int:
    print(time.time_ns())
    return 0


def add_knob_arguments(parser: argparse.ArgumentParser) -> None:
    for name in KNOB_NAMES:
        parser.add_argument("--" + name.replace("_", "-"), dest=name, type=parse_uint)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    make_config = subparsers.add_parser("make-config", help="write a strict 256-byte config")
    make_config.add_argument("--output", required=True)
    make_config.add_argument("--profile", choices=tuple(PROFILE_IDS), required=True)
    make_config.add_argument("--run-id", type=parse_hex_u64, required=True)
    make_config.add_argument("--seed", type=parse_hex_u64, required=True)
    make_config.add_argument("--flags", type=parse_flags)
    add_knob_arguments(make_config)
    make_config.set_defaults(handler=command_make_config)

    inspect_config = subparsers.add_parser("inspect-config", help="validate and print config JSON")
    inspect_config.add_argument("--config", required=True)
    inspect_config.set_defaults(handler=command_inspect_config)

    journal = subparsers.add_parser("journal-probe", help="inspect Ext3/JBD2 state read-only")
    journal.add_argument("--image", required=True)
    journal.add_argument("--output")
    journal.add_argument("--require-active", action="store_true")
    journal.add_argument("--require-clean", action="store_true")
    journal.set_defaults(handler=command_journal_probe)

    wait_journal = subparsers.add_parser(
        "wait-journal-active", help="poll until an active Zero-Intent journal tail is visible"
    )
    wait_journal.add_argument("--image", required=True)
    wait_journal.add_argument("--timeout-ms", type=parse_uint, default=10000)
    wait_journal.add_argument("--poll-us", type=parse_uint, default=250)
    wait_journal.set_defaults(handler=command_wait_journal_active)

    identity = subparsers.add_parser("assert-identity", help="prove a disk path is the same file")
    identity.add_argument("--image", required=True)
    identity.add_argument("--identity", required=True)
    identity.set_defaults(handler=command_assert_identity)

    qmp = subparsers.add_parser("qmp-snapshot", help="capture QMP vCPU thread ticks")
    qmp.add_argument("--socket", required=True)
    qmp.add_argument("--output", required=True)
    qmp.add_argument("--timeout", type=float, default=20.0)
    qmp.set_defaults(handler=command_qmp_snapshot)

    validate_qmp = subparsers.add_parser("validate-qmp", help="validate two QMP snapshots")
    validate_qmp.add_argument("--before", required=True)
    validate_qmp.add_argument("--after", required=True)
    validate_qmp.add_argument("--expected-vcpus", type=parse_uint, required=True)
    validate_qmp.set_defaults(handler=command_validate_qmp)

    validate = subparsers.add_parser("validate-log", help="validate a complete stress-v2 log")
    validate.add_argument("--config", required=True)
    validate.add_argument("--serial", required=True)
    validate.add_argument("--mode", choices=("normal", "writer", "recovery"), required=True)
    validate.add_argument("--minimum-heartbeats", type=parse_uint, default=1)
    validate.add_argument("--events")
    validate.add_argument("--end-ns", type=parse_uint)
    validate.add_argument("--heartbeat-grace-ms", type=parse_uint, default=0)
    validate.add_argument("--interrupt-log")
    validate.add_argument("--qemu-stderr")
    validate.add_argument("--qmp-before")
    validate.add_argument("--qmp-after")
    validate.set_defaults(handler=command_validate_log)

    monitor = subparsers.add_parser("monitor", help="timestamp stress-v2 serial markers")
    monitor.add_argument("--serial", required=True)
    monitor.add_argument("--events", required=True)
    monitor.add_argument("--poll-ms", type=parse_uint, default=100)
    monitor.set_defaults(handler=command_monitor)

    wait_marker = subparsers.add_parser("wait-marker", help="wait for an exact marker regex")
    wait_marker.add_argument("--serial", required=True)
    wait_marker.add_argument("--regex", required=True)
    wait_marker.add_argument("--timeout", type=float, default=60.0)
    wait_marker.add_argument("--poll-ms", type=parse_uint, default=100)
    wait_marker.add_argument("--pid", type=parse_uint)
    wait_marker.set_defaults(handler=command_wait_marker)

    now = subparsers.add_parser("now-ns", help="print the host wall-clock nanoseconds")
    now.set_defaults(handler=command_now_ns)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, StressProtocolError, ValueError, json.JSONDecodeError) as error:
        print(f"stress_protocol: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
