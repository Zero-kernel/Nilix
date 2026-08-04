#!/usr/bin/env python3
"""Adversarial self-tests for scripts/stress_protocol.py."""

from __future__ import annotations

import argparse
import json
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import stress_protocol as protocol  # noqa: E402


CHECKSUM_A = "0123456789abcdef"
CHECKSUM_B = "fedcba9876543210"


def make_config(profile: str, **overrides: int) -> protocol.StressConfig:
    values = {name: 0 for name in protocol.KNOB_NAMES}
    values.update(protocol.DEFAULT_KNOBS[profile])
    values.update(overrides)
    config = protocol.StressConfig(
        profile=protocol.PROFILE_IDS[profile],
        flags=protocol.DEFAULT_FLAGS[profile],
        run_id=0x1020304050607080,
        seed=0x8877665544332211,
        knobs=protocol.StressKnobs(**values),
    )
    return protocol.StressConfig.from_bytes(config.to_bytes())


def begin(config: protocol.StressConfig) -> str:
    return (
        f"NILIX_STRESS_V2_BEGIN run={config.run_hex} profile={config.profile_name} "
        f"config_sha256={config.digest_hex} vcpus={config.knobs.vcpus} "
        f"workers={config.knobs.workers}"
    )


def ready(config: protocol.StressConfig, mode: str) -> str:
    return f"NILIX_STRESS_V2_READY run={config.run_hex} profile={config.profile_name} mode={mode}"


def summary() -> str:
    return "Test Summary: 42 passed, 0 deferred (hardware unavailable), 0 failed"


def smp_round(config: protocol.StressConfig, sequence: int, checksum: str) -> str:
    expected = config.knobs.workers * config.knobs.contention_iterations
    mask = (1 << config.knobs.workers) - 1
    return (
        f"NILIX_STRESS_V2_SMP run={config.run_hex} seq={sequence} "
        f"workers={config.knobs.workers} iterations={config.knobs.contention_iterations} "
        f"counter={expected} expected={expected} spins=7 done_mask={mask:016x} "
        f"checksum={checksum}"
    )


def common_pass(config: protocol.StressConfig, ops: int, checksum: str) -> str:
    return (
        f"NILIX_STRESS_V2_PASS run={config.run_hex} profile={config.profile_name} "
        f"cycles=1 ops={ops} checksum={checksum}"
    )


def heartbeat(
    config: protocol.StressConfig, sequence: int, ops: int, checksum: str
) -> str:
    return (
        f"NILIX_STRESS_V2_HEARTBEAT run={config.run_hex} profile={config.profile_name} "
        f"seq={sequence} cycles={sequence * config.knobs.rounds_per_heartbeat} "
        f"ops={ops} checksum={checksum}"
    )


def write_log(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join([summary(), *lines]) + "\n", encoding="utf-8")


def write_events(path: Path, lines: list[tuple[int, str]]) -> None:
    with path.open("w", encoding="utf-8") as stream:
        for timestamp, line in lines:
            stream.write(json.dumps({"time_ns": timestamp, "line": line}) + "\n")


def make_ext3_image(path: Path, *, recover: bool, zero_intent: bool, start: int) -> None:
    block_size = 4096
    image = bytearray(16 * block_size)
    superblock = memoryview(image)[1024:2048]
    struct.pack_into("<H", superblock, 56, 0xEF53)
    struct.pack_into("<I", superblock, 24, 2)
    struct.pack_into("<I", superblock, 40, 128)
    struct.pack_into("<I", superblock, 76, 1)
    struct.pack_into("<H", superblock, 88, 256)
    struct.pack_into("<I", superblock, 92, protocol.EXT3_FEATURE_COMPAT_HAS_JOURNAL)
    struct.pack_into(
        "<I",
        superblock,
        96,
        protocol.EXT3_FEATURE_INCOMPAT_RECOVER if recover else 0,
    )
    superblock[104:120] = bytes.fromhex("00112233445566778899aabbccddeeff")
    struct.pack_into("<I", superblock, 224, 8)
    struct.pack_into("<H", superblock, 254, 32)
    struct.pack_into("<I", image, block_size + 8, 2)
    journal_inode_offset = 2 * block_size + 7 * 256
    struct.pack_into("<I", image, journal_inode_offset + 40, 10)
    journal_offset = 10 * block_size
    struct.pack_into(">I", image, journal_offset, protocol.JBD2_MAGIC)
    struct.pack_into(">I", image, journal_offset + 4, protocol.JBD2_SUPERBLOCK_V2)
    struct.pack_into(">I", image, journal_offset + 12, block_size)
    struct.pack_into(">I", image, journal_offset + 28, start)
    features = protocol.JBD2_FEATURE_INCOMPAT_ZERO_INTENT if zero_intent else 0
    struct.pack_into(">I", image, journal_offset + 40, features)
    path.write_bytes(image)


class ConfigTests(unittest.TestCase):
    def test_every_profile_round_trips_to_exact_wire_size(self) -> None:
        for profile in protocol.PROFILE_IDS:
            with self.subTest(profile=profile):
                config = make_config(profile)
                encoded = config.to_bytes()
                self.assertEqual(len(encoded), 256)
                self.assertEqual(protocol.StressConfig.from_bytes(encoded).profile_name, profile)

    def test_digest_reserved_unknown_flag_and_extra_byte_fail_closed(self) -> None:
        encoded = bytearray(make_config("memory").to_bytes())
        corrupt = bytearray(encoded)
        corrupt[32] ^= 1
        with self.assertRaises(protocol.StressProtocolError):
            protocol.StressConfig.from_bytes(bytes(corrupt))

        reserved = bytearray(encoded)
        reserved[112] = 1
        reserved[216:248] = __import__("hashlib").sha256(reserved[:216]).digest()
        with self.assertRaises(protocol.StressProtocolError):
            protocol.StressConfig.from_bytes(bytes(reserved))

        flags = bytearray(encoded)
        struct.pack_into("<I", flags, 20, 1 << 31)
        flags[216:248] = __import__("hashlib").sha256(flags[:216]).digest()
        with self.assertRaises(protocol.StressProtocolError):
            protocol.StressConfig.from_bytes(bytes(flags))

        with self.assertRaises(protocol.StressProtocolError):
            protocol.StressConfig.from_bytes(bytes(encoded) + b"\0")


class MarkerStateMachineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = make_config(
            "smp", vcpus=2, workers=2, heartbeat_max_ms=1000, contention_iterations=10
        )
        self.log = self.root / "serial.log"
        self.events = self.root / "events.jsonl"
        self.round1 = smp_round(self.config, 1, CHECKSUM_A)
        self.pass1 = common_pass(self.config, 40, CHECKSUM_A)
        self.hb1 = heartbeat(self.config, 1, 40, CHECKSUM_A)
        self.round2 = smp_round(self.config, 2, CHECKSUM_B)
        self.hb2 = heartbeat(self.config, 2, 80, CHECKSUM_B)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def valid_lines(self) -> list[str]:
        return [
            begin(self.config),
            ready(self.config, "normal"),
            self.round1,
            self.pass1,
            self.hb1,
            self.round2,
            self.hb2,
        ]

    def validate(self, lines: list[str], event_times: list[int] | None = None) -> None:
        write_log(self.log, lines)
        if event_times is None:
            event_times = [1_000_000_000, 1_500_000_000, 2_000_000_000]
        event_lines = [lines[1], self.hb1, self.hb2]
        write_events(self.events, list(zip(event_times, event_lines, strict=True)))
        protocol.validate_log(
            config=self.config,
            serial_path=str(self.log),
            mode="normal",
            minimum_heartbeats=2,
            events_path=str(self.events),
            end_ns=2_500_000_000,
            heartbeat_grace_ms=0,
            qmp_before_path=None,
            qmp_after_path=None,
        )

    def test_valid_normal_protocol(self) -> None:
        # Remove the QMP requirement for this state-machine-only fixture.
        object.__setattr__(self.config, "flags", protocol.FLAG_HOST_TERMINATED)
        self.validate(self.valid_lines())

    def test_duplicate_and_out_of_order_markers_are_rejected(self) -> None:
        object.__setattr__(self.config, "flags", protocol.FLAG_HOST_TERMINATED)
        lines = self.valid_lines()
        with self.assertRaises(protocol.StressProtocolError):
            self.validate([lines[0], lines[0], *lines[1:]])
        with self.assertRaises(protocol.StressProtocolError):
            self.validate([lines[0], lines[1], self.hb1, self.round1, self.pass1, self.round2, self.hb2])

    def test_wrong_run_profile_and_digest_are_rejected(self) -> None:
        object.__setattr__(self.config, "flags", protocol.FLAG_HOST_TERMINATED)
        for original, replacement in (
            (self.config.run_hex, "ffffffffffffffff"),
            ("profile=smp", "profile=cpu"),
            (self.config.digest_hex, "0" * 64),
        ):
            with self.subTest(replacement=replacement):
                lines = self.valid_lines()
                lines[0] = lines[0].replace(original, replacement, 1)
                with self.assertRaises(protocol.StressProtocolError):
                    self.validate(lines)

    def test_gapped_and_stale_heartbeats_are_rejected(self) -> None:
        object.__setattr__(self.config, "flags", protocol.FLAG_HOST_TERMINATED)
        lines = self.valid_lines()
        lines[-1] = lines[-1].replace("seq=2", "seq=3").replace("cycles=2", "cycles=3")
        with self.assertRaises(protocol.StressProtocolError):
            self.validate(lines)
        with self.assertRaises(protocol.StressProtocolError):
            self.validate(self.valid_lines(), [1_000_000_000, 2_500_000_001, 3_000_000_000])

    def test_wrong_profile_arithmetic_and_unknown_prefix_are_rejected(self) -> None:
        object.__setattr__(self.config, "flags", protocol.FLAG_HOST_TERMINATED)
        lines = self.valid_lines()
        lines[2] = lines[2].replace("counter=20", "counter=19")
        with self.assertRaises(protocol.StressProtocolError):
            self.validate(lines)
        lines = self.valid_lines()
        lines.insert(2, "NILIX_STRESS_V2_NOT_A_REAL_MARKER run=1020304050607080")
        with self.assertRaises(protocol.StressProtocolError):
            self.validate(lines)

    def test_qmp_count_and_progress_failures(self) -> None:
        valid_before = {
            "cpus": [
                {"cpu_index": 0, "thread_id": 10, "ticks": 100},
                {"cpu_index": 1, "thread_id": 11, "ticks": 200},
            ]
        }
        valid_after = {
            "cpus": [
                {"cpu_index": 0, "thread_id": 10, "ticks": 101},
                {"cpu_index": 1, "thread_id": 11, "ticks": 201},
            ]
        }
        protocol.validate_qmp_progress(valid_before, valid_after, 2)
        with self.assertRaises(protocol.StressProtocolError):
            protocol.validate_qmp_progress(valid_before, {"cpus": valid_after["cpus"][:1]}, 2)
        stalled = json.loads(json.dumps(valid_after))
        stalled["cpus"][1]["ticks"] = 200
        with self.assertRaises(protocol.StressProtocolError):
            protocol.validate_qmp_progress(valid_before, stalled, 2)


class BlockRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = make_config("block", heartbeat_max_ms=1000, io_writes_per_round=2)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_writer_rejects_unexpected_pass(self) -> None:
        markers = [
            protocol.parse_marker(begin(self.config)),
            protocol.parse_marker(ready(self.config, "writer")),
            protocol.parse_marker(
                f"NILIX_STRESS_V2_BLOCK_BASELINE run={self.config.run_hex} "
                f"generation=12 checksum={CHECKSUM_A}"
            ),
            protocol.parse_marker(
                f"NILIX_STRESS_V2_BLOCK_CRASH_ARMED run={self.config.run_hex} generation=12"
            ),
        ]
        protocol.validate_header(markers, self.config, "writer")
        protocol.validate_writer_markers(markers, self.config)
        markers.append(protocol.parse_marker(common_pass(self.config, 1, CHECKSUM_A)))
        with self.assertRaises(protocol.StressProtocolError):
            protocol.validate_writer_markers(markers, self.config)

    def test_raw_probe_requires_all_three_active_journal_signals(self) -> None:
        active = self.root / "active.img"
        make_ext3_image(active, recover=True, zero_intent=True, start=1)
        self.assertTrue(protocol.probe_journal(active)["active"])
        for index, settings in enumerate(
            (
                {"recover": False, "zero_intent": True, "start": 1},
                {"recover": True, "zero_intent": False, "start": 1},
                {"recover": True, "zero_intent": True, "start": 0},
            )
        ):
            path = self.root / f"inactive-{index}.img"
            make_ext3_image(path, **settings)
            self.assertFalse(protocol.probe_journal(path)["active"])

    def test_different_recovery_disk_identity_is_rejected(self) -> None:
        first = self.root / "first.img"
        second = self.root / "second.img"
        identity = self.root / "identity.json"
        make_ext3_image(first, recover=True, zero_intent=True, start=1)
        shutil.copyfile(first, second)
        identity.write_text(json.dumps(protocol.probe_journal(first)), encoding="utf-8")
        with self.assertRaises(protocol.StressProtocolError):
            protocol.command_assert_identity(
                argparse.Namespace(identity=str(identity), image=str(second))
            )

    def test_recovery_allows_only_read_only_rounds_after_successor(self) -> None:
        recovered_checksum = "1111111111111111"
        lines = [
            begin(self.config),
            ready(self.config, "recovery"),
            f"NILIX_STRESS_V2_BLOCK_RECOVERED run={self.config.run_hex} generation=20 "
            f"valid_slots=12 invalid_slots=0 checksum={recovered_checksum}",
            f"NILIX_STRESS_V2_BLOCK_RECOVERY_WRITE run={self.config.run_hex} generation=21 "
            f"slot=9 checksum={CHECKSUM_A}",
            f"NILIX_STRESS_V2_BLOCK run={self.config.run_hex} seq=1 generation=21 "
            f"valid_slots=12 read_bytes=98304 write_bytes=4096 checksum={CHECKSUM_A}",
            common_pass(self.config, 25, CHECKSUM_A),
            heartbeat(self.config, 1, 25, CHECKSUM_A),
            f"NILIX_STRESS_V2_BLOCK run={self.config.run_hex} seq=2 generation=21 "
            f"valid_slots=12 read_bytes=49152 write_bytes=0 checksum={CHECKSUM_A}",
            heartbeat(self.config, 2, 37, CHECKSUM_A),
        ]
        markers = [protocol.parse_marker(line) for line in lines]
        protocol.validate_header(markers, self.config, "recovery")
        protocol.validate_normal_markers(markers, self.config, 2, recovery=True)
        bad = list(lines)
        bad[-2] = bad[-2].replace("write_bytes=0", "write_bytes=4096")
        with self.assertRaises(protocol.StressProtocolError):
            protocol.validate_normal_markers(
                [protocol.parse_marker(line) for line in bad], self.config, 2, recovery=True
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
