#!/usr/bin/env python3
"""Synthetic evidence fixtures; these tests do not execute a guest."""
import tempfile
import unittest
from pathlib import Path

from scripts.gates.qemu.qemu_fuzz_smoke import check_guest_evidence, sha256


class GuestEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = ""
        for index, name in enumerate(("getpid", "uname")):
            run = self.root / f"nilix-syz-v2-{index}"
            run.mkdir()
            identity = f"seq={index:016x} run={'a' * 32} program={'b' * 64}"
            (run / "serial.log").write_text(
                f"NILIX_SYZ_V2_BEGIN {identity}\n"
                f"NILIX_SYZ_V2_PASS {identity} slots=1 tag={'c' * 64}\n"
            )
            (run / "syz-result.host.bin").write_bytes(b"synthetic fixture")
            (run / "syz-disk.img").write_bytes(b"synthetic disk fixture")
            disk_hash = sha256(run / "syz-disk.img")
            (run / "extraction-disk.sha256").write_text(f"before={disk_hash}\nafter={disk_hash}\n")
            self.output += f"NILIX_SYZ_QEMU_STARTED pid={index + 1} artifacts={run}\n"
            self.output += f"QEMU-FUZZ-SEED PASS name={name} occupied=1\n"
        self.output += "QEMU-FUZZ-SMOKE PASS seeds=2\n"

    def test_complete_fixture(self):
        check_guest_evidence(self.root, self.output)

    def test_constant_success_without_launch_cannot_pass(self):
        with self.assertRaises(RuntimeError):
            check_guest_evidence(self.root, "QEMU-FUZZ-SMOKE PASS seeds=2\n")

    def test_missing_or_duplicate_completion_cannot_pass(self):
        for output in (self.output.replace("QEMU-FUZZ-SMOKE PASS seeds=2", ""),
                       self.output + "QEMU-FUZZ-SMOKE PASS seeds=2\n",
                       self.output.replace("occupied=1", "occupied=0")):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                check_guest_evidence(self.root, output)

    def test_wrong_guest_identity_cannot_pass(self):
        path = self.root / "nilix-syz-v2-1/serial.log"
        path.write_text(path.read_text().replace("PASS seq=0000000000000001", "PASS seq=0000000000000002"))
        with self.assertRaises(RuntimeError):
            check_guest_evidence(self.root, self.output)

    def test_panic_after_pass_cannot_pass(self):
        path = self.root / "nilix-syz-v2-1/serial.log"
        path.write_text(path.read_text() + "KERNEL PANIC\n")
        with self.assertRaises(RuntimeError):
            check_guest_evidence(self.root, self.output)

    def test_missing_result_cannot_pass(self):
        (self.root / "nilix-syz-v2-1/syz-result.host.bin").unlink()
        with self.assertRaises(RuntimeError):
            check_guest_evidence(self.root, self.output)

    def test_changed_disk_cannot_pass(self):
        (self.root / "nilix-syz-v2-1/syz-disk.img").write_bytes(b"changed after extraction")
        with self.assertRaises(RuntimeError):
            check_guest_evidence(self.root, self.output)

    def test_extraction_cannot_mutate_disk(self):
        path = self.root / "nilix-syz-v2-1/extraction-disk.sha256"
        after = sha256(path.parent / "syz-disk.img")
        path.write_text(f"before={'0' * 64}\nafter={after}\n")
        with self.assertRaises(RuntimeError):
            check_guest_evidence(self.root, self.output)


if __name__ == "__main__":
    unittest.main()
