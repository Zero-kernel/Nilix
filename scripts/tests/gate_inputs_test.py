#!/usr/bin/env python3
"""Input capture regressions: stale firmware state, mutation and incomplete ESP."""
from pathlib import Path
import tempfile
import unittest

from scripts.ci import gate_inputs


class GateInputsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        (self.source / "EFI/BOOT").mkdir(parents=True)
        for name in gate_inputs.BOOT_FILES:
            (self.source / name).write_bytes(name.encode())
        (self.source / "NvVars").write_bytes(b"stale q35 firmware boot state")
        self.firmware = self.root / "firmware"
        self.firmware.write_bytes(b"firmware")
        self.output = self.root / "captured"

    def prepare(self):
        gate_inputs.prepare(self.source, self.output, self.firmware, self.firmware)

    def test_only_boot_inputs_enter_a_fresh_esp(self):
        self.prepare()
        self.assertEqual(sorted(str(p.relative_to(self.output / "esp")).replace("\\", "/")
                                for p in (self.output / "esp").rglob("*") if p.is_file()),
                         sorted(gate_inputs.BOOT_FILES))
        gate_inputs.verify(self.output)
        with self.assertRaises(FileExistsError):
            self.prepare()

    def test_source_or_captured_or_firmware_mutation_fails(self):
        self.prepare()
        for path in (self.source / "kernel.elf", self.output / "esp/EFI/BOOT/BOOTX64.EFI", self.firmware):
            with self.subTest(path=path):
                original = path.read_bytes()
                path.write_bytes(original + b"changed")
                with self.assertRaises(ValueError):
                    gate_inputs.verify(self.output)
                path.write_bytes(original)

    def test_missing_bootloader_cannot_produce_valid_evidence(self):
        (self.source / "EFI/BOOT/BOOTX64.EFI").unlink()
        with self.assertRaises(FileNotFoundError):
            self.prepare()
        self.assertFalse((self.output / "inputs.json").exists())


if __name__ == "__main__":
    unittest.main()
