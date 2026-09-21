#!/usr/bin/env python3
"""Mutation checks for KSA-004 guest evidence, independent of guest execution."""

import unittest
from pathlib import Path
from scripts.gates.qemu.open_fault_probe import evidence_passes


# Captured from the actual v16 Ring-3 run; kept independent of expected_markers.
SERIAL = (Path(__file__).resolve().parents[1] / "fixtures/open-fault-v16.serial").read_text()


class OpenEvidenceTests(unittest.TestCase):
    def test_complete_evidence(self):
        self.assertTrue(evidence_passes(SERIAL, 0))
        self.assertTrue(evidence_passes(SERIAL.replace("terminated with exit code", "exited with code"), 0))

    def test_duplicate_exit_is_ambiguous(self):
        self.assertFalse(evidence_passes(SERIAL + "Process 1 exited with code 0\n", 0))
        self.assertFalse(evidence_passes(SERIAL + "Process 1 terminated with exit code 139\n", 0))

    def test_recovered_fault_entry_is_not_a_terminal_fault(self):
        self.assertTrue(evidence_passes("[PF ENTRY] err=0x0000000000000003\n" + SERIAL, 0))

    def test_failed_or_incomplete_platform_gate(self):
        for status in (1, 2, 3, 124, -9):
            self.assertFalse(evidence_passes(SERIAL, status))

    def test_unrelated_errors_cannot_satisfy_injection(self):
        for text in (SERIAL.replace("stage=lsm", "stage=credential"),
                     SERIAL.replace("errno=13", "errno=12"),
                     SERIAL.replace("cap_reserved=1", "cap_reserved=0"),
                     SERIAL.replace("heap=restored", "heap=unknown")):
            self.assertFalse(evidence_passes(text, 0))

    def test_missing_duplicate_and_partial_execution(self):
        lines = SERIAL.splitlines()
        for text in ("\n".join(lines[1:]), "\n".join(lines[:-2]),
                     SERIAL.replace("KSA-004-TRUNCATE DONE\n", "", 1),
                     SERIAL + "KSA-004-TRUNCATE DONE\n",
                     SERIAL.replace("family=openat2", "family=open")):
            self.assertFalse(evidence_passes(text, 0))

    def test_late_fault_overrides_success(self):
        for fatal in ("KERNEL PANIC", "[PAGE FAULT]", "[DOUBLE FAULT]"):
            self.assertFalse(evidence_passes(SERIAL + fatal, 0))


if __name__ == "__main__":
    unittest.main()
