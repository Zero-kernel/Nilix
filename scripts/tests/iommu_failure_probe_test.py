#!/usr/bin/env python3
"""Terminal probe evidence must distinguish fault setup from actual faults."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.gates.qemu import iommu_failure_probe as probe
from scripts.gates.qemu.iommu_failure_probe import evidence_passes


SERIAL = """  Exception handlers: 20 (double fault uses IST)
KSA-001-MMIO-PROBES PASS allocation_boundaries=4 retained_capacity=1 invalid_ownership=5 exclusive=1 occupied_readonly=1 unmapped=1 restoration=exact
KSA-001-REGISTER-OWNER PASS prefix_removed=1 foreign_suffix_preserved=1 slots_restored=1 scratch_reclaimed=1
KSA-001-INIT BEGIN case=constructor
[IOMMU]   Failed to initialize unit at 0xfed90000: RegisterMappingFailed
KSA-001-INIT PASS case=constructor published=0 snapshot=0 dma_rejected=1 attach_rejected=1 sticky=1 retained=1
"""


class EvidenceTests(unittest.TestCase):
    def test_setup_banner_is_not_a_fault(self):
        self.assertTrue(evidence_passes(SERIAL, "", 33, "constructor"))

    def test_fatal_after_completion_overrides_pass(self):
        for text in ("[DOUBLE FAULT]", "[PF ENTRY]", "KERNEL PANIC", "panicked at probe"):
            self.assertFalse(evidence_passes(SERIAL + text, "", 33, "constructor"))
            self.assertFalse(evidence_passes(SERIAL, text, 33, "constructor"))

    def test_timeout_and_wrong_exit_rejected(self):
        for status in (0, 1, 35, "timeout"):
            self.assertFalse(evidence_passes(SERIAL, "", status, "constructor"))

    def test_unrelated_constructor_failure_rejected(self):
        self.assertFalse(evidence_passes(SERIAL.replace("RegisterMappingFailed", "HardwareInitFailed"), "", 33, "constructor"))

    def test_duplicate_missing_partial_or_wrong_case_rejected(self):
        for text in (SERIAL + "KSA-001-INIT BEGIN case=constructor\n",
                     SERIAL.replace("snapshot=0 ", ""),
                     SERIAL.replace("KSA-001-REGISTER-OWNER PASS", "owner"),
                     SERIAL.replace("case=constructor", "case=ir")):
            self.assertFalse(evidence_passes(text, "", 33, "constructor"))


class MainInputIdentityTests(unittest.TestCase):
    def run_fixture(self, changed_name=None, phase=None):
        """Run the real orchestration and evidence parser around a synthetic guest."""
        with tempfile.TemporaryDirectory(prefix="iommu-input-test-") as temporary:
            root = Path(temporary).resolve()
            (root / "kernel").mkdir()
            kernel = root / "kernel-target/iommu-probe/x86_64-unknown-none/release/kernel"
            loader = root / "bootloader-target/x86_64-unknown-uefi/release/bootloader.efi"
            for image in (kernel, loader):
                image.parent.mkdir(parents=True)
                image.write_bytes(b"synthetic boot image\n")
            paths = {
                "firmware": root / "firmware.fd",
                "qemu": root / "qemu-system-x86_64",
                "source": root / "proof.txt",
                "manifest": root / "inputs.sha256",
            }
            for name in ("firmware", "qemu", "source"):
                paths[name].write_bytes(b"original input\n")
            source_hash = hashlib.sha256(paths["source"].read_bytes()).hexdigest()
            paths["manifest"].write_text(source_hash + "  proof.txt\n", encoding="utf-8")
            artifacts = root / "artifacts"
            guest_calls = []

            def change_input(at_phase):
                if changed_name and phase == at_phase:
                    path = paths[changed_name]
                    path.write_bytes(path.read_bytes() + b"changed during orchestration\n")

            def execute(command, **_kwargs):
                if command[0] == "cargo":
                    change_input("build")
                elif command[0] == str(paths["qemu"]) and "--version" not in command:
                    guest_calls.append(command)
                    serial = Path(command[command.index("-serial") + 1].removeprefix("file:"))
                    serial.write_text(SERIAL, encoding="utf-8")
                    change_input("guest")
                    return SimpleNamespace(returncode=33)
                return SimpleNamespace(returncode=0)

            argv = ["iommu_failure_probe.py", "--input-manifest", str(paths["manifest"]),
                    "--revision", "synthetic-reviewed-revision", "--artifacts", str(artifacts),
                    "--cases", "constructor"]
            with patch.object(probe, "__file__", str(root / "scripts/gates/qemu/iommu_failure_probe.py")), \
                    patch.object(sys, "argv", argv), \
                    patch.dict(probe.os.environ, {"OVMF_PATH": str(paths["firmware"])}), \
                    patch.object(probe.shutil, "which", return_value=str(paths["qemu"])), \
                    patch.object(probe.subprocess, "run", side_effect=execute), \
                    contextlib.redirect_stdout(io.StringIO()):
                status = probe.main()
            runs = list(artifacts.glob("iommu-failure-*"))
            self.assertEqual(len(runs), 1)
            results = json.loads((runs[0] / "results.json").read_text(encoding="utf-8"))
            case_results = [json.loads(path.read_text(encoding="utf-8"))
                            for path in runs[0].glob("*/result.json")]
            self.assertEqual(len(results), 1)
            self.assertEqual(len(case_results), 1)
            return status, results, case_results, guest_calls, paths.get(changed_name)

    def test_real_main_accepts_unchanged_successful_guest(self):
        status, results, cases, guests, _ = self.run_fixture()
        self.assertEqual(status, 0)
        self.assertEqual(len(guests), 1)
        self.assertTrue(results[0]["pass"])
        self.assertTrue(cases[0]["pass"])

    def test_real_main_rejects_input_changes_after_build_and_guest(self):
        for phase in ("build", "guest"):
            for changed in ("firmware", "qemu", "source", "manifest"):
                with self.subTest(phase=phase, changed=changed):
                    status, results, cases, guests, path = self.run_fixture(changed, phase)
                    self.assertNotEqual(status, 0)
                    self.assertFalse(results[0]["pass"])
                    self.assertFalse(cases[0]["pass"])
                    self.assertIn(path.name, json.dumps(results) + json.dumps(cases))
                    if phase == "build":
                        self.assertFalse(guests, "unstable build inputs must not launch a guest")


if __name__ == "__main__":
    unittest.main()
