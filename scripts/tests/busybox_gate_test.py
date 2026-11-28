#!/usr/bin/env python3
"""N2 (#66): unit tests for BusyBox pinned config and gate log evaluator."""
from __future__ import annotations

from pathlib import Path
import unittest

from scripts.gates.conformance import busybox_gate as gate

ROOT = Path(__file__).resolve().parents[2]
BUSYBOX_CONFIG = ROOT / "scripts/conformance/busybox.config"
LOCKFILE = ROOT / "scripts/conformance/third_party.lock"


class BusyBoxConfigTests(unittest.TestCase):
    def test_pinned_busybox_config_enables_static_ash_job_control(self):
        self.assertTrue(BUSYBOX_CONFIG.is_file(), "busybox.config missing")
        text = BUSYBOX_CONFIG.read_text(encoding="utf-8")
        for sym in (
            "CONFIG_BUSYBOX=y",
            "CONFIG_STATIC=y",
            "CONFIG_ASH=y",
            "CONFIG_SH_IS_ASH=y",
            "CONFIG_ASH_JOB_CONTROL=y",
            "CONFIG_FEATURE_SH_STANDALONE=y",
        ):
            self.assertIn(sym, text)

    def test_lockfile_pins_busybox_and_ltp(self):
        text = LOCKFILE.read_text(encoding="utf-8")
        suites = [
            line.split()[0]
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertIn("busybox", suites)
        self.assertIn("ltp", suites)
        self.assertIn("libc-test", suites)


class BusyBoxGateEvalTests(unittest.TestCase):
    def _good_logs(self) -> tuple[str, str]:
        boot1 = "\n".join(
            [
                "BB-SCRIPT-STEPS-OK",
                "BB-SCRIPTED OK",
                "BB-INTERACTIVE-READY",
                "BB-PROMPT> sleep 30",
                "[1]+  Stopped                    sleep 30",
                "BB-PROMPT> bg && echo BB-BG-OK",
                "BB-BG-OK",
                "BB-PROMPT> fg",
                "BB-PROMPT> echo BB-FG-CTRLC-OK",
                "BB-FG-CTRLC-OK",
                "BB-INTERACTIVE-OK",
                "Process 1 terminated with exit code 0",
            ]
        )
        boot2 = "\n".join(
            [
                "BB-PERSIST-OK",
                "BB-BOOT2-DONE",
                "Process 1 terminated with exit code 0",
            ]
        )
        return boot1, boot2

    def test_valid_two_boot_transcript_passes(self):
        boot1, boot2 = self._good_logs()
        ev = gate.evaluate_busybox_logs(boot1, boot2)
        self.assertTrue(ev.ok, f"unexpected errors: {ev.errors}")
        self.assertEqual(ev.errors, ())

    def test_missing_ctrl_z_stopped_fails(self):
        boot1, boot2 = self._good_logs()
        boot1 = boot1.replace("Stopped", "Running")
        ev = gate.evaluate_busybox_logs(boot1, boot2)
        self.assertFalse(ev.ok)
        self.assertTrue(any("Stopped" in err for err in ev.errors))

    def test_missing_boot2_persistence_fails(self):
        boot1, boot2 = self._good_logs()
        boot2 = boot2.replace("BB-PERSIST-OK", "")
        ev = gate.evaluate_busybox_logs(boot1, boot2)
        self.assertFalse(ev.ok)
        self.assertTrue(any("BB-PERSIST-OK" in err for err in ev.errors))

    def test_kernel_panic_fails(self):
        boot1, boot2 = self._good_logs()
        boot2 = boot2 + "\nKERNEL PANIC: boom\n"
        ev = gate.evaluate_busybox_logs(boot1, boot2)
        self.assertFalse(ev.ok)
        self.assertTrue(any("fatal" in err for err in ev.errors))


if __name__ == "__main__":
    unittest.main()
