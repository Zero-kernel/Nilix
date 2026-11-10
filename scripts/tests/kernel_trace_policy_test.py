"""Exercise the runtime harness's trace policy with a synthetic QMP guest."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.tests.qemu_trace_test import FAKE_QEMU, MARKER, WITNESS


ROOT = Path(__file__).resolve().parents[2]
SERIAL = (
    'RUNTIME-CASE name=smoke status=pass owner=fixture reason=""\n'
    'SECURITY-CASE name=smoke status=pass owner=fixture reason=""\n'
    '=== Test Summary: 1 passed, 0 deferred, 0 failed ===\n'
    'RUNTIME-COUNTS passed=1 warning=0 deferred=0 skipped=0 failed=0\n'
    'SECURITY-COUNTS passed=1 warning=0 deferred=0 skipped=0 failed=0\n'
    + MARKER + 'Hello from Ring 3\nProcess 1 exited with code 0\n'
)


class KernelTracePolicyTests(unittest.TestCase):
    def setUp(self):
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("Bash is required")
        version = subprocess.run([bash, "--version"], capture_output=True, text=True, check=True).stdout
        major = re.search(r"version (\d+)", version)
        if major is None or int(major[1]) < 4:
            self.skipTest("the runtime shell harness requires Bash 4+ for empty arrays under nounset")
        self.bash = bash
        self.temp = tempfile.TemporaryDirectory(prefix="kernel-trace-policy-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        qemu = self.bin / "qemu-system-x86_64"
        qemu.write_text(
            f"#!{sys.executable}\nimport sys\n"
            "if '--version' in sys.argv:\n"
            "    print('QEMU synthetic trace-policy fixture')\n"
            "    sys.exit(0)\n" + FAKE_QEMU
        )
        qemu.chmod(0o755)
        # Completion mode never invokes GNU timeout, but kernel_test.sh checks
        # its availability. Fail loudly if the harness accidentally uses it.
        timeout = self.bin / "timeout"
        timeout.write_text("#!/bin/sh\nexit 99\n")
        timeout.chmod(0o755)
        self.esp = self.root / "esp"
        (self.esp / "EFI/BOOT").mkdir(parents=True)
        for path in (self.esp / "kernel.elf", self.esp / "EFI/BOOT/BOOTX64.EFI"):
            path.write_bytes(b"synthetic guest input\n")
        self.firmware = self.root / "firmware.fd"
        self.firmware.write_bytes(b"synthetic firmware\n")

    def run_gate(self, *, strict=False, override=None):
        # Real gate_inputs.py hashes the fixture inputs, and the real supervisor
        # negotiates the trace switch and quit; only the QEMU process is fake.
        environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("KERNEL_TEST_", "QEMU_TRACE_", "FAKE_"))
            and key not in ("NILIX_QEMU_TRACE", "ZERO_OS_STRICT_TESTS")
        }
        environment.update(
            PATH=str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
            TMPDIR=str(self.root), OVMF_PATH=str(self.firmware),
            KERNEL_TEST_CPUS="4", KERNEL_TEST_TIMEOUT="20", KERNEL_TEST_KEEP_LOGS="1",
            KERNEL_TEST_TRACE_DEFAULT="phased", QEMU_GATE_MODE="completion",
            ZERO_OS_STRICT_TESTS="1" if strict else "0",
            FAKE_COMMANDS=str(self.root / "commands.log"),
            FAKE_SCRIPT=json.dumps([[0.1, SERIAL], [0.2, WITNESS]]),
        )
        if override is not None:
            environment["NILIX_QEMU_TRACE"] = override
        result = subprocess.run(
            [self.bash, str(ROOT / "scripts/gates/boot/kernel_test.sh"), str(self.esp)],
            env=environment, capture_output=True, text=True, timeout=40,
        )
        artifact = re.search(r"^KERNEL-TEST ARTIFACTS: serial=(\S+)", result.stdout, re.MULTILINE)
        self.assertIsNotNone(artifact, result.stdout + result.stderr)
        counts = Path(artifact[1] + ".counts.json")
        self.assertTrue(counts.is_file(), result.stdout + result.stderr)
        return result, json.loads(counts.read_text())

    def test_phased_launch_does_not_relax_runtime_verdict(self):
        result, counts = self.run_gate()
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertEqual(counts["status"], 3)
        self.assertEqual(counts["details"]["trace_default"], "full")
        self.assertEqual(counts["details"]["trace_scope"], "phased")

    def test_strict_runtime_rejects_phased_launch(self):
        result, counts = self.run_gate(strict=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("strict mode rejects a diagnostic interrupt-trace scope", counts["reasons"])

    def test_full_override_preserves_strict_acceptance(self):
        result, counts = self.run_gate(strict=True, override="full")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(counts["status"], 0)
        self.assertEqual(counts["details"]["trace_scope"], "full")
        self.assertEqual((self.root / "commands.log").read_text().splitlines(), ["quit"])


if __name__ == "__main__":
    unittest.main()
