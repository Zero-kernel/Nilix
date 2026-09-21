#!/usr/bin/env python3
"""Exercise shell outcome propagation with mocked VM and storage dependencies.

The stress tests execute the production profile functions and final aggregate.
They establish status handling, not guest workload or filesystem correctness.
Performance and final-status tests run their complete shell entrypoints using
the existing fake-QEMU fixture. No guest or host filesystem tool is launched.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts.tests import gate_log_test as gate_fixture
from scripts.gates.stress import stress_protocol


BASH = shutil.which("bash")
ROOT = Path(__file__).resolve().parents[2]


def shell_path(path: Path) -> str:
    if os.name == "nt":
        converter = Path(BASH).with_name("cygpath.exe")
        return subprocess.check_output([str(converter), "-u", str(path)], text=True).strip()
    return str(path)


STRESS_DEPENDENCIES = r"""
set -uo pipefail
TEST_PASS=0
TEST_FAIL=1
TEST_QUALIFIED=3
STRESS_BOOT_TIMEOUT=0
STRESS_DURATION=0
STRESS_SHUTDOWN_GRACE=0
STRESS_MIN_HEARTBEATS=1
STRESS_BLOCK_CRASH_ATTEMPTS=1
STRESS_BLOCK_ACTIVE_WAIT_MS=0
STRESS_BLOCK_ACTIVE_POLL_US=0
STRESS_MEM=256M
BLOCK_KILL_OFFSETS=(0)
MONITOR_STATUS=0
QMP_BEFORE=before
QMP_AFTER=after
PYTHON=true
PROTOCOL=mocked
read -r -a SELECTED_PROFILES <<< "$OUTCOME_PROFILES"
profile_vcpus() { echo 2; }
profile_workers() { echo 2; }
profile_memory() { echo 256M; }
prepare_profile_disk() {
    mkdir -p "$2"
    printf 'review-run\n' > "$2/run-id"
    printf 'review-digest\n' > "$2/config-sha256"
    printf 'fixed-disk\n' > "$2/disk.img"
}
start_vm() { return 0; }
wait_marker() { return "$OUTCOME_READINESS_STATUS"; }
capture_qmp() { return 0; }
wait_soak_window() { return 0; }
stop_vm() { MONITOR_STATUS=0; }
record_run_end() { :; }
show_failure_logs() { :; }
validate_current_log() {
    case "$2" in
        normal) return "$OUTCOME_NORMAL_STATUS" ;;
        writer) return "$OUTCOME_WRITER_STATUS" ;;
        recovery) return "$OUTCOME_RECOVERY_STATUS" ;;
        *) return 1 ;;
    esac
}
"""


@unittest.skipUnless(BASH, "bash is required for shell outcome tests")
class StressOutcomeTests(unittest.TestCase):
    def test_profile_and_aggregate_statuses(self):
        source = (ROOT / "scripts" / "gates" / "stress" / "stress_test.sh").read_text(encoding="utf-8")
        # Keep the real branch logic and aggregate; only setup/VM operations are
        # replaced. A missing entrypoint is a test failure, not a skipped test.
        body = source[source.index("run_normal_profile() {"):]
        self.assertIn("run_block_profile() {", body)
        self.assertIn('for profile in "${SELECTED_PROFILES[@]}"', body)
        scenarios = (
            ("normal_pass", "cpu", {}, 0),
            ("normal_qualified", "cpu", {"NORMAL": 3}, 3),
            ("normal_failure_wins", "cpu", {"NORMAL": 3, "READINESS": 1}, 1),
            ("writer_qualified", "block", {"WRITER": 3}, 3),
            ("recovery_qualified", "block", {"RECOVERY": 3}, 3),
            ("recovery_failure_wins", "block", {"WRITER": 3, "RECOVERY": 1}, 1),
            ("mixed_qualified", "cpu block", {"NORMAL": 3}, 3),
            ("mixed_failure_wins", "cpu block", {"NORMAL": 3, "RECOVERY": 1}, 1),
        )
        with tempfile.TemporaryDirectory(prefix="outcome-stress-") as directory:
            work = Path(directory)
            runner = work / "caller.sh"
            runner.write_text(STRESS_DEPENDENCIES + body, encoding="utf-8", newline="\n")
            for name, profiles, statuses, expected in scenarios:
                with self.subTest(scenario=name):
                    scenario = work / name
                    scenario.mkdir()
                    environment = os.environ.copy()
                    environment.update({
                        "SUITE_TMP": shell_path(scenario),
                        "OUTCOME_PROFILES": profiles,
                        **{f"OUTCOME_{kind}_STATUS": str(statuses.get(kind, 0))
                           for kind in ("NORMAL", "WRITER", "RECOVERY", "READINESS")},
                    })
                    result = subprocess.run(
                        [BASH, "--noprofile", "--norc", shell_path(runner)],
                        env=environment, capture_output=True, text=True,
                        encoding="utf-8", timeout=10,
                    )
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    if expected:
                        self.assertNotIn("STRESS-TEST STABLE:", result.stdout)
                    if expected == 3:
                        self.assertIn("STRESS-TEST QUALIFIED:", result.stdout)


class StressEvidenceTests(unittest.TestCase):
    def test_empty_runtime_suite_cannot_complete_a_stress_gate(self):
        with tempfile.TemporaryDirectory(prefix="outcome-empty-") as directory:
            serial = Path(directory) / "serial.log"
            serial.write_text("=== Test Summary: 0 passed, 0 deferred, 0 failed ===\n")
            with mock.patch.dict(os.environ, {"ZERO_OS_STRICT_TESTS": "0"}):
                with self.assertRaises(stress_protocol.StressProtocolError):
                    stress_protocol.validate_runtime_evidence(serial)


@unittest.skipUnless(BASH, "bash is required for shell outcome tests")
class OtherCallerOutcomeTests(unittest.TestCase):
    def setUp(self):
        # Composition avoids rerunning inherited gate fixture test methods.
        self.fixture = gate_fixture.ShellTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        shutil.copyfile(
            ROOT / "scripts" / "gates" / "performance" / "perf_regression_test.sh",
            self.fixture.work / "scripts" / "gates" / "performance" / "perf_regression_test.sh",
        )

    def run_performance(self, serial: str, strict: bool):
        # perf currently invokes the short timeout form. Fake QEMU writes its
        # serial/intlog fixture and exits; this stub never starts a real guest.
        self.fixture.write_tool("timeout", '#!/bin/bash\nshift\n"$@"\nexit 124\n')
        with mock.patch.dict(os.environ, {"ZERO_OS_STRICT_TESTS": "1" if strict else "0"}):
            return self.fixture.run_gate("perf_regression_test.sh", serial)

    def test_missing_performance_measurements_are_qualified_or_strict_fail(self):
        for strict, expected in ((False, 3), (True, 1)):
            with self.subTest(strict=strict):
                result = self.run_performance(gate_fixture.CLEAN, strict)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertRegex(result.stdout, r"Passed:\s+0\b")
                self.assertRegex(result.stdout, r"Deferred:\s+6\b")
                self.assertNotIn("PERF-TEST PASS:", result.stdout)

    def test_performance_panic_remains_failure(self):
        result = self.run_performance(gate_fixture.CLEAN + "KERNEL PANIC\n", False)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("PERF-TEST PASS:", result.stdout)

    def test_final_caller_status_disambiguates_parser_json(self):
        disk = self.fixture.work / "attached disk.img"
        disk.write_bytes(b"synthetic disk fixture; no real disk is used")
        environment = {
            "ZERO_OS_STRICT_TESTS": "0",
            "KERNEL_TEST_DISK": self.fixture.shell_path(disk),
            "KERNEL_TEST_KEEP_LOGS": "1",
        }
        for has_probe, expected in ((False, 1), (True, 0)):
            with self.subTest(has_probe=has_probe), mock.patch.dict(os.environ, environment):
                before = set((self.fixture.work / "tmp").glob("*.counts.json"))
                serial = gate_fixture.CLEAN
                if has_probe:
                    serial += "R180-6 production JBD2 write path passed\n"
                    serial += "KSA-019-BLOCK PASS sector_bytes=512 sector=126 capacity_sectors=128 restored=exact\n"
                result = self.fixture.run_gate("kernel_test.sh", serial)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                produced = set((self.fixture.work / "tmp").glob("*.counts.json")) - before
                self.assertEqual(len(produced), 1, result.stdout + result.stderr)
                counts_path = produced.pop()
                evidence = json.loads(counts_path.read_text(encoding="utf-8"))
                self.assertEqual(evidence["status"], 0)
                self.assertIn("serial-and-process-policy", evidence["scope"])
                final_path = counts_path.with_name(
                    counts_path.name.removesuffix(".counts.json") + ".gate.status"
                )
                self.assertEqual(int(final_path.read_text().strip()), expected)
                if expected:
                    self.assertNotIn("KERNEL-TEST OK:", result.stdout)

    def test_musl_requires_complete_guest_and_bounded_process_evidence(self):
        tls_cases = [
            f"MUSL-TLS-IRQ-CASE-PASS phase={phase} cpu={cpu} "
            "fs_cookie=4653544c53000001 gs_cookie=4753544c53000001 checks=100"
            for phase, cpu in ((2, 2), (3, 1), (4, 2), (5, 1))
        ]
        tls_done = "MUSL-TLS-IRQ-OK migrations=4"
        markers = [
            "42 * 2 = 84", "MUSL-POLL-OK", "MUSL-SOCKET-ZERO-OK", "MUSL-STAT-OK",
            "MUSL-UNAME-OK", "MUSL-SHARED-MMAP-OK", "MUSL-STANDARD-FD-OK", "MUSL-OPEN-TRUNC-OK",
            "MUSL-ROBUST-USERCOPY-OK", "MUSL-WAIT-NAMESPACE-OK",
            "MUSL-BLOCKED-SIGNAL-OK", "MUSL-FCNTL-LIMIT-OK",
            *tls_cases, tls_done,
            "MUSL-VFS-PIVOT-OK scope=transaction-fork-namespaces-descriptors-repeat",
            "MUSL-VFS-CONTEXT-OK scope=cwd-components-dac-ids-chroot",
            "musl libc test passed!",
            "MUSL-EXIT-IDLE-OK cases=6",
            *[f"KSA-013-CASE PASS case={case}" for case in ("regular", "pipe", "socket", "nofile")],
        ]
        serial = "\n".join(markers + ["Process 1 terminated with exit code 0"]) + "\n"
        scenarios = [(serial, {}, 0), (serial, {"qemu_status": 0}, 1),
                     (serial, {"timeout_stderr": gate_fixture.TERM + "timeout: sending signal KILL to command\n"}, 1),
                     (serial + "MUSL-FCNTL-LIMIT-FAIL\n", {}, 1)]
        scenarios.extend((serial.replace(marker + "\n", ""), {}, 1) for marker in markers)
        pivot = "MUSL-VFS-PIVOT-OK scope=transaction-fork-namespaces-descriptors-repeat"
        context = "MUSL-VFS-CONTEXT-OK scope=cwd-components-dac-ids-chroot"
        for marker in (pivot, context):
            scenarios.extend((content, {}, 1) for content in (
                serial + marker + "\n",
                serial.replace(marker, marker + " malformed"),
                marker + "\n" + serial.replace(marker + "\n", ""),
                serial.replace(marker + "\n", "") + marker + "\n",
            ))
        scenarios.extend((content, {}, 1) for content in (
            serial.replace(pivot + "\n" + context, context + "\n" + pivot),
            serial.replace(pivot, "MUSL-VFS-PIVOT-DEFERRED reason=pending"),
            serial + "MUSL-VFS-PIVOT-DEFERRED reason=pending\n",
            serial + tls_cases[0] + "\n",
            serial + tls_done + "\n",
            serial.replace("cpu=2", "cpu=1"),
            serial.replace("cpu=2", "cpu=4"),
            serial.replace("fs_cookie=4653544c53000001", "fs_cookie=4653544c53000002"),
            serial.replace("gs_cookie=4753544c53000001", "gs_cookie=0"),
            serial.replace("checks=100", "checks=0"),
            serial.replace(tls_cases[0] + "\n" + tls_cases[1], tls_cases[1] + "\n" + tls_cases[0]),
            tls_done + "\n" + serial.replace(tls_done + "\n", ""),
            serial.replace(tls_done, "MUSL-TLS-IRQ-SKIP reason=requires-three-cpus"),
        ))
        with mock.patch.dict(os.environ, {"MUSL_CHECK_CPUS": "4", "MUSL_CHECK_TIMEOUT": "1"}):
            for content, parameters, expected in scenarios:
                with self.subTest(content=content, parameters=parameters):
                    result = self.fixture.run_gate("musl_check.sh", content, **parameters)
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    if expected:
                        self.assertNotIn("MUSL-CHECK OK:", result.stdout)

        up_serial = serial.replace(tls_done, "MUSL-TLS-IRQ-SKIP reason=requires-three-cpus")
        for case in tls_cases:
            up_serial = up_serial.replace(case + "\n", "")
        with mock.patch.dict(os.environ, {"MUSL_CHECK_CPUS": "1", "MUSL_CHECK_TIMEOUT": "1"}):
            for content, expected in ((up_serial, 0), (up_serial + tls_cases[0] + "\n", 1),
                                      (up_serial.replace("requires-three-cpus", "unavailable"), 1),
                                      (up_serial + "MUSL-TLS-IRQ-SKIP reason=unavailable\n", 1),
                                      (up_serial + "MUSL-TLS-IRQ-SKIP reason=requires-three-cpus\n", 1)):
                result = self.fixture.run_gate("musl_check.sh", content)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)


class RecordedGateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="outcome-recorder-")
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        (self.work / "scripts" / "ci").mkdir(parents=True)
        (self.work / "scripts" / "gates" / "qemu").mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts" / "ci" / "record_gate.py", self.work / "scripts" / "ci" / "record_gate.py")
        shutil.copyfile(ROOT / "scripts" / "gates" / "qemu" / "qemu_fuzz_smoke.py", self.work / "scripts" / "gates" / "qemu" / "qemu_fuzz_smoke.py")
        self.source = self.work / "source.txt"
        self.source.write_bytes(b"synthetic input revision\n")
        self.manifest = self.work / "inputs.sha256"
        self.manifest.write_text(
            hashlib.sha256(self.source.read_bytes()).hexdigest() + "  source.txt\n",
            encoding="utf-8",
        )
        self.kernel = self.work / "esp" / "kernel.elf"
        self.kernel.parent.mkdir()
        self.kernel.write_bytes(b"synthetic kernel image\n")
        self.artifacts = self.work / "artifacts"

    def run_recorder(self, command, *, allow_qualified=False, strict=False):
        before = set(self.artifacts.glob("run-*"))
        environment = os.environ.copy()
        # The recorder probes tool versions; make unavailable tools deterministic
        # without launching QEMU/rustup or depending on the host toolchain.
        environment["PATH"] = str(self.work / "unavailable-tools")
        environment["ZERO_OS_STRICT_TESTS"] = "1" if strict else "0"
        result = subprocess.run(
            [sys.executable, "-B", "-X", "utf8",
             str(self.work / "scripts" / "ci" / "record_gate.py"),
             "--artifacts", str(self.artifacts),
             "--input-manifest", str(self.manifest),
             "--revision", "synthetic-review-revision",
             *(["--allow-qualified"] if allow_qualified else []), "--", *command],
            env=environment, capture_output=True, text=True, encoding="utf-8", timeout=10,
        )
        produced = set(self.artifacts.glob("run-*")) - before
        self.assertEqual(len(produced), 1, result.stdout + result.stderr)
        output = produced.pop()
        summary = json.loads((output / "result.json").read_text(encoding="utf-8"))
        return result, output, summary

    def test_diagnostic_ci_accepts_only_qualified_and_preserves_gate_status(self):
        for strict in (False, True):
            for status in (0, 1, 2, 3, 7):
                with self.subTest(strict=strict, status=status):
                    command = [sys.executable, "-c", f"raise SystemExit({status})"]
                    result, output, summary = self.run_recorder(
                        command, allow_qualified=True, strict=strict)
                    accepted = status == 3 and not strict
                    self.assertEqual(result.returncode, 0 if accepted else status)
                    self.assertEqual(summary["status"], status)
                    self.assertEqual(summary["command_status"], status)
                    self.assertEqual(summary["qualified_accepted"], accepted)
                    self.assertEqual((output / "gate.status").read_text().strip(), str(status))
                    if accepted:
                        self.assertIn("strict qualification remains open", result.stdout)
                    self.assert_archive(output)

    def assert_archive(self, output):
        index = json.loads((output / "artifacts.sha256.json").read_text(encoding="utf-8"))
        for name in ("command.json", "gate.status", "result.json"):
            self.assertIn(name, index)
        for name, digest in index.items():
            self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), digest, name)

    def test_exit_statuses_logs_inputs_and_hashes_are_retained(self):
        child = (
            "import os,sys; from pathlib import Path; "
            "Path(os.environ['TMPDIR']).joinpath('caller.gate.status').write_text(sys.argv[1]); "
            "print('synthetic stdout'); print('synthetic stderr',file=sys.stderr); "
            "sys.exit(int(sys.argv[1]))"
        )
        for status in (0, 1, 2, 3):
            with self.subTest(status=status):
                command = [sys.executable, "-B", "-c", child, str(status)]
                result, output, summary = self.run_recorder(command)
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                self.assertEqual(summary["status"], status)
                self.assertIsNone(summary["error"])
                self.assertEqual((output / "gate.status").read_text().strip(), str(status))
                self.assertEqual(json.loads((output / "command.json").read_text()), command)
                log = (output / "gate.log").read_text()
                self.assertIn("synthetic stdout", log)
                self.assertIn("synthetic stderr", log)
                identity = json.loads((output / "inputs.json").read_text())
                self.assertEqual(identity["revision"], "synthetic-review-revision")
                self.assertEqual(identity["input_manifest_sha256"], hashlib.sha256(self.manifest.read_bytes()).hexdigest())
                self.assertEqual(identity["profile_environment"]["KERNEL_TEST_KEEP_LOGS"], "1")
                after = json.loads((output / "binaries-after.json").read_text())
                self.assertEqual(after["esp/kernel.elf"], hashlib.sha256(self.kernel.read_bytes()).hexdigest())
                self.assertEqual(after, identity["binaries_before"])
                self.assertEqual((output / "logs" / "caller.gate.status").read_text(), str(status))
                self.assert_archive(output)

    def test_command_failure_output_is_retained(self):
        command = [sys.executable, "-B", "-c", "import sys; print('deliberate failure'); sys.exit(17)"]
        result, output, summary = self.run_recorder(command)
        self.assertEqual(result.returncode, 17, result.stdout + result.stderr)
        self.assertEqual(summary["status"], 17)
        self.assertIn("deliberate failure", (output / "gate.log").read_text())
        self.assert_archive(output)

    def test_missing_command_is_incomplete_and_retained(self):
        result, output, summary = self.run_recorder([str(self.work / "absent-command")])
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(summary["status"], 2)
        self.assertTrue(summary["error"])
        self.assert_archive(output)

    def test_manifest_mismatch_prevents_command_execution(self):
        self.source.write_bytes(b"changed after the input manifest\n")
        marker = self.work / "must-not-exist"
        command = [sys.executable, "-B", "-c",
                   "import sys; from pathlib import Path; Path(sys.argv[1]).write_text('ran')",
                   str(marker)]
        result, output, summary = self.run_recorder(command)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse(marker.exists())
        self.assertIn("source manifest mismatch", summary["error"])
        self.assert_archive(output)

    def test_capture_failure_cannot_report_a_complete_gate(self):
        child = (
            "import os; from pathlib import Path; "
            "Path(os.environ['TMPDIR']).parent.joinpath('binaries-after.json').mkdir()"
        )
        result, output, summary = self.run_recorder([sys.executable, "-B", "-c", child])
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotEqual(summary["status"], 0)
        self.assertTrue(summary["error"])
        self.assert_archive(output)


if __name__ == "__main__":
    unittest.main()
