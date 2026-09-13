#!/usr/bin/env python3
"""Regression fixtures for boot/SMP/IOMMU gate truth; no guest execution."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.ci import gate_log


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "scripts" / "fixtures" / "gate_logs"
CLEAN = (FIXTURES / "clean-smp.serial").read_text(encoding="utf-8")
FAILED = (FIXTURES / "failed-netns-rx-pool.serial").read_text(encoding="utf-8")
QUALIFIED = (FIXTURES / "qualified-smp.serial").read_text(encoding="utf-8")
Q35_FAILED = (FIXTURES / "failed-q35-active.serial").read_text(encoding="utf-8")
SUMMARY = "=== Test Summary: 6 passed, 0 deferred (awaiting syscall infrastructure), 0 failed ==="
PID1 = "Process 1 exited with code 0"
TERM = "timeout: sending signal TERM to command 'bash'\n"
IOMMU = "      ✓ IOMMU active: 1 unit(s), DMA translation enabled\n      - IOMMU enabled: true\n"


def check(serial: str = CLEAN, **overrides: object) -> gate_log.GateResult:
    inputs = dict(serial=serial, interrupts="", qemu_stderr="", timeout_stderr=TERM, qemu_status=124)
    inputs.update(overrides)
    return gate_log.evaluate(**inputs)


class ParserTests(unittest.TestCase):
    def test_clean_fixture(self):
        result = check()
        self.assertEqual(result.status, 0)
        self.assertEqual(result.counts, (6, 0, 0))
        self.assertIn("PASS (diagnostic)", result.render())

    def test_observed_failure_shape(self):
        result = check(FAILED)
        self.assertEqual(result.status, 1)
        self.assertEqual(result.counts, (37, 36, 1))
        self.assertEqual(check(CLEAN.replace("0 failed", "1 failed")).status, 1)

    def test_fail_marker_cannot_be_overridden_by_clean_summary(self):
        self.assertEqual(check(FAILED.replace("1 failed", "0 failed")).status, 1)

    def test_missing_malformed_duplicate_or_empty_summary(self):
        for replacement in (
            "", "Test Summary", SUMMARY[:-4], SUMMARY + " trailing junk",
            SUMMARY.replace("6 passed", "-1 passed"), SUMMARY.replace("0 failed", "NaN failed"),
            SUMMARY.replace("0 failed", "0 failed, 1 failed"), SUMMARY + "\n" + SUMMARY,
            SUMMARY.replace("6 passed", "0 passed"),
        ):
            with self.subTest(replacement=replacement):
                self.assertEqual(check(CLEAN.replace(SUMMARY, replacement)).status, 2)

    def test_failed_then_clean_summary_remains_failed(self):
        self.assertEqual(check(FAILED + SUMMARY + "\n").status, 1)

    def test_pid1_must_be_exact_unique_success_after_summary(self):
        self.assertEqual(check(CLEAN.replace(PID1, "/ nilix# " + PID1)).status, 0)
        for replacement in ("", "Process 1 exited", PID1 + "0", PID1 + " trailing", PID1 + "\n" + PID1):
            with self.subTest(replacement=replacement):
                self.assertNotEqual(check(CLEAN.replace(PID1, replacement)).status, 0)
        self.assertEqual(check(CLEAN.replace(PID1, "Process 1 exited with code 7")).status, 1)
        self.assertEqual(check(PID1 + "\n" + CLEAN.replace(PID1, "")).status, 2)

    def test_early_boot_markers_are_not_completion(self):
        self.assertEqual(check("Hello from Ring 3\nAll Component Tests Passed\n进入空闲循环\n").status, 2)

    def test_fatal_markers_win_before_and_after_completion(self):
        for marker in (
            "KERNEL PANIC", "panicked at kernel/src/main.rs", "[PF ENTRY] CR2=0xfed90038",
            "[PAGE FAULT]", "[DOUBLE FAULT]", "[GPF]", "[#UD]", "Triple fault", "[FATAL]",
        ):
            for serial in (marker + "\n" + CLEAN, CLEAN + marker + "\n"):
                with self.subTest(marker=marker, serial=serial):
                    self.assertEqual(check(serial).status, 1)
        self.assertEqual(check(qemu_stderr="KERNEL PANIC").status, 1)

    def test_interrupt_faults_win_over_success(self):
        for marker in (
            "  12: v=0e e=0011 i=0 cpl=0 IP=0008:ffffffff80001000",
            "  12: v=06 e=0000 i=0 cpl=0 IP=0008:ffffffff80001000",
            "  12: v=0d e=0000 i=0 cpl=0 IP=0008:0000000000008001",
            "  12: v=08 e=0000 i=0 cpl=0 IP=0008:ffffffff80001000",
            "cpu_reset", "Triple fault",
        ):
            with self.subTest(marker=marker):
                self.assertEqual(check(interrupts=marker).status, 1)

    def test_firmware_reset_and_exception_banners_are_not_kernel_faults(self):
        self.assertEqual(check(interrupts="CPU Reset (CPU 0)\n0: v=0e e=0000 i=0 cpl=0 IP=0038:0000000010000000\n").status, 0)

    def test_deferred_warnings_and_skips_are_qualified_not_passed(self):
        for serial in (
            QUALIFIED, CLEAN.replace("0 deferred", "39 deferred"),
            CLEAN + "WARNING: security checks unavailable\n", CLEAN + "[WARN] check unavailable\n",
            CLEAN + "[SKIP] missing prerequisite\n", CLEAN + "DEFERRED: security check\n",
            CLEAN + "Total: 7 tests, 6 passed, 1 warnings, 0 failed\n",
        ):
            with self.subTest(serial=serial):
                result = check(serial)
                self.assertEqual(result.status, 3)
                self.assertIn("QUALIFIED", result.render())
                self.assertNotIn("STRICT PASS", result.render())
        self.assertEqual(check(QUALIFIED + "KERNEL PANIC\n").status, 1)
        self.assertEqual(check(QUALIFIED.replace(PID1, "")).status, 2)

    def test_process_contract_cannot_be_overridden_by_guest_success(self):
        for qemu_status in (0, 1, 2, 137, 139, 143):
            with self.subTest(qemu_status=qemu_status):
                self.assertEqual(check(qemu_status=qemu_status).status, 1)
        for timeout_stderr in ("", TERM + TERM, TERM + "timeout: sending signal KILL to command 'bash'\n"):
            self.assertEqual(check(timeout_stderr=timeout_stderr).status, 1)
        for qemu_status in (125, 126, 127):
            self.assertEqual(check(qemu_status=qemu_status).status, 2)
            self.assertEqual(check(FAILED, qemu_status=qemu_status).status, 1)

    def test_crlf_transport(self):
        self.assertEqual(check(CLEAN.replace("\n", "\r\n")).status, 0)

    def test_q35_requires_actual_activation_and_enabled_state(self):
        self.assertEqual(check(IOMMU + CLEAN, require_iommu=True).status, 0)
        for marker in ("", IOMMU.replace("1 unit", "0 unit"), IOMMU.replace("true", "false"), IOMMU + IOMMU):
            with self.subTest(marker=marker):
                self.assertEqual(check(marker + CLEAN, require_iommu=True).status, 1)
        self.assertEqual(check(CLEAN + IOMMU, require_iommu=True).status, 1)
        self.assertEqual(check(IOMMU + CLEAN + "IOMMU initialization FAILED\n", require_iommu=True).status, 1)
        self.assertEqual(check(IOMMU + QUALIFIED, require_iommu=True).status, 3)

    def test_parent_q35_active_boot_with_failed_summary_is_rejected(self):
        result = check(Q35_FAILED, require_iommu=True)
        self.assertEqual(result.status, 1)
        self.assertEqual(result.counts, (28, 45, 1))
        self.assertIn("runtime Test Summary reports failed=1", result.reasons)


class CommandTests(unittest.TestCase):
    def test_cli_exit_codes_and_missing_evidence(self):
        with tempfile.TemporaryDirectory(prefix="gate-cli-") as directory:
            work = Path(directory)
            paths = [work / name for name in ("serial", "interrupts", "qemu.stderr", "timeout.stderr")]
            for path, text in zip(paths, (CLEAN, "", "", TERM)):
                path.write_text(text, encoding="utf-8")
            command = [sys.executable, str(ROOT / "scripts" / "ci" / "gate_log.py")]
            for option, path in zip(("--serial", "--intlog", "--qemu-stderr", "--timeout-stderr"), paths):
                command.extend([option, str(path)])
            command.extend(["--qemu-status", "124"])
            for serial, status in ((CLEAN, 0), (FAILED, 1), ("", 2), (QUALIFIED, 3)):
                paths[0].write_text(serial, encoding="utf-8")
                result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=10)
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
            paths[0].write_text(CLEAN, encoding="utf-8")
            paths[1].unlink()
            result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=10)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("cannot read", result.stdout)


@unittest.skipUnless(shutil.which("bash"), "bash is required for shell caller tests")
class ShellTests(unittest.TestCase):
    scripts = (
        "kernel_test.sh", "boot_check.sh", "smp_test.sh", "smp_test_4core.sh",
        "extended_smp_test.sh", "iommu_q35_check.sh",
    )
    script_locations = {
        "kernel_test.sh": Path("gates/boot/kernel_test.sh"),
        "boot_check.sh": Path("gates/boot/boot_check.sh"),
        "smp_test.sh": Path("gates/boot/smp_test.sh"),
        "smp_test_4core.sh": Path("gates/boot/smp_test_4core.sh"),
        "extended_smp_test.sh": Path("gates/boot/extended_smp_test.sh"),
        "iommu_q35_check.sh": Path("gates/qemu/iommu_q35_check.sh"),
        "musl_check.sh": Path("gates/boot/musl_check.sh"),
        "perf_regression_test.sh": Path("gates/performance/perf_regression_test.sh"),
    }

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="gate-shell-")
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        for name in ("scripts", "esp", "bin", "tmp"):
            (self.work / name).mkdir()
        for relative in (Path("ci/gate_log.py"), Path("ci/gate_inputs.py")):
            destination = self.work / "scripts" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "scripts" / relative, destination)
        for name, relative in self.script_locations.items():
            destination = self.work / "scripts" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "scripts" / relative, destination)
        (self.work / "esp" / "kernel.elf").write_bytes(b"synthetic kernel placeholder")
        (self.work / "esp/EFI/BOOT").mkdir(parents=True)
        (self.work / "esp/EFI/BOOT/BOOTX64.EFI").write_bytes(b"synthetic bootloader")
        (self.work / "esp/NvVars").write_bytes(b"stale firmware state")
        (self.work / "firmware.fd").write_bytes(b"synthetic firmware placeholder")
        self.write_tool("python3", '#!/bin/bash\nexec "$GATE_PYTHON" "$@"\n')
        self.write_tool("timeout", """#!/bin/bash
while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
if [ "$#" -lt 3 ]; then exit 125; fi
shift 2
"$@"
command_status=$?
if [ "$command_status" -ne 0 ]; then exit "$command_status"; fi
cat "$GATE_TIMEOUT_LOG" >&2
exit "${GATE_STATUS:-124}"
""")
        self.write_tool("qemu-system-x86_64", r"""#!/bin/bash
if [ "${1:-}" = --version ]; then printf "fixture QEMU version\n"; exit 0; fi
serial=''
intlog=''
cpus=1
printf '%s\n' "$@" >"$GATE_ARGUMENTS"
while [ "$#" -gt 0 ]; do
    case "$1" in
        -serial) serial="${2#file:}"; shift 2 ;;
        -D) intlog="$2"; shift 2 ;;
        -smp) cpus="$2"; shift 2 ;;
        *) shift ;;
    esac
done
if [ -z "$serial" ] || [ -z "$intlog" ]; then exit 4; fi
aps=$((cpus - 1))
fixture="$GATE_SERIAL"
if [ "$cpus" -eq 16 ] && [ -n "${GATE_SERIAL_16:-}" ]; then fixture="$GATE_SERIAL_16"; fi
sed -e "s/4 CPU(s) online/$cpus CPU(s) online/" \
    -e "s/3\/3 APs acknowledged/$aps\/$aps APs acknowledged/" "$fixture" >"$serial"
cat "$GATE_INTLOG" >"$intlog"
printf 'synthetic QEMU stderr retained\n' >&2
exit 0
""")

    def write_tool(self, name: str, text: str):
        path = self.work / "bin" / name
        path.write_text(text, encoding="utf-8", newline="\n")
        path.chmod(0o755)

    def shell_path(self, path: Path) -> str:
        if os.name == "nt":
            converter = Path(shutil.which("bash")).with_name("cygpath.exe")
            return subprocess.check_output([str(converter), "-u", str(path)], text=True).strip()
        return str(path)

    def run_gate(
        self, name: str, serial: str = CLEAN, *, qemu_status: int = 124,
        interrupts: str = "", timeout_stderr: str = TERM, iommu: bool = True,
        second_serial: str | None = None,
    ) -> subprocess.CompletedProcess:
        if name == "iommu_q35_check.sh" and iommu:
            serial = IOMMU + serial
        if name == "extended_smp_test.sh":
            serial = serial.replace(
                "=== Test Summary:",
                "  [TEST] ipi_ping_pong... PASS\n  [TEST] tlb_shootdown_coherency... PASS\n=== Test Summary:",
            ).replace("6 passed", "8 passed")
        for filename, text in (
            ("fixture.serial", serial), ("fixture.intlog", interrupts),
            ("fixture.timeout", timeout_stderr),
        ):
            (self.work / filename).write_text(text, encoding="utf-8", newline="\n")
        environment = os.environ.copy()
        environment.update({
            "PATH": os.pathsep.join((str(self.work / "bin"), str(Path(shutil.which("bash")).parent), environment["PATH"])),
            "GATE_PYTHON": self.shell_path(Path(sys.executable)),
            "PYTHONUTF8": "1",
            "GATE_SERIAL": self.shell_path(self.work / "fixture.serial"),
            "GATE_INTLOG": self.shell_path(self.work / "fixture.intlog"),
            "GATE_TIMEOUT_LOG": self.shell_path(self.work / "fixture.timeout"),
            "GATE_ARGUMENTS": self.shell_path(self.work / "qemu.arguments"),
            "GATE_STATUS": str(qemu_status),
            "OVMF_PATH": self.shell_path(self.work / "firmware.fd"),
            "TMPDIR": self.shell_path(self.work / "tmp"),
            "IOMMU_Q35_LOG_DIR": self.shell_path(self.work / "retained logs"),
            "BOOT_CHECK_TIMEOUT": "1", "KERNEL_TEST_TIMEOUT": "1", "SMP_TEST_TIMEOUT": "1",
            "SMP_4CORE_TEST_TIMEOUT": "1", "EXTENDED_SMP_TIMEOUT": "1", "IOMMU_Q35_TIMEOUT": "1",
            "BOOT_CHECK_KEEP_LOGS": "0", "SMP_TEST_KEEP_LOGS": "0", "SMP_4CORE_TEST_KEEP_LOGS": "0",
        })
        if second_serial is not None:
            (self.work / "second.serial").write_text(second_serial, encoding="utf-8", newline="\n")
            environment["GATE_SERIAL_16"] = self.shell_path(self.work / "second.serial")
        result = subprocess.run(
            [shutil.which("bash"), "--noprofile", "--norc",
             self.shell_path(self.work / "scripts" / self.script_locations[name])],
            env=environment, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
        self.assertNotIn("integer expression expected", result.stderr)
        return result

    def assert_gate(self, result: subprocess.CompletedProcess, expected: int):
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        if expected != 0:
            for banner in ("BOOT-CHECK OK", "SMP-TEST OK", "IOMMU-Q35-CHECK OK", "EXTENDED-SMP-TEST PASS"):
                self.assertNotIn(banner, result.stdout)

    def test_all_callers_propagate_summary_and_qualification_results(self):
        for name in self.scripts:
            for serial, expected in ((CLEAN, 0), (FAILED, 1), (CLEAN.replace(SUMMARY, ""), 2), (QUALIFIED, 3)):
                with self.subTest(script=name, expected=expected):
                    self.assert_gate(self.run_gate(name, serial), expected)

    def test_all_callers_reject_late_fatal_markers(self):
        for name in self.scripts:
            with self.subTest(script=name):
                self.assert_gate(self.run_gate(name, CLEAN + "KERNEL PANIC\n"), 1)

    def test_process_status_and_kill_escalation_reach_callers(self):
        for name in self.scripts:
            with self.subTest(script=name):
                self.assert_gate(self.run_gate(name, qemu_status=0), 1)
                self.assert_gate(self.run_gate(name, timeout_stderr=TERM + "timeout: sending signal KILL to command 'bash'\n"), 1)

    def test_smp_topology_and_ordering_still_fail_closed(self):
        for name in ("smp_test.sh", "smp_test_4core.sh"):
            for serial in (
                CLEAN.replace("4 CPU(s) online", "1 CPU(s) online"),
                CLEAN.replace("smp_online... PASS", "unrelated... PASS"),
                CLEAN.replace("r175_d0_cross_3_sched_atomic... PASS", "unrelated... PASS"),
                CLEAN.replace("[SMP] process-deferred gate complete: 3/3 APs acknowledged", ""),
            ):
                with self.subTest(script=name, serial=serial):
                    self.assert_gate(self.run_gate(name, serial), 1)

    def test_q35_requires_active_iommu_and_retains_all_evidence(self):
        result = self.run_gate("iommu_q35_check.sh", iommu=False)
        self.assert_gate(result, 1)
        result = self.run_gate("iommu_q35_check.sh")
        self.assert_gate(result, 0)
        directories = list((self.work / "retained logs").glob("iommu-q35.*"))
        self.assertEqual(len(directories), 2)
        for directory in directories:
            for filename in ("serial.log", "interrupts.log", "qemu.stderr", "timeout.stderr", "qemu.status", "gate.status", "gate.result"):
                self.assertTrue((directory / filename).is_file(), filename)
            self.assertIn("synthetic QEMU stderr retained", (directory / "qemu.stderr").read_text())
            self.assertEqual((directory / "qemu.status").read_text().strip(), "124")
        arguments = (self.work / "qemu.arguments").read_text()
        self.assertIn("-machine\nq35\n", arguments)
        self.assertIn("-device\nintel-iommu,intremap=on\n", arguments)

    def test_extended_aggregate_does_not_turn_qualified_into_pass(self):
        self.assert_gate(self.run_gate("extended_smp_test.sh", second_serial=QUALIFIED), 3)
        self.assert_gate(self.run_gate("extended_smp_test.sh", FAILED, second_serial=""), 1)

    def test_q35_active_and_pid1_success_do_not_override_failed_summary(self):
        result = self.run_gate("iommu_q35_check.sh", Q35_FAILED, iommu=False)
        self.assert_gate(result, 1)
        self.assertIn("runtime Test Summary reports failed=1", result.stdout)


if __name__ == "__main__":
    unittest.main()
