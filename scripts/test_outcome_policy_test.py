#!/usr/bin/env python3
"""Regressions for owned outcomes, aggregation and strict qualification."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from gate_log_test import CLEAN, SUMMARY, PID1, check


def serial(status="pass", security_warning=0):
    cases = []
    counts = dict(passed=5, warning=0, deferred=0, skipped=0, failed=0)
    counts["passed" if status == "pass" else status] += 1
    for number in range(6):
        outcome = status if number == 5 else "pass"
        reason = "" if outcome == "pass" else "requires the specified fixture"
        cases.append(f'RUNTIME-CASE name=test_{number} status={outcome} owner=kernel::fixture::Test reason={json.dumps(reason)}')
    legacy = f'=== Test Summary: {counts["passed"]} passed, {counts["deferred"]} deferred (see per-test reasons), {counts["failed"]} failed ==='
    totals = "RUNTIME-COUNTS " + " ".join(f"{key}={value}" for key, value in counts.items())
    security_cases = [f'SECURITY-CASE name=security_{number} status={"warning" if number < security_warning else "pass"} owner=security::Test reason={json.dumps("CPU fixture unavailable" if number < security_warning else "")}' for number in range(9)]
    security = "\n".join([*security_cases, f"SECURITY-COUNTS passed={9-security_warning} warning={security_warning} deferred=0 skipped=0 failed=0"])
    return CLEAN.replace(SUMMARY, "\n".join([security, *cases, legacy, totals]))


class OutcomePolicyTests(unittest.TestCase):
    def test_strict_requires_current_structured_evidence(self):
        self.assertEqual(check(CLEAN, strict=True).status, 2)
        result = check(serial(), strict=True)
        self.assertEqual(result.status, 0, result.reasons)
        self.assertIn("STRICT PASS", result.render())

    def test_nonpasses_never_satisfy_strict_mode(self):
        for outcome in ("warning", "deferred", "skipped"):
            with self.subTest(outcome=outcome):
                result = check(serial(outcome))
                self.assertEqual(result.status, 3, result.reasons)
                self.assertEqual(result.details["suites"]["RUNTIME"]["passed"], 5)
                self.assertEqual(check(serial(outcome), strict=True).status, 1)
        self.assertEqual(check(serial("failed"), strict=True).status, 1)
        self.assertEqual(check(serial(security_warning=1), strict=True).status, 1)

    def test_deferrals_require_name_owner_and_reason(self):
        original = serial("deferred")
        for bad in (original.replace("owner=kernel::fixture::Test", "owner="),
                    original.replace('reason="requires the specified fixture"', 'reason=""'),
                    original.replace("name=test_5", "name=")):
            self.assertEqual(check(bad).status, 2)

    def test_missing_duplicate_late_or_contradictory_outcomes_fail_closed(self):
        original = serial()
        line = next(line for line in original.splitlines() if "name=test_5" in line)
        for bad in (original.replace(line + "\n", ""),
                    original.replace(line, line + "\n" + line),
                    original.replace(line + "\n", "") + line + "\n",
                    original.replace("RUNTIME-COUNTS passed=6", "RUNTIME-COUNTS passed=7"),
                    original.replace("RUNTIME-COUNTS passed=6", "RUNTIME-COUNTS passed=oops"),
                    original.replace(PID1, "RUNTIME-COUNTS passed=6 warning=0 deferred=0 skipped=0 failed=0\n" + PID1)):
            self.assertEqual(check(bad).status, 2)

    def test_security_failure_is_a_failure(self):
        broken = serial().replace("SECURITY-COUNTS passed=9 warning=0 deferred=0 skipped=0 failed=0",
                                  "SECURITY-COUNTS passed=8 warning=0 deferred=0 skipped=0 failed=1")
        self.assertEqual(check(broken).status, 1)

    def test_all_warning_suite_is_qualified(self):
        original = serial("warning")
        original = original.replace('status=pass owner=kernel::fixture::Test reason=""', 'status=warning owner=kernel::fixture::Test reason="measurement outside expected range"')
        original = original.replace("5 passed", "0 passed").replace("RUNTIME-COUNTS passed=5 warning=1", "RUNTIME-COUNTS passed=0 warning=6")
        self.assertEqual(check(original).status, 3)
        self.assertEqual(check(original, strict=True).status, 1)

    def test_counts_after_pid1_cannot_pass(self):
        original = serial()
        for prefix in ("RUNTIME-COUNTS", "SECURITY-COUNTS"):
            line = next(line for line in original.splitlines() if line.startswith(prefix))
            broken = original.replace(line + "\n", "") + line + "\n"
            self.assertEqual(check(broken, strict=True).status, 2)

    def test_security_cases_reconcile_and_keep_reasons(self):
        original = serial(security_warning=1)
        line = next(line for line in original.splitlines() if line.startswith("SECURITY-CASE"))
        for broken in (original.replace(line + "\n", ""), original.replace(line, line + "\n" + line), original.replace('reason="CPU fixture unavailable"', 'reason=""')):
            self.assertEqual(check(broken).status, 2)
        self.assertTrue(any(case["reason"] == "CPU fixture unavailable" for case in check(original).details["cases"]))

    def test_stress_summary_preserves_qualification_and_strict_policy(self):
        from stress_protocol import StressProtocolError, validate_runtime_evidence
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "serial.log"
            path.write_text(serial("deferred"), encoding="utf-8")
            with patch.dict(os.environ, {"ZERO_OS_STRICT_TESTS": "0"}):
                self.assertEqual(validate_runtime_evidence(path)["status"], "qualified")
            with patch.dict(os.environ, {"ZERO_OS_STRICT_TESTS": "1"}):
                with self.assertRaises(StressProtocolError):
                    validate_runtime_evidence(path)
                for marker in ("[WARN] unavailable", "[SKIPPED] missing fixture", "FAIL: security test failure"):
                    path.write_text(serial() + marker + "\n", encoding="utf-8")
                    with self.assertRaises(StressProtocolError):
                        validate_runtime_evidence(path)
            path.write_text(serial() + SUMMARY + "\n", encoding="utf-8")
            with self.assertRaises(StressProtocolError):
                validate_runtime_evidence(path)


if __name__ == "__main__":
    unittest.main()
