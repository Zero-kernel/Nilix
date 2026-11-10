#!/usr/bin/env python3
"""Regressions for owned outcomes, aggregation and strict qualification."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.ci import gate_log
from scripts.tests.gate_log_test import CLEAN, SUMMARY, PID1, check


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



def scoped_serial(status, scope):
    """Five passes plus one STRICT-Q declared-scope case (`test_5`)."""
    counts = dict(passed=5, warning=0, deferred=0, skipped=0, failed=0, not_applicable=0, out_of_scope=0, covered=0)
    counts[status] += 1
    cases = [f'RUNTIME-CASE name=test_{number} status=pass scope=in_scope owner=kernel::fixture::Test reason=""'
             for number in range(5)]
    cases.append(f'RUNTIME-CASE name=test_5 status={status} scope={scope} owner=kernel::fixture::Test '
                 'reason="needs 2 online CPUs; 1 online"')
    legacy = "=== Test Summary: 5 passed, 0 deferred (see per-test reasons), 0 failed ==="
    totals = "RUNTIME-COUNTS " + " ".join(f"{key}={value}" for key, value in counts.items())
    security_cases = [f'SECURITY-CASE name=security_{number} status=pass scope=in_scope owner=security::Test reason=""'
                      for number in range(9)]
    security = "\n".join([*security_cases, "SECURITY-COUNTS passed=9 warning=0 deferred=0 skipped=0 failed=0 "
                                            "not_applicable=0 out_of_scope=0 covered=0"])
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
        from scripts.gates.stress.stress_protocol import StressProtocolError, validate_runtime_evidence
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


    def test_declared_scope_is_qualified_unless_strict_lists_it(self):
        entry = ("RUNTIME", "test_5", "not_applicable", "needs_cpus:2")
        text = scoped_serial("not_applicable", "needs_cpus:2")
        result = check(text)
        self.assertEqual(result.status, 3, result.reasons)
        self.assertEqual(result.details["suites"]["RUNTIME"]["not_applicable"], 1)
        listed = check(text, strict=True, strict_scope=frozenset({entry}))
        self.assertEqual(listed.status, 0, listed.reasons)
        self.assertIn("STRICT PASS", listed.render())
        unlisted = check(text, strict=True, strict_scope=frozenset())
        self.assertEqual(unlisted.status, 1)
        self.assertIn("undeclared scope RUNTIME test_5 not_applicable needs_cpus:2", " ".join(unlisted.reasons))
        # Every field of the tuple is binding.
        for other in (("RUNTIME", "test_5", "not_applicable", "needs_cpus:4"),
                      ("SECURITY", "test_5", "not_applicable", "needs_cpus:2"),
                      ("RUNTIME", "test_4", "not_applicable", "needs_cpus:2")):
            with self.subTest(other=other):
                self.assertEqual(check(text, strict=True, strict_scope=frozenset({other})).status, 1)

    def test_listed_scope_never_excuses_other_qualifications(self):
        entry = ("RUNTIME", "test_5", "out_of_scope", "out_of_scope:N6")
        text = scoped_serial("out_of_scope", "out_of_scope:N6") + "[WARN] unavailable\n"
        self.assertEqual(check(text, strict=True, strict_scope=frozenset({entry})).status, 1)

    def test_declared_scope_status_needs_its_own_scope(self):
        for status, scope in (("not_applicable", "out_of_scope:N6"), ("out_of_scope", "needs_cpus:2"),
                              ("covered", "in_scope")):
            with self.subTest(status=status, scope=scope):
                self.assertEqual(check(scoped_serial(status, scope)).status, 2)
        missing = scoped_serial("out_of_scope", "out_of_scope:N6").replace(" scope=out_of_scope:N6", "")
        self.assertEqual(check(missing).status, 2)

    def test_declared_scope_counts_reconcile(self):
        text = scoped_serial("covered", "covered_by:ring3-mm")
        self.assertEqual(check(text).status, 3)
        self.assertEqual(check(text.replace("covered=1", "covered=0")).status, 2)
        self.assertEqual(check(text.replace(" not_applicable=0 out_of_scope=0 covered=1", "")).status, 2)

    def test_strict_scope_list_is_well_formed(self):
        entries = gate_log.load_strict_scope()
        self.assertTrue(entries)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.txt"
            for bad in ("RUNTIME smp_online deferred needs_cpus:2", "RUNTIME smp_online not_applicable out_of_scope:N6",
                        "BOOT smp_online not_applicable needs_cpus:2", "RUNTIME smp_online not_applicable",
                        "RUNTIME a not_applicable needs_cpus:2\nRUNTIME a not_applicable needs_cpus:2"):
                with self.subTest(bad=bad):
                    path.write_text(bad + "\n", encoding="utf-8")
                    with self.assertRaises(ValueError):
                        gate_log.load_strict_scope(path)

    def test_stress_runtime_evidence_applies_the_strict_scope(self):
        from scripts.gates.stress.stress_protocol import StressProtocolError, validate_runtime_evidence
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "serial.log"
            path.write_text(scoped_serial("not_applicable", "needs_cpus:2"), encoding="utf-8")
            with patch.dict(os.environ, {"ZERO_OS_STRICT_TESTS": "0"}):
                self.assertEqual(validate_runtime_evidence(path)["status"], "qualified")
            with patch.dict(os.environ, {"ZERO_OS_STRICT_TESTS": "1"}):
                with self.assertRaisesRegex(StressProtocolError, "undeclared scope"):
                    validate_runtime_evidence(path)

if __name__ == "__main__":
    unittest.main()
