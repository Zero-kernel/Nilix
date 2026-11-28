#!/usr/bin/env python3
"""N2.2 (#66): unit tests for conformance lockfile, pass list, and gate parser."""
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from scripts.gates.conformance import conformance_gate as gate

ROOT = Path(__file__).resolve().parents[2]
LOCKFILE = ROOT / "scripts/conformance/third_party.lock"
PASSLIST = ROOT / "scripts/conformance/libc-test.pass"
REMOVED = ROOT / "scripts/conformance/libc-test.removed"
LTP_PASSLIST = ROOT / "scripts/conformance/ltp.pass"
LTP_REMOVED = ROOT / "scripts/conformance/ltp.removed"
FETCH_SH = ROOT / "scripts/conformance/fetch.sh"


class ConformanceLockfileTests(unittest.TestCase):
    def test_lockfile_has_pinned_sha256_entries(self):
        self.assertTrue(LOCKFILE.is_file(), "third_party.lock missing")
        entries = []
        for raw in LOCKFILE.read_text(encoding="utf-8").splitlines():
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            self.assertEqual(len(parts), 4, f"malformed lock entry: {raw}")
            suite, version, sha, url = parts
            self.assertRegex(version, r"^[0-9a-f]{40}$|^[A-Za-z0-9._-]+$")
            self.assertRegex(sha, r"^[0-9a-f]{64}$")
            self.assertTrue(url.startswith("https://"), f"non-HTTPS URL: {url}")
            self.assertNotIn("HEAD", url, "floating HEAD URL is forbidden in third_party.lock")
            entries.append(suite)
        self.assertIn("libc-test", entries)
        self.assertIn("ltp", entries)
        self.assertIn("busybox", entries)
        self.assertEqual(len(entries), len(set(entries)), "duplicate suite in third_party.lock")

    def test_fetch_rejects_sha256_mismatch_with_exit_2(self):
        with tempfile.TemporaryDirectory(prefix="conf-fetch-test-") as td:
            root = Path(td)
            downloads = root / "downloads"
            downloads.mkdir(parents=True)
            fake_lock = root / "bad.lock"
            fake_lock.write_text(
                "dummy deadbeef 0000000000000000000000000000000000000000000000000000000000000000 https://example.invalid/x.tar.gz\n",
                encoding="utf-8",
            )
            (downloads / "dummy-deadbeef.tar.gz").write_bytes(b"corrupted payload\n")
            proc = subprocess.run(
                ["bash", str(FETCH_SH), "dummy", str(root)],
                env={"PATH": "/usr/bin:/bin", "CONFORMANCE_LOCKFILE": str(fake_lock)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("sha256 mismatch", proc.stderr)


class ConformancePasslistTests(unittest.TestCase):
    def test_checked_in_libc_test_passlist_is_valid_and_nonempty(self):
        entries = gate.parse_passlist(PASSLIST)
        self.assertGreater(len(entries), 0, "libc-test.pass must record at least one passing case")
        removed = gate.parse_removed(REMOVED)
        overlap = set(entries) & set(removed)
        self.assertEqual(overlap, set(), f"cases present in both pass and removed: {overlap}")

    def test_checked_in_ltp_passlist_is_valid_and_nonempty(self):
        entries = gate.parse_passlist(LTP_PASSLIST)
        self.assertGreater(len(entries), 0, "ltp.pass must record at least one passing case")
        removed = gate.parse_removed(LTP_REMOVED)
        overlap = set(entries) & set(removed)
        self.assertEqual(overlap, set(), f"cases present in both ltp pass and removed: {overlap}")

    def test_passlist_rejects_wrong_count_unsorted_and_duplicates(self):
        with tempfile.TemporaryDirectory(prefix="conf-passlist-") as td:
            p = Path(td) / "test.pass"
            p.write_text("# count: 3\nalpha\nbeta\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not match actual entry count"):
                gate.parse_passlist(p)

            p.write_text("# count: 2\nbeta\nalpha\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must be sorted"):
                gate.parse_passlist(p)

            p.write_text("# count: 2\nalpha\nalpha\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate case name"):
                gate.parse_passlist(p)

            p.write_text("alpha\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "first line must be '# count: N'"):
                gate.parse_passlist(p)

    def test_removals_require_recorded_reasons(self):
        old = ["case_a", "case_b", "case_c"]
        new = ["case_a", "case_c"]
        self.assertEqual(gate.check_passlist_removals(old, new, {}), ["case_b"])
        self.assertEqual(
            gate.check_passlist_removals(old, new, {"case_b": "flaky upstream timer test"}),
            [],
        )


class ConformanceGateEvalTests(unittest.TestCase):
    def _sample_serial(self, cases: list[tuple[str, str, int]], extra: str = "") -> str:
        lines = [
            f"CONF-CASE suite=libc-test name={name} status={status} exit={rc}"
            for name, status, rc in cases
        ]
        n_pass = sum(1 for _, s, _ in cases if s == "PASS")
        n_fail = sum(1 for _, s, _ in cases if s == "FAIL")
        n_to = sum(1 for _, s, _ in cases if s == "TIMEOUT")
        n_ef = sum(1 for _, s, _ in cases if s == "EXECFAIL")
        lines.append(
            f"CONF-SUMMARY suite=libc-test total={len(cases)} pass={n_pass} "
            f"fail={n_fail} timeout={n_to} execfail={n_ef}"
        )
        if extra:
            lines.append(extra)
        lines.append("Process 1 exited with code 0")
        return "\n".join(lines) + "\n"

    def test_exact_match_passes(self):
        serial = self._sample_serial([("a", "PASS", 0), ("b", "FAIL", 1), ("c", "TIMEOUT", 137)])
        ev = gate.evaluate_conformance(serial, "libc-test", ["a"], ["a", "b", "c"])
        self.assertTrue(ev.ok)
        self.assertEqual(ev.passed, ("a",))
        self.assertEqual(ev.failed, ("b",))
        self.assertEqual(ev.timed_out, ("c",))
        self.assertEqual(ev.regressions, ())
        self.assertEqual(ev.new_passes, ())

    def test_regression_fails(self):
        serial = self._sample_serial([("a", "FAIL", 1), ("b", "PASS", 0)])
        ev = gate.evaluate_conformance(serial, "libc-test", ["a", "b"])
        self.assertFalse(ev.ok)
        self.assertEqual(ev.regressions, ("a",))

    def test_new_pass_must_be_added_to_passlist(self):
        serial = self._sample_serial([("a", "PASS", 0), ("b", "PASS", 0)])
        ev = gate.evaluate_conformance(serial, "libc-test", ["a"])
        self.assertFalse(ev.ok)
        self.assertEqual(ev.new_passes, ("b",))

    def test_removed_case_does_not_trip_new_pass_or_regression(self):
        serial_pass = self._sample_serial([("a", "PASS", 0), ("flaky", "PASS", 0)])
        ev_pass = gate.evaluate_conformance(serial_pass, "libc-test", ["a"], removed_names={"flaky"})
        self.assertTrue(ev_pass.ok)
        serial_to = self._sample_serial([("a", "PASS", 0), ("flaky", "TIMEOUT", 137)])
        ev_to = gate.evaluate_conformance(serial_to, "libc-test", ["a"], removed_names={"flaky"})
        self.assertTrue(ev_to.ok)

    def test_kernel_panic_fails_even_if_passlist_matches(self):
        serial = self._sample_serial([("a", "PASS", 0)], extra="KERNEL PANIC: boom")
        ev = gate.evaluate_conformance(serial, "libc-test", ["a"])
        self.assertFalse(ev.ok)
        self.assertTrue(any("fatal" in e for e in ev.errors))

    def test_missing_summary_or_manifest_case_fails(self):
        serial = "CONF-CASE suite=libc-test name=a status=PASS exit=0\nProcess 1 exited with code 0\n"
        ev = gate.evaluate_conformance(serial, "libc-test", ["a"], ["a", "b"])
        self.assertFalse(ev.ok)
        self.assertGreaterEqual(len(ev.errors), 2)


if __name__ == "__main__":
    unittest.main()
