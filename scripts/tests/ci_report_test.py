import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

from scripts.ci.ci_report import aggregate, fuzz_report, report


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def receipt(self, name, status, accepted=False):
        path = self.root / name / 'run-one'
        path.mkdir(parents=True)
        (path / 'result.json').write_text(json.dumps({
            'status': status, 'command_status': status, 'qualified_accepted': accepted,
            'elapsed_seconds': 2.5, 'error': None}))
        return path

    def test_qualified_cases_are_not_reported_as_passing(self):
        path = self.receipt('runtime', 3, True)
        (path / 'guest.counts.json').write_text(json.dumps({'details': {'cases': [
            {'suite': 'RUNTIME', 'name': 'good', 'status': 'pass', 'owner': 'test::Good', 'reason': ''},
            {'suite': 'RUNTIME', 'name': 'pending', 'status': 'deferred', 'owner': 'test::Pending',
             'reason': 'requires <device> | unavailable'},
        ]}}))
        text = report(self.root)
        self.assertIn('| runtime | QUALIFIED | 3 |', text)
        self.assertIn('| RUNTIME | 1 | 0 | 1 | 0 | 0 |', text)
        self.assertIn('requires &lt;device&gt; &#124; unavailable', text)
        cases = ET.parse(self.root / 'gates.junit.xml').findall('.//testcase')
        self.assertEqual(len(cases), 3)
        self.assertIsNotNone(cases[0].find('skipped'))
        self.assertIsNotNone(cases[2].find('skipped'))

    def test_process_failure_overrides_successful_test_records(self):
        self.receipt('runtime', 1)
        self.receipt('missing-evidence', 2)
        self.receipt('build', 0)
        text = report(self.root)
        self.assertIn('| runtime | FAIL | 1 |', text)
        self.assertIn('| missing-evidence | INCOMPLETE | 2 |', text)
        self.assertEqual(len(ET.parse(self.root / 'gates.junit.xml').findall('.//failure')), 2)

    def test_every_required_job_must_succeed(self):
        for state in ('failure', 'cancelled', 'skipped', 'unknown'):
            with self.subTest(state=state):
                text, status = aggregate({'build': {'result': 'success'}, 'runtime': {'result': state}})
                self.assertEqual(status, 1)
                self.assertIn(state, text)
        self.assertEqual(aggregate({'build': {'result': 'success'}})[1], 0)
        with self.assertRaises(ValueError):
            aggregate({})

    def test_rust_test_names_and_failures_reach_junit(self):
        suites = self.root / 'suites'
        suites.mkdir()
        (suites / 'hosted-summary.tsv').write_text('mm\t1\t0\n')
        (suites / 'mm.log').write_text('test alloc::works ... ok\ntest failed::case ... FAILED\n')
        report(self.root)
        tree = ET.parse(suites / 'hosted.junit.xml')
        self.assertEqual([item.get('name') for item in tree.findall('.//testcase')],
                         ['alloc::works', 'failed::case'])
        self.assertEqual(len(tree.findall('.//failure')), 1)

    def test_guest_retry_events_are_visible_in_report(self):
        self.receipt('boot', 0)
        (self.root / 'retry.log').write_text(
            'CI-RETRY gate=boot attempt=1/2 status=2 action=retry\n'
            'CI-RETRY gate=boot attempt=2/2 status=0 action=recovered\n')
        text = report(self.root)
        self.assertIn('### Guest retry events', text)
        self.assertIn('attempt=1/2 status=2 action=retry', text)
        self.assertIn('attempt=2/2 status=0 action=recovered', text)

    def test_fuzz_report_rejects_missing_duplicate_or_malformed_public_results(self):
        needs = {'campaign': {'result': 'success'}}
        valid = 'Schema: nilix-fuzz-result-v1\nStatus: completed\nCandidate-Count: 2\n'
        first = self.root / 'one'
        first.mkdir()
        path = first / 'fuzz-result.txt'
        self.assertEqual(fuzz_report(self.root, 1, needs)[1], 1)
        path.write_text(valid)
        text, status = fuzz_report(self.root, 1, needs)
        self.assertEqual(status, 0)
        self.assertIn('2 opaque candidate(s)', text)
        for invalid in (valid + 'private reproducer\n', valid.replace('completed', 'incomplete'),
                        valid.replace('2', '-1'), valid + valid):
            path.write_text(invalid)
            text, status = fuzz_report(self.root, 1, needs)
            self.assertEqual(status, 1)
            self.assertNotIn('private reproducer', text)
        path.write_text(valid)
        second = self.root / 'two'
        second.mkdir()
        (second / 'fuzz-result.txt').write_text(valid)
        self.assertEqual(fuzz_report(self.root, 1, needs)[1], 1)


if __name__ == '__main__':
    unittest.main()
