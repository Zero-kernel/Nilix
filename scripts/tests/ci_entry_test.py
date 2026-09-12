"""Exercise group failure propagation without building or launching a VM."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Linux CI entrypoint')
class EntryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ci-entry-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        scripts = self.root / 'scripts'
        scripts.mkdir()
        ci = scripts / 'ci'
        ci.mkdir()
        shutil.copyfile(Path(__file__).resolve().parents[1] / 'ci' / 'entrypoint.sh', ci / 'entrypoint.sh')
        (ci / 'record_gate.py').write_text('''
import json, os, sys
from pathlib import Path
name = sys.argv[sys.argv.index('--name') + 1]
events = Path(os.environ['EVENTS'])
with events.open('a') as stream:
    stream.write(json.dumps(name) + '\\n')
base = name.split(' (retry', 1)[0]
attempt = sum(1 for line in events.read_text().splitlines()
              if json.loads(line).split(' (retry', 1)[0] == base)
if base == os.environ.get('FAIL_GATE') and attempt <= int(os.environ.get('FAIL_ATTEMPTS', '999')):
    raise SystemExit(int(os.environ.get('FAIL_STATUS', '7')))
raise SystemExit(0)
''')
        (ci / 'ci_report.py').write_text('''
import os, pathlib, sys
with open(os.environ['EVENTS'], 'a') as stream:
    stream.write('"report"\\n')
pathlib.Path(sys.argv[1], 'summary.md').write_text('current invocation')
raise SystemExit(int(os.environ.get('FAIL_REPORT', '0')))
''')

    def run_group(self, group, **environment):
        events = self.root / 'events.jsonl'
        result = subprocess.run(['bash', str(self.root / 'scripts/ci/entrypoint.sh'), group],
                                cwd=self.root, env={**os.environ, 'EVENTS': str(events), **environment},
                                capture_output=True, text=True, timeout=15)
        observed = [json.loads(line) for line in events.read_text().splitlines()]
        return result.returncode, observed

    def test_independent_failure_does_not_skip_checks_or_turn_success(self):
        status, events = self.run_group('quality', FAIL_GATE='lint')
        self.assertEqual(status, 1)
        self.assertEqual(events, ['lint', 'python', 'shell-syntax', 'report'])

    def test_build_failure_prevents_guest_launch_but_keeps_report(self):
        status, events = self.run_group('musl', FAIL_GATE='build')
        self.assertEqual(status, 7)
        self.assertEqual(events, ['build', 'report'])

    def test_report_failure_cannot_silently_complete_the_group(self):
        status, events = self.run_group('quality', FAIL_REPORT='1')
        self.assertEqual(status, 1)
        self.assertEqual(events[-1], 'report')

    def test_guest_failure_retries_once_and_recovers(self):
        status, events = self.run_group('runtime', FAIL_GATE='boot', FAIL_ATTEMPTS='1', FAIL_STATUS='1')
        self.assertEqual(status, 0)
        self.assertEqual(events, ['boot', 'boot (retry 1)', 'runtime', 'smp', 'report'])

    def test_guest_failure_after_retry_remains_a_failure(self):
        status, events = self.run_group('runtime', FAIL_GATE='boot', FAIL_ATTEMPTS='2', FAIL_STATUS='1')
        self.assertEqual(status, 1)
        self.assertEqual(events, ['boot', 'boot (retry 1)', 'runtime', 'smp', 'report'])

    def test_invalid_retry_setting_keeps_report_and_blocks(self):
        status, events = self.run_group('quality', CI_GUEST_RETRIES='2')
        self.assertEqual(status, 2)
        self.assertEqual(events, ['report'])

    def test_missing_stress_prerequisite_cannot_be_accepted_as_qualified(self):
        scripts = Path(__file__).resolve().parents[1]
        artifacts = self.root / 'stress-artifacts'
        result = subprocess.run(
            [sys.executable, str(scripts / 'ci' / 'record_gate.py'), '--allow-qualified',
             '--artifacts', str(artifacts), '--', 'bash', str(scripts / 'gates/stress/stress_test.sh')],
            env={**os.environ, 'STRESS_DURATION': '0'}, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        receipt = json.loads(next(artifacts.glob('run-*/result.json')).read_text())
        self.assertFalse(receipt['qualified_accepted'])
        self.assertIn('STRESS-TEST BLOCKED', next(artifacts.glob('run-*/gate.log')).read_text())


if __name__ == '__main__':
    unittest.main()
