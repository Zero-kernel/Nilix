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
        (self.root / 'esp').mkdir()
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
if 'INVOCATIONS' in os.environ:
    with open(os.environ['INVOCATIONS'], 'a') as stream:
        stream.write(json.dumps({'name': name, 'argv': sys.argv[1:],
                                 'strict': os.environ.get('ZERO_OS_STRICT_TESTS'),
                                 'mode': os.environ.get('QEMU_GATE_MODE')}) + '\\n')
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
        # The caller's own CI settings must not leak into the group under test:
        # an exported CI_GUEST_RETRIES=0 would disable the retry these tests pin.
        inherited = {key: value for key, value in os.environ.items()
                     if key not in ('CI_GUEST_RETRIES', 'CI_STRESS_PROFILE', 'CI_STRESS_CPUS',
                                    'CI_STRESS_SECONDS', 'QEMU_GATE_MODE',
                                    'ZERO_OS_STRICT_TESTS')}
        result = subprocess.run(['bash', str(self.root / 'scripts/ci/entrypoint.sh'), group],
                                cwd=self.root, env={**inherited, 'EVENTS': str(events), **environment},
                                capture_output=True, text=True, timeout=15)
        observed = [json.loads(line) for line in events.read_text().splitlines()]
        return result.returncode, observed

    def test_independent_failure_does_not_skip_checks_or_turn_success(self):
        status, events = self.run_group('quality', FAIL_GATE='lint')
        self.assertEqual(status, 1)
        self.assertEqual(events, ['lint', 'python', 'shell-syntax', 'ext3-fixture', 'report'])

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

    def test_extended_stress_requires_one_known_profile(self):
        for environment in ({}, {'CI_STRESS_PROFILE': ''}, {'CI_STRESS_PROFILE': 'memory,cpu'},
                            {'CI_STRESS_PROFILE': 'bogus'}):
            with self.subTest(environment=environment):
                (self.root / 'events.jsonl').unlink(missing_ok=True)
                status, events = self.run_group('extended-stress', **environment)
                self.assertEqual(status, 2)
                self.assertEqual(events, ['report'])

    def test_extended_stress_failure_is_reported_without_retry(self):
        for cpus in ('4', '16'):
            for failure in ('1', '2'):
                with self.subTest(cpus=cpus, failure=failure):
                    (self.root / 'events.jsonl').unlink(missing_ok=True)
                    status, events = self.run_group('extended-stress', CI_STRESS_PROFILE='thread',
                                                    CI_STRESS_CPUS=cpus, CI_GUEST_RETRIES='1',
                                                    FAIL_GATE='stress-thread', FAIL_ATTEMPTS='1',
                                                    FAIL_STATUS=failure)
                    self.assertEqual(status, 1)
                    self.assertEqual(events, ['stress-build', 'stress-thread', 'report'])

    def test_extended_stress_cpu_selection_reaches_the_guest_command(self):
        for environment, cpus in (({}, '4'), ({'CI_STRESS_CPUS': '4'}, '4'),
                                  ({'CI_STRESS_CPUS': '16'}, '16')):
            with self.subTest(cpus=cpus, environment=environment):
                (self.root / 'events.jsonl').unlink(missing_ok=True)
                invocations = self.root / 'invocations.jsonl'
                invocations.unlink(missing_ok=True)
                status, events = self.run_group('extended-stress', CI_STRESS_PROFILE='thread',
                                                INVOCATIONS=str(invocations), **environment)
                self.assertEqual(status, 0)
                records = [json.loads(line) for line in invocations.read_text().splitlines()]
                guest = next(record for record in records if record['name'] == 'stress-thread')
                command = guest['argv'][guest['argv'].index('--') + 1:]
                self.assertEqual(command, ['env', 'STRESS_PROFILES=thread', 'STRESS_PROFILE_LIMIT=1',
                                           'STRESS_DURATION=900', 'STRESS_CPUS=' + cpus,
                                           'STRESS_KEEP_ARTIFACTS=1', 'bash',
                                           'scripts/gates/stress/stress_test.sh', 'esp-stress'])
                self.assertEqual(guest['mode'], 'window')
                self.assertIn('--allow-qualified', guest['argv'])

    def test_invalid_stress_cpu_selection_blocks_before_building(self):
        for group in ('extended', 'extended-stress'):
            for cpus in ('0', '1', '8', '32', '04', '016', '-16', '16 ', 'bogus'):
                with self.subTest(group=group, cpus=cpus):
                    (self.root / 'events.jsonl').unlink(missing_ok=True)
                    status, events = self.run_group(group, CI_STRESS_PROFILE='thread', CI_STRESS_CPUS=cpus)
                    self.assertEqual(status, 2)
                    self.assertEqual(events, ['report'])

    def test_extended_smp_failure_is_reported_without_retry(self):
        for group, following in (('extended-smp', []), ('extended', ['ext3', 'stress-build', 'stress'])):
            for failure in ('1', '2'):
                with self.subTest(group=group, failure=failure):
                    (self.root / 'events.jsonl').unlink(missing_ok=True)
                    status, events = self.run_group(group, CI_GUEST_RETRIES='1',
                                                    FAIL_GATE='smp-8-16', FAIL_ATTEMPTS='1',
                                                    FAIL_STATUS=failure)
                    self.assertEqual(status, 1)
                    self.assertEqual(events, ['build', 'smp-8-16', 'final-owner-build',
                                              'final-owner-16', 'restore-build', *following, 'report'])

    def test_32_vcpu_failure_is_reported_without_retry(self):
        for group, prefix in (('smp-32', []), ('extended-smp-32', ['build'])):
            with self.subTest(group=group):
                (self.root / 'events.jsonl').unlink(missing_ok=True)
                status, events = self.run_group(group, FAIL_GATE='smp-32', FAIL_ATTEMPTS='1', FAIL_STATUS='1')
                self.assertEqual(status, 1)
                self.assertEqual(events, prefix + ['smp-32', 'report'])

    def test_strict_failure_is_reported_without_retry_or_skipping_gates(self):
        status, events = self.run_group('strict', CI_GUEST_RETRIES='1', FAIL_GATE='strict-boot',
                                        FAIL_ATTEMPTS='1', FAIL_STATUS='1')
        self.assertEqual(status, 1)
        self.assertEqual(events, ['build', 'strict-boot', 'strict-runtime', 'strict-runtime-4',
                                  'strict-smp-4', 'report'])

    def test_strict_gates_run_in_strict_completion_mode_without_accepting_qualified(self):
        invocations = self.root / 'invocations.jsonl'
        status, events = self.run_group('strict', INVOCATIONS=str(invocations))
        self.assertEqual(status, 0)
        self.assertEqual(events, ['build', 'strict-boot', 'strict-runtime', 'strict-runtime-4',
                                  'strict-smp-4', 'report'])
        gates = {record['name']: record for record in map(json.loads, invocations.read_text().splitlines())}
        for name in ('strict-boot', 'strict-runtime', 'strict-runtime-4', 'strict-smp-4'):
            with self.subTest(gate=name):
                self.assertEqual(gates[name]['strict'], '1')
                self.assertEqual(gates[name]['mode'], 'completion')
                self.assertNotIn('--allow-qualified', gates[name]['argv'])
        command = gates['strict-runtime-4']['argv']
        self.assertEqual(command[command.index('--') + 1:],
                         ['env', 'KERNEL_TEST_CPUS=4', 'bash', 'scripts/gates/boot/kernel_test.sh', 'esp'])
        self.assertNotIn('KERNEL_TEST_CPUS=4', gates['strict-runtime']['argv'])

    def test_extended_split_groups_keep_the_combined_gate_order(self):
        expected = {
            'extended-smp': ['build', 'smp-8-16', 'final-owner-build', 'final-owner-16',
                             'restore-build', 'report'],
            'smp-32': ['smp-32', 'report'],
            'extended-smp-32': ['build', 'smp-32', 'report'],
            'extended-ext3': ['build', 'ext3', 'report'],
            'extended': ['build', 'smp-8-16', 'final-owner-build', 'final-owner-16',
                         'restore-build', 'ext3', 'stress-build', 'stress', 'report'],
        }
        for group, gates in expected.items():
            with self.subTest(group=group):
                (self.root / 'events.jsonl').unlink(missing_ok=True)
                status, events = self.run_group(group)
                self.assertEqual(status, 0)
                self.assertEqual(events, gates)

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
