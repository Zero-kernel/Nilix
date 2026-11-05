"""PR code cannot replace the selector or the required aggregate verdict."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from scripts.ci.select_jobs import ALL_JOBS

ROOT = Path(__file__).resolve().parents[2]
TRUSTED_REF = '${{ github.event.pull_request.base.sha || github.sha }}'


def workflow_job(name):
    workflow = (ROOT / '.github/workflows/ci.yml').read_text()
    return re.search(rf'^  {name}:\n(.*?)(?=^  \w+:\n|\Z)',
                     workflow, re.M | re.S)[1]


@unittest.skipUnless(shutil.which('git') and shutil.which('bash'), 'needs git and bash')
class TrustedControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ci-control-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.runner = self.root / 'runner'
        self.runner.mkdir()
        self.git('init', '-q')
        ci = self.repo / 'scripts/ci'
        ci.mkdir(parents=True)
        for name in ('select_jobs.py', 'ci_report.py'):
            shutil.copyfile(ROOT / 'scripts/ci' / name, ci / name)
        (self.repo / 'README.md').write_text('base\n')
        self.commit()
        self.base = self.git('rev-parse', 'HEAD')
        self.env = {**os.environ, 'RUNNER_TEMP': str(self.runner),
                    'CI_CONTROL_REF': self.base, 'CI_EVENT': 'pull_request',
                    'CI_BASE': self.base, 'GITHUB_OUTPUT': str(self.root / 'output'),
                    'GITHUB_STEP_SUMMARY': str(self.root / 'summary'),
                    # A PR-owned module path must not shadow Python's stdlib.
                    'PYTHONPATH': str(ci)}

    def git(self, *args):
        return subprocess.run(['git', '-c', 'user.name=test', '-c', 'user.email=test@example.com',
                               *args], cwd=self.repo, check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit(self):
        self.git('add', '-A')
        self.git('commit', '-qm', 'fixture')

    def run_selector(self):
        job = workflow_job('changes')
        self.assertIn('CI_CONTROL_REF: ' + TRUSTED_REF, job)
        script = re.search(r'run: \|\n((?: {10}.*\n)+)', job)[1]
        script = '\n'.join(line[10:] for line in script.splitlines())
        return subprocess.run(['bash', '-euo', 'pipefail', '-c', script], cwd=self.repo,
                              env={**self.env, 'CI_HEAD': self.git('rev-parse', 'HEAD')},
                              capture_output=True, text=True, timeout=15)

    def test_pr_selector_and_import_shadow_cannot_skip_kernel_jobs(self):
        ci = self.repo / 'scripts/ci'
        (ci / 'select_jobs.py').write_text(
            'import os\nwith open(os.environ["GITHUB_OUTPUT"], "a") as f:\n'
            '    f.write(\'jobs=["license"]\\n\')\n')
        (ci / 'json.py').write_text('raise SystemExit("PR import executed")\n')
        (self.repo / 'kernel.rs').write_text('changed kernel\n')
        self.commit()
        result = self.run_selector()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        plan = (self.root / 'output').read_text().strip().removeprefix('jobs=')
        self.assertEqual(json.loads(plan), list(ALL_JOBS))

    def test_trusted_selector_preserves_documentation_fast_path(self):
        (self.repo / 'README.md').write_text('new docs\n')
        self.commit()
        result = self.run_selector()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'output').read_text().strip(), 'jobs=["license"]')

    def test_missing_trusted_revision_does_not_fall_back_to_pr(self):
        self.env['CI_CONTROL_REF'] = 'f' * 40
        result = self.run_selector()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'output').exists())

    def test_pr_report_cannot_turn_a_failed_or_skipped_build_green(self):
        report = self.repo / 'scripts/ci/ci_report.py'
        report.write_text('raise SystemExit(0)\n')
        (self.repo / 'scripts/ci/json.py').write_text('raise SystemExit(0)\n')
        self.commit()
        job = workflow_job('result')
        self.assertIn('ref: ' + TRUSTED_REF, job)
        self.assertIn('persist-credentials: false', job)
        self.assertNotIn('download-artifact', job)
        command = re.search(r'^      - run: (.*)$', job, re.M)[1]
        self.assertEqual(command, 'python3 -I scripts/ci/ci_report.py --aggregate')
        # Emulate the action's exact base-SHA checkout in this disposable repo.
        self.git('checkout', '--detach', self.base)
        for state, expected in [('failure', 1), ('cancelled', 1), ('skipped', 1), ('success', 0)]:
            with self.subTest(state=state):
                needs = {'changes': {'result': 'success'}, 'license': {'result': 'success'},
                         'build': {'result': state}}
                result = subprocess.run(['bash', '-euo', 'pipefail', '-c', command],
                                        cwd=self.repo, capture_output=True, text=True, timeout=15,
                                        env={**self.env, 'CI_JOB_RESULTS': json.dumps(needs),
                                             'CI_PLANNED_JOBS': '["license", "build"]'})
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
