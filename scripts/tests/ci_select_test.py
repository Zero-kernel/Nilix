"""Change-based CI job selection: drop only work a change cannot affect."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.ci.select_jobs import ALL_JOBS, main, select

ROOT = Path(__file__).resolve().parents[2]


class SelectTests(unittest.TestCase):
    def jobs(self, *files):
        return select(list(files))[0]

    def test_documentation_only_runs_the_license_check_alone(self):
        self.assertEqual(self.jobs('README.md', 'docs/roadmap.md', 'docs/assets/nilix.png',
                                   'kernel/README.md', 'COPYRIGHT', 'REUSE.toml',
                                   'LICENSES/MIT.txt', 'LICENSE-APACHE'), ['license'])

    def test_harness_changes_run_quality(self):
        self.assertEqual(self.jobs('scripts/tests/ci_select_test.py', 'requirements-ci.txt'),
                         ['quality', 'license'])
        # A fixture README is test data, not documentation.
        self.assertEqual(self.jobs('scripts/fixtures/gate_logs/README.md'), ['quality', 'license'])

    def test_fuzz_tool_changes_run_tools_and_qemu(self):
        self.assertEqual(self.jobs('fuzz/src/lib.rs', 'userspace/nilix-syz-fuzzer/src/main.rs'),
                         ['tools', 'qemu', 'license'])

    def test_kernel_ci_and_unknown_paths_run_everything(self):
        for path in ('kernel/kernel_core/process.rs', 'bootloader/src/main.rs', 'userspace/hello_musl.c',
                     'Makefile', 'Cargo.lock', '.github/workflows/ci.yml', 'scripts/ci/select_jobs.py',
                     'scripts/gates/boot/boot_check.sh', 'new-top-level-file'):
            with self.subTest(path=path):
                self.assertEqual(self.jobs('docs/README.md', path), list(ALL_JOBS))

    def test_unknown_or_empty_change_runs_everything(self):
        self.assertEqual(select(None)[0], list(ALL_JOBS))
        self.assertEqual(select([])[0], list(ALL_JOBS))


@unittest.skipUnless(shutil.which('git'), 'needs git')
class GitDiffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git('init', '-q')
        self.commit({'kernel/lib.rs': 'fn main() {}\n', 'README.md': '# x\n'})
        self.base = self.rev()

    def git(self, *args):
        return subprocess.run(['git', '-c', 'user.name=t', '-c', 'user.email=t@t', *args],
                              cwd=self.repo, check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, files):
        for name, text in files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.git('add', '-A')
        self.git('commit', '-q', '-m', 'change')

    def rev(self):
        return self.git('rev-parse', 'HEAD')

    def plan(self, *args):
        out = Path(self.temp.name) / 'github-output'
        out.unlink(missing_ok=True)
        env = {**os.environ, 'GITHUB_OUTPUT': str(out), 'PYTHONPATH': str(ROOT)}
        subprocess.run([sys.executable, '-m', 'scripts.ci.select_jobs', *args],
                       cwd=self.repo, env=env, check=True, capture_output=True)
        line = out.read_text().strip()
        self.assertTrue(line.startswith('jobs='))
        return json.loads(line[len('jobs='):])

    def test_push_of_documentation_runs_only_the_license_check(self):
        self.commit({'README.md': '# y\n'})
        self.assertEqual(self.plan('--event', 'push', '--base', self.base, '--head', self.rev()),
                         ['license'])

    def test_moving_a_kernel_file_into_docs_counts_as_a_kernel_change(self):
        self.git('mv', 'kernel/lib.rs', 'docs-lib.md')
        self.git('commit', '-q', '-m', 'move')
        self.assertEqual(self.plan('--event', 'push', '--base', self.base, '--head', self.rev()),
                         list(ALL_JOBS))

    def test_new_branch_unknown_base_and_manual_runs_select_everything(self):
        self.commit({'README.md': '# y\n'})
        head = self.rev()
        for args in (('--event', 'push', '--base', '0' * 40, '--head', head),
                     ('--event', 'push', '--base', 'f' * 40, '--head', head),
                     ('--event', 'workflow_dispatch')):
            with self.subTest(args=args):
                self.assertEqual(self.plan(*args), list(ALL_JOBS))


class MainTests(unittest.TestCase):
    def test_explicit_files_bypass_git(self):
        self.assertEqual(main(['--files', 'README.md']), 0)


if __name__ == '__main__':
    unittest.main()
