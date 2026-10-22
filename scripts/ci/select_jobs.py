#!/usr/bin/env python3
"""Choose the CI jobs a change needs, from the files it touches.

The CI workflow runs this before every other job. A documentation-only change
gets the license check alone; a change to the Python harness or the fuzz tools
gets the jobs that exercise them; anything else can affect the kernel, its
guest images or CI itself and runs every job. An unknown base commit, an empty
change or a manual run also selects every job, so the selection only ever drops
work it knows to be irrelevant.
"""
import argparse
import fnmatch
import json
import os
import subprocess
import sys

ALL_JOBS = ('quality', 'style', 'hosted', 'tools', 'build', 'runtime', 'qemu', 'license')

# The license check runs on every change: a new file of any kind needs a rule
# in REUSE.toml.
ALWAYS = ('license',)

# First matching rule wins; a path no rule matches selects every job. The
# patterns use fnmatch, where `*` also crosses `/`.
RULES = (
    ('Python harness', ('scripts/tests/*', 'scripts/fixtures/*', 'pytest.ini',
                        'requirements-ci.txt', '.coveragerc'), ('quality',)),
    ('documentation', ('*.md', 'docs/*', 'LICENSES/*', 'LICENSE-*', 'COPYRIGHT',
                       'REUSE.toml', '.gitignore', '.github/ISSUE_TEMPLATE/*',
                       '.github/CODEOWNERS', '.validation/*'), ()),
    ('fuzz tools', ('fuzz/*', 'tools/*', 'userspace/fuzzer/*',
                    'userspace/nilix-syz-fuzzer/*'), ('tools', 'qemu')),
)


def ordered(jobs):
    return [job for job in ALL_JOBS if job in jobs]


def select(files):
    """Return (jobs, reasons) for the changed paths, or every job for None."""
    if files is None:
        return list(ALL_JOBS), ['the changed files could not be determined']
    if not files:
        return list(ALL_JOBS), ['the change lists no files']
    jobs = set(ALWAYS)
    matched = {}
    for path in files:
        for label, patterns, rule_jobs in RULES:
            if any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns):
                jobs.update(rule_jobs)
                matched.setdefault(label, []).append(path)
                break
        else:
            return list(ALL_JOBS), [f'{path} can affect the kernel, its images or CI']
    reasons = [f'{label}: {len(paths)} file(s)' for label, paths in matched.items()]
    return ordered(jobs), reasons


def changed_files(base, head):
    """Paths changed between base and head, or None when that is unknown."""
    if not base or not head or set(base) == {'0'}:
        return None
    for sha in (base, head):
        probe = subprocess.run(['git', 'cat-file', '-e', f'{sha}^{{commit}}'],
                               capture_output=True)
        if probe.returncode != 0:
            return None
    # --no-renames lists both sides of a move, so moving a kernel file under
    # docs/ still counts as a kernel change.
    diff = subprocess.run(['git', 'diff', '--name-only', '--no-renames', f'{base}...{head}'],
                          capture_output=True, text=True)
    if diff.returncode != 0:
        return None
    return [line for line in diff.stdout.splitlines() if line]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--event', default=os.environ.get('CI_EVENT', ''))
    parser.add_argument('--base', default=os.environ.get('CI_BASE', ''))
    parser.add_argument('--head', default=os.environ.get('CI_HEAD', ''))
    parser.add_argument('--files', nargs='*', help='use these paths instead of a git diff')
    args = parser.parse_args(argv)

    if args.files is not None:
        jobs, reasons = select(args.files)
    elif args.event not in ('push', 'pull_request'):
        jobs, reasons = list(ALL_JOBS), [f'event {args.event or "unknown"} runs every job']
    else:
        jobs, reasons = select(changed_files(args.base, args.head))

    skipped = [job for job in ALL_JOBS if job not in jobs]
    print(f'Selected jobs: {", ".join(jobs)}')
    print(f'Skipped jobs: {", ".join(skipped) or "none"}')
    for reason in reasons:
        print(f'  - {reason}')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf8') as out:
            out.write(f'jobs={json.dumps(jobs)}\n')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf8') as out:
            out.write('## Job selection\n\n| Job | Runs |\n| --- | --- |\n')
            out.writelines(f'| {job} | {"yes" if job in jobs else "skipped"} |\n' for job in ALL_JOBS)
            out.write('\n' + ''.join(f'- {reason}\n' for reason in reasons))
    return 0


if __name__ == '__main__':
    sys.exit(main())
