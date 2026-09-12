#!/usr/bin/env python3
"""Render retained gate outcomes without changing their qualification policy."""
import argparse
from collections import Counter
import html
import json
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET


def cell(value):
    return html.escape(str(value)).replace('|', '&#124;').replace('\n', '<br>')


def report(root):
    lines = ['## Test results', '', '| Gate | Outcome | Exit | Seconds |',
             '| --- | --- | ---: | ---: |']
    junit = ET.Element('testsuites')
    details = []
    for path in sorted(root.rglob('result.json')):
        # Only record_gate's process receipts define job outcomes. Other result
        # schemas (device, mitigation, etc.) remain linked evidence, not passes.
        data = json.loads(path.read_text(encoding='utf8'))
        if 'command_status' not in data:
            continue
        name = data.get('name') or str(path.parent.parent.relative_to(root))
        status = data['status']
        outcome = ('PASS' if status == 0 else 'QUALIFIED' if data.get('qualified_accepted')
                   else 'INCOMPLETE' if status == 2 else 'FAIL')
        lines.append(f'| {cell(name)} | {outcome} | {status} | {data["elapsed_seconds"]:.1f} |')
        suite = ET.SubElement(junit, 'testsuite', name=name)
        case = ET.SubElement(suite, 'testcase', name='gate process',
                             time=str(data['elapsed_seconds']))
        if outcome == 'QUALIFIED':
            ET.SubElement(case, 'skipped', message='Qualified; strict acceptance remains open')
        elif status != 0:
            ET.SubElement(case, 'failure', message=data.get('error') or f'Gate exited {status}')
        for counts in sorted(path.parent.rglob('*.counts.json')):
            evidence = json.loads(counts.read_text(encoding='utf8'))
            cases = evidence.get('details', {}).get('cases', [])
            if not cases:
                continue
            details.extend(['', f'### {cell(name)}: executed and deferred cases', '',
                          '| Suite | Pass | Warning | Deferred | Skipped | Fail |',
                          '| --- | ---: | ---: | ---: | ---: | ---: |'])
            for suite_name in sorted({row['suite'] for row in cases}):
                totals = Counter(row['status'] for row in cases if row['suite'] == suite_name)
                details.append('| ' + cell(suite_name) + ' | ' + ' | '.join(
                    str(totals[key]) for key in ('pass', 'warning', 'deferred', 'skipped', 'fail')) + ' |')
            for row in cases:
                item = ET.SubElement(suite, 'testcase', name=row['name'], classname=row['owner'])
                if row['status'] == 'fail':
                    ET.SubElement(item, 'failure', message=row['reason'])
                elif row['status'] != 'pass':
                    ET.SubElement(item, 'skipped', message=f'{row["status"]}: {row["reason"]}')
            details.extend(['', '<details><summary>Checks requiring follow-up</summary>', '',
                          '| Case | Outcome | Owner | Reason |', '| --- | --- | --- | --- |'])
            for row in cases:
                if row['status'] != 'pass':
                    details.append('| ' + ' | '.join(cell(row[k]) for k in ('name', 'status', 'owner', 'reason')) + ' |')
            details.extend(['', '</details>', ''])
    lines.extend(details)
    for suite in junit:
        suite.set('tests', str(len(suite)))
        suite.set('failures', str(sum(item.find('failure') is not None for item in suite)))
        suite.set('skipped', str(sum(item.find('skipped') is not None for item in suite)))
    ET.indent(junit)
    ET.ElementTree(junit).write(root / 'gates.junit.xml', encoding='utf-8', xml_declaration=True)
    # pytest emits native test-case JUnit. Keep it separate from the process gate.
    for path in sorted(root.glob('python.junit.xml')):
        suites = ET.parse(path).getroot()
        totals = {key: sum(int(suite.get(key, 0)) for suite in suites)
                  for key in ('tests', 'failures', 'errors', 'skipped')}
        lines.extend(['', 'Python tests: ' + ', '.join(f'{key}={value}' for key, value in totals.items()) + '.'])
    coverage = root / 'coverage.json'
    if coverage.exists():
        totals = json.loads(coverage.read_text())['totals']
        lines.extend(['', f'Python host harness coverage: **{totals["percent_covered"]:.1f}%** '
                      f'({totals["covered_lines"]}/{totals["num_statements"]} lines). '
                      'This does not measure kernel instruction coverage. Download coverage HTML for missing paths.'])
    for path in sorted(root.rglob('hosted-summary.tsv')):
        lines.extend(['', '### Hosted suites', '', '| Suite | Passed | Filtered |', '| --- | ---: | ---: |'])
        lines.extend('| ' + ' | '.join(cell(item) for item in row.split('\t')) + ' |'
                     for row in path.read_text().splitlines())
        rust = ET.Element('testsuites')
        for log in sorted(path.parent.glob('*.log')):
            content = re.sub(r'\x1b\[[0-9;]*m', '', log.read_text(encoding='utf8', errors='replace'))
            cases = re.findall(r'^test (.+?) \.\.\. (ok|FAILED|ignored)\s*$', content, re.M)
            if not cases:
                continue
            suite = ET.SubElement(rust, 'testsuite', name=log.stem, tests=str(len(cases)),
                                  failures=str(sum(state == 'FAILED' for _, state in cases)),
                                  skipped=str(sum(state == 'ignored' for _, state in cases)))
            for name, state in cases:
                item = ET.SubElement(suite, 'testcase', name=name, classname=log.stem)
                if state != 'ok':
                    ET.SubElement(item, 'failure' if state == 'FAILED' else 'skipped', message=state)
        ET.indent(rust)
        ET.ElementTree(rust).write(path.parent / 'hosted.junit.xml', encoding='utf-8', xml_declaration=True)
    retry_log = root / 'retry.log'
    if retry_log.exists():
        lines.extend(['', '### Guest retry events', '', '```text',
                      retry_log.read_text(encoding='utf8', errors='replace').rstrip(), '```'])
    lines.extend(['', 'Raw status, commands, source identities and logs are retained in the job artifact.', ''])
    return '\n'.join(lines)


def aggregate(needs):
    if not needs:
        raise ValueError('required job results are missing')
    lines = ['## CI overview', '', '| Required group | Result |', '| --- | --- |']
    for name, value in sorted(needs.items()):
        lines.append(f'| {cell(name)} | {cell(value["result"])} |')
    # No skipped/cancelled prerequisites can satisfy the stable required check.
    return '\n'.join(lines) + '\n', int(any(value['result'] != 'success' for value in needs.values()))


def fuzz_report(root, expected, needs):
    text, status = aggregate(needs)
    files = list(root.rglob('fuzz-result.txt'))
    candidates = 0
    if expected < 1 or len(files) != expected:
        status = 1
    for path in files:
        match = re.fullmatch(r'Schema: nilix-fuzz-result-v1\nStatus: completed\nCandidate-Count: ([0-9]{1,10})\n',
                             path.read_text(encoding='utf8'))
        if not match:
            status = 1
        else:
            candidates += int(match[1])
    text += f'\nPublic result manifests: {len(files)}/{expected}; '
    text += 'INCOMPLETE.\n' if status else f'complete; {candidates} opaque candidate(s).\n'
    text += '\nRaw fuzzer output, findings and corpora are never included in this report.\n'
    return text, status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts', type=Path, nargs='?')
    parser.add_argument('--aggregate', action='store_true')
    parser.add_argument('--fuzz', action='store_true')
    parser.add_argument('--expected-manifests', type=int, default=11)
    args = parser.parse_args()
    status = 0
    if args.fuzz:
        if args.artifacts is None:
            parser.error('public artifact directory is required')
        args.artifacts.mkdir(parents=True, exist_ok=True)
        text, status = fuzz_report(args.artifacts, args.expected_manifests, json.loads(os.environ['CI_JOB_RESULTS']))
        (args.artifacts / 'summary.md').write_text(text, encoding='utf8')
    elif args.aggregate:
        text, status = aggregate(json.loads(os.environ['CI_JOB_RESULTS']))
    else:
        if args.artifacts is None:
            parser.error('artifacts directory is required')
        args.artifacts.mkdir(parents=True, exist_ok=True)
        text = report(args.artifacts)
        (args.artifacts / 'summary.md').write_text(text, encoding='utf8')
    print(text)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf8') as stream:
            stream.write(text)
    return status


if __name__ == '__main__':
    raise SystemExit(main())
