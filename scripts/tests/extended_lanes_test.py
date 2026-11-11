"""EXT-CI: preserve every profile and the required stress CPU topologies."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


def default_profiles():
    text = (ROOT / 'scripts/gates/stress/stress_test.sh').read_text(encoding='utf8')
    match = re.search(r'^STRESS_PROFILES="\$\{STRESS_PROFILES:-([a-z,]+)\}"$', text, re.M)
    if not match:
        raise AssertionError('stress_test.sh default STRESS_PROFILES not found')
    return match[1].split(',')


def entrypoint_profiles():
    text = (ROOT / 'scripts/ci/entrypoint.sh').read_text(encoding='utf8')
    group = re.search(r'^    extended-stress\)\n(.*?)^        ;;$', text, re.M | re.S)
    if not group:
        raise AssertionError('extended-stress group not found')
    accepted = re.search(r'^\s+([a-z|]+)\) ;;$', group[1], re.M)
    if not accepted:
        raise AssertionError('extended-stress profile allowlist not found')
    return accepted[1].split('|')


def workflow_lanes():
    text = (ROOT / '.github/workflows/extended.yml').read_text(encoding='utf8')
    return [dict(re.findall(r'(\w+): ([\w-]+)', body))
            for body in re.findall(r'^\s+- \{(name: [^}]*)\}$', text, re.M)]


class ExtendedLaneTests(unittest.TestCase):
    def test_32_vcpu_is_an_independent_regular_and_extended_lane(self):
        lanes = [lane for lane in workflow_lanes() if lane['name'] == 'smp-32']
        self.assertEqual(len(lanes), 1)
        self.assertEqual(lanes[0]['group'], 'extended-smp-32')
        regular = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf8')
        runtime = re.search(r'^  runtime:\n(.*?)^  qemu:', regular, re.M | re.S)[1]
        regular_lane = re.search(r'\{name: SMP 32-vCPU, group: smp-32, timeout: (\d+)\}', runtime)
        self.assertIsNotNone(regular_lane)
        self.assertGreaterEqual(int(regular_lane[1]) * 60 - 3600, 30 * 60)
        self.assertGreaterEqual(int(lanes[0]['timeout']) * 60 - 3600, 60 * 60)
        self.assertIn('name: normal-boot-image', runtime)
        self.assertIn('name: ci-${{ matrix.gate.group }}', runtime)

    def test_extended_keeps_stability_windows_and_stress_duration(self):
        workflow = (ROOT / '.github/workflows/extended.yml').read_text(encoding='utf8')
        self.assertRegex(workflow, r'(?m)^      QEMU_GATE_MODE: window$')
        self.assertRegex(workflow, r"(?m)^      CI_STRESS_SECONDS: '900'$")
        stress = (ROOT / 'scripts/gates/stress/stress_test.sh').read_text(encoding='utf8')
        self.assertIn('STRESS_DURATION="${STRESS_DURATION:-900}"', stress)

    def test_every_stress_profile_keeps_its_original_lane(self):
        profiles = default_profiles()
        self.assertEqual(len(profiles), 7)
        self.assertEqual(entrypoint_profiles(), profiles)
        stress = [lane['profile'] for lane in workflow_lanes()
                  if lane['group'] == 'extended-stress' and lane.get('cpus') == '4']
        self.assertEqual(stress, profiles)

    def test_scalable_stress_profiles_also_run_at_16_vcpus(self):
        stress = [lane for lane in workflow_lanes() if lane['group'] == 'extended-stress']
        self.assertEqual({lane.get('cpus', '4') for lane in stress}, {'4', '16'})
        self.assertEqual([lane['profile'] for lane in stress if lane['cpus'] == '16'],
                         ['cpu', 'smp', 'thread', 'combined'])
        workflow = (ROOT / '.github/workflows/extended.yml').read_text(encoding='utf8')
        lane_job = re.search(r'^  lane:\n(.*?)^  strict:', workflow, re.M | re.S)[1]
        self.assertIn('CI_STRESS_CPUS: ${{ matrix.lane.cpus }}', lane_job)
        self.assertRegex(lane_job, r'(?m)^        os: \[ubuntu-22\.04, ubuntu-24\.04\]$')
        self.assertNotIn('continue-on-error', lane_job)
        self.assertRegex(workflow, r'(?m)^    needs: \[lane\]$')

    def test_strict_job_is_diagnostic_and_outside_the_aggregate(self):
        workflow = (ROOT / '.github/workflows/extended.yml').read_text(encoding='utf8')
        strict = re.search(r'^  strict:\n(.*?)^  result:', workflow, re.M | re.S)
        self.assertIsNotNone(strict)
        self.assertRegex(strict[1], r'(?m)^    continue-on-error: true$')
        self.assertRegex(strict[1], r'(?m)^      - run: bash scripts/ci/entrypoint\.sh strict$')
        self.assertRegex(strict[1], r'(?m)^        os: \[ubuntu-22\.04, ubuntu-24\.04\]$')
        self.assertRegex(workflow, r'(?m)^    needs: \[lane\]$')
        self.assertNotIn('strict', [lane['name'] for lane in workflow_lanes()])
        entry = (ROOT / 'scripts/ci/entrypoint.sh').read_text(encoding='utf8')
        self.assertRegex(entry, r'(?m)^    strict\)$')

    def test_every_lane_names_a_group_and_a_budget(self):
        entry = (ROOT / 'scripts/ci/entrypoint.sh').read_text(encoding='utf8')
        lanes = workflow_lanes()
        self.assertEqual(len({lane['name'] for lane in lanes}), len(lanes))
        for lane in lanes:
            with self.subTest(lane=lane['name']):
                self.assertRegex(entry, rf'(?m)^    {re.escape(lane["group"])}\)$')
                self.assertTrue(lane['timeout'].isdigit())
                self.assertLessEqual(int(lane['timeout']), 180)


if __name__ == '__main__':
    unittest.main()
