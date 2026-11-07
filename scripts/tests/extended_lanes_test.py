"""EXT-CI: the Extended workflow must keep one lane per stress profile."""
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
    def test_extended_keeps_stability_windows_and_stress_duration(self):
        workflow = (ROOT / '.github/workflows/extended.yml').read_text(encoding='utf8')
        self.assertRegex(workflow, r'(?m)^      QEMU_GATE_MODE: window$')
        self.assertRegex(workflow, r"(?m)^      CI_STRESS_SECONDS: '900'$")
        stress = (ROOT / 'scripts/gates/stress/stress_test.sh').read_text(encoding='utf8')
        self.assertIn('STRESS_DURATION="${STRESS_DURATION:-900}"', stress)

    def test_every_stress_profile_has_exactly_one_lane(self):
        profiles = default_profiles()
        self.assertEqual(len(profiles), 7)
        self.assertEqual(entrypoint_profiles(), profiles)
        stress = [lane['profile'] for lane in workflow_lanes() if lane['group'] == 'extended-stress']
        self.assertEqual(stress, profiles)

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
