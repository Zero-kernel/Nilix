"""The gates' QEMU CPU model is one literal everywhere (C3 repair 2, #90).

Every gate runs `qemu64,+smep,+smap,+umip,+rdrand,+rdtscp`: the kernel looks
the current CPU up with RDTSCP once every CPU publishes its id in IA32_TSC_AUX.
The literal is repeated in each launcher; this test keeps the copies equal.
The PR CI runtime group's two other boots add RDPID (with MOVBE, which QEMU 8.2's
TCG needs before it decodes RDPID) and remove RDTSCP.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
STANDARD = 'qemu64,+smep,+smap,+umip,+rdrand,+rdtscp'
MODEL = re.compile(r'qemu64(?:,[+-][a-z0-9_.]+)+')

# Each launcher that names the model, and how many times.
LAUNCHERS = {
    '.github/ISSUE_TEMPLATE/bug_report.yml': 1,
    'Makefile': 1,
    'scripts/gates/boot/boot_check.sh': 1,
    'scripts/gates/boot/extended_smp_test.sh': 1,
    'scripts/gates/boot/kernel_test.sh': 1,
    'scripts/gates/boot/musl_check.sh': 1,
    'scripts/gates/boot/smp_test.sh': 1,
    'scripts/gates/boot/smp_test_4core.sh': 1,
    'scripts/gates/conformance/conformance_gate.py': 1,
    'scripts/gates/performance/perf_regression_test.sh': 1,
    'scripts/gates/qemu/fuzz_runner_test.sh': 1,
    'scripts/gates/qemu/iommu_device_probe.py': 1,
    'scripts/gates/qemu/iommu_failure_probe.py': 1,
    'scripts/gates/qemu/iommu_q35_check.sh': 1,
    'scripts/gates/qemu/mitigation_check.py': 1,
    'scripts/gates/qemu/shared_fault_reentry_probe.py': 1,
    'scripts/gates/qemu/trace_phase_probe.py': 1,
    'scripts/gates/stress/stress_test.sh': 1,
    'userspace/nilix-syz-fuzzer/src/executor.rs': 1,
}

# Models other than the standard one, where they are deliberate.
OTHER_MODELS = {
    # The runtime group's RDPID and LAPIC-path boots. The RDPID boot also needs
    # +movbe: QEMU 8.2's TCG tests MOVBE's CPUID bit before it decodes RDPID.
    'scripts/ci/entrypoint.sh': {STANDARD + ',+rdpid,+movbe', STANDARD.replace('+rdtscp', '-rdtscp')},
    'scripts/tests/ci_entry_test.py': set(),
    # A unit test of the probe's command line, with a model of its own.
    'scripts/tests/mitigation_check_test.py': {'qemu64,+smep,+smap'},
}

SEARCHED = ('Makefile', '.github', 'scripts', 'userspace/nilix-syz-fuzzer/src')


def models_in(path):
    return MODEL.findall((ROOT / path).read_text(encoding='utf-8'))


def searched_files():
    for entry in SEARCHED:
        base = ROOT / entry
        paths = [base] if base.is_file() else sorted(p for p in base.rglob('*') if p.is_file())
        for path in paths:
            try:
                text = path.read_text(encoding='utf-8')
            except (UnicodeDecodeError, OSError):
                continue
            if 'qemu64' in text:
                yield path.relative_to(ROOT).as_posix()


class CpuModelTest(unittest.TestCase):
    def test_every_launcher_uses_the_standard_model(self):
        for path, count in LAUNCHERS.items():
            with self.subTest(path=path):
                self.assertEqual(models_in(path), [STANDARD] * count)

    def test_no_other_file_names_another_model(self):
        for path in searched_files():
            if path == 'scripts/tests/cpu_model_test.py':
                continue
            with self.subTest(path=path):
                allowed = {STANDARD} | OTHER_MODELS.get(path, set())
                found = set(models_in(path))
                self.assertLessEqual(found, allowed)
                if path not in LAUNCHERS and path not in OTHER_MODELS:
                    self.assertEqual(found, set(), 'a new launcher must be listed in LAUNCHERS')

    def test_the_runtime_group_boots_rdpid_and_the_lapic_path(self):
        self.assertEqual(set(models_in('scripts/ci/entrypoint.sh')),
                         OTHER_MODELS['scripts/ci/entrypoint.sh'])


if __name__ == '__main__':
    unittest.main()
