#!/usr/bin/env python3
"""Adversarial acceptance tests using excerpts of the actual P3-2 EDU guest."""

from pathlib import Path
import re
import unittest

from iommu_device_probe import CASES, COMPLETE, evaluate


FIXTURE = Path(__file__).parent / "fixtures/iommu_device_probe"


class DeviceEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.serial, self.trace, self.stderr = (
            (FIXTURE / name).read_text() for name in ("serial.log", "vtd.trace", "qemu.stderr")
        )

    def check(self, serial=None, trace=None, stderr=None, status=33):
        return evaluate(self.serial if serial is None else serial,
                        self.trace if trace is None else trace,
                        self.stderr if stderr is None else stderr, status)

    def test_real_emulator_observations_pass(self):
        self.assertEqual(self.check(), [])

    def test_missing_or_duplicated_case_fails(self):
        for case in CASES:
            line = next(line for line in self.serial.splitlines(True) if f"PASS case={case} " in line)
            for serial in (self.serial.replace(line, ""), self.serial.replace(line, line + line)):
                with self.subTest(case=case):
                    self.assertTrue(self.check(serial=serial))

    def test_missing_completion_or_late_begin_fails(self):
        self.assertTrue(self.check(serial=self.serial.replace(COMPLETE, "")))
        begin = "KSA-P3-DEVICE BEGIN version=1\n"
        self.assertTrue(self.check(serial=self.serial.replace(begin, "") + begin))

    def test_status_and_fatal_diagnostics_cannot_be_overridden_by_markers(self):
        for status in (0, 35, "timeout"):
            self.assertTrue(self.check(status=status))
        self.assertTrue(self.check(serial=self.serial + "KSA-P3-DEVICE FAIL error=HardwareInitFailed\n"))
        self.assertTrue(self.check(serial=self.serial + "KERNEL PANIC\n"))

    def test_each_independent_trace_observation_is_required(self):
        for name in ("vtd_dmar_translate", "vtd_dmar_fault", "vtd_inv_desc_cc_device",
                     "vtd_inv_desc_iotlb_domain", "vtd_inv_desc_wait_sw", "vtd_inv_desc_iec",
                     "vtd_reg_ir_root", "vtd_ir_remap_msi_req", "vtd_ir_remap "):
            with self.subTest(name=name):
                trace = "\n".join(line for line in self.trace.splitlines() if name not in line)
                self.assertTrue(self.check(trace=trace))

    def test_raw_fault_reason_direction_sid_and_address_must_agree(self):
        raw = re.search(r"hi=(0x80000005[0-9a-f]+)", self.serial)[1]
        for mask in (1 << 63, 1 << 62, 1 << 32, 1):
            self.assertTrue(self.check(serial=self.serial.replace(raw, hex(int(raw, 16) ^ mask))))
        line = next(line for line in self.serial.splitlines() if "KSA-P3-FAULT" in line)
        address = re.search(r"iova=(0x[0-9a-f]+)", line)[1]
        self.assertTrue(self.check(serial=self.serial.replace(line, line.replace(address, "0x1000"))))

    def test_identity_dma_cannot_pass_as_translation(self):
        line = next(line for line in self.serial.splitlines() if "case=translated" in line)
        address = re.search(r"iova=(0x[0-9a-f]+)", line)[1]
        changed = re.sub(r" gpa=0x[0-9a-f]+", " gpa=" + address, line)
        self.assertTrue(self.check(serial=self.serial.replace(line, changed)))

    def test_msi_rejection_needs_emulator_evidence(self):
        for reason in ("invalid IRTE SID", "non-present IRTE"):
            self.assertTrue(self.check(stderr=self.stderr.replace(reason, "missing")))

    def test_missing_setup_or_unacknowledged_ir_pointer_fails(self):
        line = next(line for line in self.serial.splitlines(True) if line.startswith("KSA-P3-SETUP"))
        self.assertTrue(self.check(serial=self.serial.replace(line, "")))
        self.assertTrue(self.check(serial=self.serial.replace(line, line + line)))
        self.assertTrue(self.check(serial=self.serial.replace("gsts=0xc7000000", "gsts=0xc6000000")))

    def test_lost_second_delivery_trace_fails(self):
        line = next(line for line in self.trace.splitlines(True) if "vtd_ir_remap index " in line)
        self.assertTrue(self.check(trace=self.trace.replace(line, "", 1)))


if __name__ == "__main__":
    unittest.main()
