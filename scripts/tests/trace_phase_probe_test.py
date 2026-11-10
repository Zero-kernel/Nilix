"""Evidence rules for the THREAD-HB C1 trace-phase negative controls."""
from __future__ import annotations

from pathlib import Path
import tempfile
import tracemalloc
import unittest

from scripts.ci import qemu_trace
from scripts.gates.qemu import trace_phase_probe as probe


MARKER = b"[SMP] process-deferred gate complete: 3/3 APs acknowledged\n"
BOOT_TRACE = b"     0: v=20 e=0000 i=0 cpl=0 IP=0008:ffffffff80001000\n" * 4


def run(case, *, after=b"KERNEL PANIC: kernel/arch/interrupts.rs:1\n", steady=b"", armed_early=False):
    """A synthetic serial, interrupt log and receipt for one probe case."""
    armed = f"TRACE-PHASE-PROBE ARMED kind={case}\n".encode()
    expected = (probe.CASES[case] or "").encode()
    fault = (b"\n" + expected + b"\n" if expected else b"") + after
    if case == "nx-boot":
        serial = b"boot\n" + armed + fault
        intlog = BOOT_TRACE + b"    9: v=0e e=0011 i=0 cpl=0 IP=0008:ffffffff80123000\n"
        return serial, intlog, dict(schema=1, policy="phased", cpus=4, outcome="marker-missing")
    prefix = b"boot\n" + MARKER
    serial = (prefix + armed + fault) if not armed_early else (b"boot\n" + armed + MARKER + fault)
    end = len(prefix) if not armed_early else len(b"boot\n" + armed + MARKER)
    start = end - len(MARKER)
    receipt = dict(schema=1, policy="phased", cpus=4, outcome="switched", marker_offset=start, marker_end=end,
                   serial_prefix_sha256=qemu_trace.digest(serial[:end]), serial_bytes_at_switch=end,
                   intlog_bytes_at_switch=len(BOOT_TRACE), intlog_bytes_final=len(BOOT_TRACE) + len(steady),
                   qmp_reply={"return": "", "id": "hmp"})
    return serial, BOOT_TRACE + steady, receipt


class PhaseTests(unittest.TestCase):
    def phase_failures(self, case, serial, intlog, receipt):
        with tempfile.TemporaryDirectory(prefix="trace-probe-") as directory:
            path = Path(directory) / "interrupts.log"
            path.write_bytes(intlog)
            return probe.phase_failures(case, serial, path, receipt)

    def test_each_case_passes_with_its_own_evidence(self):
        for case in ("ud", "gp", "nx", "nx-boot"):
            with self.subTest(case=case):
                self.assertEqual(self.phase_failures(case, *run(case)), [])
        serial, intlog, receipt = run("triple", after=b"", steady=b"Triple fault\nCPU Reset (CPU 0)\n")
        self.assertEqual(self.phase_failures("triple", serial, intlog, receipt), [])

    def test_fault_before_the_confirmed_switch_is_rejected(self):
        failures = self.phase_failures("ud", *run("ud", armed_early=True))
        self.assertIn("ARMED was written before QEMU confirmed the switch", failures)

    def test_interrupts_traced_after_the_grace_are_rejected(self):
        steady = b"x" * probe.SWITCH_GRACE_BYTES + b"   12: v=06 e=0000 i=0 cpl=0 IP=0008:ffffffff80001234\n"
        self.assertIn("interrupts were still traced after the switch",
                      self.phase_failures("ud", *run("ud", steady=steady)))

    def test_missing_evidence_is_rejected(self):
        serial, intlog, receipt = run("triple", after=b"")
        self.assertIn("the steady-phase log lacks QEMU's Triple fault",
                      self.phase_failures("triple", serial, intlog, receipt))
        serial, intlog, receipt = run("nx-boot")
        self.assertIn("full boot trace lacks the NX signature",
                      self.phase_failures("nx-boot", serial, BOOT_TRACE, receipt))
        serial, intlog, receipt = run("gp")
        self.assertIn("missing '[GPF] error=' after ARMED",
                      self.phase_failures("gp", serial.replace(b"[GPF]", b"[gpf]"), intlog, receipt))
        self.assertEqual(self.phase_failures("ud", b"no probe\n", b"", None), ["missing ARMED marker"])
        serial, intlog, receipt = run("ud", after=b"TRACE-PHASE-PROBE RETURNED kind=ud\n")
        self.assertIn("the probed fault returned or the kind was not built",
                      self.phase_failures("ud", serial, intlog, receipt))
        serial, intlog, receipt = run("nx")
        self.assertIn("trace outcome 'marker-missing', expected switched",
                      self.phase_failures("nx", serial, intlog, dict(receipt, outcome="marker-missing")))


class VerdictTests(unittest.TestCase):
    def detections(self, serial, intlog, reason):
        with tempfile.TemporaryDirectory(prefix="trace-probe-") as directory:
            root = Path(directory)
            for name, data in (("serial", serial), ("intlog", intlog), ("stderr", b"")):
                (root / name).write_bytes(data)
            return probe.verdict_detections(root / "serial", root / "intlog", root / "stderr",
                                            {"reason": reason, "runner_status": 1})

    def test_serial_panic_is_rejected_by_every_phased_verdict(self):
        serial, intlog, _ = run("gp")
        found = self.detections(serial, intlog, "fatal-output")
        self.assertTrue(all(found.values()), found)
        self.assertEqual(found["ring3"], "serial fatal marker")

    def test_triple_fault_in_the_steady_log_is_rejected(self):
        serial, intlog, _ = run("triple", after=b"", steady=b"Triple fault\n")
        found = self.detections(serial, intlog, "deadline")
        self.assertTrue(all(found.values()), found)
        self.assertIn("triple fault", found["stress"])

    def test_a_clean_completed_run_is_accepted_by_the_serial_verdicts(self):
        found = self.detections(b"boot\n" + MARKER, BOOT_TRACE, "completed")
        self.assertIsNone(found["stress"])
        self.assertIsNone(found["ring3"])


class StreamingTests(unittest.TestCase):
    def test_boot_signature_across_chunk_boundary_has_bounded_memory(self):
        with tempfile.TemporaryDirectory(prefix="trace-probe-") as directory:
            path = Path(directory) / "interrupts.log"
            # Put the NX signature across a block boundary after a large trace.
            with path.open("wb") as stream:
                for _ in range(16):
                    stream.write(b"boot log\n" * 131072)
                stream.write(b"x\n" * ((probe.SCAN_CHUNK_BYTES - 4) // 2))
                stream.write(probe.NX_SIGNATURE + b"\n")
            serial, _, receipt = run("nx-boot")
            tracemalloc.start()
            try:
                self.assertEqual(probe.phase_failures("nx-boot", serial, path, receipt), [])
                self.assertLess(tracemalloc.get_traced_memory()[1], 8 << 20)
            finally:
                tracemalloc.stop()

    def test_multi_gigabyte_boot_prefix_is_skipped_and_tail_is_bounded(self):
        with tempfile.TemporaryDirectory(prefix="trace-probe-") as directory:
            path, tail = Path(directory) / "interrupts.log", Path(directory) / "tail.log"
            steady = b"Triple fault\n" + b"record\n" * 50000
            offset = 3 << 30
            with path.open("wb") as stream:
                stream.seek(offset)
                stream.write(steady)
            serial, _, receipt = run("triple", after=b"", steady=steady)
            receipt.update(intlog_bytes_at_switch=offset, intlog_bytes_final=path.stat().st_size)
            tracemalloc.start()
            try:
                self.assertEqual(probe.phase_failures("triple", serial, path, receipt), [])
                probe.retain_interrupt_tail(path, tail)
                self.assertLess(tracemalloc.get_traced_memory()[1], 8 << 20)
            finally:
                tracemalloc.stop()
            self.assertEqual(tail.read_bytes(), steady[-262144:])

    def test_unterminated_overlong_log_is_rejected_with_bounded_memory(self):
        with tempfile.TemporaryDirectory(prefix="trace-probe-") as directory:
            path = Path(directory) / "interrupts.log"
            path.write_bytes(b"x" * (2 * probe.SCAN_CHUNK_BYTES))
            serial, _, receipt = run("nx-boot")
            failures = probe.phase_failures("nx-boot", serial, path, receipt)
            self.assertTrue(any("overlong line" in failure for failure in failures), failures)


if __name__ == "__main__":
    unittest.main()
