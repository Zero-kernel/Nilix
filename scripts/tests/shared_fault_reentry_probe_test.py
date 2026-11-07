#!/usr/bin/env python3
"""Mutation checks for the ST-K2-P2(a) reentry probe verdict, without a guest."""

import unittest
from scripts.gates.qemu.shared_fault_reentry_probe import evidence_failures, evidence_passes


# The shape of a real fail-stop: boot noise, the kernel's HOLD marker, the
# panic handler's location line, core's panic message, then the kdump text.
def serial(lock="MmState", hold=None, message=None):
    hold = hold if hold is not None else f"ST-K2-REENTRY-PROBE HOLD lock={lock}"
    message = message if message is not None else (
        f"same-CPU {lock} reentry during shared fault at 0x1000000000 (pid 1)")
    return "\n".join([
        "[BOOT] Nilix kernel",
        "ST-K2-REENTRY-PROBE GUEST lock=2",
        hold,
        "KERNEL PANIC: kernel/arch/interrupts.rs:1340",
        "panicked at kernel/arch/interrupts.rs:1340:21:",
        message,
        "KDUMP-BEGIN",
        "q1w2e3r4t5y6",
        "KDUMP-END",
        "",
    ])


CASE_LOCKS = {"table": "PROCESS_TABLE", "pcb": "PCB", "mm": "MmState"}


class ReentryEvidenceTests(unittest.TestCase):
    def test_each_lock_passes_with_its_own_message(self):
        for case, lock in CASE_LOCKS.items():
            self.assertEqual(evidence_failures(serial(lock), "", 35, case), [], case)

    def test_a_hang_or_other_exit_fails(self):
        for status in ("timeout", 0, 1, 33, -9):
            self.assertFalse(evidence_passes(serial(), "", status, "mm"))

    def test_another_lock_cannot_satisfy_the_case(self):
        self.assertFalse(evidence_passes(serial("PCB"), "", 35, "mm"))
        self.assertFalse(evidence_passes(serial(
            "MmState", message="same-CPU PCB reentry during shared fault at 0x1000 (pid 1)"),
            "", 35, "mm"))

    def test_missing_or_duplicate_markers_fail(self):
        text = serial()
        for mutated in (text.replace("ST-K2-REENTRY-PROBE HOLD lock=MmState\n", ""),
                        text.replace("same-CPU MmState", "same-CPU  MmState"),
                        text + "ST-K2-REENTRY-PROBE HOLD lock=MmState\n",
                        text + "same-CPU MmState reentry during shared fault at 0x2000 (pid 1)\n",
                        text + "KERNEL PANIC: kernel/arch/interrupts.rs:1340\n"):
            self.assertFalse(evidence_passes(mutated, "", 35, "mm"))

    def test_the_panic_must_follow_the_hold_from_the_fault_handler(self):
        lines = serial().splitlines()
        hold = lines.pop(2)
        lines.insert(5, hold)  # after the panic and its message
        self.assertFalse(evidence_passes("\n".join(lines) + "\n", "", 35, "mm"))
        elsewhere = serial().replace("kernel/arch/interrupts.rs", "kernel/kernel_core/fork.rs")
        self.assertFalse(evidence_passes(elsewhere, "", 35, "mm"))

    def test_a_returned_probe_fails(self):
        for line in ("ST-K2-REENTRY-PROBE RETURNED lock=MmState resolved=true",
                     "ST-K2-REENTRY-PROBE GUEST-RETURNED rc=0 errno=0"):
            self.assertFalse(evidence_passes(serial() + line + "\n", "", 35, "mm"))

    def test_other_terminal_markers_fail(self):
        for fatal in ("[PF ENTRY] err=0x2", "[DOUBLE FAULT]", "triple fault"):
            self.assertFalse(evidence_passes(serial() + fatal + "\n", "", 35, "mm"))
        self.assertFalse(evidence_passes(serial(), "KERNEL PANIC", 35, "mm"))


if __name__ == "__main__":
    unittest.main()
