# C3 repair 1 validation: the steal-scan hint

Source: `4c8a1eba5d737ca8a5bec4cf77fd3cbb74e7e658` on `629fa64` (main after #105). Refs #90.

Detailed commands, environment identities and artifact hashes are archived in the private documentation repository:

[Immutable receipt archive](https://github.com/Zero-kernel/Nilix-docs-private/tree/0af33d362932afdc5f089d037f4bcdcaa9c54037/validation/c3-steal) · [Archive PR](https://github.com/Zero-kernel/Nilix-docs-private/pull/21)

## Recorded results and limits

- **Checks on the dev host.**
  - fmt, clippy, lint and the build pass.
  - The hosted sub-crate suites pass with 667 tests. `kernel-core` has 9 new `steal_hint_*` tests and `net` 3 new `c3_port_uncharge_*` tests.
  - pytest: 342 pass. The 9 `private_fuzz_evidence_test.py` tests stop at setup because the dev host has no `age`; PR CI runs them.
- **Negative controls**, each a scratch edit that must fail a named test, all fail as intended:
  - no publication on a wake;
  - a seen value stored after an inconclusive scan;
  - the port-uncharge sequence advanced before the enqueue;
  - the drain ignoring its sequence gate.
- **Dev host, QEMU 8.2, beside the parent.**
  - The runtime group is GATE-QUALIFIED, and runtime at 4 and 16 vCPUs is QUALIFIED (3) with passed=48.
  - The strict group still FAILs on the remaining deferrals, with the parent's counts apart from the new test.
  - ring3-mm passes at 1, 4, 8 and 16 vCPUs, and the ST-K2-P2(c) final-owner oracle at 1 and 4.
  - The extended SMP harness is QUALIFIED (3) at 8, 16 and 32 vCPUs.
- **STRESS-7.** All seven profiles at `STRESS_CPUS=4` and the four SMP profiles at `STRESS_CPUS=16` are QUALIFIED (3) over 900 s. The largest heartbeat gap is 4290 ms (`combined`, 16 vCPUs) against the 15000 ms bound.
- **Host time per thread** (the unmodified `thread` profile, 300 s, each run alone on the host, two counted runs a side):
  - 4 vCPUs: 17.1 ms on the parent, 10.1 ms here (−41%);
  - 8 vCPUs: 24.6 ms on the parent, 10.6 ms here (−57%);
  - 16 vCPUs: 56.2 ms on the parent, 15.5 ms here (−72%);
  - three more runs booted with an off-nominal LAPIC calibration and are not counted.
- **PAUSEs at 16 vCPUs**, under a QEMU build that accounts its global lock:
  - 43 906 per thread on the parent, 3 363 here;
  - with the ready-queue lock helper forced inline (a diagnostic), the parent's sites are in the steal scan and the port-uncharge drain, and none of this revision's are.
- **Design acceptance.** Met:
  - 16-vCPU host time at most 22 ms;
  - at most 1.6 times the 4-vCPU figure (1.53);
  - no PAUSE site on the steal path or in the drain;
  - no regression.

  **Not met: `lock_skips` are 6.9–8.8% of the queues a thief looks at, against under 5%.** A lock skip is a failed `try_lock`, with no spin. The maintainer accepted this as a recorded deviation; who holds the lock and how to reduce the collisions are being investigated on #90.
- **CI on `4c8a1eb`.**
  - PR CI passes (15 jobs).
  - The Extended run on the branch passes 31 jobs. Its two diagnostic strict jobs fail on the remaining deferrals, as on main.

None of these results is a strict pass. All host-time figures are under TCG on one shared host; KVM and real hardware were not measured. Ordinary builds and public CI do not require the private archive.

The gates receipt has aggregate status 1, from the remaining strict deferrals. The measurement receipt has status 3, and the others 0. Individual statuses and log hashes are preserved.
