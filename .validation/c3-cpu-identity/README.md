# C3 repair 2 validation: the current CPU's id from IA32_TSC_AUX

Source: `871212834a957304bb4c272d1dfbbdcc3a364782` on `c3fc51e` (main after #107). Refs #90.

Detailed commands, environment identities and artifact hashes are archived in the private documentation repository:

[Immutable receipt archive](https://github.com/Zero-kernel/Nilix-docs-private/tree/b6bbb2ff5907be2b0071e01aaf29fff76f8a1cf9/validation/c3-cpu-identity) · [Archive PR](https://github.com/Zero-kernel/Nilix-docs-private/pull/23)

## Recorded results and limits

- **Checks on the dev host.**
  - fmt, clippy, lint and the build pass.
  - The hosted sub-crate suites pass with 670 tests; `cpu-local` has 3 new identity tests.
  - pytest: 346 pass. The 9 `private_fuzz_evidence_test.py` tests stop at setup because the dev host has no `age`; PR CI runs them.
  - The runtime test passes at 1, 2 and 4 vCPUs, and each boot prints the lookup its CPU model gives: `rdtscp` on the standard model, `rdpid` with `+rdpid,+movbe`, `lapic` without `+rdtscp`.
- **Negative controls**, each a scratch edit that must fail a named gate, all fail as intended:
  - an AP publishing a wrong value panics during bring-up;
  - a value changed after the selection panics at the next tick;
  - a boot forced to the LAPIC read fails the required lookup line.
- **RDTSCP or RDMSR** (design §5.4), the `thread` profile at 16 vCPUs: RDTSCP 11.14 ms per thread, RDMSR 11.55, RDPID 10.76. RDMSR is not more than 3% cheaper, so the lookup keeps RDTSCP.
- **Dev host, QEMU 8.2, beside the parent.**
  - The runtime group is GATE-QUALIFIED with its five checks, and runtime at 4 and 16 vCPUs is QUALIFIED (3) with passed=49.
  - The strict group still FAILs on the remaining deferrals, with the parent's counts apart from the new test.
  - ring3-mm passes at 1, 4, 8 and 16 vCPUs, and the ST-K2-P2(c) final-owner oracle at 1 and 4.
  - The extended SMP harness is QUALIFIED (3) at 8, 16 and 32 vCPUs.
- **STRESS-7.** All seven profiles at `STRESS_CPUS=4` and the four SMP profiles at `STRESS_CPUS=16` are QUALIFIED (3) over 900 s. The largest heartbeat gap is 8380 ms (`combined`, 16 vCPUs) against the 15000 ms bound.
- **Host time per thread** (the unmodified `thread` profile, 300 s, each run alone on the host, two counted runs a side):
  - 4 vCPUs: 10.03 ms on the parent, 8.62 ms here (−14%);
  - 8 vCPUs: 10.74 ms on the parent, 9.00 ms here (−16%);
  - 16 vCPUs: 16.35 ms on the parent, 11.36 ms here (−31%);
  - two more runs booted with an off-nominal LAPIC calibration and are not counted.
- **At 16 vCPUs**, under a QEMU build that accounts its global lock:
  - MMIO reads: 9 568 per thread on the parent, 106 here.
  - PAUSEs per thread rose from 3 244 to 5 087, mostly the owner waiting for its own ready queue and TLB shootdowns waiting for acknowledgements.
  - The steal scan's `lock_skips` share rose to 14.2–14.6% (8.4–9.8% on the parent). Neither is a criterion.
- **Design acceptance.** Met:
  - 16-vCPU host time at most 16.5 ms (11.36);
  - at most 1.35 times the 4-vCPU figure (1.32);
  - at most 500 MMIO reads per thread (106);
  - no regression.
- **Gate configuration.**
  - Every gate's CPU model gains `+rdtscp`.
  - PR CI's runtime group gains `runtime-rdpid` and `runtime-lapic`.
  - `runtime-rdpid` also sets `+movbe`, because QEMU 8.2's TCG decodes RDPID only when MOVBE's CPUID bit is set. The maintainer approved this deviation on 2026-11-24.
- **CI on `8712128`.**
  - PR CI passes (15 jobs), with `runtime-rdpid` and `runtime-lapic` QUALIFIED.
  - The Extended run on the branch passes 31 jobs. Its two diagnostic strict jobs fail on the remaining deferrals, as on main.

None of these results is a strict pass. All host-time figures are under TCG on one shared host; KVM and real hardware were not measured. Ordinary builds and public CI do not require the private archive.

The gates receipt has aggregate status 1, from the remaining strict deferrals. The measurement receipts have status 3, and the others 0. Individual statuses and log hashes are preserved.
