# SCHED-STALL #92 validation

Source: fix `5d201b3fba44e0a6dd77fc753a6220273aab08ec` on `207ddbfdd964a65770d7c4c203b2bd42ee71a419`.

Detailed commands, environment identities and artifact hashes are archived in the private documentation repository:

[Immutable receipt archive](https://github.com/Zero-kernel/Nilix-docs-private/tree/1fdecd333c8a7f0075bed020ed66b5e604db6f0c/validation/sched-stall-92) · [Archive PR](https://github.com/Zero-kernel/Nilix-docs-private/pull/9)

## Recorded results and limits

- **Reproducer (before the fix).** A diagnostic-only probe on `207ddbf` calls the production `select_next_with_cursor()` with a lone Ready candidate whose PCB lock is held, or whose `on_cpu` is set. In both cases it reports no candidate and a complete cycle, so `prepare_switch()` does not rearm.
- **T1 (`run_idle_rearm_self_test`).** It passes with the fix. With `arm_idle_for_local_candidate()` reduced to the pre-fix behavior (never arm), it panics at the recovery assertion and the runtime gate FAILs. Both runs used local QEMU 11.1 (not CI parity); the test is deterministic.
- **Stress, eight concurrent 900-second `combined` runs on QEMU 6.2/8.2, before and after.**
  - `207ddbf`: 7956 rounds, no stall. 7 runs QUALIFIED (3) and 1 FAIL, which was the host-cut fragment fixed in #95, not a stall.
  - Fix: 8039 rounds, no stall, all 8 QUALIFIED (3). The last periodic `idle_rearms` sample of each run is 0–3, 14 in total.
  - The stress-level trigger is too rare to reproduce on demand at this scale, so T1 is the before/after evidence (design decision D3(a)).
- **Dev-host gates on QEMU 8.2.** The runtime group (boot, runtime 1 vCPU, SMP-4) is GATE-QUALIFIED. Runtime at 4 vCPUs is QUALIFIED (3). ring3-mm at 1/4/8/16 vCPUs is OK; its inner boot-harness status is 1, as on main. None of these is a strict pass.

STRESS-7 (#63) still needs a full rerun on the merged source. Ordinary builds and public CI do not require the private archive.
