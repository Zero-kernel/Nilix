# C3 kernel-stack flush batch validation

Source: `3ae42c69b007e68b733ecfb0fc459d4dd0380e22` on `82beb71` (main after #101 and #102). `3390881` is the change with its tests; `3ae42c6` edits one doc comment. The measurements use `diag/c3-kstack` (`51fa344`) against `diag/c3-kstack-base` (`3e600e2`): each side plus E2's diagnostic stress runner, not for merge.

Detailed commands, environment identities and artifact hashes are archived in the private documentation repository:

[Immutable receipt archive](https://github.com/Zero-kernel/Nilix-docs-private/tree/c33105025950e38b84c65fe7078416f3335d40f7/validation/c3-kstack) · [Archive PR](https://github.com/Zero-kernel/Nilix-docs-private/pull/16)

## Recorded results and limits

- **Local.**
  - fmt, clippy, lint and the build pass.
  - The hosted sub-crate suites pass: 650 tests, of which five `kstack_flush` tests and four `rcu` tests are new.
  - Freeing a stack before the flush, releasing its slot before the flush, and letting a push complete its own stack each fail the `kstack_flush` tests.
  - All Python harness tests pass except one `iommu_device_probe_test` import error under plain unittest, which is unrelated; CI runs pytest.
- **Dev host, QEMU 8.2, beside the parent.**
  - The runtime group is GATE-QUALIFIED, and runtime at 4 and 16 vCPUs is QUALIFIED (3) with passed=47.
  - The strict group still FAILs on the remaining deferrals. Each of its four gates has the parent's counts plus one pass, with no new deferral and no `strict_scope.txt` entry.
  - ring3-mm passes at 1, 4, 8 and 16 vCPUs, including `syscall_test`'s 2 KiB `/proc/schedstat` read.
  - The ST-K2-P2(c) final-owner oracle passes at 1 and 4 vCPUs.
  - The extended SMP harness is QUALIFIED (3) at 8, 16 and 32 vCPUs.
  - Two guest negative controls fail as they should: leaving the slot out of `FlushPending` fails `kstack_flush_batch`, and test op 6 without the waiting pages fails the final-owner oracle.
- **STRESS-7.** All seven profiles at `STRESS_CPUS=4` and the four SMP profiles at `STRESS_CPUS=16` are QUALIFIED (3) over 900 s. The largest heartbeat gap is 12191 ms (`combined`, 16 vCPUs) against the 15000 ms bound. No stack was quarantined.
- **CI.** PR CI passes (15 jobs). An Extended run on the branch is green in 31 jobs; its two diagnostic strict jobs fail on the remaining deferrals, as on main.
- **The mechanism** (E2 matrix: 16 workers at 4, 8 and 16 vCPUs, QEMU 8.2 and 6.2, all QUALIFIED).
  - One flush covers 5.6–16 stacks at every size.
  - IPIs per thread fall by 48–58%. At 16 vCPUs they go from 23.5 to 11.1, which is the design's prediction for five stacks per batch.
  - `PT_LOCK` hold time per thread falls by 38–72%.
- **Host time per thread: the batch is about 1% faster** (corrected on 2026-11-16 by C3 E3).
  - E3 compared the two behaviours within one boot: a diagnostic build switches between the batch and the parent's per-stack flush every 10000 ticks. The per-stack flush is 0.9% slower at 4 vCPUs with the E2 runner, and 1.1% slower at 4 and at 16 vCPUs on the unmodified `thread` profile. Its counted runs are QUALIFIED (3).
  - This index first reported a loss of 1.6–3.1%, from separately booted kernels with two or three boots a side. One kernel's boots differ by 3% at 16 vCPUs, so that comparison could not show a difference of this size.
  - It also said that the per-stack broadcast was a needed wake-up. E3 found no wake path behind it: the CPUs the broadcast wakes find nothing to run.
  - In the E2 matrix the repaired kernel was 6–11% slower in separate boots. It prints one more schedstat line per round there, and builds that behave the same differ by up to 2%; within one boot the batch is faster.
  - E3's receipts: [immutable archive](https://github.com/Zero-kernel/Nilix-docs-private/tree/99d1a22df772a25dbc26fc40c557728437819659/validation/c3-e3) · [archive PR](https://github.com/Zero-kernel/Nilix-docs-private/pull/17).
- **A confounder for host-time runs on this host.** Seven of 43 boots calibrated the LAPIC timer 17–46% high, which slows the tick for the whole run and makes it 4–11% faster. Such runs are marked and not counted.

None of these results is a strict pass. All host-time figures are under TCG on one shared host; KVM and real hardware were not measured. Ordinary builds and public CI do not require the private archive.

The local-checks, gates and first diagnostic receipts have aggregate status 1, from the unrelated unittest import error, the remaining strict deferrals and the negative controls, and one diagnostic kernel that did not boot. Individual statuses and log hashes are preserved.
