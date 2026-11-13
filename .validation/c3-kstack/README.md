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
- **Host time per thread does not improve.**
  - On the unmodified `thread` profile the repaired kernel is 1.6% slower at 4 vCPUs and 3.1% slower at 16 vCPUs. The parent's own runs differ by about 2%.
  - In the E2 matrix it is 6–11% slower in the six comparable pairs. About 3 points of that come from one more schedstat line per round on the repaired side, and one parent run is uncertain by up to 7%.
  - A diagnostic kernel that sends one reschedule IPI to every other CPU for each deferred stack returns to the parent's time at 4 vCPUs. The per-stack broadcast was also waking every CPU at each thread exit. Which wake path depends on that is left to E3.
- **A confounder for host-time runs on this host.** Seven of 43 boots calibrated the LAPIC timer 17–46% high, which slows the tick for the whole run and makes it 4–11% faster. Such runs are marked and not counted.

None of these results is a strict pass. Host-time samples are small (one to three runs per kernel and size), all under TCG on one shared host; KVM and real hardware were not measured. Ordinary builds and public CI do not require the private archive.

The local-checks, gates and first diagnostic receipts have aggregate status 1, from the unrelated unittest import error, the remaining strict deferrals and the negative controls, and one diagnostic kernel that did not boot. Individual statuses and log hashes are preserved.
