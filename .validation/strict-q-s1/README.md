# STRICT-Q S1 validation

Source: mechanism `f16eb5451eca95c2c970e836785c09a33108e8c4`, job-summary fix `74023b5`, on `479d06c` (main after #95).

Detailed commands, environment identities and artifact hashes are archived in the private documentation repository:

[Immutable receipt archive](https://github.com/Zero-kernel/Nilix-docs-private/tree/51c0ce847d0ccd6af368d6819cc2b9fcb49f384b/validation/strict-q-s1) · [Archive PR](https://github.com/Zero-kernel/Nilix-docs-private/pull/10)

## Recorded results and limits

- **Local.** fmt, clippy and the build pass. The hosted security suite reports the expected 3 passed / 13 filtered. All Python harness tests pass except one `iommu_device_probe_test` import error, which comes from running unittest outside pytest's path setup and is unrelated; CI runs pytest. Two negative controls fail the parity test: deleting a list entry, and changing a kernel declaration to `NeedsCpus(4)`.
- **Dev host, QEMU 8.2, strict group** (boot, runtime 1 and 4 vCPUs, SMP-4). Every gate still FAILs on the remaining deferrals (D2 network, R7 placeholders), and none reports an undeclared scope.
  - The nine SMP checks report `not_applicable scope=needs_cpus:2` at 1 vCPU.
  - Both Spectre cases report `out_of_scope scope=out_of_scope:N6`.
  - Runtime at 1 vCPU goes from passed=35 deferred=39 on main to passed=36 deferred=29 not_applicable=9.
- **Non-strict.** The runtime group is GATE-QUALIFIED and runtime at 4 vCPUs is QUALIFIED (3), as on main.
- This boot configuration emits no `SECURITY-BOOT` suite, so those list entries are not exercised by a guest run yet. The job-summary fix is covered by unit tests only.

STRICT-Q (#64) still needs S2–S8 before a strict pass. Ordinary builds and public CI do not require the private archive.
