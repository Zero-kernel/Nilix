# STRICT-Q S2 validation

Source: `45924d60c7a3581526e7c5f6d103bec00cc3fa39` on `2e09191` (main after #99). It attaches the restricted user network to the three SMP harnesses (decision D2(a)).

Detailed commands, environment identities and artifact hashes are archived in the private documentation repository:

[Immutable receipt archive](https://github.com/Zero-kernel/Nilix-docs-private/tree/d58fdb1c04d3da567680a5d908c79cedd49ad1ab/validation/strict-q-s2) · [Archive PR](https://github.com/Zero-kernel/Nilix-docs-private/pull/14)

## Recorded results and limits

- **Local.**
  - Shell syntax, `make lint` and `git diff --check` pass.
  - The `gate_log` harness tests pass, 34 including the new netdev test. Restoring `smp_test.sh` from the parent fails that test in its `smp_test.sh` case.
  - All Python harness tests pass except one `iommu_device_probe_test` import error under plain unittest, which is unrelated; CI runs pytest.
- **Dev host, QEMU 8.2, parent and S2 side by side.**
  - Strict SMP-4 goes from passed=38 deferred=36 to passed=45 deferred=29. Exactly the seven network cases change, each from deferred to pass.
  - Strict boot, runtime and runtime-4 are unchanged.
  - SMP-2 is QUALIFIED with the same change (38/36 to 45/29).
  - The runtime group is GATE-QUALIFIED on both sides.
  - Times to verdict are unchanged within a second (parent vs S2): SMP-4 30.6 s vs 30.1 s, SMP-2 27.9 s vs 27.3 s.
  - The 8/16-vCPU harness is BLOCKED on this host before QEMU starts, because `zstd` is not installed. CI covers it.
- **Extended CI, run 42978556364 on this source.**
  - Aggregate success, with every lane green. smp-8-16 and smp-32 are GATE-QUALIFIED on Ubuntu 22.04 and 24.04.
  - The strict diagnostic lanes FAIL as on main, with strict SMP-4 at 45/29 on both images.
  - The retained `counts.json` show the seven network cases passing at 8, 16 and 32 vCPUs on both images, with passed=45 deferred=29 at each size. In main's 24.04 smp-8-16 artifact they are deferred, at 38/36.
- **Budget.** Compared with main's Extended run 42950345865 on `297d7d5`:
  - smp-32 gate time: 4030.6 s → 4025.9 s (22.04) and 4251.6 s → 4223.9 s (24.04).
  - smp-8-16 gate time: 1945.9 s → 1963.2 s and 1926.4 s → 1961.9 s.
  - These are window-mode gates, and QUALIFIED means the suite completed inside each window: 900 s at 8 and 16 vCPUs, 3600 s at 32. The completion offset inside a window is not recorded, so the 32-vCPU margin itself is not measured.
  - The 22.04 smp-8-16 job grew from 40 to 46 minutes. The growth is in its `final-owner-16` gate (243.6 s → 539.5 s), whose harness this change does not touch.

None of these results is a strict pass. Ordinary builds and public CI do not require the private archive.

The local-checks and gates receipts have aggregate status 1, from the unrelated unittest import error and from the remaining strict deferrals plus the blocked dev-host extended runs respectively. Individual statuses and log hashes are preserved.
