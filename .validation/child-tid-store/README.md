# Child-TID store validation

Source: `1b6fcf015c357c7b57001cf40d8c7f3af771f135` on `e828bd0` (main after #104).

Detailed commands, environment identities and artifact hashes are archived in the private documentation repository:

[Immutable receipt archive](https://github.com/Zero-kernel/Nilix-docs-private/tree/37baf8abb79e73d33a51a8e5e3d7a79e2adcf385/validation/child-tid-store) · [Archive PR](https://github.com/Zero-kernel/Nilix-docs-private/pull/18)

## Recorded results and limits

- **Local.**
  - fmt, clippy, lint and the build pass.
  - The hosted sub-crate suites pass: 653 tests, of which three `kernel-core` tests are new.
  - With the word cleared by four byte stores, the reader test loads `0x1010500` and fails.
- **The probe** (`userspace/tid_clear_probe.c`, in the musl gate; QEMU 8.2).
  - Main with only the probe FAILs at 4 vCPUs: `MUSL-TID-CLEAR-FAIL stage=torn exit=4 value=01010100`.
  - This revision passes at 4 vCPUs (`MUSL-TID-CLEAR-OK exits=200 concurrent=102`) and at 1, where the probe records that it does not apply.
- **Dev host, QEMU 8.2, beside the parent.**
  - The runtime group is GATE-QUALIFIED, and runtime at 4 and 16 vCPUs is QUALIFIED (3) with passed=47.
  - The strict group still FAILs on the remaining deferrals, with the parent's counts.
  - ring3-mm passes at 1, 4, 8 and 16 vCPUs, and the ST-K2-P2(c) final-owner oracle at 1 and 4.
  - The extended SMP harness is QUALIFIED (3) at 8, 16 and 32 vCPUs.
- **STRESS-7.** All seven profiles at `STRESS_CPUS=4` and the four SMP profiles at `STRESS_CPUS=16` are QUALIFIED (3) over 900 s. The largest heartbeat gap is 12047 ms (`combined`, 16 vCPUs) against the 15000 ms bound.
- **The stalls before the fix.** Four, with one end state: musl's thread-list lock holds the main thread's TID, the four workers of a wave wait on it and the main thread waits in `pthread_join`.
  - In each, the wave before has a thread whose TID is a multiple of 256: `0x500`, `0x400`, `0xd00`, `0x600`.
  - One is on main's code. Its trace has thread `0x600` inside the lock right after `0x602` was cleared, and the lock word at `0x601` when `0x600` exited.
- **Thread rounds** (the 4-vCPU `thread` profile, 900 s per copy, on hosted runners and the dev host).
  - Unfixed: 4 stalls in 1.99 million waves, 3 of them with the console change of #105 (1.44 million waves) and 1 without (0.55 million).
  - Fixed: no stall in 2.47 million waves, 50 copies, all QUALIFIED (3). At the unfixed rate that would happen in about 0.7% of cases, so these rounds support the probe and do not replace it.
- **CI.**
  - PR CI passes (15 jobs), including the musl gate with the probe.
  - Extended run 44050434009 on the branch passes in 31 jobs; its two diagnostic strict jobs fail on the remaining deferrals, as on main.
  - An Extended run of #105 and this change together (44069865484) passes 29 of 30 lanes. Its `ubuntu-24.04 / stress-block` lane failed its crash capture, which main's code does as well in 2 of 12 block-only copies (run 44084332843).

None of these results is a strict pass. Everything ran under TCG; KVM and real hardware were not measured. Ordinary builds and public CI do not require the private archive.

The gates, probe and stalls receipts have aggregate status 1, from the remaining strict deferrals, the negative control and the four recorded stalls. Individual statuses and log hashes are preserved.

## PR #106 review follow-up

The archive above describes the original compare-and-exchange implementation. Review of `ce6e235` identified an aligned byte-copy fallback and three gaps in the regression checks.

| Controlled check | At `ce6e235` | After the repair |
| --- | --- | --- |
| Aligned TID store with repeated compare mismatches | The hosted caller recorded four single-byte writes and returned success. | The caller selected one unconditional 32-bit store. An aligned fault propagated directly. |
| Reader thread first scheduled when its writer blocks | The hosted test failed with zero loads in 8/8 runs. | The writer waited for the reader's first load and all eight runs passed. |
| Probe participants kept on one simulated CPU with two CPUs advertised | The guest probe reported 200 concurrent exits. | The probe rejected the placement. Each successful exit now requires acknowledgement from a reader pinned to a distinct CPU. |
| Musl gate given an impossible count or conflicting success records | Both logs passed. | Both logs failed. The SMP gate checks one record covering all 200 exits and two distinct, in-range CPU IDs. |

The first two comparisons used the production Rust functions with hosted memory primitives. The placement check used the guest C probe with controlled scheduling. The linked-ELF check verifies the new store instruction and its exception-table entry, and the Linux fault test exercises that entry on a read-only page.

In the first repair, `45abac8`, the four-vCPU guest started the reader on CPU 1 and failed before its first clone while trying to pin it to CPU 0. The revised probe keeps the reader on its current allowed CPU and selects a different CPU for the child. The Linux QEMU musl gate then passed on its first attempt at both one and four vCPUs. The single-vCPU run recorded the expected skip. The four-vCPU run recorded `MUSL-TID-CLEAR-OK exits=200 concurrent=200 reader_cpu=1 child_cpu=0`.
