# Console display change validation

Source: `d33ea64fc5906b0b00afda820d24a70a802b93da` on `e828bd0` (main after #104).

Detailed commands, environment identities and artifact hashes are archived in the private documentation repository:

[Immutable receipt archive](https://github.com/Zero-kernel/Nilix-docs-private/tree/37baf8abb79e73d33a51a8e5e3d7a79e2adcf385/validation/console-display) · [Archive PR](https://github.com/Zero-kernel/Nilix-docs-private/pull/18)

## Recorded results and limits

- **Local.**
  - fmt, clippy, lint and the build pass.
  - The hosted sub-crate suites pass: 652 tests, of which two `drivers` tests are new.
  - With a rejected framebuffer selecting the text buffer again, both new tests fail.
- **Dev host, QEMU 8.2, beside the parent.**
  - The runtime group is GATE-QUALIFIED, and runtime at 4 and 16 vCPUs is QUALIFIED (3) with passed=47.
  - The strict group still FAILs on the remaining deferrals, with the parent's counts.
  - ring3-mm passes at 1, 4, 8 and 16 vCPUs, and the ST-K2-P2(c) final-owner oracle at 1 and 4.
  - The extended SMP harness is QUALIFIED (3) at 8, 16 and 32 vCPUs.
  - `No display: console output goes to the serial port only` appears once in every serial log of this revision and in none of the parent's.
- **STRESS-7.** All seven profiles at `STRESS_CPUS=4` and the four SMP profiles at `STRESS_CPUS=16` are QUALIFIED (3) over 900 s. The largest heartbeat gap is 8521 ms (`combined`, 16 vCPUs) against the 15000 ms bound.
- **Host time per thread** (the unmodified `thread` profile, 300 s, each run alone on the host, two counted runs a side).
  - 4 vCPUs: 42.2 ms on the parent, 17.5 ms here (−59%).
  - 16 vCPUs: 215.8 ms on the parent, 56.7 ms here (−74%).
  - Three more runs booted with an off-nominal LAPIC calibration and are not counted.
- **CI.**
  - PR CI passes (15 jobs).
  - Extended run 44013514236 on the branch: 29 of 30 lanes pass, and the two diagnostic strict jobs fail on the remaining deferrals, as on main.
  - **`ubuntu-24.04 / stress-thread` FAILED**: the guest stalled after 51356 waves.
- **The stall is a kernel bug that main has without this change**, fixed in #106.
  - The kernel cleared an exiting thread's `clear_child_tid` word one byte at a time, and musl's thread-list lock could take the half-cleared word for the reader's own TID.
  - It was reproduced on main's code. Per wave it is as frequent there: one stall per 548 thousand waves, against one per 481 thousand with this change.
  - This change runs 2.3 to 4 times as many waves in the same time, so a run meets the bug sooner.
  - With both changes, 2.42 million waves of the thread profile showed no stall.
- **With #106** (`diag/console-with-tid-store`, `3fc4340`: this change with #106 cherry-picked, not for merge).
  - Extended run 44069865484 passes 29 of 30 lanes, all thread lanes among them; its two diagnostic strict jobs fail on the remaining deferrals, as on main.
  - **`ubuntu-24.04 / stress-block` FAILED** there: none of its twelve crash attempts caught an active journal tail.
  - That failure does not need either change. In block-only runs, main's code fails 2 of 12 copies the same way (run 44084332843, both on ubuntu-24.04), and the two changes together pass 12 of 12 (run 44084308928). Its cause was not investigated.
  - The Extended run has not been repeated on this branch itself.

None of these results is a strict pass. All host-time figures are under TCG on one shared host; KVM and real hardware were not measured. Ordinary builds and public CI do not require the private archive.

The gates, CI, combined-run and block-capture receipts have aggregate status 1, from the remaining strict deferrals, the stalled Extended job and the block lane's capture failures. Individual statuses and log hashes are preserved.
