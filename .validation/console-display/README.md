# Console display change validation

Source: `e1d0ad3d9efe89cc5e5435a72d5b1685ab2dd3aa` on `fb4093e` (main after #106).

- `d33ea64` is the change, made on `e828bd0` (main after #104).
- `24d947d` merges main with #106 into the branch.
- `e1d0ad3` fixes the finding of the review of this PR.

Detailed commands, environment identities and artifact hashes are archived in the private documentation repository:

[Immutable receipt archive](https://github.com/Zero-kernel/Nilix-docs-private/tree/511170ffac3e53874d30b5ccb508d13f4082ac83/validation/console-display) · [Archive PR](https://github.com/Zero-kernel/Nilix-docs-private/pull/18)

## Recorded results and limits

- **Local**, on each of the three revisions.
  - fmt, clippy, lint and the build pass.
  - The hosted sub-crate suites pass: 655 tests on `e1d0ad3`, of which three `drivers` tests are new.
  - With a rejected framebuffer selecting the text buffer again, the three new tests fail.
- **Dev host, QEMU 8.2, `d33ea64` beside its parent.** These gates were not repeated after the merge.
  - The runtime group is GATE-QUALIFIED, and runtime at 4 and 16 vCPUs is QUALIFIED (3) with passed=47.
  - The strict group still FAILs on the remaining deferrals, with the parent's counts.
  - ring3-mm passes at 1, 4, 8 and 16 vCPUs, and the ST-K2-P2(c) final-owner oracle at 1 and 4.
  - The extended SMP harness is QUALIFIED (3) at 8, 16 and 32 vCPUs.
  - `No display: console output goes to the serial port only` appears once in every serial log of this revision and in none of the parent's.
- **STRESS-7** (`d33ea64`). All seven profiles at `STRESS_CPUS=4` and the four SMP profiles at `STRESS_CPUS=16` are QUALIFIED (3) over 900 s. The largest heartbeat gap is 8521 ms (`combined`, 16 vCPUs) against the 15000 ms bound.
- **Host time per thread** (`d33ea64`; the unmodified `thread` profile, 300 s, each run alone on the host, two counted runs a side).
  - 4 vCPUs: 42.2 ms on the parent, 17.5 ms here (−59%).
  - 16 vCPUs: 215.8 ms on the parent, 56.7 ms here (−74%).
  - Three more runs booted with an off-nominal LAPIC calibration and are not counted.
- **CI on `d33ea64`.**
  - PR CI passes (15 jobs).
  - Extended run 44013514236: 29 of 30 lanes pass, and the two diagnostic strict jobs fail on the remaining deferrals, as on main.
  - **`ubuntu-24.04 / stress-thread` FAILED**: the guest stalled after 51356 waves.
- **The stall was a kernel bug that main had without this change.** #106 fixed it and is merged.
  - The kernel cleared an exiting thread's `clear_child_tid` word one byte at a time, and musl's thread-list lock could take the half-cleared word for the reader's own TID.
  - It was reproduced on main's code. Per wave it was as frequent there: one stall per 548 thousand waves, against one per 481 thousand with this change.
  - This change runs 2.3 to 4 times as many waves in the same time, so a run met the bug sooner.
  - With this change and the first form of #106, 2.42 million waves of the thread profile showed no stall. An Extended run of the two (44069865484, `diag/console-with-tid-store`, not for merge) passed 29 of 30 lanes; its `ubuntu-24.04 / stress-block` lane failed its crash capture, which main's code did as well in 2 of 12 block-only copies (run 44084332843).
- **After the merge of main with #106** (`24d947d`).
  - PR CI passes (15 jobs).
  - Extended run 44463835789 on the branch passes all 30 lanes. The two diagnostic strict jobs fail on the remaining deferrals, as on main.
  - The four thread lanes are QUALIFIED (3) without a stall; the two at 4 vCPUs ran 44444 and 62494 waves.
  - Both block lanes caught the journal tail at the first crash attempt.
- **The review finding**, fixed in `e1d0ad3`.
  - When the memory-map check accepted a framebuffer and the driver refused its geometry, the kernel wrote `Framebuffer console initialized` and no `No display` line, although the boot had no display.
  - QEMU does not reach that path. In a boot with an edit that forces it, `24d947d` writes `Framebuffer console initialized` alone, and `e1d0ad3` writes `Framebuffer rejected: geometry does not fit its region` and the `No display` line.
  - Without the edit, `e1d0ad3` writes `Framebuffer rejected: not covered by memory map` and the `No display` line, as the branch did before the fix.
  - The three boots are the 4-vCPU runtime gate on the dev host, each QUALIFIED (3) with passed=47.
- **CI on `e1d0ad3`.**
  - PR CI passes (15 jobs).
  - Extended run 44661871491 on the branch passes all 30 lanes. The two diagnostic strict jobs fail on the remaining deferrals, as on main.
  - The four thread lanes are QUALIFIED (3) without a stall; the two at 4 vCPUs ran 43999 and 62483 waves.
  - Both block lanes caught the journal tail at the first crash attempt.

None of these results is a strict pass. All host-time figures are under TCG on one shared host; KVM and real hardware were not measured. The driver's refusal was forced by an edit, and the notice after a failed high-half mapping of the framebuffer was not driven. Ordinary builds and public CI do not require the private archive.

The gates, CI, combined-run and block-capture receipts of `d33ea64` have aggregate status 1, from the remaining strict deferrals, the stalled Extended job and the block lane's capture failures. The receipts of `24d947d` and `e1d0ad3` have status 0, and the review check 3. Individual statuses and log hashes are preserved.
