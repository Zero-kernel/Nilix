# STRESS-7 runs and THREAD-HB reruns

Detailed commands, host/environment identities and artifact hashes are retained in the private documentation repository. Access to the private archive is optional for ordinary builds and public CI.

## Rerun after the #92 fix

Source: `493452c9f1966c7fb58258ef57a990aea4152f27` (main after #96, before STRICT-Q S1).

[16-vCPU supplement](https://github.com/Zero-kernel/Nilix-docs-private/tree/fb0f2b67ac2ee882a8289f2efeb61584029843b6/validation/stress16-20261111) · [Original receipt archive](https://github.com/Zero-kernel/Nilix-docs-private/tree/fb0f2b67ac2ee882a8289f2efeb61584029843b6/validation/stress-7) · [Archive PR](https://github.com/Zero-kernel/Nilix-docs-private/pull/11)

### Recorded results and limits

- Required development-host matrix, supplemented on 2026-11-11: all seven profiles are QUALIFIED (3) on QEMU 8.2 (TCG), with the full 900-second requested scope. `STRESS_CPUS=16` selects 16 vCPUs for CPU/SMP/thread/combined; memory/process retain one and block two. No profile was retried and no workload or bound changed. The verified original source-bound kernel and generated disk were reused; this supplement does not claim a fresh build.
- The supplement's largest heartbeat gap is 11221.005 ms (combined), below the actual 15000 ms configured bound. The existing 3000 ms grace remains unchanged. CPU/SMP/combined retain 16-vCPU QMP progress evidence; block retains crash/recovery and filesystem-check evidence.
- The earlier four-vCPU development matrix also remains archived: all seven QUALIFIED (3), largest gap 3333.5 ms. Its combined bound metadata is corrected from the standalone protocol default of 30000 ms to the binary configuration's actual 15000 ms; measured outcomes and hashes are unchanged.
- [Extended run 42794672290](https://github.com/Zero-kernel/Nilix/actions/runs/42794672290) completed with aggregate `success` on this same source. All 22 non-diagnostic lanes are GATE-QUALIFIED on QEMU 6.2 (Ubuntu 22.04) and 8.2 (Ubuntu 24.04). Ubuntu 22.04 stress-combined's largest gap is 1254.3 ms, below the actual 15000 ms bound. Both strict jobs are diagnostic failures from remaining deferrals.

The required development-host topology and same-source Extended evidence are complete on `493452c`. These are QUALIFIED results, not strict passes, and they do not relabel this historical source as current-main qualification. STRICT-Q remains tracked by [#64](https://github.com/Zero-kernel/Nilix/issues/64).

### Continuous 16-vCPU coverage

[PR #100](https://github.com/Zero-kernel/Nilix/pull/100) retains the original four-vCPU coverage and adds eight required 16-vCPU CPU/SMP/thread/combined jobs across both Ubuntu images. On candidate `297d7d5`, [regular CI](https://github.com/Zero-kernel/Nilix/actions/runs/42950321223) passed all 15 jobs, and all 22 stress lanes in [Extended](https://github.com/Zero-kernel/Nilix/actions/runs/42950345865) are QUALIFIED, including all eight new 16-vCPU jobs. The Extended aggregate succeeded with all 30 required lanes; both strict jobs retain their documented diagnostic failures. This S1-containing CI source is recorded separately from the development-host supplement above.

## Attempt on `207ddbf`

Source: `207ddbfdd964a65770d7c4c203b2bd42ee71a419`.

[Immutable receipt archive](https://github.com/Zero-kernel/Nilix-docs-private/tree/32d7062ab675ecd0f6a224bf3b019beff9627528/validation/stress-7) · [Audit and archive PR](https://github.com/Zero-kernel/Nilix-docs-private/pull/8)

### Recorded results and limits

- Dev-host seven-profile matrix: all seven profiles reported QUALIFIED (3), QEMU 8.2, 900-second requested scope, unchanged bounds. `STRESS_CPUS=4` is the harness setting; memory/process use one vCPU and block uses two under the existing profile policy.
- THREAD-HB: four 900-second runs at 4/16 vCPUs on QEMU 6.2/8.2 reported QUALIFIED (3), with maximum heartbeat gaps of 351.3/510.0/3784.8/4629.2 ms, below the unchanged 15-second bound. These are source-bound historical results, not new runs performed by the PR audit.
- [Extended run 42761253826](https://github.com/Zero-kernel/Nilix/actions/runs/42761253826): 18 qualified lanes; Ubuntu 22.04 stress-combined failed on a stale heartbeat (412623 ms); three lanes were cancelled during setup before a guest ran. Both strict jobs are diagnostic failures.

**STRESS-7 is not met on this source.** The observed scheduler stall is tracked in [#92](https://github.com/Zero-kernel/Nilix/issues/92). The recorded THREAD-HB reruns do not close STRESS-7, STRICT-Q, C3 or the full-audit requirement.

Raw dev-host logs and disks are not committed in either this public index or the receipt imports.
