# STRESS-7 runs and THREAD-HB reruns

Detailed commands, host/environment identities and artifact hashes are retained in the private documentation repository. Access to the private archive is optional for ordinary builds and public CI.

## Rerun after the #92 fix

Source: `493452c9f1966c7fb58258ef57a990aea4152f27` (main after #96).

[Immutable receipt archive](https://github.com/Zero-kernel/Nilix-docs-private/tree/d66f1a9a7d7303540af526cf4c154a6d86d92a43/validation/stress-7) · [Archive PR](https://github.com/Zero-kernel/Nilix-docs-private/pull/11)

### Recorded results and limits

- Dev-host seven-profile matrix: all seven profiles reported QUALIFIED (3) on QEMU 8.2 (TCG), with the 900-second requested scope and unchanged bounds. No heartbeat gap exceeded its bound; the largest was 3333.5 ms (combined, 30-second bound). `STRESS_CPUS=4` is the harness setting; memory/process use one vCPU and block uses two under the existing profile policy. The seven ran concurrently on one shared host.
- [Extended run 42794672290](https://github.com/Zero-kernel/Nilix/actions/runs/42794672290) completed with aggregate `success`. All 22 non-diagnostic lanes are GATE-QUALIFIED on QEMU 6.2 (Ubuntu 22.04) and 8.2 (Ubuntu 24.04). That includes Ubuntu 22.04 stress-combined, the lane that stalled on `207ddbf`; its largest heartbeat gap was 1254.3 ms. Both strict jobs are diagnostic failures from the remaining deferrals.

On this source, all seven profiles are QUALIFIED on one source identity and `Extended tests` completed. These are QUALIFIED results, not strict passes; strict qualification is tracked by STRICT-Q (#64).

## Attempt on `207ddbf`

Source: `207ddbfdd964a65770d7c4c203b2bd42ee71a419`.

[Immutable receipt archive](https://github.com/Zero-kernel/Nilix-docs-private/tree/32d7062ab675ecd0f6a224bf3b019beff9627528/validation/stress-7) · [Audit and archive PR](https://github.com/Zero-kernel/Nilix-docs-private/pull/8)

### Recorded results and limits

- Dev-host seven-profile matrix: all seven profiles reported QUALIFIED (3), QEMU 8.2, 900-second requested scope, unchanged bounds. `STRESS_CPUS=4` is the harness setting; memory/process use one vCPU and block uses two under the existing profile policy.
- THREAD-HB: four 900-second runs at 4/16 vCPUs on QEMU 6.2/8.2 reported QUALIFIED (3), with maximum heartbeat gaps of 351.3/510.0/3784.8/4629.2 ms, below the unchanged 15-second bound. These are source-bound historical results, not new runs performed by the PR audit.
- [Extended run 42761253826](https://github.com/Zero-kernel/Nilix/actions/runs/42761253826): 18 qualified lanes; Ubuntu 22.04 stress-combined failed on a stale heartbeat (412623 ms); three lanes were cancelled during setup before a guest ran. Both strict jobs are diagnostic failures.

**STRESS-7 is not met on this source.** The observed scheduler stall is tracked in [#92](https://github.com/Zero-kernel/Nilix/issues/92). The recorded THREAD-HB reruns do not close STRESS-7, STRICT-Q, C3 or the full-audit requirement.

Raw dev-host logs and disks are not committed in either this public index or the receipt imports.
