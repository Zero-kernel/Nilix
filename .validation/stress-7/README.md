# STRESS-7 attempt and THREAD-HB reruns

Source: `207ddbfdd964a65770d7c4c203b2bd42ee71a419`.

Detailed commands, host/environment identities and artifact hashes are retained in the private documentation repository:

[Immutable receipt archive](https://github.com/Zero-kernel/Nilix-docs-private/tree/32d7062ab675ecd0f6a224bf3b019beff9627528/validation/stress-7) · [Audit and archive PR](https://github.com/Zero-kernel/Nilix-docs-private/pull/8)

## Recorded results and limits

- Dev-host seven-profile matrix: all seven profiles reported QUALIFIED (3), QEMU 8.2, 900-second requested scope, unchanged bounds. `STRESS_CPUS=4` is the harness setting; memory/process use one vCPU and block uses two under the existing profile policy.
- THREAD-HB: four 900-second runs at 4/16 vCPUs on QEMU 6.2/8.2 reported QUALIFIED (3), with maximum heartbeat gaps of 351.3/510.0/3784.8/4629.2 ms, below the unchanged 15-second bound. These are source-bound historical results, not new runs performed by the PR audit.
- [Extended run 42761253826](https://github.com/Zero-kernel/Nilix/actions/runs/42761253826): 18 qualified lanes; Ubuntu 22.04 stress-combined failed on a stale heartbeat (412623 ms); three lanes were cancelled during setup before a guest ran. Both strict jobs are diagnostic failures.

**STRESS-7 is not met on this source.** The observed scheduler stall is tracked in [#92](https://github.com/Zero-kernel/Nilix/issues/92). The recorded THREAD-HB reruns do not close STRESS-7, STRICT-Q, C3 or the full-audit requirement.

This PR changes no executable code. Raw dev-host logs and disks are not committed in either this public index or the receipt import. Access to the private archive is optional for ordinary builds and public CI.
