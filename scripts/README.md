# CI and test scripts

The scripts are grouped by the job they support so a test entrypoint has one
obvious home. CI calls `ci/entrypoint.sh`; the other directories contain the
individual gates and supporting tools.

| Directory | Purpose |
| --- | --- |
| `ci/` | Shared CI entrypoint, gate receipts, input manifests, logs and reports |
| `gates/boot/` | Boot, runtime, musl and SMP guest checks |
| `gates/qemu/` | QEMU, KCOV, IOMMU and mitigation checks/probes |
| `gates/stress/` | Stress-v2 orchestration and protocol validation |
| `gates/performance/` | Performance and sustained-load checks |
| `fuzz/` | AFL++ helpers, corpus generation and fuzz reports |
| `tools/` | Hosted crate tests, source lints, ABI oracle and disposable ESP copies |
| `tests/` | Python and shell regression tests for the script and evidence layers |

Run the same grouped checks locally and in Actions:

```sh
bash scripts/ci/entrypoint.sh quality
bash scripts/ci/entrypoint.sh runtime
```

Each group writes a fresh receipt directory under `target/ci/<group>/run.*`.
The receipt contains the command, exit status, duration, source identity and
raw evidence. Python tests also publish JUnit and coverage files through the
`quality` group.
