# CI and test coverage

This is the contributor map for CI and its local equivalents. The September 12,
2026 cleanup groups required checks in `CI`, bounded scheduled VM checks in
`Extended tests`, and private campaigns in `Fuzzing`. Triage and stale-issue
automation are repository maintenance, not test results.

The script layout is documented in [`scripts/README.md`](../scripts/README.md);
all workflow jobs use the shared `scripts/ci/entrypoint.sh` dispatcher and the
same grouped commands are available locally.

## Workflow map

| Entry | When | Coverage and result |
| --- | --- | --- |
| `CI` | Push/PR to main; manual | Quality, hosted debug/release, tools, kernel build, boot/SMP, musl, IOMMU, mitigation, KCOV/executor; one `CI result` |
| `Extended tests` | Sunday 03:00 UTC; manual | Ubuntu 22.04/24.04, 8/16 CPU SMP, Ext3/JBD2, six 900-second stress profiles, IOMMU compatibility |
| `Fuzzing` | Daily 02:00 UTC; manual | 11 private libFuzzer campaigns, opaque candidate handling, validated public result manifests |

The disabled AFL QEMU workflow could not execute a bare-metal kernel. The old
standalone syzkaller workflow duplicated the shared QEMU executor and swallowed
process failures. Both workflow files are retired; executor code and local
development commands remain available. Simulator plumbing is exercised by
the required fuzz-tool regression suite.

## Local commands and reports

Install the pinned toolchain in `rust-toolchain.toml`, GNU make, QEMU, OVMF,
musl-tools and e2fsprogs on Linux. For Python harness tests, install
`python3 -m pip install -r requirements-ci.txt` in a virtual environment.

| Group | Command |
| --- | --- |
| Source gates and every Python harness regression | `bash scripts/ci/entrypoint.sh quality` |
| Rust format/lint | `make fmt-check` and `make clippy` |
| Kernel hosted allowlist | `make test-hosted-subcrates` |
| Optimized hosted allowlist | `HOSTED_TEST_PROFILE=release make test-hosted-subcrates` |
| Fuzz tools, all fuzz features, host executor | `bash scripts/ci/entrypoint.sh tools` |
| Normal image and usercopy | `bash scripts/ci/entrypoint.sh build` |
| UP boot/runtime and four-CPU SMP | `bash scripts/ci/entrypoint.sh runtime` after the build group |
| Static musl on one and four CPUs | `bash scripts/ci/entrypoint.sh musl` |
| Q35 activation, init failures and EDU DMA/MSI | `bash scripts/ci/entrypoint.sh iommu` |
| Four-CPU CR3/CPL3 proof | `bash scripts/ci/entrypoint.sh mitigation` |
| Adapter tests and real KCOV/executor smoke | `bash scripts/ci/entrypoint.sh qemu-fuzz` |
| Scheduled extended scope | `bash scripts/ci/entrypoint.sh extended` |

Reports live under a fresh `target/ci/<group>/run.*/` for every invocation:
`summary.md`, `gates.junit.xml`, command receipts and raw logs. The group's top-level
`summary.md` points to the latest results without combining prior failures or
cached receipts into the current run. Quality also produces native per-test `python.junit.xml`
and HTML/XML/JSON Python coverage. Set `HOSTED_TEST_LOG_DIR` to retain individual
Rust suite logs, `hosted.junit.xml`, and its verified count table. Actions publishes each group's
summary on its run page and retains the full directory as an artifact.
Guest/QEMU gates perform one bounded retry after an exit-1 failure or incomplete
exit-2 result (`CI_GUEST_RETRIES=1`, the default). Both attempts remain under the
same artifact directory, the report labels the retry, and `retry.log` records the
decision. Set `CI_GUEST_RETRIES=0` to disable it. Host/build checks remain
single-shot.

The core CI jobs allow up to 30--60 minutes for build and guest work. Boot,
runtime/SMP and musl collectors use a 600-second (10-minute) observation window
per invocation; the runtime group therefore has three sequential 10-minute
windows. Mitigation, KCOV/fuzz and extended stress keep their 900-second
(15-minute) workload windows. The aggregate report has a 15-minute reporting
budget. Extended stress runs use 900 seconds per profile and a 180-minute job
budget; scheduled fuzz campaigns use up to 900 seconds per target and a
45-minute job budget.

Use `CI result` as the single required status check when configuring branch
protection. No branch-protection settings are changed by this patch.

## Design and acceptance

- Keep one required entrypoint for pushes and pull requests, with an always-run
  aggregate result. A failed, cancelled or unexpectedly skipped required job
  must not become a green aggregate.
- Reuse the pinned Rust setup and common gate recorder. Build normal boot inputs
  once for the runtime matrix. Keep feature-specific ESPs separate.
- Extend meaningful coverage with hosted debug/release tests, one- and four-CPU
  runtime/musl checks, all Python harness regressions, and scheduled VM profiles.
  Only the explicit hosted allowlist may run in a host process; kernel-wide
  `--all-features` is invalid because unsupported and terminal features conflict.
- Publish Markdown summaries, JUnit and retained logs with exit status, duration
  and source identity. Runtime Warning/Deferred/Skipped remain visible; qualified
  exit 3 may be accepted by diagnostic CI only. Strict mode still rejects it.
- Python coverage describes host test/collector code, not kernel instruction
  coverage. Guest evidence, executed test counts and source coverage are separate.
- Do not mask failures with unbounded retries, `continue-on-error` or `|| true`.
  Any bounded workload retry must emit an explicit serial record and preserve a
  final failure when the resource condition does not clear. Reporting must run
  after failures without replacing the command's original outcome.
- Remove inactive or duplicate campaign entrypoints. Preserve real KCOV and QEMU
  executor smoke checks in required CI; lengthy campaigns run on schedule/manual.

The mitigation repair targets collector overhead: the failed QEMU 8.2 run
34684048547 produced 644,300 RSP messages (77,615,561-byte transcript), 1,388 CR3
steps, and only 15 unique site/CPU observations in 300 seconds. Buffered reads
preserve packet framing, checksum, timeout and thread validation. Duplicate
site/CPU stops do not require repeated CPL3 proof after that pair was already
verified. All 17 unique observations and the complete fork/exec workload remain
required. CI allows a 900-second collector deadline for slower hosted QEMU
versions; boot/runtime/SMP and musl use the shorter 600-second window because
their normal completion path is bounded and independently reported. The
workload emits bounded, per-attempt evidence when concurrent
fork/exec allocation transiently returns ENOMEM; a non-recovering exec failure
still fails the gate. Linux QEMU 6.2 validation passes all 17 observations and
the complete workload, and `mitigation_check_test.py` passes its 48 regression
cases.

## Reference designs

The following upstream designs informed the organization; repository-specific
code and policies are not copied wholesale:

- [rust-lang/rust CI](https://github.com/rust-lang/rust/blob/main/.github/workflows/ci.yml):
  explicit job grouping, reusable environment setup, and metrics in step summaries.
- [Arrow Rust tests](https://github.com/apache/arrow-rs/blob/main/.github/workflows/arrow.yml)
  and [workspace checks](https://github.com/apache/arrow-rs/blob/main/.github/workflows/rust.yml):
  debug/release and feature configurations, with focused crate test boundaries.
- [AstrBot unit tests](https://github.com/Xero-Team/AstrBot/blob/master/.github/workflows/unit_tests.yml)
  and [coverage](https://github.com/Xero-Team/AstrBot/blob/master/.github/workflows/coverage_test.yml):
  separate test/coverage reporting, manual runs, and matrix jobs that finish independently.
