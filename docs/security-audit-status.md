# Security Audit and Qualification Status

**Updated:** 2026-09-14 · **Current source:** local P0-A implementation working tree; remote exact-tree gates recorded in the P0-A validation copy.
**Release:** 1.0-Preview **BLOCKED**; recorded clean full-audit streak **0/3**.

This document separates historical audit closure, scoped repair evidence and
current release qualification. It is not a new security audit. Component
capabilities are in the [roadmap](roadmap.md); remaining work is in the
[current nextplan](next-phase-plan.md).

## Current acceptance

| Evidence set | Accepted result | Boundary |
| --- | --- | --- |
| KSA-2026-09-06 | KSA-001..020 accepted within their original rubrics | Does not close unrelated R186/R188/feature debt or qualify every platform |
| KSA plan | 17/18 scoped complete; P3-2 partial | Physical VT-d qualification remains unavailable |
| P0-A/R186-4 implementation | Admission-first fork snapshot, reservation handoff and fallible VMA oracles applied; exact final source remotely verified in `/tmp/zero-os-codex-final-20260913` on `40c-devbox-ts` (MM 26/26, kernel-core 68/68, hosted/build/lint PASS) | Runtime/boot/SMP are zero-failure qualified with deferred checks and musl is incomplete because required guest markers are absent; strict guest/platform qualification remains pending |
| RF180-20 | Shared supervisor page-table teardown/COW/fresh-exec ownership repaired and independently reviewed | Final v51 workload/source evidence; later changes need affected-path regression |
| P3-2 QEMU continuation | Q35/EDU nonidentity DMA, mapping replacement, remapped MSI, fault quarantine/detach and IRTE reuse accepted | Physical endpoints, MSI-X and broad topology are separate rows |
| CI on e127c34 | Hosted debug/release reached 63 vfs tests but the allowlist still expected 62; QEMU jobs were independently in progress/failed during this run | Count fix is in the current tree; complete rerun is required |
| Current hosted definition | Remote validation copy: 438 counted executions/profile, CpuLocal doctest and three compile checks; current local allowlist: 439 after the MM regression and VFS 63-test tree | The remote copy retains a pre-existing VFS 62-test baseline; this is a host-safe allowlist, not full privileged execution or code coverage |

The final KSA review (`reviewfix-2026-09-11-v2.md`) records
14/14 remaining findings PASS scoped, adding to the six previously accepted.
The P0 review and QEMU device evidence identified in the [source ledger](#record-provenance)
preserve the actual scope, source hashes, commands and guest outcomes.
Historical temporary artifact paths are not a substitute for reproducible
public gate definitions or a later exact-tree run.

## Carried release obligations

- **R186-4 / P0-A / D1-RES-HEAP-ADMISSION-REOPENED:** The implementation reserves CoreProcess admission before fork snapshot allocation, transfers one reservation into the admitted map, removes infallible `shrink_to_fit`, and preserves ordered backing/reservation cleanup on constructor and map mismatch paths. The induced COW/PT/child-publication oracle passes, with two independent U23 lenses and final remote MM 26/26, kernel-core 68/68, hosted, build and lint verification passing on `/tmp/zero-os-codex-final-20260913` on `40c-devbox-ts`. Runtime/boot/4-core SMP are zero-failure qualified; valid-prefix/KPTI-allocation-failure variants, the bounded CorruptState fail-stop policy, musl markers and strict guest/platform qualification remain explicit limits.
- **R188 review lineage:** August remediation is recorded, but the newer KSA
  verdicts cover a different rubric. Reconcile original IDs to current source/
  independent review and review uncovered rows. Reuse exact accepted overlaps;
  do not claim the entire historical obligation automatically closed.
- **Stress-v2:** the recorded September 1 user decision requires all six
  profiles for Preview. MAP_SHARED and durability/workload gaps prevent a full
  accepted run. Scheduled/diagnostic execution is not release acceptance.
- **Strict profiles and audit cadence:** qualified warnings/deferred/skipped
  outcomes cannot satisfy strict qualification. No new full clean round is
  recorded here, so the 0/3 streak does not advance.

The supported release scope also needs a coherent ABI and device/CPU matrix.
There is no fresh all-kernel open-finding census in this documentation update;
the carried HIGH is not a guarantee that no other defects exist.

## Historical lineage

| Record | Historical disposition |
| --- | --- |
| R186 / RF186 (source ledger below) | 16/17 actionables repaired; RF186-1..24 repaired; R186-4 carried |
| R187 / RF187 (source ledger below) | Seven KCOV findings and eight repair defects closed; no carried-debt streak credit |
| [R188 standalone](security/full-codebase-audit-2026-08-07.md) | 2026-09-13 reviewfix maps all 131 originals: 123 PASS, 3 PARTIAL, 5 verification pending; no clean-round credit |
| KSA audit / final review (source ledger below) | September 20/20 scoped findings accepted; not a new R-series clean round |
| P3-2 continuation (source ledger below) | QEMU endpoint qualification slice accepted September 12; physical rows pending |

The archive records 187 R-series rounds through R187, with R188 and the
September KSA work separately named. Approximate lifetime finding totals from
older pages include refuted/merged IDs; they are not maintained as current
security percentages.

## Record provenance

The table above summarizes inspected maintainer archives. These original records
and temporary raw artifacts are not all distributed in a normal clone. The
following SHA-256 values identify the exact local record bytes used for this
rollover; a hash identifies a document, not an independently rerun test.
Paths are relative to `docs/review/`.

| Record | SHA-256 |
| --- | --- |
| `audits/qa-2026-07-16.md` | `39943b33ef70e1bc6f6adc421051f0424fc4a2c0880cedf17d09617aaa6e16aa` |
| `audits/qa-2026-07-20.md` | `defafdd46ed29fa48cdd55208c3bc84fcd3295b25b788fb1cc0802fee8456da8` |
| `audits/qa-2026-07-28.md` | `a35a91f0d82acf04c6e1c0339fdabdef9f4f4f551b49f5ef1eb2273b56acd665` |
| `reviewfix/reviewfix-2026-07-30.md` | `39c35286ca40076b4c013252f2d173cd4659e1d8e7473af499003d6f27e2d00a` |
| `audits/qa-2026-08-05.md` | `e8b4a205539e7762d89febd9c86a2eadc1210d8cea4c1a697681276ba93c0270` |
| `reviewfix/reviewfix-2026-08-08.md` | `d73940f5650d526e75d364573aac4549c2440555229f6499dc793aa9820d0031` |
| `audits/qa-2026-09-06.md` | `16812633ba68570e69957b7a5978082501ef6f0a7e089b630f5716e66b4ac6d4` |
| `fixes/ksa-2026-09-06-independent-review.md` | `9a435aeb41f9aaab4771bb8b88c33fd7d01c3ea91f7ed3226859bbb4446684c6` |
| `reviewfix/reviewfix-2026-09-11-v2.md` | `b0de4b11d36ca2be9c208c7eace71d6387a08101244d8ad5f7acd8faa227f92a` |
| `fixes/p3-2-qemu-device-evidence-2026-09-12.md` | `599206953900966ea5d6b93663c2a8d28998fcea2f70127ff5ce7e4ad86cdbae` |
| `nextplan/next-phase-plan-2026-08-01.md` | `fe08be4b6bd43cb2e1884b3164ba769ec257b0d608895e84ad3b24123af04971` |
| `nextplan/next-phase-plan-2026-09-01.md` | `a40bb83b923b252783b31f26707da99661a5aeae7ab9a1acd6d2ee216682bc8d` |
| `nextplan/next-phase-plan-2026-09-06.md` | `fe837abbc46cad1d3a247db746cf14ae7e018d2e78ddeda954c178c40ee3a499` |
| `nextplan/next-phase-plan-2026-09-11.md` | `04d41728494e89b091661a67b8d53d67e49db00367728e028d761cd17df52613` |

The final KSA v51 input manifest is
`7d18459ccc243fc86a1a70040b697fad34f6cfaab2bfee6fe2bf4e3602102d86`;
the P3-2 v3 input manifest is
`eb743fc0d2533717236821a6eb03bc74bef8df1dab92a6b1487faec26157409e`.
Those historical input identities differ from the current Git revision.
The [CI guide](ci-testing.md) and [VT-d matrix](vtd-support-matrix.md) supply
public reproduction entrypoints and supported-mode boundaries. Missing original
The 2026-09-13 reviewfix report maps all 131 original R188 rows to current source
and independent review. U16-1 remains partial; U23-1/U23-2 safe API paths now pass two
independent lenses, with intentional CorruptState fail-stop retained as a policy residual.
U34-1 and U46-1 remain verification pending for focused live oracles; U37-1, U55-6 and U29-3
remain explicit design or feature limits.

## Explicit support limits

Full KPTI isolation is unsupported: dual roots still retain kernel data/heap/
stacks and low aliases. Compiler retpoline is unsupported and its feature fails
compilation. KSA-020 validates truthful reporting/generated behavior, not full
mitigation. Secure/Balanced/Performance names and FIPS policy/KATs are not
certification or a complete hardware protection promise.

[Livepatch](livepatch-support.md) is unsupported/ENOSYS. The
[VT-d support matrix](vtd-support-matrix.md) distinguishes QEMU legacy/EDU
evidence from physical, multi-unit, bridge, RMRR, ACCESS_PLATFORM and modern-mode
requirements. General Linux/glibc/pthread/OCI support is not established.

Current tests and retained reports:
[CI](ci-testing.md), [quality gates](quality-gates.md),
[hosted allowlist](../scripts/tools/hosted_subcrate_tests.sh).
Report vulnerabilities privately using [SECURITY.md](../SECURITY.md).
