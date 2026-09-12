# Zero-OS Next-Phase Plan — 2026-09-12

**Version:** 16.0 · **Stage:** kernel-next-phase, full rollover
**Source:** e127c34; this plan incorporates the runtime parser, transient mount
and hosted-count follow-ups as verification-pending implementation records.
**Mode:** source/record reconciliation and documentation; no kernel implementation or new audit.
**Inputs:** September 11 status addendum, September 6 KSA plan, September 1
complete queue, August 1 legacy queue, final KSA review-fix and P3-2 QEMU evidence.
The [plan index](README.md) and [source ledger](../../security-audit-status.md#record-provenance)
identify these local historical records and their hashes. This current plan
and its handoff designs are distributed in Git.
**Status:** KSA software closeout preserved; admission/stress/feature backlog restored.
Preview BLOCKED; clean full-audit streak 0/3.

## 1. What this rollover changes

The September 11 file is a status addendum for one task, not a complete backlog.
The September 6 plan preserves 18 KSA-related items but omitted older admission,
stress and feature queues. This document becomes the current dated plan and
conserves both lineages. Historical records remain unchanged.

The [rebuilt roadmap](../../roadmap.md) is the component capability inventory.
This plan owns execution order, dependencies, acceptance conditions and open-item
conservation. It does not grant implementation permission through a status label.

No new vulnerability census or clean audit round was performed. The carried
R186-4 HIGH is still unresolved: current fork allocates its snapshot before
admission; AdmittedMap::from_sorted_vec_charged still uses shrink_to_fit.
Conversely cwd, standard FDs, VFS credentials/paths/retirement, TLS, owned BIO,
4K geometry, real fuzzing and truthful outcomes must not be re-listed as wholly
unimplemented after the accepted KSA repairs.

## 2. Accepted KSA work — regression obligations

All 18 IDs from the September 6 plan are retained here. A DONE row refers to the
original acceptance rubric, not full Linux/platform/feature completeness.

| IDs | Disposition | Scope and continuing limit |
| --- | --- | --- |
| P0-1 | DONE scoped | KSA-001 Q35 MMIO/init/failure retention; physical/topology breadth stays P3-2 |
| P0-2 | DONE scoped | KSA-002 exact usercopy fixup/robust cleanup |
| P0-3 | DONE scoped | KSA-003 transactional namespace resource/four-CPU probes |
| P0-4 | DONE scoped | KSA-004 O_TRUNC rejection preserves data and publication |
| P0-5 | DONE scoped | KSA-005 ordinary standard descriptors and inheritance |
| P1-1 | DONE scoped | KSA-006 failed/incomplete summaries cannot pass |
| P1-2 | DONE scoped | KSA-007 two authenticated real-QEMU seeds, coverage, identity/classification |
| P1-3 | DONE scoped | KSA-008 five-way outcomes/owned reasons/strict rejection; deferred execution remains |
| P1-4 | DONE as unsupported | KSA-009 ENOSYS/nonallocating queries; future livepatch is separate |
| P1-5 | DONE scoped | KSA-010 cwd/root/pivot/path lifecycle; general CLONE_FS/dirfd not implied |
| P1-6 | DONE scoped | KSA-011/012/013 wait/signal/file status/NOFILE; pthread/other rlimits not implied |
| P2-1 | DONE scoped | KSA-015 VFS namespace-table retirement |
| P2-2 | DONE scoped | KSA-016 component resolution/jails |
| P2-3 | DONE scoped | KSA-014 credentials/host IDs and ownership compatibility |
| P2-4 | DONE scoped | KSA-017 CpuLocal lifetime and TLS/IRQ/SMP evidence |
| P2-5 | DONE scoped | KSA-018/019 BIO ownership and 512B/4096B contracts |
| P3-1 | DONE scoped | KSA-020 generated/mapping/CR3/CPL3/workload proof; full KPTI/retpoline unsupported |
| P3-2 | PARTIAL / verification pending | Q35/EDU DMA/MSI/invalidation/fault slice accepted; physical qualification pending |

The latest review records 20/20 KSA findings accepted, 17/18 plan items complete,
and the repaired RF180-20 page-table lifetime defect. Do not use these scoped
counts to erase R186/R188/stress debt.

## 3. Execution order and first handoff group

**NEXT**: R188-RF — reconcile original R188 findings to current source and
independent acceptance evidence; review originals not covered by KSA. This
preserves the recorded September 1 dependency before P0-A closure credit.
A new blanket re-audit of already accepted, unchanged KSA fixes is unnecessary.

| Order / ID | Priority and state | Work / acceptance | Dependency |
| --- | --- | --- | --- |
| 1. R188-RF | Review stage; READY for scoped evidence reconciliation | Map every original R188 actionable to final source, review and applicable gate; independently review uncovered originals, preserve U37-1/U55-6/U29-3 limits; material defects re-enter by severity | August remediation + KSA overlap records |
| 2. P0-A / R186-4 | P0 HIGH; implementation present, closure OPEN | Admission before fork snapshot allocation; no infallible shrink; one amount-symmetric reservation/charge owner; live reserved/committed delta/failure/pressure/reclaim tests and independent mechanism review | R188-RF disposition before closure credit; serialize MM changes |
| 3. ST-K2-P1 | P1 ABI/stress; planned implementation | Whole mmap flags contract after policy hook; reject unsupported forms; pipe-based stress reports; memory/cpu/process profile evidence with a real cgroup-limit oracle | P0-A integration baseline and completed ST-K3; preserve prior two-phase decision |
| 4. ST-K4 | P1 durability/stress; design refresh required | fsync/fdatasync/sync/sync_file_range device-flush contract, policy/FD validation, guest block workload and crash/recovery oracle | ST-K2-P1; reconcile current file-object/namespace/BIO contracts |

Designs and current-source notes:
[handoff refresh](../design/next-handoff-2026-09-12.md),
[P0-A](../design/p0-a-r186-4-admission-closure-design.md),
[ST-K2](../design/st-k2-map-shared-design.md),
[ST-K4](../design/st-k4-fsync-writeback-design.md).

READY for a review action is not READY to modify all affected kernel code.
The old designs retain their decisions, but current-source high-risk amendments
must receive independent review before implementation acceptance. No new
interview is required for settled decisions.

## 4. Immediate follow-through and qualification

| ID | Priority / state | Concrete outcome and oracle |
| --- | --- | --- |
| F2 | P1, source concern retained | Review the no-current-user-frame fork fallback and caller contract. Preserve valid kernel-parent behavior or explicitly reject invalid Ring-3 state; test cleanup before child publication. No new exploit/severity claim from this rollover. |
| P1-A / D2-TST-GATING-POLARITY | P1, partially satisfied by KSA-008 | Reconcile the old 66-site obligations with current outcome records; retain missing-prerequisite owners and actual execution gaps. Do not redo the accepted five-way parser. |
| ST-K2-P2 | P1 feature, planned | Shared-anonymous parent/child visibility, no COW on either side, one PAGE_REF_COUNT owner, first-toucher charge and exact last-release; real SMP/usercopy/teardown/failure tests |
| STRESS-6 | Preview acceptance work | All memory/cpu/smp/process/block/combined profiles complete at the requested 900-second scope, with validated PASS/HEARTBEAT/resource/recovery evidence; qualified results remain separate |
| ST-K1 | P2, open | Seed init/root-cgroup task membership exactly once through the supported attach path; fork/migrate/delete/counter tests. The guest fork workaround is not closure evidence. |
| NET-QUAL | P2 test integration, open | Named virtio NIC/root-MAC profile runs netns RX lifecycle and external RX/TX oracles; independent packet observation where required; retain no-device negative controls |
| SMP-QUAL | P2 test integration, open | Run 2/4/8/16-CPU topology/affinity/exit/fork/TLB workloads with actual concurrency/configuration evidence; no claim of 64-CPU validation from a constant |
| SECURE-MATRIX | P3 platform qualification, open | Per-field negative tests for required capabilities, missing-IOMMU and CPU-mitigation modes. Unsupported fields must stay visible; a profile name is not certification. |
| P3-2 | P3 hardware qualification, external prerequisite | Named physical VT-d/endpoint/spec/DMAR tuple; translated/denied DMA, remapped IRQ, invalidation and quiescent teardown; update only measured support-matrix rows |
| PERF-BASELINE | P3, deferred until correctness baseline | Real workload/timing/counter baseline with variance and regression oracle; replace placeholder benchmark/thermal claims |

Dependency sequence: R188-RF → P0-A → ST-K2-P1 → ST-K4 → ST-K2-P2 →
six-profile acceptance. F2 triage and P1-A evidence reconciliation may proceed
without editing shared MM/entry files concurrently. Physical P3-2 and long-term
platform work do not block independent software tasks.

## 5. Carried design, lifecycle and test debt

The following are retained, not silently closed by the KSA task. Names without
original stable IDs are given descriptive tracking names; the legacy ID and
source group remain in the last column.

| ID / group | State / reason and next evidence | Lineage |
| --- | --- | --- |
| F7 | Open: contiguous eight-page kernel stacks/fragmentation and large PCB frames; inventory object/stack sizes before changing allocation | ST-K3 review |
| F4/F6 | Open: diagnostics while scheduler/PCB locks held, task attribution and compiled switch-resume sentinel | ST-K3 review |
| F10 | Open: mmap-window sweep currently checks one PDPT slot; document exact intent or broaden a discriminating test | ST-K3 review |
| F11 | Open: ESP-copy failure must prevent malformed QEMU drive argument; unique run ownership/cleanup remains necessary | ST-K3 review / ST-5 |
| W-3 | Open: selective wait over-wake/efficiency; test target matching and bounded wake work | ST-K3 review |
| W-4 residual | Covered in part by KSA-011 namespace exit identity; verify original nested-zombie rubric before administrative closure | ST-K3 review |
| ROOT-INIT | Open: PID1 absence/exit with orphan fallback; do not declare the old boot-hardening panic resolved | stress status §9 |
| U37-1a | Scoped reporting satisfied by KSA-020; full-isolation claim stays false | R188 KPTI honesty |
| U37-1b | Planned: minimal trampoline/entry mappings and full isolation; no feature flag can replace mapping/entry/exit/NMI proof | R188 KPTI capability |
| U55-6 | Open: boot identity-map writable/executable transition and all live aliases | R188 residual |
| U29-3 | QEMU IRTE retirement/reuse exercised; general VM-passthrough lifecycle still deferred until a consumer exists | R188 residual |
| D3-NETNS-DATAPLANE | Open: per-netns firewall admin, veth, real routes, child RX, TX loopback and all device-transfer pre-arming dependencies | F-7/F-9 |
| D3-NETNS-CONFIG-GENERATION | Deferred until production setter; generation tags required before enablement | R186 D3 |
| D3-NET-QUEUE-ATTRIBUTION | Retained; exact owner charge/fairness before raising queue/namespace limits | R186 D3 |
| D3-NET-CHILD-DRAIN-REACHABILITY | Retained as mandatory move-device precondition | R186 D3 |
| D3-SEC-NET-CONTROL-HOOK | Deferred to the network administration surface | R186 D3 |
| D4-ARC-ARP-PREPARED-OWNER | Retained ownership/type debt; review with ARP mutation | R186 D4 |
| D4-OPS-PENDING-COUNTERS | Retained diagnostics/counter debt | R186 D4 |
| D4-TST-PENDING-WIRE-ORACLE | Retained independent wire-test obligation | R186 D4 |
| D4-CTR-SATURATION | Retained counter saturation semantics | R186 D4 |
| D3-R37-1-TSYNC-CLONE-SIDE | Deferred until TSYNC; current syscall rejects TSYNC, so do not invent a live enabling path | F-5 |
| D3 ex-D2-ARC | Deferred compile-time tokens/front-door unification until native interfaces/Phase M | F-9 |
| D1-RES validation breadth | Retained multi-CPU class-cap interleavings, fragmentation and charge-model corpus beyond P0-A closure slice | P2 design queue |
| PO-SEC-01 | Open: July 20 rubric is credential-transition LSM hook coverage; reconcile overlap with accepted KSA credential lifecycle by each transition | July 20 PO ledger / F-9 |
| PO-SEC-02 | Open: July 20 rubric is temporal W^X (RW→RX denial) or alias tracking; current per-mapping W^X does not establish it | July 20 PO ledger / F-9 |
| PO-ISO-01 | Later-plan label retained; original rubric/alias not identified, verification pending before design | July 22–August queue / PO-LINEAGE |
| PO-SCHED-01 | Later-plan label retained; original rubric/alias not identified, verification pending before design | July 22–August queue / PO-LINEAGE |
| PO-SEC-03 / PO-TEST-01 / PO-LINEAGE | July 20 originals require post-boot LSM policy lockdown and U.S3 Ring-3 IPC loopback. Reconcile their disposition against later ISO/SCHED labels; do not assume a rename or closure | July 20 ledger / F-2/F-9 |
| RF186-24 | Open exact-fallback injection/branch-coverage debt | P3 |
| STORAGE-TESTS | Retain crafted ext2 and true readdir-OOM, created/renamed-image fsck and recovery evidence; real syz extraction now has KSA-007 proof | P3 / August ext2 residuals |
| DMA-TESTS | Retain physical hostile-PCI/DMA/IOMMU fixtures and device teardown | P3 / P3-2 |
| HOSTED-PRIVILEGED | Keep privileged suites QEMU-only or explicitly convert harnesses; no host SIGSEGV suppression | P3 |
| R184-7 / R184-42 | Retain release-vs-debug assertions/LockStack questions; no automatic refiling of previously refuted findings | P3 |
| R184-49 | Retain ADMIN-bit NET/SYS/per-namespace authority split | P3 / F-9 |
| STAT-UNITS | Retain st_blocks 512-byte units and dev_t encoding audit; matching layout alone is insufficient | P3 |
| S-7 | Retain source-placeholder tripwire; use actual scanner policy, not a calendar date as proof | P3 |
| CACHE-DEBT | Open error-refill-while-dirty, LRU-detach window, writeback-error channel and dirty-unreclaimable pressure | ST-K4 lens |
| UMOUNT-SYNC | Reconcile sync/invalidation and descriptor-pinned filesystem lifetime with new namespace retirement; test before closure | ST-K4 lens |
| FS-ID-ALIAS | Later filesystem identity repairs overlap; preserve original duplicate-mount/cache-owner oracle for explicit closure | ST-K4 lens / KSA VFS |
| R6 / WARNING-DOUBLE-COUNT | Five-way ownership/counting addressed by KSA-008; keep full old per-test rubric in P1-A reconciliation | P3 |
| SYZ-SYNC-ALLOWLIST | Deferred until 74/75/162/277 exist; update corpus/filters only with implemented durability contract | ST-K4 follow-on |
| MMAP-E8 | Retain commit rollback/release-assertion review; old diagnostic did not prove every failure unreachable | ST-K3 follow-on |

The later queue says 12 PO records, eight complete and four open, but its final
two labels do not match the July 20 source ledger (SEC-03/TEST-01 vs ISO-01/SCHED-01).
PO-LINEAGE retains both name sets until an explicit mapping exists; the historical
8/12 count is not a newly verified total. July 16 also reused SEC-01/02 for different
rubrics, so date/round and invariant must accompany an ID in the reconciliation.

## 6. Feature backlog — preserved, with corrected current premises

These remain behind release-directed correctness and qualification. Existing
implemented subparts must be reused rather than rebuilt.

| ID | Capability and missing work | Dependency |
| --- | --- | --- |
| F-1b | U.S2 slices 4/5: native_cap_op(604), native-number/filter parity, generation exhaustion errno | Delivered FileOps/pipe CapId wiring; authority/admission |
| F-1c | U.S2 slices 6/7: native invoke/spawn, endpoint_call/event_wait | U.S3 IPC design |
| F-2 | U.S3/U.S4: IPC/shared-memory lifecycle, cap-table fuzz, SMP dup/close/fork and native APIs | F-1 family; MM ownership |
| F-3 | Remaining VFS/termios: chown/statx/hard links/general dirfd and real terminal state; symlink/readlink/cwd already exist | Preserve accepted KSA paths/credentials/FDs |
| F-4 | Signals/thread ABI: sigaltstack, complete siginfo/restart/queued-RT, CLONE_SIGHAND/thread sharing, nanosleep remainder | Accepted wait/signal/TLS subset |
| F-5 | seccomp parity, exempt-list shrink/procmask promises and TSYNC; review clone-side membership together | D3-R37-1 re-scoping when enabled |
| F-6 | I.1 klog caller/profile/redaction sweep; lint/macros exist | Preserve forced fatal output policy |
| F-7 | I.3/I.4/I.5/I.7 DMA/boot/arch/invariant closure; netns FD, root device seeding, per-ns authority, generations/drain, namespace-drop rehoming | P3-2 support matrix and F-9 authority where needed |
| F-8 | J.2 kmem.current ABI, PT/slab/conntrack accounting and resource observability | P0-A capacity/ownership model |
| F-9 | Phase K/L/M ABI breadth, measured performance, enterprise isolation/operations and compile-time authority tokens | Correctness/release gates; no enterprise-ready claim |
| F-10 | Phase U.S4–S7: personality → dynamic ELF/ld.so/vDSO/user ASLR → glibc → OCI | U.S3/native IPC, static ABI and containers/network |

P0/P1 fixes precede P2/P3 cleanup; H.0/H/I/J/K/L/M expansion respects actual
prerequisites. Phase letters are historical work families, not evidence that all
features in a phase are complete.

## 7. Release conditions and metrics

| Metric / gate | Current value |
| --- | --- |
| KSA findings accepted | 20/20 within original scopes; no new full audit performed here |
| KSA plan items | 17/18 scoped complete; P3-2 partial |
| Carried audit HIGH | R186-4 remains open; current-source pre-admission/shrink paths reconfirmed |
| R188 review lineage | Reconciliation/independent uncovered-scope review pending |
| Zero-HIGH streak | 0/3, unchanged; no fabricated next round number or clean credit |
| Stress acceptance | All six profiles required by September 1 decision; no accepted full run |
| Hosted count | 438 counted executions/profile + CpuLocal doctests + three compile checks, from current gate definition |
| Runtime scanner | 74 source-discovered implementations; no blanket instruction/behavior coverage claim |
| CI | e127c34: hosted vfs reached 63 passed but its expected count was stale at 62; the count correction and QEMU transient/parser fixes await a complete rerun |
| Velocity | No new audit row/fix-rate inferred; this is a planning rollover |

Release requires no unresolved Critical/High within the supported scope, the
recorded three clean full rounds, all six validated stress profiles, strict
supported-profile outcomes and coherent ABI/device/mitigation claims. Physical
support is only claimed for measured matrix rows. Diagnostic CI success does
not override any of these conditions.

## 8. Open-item conservation and overlap decisions

| Input group | Disposition in this plan |
| --- | --- |
| September 11 P3-2 only-pending snapshot | Retained P3-2 physical row plus its accepted QEMU slice |
| September 6 18-item KSA queue | All 18 IDs in §2; 17 DONE scoped and one partial |
| September 1 P0-A/R186-4/D1-RES | Restored §3; not erased by unrelated KSA acceptance |
| R188-RF / audit cadence | Restored §3/§7; reuse overlap, do not assume a full review took place |
| ST-K1/ST-K2/ST-K3/ST-K4 | ST-K1/K2/K4 retained; ST-K3 diagnosis/repair historically DONE, acceptance of dependent stress profiles stays open |
| ST-5 | Disposable ESP copying historically implemented; remaining failure/lifecycle issue retained as F11 |
| ST-6 | Monthly-policy task superseded by weekly/manual Extended tests; no stress acceptance inferred |
| DOC-1 | Fulfilled by this roadmap/README/nextplan reconciliation; all-six condition restored |
| Six ST-K3 residual groups | F2, F7, F4/F6, F10, F11, W-3/W-4 each retained in §4/§5 |
| R188 U37-1/U55-6/U29-3 | Honesty vs capability split retained; QEMU IRTE overlap separated from passthrough |
| P2 D3/D4 and PO queues | Every named group/record carried in §5; unmatched July 20 PO labels retained for provenance reconciliation |
| P3 original/new debts | Preserved in §4/§5, including cache/umount/identity/polarity/syz/E8 |
| F-1b..F-10 | All 11 IDs retained in §6; F-1/3A/3B historical completion not reversed |

Dropped without disposition: **none**. Deferred items have their enabling
dependency or reason in the row; historical detailed checklists remain in the
local source plans identified by the source ledger rather than deleted.

## 9. Handoff and review record

The next action is the R188-RF scoped evidence reconciliation using
kernel-review-fix. Subsequent implementation uses kernel-implement with the
four-item handoff/design set, current source and preserved acceptance oracles.
Planning does not start either stage.

This plan and the documentation need no kernel build. Validate source links,
component count, current hosted count, exactly one NEXT marker, all 18 KSA IDs,
all 11 feature-backlog IDs and the September 1 conservation groups. High-risk
design refresh status and actual independent review are recorded in
[handoff notes](../design/next-handoff-2026-09-12.md).
