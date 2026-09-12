# Nilix (Zero-OS) Kernel Roadmap

**Roadmap revision:** 5.4
**Updated:** 2026-09-10
**Audit baseline:** 2873c1415f10981717e223f9b70737a38a3437d1, clean on September 6.
**Current tree:** baseline plus the [v24 handoff manifest](../.tmp-ksa-20260910-resume/inputs-v24.sha256), including unbuilt WIP. Last tested batch is v23. Resume from the [P1/P2/P3 handoff](review/fixes/ksa-2026-09-06-p1-p3-handoff-2026-09-10.md).
**Roadmap purpose:** record the real current state of the implementation by component, preserve completed work, and order the remaining work from blockers to long-term features.

The current source, executable tests and recorded gate outcomes are authoritative.
This revision reconciles the [audit](review/audits/qa-2026-09-06.md),
[current plan](review/nextplan/next-phase-plan-2026-09-06.md) and
[repair/evidence ledger](review/fixes/ksa-2026-09-06-progress.md). Normal validation
is bound to v18, final namespace evidence to v19, and O_TRUNC guest evidence to v16
with corrected v18 host replay. Independent review of the P0-3/P0-4 probes is now
complete; earlier reviews retain their recorded source scope.

The latest P1/P2/P3 work is recorded in the [batch ledger](review/fixes/ksa-2026-09-06-p1-p3-progress.md).
Filesystem identity and CpuLocal repairs are source-reviewed; explicit unsupported
livepatch is implemented and reviewed; outcome-policy changes remain WIP.
The user requested a new-session handoff before final validation. No additional
finding is accepted, and no new audit round or plan rollover is claimed.

## Status legend

| Status | Meaning |
|---|---|
| **Validated** | Wired into the active path and exercised by a relevant named gate or runtime test. |
| **Scoped FIXED** | The original finding's applicable validation and independent review are complete within the stated scope. |
| **Verification pending** | Implementation/evidence exists, but required review or acceptance checks remain incomplete. |
| **Qualified** | The exercised gate has zero failed tests but retains warnings/deferrals; this is not strict qualification. |
| **Implemented** | Active implementation exists, but validation is partial or indirect. |
| **Partial** | A major dependency, contract, lifecycle path, or integration is incomplete. |
| **Blocked** | A confirmed defect prevents safe use or release qualification. |
| **Planned** | New implementation is required. |
| **Needs Verification** | Source inspection found a contract or risk, but a focused runtime, hardware, or disassembly oracle is still required. |

A component is not called complete merely because its files or APIs exist.

## Executive status

Nilix is a buildable x86_64 Rust kernel prototype with substantial kernel, userspace, and validation infrastructure. The current tree is not release-ready.

| Evidence | Result | Roadmap meaning |
|---|---|---|
| make build / make lint | v18: both exit 0 | Compilation, fallibility checks and ABI oracle pass. |
| make test-hosted-subcrates | v18: exit 0, 278 tests plus 3 compile checks | Hosted behavior is validated for exercised paths. |
| make test | v18: exit 0, 35 passed / 39 deferred / 0 failed | Runtime suite passes with explicit deferrals; no panic/NX. |
| Static-musl build and guest gate | v18: both exit 0 | Standard-FD redirection/close/fork/exec/CLOEXEC, O_TRUNC and robust-usercopy checks pass. |
| Four-core SMP | v18: exit 3 qualified, 37 passed / 37 deferred / 0 failed | Four CPUs and all three R175 cross-core checks; strict qualification remains open. |
| Boot and Q35 IOMMU | v18: each exit 3 qualified, 28 passed / 46 deferred / 0 failed | Q35 translation active; scoped initialization/failure repair accepted on v13. |
| Namespace resource/SMP probes | v19: 52 boundary/Arc failures, 3 class-budget rejections, 24 four-CPU rounds; separate v15 one-CPU control rejects | Exact count/heap restoration; independent probe review complete. |
| O_TRUNC syscall-failure probes | Both open families: 32 rejected calls preserve data, 2 controls truncate once | Guest and corrected evidence checks pass; independent probe design/change review complete. |
| QEMU backend hosted checks | 32 syz tests, 4 adapter tests and 6 evidence fixtures pass | Backend corrections reviewed; hosted checks do not prove successful guest execution. |
| Latest hosted batch | v23: 296 unit tests, one compile-fail doctest (two ignored examples), three compile checks; exit 0 | Includes identity/CpuLocal and earlier livepatch version; later WIP is unbuilt. |
| Actual QEMU fuzz guest | v23 syz build 0; smoke 1. First seed PASS slots=3/exit 0, then e2fsck rejects private JBD2 | Identity collision repaired; authenticated host decoding and second seed remain pending. |

The audit has **6 of 20 scoped FIXED findings (30%)**: KSA-001 through KSA-006.
**14 remain open/pending**: KSA-007 has an unresolved guest failure, and
KSA-008..020 remain open. The user authorized independent probe review; both
remaining P0 items passed and all five P0 items are now accepted. The next
implementation item is **P1-2**, finishing read-only result extraction. Strict platform
qualification and broad Linux compatibility remain release limitations.

# 1. Kernel Modules

This section records kernel work by subsystem. Historical completed work means the capability is present in the current tree and was previously delivered; it does not erase current defects or missing verification.

## 1.1 Kernel core, architecture, memory, and scheduling

### Historical completed work

- Rust no_std kernel entry and UEFI boot path.
- Syscall dispatch and userspace return paths.
- Process table, PCB lifecycle, fork/exec/exit/wait scaffolding.
- User stack mapping, guard-page handling, ELF loading, copy-in/copy-out helpers.
- Buddy/page-table/memory-management infrastructure and copy-on-write paths.
- AP startup, per-CPU data, scheduler queues, IPI/TLB-shootdown paths, RCU and futex-PI infrastructure.
- Context-switch and Ring-3 bring-up repairs that enabled the current memory/fork/wait guest path.
- Basic SMEP, SMAP, NX/W^X, UMIP, stack-guard and fault-reporting paths.

### Current state

| Component | State | Evidence and limitation |
|---|---|---|
| Syscall dispatch | **Implemented** | The syscall table and userspace wrappers are active; broad ABI completeness is not established. |
| Process/fork/wait | **Implemented / Needs Verification** | musl fork/re-exec and descriptor inheritance pass after LAPIC mapping/SYSRET-frame repairs. Nested-PID wait after teardown remains open. |
| Usercopy | **Validated / Scoped FIXED** | KSA-002 exact linked-table/LOCK CMPXCHG checks and writable/read-only/unmapped robust-futex cleanup pass; independent review complete. |
| Scheduler/SMP | **Implemented / Qualified** | v18 four-core gate: 37 passed / 37 deferred / 0 failed. Failed summaries are rejected; strict warning/deferred qualification remains open. |
| CpuLocal | **Implemented / Verification pending** | Owner-borrowed access, safe Once ownership, automatic Send/Sync and explicit IRQ buffer mutation; source-reviewed, 11 hosted tests/compile-fail doctest pass. Final normal/IRQ/SMP gates pending. |
| KPTI | **Partial / Needs Verification** | Dual-CR3 structures and switching stubs exist; complete page-table separation and all entry/exit paths are not proven. |
| Retpoline | **Needs Verification** | Status is derived from a feature flag; compiler code generation is not proven. |

### Remaining work

- **P1:** preserve PID namespace identity through zombie wait/reap; verify blocked signal behavior against rt_sigprocmask.
- **P1:** make F_GETFL/F_SETFL stateful and enforce RLIMIT_NOFILE instead of only storing/reporting it.
- **P2:** complete final normal/IRQ/SMP validation of the reviewed CpuLocal ownership repair.
- **P3:** prove KPTI and retpoline from generated assembly and page-table mappings.

## 1.2 Security, capabilities, namespaces, cgroups, and isolation

### Historical completed work

- Capability object/table model with generation-aware handles and refcount lifecycle.
- LSM/MAC hooks, DAC permission checks, seccomp/pledge filtering, audit events and compliance state.
- PID, mount, user, IPC, network and cgroup-related isolation structures.
- cgroups v2 controllers and resource accounting infrastructure.
- Network namespace ownership gates, per-namespace network data structures, ARP/addressing/routing/RX paths and bounded network budgets.
- FIPS/KAT, RNG, kptr protection, Spectre status, W^X validation and security test framework.
- DMAR parsing and VT-d/IOMMU driver structure, including domain/fault/invalidation components.

### Current state

| Component | State | Evidence and limitation |
|---|---|---|
| Capabilities/LSM/seccomp/audit | **Implemented** | Prepared-open preflight precedes mutation and infallible publication. Rejection probes independently reviewed; broader policy contracts, including KSA-014, remain scoped. |
| Namespace limits | **Validated / Scoped FIXED** | Move-only permits repair the double decrement. Hosted and real allocator/four-CPU resource probes pass with independent review; KSA-015 mount-table lifecycle remains open. |
| VFS credentials/DAC | **Partial / Needs Verification** | KSA-014: missing credential snapshots allow access. Reachability from untrusted contexts must be tested. |
| Network namespace dataplane | **Implemented / Qualified** | The no-NIC/root-MAC prerequisite is explicitly deferred in the tested profile. Full NIC-backed lifecycle coverage remains required. |
| IOMMU/VT-d | **Validated / Scoped FIXED on Q35** | Checked MMIO mapping, retained-hierarchy rollback and constructor/IR/TE rejection probes pass with independent review. Physical/multi-unit qualification remains open. |
| Livepatch | **Explicitly unsupported / Verification pending** | Registration, direct lifecycle APIs and syscalls reject with ENOSYS; query is nonallocating and boot reports unsupported. Final correction is reviewed but unbuilt. |
| Security runtime reporting | **Partial** | Warning is treated as is_ok; many runtime checks remain deferred or placeholders. |

### Remaining work

- **Regression coverage:** retain the accepted [namespace resource/SMP probes](review/design/ksa-003-kernel-resource-probes-design.md); scoped P0 acceptance is complete.
- **P1:** validate the explicit unsupported livepatch capability; future enablement requires real keys and reviewed cross-core integration.
- **P1:** separate pass, warning, deferred, skipped and failed security results.
- **P2:** couple mount namespace lifetime to materialized VFS table reclamation.
- **P2:** make path resolution symlink/mount-aware and remove credential fail-open behavior.
- **P3:** establish a VT-d hardware/spec matrix and complete mitigation evidence.

## 1.3 VFS, storage, block, drivers, and IPC

### Historical completed work

- VFS manager and callback boundary, RAMFS, initramfs, procfs, devfs, cgroupfs and ext2-family storage paths.
- Ext2 journal replay/validation and block-ownership checks.
- Open/create/stat/read/write/readdir, openat/openat2-related resolution scaffolding, pipes, sockets and futex/IPC primitives.
- Capability-aware fd publication and fallible open preparation.
- Virtio-blk and block request abstractions, descriptor validation, timeout/late-completion tracking and filesystem consumers.
- Keyboard/console/framebuffer and other core QEMU device paths.

### Current state

| Component | State | Evidence and limitation |
|---|---|---|
| VFS open/publication | **Validated / Scoped FIXED** | Core transaction and new probe design/change independently reviewed; 32 allocation/LSM/credential rejections preserve bytes and FD reuse, and two controls truncate once. KSA-014 remains separate. |
| Standard fd behavior | **Validated / Scoped FIXED** | Ordinary console descriptors and object routing; musl redirection, close, fork/exec inheritance and CLOEXEC checks pass with independent review. |
| Working directory | **Blocked** | KSA-010: getcwd always returns slash; chdir stores no cwd. |
| Path semantics | **Partial / Needs Verification** | normalize_path removes dot-dot lexically before object resolution; symlink and mount-root behavior is incomplete. |
| Mount namespace VFS tables | **Partial** | Materialization and rollback exist; normal successful-destruction cleanup was not found. |
| Block/BIO API | **Implemented / Needs Verification** | Raw buffer pointers and callback ownership do not encode lifetime/write authority or prove callback lock ordering. |
| Virtio 4K support | **Needs Verification** | Capacity uses 512-byte units while logical sector conversions use negotiated sector_size; consumers need exact boundary tests. |
| IPC/pipe/futex | **Implemented / Needs Verification** | Pipe redirection and robust-usercopy cleanup pass in musl; broader blocked-signal and lifetime interactions remain scoped. |

### Remaining work

- **P0 acceptance:** independently review the new [O_TRUNC syscall-failure probes](review/design/ksa-004-syscall-failure-probes-design.md); implementation and applicable validation are complete.
- **P1:** implement cwd state, relative path resolution and fork/chroot/pivot-root behavior.
- **P2:** reclaim VFS namespace tables, repair component-wise path resolution, and make missing credentials fail closed.
- **P2:** redesign BIO ownership/callback locking and define one typed unit model for 512-byte capacity versus 4K logical sectors.
- **P2:** complete ext2/RAMFS UID/GID and user-namespace ownership compatibility tests.

## 1.4 Networking, observability, and operational kernel services

### Historical completed work

- IPv4, ARP, ICMP, UDP, TCP, connection tracking, firewall and virtio-net paths.
- Namespace-aware RX/TX structures, ARP caches, routing/addressing scaffolding, packet budgets and pending-frame handling.
- Trace counters, watchdog, profiler, kdump and audit logging infrastructure.
- Runtime markers used by boot, SMP and stress harnesses.

### Current state

- Network core is **Implemented for exercised paths**. Current SMP gates have zero failures; the missing NIC/root-MAC prerequisite is deferred and does not establish full network lifecycle coverage.
- Host gates distinguish failed/incomplete/qualified results. Kernel security warning/deferred policy still needs strict qualification work under KSA-008.
- Bare-metal, real-hardware DMA and broad device-matrix validation remain open.

### Remaining work

- Exercise netns_rx_pool_lifecycle with its configured virtio NIC and root-MAC prerequisites.
- Complete strict warning/deferred policy while retaining the repaired failed-summary gate behavior.
- Add longer-running namespace/network resource stress and device fault tests.

# 2. Userspace

## 2.1 Historical completed work

- Static userspace ABI wrappers in userspace/src/syscall.rs.
- Minimal libc helpers and shell implementation.
- Ring-3 startup, process creation, fork/wait call paths and userspace test programs.
- Static musl integration and the make musl-check gate.
- Stress runners, advanced stress runner, syscall fuzzer executor, nilix-syz-fuzzer protocol/mutator/corpus components.
- Userspace-facing structures for stat, uname, directory entries, sockets and common syscall arguments.
- Native capability/fd wiring infrastructure from U.S2 3A/3B, with current integration limitations described in the kernel section.

## 2.2 Current status

| Userspace component | State | Evidence and limitation |
|---|---|---|
| Userspace syscall wrappers | **Implemented** | Wrappers are active and musl smoke passes; behavior is limited by kernel contract gaps. |
| libc and shell | **Implemented / Partial** | Basic commands and musl standard-FD redirection/inheritance work; cwd and fcntl semantics remain incomplete. |
| Static musl | **Validated for exercised subset** | v18 guest passes descriptor, fork/exec/CLOEXEC, robust-usercopy and existing ABI markers. Dynamic linking and broad glibc compatibility remain open. |
| Stress programs | **Implemented / Partial** | Scoped namespace resource/SMP probes pass; longer-running and deferred profiles remain incomplete. |
| Userspace fuzz executors | **Implemented / Extraction unresolved** | First guest PASS/exit 0 reached after identity repair; post-guest fsck rejects private JBD2, preventing authenticated decoding/second seed. |
| Dynamic linking and vDSO | **Planned** | No complete ld.so/PT_INTERP/PIE/ASLR/vDSO path is established. |
| glibc and OCI compatibility | **Directional** | Requires the user-mode personality and broader syscall/ABI completion. |

## 2.3 Remaining work

- **P1:** implement cwd, fcntl status flags, wait/signal semantics and NOFILE enforcement required by normal applications.
- **P1:** define and publish the supported Linux-compatible ABI subset; do not claim byte-complete compatibility beyond tested calls.
- **P2:** add userspace regression programs for symlink/jail behavior, namespace teardown, 4K storage, lowered descriptor limits and blocked signals.
- **P3:** implement dynamic linking, vDSO and user-space ASLR only after the current static ABI is coherent.
- **Long term:** de-privileged Linux personality, glibc compatibility, OCI/container image execution.

# 3. Tests and Fuzzing

## 3.1 Historical completed work

- make build, make lint, fallibility lint, ABI layout oracle and musl-check integration.
- Hosted subcrate test infrastructure across kernel-core, VFS, IPC, security, block and networking components.
- Baseline kernel runtime test framework with pass/deferred/fail summaries.
- Single-core boot and kernel test harnesses with serial/interrupt log collection.
- SMP and extended SMP harnesses, stress profiles and parser scripts.
- Fuzz target inventory for scheduler, memory, page tables, ELF, futex, IPC, network, VFS, cgroups, signals and syscall paths.
- Userspace fuzzer infrastructure: syscall descriptions, mutators, state machines, resource tracking, corpus management, crash triage and offline protocol tests.
- KCOV/manual tracepoint support and QEMU guest test scaffolding.

## 3.2 Current status

| Test component | State | Evidence and limitation |
|---|---|---|
| Build/lint/hosted tests | **Validated** | v18 gates pass, including 278 tests and 3 compile checks; hardware/DMA evidence remains separate. |
| Baseline runtime tests | **Partial** | 35 pass, 39 deferred, 0 fail; deferred and warning results are not equivalent to pass. |
| SMP gate | **Scoped FIXED / Qualified platform** | Failed summaries are rejected; v18 four-core guest has zero failures and 37 deferrals. |
| IOMMU gate | **Qualified platform** | v18 Q35 boots with translation active, zero failures and 46 deferrals; v13 failure probes reviewed. |
| musl gate | **Validated for exercised subset** | Descriptor/fork/exec/CLOEXEC, O_TRUNC, robust-usercopy and existing ABI markers pass. |
| Namespace/O_TRUNC probes | **Validated / Scoped FIXED** | Actual resource/SMP and syscall-failure oracles pass with independent design/change review. Seven O_TRUNC evidence regressions pass locally and are registered in CI. |
| Offline fuzzing | **Validated for utilities** | Stress/userspace/nilix-syz checks pass without QEMU execution. |
| QEMU fuzz executor | **Implemented / Acceptance blocked** | First guest PASS slots=3/exit 0; host extraction/authentication and second seed pending. |
| Runtime security test policy | **WIP / Verification pending** | Distinct outcomes, owned reasons and strict structured parser; five policy/15 parser fixtures pass. Build, caller/CI integration and independent review pending. |
| Coverage quality | **Partial** | KCOV and tracepoints exist; successful fuzz-guest coverage and deferred test execution remain unproven. |

## 3.3 Remaining work

- **Regression coverage:** preserve the five accepted P0 repairs and their namespace/O_TRUNC, usercopy, descriptor and IOMMU oracles.
- **P1:** finish read-only post-guest extraction, obtain two authenticated successful seeds/coverage, and retain execution/failure classification evidence.
- **P1:** classify warnings, deferred, skipped and failed tests separately; assign every deferred test an owner and acceptance oracle.
- **P3:** extend artifact-backed CI across the supported matrix, preserving source/image identity, commands, status and serial/QEMU/interrupt evidence.
- **P2:** add path, ownership, PID namespace, signal-mask, fcntl, NOFILE, BIO lifetime and 4K virtio test families.
- **P3:** add disassembly/page-table tests for KPTI and retpoline; establish VT-d emulator/hardware matrix.
- **Long term:** continuous fuzzing with real guest execution, KCOV feedback validation, corpus retention and performance baselines.

# 4. Cross-component priority and release plan

## P0 — blockers

1. **P0-1 — DONE within Q35 scope:** VT-d MMIO/fail-closed initialization; physical/multi-unit qualification remains P3-2.
2. **P0-2 — DONE:** exact usercopy fixup and robust-futex recovery.
3. **P0-3 — DONE:** transactional namespace counters and resource/SMP probes independently reviewed; exact count/heap restoration verified.
4. **P0-4 — DONE:** O_TRUNC publication and syscall-failure probes independently reviewed; rejection preserves data and successful truncation occurs once.
5. **P0-5 — DONE:** table-backed standard descriptors and tested inheritance/redirection/CLOEXEC.

## P1 — correctness and validation truth

6. **P1-1 — DONE:** failed-summary parser repair; strict warning/deferred policy remains separate.
7. **P1-2 — Next implementation:** finish extraction after guest PASS and complete two authenticated seeds/coverage.
8. **P1-3 — WIP:** integrate/build/review distinct outcomes and strict qualification.
9. **P1-4 — Verification pending:** explicit unsupported capability, final source-reviewed correction unbuilt.
10. **P1-5 — Open:** working directory.
11. **P1-6 — Open:** wait, signal, fcntl and NOFILE contracts.

## P2 — lifecycle and component quality

12. **P2-1/P2-2:** VFS table reclamation and path semantics.
13. **P2-3:** credential fail-closed behavior and UID/GID compatibility.
14. **P2-4 — Verification pending:** reviewed CpuLocal ownership repair; final IRQ/SMP gates pending.
15. **P2-5:** BIO ownership/callback ordering and virtio 4K units.
16. Execute deferred network lifecycle coverage with its prerequisites and extend namespace stress.

## P3 — hardening and expansion

17. **P3-1:** KPTI/retpoline generated-behavior proof.
18. **P3-2:** VT-d hardware/spec matrix.
19. Artifact-backed CI across that matrix and performance baselines.
20. Dynamic linking/vDSO/ASLR, personality server, glibc and OCI.

## 5. Release gates and acceptance conditions

The 1.0-Preview gate remains **BLOCKED**. Current condition status:

| Condition | Disposition |
|---|---|
| P0 repairs and independent review | All five P0 items accepted within their documented scopes; independent probe reviews and source-bound evidence verification complete. |
| Failed summaries cannot pass relevant gates | Scoped KSA-006 repair accepted, with 23 parser/caller regressions. |
| Strict warning/deferred security policy | Open KSA-008; qualified platform results are not strict passes. |
| Q35 initialization and controlled failure handling | Scoped KSA-001 repair accepted; supported release-profile policy and physical/multi-unit matrix remain open. |
| Operational QEMU fuzz evidence | Open KSA-007: successful authenticated seeds/results/coverage are missing. |
| Documented, coherent userspace ABI | Standard descriptors validated; cwd, signals, wait, fcntl and rlimits remain incomplete. |
| Fresh audit with no unresolved Critical/High findings in claimed profiles | Not established; no new full audit or clean streak is claimed. |

Each gate must retain revision, configuration, command, exit status, serial output, QEMU stderr, interrupt logs where applicable, parsed counts and not-run reasons.

## Risk register

| Risk | Severity | State | Owning area | Next action |
|---|---|---|---|---|
| VT-d MMIO fault | Critical | Scoped FIXED on Q35 | Kernel Modules | P0-1 closed; P3-2 hardware matrix |
| Usercopy fixup mismatch | High | Scoped FIXED | Kernel Modules | P0-2 closed; retain regression coverage |
| Namespace counter undercount | High | Scoped FIXED | Kernel Modules | P0-3 closed; retain resource/SMP regressions |
| O_TRUNC partial failure | High | Scoped FIXED | Kernel Modules | P0-4 closed; KSA-014 authorization remains separate |
| Standard fd bypass | High | Scoped FIXED | Kernel Modules/Userspace | P0-5 closed; broader ABI P1-5/P1-6 |
| False-green SMP gate | High | Scoped FIXED | Tests and Fuzzing | P1-1 closed; strict policy P1-3 |
| QEMU fuzz host extraction failure | High | First guest PASS; authentication/second seed pending | Tests and Fuzzing | P1-2 |
| Warning/deferred polarity | High | WIP; final build/review pending | Tests and Fuzzing | P1-3 |
| Livepatch unsupported capability | High | Implemented/reviewed; final validation pending | Kernel Modules | P1-4 |
| cwd/fcntl/rlimit/wait/signal gaps | High/Medium | Open | Kernel Modules/Userspace | P1-5/P1-6 |
| VFS table retention | Medium | Likely open | Kernel Modules | P2-1 |
| Path and credential semantics | Medium | Open/Needs Verification | Kernel Modules | P2-2/P2-3 |
| CpuLocal ownership validation | Medium | Implemented/reviewed; normal/IRQ/SMP checks pending | Kernel Modules | P2-4 |
| BIO/4K contract ambiguity | Medium | Open/Needs Verification | Kernel Modules | P2-5 |
| KPTI/retpoline proof gap | Low/Medium | Needs Verification | Kernel Modules/Tests | P3-1 |

## Priority-ordered action list

1. Preserve the six scoped accepted KSA repairs and their regression evidence; all five P0 acceptance requirements are complete.
2. Continue P1-2 from private-JBD2 extraction rejection and obtain two authenticated guests.
3. Complete strict warning/deferred policy under P1-3.
4. Close livepatch, cwd, wait, signal, fcntl and NOFILE contracts.
5. Repair VFS lifecycle/path/ownership, CpuLocal, BIO and 4K contracts.
6. Add network lifecycle regression and extended resource stress.
7. Prove KPTI/retpoline and establish hardware/spec matrices.
8. Resume long-term userspace expansion only after the static ABI is coherent.

## Recommended Next Plan

Resume the full authorized open P1/P2/P3 batch using `kernel-implement` and the
[current handoff](review/fixes/ksa-2026-09-06-p1-p3-handoff-2026-09-10.md).
Start with **P1-2/KSA-007** post-guest extraction; retain its earlier
[executor design](review/design/ksa-007-real-qemu-executor-design.md) and
[backend review](review/fixes/ksa-007-independent-review.md). Independent reviewer
agents are already authorized. The [P0 probe acceptance review](review/fixes/ksa-2026-09-06-independent-review.md#p0-3-and-p0-4-acceptance-review)
is complete. The next review stage is `kernel-security-audit`, with the current
diff, designs and evidence ledger; this closeout does not run it. Reuse passing revision-bound evidence
for unchanged inputs and run the affected gates after new runtime changes. The
current plan retains all remaining P1/P2/P3 items and their acceptance conditions.

## Information, tests, and human decisions required

- Confirm whether q35 VT-d is mandatory for supported release profiles.
- Future livepatch enablement needs provisioned trust keys and reviewed integration; support is explicitly disabled for this repair.
- Define the broader supported Linux ABI subset for cwd, signals, wait, fcntl and rlimits; standard-FD semantics are already exercised and scoped accepted.
- Provide or approve the VT-d, 4K virtio, KPTI and retpoline hardware/toolchain matrix.
- Establish the NIC/root-MAC and other hardware prerequisites needed to execute deferred tests; failed-summary parser fixtures already cover KSA-006.

---

This roadmap is source- and test-grounded. It records historical delivered work but does not treat historical completion summaries as current proof.
