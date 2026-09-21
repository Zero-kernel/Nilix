# Nilix (Zero-OS) — Development and Capability Roadmap

**Revision:** 6.1 — **Updated:** 2026-09-14
**Source baseline:** local 3.1–3.3 implementation working tree; exact final remote verification copy `/tmp/zero-os-codex-final-20260913` on `40c-devbox-ts`.

**Active plan:** [next-phase-plan-2026-09-13.md](review/nextplan/next-phase-plan-2026-09-13.md) (v16.4).

Nilix is an experimental x86_64 OS kernel with UEFI boot, Ring-3 programs, a
tested static-musl ABI subset, SMP scheduling, filesystems, IPv4 networking and
security policy machinery. **1.0-Preview remains blocked.** This roadmap records
the capabilities, missing contracts and evidence boundaries of the current tree.

Revision 6 restores component detail, trust boundaries, the Linux comparison,
phase history and release conditions lost in revision 5.4. It incorporates
September's scoped KSA repairs and restores the older admission, stress and
feature backlog. Historical roadmaps remain in Git; dated audits retain their
original evidence.

## 0. How to read status

| Label | Meaning |
| --- | --- |
| Tested subset | A named test exercises the stated behavior; other modes are not implied. |
| Implemented | Active code exists; behavioral qualification is incomplete. |
| Partial | Useful behavior coexists with identified missing contracts. |
| Unsupported | Disabled, rejected or unimplemented. |
| Verification pending | Current-tree, platform or independent-review evidence is missing. |
| Planned | A future implementation or qualification milestone. |

A scoped audit PASS closes that finding's rubric. Diagnostic CI may accept
exit 3 while retaining qualified warnings/deferred/skipped results; that is not
strict release qualification. Source-scanner coverage, host tests and actual
guest execution measure different things.

## 1. Executive status

| Area | Current state |
| --- | --- |
| Composition | 25 kernel library crates plus the entry binary; separate UEFI bootloader, userspace and host tools. Most services execute in Ring 0. |
| Userspace proof | Static ELF and real musl tests run in Ring 3; fork/exec/wait, descriptors, cwd/jails and several failure paths have guest evidence. |
| September KSA | KSA-001..020 accepted within recorded rubrics; 17/18 associated plan items complete. P3-2 physical VT-d remains pending. |
| Hosted gate | 438 counted unit-test executions per debug/release profile, CpuLocal doctests and three test-code compile checks; explicit host-safe allowlist. |
| Runtime inventory | 74 source-discovered RuntimeTest implementations; actual pass/deferred/warning/skipped/failed counts depend on image/platform. This is not 100% kernel code coverage. |
| Recent CI | [Run 34701321475](https://github.com/Zero-kernel/Nilix/actions/runs/34701321475), e127c34: hosted suites exposed a stale vfs oracle (actual 63 passed, expected 62); the count fix is in this tree. Runtime QEMU jobs are separately pending/completing. |
| Release gate | BLOCKED: R186-4 admission closure, historical review lineage, strict profile qualification, all six stress profiles and the recorded 0/3 clean-audit streak. |

Acceptance sources: the [historical record ledger](security-audit-status.md#record-provenance)
identifies the KSA audit, final review-fix and P3-2 QEMU evidence; the public
[VT-d matrix](vtd-support-matrix.md) defines platform scope. Their manifests
identify the actual tested trees. Later commits do not retroactively change
historical acceptance.

## 2. Vision, principles and non-goals

The goal is a Rust OS with a Linux-compatible userspace surface, capability
authority and explicit resource ownership. The long-term architecture moves
selected Linux personality services into less-privileged userspace. Today
scheduler, VFS, network, drivers and Linux syscall semantics are predominantly
in-kernel; microkernel privilege separation is a future milestone.

**Safety > Correctness > Efficiency > Performance.** Fallible publication,
symmetric accounting, teardown ownership and IRQ-safe locking precede API
breadth or optimization. Matching syscall numbers/layouts and passing musl
smoke do not establish general Linux, pthread, glibc or OCI compatibility.
Enterprise deployment, certified FIPS operation, universal devices and complete
speculative-execution protection are qualification goals.

## 3. Architecture and trust boundaries

### 3.1 Current execution and planned personality

Ring 3 → architecture entry/usercopy → seccomp/capability/LSM gates →
kernel_core → VFS/IPC/network/scheduler → memory/arch/drivers → hardware.

Cargo layering and callbacks break dependency cycles; they do not create
privilege boundaries. The trusted bootloader supplies the image, memory map and
ACPI pointer. Credentials/capabilities/LSM authorize supported operations.
IOMMU mediates device requests only within the supported device matrix. A
deprivileged Linux personality, reached through native IPC, is planned.
See [architecture.md](architecture.md) for the composition graph and hot paths.

### 3.2 Threat model

| Actor/input | Existing defenses | Remaining boundary work |
| --- | --- | --- |
| Unprivileged process/syscall arguments | Exact usercopy fixups, W^X/address checks, credential snapshots, capability generations, seccomp/pledge and LSM | MM admission closure, partial ABI semantics, failure/concurrency breadth |
| Tenant/resource pressure | Five namespace types, cgroups/class budgets, transactional constructors and descriptor publication | Shared memory, init membership, delegated device authority, complete container interfaces |
| Malformed ELF/filesystem/packet | Checked ELF, geometry, path, journal and protocol processing; conntrack/firewall | Recovery corpus, network topology and interoperability |
| Faulty/hostile device | Owned BIO, virtqueue validation, VT-d mappings/invalidation, remapped MSI and quarantine tested with EDU | Physical DMA, bridge/multi-unit/RMRR/ACCESS_PLATFORM and device breadth |
| Operator/diagnostic reader | Profile logging, kptr redaction, authorized trace/audit export, hash/HMAC audit | Durable/remote backend, keys and complete Secure-profile qualification |
| Speculative execution | Hardware-dependent controls/barriers and dual-root transition evidence | Full KPTI and compiler retpoline unsupported; CPU-specific proof required |

## 4. Kernel composition

All 25 library crates are listed. A crate/API's presence is not a completion claim.

| Crate | Role | Qualification/gap |
| --- | --- | --- |
| [arch](../kernel/arch/lib.rs) | GDT/IDT, APIC/HPET, IRQs, SYSCALL, context switch, AP boot | UP/SMP evidence; high-core/physical/exception-entry breadth pending |
| [cpu_local](../kernel/cpu_local/lib.rs) | CPU topology/local storage/FPU ownership | Borrowed lifetime API and TLS migration evidence; 64 CPUs is a ceiling |
| [tlb_ops](../kernel/tlb_ops/lib.rs) | TLB/INVPCID primitives | Active MM/arch dependency; CPU-feature dependent |
| [sync_safe](../kernel/sync_safe/lib.rs) | IRQ-safe lock wrappers | Caller lock-order/entry-state obligations remain |
| [drivers](../kernel/drivers/lib.rs) | VGA/framebuffer, serial, keyboard | Basic console, not a desktop/device-driver ecosystem |
| [virtio](../kernel/virtio/src/lib.rs) | Shared PCI/MMIO transport/queues | Block/network integration; ACCESS_PLATFORM/device breadth pending |
| [crypto](../kernel/crypto/lib.rs) | Shared SHA-256 | Narrow primitive, not a general certified provider |
| [klog](../kernel/klog/lib.rs) | Profile-aware logging | Active lint/macros; full caller/redaction sweep tracked |
| [mm](../kernel/mm/lib.rs) | Buddy/heap/admission, paging/cache/DMA/OOM/TLB | Anonymous/COW paths; admission/shared/file-mapping gaps |
| [coverage](../kernel/coverage/lib.rs) | KCOV task bitmap/control | Host-root authority/manual instrumentation; not exhaustive coverage |
| [cap](../kernel/cap/lib.rs) | Rights, IDs, generations and tables | File/pipe lifecycle integration; native syscall family incomplete |
| [audit](../kernel/audit/lib.rs) | Hash/HMAC ring and export | Policy/hosted evidence; durable production backend missing |
| [security](../kernel/security/lib.rs) | W^X/NX, RNG/kptr/KASLR, CPU mitigations | Mechanism/status tests; full KPTI/retpoline unsupported |
| [lsm](../kernel/lsm/lib.rs) | Process/file/IPC/memory/network hooks | Active policies; future-operation hooks do not implement operations |
| [seccomp](../kernel/seccomp/lib.rs) | Strict/filter and pledge | Tested subset; TSYNC/Linux parity residuals |
| [compliance](../kernel/compliance/lib.rs) | Profiles, sticky FIPS state/KAT policy | No certification or complete Secure-platform guarantee |
| [livepatch](../kernel/livepatch/lib.rs) | Experimental signed patch/lifecycle machinery | Unsupported, ENOSYS; production enablement absent |
| [block](../kernel/block/src/lib.rs) | Owned BIO/completion/geometry/virtio-blk | Host/guest 512B/4096B evidence; physical matrix pending |
| [net](../kernel/net/src/lib.rs) | IPv4/TCP/UDP, sockets, conntrack/firewall, virtio-net | Container connectivity/IPv6/interoperability gaps |
| [trace](../kernel/trace/lib.rs) | Counters/tracepoints/watchdog/profiler/kdump | Diagnostics exist; external collection/performance pending |
| [iommu](../kernel/iommu/lib.rs) | DMAR/legacy VT-d/domains/remapping/quarantine | Q35/EDU scope tested; physical/topology gaps explicit |
| [kernel_core](../kernel/kernel_core/lib.rs) | Process/ABI/namespaces/cgroups/signals/RCU/ELF | Active hub; resource/ABI/teardown backlog remains |
| [vfs](../kernel/vfs/lib.rs) | Path/DAC/mounts, ramfs/ext2/JBD2/procfs/devfs/CPIO/cgroupfs | Tested publication/lifetime; durability/POSIX breadth missing |
| [ipc](../kernel/ipc/lib.rs) | Pipes/endpoints/messages/futex/sync | Pipes/robust cleanup exercised; native IPC/Linux futex parity pending |
| [sched](../kernel/sched/lib.rs) | Per-CPU MLFQ/preemption/stealing/affinity/cpuset | UP/four-CPU evidence; long/high-core/performance pending |

The [kernel binary](../kernel/src/main.rs) wires services together; the
[bootloader](../bootloader/src/main.rs) is separate. [userspace](../userspace/)
contains libc helpers, shell, musl/stress probes and guest fuzz executors.
[fuzz](../fuzz/) and [tools/fuzz_executor](../tools/fuzz_executor/) are host tooling.

## 5. Capabilities and missing contracts

### 5.1 Boot, memory and VM

**Available:** UEFI handoff, relocated PIE kernel, high-half/identity maps,
memory reservations, buddy/global heap, charged fallible containers, guards,
page cache and OOM machinery. Anonymous mmap/munmap/mprotect/brk, PROT_NONE and
COW fork have real userspace paths. RF180-20 repaired shared supervisor
page-table ownership across fork/exec/teardown; the complete four-worker
mitigation workload exercises this repair.

**Current state:** sys_mmap validates the complete flags word after the LSM hook, admits private/shared-anonymous forms and rejects unsupported forms before VMA mutation. Shared-anonymous regions use an admitted side-map and first-touch demand faults with `PAGE_REF_COUNT` ownership; report and CPU-worker transport uses pipes. `sys_mremap` no longer returns `ENOSYS`: private-anonymous and private-`PROT_NONE` VMAs can grow or shrink in place or relocate under `MREMAP_MAYMOVE`, using the same three-phase VMA/page-table transaction as mmap/munmap ([design](review/design/st-k2-mremap-anonymous-design.md)). Bounded slab, NUMA, swap and THP primitives are available with integration self-tests. **Remaining:** strict guest/musl qualification; MAP_FIXED and file mappings; shared-anonymous `mremap` (a shared region is snapshotted into every fork child, so resizing needs a per-VMA identity model) and qualified backend consumers/stress. The `mremap` page-table/refcount behavioral legs need a live user address space and remain independent-review/guest pending; the in-tree oracle covers the flags/placement/delta contract. SMP/combined stress still requires the full shared fault contract.

**R186-4 final remote verification is complete for the supported scope:** the fork snapshot reserves before allocation and the admitted-map constructor no longer shrinks infallibly. Local charge/cleanup oracles, two independent U23 safe-path reviews, and the exact final remote MM 26/26, kernel-core 68/68, hosted, build and lint gates pass on `40c-devbox-ts` in `/tmp/zero-os-codex-final-20260913`; runtime/boot/4-core SMP are zero-failure qualified. The bounded CorruptState policy, musl markers and strict guest/platform qualification remain. Owners: **ST-K2-P1/P2, U55-6**; [admission design](review/design/p0-a-r186-4-admission-closure-design.md).

### 5.2 Processes, threads, scheduling and teardown

**Available:** isolated address spaces, fork/path-exec/exit/reap, wait4/WNOHANG,
MLFQ/preemption/stealing/balancing/affinity/cpuset. TLS restoration has UP/SMP
musl evidence including timer-context migration. KSA-011 exercises namespace
wait identity and six exit/reap/idle cases.

**Missing:** clone is narrower than Linux threads. CLONE_VM/TLS setup exists;
general CLONE_THREAD/CLONE_FILES/CLONE_FS/CLONE_SIGHAND combinations are rejected.
This is not pthread support. waitid is a stub. Historical fork fallback,
stack-fragmentation, switch-sentinel and PID1 orphan/reaper questions remain;
reconcile overlap with newer KSA fixes by original oracle. Owners: **F2, F7,
F4/F6, ROOT-INIT, F-4**.

### 5.3 IPC, signals, polling and time

**Available:** capability-backed pipes, blocking/wakeup, futex primitives with
internal PI, robust cleanup, masks, kill/tgkill, rt_sigaction/rt_sigreturn,
IRQ-return delivery, basic poll/select and startup/time calls. Musl exercises
blocked signals, robust usercopy and zero-length socket behavior.

**Missing:** endpoint/message types are not complete native synchronous IPC and
shared memory. Internal futex operations are not full Linux opcode/flag parity.
SA_RESTART is accepted but interrupted calls can return EINTR; siginfo is
minimal, sigaltstack absent, queued real-time signals incomplete. No completed
epoll/eventfd/timerfd surface is claimed. Owners: **F-1c, F-2, F-4, F-10**.

### 5.4 Security framework and operational policy

**Available:** capability rights/generations, credential-bound descriptor
publication, LSM/seccomp/pledge, tamper-evident audit and profile logs. Namespace
and O_TRUNC probes test exact rollback/data preservation.

**Missing:** native_cap_op/invoke/spawn and delegated endpoint/event APIs;
TSYNC is rejected until sibling/clone publication is coherent. Global ADMIN
is not per-netns authority. Audit persistence is a hook without a production
durable/remote backend. FIPS policy/KATs are not certification.
[Livepatch is unsupported](livepatch-support.md): hooks, real keys, cross-core
synchronization and rollback qualification are prerequisites. Owners:
**F-1b/F-1c, F-5, F-6, F-9, PO-SEC-01/02**.

### 5.5 Hardware memory and speculative-execution hardening

**Available:** NX/W^X, guards, SMEP/SMAP/UMIP, KASLR, usercopy, RNG/CSPRNG and
kptr redaction. Mitigation status separates supported from active controls.
The collector checks generated code, mappings, CR3/CPL3 and the complete
four-vCPU fork/exec/wait workload.

**Missing:** dual roots retain kernel data/heap/stacks and low aliases.
FULL_KPTI_ISOLATION_SUPPORTED is false: no full Meltdown isolation. Compiler
retpoline is unsupported and its feature deliberately fails compilation.
Early-boot W+X is separate lifecycle debt. Balanced/QEMU success does not qualify
every Secure field/CPU. Owners: **U37-1b, U55-6, SECURE-MATRIX**. KSA-020 closed
truthful reporting/proof, not these future features.

### 5.6 VFS, descriptors and storage

**Available:** ramfs, ext2/constrained JBD2, procfs/devfs/CPIO/cgroupfs,
virtio-blk/owned BIO. fd 0/1/2 are table-backed; dup/close/fork/exec/CLOEXEC,
shared file status, O_NONBLOCK consumers and numeric RLIMIT_NOFILE have tests.
Component paths, cwd/root inheritance, chdir/chroot/pivot_root, DAC host IDs,
Ext2 32-bit UID/GID, mount-table retirement and O_TRUNC rejection have host/guest
evidence. 512B/4096B logical blocks have dedicated checks.

**Missing:** full ext4/POSIX support. chown/fchown/lchown, statx, hard links and
general dirfd-relative combinations remain incomplete/stubbed. Symlink/readlink
already exist: do not re-plan them as entirely absent. fsync/fdatasync/sync/
sync_file_range are not wired into dispatch. Write-through/JBD2 is not an
application durability syscall contract. Cache error/dirty/reclaim, unmount
sync/invalidation and power-loss recovery need separate proof. Owners:
**ST-K4, F-3, CACHE-DEBT, STORAGE-TESTS**.

### 5.7 Networking

**Available:** virtio-net, Ethernet/ARP/IPv4/reassembly/ICMP/UDP/TCP, retransmission,
NewReno/window scaling/SYN cookies, sockets, conntrack and stateful default-DROP
firewall machinery. Process-context RX and namespace-owned buffer/address/ARP
state exist; current hosted network allowlist has 118 tests.

**Missing:** root device ownership is the operational baseline.
MOVE_NET_DEVICE_ARMED=false keeps transfer at ENOSYS until namespace-FD
authority, generations and drain/revocation exist. veth, child RX steering,
general route-table management, per-netns firewall administration and complete
loopback delivery remain open. IPv6, wider NIC/control interfaces are missing.
Deferred NIC/root-MAC tests need runnable profiles; parser/host tests do not
prove wire connectivity. Owners: **NET-QUAL, F-7/F-9, D3-NETNS**.

### 5.8 SMP, devices and IOMMU

**Available:** APIC/AP boot, per-CPU scheduling, IPI/TLB shootdown, PCID/INVPCID
helpers, RCU and lock ordering. Four-CPU evidence exists; extended scripts
define 8/16-CPU runs. CPU-local supports a 64-logical-CPU ceiling; x2APIC is
unsupported by its current path.

DMAR is wired at boot. Q35 initialization/constructor/SIRTP/IR/TE failures and
EDU translated DMA, replacement, remapped MSI, invalid requests, quarantine,
detach and IRTE reuse have scoped QEMU evidence. The old unconnected-DMAR claim
is obsolete.

**Missing:** physical endpoint/MSI-X, multi-DRHD/bridge/nonzero-segment routing,
RMRR mappings, scalable mode, ATS/PASID and ACCESS_PLATFORM virtio qualification.
No-IOMMU boot is not isolated DMA. Mitigation single-thread TCG/four-vCPU proof
is not host-parallel SMP qualification. Owners: **P3-2, F-7, SMP-QUAL**;
[device matrix](vtd-support-matrix.md).

### 5.9 Containers and resources

**Available:** PID/mount/IPC/net/user objects/inheritance, transactional
allocation/retirement, selected CPU/memory/PIDs/I/O/files/ports controllers,
cpusets and class/namespace budgets. Failure/four-CPU near-limit probes restore
exact counts/heap; cgroupfs exposes supported controls.

**Missing:** full cgroups-v2/OCI, cgroup namespace/delegation, all namespace
FD/setns/unshare/clone combinations and container networking. PID1 root-cgroup
membership remains tracked. Non-NOFILE rlimits are largely advisory; kmem/slab/
conntrack accounting and ABI exposure need completion. Owners:
**ST-K1, F-7/F-8/F-9, PO-ISO-01**.

### 5.10 User mode, Linux ABI and tooling

**Available:** Linux-numbered subset/private calls, ELF64 ET_EXEC, SysV
stack/auxv, static musl, libc helpers and a development shell. Musl tests actual
Ring-3 behavior; the ABI oracle checks selected layouts against C. The QEMU fuzz
adapter launches real guests and authenticates two inputs, coverage and disk/
image identity.

**Missing:** userspace ET_DYN is rejected; ld.so/PT_INTERP, dynamic relocations,
complete userspace PIE/ASLR/vDSO are not a working chain. No general glibc,
pthread, BusyBox-distribution, OCI or personality acceptance. Native capability
syscalls and synchronous IPC precede personality work. Owners:
**F-1b/F-1c/F-2/F-3/F-4/F-10**.

### 5.11 Observability, testing and performance

**Available:** counters/tracepoints/watchdog/profiler/serial kdump, task KCOV
with host-root authority, command/input/image identity, Markdown/JUnit and
Python harness coverage. Debug/release hosted and feature-specific QEMU images
are separate. Five outcomes and strict rejection are implemented.

**Missing:** durable telemetry and a measured performance envelope. Performance
scripts defer unmeasured workloads; melting scripts include simulation/framework
paths, not hardware qualification. Stress block explicitly fails at
fsync_unsupported; no full six-profile success is accepted. Manual KCOV and
source-discovered tests are not all-instruction/ABI coverage. Owners:
**ST-K2/ST-K4, PERF-BASELINE, F-6/F-9**.

## 6. Gap analysis versus Linux

| Domain | Nilix today | Next boundary |
| --- | --- | --- |
| Memory | Buddy/heap/charged maps/anonymous/COW | Admission, honest flags, shared/file mapping; later slab/NUMA/swap |
| Processes | Static programs/fork/exec/wait/restricted clone | Thread/signal/wait fidelity before pthread claims |
| Storage | ramfs/ext2/JBD2/namespace VFS | Durability/recovery, dirfd/metadata and filesystem breadth |
| Network | IPv4/TCP/UDP/policy/virtio | Wire tests, namespace links/routes/admin, IPv6/drivers |
| Containers | Five namespaces/selected controllers | Delegation/shared memory/FS sharing/OCI |
| Security | Capabilities/LSM/seccomp/mitigation machinery | Isolation profiles/hardware/TSYNC/keys/backends |
| Userspace | Static-musl subset/shell | Native IPC/personality/dynamic/vDSO/glibc/apps |
| Operations | Logs/trace/KCOV/CI receipts | Durable audit, reproducible stress/performance, releases |

## 7. Phase chronology (A–U)

Historical phases describe delivered foundations, not full subsystem acceptance.

| Phase | Foundation delivered | Remaining work |
| --- | --- | --- |
| A | Entry/usercopy/hardware hardening/audit | Full isolation/platform qualification |
| B | Capability/LSM/syscall policy | Native API/TSYNC/authority breadth |
| C | VFS/block/ext2/cache/OOM | Durability/recovery/POSIX breadth |
| D | IPv4/conntrack/firewall | Wire/namespace/control-plane breadth |
| E | SMP/scheduler/IPI/TLB/RCU/futex | Long/high-core tests/thread contracts |
| F | Namespaces/controllers/VT-d | Admission/shared memory/delegation |
| G | KASLR/dual-root/observability/compliance/patch experiments | Full KPTI/backends; livepatch unsupported |
| H.0 / H | Structural/ABI audit/isolation hardening | Revalidate changed entry/MM/ownership |
| I | Policy/DMA/boot/logging hygiene | I.3/I.4/I.5/I.7, netns pre-arming |
| J | Resource/tenant observability | J.2 kmem/controller extensions |
| K / L / M | Compatibility/performance/enterprise direction | Downstream backlog |
| U | Static Ring-3 ABI/partial native cap wiring | IPC/personality/dynamic/application chain |

## 8. 1.0-Preview release gate

**BLOCKED; clean full-audit streak 0/3.** Neither this rollover nor green Actions
creates a new full clean audit round.

| Requirement | Disposition |
| --- | --- |
| R186-4 / P0-A / D1-RES-HEAP-ADMISSION-REOPENED | Implemented and final remote verification complete for supported scope; strict guest/platform qualification remains pending |
| R188 original review lineage | Full original-rubric map absent from newer scoped KSA records; reconcile/review uncovered originals, reuse proven overlap |
| No unresolved Critical/High in claimed scope; three clean rounds | Not established; streak unchanged |
| All six stress-v2 profiles | Required by recorded 2026-09-01 user decision; memory/cpu/smp/process/block/combined acceptance pending |
| Strict security/platform policy | Outcome truth implemented; deferred prerequisites still block qualification |
| ABI/device/mitigation matrix | Preserve supported/rejected/advisory and physical/full-isolation limits |
| CI result/retained evidence | Exact final remote source passes hosted/build/lint and zero-failure qualified QEMU runtime/boot/4-core SMP gates; musl markers remain incomplete; historical e127c34 count/parser notes are retained as provenance |

The five KSA P0 repairs and KSA-007..020 rubrics are accepted within scope. They
are regression obligations, not still-open implementation tasks.

## 9. Current execution — Phase U / static ABI

| Milestone | State | Dependency |
| --- | --- | --- |
| U.M0 / U.S1 | Static musl, disjoint path-exec/native image-spawn delivered; scoped fixes accepted | Preserve ELF/usercopy/musl |
| U.S2 3A/3B | Pipe capability IDs/FileOps wiring delivered | Native syscall family incomplete |
| U.S2 4/5 (F-1b) | native_cap_op/filter/generation contract pending | Admission/authority gates |
| U.S2 6/7 (F-1c) | invoke/spawn, endpoint/event pending | U.S3 IPC design |
| U.S3 (F-2) | Synchronous IPC/shared memory/lifecycle/SMP pending | Capability family/MM ownership |
| U.S4 (F-10) | Userspace personality planned | U.S3/reviewed trust boundary |
| U.S5 (F-10) | Dynamic linking/user PIE/ASLR/vDSO planned | Static ABI/ELF/MM contracts |
| U.S6/U.S7 (F-10) | glibc/application/OCI direction | Dynamic ABI/threads/signals/storage/network |

## 10. Forward roadmap

**Next group:** reconcile R188 review lineage and complete strict guest qualification; continue ST-K2/ST-K4 and the six-profile acceptance sequence.

[Current handoff notes](review/design/next-handoff-2026-09-12.md) retain prior
design choices and identify changed-premise review requirements.

**Then:** shared-anonymous memory, all six stress profiles, strict network/SMP/
Secure evidence and full-audit qualification. Physical VT-d remains a platform
dependency; independent software work can continue.

**After qualification:** F-1b..F-10, static ABI residuals, native IPC/personality,
dynamic linking, container networking, telemetry and measured performance.
These are capability milestones without unsupported calendar commitments.

## 11. Audit and repair history

| Record | Accepted scope/remaining limit |
| --- | --- |
| R186 / RF186 | 16/17 historical actionables repaired; R186-4 admission carried |
| R187 / RF187 | Seven KCOV findings/eight repair defects closed; carried debt prevents streak credit |
| R188 standalone | August remediation recorded; residuals/original review lineage separate |
| KSA-2026-09-06 | 20/20 scoped findings accepted; RF180-20 page-table ownership repaired |
| P3-2, September 12 | QEMU EDU DMA/MSI/invalidation/fault slice accepted; physical rows pending |
| September CI cleanup | Shared groups/reports, hosted/harness/real-guest tests, categorized scripts; runtime budget follow-up |

[Security status](security-audit-status.md) separates these histories.
Historical cumulative totals are not a current vulnerability census. This
rollover creates no new audit or independent-repair verdict.

## 12. Known debt and conservation

The [active plan](review/nextplan/next-phase-plan-2026-09-12.md) restores the KSA
queue plus P0-A/P1-A, ST-K1..K4/ST-5/ST-6, F2/F7/F4-F6/F10/F11/wait residuals,
U37-1a/U37-1b/U55-6/U29-3, D3 network/TSYNC/ARC, R186 design rows, four open PO
records, P3 tests and F-1b..F-10.

An overlap closes only by rubric: KSA-008 closes outcome accounting, not all
deferred execution; KSA-011 covers namespace wait identity, not all waiter
efficiency; QEMU IRTE reuse does not qualify general VM passthrough.

## 13. Testing, CI and fuzzing

| Layer | Evidence | Limit |
| --- | --- | --- |
| Source/build | fmt/Clippy/lints/ABI C oracle/build/linked usercopy | Not runtime completeness |
| Hosted | 438 counted executions/profile, CpuLocal doctests, three compile checks | Host-safe allowlist; privileged paths guest-only |
| Harness | Python JUnit/coverage, shell syntax, outcome/parser regressions | Host coverage, not kernel instruction coverage |
| Required QEMU | Boot/runtime/SMP, UP/four-CPU musl, IOMMU/mitigation/KCOV/two-seed smoke | Qualified outcomes/emulator scope retained |
| Extended | Ubuntu 22.04/24.04, 8/16 CPU, Ext3/JBD2, six stress profiles | Scheduled/manual; stress acceptance incomplete |
| Campaigns | Eleven scheduled libFuzzer targets, corpus/opaque findings | Sampling is not absence-of-bugs/ABI completeness |
| Hardware/performance | Named matrix/protocols and future oracles | Physical VT-d/performance/thermal evidence pending |

Commands: [CI guide](ci-testing.md), [quality gates](quality-gates.md),
[script map](../scripts/README.md). Boot/runtime/SMP and musl observation windows
default to 900 seconds; mitigation, qemu-fuzz and stress retain their 900-second
budgets. Job budgets include sequential windows/setup/build/artifacts. Short mock unit
deadlines do not shorten real guest execution.

## 14. Risks and dependencies

Primary risks are ownership/accounting under pressure, partial Linux semantics
mistaken for compatibility, missing strict-profile prerequisites and hardware
claims broader than measured evidence. Retain exact source/image identity and
failure/teardown tests. Livepatch, netns device transfer, full-isolation and
retpoline must not be enabled through documentation changes.

New device/trust-boundary modes need design, negative tests and independent
review. Reuse accepted designs after checking changed premises; unavailable
hardware does not block independent software tasks.

## 15. Version history and navigation

| Revision | Change |
| --- | --- |
| 4.x | Unified development/enterprise detail and historical phases |
| 5.4, September 10 | Intermediate KSA snapshot; later acceptance/older backlog not reconciled |
| 6.0, September 12 | Restored component/phase/release detail, current gaps/evidence and conserved backlog |

[README](../README.md) · [Docs](README.md) · [Architecture](architecture.md) ·
[Nextplan](next-phase-plan.md) · [Security](security-audit-status.md) · [CI](ci-testing.md)
