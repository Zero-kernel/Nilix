# Nilix

[中文](README_zh.md) · [Roadmap and component status](docs/roadmap.md) ·
[Next-phase plan](docs/next-phase-plan.md) · [CI](docs/ci-testing.md)

Nilix is an experimental operating-system kernel written primarily in Rust for
x86_64, with a Linux-compatible syscall subset and a capability/LSM security
framework. It boots through UEFI, runs static Ring-3 programs and a real musl
test binary, and includes SMP scheduling, VFS/storage and IPv4 networking.

**Nilix** means **N**ilix **I**s **L**inux **I**ndependent e**X**istence: a
from-scratch kernel, not a Linux fork. Linux compatibility is an incremental
goal, not a claim that arbitrary Linux applications or containers already run.

**Design principle:** Safety > Correctness > Efficiency > Performance.

## Status

**Snapshot: 2026-09-14**, local implementation working tree; exact final source remotely verified on `40c-devbox-ts` in `/tmp/zero-os-codex-final-20260913` for hosted/MM/core/build/lint, with zero-failure qualified runtime/boot/4-core SMP gates.

**1.0-Preview is blocked.** Most services still execute in Ring 0. A deprivileged
Linux personality and broader application compatibility are planned.

The September KSA audit's 20 findings are accepted within their specific rubrics. R186-4 admission closure, ST-K2 shared-anonymous demand paging and MM 3.3 bounded primitives are implemented; the exact final source passes the remote hosted/MM/core/build/lint gates.

The implementation does not establish complete Linux, guest musl/usercopy/teardown, hardware or security qualification.

Release work still includes reconciliation of original R188 review obligations, strict supported-profile tests and **all six stress-v2 profiles**.

The recorded clean full-audit streak remains **0/3**. Physical VT-d, full KPTI isolation, compiler retpoline and production livepatch are not qualified capabilities. See [security status](docs/security-audit-status.md) and the [release conditions](docs/roadmap.md#8-10-preview-release-gate).

## What works, and what is missing

This table describes supported subsets and active code. It deliberately avoids
calling an entire subsystem complete because its API or source files exist.

| Component | Current capability | Remaining gap / boundary |
| --- | --- | --- |
| UEFI and boot | PIE kernel loading/relocation, memory-map handoff, KASLR placement, console initialization | x86_64 platform scope; broader firmware/hardware and early-boot W+X qualification |
| Memory | Buddy/global heap, charged fallible containers, guards, anonymous mmap/munmap/mprotect/brk, COW fork, cache/OOM machinery; mmap flag allowlist, demand-paged shared-anonymous regions, private-anonymous `mremap` (in-place grow/shrink + `MREMAP_MAYMOVE`) and bounded slab/NUMA/swap/THP primitives | Remote MM/core/hosted/build/lint verification is complete for this slice and `mremap` is remote-validated with the Ring-3 oracle gate (`make test-ring3-mm`) passing, but independent review is still pending; MAP_FIXED/file mappings, shared-anonymous `mremap`, and integrated slab/NUMA/swap/THP backends remain unqualified |
| Process lifecycle | Static ELF, fork/exec/exit/wait4, zombie/namespace identity and teardown tests; `waitid` (`P_ALL`/`P_PID`, `WNOHANG`/`WNOWAIT`, `siginfo_t` copyout) sharing one reap engine with `wait4`, and root PID-namespace init registered through the normal PID chain | `waitid` `P_PGID` and `WUNTRACED`/`WCONTINUED` are fail-closed EINVAL, not supported; PID1 exit, reaper races and the attach-time/fd-charge rollback paths are uncovered (waitid WNOWAIT-then-reap, copyout-fault, ROOT-INIT orphan adoption and fork refusal under `pids.max` are guest-verified); PID1/reaper races and remaining failure/stress breadth |
| Threads and TLS | Restricted CLONE_VM/TLS setup, FS/user-GS restoration tested across SMP migration | General CLONE_THREAD/CLONE_FILES/CLONE_FS/CLONE_SIGHAND rejected; not pthread compatibility |
| Scheduler and SMP | Per-CPU MLFQ/preemption, work stealing, balancing, affinity/cpuset, APIC/IPI/TLB, RCU/lock ordering | High-core/long-run/physical qualification; 64 is a CPU ceiling, not a tested topology claim |
| IPC and signals | Capability-backed pipes, futex primitives/robust cleanup, masks/handlers/return, blocked-signal tests, poll/select | Native synchronous IPC/shared-memory completion, Linux futex parity, sigaltstack/queued-RT/restart semantics |
| File descriptors | Ordinary fd 0/1/2, dup/close/fork/exec/CLOEXEC, shared status flags, O_NONBLOCK consumers and NOFILE enforcement | Broader fcntl/rlimit/thread-sharing semantics |
| VFS and paths | ramfs/ext2/JBD2 subset, procfs/devfs/CPIO/cgroupfs; cwd/root/pivot, symlink/jail resolution, DAC/UID/GID, mount retirement | General dirfd, chown/statx/hard links, terminal fidelity and full POSIX/filesystem compatibility |
| Storage | Owned BIO/completion, virtio-blk, checked 512B/4096B geometry and guest I/O evidence | fsync/fdatasync/sync/sync_file_range not wired; power-loss/recovery/cache qualification |
| Networking | virtio-net, Ethernet/ARP/IPv4/ICMP/UDP/TCP, conntrack/default-DROP firewall machinery, per-netns state and process-context RX | veth/child RX/routes/admin/loopback breadth, IPv6 and wire interoperability; device transfer remains disabled |
| Namespaces and cgroups | PID/mount/IPC/net/user objects, selected CPU/memory/PIDs/I/O/files/ports controllers and transactional resource tests | Full cgroups-v2/delegation/OCI, init membership, namespace/clone combinations and container networking |
| Capabilities / LSM / seccomp | Generation-checked authority, credential-bound publication, policy hooks, supported filter/pledge paths | Native capability syscall family, per-netns administration and TSYNC |
| Memory hardening | NX/W^X/guards/SMEP/SMAP/UMIP, KASLR, RNG/CSPRNG/kptr and exact usercopy recovery | Full KPTI false; dual roots still contain kernel mappings; compiler retpoline unsupported and CPU controls vary |
| VT-d | DMAR boot wiring; Q35 init failures and EDU translated DMA/MSI/invalidation/quarantine/reuse tested | Physical qualification, MSI-X, multi-unit/bridge/RMRR/ACCESS_PLATFORM and modern modes |
| Livepatch | Unsupported behavior tested; experimental parser/signature/lifecycle code retained | All mutation/syscall paths reject ENOSYS; real hooks/keys/SMP rollback required |
| Audit and observability | Hash/HMAC audit, authorized trace/counters, profile logs, watchdog/profiler/serial kdump | Durable/remote backend, key operations and measured performance; no FIPS certification |
| Userspace and compatibility | Native libc helpers/development shell, static ET_EXEC/musl/SysV auxv and selected ABI layouts | ET_DYN/dynamic loader/vDSO, glibc/pthread, general application/OCI and userspace personality |
| Tests and fuzzing | Hosted debug/release, harness JUnit/coverage, real KCOV/two-seed QEMU smoke, scheduled fuzz/extended groups | Deferred guest tests, six-profile stress acceptance and real performance/thermal evidence |

The [full roadmap](docs/roadmap.md#4-kernel-composition) covers all **25 kernel
library crates**, implementation evidence, threat boundaries, Linux comparison,
phase history and named backlog owners. The [VT-d matrix](docs/vtd-support-matrix.md)
and [livepatch status](docs/livepatch-support.md) define their support limits.

## Architecture at a glance

Ring 3 → architecture entry/usercopy → policy gates → kernel_core →
kernel services → hardware. Cargo separation is modular organization; most
services are not yet separated into distinct privilege domains.

<p align="center">
  <img src="docs/assets/architecture-at-a-glance.svg" alt="Nilix kernel component and execution map" width="960">
</p>

| Path | Source entrypoints | Responsibility |
| --- | --- | --- |
| Boot | [UEFI loader](bootloader/src/main.rs), [kernel _start](kernel/src/main.rs) | Load/relocate, publish BootInfo and initialize services |
| Syscall | [SYSCALL entry](kernel/arch/syscall.rs), [dispatcher](kernel/kernel_core/syscall.rs) | Register frame/usercopy, policy and supported Linux/private operations |
| Process / MM | [fork/COW](kernel/kernel_core/fork.rs), [process/teardown](kernel/kernel_core/process.rs), [paging](kernel/mm/page_table.rs) | Ownership, publication, isolated address spaces and reclaim |
| Scheduling | [MLFQ](kernel/sched/enhanced_scheduler.rs), [context switch](kernel/arch/context_switch.rs) | CPU-local runnable state, affinity, TLS/FPU/entry-state handoff |
| Storage / VFS | [VFS manager](kernel/vfs/manager.rs), [Ext2](kernel/vfs/ext2.rs), [block](kernel/block/src/lib.rs) | Paths/authorization, filesystem transactions and owned I/O |
| Network | [stack](kernel/net/src/stack.rs), [socket](kernel/net/src/socket.rs) | Protocol/RX work, policy, queues and wakeup |
| Security / devices | [security](kernel/security/lib.rs), [LSM](kernel/lsm/lib.rs), [VT-d](kernel/iommu/lib.rs) | Enforce/report supported protections and device authority |

See [architecture.md](docs/architecture.md) for layering, boot flow and subsystem
narratives. The roadmap is the current capability/qualification reference.

## Tests and CI

The current hosted allowlist runs **454 counted unit-test executions per
debug/release profile**, CpuLocal doctests and three test-code compile checks.
The runtime scanner discovers **74 RuntimeTest implementations**; that count
does not mean 74 guest passes or 100% kernel instruction coverage.

The shared CI groups run source checks, hosted tests, feature-specific builds,
boot/SMP, one-/four-CPU musl, IOMMU, mitigation and real KCOV/fuzz guests.
JUnit, Markdown summaries, logs and source/image identities preserve each
outcome. Python coverage measures host harness code. Diagnostic qualified
results remain distinct from strict passes. Guest gates retry one failed or
incomplete QEMU attempt by default and retain both attempts in the report.

Stress runs cover six defined profiles on a weekly/manual workflow, but full
acceptance is still blocked by kernel/workload gaps. Eleven scheduled fuzz
campaigns complement deterministic smoke; sampling is not proof of completeness.
[CI guide](docs/ci-testing.md) · [Quality gates](docs/quality-gates.md) ·
[Script categories](scripts/README.md).

## Quick start

Use Linux for the complete build/QEMU toolchain:

- Rust **nightly-2025-12-08**, with rust-src and llvm-tools-preview, as pinned in
  [rust-toolchain.toml](rust-toolchain.toml).
- Targets: x86_64-unknown-none and **x86_64-unknown-uefi**.
- GNU Make, QEMU system x86_64, OVMF, a C compiler and e2fsprogs.
- musl-tools/musl-gcc for the musl and guest-workload builds.
- Python test dependencies from [requirements-ci.txt](requirements-ci.txt).

```sh
make build                 # UEFI bootloader and normal kernel image in esp/
make run-serial            # QEMU serial console
make run-shell             # Development shell
make run-blk               # Disposable ESP plus the configured virtio disk
make run-smp SMP_CPUS=4     # Four logical CPUs
make build-musl-test        # Dedicated musl image
bash scripts/ci/entrypoint.sh quality
bash scripts/ci/entrypoint.sh hosted
bash scripts/ci/entrypoint.sh build
bash scripts/ci/entrypoint.sh runtime
bash scripts/ci/entrypoint.sh musl
```

Boot/runtime/SMP and musl guest observation windows default to **900 seconds**.
The boot/runtime/SMP group
has three sequential windows. A nonzero make exit can represent a qualified
guest result; use the retained group report and original gate status to diagnose
it. The default CPU/profile cannot satisfy every security/hardware test.

## Next milestones

1. Reconcile outstanding R188 review lineage and close R186-4 admission.
2. Make mmap flags honest, replace stress report-page assumptions and implement
   the scoped durability/block workload.
3. Add shared-anonymous memory and qualify all six stress profiles, supported
   network/SMP/security matrices and fresh full-audit release conditions.
4. Resume native capability/IPC, static ABI residuals, personality/dynamic
   linking, container networking and measured operations/performance.

Detailed dependencies and acceptance: [current nextplan](docs/next-phase-plan.md).
Completed KSA repairs are retained as regressions, not scheduled for reimplementation.

## Documentation and contributing

| Goal | Reference |
| --- | --- |
| Capabilities / gaps / release conditions | [Roadmap](docs/roadmap.md) |
| Prioritized work and handoff | [Nextplan](docs/next-phase-plan.md) |
| Architecture / documentation index | [Architecture](docs/architecture.md) · [Docs](docs/README.md) |
| CI / tests / fuzzing | [CI](docs/ci-testing.md) · [Quality gates](docs/quality-gates.md) |
| Audit evidence / recent changes | [Security status](docs/security-audit-status.md) · [Commit history](https://github.com/Zero-kernel/Nilix/commits/main/) |

Read [CONTRIBUTING](CONTRIBUTING.md), [GOVERNANCE](GOVERNANCE.md) and
[CODE_OF_CONDUCT](CODE_OF_CONDUCT.md). Report vulnerabilities privately through
[SECURITY](SECURITY.md); use [SUPPORT](SUPPORT.md) for other questions.
Include meaningful regressions and risk-appropriate evidence with changes.

## License

License terms are currently TBD.

## References

[OSDev](https://wiki.osdev.org) · [Writing an OS in Rust](https://os.phil-opp.com) ·
[Linux](https://kernel.org) · [seL4](https://sel4.systems)
