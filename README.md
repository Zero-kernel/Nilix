<div align="center">

<img src="docs/assets/nilix.png" alt="Nilix" width="420">

# Nilix

### An experimental x86_64 kernel, written from scratch in Rust

**N**ilix **I**s **L**inux **I**ndependent e**X**istence: a Linux-compatible syscall subset, a
capability/LSM security framework and SMP scheduling. It boots through UEFI and runs static
Ring-3 programs and real musl binaries, pthreads included.

[![CI](https://img.shields.io/github/actions/workflow/status/Zero-kernel/Nilix/ci.yml?branch=main&style=flat&logo=githubactions&logoColor=white&label=CI)](https://github.com/Zero-kernel/Nilix/actions/workflows/ci.yml)
[![Fuzzing](https://img.shields.io/github/actions/workflow/status/Zero-kernel/Nilix/fuzz.yml?branch=main&style=flat&logo=githubactions&logoColor=white&label=fuzzing)](https://github.com/Zero-kernel/Nilix/actions/workflows/fuzz.yml)
[![Rust](https://img.shields.io/badge/rust-nightly--2025--12--08-orange?style=flat&logo=rust)](rust-toolchain.toml)
[![Platform](https://img.shields.io/badge/platform-x86__64%20%7C%20UEFI-blue?style=flat)](#quick-start)
[![Status](https://img.shields.io/badge/status-experimental-red?style=flat)](#status)
[![License](https://img.shields.io/badge/license-Apache%20%7C%20GPL%20%7C%20AGPL%20%7C%20CC%20BY-blue?style=flat)](#license)
[![Stars](https://img.shields.io/github/stars/Zero-kernel/Nilix?style=flat&logo=github)](https://github.com/Zero-kernel/Nilix/stargazers)

**English** · [中文](README_zh.md)

**[Why Nilix](#why-nilix) · [Status](#status) · [Capabilities](#capabilities) · [Architecture](#architecture) · [Quick Start](#quick-start) · [Tests and CI](#tests-and-ci) · [Roadmap](#roadmap) · [FAQ](#faq)**

</div>

---

## Why Nilix?

Nilix grows Linux compatibility one verified contract at a time, under one rule:
**Safety > Correctness > Efficiency > Performance**. It is not a Linux fork, and
compatibility is a goal, not a claim that arbitrary Linux applications or containers
already run.

- **From scratch in Rust**: 25 kernel library crates, from the UEFI loader to the
  network stack, none of them derived from Linux.
- **Linux-compatible where it is verified**: static ELF and musl binaries,
  `fork`/`exec`/`wait4`/`waitid`, signals, `poll`/`select`, and Linux futex ops including
  requeue, `WAKE_OP` and priority-inheritance locks.
- **Real threads**: thread groups in every build, with a shared signal table, fd table
  and fs context, group-wide signals and children, and exec from any thread. musl
  pthreads pass on 1-16 CPUs.
- **SMP throughout**: per-CPU MLFQ with preemption, work stealing, affinity and cpusets,
  APIC/IPI/TLB shootdown and RCU.
- **Security built in**: generation-checked capabilities, LSM hooks, seccomp and pledge
  subsets, NX/W^X, SMEP/SMAP/UMIP, KASLR, hash/HMAC audit, and a VT-d path tested under
  QEMU.
- **Storage and networking**: a VFS with ramfs/ext2/JBD2 subsets and procfs/devfs/cgroupfs,
  virtio-blk, and virtio-net with IPv4/TCP/UDP and a default-DROP firewall.
- **Evidence over claims**: 515 hosted unit tests per profile, QEMU boot/SMP/musl/Ring-3
  gates, KCOV fuzzing, 900-second stress soaks and independent security audits.
  A *qualified* result is never reported as a pass.

## Status

> [!WARNING]
> Nilix is experimental and **1.0-Preview is blocked**. Most services still run in
> Ring 0; a deprivileged Linux personality and broader application compatibility are
> planned work.

| Area | Where it stands |
| --- | --- |
| **Latest batch** (2026-10-21) | Thread groups enabled in every build: exec from a thread group, group-wide signals and children, procfs thread lists, futex parity and PI futexes. Final gate ladder: build, lint, clippy, 515 hosted tests and the Ring-3 MM oracle pass; boot, runtime and SMP gates are zero-failure qualified; seven thread soaks ran without a stall |
| **September KSA audit** | All 20 findings accepted within their rubrics; R186-4 admission closure, ST-K2 shared-anonymous demand paging and MM 3.3 bounded primitives implemented |
| **Not qualified yet** | Complete Linux compatibility, guest musl/usercopy/teardown breadth, physical hardware and physical VT-d, full KPTI isolation, compiler retpoline, production livepatch |
| **Release work** | R188 review-lineage reconciliation, strict supported-profile tests and all seven stress-v2 profiles; the clean full-audit streak stands at **0/3** |

Details: [security status](docs/security-audit-status.md) ·
[release conditions](docs/roadmap.md#8-10-preview-release-gate) ·
[current handoff](docs/review/design/next-handoff-2026-10-20.md).

## Capabilities

What works today, and what is still missing. A subsystem is never called complete
just because its API or source files exist.

### Core kernel

| Component | What works | Still missing |
| --- | --- | --- |
| UEFI and boot | PIE kernel loading/relocation, memory-map handoff, KASLR placement, console initialization; boots with 2 GiB or more and reads ACPI tables above 1 GiB | x86_64 platform scope; broader firmware/hardware and early-boot W+X qualification |
| Memory | Buddy/global heap, charged fallible containers, guards, anonymous mmap/munmap/mprotect/brk, COW fork, cache/OOM machinery; mmap flag allowlist, demand-paged shared-anonymous regions, private-anonymous `mremap` (in-place grow/shrink + `MREMAP_MAYMOVE`) and bounded slab/NUMA/swap/THP primitives | Independent review of the MM slice (its remote gates and the Ring-3 oracle pass); MAP_FIXED/file mappings, shared-anonymous `mremap`, and integrated slab/NUMA/swap/THP backends remain unqualified |
| Process lifecycle | Static ELF, fork/exec/exit/wait4, zombie/namespace identity and teardown tests; `waitid` (`P_ALL`/`P_PID`, `WNOHANG`/`WNOWAIT`, `siginfo_t` copyout) sharing one reap engine with `wait4`; root PID-namespace init registered through the normal PID chain; WNOWAIT-then-reap, copyout faults, ROOT-INIT orphan adoption and fork refusal under `pids.max` are guest-verified | `waitid` `P_PGID` and `WUNTRACED`/`WCONTINUED` fail closed with EINVAL; PID1 exit, reaper races and the attach-time/fd-charge rollback paths are uncovered |
| Threads and TLS | Thread groups in every build (CLONE_VM/SIGHAND/THREAD/FILES/FS): shared signal table with a group pending set, fs context and fd table; group exit, fatal signals and stop; tkill/tgkill; exactly-once reaping and group-wide children; exec from the leader or any thread; procfs `task/` lists. FS/user-GS restoration across SMP migration. musl `pthread_create`/`join`/mutex/condition variables/TLS/signals pass on 1-16 CPUs | A handler signal waits while a thread is blocked in LOCK_PI (no restart); no sigaltstack or rt_tgsigqueueinfo; sigframes only on the main or an mmap'd stack; reviewed D3-D5 debt in the [design](docs/review/design/gap-5-slice4-thread-group-design.md) |
| Scheduler and SMP | Per-CPU MLFQ/preemption, work stealing from every CPU, balancing, affinity/cpuset, APIC/IPI/TLB, RCU/lock ordering, guard-free SCHED-TRAP and a switch sentinel; `/proc/schedstat` per-CPU switch/migration counters; memory/cpu/smp/thread stress soaks qualify on 4 vCPUs | Process/block/combined soak profiles, physical and longer high-core qualification; 64 CPUs boot in QEMU as a reject ceiling, not a tested workload |

### IPC, files, storage and networking

| Component | What works | Still missing |
| --- | --- | --- |
| IPC and signals | Capability-backed pipes, Linux futex ops (WAIT/WAKE, true REQUEUE/CMP_REQUEUE, WAKE_OP, partial bitsets, PI lock/trylock/unlock with priority inheritance, requeue-PI) keyed by address space, robust cleanup, masks/handlers/return, blocked-signal tests, poll/select | Native synchronous IPC/shared-memory completion, sigaltstack/queued-RT/restart semantics, PI ABBA `EDEADLK` detection |
| File descriptors | Ordinary fd 0/1/2, dup/close/fork/exec/CLOEXEC, shared status flags, O_NONBLOCK consumers and NOFILE enforcement | Broader fcntl/rlimit semantics |
| VFS and paths | ramfs/ext2/JBD2 subset, procfs/devfs/CPIO/cgroupfs; cwd/root/pivot, symlink/jail resolution, DAC/UID/GID, mount retirement | General dirfd, chown/statx/hard links, terminal fidelity and full POSIX/filesystem compatibility |
| Storage | Owned BIO/completion, virtio-blk, checked 512B/4096B geometry and guest I/O evidence | fsync/fdatasync/sync/sync_file_range not wired; power-loss/recovery/cache qualification |
| Networking | virtio-net, Ethernet/ARP/IPv4/ICMP/UDP/TCP, conntrack/default-DROP firewall machinery, per-netns state and process-context RX | veth/child RX/routes/admin/loopback breadth, IPv6 and wire interoperability; device transfer remains disabled |

### Isolation and security

| Component | What works | Still missing |
| --- | --- | --- |
| Namespaces and cgroups | PID/mount/IPC/net/user objects, selected CPU/memory/PIDs/I/O/files/ports controllers and transactional resource tests | Full cgroups-v2/delegation/OCI, init membership, namespace/clone combinations and container networking |
| Capabilities / LSM / seccomp | Generation-checked authority, credential-bound publication, policy hooks, supported filter/pledge paths | Native capability syscall family, per-netns administration and TSYNC |
| Memory hardening | NX/W^X/guards/SMEP/SMAP/UMIP, KASLR, RNG/CSPRNG/kptr and exact usercopy recovery | Full KPTI false; dual roots still contain kernel mappings; compiler retpoline unsupported and CPU controls vary |
| VT-d | DMAR boot wiring; Q35 init failures and EDU translated DMA/MSI/invalidation/quarantine/reuse tested | Physical qualification, MSI-X, multi-unit/bridge/RMRR/ACCESS_PLATFORM and modern modes |
| Livepatch | Unsupported behavior tested; experimental parser/signature/lifecycle code retained | All mutation/syscall paths reject ENOSYS; real hooks/keys/SMP rollback required |
| Audit and observability | Hash/HMAC audit, authorized trace/counters, profile logs, watchdog/profiler/serial kdump | Durable/remote backend, key operations and measured performance; no FIPS certification |

### Userspace and tooling

| Component | What works | Still missing |
| --- | --- | --- |
| Userspace and compatibility | Native libc helpers/development shell, static ET_EXEC/musl/SysV auxv and selected ABI layouts; musl pthreads | ET_DYN/dynamic loader/vDSO, glibc, general application/OCI and userspace personality |
| Tests and fuzzing | Hosted debug/release, harness JUnit/coverage, real KCOV/two-seed QEMU smoke, scheduled fuzz/extended groups | Deferred guest tests, seven-profile stress acceptance and real performance/thermal evidence |

The [full roadmap](docs/roadmap.md#4-kernel-composition) covers all **25 kernel library
crates**, implementation evidence, threat boundaries, Linux comparison, phase history and
named backlog owners. The [VT-d matrix](docs/vtd-support-matrix.md) and
[livepatch status](docs/livepatch-support.md) define their support limits.

## Architecture

Ring 3 → architecture entry/usercopy → policy gates → kernel_core → kernel services →
hardware. The Cargo split organizes the code; most services do not yet run in separate
privilege domains.

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
narratives; the roadmap is the current capability and qualification reference.

## Quick Start

### Prerequisites

The complete build and QEMU toolchain runs on Linux.

| Requirement | Notes |
| --- | --- |
| Rust **nightly-2025-12-08** | With `rust-src` and `llvm-tools-preview`, pinned in [rust-toolchain.toml](rust-toolchain.toml) |
| Targets | `x86_64-unknown-none` and `x86_64-unknown-uefi` |
| Build and emulation | GNU Make, QEMU (`qemu-system-x86_64`), OVMF, a C compiler, e2fsprogs |
| musl | `musl-tools` / `musl-gcc` for the musl and guest-workload images |
| Python | Test dependencies from [requirements-ci.txt](requirements-ci.txt) |

### Build and run

```sh
make build                  # UEFI bootloader and kernel image in esp/
make run-serial             # boot in QEMU with a serial console
make run-shell              # development shell
make run-blk                # disposable ESP plus the configured virtio disk
make run-smp SMP_CPUS=4     # four logical CPUs
make build-musl-test        # dedicated musl image
```

### Run the CI groups locally

```sh
bash scripts/ci/entrypoint.sh quality   # lint, Python harness tests, shell syntax, Ext3 fixture
bash scripts/ci/entrypoint.sh hosted    # hosted kernel sub-crate unit tests
bash scripts/ci/entrypoint.sh build     # kernel image and usercopy exception-table check
bash scripts/ci/entrypoint.sh runtime   # boot, runtime and 4-CPU SMP guests
bash scripts/ci/entrypoint.sh musl      # musl guest on 1 and 4 CPUs
```

> [!NOTE]
> Guest gates observe each QEMU run for **900 seconds** by default (the runtime group runs
> three windows in sequence), so a quiet host is waiting, not hung. A nonzero `make` exit
> can mean a *qualified* guest result: read the group report and the original gate status.
> The default CPU model cannot satisfy every security or hardware test.

## Tests and CI

| Measure | Count |
| --- | --- |
| Hosted unit tests | **515** per debug/release profile, plus CpuLocal doctests and 3 test-code compile checks |
| Runtime tests discovered | **74** `RuntimeTest` implementations (a source count, not 74 guest passes) |
| Stress-v2 profiles | **7**, 900 seconds each |
| Fuzz campaigns | **11** scheduled campaigns, plus deterministic KCOV smoke |

| Workflow | When | Coverage |
| --- | --- | --- |
| `CI` | Push/PR to main; manual | Quality, hosted debug/release, tools, kernel build, boot/SMP, musl, IOMMU, KCOV/executor; one `CI result` |
| `Extended tests` | Sunday 03:00 UTC; manual | Ubuntu 22.04/24.04, 8/16-CPU SMP, Ext3/JBD2, seven 900-second stress profiles, IOMMU compatibility |
| `Fuzzing` | Daily 02:00 UTC; manual | 11 private libFuzzer campaigns with validated public result manifests |

JUnit, Markdown summaries, logs and source/image identities preserve each outcome. Python
coverage measures host harness code. Qualified diagnostic results stay distinct from
strict passes, and guest gates retry one failed or incomplete QEMU attempt by default,
keeping both attempts in the report. Full stress acceptance is still blocked by kernel and
workload gaps, and fuzz sampling is not proof of completeness.

[CI guide](docs/ci-testing.md) · [Quality gates](docs/quality-gates.md) ·
[Script categories](scripts/README.md)

## Roadmap

1. **Audit the thread-group batch**: a security audit and review-fix pass over the
   2026-10-21 work, then the open thread debt (PI handler signals, a serial console lock).
2. **Strict qualification**: reconcile the R188 review lineage and complete strict guest
   qualification.
3. **Release conditions**: all seven stress profiles (process, block and combined still
   need `RLIMIT_NPROC`, `fsync` and `open` modes), strict network/SMP/security matrices
   and fresh full-audit conditions.
4. **After qualification**: native capability/IPC, static ABI residuals,
   personality/dynamic linking, container networking and measured operations/performance.

Dependencies and acceptance: [roadmap](docs/roadmap.md#10-forward-roadmap) ·
[current plan](docs/next-phase-plan.md) ·
[current handoff](docs/review/design/next-handoff-2026-10-20.md). Completed audit repairs
stay as regressions; they are not rescheduled.

## FAQ

<details>
<summary><strong>Is Nilix a Linux fork?</strong></summary>

No. Nilix is written from scratch; no part of it is derived from Linux. It implements a
Linux-compatible syscall subset so that Linux programs can run where the contract is
verified.

</details>

<details>
<summary><strong>Can it run my Linux applications?</strong></summary>

Not in general. Static ET_EXEC programs and musl binaries run within the supported subset,
including pthreads. There is no dynamic loader, vDSO or glibc yet, and containers and OCI
images are out of reach for now. The [capability tables](#capabilities) list what works.

</details>

<details>
<summary><strong>What does a "qualified" gate result mean?</strong></summary>

The guest ran to completion with zero failures, but some tests were deferred or skipped
(for example `passed=35 deferred=39 failed=0`). Qualified results are recorded separately
from strict passes, and `make` exits nonzero for them, so read the report rather than the
exit code alone.

</details>

<details>
<summary><strong>Why does every QEMU gate take about 15 minutes?</strong></summary>

Each guest gate keeps the guest under observation for a fixed 900-second window, even when
the guest finishes in a minute or two. Run independent gates in parallel to save time.

</details>

<details>
<summary><strong>How do I report a security issue?</strong></summary>

Privately, as described in [SECURITY](SECURITY.md). Please do not open a public issue.

</details>

## Documentation

| Goal | Reference |
| --- | --- |
| Capabilities, gaps and release conditions | [Roadmap](docs/roadmap.md) |
| Prioritized work and handoff | [Next-phase plan](docs/next-phase-plan.md) |
| Architecture and documentation index | [Architecture](docs/architecture.md) · [Docs](docs/README.md) |
| CI, tests and fuzzing | [CI](docs/ci-testing.md) · [Quality gates](docs/quality-gates.md) |
| Audit evidence and recent changes | [Security status](docs/security-audit-status.md) · [Commit history](https://github.com/Zero-kernel/Nilix/commits/main/) |

## Contributing

Read [CONTRIBUTING](CONTRIBUTING.md), [GOVERNANCE](GOVERNANCE.md) and the
[CODE_OF_CONDUCT](CODE_OF_CONDUCT.md) first. Changes should include meaningful
regressions and evidence that matches their risk. Report vulnerabilities privately through
[SECURITY](SECURITY.md), and use [SUPPORT](SUPPORT.md) for other questions.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Zero-kernel/Nilix&type=Date)](https://www.star-history.com/#Zero-kernel/Nilix&Date)

## License

Nilix is licensed per component, in the style of the Rust project.
[COPYRIGHT](COPYRIGHT) maps every path to exactly one license:

| Component | License |
| --- | --- |
| Kernel, bootloader and the rest of the Rust code | [Apache-2.0](LICENSE-APACHE) |
| GNU-related code: C programs built with GCC/musl-gcc, and the Makefile | [GPL-3.0-or-later](LICENSE-GPL) |
| Test, stress, fuzz and CI scaffolding | [AGPL-3.0-or-later](LICENSE-AGPL) |
| Documentation and images | [CC-BY-4.0](LICENSE-CC-BY) |

A contribution is licensed under the license of the files it changes; see
[CONTRIBUTING](CONTRIBUTING.md#8-licensing).

## References

[OSDev](https://wiki.osdev.org) · [Writing an OS in Rust](https://os.phil-opp.com) ·
[Linux](https://kernel.org) · [seL4](https://sel4.systems)
