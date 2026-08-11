# Nilix

[Switch to Chinese (切换到中文)](README_zh.md)

A security-first hybrid microkernel operating system written in Rust for the x86_64 architecture.

> **Nilix** is a recursive acronym — **N**ilix **I**s **L**inux **I**ndependent e**X**istence — in the
> self-referential naming tradition of GNU and Linux. The name captures the positioning: Linux-*compatible*
> (a byte-exact syscall ABI runs a real musl libc binary unmodified) yet Linux-*independent* (its own
> from-scratch Rust kernel, not a fork).

**Design Principle:** Security > Correctness > Efficiency > Performance

---

## 1. Overview

Nilix is an enterprise-grade hybrid kernel inspired by Linux's modular design, hardened
through **186 successive security-audit rounds**. It pairs a capability- and LSM-gated
in-kernel hot path with a roadmap toward a de-privileged Linux-compatible user-space
personality.

- **Memory Safety** — written entirely in Rust (`no_std`), backed by hardware protections
  (NX, W^X, SMEP/SMAP/UMIP) and KASLR/KPTI.
- **Process Isolation** — per-process address spaces, Copy-on-Write fork, user-stack guard pages.
- **SMP** — multi-core bring-up (up to 64 CPUs), per-CPU MLFQ scheduling, work-stealing load
  balancing, IPI-driven TLB shootdown, RCU and lockdep.
- **Security Framework** — object capabilities, an LSM hook layer (40+ hook points),
  seccomp/pledge syscall filtering, and a SHA-256 hash-chained tamper-evident audit log.
- **Containers** — five namespaces (PID/mount/IPC/net/user) and cgroups v2 (CPU, memory, PIDs,
  I/O, FD, port controllers), plus a per-namespace network dataplane (isolated ARP caches,
  addressing, and routing) held under per-namespace byte budgets.
- **Network** — a full software TCP/IP stack (TCP with NewReno, window scaling, SYN cookies,
  connection tracking, and a stateful default-DROP firewall), fed by a bounded process-context
  RX ingress loop that ingests real frames off `eth0`.
- **Linux ABI** — a byte-exact x86-64 syscall surface; a real **static-musl libc binary runs
  end-to-end** under the user-mode ABI (Phase U / milestone M0).

### Current Status

**Milestone:** approaching **1.0-Preview** — Phase A–G complete; **Phase U** (user-mode ABI)
in progress. The 1.0-Preview release gate remains **BLOCKED** on the carried `R186-4` HIGH
(VMA/MM aggregate admission) and its design parent; the zero-HIGH streak is **0/3**. R187
(KCOV remediation) closed clean — all 7 findings fixed and 8/8 review-fix defects repaired —
but did not advance the streak, because `R186-4` is carried debt, not an R187 finding. See [Section 6](#6-security-audit-status).

**Recent Additions:**
- **2026-08-08:** **R187 KCOV remediation + ReviewFix closure** — the KCOV observability surface
  was hardened across authority, admission context, and topology to make coverage *measurement*
  accurate and fail-closed: (1) KCOV authority is **host-root-only** — the reserved
  `CapRights::KCOV` bit no longer authorizes access, pending a reviewed identity-bound issuance
  protocol; (2) an allocation-free IRQ-return **soft-progress guard** keeps KCOV admission
  fail-closed on the deferred-callback drain and rejects recursive re-entry; (3) the CPU online
  topology is unified under one authoritative `cpu_local` mask (TLB/IPI/scheduler/KCOV all read
  it) with reciprocal-LAPIC validation and idempotent publication; (4) the fuzzer ABI reports
  **occupied KCOV bitmap slots** (not source edges) and bounds KCOV control retries. ReviewFix
  closure verified 7/7 fixes PASS and 8/8 review-fix defects repaired (0 escalated); the remote
  fmt/clippy/build/lint/test/boot/musl ladder is green. The gate stays BLOCKED on carried
  `R186-4`. See [Section 6](#6-security-audit-status).
- **2026-08-05:** **Cargo-fuzz QEMU Integration** — Extended fuzzing infrastructure with cargo-fuzz targets
  for syscall execution against the real KCOV-enabled kernel. New components: (1) `fuzz_syscall_qemu` target
  with lazy QEMU executor initialization and safe syscall allowlist (19 syscalls); (2) Bridge module
  (`syz_bridge.rs`) interfacing with the standalone `nilix-syz-fuzzer` binary; (3) QEMU executor stub
  (`qemu_executor.rs`) ready for vendoring; (4) Makefile integration (`make fuzz-qemu-smoke`, 
  `make fuzz-qemu-campaign`, parallel/overnight targets); (5) Feature-gated compilation (`qemu-executor`);
  (6) Documentation updates (fuzz/README.md, FUZZING_SUMMARY.md). Architecture provides both mock-based
  fast iteration (50K exec/sec) and QEMU-based deep testing (5-10 exec/sec with real KCOV). Three new
  fuzz targets for buddy allocator, page table operations, and syscall execution. See [Section 5.5](#55-fuzzing-infrastructure).
- **2026-08-04:** **Phase 7 Syzkaller-Style Fuzzing COMPLETE** — Host-driven coverage-guided fuzzing
  infrastructure is now operational. Built and integrated: (1) Rust-based host fuzzer with 5 mutation
  strategies, energy-based corpus scheduling, and crash classification; (2) C-based guest executor with
  KCOV integration running in QEMU; (3) GitHub Actions CI workflow with weekly scheduled runs and corpus
  caching; (4) 600+ line syscall grammar (`.syz` format) covering 40+ syscalls; (5) Makefile targets
  (`make run-syz-fuzz`, `make test-syz`); (6) 2,800+ lines of comprehensive documentation. Performance:
  5-10 exec/sec, 50-200 new edges/hour (early phase). See [Section 5.5](#55-fuzzing-infrastructure).
- **2026-08-03:** R186-4 HIGH fix complete — VMA/MM metadata admission via `AdmittedMap` migration.
  All `mmap_regions` and `pt_charged_frames` maps now use `AdmittedMap<HeapClass::CoreProcess>`,
  charging their backing Vec capacity to the per-process heap budget. Fork uses
  `from_sorted_vec_charged` with `shrink_to_fit` pre-charge to prevent capacity amplification.
  Three convergence issues resolved: (1) shrink before charge, (2) propagate errors instead of
  panic, (3) no double-uncharge on reservation failure. Three new runtime tests validate coexistence,
  pressure scenarios, and fork combined-load. The zero-HIGH streak advances to **1/3**; 1.0-Preview
  is now blocked on streak only. Gate status: `make test` **34 passed / 39 deferred / 0 failed**;
  boot-check, musl-check, and all CI gates remain green.
- **2026-07-30:** Authoritative R186 ReviewFix source and environment closure — 16 landed fixes
  were reviewed: **2 PASS / 12 PARTIAL / 2 FAIL**. All **24 review-fix defects**
  (`RF186-1`…`RF186-24`) are repaired with **0 escalations**; the source/test
  judges and independent RF186-20..24 security reviewer returned **SAFE**.
  Focused/default-parallel checks and the final remote ladder are green: net 110/110,
  conntrack stress 50/50, and boot/musl PASS.
- **2026-07-28:** R186 remediation — 16 of 17 actionable findings are fully fixed and one
  remains open. The landed set removes the open/openat publication
  deadlock, makes netns and VFS allocation paths fallible, validates VirtIO PCI capability
  windows against atomically sized BARs with device decoders off, rejects invalid ext2 inode
  and block-ownership aliases, gives `SYN_SENT` a terminal timeout owner, distinguishes
  retryable COW contention, shares credential generations across threads, and makes
  audit/capability reporting truthful. The default gate is **31 passed / 39 deferred / 0 failed**.
- **2026-07-27:** D3 PENDING-FRAME v2 — park-on-miss + retransmit-on-learn architecture retires
  gateway-fallback delivery. On-link ARP misses now park data frames in a per-cache 8-slot FIFO
  (3-second TTL, oldest-evicted on full) and probe for the neighbor; learned neighbors trigger
  frame retransmission via `drain_parked_ready`. Ownership gate moved before park AND probe
  admission (ownership-denied namespaces draw no ring/bucket/queue resources). Counter conservation
  holds in quiescence: `parked_total == occupancy + retransmitted + expired + evicted + flushed +
  retx_failures`.
- **2026-07-25:** D3 network-namespace dataplane — per-namespace ARP caches, addressing and
  routing, all charged to a per-namespace byte budget; a bounded process-context RX ingress
  loop; external-device RX completion (the kernel now ingests real external frames on `eth0`);
  and ARP request-TX probe emission. Eleven new `netns_*` boot tests bring the in-kernel suite
  to **30 passed / 39 deferred / 0 failed**. See [Section 3.9](#39-containers).
- **2026-07-24:** R184 review-fix round — fixed 4 findings from R183 follow-up review: allocation-free 
  clear_child_tid validation (RF184-1), capability allocation atomicity in openat2 (RF184-2), 
  TX-memory budget accounting fix (RF184-3), and documented handle_ack precondition contract (RF184-7). 
  Updated roadmap documentation to reflect current state.
- **2026-07-23:** U.S2 SLICE-3B capability infrastructure — FileOps trait with cap_id/set_cap_id methods, 
  interior mutability via spin::once::Once, regular file capability allocation in syscall layer, and 
  credential generation TOCTOU defense during VFS open.
- **2026-07-21 (historical):** KCOV primitives, fuzzing architecture prototypes, and the first CI
  integration landed. The original "production-ready continuous fuzzing" claim was later retired:
  that worker was a pipeline simulator, not a kernel executor. See [Section 5.5](#55-fuzzing-infrastructure).

| Subsystem | Status | Highlights |
|-----------|--------|-----------|
| Boot & Memory | ✅ Complete | UEFI static-PIE boot, high-half map, reservation-aware buddy allocator, page cache, COW fork, guard pages, OOM killer |
| Process & Threads | ✅ Complete | Per-process address spaces, fork/exec/clone, threads + TLS, wait/zombie reaping, hung-task watchdog |
| Scheduler | ✅ Complete | Per-CPU MLFQ, preemptive, work-stealing + periodic load balancing, CPU affinity / cpuset |
| IPC | ✅ Complete | Pipes, capability message queues, futex (+ priority inheritance), POSIX signals |
| Hardening | ✅ Complete | W^X/NX, SMEP/SMAP/UMIP, KASLR, KPTI, Spectre/Meltdown mitigations, ChaCha20 CSPRNG, kptr guard |
| Security Framework | ✅ Complete | Capabilities, LSM (40+ hooks), seccomp/pledge, SHA-256/HMAC hash-chained audit, compliance profiles |
| VFS & Storage | ✅ Complete | ramfs, ext2, procfs, devfs, initramfs (CPIO), cgroupfs, DAC + openat2 RESOLVE flags, virtio-blk |
| Network | ✅ Complete | virtio-net, ARP, IPv4 (+reassembly), ICMP, UDP, TCP, conntrack, stateful firewall, bounded RX ingress loop with live `eth0` receive |
| SMP & Concurrency | ✅ Complete | LAPIC/IOAPIC, AP boot (≤64 CPUs), IPI TLB shootdown, PCID/INVPCID, RCU, lockdep |
| Containers | ✅ Complete | PID/mount/IPC/net/user namespaces, cgroups v2 (6 controllers), per-namespace network dataplane (ARP/addressing/routing under per-NS byte budgets) |
| IOMMU / VT-d | 🟡 Infrastructure | Full Intel VT-d driver (DMA isolation, IRQ remapping, fault handling); DMAR discovery wiring pending |
| Live Patching | 🟡 Infrastructure | ECDSA P-256 signed kpatch, INT3 detour, fail-closed LSM gate |
| User Mode & ABI (Phase U / M0) | 🟡 In Progress | Ring 3, 100+ Linux syscalls, SysV auxv, signal delivery, static-musl libc runs end-to-end |
| Fuzzing & Testing | ✅ Complete | **Syzkaller-style coverage-guided fuzzing operational**: host-driven mutation engine, QEMU executor, KCOV integration, CI workflow with corpus caching, 5 mutation strategies, crash classification. **Cargo-fuzz QEMU integration**: `fuzz_syscall_qemu` target with bridge to standalone fuzzer, mock (50K exec/sec) + QEMU (5-10 exec/sec) dual paths, 13 total targets (buddy allocator, page tables, syscalls, parsers). KCOV per-task coverage, deterministic guest E2E, extended stability/SMP/security suites |
| CI & Quality Gates | ✅ Complete | GitHub Actions (fmt/clippy, build, lint, boot+musl+fuzz), custom lint gates, local-first pre-push hook with optional SSH offload |

---

## 2. Project Structure

The kernel is a Cargo workspace of focused crates (`kernel/<subsystem>/`), each owning one
concern. The bootloader and the user-space programs are separate build units.

```text
Nilix/
├── bootloader/             # UEFI bootloader: ELF load, relocation (PIE), high-half paging, KASLR slide
├── kernel/
│   ├── arch/               # x86_64: IDT/exceptions, context switch, SYSCALL/SYSRET, GDT/TSS, APIC, SMP, IPI, INVPCID
│   ├── mm/                 # Buddy allocator, heap, page tables, page cache, TLB shootdown, OOM killer, fallible_map
│   ├── sched/              # Per-CPU MLFQ scheduler + documented lock ordering (lockdep)
│   ├── ipc/                # Pipes, capability message queues, futex (+PI), WaitQueue/KMutex/Semaphore
│   ├── kernel_core/        # PCB & process table, fork (COW), exec + ELF loader, signals, namespaces, cgroups, RCU, syscalls, KCOV
│   ├── coverage/           # KCOV infrastructure: per-task coverage tracking, edge recording, fuzzing syscalls
│   ├── cap/                # Object-capability model (CapId, CapRights, CapTable)
│   ├── lsm/                # Linux Security Module hook layer + policies
│   ├── seccomp/            # seccomp/pledge syscall filtering (BPF-like VM)
│   ├── audit/              # SHA-256 / HMAC hash-chained tamper-evident audit log
│   ├── crypto/             # Shared no_std crypto (SHA-256, ECDSA P-256) for audit + livepatch
│   ├── compliance/         # Hardening profiles (Secure / Balanced / Performance)
│   ├── security/           # W^X, NX, KASLR, KPTI, Spectre/Meltdown, kptr guard, RNG, memory hardening
│   ├── vfs/                # VFS core, ramfs, ext2, procfs, devfs, initramfs, cgroupfs, mount namespaces
│   ├── block/              # Block layer + virtio-blk driver (PCI/MMIO), BIO queue
│   ├── virtio/             # Shared VirtIO transport (virtqueues)
│   ├── net/                # TCP/IP stack: virtio-net, ARP, IPv4, ICMP, UDP, TCP, conntrack, firewall, sockets
│   ├── iommu/              # Intel VT-d: DMAR parse, domains, fault handling, interrupt remapping
│   ├── cpu_local/          # Per-CPU data (CpuLocal<T>), LAPIC-ID ↔ CPU-index mapping
│   ├── tlb_ops/            # PCID / INVPCID TLB invalidation primitives
│   ├── livepatch/          # Signed live kernel patching (kpatch-style)
│   ├── trace/              # Static tracepoints, per-CPU counters, hung-task watchdog
│   ├── klog/               # Profile-aware kernel logging (klog!/klog_force!/kprintln!)
│   ├── drivers/            # VGA / serial (UART 16550) / PS-2 keyboard
│   ├── src/                # Kernel entry (main.rs), runtime tests, Ring-3 boot diagnostics
│   └── kernel.ld           # Linker script
├── userspace/              # Ring-3 programs: shell, syscall_test, hello_musl.c (static-musl), stress runners, syzkaller fuzzer
│   ├── nilix-syz-fuzzer/   # Host-driven coverage-guided fuzzer (Rust): mutation engine, corpus manager, QEMU executor
│   ├── nilix_syz_executor.c # Guest executor: deserialize programs, execute syscalls, collect KCOV coverage
│   ├── stress_runner.c     # Basic stress test: 5 phases (memory, CPU, process, file, combined)
│   └── stress_runner_advanced.c # Security stress test: permission boundaries, concurrency, resource exhaustion
├── fuzz/                   # Cargo-fuzz targets: parsers (10 targets) + QEMU syscall execution (3 targets: buddy, page tables, syscalls)
├── docs/fuzzing/           # Fuzzing documentation: Phase 7 implementation, quickstart, syscall grammar (.syz)
├── scripts/                # CI gate scripts: boot/musl/smp/iommu checks, stress tests, performance gates
├── tools/                  # Development tools: coverage analyzers, crash triage, corpus management
├── docs/                   # roadmap.md, review/ (QA reports), fuzzing/, testing/ (test suite documentation)
├── .github/workflows/      # GitHub Actions: ci.yml (build/test/lint), fuzz.yml (continuous fuzzing), monthly-stress-test.yml
├── .githooks/pre-push      # Local-first fmt + clippy gate (optional SSH offload)
└── Makefile                # Build / run / lint / gate targets
```

---

## 3. Core Components

### 3.1 Boot & Memory

- **UEFI boot** — the bootloader loads a static-PIE `kernel.elf`, applies `R_X86_64_RELATIVE`
  relocations (with an RDRAND-derived KASLR slide), sets up 4-level paging, identity-maps the
  low region for hardware access, and maps the high-half kernel at `0xFFFFFFFF80000000`.
- **Buddy allocator** — reservation-aware physical page allocation: heap/kernel/framebuffer/UEFI
  regions are reserved per-page so they can never collide with the allocator (fail-closed on
  overflow).
- **COW fork** — page-table deep-copy with shared, ref-counted physical frames; fork-time cgroup
  memory charging.
- **Page cache** — global hashed LRU with per-inode indexing, page-state tracking, dirty
  writeback, and reclaim under memory pressure.
- **Guard pages** — unmapped guard pages protect the kernel stack and the double-fault IST stack;
  user stacks carry a permanently-unmapped guard page.
- **OOM killer** — watermark-triggered cache reclaim, per-process scoring, audited emergency kill.

### 3.2 Process, Threads & Scheduler

- **PCB** — full per-task state: pid/tgid, priority, CPU affinity, cgroup membership, TLS
  (FS/GS base), seccomp/pledge state, namespace chains, per-task resource limits.
- **fork / exec / clone** — independent address spaces (or shared `MmState` under `CLONE_VM`);
  threads via `CLONE_THREAD` with TLS, `set_tid_address`, and a `robust_list` for futex cleanup.
- **Scheduler** — a per-CPU Multi-Level Feedback Queue with starvation detection and priority
  boosting, preemption on timer ticks, work-stealing, periodic load balancing, and CPU
  affinity / cpuset isolation.
- **Wait / exit** — zombie reaping via `wait4`/`waitpid`, `SIGCHLD` to the parent, orphan
  reparenting; cross-CPU deferred termination; a hung-task watchdog heartbeat.

### 3.3 IPC & Signals

- **Pipes** — FIFO buffers with reader/writer ref-counting and signal-interruptible blocking I/O.
- **Message queues** — capability-gated endpoints, partitioned per IPC namespace.
- **Futex** — `FUTEX_WAIT`/`FUTEX_WAKE`, plus `FUTEX_LOCK_PI`/`FUTEX_UNLOCK_PI` with priority
  inheritance and per-thread-group bucket budgets.
- **Signals** — 64 POSIX signals, per-task blocked masks and dispositions; synchronous handler
  delivery on the syscall-return path with a SROP-defended `rt_sigframe` builder and
  `rt_sigreturn`; EINTR wake of blocked syscalls.

### 3.4 Security Framework

- **Capabilities** — non-forgeable `CapId` (generation + index), `CapRights` bitflags, a per-process
  `CapTable`, and capability syscalls (allocate / revoke / delegate) gated by LSM + audited.
  Regular files allocate capabilities at open time with rights derived from open flags; pipes
  carry pre-allocated capabilities. *(Full fd-table → capability integration ongoing under Phase U.)*
- **LSM** — a pluggable `LsmPolicy` trait with 40+ hook points across syscalls, task lifecycle,
  VFS, memory, IPC, signals, network, and livepatch; the Secure profile enforces the
  `SecureBaselinePolicy` (W^X on mmap/mprotect, kpatch default-deny), while Balanced/Performance
  remain permissive. Denials are fail-closed and audited.
- **Seccomp / Pledge** — a BPF-like filter VM with 18 pledge promises and a fast-allow bitmap;
  a boot-time partition self-test guards against seccomp/dispatch divergence.
- **Audit** — SHA-256 (FIPS 180-4) hash-chained events with an optional HMAC-SHA256 mode,
  bounded ring buffer with overflow tracking, and a cursor-based non-draining export interface.
- **Compliance profiles** — Secure / Balanced / Performance, each tuning W^X strictness,
  Spectre mitigations, kptr guard, audit capacity, and log verbosity.

### 3.5 Memory-Safety Hardening

W^X enforcement (no page is both writable and executable), NX on data pages, SMEP/SMAP/UMIP,
KASLR (kernel heap/stack/mmap + text-relocation infrastructure), KPTI dual page-table isolation,
Spectre/Meltdown mitigations (IBRS/IBPB/STIBP/SSBD, RSB stuffing, SWAPGS+LFENCE), a ChaCha20
CSPRNG seeded from RDRAND/RDSEED, and kernel-pointer obfuscation (kptr guard).

### 3.6 VFS & Storage

VFS inode abstraction over ramfs, ext2 (read/write, page-cache-backed), procfs
(`/proc/self`, `/proc/[pid]/…`, `/proc/meminfo`), devfs (`/dev/null|zero|console`),
initramfs (CPIO `newc`), and cgroupfs. POSIX DAC (owner/group/other, umask, sticky bit),
`openat2` `RESOLVE_*` flags (`NO_SYMLINKS`/`BENEATH`/`IN_ROOT`/`NO_XDEV`/`NO_MAGICLINKS`),
symlink-loop detection, and per-namespace copy-on-write mount tables. Storage is backed by a
virtio-blk driver (PCI + MMIO) and a BIO request layer.

### 3.7 Network

A software TCP/IP stack: virtio-net driver, DMA-friendly packet buffers, Ethernet/ARP
(anti-spoofing, rate-limited), IPv4 (checksums, source-route rejection, fragment reassembly
with overlap detection), ICMP, and UDP. TCP implements the full state machine and 3-way
handshake, RFC 6298 RTT/RTO with Karn's algorithm, NewReno congestion control, window scaling,
SYN cookies, listen/accept, and graceful close. Above the protocols sit connection tracking,
a stateful priority-ordered firewall (ACCEPT/DROP/REJECT, default-DROP), and a
capability-based socket API with per-hook LSM mediation. Network namespace TX ownership gates
prevent isolated namespaces from egressing on devices they do not own.

Receive runs as a **bounded process-context ingress loop** rather than in interrupt context: the
scheduler's deferred-work drain polls the registered devices under a self-throttled ~10 ms
window with a fixed frame budget and a fair per-device quantum, so no single device can starve
the others. Buffers come from a statically pre-allocated DMA pool (32 × 4 KiB) that sits
deliberately outside heap admission — provenance is verified at the pool on free, and each
device is capped on the number of buffers it may own. With completion servicing and replenish
wired through the virtio-net driver, the kernel ingests **real external frames on `eth0`**: the
`netns_rx_eth0_slirp` gate drives an ARP probe out to the QEMU SLIRP gateway and asserts the
reply is received and learned. On the transmit side, an on-link cache miss now emits a
rate-limited **ARP request probe** (per-namespace ring and token bucket, with a global bucket
drawn only at emission so a device-less namespace cannot pin the shared budget).

### 3.8 SMP, IOMMU & Concurrency

LAPIC/IOAPIC init, AP bring-up via INIT-SIPI-SIPI (up to 64 CPUs), five IPI types, IPI-driven
TLB shootdown with per-CPU mailboxes, PCID/INVPCID, per-CPU data (`CpuLocal<T>`), RCU
grace-period reclamation, and a documented 9-level lock ordering with a lockdep checker. The
Intel VT-d driver provides DMAR parsing, domain management, DMA second-level page tables, fault
handling, and interrupt remapping (DMAR table discovery wiring is the remaining boot step).

### 3.9 Containers

Five namespaces — PID (cascade init-kill), mount (CoW tables), IPC (System V), network
(per-NS devices/sockets), and user (UID/GID mapping for unprivileged containers) — driven by
`clone(2)`/`unshare(2)`/`setns(2)`. Cgroups v2 provide CPU (`cpu.weight`/`cpu.max`), memory
(`memory.max`/`memory.high` + OOM events), PIDs, I/O (token-bucket `io.max`), FD, and port
controllers, exposed via syscalls and a `/sys/fs/cgroup` cgroupfs mount, with subtree delegation.

The network namespace owns a real **per-namespace dataplane**, not just a device list. Each
namespace (root included) holds its own ARP cache, so the same IP may legitimately map to
different MACs in different namespaces and neither can poison the other; the net crate reaches
that state only through a `NetNsDeviceHooks` upcall that hands back the cache itself, never a
namespace handle, and fails closed when the namespace is unknown or already destroyed. Each
namespace also carries its own validated address/gateway/subnet configuration and derives its
own routing decisions (local / on-link / gateway / unroutable, surfaced to user space as
`ENETUNREACH`). Children are born unconfigured and must be configured explicitly; root delegates
to the global config rather than keeping a second copy that could drift. All of this config
state is charged both to a global `NetnsConfig` heap class and to a **16 KiB per-namespace byte
budget**, from which root is deliberately *not* exempt, so a leak in one namespace's dataplane
cannot consume another's.

### 3.10 User Mode & Linux ABI (Phase U / M0)

Ring-3 execution via SYSCALL/SYSRET, **100+ Linux x86-64 syscalls** (113 dispatched), a full
SysV AMD64 `auxv` builder on the initial stack, ELF loading with DoS/corruption guards, `#!`
shebang resolution, path-based `execve` vs. native image-spawn disambiguation, and signal
delivery. The headline milestone: **a genuine statically-linked musl libc binary runs
end-to-end** — crt startup consuming the auxv, musl stdio `printf`→`writev`, and a clean
`exit(0)` — proven by the `musl-check` conformance gate.

> M0 is foundational and intentionally divergent from full Linux: resource limits are advisory
> (not yet enforced on `brk`/`mmap`), there is no dynamic linking (`ld.so`/vDSO) or user-space
> ASLR yet, and `readlink`/`symlink`/`chown` and a few other syscalls are deferred. These are
> tracked under Phase U in `docs/next-phase-plan.md`.

---

## 4. Build and Run

### Prerequisites

- Rust **nightly** with `rust-src` and `llvm-tools-preview` (pinned in `rust-toolchain.toml`;
  targets `x86_64-unknown-none` and `x86_64-unknown-uefi`)
- QEMU (`qemu-system-x86_64`) with OVMF firmware for UEFI boot
- GNU Make
- `musl-tools` (`musl-gcc`) — only for the musl conformance gate

### Common commands

```bash
make build           # Build bootloader + kernel into the EFI System Partition (esp/)
make run             # Run in QEMU (graphical VGA window)
make run-serial      # Run with serial console on the terminal
make run-shell       # Build + run the interactive shell (serial)
make run-blk         # Attach a 64 MB ext2 virtio-blk disk
make run-smp         # Multi-core boot (SMP_CPUS=N, default 2)
make debug           # Start QEMU paused for GDB on :1234
make clean           # Remove build artifacts
```

QEMU is launched with a CPU model that exposes `+smep,+smap,+umip,+rdrand`, so SMEP/SMAP/UMIP
and hardware RNG are exercised by default. Run `make help` for the full target list.

---

## 5. Continuous Integration & Quality Gates

Nilix enforces correctness, style, and boot health automatically — the same gates run in CI, and
contributors can run them locally (the maintainer's Windows mirror offloads to a Linux build host).

### 5.1 GitHub Actions (`.github/workflows/ci.yml`)

Runs on every push and pull request to `main`, with in-progress runs on the same ref cancelled.
Four parallel jobs:

| Job | Runs | Asserts |
|-----|------|---------|
| **rustfmt + clippy** | `make fmt-check` · `make clippy` | All crates rustfmt-clean; clippy reports no errors |
| **build** | `make build` | Bootloader + kernel compile (PIE / build-std / hardened flags) |
| **custom lints** | `make lint` | Four structural source lints plus VFS fallibility and ABI-layout gates pass (below) |
| **boot + test + musl** | `make boot-check` · `make test` · `make musl-check` | Kernel boots clean to user space, runtime suite scores clean, and a static-musl binary runs end-to-end |

### 5.2 Boot & conformance gates

These QEMU gates have **real exit codes** read from the serial log and the QEMU `-d int`
interrupt log — never from QEMU's own exit code (`-no-reboot -no-shutdown` makes a timeout the
normal end of a healthy run).

- **`make boot-check`** (`scripts/boot_check.sh`) — boots under QEMU and fails unless the kernel
  reaches user space / its idle loop **and** zero NX-violation instruction-fetch page faults
  occurred (the `v=0e e=0011` signature from the D1-BOOT-NX-KASLR-LAYOUT class of bugs).
- **`make test`** (`scripts/kernel_test.sh`, P1-C VT-2 / Gate #4) — boots the default
  `make build` image and asserts a parseable in-kernel
  `=== Test Summary: N passed, M deferred (...), K failed ===` with `K == 0`, plus zero
  `KERNEL PANIC` and zero NX-violation #PF. Exit polarity: **0 PASS / 1 FAILED / 2 NOT-RUN**
  (missing summary or missing OVMF/ESP is NOT-RUN, not a silent green). Deferred/warning
  counts are informational only.
- **`make musl-check`** (`scripts/musl_check.sh`) — builds with `--features musl_test` so the
  embedded `hello_musl.elf` is the Ring-3 init program, then asserts **all** of: the
  libc-attributable `printf` marker (`42 * 2 = 84`), the `musl libc test passed!` success line,
  a clean `exit code 0`, zero NX-violation #PF, and no kernel panic. The gate is bidirectional
  and fail-closed — the default (native-Rust) kernel, which also exits 0, never prints the libc
  marker and therefore fails the gate.

### 5.3 Custom source lints (`make lint`)

Six repository-specific gates catch invariants the compiler cannot prove:

| Gate | Enforces |
|------|----------|
| `lint-release` | No ungated `println!` in kernel code (only `drivers/`, `klog/`); use `kprintln!` / `klog!` / `klog_force!` |
| `lint-smap` | Only `usercopy.rs` may instantiate `UserAccessGuard` (SMAP-window minimization) |
| `lint-fetch-add` | No bare `fetch_add(1)` for IDs/refcounts in core/VFS paths — use `fetch_update` + `checked_add` (or an explicit `// lint-fetch-add: allow`) |
| `lint-repr-c-copy` | Every `from_raw_parts` / `copy_nonoverlapping` / `transmute` on a `#[repr(C)]` struct at the user boundary must carry a padding-safety annotation |
| `lint-fallible` | Recoverable VFS paths, especially `readdir`, must use fallible name/allocation staging; its fixture self-test must catch 22 candidates with 0 false positives |
| `abi-check` | Kernel Rust `#[repr(C)]` layouts must match the cited Linux x86-64 UAPI oracle (11 structs, 100 values, 17 tripwires, with a C compiler cross-check) |

### 5.4 Extended test suite (NEW)

Nilix has sustained stability, performance, and extended SMP tests beyond the core CI gates:

- **QEMU stability soaks** (`scripts/stress_test.sh`) — six repeated boot/runtime profiles covering
  constrained memory, single/multi-vCPU, SMP, attached storage, and combined configurations over
  60–300 seconds. These are stability profiles, not dedicated in-guest pressure workloads. Invoke
  them via `make stress-test` or `make stress-test-extended`.
- **Extended SMP** (`scripts/extended_smp_test.sh`) — validates 8-core and 16-core boot, IPI
  broadcast, and multi-CPU lock contention. Run via `make test-smp-extended`.
- **Performance regression gate** (`scripts/perf_regression_test.sh`) — framework for detecting
  syscall latency, context-switch, and page-fault regressions. Invoked via `make test-perf`
  (benchmarks pending).
- **Security tests** (`kernel/security/tests.rs`) — nine runtime tests validating W^X, RNG, kptr
  guard, Spectre V1/V2, SMAP, and SMEP mitigations. Integrated into the standard `make test` suite.
- **Melting tests** (`scripts/melting_test.sh`) — sustained maximum-load scenarios (10+ minutes)
  for bare-metal thermal validation. Framework in place; requires real hardware.

Full documentation lives in `docs/testing/`.

### 5.5 Fuzzing infrastructure (NEW)

Nilix has two complementary fuzzing approaches: (1) **Syzkaller-style host-driven fuzzing** with a
standalone mutation engine and QEMU executor, and (2) **Cargo-fuzz integration** with both mock-based
parser targets and QEMU-based syscall execution.

#### Syzkaller-Style Fuzzing (Phase 7)

Host-driven coverage-guided fuzzing with mutation, corpus management, and real kernel execution:

- **Host fuzzer** (`userspace/nilix-syz-fuzzer/`) — Rust-based mutation engine with 5 strategies
  (insert, delete, modify, duplicate, reorder), energy-based corpus scheduling, and crash classification.
- **Guest executor** (`userspace/nilix_syz_executor.c`) — C binary that deserializes syscall programs,
  executes them in Ring 3, and collects KCOV coverage via the kernel's edge-recording infrastructure.
- **Syscall grammar** — 600+ line `.syz` format descriptions covering 40+ syscalls with type constraints,
  resource tracking (fd, pid, addr), and dependency relationships.
- **Crash detection** — Classifies kernel panic, page fault, triple fault, timeout, and hang scenarios
  with HMAC-based deduplication.
- **CI workflow** — Weekly scheduled runs in GitHub Actions with corpus caching across runs.
- **Performance** — 5-10 executions/sec, 50-200 new edges/hour (early phase).

#### Cargo-Fuzz Integration (NEW)

Integrated libFuzzer targets for both fast parser iteration and deep kernel testing:

**Mock-based targets (10 targets)** — Fast iteration on parsers without kernel execution:
- VFS path normalization, network packet parsing, ELF loader, signal handling, ext2 structures,
  TCP segment processing, capability operations, syscall argument validation, firewall rules,
  procfs entries.
- **Performance**: 50,000+ exec/sec, ideal for rapid development feedback.

**QEMU-based targets (3 targets, NEW)** — Real kernel execution with KCOV coverage feedback:
- `fuzz_buddy_allocator` — Memory allocator operations (alloc, free, split, coalesce).
- `fuzz_page_table_ops` — Page table manipulation (map, unmap, COW, protection changes).
- `fuzz_syscall_qemu` — Syscall execution against KCOV-enabled kernel with safe allowlist
  (19 syscalls: getpid, stat, brk, mmap, munmap, etc.).

**Architecture**:
```
┌──────────────────┐
│   libfuzzer      │  Generates inputs, tracks coverage
└────────┬─────────┘
         │
         v
┌──────────────────┐
│ fuzz target      │  Parses input → SyscallProgram
└────────┬─────────┘
         │
         v
┌──────────────────┐
│  syz_bridge.rs   │  Shells out to nilix-syz-fuzzer --single-shot
└────────┬─────────┘
         │
         v
┌──────────────────┐
│ nilix-syz-fuzzer │  QEMU orchestration, coverage extraction
└────────┬─────────┘
         │
         v
┌──────────────────┐
│   QEMU + kernel  │  Executes syscalls, records KCOV edges
└──────────────────┘
```

**Key features**:
- Lazy QEMU executor initialization (spawned on first input)
- Safe syscall allowlist (non-destructive operations only)
- Coverage feedback loop (KCOV bitmap → libfuzzer guidance)
- Crash detection with serial log extraction
- Feature-gated compilation (`--features qemu-executor`)
- Configurable timeout (default 10s per program)

**Makefile targets**:
```bash
make build-fuzz-qemu-deps    # Build KCOV kernel + fuzzer binary
make fuzz-qemu-smoke          # 5-minute smoke test
make fuzz-qemu-campaign       # 1-hour campaign
make fuzz-qemu-overnight      # 8-hour overnight run
make fuzz-qemu-parallel       # 4-worker parallel fuzzing
make fuzz-list                # List all 13 cargo-fuzz targets
make fuzz-clean               # Clean artifacts/corpus
```

**Performance comparison**:

| Fuzzer Type | Exec/sec | Coverage | Memory | Use Case |
|-------------|----------|----------|--------|----------|
| Mock-based parser | 50,000 | Logic only | 100 MB | Fast iteration |
| QEMU syscall (shell) | 5-10 | Real KCOV | 512 MB | Deep testing |
| QEMU syscall (vendored) | 50-100 | Real KCOV | 512 MB | Production (future) |
| Standalone syzkaller | 8-12 | Real KCOV | 512 MB | Long campaigns |

#### KCOV Infrastructure

- **Per-task coverage tracking** — IRQ-skipping, non-blocking edge recording with manual syscall
  tracepoints. KCOV is a host-global privileged surface: authority is **host-root-only** (the
  reserved `CapRights::KCOV` bit is retained for ABI stability but does not authorize access
  until a reviewed identity-bound issuance protocol exists).
- **Management syscalls** — `kcov_init`, `kcov_enable`, `kcov_disable`, `kcov_dump`, `kcov_reset`
  for coverage lifecycle control from Ring 3.
- **Deterministic E2E gate** — QEMU guest executor validates KCOV enable/disable/reset/dump, bitmap
  counts, program differentiation, and repeat stability.

#### Architecture

- **KCOV coverage tracking** — per-task edge coverage via IRQ-skipping, non-blocking current-task
  recording and selected manual syscall tracepoints, with five management syscalls:
  `kcov_init/enable/disable/dump/reset`.
- **Syscall descriptions** — TOML-based type-safe syscall definitions with constraints (ranges,
  flags, enums) and resource relationships (fd → file, pid → process). 20+ core syscalls described
  in `fuzz/syscall_descriptions/`.
- **Coverage-guided mutation** — genetic algorithm with 8 mutation strategies (flip order, insert,
  remove, mutate args, splice, cross over, havoc, dictionary-based). Corpus management tracks
  "interesting" inputs that expand coverage.
- **Resource-aware fuzzing** — tracks five resource types (fd, pid, addr, port, cap_id) with
  constraint validation, dependency tracking (exec clears fds, fork duplicates), and leak detection.
- **Stateful fuzzing** — protocol-aware fuzzing with state machines (FileDescriptor: CLOSED ↔ OPEN,
  MemoryRegion: UNMAPPED → MAPPED → PROTECTED, ProcessLifecycle: INIT → FORKED → EXEC → ZOMBIE),
  IPC coordinator, and input minimizer (delta debugging, 70%+ size reduction).
- **Hybrid path** — a real QEMU guest E2E executes two deterministic syscall programs and validates
  KCOV enable/disable/reset/dump, bitmap counts, program differentiation, and repeat stability. Ten
  specialized cargo-fuzz targets (VFS, ELF, signal, etc.) provide host-safe parser and model checks.

#### CI Integration

The `.github/workflows/fuzz.yml` workflow runs:

- **Push mode** — 60-second runs of the VFS path, network packet, and ELF loader targets, each of
  which calls real kernel parser code.
- **Scheduled target mode** — all 10 libFuzzer targets, daily at 2 AM UTC.
- **KCOV QEMU executor E2E** — rebuilds the static guest runner from source, boots `esp-kcov`, runs
  fixed syscall programs in Ring 3, and fails closed on missing markers, inconsistent coverage,
  panic, NX fault, early QEMU exit, or timeout.
- **Pipeline simulator smoke** — remains a separate dashboard/report plumbing check with an explicit
  zero-kernel-execution manifest; it is never treated as coverage or crash evidence.
- **Private candidate triage** — raw libFuzzer output and finding inputs stay inside the ephemeral
  runner. Candidate artifacts and Issue bodies contain only a stable keyed HMAC identifier and a
  workflow pointer; they omit payloads, stack traces, ordinary hashes, and target names. Public
  matrix job names and result manifests still identify the target that ran and its candidate count.
- **Corpus cache** — clean-run cargo-fuzz corpora are cached across runs but never published as
  artifacts; a run with any finding is not saved back to the cache.

Pushes to `main` affecting `kernel/**`, `userspace/fuzzer/**`, or `fuzz/**` run the three real-kernel
parser targets. Manual `smoke` runs both the deterministic guest E2E and the independent
zero-execution simulator; `both` adds cargo-fuzz targets. Only target runs can produce fuzz findings.
Candidate reporting requires a stable, randomly generated repository secret named
`FUZZ_FINGERPRINT_KEY` (at least 32 bytes); a finding fails closed if that private channel is not
configured.

Full documentation lives in `docs/fuzzing/` (7 phase guides, 33,000+ words, architectural deep-dive).

#### Invoking fuzzing locally

```bash
# Syzkaller-style coverage-guided fuzzing (Phase 7)
make build-kcov build-syz-executor build-syz-fuzzer  # Build all components
make test-syz                                         # 60-second smoke test
make run-syz-fuzz DURATION=3600 WORKERS=4            # Full fuzzing campaign

# Cargo-fuzz QEMU syscall fuzzing (NEW)
make build-fuzz-qemu-deps                            # Build KCOV kernel + fuzzer
make fuzz-qemu-smoke                                 # 5-minute smoke test
make fuzz-qemu-campaign                              # 1-hour campaign
make fuzz-qemu-overnight                             # 8-hour overnight run
make fuzz-qemu-parallel                              # 4-worker parallel

# Deterministic KCOV guest E2E (legacy)
make test-kcov

# Cargo-fuzz targets for parsers
cd fuzz && cargo +nightly fuzz run fuzz_elf_loader -- -max_total_time=60
cd fuzz && cargo +nightly fuzz run fuzz_buddy_allocator --features qemu-executor
cd fuzz && ./run_all_fuzz.sh
```

**Phase 7 Complete (2026-08-04)**: The host-driven syzkaller-style fuzzing infrastructure is now
fully operational. A Rust-based host fuzzer mutates programs using 5 strategies (insert, delete,
modify, duplicate, reorder), manages an energy-based corpus, and executes programs in QEMU with
timeout enforcement. A C-based guest executor deserializes programs, executes syscalls, and collects
KCOV coverage. The fuzzer detects and classifies crashes (panic, page fault, triple fault, timeout,
hang), with HMAC-based deduplication. GitHub Actions CI runs weekly fuzzing campaigns with corpus
caching across runs. Performance: 5-10 executions/sec, 50-200 new edges/hour (early phase). See
`docs/fuzzing/QUICKSTART.md` for usage and `docs/fuzzing/phase7-implementation.md` for architecture.

**Cargo-Fuzz QEMU Integration (2026-08-05)**: Extended cargo-fuzz with QEMU-based syscall execution
targets. The `fuzz_syscall_qemu` target uses a bridge module (`syz_bridge.rs`) to shell out to the
standalone fuzzer binary, enabling libFuzzer's mutation strategies with real kernel coverage feedback.
Three new targets cover buddy allocator, page table operations, and syscall execution. Mock-based
parser fuzzing (50K exec/sec) and QEMU-based deep testing (5-10 exec/sec) provide complementary
coverage. See `docs/FUZZING_SUMMARY.md` for architecture details.

The cargo-fuzz path and deterministic KCOV regression continue to run in CI. Private candidate
reporting with HMAC identifiers remains operational for parser fuzzing.

### 5.6 Style gates & pre-push hook

- **`make fmt-check`** — `cargo fmt --all --check` across the workspace and userspace.
  `rustfmt.toml` pins `newline_style = "Windows"` because the repo stores CRLF blobs.
- **`make clippy`** — clippy across all three build units (bootloader, kernel, userspace) in
  isolated target dirs; deny-by-default correctness errors fail the build.
- **`.githooks/pre-push`** — opt-in (`make hooks`). The hook is **local-first**: it runs
  `make fmt-check` + `make clippy` locally when a Rust toolchain is present, and can offload
  over SSH for a toolchain-less mirror (`git config zeroos.remote`/`zeroos.remoteDir`). Bypass
  a single push with `SKIP_PREPUSH=1 git push`. A pre-commit-framework equivalent
  (`.pre-commit-config.yaml`) is also provided — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 6. Security Audit Status

Nilix is developed under a continuous adversarial-review process: each round audits the
kernel, files findings by severity, fixes them, and converges via bidirectional peer review
(Claude Code + the Codex MCP) before the round closes.

| Metric | Value |
|--------|-------|
| Audit rounds | **187** (R187 KCOV remediation completed 2026-08-08; ReviewFix closure 2026-08-08) |
| Cumulative findings | ~1,340 (historical IDs include merged/refuted findings) |
| Findings fixed/resolved | ~1,184 |
| Latest round | R187 — KCOV authority/access/topology; 7 fixes, 7 PASS (review-fix 8/8 repaired) |
| Latest review-fix pass | RF187 — 7/7 fixes PASS, 8/8 RF defects repaired, 0 escalated; remote ladder green |
| Current actionable debt | **1 HIGH** (`R186-4`, carried) |
| 1.0-Preview release gate | **BLOCKED** — carried `R186-4` HIGH remains; zero-HIGH streak 0/3 |

R186 found 18 issues in total: 17 actionable findings and one INFO. Sixteen actionables
are fully fixed; `R186-18` is fixed and review-verified through shared credential
generation, writer-fair authorization, and stable subject ownership across side effects
and publication. `R186-4` remains the sole HIGH blocker. The round therefore reset the
zero-HIGH streak to 0/3 and reopened the aggregate heap-admission design parent. See the
[R186 report](docs/review/audits/qa-2026-07-28.md) and the
[current plan](docs/review/nextplan/next-phase-plan-2026-07-23-v2.md).

The authoritative **RF186 ReviewFix closure** reviewed all 16 landed fixes: 2 PASS,
12 PARTIAL, and 2 FAIL. All 24 defects (`RF186-1`…`RF186-24`) are repaired with
0 escalations. Final execution passes net 110/110 under default parallelism, conntrack
stress 50/50, and the complete fmt/clippy/build/lint/test/boot/musl ladder.
`R186-4` was never fixed and remains outside the Stage-3 verdict scope, so the gate
and streak remain unchanged.

R187 (2026-08-08) audited the KCOV observability surface and recorded 7 findings —
authority, IRQ/NMI/soft-progress admission, exact dump, occupied-slot collision semantics,
fuzzer timing/control, documentation, and static CPU/topology safety. All 7 are fixed and the
ReviewFix closure verified 7/7 PASS. Eight review-fix defects (RF187-1…RF187-8) were repaired
with 0 escalations: KCOV authority is now host-root-only (the reserved `CapRights::KCOV` bit
cannot elevate a caller), an allocation-free soft-progress guard spans the public
deferred-callback drain, the CPU online topology is unified under one authoritative `cpu_local`
mask, and the fuzzer ABI reports occupied bitmap slots with bounded KCOV control retries. R187
added no new open HIGH; the gate remains BLOCKED on the carried `R186-4` and the streak stays
0/3. See the [R187 report](docs/review/audits/qa-2026-08-05.md) and the
[RF187 closure](docs/review/reviewfix/reviewfix-2026-08-08.md).

CI now runs `make test-hosted-subcrates`: **169 default-parallel hosted tests** across
audit, MM, block, seccomp, net, and the focused RF186 capability lifecycle pair, plus
compile checks for IPC, kernel_core, and kernel test code. Exact test-count oracles prevent
zero-test/filter drift from passing silently. Full capability and privileged kernel suites
remain QEMU-only because hosted execution cannot safely run interrupt/MMIO paths. See the
[authoritative RF186 report](docs/review/reviewfix/reviewfix-2026-07-30.md).

---

## 7. Roadmap

**Completed**

- **Phase A** — Security foundation: usercopy/SMAP API, Spectre/Meltdown, audit upgrade, SMP-ready interfaces
- **Phase B** — Capability + LSM + seccomp framework, integrated into syscall/VFS/process paths
- **Phase C** — Storage: virtio-blk, page cache, ext2, procfs/devfs/initramfs, OOM killer, `openat2`
- **Phase D** — Network: full TCP/IP stack with conntrack and a stateful firewall
- **Phase E** — SMP & concurrency: AP boot, IPI TLB shootdown, per-CPU scheduling, RCU, lockdep, futex PI
- **Phase F** — Resource governance: five namespaces, cgroups v2 controllers, IOMMU/VT-d driver
- **Phase G** — Production-readiness hardening: KASLR (H.2), KPTI (H.3), tracing & watchdog, livepatch

**In progress**

- **Phase U — User Mode & ABI** (*Compat-ZeroABI*): a capability-first native core plus a
  de-privileged Linux-compatible personality. Milestone **M0** builds the user-mode foundation
  (auxv, signal delivery, missing syscalls, exec disambiguation, user-stack guards) on the
  existing Linux cABI, proven by the static-musl conformance gate, before the native/personality
  fork is committed. **U.S2 SLICE-3B complete (2026-07-23):** FileOps trait capability 
  infrastructure with cap_id/set_cap_id methods, interior mutability via spin::once::Once, 
  and regular file capability allocation at open time.
- **D3 network-namespace dataplane** (Phase I.3) — per-namespace ARP caches, addressing, routing
  and byte budgets are landed, along with a bounded RX ingress loop and live `eth0` receive.
  The pending-frame queue is also landed: on-link misses park and later retransmit frames, and the
  metered gateway-fallback delivery path is retired. Remaining work is the firewall-admin syscall
  surface, `veth` pairs with a real routing table, and capability-safe device-move arming.
- IOMMU DMAR table-discovery wiring; full demand-grown user stacks.

**Future**

- Dynamic linking (`ld.so`/vDSO), glibc + OCI compatibility, user-space ASLR
- Per-tenant network resource budgets, NUMA-aware scheduling, KVM/hypervisor support

See [docs/roadmap.md](docs/roadmap.md) and
[docs/roadmap-enterprise.md](docs/roadmap-enterprise.md) for the complete roadmap.

---

## 8. Contributing

Community and maintenance entry points:

- **[CONTRIBUTING.md](CONTRIBUTING.md)** — toolchain, kernel invariants, risk-selected tests,
  RFCs, commits, pull requests, and review.
- **[SUPPORT.md](SUPPORT.md)** — where and how to file bugs, proposals, performance reports,
  documentation issues, and questions.
- **[SECURITY.md](SECURITY.md)** — private vulnerability reporting, threat scope, evidence,
  and coordinated disclosure.
- **[GOVERNANCE.md](GOVERNANCE.md)** — roles, decisions, review/merge policy, issue lifecycle,
  and release gates.
- **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** — expected behavior in project spaces.

In short:

1. Contributors with a local Rust toolchain build, lint, and test locally — exactly what CI
   does. (The maintainer's Windows mirror has no toolchain and offloads to a Linux build host.)
2. Run the core gates plus the checks selected by risk: ABI, SMP/concurrency, storage,
   fuzzing, performance, and hardware changes each require different evidence.
3. Open an RFC before architecture, trust-boundary, ABI, dependency, or cross-subsystem
   implementation. Bug and security fixes should include regression tests.
4. Git commits are manual — nothing is auto-committed or auto-pushed.

---

## 9. License

---

## 10. References

- [OSDev Wiki](https://wiki.osdev.org)
- [Writing an OS in Rust](https://os.phil-opp.com)
- [Linux Kernel Source](https://kernel.org)
- [seL4 Microkernel](https://sel4.systems)
