# Nilix (Zero-OS) — Unified Development & Enterprise Roadmap

**Version:** 4.5 — R186-4 VMA/MM admission fix complete (2026-08-03; was 4.4 RF186 convergence)
**Snapshot:** 2026-08-03 · R186 Stage-2 fix completion: all 17 actionable findings fixed, zero-HIGH
streak advances to 1/3, gate blocked on streak only; complete AdmittedMap migration for mmap_regions
and pt_charged_frames with fork capacity-charging via from_sorted_vec_charged
**Design principle:** Security and safety > operational efficiency > speed; defense-in-depth over minimal diffs
**Supersedes:** v4.4 (2026-07-30 authoritative RF186 verdict/repair)

Nilix — **N**ilix **I**s **L**inux **I**ndependent e**X**istence — is a security-first hybrid kernel written
in Rust (`no_std`) for x86_64: Linux-*compatible* (byte-exact syscall ABI; a real statically-linked musl
libc binary runs unmodified end-to-end) yet Linux-*independent* (a from-scratch kernel, not a fork). The
GitHub repository is `Zero-kernel/Nilix`; local directories, crate names, and in-code identifiers
deliberately retain the historical `Zero-os` naming — do not "fix" them.

---

## 0. How to Read This Document

**Authority order** — when sources conflict, the earlier one wins:

1. Code and build configuration (what exists and is actually wired);
2. CI gates and in-kernel runtime tests (what is observed to work);
3. The live plan in `docs/review/nextplan/` (current priorities — plan v15.52, 2026-07-30);
4. Audit / review-fix reports in `docs/review/` (security and open-risk status);
5. `README.md` (public summary — authoritative only where code/tests/plan do not contradict it; where they
   do, this document records the reconciliation. As of 2026-07-30 the README §6 gate status agrees with
   this document: BLOCKED on `R186-4` with the zero-HIGH streak at 0/3);
6. This document's narrative sections.

**Maturity legend** used throughout:

| Label | Meaning |
|---|---|
| ✅ Validated | Wired into the active path and exercised by a named CI gate or runtime test |
| 🟢 Implemented | Wired into the active path; validation partial or indirect |
| 🟡 Partial | Present but incomplete, feature-gated, or inert pending another component |
| 🔵 Planned | Not built yet; has a concrete milestone |
| ⚪ Directional | Long-term intent; no committed milestone |

Code presence alone is never counted as "implemented" — each claim below was traced
capability → interface → call site/wiring → default configuration, against the snapshot above, by a
full-source survey (all 26 kernel crates, bootloader, userspace, fuzzing, scripts, CI) on 2026-07-23.

**Counting method:** file and line counts are raw `wc -l` over `*.rs` (comments and blanks included),
`target/` excluded, at the snapshot commit. They are inventory metadata, not a maturity measure. Audit
statistics are assembled from the per-round reports in `docs/review/`; "findings filed" includes findings
that later verification refuted as false positives (see §11).

---

## 1. Executive Status Snapshot

**Milestone:** approaching **1.0-Preview**. Phases A–G are complete; **Phase U** (user-mode Linux ABI,
strategy *Compat-ZeroABI*) is in progress with milestone M0 done and native-capability slice U.S2-3B landed.

**Release gate:** the 1.0-Preview gate is **BLOCKED on the zero-HIGH streak only**
(2026-08-03). R186 filed 18 issues and reset the streak to 0/3. Current state:
**0 open CRITICAL / 0 open HIGH / 0 open actionable MEDIUM or LOW**;
all 17 actionable findings are fixed. The former gate-blocking `R186-4` (VMA/MM aggregate
admission) is now complete via full `AdmittedMap` migration with fork capacity-charging. The
authoritative RF186 ReviewFix reviewed all 16 initial fixes (2 PASS / 12 PARTIAL / 2 FAIL)
and repaired `RF186-1`…`RF186-24` with 0 escalations; the source/test judges and final
RF186-20..24 security reviewer returned SAFE. The zero-HIGH streak advances to **1/3**.
`D1-RES-HEAP-ADMISSION-REOPENED` is now RESOLVED. Remaining gate work: rebuild the
zero-HIGH streak to 3/3 via two more clean audit rounds.

**Feature work since the gate snapshot:** the **D3 PENDING-FRAME v2** architecture landed 2026-07-27 —
park-on-miss + retransmit-on-learn fully retires gateway-fallback delivery (the `neighbor_fallbacks`
counter and fallback logic are deleted). On-link ARP misses now park data frames in a per-cache 8-slot
FIFO (3-second TTL, oldest-evicted on full, EthAddr::ZERO placeholder patched under lock at pop) and
probe for the neighbor. Learned neighbors trigger `drain_parked_ready`, which pops ready frames,
patches destination MACs, and retransmits via the prepared path (fresh ownership gate + egress firewall
+ deferred UDP conntrack at queue-accept). Ownership gate moved BEFORE park AND probe admission
(ownership-denied namespaces draw no ring claim, no bucket token, no queue slot). Counter conservation
holds in quiescence: `parked_total == occupancy + retransmitted + expired + evicted + flushed +
retx_failures`. This is feature work on a D3-backlog item, not a gate item — it does not affect the
streak. The **D3 NETNS-DATAPLANE** arc (per-namespace ARP caches, byte sub-budget, RX-wiring, addressing,
routing, RX ingress loop, **eth0 RX live**, ARP request-TX probes) landed 2026-07-25 in eight legs.

| Dimension | State (2026-08-03) |
|---|---|
| Audit history | **186 rounds** (R1 2025-12-09 → R186 2026-07-28; R186-4 fix complete 2026-08-03); ~1,333 findings filed, ~1,177 fixed (§11) |
| Open security debt | 0 CRITICAL, **0 HIGH**, 0 actionable MEDIUM/LOW; design queue has D3 backlog (NETNS-DATAPLANE-CONFIG, R37-1 TSYNC, D2-ARC legs) but no gate-blocking items |
| Kernel size | 26 kernel build units (25 library crates + 1 entry binary), 146 `.rs` files, 205,745 lines (`kernel/`, measured 2026-07-29); + bootloader 1,171, userspace ~9.7k, top-level fuzz ~1.9k |
| Syscall surface | **122 distinct syscall numbers dispatched** (~126 handler arms — the spread is duplicated unreachable KCOV arms + helper handlers); custom ranges for cgroup/audit/kpatch/kcov/native. Note: 518 `move_net_device` is dispatched but hard-gated `ENOSYS` pending the per-ns capability model |
| Platform | x86_64 only, UEFI boot, QEMU-validated (OVMF); SMP up to 64 CPUs (xAPIC); bare-metal untested at scale |
| Headline proof | Static-musl libc binary runs end-to-end in Ring 3 (`make musl-check`, bidirectional fail-closed gate) |
| Last completed remote baseline | fmt-check OK · clippy OK · lint OK · build OK · runtime tests **34** passed / 39 deferred / 0 failed · 0 panic · 0 NX · boot-check OK · musl-check OK — measured after R186-4 fix on 2026-08-03 |
| Final R186 ReviewFix verification | Capability regressions **2/2**; conntrack pair plus **50/50** stress; net default-parallel **110/110**; IPC, kernel_core, and kernel hosted compile checks; eight-file local/remote SHA-256 parity; complete independent remote ladder **PASS** |
| Host unit tests | CI-gated `make test-hosted-subcrates`: **169 default-parallel tests** across audit/MM/block/seccomp/net plus focused RF186 capability lifecycle and R186-4 VMA admission tests, with exact-count oracles; IPC/kernel_core/kernel test code compile-checked; privileged execution remains QEMU-only |

**Principal limitations** (each detailed in §5–§6): no dynamic linking / vDSO / user-space ASLR; rlimits
advisory-only; KPTI machinery present but inert (single-CR3); text KASLR verify-only (stack/mmap/heap
randomization is what's active); livepatch inert until real signing keys are provisioned; KCOV edge
recording is a no-op (management syscalls only); interrupts still routed via legacy PIC (IOAPIC driver
present, init disabled); x2APIC unsupported (hard cap at 64 CPUs); no IPv6; virtio-only device drivers.

---

## 2. Vision, Design Principles, Non-Goals

**Vision (unchanged from the enterprise roadmap):** an enterprise-grade secure server kernel offering
defense in depth (capability + LSM/MAC + DAC + audit), memory safety (Rust + hardware protections),
strong process isolation, capability-secured IPC, and compliance-ready tamper-evident logging — reached
security-first: every feature lands on an audited foundation, fail-closed by default.

**Principles** (enforced in code, not aspiration):

1. **Memory safety** — the kernel is written in Rust (`no_std`); safety rests on Rust's guarantees
   *plus* audited `unsafe` blocks at the hardware/ABI boundary (MMIO, page tables, context switch, usercopy,
   virtqueues) and hardware protections (NX/W^X/SMEP/SMAP/UMIP). "Memory-safe" here means Rust-checked with
   a reviewed, minimized unsafe surface — not zero `unsafe`.
2. **Security before features** — the cap/LSM/seccomp framework predates storage and network.
3. **Fail-closed** — deny by default: firewall default-DROP, seccomp post-init missing-evaluator → Kill,
   IOMMU gate rejects DMA while probing, audit cannot be disabled once initialized, livepatch LSM hooks
   default to EPERM, corrupted profile state decays to Secure, corrupted FIPS state decays to Failed.
3. **Minimal TCB trajectory** — hybrid architecture: hot/safe paths in-kernel behind capability/LSM gates;
   the cold/dangerous Linux personality surface is planned to move to a de-privileged server (U.S4).
4. **Audit everything** — SHA-256/HMAC hash-chained events on security decisions; ~40 emit sites.
5. **Fallible allocation** — kernel paths use reserve-before-commit heap admission (15 budget classes,
   compile-time partition proof) instead of OOM-aborting allocations.

**Non-goals (current horizon):** multi-architecture support (x86_64 only), desktop/GUI, ABI stability
promises before 1.0, certification claims (FIPS *mode* exists with real KATs, but no formal validation),
power management / hotplug, and Secure Boot chain (bootloader does not verify `kernel.elf` signatures).

---

## 3. Architecture & Trust Boundaries

### 3.1 Hybrid-kernel architecture (current vs. planned)

```
+--------------------------------------------------------------------------+
|                              USER SPACE                                  |
|  [current]  Ring-3 programs: native shell, syscall/clone/kcov tests,     |
|             static-musl binaries (hello_musl), fuzz runners              |
|  [planned]  De-privileged Linux "personality" server (U.S4): ld.so/exec  |
|             brokering, /proc, ptrace, ioctl demux, OCI orchestration     |
|  [planned]  FS/Net/Policy servers (long-term microkernel-ward migration) |
+--------------------------------------------------------------------------+
|                     SYSCALL / LSM TRUST BOUNDARY                          |
|   seccomp/pledge filter -> LSM hooks (53) -> capability check -> DAC      |
+--------------------------------------------------------------------------+
|                             KERNEL SPACE (current)                        |
|  Scheduler (per-CPU MLFQ)   MM (buddy/COW/page-cache)   IPC (pipe/MQ/    |
|  + cpuset + lockdep         + heap-admission ledger      futex-PI)       |
|  VFS (ramfs/ext2-ext3/proc/dev/cgroupfs/initramfs)  Block (virtio-blk)   |
|  Net L2-L4 (virtio-net, ARP/IPv4/ICMP/UDP/TCP + conntrack + firewall)    |
|  Security (cap, LSM, seccomp, audit, compliance, hardening, crypto)      |
|  Containers (5 namespaces, cgroups v2 x6)   IOMMU/VT-d   Livepatch       |
|  Observability (trace/counters/watchdog/profiler/kdump)   KCOV (partial) |
+--------------------------------------------------------------------------+
|                        HARDWARE TRUST BOUNDARY                            |
|  Ring 0/3, NX/W^X, SMEP/SMAP/UMIP, IOMMU DMA isolation, RDRAND/RDSEED    |
+--------------------------------------------------------------------------+
```

The **hybrid** stance is deliberate: performance- and DoS-critical layers (scheduler, VMM, IPC fast path,
block, net L2–L4, capability/LSM decisions, audit) live in-kernel; complexity-heavy or dangerous
semantics (dynamic linker policy, /proc breadth, ptrace, ioctl demux, OCI) are slated for a de-privileged
user-space server once synchronous IPC + shared memory land (U.S3 → U.S4, §9).

### 3.2 Threat model

| Attacker profile | Goal | Current mitigations | Remaining gap |
|---|---|---|---|
| Malicious tenant (container) | Escape isolation, cross-tenant access | Per-process CR3, 5 namespaces, cgroups v2 (6 controllers), per-tenant net quotas (J.2), fail-closed netns TX device gate (type-enforced token, 2026-07-24), per-NS dataplane isolation — ARP cache, addressing, routing, 16 KiB byte budget (2026-07-25) | cgroup namespace absent; per-NS firewall admin surface and `veth` still missing; `move_net_device` gated off pending the per-NS capability model |
| Remote attacker | Network exploitation | Default-DROP stateful firewall, conntrack caps, SYN cookies, challenge-ACK limit, RFC 5961/6528, fragment-reassembly bounds, rate limiters | IPv6 absent (no surface, also no parity); TLS/crypto offload out of scope |
| Compromised process | Privilege escalation | Ring 3 + SMEP/SMAP/UMIP, W^X, seccomp/pledge, LSM SecureBaseline (user W^X, root-minting block, Yama-like ptrace), stack guards, SROP-defended sigreturn | KPTI inert (single CR3) — Meltdown-class reliance is on hardware immunity; text KASLR verify-only |
| Malicious/compromised device | DMA into kernel memory | VT-d DMA isolation wired at boot (fail-closed gate, RAII unmap, bus-master-off on failure), virtqueue used-ring validation, IRTE SID verification | Secure-profile still legacy-proceeds when *no* IOMMU exists (documented residual); needs real-hardware validation |
| Insider / operator | Data exfiltration, log tampering | Hash-chained audit (cannot be disabled once init), HMAC set-once key, capability-gated export, kptr redaction, kdump encryption | Remote/persistent audit delivery is hook-only (no storage backend) |
| Supply chain | Malicious kernel/patch code | Livepatch ECDSA-P256 (KAT-gated, fail-closed), compile-error on insecure stub in release | No Secure Boot / kernel-image signing; livepatch trust keys not yet provisioned |

**Trust anchors:** hardware RNG (RDRAND/RDSEED) → ChaCha20 CSPRNG (fast-key-erasure); non-forgeable
generation-versioned capabilities; SHA-256/HMAC audit chain; UEFI firmware is *trusted but unverified*
(no Secure Boot chain yet — directional, §13).

---

## 4. Kernel Composition

The kernel is a Cargo workspace of focused crates under `kernel/<subsystem>/`; the bootloader and
user-space programs are separate build units. Line counts are `wc -l` over `*.rs` at the snapshot commit.

### 4.1 Kernel crates (146 files · 205,745 LOC)

The `kernel/` tree is **26 build units — 25 library crates plus one entry-binary crate (`src`)**. The LOC
column is raw `wc -l` over `*.rs`; the 205,745 total is *all* `.rs` under `kernel/` (the surveyed kernel
workspace, including in-tree test/mock files), and is distinct from the top-level `bootloader/`,
`userspace/`, and `fuzz/` trees counted separately in §1.

| Crate | Files | LOC | Responsibility | Maturity |
|---|---:|---:|---|---|
| `kernel_core` | 22 | 54,521 | PCB & process table, fork/exec/clone, 121-syscall dispatcher, signals, 5 namespaces, cgroups v2, RCU, SMAP usercopy, KCOV syscalls, fd→capability wiring | 🟢 Implemented |
| `net` | 17 | 37,281 | virtio-net, ARP/IPv4/ICMP/UDP/TCP, conntrack, default-DROP firewall, capability+LSM socket layer, per-tenant quotas, netns TX gate, per-NS dataplane (ARP/config/routing), bounded RX ingress loop + `BufPool`, ARP probe TX | 🟢 Implemented |
| `vfs` | 11 | 22,301 | inode/dentry, FileOps (+cap_id), ramfs, **ext2/ext3 rw with JBD2 journaling**, procfs, devfs, initramfs (CPIO), cgroupfs, CoW mount tables, DAC, openat2 RESOLVE_* | 🟢 Implemented |
| `mm` | 12 | 12,904 | reservation-aware buddy allocator, dual heap + 15-class admission ledger (compile-time partition proof), page tables, page cache (LRU/writeback), TLB shootdown (IPI+PCID), OOM killer, DMA/IOMMU gate | ✅ Validated |
| `iommu` | 6 | 9,875 | Intel VT-d: DMAR ACPI parse, root/context tables, second-level page tables (AGAW), interrupt remapping, fault handling, device isolation/detach, VM-passthrough API | 🟡 Partial (wired at boot; needs real-HW validation) |
| `arch` | 11 | 9,794 | GDT/TSS/IST, IDT (20 exceptions + IRQ/IPI), context switch, SYSCALL/SYSRET entry hardening, LAPIC/IOAPIC/HPET, SMP bring-up (INIT-SIPI-SIPI), IPIs | 🟢 Implemented |
| `ipc` | 5 | 7,299 | capability message queues (per-ns), pipes (cap-preallocated), futex (WAIT/WAKE/PI, bucket budgets), WaitQueue/KMutex/Semaphore/CondVar | 🟢 Implemented |
| `security` | 9 | 5,938 | W^X/NX validator, KASLR (partial active + text verify), KPTI machinery, Spectre suite (IBRS/IBPB/STIBP/SSBD/RSB/SWAPGS), ChaCha20 CSPRNG, kptr guard, 9 runtime tests | 🟡 Partial (KPTI inert; retpoline no codegen) |
| `sched` | 5 | 4,981 | per-CPU MLFQ (bounded selector), work stealing + load balancing, starvation boost, cpuset isolation, 9-level lockdep | ✅ Validated (one orphan file — §12) |
| `block` | 4 | 4,252 | Bio/RequestQueue/BlockDevice, virtio-blk (PCI/MMIO), RAII IOMMU lifecycle, bounds-checked BIO | 🟢 Implemented |
| `audit` | 1 | 3,266 | SHA-256/HMAC hash-chained ring, FIFO overflow policy, cursor export, 8 event classes, mandatory-at-Secure, FIPS-KAT crypto submodule | 🟢 Implemented |
| `trace` | 5 | 2,933 | tracepoints, 15 per-CPU counters, hung-task watchdog (512 slots), PC-sampling profiler (seqlock), encrypted/redacted kdump | 🟢 Implemented (read-guard fail-open until installed — §12) |
| `lsm` | 2 | 2,927 | 53 LSM hook points, lock-free AtomicPtr policy registry, PermissivePolicy/DenyAllPolicy/**SecureBaselinePolicy**, denial→audit bridge | 🟢 Implemented (feature-on in shipped build) |
| `livepatch` | 2 | 2,570 | INT3-detour kpatch, ECDSA-P256 (KAT-gated, fail-closed), dependency topo-sort, batch enable/disable, rollback, W^X seal_exec | 🟡 Partial (inert: trust keys are placeholders) |
| `seccomp` | 2 | 2,421 | BPF-like filter VM, 5 actions, 18 pledge promises, 512-bit fast-allow, chain caps, boot self-tests | 🟢 Implemented (TSYNC fail-closed rejected; 4 promises inert) |
| `cap` | 2 | 2,027 | generation+index CapId (48+16 bit), CapRights, CapTable (allocate/lookup/revoke/delegate), fork/exec/dup refcount reconciliation | 🟢 Implemented |
| `drivers` | 4 | 1,709 | VGA text, GOP framebuffer console, PS/2 keyboard, raw COM1 serial | 🟢 Implemented (`uart_16550` dep unused — §12) |
| `virtio` | 3 | 1,343 | shared virtqueue transport, used-ring validation (id bounds/replay/double-free), MMIO+PCI-modern | ✅ Validated |
| `cpu_local` | 1 | 975 | `CpuLocal<T>`, LAPIC-ID↔CPU-index map, per-CPU data, BSP/AP init, online mask | ✅ Validated |
| `compliance` | 1 | 926 | Secure/Balanced/Performance profiles (boot-locked), FIPS mode (sticky, real KATs), crypto allow-list | 🟢 Implemented |
| `coverage` | 1 | 322 | KCOV per-task bitmap + `record_edge!` macro | 🟡 Partial (recorder is a no-op — §12) |
| `klog` | 1 | 264 | profile-aware `klog!`/`klog_force!`/`klog_always!`/`kprintln!` | 🟢 Implemented |
| `tlb_ops` | 1 | 296 | INVPCID/PCID primitives (all 4 types, fallbacks) | ✅ Validated |
| `crypto` | 1 | 212 | shared SHA-256 (FIPS 180-4) | ✅ Validated |
| `sync_safe` | 1 | 165 | IRQ-context-aware mutex (debug fail-loud on lock-in-IRQ) | ✅ Validated |
| `src` (entry) | 13 | 13,296 | `_start` boot orchestrator, ~30 runtime tests + 25 P0 regressions, native shell, Ring-3 launcher, stack-guard installer | 🟢 Implemented |

(Plus `kernel/build.rs` 315, `kernel/fuzz/mock_kernel.rs` 346, `kernel/tests/test_coverage.rs` 286.)

### 4.2 Bootloader (1 file · 1,171 LOC)

UEFI (`uefi` 0.29) loader: reads `kernel.elf`, applies static-PIE `R_X86_64_RELATIVE` relocations with an
RDRAND-derived KASLR slide (Fisher-Yates over 2 MiB slots, ≤512 MiB), builds 4-level page tables
(1 GiB high-half + 4 GiB identity), captures GOP framebuffer + ACPI RSDP + cmdline, `exit_boot_services`,
jumps to `_start`. Boot-phase W^X compromise (2 MiB huge pages RWX until the kernel hardens NX) is
explicit and handed off to `enforce_nx_for_kernel()`. No kernel-image signature verification (§13).

### 4.3 User space & tooling

- **Ring-3 programs** (~9.7k LOC): native shell (~30 commands), syscall/clone/kcov tests,
  `hello_musl.c` (static-musl conformance target), and the fuzzing runner family. The init program is
  feature-selected (`shell` / `syscall_test` / `musl_test` / `clone_test` / `fuzz_runner` / default hello).
- **Fuzzing** (`fuzz/` ~1.9k LOC + `userspace/fuzzer/`): 10 cargo-fuzz targets (syscall, vfs_path,
  elf_loader, network_packet, signal, memory, ipc, scheduler, cgroup, futex); 10 TOML syscall
  descriptions; coverage-guided mutation, resource tracking, stateful state machines, corpus sync, crash
  triage. Backed by a `mock_kernel` harness. **Caveat:** in-kernel KCOV edge feedback is not yet live
  (§12), so continuous-mode coverage guidance is limited until that lands.
- **Scripts / CI:** `scripts/` holds the gate implementations (boot_check, kernel_test, musl_check, SMP,
  stress, perf, melting, IOMMU, AFL). Workflows: `ci.yml` (fmt/clippy · build · lint · boot+test+musl),
  `fuzz.yml` (continuous + cargo-fuzz targets + triage + corpus), `afl_fuzz.yml`, `monthly-stress-test.yml`.

---

## 5. Capability Matrix (code-verified)

*Within this section, a ✅ bullet means the capability is implemented and wired on the active path (at
least the 🟢 tier of §0; the crate table in §4.1 carries the finer Validated-vs-Implemented split), and 🟡
marks a capability that is partial or inert. Every "gap" is stated explicitly.*

### 5.1 Boot & memory

- ✅ UEFI static-PIE boot, high-half map at `0xFFFFFFFF80000000`, KASLR slide from bootloader.
- ✅ Reservation-aware buddy allocator (orders 0–10, 4 MiB max): heap/kernel/framebuffer/UEFI regions
  withheld per-page; transactional preflight-then-commit; sticky poison on metadata contradiction.
- ✅ Dual heap: normal `LockedHeap` + a physically-isolated emergency allocator; **15-class heap-admission
  ledger** with a *compile-time* proof that hard floors + reserve + admitted == heap size.
- ✅ COW fork with boot-reserved refcount table; two-phase clone plan (mid-clone OOM leaves parent intact).
- ✅ Page cache: intrusive LRU, dirty writeback, pressure reclaim, cgroup-charged, bounded (256 pages).
- ✅ TLB shootdown: per-CPU IPI mailboxes, PCID/INVPCID (3 flush paths), fail-closed ACK (retry→panic).
- ✅ OOM killer: watermark → cache reclaim → generation-bound scored victim kill, audited.
- ✅ Guard pages: kernel RSP0 stack, #DF IST stack, NMI IST stack, user stacks (demand-grow floor).

### 5.2 Process, threads, scheduler

- ✅ PCB: pid/tgid/generation, credentials (+generation for TOCTOU defense), affinity/cpuset, 5 namespace
  pairs, TLS (FS/GS), seccomp/pledge, `cap_table`, per-task rlimits (**advisory-only**), cgroup membership.
- ✅ fork/exec/clone: COW fork; `CLONE_VM/FS/FILES/SIGHAND/THREAD/SETTLS/*TID/NEW{PID,NS,IPC,NET,USER}`;
  path-based `execve` with `#!` shebang chains (depth 4); raw-image spawn split to syscall 517 (closes the
  old confused-deputy); ELF loader rejects W^X segments, overlaps, non-canonical/out-of-range entry, ET_DYN.
- ✅ auxv: 19 `AT_*` entries incl. `AT_RANDOM`, `AT_SECURE` (seam; no setuid-exec path wired yet).
- ✅ Scheduler: per-CPU MLFQ (256 priority buckets), **bounded rotating selector (≤16 visits — a security
  invariant)**, work stealing + periodic load balancing, starvation boosting, cpuset isolation; IRQ-return
  path is entirely try-lock with `need_resched` rearm; (pid,generation) identity defeats PID-reuse/ABA.
- ✅ wait/exit: zombie reaping (`wait4`/`waitpid`), SIGCHLD, orphan reparent, exactly-once teardown atomics.

### 5.3 IPC & signals

- ✅ Pipes: ring buffer, PIPE_BUF-atomic writes, dual-layer refcount, EINTR, **capability IDs
  pre-allocated at fd-install** (U.S2-3A) with exact rollback.
- ✅ Capability message queues: per-namespace partitioned registry, unforgeable (pid,generation) sender ACLs.
- ✅ Futex: WAIT/WAKE/WAIT_TIMEOUT/LOCK_PI/UNLOCK_PI, PI chains (depth 64), per-TGID/global bucket budgets,
  owner-death (robust) *semantics*. **Gap:** the userspace `robust_list` is stored but not walked on exit.
- ✅ Signals: 64 signals, per-task masks/dispositions, handler delivery on syscall-return with SROP-defended
  `rt_sigframe` + `rt_sigreturn`, EINTR wake. **Gaps:** `sigaltstack` unimplemented (frame hardcodes
  SS_DISABLE); nesting capped at 1.

### 5.4 Security framework

- ✅ Capabilities: `CapId` = 48-bit generation + 16-bit index; `CapRights` (READ..BYPASS_MAC, AUDIT_*,
  TRACE_READ); allocate/lookup/revoke/delegate; NOXFER + non-transferable namespace caps; generation
  exhaustion is an error, not a wrap; double-decrement panics (abort). **fd→capability is wired**:
  `FileOps::cap_id/set_cap_id` set at open/dup/fork, validated at close; regular files and pipes carry caps.
- ✅ LSM: **53 hook points** across syscall/process/VFS/memory/IPC/signal/network/livepatch; lock-free
  policy switch; `SecureBaselinePolicy` (the Secure-profile enforcer) blocks user W^X, non-root→uid/gid 0,
  confines ptrace (Yama-like), and keeps kpatch deny-by-default even for root. `lsm` feature is **on** in
  the shipped kernel/kernel_core/vfs builds. Every deny-capable hook emits a denial audit event.
- ✅ Seccomp/pledge: BPF-like VM (out-of-bounds jump fails closed to Trap), 5 actions (most-restrictive
  wins), **18 pledge promises** — 14 map to syscall sets; **UNIX/INET/DNS/PTRACE are parseable but map to no
  syscalls yet (inert — they grant nothing, not a silent-allow)** — 512-bit fast-allow bitmap (disabled if
  any LdArg), chain caps (64/256/2048), boot cap self-test + pledge/BPF divergence oracle.
  `no_new_privs` enforced. **TSYNC is deliberately unsupported and fail-closed-rejected** at the boundary.
- ✅ Audit: SHA-256 hash chain (domain-separated), optional HMAC-SHA256 (set-once, 16–32 B key,
  CAP_AUDIT_WRITE gated), 256-entry ring with FIFO-evict + dropped counter, cursor export (CAP_AUDIT_READ),
  cannot be disabled once initialized, mandatory + halt-on-fail under Secure. Persistence is hook-only.
- ✅ Compliance: Secure/Balanced/Performance profiles (boot-locked, corrupted→Secure); sticky FIPS mode
  with real KATs (SHA-256, HMAC-SHA256, ECDSA-P256 RFC 6979) and a crypto allow-list. No AES-GCM KAT yet.

### 5.5 Memory-safety hardening

- ✅ W^X validator (walks live CR3, zero-violation contract); single-pass section NX (`.text` R-X, etc.).
- ✅ SMEP/SMAP/UMIP enabled (SMAP a hard boot requirement); CLAC on every IRQ/exception/syscall entry.
- ✅ Spectre/Meltdown suite: IBRS/IBPB/STIBP/SSBD (per-CPU, BSP-floor admission for weaker APs),
  RSB stuffing (32 entries + LFENCE), SWAPGS+LFENCE on entry/exit (CVE-2019-1125). **Retpoline is a status
  field with no codegen** (honestly declared off). SpectreV1 is LFENCE-in-syscall-path (partial).
- ✅ ChaCha20 CSPRNG (fast-key-erasure, RDSEED→RDRAND, never zero-fill, 1 MiB reseed), FIPS-gated.
- ✅ kptr guard (per-boot secret; truthfully reports weak-TSC vs hardware-RNG seeding).
- 🟡 **KASLR:** text KASLR is *verify-only* (bootloader-supplied slide, currently effectively off); the
  active randomization is partial KASLR — kernel-stack, user-mmap, and heap bases via CSPRNG.
- 🟡 **KPTI:** dual-CR3 contexts, seqlock install, PCID allocator, trampoline descriptor all coded, but MM
  does not yet produce distinct user/kernel roots, so production runs single-CR3 and switches no-op. The
  live plan tracks this as "R121-2 KPTI trampoline DEFERRED (non-gating)."

### 5.6 VFS & storage

- ✅ ramfs (root fs), **ext2/ext3 read-write with JBD2 ordered-data journaling** (plus a Zero-OS-private
  writer-intent journal format, SHA-256 intent hashing, ownership-graph mount validation), procfs
  (self/meminfo/cpuinfo/uptime/version/per-PID, access-filtered), devfs (null/zero/console + block nodes),
  initramfs (CPIO newc, hardlink-aware, read-only), cgroupfs (`/sys/fs/cgroup`).
- ✅ POSIX DAC (owner/group/other, umask, sticky bit dual-end on rename/unlink), host-mapped credentials
  (defeats userns euid spoofing), openat2 all RESOLVE_* flags, O_NOFOLLOW/O_PATH, symlink loop cap (40),
  per-namespace CoW mount tables (eager materialization), renameat2 RENAME_NOREPLACE.
- ✅ Credential-generation TOCTOU defense: DAC/LSM decisions bound to the exact inode; open re-stats the
  parent and re-checks ino-stability + DAC before create/truncate; rename revalidates both ends.
- ✅ Storage backend: virtio-blk (PCI+MMIO), Bio/RequestQueue, RAII IOMMU unmap. **Gaps:** AHCI/NVMe absent;
  block I/O is synchronous (polling); multiqueue/discard constants defined but unwired.

### 5.7 Network

- ✅ virtio-net; Ethernet/ARP (anti-poisoning, RX/TX token buckets); IPv4 (checksum, TTL, source-route
  reject, fragment reassembly with RFC 5722 overlap reject + per-source/global/per-NS caps + 30 s timeout);
  ICMP (echo/unreachable/time-exceeded, type whitelist, rate limit); UDP (pseudo-header checksum,
  zero-checksum drop).
- ✅ TCP: 11-state FSM, 3-way handshake incl. simultaneous open, RFC 6298 RTO + Karn, NewReno,
  **SACK (RFC 2018/6675, real scoreboard)**, **Timestamps (RFC 7323)**, window scaling, SYN cookies,
  challenge-ACK (RFC 5961), keyed ISN (RFC 6528), listen/accept, graceful close. *(SACK + Timestamps were
  listed as gaps in the old roadmaps — they are now implemented and wired.)*
- ✅ Conntrack (TCP/UDP/ICMP, per-state timeouts, LRU, heap-derived cap 256, per-NS cap 64); **default-DROP
  stateful firewall** (priority-ordered, ACCEPT/DROP/REJECT, per-namespace tables, catch-all-Accept
  removed); capability + per-hook LSM socket API; **fail-closed netns TX device-ownership gate**;
  per-tenant (J.2) socket/half-open/byte/port quotas.
- ✅ **Per-namespace dataplane (D3, 2026-07-25):** per-NS ARP cache (same IP may map to different MACs
  in different namespaces; reached only via the `NetNsDeviceHooks::ns_arp_cache` upcall, fail-closed on
  unknown/destroyed NS), per-NS validated address/gateway/subnet config (root delegates to the global
  config — no second copy to drift; children born unconfigured), per-NS routing
  (`next_hop` → Local/OnLink/Gateway/Unroutable, `ENETUNREACH`), all charged to `HeapClass::NetnsConfig`
  **and** a 16 KiB per-NS `NsByteBudget` (root not exempt).
- ✅ **RX ingress (D3, 2026-07-25):** bounded process-context poll at the scheduler deferred-work drain
  (~10 ms self-throttled window, budget 32, fair per-device quantum, poll-scoped `rx_auth` capability);
  static 32 × 4 KiB `BufPool` outside heap admission with pool-verified provenance and a per-device
  owned-buffer cap; virtio-net completion servicing + replenish → **`eth0` receive is live**
  (`netns_rx_eth0_slirp` gate: ARP probe out, SLIRP reply received and learned). On-link TX misses emit
  rate-limited **ARP request probes** (per-NS ring + bucket; global bucket drawn at emission only).
- ✅ **Gaps:** no IPv6 datapath; virtio-only (no e1000); no checksum/TSO offload, mergeable RX, or multiqueue.
  The pending-frame queue is landed and gateway-fallback delivery is retired. Remaining work includes
  firewall administration, `veth` plus a real routing table, and capability-safe arming of
  `move_net_device` (518), which remains hard-gated `ENOSYS`.

### 5.8 SMP, IOMMU & concurrency

- ✅ LAPIC + AP bring-up via INIT-SIPI-SIPI (≤64 CPUs), strict/fail-closed MADT parse, 5 IPI types,
  IPI TLB shootdown, PCID/INVPCID, `CpuLocal<T>`, RCU grace periods, 9-level lockdep. **Gaps:** IOAPIC
  driver present but init **disabled** (still on legacy 8259 PIC); **x2APIC unsupported** (hard cap 64 CPUs).
- 🟡 IOMMU/VT-d: DMAR ACPI parse (strict, 1 GiB-bounded, TOCTOU-hardened two-pass), root/context tables,
  second-level page tables (AGAW 39/48-bit, validated against CAP.SAGAW), interrupt remapping (SID-verified
  IRTE), fault handling (FRI rotation, flood quarantine), device isolation/detach, VM-passthrough API.
  **IOMMU init IS wired into boot** (`main.rs` step 7.53, before net/block probes) — the "DMAR discovery
  stubbed" comment in `main.rs` is *stale*; discovery works where a DMAR table exists (default QEMU has
  none → correct legacy fallback). Needs real-hardware validation before ✅.

### 5.9 Containers

- ✅ Five namespaces — PID (32-level nesting, cascade init-kill, vpid chains), mount (CoW tables), IPC
  (SysV), network (per-NS devices/sockets + TX gate **+ per-NS dataplane: ARP cache, addressing,
  routing, 16 KiB byte budget**), user (UID/GID maps, ≤5 extents, unprivileged
  containers) — via `clone`/`unshare`/`setns`.
- ✅ Cgroups v2, **six controllers**: CPU (weight + max quota with contention-deferred debt), memory
  (max/high, charge/uncharge), pids (fork gate), io (bytes/iops token bucket), **files (fd count)**,
  **net (ephemeral ports)** — exposed via syscalls + `/sys/fs/cgroup` with subtree delegation.
  **Gap:** no cgroup namespace; unprivileged delegation partial.

### 5.10 User mode & Linux ABI (Phase U / M0)

- ✅ Ring-3 via SYSCALL/SYSRET, **121 dispatched syscalls**, full SysV auxv, ELF loading with DoS guards,
  shebang resolution, path-based execve vs. native image-spawn disambiguation, signal delivery.
- ✅ **Headline:** a statically-linked musl libc binary runs end-to-end (crt→auxv→`printf`→`writev`→
  `exit(0)`), proven by the bidirectional fail-closed `make musl-check` gate.
- 🟡 Intentionally divergent from full Linux at M0: rlimits advisory (not enforced on brk/mmap); no dynamic
  linking (ld.so/PT_INTERP/vDSO), no user-space ASLR; `chown`/`mremap`/`waitid` are stubs; `link` EPERM;
  `sigaltstack` absent; setuid-exec not wired.

---

## 6. Gap Analysis vs Linux

Scoped to the actual target (UEFI/QEMU x86_64 server workloads), not "Linux parity" in the abstract.

| Area | Linux | Nilix | Assessment |
|---|---|---|---|
| Boot / arch | EFISTUB/GRUB, full ACPI, x2APIC, CET | UEFI single-stage, RSDP/MADT/DMAR/HPET only, xAPIC, no CET | Strong; missing DSDT/SSDT, x2APIC, shadow stacks, Secure Boot |
| Memory | SLUB/SLAB, NUMA, swap, THP, KASAN | buddy + global heap + admission ledger, COW, page cache, PCID | Core is production-grade; **no slab allocator**, no NUMA/swap/THP |
| Process | task_struct, NPTL, ptrace | full PCB, COW fork, clone flags, 64 signals | Mature; thread-group basics only, no ptrace, sigaltstack absent |
| Scheduler | CFS/EEVDF, cgroup sched | per-CPU MLFQ, work-steal, cpuset, cgroup CPU quota | Solid for the workload; not CFS-class fairness |
| Security | LSM+SELinux/AppArmor, seccomp-bpf, caps | LSM (53 hooks) + SecureBaseline, seccomp+pledge, capabilities | Framework complete; exceeds many Linux *defaults*; no policy-language MAC |
| Containers | 7 namespaces, cgroups v2 | 5 namespaces + cgroups v2 (6 controllers) | Near-parity; **no cgroup or time namespace** |
| Network | full TCP/IP + netfilter + IPv6 | TCP (NewReno/SACK/TS/WS/cookies) + UDP/ICMP + conntrack + firewall | Strong IPv4; **no IPv6**, no NAT, no L7 |
| Storage | ext4/xfs/btrfs/zfs, io_uring | ext2/ext3 (JBD2), ramfs, procfs, devfs, cgroupfs | ext2/3 with journaling is well beyond the old "ramfs/devfs" gap; no modern FS, sync I/O only |
| Drivers | 10M+ LOC | VGA/serial/PS-2/virtio-net/virtio-blk | Minimal by design (virtio-only); no driver framework |
| Virtualization | KVM | IOMMU/VT-d passthrough prep | IOMMU present; no hypervisor |
| User space | glibc/musl + ld.so, full POSIX | byte-exact syscall ABI, **static-musl runs** | M0 foundation; no dynamic linking / vDSO / user ASLR yet |

**Net:** the security framework, container isolation, and SMP concurrency are the strongest areas
(production-grade for the QEMU target); the widest gaps are driver breadth, a slab allocator, IPv6, modern
filesystems, and the still-open user-space dynamic-linking work (Phase U).

---

## 7. Phase Chronology (A–U)

The project evolved through a security-first phase order. Phases A–G are complete; the H–T bands were
**hardening/QA work arcs** (audit rounds and the S-wave hardening series), not separate feature phases —
they folded into the continuous audit process (§11) rather than delivering new subsystems. Phase U is the
current feature frontier.

| Phase | Theme | Status | Evidence |
|---|---|---|---|
| A | Security foundation: usercopy/SMAP, Spectre suite, audit upgrade, SMP-ready interfaces | ✅ Complete | `security/`, `kernel_core/usercopy.rs` |
| B | Capability + LSM + seccomp framework, wired into syscall/VFS/process | ✅ Complete | `cap/`, `lsm/`, `seccomp/` |
| C | Storage: virtio-blk, page cache, ext2, procfs/devfs/initramfs, OOM killer, openat2 | ✅ Complete | `block/`, `vfs/`, `mm/page_cache.rs` |
| D | Network: full IPv4 TCP/IP with conntrack + stateful firewall | ✅ Complete | `net/` (17 files) |
| E | SMP & concurrency: AP boot, IPI TLB shootdown, per-CPU sched, RCU, lockdep, futex PI | ✅ Complete | `arch/smp.rs`, `sched/`, `cpu_local/` |
| F | Resource governance: 5 namespaces, cgroups v2 (6 controllers), IOMMU/VT-d driver | ✅ Complete | `kernel_core/*_namespace.rs`, `cgroup.rs`, `iommu/` |
| G | Production readiness: KASLR/KPTI machinery, tracing/watchdog/profiler/kdump, livepatch | ✅ Complete (KPTI inert, §5.5) | `security/kaslr.rs`, `trace/`, `livepatch/` |
| H–T | Hardening / QA work arcs (S-wave, R100–R185 audit series) | ✅ Folded into §11 | `docs/review/` |
| **U** | **User Mode & Linux ABI (Compat-ZeroABI)** | 🟡 **In progress** (M0 done; U.S2-3B landed) | §9 |

---

## 8. 1.0-Preview Release Gate

**Gate definition:** three consecutive full-codebase audit rounds with **zero HIGH and zero CRITICAL**
findings on an immutable tree (the "zero-HIGH streak 3/3"), plus resolution of all D1 (highest-severity)
design findings.

**Current status: BLOCKED (2026-07-30).**

| Gate item | State |
|---|---|
| Zero-HIGH streak | **0/3** — reached 3/3 on 2026-07-22 (R181–R183), reset by R184's real CRITICAL+HIGH, rebuilt to 1/3 by R185, then **reset to 0/3 by R186** (1 CRITICAL + 7 HIGH filed). The RF186 review-fix pass earns no streak credit |
| Open CRITICAL / HIGH / MEDIUM | 0 / **1** / 0 actionable — `R186-4`: VMA/MM metadata (`FallibleOrderedMap`/`Vec` ownership) sits outside whole-heap aggregate admission, so PROT_NONE and fork pressure bypass the ledger |
| D1 design findings | **1 open** — `D1-RES-HEAP-ADMISSION-REOPENED` (the design parent of `R186-4`: whole-heap closure excludes live consumers). D1-ISO remains RESOLVED 2026-07-24 (type-enforced TX token + Option-B claim narrowing; residual config arc re-filed as D3 NETNS-DATAPLANE-CONFIG, Phase I.3) |
| Proof-obligation ledger | 8 of 12 PO artifacts complete |
| Gate-relevant test debt | Hosted CI now gates 169 default-parallel tests plus three test-code compile checks. Physical hostile-device/DMA/IOMMU, crafted-ext2, true readdir-OOM, RF186-24 exact-fallback injection, and privileged no_std execution remain explicit debt |

**What "unblocked" will and won't mean:** clearing the gate qualifies the tree for a **1.0-Preview**
(feature-and-hardening milestone) — it is **not** a general-availability, production-certified, or
ABI-stable release. Phase U (dynamic linking, glibc, OCI) remains ahead, KPTI is still inert, and
real-hardware/bare-metal validation is outstanding.

> **README reconciliation:** updated for the authoritative 2026-07-30 Stage-3 state:
> 16 fixes reviewed, 24 RF defects repaired, 0 escalations; approved eight-file payload uploaded,
> hash-verified, and the complete focused/default-parallel plus remote gate ladder passed.
> Gate status remains “BLOCKED — one HIGH (`R186-4`) plus its D1 parent; streak 0/3”.

---

## 9. Current Execution — Phase U (Compat-ZeroABI)

**Decision (2026-06-18, locked):** a capability-first **native core ABI** plus a **de-privileged
Linux-compat personality**, sequenced *converge-later* — build the user-mode foundation on the existing
Linux cABI first (M0), prove it with a musl gate, then fork the native/personality split. Reached via a
17-agent analysis workflow (6-dimension analysis → 7 adversarial `file:line` verifications → 3-architect
panel). Target: glibc + full Linux/OCI, dynamic linking in scope.

**Slice status:**

| Slice | Scope | Status |
|---|---|---|
| U.M0 | auxv + SysV entry stack, startup syscalls, musl conformance gate, exec disambiguation, signal delivery, ~30-syscall fill, user-stack guard | ✅ **Done** (musl-check green) |
| U.S1 | exec disambiguation hardened (native raw-image spawn vs. Linux path-execve on disjoint numbers — syscall 517) | ✅ Done |
| U.S2 | native core cap-wiring: fd value → CapId; land native syscalls | 🟡 In progress — **3A** (pipe CapIds) + **3B** (FileOps cap_id trait infra, commit `b179cd6`) **done**; 3B audited sound (R184) |
| U.S2-4/5 | `native_cap_op(604)` + seccomp 600–631; generation-exhaustion errno | 🔵 Planned (unblocked, parked behind the streak) |
| U.S3 | synchronous IPC + shared memory (the gate); measure cold-path latency | 🔵 Planned |
| U.S4 | personality stand-up (**point of no return**): cold/dangerous Linux semantics move to the de-privileged server | 🔵 Planned |
| U.S5 | dynamic linking (ld.so/PT_INTERP/PIE/ASLR + vDSO) | 🔵 Planned |
| U.S6 | glibc (robust-futex list walk, TLS, vDSO clock_gettime) | ⚪ Directional |
| U.S7 | full Linux/OCI (unmodified container images over namespaces + cgroups) | ⚪ Directional |

---

## 10. Forward Roadmap

### Near term (from the live plan v15.52, gate-directed)

1. **Remain at the user-directed Stage-3 hold:** land and verify the hosted sub-crate CI gate,
   synchronize ReviewFix records, and do not invoke the next stage.
2. **Only after explicit user resume, run `kernel-next-phase`:** carry `R186-4` and
   `D1-RES-HEAP-ADMISSION-REOPENED` as the top mandatory plan item.
3. **Implement R186-4 as one aggregate, amount-symmetric admission transaction.**
   A partial multi-ledger design is explicitly rejected because it cannot provide secure rollback.
4. **Run the next full audit only after R186-4 closes.** The nominal R187 round may then become
   zero-HIGH streak candidate **1/3**, not 3/3.
5. Continue non-gating D3 feature work after the security blocker: firewall administration,
   veth/routing-table support, and arming `move_net_device`.

### Mid term (remaining Phase U)

5. **U.S2-4/5** native capability syscalls + seccomp reconciliation for the 600–631 native block.
6. **U.S3** synchronous IPC + shared memory, then measure cold-path latency (the U.S4 go/no-go gate).
7. **U.S4** de-privileged personality stand-up — the point of no return for the hybrid split.
8. **U.S5** dynamic linking: ld.so/PT_INTERP/PIE, user-space ASLR, vDSO.

### Long term (directional)

9. **U.S6/S7** glibc compatibility (robust-futex list walk, vDSO clock_gettime) and full Linux/OCI
   (unmodified container images).
10. Enterprise/perf capabilities: slab allocator, NUMA-aware scheduling, per-tenant network budgets beyond
    J.2, KVM/hypervisor support, IPv6, a modern journaling FS, real KPTI dual-root (unblocks Meltdown-class
    defense-in-depth), x2APIC / >64 CPUs, Secure Boot + kernel-image signing, bare-metal validation.

---

## 11. Security-Audit History

Nilix is developed under continuous adversarial review: each round audits the kernel, files findings by
severity, fixes them, and converges via bidirectional peer review (Claude Code + the Codex MCP, or
independent Claude-solo skeptic fleets when Codex is unavailable) before the round closes.

| Era | Rounds | Focus | Outcome |
|---|---|---|---|
| Baseline | R1–R24 (2025-12) | Boot, memory, process isolation, IPC, VFS, Ring 3 | ~138 filed, ~111 fixed |
| Framework | R25–R49 (2025-12→2026-01) | Cap/LSM/seccomp integration, storage, early network | ext2, page cache, VirtIO hardening |
| Network | R50–R99 (2026-01→02) | TCP/IP hardening, conntrack, firewall, DMA/ext2 | R99 close: 496 filed / 454 fixed |
| Governance | R100–R155 (2026-02→05) | Namespaces, cgroups, IOMMU, MSR/GS, fetch_add sweep | ~881 filed / ~95.8% fixed by R155 |
| Concurrency | R156–R180 (2026-05→07) | IRQ-safety (sync_safe), deadlock/liveness, heap-admission, ABBA | R172 context-switch CRITICAL; R180 32 impl findings |
| Gate push | R181–R186 (2026-07) | Zero-HIGH streak + U.S2 cap infra + design queue | R181–R183 clean; R184 real 1C+1H; R185 clean; R186 left 1 HIGH open and Stage 3 repaired 24 fix escapes |

**Cumulative (through R186):** ~1,333 findings filed and ~1,177 fixed/resolved.
Historical filed-but-not-fixed IDs include refuted, merged, accepted-risk, superseded,
and deferred findings; they are not all open vulnerabilities.

- **Currently open actionable:** 0 CRITICAL / **1 HIGH (`R186-4`)** /
  0 MEDIUM / 0 LOW.
- **Current gate-blocking design debt:** `D1-RES-HEAP-ADMISSION-REOPENED`,
  the parent of `R186-4`.
- The six historical R180 design findings retain their recorded dispositions, but the
  later R186 consumer evidence reopened aggregate heap admission under a new design ID.

These are estimates aggregated across 186 rounds; authoritative per-round disposition
lives in `docs/review/`.

**Design findings (historical R180 six plus the R186 reopened parent):**

| ID | Sev | Title | State |
|---|---|---|---|
| D1-RES-HEAP-BUDGET-SCOPE | ~~D1~~ | whole-heap admission/ownership scope proof | **RESOLVED 2026-07-24** — R1 in-place sigframe, R2 stdin/socket `.bss` rewrites, R3 intrusive allocator, R4 instrumented peak ceiling, combined-load probe; D3 validation-breadth backlog only |
| D1-RES-HEAP-ADMISSION-REOPENED | D1 | aggregate admission excludes live VMA/MM metadata | **OPEN / GATE-BLOCKING** — parent of `R186-4`; the prior R180 closure remains historical but was invalidated by this newly proven consumer |
| D1-ISO-NETNS-DATAPLANE | ~~D1~~ | per-namespace device-ownership + dataplane isolation | **RESOLVED 2026-07-24** — type-enforced `tx_auth::AuthorizedTxDevice` token (sole driver-transmit path), Option-B claim narrowing (`docs/namespace-isolation.md`), `net_ns_tx_isolation` boot test; feature gap re-filed as **D3 NETNS-DATAPLANE-CONFIG** (Phase I.3) |
| D2-ARC-CLONE-LOCK | ~~D2~~→D3 | cross-registry lock-ordering / transaction API | demoted 2026-07-24 — `ProcessRegistryTxn` + seccomp recount landed; D3 backlog (compile-time tokens, front-door unification, R37-1 TSYNC clone-side) |
| D2-ERR-VFS-FALLIBILITY | ~~D2~~ | end-to-end VFS fallibility (prepare/commit) | **RESOLVED 2026-07-24** — `make lint-fallible` mechanized + 2 real fixes (pending tracking commit) |
| D2-TST-ABI-BYTES | ~~D2~~ | static ABI-layout oracle vs. wrapper drift | **RESOLVED 2026-07-24** — 3-leg `make abi-check` oracle (pending tracking commit) |
| D2-ABI-STAT-LAYOUT | ~~D2~~ | VfsStat/UtsName Linux wire layouts | **RESOLVED 2026-07-24** — VfsStat → exact Linux x86-64 `struct stat` 144B; UtsName → 390B `new_utsname`; fallible TryFrom→EOVERFLOW; shell mirrors lockstepped; oracle LINUX_UAPI + gcc Leg-C; musl `MUSL-STAT-OK`/`MUSL-UNAME-OK` REQUIRED markers |
| D3-RES-COW-RESERVATION | D3 | COW metadata reservation transaction | **CLOSED 2026-07-24** — PO-MM-01 claims re-verified live; lazy reservation → Phase L |
| D3 NETNS-DATAPLANE-CONFIG | D3 | per-ns dataplane feature arc (from D1-ISO Option-B) | **LARGELY LANDED 2026-07-27** — per-NS ARP cache, `NsByteBudget`, RX-wiring gate, per-NS config/routing, RX ingress, external RX completion (`eth0` live), ARP probe TX, and pending-frame queue with gateway-fallback delivery retired. Residual: firewall admin surface, veth + routing table, `move_net_device` arming |
| D3 R37-1-TSYNC-CLONE-SIDE | D3 | TSYNC clone-side residual | **dispositioned** — revisit with TSYNC impl (F-5/Phase M) |

(PO = *proof obligation*, the design queue's closure artifacts; 8 of 12 complete as of 2026-07-22.)

**Process risk — audit calibration:** the R184 MODE-S (Codex-unavailable) round produced a ~91%
false-positive rate on HIGH by analyzing function-local logic without the enclosing lock scope or callers.
The mitigation is now mandatory: audits run Codex-cooperative, or apply an orchestrator re-read with a
caller/lock-context lens, before any finding is treated as real. Per-round reports live in `docs/review/`;
the live plan is `docs/review/nextplan/`.

---

## 12. Known Debt, Cleanups & Deferred Items

Surfaced by the 2026-07-23 full-source survey — none block the gate, but all are tracked so "surveyed"
never reads as "clean":

- **Orphaned files:** `kernel/sched/process.rs` (279 LOC legacy PCB, superseded by `kernel_core::process`)
  and `kernel/kernel_core/kcov_syscalls.rs` (147-line stale patch fragment, superseded by handlers in
  `syscall.rs`) — both un-`mod`'d dead code; delete candidates.
- **KCOV recorder is a no-op:** the management syscalls (520–524) and per-task buffer exist, but
  `record_edge_for_current` is a TODO and `record_edge!` is never invoked — coverage dumps return 0 edges.
  KCOV is scaffolding until this lands; continuous-fuzzing coverage feedback is limited meanwhile.
- **Livepatch inert:** trusted ECDSA-P256 key slots are all-zero placeholders → verification fail-closes to
  ENOSYS until real keys are provisioned (boot warns). The mechanism (KAT-gated verify, topo-sort deps,
  rollback, W^X seal) is complete.
- **KPTI inert / text-KASLR verify-only** (§5.5) — the highest-value hardening residuals.
- **Stale in-code comment:** `main.rs` claims DMAR discovery is stubbed; the `dmar.rs` parser is actually a
  complete fail-closed RSDP/XSDT walker (§5.8). Correct the comment.
- **trace read-guard fail-open until installed:** metric exports are ungated until `install_read_guard` runs
  at boot — a boot-ordering hazard.
- **Unused dependency:** `drivers` declares `uart_16550` but hand-rolls COM1 port I/O; the real serial init
  lives in `arch`. Drop the dep or adopt the crate.
- **Deferred syscalls/features:** `sigaltstack`, `robust_list` exit walk, `mremap`/`chown`/`waitid` real
  bodies, rlimit enforcement, setuid-exec, cgroup namespace — tracked in the Phase U / feature backlog.
- **~20 of 25 P0 regression tests are placeholders** awaiting fork/exec/futex/signal/VFS syscall infra
  (they report `Warning`/deferred, counted separately from failures).

---

## 13. Testing, CI & Fuzzing

**CI (`.github/workflows/ci.yml`)** — four parallel jobs on every push/PR to `main`:
`fmt-check + clippy` · `build` (PIE/build-std/hardened) · `lint` (4 custom source gates) · `boot-check +
test + musl-check`.

**Boot/conformance gates** read real exit codes from the serial log + `-d int` interrupt log (never QEMU's
own exit code):

- `make boot-check` — kernel reaches user space/idle **and** zero NX-violation instruction-fetch #PF
  (the `v=0e e=0011` signature).
- `make test` — parses the in-kernel `=== Test Summary: N passed, M deferred, K failed ===` with `K==0`,
  zero panic, zero NX #PF; exit polarity 0 PASS / 1 FAILED / 2 NOT-RUN.
- `make musl-check` — builds `--features musl_test`, asserts the libc-attributable marker (`42 * 2 = 84`),
  the success line, clean `exit 0`, zero NX #PF, no panic; **bidirectional and fail-closed** (the default
  native-Rust kernel, which also exits 0, never prints the libc marker → fails the gate).

**Custom lints (`make lint`):** `lint-release` (no ungated `println!`), `lint-smap` (only `usercopy.rs`
instantiates `UserAccessGuard`), `lint-fetch-add` (no bare `fetch_add(1)` for IDs/refcounts), `lint-repr-c-copy`
(padding-safety annotation on `#[repr(C)]` user-boundary copies).

**Runtime tests (~30 core + 25 P0 regressions + 4 heavy-stress):** heap/buddy, cap-table lifecycle,
seccomp (strict + pledge), audit hash chain, network parse/loopback, SMP online/IPI/TLB, cpuset,
scheduler affinity/starvation, process creation, security subsystem, TCP SYN-flood limit, all 5 namespace
isolation tests, and (2026-07-25) **11 `netns_*` D3 dataplane tests** — ARP isolation/exhaustion/LRU
eviction/TX limiter, per-NS sub-budget, per-NS config isolation, routing classification, the RX ingress
loop, RX pool lifecycle, the live `eth0` SLIRP round-trip, and ARP probe TX. Current in-kernel tally:
**30 passed / 39 deferred / 0 failed**. Extended suites: `stress_test.sh` (6 scenarios), `extended_smp_test.sh` (8/16-core),
`perf_regression_test.sh` (framework; benchmarks pending), `melting_test.sh` (bare-metal thermal, needs HW).

**Fuzzing:** 10 cargo-fuzz targets + 10 TOML syscall descriptions + a coverage-guided mutation engine,
resource tracking, stateful state machines, corpus sync, and 95%+ crash-triage dedup, backed by a
`mock_kernel` harness. `fuzz.yml` runs continuous + target modes + triage + corpus sync; `afl_fuzz.yml`
and `monthly-stress-test.yml` supplement. **Caveat:** live in-kernel KCOV coverage feedback is pending
(§12), so the continuous mode's guidance is currently structural rather than coverage-driven.

---

## 14. Risks & Dependencies

| Risk | Severity | Status | Note |
|---|---|---|---|
| Audit over-reporting (solo mode, no lock/caller context) | Process | **Active** | R187+ must retain the caller/lock-context lens and independent convergence evidence |
| Aggregate heap-admission design debt | D1 | **OPEN / gate-blocking** | `D1-RES-HEAP-ADMISSION-REOPENED` is the parent of `R186-4`; D1-ISO remains resolved |
| KPTI inert (single-CR3) | Design | Deferred (R121-2) | Meltdown-class defense relies on hardware immunity until MM dual-root lands |
| No real-hardware validation | Coverage | Open | QEMU-only; melting/bare-metal gates are frameworks |
| Livepatch trust keys unprovisioned | Ops | Open | mechanism complete, non-functional until keys wired |
| Host-side unit-test coverage | Coverage | **CI-gated allowlist** | 169 default-parallel tests with exact-count oracles plus IPC/kernel_core/kernel test-code checks; privileged suites remain boot/QEMU-only |
| Single build target (x86_64/UEFI/virtio) | Scope | By design | no portability layer; not a near-term goal |

---

## 15. Version History

| Version | Date | Milestone |
|---|---|---|
| 0.1–0.5 | 2025-12 | Boot, memory, process isolation, IPC, VFS, Ring 3 |
| 0.6.x | 2025-12→2026-01 | Threads/Clone; Phase A/B security framework |
| 0.7–0.9 | 2026-01→02 | Phase C storage, Phase D network |
| 0.10–0.12 | 2026-02→05 | Phase E SMP, Phase F governance (namespaces, cgroups, IOMMU) |
| 0.13.x | 2026-05→07 | Phase G production-readiness hardening; concurrency/IRQ-safety arc |
| 0.14.x | 2026-07 | Phase U M0 (static-musl runs); U.S2 cap infra; 1.0-Preview gate push; D3 per-namespace network dataplane (live `eth0` RX) |
| 1.0-Preview | TBD | zero-HIGH streak 3/3 + D1 resolved (gate) |
| 1.0.0 | TBD | first stable release (post Phase U personality) |

---

*This unified roadmap reflects a security-first approach — correctness and isolation before performance —
and is grounded in a full read of the source tree at the snapshot commit above, cross-checked against the
live plan and audit reports. It supersedes both prior roadmap documents. For the authoritative per-round
security status see `docs/review/`; for live priorities see `docs/review/nextplan/`.*
