# Nilix Architecture

This is the readable architecture reference behind the top-level
[README](../README.md). It covers the workspace layout, the verified crate layering and
dependency DAG, the boot flow, the syscall path, and the core subsystems. For the deep
reference — lock ordering, critical code paths, and the historical audit-finding record —
see [`docs/overview/architecture/ARCHITECTURE.md`](overview/architecture/ARCHITECTURE.md);
for per-subsystem deep dives see
[`docs/overview/02-architecture/subsystems/`](overview/02-architecture/subsystems/).

> **Design principle:** Security > Correctness > Efficiency > Performance.

---

## 1. Workspace layout

Nilix is a Cargo workspace. The kernel is an aggregate **binary** crate that pulls in ~25
focused sub-crates under `kernel/<subsystem>/`, each owning one concern. The bootloader and
the host fuzz executor are separate build units.

| Crate | Path | Role |
|---|---|---|
| `bootloader` | `bootloader/` | UEFI x86_64 bootloader: loads `kernel.elf`, applies PIE/KASLR relocations, builds page tables, exits boot services, jumps to kernel `_start` with `BootInfo*` in `rdi` |
| `kernel` | `kernel/` | The kernel aggregate **binary** (`kernel/src/main.rs` = `_start`); pulls in 21 sub-crates as path deps |
| `drivers` | `kernel/drivers/` | Console primitives: VGA, framebuffer, serial, PS/2 keyboard — and the `_print` sink + `kprintln!`/`println!` macros |
| `cpu_local` | `kernel/cpu_local/` | Per-CPU storage for SMP (`CpuLocal`, `current_cpu_id`) |
| `tlb_ops` | `kernel/tlb_ops/` | Low-level TLB/INVPCID primitives (dependency-free) |
| `virtio` | `kernel/virtio/` | Shared VirtIO transport: virtqueues, MMIO/PCI |
| `crypto` | `kernel/crypto/` | Shared no_std crypto (SHA-256) for audit/livepatch/vfs |
| `sync_safe` | `kernel/sync_safe/` | IRQ-context-safe wrappers around `spin` primitives |
| `klog` | `kernel/klog/` | Profile-aware, security-conscious kernel logging |
| `mm` | `kernel/mm/` | Memory: buddy allocator, heap admission ledger, page tables, page cache, DMA, OOM killer, TLB shootdown, fallible containers |
| `coverage` | `kernel/coverage/` | KCOV code-coverage infra (per-task bitmap, `record_edge!`) |
| `cap` | `kernel/cap/` | Capability access control (`CapRights`, `CapTable`, `CapId`) |
| `audit` | `kernel/audit/` | Security audit: hash-chained (HMAC-SHA256) tamper-evident ring |
| `security` | `kernel/security/` | Hardening: W^X/NX, KASLR, KPTI, CSPRNG (ChaCha20+RDRAND), kptr guard, Spectre |
| `lsm` | `kernel/lsm/` | Linux-Security-Module-style hook layer + policies |
| `seccomp` | `kernel/seccomp/` | seccomp/pledge syscall filtering (BPF-like VM) |
| `compliance` | `kernel/compliance/` | Hardening profiles (Secure/Balanced/Performance) + FIPS PolicySurface |
| `livepatch` | `kernel/livepatch/` | Signed live patching: INT3 detour + ECDSA/P-256 verify |
| `block` | `kernel/block/` | Block layer: `BlockDevice` trait, request queue, virtio-blk driver |
| `net` | `kernel/net/` | TCP/IP stack: buffers, ARP/IP/TCP/UDP, sockets, conntrack, firewall, net-ns |
| `trace` | `kernel/trace/` | Observability: tracepoints, per-CPU counters, watchdog, kdump |
| `iommu` | `kernel/iommu/` | IOMMU/VT-d DMA isolation |
| `kernel_core` | `kernel/kernel_core/` | **The hub**: PCB, syscall dispatch, fork/COW, signals, RCU, time, usercopy, ELF loader, all namespaces, cgroup v2 |
| `arch` | `kernel/arch/` | x86_64: GDT/IDT/interrupts, APIC, HPET, SMP, context switch, SYSCALL entry |
| `vfs` | `kernel/vfs/` | VFS core, ramfs, ext2, procfs, devfs, initramfs, cgroupfs, mount namespace |
| `ipc` | `kernel/ipc/` | Capability IPC: pipes, endpoints, futex(+PI), shm/timer/socket caps |
| `sched` | `kernel/sched/` | Per-CPU MLFQ scheduler + work-stealing + cpuset isolation |
| `fuzz_executor` | `tools/fuzz_executor/` | Host-side fuzz executor (libc/nix); not part of the kernel image |

---

## 2. Layered model

The kernel-internal dependency graph is a clean DAG (no cycles). The verified topological
layers, foundation → top:

| Layer | Crates | Role |
|---|---|---|
| **L0** foundation leaves | `drivers`, `cpu_local`, `tlb_ops`, `virtio`, `crypto`, `sync_safe` | Depended on by many, depend on ~0 kernel crates |
| **L1** | `klog`, `coverage` | Cross-cutting logging + coverage |
| **L2** | `mm`, `livepatch` | Memory foundation + signed patching |
| **L3** security core | `cap`, `audit`, `security`, `iommu` | Capability, audit, hardening, DMA isolation |
| **L4** | `lsm`, `seccomp` | Policy hooks + syscall filtering |
| **L5** | `block`, `net`, `compliance` | Device I/O + network + compliance |
| **L6** | `trace` | Observability |
| **L7** hub | `kernel_core` | The hub: process, syscall, namespaces, cgroup |
| **L8** | `arch`, `vfs` | Architecture + filesystems |
| **L9** | `sched`, `ipc` | Scheduling + IPC |
| **L10** binary | `kernel` (`.elf`) | Top of the DAG, with `bootloader` as the sole upstream producer |

**Leaf crates** (no outgoing kernel edges): `drivers`, `cpu_local`, `tlb_ops`, `virtio`,
`crypto`, `sync_safe`. **Hub:** `kernel_core` (14 kernel deps). **Top:** the `kernel`
binary. Anti-cycle constraints are deliberate: `cap`/`lsm`/`audit` Cargo.tomls document that
`kernel_core`/`vfs` were removed to avoid cycles, and `ipc/Cargo.toml` records the invariant.

---

## 3. Crate dependency graph

Edges `A --> B` mean **A depends on B**, grouped by the layers above. (The deep reference
also has an ASCII form; this Mermaid version is the readable one.)

```mermaid
flowchart LR
  subgraph L0["L0 foundation leaves"]
    drv[drivers] cpu[cpu_local] tlb[tlb_ops] vio[virtio] cry[crypto] ssf[sync_safe]
  end
  subgraph L1["L1"]
    klog[klog] cov[coverage]
  end
  subgraph L2["L2"]
    mm[mm] lp[livepatch]
  end
  subgraph L3["L3 security core"]
    cap[cap] aud[audit] sec[security] iommu[iommu]
  end
  subgraph L4["L4"]
    lsm[lsm] scc[seccomp]
  end
  subgraph L5["L5"]
    blk[block] net[net] cmp[compliance]
  end
  subgraph L6["L6"]
    trc[trace]
  end
  subgraph L7["L7 hub"]
    kc[kernel_core]
  end
  subgraph L8["L8"]
    arch[arch] vfs[vfs]
  end
  subgraph L9["L9"]
    sch[sched] ipc[ipc]
  end
  subgraph L10["L10 binary"]
    krn[kernel .elf]
  end
  boot[bootloader]

  klog-->drv
  cov-->cpu
  mm-->drv; mm-->cpu; mm-->tlb; mm-->klog
  lp-->cry; lp-->klog
  cap-->drv; cap-->klog; cap-->mm
  aud-->drv; aud-->klog; aud-->cry
  sec-->mm; sec-->drv; sec-->klog; sec-->cpu
  iommu-->drv; iommu-->mm; iommu-->klog
  lsm-->cap; lsm-->aud; lsm-->drv
  scc-->drv; scc-->aud; scc-->klog; scc-->mm
  blk-->drv; blk-->mm; blk-->vio; blk-->iommu; blk-->klog; blk-->lsm
  net-->mm; net-->vio; net-->drv; net-->cap; net-->lsm; net-->sec; net-->iommu; net-->klog
  cmp-->sec; cmp-->aud; cmp-->lp
  trc-->cpu; trc-->drv; trc-->sec; trc-->cmp; trc-->klog
  kc-->drv; kc-->mm; kc-->cpu; kc-->aud; kc-->scc; kc-->cap; kc-->lsm; kc-->sec; kc-->net; kc-->trc; kc-->cmp; kc-->lp; kc-->klog; kc-->cov
  arch-->kc; arch-->drv; arch-->cpu; arch-->mm; arch-->tlb; arch-->trc; arch-->klog
  vfs-->kc; vfs-->drv; vfs-->lsm; vfs-->blk; vfs-->mm; vfs-->cap; vfs-->klog; vfs-->cry
  sch-->kc; sch-->drv; sch-->arch; sch-->cpu; sch-->trc; sch-->klog; sch-->mm
  ipc-->kc; ipc-->drv; ipc-->mm; ipc-->vfs; ipc-->trc; ipc-->klog; ipc-->cap; ipc-->lsm; ipc-->aud
  krn-->arch; krn-->mm; krn-->sch; krn-->ipc; krn-->drv; krn-->kc; krn-->sec; krn-->vfs; krn-->aud; krn-->cap; krn-->lsm; krn-->scc; krn-->blk; krn-->net; krn-->iommu; krn-->trc; krn-->cmp; krn-->lp; krn-->klog; krn-->ssf; krn-->cov
  boot-. "UEFI handoff (BootInfo* in rdi)" .-> krn
```

**Foundation crate fan-in** (how many crates depend on each leaf): `drivers` 16,
`klog` 15, `mm` 11, `cpu_local` 7, `cap`/`audit`/`lsm` 5, `tlb_ops`/`virtio` 2,
`crypto` 3. These are the cross-cutting concerns — `drivers` (the `_print`/macro sink),
`klog` (`klog!` everywhere), and `mm` (the memory foundation) underpin the whole tree.

---

## 4. Boot flow: UEFI → kernel main

### Bootloader (`bootloader/src/main.rs`, `efi_main` at line 606)

1. `uefi::helpers::init`; locate the ESP, open `kernel.elf`.
2. Parse the ELF, allocate exact physical pages with KASLR placement
   (Fisher-Yates RDRAND/RDSEED shuffle).
3. Load LOAD segments to the slid physical base; classify per-4 KiB W^X permissions; apply
   `.rela.dyn` `R_X86_64_RELATIVE` relocations.
4. Find ACPI RSDP via the UEFI config table; read UEFI load-options cmdline.
5. Build 4-level page tables: high-half 1 GiB direct map (`0xffffffff80000000`→`0`), 4 KiB
   leaves over the kernel image for exact W^X, low 4 GiB identity map (hardened later),
   recursive PML4[510].
6. `Cr3::write`; snapshot the memory map; `exit_boot_services`.
7. Populate `BootInfo` (memory map, framebuffer, kaslr slide/flags, rsdp, cmdline,
   kernel phys base/size, version=2).
8. `mov rdi, boot_info; jmp entry` → kernel `_start`.

### Kernel (`kernel/src/main.rs`, `_start` at line 321). In order:

1. `cli`; serial banner; validate `BootInfo` pointer.
2. `drivers::framebuffer::init` + `drivers::vga_buffer::init`.
3. `klog::set_profile` from the `profile=` cmdline token.
4. `arch::apic::publish_lapic_state` (latch LAPIC MMIO base before the IDT).
5. `arch::interrupts::init` (IDT, 20+ handlers).
6. `mm::memory::init_with_bootinfo` (heap + buddy) → `mm::publish_heap_budgets` →
   `kernel_core::syscall::init_blocking_waiter_registries` → `mm::page_table::init`.
7. `stack_guard::run_rollback_self_test` + `stack_guard::install`.
8. **Security hardening:** `compliance::init_policy_surface` → `security::init`
   (W^X/NX/CSPRNG/kptr/Spectre) → `lsm::init` (+ `SECURE_BASELINE` under Secure) →
   `compliance::lock_profile` → `arch::gdt::install_ist_guard_pages_before_smp`.
9. `security::init_kaslr` + KASLR/KPTI fail-closed policy checks.
10. `mm::tlb_shootdown::init_invpcid_support`; `arch::cpu_protection::enable_protections`
    (SMEP/SMAP/UMIP).
11. `arch::init_syscall_msr(syscall_entry_stub)` (LSTAR) + KPTI CR3 callback +
    `security::kaslr::enable_kpti`.
12. `kernel_core::init` → `process::init`, `time::init`, `lsm::register_context_provider`,
    `seccomp::register_current_hooks`, socket/cgroup/netns hooks, audit authorizer, OOM
    callbacks, `cgroup::init`.
13. **APIC + SMP:** `arch::apic::init`, `arch::hpet::init`, calibrate LAPIC, `arch::init_bsp`,
    force-init all lazy CpuLocals, `coverage::init`, `arch::syscall::init_syscall_percpu(0)`,
    `arch::register_ap_security_init(security::spectre::init_cpu)`, `arch::start_aps`.
14. `sched::enhanced_scheduler::register_security_switch_hook(security::spectre::context_switch_barrier)`
    → `sched::enhanced_scheduler::init` → `sched::cpuset::init`.
15. `ipc::init`.
16. `vfs::init` (devfs: null/zero/console).
17. `mm::init_page_cache`.
18. `iommu::init(rsdp_phys)` + IOMMU fault callbacks.
19. `net::init(iommu_required)`.
20. `block::init` → `block::probe_devices` → `block::register_device` →
    `vfs::register_block_device` → `vfs::Ext2Fs::mount` → `vfs::mount("/mnt")`.
21. `audit::init(capacity)` + authorizers + CSPRNG HMAC key + boot event emit + OOM/livepatch
    callbacks.
22. `trace::init` + `trace::install_read_guard` (CAP_TRACE_READ).
23. (if debug interfaces) integration tests, runtime tests, `usermode_test::prepare_usermode_test`.
24. `arch::interrupts::enable_serial_interrupts`; `BOOT_PHASE_COMPLETE = true`; **`sti`**
    (line 1449) — interrupts enabled only now, at the very end.
25. `kernel_core::mark_process_deferred_work_ready` → `arch::ipi::broadcast_ipi(Reschedule)`.
26. Add the pending Ring-3 process to the scheduler; `shell::init_and_run()` (BSP enters the
    interactive shell; never returns).

**First-initialized:** console (`drivers`) → interrupts (`arch`) → memory (`mm`) →
security/compliance/lsm → `kernel_core` (process) → APIC/SMP (`arch`) → scheduler → IPC →
VFS → page cache → IOMMU → net → block → audit → trace.

---

## 5. Syscall path: Ring 3 → arch → kernel_core → subsystems

1. **Ring 3 executes `SYSCALL`.** The CPU loads `IA32_LSTAR` (set in
   `arch/syscall.rs:573` `init_syscall_msr`, registered at `main.rs:762` with
   `syscall_entry_stub`).
2. **arch entry** — `syscall_entry_stub` (`kernel/arch/syscall.rs:1036`, naked asm):
   SWAPGS (GS → per-CPU `SyscallPerCpu`), save user registers to the per-CPU scratch stack,
   nested-syscall detection, fetch kernel RSP0, switch to kernel stack, FXSAVE user FPU,
   STAC (SMAP), then `call syscall_dispatcher_bridge`.
3. **bridge** — `syscall_dispatcher_bridge` (`arch/syscall.rs:977`, `extern "C"`) forwards to
   `kernel_core::syscall::syscall_dispatcher(num, a0..a5)`.
4. **dispatch** — `kernel_core::syscall::syscall_dispatcher`
   (`kernel/kernel_core/syscall.rs:3682`). Security-gate order before the table:
   - timestamp + `increment_counter(SyscallEntry)` (`:3695`)
   - pending-exit (`take_pending_process_exit`) + signal-frame owner binding (`:3703`–`:3740`)
   - **seccomp/pledge filter** — `evaluate_seccomp(syscall_num, &args)` (`:3744`) →
     `Kill`/`Trap`/`Errno`/`Log`/`Allow`
   - **LSM enter** — `lsm::SyscallCtx::from_current` then `lsm::hook_syscall_enter` (`:3878`);
     denial → `audit::emit_lsm_denial` + return EPERM
   - **dispatch table** — `match syscall_num { ... }` (`:3888`) using Linux x86-64 numbers:
     `0→sys_read`, `1→sys_write`, `2→sys_open`, `3→sys_close`, `16→sys_ioctl`,
     `39→sys_getpid`, `56→sys_clone`, `57→sys_fork`, `59→sys_execve`, `60→sys_exit`,
     `231→sys_exit_group`, `257/437→sys_openat(2)` (`:3890`–`:3992`); plus mmap/brk/munmap/
     mprotect, socket/accept/bind/connect/sendto/recvfrom, pipe, etc.
   - **LSM exit** — `lsm::hook_syscall_exit` (`:4230`).
5. **subsystem reach** from the `sys_*` handlers:
   - **VFS** — `sys_read/write/open/close/ioctl` → `vfs` (with `lsm::hook_file_permission`,
     cap checks)
   - **mm** — `sys_mmap`→`lsm::hook_memory_mmap`; `sys_brk`→`hook_memory_brk`; munmap/mprotect
   - **net** — socket syscalls → `net::socket_table()`, wait hooks, netns/cgroup upcalls,
     `lsm::hook_net_accept`
   - **cap** — `current_has_cap_rights(CapRights::*)` gates on audit/trace/setuid;
     `prepare_process_cap_allocation_authorized` under `lsm::hook_task_fork`
   - **seccomp** — pre-dispatch `evaluate_seccomp` + `seccomp::notify_violation`
   - **lsm** — `hook_syscall_enter/exit`, `hook_task_fork/exec/setns/unshare`,
     `hook_memory_*`, `hook_file_permission`, `hook_net_*`, `hook_signal_send`
   - **audit** — `audit::emit`/`emit_lsm_denial` on every security decision
   - **ipc** — `sys_pipe` → `ipc::pipe_create_callback` (cap install + lsm)
   - **sched/kernel_core::process** — `sys_clone/fork/exec/exit` → `kernel_core::fork`,
     `process`, `sched`
6. **Return path:** result → `syscall_dispatcher_bridge` → `syscall_entry_stub` restores FPU
   (FXRSTOR), CLAC, SWAPGS, `SYSRET` to Ring 3.

---

## 6. Core components

### 6.1 Boot & Memory

- **UEFI boot** — the bootloader loads a static-PIE `kernel.elf`, applies
  `R_X86_64_RELATIVE` relocations (with an RDRAND-derived KASLR slide), sets up 4-level
  paging, identity-maps the low region for hardware access, and maps the high-half kernel
  at `0xFFFFFFFF80000000`.
- **Buddy allocator** — reservation-aware physical page allocation: heap/kernel/framebuffer/
  UEFI regions are reserved per-page so they can never collide with the allocator
  (fail-closed on overflow).
- **COW fork** — page-table deep-copy with shared, ref-counted physical frames; fork-time
  cgroup memory charging.
- **Page cache** — global hashed LRU with per-inode indexing, page-state tracking, dirty
  writeback, and reclaim under memory pressure.
- **Guard pages** — unmapped guard pages protect the kernel stack and the double-fault IST
  stack; user stacks carry a permanently-unmapped guard page.
- **OOM killer** — watermark-triggered cache reclaim, per-process scoring, audited
  emergency kill.

### 6.2 Process, Threads & Scheduler

- **PCB** — full per-task state: pid/tgid, priority, CPU affinity, cgroup membership, TLS
  (FS/GS base), seccomp/pledge state, namespace chains, per-task resource limits.
- **fork / exec / clone** — independent address spaces (or shared `MmState` under
  `CLONE_VM`); threads via `CLONE_THREAD` with TLS, `set_tid_address`, and a `robust_list`
  for futex cleanup.
- **Scheduler** — a per-CPU Multi-Level Feedback Queue with starvation detection and
  priority boosting, preemption on timer ticks, work-stealing, periodic load balancing,
  and CPU affinity / cpuset isolation.
- **Wait / exit** — zombie reaping via `wait4`/`waitpid`, `SIGCHLD` to the parent, orphan
  reparenting; cross-CPU deferred termination; a hung-task watchdog heartbeat.

### 6.3 IPC & Signals

- **Pipes** — FIFO buffers with reader/writer ref-counting and signal-interruptible
  blocking I/O.
- **Message queues** — capability-gated endpoints, partitioned per IPC namespace.
- **Futex** — `FUTEX_WAIT`/`FUTEX_WAKE`, plus `FUTEX_LOCK_PI`/`FUTEX_UNLOCK_PI` with
  priority inheritance and per-thread-group bucket budgets.
- **Signals** — 64 POSIX signals, per-task blocked masks and dispositions; synchronous
  handler delivery on the syscall-return path with a SROP-defended `rt_sigframe` builder
  and `rt_sigreturn`; EINTR wake of blocked syscalls.

### 6.4 Security Framework

- **Capabilities** — non-forgeable `CapId` (generation + index), `CapRights` bitflags, a
  per-process `CapTable`, and capability syscalls (allocate / revoke / delegate) gated by
  LSM + audited. Regular files allocate capabilities at open time with rights derived from
  open flags; pipes carry pre-allocated capabilities. *(Full fd-table → capability
  integration ongoing under Phase U.)*
- **LSM** — a pluggable `LsmPolicy` trait with 40+ hook points across syscalls, task
  lifecycle, VFS, memory, IPC, signals, network, and livepatch; the Secure profile
  enforces the `SecureBaselinePolicy` (W^X on mmap/mprotect, kpatch default-deny), while
  Balanced/Performance remain permissive. Denials are fail-closed and audited.
- **Seccomp / Pledge** — a BPF-like filter VM with 18 pledge promises and a fast-allow
  bitmap; a boot-time partition self-test guards against seccomp/dispatch divergence.
- **Audit** — SHA-256 (FIPS 180-4) hash-chained events with an optional HMAC-SHA256 mode,
  bounded ring buffer with overflow tracking, and a cursor-based non-draining export
  interface.
- **Compliance profiles** — Secure / Balanced / Performance, each tuning W^X strictness,
  Spectre mitigations, kptr guard, audit capacity, and log verbosity.

### 6.5 Memory-Safety Hardening

W^X enforcement (no page is both writable and executable), NX on data pages,
SMEP/SMAP/UMIP, KASLR (kernel heap/stack/mmap + text-relocation infrastructure), KPTI dual
page-table isolation, Spectre/Meltdown mitigations (IBRS/IBPB/STIBP/SSBD, RSB stuffing,
SWAPGS+LFENCE), a ChaCha20 CSPRNG seeded from RDRAND/RDSEED, and kernel-pointer
obfuscation (kptr guard).

### 6.6 VFS & Storage

VFS inode abstraction over ramfs, ext2 (read/write, page-cache-backed), procfs
(`/proc/self`, `/proc/[pid]/…`, `/proc/meminfo`), devfs (`/dev/null|zero|console`),
initramfs (CPIO `newc`), and cgroupfs. POSIX DAC (owner/group/other, umask, sticky bit),
`openat2` `RESOLVE_*` flags (`NO_SYMLINKS`/`BENEATH`/`IN_ROOT`/`NO_XDEV`/`NO_MAGICLINKS`),
symlink-loop detection, and per-namespace copy-on-write mount tables. Storage is backed
by a virtio-blk driver (PCI + MMIO) and a BIO request layer.

### 6.7 Network

A software TCP/IP stack: virtio-net driver, DMA-friendly packet buffers, Ethernet/ARP
(anti-spoofing, rate-limited), IPv4 (checksums, source-route rejection, fragment reassembly
with overlap detection), ICMP, and UDP. TCP implements the full state machine and 3-way
handshake, RFC 6298 RTT/RTO with Karn's algorithm, NewReno congestion control, window
scaling, SYN cookies, listen/accept, and graceful close. Above the protocols sit
connection tracking, a stateful priority-ordered firewall (ACCEPT/DROP/REJECT,
default-DROP), and a capability-based socket API with per-hook LSM mediation. Network
namespace TX ownership gates prevent isolated namespaces from egressing on devices they do
not own.

Receive runs as a **bounded process-context ingress loop** rather than in interrupt
context: the scheduler's deferred-work drain polls the registered devices under a
self-throttled ~10 ms window with a fixed frame budget and a fair per-device quantum, so no
single device can starve the others. Buffers come from a statically pre-allocated DMA pool
(32 × 4 KiB) that sits deliberately outside heap admission — provenance is verified at the
pool on free, and each device is capped on the number of buffers it may own. With
completion servicing and replenish wired through the virtio-net driver, the kernel ingests
**real external frames on `eth0`**: the `netns_rx_eth0_slirp` gate drives an ARP probe out
to the QEMU SLIRP gateway and asserts the reply is received and learned. On the transmit
side, an on-link cache miss emits a rate-limited **ARP request probe** (per-namespace ring
and token bucket, with a global bucket drawn only at emission so a device-less namespace
cannot pin the shared budget).

### 6.8 SMP, IOMMU & Concurrency

LAPIC/IOAPIC init, AP bring-up via INIT-SIPI-SIPI (up to 64 CPUs), five IPI types,
IPI-driven TLB shootdown with per-CPU mailboxes, PCID/INVPCID, per-CPU data
(`CpuLocal<T>`), RCU grace-period reclamation, and a documented 9-level lock ordering with
a lockdep checker. The Intel VT-d driver provides DMAR parsing, domain management, DMA
second-level page tables, fault handling, and interrupt remapping (DMAR table discovery
wiring is the remaining boot step).

### 6.9 Containers

Five namespaces — PID (cascade init-kill), mount (CoW tables), IPC (System V), network
(per-NS devices/sockets), and user (UID/GID mapping for unprivileged containers) — driven
by `clone(2)`/`unshare(2)`/`setns(2)`. Cgroups v2 provide CPU (`cpu.weight`/`cpu.max`),
memory (`memory.max`/`memory.high` + OOM events), PIDs, I/O (token-bucket `io.max`), FD,
and port controllers, exposed via syscalls and a `/sys/fs/cgroup` cgroupfs mount, with
subtree delegation.

The network namespace owns a real **per-namespace dataplane**, not just a device list. Each
namespace (root included) holds its own ARP cache, so the same IP may legitimately map to
different MACs in different namespaces and neither can poison the other; the net crate
reaches that state only through a `NetNsDeviceHooks` upcall that hands back the cache
itself, never a namespace handle, and fails closed when the namespace is unknown or already
destroyed. Each namespace also carries its own validated address/gateway/subnet
configuration and derives its own routing decisions (local / on-link / gateway / unroutable,
surfaced to user space as `ENETUNREACH`). Children are born unconfigured and must be
configured explicitly; root delegates to the global config rather than keeping a second
copy that could drift. All of this config state is charged both to a global `NetnsConfig`
heap class and to a **16 KiB per-namespace byte budget**, from which root is deliberately
*not* exempt, so a leak in one namespace's dataplane cannot consume another's.

### 6.10 User Mode & Linux ABI (Phase U / M0)

Ring-3 execution via SYSCALL/SYSRET, **100+ Linux x86-64 syscalls** (113 dispatched), a full
SysV AMD64 `auxv` builder on the initial stack, ELF loading with DoS/corruption guards, `#!`
shebang resolution, path-based `execve` vs. native image-spawn disambiguation, and signal
delivery. The headline milestone: **a genuine statically-linked musl libc binary runs
end-to-end** — crt startup consuming the auxv, musl stdio `printf`→`writev`, and a clean
`exit(0)` — proven by the `musl-check` conformance gate.

> M0 is foundational and intentionally divergent from full Linux: resource limits are
> advisory (not yet enforced on `brk`/`mmap`), there is no dynamic linking
> (`ld.so`/vDSO) or user-space ASLR yet, and `readlink`/`symlink`/`chown` and a few other
> syscalls are deferred. These are tracked under Phase U in the next-phase plan.

---

## 7. Deeper reference

- **[`docs/overview/architecture/ARCHITECTURE.md`](overview/architecture/ARCHITECTURE.md)** —
  the authoritative deep map: the 10-level lock ordering hierarchy, the critical code paths
  (fork / exec / schedule / timer IRQ / page fault), IRQ-context constraints, and the
  historical R166–R172 audit-finding record. *(Note: its status block predates R187/R188;
  see the [security audit status](security-audit-status.md) for current numbers.)*
- **[`docs/overview/02-architecture/subsystems/`](overview/02-architecture/subsystems/)** —
  per-subsystem deep dives (bootloader, arch, memory, scheduler, IPC, kernel-core, VFS,
  networking, security, drivers, LSM/capabilities, observability, cpu-local, userspace,
  kernel-entry).
- **[`docs/review/nextplan/`](review/nextplan/)** — the current prioritized development plan.
