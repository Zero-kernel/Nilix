# Zero-OS Enterprise Security Kernel Roadmap

**Version:** 3.2
**Last Updated:** 2025-12-23
**Design Principle:** Security > Correctness > Efficiency > Performance

This document extends the Zero-OS development roadmap toward an **enterprise-grade secure server kernel**, with detailed gap analysis against Linux and a security-first implementation plan.

---

## Executive Summary

### Vision

Zero-OS aims to be an enterprise-grade server kernel with:
- **Defense in Depth**: Multiple security layers (Capability, MAC, DAC, Audit)
- **Memory Safety**: Rust + hardware protections (SMAP/SMEP/NX/W^X)
- **Process Isolation**: Strong address space separation with COW
- **Secure IPC**: Capability-based access control for all kernel objects
- **Compliance Ready**: Comprehensive audit logging with tamper evidence

### Current Status (2025-12-23)

| Component | Status | Security Level |
|-----------|--------|----------------|
| Boot & Memory | Complete | Hardened (COW, guard pages, W^X) |
| Process Management | Complete | Isolated (per-process CR3) |
| Thread Support | Complete | Clone syscall, TLS inheritance |
| Scheduler | Complete | Safe (IRQ-safe, MLFQ) |
| IPC (Pipe/MQ/Futex) | Complete | Basic capabilities |
| Signals | Complete | Basic permission checks |
| VFS | Complete | DAC permissions (owner/group/other/umask) |
| Audit | Complete | SHA-256 hash-chained syscall logging |
| User Mode (Ring 3) | Complete | SYSCALL/SYSRET, IRETQ entry |
| Usercopy API | Partial | SMAP guards (STAC/CLAC) - interrupt window issue (R25-10) |
| Spectre/Meltdown | Complete | IBRS/IBPB/STIBP/SSBD/RSB stuffing |
| KASLR/KPTI | Partial | Infrastructure ready, not applied (R25-11) |
| SMP-Ready Stubs | Complete | Per-CPU, IPI, TLB shootdown APIs |
| Capability System | **In Progress** | CapTable in PCB - R25-1 **FIXED**, R25-8 **FIXED** |
| LSM Hooks | **In Progress** | R25-9 **FIXED** (VFS integration), R25-3 pending (audit gaps) |
| Seccomp/Pledge | **In Progress** | R25-4 **FIXED** (Kill terminates), R25-6 **FIXED** (TSYNC required) |
| Network | Not started | - |
| SMP | Not started | - |

**Note**: Round 25 fixes in progress. 6 of 11 issues fixed. See qa-2025-12-23.md for details.

### Security Audit Summary

- **Total Audits**: 25 rounds
- **Issues Identified**: 149
- **Issues Fixed**: 117 (78%)
- **Open Issues**: 32 (5 pending from Round 25)

**Round 25 Status** (2025-12-23):
- R25-4 (CRITICAL): SeccompAction::Kill now terminates process - **FIXED**
- R25-9 (CRITICAL): VFS manager now calls LSM hooks - **FIXED**
- R25-1, R25-6, R25-7, R25-8 (HIGH): **FIXED**
- R25-2, R25-3, R25-5, R25-10, R25-11: Pending

---

## Part I: Gap Analysis vs Linux Kernel

### Quantitative Comparison

| Metric | Linux 6.x | Zero-OS 0.6 | Gap Factor |
|--------|-----------|-------------|------------|
| Lines of Code | ~30M | ~15K | 2000x |
| Syscalls | 450+ | 50 (35 impl) | 13x |
| Drivers | 10M+ LOC | 3 basic | N/A |
| File Systems | 30+ | 2 (ramfs/devfs) | 15x |
| CPU Architectures | 20+ | 1 (x86_64) | 20x |
| Security Modules | LSM/SELinux/AppArmor/SMACK | Basic IPC caps | N/A |
| Container Support | Namespaces/Cgroups v2 | None | Full gap |

### Feature Gap Matrix

| Category | Linux | Zero-OS | Priority |
|----------|-------|---------|----------|
| **SMP/Multi-core** | 256+ CPUs, NUMA | Single-core | High (Phase E) |
| **Security Framework** | LSM + multiple policies | LSM hooks exist but **VFS bypasses** | **Partial** (Phase B fix needed) |
| **Capability System** | POSIX caps (CAP_*) | CapTable exists but **delegation/clone gaps** | **Partial** (Phase B fix needed) |
| **Syscall Filtering** | seccomp-bpf | seccomp exists but **Kill broken, TSYNC missing** | **Partial** (Phase B fix needed) |
| **Namespaces** | pid/mnt/net/ipc/user/cgroup | None | Medium (Phase F) |
| **Cgroups** | v2 unified hierarchy | None | Medium (Phase F) |
| **Network Stack** | Full TCP/IP + netfilter | None | High (Phase D) |
| **Block Layer** | Multi-queue + schedulers | None | High (Phase C) |
| **File Systems** | ext4/xfs/btrfs/zfs/overlay | ramfs/devfs | High (Phase C) |
| **Virtualization** | KVM/QEMU | None | Future |
| **IOMMU** | VT-d/AMD-Vi | None | Medium (Phase F) |
| **Power Management** | ACPI/cpufreq/suspend | None | Low |
| **Hot-plug** | CPU/Memory/Devices | None | Low |

### Security Feature Gap

| Feature | Linux | Zero-OS | Notes |
|---------|-------|---------|-------|
| W^X (NX bit) | Yes | **Yes** | Implemented |
| SMEP | Yes | **Yes** | Enabled at boot |
| SMAP | Yes | **Yes** | Enabled at boot |
| UMIP | Yes | **Yes** | Enabled at boot |
| KASLR | Yes | No | Phase A planned |
| KPTI | Yes | No | Phase A planned |
| Stack Canaries | Yes | Partial | Rust has some |
| Spectre v1 | mitigated | **Yes** | IBRS/IBPB/STIBP |
| Spectre v2 | retpoline/IBRS | **Yes** | RSB stuffing done |
| Meltdown | KPTI | No | Phase A planned |
| seccomp-bpf | Yes | **Yes** | Integrated in dispatcher |
| LSM (SELinux/AppArmor) | Yes | **Yes** | Hooks wired to syscall/VFS |
| Audit subsystem | Yes | **Yes** | Hash-chained |
| Integrity (IMA/EVM) | Yes | No | Phase C planned |

---

## Part II: Threat Model

### Attacker Profiles

| Profile | Goal | Current Mitigation | Gap |
|---------|------|-------------------|-----|
| **Malicious Tenant** | Escape container, access other data | Address space isolation | Namespace/cgroup |
| **Remote Attacker** | Network exploitation | N/A (no network) | Full stack needed |
| **Compromised Process** | Privilege escalation | SMAP/SMEP, Ring 3, LSM | Namespace isolation |
| **Insider** | Data exfiltration | DAC permissions | MAC needed |
| **Supply Chain** | Malicious code | None | Code signing needed |

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                     UNTRUSTED                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ User Apps   │  │ Network     │  │ Storage     │          │
│  │ (Ring 3)    │  │ Packets     │  │ Files       │          │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │
│         │                │                │                  │
│         ▼                ▼                ▼                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              TRUST BOUNDARY: SYSCALL/LSM              │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                    KERNEL SPACE                       │   │
│  │   ┌──────────┐  ┌──────────┐  ┌──────────┐           │   │
│  │   │ Scheduler│  │ VMM      │  │ IPC      │           │   │
│  │   └──────────┘  └──────────┘  └──────────┘           │   │
│  │                       │                               │   │
│  │                       ▼                               │   │
│  │   ┌──────────────────────────────────────────────┐   │   │
│  │   │         TRUST BOUNDARY: HARDWARE              │   │   │
│  │   └──────────────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                    HARDWARE                           │   │
│  │   CPU (Ring 0) │ Memory │ Devices │ Firmware          │   │
│  └──────────────────────────────────────────────────────┘   │
│                        TRUSTED                               │
└─────────────────────────────────────────────────────────────┘
```

### Trust Anchors

- UEFI Secure Boot chain (future)
- Kernel image integrity (future signing)
- Capability-based resource handles (non-forgeable)
- Audit log integrity chain (SHA-256/HMAC planned)
- Hardware RNG (RDRAND/RDSEED)

---

## Part III: Security-First Implementation Plan

### Guiding Principles

1. **Security before features**: Complete security framework before adding network/storage
2. **Defense in depth**: Multiple layers (Capability + MAC + DAC + Audit)
3. **Fail-closed**: Deny by default, explicit allow
4. **Minimal TCB**: Keep kernel small, move complexity to userspace
5. **Audit everything**: All security decisions logged

### Phase Order Rationale

```
Phase A (Security Foundation)
    ↓
Phase B (Capability/MAC Framework) ← Security gate for all features
    ↓
┌───┴───┐
↓       ↓
Phase C (Storage)   Phase D (Network)  ← Can be parallel on single-core
        ↓
Phase E (SMP) ← Performance, not security
    ↓
Phase F (Resource Governance)
    ↓
Phase G (Production Readiness)
```

**Key Decision**: SMP is deferred after storage/network because:
1. Security framework must be complete first (no race conditions in security code)
2. Single-core is sufficient for security testing
3. SMP adds complexity (locks, per-CPU data, TLB shootdown)
4. Storage/network can work on single-core

---

## Part IV: Detailed Phase Specifications

### Phase A: Security Foundation [~80% COMPLETE]

**Duration Estimate**: 2-4 weeks
**Blocking**: All subsequent phases
**Status**: A.1 ✅, A.3 (Spectre) ✅, A.6 ✅ | A.2/A.3(Audit)/A.4 Partial

#### A.1 Usercopy API (Critical) ✅ COMPLETE

**Current State**: Fully implemented with SMAP support
**Location**: kernel/kernel_core/usercopy.rs

```rust
// API specification
pub fn copy_from_user<T: Copy>(dst: &mut T, src: UserPtr<T>) -> Result<(), Errno>;
pub fn copy_to_user<T: Copy>(dst: UserPtr<T>, src: &T) -> Result<(), Errno>;
pub fn copy_from_user_slice(dst: &mut [u8], src: UserPtr<[u8]>) -> Result<usize, Errno>;
pub fn strncpy_from_user(dst: &mut [u8], src: UserPtr<u8>) -> Result<usize, Errno>;

// Must handle:
// - SMAP: stac/clac bracketing
// - Alignment: handle unaligned access
// - Cross-page: validate both pages
// - Length limits: prevent DoS
// - Null termination: for strings
```

**Security Requirements**:
- All user pointer access through this API
- Panic on direct user pointer dereference in kernel
- Audit log on validation failure

#### A.2 Syscall Hardening

**Current State**: ~35 implemented, many return ENOSYS
**Target**: All defined syscalls either implemented or return proper error

| Category | Syscalls | Status |
|----------|----------|--------|
| Process | fork, clone, exec, exit, wait | Implemented |
| Memory | mmap, munmap, mprotect, brk | Implemented |
| File | open, read, write, close, lseek | Implemented |
| IPC | pipe, futex, kill | Implemented |
| Info | getpid, gettid, getppid | Implemented |
| Time | time, sleep | Partial |
| Network | socket, bind, connect... | ENOSYS (Phase D) |

#### A.3 Spectre/Meltdown Hardening ✅ COMPLETE

**Current State**: Complete mitigation suite implemented
**Location**: kernel/security/spectre.rs

| Mitigation | Status | Details |
|------------|--------|---------|
| IBRS | ✅ Done | Enabled if supported via IA32_SPEC_CTRL |
| IBPB | ✅ Done | issue_ibpb()/try_ibpb() on context switch |
| STIBP | ✅ Done | Enabled if supported |
| SSBD | ✅ Done | Enabled if supported |
| RSB stuffing | ✅ Done | rsb_fill() with 32 entries |
| Retpoline | ✅ Done | cfg!(feature = "retpoline") build option |
| KPTI skeleton | ✅ Done | Infrastructure in kaslr.rs |
| SWAPGS fence | ✅ Done | CVE-2019-1125 mitigated in syscall.rs |
| VulnerabilityInfo | ✅ Done | Reads IA32_ARCH_CAPABILITIES MSR |

#### A.4 KASLR/KPTI Preparation

**KASLR Design**:
```
+------------------+
| Randomized Slide | (boot-time, from RDRAND)
+------------------+
| Kernel Text      | 0xffffffff80000000 + slide
+------------------+
| Kernel Data      | Text + text_size + slide
+------------------+
| Kernel Heap      | Fixed (for now)
+------------------+
```

**KPTI Design** (dual page tables):
```
User-mode page table:        Kernel-mode page table:
+------------------+         +------------------+
| User mappings    |         | User mappings    |
+------------------+         +------------------+
| Trampoline only  |    ←→   | Full kernel      |
| (syscall entry)  |         | mappings         |
+------------------+         +------------------+
```

---

### Phase B: Capability & MAC Framework [COMPLETE]

**Duration Estimate**: 4-6 weeks
**Blocking**: Storage and Network phases
**Status**: Integrated into syscall/process/VFS paths

#### B.1 Unified Capability System (Complete - kernel/cap/)

**Current State**: CapTable integrated into PCB with CLOEXEC/CLOFORK semantics
**Location**: kernel/cap/lib.rs, kernel/cap/types.rs

**CapId Structure**:
```
63              32 31              0
+----------------+------------------+
|   Generation   |      Index       |
+----------------+------------------+
```

- **Index**: Slot in per-process CapTable (max 65536)
- **Generation**: Incremented on free, prevents use-after-free

**CapObject Variants**:
```rust
enum CapObject {
    File(Arc<File>),           // VFS file handle
    Directory(Arc<Dir>),       // VFS directory handle
    Socket(Arc<Socket>),       // Network socket
    Endpoint(Arc<Endpoint>),   // IPC endpoint
    Shm(Arc<ShmRegion>),       // Shared memory
    Timer(Arc<Timer>),         // Timer handle
    Process(Pid),              // Process reference
    Thread(Tid),               // Thread reference
    Namespace(NsId),           // Namespace reference
    Cgroup(CgroupId),          // Cgroup reference
}
```

**CapRights Bits**:
```rust
bitflags! {
    pub struct CapRights: u64 {
        // Generic
        const READ       = 1 << 0;   // Read data
        const WRITE      = 1 << 1;   // Write data
        const EXEC       = 1 << 2;   // Execute/map executable
        const IOCTL      = 1 << 3;   // Device control
        const ADMIN      = 1 << 4;   // Administrative operations

        // Memory
        const MAP        = 1 << 5;   // mmap allowed
        const MAP_EXEC   = 1 << 6;   // mmap PROT_EXEC allowed

        // Network
        const BIND       = 1 << 7;   // Bind to address
        const CONNECT    = 1 << 8;   // Connect to remote
        const LISTEN     = 1 << 9;   // Listen for connections
        const ACCEPT     = 1 << 10;  // Accept connections

        // Process
        const SIGNAL     = 1 << 11;  // Send signals
        const WAIT       = 1 << 12;  // Wait for termination
        const PTRACE     = 1 << 13;  // Debug/trace

        // Special
        const BYPASS_DAC = 1 << 30;  // Bypass DAC checks
        const BYPASS_MAC = 1 << 31;  // Bypass MAC checks (root only)
    }
}
```

#### B.2 LSM Hook Infrastructure (Complete - kernel/lsm/)

**Current State**: Hooks wired to syscall dispatcher, process ops, and VFS paths
**Location**: kernel/lsm/lib.rs, kernel/lsm/policy.rs

**Implemented**:
- [x] LsmPolicy trait with all hook methods
- [x] DefaultPolicy (permissive)
- [x] LsmContext wrapper
- [x] Hook registration infrastructure
- [x] Hooks called from syscall_dispatcher (enter/exit)
- [x] Hooks called from fork/clone/exec/exit
- [x] Hooks called from VFS operations (open, create, mkdir, rmdir, unlink)
- [x] Audit integration for denials

**Hook Categories**:

| Category | Hooks |
|----------|-------|
| **Syscall** | enter, exit |
| **Process** | fork, exec, exit, setuid, setgid |
| **File** | lookup, open, create, read, write, mmap, chmod, chown |
| **Directory** | mkdir, rmdir, rename, link, unlink |
| **Mount** | mount, umount, remount |
| **IPC** | mq_send, mq_recv, pipe_create, shm_create |
| **Network** | socket, bind, connect, listen, accept, send, recv |
| **Signal** | kill, ptrace |
| **Namespace** | create, enter, leave |

**Policy Interface**:
```rust
pub trait LsmPolicy: Send + Sync {
    fn name(&self) -> &'static str;
    fn priority(&self) -> u32;  // Lower = earlier

    // Process hooks
    fn task_alloc(&self, task: &Task, clone_flags: CloneFlags) -> Result<()>;
    fn task_free(&self, task: &Task);
    fn cred_prepare(&self, cred: &mut Credentials) -> Result<()>;

    // File hooks
    fn inode_permission(&self, inode: &Inode, mask: Permission) -> Result<()>;
    fn file_open(&self, file: &File) -> Result<()>;
    fn file_mmap(&self, file: &File, prot: Protection) -> Result<()>;

    // IPC hooks
    fn ipc_permission(&self, ipc: &IpcObject, perm: IpcPerm) -> Result<()>;

    // Network hooks
    fn socket_create(&self, family: u16, type_: u16, protocol: u16) -> Result<()>;
    fn socket_connect(&self, sock: &Socket, addr: &SockAddr) -> Result<()>;
    fn socket_bind(&self, sock: &Socket, addr: &SockAddr) -> Result<()>;
}
```

#### B.3 Seccomp/Pledge (Complete - kernel/seccomp/)

**Current State**: Integrated into syscall dispatcher with full lifecycle support
**Location**: kernel/seccomp/lib.rs, kernel/seccomp/types.rs

**Implemented**:
- [x] SeccompFilter structure with rules
- [x] SeccompRule with syscall matching
- [x] SeccompAction enum (Allow/Log/Errno/Trap/Kill)
- [x] PledgePromise enum
- [x] Filter evaluation logic
- [x] evaluate_seccomp called in syscall_dispatcher
- [x] sys_seccomp syscall implemented
- [x] sys_prctl for seccomp modes
- [x] Seccomp state inheritance in fork/clone
- [x] notify_violation audit integration

**Design Options**:
1. **BPF-based** (like Linux seccomp-bpf): Flexible but complex
2. **Pledge-based** (like OpenBSD): Simple, predefined profiles
3. **Hybrid**: Pledge profiles + custom rules

**Recommended**: Pledge-style with extension capability

```rust
pub enum PledgePromise {
    Stdio,      // read, write, close on existing fds
    Rpath,      // read-only file access
    Wpath,      // write file access
    Cpath,      // create/delete files
    Fattr,      // file attribute modification
    Proc,       // fork, exec, wait
    Exec,       // execve
    Net,        // network access
    Unix,       // unix domain sockets
    Inet,       // IPv4/IPv6
    Dns,        // DNS resolution
    Mcast,      // multicast
    Ioctl,      // limited ioctls
    // ... more as needed
}

// Syscall: pledge(promises, execpromises)
// - promises: active promises
// - execpromises: promises after exec (can only reduce)
```

---

### Phase C: Storage Foundation

**Duration Estimate**: 4-6 weeks
**Dependencies**: Phase B complete

#### C.1 Block Layer

**Architecture**:
```
┌─────────────┐
│   VFS       │
└──────┬──────┘
       ↓
┌─────────────┐
│ Page Cache  │ ← Radix tree, per-inode
└──────┬──────┘
       ↓
┌─────────────┐
│ Block Layer │ ← BIO queue, request merging
└──────┬──────┘
       ↓
┌─────────────┐
│ I/O Sched   │ ← FIFO initially, then mq-deadline
└──────┬──────┘
       ↓
┌─────────────┐
│ Driver      │ ← virtio-blk / AHCI
└─────────────┘
```

#### C.2 File Systems

**Priority Order**:
1. **ext2 read-only**: Proven, simple, good for initial testing
2. **tmpfs enhancement**: Already have ramfs, extend with size limits
3. **procfs**: /proc/self, /proc/[pid]/*, /proc/sys
4. **initramfs**: CPIO archive for init

**Permission Chain** (in order):
```
1. MAC (LSM) → Check security labels
2. Capability → Check CapRights
3. DAC → Check uid/gid/mode
4. ACL → Extended permissions (future)
5. Inode Flags → IMMUTABLE, APPEND, NOEXEC
6. W^X → No writable+executable mmap
```

---

### Phase D: Network Foundation

**Duration Estimate**: 6-8 weeks
**Dependencies**: Phase B complete

#### D.1 Stack Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       Socket Layer                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ TCP Socket  │  │ UDP Socket  │  │ Raw Socket  │          │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │
└─────────┼────────────────┼────────────────┼─────────────────┘
          ↓                ↓                ↓
┌─────────────────────────────────────────────────────────────┐
│                     Transport Layer                          │
│  ┌─────────────┐  ┌─────────────┐                           │
│  │    TCP      │  │    UDP      │                           │
│  │ (stateful)  │  │ (stateless) │                           │
│  └──────┬──────┘  └──────┬──────┘                           │
└─────────┼────────────────┼──────────────────────────────────┘
          ↓                ↓
┌─────────────────────────────────────────────────────────────┐
│                      Network Layer                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │    IPv4     │  │   ICMP      │  │  Routing    │          │
│  └──────┬──────┘  └──────┬──────┘  └─────────────┘          │
└─────────┼────────────────┼──────────────────────────────────┘
          ↓                ↓
┌─────────────────────────────────────────────────────────────┐
│                        Netfilter                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │  Conntrack  │  │  Firewall   │  │    NAT      │          │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │
└─────────┼────────────────┼────────────────┼─────────────────┘
          ↓                ↓                ↓
┌─────────────────────────────────────────────────────────────┐
│                       Link Layer                             │
│  ┌─────────────┐  ┌─────────────┐                           │
│  │   Driver    │  │    ARP      │                           │
│  │(virtio/e1000)│  │             │                           │
│  └─────────────┘  └─────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

#### D.2 Security Mechanisms

| Mechanism | Description |
|-----------|-------------|
| **SYN Cookies** | Prevent SYN flood DoS |
| **Conntrack limits** | Per-source connection caps |
| **Rate limiting** | Token bucket per-IP |
| **ISN randomization** | RFC 6528 compliant |
| **Port randomization** | Ephemeral port selection |
| **Source routing disabled** | Drop source-routed packets |
| **Fragment limits** | Maximum fragments, timeout |
| **TTL/hop limit** | Prevent routing loops |

---

### Phase E: SMP & Concurrency

**Duration Estimate**: 6-8 weeks
**Dependencies**: Phase A.6 (SMP-ready interfaces)

#### E.1 Hardware Topology

```
┌─────────────────────────────────────────────────────────────┐
│                          BSP (CPU 0)                         │
│  ┌─────────────┐                                            │
│  │   LAPIC     │ ← Local APIC for each CPU                  │
│  └──────┬──────┘                                            │
│         │                                                    │
│         ↓                                                    │
│  ┌─────────────┐                                            │
│  │   IOAPIC    │ ← Distributes external interrupts          │
│  └──────┬──────┘                                            │
│         │                                                    │
│         ↓                                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │    AP 1     │  │    AP 2     │  │    AP N     │          │
│  │   (CPU 1)   │  │   (CPU 2)   │  │   (CPU N)   │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

#### E.2 Lock Ordering

**Global Lock Order** (acquire in this order, release in reverse):
```
1. irq_disable
2. percpu_lock
3. rcu_read_lock
4. mm_lock (per-process)
5. vfs_inode_lock
6. vfs_dentry_lock
7. file_table_lock
8. socket_lock
9. proc_table_lock
10. sched_lock (per-runqueue)
11. net_route_lock
```

#### E.3 Per-CPU Data

```rust
#[repr(C)]
pub struct PerCpuData {
    // Identity
    pub cpu_id: u32,
    pub lapic_id: u32,

    // Scheduling
    pub current_task: *mut Task,
    pub idle_task: *mut Task,
    pub runqueue: RunQueue,

    // Stacks
    pub kernel_stack_top: usize,
    pub irq_stack_top: usize,
    pub syscall_stack_top: usize,

    // State
    pub preempt_count: u32,
    pub irq_count: u32,
    pub need_resched: bool,

    // Epoch/RCU
    pub rcu_epoch: u64,
    pub rcu_callbacks: CallbackQueue,
}
```

---

### Phase F: Resource Governance

**Duration Estimate**: 4-6 weeks
**Dependencies**: Phase B, C, D

#### F.1 Namespaces

| Namespace | Isolates | Priority |
|-----------|----------|----------|
| **PID** | Process IDs | High |
| **Mount** | Filesystem view | High |
| **Network** | Network stack | High |
| **IPC** | Message queues, semaphores | Medium |
| **User** | UID/GID mapping | Medium |
| **Cgroup** | Cgroup root | Medium |

#### F.2 Cgroups v1.5

**Controllers**:
```
/sys/fs/cgroup/
├── cpu/
│   ├── cpu.shares      # Proportional weight
│   ├── cpu.max         # Quota (max, period)
│   └── cpu.stat        # Usage statistics
├── memory/
│   ├── memory.max      # Hard limit
│   ├── memory.high     # Throttle threshold
│   ├── memory.low      # Protection
│   └── memory.oom.group # OOM together
├── io/
│   ├── io.max          # BPS/IOPS limits
│   └── io.stat         # I/O statistics
└── pids/
    └── pids.max        # Process count limit
```

---

### Phase G: Production Readiness

**Duration Estimate**: 4-6 weeks
**Dependencies**: All previous phases

#### G.1 Observability

| Feature | Description |
|---------|-------------|
| **Tracepoints** | Static instrumentation points |
| **Counters** | Atomic per-CPU counters |
| **Profiler** | Sampling-based CPU profiler |
| **kdump** | Kernel crash dump (encrypted) |
| **Watchdog** | Hardware watchdog integration |
| **Hung task** | Detect stuck processes |

#### G.2 Hardening Profiles

| Profile | Security | Performance | Use Case |
|---------|----------|-------------|----------|
| **Secure** | Maximum | Reduced | Sensitive workloads |
| **Balanced** | Standard | Normal | General purpose |
| **Performance** | Minimal | Maximum | Benchmarks only |

**Secure Profile Settings**:
- KASLR: enabled
- KPTI: enabled
- Spectre mitigations: all
- W^X: enforced
- Audit: all syscalls
- seccomp: default deny
- LSM: enforcing

---

## Part V: Enterprise Parity Roadmap

### Linux Feature Parity Timeline

| Feature | Linux | Zero-OS Phase | Priority |
|---------|-------|---------------|----------|
| Basic syscalls | 6.0 | 0.6 (done) | Done |
| Ring 3 | 2.0 | 0.6 (done) | Done |
| VFS | 0.1 | 0.4 (done) | Done |
| Audit | 2.6 | 0.4 (done) | Done |
| Capabilities | 2.6.24 | B | Critical |
| LSM | 2.6 | B | Critical |
| seccomp | 3.5 | B | Critical |
| ext2 | 0.1 | C | High |
| TCP/IP | 1.0 | D | High |
| SMP | 2.0 | E | Medium |
| Namespaces | 2.6.24+ | F | Medium |
| Cgroups | 2.6.24+ | F | Medium |

### Gap Closure Metrics

| Metric | Current | Phase B | Phase E | 1.0 |
|--------|---------|---------|---------|-----|
| Syscalls impl | 35 | 50 | 80 | 100+ |
| Security features | 4 | 8 | 10 | 12 |
| File systems | 2 | 3 | 5 | 7 |
| Network protocols | 0 | 0 | 4 | 6 |
| Container support | 0% | 0% | 50% | 80% |

---

## Appendix A: Security Audit History

| Round | Date | Focus | Issues | Fixed |
|-------|------|-------|--------|-------|
| 1-3 | 2025-12-09 | Initial baseline | 25 | 24 |
| 4-7 | 2025-12-10 | Preemption, COW | 22 | 21 |
| 8-13 | 2025-12-11 | IPC, signals | 23 | 19 |
| 16-19 | 2025-12-15/16 | VFS, W^X | 11 | 10 |
| 20-22 | 2025-12-17/18 | Ring 3, SYSCALL | 29 | 19 |
| 23-24 | 2025-12-20 | Thread, TLS | 12 | 12 |
| **Total** | - | - | **138** | **111 (80%)** |

## Appendix B: Code Statistics

| Module | LOC | Files | Description |
|--------|-----|-------|-------------|
| kernel_core | ~4000 | 8 | Process, syscall, ELF |
| sched | ~1500 | 4 | Scheduler, MLFQ |
| mm | ~2000 | 4 | Memory, page table |
| arch | ~2000 | 6 | x86_64, interrupts |
| ipc | ~1500 | 5 | Pipe, futex, signals |
| vfs | ~1500 | 6 | VFS, ramfs, devfs |
| drivers | ~800 | 4 | VGA, serial, keyboard |
| security | ~500 | 2 | Hardening, RNG |
| audit | ~800 | 1 | SHA-256 hash-chained events |
| **Total** | **~15000** | **40+** | - |

---

*This enterprise roadmap is a living document, updated as the project evolves toward production-grade security. The security-first approach ensures that every feature added is built on a solid, audited foundation.*
