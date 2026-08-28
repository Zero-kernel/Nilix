# Nilix

[英文 (switch to English)](README.md)

一个以安全为先的混合微内核操作系统，使用 Rust 编写，面向 x86_64 架构。

> **Nilix** 是一个递归缩写 —— **N**ilix **I**s **L**inux **I**ndependent e**X**istence
> （“Nilix 是独立于 Linux 的存在”）—— 沿袭 GNU、Linux 的自指命名传统。这个名字也概括了它的定位：
> 与 Linux **兼容**（字节精确的系统调用 ABI 可原样运行真实的 musl libc 程序），却又**独立**于 Linux
> （自有的、从零用 Rust 编写的内核，而非分叉）。

**设计原则：** 安全性 > 正确性 > 效率 > 性能

---

## 什么是 Nilix

Nilix 是一个企业级混合内核，灵感来自 Linux 的模块化设计，并经过 **187 轮持续 R 系列安全审计**，
以及一次于 2026-08-07 开展、并于 2026-08-27 完成修复的独立全代码库审计加固。它将能力与 LSM
门控的内核热路径结合起来，并计划逐步演进为去特权化的 Linux 兼容用户态人格。

## 要点

- **内存安全** —— 完全使用 Rust（`no_std`）编写，配合硬件保护（NX、W^X、SMEP/SMAP/UMIP）以及
  KASLR/KPTI。
- **进程隔离** —— 每进程独立地址空间、写时复制（COW）fork、用户栈守护页。
- **SMP** —— 多核启动（最多 64 核）、每 CPU 的 MLFQ 调度、工作窃取负载均衡、IPI 驱动的 TLB
  shootdown、RCU 与 lockdep。
- **安全框架** —— 对象能力、LSM 钩子层（40+ 钩子点）、seccomp/pledge 系统调用过滤，以及
  SHA-256/HMAC 哈希链的防篡改审计日志。
- **容器** —— 五种命名空间（PID/mount/IPC/net/user）与 cgroups v2（CPU、内存、PID、I/O、FD、
  端口控制器），以及受每命名空间字节预算约束的每命名空间网络数据平面（隔离的 ARP 缓存、地址与路由）。
- **网络** —— 完整的软件 TCP/IP 协议栈（TCP 含 NewReno、窗口缩放、SYN cookies、连接跟踪，以及
  默认 DROP 的有状态防火墙），由有界的进程上下文 RX 入站循环驱动，从 `eth0` 接收真实帧。
- **Linux ABI** —— 字节精确的 x86-64 系统调用面；一个真正的 **静态链接 musl libc 程序可端到端
  运行** 于用户态 ABI 之上（Phase U / 里程碑 M0）。

## 架构一览

Nilix 围绕一条清晰的主执行链路组织：

`Ring 3 → 架构入口 → 策略门 → kernel_core → 内核服务层 → 硬件`

<p align="center">
  <img src="docs/assets/architecture-at-a-glance.svg" alt="Nilix 内核架构图" width="960">
</p>

实线表示主要调用/数据流，虚线表示横向安全与可观测性依赖。图采用均衡网格布局，方便同时查看
所有权边界、`kernel_core` 枢纽，以及跨层传递工作的主要函数。

### 主路径

| 路径 | 主要函数 | 做什么 |
|------|----------|--------|
| 启动与交接 | [`bootloader::efi_main`](bootloader/src/main.rs#L607) → [`kernel::_start`](kernel/src/main.rs#L321) | 加载 PIE 内核、建立分页与 KASLR、发布 `BootInfo*`，再按依赖顺序初始化内核。 |
| 系统调用 ABI | [`arch::syscall_entry_stub`](kernel/arch/syscall.rs#L1036) → [`kernel_core::syscall_dispatcher`](kernel/kernel_core/syscall.rs#L3682) → `sys_*` | 从 `SYSCALL` 进入，依次执行 seccomp/LSM/能力门控，分派 Linux 兼容编号，再经 `SYSRET` 返回。 |
| 进程与内存 | [`fork::sys_fork`](kernel/kernel_core/fork.rs#L155)、[`fork::handle_cow_page_fault`](kernel/kernel_core/fork.rs#L1186)、[`mm::memory::init_with_bootinfo`](kernel/mm/memory.rs#L421) | 建立隔离地址空间、共享 COW 页、计费资源，并在不发布半成品状态的前提下处理缺页。 |
| 中断与调度 | [`sched::enhanced_scheduler::on_clock_tick`](kernel/sched/enhanced_scheduler.rs#L2107) → [`reschedule_now`](kernel/sched/enhanced_scheduler.rs#L2565) → [`arch::context_switch::switch_context`](kernel/arch/context_switch.rs#L235) | 定时器/IPI 事件更新每 CPU MLFQ，选择可运行任务，并在亲和性与安全钩子约束下切换上下文。 |
| 网络接收 | [`net::process_frame`](kernel/net/src/stack.rs#L452) → [`rx_ingress_poll`](kernel/net/src/stack.rs#L3583) | 在进程上下文中有界轮询设备，解析 Ethernet/IP/TCP/UDP，应用 conntrack/防火墙策略并唤醒 socket。 |
| 存储与挂载 | [`vfs::vfs_init`](kernel/vfs/lib.rs#L118) → [`block::probe_devices`](kernel/block/src/lib.rs#L1238) → [`iommu::init`](kernel/iommu/lib.rs#L401) | 启动文件系统根和块设备，经 BIO/virtio 路径发现并挂载存储。 |

<details>
<summary>按子系统查看主要入口函数</summary>

| 区域 | 主要符号 | 职责 |
|------|----------|------|
| 入口 | `bootloader::efi_main`、`kernel::_start`、`arch::syscall_entry_stub` | UEFI 交接、内核启动、寄存器安全的 Ring-3 进出。 |
| 核心 | `kernel_core::syscall_dispatcher`、`sys_fork`、`sys_clone`、`sys_execve`、`sys_exit` | 分派、进程生命周期、ELF 替换、信号、命名空间和 cgroups。 |
| 内存 | `mm::memory::init_with_bootinfo`、`PageTableManager::{map_range, unmap_range}`、`handle_cow_page_fault` | 带准入计费的堆/伙伴分配、页表发布、COW 与回收。 |
| 调度 | `enhanced_scheduler::{init, select_next, on_clock_tick, reschedule_now}` | 每 CPU MLFQ、抢占、工作窃取、亲和性/cpuset 和上下文切换。 |
| VFS 与块设备 | `vfs::vfs_init`、`FileDescriptor::{read, write}`、`block::{init, probe_devices}` | 文件系统操作、页缓存 I/O、BIO 队列和 virtio-blk 发现。 |
| 网络 | `net::{process_frame, rx_ingress_poll}`、`tcp::{handle_ack, handle_retransmission_timeout}` | 有界接收、协议状态机、重传、conntrack 和防火墙决策。 |
| IPC | `ipc::{init, pipe_create_callback, futex_callback}` | 携带能力的管道、带 PI 的 futex 等待/唤醒和可被信号打断的阻塞。 |
| 安全 | `security::init`、`lsm::{hook_syscall_enter, hook_syscall_exit}`、`seccomp::evaluate_current`、`audit::{emit, export}` | 执行 W^X/KPTI 与策略门控，并将安全决策写入哈希链。 |
| 平台 | `arch::{interrupts::init, apic::init, smp::start_aps}`、`iommu::init`、`trace::init` | 中断、SMP/IPI、DMA 隔离、看门狗、追踪和 KCOV 接入。 |

</details>

| 子系统 | 状态 | 要点 |
|-----------|--------|-----------|
| 启动与内存 | ✅ 完成 | UEFI 静态 PIE 启动、高半区映射、预留感知伙伴分配器、页缓存、COW fork、守护页、OOM killer |
| 进程与线程 | ✅ 完成 | 每进程地址空间、fork/exec/clone、线程 + TLS、wait/僵尸回收、挂起任务看门狗 |
| 调度器 | ✅ 完成 | 每 CPU MLFQ、抢占式、工作窃取 + 周期性负载均衡、CPU 亲和性 / cpuset |
| IPC | ✅ 完成 | 管道、基于能力的消息队列、futex（含优先级继承）、POSIX 信号 |
| 安全加固 | ✅ 完成 | W^X/NX、SMEP/SMAP/UMIP、KASLR、KPTI、Spectre/Meltdown 缓解、ChaCha20 CSPRNG（加密安全伪随机数）、kptr 守护 |
| 安全框架 | ✅ 完成 | 能力、LSM（40+ 钩子）、seccomp/pledge、SHA-256/HMAC 哈希链审计、合规配置 |
| VFS 与存储 | ✅ 完成 | ramfs、ext2、procfs、devfs、initramfs（CPIO）、cgroupfs、DAC + openat2 RESOLVE 标志、virtio-blk |
| 网络 | ✅ 完成 | virtio-net、ARP、IPv4（含重组）、ICMP、UDP、TCP、conntrack、有状态防火墙、有界 RX 入站循环与 `eth0` 实时接收 |
| SMP 与并发 | ✅ 完成 | LAPIC/IOAPIC、AP 启动（≤64 核）、IPI TLB shootdown、PCID/INVPCID、RCU、lockdep |
| 容器 | ✅ 完成 | PID/mount/IPC/net/user 命名空间、cgroups v2（6 个控制器）、每命名空间网络数据平面（ARP/地址/路由，受每 NS 字节预算约束） |
| IOMMU / VT-d | 🟡 基础设施 | 完整 Intel VT-d 驱动（DMA 隔离、中断重映射、故障处理）；DMAR 发现接线待完成 |
| 实时补丁 | 🟡 基础设施 | ECDSA P-256 签名的 kpatch、INT3 跳转、失败即关闭的 LSM 门控 |
| 用户模式与 ABI（Phase U / M0） | 🟡 进行中 | Ring 3、100+ Linux 系统调用、SysV auxv、信号投递、静态 musl libc 端到端运行 |
| 模糊测试与测试 | ✅ 完成 | Syzkaller 风格覆盖引导模糊测试已运行 + cargo-fuzz QEMU 集成（13 个目标）、KCOV 每任务覆盖、确定性 guest 端到端测试、扩展稳定性/SMP/安全测试套件 |
| CI 与质量门禁 | ✅ 完成 | GitHub Actions（fmt/clippy、build、lint、boot+musl+fuzz）、自定义 lint 门禁、本地优先且可 SSH 卸载的 pre-push 钩子 |

crate 布局、经验证的分层与依赖 DAG、启动流程、系统调用路径，以及完整的组件叙述详见
**[docs/architecture.md](docs/architecture.md)**。

## 当前状态

**里程碑：** 接近 **1.0-Preview** —— Phase A–G 已完成；**Phase U**（用户态 ABI）进行中。当前
1.0-Preview 发布门禁被一个 HIGH 发现（`R186-4`，VMA/MM 聚合准入）阻塞；零 HIGH 连续记录为
**0/3**。R187（KCOV 修复，2026-08-08）已干净收尾 —— 7 项发现全部修复、8/8 review-fix 缺陷已修复
—— 但未推进连续记录（结转债务而非 R187 发现）。2026-08-07 的一次独立全代码库审计（R188）已于
2026-08-27 完成修复 —— 3 项 HIGH 与 24 项 MEDIUM 发现全部修复，残留
`U37-1`/`U55-6`/`U29-3` 明确保持开放 —— 但作为独立审计它不属于 R 系列轮次，不推进连续记录。
完整细节：**[安全审计状态](docs/security-audit-status.md)** 与 **[CHANGELOG](CHANGELOG.md)**。

## 快速开始

### 前置条件

- Rust **nightly**，带 `rust-src` 与 `llvm-tools-preview`（在 `rust-toolchain.toml` 中固定；目标
  `x86_64-unknown-none` 与 `x86_64-unknown-none-uefi`）
- 带 OVMF 固件的 QEMU（`qemu-system-x86_64`），用于 UEFI 启动
- GNU Make
- `musl-tools`（`musl-gcc`）—— 仅用于 musl 一致性门禁

### 常用命令

```bash
make build           # 将引导程序 + 内核构建到 EFI 系统分区（esp/）
make run             # 在 QEMU 中运行（图形 VGA 窗口）
make run-serial      # 在终端以串口控制台运行
make run-shell       # 构建 + 运行交互式 shell（串口）
make run-blk         # 挂载一个 64 MB 的 ext2 virtio-blk 磁盘
make run-smp         # 多核启动（SMP_CPUS=N，默认 2）
make debug           # 启动 QEMU 并暂停，等待 GDB 连接到 :1234
make clean           # 清理构建产物
```

QEMU 以暴露 `+smep,+smap,+umip,+rdrand` 的 CPU 模型启动，因此 SMEP/SMAP/UMIP 与硬件 RNG
默认即被使用。运行 `make help` 查看完整目标列表。CI、启动/一致性门禁、自定义 lint 与模糊测试
基础设施详见 **[docs/quality-gates.md](docs/quality-gates.md)**。

## 文档

| 目标 | 文档 |
|------|----------|
| 概览与导航 | [docs/README.md](docs/README.md) —— 文档索引 |
| 架构（布局、DAG、启动、系统调用、组件） | [docs/architecture.md](docs/architecture.md) · 深入：[docs/overview/architecture/ARCHITECTURE.md](docs/overview/architecture/ARCHITECTURE.md) |
| CI、测试与模糊测试门禁 | [docs/quality-gates.md](docs/quality-gates.md) · [docs/fuzzing/](docs/fuzzing/) · [docs/testing/](docs/testing/) |
| 安全审计状态 | [docs/security-audit-status.md](docs/security-audit-status.md) · [docs/security/](docs/security/) · [docs/review/audits/](docs/review/audits/) |
| 近期变更 | [CHANGELOG.md](CHANGELOG.md) |
| 路线图 | [docs/roadmap.md](docs/roadmap.md) · [docs/roadmap-enterprise.md](docs/roadmap-enterprise.md) |
| 评审流程 | [docs/review/](docs/review/)（审计、review-fix、下一阶段计划） |

## 贡献指南

社区与维护入口：

- **[CONTRIBUTING.md](CONTRIBUTING.md)** —— 工具链、内核安全不变量、按风险选择的测试、RFC、提交、
  PR 与评审流程。
- **[SUPPORT.md](SUPPORT.md)** —— Bug、提案、性能回归、文档问题和使用问题的提交方式。
- **[SECURITY.md](SECURITY.md)** —— 私密漏洞报告、威胁范围、证据要求与协调披露。
- **[GOVERNANCE.md](GOVERNANCE.md)** —— 角色、决策、评审合并、Issue 生命周期与发布门禁。
- **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** —— 项目社区空间的行为规范。

简而言之：拥有本地 Rust 工具链的贡献者在本地完成构建、lint 与测试——与 CI 完全一致。运行核心门禁，并按风险补充验证（ABI、SMP/并发、存储、模糊
测试、性能和硬件改动分别需要对应证据），架构/信任边界/ABI/依赖/跨子系统实现前先提交 RFC，Bug 与
安全修复应包含回归测试。Git 提交为手动，不会自动提交或自动推送。

## 许可证

许可证条款目前待定。

## 参考资料

- [OSDev Wiki](https://wiki.osdev.org)
- [用 Rust 写操作系统](https://os.phil-opp.com)
- [Linux 内核源码](https://kernel.org)
- [seL4 微内核](https://sel4.systems)
