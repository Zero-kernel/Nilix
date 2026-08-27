# Nilix

[Switch to English (切换到英文)](README.md)

一个以安全为先的混合微内核操作系统，使用 Rust 编写，面向 x86_64 架构。

> **Nilix** 是一个递归缩写 —— **N**ilix **I**s **L**inux **I**ndependent e**X**istence（“Nilix 是独立于 Linux 的存在”）—— 沿袭 GNU、Linux 的自指命名传统。这个名字也概括了它的定位：与 Linux **兼容**（字节精确的系统调用 ABI 可原样运行真实的 musl libc 程序），却又**独立**于 Linux（自有的、从零用 Rust 编写的内核，而非分叉）。

**设计原则：** 安全性 > 正确性 > 效率 > 性能

---

## 1. 概述

Nilix 是一个企业级混合内核，灵感来自 Linux 的模块化设计，并经过 **186 轮持续安全审计**
加固。它将能力（capability）与 LSM 门控的内核内热路径相结合，并规划演进为一个去特权化的
Linux 兼容用户态人格（personality）。

- **内存安全** —— 完全使用 Rust（`no_std`）编写，配合硬件保护（NX、W^X、SMEP/SMAP/UMIP）
  以及 KASLR/KPTI。
- **进程隔离** —— 每进程独立地址空间、写时复制（COW）fork、用户栈守护页。
- **SMP** —— 多核启动（最多 64 核）、每 CPU 的 MLFQ 调度、工作窃取负载均衡、IPI 驱动的
  TLB shootdown、RCU 与 lockdep。
- **安全框架** —— 对象能力、LSM 钩子层（40+ 钩子点）、seccomp/pledge 系统调用过滤，以及
  SHA-256 哈希链的防篡改审计日志。
- **容器** —— 五种命名空间（PID/mount/IPC/net/user）与 cgroups v2（CPU、内存、PID、I/O、
  FD、端口控制器）。
- **网络** —— 完整的软件 TCP/IP 协议栈（TCP 含 NewReno、窗口缩放、SYN cookies、连接跟踪，
  以及默认 DROP 的有状态防火墙）。
- **Linux ABI** —— 字节精确的 x86-64 系统调用面；一个真正的 **静态链接 musl libc 程序可端到端
  运行** 于用户态 ABI 之上（Phase U / 里程碑 M0）。

### 当前状态

**里程碑：** 接近 **1.0-Preview** —— Phase A–G 已完成；**Phase U**（用户态 ABI）进行中。
当前 1.0-Preview 发布门禁被一个 HIGH 发现（`R186-4`，VMA/MM 聚合准入）及其设计父项阻塞，
零 HIGH 连续记录为 **0/3**；R186 的其余可执行发现均已修复，并已完成 review-fix 复核。
R187（KCOV 修复）已干净收尾 —— 7 项发现全部修复、8/8 review-fix 缺陷已修复 —— 但未推进
连续记录，因为 `R186-4` 是结转债务而非 R187 发现。2026-08-07 的一次独立全代码库审计
（R188）已于 2026-08-27 完成修复 —— 3 项 HIGH 与 24 项 MEDIUM 发现全部修复，残留
U37-1/U55-6/U29-3 明确保持开放 —— 但作为独立审计它不属于 R 系列轮次，不推进连续记录。
详见[第 6 节](#6-安全审计状态)。

**最近新增：**
- **2026-08-27：** **R188 独立全代码库审计修复** —— 对整棵树的一次自顶向下对抗式审计
  （2026-08-07）在一轮内完成修复：3 项 HIGH 发现（cgroup 端口反记账 `U06-1`、信号交付
  RFLAGS 净化器 + PCB 锁生命周期 + 发送者身份 `U09-1/2/3`、robust-futex 拆除 `U34-1`）与
  全部 24 项 MEDIUM 发现均已修复，并覆盖所有可实现的 LOW/关联集合。覆盖范围包括命名空间
  准入/授权、VFS inode 所有权与边界、boot/UEFI/ELF/virtio/IOMMU/PCID/TLB 的发布构建边界
  检查、audit/compliance/crypto/LSM/livepatch 完整性、分配器诊断、调度器与 TLB 契约、
  键盘/启动加固、运行时测试注册表，以及用户态模糊测试工具链。残留设计工作
  （`U37-1` KPTI/双 CR3、`U55-6` 早期启动 W+X 转换、`U29-3` VM 透传生命周期）明确保持开放，
  不计入已修复。这是*独立*审计，不属于 R 系列轮次，因此零 HIGH 连续记录保持 **0/3**，门禁
  仍因结转的 `R186-4` 阻塞。所有远程门禁通过：`make build`/`lint`/`test`（34 通过 / 39 延后 /
  0 失败）与 239 项主机子 crate 测试。详见[第 6 节](#6-安全审计状态)。
- **2026-08-08：** **R187 KCOV 修复 + ReviewFix 闭环** —— 从授权、准入上下文与拓扑三个维度
  加固 KCOV 可观测面，使覆盖率*度量*准确且失败即关闭：(1) KCOV 授权改为**仅宿主 root** —— 保留的
  `CapRights::KCOV` 位不再授权访问，待评审通过的身份绑定发放协议后再开放；(2) 无分配的 IRQ-return
  **软进度守护**使延迟回调排空路径上的 KCOV 准入失败即关闭，并拒绝递归重入；(3) CPU 在线拓扑统一到
  唯一权威的 `cpu_local` 掩码（TLB/IPI/调度器/KCOV 均读取它），带双向 LAPIC 校验与幂等发布；(4) 模糊器
  ABI 报告**已占用的 KCOV 位图槽位**（而非源边）并限制 KCOV 控制重试次数。ReviewFix 闭环验证 7/7 修复
  PASS、8/8 review-fix 缺陷已修复（0 项升级）；远程 fmt/clippy/build/lint/test/boot/musl 门禁全绿。
  门禁仍因结转的 `R186-4` 而阻塞。详见[第 6 节](#6-安全审计状态)。
- **2026-08-05：** **Cargo-fuzz QEMU 集成** — 使用 cargo-fuzz 目标对真实 KCOV 启用的内核进行
  系统调用执行的模糊测试基础设施扩展。新组件：(1) `fuzz_syscall_qemu` 目标，具有惰性 QEMU 执行器
  初始化与安全系统调用白名单（19 个系统调用）；(2) 桥接模块（`syz_bridge.rs`），与独立的
  `nilix-syz-fuzzer` 二进制文件对接；(3) QEMU 执行器桩（`qemu_executor.rs`），可供复制；
  (4) Makefile 集成（`make fuzz-qemu-smoke`、`make fuzz-qemu-campaign`、并行/通宵目标）；
  (5) 特性门控编译（`qemu-executor`）；(6) 文档更新（fuzz/README.md、FUZZING_SUMMARY.md）。
  架构同时提供基于 mock 的快速迭代（50K 执行/秒）与基于 QEMU 的深度测试（5-10 执行/秒，真实 KCOV）。
  三个新模糊测试目标：伙伴分配器、页表操作、系统调用执行。详见[第 5.5 节](#55-模糊测试基础设施)。
- **2026-08-04：** **Phase 7 Syzkaller 风格模糊测试完成** — 宿主驱动的覆盖引导模糊测试基础设施
  现已可运行。已构建并集成：(1) 基于 Rust 的宿主模糊器，具有 5 种变异策略、基于能量的语料库
  调度及崩溃分类；(2) 基于 C 的 guest 执行器，在 QEMU 中运行并集成 KCOV；(3) GitHub Actions CI
  工作流，每周定时运行并缓存语料库；(4) 600+ 行系统调用语法（`.syz` 格式），覆盖 40+ 系统调用；
  (5) Makefile 目标（`make run-syz-fuzz`、`make test-syz`）；(6) 2,800+ 行综合文档。性能：
  5-10 执行/秒，50-200 新边/小时（早期阶段）。详见[第 5.5 节](#55-模糊测试基础设施)。
- **2026-08-03：** R186-4 HIGH 修复完成 — 通过 `AdmittedMap` 迁移实现 VMA/MM 元数据准入。
  **2 项 PASS / 12 项 PARTIAL / 2 项 FAIL**。全部 **24 项 review-fix 缺陷**
  （`RF186-1`…`RF186-24`）均已修复，**0 项升级**；源码/测试评审者与
  RF186-20..24 独立安全评审者均给出 **SAFE**。
  `R186-18` 已完全修复并通过复核。唯一开放的可执行发现仍是 `R186-4`
  （HIGH），因此 1.0-Preview 仍被该项及
  `D1-RES-HEAP-ADMISSION-REOPENED` 阻塞，零 HIGH 连续记录仍为 **0/3**。
  聚焦/默认并行测试与最终远程门禁均为绿色：net 110/110、conntrack 压力 50/50、
  `make test` 31/39/0，boot/musl 均通过。
- **2026-07-28：** R186 修复轮次 —— 17 个可执行发现中 16 个已完全修复、1 个仍开放。
  已落地修复包括：消除 open/openat 发布死锁、使 netns/VFS 分配路径可失败恢复、在关闭设备
  解码器时原子测量 BAR 并校验 VirtIO PCI capability 窗口、拒绝无效 ext2 inode/块所有权别名、
  为 `SYN_SENT` 提供终止超时所有者、区分可重试 COW 竞争、在线程间共享凭证代际，以及修正
  审计/能力报告真实性。
  默认门禁结果为 **31 通过 / 39 延后 / 0 失败**。
- **2026-07-27：** D3 PENDING-FRAME v2 —— on-link ARP 未命中时暂存数据帧，学习到邻居后重传，
  从而退役网关回退交付路径；每缓存使用 8 槽 FIFO、3 秒 TTL，并在所有权门禁后进行探测准入。
- **2026-07-25：** D3 网络命名空间数据平面 —— 每命名空间 ARP 缓存、地址配置与路由，全部计入
  每命名空间字节预算；有界的进程上下文 RX 入站轮询循环；外部设备 RX 完成路径（内核现已能在
  `eth0` 上接收真实外部帧）；以及 ARP 请求探测发送。新增 11 个 `netns_*` 启动测试，使内核内
  测试套件达到 **30 通过 / 39 延后 / 0 失败**。详见[第 3.9 节](#39-容器)。
- **2026-07-24：** R184 review-fix 轮次 —— 修复 R183 后续评审的 4 项发现：无分配的
  clear_child_tid 校验（RF184-1）、openat2 中的能力分配原子性（RF184-2）、TX 内存预算记账修正
  （RF184-3），以及 handle_ack 前置条件契约的文档化（RF184-7）。
- **2026-07-23：** U.S2 SLICE-3B 能力基础设施 —— FileOps trait 添加 cap_id/set_cap_id 方法，
  通过 spin::once::Once 实现内部可变性，系统调用层为常规文件分配能力，以及 VFS 打开期间的
  凭证生成 TOCTOU 防御。
- **2026-07-21（历史记录）：** KCOV 原语、模糊测试架构原型和首版 CI 集成落地。后来已撤回
  “生产就绪的持续模糊测试”这一说法：当时的 worker 只是流水线模拟器，并未执行内核输入。
  当前状态详见[第 5.5 节](#55-模糊测试基础设施)。

| 子系统                         | 状态        | 要点                                                                                            |
| 启动与内存                     | ✅ 完成     | UEFI 静态 PIE 启动、高半区映射、预留感知伙伴分配器、页缓存、COW fork、守护页、OOM killer        |
| 进程与线程                     | ✅ 完成     | 每进程地址空间、fork/exec/clone、线程 + TLS、wait/僵尸回收、挂起任务看门狗                      |
| 调度器                         | ✅ 完成     | 每 CPU MLFQ、抢占式、工作窃取 + 周期性负载均衡、CPU 亲和性 / cpuset                             |
| IPC                            | ✅ 完成     | 管道、基于能力的消息队列、futex（含优先级继承）、POSIX 信号                                     |
| 安全加固                       | ✅ 完成     | W^X/NX、SMEP/SMAP/UMIP、KASLR、KPTI、Spectre/Meltdown 缓解、ChaCha20 CSPRNG、kptr 守护          |
| 安全框架                       | ✅ 完成     | 能力、LSM（40+ 钩子）、seccomp/pledge、SHA-256/HMAC 哈希链审计、合规配置                        |
| VFS 与存储                     | ✅ 完成     | ramfs、ext2、procfs、devfs、initramfs（CPIO）、cgroupfs、DAC + openat2 RESOLVE 标志、virtio-blk |
| 网络                           | ✅ 完成     | virtio-net、ARP、IPv4（含重组）、ICMP、UDP、TCP、conntrack、有状态防火墙、有界 RX 入站循环与 `eth0` 实时接收 |
| SMP 与并发                     | ✅ 完成     | LAPIC/IOAPIC、AP 启动（≤64 核）、IPI TLB shootdown、PCID/INVPCID、RCU、lockdep                 |
| 容器                           | ✅ 完成     | PID/mount/IPC/net/user 命名空间、cgroups v2（6 个控制器）、每命名空间网络数据平面（ARP/地址/路由，受每 NS 字节预算约束） |
| IOMMU / VT-d                   | 🟡 基础设施 | 完整 Intel VT-d 驱动（DMA 隔离、中断重映射、故障处理）；DMAR 发现接线待完成                     |
| 实时补丁                       | 🟡 基础设施 | ECDSA P-256 签名的 kpatch、INT3 detour、fail-closed 的 LSM 门控                                 |
| 用户模式与 ABI（Phase U / M0） | 🟡 进行中   | Ring 3、100+ Linux 系统调用、SysV auxv、信号投递、静态 musl libc 端到端运行                     |
| 模糊测试与测试                 | ✅ 完成     | **Syzkaller 风格覆盖引导模糊测试已运行**：宿主驱动的变异引擎、QEMU 执行器、KCOV 集成、带语料库缓存的 CI 工作流、5 种变异策略、崩溃分类。**Cargo-fuzz QEMU 集成**：`fuzz_syscall_qemu` 目标与独立模糊器桥接，mock（50K 执行/秒）+ QEMU（5-10 执行/秒）双路径，共 13 个目标（伙伴分配器、页表、系统调用、解析器）。KCOV 每任务覆盖、确定性 guest E2E、扩展稳定性/SMP/安全测试套件 |
| CI 与质量门禁                  | ✅ 完成     | GitHub Actions（fmt/clippy、build、lint、boot+musl+fuzz）、自定义 lint 门禁、本地优先且可 SSH 卸载的 pre-push 钩子      |

---

## 2. 项目结构

内核是一个由若干聚焦 crate（`kernel/<子系统>/`）组成的 Cargo workspace，每个 crate 负责单一
关注点。引导加载程序与用户态程序是独立的构建单元。

```text
Nilix/
├── bootloader/             # UEFI 引导：ELF 加载、重定位（PIE）、高半区分页、KASLR 偏移
├── kernel/
│   ├── arch/               # x86_64：IDT/异常、上下文切换、SYSCALL/SYSRET、GDT/TSS、APIC、SMP、IPI、INVPCID
│   ├── mm/                 # 伙伴分配器、堆、页表、页缓存、TLB shootdown、OOM killer、fallible_map
│   ├── sched/              # 每 CPU MLFQ 调度器 + 文档化的锁顺序（lockdep）
│   ├── ipc/                # 管道、基于能力的消息队列、futex（含 PI）、WaitQueue/KMutex/Semaphore
│   ├── kernel_core/        # PCB 与进程表、fork（COW）、exec + ELF 加载器、信号、命名空间、cgroups、RCU、系统调用
│   ├── cap/                # 对象能力模型（CapId、CapRights、CapTable）
│   ├── lsm/                # Linux 安全模块钩子层 + 策略
│   ├── seccomp/            # seccomp/pledge 系统调用过滤（类 BPF 虚拟机）
│   ├── audit/              # SHA-256 / HMAC 哈希链防篡改审计日志
│   ├── crypto/             # 共享 no_std 加密（SHA-256、ECDSA P-256），供审计 + 实时补丁使用
│   ├── compliance/         # 加固配置（Secure / Balanced / Performance）
│   ├── security/           # W^X、NX、KASLR、KPTI、Spectre/Meltdown、kptr 守护、RNG、内存加固
│   ├── vfs/                # VFS 核心、ramfs、ext2、procfs、devfs、initramfs、cgroupfs、挂载命名空间
│   ├── block/              # 块层 + virtio-blk 驱动（PCI/MMIO）、BIO 队列
│   ├── virtio/             # 共享 VirtIO 传输（virtqueue）
│   ├── net/                # TCP/IP 栈：virtio-net、ARP、IPv4、ICMP、UDP、TCP、conntrack、防火墙、套接字
│   ├── iommu/              # Intel VT-d：DMAR 解析、域、故障处理、中断重映射
│   ├── cpu_local/          # 每 CPU 数据（CpuLocal<T>）、LAPIC-ID ↔ CPU 索引映射
│   ├── tlb_ops/            # PCID / INVPCID TLB 失效原语
│   ├── livepatch/          # 签名的实时内核补丁（kpatch 风格）
│   ├── trace/              # 静态 tracepoint、每 CPU 计数器、挂起任务看门狗
│   ├── klog/               # 配置感知的内核日志（klog!/klog_force!/kprintln!）
│   ├── drivers/            # VGA / 串口（UART 16550）/ PS-2 键盘
│   ├── src/                # 内核入口（main.rs）、运行时测试、Ring-3 启动诊断
│   └── kernel.ld           # 链接脚本
├── userspace/              # Ring-3 程序：shell、syscall_test、hello_musl.c（静态 musl）、压力测试器、syzkaller 模糊器
│   ├── nilix-syz-fuzzer/   # 宿主驱动的覆盖引导模糊器（Rust）：变异引擎、语料库管理器、QEMU 执行器
│   ├── nilix_syz_executor.c # Guest 执行器：反序列化程序、执行系统调用、收集 KCOV 覆盖
│   ├── stress_runner.c     # 基础压力测试：5 个阶段（内存、CPU、进程、文件、组合）
│   └── stress_runner_advanced.c # 安全压力测试：权限边界、并发、资源耗尽
├── fuzz/                   # Cargo-fuzz 解析器目标
├── docs/fuzzing/           # 模糊测试文档：Phase 7 实现、快速入门、系统调用语法（.syz）
├── scripts/                # CI 门禁脚本：boot_check.sh、musl_check.sh、smp_check.sh、iommu_check.sh…
├── docs/                   # roadmap.md、roadmap-enterprise.md、next-phase-plan.md、review/（QA 报告）
├── .github/workflows/ci.yml  # GitHub Actions 流水线
├── .githooks/pre-push      # 本地优先的 fmt + clippy 门禁（可选 SSH 卸载）
└── Makefile                # 构建 / 运行 / lint / 门禁 目标
```

---

## 3. 核心组件

### 3.1 启动与内存

- **UEFI 启动** —— 引导程序加载静态 PIE 的 `kernel.elf`，应用 `R_X86_64_RELATIVE` 重定位
  （配合 RDRAND 生成的 KASLR 偏移），建立 4 级分页，恒等映射低地址区供硬件访问，并将高半区
  内核映射到 `0xFFFFFFFF80000000`。
- **伙伴分配器** —— 预留感知的物理页分配：堆/内核/帧缓冲/UEFI 区域按页预留，永不与分配器
  冲突（溢出时 fail-closed）。
- **COW fork** —— 页表深拷贝，共享带引用计数的物理帧；fork 时进行 cgroup 内存计费。
- **页缓存** —— 全局哈希 LRU + 每 inode 索引、页状态跟踪、脏页回写，内存压力下回收。
- **守护页** —— 未映射的守护页保护内核栈与双重故障 IST 栈；用户栈带一个永久未映射的守护页。
- **OOM killer** —— 水位触发的缓存回收、每进程评分、带审计的紧急杀进程。

### 3.2 进程、线程与调度器

- **PCB** —— 完整的每任务状态：pid/tgid、优先级、CPU 亲和性、cgroup 成员、TLS（FS/GS base）、
  seccomp/pledge 状态、命名空间链、每任务资源限制。
- **fork / exec / clone** —— 独立地址空间（或 `CLONE_VM` 下共享的 `MmState`）；线程经
  `CLONE_THREAD` 携带 TLS、`set_tid_address`，以及用于退出时 futex 清理的 `robust_list`。
- **调度器** —— 每 CPU 的多级反馈队列，含饥饿检测与优先级提升、时钟节拍抢占、工作窃取、
  周期性负载均衡，以及 CPU 亲和性 / cpuset 隔离。
- **wait / exit** —— 经 `wait4`/`waitpid` 回收僵尸、向父进程投递 `SIGCHLD`、孤儿重新归属；
  跨 CPU 延迟终止；挂起任务看门狗心跳。

### 3.3 IPC 与信号

- **管道** —— FIFO 缓冲、读写端引用计数、信号可中断的阻塞 I/O。
- **消息队列** —— 基于能力的端点，按 IPC 命名空间分区。
- **Futex** —— `FUTEX_WAIT`/`FUTEX_WAKE`，以及带优先级继承的 `FUTEX_LOCK_PI`/`FUTEX_UNLOCK_PI`
  和每线程组的 bucket 预算。
- **信号** —— 64 个 POSIX 信号、每任务的阻塞掩码与处置；在系统调用返回路径上同步投递处理函数，
  配合具备 SROP 防御的 `rt_sigframe` 构造器与 `rt_sigreturn`；阻塞的系统调用 EINTR 唤醒。

### 3.4 安全框架

- **能力（Capabilities）** —— 不可伪造的 `CapId`（代际 + 索引）、`CapRights` 位标志、每进程的
  `CapTable`，以及由 LSM 门控并审计的能力系统调用（分配 / 撤销 / 委派）。*（fd 表 → 能力的
  整合仍在进行中；文件描述符访问目前仍是环境式的。）*
- **LSM** —— 可插拔的 `LsmPolicy` trait，40+ 钩子点遍布系统调用、任务生命周期、VFS、内存、
  IPC、信号、网络与实时补丁；默认策略为放行，并支持全拒绝及自定义策略。拒绝为 fail-closed
  并审计。
- **Seccomp / Pledge** —— 类 BPF 过滤虚拟机，18 个 pledge promise 与快速放行位图；启动期分区
  自检防止 seccomp/分派出现分歧。
- **审计** —— SHA-256（FIPS 180-4）哈希链事件，可选 HMAC-SHA256 模式；带溢出跟踪的有界环形
  缓冲；基于游标、不消费的导出接口。
- **合规配置** —— Secure / Balanced / Performance，各自调节 W^X 严格度、Spectre 缓解、kptr
  守护、审计容量与日志详细度。

### 3.5 内存安全加固

W^X 强制（没有页面同时可写且可执行）、数据页 NX、SMEP/SMAP/UMIP、KASLR（内核堆/栈/mmap +
text 重定位基础设施）、KPTI 双页表隔离、Spectre/Meltdown 缓解（IBRS/IBPB/STIBP/SSBD、RSB
填充、SWAPGS+LFENCE）、由 RDRAND/RDSEED 播种的 ChaCha20 CSPRNG，以及内核指针混淆（kptr 守护）。

### 3.6 VFS 与存储

VFS inode 抽象之上有 ramfs、ext2（读/写，页缓存支持）、procfs（`/proc/self`、
`/proc/[pid]/…`、`/proc/meminfo`）、devfs（`/dev/null|zero|console`）、initramfs（CPIO
`newc`）与 cgroupfs。POSIX DAC（owner/group/other、umask、粘滞位）、`openat2` 的 `RESOLVE_*`
标志（`NO_SYMLINKS`/`BENEATH`/`IN_ROOT`/`NO_XDEV`/`NO_MAGICLINKS`）、符号链接循环检测，以及
每命名空间的写时复制挂载表。存储由 virtio-blk 驱动（PCI + MMIO）和 BIO 请求层支撑。

### 3.7 网络

软件 TCP/IP 栈：virtio-net 驱动、DMA 友好的数据包缓冲、Ethernet/ARP（反欺骗、限速）、IPv4
（校验和、源路由拒绝、带重叠检测的分片重组）、ICMP 与 UDP。TCP 实现完整状态机与三次握手、
RFC 6298 RTT/RTO（含 Karn 算法）、NewReno 拥塞控制、窗口缩放、SYN cookies、listen/accept 与
优雅关闭。协议之上是连接跟踪、优先级有序的有状态防火墙（ACCEPT/DROP/REJECT、默认 DROP），
以及带逐钩子 LSM 仲裁的基于能力的套接字 API。网络命名空间的 TX 归属门禁阻止被隔离的命名空间
从其并不拥有的设备上发包。

接收路径运行为**有界的进程上下文入站循环**，而非中断上下文：调度器的延迟工作 drain 点在一个
自限流的 ~10 ms 窗口内轮询已注册设备，配有固定的帧预算与公平的每设备配额，因此任何单个设备
都无法饿死其它设备。缓冲区来自静态预分配的 DMA 池（32 × 4 KiB），该池刻意置于堆准入之外 ——
归属在释放时由池自身校验，且每个设备可持有的缓冲区数量设有上限。随着完成处理与补充逻辑接入
virtio-net 驱动，内核已能在 **`eth0` 上接收真实外部帧**：`netns_rx_eth0_slirp` 门禁向 QEMU
SLIRP 网关发出 ARP 探测，并断言回复被接收并学习。在发送侧，on-link 缓存未命中现在会发出限速的
**ARP 请求探测**（每命名空间的环形缓冲与令牌桶；全局令牌桶仅在真正发射时扣减，因此一个没有
设备的命名空间无法长期占死共享预算）。

### 3.8 SMP、IOMMU 与并发

LAPIC/IOAPIC 初始化、经 INIT-SIPI-SIPI 的 AP 启动（最多 64 核）、五种 IPI 类型、带每 CPU
邮箱的 IPI 驱动 TLB shootdown、PCID/INVPCID、每 CPU 数据（`CpuLocal<T>`）、RCU 宽限期回收，
以及带 lockdep 检查器的文档化 9 级锁顺序。Intel VT-d 驱动提供 DMAR 解析、域管理、DMA 二级页表、
故障处理与中断重映射（DMAR 表发现的接线是剩余的启动步骤）。

### 3.9 容器

五种命名空间 —— PID（init 级联杀）、mount（CoW 表）、IPC（System V）、network（每命名空间
设备/套接字）、user（供非特权容器的 UID/GID 映射）—— 由 `clone(2)`/`unshare(2)`/`setns(2)`
驱动。Cgroups v2 提供 CPU（`cpu.weight`/`cpu.max`）、内存（`memory.max`/`memory.high` + OOM
事件）、PID、I/O（令牌桶 `io.max`）、FD 与端口控制器，经由系统调用与 `/sys/fs/cgroup`
cgroupfs 挂载暴露，并支持子树委派。

网络命名空间拥有真正的**每命名空间数据平面**，而不只是一份设备清单。每个命名空间（含 root）
持有自己的 ARP 缓存，因此同一个 IP 在不同命名空间中可以合法地映射到不同的 MAC，且彼此无法
投毒；net crate 只能通过 `NetNsDeviceHooks` 上调触达该状态，上调返回的是缓存本身而非命名空间
句柄，并在命名空间未知或已销毁时 fail-closed。每个命名空间还持有各自经过校验的
地址/网关/子网配置，并据此做出自己的路由判定（local / on-link / gateway / unroutable，向用户态
呈现为 `ENETUNREACH`）。子命名空间创建时处于未配置状态，必须显式配置；root 则委派给全局配置，
而不是保留可能与之漂移的第二份副本。所有这些配置状态同时计入全局 `NetnsConfig` 堆类别与
**16 KiB 的每命名空间字节预算**（root 刻意不豁免），因此某个命名空间数据平面的泄漏不会侵占
其它命名空间的额度。

### 3.10 用户模式与 Linux ABI（Phase U / M0）

经 SYSCALL/SYSRET 的 Ring-3 执行、**100+ Linux x86-64 系统调用**（113 个已分派）、初始栈上完整的
SysV AMD64 `auxv` 构造、带 DoS/损坏防护的 ELF 加载、`#!` shebang 解析、基于路径的 `execve` 与
原生镜像 spawn 的消歧，以及信号投递。标志性里程碑：**一个真正的静态链接 musl libc 程序可端到端
运行** —— crt 启动消费 auxv、musl stdio 的 `printf`→`writev`，以及干净的 `exit(0)` —— 由
`musl-check` 一致性门禁证明。

> M0 是基础性的，且有意与完整 Linux 存在差异：资源限制为建议性（尚未在 `brk`/`mmap` 上强制
> 执行），尚无动态链接（`ld.so`/vDSO）或用户态 ASLR，且 `readlink`/`symlink`/`chown` 等少数
> 系统调用被推迟。这些都在 `docs/next-phase-plan.md` 的 Phase U 中跟踪。

---

## 4. 构建与运行

### 前置条件

- Rust **nightly**，带 `rust-src` 与 `llvm-tools-preview`（在 `rust-toolchain.toml` 中固定；
  目标 `x86_64-unknown-none` 与 `x86_64-unknown-uefi`）
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
默认即被使用。运行 `make help` 查看完整目标列表。

---

## 5. 持续集成与质量门禁

Nilix 自动强制执行正确性、风格与启动健康度——相同的门禁在 CI 中运行，贡献者也可在本地运行
（维护者的 Windows 镜像会卸载到 Linux 构建主机）。

### 5.1 GitHub Actions（`.github/workflows/ci.yml`）

在每次向 `main` 的 push 与 pull request 时运行，同一 ref 上进行中的运行会被取消。四个并行作业：

| 作业                       | 运行                                       | 断言                                                  |
| -------------------------- | ------------------------------------------ | ----------------------------------------------------- |
| **rustfmt + clippy** | `make fmt-check` · `make clippy`      | 所有 crate rustfmt 干净；clippy 无错误                |
| **build**            | `make build`                             | 引导程序 + 内核编译通过（PIE / build-std / 加固标志） |
| **custom lints**     | `make lint`                              | 四个结构化源码 lint，加 VFS 可失败性与 ABI 布局门禁通过（见下） |
| **boot + test + musl** | `make boot-check` · `make test` · `make musl-check` | 内核干净启动至用户态、运行时套件计分为干净，且静态 musl 程序端到端运行 |

### 5.2 启动与一致性门禁

这些 QEMU 门禁的**退出码是真实的**——从串口日志与 QEMU `-d int` 中断日志读取，而绝不从
QEMU 自身的退出码读取（`-no-reboot -no-shutdown` 下 timeout 是健康运行的正常结束方式）。

- **`make boot-check`**（`scripts/boot_check.sh`）—— 在 QEMU 下启动，除非内核到达用户态 /
  其空闲循环 **且** 发生了零次 NX 违例取指缺页（D1-BOOT-NX-KASLR-LAYOUT 类缺陷的
  `v=0e e=0011` 签名），否则失败。
- **`make test`**（`scripts/kernel_test.sh`，P1-C VT-2 / Gate #4）—— 启动默认 `make build`
  镜像，并断言可解析的内核
  `=== Test Summary: N passed, M deferred (...), K failed ===` 且 `K == 0`，外加零次
  `KERNEL PANIC` 与零次 NX 违例 #PF。退出极性：**0 PASS / 1 FAILED / 2 NOT-RUN**
  （缺少 summary 或缺少 OVMF/ESP 为 NOT-RUN，而非静默变绿）。deferred/warning 计数仅供参考。
- **`make musl-check`**（`scripts/musl_check.sh`）—— 以 `--features musl_test` 构建，使内嵌的
  `hello_musl.elf` 成为 Ring-3 init 程序，然后断言**以下全部**：libc 可归因的 `printf` 标记
  （`42 * 2 = 84`）、`musl libc test passed!` 成功行、干净的 `exit code 0`、零次 NX 违例 #PF，
  以及无内核 panic。该门禁是双向且 fail-closed 的——默认的（原生 Rust）内核同样退出 0，但绝不会
  打印 libc 标记，因此会使门禁失败。

### 5.3 自定义源码 lint（`make lint`）

六个仓库专用门禁捕获编译器无法证明的关键不变量：

| 门禁                 | 强制                                                                                                                                     |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `lint-release`     | 内核代码中无未门控的 `println!`（仅 `drivers/`、`klog/` 允许）；改用 `kprintln!` / `klog!` / `klog_force!`                   |
| `lint-smap`        | 仅 `usercopy.rs` 可实例化 `UserAccessGuard`（SMAP 窗口最小化）                                                                       |
| `lint-fetch-add`   | 核心/VFS 路径中 ID/引用计数不得用裸 `fetch_add(1)` —— 改用 `fetch_update` + `checked_add`（或显式 `// lint-fetch-add: allow`） |
| `lint-repr-c-copy` | 用户边界上对 `#[repr(C)]` 结构体的每个 `from_raw_parts` / `copy_nonoverlapping` / `transmute` 都必须带 padding 安全注解          |
| `lint-fallible`    | 可恢复的 VFS 路径（尤其 `readdir`）必须使用可失败的名称/分配暂存；fixture 自测必须捕获 22 个候选且 0 误报                       |
| `abi-check`        | 内核 Rust `#[repr(C)]` 布局必须匹配注明来源的 Linux x86-64 UAPI oracle（11 个结构、100 个值、17 个绊线，并由 C 编译器交叉检查） |

### 5.4 扩展测试套件

除核心 CI 门禁外，Nilix 还具备持续稳定性、性能与扩展 SMP 测试：

- **QEMU 稳定性 soak**（`scripts/stress_test.sh`）—— 六种重复启动/运行配置，覆盖受限内存、
  单/多 vCPU、SMP、挂载存储和组合配置，每场景 60–300 秒。它们是稳定性配置，尚不是
  guest 内专用的内存/CPU/进程压力 workload。
- **扩展 SMP**（`scripts/extended_smp_test.sh`）—— 验证 8 核与 16 核启动、IPI 广播与多 CPU
  锁争用。经 `make test-smp-extended` 运行。
- **性能回归门禁**（`scripts/perf_regression_test.sh`）—— 用于检测系统调用延迟、上下文切换与
  缺页回归的框架。经 `make test-perf` 调用（基准测试待补）。
- **安全测试**（`kernel/security/tests.rs`）—— 九项运行时测试，验证 W^X、RNG、kptr 守护、
  Spectre V1/V2、SMAP 与 SMEP 缓解。已并入标准 `make test` 套件。
- **熔炼测试**（`scripts/melting_test.sh`）—— 持续满载场景（10 分钟以上）用于裸机热验证。
  框架已就位，需真实硬件。

完整文档位于 `docs/testing/`。

### 5.5 模糊测试基础设施

Nilix 目前具备可用的宿主机 cargo-fuzz 路径、KCOV 每任务覆盖和确定性 QEMU guest
执行门禁；它能端到端验证 guest 内 KCOV 生命周期与选定的系统调用路径，但还不是生产就绪的
syzkaller 等价物。当前 CI 行为如下：

- **KCOV 覆盖率跟踪** —— 通过跳过 IRQ、非阻塞的当前任务 recorder 和选定的手工系统调用
  tracepoint 实现每任务覆盖，并提供 5 个 KCOV 管理系统调用。KCOV 是宿主全局的特权面：授权
  **仅限宿主 root**（保留的 `CapRights::KCOV` 位为 ABI 稳定性保留，但在评审通过的身份绑定发放
  协议存在前不授权访问）。
- **系统调用描述** —— 基于 TOML 的类型安全定义，带约束（范围、标志、枚举）与资源关系
  （fd → 文件，pid → 进程），已描述 20+ 个核心系统调用。
- **架构原型** —— 覆盖引导变异、资源跟踪、状态机与语料库组件已经存在，但尚未连接成由宿主机
  驱动 QEMU Nilix guest 的持续反馈环。
- **真实解析器目标** —— push 对 VFS 路径、网络报文和 ELF 加载器做 60 秒短跑，这 3 个 target
  直接调用内核解析代码；每日任务运行全部 10 个已注册 target，其余 7 个是自包含模型 harness。
- **KCOV QEMU guest E2E** —— 从源码重建静态 runner，启动 `esp-kcov`，在 Ring 3 执行两组确定性
  syscall program，并验证 enable/disable/reset/dump、bitmap 计数、序列差异和重复稳定性。
- **流水线 simulator smoke** —— 作为独立的 dashboard/report 接线检查保留，显式记录 0 次
  内核执行，不得作为 coverage 或 crash 证据。
- **私密候选分流** —— 原始 libFuzzer 日志和 finding 输入只留在临时 runner；公开候选文件与 Issue
  正文只携带带密钥的 HMAC 标识和 workflow 指针，不公开 payload、栈、普通哈希或 target 名。
  仓库管理员必须配置至少 32 字节的 `FUZZ_FINGERPRINT_KEY`，否则发现 finding 时会 fail closed。

完整文档位于 `docs/fuzzing/`（7 份阶段指南，33,000+ 字）。

### 5.6 风格门禁与 pre-push 钩子

- **`make fmt-check`** —— 对 workspace 与 userspace 执行 `cargo fmt --all --check`。
  `rustfmt.toml` 固定 `newline_style = "Windows"`，因为仓库存储 CRLF blob。
- **`make clippy`** —— 在三个构建单元（引导程序、内核、userspace）上分别于隔离的 target 目录
  运行 clippy；deny-by-default 的正确性错误会使构建失败。
- **`.githooks/pre-push`** —— 选择性启用（`make hooks`）。钩子是**本地优先**的：当存在本地 Rust
  工具链时直接在本地运行 `make fmt-check` + `make clippy`；对于无工具链的镜像，可经 SSH 卸载到
  远程（`git config zeroos.remote`/`zeroos.remoteDir`）。用 `SKIP_PREPUSH=1 git push` 跳过单次
  push。仓库还提供了等效的 pre-commit 框架配置（`.pre-commit-config.yaml`）——详见
  [CONTRIBUTING.md](CONTRIBUTING.md)。

---

## 6. 安全审计状态

Nilix 在持续的对抗式评审流程下开发：每一轮审计内核、按严重程度记录发现、修复它们，并在
该轮结束前经双向同行评审（Claude Code + Codex MCP）收敛。

| 指标                 | 数值                                     |
| -------------------- | ---------------------------------------- |
| 审计轮次             | **187**（R187 KCOV 修复于 2026-08-08 完成；ReviewFix 闭环于 2026-08-08） |
| 累计发现             | ~1,340（历史 ID 含合并/驳回项）          |
| 已修复/解决的发现    | ~1,184                                   |
| 最新轮次             | R187 —— KCOV 授权/接入/拓扑；7 项修复、7 PASS（review-fix 8/8 已修复） |
| 最新 review-fix 复核 | RF187 —— 7/7 修复 PASS、8/8 RF 缺陷已修复，0 项升级；远程门禁全绿 |
| 独立全代码库审计 | R188（审计 2026-08-07；修复 2026-08-27）—— 3 HIGH + 24 MEDIUM 已修复；非 R 系列轮次；残留 U37-1/U55-6/U29-3 开放；连续记录不变 0/3 |
| 当前可执行债务       | **1 HIGH**（`R186-4`，结转）              |
| 1.0-Preview 发布门禁 | **已阻塞** —— 结转 `R186-4` HIGH 尚存；零 HIGH 连续记录 0/3 |

R186 共记录 18 个问题：17 个可执行发现与 1 个 INFO。16 个可执行项已完全修复；
`R186-18` 通过共享凭证代际、写者公平授权以及贯穿副作用和发布过程的稳定主体身份完成修复并通过复核。
`R186-4` 是唯一仍开放的 HIGH。因此零 HIGH 连续记录重置为 0/3，聚合堆准入的设计父项也被重新打开。
精确状态见 [R186 报告](docs/review/audits/qa-2026-07-28.md)，剩余工作见
[当前计划](docs/review/nextplan/next-phase-plan-2026-07-23-v2.md)。

权威 **RF186 ReviewFix 闭环** 共复核 16 项已落地修复：2 项 PASS、12 项 PARTIAL、2 项 FAIL。
全部 24 项缺陷（`RF186-1`…`RF186-24`）均已修复，0 项升级；最终聚焦测试、
默认并行测试及 fmt/clippy/build/lint/test/boot/musl 门禁均为绿色。`R186-4` 从未进入
修复阶段，因此不属于 Stage-3 判定范围，发布门禁和连续记录保持不变。

R187（2026-08-08）审计 KCOV 可观测面，记录 7 项发现 —— 授权、IRQ/NMI/软进度准入、精确
dump、占用槽位碰撞语义、模糊器时序/控制、文档与静态 CPU/拓扑安全。7 项全部修复，ReviewFix
闭环验证 7/7 PASS。8 项 review-fix 缺陷（RF187-1…RF187-8）均已修复，0 项升级：KCOV 授权改为
仅宿主 root（保留的 `CapRights::KCOV` 位无法提升调用者），无分配的软进度守护覆盖公开的
延迟回调排空，CPU 在线拓扑统一到唯一权威的 `cpu_local` 掩码，模糊器 ABI 报告已占用位图槽位并
限制 KCOV 控制重试次数。R187 未新增开放 HIGH；门禁仍因结转的 `R186-4` 阻塞，连续记录保持
0/3。详见 [R187 报告](docs/review/audits/qa-2026-08-05.md) 与
[RF187 闭环](docs/review/reviewfix/reviewfix-2026-08-08.md)。

一次独立全代码库审计（R188，2026-08-07）已于 2026-08-27 完成修复：3 项 HIGH 发现
（`U06-1` cgroup 端口反记账、`U09-1/2/3` 信号交付 ABI 与锁生命周期、`U34-1` robust-futex
拆除）与全部 24 项 MEDIUM 发现均已修复，并覆盖所有可实现的 LOW/关联集合。残留设计工作
——`U37-1`（KPTI/双 CR3）、`U55-6`（早期启动身份映射 W+X 转换）、`U29-3`（VM 透传生命周期）
——明确保持开放且不计入已修复。这是*独立*审计，不属于 R 系列，因此不做零 HIGH 连续记录
声明，门禁仍因结转的 `R186-4` 阻塞。同步树的所有远程门禁通过。详见
[审计文档](docs/security/full-codebase-audit-2026-08-07.md)（§13 处置）。

CI 现已运行 `make test-hosted-subcrates`：audit、MM、block、seccomp、net 及聚焦的
RF186 capability 生命周期用例共 **169 项默认并行主机测试**，并编译检查 IPC、
kernel_core 与 kernel 的测试代码。精确测试数量门禁可阻止零测试或过滤器漂移静默通过。
完整 capability 套件及含特权指令的内核套件仍只能在 QEMU 中执行，避免主机进程误触
中断/MMIO 路径。
详见 [权威 RF186 报告](docs/review/reviewfix/reviewfix-2026-07-30.md)。

---

## 7. 路线图

**已完成**

- **Phase A** —— 安全基础：usercopy/SMAP API、Spectre/Meltdown、审计升级、SMP 就绪接口
- **Phase B** —— 能力 + LSM + seccomp 框架，集成进系统调用/VFS/进程路径
- **Phase C** —— 存储：virtio-blk、页缓存、ext2、procfs/devfs/initramfs、OOM killer、`openat2`
- **Phase D** —— 网络：完整 TCP/IP 栈，含 conntrack 与有状态防火墙
- **Phase E** —— SMP 与并发：AP 启动、IPI TLB shootdown、每 CPU 调度、RCU、lockdep、futex PI
- **Phase F** —— 资源治理：五种命名空间、cgroups v2 控制器、IOMMU/VT-d 驱动
- **Phase G** —— 生产就绪加固：KASLR（H.2）、KPTI（H.3）、tracing 与看门狗、实时补丁

**进行中**

- **Phase U —— 用户模式与 ABI**（*Compat-ZeroABI*）：能力优先的原生核心，加上去特权化的
  Linux 兼容人格。里程碑 **M0** 在既有 Linux cABI 之上构建用户态基础（auxv、信号投递、缺失的
  系统调用、exec 消歧、用户栈守护），由静态 musl 一致性门禁证明，之后再提交原生/人格分叉。
- **D3 网络命名空间数据平面**（Phase I.3）—— 每命名空间的 ARP 缓存、地址配置、路由与字节预算
  均已落地，另有有界 RX 入站循环与 `eth0` 实时接收。待发帧队列也已落地：on-link 未命中时
  暂存并在学习到邻居后重传数据帧，带计量的网关回退交付路径已退役。剩余工作是防火墙管理系统
  调用面、`veth` 对与真正的路由表，以及具备能力约束的设备迁移启用。
- IOMMU DMAR 表发现接线；完整的按需增长用户栈；能力支撑的 fd 表。

**未来**

- 动态链接（`ld.so`/vDSO）、glibc + OCI 兼容、用户态 ASLR
- 每租户网络资源预算、NUMA 感知调度、KVM/虚拟机管理程序支持

完整路线图见 [docs/roadmap.md](docs/roadmap.md) 与
[docs/roadmap-enterprise.md](docs/roadmap-enterprise.md)。

---

## 8. 贡献指南

社区与维护入口：

- **[CONTRIBUTING.md](CONTRIBUTING.md)** —— 工具链、内核安全不变量、按风险选择的测试、
  RFC、提交、PR 与评审流程。
- **[SUPPORT.md](SUPPORT.md)** —— Bug、提案、性能回归、文档问题和使用问题的提交方式。
- **[SECURITY.md](SECURITY.md)** —— 私密漏洞报告、威胁范围、证据要求与协调披露。
- **[GOVERNANCE.md](GOVERNANCE.md)** —— 角色、决策、评审合并、Issue 生命周期与发布门禁。
- **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** —— 项目社区空间的行为规范。

简而言之：

1. 拥有本地 Rust 工具链的贡献者在本地完成构建、lint 与测试——与 CI 完全一致。（维护者的
   Windows 镜像没有工具链，会卸载到 Linux 构建主机。）
2. 运行核心门禁，并按风险补充验证：ABI、SMP/并发、存储、模糊测试、性能和硬件改动
   分别需要对应证据。
3. 架构、信任边界、ABI、依赖或跨子系统实现前先提交 RFC；Bug 与安全修复应包含回归测试。
4. Git 提交为手动 —— 不会自动提交或自动推送。

---

## 9. 许可证

---

## 10. 参考资料

- [OSDev Wiki](https://wiki.osdev.org)
- [用 Rust 写操作系统](https://os.phil-opp.com)
- [Linux 内核源码](https://kernel.org)
- [seL4 微内核](https://sel4.systems)
