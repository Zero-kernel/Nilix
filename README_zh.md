# Nilix

[English](README.md) · [组件能力与路线图](docs/roadmap.md) · [中文路线图](docs/roadmap_zh.md) ·
[下一阶段计划](docs/next-phase-plan.md) · [CI 与测试](docs/ci-testing.md)

Nilix 是面向 x86_64、主要以 Rust 编写的实验性操作系统内核，提供 Linux 系统调用的
一个兼容子集，以及 capability/LSM 安全框架。目前能够通过 UEFI 启动，运行 Ring 3
静态程序和真正的 musl 测试程序，并包含 SMP 调度、文件系统、块设备和 IPv4 网络栈。

**Nilix** 是 **N**ilix **I**s **L**inux **I**ndependent e**X**istence 的递归缩写。
项目从零实现，没有派生自 Linux；Linux 兼容性是逐步实现的目标，目前不能据此宣称
任意 Linux 应用、线程库或容器镜像都能运行。

**设计原则：Safety > Correctness > Efficiency > Performance（安全 > 正确性 > 效率 > 性能）。**

## 当前状态

**更新日期：2026-09-12**；代码基线 e127c34，CI 总时间预算和运行时解析修复等待下一轮完整验证。
**1.0-Preview 仍被阻塞。** 大多数服务目前位于 Ring 0，去特权化的 Linux 用户态人格
服务属于后续架构工作。

九月 KSA 审计的 20 项发现已在各自验收范围内完成修复和独立评审，包括真实 QEMU
fuzz、描述符/路径/凭据、TLS 迁移、BIO 生命周期和缓解状态真实性。这不等于完成了
整个内核，也没有自动关闭较早的 R186-4 准入问题。

发布仍需完成 R186-4 准入闭环、R188 原始修复的评审证据核对、严格的平台/安全门禁及
**全部六种 stress-v2 压力场景**。历史零 HIGH 完整审计连续记录维持 **0/3**。
物理 VT-d、完整 KPTI 隔离、编译器 retpoline 和生产 livepatch 尚未具备对应支持或
验收。详情见 [安全状态](docs/security-audit-status.md) 与
[发布条件](docs/roadmap.md#8-10-preview-release-gate)。

## 当前组件能做什么，还缺什么

下面区分实际可用子集、已接入代码和未完成能力。模块存在、API 可调用或局部测试通过，
都不能单独作为整个子系统“完成”的依据。

| 组件 | 当前能力 | 缺失能力与边界 |
| --- | --- | --- |
| UEFI 与启动 | PIE 内核加载/重定位、内存图交接、KASLR 放置、基础控制台 | x86_64 平台范围；更多固件/物理平台及早期 W+X 转换验证 |
| 内存管理 | buddy/全局堆、准入计费容器、保护页、匿名 mmap/munmap/mprotect/brk、COW fork、缓存/OOM 机制 | R186-4 闭环；MAP_SHARED/MAP_FIXED 语义、文件映射、mremap；无已验收 slab/NUMA/swap/THP |
| 进程生命周期 | 静态 ELF、fork/exec/exit/wait4、僵尸与 PID namespace 身份保留、清理路径测试 | waitid、PID1/reaper 及更广的失败/压力路径 |
| 线程与 TLS | 受限 CLONE_VM/TLS 创建，SMP 迁移时 FS/user-GS 恢复已有 guest 证据 | 通用 CLONE_THREAD/FILES/FS/SIGHAND 组合拒绝；不能宣称 pthread 兼容 |
| 调度与 SMP | 每 CPU MLFQ、抢占、工作窃取/平衡、亲和性/cpuset、APIC/IPI/TLB、RCU/锁序 | 更高核数/长时间/物理并发验证；64 核是实现上限，不是已验证拓扑 |
| IPC 与信号 | capability 管道、futex 原语/robust 清理、屏蔽/处理/返回、阻塞信号测试、poll/select | 完整原生同步 IPC/共享内存、Linux futex 语义、sigaltstack/RT 队列/重启语义 |
| 文件描述符 | fd 0/1/2 已表驱动，dup/close/fork/exec/CLOEXEC、共享状态、O_NONBLOCK 消费者、NOFILE 限制 | 更完整 fcntl/rlimit/线程共享语义 |
| VFS 与路径 | ramfs/ext2/JBD2 子集、procfs/devfs/CPIO/cgroupfs；cwd/root/pivot、symlink/jail、DAC/UID/GID、挂载表回收 | 通用 dirfd、chown/statx/硬链接、真实终端状态、完整 POSIX/文件系统兼容 |
| 存储与块 I/O | BIO/完成回调所有权、virtio-blk、512B/4096B 几何与 guest I/O 验证 | fsync/fdatasync/sync/sync_file_range 未接线；掉电/恢复/缓存语义待验证 |
| 网络 | virtio-net、Ethernet/ARP/IPv4/ICMP/UDP/TCP、conntrack/默认 DROP 防火墙、namespace 状态及进程上下文 RX | veth/子 namespace RX/路由管理/防火墙管理/完整 loopback、IPv6、线上互通；设备迁移仍禁用 |
| namespace 与 cgroup | PID/mount/IPC/net/user 对象；部分 CPU/内存/PID/I/O/FD/端口控制器与资源事务测试 | 完整 cgroups-v2/委派/OCI、init 成员归属、namespace/clone 组合和容器网络 |
| capability / LSM / seccomp | 带 generation 的权限、凭据绑定发布、策略钩子、过滤与 pledge 子集 | 完整原生 capability syscall、每 namespace 管理权限与 TSYNC |
| 内存与 CPU 加固 | NX/W^X/保护页/SMEP/SMAP/UMIP、KASLR、RNG/CSPRNG/kptr、精确 usercopy 恢复 | full KPTI=false；双根仍保留内核映射；retpoline 不支持，硬件缓解依赖 CPU |
| VT-d | DMAR 已接入启动；Q35 初始化失败、EDU 真实 translated DMA/MSI/失效/隔离/复用测试 | 物理验收、MSI-X、多 unit/bridge/RMRR/ACCESS_PLATFORM/现代模式 |
| Livepatch | 不支持的返回路径已测试，保留实验性解析/签名/生命周期代码 | 修改 API/syscall 返回 ENOSYS；缺少生产 hooks/密钥/SMP 回滚验收 |
| 审计与可观测性 | hash/HMAC 审计、授权 trace/计数器、分级日志、watchdog/profiler/串口 kdump | 持久/远程后端、密钥运维与真实性能基线；没有 FIPS 认证 |
| 用户态与 Linux ABI | 原生 libc 辅助/开发 shell、静态 ET_EXEC/musl/SysV auxv、部分布局 oracle | ET_DYN/动态加载器/vDSO、glibc/pthread、通用应用/OCI、用户态人格服务 |
| 测试与 fuzz | hosted debug/release、Python JUnit/覆盖报告、真实 KCOV/双 seed QEMU、定时 fuzz/extended | deferred guest 场景、六种压力场景和真实性能/热稳定性验收 |

[完整 roadmap](docs/roadmap.md#4-kernel-composition) 恢复了 **25 个内核库 crate**
的职责和证据入口，以及信任边界、Linux 差距、历史阶段和欠账归属。
[VT-d 支持矩阵](docs/vtd-support-matrix.md) 与
[livepatch 状态](docs/livepatch-support.md) 单独说明设备/功能范围。

## 架构与主要执行路径

Ring 3 → 架构入口/usercopy → 策略门 → kernel_core → 内核服务 → 硬件。
Cargo 模块划分用于组织职责，不代表服务已运行在独立权限域中。

<p align="center">
  <img src="docs/assets/architecture-at-a-glance.svg" alt="Nilix 内核组件与执行路径" width="960">
</p>

| 路径 | 源码入口 | 职责 |
| --- | --- | --- |
| 启动 | [UEFI](bootloader/src/main.rs)、[kernel _start](kernel/src/main.rs) | 加载/重定位、BootInfo、服务初始化 |
| 系统调用 | [入口汇编](kernel/arch/syscall.rs)、[dispatcher](kernel/kernel_core/syscall.rs) | 寄存器帧/usercopy、策略、兼容和私有调用 |
| 进程/内存 | [fork/COW](kernel/kernel_core/fork.rs)、[process](kernel/kernel_core/process.rs)、[paging](kernel/mm/page_table.rs) | 所有权、发布、独立地址空间和回收 |
| 调度 | [MLFQ](kernel/sched/enhanced_scheduler.rs)、[context switch](kernel/arch/context_switch.rs) | 队列/亲和性、TLS/FPU/入口状态切换 |
| 存储/VFS | [manager](kernel/vfs/manager.rs)、[Ext2](kernel/vfs/ext2.rs)、[block](kernel/block/src/lib.rs) | 路径授权、文件系统事务、拥有缓冲区的 I/O |
| 网络 | [stack](kernel/net/src/stack.rs)、[socket](kernel/net/src/socket.rs) | 协议/RX、策略、队列和唤醒 |
| 安全/设备 | [security](kernel/security/lib.rs)、[LSM](kernel/lsm/lib.rs)、[VT-d](kernel/iommu/lib.rs) | 执行并报告已支持的防护与设备权限 |

分层和流程详见 [architecture.md](docs/architecture.md)，当前功能验收以 roadmap 为准。

## 测试与 CI

当前 hosted allowlist 在 debug/release 下分别执行 **438 次计数受检的单元测试**，
另有 CpuLocal doctest 和三组测试代码编译检查。源码扫描发现 **74 个 RuntimeTest
实现**，不代表 74 个 guest 测试都通过，更不代表内核指令覆盖率 100%。

CI 按 source/hosted/build/boot-SMP/musl/IOMMU/mitigation/KCOV-fuzz 分组。
JUnit、Markdown、原始日志及源码/镜像身份共同保留实际结果。Python 覆盖率衡量的是
宿主测试脚本；qualified 的诊断结果与严格 PASS 分开记录。guest 门禁默认对失败或
不完整的 QEMU 首次尝试重试一次，并在报告中保留两次结果。

六种 stress 场景通过每周/手动工作流运行，但内核和 workload 缺口仍阻塞完整验收。
11 个定时 fuzz campaign 补充确定性 smoke，不能替代功能契约或无漏洞证明。
[CI 说明](docs/ci-testing.md) · [门禁细节](docs/quality-gates.md) ·
[脚本目录](scripts/README.md)。

## 快速开始

完整构建/QEMU 测试使用 Linux：

- 固定 Rust **nightly-2025-12-08**，rust-src、llvm-tools-preview：
  [rust-toolchain.toml](rust-toolchain.toml)。
- 目标：x86_64-unknown-none、**x86_64-unknown-uefi**。
- GNU Make、QEMU system x86_64、OVMF、C 编译器、e2fsprogs。
- musl-tools/musl-gcc 用于 musl 和 guest workload。
- Python 测试依赖：[requirements-ci.txt](requirements-ci.txt)。

```sh
make build                 # esp/ 中的 UEFI bootloader 与普通内核
make run-serial            # 串口控制台
make run-shell             # 开发 shell
make run-blk               # 临时 ESP 与配置的 virtio 磁盘
make run-smp SMP_CPUS=4     # 4 个逻辑 CPU
make build-musl-test        # 独立 musl 镜像
bash scripts/ci/entrypoint.sh quality
bash scripts/ci/entrypoint.sh hosted
bash scripts/ci/entrypoint.sh build
bash scripts/ci/entrypoint.sh runtime
bash scripts/ci/entrypoint.sh musl
```

boot/runtime/SMP 与 musl 的单次 guest 观察窗口默认 **600 秒**，boot/runtime/SMP
组会依次运行三个窗口；mitigation、qemu-fuzz 和 extended stress 仍保留更长窗口。
make 非零退出也可能来自 qualified 结果，应查看报告保留的原始 gate 状态；
默认 CPU/配置不能满足全部安全和硬件测试的前提。

## 下一阶段

1. 核对未闭合的 R188 评审证据，完成 R186-4 准入机制和验收。
2. 修正 mmap flags 语义、压力测试报告传输，落地限定范围的持久化调用和 block workload。
3. 实现共享匿名内存，验收六种压力场景、严格网络/SMP/安全矩阵及完整审计发布条件。
4. 恢复原生 capability/IPC、静态 ABI 缺项、personality/动态链接、容器网络和可测量的运维/性能工作。

[当前 nextplan](docs/next-phase-plan.md) 写明依赖、设计和验收 oracle。
已通过 KSA 验收的修复会保留回归证据，不重新当作未实现功能排期。

## 文档与贡献

| 目标 | 入口 |
| --- | --- |
| 当前能力/缺口/发布条件 | [Roadmap](docs/roadmap.md) |
| 优先级与交接 | [Nextplan](docs/next-phase-plan.md) |
| 架构/文档索引 | [Architecture](docs/architecture.md) · [Docs](docs/README.md) |
| CI/测试/fuzz | [CI](docs/ci-testing.md) · [Quality gates](docs/quality-gates.md) |
| 审计证据/变更 | [Security status](docs/security-audit-status.md) · [提交历史](https://github.com/Zero-kernel/Nilix/commits/main/) |

贡献前阅读 [CONTRIBUTING](CONTRIBUTING.md)、[GOVERNANCE](GOVERNANCE.md) 和
[CODE_OF_CONDUCT](CODE_OF_CONDUCT.md)。安全问题通过 [SECURITY](SECURITY.md)
私下报告，其他问题见 [SUPPORT](SUPPORT.md)。改动应包含有效回归和对应风险的验证证据。

## 许可证

许可证条款目前待定。

## 参考

[OSDev](https://wiki.osdev.org) · [用 Rust 写操作系统](https://os.phil-opp.com) ·
[Linux](https://kernel.org) · [seL4](https://sel4.systems)
