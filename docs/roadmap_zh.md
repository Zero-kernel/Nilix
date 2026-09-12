## Nilix (Zero-OS) — 开发与能力路线图

**修订：** 6.0 · **更新日期：** 2026-09-12
**源码基线：** `e127c34`（运行时解析与挂载瞬态修复）；hosted 计数修复等待下一轮完整 CI。
**现行计划：** [next-phase-plan-2026-09-12.md](review/nextplan/next-phase-plan-2026-09-12.md)

Nilix 是实验性 x86_64 内核：UEFI 启动、Ring-3 程序、已测 static-musl ABI 子集、SMP 调度、文件系统、IPv4 网络与安全策略机制。**1.0-Preview 仍阻塞。** 本文记录当前树的能力、缺失契约与证据边界。

修订 6 恢复了 5.4 中丢失的组件细节、信任边界、Linux 对照、阶段历史与发布条件；纳入 9 月范围内 KSA 修复，并恢复更早的准入、压力与功能积压。历史路线图仍在 Git；带日期的审计保留其原始证据。

## 0. 如何阅读状态

<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px;margin:0.75em 0">
  <div style="background:var(--card);color:var(--card-foreground);border:1px solid var(--border);border-radius:var(--radius);padding:10px 12px;box-shadow:var(--shadow-xs)">
    <div style="font-weight:var(--font-chat-strong-weight);color:var(--primary);margin-bottom:4px">Tested subset · 已测子集</div>
    <div style="font-size:0.9em;color:var(--muted-foreground)">具名测试覆盖所述行为；不暗示其他模式。</div>
  </div>
  <div style="background:var(--card);color:var(--card-foreground);border:1px solid var(--border);border-radius:var(--radius);padding:10px 12px;box-shadow:var(--shadow-xs)">
    <div style="font-weight:var(--font-chat-strong-weight);margin-bottom:4px">Implemented · 已实现</div>
    <div style="font-size:0.9em;color:var(--muted-foreground)">代码已激活；行为鉴定不完整。</div>
  </div>
  <div style="background:var(--card);color:var(--card-foreground);border:1px solid var(--border);border-radius:var(--radius);padding:10px 12px;box-shadow:var(--shadow-xs)">
    <div style="font-weight:var(--font-chat-strong-weight);margin-bottom:4px">Partial · 部分实现</div>
    <div style="font-size:0.9em;color:var(--muted-foreground)">有用行为与已识别的缺失契约并存。</div>
  </div>
  <div style="background:var(--card);color:var(--card-foreground);border:1px solid var(--border);border-radius:var(--radius);padding:10px 12px;box-shadow:var(--shadow-xs)">
    <div style="font-weight:var(--font-chat-strong-weight);color:var(--destructive);margin-bottom:4px">Unsupported · 不支持</div>
    <div style="font-size:0.9em;color:var(--muted-foreground)">已禁用、已拒绝或未实现。</div>
  </div>
  <div style="background:var(--card);color:var(--card-foreground);border:1px solid var(--border);border-radius:var(--radius);padding:10px 12px;box-shadow:var(--shadow-xs)">
    <div style="font-weight:var(--font-chat-strong-weight);margin-bottom:4px">Verification pending · 验证待定</div>
    <div style="font-size:0.9em;color:var(--muted-foreground)">缺当前树、平台或独立评审证据。</div>
  </div>
  <div style="background:var(--card);color:var(--card-foreground);border:1px solid var(--border);border-radius:var(--radius);padding:10px 12px;box-shadow:var(--shadow-xs)">
    <div style="font-weight:var(--font-chat-strong-weight);margin-bottom:4px">Planned · 已规划</div>
    <div style="font-size:0.9em;color:var(--muted-foreground)">未来实现或鉴定里程碑。</div>
  </div>
</div>

范围审计 PASS 仅关闭该发现的评分细则。诊断 CI 可在保留合格警告/延期/跳过结果的同时接受退出码 3——这**不是**严格发布鉴定。源码扫描覆盖、宿主测试与真实客户机执行测量的是不同事物。

## 1. 执行摘要

<div style="background:color-mix(in srgb, var(--destructive) 12%, var(--card));color:var(--card-foreground);border:1px solid color-mix(in srgb, var(--destructive) 45%, var(--border));border-radius:var(--radius);padding:12px 14px;margin:0.75em 0;box-shadow:var(--shadow-sm)">
  <div style="font-weight:var(--font-chat-strong-weight);color:var(--destructive);margin-bottom:6px">发布门禁 · BLOCKED</div>
  <div style="font-size:0.92em">阻塞项：R186-4 准入关闭、历史评审谱系、严格配置鉴定、全部 6 个压力配置，以及记录的 0/3 清洁审计连胜。</div>
</div>

<div style="overflow-x:auto;margin:0.75em 0">
<table style="width:100%;border-collapse:collapse;font-size:0.9em;font-family:var(--font-sans);background:var(--card);color:var(--card-foreground);border:1px solid var(--border);border-radius:var(--radius)">
  <thead>
    <tr style="background:var(--muted);color:var(--muted-foreground);text-align:left">
      <th style="padding:8px 10px;border-bottom:1px solid var(--border);width:18%">领域</th>
      <th style="padding:8px 10px;border-bottom:1px solid var(--border)">当前状态</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-weight:var(--font-chat-strong-weight)">组成</td>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border)">25 个内核库 crate + 入口二进制；独立 UEFI 引导器、用户空间与宿主工具。多数服务在 Ring 0 执行。</td>
    </tr>
    <tr>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-weight:var(--font-chat-strong-weight)">用户态实证</td>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border)">静态 ELF 与真实 musl 测试在 Ring 3 运行；fork/exec/wait、描述符、cwd/jail 及若干失败路径有客户机证据。</td>
    </tr>
    <tr>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-weight:var(--font-chat-strong-weight)">9 月 KSA</td>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border)">KSA-001..020 在记录细则内已接受；18 项关联计划中 17 项完成。P3-2 物理 VT-d 仍待定。</td>
    </tr>
    <tr>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-weight:var(--font-chat-strong-weight)">宿主侧门禁</td>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border)">debug/release 各 438 次计入的单元测试执行、CpuLocal doctest、三项测试代码编译检查；显式宿主安全白名单。</td>
    </tr>
    <tr>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-weight:var(--font-chat-strong-weight)">运行时清单</td>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border)">源码发现 74 个 RuntimeTest 实现；实际通过/延期/警告/跳过/失败计数取决于镜像/平台。这<strong>不是</strong> 100% 内核代码覆盖。</td>
    </tr>
    <tr>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-weight:var(--font-chat-strong-weight)">近期 CI</td>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border)"><a href="https://github.com/Zero-kernel/Nilix/actions/runs/34701321475" style="color:var(--primary)">Run 34701321475</a>，e127c34：hosted 的 vfs 实际 63 项全部通过，但白名单仍要求 62；计数修复已在本树，等待完整重跑。</td>
    </tr>
    <tr>
      <td style="padding:8px 10px;vertical-align:top;font-weight:var(--font-chat-strong-weight)">发布门禁</td>
      <td style="padding:8px 10px"><span style="color:var(--destructive);font-weight:var(--font-chat-strong-weight)">BLOCKED</span>：R186-4 准入关闭、历史评审谱系、严格配置鉴定、全部 6 个压力配置、记录的 0/3 清洁审计连胜。</td>
    </tr>
  </tbody>
</table>
</div>

验收来源：[KSA 审计](review/audits/qa-2026-09-06.md)、[最终 review-fix](review/reviewfix/reviewfix-2026-09-11-v2.md)、[P3-2 QEMU 证据](review/fixes/p3-2-qemu-device-evidence-2026-09-12.md)、[VT-d 矩阵](vtd-support-matrix.md)。其清单标识实际测试树。后续提交**不回溯**改变历史验收。

## 2. 愿景、原则与非目标

目标是带 Linux 兼容用户态表面、能力授权与显式资源所有权的 Rust OS。长期架构将选定 Linux personality 服务下沉到低特权用户空间。当前调度器、VFS、网络、驱动与 Linux 系统调用语义**主要在内核内**；微内核特权分离是未来里程碑。

**安全 > 正确性 > 效率 > 性能。** 可失败发布、对称记账、拆除所有权与 IRQ 安全锁优先于 API 广度或优化。匹配系统调用号/布局并通过 musl smoke **不能**建立一般 Linux、pthread、glibc 或 OCI 兼容性。企业部署、认证 FIPS 运行、通用设备与完整推测执行防护是鉴定目标——不是当前声明。

## 3. 架构与信任边界

### 3.1 当前执行与规划中的 personality

Ring 3 → 架构入口/usercopy → seccomp/capability/LSM 门 → kernel_core → VFS/IPC/网络/调度 → 内存/arch/驱动 → 硬件。

Cargo 分层与回调打破依赖环，**不**创造特权边界。受信任引导器提供镜像、内存图与 ACPI 指针。凭据/能力/LSM 授权已支持操作。IOMMU 仅在受支持设备矩阵内中介设备请求。经原生 IPC 到达的去特权 Linux personality 已规划。组成图与热路径见 [architecture.md](architecture.md)。

### 3.2 威胁模型

<div style="overflow-x:auto;margin:0.75em 0">
<table style="width:100%;border-collapse:collapse;font-size:0.88em;font-family:var(--font-sans);background:var(--card);color:var(--card-foreground);border:1px solid var(--border);border-radius:var(--radius)">
  <thead>
    <tr style="background:var(--muted);color:var(--muted-foreground);text-align:left">
      <th style="padding:8px 10px;border-bottom:1px solid var(--border);width:22%">行为者/输入</th>
      <th style="padding:8px 10px;border-bottom:1px solid var(--border);width:39%">已有防御</th>
      <th style="padding:8px 10px;border-bottom:1px solid var(--border)">剩余边界工作</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top">非特权进程/系统调用参数</td>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top">精确 usercopy 修复、W^X/地址检查、凭据快照、能力世代、seccomp/pledge 与 LSM</td>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top">MM 准入关闭、部分 ABI 语义、失败/并发广度</td>
    </tr>
    <tr>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top">租户/资源压力</td>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top">五类命名空间、cgroup/类预算、事务性构造器与描述符发布</td>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top">共享内存、init 成员资格、委托设备权威、完整容器接口</td>
    </tr>
    <tr>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top">畸形 ELF/文件系统/报文</td>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top">已检查 ELF、几何、路径、日志与协议处理；conntrack/防火墙</td>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top">恢复语料、网络拓扑与互操作性</td>
    </tr>
    <tr>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top">故障/敌对设备</td>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top">Owned BIO、virtqueue 校验、VT-d 映射/失效、重映射 MSI 与 EDU 隔离测试</td>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top">物理 DMA、桥/多单元/RMRR/ACCESS_PLATFORM 与设备广度</td>
    </tr>
    <tr>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top">操作员/诊断读取者</td>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top">配置日志、kptr 脱敏、授权 trace/audit 导出、hash/HMAC 审计</td>
      <td style="padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top">持久/远程后端、密钥与完整 Secure 配置鉴定</td>
    </tr>
    <tr>
      <td style="padding:8px 10px;vertical-align:top">推测执行</td>
      <td style="padding:8px 10px;vertical-align:top">硬件相关控制/屏障与双根转换证据</td>
      <td style="padding:8px 10px;vertical-align:top">完整 KPTI 与编译器 retpoline 不支持；需 CPU 特定证明</td>
    </tr>
  </tbody>
</table>
</div>

## 4. 内核组成

全部 25 个库 crate 列出。crate/API 存在**不是**完成声明。

<div style="overflow-x:auto;margin:0.75em 0">
<table style="width:100%;border-collapse:collapse;font-size:0.86em;font-family:var(--font-sans);background:var(--card);color:var(--card-foreground);border:1px solid var(--border);border-radius:var(--radius)">
  <thead>
    <tr style="background:var(--muted);color:var(--muted-foreground);text-align:left">
      <th style="padding:7px 10px;border-bottom:1px solid var(--border);width:16%">Crate</th>
      <th style="padding:7px 10px;border-bottom:1px solid var(--border);width:32%">角色</th>
      <th style="padding:7px 10px;border-bottom:1px solid var(--border)">鉴定/缺口</th>
    </tr>
  </thead>
  <tbody>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/arch/lib.rs" style="color:var(--primary)">arch</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">GDT/IDT、APIC/HPET、IRQ、SYSCALL、上下文切换、AP 启动</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">UP/SMP 证据；高核/物理/异常入口广度待定</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/cpu_local/lib.rs" style="color:var(--primary)">cpu_local</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">CPU 拓扑/本地存储/FPU 所有权</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">借用生命周期 API 与 TLS 迁移证据；64 CPU 为上限</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/tlb_ops/lib.rs" style="color:var(--primary)">tlb_ops</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">TLB/INVPCID 原语</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">活动 MM/arch 依赖；依赖 CPU 特性</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/sync_safe/lib.rs" style="color:var(--primary)">sync_safe</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">IRQ 安全锁包装</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">调用方锁序/入口状态义务仍在</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/drivers/lib.rs" style="color:var(--primary)">drivers</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">VGA/framebuffer、串口、键盘</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">基础控制台，非桌面/设备驱动生态</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/virtio/src/lib.rs" style="color:var(--primary)">virtio</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">共享 PCI/MMIO 传输/队列</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">块/网络集成；ACCESS_PLATFORM/设备广度待定</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/crypto/lib.rs" style="color:var(--primary)">crypto</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">共享 SHA-256</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">窄原语，非通用认证提供方</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/klog/lib.rs" style="color:var(--primary)">klog</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">配置感知日志</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">活动 lint/宏；完整调用方/脱敏扫描在跟踪</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/mm/lib.rs" style="color:var(--primary)">mm</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">Buddy/堆/准入、分页/缓存/DMA/OOM/TLB</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">匿名/COW 路径；准入/共享/文件映射缺口</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/coverage/lib.rs" style="color:var(--primary)">coverage</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">KCOV 任务位图/控制</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">宿主根权威/手工插桩；非穷尽覆盖</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/cap/lib.rs" style="color:var(--primary)">cap</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">权利、ID、世代与表</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">文件/管道生命周期集成；原生系统调用族不完整</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/audit/lib.rs" style="color:var(--primary)">audit</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">Hash/HMAC 环与导出</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">策略/宿主证据；缺生产级持久后端</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/security/lib.rs" style="color:var(--primary)">security</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">W^X/NX、RNG/kptr/KASLR、CPU 缓解</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">机制/状态测试；完整 KPTI/retpoline 不支持</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/lsm/lib.rs" style="color:var(--primary)">lsm</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">进程/文件/IPC/内存/网络钩子</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">活动策略；未来操作钩子不实现操作本身</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/seccomp/lib.rs" style="color:var(--primary)">seccomp</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">Strict/filter 与 pledge</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">已测子集；TSYNC/Linux 对等残差</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/compliance/lib.rs" style="color:var(--primary)">compliance</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">配置、粘性 FIPS 状态/KAT 策略</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">无认证或完整 Secure 平台保证</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/livepatch/lib.rs" style="color:var(--primary)">livepatch</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">实验性签名补丁/生命周期机制</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">不支持，ENOSYS；无生产启用</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/block/src/lib.rs" style="color:var(--primary)">block</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">Owned BIO/完成/几何/virtio-blk</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">宿主/客户机 512B/4096B 证据；物理矩阵待定</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/net/src/lib.rs" style="color:var(--primary)">net</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">IPv4/TCP/UDP、套接字、conntrack/防火墙、virtio-net</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">容器连通/IPv6/互操作性缺口</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/trace/lib.rs" style="color:var(--primary)">trace</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">计数器/tracepoint/看门狗/profiler/kdump</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">诊断存在；外部采集/性能待定</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/iommu/lib.rs" style="color:var(--primary)">iommu</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">DMAR/legacy VT-d/域/重映射/隔离</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">Q35/EDU 范围已测；物理/拓扑缺口明确</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/kernel_core/lib.rs" style="color:var(--primary)">kernel_core</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">进程/ABI/命名空间/cgroup/信号/RCU/ELF</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">活动枢纽；资源/ABI/拆除积压仍在</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/vfs/lib.rs" style="color:var(--primary)">vfs</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">路径/DAC/挂载、ramfs/ext2/JBD2/procfs/devfs/CPIO/cgroupfs</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">已测发布/生命周期；缺持久性/POSIX 广度</td></tr>
    <tr><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/ipc/lib.rs" style="color:var(--primary)">ipc</a></td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">管道/端点/消息/futex/同步</td><td style="padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top">管道/robust 清理已练；原生 IPC/Linux futex 对等待定</td></tr>
    <tr><td style="padding:6px 10px;vertical-align:top;font-family:var(--font-mono)"><a href="../kernel/sched/lib.rs" style="color:var(--primary)">sched</a></td><td style="padding:6px 10px;vertical-align:top">每 CPU MLFQ/抢占/窃取/亲和/cpuset</td><td style="padding:6px 10px;vertical-align:top">UP/四 CPU 证据；长时/高核/性能待定</td></tr>
  </tbody>
</table>
</div>

[内核二进制](../kernel/src/main.rs) 将服务接线；[引导器](../bootloader/src/main.rs) 独立。[userspace](../userspace/) 含 libc 辅助、shell、musl/压力探针与客户机 fuzz 执行器。[fuzz](../fuzz/) 与 [tools/fuzz_executor](../tools/fuzz_executor/) 为宿主工具。

## 5. 能力与缺失契约

### 5.1 启动、内存与 VM

**已有：** UEFI 移交、重定位 PIE 内核、高半/恒等映射、内存保留、buddy/全局堆、计费可失败容器、guard、页缓存与 OOM 机制。匿名 mmap/munmap/mprotect/brk、PROT_NONE 与 COW fork 有真实用户态路径。RF180-20 修复了 fork/exec/拆除间共享监督页表所有权；完整四工人缓解负载已练此修复。

**缺失：** `sys_mmap` 仍接受除策略转发外未使用的 flags 参数；MAP_SHARED/MAP_FIXED 语义未实现。文件映射返回 EOPNOTSUPP；mremap 返回 ENOSYS。共享匿名内存、slab、NUMA、swap 与 THP 不是合格特性。压力 MAP_SHARED 报告页无法提供预期的 fork 共享通信。

**R186-4 仍开放：** MmState 映射已用 AdmittedMap，但 fork 在准入前分配快照，且 `from_sorted_vec_charged` 仍调用 `shrink_to_fit`。关闭需要机制评审、计费对称与 live-delta 测试，而非又一次容器迁移声明。责任人：**P0-A、ST-K2-P1/P2、U55-6**；[准入设计](review/design/p0-a-r186-4-admission-closure-design.md)。

### 5.2 进程、线程、调度与拆除

**已有：** 隔离地址空间、fork/路径 exec/exit/reap、wait4/WNOHANG、MLFQ/抢占/窃取/均衡/亲和/cpuset。TLS 恢复有含定时器上下文迁移的 UP/SMP musl 证据。KSA-011 练命名空间 wait 身份与六种 exit/reap/idle 情形。

**缺失：** clone 窄于 Linux 线程。CLONE_VM/TLS 设置存在；一般 CLONE_THREAD/CLONE_FILES/CLONE_FS/CLONE_SIGHAND 组合被拒绝。这**不是** pthread 支持。waitid 是桩。历史 fork 回退、栈碎片、switch-sentinel 与 PID1 孤儿/收割问题仍在；与较新 KSA 修复的重叠须按原始判定标准调和。责任人：**F2、F7、F4/F6、ROOT-INIT、F-4**。

### 5.3 IPC、信号、轮询与时间

**已有：** 能力支持的管道、阻塞/唤醒、带内部 PI 的 futex 原语、robust 清理、掩码、kill/tgkill、rt_sigaction/rt_sigreturn、IRQ 返回投递、基础 poll/select 与启动/时间调用。musl 练阻塞信号、robust usercopy 与零长度套接字行为。

**缺失：** 端点/消息类型不是完整原生同步 IPC 与共享内存。内部 futex 操作不是完整 Linux opcode/flag 对等。SA_RESTART 被接受但被中断调用可返回 EINTR；siginfo 最小、无 sigaltstack、排队实时信号不完整。未声明完成的 epoll/eventfd/timerfd 表面。责任人：**F-1c、F-2、F-4、F-10**。

### 5.4 安全框架与操作策略

**已有：** 能力权利/世代、凭据绑定的描述符发布、LSM/seccomp/pledge、防篡改审计与配置日志。命名空间与 O_TRUNC 探针测试精确回滚/数据保留。

**缺失：** native_cap_op/invoke/spawn 与委托端点/事件 API；TSYNC 在兄弟/clone 发布一致前被拒绝。全局 ADMIN 不是 per-netns 权威。审计持久化是无生产持久/远程后端的钩子。FIPS 策略/KAT 不是认证。[Livepatch 不支持](livepatch-support.md)：钩子、真实密钥、跨核同步与回滚鉴定是前置条件。责任人：**F-1b/F-1c、F-5、F-6、F-9、PO-SEC-01/02**。

### 5.5 硬件内存与推测执行加固

**已有：** NX/W^X、guard、SMEP/SMAP/UMIP、KASLR、usercopy、RNG/CSPRNG 与 kptr 脱敏。缓解状态区分已支持与活动控制。采集器检查生成代码、映射、CR3/CPL3 与完整四 vCPU fork/exec/wait 负载。

**缺失：** 双根仍保留内核数据/堆/栈与低别名。`FULL_KPTI_ISOLATION_SUPPORTED` 为 false：无完整 Meltdown 隔离。编译器 retpoline 不支持，其特性故意编译失败。早期启动 W+X 是独立生命周期债务。Balanced/QEMU 成功不定格每个 Secure 字段/CPU。责任人：**U37-1b、U55-6、SECURE-MATRIX**。KSA-020 关闭了如实报告/证明，而非这些未来特性。

### 5.6 VFS、描述符与存储

**已有：** ramfs、ext2/受限 JBD2、procfs/devfs/CPIO/cgroupfs、virtio-blk/owned BIO。fd 0/1/2 由表支持；dup/close/fork/exec/CLOEXEC、共享文件状态、O_NONBLOCK 消费者与数值 RLIMIT_NOFILE 有测试。组件路径、cwd/root 继承、chdir/chroot/pivot_root、DAC 宿主 ID、Ext2 32 位 UID/GID、挂载表退役与 O_TRUNC 拒绝有宿主/客户机证据。512B/4096B 逻辑块有专用检查。

**缺失：** 完整 ext4/POSIX 支持。chown/fchown/lchown、statx、硬链接与一般 dirfd 相对组合仍不完整/桩化。symlink/readlink 已存在：不要把它们重新规划为完全缺席。fsync/fdatasync/sync/sync_file_range 未接入分发。直写/JBD2 不是应用持久性系统调用契约。缓存错误/脏/回收、卸载同步/失效与掉电恢复需单独证明。责任人：**ST-K4、F-3、CACHE-DEBT、STORAGE-TESTS**。

### 5.7 网络

**已有：** virtio-net、Ethernet/ARP/IPv4/重组/ICMP/UDP/TCP、重传、NewReno/窗口缩放/SYN cookie、套接字、conntrack 与有状态默认 DROP 防火墙机制。进程上下文 RX 与命名空间所有的缓冲/地址/ARP 状态存在；当前宿主网络白名单有 118 项测试。

**缺失：** 根设备所有权是操作基线。`MOVE_NET_DEVICE_ARMED=false` 在命名空间 FD 权威、世代与排空/撤销存在前将转移保持为 ENOSYS。veth、子 RX 导向、一般路由表管理、per-netns 防火墙管理与完整 loopback 投递仍开放。缺 IPv6、更广 NIC/控制接口。延期 NIC/根 MAC 测试需要可运行配置；解析器/宿主测试不证明线缆连通。责任人：**NET-QUAL、F-7/F-9、D3-NETNS**。

### 5.8 SMP、设备与 IOMMU

**已有：** APIC/AP 启动、每 CPU 调度、IPI/TLB shootdown、PCID/INVPCID 辅助、RCU 与锁序。四 CPU 证据存在；扩展脚本定义 8/16 CPU 运行。CPU-local 支持 64 逻辑 CPU 上限；x2APIC 当前路径不支持。

DMAR 在启动时接线。Q35 初始化/构造器/SIRTP/IR/TE 失败与 EDU 翻译 DMA、替换、重映射 MSI、无效请求、隔离、分离与 IRTE 复用有范围 QEMU 证据。旧的「DMAR 未连接」声明已过时。

**缺失：** 物理端点/MSI-X、多 DRHD/桥/非零段路由、RMRR 映射、可扩展模式、ATS/PASID 与 ACCESS_PLATFORM virtio 鉴定。无 IOMMU 启动不是隔离 DMA。缓解单线程 TCG/四 vCPU 证明不是宿主并行 SMP 鉴定。责任人：**P3-2、F-7、SMP-QUAL**；[设备矩阵](vtd-support-matrix.md)。

### 5.9 容器与资源

**已有：** PID/mount/IPC/net/user 对象/继承、事务性分配/退役、选定 CPU/内存/PID/I/O/文件/端口控制器、cpuset 与类/命名空间预算。失败/四 CPU 近限探针恢复精确计数/堆；cgroupfs 暴露已支持控制。

**缺失：** 完整 cgroups-v2/OCI、cgroup 命名空间/委托、全部命名空间 FD/setns/unshare/clone 组合与容器网络。PID1 根 cgroup 成员资格仍在跟踪。非 NOFILE rlimit 大多是建议性的；kmem/slab/conntrack 记账与 ABI 暴露需完成。责任人：**ST-K1、F-7/F-8/F-9、PO-ISO-01**。

### 5.10 用户模式、Linux ABI 与工具

**已有：** Linux 编号子集/私有调用、ELF64 ET_EXEC、SysV 栈/auxv、静态 musl、libc 辅助与开发 shell。musl 测试实际 Ring-3 行为；ABI 判定对照 C 检查选定布局。QEMU fuzz 适配器启动真实客户机并认证两份输入、覆盖与磁盘/镜像身份。

**缺失：** 用户空间 ET_DYN 被拒绝；ld.so/PT_INTERP、动态重定位、完整用户空间 PIE/ASLR/vDSO 不是工作链。无一般 glibc、pthread、BusyBox 发行、OCI 或 personality 验收。原生能力系统调用与同步 IPC 先于 personality 工作。责任人：**F-1b/F-1c/F-2/F-3/F-4/F-10**。

### 5.11 可观测性、测试与性能

**已有：** 计数器/tracepoint/看门狗/profiler/串口 kdump、带宿主根权威的任务 KCOV、命令/输入/镜像身份、Markdown/JUnit 与 Python 工具覆盖。Debug/release 宿主与特性特定 QEMU 镜像分离。五种结果与严格拒绝已实现。

**缺失：** 持久遥测与可测量性能包络。性能脚本推迟未测量负载；melting 脚本含模拟/框架路径，非硬件鉴定。压力块在 `fsync_unsupported` 显式失败；无完整六配置成功被接受。手工 KCOV 与源码发现测试不是全指令/ABI 覆盖。责任人：**ST-K2/ST-K4、PERF-BASELINE、F-6/F-9**。

## 6. 相对 Linux 的差距分析

<div style="overflow-x:auto;margin:0.75em 0">
<table style="width:100%;border-collapse:collapse;font-size:0.88em;font-family:var(--font-sans);background:var(--card);color:var(--card-foreground);border:1px solid var(--border);border-radius:var(--radius)">
  <thead>
    <tr style="background:var(--muted);color:var(--muted-foreground);text-align:left">
      <th style="padding:8px 10px;border-bottom:1px solid var(--border);width:16%">域</th>
      <th style="padding:8px 10px;border-bottom:1px solid var(--border);width:42%">Nilix 现状</th>
      <th style="padding:8px 10px;border-bottom:1px solid var(--border)">下一边界</th>
    </tr>
  </thead>
  <tbody>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">内存</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">Buddy/堆/计费映射/匿名/COW</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">准入、诚实 flags、共享/文件映射；其后 slab/NUMA/swap</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">进程</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">静态程序/fork/exec/wait/受限 clone</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">在声称 pthread 前先做线程/信号/wait 保真</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">存储</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">ramfs/ext2/JBD2/命名空间 VFS</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">持久性/恢复、dirfd/元数据与文件系统广度</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">网络</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">IPv4/TCP/UDP/策略/virtio</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">线缆测试、命名空间链路/路由/管理、IPv6/驱动</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">容器</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">五类命名空间/选定控制器</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">委托/共享内存/FS 共享/OCI</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">安全</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">能力/LSM/seccomp/缓解机制</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">隔离配置/硬件/TSYNC/密钥/后端</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">用户空间</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">静态 musl 子集/shell</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">原生 IPC/personality/动态/vDSO/glibc/应用</td></tr>
    <tr><td style="padding:7px 10px;font-weight:var(--font-chat-strong-weight)">运维</td><td style="padding:7px 10px">日志/trace/KCOV/CI 回执</td><td style="padding:7px 10px">持久审计、可复现压力/性能、发布</td></tr>
  </tbody>
</table>
</div>

## 7. 阶段编年（A–U）

历史阶段描述已交付基础，**不是**完整子系统验收。

<div style="overflow-x:auto;margin:0.75em 0">
<table style="width:100%;border-collapse:collapse;font-size:0.88em;font-family:var(--font-sans);background:var(--card);color:var(--card-foreground);border:1px solid var(--border);border-radius:var(--radius)">
  <thead>
    <tr style="background:var(--muted);color:var(--muted-foreground);text-align:left">
      <th style="padding:8px 10px;border-bottom:1px solid var(--border);width:12%">阶段</th>
      <th style="padding:8px 10px;border-bottom:1px solid var(--border);width:44%">已交付基础</th>
      <th style="padding:8px 10px;border-bottom:1px solid var(--border)">剩余工作</th>
    </tr>
  </thead>
  <tbody>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">A</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">入口/usercopy/硬件加固/审计</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">完整隔离/平台鉴定</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">B</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">能力/LSM/系统调用策略</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">原生 API/TSYNC/权威广度</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">C</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">VFS/块/ext2/缓存/OOM</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">持久性/恢复/POSIX 广度</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">D</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">IPv4/conntrack/防火墙</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">线缆/命名空间/控制面广度</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">E</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">SMP/调度器/IPI/TLB/RCU/futex</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">长时/高核测试/线程契约</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">F</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">命名空间/控制器/VT-d</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">准入/共享内存/委托</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">G</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">KASLR/双根/可观测性/合规/补丁实验</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">完整 KPTI/后端；livepatch 不支持</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">H.0 / H</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">结构/ABI 审计/隔离加固</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">对变更入口/MM/所有权重验证</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">I</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">策略/DMA/启动/日志卫生</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">I.3/I.4/I.5/I.7、netns 预武装</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">J</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">资源/租户可观测性</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">J.2 kmem/控制器扩展</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);font-weight:var(--font-chat-strong-weight)">K / L / M</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">兼容性/性能/企业方向</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">下游积压</td></tr>
    <tr><td style="padding:7px 10px;font-weight:var(--font-chat-strong-weight)">U</td><td style="padding:7px 10px">静态 Ring-3 ABI/部分原生 cap 接线</td><td style="padding:7px 10px">IPC/personality/动态/应用链</td></tr>
  </tbody>
</table>
</div>

## 8. 1.0-Preview 发布门禁

**BLOCKED；清洁全量审计连胜 0/3。** 本次滚动或绿色 Actions **都不**创造新的全量清洁审计轮次。

<div style="overflow-x:auto;margin:0.75em 0">
<table style="width:100%;border-collapse:collapse;font-size:0.88em;font-family:var(--font-sans);background:var(--card);color:var(--card-foreground);border:1px solid var(--border);border-radius:var(--radius)">
  <thead>
    <tr style="background:var(--muted);color:var(--muted-foreground);text-align:left">
      <th style="padding:8px 10px;border-bottom:1px solid var(--border);width:38%">要求</th>
      <th style="padding:8px 10px;border-bottom:1px solid var(--border)">处置</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">R186-4 / P0-A / D1-RES-HEAP-ADMISSION-REOPENED</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top"><span style="color:var(--destructive);font-weight:var(--font-chat-strong-weight)">开放</span>；准入前分配/shrink 与验收义务仍在</td>
    </tr>
    <tr>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">R188 原始评审谱系</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">较新范围 KSA 记录中缺完整原始细则映射；调和/评审未覆盖原文，复用已证明重叠</td>
    </tr>
    <tr>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">声称范围内无未解 Critical/High；三轮清洁</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">未建立；连胜不变</td>
    </tr>
    <tr>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">全部 6 个 stress-v2 配置</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">2026-09-01 用户决定所要求；memory/cpu/smp/process/block/combined 验收待定</td>
    </tr>
    <tr>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">严格安全/平台策略</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">结果如实已实现；延期前置条件仍阻塞鉴定</td>
    </tr>
    <tr>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">ABI/设备/缓解矩阵</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">保留支持/拒绝/建议以及物理/完整隔离限制</td>
    </tr>
    <tr>
      <td style="padding:7px 10px;vertical-align:top">CI 结果/保留证据</td>
      <td style="padding:7px 10px;vertical-align:top">e127c34 的 hosted vfs 计数修复等待重跑；QEMU 瞬态与解析修复也等待完整运行证据</td>
    </tr>
  </tbody>
</table>
</div>

五项 KSA P0 修复与 KSA-007..020 细则在范围内已接受。它们是回归义务，**不是**仍开放的实现任务。

## 9. 当前执行 — 阶段 U / 静态 ABI

<div style="overflow-x:auto;margin:0.75em 0">
<table style="width:100%;border-collapse:collapse;font-size:0.88em;font-family:var(--font-sans);background:var(--card);color:var(--card-foreground);border:1px solid var(--border);border-radius:var(--radius)">
  <thead>
    <tr style="background:var(--muted);color:var(--muted-foreground);text-align:left">
      <th style="padding:8px 10px;border-bottom:1px solid var(--border);width:22%">里程碑</th>
      <th style="padding:8px 10px;border-bottom:1px solid var(--border);width:46%">状态</th>
      <th style="padding:8px 10px;border-bottom:1px solid var(--border)">依赖</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)">U.M0 / U.S1</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">静态 musl、不相交路径 exec/原生镜像 spawn 已交付；范围修复已接受</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">保持 ELF/usercopy/musl</td>
    </tr>
    <tr>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)">U.S2 3A/3B</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">管道能力 ID/FileOps 接线已交付</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">原生系统调用族不完整</td>
    </tr>
    <tr>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)">U.S2 4/5 (F-1b)</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">native_cap_op/filter/世代契约待定</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">准入/权威门</td>
    </tr>
    <tr>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)">U.S2 6/7 (F-1c)</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">invoke/spawn、端点/事件待定</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">U.S3 IPC 设计</td>
    </tr>
    <tr>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)">U.S3 (F-2)</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">同步 IPC/共享内存/生命周期/SMP 待定</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">能力族/MM 所有权</td>
    </tr>
    <tr>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)">U.S4 (F-10)</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">用户空间 personality 已规划</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">U.S3/已评审信任边界</td>
    </tr>
    <tr>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--font-mono)">U.S5 (F-10)</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">动态链接/用户 PIE/ASLR/vDSO 已规划</td>
      <td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">静态 ABI/ELF/MM 契约</td>
    </tr>
    <tr>
      <td style="padding:7px 10px;vertical-align:top;font-family:var(--font-mono)">U.S6/U.S7 (F-10)</td>
      <td style="padding:7px 10px;vertical-align:top">glibc/应用/OCI 方向</td>
      <td style="padding:7px 10px;vertical-align:top">动态 ABI/线程/信号/存储/网络</td>
    </tr>
  </tbody>
</table>
</div>

## 10. 后续路线

**下一组：** 调和 R188 评审谱系，关闭 R186-4 准入，完成 ST-K2 阶段 1 flags/报告传输与 ST-K4 持久性/块负载。[当前交接说明](review/design/next-handoff-2026-09-12.md) 保留先前设计选择并标识前提已变的评审要求。

**然后：** 共享匿名内存、全部 6 个压力配置、严格网络/SMP/Secure 证据与全量审计鉴定。物理 VT-d 仍是平台依赖；独立软件工作可继续。

**鉴定之后：** F-1b..F-10、静态 ABI 残差、原生 IPC/personality、动态链接、容器网络、遥测与可测量性能。这些是能力里程碑，**无**不受支持的日历承诺。

## 11. 审计与修复历史

<div style="overflow-x:auto;margin:0.75em 0">
<table style="width:100%;border-collapse:collapse;font-size:0.88em;font-family:var(--font-sans);background:var(--card);color:var(--card-foreground);border:1px solid var(--border);border-radius:var(--radius)">
  <thead>
    <tr style="background:var(--muted);color:var(--muted-foreground);text-align:left">
      <th style="padding:8px 10px;border-bottom:1px solid var(--border);width:28%">记录</th>
      <th style="padding:8px 10px;border-bottom:1px solid var(--border)">已接受范围 / 剩余限制</th>
    </tr>
  </thead>
  <tbody>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">R186 / RF186</td><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">16/17 历史可操作项已修；R186-4 准入结转</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">R187 / RF187</td><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">7 项 KCOV 发现 / 8 项修复缺陷关闭；结转债务阻止连胜记分</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">R188 独立</td><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">8 月补救已记录；残差/原始评审谱系分开</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">KSA-2026-09-06</td><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">20/20 范围发现已接受；RF180-20 页表所有权已修</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">P3-2，9 月 12 日</td><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">QEMU EDU DMA/MSI/失效/故障切片已接受；物理行待定</td></tr>
    <tr><td style="padding:7px 10px;vertical-align:top">9 月 CI 清理</td><td style="padding:7px 10px;vertical-align:top">共享组/报告、宿主/harness/真实客户机测试、分类脚本；运行时预算后续</td></tr>
  </tbody>
</table>
</div>

[安全状态](security-audit-status.md) 分离这些历史。历史累计总数**不是**当前漏洞普查。本次滚动不创造新的审计或独立修复裁决。

## 12. 已知债务与守恒原则

[现行计划](review/nextplan/next-phase-plan-2026-09-12.md) 恢复 KSA 队列以及 P0-A/P1-A、ST-K1..K4/ST-5/ST-6、F2/F7/F4-F6/F10/F11/wait 残差、U37-1a/U37-1b/U55-6/U29-3、D3 网络/TSYNC/ARC、R186 设计行、四条开放 PO 记录、P3 测试与 F-1b..F-10。

重叠仅按细则关闭：KSA-008 关闭结果记账，而非全部延期执行；KSA-011 覆盖命名空间 wait 身份，而非全部 waiter 效率；QEMU IRTE 复用不定格一般 VM 直通。

## 13. 测试、CI 与模糊测试

<div style="overflow-x:auto;margin:0.75em 0">
<table style="width:100%;border-collapse:collapse;font-size:0.88em;font-family:var(--font-sans);background:var(--card);color:var(--card-foreground);border:1px solid var(--border);border-radius:var(--radius)">
  <thead>
    <tr style="background:var(--muted);color:var(--muted-foreground);text-align:left">
      <th style="padding:8px 10px;border-bottom:1px solid var(--border);width:18%">层</th>
      <th style="padding:8px 10px;border-bottom:1px solid var(--border);width:42%">证据</th>
      <th style="padding:8px 10px;border-bottom:1px solid var(--border)">限制</th>
    </tr>
  </thead>
  <tbody>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-weight:var(--font-chat-strong-weight)">源码/构建</td><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">fmt/Clippy/lint/ABI C 判定/构建/已链接 usercopy</td><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">非运行时完备</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-weight:var(--font-chat-strong-weight)">宿主</td><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">每配置 438 次计入执行、CpuLocal doctest、三项编译检查</td><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">宿主安全白名单；特权路径仅客户机</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-weight:var(--font-chat-strong-weight)">Harness</td><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">Python JUnit/覆盖、shell 语法、结果/解析器回归</td><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">宿主覆盖，非内核指令覆盖</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-weight:var(--font-chat-strong-weight)">必选 QEMU</td><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">Boot/runtime/SMP、UP/四 CPU musl、IOMMU/缓解/KCOV/两种子 smoke</td><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">合格结果/模拟器范围保留</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-weight:var(--font-chat-strong-weight)">扩展</td><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">Ubuntu 22.04/24.04、8/16 CPU、Ext3/JBD2、六个压力配置</td><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">计划/手工；压力验收不完整</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top;font-weight:var(--font-chat-strong-weight)">战役</td><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">11 个计划 libFuzzer 目标、语料/不透明发现</td><td style="padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top">采样不是无 bug/ABI 完备</td></tr>
    <tr><td style="padding:7px 10px;vertical-align:top;font-weight:var(--font-chat-strong-weight)">硬件/性能</td><td style="padding:7px 10px;vertical-align:top">具名矩阵/协议与未来判定</td><td style="padding:7px 10px;vertical-align:top">物理 VT-d/性能/热证据待定</td></tr>
  </tbody>
</table>
</div>

命令：[CI 指南](ci-testing.md)、[质量门](quality-gates.md)、[脚本图](../scripts/README.md)。客户机观察默认 900 秒；作业预算含顺序窗口/准备/构建/产物。短 mock 单元截止**不**缩短真实客户机执行。

## 14. 风险与依赖

首要风险是压力下的所有权/记账、把部分 Linux 语义误当作兼容性、缺严格配置前置条件，以及宽于实测证据的硬件声明。保留精确源码/镜像身份与失败/拆除测试。Livepatch、netns 设备转移、完整隔离与 retpoline **不得**通过文档变更启用。

新设备/信任边界模式需要设计、负向测试与独立评审。复用已接受设计前检查前提是否改变；硬件不可用不阻塞独立软件任务。

## 15. 版本历史与导航

<div style="overflow-x:auto;margin:0.75em 0">
<table style="width:100%;border-collapse:collapse;font-size:0.88em;font-family:var(--font-sans);background:var(--card);color:var(--card-foreground);border:1px solid var(--border);border-radius:var(--radius)">
  <thead>
    <tr style="background:var(--muted);color:var(--muted-foreground);text-align:left">
      <th style="padding:8px 10px;border-bottom:1px solid var(--border);width:22%">修订</th>
      <th style="padding:8px 10px;border-bottom:1px solid var(--border)">变更</th>
    </tr>
  </thead>
  <tbody>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border)">4.x</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">统一开发/企业细节与历史阶段</td></tr>
    <tr><td style="padding:7px 10px;border-bottom:1px solid var(--border)">5.4，9 月 10 日</td><td style="padding:7px 10px;border-bottom:1px solid var(--border)">中间 KSA 快照；后续验收/更早积压未调和</td></tr>
    <tr><td style="padding:7px 10px">6.0，9 月 12 日</td><td style="padding:7px 10px">恢复组件/阶段/发布细节、当前缺口/证据与守恒积压</td></tr>
  </tbody>
</table>
</div>

[README](../README.md) · [文档](README.md) · [架构](architecture.md) · [Nextplan](next-phase-plan.md) · [安全](security-audit-status.md) · [CI](ci-testing.md)
