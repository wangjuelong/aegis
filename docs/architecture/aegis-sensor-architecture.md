# Aegis Sensor 架构设计文档

> 版本：1.0  
> 日期：2026-04-09  
> 状态：草稿  
> 分类：内部 / 机密  
> 依赖文档：aegis-architecture-design.md、sensor-final技术解决方案.md
>
> 当前代码实现口径的分平台采集清单见：
> - [Windows 数据采集清单](./aegis-sensor-windows-data-collection.md)
> - [Linux 数据采集清单](./aegis-sensor-linux-data-collection.md)

---

## 目录

1. [概述与定位](#1-概述与定位)
2. [设计原则与约束](#2-设计原则与约束)
3. [总体架构](#3-总体架构)
4. [模块详细设计](#4-模块详细设计)
   - 4.1 内核态模块
   - 4.2 用户态核心引擎
   - 4.3 本地检测引擎
   - 4.4 响应执行引擎
   - 4.5 通信模块
   - 4.6 自保护模块
   - 4.7 插件隔离架构
   - 4.8 攻击故事线引擎
   - 4.9 扩展能力模块
5. [数据流设计](#5-数据流设计)
6. [性能设计](#6-性能设计)
7. [安全设计](#7-安全设计)
8. [部署与运维](#8-部署与运维)
9. [接口定义](#9-接口定义)
10. [技术选型说明](#10-技术选型说明)

---

<a id="1-概述与定位"></a>
## 1. 概述与定位

### 1.1 产品定位

Aegis Sensor 是 Aegis EDR 平台的终端组件（Endpoint Agent），部署在 Windows、Linux 和 macOS 终端上，负责实时数据采集、本地检测、威胁响应和遥测上报。作为平台的"眼睛和手"，Sensor 在整个五平面架构中承担终端平面（Endpoint Plane）的全部职责。

### 1.2 核心职责

| 职责域 | 具体能力 |
|--------|----------|
| **数据采集** | 通过内核态 Hook 实时捕获进程、文件、网络、注册表、认证、脚本、内存、容器等 8 类事件 |
| **本地检测** | 6 阶段流水线：快速过滤 -> IOC 匹配 -> 规则引擎 -> YARA 扫描 -> ML 推理 -> 状态关联 |
| **威胁响应** | 进程 Suspend/Kill、文件隔离、网络隔离、注册表/文件系统回滚、实时取证、远程 Shell |
| **遥测上报** | 三路 gRPC 通道（高优先级/常规/大文件）+ WAL 离线缓冲 + 通信隐蔽回退链 |
| **攻击面收缩** | ASR 规则、设备控制、端点防火墙、预防性阻断 |
| **自保护** | 四层纵深防御：内核级保护 + 完整性校验 + 看门狗 + 反篡改 |
| **离线自治** | 与云端断连时保持完整本地检测、响应与审计能力 |
| **扩展能力** | 欺骗防御、身份威胁检测、漏洞评估、被动网络发现、AI 应用监控、WASM 插件 |

### 1.3 规模与对标

- **终端规模**：支持 100 万终端部署
- **日事件量**：平台总计 >= 500 亿事件/天，单终端约 500 events/min
- **对标产品**：CrowdStrike Falcon、Microsoft Defender for Endpoint、SentinelOne Singularity

### 1.4 文档范围

本文档聚焦于 Aegis Sensor 自身的架构设计，包含内核态采集、用户态引擎、检测流水线、响应执行器、通信子系统、自保护机制、插件架构和运维相关设计。云端分析平面、数据平面和管理平面的架构请参考 `aegis-architecture-design.md`。

---

<a id="2-设计原则与约束"></a>
## 2. 设计原则与约束

### 2.1 核心设计原则

| 原则 | 说明 | 落地约束 |
|------|------|----------|
| **最小特权** | 内核驱动仅做数据采集与事件投递；所有策略逻辑在用户态执行 | 代码评审 + 设计评审闸门 |
| **故障隔离** | Sensor、Detection、Response、Comms 运行在独立线程池/进程；插件通过 WASM 沙箱隔离 | 进程模型 + watchdog |
| **零信任通信** | Agent <-> Cloud 全链路 mTLS；本地存储 AES-256-GCM；敏感内存 mlock+zeroize；密钥绑定 TPM/Secure Enclave | 证书生命周期自动化 |
| **热更新** | 规则、ML 模型、Sensor 插件、配置均可在线热加载，无需重启 Agent 或内核驱动 | 带签名的原子替换与回滚 |
| **可观测性** | Agent 暴露健康指标（CPU/Mem/队列深度/丢事件计数）随心跳上报；端到端 event lineage_id 贯穿全链路 | lineage 检查点计数器 |
| **跨平台一致性** | 用户态核心用 Rust 单一代码库，通过条件编译 + 平台 Sensor Trait 适配三平台 | 平台 trait 接口 |
| **明确保护边界** | Agent 自保护覆盖 Ring 3 防御 + Ring 0 检测（不承诺 Ring 0 防御），文档中显式声明 | 文档 + 安全模型 |
| **自适应反馈** | 云端确认的误报自动回填到本地白名单，降低后续检测开销 | 反馈闭环子系统 |
| **离线自治** | 与云端断连时保留完整本地检测、缓存、响应与审计能力 | WAL + 本地规则/模型缓存 |
| **攻击面收缩** | Agent 不仅检测与响应，还通过 ASR、设备控制、防火墙策略主动缩减攻击面 | ASR 规则引擎 + 设备控制 |
| **不可变性** | 所有数据转换都生成新对象；不对共享状态做原地修改 | Rust 所有权模型 + 代码评审 |

### 2.2 质量属性目标

| 类别 | 指标 | 目标 |
|------|------|------|
| CPU 占用（稳态 P95） | <= 2% |
| CPU 占用（全量 profile P95） | <= 3% |
| CPU 占用（峰值 P99） | <= 6% |
| 内存 RSS（基础） | <= 150 MB |
| 内存 RSS（全量 profile） | <= 220 MB |
| 网络带宽（均值） | <= 60 KB/s |
| 磁盘写入（均值） | <= 5 MB/s |
| 安装包大小 | <= 75 MB |
| 本地检测 P50 时延 | < 20 us |
| 本地检测 P99 时延 | < 200 us |
| 事件处理吞吐 | >= 350K event/s |
| CRITICAL 事件丢失率 | 0% |
| 全局事件丢失率 | < 0.01% |
| MITRE ATT&CK 覆盖率 | >= 85% |
| Agent 崩溃率 | <= 0.01%/month |
| Agent 启动时间 | < 5s |
| 离线检测能力 | 100%（本地完整检测链可用） |

### 2.3 设计约束

1. **语言约束**：用户态统一使用 Rust（内存安全 + 性能）；内核态 Windows 使用 C/WDM，Linux 使用 eBPF/C，macOS 使用 Swift/ObjC（System Extension）
2. **二进制约束**：单一可执行文件 + 内核驱动 + 看门狗 + 升级器，共 4 个独立组件
3. **内核态最小化**：内核代码仅做 Hook/Filter/Deliver/Guard 四件事，严禁在内核态实现策略逻辑
4. **向后兼容**：Windows 10 1809+、Linux kernel 4.14+（完整 eBPF 需 5.8+）、macOS 12+
5. **安全合规**：Agent 二进制全链路代码签名；驱动 WHQL/DKMS 签名；更新包签名校验

---

<a id="3-总体架构"></a>
## 3. 总体架构

### 3.1 进程模型

Aegis Sensor 运行时由三个 OS 级进程和一个内核态组件组成：

```
┌─────────────────────────────────────────────────────────────────────┐
│                        操作系统进程视图                               │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  aegis-sensor (主进程, Rust)                          PID 1001│    │
│  │  ├── main thread        — Orchestrator 事件循环             │    │
│  │  ├── sensor-dispatch    — Sensor 事件分发 (从 Ring Buffer)  │    │
│  │  ├── detection-pool[0..N] — 本地检测引擎工作线程            │    │
│  │  ├── response-executor  — 响应动作执行线程                  │    │
│  │  ├── comms-tx-high      — 高优先级上行 (CRITICAL/HIGH)      │    │
│  │  ├── comms-tx-normal    — 普通上行 (batched telemetry)      │    │
│  │  ├── comms-rx           — 下行命令接收 (gRPC stream)        │    │
│  │  ├── comms-wal          — WAL 持久化/重放线程               │    │
│  │  ├── config-watcher     — 配置/策略热更新监听               │    │
│  │  ├── health-reporter    — 自身健康指标采集+心跳             │    │
│  │  ├── lineage-tracker    — 端到端事件溯源追踪                │    │
│  │  ├── feedback-loop      — 云端误报反馈 → 本地白名单同步     │    │
│  │  ├── storyline-engine   — 攻击故事线自动构建                │    │
│  │  ├── snapshot-manager   — 卷快照 / 回滚点管理               │    │
│  │  ├── asr-enforcer       — 攻击面削减规则执行                │    │
│  │  ├── device-control     — USB / 外设 / 存储介质管控         │    │
│  │  ├── deception-manager  — 蜜标 / 诱饵管理                   │    │
│  │  ├── vuln-scanner       — 本地漏洞评估                      │    │
│  │  ├── network-discovery  — 被动网络设备发现                  │    │
│  │  ├── ai-monitor         — 本地 AI 应用安全监控              │    │
│  │  └── plugin-host[0..M]  — WASM 沙箱隔离的 Sensor 插件宿主  │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────┐      │
│  │  aegis-sensor-watchdog (看门狗, Rust, PPL 保护)      PID 1002│      │
│  │  ├── 监控主进程存活                                        │      │
│  │  ├── 二进制完整性校验                                      │      │
│  │  ├── 内核完整性监控 (SSDT/IDT/回调表 hash)                │      │
│  │  └── 崩溃自动重启 + 核心转储上传                           │      │
│  └───────────────────────────────────────────────────────────┘      │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────┐      │
│  │  edr-updater (升级器, Rust)        PID 1003 (按需启动)     │      │
│  │  ├── 增量包下载 + 签名验证 (支持跨版本全量 fallback)       │      │
│  │  ├── A/B 分区切换 + Schema Migration                      │      │
│  │  └── 回滚逻辑 + 灰度健康 Gate                             │      │
│  └───────────────────────────────────────────────────────────┘      │
│                                                                     │
│  ════════════════════ 内核态 ════════════════════                    │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────┐      │
│  │  aegis-sensor-kmod (内核驱动/eBPF)                         │      │
│  │  ├── 事件采集 Hook 点                                      │      │
│  │  ├── MPSC Ring Buffer (零拷贝到用户态, 优先级保留)         │      │
│  │  ├── 网络过滤 (隔离执行)                                   │      │
│  │  ├── ETW/BPF 完整性看门狗                                  │      │
│  │  ├── VSS / 文件系统快照保护                                │      │
│  │  └── 设备过滤 / 存储访问控制                               │      │
│  └───────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 架构分层

Sensor 在逻辑上分为四个层次，自下而上：

```
┌────────────────────────────────────────────────────────────────────┐
│                        应用层 (扩展能力)                              │
│  ASR | 设备控制 | 欺骗防御 | 漏洞评估 | 网络发现 | AI 监控 | 插件  │
├────────────────────────────────────────────────────────────────────┤
│                        引擎层 (核心处理)                              │
│  检测流水线 | 响应执行器 | 故事线引擎 | 反馈闭环 | 进程树缓存      │
├────────────────────────────────────────────────────────────────────┤
│                        平台层 (数据传输与管理)                        │
│  通信模块(gRPC/WAL) | 配置管理 | 健康上报 | 升级管理 | 自保护      │
├────────────────────────────────────────────────────────────────────┤
│                        采集层 (内核态 + 用户态传感器)                  │
│  进程 | 文件 | 网络 | 注册表 | 认证 | 脚本 | 内存 | 容器           │
│  MPSC Ring Buffer (零拷贝, 4 优先级通道, 64MB)                     │
└────────────────────────────────────────────────────────────────────┘
```

### 3.3 内部数据流总览

```
内核态事件源                  用户态
─────────────────────────────────────────────────────────────────
                              ┌─────────┐
ETW / kprobe / ESF ──────────→│         │
Minifilter / fanotify ───────→│  MPSC   │   ┌──────────────┐
WFP / eBPF sock ─────────────→│  Ring   ├──→│ Sensor       │
CmCallback / LSM Hook ──────→│ Buffer  │   │ Dispatch     │
AMSI / audit ────────────────→│ (mmap)  │   │ (解码+归一化 │
                              │         │   │  +lineage_id)│
                              └─────────┘   └──────┬───────┘
                                                   │
                              ┌─────────────────────▼──────────────────┐
                              │          Event Pipeline (lockfree)      │
                              │                                        │
                              │  ┌──────────┐    ┌──────────────────┐  │
                              │  │ Enricher │    │ Local Detection  │  │
                              │  │ (进程树  │───→│ Engine           │  │
                              │  │  上下文  │    │ ┌──────────────┐ │  │
                              │  │  填充)   │    │ │ Stage 0-5    │ │  │
                              │  └──────────┘    │ │ 6 阶段流水线 │ │  │
                              │                  │ └──────┬───────┘ │  │
                              │  ┌──────────┐    └────────┼────────┘  │
                              │  │ Feedback │←────────────┘           │
                              │  │ Loop     │              │           │
                              │  └──────────┘   ┌──────────▼──────┐   │
                              │                 │ Decision Router  │   │
                              │                 │ BENIGN/SUSPICIOUS│   │
                              │                 │ MALICIOUS/CRITICAL│  │
                              │                 └──┬────┬────┬────┘   │
                              └────────────────────┼────┼────┼────────┘
                                                   │    │    │
                              ┌─────────────────────▼────▼──┐ │
                              │  Comms Module                │ │
                              │  WAL + gRPC (Hi/Norm/Bulk)   │ │
                              └──────────────────────────────┘ │
                                                               │
                              ┌─────────────────────────────────▼──┐
                              │  Response Executor                  │
                              │  Suspend → Kill / Quarantine /      │
                              │  Isolate / Rollback / Forensic      │
                              └────────────────────────────────────┘
```

---

<a id="4-模块详细设计"></a>
## 4. 模块详细设计

### 4.1 内核态模块

#### 4.1.1 设计哲学

内核驱动/eBPF 程序**只做四件事**：

1. **Hook** -- 挂载到操作系统事件源
2. **Filter** -- 在内核态做最小化前置过滤（减少用户态负载）
3. **Deliver** -- 通过零拷贝 MPSC Ring Buffer 投递事件到用户态
4. **Guard** -- 监控自身及操作系统关键结构的完整性

所有策略判断、检测逻辑、响应决策**一律在用户态**完成，最大限度降低内核态代码复杂度和 BSOD/Kernel Panic 风险。

**保护边界声明**：Agent 内核态组件能够**防护** Ring 3 攻击者（阻断其对 Agent 的篡改），但对 Ring 0 攻击者仅提供**检测**能力（发现 rootkit/内核篡改后上报告警），不保证防护。

#### 4.1.2 传感器子系统概览

八类传感器，按平台有不同实现：

| 传感器 | Windows | Linux | macOS | 采集粒度 |
|--------|---------|-------|-------|----------|
| 进程 | ETW + PsSetCreateProcessNotifyRoutineEx2 + ObRegisterCallbacks + Direct Syscall Detection | kprobe/tracepoint sched_process_exec/exit/fork + kprobe commit_creds + LSM bprm_check_security + mmap hooks | ESF AUTH_EXEC + NOTIFY_EXEC/FORK/EXIT | 进程树、命令行、环境变量、签名、PE/ELF 元数据、PPL 等级 |
| 文件 | Minifilter (IRP_MJ_CREATE/WRITE/SET_INFO/CLEANUP) + Pre/Post callbacks | fentry vfs_write/rename/unlink + security_file_open (LSM) + fanotify | ESF AUTH_OPEN/RENAME/UNLINK + NOTIFY_WRITE/CLOSE | 路径、SHA256、熵值、magic bytes、所属进程 |
| 网络 | WFP Callout (ALE_AUTH_CONNECT/RECV_ACCEPT/FLOW_ESTABLISHED + OUTBOUND_TRANSPORT) + ETW DNS Client | kprobe tcp_connect/inet_csk_accept + tracepoint sock/inet_sock_set_state + TC/XDP + 内核 DNS 解析 | Network Extension + NEFilterDataProvider | 五元组、DNS query/response、SNI、JA3/JA3S |
| 注册表 | CmRegisterCallbackEx (RegNtPreSetValueKey 等) + Registry Change Journal (SQLite, 7d/100MB FIFO) | N/A | N/A | Key/Value 路径、操作类型、旧值/新值、PID |
| 认证 | Security Event Log (4624/4625/4672/4768) | PAM uprobe + audit + /var/log/auth.log | OpenDirectory + ESF NOTIFY_OPENSSH_LOGIN | 登录类型、源 IP、权限提升、Kerberos TGT/TGS |
| 脚本 | AMSI Provider + AMSI Bypass Detection | bash PROMPT_COMMAND + eBPF uretprobe | ESF | 完整脚本内容（解混淆后）、解释器 PID |
| 内存 | VirtualAlloc/NtMapViewOfSection Hook + YARA scan | process_vm_readv + YARA | mach_vm_read | 可疑内存区域转储、注入检测 |
| 容器 | N/A | eBPF + cgroup_id + namespace ID + CRI socket query | N/A | Pod/Container 元数据、逃逸检测 |

**附加监控能力：**

- **Named Pipe / IPC 监控**：Windows ETW + Minifilter on \Device\NamedPipe\；Linux AF_UNIX 监控。捕获 Cobalt Strike、Metasploit 等框架常见 IPC 通道行为
- **DLL 加载深度监控**：PsSetLoadImageNotifyRoutineEx，用于 sideloading / search order hijack / phantom DLL 检测
- **VSS / 文件系统快照保护**：拦截快照删除，周期性每 4 小时创建一次快照，保留 3 份
- **设备控制**：USB/可移动介质/Bluetooth/Thunderbolt；策略支持 ALLOW/BLOCK/READ_ONLY/AUDIT/ALLOW_APPROVED

#### 4.1.3 Windows 内核驱动栈

```
aegis-sensor-kmod.sys (WDM Minifilter + WFP Callout + ETW Provider)
│
├── Process Monitor
│   ├── PsSetCreateProcessNotifyRoutineEx2
│   │   → 进程创建/退出，含完整 ImageFileName、CommandLine、Token 信息
│   ├── PsSetCreateThreadNotifyRoutineEx
│   │   → 线程创建（检测远程线程注入 T1055）
│   ├── PsSetLoadImageNotifyRoutineEx
│   │   → DLL/驱动加载事件，含签名验证结果
│   ├── ObRegisterCallbacks
│   │   → 保护 Agent 进程句柄不被 OpenProcess/DuplicateHandle 窃取
│   │   → 保护边界: 仅防护 Ring 3; Ring 0 可绕过
│   │   → 看门狗定期校验 Ob 回调表完整性
│   └── Direct Syscall Detection
│       → 记录 syscall 返回地址
│       → 验证返回地址是否落在 ntdll.dll 合法代码段内
│       → 非 ntdll 来源 → DIRECT_SYSCALL 事件
│       → 检测 SysWhispers3 / HellsGate / HalosGate
│
├── File Monitor (Minifilter)
│   ├── IRP_MJ_CREATE / IRP_MJ_WRITE / IRP_MJ_SET_INFORMATION / IRP_MJ_CLEANUP
│   ├── Pre-op: 阻断（隔离/预防性阻断）
│   ├── Post-op: 采集（文件内容哈希、entropy 计算）
│   └── 过滤优化:
│       ├── Volume/Path 白名单（跳过 %SystemRoot%\WinSxS 等噪音路径）
│       ├── 进程白名单（跳过 Windows Update / SCCM 等可信进程）
│       └── 文件大小阈值（>100MB 仅记录元数据不计算哈希）
│
├── Registry Monitor
│   ├── CmRegisterCallbackEx (Pre/Post callbacks)
│   ├── Registry Change Journal → SQLite 持久化（7d/100MB FIFO）
│   └── 焦点路径: Run*, Services, IFEO, CLSID (COM Hijacking)
│
├── Network Monitor (WFP Callout)
│   ├── ALE_AUTH_CONNECT/RECV_ACCEPT/FLOW_ESTABLISHED/OUTBOUND_TRANSPORT
│   └── DNS: ETW DNS Client 或 WFP UDP:53/TCP:53 payload 解析
│
├── AMSI Integration + Bypass Detection
│   ├── 注册为 AMSI Provider，接收 PowerShell/VBScript/.NET 内容
│   ├── 与检测引擎联动（支持阻断 AMSI_RESULT_DETECTED）
│   └── Bypass Detection:
│       ├── amsi.dll 内存完整性定期校验
│       ├── amsi.dll 卸载事件监控
│       ├── .NET CLR AmsiInitialize 篡改检测
│       └── 检出 → AMSI_TAMPER_DETECTED (CRITICAL)
│
├── ETW Tamper Detection & Resilience
│   ├── Provider 看门狗（每 10s 枚举，异常自动重注册）
│   ├── EtwEventWrite Patch 检测
│   ├── Fallback: 纯内核回调模式（保留 80%+ 覆盖）
│   └── ETW Threat Intelligence Provider 篡改检测
│
├── ETW Consumer (补充采集)
│   └── Kernel-Process/File/Network, Security-Auditing, PowerShell, WMI, TaskScheduler
│
├── MPSC Ring Buffer (见 4.1.6)
│
└── Self-Protection Enforcement
    ├── ObRegisterCallbacks → 保护进程句柄
    ├── Minifilter → 保护文件/目录
    ├── CmRegisterCallbackEx → 保护注册表键
    ├── PsSetCreateProcessNotifyRoutine → 防止进程被终止
    └── ELAM (Early Launch Anti-Malware) → 最早驱动加载
```

#### 4.1.4 Linux 内核态 (eBPF)

```
aegis-sensor-ebpf (CO-RE, BTF-enabled, libbpf-based)
│
├── Process Sensor
│   ├── tracepoint/sched/sched_process_exec/exit/fork
│   ├── kprobe/__x64_sys_execve / __x64_sys_execveat
│   ├── kprobe/commit_creds (权限变更/提权检测)
│   ├── LSM/bprm_check_security (可阻断 + 预防性阻断)
│   └── kprobe/do_mmap / vm_mmap_pgoff (进程注入/无文件执行)
│
├── File Sensor
│   ├── fentry/vfs_write / vfs_rename / vfs_unlink
│   ├── fentry/security_file_open (LSM, 支持阻断)
│   ├── fanotify (用户态补充: FAN_CLOSE_WRITE, FAN_OPEN_PERM)
│   └── 过滤: BPF Map LPM Trie 路径白名单，跳过 /proc /sys /dev /run
│
├── Network Sensor
│   ├── kprobe tcp_v4_connect / tcp_v6_connect / inet_csk_accept
│   ├── tracepoint/sock/inet_sock_set_state
│   ├── fentry/security_socket_connect (LSM, 网络隔离)
│   ├── TC / XDP (高性能包级过滤)
│   └── DNS: 内核态 UDP:53 解析 或 uprobe getaddrinfo/gethostbyname
│
├── Auth Sensor
│   ├── uprobe pam_authenticate / pam_open_session
│   ├── kprobe/audit_log_start
│   └── /var/log/auth.log inotify 监控
│
├── Container-Aware
│   ├── 所有 eBPF 程序读取 cgroup_id + namespace IDs
│   ├── CRI socket 查询关联容器元数据
│   └── 逃逸检测: nsenter/setns/unshare/CAP_SYS_ADMIN 监控
│
├── BPF Self-Protection
│   ├── tracepoint/syscalls/sys_enter_bpf (监控非 Agent 的 BPF 操作)
│   ├── 定期校验 BPF 程序完整性（tag/insn hash, 每 30s）
│   └── BPF 程序 pin 到 /sys/fs/bpf/edr/, 监控 unlink
│
├── BPF Maps
│   ├── config_map (ARRAY), pid_whitelist (HASH)
│   ├── path_whitelist (LPM_TRIE), ioc_bloom_filter (ARRAY)
│   ├── process_cache (LRU_HASH), connection_track (LRU_HASH)
│   ├── drop_counters (PERCPU_ARRAY), isolation_rules (LPM_TRIE)
│   └── bpf_prog_hashes (HASH)
│
└── 兼容性与降级策略
    ├── 优先: CO-RE + BTF (kernel >= 5.8)
    ├── 降级1: CO-RE + BTFHub (kernel 4.18+)
    ├── 降级2: kprobe + fallback helpers (kernel 4.14+)
    └── 降级3: 纯用户态 (auditd + fanotify + /proc polling)
```

**降级能力量化：**

| 能力 | 完整 eBPF | 降级1 | 降级2 | 降级3 |
|------|-----------|-------|-------|-------|
| 进程创建/退出 | 完整 | 完整 | 完整 | audit |
| 进程注入检测 | 完整 | 完整 | 部分 | 不支持 |
| 文件读写监控 | 完整 | 完整 | 完整 | fanotify |
| 网络连接追踪 | 完整 | 完整 | 完整 | ss 轮询 |
| DNS 内核态解析 | 完整 | 完整 | uprobe | 不支持 |
| 容器感知 | 完整 | 完整 | 部分 | 不支持 |
| 网络隔离 (XDP) | 完整 | 完整 | nftables | nftables |
| 预防性阻断 (LSM) | 完整 | 完整 | 不支持 | 不支持 |
| ATT&CK 覆盖率 | ~85% | ~82% | ~65% | ~45% |

#### 4.1.5 macOS 内核态 (Endpoint Security Framework)

```
aegis-sensor-esf (System Extension, ESF Client)
│
├── AUTH Events (可阻断)
│   ├── ES_EVENT_TYPE_AUTH_EXEC / AUTH_OPEN / AUTH_RENAME
│   ├── AUTH_UNLINK / AUTH_MMAP / AUTH_MOUNT / AUTH_SIGNAL
│
├── NOTIFY Events (仅观测)
│   ├── NOTIFY_EXEC/FORK/EXIT / NOTIFY_WRITE/CLOSE/CREATE
│   ├── NOTIFY_KEXTLOAD / NOTIFY_PTY_GRANT
│   ├── NOTIFY_CS_INVALIDATED / NOTIFY_REMOTE_THREAD_CREATE
│
├── Network Events
│   ├── Network Extension (NEFilterDataProvider)
│   └── ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN
│
├── 响应: es_respond_auth_result / es_mute_process
└── 部署: System Extension + MDM + Notarization
```

#### 4.1.6 MPSC Ring Buffer 详细设计

**设计目标**：支持多内核线程 producer，最大限度保障 CRITICAL 事件不丢失（有界丢失预算 + 可审计），防御噪声攻击。

**共享内存布局（64MB, mmap）：**

```
┌──────────────────────────────────────────────────────────────┐
│  Header (4KB, Page-aligned)                                   │
│  magic: 0x45445252_494E4732 ("EDRRING2"), version: 2          │
│  total_capacity: 67104768, flags: AtomicU32                   │
├──────────────────────────────────────────────────────────────┤
│  Lane 0: CRITICAL (8MB)                                       │
│  用途: PROCESS_CREATE/EXIT, AUTH_*, AMSI_TAMPER,              │
│        ETW_TAMPER, DIRECT_SYSCALL, NETWORK_CONNECT            │
│  溢出: 阻塞等待 (bounded spin, 最多 100us)                    │
│        超时仍满 → 溢出至 Emergency Spill 持久化队列           │
│        Spill 队列亦满 → 强制覆盖最旧 + LOSS 计数 + 告警      │
├──────────────────────────────────────────────────────────────┤
│  Lane 1: HIGH (16MB)                                          │
│  用途: FILE_WRITE(可执行), REGISTRY_WRITE, SCRIPT_EXEC,       │
│        DNS_QUERY, SUSPICIOUS_*                                │
│  溢出: 丢弃当前事件 + drop_count++                            │
├──────────────────────────────────────────────────────────────┤
│  Lane 2: NORMAL (24MB)                                        │
│  用途: FILE_WRITE(常规), FILE_READ, NET_FLOW_STATS            │
│  溢出: 丢弃当前事件 + 启动采样模式 (1/10)                    │
├──────────────────────────────────────────────────────────────┤
│  Lane 3: LOW (16MB)                                           │
│  用途: FILE_INFO(metadata-only), HEARTBEAT_INTERNAL           │
│  溢出: 直接丢弃, 仅递增 drop_count                           │
└──────────────────────────────────────────────────────────────┘
```

**MPSC 写入协议（内核态）：**

1. `lane = priority_classify(event_type)`
2. `total = align8(32 + payload_len)`
3. `slot = atomic_fetch_add(&lane.write_offset, total)`
4. If slot exceeds capacity: handle per overflow policy
5. **Wrap-safe 写入**：
   - 若 `slot % lane.capacity + total <= lane.capacity`：记录未跨越边界，单次 `memcpy` 写入
   - 若记录跨越 lane 尾部：在剩余空间写入 `PAD_SENTINEL`（magic + 剩余长度），`slot` 推进至下一 lane 起始位置后重试步骤 3（CAS 重试，非递归）
   - 备选方案：lane 采用 **虚拟双映射**（同一物理页映射到连续两倍虚拟地址空间），此时 `memcpy` 天然连续，无需 sentinel 处理
6. `memcpy(lane.data[slot % lane.capacity], event, total)`
7. `store_release(event.flags, COMMITTED)`

**消费者（用户态，单线程）：**

加权轮询：Lane 0 (4x) -> Lane 1 (2x) -> Lane 2 (1x) -> Lane 3 (1x) -> cycle。背压信号：Lane 0 利用率 > 50% 时通知检测引擎加速。

**Linux 实现**：4 个独立 BPF_MAP_TYPE_RINGBUF，用户态 ring_buffer__poll 同时监听。

**性能指标**：

| 指标 | 目标 |
|------|------|
| 单事件投递时延 | < 800ns |
| 吞吐 | > 3M events/sec（单核消费） |
| CRITICAL 丢失率 | 趋近于 0（有界丢失预算，见下方 Spill 机制） |
| 噪声攻击防御 | 高频 FILE 事件仅影响 Lane 2/3 |

**Emergency Spill Queue（Lane 0 溢出保护）：**

Lane 0 的 Ring Buffer 满载且 bounded spin 超时后，事件不直接覆盖，而是溢出至 Emergency Spill 持久化队列：

- **存储**：`/data/spill/critical-{N}.spill`，单文件 4MB，最多 32MB（8 个分段）
- **独立 Drain 线程**：Spill 由专用的 `spill_drain` 线程管理，独立于主消费者线程。该线程常驻运行，仅监控 Lane 0 溢出信号和 Spill 分段状态，不参与常规事件消费。当 Lane 0 满载的根因是主消费者过载/调度饥饿时，`spill_drain` 线程仍可独立写盘，避免兜底路径与故障路径共享同一个瓶颈
- **写入方式**：`spill_drain` 线程通过预分配的 `mmap` 区域直写磁盘，绕过常规 WAL 路径；Spill 分段文件在启动时预创建（fallocate），写入时无需文件系统分配
- **回收**：Spill 队列中的事件在被主消费者正常处理后，由 `spill_drain` 线程回收分段
- **Spill 亦满**：当 32MB Spill 队列也写满时（极端情况），才强制覆盖 Ring Buffer 最旧事件 + 递增 `critical_loss_count` + 触发 HIGH_PRIORITY 告警上报
- **可观测性**：`spill_write_count`、`spill_active_bytes`、`critical_loss_count`、`spill_drain_alive`（线程存活心跳）四个指标实时暴露至 Heartbeat 遥测
- **丢失预算**：设计目标为零丢失；当 `critical_loss_count > 0` 时，告警明确标注受影响的时间窗口和丢失事件数，供云端关联引擎标记该时段取证可信度降级

#### 4.1.7 内核完整性监控

运行于看门狗进程中，周期执行：

**Windows：**
- SSDT hash 校验（每 30s）
- IDT hash 校验
- 内核代码段 (.text) hash（ntoskrnl.exe）
- Callback 表完整性（Ob/Ps/Cm 回调列表）
- DKOM 检测（多路径进程枚举：NtQuerySystemInformation / PsActiveProcessHead / 调度器线程）
- PatchGuard 状态检测

**Linux：**
- 内核代码段 (.text) hash
- sys_call_table 指针校验（各 syscall 指向 .text 范围内）
- 内核模块列表校验（/proc/modules vs lsmod 一致性）
- eBPF 程序完整性（已在 BPF Self-Protection 中覆盖）

**macOS：**
- kext 列表校验
- System Extension 完整性
- SIP (System Integrity Protection) 状态监控

---

### 4.2 用户态核心引擎

#### 4.2.1 Orchestrator（主事件循环）

基于 tokio 异步运行时，负责初始化所有子系统并建立 channel 连接：

```rust
// 伪代码
async fn main_loop(config: AgentConfig) {
    // 1. 初始化共享数据结构
    let ring_buffer = MpscRingBuffer::mmap_open(&config.ring_buffer_path);
    let (event_tx, event_rx) = bounded_channel::<NormalizedEvent>(65536);
    let (alert_tx_hi, alert_rx_hi) = bounded_channel::<Alert>(1024);
    let (alert_tx_norm, alert_rx_norm) = bounded_channel::<Alert>(4096);
    let (response_tx, response_rx) = bounded_channel::<ResponseAction>(1024);
    let (telemetry_tx, telemetry_rx) = bounded_channel::<TelemetryBatch>(2048);

    // 2. 初始化核心组件
    let process_tree = Arc::new(ProcessTree::new());
    let feedback_whitelist = Arc::new(AdaptiveWhitelist::new());
    let lineage_tracker = Arc::new(LineageTracker::new());

    // 3. 启动子系统
    spawn(sensor_dispatch_loop(ring_buffer, event_tx, process_tree.clone(),
                               lineage_tracker.clone()));
    spawn(detection_engine(event_rx, alert_tx_hi, alert_tx_norm,
                           telemetry_tx.clone(), config.detection,
                           feedback_whitelist.clone()));
    spawn(response_executor(response_rx, config.response));
    spawn(comms_uplink_high(alert_rx_hi, config.comms));
    spawn(comms_uplink_normal(telemetry_rx, alert_rx_norm, config.comms));
    spawn(comms_downlink(response_tx, feedback_whitelist.clone(), config.comms));
    spawn(config_watcher(config.config_path));
    spawn(health_reporter(config.heartbeat_interval, lineage_tracker.clone()));
    spawn(process_tree_snapshot_sync(process_tree.clone(),
                                     config.snapshot_interval));
    spawn(watchdog_heartbeat());

    signal::ctrl_c().await;
    graceful_shutdown().await;
}
```

#### 4.2.2 Sensor Dispatch -- 事件归一化

从 Ring Buffer 4 条 Lane 消费原始事件，转化为统一的 NormalizedEvent：

```
原始内核事件                    NormalizedEvent
┌─────────────┐                ┌────────────────────────────────────┐
│ EventHeader │                │ event_id:    UUID (Agent 端生成)   │
│ + FlatBuf   │──解码+归一化──→│ lineage_id:  u128                  │
│   Payload   │                │ timestamp:   u64 (纳秒)           │
└─────────────┘                │ event_type:  EventType enum        │
                               │ priority:    CRITICAL|HIGH|NORMAL  │
      ┌───────────┐            │ process:     ProcessContext {...}   │
      │ Process   │──填充──→   │ payload:     EventPayload enum     │
      │ Tree      │ 上下文     │ container:   Option<ContainerCtx>  │
      │ Cache     │            │ enrichment:  EventEnrichment       │
      └───────────┘            │ syscall_origin: Option<SyscallOri> │
                               └────────────────────────────────────┘
      ┌───────────┐
      │ Adaptive  │──检查──→ 命中反馈白名单 → 跳过检测, 标记 BENIGN
      │ Whitelist │
      └───────────┘
```

#### 4.2.3 进程树缓存 (Process Tree Cache)

```
ProcessTree (LRU, 内存上限 30MB)
│
├── 数据结构: HashMap<(PID, StartTime), ProcessNode>
│   ProcessNode {
│     pid, ppid, start_time, exe_path, exe_hash, cmdline, user,
│     integrity, signature, cwd, env_vars, children, creation_flags,
│     token_elevation, container_id, namespace_ids,
│     last_activity: AtomicU64, protection_level: Option<PPL_LEVEL>,
│   }
│
├── 定期全量快照同步:
│   ├── 频率: 每 5 分钟
│   ├── 格式: 所有活跃进程的压缩包 (~20KB)
│   ├── 用途: 云端修复 orphan 事件、检测被隐藏进程
│
└── 操作: on_process_create / on_process_exit / get_ancestor_chain / is_descendant_of
```

#### 4.2.4 文件哈希计算策略

- **默认算法**：SHA-256；大文件流式处理优先使用 BLAKE3 预筛
- **触发时机**：新可执行文件落盘、Stage 2/3 深度分析请求、隔离前留证、云端补算
- **缓存**：key = (inode/file_id, size, mtime, content_hint)，命中复用
- **限流**：前台进程限速、大文件分片后台处理、CPU/IO 高压时降级为元数据优先
- **SSD 安全删除**：优先文件系统级加密删除（NTFS EFS / ext4 fscrypt / APFS）；回退 overwrite + TRIM

---

### 4.3 本地检测引擎

#### 4.3.1 六阶段检测流水线

```
NormalizedEvent
     │
     ▼
┌──────────────────────────────────────────────────────────────┐
│  Stage 0: Fast Path Filter (< 100ns/event, 10M event/s)      │
│  ├── 事件类型路由表                                            │
│  ├── 全局采样率控制                                            │
│  ├── 静态白名单匹配                                           │
│  └── Adaptive Whitelist 检查（反馈回路）                       │
│      → 命中云端确认误报条目 → 跳过检测, 直接 BENIGN            │
└──────────────────────┬───────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  Stage 1: IOC Matching (< 500ns/event, 5M event/s)            │
│  分层 Bloom + Cuckoo Filter，支持 500 万 IOC，~10MB           │
│  ├── Tier 0: CRITICAL Bloom (FPR 0.001%, ~50K, ~1MB)          │
│  ├── Tier 1: HIGH Bloom (FPR 0.01%, ~500K, ~5MB)              │
│  └── Tier 2: STANDARD Cuckoo (FPR 0.01%, ~5M, ~4.5MB)        │
│      → Cuckoo 支持动态删除（IOC aging）                        │
│      → 命中 → HashMap 精确确认                                  │
└──────────────────────┬───────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  Stage 2: Rule Engine - Sigma + Custom DSL + Temporal (< 15us)│
│  Rule VM 指令集:                                               │
│  ├── 基础: LOAD_FIELD, CMP_EQ/NE/GT/LT/REGEX/CONTAINS,       │
│  │         AND, OR, NOT, MATCH_RESULT                          │
│  ├── IOC: BLOOM_CHECK, CUCKOO_CHECK                            │
│  ├── 上下文: LOAD_PARENT, LOAD_ANCESTOR, LOAD_CHILDREN_COUNT  │
│  └── Temporal 算子:                                            │
│      ├── TEMPORAL_WINDOW(duration_ms)                           │
│      ├── TEMPORAL_SEQUENCE(matchers[], ordered=bool)            │
│      ├── TEMPORAL_COUNT(matcher, min, max)                      │
│      └── TEMPORAL_NEAR(event_a, event_b, max_gap_ms)           │
│  每条 temporal 规则: 128-event ring buffer, < 64KB, TTL 自清理 │
│  热更新: 签名校验 + 原子替换 + 失败回滚 + 灰度发布            │
└──────────────────────┬───────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  Stage 2.5: AMSI Fast-Path Interlock (< 50us, 100K script/s) │
│  AMSI 来源 + Stage 2 判定 MALICIOUS/CRITICAL:                 │
│  → 共享内存 flag 通知内核 AMSI Provider                        │
│  → Provider 返回 AMSI_RESULT_DETECTED 阻断后续脚本块           │
│  Linux: LSM bprm_check_security 阻断                          │
│  macOS: ESF AUTH_EXEC 阻断                                     │
└──────────────────────┬───────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  Stage 3: YARA Memory/File Scan (按需, < 50ms/scan, 100/s)   │
│  触发: 新可执行文件、Stage 2 深度扫描请求、RWX 页、           │
│        .NET Assembly.Load(byte[])、LOLBin 非标准 DLL、         │
│        Office 宏、脚本 payload 解码后                          │
│  异步任务队列; 同对象 TTL 去重; 大样本切片                    │
└──────────────────────┬───────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  Stage 4: Local ML Inference (< 8ms, 800 inference/s)         │
│  Model A: Static PE/ELF Classifier                             │
│    XGBoost + LightGBM + MLP ensemble, 200+ features            │
│    OOD detection (Mahalanobis), adversarial training            │
│  Model B: Behavioral Sequence Anomaly                          │
│    1D-CNN, cold-start profile (前 50 events 用 2-layer CNN)    │
│    冷启动 ~1MB, 标准 ~3MB                                      │
│  Model C: Script Risk Assessment                               │
│    Distilled 4-layer Transformer (hidden_dim=128), ~8MB ONNX   │
│    处理 Base64/XOR/concat; 输出 risk_score + intent_tags       │
│  总模型内存 <= 20MB, 全部 ONNX Runtime (CPU)                  │
│  模型发布: shadow mode / A-B bucket / canary + auto-revert     │
└──────────────────────┬───────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  Stage 5: Sharded Stateful Correlation (< 2us, 2M event/s)   │
│  状态机按 process_group_id 分片                                │
│  同进程树 → 同分片 → 同 detection-pool 线程（无跨线程锁）     │
│  跨进程树关联: 异步 cross-shard query                          │
│  每分片 > 500K event/s; 线性扩展                               │
└──────────────────────┬───────────────────────────────────────┘
                       ▼
           Decision Router
           ├── BENIGN    → 遥测 (仅 comms-tx-normal)
           ├── SUSPICIOUS → 遥测 + 低优先级告警 (comms-tx-normal)
           ├── MALICIOUS  → 遥测 + 高优先级告警 + 响应
           └── CRITICAL   → 遥测 + 告警 + 即时响应
```

#### 4.3.2 检测引擎性能预算

| 阶段 | 延迟预算 | 吞吐量 | 备注 |
|------|---------|--------|------|
| Stage 0: Fast Path | < 100ns | 10M event/s | 含 Adaptive Whitelist |
| Stage 1: IOC | < 500ns | 5M event/s | 500 万 IOC |
| Stage 2: Rule VM | < 15us | 400K event/s | 含 temporal 关联 |
| Stage 2.5: AMSI | < 50us | 100K script/s | 仅 AMSI 来源 |
| Stage 3: YARA | < 50ms | 100 scan/s | 按需深度扫描 |
| Stage 4: ML | < 8ms | 800 inference/s | 3 模型投票 + OOD |
| Stage 5: Correlation | < 2us | 2M event/s | 分片后线性扩展 |
| **端到端（典型）** | **< 20us** | **> 400K event/s** | **P99 < 150us** |

#### 4.3.3 勒索软件专项检测（4 层）

| Layer | 检测手段 | 响应联动 |
|-------|----------|----------|
| 1: 金丝雀文件 | 关键目录部署隐藏诱饵；修改/重命名/删除即触发 CRITICAL | 立即 Suspend 可疑进程 |
| 2: 加密行为 | 熵值跃升 (写后 >7.9, 写前 <7.0)；大规模 read-encrypt-write；后缀重写；勒索信 | 联动 VSS 快照保护/回滚 |
| 3: MBR/VBR 保护 | 监控 PhysicalDisk/raw block device 直接写入 | 非授权写入立即阻断 |
| 4: 状态机 | file enumeration -> snapshot deletion -> mass encryption -> ransom note | 多阶段关联告警 |

#### 4.3.4 脚本多层解混淆流水线

1. **Layer 1 编码解码**：Base64 / Hex / URL / Unicode 转义
2. **Layer 2 字符串还原**：拼接 / Replace / -join / 环境变量替换
3. **Layer 3 执行层解包**：Invoke-Expression / ScriptBlock.Create / -EncodedCommand（最多递归 10 层）
4. **Layer 4 语义分析**：解混淆文本进入 Stage 4 Model C

**性能目标**：典型脚本 < 2ms，深度混淆 < 10ms。

---

### 4.4 响应执行引擎

#### 4.4.1 架构概览

```
Response Executor
├── 输入: Decision Router 生成的 response plan
├── 执行阶段:
│   ├── pre-check: 目标存在性、权限、幂等键检查
│   ├── containment: suspend / isolate / block
│   ├── evidence: 连接、句柄、内存、注册表、文件留证
│   ├── commit: terminate / quarantine / rollback / remote action
│   └── audit: 结果记录、回执签名、上报 cloud
├── 设计要求:
│   ├── 每个动作具备幂等语义和超时控制
│   ├── 高风险动作要求强审计
│   └── 能留证的动作优先留证再破坏
```

#### 4.4.2 两阶段进程终止

- **Phase 1：Immediate Suspend（< 100ms）**
  - Windows: NtSuspendProcess
  - Linux: SIGSTOP + freeze cgroup
  - macOS: task_suspend(task_port)
  - 进程立即停止执行但保留所有资源

- **Phase 2：Assess & Respond**
  - 自动路径 (confidence > 0.9)：检查 C2 连接 -> 检查加密行为 -> 可选内存快照 -> 递归终止进程树
  - 手动路径 (confidence 0.5-0.9)：挂起等待分析师确认（5min 超时）
  - PPL-Aware 路径：普通进程标准 kill；PPL 通过内核驱动 ZwTerminateProcess 或 token demotion；PP（Protected Process）不终止，仅 CRITICAL 告警 + 可选网络隔离

#### 4.4.3 预防性阻断架构

内核态 pre-callback 读取 Block Decision Map（共享内存 bitmap），用户态检测引擎写入。

**信任模型与完整性保护**：Block Decision Map 位于内核态与用户态的信任边界上，须防止用户态篡改导致阻断绕过或误阻断：
- **内核持有权威副本**：Map 的权威状态由内核驱动/BPF map 持有，用户态检测引擎通过受约束的更新通道（ioctl / BPF_MAP_UPDATE_ELEM）提交变更，而非直接写入内核读取的内存区域
- **版本化更新**：每次更新携带单调递增的 `map_version`，内核侧拒绝 version 回退的更新，防止 replay 攻击
- **来源校验**：更新请求须来自经身份验证的检测引擎进程（通过进程签名 / cgroup 绑定 / BPF token 验证），拒绝未授权进程的写入

阻断点：

| 平台 | 阻断点 | 机制 |
|------|--------|------|
| Windows | Minifilter IRP_MJ_CREATE | STATUS_ACCESS_DENIED |
| Windows | WFP ALE_AUTH_CONNECT | FWP_ACTION_BLOCK |
| Linux | LSM bprm_check_security | -EPERM |
| macOS | ESF AUTH_EXEC/AUTH_OPEN | es_respond_auth_result(DENY) |

**Block List 规则**：
- 条目类型：hash-block / pid-block / path-block / net-block
- TTL：默认 300s；永久阻断需云端显式指令
- 上限：10,000 条
- 安全：系统关键进程白名单不可阻断；云端可远程清空
- 延迟：用户态写入 -> 内核态生效 < 1us

#### 4.4.4 响应能力矩阵

| 动作 | 时延目标 | 在线审批要求 | 离线行为 | 可回滚 |
|------|---------|-------------|---------|--------|
| 进程 Suspend -> Kill | <= 3s | 自动/手动 | 自动执行 | 否 |
| 文件隔离 | <= 5s | 自动/手动 | 自动执行 | 是 |
| 网络隔离 | <= 3s | 需审批 | 仅限预审批 Playbook | 是 |
| 注册表回滚 | <= 5s | 手动 | 禁止（挂起至恢复连接） | 是 |
| 文件系统回滚 | <= 60s | 需审批 | 禁止（挂起至恢复连接） | 部分 |
| 用户会话锁定 | <= 10s | 需审批 | 仅限预审批 Playbook | 是 |
| 远程取证 | 按需 | 需审批 | 禁止（依赖云端） | N/A |
| Remote Shell | 按需 | 双人审批 | 禁止（依赖云端） | N/A |
| 自动 Playbook | <= 10s | 预审批 | 自动执行（需本地签名校验） | 部分 |
| ASR 规则执行 | <= 1s | 自动 | 自动执行 | 否 |
| 设备控制 | <= 1s | 自动 | 自动执行 | 否 |

**离线审批机制：**

- **自动执行类**（进程 Kill、文件隔离、ASR、设备控制）：无需审批，检测引擎触发后立即执行
- **预审批 Playbook 类**（网络隔离、用户会话锁定）：仅当本地存在有效预签名 Playbook 时自动执行；无有效 Playbook 则挂起动作，记录待审批队列，恢复连接后立即上报请求审批。Playbook 有效性需同时满足以下全部条件：
  - **签名校验**：管理员 Ed25519 签名有效
  - **TTL 未过期**：默认 48h（可配置，上限 7 天），网络隔离类动作建议 24h
  - **使用次数未耗尽**：每个 Playbook 携带 `max_executions`（默认 1，即 one-shot），执行后递减并持久化，归零后作废
  - **策略版本不低于 revocation floor**：本地维护 `min_policy_version`，每次与云端同步时更新；低于该版本的 Playbook 立即作废
  - **目标约束匹配**：Playbook 绑定特定的 `incident_id`（可选）、`detection_rule_ids`、`target_scope`（进程名/路径/网段等），不匹配当前上下文则不触发
  - **重连即清理**：恢复连接后，Agent 立即拉取最新 revocation floor 和 Playbook 清单，淘汰本地过期/已撤销的 Playbook
- **禁止离线类**（注册表/文件系统回滚、远程取证、Remote Shell）：离线时不执行，动作请求进入 pending 队列，恢复连接后按优先级提交审批

#### 4.4.5 文件隔离 (Quarantine)

1. Suspend 正在访问该文件的可疑进程
2. 采集元数据（原始路径、SHA256、签名、来源标签）
3. LZ4 压缩 + AES-256-GCM 加密 -> /quarantine/{sha256}.vault
4. 原文件安全删除（优先文件系统级加密删除）
5. 审计记录上报

治理：容量 2GB，保留 30 天，支持云端还原。

#### 4.4.6 注册表回滚

基于 Registry Change Journal (SQLite)，支持按时间点 / 按进程 / 按 key / 按 incident 回滚。回滚前自动备份当前值。系统关键键需审批。

#### 4.4.7 文件系统回滚

基于 VSS (Windows) / btrfs snapshot (Linux) / APFS snapshot (macOS)。支持卷级 / 目录级 / 文件列表级 / 按进程作用域回滚。通过 hash 对比仅恢复被修改/删除的对象。

#### 4.4.8 网络隔离

**基本规则：**
- 防火墙规则使用 IP 白名单（不依赖 DNS）
- DNS 仅允许 EDR 指定服务器
- 隔离跨重启持久

**隔离模式控制面通信（与常规回退链解耦）：**

隔离模式下的通信路径独立于 4.5.2 中的常规回退链，避免 Domain Fronting 等依赖动态 CDN IP 的回退层级与 IP 白名单冲突：

| 层级 | 隔离模式可用性 | 说明 |
|------|-------------|------|
| Primary gRPC | ✓ | IP 已缓存 |
| Fallback 1 WebSocket | ✓ | 同一组服务器 IP |
| Fallback 2 Long-Polling | ✓ | 同一组服务器 IP |
| Fallback 3 Domain Fronting | **✗ 禁用** | CDN IP 范围动态且庞大，纳入白名单会削弱隔离强度 |

**IP 缓存策略（防失联锁死）：**
- 缓存多层 IP 池：primary 集群 IP + failover 集群 IP + 最近 30 天历史解析 IP
- 安装时 / 启动时 / 每次 Heartbeat 时更新缓存
- 缓存持久化至磁盘（`/data/config/edr-ip-cache.json`），跨重启保留
- 缓存命中率监控：若连续 3 次连接失败（所有缓存 IP 均不可达），触发 `isolation_control_plane_unreachable` CRITICAL 告警

**Break-Glass 释放机制（防止自锁死）：**

TTL 到期**不恢复全量网络**，而是进入 management-only 模式，在"防自锁死"和"持续遏制"之间取得平衡：

- **TTL 到期 → management-only 模式**：隔离动作携带 TTL（默认 24h，可配置）。TTL 到期后仅放行 EDR 控制面通信（保持缓存 IP 白名单），其余网络流量仍被阻断。Agent 尝试重连控制面，由控制面重新评估主机状态后决定：
  - 签名释放命令 → 恢复全量网络
  - 续期隔离命令 → 重置 TTL，保持隔离
  - 无响应（控制面不可达）→ 维持 management-only 模式，每 5 分钟重试
- **本地管理员释放**：具有物理访问权限的本地管理员可通过 CLI 工具（需硬件 token 或预共享解锁码验证）手动释放隔离，恢复全量网络
- **释放后行为**：释放后 Agent 立即上报隔离期间的 Forensic Journal 和 pending 审批队列
- **防攻击者利用**：攻击者即使在隔离期内存活并等待 TTL 到期，也只能获得 management-only 网络（仅 EDR IP 可达），无法重建 C2 或横向移动

#### 4.4.9 实时取证

**易失性证据**：进程列表/线程/模块、连接/路由/ARP/DNS 缓存、会话/Token/驱动、文件句柄、内存 dump

**持久化证据**：
- Windows: $MFT、$UsnJrnl、Prefetch、Event Logs、Registry Hives、Amcache、SRUM、浏览器历史、LNK
- Linux: auth.log、syslog、audit.log、crontab、shell history
- macOS: Unified Log、Launch Agents、FSEvents、KnowledgeC.db

**证据链**：artifact_id + hash_chain + Agent signature + NTP 校验时间戳；云端独立复核。

#### 4.4.10 Remote Shell 安全加固

- **访问控制**：双人审批；默认 30min / 最长 2h；每端点最多 1 并发 session
- **命令控制**：黑名单（format/dd/chmod 777/psexec 等）；可选白名单模式
- **资源限制**：CPU 5%、Mem 256MB、Disk 100MB、无外网（cgroup/Job Object）
- **审计**：全量 asciicast 录制 + 单命令审计日志

#### 4.4.11 端点防火墙管控

在网络隔离（4.4.8）的"全量阻断/放行"之上，提供持久化、可编排的端点网络面控制，支持细粒度策略下发：

**策略类型：**

| 类型 | 说明 | 示例 |
|------|------|------|
| 应用级规则 | 按进程路径/签名控制联网权限 | 允许 `outlook.exe` 出站 443；阻止 `powershell.exe` 出站非 EDR 目标 |
| 端口 / 协议规则 | 入站/出站 allow/deny 列表 | 阻止入站 RDP (3389)；阻止出站 SMB (445) |
| 地理围栏 | 基于 GeoIP 数据库的目标国家/地区过滤 | 阻止与制裁国家的所有出站连接 |
| 响应触发临时规则 | 由检测引擎或响应动作动态插入，携带 TTL | 检测到 C2 beacon 后临时阻断目标 IP，TTL 300s |

**平台实现：**

| 平台 | 机制 | 说明 |
|------|------|------|
| Windows | WFP (Windows Filtering Platform) | 规则持久化至 BFE，跨重启保留；与 4.4.3 预防性阻断的 ALE_AUTH_CONNECT 层共用 WFP callout，但规则优先级低于阻断层 |
| Linux | nftables (优先) / iptables (降级) | 独立 nftables table `aegis-firewall`，与隔离规则 `aegis-isolate` 分离；内核 < 3.13 降级至 iptables |
| macOS | pf (Packet Filter) | 通过 `/etc/pf.anchors/com.aegis.firewall` 锚点加载；与 Network Extension 协同 |

**与网络隔离的关系：** 网络隔离（4.4.8）是应急响应动作，触发后进入"仅 EDR 通信"模式，覆盖所有防火墙规则。防火墙管控是常态运行的策略层，在非隔离状态下提供持续的网络面收缩。隔离解除后，防火墙规则自动恢复生效。

**与 ASR 的协同：** ASR 网络保护规则（4.9.1）侧重于应用行为约束（如阻止 Office 进程访问外网），防火墙规则侧重于网络层面的端口/协议/地理控制。两者在 WFP/nftables/pf 层面共存，ASR 规则优先级高于防火墙通用规则。

---

### 4.5 通信模块

#### 4.5.1 三路 gRPC 通道

| 通道 | 用途 | 行为 |
|------|------|------|
| A: High-Priority | CRITICAL/HIGH 告警、响应结果、篡改检测 | 零延迟，独立 gRPC stream + 线程 |
| B: Normal Telemetry | 常规遥测、低优先级告警 | 批量 100-500 事件，最长 1s，LZ4 压缩 |
| C: Bulk Upload | 取证包、内存 dump、大文件 | 分块上传、断点续传、带宽受限 |

#### 4.5.2 通信隐蔽与回退链

```
1. Primary:    gRPC over TLS 1.3
2. Fallback 1: HTTPS WebSocket (HTTP/2 被 DPI 阻断时; Protobuf 封装)
3. Fallback 2: HTTPS Long-Polling (最保守; +5-30s 延迟)
4. Fallback 3: Domain Fronting (可选; 通过合法 CDN)

自动切换: gRPC → fail 3x → WebSocket → fail 3x → Long-Polling → Domain Fronting
恢复: 后台每 5min 探测, 尝试升级回更优信道
TLS 指纹: utls 模拟浏览器 ClientHello, 随机化 JA3, ALPN h2/http1.1 随机
```

#### 4.5.3 WAL (Write-Ahead Log)

- **存储**：/data/wal/segment-{N}.wal，16MB 分段，默认上限 500MB（可配置，范围 256MB-2GB）
- **格式**：Segment Header + Record[] (record_len + type + crc32 + priority + payload)
- **重连**：按 sequence_id 顺序回放，服务端幂等去重
- **加密分级**：
  - 高敏字段 (username, IP, credentials)：TPM-bound 密钥
  - 普通字段 (process name, file path)：OS keystore 密钥
  - 元数据 (sequence, timestamp)：明文
- **密钥保护**：Tier 1 TPM/Secure Enclave 绑定（优先）；Tier 2 DPAPI/LUKS/Keychain + 增强 ACL

**WAL 分层存储：**

WAL 分为两类独立存储，具有不同的淘汰策略：

| 类型 | 路径 | 默认配额 | 淘汰策略 |
|------|------|---------|---------|
| **Forensic Journal** | `/data/wal/forensic/` | 64MB（不可低于 32MB） | **不可淘汰**（见下方） |
| **Telemetry WAL** | `/data/wal/telemetry/` | 436MB（总 500MB 减 Forensic 配额） | 按水位降级（见下方） |

**Forensic Journal（不可淘汰）：**

存储安全关键记录，独立于 Telemetry WAL 的压力策略，不参与采样/摘要化/FIFO 淘汰：

- 离线期间执行的所有响应动作记录（Kill/Quarantine/Isolate 及其上下文）
- 命令执行状态日志（收到的 ServerCommand、校验结果、执行结果）
- 检测引擎触发的告警及其关联的关键证据事件（触发告警的进程链、网络连接、文件操作）
- Playbook 执行记录（含 playbook_id、触发条件、执行结果）
- `COMMAND_REJECTED` 安全审计事件

**Forensic Journal 内部分区：**

64MB 空间划分为两个区域，确保响应审计记录始终可写：

| 分区 | 容量 | 存储内容 | 淘汰规则 |
|------|------|---------|---------|
| **Evidence Zone** | 56MB | 告警关联证据事件、Playbook 执行记录、COMMAND_REJECTED 事件 | 不可淘汰；写满后停止写入新证据事件 |
| **Action Log Zone** | 8MB（硬预留，不可征用） | 响应动作执行记录（Kill/Quarantine/Isolate）、命令执行状态日志 | 不可淘汰；此分区独立于 Evidence Zone，确保在 Evidence Zone 满载时仍可记录新的响应动作 |

**满载行为（分阶段）：**

1. **Evidence Zone 满载**（56MB 耗尽）：停止写入新的证据事件；触发 `forensic_evidence_full` CRITICAL 告警；响应动作和命令状态继续写入 Action Log Zone
2. **Action Log Zone 也满载**（8MB 耗尽，极端场景）：触发 `forensic_action_log_full` CRITICAL 告警；**fail-closed 降级**——新的不可逆响应动作（网络隔离、文件系统回滚、用户会话锁定）自动降级为挂起状态，进入 pending 队列等待恢复连接后审批；轻量级响应（进程 Kill、文件隔离）继续执行，其执行记录写入 Emergency Audit Ring（见下方）
3. 绝不淘汰已有记录——两个分区均为 append-only，无 FIFO 驱逐

**Emergency Audit Ring（最终保底）：**

当 Forensic Journal 的 Action Log Zone 也耗尽时，轻量级响应（Kill/Quarantine）的执行记录写入此 ring，确保在任何存储压力下都有审计记录：

- **存储**：`/data/wal/emergency-audit.ring`，固定 1MB，预分配，不可配置为更小
- **格式**：固定大小 ring buffer，每条记录 128B（action_type + target_pid + target_path_hash + timestamp + command_id + result_code + signature）
- **淘汰**：环形覆盖最旧条目（FIFO），可存约 8,000 条记录——足够覆盖极端场景下数天的 Kill/Quarantine 操作
- **不降级写入 Telemetry WAL**：避免审计记录进入会被摘要化/淘汰的存储层
- **可观测性**：`emergency_audit_ring_utilization`、`emergency_audit_ring_overwrites` 指标暴露至 Heartbeat

**Telemetry WAL 耗尽策略：**

Telemetry WAL 写入受磁盘水位和分段上限双重约束，耗尽时按以下策略降级：

| 水位阈值 | 行为 |
|---------|------|
| < 70% | 正常写入，全量遥测事件入 WAL |
| 70%-85% | 告警（`wal_pressure` 指标上报 Heartbeat）；LOW 优先级事件按 1/10 采样写入，其余摘要化（仅保留 event_type + timestamp + hash） |
| 85%-95% | HIGH 告警；仅 CRITICAL + HIGH 优先级遥测事件写入完整记录；NORMAL/LOW 事件仅写摘要行（固定 64B/条） |
| > 95% | CRITICAL 告警；仅 CRITICAL 遥测事件写入；淘汰最旧的非 CRITICAL 分段腾出空间 |
| 磁盘剩余 < 1GB | 紧急模式：Telemetry WAL 停止扩张，仅保留最近 2 个 CRITICAL 分段，其余按 FIFO 淘汰；触发 `wal_emergency` 告警。Forensic Journal 不受影响 |

**可观测性**：`wal_telemetry_bytes`、`wal_forensic_bytes`、`wal_segment_count`、`wal_pressure_level`、`wal_evicted_segments`、`wal_summarized_events`、`forensic_journal_utilization` 七个指标实时暴露至 Heartbeat 遥测。

**能力降级声明**：当 Telemetry WAL 进入 85% 以上水位或发生分段淘汰时，恢复连接后的 WAL 回放摘要中会标注受影响时间窗口和丢失/摘要化的遥测事件类别，供云端标记该时段遥测完整性为 `PARTIAL`。Forensic Journal 的记录始终完整回放，确保响应动作和告警证据链不受遥测降级影响。

#### 4.5.4 带宽自适应 QoS

| 网络分级 | 批量间隔 | 压缩 | 采样 |
|---------|---------|------|------|
| HIGH (>10Mbps) | 1s | LZ4 | 全量 |
| MEDIUM (1-10Mbps) | 3s | ZSTD | 全量 |
| LOW (<1Mbps) | 10s | ZSTD | INFO 级 1/100 |
| SATELLITE (RTT>500ms) | 优先告警 | ZSTD | 仅 CRITICAL |
| METERED | 同 LOW | ZSTD | 暂停大文件上传 |

**前后台感知**：用户前台活跃时降低 Agent 网络优先级；空闲时回放 WAL、同步资产。

#### 4.5.5 gRPC 服务定义

> **Wire contract 单一事实来源**：Agent ↔ Gateway 的 RPC 形态以 `docs/architecture/aegis-transport-architecture.md` §12.1 为准；本节仅列出 Sensor 侧的语义契约与验签逻辑。任何字段/枚举差异均以 transport 文档为准并反向同步至此。

```protobuf
service AgentService {
  // EventStream 上下行封装为 UplinkMessage / DownlinkMessage，详见 transport §12.1.1-12.1.3
  rpc EventStream(stream UplinkMessage) returns (stream DownlinkMessage);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
  rpc UploadArtifact(stream ArtifactChunk) returns (UploadResult);
  rpc PullUpdate(UpdateRequest) returns (stream UpdateChunk);
}

// UplinkMessage（Agent→Gateway）oneof 封装：EventBatch / ClientAck / FlowControlHint
// DownlinkMessage（Gateway→Agent）oneof 封装：SignedServerCommand / BatchAck / FlowControlHint
// 详细字段见 transport §12.1.1-12.1.5

// 所有下行命令仍以 SignedServerCommand 为载荷（被包裹在 DownlinkMessage.command 字段中）
message SignedServerCommand {
  bytes   payload       = 1;  // ServerCommand 序列化字节
  bytes   signature     = 2;  // Ed25519 签名 (签名覆盖 payload 全部字节)
  string  signing_key_id = 3; // 签名密钥 ID，用于密钥轮换
}

message ServerCommand {
  string  command_id    = 1;  // 全局唯一 (UUIDv7)，防重放主键
  string  tenant_id     = 2;
  string  agent_id      = 3;  // unicast 目标；broadcast 可为空，由 target_scope 决定
  CommandType type      = 4;
  bytes   command_data  = 5;  // 具体命令载荷
  int64   issued_at     = 6;  // 签发时间戳 (Unix ms)，用于审计和壁钟 sanity bound
  uint32  ttl_ms        = 7;  // 命令有效期（相对 TTL，毫秒），Agent 收到后计算本地截止时间
  uint64  sequence_hint = 8;  // 排序辅助，非防重放主机制
  ApprovalPolicy approval  = 9;  // 审批策略（按动作类型差异化）
  TargetScope    target_scope = 10; // **签名覆盖**的扇出作用域（见 transport §12.1.3）；
                                    // Agent 侧验签后必须再次校验本机身份落在 target_scope 内
}

message ApprovalPolicy {
  uint32  min_approvers       = 1; // 最少审批人数（Remote Shell >= 2）
  repeated ApproverEntry approvers = 2; // 审批人条目（绑定 ID、角色、证明）
  string  policy_version      = 3; // 审批策略版本，Agent 侧可校验
}

// 将审批人 ID、角色、证明结构化绑定，避免平行数组导致角色与身份错位
message ApproverEntry {
  string  approver_id    = 1; // 审批人 ID
  string  role           = 2; // 审批人角色（security_admin / analyst 等），与 proof 绑定
  ApprovalProof proof    = 3; // 该审批人的不可抵赖证明（高危命令必填）
}

// 每个审批人或独立审批服务产生的不可抵赖证明
message ApprovalProof {
  bytes   signature      = 1; // 审批人对 canonical_command_hash 的 Ed25519 签名（见下方覆盖范围）
  string  signing_key_id = 2; // 审批人签名密钥 ID，用于密钥轮换
}

// ApprovalProof.signature 覆盖范围：
// canonical_command_hash = SHA-256(
//   command_id || tenant_id || agent_id || type ||
//   command_data || ttl_ms || policy_version
// )
// 覆盖完整命令内容，防止同一 command_id 下替换 command_data/ttl_ms 而不破坏审批签名
```

**命令签名验证流程（Agent 侧）：**

1. 从 `SignedServerCommand` 提取 `payload` 和 `signature`
2. 使用本地预置的 Server 签名公钥（安装时内嵌 + 支持在线轮换）验证 Ed25519 签名
3. 反序列化 `ServerCommand`，依次校验：
   - `tenant_id` 匹配本机配置的租户 ID（优先从设备证书 SAN 提取，而非仅依赖 payload 字段；高危命令须额外校验 per-tenant 信任根）
   - **`target_scope` 包含本机**：
     - `kind=AGENT` → `agent_id` 必须精确匹配本机
     - `kind=AGENT_SET` → `agent_ids` 必须包含本机 `agent_id`
     - `kind=TENANT` → `target_scope.tenant_id` 必须等于本机 `tenant_id`
     - `kind=GLOBAL` → 仅在本机配置显式允许 GLOBAL 命令时接受（默认关闭）
     - 任一失败即视为 **越权扇出**，即便签名有效也丢弃 + 上报 `COMMAND_SCOPE_VIOLATION`
   - 命令未过期（见下方时间校验机制）
   - `command_id` 去重（见下方防重放机制）
   - 审批策略校验（见下方审批执行机制）
4. 校验通过后执行；任何校验失败 → 丢弃命令 + 记录安全审计日志 + 上报 `COMMAND_REJECTED` 事件

**命令时间校验机制：**

命令有效期采用**相对 TTL** 而非绝对过期时间戳，避免壁钟与单调时钟的基准冲突：

- **接收时计算截止时间**：Agent 收到命令时，记录 `deadline = monotonic_now() + ttl_ms`，后续校验仅比较 `monotonic_now() < deadline`，基于同一时钟基准，无跨基准问题
- **壁钟 sanity bound**：`issued_at`（Unix ms）作为辅助校验——若 `abs(wall_clock_now - issued_at) > max_clock_skew`（默认 5 分钟），拒绝命令并上报 `CLOCK_SKEW_DETECTED` 告警。这可以防御极端时钟漂移或 NTP 篡改，但不作为过期判断的主时基
- **重启处理**：`deadline` 基于单调时钟，重启后失效。Agent 重启时丢弃所有未执行的 pending 命令，由控制面在 Heartbeat 中检测到重启事件后重新下发

**防重放机制（基于 command_id 去重）：**

不依赖单调递增 nonce，而采用 `command_id` 有界去重窗口：

- **去重账本**：本地持久化的 Bloom Filter + LRU 精确集，容量覆盖 `max_ttl` 时间窗口内的命令量（默认 72h / 10,000 条）
- **校验逻辑**：`command_id` 已存在于账本中 → 拒绝（重放）；不存在 → 放行并写入账本
- **TTL 联动**：`expires_at` 过期的 `command_id` 自动从账本中淘汰，控制存储开销
- **回滚保护**：去重账本的最新 checkpoint 时间戳锚定至 TPM NV Monotonic Counter（若可用）；端点重装/回滚后，若本地时间落后于 TPM 锚定值，拒绝所有 `issued_at` 早于锚定值的命令
- **降级**：无 TPM 环境下回退至 OS 安全存储 + 文件系统时间戳交叉校验；降级状态上报 Heartbeat

**审批策略执行机制（Agent 侧）：**

Agent 侧根据 `CommandType` 强制执行差异化审批校验，不仅检查"非空"：

| 动作类型 | 最少审批人数 | 角色要求 | 附加约束 |
|---------|------------|---------|---------|
| 进程 Kill / 文件隔离 | 0（可自动） | — | — |
| 网络隔离 / 用户会话锁定 | 1 | security_analyst 或以上 | — |
| 文件系统回滚 / 注册表回滚 | 1 | security_analyst 或以上 | — |
| Remote Shell | 2 | 至少 1 个 security_admin | 审批人互不相同 |
| Remote Forensics | 1 | security_analyst 或以上 | — |

校验逻辑：
1. 从 `ApprovalPolicy` 提取 `min_approvers` 和 `approvers`（`ApproverEntry` 列表）
2. 检查 `approvers` 中 `approver_id` 去重后数量 >= 上表对应的最少审批人数
3. 遍历每个 `ApproverEntry`，校验其 `role` 满足上表的角色要求——由于 `approver_id`、`role`、`proof` 结构化绑定在同一条目中，不存在角色与身份错位的风险
4. Remote Shell 额外检查：`approvers` 中 `approver_id` 无重复值，且至少 1 个条目的 `role` 为 `security_admin`
5. 校验 `policy_version` 不低于本地缓存的最低策略版本（防止策略降级攻击）
6. **独立审批证明验签**（高危命令必须通过）：
   - 对每个 `ApproverEntry.proof`，计算 `canonical_command_hash = SHA-256(command_id || tenant_id || agent_id || type || command_data || ttl_ms || policy_version)`，使用本地预置的审批人公钥（安装时内嵌，支持在线轮换）验证 `proof.signature` 覆盖该哈希
   - 验签通过的条目数量 >= `min_approvers`；验签同时确认该 `approver_id` 确实持有所声称的 `role`（通过本地目录或证书中的角色绑定）
   - 审批人公钥与命令签名公钥为**不同密钥体系**，确保控制面审批工作流 bug（签名密钥完好但审批流程被绕过）无法伪造审批证明
   - 低危命令（进程 Kill / 文件隔离）可豁免审批证明，仅校验命令签名即可

#### 4.5.6 差分上报与 Orphan 修复

三层保障：
1. 进程创建事件在 CRITICAL Lane（不可丢弃）
2. 每 5 分钟全量进程树快照
3. 云端 Orphan 检测 + ServerCommand 请求 Agent 补发

---

### 4.6 自保护模块

#### 4.6.1 四层纵深防御

**Layer 1：内核级保护**
- Windows: ObRegisterCallbacks / Minifilter / CmCallback / PsNotify / ELAM
- Linux: LSM / fanotify / eBPF 保护关键进程与目录
- macOS: System Extension + Endpoint Security
- 边界：可防御 Ring 3；对 Ring 0 仅检测

**Layer 2：完整性校验**
- Agent 二进制、驱动、规则、模型、插件统一签名校验
- 关键配置带版本号和 checksum digest
- 校验失败 -> restricted mode + high-priority alert

**Layer 3：看门狗**
- 主进程与 watchdog 双向心跳
- Windows: watchdog 注册为 PPL-AntiMalware
- Linux: LSM/AppArmor/SELinux 限制 ptrace/kill
- 内核完整性监控周期执行（见 4.1.7）
- 崩溃处理：自动拉起 + core dump 保留 + 上传崩溃摘要

**Layer 4：反篡改**
- Anti-Debug: 调试附加检测、时序异常、断点检测
- Hypervisor 检测: 仅告警不阻断
- Anti-Unload: 拒绝未授权卸载请求
- Secure Update: 升级包签名 + 版本闸门 + 回滚保护

#### 4.6.2 Agent 密钥与身份管理

```
设备身份: agent_id + device certificate + 平台证明 (TPM/Secure Enclave)

主密钥: 优先绑定 TPM/Secure Enclave; 回退至 OS credential store + 轮换

密钥派生 (HKDF):
├── WAL 加密      = HKDF(master_key, "wal-encryption")
├── 隔离区加密    = HKDF(master_key, "quarantine")
├── 配置加密      = HKDF(master_key, "config")
└── Registry Journal = HKDF(master_key, "reg-journal")

插件签名验证: 内置只读 trust root 公钥
使用策略: 短时解封, 使用后 zeroize; 关键 buffer mlock
轮换: 证书按策略轮换; 吊销时拒绝命令下发; 缓存凭据受 TTL + signature 约束
```

#### 4.6.3 崩溃利用分析

Agent 崩溃时自动收集 minidump/core dump、最近 4KB Ring Buffer 片段、异常类型与线程寄存器快照。本地分析崩溃地址、栈帧模式（ROP/JOP）、堆状态（spray/overflow/UAF），评分为 BENIGN_CRASH / SUSPICIOUS_CRASH / EXPLOITATION_LIKELY。SUSPICIOUS 及以上立即高优先级告警并提升取证保留等级。

---

### 4.7 插件隔离架构

```
Plugin Host (per plugin 独立 WASM 沙箱, wasmtime)
│
├── 每个插件: 独立内存空间 + CPU 时间限制
│
├── Host Function ABI:
│   ├── emit_event(event) → 主 Event Pipeline
│   ├── read_config(key) → 只读配置访问
│   ├── log(level, msg) → 结构化日志
│   └── request_scan(target) → 请求 YARA/ML 扫描
│
├── 崩溃处理:
│   ├── WASM trap → 捕获, 记录, 重启该插件（不影响主进程）
│   ├── 超时 (>100ms/event) → 终止 + 降级日志
│   └── 1 小时内崩溃 3 次 → 自动禁用 + 上报
│
└── 热修复:
    ├── 插件以 .wasm 文件独立分发
    ├── Ed25519 签名验证
    └── 插件版本独立于 Agent 版本
```

---

### 4.8 攻击故事线引擎 (Storyline Engine)

在 Agent 侧运行，将离散事件构建为实时攻击上下文：

```rust
Storyline {
    id:               u64,
    root_event:       EventRef,
    events:           Vec<EventRef>,
    processes:        HashSet<PID>,
    tactics:          Vec<MitreTactic>,
    techniques:       Vec<MitreTechnique>,
    severity:         Severity,
    kill_chain_phase: KillChainPhase,
    auto_narrative:   String,
}
```

**合并规则**：
- 同进程树共享 storyline_id
- 文件传递链（进程 A 写入 -> 进程 B 执行同一文件）
- 网络传递链（相同 C2 IP/domain、下载源）
- Temporal 规则命中时可跨进程树合并

**资源治理**：最多 500 个活跃 storyline，LRU 淘汰。云端负责最终可视化。

---

### 4.9 扩展能力模块

#### 4.9.1 攻击面削减 (ASR)

| 规则域 | 保护对象 | 模式 |
|--------|----------|------|
| Office 宏防护 | 阻止子进程创建/可执行内容写入/进程注入 | Block/Audit/Warn |
| 脚本执行控制 | 阻止混淆脚本/download-execute/WMI 持久化 | Block/Audit/Warn |
| 凭据保护 | 阻止非授权访问 LSASS / 凭据窃取内存读取 | Block/Audit/Warn |
| USB 执行控制 | 阻止从 USB 运行未签名进程 | Block/Audit/Warn |
| 网络保护 | 阻断已知恶意 IOC / 低信誉域名 | Block/Audit/Warn |

#### 4.9.2 身份威胁检测

- Kerberoasting (RC4 etype 23 TGS-REQ, 大量 TGS 请求)
- Golden Ticket (异常 TGT 有效期, SID history 异常)
- DCSync (非 DC 发起 DrsGetNCChanges RPC)
- Pass-the-Hash/Ticket, NTLM Relay, AS-REP Roasting

#### 4.9.3 欺骗技术

| 诱饵类型 | 触发条件 | 告警级别 |
|---------|---------|---------|
| 蜜凭据 | 被使用 | HIGH |
| 蜜文件 | 读取 / 修改 | MEDIUM / HIGH |
| 蜜共享 (SMB) | 枚举或访问 | HIGH |
| 蜜 DNS | 被解析或访问 | HIGH |

治理：全网唯一、周期轮换、对正常用户不可见。

#### 4.9.4 漏洞评估

- **软件清单**：Windows registry/MSI/AppX/Winget、Linux dpkg/rpm/snap/flatpak、macOS /Applications/Homebrew/pkgutil。每 6h 全量 + 实时增量
- **CVE 匹配**：云端下发增量 CPE->CVE 映射，本地解析，CVSS+EPSS+资产重要性排序
- **配置审计**：UAC/firewall/RDP/Credential Guard (Win)、SSH/SUID (Linux)、Gatekeeper/FDA (macOS)

#### 4.9.5 被动网络发现

完全被动（无主动探测）。数据源：ARP/NDP cache、DHCP、mDNS/LLMNR/NetBIOS、连接表、eBPF 被动抓取。输出：IP/MAC/hostname、TCP 指纹 OS 猜测、服务端口、Agent 安装状态、confidence score。多端点结果在云端汇聚为网络拓扑。

#### 4.9.6 AI 应用安全监控

- AI 应用清单（发现已安装 AI 工具，标记影子 AI）
- AI DLP（检测敏感数据进入 AI 会话，BLOCK/WARN/AUDIT）
- 模型完整性（监控 GGUF/ONNX/SafeTensors 文件篡改/替换）
- Prompt Injection 关联（AI 输出中的可执行指令 + 后续脚本执行关联）

#### 4.9.7 设备控制

匹配条件：Device Class / VID+PID / Serial Number / Device Instance Path / 加密状态

平台实现：
- Windows: PnP + SetupDi 监控 + 文件系统/卷挂载联动
- Linux: udev rules + USBGuard + LSM mount hook
- macOS: IOKit + ESF AUTH_MOUNT + MDM 联动

---

<a id="5-数据流设计"></a>
## 5. 数据流设计

### 5.1 端到端 Event Lineage 追踪

每条事件在内核态生成时即分配 lineage_id (128-bit, UUIDv7)：

```
lineage_id = UUIDv7
  ├── timestamp_ms[48]   // Unix 毫秒，不回卷（可用至公元 10889 年）
  ├── version[4]         // 固定 0b0111
  ├── rand_a[12]         // 随机位
  ├── variant[2]         // 固定 0b10
  └── rand_b[62]         // 随机位（内核态用 per-CPU 单调计数器替代，保证同毫秒内有序且无碰撞）
```

选择 UUIDv7 而非自定义编码的理由：48-bit 毫秒时间戳不会在可预见时间内回卷；自带时间排序性；与 OCSF/ECS 的 UUID 字段兼容；消除自定义 `timestamp_ns[48]` 方案在 ~78 小时后的确定性碰撞问题。

**追踪检查点：**

| 检查点 | 位置 | 计数器 |
|--------|------|--------|
| 1 | 内核态 Ring Buffer 写入 | rb_produced (per event_type) |
| 2 | 用户态 Ring Buffer 消费 | rb_consumed |
| 3 | Detection Engine 入口 | det_received |
| 4 | Decision Router 出口 | dec_emitted (per LOG/ALERT/RESP) |
| 5 | Comms WAL 写入 | wal_written |
| 6 | Comms gRPC 发送确认 | grpc_acked (server ACK) |

健康上报包含各检查点计数器差值，云端实时计算每环节丢失率和延迟分布。调试模式可按 lineage_id 查询完整生命周期（+32 bytes/event 开销）。

### 5.2 Threat Intelligence 反馈回路

```
Cloud Feedback → Agent Local Whitelist

反馈类型:
├── FALSE_POSITIVE_CONFIRM  → 自动加入 Local Adaptive Whitelist
│   条目: (rule_id, process_hash, target_path), TTL 7d
├── BENIGN_PROCESS_CONFIRM  → 降低检测敏感度, 减少 YARA/ML 频率
├── HIGH_RISK_INTEL_PUSH    → 临时提升 Sensor 粒度 + 降低告警阈值
└── TUNING_DIRECTIVE        → 批量调整规则参数

安全约束:
├── 白名单上限: 10,000
├── 所有下行指令均需端到端签名验证（见 4.5.5）
├── CRITICAL 级规则不可被白名单覆盖
└── 每条白名单操作记录审计日志
```

### 5.3 离线自治数据流

与云端断连 (>30s) 后自动进入自治模式：

- **Sensor**：全量采集不降级
- **Detection**：IOC/Sigma/YARA/ML/Temporal/Storyline 全部本地运行
- **Response**（三级分类，详见 4.4.4 响应能力矩阵）：
  - **自动执行**：进程 Suspend/Kill、文件隔离、ASR 规则、设备控制 — 检测触发后立即执行，无需审批
  - **预审批执行**：网络隔离、用户会话锁定 — 仅当本地存在有效预签名 Playbook（TTL 内）时自动执行；无有效 Playbook 则挂起至恢复连接
  - **禁止执行**：注册表/文件系统回滚、远程取证、Remote Shell — 进入 pending 队列，恢复连接后提交审批
- **Data**：遥测事件写入 Telemetry WAL（436MB，约 24-48h；耗尽策略见 4.5.3）；响应动作记录、命令状态和告警证据链写入 Forensic Journal（64MB，不可淘汰）
- **不可用**：跨端点关联、实时情报更新、远程取证/Shell、云端调度的诱饵轮换

**恢复流程**：重建 mTLS -> 提交 pending 审批队列 -> 离线摘要 -> WAL 按序回放 -> 拉取缺失更新 -> 云端补关联

---

<a id="6-性能设计"></a>
## 6. 性能设计

### 6.1 性能敏感路径分析

```
Latency Budget (Agent-side, per event):

Kernel hook execution:              ~200ns
Ring Buffer write (MPSC atomic):    ~800ns
   -- zero-copy mmap boundary --
Ring Buffer read (user-space):      ~200ns
Event decode + normalize:           ~500ns
Process Tree context fill:          ~300ns
Adaptive Whitelist check:           ~100ns
                                    --------
Subtotal (to detection entry):      ~2.1us

Stage 0: Fast Path Filter:          < 100ns
Stage 1: IOC Tiered Bloom/Cuckoo:   < 500ns
Stage 2: Rule VM + Temporal:        < 15us (大多数规则 < 1us)
Stage 5: Sharded Correlation:       < 2us
                                    --------
Detection subtotal (typical):       ~18us (P50), ~150us (P99)

Decision Router:                    ~100ns
Comms channel enqueue:              ~200ns
                                    --------
Agent-side total:                   ~20us (P50), ~200us (P99)
```

### 6.2 关键优化策略

| 优化点 | 技术手段 | 效果 |
|--------|----------|------|
| 内核-用户态传输 | mmap 零拷贝 | 消除数据复制 |
| 事件优先级 | 4 通道 MPSC Ring Buffer | CRITICAL 事件防饥饿 |
| 并发写入 | atomic_fetch_add 无锁 | 消除 mutex 争用 |
| 检测并行 | per-shard detection-pool | 消除跨线程同步 |
| IOC 查询 | Bloom/Cuckoo O(1) | 5M IOC 仅 ~10MB |
| ML 推理 | ONNX Runtime + 预热 | 消除模型加载延迟 |
| 规则匹配 | 编译到 bytecode VM | 执行效率接近原生 |
| 进程上下文 | LRU HashMap 内存缓存 | 避免重复系统调用 |

### 6.3 资源治理模型

分为 Level 0-3 四级，根据 CPU/Memory 压力自动切换：

| Level | CPU 阈值 | 行为 | ATT&CK 覆盖率 |
|-------|---------|------|---------------|
| 0 Normal | < 2% | 全量传感器 + 全量检测链 | ~85% |
| 1 Elevated | 2-3% | 保留全量安全能力，降低低价值遥测频率 | ~85% |
| 2 High | 3-5% | 暂停 File READ/WRITE(非 exe)、Registry INFO、Flow Stats | ~70% |
| 3 Critical | > 5% | 仅保留关键传感器和关键响应，上报 AGENT_DEGRADED | ~50% |

Level 3 降级告警包含：当前等级、触发原因、预估覆盖率、禁用 Sensor/检测阶段列表。

### 6.4 关键性能基准表

| 指标 | 目标 | 说明 |
|------|------|------|
| Agent 启动时间 | < 5s | 首次注册与首次全量资产同步不计入 |
| 稳态 CPU (P95) | <= 3% | 含 Storyline、ASR、Deception、Vuln Scan 等完整能力 |
| 峰值 CPU (P99) | <= 6% | 含模型推理、实时取证与完整性检查 |
| 内存 RSS (全功能) | <= 220MB | 全功能 profile |
| 事件处理吞吐 | >= 350K event/s | 含故事线关联与脚本解混淆 |
| 单事件延迟 P50 | < 20us | 常规检测路径 |
| 单事件延迟 P99 | < 200us | 含 temporal / storyline 关联 |
| Ring Buffer 丢事件率 (CRITICAL) | 0% | 优先级保留设计 |
| Ring Buffer 丢事件率 (全局) | < 0.01% | 低优先级 lane 允许受控丢弃 |
| 文件哈希吞吐 | >= 500 MB/s | 启用流式与硬件加速时 |
| 网络带宽均值 | <= 60 KB/s | 含资产、漏洞、发现与健康指标上报 |
| 网络带宽峰值 | <= 500 KB/s | 不含取证包 / 内存 dump 上传 |
| 磁盘写入均值 | <= 5 MB/s | 含 WAL、快照元数据与本地缓存 |
| 安装包大小 | <= 75 MB | 含模型、CVE 数据与诱饵模板 |
| 内存中规则集 | <= 22 MB | 含 temporal 状态与热更新缓冲 |
| 内存中 ML 模型 | <= 20 MB | 含主模型与冷启动模型 |
| VSS / 快照周期 | 4h | 默认保护周期，可按策略调整 |
| 金丝雀文件检测延迟 | < 100ms | 从文件被触碰到触发告警 |
| 离线检测能力 | 100% | 本地完整检测链与自主响应保持可用 |

> 上述指标以桌面/服务器全功能 profile 为基准。Sidecar、Runtime SDK、Cloud API Connector 等轻量模式按各自部署形态单独核算。

---

<a id="7-安全设计"></a>
## 7. 安全设计

### 7.1 信任边界

```
+--[Untrusted]--+     +--[Semi-Trusted]--+     +--[Trusted]--------+
|  Endpoints     | mTLS| Transport Plane   | mTLS| Analytics/Data/   |
|  (potentially  |---->| (Gateway, LB)     |---->| Management Planes |
|   compromised) |     |                   |     | (K8s cluster)     |
+----------------+     +-------------------+     +--------------------+
```

### 7.2 STRIDE 威胁模型

| 边界 | 威胁 | 缓解措施 |
|------|------|----------|
| Agent <-> Gateway | Spoofing | mTLS + 每 Agent 独立证书 |
| Agent <-> Gateway | Tampering | TLS 1.3 + Protobuf validation |
| Agent <-> Gateway | Repudiation | lineage_id + sequence logging |
| Agent <-> Gateway | Info Disclosure | TLS 加密 |
| Agent <-> Gateway | DoS | 按 Agent 限速 + 证书吊销 |
| Agent <-> Gateway | Elevation | Tenant ID 来自证书，非 payload |
| Agent self | Tampering | 四层自保护 |

### 7.3 mTLS 证书生命周期

```
Root CA (offline, HSM)
  └── Intermediate CA (online, Vault-managed)
       └── Agent Device Certificate (per-agent)
            Validity: 90 days
            CN: agent_id, SAN: tenant_id
            Key: TPM/Secure Enclave (优先) 或 OS keystore
```

**生命周期**：
1. Provisioning：生成密钥对 -> CSR -> 云端签发
2. Rotation：过期前 14 天主动轮换，原子切换
3. Revocation：CRL/OCSP 推送至 Gateway；被吊销 Agent 进入 degraded mode
4. Emergency rotation：带外通道触发强制轮换

### 7.4 数据安全

| 方面 | 机制 |
|------|------|
| 传输加密 | TLS 1.3 + mTLS |
| 存储加密 | AES-256-GCM (WAL/隔离区/配置) |
| 密钥管理 | TPM/Secure Enclave 绑定 + HKDF 派生 + zeroize |
| 内存保护 | mlock 敏感 buffer + 使用后 zeroize |
| 安全删除 | 文件系统级 crypto delete (优先) 或 overwrite + TRIM |

---

<a id="8-部署与运维"></a>
## 8. 部署与运维

### 8.1 安装

| 平台 | 安装包 | 内容 | 校验 |
|------|--------|------|------|
| Windows | MSI | 主进程 + 驱动 + watchdog + updater | 证书链 + 驱动签名 + ELAM |
| Linux | DEB/RPM | systemd service + eBPF assets + 策略 | kernel features + BTF/CO-RE |
| macOS | pkg | System Extension + Network Extension | 引导用户授权 |

**通用要求**：
- 安装前检查（磁盘、权限、OS 版本、冲突软件）
- 安装后最小化 self-test + rollback point 创建
- 首次心跳成功前不启用高风险自动响应

### 8.2 A/B 分区升级

- **Schema Migration**：SQLite agent.db 版本管理，内嵌迁移脚本，升级前自动备份
- **配置迁移**：config transformer 旧格式 -> 新格式 -> 校验 -> 写入
- **版本路径**：相邻版本 bsdiff 增量 (~5-15MB) -> 跨 1-3 版本 delta chain -> 超过 3 版本全量 (~75MB)

### 8.3 灰度发布闸门

| 健康指标 | Gate 阈值 |
|---------|-----------|
| crash_rate | < 0.1% |
| cpu_p95 | < 3% |
| memory_p95 | < 220MB |
| event_drop_rate | < 0.01% |
| detection_rate | >= 基线 90% |
| heartbeat_loss_rate | < 0.5% |

任一 Gate 不通过 -> 自动暂停灰度 + 可选自动回滚。

**灰度流程**：Canary 1% (50 Agent, 2h) -> 5% (4h) -> 25% (12h) -> 50% (24h) -> 100%

### 8.4 容器部署

**Mode A：宿主机 Agent + eBPF (DaemonSet)**
- Capabilities: BPF/PERFMON/SYS_ADMIN/SYS_PTRACE/NET_ADMIN/SYS_RESOURCE (先 drop ALL)
- readOnlyRootFilesystem: true, hostPID: true
- SELinux/AppArmor 严格限制
- ATT&CK 覆盖 ~85%

**Mode B：Sidecar (Lite Profile)**
- 禁用 YARA/ML/文件哈希（委托宿主机 Agent）
- 仅进程/网络/文件元数据，~200 条规则
- ~30MB memory, <0.5% CPU
- 通过 unix socket -> 宿主机 Agent -> Cloud

**Mode C：Serverless / Managed Runtime**
- Option 1: Runtime SDK (Lambda Layer, ATT&CK ~30%)
- Option 2: Cloud API log integration (CloudTrail, ATT&CK ~15%)
- Option 3: WASM Runtime Security Agent

### 8.5 Agent 健康指标上报

```
HeartbeatRequest.AgentHealth {
  agent_version, policy_version, ruleset_version, model_version,
  cpu_percent_p95, memory_rss_mb, queue_depths, dropped_events_total,
  sensor_status, communication_channel, kernel_integrity_pass,
  etw_tamper_detected, amsi_tamper_detected, bpf_integrity_pass,
  adaptive_whitelist_size, plugin_status,
  lineage_counters: {
    rb_produced, rb_consumed, rb_dropped (per Lane),
    det_received, dec_emitted, wal_written, grpc_acked
  }
}
```

### 8.6 诊断模式

`aegis-sensor --diagnose` 生成受控诊断包，包含：连接测试、证书状态、Sensor 状态、检测引擎版本、Ring Buffer 使用率、WAL 状态、资源使用、自保护状态。自动剔除密钥和敏感情报内容。

---

<a id="9-接口定义"></a>
## 9. 接口定义

### 9.1 模块间接口

#### 9.1.1 Ring Buffer -> Sensor Dispatch

| 项目 | 规格 |
|------|------|
| 传输机制 | mmap 共享内存，零拷贝 |
| 编码格式 | FlatBuffers (EventHeader + Payload) |
| 消费模式 | 单线程加权轮询 (4:2:1:1) |
| 背压信号 | Lane 0 利用率 > 50% -> 通知检测引擎 |

#### 9.1.2 Sensor Dispatch -> Detection Engine

| 项目 | 规格 |
|------|------|
| Channel | bounded_channel<NormalizedEvent>(65536) |
| 事件格式 | NormalizedEvent (解码 + 归一化 + lineage_id + 进程上下文) |
| 路由 | 按 process_group_id 分片到对应 detection-pool 线程 |

#### 9.1.3 Detection Engine -> Decision Router -> Comms/Response

| 判定 | 下游通道 | 数据格式 |
|------|---------|---------|
| BENIGN | comms-tx-normal (telemetry) | TelemetryBatch |
| SUSPICIOUS | comms-tx-normal (alert) | Alert (low priority) |
| MALICIOUS | comms-tx-high (alert) + response-tx | Alert + ResponseAction |
| CRITICAL | comms-tx-high (alert) + response-tx (immediate) | Alert + ResponseAction |

#### 9.1.4 用户态 -> 内核态 Block Decision Map

| 项目 | 规格 |
|------|------|
| 传输机制 | 共享内存 bitmap / BPF Map |
| 写入方 | 用户态检测引擎 |
| 读取方 | 内核态 pre-callback |
| 延迟 | < 1us |
| 容量 | 10,000 条目 |
| TTL | 默认 300s |

### 9.2 与 Server 的接口

#### 9.2.1 上行接口

| 接口 | 协议 | 数据格式 | 频率/触发 |
|------|------|---------|---------|
| EventStream | gRPC bidirectional stream | 上行 `UplinkMessage`（oneof = EventBatch / ClientAck / FlowControlHint，LZ4）；下行 `DownlinkMessage`（oneof = SignedServerCommand / BatchAck / FlowControlHint）。单一事实源见 transport §12.1.1-12.1.3 | 连续流 |
| Heartbeat | gRPC unary | Protobuf HeartbeatRequest | 每 60s |
| UploadArtifact | gRPC client stream | Protobuf ArtifactChunk | 按需 |
| PullUpdate | gRPC server stream | Protobuf UpdateChunk | 按需 |

#### 9.2.2 下行命令

所有下行命令通过 `SignedServerCommand` 作为 `DownlinkMessage.command` 字段在 EventStream 双向流中下发；Agent 侧必须完成端到端签名验证并校验 `ServerCommand.target_scope` 包含本机身份后才执行（详见 4.5.5 命令签名验证流程与 transport §12.1.3 TargetScope 签名覆盖契约）。

| 命令类型 | 说明 | 安全等级 |
|---------|------|---------|
| RESPONSE_ACTION | 响应动作指令（kill/quarantine/isolate/rollback/forensics） | 高危：需 ApprovalPolicy + command_id 去重 + TTL |
| REMOTE_SHELL | 远程 Shell 会话 | 最高危：需 min_approvers >= 2 + security_admin 角色 + TTL |
| POLICY_UPDATE | 策略更新推送 | 高危：需签名 + command_id 去重 |
| RULE_UPDATE | 规则/模型热更新 | 高危：需签名 + command_id 去重 |
| IOC_UPDATE | IOC 增量更新 | 常规：需签名 |
| FEEDBACK | 误报反馈/调优指令 | 常规：需签名 |
| REQUEST_PROCESS_INFO | 请求补发进程信息 | 常规：需签名 |
| CONFIG_CHANGE | 配置变更 | 高危：需签名 + command_id 去重 + TTL |

**信任模型**：mTLS 保护传输信道，命令级 Ed25519 签名保护指令完整性。Gateway/LB 为 Semi-Trusted，即使 Gateway 被攻破，攻击者无法伪造有效签名的 `ServerCommand`，从而无法驱动 Agent 执行任何高危动作。防重放基于 `command_id` 有界去重窗口，容忍乱序投递和签发节点切换。命令有效期采用相对 TTL（`ttl_ms`）+ 壁钟 sanity bound，避免绝对时间戳与单调时钟的基准冲突。审批策略按动作类型差异化执行，详见 4.5.5。

### 9.3 统一事件模型 (兼容 ECS/OCSF)

```
TelemetryEvent {
  // 核心字段
  event_id:        UUID
  lineage_id:      u128
  timestamp:       i64 (nanosecond)
  tenant_id:       string
  agent_id:        string

  host: { hostname, os, ip[], mac[], asset_tags[] }
  event_type:      enum (PROCESS_CREATE | FILE_WRITE | NET_CONNECT | ...)
  severity:        enum (INFO | LOW | MEDIUM | HIGH | CRITICAL)
  priority:        enum (CRITICAL | HIGH | NORMAL | LOW)

  // 多态载荷 (由 event_type 决定)
  process?:   { pid, ppid, name, cmdline, exe_path, exe_hash, user,
                integrity, signature, tree, cwd, env_vars, container_id,
                namespace_ids, protection_level }
  file?:      { path, hash, size, entropy, magic, action }
  network?:   { src_ip, src_port, dst_ip, dst_port, protocol,
                dns_query, dns_response, sni, ja3, ja3s, bytes_sent/recv }
  registry?:  { key_path, value_name, old_value, new_value, operation }
  auth?:      { logon_type, source_ip, user, domain, result,
                kerberos_type, elevation }
  script?:    { content, interpreter, obfuscation_layers,
                deobfuscated_content }
  memory?:    { region_address, region_size, protection,
                content_hash, injection_type }
  container?: { container_id, image, pod_name, namespace, node_name }

  // 故事线上下文
  storyline?: { storyline_id, processes, tactics, techniques,
                kill_chain_phase, narrative }

  // 富化字段
  enrichment: { geo, threat_intel, mitre_ttps, risk_score,
                asset_criticality, user_risk_score }

  // 直接系统调用检测
  syscall_origin?: { return_address, expected_module,
                     actual_module, is_direct }
}
```

---

<a id="10-技术选型说明"></a>
## 10. 技术选型说明

### 10.1 用户态语言：Rust

| 方面 | 说明 |
|------|------|
| **选择理由** | 零成本抽象接近 C 性能 + 编译期内存安全（所有权系统阻止 UAF/buffer overflow/data race）+ 单一二进制分发 + 条件编译跨平台 + wasmtime 原生 WASM 宿主 + tokio 异步生态 |
| **安全收益** | 降低 Agent 自身漏洞暴露面 -- Agent 运行在高权限环境，内存安全不是可选项 |
| **备选淘汰** | C++: 无内存安全保证；Go: GC pause 不适合实时检测，内存占用高；C: 安全风险最高 |

### 10.2 内核态事件传输：MPSC 优先级 Ring Buffer

| 方面 | 说明 |
|------|------|
| **选择理由** | mmap 零拷贝 + 4 优先级通道抵御噪声攻击 + atomic_fetch_add 无锁 MPSC + CRITICAL 通道有界 spin-wait |
| **备选淘汰** | 单一 Ring Buffer: 无法抵御噪声攻击；kernel-to-user pipe/netlink: 复制开销大；perf event: 无优先级通道 |

### 10.3 IOC 匹配：分层 Bloom + Cuckoo Filter

| 方面 | 说明 |
|------|------|
| **选择理由** | 分层 FPR 匹配 IOC 严重度 + Cuckoo 支持动态删除 + 5M IOC 仅 ~10MB + O(1) 查询 |
| **备选淘汰** | 单一 Bloom: 无法删除；HashSet: 5M*80B = ~400MB 超预算；Aho-Corasick: 不适合 hash/IP lookup |

### 10.4 ML 推理：ONNX Runtime (CPU)

| 方面 | 说明 |
|------|------|
| **选择理由** | 跨平台 CPU 推理 + 模型格式统一 + 多框架导出兼容 + 总模型 <= 20MB + 推理延迟 < 8ms |
| **模型策略** | Ensemble (XGBoost + LightGBM + MLP) 抗对抗 + 蒸馏 Transformer 脚本分析 + OOD 检测 |

### 10.5 通信协议：gRPC + mTLS + 回退链

| 方面 | 说明 |
|------|------|
| **选择理由** | HTTP/2 多路复用 + Protobuf 紧凑高效 + 内建 flow control + 双向流即时命令下发 |
| **抗审查** | WebSocket/Long-Polling/Domain Fronting 回退链 + utls JA3 随机化 |
| **备选淘汰** | HTTPS REST: 命令延迟高；MQTT: 偏 IoT；自定义 TCP: 需从零构建安全/framing |

### 10.6 插件隔离：WASM (wasmtime)

| 方面 | 说明 |
|------|------|
| **选择理由** | 独立 linear memory 内存隔离 + CPU 时间限制 + 独立 .wasm 分发 + Ed25519 签名 + Host Function ABI 受控访问 |
| **备选淘汰** | 独立进程: IPC 开销高；动态库: 无内存隔离；Lua/Python: GC pause + 弱沙箱 |

### 10.7 操作系统兼容性矩阵

| 平台 | 最低版本 | 内核态方式 | 降级方案 |
|------|---------|-----------|---------|
| Windows 10 | 1809 (LTSC 2019) | WDM Minifilter + WFP + ETW | -- |
| Windows 11 | 21H2 | 同上 | -- |
| Windows Server | 2016+ | 同上 | -- |
| Ubuntu | 18.04+ | eBPF (CO-RE, kernel 5.8+) | 4 级降级 |
| RHEL/CentOS | 7.6+ | eBPF (kernel 4.18+ with BTFHub) | 4 级降级 |
| Debian | 10+ | eBPF | 4 级降级 |
| Amazon Linux | 2+ | eBPF | 4 级降级 |
| SUSE | 15 SP2+ | eBPF | 4 级降级 |
| macOS | 12 (Monterey)+ | ESF + Network Extension | -- |
| AWS Lambda | 全版本 | Runtime SDK | 应用层仅 |
| ECS Fargate | 全版本 | Runtime SDK / API | 应用层仅 |

### 10.8 跨平台抽象层

```rust
pub trait PlatformSensor: Send + Sync {
    fn start(&mut self, config: &SensorConfig) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
    fn poll_events(&self, buf: &mut EventBuffer) -> Result<usize>;
    fn capabilities(&self) -> SensorCapabilities;
}

pub trait PlatformResponse: Send + Sync {
    fn suspend_process(&self, pid: u32) -> Result<()>;
    fn kill_process(&self, pid: u32) -> Result<()>;
    fn kill_ppl_process(&self, pid: u32) -> Result<()>;
    fn quarantine_file(&self, path: &Path) -> Result<QuarantineReceipt>;
    fn network_isolate(&self, rules: &IsolationRulesV2) -> Result<()>;
    fn network_release(&self) -> Result<()>;
    fn registry_rollback(&self, target: &RollbackTarget) -> Result<()>;
    fn collect_forensics(&self, spec: &ForensicSpec) -> Result<ArtifactBundle>;
}

pub trait PreemptiveBlock: Send + Sync {
    fn block_hash(&self, hash: &str, ttl: Duration) -> Result<()>;
    fn block_pid(&self, pid: u32, ttl: Duration) -> Result<()>;
    fn block_path(&self, path: &Path, ttl: Duration) -> Result<()>;
    fn block_network(&self, target: &NetworkTarget, ttl: Duration) -> Result<()>;
    fn clear_all_blocks(&self) -> Result<()>;
}

pub trait KernelIntegrity: Send + Sync {
    fn check_ssdt_integrity(&self) -> Result<IntegrityReport>;
    fn check_callback_tables(&self) -> Result<IntegrityReport>;
    fn check_kernel_code(&self) -> Result<IntegrityReport>;
    fn detect_hidden_processes(&self) -> Result<Vec<SuspiciousProcess>>;
}

pub trait PlatformProtection: Send + Sync {
    fn protect_process(&self, pid: u32) -> Result<()>;
    fn protect_files(&self, paths: &[PathBuf]) -> Result<()>;
    fn verify_integrity(&self) -> Result<IntegrityReport>;
    fn check_etw_integrity(&self) -> Result<EtwStatus>;   // Windows
    fn check_amsi_integrity(&self) -> Result<AmsiStatus>; // Windows
    fn check_bpf_integrity(&self) -> Result<BpfStatus>;   // Linux
}
```

---

## 附录 A：架构决策记录摘要

| ADR | 决策 | 关键理由 |
|-----|------|---------|
| ADR-001 | Agent 用户态采用 Rust | 内存安全 + 性能预算 + 高权限环境漏洞面 |
| ADR-006 | MPSC 优先级 Ring Buffer | 零拷贝 + 噪声攻击防御 + CRITICAL 事件保证 |
| ADR-007 | 分层 Bloom + Cuckoo Filter | 5M IOC ~10MB + 动态删除 + 分层 FPR |
| ADR-009 | WASM 插件隔离 | 内存隔离 + 独立分发 + 崩溃不影响主进程 |
| ADR-004 | gRPC + mTLS + 回退链 | HTTP/2 多路复用 + 强认证 + 抗审查 |

完整 ADR 详情请参考 `aegis-architecture-design.md` 第 9 章。

## 附录 B：术语表

| 术语 | 说明 |
|------|------|
| MPSC | Multi-Producer Single-Consumer |
| WAL | Write-Ahead Log |
| ASR | Attack Surface Reduction |
| ESF | Endpoint Security Framework (macOS) |
| WFP | Windows Filtering Platform |
| ETW | Event Tracing for Windows |
| AMSI | Anti-Malware Scan Interface |
| CO-RE | Compile Once, Run Everywhere (eBPF) |
| BTF | BPF Type Format |
| PPL | Protected Process Light |
| ELAM | Early Launch Anti-Malware |
| IOC | Indicator of Compromise |
| FPR | False Positive Rate |
| OOD | Out-of-Distribution |
| HKDF | HMAC-based Key Derivation Function |

---

> 本文档是 Aegis Sensor 的终态架构设计，覆盖了内核态采集、用户态引擎、检测流水线、响应执行、通信、自保护、插件架构和运维等全部子系统。文档可作为开发团队的实施指南，各子系统应按此架构进行详细设计和编码实现。
