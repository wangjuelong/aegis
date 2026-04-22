# EDR Endpoint Sensor 技术解决方案
## Production-Grade Endpoint Sensor Technical Specification
> 本文档定义 EDR Endpoint Sensor / Agent 的最终实施方案，覆盖内核态采集、用户态核心引擎、本地检测、响应执行、通信、自保护、升级发布、容器与云原生适配等核心子系统。
>
> 文档按终态架构组织，直接描述可落地的设计、边界、指标与运维要求，不再区分版本演进路径。
>
> 当前代码实现口径的分平台采集清单见：
> - [Windows 数据采集清单](../architecture/aegis-sensor-windows-data-collection.md)
> - [Linux 数据采集清单](../architecture/aegis-sensor-linux-data-collection.md)
---
## 一、Agent 总体架构
### 1.1 设计原则
| 原则 | 说明 |
|------|------|
| 最小特权 | 内核驱动仅做数据采集与事件投递，所有策略逻辑在用户态执行 |
| 故障隔离 | Sensor、Detection、Response、Comms 运行在独立线程池/进程，单模块崩溃不拖垮整体；Sensor 插件通过 WASM 沙箱隔离（见 1.4） |
| 零信任通信 | Agent ↔ Cloud 全链路 mTLS，本地存储 AES-256-GCM，内存敏感数据 mlock+zeroize，密钥绑定 TPM/Secure Enclave |
| 热更新 | 规则、ML 模型、Sensor 插件、配置均可在线热加载，无需重启 Agent 或内核驱动 |
| 可观测 | Agent 自身暴露健康指标（CPU/Mem/队列深度/丢事件计数）随心跳上报；端到端 event lineage ID 贯穿全链路 |
| 跨平台一致性 | 用户态核心用 Rust 编写单一代码库，通过条件编译 + 平台 Sensor Trait 适配三平台 |
| 明确保护边界 | Agent 自保护覆盖 Ring 3 攻击者的防护 + Ring 0 攻击者的检测（非防护），文档中对此做显式声明 |
| 自适应反馈 | Agent 支持本地检测结果反馈回路——云端确认的误报自动加入本地白名单，减少检测开销 |
| 离线自治 | 与云端失联时仍保留完整本地检测、缓存、响应与审计能力 |
| 攻击面削减 | Agent 不仅检测与响应，还通过 ASR、设备控制、防火墙策略主动压缩端点攻击面 |
### 1.2 进程模型
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
│  │  aegis-sensor-watchdog (看门狗, Rust, PPL 保护)      PID 1002      │      │
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
│  │  aegis-sensor-kmod (内核驱动/eBPF)                                  │      │
│  │  ├── 事件采集 Hook 点                                      │      │
│  │  ├── MPSC Ring Buffer (零拷贝到用户态, 优先级保留)         │      │
│  │  ├── 网络过滤 (隔离执行)                                   │      │
│  │  ├── ETW 完整性看门狗 (Windows)                            │      │
│  │  ├── BPF 程序完整性监控 (Linux)                            │      │
│  │  ├── VSS / 文件系统快照保护                                │      │
│  │  └── 设备过滤 / 存储访问控制                               │      │
│  └───────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────┘
```
### 1.3 内部数据流（含 Event Lineage）
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
                              │  │  填充)   │    │ │ Bloom Filter │ │  │
                              │  └──────────┘    │ │ → Sigma/YARA │ │  │
                              │                  │ │ → ML Model   │ │  │
                              │                  │ │ → Stateful   │ │  │
                              │  ┌──────────┐    │ │   Correlator │ │  │
                              │  │ Feedback │    │ └──────┬───────┘ │  │
                              │  │ Loop     │←───│────────┘         │  │
                              │  │ (误报白  │    └─────────────────┘  │
                              │  │  名单)   │              │           │
                              │  └──────────┘   ┌──────────▼──────┐   │
                              │                 │ Decision Router  │   │
                              │                 │ ┌───┐ ┌────┐┌──┐│   │
                              │                 │ │Log│ │Alrt││Rsp││   │
                              │                 │ └─┬─┘ └─┬──┘└┬─┘│   │
                              │                 └───┼─────┼────┼──┘   │
                              └─────────────────────┼─────┼────┼──────┘
                                                    │     │    │
                              ┌─────────────────────▼─────▼──┐ │
                              │  Comms Module                 │ │
                              │  ┌──────┐  ┌──────────────┐  │ │
                              │  │ WAL  │  │ gRPC Streams  │  │ │
                              │  │      ├─→│ Hi-Pri + Norm │  │ │
                              │  └──────┘  └──────────────┘  │ │
                              └──────────────────────────────┘ │
                                                               │
                              ┌─────────────────────────────────▼──┐
                              │  Response Executor                  │
                              │  Suspend → Kill / Quarantine /      │
                              │  Isolate / Rollback / Forensic      │
                              └────────────────────────────────────┘
```
### 1.4 插件隔离架构
```
解决: 单一 Rust 二进制的插件崩溃隔离问题
┌─────────────────────────────────────────────────────────────┐
│  Plugin Host (per plugin 独立 WASM 沙箱)                     │
│                                                             │
│  ┌───────────────────┐  ┌───────────────────┐               │
│  │  Plugin A (WASM)  │  │  Plugin B (WASM)  │   ...         │
│  │  ├── 独立内存空间  │  │  ├── 独立内存空间  │               │
│  │  ├── CPU 时间限制  │  │  ├── CPU 时间限制  │               │
│  │  └── Host API 调用 │  │  └── Host API 调用 │               │
│  └────────┬──────────┘  └────────┬──────────┘               │
│           │ Host Function ABI    │                           │
│  ┌────────▼──────────────────────▼──────────────────┐       │
│  │  Plugin Host Runtime (wasmtime)                   │       │
│  │  ├── emit_event(event) → 主 Event Pipeline        │       │
│  │  ├── read_config(key) → 只读配置访问              │       │
│  │  ├── log(level, msg) → 结构化日志                 │       │
│  │  └── request_scan(target) → 请求 YARA/ML 扫描    │       │
│  └───────────────────────────────────────────────────┘       │
│                                                             │
│  崩溃处理:                                                   │
│  ├── WASM trap → 捕获, 记录, 重启该插件 (不影响主进程)      │
│  ├── 超时 (>100ms/event) → 终止 + 降级日志                  │
│  └── 累计 3 次崩溃/小时 → 自动禁用该插件 + 上报              │
│                                                             │
│  热修复能力:                                                 │
│  ├── 插件以 .wasm 文件独立分发, 无需全量 Agent 升级          │
│  ├── 插件签名验证 (Ed25519)                                  │
│  └── 插件版本独立于 Agent 版本                               │
└─────────────────────────────────────────────────────────────┘
```
### 1.5 端到端 Event Lineage 追踪
```
解决: 事件在任意环节丢失时无法定位
每条事件在内核态生成时即分配 lineage_id (128-bit):
  lineage_id = (agent_id[64] | timestamp_ns[48] | seq[16])
追踪点:
  ┌─────────────────────────────────────────────────────────┐
  │  Checkpoint 1: 内核态 Ring Buffer 写入                   │
  │  → counter: rb_produced (per event_type)                 │
  │                                                         │
  │  Checkpoint 2: 用户态 Ring Buffer 消费                   │
  │  → counter: rb_consumed (per event_type)                 │
  │  → diff: rb_produced - rb_consumed = rb_in_flight        │
  │                                                         │
  │  Checkpoint 3: Detection Engine 入口                     │
  │  → counter: det_received                                 │
  │                                                         │
  │  Checkpoint 4: Decision Router 出口                      │
  │  → counter: dec_emitted (per decision: LOG/ALERT/RESP)   │
  │                                                         │
  │  Checkpoint 5: Comms WAL 写入                            │
  │  → counter: wal_written                                  │
  │                                                         │
  │  Checkpoint 6: Comms gRPC 发送确认                       │
  │  → counter: grpc_acked (server ACK)                      │
  └─────────────────────────────────────────────────────────┘
  健康上报中包含各 checkpoint counter 差值,
  云端可实时计算每个环节的丢失率和延迟分布。
  调试模式 (可按需开启):
  ├── 每条事件携带 lineage_id + checkpoint timestamps[]
  ├── 云端可按 lineage_id 查询完整生命周期
  └── 典型开销: +32 bytes/event, 仅调试模式启用
```
### 1.6 Threat Intelligence 反馈回路
```
解决: Agent 无法从云端反馈中自适应调整行为
Cloud Feedback → Agent Local Whitelist
┌──────────────────────────────────────────────────────────┐
│  反馈类型:                                                │
│  ├── FALSE_POSITIVE_CONFIRM                               │
│  │   云端分析师标记某告警为误报                            │
│  │   → Agent 自动加入 Local Adaptive Whitelist            │
│  │   → 白名单条目: (rule_id, process_hash, target_path)  │
│  │   → TTL: 7 天, 到期后重新触发检测                      │
│  │                                                        │
│  ├── BENIGN_PROCESS_CONFIRM                               │
│  │   云端 ML 确认某进程行为正常                            │
│  │   → 降低该进程的检测敏感度 (提高阈值)                   │
│  │   → 减少 YARA/ML 扫描频率                              │
│  │                                                        │
│  ├── HIGH_RISK_INTEL_PUSH                                 │
│  │   云端推送紧急 IOC / 新攻击模式                        │
│  │   → 临时提升相关 Sensor 采集粒度                        │
│  │   → 临时降低相关规则的告警阈值                          │
│  │                                                        │
│  └── TUNING_DIRECTIVE                                     │
│      云端全局调优指令 (基于全网误报统计)                    │
│      → 批量调整规则参数 (阈值/白名单/采样率)               │
│                                                           │
│  安全约束:                                                 │
│  ├── 白名单条目上限: 10,000                                │
│  ├── 所有反馈指令需云端签名验证                             │
│  ├── 白名单不可覆盖 CRITICAL 级规则                        │
│  └── 每条白名单操作记录审计日志                             │
└──────────────────────────────────────────────────────────┘
```
### 1.7 Storyline Engine — 攻击故事线
```
Storyline Engine 用于在 Agent 端实时构建攻击上下文, 将离散事件组织为可追溯的攻击叙事。

Storyline {
  id:              u64
  root_event:      EventRef
  events:          Vec<EventRef>
  processes:       HashSet<PID>
  tactics:         Vec<MitreTactic>
  techniques:      Vec<MitreTechnique>
  severity:        Severity
  kill_chain_phase: KillChainPhase
  auto_narrative:  String
}

构建规则:
├── 同一进程树下的事件默认共享同一 storyline_id
├── 文件传递链:
│   ├── 进程 A 写文件
│   └── 进程 B 读取/执行同一文件 → 归并到同一故事线
├── 网络传递链:
│   ├── 相同 C2 IP/域名
│   └── 相同下载源 / 横向移动目标 → 归并
├── Temporal 规则命中时可跨进程树合并 storyline
├── 告警上报时附带 storyline 摘要
│   ├── 涉及的进程
│   ├── 命中的 MITRE Tactic / Technique
│   └── 自动生成的攻击叙述
└── 资源治理:
    ├── 最多维护 500 个活跃 storyline
    ├── 使用 LRU 淘汰
    └── 云端负责最终可视化, Agent 仅维护实时数据结构
```
---
## 二、内核态子系统
### 2.1 设计哲学
内核驱动/eBPF 程序**只做四件事**：
1. **Hook** — 挂载到操作系统事件源
2. **Filter** — 在内核态做最小化的前置过滤（减少用户态负载）
3. **Deliver** — 通过零拷贝 MPSC Ring Buffer 投递事件到用户态
4. **Guard** — 监控自身及操作系统关键结构的完整性（ETW 看门狗、BPF 程序监控、内核代码段校验）
所有策略判断、检测逻辑、响应决策**一律在用户态**完成，最大限度降低内核态代码复杂度和 BSOD/Kernel Panic 风险。
**保护边界声明**：Agent 内核态组件能够**防护** Ring 3 攻击者（阻断其对 Agent 的篡改），但对 Ring 0 攻击者仅提供**检测**能力（发现 rootkit/内核篡改后上报告警），不保证防护——因为与 Ring 0 攻击者共享同一特权级时，完美防护在理论上不可实现。
### 2.2 Windows 内核驱动栈
```
aegis-sensor-kmod.sys (WDM Minifilter + WFP Callout + ETW Provider)
│
├── Process Monitor
│   ├── PsSetCreateProcessNotifyRoutineEx2
│   │   → 捕获进程创建/退出，含完整 ImageFileName、CommandLine、Token 信息
│   ├── PsSetCreateThreadNotifyRoutineEx
│   │   → 捕获线程创建（用于检测远程线程注入 T1055）
│   ├── PsSetLoadImageNotifyRoutineEx
│   │   → DLL/驱动加载事件，含签名验证结果
│   ├── ObRegisterCallbacks
│   │   → 保护 Agent 进程句柄不被 OpenProcess/DuplicateHandle 窃取
│   │   → ⚠️ 保护边界: 仅防护 Ring 3 攻击者; Ring 0 可绕过 Ob 回调
│   │     (通过直接引用 EPROCESS 或 patch 回调表)
│   │   → 检测补充: 看门狗定期校验 Ob 回调表完整性 (见 2.7)
│   └── Direct Syscall Detection
│       → 在内核 callback 中记录 syscall 返回地址
│       → 验证返回地址是否落在 ntdll.dll 合法代码段内
│       → 非 ntdll 来源的 syscall → 标记为 DIRECT_SYSCALL 事件
│       → 用于检测 SysWhispers3 / HellsGate / HalosGate 等工具
│
├── File Monitor (Minifilter)
│   ├── IRP_MJ_CREATE          → 文件打开/创建
│   ├── IRP_MJ_WRITE           → 文件写入（含偏移量、大小）
│   ├── IRP_MJ_SET_INFORMATION → 重命名/删除/属性变更
│   ├── IRP_MJ_CLEANUP         → 文件关闭（触发哈希计算）
│   └── Pre/Post Operation Callbacks
│       → Pre-op 用于阻断（如隔离状态下阻止写入）
│       → Pre-op 用于预防性阻断（检测引擎高置信判定时直接阻断, 见 5.3）
│       → Post-op 用于采集（文件内容哈希、entropy 计算）
│   ├── 过滤优化:
│   │   ├── Volume/Path 白名单 (跳过 %SystemRoot%\WinSxS 等噪音路径)
│   │   ├── 进程白名单 (跳过 Windows Update / SCCM 等可信进程)
│   │   └── 文件大小阈值 (>100MB 的文件只记录元数据不计算哈希)
│
├── Registry Monitor
│   ├── CmRegisterCallbackEx
│   │   → RegNtPreSetValueKey    — 值写入前回调
│   │   → RegNtPostSetValueKey   — 值写入后回调
│   │   → RegNtPreDeleteKey      — 键删除前回调
│   │   → RegNtPreCreateKeyEx    — 键创建前回调
│   ├── Registry Change Journal
│   │   → 每次写操作记录: (key_path, value_name, old_value, new_value, timestamp, pid)
│   │   → 持久化到本地 SQLite: /data/registry_journal.db
│   │   → 支持 point-in-time 回滚: 给定 timestamp 回退所有变更
│   │   → 空间限制: 最多保留 7 天 / 100MB, FIFO 淘汰
│   └── 监控焦点路径:
│       ├── HKLM\Software\Microsoft\Windows\CurrentVersion\Run*
│       ├── HKLM\SYSTEM\CurrentControlSet\Services
│       ├── HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
│       ├── HKLM\Software\Classes\CLSID (COM Hijacking)
│       └── HKCU\Software\Microsoft\Windows\CurrentVersion\Run*
│
├── Network Monitor (WFP Callout)
│   ├── FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6
│   │   → 出站连接建立（含进程上下文）
│   ├── FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6
│   │   → 入站连接接受
│   ├── FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4/V6
│   │   → 连接建立（用于流量统计）
│   ├── FWPM_LAYER_OUTBOUND_TRANSPORT_V4/V6
│   │   → 传输层出站（网络隔离执行点）
│   └── DNS 解析捕获:
│       → ETW Microsoft-Windows-DNS-Client
│       → 或 WFP 对 UDP:53/TCP:53 的 payload 解析
│
├── AMSI Integration + Bypass Detection
│   ├── 注册为 AMSI Provider
│   │   → 接收 PowerShell/VBScript/JScript 执行内容
│   │   → 接收 .NET Assembly 加载内容
│   ├── 与本地检测引擎联动:
│   │   → 脚本内容直接投递到检测流水线
│   │   → 支持阻断（返回 AMSI_RESULT_DETECTED）
│   │   → 检测引擎快速路径判定 → 直接返回 AMSI 阻断 (见 4.1 Stage 2.5)
│   └── AMSI Bypass Detection :
│       ├── 定期校验 amsi.dll 内存完整性:
│       │   → AmsiScanBuffer 函数入口字节 hash
│       │   → amsi.dll .text section hash
│       │   → 检测 patch (如 mov eax, 0x80070057; ret)
│       ├── 监控 amsi.dll 卸载事件:
│       │   → PsSetLoadImageNotifyRoutine 捕获卸载
│       │   → 进程中 amsi.dll 消失 → CRITICAL 告警
│       ├── .NET CLR 内部字段篡改检测:
│       │   → 监控 clr.dll!AmsiInitialize 返回值
│       │   → 检测 amsiinitfailed 字段被强制设置为 true
│       └── 所有 AMSI bypass 检测结果:
│           → event_type: AMSI_TAMPER_DETECTED
│           → severity: CRITICAL
│           → auto_response: SUSPEND + ALERT (该进程所有后续脚本执行不可信)
│
├── ETW Tamper Detection & Resilience
│   ├── ETW Provider 看门狗:
│   │   ├── 内核驱动定期 (每 10s) 枚举已注册的 ETW Provider
│   │   ├── 检测 Agent 依赖的 Provider 是否被卸载/禁用
│   │   ├── 检测 NtTraceControl 调用 (通过 syscall hook / callback)
│   │   └── Provider 异常 → 自动重注册 + CRITICAL 告警
│   ├── ntdll!EtwEventWrite Patch 检测:
│   │   ├── 定期校验 EtwEventWrite 函数入口字节
│   │   ├── 检测 ret/nop patch (常见 ETW blind 技术)
│   │   └── 检测到 patch → CRITICAL 告警 + 切换到 Direct Callback 模式
│   ├── Fallback: Direct Kernel Callbacks:
│   │   ├── 当 ETW 被篡改时, 启用纯内核回调采集模式
│   │   ├── PsSetCreateProcessNotifyRoutine (已有, 不依赖 ETW)
│   │   ├── Minifilter (已有, 不依赖 ETW)
│   │   └── WFP Callout (已有, 不依赖 ETW)
│   │   → ETW 失效时的能力降级评估:
│   │       ├── 丢失: PowerShell Logging, WMI Activity, DNS Client 详细日志
│   │       ├── 保留: 进程/文件/网络/注册表的核心事件 (80%+ 覆盖)
│   │       └── MITRE ATT&CK 覆盖率: 约从 85% 降至 70%
│   └── 检测 "ETW Threat Intelligence" Provider 篡改:
│       → Ti Provider 被 Microsoft 用于内核级遥测
│       → 篡改 Ti Provider 是高级攻击标志
│       → 检测 + 告警 (Agent 无法恢复 Ti Provider, 但可以通知)
│
├── ETW Consumer (补充采集)
│   ├── Microsoft-Windows-Kernel-Process
│   ├── Microsoft-Windows-Kernel-File
│   ├── Microsoft-Windows-Kernel-Network
│   ├── Microsoft-Windows-Security-Auditing
│   ├── Microsoft-Windows-PowerShell
│   ├── Microsoft-Windows-WMI-Activity
│   ├── Microsoft-Windows-TaskScheduler
│   └── Microsoft-Windows-Sysmon (若共存)
│
├── MPSC Ring Buffer
│
└── Self-Protection Enforcement
    ├── ObRegisterCallbacks → 阻止对 Agent 进程的句柄操作 (Ring 3)
    ├── Minifilter → 阻止对 Agent 文件/目录的修改
    ├── CmRegisterCallbackEx → 阻止对 Agent 注册表键的修改
    ├── PsSetCreateProcessNotifyRoutine → 阻止 Agent 进程被终止
    └── ELAM (Early Launch Anti-Malware) → Agent 驱动最早加载
```
### 2.3 Linux 内核态 (eBPF)
```
aegis-sensor-ebpf (CO-RE, BTF-enabled, libbpf-based)
│
├── Process Sensor Programs
│   ├── tracepoint/sched/sched_process_exec
│   │   → 进程执行，读取 bprm->filename、argv、envp
│   ├── tracepoint/sched/sched_process_exit
│   │   → 进程退出 + exit_code
│   ├── tracepoint/sched/sched_process_fork
│   │   → fork 事件，建立父子进程关联
│   ├── kprobe/__x64_sys_execve / kprobe/__x64_sys_execveat
│   │   → execve 系统调用入口（补充 tracepoint 不足场景）
│   ├── kprobe/commit_creds
│   │   → 权限变更（检测提权）
│   ├── LSM/bprm_check_security
│   │   → 可执行文件加载安全检查点（支持阻断）
│   │   → 与检测引擎联动实现预防性阻断 (见 5.3)
│   └── kprobe/do_mmap / kprobe/vm_mmap_pgoff
│       → 内存映射（检测进程注入 / 无文件执行）
│
├── File Sensor Programs
│   ├── fentry/vfs_write / fentry/vfs_writev → 文件写入事件
│   ├── fentry/vfs_rename → 文件重命名
│   ├── fentry/vfs_unlink → 文件删除
│   ├── fentry/security_file_open → 文件打开（LSM Hook，支持阻断）
│   ├── fanotify (用户态补充)
│   │   → FAN_CLOSE_WRITE — 文件写关闭（触发哈希）
│   │   → FAN_OPEN_PERM — 可执行文件打开（阻断支持）
│   └── 过滤:
│       → BPF Map 存储路径白名单 (LPM Trie)
│       → 跳过 /proc, /sys, /dev, /run 等虚拟文件系统
│
├── Network Sensor Programs
│   ├── kprobe/tcp_v4_connect / kprobe/tcp_v6_connect → TCP 出站
│   ├── kprobe/inet_csk_accept → TCP 入站
│   ├── tracepoint/sock/inet_sock_set_state → TCP 状态变迁
│   ├── kprobe/udp_sendmsg / kprobe/udp_recvmsg → UDP
│   ├── fentry/security_socket_connect → LSM（支持阻断/网络隔离）
│   ├── TC (Traffic Control) / XDP → 高性能包级过滤
│   └── DNS 解析:
│       → 解析 UDP:53 payload (内核态 DNS 协议解码)
│       → 或 uprobe on getaddrinfo/gethostbyname
│
├── Auth Sensor Programs
│   ├── uprobe on pam_authenticate / pam_open_session → PAM
│   ├── kprobe/audit_log_start → audit 子系统
│   └── 读取 /var/log/auth.log (inotify 监控 + 解析)
│
├── Container-Aware Programs
│   ├── 所有 eBPF 程序读取: cgroup_id + namespace IDs
│   ├── cgroup 元数据关联: containerd/CRI-O socket 查询
│   └── 容器逃逸检测: nsenter/setns/unshare/CAP_SYS_ADMIN 监控
│
├── BPF Self-Protection
│   ├── 监控 bpf() 系统调用:
│   │   ├── tracepoint/syscalls/sys_enter_bpf
│   │   ├── 检测非 Agent 进程对 BPF 子系统的操作
│   │   ├── 检测 BPF_PROG_DETACH / BPF_LINK_DETACH 调用
│   │   └── 非授权 bpf() 调用 → CRITICAL 告警
│   ├── 定期校验已加载 BPF 程序完整性:
│   │   ├── 用户态通过 bpf(BPF_PROG_GET_FD_BY_ID) 枚举
│   │   ├── 验证 Agent BPF 程序仍在加载列表中
│   │   ├── 验证程序 tag (insn hash) 未被篡改
│   │   └── 校验频率: 每 30s
│   └── BPF 程序固定 (pinning):
│       → 所有 Agent BPF 程序 pin 到 /sys/fs/bpf/edr/
│       → 监控 pin 路径的 unlink 操作
│       → pin 文件被删除 → 自动重加载 + CRITICAL 告警
│
├── Ring Buffer (见 2.5 统一设计)
│
├── BPF Maps (内核态数据结构)
│   ├── config_map        (BPF_MAP_TYPE_ARRAY)         — 运行时配置
│   ├── pid_whitelist     (BPF_MAP_TYPE_HASH)          — 进程白名单
│   ├── path_whitelist    (BPF_MAP_TYPE_LPM_TRIE)      — 路径前缀白名单
│   ├── ioc_bloom_filter  (BPF_MAP_TYPE_ARRAY)         — IOC 布隆过滤器
│   ├── process_cache     (BPF_MAP_TYPE_LRU_HASH)      — 进程元数据缓存
│   ├── connection_track  (BPF_MAP_TYPE_LRU_HASH)      — 连接跟踪表
│   ├── drop_counters     (BPF_MAP_TYPE_PERCPU_ARRAY)  — 丢事件计数
│   ├── isolation_rules   (BPF_MAP_TYPE_LPM_TRIE)      — 网络隔离规则
│   └── bpf_prog_hashes  (BPF_MAP_TYPE_HASH)          — BPF 程序校验哈希
│
└── 兼容性策略 + 降级能力量化
    ├── 优先: CO-RE + BTF (kernel ≥ 5.8, 零适配)
    ├── 降级1: CO-RE + BTF from BTFHub (kernel 4.18+ without BTF)
    ├── 降级2: kprobe + fallback helpers (kernel 4.14+)
    └── 降级3: 纯用户态 (auditd + fanotify + /proc polling)
              → 降级能力量化表 :
    ┌──────────────────────┬──────────┬──────────┬──────────┬──────────┐
    │  能力                │ 完整 eBPF│ 降级1    │ 降级2    │ 降级3    │
    ├──────────────────────┼──────────┼──────────┼──────────┼──────────┤
    │ 进程创建/退出        │ ✅       │ ✅       │ ✅       │ ✅ (audit)│
    │ 进程注入检测         │ ✅       │ ✅       │ ⚠️ 部分  │ ❌        │
    │ 文件读写监控         │ ✅       │ ✅       │ ✅       │ ✅ (fano) │
    │ 网络连接追踪         │ ✅       │ ✅       │ ✅       │ ⚠️ (ss)  │
    │ DNS 内核态解析       │ ✅       │ ✅       │ ⚠️ uprobe│ ❌        │
    │ 容器感知             │ ✅       │ ✅       │ ⚠️ 部分  │ ❌        │
    │ 网络隔离 (XDP)       │ ✅       │ ✅       │ ❌ nftab │ ❌ nftab  │
    │ 预防性阻断 (LSM)     │ ✅       │ ✅       │ ❌       │ ❌        │
    │ 容器逃逸检测         │ ✅       │ ✅       │ ⚠️ 部分  │ ❌        │
    │ BPF 自保护监控       │ ✅       │ ✅       │ ⚠️ 部分  │ N/A      │
    ├──────────────────────┼──────────┼──────────┼──────────┼──────────┤
    │ ATT&CK 覆盖率 (估)  │ ~85%     │ ~82%     │ ~65%     │ ~45%     │
    │ 可用响应动作         │ 全部     │ 全部     │ 无LSM阻断│ 仅 Kill  │
    │ 上报标签             │ FULL     │ FULL     │ DEGRADED │ LIMITED  │
    └──────────────────────┴──────────┴──────────┴──────────┴──────────┘
```
### 2.4 macOS 内核态 (Endpoint Security Framework)
```
aegis-sensor-esf (System Extension, ESF Client)
│
├── ESF Event Subscriptions
│   ├── AUTH Events (可阻断)
│   │   ├── ES_EVENT_TYPE_AUTH_EXEC          → 进程执行
│   │   ├── ES_EVENT_TYPE_AUTH_OPEN          → 文件打开
│   │   ├── ES_EVENT_TYPE_AUTH_RENAME        → 文件重命名
│   │   ├── ES_EVENT_TYPE_AUTH_UNLINK        → 文件删除
│   │   ├── ES_EVENT_TYPE_AUTH_MMAP          → 内存映射
│   │   ├── ES_EVENT_TYPE_AUTH_MOUNT         → 文件系统挂载
│   │   └── ES_EVENT_TYPE_AUTH_SIGNAL        → 信号发送
│   │
│   ├── NOTIFY Events (仅观测)
│   │   ├── ES_EVENT_TYPE_NOTIFY_EXEC/FORK/EXIT → 进程生命周期
│   │   ├── ES_EVENT_TYPE_NOTIFY_WRITE/CLOSE/CREATE → 文件操作
│   │   ├── ES_EVENT_TYPE_NOTIFY_KEXTLOAD    → 内核扩展加载
│   │   ├── ES_EVENT_TYPE_NOTIFY_PTY_GRANT   → 伪终端分配
│   │   ├── ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED → 代码签名失效
│   │   └── ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE → 远程线程
│   │
│   └── Network Events
│       ├── Network Extension (NEFilterDataProvider)
│       └── ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN
│
├── 响应: es_respond_auth_result / es_mute_process
└── 部署: System Extension + MDM + Notarization
```
### 2.5 MPSC Ring Buffer 详细设计
```
目标: 支持多内核线程 producer，并避免溢出时覆盖高价值事件
架构: Multi-Producer Single-Consumer + Priority-Preserving Overflow
共享内存布局 (64MB, mmap)
┌──────────────────────────────────────────────────────────────┐
│  Header (4KB, Page-aligned)                                   │
│  ┌───────────────────────────────────────────────────────┐   │
│  │  magic:         u64  = 0x45445252_494E4732 ("EDRRING2") │
│  │  version:       u32  = 2                                │
│  │  total_capacity: u64 = 67104768 (64MB - 4KB)            │
│  │  flags:         AtomicU32  (ACTIVE | PAUSED | DRAINING)  │
│  │  reserved:      [u8; ...]                                │
│  └───────────────────────────────────────────────────────┘   │
├──────────────────────────────────────────────────────────────┤
│  Priority Lanes (分优先级的独立环形缓冲)                       │
│                                                              │
│  ┌─── Lane 0: CRITICAL (8MB, 不可丢弃) ──────────────────┐  │
│  │  用途: PROCESS_CREATE/EXIT, AUTH_*, AMSI_TAMPER,       │  │
│  │        ETW_TAMPER, DIRECT_SYSCALL, NETWORK_CONNECT      │  │
│  │  溢出: 阻塞等待 (bounded spin, 最多 100μs)              │  │
│  │        超时后仍满 → 强制写入 + 覆盖最旧 + ERROR 计数    │  │
│  │  Header:                                                │  │
│  │    write_offset:  AtomicU64                              │  │
│  │    read_offset:   AtomicU64                              │  │
│  │    drop_count:    AtomicU64                              │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌─── Lane 1: HIGH (16MB) ───────────────────────────────┐  │
│  │  用途: FILE_WRITE (可执行文件), REGISTRY_WRITE,        │  │
│  │        SCRIPT_EXEC, DNS_QUERY, SUSPICIOUS_*             │  │
│  │  溢出: 丢弃当前事件 + drop_count++                      │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌─── Lane 2: NORMAL (24MB) ────────────────────────────┐   │
│  │  用途: FILE_WRITE (普通), FILE_READ, NET_FLOW_STATS    │  │
│  │  溢出: 丢弃当前事件 + 启动采样模式 (1/10)              │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌─── Lane 3: LOW (16MB) ───────────────────────────────┐   │
│  │  用途: FILE_INFO (metadata-only), HEARTBEAT_INTERNAL   │  │
│  │  溢出: 直接丢弃, 仅递增 drop_count                     │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                              │
│  MPSC 写入协议 (内核态, 任意线程/IRQL):                        │
│  1. lane = priority_classify(event_type)                     │
│  2. total = align8(32 + payload_len)                         │
│  3. slot = atomic_fetch_add(&lane.write_offset, total)       │
│  4. if slot 超出 lane 容量:                                   │
│       按 lane 溢出策略处理 (阻塞/丢弃/采样)                  │
│  5. memcpy(lane.data[slot % lane.capacity], event, total)    │
│  6. store_release(event.flags, COMMITTED)                    │
│                                                              │
│  MPSC 正确性保证:                                             │
│  ├── atomic_fetch_add 保证 slot 分配的原子性                  │
│  ├── 每个 slot 独立写入, 无写-写竞争                         │
│  ├── COMMITTED flag 用 store_release, consumer 用 load_acquire│
│  └── Consumer 遇到未 COMMITTED 的 slot → spin_wait (bounded) │
│                                                              │
│  Consumer (用户态, 单线程):                                   │
│  1. Round-robin 按优先级轮询: Lane 0 (4次) → Lane 1 (2次)   │
│     → Lane 2 (1次) → Lane 3 (1次) → 循环                    │
│  2. 保证 CRITICAL 事件被最优先消费                             │
│  3. 背压信号: Lane 0 使用率 > 50% → 通知检测引擎加速         │
└──────────────────────────────────────────────────────────────┘
Linux eBPF 实现:
  ├── 4 个独立 BPF_MAP_TYPE_RINGBUF (替代单一 ringbuf)
  ├── 每个 map 对应一个 priority lane
  └── 用户态通过 ring_buffer__poll 同时监听 4 个 ringbuf
性能指标:
  - 单事件投递延迟: < 800ns (MPSC 略高于 SPSC)
  - 吞吐: > 3M events/sec (单核消费, 4-lane 轮询)
  - CRITICAL 事件丢失率: 0 (设计目标, 正常负载)
  - 噪音攻击防御: 攻击者制造的高频 FILE 事件仅影响 Lane 2/3,
    不影响 Lane 0 的 Process/Auth 事件
```
### 2.6 Kernel Integrity Monitoring
```
解决: 内核 rootkit 对抗能力缺失
┌─────────────────────────────────────────────────────────────┐
│  Kernel Integrity Monitor (在看门狗进程中运行)                │
│                                                             │
│  Windows:                                                   │
│  ├── SSDT (System Service Descriptor Table) 校验:           │
│  │   ├── 启动时记录 SSDT 基准 hash                          │
│  │   ├── 每 30s 重新计算 SSDT hash                          │
│  │   ├── 变化 → CRITICAL: KERNEL_TAMPER_SSDT               │
│  │   └── 注: Windows 8+ PatchGuard 已保护 SSDT,            │
│  │       但 PatchGuard 本身可被高级 rootkit 绕过             │
│  ├── IDT (Interrupt Descriptor Table) 校验:                 │
│  │   ├── 同 SSDT 的基准+定期校验模式                        │
│  │   └── IDT 条目被修改 → CRITICAL: KERNEL_TAMPER_IDT      │
│  ├── 内核代码段完整性:                                       │
│  │   ├── ntoskrnl.exe .text section hash (基准 vs 运行时)   │
│  │   └── 关键函数入口字节检查 (NtCreateProcess 等)          │
│  ├── Callback 表完整性:                                      │
│  │   ├── ObRegisterCallbacks 回调列表枚举+校验              │
│  │   ├── PsSetCreateProcessNotifyRoutine 回调列表校验       │
│  │   ├── CmRegisterCallbackEx 回调列表校验                  │
│  │   └── 回调被移除/替换 → CRITICAL: KERNEL_TAMPER_CALLBACK │
│  ├── DKOM (Direct Kernel Object Manipulation) 检测:         │
│  │   ├── 定期通过不同 API 路径枚举进程列表:                 │
│  │   │   → NtQuerySystemInformation                         │
│  │   │   → 遍历 PsActiveProcessHead 链表                    │
│  │   │   → 通过调度器线程列表间接枚举                        │
│  │   ├── 多路径结果不一致 → 存在隐藏进程 → CRITICAL         │
│  │   └── 检查 Agent 自身 EPROCESS 是否仍在链表中            │
│  └── PatchGuard 状态检测:                                    │
│      ├── 检测 KdDebuggerEnabled / KdDebuggerNotPresent 篡改 │
│      └── 这些标志被修改通常意味着 PatchGuard 被禁用          │
│                                                             │
│  Linux:                                                     │
│  ├── 内核代码段 (.text) hash 校验:                           │
│  │   → 通过 /dev/kmem 或 kprobes 读取                       │
│  │   → 基准在 Agent 启动时建立                               │
│  ├── 系统调用表 (sys_call_table) 校验:                       │
│  │   → 通过 /proc/kallsyms 获取地址                          │
│  │   → 定期校验各 syscall 指针指向 .text 范围内              │
│  ├── 内核模块列表校验:                                       │
│  │   → /proc/modules vs lsmod 一致性                         │
│  │   → 检测隐藏的内核模块                                    │
│  └── eBPF 程序完整性 (已在 2.3 BPF Self-Protection 中覆盖)  │
│                                                             │
│  macOS:                                                     │
│  ├── kext 列表校验 (kextstat 等效)                           │
│  ├── System Extension 完整性                                 │
│  └── SIP (System Integrity Protection) 状态监控              │
│                                                             │
│  ⚠️ 保护边界声明:                                            │
│  上述检测在 Ring 0 攻击者面前不保证完整性 —                   │
│  攻击者可以同样篡改检测代码本身。                              │
│  设计目标是: 增加攻击者的隐蔽成本, 检测非完美 rootkit,        │
│  并为取证提供篡改痕迹线索。                                    │
└─────────────────────────────────────────────────────────────┘
```
### 2.7 Named Pipe / IPC 监控
```
目标: 捕获 Cobalt Strike、Metasploit、横向移动框架常见的 IPC 通道行为。

Windows:
├── ETW Provider: Microsoft-Windows-Kernel-File
│   └── 采集 Named Pipe 创建、连接、关闭事件
├── Minifilter 对 \Device\NamedPipe\ 路径监控
│   ├── IRP_MJ_CREATE_NAMED_PIPE → 管道创建
│   └── IRP_MJ_CREATE → 连接已有管道
├── 采集字段:
│   ├── pipe_name
│   ├── server_pid / client_pid
│   ├── pipe_mode
│   └── security_descriptor
└── 检测要点:
    ├── 已知恶意管道名模式
    ├── 随机名称管道 + 跨进程连接
    └── 非标准进程创建 SMB / IPC 管道

Linux:
├── eBPF 监控 mkfifo / mknod
├── 监控 AF_UNIX socket 的 bind / connect
└── /proc/net/unix 定期扫描做补偿
```
### 2.8 DLL 加载深度监控
```
目标: 覆盖 DLL sideloading、搜索顺序劫持、phantom DLL 和非标准动态库加载。

Windows:
├── 使用 PsSetLoadImageNotifyRoutineEx 获取镜像加载事件
├── 检测逻辑:
│   ├── 签名进程加载非标准路径 DLL
│   ├── 系统 DLL 同名但路径不在 %SystemRoot%
│   ├── 先尝试加载缺失 DLL, 随后同名 DLL 出现
│   └── 加载 DLL 的签名、发布者与预期不匹配
└── 归一化字段:
    ├── dll_path / dll_hash / dll_signer
    ├── loading_process
    ├── expected_path
    ├── is_sideload_suspect
    └── search_order_rank

Linux:
├── 监控 ld.so / dlopen 相关路径
├── 检测 LD_PRELOAD 劫持
└── 检测非标准路径 .so 加载
```
### 2.9 VSS / 文件系统快照保护
```
目标: 为勒索场景提供快照保护、删除阻断和文件系统回滚基础能力。

Windows:
├── 阻断:
│   ├── vssadmin delete shadows
│   ├── wmic shadowcopy delete
│   ├── PowerShell 调用 VSS 删除接口
│   └── 直接调用 DeleteSnapshots 类接口
├── 保护:
│   ├── 保护 VSS 服务进程不被终止/禁用
│   └── 保护 Agent 自建快照不被恶意删除
├── 快照计划:
│   ├── 每 4 小时创建系统卷快照
│   ├── 保留最近 3 个快照
│   └── 卷空间占用不超过 10%
└── 回滚基础:
    ├── 支持整卷、目录、文件级恢复
    └── 与注册表回滚和取证动作联动

Linux:
├── Btrfs: btrfs snapshot
├── LVM: lvm snapshot
└── ext4: 关键目录增量备份作为替代

macOS:
├── APFS Snapshot
└── Time Machine 本地快照保护
```
### 2.10 设备控制 (Device Control)
```
目标: 实现 USB、可移动存储、蓝牙、Thunderbolt 等设备的可编排访问控制。

策略类型:
├── ALLOW
├── BLOCK
├── READ_ONLY
├── AUDIT
└── ALLOW_APPROVED

匹配条件:
├── Device Class
├── Vendor ID + Product ID
├── Serial Number
├── Device Instance Path
└── 设备加密状态

Windows:
├── PnP 到达/离开通知 + SetupDi 监控
├── 与文件系统 / 卷挂载事件联动
└── 产生 DEVICE_CONNECT / DEVICE_BLOCK / DATA_COPY 事件

Linux:
├── udev rules 动态生成
├── USBGuard 集成
└── LSM mount hook 拦截挂载

macOS:
├── IOKit 监控设备连接
├── ESF AUTH_MOUNT 阻断挂载
└── 可与 MDM 配置联动
```
---
## 三、用户态核心引擎
### 3.1 Orchestrator（主事件循环）
```rust
// 伪代码 — 基于 tokio 异步运行时
async fn main_loop(config: AgentConfig) {
    // 1. 初始化
    let ring_buffer = MpscRingBuffer::mmap_open(&config.ring_buffer_path); // MPSC
    let (event_tx, event_rx) = bounded_channel::<NormalizedEvent>(65536);
    let (alert_tx_hi, alert_rx_hi) = bounded_channel::<Alert>(1024);     // 高优先级
    let (alert_tx_norm, alert_rx_norm) = bounded_channel::<Alert>(4096); // 普通
    let (response_tx, response_rx) = bounded_channel::<ResponseAction>(1024);
    let (telemetry_tx, telemetry_rx) = bounded_channel::<TelemetryBatch>(2048);
    // 2. 启动子系统
    let process_tree = Arc::new(ProcessTree::new());
    let feedback_whitelist = Arc::new(AdaptiveWhitelist::new()); // 反馈白名单
    let lineage_tracker = Arc::new(LineageTracker::new());       // 端到端追踪
    spawn(sensor_dispatch_loop(ring_buffer, event_tx, process_tree.clone(), lineage_tracker.clone()));
    spawn(detection_engine(event_rx, alert_tx_hi, alert_tx_norm, telemetry_tx.clone(),
                           config.detection, feedback_whitelist.clone()));
    spawn(response_executor(response_rx, config.response));
    spawn(comms_uplink_high(alert_rx_hi, config.comms));          // 独立高优先级流
    spawn(comms_uplink_normal(telemetry_rx, alert_rx_norm, config.comms));
    spawn(comms_downlink(response_tx, feedback_whitelist.clone(), config.comms));
    spawn(config_watcher(config.config_path));
    spawn(health_reporter(config.heartbeat_interval, lineage_tracker.clone()));
    spawn(process_tree_snapshot_sync(process_tree.clone(), config.snapshot_interval)); // 定期全量快照同步
    spawn(watchdog_heartbeat());
    signal::ctrl_c().await;
    graceful_shutdown().await;
}
```
### 3.2 Sensor Dispatch — 事件归一化
```
从 MPSC Ring Buffer 4 条 Lane 中轮询消费:
原始内核事件                    NormalizedEvent
┌─────────────┐                ┌────────────────────────────────────────┐
│ EventHeader │                │ event_id:    UUID (Agent 端生成)       │
│ + Flatbuf   │──解码+归一化──→│ lineage_id:  u128   │
│   Payload   │                │ timestamp:   u64 (纳秒)               │
└─────────────┘                │ event_type:  EventType enum            │
                               │ priority:    CRITICAL|HIGH|NORMAL|LOW  │
      ┌───────────┐            │ process:     ProcessContext { ... }    │
      │ Process   │──填充──→   │ payload:     EventPayload enum { ... } │
      │ Tree      │ 上下文     │ container:   Option<ContainerContext>  │
      │ Cache     │            │ enrichment:  EventEnrichment           │
      └───────────┘            │ syscall_origin: Option<SyscallOrigin>  │
                               │           │
      ┌───────────┐            └────────────────────────────────────────┘
      │ Adaptive  │──检查──→ 命中反馈白名单 → 跳过后续检测, 直接标记 BENIGN
      │ Whitelist │
      └───────────┘
```
### 3.3 进程树 (Process Tree Cache)
```
ProcessTree (LRU, 内存上限 30MB)
│
├── 数据结构: HashMap<(PID, StartTime), ProcessNode>
│   ProcessNode {
│     pid, ppid, start_time,
│     exe_path, exe_hash, cmdline, user, integrity,
│     signature, cwd, env_vars,
│     children, creation_flags, token_elevation,
│     container_id, namespace_ids,
│     last_activity: AtomicU64,
│     protection_level: Option<PPL_LEVEL>,  // PPL 信息
│   }
│
├── 定期全量快照同步:
│   ├── 用于修复差分上报中的 orphan 事件问题
│   ├── 频率: 每 5 分钟发送完整进程树快照到云端
│   ├── 快照格式: 所有活跃进程的 (pid, start_time, ppid, exe_hash, cmdline) 压缩包
│   ├── 云端收到快照后, 可修复所有 orphan 事件的进程上下文
│   ├── 典型大小: ~500 进程 × 200B = ~100KB (压缩后 ~20KB)
│   └── 快照也用于云端检测 Agent 端被隐藏进程的异常
│       (快照中有但遥测中从未出现的进程 → 可疑)
│
└── 其他操作:
    ├── on_process_create / on_process_exit
    ├── get_ancestor_chain
    └── is_descendant_of
```
### 3.4 文件哈希计算策略
```
文件哈希策略:
├── 默认算法: SHA-256；大文件流式处理优先使用 BLAKE3 做预筛，再按策略补充 SHA-256
├── 触发时机:
│   ├── 新可执行文件落盘
│   ├── Stage 2/Stage 3 请求深度分析
│   ├── 隔离前留证
│   └── 云端要求补算时
├── 缓存策略:
│   ├── key = (inode/file_id, size, mtime, content_hint)
│   ├── 命中缓存直接复用, 避免重复扫描
│   └── 可执行文件与脚本采用更长 TTL, 临时文件采用更短 TTL
├── 限流策略:
│   ├── 前台业务进程限速
│   ├── 大文件分片与后台队列处理
│   └── CPU/IO 压力过高时降级为元数据优先
└── SSD 安全删除注意事项:
    ├── 在 SSD 上 3-pass 覆写不保证物理擦除 (wear-leveling)
    ├── 文件隔离时优先使用文件系统级加密删除
    │   ├── NTFS: EFS → 删除密钥 → 删除文件
    │   ├── ext4: fscrypt 加密目录 → 删除密钥
    │   └── APFS: 删除文件描述符密钥
    ├── 如无文件系统级加密:
    │   ├── 覆写 + TRIM/UNMAP 命令
    │   └── 明确标注 SSD 上的安全删除不保证完全不可恢复
    └── 取证保留场景: 不做安全删除, 仅加密隔离
```
---
## 四、本地检测引擎（深入设计）
### 4.1 多阶段检测流水线
```
NormalizedEvent
     │
     ▼
┌────────────────────────────────────────────────────────────────┐
│  Stage 0: Fast Path Filter (< 100ns/event)                     │
│  ├── 事件类型路由表                                             │
│  ├── 全局采样率控制                                             │
│  ├── 静态白名单匹配                                            │
│  └── Adaptive Whitelist 检查 (反馈回路)                   │
│       → 命中云端确认的误报条目 → 跳过检测, 直接 BENIGN          │
└────────────────────┬───────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────────┐
│  Stage 1: IOC Matching (< 500ns/event)                         │
│  方案: 分层 Bloom + Cuckoo Filter                           │
│                                                                │
│  ├── Tiered Bloom Filter                                   │
│  │   ├── Tier 0: CRITICAL IOC Bloom (固定 FPR 0.001%)          │
│  │   │   → 仅包含: 活跃 APT 的 hash/IP/domain (~50K entries)   │
│  │   │   → 内存: ~1MB                                          │
│  │   ├── Tier 1: HIGH IOC Bloom (FPR 0.01%)                    │
│  │   │   → 已确认恶意指标 (~500K entries)                      │
│  │   │   → 内存: ~5MB                                          │
│  │   └── Tier 2: STANDARD IOC Cuckoo Filter (FPR 0.01%)       │
│  │       → 全量 IOC (~5M entries)                              │
│  │       → 使用 Cuckoo Filter 替代 Bloom:                      │
│  │         ├── 支持动态删除 (IOC 老化淘汰)                     │
│  │         ├── 空间效率: ~7 bits/entry vs Bloom ~10 bits/entry │
│  │         └── 内存: ~4.5MB (5M × 7 bits)                     │
│  │   → 总 IOC 内存: ~10MB, 支持 500 万 IOC 无 FPR 退化       │
│  ├── Bloom/Cuckoo 命中 → 精确查找确认 (HashMap)                │
│  └── 匹配结果附加到 enrichment                                  │
└────────────────────┬───────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────────┐
│  Stage 2: Rule Engine — Sigma + Custom DSL + Temporal (< 10μs) │
│                                                                │
│  Rule VM 指令集                                             │
│  ├── 基础: LOAD_FIELD, CMP_EQ, CMP_NE, CMP_GT, CMP_LT,       │
│  │         CMP_REGEX, CMP_CONTAINS, AND, OR, NOT, MATCH_RESULT │
│  ├── IOC: BLOOM_CHECK, CUCKOO_CHECK                            │
│  ├── 上下文: LOAD_PARENT, LOAD_ANCESTOR, LOAD_CHILDREN_COUNT  │
│  └── Temporal 算子                                          │
│      ├── TEMPORAL_WINDOW(duration_ms)                           │
│      │   → 设置时间窗口上下文                                   │
│      ├── TEMPORAL_SEQUENCE(event_matchers[], ordered=bool)      │
│      │   → 在窗口内匹配事件序列                                │
│      │   → ordered=true: 严格按序匹配                           │
│      │   → ordered=false: 无序, 仅要求全部出现                  │
│      ├── TEMPORAL_COUNT(event_matcher, min, max)                │
│      │   → 在窗口内计数事件出现次数                             │
│      └── TEMPORAL_NEAR(event_a, event_b, max_gap_ms)            │
│          → 两事件在 max_gap_ms 内先后出现                       │
│                                                                │
│      实现: 基于 per-rule 的 Temporal State Buffer               │
│      ├── 每条 temporal 规则维护一个小型事件环形缓冲 (128 条)    │
│      ├── 新事件到达时, 扫描缓冲内的历史事件做关联               │
│      ├── 缓冲按 TTL 自动过期清理                                │
│      └── 内存限制: 每条 temporal 规则 < 64KB                    │
│                                                                │
│  Sigma "near" 规则示例:                                         │
│  rule suspicious_lateral_movement {                             │
│    meta: mitre_ttp = "T1021"                                   │
│    condition:                                                   │
│      temporal_near(                                             │
│        event_a: { type == AUTH_LOGON AND logon_type == 3 },     │
│        event_b: { type == PROCESS_CREATE                        │
│                   AND process.name in ["psexec", "wmic", "sc"] },│
│        max_gap: 30s                                             │
│      )                                                          │
│  }                                                              │
│                                                                │
│  规则热更新: 支持签名校验、原子替换、失败回滚和灰度发布          │
└────────────────────┬───────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────────┐
│  Stage 2.5: AMSI Fast-Path Interlock                           │
│                                                                │
│  目标: 对脚本类事件建立快速联动阻断, 缩小检测与执行之间的窗口   │
│                                                                │
│  当事件来源为 AMSI (脚本内容):                                  │
│  ├── Stage 2 规则匹配完成后, 如果判定为 MALICIOUS/CRITICAL:    │
│  │   → 通过共享内存 flag 通知内核态 AMSI Provider              │
│  │   → AMSI Provider 在下一次 AmsiScanBuffer 调用时返回:       │
│  │     AMSI_RESULT_DETECTED                                     │
│  │   → 阻断后续脚本块的执行                                    │
│  ├── 延迟预算: < 50μs (从事件接收到 AMSI flag 设置)            │
│  │   → 对于多块脚本 (PowerShell 分块执行), 可在第一块完成检测  │
│  │     后阻断后续块                                             │
│  └── 局限: 单块脚本的首次执行无法阻断 (脚本已在 AMSI 回调返回前│
│       执行完毕), 但可以阻止该进程的后续脚本执行                 │
│                                                                │
│  Linux 等效: LSM bprm_check_security 在 execve 前阻断          │
│  macOS 等效: ESF AUTH_EXEC 在执行前阻断                        │
└────────────────────┬───────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────────┐
│  Stage 3: YARA 内存/文件扫描 (按需触发, < 50ms/scan)           │
│  触发条件:                                                      │
│  ├── 新可执行文件落盘                                           │
│  ├── Stage 2 规则要求深度扫描                                   │
│  ├── 可疑内存区域 (RWX 页, 无文件映射的代码段)                  │
│  ├── .NET Assembly.Load(byte[]) 检测                            │
│  │   → 监控 clr.dll 的 Assembly 加载事件                        │
│  │   → 无磁盘文件对应的 Assembly → 触发内存 YARA                │
│  ├── LOLBin 加载监控                                            │
│  │   → msbuild.exe / csc.exe / installutil.exe / regsvr32.exe   │
│  │     加载非标准 DLL/代码 → 触发 YARA                          │
│  ├── Office/PDF 宏/嵌入对象                                     │
│  │   → 检测 WINWORD.EXE/EXCEL.EXE 写入可执行文件               │
│  │   → 或 OLE/VBA stream 提取 → YARA 扫描                      │
│  └── 脚本 payload 解码后扫描                                    │
│      → Base64/XOR 解码后的内容 → YARA 扫描                      │
│      → 与 AMSI 捕获内容联动                                     │
│                                                                │
│  扫描执行策略:                                                  │
│  ├── 文件与内存扫描统一走异步任务队列                           │
│  ├── 同一对象在 TTL 窗口内复用最近一次扫描结果                  │
│  └── 超大样本优先切片并限制单次扫描预算                         │
└────────────────────┬───────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────────┐
│  Stage 4: 本地 ML 推理                                         │
│                                                                │
│  ┌── Model A: Static PE/ELF Classifier ──────────────────┐    │
│  │  模型形态: XGBoost + LightGBM + 小型 MLP 集成          │    │
│  │  对抗鲁棒性:                                           │    │
│  │  ├── Ensemble Voting: XGBoost + LightGBM + 小型 MLP     │    │
│  │  │   → 3 模型多数投票, 单一模型被对抗绕过时其他补位     │    │
│  │  ├── Feature Anomaly Detection (OOD):                   │    │
│  │  │   → 输入特征向量与训练集分布的 Mahalanobis 距离      │    │
│  │  │   → 距离 > 阈值 → 标记 "OOD_INPUT", 不信任 ML 输出  │    │
│  │  │   → 转为 YARA + 云端深度分析                          │    │
│  │  ├── 对抗训练:                                           │    │
│  │  │   → 训练集包含 Adversarial PE 样本                    │    │
│  │  │   → (FGSM / PGD 生成的对抗样本)                      │    │
│  │  └── Feature Robustness:                                │    │
│  │      → 使用难以篡改的结构特征 (如 PE rich header hash,   │    │
│  │        import directory 结构 anomaly) 而非易修改的表面特征│    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                │
│  ┌── Model B: 行为序列异常检测 ────────────────────────┐    │
│  │  模型形态: 1D-CNN + early-stage profile            │    │
│  │  冷启动策略:                                       │    │
│  │  ├── 冷启动窗口 (前 50 事件) 期间:                      │    │
│  │  │   ├── 启用 "Initial Phase Profile" 模式              │    │
│  │  │   ├── 使用预训练的 "进程首 N 秒行为" 专用模型        │    │
│  │  │   │   → 训练集: 已知恶意软件的初始行为序列            │    │
│  │  │   │   → 模型: 轻量 2-layer CNN, 只需 5 个事件即可推理│    │
│  │  │   ├── 同时提升 Stage 2 规则引擎的敏感度:             │    │
│  │  │   │   → 对新进程的前 10s 应用额外的 "early-stage" 规则│
│  │  │   │     集 (进程初始行为 pattern, 如快速枚举+提权+外连│
│  │  │   │     的组合)                                       │    │
│  │  │   └── 50 事件窗口填满后, 切换回标准 Model B           │    │
│  │  └── 模型大小: 冷启动模型 ~1MB, 标准模型 ~3MB           │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                │
│  ┌── Model C: 脚本风险评估 ───────────────────────────┐    │
│  │  模型形态: Distilled Transformer                   │    │
│  │  目标: 稳健识别脚本混淆、语义意图和高风险动作       │    │
│  │  ├── 架构: 4-layer Transformer, hidden_dim=128         │    │
│  │  │   → 从 7B LLM teacher model 蒸馏而来                │    │
│  │  ├── 大小: ~8MB (.onnx)                                │    │
│  │  ├── 推理: ONNX Runtime (CPU), < 5ms                   │    │
│  │  ├── 能力:                                              │    │
│  │  │   ├── 处理 Base64/XOR/字符串拼接等常见混淆          │    │
│  │  │   ├── 识别 Invoke-Obfuscation 多层编码              │    │
│  │  │   ├── 提取语义意图 (下载执行/凭据窃取/持久化等)     │    │
│  │  │   └── 输出: risk_score + intent_tags[]              │    │
│  │  └── 与 AMSI Fast-Path 联动:                           │    │
│  │      → risk_score > 0.9 → AMSI 阻断后续脚本块         │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                │
│  模型发布与性能守护:                                          │
│  ├── shadow mode / A-B bucket / canary                        │
│  ├── 推理时延、内存占用、误报率达阈值自动回退                 │
│  └── 模型与规则版本均支持独立灰度                             │
└────────────────────┬───────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────────┐
│  Stage 5: 状态关联 — Sharded Stateful Correlation            │
│                                                                │
│  目标: 在保持高吞吐的同时支持复杂多阶段攻击链关联               │
│                                                                │
│  分片设计:                                                      │
│  ├── 状态机实例按 process_group_id 分片                         │
│  │   → process_group_id = 进程树的根进程 (session leader) PID  │
│  │   → 同一进程树下的所有事件路由到同一分片                     │
│  ├── 分片数 = detection-pool 线程数                             │
│  │   → 每个线程拥有独立的 ShardedStateStore, 无跨线程锁竞争   │
│  ├── 跨进程树的关联 (如横向移动):                               │
│  │   → 通过异步 cross-shard query channel                      │
│  │   → 仅在需要时查询, 不阻塞主路径                            │
│  └── 吞吐: 每分片 > 500K event/s → N 线程 × 500K = 总吞吐     │
│                                                                │
│  关联分工:                                                      │
│  ├── 简单时间窗口规则在 Stage 2 的 Temporal VM 中执行          │
│  └── 复杂多阶段攻击链由 Stage 5 的状态机关联负责                │
└────────────────────┬───────────────────────────────────────────┘
                     │
                     ▼
           Decision Router
           ├── BENIGN    → 遥测 (仅 comms-tx-normal)
           ├── SUSPICIOUS → 遥测 + 低优先级告警 (comms-tx-normal)
           ├── MALICIOUS  → 遥测 + 高优先级告警 (comms-tx-high) + 响应
           └── CRITICAL   → 遥测 + 告警 (comms-tx-high) + 即时响应
```
### 4.2 检测引擎性能预算
| 阶段 | 延迟预算 | 吞吐量 | 备注 |
|------|---------|--------|------|
| Stage 0: Fast Path | < 100ns | 10M event/s | 含 Adaptive Whitelist 检查 |
| Stage 1: IOC Tiered Bloom/Cuckoo | < 500ns | 5M event/s | 支持 500 万 IOC |
| Stage 2: Rule VM + Temporal | < 15μs | 400K event/s | 含 temporal 窗口关联 |
| Stage 2.5: AMSI Fast-Path | < 50μs | 100K script/s | 仅 AMSI 来源事件 |
| Stage 3: YARA | < 50ms | 100 scan/s | 按需深度扫描 |
| Stage 4: ML Ensemble | < 8ms | 800 inference/s | 3 模型投票 + OOD 检测 |
| Stage 5: Sharded Correlation | < 2μs | 2M event/s (total) | 分片后吞吐线性扩展 |
| **端到端 (典型)** | **< 20μs** | **> 400K event/s** | **P99 < 150μs** |
### 4.3 勒索软件专项检测
```
目标: 在大规模加密真正发生前完成早期发现、挂起、快照保护和后续恢复。

Layer 1: 金丝雀文件
├── 在关键目录部署隐藏诱饵文件
├── 任何修改 / 重命名 / 删除即触发 CRITICAL
└── 触发后立即 Suspend 可疑进程

Layer 2: 文件加密行为检测
├── entropy 跃升检测:
│   ├── 写入后 entropy > 7.9
│   └── 写入前 entropy < 7.0
├── 短时间内大量文件 Read → Encrypt → Write
├── 大量扩展名重写 / 勒索信创建
└── 与 VSS 快照保护、回滚联动

Layer 3: MBR / VBR / Boot Sector 保护
├── 监控对 PhysicalDisk / raw block device 的直接写入
├── 非授权进程写入启动扇区 → 立即阻断
└── 周期校验引导区 hash

Layer 4: 勒索行为状态机
├── 文件枚举
├── 删除快照尝试
├── 批量加密
└── 勒索信落盘
```
### 4.4 攻击面削减规则 (ASR)
```
目标: 在恶意行为发生前通过预防性规则阻断高风险操作。

规则域:
├── Office 宏防护
│   ├── 阻止 Office 创建子进程
│   ├── 阻止 Office 写入可执行内容
│   └── 阻止 Office 注入其他进程
├── 脚本执行控制
│   ├── 阻止混淆脚本执行
│   ├── 阻止脚本链路下载并执行载荷
│   └── 阻止 WMI 事件订阅持久化
├── 凭据保护
│   ├── 阻止非授权进程访问 LSASS
│   └── 阻止凭据窃取相关内存读取
├── USB 执行控制
│   └── 阻止从 USB 运行未签名或不受信任的进程
└── 网络保护
    ├── 阻止连接已知恶意 IOC
    └── 阻止低信誉域名 / IP

策略模式:
├── Block
├── Audit
└── Warn
```
### 4.5 身份威胁检测 (Identity Threat Detection)
```
目标: 在域环境端点上识别身份凭据相关攻击活动。

检测覆盖:
├── Kerberoasting
│   ├── TGS-REQ 使用 RC4 etype 23
│   └── 单用户短时间内大量 TGS 请求
├── Golden Ticket
│   ├── TGT 有效期异常
│   ├── SID 历史异常
│   └── 不经 KDC 直接使用 TGT
├── DCSync
│   └── 非 DC 主机发起 DrsGetNCChanges RPC
├── Pass-the-Hash / Pass-the-Ticket
│   ├── 登录类型 9 异常频率
│   └── 凭据在非预期主机使用
├── NTLM Relay
└── AS-REP Roasting
```
### 4.6 欺骗技术 (Deception)
```
目标: 通过蜜凭据、蜜文件、蜜共享和蜜 DNS 提前暴露攻击者行为。

能力:
├── 蜜凭据
│   ├── 伪造高价值凭据条目
│   └── 一旦被使用立即告警
├── 蜜文件
│   ├── 伪造敏感文件名
│   └── 读取即告警, 修改则升级为更高优先级
├── 蜜共享
│   ├── 伪造 SMB 共享
│   └── 用于检测网络枚举和横向移动
└── 蜜 DNS
    ├── 添加虚假内部域名解析
    └── 被解析或访问即告警

治理要求:
├── 诱饵内容全网唯一
├── 周期轮换
└── 对正常用户不可见或不影响正常路径
```
### 4.7 脚本多层解混淆流水线
```
目标: 在脚本送入规则与模型前尽可能恢复真实语义。

Layer 1: 编码解码
├── Base64 / UTF-16 Base64
├── Hex / URL / Unicode 转义
└── 常见字符表变体

Layer 2: 字符串操作还原
├── 拼接
├── Replace
├── -join / [char][]
└── 环境变量替换

Layer 3: 执行层解包
├── Invoke-Expression 参数提取
├── 调用操作符参数提取
├── ScriptBlock.Create 参数提取
├── -EncodedCommand 解码
└── 最多递归 10 层

Layer 4: 语义分析
├── 解混淆文本进入 Stage 4 Model C
└── 输出 risk_score + intent_tags

性能目标:
├── 典型脚本 < 2ms
└── 深度混淆脚本 < 10ms
```
---
## 五、响应执行引擎
### 5.1 Response Executor 架构
```
Response Executor
├── 输入: Decision Router 生成的 response plan
├── 执行阶段:
│   ├── pre-check: 目标存在性、权限、幂等键检查
│   ├── containment: suspend / isolate / block
│   ├── evidence: 连接、句柄、内存、注册表、文件留证
│   ├── commit: terminate / quarantine / rollback / remote action
│   └── audit: 结果记录、回执签名、上报 cloud
├── 动作集合:
│   ├── PPL-Aware Process Termination
│   ├── Two-Phase Kill: Suspend → Kill/Release
│   ├── File Quarantine / Filesystem Rollback
│   ├── Registry Change Journal Rollback
│   ├── Network Isolation
│   ├── Live Forensics / Artifact Upload
│   ├── Endpoint Firewall Control
│   └── Remote Shell with hardened policy
└── 设计要求:
    ├── 每个动作具备幂等语义和超时控制
    ├── 高风险动作要求强审计
    └── 能留证的动作优先留证再破坏
```
### 5.2 Two-Phase Process Termination
```
解决: Kill 前恶意动作已完成的竞态条件
旧方案: detect → kill  (时间窗口内恶意动作已执行)
新方案: detect → suspend → assess → kill/release
┌────────────────────────────────────────────────────────────────┐
│  Phase 1: Immediate Suspend (< 100ms from detection)           │
│  ├── Windows: NtSuspendProcess (挂起所有线程)                   │
│  ├── Linux: kill(pid, SIGSTOP) + freeze cgroup (容器场景)       │
│  ├── macOS: task_suspend(task_port)                             │
│  └── 效果: 进程立即停止执行, 但不释放资源                       │
│            (文件句柄、网络连接、内存映射全部保持)               │
│                                                                │
│  Phase 2: Assess & Respond (在进程挂起状态下)                   │
│  ├── 自动路径 (高置信检测, confidence > 0.9):                   │
│  │   ├── 检查网络连接: 是否有活跃外连 → 记录 C2 地址           │
│  │   ├── 检查打开文件: 是否正在加密文件 → 记录影响范围          │
│  │   ├── 内存快照 (可选): 转储可疑内存区域供取证                │
│  │   └── 终止进程: TerminateProcess / kill -9                  │
│  │       + 终止所有子进程 (递归遍历进程树)                      │
│  │                                                              │
│  ├── 人工确认路径 (中置信检测, confidence 0.5-0.9):             │
│  │   ├── 进程保持挂起状态, 等待分析师确认 (超时 5min)          │
│  │   ├── 超时未确认 → 根据策略: 自动终止 / 自动释放            │
│  │   └── 分析师可远程检查进程状态后决定                         │
│  │                                                              │
│  └── PPL-Aware 路径 :                            │
│      ├── 检测目标进程的保护级别:                                 │
│      │   → NtQueryInformationProcess(ProcessProtectionInformation)│
│      ├── If 普通进程 → 正常 Suspend+Kill                       │
│      ├── If PPL (Protected Process Light):                      │
│      │   ├── 用户态 TerminateProcess 会返回 ACCESS_DENIED      │
│      │   ├── 内核驱动级终止:                                    │
│      │   │   → 通过 aegis-sensor-kmod 调用 ZwTerminateProcess            │
│      │   │     (内核驱动运行在 Ring 0, 可以终止 PPL 进程)       │
│      │   ├── 或: Token 降级                                     │
│      │   │   → 通过内核驱动修改进程 Token 移除保护标志          │
│      │   │   → 然后用户态正常终止                                │
│      │   └── 审计: PPL 进程终止操作强制记录详细审计日志         │
│      └── If PP (Protected Process, 更高保护):                   │
│          ├── 仅少数系统关键进程使用 PP                           │
│          ├── 终止 PP 进程风险极高 (可能导致系统不稳定)          │
│          ├── 策略: 不终止, 仅 CRITICAL 告警 + 建议人工处理     │
│          └── 可选: 网络隔离阻断其外连 (不需要终止进程)          │
└────────────────────────────────────────────────────────────────┘
```
### 5.3 预防性阻断
```
解决: 响应总是滞后于恶意动作的根本问题
在内核态 pre-callback 中实现实时阻断, 消除用户态检测延迟:
┌────────────────────────────────────────────────────────────────┐
│  Preemptive Blocking Architecture                              │
│                                                                │
│  内核态 Pre-Callback:                                          │
│  ├── Minifilter IRP_MJ_CREATE (文件打开前):                    │
│  │   → 查询 Block Decision Map (BPF Map / 共享内存 bitmap)     │
│  │   → 如果 (process_hash, action_type) 在 block list 中       │
│  │   → 返回 STATUS_ACCESS_DENIED, 阻止文件操作                 │
│  │                                                              │
│  ├── WFP ALE_AUTH_CONNECT (网络连接前):                         │
│  │   → 查询 network block list                                  │
│  │   → 如果目标 IP/port 在 block list 中                       │
│  │   → FWP_ACTION_BLOCK, 阻止连接                              │
│  │                                                              │
│  ├── Linux LSM bprm_check_security (execve 前):                │
│  │   → 查询 exec block list (BPF Map)                          │
│  │   → 如果 exe_hash 在 block list 中                          │
│  │   → 返回 -EPERM, 阻止执行                                   │
│  │                                                              │
│  └── macOS ESF AUTH_EXEC / AUTH_OPEN:                           │
│      → 查询 block list → es_respond_auth_result(DENY)          │
│                                                                │
│  用户态检测引擎 → 内核态 Block List 同步:                       │
│  ├── 检测引擎判定 MALICIOUS 后:                                 │
│  │   → 将 (hash/pid/path) 写入 Block Decision Map              │
│  │   → 内核态下一次 pre-callback 立即生效                       │
│  │   → 延迟: 用户态写入 → 内核态生效 < 1μs (共享内存)          │
│  ├── Block List 条目类型:                                       │
│  │   ├── hash-block:   阻止特定 hash 的文件执行                │
│  │   ├── pid-block:    阻止特定 PID 的所有后续操作             │
│  │   ├── path-block:   阻止对特定路径的写入                    │
│  │   └── net-block:    阻止到特定 IP/域名的连接                │
│  ├── TTL: 每条 block 条目有 TTL (默认 300s)                    │
│  │   → 防止永久阻断导致系统故障                                 │
│  │   → 永久阻断需云端显式指令                                   │
│  └── 安全限制:                                                  │
│      ├── Block List 上限: 10,000 条目                           │
│      ├── 不可阻断: 系统关键进程白名单 (csrss, wininit, init, launchd) │
│      └── 误阻断恢复: 云端可远程清空 Block List                 │
└────────────────────────────────────────────────────────────────┘
```
### 5.4 网络隔离增强
```
解决: 隔离模式下的 DNS chicken-and-egg 问题
┌────────────────────────────────────────────────────────────────┐
│  Network Isolation                                         │
│                                                                │
│  DNS 解决方案:                                                  │
│  ├── Agent 安装时 / 每次启动时 / 每次云端通信时:                │
│  │   ├── 解析所有 EDR Cloud 域名 → 缓存 IP 列表               │
│  │   ├── 存储在: /data/edr_cloud_ips.cache                    │
│  │   └── 格式: { "cloud.edr.com": ["1.2.3.4", "5.6.7.8"],    │
│  │              "update.edr.com": [...],                       │
│  │              "telemetry.edr.com": [...] }                   │
│  │                                                              │
│  ├── 隔离生效时:                                                │
│  │   ├── 防火墙规则使用 IP 白名单 (不依赖 DNS)                 │
│  │   ├── DNS 请求仅放行到 EDR 指定 DNS 服务器 (IP 硬编码)     │
│  │   └── 如果 IP 缓存过期 (>24h): 允许 DNS 查询 EDR 域名     │
│  │       → 精确匹配域名后缀, 阻断其他所有 DNS 查询            │
│  │                                                              │
│  ├── 备选: Agent 内嵌 EDR Cloud IP 列表                        │
│  │   ├── 每次 Agent 升级时更新                                  │
│  │   ├── 作为最终 fallback (IP 列表可能过期但至少有一个可用)    │
│  │   └── 内嵌列表包含多地域 Anycast IP                         │
│  └── 隔离持久化:                                            │
│      ├── 规则在 Agent 重启后仍可恢复                         │
│      ├── 仅分析师释放、策略回滚或 TTL 到期后解除              │
│      └── 每次状态切换写入审计日志与本地 WAL                   │
└────────────────────────────────────────────────────────────────┘
```
### 5.5 文件隔离 (Quarantine)
```
目标: 在保留证据的前提下将恶意文件从原始路径安全移出, 并确保可审计、可还原。

隔离流程:
1. Suspend 正在访问该文件的可疑进程
2. 采集元数据:
   ├── 原始路径
   ├── SHA256 / SHA1 / MD5
   ├── 签名信息 / 发布者 / Magic
   └── 来源标签 (下载源 / Zone Identifier / 上下文事件)
3. 使用 LZ4 压缩 + AES-256-GCM 加密
   └── 写入 /quarantine/{sha256}.vault
4. 原文件执行安全删除:
   ├── 优先使用文件系统级加密删除
   └── 不支持时执行 SSD 感知的删除与 TRIM
5. 根据策略释放非恶意访问进程或终止恶意进程
6. 生成完整审计记录并上报云端

隔离区治理:
├── 容量上限: 2GB
├── 默认保留: 30 天
├── 支持云端指令还原
└── 还原前必须校验签名、策略和目标路径冲突
```
### 5.6 注册表回滚增强
```
解决: 变更日志从哪里来
基于 2.2 中新增的 Registry Change Journal:
回滚操作:
┌─────────────────────────────────────────────────────────┐
│  RegistryRollback(target: RollbackTarget)                │
│                                                         │
│  RollbackTarget 类型:                                    │
│  ├── ByTimestamp { before: u64 }                         │
│  │   → 回退指定时间之后的所有注册表变更                   │
│  │   → SQL: SELECT * FROM journal WHERE ts > before      │
│  │     ORDER BY ts DESC                                  │
│  │   → 按逆序逐条还原 old_value                          │
│  │                                                       │
│  ├── ByProcess { pid: u32, start_time: u64 }             │
│  │   → 回退指定进程的所有注册表变更                       │
│  │   → 精确到 (pid, start_time) 避免 PID 重用            │
│  │                                                       │
│  ├── ByKey { key_path: String }                          │
│  │   → 回退指定注册表键的所有最近变更                     │
│  │                                                       │
│  └── ByIncident { incident_id: String }                  │
│      → 云端关联事件 ID, 回退所有相关变更                  │
│                                                         │
│  安全限制:                                               │
│  ├── 系统关键键 (BCD, Boot Configuration) 回滚需审批     │
│  ├── 回滚前自动备份当前值 (防止回滚错误)                 │
│  └── 回滚操作本身记录到 Change Journal (可审计)          │
└─────────────────────────────────────────────────────────┘
```
### 5.7 Remote Shell Security Hardening
```
解决: Remote Shell 安全边界不足
┌──────────────────────────────────────────────────────────┐
│  Remote Shell 安全加固                                    │
│                                                          │
│  访问控制:                                                │
│  ├── 双人审批: 发起人 + 审批人 (不同角色)                │
│  ├── 会话时长限制: 默认 30min, 最长 2h, 可续期 (需再次审批)│
│  ├── 并发限制: 同一端点最多 1 个活跃 Shell 会话          │
│  └── 时间窗口: 仅工作时间允许, 或需额外审批              │
│                                                          │
│  命令控制:                                                │
│  ├── 命令黑名单 (不可执行):                               │
│  │   ├── 格式化命令: format, fdisk, mkfs                 │
│  │   ├── 擦除命令: dd if=/dev/zero, cipher /w            │
│  │   ├── 权限变更: chmod 777, icacls /grant Everyone     │
│  │   ├── Agent 篡改: 停止/删除 Agent 服务               │
│  │   └── 横向移动工具: psexec, wmiexec, smbexec          │
│  ├── 命令白名单模式 (可选, 高安全环境):                   │
│  │   → 仅允许预定义的取证/诊断命令集                     │
│  └── 所有命令在执行前校验, 命中黑名单 → 拒绝 + 审计日志  │
│                                                          │
│  资源限制:                                                │
│  ├── CPU: 单 Shell 会话 CPU 限制 5%                      │
│  ├── Memory: 会话进程内存限制 256MB                      │
│  ├── Network: 会话进程仅允许回连 EDR Cloud (无外连)      │
│  ├── Disk: 写入限制 100MB (取证数据收集)                 │
│  └── 实现: cgroup (Linux) / Job Object (Windows)         │
│                                                          │
│  审计:                                                    │
│  ├── 全程录屏 (终端输出的 asciicast 格式录制)            │
│  ├── 每条命令 + 输出 + 时间戳记录                        │
│  ├── 审计日志不可由 Shell 会话内修改                     │
│  └── 会话结束后审计包自动上传到云端                       │
└──────────────────────────────────────────────────────────┘
```
### 5.8 文件系统回滚
```
目标: 基于快照与变更日志恢复勒索或破坏性操作造成的文件系统影响。

FilesystemRollback(target: RollbackSpec) {
  scope:
    ├── FullVolume
    ├── Directory
    ├── FileList
    └── ByProcess

  流程:
    1. 验证快照可用性
    2. 枚举需恢复文件
    3. 比对快照版本与当前版本 hash
    4. 仅恢复被修改/删除对象
    5. 联动注册表回滚
    6. 记录完整审计日志
    7. 上报恢复结果
}

限制:
├── 默认恢复到最近可用快照
├── 回滚可能覆盖快照之后的合法修改, 默认需人工确认
└── 仅恢复文件系统与注册表, 不恢复进程运行态
```
### 5.9 实时取证与证据链保障
```
目标: 在响应窗口内快速收集易失与持久化证据, 并保证证据链可验证。

实时取证范围:
├── Volatile Data:
│   ├── 进程列表 / 线程 / 模块
│   ├── 网络连接 / 路由表 / ARP / DNS 缓存
│   ├── 登录会话 / Token / 驱动列表
│   ├── 文件句柄
│   └── 按策略采集的内存 dump
├── Persistent Artifacts:
│   ├── Windows: $MFT / $UsnJrnl / Prefetch / Event Log / Registry Hives
│   ├── Windows: Amcache / SRUM / Scheduled Tasks / WMI Repo / 浏览器历史 / LNK
│   ├── Linux: auth.log / syslog / audit.log / crontab / systemd / shell history
│   └── macOS: Unified Log / Launch Agents / Quarantine DB / FSEvents / KnowledgeC.db
└── 打包与传输:
    ├── tar.gz 分块
    ├── AES-256-GCM 一次性会话密钥加密
    ├── 支持断点续传
    └── 资源约束: CPU < 10%, Disk < 50MB/s, Upload < 10MB/s, 超时 30min

证据链保障:
├── 每个 artifact 包含:
│   ├── artifact_id
│   ├── collected_at / collected_by
│   ├── encryption metadata
│   ├── hash_chain
│   └── Agent 签名
├── hash_chain 记录 collected / encrypted / uploaded / reviewed 等步骤
├── 每一步操作后重新计算 hash
├── chain 本身带签名且不可篡改
├── 时间戳使用可信时间源 / NTP 校验
└── 云端收到后独立复算校验
```
### 5.10 端点防火墙管控
```
目标: 在“隔离/解除”之外提供持久化、可编排的端点网络面控制。

策略类型:
├── 应用级规则
│   ├── 允许 / 阻止特定进程联网
│   └── 限制特定进程仅访问指定协议或目标
├── 端口 / 协议规则
│   ├── 入站 RDP
│   ├── 出站 SMB
│   └── 自定义 allow / deny 列表
├── 地理围栏
└── 响应触发的临时规则

平台实现:
├── Windows: WFP 规则持久化
├── Linux: nftables / iptables
└── macOS: pf
```
### 5.11 响应能力矩阵
| 动作 | 延迟目标 | 审批要求 | 可回滚 |
|------|---------|---------|--------|
| 进程 Suspend → Kill | ≤ 3s | 自动 / 手动 | 否 |
| 文件隔离 | ≤ 5s | 自动 / 手动 | 是 |
| 网络隔离 | ≤ 3s | 需审批 | 是 |
| 注册表回滚 | ≤ 5s | 手动 | 是 |
| 文件系统回滚 | ≤ 60s | 需审批 | 部分 |
| 用户会话锁定 | ≤ 10s | 需审批 | 是 |
| 远程取证 | 按需 | 需审批 | N/A |
| Remote Shell | 按需 | 双人审批 | N/A |
| 自动 Playbook | ≤ 10s | 预审批 | 部分 |
---
## 六、通信子系统
### 6.1 双流 gRPC + 通信隐蔽性
```
解决: 高优先级事件被普通事件批量延迟阻塞
解决: gRPC 通信 fingerprinting 和隐蔽性
┌────────────────────────────────────────────────────────────────┐
│  通信架构                                                   │
│                                                                │
│  双流设计:                                                      │
│  ├── Stream A: High-Priority (零延迟)                          │
│  │   ├── CRITICAL/HIGH 告警, 响应结果, 篡改检测事件            │
│  │   ├── 无批量聚合, 即时发送                                  │
│  │   └── 独立 gRPC stream + 独立线程                           │
│  ├── Stream B: Normal Telemetry (批量)                          │
│  │   ├── 普通遥测事件, 低优先级告警                            │
│  │   ├── 批量: 100-500 events, 最大等待 1s                    │
│  │   └── LZ4 压缩                                              │
│  └── Stream C: Bulk Upload (按需)                               │
│      ├── 取证包, 内存 dump, 大文件                             │
│      └── 分块上传, 断点续传, 带宽限制                          │
│                                                                │
│  通信隐蔽性                                                  │
│  ├── 主通道: gRPC over TLS 1.3 (标准)                          │
│  ├── Fallback 1: HTTPS WebSocket                                │
│  │   ├── 当 gRPC (HTTP/2) 被 DPI 设备阻断时自动切换           │
│  │   ├── 伪装为普通 WebSocket 流量 (wss://)                   │
│  │   └── Protobuf 序列化封装在 WebSocket frames 中             │
│  ├── Fallback 2: HTTPS Long-Polling                             │
│  │   ├── 最保守的 fallback, 几乎不会被阻断                    │
│  │   ├── Agent 定期 POST 事件 + GET 命令                       │
│  │   └── 延迟增加到 5-30s, 但保证连通性                        │
│  ├── Fallback 3: Domain Fronting (可选, 需配置)                 │
│  │   ├── 通过合法 CDN 域名 (如 cloudfront) 中转                │
│  │   ├── TLS SNI = 合法域名, Host Header = EDR 域名            │
│  │   └── 仅在极端网络管控环境中启用                             │
│  ├── 自动切换逻辑:                                              │
│  │   ├── 尝试 gRPC → 失败 3 次 → WebSocket → 失败 3 次        │
│  │   │   → Long-Polling → 失败 → Domain Fronting (如配置)     │
│  │   ├── 恢复检测: 后台定期 (每 5min) 尝试升级到更优通道       │
│  │   └── 通道状态包含在心跳中上报                               │
│  └── TLS Fingerprint 多样化:                                    │
│      ├── 使用 utls 库模拟常见浏览器的 TLS ClientHello          │
│      ├── 随机化 JA3 指纹                                       │
│      └── ALPN 随机选择 h2 / http/1.1                           │
└────────────────────────────────────────────────────────────────┘
```
### 6.2 WAL (Write-Ahead Log) 与密钥保护
```
解决: 失联缓冲、断点重放与本地敏感数据落盘保护
┌────────────────────────────────────────────────────────────────┐
│  WAL 结构与保护策略                                              │
│                                                                │
│  存储结构:                                                      │
│  ├── /data/wal/segment-{N}.wal                                  │
│  ├── 每段默认 16MB                                              │
│  ├── 格式: Segment Header + Record[]                            │
│  │   → record_len + type + crc32 + payload                     │
│  ├── 容量: 默认 500MB, 满时 FIFO 淘汰并记录统计                 │
│  └── 重连后按 sequence_id 顺序重放, 服务端幂等去重              │
│                                                                │
│  密钥保护分级策略:                                               │
│  ├── Tier 1: TPM/Secure Enclave 绑定 (推荐)                    │
│  │                                                              │
│  ├── Windows: TPM 2.0 密钥存储                                  │
│  │   ├── Agent 主密钥生成在 TPM 内, 永不导出                   │
│  │   ├── 加密操作: 数据发送到 TPM → TPM 内部加解密 → 返回结果  │
│  │   ├── 即使 SYSTEM 权限也无法读取 TPM 内部密钥               │
│  │   └── Fallback: 无 TPM → Tier 2                             │
│  ├── Linux: TPM 2.0 (tpm2-tss)                                 │
│  │   └── 同 Windows, 通过 PKCS#11 或 tpm2-tools               │
│  ├── macOS: Secure Enclave                                      │
│  │   ├── kSecAttrTokenIDSecureEnclave                           │
│  │   └── 密钥绑定到设备硬件, 不可提取                          │
│                                                                │
│  Tier 2: OS Credential Store + 增强保护 (无 TPM 时)            │
│  ├── Windows: DPAPI + additional entropy (Agent binary hash)   │
│  ├── Linux: 密钥文件 + LUKS 加密分区 + mlock                  │
│  ├── macOS: Keychain + 应用 ACL                                │
│  └── 增强: 密钥文件 ACL 限制为仅 Agent 进程用户可读            │
│                                                                │
│  WAL 数据分级加密:                                              │
│  ├── 高敏感字段 (用户名, IP, 凭据相关):                        │
│  │   → 使用 TPM-bound 密钥加密                                 │
│  │   → 即使攻击者读取 WAL 文件, 无法解密这些字段               │
│  ├── 普通字段 (进程名, 文件路径):                               │
│  │   → 使用 OS 密钥存储保护的密钥加密                          │
│  └── 元数据 (序列号, 时间戳):                                   │
│      → 明文存储 (用于 WAL 管理, 不含敏感信息)                  │
│                                                                │
│  运行要求:                                                      │
│  ├── 支持速率限制与后台重放                                     │
│  ├── 损坏 segment 通过 crc32 检测并隔离                         │
│  └── 与 Bulk Upload 共用断点续传与带宽控制机制                 │
└────────────────────────────────────────────────────────────────┘
```
### 6.3 差分上报增强
```
解决: 进程创建事件丢失导致 orphan
三层保障:
├── 1. 进程创建事件在 CRITICAL Lane (不可丢弃)
│      → Ring Buffer 优先级保留策略已保证不丢失
│
├── 2. 定期全量进程树快照 (见 3.3)
│      → 每 5 分钟发送完整快照, 云端可修复 orphan
│
└── 3. 云端 Orphan 检测 + 请求重传:
       → 云端检测到引用了未知 PID 的事件
       → 通过 ServerCommand 请求 Agent 补发该 PID 的进程信息
       → Agent 从 ProcessTree Cache 中查找并回传
       → 如果进程已退出且缓存已过期 → 返回 NOT_FOUND
         → 云端标记该进程上下文为 "incomplete"
```
### 6.4 离线完整检测模式
```
触发: Agent 与云端控制面失联超过 30s 后自动进入自治模式

离线期间保留的能力:
├── Sensor 侧:
│   ├── 内核态与用户态传感器持续采集
│   └── Process / File / Registry / Network / Script 事件不降级
├── 检测侧:
│   ├── IOC Filter 使用本地缓存
│   ├── Sigma / YARA 使用本地已编译规则
│   ├── ML 推理在本地 ONNX Runtime 执行
│   ├── Temporal 关联与状态机继续运行
│   └── Storyline Engine 持续构建攻击故事线
├── 响应侧:
│   ├── Suspend / Kill / Quarantine 等本地动作按策略继续执行
│   ├── 网络隔离与端点防火墙临时规则可继续生效
│   └── ASR / Device Control / Deception 保留本地执行能力
├── 数据侧:
│   ├── 遥测、告警、响应审计全部写入 WAL
│   ├── WAL 默认容量 500MB, 覆盖约 24-48 小时数据
│   └── 使用 sequence_id 保证重连后按序重放
└── 离线期间不可用:
    ├── 跨端点 / 跨租户云端关联分析
    ├── 实时威胁情报更新
    ├── 远程取证与 Remote Shell
    └── 依赖云端调度的诱饵轮换与大规模策略编排

恢复流程:
├── 重新建立 mTLS 会话后先发送离线摘要
├── 回放 WAL 中的遥测、告警与响应审计
├── 拉取离线期间缺失的规则 / 模型 / IOC / 策略
└── 对离线期间产生的 Storyline 进行云端补关联
```
### 6.5 带宽自适应 QoS
```
网络环境识别:
├── Windows: NetworkListManager / 计量连接状态
├── Linux: NetworkManager metered 属性 + RTT 采样
├── macOS: Network framework + 接口吞吐估算
└── 分类:
    ├── HIGH:      > 10 Mbps
    ├── MEDIUM:    1-10 Mbps
    ├── LOW:       < 1 Mbps
    ├── SATELLITE: RTT > 500 ms
    └── METERED:   计量或按流量计费链路

QoS 策略:
├── HIGH:
│   └── 正常批量上报, 全量遥测
├── MEDIUM:
│   ├── 批量间隔扩展到 3s
│   └── 默认启用 ZSTD 压缩
├── LOW:
│   ├── 批量间隔扩展到 10s
│   ├── INFO 级遥测采样 1/100
│   └── 大文件与低优先级快照延迟发送
├── SATELLITE:
│   ├── 仅优先发送告警、CRITICAL 遥测与控制面数据
│   └── 普通流量等待空闲窗口回放
└── METERED:
    ├── 沿用 LOW 策略
    └── 默认暂停大文件上传与非必要取证包传输

前后台感知:
├── 检测到用户前台活跃时, 主动降低 Agent 网络优先级
└── 设备空闲时执行 WAL 回放、快照补传与资产同步
```
### 6.6 gRPC 服务定义

Agent↔Gateway 的 wire-level 单一事实源见 `docs/architecture/aegis-transport-architecture.md §12.1`。上下行统一使用 `UplinkMessage` / `DownlinkMessage` oneof 包络承载批量 ACK、流控与签名命令；Sensor 本地实现禁止自行定义等价的简化 RPC。

```protobuf
service AgentService {
  // 上行 oneof = EventBatch / ClientAck / FlowControlHint
  // 下行 oneof = SignedServerCommand / BatchAck / FlowControlHint
  rpc EventStream(stream UplinkMessage) returns (stream DownlinkMessage);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
  rpc UploadArtifact(stream ArtifactChunk) returns (UploadResult);
  rpc PullUpdate(UpdateRequest) returns (stream UpdateChunk);
}
// 下行命令仍以 SignedServerCommand 承载；Agent 必须在签名验证通过后再校验
// ServerCommand.target_scope（见 transport §12.1.3）——不匹配即丢弃并审计。
```
---
## 七、自保护子系统
### 7.1 防篡改机制全景
```
┌────────────────────────────────────────────────────────────────┐
│                  Agent Self-Protection Layers                  │
│                                                                │
│  Layer 1: 内核级保护                                            │
│  ├── Windows: ObRegisterCallbacks / Minifilter / CmCallback    │
│  ├── Linux: LSM / fanotify / eBPF 保护关键进程与目录           │
│  ├── macOS: System Extension + Endpoint Security               │
│  ├── ELAM 确保驱动尽早加载                                      │
│  └── 边界: Ring 0 攻击者不保证可防护, 由完整性监测负责发现      │
│                                                                │
│  Layer 2: 完整性校验                                            │
│  ├── Agent 二进制、驱动、规则、模型、插件统一签名校验          │
│  ├── 关键配置与热更新资产带版本号和校验摘要                     │
│  └── 校验失败进入受限模式并上报高优先级告警                     │
│                                                                │
│  Layer 3: 看门狗                                                │
│  ├── 主进程与看门狗双向心跳                                     │
│  ├── Windows: 看门狗注册为 PPL-AntiMalware 进程                │
│  ├── Linux: 通过 LSM / AppArmor / SELinux 限制 ptrace / kill   │
│  ├── macOS: System Extension 受系统机制保护                     │
│  ├── Kernel Integrity Monitor 在看门狗中周期执行                │
│  └── 崩溃处理: 自动拉起、保留 core dump、上报崩溃摘要           │
│                                                                │
│  Layer 4: Anti-Tampering Techniques                            │
│  ├── Anti-Debug: 调试附加检测、时间异常检测、断点检测           │
│  ├── Hypervisor 检测: 仅告警, 不作为阻断依据                    │
│  ├── Anti-Unload: 非授权卸载请求拒绝, 服务与驱动受保护          │
│  └── Secure Update: 升级包签名、版本门限、回滚保护              │
└────────────────────────────────────────────────────────────────┘
```
### 7.2 Agent 密钥与身份管理
```
Agent 身份与密钥体系:
├── 设备身份:
│   ├── agent_id
│   ├── 设备证书 / attestation 结果
│   └── 平台特征摘要 (TPM / Secure Enclave / OS keystore)
├── 主密钥:
│   ├── 优先绑定 TPM / Secure Enclave
│   └── 无硬件根时退化到 OS credential store + 密钥轮换策略
├── 派生关系:
│   ├── WAL 加密密钥 = HKDF(master_key, "wal-encryption")
│   ├── 隔离区加密密钥 = HKDF(master_key, "quarantine")
│   ├── 本地配置加密密钥 = HKDF(master_key, "config")
│   ├── Registry Journal 加密密钥 = HKDF(master_key, "reg-journal")
│   └── 插件签名验证公钥为内嵌只读信任根
├── 使用策略:
│   ├── 高敏感字段优先使用硬件根直接封装
│   ├── 敏感密钥只在短生命周期内解封
│   └── 使用完立即 zeroize, 关键缓冲区 mlock
└── 轮换与吊销:
    ├── 证书按策略轮换
    ├── 设备吊销后拒绝下发命令
    └── 本地缓存凭证受 TTL 与签名双重约束
```
### 7.3 崩溃利用分析
```
当 Agent 主进程、看门狗或关键插件发生崩溃时:
├── 自动收集:
│   ├── minidump / core dump
│   ├── 崩溃前最近 4KB Ring Buffer 片段
│   ├── 当前活跃 Sensor / Rule / Plugin 上下文
│   └── 异常类型与故障线程寄存器快照
├── 本地分析:
│   ├── 崩溃地址是否位于高风险函数或可执行堆区域
│   ├── 栈帧是否呈现 ROP / JOP 异常模式
│   ├── 堆状态是否符合 spray / overflow / UAF 特征
│   ├── 异常类型是否为可疑的读写执行违例
│   └── 崩溃是否与特定输入样本、脚本或文件相关联
├── 评分:
│   ├── BENIGN_CRASH: 常规软件缺陷
│   ├── SUSPICIOUS_CRASH: 存在利用迹象
│   └── EXPLOITATION_LIKELY: 高度疑似被利用
├── 联动:
│   ├── SUSPICIOUS 及以上立即上报高优先级告警
│   ├── 自动提升该端点取证保留等级
│   └── 连续异常崩溃 > 3 次/小时 → 进入安全模式并限制高风险路径
└── 目标:
    ├── 区分普通崩溃与攻击触发崩溃
    └── 防止攻击者利用 Agent 自身漏洞作为绕过入口
```
---
## 八、升级与部署子系统
### 8.1 A/B 分区升级 + Schema Migration
```
升级框架由 A/B 分区、Schema Migration、配置迁移、灰度门禁与跨版本升级路径组成。

┌────────────────────────────────────────────────────────────────┐
│  Schema Migration Framework                                    │
│                                                                │
│  agent.db (SQLite) 版本管理:                                    │
│  ├── 每个 Agent 版本声明所需 schema 版本:                      │
│  │   → release_A → schema_v15                                  │
│  │   → release_B → schema_v17                                  │
│  ├── 升级时检测 schema 差异:                                    │
│  │   → current_schema < required_schema → 执行 migration        │
│  ├── Migration 脚本嵌入 Agent 二进制中:                         │
│  │   → migrations/v15_to_v16.sql                                │
│  │   → migrations/v16_to_v17.sql                                │
│  │   → 按序执行, 每步有 checksum 验证                           │
│  ├── 回滚支持:                                                  │
│  │   → 升级前自动备份 agent.db → agent.db.pre_v17               │
│  │   → 回滚时恢复备份                                          │
│  └── 兼容性矩阵:                                               │
│      → Agent 二进制标注 min_schema_version / max_schema_version │
│      → 不在范围内 → 拒绝启动, 要求先升级/回退                  │
│                                                                │
│  配置迁移:                                                      │
│  ├── agent.conf 版本化 (conf_version 字段)                     │
│  ├── 新版本包含 config transformer:                              │
│  │   → 读取旧格式 → 输出新格式 → 验证 → 写入                  │
│  └── 不可迁移的字段 → 使用默认值 + 上报 CONFIG_MIGRATED 事件   │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  Automated Rollout Gate                                        │
│                                                                │
│  灰度阶段健康指标 (云端自动评估):                               │
│  ├── crash_rate:          升级后 Agent 崩溃率                  │
│  │   → Gate: < 0.1% (1/1000 Agent)                            │
│  ├── cpu_p95:             升级后 CPU P95                       │
│  │   → Gate: < 3% (不超过基线 50%)                             │
│  ├── memory_p95:          升级后内存 P95                       │
│  │   → Gate: < 220MB (且不超过目标上限)                        │
│  ├── event_drop_rate:     事件丢失率                           │
│  │   → Gate: < 0.01%                                          │
│  ├── detection_rate:      检测命中率                           │
│  │   → Gate: 不低于基线 90% (防止检测能力退化)                 │
│  ├── heartbeat_loss_rate: 心跳丢失率                           │
│  │   → Gate: < 0.5%                                           │
│  └── 任一 Gate 不通过 → 自动暂停灰度 + 告警 + 可选自动回滚    │
│                                                                │
│  灰度流程 (自动化):                                             │
│  ├── Canary:  1% (50 Agent) → 观察 2h → 评估 Gate             │
│  ├── Stage 1: 5% → 观察 4h → 评估 Gate                        │
│  ├── Stage 2: 25% → 观察 12h → 评估 Gate                      │
│  ├── Stage 3: 50% → 观察 24h → 评估 Gate                      │
│  └── Full:    100%                                             │
│  每个阶段之间需人工确认 (或配置为全自动)                        │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  Multi-Version Upgrade Path                                     │
│                                                                │
│  ├── 相邻版本: bsdiff 增量包 (典型 5-15MB)                     │
│  ├── 跨 1-3 个版本: 链式 delta                                 │
│  │   → release_N → release_N+1.delta → release_N+1 → release_N+2.delta │
│  │   → Agent 按序应用 delta 链                                  │
│  ├── 跨 >3 个版本: 全量包 fallback                             │
│  │   → 下载完整 Agent 包 (~75MB)                               │
│  │   → 替换非活跃分区全部内容                                   │
│  │   → Schema migration 从当前版本逐步升级到目标版本            │
│  └── 云端维护升级路径矩阵:                                     │
│      → 对每个 (source_version, target_version) 组合              │
│      → 预计算最优升级方式 (delta chain 或 full package)         │
│      → Agent 请求升级时, 云端返回最优路径                       │
└────────────────────────────────────────────────────────────────┘
```
### 8.2 安装部署
```
安装与首启流程:
├── Windows:
│   ├── MSI 安装主进程、驱动、看门狗与升级器
│   ├── 校验证书链、驱动签名与 ELAM 依赖
│   └── 首启完成设备注册、策略拉取与自检
├── Linux:
│   ├── DEB/RPM 安装 systemd service、eBPF 资产与策略文件
│   ├── 校验 kernel feature、BTF/CO-RE 兼容性
│   └── 首启挂载 /sys/fs/bpf、注册 Agent、执行健康检查
├── macOS:
│   ├── pkg 安装 System Extension 与 Network Extension
│   ├── 引导用户完成系统授权
│   └── 首启注册、插件验签、通信与传感器自检
└── 通用部署要求:
    ├── 安装前检查磁盘、权限、系统版本与冲突软件
    ├── 安装后执行最小可用自检与回滚点创建
    └── 首次心跳成功前不执行高风险自动响应
```
---
## 九、性能、资产与运维治理
### 9.1 资源治理模型
```
资源治理分为 Level 0-3:
├── Level 0 Normal:
│   ├── 全量传感器 + 全量检测链
│   └── 适用于稳态运行
├── Level 1 Elevated:
│   ├── 保留全量安全能力
│   └── 降低低价值遥测频率, 收紧后台任务并发
├── Level 2 High:
│   ├── 保留: Process CREATE/EXIT, AUTH_*, NETWORK_CONNECT, AMSI
│   ├── 暂停: File READ/WRITE (non-exe), Registry INFO, Network FLOW_STATS
│   └── ATT&CK 覆盖率下降约 15%
└── Level 3 Critical:
    ├── 仅保留关键传感器与关键响应动作
    ├── 上报 AGENT_DEGRADED 告警
    │   ├── 当前降级等级
    │   ├── 触发原因 (CPU / Memory / 具体指标值)
    │   ├── 预估 ATT&CK 覆盖率
    │   ├── 被禁用的 Sensor 列表
    │   └── 被禁用的检测阶段列表
    └── 运营团队据此评估风险并触发扩容、排障或策略调整
```
### 9.2 Agent 健康指标体系
```
HeartbeatRequest.AgentHealth {
  agent_version:            string
  policy_version:           string
  ruleset_version:          string
  model_version:            string
  cpu_percent_p95:          f32
  memory_rss_mb:            u32
  queue_depths:             Map<String, u32>
  dropped_events_total:     u64
  sensor_status:            Map<String, SensorHealth>
  communication_channel:   string  // "grpc" | "websocket" | "long-polling" | "domain-fronting"
  kernel_integrity_pass:   bool    // 最近内核完整性检测结果
  etw_tamper_detected:     bool    // (Windows) ETW 篡改检测
  amsi_tamper_detected:    bool    // (Windows) AMSI 篡改检测
  bpf_integrity_pass:      bool    // (Linux) BPF 程序完整性
  adaptive_whitelist_size: u32     // 反馈白名单当前条目数
  plugin_status:           Map<String, PluginHealth>  // 插件健康状态
  // Lineage 计数器
  lineage_counters: {
    rb_produced:     u64
    rb_consumed:     u64
    rb_dropped:      Map<Lane, u64>  // 每 Lane 丢弃数
    det_received:    u64
    dec_emitted:     u64
    wal_written:     u64
    grpc_acked:      u64
  }
}
```
### 9.3 本地漏洞评估
```
本地漏洞评估由软件资产清单、CVE 匹配与基础配置审计三部分组成:
├── 软件资产清单:
│   ├── Windows: Uninstall 注册表、MSI 数据库、AppX、Winget
│   ├── Linux: dpkg / rpm / snap / flatpak / 自编译软件指纹
│   ├── macOS: /Applications、Homebrew、pkgutil
│   └── 周期: 每 6 小时全量扫描 + 安装/卸载实时增量更新
├── CVE 匹配:
│   ├── 云端下发增量 CPE→CVE 映射数据库
│   ├── Agent 本地完成版本 → CPE → CVE 解析
│   ├── 风险排序融合 CVSS、EPSS 与资产重要性
│   └── 漏洞清单随心跳与资产快照一并上报
├── 配置审计:
│   ├── Windows: UAC、防火墙、RDP、Credential Guard 等
│   ├── Linux: SSH 配置、SUID/SGID、关键目录权限
│   ├── macOS: Gatekeeper、Full Disk Access、系统扩展状态
│   └── 通用: 弱密码策略、磁盘加密、证书过期、CIS 子集检查
└── 与检测联动:
    ├── 利用链告警可自动附带端点已有漏洞背景
    └── 输出按暴露面排序的修复优先级建议
```
### 9.4 被动网络设备发现
```
设计约束: 全被动发现, 不发送主动探测包

数据来源:
├── ARP / NDP 缓存
├── DHCP 请求与响应
├── mDNS / LLMNR / NetBIOS 广播
├── 本地网络连接表中的对端 IP / 端口
└── Linux 场景可使用 eBPF 被动捕获 ARP / DHCP / mDNS 元数据

输出信息:
├── IP / MAC / 主机名
├── TCP 指纹推测的 OS 类型
├── 已观测服务端口与连接方向
├── 该设备是否安装 EDR Agent
└── 设备首次出现、最近出现与可信度评分

上报与隐私:
├── 多端点发现结果在云端汇聚为网络拓扑
├── 未安装 Agent 的设备标记为 Unmanaged
└── MAC 等敏感标识支持脱敏后上报
```
### 9.5 本地 AI 应用安全监控
```
监控目标: 本地 AI 助手、桌面客户端、嵌入式模型运行时与模型文件

能力范围:
├── AI 应用清单:
│   ├── 发现已安装 AI 工具与本地推理框架
│   ├── 标记未经批准的影子 AI
│   └── 上报版本、签名与运行模式
├── AI DLP:
│   ├── 检测敏感数据被复制、粘贴或拖拽进 AI 会话
│   ├── 识别凭据、PII、源代码与密钥材料
│   └── 策略支持 BLOCK / WARN / AUDIT
├── 模型完整性:
│   ├── 监控 GGUF / ONNX / SafeTensors 等模型文件
│   ├── 检测模型被篡改、替换或异常加载
│   └── 记录模型来源、摘要与加载链路
└── Prompt 注入关联:
    ├── 识别 AI 输出中的可执行指令片段
    └── 当 AI 输出紧随脚本执行时建立关联告警
```
### 9.6 Agent 诊断模式
```
本地管理员可执行 aegis-sensor --diagnose 生成受控诊断包。

诊断内容:
├── 连接测试: TLS 握手、DNS、控制面可达性
├── 证书状态: 设备证书有效期、链路校验、吊销状态
├── Sensor 状态: Hook 结果、事件计数、失败原因
├── 检测引擎: 规则版本、模型版本、插件加载状态
├── Ring Buffer: 各 Lane 使用率与丢弃统计
├── WAL: 当前大小、待回放事件数、最近 checkpoint
├── 资源使用: CPU / Memory / Disk / Network 实时指标
├── 自保护: 完整性校验、看门狗状态、降级等级
└── 支持包: 最近 24h 日志与最小化配置摘要

输出与约束:
├── 默认输出到临时目录并支持管理员显式导出
├── 自动剔除密钥、规则全文、敏感情报内容
└── 适用于现场排障、灰度回归与客户支持
```
---
## 十、容器与云原生支持
### 10.1 容器环境 Agent 部署模式
```
模式 A: 宿主机 Agent + eBPF — 最小权限
┌──────────────────────────────────────────────────────────────┐
│  最小权限 DaemonSet                                          │
│                                                              │
│  securityContext:                                             │
│    privileged: false                                         │
│    capabilities:                                             │
│      add:                                                    │
│        - BPF              # 加载 eBPF 程序                   │
│        - PERFMON          # 性能监控 (eBPF perf events)      │
│        - SYS_ADMIN        # 挂载 debugfs/tracefs, cgroup     │
│        - SYS_PTRACE       # 读取 /proc/*/fd, 进程内存        │
│        - NET_ADMIN        # 网络隔离 (TC/XDP)               │
│        - SYS_RESOURCE     # 增加 rlimit (eBPF map size)      │
│      drop:                                                   │
│        - ALL              # 先 drop all, 再逐一 add          │
│    readOnlyRootFilesystem: true                              │
│    runAsNonRoot: false     # 需要 root 加载 eBPF             │
│                                                              │
│  SELinux / AppArmor 策略:                                    │
│  ├── 允许: bpf(), perf_event_open(), /sys/fs/bpf/ 读写      │
│  ├── 允许: /proc/*/ns/*, /proc/*/cgroup 读取                │
│  ├── 允许: containerd.sock / cri-o.sock 读取 (只读)         │
│  ├── 禁止: 宿主机文件系统写入 (除 Agent 数据目录)           │
│  ├── 禁止: 加载内核模块 (insmod/modprobe)                    │
│  └── 禁止: 挂载文件系统                                      │
│                                                              │
│  hostPID: true  (仍需, eBPF 需要全局进程视野)                │
│  hostNetwork: false (Agent 使用 Pod 网络)                    │
│                                                              │
│  安全收益:                                                   │
│  ├── 无 privileged → 无法直接访问所有设备                    │
│  ├── 无 SYS_MODULE → 无法加载恶意内核模块                    │
│  ├── readOnlyRootFilesystem → 无法修改 Agent 二进制          │
│  └── SELinux / AppArmor 提供额外约束                         │
└──────────────────────────────────────────────────────────────┘
模式 B: Sidecar — 轻量化裁剪
┌──────────────────────────────────────────────────────────────┐
│  Sidecar Lite Profile:                                        │
│  ├── 禁用: YARA 扫描, ML 推理, 文件哈希 (由宿主机 Agent 做)  │
│  ├── 仅启用: 进程/网络/文件元数据采集 (不含文件内容)         │
│  ├── 规则: 仅加载与容器相关的精简规则集 (~200 rules)         │
│  └── 资源占用:                                                │
│      ├── 内存: ~30MB                                          │
│      ├── CPU: < 0.5%                                         │
│      └── 50 Pod/节点 → 1.5GB                                  │
│                                                              │
│  数据流: Sidecar → (unix socket) → 宿主机 Agent → Cloud      │
│  ├── Sidecar 不直接与 Cloud 通信                              │
│  ├── 宿主机 Agent 汇聚所有 Sidecar 的遥测                    │
│  └── 减少 TLS 连接数和证书管理复杂度                          │
└──────────────────────────────────────────────────────────────┘
模式 C: Serverless / Managed Runtime
┌──────────────────────────────────────────────────────────────┐
│  覆盖: AWS Lambda / ECS Fargate / Azure Container Instances  │
│  / Google Cloud Run 等无法运行 Agent 的环境                   │
│                                                              │
│  方案 1: Runtime Library Instrumentation                      │
│  ├── 提供 EDR SDK (Python/Node.js/Java/Go/.NET)             │
│  ├── 作为 Lambda Layer / 依赖库集成                           │
│  ├── 采集能力:                                                │
│  │   ├── HTTP 请求/响应 (入/出)                               │
│  │   ├── 文件操作 (os.open/write/read 拦截)                   │
│  │   ├── 子进程创建 (subprocess 拦截)                          │
│  │   ├── 网络连接 (socket 拦截)                                │
│  │   └── 环境变量 / 运行时元数据                               │
│  ├── 数据上报: 直接 HTTPS POST 到 EDR Cloud                   │
│  └── 局限: 无内核态可见性, 仅应用层                           │
│                                                              │
│  方案 2: Cloud API 日志集成                                    │
│  ├── 采集 CloudTrail / CloudWatch / Azure Monitor 日志        │
│  ├── 通过云端 Connector 而非 Agent 采集                       │
│  └── 延迟: 分钟级 (非实时)                                    │
│                                                              │
│  方案 3: Runtime Security Agent (WASM-based)                  │
│  ├── 轻量 WASM Agent 运行在应用进程内                         │
│  ├── 无需特权, 无需 eBPF                                     │
│  ├── 采集: syscall wrapper hook (LD_PRELOAD / WASM 沙箱)     │
│  └── 适用: 支持 WASM 的 serverless 运行时                     │
│                                                              │
│  覆盖率对比:                                                  │
│  ├── 宿主机 Agent + eBPF:   ATT&CK ~85%                     │
│  ├── Sidecar:               ATT&CK ~60%                     │
│  ├── Runtime SDK:           ATT&CK ~30%                     │
│  ├── Cloud API 日志:        ATT&CK ~15%                     │
│  └── 无覆盖:                ATT&CK 0%                       │
│  → 即使 30% 覆盖也远好于 0%, SDK 方案值得部署               │
└──────────────────────────────────────────────────────────────┘
```
### 10.2 容器特定检测能力
```
容器环境检测能力:
├── 容器逃逸:
│   ├── 可疑 mount / namespace 切换
│   ├── hostPath 滥用
│   └── 对宿主机 /proc、/sys、/var/run 的异常访问
├── 权限异常:
│   ├── privileged 容器
│   ├── 新增危险 capability
│   └── ServiceAccount / Token 挂载异常
├── 运行时篡改:
│   ├── 镜像层之外的二进制落盘
│   ├── entrypoint / command 被篡改
│   └── side-loaded 二进制与脚本执行
├── 横向移动:
│   ├── 容器到容器异常扫描
│   ├── 对 kube-apiserver / etcd / metadata service 的探测
│   └── 凭据复用与秘密读取行为
└── 编排关联:
    ├── 结合 Pod / Namespace / Node / OwnerReference 做实体归因
    └── 将容器事件回填到宿主机进程树和云端资产图谱
```
---
## 十一、平台适配与兼容性
### 11.1 操作系统兼容性矩阵
| 平台 | 最低版本 | 内核态方式 | 降级方案 |
|------|---------|-----------|---------|
| Windows 10 | 1809 (LTSC 2019) | WDM Minifilter + WFP + ETW | — |
| Windows 11 | 21H2 | 同上 | — |
| Windows Server | 2016+ | 同上 | — |
| Ubuntu | 18.04+ | eBPF (CO-RE, kernel 5.8+) | 4 级降级 (见 2.3) |
| RHEL/CentOS | 7.6+ | eBPF (kernel 4.18+ with BTFHub) | 4 级降级 |
| Debian | 10+ | eBPF | 4 级降级 |
| Amazon Linux | 2+ | eBPF | 4 级降级 |
| SUSE | 15 SP2+ | eBPF | 4 级降级 |
| macOS | 12 (Monterey)+ | ESF + Network Extension | — |
| **AWS Lambda** | **全版本** | **Runtime SDK** | **应用层仅** |
| **ECS Fargate** | **全版本** | **Runtime SDK / API** | **应用层仅** |
### 11.2 Rust 跨平台抽象层
```rust
// 跨平台抽象层示例
pub trait PlatformSensor: Send + Sync {
    fn start(&mut self, config: &SensorConfig) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
    fn poll_events(&self, buf: &mut EventBuffer) -> Result<usize>;
    fn capabilities(&self) -> SensorCapabilities;
}
pub trait PlatformResponse: Send + Sync {
    fn suspend_process(&self, pid: u32) -> Result<()>;    // 必须先于 kill
    fn kill_process(&self, pid: u32) -> Result<()>;
    fn kill_ppl_process(&self, pid: u32) -> Result<()>;   // PPL 进程终止
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
## 十二、关键性能基准
| 指标 | 目标 | 说明 |
|------|------|------|
| Agent 启动时间 | < 5s | 首次注册与首次全量资产同步不计入 |
| 稳态 CPU 占用 | ≤ 3% (P95) | 含 Storyline、ASR、Deception、Vuln Scan 等完整能力 |
| 峰值 CPU 占用 | ≤ 6% (P99) | 含模型推理、实时取证与完整性检查 |
| 内存占用 (RSS) | ≤ 220MB | 全功能 profile |
| 事件处理吞吐 | ≥ 350K event/s | 含故事线关联与脚本解混淆 |
| 单事件延迟 (P50) | < 20μs | 常规检测路径 |
| 单事件延迟 (P99) | < 200μs | 含 temporal / storyline 关联 |
| Ring Buffer 丢事件率 (CRITICAL) | 0% | 优先级保留设计 |
| Ring Buffer 丢事件率 (全局) | < 0.01% | 低优先级 lane 允许受控丢弃 |
| 文件哈希吞吐 | ≥ 500 MB/s | 启用流式与硬件加速时 |
| 网络带宽 (均值) | ≤ 60 KB/s | 含资产、漏洞、发现与健康指标上报 |
| 网络带宽 (峰值) | ≤ 500 KB/s | 不含取证包 / 内存 dump 上传 |
| 磁盘写入 (均值) | ≤ 5 MB/s | 含 WAL、快照元数据与本地缓存 |
| 安装包大小 | ≤ 75 MB | 含模型、CVE 数据与诱饵模板 |
| 内存中规则集 | ≤ 22 MB | 含 temporal 状态与热更新缓冲 |
| 内存中 ML 模型 | ≤ 20 MB | 含主模型与冷启动模型 |
| VSS / 快照周期 | 4h | 默认保护周期, 可按策略调整 |
| 金丝雀文件检测延迟 | < 100ms | 从文件被触碰到触发告警 |
| 离线检测能力 | 100% | 本地完整检测链与自主响应保持可用 |

说明:
- 上述指标默认以桌面/服务器全功能 profile 为基准。
- Sidecar、Runtime SDK、Cloud API Connector 等轻量模式按各自部署形态单独核算。
