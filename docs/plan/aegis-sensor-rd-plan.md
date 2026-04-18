# Aegis Sensor 研发计划（完整能力版）

> 依据文档：
> - `docs/技术方案/sensor-final技术解决方案.md`
> - `docs/architecture/aegis-sensor-architecture.md`
> - 关联依赖：`docs/architecture/aegis-transport-architecture.md`（仅用于 Agent↔Gateway wire contract）

## 1. 背景与目标

本计划用于将 Aegis Sensor 按终态方案落地为可发布、可灰度、可审计、可回滚的 Production-Grade 终端 Agent。

交付目标不是 MVP，也不是“主能力先做、扩展能力后补”。交付基线必须覆盖：

- Windows / Linux / macOS 主线 Sensor
- 内核态采集、用户态核心引擎、本地检测、响应执行、通信、自保护、升级发布
- 容器宿主机模式、Sidecar Lite、Serverless Runtime SDK / Cloud API Connector
- 运维诊断、性能治理、灰度发布、离线自治、证据链和审批安全

## 2. 非妥协原则

- 不删功能：技术方案和架构文档中的能力项全部进入交付范围。
- 不降设计：接口契约、安全模型、审批链、离线语义、资源指标按文档执行，不以“先简化实现”替代。
- 不拆事实源：Sensor 侧接口、事件模型、命令签名与审批逻辑必须与架构文档和 transport 契约一致。
- 不以资源不足为由裁剪范围：团队不足时仅允许延长周期，不允许删减平台、能力或安全边界。
- 不以内核态承载策略逻辑：内核态只做 Hook / Filter / Deliver / Guard，策略判断统一在用户态完成。

## 3. 范围基线

### 3.1 内核与平台采集

必须完整交付以下平台与传感器能力：

| 类别 | Windows | Linux | macOS |
|------|---------|-------|-------|
| 进程 | ETW + Ps* + Ob* + Direct Syscall Detection | eBPF/kprobe/tracepoint/LSM | ESF AUTH/NOTIFY |
| 文件 | Minifilter | eBPF + fanotify + LSM | ESF AUTH_OPEN/WRITE/CLOSE |
| 网络 | WFP + DNS | eBPF + TC/XDP + DNS | Network Extension |
| 注册表 | CmRegisterCallbackEx + Registry Change Journal | N/A | N/A |
| 认证 | Security Auditing | PAM/audit/auth.log | OpenDirectory/OpenSSH login |
| 脚本 | AMSI + AMSI bypass 检测 | bash/audit/uretprobe | ESF 事件补充 |
| 内存 | NtMapView/VirtualAlloc 监测 + YARA 触发 | process_vm_readv / mmap 监测 | mach_vm 取证 |
| 容器 | N/A | cgroup/ns/CRI 感知 | N/A |

必须额外交付：

- Named Pipe / IPC 监控
- DLL 加载深度监控
- VSS / 文件系统快照保护
- 设备控制
- 内核完整性监控
- Linux eBPF 4 级降级路径

### 3.2 用户态核心引擎

必须完整交付：

- Rust `Orchestrator`
- 4-lane MPSC Ring Buffer 消费器
- `Emergency Spill Queue`
- `Sensor Dispatch`
- `NormalizedEvent`
- `TelemetryEvent`
- `ProcessTree`
- 文件哈希策略与缓存
- `LineageTracker`
- `AdaptiveWhitelist`
- `HealthReporter`
- 配置热更新、规则热更新、模型热更新、插件热更新

### 3.3 本地检测与情报能力

必须完整交付：

- Stage 0 Fast Path
- Stage 1 Tiered Bloom + Cuckoo IOC
- Stage 2 Rule VM + Temporal
- Stage 2.5 AMSI Fast-Path Interlock
- Stage 3 YARA Memory/File Scan
- Stage 4 ONNX Runtime 本地 ML（含 OOD）
- Stage 5 Sharded Stateful Correlation
- 勒索软件 4 层检测
- ASR
- 身份威胁检测
- 欺骗技术
- 脚本多层解混淆
- Storyline Engine
- Threat Intelligence 反馈回路
- 本地漏洞评估
- 被动网络设备发现
- 本地 AI 应用安全监控

### 3.4 响应执行与自保护

必须完整交付：

- Two-Phase Process Termination
- PPL-aware 终止路径
- Block Decision Map / 预防性阻断
- 文件隔离（Quarantine）
- 网络隔离 / management-only / break-glass 释放
- 端点防火墙管控
- 注册表回滚
- 文件系统回滚
- 实时取证
- Remote Shell 安全加固
- 用户会话锁定
- 预签名 Playbook 与离线审批队列
- 四层自保护
- 主密钥、派生密钥、证书与吊销
- 崩溃利用分析

### 3.5 通信、升级、运维与云原生

必须完整交付：

- High / Normal / Bulk 三路通道
- gRPC + WebSocket + Long-Polling + Domain Fronting 回退链
- `SignedServerCommand` 验签、`target_scope` 校验、`command_id` 去重、`ApprovalProof` 验签
- WAL 分层存储：Telemetry WAL + Forensic Journal + Emergency Audit Ring
- 离线自治与恢复回放
- QoS 与前后台感知
- A/B 升级、Schema Migration、配置迁移、灰度 Gate
- 诊断模式 `aegis-sensor --diagnose`
- 容器宿主机 Agent + eBPF
- Sidecar Lite
- Runtime SDK
- Cloud API Connector

## 4. 研发组织与并行工作流

建议编制 18-22 FTE，按 5 条工作流并行推进：

| 工作流 | 责任范围 | 建议编制 |
|--------|----------|---------|
| WF-1 平台采集 | Windows 内核、Linux eBPF、macOS ESF/NE、设备控制、快照保护 | 6-7 |
| WF-2 核心运行时 | Rust 主进程、事件模型、Ring Buffer/Spill、process tree、health/lineage | 4 |
| WF-3 检测引擎 | IOC、Rule VM、Temporal、YARA、ML、勒索/ASR/身份/欺骗/脚本/Storyline | 4-5 |
| WF-4 响应与保护 | response executor、隔离、回滚、取证、Remote Shell、自保护、密钥与审批 | 3-4 |
| WF-5 通信与发布 | gRPC/WAL/QoS/离线、升级灰度、容器模式、QE、性能、安全、SRE | 4-5 |

协作规则：

- M0 完成前冻结接口，不允许平台实现私自扩展 wire shape。
- 平台采集、核心运行时、检测引擎、响应引擎、通信升级在 M1 之后并行推进。
- QE 从 M0 开始介入，所有里程碑都有独立退出 Gate。

## 5. 里程碑计划

总周期按 40-48 周规划；M1-M5 允许重叠，但每个里程碑的退出标准必须独立满足。

### 5.1 M0：规格冻结与工程底座（4 周）

**目标**

- 冻结事件模型、模块接口、platform trait、wire contract、审批与签名模型。
- 建立 Rust workspace、平台目录、代码生成、CI、测试基座、性能基准框架。

**必须交付**

- `PlatformSensor` / `PlatformResponse` / `PreemptiveBlock` / `KernelIntegrity` / `PlatformProtection`
- FlatBuffers 事件 ABI
- Protobuf/gRPC 契约集成方式
- SQLite schema versioning 框架
- 规则/模型/插件签名校验框架
- 实验室环境：Windows、Linux、macOS、K8s、Serverless 集成测试基座

**退出标准**

- 接口评审通过
- Sensor 文档与 transport 契约一致
- CI 可跑静态检查、单元测试、契约测试

### 5.2 M1：平台采集与内核保护基线（8 周）

**目标**

- 交付三平台采集基线与内核保护路径，不留“后补传感器”。

**必须交付**

- Windows：ETW、Ps*、Ob*、Minifilter、WFP、CmCallback、AMSI、Direct Syscall、Named Pipe、DLL、VSS、设备控制、ETW tamper
- Linux：eBPF process/file/network/auth/container、TC/XDP、LSM、fanotify、BPF self-protection、4 级降级
- macOS：ESF AUTH/NOTIFY、Network Extension、System Extension、签发/授权流程
- 统一采集事件可进入 Ring Buffer mock 流水线

**退出标准**

- 三平台安装/启动/采集冒烟通过
- 平台传感器与文档清单一一对应，无空项
- Ring 3 防护与 Ring 0 检测边界可验证

### 5.3 M2：核心运行时与数据平面（6 周）

**目标**

- 建立稳定的用户态事件平面与观测面。

**必须交付**

- `Orchestrator`
- 4-lane 消费 + Spill drain
- `Sensor Dispatch`
- `NormalizedEvent` / `TelemetryEvent`
- `ProcessTree` / 进程快照同步
- 文件哈希策略、缓存、限流
- `LineageTracker`
- `HealthReporter`
- `AdaptiveWhitelist` 基础闭环
- 配置、规则、模型、插件热加载骨架

**退出标准**

- 从原始事件到统一事件模型的转换链可观测
- lineage 计数器可用于环节丢失率计算
- CRITICAL 事件在压力下具备审计可追踪性

### 5.4 M3：本地检测引擎与扩展检测能力（8 周）

**目标**

- 交付完整 Stage 0-5 本地检测链与文档中的专项检测能力。

**必须交付**

- Stage 0/1/2/2.5/3/4/5 全链路
- Tiered Bloom + Cuckoo
- Rule VM + Temporal state buffer
- AMSI Fast-Path 与阻断联动
- YARA 文件/内存扫描
- ONNX Runtime ML（Static / Behavioral / Script）
- 勒索软件 4 层检测
- ASR
- 身份威胁检测
- 欺骗技术
- 脚本多层解混淆
- Storyline Engine
- Threat Intel 反馈回路
- 漏洞评估
- 被动网络设备发现
- 本地 AI 应用安全监控

**退出标准**

- 端到端典型事件延迟达到 P50 < 20us、P99 < 200us
- 事件吞吐达到 >= 350K event/s
- 规则、模型、YARA、Storyline、专项检测都有独立验证用例

### 5.5 M4：响应执行、自保护与安全控制（8 周）

**目标**

- 交付完整的响应执行链、审批链、自保护和证据链能力。

**必须交付**

- Two-Phase Termination
- PPL-aware 终止
- Block Decision Map
- Quarantine
- 网络隔离、management-only、break-glass
- 端点防火墙规则层
- 注册表回滚
- 文件系统回滚
- 实时取证
- Remote Shell
- 用户会话锁定
- 离线审批与预签名 Playbook
- 四层自保护
- 主密钥与派生密钥
- 证书轮换与吊销
- 崩溃利用分析

**Playbook 约束必须落地**

- `ttl_ms`
- `max_executions`
- `min_policy_version` / revocation floor
- `target_scope`
- 重连即清理撤销/过期项

**退出标准**

- 所有高危动作均有审批与审计闭环
- 所有离线动作都符合文档中的自动/预审批/禁止三类语义
- 自保护与防篡改对抗测试通过

### 5.6 M5：通信、离线自治、升级发布（6 周）

**目标**

- 交付完整通信平面、离线自治和发布系统。

**必须交付**

- High / Normal / Bulk 三路通道
- 回退链与信道升级探测
- `SignedServerCommand`、`ApprovalPolicy`、`ApproverEntry`、`ApprovalProof`
- `target_scope` 校验
- `command_id` 去重账本
- clock skew sanity bound
- Telemetry WAL
- Forensic Journal
- Emergency Audit Ring
- WAL 分级水位降级与 `PARTIAL` 标记
- QoS、自适应带宽、前后台感知
- A/B 升级、Schema Migration、配置迁移
- 自动灰度 Gate
- 诊断模式

**退出标准**

- 断网 72h 后可完整恢复 Forensic Journal
- 审批证明、scope violation、replay、clock skew 均可被拒绝并审计
- 升级失败可自动回滚

### 5.7 M6：容器模式、兼容性与 GA 硬化（6-8 周）

**目标**

- 交付主机、容器和 Serverless 形态的完整版本，并完成 GA 前硬化。

**必须交付**

- 宿主机 Agent + eBPF DaemonSet
- Sidecar Lite
- Runtime SDK
- Cloud API Connector
- 容器逃逸 / 权限异常 / 运行时篡改 / 横向移动 / 编排关联
- 三平台安装包、签名、Notarization/等效签发链
- Pilot、灰度、GA Runbook

**退出标准**

- 容器与 Serverless 模式可安装、可观测、可升级、可回滚
- 兼容矩阵全部走完
- 发布 Gate 达标

## 6. 测试、验证与发布闸门

### 6.1 测试体系

- 单元测试：事件模型、规则 VM、审批验证、WAL、Playbook、隔离语义
- 平台集成测试：Windows / Linux / macOS 各传感器和响应动作
- 契约测试：FlatBuffers、gRPC、命令签名、审批签名、target scope
- 对抗测试：ETW tamper、AMSI bypass、direct syscall、BPF 篡改、callback 篡改、进程隐藏、离线审批伪造
- 性能测试：延迟、吞吐、CPU、RSS、磁盘写、网络、Spill、WAL 水位
- 兼容性测试：OS 版本、kernel 版本、降级路径、K8s 发行版、Serverless runtime

### 6.2 强制发布 Gate

| 指标 | Gate |
|------|------|
| crash_rate | < 0.1% |
| cpu_p95 | < 3% |
| memory_p95 | < 220MB |
| event_drop_rate | < 0.01% |
| detection_rate | >= 基线 90% |
| heartbeat_loss_rate | < 0.5% |

Gate 任一失败：

- 自动停止灰度
- 进入回滚或人工复核
- 禁止进入下阶段

## 7. 交付完成定义

同时满足以下条件才视为计划完成：

- 源文档中的能力项全部有实现归属、测试归属、验收归属
- 不存在 “后续增强”“可选交付”“降级实现替代正式实现” 的能力项
- Pilot 完成并通过灰度 Gate
- 三平台主线、容器模式、Sidecar、Runtime SDK / Cloud API Connector 全部具备发布能力
- 审计结论为：无功能缺失、无功能妥协、无设计妥协

## 8. 计划执行约束

- 开发顺序允许并行，但交付验收必须按接口冻结和里程碑 Gate 收口。
- 如 transport 契约变更，Sensor 计划必须同步修订，不允许本地派生私有协议。
- 如 Windows/macOS 签发流程导致节奏变化，只允许顺延里程碑，不允许删减平台或安全能力。
