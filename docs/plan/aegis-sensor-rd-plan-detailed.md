# Aegis Sensor 详细研发计划（执行分解版）

> 来源：
> - `docs/plan/aegis-sensor-rd-plan.md`
> - `docs/plan/aegis-sensor-rd-plan-audit.md`
> - `docs/技术方案/sensor-final技术解决方案.md`
> - `docs/architecture/aegis-sensor-architecture.md`

## 1. 执行规则

- 所有工作包都必须对应明确代码交付、测试交付、文档交付。
- 不允许把源文档中的正式能力下调为“占位实现”后宣称完成。
- 每完成一个工作包：
  - 先提交代码或工程变更一次
  - 再更新相应文档并单独提交一次
- 提交信息统一使用中文。

## 2. 工作包清单

### P00：详细计划与执行基线

- 目标：将总计划拆成工作包、依赖和完成定义。
- 交付：
  - 本文档
  - `docs/plan/aegis-sensor-rd-status.md`
- 依赖：无

### P01：Rust Workspace 与基础工程骨架

- 目标：建立从零实现所需的 workspace、二进制入口、共享模型、平台 trait、proto/schema 目录。
- 交付：
  - workspace 根配置
  - `agentd` / `watchdog` / `updater` 二进制骨架
  - `aegis-model` / `aegis-platform` / `aegis-core` 基础 crate
  - proto 与 flatbuffers schema 骨架
  - 基础 CI / Makefile / `.gitignore`
- 依赖：P00
- 完成记录（2026-04-18）：
  - 已建立 `Cargo` workspace 与 `agentd` / `watchdog` / `updater` 二进制骨架
  - 已建立 `aegis-model` / `aegis-platform` / `aegis-core` 基础 crate 与平台 trait/mock harness
  - 已建立 `proto/agent/v1/agent_service.proto` 与 `schemas/event.fbs`
  - 已通过 `cargo check --workspace` 与 `cargo test --workspace`

### P02：统一配置模型与 Schema 版本框架

- 目标：建立 Agent 配置、策略版本、SQLite schema versioning、配置迁移骨架。
- 交付：
  - `AgentConfig`
  - `conf_version`
  - `agent.db` 版本元数据
  - migration 目录与执行器
- 依赖：P01
- 完成记录（2026-04-18）：
  - 已建立 `AgentConfig` / `PolicyVersion` / `ConfVersion` / `StorageConfig` / `RuntimeConfig`
  - 已建立 `AgentDb`、`schema_migrations`、`schema_metadata` 与 `active_config` / `config_snapshots`
  - 已建立 `crates/aegis-core/migrations/0001_agent_base.sql`
  - 已通过配置 roundtrip、非法 `conf_version`、schema migration 与配置落库测试

### P03：统一事件模型与 Lineage 模型

- 目标：定义 `NormalizedEvent`、`TelemetryEvent`、`Storyline`、lineage 计数器与 checkpoint 模型。
- 交付：
  - 统一事件结构
  - ECS/OCSF 兼容字段骨架
  - lineage checkpoint 类型
- 依赖：P01
- 完成记录（2026-04-18）：
  - 已建立 `HostContext`、多态 `EventPayload`、`EventEnrichment`、`SyscallOrigin`
  - 已建立 `NormalizedEvent` / `TelemetryEvent` / `Storyline` / `StorylineContext`
  - 已建立 `LineageTrace`、`LineageCheckpoint`、`LineageCounters` 与 `TelemetryIntegrity`
  - 已通过统一事件构造与遥测转换测试

### P04：Core Orchestrator 与通道拓扑

- 目标：建立主事件循环、任务编排、channel 拓扑与 graceful shutdown。
- 交付：
  - tokio runtime
  - 核心 channel 连接
  - health / config / comms / response 任务入口
- 依赖：P01、P02、P03
- 完成记录（2026-04-18）：
  - 已建立 `BootstrapArtifacts`、发送/接收端拆分与运行时队列容量拓扑
  - 已建立 `sensor-dispatch`、`comms-tx-high`、`comms-tx-normal`、`telemetry-drain`、`response-executor`、`health-reporter`、`config-watcher`
  - 已建立 `RuntimeHandle` 与优雅退出流程，并接入 `agentd` 启停骨架
  - 已通过 runtime bootstrap 与 graceful shutdown 测试

### P05：Ring Buffer / Spill / Dispatch 基础实现

- 目标：建立用户态 4-lane 消费器、Spill、背压、原始事件到 `NormalizedEvent` 的转换骨架。
- 交付：
  - lane 抽象
  - spill 存储布局
  - `SensorDispatch`
- 依赖：P03、P04
- 完成记录（2026-04-18）：
  - 已建立 `FourLaneBuffer` 与 `LanePriority`，支持高优先级优先消费
  - 已建立 `SpillStore`，按 lane 持久化 `jsonl` overflow 记录
  - 已建立 `RawSensorEvent` 与 `SensorDispatch`，支持 raw → normalized 转换与 spill recover
  - 已通过优先级消费、溢出 spill、spill recover 测试

### P06：ProcessTree / Hashing / AdaptiveWhitelist / Health

- 目标：建立核心 runtime 辅助能力。
- 交付：
  - `ProcessTree`
  - 文件哈希策略
  - `AdaptiveWhitelist`
  - `HealthReporter`
- 依赖：P04、P05
- 完成记录（2026-04-18）：
  - 已建立 `ProcessTree`，支持进程创建、退出、祖先链与快照
  - 已建立 `HashCache` / `HashingPolicy`，支持 SHA-256 与阈值内 BLAKE3 预筛
  - 已建立 `AdaptiveWhitelist`，支持 TTL 清理与容量淘汰
  - 已建立 `HealthReporter`，支持以 lineage counter 生成健康快照
  - 已通过进程树、哈希缓存、自适应白名单、健康快照测试

### P07：平台 Trait 细化与 Mock Harness

- 目标：冻结 `PlatformSensor`、`PlatformResponse`、`PreemptiveBlock`、`KernelIntegrity`、`PlatformProtection` 的 mock 可执行契约。
- 交付：
  - trait 定义
  - mock 实现
  - 契约测试
- 依赖：P01、P03
- 完成记录（2026-04-18）：
  - 已建立 `PlatformDescriptor`、`PlatformTarget`、`KernelTransport`、`PlatformRuntime`
  - 已将 `MockPlatform` 扩展为可注入事件、记录动作、返回隐藏进程和导出 descriptor
  - 已建立 Windows/Linux/macOS 三类 mock descriptor
  - 已通过事件注入、响应动作记录、隐藏进程返回等平台层测试

### P08：Windows 平台采集基线

- 目标：Windows 传感器与保护路径代码骨架。
- 交付：
  - ETW / Ps / Ob / Minifilter / WFP / CmCallback 适配层
  - AMSI / Direct Syscall / IPC / DLL / VSS / Device Control 接口骨架
- 依赖：P07
- 实施分解：
  - 建立 `windows` 平台模块与子传感器注册表
  - 抽象 ETW、进程、文件、网络、注册表、脚本、内存、IPC、模块加载、快照保护、设备控制 11 类 provider
  - 建立 Windows 事件到 `RawSensorEvent` 的转换入口与能力矩阵
- 验收：
  - 单元测试覆盖 provider 注册、能力矩阵、关键事件转换
  - 不依赖目标主机即可在本地通过 cargo test；集成环境参考 `docs/env/开发环境.md`
- 完成记录（2026-04-19）：
  - 已建立 `WindowsPlatform`、12 类 provider 注册与 Windows descriptor
  - 已建立事件注入与 `EventBuffer` 轮询能力
  - 已覆盖 ETW/注册表/IPC/DLL/VSS/设备控制 等基线 provider 存在性测试
  - 已通过 Windows 平台事件轮询与能力矩阵测试

### P09：Linux 平台采集基线

- 目标：Linux eBPF/LSM/fanotify/container-aware 代码骨架。
- 交付：
  - eBPF loader 接口
  - maps/ringbuf 抽象
  - 4 级降级路径骨架
- 依赖：P07
- 实施分解：
  - 建立 `linux` 平台模块与 eBPF 程序装载抽象
  - 建立 process/file/network/auth/container 事件 provider 与 maps/ringbuf façade
  - 建立完整能力、tracepoint、fanotify、audit、最小模式 4 级降级模型
- 验收：
  - 单元测试覆盖降级决策、provider 能力矩阵、容器感知转换
  - 平台描述与 `degrade_levels=4` 保持一致
- 完成记录（2026-04-19）：
  - 已建立 `LinuxPlatform`、7 类 provider 注册与 Linux descriptor
  - 已建立 `Full / TracepointOnly / FanotifyAudit / Minimal` 4 级降级模型
  - 已建立带 `container_id` 的 Linux 事件注入与 `EventBuffer` 轮询能力
  - 已通过 provider 注册、降级层级和容器感知事件轮询测试

### P10：macOS 平台采集基线

- 目标：ESF / Network Extension / System Extension 代码骨架。
- 交付：
  - macOS 平台接口与授权流程抽象
- 依赖：P07
- 实施分解：
  - 建立 `macos` 平台模块与 ESF / NE / System Extension 抽象
  - 抽象授权状态机、事件订阅集与网络隔离入口
  - 建立 macOS 事件到 `RawSensorEvent` 的转换入口
- 验收：
  - 单元测试覆盖授权状态流转、能力矩阵、事件转换
- 完成记录（2026-04-19）：
  - 已建立 `MacosPlatform`、ESF / NE / System Extension / TCC / ExecPolicy provider 基线
  - 已建立 `NotDetermined / AwaitingUserApproval / Approved / Denied` 授权状态机
  - 已建立事件订阅集、授权态感知事件注入与 `EventBuffer` 轮询能力
  - 已通过授权状态流转、能力矩阵和授权事件轮询测试

### P11：IOC / Rule VM / Temporal

- 目标：Stage 0-2 核心实现。
- 交付：
  - Tiered Bloom + Cuckoo
  - Rule VM
  - Temporal state buffer
- 依赖：P03、P04、P05
- 实施分解：
  - 建立 IOC tier 索引、精确命中确认与风险级别映射
  - 建立规则字节码、栈式求值器、字段读取与布尔组合
  - 建立 temporal 窗口状态缓存与多事件匹配
- 验收：
  - 测试覆盖 IOC 命中、规则执行、时间窗口命中与误报旁路
- 完成记录（2026-04-19）：
  - 已建立 `TieredIndicatorIndex`，支持 Bloom 预筛与精确确认后的风险分层命中
  - 已建立栈式 `RuleVm`，覆盖字段读取、布尔组合、存在性与阈值比较
  - 已建立 `TemporalStateBuffer`，支持按 key 时间窗保留、超时淘汰与序列检测
  - 已通过 IOC 命中、Rule VM 求值和 temporal 序列/淘汰测试

### P12：YARA / Script Decode / AMSI Interlock

- 目标：Stage 2.5 与 Stage 3。
- 交付：
  - YARA 任务队列
  - 脚本多层解混淆
  - AMSI fast-path 联动
- 依赖：P11
- 实施分解：
  - 建立 YARA 扫描作业模型、调度器与结果缓存
  - 建立脚本解混淆流水线（编码识别、base64/charcode/powershell 常见混淆还原）
  - 建立 AMSI 命中与本地决策联动接口
- 验收：
  - 测试覆盖扫描任务调度、解混淆层计数、AMSI fast-path 分流
- 完成记录（2026-04-19）：
  - 已建立 `YaraScheduler`，支持作业入队、待处理去重与结果缓存
  - 已建立 `ScriptDecodePipeline`，覆盖 PowerShell `-enc`、base64 与 charcode 常见解码层
  - 已建立 `AmsiInterlock`，支持本地阻断与 YARA 快速分流决策
  - 已通过 YARA 调度、脚本解码和 AMSI fast-path 测试

### P13：ML / OOD / Behavioral Models

- 目标：Stage 4 模型框架。
- 交付：
  - ONNX Runtime 集成
  - Static / Behavioral / Script 三模型接口
  - OOD 判定骨架
- 依赖：P11
- 实施分解：
  - 建立模型抽象层、推理输入输出协议与本地模型注册
  - 建立静态、行为、脚本三类特征向量转换
  - 建立 OOD 评分器与阈值决策
- 验收：
  - 测试覆盖特征提取、模型路由、OOD 判定与失败回退
- 完成记录（2026-04-19）：
  - 已建立 `OnnxRuntimeSession` 抽象、`ModelRegistry` 与模型路由接口
  - 已建立静态、行为、脚本三类特征向量转换与行为窗口路由策略
  - 已建立在线质心 `OodScorer` 与缺模/推理失败回退策略
  - 已通过特征提取、模型路由、OOD 判定与失败回退测试

### P14：Correlation / Storyline / Threat Feedback

- 目标：Stage 5 与反馈闭环。
- 交付：
  - 分片关联器
  - Storyline engine
  - threat feedback / adaptive whitelist 回灌
- 依赖：P03、P11、P13
- 实施分解：
  - 建立按主机/进程树/lineage 分片的关联缓存
  - 建立 storyline 合并规则与自动叙事生成
  - 建立云端 threat feedback 到本地 adaptive whitelist 的应用器
- 验收：
  - 测试覆盖跨事件关联、storyline 合并、误报回灌生效
- 完成记录（2026-04-19）：
  - 已建立 `CorrelationCache`，支持按主机、根进程与 lineage 分片关联
  - 已建立 `StorylineEngine`，支持多事件合并、叙事生成与 technique/tactic 汇总
  - 已建立 `ThreatFeedbackApplier`，支持 feedback 到 `AdaptiveWhitelist` 的本地回灌
  - 已通过跨事件关联、storyline 合并和白名单回灌测试

### P15：专项检测能力

- 目标：勒索软件、ASR、Identity、Deception。
- 交付：
  - 勒索专项状态机
  - ASR 规则域
  - 身份威胁规则
  - 欺骗对象模型
- 依赖：P11、P12、P14
- 实施分解：
  - 建立勒索软件多信号状态机
  - 建立 ASR 域策略、身份威胁规则集与欺骗对象/触发器
  - 将专项检测统一接入规则与 storylines
- 验收：
  - 测试覆盖勒索信号聚合、ASR 命中、身份告警、欺骗触发
- 完成记录（2026-04-19）：
  - 已建立 `RansomwareStateMachine`，支持重命名、高熵写入、canary 与影子删除多信号聚合
  - 已建立 `AsrPolicyDomain`、`IdentityThreatDetector` 与 `DeceptionRegistry`
  - 已建立 `SpecializedDetectionEngine`，统一输出专项检测 findings 并保留 storyline_id
  - 已通过勒索聚合、ASR 命中、身份暴力破解与欺骗触发测试

### P16：Vuln Scan / Passive Discovery / AI Monitor

- 目标：扩展能力模块。
- 交付：
  - 软件清单 / CVE 匹配
  - 被动网络资产发现
  - AI 工具 / 模型完整性 / DLP 监控
- 依赖：P03、P04
- 实施分解：
  - 建立本地软件清单与 CVE 匹配器
  - 建立被动网络发现缓存与资产聚合
  - 建立 AI 应用风险监控、模型完整性与敏感数据外泄规则
- 验收：
  - 测试覆盖清单匹配、资产发现聚合与 AI 监控判定
- 完成记录（2026-04-19）：
  - 已建立 `VulnerabilityMatcher`，支持软件清单与 CVE 版本门槛匹配
  - 已建立 `PassiveDiscoveryCache`，支持网络资产的被动聚合与去重
  - 已建立 `AiMonitor`，覆盖 AI 工具使用、模型完整性与 DLP 外泄规则
  - 已通过清单匹配、资产发现聚合和 AI 监控判定测试

### P17：Response Executor / Quarantine / Kill

- 目标：响应执行器主线。
- 交付：
  - two-phase termination
  - quarantine
  - basic response audit
- 依赖：P04、P07
- 实施分解：
  - 建立响应执行器、两阶段终止状态机与审计记录
  - 建立文件隔离 vault 与恢复凭据
  - 建立响应动作结果模型
- 验收：
  - 测试覆盖 suspend→assess→kill、quarantine、审计落盘
- 完成记录（2026-04-19）：
  - 已建立 `ResponseExecutor`、`TerminationRequest` 与两阶段终止审计模型
  - 已建立 `ResponseAuditLog`，支持响应动作 JSONL 审计落盘
  - 已建立文件隔离执行与隔离凭据回填
  - 已通过 suspend→assess→kill、quarantine 与审计落盘测试

### P18：Block Decision / Network Isolate / Firewall

- 目标：预防性阻断和网络面控制。
- 交付：
  - block map
  - isolation / release
  - management-only / break-glass
  - firewall policy 层
- 依赖：P17
- 实施分解：
  - 建立 block decision map 与 TTL 语义
  - 建立网络隔离、release、management-only、break-glass 策略对象
  - 建立防火墙策略编排器
- 验收：
  - 测试覆盖阻断命中、隔离释放和 break-glass 审计
- 完成记录（2026-04-19）：
  - 已建立 `BlockDecisionMap`，支持 hash/pid/path/network 多目标与 TTL 语义
  - 已建立 `IsolationPolicy` 与 `FirewallPolicyOrchestrator`，覆盖 Full / ManagementOnly / BreakGlass
  - 已建立 containment 审计记录模型
  - 已通过阻断命中、隔离应用与 break-glass 审计测试

### P19：Registry / Filesystem Rollback / Forensics

- 目标：回滚与取证。
- 交付：
  - registry rollback
  - filesystem rollback
  - artifact bundle / evidence chain
- 依赖：P17
- 实施分解：
  - 建立注册表回滚计划器与文件系统回滚计划器
  - 建立证据链模型、artifact bundle、hash 证明
  - 建立取证采集规范到归档对象的转换
- 验收：
  - 测试覆盖回滚计划生成、artifact bundle 完整性、证据链串联
- 完成记录（2026-04-19）：
  - 已建立 `RegistryRollbackPlanner`、`FilesystemRollbackPlanner` 与 `RecoveryCoordinator`
  - 已建立 `EvidenceChain`，支持 artifact hash、前序 hash 与链式校验
  - 已建立取证采集到 artifact/evidence entry 的转换
  - 已通过回滚计划生成、文件恢复、artifact bundle 完整性和证据链串联测试

### P20：Remote Shell / Session Lock / Approval Queue

- 目标：高危动作与审批链。
- 交付：
  - remote shell
  - user session lock
  - pending approval queue
  - pre-approved playbook runtime
- 依赖：P17、P18、P19
- 实施分解：
  - 建立远程 shell 会话策略、命令审计和超时控制
  - 建立用户会话锁定动作与审批队列
  - 建立预签名 playbook 执行上下文
- 验收：
  - 测试覆盖审批排队、playbook 约束、remote shell 审计
- 完成记录（2026-04-19）：
  - 已建立 `ApprovalQueue`，支持高危请求排队与审批状态流转
  - 已建立 `RemoteShellRuntime`、`PreApprovedPlaybook` 与 `PlaybookRuntime`
  - 已建立 `SessionLockRuntime` 与统一高危动作审计记录
  - 已通过审批排队、remote shell 约束、playbook 执行与会话锁定审计测试

### P21：Self-Protection / Keys / Crash Exploit Analysis

- 目标：四层自保护与密钥体系。
- 交付：
  - self-protection manager
  - key derivation
  - cert lifecycle hooks
  - crash triage / exploit suspicion
- 依赖：P07、P17
- 实施分解：
  - 建立自保护状态机、关键资源保护名单与策略开关
  - 建立主密钥/派生密钥接口与证书生命周期 hook
  - 建立 crash triage 与 exploit suspicion 规则
- 验收：
  - 测试覆盖密钥派生、自保护策略和崩溃可疑性判定
- 完成记录（2026-04-19）：
  - 已建立 `SelfProtectionManager`，支持关键进程/文件保护名单、篡改计数与防护姿态切换
  - 已建立 `KeyDerivationService`，支持租户、Agent 与用途维度的派生密钥生成
  - 已建立 `CertificateLifecycleHooks`，覆盖证书签发、轮换、吊销与生命周期审计
  - 已建立 `CrashExploitAnalyzer`，支持崩溃 triage 与 exploit suspicion 规则判定
  - 已通过自保护策略、密钥派生、证书生命周期与崩溃可疑性测试

### P22：Comms / SignedCommand / ApprovalProof

- 目标：通信主线与命令校验。
- 交付：
  - EventStream / Heartbeat / UploadArtifact / PullUpdate
  - SignedServerCommand 验签
  - target_scope / command_id / approval proof 校验
- 依赖：P03、P04
- 实施分解：
  - 建立上行消息批处理与心跳模型
  - 建立命令验签器、scope 校验器、去重账本
  - 建立 approval proof 校验和命令执行前置检查
- 验收：
  - 测试覆盖签名校验、scope 违规、replay 拒绝、审批证明失败
- 完成记录（2026-04-19）：
  - 已在 `aegis-model` 建立 `EventBatch`、`UplinkMessage`、`DownlinkMessage`、`HeartbeatRequest/Response`、`ArtifactChunk`、`UpdateChunk` 等传输消息模型
  - 已建立 `ServerCommand` / `SignedServerCommand` / `TargetScope` 结构，覆盖 AGENT、TENANT、AGENT_SET、GLOBAL 作用域
  - 已建立 `TelemetryBatchBuilder`、`HeartbeatBuilder`、`CommandReplayLedger` 与 `CommandValidator`
  - 已实现签名命令验签、`target_scope` 校验、`command_id` 去重账本与审批证明校验
  - 已通过上行批处理、签名校验、scope 违规、replay 拒绝与审批证明失败测试

### P23：WAL / Forensic Journal / Emergency Audit Ring

- 目标：离线自治和审计持久化。
- 交付：
  - Telemetry WAL
  - Forensic Journal
  - Emergency Audit Ring
  - `PARTIAL` 完整性标记
- 依赖：P22
- 实施分解：
  - 建立 WAL 分段写入与回放
  - 建立 Forensic Journal 与 Emergency Audit Ring
  - 建立高水位降级与 `PARTIAL` 完整性标记
- 验收：
  - 测试覆盖 WAL 回放、满载降级和 `PARTIAL` 标记传播
- 完成记录（2026-04-19）：
  - 已建立 `TelemetryWal`，支持分段写入、顺序回放与压力感知摘要化
  - 已建立 `ForensicJournal`，覆盖 Evidence Zone 与 Action Log Zone 分区容量控制
  - 已建立 `EmergencyAuditRing` 与 `ForensicPersistenceCoordinator`，支持轻量响应审计保底落盘路径
  - 已建立高水位降级策略与 `TelemetryReplayResult` 的 `PARTIAL` 完整性传播
  - 已通过 WAL 回放、Journal 满载、审计环回退与 `PARTIAL` 标记传播测试

### P24：Upgrade / Migration / Canary Gate / Diagnose

- 目标：升级、灰度、诊断。
- 交付：
  - updater
  - schema/config migration
  - rollout gate evaluator
  - diagnose bundle
- 依赖：P02、P22、P23
- 实施分解：
  - 建立升级计划对象、回滚元数据与迁移执行器对接
  - 建立灰度 gate evaluator 与健康阈值判定
  - 建立 `--diagnose` 输出 bundle
- 验收：
  - 测试覆盖 gate 判定、升级计划、diagnose bundle 生成
- 完成记录（2026-04-19）：
  - 已建立 `UpgradePlanner` 与 `UpgradePlan`，覆盖升级步骤、schema/config 迁移判定与回滚元数据保留
  - 已建立 `RolloutGateEvaluator`，支持基于健康指标、WAL 压力与自保护姿态的 canary gate 判定
  - 已建立 `DiagnoseCollector` / `DiagnoseBundle`，输出连接、证书、Sensor、WAL、资源与自保护状态
  - 已接通 `aegis-agentd --diagnose` 输出路径，并验证 JSON 诊断包可生成
  - 已通过升级计划、灰度门控与诊断包生成测试

### P25：Container Host Agent / Sidecar Lite

- 目标：K8s 与容器模式。
- 交付：
  - 宿主机 Agent DaemonSet 方案
  - sidecar lite
  - 容器特定检测骨架
- 依赖：P09、P16、P22
- 实施分解：
  - 建立容器宿主机观测模型、K8s 元数据映射和 sidecar lite 契约
  - 建立容器特定检测事件与横移/逃逸基础规则
  - 建立 DaemonSet/sidecar 所需配置对象
- 验收：
  - 测试覆盖容器元数据映射、sidecar 契约和容器检测规则
- 完成记录（2026-04-19）：
  - 已建立 `ContainerMetadataMapper`，支持 `NormalizedEvent` 与 K8s 元数据的容器资产映射
  - 已建立 `DaemonSetHostAgentConfig` 与 `SidecarLiteContract`，覆盖宿主机 Agent / sidecar lite 关键约束校验
  - 已建立 `ContainerDetectionEngine`，覆盖容器横移与主机逃逸基础规则
  - 已通过容器元数据映射、sidecar 契约和容器检测规则测试

### P26：Runtime SDK / Cloud API Connector

- 目标：Serverless / Managed Runtime。
- 交付：
  - runtime sdk contracts
  - cloud api connector contracts
- 依赖：P22
- 实施分解：
  - 建立 runtime sdk 事件/心跳/策略契约
  - 建立 cloud API connector 的事件映射与缓冲接口
  - 建立最小接入示例与契约测试
- 验收：
  - 测试覆盖 SDK 事件编码、connector 映射和契约兼容性
- 完成记录（2026-04-19）：
  - 已建立 `RuntimeSdkEvent` / `RuntimeHeartbeat` / `RuntimePolicyContract` 与 `CloudApiConnectorContract` 等共享契约
  - 已建立 `RuntimeSdkEncoder`，支持运行时信号编码、契约版本校验与策略绑定校验
  - 已建立 `CloudApiConnector` 与 `CloudConnectorBuffer`，覆盖 Cloud API 记录映射与游标缓冲
  - 已建立 `crates/aegis-core/examples/runtime_sdk_connector.rs` 最小接入示例
  - 已通过 SDK 事件编码、connector 映射、契约兼容性与示例运行验证

### P27：QE / Pilot / Merge / Release

- 目标：整体验证、试点、合并主线。
- 交付：
  - 性能、安全、兼容性测试结果
  - pilot 记录
  - merge to main
  - 发布说明
- 依赖：P00-P26
- 实施分解：
  - 补齐测试矩阵、试点记录模板、发布说明模板
  - 汇总验收结果并完成分支合并
  - 推送 `main`
- 验收：
  - 所有工作包状态为 `done`
  - `main` 合并完成并推送
- 完成记录（2026-04-19）：
  - 已新增 `docs/qe/aegis-sensor-qe-matrix.md`，固化工作区回归、诊断模式与 Runtime SDK 示例验收结果
  - 已新增 `docs/pilot/aegis-sensor-pilot-record.md` 与 `docs/release/aegis-sensor-release-notes.md`
  - 已完成 `feat/sensor-implementation` 到 `main` 的合并
  - 下一步仅剩将 `main` 推送到 `origin/main`

## 3. 关键依赖链

- 主线一：P00 → P01 → P02 → P03 → P04 → P05 → P06
- 主线二：P07 → P08 / P09 / P10
- 检测主线：P11 → P12 → P13 → P14 → P15 → P16
- 响应主线：P17 → P18 → P19 → P20 → P21
- 通信主线：P22 → P23 → P24
- 云原生主线：P25 → P26
- 收口：P27

## 4. 完成定义

- P00-P27 每个工作包都必须同时满足：代码、测试、文档三类交付齐全。
- 任何源文档能力项如果只建立目录/接口、没有形成可验证行为，不得标记完成。
- P27 完成前，不得宣称“所有研发计划已完成”。
