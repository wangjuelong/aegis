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

### P03：统一事件模型与 Lineage 模型

- 目标：定义 `NormalizedEvent`、`TelemetryEvent`、`Storyline`、lineage 计数器与 checkpoint 模型。
- 交付：
  - 统一事件结构
  - ECS/OCSF 兼容字段骨架
  - lineage checkpoint 类型
- 依赖：P01

### P04：Core Orchestrator 与通道拓扑

- 目标：建立主事件循环、任务编排、channel 拓扑与 graceful shutdown。
- 交付：
  - tokio runtime
  - 核心 channel 连接
  - health / config / comms / response 任务入口
- 依赖：P01、P02、P03

### P05：Ring Buffer / Spill / Dispatch 基础实现

- 目标：建立用户态 4-lane 消费器、Spill、背压、原始事件到 `NormalizedEvent` 的转换骨架。
- 交付：
  - lane 抽象
  - spill 存储布局
  - `SensorDispatch`
- 依赖：P03、P04

### P06：ProcessTree / Hashing / AdaptiveWhitelist / Health

- 目标：建立核心 runtime 辅助能力。
- 交付：
  - `ProcessTree`
  - 文件哈希策略
  - `AdaptiveWhitelist`
  - `HealthReporter`
- 依赖：P04、P05

### P07：平台 Trait 细化与 Mock Harness

- 目标：冻结 `PlatformSensor`、`PlatformResponse`、`PreemptiveBlock`、`KernelIntegrity`、`PlatformProtection` 的 mock 可执行契约。
- 交付：
  - trait 定义
  - mock 实现
  - 契约测试
- 依赖：P01、P03

### P08：Windows 平台采集基线

- 目标：Windows 传感器与保护路径代码骨架。
- 交付：
  - ETW / Ps / Ob / Minifilter / WFP / CmCallback 适配层
  - AMSI / Direct Syscall / IPC / DLL / VSS / Device Control 接口骨架
- 依赖：P07

### P09：Linux 平台采集基线

- 目标：Linux eBPF/LSM/fanotify/container-aware 代码骨架。
- 交付：
  - eBPF loader 接口
  - maps/ringbuf 抽象
  - 4 级降级路径骨架
- 依赖：P07

### P10：macOS 平台采集基线

- 目标：ESF / Network Extension / System Extension 代码骨架。
- 交付：
  - macOS 平台接口与授权流程抽象
- 依赖：P07

### P11：IOC / Rule VM / Temporal

- 目标：Stage 0-2 核心实现。
- 交付：
  - Tiered Bloom + Cuckoo
  - Rule VM
  - Temporal state buffer
- 依赖：P03、P04、P05

### P12：YARA / Script Decode / AMSI Interlock

- 目标：Stage 2.5 与 Stage 3。
- 交付：
  - YARA 任务队列
  - 脚本多层解混淆
  - AMSI fast-path 联动
- 依赖：P11

### P13：ML / OOD / Behavioral Models

- 目标：Stage 4 模型框架。
- 交付：
  - ONNX Runtime 集成
  - Static / Behavioral / Script 三模型接口
  - OOD 判定骨架
- 依赖：P11

### P14：Correlation / Storyline / Threat Feedback

- 目标：Stage 5 与反馈闭环。
- 交付：
  - 分片关联器
  - Storyline engine
  - threat feedback / adaptive whitelist 回灌
- 依赖：P03、P11、P13

### P15：专项检测能力

- 目标：勒索软件、ASR、Identity、Deception。
- 交付：
  - 勒索专项状态机
  - ASR 规则域
  - 身份威胁规则
  - 欺骗对象模型
- 依赖：P11、P12、P14

### P16：Vuln Scan / Passive Discovery / AI Monitor

- 目标：扩展能力模块。
- 交付：
  - 软件清单 / CVE 匹配
  - 被动网络资产发现
  - AI 工具 / 模型完整性 / DLP 监控
- 依赖：P03、P04

### P17：Response Executor / Quarantine / Kill

- 目标：响应执行器主线。
- 交付：
  - two-phase termination
  - quarantine
  - basic response audit
- 依赖：P04、P07

### P18：Block Decision / Network Isolate / Firewall

- 目标：预防性阻断和网络面控制。
- 交付：
  - block map
  - isolation / release
  - management-only / break-glass
  - firewall policy 层
- 依赖：P17

### P19：Registry / Filesystem Rollback / Forensics

- 目标：回滚与取证。
- 交付：
  - registry rollback
  - filesystem rollback
  - artifact bundle / evidence chain
- 依赖：P17

### P20：Remote Shell / Session Lock / Approval Queue

- 目标：高危动作与审批链。
- 交付：
  - remote shell
  - user session lock
  - pending approval queue
  - pre-approved playbook runtime
- 依赖：P17、P18、P19

### P21：Self-Protection / Keys / Crash Exploit Analysis

- 目标：四层自保护与密钥体系。
- 交付：
  - self-protection manager
  - key derivation
  - cert lifecycle hooks
  - crash triage / exploit suspicion
- 依赖：P07、P17

### P22：Comms / SignedCommand / ApprovalProof

- 目标：通信主线与命令校验。
- 交付：
  - EventStream / Heartbeat / UploadArtifact / PullUpdate
  - SignedServerCommand 验签
  - target_scope / command_id / approval proof 校验
- 依赖：P03、P04

### P23：WAL / Forensic Journal / Emergency Audit Ring

- 目标：离线自治和审计持久化。
- 交付：
  - Telemetry WAL
  - Forensic Journal
  - Emergency Audit Ring
  - `PARTIAL` 完整性标记
- 依赖：P22

### P24：Upgrade / Migration / Canary Gate / Diagnose

- 目标：升级、灰度、诊断。
- 交付：
  - updater
  - schema/config migration
  - rollout gate evaluator
  - diagnose bundle
- 依赖：P02、P22、P23

### P25：Container Host Agent / Sidecar Lite

- 目标：K8s 与容器模式。
- 交付：
  - 宿主机 Agent DaemonSet 方案
  - sidecar lite
  - 容器特定检测骨架
- 依赖：P09、P16、P22

### P26：Runtime SDK / Cloud API Connector

- 目标：Serverless / Managed Runtime。
- 交付：
  - runtime sdk contracts
  - cloud api connector contracts
- 依赖：P22

### P27：QE / Pilot / Merge / Release

- 目标：整体验证、试点、合并主线。
- 交付：
  - 性能、安全、兼容性测试结果
  - pilot 记录
  - merge to main
  - 发布说明
- 依赖：P00-P26

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
