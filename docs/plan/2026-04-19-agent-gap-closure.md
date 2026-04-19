# Aegis Agent 缺口收口实施计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.
>
> 说明：
> - 本计划基于 2026-04-19 对 `docs/技术方案/sensor-final技术解决方案.md` 与 `docs/architecture/aegis-sensor-architecture.md` 的符合性审查。
> - 本计划用于收口“agent 相关能力仍停留在契约/骨架/占位层”的问题。
> - 本计划在既有隔离 worktree `/Users/lamba/github/aegis-sensor-dev` 的新分支 `feat/agent-gap-closure` 中执行。

**Goal:** 将 agent 仍处于骨架/占位状态的关键能力收口为可执行、可测试、可诊断、可发布的实现基线，并同步修正文档与状态基线。

**Architecture:** 本轮不重写既有 Rust workspace，而是在 `aegis-core`、`aegis-platform`、`aegis-agentd`、`aegis-watchdog`、`aegis-updater` 上增量补齐运行时能力。收口顺序遵循“高危操作与审计面 -> 通信/WAL/诊断面 -> 插件/热更新/看门狗面 -> 容器与 serverless 接入面 -> 平台执行基线”。

**Tech Stack:** Rust workspace、Tokio、rusqlite、serde/serde_json、ed25519、BLAKE3/SHA-256；按需引入 AEAD、WASM runtime、HTTP/WebSocket/gRPC 客户端能力。

---

## 1. 审计基线

### 1.1 本轮必须收口的关键缺口

1. 平台层仍是 stub/no-op，尤其采集、响应、取证、阻断与完整性检查未形成可执行基线。
2. 高危操作仅有审批对象和字符串前缀校验，缺少会话约束、并发控制、时窗控制、持久化审计与录屏记录。
3. 通信子系统只有消息构造/验签，无通道状态机、回退链、链路健康、诊断暴露。
4. WAL 与恢复子系统缺少加密、校验、密钥分级、证据链增强与故障恢复联动。
5. 插件宿主、watchdog、updater 仍是 skeleton，热更新链路不闭环。
6. 容器/Sidecar/Serverless 只有契约对象，缺少运行态执行器。
7. `--diagnose` 输出仍然是静态拼装，未覆盖文档要求的关键健康字段。

### 1.2 本轮完成定义

- 每个工作包都必须同时交付：
  - 代码
  - 单元测试或集成测试
  - 对应研发/状态/验证文档
- 每个工作包都必须完成两次提交：
  - 第一次：代码与测试
  - 第二次：文档更新
- 所有工作包完成后：
  - `cargo fmt --all`
  - `cargo test --workspace`
  - 必要的示例/二进制自检
  - 合并至 `main`
  - 推送 `origin/main`

## 2. 工作包清单

### G00：缺口审计与执行基线重建

**目标**

- 建立新的 gap 收口计划，替换“已全部覆盖、无妥协”的失真状态判断。

**Files**

- Create: `docs/plan/2026-04-19-agent-gap-closure.md`
- Modify: `docs/plan/aegis-sensor-rd-status.md`
- Modify: `docs/plan/aegis-sensor-rd-plan-audit.md`

**交付**

- 新的缺口收口计划文档
- 新的状态表与审计结论

**验收**

- 文档明确列出工作包、代码范围、完成定义、验证命令
- 状态文档不再宣称“无功能缺失、无设计妥协”

**完成记录（2026-04-19）**

- 已新增本计划，明确 G00-G06 的收口顺序、代码范围、验证命令与提交约束
- 已同步修正 `docs/plan/aegis-sensor-rd-status.md` 与 `docs/plan/aegis-sensor-rd-plan-audit.md`
- 已将“agent 已完整实现”的失真判断回退为按工作包推进的真实状态基线

### G01：高危操作执行链路加固

**目标**

- 将审批队列、Remote Shell、Playbook、Session Lock 从“内存对象 + 审计记录”提升为可执行运行时。

**Files**

- Modify: `crates/aegis-core/src/high_risk_ops.rs`
- Modify: `crates/aegis-core/src/comms.rs`
- Modify: `crates/aegis-model/src/lib.rs`
- Test: `crates/aegis-core/src/high_risk_ops.rs`
- Modify: `docs/plan/aegis-sensor-rd-status.md`
- Modify: `docs/plan/aegis-sensor-rd-plan-detailed.md`

**交付**

- 持久化审批存储
- Remote Shell 会话管理器：TTL、并发、工作时间窗、黑白名单
- asciicast 风格审计记录
- 会话锁定执行器与可撤销状态

**验收**

- 测试覆盖审批持久化、超时失效、单端点单 session、命令黑白名单、审计回放

**完成记录（2026-04-19）**

- 已将审批队列升级为支持内存/SQLite 双后端的持久化实现，补齐审批人去重、TTL、过期状态与重载恢复
- 已为 Remote Shell 增加单端点并发限制、工作时间窗、命令黑白名单、会话 TTL 与 asciicast 风格审计输出
- 已为 Playbook 与 Session Lock 增加运行时状态、次数限制、释放路径与对应测试
- 已通过 `cargo fmt --all` 与 `cargo test --workspace`

### G02：通信回退运行时与诊断扩展

**目标**

- 建立 agent 通信运行时，收口 gRPC/WebSocket/Long-Polling/Domain Fronting 四态回退与健康暴露。

**Files**

- Modify: `crates/aegis-core/src/comms.rs`
- Modify: `crates/aegis-core/src/orchestrator.rs`
- Modify: `crates/aegis-core/src/health.rs`
- Modify: `crates/aegis-core/src/upgrade.rs`
- Modify: `crates/aegis-model/src/lib.rs`
- Modify: `crates/aegis-agentd/src/main.rs`
- Test: `crates/aegis-core/src/comms.rs`
- Test: `crates/aegis-core/src/orchestrator.rs`
- Modify: `docs/qe/aegis-sensor-qe-matrix.md`
- Modify: `docs/plan/aegis-sensor-rd-status.md`

**交付**

- 通道状态机
- 驱动抽象与回退策略
- 健康快照中的通信字段
- `--diagnose` 中的通信/篡改/插件健康字段

**验收**

- 测试覆盖失败 3 次后的自动降级、后台恢复升级、诊断字段输出

**完成记录（2026-04-19）**

- 已建立 `CommunicationRuntime`，覆盖 `gRPC -> WebSocket -> Long-Polling -> Domain Fronting` 四级回退顺序、失败阈值降级与恢复探测升级
- 已将通信运行时接入 `orchestrator` 的 telemetry/heartbeat 链路，并新增 `comms-link-manager` 后台任务
- 已扩展 `AgentHealth`、`HeartbeatRequest` 与 `DiagnoseBundle`，补齐 `communication_channel`、篡改信号与 `plugin_status` 字段
- 已通过 `cargo fmt --all`、`cargo test --workspace` 与 `cargo run -p aegis-agentd -- --diagnose`

### G03：WAL 加密、恢复与证据链加固

**目标**

- 让 WAL、Forensic Journal、Rollback/Evidence 不再停留在明文 JSONL 与简单复制。

**Files**

- Modify: `crates/aegis-core/src/wal.rs`
- Modify: `crates/aegis-core/src/recovery.rs`
- Modify: `crates/aegis-core/src/self_protection.rs`
- Modify: `crates/aegis-core/src/upgrade.rs`
- Test: `crates/aegis-core/src/wal.rs`
- Test: `crates/aegis-core/src/recovery.rs`
- Modify: `docs/qe/aegis-sensor-qe-matrix.md`
- Modify: `docs/plan/aegis-sensor-rd-status.md`

**交付**

- WAL segment 加密/校验
- 密钥派生分级接口
- 回滚清单与证据链增强
- 诊断输出中的 WAL 完整性与加密状态

**验收**

- 测试覆盖密钥轮换、加密 segment 回放、损坏 segment 隔离、证据链连续性

**完成记录（2026-04-19）**

- 已为 Telemetry WAL 与 Forensic Journal 引入分级密钥派生接口和 `XChaCha20-Poly1305` 加密/CRC 校验
- 已将损坏 WAL segment 自动隔离到 quarantine 目录，并在诊断输出中暴露 `encrypted`、`key_version`、`quarantined_segments`
- 已增强文件回滚清单校验，新增 snapshot 篡改拒绝恢复与证据链篡改检测测试
- 已通过 `cargo fmt --all`、`cargo test --workspace` 与 `cargo run -p aegis-agentd -- --diagnose`

### G04：插件宿主、Watchdog 与 Updater 热更新链路

**目标**

- 将插件、watchdog、updater 从 skeleton 收口为真实运行链路。

**Files**

- Modify: `crates/aegis-core/src/upgrade.rs`
- Create or Modify: `crates/aegis-core/src/plugin_host.rs`
- Modify: `crates/aegis-core/src/lib.rs`
- Modify: `crates/aegis-watchdog/src/main.rs`
- Modify: `crates/aegis-updater/src/main.rs`
- Modify: `crates/aegis-agentd/src/main.rs`
- Modify: `crates/aegis-model/src/lib.rs`
- Test: `crates/aegis-core/src/plugin_host.rs`
- Test: `crates/aegis-core/src/upgrade.rs`
- Modify: `docs/release/aegis-sensor-release-notes.md`
- Modify: `docs/plan/aegis-sensor-rd-status.md`

**交付**

- WASM 插件宿主与健康状态
- 插件崩溃计数/禁用逻辑
- 升级清单验签与回滚工件校验
- watchdog/agent 双向心跳与异常上报

**验收**

- 测试覆盖插件超时/崩溃、热更新验签失败、watchdog 失联检测

**完成记录（2026-04-19）**

- 已新增 `PluginHost` 与 `PluginManifest`，实现 `.wasm` 模块校验、崩溃预算、超时/崩溃状态与自动禁用逻辑
- 已建立 `HotUpdateManifestVerifier`，补齐升级清单验签、artifact 哈希校验与 rollback artifact 校验
- 已建立 `WatchdogLinkMonitor` 与 agent/watchdog 双向心跳模型，并在 `watchdog` 二进制中实跑监测链路
- 已通过 `cargo fmt --all`、`cargo test --workspace`、`cargo run -p aegis-agentd -- --diagnose`、`cargo run -p aegis-watchdog`、`cargo run -p aegis-updater`

### G05：容器、Sidecar 与 Serverless 运行时接入

**目标**

- 将容器/sidecar/serverless 从“契约对象”提升为运行态组件。

**Files**

- Modify: `crates/aegis-core/src/container_mode.rs`
- Modify: `crates/aegis-core/src/runtime_sdk.rs`
- Modify: `crates/aegis-core/src/orchestrator.rs`
- Modify: `crates/aegis-model/src/lib.rs`
- Test: `crates/aegis-core/src/container_mode.rs`
- Test: `crates/aegis-core/src/runtime_sdk.rs`
- Modify: `docs/pilot/aegis-sensor-pilot-record.md`
- Modify: `docs/plan/aegis-sensor-rd-status.md`

**交付**

- Sidecar 到宿主 agent 的本地控制面
- Runtime SDK 事件发射器
- Cloud API connector runner
- 运行时 heartbeat 与诊断映射

**验收**

- 测试覆盖 unix socket/本地消息转发、connector flush/cursor、runtime heartbeat

**完成记录（2026-04-19）**

- 已新增 `SidecarControlMessage` 与 `SidecarLocalControlPlane`，补齐 sidecar 到宿主 agent 的 unix socket 本地控制面与消息转发
- 已新增 `RuntimeEventEmitter`、`CloudConnectorRunner` 与 `RuntimeBridgeStatus`，补齐 runtime heartbeat、connector flush/cursor 与 bridge 诊断快照
- 已将 `runtime-bridge` 纳入 `Orchestrator` 拓扑，并将 `runtime_bridge` 映射接入 `aegis-agentd -- --diagnose`
- 已通过 `cargo fmt --all`、`cargo test --workspace`、`cargo run -p aegis-core --example runtime_sdk_connector`、`cargo run -p aegis-agentd -- --diagnose`

### G06：平台执行基线收口

**目标**

- 将平台层从纯 no-op 提升到“有状态、可审计、可回放”的执行基线。

**Files**

- Modify: `crates/aegis-platform/src/windows.rs`
- Modify: `crates/aegis-platform/src/linux.rs`
- Modify: `crates/aegis-platform/src/macos.rs`
- Modify: `crates/aegis-platform/src/traits.rs`
- Test: `crates/aegis-platform/src/windows.rs`
- Test: `crates/aegis-platform/src/linux.rs`
- Test: `crates/aegis-platform/src/macos.rs`
- Modify: `docs/qe/aegis-sensor-qe-matrix.md`
- Modify: `docs/plan/aegis-sensor-rd-status.md`

**交付**

- 平台动作状态、阻断 TTL 表、隔离/释放状态、隔离区/取证工件落地
- provider 健康状态与完整性快照
- 与 `ResponseExecutor` / `RecoveryCoordinator` 的真实联动

**验收**

- 测试覆盖文件隔离、取证工件、阻断 TTL、健康快照与响应执行链

**完成记录（2026-04-19）**

- 已在 `aegis-platform` 建立 `PlatformExecutionSnapshot`、`PlatformHealthSnapshot` 与 `BlockLease`，统一平台动作状态、阻断 TTL 与健康快照结构
- 已将 Windows/Linux/macOS 平台从纯 no-op 提升为有状态执行基线，补齐隔离区、取证工件、隔离/释放与阻断状态落地
- 已新增 `ResponseExecutor -> WindowsPlatform` 与 `RecoveryCoordinator -> LinuxPlatform` 的真实联动测试，验证 core 执行链已接入平台状态快照
- 已通过 `cargo fmt --all`、`cargo test --workspace`、`cargo run -p aegis-agentd -- --diagnose`、`cargo run -p aegis-core --example runtime_sdk_connector`

## 3. 执行顺序

1. G00：文档基线
2. G01：高危操作
3. G02：通信与诊断
4. G03：WAL/恢复
5. G04：插件/热更新/watchdog
6. G05：容器/serverless
7. G06：平台执行基线

## 4. 统一验证命令

```bash
cargo fmt --all
cargo test --workspace
cargo run -p aegis-agentd -- --diagnose
cargo run -p aegis-core --example runtime_sdk_connector
```

## 5. 交付约束

- 所有 git 提交信息统一使用中文。
- 合并前必须保持 worktree 干净。
- 根工作区 `/Users/lamba/github/aegis` 上现有未提交改动不得被带入本次开发。
