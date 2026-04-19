# Aegis Agent 第三轮完整性收口计划

> 说明：
> - 本计划在隔离 worktree `/Users/lamba/github/aegis-sensor-dev` 的分支 `feat/agent-round3-closure` 中执行。
> - 本轮目标是把上一轮被归类为“外部工程”的两条主链里，当前仓库内实际上可以先完成的部分真正收口，不再接受“loopback/demo 可运行即视为完成”的口径。

## 1. 目标与边界

### 1.1 本轮目标

1. 将 agent 传输栈从“默认 loopback 驱动”升级为正式配置化运行时，并补齐 gRPC / WebSocket / Long-Polling / Domain Fronting 四类真实传输驱动接线。
2. 将 WAL / Forensic Journal / 命令去重账本所依赖的密钥体系从“进程内 root secret + HKDF”升级为正式主密钥管理、回滚保护与敏感内存强化链路。
3. 重新审计 `docs/技术方案/sensor-final技术解决方案.md` 与 `docs/architecture/aegis-sensor-architecture.md` 中 agent 侧仍未满足的能力项，直到仓库内可落地事项不再残留为止。

### 1.2 本轮不谎称完成的事项

下列事项若仍需额外签名驱动、系统扩展证书、专用硬件或跨仓网关配套，则只能保留为后续工程，不在本轮以“已完成”名义落入状态文档：

- Windows ETW / Minifilter / WFP / CmCallback 的真实驱动交付
- Linux eBPF / LSM / fanotify 的真实内核侧交付
- macOS ESF / Network Extension / System Extension 的真实系统扩展交付
- 依赖组织级 PKI、独立 CA、在线吊销基础设施的正式证书发放体系

本轮允许先在当前仓库把 agent 侧运行时、配置、状态暴露、密钥存储契约、降级语义和测试闭环补齐。

## 2. 当前问题重述

### 2.1 传输栈仍不满足文档承诺

当前代码与文档要求存在以下偏差：

1. `aegis-agentd` 与 `orchestrator` 启动路径仍直接构造 `CommunicationRuntime::with_loopback_drivers(...)`，主运行时没有从配置加载真实传输驱动。
2. `--diagnose` 返回的通信状态仍来自 loopback 快照，而不是正式 transport runtime。
3. 当前没有真实的 gRPC / WebSocket / Long-Polling / Domain Fronting 客户端驱动，也没有 transport 级配置项、开关、探活参数和受限降级语义。

### 2.2 密钥与回滚保护仍不满足文档承诺

当前代码与文档要求存在以下偏差：

1. `KeyDerivationService` 仅基于传入 root secret 做 HKDF 派生，没有主密钥 provider、OS keystore/硬件绑定分级和能力暴露。
2. `TelemetryWal` / `ForensicJournal` 直接消费进程内派生密钥，没有“主密钥 -> tiered key material”的正式接线。
3. `CommandReplayLedger` 只有持久化去重，没有回滚保护 floor，也没有“无 TPM 时退化到 OS 安全存储 + 文件时间戳交叉校验”的状态表达。
4. 敏感明文 buffer 没有 `zeroize` / `mlock` 最佳努力清理，和文档中的“短时解封、用后清理”存在差距。

## 3. 本轮工作包

### C05：传输栈正式化

**目标**

- 引入正式的 `communication` 配置模型与 runtime builder。
- 将 gRPC / WebSocket / Long-Polling / Domain Fronting 四类传输驱动纳入 `CommunicationRuntime`，结束默认 loopback 启动路径。
- 让 `health-reporter`、`telemetry-drain`、`comms-rx`、`--diagnose` 全部读取同一份真实 transport runtime 状态。

**代码范围**

- `Cargo.toml`
- `Cargo.lock`
- `crates/aegis-core/Cargo.toml`
- `crates/aegis-core/src/config.rs`
- `crates/aegis-core/src/comms.rs`
- `crates/aegis-core/src/orchestrator.rs`
- `crates/aegis-agentd/src/main.rs`
- 传输相关测试与必要的 proto/build 文件

**交付**

- `AgentConfig` 新增通信配置与各通道参数
- transport runtime builder 按配置注册真实驱动，只有显式开发模式才允许 loopback
- 四类驱动具备 uplink / heartbeat / downlink / probe 基本能力
- 诊断输出明确展示启用状态、当前活跃通道、回退链与降级状态

**验收**

- 单测或集成测试覆盖：
  - gRPC 驱动可收发上/下行消息
  - gRPC 不可用时可回退到 WebSocket / Long-Polling / Domain Fronting
  - `probe_upgrade` 能将运行时提升回更优通道
  - agent 启动路径不再硬编码 loopback

**完成记录（2026-04-19）**

- 已通过提交 `7961edd` 完成代码收口：
  - 新增 `transport_drivers.rs` 与 `build.rs`，正式生成并接入 transport proto
  - `CommunicationRuntime::from_config(...)` 已在 orchestrator 与 `--diagnose` 路径接线
  - 已补齐 gRPC / WebSocket / Long-Polling / Domain Fronting 四类真实驱动
  - HTTP / WebSocket 路径不再使用 ad-hoc JSON frame，而是统一使用 protobuf transport bundle
  - `telemetry-drain` 已恢复正常批量发送，而非单事件伪 batch
  - 高优先级告警已具备独立上行链路，低/普通告警会归并进常规遥测批次
  - `BatchAck` 与 `FlowControlHint` 已落到 runtime 行为，不再只停留在日志打印
- 已通过以下验证：
  - `cargo test --workspace`
  - `cargo run -p aegis-agentd -- --diagnose`

**本工作包完成后仍明确保留的差距**

- 当前 `sequence_id` 仍在本地发送时推进，而不是在服务端 `BatchAck::Accepted` 后推进
- `TelemetryWal` / `ForensicJournal` 仍未与传输 runtime 的 ACK / retry / replay 正式接线
- `upload_artifact` / `pull_update` 目前已具备 proto 与测试服务，但尚未进入 agent 运行时闭环

以上三项不再归入 C05，留待 C06 完成后重新审计，必要时拆出新工作包。

### C06：密钥保护、回滚保护与敏感内存强化

**目标**

- 建立主密钥 provider 与 tiered key material 正式链路。
- 将 WAL / Journal / 命令回滚保护接入统一密钥与 floor 存储。
- 对敏感 buffer 增加 `zeroize` / `mlock` 最佳努力强化，并在状态面暴露降级信息。

**代码范围**

- `Cargo.toml`
- `Cargo.lock`
- `crates/aegis-core/Cargo.toml`
- `crates/aegis-core/src/config.rs`
- `crates/aegis-core/src/self_protection.rs`
- `crates/aegis-core/src/wal.rs`
- `crates/aegis-core/src/comms.rs`
- `crates/aegis-core/src/orchestrator.rs`
- `crates/aegis-agentd/src/main.rs`
- 相关测试文件

**交付**

- 主密钥 provider / keystore tier / availability descriptor
- `TelemetryWal` / `ForensicJournal` 不再直接依赖裸 root secret，而是经正式 provider 派生
- replay ledger 写入并校验 rollback floor；无硬件锚定时进入受控降级
- 关键明文 buffer 使用后清理，敏感内存尝试锁页
- `--diagnose` 输出密钥保护层级、降级状态与 rollback floor 状态

**验收**

- 单测或集成测试覆盖：
  - 主密钥 provider 生成稳定且可轮换的 tiered key material
  - WAL / Journal 可用 provider 导出的 material 正常加解密
  - rollback floor 能拒绝回滚后的旧命令
  - 降级环境能被显式标记并写入状态输出

**完成记录（2026-04-19）**

- 已通过提交 `dccb1ce` 完成代码收口：
  - 为 `AgentConfig` 新增 `security` 配置，统一控制 OS 凭据存储、文件后备与敏感内存锁定策略
  - `KeyDerivationService` 已接入正式主密钥加载路径，支持 OS Credential Store 优先、文件后备降级与状态输出
  - `DerivedKeyMaterial` 已增加 `zeroize` 用后清理；敏感主密钥缓冲新增 `mlock/munlock` 最佳努力锁页
  - `CommandReplayLedger` 已增加 `issued_at` rollback floor、持久化锚点与交叉校验状态
  - `--diagnose` 已新增 `key_protection` 输出，并改为读取真实 WAL / rollback 状态，不再使用静态占位值
  - `aegis-agentd` 的 `self_protection_posture` 已改为基于当前密钥/回滚降级状态推导
- 已通过以下验证：
  - `cargo fmt --all`
  - `cargo test --workspace`
  - `AEGIS_STATE_ROOT=$(mktemp -d) cargo run -p aegis-agentd -- --diagnose`
- 本轮诊断快照已能显示以下真实字段：
  - `key_protection.active_tier`
  - `key_protection.memory_lock_enabled`
  - `key_protection.rollback_anchor`
  - `key_protection.rollback_cross_check_ok`
  - `wal.key_version`
  - `self_protection_posture`

**本工作包完成后仍明确保留的差距**

- `TelemetryWal` / `ForensicJournal` 仍未进入 ACK-gated retry / replay 闭环
- `upload_artifact` / `pull_update` 虽已有 proto/driver/test service，但尚未纳入 agent 运行时主任务闭环
- TPM / Secure Enclave / 正式硬件绑定仍属于外部工程，本轮仅完成仓库内受控降级与状态诚实化

### C07：WAL / Journal ACK-gated replay 正式闭环

**目标**

- 将 `TelemetryWal` / `ForensicJournal` 从“可独立读写”升级为“受 ACK 驱动的传输重放层”。
- 让 `sequence_id`、重放窗口、失败重试与完整性标记遵循服务端 `BatchAck::Accepted` 语义，而不是本地发送即前推。

**代码范围**

- `crates/aegis-core/src/comms.rs`
- `crates/aegis-core/src/orchestrator.rs`
- `crates/aegis-core/src/wal.rs`
- `crates/aegis-agentd/src/main.rs`
- 相关测试与状态文档

**交付**

- `sequence_id` 仅在服务端接受后推进
- 正常遥测、告警与重放队列共享统一 ACK / retry 语义
- WAL 回放结果与 `TelemetryIntegrity`、重试状态、未确认窗口在诊断面可见
- `ForensicJournal` 与高危动作审计具备正式落盘与回放关联

**验收**

- 单测或集成测试覆盖：
  - 重试场景不会重复前推 `sequence_id`
  - `BatchAck::Accepted` 后 WAL 项会被确认并退出待重放窗口
  - 未确认或拒绝的批次会保留在重放队列
  - 诊断面能展示待确认窗口与 replay 状态

**完成记录（2026-04-19）**

- 已通过提交 `3e34dcc` 完成代码收口：
  - 新增 `PendingBatchStore` 与 `UplinkReplayRuntime`，把正常遥测、告警与重试队列统一收敛到 ACK-gated replay 窗口
  - `sequence_id` 改为仅在 `BatchAck::Accepted` 后前推；拒绝或未确认批次保留在待重放窗口，并沿用原 `sequence_id` 重试
  - `alert_uplink_high_task`、`telemetry_drain_task` 不再直接发送上行批次，而是统一写入 replay runtime，再由 `uplink_replay_task` 按窗口状态与流控提示发送
  - `response_executor_task` 已把高危响应审计同步写入 `ForensicJournal`，使响应动作与 replay 状态进入同一条本地取证链
  - `--diagnose` / runtime snapshot 已新增 `replay` 输出，真实展示 `last_acked_sequence_id`、待确认批次数、in-flight 序号、重试计数与最近错误
  - 修复 `telemetry_drain_task` 首次 tick 立即触发导致的批量切分时序缺陷，确保 `max_batch_events` 与 ACK 前沿语义一致
- 已通过以下验证：
  - `cargo fmt --all`
  - `cargo test --workspace`
  - `AEGIS_STATE_ROOT=$(mktemp -d) cargo run -p aegis-agentd -- --diagnose`
- 本轮诊断快照已能显示以下真实字段：
  - `wal.telemetry_segments`
  - `wal.completeness`
  - `key_protection.rollback_anchor`
  - `replay.last_acked_sequence_id`
  - `replay.pending_batches`
  - `replay.in_flight_sequence_id`

**本工作包完成后仍明确保留的差距**

- `upload_artifact` / `pull_update` 虽已有 proto/driver/test service，但尚未纳入 agent / updater 主运行时闭环
- TPM / Secure Enclave / 正式硬件绑定仍属于外部工程，本轮仅完成仓库内受控降级与状态诚实化

### C08：升级产物传输与运行时更新闭环

**目标**

- 将 `upload_artifact` / `pull_update` 从 proto / 驱动测试升级为 agent 运行时真实闭环。
- 让 updater、runtime state、诊断面和控制平面传输状态共享同一条升级主链。

**代码范围**

- `crates/aegis-core/src/orchestrator.rs`
- `crates/aegis-core/src/transport_drivers.rs`
- `crates/aegis-core/src/upgrade.rs`
- `crates/aegis-updater/src/main.rs`
- `crates/aegis-agentd/src/main.rs`
- 相关测试与状态文档

**交付**

- 运行时可正式拉取 update manifest / artifact / rollback artifact
- updater 状态快照与 `--diagnose` 输出真实同步到当前升级阶段
- 失败重试、校验失败、rollback artifact 缺失等错误有明确状态面

**验收**

- 单测或集成测试覆盖：
  - update transport 能拉取 manifest 与 artifact
  - 校验失败时会进入受控拒绝状态
  - rollback artifact 缺失会阻断高风险升级
  - `aegis-updater` / `aegis-agentd --diagnose` 输出一致的升级状态

**完成记录（2026-04-19）**

- 已通过提交 `99ef1a0` 完成代码收口：
  - `health-reporter` 现在会消费 heartbeat 返回的升级公告，并将 `pending_update_ids` / `config_changed` 正式写入共享 `update-state.json`
  - 新增 `update-manager` 主任务，负责真实执行 `pull_update`、分段组装 manifest / artifact / rollback artifact、签名与 digest 校验、兼容性规划与阶段状态持久化
  - `upload_artifact` 已不再停留在 proto / 驱动测试层，而是作为升级状态回执通道，由运行时把终态 `update-state` 回传到控制平面
  - `aegis-updater` 不再伪造本地 staged 包；现在仅消费真实 staged manifest / artifact / rollback，并把 `Verifying` / `Ready` / `Rejected` 状态写回同一份快照
  - `aegis-agentd --diagnose` 现在会直接读取正式 `update-state.json`，输出 `phase`、`pending_update_ids`、`transport_channel`、staged 路径、重试计数、最近错误与最近成功时间
  - 新增运行时测试覆盖升级 Ready/Failed 两条主路径，明确验证 rollback artifact 缺失会阻断升级
- 已通过以下验证：
  - `cargo fmt --all`
  - `cargo test --workspace`
  - `AEGIS_STATE_ROOT=$(mktemp -d) cargo run -p aegis-agentd -- --diagnose`
- 本工作包完成后，第三轮在当前仓库内可闭合的 agent 完整性缺口已全部收口

**本工作包完成后仍明确保留的边界**

- 三平台真实内核/系统集成仍属于仓库外部工程
- TPM / Secure Enclave / 正式硬件绑定仍属于外部工程，本轮仅完成仓库内受控降级与状态诚实化

## 4. 执行与提交要求

每个工作包按以下节奏执行：

1. 代码与测试提交一次（中文提交）
2. 相应文档更新再提交一次（中文提交）

本轮统一验证命令：

```bash
cargo fmt --all
cargo test --workspace
cargo run -p aegis-agentd -- --diagnose
```

传输栈工作包完成后，额外验证：

```bash
cargo test --workspace comms
```

## 5. 完成定义

只有同时满足以下条件，才能认为本轮完成：

- `C05-C08` 均已完成代码、测试、文档与中文提交
- `docs/plan/aegis-sensor-rd-plan-audit.md` 的本轮审计结论不再把仓库内可落地项留在“外部工程”
- `docs/plan/aegis-sensor-rd-status.md` 与本轮实际状态一致
- 重新执行第一步审计后，不再发现新的仓库内 agent 完整性缺口
- 分支合并到 `main` 并推送
