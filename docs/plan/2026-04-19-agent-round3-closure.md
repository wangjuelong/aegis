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

- `C05-C06` 均已完成代码、测试、文档与中文提交
- `docs/plan/aegis-sensor-rd-plan-audit.md` 的本轮审计结论不再把仓库内可落地项留在“外部工程”
- `docs/plan/aegis-sensor-rd-status.md` 与本轮实际状态一致
- 重新执行第一步审计后，不再发现新的仓库内 agent 完整性缺口
- 分支合并到 `main` 并推送
