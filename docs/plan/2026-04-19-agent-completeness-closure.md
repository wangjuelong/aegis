# Aegis Agent 第二轮完整性收口计划

> 说明：
> - 本计划在隔离 worktree `/Users/lamba/github/aegis-sensor-dev` 的分支 `feat/agent-completeness-closure` 中执行。
> - 本计划用于收口 2026-04-19 二次符合性审计发现的“runtime 未闭环、实现与文档承诺不一致、旧状态文档失真”问题。
> - 本轮只把“当前仓库内能够真实落地并可验证”的工作列入 merge gate；需要新驱动工程、系统扩展工程或硬件密钥基础设施的事项单列为外部工程，不在本轮谎称完成。

## 1. 目标与边界

### 1.1 本轮目标

1. 将 `aegis-core` 已存在的检测、关联、反馈、响应、高危操作等原语真正接入主运行时。
2. 建立下行命令接收、验签、持久化重放防护、执行与 ACK 的闭环。
3. 将插件宿主从“仅校验 wasm 文件头/哈希”升级为真实 `wasmtime` 沙箱执行。
4. 将 `watchdog`、`updater`、`--diagnose` 从演示程序升级为可运行、可观测的状态链路。
5. 修正文档与状态基线，停止把“骨架/契约件”写成“完整实现”。

### 1.2 本轮不纳入 merge gate 的外部工程

下列事项仍然是必须完成的研发项，但不属于当前仓库内可在本轮真实闭合的代码工作：

- Windows ETW/Minifilter/WFP/CmCallback 的真实驱动与签名分发
- Linux eBPF/LSM/fanotify 的真实内核侧实现
- macOS ESF/Network Extension/System Extension 的真实系统扩展
- TPM 2.0 / Secure Enclave / OS keystore 的跨平台正式接入
- mlock/zeroize 的系统级强化与硬件锚定回滚计数器

这些内容会在本文档的“外部工程工作包”中保留详细研发要求，但不计入本轮 merge 条件。

## 2. 当前问题重述

### 2.1 本轮必须收口的仓库内缺口

1. `orchestrator` 只启动少量后台任务，`sensor-dispatch`、告警转发、`response-executor` 仍主要是日志输出，没有形成检测/决策/响应闭环。
2. `CommandValidator`、`ApprovalQueue`、`RemoteShellRuntime`、`PlaybookRuntime`、`ResponseExecutor` 等模块存在，但未接入主运行时。
3. `CommunicationRuntime` 只有 uplink 与回退状态机，没有 downlink 接收与命令执行链；`CommandReplayLedger` 仍是进程内 `HashMap`。
4. `PluginHost` 没有真实 wasm 运行时，只做模块头/哈希校验与错误状态记账。
5. `aegis-watchdog`、`aegis-updater`、`aegis-agentd -- --diagnose` 仍然是静态演示/拼装输出，不反映真实运行态状态。

### 2.2 本轮完成定义

每个工作包都必须同时满足：

- 代码交付
- 测试交付
- 文档交付
- 中文提交

每个代码型工作包按以下节奏执行：

1. 代码与测试提交一次
2. 相应文档更新再提交一次

统一验证命令：

```bash
cargo fmt --all
cargo test --workspace
cargo run -p aegis-agentd -- --diagnose
cargo run -p aegis-watchdog -- --once
cargo run -p aegis-updater -- --once
```

## 3. 仓库内收口工作包

### C01：运行时检测/决策/响应闭环

**状态**

- `done`（2026-04-19，代码提交：`61c22e4`）

**目标**

- 将 `IOC / Rule VM / Temporal / Script Decode / YARA / ML / Specialized Detection / Correlation / Storyline / Feedback / ResponseExecutor` 接入主运行时。

**代码范围**

- `crates/aegis-core/src/orchestrator.rs`
- `crates/aegis-core/src/dispatch.rs`
- `crates/aegis-core/src/ioc.rs`
- `crates/aegis-core/src/rule_vm.rs`
- `crates/aegis-core/src/temporal.rs`
- `crates/aegis-core/src/script_decode.rs`
- `crates/aegis-core/src/yara.rs`
- `crates/aegis-core/src/ml.rs`
- `crates/aegis-core/src/correlation.rs`
- `crates/aegis-core/src/feedback.rs`
- `crates/aegis-core/src/response_executor.rs`
- `crates/aegis-model/src/lib.rs`

**交付**

- `sensor-dispatch -> detection-pool -> decision-router -> alert/response/telemetry` 闭环
- `storyline-engine`、`feedback-loop` 的运行时接线
- 响应执行器不再只是日志，而是真正调用 `ResponseExecutor`
- `BootstrapSummary.task_topology` 与真实后台任务一致

**验收**

- 单测或集成测试覆盖：
  - 恶意脚本/高风险事件进入检测流水线后产生告警或响应
  - 响应动作进入 `ResponseExecutor`
  - telemetry 中能看到从 `NormalizedEvent` 派生的记录
  - storyline / correlation 能生成聚合结果

**本次实际落地**

- 实际改动文件收敛为：
  - `crates/aegis-core/src/orchestrator.rs`
  - `crates/aegis-core/src/feedback.rs`
  - `crates/aegis-core/src/response_executor.rs`
- 将运行时任务拓扑扩展为 `sensor-dispatch -> detection-pool -> decision-router -> alert/response/telemetry`，并同步修正 `BootstrapSummary.task_topology` / `queue_capacities`。
- 在主运行时内接入 `IOC / Rule VM / Temporal / Script Decode / YARA / ML / Specialized Detection / Correlation / Storyline / Threat Feedback`，不再停留在“模块存在但未接线”状态。
- `response-executor` 任务已改为真实调用 `ResponseExecutor`，覆盖 `KillProcess`、`QuarantineFile`、`NetworkIsolate` 审计落盘，而不是仅输出日志。
- `HealthReporter` 改为读取运行时计数与自适应白名单大小，状态页不再固定返回空白计数。
- 新增闭环测试：
  - `bootstrap_creates_runtime_topology`
  - `runtime_executes_response_flow_for_malicious_script`

**验证**

```bash
cargo fmt --all
cargo test --workspace
```

**完成后仍保留的后续项**

- `C02` 负责把 downlink 命令接收、验签、持久化 replay ledger、审批和高危执行链接入主运行时。
- `C03` 负责把插件宿主升级为真实 `wasmtime` 沙箱。
- `C04` 负责把 watchdog / updater / diagnose 改为读取真实状态快照。

### C02：下行命令、持久化重放防护与高危执行链

**状态**

- `done`（2026-04-19，代码提交：`ba818b8`）

**目标**

- 建立 `comms-rx`、持久化 replay ledger、命令验证、ACK 生成以及对 `ResponseExecutor` / `ApprovalQueue` / `RemoteShellRuntime` / `PlaybookRuntime` / `SessionLockRuntime` 的执行桥接。

**代码范围**

- `crates/aegis-core/src/comms.rs`
- `crates/aegis-core/src/orchestrator.rs`
- `crates/aegis-core/src/high_risk_ops.rs`
- `crates/aegis-core/src/response_executor.rs`
- `crates/aegis-model/src/lib.rs`

**交付**

- `TransportDriver` 支持 downlink 轮询
- loopback/测试驱动支持注入 `SignedServerCommand`
- `CommandReplayLedger` 升级为持久化实现
- `CommandValidator` 接入 `comms-rx`
- 命令到 `kill-process` / `quarantine-file` / `network-isolate` / `remote-shell` / `playbook` / `session-lock` 的映射执行
- 成功/失败 ACK 与审计记录

**验收**

- 单测或集成测试覆盖：
  - 签名正确的命令可被消费并执行
  - 重放命令被拒绝
  - 高危命令在审批不足时被拒绝
  - Remote Shell / Playbook / Session Lock 至少一条真实执行链可打通

**本次实际落地**

- 实际改动文件收敛为：
  - `crates/aegis-core/src/comms.rs`
  - `crates/aegis-core/src/orchestrator.rs`
  - `crates/aegis-agentd/src/main.rs`
- `TransportDriver` 已补齐 downlink 轮询接口，`CommunicationRuntime` 新增 `poll_downlink`、loopback 注入/回收句柄与测试支撑，不再只有 uplink 回退状态机。
- `CommandReplayLedger` 已从进程内 `HashMap` 升级为 sqlite 持久化账本，进程重启后仍可拒绝命令重放。
- 主运行时新增 `comms-rx` 后台任务与 `CommandExecutionRuntime`，打通 `SignedServerCommand -> validate -> execute -> ClientAck` 闭环。
- 已将 `kill-process`、`quarantine-file`、`network-isolate`、`remote-shell`、`playbook`、`session-lock` 映射到真实执行桥接，其中高危路径通过 `ApprovalQueue` / `RemoteShellRuntime` / `PlaybookRuntime` / `SessionLockRuntime` 落地。
- 新增闭环测试：
  - `communication_runtime_polls_loopback_downlink_and_records_uplink`
  - `command_replay_ledger_persists_across_reopen`
  - `runtime_accepts_kill_command_and_rejects_replay`
  - `runtime_rejects_remote_shell_without_required_approvers`
  - `runtime_executes_session_lock_command`

**验证**

```bash
cargo fmt --all
cargo test --workspace
```

**完成后仍保留的后续项**

- `C03` 负责将插件宿主从 wasm 文件校验器升级为真实 `wasmtime` 沙箱。
- `C04` 负责将 watchdog / updater / diagnose 与运行态状态快照绑定。

### C03：真实 `wasmtime` 插件宿主

**状态**

- `done`（2026-04-19，代码提交：`4035bd2`）

**目标**

- 用真实 `wasmtime` 沙箱替换当前“只校验文件头/哈希”的伪宿主。

**代码范围**

- `Cargo.toml`
- `crates/aegis-core/Cargo.toml`
- `crates/aegis-core/src/plugin_host.rs`
- `crates/aegis-agentd/src/main.rs`

**交付**

- 基于 `wasmtime` 的模块加载、实例化、导出函数调用
- 插件 fuel/执行预算控制
- trap / fuel 耗尽 / 非零返回状态映射到健康状态
- `PluginHost.statuses()` 返回真实运行结果而不是静态空列表

**验收**

- 单测覆盖：
  - 正常 wasm 插件成功执行
  - 死循环或超预算插件被中断并标记超时/失败
  - trap 导致 crash 计数递增并在阈值后禁用

**本次实际落地**

- 实际改动文件收敛为：
  - `Cargo.toml`
  - `Cargo.lock`
  - `crates/aegis-core/Cargo.toml`
  - `crates/aegis-core/src/plugin_host.rs`
  - `crates/aegis-agentd/src/main.rs`
- 默认插件执行器已从“只校验 wasm 头和哈希”升级为真实 `wasmtime` 宿主，支持模块编译校验、实例化以及导出 `run` 函数调用。
- 插件运行加入 fuel 预算控制，死循环/超预算路径会映射为 `timed_out`，trap 与非零返回值映射为 `crashed`。
- `PluginHost` 新增 manifest 目录装载与 `run_all_once`，支持从默认插件目录发现插件并收集真实运行状态。
- `aegis-agentd` 的 `--diagnose` 与 supervisor heartbeat 已改为从默认插件目录收集插件状态，不再固定读取空宿主列表。
- 新增真实 wasm 测试：
  - `plugin_host_executes_real_wasm_module`
  - `plugin_host_maps_wasm_trap_to_crash`
  - `plugin_host_times_out_infinite_wasm_loop`
  - `plugin_host_loads_manifests_from_directory`

**验证**

```bash
cargo fmt --all
cargo test --workspace
cargo run -p aegis-agentd -- --diagnose
```

**完成后仍保留的后续项**

- `C04` 负责将 watchdog / updater / diagnose 与真实状态快照、热更新清单和观测链路绑定。

### C04：watchdog、updater 与诊断面运行态化

**目标**

- 将 `watchdog`、`updater`、`--diagnose` 从 demo 程序升级为基于状态文件/运行态快照的真实链路。

**代码范围**

- `crates/aegis-agentd/src/main.rs`
- `crates/aegis-core/src/orchestrator.rs`
- `crates/aegis-core/src/upgrade.rs`
- `crates/aegis-watchdog/src/main.rs`
- `crates/aegis-updater/src/main.rs`
- `crates/aegis-model/src/lib.rs`

**交付**

- agent 周期性落地 supervisor/runtime 状态快照
- watchdog 读取快照并执行 `WatchdogLinkMonitor`
- updater 支持从文件或参数加载 manifest/artifact 进行真实验签流程
- `--diagnose` 读取真实状态快照，而非只拼默认对象

**验收**

- 单测或运行验证覆盖：
  - `cargo run -p aegis-watchdog -- --once` 能读取状态并输出当前监测结果
  - `cargo run -p aegis-updater -- --once` 能验证传入清单
  - `cargo run -p aegis-agentd -- --diagnose` 返回的通信/插件/watchdog/runtime 字段来自状态快照

**本次实际落地**

- 代码提交：`88c6de2`
- 实际改动文件收敛为：
  - `Cargo.lock`
  - `crates/aegis-agentd/src/main.rs`
  - `crates/aegis-core/src/config.rs`
  - `crates/aegis-core/src/upgrade.rs`
  - `crates/aegis-updater/Cargo.toml`
  - `crates/aegis-updater/src/main.rs`
  - `crates/aegis-watchdog/src/main.rs`
- `RuntimeStateStore` 已补齐 agent / watchdog / update 三类运行态快照的落盘与回读，并为 `DiagnoseBundle` 新增可选 `watchdog` 视图。
- `aegis-agentd -- --diagnose` 已切换为优先读取持久化 agent 快照；若本机默认 `/var/lib/aegis` 不可写，会自动回退到仓库内 `target/aegis-dev/state`，并附带读取 `watchdog-state.json`。
- `aegis-watchdog -- --once` 已改为从 agent 快照构建监测结果、执行 `WatchdogLinkMonitor`、落盘 `watchdog-state.json`，而不是输出静态示例对象。
- `aegis-updater -- --once` 已改为读取或自动种入 `updates/manifest.json`、`artifact.bin`、`rollback.bin`，执行真实签名与摘要校验，并落盘 `update-state.json`。
- `aegis-updater` 额外支持 `--manifest`、`--artifact`、`--rollback`、`--state-root` 参数，便于对外部 staged 文件做一次性验签。
- `AgentConfig` 已补充 `with_state_root`，确保 CLI 在开发环境下能统一重绑定可写的运行态目录。

**验证**

```bash
cargo fmt --all
cargo test --workspace
cargo run -p aegis-agentd -- --diagnose
cargo run -p aegis-watchdog -- --once
cargo run -p aegis-updater -- --once
cargo run -p aegis-agentd -- --diagnose
```

**完成后仍保留的后续项**

- 本轮仓库内 merge gate 已全部闭合。
- 剩余事项仅为外部工程：
  - `X01` 三平台真实内核/系统集成
  - `X02` 硬件绑定密钥与内存强化
  - `X03` 传输栈正式化

## 4. 外部工程工作包

以下工作包必须保留，但不属于本轮 merge gate：

### X01：三平台真实内核/系统集成

- Windows：ETW / Minifilter / WFP / CmCallback / PPL / ELAM
- Linux：eBPF / LSM / fanotify / audit / systemd 集成
- macOS：ESF / Network Extension / System Extension / notarization

### X02：硬件绑定密钥与内存强化

- TPM 2.0 / Secure Enclave / Keychain / DPAPI / tpm2-tss
- `mlock + zeroize`
- TPM NV monotonic counter / rollback floor
- mTLS 设备证书真实轮换

### X03：传输栈正式化

- gRPC / WebSocket / Long-Polling / Domain Fronting 的真实客户端实现
- 网络故障、代理、证书、回退与恢复的真实联调

## 5. 执行顺序

1. 文档基线重建
2. C01：运行时闭环
3. C02：命令与高危执行链
4. C03：真实插件宿主
5. C04：watchdog / updater / diagnose

## 6. 合并条件

合并到 `main` 前必须满足：

- `C01-C04` 全部完成
- 对应状态文档已更新
- worktree 干净
- 不污染根工作区 `/Users/lamba/github/aegis`
