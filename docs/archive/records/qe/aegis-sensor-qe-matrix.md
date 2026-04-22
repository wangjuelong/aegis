# Aegis Sensor QE 矩阵

- 执行日期：2026-04-20
- 执行分支：`wangjuelong/feat/windows-system-completion`
- 环境基线：[`docs/env/开发环境.md`](../../../env/开发环境.md)
- 当前轮次定位：G01-G06 收口回归与诊断链验证

## 1. 执行结果

| 类别 | 命令 / 依据 | 结果 | 备注 |
|------|-------------|------|------|
| 格式校验 | `cargo fmt --all` | 通过 | G06 代码收口后执行 |
| 工作区回归 | `cargo test --workspace` | 通过 | `aegis_core` 91 项、`aegis_model` 4 项、`aegis_platform` 15 项，共 110 项单元测试；doc tests 全部通过 |
| 诊断模式 | `cargo run -p aegis-agentd -- --diagnose` | 通过 | 诊断包持续输出 `communication`、`runtime_signals`、`runtime_bridge`、`plugin_status`、WAL 加密状态、资源、自保护状态 |
| Watchdog 运行时 | `cargo run -p aegis-watchdog` | 通过 | 已完成 agent/watchdog 心跳链路启动并输出 runtime ready 日志 |
| Updater 运行时 | `cargo run -p aegis-updater` | 通过 | 已完成签名升级清单自校验并输出已验签 artifact 日志 |
| Serverless 示例 | `cargo run -p aegis-core --example runtime_sdk_connector` | 通过 | 输出 `first_flush=false second_flush=true buffered_events=1 emitted_batches=1`，完成 Runtime SDK 编码、connector flush 与 bridge 计数示例 |
| Windows release 验证 | `packaging/windows/validate.ps1 -BundleChannel release` | 通过 | `192.168.2.218` 上完成 release 签名、payload 验签、安装后复验与卸载，`required_failures=[]` |

## 2. 能力覆盖

| 维度 | 覆盖方式 | 当前结果 |
|------|----------|----------|
| 平台兼容性 | `aegis_platform` Windows/Linux/macOS 状态基线与 mock harness 测试 | 15/15 通过 |
| 通信与安全链 | `comms`、`high_risk_ops`、`self_protection` 相关单元测试 | 命令验签、审批证明、重放保护、四级回退、恢复探测、证书生命周期、自保护全部通过 |
| 容器与云原生 | `container_mode`、`runtime_sdk`、`orchestrator` 相关单元测试 | 容器元数据映射、unix socket sidecar 控制面、Runtime SDK 编码、connector flush/cursor、runtime-bridge 拓扑全部通过 |
| 升级与诊断 | `upgrade` 模块单元测试 + `--diagnose` / `watchdog` / `updater` 实际运行 | 升级规划、灰度门控、清单验签、rollback 校验、watchdog 失联检测、`runtime_bridge` 诊断映射通过 |
| 平台执行链 | `response_executor`、`recovery` 与实际平台实现联动测试 | `ResponseExecutor -> WindowsPlatform`、`RecoveryCoordinator -> LinuxPlatform` 真正写入平台状态快照并通过验证 |
| 离线自治与取证 | `wal`、`recovery`、`response_executor` 单元测试 | 加密 WAL、损坏 segment 隔离、紧急审计环、快照恢复校验与取证链反篡改全部通过 |

## 3. 诊断模式快照

- `control_plane_url`: `https://127.0.0.1:7443`
- `reachable`: `true`
- `device_certificate_loaded`: `true`
- `last_rotation_succeeded`: `true`
- `enabled_sensors`: `process`, `file`, `network`
- `communication.active_channel`: `Grpc`
- `communication.fallback_chain`: `Grpc`, `WebSocket`, `LongPolling`, `DomainFronting`
- `wal.completeness`: `Full`
- `wal.encrypted`: `true`
- `wal.key_version`: `1`
- `wal.quarantined_segments`: `0`
- `dropped_events_total`: `0`
- `runtime_signals.communication_channel`: `Grpc`
- `runtime_signals.etw_tamper_detected`: `false`
- `runtime_signals.amsi_tamper_detected`: `false`
- `runtime_signals.bpf_integrity_pass`: `true`
- `runtime_bridge.control_socket_path`: `/var/lib/aegis/runtime-bridge-local-agent.sock`
- `runtime_bridge.buffered_events`: `0`
- `runtime_bridge.emitted_batches`: `0`
- `plugin_status`: `[]`
- `self_protection_posture`: `Normal`
- `redacted_fields`: `server_signing_keys`, `approval_private_keys`, `threat_intel_cache`

## 4. 环境与限制说明

- 本轮结果来自当前 macOS 开发机上的工作区回归、示例运行，以及 `192.168.2.218` Windows 真机 release 验收。
- Windows 与 Linux 测试主机信息已在 [`docs/env/开发环境.md`](../../../env/开发环境.md) 记录，可用于后续安装冒烟或现场联调。
- 当前 QE 结果能够证明代码契约、跨平台 mock 行为、发布前诊断路径与 Windows release gate 可工作；不宣称已覆盖 Windows 10 / Windows Server 全量主机池。
