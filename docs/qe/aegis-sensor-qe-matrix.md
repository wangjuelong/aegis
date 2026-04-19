# Aegis Sensor QE 矩阵

- 执行日期：2026-04-19
- 执行分支：`feat/agent-gap-closure`
- 环境基线：[`docs/env/开发环境.md`](../env/开发环境.md)
- 当前轮次定位：G01-G03 收口回归与诊断链验证

## 1. 执行结果

| 类别 | 命令 / 依据 | 结果 | 备注 |
|------|-------------|------|------|
| 格式校验 | `cargo fmt --all` | 通过 | G03 代码收口后执行 |
| 工作区回归 | `cargo test --workspace` | 通过 | `aegis_core` 80 项、`aegis_model` 4 项、`aegis_platform` 12 项，共 96 项单元测试；doc tests 全部通过 |
| 诊断模式 | `cargo run -p aegis-agentd -- --diagnose` | 通过 | 诊断包已输出 `communication`、`runtime_signals`、`plugin_status`、WAL 加密状态、资源、自保护状态 |
| Serverless 示例 | `cargo run -p aegis-core --example runtime_sdk_connector` | 通过 | `real 0.44s`，完成 Runtime SDK 事件编码与 Cloud connector 映射示例 |

## 2. 能力覆盖

| 维度 | 覆盖方式 | 当前结果 |
|------|----------|----------|
| 平台兼容性 | `aegis_platform` Windows/Linux/macOS mock harness 测试 | 12/12 通过 |
| 通信与安全链 | `comms`、`high_risk_ops`、`self_protection` 相关单元测试 | 命令验签、审批证明、重放保护、四级回退、恢复探测、证书生命周期、自保护全部通过 |
| 容器与云原生 | `container_mode`、`runtime_sdk` 相关单元测试 | 容器元数据映射、sidecar/DaemonSet 契约、Runtime SDK 编码、Cloud connector 映射全部通过 |
| 升级与诊断 | `upgrade` 模块单元测试 + `--diagnose` 实际运行 | 升级规划、灰度门控、通信状态、WAL 加密字段、篡改信号与诊断输出通过 |
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
- `plugin_status`: `[]`
- `self_protection_posture`: `Normal`
- `redacted_fields`: `server_signing_keys`, `approval_private_keys`, `threat_intel_cache`

## 4. 环境与限制说明

- 本轮结果来自当前 macOS 开发机上的工作区回归与示例运行。
- Windows 与 Linux 测试主机信息已在 [`docs/env/开发环境.md`](../env/开发环境.md) 记录，可用于后续安装冒烟或现场联调。
- 当前 QE 结果能够证明代码契约、跨平台 mock 行为和发布前诊断路径可工作；不宣称已完成远端宿主机自动化部署验收。
