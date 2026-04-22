# Aegis Sensor 发布说明

- 发布日期：2026-04-20
- 合入目标：`main`
- 发布来源：`wangjuelong/feat/windows-system-completion`

## 1. 本次交付

本轮完成 P00-P27 全部工作包，交付范围覆盖：

- Rust workspace、平台抽象、统一事件模型、运行时编排、Ring Buffer / Spill / WAL
- Windows / Linux / macOS 平台基线、动作状态快照、隔离/取证落地与 mock harness
- IOC / Rule VM / Temporal / YARA / ML / Storyline / 专项检测 / AI 监控
- 响应执行、自保护、审批链、升级门控、诊断模式、WASM 插件宿主
- 容器宿主机模式、sidecar lite、Runtime SDK、Cloud API Connector
- watchdog / updater 热更新链路、升级清单验签与 rollback artifact 校验
- Windows release manifest、签名/验签脚本、安装前后 release gate、ELAM/PPL 批准依赖校验与 Windows 11 真机发布验证

## 2. 验证摘要

- `cargo fmt --all`：通过
- `cargo test --workspace`：通过，110 项单元测试 + 全部 doc tests 通过
- `cargo run -p aegis-agentd -- --diagnose`：通过
- `cargo run -p aegis-watchdog`：通过
- `cargo run -p aegis-updater`：通过
- `cargo run -p aegis-core --example runtime_sdk_connector`：通过
- `packaging/windows/validate.ps1 -BundleChannel release`：在 `192.168.2.218` 通过，`required_failures=[]`

相关 QE 细节见 [`docs/archive/records/qe/aegis-sensor-qe-matrix.md`](../qe/aegis-sensor-qe-matrix.md)。

## 3. 运维与排障入口

- 诊断模式：`cargo run -p aegis-agentd -- --diagnose`
- Runtime SDK 最小示例：`cargo run -p aegis-core --example runtime_sdk_connector`
- 研发环境池：[`docs/env/开发环境.md`](../../../env/开发环境.md)

## 4. 回滚说明

- 所有工作包均按“代码提交 + 文档提交”形成独立提交对，可按工作包粒度回退。
- 升级与回滚模型已在 `upgrade`、`recovery`、`wal` 模块中建立基线，并补齐 release 清单验签、receipt/CMS 校验与 rollback artifact 校验，可作为后续正式发布工程化的直接输入。

## 5. 已知边界

- 本轮发布说明基于本地工作区回归和 mock/platform contract 验证。
- Windows 远端已在 `192.168.2.218` 完成 release 安装验收；Windows 10 / Windows Server 扩展兼容性仍依赖额外主机池。
- Microsoft 正式代码签名、驱动签发与 ELAM/PPL 外部审批链不在仓库内伪造；当前仓库只保证“缺外部凭据即失败、有凭据即可完成 release gate”。
