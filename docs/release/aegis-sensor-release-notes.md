# Aegis Sensor 发布说明

- 发布日期：2026-04-19
- 合入目标：`main`
- 发布来源：`feat/sensor-implementation`

## 1. 本次交付

本轮完成 P00-P27 全部工作包，交付范围覆盖：

- Rust workspace、平台抽象、统一事件模型、运行时编排、Ring Buffer / Spill / WAL
- Windows / Linux / macOS 平台基线与 mock harness
- IOC / Rule VM / Temporal / YARA / ML / Storyline / 专项检测 / AI 监控
- 响应执行、自保护、审批链、升级门控、诊断模式
- 容器宿主机模式、sidecar lite、Runtime SDK、Cloud API Connector

## 2. 验证摘要

- `cargo fmt --all`：通过
- `cargo test --workspace`：通过，89 项单元测试 + 全部 doc tests 通过
- `cargo run -p aegis-agentd -- --diagnose`：通过
- `cargo run -p aegis-core --example runtime_sdk_connector`：通过

相关 QE 细节见 [`docs/qe/aegis-sensor-qe-matrix.md`](../qe/aegis-sensor-qe-matrix.md)。

## 3. 运维与排障入口

- 诊断模式：`cargo run -p aegis-agentd -- --diagnose`
- Runtime SDK 最小示例：`cargo run -p aegis-core --example runtime_sdk_connector`
- 研发环境池：[`docs/env/开发环境.md`](../env/开发环境.md)

## 4. 回滚说明

- 所有工作包均按“代码提交 + 文档提交”形成独立提交对，可按工作包粒度回退。
- 升级与回滚模型已在 `upgrade`、`recovery`、`wal` 模块中建立基线，可作为后续发布工程化的直接输入。

## 5. 已知边界

- 本轮发布说明基于本地工作区回归和 mock/platform contract 验证。
- Windows/Linux 远端宿主机未纳入自动化安装验收；如需现场联调，直接使用 [`docs/env/开发环境.md`](../env/开发环境.md) 中环境。
