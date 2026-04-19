# Aegis Sensor 研发内测试点记录

- 记录日期：2026-04-19
- 试点类型：研发内测 / 合并前收口
- 执行分支：`feat/agent-gap-closure`
- 环境参考：[`docs/env/开发环境.md`](../env/开发环境.md)

## 1. 试点目标

- 验证 P00-P26 工作包已经形成连续的代码、测试、文档闭环。
- 验证容器模式、sidecar 本地控制面、Runtime SDK、Cloud API Connector 与诊断模式可在本地工作区完成最小闭环。
- 为合并 `main` 提供明确的回归结论和回滚依据。

## 2. 试点范围

| 范围 | 说明 |
|------|------|
| 核心工程 | workspace、模型层、平台层、运行时、检测、响应、升级、容器、Serverless |
| 验证方式 | `cargo fmt --all`、`cargo test --workspace`、`--diagnose`、Runtime SDK 示例 |
| 环境池 | 当前 macOS 开发机；Windows `192.168.1.4`；Linux `192.168.1.15` |

## 3. 本轮结论

| 检查项 | 结果 | 说明 |
|--------|------|------|
| 工作区回归 | 通过 | 105 项单元测试与全部 doc tests 通过 |
| 诊断模式 | 通过 | 输出诊断包且 `runtime_bridge`、WAL 加密状态等关键字段正常 |
| 容器 / Sidecar 契约 | 通过 | 容器元数据映射、sidecar/DaemonSet 契约、unix socket 本地控制面测试全部通过 |
| Runtime SDK / Cloud API | 通过 | 编码器、connector runner、flush/cursor、bridge 示例运行通过 |
| 主线合并准入 | 通过 | 满足进入 `main` 的本地回归门槛 |

## 4. 风险说明

- 当前试点结论基于代码契约测试和本地运行结果。
- [`docs/env/开发环境.md`](../env/开发环境.md) 中的 Windows/Linux 主机保留为后续安装冒烟与现场联调环境，不在本轮自动化回归范围内。
- 本轮不发现阻断 `main` 合并的问题，回滚可直接使用 feature branch 上逐工作包提交记录。
