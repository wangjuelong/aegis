# Aegis Sensor macOS 研发计划与完成状态

> 来源：
> - `docs/技术方案/sensor-final技术解决方案.md`
> - `docs/architecture/aegis-sensor-architecture.md`
> - 既有总体计划、执行分解、状态与审计记录中的 macOS 部分

## 1. 文档定位

本文件统一描述 macOS 平台研发计划与完成状态，不再使用单独的 macOS 子目录索引。

## 2. 状态定义

- `done`：已完成代码、验证与文档闭环
- `doing`：已进入实施但未完成闭环
- `todo`：未开始

## 3. macOS 目标范围

macOS 平台目标覆盖：

- `MacosPlatform` 平台模块与 descriptor
- ESF / Network Extension / System Extension 抽象与真实系统级交付
- 授权状态机、订阅集与事件转换
- macOS 平台响应、防护与系统级强制执行
- 签名、notarization、用户授权流与试点发布
- Secure Enclave / Keychain 级别的正式硬件根信任

## 4. 当前总体结论

- macOS 当前已经完成的是平台骨架、provider 基线、授权状态机、订阅集、事件注入与测试基线。
- macOS 最终交付所需的 ESF / Network Extension / System Extension 系统级能力尚未完成。

## 5. macOS 研发计划与状态

| 工作包 | 目标 | 状态 | 当前结论 |
|--------|------|------|----------|
| M01 | macOS 平台模块与 provider 基线 | done | 已完成 `MacosPlatform`、ESF / NE / System Extension / TCC / ExecPolicy provider 基线 |
| M02 | 授权状态机、订阅集、事件注入与能力矩阵测试 | done | 已完成 `NotDetermined / AwaitingUserApproval / Approved / Denied` 状态机、订阅集与平台测试 |
| M03 | ESF 真实系统事件交付 | todo | 当前仅有抽象与测试基线，真实 ESF 进程/文件/认证事件尚未交付 |
| M04 | Network Extension 真实网络事件与网络隔离链 | todo | 当前仅有抽象入口，真实网络事件与隔离执行尚未交付 |
| M05 | System Extension 打包、签名、公证与用户批准链 | todo | 当前未完成 System Extension 的正式包装、签名、notarization 与批准流程 |
| M06 | macOS 平台响应与保护强制执行链 | todo | 当前公共响应引擎已完成，但 macOS 侧真实隔离、回滚、保护动作未完成 |
| M07 | Secure Enclave / Keychain 正式硬件根信任与密钥保护 | todo | 当前未完成正式 hardware-backed trust chain 收口 |
| M08 | macOS QE / 试点 / 发布验证 | todo | 当前未完成系统级集成后的试点、兼容性与发布验证 |

## 6. macOS 完成判定

当前可以诚实判定为：

- macOS 平台骨架与测试基线：`done`
- macOS 真实系统级交付：`todo`

因此，本文件中的平台状态应保持：

- `M01-M02 = done`
- `M03-M08 = todo`

## 7. macOS 后续执行顺序

建议按以下顺序推进剩余事项：

1. 先补齐 `M03-M04` 的真实系统事件与网络隔离链
2. 再完成 `M05` 的 System Extension 签名、公证与授权流程
3. 然后完成 `M06` 的真实响应/保护动作
4. 最后完成 `M07-M08` 的硬件根信任、试点与发布验证

