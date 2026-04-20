# Aegis Sensor Windows 研发计划与完成状态

> 来源：
> - `docs/技术方案/sensor-final技术解决方案.md`
> - `docs/architecture/aegis-sensor-architecture.md`
> - 既有总体计划、执行分解、状态与审计记录中的 Windows 部分

## 1. 文档定位

本文件统一描述 Windows 平台研发计划与完成状态，不再使用单独的 Windows 子目录索引。

## 2. 状态定义

- `done`：已完成代码、验证与文档闭环
- `doing`：已进入实施但未完成闭环
- `todo`：未开始

## 3. Windows 目标范围

Windows 平台目标覆盖：

- `WindowsPlatform` 平台模块与 descriptor
- ETW / Ps / Ob / Minifilter / WFP / CmCallback 真实系统采集
- AMSI / Direct Syscall / IPC / DLL / VSS / Device Control 真实系统采集
- 平台事件到统一 `RawSensorEvent` / `NormalizedEvent` 的转换
- Windows 平台响应、防护、自保护与系统级强制执行
- 驱动、ELAM、签名、兼容性验证与试点发布
- 正式硬件根信任、密钥保护与回滚保护

## 4. 当前总体结论

- Windows 当前已经完成的是平台骨架、provider 注册、能力矩阵、事件注入与测试基线。
- Windows 最终交付所需的真实驱动/系统级能力尚未完成。

## 5. Windows 研发计划与状态

| 工作包 | 目标 | 状态 | 当前结论 |
|--------|------|------|----------|
| W01 | Windows 平台模块与 provider 注册表基线 | done | 已完成 `WindowsPlatform`、12 类 provider 注册与 Windows descriptor |
| W02 | 事件注入、`EventBuffer` 轮询与能力矩阵测试 | done | 已完成事件注入、平台轮询与能力矩阵基线测试 |
| W03 | ETW / Ps / Ob 真实进程与句柄采集链 | todo | 当前仅有抽象与测试基线，真实系统级进程/句柄采集尚未交付 |
| W04 | Minifilter / WFP / CmCallback 真实文件、网络、注册表采集链 | todo | 当前仅有抽象与测试基线，真实文件/网络/注册表系统级交付尚未完成 |
| W05 | AMSI / Direct Syscall / IPC / DLL / VSS / Device Control 真实采集链 | todo | 当前 provider 名义已建，但尚未完成真实系统级事件交付 |
| W06 | Windows 平台响应与保护强制执行链 | todo | 当前公共响应引擎已完成，但 Windows 侧真实 kill/quarantine/firewall/rollback 系统级实现未完成 |
| W07 | 驱动、ELAM、签名、兼容性验证与试点 | todo | 当前未完成驱动签发、ELAM、兼容性矩阵与正式试点发布 |
| W08 | 正式硬件根信任、密钥保护与回滚保护 | todo | 当前未完成 Windows 正式 keystore / TPM / hardware-backed trust chain 收口 |

## 6. Windows 完成判定

当前可以诚实判定为：

- Windows 平台骨架与测试基线：`done`
- Windows 真实系统级交付：`todo`

因此，本文件中的平台状态应保持：

- `W01-W02 = done`
- `W03-W08 = todo`

## 7. Windows 后续执行顺序

建议按以下顺序推进剩余事项：

1. 先补齐 `W03-W05` 的真实采集链
2. 再补齐 `W06` 的真实响应/保护动作
3. 然后完成 `W07` 的驱动签名、兼容性与试点验证
4. 最后完成 `W08` 的正式硬件根信任与密钥保护

