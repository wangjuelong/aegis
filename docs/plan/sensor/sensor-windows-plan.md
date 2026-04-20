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
- `W03.1` 已完成：`WindowsPlatform` 已接入本机 Windows / SSH Windows 两类真实执行通道，启动阶段会实测 PowerShell、进程枚举、事件日志、防火墙与注册表能力，不再返回硬编码健康状态。
- `W03.2` 已完成：`poll_events()` 已接入 `Win32_Process` 真实进程基线差分，`detect_hidden_processes()` 已接入 `Win32_Process` / `tasklist` 双视图比对；并已修复中文 Windows 主机下 `tasklist /FO CSV /NH` 无表头导致的解析问题。
- `W03.3` 已完成：启动阶段会实测 Security 4688 可用性并固定增量游标，`poll_events()` 已接入基于 Security 4688 的真实进程审计增量事件；`EtwProcess` 健康状态不再只依赖“日志存在”，而是依赖真实的 Process Creation 审计可读性。
- 当前仓库的主要缺口不是“没有接口”，而是 Windows 侧仍大量使用伪状态与伪成功返回，无法反映真实主机能力、真实事件链路与真实响应结果。
- 本轮研发的原则是先把 `WindowsPlatform` 变成“只汇报真实能力、不伪造成功”的运行时，再逐步补齐进程、网络、注册表、脚本、自保护、签名与硬件根信任链。

## 5. Windows 研发计划与状态

### 5.1 已完成基线

| 工作包 | 目标 | 状态 | 当前结论 |
|--------|------|------|----------|
| W01 | Windows 平台模块与 provider 注册表基线 | done | 已完成 `WindowsPlatform`、12 类 provider 注册与 Windows descriptor |
| W02 | 事件注入、`EventBuffer` 轮询与能力矩阵测试 | done | 已完成事件注入、平台轮询与能力矩阵基线测试 |

### 5.2 本轮详细研发计划

| 工作包 | 目标 | 状态 | 设计约束 | 完成判定 |
|--------|------|------|----------|----------|
| W03.1 | Windows 主机真实执行链与能力探测 | done | 不允许继续返回硬编码健康状态；必须区分本机 Windows、远端 SSH Windows、不可用三种运行态 | 已完成本机/SSH 真实执行通道、启动期能力探测、真实能力矩阵与真实健康快照；不可用时会直接失败而不是伪成功 |
| W03.2 | 真实进程基线、增量轮询与隐藏进程检测 | done | 不允许仅保留注入事件；必须基于 `Win32_Process`/`tasklist` 等真实主机视图构造 process delta | 已完成真实进程基线差分与双视图隐藏进程检测，`poll_events()` 可输出真实 `process-start/process-exit` 事件 |
| W03.3 | ETW/审计能力健康检查与进程审计事件链 | done | 不允许把 ETW/AMSI 健康固定为 `true`；必须根据日志/审计策略实测结果判断 | 已完成 Security 4688 可用性探测、启动游标初始化、增量审计事件轮询与 `EtwProcess` 健康状态收口，并已在真实 Windows 主机验证 JSON 查询结果 |
| W04.1 | 真实网络基线、连接增量与隔离执行链 | todo | 不允许只改内存快照；必须生成并执行真实 Windows 防火墙/网络隔离命令 | 能枚举 TCP/UDP 连接，输出真实 network delta；`network_isolate/network_release` 能在主机执行防火墙动作 |
| W04.2 | 注册表回滚与保护清单落盘 | todo | 不允许只把 rollback 目标塞进快照；必须生成可审计的注册表回滚/保护清单 | 回滚目标、受保护路径和注册表保护面能落盘到审计工件，并返回真实路径 |
| W05.1 | Named Pipe / DLL / VSS / Device 资产可见性 | todo | 不允许 provider 名义存在但永远返回健康；必须对每类 provider 给出真实“已实现/未实现/主机不可用”状态 | 至少完成资产枚举与健康探测，未实现的实时回调必须明确标为不健康而不是伪完成 |
| W05.2 | AMSI / 脚本 / ETW 篡改健康面 | todo | 不允许把 `check_amsi_integrity()` 固定返回健康；必须根据 Defender/AMSI/审计实际状态给出结论 | 能报告 AMSI 可用性、PowerShell ScriptBlock 日志可用性、ETW 日志读取状态 |
| W06.1 | 真实进程终止、挂起、隔离、取证执行链 | todo | 不允许继续只改内存；必须执行真实 Windows 命令并在失败时返回错误 | `suspend_process/kill_process/kill_ppl_process/quarantine_file/collect_forensics` 能执行真实动作或诚实失败 |
| W06.2 | 预防性阻断与保护面审计 | todo | 不允许只记录 block lease；必须把阻断/保护面结果写成工件用于复盘 | hash/path/network block、受保护 PID/路径和完整性验证结果可形成真实审计工件 |
| W07.1 | 真实 Windows 测试主机验证、兼容性矩阵与验收脚本 | todo | 不允许只跑本地单测；必须在可用 Windows 主机验证 | 仓库内有可复跑验证脚本，且文档记录实际使用主机、验证项与结果 |
| W08.1 | Windows 凭据存储、DPAPI/TPM 根信任与回滚锚点方案收口 | todo | 不允许继续只依赖 Linux TPM 分支；Windows 必须有独立的正式方案和代码接入面 | `aegis-core` 对 Windows 密钥保护与回滚锚点具备明确实现路径和状态输出 |

### 5.3 执行顺序与提交粒度

每个工作包都必须按以下顺序闭环：

1. 完成对应代码与测试
2. 提交一次中文代码提交
3. 更新本文件与总计划文档中的状态
4. 再提交一次中文文档提交

本轮默认执行顺序：

1. `W03.1` `done`
2. `W03.2` `done`
3. `W03.3` `done`
4. `W04.1`
5. `W04.2`
6. `W05.1`
7. `W05.2`
8. `W06.1`
9. `W06.2`
10. `W07.1`
11. `W08.1`

## 6. Windows 完成判定

当前可以诚实判定为：

- Windows 平台骨架与测试基线：`done`
- Windows 真实执行链与能力探测：`done`
- Windows 真实进程差分与隐藏进程检测：`done`
- Windows 真实 ETW/审计健康检查与进程审计事件链：`done`
- Windows 真实系统级交付：`doing`

因此，本文件中的平台状态应保持：

- `W01-W02 = done`
- `W03.1 = done`
- `W03.2 = done`
- `W03.3 = done`
- `W04.1-W08.1 = todo`，进入实施后逐项更新为 `doing/done`

## 7. Windows 后续执行顺序

Windows 专项的最终目标不变：

1. 先把运行时改成“真实能力、真实失败、真实工件”
2. 再把进程/网络/注册表/脚本/取证链路逐步从骨架替换为真实主机交付
3. 然后补齐真实 Windows 主机验证、兼容性与发布前验收
4. 最后收口 Windows 正式密钥保护、回滚锚点与硬件根信任
