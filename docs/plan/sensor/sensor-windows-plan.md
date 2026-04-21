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
- `W04.1` 已完成：启动阶段会采集 TCP/UDP 真实网络基线，`poll_events()` 已接入连接增量事件；`network_isolate/network_release` 已通过 Windows 防火墙真实执行隔离与释放，不再只修改内存态。
- `W04.2` 已完成：`protect_files` 与 `registry_rollback` 会生成真实 JSON 审计工件，回滚目标、受保护路径和注册表保护面已可落盘并通过执行快照回看工件路径。
- `W06.1` 已完成：`suspend_process/kill_process/kill_ppl_process/quarantine_file/collect_forensics` 已切换为真实 Windows 响应执行链；挂起链使用 `NtSuspendProcess`，终止链会等待进程退出，文件隔离与取证打包会返回真实主机产物路径，不再依赖本地伪造快照。
- `W06.2` 已完成：`block_network/clear_all_blocks` 已接入真实 Windows 防火墙与 Minifilter 双清理链；`block_hash/block_pid/block_path` 已通过 `W16` 收口为真实 preemptive block。
- `W07.1` 已完成：仓库已新增 `scripts/windows-runtime-verify.sh` / `scripts/windows-runtime-verify.ps1` 真机验收脚本，并在 `192.168.2.218` 跑通完整矩阵；详细结果见 `docs/plan/sensor/sensor-windows-validation-matrix.md`。
- `W08.1` 已完成：`aegis-core` 已接入 Windows 专用 DPAPI 主密钥与回滚锚点实现，诊断状态会输出 `provider_detail`、Windows TPM 可用性与回滚锚点状态；并已在 `192.168.2.218` 实测拿到 `tpm_present=true`、`tpm_ready=true` 和 DPAPI machine/user scope 往返成功结果。
- 当前仓库还剩 2 个经代码审查确认的剩余缺口：`clear_all_blocks` 平面耦合、AMSI 严格阻断仍是条件成立。
- `W11/W15` 已完成：`ObRegisterCallbacks` 进程保护、Minifilter 路径保护、注册表真实 pre-callback 阻断与驱动完整性回执均已接入，保护面工件只反映真实已下发状态。
- `W12` 已完成：共享脚本解码、AMSI 脚本阻断/告警链、PowerShell 4104 脚本块事件与内存快照增量已接入，`192.168.2.218` 已验证 benign script 事件捕获和官方 AMSI 测试样本阻断。
- `W13` 已完成：开发包安装/卸载、自举自检、watchdog 状态快照、失败回滚与远端打包验证已经闭环，真机 `validate.ps1` 返回 `required_failures=[]`。
- `W15` 已完成：`protect_registry`、驱动保护表、registry pre-callback 阻断与真机 `192.168.2.222` 验收已经闭环，`windows-runtime-verify` 新增 `registry_protection` 必选步骤并返回 `required_failures=[]`。
- `W16` 已完成主体：`block_hash` / `block_pid` / `block_path` 已切到真实 Minifilter block map、TTL、事件回传与清空链路，但仍遗留清理平面耦合问题，需由 `W19` 收口。
- `W17` 已完成：`protect_files` 的目标路径阻断已经收口，外部文件 move / hardlink 进入受保护目录在 `192.168.2.222` 被拒绝，新增 `file_target_path_protection` 必选步骤返回 `required_failures=[]`。
- `W18` 已完成：`block_hash` 已切到 create 返回前的严格预阻断，`.222` 上 `preemptive_blocking` 再次返回 `required_failures=[]`。
- `W20` 待完成：AMSI 严格阻断当前仍依赖宿主 `scan_interface_ready=true`，不能继续按“无条件完成”计。
- 因此仓库侧 Windows 最终系统级交付当前应回退为 `doing`，待 `W17-W20` 收口后再恢复 `done`。

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
| W04.1 | 真实网络基线、连接增量与隔离执行链 | done | 不允许只改内存快照；必须生成并执行真实 Windows 防火墙/网络隔离命令 | 已完成 TCP/UDP 基线与增量事件、WfpNetwork 健康面与真实防火墙隔离/释放执行链，并已在真实 Windows 主机验证网络枚举 JSON 输出 |
| W04.2 | 注册表回滚与保护清单落盘 | done | 不允许只把 rollback 目标塞进快照；必须生成可审计的注册表回滚/保护清单 | 已完成保护清单与回滚清单 JSON 工件落盘，执行快照可回看真实工件路径，并覆盖受保护路径、回滚目标和注册表保护面 |
| W05.1 | Named Pipe / DLL / VSS / Device 资产可见性 | done | 不允许 provider 名义存在但永远返回健康；必须对每类 provider 给出真实“已实现/未实现/主机不可用”状态 | 已完成四类 provider 的真实能力探测、启动基线与差分事件；并在 `192.168.2.218` 实测拿到四类能力均为 `true` 的探测 JSON，以及命名管道、模块、VSS、PnP 设备枚举样本 |
| W05.2 | AMSI / 脚本 / ETW 篡改健康面 | done | 不允许把 `check_amsi_integrity()` 固定返回健康；必须根据 Defender/AMSI/审计实际状态给出结论 | 已完成 AMSI runtime、ScriptBlockLogging 与 ETW ingest 的真实能力探测、健康报告与 provider 收口；在 `192.168.2.218` 实测得到 `has_amsi_runtime=true`、`has_script_block_logging=false`、`has_powershell_operational_log=true`、`has_process_creation_audit=true` |
| W06.1 | 真实进程终止、挂起、隔离、取证执行链 | done | 不允许继续只改内存；必须执行真实 Windows 命令并在失败时返回错误 | 已完成真实挂起/终止/隔离/取证执行链；`192.168.2.218` 实测确认挂起/终止、文件隔离、取证打包闭环，且 `Suspend-Process` 缺失主机已改用 `NtSuspendProcess` 实现 |
| W06.2 | 预防性阻断与保护面审计 | done | 不允许只记录 block lease；必须把阻断/保护面结果写成工件用于复盘 | 已完成 hash/pid/path 阻断审计工件、network block 真实防火墙 rule group 执行/清理、保护面工件与完整性工件；`192.168.2.218` 已实测完成防火墙阻断与清理闭环 |
| W07.1 | 真实 Windows 测试主机验证、兼容性矩阵与验收脚本 | done | 不允许只跑本地单测；必须在可用 Windows 主机验证 | 已完成 `scripts/windows-runtime-verify.sh` / `scripts/windows-runtime-verify.ps1`，并在 `192.168.2.218` 实测通过；主机选择、兼容性矩阵与验收结果已记录在 `sensor-windows-validation-matrix.md` |
| W08.1 | Windows 凭据存储、DPAPI/TPM 根信任与回滚锚点方案收口 | done | 不允许继续只依赖 Linux TPM 分支；Windows 必须有独立的正式方案和代码接入面 | 已完成 Windows 专用 DPAPI 主密钥/回滚锚点路径、`provider_detail` 诊断输出、Windows TPM 可用性探测与真机 DPAPI 往返验证 |

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
4. `W04.1` `done`
5. `W04.2` `done`
6. `W05.1` `done`
7. `W05.2` `done`
8. `W06.1` `done`
9. `W06.2` `done`
10. `W07.1` `done`
11. `W08.1`
12. `W09`
13. `W10`
14. `W11`
15. `W12`
16. `W13`
17. `W14`
18. `W15`
19. `W16`

### 5.4 后续不妥协系统级研发计划

| 工作包 | 目标 | 状态 | 设计约束 | 完成判定 |
|--------|------|------|----------|----------|
| W09 | Windows 驱动工程、安装链与用户态桥接 | done | 不允许继续声明 `KernelTransport::Driver` 但实际只依赖 PowerShell/SSH；缺驱动必须显式失败 | 已入仓可构建驱动工程、安装/卸载脚本、版本协商与严格失败逻辑，`192.168.2.218` 已完成构建、安装、协议握手、卸载与 `windows-runtime-verify` 闭环 |
| W10 | 文件与注册表系统采集链 | done | 不允许继续把 `file/registry=false` 或把 rollback 只做成 JSON 工件 | 已完成 Minifilter 文件事件、注册表 journal/回滚、真实事件上报与真机回滚闭环 |
| W11 | 进程/文件/注册表保护与内核完整性 | done | 不允许继续把保护面仅落成工件；`check_ssdt_integrity`/`check_callback_tables`/`check_kernel_code` 不得再返回 `not implemented` | 已完成真实保护执行链和完整性检查，真机可验证阻断与检测结果 |
| W15 | 注册表真实保护链 | done | 不允许把静态保护面路径继续当成保护能力；必须具备真实路径下发、驱动权威状态与 pre-callback 阻断 | 已完成 `protect_registry`、保护面工件、journal 和真机阻断结果的真实收口，`192.168.2.222` 已验证通过 |
| W16 | hash/pid/path 真实阻断链 | done | 不允许继续用 userspace ledger 冒充 preemptive block；TTL 与 block map 必须在 minifilter 权威状态里生效 | 已完成 Minifilter 权威 block map、TTL、状态查询、事件回传与真机阻断闭环，`clear_all_blocks` 可同时清空 firewall 与 block entry |
| W17 | 受保护目录目标路径阻断收口 | done | 不允许继续只看源路径；rename/move/link 进入受保护目录必须在目标路径上被拒绝 | 已完成目标路径绕过收口，外部 move / hardlink 进入受保护目录被拒绝 |
| W18 | hash 严格 pre-create 阻断链 | done | 不允许继续把 `post-create + FltCancelFileOpen` 描述成 pre-op | 已完成 create 返回前哈希阻断，`AegisFilePostCreate` 不再承担阻断职责 |
| W19 | block 清理平面解耦 | todo | 不允许继续让 Minifilter 故障阻塞 firewall release | 完成后 `clear_all_blocks` 分平面释放并显式暴露部分成功 |
| W20 | AMSI 严格阻断收口 | todo | 不允许继续在 `scan_interface_ready=false` 时跳过恶意样本阻断并写成完成 | 完成后 AMSI 严格阻断在 `.222` 上无条件验收通过 |
| W12 | 脚本/AMSI/内存信号闭环 | done | 不允许继续把 `AmsiScript`/`MemorySensor` 固定为未实现；脚本能力不能只停留在日志健康面 | 已完成共享脚本解码、AMSI 扫描/阻断、PowerShell 4104 事件桥接、内存快照增量事件与真机验收 |
| W13 | 打包、看门狗、自举与发布前自检 | done | 不允许继续把系统级交付等同于单个 `powershell.exe` 运行时；安装链必须显式校验驱动/服务/依赖 | 已完成开发包 manifest/install/uninstall/validate、`aegis-agentd` 首启配置与 bootstrap 检查、`aegis-watchdog --once` 状态快照，以及 `192.168.2.218` 真机安装/回滚闭环 |
| W14 | 正式签名、兼容性矩阵与发布验证 | done | 不允许把自签名或未验签产物标记为正式发布；无签名凭据必须严格失败 | 已完成 release manifest、签名/验签脚本、安装前后 release gate、支持矩阵文档与 `192.168.2.218` 真机发布验收 |

## 6. Windows 完成判定

当前可以诚实判定为：

- Windows 平台骨架与测试基线：`done`
- Windows 真实执行链与能力探测：`done`
- Windows 真实进程差分与隐藏进程检测：`done`
- Windows 真实 ETW/审计健康检查与进程审计事件链：`done`
- Windows 真实网络基线、连接增量与隔离执行链：`done`
- Windows 注册表回滚与保护审计工件：`done`
- Windows Named Pipe / DLL / VSS / Device 资产可见性：`done`
- Windows AMSI / ScriptBlock / ETW 健康面：`doing`
- Windows 真实挂起/终止/隔离/取证执行链：`done`
- Windows 预防性阻断与保护面审计：`doing`
- Windows 注册表真实保护链：`done`
- Windows 受保护目录目标路径阻断：`done`
- Windows 真机验收、兼容性矩阵与验收脚本：`done`
- Windows 凭据存储、DPAPI/TPM 根信任与回滚锚点：`done`
- Windows 驱动工程、安装链与用户态桥接：`done`
- Windows 文件与注册表系统采集链：`done`
- Windows 进程/文件保护与内核完整性：`done`
- Windows 脚本/AMSI/内存信号闭环：`done`
- Windows 打包、看门狗、自举与发布前自检：`done`
- Windows 真实系统级交付：`doing`
- Windows 正式签名、发布验证：`done`

因此，本文件中的平台状态应保持：

- `W01-W02 = done`
- `W03.1 = done`
- `W03.2 = done`
- `W03.3 = done`
- `W04.1 = done`
- `W04.2 = done`
- `W05.1 = done`
- `W05.2 = done`
- `W06.1 = done`
- `W06.2 = done`
- `W07.1 = done`
- `W08.1 = done`
- `W09 = done`
- `W10 = done`
- `W11 = done`
- `W15 = done`
- `W16 = done`
- `W17 = done`
- `W18 = done`
- `W19 = todo`
- `W20 = todo`
- `W12 = done`
- `W13 = done`
- `W14 = done`

## 7. Windows 后续执行顺序

Windows 专项的最终目标不变：

1. 先把运行时改成“真实能力、真实失败、真实工件”
2. 再补齐真正的 Windows 驱动工程、文件/注册表/脚本/内存系统采集与保护链
3. 先收口 `W19-W20` 两个硬化缺口，修正 block 清理平面与 AMSI 严格阻断
4. 再保持 `block_hash/pid/path`、注册表保护、目标路径阻断、脚本/内存、安装/签名链在新增 Windows 主机上的持续回归验收
5. 再将真机兼容性矩阵从 `192.168.2.218 / 192.168.2.222` 扩展到更多 Windows 版本与硬件形态
