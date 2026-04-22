# Aegis Sensor Windows 数据采集清单

> 版本：1.0  
> 日期：2026-04-22  
> 状态：生效  
> 分类：内部 / 机密  
> 口径：仅描述当前仓库代码已经实现并进入 Windows Sensor 运行链的采集能力，不沿用终态方案中的未落地项。

---

## 1. 文档范围

本文档基于当前 Windows 平台实现，整理 `aegis-platform` 中已经接入 `poll_events()` 运行链的数据采集能力，聚焦两件事：

1. 采集的数据源
2. 采集到的数据维度

本文档不描述响应动作、阻断配置 API、打包发布流程，也不把“仅在方案文档中存在、但当前代码未持续上送”的能力写成已交付能力。

---

## 2. 采集的数据源

| 数据域 | 当前数据源 | 采集方式 | 当前输出的关键字段 |
|--------|------------|----------|--------------------|
| 进程快照 | `Win32_Process` | `Get-CimInstance Win32_Process` 周期性快照差分 | `process_id`、`parent_process_id`、`name`、`command_line` |
| 进程审计 | Windows Security 日志 `4688` | `Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688 }` 增量拉取 | `record_id`、`process_name`、`command_line` |
| 认证 | Windows Security 日志 `4624 / 4625 / 4672 / 4768` | `Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624,4625,4672,4768 }` 增量拉取 | `record_id`、`event_id`、`target_user`、`subject_user`、`logon_type`、`source_ip`、`status` |
| 文件 | Aegis Minifilter 通信端口 `\\AegisFileMonitorPort` | 通过 `fltlib` 向 Minifilter 查询文件事件队列 | `sequence`、`timestamp`、`process_id`、`operation`、`path` |
| 注册表 | Aegis 内核驱动 Registry Callback 日志 | 通过设备 `\\.\AegisSensor` 查询注册表 journal | `sequence`、`timestamp`、`operation`、`key_path`、`value_name`、`blocked`、`old_value`、`new_value` |
| 脚本 | PowerShell Operational 日志 `4104` | `Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104 }` 增量拉取 | `record_id`、`process_id`、`script_block_id`、`path`、`script_text` |
| 脚本判定 | AMSI 扫描接口 | 对已拼装的脚本内容执行 AMSI 扫描 | `amsi_result`、`blocked_by_admin`、`malware`、`should_block`、`scan_interface_ready`、`strict_block_ready` |
| 内存 | 进程内存快照 | 内置 `query-memory-snapshot.ps1` 采集进程内存指标 | `process_id`、`process_name`、`working_set_bytes`、`private_memory_bytes`、`virtual_memory_bytes`、`paged_memory_bytes`、`path` |
| 网络 | TCP/UDP 连接清单 | `Get-NetTCPConnection` + `Get-NetUDPEndpoint` 周期性快照差分 | `protocol`、`local_address`、`local_port`、`remote_address`、`remote_port`、`state`、`owning_process` |
| Named Pipe | `\\.\pipe\` 目录 | `Get-ChildItem -Path '\\.\pipe\'` 周期性快照差分 | `pipe_name` |
| 模块 | 进程模块清单 | `Get-Process | $_.Modules` 周期性快照差分 | `process_id`、`process_name`、`module_path` |
| VSS | `Win32_ShadowCopy` | `Get-CimInstance Win32_ShadowCopy` 周期性快照差分 | `snapshot_id`、`volume_name` |
| 设备 | PnP 设备清单 | `Get-PnpDevice` 周期性快照差分 | `instance_id`、`class`、`friendly_name`、`status` |

---

## 3. 采集到的数据维度

### 3.1 进程

| 采集维度 | 当前 operation | 来源 | 关键字段 |
|----------|----------------|------|----------|
| 进程创建 | `process-start` | `Win32_Process` 快照差分 | `pid`、`ppid`、`name`、`cmdline` |
| 进程终止 | `process-exit` | `Win32_Process` 快照差分 | `pid`、`ppid`、`name`、`cmdline` |
| 进程创建审计 | `process-audit` | Security `4688` | `record_id`、`process`、`cmdline` |

### 3.2 文件

Windows 文件事件由 Minifilter 驱动通过队列上送，用户态统一编码为 `file-<operation>`。

| 采集维度 | 当前 operation | 来源 | 关键字段 |
|----------|----------------|------|----------|
| 文件打开 | `file-open` | Minifilter | `sequence`、`pid`、`path` |
| 文件写入 | `file-write` | Minifilter | `sequence`、`pid`、`path` |
| 文件重命名 | `file-rename` | Minifilter | `sequence`、`pid`、`path` |
| 文件删除 | `file-delete` | Minifilter | `sequence`、`pid`、`path` |
| 按进程阻断文件访问 | `file-block-pid` | Minifilter | `sequence`、`pid`、`path` |
| 按路径阻断文件访问 | `file-block-path` | Minifilter | `sequence`、`pid`、`path` |
| 受保护目录创建阻断 | `file-block-create` | Minifilter | `sequence`、`pid`、`path` |
| 按哈希阻断文件访问 | `file-block-hash` | Minifilter | `sequence`、`pid`、`path` |
| 受保护目录写入阻断 | `file-block-write` | Minifilter | `sequence`、`pid`、`path` |
| 受保护目录重命名阻断 | `file-block-rename` | Minifilter | `sequence`、`pid`、`path` |
| 受保护目录硬链接阻断 | `file-block-link` | Minifilter | `sequence`、`pid`、`path` |
| 受保护目录删除阻断 | `file-block-delete` | Minifilter | `sequence`、`pid`、`path` |

### 3.3 认证

| 采集维度 | 当前 operation | 来源 | 关键字段 |
|----------|----------------|------|----------|
| 登录成功 | `auth-logon-success` | Security `4624` | `record_id`、`event_id`、`target_user`、`target_domain`、`subject_user`、`subject_domain`、`logon_type`、`logon_process`、`auth_package`、`source_ip`、`source_port`、`workstation` |
| 登录失败 | `auth-logon-failure` | Security `4625` | `record_id`、`event_id`、`target_user`、`target_domain`、`subject_user`、`subject_domain`、`logon_type`、`logon_process`、`auth_package`、`source_ip`、`source_port`、`workstation`、`status`、`sub_status`、`failure_reason` |
| 特权授予 | `auth-privilege-assigned` | Security `4672` | `record_id`、`event_id`、`subject_user`、`subject_domain`、`privileges` |
| Kerberos TGT 申请 | `auth-kerberos-tgt` | Security `4768` | `record_id`、`event_id`、`target_user`、`target_domain`、`source_ip`、`source_port`、`status`、`ticket_encryption_type`、`ticket_options`、`service_name` |

### 3.4 注册表

Windows 注册表事件由内核驱动的 `CmRegisterCallbackEx` journal 上送，用户态统一编码为 `registry-*` 或 `registry-block-*`。

| 采集维度 | 当前 operation | 来源 | 关键字段 |
|----------|----------------|------|----------|
| 注册表值设置 | `registry-set` | Registry Callback | `sequence`、`key`、`value`、`old`、`new` |
| 注册表值删除 | `registry-delete` | Registry Callback | `sequence`、`key`、`value`、`old`、`new` |
| 注册表键创建 | `registry-create-key` | Registry Callback | `sequence`、`key`、`value`、`old`、`new` |
| 注册表键删除 | `registry-delete-key` | Registry Callback | `sequence`、`key`、`value`、`old`、`new` |
| 注册表值设置阻断 | `registry-block-set` | Registry Callback | `sequence`、`blocked=true`、`key`、`value`、`old`、`new` |
| 注册表值删除阻断 | `registry-block-delete` | Registry Callback | `sequence`、`blocked=true`、`key`、`value`、`old`、`new` |
| 注册表键创建阻断 | `registry-block-create-key` | Registry Callback | `sequence`、`blocked=true`、`key`、`value`、`old`、`new` |
| 注册表键删除阻断 | `registry-block-delete-key` | Registry Callback | `sequence`、`blocked=true`、`key`、`value`、`old`、`new` |

### 3.5 脚本

脚本事件先从 PowerShell `4104` 日志取原始脚本块，再做分块拼装和 AMSI 扫描，最终输出脚本判定事件。

| 采集维度 | 当前 operation | 来源 | 关键字段 |
|----------|----------------|------|----------|
| 脚本允许 | `script-allow` | `4104` + AMSI | `record_id`、`pid`、`script_block_id`、`decision`、`risk`、`amsi_result`、`layers`、`tokens`、`sha256`、`path`、`preview` |
| 脚本告警 | `script-alert` | `4104` + AMSI | 同上 |
| 脚本阻断 | `script-block` | `4104` + AMSI | 同上 |

### 3.6 内存

| 采集维度 | 当前 operation | 来源 | 关键字段 |
|----------|----------------|------|----------|
| 高热点内存进程 | `memory-hot` | 进程内存快照 | `pid`、`name`、`private_memory_bytes`、`working_set_bytes`、`path` |
| 内存快速增长 | `memory-growth` | 进程内存快照 | `pid`、`name`、`private_memory_bytes`、`private_delta_bytes`、`working_set_bytes`、`working_delta_bytes`、`path` |

### 3.7 网络

| 采集维度 | 当前 operation | 来源 | 关键字段 |
|----------|----------------|------|----------|
| 新建连接/端点可见 | `network-open` | TCP/UDP 连接清单差分 | `protocol`、`local_address`、`local_port`、`remote_address`、`remote_port`、`state`、`owning_process` |
| 连接关闭/端点消失 | `network-close` | TCP/UDP 连接清单差分 | 同上 |

### 3.8 IPC / 模块 / VSS / 设备

| 采集维度 | 当前 operation | 来源 | 关键字段 |
|----------|----------------|------|----------|
| Named Pipe 可见 | `pipe-visible` | `\\.\pipe\` 清单差分 | `pipe_name` |
| Named Pipe 消失 | `pipe-gone` | `\\.\pipe\` 清单差分 | `pipe_name` |
| 模块可见 | `module-visible` | 进程模块清单差分 | `process_id`、`process_name`、`module_path` |
| 模块消失 | `module-gone` | 进程模块清单差分 | `process_id`、`process_name`、`module_path` |
| VSS 快照可见 | `shadow-visible` | `Win32_ShadowCopy` 差分 | `snapshot_id`、`volume_name` |
| VSS 快照消失 | `shadow-gone` | `Win32_ShadowCopy` 差分 | `snapshot_id`、`volume_name` |
| PnP 设备可见 | `device-visible` | `Get-PnpDevice` 差分 | `instance_id`、`class`、`friendly_name`、`status` |
| PnP 设备消失 | `device-gone` | `Get-PnpDevice` 差分 | `instance_id`、`class`、`friendly_name`、`status` |

---

## 4. 辅助一致性视图

以下能力已实现，但不走常规 `poll_events()` 持续事件流，单独作为辅助检查能力存在：

| 能力 | 数据源 | 输出 |
|------|--------|------|
| 隐藏进程一致性检查 | `Win32_Process` + `tasklist /FO CSV /NH` 双视图比对 | `pid`、`reason` |

---

## 5. 当前未纳入持续采集文档的项

以下能力在终态架构文档中出现过，但当前 Windows 持续上送主链未作为独立数据源落地到本清单：

- WMI Activity 原始事件流
- Task Scheduler 原始事件流
- DNS Client 原始事件流
- 独立的 Sysmon 共存采集流

这些项不应在当前版本对外表述为“已持续采集”。
