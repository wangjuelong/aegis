# Aegis Sensor Windows Device / Pipe / VSS 行为采集闭环计划

> 编号：`W25`
> 状态：`todo`
> 日期：`2026-04-22`

## 1. 缺口定义

当前 Windows 对 Pipe、Device、VSS 只有“可见/消失”资产视图，缺少更适合 EDR 的行为级事件：

- Pipe 打开/写入/删除
- 设备挂载变化
- VSS 创建/删除尝试与结果

## 2. 目标

交付 Pipe / Device / VSS 的行为级采集闭环，使这些域不再停留在资产枚举层。

## 3. 设计约束

- 不允许继续只做 visibility inventory。
- 不允许把文件事件中的 Pipe/VSS 行为丢弃。
- 设备域必须至少包含挂载变化，不能只剩 PnP 可见性。
- 行为事件必须给出关联进程或命令来源，只在宿主无法解析时才显式标记缺失。

## 4. 研发范围

1. 基于 Minifilter 文件事件识别 Pipe 行为。
2. 补齐卷/设备挂载变化与设备可见性联动。
3. 基于进程审计 + VSS inventory 差分补齐快照创建/删除行为。
4. 更新验证脚本与数据采集文档。

## 5. 具体实现

### 5.1 数据源

- Minifilter 文件事件队列
- `\\.\pipe\` 清单
- `Win32_ShadowCopy`
- `Get-PnpDevice`
- `Get-Volume` / `Win32_Volume`
- Security `4688`

### 5.2 采集维度

- `pipe-visible`
- `pipe-gone`
- `pipe-open`
- `pipe-write`
- `shadow-visible`
- `shadow-gone`
- `shadow-create`
- `shadow-delete`
- `device-visible`
- `device-gone`
- `device-mount-add`
- `device-mount-remove`
- `device-mount-change`

### 5.3 输出字段

- Pipe：`pipe_name`、`pid`、`operation`
- VSS：`snapshot_id`、`volume_name`、`pid`、`process_name`、`command_line`
- Device：`instance_id`、`class`、`friendly_name`、`status`、`drive_letter`、`volume_label`、`mount_path`

## 6. 验证要求

- 真机验证：
  - 创建/访问命名管道
  - 创建/删除 VSS 快照
  - 插拔设备或挂载/卸载卷
- 数据采集文档更新 Pipe/Device/VSS 行为域。

## 7. 完成判定

1. Pipe 行为不再只有 visible/gone。
2. Device 行为包含挂载变化。
3. VSS 行为包含 create/delete。
4. 代码提交与文档提交各一次。
