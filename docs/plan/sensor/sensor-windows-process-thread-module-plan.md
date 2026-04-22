# Aegis Sensor Windows 进程线程模块细粒度采集闭环计划

> 编号：`W24`
> 状态：`todo`
> 日期：`2026-04-22`

## 1. 缺口定义

当前 Windows 进程主链由 `Win32_Process` 快照差分和 `4688` 审计组成，模块主链由进程模块清单差分组成，缺少更细粒度的线程与进程上下文：

- 线程创建/终止
- 更完整的进程镜像路径、签名与父子上下文
- 更贴近事件时刻的模块加载视图

## 2. 目标

交付 Windows 进程/线程/模块的细粒度采集链，使该域达到“适合 EDR 检测与故事线构建”的最低闭环。

## 3. 设计约束

- 不允许继续只靠快照差分冒充实时进程监控。
- 不允许只有模块可见/消失，没有线程维度。
- 不允许丢失进程镜像路径和父进程上下文。
- 不允许把“无法获取签名”写成签名正常。

## 4. 研发范围

1. 新增线程 inventory / delta 采集。
2. 补齐进程镜像路径、父进程、签名、命令行等上下文。
3. 扩展模块事件字段，补齐签名与宿主进程信息。
4. 更新 Windows 数据采集文档与总计划状态。

## 5. 具体实现

### 5.1 数据源

- `Win32_Process`
- `Win32_Thread` 或等价线程视图
- Security `4688`
- `Get-Process.Modules`
- `Get-AuthenticodeSignature`

### 5.2 采集维度

- `process-start`
- `process-exit`
- `process-audit`
- `thread-start`
- `thread-exit`
- `module-visible`
- `module-gone`

### 5.3 输出字段

- 进程：`pid`、`ppid`、`name`、`image_path`、`cmdline`、`signer_subject`、`signature_status`
- 线程：`thread_id`、`process_id`、`start_address`、`thread_state`
- 模块：`process_id`、`process_name`、`module_path`、`signer_subject`、`signature_status`

## 6. 验证要求

- 单测覆盖线程、进程、模块解析。
- 真机验证：
  - 新进程拉起/退出
  - 新线程创建
  - 模块动态加载
- 文档同步更新采集维度与字段说明。

## 7. 完成判定

1. 线程事件进入 `poll_events()` 主链。
2. 进程与模块事件补齐镜像路径和签名字段。
3. 代码提交与文档提交各一次。
