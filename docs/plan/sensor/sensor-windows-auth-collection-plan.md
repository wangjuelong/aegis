# Aegis Sensor Windows 认证采集闭环计划

> 编号：`W22`
> 状态：`todo`
> 日期：`2026-04-22`

## 1. 缺口定义

当前 Windows 平台运行链没有认证采集域，无法覆盖 EDR 基础登录面：

- 登录成功
- 登录失败
- 特权授予
- Kerberos TGT 申请

这与 `docs/architecture` 和 `docs/技术方案` 中对 Windows 认证采集的要求不一致。

## 2. 目标

交付真实 Windows 认证采集链，基于 Security Event Log 持续产出认证事件，并进入统一 `poll_events()` 事件流。

## 3. 设计约束

- 不允许把认证采集写成“文档有、代码无”的名义 provider。
- 不允许只做健康探测，不做事件增量。
- 不允许只采单一事件号，必须覆盖 `4624 / 4625 / 4672 / 4768`。
- 不允许丢失关键认证字段，至少要保留登录类型、目标账户、源地址、认证包、Kerberos 票据结果等核心字段。

## 4. 研发范围

1. 新增 Windows 认证 provider、能力探测与健康状态。
2. 新增 Security Event Log 增量游标与事件拉取。
3. 解析认证相关 XML/EventData，标准化为统一 subject/payload。
4. 为 `4624 / 4625 / 4672 / 4768` 建立清晰的 operation 命名。
5. 补齐单测与真机验证脚本。

## 5. 具体实现

### 5.1 数据源

- `Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624,4625,4672,4768 }`

### 5.2 采集维度

- `auth-logon-success`
- `auth-logon-failure`
- `auth-privilege-assigned`
- `auth-kerberos-tgt`

### 5.3 输出字段

- `record_id`
- `event_id`
- `target_user`
- `target_domain`
- `subject_user`
- `subject_domain`
- `logon_type`
- `logon_process`
- `authentication_package`
- `source_ip`
- `source_port`
- `workstation`
- `status`
- `sub_status`
- `ticket_encryption_type`
- `ticket_options`

## 6. 验证要求

- 本地单测覆盖 4 类事件解析。
- `poll_events()` 能稳定增量拉取，不重复、不回卷。
- 真机通过成功登录、失败登录、提权、Kerberos 样本验证事件落地。
- 文档更新 `sensor-windows-plan.md` 与 Windows 数据采集清单。

## 7. 完成判定

满足以下条件才可标记 `done`：

1. 代码、测试、真机验证全部完成。
2. `WindowsPlatform` provider health 对认证面真实可见。
3. Windows 数据采集文档新增认证域。
4. 提交顺序满足“代码提交一次 + 文档提交一次”。
