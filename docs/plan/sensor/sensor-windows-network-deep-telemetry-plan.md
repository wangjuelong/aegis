# Aegis Sensor Windows 深度网络遥测闭环计划

> 编号：`W23`
> 状态：`todo`
> 日期：`2026-04-22`

## 1. 缺口定义

当前 Windows 网络侧只有连接清单差分，只能给出 `network-open/network-close`，不能满足 EDR 对网络细粒度遥测的要求，尤其缺少：

- DNS 查询/响应
- TLS/SNI 元数据
- 更接近建立时刻的连接事件

## 2. 目标

交付 Windows 深度网络遥测链，在现有连接差分基础上补齐 DNS 与 TLS 元数据，使 Windows 网络面达到可用于 EDR 分析的最低闭环。

## 3. 设计约束

- 不允许继续把连接清单差分描述成 WFP 深度遥测。
- 不允许只补健康状态，不补事件。
- 不允许把无法稳定获取的字段硬编码为成功。
- DNS 与 TLS 元数据必须明确区分“已采集字段”和“当前宿主不支持字段”。

## 4. 研发范围

1. 补齐 DNS Client Operational 增量采集。
2. 补齐 TLS/Schannel 相关握手元数据采集。
3. 扩展网络 provider 事件类型，不再仅有 `network-open/network-close`。
4. 补齐真机验证脚本与 Windows 数据采集文档。

## 5. 具体实现

### 5.1 数据源

- `Get-NetTCPConnection` / `Get-NetUDPEndpoint`
- `Microsoft-Windows-DNS-Client/Operational`
- `Microsoft-Windows-Schannel/Operational` 或等价 TLS 日志面

### 5.2 采集维度

- `network-open`
- `network-close`
- `dns-query`
- `dns-response`
- `tls-client-hello`
- `tls-session-established`

### 5.3 输出字段

- 连接字段：`protocol`、`local_address`、`local_port`、`remote_address`、`remote_port`、`state`、`owning_process`
- DNS 字段：`query_name`、`query_type`、`query_status`、`answer_count`、`answers`
- TLS 字段：`server_name`、`protocol_version`、`cipher_suite`、`cert_subject`、`cert_issuer`

## 6. 验证要求

- 单测覆盖 DNS/TLS 事件解析。
- 真机验证：
  - `nslookup` / `Resolve-DnsName`
  - HTTPS 访问
  - 连接建立与关闭
- Windows 数据采集文档更新网络域。

## 7. 完成判定

1. DNS 事件进入 `poll_events()` 主链。
2. TLS 元数据进入 `poll_events()` 主链。
3. 连接清单差分继续保留，但不再是唯一网络数据源。
4. 代码提交与文档提交各一次。
