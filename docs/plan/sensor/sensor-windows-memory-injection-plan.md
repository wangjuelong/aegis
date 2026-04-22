# Aegis Sensor Windows 内存注入 / YARA / 映射采集闭环计划

> 编号：`W26`
> 状态：`done`
> 日期：`2026-04-22`

## 1. 缺口定义

当前 Windows 内存侧已从 `memory-hot / memory-growth` 资源信号推进到“资源 + 区域安全信号”双链路，已补齐：

- 私有可执行内存区域
- RWX / RX 私有页
- 映像映射异常
- 基于内存内容或区域摘要的 YARA 信号

## 2. 目标

交付 Windows 内存行为采集链，使内存域具备基础的注入、映射和 YARA 检测能力。

## 3. 设计约束

- 不允许继续把资源占用当成内存安全检测。
- 不允许只扫总量，不扫区域属性。
- 不允许把 YARA 接口留成空壳。
- 必须显式区分“资源类内存信号”和“安全类内存信号”。

## 4. 研发范围

1. 新增虚拟内存区域枚举。
2. 识别私有可执行页、RWX、映像映射异常。
3. 为可扫描区域生成摘要并接入 YARA 信号。
4. 更新验证脚本与文档。

## 5. 具体实现

### 5.1 数据源

- `VirtualQueryEx`
- `ReadProcessMemory`
- 现有 YARA 调度能力

### 5.2 采集维度

- `memory-hot`
- `memory-growth`
- `memory-private-exec`
- `memory-rwx`
- `memory-image-anomaly`
- `memory-yara-match`

### 5.3 输出字段

- `pid`
- `name`
- `region_base`
- `region_size`
- `allocation_type`
- `protection`
- `memory_type`
- `mapped_path`
- `sha256`
- `yara_rule`
- `path`

## 6. 验证要求

- 单测覆盖区域分类与 YARA 结果解析。
- 真机验证：
  - PowerShell/自定义进程申请可执行私有内存
  - 受控样本触发 YARA
- 数据采集文档更新内存域。

## 7. 完成结果

- 新增 `scripts/windows/query-memory-regions.ps1`，通过 `OpenProcess / VirtualQueryEx / ReadProcessMemory / GetMappedFileName` 枚举可执行区域。
- `MemorySensor` 已新增 `memory-private-exec / memory-rwx / memory-image-anomaly / memory-yara-match` 四类事件。
- 内存规则命中已基于区域样本内容生成真实规则名，不再只停留在资源占用信号。
- 本地单测已新增 `windows_poll_events_emits_memory_region_and_yara_signals`，`cargo test -p aegis-platform windows_ -- --nocapture` 通过。
- 真机 `.218` 已验证 `query-memory-regions.ps1` 能返回真实可执行区域、保护属性、映射路径与样本数据。
- Windows 数据采集清单已补充内存区域数据源与 4 类安全事件维度。

## 8. 完成判定

1. 内存安全类事件已进入 `poll_events()` 主链。
2. 资源类和安全类内存事件已明确区分。
3. 代码提交与文档提交各一次。
