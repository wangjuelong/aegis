# Aegis Sensor Windows 内存注入 / YARA / 映射采集闭环计划

> 编号：`W26`
> 状态：`todo`
> 日期：`2026-04-22`

## 1. 缺口定义

当前 Windows 内存侧只有 `memory-hot` / `memory-growth` 两种资源信号，不足以满足 EDR 对内存注入与恶意映射的要求，缺少：

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

## 7. 完成判定

1. 内存安全类事件进入 `poll_events()` 主链。
2. 资源类和安全类内存事件明确区分。
3. 代码提交与文档提交各一次。
