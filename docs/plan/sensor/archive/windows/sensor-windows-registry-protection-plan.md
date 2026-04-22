# Windows 注册表真实保护研发计划

## 0. 状态

- 已完成
- 代码提交：`9061fea`
- 真机主机：`192.168.2.222`
- 远端验收时间：`2026-04-21 11:17:56 +08:00`
- 验收 ID：`windows-runtime-20260421-111721`

## 1. 目标

把 Windows 当前“注册表 journal + rollback + 静态保护面工件”的实现，升级为真正的注册表保护链路：

- 用户态显式下发受保护注册表路径
- 内核驱动维护权威保护表
- 注册表 pre-callback 在写入、删除、创建、删除键之前实时判定并拒绝
- 阻断结果进入事件流与审计工件
- `PlatformProtection`/`provider_health`/运行时验证全部反映真实状态

## 2. 当前缺口

以下缺口已在本轮收口，保留为计划与实际交付的对照基线：

- `PlatformProtection` 没有 `protect_registry`，平台接口层不存在一等能力。
- `aegis_sensor_kmod.c` 的注册表回调只记录 `RegNtPreSetValueKey` / `RegNtPreDeleteValueKey`，并始终返回 `STATUS_SUCCESS`。
- 驱动控制面没有注册表保护相关 IOCTL、状态回执和清空能力。
- `windows.rs` 只把静态路径写入 `registry_protection_surface` 工件，没有真实已下发保护路径。
- `windows-runtime-verify.ps1` 没有注册表保护阻断验收。

## 3. 不妥协设计

- 不接受“只写工件、不阻断”的假保护。
- 不接受把注册表保护塞进现有 rollback 语义里复用；保护与回滚必须是独立控制面。
- 不接受静态保护面冒充运行时状态；工件必须记录真实受保护路径、协议版本、驱动回执。
- 不接受系统级模式下静默降级；驱动或回调面不满足时直接失败。

## 4. 研发范围

### 4.1 平台接口与状态面

- 为 `PlatformProtection` 增加 `protect_registry(&self, selectors: &[String]) -> Result<()>`
- 为 `PlatformExecutionSnapshot` 增加 `protected_registry_paths: Vec<String>`
- 为 Windows 保护面工件和 registry rollback 工件增加真实 `protected_registry_paths`
- 为 mock/linux/macos 提供编译通过且语义明确的实现

### 4.2 驱动协议与控制面

- 在 `aegis_windows_driver_protocol.h` 增加：
  - `AEGIS_IOCTL_PROTECT_REGISTRY_PATH`
  - `AEGIS_IOCTL_CLEAR_PROTECTED_REGISTRY_PATHS`
- 增加请求/响应结构：
  - 注册表保护写入请求
  - 注册表保护清空响应
- 复用 `QUERY_STATUS` 回执返回 `ProtectedRegistryPathCount`，不再单独拆分新的查询 IOCTL

### 4.3 驱动数据面

- 驱动维护大小受限、大小写无关、去重的受保护注册表路径表
- 保护匹配统一使用内核路径（`\REGISTRY\MACHINE\...` / `\REGISTRY\USER\...`）
- 扩展注册表回调覆盖：
  - `RegNtPreSetValueKey`
  - `RegNtPreDeleteValueKey`
  - `RegNtPreCreateKeyEx`
  - `RegNtPreDeleteKey`
- 命中受保护路径时：
  - 记录 `block-*` 事件到 journal
  - 返回 `STATUS_ACCESS_DENIED`

### 4.4 用户态桥接

- 新增 `scripts/windows-configure-registry-protection.ps1`
- 统一通过 `Mode=status/protect/clear` 完成状态查询、路径下发与保护清空
- `windows.rs` 通过嵌入脚本调用驱动控制面
- `record_windows_protection_surface_artifact()` 记录真实保护路径而不是静态清单

### 4.5 验证与回归

- Rust 单元测试：
  - 快照记录真实 `protected_registry_paths`
  - 工件内容不再依赖静态常量
- PowerShell 真机验收：
  - 下发保护路径
  - 尝试创建/修改/删除值和键
  - 确认被拒绝
  - 查询 journal 中出现 `block-*` 事件
- `windows-runtime-verify.ps1` 增加 `registry_protection` 必选步骤

## 5. 交付物

- `crates/aegis-platform/src/traits.rs`
- `crates/aegis-platform/src/windows.rs`
- `crates/aegis-platform/src/mock.rs`
- `crates/aegis-platform/src/linux.rs`
- `crates/aegis-platform/src/macos.rs`
- `windows/driver/include/aegis_windows_driver_protocol.h`
- `windows/driver/src/aegis_sensor_kmod.c`
- `scripts/windows-configure-registry-protection.ps1`
- `scripts/windows-query-registry-events.ps1`
- `scripts/windows-runtime-verify.ps1`

## 6. 实际交付结果

- `PlatformProtection` 已新增 `protect_registry(&self, selectors: &[String]) -> Result<()>`，并把真实受保护路径写入 `PlatformExecutionSnapshot.protected_registry_paths`。
- Windows 驱动协议已新增 `AEGIS_IOCTL_PROTECT_REGISTRY_PATH` / `AEGIS_IOCTL_CLEAR_PROTECTED_REGISTRY_PATHS`，并在 `QUERY_STATUS` 中回传 `ProtectedRegistryPathCount`。
- 内核驱动已维护受保护注册表路径表，并把 `RegNtPreSetValueKey`、`RegNtPreDeleteValueKey`、`RegNtPreCreateKeyEx`、`RegNtPreDeleteKey` 纳入统一 pre-callback 阻断。
- 命中受保护路径时，驱动会写入带 `blocked=true` 的 registry journal 记录，并返回 `STATUS_ACCESS_DENIED`。
- `windows-configure-registry-protection.ps1` 已统一提供 `status/protect/clear` 三种模式，`windows.rs` 通过该脚本下发真实内核路径，不再写入静态保护面常量。
- `windows-runtime-verify.ps1` 已新增 `registry_protection` 必选步骤，并在 `192.168.2.222` 上验证受保护键写入被拒绝、journal 命中 `blocked=true`、最终 `required_failures=[]`。

## 7. 完成判定

- `protect_registry` 存在且 Windows 平台真实执行。
- 受保护路径的注册表创建、修改、删除操作在真机 `192.168.2.222` 上被拒绝。
- `provider_health(RegistryCallback)` 和 protection 工件反映真实保护状态。
- 审计工件中的注册表保护面来自真实已下发路径，不再来自静态常量。
- `windows-runtime-verify.sh` 通过且 `required_failures=[]`。
