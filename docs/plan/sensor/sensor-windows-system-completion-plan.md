# Windows System Completion Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 将 Windows 平台从当前“用户态运行时闭环”推进到“内核驱动 + 真实系统采集 + 自保护 + 正式签名与兼容性验证”的完整交付状态。

**Architecture:** 用户态继续由 `crates/aegis-platform` / `crates/aegis-core` 承担调度、检测与响应编排；新增 Windows 驱动工程承载 Minifilter / 注册表回调 / 进程保护 / 内核完整性采集；驱动与用户态通过严格版本化的控制通道通信，系统级模式下禁止静默退回 PowerShell 假实现。

**Tech Stack:** Rust 用户态、Windows WDM/Minifilter/WFP 驱动工程、PowerShell/SSH 真机验收、MSBuild/Windows Kits/Signtool、MSI/INF/CAT 打包与签名校验。

## 当前进度（2026-04-20）

| 工作包 | 状态 | 结果 |
|--------|------|------|
| `W09` | `done` | 已完成驱动工程、安装链、协议握手与 `driver mode` 严格失败闭环 |
| `W10` | `done` | 已完成 Minifilter 文件事件、注册表 journal/rollback 真实链路，以及 Rust 平台层接入 |
| `W11` | `pending` | 保护面与内核完整性检查仍需继续实现 |
| `W12` | `pending` | AMSI provider / memory signal 仍需继续实现 |
| `W13` | `pending` | 安装、自检、watchdog、自举链仍需继续实现 |
| `W14` | `pending` | 正式签名、兼容性矩阵与发布门禁仍需继续实现 |

---

## 1. 不妥协约束

- 不允许继续把 `KernelTransport::Driver`、`supports_registry`、`supports_amsi` 等能力声明为已支持，但运行时仍然只依赖 PowerShell/SSH。
- 不允许继续用审计工件替代真实系统级能力。`registry_rollback`、`protect_process`、`protect_files`、`block_hash/pid/path` 必须具备真实执行链，否则状态保持 `todo/doing`。
- 不允许在系统级模式下静默降级到用户态替代实现；缺驱动、缺签名、缺依赖时必须显式失败并暴露诊断。
- 不允许把开发签名、自签名或未验收兼容矩阵误记为“正式签名/正式发布”。
- 不允许引入兜底路径掩盖真实失败；所有外部依赖缺失都必须以结构化错误暴露。

## 2. 当前缺口

- 缺少入仓的 Windows 驱动工程、安装清单、控制面协议与版本协商。
- 缺少真实文件监控、注册表 journal/回滚、脚本执行阻断、内存信号采集。
- 缺少真实的进程/文件/注册表保护和回调表、内核代码、ETW 篡改完整性检查。
- 缺少正式 MSI/驱动打包、驱动签名、ELAM 依赖校验、支持矩阵验收。
- 测试机 `192.168.2.218` 可用；`192.168.1.4` 当前不可达，不能作为主验收机。
- 当前仓库没有可用的正式代码签名证书或 `pfx/cer` 资产；正式签名链必须依赖外部凭据注入。

## 3. 研发工作包

### W09: Windows 驱动工程、安装链与用户态桥接

**状态**

- 已完成，真机主机：`192.168.2.218`
- 已验证驱动构建、安装、协议握手、卸载闭环
- 参考提交：`3bc839c`、`7f5111e`

**目标**

- 入仓可构建的 Windows 驱动工程与安装清单。
- 建立用户态与驱动的版本化控制协议。
- 消除 `descriptor()` 与真实运行态不一致的问题。

**交付物**

- 新增 Windows 驱动源码目录、工程文件、INF/CAT 生成入口、版本资源。
- 用户态驱动探测、连接、版本协商、健康诊断和严格失败逻辑。
- 驱动安装、卸载、状态检查脚本与真机验收命令。

**完成判定**

- `192.168.2.218` 能完成驱动安装、加载、握手和卸载闭环。
- 系统级模式下若驱动未加载，`WindowsPlatform` 启动直接失败，不得伪装成 driver 模式。
- `descriptor()`、健康快照、诊断输出与真实驱动状态一致。

**关键文件**

- 新增：`windows/driver/`
- 修改：`crates/aegis-platform/src/windows.rs`
- 修改：`scripts/windows-runtime-verify.sh`
- 修改：`scripts/windows-runtime-verify.ps1`

### W10: 文件与注册表系统采集链

**状态**

- 已完成，真机主机：`192.168.2.218`
- 已验证 Minifilter 文件事件采集：`write/rename/delete`
- 已验证注册表 journal 与回滚闭环：`before -> after -> rollback -> before`
- 代码提交：`0677754`

**目标**

- 以 Minifilter 提供真实文件打开、写入、重命名、删除事件。
- 以 `CmRegisterCallbackEx` 提供真实注册表变更与 journal。
- 实现真正可回放的 registry rollback 数据面，而不是只生成 JSON 工件。

**交付物**

- 文件事件桥接到 `RawSensorEvent` / `NormalizedEvent`。
- 注册表变更 journal、容量控制、回滚索引与 point-in-time 回滚执行链。
- 真机验证脚本、单元测试与集成测试。

**完成判定**

- `capabilities().file`、`capabilities().registry` 变为真实能力判断。
- `provider_health(MinifilterFile/RegistryCallback)` 由驱动状态和真实事件流决定，而不是硬编码 `false`。
- 在 `192.168.2.218` 可实测得到文件写入/重命名/删除事件以及注册表写入/回滚闭环。

**关键文件**

- 修改：`crates/aegis-platform/src/windows.rs`
- 新增：`windows/driver/src/file_*`
- 新增：`windows/driver/src/registry_*`

### W11: 进程/文件/注册表保护与内核完整性

**目标**

- 用 `ObRegisterCallbacks`、Minifilter、注册表回调实现真实保护面。
- 实现 SSDT / 回调表 / 内核代码完整性检查。
- 把 `protect_process`、`protect_files`、`verify_integrity` 从 audit-only 变成真实执行。

**交付物**

- 保护策略下发、驱动执行、结果回执与失败面诊断。
- 完整性检查结果结构化上报。
- 验收脚本覆盖保护前后行为差异。

**完成判定**

- `protect_process` 能阻止非受信句柄访问或终止路径。
- `protect_files` 能阻止对 Agent 关键路径的修改。
- `check_ssdt_integrity`、`check_callback_tables`、`check_kernel_code` 不再返回 `not implemented`。

**关键文件**

- 修改：`crates/aegis-platform/src/windows.rs`
- 新增：`windows/driver/src/protection_*`
- 新增：`windows/driver/src/integrity_*`

### W12: 脚本/AMSI/内存信号闭环

**目标**

- 用真实 AMSI provider 接入脚本扫描与阻断。
- 把脚本能力从“日志侧健康面”推进到真实执行链。
- 为内存信号提供真实数据面和事件模型，而不是永远 `memory=false`。

**交付物**

- AMSI provider 注册、扫描回调、阻断路径、绕过检测。
- 脚本与内存事件桥接、健康诊断和验收脚本。

**完成判定**

- `capabilities().script`、`capabilities().memory` 变为真实能力判断。
- `AmsiScript`、`MemorySensor` 不再硬编码 `false`。
- 真机能验证 AMSI 注册、脚本阻断或告警、内存信号采集至少一条完整链路。

**关键文件**

- 修改：`crates/aegis-platform/src/windows.rs`
- 新增：`windows/driver/src/memory_*`
- 新增：`windows/amsi/`

### W13: 打包、看门狗、自举与发布前自检

**目标**

- 交付 Windows 安装链：主进程、watchdog、updater、驱动。
- 发布前完成自检、依赖检查与失败回滚。
- 建立 ELAM/PPL 依赖检查和严格状态暴露。

**交付物**

- MSI/安装脚本、驱动服务注册、首启自检、回滚点。
- watchdog 与主进程心跳、自检结果、诊断输出。
- 发布前验证脚本。

**完成判定**

- 安装过程会显式校验驱动加载、服务注册、依赖项与运行模式。
- 若缺签名/缺依赖/缺批准，安装与首启失败，并留下可复盘日志。

**关键文件**

- 新增：`packaging/windows/`
- 修改：`crates/aegis-watchdog/src/main.rs`
- 修改：`crates/aegis-agentd/src/main.rs`

### W14: 正式签名、兼容性矩阵与发布验证

**目标**

- 建立正式代码签名、驱动签名、目录签名与验签流程。
- 完成支持版本兼容性矩阵和发布验收。
- 把“正式签名/发布”与“开发构建/未签名验收”严格分离。

**交付物**

- 签名与验签脚本、构建参数、证书变量契约、失败诊断。
- 支持矩阵、发布门禁、真机验收记录。

**完成判定**

- 没有代码签名凭据时，签名流水线必须失败，不允许假通过。
- 有凭据时，可在 Windows 构建机生成签名后的可安装产物并完成验签。
- 文档明确哪些步骤依赖 Microsoft / 证书外部资源。

**关键文件**

- 新增：`scripts/windows-sign-driver.ps1`
- 新增：`scripts/windows-build-driver.ps1`
- 修改：`docs/plan/sensor/sensor-windows-validation-matrix.md`
- 修改：`docs/release/`

## 4. 验证矩阵

- 本地 Rust 单元测试：
  - `cargo test -p aegis-platform windows --lib`
- Windows 真机运行时验收：
  - `scripts/windows-runtime-verify.sh`
  - `scripts/windows-runtime-verify.ps1`
- Windows 构建与打包验收：
  - 驱动工程构建
  - 安装/卸载
  - 签名/验签
  - 首启自检
- 支持版本验收：
  - Windows 10 1809
  - Windows 11 21H2+
  - Windows Server 2016+

## 5. 外部前提

- `192.168.2.218` 当前是唯一已验证可用的 Windows 主机。
- 正式代码签名、驱动签发、ELAM 相关验证需要外部证书与 Microsoft 签发链；仓库内不能伪造这条链路。
- 若缺少正式证书，允许完成严格失败的构建/签名流水线实现，但不得把 `W14` 标记为 `done`。
