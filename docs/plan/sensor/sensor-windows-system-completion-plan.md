# Windows System Completion Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 将 Windows 平台从当前“用户态运行时闭环”推进到“内核驱动 + 真实系统采集 + 自保护 + 正式签名与兼容性验证”的完整交付状态。

**Architecture:** 用户态继续由 `crates/aegis-platform` / `crates/aegis-core` 承担调度、检测与响应编排；新增 Windows 驱动工程承载 Minifilter / 注册表回调 / 进程保护 / 内核完整性采集；驱动与用户态通过严格版本化的控制通道通信，系统级模式下禁止静默退回 PowerShell 假实现。

**Tech Stack:** Rust 用户态、Windows WDM/Minifilter/WFP 驱动工程、PowerShell/SSH 真机验收、MSBuild/Windows Kits/Signtool、MSI/INF/CAT 打包与签名校验。

## 当前进度（2026-04-21）

| 工作包 | 状态 | 结果 |
|--------|------|------|
| `W09` | `done` | 已完成驱动工程、安装链、协议握手与 `driver mode` 严格失败闭环 |
| `W10` | `done` | 已完成 Minifilter 文件事件、注册表 journal/rollback 真实链路，以及 Rust 平台层接入 |
| `W11` | `done` | 已完成 `ObRegisterCallbacks` 进程保护、Minifilter 文件保护与真实完整性回执，真机验证通过 |
| `W12` | `done` | 已完成共享脚本解码、AMSI 脚本阻断/告警链与内存信号采集，`192.168.2.218` 真机验证通过 |
| `W13` | `done` | 已完成开发包安装/卸载、自举自检、watchdog 状态闭环与远端真机验收，`required_failures=[]` |
| `W14` | `done` | 已完成 release 清单、签名/验签脚本、安装前后 release gate 与 Windows 11 真机发布验证；外部证书/审批缺失时严格失败 |
| `W15` | `done` | 已完成 `protect_registry`、驱动保护表、registry pre-callback 阻断与 `192.168.2.222` 真机验收 |
| `W16` | `done` | 已完成 Minifilter 权威 block map、TTL、状态查询与 `192.168.2.222` 真机验收 |
| `W17` | `todo` | 收口目标路径阻断：外部文件 rename/move/link 进入受保护目录必须被拒绝 |
| `W18` | `todo` | 收口 `block_hash` 严格 pre-create 阻断，不再依赖 `post-create + FltCancelFileOpen` |
| `W19` | `todo` | 收口 `clear_all_blocks` 平面解耦：防火墙与 Minifilter 独立释放、部分成功显式可见 |
| `W20` | `todo` | 收口 AMSI 严格阻断：恶意样本阻断不能再走 skip 分支，能力声明与真机结果一致 |

---

## 1. 不妥协约束

- 不允许继续把 `KernelTransport::Driver`、`supports_registry`、`supports_amsi` 等能力声明为已支持，但运行时仍然只依赖 PowerShell/SSH。
- 不允许继续用审计工件替代真实系统级能力。`registry_rollback`、`protect_process`、`protect_files`、`block_hash/pid/path` 必须具备真实执行链，否则状态保持 `todo/doing`。
- 不允许把“注册表保护面”继续写成静态路径列表冒充真实保护状态；必须记录真实已下发保护路径与驱动状态。
- 不允许在系统级模式下静默降级到用户态替代实现；缺驱动、缺签名、缺依赖时必须显式失败并暴露诊断。
- 不允许把开发签名、自签名或未验收兼容矩阵误记为“正式签名/正式发布”。
- 不允许引入兜底路径掩盖真实失败；所有外部依赖缺失都必须以结构化错误暴露。

## 2. 当前结论

- 新一轮代码审查重新发现 4 个剩余缺口：目标路径 rename/move 绕过、`block_hash` 非严格 pre-create、`clear_all_blocks` 平面耦合、AMSI 严格阻断仍是条件成立。
- 因此仓库侧 Windows 功能不能继续诚实标记为“缺口已清零 / 系统级交付 done”；当前状态回退为 `doing`，待 `W17-W20` 收口。
- 测试机 `192.168.2.218` 与 `192.168.2.222` 均可用；`192.168.1.4` 当前不可达，不作为当前验收主机。
- `W14` 需要的签名、验签、批准文件依赖已经形成严格失败链路，但正式 `pfx/cer` 资产仍由外部发布环境注入。

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

**状态**

- 已完成，真机主机：`192.168.2.218`
- 已验证 `ObRegisterCallbacks` 进程保护、Minifilter 路径保护与驱动完整性回执
- 已验证 `Stop-Process` 被拒绝、受保护目录 `write/rename/delete` 被拒绝，且 Minifilter 记录 `block-create` 阻断事件
- 代码提交：`1651733`

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
- 新增：`scripts/windows-configure-file-protection.ps1`
- 新增：`scripts/windows-protect-process.ps1`
- 新增：`scripts/windows-query-driver-integrity.ps1`
- 修改：`scripts/windows-install-driver.ps1`
- 修改：`windows/driver/AegisSensorKmod.vcxproj`
- 修改：`windows/driver/src/aegis_sensor_kmod.c`
- 修改：`windows/minifilter/src/aegis_file_minifilter.c`

### W12: 脚本/AMSI/内存信号闭环

**状态**

- 已完成，真机主机：`192.168.2.218`
- 已验证 `AmsiScanBuffer`、PowerShell 4104 脚本块采集与内存快照增量链
- 代码提交：`b896275`

**目标**

- 用真实 AMSI provider 接入脚本扫描与阻断。
- 把脚本能力从“日志侧健康面”推进到真实执行链。
- 为内存信号提供真实数据面和事件模型，而不是永远 `memory=false`。

**交付物**

- 共享脚本解码流水线，统一承载 Base64 / CharCode / EncodedCommand 解码逻辑。
- AMSI 扫描/阻断脚本、PowerShell ScriptBlock 事件桥接、内存快照事件桥接。
- 脚本与内存健康诊断、单元测试与真机验收脚本。

**完成判定**

- `capabilities().script`、`capabilities().memory` 变为真实能力判断。
- `AmsiScript`、`MemorySensor` 不再硬编码 `false`。
- 真机能验证 AMSI 注册、脚本阻断或告警、内存信号采集至少一条完整链路。

**关键文件**

- 新增：`crates/aegis-script/src/lib.rs`
- 修改：`crates/aegis-core/src/script_decode.rs`
- 修改：`crates/aegis-platform/src/windows.rs`
- 新增：`scripts/windows-scan-script-with-amsi.ps1`
- 新增：`scripts/windows-query-script-events.ps1`
- 新增：`scripts/windows-query-memory-snapshot.ps1`
- 修改：`scripts/windows-runtime-verify.ps1`

### W13: 打包、看门狗、自举与发布前自检

**状态**

- 已完成，真机主机：`192.168.2.218`
- 已验证开发包安装、驱动注册、`aegis-agentd --write-default-config`、`--bootstrap-check` 与 `aegis-watchdog --once` 闭环
- 远端验证时间：`2026-04-20 20:22:37 +08:00`
- 远端 payload：`C:\ProgramData\Aegis\validation\windows-package-verify-20260420-200129`
- 离线 Rust 工具链：`C:\ProgramData\Aegis\toolchains\1.91.0`
- 代码提交：`61e1d0e`

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
- 已在真机拿到 `install-result.json`、`bootstrap-check.json`、`watchdog-state.json`，且 `required_failures=[]`。

**关键文件**

- 新增：`packaging/windows/`
- 修改：`crates/aegis-watchdog/src/main.rs`
- 修改：`crates/aegis-agentd/src/main.rs`

### W14: 正式签名、兼容性矩阵与发布验证

**状态**

- 已完成，真机主机：`192.168.2.218`
- 已验证 `bundle_channel=release` 的签名、验签、安装前 release gate、安装后 release gate 与卸载闭环
- 远端验证时间：`2026-04-20 21:09:35 +08:00`
- 远端 payload：`C:\ProgramData\Aegis\validation\windows-package-verify-20260420-200129`
- 代码提交：`08d94a3`

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
- 新增：`packaging/windows/manifest.release.json`
- 新增：`packaging/windows/verify-release.ps1`
- 修改：`packaging/windows/install.ps1`
- 修改：`packaging/windows/uninstall.ps1`
- 修改：`packaging/windows/validate.ps1`
- 修改：`scripts/windows-package-verify.sh`
- 修改：`crates/aegis-core/src/upgrade.rs`
- 修改：`docs/plan/sensor/sensor-windows-validation-matrix.md`
- 修改：`docs/release/aegis-sensor-release-notes.md`

### W15: 注册表真实保护链

**状态**

- 已完成，真机主机：`192.168.2.222`
- 已验证 `protect_registry` 真实下发、保护路径状态回执、registry pre-callback 阻断与 journal `blocked=true`
- 远端验证时间：`2026-04-21 11:17:56 +08:00`
- 远端 payload：`C:\ProgramData\Aegis\validation\windows-runtime-verify-20260421-111712`
- 代码提交：`9061fea`

**目标**

- 为 Windows 平台补齐一等注册表保护接口与真实内核阻断。
- 让 `CmRegisterCallbackEx` 在键/值创建、修改、删除前执行实时保护判定。
- 让保护面工件和运行时状态只反映真实已下发保护路径。

**完成判定**

- `protect_registry` 能下发真实保护路径并返回驱动回执。
- 键/值创建、修改、删除在保护面上被拒绝，并进入 journal。
- `windows-runtime-verify` 新增 `registry_protection` 必选步骤，`192.168.2.222` 真机通过。

**关键文件**

- 修改：`crates/aegis-platform/src/traits.rs`
- 修改：`crates/aegis-platform/src/windows.rs`
- 修改：`windows/driver/include/aegis_windows_driver_protocol.h`
- 修改：`windows/driver/src/aegis_sensor_kmod.c`
- 新增：`scripts/windows-configure-registry-protection.ps1`
- 修改：`scripts/windows-query-registry-events.ps1`
- 修改：`scripts/windows-runtime-verify.ps1`
- 修改：`scripts/windows-runtime-verify.sh`

**详细计划**

- `docs/plan/sensor/sensor-windows-registry-protection-plan.md`

### W16: hash/pid/path 真实阻断链

**状态**

- 已完成，真机主机：`192.168.2.222`
- 已验证 `block_path` / `block_pid` / `block_hash` 三类真实阻断、事件回传与 Minifilter `block_entry_count=0` 清空闭环
- 远端验证时间：`2026-04-21 12:16:16 +08:00`
- 远端 payload：`C:\ProgramData\Aegis\validation\windows-runtime-verify-20260421-121345`
- 代码提交：`e3769ac`

**目标**

- 为 Windows Minifilter 增加 block map、TTL 与状态查询。
- 让 `block_hash`、`block_pid`、`block_path` 成为真实 pre-op 阻断，而不是 userspace ledger。
- 让 `clear_all_blocks` 清空 firewall 与 minifilter 权威 block 状态。

**完成判定**

- `block_hash/pid/path` 审计工件全部为 `enforced=true`。
- Minifilter 状态可查询真实 block 计数与类型分布。
- `windows-runtime-verify` 新增 `preemptive_blocking` 必选步骤，`192.168.2.222` 真机通过。

**关键文件**

- 修改：`crates/aegis-platform/src/windows.rs`
- 修改：`windows/minifilter/include/aegis_file_minifilter_protocol.h`
- 修改：`windows/minifilter/src/aegis_file_minifilter.c`
- 修改：`windows/minifilter/AegisFileMonitor.vcxproj`
- 新增：`scripts/windows-build-minifilter.ps1`
- 新增：`scripts/windows-configure-preemptive-block.ps1`
- 修改：`scripts/windows-install-minifilter.ps1`
- 修改：`scripts/windows-query-file-events.ps1`
- 修改：`scripts/windows-runtime-verify.ps1`
- 修改：`scripts/windows-runtime-verify.sh`

**详细计划**

- `docs/plan/sensor/sensor-windows-preemptive-block-plan.md`

### W17: 受保护目录目标路径阻断收口

**状态**

- `todo`
- 目标主机：`192.168.2.222`

**目标**

- 收口 rename / move / link 进入受保护目录的目标路径绕过。
- 让 `protect_files` 与 `block_path` 同时覆盖源路径与目标路径判定。

**完成判定**

- 外部文件无法通过 rename / move / link 进入受保护目录。
- 真机 `192.168.2.222` 可验证目标路径阻断与事件回传。

**详细计划**

- `docs/plan/sensor/sensor-windows-protected-destination-rename-plan.md`

### W18: hash 严格 pre-create 阻断链

**状态**

- `todo`
- 目标主机：`192.168.2.222`

**目标**

- 把 `block_hash` 从 `post-create + FltCancelFileOpen` 收口为严格 create 入口阻断。
- 保证文档中的“preemptive block”与内核真实时序一致。

**完成判定**

- `block_hash` 不再依赖 post-create cancel。
- 命中 hash 的文件在 create 返回前被拒绝。

**详细计划**

- `docs/plan/sensor/sensor-windows-hash-precreate-block-plan.md`

### W19: block 清理平面解耦

**状态**

- `todo`
- 目标主机：`192.168.2.222`

**目标**

- 让 `clear_all_blocks()` 分平面清理 Windows 防火墙与 Minifilter block。
- 某一平面失效时，另一平面仍能完成 release，并把部分成功显式写入工件。

**完成判定**

- Minifilter 失效时 network release 仍能完成。
- 清理工件显式包含分平面结果与残留状态。

**详细计划**

- `docs/plan/sensor/sensor-windows-block-release-decoupling-plan.md`

### W20: AMSI 严格阻断收口

**状态**

- `todo`
- 目标主机：`192.168.2.222`

**目标**

- 收口 AMSI 严格阻断只能条件成立的问题。
- 让 `supports_amsi` / `AmsiStatus` / 验收脚本与真实主机阻断能力一致。

**完成判定**

- `.222` 上官方 AMSI test sample 被严格阻断，不能再走 skip 分支。
- 文档不再把条件性能力写成无条件完成。

**详细计划**

- `docs/plan/sensor/sensor-windows-amsi-strict-enforcement-plan.md`

## 4. 验证矩阵

- 本地 Rust 单元测试：
  - `cargo test -p aegis-platform windows --lib`
  - `cargo test -p aegis-core windows_install_manifest_requires_relative_release_dependency_paths`
- Windows 真机运行时验收：
  - `scripts/windows-runtime-verify.sh`
  - `scripts/windows-runtime-verify.ps1`
- Windows 构建与打包验收：
  - 驱动工程构建
  - 安装/卸载
  - 签名/验签
  - 首启自检
  - `packaging/windows/validate.ps1 -BundleChannel release`
- 支持版本验收：
  - Windows 10 1809
  - Windows 11 21H2+
  - Windows Server 2016+

## 5. 外部前提

- `192.168.2.218` 与 `192.168.2.222` 均已验证可用，分别承接 `W12-W14` 与 `W15/W16` 真机验收。
- 正式代码签名、驱动签发、ELAM 相关验证需要外部证书与 Microsoft 签发链；仓库内不能伪造这条链路。
- 当前仓库侧 `W14` 已通过“外部证书/批准文件注入 + 缺失即失败”的 release 验收；Microsoft 正式签发、多版本试点扩容仍属于仓库外流程，不在仓库内伪造。
