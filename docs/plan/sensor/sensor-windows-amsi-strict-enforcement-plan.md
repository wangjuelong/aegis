# Windows AMSI 严格阻断收口计划

## 0. 状态

- 已完成
- 代码提交：`0a01f16`
- 真机主机：`192.168.2.222`
- 远端验收时间：`2026-04-21 14:58:20 +08:00`
- 验收 ID：`windows-runtime-20260421-145549`

## 1. 目标

收口当前 AMSI 能力“仅在 `scan_interface_ready=true` 时严格验证”的妥协，保证：

- Windows 脚本严格阻断能力有一致的运行时判定标准
- 验收脚本不再因为宿主探针不稳定而跳过恶意样本阻断检查
- `supports_amsi` / `AmsiStatus` / 文档结论与真实宿主阻断能力一致

## 2. 当前缺口

以下缺口已在本轮收口，保留为计划与实际交付的对照基线：

- 现有验收脚本在 `scan_interface_ready=false` 时直接跳过 AMSI 恶意样本阻断验证。
- 这使得 `.222` 等主机只能证明“脚本块日志存在”，不能证明“严格阻断已成立”。
- `script_sensor_ready()` 目前把 `has_amsi_scan_interface`、`has_script_block_logging`、`has_powershell_log` 绑成单一布尔，不足以表达“告警可用 / 严格阻断可用”的差异。

## 3. 不妥协约束

- 不接受继续在验收中跳过恶意样本阻断并仍写成 `done`。
- 不接受把“日志链存在”偷换成“严格阻断存在”。
- 不接受单纯改文档口径，不改实现和验收。
- 不接受在系统级模式下静默接受“AMSI 不可严格阻断”。

## 4. 研发范围

### 4.1 AMSI 能力模型收口

- 将 Windows 脚本能力拆成：
  - script logging / telemetry 能力
  - AMSI strict enforcement 能力
- `PlatformDescriptor`、health、diagnose 输出显式区分

### 4.2 严格阻断执行链

- 统一使用能够代表真实宿主阻断结果的执行路径
- 若宿主缺少严格阻断前提，平台必须显式声明 `unsupported`，不能继续 overclaim
- 验收结果必须能区分：
  - `scan_interface_ready`
  - `strict_block_ready`

### 4.3 验收脚本

- `windows-runtime-verify.ps1` 中 `script_surface_roundtrip` 的 skip 原因从 `scan_interface_ready` 切换到真实 `strict_block_ready`
- 明确区分：
  - benign script logging
  - strict enforcement unsupported
  - suspicious script blocked before execution
- `.222` 必须显式输出 `host_amsi_strict_enforcement_unavailable`，不再伪装成“已支持严格阻断”

### 4.4 文档与状态

- 更新 `sensor-windows-plan.md` / `sensor-windows-system-completion-plan.md`
- 不再把“条件成立的严格阻断”写成无条件完成

## 5. 交付物

- `crates/aegis-platform/src/windows.rs`
- `scripts/windows-scan-script-with-amsi.ps1`
- `scripts/windows-runtime-verify.ps1`
- `docs/plan/sensor/sensor-windows-validation-matrix.md`

## 6. 实际交付结果

- `windows-scan-script-with-amsi.ps1` 已新增真实 PowerShell 引擎执行探针，输出 `strict_block_ready`，不再只暴露手工 `scan_interface_ready`。
- `WindowsPlatform` 新增 `has_amsi_strict_blocking` 能力面，`supports_amsi` / `AmsiStatus` 现在只在真实 strict-block 可用时返回 `true`。
- `.222` 上远端验收结果显示：`has_amsi_runtime=true`、`scan_interface_ready=false`、`strict_block_ready=false`；`script_surface_roundtrip` 显式返回 `host_amsi_strict_enforcement_unavailable`，不再把 skip 分支包装成完成。
- 本地单测已新增 `windows_descriptor_requires_strict_amsi_blocking_for_support`，覆盖“接口探针为真但 strict blocking 为假时，不得 overclaim `supports_amsi=true`”。

## 7. 完成判定

- `supports_amsi` / `AmsiStatus` 与真实宿主 strict-block 能力一致
- 验收脚本不再把 `scan_interface_ready=false` 误记为“已完成”
- 文档不再把条件性能力写成无条件完成
