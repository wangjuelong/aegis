# Aegis Windows Packaging

本目录保存 Windows 开发包的安装清单、安装/卸载脚本与真机验证脚本。

## 目录内容

- `manifest.json`：Windows 安装清单，描述必须交付的二进制、驱动目录与驱动安装脚本
- `install.ps1`：开发包安装脚本，负责复制 payload、生成配置、安装驱动、执行首启自检与 watchdog 一次性验证
- `uninstall.ps1`：回滚/卸载脚本，负责停止并删除驱动服务、移除已安装文件
- `validate.ps1`：在 Windows 主机上完成本地构建、payload 组装、安装、自检、watchdog 验证与卸载
- `scripts/windows-package-verify.sh`：从 macOS/Linux 主机通过 SSH 把仓库 payload 发到 Windows 主机，并远端调用 `validate.ps1`

## Payload 约定

安装脚本消费一个已经组装好的 payload 目录，默认结构如下：

```text
payload/
  manifest.json
  bin/
    aegis-agentd.exe
    aegis-watchdog.exe
    aegis-updater.exe
  driver/
    ...
  scripts/
    windows-install-driver.ps1
    windows-uninstall-driver.ps1
```

其中：

- `bin/` 中的三个可执行文件必须由当前仓库源码构建得到
- `driver/` 必须包含驱动工程目录；验证脚本会先在目标 Windows 主机上构建它
- `scripts/` 目录中的驱动安装/卸载脚本来自仓库根目录 `scripts/`

## 开发包与正式包

当前 `manifest.json` 的 `bundle_channel=development`，因此：

- 会暴露 `trusted_bundle_signature` / `elam_approval` / `watchdog_ppl_approval` 的状态
- 但不会把这些正式发布前置条件当成开发包安装阻断项

正式签名和发布门禁在 `W14` 中补齐后，应额外产出 `bundle_channel=release` 的安装清单，并把上述依赖改为强制项。

## 真机验证

在 Windows 主机上执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\packaging\windows\validate.ps1 -RepoRoot C:\path\to\aegis
```

如果目标主机无法稳定通过 `rustup` 拉起所需工具链，可显式传入离线工具链根目录：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\packaging\windows\validate.ps1 `
  -RepoRoot C:\path\to\aegis `
  -ToolchainRoot C:\ProgramData\Aegis\toolchains\1.91.0
```

验证脚本会输出一个 JSON 结果，其中：

- `required_failures=[]` 表示安装、自检、watchdog 与卸载闭环通过
- `install_result_path` 指向安装结果工件
- `bootstrap_report_path` 与 `watchdog_snapshot_path` 指向首启自检和 watchdog 状态工件

## 已验证场景

- 真机：`192.168.2.218` (`DESKTOP-TLASHJG`)
- 验证时间：`2026-04-20 20:22:37 +08:00`
- payload 根目录：`C:\ProgramData\Aegis\validation\windows-package-verify-20260420-200129`
- 离线工具链：`C:\ProgramData\Aegis\toolchains\1.91.0`
- 结果：`required_failures=[]`，安装结果、自检工件、watchdog 工件全部生成

## 失败语义

- 缺少 payload 组件：安装立即失败
- 配置生成失败：安装立即失败
- 驱动安装失败：安装立即失败并回滚已复制文件
- `aegis-agentd --bootstrap-check` 未批准：安装立即失败并回滚
- `aegis-watchdog --once` 有告警或 bootstrap 未通过：安装立即失败并回滚
