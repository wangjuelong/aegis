# Aegis Windows Packaging

本目录保存 Windows MSI / payload 双阶段打包清单、安装/卸载脚本与真机验证入口。

## 目录内容

- `manifest.json`：Windows 安装清单，描述必须交付的二进制、驱动目录与驱动安装脚本
- `manifest.release.json`：release 安装清单，额外声明签名 receipt、CMS 签名与批准文件等强制依赖
- `install.ps1`：开发包安装脚本，负责复制 payload、生成配置、安装驱动、执行首启自检与 watchdog 一次性验证
- `uninstall.ps1`：回滚/卸载脚本，负责停止并删除驱动服务、移除已安装文件
- `verify-release.ps1`：对 release payload 执行 receipt/CMS/Authenticode/批准文件依赖校验
- `msi/`：MSI 工程说明目录
- `validate.ps1`：在 Windows 主机上完成本地构建、payload 组装、MSI 构建、签名、安装、自检、watchdog 验证与卸载
- `scripts/windows/build-msi.ps1`：基于 staged payload 生成真实 `.msi`，并注入安装/卸载自定义动作
- `scripts/windows-sign-driver.ps1`：对 release payload 中的 EXE/脚本/驱动/CAT 产物完成签名并生成 detached CMS receipt
- `scripts/windows-package-verify.sh`：从 macOS/Linux 主机通过 SSH 同步仓库与 vendored crates，远端调用 `validate.ps1`

## Payload 约定

MSI 构建脚本消费一个已经组装好的 staged payload 目录，默认结构如下：

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

## 打包形态

当前仓库维护两层打包形态：

- staged payload：供 `install.ps1` / `verify-release.ps1` / `build-msi.ps1` 消费
- 真实 MSI：由 `build-msi.ps1` 生成，使用 `msiexec /i` / `msiexec /x` 执行安装卸载

MSI 自定义动作约束：

- 安装阶段执行 `install.ps1 -PayloadAlreadyInstalled`
- 卸载阶段执行 `uninstall.ps1 -SkipInstallRootCleanup -RemoveStateRoot`
- 安装前后都保留 bootstrap-check / watchdog / release gate 的严格失败语义

## 开发包与正式包

当前仓库同时维护两条严格隔离的交付路径：

- `manifest.json`：`bundle_channel=development`
- `manifest.release.json`：`bundle_channel=release`

开发包路径下：

- 会暴露 `trusted_bundle_signature` / `elam_approval` / `watchdog_ppl_approval` 的状态
- 但不会把这些正式发布前置条件当成开发包安装阻断项

release 路径下：

- 必须先执行 `scripts/windows-sign-driver.ps1`
- 必须生成 `metadata/signed-release.json` 与 `metadata/signed-release.cms`
- 必须携带 `metadata/elam-approved.txt` 与 `metadata/ppl-approved.txt`
- 安装前后都会执行 `verify-release.ps1`
- 缺少签名证书、时间戳地址、批准文件或任一 release 依赖时，`validate.ps1` 立即失败，不允许假通过

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
- `msi_build_result.msi_path` 指向真实 MSI 产物
- `msi_install_log_path` / `msi_uninstall_log_path` 指向 `msiexec` 日志
- `install_result_path` 指向安装结果工件
- `bootstrap_report_path` 与 `watchdog_snapshot_path` 指向首启自检和 watchdog 状态工件

如需执行 release 验证，可显式指定：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\packaging\windows\validate.ps1 `
  -RepoRoot C:\path\to\aegis `
  -BundleChannel release `
  -ToolchainRoot C:\ProgramData\Aegis\toolchains\1.91.0 `
  -SigningCertificateThumbprint <thumbprint> `
  -TimestampServer http://timestamp.digicert.com `
  -ElamApprovalPath C:\path\to\elam-approved.txt `
  -WatchdogPplApprovalPath C:\path\to\ppl-approved.txt
```

从 macOS/Linux 主机远端触发时，可使用：

```bash
AEGIS_WINDOWS_BUNDLE_CHANNEL=release \
AEGIS_WINDOWS_SIGNING_CERT_THUMBPRINT=<thumbprint> \
AEGIS_WINDOWS_TIMESTAMP_SERVER=http://timestamp.digicert.com \
AEGIS_WINDOWS_ELAM_APPROVAL_FILE=/local/path/elam-approved.txt \
AEGIS_WINDOWS_WATCHDOG_PPL_APPROVAL_FILE=/local/path/ppl-approved.txt \
./scripts/windows-package-verify.sh
```

## 已验证场景

- 真机：`192.168.2.218` (`DESKTOP-TLASHJG`)
- 验证时间：`2026-04-22 14:59:40 +08:00`
- payload 根目录：`C:\ProgramData\Aegis\validation\windows-package-verify-20260422-145307`
- 离线工具链：`C:\ProgramData\Aegis\toolchains\1.91.0`
- 结果：`required_failures=[]`，真实 MSI 构建、`msiexec /i`、自检、watchdog、`msiexec /x` 全部通过

release 补充验证：

- 验证时间：`2026-04-20 21:09:35 +08:00`
- 主机：`192.168.2.218`
- 结果：`bundle_channel=release`、`payload_release_verification.verified=true`、`installed_release_verification.verified=true`、`required_failures=[]`

## 失败语义

- 缺少 payload 组件：安装立即失败
- 配置生成失败：安装立即失败
- 驱动安装失败：安装立即失败并回滚已复制文件
- `aegis-agentd --bootstrap-check` 未批准：安装立即失败并回滚
- `aegis-watchdog --once` 有告警或 bootstrap 未通过：安装立即失败并回滚
- release 模式缺少签名证书 / 时间戳 / 批准文件 / receipt / CMS 签名：验证立即失败
