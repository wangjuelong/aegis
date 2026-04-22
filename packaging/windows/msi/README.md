# Windows MSI 工程

本目录用于说明 Windows Sensor 的 MSI 交付工程。

当前实现特点：

- MSI 由 `scripts/windows/build-msi.ps1` 根据 staged payload 动态生成 WiX 源文件并构建
- MSI 负责铺设：
  - `aegis-agentd.exe`
  - `aegis-watchdog.exe`
  - `aegis-updater.exe`
  - 驱动目录
  - 安装 / 卸载 / release 校验脚本
- MSI 自定义动作会在安装阶段调用 `install.ps1 -PayloadAlreadyInstalled`
- MSI 卸载阶段会调用 `uninstall.ps1 -SkipInstallRootCleanup -RemoveStateRoot`

真机验收入口仍然统一使用：

- `packaging/windows/validate.ps1`
- `scripts/windows-package-verify.sh`
