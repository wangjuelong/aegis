# Windows MSI 工程计划

## 1. 目标

把当前 Windows `payload + install.ps1 + validate.ps1` 的开发包交付链升级为真正的 MSI 工程，保证：

- 仓库内可生成真实 `.msi` 产物
- MSI 安装内容覆盖 `agentd/watchdog/updater/driver/scripts`
- MSI 安装后执行驱动安装、配置生成、bootstrap-check、watchdog 一次性校验
- MSI 卸载可清理驱动、安装目录与状态目录
- release MSI 仍保留签名、ELAM、PPL 批准物料的严格 gate

## 2. 当前缺口

- 文档承诺 Windows 安装包为 `MSI`，但仓库当前实现是 payload 目录 + `install.ps1`/`validate.ps1`，不是 MSI 工程。
- 当前 `windows-package-verify.sh` 只远端调用 `validate.ps1`，不产出 MSI。
- 当前仓库没有 WiX/MSI 项目、MSI 构建脚本或 MSI 安装/卸载验收链。

## 3. 不妥协约束

- 不接受继续把 `payload/install gate` 说成 `MSI`。
- 不接受 MSI 只放一个 bootstrap EXE，不真正安装核心文件。
- 不接受 MSI 绕过驱动安装、自检或 watchdog 校验。
- 不接受 release MSI 弱化签名/批准依赖。

## 4. 研发范围

### 4.1 MSI 项目

- 新增 `packaging/windows/msi/`
- 使用 WiX SDK 构建 `.msi`
- 定义：
  - 产品元数据
  - 安装目录
  - 组件 / Feature
  - 自定义动作

### 4.2 构建 / 安装 / 卸载

- 新增 MSI 构建脚本
- 扩展 `validate.ps1`
- 真实执行：
  - 构建 Rust 二进制
  - 构建驱动
  - 组装 MSI payload
  - `msiexec /i`
  - bootstrap-check / watchdog
  - `msiexec /x`

### 4.3 release gate

- release MSI 仍要求：
  - 签名证书
  - 时间戳
  - `signed-release.json`
  - `signed-release.cms`
  - `elam-approved.txt`
  - `ppl-approved.txt`

### 4.4 验证

- Windows 真机 `.218` 上完成 MSI 构建、安装、验证、卸载
- 输出 `required_failures=[]`

## 5. 交付物

- `packaging/windows/msi/`
- `packaging/windows/validate.ps1`
- `scripts/windows-package-verify.sh`
- `docs/plan/sensor/sensor-windows-plan.md`

## 6. 完成判定

- 仓库内存在真实 MSI 项目与构建脚本
- `.218` 可产出 `.msi`
- `.218` 完成 `msiexec /i`、bootstrap-check、watchdog、`msiexec /x`
- release MSI gate 保持严格失败
- 文档状态同步更新
