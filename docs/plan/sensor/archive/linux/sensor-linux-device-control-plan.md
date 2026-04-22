# Linux 设备控制链计划

## 1. 目标

把当前 Linux 缺失的设备控制链补齐，保证：

- 真实识别 USB / removable device 到达、移除与挂载变化
- 交付 `udev` rules 与 `USBGuard` policy 产物
- 对可疑设备挂载与数据访问产生统一 `DeviceControl` 遥测
- 安装链可部署设备控制配置，验证链可复跑

## 2. 当前缺口

- 文档要求 Linux 具备 `udev rules + USBGuard + LSM mount hook` 设备控制链，但仓库里还没有对应 Linux provider、脚本和交付物。
- 当前 `LinuxPlatform` 没有 `DeviceControl` provider，也没有 removable device 基线 / 增量事件。
- 安装包没有设备控制配置目录和验收入口。

## 3. 不妥协约束

- 不接受只写静态文档，不落真实配置和事件链。
- 不接受只看 `/proc/mounts`，不识别设备到达/移除。
- 不接受把 Windows `DeviceControl` provider 口径直接挪到 Linux，不区分主机能力。
- 不接受没有安装/验证入口的半交付。

## 4. 研发范围

### 4.1 Linux provider 与事件链

- 新增 Linux `DeviceControl` provider
- 建立 USB/removable device 基线与增量检测
- 识别：
  - 设备到达
  - 设备移除
  - 新挂载点
  - 可疑挂载源

### 4.2 设备控制配置产物

- 新增 `packaging/linux/device-control/`
- 交付：
  - `udev` rules
  - `USBGuard` policy baseline
  - mount monitor / policy 配置模板

### 4.3 安装 / 验证

- 扩展 Linux 安装链复制设备控制配置
- 新增 `scripts/linux-device-control-validate.sh`
- 在 Linux 主机上校验：
  - provider 健康面
  - 配置文件部署
  - 基线输出与诊断状态

## 5. 交付物

- `crates/aegis-platform/src/linux.rs`
- `packaging/linux/device-control/`
- `scripts/linux-device-control-validate.sh`
- `docs/plan/sensor/sensor-linux-plan.md`

## 6. 完成判定

- Linux 仓库内存在真实设备控制 provider 与交付目录
- 安装链包含设备控制配置部署
- 本地测试通过
- Linux 测试机完成设备控制验证
- 文档状态同步更新

## 7. 实际交付

- 代码提交：`46db501 feat(linux): 完成设备控制链与配置交付`
- 已新增：
  - `packaging/linux/device-control/udev/99-aegis-removable.rules`
  - `packaging/linux/device-control/usbguard/rules.conf`
  - `packaging/linux/device-control/mount-monitor.conf`
  - `scripts/linux-device-control-validate.sh`
- 已完成：
  - Linux `DeviceControl` provider 已接入 `LinuxPlatform`
  - 设备基线可识别 USB/removable block device 与挂载变化
  - 包安装链会部署 `udev`、`USBGuard` 与 mount monitor 配置
  - 卸载链会清理系统级设备控制配置

## 8. 验证结果

本地已完成：

- `cargo test -p aegis-platform linux_device_control -- --nocapture`
- `cargo test -p aegis-platform linux_baseline_registers_required_providers -- --nocapture`
- `bash scripts/linux-device-control-validate.sh`

Linux 测试机 `192.168.2.123` 已完成：

- 通过 `scripts/linux-package-verify.sh` 闭环安装/卸载链
- `device_control_paths` 返回：
  - `/etc/udev/rules.d/99-aegis-removable.rules`
  - `/etc/usbguard/rules.conf`
  - `/etc/aegis/device-control/mount-monitor.conf`
- `required_failures=[]`

本地验收工件：

- `target/linux-validation/192.168.2.123.json`

## 9. 结论

- `L14` 已完成代码、真机验收与文档闭环。
