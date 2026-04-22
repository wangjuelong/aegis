# Linux 设备控制配置

本目录提供 Linux 设备控制链的最小交付配置：

- `udev/99-aegis-removable.rules`
  - 为 USB/removable block device 标记 `AegisManaged=1`
- `usbguard/rules.conf`
  - 默认显式放行 HID 与当前已知可信设备，其他设备交由主机策略继续细化
- `mount-monitor.conf`
  - 约束可疑挂载前缀与允许写入的 Agent 数据目录

安装链会把这些文件分别部署到：

- `/etc/udev/rules.d/99-aegis-removable.rules`
- `/etc/usbguard/rules.conf`
- `/etc/aegis/device-control/mount-monitor.conf`
