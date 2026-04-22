# Linux DEB 真机安装验收计划

> 当前状态：`done`

## 1. 目标

把当前 Linux `DEB` 仅做元信息检查的验证链升级为真实 Debian/Ubuntu 主机上的安装、校验与卸载闭环，保证：

- `.226` 上真实执行 `dpkg -i`
- 安装后完成 bootstrap-check、watchdog、诊断验证
- 卸载后清理安装目录、状态目录、配置目录
- 验证结果与现有 RPM 链保持同等级别工件输出

## 2. 原始缺口

- 当前 `validate.sh` 只对 `DEB` 执行 `dpkg-deb --info`，没有真实安装。
- 当前 `linux-package-verify.sh` 只在 `.123` 上走 RPM 原生验收。
- 没有 Ubuntu/Debian 主机上的安装/卸载验证入口。

## 3. 不妥协约束

- 不接受继续用 `dpkg-deb --info` 冒充安装验收。
- 不接受只验证包能生成，不验证服务启动。
- 不接受卸载不清理 `/opt/aegis`、`/var/lib/aegis`、`/etc/aegis`。
- 不接受 Debian/Ubuntu 链和 RPM 链输出口径不一致。

## 4. 研发范围

### 4.1 validate 链升级

- 扩展 `packaging/linux/validate.sh`
- 新增对 `DEB` 的真实安装/卸载分支

### 4.2 Ubuntu 主机验收入口

- 扩展 `scripts/linux-package-verify.sh`
- 让 `.226` 走 `DEB` 原生安装链

### 4.3 验收工件

- 安装结果工件
- bootstrap-check 工件
- watchdog 工件
- diagnose 工件
- `required_failures=[]`

## 5. 交付物

- `packaging/linux/validate.sh`
- `scripts/linux-package-verify.sh`
- `docs/plan/sensor/sensor-linux-plan.md`

## 6. 完成判定

- `.226` 上可完成真实 `DEB` 安装、校验、卸载
- 与 `.123` RPM 验收链并存，不互相覆盖
- 本地输出 Ubuntu 验收 JSON 工件
- 文档状态同步更新

## 7. 完成结果

- `packaging/linux/validate.sh` 已重组为三种模式：
  - `build-only`
  - `rpm`
  - `deb`
- `scripts/linux-package-verify.sh` 已改成双主机链路：
  - `.123` 负责构建 `DEB/RPM`
  - `.226` 负责真实 `dpkg -i` / `dpkg -P` 验收
- 本地已回收以下 Ubuntu 验收工件：
  - `target/linux-validation/192.168.2.226.json`
  - `target/linux-validation/192.168.2.226-artifacts/install-result.json`
  - `target/linux-validation/192.168.2.226-artifacts/bootstrap-check.json`
  - `target/linux-validation/192.168.2.226-artifacts/watchdog-state.json`
  - `target/linux-validation/192.168.2.226-artifacts/diagnose.json`

## 8. 验收记录

- 构建主机：`192.168.2.123`
- 验收主机：`192.168.2.226`
- 官方入口：`AEGIS_LINUX_PACKAGE_FORMAT=deb ./scripts/linux-package-verify.sh`
- 最新结果：
  - `required_failures=[]`
  - `.226` 完成真实 `dpkg -i`
  - 安装后 `aegis-agentd.service` / `aegis-watchdog.service` 均通过
  - 卸载后 `/opt/aegis`、`/var/lib/aegis`、`/etc/aegis` 均清理完成
