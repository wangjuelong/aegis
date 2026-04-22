# Linux 安装 / 发布工程计划

## 1. 目标

把当前 Linux 仅有的 eBPF 资产构建脚本升级为完整的安装/发布工程，保证：

- 交付 Linux 包安装链：`DEB/RPM + systemd + eBPF assets + config`
- 安装时完成 kernel feature / BTF/CO-RE / bpffs 检查
- 安装后完成首启自检、回滚与卸载
- 仓库内具备 validate 入口，而不是只有手工脚本

## 2. 当前缺口

- 文档要求 `DEB/RPM + systemd service + eBPF assets + 首启检查`，仓库里只有 `packaging/linux-ebpf`。
- 没有 Linux 安装 manifest、systemd unit、install/uninstall/validate 脚本。
- 没有仓库内的 Linux 包验收入口与回滚记录。

## 3. 不妥协约束

- 不接受只复制 eBPF 对象文件，不交付 Agent / Watchdog / Updater。
- 不接受没有 systemd unit、首启检查和卸载回滚的“半包”。
- 不接受安装前不检查 kernel/BTF/bpffs 兼容性。
- 不接受 validate 只做 shell 语法检查，不做真实 build/install/self-check。

## 4. 研发范围

### 4.1 packaging/linux

- 新增 Linux install manifest
- 新增 systemd unit：
  - `aegis-agentd.service`
  - `aegis-watchdog.service`
- 组装 agent binary、watchdog、updater、config、eBPF assets

### 4.2 install / uninstall / validate

- 新增：
  - `packaging/linux/install.sh`
  - `packaging/linux/uninstall.sh`
  - `packaging/linux/validate.sh`
- 覆盖：
  - kernel feature / BTF / bpffs 检查
  - 文件复制 / 权限 / systemd daemon-reload
  - 首启 `aegis-agentd --bootstrap-check`
  - 回滚与卸载

### 4.3 包构建

- 新增 `DEB` / `RPM` 构建入口脚本
- 对缺失工具链的情况明确 fail-fast
- 输出 release artifact 清单与校验和

### 4.4 验证

- 本地构建 validate
- Linux 测试机安装 / 自检 / 卸载闭环

## 5. 交付物

- `packaging/linux/`
- `scripts/linux-package-verify.sh`
- `crates/aegis-agentd/src/main.rs`
- `crates/aegis-watchdog/src/main.rs`

## 6. 完成判定

- 仓库内可构建 Linux `DEB/RPM`
- Linux 测试机完成 install / bootstrap-check / watchdog / uninstall 闭环
- validate 输出 `required_failures=[]`

## 7. 实际交付

- 代码提交：`4bac302 feat(linux): 完成安装发布工程与原生包验收链`
- 已新增：
  - `packaging/linux/manifest.json`
  - `packaging/linux/install.sh`
  - `packaging/linux/uninstall.sh`
  - `packaging/linux/validate.sh`
  - `packaging/linux/build-bundle.sh`
  - `packaging/linux/build-packages.sh`
  - `packaging/linux/systemd/aegis-agentd.service`
  - `packaging/linux/systemd/aegis-watchdog.service`
  - `scripts/linux-package-verify.sh`
- 已补齐：
  - Linux install manifest 已进入通用安装 manifest 体系，`aegis-agentd --bootstrap-check` 可校验 `config_root` 与 systemd unit
  - Linux 包验证链可在 `192.168.2.123` 上完成原生 `RPM/DEB` 构建、RPM 安装、自检、watchdog、诊断与卸载
  - `packaging/linux-ebpf/build.sh` 已支持 vendored `libbpf` headers 与主机 BTF 驱动的真实编译，不再依赖目标机仓库提供 `libbpf-devel`

## 8. 验证结果

本地已完成：

- `bash -n packaging/linux/install.sh packaging/linux/uninstall.sh packaging/linux/build-packages.sh packaging/linux/validate.sh scripts/linux-package-verify.sh`
- `cargo test -p aegis-core install_manifest -- --nocapture`
- `cargo check -p aegis-agentd`

Linux 测试机 `192.168.2.123` 已完成：

- `./scripts/linux-package-verify.sh`
- 关键结果：
  - `deb_package=/root/aegis-linux-package-verify/target/linux-package-validate/output/aegis-sensor_0.1.0-1_amd64.deb`
  - `rpm_package=/root/aegis-linux-package-verify/target/linux-package-validate/output/aegis-sensor-0.1.0-1.el8.x86_64.rpm`
  - `bootstrap_report.approved=true`
  - `watchdog.alerts=[]`
  - `required_failures=[]`

本地验收工件：

- `target/linux-validation/192.168.2.123.json`

## 9. 结论

- `L12` 已完成代码、真机验收与文档闭环。
- Linux 剩余未完成项收敛为 `L13 Linux 容器 / Sidecar / Runtime Connector 交付链`。
