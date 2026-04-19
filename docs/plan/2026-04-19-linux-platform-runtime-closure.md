# Aegis Linux 平台运行时收口记录

> 时间：2026-04-19
> 范围：`crates/aegis-platform/src/linux.rs`、`crates/aegis-core/src/self_protection.rs`、`crates/aegis-core/src/comms.rs`、`crates/aegis-core/src/linux_tpm.rs`、`crates/aegis-core/src/config.rs`、`packaging/linux-ebpf/`、`scripts/linux-*.sh`
> 目标：把 Linux 相关能力从“纯 in-memory baseline/stub + 硬件根信任缺口”推进到“具备真实主机探测、真实用户态事件采集、真实响应落盘、真实 eBPF 资产与安装链、TPM-backed key/rollback provider、sealed-object 主密钥路径”的可验证状态。

## 1. 本次收口内容

本次仅收口 Linux 相关、且当前仓库内可在现有环境完成的部分：

- 真实 Linux host capability probing
- 4 级降级模型与能力矩阵按主机状态动态推导
- `/proc` 进程差分事件采集
- auth log 增量采集
- 信号级响应执行
- 隔离、取证、保护 manifest 的真实物料落盘
- eBPF attachment/link manifest contract 与 link 完整性状态
- Linux TPM NV index-backed 主密钥与 rollback anchor provider
- Linux 真实 eBPF 资产、`autoattach`/`pinmaps` 装载模型与特权安装/验证脚本
- Linux TPM sealed-object 主密钥路径与 NV fallback
- Linux 容器环境下的测试验证

本次**不谎称完成**以下事项：

- Linux eBPF 强制执行面的最终真机验收闭环
- Linux TPM sealed object 的测试机 create/unseal 真机验收
- Linux TPM policy session / attestation / quote 级别硬件根信任
- Windows / macOS 的正式硬件根信任与系统级交付

## 2. 已交付能力

### 2.1 主机能力探测

Linux 平台初始化与 `start()` 路径已改为探测真实主机状态，而不是固定 stub：

- `bpffs`
- `BTF`
- `bpftool`
- `fanotify`
- auth log
- `journalctl`
- `nft` / `iptables`
- `AppArmor`
- `TPM`
- container metadata
- LSM stack

### 2.2 运行时降级语义

`LinuxDegradeLevel` 现按真实主机状态推导：

- `Full`
- `TracepointOnly`
- `FanotifyAudit`
- `Minimal`

相关健康状态、能力矩阵、完整性报告已同步改为基于真实探测结果输出。

### 2.3 eBPF 资产、装载与 attach contract

Linux 平台已新增面向内核侧集成的真实状态机：

- `manifest.json` 驱动的 eBPF bundle discovery
- bundle 到 pin root 的规划
- 已存在 pin 目录的加载态识别
- attachment/link 元数据规划
- 已存在 link pin 的附着态识别
- `bpftool prog loadall` 的受控 opt-in 装载路径
- `check_kernel_code()` / `check_bpf_integrity()` 对资产、bundle、attachment、pin root、加载错误的真实反映

说明：

- 运行时 manifest 已升级为真实 `autoattach` / `pinmaps` 语义，可识别 auto-attached link 与 pinned map 布局
- 仓库已新增 `packaging/linux-ebpf/manifest.json`、`process.bpf.c`、`file.bpf.c`、`network.bpf.c` 与 `build.sh`
- 仓库已新增 `scripts/linux-ebpf-{sync,install,verify,uninstall}.sh`，覆盖远端同步、编译、装载、校验、卸载链路
- `linux-ebpf-verify.sh` 会在执行 smoke test 前显式检查活动 LSM 是否包含 `bpf`，避免把环境问题误判成功能故障
- 当前缺口不再是“资产未入仓”，而是测试机启用 `bpf` LSM 后离线，导致最终强制执行真机验收尚未收口

### 2.4 Linux TPM-backed 主密钥与 rollback anchor

`aegis-core` 已新增 Linux TPM provider 路径：

- `SecurityConfig` 新增 Linux TPM tools/device/NV index 配置项
- 主密钥可通过 TPM NV index 真实读写，成功时 `KeyProtectionTier=HardwareBound`
- rollback protection 可通过 TPM NV index 持久化 `floor_issued_at_ms`
- 允许显式 opt-in 的 NV auto provisioning
- provider 状态在 fallback 时会诚实反映“TPM 可用但未配置”或“TPM provider 失败后已降级”

说明：

- 当前实现已新增 sealed-object 主密钥路径、sealed 优先 / NV fallback 与 `TPM2TOOLS_TCTI=device:/dev/tpmrm0` 设备绑定
- 仓库已新增 `scripts/linux-tpm-sealed-verify.sh`，用于测试机上的 `createprimary/create/load/unseal` 真机 roundtrip 验收
- owner/index auth 通过环境变量注入，避免把敏感认证材料固化进配置文件
- rollback anchor 仍基于 TPM NV index；policy session / attestation 尚未进入当前仓库

### 2.5 真实用户态事件采集

`poll_events()` 不再只 drain 注入队列，现会先采集实时 Linux 事件：

- `/proc` 进程差分产生 `process-start` / `process-exit`
- auth log 增量读取产生 `auth-log`
- 注入事件仍保留，便于平台层单元测试

### 2.6 真实响应与物料落盘

以下动作已从“仅改内存快照”升级为真实用户态执行/落盘：

- `suspend_process()` -> `kill -STOP`
- `kill_process()` / `kill_ppl_process()` -> `kill -KILL`
- `quarantine_file()` -> 真实 SHA-256、vault 落盘、源文件移除
- `collect_forensics()` -> 真实 staging 目录、系统快照、tar 包
- `protect_process()` / `protect_files()` -> protection manifest
- `network_isolate()` / `network_release()` -> firewall manifest

说明：

- firewall 真实应用仍为 opt-in，需 `AEGIS_LINUX_APPLY_FIREWALL=1`
- 当前默认保证 manifest 与状态闭环，不默认写入主机防火墙

## 3. 验证结果

### 3.1 本地验证

- `cargo fmt --all`
- `cargo test -p aegis-core`
- `cargo test -p aegis-platform`
- `cargo test --workspace`
- `cargo test -p aegis-core linux_tpm -- --nocapture`
- `bash -n scripts/linux-ebpf-install.sh scripts/linux-ebpf-verify.sh scripts/linux-ebpf-sync.sh scripts/linux-ebpf-uninstall.sh packaging/linux-ebpf/build.sh scripts/linux-tpm-sealed-verify.sh`

### 3.2 Linux 容器验证

在 Linux 用户态容器内执行：

```bash
docker run --rm \
  -v /Users/lamba/.config/superpowers/worktrees/aegis/feat-linux-platform-runtime:/work \
  -w /work \
  rust:bookworm \
  sh -lc 'apt-get update \
    && apt-get install -y pkg-config libdbus-1-dev \
    && /usr/local/cargo/bin/cargo test -p aegis-core -p aegis-platform'
```

说明：

- 官方 `rust:bookworm` 基础镜像默认未包含 `libdbus-1-dev`
- 容器内 `cargo` 位于 `/usr/local/cargo/bin`
- `rust:1.88-bookworm` 已低于当前依赖树要求的 `rustc >= 1.91`，不再适合作为稳定容器验证基线

结果：

- `aegis-core` `119/119` 通过
- `aegis-platform` `22/22` 通过

### 3.3 Linux 测试机验证

测试机来源：`docs/env/开发环境.md`

已确认：

- `bpftool`、`clang`、`llc`、`libbpf-dev` 已存在
- `/dev/tpm0` 与 `/dev/tpmrm0` 已存在
- 真实 `process/file/network` BPF 资产可在测试机编译成功
- `scripts/linux-ebpf-install.sh` 已成功完成远端编译、装载，并产生真实 pin/link/map
- `bpftool link show` 已确认 `tracepoint`、`kprobe` 与 `lsm/*` link 被创建

补充说明：

- 初始失败根因已定位为测试机活动 LSM 顺序不含 `bpf`
- 已把 `lsm=lockdown,capability,bpf,landlock,yama,apparmor,ima,evm` 写入测试机 GRUB 配置并触发重启
- 当前测试机在重启后离线，因此：
  - `scripts/linux-ebpf-verify.sh` 的最终强制执行 smoke test 尚未补完
  - `scripts/linux-tpm-sealed-verify.sh` 的 `create + unseal` 真机 roundtrip 尚未补完

## 4. 剩余差距

Linux 相关未完成项已收缩为：

- eBPF 强制执行链在 Linux 测试机恢复后的最终真机验收
- TPM sealed-object `create + unseal` 在 Linux 测试机恢复后的最终真机验收
- Linux TPM attestation / quote / policy session 级别硬件根信任

因此，Linux 平台现在可以诚实地标记为：

- 用户态运行时：已收口
- 内核态 loader/pin/link 生命周期与 attach contract：已进入代码
- 内核态真实资产与特权安装链：已进入代码
- Linux TPM-backed key protection / rollback anchor：已进入代码
- Linux TPM sealed-object 主密钥路径：已进入代码
- Linux 测试机最终强制执行验收：未收口
