# Aegis Linux 剩余研发计划（2026-04-19）

> 来源：
> - `docs/plan/2026-04-19-linux-platform-runtime-closure.md`
> - `docs/plan/aegis-sensor-rd-plan-audit.md`
> - `docs/architecture/aegis-sensor-architecture.md`
> - `docs/技术方案/sensor-final技术解决方案.md`
> - `docs/env/开发环境.md`
>
> 说明：
> 仓库现有文档统一放在 `docs/plan/`，因此本计划继续沿用该目录，不引入新的 `docs/plans/` 层级。

## 1. 目标

将 Linux 平台从“用户态运行时已收口、内核态真实资产与更强 TPM 绑定未闭合”推进到：

- 仓库内存在真实可编译的 Linux eBPF 资产
- 仓库内存在可复现的 Linux 特权安装/装载/附着/验证链路
- `aegis-core` 存在比 NV index 更强的 TPM sealed-object 主密钥路径
- 所有变更均在 `docs/env/开发环境.md` 指定 Linux 测试机完成真实验证
- 每完成一个阶段，更新研发状态文档并提交一次或多次批次 commit

## 2. 当前基线

截至 2026-04-19，本仓库 Linux 已完成：

- 真实主机能力探测
- 4 级降级模型
- `/proc` 进程差分与 auth log 增量采集
- 信号级响应、隔离/取证 manifest 落盘
- eBPF manifest/load/attach contract 状态机
- TPM NV-backed 主密钥与 rollback anchor
- Linux 容器验证

尚未完成：

- Linux TPM attestation / quote / policy session 级别硬件根信任
- 更高阶生产部署或发行工程项

## 3. 当前进度快照（2026-04-19 续）

- B00：done，已由 `5fcd19c` 固化 Linux runtime / TPM NV / 文档基线。
- B01：代码已完成。`packaging/linux-ebpf/` 已入仓真实 `process/file/network` BPF 资产、`build.sh`、`README.md` 和 manifest。
- B02：done。已在新测试机 `192.168.1.6` 安装 `clang` / `llvm` / `libbpf-dev`，写入 `lsm=lockdown,capability,bpf,landlock,yama,apparmor` 并重启生效；`scripts/linux-ebpf-{sync,install,verify,uninstall}.sh` 已完成真实编译、装载、pin/link/map 校验与最终 verify smoke test。
- B03：done。已修正 sealed-object 路径对真实 `tpm2-tools` 的参数兼容性问题（sealing input 不再显式传 `-G keyedhash`），并在新测试机 `192.168.1.6` 安装 `tpm2-tools` 后通过 `scripts/linux-tpm-sealed-verify.sh` 的 `create + unseal` 真机 roundtrip。
- B04：done。环境文档、状态文档、审计文档与 Linux 收口记录已同步更新，本轮 Linux 剩余研发只剩 attestation / quote 与更高阶发行工程项。

## 4. 执行规则

- 所有 Linux 阶段都必须同时包含代码、验证、文档三个交付面。
- 所有“已完成”都必须以本地测试 + Linux 测试机验证为依据。
- 不把“脚本占位”或“manifest 占位”标记为完成。
- 每个批次提交前必须至少完成：
  - `cargo fmt --all`
  - 受影响 crate 测试
  - 对应 Linux 测试机验证
- 提交策略：
  - B00 完成后提交一次
  - B01 + B02 完成后提交一次
  - B03 + B04 完成后提交一次

## 5. 工作批次

### B00：Linux 基线固化

- 目标：把已实现但未提交的 Linux runtime / TPM NV / 文档收口改动固化为可追踪基线。
- 代码范围：
  - `crates/aegis-platform/src/linux.rs`
  - `crates/aegis-core/src/linux_tpm.rs`
  - `crates/aegis-core/src/self_protection.rs`
  - `crates/aegis-core/src/comms.rs`
  - `crates/aegis-core/src/config.rs`
  - `crates/aegis-core/src/lib.rs`
  - `crates/aegis-core/src/orchestrator.rs`
- 文档范围：
  - `docs/plan/2026-04-19-linux-platform-runtime-closure.md`
  - `docs/plan/aegis-sensor-rd-status.md`
  - `docs/plan/aegis-sensor-rd-plan-audit.md`
- 验收：
  - `cargo test --workspace`
  - Linux 测试机确认 `bpftool` / `clang` / `llc` / TPM 设备存在
  - 提交一条 Linux 基线 commit

### B01：真实 eBPF 资产入仓

- 目标：把 Linux 真实 eBPF 源码、manifest 和构建输出布局正式纳入仓库。
- 交付：
  - `packaging/linux-ebpf/manifest.json`
  - `packaging/linux-ebpf/src/*.bpf.c`
  - `packaging/linux-ebpf/include/` 或生成头文件策略
  - `packaging/linux-ebpf/build.sh`
  - `packaging/linux-ebpf/README.md`
- 能力目标：
  - 至少覆盖 `tracepoint`、`kprobe`、`LSM` 三类 program
  - `manifest.json` 中给出真实 `attach_argv`
  - 产物可被 `bpftool prog loadall` + `bpftool link create` 使用
- 验收：
  - Linux 测试机成功编译出 `.bpf.o`
  - 运行时发现 manifest 后能规划 bundles / attachments
  - 测试机上可以完成 load + attach + pin

### B02：Linux 特权安装与验证链路

- 目标：把 eBPF 资产从“可编译”推进到“可安装、可验证、可卸载”。
- 交付：
  - `scripts/linux-ebpf-sync.sh`
  - `scripts/linux-ebpf-install.sh`
  - `scripts/linux-ebpf-verify.sh`
  - `scripts/linux-ebpf-uninstall.sh`
  - 需要的 `docker-compose.yaml` 或宿主机构建说明
- 能力目标：
  - 同步仓库到 Linux 测试机
  - 远端构建 `.bpf.o`
  - 创建 pin root / map root
  - 装载、附着、健康检查、卸载全链路可执行
  - 输出确定性的验证结果，便于文档沉淀
- 验收：
  - Linux 测试机执行 install + verify 成功
  - 运行 `aegis-platform` 相关测试时，`check_kernel_code` / `check_bpf_integrity` 反映真实 loaded/attached 状态
  - 提交一条 eBPF 资产/安装链 commit

### B03：TPM sealed-object 主密钥路径

- 目标：在 Linux TPM 路径中加入 sealed object 主密钥实现，并保留 NV index fallback。
- 交付：
  - `SecurityConfig` 新增 sealed-object 相关配置
  - `linux_tpm.rs` 新增 sealed object create/load/unseal 路径
  - 必要时加入 PCR policy session 支持
  - 测试 harness 扩展到 sealed-object 场景
- 能力目标：
  - 优先尝试 sealed object
  - sealed object 不可用时诚实回退到 NV index / 其他 provider
  - 错误状态进入 `self_protection` / `comms` 诊断面
- 验收：
  - 本地单元测试覆盖 sealed-object roundtrip
  - Linux 测试机在安装 `tpm2-tools` 后成功执行 create + unseal
  - 文档中将“Linux TPM 仅 NV index”更新为“sealed object 已落地，attestation 仍待完成”

### B04：文档与状态收尾

- 目标：把 Linux 剩余研发从“执行中”收口到明确状态。
- 交付：
  - 更新 `docs/plan/aegis-sensor-rd-status.md`
  - 更新 `docs/plan/aegis-sensor-rd-plan-audit.md`
  - 更新 `docs/plan/2026-04-19-linux-platform-runtime-closure.md`
  - 如有必要，补充 Linux 测试机实测记录
- 验收：
  - 状态文档与代码事实一致
  - 明确剩余未完成项是否只剩 attestation / 更高阶系统集成
  - 提交最终收尾 commit

## 5. 远端验证环境

Linux 测试机来源：`docs/env/开发环境.md`

- IP：`192.168.1.6`
- 用户：`ubuntu`
- 密码：`ubuntu`

执行要求：

- 所有 Linux 特权命令通过 `sudo -S` 明确执行
- 若缺少依赖，优先在测试机安装：
  - `libbpf-dev`
  - `tpm2-tools`
  - 其他构建/验证所需的最小包
- 若需要容器化辅助环境，保留 `docker-compose.yaml`

## 6. 完成定义

仅当以下条件同时满足，才可将本轮 Linux 剩余计划标记为完成：

- B00-B04 全部完成并提交
- Linux 测试机完成 eBPF build/install/verify/uninstall
- Linux 测试机完成 TPM sealed-object create/unseal 验证
- 文档中的 Linux 剩余差距不再包含：
  - 真实 `.bpf.o` 资产缺失
  - 安装/装载/附着链路缺失
  - TPM 仅 NV index

若仍有剩余项，应只允许保留：

- attestation / quote / 远端证明链
- 更高阶生产部署或发行工程项
