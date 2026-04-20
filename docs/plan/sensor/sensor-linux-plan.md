# Aegis Sensor Linux 研发计划与完成状态

> 来源：
> - `docs/技术方案/sensor-final技术解决方案.md`
> - `docs/architecture/aegis-sensor-architecture.md`
> - 既有 Linux 运行时收口、TPM attestation 与剩余研发记录

## 1. 文档定位

本文件统一描述 Linux 平台研发计划、完成状态与剩余差距，不再拆分多个 Linux 子文档。

## 2. 状态定义

- `done`：已完成代码、验证与文档闭环
- `doing`：已进入实施但未完成闭环
- `todo`：未开始

## 3. Linux 目标范围

Linux 平台目标覆盖：

- 真实主机能力探测与 4 级降级模型
- 真实用户态事件采集与信号级响应
- eBPF 资产、loader、pin/link、安装/验证/卸载链
- TPM NV-backed key protection 与 rollback anchor
- sealed-object 主密钥路径
- quote / checkquote attestation baseline
- PCR policy session 绑定的 sealed-object 解封
- Linux 容器验证与诊断面集成

## 4. 当前总体结论

- 当前开发机与 Linux 测试机可闭合的 Linux 研发项已完成。
- 剩余未完成项已经收缩为更高阶 remote attestation / verifier 分离信任链，以及更高阶生产部署/发行工程。

## 5. Linux 研发计划与状态

| 工作包 | 目标 | 状态 | 当前结论 |
|--------|------|------|----------|
| L01 | 主机能力探测与降级模型 | done | 已完成 `bpffs` / BTF / `bpftool` / fanotify / auth log / TPM / LSM 等主机能力探测，并可动态推导 `Full / TracepointOnly / FanotifyAudit / Minimal` |
| L02 | 真实用户态事件采集 | done | 已完成 `/proc` 进程差分与 auth log 增量采集，`poll_events()` 不再只是注入队列 |
| L03 | Linux 响应执行与物料落盘 | done | 已完成信号级 `suspend/kill`、隔离、取证打包、protection/firewall manifest 落盘 |
| L04 | eBPF 资产发现、loader 与 attach contract | done | 已完成 manifest 驱动的 bundle discovery、pin root/link 状态识别与 `bpftool prog loadall` 受控装载路径 |
| L05 | 真实 eBPF 资产与安装/验证链 | done | 已入仓 `process/file/network` BPF 资产、`build.sh` 与 `linux-ebpf-{sync,install,verify,uninstall}.sh`，并完成真机编译、装载、校验、卸载 |
| L06 | TPM NV-backed 主密钥与 rollback anchor | done | 已完成 Linux TPM tools/device/NV index provider、`HardwareBound` 主密钥路径与 rollback floor 持久化 |
| L07 | TPM sealed-object 主密钥路径 | done | 已完成 sealed-object 主路径、sealed 优先 / NV fallback 与真实 `tpm2-tools` 参数兼容 |
| L08 | TPM quote / checkquote attestation baseline | done | 已完成 AK/PCR 配置、quote/checkquote 运行时、诊断状态与真机正反向验收 |
| L09 | TPM PCR policy session 绑定 | done | 已完成 `linux_tpm_master_key_pcrs`、policy digest、`session:<ctx>` 解封与真机正反向验收 |
| L10 | Linux 容器验证与诊断集成 | done | 已完成 Linux 容器内 `cargo test` 基线验证与 `aegis-agentd -- --diagnose` 诊断接线 |
| L11 | 更高阶 remote attestation / verifier 分离信任链 | todo | 当前仅完成单机 TPM attestation baseline，未完成远端 verifier、信任根与证明链 |
| L12 | Linux 生产部署、签名与发行工程 | todo | 当前已具备测试机闭环，但更高阶生产打包、发行与长期运维工程未单独收口 |

## 6. 已完成验证

本地已完成：

- `cargo fmt --all`
- `cargo test -p aegis-core`
- `cargo test -p aegis-platform`
- `cargo test --workspace`
- `cargo check -p aegis-agentd`
- `AEGIS_STATE_ROOT=$(mktemp -d) cargo run -p aegis-agentd -- --diagnose`
- `bash -n scripts/linux-ebpf-install.sh scripts/linux-ebpf-verify.sh scripts/linux-ebpf-sync.sh scripts/linux-ebpf-uninstall.sh packaging/linux-ebpf/build.sh scripts/linux-tpm-sealed-verify.sh scripts/linux-tpm-quote-verify.sh scripts/linux-tpm-policy-verify.sh`

Linux 测试机已完成：

- `scripts/linux-ebpf-install.sh`
- `scripts/linux-ebpf-verify.sh`
- `scripts/linux-ebpf-uninstall.sh`
- `scripts/linux-tpm-sealed-verify.sh`
- `scripts/linux-tpm-quote-verify.sh`
- `scripts/linux-tpm-policy-verify.sh`

## 7. Linux 完成定义

当且仅当以下判断同时成立，Linux 计划中的对应工作包才可标记为 `done`：

- 仓库内存在真实代码或脚本交付
- 本地测试通过
- Linux 测试机完成对应真机验证
- 文档状态已同步更新

按当前事实，Linux 文档应保持：

- `L01-L10 = done`
- `L11-L12 = todo`

