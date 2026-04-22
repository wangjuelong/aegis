# Aegis Sensor 总体研发计划与完成状态

> 来源：
> - `docs/技术方案/sensor-final技术解决方案.md`
> - `docs/architecture/aegis-sensor-architecture.md`
> - 既有 `docs/plan/sensor` 历史计划、审计、状态与 Linux 专项收口记录

## 1. 文档定位

本文件是 Aegis Sensor 的总文档，统一说明：

- 总体研发目标与范围
- 跨平台公共工作包
- 当前完成状态
- 剩余未完成事项

平台专项计划与状态见：

- `docs/plan/sensor/sensor-windows-plan.md`
- `docs/plan/sensor/sensor-linux-plan.md`
- `docs/plan/sensor/sensor-macos-plan.md`

## 2. 状态定义

- `done`：已完成代码、验证与文档闭环
- `doing`：已进入实施但未完成闭环
- `todo`：未开始或尚未进入当前仓库交付

## 3. 总体目标

交付目标不是 MVP，而是 Production-Grade 终端 Agent，范围覆盖：

- Windows / Linux / macOS 主线 Sensor
- 内核态或系统级采集、用户态核心运行时、本地检测、响应执行、通信、自保护、升级发布
- 容器宿主机、Sidecar Lite、Runtime SDK、Cloud API Connector
- 诊断、灰度、离线自治、证据链、审批与审计

## 4. 当前总体结论

- 跨平台公共研发包已完成，仓库内主链路已经闭合。
- Linux 在当前测试机可闭合的运行时、eBPF 资产链、TPM key protection、sealed object、quote/checkquote、PCR policy session 已完成。
- Windows 当前已完成平台代码骨架、provider 注册、事件注入、能力矩阵与测试基线，以及真实主机能力探测链、真实进程差分、隐藏进程检测、Security 4688 进程审计事件链、真实网络基线/防火墙隔离执行链、真实文件/注册表/脚本/内存系统采集、自保护/完整性强制执行、真机验收脚本/兼容性矩阵、Windows 驱动工程/安装卸载链/版本化控制通道、Windows 专用 DPAPI/TPM 根信任与回滚锚点方案，以及 release manifest、签名/验签/install gate 与 Windows 11 真机发布验证；但从 EDR 数据采集要求再审视，Windows 仍缺认证采集、深度网络、细粒度进程线程模块、Device/Pipe/VSS 行为、内存注入/YARA 五个采集闭环。
- macOS 当前完成的是平台代码骨架、授权状态机、provider 基线、订阅集与测试基线，真实 ESF / Network Extension / System Extension 交付尚未完成。

## 5. 跨平台公共研发计划与状态

### 5.1 基础工程与运行时

| 工作包 | 目标 | 状态 | 当前结论 |
|--------|------|------|----------|
| P00 | 详细计划与执行基线 | done | 已完成工作包拆分与状态基线重建 |
| P01 | Rust workspace 与基础工程骨架 | done | 已建立 workspace、基础 crate、proto/schema、CI 骨架 |
| P02 | 配置模型与 schema versioning | done | 已建立 `AgentConfig`、迁移执行器、配置落库路径 |
| P03 | 统一事件模型与 lineage 模型 | done | 已建立 `NormalizedEvent`、`TelemetryEvent`、`Storyline`、lineage checkpoint |
| P04 | Core orchestrator 与通道拓扑 | done | 已建立运行时任务拓扑、通道与优雅退出 |
| P05 | Ring buffer / spill / dispatch | done | 已建立 4-lane 缓冲、spill 存储与 raw → normalized 转换 |
| P06 | ProcessTree / Hashing / AdaptiveWhitelist / Health | done | 已建立进程树、哈希缓存、自适应白名单与健康快照 |
| P07 | 平台 trait 与 mock harness | done | 已建立平台能力矩阵、descriptor 与可验证 mock 契约 |

### 5.2 平台基线

| 工作包 | 目标 | 状态 | 当前结论 |
|--------|------|------|----------|
| P08 | Windows 平台采集基线 | done | 已完成 Windows 平台骨架与测试基线，真实系统级交付仍待 Windows 专项计划 |
| P09 | Linux 平台采集基线 | done | 已完成 Linux 平台骨架，并继续收口真实 Linux 运行时、eBPF 与 TPM 基线 |
| P10 | macOS 平台采集基线 | done | 已完成 macOS 平台骨架与测试基线，真实系统级交付仍待 macOS 专项计划 |

### 5.3 检测、关联与分析

| 工作包 | 目标 | 状态 | 当前结论 |
|--------|------|------|----------|
| P11 | IOC / Rule VM / Temporal | done | 已完成分层 IOC、规则虚拟机与时间窗口检测 |
| P12 | YARA / Script Decode / AMSI Interlock | done | 已完成 YARA 调度、脚本解码、AMSI 快速联动 |
| P13 | ML / OOD / Behavioral Models | done | 已完成 ONNX 接口、特征转换、OOD 判定与失败回退 |
| P14 | Correlation / Storyline / Threat Feedback | done | 已完成关联缓存、故事线合并与反馈回灌 |
| P15 | 专项检测能力 | done | 已完成勒索、ASR、身份与诱捕专项检测输出 |
| P16 | Vuln Scan / Passive Discovery / AI Monitor | done | 已完成软件清单匹配、被动发现缓存与 AI 风险监控基线 |

### 5.4 响应、自保护与审批

| 工作包 | 目标 | 状态 | 当前结论 |
|--------|------|------|----------|
| P17 | Response Executor / Quarantine / Kill | done | 已完成两阶段终止、文件隔离、审计落盘 |
| P18 | Block Decision / Network Isolate / Firewall | done | 已完成 TTL 阻断映射、隔离策略与审计 |
| P19 | Registry / Filesystem Rollback / Forensics | done | 已完成回滚计划、文件恢复、证据链与取证归档 |
| P20 | Remote Shell / Session Lock / Approval Queue | done | 已完成审批队列、远程 shell 约束与会话锁定审计模型 |
| P21 | Self-Protection / Keys / Crash Exploit Analysis | done | 已完成自保护状态机、密钥派生、证书 hook 与崩溃分析基线 |

### 5.5 通信、持久化、升级与扩展形态

| 工作包 | 目标 | 状态 | 当前结论 |
|--------|------|------|----------|
| P22 | Comms / SignedCommand / ApprovalProof | done | 已完成命令验签、scope 校验、重放防护与审批证明校验 |
| P23 | WAL / Forensic Journal / Emergency Audit Ring | done | 已完成三类持久化面与 ACK-gated replay 闭环 |
| P24 | Upgrade / Migration / Canary Gate / Diagnose | done | 已完成升级计划、迁移编排、灰度门控与 `--diagnose` |
| P25 | Container Host Agent / Sidecar Lite | done | 已完成容器宿主机与 sidecar lite 契约与测试基线 |
| P26 | Runtime SDK / Cloud API Connector | done | 已完成 runtime SDK 与 cloud connector 基线 |
| P27 | QE / Pilot / Merge / Release | done | 已完成仓库内 QE/试点/发布文档与主分支闭环 |

## 6. 平台专项剩余计划与状态

| 编号 | 剩余事项 | 状态 | 说明 |
|------|----------|------|------|
| O01 | Linux 更高阶 remote attestation / verifier 分离信任链 | done | 已完成 attestation bundle、verifier receipt 与本地正反向验证，真实 TPM 测试主机补齐后可直接复跑 |
| O06 | Linux 安装 / 发布工程（DEB/RPM + systemd + validate） | done | 已完成 install manifest、systemd、包构建入口与 `192.168.2.123` 原生 RPM 安装/自检/watchdog/卸载闭环 |
| O07 | Linux 容器 / Sidecar / Runtime Connector 交付链 | done | 已完成最小权限 Host Agent DaemonSet、Sidecar Lite Pod 样例、Runtime SDK / Cloud Connector 样例目录与 `scripts/linux-container-validate.sh` 校验链 |
| O08 | Linux 设备控制链（udev / USBGuard / mount monitor） | done | 已完成 Linux `DeviceControl` provider、设备控制配置目录与 `scripts/linux-device-control-validate.sh` / `.123` 安装链验收 |
| O09 | Linux Runtime SDK / Cloud Connector 多语言交付 | done | 已完成 `Python/Node.js/Go/Java/.NET` 五种参考 SDK、多云 connector 合同与 `scripts/linux-container-validate.sh` 多语言验证链 |
| O02 | Windows 真实运行时、事件链路、响应链与系统级交付 | doing | 运行时主链已闭环，但仍有 5 个 Windows EDR 数据采集缺口待收口，详见 `sensor-windows-plan.md` 中 `W22-W26` |
| O03 | Windows 正式硬件根信任、签名与兼容性验证 | done | 已完成仓库侧 release manifest、签名/验签/install gate、批准依赖校验与支持矩阵文档；Microsoft 正式签发与更多主机 rollout 继续依赖仓库外流程 |
| O10 | Windows 真实 MSI 工程 | done | 已完成 MSI 构建脚本、`validate.ps1` / `windows-package-verify.sh` 验收链，并在 `.218` 上完成 `msiexec` 安装/卸载闭环 |
| O11 | Linux Debian/Ubuntu 的真实 DEB 安装验收链 | done | 已完成 `.123 build -> .226 dpkg -i / dpkg -P` 验收链，本地输出 Ubuntu 验收 JSON 与 install/bootstrap/watchdog/diagnose 工件 |
| O04 | macOS ESF / Network Extension / System Extension 真实系统级交付 | todo | 当前仅完成 macOS 平台骨架与测试基线 |
| O05 | macOS notarization、授权流与正式硬件根信任 | todo | 当前未完成签名、公证、用户批准与 Secure Enclave/Keychain 正式接入 |

## 7. 当前完成判定

当前仓库可以诚实判定为：

- 公共运行时、检测、响应、通信、升级、容器与扩展形态：已完成
- Linux 测试机可闭合项：已完成
- Windows / macOS 最终系统级平台交付：未完成

因此，总体状态应定义为：

- 仓库内公共能力研发：`done`
- 平台终态研发：`doing`
