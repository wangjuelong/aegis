# Aegis Sensor 研发计划覆盖审计

> 审计对象：
> - `docs/技术方案/sensor-final技术解决方案.md`
> - `docs/architecture/aegis-sensor-architecture.md`
> - `docs/plan/aegis-sensor-rd-plan.md`

## 1. 审计结论

> 说明（2026-04-19 三次修订）：
> 本文档此前虽然回退了“已全部完成”的错误判断，但对 `C01-C04` 完成后的剩余差距仍然过于乐观。
> 当前结论以 2026-04-19 的第三轮实现复核为准，并由
> `docs/plan/2026-04-19-agent-round3-closure.md` 作为新的执行基线。

### 1.1 对“原生成计划”的结论

原生成计划总体方向正确，但**不完全满足**两份源文档，存在若干“弱覆盖”与“未显式交付”项，不能直接作为最终落地版发布。

### 1.2 对“落地版计划”的结论

`docs/plan/aegis-sensor-rd-plan.md` 对终态能力做了完整规划，但**当前代码实现**并未达到对应完成度。按 2026-04-19 的第三轮复核结果：

- **功能缺失：有**
- **功能妥协：有**
- **设计妥协：有**

当前问题不在于计划缺失，而在于实现层存在明显的“骨架化交付”：

- 主运行时此前没有把检测、决策、故事线、反馈、响应装配成闭环；该缺口已由 C01（提交 `61c22e4`）收口
- 下行命令链此前缺少 `comms-rx`、持久化 replay ledger 与 ACK/执行桥接；该缺口已由 C02（提交 `ba818b8`）收口
- 插件宿主此前仍不是 `wasmtime` 沙箱，只是 wasm 文件校验器；该缺口已由 C03（提交 `4035bd2`）收口
- `watchdog`、`updater`、`--diagnose` 的 demo/静态拼装缺口已由 C04（提交 `88c6de2`）收口
- 传输栈 loopback/demo 化缺口已由 C05（提交 `7961edd`）收口
- 但仓库内仍然存在未闭合项：
  - 主密钥 provider、rollback floor 与敏感内存强化尚未真正接线
  - `TelemetryWal` / `ForensicJournal` 还没有进入 ACK-gated retry / replay 闭环
  - `upload_artifact` / `pull_update` 仍停留在 proto / driver 测试层，未进入 agent 运行时闭环
- 平台真实内核/系统集成与 TPM/Secure Enclave 绑定仍属于外部工程

## 2. 审计方法

- 以两份源文档的一级能力域和关键二级能力项为基准建立矩阵。
- 审计维度包括：采集、核心引擎、检测、响应、通信、自保护、升级、容器、平台兼容、接口、性能、安全、运维。
- 状态定义：
  - `covered`：计划中已有明确交付与归属
  - `weak`：计划提及但未形成明确交付项或退出标准
  - `missing`：计划未覆盖
  - `design deviation`：计划表达与源设计冲突

## 3. 原生成计划缺口清单

下表说明为什么原生成计划不能直接落盘为最终版：

| 项目 | 源文档要求 | 原生成计划状态 | 结论 |
|------|------------|----------------|------|
| Named Pipe / IPC 监控 | 技术方案 2.7 | 未显式列为交付项 | missing |
| DLL 加载深度监控 | 技术方案 2.8 | 未显式列为交付项 | missing |
| VSS / 文件系统快照保护 | 技术方案 2.9 | 只在高层提及 | weak |
| 设备控制 | 技术方案 2.10 / 架构 4.9.7 | 只在高层提及 | weak |
| 本地漏洞评估 | 技术方案 9.3 / 架构 4.9.4 | 未列为独立交付 | missing |
| 被动网络设备发现 | 技术方案 9.4 / 架构 4.9.5 | 未列为独立交付 | missing |
| 本地 AI 应用安全监控 | 技术方案 9.5 / 架构 4.9.6 | 未列为独立交付 | missing |
| 用户会话锁定 | 架构 4.4.4 | 未列为独立动作 | missing |
| Playbook 细粒度约束 | 架构 4.4.4 / 4.4.8 | 未覆盖 `max_executions` / revocation floor / target_scope | weak |
| management-only 与 break-glass | 架构 4.4.8 | 未显式写入 | weak |
| Telemetry WAL 水位降级 | 架构 4.5.3 | 未显式写入 | weak |
| `PARTIAL` 完整性标记 | 架构 4.5.3 / 5.3 | 未显式写入 | missing |
| Emergency Audit Ring | 架构 4.5.3 | 未显式写入 | missing |
| Linux 4 级降级能力 | 技术方案 2.3 / 架构 10.7 | 未显式写入交付要求 | weak |
| Sidecar / Runtime SDK / Cloud API | 技术方案 10 / 架构 8.4 | 提及但不够明确 | weak |

## 4. 落地版计划覆盖矩阵

| 能力域 | 关键要求 | 计划章节 | 状态 |
|--------|----------|----------|------|
| 总体目标 | 完整能力版、非 MVP | 计划 §1、§2 | covered |
| 设计原则 | 不删功能、不降设计、接口不分叉 | 计划 §2 | covered |
| 三平台主线 | Windows / Linux / macOS | 计划 §3.1、§5.2 | covered |
| 八类主传感器 | 进程、文件、网络、注册表、认证、脚本、内存、容器 | 计划 §3.1、§5.2 | covered |
| Named Pipe / IPC | Windows/Linux IPC 监控 | 计划 §3.1、§5.2 | covered |
| DLL 深度监控 | sideloading / phantom DLL | 计划 §3.1、§5.2 | covered |
| 快照保护 | VSS / btrfs / APFS snapshot 基础 | 计划 §3.1、§5.2、§5.4 | covered |
| 设备控制 | USB/外设/可移动介质策略 | 计划 §3.1、§5.2 | covered |
| 核心运行时 | Orchestrator / Dispatch / ProcessTree / Hashing | 计划 §3.2、§5.3 | covered |
| 数据平面 | Ring Buffer / Spill / lineage / health | 计划 §3.2、§5.3 | covered |
| IOC 匹配 | Tiered Bloom + Cuckoo | 计划 §3.3、§5.4 | covered |
| 检测流水线 | Stage 0-5 全链路 | 计划 §3.3、§5.4 | covered |
| 脚本/AMSI | AMSI Interlock + 解混淆 | 计划 §3.3、§5.4 | covered |
| YARA / ML | YARA、ONNX、OOD | 计划 §3.3、§5.4 | covered |
| 勒索专项 | 4 层检测 | 计划 §3.3、§5.4 | covered |
| ASR / 身份 / 欺骗 | ASR、Identity、Deception | 计划 §3.3、§5.4 | covered |
| Storyline / 反馈回路 | Storyline、Adaptive Whitelist | 计划 §3.3、§5.3、§5.4 | covered |
| 漏洞评估 | 软件清单、CVE、配置审计 | 计划 §3.3、§5.4 | covered |
| 被动网络发现 | 完全被动资产发现 | 计划 §3.3、§5.4 | covered |
| AI 监控 | 影子 AI、DLP、模型完整性 | 计划 §3.3、§5.4 | covered |
| 响应执行 | Suspend/Kill/PPL-aware | 计划 §3.4、§5.5 | covered |
| 预防性阻断 | Block Decision Map | 计划 §3.4、§5.5 | covered |
| 隔离与回滚 | Quarantine、网络隔离、注册表回滚、文件系统回滚 | 计划 §3.4、§5.5 | covered |
| 用户会话锁定 | 离线/预审批语义 | 计划 §3.4、§5.5 | covered |
| Remote Shell | 双人审批、会话限制、审计 | 计划 §3.4、§5.5 | covered |
| Playbook | TTL、执行次数、撤销基线、目标约束 | 计划 §3.4、§5.5 | covered |
| 自保护 | 四层防护、密钥、证书、崩溃利用分析 | 计划 §3.4、§5.5 | covered |
| 通信回退链 | gRPC/WebSocket/Long-Polling/Domain Fronting | 计划 §3.5、§5.6 | covered |
| 命令安全 | SignedServerCommand、scope、replay、approval proof | 计划 §3.5、§5.6 | covered |
| WAL | Telemetry WAL / Forensic Journal / Emergency Audit Ring | 计划 §3.5、§5.6 | covered |
| WAL 降级语义 | 水位降级、`PARTIAL` 标记 | 计划 §3.5、§5.6 | covered |
| 离线自治 | pending 审批队列、恢复回放 | 计划 §3.5、§5.6 | covered |
| 升级发布 | A/B、Schema、配置迁移、灰度 Gate | 计划 §3.5、§5.6 | covered |
| 诊断模式 | `aegis-sensor --diagnose` | 计划 §3.5、§5.6 | covered |
| 容器模式 | 宿主机 Agent、Sidecar Lite | 计划 §3.5、§5.7 | covered |
| Serverless | Runtime SDK、Cloud API Connector | 计划 §3.5、§5.7 | covered |
| 平台兼容性 | OS 版本矩阵、Linux 降级 | 计划 §3.1、§5.2、§5.7 | covered |
| 性能指标 | CPU / RSS / 延迟 / 吞吐 / 带宽 / 磁盘 | 计划 §5.4、§6.2 | covered |
| 安全模型 | Ring 3 防护 / Ring 0 检测 / 审批与签名 | 计划 §2、§5.5、§5.6 | covered |
| 发布 Gate | crash/cpu/mem/drop/detection/heartbeat | 计划 §6.2 | covered |

## 5. 是否存在功能缺失或妥协

### 5.1 功能缺失

从“计划覆盖”维度看，终态能力项仍在研发文档中；但从“仓库代码实现”维度看，在 `C05` 完成后，剩余缺失**不只**在外部工程边界，仍包含明确的仓内研发项：

- 主密钥 provider、OS keystore/硬件绑定层级表达、rollback floor 与敏感内存强化未落地
- `TelemetryWal` / `ForensicJournal` 尚未与传输 ACK / replay 正式接线
- `upload_artifact` / `pull_update` 仍未进入运行时任务闭环
- 三平台真实内核/系统集成未落地
- TPM / Secure Enclave / OS keystore 的正式硬件绑定仍未落地

### 5.2 功能妥协

当前主要妥协已从第一轮的“骨架化闭环”收缩，但仍存在两类事实妥协：

- 仓库内仍有正式链路未闭合：密钥保护、rollback floor、WAL/Journal 的 ACK-gated replay、升级产物传输链
- 驱动 / System Extension / eBPF/LSM 等系统级集成与硬件根信任仍未进入当前仓库

### 5.3 设计妥协

设计上保留了终态目标，但实现层仍存在以下事实上的降级：

- 真实平台集成仍降为 in-memory provider 注入
- 传输链路虽然已正式接线，但 ACK 驱动的重放/续传语义仍未收口
- 升级传输链仍未进入主运行时，只完成了 proto 与最小测试服务
- 真实高危执行仍未进入跨平台系统级强制执行面

## 6. 收口计划

本次复核后的执行基线见：

- `docs/plan/2026-04-19-agent-round3-closure.md`

该计划将第三轮仓库内可闭合工作拆分为 `C05-C06` 两个工作包。当前 `C05` 已完成，`C06` 正在执行；待 `C06` 完成后，还需要重新复核 ACK/replay 与升级传输链是否需要继续拆包，直到仓库内可落地差距不再残留。

## 7. 剩余说明

仍然存在的并不只是排期风险，还包括明确的仓库边界：

- Windows 驱动签发与兼容性验证周期长
- macOS System Extension / Notarization / 用户授权流程复杂
- ML 模型质量依赖训练数据和 shadow/canary 闭环
- 容器与 Serverless 形态需要独立 QE 场景池
- TPM / Secure Enclave / OS keystore 的正式接入需要系统级依赖和更多工程面

因此，本轮计划以“仓库内真实可交付闭环”为 merge 条件，外部工程另行追踪。
