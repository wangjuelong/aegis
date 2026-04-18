# Aegis Sensor 研发计划覆盖审计

> 审计对象：
> - `docs/技术方案/sensor-final技术解决方案.md`
> - `docs/architecture/aegis-sensor-architecture.md`
> - `docs/plan/aegis-sensor-rd-plan.md`

## 1. 审计结论

### 1.1 对“原生成计划”的结论

原生成计划总体方向正确，但**不完全满足**两份源文档，存在若干“弱覆盖”与“未显式交付”项，不能直接作为最终落地版发布。

### 1.2 对“落地版计划”的结论

`docs/plan/aegis-sensor-rd-plan.md` 已将上述缺口补齐。按当前审计结果：

- **功能缺失：无**
- **功能妥协：无**
- **设计妥协：无**

当前计划中的阶段化仅是研发排序，不构成能力删减或设计降级。

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

经本次补齐后，未发现计划中仍然缺失的源文档能力项。

### 5.2 功能妥协

未发现将正式能力降为“可选”“二期增强”“后续补齐”的条目。

### 5.3 设计妥协

未发现与源文档冲突的设计降级，尤其以下高风险设计均已保持原样：

- 内核态不承载策略逻辑
- 命令级签名与审批证明双重校验
- offline 自动/预审批/禁止三类动作语义
- WAL 分层与 Forensic Journal 不可淘汰语义
- management-only 隔离释放
- Linux 降级能力矩阵
- Sidecar / Runtime SDK / Cloud API Connector 作为正式交付项

## 6. 剩余说明

仍然存在的仅是执行风险，不是范围妥协：

- Windows 驱动签发与兼容性验证周期长
- macOS System Extension / Notarization / 用户授权流程复杂
- ML 模型质量依赖训练数据和 shadow/canary 闭环
- 容器与 Serverless 形态需要独立 QE 场景池

这些风险只影响排期，不影响本计划的功能与设计基线。
