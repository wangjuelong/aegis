# Aegis Sensor 研发状态

## 状态定义

- `todo`：未开始
- `doing`：进行中
- `done`：已完成并提交代码、文档

## 工作包状态

| 工作包 | 名称 | 状态 | 备注 |
|--------|------|------|------|
| P00 | 详细计划与执行基线 | done | 已完成详细分解与执行状态文档 |
| P01 | Rust Workspace 与基础工程骨架 | done | 已建立 workspace、基础 crate、proto/schema 骨架，并通过 `cargo check --workspace` 与 `cargo test --workspace` |
| P02 | 统一配置模型与 Schema 版本框架 | done | 已建立 `AgentConfig`、`conf_version`、`agent.db` schema metadata、迁移执行器，并通过配置/迁移测试 |
| P03 | 统一事件模型与 Lineage 模型 | done | 已建立统一事件/遥测/故事线/富化/lineage checkpoint 模型，并通过模型层测试 |
| P04 | Core Orchestrator 与通道拓扑 | done | 已建立运行时通道、后台任务拓扑、shutdown 协调器，并通过运行时测试 |
| P05 | Ring Buffer / Spill / Dispatch 基础实现 | done | 已建立 4-lane 缓冲、Spill 存储、dispatch 转换与恢复测试 |
| P06 | ProcessTree / Hashing / AdaptiveWhitelist / Health | done | 已建立进程树、哈希缓存、自适应白名单与健康快照模块，并通过模块测试 |
| P07 | 平台 Trait 细化与 Mock Harness | done | 已建立平台描述、能力矩阵和可注入/可断言的 mock harness，并通过平台层测试 |
| P08 | Windows 平台采集基线 | done | 已建立 Windows provider 基线、能力矩阵、事件注入与平台测试 |
| P09 | Linux 平台采集基线 | done | 已建立 Linux provider 基线、4 级降级模型、容器感知事件注入与平台测试 |
| P10 | macOS 平台采集基线 | done | 已建立 macOS provider 基线、授权状态机、订阅集与平台测试 |
| P11 | IOC / Rule VM / Temporal | done | 已建立分层 IOC 索引、栈式 Rule VM、时间窗口缓冲与核心测试 |
| P12 | YARA / Script Decode / AMSI Interlock | done | 已建立 YARA 调度缓存、脚本解码流水线、AMSI 快速分流与测试 |
| P13 | ML / OOD / Behavioral Models | done | 已建立模型注册、特征抽取、OOD 评分与失败回退测试 |
| P14 | Correlation / Storyline / Threat Feedback | done | 已建立分片关联缓存、storyline 合并与 feedback 回灌测试 |
| P15 | 专项检测能力 | done | 已建立勒索、ASR、身份与诱捕检测引擎及统一 finding 输出 |
| P16 | Vuln Scan / Passive Discovery / AI Monitor | done | 已建立软件清单匹配、被动发现缓存与 AI 风险监控测试 |
| P17 | Response Executor / Quarantine / Kill | done | 已建立两阶段终止、文件隔离、审计落盘与 MockPlatform 测试 |
| P18 | Block Decision / Network Isolate / Firewall | done | 已建立 TTL 阻断映射、隔离策略与 break-glass 审计测试 |
| P19 | Registry / Filesystem Rollback / Forensics | done | 已建立回滚计划、文件恢复、证据链与取证归档测试 |
| P20 | Remote Shell / Session Lock / Approval Queue | done | 已建立审批队列、远程 shell 约束、playbook 与会话锁定审计模型 |
| P21 | Self-Protection / Keys / Crash Exploit Analysis | done | 已建立自保护状态机、密钥派生、证书生命周期 hook 与崩溃可利用性分析 |
| P22 | Comms / SignedCommand / ApprovalProof | done | 已建立传输消息模型、签名命令验签、scope 校验、重放账本与审批证明校验 |
| P23 | WAL / Forensic Journal / Emergency Audit Ring | done | 已建立 Telemetry WAL、Forensic Journal、Emergency Audit Ring 与 PARTIAL 完整性传播 |
| P24 | Upgrade / Migration / Canary Gate / Diagnose | done | 已建立升级计划、灰度门控、迁移协同与 `--diagnose` 诊断输出 |
| P25 | Container Host Agent / Sidecar Lite | doing | 当前进入容器宿主机观测与 sidecar lite 契约实现 |
| P26 | Runtime SDK / Cloud API Connector | todo | 依赖 P22 |
| P27 | QE / Pilot / Merge / Release | todo | 依赖 P00-P26 |
