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
| P05 | Ring Buffer / Spill / Dispatch 基础实现 | doing | 当前进入 4-lane 消费、Spill 存储与 dispatch 转换基础实现 |
| P06 | ProcessTree / Hashing / AdaptiveWhitelist / Health | todo | 依赖 P04-P05 |
| P07 | 平台 Trait 细化与 Mock Harness | todo | 依赖 P01 |
| P08 | Windows 平台采集基线 | todo | 依赖 P07 |
| P09 | Linux 平台采集基线 | todo | 依赖 P07 |
| P10 | macOS 平台采集基线 | todo | 依赖 P07 |
| P11 | IOC / Rule VM / Temporal | todo | 依赖 P03-P05 |
| P12 | YARA / Script Decode / AMSI Interlock | todo | 依赖 P11 |
| P13 | ML / OOD / Behavioral Models | todo | 依赖 P11 |
| P14 | Correlation / Storyline / Threat Feedback | todo | 依赖 P03/P11/P13 |
| P15 | 专项检测能力 | todo | 依赖 P11-P14 |
| P16 | Vuln Scan / Passive Discovery / AI Monitor | todo | 依赖 P03-P04 |
| P17 | Response Executor / Quarantine / Kill | todo | 依赖 P04/P07 |
| P18 | Block Decision / Network Isolate / Firewall | todo | 依赖 P17 |
| P19 | Registry / Filesystem Rollback / Forensics | todo | 依赖 P17 |
| P20 | Remote Shell / Session Lock / Approval Queue | todo | 依赖 P17-P19 |
| P21 | Self-Protection / Keys / Crash Exploit Analysis | todo | 依赖 P07/P17 |
| P22 | Comms / SignedCommand / ApprovalProof | todo | 依赖 P03-P04 |
| P23 | WAL / Forensic Journal / Emergency Audit Ring | todo | 依赖 P22 |
| P24 | Upgrade / Migration / Canary Gate / Diagnose | todo | 依赖 P02/P22/P23 |
| P25 | Container Host Agent / Sidecar Lite | todo | 依赖 P09/P16/P22 |
| P26 | Runtime SDK / Cloud API Connector | todo | 依赖 P22 |
| P27 | QE / Pilot / Merge / Release | todo | 依赖 P00-P26 |
