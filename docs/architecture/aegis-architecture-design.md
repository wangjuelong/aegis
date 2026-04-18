# Aegis EDR 平台 — 架构设计文档

> 版本：1.0  
> 日期：2026-04-09  
> 状态：草稿  
> 分类：内部 / 机密  
> 对标：CrowdStrike Falcon / Microsoft Defender for Endpoint / SentinelOne Singularity

---

## 目录

1. [架构概览与设计原则](#1-architecture-overview-and-design-principles)
2. [按平面划分的详细架构](#2-detailed-architecture-by-plane)
   - 2.1 终端平面（Agent）
   - 2.2 传输平面
   - 2.3 分析平面
   - 2.4 数据平面
   - 2.5 管理平面
3. [性能关键路径分析](#3-performance-critical-path-analysis)
4. [数据架构](#4-data-architecture)
5. [服务间通信架构](#5-inter-service-communication-architecture)
6. [韧性与容错设计](#6-resilience-and-fault-tolerance-design)
7. [安全架构](#7-security-architecture)
8. [部署与运维架构](#8-deployment-and-operations-architecture)
9. [架构决策记录](#9-architecture-decision-records)

---

<a id="1-architecture-overview-and-design-principles"></a>
## 1. 架构概览与设计原则

### 1.1 系统愿景

Aegis 是一套生产级 Endpoint Detection and Response（EDR）平台，旨在为 Windows、Linux 与 macOS 提供全面的终端安全能力。平台横跨五个架构平面，这五个平面协同提供实时行为检测、IOC 匹配、ML/AI 异常检测、威胁狩猎，以及自动化响应编排能力，并可扩展至 100 万终端、每日处理 500 亿事件的规模。

### 1.2 治理原则

| 原则 | 描述 | 落地约束 |
|-----------|-------------|-------------|
| 最小权限 | 内核驱动仅负责采集与投递；全部策略逻辑运行在用户态 | 代码评审 + 设计评审闸门 |
| 故障隔离 | Sensor、Detection、Response、Comms 运行在独立线程池/进程中；插件通过 WASM 沙箱隔离 | 进程模型 + watchdog |
| 零信任通信 | Agent 到云端全链路 mTLS；本地存储 AES-256-GCM；敏感内存 mlock+zeroize；密钥绑定 TPM/Secure Enclave | 证书生命周期自动化 |
| 热更新 | 规则、ML 模型、传感器插件、配置均可在不重启 Agent 的情况下热加载 | 带签名的原子替换与回滚 |
| 可观测性 | Agent 通过 heartbeat 暴露健康指标（CPU/内存/队列深度/丢弃事件）；全链路使用 event lineage_id 串联 | lineage 检查点计数器 |
| 跨平台一致性 | 用户态核心采用单一 Rust 代码库，通过条件编译 + 平台 Sensor Trait 抽象实现 | 平台 trait 接口 |
| 明确防护边界 | Agent 自保护覆盖 Ring 3 防御 + Ring 0 检测（不承诺 Ring 0 防御）并显式声明 | 文档 + 安全模型 |
| 自适应反馈 | 云端确认的误报会自动回填到本地白名单，降低后续检测开销 | 反馈闭环子系统 |
| 离线自治 | 与云端断连时仍具备完整的本地检测、缓存、响应与审计能力 | WAL + 本地规则/模型缓存 |
| 攻击面收缩 | Agent 不仅检测与响应，还通过 ASR、设备控制、防火墙策略主动缩减攻击面 | ASR 规则引擎 + 设备控制 |
| 不可变性 | 所有数据转换都生成新对象；不对共享状态做原地修改 | Rust 所有权模型 + 代码评审 |

### 1.3 质量属性与规模目标

| 类别 | 指标 | 目标 |
|----------|--------|--------|
| **规模** | 终端数量 | 1,000,000 |
| **规模** | 日事件量 | >= 50 billion |
| **规模** | 集群事件速率 | ~8.3M events/sec |
| **规模** | 日原始数据量（压缩前） | ~50 TB/day |
| **Agent 性能** | CPU（稳态 P95） | <= 2% |
| **Agent 性能** | CPU（全量 profile P95） | <= 3% |
| **Agent 性能** | CPU（峰值 P99） | <= 6% |
| **Agent 性能** | Memory RSS（基础） | <= 150 MB |
| **Agent 性能** | Memory RSS（全量 profile） | <= 220 MB |
| **Agent 性能** | 网络带宽（均值） | <= 50 KB/s |
| **Agent 性能** | 网络带宽（全量 profile 均值） | <= 60 KB/s |
| **Agent 性能** | 磁盘写入（均值） | <= 5 MB/s |
| **Agent 性能** | 安装包大小 | <= 75 MB |
| **检测时延** | 端到端（关键规则） | <= 1s |
| **检测时延** | 云端关联 | <= 5s |
| **检测时延** | Agent 本地 P50 | < 20 us |
| **检测时延** | Agent 本地 P99 | < 200 us |
| **检测有效性** | MITRE ATT&CK 覆盖率 | >= 85% |
| **检测有效性** | 已知恶意软件检出率 | >= 99.5% |
| **检测有效性** | 未知/0-day 检出率 | >= 70% |
| **检测有效性** | 高危误报率 | <= 1% |
| **响应速度** | MTTD | <= 60s |
| **响应速度** | MTTR（自动化） | <= 30 min |
| **平台稳定性** | Agent 崩溃率 | <= 0.01%/month |
| **平台稳定性** | 云端可用性 | >= 99.95% |
| **平台稳定性** | 数据接入可用性 | >= 99.99% |
| **运营** | 告警噪声比 | >= 50:1 (events:incidents) |
| **运营** | 自动化处置率 | >= 60% (high-confidence) |

### 1.4 五平面架构总览

```
+------------------------------------------------------------------------+
|                          Management Plane                                |
|  +------------+  +------------+  +-------------+  +----------------+   |
|  | Web Console|  | REST/GQL   |  | RBAC / SSO  |  | Tenant Mgmt    |   |
|  | (React+TS) |  | API Gateway|  | (OIDC/SAML) |  | (Multi-tenant) |   |
|  +-----+------+  +-----+------+  +------+------+  +-------+--------+   |
|        +----------------+---------------+-----------------+             |
+------------------------------------------------------------------------+
|                         Analytics Plane                                  |
|  +--------------+  +--------------+  +--------------+  +------------+  |
|  | Stream       |  | Correlation  |  | ML / AI      |  | Threat     |  |
|  | Processing   |  | Engine       |  | Engine       |  | Intel Svc  |  |
|  | (Flink)      |  | (CEP, Go)   |  | (Triton/GPU) |  | (STIX/TAXII|  |
|  +------+-------+  +------+-------+  +------+-------+  +-----+------+  |
|         +-----------------+------------------+----------------+         |
+------------------------------------------------------------------------+
|                          Data Plane                                      |
|  +--------------+  +--------------+  +--------------+  +------------+  |
|  | Event Bus    |  | Hot Store    |  | Warm Store   |  | Cold Store |  |
|  | (Kafka)      |  | (ClickHouse) |  | (Elastic)    |  | (S3/MinIO) |  |
|  +--------------+  +--------------+  +--------------+  +------------+  |
+------------------------------------------------------------------------+
|                         Transport Plane                                  |
|  +--------------------------------------------------------------+      |
|  |  Ingestion Gateway (gRPC + mTLS + LB, Go, Stateless, HPA)   |      |
|  |  +----------+ +----------+ +-----------+ +--------------+    |      |
|  |  | mTLS Auth| | LZ4      | | Protobuf  | | Enrichment + |    |      |
|  |  | +Tenant  | | Decompr. | | Validate  | | Kafka Route  |    |      |
|  |  +----------+ +----------+ +-----------+ +--------------+    |      |
|  +--------------------------------------------------------------+      |
+------------------------------------------------------------------------+
|                       Endpoint Plane (Agent)                             |
|  +---------------------------------------------------------------+     |
|  |  +----------+ +----------+ +----------+ +------------------+  |     |
|  |  | Sensor   | | Local    | | Response | | Comms Module     |  |     |
|  |  | Module   | | Detection| | Executor | | (gRPC+WAL+QoS)  |  |     |
|  |  | (Kernel+ | | Engine   | | (Suspend/| |                  |  |     |
|  |  |  User)   | | (6-stage)| |  Kill/   | |                  |  |     |
|  |  +----------+ +----------+ | Isolate) | +------------------+  |     |
|  |                            +----------+                       |     |
|  +---------------------------------------------------------------+     |
+------------------------------------------------------------------------+
```

### 1.5 横切关注点

| 关注点 | 方案 |
|---------|----------|
| 多租户 | Tenant ID 在每个事件、API 调用和存储分区中全程透传；各层逻辑隔离；高安全租户可启用物理隔离 |
| 可观测性 | Prometheus 指标 + Grafana 看板 + Jaeger 分布式追踪 + Loki 运维日志（区别于安全遥测） |
| 配置 | etcd/Consul 用于服务发现；Vault 用于密钥；策略分层（Global -> Group -> Endpoint） |
| CI/CD | GitLab CI / ArgoCD 持续交付；Agent 通过 canary/staged rollout 灰度发布，并带自动健康闸门 |
| 合规 | Reporting Service 内建 SOC2、ISO 27001、MLPS（等保）报表；审计日志永久保存且仅追加 |

---

<a id="2-detailed-architecture-by-plane"></a>
## 2. 按平面划分的详细架构

### 2.1 终端平面（Agent）

#### 2.1.1 进程模型

Agent 运行时由三个 OS 级进程组成：

1. **aegis-sensor**（主进程，Rust，PID 1001）：负责编排器事件循环、传感器分发、检测线程池、响应执行器、通信模块（高优先级 + 普通 + 批量）、配置监听、健康上报、lineage 跟踪、反馈闭环、storyline 引擎、快照管理、ASR 执行、设备控制、欺骗防御管理、漏洞扫描、网络发现、AI 监控、WASM 插件宿主。

2. **aegis-sensor-watchdog**（Rust，在 Windows 上受 PPL 保护，PID 1002）：监控主进程存活状态、校验二进制完整性、执行内核完整性监控（SSDT/IDT/callback table 哈希）、崩溃自动拉起 + core dump 上传。

3. **edr-updater**（Rust，按需启动 PID 1003）：负责增量包下载 + 签名校验（跨多版本时回退为全量包）、A/B 分区切换 + schema migration、回滚逻辑 + 金丝雀健康闸门。

**内核态**：aegis-sensor-kmod（内核驱动 / eBPF 程序）：负责事件采集 hook、MPSC Ring Buffer（零拷贝传递到用户态并保留优先级）、网络过滤（执行隔离）、ETW/BPF 完整性 watchdog、VSS/文件系统快照保护、设备过滤/存储访问控制。

#### 2.1.2 传感器子系统

八类传感器，按平台有不同实现：

| 传感器 | Windows | Linux | macOS | 采集粒度 |
|--------|---------|-------|-------|----------------------|
| 进程 | ETW + PsSetCreateProcessNotifyRoutineEx2 + ObRegisterCallbacks + Direct Syscall Detection | kprobe/tracepoint sched_process_exec/exit/fork + kprobe commit_creds + LSM bprm_check_security + mmap hooks | ESF AUTH_EXEC + NOTIFY_EXEC/FORK/EXIT | 进程树、命令行、环境变量、签名、PE/ELF 元数据、PPL 等级 |
| 文件 | Minifilter（IRP_MJ_CREATE/WRITE/SET_INFO/CLEANUP）+ Pre/Post callbacks | fentry vfs_write/rename/unlink + security_file_open（LSM）+ fanotify | ESF AUTH_OPEN/RENAME/UNLINK + NOTIFY_WRITE/CLOSE | 路径、SHA256、熵值、magic bytes、所属进程 |
| 网络 | WFP Callout（ALE_AUTH_CONNECT/RECV_ACCEPT/FLOW_ESTABLISHED + OUTBOUND_TRANSPORT）+ ETW DNS Client | kprobe tcp_connect/inet_csk_accept + tracepoint sock/inet_sock_set_state + TC/XDP + 内核 DNS 解析 | Network Extension + NEFilterDataProvider | 五元组、DNS query/response、SNI、JA3/JA3S |
| 注册表 | CmRegisterCallbackEx（RegNtPreSetValueKey 等）+ Registry Change Journal（SQLite，7d/100MB FIFO） | N/A | N/A | Key/Value 路径、操作类型、旧值/新值、PID |
| 认证 | Security Event Log（4624/4625/4672/4768） | PAM uprobe + audit + /var/log/auth.log | OpenDirectory + ESF NOTIFY_OPENSSH_LOGIN | 登录类型、源 IP、权限提升、Kerberos TGT/TGS |
| 脚本 | AMSI Provider + AMSI Bypass Detection（amsi.dll 完整性、CLR 篡改、卸载检测） | bash PROMPT_COMMAND + eBPF uretprobe | ESF | 完整脚本内容（解混淆后）、解释器 PID |
| 内存 | VirtualAlloc/NtMapViewOfSection Hook + YARA scan | process_vm_readv + YARA | mach_vm_read | 可疑内存区域转储、注入检测 |
| 容器 | N/A | eBPF + cgroup_id + namespace ID + CRI socket query | N/A | Pod/Container 元数据、逃逸检测 |

**附加监控能力：**
- Named Pipe / IPC 监控（Windows ETW + Minifilter on \Device\NamedPipe\; Linux AF_UNIX）
- DLL 加载深度监控（PsSetLoadImageNotifyRoutineEx，用于 sideloading / search order hijack / phantom DLL 检测）
- VSS / 文件系统快照保护（拦截快照删除，周期性每 4 小时创建一次快照，保留 3 份）
- 设备控制（USB/可移动介质/Bluetooth/Thunderbolt；策略支持 ALLOW/BLOCK/READ_ONLY/AUDIT/ALLOW_APPROVED）

#### 2.1.3 MPSC Ring Buffer 设计

64 MB 共享内存（mmap），划分为 4 条优先级通道：

| 通道 | 大小 | 内容 | 溢出策略 |
|------|------|---------|----------------|
| 0: CRITICAL | 8 MB | PROCESS_CREATE/EXIT, AUTH_*, AMSI_TAMPER, ETW_TAMPER, DIRECT_SYSCALL, NETWORK_CONNECT | 阻塞等待（有界自旋 100us），之后强制覆盖最老事件 + ERROR 计数 |
| 1: HIGH | 16 MB | FILE_WRITE（可执行文件）, REGISTRY_WRITE, SCRIPT_EXEC, DNS_QUERY, SUSPICIOUS_* | 丢弃当前事件 + increment drop_count |
| 2: NORMAL | 24 MB | FILE_WRITE（常规）, FILE_READ, NET_FLOW_STATS | 丢弃当前事件 + 启用采样模式（1/10） |
| 3: LOW | 16 MB | FILE_INFO（仅元数据）, HEARTBEAT_INTERNAL | 直接丢弃，仅累计 drop_count |

**MPSC 写入协议（内核态，任意线程/IRQL）：**
1. lane = priority_classify(event_type)
2. total = align8(32 + payload_len)
3. slot = atomic_fetch_add(&lane.write_offset, total)
4. If slot exceeds lane capacity: handle per overflow policy
5. memcpy(lane.data[slot % lane.capacity], event, total)
6. store_release(event.flags, COMMITTED)

**消费者（用户态，单线程）：**
采用带权轮询：Lane 0（4x）-> Lane 1（2x）-> Lane 2（1x）-> Lane 3（1x）-> cycle。  
背压信号：当 Lane 0 利用率 > 50% 时，通知检测引擎加速处理。

**性能目标：**
- 单事件投递时延：< 800ns
- 吞吐：> 3M events/sec（单核 consumer，4-lane polling）
- CRITICAL 事件丢失率：0（设计目标，正常负载下）
- 噪声攻击防御：攻击者高频制造 FILE 事件只会影响 Lane 2/3，不会影响 Lane 0 中的 Process/Auth 事件

#### 2.1.4 本地检测引擎（6 阶段流水线）

```
NormalizedEvent
     |
     v
+------------------------------------------------------------------+
| Stage 0: Fast Path Filter (< 100ns/event, 10M event/s)           |
| - Event type routing table                                        |
| - Global sampling rate control                                    |
| - Static whitelist match                                          |
| - Adaptive Whitelist check (feedback loop)                        |
|   -> Hit cloud-confirmed FP entry -> skip detection, mark BENIGN  |
+------------------------------------------------------------------+
     |
     v
+------------------------------------------------------------------+
| Stage 1: IOC Matching (< 500ns/event, 5M event/s)                |
| Tiered Bloom + Cuckoo Filter supporting 5M IOCs in ~10MB:        |
| - Tier 0: CRITICAL IOC Bloom (FPR 0.001%, ~50K entries, ~1MB)    |
| - Tier 1: HIGH IOC Bloom (FPR 0.01%, ~500K entries, ~5MB)        |
| - Tier 2: STANDARD IOC Cuckoo (FPR 0.01%, ~5M entries, ~4.5MB)   |
|   Cuckoo chosen for dynamic deletion (IOC aging)                 |
| Bloom/Cuckoo hit -> precise confirmation via HashMap             |
+------------------------------------------------------------------+
     |
     v
+------------------------------------------------------------------+
| Stage 2: Rule Engine - Sigma + Custom DSL + Temporal (< 15us)    |
| Rule VM instruction set:                                          |
| - Basic: LOAD_FIELD, CMP_EQ/NE/GT/LT/REGEX/CONTAINS, AND/OR/NOT   |
| - IOC: BLOOM_CHECK, CUCKOO_CHECK                                  |
| - Context: LOAD_PARENT, LOAD_ANCESTOR, LOAD_CHILDREN_COUNT        |
| - Temporal: TEMPORAL_WINDOW, TEMPORAL_SEQUENCE (ordered/unordered),|
|   TEMPORAL_COUNT, TEMPORAL_NEAR                                   |
| Each temporal rule: 128-event ring buffer, < 64KB memory, TTL     |
| Hot update: signed verification, atomic replace, failure rollback |
+------------------------------------------------------------------+
     |
     v
+------------------------------------------------------------------+
| Stage 2.5: AMSI Fast-Path Interlock (< 50us, 100K script/s)      |
| When event source is AMSI and Stage 2 judges MALICIOUS/CRITICAL:  |
| - Shared memory flag notifies kernel AMSI Provider                |
| - Provider returns AMSI_RESULT_DETECTED on next AmsiScanBuffer    |
| Linux equivalent: LSM bprm_check_security blocks before execve    |
| macOS equivalent: ESF AUTH_EXEC blocks before execution           |
+------------------------------------------------------------------+
     |
     v
+------------------------------------------------------------------+
| Stage 3: YARA Memory/File Scan (< 50ms/scan, 100 scan/s)         |
| Triggered on: new executable, Stage 2 deep scan request, RWX page,|
| .NET Assembly.Load(byte[]), LOLBin non-standard DLL, Office macro,|
| script payload post-decode                                        |
| Async task queue; same-object TTL dedup; large sample slicing     |
+------------------------------------------------------------------+
     |
     v
+------------------------------------------------------------------+
| Stage 4: Local ML Inference (< 8ms, 800 inference/s)             |
| Model A: Static PE/ELF Classifier                                 |
|   XGBoost + LightGBM + small MLP ensemble (majority vote)         |
|   OOD detection via Mahalanobis distance; adversarial training    |
|   200+ structural features (PE rich header hash, import anomaly)  |
| Model B: Behavioral Sequence Anomaly                              |
|   1D-CNN with cold-start profile (first 50 events use 2-layer CNN |
|   trained on malware initial behavior; 5 events sufficient)       |
|   Cold-start model ~1MB, standard model ~3MB                      |
| Model C: Script Risk Assessment                                   |
|   Distilled 4-layer Transformer (hidden_dim=128) from 7B LLM      |
|   ~8MB ONNX; handles Base64/XOR/concat; outputs risk_score+intents|
| Total model memory: <= 20MB. All via ONNX Runtime (CPU).         |
| Model release: shadow mode / A-B bucket / canary with auto-revert |
+------------------------------------------------------------------+
     |
     v
+------------------------------------------------------------------+
| Stage 5: Sharded Stateful Correlation (< 2us, 2M event/s total)  |
| State machines sharded by process_group_id (session leader PID)   |
| Same process tree -> same shard -> same detection-pool thread     |
| Cross-tree correlation (lateral movement): async cross-shard query|
| Per-shard throughput > 500K event/s; scales linearly with threads |
| Simple temporal rules: Stage 2 Temporal VM                        |
| Complex multi-stage attack chains: Stage 5 state machines         |
+------------------------------------------------------------------+
     |
     v
Decision Router:
  BENIGN    -> telemetry (comms-tx-normal only)
  SUSPICIOUS -> telemetry + low-priority alert (comms-tx-normal)
  MALICIOUS  -> telemetry + high-priority alert (comms-tx-high) + response
  CRITICAL   -> telemetry + alert (comms-tx-high) + immediate response
```

#### 2.1.5 Storyline 引擎

Storyline Engine 在 Agent 侧运行，用于从离散事件构建实时攻击上下文：

```
Storyline {
  id:               u64
  root_event:       EventRef
  events:           Vec<EventRef>
  processes:        HashSet<PID>
  tactics:          Vec<MitreTactic>
  techniques:       Vec<MitreTechnique>
  severity:         Severity
  kill_chain_phase: KillChainPhase
  auto_narrative:   String
}
```

合并规则：相同进程树共享 storyline_id；文件传递链（进程 A 写入，进程 B 执行同一文件）；网络传递链（相同 C2 IP/domain、相同下载源）；命中时序规则时可跨进程树合并 storyline。资源治理：最多保留 500 个活跃 storyline，采用 LRU 淘汰。最终可视化由云端完成；Agent 仅维护实时数据结构。

#### 2.1.6 响应执行器

Response Executor 实现多阶段响应架构：

**两阶段进程终止：**
- Phase 1：立即 Suspend（检测后 < 100ms） -- NtSuspendProcess（Win）/ SIGSTOP + freeze cgroup（Linux）/ task_suspend（macOS）。进程停止运行但保留其资源。
- Phase 2：评估并处置（挂起期间）：
  - 自动路径（confidence > 0.9）：检查是否存在 C2 连接、检查打开文件中是否存在加密行为、可选执行内存快照，然后递归终止该进程及全部子进程。
  - 手动路径（confidence 0.5-0.9）：挂起等待分析师确认（5min 超时），之后按策略自动 kill 或 release。
  - PPL 感知路径：通过 NtQueryInformationProcess 检测保护级别；普通进程 -> 标准 suspend+kill；PPL -> 内核驱动 ZwTerminateProcess 或 token demotion；PP（Protected Process）-> 不执行终止，产生 CRITICAL 告警 + 可选网络隔离。

**预先阻断架构：**
内核 pre-callback 检查 Block Decision Map（共享内存 bitmap）：
- Minifilter IRP_MJ_CREATE：若 (process_hash, action_type) 命中阻断列表，则阻断文件操作 -> STATUS_ACCESS_DENIED
- WFP ALE_AUTH_CONNECT：若 IP/port 命中阻断列表，则阻断网络连接 -> FWP_ACTION_BLOCK
- Linux LSM bprm_check_security：若 exe_hash 命中阻断列表，则阻止执行 -> -EPERM
- macOS ESF AUTH_EXEC/AUTH_OPEN：-> es_respond_auth_result(DENY)
- 用户态检测引擎写入 Block Decision Map；内核在 < 1us 内读取。
- 阻断项带 TTL（默认 300s）；上限 10,000 条；系统关键进程白名单不可被阻断。

**附加响应能力：**
- 文件隔离（Quarantine）：挂起访问中的进程 -> 收集元数据 -> LZ4+AES-256-GCM -> /quarantine/{sha256}.vault -> 安全删除原文件 -> 审计。容量 2GB，保留 30 天，可从云端恢复。
- 注册表回滚：基于 Registry Change Journal（SQLite）。支持按时间点、按进程、按 key、按 incident 回滚。回滚前自动备份。系统关键 key 需要审批。
- 文件系统回滚：基于 VSS/btrfs/LVM/APFS 快照。支持卷级、目录级、文件列表级或按进程作用域回滚。通过与快照的 hash 对比，仅恢复被修改/删除的对象。
- 网络隔离：预缓存 EDR 云端 IP 列表；防火墙规则使用 IP 白名单（不依赖 DNS）；DNS 仅允许访问硬编码的 EDR DNS 服务器；隔离跨重启持久；仅允许分析师释放、策略回滚或 TTL 到期解除隔离。
- 远程 Shell：双人审批；默认 30min / 最长 2h 且需重新批准；每终端最多 1 个并发 session；命令黑名单（format、dd、chmod 777、psexec）；可选白名单模式；资源限制（CPU 5%、Mem 256MB、Disk 100MB、无外网）；全量 asciicast 录制 + 单命令审计。
- 实时取证：易失性证据（进程列表/线程/modules、connections/routes/ARP/DNS cache、sessions/tokens/drivers、file handles、memory dump）+ 持久化证据（MFT、UsnJrnl、Prefetch、Event Logs、Registry Hives、Amcache、SRUM、browser history、LNK on Windows；auth.log、syslog、crontab、shell history on Linux；Unified Log、Launch Agents、FSEvents on macOS）。证据链：artifact_id + hash_chain + Agent signature + NTP 校验时间戳；云端独立复核。
- 终端防火墙控制：支持应用级规则、端口/协议规则、地理围栏、响应触发的临时规则。通过 WFP（Win）、nftables（Linux）、pf（macOS）实现。

**响应能力矩阵：**

| 动作 | 时延目标 | 审批要求 | 可回滚性 |
|--------|---------------|----------|----------|
| Process Suspend -> Kill | <= 3s | Auto/Manual | No |
| File Quarantine | <= 5s | Auto/Manual | Yes |
| Network Isolation | <= 3s | Approval Required | Yes |
| Registry Rollback | <= 5s | Manual | Yes |
| Filesystem Rollback | <= 60s | Approval Required | Partial |
| User Session Lock | <= 10s | Approval Required | Yes |
| Live Forensics | On-demand | Approval Required | N/A |
| Remote Shell | On-demand | Dual-Person Approval | N/A |
| Auto Playbook | <= 10s | Pre-approved | Partial |

#### 2.1.7 通信子系统

**三路 gRPC 通道 + 通信隐蔽性设计：**

| 通道 | 用途 | 行为 |
|--------|---------|----------|
| A: High-Priority | CRITICAL/HIGH 告警、响应结果、篡改检测 | 不批处理，立即发送，独立 gRPC stream + thread |
| B: Normal Telemetry | 常规遥测、低优先级告警 | 批量 100-500 事件，最长等待 1s，LZ4 压缩 |
| C: Bulk Upload | 取证包、内存 dump、大文件 | 分块上传、支持断点续传、带宽受限 |

**通信隐蔽与回退链：**
1. Primary：gRPC over TLS 1.3（标准）
2. Fallback 1：HTTPS WebSocket（当 HTTP/2 被 DPI 阻断时；Protobuf 封装在 WebSocket 帧中）
3. Fallback 2：HTTPS Long-Polling（最保守；额外增加 5-30s 延迟）
4. Fallback 3：Domain Fronting（可选；通过合法 CDN；TLS SNI = 合法域名，Host = EDR 域名）
- 自动切换：gRPC -> fail 3x -> WebSocket -> fail 3x -> Long-Polling -> fail -> Domain Fronting
- 恢复机制：后台每 5min 探测一次，尝试升级回更优信道
- TLS 指纹多样化：utls 模拟浏览器 ClientHello，随机化 JA3，ALPN h2/http1.1 随机

**WAL（Write-Ahead Log）：**
- 存储：/data/wal/segment-{N}.wal，16MB 分段，总计 500MB
- 格式：Segment Header + Record[]（record_len + type + crc32 + payload）
- 重连：按 sequence_id 顺序回放，服务端做幂等去重
- 加密：分层密钥保护 -- Tier 1：TPM/Secure Enclave 绑定（优先）；Tier 2：DPAPI（Win）/ LUKS（Linux）/ Keychain（macOS）并配增强 ACL
- 数据级加密：高敏字段（username、IP、credentials）使用 TPM 绑定密钥；常规字段（process name、file path）使用 OS keystore 密钥；元数据（sequence、timestamp）明文存储

**带宽自适应 QoS：**
网络分级：HIGH（>10Mbps）、MEDIUM（1-10Mbps）、LOW（<1Mbps）、SATELLITE（RTT>500ms）、METERED。各档位拥有不同的 batch interval、压缩、采样和上传策略。前后台感知：活跃用户会话期间降低 Agent 网络优先级；空闲时回放 WAL 并同步资产。

**gRPC 服务定义：**

Agent↔Gateway 的单一事实源是 `docs/architecture/aegis-transport-architecture.md §12.1.1-12.1.3`。上下行以 `UplinkMessage` / `DownlinkMessage` oneof 包络统一 wire format，支持批量 ACK、端到端流控与签名命令透传；禁止在分派文档中单独定义等价或简化的 RPC 契约。

```protobuf
service AgentService {
  // 上行封装 EventBatch / ClientAck / FlowControlHint
  // 下行封装 SignedServerCommand / BatchAck / FlowControlHint
  rpc EventStream(stream UplinkMessage) returns (stream DownlinkMessage);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
  rpc UploadArtifact(stream ArtifactChunk) returns (UploadResult);
  rpc PullUpdate(UpdateRequest) returns (stream UpdateChunk);
}
// 所有下行命令以 SignedServerCommand 承载于 DownlinkMessage.command；
// Agent 必须在本地完成签名验证 + target_scope 校验（见 transport §12.1.3）。
```

#### 2.1.8 自保护子系统

四层纵深防御：

**Layer 1：内核级保护**
- Windows：ObRegisterCallbacks（保护 Agent 进程句柄）、Minifilter（保护 Agent 文件/目录）、CmCallback（保护 Agent 注册表键）、PsSetCreateProcessNotifyRoutine（防止 Agent 进程被终止）、ELAM（最早期驱动加载）
- Linux：LSM hooks、fanotify、eBPF，保护关键进程与目录
- macOS：System Extension + Endpoint Security Framework
- 边界：可防御 Ring 3 攻击者；对 Ring 0 攻击者提供检测，不承诺防御

**Layer 2：完整性校验**
- 对 Agent 二进制、驱动、规则、模型、插件做统一签名校验
- 关键配置与热更新资产携带版本号和 checksum digest
- 校验失败 -> restricted mode + high-priority alert

**Layer 3：Watchdog**
- 主进程与 watchdog 双向 heartbeat
- Windows：watchdog 注册为 PPL-AntiMalware 进程
- Linux：通过 LSM/AppArmor/SELinux 限制对 watchdog 的 ptrace/kill
- macOS：System Extension 依赖系统原生保护机制
- Kernel Integrity Monitor 周期性运行于 watchdog：SSDT hash、IDT hash、kernel code segment integrity、callback table integrity、DKOM detection（多路径进程枚举）、PatchGuard status（Windows）；sys_call_table、kernel modules、kernel .text hash（Linux）；kext list、SIP status（macOS）
- 崩溃处理：自动拉起、保留 core dump、上传崩溃摘要

**Layer 4：反篡改技术**
- Anti-Debug：debugger attach 检测、时序异常检测、breakpoint 检测
- Hypervisor 检测：只告警不阻断
- Anti-Unload：拒绝未授权卸载请求，保护服务和驱动
- Secure Update：升级包签名、版本闸门、回滚保护

**Agent 密钥与身份管理：**
- 设备身份：agent_id + device certificate + 平台证明（TPM/Secure Enclave）
- 主密钥：优先绑定 TPM/Secure Enclave；回退至 OS credential store，并支持轮换
- 密钥派生：HKDF(master_key, "wal-encryption"), HKDF(master_key, "quarantine"), HKDF(master_key, "config"), HKDF(master_key, "reg-journal")
- 插件签名校验使用内置只读 trust root 公钥
- 使用方式：短时解封，使用后立即 zeroize；关键 buffer 使用 mlock
- 轮换：证书按策略轮换；设备被吊销时拒绝命令下发；本地缓存凭据受 TTL + signature 约束

#### 2.1.9 Agent 额外能力

**针对勒索软件的专用检测（4 层）：**
1. 在关键目录布置 canary files；任意修改/重命名/删除立即触发 CRITICAL + 立刻挂起进程
2. 文件加密行为：熵值激增（写后 >7.9，写前 <7.0）；大规模 read-encrypt-write；后缀重写；勒索信生成；与 VSS 快照保护/回滚联动
3. MBR/VBR/boot sector 保护：监控对 PhysicalDisk/raw block device 的直接写入；未授权写入立即阻断
4. 勒索行为状态机：file enumeration -> snapshot deletion attempt -> mass encryption -> ransom note drop

**攻击面收缩（ASR）规则：**
Office 宏防护（阻止子进程创建、可执行内容写入、进程注入）；脚本执行控制（阻止混淆脚本、download-and-execute 链、WMI 持久化）；凭据保护（阻止未授权访问 LSASS、凭据窃取型内存读取）；USB 执行控制；网络保护（阻断已知恶意 IOC 连接、低信誉域名）。策略模式：Block / Audit / Warn。

**身份威胁检测：**
Kerberoasting（RC4 etype 23 TGS-REQ、大量 TGS 请求）；Golden Ticket（异常 TGT 有效期、SID history 异常、绕过 KDC 的直接 TGT 使用）；DCSync（非 DC 发起 DrsGetNCChanges RPC）；Pass-the-Hash/Ticket；NTLM Relay；AS-REP Roasting。

**欺骗（Honeytokens）：**
Honey 凭据（伪造高价值凭据项，使用即告警）；honey 文件（伪造敏感文件名，读取即告警，修改则提升严重级别）；honey 共享（伪造 SMB share，用于探测网络枚举/横向移动）；honey DNS（伪造内部 DNS 条目，解析/访问即告警）。治理要求：诱饵内容全局唯一、定期轮换、对正常用户不可见。

**脚本多层解混淆流水线：**
Layer 1：编码解码（Base64、Hex、URL、Unicode）。Layer 2：字符串操作还原（concat、Replace、-join、环境变量替换）。Layer 3：执行层解包（Invoke-Expression 参数、ScriptBlock.Create、-EncodedCommand；最多 10 层递归）。Layer 4：通过 Stage 4 Model C 做语义分析。性能目标：普通场景 < 2ms，深度混淆 < 10ms。

**漏洞评估：**
软件清单（Windows：registry/MSI/AppX/Winget；Linux：dpkg/rpm/snap/flatpak；macOS：/Applications/Homebrew/pkgutil；每 6h 全量 + 实时增量）。CPE->CVE 映射（云端下发增量数据库，本地解析，结合 CVSS+EPSS+资产重要性排序）。配置审计（Windows 的 UAC、firewall、RDP、Credential Guard；Linux 的 SSH config、SUID/SGID；macOS 的 Gatekeeper、FDA；内建 CIS 子集检查）。

**被动网络发现：**
完全被动（无主动探测）。数据源：ARP/NDP cache、DHCP、mDNS/LLMNR/NetBIOS、本地连接表、eBPF 被动抓取。输出：IP/MAC/hostname、TCP 指纹 OS 猜测、观测到的服务端口、EDR Agent 安装状态、confidence score。云端聚合多终端结果，构建网络拓扑并标记未纳管设备。

**本地 AI 应用安全监控：**
AI 应用清单（发现已安装 AI 工具和本地推理框架，标记未批准的 shadow AI）。AI DLP（检测敏感数据复制/粘贴/拖拽进入 AI 会话；识别 credentials/PII/source code/key material；支持 BLOCK/WARN/AUDIT 策略）。模型完整性（监控 GGUF/ONNX/SafeTensors 文件是否被篡改/替换）。Prompt injection 关联（识别 AI 输出中的可执行指令片段，并与后续脚本执行行为关联）。

#### 2.1.10 插件隔离架构

通过 wasmtime 提供 WASM 沙箱。每个插件运行在独立内存空间中，并带 CPU 时间限制。Host Function ABI：emit_event、read_config（只读）、log、request_scan。崩溃处理：WASM trap 被捕获 -> 记录日志 -> 重启插件（主进程不受影响）；timeout >100ms/event -> 终止 + 记录降级日志；1 小时内崩溃 3 次 -> 自动禁用 + 上报。热修复：插件以独立 .wasm 文件分发，并进行 Ed25519 签名校验；插件版本独立于 Agent 版本。

#### 2.1.11 容器与云原生支持

**Mode A：Host Agent + eBPF（DaemonSet，最小权限）**
Capabilities：BPF、PERFMON、SYS_ADMIN、SYS_PTRACE、NET_ADMIN、SYS_RESOURCE（显式先 drop ALL）。readOnlyRootFilesystem: true。hostPID: true（需要全局进程视图）。SELinux/AppArmor：允许 bpf()、perf_event_open()、/sys/fs/bpf/ rw、/proc/*/ns/* 读取、CRI socket 只读；禁止写宿主文件系统（除 Agent 数据目录外）、加载内核模块、挂载文件系统。ATT&CK 覆盖：~85%。

**Mode B：Sidecar（Lite Profile）**
关闭：YARA、ML inference、file hash（委托给 host Agent）。启用：仅 process/network/file metadata。规则：容器专用约 200 条。资源：~30MB memory，<0.5% CPU。数据流：Sidecar -> unix socket -> host Agent -> Cloud。ATT&CK 覆盖：~60%。

**Mode C：Serverless / Managed Runtime**
Option 1：Runtime Library Instrumentation（为 Python/Node.js/Java/Go/.NET 提供 EDR SDK 作为 Lambda Layer）。Option 2：Cloud API log integration（CloudTrail/CloudWatch/Azure Monitor，分钟级时延）。Option 3：WASM-based Runtime Security Agent。ATT&CK 覆盖：30%/15%/varies。

**容器专用检测：**
Container escape（可疑 mount/namespace switch、hostPath 滥用、访问宿主 /proc,/sys,/var/run）。权限异常（privileged containers、危险 capabilities、ServiceAccount token 挂载）。运行时篡改（镜像层之外的二进制、entrypoint 变更、side-loaded executables）。横向移动（容器间扫描、对 kube-apiserver/etcd/metadata service 的探测、凭据复用）。编排层关联：将 Pod/Namespace/Node/OwnerReference 归因接入宿主进程树与云端资产图谱。

#### 2.1.12 升级与部署

**A/B 分区升级 + Schema Migration：**
SQLite agent.db 版本管理采用内嵌迁移脚本（v15_to_v16.sql 等）。升级前备份。兼容矩阵：min_schema_version/max_schema_version。配置迁移通过 transformer（旧格式 -> 新格式）完成。自动发布闸门健康指标：crash_rate（<0.1%）、cpu_p95（<3%）、memory_p95（<220MB）、event_drop_rate（<0.01%）、detection_rate（不低于基线的 90%）、heartbeat_loss_rate（<0.5%）。任一闸门失败 -> 自动暂停 + 可选自动回滚。Canary 流程：1%（50 Agents，2h）-> 5%（4h）-> 25%（12h）-> 50%（24h）-> 100%。多版本路径：相邻版本（bsdiff 增量 ~5-15MB）、跨 1-3 个版本（delta chain）、超过 3 个版本（full package ~75MB）。

**安装：**
Windows：MSI（主进程、驱动、watchdog、updater；校验证书链、驱动签名、ELAM）。Linux：DEB/RPM（systemd service、eBPF assets；校验 kernel features、BTF/CO-RE compatibility）。macOS：pkg（System Extension + Network Extension；引导用户授权）。通用要求：安装前检查（磁盘、权限、OS 版本、冲突软件）；安装后执行最小化 self-test + 创建 rollback point；在首次成功 heartbeat 之前不启用高风险自动响应。

---

### 2.2 传输平面

#### 2.2.1 Ingestion Gateway 架构

```
                    Agent Connections (~1M)
                          |
               +----------v----------+
               |  L4 Load Balancer   |  <- Envoy / HAProxy (TCP/gRPC-aware)
               |  (TLS termination   |     Session affinity optional
               |   optional)         |
               +----------+----------+
                          |
            +-------------v-------------+
            |    Ingestion Gateway      |
            |  (Stateless, Go, HPA)     |  70-90 pods（按 1M 连接 + 1-AZ 容错余量基线）
            |  连接数为主 HPA 触发       |  详见 aegis-transport-architecture.md §7
            |                           |
            | 1. mTLS verify + Tenant ID|
            | 2. LZ4 decompress         |
            | 3. Protobuf schema validate|
            | 4. Event normalization +   |
            |    enrichment (GeoIP,      |
            |    Asset Tag)              |
            | 5. Route by Tenant +       |
            |    EventType to Kafka      |
            |    partition               |
            +-------------+-------------+
                          |
                 +--------v--------+
                 |  Kafka Cluster  |
                 |  (Event Bus)    |
                 +-----------------+
```

**入口接口契约：**
- 协议：gRPC over TLS 1.3 with mTLS
- 认证：客户端证书 CN 包含 agent_id；证书通过查表映射到 tenant_id
- 负载：Protobuf EventBatch（LZ4 压缩）
- 限速：按 Agent（可配置，默认 1000 events/s），按租户（聚合）

**出站到 Kafka 的接口契约：**
- 序列化：Protobuf（富化后的事件）
- 分区策略：按 topic 独立策略（见下）
- 压缩：Kafka producer 侧使用 LZ4

**Gateway 内部富化流水线：**
1. 对网络事件执行 GeoIP lookup（MaxMind DB，内存驻留）
2. 附加资产标签（来自 Redis cache：agent_id -> asset_group, criticality, tags）
3. 注入租户元数据
4. 基于事件类型的启发式规则预打 MITRE ATT&CK TTP 标签（仅初步，后续由分析平面修正）
5. 透传 lineage_id（checkpoint 7: gateway_received）

#### 2.2.2 Kafka Topic 设计

> **规范性文档**：详见 `docs/architecture/aegis-transport-architecture.md` 第 4.4 节；本节仅保留概要。

| Topic | 分区策略 | 保留期 | 用途 |
|-------|-------------------|-----------|---------|
| `raw-events.{tenant}` | Agent ID hash | 72h | 原始遥测数据接入入口 |
| `enriched-events` | Event Type | 72h | 供流式处理消费的富化事件 |
| `detections` | Severity | 30d | 已确认检测告警 |
| `commands.unicast` | Agent ID | 24h | agent-scoped 下行命令，Gateway 经 Connection Registry 投递至 owner pod（取代旧 `responses` topic） |
| `commands.broadcast` | Round-robin | 24h | tenant/global-scoped 下行命令（POLICY_UPDATE/RULE_UPDATE/IOC_UPDATE/CONFIG_CHANGE）（取代旧 `threat-intel-updates` 与策略推送合流） |
| `commands.pending` | Agent ID | 7d（compact+delete）| 未投递命令补投；与 Consumer 位点提交同属一个 Kafka 事务 |
| `commands.dead-letter` | Agent ID | 30d | TTL 过期或多次失败的命令归档，审计 + 告警 |
| `audit-log` | Tenant ID | 365d | 操作审计轨迹 |

**Kafka 集群规模（100 万终端）：**
- 15+ brokers，分布于 3 AZ（每 AZ 5 台）
- 写入吞吐：~10 GB/s
- 副本数：3（跨 AZ）
- 每个 topic 的分区数：64-256（按 topic 调优）
- 保留策略：如上表所示

---

### 2.3 分析平面

#### 2.3.1 服务拆分

```
Analytics Plane
|-- Stream Processing Service (Java/Flink, 10+ TaskManagers)
|   |-- Real-time Rule Matching (Sigma/YARA streaming)
|   |-- Behavioral Sequencing (time-window behavioral sequences)
|   |-- Statistical Anomaly (baseline deviation: login freq, network flow)
|   +-- TTP Chain Correlation (MITRE ATT&CK tactical chain correlation)
|
|-- ML/AI Inference Service (Python, Triton/TorchServe, 4+ GPU nodes)
|   |-- Static File Analysis (Transformer 12-layer; PE/ELF/Mach-O)
|   |-- Behavioral Classifier (Bi-LSTM + Attention; process behavior sequences)
|   |-- Script Analyzer (Fine-tuned 7B LLM; PowerShell/Bash semantics)
|   |-- Anomaly Detection (Isolation Forest + Autoencoder; statistical features)
|   +-- Alert Triage / Scoring (XGBoost; auto-prioritize P1-P4)
|
|-- Correlation Engine (Go, 5+ instances)
|   |-- Kill Chain Tracker (cross-endpoint attack chain reconstruction)
|   |-- Lateral Movement Detector (lateral movement graph analysis)
|   |-- Campaign Clustering (same-origin attack activity clustering)
|   +-- Alert Deduplication (alert dedup and merge)
|
|-- Threat Intelligence Service (Go, 3+ instances)
|   |-- Feed Aggregator (STIX/TAXII + commercial + open-source feeds)
|   |-- IOC Manager (IOC lifecycle: add/age/retire)
|   |-- IOC Distribution (compile to Bloom Filter -> push to Agents)
|   +-- TTP Knowledge Graph (ATT&CK technique/tactic graph)
|
+-- Threat Hunting Service (Python+Go, 3+ instances)
    |-- Query Engine (SQL-like query syntax over tiered storage)
    |-- Notebook Interface (Jupyter-style interactive hunting)
    |-- Hypothesis Library (pre-built hunting hypothesis templates)
    +-- IOC Sweeper (full-endpoint historical retrospective scan)
```

#### 2.3.2 检测引擎分层模型

```
Layer 5: Campaign Intelligence
  |  Cross-organization APT activity correlation, MITRE ATT&CK Group mapping
  v
Layer 4: Kill Chain Correlation
  |  Cross-endpoint, cross-time-window attack chain reconstruction
  |  Reconnaissance -> Initial Access -> Execution -> Persistence -> ...
  v
Layer 3: Behavioral Analytics (ML/AI)
  |  Behavioral sequence modeling, anomaly scoring, adversarial robustness
  v
Layer 2: Rule-based Detection
  |  Sigma rules, YARA rules, custom DSL rules
  |  Known TTP coverage, precise IOC matching
  v
Layer 1: Telemetry Collection & Enrichment
     Raw event collection -> normalization -> GeoIP/Asset/User enrichment
```

#### 2.3.3 ML 模型架构

| 模型 | 架构 | 输入 | 输出 | 部署位置 | 硬件 |
|-------|-------------|-------|--------|------------|----------|
| 静态文件分类器 | Transformer（12-layer） | PE/ELF 结构特征 + 字节序列 | 恶意概率 + 家族分类 | 云端 | GPU |
| 行为序列模型 | Bi-LSTM + Attention | 进程行为序列（时序事件） | 攻击 TTP 概率向量 | 云端 | GPU |
| 脚本分析器 | Fine-tuned LLM（7B） | PowerShell/Bash 脚本文本 | 恶意意图分数 + 解释 | 云端 | GPU |
| 异常检测器 | Isolation Forest + Autoencoder | 统计特征向量（登录/网络/文件） | 异常分数 | 云端 | CPU |
| 告警分诊模型 | XGBoost | 告警特征 + 上下文 + 历史 | 优先级分数（P1-P4） | 云端 | CPU |
| 轻量终端模型 | XGBoost + LightGBM + MLP ensemble | 文件静态特征（200+ 维） | 恶意/正常二分类 | Agent 本地 | CPU（ONNX） |

#### 2.3.4 MITRE ATT&CK 覆盖目标

| Tactic | 覆盖目标 | 关键技术 |
|--------|----------------|----------------|
| Initial Access | >= 85% | T1566, T1190 |
| Execution | >= 95% | T1059, T1204 |
| Persistence | >= 90% | T1547, T1053 |
| Privilege Escalation | >= 85% | T1068, T1548 |
| Defense Evasion | >= 80% | T1055, T1027 |
| Credential Access | >= 90% | T1003, T1558 |
| Discovery | >= 75% | T1087, T1082 |
| Lateral Movement | >= 90% | T1021, T1550 |
| Collection | >= 80% | T1005 |
| Command & Control | >= 85% | T1071, T1573 |
| Exfiltration | >= 80% | T1048 |
| Impact | >= 85% | T1486 |

#### 2.3.5 Flink 流处理细节

**作业拓扑：**
1. Kafka Source（enriched-events）-> 按 agent_id 做 Keyed
2. Sigma Rule Matcher：预编译 Sigma 规则在事件流上执行；命中时写入 detections topic
3. Behavioral Sequencer：基于 (agent_id, process_group_id) 分组的 session windows（5min tumbling / 30min sliding）；检测有序与无序攻击序列
4. Statistical Anomaly Detector：按实体（user、host、network segment）在滑动窗口（1h、24h）内构建基线；Z-score 偏离触发告警
5. TTP Chain Correlator：CEP 模式匹配多步 MITRE ATT&CK 链；输出 kill chain correlation 事件
6. Sinks：detections topic、enriched-events topic（附加更新后的注释）、ML inference request topic

**Flink 集群规模：**
- 10+ TaskManagers（跨 AZ）
- 各 operator 的并行度分别调优（source: 64，rule matcher: 128，anomaly: 32）
- Checkpointing：30s 间隔，RocksDB state backend，增量 checkpoint 到 S3
- 通过 Kafka transaction coordination 实现 exactly-once semantics

#### 2.3.6 关联引擎细节

使用 Go 实现，核心为内存图数据结构：

- **Kill Chain Tracker**：维护按终端划分的 MITRE ATT&CK tactic 进展状态机。通过共享 IOC/identity pivot 点做跨终端关联。时间窗口：72h rolling。
- **Lateral Movement Detector**：构建认证图（source_host -> target_host 边，按 credential type、time、success/failure 加权）。利用社区发现算法识别异常穿透路径。
- **Campaign Clustering**：依据共享 IOC、TTP、时间模式与目标画像对告警聚类。基于从检测元数据提取的 feature vectors 使用 DBSCAN 聚类。
- **Alert Deduplication**：在可配置时间窗口内合并共享 (rule_id, agent_id, process_hash) 的告警。去重状态存储于 Redis，并带 TTL。

---

### 2.4 数据平面

#### 2.4.1 三层存储架构

```
+-----------------------------------------------+
|              Query Routing Layer                |
|   (Unified SQL interface, auto-routes to       |
|    appropriate storage tier based on time       |
|    range and query characteristics)             |
+------+----------------+----------------+-------+
       v                v                v
+--------------+ +--------------+ +--------------+
|  Hot Store   | | Warm Store   | | Cold Store   |
| ClickHouse   | | Elasticsearch| | S3 / MinIO   |
|              | |              | | + Parquet    |
| Last 7 days  | | 7-90 days    | | 90d - 3 years|
| Columnar     | | Full-text    | | Ultra-low    |
| compression  | | index        | | cost         |
| Sub-second   | | Fuzzy search | | Presto/Trino |
| aggregation  | | Structured   | | on-demand    |
| ~2TB/day     | | queries      | | query        |
| ingest       | |              | |              |
+--------------+ +--------------+ +--------------+
```

#### 2.4.2 存储引擎细节

**ClickHouse（Hot，7 天）：**
- 6+ 节点（每节点 64C/256G/NVMe）
- ReplicatedMergeTree 引擎，3 shards x 2 replicas
- 分区：按天（toYYYYMMDD(timestamp)）
- 排序键：`(tenant_id, event_type, timestamp)`
- Codec：热点列使用 LZ4，冷列使用 ZSTD
- 为常见聚合模式建立物化视图（如每 Agent 事件量、每类型每小时事件量）
- TTL：7 天自动删除

**Elasticsearch（Warm，7-90 天）：**
- 9+ data nodes（32C/128G/SSD）+ 3 master nodes（跨 AZ）
- 索引模式：`aegis-events-{tenant}-{YYYY.MM.dd}`
- ILM：hot（SSD，7d）-> warm（SSD，83d）-> delete
- Mapping：兼容 ECS 的字段映射；可搜索字符串同时保留 keyword + text 双字段
- 分片：每天每索引 1 primary + 1 replica，50GB 自动 rollover
- 搜索：对 cmdline、script content、file paths 支持全文检索；对所有 typed fields 支持结构化查询

**S3/MinIO + Parquet（Cold，90d-3y）：**
- 3+ MinIO 节点（或 AWS S3）
- 格式：Apache Parquet + Snappy 压缩
- 分区：`s3://aegis-cold/{tenant_id}/event_type={type}/year={YYYY}/month={MM}/day={dd}/`
- Schema：与统一事件模型一致，列类型针对 Parquet 优化
- 查询：Presto/Trino 联邦查询，支持 predicate pushdown
- 生命周期：通过夜间批作业从 ES warm tier 自动迁移；按保留策略自动删除

#### 2.4.3 数据保留策略

| 数据类型 | Hot | Warm | Cold | 总保留期 |
|-----------|-----|------|------|----------------|
| 原始遥测 | 7d | 83d | 275d | 1 year |
| 检测告警 | 30d | 335d | 2y | 3 years |
| 取证快照 | 30d | -- | 3y | 3 years |
| 审计日志 | 90d | 275d | Permanent | Permanent |
| 威胁情报 | 当前版本 | -- | 历史版本 | Permanent |

---

### 2.5 管理平面

#### 2.5.1 服务拆分

```
Management Plane
|-- API Gateway Service (Kong/Envoy, 3+ instances)
|   |-- REST API (OpenAPI 3.0)
|   |-- GraphQL API (complex relational queries)
|   |-- Rate Limiting + Throttling
|   +-- API Versioning (v1/v2)
|
|-- Auth & Identity Service (Go, Kratos/Hydra, 3+ instances)
|   |-- OIDC / SAML 2.0 SSO
|   |-- RBAC: Super Admin / Tenant Admin / Analyst / Viewer / API-Only
|   |   +-- Fine-grained: by endpoint group, by operation type
|   |-- MFA (TOTP / WebAuthn / FIDO2)
|   +-- API Key Management
|
|-- Asset Management Service (Go, 3+ instances)
|   |-- Agent Lifecycle (Install->Configure->Monitor->Upgrade->Decommission)
|   |-- Agent Health Dashboard
|   |-- Software Inventory
|   |-- Vulnerability Context (CVE integration)
|   +-- Asset Grouping / Tagging
|
|-- Policy Engine Service (Go, 3+ instances)
|   |-- Detection Policy (rule set assignment)
|   |-- Response Policy (auto-response strategy)
|   |-- Collection Policy (collection scope/granularity)
|   |-- Exclusion Policy (whitelist/exclusion rules)
|   +-- Policy Inheritance (Global -> Group -> Endpoint)
|
|-- Incident Management Service (Go, 3+ instances)
|   |-- Incident Lifecycle (New->Triaged->Investigating->Resolved->Closed)
|   |-- Alert-to-Incident Aggregation
|   |-- Investigation Timeline
|   |-- Evidence Attachment
|   +-- SLA Tracking (MTTD / MTTR)
|
|-- Response Orchestration Service (Go + Temporal, 3+ instances)
|   |-- Playbook Engine (YAML DSL, visual orchestration)
|   |-- Response Actions (kill, quarantine, isolate, rollback, remote shell, forensics)
|   |-- Approval Workflow (high-risk operations require approval)
|   +-- Third-party Integration (SIEM / SOAR / Ticketing)
|
|-- Reporting Service (Python, 2+ instances)
|   |-- Executive Dashboard
|   |-- Compliance Reports (SOC2/ISO27001/MLPS)
|   |-- Detection Efficacy Reports
|   |-- Agent Coverage Reports
|   +-- Scheduled Report Generation (PDF/CSV)
|
|-- Notification Service (Go, 3+ instances)
|   |-- Email / SMS / Webhook
|   |-- Slack / Teams / DingTalk / Feishu
|   |-- Syslog (SIEM integration)
|   +-- PagerDuty / OpsGenie
|
+-- Web Console (React + TypeScript, CDN-deployed)
```

#### 2.5.2 SOAR-Lite Playbook 引擎

Playbook Engine 使用 Temporal 作为持久化工作流执行引擎，定义方式为 YAML DSL：

```yaml
name: ransomware-auto-response
trigger:
  detection_rule: "ransomware-*"
  min_severity: HIGH
  min_confidence: 0.85

stages:
  - name: immediate-containment
    parallel: true
    actions:
      - type: kill_process
        target: "{{ detection.process.pid }}"
      - type: network_isolate
        target: "{{ detection.agent_id }}"
        allow: ["edr-c2-channel"]
      - type: file_quarantine
        target: "{{ detection.file.path }}"

  - name: scope-assessment
    actions:
      - type: ioc_sweep
        iocs:
          - "{{ detection.file.hash }}"
          - "{{ detection.network.dst_ip }}"
        scope: "all-endpoints"
        timeframe: "72h"

  - name: notification
    actions:
      - type: create_incident
        severity: CRITICAL
        assign_to: "soc-tier2"
      - type: notify
        channels: ["slack:#soc-critical", "pagerduty:oncall"]

  - name: forensic-collection
    requires_approval: true
    approvers: ["soc-lead", "ir-manager"]
    actions:
      - type: memory_dump
        target: "{{ detection.agent_id }}"
      - type: collect_artifacts
        artifacts: ["$MFT", "prefetch", "event_logs", "registry_hives"]
```

---

<a id="3-performance-critical-path-analysis"></a>
## 3. 性能关键路径分析

### 3.1 Agent 事件流水线（Zero-Copy Ring Buffer -> Detection -> Upload）

```
Latency Budget Breakdown (Agent-side, per event):

Kernel hook execution:              ~200ns
Ring Buffer write (MPSC atomic):    ~800ns
   -- zero-copy mmap boundary --
Ring Buffer read (user-space):      ~200ns
Event decode + normalize:           ~500ns
Process Tree context fill:          ~300ns
Adaptive Whitelist check:           ~100ns
                                    --------
Subtotal (to detection entry):      ~2.1us

Stage 0: Fast Path Filter:          < 100ns
Stage 1: IOC Tiered Bloom/Cuckoo:   < 500ns
Stage 2: Rule VM + Temporal:        < 15us    (amortized; most rules < 1us)
Stage 5: Sharded Correlation:       < 2us
                                    --------
Detection subtotal (typical):       ~18us (P50), ~150us (P99)

Decision Router:                    ~100ns
Comms channel enqueue:              ~200ns
                                    --------
Agent-side total (kernel to queue): ~20us (P50), ~200us (P99)

Comms batching + LZ4 + gRPC:       ~1s (batch window for normal telemetry)
                                    0ms (high-priority: immediate send)
```

**关键优化点：**
- 使用 kernel 与 user-space 之间的 zero-copy mmap，消除数据复制
- 带优先级通道的 MPSC ring buffer，确保 CRITICAL 事件不被饿死
- 无锁设计：通过 atomic_fetch_add 分配 slot，无 mutex 争用
- 基于 per-shard detection-pool thread 消除跨线程同步
- Bloom/Cuckoo filter 的 O(1) IOC lookup 避免大规模 hash table 开销
- ONNX Runtime + 预热模型避免模型加载时延

### 3.2 接入热路径（Gateway -> Kafka -> Flink -> ClickHouse）

```
Latency Budget Breakdown (Cloud-side, per event batch):

Agent gRPC send:                    ~5ms (network RTT)
Gateway mTLS verify:                ~0.5ms (session reuse)
LZ4 decompress:                     ~0.2ms (per batch of 100-500 events)
Protobuf validation:                ~0.1ms
Enrichment (GeoIP + Asset tag):     ~0.3ms
Kafka produce (acks=all, ISR sync): ~4-5ms   (min.insync.replicas=2；不再使用 acks=1)
                                    --------
Gateway subtotal:                   ~10ms (per batch, 含网络 RTT)

Kafka -> Flink source:              ~10ms (consumer poll interval)
Flink rule matching:                ~5ms (per event, includes CEP window)
Flink -> Kafka sink (detections):   ~2ms
Flink -> ClickHouse sink (batch):   ~100ms (micro-batch every 100ms)
                                    --------
Stream processing subtotal:         ~120ms

Total ingestion-to-queryable:       ~130ms (from gateway receive to ClickHouse)
Total end-to-end (critical rule):   < 1s (Agent detection + gateway + Flink)
Total cloud correlation:            < 5s (includes Correlation Engine graph analysis)
```

**吞吐计算（100 万终端）：**
- 单终端事件速率：~500 events/min = ~8.3 events/sec
- 集群总量：8.3M events/sec
- 平均事件大小（压缩后）：~200 bytes
- Kafka 写吞吐：8.3M * 200B = ~1.66 GB/s（原始）* 3 replicas = ~5 GB/s
- ClickHouse 插入速率：8.3M events/sec / 6 shards = 每 shard ~1.4M inserts/sec
- 日数据量：8.3M * 86400 * 600B（未压缩）= ~430 TB -> 压缩后约 ~50 TB/day（~10:1）

### 3.3 检测端到端时延预算

```
+---------------------+----------+-------------------------+
| Phase               | Budget   | Notes                   |
+---------------------+----------+-------------------------+
| Kernel collection   | 1us      | Hook + ring buffer write|
| Agent detection     | 20us P50 | 6-stage pipeline        |
|                     | 200us P99| Including ML + temporal |
| Agent -> Gateway    | 0ms-1s   | Immediate for CRITICAL  |
|                     |          | 1s batch for normal     |
| Gateway processing  | 10ms     | Per batch（acks=all）   |
| Kafka transit       | 10ms     | Consumer poll interval  |
| Flink processing    | 5ms      | Rule + CEP              |
| Correlation Engine  | 50ms     | Kill chain + dedup      |
| ML Inference (cloud)| 200ms    | GPU inference           |
+---------------------+----------+-------------------------+
| CRITICAL path total | < 300ms  | Agent immediate + cloud |
| Normal path total   | < 1.3s   | With batch window       |
| Full correlation    | < 5s     | Graph analysis + ML     |
+---------------------+----------+-------------------------+
```

### 3.4 查询热路径（Unified SQL -> Tiered Storage）

```
User query (SQL-like)
     |
     v
Query Router (parses time range + query characteristics)
     |
     +--- time <= 7d ----> ClickHouse (sub-second aggregation)
     |                     Direct SQL, columnar scan, materialized views
     |
     +--- 7d < time <= 90d -> Elasticsearch
     |                     Translate SQL to ES DSL
     |                     Full-text: use text fields
     |                     Structured: use keyword fields
     |
     +--- time > 90d ----> Presto/Trino -> S3 Parquet
     |                     Predicate pushdown to Parquet
     |                     Partition pruning on tenant/type/date
     |
     +--- spans tiers ---> Fan-out to multiple tiers
                           Merge results in query layer
                           Consistent field mapping (ECS/OCSF)

Typical query latencies:
  Hot (ClickHouse, last 7d):      < 1s for aggregations, < 3s for raw scans
  Warm (ES, 7-90d):               < 5s for structured, < 10s for full-text
  Cold (Presto+Parquet, 90d-3y):  30s-5min depending on scan volume
  Cross-tier:                     Max of individual tier latencies + merge overhead
```

---

<a id="4-data-architecture"></a>
## 4. 数据架构

### 4.1 统一事件模型（兼容 ECS/OCSF）

```
TelemetryEvent {
  // Core fields (all events)
  event_id:        UUID              // Globally unique
  lineage_id:      u128              // End-to-end tracing (agent_id[64] | ts_ns[48] | seq[16])
  timestamp:       int64             // Nanosecond-precision Unix timestamp
  tenant_id:       string            // Tenant identifier
  agent_id:        string            // Agent unique identifier

  host: {
    hostname:      string
    os:            string            // "windows-11-22H2", "ubuntu-22.04"
    ip:            string[]
    mac:           string[]
    asset_tags:    string[]          // CMDB asset tags
  }

  event_type:      enum              // PROCESS_CREATE | FILE_WRITE | NET_CONNECT | ...
  severity:        enum              // INFO | LOW | MEDIUM | HIGH | CRITICAL
  priority:        enum              // CRITICAL | HIGH | NORMAL | LOW

  // Polymorphic payload (determined by event_type)
  process?: {
    pid:           int32
    ppid:          int32
    name:          string
    cmdline:       string
    exe_path:      string
    exe_hash:      string            // SHA256
    user:          string
    integrity:     string            // System/High/Medium/Low
    signature:     SignatureInfo
    tree:          ProcessNode[]     // Complete process tree (parent -> grandparent)
    cwd:           string
    env_vars:      Map<string,string>
    creation_flags: int32
    token_elevation: bool
    container_id:  string?
    namespace_ids: NamespaceIDs?
    protection_level: string?        // PPL level
  }

  file?: {
    path:          string
    hash:          string            // SHA256
    size:          int64
    entropy:       float
    magic:         string
    action:        enum              // CREATE | MODIFY | DELETE | RENAME
  }

  network?: {
    src_ip:        string
    src_port:      int32
    dst_ip:        string
    dst_port:      int32
    protocol:      string
    dns_query:     string
    dns_response:  string[]
    sni:           string
    ja3:           string
    ja3s:          string
    bytes_sent:    int64
    bytes_recv:    int64
  }

  registry?: {
    key_path:      string
    value_name:    string
    old_value:     bytes
    new_value:     bytes
    operation:     enum              // CREATE_KEY | SET_VALUE | DELETE_KEY | DELETE_VALUE
  }

  auth?: {
    logon_type:    int32
    source_ip:     string
    user:          string
    domain:        string
    result:        enum              // SUCCESS | FAILURE
    kerberos_type: string?           // TGT | TGS
    elevation:     bool
  }

  script?: {
    content:       string            // Full script content (de-obfuscated)
    interpreter:   string
    obfuscation_layers: int32
    deobfuscated_content: string?
  }

  memory?: {
    region_address: uint64
    region_size:    uint64
    protection:     string           // RWX, RW, RX
    content_hash:   string
    injection_type: string?
  }

  container?: {
    container_id:  string
    image:         string
    pod_name:      string?
    namespace:     string?
    node_name:     string?
  }

  // Storyline context (Agent-generated)
  storyline?: {
    storyline_id:  uint64
    processes:     int32[]
    tactics:       string[]
    techniques:    string[]
    kill_chain_phase: string
    narrative:     string
  }

  // Enrichment fields (filled by Ingestion Gateway and Analytics)
  enrichment: {
    geo:           GeoInfo
    threat_intel:  ThreatIntelMatch[]
    mitre_ttps:    string[]          // ["T1059.001", "T1055.012"]
    risk_score:    float             // 0.0 - 100.0
    asset_criticality: string
    user_risk_score: float
  }

  // Syscall origin (for direct syscall detection)
  syscall_origin?: {
    return_address: uint64
    expected_module: string
    actual_module:  string?
    is_direct:     bool
  }
}
```

### 4.2 存储层迁移与生命周期

```
Event Lifecycle:

Agent generates event
     |
     v
[Kafka raw-events] -- 72h retention
     |
     v (Ingestion Gateway enrichment)
[Kafka enriched-events] -- 72h retention
     |
     +---> [Flink] -- stream processing
     |       |
     |       v (detection matches)
     |     [Kafka detections] -- 30d retention
     |
     v (Flink batch sink, every 100ms)
[ClickHouse Hot] -- 7 day TTL
     |
     v (Nightly batch migration job, T+7d)
[Elasticsearch Warm] -- 83 day ILM
     |
     v (Nightly batch export job, T+90d)
[S3/MinIO Parquet Cold] -- retention per data type
     |
     v (retention expiry)
[DELETE]
```

**迁移作业：**
- Hot -> Warm：夜间 Spark/Flink 批任务读取超过 7d 的 ClickHouse 分区，批量导入 Elasticsearch，校验计数一致后删除 ClickHouse 分区。
- Warm -> Cold：夜间作业将超过 90d 的 ES 索引导出为 S3 上的 Parquet 文件，校验后删除 ES 索引。
- Cold -> Delete：由 S3 lifecycle policy 按保留规则自动清理（遥测 1 年、告警 3 年、审计永久）。

### 4.3 分区与分片策略

**ClickHouse：**
- 集群：3 shards x 2 replicas（至少 6 节点）
- Distributed table 分片键：`sipHash64(tenant_id, agent_id) % 3`
- 分区键：`toYYYYMMDD(timestamp)`（按天）
- 排序键：`(tenant_id, event_type, timestamp, event_id)`
- Skip indices：`exe_hash`、`dns_query`、`src_ip`、`dst_ip`

**Elasticsearch：**
- 索引模板：`aegis-{tenant_id}-events-{YYYY.MM.dd}`
- 分片数：每索引 1 primary + 1 replica
- Rollover：50GB 或 1 天，以先到者为准
- ILM 阶段：hot（7d，SSD）-> warm（83d，SSD，只读，force-merge 到 1 segment）-> delete

**S3/MinIO Parquet：**
- 分区布局：`s3://aegis-cold/{tenant_id}/event_type={type}/year={YYYY}/month={MM}/day={dd}/`
- 文件大小目标：每个 Parquet 文件 256MB（row group size 128MB）
- 压缩：Snappy（便于分析查询快速解压）
- 列统计：在 Parquet footer 中维护每列 min/max/count 以支持 predicate pushdown

### 4.4 查询路由逻辑

```python
def route_query(query: ParsedQuery) -> List[StorageTier]:
    """根据时间范围和查询类型，决定应查询哪些存储层。"""

    time_range = query.extract_time_range()
    tiers = []

    if time_range.overlaps(now - 7d, now):
        tiers.append(StorageTier.CLICKHOUSE_HOT)

    if time_range.overlaps(now - 90d, now - 7d):
        tiers.append(StorageTier.ELASTICSEARCH_WARM)

    if time_range.overlaps(now - 3y, now - 90d):
        tiers.append(StorageTier.S3_PARQUET_COLD)

    # 优化：全文检索始终优先走 ES，即使时间范围仍在 hot
    if query.has_full_text_search() and StorageTier.ELASTICSEARCH_WARM not in tiers:
        tiers.append(StorageTier.ELASTICSEARCH_WARM)

    # 优化：纯聚合查询优先走 ClickHouse
    if query.is_aggregation_only() and time_range.within(now - 7d, now):
        tiers = [StorageTier.CLICKHOUSE_HOT]

    return tiers
```

---

<a id="5-inter-service-communication-architecture"></a>
## 5. 服务间通信架构

### 5.1 同步与异步边界

| 通信路径 | 模式 | 协议 | 原因 |
|-------------------|---------|----------|-----------|
| Agent -> Gateway | Async streaming | gRPC bidirectional stream over mTLS | 高吞吐，通过 flow control 传递背压 |
| Gateway -> Kafka | Async durable produce | Kafka producer（**全部 Producer 统一 acks=all + enable.idempotence=true + min.insync.replicas=2**；延迟/吞吐差异仅靠 batch/linger 调节） | 持久化不妥协，是 BatchAck.ACCEPTED 契约的前提，详见 transport 架构 §4.4.3 |
| Kafka -> Flink | Async consume | Kafka consumer with exactly-once | 流处理语义 |
| Flink -> ClickHouse | Async batch | JDBC batch insert（100ms micro-batches） | 减少写放大 |
| Flink -> Detections topic | Async produce | Kafka producer | 将检测与消费解耦 |
| Correlation Engine <- Kafka | Async consume | Kafka consumer（detections topic） | 事件驱动关联 |
| ML Inference <- Kafka | Async consume | Kafka consumer（inference-request topic） | 优化 GPU batching |
| Web Console -> API Gateway | Sync request-response | REST/GraphQL over HTTPS | 满足用户交互时延 |
| API Gateway -> Backend services | Sync request-response | gRPC（内部） | 通过 service mesh mTLS 获取低时延 |
| Response Orchestrator -> Agent | Async command | gRPC server stream（`commands.unicast` → Gateway Connection Registry → owner pod → agent；详见 transport §4.5.4） | 事务化补投 + WAL 幂等回放保证可靠交付 |
| Notification Service <- Kafka | Async consume | Kafka consumer（detections topic） | 将告警与通知解耦 |
| Threat Intel -> Agents | Async broadcast | `commands.broadcast`（`command_type=IOC_UPDATE`）→ 每个 Gateway pod 独立 consumer group 透传 → Agent | 广播通道统一，Gateway 不改写 command_type |

### 5.2 事件驱动模式

**以 Kafka 为系统主干的 Event Bus：**  
分析、检测与响应工作流全部通过 Kafka topic 事件驱动完成。这带来：
- 时间解耦：producer 与 consumer 可独立运行
- 可重放：72h retention 支持在修复 bug 或更新规则后重新处理
- 扇出：单个事件可被多个服务消费（Flink、Correlation、ML、Archival）
- 顺序保证：按 partition key（agent_id 或 event_type）维持分区内顺序

**响应编排使用 Saga Pattern：**
复杂响应 playbook 通过 Temporal workflow（saga 模式）实现：
1. 每个响应动作都是可补偿 activity
2. 任意阶段失败触发补偿（例如取证失败则撤销网络隔离）
3. Temporal 处理重试、超时和状态持久化
4. 人工审批步骤通过 Temporal signals 实现

**CQRS（Command Query Responsibility Segregation）：**
- 写路径：Agent -> Gateway -> Kafka -> Flink -> ClickHouse（针对吞吐优化）
- 读路径：Web Console -> API Gateway -> Query Router -> ClickHouse/ES/Parquet（针对查询模式优化）
- 写链路（Kafka brokers、Flink TaskManagers）与读链路（ClickHouse replicas、ES replicas）可独立扩缩容

### 5.3 背压与流控

| 层 | 机制 | 过载时动作 |
|-------|-----------|-------------------|
| Agent Ring Buffer | 优先级通道溢出策略 | Lane 0：有界自旋等待；Lane 1-3：丢弃并计数 |
| Agent Comms | gRPC HTTP/2 flow control + WAL | 云端变慢 -> 事件写入 WAL（500MB，24-48h） |
| Ingestion Gateway | gRPC server-side flow control | 通过 WINDOW_UPDATE 减少 Agent 发送速率 |
| Kafka | Producer backoff（linger.ms、buffer.memory） | Kafka buffer 满时 Gateway 阻塞；gRPC 背压向 Agent 传导 |
| Flink | Backpressure propagation（credit-based） | 慢 operator 导致上游 buffer 堆积 -> Kafka consumer 暂停 |
| ClickHouse | Async insert with buffer table | buffer table 吸收流量尖峰，后台合并 |
| Query path | Connection pool limits + query timeout | 连接池耗尽时拒绝查询；超时终止长查询 |

**端到端背压链：**  
ClickHouse 变慢 -> Flink backpressure -> Kafka consumer lag 增长 -> Gateway Kafka producer 阻塞 -> gRPC flow control 降低 Agent 发送速率 -> Agent 缓冲到 WAL。

该链路确保系统不会在压力下静默丢数，而是从 ClickHouse 一路优雅退化至 Agent 侧 WAL。

---

<a id="6-resilience-and-fault-tolerance-design"></a>
## 6. 韧性与容错设计

### 6.1 Agent 离线自治

当与云端断连（>30s）时：
- **Sensors**：所有内核态和用户态传感器持续全量采集，不降级
- **Detection**：IOC filter 使用本地缓存；Sigma/YARA 使用本地已编译规则；ML inference 使用本地 ONNX Runtime；Temporal correlation + state machines 继续运行；Storyline Engine 持续构建上下文
- **Response**：按本地策略执行 Suspend/Kill/Quarantine；network isolation 与 endpoint firewall 持续生效；ASR/Device Control/Deception 保持本地执行
- **Data**：全部遥测、告警、响应审计写入 WAL（500MB，约 24-48h 覆盖）；sequence_id 保证重连后的有序回放
- **离线不可用**：跨终端云端关联、实时威胁情报更新、远程取证、远程 shell、云端调度的 decoy rotation

**重连恢复：**
1. 重新建立 mTLS session
2. 发送离线摘要（时长、事件计数、检测计数、WAL 利用率）
3. 按 sequence_id 顺序回放 WAL 遥测、告警和响应审计
4. 拉取缺失的 rules/models/IOC/policy 更新
5. 云端对离线期间的 Storylines 做追溯关联分析

### 6.2 云端故障切换

**多 AZ 部署：**
全部有状态服务都跨 3 个可用区部署：
- Kafka：每 AZ 5 brokers（总 15），replication factor 3
- ClickHouse：shard 跨 AZ 分布，每个 shard 的 replica 位于不同 AZ
- Elasticsearch：每 AZ 3 data nodes（总 9），master nodes 跨 AZ
- PostgreSQL：Primary 在 AZ-a，同步 standby 在 AZ-b，异步 standby 在 AZ-c
- Redis：6 节点集群跨 3 AZ（3 masters + 3 replicas）
- Vault：3 节点集群跨 AZ（Raft 共识）

**数据复制：**

| 组件 | 复制策略 | RPO | RTO |
|-----------|---------------------|-----|-----|
| Kafka | ISR（In-Sync Replicas），min.insync.replicas=2 | 0（同步） | < 30s（leader election） |
| ClickHouse | ReplicatedMergeTree via ZooKeeper | < 1s（异步复制延迟） | < 60s（replica promotion） |
| Elasticsearch | 每 shard 1 个 replica，跨 AZ | < 1s | < 60s（shard reallocation） |
| PostgreSQL | Synchronous standby | 0 | < 30s（Patroni failover） |
| Redis | Redis Cluster replication | < 1s | < 15s（sentinel/cluster failover） |
| S3/MinIO | Erasure coding（MinIO）或 S3 11 个 9 持久性 | 0 | N/A（持续可用） |

### 6.3 熔断、隔舱与重试策略

**Circuit Breaker Pattern（在 service mesh - Istio 中实现）：**

| 服务 | 失败阈值 | 打开时长 | Half-Open 探测数 |
|---------|------------------|---------------|------------------|
| ML Inference | 10s 窗口内 50% 错误率 | 30s | 3 probes |
| Threat Intel | 30s 窗口内 30% 错误率 | 60s | 5 probes |
| ClickHouse query | 60s 内 20% timeout | 120s | 3 probes |
| External feed（STIX/TAXII） | 连续 3 次失败 | 300s | 1 probe |

**Bulkhead Pattern：**
- 为 ingestion path、query path、management API、background jobs 分离线程池
- 每个服务使用独立 Kafka consumer group（Flink、Correlation、ML、Archival）
- 每类下游依赖（ClickHouse、ES、PostgreSQL、Redis）使用独立连接池
- Flink 作业隔离：rule matching、anomaly detection、TTP correlation 拆为不同 job graph

**重试策略：**

| 操作 | 策略 | 最大重试次数 | Backoff |
|-----------|----------|-------------|---------|
| Agent -> Gateway gRPC | 指数退避 + jitter | Unlimited（依赖 WAL 缓冲） | 1s -> 5min max |
| Gateway -> Kafka produce | 线性退避 | 5 | 100ms, 200ms, 500ms, 1s, 2s |
| Flink -> ClickHouse insert | 指数退避 | 10 | 1s -> 30s |
| Temporal workflow activity | 按 activity 可配置 | Per playbook definition | 指数退避 |
| API Gateway -> Backend | 503 时立即重试 | 2 | 0ms, 100ms |

### 6.4 防止数据丢失

| 层 | 机制 | 覆盖范围 |
|-------|-----------|----------|
| Agent kernel | 优先级 Ring Buffer 通道 | CRITICAL 事件：目标 0% 丢失 |
| Agent user-space | WAL + 每条 record 的 CRC32 | 网络中断：缓冲 24-48h |
| Agent -> Gateway | gRPC ACK + sequence_id | 可靠交付 + 去重 |
| Gateway -> Kafka | **全量 acks=all + idempotent producer + min.insync.replicas=2**；不存在 "ACCEPTED 但未 ISR 同步" 的中间状态 | Kafka ISR 持久性成为 BatchAck.ACCEPTED 契约的前提，详见 transport 架构 §4.4.3 |
| Kafka | replication factor 3，min.insync.replicas=2 | 能承受 1 个 AZ 故障 |
| Flink | Kafka transactions + checkpoints 的 exactly-once | 可从 checkpoint 恢复状态 |
| ClickHouse | ReplicatedMergeTree，每 shard 2 个副本 | 能承受 1 个 replica 故障 |
| Elasticsearch | 每 shard 1 个 replica，跨 AZ | 能承受 1 个 AZ 故障 |
| S3/MinIO | Erasure coding / 11 个 9 | 能承受多磁盘故障 |
| PostgreSQL | 同步复制 + WAL 归档 | failover 时零数据丢失 |

---

<a id="7-security-architecture"></a>
## 7. 安全架构

### 7.1 信任边界与威胁模型

```
Trust Boundary Diagram:

+--[Untrusted]--+     +--[Semi-Trusted]--+     +--[Trusted]--------+
|                |     |                   |     |                    |
| Endpoints      | mTLS| Transport Plane   | mTLS| Analytics/Data/   |
| (potentially   |---->| (Gateway, LB)     |---->| Management Planes |
|  compromised)  |     |                   |     | (K8s cluster)     |
|                |     |                   |     |                    |
+----------------+     +-------------------+     +--------------------+
                                                        |
                                                   mTLS | (Service Mesh)
                                                        |
                                                 +------v------+
                                                 | External    |
                                                 | Integrations|
                                                 | (SIEM, SOAR,|
                                                 |  Feeds)     |
                                                 +-------------+
```

**威胁模型（按边界使用 STRIDE）：**

| 边界 | 威胁 | 缓解措施 |
|----------|--------|------------|
| Agent <-> Gateway | Spoofing | mTLS + 每 Agent 独立证书；cert CN = agent_id |
| Agent <-> Gateway | Tampering | TLS 1.3 通道加密；Protobuf schema validation |
| Agent <-> Gateway | Repudiation | lineage_id tracing；服务端 sequence logging |
| Agent <-> Gateway | Info Disclosure | TLS 加密；LZ4 压缩（非安全手段，仅混淆） |
| Agent <-> Gateway | DoS | 按 Agent 限速；支持证书吊销 |
| Agent <-> Gateway | Elevation | Tenant ID 来自证书，不来自 Agent payload |
| Gateway <-> Internal | Spoofing | Service mesh mTLS（Istio） |
| Gateway <-> Internal | Tampering | 每个服务边界再次执行 Protobuf validation |
| Web Console <-> API | Spoofing | OIDC/SAML SSO + MFA |
| Web Console <-> API | Elevation | 最小权限 RBAC |
| Data at rest | Info Disclosure | AES-256-GCM；LUKS 磁盘级加密 |
| Agent self | Tampering | 四层自保护（内核保护、完整性、watchdog、反篡改） |

### 7.2 mTLS 证书生命周期

```
Certificate Hierarchy:

Root CA (offline, HSM-stored)
  |
  +-- Intermediate CA (online, Vault-managed)
       |
       +-- Agent Device Certificates (per-agent)
       |     Validity: 90 days
       |     CN: agent_id
       |     SAN: tenant_id
       |     Key storage: TPM/Secure Enclave (Tier 1) or OS keystore (Tier 2)
       |
       +-- Service Certificates (per-service)
       |     Validity: 30 days (auto-rotated by Istio/Vault)
       |     CN: service-name.namespace.svc.cluster.local
       |
       +-- Gateway Server Certificates
             Validity: 90 days
             SAN: *.gateway.aegis.io
```

**Agent 证书生命周期：**
1. **Provisioning**：Agent 安装时生成密钥对（优先 TPM 绑定），创建 CSR，提交至云端 enrollment API，获取签发证书
2. **Rotation**：在过期前 14 天主动发起轮换；生成新密钥对，以旧证书作为身份凭证提交 CSR，收到新证书后原子切换
3. **Revocation**：云端将 CRL/OCSP 推送到 Gateway；被吊销 Agent 的连接被拒绝；Agent 进入 degraded mode（仅本地检测，不再与云通信）
4. **Emergency rotation**：怀疑密钥泄露时，云端通过带外通道触发强制轮换

### 7.3 多租户隔离保证

| 层 | 隔离机制 |
|-------|-------------------|
| Agent | agent_id 和 tenant_id 写入证书，无法冒充其他租户 |
| Gateway | tenant_id 从 mTLS 证书提取，不信任 payload 中自报字段；并注入到每个事件 |
| Kafka | raw-events 按租户独立 topic（raw-events.{tenant}）；共享 topic 使用 tenant_id 作为 message key 保持分区亲和 |
| ClickHouse | 所有查询都强制带 tenant_id filter；代理层 query rewriting 阻止跨租户访问 |
| Elasticsearch | 索引按租户划分（aegis-{tenant_id}-events-*）；利用 ES security features 实现索引级隔离 |
| S3/MinIO | 每租户独立 prefix；IAM policy 禁止跨租户访问 |
| PostgreSQL | 所有 tenant-scoped table 启用 Row-Level Security（RLS） |
| API Gateway | JWT/session 中携带 tenant_id；middleware 对每个请求强制 tenant context |
| RBAC | 角色按租户作用域划分；Super Admin（平台级）与 Tenant Admin（租户内）分离 |
| 物理隔离 | 对高安全租户可启用：独立 Kafka topics、独立 ClickHouse 集群、独立 ES 索引、独立 S3 buckets |

### 7.4 Agent 自保护的纵深防御

（细节见第 2.1.8 节。此处从安全架构角度做摘要。）

**Ring 3（用户态）攻击者防御：**
- Kernel callbacks 防止句柄劫持（ObRegisterCallbacks）
- Minifilter 防止文件篡改
- Registry callbacks 防止注册表篡改
- Process notification 防止进程被终止
- ELAM 保证最早驱动加载
- Watchdog（Windows 上为 PPL）负责监控与重启

**Ring 0（内核态）攻击者检测：**
- SSDT/IDT hash 监控
- Kernel code segment integrity
- Callback table verification
- DKOM detection（多路径进程枚举）
- BPF program integrity monitoring（Linux）
- ETW/AMSI tamper detection（Windows）
- 明确声明：不承诺 Ring 0 防御，目标是提升攻击成本并发现不完美 rootkit

**供应链安全：**
- Agent binary 全链路代码签名
- Driver WHQL/DKMS 签名
- Secure Boot 集成（UEFI chain verification）
- Update packages 带签名（Sigstore/TUF）
- Plugin WASM 带签名（Ed25519）

### 7.5 数据安全

| 方面 | 机制 |
|--------|-----------|
| 传输加密 | TLS 1.3 + mTLS（Agent <-> Gateway）；内部走 service mesh mTLS（Istio） |
| 存储加密 | AES-256-GCM（全部静态数据）；LUKS（磁盘级） |
| 密钥管理 | Vault 自动轮换；Agent 证书 90 天有效期 |
| 数据脱敏 | PII 字段（username/IP）支持假名化存储 |
| 数据隔离 | Tenant ID 全链路透传；关键租户可物理隔离 |
| 审计轨迹 | 所有管理操作完整审计；append-only log；抗篡改 |
| 安全删除 | SSD 感知：优先用文件系统级 crypto delete；回退方案为 overwrite + TRIM |

---

<a id="8-deployment-and-operations-architecture"></a>
## 8. 部署与运维架构

### 8.1 Kubernetes 资源拓扑

```
Region: primary (e.g., us-west-2)
|
+-- AZ-a
|   |-- Ingestion Gateway (5 pods, gRPC, HPA)
|   |-- Kafka Broker x 5 (StatefulSet)
|   |-- ClickHouse Shard 1-3 (StatefulSet, NVMe PV)
|   |-- ES Data Node x 3 (StatefulSet, SSD PV)
|   |-- Flink TaskManager x 4 (Deployment)
|   |-- Correlation Engine x 2 (Deployment)
|   +-- Management Services (1-2 pods each: Auth, Asset, Policy, Incident,
|       Response Orchestrator, Reporting, Notification)
|
+-- AZ-b
|   |-- Ingestion Gateway (5 pods)
|   |-- Kafka Broker x 5
|   |-- ClickHouse Shard 4-6
|   |-- ES Data Node x 3
|   |-- Flink TaskManager x 3
|   |-- ML Inference (GPU x 2: A100/H100)
|   +-- Management Services (1-2 pods each)
|
+-- AZ-c
|   |-- Ingestion Gateway (5 pods)
|   |-- Kafka Broker x 5
|   |-- ClickHouse Replica nodes
|   |-- ES Data Node x 3
|   |-- Flink TaskManager x 3
|   |-- ML Inference (GPU x 2)
|   +-- PostgreSQL Standby + Redis Replica
|
+-- Shared (cross-AZ)
    |-- ZooKeeper x 3 (Kafka coordination, one per AZ)
    |-- ES Master x 3 (dedicated master, one per AZ)
    |-- PostgreSQL Primary + PgBouncer (AZ-a, sync standby AZ-b)
    |-- Redis Cluster (6 nodes: 3 masters + 3 replicas, cross-AZ)
    |-- Vault Cluster x 3 (one per AZ, Raft consensus)
    |-- Flink JobManager x 2 (HA, cross-AZ)
    |-- Temporal Server x 3 (cross-AZ)
    |-- MinIO / S3 (cold storage)
    |-- CDN -> Web Console (React SPA)
    |-- Prometheus + Grafana + Jaeger + Loki (observability stack)
```

### 8.2 容量规划公式

**Kafka：**
```
kafka_brokers = ceil(total_write_throughput_bytes / per_broker_write_capacity)
  = ceil(10 GB/s / 800 MB/s) = 13 -> 15 (round to 5 per AZ)

kafka_storage_per_broker = daily_data * retention_days * replication_factor / broker_count
  = 5 TB/day * 3 days * 3 / 15 = 3 TB per broker

kafka_partitions_per_topic = max(consumer_parallelism, throughput / per_partition_throughput)
  = max(128, 8.3M/s / 100K/s) = 128
```

**ClickHouse：**
```
clickhouse_nodes = ceil(daily_compressed_data * hot_days / per_node_storage * safety_factor)
  = ceil(2 TB/day * 7 days / 4 TB * 1.5) = 6 nodes (3 shards x 2 replicas)

clickhouse_cpu = events_per_second / per_core_insert_rate * query_overhead_factor
  = 8.3M / 500K * 2 = 34 cores -> 6 nodes x 64 cores (ample headroom)
```

**Elasticsearch：**
```
es_data_nodes = ceil(daily_index_size * warm_days / per_node_storage * safety_factor)
  = ceil(3 TB/day * 83 days / 30 TB * 1.5) = 13 -> 9 nodes (with compression gains)

es_memory = per_node: 128 GB (50% JVM heap = 64 GB, 50% OS cache)
```

**GPU（ML Inference）：**
```
gpu_nodes = ceil(inference_requests_per_second / per_gpu_throughput)
  Static file: 50K files/day -> ~1/s -> 0.01 GPU
  Behavioral: 1M suspicious sequences/day -> ~12/s -> 0.1 GPU
  Script: 500K scripts/day -> ~6/s -> 1 GPU (7B model)
  Total: 4 GPUs (2 per AZ, with headroom for batch retraining)
```

### 8.3 扩缩容触发器与策略

| 服务 | 指标 | 扩容触发 | 缩容触发 | 类型 |
|---------|--------|-------------------|------------------|------|
| Ingestion Gateway | CPU utilization | > 60% 持续 3min | < 30% 持续 10min | HPA |
| Ingestion Gateway | gRPC connection count | > 5000/pod | < 2000/pod | HPA |
| Flink TaskManager | Kafka consumer lag | > 100K messages 持续 5min | < 10K 持续 30min | 自定义指标 + HPA |
| Correlation Engine | Processing queue depth | > 10K 持续 2min | < 1K 持续 10min | HPA |
| ML Inference | GPU utilization | > 70% 持续 5min | < 30% 持续 30min | HPA（自定义 GPU 指标） |
| API Gateway | Request latency P99 | > 500ms 持续 2min | < 100ms 持续 10min | HPA |
| Management Services | CPU utilization | > 70% 持续 3min | < 30% 持续 10min | HPA |
| Kafka | Disk utilization | > 70% | 手动扩容（增加 broker） | 告警触发 |
| ClickHouse | Query latency P99 | > 3s 持续 5min | 手动评估 | 告警触发 |
| Elasticsearch | Search latency P99 | > 5s 持续 5min | 手动评估 | 告警触发 |

**VPA（Vertical Pod Autoscaler）：**
应用于 Kafka、ClickHouse、ES 这类有状态服务，因为它们的水平扩容通常伴随重平衡。VPA 会依据真实使用模式调整 memory/CPU requests。

### 8.4 可观测性栈集成

```
Observability Architecture:

+-- Prometheus (Metrics) ----+
|  Service metrics (latency, |     +-- Grafana (Visualization) --+
|  throughput, error rate)    |---->| Unified dashboards:          |
|  Infrastructure metrics     |     | - Platform health overview   |
|  (CPU, memory, disk, net)  |     | - Per-service metrics        |
|  Custom metrics (Kafka lag, |     | - Agent fleet health         |
|  detection rate, FP rate)   |     | - Capacity planning          |
+-----------------------------+     | - SLO tracking               |
                                    +------------------------------+
+-- Jaeger (Tracing) --------+            ^
|  Distributed traces across  |            |
|  service mesh (Istio)       |------------+
|  lineage_id correlation     |
|  Gateway -> Kafka -> Flink  |
|  -> ClickHouse traces       |
+-----------------------------+

+-- Loki (Logs) -------------+
|  Operational logs (not      |
|  security telemetry)        |------------+
|  Structured JSON logging    |            |
|  from all services          |            v
+-----------------------------+     Alertmanager
                                    - PagerDuty
+-- Custom Metrics -----------+     - Slack
|  Agent fleet health:        |     - Email
|  - Connected agents count   |
|  - Agent version dist.      |
|  - Detection rate trends    |
|  - False positive rate      |
|  - WAL utilization fleet    |
|  - Ring Buffer drop rates   |
+-----------------------------+
```

**关键 SLO 与告警门槛：**

| SLO | 目标 | 告警阈值 |
|-----|--------|----------------|
| 数据接入可用性 | 99.99% | Error rate > 0.01% 持续 5min |
| 云平台可用性 | 99.95% | 任意关键服务 down > 5min |
| 端到端检测时延（critical） | < 1s | P99 > 1s 持续 5min |
| 云端关联时延 | < 5s | P99 > 5s 持续 5min |
| Agent 崩溃率 | < 0.01%/month | 任意 24h 窗口 > 0.005% |
| Kafka consumer lag（Flink） | < 100K | > 500K 持续 10min |
| ClickHouse query P99 | < 3s | > 5s 持续 5min |

---

<a id="9-architecture-decision-records"></a>
## 9. 架构决策记录

### ADR-001：Agent 用户态采用 Rust

**背景：**  
Agent 运行在每一台终端上（100 万+），必须在执行复杂检测流水线、ML 推理和响应动作的同时维持 CPU <= 2%、memory <= 150MB。Agent 本身又是高价值攻击目标，因此必须具备内存安全保障。

**决策：**  
Agent 所有用户态代码统一使用 Rust。

**影响：**

| 方面 | 细节 |
|--------|--------|
| **正向** | 零成本抽象可提供接近 C 的性能，并具备内存安全保证。所有权系统在编译期阻止 use-after-free、buffer overflow 与 data race。单一二进制便于分发。通过条件编译实现跨平台。WASM 插件宿主通过 wasmtime（Rust 原生）。强大的 async 生态（tokio）适合并发事件处理。 |
| **正向** | 降低 Agent 自身的漏洞暴露面，这一点至关重要，因为 Agent 运行在高权限环境。 |
| **负向** | 学习曲线高于 Go/C++；编译时间更长；可用人才池更小。 |
| **负向** | 与内核驱动交互时仍需通过 FFI（C ABI）。 |
| **备选** | **C++**：性能接近，但无内存安全保证；而 Agent 漏洞本身就是高风险。**Go**：开发更简单，但 GC pause 不适合实时检测流水线，且内存占用更高。**C**：控制力最强，但安全风险最高。 |
| **理由** | 对于部署在每个终端、贴近内核权限、且自身就是攻击目标的安全产品，内存安全不是可选项。Rust 是唯一能同时满足性能预算与安全保证的方案。 |

**状态：** Accepted

---

### ADR-002：ClickHouse + Elasticsearch + S3 分层存储

**背景：**  
平台需要存储 500 亿事件/天（原始 50TB、压缩后 5TB），查询时延需求从亚秒级（运营）到分钟级（深度取证），保留周期从 7 天到 3 年不等。

**决策：**  
采用三层存储：ClickHouse（hot，7d）、Elasticsearch（warm，7-90d）、S3/MinIO+Parquet（cold，90d-3y）。

**影响：**

| 方面 | 细节 |
|--------|--------|
| **正向** | ClickHouse：适合运营看板与实时查询，聚合可达亚秒级。列式压缩比可达 10:1。原生支持 SQL。已在 Cloudflare、Uber 等场景验证规模能力。 |
| **正向** | Elasticsearch：提供威胁狩猎所需的全文检索能力（如 cmdline grep、脚本内容搜索）。可配合 Kibana/OpenSearch Dashboards 做临时探索。 |
| **正向** | S3+Parquet：长期存储成本接近最低。Parquet 列式格式可通过 Presto/Trino 高效分析查询。满足合规保留要求且成本可控。 |
| **正向** | 每一层都针对其访问模式最优化：ClickHouse 面向近期聚合，ES 面向全文检索，Parquet 面向大规模离线分析。 |
| **负向** | 需要同时运维三种存储引擎；层间迁移作业增加复杂度；统一查询路由增加抽象层。 |
| **负向** | 跨层查询（时间范围跨多个 tier）需要结果合并。 |
| **备选** | **仅 ClickHouse**：缺少优秀的全文检索能力。**仅 ES**：无法承受 8.3M events/sec 插入速率；聚合性能不足。**单一 data lake（Iceberg+Spark）**：查询延迟过高，不适合运营场景。**Snowflake/BigQuery**：云厂商锁定；50TB/day 成本过高；实时性不足。 |
| **理由** | 没有任何单一存储引擎能同时满足高吞吐写入 + 亚秒聚合、全文检索和低成本长期保留三类需求。分层存储是最匹配访问模式的方案。 |

**状态：** Accepted

---

### ADR-003：Apache Flink 用于流处理

**背景：**  
平台需要以 8.3M events/sec 的规模实时执行规则匹配、行为序列分析、统计异常检测和 TTP 链关联。处理过程中需要窗口聚合、复杂事件处理（CEP）以及 exactly-once 语义。

**决策：**  
使用 Apache Flink 作为流处理引擎。

**影响：**

| 方面 | 细节 |
|--------|--------|
| **正向** | 原生 CEP 库适合复杂事件模式匹配（攻击链检测）。基于 event-time + watermarks，可处理迟到事件。通过 Kafka transactional integration 实现 exactly-once。增量 checkpoint 到 RocksDB+S3，恢复迅速。规模能力已在业界验证（如阿里 1B+ events/sec）。 |
| **正向** | 支持同一套流水线同时处理实时流和历史回放。 |
| **负向** | JVM 实现导致内存开销高于 Go/Rust 原生服务；运维模型较复杂（JobManager、TaskManager、ZooKeeper/etcd）。 |
| **负向** | 需要专门团队掌握 Flink job 开发与调优。 |
| **备选** | **Kafka Streams**：更简单，但 CEP 能力不足，窗口聚合成熟度较低，也无法与 Kafka 独立扩展。**Apache Spark Structured Streaming**：micro-batch 模型增加延迟（最少 100ms+），不是真流处理。**自研 Go 服务**：可控性高，但需从零构建 CEP、窗口、checkpoint 与 exactly-once。**ksqlDB**：SQL-only 表达力不足以支撑复杂 TTP 关联。 |
| **理由** | 多步攻击链检测离不开 CEP；准确告警计数离不开 exactly-once；再加上可验证的规模能力，使 Flink 成为尽管复杂、但仍然最优的选择。 |

**状态：** Accepted

---

### ADR-004：Agent 通信采用 gRPC + mTLS

**背景：**  
100 万 Agent 持续与云平台通信，上送遥测并接收命令。通信必须安全、高效、双向，并具备抗网络中断能力。

**决策：**  
采用 TLS 1.3 上的 gRPC 双向流 + 双向 TLS 认证，并提供 WebSocket、HTTPS long-polling 与可选 domain fronting 的回退链。

**影响：**

| 方面 | 细节 |
|--------|--------|
| **正向** | gRPC 基于 HTTP/2 多路复用：单 TCP 连接可同时承载双向数据流（遥测上行、命令下行）。内建 flow control 防止过载。Protobuf 紧凑且高效。mTLS 在不引入额外凭据系统的前提下提供强身份认证。 |
| **正向** | 双向流支持无需轮询的即时命令下发。 |
| **正向** | 回退链（WebSocket、long-polling、domain fronting）确保在敌对网络环境（DPI、proxy、firewall）下仍能维持连接。 |
| **负向** | gRPC HTTP/2 容易被 DPI 指纹化并阻断。通过回退链和 JA3 随机化缓解。 |
| **负向** | 在 100 万 Agent 规模下进行 mTLS 证书生命周期管理，需要非常稳健的自动化体系（Vault 集成、自动轮换）。 |
| **备选** | **HTTPS REST polling**：更简单，但命令下发延迟高，遥测不适合流式传输。**MQTT**：偏 IoT 场景，缺少 HTTP/2 多路复用效率，生态也不如 gRPC 成熟。**自定义 TCP 协议**：灵活，但要从零构建安全、framing、flow control。**仅 WebSocket**：可行，但在 Protobuf 集成与 HTTP/2 多路复用方面不如 gRPC 成熟。 |
| **理由** | gRPC 是高吞吐、双向、强类型服务通信的事实标准；mTLS 同时解决加密与认证问题；回退链解决其最显著的短板（被 DPI 阻断）。 |

**状态：** Accepted

---

### ADR-005：Temporal 用于响应编排

**背景：**  
响应 playbook 包含多步骤工作流（kill process、isolate network、sweep IOCs、collect forensics、notify），中间可能存在人工审批、失败补偿，以及在服务重启后仍需持续执行的要求。

**决策：**  
Response Orchestration Service 使用 Temporal 作为工作流引擎。

**影响：**

| 方面 | 细节 |
|--------|--------|
| **正向** | 持久执行：服务重启后 workflow state 依然可恢复，不会丢失 playbook 执行。每个 activity 自带可配置重试与 backoff。支持 saga pattern：失败后执行补偿动作（如撤销隔离）。通过 signals 支持 human-in-the-loop 审批。可完整保留 workflow history 以满足审计。 |
| **正向** | Temporal workers 可独立水平扩展；Temporal server cluster 提供高可用。 |
| **负向** | 需要额外运维 Temporal 基础设施（Temporal server、Cassandra/PostgreSQL backend）；还要掌握 Temporal workflow/activity 的开发模式。 |
| **备选** | **PostgreSQL 上自建状态机**：更简单，但重试、补偿、持久执行与可视化都需要从零开发。**Apache Airflow**：偏 DAG，不适合事件驱动的实时工作流。**AWS Step Functions**：存在云厂商锁定。**Cadence**：社区活跃度低于 Temporal。 |
| **理由** | 响应编排是安全关键路径。一个执行了一半的 playbook（例如进程被杀死但网络未隔离）比完全不执行更危险。Temporal 的持久执行和 saga 支持正面解决了这一问题，审批流程也天然适配 signals。 |

**状态：** Accepted

---

### ADR-006：内核到用户态采用 MPSC 优先级 Ring Buffer

**背景：**  
内核态 sensor hooks 会以极高频率（百万级/sec）产生事件，必须以最低延迟将其传递到用户态；同时，在敌对条件下（噪声攻击用大量低价值事件冲刷）也不能丢失关键事件。

**决策：**  
采用共享内存（mmap）上的 Multi-Producer Single-Consumer（MPSC）ring buffer，并划分 4 条优先级通道，总大小 64MB。

**影响：**

| 方面 | 细节 |
|--------|--------|
| **正向** | 通过 mmap 实现 zero-copy 传输，消除 kernel->user 数据复制。优先级通道可确保 CRITICAL 事件（进程创建、认证、篡改检测）在 FILE/NET 噪声冲击下仍被保留。无锁 MPSC 设计（atomic_fetch_add）支持多个内核线程并发写入，无需 mutex。对 CRITICAL 通道采用有界 spin-wait，尽量避免丢失。 |
| **正向** | 用户态 consumer 采用加权 round-robin（4:2:1:1）保证优先级调度。 |
| **正向** | 按通道维护 drop counters，可精确观测各优先级的事件丢失情况。 |
| **负向** | 固定占用 64MB 内存。Linux 上需要 4 个独立 ring buffer（BPF_MAP_TYPE_RINGBUF）。相比单一 ring buffer 更复杂。 |
| **备选** | **单一 ring buffer + priority field**：更简单，但不能抵御噪声攻击，高频低价值事件会饿死关键事件。**kernel-to-user pipe/netlink**：复制开销大，且无法保留优先级。**perf event ring buffer**：仅单 consumer，且无优先级通道。**BPF_MAP_TYPE_PERF_EVENT_ARRAY**：按 CPU 分布，但无优先级通道，高争用下可能丢数。 |
| **理由** | 优先级通道设计是 Agent 在对抗场景下保持检测能力的基础。攻击者即使制造每秒数百万文件写事件，也不应能遮蔽进程和认证监控。 |

**状态：** Accepted

---

### ADR-007：IOC 匹配采用分层 Bloom + Cuckoo Filter

**背景：**  
Agent 需要以亚微秒时延匹配多达 500 万个 IOC（hash、IP、domain），同时占用极小内存，并支持 IOC 生命周期管理（新增、删除）。

**决策：**  
采用三层过滤器：Tier 0 CRITICAL Bloom（50K entries，~1MB）、Tier 1 HIGH Bloom（500K entries，~5MB）、Tier 2 STANDARD Cuckoo Filter（5M entries，~4.5MB）。总计约 10MB。正匹配后再通过精确 HashMap 复核。

**影响：**

| 方面 | 细节 |
|--------|--------|
| **正向** | 每层 O(1) 查询，且可按 IOC 重要性配置误报率（critical 为 0.001%，standard 为 0.01%）。总计 5M IOCs 仅需 ~10MB。Tier 2 使用 Cuckoo Filter，可支持动态删除（IOC aging/retirement），这是 Bloom filter 做不到的。 |
| **负向** | 相比单一过滤器，三层设计更复杂。Cuckoo filter 在极高装载率下可能插入失败。 |
| **备选** | **单一大 Bloom filter**：无法删除，需要在 IOC 退役时全量重建。**HashSet**：5M entries * ~80 bytes = ~400MB，超出内存预算。**Aho-Corasick**：适合字符串匹配，不适合 hash/IP lookup。 |
| **理由** | 分层设计让 IOC 严重度与 FPR 要求匹配；而 Cuckoo filter 又是唯一能在不重建的情况下支持删除的选择，满足 Agent 严格内存预算下的 IOC 生命周期管理。 |

**状态：** Accepted

---

### ADR-008：Kafka 作为事件总线

**背景：**  
平台需要一个中央事件总线，以解耦 Gateway 这类 producer 与 Flink、Correlation、ML、Archival 等 consumer，并提供可重放能力、顺序保证以及 10 GB/s 的写入吞吐。

**决策：**  
采用 Apache Kafka 3.x 作为中心事件总线，在 3 个 AZ 部署 15+ brokers。

**影响：**

| 方面 | 细节 |
|--------|--------|
| **正向** | 在 10 GB/s+ 吞吐下已有充分实践验证（LinkedIn、Uber）。分区内具备顺序保证。保留期可灵活配置（原始事件 72h、检测 30d、审计 365d）。consumer group 隔离使 Flink、Correlation、ML 等流水线可独立扩缩容。事件可重放，便于在规则/模型更新后追溯重算。 |
| **正向** | 通过 transactional API（Flink 集成）支持 exactly-once。 |
| **负向** | 运维复杂度较高（旧版本依赖 ZooKeeper，新版本可切 KRaft）。扩容重平衡期间可能出现短暂 lag 峰值。 |
| **备选** | **Pulsar**：内建多租户与 tiered storage，但生态较小，且在此吞吐级别的落地经验不如 Kafka。**Redpanda**：Kafka 兼容、运维更简单（非 JVM），但超大规模案例不如 Kafka 丰富。**NATS JetStream**：更简单，但生态集成（Flink、Spark connectors）不如 Kafka。**AWS Kinesis**：云厂商锁定，且 shard 管理复杂。 |
| **理由** | Kafka 是高吞吐事件流的事实标准，且拥有最完善的周边生态（Flink、Spark、ClickHouse、ES connectors）。在 10 GB/s 级别场景下，经过充分验证的稳定性是首要考虑。 |

**状态：** Accepted

---

### ADR-009：Agent 插件隔离采用 WASM Sandbox

**背景：**  
Agent 必须支持可扩展的 sensor plugins，这些插件可以独立开发、分发和更新，同时不能因插件 bug 破坏主进程稳定性。

**决策：**  
采用 WASM（wasmtime runtime）实现插件隔离，并定义 Host Function ABI。

**影响：**

| 方面 | 细节 |
|--------|--------|
| **正向** | 内存隔离：每个插件位于独立 WASM linear memory 中，崩溃只影响插件实例。CPU 时间限制可防止 runaway plugin。插件以 .wasm 文件独立分发，并用 Ed25519 签名，无需完整升级 Agent。Host Function ABI 提供受控访问（emit_event、read_config、log、request_scan）。 |
| **负向** | WASM 存在运行时开销：对于重计算任务通常比原生 Rust 慢约 2-5 倍。系统调用访问受限（这本身也是安全设计的一部分）。 |
| **备选** | **独立进程**：隔离更强，但 IPC 开销和每插件内存成本更高。**动态库（.so/.dll）**：无内存隔离，插件崩溃会拖垮 Agent。**Lua/Python embedded**：存在 GC pause，沙箱强度也更弱。 |
| **理由** | 对于既要求稳定性又要求可扩展性的终端安全产品，WASM 在隔离强度、性能开销和分发灵活性之间提供了最优平衡。 |

**状态：** Accepted

---

## 附录 A：完整微服务清单

| 平面 | 服务 | 职责 | 语言/框架 | 实例数 |
|-------|---------|---------------|-------------------|----------------|
| Endpoint | Agent | 遥测 + 本地检测 + 响应 | Rust（user）+ C（kernel） | 每终端 1 个 |
| Transport | Ingestion Gateway | mTLS 认证 + 解压 + 校验 + 路由 | Go（gRPC） | 20+（HPA） |
| Data | Kafka | 事件总线 | Kafka 3.x | 15+ brokers |
| Data | ClickHouse | 热存储 | ClickHouse | 6+ nodes |
| Data | Elasticsearch | 温存储 + 全文检索 | ES 8.x | 9+ nodes |
| Data | MinIO/S3 | 冷存储 | MinIO | 3+ nodes |
| Analytics | Stream Processor | 实时规则 + 行为关联 | Java（Flink） | 10+ TaskManagers |
| Analytics | Correlation Engine | 攻击链 + 告警聚合 | Go | 5+ |
| Analytics | ML Inference | 模型推理 | Python（Triton/TorchServe） | 4+ GPU nodes |
| Analytics | Threat Intel Service | 情报聚合 + IOC 管理 + 分发 | Go | 3+ |
| Analytics | Hunting Service | 交互式威胁狩猎 | Python + Go | 3+ |
| Management | API Gateway | 统一入口 + 限速 + 路由 | Kong/Envoy | 3+ |
| Management | Auth Service | SSO + RBAC + MFA | Go（Kratos/Hydra） | 3+ |
| Management | Asset Service | 资产管理 + Agent 生命周期 | Go | 3+ |
| Management | Policy Service | 策略管理 + 分发 | Go | 3+ |
| Management | Incident Service | 事件处置流程 + 工作流 | Go | 3+ |
| Management | Response Orchestrator | Playbook 引擎 + 响应编排 | Go + Temporal | 3+ |
| Management | Reporting Service | 报表生成 + 导出 | Python | 2+ |
| Management | Notification Service | 多通道通知 | Go | 3+ |
| Management | Web Console | 管理界面 | React + TypeScript | CDN |

## 附录 B：基础设施依赖

| 组件 | 选型 | 用途 |
|-----------|----------|---------|
| 容器编排 | Kubernetes | 所有服务部署 |
| Service mesh | Istio / Linkerd | 服务间 mTLS + 可观测性 |
| 配置中心 | etcd / Consul | 服务发现 + 分布式配置 |
| 密钥管理 | HashiCorp Vault | 证书、密钥、API keys |
| CI/CD | GitLab CI / ArgoCD | 持续交付 |
| 可观测性 | Prometheus + Grafana + Jaeger | 指标 + tracing + 告警 |
| 日志 | Loki + Grafana | 内部运维日志 |
| 消息队列 | Kafka + Redis Streams | 主事件总线 + 轻量内部消息 |
| 数据库 | PostgreSQL | 元数据（资产、策略、用户、事件元数据） |
| 缓存 | Redis Cluster | 会话、热点 IOC、Agent 状态 |

## 附录 C：与 CrowdStrike Falcon 的能力映射

| CrowdStrike Falcon 能力 | Aegis 对应能力 |
|----------------------------|------------------|
| Lightweight Agent（single kernel driver） | Rust 用户态 + 最小内核驱动，<= 150MB memory |
| Threat Graph（cloud graph DB） | Correlation Engine + Kill Chain Tracker + 图分析 |
| CrowdStrike AI / Charlotte AI | ML Inference Service（多模型矩阵）+ LLM 脚本分析 |
| Falcon OverWatch（managed hunting） | Hunting Service + Notebook + Hypothesis Library |
| Real Time Response（RTR） | Response Orchestrator + Remote Shell（双人审批） |
| Falcon Insight XDR | 开放集成（SIEM/SOAR/Cloud/Identity） |
| Falcon Discover（asset discovery） | Asset Management + 被动网络发现 |
| IOA（Indicators of Attack） | 行为序列检测（Flink CEP + ML Behavioral Model） |
| FileVantage（FIM） | File Sensor（Minifilter/fanotify）全量文件监控 |
| Identity Protection | Auth Sensor + AD/LDAP + Kerberos 异常检测 |
| Cloud Workload Protection | Container Sensor（eBPF + K8s integration） |
| Falcon Sandbox | 可扩展集成：Cuckoo/CAPE sandbox service |

---
