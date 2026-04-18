# Aegis Transport Plane 架构设计文档

> 版本：1.0  
> 日期：2026-04-18  
> 状态：草稿  
> 分类：内部 / 机密  
> 依赖文档：aegis-architecture-design.md、aegis-sensor-architecture.md、总技术解决方案.md

---

## 目录

1. [概述与定位](#1-概述与定位)
2. [设计原则与约束](#2-设计原则与约束)
3. [总体架构](#3-总体架构)
4. [模块详细设计](#4-模块详细设计)
   - 4.1 L4 负载均衡器
   - 4.2 Ingestion Gateway
   - 4.3 事件富化流水线
   - 4.4 Kafka Event Bus
   - 4.5 命令路由（下行通道）
   - 4.6 速率限制与准入控制
   - 4.7 连接管理
   - 4.8 Fallback Transport 子系统
5. [数据流设计](#5-数据流设计)
   - 5.1 上行数据流
   - 5.2 下行数据流
   - 5.3 Heartbeat 处理
6. [性能设计](#6-性能设计)
   - 6.1 热路径延迟预算
   - 6.2 吞吐计算
   - 6.3 关键优化策略
   - 6.4 关键性能基准表
7. [背压与流控设计](#7-背压与流控设计)
8. [韧性与容错设计](#8-韧性与容错设计)
9. [安全设计](#9-安全设计)
   - 9.1 信任边界
   - 9.2 mTLS 证书处理
   - 9.3 多租户隔离
   - 9.4 STRIDE 威胁模型
   - 9.5 DDoS 防护
   - 9.6 审计
10. [部署与运维](#10-部署与运维)
    - 10.1 K8s 部署拓扑
    - 10.2 扩缩容策略
    - 10.3 灰度发布
    - 10.4 容量规划
11. [可观测性](#11-可观测性)
    - 11.1 指标
    - 11.2 分布式追踪
    - 11.3 日志
    - 11.4 SLO 与告警
12. [接口定义](#12-接口定义)
    - 12.1 Agent 与 Gateway 接口
    - 12.2 Gateway 与 Kafka 接口
    - 12.3 内部管理接口
13. [技术选型说明](#13-技术选型说明)

---

<a id="1-概述与定位"></a>
## 1. 概述与定位

### 1.1 产品定位

Aegis Transport Plane（传输平面）是 Aegis EDR 平台五平面架构中的接入网关层，位于 Endpoint Plane（终端平面）与 Data/Analytics Plane（数据/分析平面）之间，承担全部终端遥测数据的安全接入、初步富化与可靠投递职责。作为平台的"咽喉"，Transport Plane 是 100 万终端与云端之间的唯一入口，每秒处理 830 万事件，在确保零信任安全的同时维持亚毫秒级处理延迟。

在整个平台架构中，Transport Plane 同时扮演三个角色：

- **安全边界**：作为 Untrusted（终端）与 Trusted（K8s 内部集群）之间的 Semi-Trusted 区域，负责全部 mTLS 认证、租户身份提取和协议验证
- **数据管道**：将来自终端的原始遥测事件经解压、校验、富化后投递至 Kafka Event Bus，供下游流处理和存储消费
- **命令通道**：反向承载从 Management Plane 发出的响应指令、策略更新和威胁情报推送，经 Kafka 消费后通过 gRPC 双向流下发至目标 Agent

### 1.2 核心职责

| 职责域 | 具体能力 |
|--------|----------|
| **安全接入** | mTLS 双向认证、TLS 1.3 加密传输、Agent 证书校验、CRL/OCSP 吊销检查、Tenant ID 从证书 SAN 提取 |
| **协议处理** | gRPC 双向流管理（EventStream/Heartbeat/UploadArtifact/PullUpdate）、HTTP/2 多路复用、LZ4 流式解压、Protobuf Schema 校验 |
| **事件富化** | GeoIP 查询（MaxMind，内存驻留）、资产标签附加（Redis cache）、租户元数据注入、MITRE ATT&CK TTP 预标签、lineage_id 检查点 |
| **可靠投递** | 按 Tenant + EventType 路由到 Kafka 分区、按数据关键性差异化 acks 策略、端到端有序性保证 |
| **命令下发** | 消费 Kafka commands.unicast / commands.broadcast topic，通过 Connection Registry 按 Agent ID 定位 owner pod（本地或跨 pod 转发）投递到 gRPC stream，SignedServerCommand 签名全程透传 |
| **流量治理** | 按 Agent 和按租户的多层限速、Token Bucket 准入控制、背压传导（gRPC → Kafka → Agent WAL） |
| **Heartbeat 汇聚** | Agent 健康信息接收与聚合、在线状态管理、离线检测与告警 |

### 1.3 规模与对标

- **终端规模**：支持 100 万终端同时在线连接
- **集群事件速率**：~8.3M events/sec
- **日事件量**：>= 500 亿事件/天
- **日原始数据量**：~50 TB/day（压缩前）
- **Gateway 实例数**：90 实例稳态（3 AZ × 30 pods），最高 150 实例（HPA 上限）；每 pod 稳态 12,000 gRPC 连接，硬上限 16,000
- **对标产品**：CrowdStrike Falcon ThreatGrid Ingestion Layer、Microsoft Defender Gateway、SentinelOne Cloud Funnel

### 1.4 文档范围

本文档聚焦于 Aegis Transport Plane 自身的架构设计，包含 L4 负载均衡、Ingestion Gateway 服务、事件富化流水线、Kafka Event Bus 集成、命令路由通道、流量治理、连接管理以及相关的安全、部署和可观测性设计。

终端平面（Agent）的通信模块设计请参考 `aegis-sensor-architecture.md` 第 4.5 节；分析平面、数据平面和管理平面的架构请参考 `aegis-architecture-design.md`。

---

<a id="2-设计原则与约束"></a>
## 2. 设计原则与约束

### 2.1 核心设计原则

| 原则 | 说明 | 落地约束 |
|------|------|----------|
| **无状态设计** | Gateway 不保存任何会话状态，全部上下文来自 mTLS 证书和事件 payload；任意 pod 可处理任意 Agent 连接 | 禁止在 Gateway 进程内维护跨请求的会话状态 |
| **零信任** | 每个连接都验证 mTLS 证书；Tenant ID 仅从证书 SAN 提取，不信任 payload 自报字段；Gateway 自身是 Semi-Trusted，无法伪造下行命令签名 | 代码评审 + 安全评审闸门 |
| **背压感知** | Gateway 必须参与端到端背压链（ClickHouse → Flink → Kafka → Gateway → Agent WAL），不得在任何环节静默丢弃数据 | gRPC flow control + Kafka producer backoff |
| **多租户隔离** | 租户身份全链路透传；raw-events 按租户独立 Kafka topic；共享 topic 使用 tenant_id 作为 partition key | 租户边界在 Gateway 层强制注入 |
| **可观测性优先** | 全部关键路径暴露 Prometheus 指标；每个事件 batch 携带 lineage_id 用于分布式追踪；结构化 JSON 日志 | lineage 检查点计数器 |
| **水平弹性** | Gateway 完全无状态，支持 HPA 快速扩缩；Kafka 按 AZ 均匀分布 broker | K8s HPA + Pod Anti-Affinity |
| **不可变性** | 事件在流水线中每一步都生成新对象，不对上游传入的 payload 做原地修改 | Go 值语义 + 代码评审 |
| **优雅降级（功能层）** | 下游辅助组件故障时降级而非拒绝：Redis 不可用时跳过 Asset Tag 富化（事件仍入 Kafka，标记 enrichment_degraded=true）；Connection Registry 不可用时命令进入 pending 队列；这些降级**不丢数据** | 熔断器 + 降级标记 |
| **严格不丢弃（数据层）** | Gateway 对上行 EventBatch 采用 all-or-nothing 契约：要么 ACCEPTED 且已落 Kafka，要么整批 NACK 让 Agent 在 WAL 中保留重传。禁止 Gateway 侧按优先级选择性丢弃事件（见 4.6.2.1） | BatchAck 协议 + gRPC flow control |

### 2.2 质量属性目标

| 类别 | 指标 | 目标 |
|------|------|------|
| **可用性** | 数据接入可用性 | >= 99.99% |
| **可用性** | 单 AZ 故障容忍 | 不影响服务 |
| **延迟** | Gateway 单 batch 处理延迟 | <= 8ms（含 mTLS verify + 解压 + 校验 + 富化 + Kafka produce） |
| **延迟** | 端到端 ingestion-to-queryable | ~130ms（Gateway → Kafka → Flink → ClickHouse） |
| **吞吐** | 集群事件速率 | ~8.3M events/sec |
| **吞吐** | Kafka 写入吞吐 | ~10 GB/s（含 3x 副本） |
| **连接** | 单 pod 设计连接数 | 16,000 gRPC 连接（稳态目标，HPA target 12,000 留 25% 余量；硬上限 20,000） |
| **连接** | 单 pod 资源 profile | 8 vCPU / 16 GB RAM / 1 Gbps NIC |
| **连接** | 集群最大连接数 | 100 万+ 并发连接 |
| **连接** | AZ 故障容忍 | 单 AZ 失效后剩余 pods 必须 < 85% 利用率（设计点：稳态 67% 利用率）|
| **数据完整性** | CRITICAL 事件丢失率 | 0% |
| **数据完整性** | 全局事件丢失率 | < 0.001% |
| **安全** | mTLS 覆盖率 | 100%（Agent ↔ Gateway） |
| **安全** | 未授权连接拒绝率 | 100% |

### 2.3 设计约束

1. **语言约束**：Ingestion Gateway 使用 Go 实现（高并发 goroutine 模型 + 成熟 gRPC 生态 + 快速编译部署）
2. **协议约束**：Agent ↔ Gateway 主通道为 gRPC over TLS 1.3 with mTLS；当 HTTP/2 被中间设备阻断时，Gateway 必须提供第 4.8 节定义的 **Fallback Transport 子系统**（WebSocket / Long-Polling / Domain Fronting），保持与主通道等价的上行 ACK / 下行命令 / 背压 / 租户隔离语义
3. **序列化约束**：全链路使用 Protobuf；事件压缩采用 LZ4（Agent 侧压缩，Gateway 侧解压）
4. **证书约束**：Agent 证书有效期 90 天，CN=agent_id，SAN=tenant_id，由 Vault 管理的 Intermediate CA 签发
5. **部署约束**：运行于 Kubernetes 集群，跨 3 AZ 部署；每 AZ 至少 30 pods（稳态），以支持 100 万连接目标并满足单 AZ 失效后剩余容量不过载的硬约束
6. **兼容性约束**：必须支持 `aegis-sensor-architecture.md` 第 4.5.5 节定义的全部 gRPC 服务接口和 SignedServerCommand 协议

---

<a id="3-总体架构"></a>
## 3. 总体架构

### 3.1 架构概览

```
                      100万 Agent Connections
                              |
                   +----------v----------+
                   |   L4 Load Balancer  |  Envoy / HAProxy (TCP/gRPC-aware)
                   |   (TLS passthrough  |  跨 3 AZ 分发
                   |    or termination)  |  健康检查 + DDoS 防护
                   +----+-----+-----+---+
                        |     |     |
              +---------+     |     +----------+
              |               |                |
        +-----v-----+  +-----v-----+    +-----v-----+
        |  AZ-a     |  |  AZ-b     |    |  AZ-c     |
        |  Gateway  |  |  Gateway  |    |  Gateway  |
        |  pods x30 |  |  pods x30 |    |  pods x30 |
        +-----+-----+  +-----+-----+    +-----+-----+
              |               |                |
              +-------+-------+--------+-------+
                      |                |
              +-------v-------+ +------v-------+
              |   Kafka       | |   Redis      |
              |   Cluster     | |   Cluster    |
              |  (15 brokers  | | (Asset cache |
              |   3 AZ)       | |  6 nodes)    |
              +---------------+ +--------------+
```

### 3.2 Transport Plane 在五平面中的位置

```
+------------------------------------------------------------------------+
|                          Management Plane                                |
|  +------------+  +------------+  +-------------+  +----------------+   |
|  | Web Console|  | REST/GQL   |  | RBAC / SSO  |  | Response       |   |
|  | (React+TS) |  | API Gateway|  | (OIDC/SAML) |  | Orchestrator   |   |
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
|  >>>>>>>>>>>>>>>>>> Transport Plane (本文档) <<<<<<<<<<<<<<<<<<<<<<<<   |
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
|  |  Comms Module: gRPC 3-stream + WAL + QoS + Fallback Chain     |     |
|  +---------------------------------------------------------------+     |
+------------------------------------------------------------------------+
```

### 3.3 Gateway Pod 内部架构

每个 Ingestion Gateway pod 是一个无状态 Go 进程，内部由以下协程组划分职责：

```
┌──────────────────────────────────────────────────────────────────┐
│  Ingestion Gateway Pod (Go, 8 vCPU, 16GB memory, 1Gbps NIC)     │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  gRPC Server (goroutine-per-stream)                      │   │
│  │  ├── EventStream handler pool     (goroutine per Agent)  │   │
│  │  ├── Heartbeat handler pool       (goroutine per call)   │   │
│  │  ├── UploadArtifact handler pool  (goroutine per upload) │   │
│  │  ├── PullUpdate handler pool      (goroutine per pull)   │   │
│  │  └── Command delivery goroutines  (per active stream)    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌─────────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  mTLS Verifier  │  │  Rate Limiter│  │  Connection      │   │
│  │  + CRL/OCSP     │  │  (per-agent  │  │  Manager         │   │
│  │  + Tenant ID    │  │   per-tenant)│  │  (lifecycle,     │   │
│  │    Extractor    │  │              │  │   drain, health) │   │
│  └─────────────────┘  └──────────────┘  └──────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Enrichment Pipeline (per-event-batch, goroutine pool)   │   │
│  │  ① LZ4 Decompress                                       │   │
│  │  ② Protobuf Schema Validate                              │   │
│  │  ③ GeoIP Lookup (MaxMind, mmap)                          │   │
│  │  ④ Asset Tag Lookup (Redis cache)                        │   │
│  │  ⑤ Tenant Metadata Injection                             │   │
│  │  ⑥ MITRE ATT&CK TTP Pre-label                           │   │
│  │  ⑦ lineage_id Checkpoint (gateway_received)              │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Kafka Producer Pool（统一 acks=all + idempotence + ISR=2）│   │
│  │  ├── High-priority producer  (linger.ms=0, max.in.flight=1) │
│  │  ├── Normal producer         (linger.ms=5, batch.size=64KB) │
│  │  └── Bulk producer           (linger.ms=10, batch.size=128KB)│
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Command Consumer                                         │   │
│  │  ├── Unicast consumer  (commands.unicast, shared group)  │   │
│  │  ├── Broadcast consumer(commands.broadcast, per-pod grp) │   │
│  │  ├── Pending dispatcher(commands.pending, 重试循环)       │   │
│  │  ├── Connection Registry client (Redis)                   │   │
│  │  └── Inter-Pod Forwarder (GatewayInternal gRPC, :9443)   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌─────────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  Health Check   │  │  Prometheus  │  │  Admin API       │   │
│  │  (/healthz,     │  │  /metrics    │  │  (config reload, │   │
│  │   /readyz)      │  │  exporter    │  │   diagnostic)    │   │
│  └─────────────────┘  └──────────────┘  └──────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

### 3.4 数据流总览

```
上行路径 (Agent → Cloud):

Agent                    Gateway                          Kafka
  |                        |                                |
  |-- EventBatch --------->|                                |
  |   (gRPC stream,        |-- ① mTLS verify               |
  |    LZ4 compressed,     |-- ② LZ4 decompress            |
  |    Protobuf)           |-- ③ Protobuf validate          |
  |                        |-- ④ Enrich (GeoIP/Asset/TTP)   |
  |                        |-- ⑤ lineage checkpoint         |
  |                        |-- ⑥ Route to topic/partition ->|
  |                        |                                |
  |<- ACK (implicit) -----|                                |

下行路径 (Cloud → Agent):

Management               Kafka                    Gateway                      Agent
  |                        |                        |                             |
  |-- ServerCommand ------>|                        |                             |
  |  commands.unicast /    |-- consume ------------>|                             |
  |  commands.broadcast    |                        |-- Registry lookup           |
  |                        |                        |   owner_pod == self?        |
  |                        |                        |   yes: local gRPC send ---->|
  |                        |                        |   no : Inter-Pod forward    |
  |                        |                        |         (gRPC :9443) ------>|
```

---

<a id="4-模块详细设计"></a>
## 4. 模块详细设计

### 4.1 L4 负载均衡器

#### 4.1.1 架构定位

L4 Load Balancer 是 Agent 连接到达云端的第一跳，负责 TCP 层的流量分发、可选的 TLS 终止以及基础 DDoS 防护。

#### 4.1.2 部署选型

| 选项 | 优势 | 劣势 | 推荐场景 |
|------|------|------|----------|
| **Envoy (推荐)** | gRPC-aware L7 能力、xDS 动态配置、与 Istio service mesh 无缝集成、丰富的可观测性 | 内存占用高于 HAProxy | 首选方案 |
| **HAProxy** | 极高性能 TCP 代理、低内存占用、长期生产验证 | gRPC 支持需额外配置、与 service mesh 集成弱 | 纯 L4 模式或极端性能需求 |
| **Cloud LB** | 托管服务、内建 DDoS 防护、自动扩容 | 厂商锁定、gRPC 支持取决于厂商 | 公有云部署 |

#### 4.1.3 TLS 终止策略

两种模式可选，根据安全与性能需求决策：

**模式 A：TLS Passthrough（推荐）**
- LB 不终止 TLS，直接透传加密流量到 Gateway pod
- Gateway 自行执行 mTLS 握手和证书校验
- 优势：LB 无需访问私钥，攻击面更小；证书校验逻辑完全由 Gateway 控制
- 劣势：LB 无法做 L7 路由

**模式 B：TLS Termination at LB**
- LB 终止 TLS 后以 plaintext 或 re-encrypt 转发到 Gateway
- 优势：LB 可做 L7 智能路由、连接复用
- 劣势：LB 需持有服务端私钥；Agent 证书信息需通过 header 传递（增加伪造风险）

#### 4.1.4 会话亲和性

- 默认关闭（Gateway 无状态，任意 pod 可处理任意连接）
- 可选按 source IP hash 开启弱亲和，减少 Agent 重连时的 TLS 握手开销
- gRPC 长连接天然保持亲和（连接建立后流量固定在同一 pod）

#### 4.1.5 健康检查

| 类型 | 端点 | 间隔 | 超时 | 不健康阈值 |
|------|------|------|------|-----------|
| TCP | port 8443 | 5s | 3s | 3 次失败 |
| gRPC | /grpc.health.v1.Health/Check | 10s | 5s | 2 次失败 |
| HTTP | /healthz | 10s | 5s | 2 次失败 |

#### 4.1.6 DDoS 防护（LB 层）

| 威胁 | 防护措施 |
|------|----------|
| SYN Flood | SYN cookies 启用；半连接队列限制 |
| 连接耗尽 | 单 IP 最大连接数限制（默认 100） |
| 无效 TLS | TLS 握手超时 5s；握手失败后立即关闭 |
| 流量放大 | 出站限速防止反射攻击 |

---

### 4.2 Ingestion Gateway

#### 4.2.1 服务定位

Ingestion Gateway 是 Transport Plane 的核心服务，以无状态 Go 进程形式运行。每个 Gateway pod 处理数千个并发 gRPC 连接，执行安全校验、数据解压、Schema 验证、事件富化和 Kafka 投递。

#### 4.2.2 gRPC 服务端点

Gateway 实现以下 gRPC 服务（wire-level 单一事实源为本文档 §12.1.1-12.1.3，Sensor / 总体架构文档一致落地）：

```protobuf
service AgentService {
  // 上行 UplinkMessage oneof = EventBatch / ClientAck / FlowControlHint
  // 下行 DownlinkMessage oneof = SignedServerCommand / BatchAck / FlowControlHint
  rpc EventStream(stream UplinkMessage) returns (stream DownlinkMessage);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
  rpc UploadArtifact(stream ArtifactChunk) returns (UploadResult);
  rpc PullUpdate(UpdateRequest) returns (stream UpdateChunk);
}
// 所有下行命令仍以 SignedServerCommand 作为 DownlinkMessage.command 字段承载；
// 广播/组播命令的投递作用域 TargetScope 纳入签名覆盖，Kafka header 仅作缓存/预过滤提示，不作授权依据（见 §12.1.3）。
```

| 端点 | 模式 | 用途 | 并发模型 |
|------|------|------|----------|
| EventStream | 双向流 | 遥测上行 + 命令下行 | 每 Agent 一个长活 goroutine |
| Heartbeat | Unary RPC | Agent 健康上报 | goroutine-per-call |
| UploadArtifact | Client streaming | 取证包 / 内存 dump 上传 | goroutine-per-upload |
| PullUpdate | Server streaming | 规则 / 模型 / 安装包下载 | goroutine-per-pull |

#### 4.2.3 mTLS 验证流程

```
Agent TLS ClientHello
        |
        v
+-------+--------+
| TLS 1.3 握手   |
| (session reuse  |  ~0.5ms (session resumption)
|  优先)          |  ~2ms (full handshake)
+-------+--------+
        |
        v
+-------+--------+
| 证书链校验      |
| Root CA →       |
| Intermediate CA |
| → Agent Cert    |
+-------+--------+
        |
        v
+-------+--------+
| CRL/OCSP 检查   |  本地缓存 CRL（云端定期推送至 Gateway）
| - CRL 本地缓存  |  OCSP stapling 优先
| - OCSP stapling |
+-------+--------+
        |
        v
+-------+--------+
| 提取身份信息     |
| CN → agent_id   |
| SAN → tenant_id |
+-------+--------+
        |
        v
+-------+--------+
| 注入请求上下文   |
| ctx.agent_id    |
| ctx.tenant_id   |
+--------+-------+
         |
    认证通过 / 拒绝
```

**关键安全决策**：Tenant ID 必须从证书 SAN 提取，绝对不信任 Agent payload 中自报的 tenant_id。这确保即使 Agent 被攻破，攻击者也无法冒充其他租户。

#### 4.2.4 事件处理流水线

每收到一个 EventBatch，Gateway 依次执行以下步骤：

```
EventBatch (gRPC stream)
    |
    v
① mTLS 已验证 (连接建立时完成, ctx 中携带 agent_id + tenant_id)
    |
    v
② LZ4 解压                         ~0.2ms / batch
    |
    v
③ Protobuf Schema 验证              ~0.1ms / batch
   - 必填字段校验
   - 枚举值范围校验
   - event_type 合法性校验
   - 事件数量上限校验 (max 500/batch)
    |
    v
④ 事件富化 (见 4.3 节详细设计)       ~0.3ms / batch
   - GeoIP lookup
   - Asset Tag lookup
   - Tenant metadata injection
   - MITRE ATT&CK TTP pre-label
    |
    v
⑤ lineage_id 检查点                 ~0.01ms
   checkpoint 7: gateway_received
    |
    v
⑥ Kafka Produce                     ~2ms / batch
   - 按 tenant + event_type 路由到对应 topic/partition
   - 全部 Producer 统一 acks=all + enable.idempotence=true + min.insync.replicas=2
   - 延迟/吞吐差异仅靠 linger.ms/batch.size 调节，不退化为 acks=1
     （ACCEPTED ⇒ ISR 同步完成，详见 §4.2.5 持久化不妥协与 §4.4.3 BatchAck 契约）
    |
    v
⑦ gRPC 隐式 ACK (flow control)
```

**批次处理规则**：
- Agent 侧将事件打包为 EventBatch（100-500 事件/batch，最长 1s 窗口）
- High-Priority 通道事件独立 stream，零延迟发送
- Bulk Upload（取证包等）通过独立 UploadArtifact RPC 处理

#### 4.2.5 三路流映射

Gateway 对应 Agent 的三路 gRPC 通道分别处理：

| Agent 通道 | Gateway 处理 | Kafka 路由 | acks 策略 | 差异化配置 |
|-----------|-------------|-----------|----------|-----------|
| A: High-Priority | 立即处理，独立 goroutine | raw-events.{tenant}（CRITICAL partition key） | **acks=all** + idempotence | linger.ms=0 / max.in.flight=1（延迟最小） |
| B: Normal Telemetry | 批量处理，共享 goroutine pool | raw-events.{tenant}（agent_id hash） | **acks=all** + idempotence | linger.ms=5 / batch.size=64KB（吞吐优先） |
| C: Bulk Upload | 分块接收，存储到 S3/MinIO | artifact-uploads（tenant/agent/artifact_id） | **acks=all** + idempotence | linger.ms=10 / batch.size=128KB |

> **持久化不妥协**：三路通道的差异仅在 linger/batch/in-flight（延迟 vs 吞吐），**acks 一律为 all**。本表不保留 `acks=1` 变体——这是为了避免与 §4.4.3 / §4.6.2.1 "ACCEPTED ⇒ ISR 同步完成" 契约冲突。当前版本无弱持久化快速路径；若未来引入，必须同步增设独立的 `ACCEPTED_NONDURABLE` ACK 状态（见 §12.1.5）以及 Agent 不推进 sequence_id 的配套行为。

---

### 4.3 事件富化流水线

#### 4.3.1 富化步骤

Gateway 内部的事件富化流水线对每个 EventBatch 执行以下操作：

**Step 1：GeoIP Lookup**

| 项目 | 规格 |
|------|------|
| 数据源 | MaxMind GeoLite2-City / GeoIP2-Enterprise |
| 加载方式 | mmap 内存映射，进程启动时加载 |
| 数据库大小 | ~70MB（GeoLite2-City） |
| 更新频率 | 每周自动更新（MaxMind 发布节奏） |
| 查询延迟 | < 1us / lookup |
| 适用事件 | 含 src_ip / dst_ip 的 network 类事件 |
| 输出字段 | enrichment.geo: { country, city, latitude, longitude, asn, org } |
| 降级处理 | 查询失败时标记 geo: null，不阻塞流水线 |

**Step 2：Asset Tag Lookup**

| 项目 | 规格 |
|------|------|
| 数据源 | Asset Management Service（PostgreSQL） |
| 缓存层 | Redis Cluster（6 节点跨 3 AZ） |
| 缓存键 | agent_id → { asset_group, criticality, tags[], location } |
| 缓存 TTL | 300s（5 分钟），支持主动失效 |
| 查询延迟 | < 0.1ms（Redis hit）/ < 5ms（Redis miss → PostgreSQL） |
| 降级处理 | Redis 不可用时跳过 Asset Tag 富化，事件标记 enrichment_partial: true |

**Step 3：Tenant Metadata Injection**

从 mTLS 证书中提取的 tenant_id 强制注入到每个事件的 tenant_id 字段，覆盖 payload 中的任何自报值。同时注入：
- 租户级配置元数据（如保留策略标识、数据分级标签）
- Gateway pod 标识（用于追踪和审计）
- 接收时间戳（gateway_received_at）

**Step 4：MITRE ATT&CK TTP Pre-label**

| 项目 | 规格 |
|------|------|
| 规则来源 | 预编译的启发式规则集（Gateway 内嵌） |
| 匹配逻辑 | 基于 event_type + 关键字段的快速匹配 |
| 准确度定位 | 初步标签，仅供下游分析平面加速处理；不作为最终检测结论 |
| 示例 | PROCESS_CREATE + cmdline 含 "powershell -enc" → 预标记 T1059.001 |
| 输出字段 | enrichment.mitre_ttps: ["T1059.001"] |
| 覆盖率 | 针对高置信度模式，覆盖约 30% 的事件；其余由分析平面补充 |

**Step 5：lineage_id Checkpoint**

将 lineage_id 的第 7 个检查点（gateway_received）写入事件元数据，用于端到端事件追踪。lineage_id 编码结构：agent_id[64bit] | timestamp_ns[48bit] | sequence[16bit]，在全链路中保持不变，每个处理节点仅追加检查点计数。

#### 4.3.2 富化流水线性能

| 步骤 | 延迟 | 可失败 | 降级行为 |
|------|------|--------|----------|
| GeoIP Lookup | < 1us | 是 | 标记 geo: null |
| Asset Tag Lookup | < 0.1ms | 是 | 标记 enrichment_partial: true |
| Tenant Metadata | < 1us | 否 | 强制步骤，不可跳过 |
| MITRE TTP Pre-label | < 0.05ms | 是 | 标记 ttps: [] |
| lineage_id Checkpoint | < 1us | 否 | 强制步骤 |
| **总计** | **~0.3ms** | | |

---

### 4.4 Kafka Event Bus

#### 4.4.1 Topic 设计

| Topic | 分区策略 | 分区数 | 保留期 | 副本数 | 用途 |
|-------|---------|--------|--------|--------|------|
| `raw-events.{tenant}` | Agent ID hash | 128 | 72h | 3 | 原始遥测数据入口，按租户独立 topic |
| `enriched-events` | Event Type | 128 | 72h | 3 | 富化后事件，供 Flink 流处理消费 |
| `detections` | Severity | 64 | 30d | 3 | 已确认检测告警 |
| `commands.unicast` | Agent ID | 128 | 24h | 3 | agent-scoped 下行命令；Gateway 通过 Connection Registry 定位 owner pod 投递（见 4.5.4） |
| `commands.broadcast` | Round-robin | 32 | 24h | 3 | 租户/全局作用域下行命令；每个 Gateway pod 用独立 consumer group 消费全部副本（见 4.5.6） |
| `commands.pending` | Agent ID | 64 | 7d（`compact,delete`）| 3 | 未投递命令补投；log-compact + 删除策略共用，key = `tenant:agent:command_id`；写入由 4.5.4 Kafka 事务原子保证（见 4.5.7） |
| `commands.dead-letter` | Agent ID | 16 | 30d | 3 | TTL 过期或多次失败的命令归档，审计 + 告警 |
| `audit-log` | Tenant ID | 64 | 365d | 3 | 操作审计轨迹 |

**分区策略详解**：

- **raw-events.{tenant}**：按 agent_id hash 分区，保证同一 Agent 的事件有序到达同一分区，支持下游按 Agent 的状态关联
- **enriched-events**：按 event_type 分区，优化下游按事件类型的消费模式（如进程事件流、网络事件流分别消费）
- **detections**：按 severity 分区，允许下游优先消费高严重度告警
- **commands.unicast**：按 agent_id 分区；消费组 `gateway-unicast`（shared），Gateway 侧通过 Connection Registry 做 owner 归属判定 + Inter-Pod 转发
- **commands.broadcast**：round-robin 分区（或按 scope hash）；每 pod 一个独立 consumer group `gateway-bcast-{pod_uid}`，所有 pods 都收到完整副本

#### 4.4.2 集群规模（100 万终端）

```
集群拓扑:
├── 15+ brokers (3 AZ × 5 brokers/AZ)
├── 3 ZooKeeper nodes (1 per AZ)
├── Replication Factor: 3 (跨 AZ)
├── min.insync.replicas: 2
└── 每 topic 分区数: 64-256 (按 topic 调优)

容量计算:
kafka_brokers = ceil(total_write_throughput / per_broker_capacity)
             = ceil(10 GB/s / 800 MB/s)
             = 13 → 15 (向上取整至 5 per AZ)

kafka_storage_per_broker = daily_data × retention_days × replication_factor / broker_count
                        = 5 TB/day × 3 days × 3 / 15
                        = 3 TB per broker

kafka_partitions_per_topic = max(consumer_parallelism, throughput / per_partition_throughput)
                          = max(128, 8.3M/s / 100K/s)
                          = 128
```

#### 4.4.3 Producer 配置

Gateway 内部维护多个 Kafka Producer，按数据关键性差异化配置**延迟与吞吐**，但**持久性一律不妥协**——所有面向 Agent 返回 `BatchAck.ACCEPTED` 的 Producer 必须使用 `acks=all` 且启用幂等 Producer。这是 4.6.2.1 严格不丢弃契约的前提：若 leader 已确认但 ISR 未同步完成就返回 ACCEPTED，leader 故障将使 Agent 永久丢失该批次（sequence_id 已前进、WAL 已清理）。

| Producer | 对应数据 | acks | enable.idempotence | compression | linger.ms | batch.size | buffer.memory | max.in.flight |
|----------|---------|------|--------------------|-------------|-----------|------------|---------------|---------------|
| High-Priority | CRITICAL/HIGH 告警、响应结果 | **all** | true | lz4 | 0 | 16KB | 64MB | 1 |
| Normal | 常规遥测事件 | **all** | true | lz4 | 5 | 64KB | 512MB | 5 |
| Bulk | 大文件元数据、审计日志 | **all** | true | lz4 | 10 | 128KB | 256MB | 5 |

**关键参数说明**：
- **所有 Producer 均使用 `acks=all` + `enable.idempotence=true` + `min.insync.replicas=2`**，确保 ISR 同步后才确认；这是 Agent 侧在 `ACCEPTED` 后推进 sequence_id 的正确性前提。`max.in.flight <= 5` 搭配 idempotent producer 仍可保持分区内有序
- 三类 Producer 的差异点**仅在延迟-吞吐**：`linger.ms` / `batch.size` / `buffer.memory` 不同。High-Priority 牺牲 throughput 换 latency（linger=0），Normal/Bulk 走批量
- Buffer 上调至 512MB/256MB 以吸收 `acks=all` 带来的单 produce 延迟增加（典型 P50 从 2ms 升至 4-5ms）；若 buffer 打满将触发 `REJECTED_BACKPRESSURE`（见 12.1.5），Agent 在 WAL 侧重试
- **禁止**存在 "`ACCEPTED` 但未 ISR 同步" 的中间状态。如果未来需要弱持久化通道（如 debug trace），必须定义独立的 `BatchAck.Status.ACCEPTED_NONDURABLE` 并明确 Agent 在该状态下**不得**推进 sequence_id；当前版本不启用此模式
- Kafka producer 侧统一使用 LZ4 压缩，与 Agent 侧压缩算法保持一致

#### 4.4.4 数据复制与持久性

| 参数 | 设置 | 说明 |
|------|------|------|
| replication.factor | 3 | 每个 partition 3 个副本，跨 3 AZ |
| min.insync.replicas | 2 | 至少 2 个副本同步后才确认写入 |
| unclean.leader.election.enable | false | 禁止非同步副本当选 leader，防止数据丢失 |
| log.flush.interval.messages | 10000 | 每 10000 条消息强制刷盘 |

**故障容忍**：
- 单 broker 故障：自动 leader election，< 30s RPO=0
- 单 AZ 故障：剩余 2 AZ 的副本满足 min.insync.replicas=2，服务不中断
- 双 AZ 故障：不可用（设计上限为容忍 1 AZ 故障）

---

### 4.5 命令路由（下行通道）

#### 4.5.1 设计目标与下行投递的架构约束

下行命令（RESPONSE_ACTION / POLICY_UPDATE / RULE_UPDATE / IOC_UPDATE / REMOTE_SHELL …）必须满足：

| 约束 | 说明 |
|------|------|
| **确定性投递**（Unicast） | 每条 agent-scoped 命令必须且只能被目标 Agent 所在的那个 pod 投递，不能依赖 "广播 + 忽略" 这类概率式模型 |
| **广播一致性**（Broadcast） | 策略/IOC 全量/增量更新必须被**所有**持有相关连接的 pod 消费到，不得在共享消费组里被单个 pod 独占 |
| **不丢失** | 投递失败（agent 离线、pod 失败、ttl 过期）必须记录并进入补投流程；不得静默吞没 |
| **有序 per agent** | 同一 agent 的命令按 `sequence_hint` 保持相对顺序 |
| **零信任透传** | Gateway 不解析 payload、不校验签名、不修改 SignedServerCommand |

> **注（与旧版设计的差异）**：早期草案曾提出 "所有 pod 加入同一个 consumer group，仅持有目标连接的 pod 投递，其余静默忽略"。**该模型不可行**——Kafka shared consumer group 对每条记录仅交付给组内一个消费者，不是广播；这会导致投递到 "没有该连接" 的 pod 时静默丢失命令。下行通道采用下述 **所有权模型（Ownership Model）** + **Connection Registry 跨 pod 转发**，确保 unicast 命令的确定性投递。

#### 4.5.2 下行通道架构

```
Management Plane              Kafka                        Gateway Pods                   Agent
┌──────────────┐        ┌────────────────────┐      ┌────────────────────────┐      ┌──────────┐
│ Response     │────►   │ commands.unicast   │─────►│ Unicast Consumer       │      │          │
│ Orchestrator │        │ (partition by      │      │ (shared group)         │      │          │
│              │        │  agent_id)         │      │        │               │      │          │
│              │        └────────────────────┘      │        ▼               │      │          │
│              │                                    │ Connection Registry    │      │          │
│ Policy       │        ┌────────────────────┐      │ (Redis: agent_id →     │      │  comms-rx│
│ Engine       │────►   │ commands.broadcast │──┐   │  {owner_pod, epoch})   │      │  thread  │
│              │        │ (replicated to     │  │   │        │               │      │          │
│              │        │  per-pod groups)   │  │   │        ▼               │      │          │
│ Threat Intel │        └────────────────────┘  │   │ ┌──── Local? ────┐     │      │  验签    │
│ Service      │────►                           │   │ │ yes │    no    │     │      │  + 校验  │
│              │                                │   │ ▼     ▼          │     │      │  + 执行  │
│              │                                │   │ gRPC  Inter-Pod  │     │      │          │
│              │                                │   │ stream Forward   │     ├─────►│          │
│              │                                │   │ (server→client) (gRPC) │      │          │
│              │                                │   └────────────────────────┘      │          │
│              │                                └──► 每个 Gateway pod 独立          │          │
│              │                                    consumer group，收到全部 copy   │          │
└──────────────┘                                                                     └──────────┘
```

#### 4.5.3 连接所有权模型（Connection Ownership）

**连接登记协议（Connection Registry）**：

| 字段 | 存储 | 说明 |
|------|------|------|
| key | `conn:{agent_id}` | Redis Hash |
| owner_pod | string | 当前持有连接的 Gateway pod 的稳定 ID（pod_uid） |
| owner_endpoint | string | 该 pod 的内部 gRPC 转发端点 `<pod-ip>:9443` |
| epoch | uint64 | 单调递增版本号，防止陈旧 owner 被误用 |
| tenant_id | string | 用于 Cross-tenant 校验 |
| connected_at | int64 | 连接建立时间（Unix ms） |
| ttl | — | Redis TTL = 2 × max_connection_age（默认 48h）；心跳续期 |

**写入时机（由持有连接的 pod 执行）**：
- `EventStream` RPC accept 后、mTLS 和 tenant 校验通过，**先**写入本地 `LocalOwnershipCache`（内存，lease=60s），**再**异步 `HSET conn:{agent_id} ...` + `EXPIRE` 到 Redis；epoch 取 `INCR conn:{agent_id}:epoch`。Redis 失败不阻塞连接建立
- 连接关闭（GOAWAY、TCP RST、drain）：先清理本地 lease，再 `DEL conn:{agent_id}` —— Redis 删除使用 Lua 脚本做 `owner_pod == 本pod` 的 CAS 校验，防止覆盖新 owner
- 每 15s 续期本地 lease（仅依赖 gRPC stream 活性）；每 30s 心跳刷新 Redis TTL（依赖 Redis）

**双轨机制的意义**：LocalOwnershipCache 保证**本 pod 已持有的连接**在 Redis 故障时仍可被本地直投（4.5.7.4）；Redis Registry 保证**跨 pod 的目标发现**。正常路径先查本地再查 Redis，降级路径按命令类型走不同兜底。

**Redis 选型与可用性**：
- Redis Cluster（6 节点跨 3 AZ，主从 1+1 per shard）
- 单命令 P99 < 1ms；Registry 流量 ≈ `new_connections/s × 2 + heartbeat_refresh/s ≈ 数千 ops/s`，远低于容量上限
- Redis 不可用时进入 **Registry 降级模式**（第 4.5.7.4 节），按命令类型分流

#### 4.5.4 Unicast 命令路由（agent-scoped）

Topic：`commands.unicast`（partition key = `agent_id`）；消费组：`gateway-unicast`（**shared**，一条记录只交付给一个 pod）。

每个 Gateway pod 的 Unicast Consumer goroutine 使用一个**事务型 Producer**（`transactional.id = gateway-{pod_uid}-unicast`，`enable.idempotence=true`）与 Consumer 协同，按 **Kafka 事务 + read_committed** 语义保证 "消费位点前进、补投写入、Registry 索引更新" 三者的原子边界。核心流程：

```
producer.initTransactions()

for record in kafka.consume("commands.unicast"):   # isolation.level=read_committed
    agent_id = record.key
    entry    = registry.get("conn:" + agent_id)    # Redis HGETALL

    producer.beginTransaction()
    try:
        if entry == nil or entry.expired():
            # 目标 agent 不在线 → 转写入 commands.pending（与 offset 提交同事务）
            producer.send("commands.pending", key=pending_key(record), value=record.value,
                          headers=record.headers | {ttl, enqueued_at, source_offset})
        elif entry.owner_pod == self.pod_uid:
            local_stream = conn_table.get(agent_id)
            if local_stream != nil:
                # 本地投递；send 内部走 gRPC stream 背压，满则抛异常进入 catch
                local_stream.send(record.value)
            else:
                # Registry 声明本 pod 拥有但本地没有 → 清理僵尸 + 补投
                registry.compare_and_delete(agent_id, self.pod_uid, entry.epoch)
                producer.send("commands.pending", ...)
        else:
            # 跨 pod 转发（见 4.5.5）
            ack = inter_pod.forward(entry.owner_endpoint, record)
            if ack.status != DELIVERED:
                producer.send("commands.pending", ...)                 # 转发失败 → 补投

        # Consumer 消费位点作为事务的一部分提交
        producer.sendOffsetsToTransaction(
            offsets={ (topic, partition): record.offset + 1 },
            consumer_group_id="gateway-unicast")

        producer.commitTransaction()
    except (ProducerFencedException, OutOfOrderSequenceException, AuthorizationException):
        raise                                                        # 立即退出、由 K8s 重启重建事务
    except Exception as e:
        producer.abortTransaction()                                  # 回滚；位点不前进；下轮重试
        metrics.unicast_tx_aborted_total.inc(labels={reason: type(e).__name__})
```

**关键语义**：
- **无部分可见状态**：`commands.pending` 的写入、Consumer 消费位点提交**同属一个 Kafka 事务**；要么全部对外可见（被 Pending Dispatcher 看到且位点前进），要么全部作废（下一轮重试）。Producer 故障、pod 崩溃、Kafka broker leader 切换都不会产生 "已 commit 位点但未写入 pending" 或 "已写 pending 但未 commit 位点" 的中间态。
- **read_committed 扩散**：所有下游 Consumer（Pending Dispatcher、Audit Pipeline、跨 AZ 复制）均使用 `isolation.level=read_committed`，只读取已提交事务的记录。
- **本地投递失败不污染事务**：`local_stream.send` 若抛异常（stream 已关/背压上限），由 `abortTransaction` 回滚，下一轮消费到同一条记录时会走补投分支。
- **转发路径也原子**：Inter-Pod forward 的"成功/失败"结果决定事务内写不写 `commands.pending`；转发本身不是 Kafka 事务参与者，但结果已反映在同一事务中。
- **transactional.id 与 pod 生命周期绑定**：`gateway-{pod_uid}-unicast` 保证 pod 重启后 Kafka 能围栏（fence）旧实例的僵尸事务；pod UID 取自 K8s Downward API，滚动更新天然产生新 UID。
- **不再存在 "消息被多 pod 消费后各自判断归属" 的广播式 unicast**。

#### 4.5.5 Inter-Pod gRPC 转发（内部控制面）

为支持跨 pod 转发，Gateway 同时暴露一个**内部 gRPC 服务**（非 Agent 流量端口，监听 9443，仅集群内网络）：

```protobuf
service GatewayInternal {
  // 将命令转发给该 pod 持有的目标 agent 连接
  rpc ForwardCommand(ForwardCommandRequest) returns (ForwardCommandAck);
}

message ForwardCommandRequest {
  string  agent_id        = 1;
  uint64  owner_epoch     = 2;   // 调用方认定的 owner epoch，用于 CAS
  bytes   signed_command  = 3;   // 原始 SignedServerCommand 字节，pass-through
  string  lineage_id      = 4;   // 分布式追踪
}

message ForwardCommandAck {
  enum Status {
    DELIVERED        = 0;  // 已写入目标 agent 的 gRPC stream
    NOT_OWNER        = 1;  // 本 pod 不再持有该连接（epoch mismatch 或已断开）
    AGENT_BACKPRESSURED = 2; // 目标 stream 缓冲满，调用方应补投
    INTERNAL_ERROR   = 3;
  }
  Status status = 1;
}
```

- 鉴权：Gateway 间使用独立的 **内部 mTLS 证书**（由 Vault 签发，CN=`gateway.internal`），与 Agent ↔ Gateway 证书链完全隔离，禁止被 Agent 侧证书调用
- 网络：K8s NetworkPolicy 仅放行 `ingestion-gateway` pod 之间的 9443 端口
- 背压：单个转发连接使用独立 HTTP/2 连接池，`MaxConcurrentStreams=1000`；若目标 pod 过载，返回 `AGENT_BACKPRESSURED`，调用方进入补投
- `NOT_OWNER` 时调用方立即刷新 Registry 并重试 1 次；仍失败则进入补投

#### 4.5.6 Broadcast 命令路由（tenant/global-scoped）

用于 POLICY_UPDATE、IOC_UPDATE、RULE_UPDATE 等需要推送给**多个或全部 Agent**的命令。

Topic：`commands.broadcast`；消费组：**每 pod 一个独立 consumer group**，group_id = `gateway-bcast-{pod_uid}`。

- 每个 pod 独立消费 `commands.broadcast` 的所有分区（独立 group 保证每条记录被每个 pod 收到一次）
- Consumer 从消息 header 读取目标作用域（`scope=tenant:{tenant_id}` / `scope=global` / `scope=agent_set:{ids...}`），然后遍历本 pod 的 **本地连接表**，对匹配的 Agent 投递
- 不跨 pod 转发——因为每个 pod 都会自己收到一份 copy
- Offset 在本地投递完成后 commit；即使某些 Agent 在该 pod 掉线，仍会由其他 pod 的副本覆盖到

**Pod 弹性下的正确性**：
- 新 pod 启动时，consumer group `gateway-bcast-{new_pod_uid}` 的起始 offset = **latest**（仅消费新加入后产生的广播）
- 历史策略由连接建立时的 "初始化推送" 覆盖（Agent EventStream open 后，Gateway 从 Policy Service 拉取当前租户策略，同步推送一次；参见 Section 5.2）
- Pod 缩容时：consumer group 随 pod 一起销毁，不残留僵尸消费组；Kafka broker 侧配置 `offsets.retention.minutes=1440`（24h）自动清理

#### 4.5.7 未投递命令的补投与 TTL 处理

即使有 Ownership 模型，仍存在三类 agent-scoped 命令无法即时投递的场景：① Agent 离线；② Agent 重连切换 pod 过程中 Registry 短暂无 owner；③ 转发目标 pod 返回 `AGENT_BACKPRESSURED` / `NOT_OWNER`。

##### 4.5.7.1 `commands.pending` Topic 形态

| 属性 | 设置 | 说明 |
|------|------|------|
| cleanup.policy | `compact,delete` | 既保留每个 `(agent_id, command_id)` 的最新状态，又通过 retention 防止 TTL 过期记录永驻 |
| key | `{tenant_id}:{agent_id}:{command_id}` | 保证 compaction 粒度为单条命令；投递完成后以 tombstone 清除 |
| partition key | `agent_id`（独立于 key 的 hash） | 与 `commands.unicast` 一致，保证同一 agent 的补投顺序 |
| retention.ms | 7 天 | 覆盖最长业务 TTL，兜底防止死信永驻 |
| min.insync.replicas / acks | 2 / all | 与上行链路持久化等级一致（见 4.4.3） |
| isolation.level（下游消费） | `read_committed` | 只看到事务性提交的条目，与 4.5.4 配合 |

补投写入由 4.5.4 的**事务型 Producer** 与 Consumer 位点提交一同原子完成，从而不存在 "位点已前进但 pending 未写入" 或 "pending 已写入但位点未提交" 的中间状态。

##### 4.5.7.2 Pending Dispatcher（可查询的活动补投集）

补投的难点不是"写得进去"，而是"Agent 重连时 O(1) 查得出来"。单靠 compacted topic 难以支撑 "按 agent_id 列出未过期命令"，因此设计**物化索引**：

```
Kafka commands.pending  ─── Pending Dispatcher (per-pod, read_committed consumer group) ───► Redis
        │                     │                                                       │
        │                     ├── 对每条 pending 记录：                               │  ZSET: pending:{agent_id}
        │                     │   1. 如果 TTL 已过 → 写 tombstone + produce           │   member = command_id
        │                     │      commands.dead-letter（同事务）                    │   score  = expiry_ts
        │                     ├── 2. 否则查 Registry：                                 │  HSET:  pending_body:{command_id}
        │                     │   - owner == self：本地投递成功 → 写 tombstone         │   holds signed bytes + headers
        │                     │   - owner != self：转发成功    → 写 tombstone         │
        │                     │   - owner nil / 失败          → 保留，按指数退避     │
        │                     └── 退避：初始 2s，最大 60s，抖动 ±20%                  │
        │                                                                              │
        └───────────── compaction 兜底：tombstone 后 topic 自动清理                    │
```

- Redis ZSET `pending:{agent_id}` 提供 O(log N) 的 "该 agent 的未过期命令列表"；HSET `pending_body:{command_id}` 保存原始 SignedServerCommand 字节与 headers（Gateway 不解码 payload）。
- 索引写入策略：Pending Dispatcher 读取 `commands.pending` 后先写 Redis ZSET/HSET，再返回，配合 Consumer 位点提交保证 "索引存在 ⇒ 记录已被写入 pending"；反向最终一致（索引可能临时落后于 Kafka，重连回放时 Gateway 同时查询 Redis + compacted topic replay 兜底，详见 4.5.7.3）。
- Redis 故障降级：索引不可用时，Gateway 退回到扫描 `commands.pending` 的 agent-scoped compacted view（慢路径）并触发 P2 告警；此时新 pending 写入 Kafka 仍持续，索引在 Redis 恢复后由 Dispatcher 回填（以 source offset 为起点）。
- 死信：TTL 到期 → `commands.dead-letter`（审计 + 告警） + `CommandExpired` 事件发布给 Management Plane；dead-letter 写入与 tombstone 在同一 Kafka 事务中。

##### 4.5.7.3 Agent 重连后的命令回放

Agent 通过 `EventStream.open` 重连时：
1. Gateway 完成 mTLS + Registry CAS 占据 ownership 后，**先**按如下顺序回放 pending：
   ```
   entries = redis.ZRANGEBYSCORE("pending:" + agent_id, now, +inf)
   if entries is not None:
       for cid in entries:
           body = redis.HGET("pending_body:" + cid)
           stream.send(body)
           # 投递成功：追加事务写 commands.pending tombstone + 删除 Redis 条目
   else:
       # Redis 降级兜底：直接消费 commands.pending 的 agent-scoped 段（慢）
       replay_from_compacted_topic(agent_id)
   ```
2. 完成 pending 回放后再放行 Live 下行（Live 流中的新命令在回放期间临时缓冲于 gRPC stream 发送队列，保持 sequence_hint 单调）。
3. Agent 侧通过 `command_id` 去重（参见 `aegis-sensor-architecture.md` 第 4.5.5 节命令去重表），因此 "Redis 索引 + compacted topic" 双路径带来的偶发重复被幂等吸收。

##### 4.5.7.4 Registry 降级模式（Redis Connection Registry 不可用）

"一律 pending" 对 CRITICAL 命令（`RESPONSE_ACTION` / `REMOTE_SHELL`）不可接受——攻击正在进行时，等下次重连回放意味着已经错过隔离/终止窗口。因此 Registry 降级需要**双层兜底**：已在线连接走本地直投，新连接/跨 pod 目标走 pending，按命令类型精细化策略。

**本地 Ownership 缓存（Local Lease）**：
- 每个 Gateway pod 在本地持有一份 `LocalOwnershipCache`，内容与写入 Redis Registry 的条目同源：`agent_id → {owner_pod=self, epoch, lease_expires_at}`
- 入库路径：Agent 完成 mTLS + EventStream.open 时，Gateway 先写入 `LocalOwnershipCache`，再异步写入 Redis；Redis 失败不阻塞连接建立
- Lease 续期：每个活跃连接每 15s 续期本地 lease（`lease_ttl = 60s`）；续期仅依赖 gRPC stream 的存活，不依赖 Redis
- 连接断开：gRPC stream 关闭时立即清理本地 lease；不依赖 Redis TTL

**检测**：所有 Registry 调用启用熔断器（5xx 或超时 > 100ms 达阈值 50%）；熔断后转入降级模式并发 P1 告警。

**降级模式下的命令分流（按命令类型）**：

| 命令类型 | 本 pod 持有目标连接 | 本 pod 未持有 / 不确定 |
|----------|---------------------|------------------------|
| RESPONSE_ACTION（CRITICAL） | **本地直投**（LocalOwnershipCache 命中即送，事务内写入 audit-log，不走 pending） | **Fan-out-on-miss**：在事务内写 `commands.pending` + 通过 Inter-Pod 9443 向**所有其它 pod** 并发 ForwardCommand；任一 pod 返回 DELIVERED 即标记成功并写 tombstone；30s 内无人 DELIVERED → 保留在 pending + 告警 |
| REMOTE_SHELL（CRITICAL） | 同上，但额外要求 `approval.human_in_loop == true` 已由上游盖章；降级期间禁止自动放行审批 | 同上；Agent 侧仍需完成交互式审批链 |
| FEEDBACK / REQUEST_PROCESS_INFO（LOW/NORMAL） | 本地直投 | 进入 `commands.pending`，正常退避 |
| POLICY_UPDATE / RULE_UPDATE / IOC_UPDATE / CONFIG_CHANGE | **不受影响**——广播通道不依赖 Registry，每 pod 独立 consumer group 已覆盖全部本地连接 | 同左（Registry 故障对广播路径透明） |

**策略矩阵的理论依据**：
- **CRITICAL 命令 Fan-out-on-miss** 的成本是 N-1 次跨 pod RPC（N = pod 数，≈ 70-90），但这些 RPC 只在 Registry 降级时发生，且只针对 CRITICAL 命令；平均每秒全局 CRITICAL 命令速率 < 10 QPS，该成本在紧急情况下可接受。
- **FEEDBACK / NORMAL 命令不做 Fan-out-on-miss**：这些命令时效性弱、业务价值低，pending 重连回放足矣，避免降级期间的放大效应。
- **本地 lease 不能永久取代 Registry**：lease 只覆盖"本 pod 本已持有"的连接；跨 pod 投递仍需 Registry 或 Fan-out-on-miss。Redis 恢复后 Pending Dispatcher 会用 Registry 重新收敛。

**Registry 恢复后**：
- 熔断器半开试探成功后，降级模式自动退出；`LocalOwnershipCache` 与 Redis Registry 以 `(agent_id, owner_pod, epoch)` 做 CAS 对账，冲突时保留本地（本地是事实来源）
- Pending Dispatcher 正常扫描 `commands.pending`，命中 Registry 的记录走正常 unicast 路径

**Pending 失败开关（Fail-Closed）**：
- 若某条 `RESPONSE_ACTION` / `REMOTE_SHELL` 在 pending 中停留超过 30s 仍未投递，Gateway 向 Management Plane 发布 `CriticalCommandDelayed` 事件，由 Response Orchestrator 决策是否升级到带外通道（OOB，如管理员手动 SSH / EDR 侧信道）——此机制已在 `aegis-architecture-design.md` §6.4 登记；本节仅保证"Registry 故障不会吞没 CRITICAL 命令"。

**Registry 降级观测**：
- `gateway_registry_circuit_state{state=closed|half-open|open}`
- `gateway_local_lease_coverage_ratio`（= 本 pod 活跃连接数 / Registry 记录数）
- `gateway_critical_fanout_on_miss_total{result=delivered|pending|expired}`

#### 4.5.8 租户作用域命令隔离

| 隔离机制 | 说明 |
|----------|------|
| Kafka partition key | `commands.unicast` 按 agent_id 分区，agent_id 内嵌 tenant_id 信息 |
| Registry 租户校验 | Gateway 投递或转发前校验 `record.tenant_id == registry.tenant_id == stream.cert_tenant_id`，三者必须一致，否则丢弃并告警（STRIDE Tampering） |
| 证书绑定 | Gateway 仅向与 agent_id 证书匹配的 gRPC stream 投递命令 |
| 签名绑定 | ServerCommand 内含 tenant_id 和 agent_id，Agent 侧验签时校验两者匹配本机 |
| 审计追踪 | 每次命令投递记录 command_id + agent_id + tenant_id + delivery_timestamp + owner_pod + via_forward(bool) |

**命令签名透传**：Gateway 不解析也不修改 SignedServerCommand 的 payload 和 signature 字段。Gateway（包括本地投递和 Inter-Pod 转发路径）均为 Semi-Trusted 角色，即使被攻破也无法伪造有效的 Ed25519 命令签名。命令完整性验证完全由 Agent 侧执行（参见 `aegis-sensor-architecture.md` 第 4.5.5 节）。

---

### 4.6 速率限制与准入控制

#### 4.6.1 多层限速架构

```
┌──────────────────────────────────────────┐
│  Layer 1: LB 层                          │
│  - 单 IP 连接数限制 (100/IP)             │
│  - SYN rate 限制                         │
├──────────────────────────────────────────┤
│  Layer 2: Gateway 层 - 按 Agent          │
│  - Token Bucket (默认 1000 events/s)     │
│  - 可按策略调整 (50-5000 events/s)       │
├──────────────────────────────────────────┤
│  Layer 3: Gateway 层 - 按 Tenant         │
│  - Sliding Window 聚合限速               │
│  - 基于租户 SLA 差异化配额               │
├──────────────────────────────────────────┤
│  Layer 4: Kafka 层 - 背压               │
│  - Producer buffer.memory 上限           │
│  - 超限时阻塞 → gRPC 背压传导           │
└──────────────────────────────────────────┘
```

#### 4.6.2 按 Agent 限速

| 参数 | 默认值 | 可配置范围 | 说明 |
|------|--------|-----------|------|
| 算法 | Token Bucket | — | 令牌桶算法，支持突发 |
| 速率 | 1,000 events/s | 50-5,000 | 每 Agent 的稳态速率 |
| 突发容量 | 2,000 events | 100-10,000 | 允许的最大突发 |
| 超限行为 | 严格不丢弃（whole-batch NACK） | — | 见 4.6.2.1 |
| 背压下限 | 7x 持续 60s 触发 CB | — | 见 4.6.2.2 |

##### 4.6.2.1 严格不丢弃契约（Strict No-Drop Contract）

> **设计决策**：Gateway 过载时**不再静默丢弃 LOW/INFO 事件**。过载时整批拒绝，Agent 保留在本地 WAL 并重试。此举将 "过载损失" 从 **静默 + 选择性** 变为 **可见 + 可恢复**，与第 2.1 节 "背压感知" 原则以及 `aegis-sensor-architecture.md` WAL + Forensic Journal 的分层持久化保持一致。

Gateway 每一个上行 `EventBatch` 必须返回一个明确的 `BatchAck`（见 12.1.5），其状态为 `ACCEPTED` / `REJECTED_RATE_LIMIT` / `REJECTED_BACKPRESSURE` / `REJECTED_MALFORMED` / `REJECTED_AUTH` 之一。**不存在 "部分接受" 的中间态**。

| 超限程度（相对 Agent 稳态速率） | Gateway 行为 | BatchAck 状态 | retry_after | Agent 侧动作 |
|----------|------|------|-------------|-------------|
| ≤ 1x | 正常接收 | ACCEPTED | — | 推进 sequence_id |
| 1-2x（短时突发） | 消费 Token Bucket 突发容量 | ACCEPTED | — | 推进 sequence_id |
| 2-5x（持续超限） | 整批 NACK | REJECTED_RATE_LIMIT | 500-2000 ms jitter | batch 保留在 WAL，按 `retry_after` 退避重传；不推进 sequence_id |
| > 5x（严重超限） | 整批 NACK + 发送 gRPC 背压（FlowControl window 缩小） | REJECTED_RATE_LIMIT | 2000-5000 ms jitter | 同上；若连续 10 次 NACK，Agent 降低本地采样率（见 sensor 侧 QoS） |
| Gateway 下游 Kafka 不可写 | 整批 NACK（无关配额） | REJECTED_BACKPRESSURE | 100-500 ms jitter | 本地缓冲，等待重试 |

**关键不变量**：
- **None lost, none duplicated**：Gateway 返回 `ACCEPTED` 的前提是该 batch 的全部事件 **均已被所有 Kafka Producer 以 `acks=all` 模式确认**（ISR 同步完成），这与 4.4.3 的 Producer 配置强制约束一致。任意 Producer 返回错误（`NotEnoughReplicasException` / 超时 / leader 切换失败等）必须整批改回 `REJECTED_BACKPRESSURE`。
- **sequence_id 原子推进**：Agent 仅在收到 ACCEPTED 后推进本地 sequence_id，从而 NACK 的 batch 在重连或重试时按原 sequence_id 重发，Gateway/Kafka 上游按 sequence_id 幂等去重（参见 4.7.4）。
- **禁止弱持久化快速路径**：Gateway 不得为了降低尾部延迟而在未收到 `acks=all` 确认的情况下返回 ACCEPTED。任何此类 "fast ack" 选项必须升级为独立的 `ACCEPTED_NONDURABLE` 状态，且 Agent 不得推进 sequence_id（当前版本不启用）。
- **可观测性**：每个 NACK 记录 `nack_reason + agent_id + tenant_id + batch_size + retry_after` 到审计日志和 Prometheus 计数器 `gateway_batch_rejected_total{reason}`；`gateway_produce_duration_seconds` 按 Producer 类型和事件优先级打标，用于持续观测 `acks=all` 带来的延迟分布。

##### 4.6.2.2 熔断与保护（Circuit Breaker）

严格不丢弃不意味着无限重试风暴。保护：

- Agent 侧：Forensic Journal 与 Telemetry WAL 各有独立容量上限（参见 `aegis-sensor-architecture.md` 4.4.x）。WAL 打满时 **Agent 端** 启动分级降采样（先丢弃 INFO，其次 LOW，保留 HIGH/CRITICAL），但这是 **Agent 自主决策**，对 Gateway 不可见，且事件丢弃记录为本地 telemetry metric 并上报
- Gateway 侧：若单 Agent 在 60s 内 NACK 计数 > 120（2 NACK/s），Gateway 对该 Agent 启用**连接级熔断**：返回 `RESOURCE_EXHAUSTED` 并关闭该 EventStream（GOAWAY）；Agent 退避 30s 后重连（重连后会走完整的 mTLS + 准入检查）
- 全局：若 Gateway pod 整体 NACK 率 > 15%（1min 滑窗），Pod 从 LB 后端池被 drain（readiness=false），其余 pods 承接流量，HPA 触发扩容

#### 4.6.3 按 Tenant 限速

- 算法：Sliding Window（滑动窗口，1 分钟窗口）
- 配额来源：租户 SLA 配置（存储于 Policy Service → Redis cache）
- 默认配额：租户下所有 Agent 聚合限速 = Agent 数量 × 1,200 events/s（1.2x 余量）
- 超限时所有后续 EventBatch 整批返回 `BatchAck.REJECTED_QUOTA_EXCEEDED`（见 12.1.5），`retry_after_ms` 根据剩余窗口动态计算（典型 10-30s）；Agent 在 WAL 中保留待重发，禁止 Gateway 侧丢弃

#### 4.6.4 证书吊销集成

被吊销证书的 Agent 连接会被立即拒绝：
- CRL（Certificate Revocation List）由云端 CA 定期生成，推送至所有 Gateway pod（默认 5 分钟更新间隔）
- OCSP Stapling 作为补充手段
- 被吊销 Agent 的连接断开后，其 agent_id 加入本地拒绝列表（TTL 与 CRL 更新间隔一致）

---

### 4.7 连接管理

#### 4.7.1 gRPC 连接生命周期

```
Agent                              Gateway
  |                                  |
  |-- TLS ClientHello -------------->|
  |<- TLS ServerHello + Cert --------|
  |-- TLS Client Cert -------------->|
  |     mTLS 握手完成                 |
  |                                  |
  |-- EventStream RPC open --------->|
  |     注册连接表 (agent_id → stream)|
  |                                  |
  |== 双向流持续运行 ================|
  |   上行: EventBatch              |
  |   下行: SignedServerCommand     |
  |                                  |
  |-- Heartbeat (每 60s) ----------->|
  |<- HeartbeatResponse -------------|
  |                                  |
  |   ... (连接可持续数小时-数天) ... |
  |                                  |
  |-- Connection close / error ----->|
  |     注销连接表                    |
  |     触发离线检测 (若 > 2x 心跳)  |
```

#### 4.7.2 HTTP/2 参数

| 参数 | 设置 | 说明 |
|------|------|------|
| MaxConcurrentStreams | 100 | 单连接最大并发 stream 数 |
| InitialWindowSize | 1MB | 初始流控窗口 |
| MaxFrameSize | 16KB | 单帧最大大小 |
| KeepAliveTime | 30s | Keep-alive ping 间隔 |
| KeepAliveTimeout | 10s | Keep-alive ping 超时 |
| MaxConnectionIdle | 15min | 空闲连接超时 |
| MaxConnectionAge | 24h | 连接最大存活时间（强制重连以触发负载均衡再平衡） |
| MaxConnectionAgeGrace | 30s | 优雅关闭宽限期 |

#### 4.7.3 连接排水（Connection Draining）

当 Gateway pod 需要关闭时（滚动更新、缩容等），执行连接排水流程：

1. **标记不就绪**：将 pod 从 LB 后端池移除（readiness probe 返回 false）
2. **停止接受新连接**：gRPC server 停止 accept
3. **通知现有连接**：通过 gRPC GOAWAY 帧通知 Agent 迁移
4. **等待排水期**：默认 30s 宽限期，允许 Agent 完成当前 batch 并重连到其他 pod
5. **强制关闭**：宽限期后强制关闭剩余连接
6. **Agent 行为**：收到 GOAWAY 后，Agent 立即重连（通过 LB 被分配到其他 pod）

#### 4.7.4 重连处理

- Agent 重连时通过 mTLS 重新认证，Gateway 重新创建连接表条目并刷新 Connection Registry（见 4.5.3）
- 重连后 Agent 按 sequence_id 顺序回放 WAL 中未确认的事件
- Gateway 基于 `(agent_id, sequence_id)` 做幂等去重，防止重复投递
- 重连时 Gateway 先回放 pending 下行命令（见 4.5.7），再恢复正常双向流

---

### 4.8 Fallback Transport 子系统

#### 4.8.1 背景与作用域

HTTP/2 / gRPC 在下列网络环境中可能被阻断或降级到不可用：严格企业代理、仅放行 HTTP/1.1 的 WAF、强制 HTTPS 解包的 MITM 代理、仅放行特定域名白名单的出站网关、对长连接空闲超时激进的 NAT/防火墙。这些环境在金融、政府、OT、境外出海场景中不可忽略。

**Fallback 子系统必须保证**：与主通道 **语义等价**（不是功能子集）——同样的 mTLS/tenant 身份语义、同样的 BatchAck 契约、同样的 SignedServerCommand 下行、同样的背压规则、同样的 Connection Registry 参与。Fallback 只在**传输层**不同，**应用层协议**和**安全语义**完全一致。

**Fallback 等级（Agent 侧探测与切换逻辑参见 `aegis-sensor-architecture.md` 通信模块）**：

| 等级 | 传输 | 触发条件 | Gateway 侧实现 |
|------|------|---------|---------------|
| L0 | gRPC/HTTP2 + mTLS（主通道） | 默认 | Section 4.1-4.7 |
| L1 | WebSocket + mTLS（TLS 1.3，HTTP/1.1 Upgrade） | HTTP/2 被代理剥离或被阻断 | 4.8.2 |
| L2 | HTTPS Long-Polling + mTLS | WebSocket 也被阻断（常见于激进 WAF） | 4.8.3 |
| L3 | Domain-Fronted HTTPS（CDN 前端 + Host header 变更） | 出站域名白名单环境 | 4.8.4 |

所有 L1-L3 共享同一后端逻辑（鉴权、Enrichment、Kafka produce、下行命令分发），仅入口协议适配器不同。

#### 4.8.2 L1 — WebSocket 回退

**入口端点**：`wss://ingest.<region>.aegis.example/v1/stream`
- TLS 1.3 终结在同一批 Gateway pod（独立监听端口 8443，复用同套 mTLS 证书和 CA 信任链）
- HTTP/1.1 Upgrade 握手，子协议 `aegis.ingest.v1+ws`
- 鉴权：与 gRPC 路径相同——客户端证书在 TLS 握手中提供，Gateway 从证书 SAN 提取 tenant_id（与 gRPC 路径一致）

**消息帧**：WebSocket binary frames，每帧一个 Protobuf 消息：

| 方向 | 消息 | 对应 gRPC |
|------|------|---------|
| Client → Server | `UplinkMessage`（EventBatch 或 ClientAck） | EventStream 上行 |
| Server → Client | `DownlinkMessage`（BatchAck / SignedServerCommand / FlowControlHint） | EventStream 下行 |

**心跳与保活**：
- WebSocket 协议层 ping/pong 每 30s（对应 gRPC KeepAlive）
- 应用层 `HeartbeatRequest` 每 60s（与主通道一致）
- 最大连接存活 24h，到期后 Gateway 发送 `FlowControlHint(reason=reconnect)` 并在 30s 内关闭，触发 Agent 重连

**背压**：
- WebSocket 没有内建流控窗口，改用 **应用层信用（credit-based）**：Gateway 初始向 Agent 授予 100 batch credits，Agent 每发送一个 EventBatch 消耗 1 credit，每收到一个 BatchAck.ACCEPTED 返还 1 credit；credits 归零时 Agent 必须停止发送
- Credit 参数包含在连接建立后的首个 `DownlinkMessage.flow_hint` 中

**连接 Registry 与下行命令**：与主通道完全相同。Gateway 在 WebSocket 连接建立后写入 `conn:{agent_id}` 并在其中标记 `transport=ws`；Inter-Pod 转发协议（4.5.5）对 transport 类型透明——目标 pod 的本地分发器按 transport 决定用 gRPC server-send 还是 WebSocket send

**LB 路由**：L4 LB（与主通道同一入口）按 ALPN + TLS SNI + SNI `ingest.*` 分流到 8443 端口；L7 负载均衡不参与（维持 TLS 直通），跨 AZ 就近分发

#### 4.8.3 L2 — HTTPS Long-Polling 回退

**入口端点**：
- 上行（Agent → Gateway）：`POST https://ingest.<region>.aegis.example/v1/uplink`
- 下行（Gateway → Agent）：`POST https://ingest.<region>.aegis.example/v1/downlink`（Agent 发起长轮询）
- 鉴权：客户端证书 mTLS（同一套证书与 tenant 语义）

**上行 POST 语义**：
- 请求体：Protobuf `UplinkBundle { repeated EventBatch batches = 1; ClientAck? ack = 2; }`
- 响应体：Protobuf `UplinkAckBundle { repeated BatchAck acks = 1; FlowControlHint? hint = 2; }`
- HTTP 状态码仅反映传输层成功；应用层成败由 BatchAck.Status 决定
- 每个 POST 的最大 batch 数 ≤ 16，最大 body 1MB（防代理切片）

**下行长轮询语义**：
- Agent 以一个挂起 POST 调用请求下行命令；请求体为 `DownlinkPollRequest { agent_id, last_seen_command_id, poll_timeout_ms=25000 }`
- Gateway 注册一个虚拟 "stream slot" 到 Connection Registry（transport=longpoll），等待命令到达或超时；到达则即时响应 `DownlinkPollResponse { repeated SignedServerCommand commands = 1; FlowControlHint? hint = 2; }`
- Agent 收到响应后立即发起下一个长轮询（保持虚拟 "连接"）
- 单次最大挂起时长 30s，避免代理超时；空响应也算正常应答

**Connection Registry 与虚拟连接**：
- Gateway 在 Agent 首次 POST 或 long-poll 时写入 Registry，`owner_pod` 为处理该请求的 pod；`epoch` 用于解决并发请求到不同 pod 的冲突（sticky session 优先，失败时回退 epoch-based 竞争）
- 虚拟连接 TTL = 90s（3× poll_timeout）；Agent 必须在 TTL 内发起下一次 poll，否则 Registry 条目过期
- **Sticky Session**：LB 按 agent_id 的 `Cookie: aegis-agent=<hash>` 或 `X-Aegis-Agent-Id` header 做 hash 亲和，尽量让同一 Agent 的 POST 落到同一 pod；切换 pod 时通过 Inter-Pod 转发保持一致性

**背压**：与 L1 类似的信用机制，FlowControlHint 包含 `cooldown_ms` 与 `suggested_rate_eps`；Agent 遵循 `cooldown_ms` 暂停发起 POST

**限制**：L2 比 L1 更高延迟（命令下行平均延迟 ≈ poll_timeout/2），仅用于 L1 被阻断的兜底

#### 4.8.4 L3 — Domain-Fronted HTTPS（独立信任域）

> **L3 不是 L0-L2 的语义等价兜底**。它把 TLS 终结从 Gateway 边界前移到 CDN 边缘，将"身份来自客户端证书"替换为"身份来自 CDN 签发的 header"。这是一次**信任域切换**，因此本节被显式建模为**独立 trust zone**，并在第 9 节威胁模型有专属 STRIDE 条目。下文的功能受限列表与默认禁用策略是对这次信任降级的代价对齐。

**动机**：在出站域名白名单仅允许某些公有云/CDN 域名（如 `*.cloudfront.net`、`*.azureedge.net`）的环境，Agent 需要通过这些域名连通 Aegis Gateway。L3 仅作为 L0-L2 全部失败时的**最后可达性手段**，默认在部署清单中**关闭**（`transport.l3.enabled=false`），需要显式开启。

**架构**：
```
Agent ─► TLS(SNI="dXXXX.cloudfront.net") ─► CDN Edge ─► mTLS(Agent→CDN) 终结
         Host="ingest.<region>.aegis.example"              │
                                                           ▼ （签名 header 回源）
                                                    Origin: Gateway L3 Adapter
                                                    (独立端口 :8444，单独证书，单独策略)
```

- Agent 使用 CDN 边缘域名做 SNI 和 TLS 握手；HTTP Host header 写真实 Gateway 域名
- **mTLS 终结在 CDN 边缘**：CDN 校验 Agent 客户端证书，提取 `agent_id` / `tenant_id` / `cert_fingerprint`，以 CDN→Origin 独立密钥（Ed25519，HSM 签发）签入 `X-Aegis-L3-Identity` header
- Origin（Gateway L3 Adapter）**仅接受由合法 CDN 签名密钥**签发的 header，且：
  - 校验时间戳新鲜度（≤ 60s）防重放
  - 校验 CDN PoP 的 mTLS（边缘到源站通道）
  - 拒绝任何未经签名或签名不通过的请求
- 每个 Agent 的 L3 会话在 Connection Registry 中标记 `transport=fronted`

**信任模型（与 L0-L2 对比）**：

| 维度 | L0-L2 | L3 |
|------|-------|-----|
| 身份信任来源 | Gateway 直接校验客户端证书（mTLS 到 Gateway） | Gateway 信任 CDN 的 Ed25519 签名 header → CDN 终结 mTLS |
| 新信任根 | Aegis CA | Aegis CA **+ CDN↔Gateway 专用签名密钥 + CDN 运行时** |
| 被攻击面 | Gateway 进程、Aegis CA | 同左 **+ CDN 边缘配置 + CDN 运营方 + 签名密钥管理** |
| 证书吊销 | CRL/OCSP 立即生效 | 取决于 CDN 边缘的 CRL 刷新 cadence（通常 5-15min 额外延迟） |
| 端到端加密 | 点到点 TLS 1.3 | 两段：Agent↔CDN 与 CDN↔Origin；CDN 内部可见明文 |
| DoS 保护 | Gateway LB/WAF | CDN 原生 DDoS + Gateway 二次限流 |

**L3 独立信任域下的 STRIDE**（补充 §9 主威胁模型）：

| STRIDE | 风险 | 控制 |
|--------|------|------|
| Spoofing | 非法源伪造 CDN 签名 header 直连 Origin | Origin 启用 IP 白名单（仅 CDN 边缘网段）+ mTLS（CDN→Origin 专用客户端证书）+ Ed25519 签名 header 双重校验 |
| Tampering | CDN 配置被篡改导致身份透传错误 | CDN 配置纳入 GitOps 审计 + 自动一致性巡检；Gateway 侧每日对签名密钥指纹做独立校验并告警 |
| Repudiation | CDN 侧的投递/接收日志缺口 | CDN access log 强制开启，镜像到 Aegis audit-log topic；Origin 侧额外记录 `transport=fronted` 标记 |
| Info Disclosure | CDN 边缘明文暴露 payload | Agent 在 L3 模式下**额外启用 payload-layer AES-256-GCM 端到端加密**（密钥由 Agent 与 Gateway Master Key 协商，不经 CDN），CDN 仅看到加密后的字节流 |
| DoS | CDN 或其 PoP 故障导致全租户 L3 瘫痪 | L3 作为最后兜底，不是 primary；Agent 自动退回本地缓冲 + WAL |
| Elevation | CDN 签名密钥泄漏导致伪造任意身份 | 签名密钥 HSM 保护 + 24h 轮换 + 每次签名审计 + Gateway 侧密钥白名单支持热下线 |

**L3 功能降级清单（硬性约束）**：

| 命令类型 | L3 行为 |
|---------|---------|
| POLICY_UPDATE / RULE_UPDATE / IOC_UPDATE | 允许；附加 `target_scope.tenant_id` 必须匹配 CDN 签名内 tenant，否则 Gateway 丢弃 |
| CONFIG_CHANGE | 允许；仅 AGENT_SET 精准投递 |
| FEEDBACK / REQUEST_PROCESS_INFO | 允许 |
| **RESPONSE_ACTION** | **禁止**（Gateway 层强制拒绝；Response Orchestrator 侧侦测 `transport=fronted` 自动降级为 "延后执行待 Agent 切回 L0-L2"） |
| **REMOTE_SHELL** | **禁止**（同上；人工审批 UI 显式提示当前 Agent 在 L3 模式） |
| 上行 CRITICAL 告警 | 允许；但 Gateway 侧对 `transport=fronted` 的 CRITICAL 事件标注额外置信度降级 flag（供 Analytics 衡量） |

> **L3 不承担实时响应能力**——这是信任域决定的功能边界，不是实现遗憾。将 `RESPONSE_ACTION` / `REMOTE_SHELL` 放到 L3 下执行等于让 CDN 运营方获得对终端的直接操控能力，违反零信任模型。

**协议载荷**：L3 内部使用与 L2 相同的 HTTP Long-Polling 语义（POST uplink / POST poll），外加 payload-layer AES-256-GCM 加密；不新增上下行 wire format。

**默认禁用 + Fail-closed 开关**：
- `transport.l3.enabled` 默认为 `false`，启用需平台管理员双人审批
- `transport.l3.kill_switch`：一键全局禁用 L3（返回 `TRANSPORT_DISABLED`，Agent 退回本地缓冲），用于 CDN 入侵、签名密钥泄漏等事件
- 启用 L3 的租户必须签署独立的"信任域扩展同意书"；审计日志保留 365 天

#### 4.8.5 统一的应用层语义（仅 L0-L2；L3 为受限子集）

**L0-L2 等价保证**（与主通道完全一致）：

| 语义 | 保证 |
|------|------|
| 上行 ACK | 每个 EventBatch 对应一个 BatchAck，含 Status + retry_after_ms；不存在静默丢弃 |
| 下行命令 | SignedServerCommand 端到端透传，签名验证由 Agent 完成；命令不降级 |
| tenant 隔离 | tenant_id 始终来自证书 SAN；payload 自报 tenant 不可信 |
| 幂等 | `(agent_id, sequence_id)` 幂等去重，切换 transport 时 sequence_id 不重置 |
| 背压 | Credit-based flow control（L1/L2）或 gRPC flow control（L0） |
| 可观测性 | Gateway 侧按 `transport={grpc,ws,longpoll}` 打标 Prometheus 指标 |

**L3 的语义差异**（独立信任域，见 §4.8.4）：

| 语义 | L3 保证 |
|------|---------|
| 上行 ACK | 保留 BatchAck 语义；但 `ACCEPTED` 下 CRITICAL 事件附带 `l3_confidence_derating=true` 标记 |
| 下行命令 | 仅 POLICY_UPDATE/RULE_UPDATE/IOC_UPDATE/CONFIG_CHANGE/FEEDBACK/REQUEST_PROCESS_INFO；**RESPONSE_ACTION / REMOTE_SHELL 禁止** |
| tenant 隔离 | tenant_id 来自 CDN 签名 header，信任根包含 CDN 运行时与签名密钥 |
| Payload 机密性 | **附加 AES-256-GCM 端到端加密层**（密钥不经 CDN） |
| 幂等 | 同上 |
| 背压 | Long-Polling 信用机制 |
| 可观测性 | `transport=fronted`；所有事件和命令额外标记 L3 血缘 |
| 启用条件 | 租户显式同意 + `transport.l3.enabled=true` + kill-switch 可用 |

#### 4.8.6 Gateway 内部架构适配

L1-L3 复用同一后端流水线（Enrichment、Kafka Producer、Connection Registry、Inter-Pod Forward）；仅入口协议适配器不同：

```
┌─────────────────────────────────────────────────────────────┐
│  Gateway Pod                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐ │
│  │ gRPC L0      │  │ WS L1        │  │ HTTP L2/L3         │ │
│  │ :9090        │  │ :8443        │  │ :8080              │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬─────────────┘ │
│         │                  │                  │              │
│         └──────────────────┼──────────────────┘              │
│                            ▼                                  │
│              ┌───────────────────────────┐                   │
│              │  Transport Adapter Layer  │                   │
│              │  (统一为 UplinkMessage /   │                   │
│              │   DownlinkMessage 语义)    │                   │
│              └────────────┬──────────────┘                   │
│                           ▼                                   │
│              ┌───────────────────────────┐                   │
│              │  共享后端:                 │                   │
│              │  mTLS Verify → Enrich →   │                   │
│              │  Kafka Produce → Ack      │                   │
│              │  Conn Registry → Cmd路由  │                   │
│              └───────────────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

Transport Adapter 负责把三种入口协议的消息归一为 UplinkMessage/DownlinkMessage，对后端完全屏蔽 transport 细节。后端唯一感知到 transport 的地方是 **Connection Registry 的 transport 字段**（用于下行命令路由时选择正确的发送方法）。

#### 4.8.7 容量规划与取舍

- L1/L2/L3 流量占比预期 < 5%（大多数企业环境 gRPC 可用）
- L1 WebSocket 每连接成本略高于 gRPC（无帧多路复用），单 pod 连接上限降至 10,000（相比 gRPC 的 16,000）
- L2 Long-Polling 因为每次 POST 都要新建 HTTP 请求，CPU 成本显著升高——单 pod 长轮询会话上限 5,000；**不建议**作为大规模部署主用
- L3 Domain Fronting 由于 CDN 中继带来额外 100-300ms 延迟且属于独立信任域，**不承担响应动作类能力**（见 §4.8.4 功能降级清单）；纯粹作为 "仅保证能连通 + 遥测回传" 的兜底，且默认禁用需显式开启
- Fallback 专用 pod 组：在需要支持 L2/L3 的环境中，建议为这些入口部署独立 pod pool（L3 adapter 监听独立端口 :8444），避免挤占主通道资源，并便于针对 L3 的独立密钥管理/审计

---

<a id="5-数据流设计"></a>
## 5. 数据流设计

### 5.1 上行数据流（Agent → Gateway → Kafka）

#### 5.1.1 三路流映射

Agent 的三路 gRPC 通道在 Gateway 侧被映射为不同的处理路径：

```
Agent 通道 A (High-Priority)
  CRITICAL/HIGH 告警、响应结果、篡改检测事件
  ├── 独立 gRPC stream + 独立 goroutine
  ├── 零延迟处理（不等待批量窗口）
  ├── Kafka High-Priority Producer (acks=all)
  └── 路由到 raw-events.{tenant} (CRITICAL partition key)

Agent 通道 B (Normal Telemetry)
  常规遥测、低优先级告警
  ├── 批量 100-500 事件 / batch，最长 1s 窗口
  ├── LZ4 压缩（Agent 侧压缩，Gateway 侧解压）
  ├── Kafka Normal Producer (acks=all + idempotent，linger.ms=5 批量提交)
  └── 路由到 raw-events.{tenant} (agent_id hash partition)

Agent 通道 C (Bulk Upload)
  取证包、内存 dump、大文件
  ├── 通过 UploadArtifact RPC（独立 stream）
  ├── 分块上传（chunk size 64KB-1MB）
  ├── 断点续传支持（offset-based）
  ├── 带宽受限（不影响通道 A/B 吞吐）
  └── 存储到 S3/MinIO，元数据写 Kafka
```

#### 5.1.2 批量处理流程

```
Gateway 收到 EventBatch:
1. 从 gRPC stream 上下文提取 agent_id, tenant_id
2. LZ4 解压 batch payload
3. 逐事件 Protobuf 反序列化 + Schema 校验
4. 批量富化 (GeoIP/Asset/TTP/Tenant/lineage)
5. 构建 Kafka ProducerRecords:
   - topic: raw-events.{tenant_id}
   - key: agent_id (确保分区内有序)
   - value: 富化后的 Protobuf 序列化字节
   - headers: lineage_id, priority, event_type
6. 批量 Produce 到 Kafka
7. 根据 acks 策略等待确认
8. gRPC flow control ACK (隐式)
```

#### 5.1.3 压缩处理

| 环节 | 压缩算法 | 说明 |
|------|---------|------|
| Agent → Gateway | LZ4（Agent 侧压缩） | 典型压缩比 5:1，降低网络带宽 |
| Gateway 内部 | 解压处理 | Gateway 需要读取事件内容做富化 |
| Gateway → Kafka | LZ4（Kafka producer 侧压缩） | 减少 Kafka 存储和网络开销 |

### 5.2 下行数据流（Kafka → Gateway → Agent）

#### 5.2.1 命令投递流程

```
1. Management Plane 服务生产 SignedServerCommand 到 Kafka 下行 topic
   - Unicast：`commands.unicast`，partition key = agent_id
   - Broadcast：`commands.broadcast`，headers 含 scope
   - value: SignedServerCommand (Protobuf)
   - headers: tenant_id, command_type, priority

2. Gateway 下行路由（详见 4.5.4-4.5.7）:
   - Unicast 路径：消费后查 Connection Registry 找到 owner_pod
     - 若 owner == 本 pod：本地 gRPC stream 投递
     - 若 owner == 其它 pod：通过 Inter-Pod gRPC 转发到 owner pod 投递
     - 若 owner 不存在（Agent 离线）：produce 到 commands.pending 等待重连回放
   - Broadcast 路径：每 pod 独立 consumer group 消费所有副本，对本地连接表中作用域匹配的
     Agent 投递

3. Agent 收到 SignedServerCommand:
   - Ed25519 签名验证
   - tenant_id / agent_id 匹配校验
   - command_id 去重 (防重放)
   - TTL 过期校验
   - 审批策略校验 (按命令类型)
   - 校验通过后执行
```

#### 5.2.2 下行消息类型

| 消息类型 | 来源服务 | Kafka Topic | target_scope.kind | 下发方式 | 优先级 |
|---------|---------|-------------|-------------------|---------|--------|
| RESPONSE_ACTION | Response Orchestrator | commands.unicast | AGENT | Registry 查 owner → 本地或转发（Registry 降级时走本地 ownership 缓存兜底，见 §4.5.7.4） | CRITICAL |
| REMOTE_SHELL | Response Orchestrator | commands.unicast | AGENT | 同上 | CRITICAL |
| POLICY_UPDATE | Policy Engine | commands.broadcast | TENANT / GLOBAL | 每 pod 独立 consumer group；按签名 target_scope 收窄扇出 | HIGH |
| RULE_UPDATE | Policy Engine | commands.broadcast | TENANT / GLOBAL | 每 pod 独立 consumer group；按签名 target_scope 收窄扇出 | HIGH |
| IOC_UPDATE | Threat Intel Service | commands.broadcast | TENANT / GLOBAL | 每 pod 独立 consumer group；按签名 target_scope 收窄扇出 | NORMAL |
| FEEDBACK | Analytics | commands.unicast | AGENT | Registry 查 owner → 本地或转发 | LOW |
| CONFIG_CHANGE | Policy Engine | commands.broadcast | AGENT_SET / TENANT | 每 pod 独立 consumer group；按签名 target_scope 收窄扇出 | HIGH |

#### 5.2.3 广播命令推送（策略/规则/IOC）

commands.broadcast topic 被每个 Gateway pod 以独立 consumer group 消费（group_id = `gateway-bcast-{pod_uid}`），保证每个 pod 都收到完整副本。收到消息后：

1. **读 header 作为缓存提示**：从 Kafka headers 读取 `scope_hint`、`command_type_hint`、`priority`、`origin_service`；header 仅用于预过滤和跳过显然不匹配的消息，**不作为授权或扩散依据**
2. **强制解码签名内 `target_scope`**：Gateway 解码 `ServerCommand.target_scope`（位于 `SignedServerCommand.payload` 内），以此作为**唯一扇出授权来源**；若 header `scope_hint` 与 `target_scope` 不一致，以 `target_scope` 为准并写审计 `scope_header_mismatch`（STRIDE Tampering）
3. **收窄扇出**：按 `target_scope.kind` 决定本 pod 的候选投递集 = (本 pod 的活跃连接表) ∩ (target_scope 允许集合)；Gateway 必须保证 `|delivered_in_pod| ≤ target_scope.max_fanout`（跨 pod 的聚合检查由 §12.1.3 审计事件流完成）
4. **透传 `SignedServerCommand` 字节**：不改写 payload、不改写 signature、不改写 `command_type`；Agent 验签后再次校验 `target_scope` 是否包含本机身份（详见 §12.1.3）
5. **每类命令的业务语义**（快照 / 增量 / 审批 / 执行）由 Agent 按 `command_type` 分派，与 Gateway 无关：

| `command_type` | 上游服务 | 典型语义 | Agent 重连首次投递 | TTL |
|----------------|----------|----------|--------------------|-----|
| POLICY_UPDATE | Policy Engine | 策略全量/增量；带 `policy_version` 单调递增 | 上游在 Agent 握手完成事件驱动下发送一次 full snapshot（见 Section 5.2） | 长（24h，允许重放） |
| RULE_UPDATE | Policy Engine | 检测规则/模型热更新；带 `rule_bundle_version` | 同上，snapshot 优先 | 24h |
| IOC_UPDATE | Threat Intel Service | IOC 增量；带 `feed_version` + TTL | Agent 查询本地 `feed_version` → 上游生产差异包补齐 | 由 feed 决定（小时级） |
| CONFIG_CHANGE | Policy Engine | Agent 配置变更，按 `target_scope.kind=AGENT_SET` 精准投递 | Snapshot 由配置中心在 Agent 首次连接时同步 | 6h |

> **Gateway 的角色严格受限为"按签名内 target_scope 收窄扇出并透传"**。命令类型的语义差异、幂等性、回放/快照、审批链全部由 Policy Engine / Threat Intel Service / Agent 侧承担；Gateway 既不应也不能替换这些语义。参见 `aegis-sensor-architecture.md` 第 4.5.5 节的命令类型分派逻辑以及本文档 §12.1.3 `TargetScope` 定义。

### 5.3 Heartbeat 处理

#### 5.3.1 Heartbeat 协议

```protobuf
// Agent 每 60s 发送一次 Heartbeat
rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);

// HeartbeatRequest 包含:
HeartbeatRequest {
  agent_id, tenant_id,
  AgentHealth {
    agent_version, policy_version, ruleset_version, model_version,
    cpu_percent_p95, memory_rss_mb,
    queue_depths, dropped_events_total,
    sensor_status, communication_channel,
    kernel_integrity_pass, etw_tamper_detected,
    amsi_tamper_detected, bpf_integrity_pass,
    adaptive_whitelist_size, plugin_status,
    lineage_counters {
      rb_produced, rb_consumed, rb_dropped (per Lane),
      det_received, dec_emitted, wal_written, grpc_acked
    },
    wal_telemetry_bytes, wal_forensic_bytes,
    wal_pressure_level, forensic_journal_utilization,
    emergency_audit_ring_utilization
  }
}
```

#### 5.3.2 Gateway 侧 Heartbeat 处理

1. **健康信息聚合**：接收 Heartbeat 后写入 Redis（key: agent_status:{agent_id}，TTL: 180s = 3x 心跳间隔）
2. **Fleet Status 更新**：按 tenant_id 聚合在线 Agent 数量、版本分布、健康指标
3. **离线检测**：若 Agent 在 2x 心跳间隔（120s）内未发送 Heartbeat，标记为 OFFLINE；3x 间隔（180s）后触发 agent_offline 告警
4. **Heartbeat Response**：返回服务端时间戳（用于 Agent 粗粒度时钟校准）、待拉取的更新列表、配置变更标记
5. **异常上报**：若 Heartbeat 包含异常指标（etw_tamper_detected、高 WAL 压力等），Gateway 生成 agent_health_alert 事件写入 Kafka

---

<a id="6-性能设计"></a>
## 6. 性能设计

### 6.1 热路径延迟预算

```
Latency Budget Breakdown (Gateway 侧, per event batch):

步骤                               延迟         说明
─────────────────────────────────────────────────────────────
Agent gRPC send:                   ~5ms         网络 RTT (可变)
Gateway mTLS verify:               ~0.5ms       TLS session resumption
LZ4 decompress:                    ~0.2ms       per batch (100-500 events)
Protobuf validation:               ~0.1ms       schema check
Enrichment (GeoIP + Asset tag):    ~0.3ms       GeoIP mmap + Redis
Tenant + TTP + lineage:            ~0.05ms      内存操作
Kafka produce (acks=all, ISR):     ~4-5ms       同步等待 min.insync.replicas=2 + 跨 AZ 副本
                                   ────────
Gateway subtotal:                  ~5.15ms      (不含网络 RTT)
Gateway with network:              ~10ms        (含 Agent→Gateway RTT)

备注：
- 所有 Producer 统一 acks=all（见 4.4.3），牺牲 ~2-3ms 延迟换取 ACCEPTED=已持久化 的契约一致性
- 若某租户对延迟极敏感，优化路径是提升 Kafka broker 性能（NVMe、更高网卡）而非退化为 acks=1

后续路径 (非 Gateway 职责，仅供参考):
Kafka → Flink source:              ~10ms        consumer poll interval
Flink rule matching:               ~5ms         per event, includes CEP
Flink → ClickHouse sink:           ~100ms       micro-batch 100ms
                                   ────────
Total ingestion-to-queryable:      ~130ms       Gateway → Kafka → Flink → ClickHouse
Total end-to-end (critical rule):  < 1s         Agent detection + cloud pipeline
Total cloud correlation:           < 5s         includes Correlation Engine
```

### 6.2 吞吐计算

```
规模基准: 100 万终端

单终端事件速率:
  ~500 events/min = ~8.3 events/sec

集群总事件速率:
  1,000,000 × 8.3 = 8.3M events/sec

平均事件大小:
  压缩后: ~200 bytes
  未压缩: ~600 bytes

Gateway 入口带宽:
  8.3M × 200B = ~1.66 GB/s (压缩后)
  LZ4 压缩比 ~5:1, 实际网络带宽: ~330 MB/s

Kafka 写入吞吐:
  8.3M × 200B × 3 replicas = ~5 GB/s
  含 overhead: ~10 GB/s

日数据量:
  8.3M × 86400 × 600B = ~430 TB (未压缩)
  列式压缩后: ~50 TB/day (~10:1)
  Kafka 3 天保留: ~150 TB

单 Gateway pod 吞吐:
  目标: ~500K events/sec / pod
  需要 pods: 8.3M / 500K ≈ 17 → 20+ (含冗余)
```

### 6.3 关键优化策略

| 优化项 | 技术手段 | 效果 |
|--------|---------|------|
| **GeoIP 内存映射** | MaxMind DB 通过 mmap 加载，避免每次查询的文件 I/O | < 1us/lookup |
| **批量处理** | 事件以 batch 为单位处理（100-500 events），摊薄 per-event 开销 | 吞吐提升 10x |
| **Kafka Producer 批量** | 所有 Producer 在 `acks=all` 前提下通过 linger.ms + batch.size 合并写入，充分摊薄 ISR 同步开销；Normal/Bulk 允许 `max.in.flight=5`（配合幂等 Producer 仍分区内有序） | 在 acks=all 下维持吞吐 |
| **连接池复用** | Redis 连接池、Kafka producer 连接池，避免频繁建连 | 减少 TCP 握手开销 |
| **Zero-copy 尽量** | Protobuf bytes 字段避免不必要的拷贝；Go slice 引用传递 | 减少 GC 压力 |
| **TLS Session Resumption** | 启用 TLS session ticket / PSK，减少 full handshake | 握手延迟 2ms → 0.5ms |
| **gRPC Stream 复用** | 单连接双向流，避免 per-RPC 连接开销 | 减少连接数 |
| **goroutine 池** | 限制并发 goroutine 数量（GOMAXPROCS × 256），避免调度开销 | 稳定 CPU 使用 |

### 6.4 关键性能基准表

| 指标 | 目标 | 说明 |
|------|------|------|
| 单 batch 处理延迟 (P50) | < 8ms | 含 Kafka acks=all ISR 同步，不含网络 RTT |
| 单 batch 处理延迟 (P99) | < 20ms | 含 Redis 抖动、ISR 尾部延迟 |
| 端到端 batch 延迟 (P50) | < 12ms | 含 Agent → Gateway RTT |
| 端到端 batch 延迟 (P99) | < 30ms | 含网络抖动 |
| 单 pod 事件吞吐 | >= 1.0M events/s | 8 vCPU 上稳态，突发可至 1.5M |
| 单 pod gRPC 连接数 | 16,000 稳态（20,000 硬上限） | 16GB 内存；连接每条约 80KB 常驻（含发送/接收缓冲+stream state） |
| 单 pod 网络吞吐 | <= 400 Mbps（稳态）/ 800 Mbps（峰值） | 1Gbps NIC 下留 20% 协议栈余量 |
| 集群总吞吐 | >= 8.3M events/s | 90 pods 稳态、最高 150 pods |
| Kafka produce 延迟 (P50) | < 4ms | 统一 acks=all |
| Kafka produce 延迟 (P99) | < 12ms | acks=all + ISR=2 |
| GeoIP lookup 延迟 | < 1us | mmap |
| Asset Tag lookup 延迟 (P50) | < 0.1ms | Redis hit |
| Asset Tag lookup 延迟 (P99) | < 1ms | Redis miss fallback |
| mTLS 握手延迟 | < 2ms | full handshake |
| mTLS 握手延迟 (resumption) | < 0.5ms | session ticket |

---

<a id="7-背压与流控设计"></a>
## 7. 背压与流控设计

### 7.1 端到端背压链

```
ClickHouse 变慢
    ↓
Flink backpressure (credit-based)
    ↓
Kafka consumer lag 增长
    ↓
Kafka partition backlog
    ↓
Gateway Kafka producer 阻塞 (buffer.memory 耗尽)
    ↓
Gateway gRPC server-side flow control (减小 WINDOW_UPDATE)
    ↓
Agent gRPC client 发送速率降低
    ↓
Agent 事件缓冲到 WAL (500MB, 24-48h 覆盖)
```

**核心设计原则**：系统在压力下不静默丢数据，而是从 ClickHouse 一路优雅退化到 Agent 侧 WAL。

### 7.2 Gateway 层背压机制

| 机制 | 触发条件 | 动作 |
|------|---------|------|
| gRPC Server Flow Control | Kafka producer buffer > 80% | 减少 WINDOW_UPDATE 大小，降低 Agent 发送速率 |
| Kafka Producer Backoff | Kafka 不可用或 buffer 满 | Gateway 阻塞当前 batch，gRPC 背压自动向 Agent 传导 |
| 按 Agent 限速 | Agent 超过速率限制 | 返回 gRPC RESOURCE_EXHAUSTED，Agent 降速或写 WAL |
| 熔断器 | Redis/外部依赖连续失败 | 跳过对应富化步骤，降级处理 |

### 7.3 各层背压总览

| 层 | 机制 | 过载时动作 |
|----|------|-----------|
| Agent Ring Buffer | 优先级通道溢出策略 | Lane 0: 有界自旋等待；Lane 1-3: 丢弃并计数 |
| Agent Comms | gRPC HTTP/2 flow control + WAL | 云端变慢 → 事件写入 WAL（500MB，24-48h） |
| **Ingestion Gateway** | **gRPC server-side flow control** | **通过 WINDOW_UPDATE 减少 Agent 发送速率** |
| **Kafka Producer** | **Producer backoff (linger.ms, buffer.memory)** | **buffer 满时 Gateway 阻塞；背压向 Agent 传导** |
| Flink | Backpressure propagation (credit-based) | 慢 operator 导致上游 buffer 堆积 → Kafka consumer 暂停 |
| ClickHouse | Async insert with buffer table | buffer table 吸收流量尖峰，后台合并 |

### 7.4 WAL 回放协调

当背压缓解后，Agent 开始回放 WAL 中缓冲的事件。Gateway 需要：

1. **速率控制**：WAL 回放事件与实时事件混合接收时，优先处理实时事件
2. **幂等去重**：基于 sequence_id 去重，防止 WAL 回放导致重复事件
3. **水位标记**：WAL 回放事件携带 `is_replay: true` 标记，供下游区分实时与回放数据

---

<a id="8-韧性与容错设计"></a>
## 8. 韧性与容错设计

### 8.1 多 AZ 部署

```
Region (e.g., us-west-2)
├── AZ-a: 5 Gateway pods + 5 Kafka brokers
├── AZ-b: 5 Gateway pods + 5 Kafka brokers
└── AZ-c: 5 Gateway pods + 5 Kafka brokers

故障容忍:
- 单 pod 故障: LB 自动摘除，Agent 重连到其他 pod (<5s)
- 单 AZ 故障: 剩余 2 AZ 承载全部流量 (66% → 100% 负载)
  - Gateway: 剩余 10 pods 需扩容至 15+ (HPA 自动)
  - Kafka: min.insync.replicas=2，剩余 10 brokers 可选举 leader
- 双 AZ 故障: 不可用 (设计上限)
```

### 8.2 无状态即时恢复

Gateway 完全无状态，故障恢复极其简单：

| 故障场景 | 恢复方式 | RTO | 数据影响 |
|---------|---------|-----|---------|
| 单 pod crash | K8s 自动重启 + Agent 重连 | < 15s | 零（Agent WAL 兜底） |
| Pod OOM | K8s 重启 + 可能触发 HPA | < 30s | 零 |
| 全 AZ 故障 | LB 切换到存活 AZ | < 30s | 零 |
| 滚动更新 | 连接排水 → 新 pod 启动 | 0（zero-downtime） | 零 |

### 8.3 优雅关闭

```
SIGTERM received
    |
    v
1. 标记 readiness probe = false (LB 摘除)       t=0s
    |
    v
2. 停止接受新连接                                t=0s
    |
    v
3. 发送 gRPC GOAWAY 给所有活跃连接               t=1s
    |
    v
4. 等待进行中的 batch 处理完成                    t=1-25s
   (同时 Agent 重连到其他 pod)
    |
    v
5. Flush Kafka producer buffer                    t=25s
    |
    v
6. 关闭 Kafka producer / Redis 连接               t=28s
    |
    v
7. 强制关闭剩余连接                               t=30s (deadline)
    |
    v
8. 进程退出                                       t=30s
```

### 8.4 熔断器设计

Gateway 对外部依赖使用 Circuit Breaker 模式：

| 依赖 | 失败阈值 | 打开时长 | Half-Open 探测数 | 降级行为 |
|------|---------|---------|-----------------|---------|
| Kafka (生产) | 10s 内 30% 错误率 | 15s | 3 probes | 阻塞 → gRPC 背压 → Agent WAL |
| Redis (Asset cache) | 10s 内 50% 错误率 | 30s | 5 probes | 跳过 Asset Tag 富化 |
| MaxMind GeoIP | N/A（本地 mmap） | N/A | N/A | 文件损坏时标记 geo: null |
| CRL/OCSP | 连续 5 次失败 | 300s | 1 probe | 使用本地缓存 CRL 继续校验 |

### 8.5 隔舱模式（Bulkhead）

| 隔舱 | 资源 | 隔离方式 |
|------|------|---------|
| Ingestion Path (上行) | goroutine pool, Kafka producer pool | 独立 goroutine pool 和连接池 |
| Command Path (下行) | Kafka consumer, stream router | 独立 consumer group 和 goroutine |
| Heartbeat Path | goroutine pool | 独立处理，不与 ingestion 竞争 |
| Management API | HTTP handler pool | 独立端口和 goroutine pool |
| Bulk Upload | goroutine pool, S3 client pool | 独立资源，带宽受限 |

隔舱确保：即使 Kafka 生产路径完全阻塞，Heartbeat 和 Management API 仍然可用。

### 8.6 重试策略

| 操作 | 策略 | 最大重试次数 | Backoff |
|------|------|-------------|---------|
| Gateway → Kafka produce | 线性退避 | 5 | 100ms, 200ms, 500ms, 1s, 2s |
| Gateway → Redis query | 立即重试 | 2 | 0ms, 50ms |
| Gateway → CRL fetch | 指数退避 | Unlimited | 30s → 300s max |
| Agent → Gateway gRPC | 指数退避 + jitter | Unlimited（依赖 WAL） | 1s → 5min max |

### 8.7 数据丢失防护

| 层 | 机制 | 覆盖范围 |
|----|------|---------|
| Agent → Gateway | gRPC ACK + sequence_id | 可靠交付 + 去重 |
| Agent WAL | 本地持久化 + CRC32 校验 | 网络中断缓冲 24-48h |
| Gateway → Kafka | 全部 Producer acks=all + enable.idempotence=true + min.insync.replicas=2（无弱持久化快速路径；见 §4.2.5 / §4.4.3） | Kafka ISR 成为 BatchAck.ACCEPTED 契约前提 |
| Kafka | replication factor 3, min.insync.replicas=2 | 容忍 1 AZ 故障 |
| 端到端 | lineage_id 检查点追踪 | 可审计事件全链路完整性 |

---

<a id="9-安全设计"></a>
## 9. 安全设计

### 9.1 信任边界

**主信任域（L0-L2：直连 mTLS）**：

```
+--[Untrusted]------+     +--[Semi-Trusted]------+     +--[Trusted]----------+
|                    |     |                       |     |                      |
| Endpoints          | mTLS| Transport Plane       | mTLS| Analytics/Data/     |
| (potentially       |====>| (L4 LB + Gateway)     |====>| Management Planes   |
|  compromised)      |     |                       |     | (K8s cluster)       |
|                    |     | ● 验证 Agent 身份     |     |                      |
| ● 可能被攻破      |     | ● 提取 Tenant ID      |     | ● Service Mesh mTLS  |
| ● 可能被伪造      |     | ● 不可伪造命令签名    |     | ● 完全信任           |
|                    |     | ● 不可解密命令内容    |     |                      |
+--------------------+     +-----------------------+     +----------------------+
```

**Semi-Trusted 定义**：Gateway 可以读取遥测事件内容（用于富化），但无法：
- 伪造 ServerCommand 的 Ed25519 签名（签名私钥不在 Gateway）
- 冒充其他 Agent 或租户（身份来自 mTLS 证书）
- 修改下行命令的审批策略（签名覆盖全部命令字段）
- 扩大广播命令扇出面（scope 已被签名覆盖，见 §12.1.3 `TargetScope`）

即使 Gateway 被攻破，攻击者也无法驱动 Agent 执行任何高危响应动作。

**L3 独立信任域（Domain-Fronted，默认禁用）**：

```
+--[Untrusted]------+     +--[Externally-Trusted]----+     +--[Semi-Trusted]-----+     +--[Trusted]-------+
| Endpoints          | mTLS| CDN Edge (非 Aegis)      |mTLS| Transport L3 Adapter |mTLS | Internal         |
|                    |====>| ● 终结客户端 mTLS        |====>| (独立端口 :8444)     |====>|                  |
| ● 可能被攻破      |     | ● 签发 X-Aegis-L3-Identity|     | ● 校验 CDN 签名       |     |                  |
|                    |     | ● 运行时由 CDN 运营方管理|     | ● 仅接受受限命令类型  |     |                  |
+--------------------+     +--------------------------+     +-----------------------+     +------------------+
                                      ▲
                                      │ 新增信任根：CDN 运行时 + CDN↔Origin 签名密钥（HSM）
```

**L3 新增的信任前提**（任一失守都会放大攻击面）：
- CDN 运营方的运行时完整性（超出 Aegis 控制）
- CDN↔Origin 签名密钥的保密性（HSM 托管 + 24h 轮换）
- CDN 边缘 mTLS 配置的正确性（GitOps + 自动一致性巡检）

因此 L3 的功能面被硬性限制（见 §4.8.4 功能降级清单）：禁止 `RESPONSE_ACTION` / `REMOTE_SHELL`；payload 强制 AES-256-GCM 端到端加密以对 CDN 保密；配备全局 kill-switch。

### 9.2 mTLS 证书处理

#### 9.2.1 证书层次结构

```
Root CA (offline, HSM-stored, 20 年有效期)
  |
  +-- Intermediate CA (online, Vault-managed, 5 年有效期)
       |
       +-- Agent Device Certificates (per-agent)
       |     Validity: 90 days
       |     CN: agent_id
       |     SAN: tenant_id
       |     Key storage: TPM/Secure Enclave (Tier 1) 或 OS keystore (Tier 2)
       |
       +-- Gateway Server Certificates
       |     Validity: 90 days
       |     SAN: *.gateway.aegis.io
       |     Auto-rotated by Vault
       |
       +-- Service Certificates (per-service, Istio managed)
             Validity: 30 days
             CN: service-name.namespace.svc.cluster.local
```

#### 9.2.2 Gateway 侧证书校验

| 校验步骤 | 失败行为 |
|---------|---------|
| 证书链完整性（Root → Intermediate → Agent） | 拒绝连接，记录 tls_handshake_failed |
| 证书有效期 | 拒绝连接，记录 cert_expired |
| CRL 检查（本地缓存 CRL，5 分钟更新） | 拒绝连接，记录 cert_revoked |
| OCSP Stapling（可选补充） | 降级至 CRL 检查 |
| CN 格式校验（agent_id 格式合法性） | 拒绝连接，记录 invalid_cert_cn |
| SAN 格式校验（tenant_id 格式合法性） | 拒绝连接，记录 invalid_cert_san |

#### 9.2.3 证书轮换支持

- Agent 在证书过期前 14 天发起轮换，使用旧证书作为身份凭证提交 CSR
- Gateway 在轮换期间同时接受新旧证书
- 轮换完成后旧证书进入 CRL
- Emergency rotation：云端可通过带外通道触发强制轮换

### 9.3 多租户隔离

| 层 | 隔离机制 |
|----|---------|
| **Agent 证书** | agent_id 和 tenant_id 写入证书，无法冒充其他租户 |
| **Gateway 身份提取** | tenant_id 从 mTLS 证书 SAN 提取，不信任 payload 中自报字段；强制注入到每个事件 |
| **Kafka Topics** | raw-events 按租户独立 topic（raw-events.{tenant}）；共享 topic 使用 tenant_id 作为 message key |
| **速率限制** | 按租户聚合限速，防止单租户耗尽集群资源 |
| **命令隔离** | commands.unicast 按 agent_id 分区；Connection Registry 条目带 tenant_id，Gateway 投递前三方交叉校验 `record.tenant_id == registry.tenant_id == stream.cert_tenant_id`（见 4.5.8） |
| **物理隔离（可选）** | 高安全租户可启用独立 Kafka topics、独立 Gateway 部署 |

### 9.4 STRIDE 威胁模型

**主信任域（L0-L2）**：

| 边界 | 威胁 | 缓解措施 | 残余风险 |
|------|------|---------|---------|
| Agent ↔ Gateway | **Spoofing**（身份冒充） | mTLS + 每 Agent 独立证书；CN=agent_id, SAN=tenant_id | 证书泄露风险，通过 CRL 缓解 |
| Agent ↔ Gateway | **Tampering**（数据篡改） | TLS 1.3 通道加密；Protobuf schema validation；广播 scope 入签名（§12.1.3） | 无（TLS + 签名双保证） |
| Agent ↔ Gateway | **Repudiation**（抵赖） | lineage_id 端到端追踪；服务端 sequence logging | 低（lineage_id 保证可审计） |
| Agent ↔ Gateway | **Info Disclosure**（信息泄露） | TLS 1.3 加密全部传输数据 | TLS 侧信道攻击（极低概率） |
| Agent ↔ Gateway | **DoS**（拒绝服务） | 按 Agent 限速（1000 events/s）；证书吊销；LB 层 DDoS 防护 | 分布式慢速 DoS |
| Agent ↔ Gateway | **Elevation**（权限提升） | Tenant ID 来自证书 SAN 而非 payload；命令签名独立于 Gateway；TargetScope 签名覆盖 | 无（Gateway 无法伪造签名，也无法放大扇出） |
| Gateway ↔ Internal | **Spoofing** | Service mesh mTLS（Istio） | 无 |
| Gateway ↔ Internal | **Tampering** | 服务边界再次执行 Protobuf validation | 低 |

**L3 独立信任域（Domain-Fronted，可选启用）**：

| 边界 | 威胁 | 缓解措施 | 残余风险 |
|------|------|---------|---------|
| Agent ↔ CDN Edge | **Spoofing** | CDN 终结 mTLS + CDN↔Origin 独立签名密钥（HSM，24h 轮换） | CDN 运营方完整性（不可完全消除） |
| CDN ↔ Origin | **Tampering / Spoofing** | Origin 仅接受合法 CDN 签发的 `X-Aegis-L3-Identity` header；双向 mTLS；IP 白名单 | CDN 签名密钥泄漏 → 通过 kill-switch + 24h 轮换收敛 |
| Agent ↔ CDN Edge | **Repudiation** | CDN access log 强制开启；镜像至 Aegis audit-log | 依赖 CDN 日志完整性 |
| Agent ↔ CDN Edge | **Info Disclosure**（CDN 明文可见 payload） | **Agent 启用 AES-256-GCM 端到端加密**，CDN 只见密文 | 密钥协商阶段元数据暴露（连接时间、量级） |
| Agent ↔ CDN Edge | **DoS**（CDN 故障全租户瘫痪） | L3 仅作兜底；主通道持续可用；Agent 本地 WAL | CDN 全区域故障短时丢失 L3 回传可达性 |
| Agent ↔ CDN Edge | **Elevation**（恶意执行 RESPONSE_ACTION） | **Gateway 强制拒绝** `RESPONSE_ACTION` / `REMOTE_SHELL`（§4.8.4）；Response Orchestrator 侧检测 `transport=fronted` 自动延后 | 无（功能面硬性闭合） |
| L3 密钥管理 | **Elevation**（签名密钥泄漏伪造任意身份） | HSM 托管 + 24h 轮换 + 签名审计 + Gateway 白名单热下线 + kill-switch | 单次轮换窗口内的签名可能被重放 60s 内（签名含时间戳） |

### 9.5 DDoS 防护

#### 9.5.1 多层防护体系

```
Layer 1: 网络基础设施
├── ISP/Cloud 提供商的网络层 DDoS 防护
├── BGP Anycast 分散流量
└── WAF (Web Application Firewall) 可选

Layer 2: L4 Load Balancer
├── SYN cookies 防 SYN Flood
├── 半连接队列限制
├── 单 IP 连接数限制 (100)
└── 无效 TLS 握手快速拒绝 (5s timeout)

Layer 3: Gateway 应用层
├── mTLS 强制认证 (无有效证书即拒绝)
├── 按 Agent 速率限制 (Token Bucket)
├── 按 Tenant 聚合速率限制
├── 证书吊销拒绝列表
└── 异常连接模式检测
```

#### 9.5.2 攻击场景与应对

| 攻击类型 | 应对措施 |
|---------|---------|
| SYN Flood | LB SYN cookies + 半连接限制 |
| TLS 握手消耗 | 握手超时 5s + 单 IP 连接限制 |
| 无效证书轰炸 | 快速拒绝 + IP 临时封禁 |
| 合法 Agent 异常大量上报 | 按 Agent 限速 + 严格不丢弃（整批 NACK）+ 连接级熔断（见 4.6.2.2） |
| 被攻破 Agent 发起 DoS | 证书吊销 + IP/Agent 封禁 |
| Kafka 慢写导致连接堆积 | 背压传导 + 连接级 timeout |

### 9.6 审计

| 审计事件 | 记录内容 | 存储 |
|---------|---------|------|
| 连接建立 | agent_id, tenant_id, source_ip, cert_serial, timestamp | Kafka audit-log topic |
| 连接断开 | agent_id, reason, duration, events_processed | Kafka audit-log topic |
| 认证失败 | source_ip, failure_reason, cert_details | Kafka audit-log topic + 告警 |
| 限速触发 | agent_id, tenant_id, current_rate, limit | Prometheus metrics + 日志 |
| 命令投递 | command_id, agent_id, tenant_id, command_type, delivery_time | Kafka audit-log topic |
| 管理操作 | operator, action, target, timestamp | Kafka audit-log topic |

---

<a id="10-部署与运维"></a>
## 10. 部署与运维

### 10.1 K8s 部署拓扑

```yaml
# Gateway Deployment 核心配置
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ingestion-gateway
spec:
  replicas: 5  # per AZ, 15+ total
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 2
  template:
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - topologyKey: topology.kubernetes.io/zone
              # 确保 pods 跨 AZ 分布
      containers:
        - name: gateway
          resources:
            requests:
              cpu: "4"
              memory: "8Gi"
            limits:
              cpu: "8"
              memory: "16Gi"
          ports:
            - containerPort: 8443  # gRPC (mTLS)
            - containerPort: 8080  # Admin/Health
            - containerPort: 9090  # Prometheus metrics
          livenessProbe:
            grpc:
              port: 8443
            initialDelaySeconds: 10
            periodSeconds: 15
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5
      terminationGracePeriodSeconds: 30
```

**Pod Disruption Budget**：
```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: gateway-pdb
spec:
  minAvailable: "67%"  # 至少 2/3 pods 存活
  selector:
    matchLabels:
      app: ingestion-gateway
```

### 10.2 扩缩容策略

| 指标 | 扩容触发 | 缩容触发 | 类型 | 冷却期 |
|------|---------|---------|------|--------|
| gRPC connection count | > 12,000/pod | < 6,000/pod | HPA（**主触发**） | 扩 60s / 缩 600s |
| CPU utilization | > 60% 持续 3min | < 30% 持续 10min | HPA | 扩 60s / 缩 300s |
| Memory utilization | > 75% 持续 5min | < 40% 持续 15min | HPA | 扩 60s / 缩 300s |
| Reconnect storm detection | 新建连接速率 > 30k/s 持续 30s | — | 预扩容脚本（见 10.2.1） | — |

> **为什么连接数是主触发**：Gateway 是连接密集型负载（每条常驻 gRPC 流占用固定 heap、goroutine、内核 fd 资源），CPU 会在连接数逼近上限前仍保持低位。仅用 CPU 触发会错过连接风暴（AZ 失效后 30% Agent 同时重连）。因此将 `grpc_connections_active` 作为 HPA 主指标，CPU/Memory 作为辅助保护。

**HPA 配置**：
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: gateway-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ingestion-gateway
  minReplicas: 90     # 3 AZ × 30 pods (1M 稳态连接 + 单 AZ 失效后剩余 60 pods 仍能承载)
  maxReplicas: 150    # 3 AZ × 50 pods (reconnect storm + 租户突增保护头寸)
  metrics:
    - type: Pods
      pods:
        metric:
          name: grpc_connections_active
        target:
          type: AverageValue
          averageValue: "12000"  # 16k 硬上限的 75%，扩容在达到硬上限前启动
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 60
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 75
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
        - type: Percent
          value: 50            # 单次最多扩 50%（90→135 / 3min）
          periodSeconds: 60
        - type: Pods
          value: 30            # 或一次最多新增 30 pods，取二者最大
          periodSeconds: 60
      selectPolicy: Max
    scaleDown:
      stabilizationWindowSeconds: 600   # 缩容更保守，避免震荡
      policies:
        - type: Percent
          value: 10            # 单次最多缩 10%
          periodSeconds: 300
```

#### 10.2.1 Reconnect Storm 预扩容

当单 AZ 失效时，该 AZ 的 ~33% Agent 会在 30-120s 内向剩余 AZ 重连。剩余 pods 在 HPA 反应前可能瞬间过载。应对：

- **预扩容脚本**：监听 K8s node condition 或云商 AZ 事件，检测到 AZ 不可用时立即将 `minReplicas` 从 90 临时提升到 135（+50%），绕过 HPA 反应时间；AZ 恢复后 30min 恢复
- **连接建立速率限制（LB 层）**：单 pod 新建连接 `accept rate ≤ 500 conn/s`，超限返回 TCP RST-retry，Agent 本地指数退避 jitter 重连（参见 `aegis-sensor-architecture.md` 通信模块），避免雪崩
- **证书缓存预热**：mTLS session ticket 跨 AZ 共享（Redis 缓存），降低 resumption 握手成本，缩短风暴响应时间

### 10.3 灰度发布

#### 10.3.1 Canary 部署策略

```
阶段 1: Canary 5%          2h   观察 error rate, latency, throughput
阶段 2: Blue-Green 25%     4h   观察全量指标 + Agent 兼容性
阶段 3: Rolling 50%        12h  分 AZ 逐步替换
阶段 4: Full rollout 100%  持续  全量替换完成
```

#### 10.3.2 回滚判据

任一条件触发自动回滚：
- Error rate > 0.1% 持续 5min
- P99 latency > 30ms 持续 5min
- Kafka produce failure rate > 1% 持续 3min
- gRPC connection failure rate > 0.5% 持续 3min
- Agent heartbeat loss rate > 1% 持续 5min

#### 10.3.3 流量分割

通过 Istio VirtualService 实现精确的流量权重控制：
- Canary pod 使用独立 Deployment + Service
- Istio DestinationRule 按权重分流
- 可按 tenant_id header 精确控制哪些租户走 Canary

### 10.4 容量规划

#### 10.4.1 Gateway Pod 数量（连接预算驱动）

> **基线原则**：Gateway 是连接密集型负载，容量规划**必须**以连接数为主约束，吞吐/CPU 为次约束。历史草案曾错误地按吞吐推算 20-30 pods，这无法支撑连接 SLO 与 AZ 失效头寸。

**输入参数**：

| 参数 | 值 | 来源 |
|------|------|------|
| 全量 Agent 数 | 1,000,000 | 企业目标规模 |
| 活跃连接比例（稳态 P50） | 70% → 700k | 经验值：夜间/维护窗口 |
| 活跃连接比例（峰值 P99） | 90% → 900k | 工作日高峰 |
| 单 pod 连接 HPA target | 12,000 | 16k 硬上限 × 75%，留 25% 余量 |
| AZ 数 | 3 | 部署约束 |
| 单 AZ 失效后允许利用率 | ≤ 85% | SLO："单 AZ 故障不影响服务" 的硬约束 |

**推导（以峰值 900k active 为基准）**：

```
# 1. 稳态 pod 数（所有 AZ 在线）
pods_steady = ceil(active_peak / hpa_target_per_pod)
            = ceil(900,000 / 12,000)
            = 75 pods

# 2. AZ 失效后的剩余容量约束：丢失 1/3 pods 后利用率 ≤ 85%
#    设全量 pods = N，丢失 1 AZ 后剩余 (2/3)N pods 须承载 900k 连接，
#    每 pod ≤ 16,000 × 85% = 13,600
pods_az_survive = ceil(900,000 / 13,600 / (2/3))
                = ceil(66.2 / 0.667)
                = 100 pods

# 3. Reconnect storm 头寸：AZ 失效瞬间 ~30% agent 重连，剩余 pods 短时过载保护
#    HPA + 预扩容脚本最高扩到 150 pods

# 4. 最终部署参数
minReplicas = 90     (3 AZ × 30，介于 pods_steady=75 与 pods_az_survive=100 之间，
                     依赖预扩容脚本在 AZ 失效时立即顶到 135)
maxReplicas = 150    (3 AZ × 50)

# 吞吐校验（次约束）
events_per_pod = 8,300,000 / 90 ≈ 92k events/s
                 远低于单 pod 1M events/s 能力，CPU 将处于低位
```

**结论**：
- 稳态：90 pods（3 AZ × 30）
- AZ 失效 + 重连风暴：预扩容脚本瞬时 → 135 pods，HPA 进一步扩至 150 pods
- AZ 恢复：30min 冷却后回落至 90 pods
- 所有数字与 Section 2.2（单 pod 16k 连接）、2.3（每 AZ 至少 30 pods）、10.2（HPA 边界）保持一致

#### 10.4.2 Kafka 集群

```
kafka_brokers = ceil(10 GB/s / 800 MB/s) = 13 → 15 (5 per AZ)
kafka_storage = 5 TB/day × 3 days × 3 replicas / 15 = 3 TB/broker
kafka_memory  = 32 GB/broker (JVM heap 6G + page cache 26G)
kafka_cpu     = 16 cores/broker
kafka_network = 10 Gbps/broker
```

#### 10.4.3 网络带宽

```
Agent → LB:       ~330 MB/s (压缩后)
LB → Gateway:     ~330 MB/s
Gateway → Kafka:  ~1.66 GB/s (解压后 + 富化)
Kafka internal:   ~5 GB/s (含 3x 复制)
跨 AZ 带宽需求:   ~3.3 GB/s (2/3 的复制流量跨 AZ)
总出口带宽:       >= 50 Gbps
```

---

<a id="11-可观测性"></a>
## 11. 可观测性

### 11.1 指标（Prometheus Metrics）

#### 11.1.1 连接指标

| 指标名称 | 类型 | 标签 | 说明 |
|---------|------|------|------|
| gateway_grpc_connections_active | Gauge | az, pod | 当前活跃 gRPC 连接数 |
| gateway_grpc_connections_total | Counter | az, pod, status | 累计连接数（success/failed） |
| gateway_tls_handshake_duration_seconds | Histogram | az, result | TLS 握手延迟分布 |
| gateway_tls_handshake_failures_total | Counter | az, reason | TLS 握手失败计数（按原因） |
| gateway_cert_revocation_rejections_total | Counter | az, tenant | 证书吊销拒绝计数 |

#### 11.1.2 吞吐指标

| 指标名称 | 类型 | 标签 | 说明 |
|---------|------|------|------|
| gateway_events_received_total | Counter | az, pod, tenant, priority | 接收事件总数 |
| gateway_events_produced_total | Counter | az, pod, topic, status | Kafka 生产事件总数 |
| gateway_batches_processed_total | Counter | az, pod, stream_type | 处理的 batch 总数 |
| gateway_bytes_received_total | Counter | az, pod | 接收字节总数（压缩后） |
| gateway_bytes_produced_total | Counter | az, pod | Kafka 写入字节总数 |

#### 11.1.3 延迟指标

| 指标名称 | 类型 | 标签 | 说明 |
|---------|------|------|------|
| gateway_batch_processing_duration_seconds | Histogram | az, pod, step | 单 batch 各步骤处理延迟 |
| gateway_kafka_produce_duration_seconds | Histogram | az, pod, topic, acks | Kafka 生产延迟 |
| gateway_enrichment_duration_seconds | Histogram | az, pod, step | 富化各步骤延迟 |

#### 11.1.4 错误指标

| 指标名称 | 类型 | 标签 | 说明 |
|---------|------|------|------|
| gateway_errors_total | Counter | az, pod, type | 错误总数（按类型） |
| gateway_schema_validation_failures_total | Counter | az, pod, event_type | Schema 校验失败 |
| gateway_rate_limit_rejections_total | Counter | az, pod, tenant, level | 限速拒绝计数 |
| gateway_enrichment_failures_total | Counter | az, pod, step | 富化步骤失败（降级处理） |

#### 11.1.5 Kafka Producer 指标

| 指标名称 | 类型 | 标签 | 说明 |
|---------|------|------|------|
| gateway_kafka_producer_buffer_bytes | Gauge | az, pod, producer_type | Producer buffer 使用量 |
| gateway_kafka_producer_inflight_requests | Gauge | az, pod, producer_type | 进行中的请求数 |
| gateway_kafka_producer_retries_total | Counter | az, pod, topic | Producer 重试次数 |

#### 11.1.6 命令下发指标

| 指标名称 | 类型 | 标签 | 说明 |
|---------|------|------|------|
| gateway_commands_delivered_total | Counter | az, pod, command_type | 命令投递总数 |
| gateway_commands_delivery_duration_seconds | Histogram | az, pod | 命令投递延迟 |
| gateway_commands_unroutable_total | Counter | az, pod | 目标 Agent 不在本 pod 的命令数 |

### 11.2 分布式追踪

#### 11.2.1 Jaeger 集成

- Gateway 为每个 EventBatch 创建 span，span 名称为 `gateway.process_batch`
- 子 span：`gateway.decompress`、`gateway.validate`、`gateway.enrich`、`gateway.produce`
- lineage_id 作为 baggage item 注入 trace context，贯穿全链路
- trace 采样率：生产环境 1%（CRITICAL 事件 100% 采样）

#### 11.2.2 lineage_id 关联

```
Agent                  Gateway                 Flink              ClickHouse
  |                      |                       |                    |
  |-- lineage_id ------->|                       |                    |
  |   checkpoint 1-6     |-- checkpoint 7 ------>|                    |
  |   (agent 内部)       |   gateway_received    |-- checkpoint 8 -->|
  |                      |                       |   flink_processed  |-- checkpoint 9
  |                      |                       |                    |   ch_stored
```

lineage_id 编码：`agent_id[64bit] | timestamp_ns[48bit] | sequence[16bit]`

通过 lineage_id 可追踪任意事件从 Agent 内核态采集到 ClickHouse 持久化的完整路径，用于：
- 事件丢失排查（对比各检查点计数）
- 端到端延迟分析（各检查点时间戳差值）
- 数据完整性审计

### 11.3 日志

#### 11.3.1 结构化 JSON 日志

```json
{
  "timestamp": "2026-04-11T10:30:00.123Z",
  "level": "INFO",
  "service": "ingestion-gateway",
  "pod": "gateway-az-a-0",
  "az": "az-a",
  "msg": "batch processed",
  "agent_id": "agt-xxxxx",
  "tenant_id": "tnt-yyyyy",
  "batch_size": 250,
  "duration_ms": 4.2,
  "kafka_topic": "raw-events.tnt-yyyyy",
  "lineage_id": "abc123...",
  "trace_id": "def456..."
}
```

#### 11.3.2 日志级别

| 级别 | 用途 | 生产环境默认 |
|------|------|------------|
| ERROR | 影响数据完整性的错误（Kafka 生产失败、证书校验异常） | 开启 |
| WARN | 降级行为（Redis 不可用跳过富化、限速触发） | 开启 |
| INFO | 连接建立/断开、批量处理摘要 | 开启（采样） |
| DEBUG | 每事件级处理细节 | 关闭 |

#### 11.3.3 敏感数据脱敏

- Agent 证书 serial number：保留末 8 位
- IP 地址：保留前 3 段（如 192.168.1.x）
- tenant_id：完整记录（运维必需）
- 事件 payload：日志中不记录完整事件内容

### 11.4 SLO 与告警

| SLO | 目标 | 告警阈值 | 告警级别 |
|-----|------|---------|---------|
| 数据接入可用性 | 99.99% | Error rate > 0.01% 持续 5min | P1 (PagerDuty) |
| Gateway batch 处理延迟 P99 | < 15ms | P99 > 20ms 持续 5min | P2 |
| Kafka produce 成功率 | 99.99% | Failure rate > 0.01% 持续 3min | P1 |
| gRPC 连接成功率 | 99.9% | Failure rate > 0.1% 持续 5min | P2 |
| Agent 心跳丢失率 | < 0.5% | Loss rate > 1% 持续 10min | P2 |
| Kafka consumer lag (commands) | < 1000 | Lag > 5000 持续 5min | P2 |
| Pod CPU utilization | < 60% (均值) | > 80% 持续 5min | P3 (HPA 应已介入) |

**告警通道**：

| 级别 | 通道 | 响应时间 |
|------|------|---------|
| P1 | PagerDuty + Slack #soc-critical | < 5min |
| P2 | Slack #soc-alerts + Email | < 30min |
| P3 | Slack #infra-alerts | 下一工作日 |

---

<a id="12-接口定义"></a>
## 12. 接口定义

### 12.1 Agent ↔ Gateway 接口

#### 12.1.1 gRPC 服务定义

以下接口与 `aegis-sensor-architecture.md` 第 4.5.5 节和第 9.2 节完全对齐：

```protobuf
service AgentService {
  // 双向流：上行 EventEnvelope（EventBatch or BatchAck 回执是通过 server→client 方向的
  // 独立消息类型传回；下行 SignedServerCommand 走同一方向），
  // 多路复用为 UplinkMessage / DownlinkMessage 包络
  rpc EventStream(stream UplinkMessage) returns (stream DownlinkMessage);

  // 单次调用：Agent 健康心跳
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);

  // 客户端流：取证包/内存 dump 上传
  rpc UploadArtifact(stream ArtifactChunk) returns (UploadResult);

  // 服务端流：规则/模型/安装包下载
  rpc PullUpdate(UpdateRequest) returns (stream UpdateChunk);
}

message UplinkMessage {
  oneof kind {
    EventBatch      event_batch = 1;
    ClientAck       client_ack  = 2;  // Agent 确认收到/执行了下行命令
  }
}

message DownlinkMessage {
  oneof kind {
    BatchAck             batch_ack      = 1;  // Gateway 对 EventBatch 的回执（见 12.1.5）
    SignedServerCommand  server_command = 2;  // 下行命令（见 12.1.3）
    FlowControlHint      flow_hint      = 3;  // 软背压提示（retry_after_ms 等）
  }
}
```

#### 12.1.2 上行接口规格

| 接口 | 协议 | 数据格式 | 频率/触发 | 压缩 | 回执 |
|------|------|---------|---------|------|------|
| EventStream (上行) | gRPC bidirectional stream | UplinkMessage（含 EventBatch / ClientAck） | 连续流 | LZ4（EventBatch） | 每 EventBatch 对应一条 BatchAck（见 12.1.5） |
| Heartbeat | gRPC unary | Protobuf HeartbeatRequest | 每 60s | 无 | HeartbeatResponse |
| UploadArtifact | gRPC client stream | Protobuf ArtifactChunk | 按需 | 无 | UploadResult |
| PullUpdate | gRPC server stream | Protobuf UpdateChunk | 按需 | LZ4 | — |

#### 12.1.3 下行命令接口

所有下行命令通过 EventStream 双向流的 server→client 方向，以 SignedServerCommand 封装投递：

```protobuf
message SignedServerCommand {
  bytes   payload       = 1;  // ServerCommand 序列化字节
  bytes   signature     = 2;  // Ed25519 签名 (覆盖 payload 全部字节)
  string  signing_key_id = 3; // 签名密钥 ID (密钥轮换)
}

message ServerCommand {
  string  command_id    = 1;  // UUIDv7, 防重放主键
  string  tenant_id     = 2;
  string  agent_id      = 3;  // unicast 目标；broadcast 可为空，由 target_scope 决定
  CommandType type      = 4;
  bytes   command_data  = 5;  // 命令载荷
  int64   issued_at     = 6;  // 签发时间戳 (Unix ms)
  uint32  ttl_ms        = 7;  // 命令有效期 (相对 TTL)
  uint64  sequence_hint = 8;  // 排序辅助
  ApprovalPolicy approval = 9; // 审批策略
  TargetScope target_scope = 10;  // **签名覆盖**的投递作用域（见下）
}

// 目标作用域是签名的一部分，决定命令允许扩散的范围；
// Gateway 只能**收窄**而不得扩大：任何越出 target_scope 的投递都违反契约。
message TargetScope {
  enum Kind {
    AGENT      = 0;  // 仅该 agent_id，必须匹配 ServerCommand.agent_id
    TENANT     = 1;  // 该 tenant_id 下的所有 agent
    AGENT_SET  = 2;  // 显式枚举 agent_ids
    GLOBAL     = 3;  // 所有租户（仅平台管理员可签发；生产环境默认禁用）
  }
  Kind           kind       = 1;
  string         tenant_id  = 2;        // Kind != GLOBAL 时必填；与 ServerCommand.tenant_id 一致
  repeated string agent_ids = 3;        // Kind == AGENT_SET 时必填
  uint32          max_fanout = 4;       // 签发方声明的上限，Gateway 必须校验 |targets| ≤ max_fanout
}
```

**Gateway 在命令投递中的角色**：纯透传 + 收窄路由。

1. Gateway 仍然不解析 `command_data`，也不修改 `signature` / `payload` / `signing_key_id`。
2. **但 Gateway 必须解码 `ServerCommand.target_scope` 与 `tenant_id`**（这两个字段位于已签名的 `payload` 内），并将其作为路由的**唯一授权依据**。Kafka header 的 `scope` 仅作缓存/预过滤提示，不得作为扩散依据。
3. 路由规则：
   - Gateway 推导出的投递目标集合必须是 `target_scope` 表达集合的**子集**（collect ∩ pod-local connections）；`|delivered| ≤ target_scope.max_fanout`。
   - 若 Kafka header scope 与 `target_scope` 冲突，Gateway 以 `target_scope` 为准并生成 `scope_header_mismatch` 审计事件（STRIDE Tampering）。
   - Gateway 对非法组合（`GLOBAL` 未开启、`AGENT_SET` 超过 `max_fanout`、`tenant_id` 与 Kafka record tenant 不一致）整批丢弃并写 `commands.dead-letter`，不得降级投递。
4. Agent 侧验签后**再次校验** `target_scope` 是否包含本机身份（`tenant_id` 必须匹配、`agent_ids` 包含本机 / `TENANT` 匹配 / `AGENT` 精确匹配）；不匹配即视为越权扇出并丢弃 + 本地审计上报，即便签名有效。

> **为什么 scope 必须入签名**：若 scope 只靠 Kafka header 承载，攻破生产方主题权限或中间转发链路的任一环节即可将 `agent_set` 放大为 `tenant` / `global`。当前模型把扩散边界绑定到 Ed25519 签名覆盖，使 Gateway 和中间链路即使被攻破也无法扩大扇出面。

#### 12.1.4 命令类型列表

| 命令类型 | 说明 | 安全等级 |
|---------|------|---------|
| RESPONSE_ACTION | 响应动作（kill/quarantine/isolate/rollback/forensics） | 高危 |
| REMOTE_SHELL | 远程 Shell 会话 | 最高危 |
| POLICY_UPDATE | 策略更新推送 | 高危 |
| RULE_UPDATE | 规则/模型热更新 | 高危 |
| IOC_UPDATE | IOC 增量更新 | 常规 |
| FEEDBACK | 误报反馈/调优指令 | 常规 |
| REQUEST_PROCESS_INFO | 请求补发进程信息 | 常规 |
| CONFIG_CHANGE | 配置变更 | 高危 |

#### 12.1.5 EventBatch 准入契约（BatchAck）

与 4.6.2.1 "严格不丢弃契约" 对齐。每个上行 `EventBatch` 必须且只能收到一个 `BatchAck`。

```protobuf
message EventBatch {
  string  batch_id        = 1;  // UUIDv7；Agent 端生成，用于 ack 关联和去重
  uint64  sequence_id     = 2;  // per-agent 单调递增；Gateway + Kafka 上游按此去重
  uint32  event_count     = 3;
  bytes   compressed_events = 4;  // LZ4(Protobuf TelemetryEvent[])
  Priority priority       = 5;    // LOW / INFO / MEDIUM / HIGH / CRITICAL
  int64   batched_at      = 6;    // Agent 打包时间（Unix ms）
}

message BatchAck {
  string  batch_id        = 1;    // 回执关联的上行 batch
  uint64  sequence_id     = 2;    // 回执关联的 sequence_id
  Status  status          = 3;
  uint32  retry_after_ms  = 4;    // 仅在 status != ACCEPTED 时有意义；Agent 必须遵守
  string  reason          = 5;    // 可选人类可读说明（仅用于日志，不解析）
  int64   acked_at        = 6;    // Gateway ack 时间（Unix ms），用于端到端延迟统计

  enum Status {
    ACCEPTED                  = 0;  // 已持久化至 Kafka（acks=all + ISR 同步完成）；Agent 推进 sequence_id
    REJECTED_RATE_LIMIT       = 1;  // 触发 per-agent / per-tenant 限速，整批拒绝；Agent 不推进 sequence_id
    REJECTED_BACKPRESSURE     = 2;  // 下游（Kafka produce / 富化管道）背压；Agent 不推进 sequence_id
    REJECTED_MALFORMED        = 3;  // Protobuf 解析失败 / schema 不匹配；Agent 不应重传，需上报异常
    REJECTED_AUTH             = 4;  // 证书/租户不匹配；Agent 应重新 bootstrap
    REJECTED_QUOTA_EXCEEDED   = 5;  // 租户级配额已耗尽（见 4.6.3），大时间窗口退避
    // 保留槽位：ACCEPTED_NONDURABLE = 6;
    // 仅在未来引入显式弱持久化通道时启用；启用后 Agent 不得推进 sequence_id，
    // 且该 batch 的 durability 责任仍保留在 Agent WAL 侧。当前版本不使用。
  }
}

message ClientAck {
  string  command_id      = 1;    // Agent 对下行命令的接收/执行回执
  Status  status          = 2;
  string  error_detail    = 3;    // 失败时填充，审计用
  int64   acked_at        = 4;

  enum Status {
    RECEIVED   = 0;
    EXECUTED   = 1;
    REJECTED   = 2;  // 验签失败 / tenant 不匹配 / 超 TTL
    FAILED     = 3;  // 执行错误
  }
}

message FlowControlHint {
  uint32  suggested_rate_eps    = 1;  // 建议发送速率（events/s）；0 表示无限制
  uint32  cooldown_ms           = 2;  // 建议冷却时间
  string  reason                = 3;
}
```

**回执时序契约**：
- Gateway 必须在接收 EventBatch 后 **500ms 内** 发出 BatchAck（目标 P99 < 15ms），即使是 REJECTED 也必须回执
- Agent 等待 BatchAck 超时（默认 5s）后视为连接失效，关闭 stream 并重连；重连后按 sequence_id 回放 WAL 中未 ack 的 batch
- sequence_id 语义：ACCEPTED 后 Agent 推进本地 sequence_id；任何 REJECTED 都不推进（见 4.6.2.1 不变量）
- Gateway / Kafka 上游按 `(agent_id, sequence_id)` 去重，幂等重传不会导致重复入库

**禁止的行为**：
- 不允许 Gateway 接收 EventBatch 后不发送 BatchAck（无论成功/失败都必须回执）
- 不允许 Gateway 返回 ACCEPTED 但部分事件未落库（all-or-nothing 语义）
- 不允许 Agent 在收到非 ACCEPTED 回执后推进 sequence_id

### 12.2 Gateway → Kafka 接口

#### 12.2.1 消息格式

| 字段 | 内容 |
|------|------|
| Topic | raw-events.{tenant_id}、enriched-events、audit-log 等 |
| Key | agent_id（raw-events）/ event_type（enriched）/ tenant_id（audit） |
| Value | Protobuf 序列化的富化后 TelemetryEvent |
| Headers | lineage_id, priority, event_type, gateway_pod, gateway_timestamp |
| Compression | LZ4 (Kafka producer 侧) |

#### 12.2.2 Partition Key 策略

| Topic | Partition Key | 理由 |
|-------|-------------|------|
| raw-events.{tenant} | hash(agent_id) | 同一 Agent 事件保持分区内有序 |
| enriched-events | hash(event_type) | 按类型消费优化 |
| detections | hash(severity) | 优先消费高严重度 |
| commands.unicast | hash(agent_id) | Gateway 通过 Connection Registry 按 Agent 路由；shared consumer group + Inter-Pod 转发（4.5.4-4.5.5） |
| commands.broadcast | round-robin | 每个 Gateway pod 独立 consumer group 消费全部副本（4.5.6） |
| commands.pending | hash(agent_id) | 未投递命令补投队列（4.5.7） |
| commands.dead-letter | hash(agent_id) | TTL 过期命令归档 |
| audit-log | hash(tenant_id) | 按租户审计 |

### 12.3 内部管理接口

#### 12.3.1 健康检查端点

| 端点 | 端口 | 方法 | 说明 |
|------|------|------|------|
| /healthz | 8080 | GET | Liveness：进程存活检查 |
| /readyz | 8080 | GET | Readiness：就绪检查（含 Kafka 连通性） |
| /metrics | 9090 | GET | Prometheus 指标导出 |

#### 12.3.2 运维诊断端点

| 端点 | 端口 | 方法 | 说明 |
|------|------|------|------|
| /debug/connections | 8080 | GET | 活跃连接列表（agent_id, tenant_id, duration, events_count） |
| /debug/kafka | 8080 | GET | Kafka producer 状态（buffer usage, inflight, errors） |
| /debug/ratelimit | 8080 | GET | 限速状态（per-agent, per-tenant 当前令牌） |
| /admin/reload | 8080 | POST | 热加载配置（GeoIP DB, CRL, 限速参数） |
| /admin/drain | 8080 | POST | 手动触发连接排水 |

**安全约束**：管理端点仅暴露在 K8s 集群内部网络（ClusterIP），不通过 LB 对外暴露。敏感操作（reload, drain）需通过 service mesh mTLS 认证。

---

<a id="13-技术选型说明"></a>
## 13. 技术选型说明

### 13.1 Gateway 语言：Go

| 方面 | 说明 |
|------|------|
| **选择理由** | goroutine 并发模型天然适合 per-connection 处理（100 万连接 → 100 万 goroutine，开销可控）；成熟的 gRPC-Go 生态；快速编译部署（单二进制，< 30s 编译）；丰富的网络库（net/http2, crypto/tls）；GC 暂停可控（< 1ms with GOGC tuning） |
| **性能适配** | Gateway 是 I/O 密集型（网络收发 + Kafka 写入），非 CPU 密集型；Go 的 I/O 调度器在此场景下性能优异 |
| **团队效率** | 相比 Rust 降低学习曲线；相比 Java 减少内存占用和启动时间 |
| **备选淘汰** | **Rust**：性能更高但开发效率低，Gateway 非安全敏感组件（不执行检测/响应），内存安全收益较 Agent 低。**Java/Kotlin (Netty)**：内存占用高（JVM heap），启动慢，GC 暂停在高连接数下难以控制。**C++**：开发效率低，内存安全风险，不适合快速迭代。**Node.js**：单线程模型不适合 CPU 密集的 Protobuf 解析/压缩 |

### 13.2 负载均衡：Envoy vs HAProxy

| 维度 | Envoy | HAProxy |
|------|-------|---------|
| gRPC 支持 | 原生 L7 gRPC-aware | 需 L4 TCP 模式 |
| 动态配置 | xDS API（与 Istio 集成） | 需 reload |
| 可观测性 | 内建 Prometheus、Jaeger、access log | 基础统计 |
| Service Mesh | 与 Istio sidecar 无缝集成 | 需额外适配 |
| 性能 | 优秀（C++ 实现） | 极致（C 实现） |
| 社区 | CNCF 毕业项目 | 长期生产验证 |
| **选择** | **首选**（生态集成优势） | 备选（极致性能场景） |

### 13.3 消息队列：Kafka vs 备选

| 维度 | Kafka | Pulsar | NATS JetStream | RabbitMQ |
|------|-------|--------|----------------|----------|
| 吞吐 | 极高（10 GB/s+） | 高 | 高 | 中 |
| 持久性 | ISR 复制 | BookKeeper | RAFT | 镜像队列 |
| 保留与回放 | 原生 72h+ | 原生 | 有限 | 不支持 |
| 分区有序 | 是 | 是 | 是 | 否（默认） |
| 生态 | 极成熟（Flink/Connect） | 成熟 | 新兴 | 成熟 |
| 运维复杂度 | 中（ZooKeeper/KRaft） | 高（BookKeeper） | 低 | 低 |
| **选择** | **首选**（吞吐 + 生态 + 回放能力） | | | |

**Kafka 选择理由**：
- 8.3M events/sec 的吞吐需求排除了 RabbitMQ
- 72h 保留 + 可重放特性是 Flink 流处理的关键依赖（规则更新后可重新处理历史事件）
- 分区内有序保证支持按 Agent 的事件关联
- Flink 原生 Kafka connector 支持 exactly-once 语义
- 成熟的多 AZ 部署和运维实践

### 13.4 GeoIP 数据库：MaxMind

| 维度 | MaxMind GeoIP2 | IP2Location | DB-IP |
|------|---------------|-------------|-------|
| 准确度 | 城市级 ~80% | 城市级 ~75% | 城市级 ~70% |
| 更新频率 | 每周 | 每月 | 每月 |
| 格式 | MMDB (mmap 友好) | BIN | MMDB |
| 性能 | < 1us/lookup (mmap) | < 1us | < 1us |
| 许可 | 商业/免费版 | 商业 | 商业/免费版 |
| **选择** | **首选**（准确度 + MMDB 格式 + 行业标准） | | |

---

## 附录 A：与其他文档的交叉引用

| 本文档章节 | 引用文档 | 引用章节 | 说明 |
|-----------|---------|---------|------|
| 4.2 gRPC 服务端点 | aegis-sensor-architecture.md | 4.5.5, 9.2 | Agent 侧接口定义，Gateway 必须兼容 |
| 4.5 命令路由 | aegis-sensor-architecture.md | 4.5.5 | SignedServerCommand 协议和验签流程 |
| 5.3 Heartbeat | aegis-sensor-architecture.md | 8.5 | HeartbeatRequest.AgentHealth 字段定义 |
| 6.1 热路径延迟 | aegis-architecture-design.md | 3.2 | 端到端延迟预算分解 |
| 7 背压设计 | aegis-architecture-design.md | 5.3 | 全链路背压机制 |
| 8 韧性设计 | aegis-architecture-design.md | 6.2-6.4 | 多 AZ、熔断、重试、防丢失 |
| 9 安全设计 | aegis-architecture-design.md | 7.1-7.3 | 信任边界、STRIDE、多租户 |
| 10 部署 | aegis-architecture-design.md | 8.1-8.3 | K8s 拓扑、容量公式、HPA |
| 11 可观测性 | aegis-architecture-design.md | 8.4 | 可观测性栈、SLO |

---

## 附录 B：术语表

| 术语 | 说明 |
|------|------|
| Agent | 部署在终端的 Aegis Sensor 进程 |
| EventBatch | 一组遥测事件的 Protobuf 打包，100-500 事件/batch |
| SignedServerCommand | Ed25519 签名封装的下行命令 |
| lineage_id | 端到端事件追踪标识符，128bit |
| WAL | Write-Ahead Log，Agent 侧的离线事件缓冲 |
| ISR | In-Sync Replicas，Kafka 同步副本集 |
| mTLS | mutual TLS，双向 TLS 认证 |
| HPA | Horizontal Pod Autoscaler |
| PDB | Pod Disruption Budget |
| Semi-Trusted | Gateway 所在的信任区域，可读取数据但不可伪造签名 |

---

*文档版本: v1.1 | 本文档基于 aegis-architecture-design.md v1.0 和 aegis-sensor-architecture.md v1.0 的设计参数编写，全部技术指标均从源文档推导而非估算。*

*v1.1 变更（2026-04-18）：融合 Codex 对抗评审的 4 项架构级发现——① 4.5 下行通道改为 Connection Registry 所有权模型 + Inter-Pod 转发（unicast）与 per-pod 消费组（broadcast）；② 重算容量基线（单 pod 16k 连接 / 8vCPU 16GB；minReplicas=90，maxReplicas=150；AZ 失效头寸硬约束）；③ 4.6 限速契约改为严格不丢弃（BatchAck all-or-nothing + sequence_id 幂等重传）；④ 新增 4.8 Fallback Transport 子系统（L1 WebSocket / L2 Long-Polling / L3 Domain Fronting，应用层语义与 gRPC 主通道等价）。*
