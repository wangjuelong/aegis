# EDR Transport Plane 技术解决方案
## Production-Grade Ingestion Gateway & Event Bus Technical Specification
> 本文档定义 EDR Transport Plane（Ingestion Gateway + Kafka Event Bus + 下行命令路由 + Fallback 接入）的最终实施方案，覆盖接入、鉴权、富化、上行投递、下行命令、韧性、安全、部署、可观测性与接口契约。
>
> 文档按终态架构组织，直接描述可落地的设计、边界、指标与运维要求，不再区分版本演进路径。
>
> 架构总体描述与跨文档契约以 `docs/architecture/aegis-transport-architecture.md` 为单一事实来源（SSoT）；本文档聚焦**落地细节**（参数、时序、代码骨架、配置清单、诊断脚本）与**运营契约**（SLO、灰度、容量、审计），不做语义推倒重来。冲突以 SSoT 为准。
---
## 一、Transport 总体架构

### 1.1 设计原则

| 原则 | 说明 |
|------|------|
| **无状态** | 每个 Ingestion Gateway pod 可被任意替换；所有必要状态外置到 Connection Registry（Redis Cluster）、Kafka、Policy/Threat Intel 服务 |
| **持久化不妥协** | 所有 Producer `acks=all + enable.idempotence=true + min.insync.replicas=2`；Gateway 仅在 ISR 同步完成后返回 `BatchAck.ACCEPTED`；禁止"fast ack"快速路径 |
| **背压不丢数据** | 过载时整批 NACK（`REJECTED_RATE_LIMIT` / `REJECTED_BACKPRESSURE` / `REJECTED_QUOTA_EXCEEDED`），Agent 保留 WAL 重试；Gateway 不做静默选择性丢弃 |
| **确定性投递** | 下行 unicast 命令走 Connection Registry 所有权模型 + Inter-Pod 转发，**不依赖"广播 + 忽略"** |
| **广播正确性** | 策略/规则/IOC 走 `commands.broadcast` + **每 pod 独立 consumer group**（group_id = `gateway-bcast-{pod_uid}`），保证每个 pod 都收到完整副本 |
| **签名是最终授权** | `ServerCommand.target_scope` 位于签名负载内，Gateway 只能**收窄**扇出；Kafka header 仅为缓存提示，不得扩大扇出面 |
| **零信任透传** | Gateway 不解析 `command_data`、不修改签名、不伪造身份；被攻破也无法驱动 Agent 执行高危动作 |
| **Tenant 来自证书** | Tenant ID 强制从 mTLS 证书 SAN 提取，覆盖 payload 自报字段；防止被攻破的 Agent 冒充其他租户 |
| **语义等价的 Fallback** | L1/L2 Fallback 与 L0 主通道应用层语义完全一致；L3 Domain Fronting 是独立信任域、功能受限、默认禁用 |
| **连接数是主约束** | 容量规划、HPA 触发条件、AZ 失效头寸均以 gRPC 活跃连接数为主指标；CPU/Memory 作为辅助 |
| **可观测** | 全链路 lineage_id 检查点；transport 维度打标（grpc/ws/longpoll/fronted）；`BatchAck` 状态按 reason 分桶 |
| **安全透明** | 广播命令的 `scope_header_mismatch`、L3 的 CDN 签名异常、Gateway 投递违反 `target_scope` 等均产生强制审计事件 |

### 1.2 Pod 内部进程/协程模型

```
┌─────────────────────────────────────────────────────────────────────┐
│  Ingestion Gateway Pod (Go, 8 vCPU, 16GB memory, 1Gbps NIC)          │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │  Entry Adapters (监听层, 独立 listener)                     │     │
│  │  ├── :8443  gRPC over mTLS (L0 主通道)                      │     │
│  │  ├── :8443  WebSocket over mTLS (L1, ALPN 复用)             │     │
│  │  ├── :8080  HTTP Long-Polling (L2)                          │     │
│  │  ├── :8444  L3 Domain-Fronted Adapter (独立证书/策略/端口)   │     │
│  │  ├── :9443  GatewayInternal gRPC (Inter-Pod forward, 集群内) │     │
│  │  └── :9090  Prometheus /metrics                              │     │
│  └────────────────────────────────────────────────────────────┘     │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │  Transport Adapter Layer (归一化为 UplinkMessage/             │     │
│  │  DownlinkMessage，对后端屏蔽 transport 细节)                 │     │
│  └────────────────────────────────────────────────────────────┘     │
│                                                                      │
│  ┌────────────────┐  ┌──────────────┐  ┌──────────────────────┐     │
│  │ mTLS Verifier  │  │ Rate Limiter │  │ Connection Manager   │     │
│  │ + CRL/OCSP     │  │ per-agent    │  │ (生命周期/排水/健康) │     │
│  │ + Tenant 提取  │  │ per-tenant   │  │ + LocalOwnershipCache│     │
│  └────────────────┘  └──────────────┘  └──────────────────────┘     │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │  Enrichment Pipeline (goroutine pool, per-batch)            │     │
│  │  ① LZ4 Decompress                                           │     │
│  │  ② Protobuf Schema Validate                                 │     │
│  │  ③ GeoIP Lookup (MaxMind, mmap)                             │     │
│  │  ④ Asset Tag Lookup (Redis cache)                           │     │
│  │  ⑤ Tenant Metadata Injection (覆盖 payload 自报)            │     │
│  │  ⑥ MITRE ATT&CK TTP Pre-label                               │     │
│  │  ⑦ lineage_id Checkpoint (gateway_received)                 │     │
│  └────────────────────────────────────────────────────────────┘     │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │  Kafka Producer Pool (全部 acks=all + idempotence)           │     │
│  │  ├── High-Priority  (linger.ms=0, in-flight=1)              │     │
│  │  ├── Normal         (linger.ms=5, batch=64KB)               │     │
│  │  ├── Bulk           (linger.ms=10, batch=128KB)             │     │
│  │  └── Transactional  (downlink pending/dead-letter EOS)      │     │
│  └────────────────────────────────────────────────────────────┘     │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │  Downlink Subsystem                                          │     │
│  │  ├── Unicast Consumer  (shared group `gateway-unicast`)      │     │
│  │  ├── Broadcast Consumer(per-pod group `gateway-bcast-{uid}`) │     │
│  │  ├── Pending Dispatcher(Redis ZSET + compacted topic)        │     │
│  │  ├── Connection Registry Client (Redis Cluster)              │     │
│  │  └── Inter-Pod Forwarder (GatewayInternal gRPC :9443)        │     │
│  └────────────────────────────────────────────────────────────┘     │
│                                                                      │
│  ┌────────────────┐  ┌──────────────┐  ┌────────────────────────┐   │
│  │ Health (/healthz│  │ Metrics (/metrics│ Admin (/admin/*        │   │
│  │ /readyz)        │  │ Prometheus)      │ reload / drain)         │  │
│  └────────────────┘  └──────────────┘  └────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

每条 gRPC stream 由独立 goroutine 处理；Kafka Producer 共享 pool 但按优先级分通道。所有 goroutine 使用统一的 `errgroup + ctx` 链路以支持 GOAWAY 和 graceful shutdown。

### 1.3 端到端数据流

```
上行 (Agent → Gateway → Kafka):

Agent                      Gateway                              Kafka
  │                          │                                    │
  │─ EventBatch (LZ4+PB) ────►│                                   │
  │                          │ ① mTLS(ctx) 已验证                 │
  │                          │ ② LZ4 Decompress                   │
  │                          │ ③ Protobuf Schema Validate         │
  │                          │ ④ Enrich (GeoIP/Asset/Tenant/TTP)  │
  │                          │ ⑤ lineage checkpoint #7            │
  │                          │ ⑥ Kafka Produce (acks=all)         │
  │                          │    等待 ISR 同步                   │
  │                          │───────────────────────────────────►│
  │◄─ BatchAck(ACCEPTED) ────│◄── ISR ack (2/3) ──────────────────│
  │                          │                                    │

下行 (Kafka → Gateway → Agent):

Management             Kafka                Gateway                    Agent
  │                      │                    │                          │
  │─ SignedServerCommand ►│                   │                          │
  │                      │─ commands.unicast ►│ Unicast Consumer          │
  │                      │   (shared group)   │ (Kafka 事务边界)         │
  │                      │                    │                          │
  │                      │                    │ ① 读取 target_scope       │
  │                      │                    │ ② Registry lookup owner  │
  │                      │                    │ ③ 分流:                  │
  │                      │                    │   a. owner=self → 本地   │
  │                      │                    │   b. owner=其它 pod →    │
  │                      │                    │      Inter-Pod forward   │
  │                      │                    │   c. 无 owner/失败 →     │
  │                      │                    │      commands.pending    │
  │                      │                    │      (同事务 atomic)     │
  │                      │                    │─ stream.send ──────────►│
  │                      │                    │                          │ 验签
  │                      │                    │                          │ + target_scope
  │                      │                    │                          │ + 去重/TTL
  │                      │                    │                          │ + 执行
```

### 1.4 无状态与即时恢复

Pod 被设计为纯请求处理器；以下表格罗列每类外部状态的归属：

| 状态 | 归属 | 重启后恢复方式 |
|------|------|----------------|
| 活跃 gRPC 连接表 | pod 本地内存 | 连接随 pod 消亡；Agent 收到 GOAWAY 后自行重连到新 pod |
| LocalOwnershipCache | pod 本地内存 (lease=60s) | 新连接重新登记；不跨 pod |
| Connection Registry | Redis Cluster (跨 pod 视图) | 条目 TTL=48h；心跳续期；Lua CAS 防覆盖 |
| Unicast Consumer 位点 | Kafka `__consumer_offsets` + 事务 | pod 重启后 group rebalance 自动接管 |
| Broadcast Consumer 位点 | Kafka（pod 专属 group） | 新 pod = 新 group，起点 latest；历史策略由 Agent 重连时初始化推送覆盖 |
| Pending 索引 | Redis ZSET / HSET | Pending Dispatcher 重启从 Kafka compacted topic 增量回填 |
| 配置（限速/证书/GeoIP） | ConfigMap / Vault / 本地 mmap | 启动时加载；支持 SIGHUP 热加载 |

故障模式（见第八章）：

| 故障 | RTO | 数据影响 |
|------|-----|----------|
| 单 pod crash | < 15s | 0（Agent WAL + sequence_id 幂等重传） |
| 单 AZ 故障 | < 30s | 0（跨 AZ 副本 + ISR=2 仍可用） |
| Redis 分片故障 | < 10s（主从切换） | 0（Registry 降级走 LocalOwnershipCache 兜底） |
| Kafka broker 故障 | < 30s | 0（leader election；unclean.leader.election=false） |

### 1.5 不变量清单（违反即视为 bug）

- **I1**：`BatchAck.ACCEPTED` ⇒ 该 batch 所有事件已写入 Kafka 且 ISR 同步完成（`acks=all` + `min.insync.replicas=2`）
- **I2**：`BatchAck.REJECTED_*` ⇒ Agent 不得推进 `sequence_id`，该 batch 的持久化责任仍在 Agent WAL
- **I3**：Agent ↔ Gateway 信任根是 mTLS 客户端证书；tenant_id 来自证书 SAN，payload 自报字段不被信任
- **I4**：SignedServerCommand 的 payload/signature/signing_key_id 三元组由 Gateway 透传，不改写一个字节
- **I5**：Gateway 的广播扇出 ⊆ `target_scope` 表达集合；`|delivered| ≤ target_scope.max_fanout`
- **I6**：Kafka header 的 scope 仅作缓存/预过滤，**不得**作为授权依据；冲突以签名内 `target_scope` 为准，并审计 `scope_header_mismatch`
- **I7**：Unicast 命令路由的"消费位点提交 + pending 写入 + tombstone"必须在同一 Kafka 事务
- **I8**：L3 Domain-Fronted 上**不得**下发 `RESPONSE_ACTION` / `REMOTE_SHELL`；违反即 Gateway 拒绝并告警
- **I9**：所有下游 Kafka Consumer 设置 `isolation.level=read_committed`，不读未提交事务
- **I10**：所有 Producer 统一 `acks=all + idempotence=true + min.insync.replicas=2`；不存在"ACCEPTED 但未 ISR 同步"的中间态

---

## 二、接入层 (L4 + TLS)

### 2.1 L4 负载均衡

| 维度 | 方案 |
|------|------|
| 主选 | Envoy（L4 模式 + gRPC-aware L7 可选），xDS 动态配置，与 Istio 集成 |
| 备选 | HAProxy（纯 L4 高性能）、云厂商 NLB（托管 DDoS，公有云部署） |
| 监听端口 | `:8443` gRPC/WS（TLS 直通），`:8080` HTTP/L2，`:8444` L3 Adapter（独立策略） |
| TLS 策略 | **Passthrough**：LB 不持有私钥；mTLS 完整发生在 Gateway；攻击面最小 |
| 会话亲和性 | 默认关闭（无状态）；L2 Long-Polling 按 `X-Aegis-Agent-Id` / `Cookie: aegis-agent=<hash>` 做 consistent hash 弱亲和 |
| 健康检查 | TCP :8443 (5s/3s/3次)；gRPC Health :8443 (10s/5s/2次)；HTTP /healthz :8080 (10s/5s/2次) |
| 单 IP 限制 | 并发连接 ≤ 100；SYN rate 限制 + SYN cookies |
| 连接建立速率 | `per-pod accept ≤ 500 conn/s`，超限返回 TCP RST-retry，Agent 侧指数退避 jitter 重连 |

### 2.2 TLS/mTLS 策略

| 参数 | 值 |
|------|-----|
| TLS 版本 | 1.3（强制）；1.2 仅保留给 L3 CDN 边缘（由 CDN 决定） |
| 加密套件 | `TLS_AES_256_GCM_SHA384`、`TLS_CHACHA20_POLY1305_SHA256`、`TLS_AES_128_GCM_SHA256` |
| 客户端证书 | 强制（Gateway 端 `ClientAuth=RequireAndVerifyClientCert`） |
| Session Resumption | Session Ticket + PSK；`SessionTicketKey` 通过 Redis 跨 pod 共享（跨 AZ resumption） |
| 握手延迟目标 | P50 ≤ 0.5ms（resumption）；P99 ≤ 2ms（full） |
| SNI 约束 | `ingest.<region>.aegis.example`；SNI 不匹配直接拒绝 |
| ALPN | `h2`（gRPC）/ `aegis.ingest.v1+ws`（WebSocket）/ `http/1.1`（L2 Long-Poll）|

**身份提取**（绝对原则，任何违反即 `REJECTED_AUTH`）：

```go
// 伪代码：mTLS 握手完成后执行
func extractIdentity(peerCert *x509.Certificate) (Identity, error) {
    if len(peerCert.Subject.CommonName) == 0 {
        return Identity{}, ErrInvalidCertCN
    }
    agentID := peerCert.Subject.CommonName
    if !validAgentIDFormat(agentID) {
        return Identity{}, ErrInvalidCertCN
    }
    // Tenant 从 URI SAN 提取；**禁止**从 payload 读取
    tenantID, ok := extractTenantFromSAN(peerCert)
    if !ok {
        return Identity{}, ErrInvalidCertSAN
    }
    // CRL 检查（本地缓存 5min 更新）
    if revoked, _ := crlCache.IsRevoked(peerCert); revoked {
        auditLog("cert_revoked", agentID, tenantID)
        return Identity{}, ErrCertRevoked
    }
    return Identity{AgentID: agentID, TenantID: tenantID,
                    CertFingerprint: sha256Fingerprint(peerCert),
                    CertSerial: peerCert.SerialNumber.String()}, nil
}
```

### 2.3 证书轮换与吊销

| 层 | 有效期 | 轮换策略 |
|----|--------|----------|
| Root CA | 20y | 离线 HSM；不在线使用 |
| Intermediate CA | 5y | Vault 管理；每 2y 主动轮换 |
| Agent Device Cert | 90d | 过期前 14 天 Agent 发起 CSR（以旧证书身份凭证）；双证书共存窗口 ≤ 7d |
| Gateway Server Cert | 90d | Vault 自动轮换；SIGHUP 热加载 |
| Service Mesh Cert | 30d | Istio Citadel 自动 |
| L3 CDN→Origin 签名密钥 | 24h | HSM 签发；Gateway 侧允许密钥白名单热下线 |

**CRL / OCSP**：
- CRL 主动推送至所有 Gateway pod，`/admin/reload` 或文件 inotify 触发加载
- OCSP Stapling 作为补充，不作为主干路径（避免外部依赖）
- 被吊销 `agent_id` 加入 pod 本地拒绝表（TTL 与 CRL 更新周期一致）
- 吊销触发即时 `GOAWAY` 该 agent 的所有现存连接

### 2.4 连接建立速率控制

三层递进，保护 Gateway 不被重连风暴打垮：

1. **LB 层**：单 IP SYN rate + 并发连接上限
2. **Gateway 层**：每 pod `accept ≤ 500 conn/s`；超限立即关闭 TCP 连接（四次挥手），Agent 侧本地指数退避 + jitter
3. **全局层**：若整集群 `new_connections/s > 30,000` 持续 30s，触发**预扩容脚本**（见 10.2.1），`minReplicas` 从 90 临时提升至 135

### 2.5 DDoS 多层防护体系

| 层 | 措施 |
|----|------|
| 网络基础设施 | Anycast + ISP DDoS 清洗 + 可选 WAF |
| L4 LB | SYN cookies；半连接队列；单 IP 并发上限；无效 TLS 握手 5s 快速拒绝 |
| Gateway 应用层 | 强制 mTLS；per-agent Token Bucket；per-tenant Sliding Window；证书吊销表；异常模式检测 |
| Kafka 层 | Producer backoff；buffer 上限触发 `REJECTED_BACKPRESSURE`（非丢弃） |

典型攻击响应：

| 攻击类型 | 应对 |
|----------|------|
| SYN Flood | LB SYN cookies + 半连接限制 |
| TLS 握手消耗 | 握手超时 5s + 单 IP 连接限制 + `accept ≤ 500 conn/s` |
| 无效证书轰炸 | 快速拒绝 + IP 临时封禁（30min） |
| 合法 Agent 异常上报 | per-agent Token Bucket + **严格不丢弃（整批 NACK）** + 连接级熔断（60s 内 NACK > 120 → `GOAWAY` + 30s 退避）|
| 被攻破 Agent 发起 DoS | 证书吊销 + `agent_id` 拒绝表 |
| Kafka 慢写 | Producer buffer 背压透传到 gRPC flow control → Agent WAL |

---

## 三、Ingestion Gateway 核心

### 3.1 gRPC 服务端点

**Wire contract 单一事实来源：**`docs/architecture/aegis-transport-architecture.md §12.1`

```protobuf
service AgentService {
  rpc EventStream(stream UplinkMessage) returns (stream DownlinkMessage);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
  rpc UploadArtifact(stream ArtifactChunk) returns (UploadResult);
  rpc PullUpdate(UpdateRequest) returns (stream UpdateChunk);
}

message UplinkMessage {
  oneof kind {
    EventBatch event_batch = 1;
    ClientAck  client_ack  = 2;
  }
}

message DownlinkMessage {
  oneof kind {
    BatchAck            batch_ack      = 1;
    SignedServerCommand server_command = 2;
    FlowControlHint     flow_hint      = 3;
  }
}
```

每个端点的并发模型：

| 端点 | 模式 | Goroutine 模型 | 典型 P99 延迟目标 |
|------|------|----------------|-------------------|
| EventStream | Bidirectional stream | per-Agent 一个长活 goroutine + 独立 Kafka Producer 分派 | < 20ms（acks=all）|
| Heartbeat | Unary | goroutine-per-call | < 5ms |
| UploadArtifact | Client stream | goroutine-per-upload；分块 ≤ 1MB；带宽配额池 | 不影响 EventStream |
| PullUpdate | Server stream | goroutine-per-pull；LZ4 压缩；支持 Range 续传 | — |

### 3.2 mTLS 验证流水线

```
Agent TLS ClientHello
    │
    ▼
TLS 1.3 Handshake (resumption 优先)
    │
    ▼
证书链校验 (Root → Intermediate → Agent)
    │
    ▼
CRL/OCSP 检查 (本地缓存)
    │
    ▼
身份提取 (CN → agent_id, URI-SAN → tenant_id)
    │
    ▼
注入 ctx.Value("identity") = Identity{agent_id, tenant_id, cert_fp}
    │
    ▼
EventStream RPC accept
    │
    ▼
LocalOwnershipCache 写入 (lease=60s)  ──►  异步 HSET Registry
```

**Session Ticket 跨 pod 共享**：
- 使用 Redis Cluster `gateway:session_ticket_key` 存储当前 ticket key + `ticket_key_prev`
- Gateway 每 6h 轮换一次 ticket key，prev 保留 6h 以容忍 in-flight ticket
- Redis 故障时降级为 pod 本地 ticket（失去跨 pod resumption，但 mTLS 功能不受影响）

### 3.3 事件富化流水线

| 步骤 | 数据源 | 加载方式 | 典型延迟 | 失败降级 |
|------|--------|----------|----------|----------|
| LZ4 Decompress | Agent 压缩 payload | 纯计算 | ~0.2ms/batch | REJECTED_MALFORMED |
| Protobuf Validate | 编译时 schema + 运行时必填检查 + 枚举范围 | 纯计算 | ~0.1ms/batch | REJECTED_MALFORMED |
| GeoIP Lookup | MaxMind GeoLite2-City / GeoIP2-Enterprise | mmap（~70MB，启动时加载，每周更新）| < 1µs/lookup | `geo: null`；不阻塞 |
| Asset Tag Lookup | Asset Mgmt Service → Redis | Redis HGETALL，TTL=300s | < 0.1ms（hit）/ < 5ms（miss） | 跳过富化；事件标记 `enrichment_partial: true` |
| Tenant Metadata | 从 mTLS ctx 读取 | 内存 | < 10µs | 不可降级（拒绝事件） |
| MITRE TTP Pre-label | 规则包 | 本地 mmap（分钟级热加载） | ~0.1ms/batch | 跳过标签；原始事件仍入库 |
| lineage_id Checkpoint | 纯计数 | 内存 | ~10µs | 不降级 |

**富化代码骨架**：

```go
func (e *Enricher) Enrich(batch *EventBatch, id Identity) (*EnrichedBatch, error) {
    eb := e.pool.Get() // sync.Pool 复用，避免 GC 压力
    defer e.pool.Put(eb)

    raw, err := lz4.Decompress(batch.CompressedEvents)
    if err != nil { return nil, ErrMalformed }

    events, err := parseEventsProto(raw)
    if err != nil { return nil, ErrMalformed }

    for i := range events {
        events[i].TenantId = id.TenantID // 强制覆盖
        events[i].AgentId = id.AgentID

        if ip := events[i].NetworkCtx.GetSrcIp(); ip != "" {
            geo, _ := e.geoip.Lookup(ip) // 返回 nil 时写空，不阻塞
            events[i].Enrichment.Geo = geo
        }

        if tag, ok := e.assetCache.Get(id.AgentID); ok {
            events[i].Enrichment.Asset = tag
        } else if tag, err := e.assetCache.FetchAndStore(id.AgentID); err == nil {
            events[i].Enrichment.Asset = tag
        } else {
            events[i].EnrichmentPartial = true
        }

        events[i].MitreTtps = e.ttpLabeler.Label(&events[i])
        e.lineage.Checkpoint(events[i].LineageId, "gateway_received")
    }

    eb.Events = events
    eb.BatchId = batch.BatchId
    eb.SequenceId = batch.SequenceId
    eb.Priority = batch.Priority
    return eb, nil
}
```

### 3.4 三路通道映射 (A/B/C)

| Agent 通道 | 语义 | Gateway 处理 | Kafka Topic | acks | linger.ms / batch.size |
|------------|------|--------------|-------------|------|-------------------------|
| A: High-Priority | CRITICAL/HIGH 告警、响应结果 | 独立 goroutine，零延迟 | `raw-events.{tenant}`（CRITICAL partition key）| **all** + idempotent | 0 / 16KB / max.in.flight=1 |
| B: Normal Telemetry | 常规遥测 | 批量共享 pool | `raw-events.{tenant}`（agent_id hash）| **all** + idempotent | 5 / 64KB |
| C: Bulk Upload | 取证包 / memory dump | `UploadArtifact` RPC + S3/MinIO 分块 | `artifact-uploads`（元数据）| **all** + idempotent | 10 / 128KB |

> **持久化不妥协**：三路通道仅在延迟-吞吐维度调参；`acks` 一律 `all`。未来若引入弱持久化通道，必须新增 `BatchAck.ACCEPTED_NONDURABLE` 状态并约束 Agent 不得推进 `sequence_id`。

### 3.5 Rate Limiter

```
┌───────────────────────────────────────────┐
│  Layer 1: LB 层                           │
│  - 单 IP 并发 100                         │
│  - SYN rate 限制                          │
├───────────────────────────────────────────┤
│  Layer 2: Gateway per-Agent               │
│  - Token Bucket: 1000 events/s (默认)     │
│  - Burst: 2000 events                     │
│  - 可按策略调整 50-5000 events/s          │
├───────────────────────────────────────────┤
│  Layer 3: Gateway per-Tenant              │
│  - Sliding Window: 1min                   │
│  - 配额 = Σ(agent_count) × 1200 × 1.2x    │
├───────────────────────────────────────────┤
│  Layer 4: Kafka 层                        │
│  - Producer buffer 上限                   │
│  - 阻塞 → gRPC 背压                       │
└───────────────────────────────────────────┘
```

**Token Bucket 实现要点**：
- 每 `agent_id` 独立 bucket；`sync.Map` + 原子操作
- 惰性刷新：请求到达时按 `now - last_refill` 补充 token，避免全局 ticker
- 内存占用：每 bucket ~100B；1M agents ≈ 100MB（Gateway 集群整体，分布在 90 pods 上 < 2MB/pod）

**Sliding Window 实现**（per-tenant）：
- 6 × 10s 细分桶（sub-window），Redis `INCR` + `EXPIRE`
- 每个 tenant 的 window 值 = 6 桶总和
- 误差 ≤ 16.7%（10s / 60s），可接受

### 3.6 BatchAck 协议 (Strict No-Drop Contract)

**严格不丢弃契约**（与 §4.6.2.1 SSoT 对齐）：

| 超限程度（相对稳态速率） | Gateway 行为 | BatchAck 状态 | retry_after_ms | Agent 侧动作 |
|--------------------------|--------------|----------------|-----------------|---------------|
| ≤ 1x | 正常接收 | ACCEPTED | — | 推进 sequence_id |
| 1-2x（短时突发）| 消费 burst 容量 | ACCEPTED | — | 推进 sequence_id |
| 2-5x（持续超限）| 整批 NACK | REJECTED_RATE_LIMIT | 500-2000 jitter | WAL 保留，退避重传，不推进 |
| > 5x（严重超限）| 整批 NACK + gRPC window 缩小 | REJECTED_RATE_LIMIT | 2000-5000 jitter | 同上；连续 10 次 NACK → Agent 降采样 |
| Kafka 不可写 | 整批 NACK | REJECTED_BACKPRESSURE | 100-500 jitter | WAL 保留，等待恢复 |
| Tenant 配额耗尽 | 整批 NACK | REJECTED_QUOTA_EXCEEDED | 10000-30000 jitter | WAL 保留，大时间窗退避 |
| Schema 错误 | 整批 NACK（不重试）| REJECTED_MALFORMED | — | 上报异常，不重传 |
| 证书异常 | 整批 NACK + GOAWAY | REJECTED_AUTH | — | 重新 bootstrap |

**关键不变量**：
- **All-or-nothing**：`ACCEPTED` 意味着整批所有事件已 ISR 同步；任何事件失败必须整批改回 `REJECTED_BACKPRESSURE`
- **sequence_id 原子推进**：仅 ACCEPTED 后推进；REJECTED 后保持不变
- **回执时序**：Gateway 在接收 EventBatch 后 **500ms 内** 回 BatchAck（目标 P99 < 15ms）
- **Agent 超时**：默认 5s；超时视为连接失效，关 stream 重连，按 sequence_id 回放 WAL

**连接级熔断**：
- 单 Agent 60s 内 NACK 计数 > 120（2 NACK/s）→ `RESOURCE_EXHAUSTED` + `GOAWAY`；Agent 退避 30s 后重连
- Pod 整体 NACK 率 > 15%（1min 滑窗）→ pod 从 LB 后端池 drain（readiness=false），HPA 介入

### 3.7 Connection Manager & HTTP/2 调优

| 参数 | 值 | 理由 |
|------|-----|------|
| `MaxConcurrentStreams` | 100 | 单连接最多 100 stream（EventStream + Heartbeat + Upload + Pull + 下行）|
| `InitialWindowSize` | 1MB | 平衡吞吐与内存 |
| `MaxFrameSize` | 16KB | gRPC 默认；更大帧无明显收益 |
| `KeepAliveTime` | 30s | 对抗 NAT 超时（典型 60s） |
| `KeepAliveTimeout` | 10s | 无响应 10s 即判定断开 |
| `MaxConnectionIdle` | 15min | 空闲连接释放 |
| `MaxConnectionAge` | 24h | 强制重连以触发 LB 再平衡 |
| `MaxConnectionAgeGrace` | 30s | 优雅关闭宽限 |
| `WriteBufferSize` | 32KB | HTTP/2 发送缓冲 |
| `ReadBufferSize` | 32KB | HTTP/2 接收缓冲 |
| `NumStreamWorkers` | GOMAXPROCS | stream 处理 worker 数 |

**连接表**：`sync.Map[agent_id]*ConnState`；每条 ~80KB 常驻（stream state + 发/收缓冲）；单 pod 稳态 16,000 连接，硬上限 20,000。

### 3.8 连接排水 (Graceful Shutdown)

```
SIGTERM received (K8s pre-stop hook)
    │
    ▼
t=0s   Readiness probe 返回 false (LB 摘除)
       停止 accept 新连接
    │
    ▼
t=1s   发送 gRPC GOAWAY 给所有活跃连接
       Agent 收到 GOAWAY → 立即重连其他 pod
    │
    ▼
t=1-25s  等待进行中的 EventBatch 处理完成
         Kafka Producer flush; BatchAck 回执
    │
    ▼
t=25s  Flush 所有 Kafka producer buffer (synchronous)
       提交 pending Unicast 事务 (或 abort)
    │
    ▼
t=28s  关闭 Redis 连接池；关闭 Kafka producer/consumer
       清理 LocalOwnershipCache 并从 Registry 删除本 pod 持有的条目
       （Lua CAS: DEL conn:{agent_id} WHERE owner_pod=self）
    │
    ▼
t=30s  强制关闭剩余连接；进程退出
```

`terminationGracePeriodSeconds: 30` 与 K8s 对齐。

### 3.9 Transport Adapter Layer

为支持 L0 gRPC / L1 WebSocket / L2 Long-Polling / L3 Fronted 的后端共享，Gateway 引入 Transport Adapter Layer：

```
┌──────────────────────────────────────────────────────────┐
│  Entry Adapters                                          │
│  ├── gRPC L0       (grpc-go)                             │
│  ├── WebSocket L1  (gorilla/websocket or nhooyr/websocket)│
│  ├── HTTP L2       (net/http + custom long-poll handler)  │
│  └── HTTP L3       (独立端口 + CDN 签名 header 校验)     │
└─────────────────────┬────────────────────────────────────┘
                      │
                      ▼ 归一化为 UplinkMessage/DownlinkMessage
┌──────────────────────────────────────────────────────────┐
│  共享后端: mTLS/CDN-identity → Enrich → Kafka → BatchAck │
│           Connection Registry → 下行命令分派              │
└──────────────────────────────────────────────────────────┘
```

后端唯一感知 transport 的地方是 Connection Registry 条目的 `transport` 字段（`grpc` / `ws` / `longpoll` / `fronted`），用于下行命令选择正确的 send 方法。

---

## 四、Kafka Event Bus

### 4.1 Topic 设计

> **单一事实来源**：Topic 清单详见 `docs/architecture/aegis-transport-architecture.md §4.4.1`；此处保留概要并补充 Producer/Consumer 配置落地。

| Topic | 分区策略 | 分区数 | 保留期 | 副本 | acks | Consumer 模型 |
|-------|----------|--------|--------|------|------|----------------|
| `raw-events.{tenant}` | hash(agent_id) | 128 | 72h | 3 | all | Flink 消费富化流水线 |
| `enriched-events` | hash(event_type) | 128 | 72h | 3 | all | Analytics |
| `detections` | hash(severity) | 64 | 30d | 3 | all | Management / SIEM |
| `commands.unicast` | hash(agent_id) | 128 | 24h | 3 | all + TXN | **shared group** `gateway-unicast` |
| `commands.broadcast` | round-robin / hash(tenant_id) | 32 | 24h | 3 | all | **per-pod group** `gateway-bcast-{pod_uid}` |
| `commands.pending` | hash(agent_id), key=`tenant:agent:command_id` | 64 | 7d（compact+delete）| 3 | all + TXN | Pending Dispatcher（read_committed）|
| `commands.dead-letter` | hash(agent_id) | 16 | 30d | 3 | all | 审计 + 告警 |
| `audit-log` | hash(tenant_id) | 64 | 365d | 3 | all | 长期归档 |
| `artifact-uploads` | hash(agent_id) | 32 | 30d | 3 | all | Artifact Service |

### 4.2 Producer 配置（持久化不妥协）

所有 Producer 共享的铁律：

```properties
acks=all
enable.idempotence=true
min.insync.replicas=2
compression.type=lz4
retries=2147483647          # Int.MAX；配合 idempotent producer 不会重复
delivery.timeout.ms=120000  # 2min，防止无限重试阻塞 Gateway
max.in.flight.requests.per.connection=5  # 幂等 producer 下仍保证分区内有序
```

差异化参数（延迟 vs 吞吐）：

| Producer | 用途 | linger.ms | batch.size | buffer.memory | max.in.flight |
|----------|------|-----------|------------|---------------|---------------|
| High-Priority | CRITICAL/HIGH | 0 | 16KB | 64MB | 1 |
| Normal | 常规遥测 | 5 | 64KB | 512MB | 5 |
| Bulk | Artifact 元数据 / 审计 | 10 | 128KB | 256MB | 5 |
| Transactional | 下行 unicast pending + dead-letter | 5 | 64KB | 128MB | 5（+ `transactional.id=gateway-{pod_uid}-unicast`）|

**Buffer 上限的由来**：`acks=all` 下单次 produce P50 从 ~2ms 升至 4-5ms，buffer 需放大以吸收同样吞吐；满时触发 `REJECTED_BACKPRESSURE`，而非丢弃。

### 4.3 Consumer 分组模式

| Consumer | group_id | isolation.level | 模式 |
|----------|----------|-----------------|------|
| Unicast Consumer | `gateway-unicast` | read_committed | **Shared group**（一条记录仅一个 pod 消费）|
| Broadcast Consumer | `gateway-bcast-{pod_uid}` | read_committed | **Per-pod group**（每 pod 独立 consumer group，均收到完整副本）|
| Pending Dispatcher | `gateway-pending-{pod_uid}` | read_committed | Per-pod（或 N 个共享，按分区均分）|
| Dead-letter Consumer | `audit-dead-letter` | read_committed | Shared；仅做归档 |

**Broadcast per-pod group 的正确性保证**：
- 新 pod 启动：group 起始 offset = `latest`（不消费历史广播），历史策略由 Agent 连接时 Policy Service 主动推送 snapshot 覆盖
- Pod 缩容：group 随 pod 销毁；Kafka `offsets.retention.minutes=1440` 24h 自动清理僵尸 group
- 单 AZ 故障：剩余 pods 的 per-pod group 正常运行，无 rebalance 成本

### 4.4 Kafka 事务（commands.pending EOS）

Unicast 下行的核心正确性保证。每个 Gateway pod 在 Unicast Consumer 旁挂一个事务型 Producer（`transactional.id = gateway-{pod_uid}-unicast`），与 Consumer 协同按 Kafka 事务 + `read_committed` 语义保证**三件事原子**：
1. 本批 Unicast 记录的消费位点提交
2. 未投递命令写入 `commands.pending`（附 TTL / enqueued_at / source_offset headers）
3. 已投递命令的 tombstone 写入（compaction 清理）

```python
producer.initTransactions()

for record in kafka.consume("commands.unicast", isolation_level="read_committed"):
    agent_id = record.key
    entry    = registry.get("conn:" + agent_id)  # HGETALL

    producer.beginTransaction()
    try:
        if entry is None or entry.expired():
            producer.send("commands.pending", key=pending_key(record), value=record.value,
                          headers=record.headers | {ttl, enqueued_at, source_offset})
        elif entry.owner_pod == self.pod_uid:
            local_stream = conn_table.get(agent_id)
            if local_stream:
                local_stream.send(record.value)  # gRPC 背压满则 raise
            else:
                registry.compare_and_delete(agent_id, self.pod_uid, entry.epoch)
                producer.send("commands.pending", ...)
        else:
            ack = inter_pod.forward(entry.owner_endpoint, record)
            if ack.status != DELIVERED:
                producer.send("commands.pending", ...)

        producer.sendOffsetsToTransaction(
            offsets={(topic, partition): record.offset + 1},
            consumer_group_id="gateway-unicast")
        producer.commitTransaction()

    except (ProducerFencedException, OutOfOrderSequenceException, AuthorizationException):
        raise                       # 立即退出、K8s 重启，新 pod_uid 重建事务
    except Exception as e:
        producer.abortTransaction()
        metrics.unicast_tx_aborted_total.inc(reason=type(e).__name__)
```

**关键语义**：
- `commands.pending` 写入 + 消费位点提交 + tombstone 写入**同事务**；不存在"位点前进但 pending 未写"或"pending 已写但位点未提交"
- 所有下游 Consumer `isolation.level=read_committed`，只看已提交
- `transactional.id = gateway-{pod_uid}-unicast` 确保 pod 重启后 Kafka fence 旧实例的僵尸事务；pod UID 来自 K8s Downward API，滚动更新天然新 UID

### 4.5 集群规模与持久性

```
Brokers: 15 (3 AZ × 5)
ZooKeeper / KRaft: 3 (1 per AZ)
Replication Factor: 3 (跨 AZ)
min.insync.replicas: 2
unclean.leader.election.enable: false

单 broker 容量:
  CPU: 16 cores
  Memory: 32GB (JVM heap 6G + page cache 26G)
  Network: 10 Gbps
  Storage: 3TB NVMe (5TB/day × 3d retention × 3x / 15 brokers)

容量推导 (8.3M events/s, 200B/event 压缩后):
  吞吐: 8.3M × 200B = 1.66 GB/s ≈ 1.66 GB/s × 3 replicas = 5 GB/s 写入
  + overhead (replica + audit + downlink): ≈ 10 GB/s
  per-broker: 10 / 15 ≈ 0.67 GB/s （低于 800 MB/s 单 broker 上限）
```

**故障容忍**：
- 单 broker 故障：自动 leader election < 30s；RPO=0（ISR ≥ 2）
- 单 AZ 故障：剩余 2 AZ 的 ISR ≥ 2 仍满足；服务不中断
- 双 AZ 故障：不可用（设计上限）

### 4.6 分区与路由

| Topic | Partition Key | 理由 |
|-------|---------------|------|
| `raw-events.{tenant}` | hash(agent_id) | 同 Agent 事件保持分区内有序 |
| `enriched-events` | hash(event_type) | Flink 按类型并行消费 |
| `detections` | hash(severity) | 优先消费 CRITICAL |
| `commands.unicast` | hash(agent_id) | 与 Unicast Consumer 分区策略一致；配合 Registry 查找 |
| `commands.broadcast` | round-robin | 所有 pods 都要见到；分区数 = 32（控制 broker 负载）|
| `commands.pending` | hash(agent_id) | 与 unicast 保持同一 agent 的补投顺序 |

---

## 五、下行命令路由

### 5.1 Connection Registry (Redis Cluster)

**选型**：Redis Cluster（6 节点跨 3 AZ，主从 1+1 per shard），单命令 P99 < 1ms。

| 字段 | 类型 | 说明 |
|------|------|------|
| `conn:{agent_id}` | Hash | owner_pod, owner_endpoint, epoch, tenant_id, connected_at, transport |
| `conn:{agent_id}:epoch` | Counter | `INCR` 生成，单调递增 |
| TTL | 48h | 2 × max_connection_age；心跳续期 |

**写入路径**（连接建立时）：
1. mTLS + tenant 校验通过
2. **先**写入 `LocalOwnershipCache`（内存 lease=60s）
3. **后**异步 `HSET conn:{agent_id} ...` + `EXPIRE`；epoch = `INCR conn:{agent_id}:epoch`
4. Redis 失败**不阻塞**连接建立

**删除路径**（连接关闭）：
1. 先清理本地 lease
2. 后 `DEL conn:{agent_id}`，使用 Lua CAS 脚本：
   ```lua
   if redis.call('HGET', KEYS[1], 'owner_pod') == ARGV[1]
      and redis.call('HGET', KEYS[1], 'epoch') == ARGV[2] then
     return redis.call('DEL', KEYS[1])
   else
     return 0
   end
   ```

**续期**：
- 本地 lease 每 15s 续期（依赖 gRPC stream 活性）
- Redis TTL 每 30s 刷新（依赖 Redis 可用）

**容量估算**（1M 连接）：
- Registry 条目：1M × 200B ≈ 200MB（远低于 6 节点 × 4GB ≈ 24GB 容量）
- 流量：`new_conn/s × 2 + heartbeat_refresh/s ≈ 数千 ops/s`（远低于 Redis Cluster 百万 ops/s 能力）

### 5.2 LocalOwnershipCache（双轨兜底）

每个 pod 内存持有一份 `agent_id → {owner_pod=self, epoch, lease_expires_at}` 表：

| 特性 | 说明 |
|------|------|
| 作用 | Redis 故障时，**本 pod 已持有的连接**仍可被本地直投 |
| lease | 60s；活跃连接每 15s 续期 |
| 大小 | 16,000 条目 × ~80B = ~1.3MB |
| 数据结构 | `sync.Map` + 定时 sweep goroutine 清理过期 |

**正常路径**：Registry lookup 先查本地 → 命中即本地直投；未命中查 Redis → 命中转发；仍未命中 → pending。

**Registry 降级路径**（5.7 节）：本地命中走直投；本地未命中按命令类型分流。

### 5.3 Unicast 路径：shared group + Inter-Pod 转发

```
Management → commands.unicast (hash by agent_id)
                │
                ▼
        Unicast Consumer (group=gateway-unicast, read_committed)
                │
                ▼
        [Kafka 事务边界] (§4.4)
                │
                ▼
        Registry.get(conn:{agent_id})
         │        │        │
         ▼        ▼        ▼
       owner    owner    owner
       == self  == 其它   == null
         │        │        │
         ▼        ▼        ▼
       本地     Inter-Pod  commands.pending
       stream   :9443      (同事务写入)
       .send()  转发
```

**Inter-Pod gRPC**（`:9443`，集群内网络）：

```protobuf
service GatewayInternal {
  rpc ForwardCommand(ForwardCommandRequest) returns (ForwardCommandAck);
}

message ForwardCommandRequest {
  string agent_id       = 1;
  uint64 owner_epoch    = 2;   // 调用方认定的 owner epoch
  bytes  signed_command = 3;   // SignedServerCommand 字节，pass-through
  string lineage_id     = 4;
}

message ForwardCommandAck {
  enum Status {
    DELIVERED           = 0;
    NOT_OWNER           = 1;   // epoch mismatch 或已断开
    AGENT_BACKPRESSURED = 2;
    INTERNAL_ERROR      = 3;
  }
  Status status = 1;
}
```

- 鉴权：**独立内部 mTLS 证书**（Vault 签发，CN=`gateway.internal`）；与 Agent↔Gateway 证书链完全隔离
- 网络：K8s NetworkPolicy 仅放行 ingestion-gateway 间 9443
- 背压：HTTP/2 `MaxConcurrentStreams=1000`；目标 pod 过载返回 `AGENT_BACKPRESSURED`
- `NOT_OWNER` 处理：调用方立即刷新 Registry，重试 1 次；仍失败 → pending

### 5.4 Broadcast 路径：per-pod group + TargetScope 扇出

Topic：`commands.broadcast`；group_id = `gateway-bcast-{pod_uid}`（**每 pod 独立**）。

**消费流水线**：

1. **读 header 作为缓存提示**：`scope_hint` / `command_type_hint` / `priority` / `origin_service`；header 仅用于预过滤，**不作授权依据**
2. **强制解码签名内 `target_scope`**：位于 `SignedServerCommand.payload` 内；签名外的 header 与 `target_scope` 冲突时以 `target_scope` 为准，写审计 `scope_header_mismatch`（STRIDE Tampering）
3. **收窄扇出**：本 pod 投递集合 = (本 pod 活跃连接表) ∩ (target_scope 允许集合)；必须保证 `|delivered_in_pod| ≤ target_scope.max_fanout`
4. **透传 SignedServerCommand 字节**：不改写 payload / signature / command_type
5. **按 command_type 的业务语义由 Agent 分派**（见 5.2.2 表）；Gateway 不关心业务含义

**TargetScope.kind 的路由语义**：

| kind | 投递目标 | Gateway 行为 |
|------|----------|---------------|
| AGENT | 仅 `ServerCommand.agent_id` | 精确投递（本 pod 或跨 pod 转发）|
| AGENT_SET | `target_scope.agent_ids` 枚举 | 本 pod 遍历 ∩ 连接表；跨 pod 由其它 pod 的广播消费覆盖 |
| TENANT | `target_scope.tenant_id` 的所有连接 | 本 pod 遍历 tenant 的连接表 |
| GLOBAL | 所有 tenant 所有连接 | 生产环境默认禁用；平台管理员显式授权后启用 |

**非法组合直接整批丢弃 + `commands.dead-letter`**：
- `GLOBAL` 未开启
- `AGENT_SET.|agent_ids| > max_fanout`
- `target_scope.tenant_id != Kafka record tenant` （跨租户投递）
- 广播通道出现 `AGENT kind` 但 `agent_id` 与 Registry tenant 冲突

### 5.5 Pending Dispatcher（物化索引）

```
commands.pending (compact+delete, 7d)  ──► Pending Dispatcher (per-pod) ──► Redis
                                           │                                 │
                                           │ 对每条 pending 记录：            │
                                           │ 1. 若 TTL 已过 → tombstone +    │
                                           │    dead-letter（同事务）         │
                                           │ 2. 否则 Registry.get:            │
                                           │    - owner==self: 本地投递       │
                                           │    - owner!=self: 转发           │
                                           │    - owner==null: 保留，退避     │
                                           │ 3. 投递成功 → tombstone + 删 idx │
                                           │                                  │
                                           │ 退避: 初始 2s，最大 60s，±20%    │
                                           │                                  │
                                           └──► Redis: ZSET pending:{agent_id}│
                                                member=command_id, score=expiry_ts
                                                HSET pending_body:{command_id}
                                                bytes=SignedServerCommand
```

**正确性**：
- 索引写入策略：**先**写 Redis，**再**返回；配合 Consumer 位点提交保证 "索引存在 ⇒ 记录已写 pending"
- 反向最终一致：索引可能临时落后，Agent 重连回放同时查 Redis + compacted topic replay 兜底
- Redis 故障降级：直接扫描 `commands.pending` 的 agent-scoped compacted view（慢路径，触发 P2 告警）

### 5.6 Agent 重连回放

```python
def on_agent_reconnect(agent_id, stream):
    # 1. mTLS + Registry CAS 占据 ownership
    registry.cas_set("conn:" + agent_id, old_epoch, new_epoch, owner_pod=self.pod_uid)
    local_ownership_cache.put(agent_id, lease=60s)

    # 2. 先回放 pending
    entries = redis.zrangebyscore(f"pending:{agent_id}", now, "+inf")
    if entries is not None:
        for cid in entries:
            body = redis.hget(f"pending_body:{cid}")
            stream.send(body)
            # 投递成功 → 事务写 commands.pending tombstone + 删 Redis 条目
            producer.beginTransaction()
            producer.send("commands.pending", key=cid, value=None)  # tombstone
            redis.zrem(f"pending:{agent_id}", cid)
            redis.hdel("pending_body", cid)
            producer.commitTransaction()
    else:
        # Redis 降级：compacted topic 回放
        replay_from_compacted_topic(agent_id)

    # 3. 完成回放后放行 Live 下行
    unblock_live_downlink(stream)
```

**Agent 侧去重**：按 `command_id` 幂等（见 `aegis-sensor-architecture.md` §4.5.5 命令去重表）；即使 Redis + topic 双路径产生偶发重复，也不会被执行两次。

### 5.7 Registry 降级：Fan-out-on-miss (CRITICAL)

当 Redis Connection Registry 不可用（熔断器 open）时，按命令类型精细化策略：

| 命令类型 | 本 pod 持有目标连接 | 本 pod 未持有 / 不确定 |
|----------|---------------------|------------------------|
| RESPONSE_ACTION (CRITICAL) | **本地直投**（LocalOwnershipCache 命中即送，事务内写 audit-log）| **Fan-out-on-miss**：事务内写 `commands.pending` + 并发向**所有其它 pod** 发 `ForwardCommand`；任一 pod DELIVERED → tombstone；30s 内无人 DELIVERED → 保留 + 告警 |
| REMOTE_SHELL (CRITICAL) | 同上；`approval.human_in_loop=true` 必须已由上游盖章 | 同上；Agent 侧仍需完成交互式审批链 |
| FEEDBACK / REQUEST_PROCESS_INFO (LOW/NORMAL) | 本地直投 | 进入 `commands.pending` 正常退避 |
| POLICY/RULE/IOC/CONFIG (广播) | **不受 Registry 影响**（每 pod 独立 consumer group 已覆盖）| 同左 |

**Fan-out-on-miss 成本模型**：
- 每次 fan-out 成本 = (N-1) 次 RPC × 平均 RTT ~2ms ≈ (90-1) × 2ms ≈ 180ms（并发）
- 发生频率 = CRITICAL 命令速率 × Registry 降级占比；平均 < 10 QPS × 极少降级时间 → 可忽略
- 不对 FEEDBACK/NORMAL 做 fan-out：避免降级期间的放大效应

**熔断器配置**：
- 5xx 或超时 > 100ms 达 50% 率 → open
- open 期间 30s 后 half-open 探测；探测成功 → close
- `gateway_registry_circuit_state{state=closed|half-open|open}`

### 5.8 Fail-closed: 升级到 OOB 通道

若 `RESPONSE_ACTION` / `REMOTE_SHELL` 在 pending 中停留 > 30s 仍未投递：
- Gateway 发布 `CriticalCommandDelayed` 事件
- 由 Response Orchestrator 决策是否升级到带外通道（OOB，如管理员手动 SSH / EDR 侧信道）
- 此机制已在 `aegis-architecture-design.md §6.4` 登记；Transport 层仅保证"Registry 故障不吞没 CRITICAL 命令"

---

## 六、Fallback Transport 子系统

### 6.1 L0 gRPC 主通道（基线）

见第三章。L0 是所有 Fallback 的语义等价基准。

### 6.2 L1 WebSocket

**入口**：`wss://ingest.<region>.aegis.example/v1/stream`，复用 `:8443`，TLS 1.3，HTTP/1.1 Upgrade，子协议 `aegis.ingest.v1+ws`。

**鉴权**：与 gRPC 路径完全相同（TLS 握手中 Agent 提供客户端证书；从证书 SAN 提取 tenant_id）。

**消息帧**：WebSocket binary frames，每帧一个 Protobuf：

| 方向 | 消息 | 对应 gRPC |
|------|------|-----------|
| C→S | `UplinkMessage`（EventBatch 或 ClientAck）| EventStream 上行 |
| S→C | `DownlinkMessage`（BatchAck / SignedServerCommand / FlowControlHint）| EventStream 下行 |

**保活**：
- WebSocket 协议层 ping/pong 每 30s
- 应用层 `HeartbeatRequest` 每 60s
- MaxConnectionAge 24h；到期发 `FlowControlHint(reason=reconnect)` + 30s 内关闭

**背压（Credit-based）**：
- Gateway 初始授予 100 batch credits
- Agent 每发一个 EventBatch 消耗 1 credit
- 每收 BatchAck.ACCEPTED 返还 1 credit
- credits=0 时 Agent 必须停止发送
- Credit 参数在连接首个 `DownlinkMessage.flow_hint` 中携带

**Connection Registry**：在 Registry 条目中标记 `transport=ws`；Inter-Pod 转发对 transport 透明（目标 pod 的分发器按 transport 选择发送方法）。

**LB 路由**：L4 LB 按 ALPN + SNI 分流到 `:8443`；TLS 直通。

### 6.3 L2 HTTPS Long-Polling

**入口**：
- 上行：`POST https://ingest.<region>.aegis.example/v1/uplink`
- 下行：`POST https://ingest.<region>.aegis.example/v1/downlink`（Agent 长轮询）

**鉴权**：客户端证书 mTLS（同一套证书与 tenant 语义）。

**上行 POST**：
- 请求：`UplinkBundle { repeated EventBatch batches = 1; ClientAck? ack = 2; }`
- 响应：`UplinkAckBundle { repeated BatchAck acks = 1; FlowControlHint? hint = 2; }`
- HTTP 状态码仅反映传输层成功；应用层成败由 BatchAck.Status 决定
- 单 POST 最大 ≤ 16 batches / 1MB（防代理切片）

**下行长轮询**：
- 请求：`DownlinkPollRequest { agent_id, last_seen_command_id, poll_timeout_ms=25000 }`
- Gateway 注册虚拟"stream slot"到 Registry（transport=longpoll）
- 命令到达或 30s 超时即刻响应 `DownlinkPollResponse { repeated SignedServerCommand commands; FlowControlHint? hint }`
- Agent 收到响应后立即发起下一次长轮询

**虚拟连接 TTL**：90s（3 × poll_timeout）；Agent 必须在 TTL 内发起下一次 poll。

**Sticky Session**：LB 按 `Cookie: aegis-agent=<hash>` 或 `X-Aegis-Agent-Id` header 做 consistent hash 亲和；切换 pod 由 Inter-Pod 转发保持一致。

**背压**：FlowControlHint `cooldown_ms` + `suggested_rate_eps`；Agent 遵循 cooldown 暂停发起 POST。

### 6.4 L3 Domain-Fronted（独立信任域）

> **L3 不是 L0-L2 的语义等价兜底**。它把 TLS 终结从 Gateway 前移到 CDN 边缘，把身份来源从客户端证书换成 CDN 签发的 header。这是一次**信任域切换**，必须作为独立 trust zone 治理。

**架构**：
```
Agent ─► TLS(SNI="dXXXX.cloudfront.net") ─► CDN Edge ─► mTLS(Agent↔CDN) 终结
         Host="ingest.<region>.aegis.example"              │
                                                           ▼ (签名 header 回源)
                                                    Origin: Gateway L3 Adapter
                                                    (独立端口 :8444，独立证书)
```

**信任链与校验**：
- CDN 校验 Agent 客户端证书，提取 `agent_id` / `tenant_id` / `cert_fingerprint`
- 以 CDN↔Origin 独立密钥（Ed25519，HSM 签发）签入 `X-Aegis-L3-Identity` header
- Origin 仅接受合法 CDN 签名密钥签发的 header，并：
  - 校验时间戳新鲜度（≤ 60s）防重放
  - 校验 CDN PoP 的 mTLS（边缘到源站通道）
  - 拒绝未经签名或签名不通过的请求

**L3 信任模型对比 L0-L2**：

| 维度 | L0-L2 | L3 |
|------|-------|-----|
| 身份信任来源 | Gateway 直接校验客户端证书 | Gateway 信任 CDN 的 Ed25519 签名 header |
| 新信任根 | Aegis CA | Aegis CA **+ CDN↔Gateway 签名密钥 + CDN 运行时** |
| 被攻击面 | Gateway / Aegis CA | 同左 **+ CDN 边缘 + CDN 运营方 + 签名密钥管理** |
| 证书吊销 | CRL/OCSP 立即生效 | 取决于 CDN CRL 刷新 cadence（5-15min 额外延迟）|
| 端到端加密 | 点到点 TLS 1.3 | 两段：Agent↔CDN / CDN↔Origin；CDN 内部可见明文 |
| DoS 保护 | Gateway LB/WAF | CDN 原生 DDoS + Gateway 二次限流 |

**L3 功能降级清单（硬性约束）**：

| 命令类型 | L3 行为 |
|----------|---------|
| POLICY/RULE/IOC_UPDATE | 允许；`target_scope.tenant_id` 必须匹配 CDN 签名内 tenant |
| CONFIG_CHANGE | 允许；仅 AGENT_SET 精准投递 |
| FEEDBACK / REQUEST_PROCESS_INFO | 允许 |
| **RESPONSE_ACTION** | **禁止**（Gateway 强制拒绝；Orchestrator 侧检测 `transport=fronted` 延后到 L0-L2 恢复）|
| **REMOTE_SHELL** | **禁止**（同上；审批 UI 显式提示 Agent 在 L3 模式）|
| 上行 CRITICAL 告警 | 允许；Gateway 对 `transport=fronted` 的 CRITICAL 事件打 `l3_confidence_derating=true` |

**L3 专属 STRIDE**（补充主威胁模型）：

| STRIDE | 风险 | 控制 |
|--------|------|------|
| Spoofing | 非法源伪造 CDN header 直连 Origin | Origin IP 白名单（仅 CDN 边缘网段）+ mTLS（CDN→Origin 专用客户端证书）+ Ed25519 签名 header 双重校验 |
| Tampering | CDN 配置被篡改导致身份透传错误 | CDN 配置纳入 GitOps 审计 + 自动一致性巡检；Gateway 每日对签名密钥指纹独立校验 |
| Repudiation | CDN 投递/接收日志缺口 | CDN access log 强制开启，镜像至 `audit-log`；Origin 额外记录 `transport=fronted` |
| Info Disclosure | CDN 边缘明文暴露 payload | **Agent 在 L3 模式下额外启用 AES-256-GCM 端到端加密**（密钥由 Agent↔Gateway 协商，不经 CDN）|
| DoS | CDN 或其 PoP 故障致全租户 L3 瘫痪 | L3 仅作兜底；Agent 自动退回本地缓冲 + WAL |
| Elevation | CDN 签名密钥泄漏 | HSM 保护 + 24h 轮换 + 每次签名审计 + Gateway 签名密钥白名单热下线 |

**默认禁用 + Fail-closed 开关**：
- `transport.l3.enabled=false`（默认）；启用需平台管理员双人审批
- `transport.l3.kill_switch`：一键全局禁用 L3（返回 `TRANSPORT_DISABLED`，Agent 退回本地缓冲），用于 CDN 入侵 / 密钥泄漏
- 启用 L3 的租户必须签署"信任域扩展同意书"；审计日志保留 365 天

### 6.5 Fallback 协议适配层

```
┌────────────────────────────────────────────────────────────┐
│  Gateway Pod                                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ gRPC L0      │  │ WS L1        │  │ HTTP L2 / L3      │  │
│  │ :8443        │  │ :8443        │  │ :8080 / :8444     │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────────┘  │
│         │                  │                  │             │
│         └──────────────────┼──────────────────┘             │
│                            ▼                                 │
│              ┌───────────────────────────┐                   │
│              │  Transport Adapter Layer  │                   │
│              │  (统一为 UplinkMessage /   │                   │
│              │   DownlinkMessage 语义)    │                   │
│              └────────────┬──────────────┘                   │
│                           ▼                                   │
│              ┌───────────────────────────┐                   │
│              │  共享后端:                 │                   │
│              │  mTLS/CDN-Identity Verify │                   │
│              │  → Enrich → Kafka → Ack   │                   │
│              │  → Conn Registry → 下行   │                   │
│              └───────────────────────────┘                   │
└────────────────────────────────────────────────────────────┘
```

### 6.6 能力降级矩阵 & Kill-switch

| 层级 | 启用方式 | 流量占比预期 | 单 pod 连接上限 | 能力 |
|------|----------|---------------|-----------------|------|
| L0 gRPC | 默认 | > 95% | 16,000 稳态 / 20,000 硬 | 全功能 |
| L1 WebSocket | 自动 fallback | < 5% | 10,000 | 全功能（等价 L0） |
| L2 Long-Polling | 自动 fallback | < 1% | 5,000 | 全功能（等价 L0，延迟 ≈ poll_timeout/2）|
| L3 Fronted | **默认禁用**，显式开启 | 极少 | 独立 pod pool | **受限**（见 6.4 降级清单）|

**Kill-switches**：
- `transport.l3.enabled`：全局 L3 开关
- `transport.l3.kill_switch`：紧急禁用 L3
- `transport.l2.enabled`：L2 开关（长期部署可关闭）
- `transport.l1.enabled`：L1 开关

---

## 七、背压与流控

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
Gateway gRPC server-side flow control (WINDOW_UPDATE 缩小)
    ↓
Agent gRPC client 发送速率降低
    ↓
Agent 事件缓冲到 WAL (500MB, 24-48h 覆盖)
```

**核心原则**：系统从 ClickHouse 一路优雅退化到 Agent 侧 WAL，**不静默丢数据**。

### 7.2 Gateway 层触发点

| 机制 | 触发条件 | 动作 |
|------|----------|------|
| gRPC Server Flow Control | Kafka producer buffer > 80% | 减小 WINDOW_UPDATE 大小 |
| Kafka Producer Backoff | Kafka 不可用或 buffer 满 | 阻塞当前 batch；gRPC 背压自动向上游传导 |
| per-Agent Token Bucket | Agent 超过速率限制 | `BatchAck.REJECTED_RATE_LIMIT`（见 3.6）|
| per-Tenant Sliding Window | 租户配额耗尽 | `BatchAck.REJECTED_QUOTA_EXCEEDED` |
| WebSocket/LongPoll Credits | credits=0 | Agent 停发 |
| Circuit Breaker（Redis/Kafka）| 依赖失败率阈值 | 对应降级路径 |

### 7.3 WAL 回放协调

背压缓解后，Agent 回放 WAL 中缓冲的事件。Gateway 需要：

1. **速率控制**：WAL 回放与实时混合时，优先处理实时事件（通过 Agent 侧优先级通道 A）
2. **幂等去重**：基于 `(agent_id, sequence_id)` 去重
3. **水位标记**：WAL 回放事件携带 `is_replay=true` header，供下游区分

### 7.4 水位指标与告警

| 指标 | 正常 | 告警 | 动作 |
|------|------|------|------|
| `gateway_kafka_producer_buffer_usage_ratio` | < 60% | > 80% | 降 WINDOW_UPDATE |
| `gateway_batch_rejected_total{reason=backpressure}` rate | 0 | > 10/s 持续 1min | P2 告警 + 排查 Kafka |
| `gateway_grpc_flow_control_window_bytes` | stable | 持续缩小 | 监控关联指标 |
| Agent WAL utilization（上报至 Heartbeat）| < 30% | > 70% | Agent 自行降采样 LOW/INFO |

---

## 八、韧性与容错

### 8.1 多 AZ 部署 (3 AZ)

```
Region (e.g., us-west-2)
├── AZ-a: 30 Gateway pods + 5 Kafka brokers + 2 Redis shard primaries
├── AZ-b: 30 Gateway pods + 5 Kafka brokers + 2 Redis shard primaries
└── AZ-c: 30 Gateway pods + 5 Kafka brokers + 2 Redis shard primaries

故障容忍:
- 单 pod 故障: LB 摘除，Agent 重连 (< 5s)
- 单 AZ 故障: 剩余 2 AZ 承载 (66% → 100% 负载)
  - Gateway: 60 pods 需预扩容至 100+
  - Kafka: ISR=2 满足，leader 自动切换
  - Redis: 主从切换；跨 AZ 副本接管
- 双 AZ 故障: 不可用（设计上限）
```

### 8.2 无状态即时恢复

| 故障场景 | 恢复方式 | RTO | 数据影响 |
|----------|----------|-----|----------|
| 单 pod crash | K8s 重启 + Agent 重连 | < 15s | 0（WAL + sequence_id）|
| Pod OOM | K8s 重启 + HPA 可能触发 | < 30s | 0 |
| 全 AZ 故障 | LB 切换到存活 AZ + 预扩容脚本 | < 30s | 0 |
| 滚动更新 | 连接排水 → 新 pod 启动 | 0（zero-downtime）| 0 |

### 8.3 优雅关闭时序

见 3.8 节。`terminationGracePeriodSeconds=30`。

### 8.4 熔断器矩阵

| 依赖 | 失败阈值 | Open 时长 | Half-Open 探测 | 降级行为 |
|------|----------|-----------|-----------------|----------|
| Kafka 生产 | 10s 内 30% 错误率 | 15s | 3 probes | 阻塞 → gRPC 背压 → Agent WAL |
| Redis Asset cache | 10s 内 50% 错误率 | 30s | 5 probes | 跳过 Asset 富化 |
| Redis Connection Registry | 10s 内 50% 错误率 或 超时 > 100ms | 30s | 5 probes | LocalOwnershipCache + Fan-out-on-miss（§5.7）|
| MaxMind GeoIP | N/A（本地 mmap）| N/A | N/A | 文件损坏标记 `geo: null` |
| CRL/OCSP | 连续 5 次失败 | 300s | 1 probe | 使用本地缓存 CRL 继续 |
| Inter-Pod gRPC | 10s 内 40% 错误率 | 20s | 3 probes | 直接走 pending |

### 8.5 隔舱模式 (Bulkhead)

| 隔舱 | 资源 | 隔离方式 |
|------|------|----------|
| Ingestion Path（上行）| goroutine pool + Kafka producer pool | 独立资源 |
| Command Path（下行）| Kafka consumer + stream router | 独立 consumer group + goroutine |
| Heartbeat Path | goroutine pool | 独立，不与 ingestion 竞争 |
| Management API | HTTP handler pool | 独立端口（`:8080`）+ goroutine |
| Bulk Upload | goroutine pool + S3 client pool | 独立资源 + 带宽配额 |
| Inter-Pod Forward | HTTP/2 连接池 | 独立（`:9443`）|

**效果**：Kafka 生产路径完全阻塞时，Heartbeat 和 Management API 仍可用；诊断窗口不受影响。

### 8.6 重试策略

| 操作 | 策略 | 最大重试 | Backoff |
|------|------|----------|---------|
| Gateway → Kafka produce | 线性退避 | 5 | 100ms, 200ms, 500ms, 1s, 2s |
| Gateway → Redis query | 立即重试 | 2 | 0ms, 50ms |
| Gateway → CRL fetch | 指数退避 | Unlimited | 30s → 300s max |
| Inter-Pod Forward | 单次重试（仅 NOT_OWNER）| 1 | 刷新 Registry 后重试 |
| Agent → Gateway gRPC | 指数退避 + jitter | Unlimited（依赖 WAL）| 1s → 5min max |

### 8.7 Reconnect Storm 预扩容

当单 AZ 失效时，~33% Agent 在 30-120s 内向剩余 AZ 重连：

- **预扩容脚本**：监听 K8s node condition 或云商 AZ 事件，检测到 AZ 不可用时立即将 `minReplicas` 从 90 提升至 135（+50%），绕过 HPA 反应时间；AZ 恢复后 30min 回落
- **连接建立速率限制**：单 pod `accept ≤ 500 conn/s`；超限返回 TCP RST-retry，Agent 本地指数退避 jitter 重连
- **证书缓存预热**：mTLS session ticket 跨 AZ 共享（Redis），降低 resumption 握手成本

### 8.8 数据丢失防护

| 层 | 机制 | 覆盖范围 |
|----|------|----------|
| Agent → Gateway | BatchAck + sequence_id 幂等 | 可靠交付 + 去重 |
| Agent WAL | 本地持久化 + CRC32 校验 | 网络中断缓冲 24-48h |
| Gateway → Kafka | **统一 acks=all + ISR=2** | ISR 持久性 |
| Kafka | replication=3, ISR=2 | 容忍 1 AZ 故障 |
| Downlink Kafka 事务 | commands.pending EOS | 不存在"位点前进但 pending 未写"中间态 |
| 端到端 | lineage_id 检查点 | 审计完整性 |

---

## 九、安全设计

### 9.1 主信任域（L0-L2）

```
[Untrusted]             [Semi-Trusted]            [Trusted]
  Endpoints       mTLS   Transport Plane    mTLS   Analytics/Data/Management
  (可能被攻破)   ═════►  (L4 LB + Gateway)  ═════►  (K8s cluster + service mesh)
                         ● 验证 Agent 身份
                         ● 提取 Tenant ID
                         ● 不可伪造命令签名
                         ● 不可解密命令内容
                         ● 不可扩大广播扇出
```

**Semi-Trusted 定义**：Gateway 可读取遥测事件（用于富化），但**无法**：
- 伪造 ServerCommand 的 Ed25519 签名（私钥不在 Gateway）
- 冒充其他 Agent 或租户（身份来自 mTLS）
- 修改下行命令的审批策略（签名覆盖全部字段）
- 扩大广播命令扇出面（`target_scope` 已被签名覆盖，§12.1.3）

**即使 Gateway 被攻破**，攻击者也无法驱动 Agent 执行任何高危响应动作。

### 9.2 L3 独立信任域（Domain-Fronted，可选启用）

```
[Untrusted]           [Externally-Trusted]        [Semi-Trusted]              [Trusted]
  Endpoints    mTLS    CDN Edge (非 Aegis)  mTLS   Transport L3 Adapter  mTLS  Internal
                ═════►  ● 终结客户端 mTLS   ═════►  (独立端口 :8444)     ═════►
                        ● 签发 X-Aegis-L3-                ● 校验 CDN 签名
                          Identity                        ● 仅受限命令类型
                        ● 运行时由 CDN 管理
                              ▲
                              │ 新增信任根:
                              │ CDN 运行时 + CDN↔Origin 签名密钥(HSM)
```

**L3 新增的信任前提**（任一失守都放大攻击面）：
- CDN 运营方的运行时完整性（超出 Aegis 控制）
- CDN↔Origin 签名密钥的保密性（HSM + 24h 轮换）
- CDN 边缘 mTLS 配置的正确性（GitOps + 自动一致性巡检）

因此 L3 功能面被硬性限制（§6.4）：禁止 `RESPONSE_ACTION` / `REMOTE_SHELL`；payload 强制 AES-256-GCM 端到端加密；配备全局 kill-switch。

### 9.3 STRIDE 威胁模型

**主信任域（L0-L2）**：

| 边界 | 威胁 | 缓解 | 残余风险 |
|------|------|------|----------|
| Agent ↔ Gateway | Spoofing | mTLS + 每 Agent 独立证书；CN=agent_id, SAN=tenant_id | 证书泄露（CRL 缓解）|
| Agent ↔ Gateway | Tampering | TLS 1.3 + Protobuf schema + 广播 scope 入签名 | 无（TLS + 签名双保证）|
| Agent ↔ Gateway | Repudiation | lineage_id 全链路追踪；sequence logging | 低（lineage 保证可审计）|
| Agent ↔ Gateway | Info Disclosure | TLS 1.3 | TLS 侧信道（极低）|
| Agent ↔ Gateway | DoS | per-Agent 限速；证书吊销；LB DDoS | 分布式慢速 DoS |
| Agent ↔ Gateway | Elevation | Tenant 来自证书；TargetScope 签名覆盖 | 无 |
| Gateway ↔ Internal | Spoofing / Tampering | Service mesh mTLS；边界再次 Protobuf 校验 | 低 |

**L3 独立信任域**（见 6.4 节 STRIDE 表）。

### 9.4 多租户隔离（分层）

| 层 | 隔离机制 |
|----|----------|
| Agent 证书 | agent_id 和 tenant_id 写入证书 |
| Gateway 身份提取 | tenant_id 强制从 mTLS SAN 提取；payload 自报被覆盖 |
| Kafka Topics | `raw-events.{tenant}` 按租户独立 |
| 限速 | per-tenant Sliding Window 聚合配额 |
| 命令隔离 | Gateway 投递前三方交叉校验 `record.tenant_id == registry.tenant_id == stream.cert_tenant_id`（见 5.7 节不变量）|
| 物理隔离（可选）| 高安全租户 → 独立 Kafka topics + 独立 Gateway 部署 |

### 9.5 命令签名透传与 TargetScope 收窄

**Gateway 在命令投递中的角色**：纯透传 + 收窄路由。

1. Gateway 不解析 `command_data`，不修改 `payload` / `signature` / `signing_key_id`
2. **但** Gateway 必须解码 `ServerCommand.target_scope` 与 `tenant_id`（签名 payload 内），作为路由的唯一授权依据
3. Kafka header 的 `scope` 仅作缓存/预过滤，不得作扩散依据
4. 非法组合整批丢弃 + `commands.dead-letter`（见 5.4 节）
5. Agent 验签后**再次校验** `target_scope` 包含本机身份；不匹配即丢弃 + 本地审计（`COMMAND_SCOPE_VIOLATION`）

**签名入 scope 的理由**：若 scope 仅靠 Kafka header 承载，攻破生产方主题权限或中间转发链路的任一环节即可将 `AGENT_SET` 放大为 `TENANT` / `GLOBAL`。当前模型把扩散边界绑定到 Ed25519 签名覆盖，使 Gateway 和中间链路即使被攻破也无法扩大扇出面。

### 9.6 审计日志

| 审计事件 | 记录内容 | 存储 |
|----------|----------|------|
| 连接建立 | agent_id, tenant_id, source_ip, cert_serial, timestamp, transport | Kafka `audit-log` |
| 连接断开 | agent_id, reason, duration, events_processed | Kafka `audit-log` |
| 认证失败 | source_ip, failure_reason, cert_details | Kafka `audit-log` + P2 告警 |
| 限速触发 | agent_id, tenant_id, current_rate, limit | Prometheus + 日志 |
| 命令投递 | command_id, agent_id, tenant_id, command_type, delivery_time, owner_pod, via_forward(bool), transport | Kafka `audit-log` |
| scope_header_mismatch | command_id, header_scope, signed_scope | Kafka `audit-log` + P2 告警 |
| L3 访问 | agent_id, tenant_id, cdn_pop_id, sign_ts, l3_confidence_derating | Kafka `audit-log` |
| 管理操作 | operator, action, target, timestamp | Kafka `audit-log` |
| CriticalCommandDelayed | command_id, delayed_ms, pending_reason | Kafka `audit-log` + P1 告警 |

---

## 十、部署与容量

### 10.1 K8s Deployment & PDB

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ingestion-gateway
  namespace: aegis-transport
spec:
  replicas: 90
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 2
  selector:
    matchLabels:
      app: ingestion-gateway
  template:
    metadata:
      labels:
        app: ingestion-gateway
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
    spec:
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: topology.kubernetes.io/zone
          whenUnsatisfiable: DoNotSchedule
          labelSelector:
            matchLabels:
              app: ingestion-gateway
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                topologyKey: kubernetes.io/hostname
                labelSelector:
                  matchLabels:
                    app: ingestion-gateway
      terminationGracePeriodSeconds: 30
      containers:
        - name: gateway
          image: registry.aegis.internal/ingestion-gateway:v1.x.y
          resources:
            requests:
              cpu: "4"
              memory: "8Gi"
            limits:
              cpu: "8"
              memory: "16Gi"
          ports:
            - containerPort: 8443  # gRPC / WS (mTLS)
            - containerPort: 8080  # HTTP L2 + Admin
            - containerPort: 8444  # L3 Adapter (若启用)
            - containerPort: 9443  # Inter-Pod forward (cluster internal)
            - containerPort: 9090  # Prometheus
          env:
            - name: POD_UID
              valueFrom:
                fieldRef:
                  fieldPath: metadata.uid
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
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
          lifecycle:
            preStop:
              exec:
                command: ["/bin/sh", "-c", "curl -X POST http://localhost:8080/admin/drain; sleep 25"]
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: gateway-pdb
  namespace: aegis-transport
spec:
  minAvailable: "67%"
  selector:
    matchLabels:
      app: ingestion-gateway
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: gateway-internal-forward
  namespace: aegis-transport
spec:
  podSelector:
    matchLabels:
      app: ingestion-gateway
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: ingestion-gateway
      ports:
        - port: 9443
          protocol: TCP
```

### 10.2 HPA（连接数为主触发）

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: gateway-hpa
  namespace: aegis-transport
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ingestion-gateway
  minReplicas: 90        # 3 AZ × 30，满足 1M 稳态连接 + 单 AZ 失效后仍可承载
  maxReplicas: 150       # 3 AZ × 50，reconnect storm + 租户突增
  metrics:
    - type: Pods
      pods:
        metric:
          name: grpc_connections_active
        target:
          type: AverageValue
          averageValue: "12000"   # 16k 硬上限 × 75%
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
          value: 50
          periodSeconds: 60
        - type: Pods
          value: 30
          periodSeconds: 60
      selectPolicy: Max
    scaleDown:
      stabilizationWindowSeconds: 600
      policies:
        - type: Percent
          value: 10
          periodSeconds: 300
```

**为什么连接数是主触发**：Gateway 是连接密集型负载；每条常驻 gRPC 流占用固定 heap / goroutine / fd；CPU 会在连接数逼近上限前仍保持低位。仅用 CPU 触发会错过 AZ 失效后的重连风暴。

**Reconnect Storm 预扩容脚本**（见 8.7）：
- 监听 K8s node condition / 云商 AZ 事件
- AZ 不可用 → 临时 `minReplicas=135`（+50%）
- AZ 恢复 30min 后回落 `minReplicas=90`

### 10.3 灰度发布与回滚

**Canary 策略**：

| 阶段 | 比例 | 持续时间 | 监控指标 |
|------|------|----------|----------|
| 1 Canary | 5% | 2h | error rate, latency, throughput |
| 2 Blue-Green | 25% | 4h | 全量指标 + Agent 兼容性 |
| 3 Rolling | 50% | 12h | 按 AZ 逐步 |
| 4 Full | 100% | 持续 | — |

**回滚判据**（任一触发自动回滚）：
- Error rate > 0.1% 持续 5min
- P99 latency > 30ms 持续 5min
- Kafka produce failure rate > 1% 持续 3min
- gRPC connection failure rate > 0.5% 持续 3min
- Agent heartbeat loss rate > 1% 持续 5min
- commands.unicast 事务 abort rate > 0.5% 持续 3min

**流量分割**：Istio VirtualService + DestinationRule 按权重分流；可按 tenant_id header 精确控制 Canary 租户。

### 10.4 容量规划（连接预算驱动，1M 端点）

**基线原则**：Gateway 是连接密集型负载，容量规划**必须**以连接数为主约束，吞吐/CPU 为次约束。

**输入参数**：

| 参数 | 值 |
|------|-----|
| 全量 Agent 数 | 1,000,000 |
| 活跃连接比例（稳态 P50）| 70% → 700k |
| 活跃连接比例（峰值 P99）| 90% → 900k |
| 单 pod 连接 HPA target | 12,000（16k 硬上限 × 75%）|
| AZ 数 | 3 |
| 单 AZ 失效后允许利用率 | ≤ 85% |

**推导（以 900k 峰值为基准）**：

```
# 稳态 pod 数
pods_steady = ceil(900,000 / 12,000) = 75 pods

# AZ 失效后剩余容量约束
# 丢 1 AZ 后 (2/3)N pods 需承载 900k，每 pod ≤ 16,000 × 85% = 13,600
pods_az_survive = ceil(900,000 / 13,600 / (2/3)) = 100 pods

# Reconnect storm 头寸
# HPA + 预扩容最高扩至 150 pods

# 最终部署参数
minReplicas = 90     # 3 AZ × 30，预扩容时瞬时顶到 135
maxReplicas = 150    # 3 AZ × 50

# 吞吐校验（次约束）
events_per_pod = 8.3M / 90 ≈ 92k events/s （远低于单 pod 1M 能力）
```

**结论**：
- 稳态：90 pods
- AZ 失效 + 重连风暴：预扩容瞬时 135 pods，HPA 进一步扩至 150 pods
- AZ 恢复：30min 冷却后回落至 90 pods

### 10.5 Kafka 集群规模

```
kafka_brokers   = 15 (3 AZ × 5)
kafka_storage   = 3 TB/broker (5 TB/day × 3 days × 3 replicas / 15)
kafka_memory    = 32 GB/broker (JVM heap 6G + page cache 26G)
kafka_cpu       = 16 cores/broker
kafka_network   = 10 Gbps/broker
```

### 10.6 网络带宽

```
Agent → LB:       ~330 MB/s (压缩后)
LB → Gateway:     ~330 MB/s
Gateway → Kafka:  ~1.66 GB/s (解压后 + 富化)
Kafka internal:   ~5 GB/s (含 3x 复制)
跨 AZ 带宽:       ~3.3 GB/s (2/3 复制跨 AZ)
总出口带宽:       >= 50 Gbps
```

---

## 十一、可观测性

### 11.1 Prometheus 指标全集

**连接指标**：

| 指标 | 类型 | 标签 | 说明 |
|------|------|------|------|
| `gateway_grpc_connections_active` | Gauge | az, pod, transport | 活跃连接数（按 transport 打标）|
| `gateway_grpc_connections_total` | Counter | az, pod, status, transport | 累计连接数 |
| `gateway_tls_handshake_duration_seconds` | Histogram | az, result, resumption | 握手延迟 |
| `gateway_tls_handshake_failures_total` | Counter | az, reason | 握手失败 |
| `gateway_cert_revocation_rejections_total` | Counter | az, tenant | 吊销拒绝 |

**吞吐 & 延迟指标**：

| 指标 | 类型 | 标签 | 说明 |
|------|------|------|------|
| `gateway_events_received_total` | Counter | az, pod, tenant, priority | 接收事件总数 |
| `gateway_events_produced_total` | Counter | az, pod, topic, status | Kafka 写入事件总数 |
| `gateway_batches_processed_total` | Counter | az, pod, stream_type | 处理的 batch 数 |
| `gateway_batch_processing_duration_seconds` | Histogram | az, pod, step | 各步骤延迟 |
| `gateway_kafka_produce_duration_seconds` | Histogram | az, pod, topic, acks, priority | Kafka 生产延迟 |
| `gateway_enrichment_duration_seconds` | Histogram | az, pod, step | 富化延迟 |

**错误 & 限速指标**：

| 指标 | 类型 | 标签 | 说明 |
|------|------|------|------|
| `gateway_batch_rejected_total` | Counter | az, pod, reason, tenant | NACK 按原因分桶（见 3.6）|
| `gateway_schema_validation_failures_total` | Counter | az, pod, event_type | Schema 校验失败 |
| `gateway_rate_limit_rejections_total` | Counter | az, pod, tenant, level | 限速拒绝（agent/tenant）|
| `gateway_enrichment_failures_total` | Counter | az, pod, step | 富化失败（降级）|

**Kafka Producer 指标**：

| 指标 | 类型 | 标签 | 说明 |
|------|------|------|------|
| `gateway_kafka_producer_buffer_bytes` | Gauge | az, pod, producer_type | buffer 使用量 |
| `gateway_kafka_producer_inflight_requests` | Gauge | az, pod, producer_type | 进行中请求数 |
| `gateway_kafka_producer_retries_total` | Counter | az, pod, topic | 重试次数 |
| `gateway_unicast_tx_committed_total` | Counter | az, pod | Unicast 事务 commit 次数 |
| `gateway_unicast_tx_aborted_total` | Counter | az, pod, reason | Unicast 事务 abort |

**命令下发指标**：

| 指标 | 类型 | 标签 | 说明 |
|------|------|------|------|
| `gateway_commands_delivered_total` | Counter | az, pod, command_type, via | 投递（via=local/forward/pending）|
| `gateway_commands_delivery_duration_seconds` | Histogram | az, pod | 投递延迟 |
| `gateway_commands_scope_header_mismatch_total` | Counter | az, pod | scope header 与签名不一致（STRIDE Tampering）|
| `gateway_commands_target_scope_violation_total` | Counter | az, pod, reason | `target_scope` 违规丢弃（`max_fanout` / `GLOBAL`）|

**Registry & 降级指标**：

| 指标 | 类型 | 标签 | 说明 |
|------|------|------|------|
| `gateway_registry_circuit_state` | Gauge | az, pod, state | Registry 熔断状态（0=closed/1=half-open/2=open）|
| `gateway_local_lease_coverage_ratio` | Gauge | az, pod | 本 pod 活跃连接数 / Registry 记录数 |
| `gateway_critical_fanout_on_miss_total` | Counter | az, pod, result | Fan-out-on-miss 结果（delivered/pending/expired）|
| `gateway_pending_queue_depth` | Gauge | az, pod, tenant | Pending 索引深度 |

**Fallback 指标**：

| 指标 | 类型 | 标签 | 说明 |
|------|------|------|------|
| `gateway_transport_sessions_active` | Gauge | az, pod, transport | 按 transport 的活跃会话 |
| `gateway_l3_signature_verify_failures_total` | Counter | az, pod, reason | L3 CDN 签名校验失败 |
| `gateway_l3_kill_switch_active` | Gauge | az, pod | L3 kill switch 状态 |

### 11.2 Jaeger 分布式追踪

- 每个 EventBatch 创建 span，名称 `gateway.process_batch`
- 子 span：`gateway.decompress` / `validate` / `enrich` / `produce`
- `lineage_id` 注入 baggage，贯穿全链路
- 采样率：生产 1%；CRITICAL 事件 100%；调试模式可按 `tenant_id=<id>` 开关

**lineage_id 关联**：
```
Agent     Gateway     Flink     ClickHouse
  │         │           │           │
  ├─chkpt 1-6─►         │           │
  │         ├─chkpt 7──►│           │
  │         │           ├─chkpt 8──►│
  │         │           │           ├─chkpt 9
```

lineage_id 编码：`agent_id[64] | timestamp_ns[48] | seq[16]`

### 11.3 结构化日志

```json
{
  "timestamp": "2026-04-18T10:30:00.123Z",
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
  "acks_used": "all",
  "lineage_id": "abc123...",
  "trace_id": "def456...",
  "transport": "grpc"
}
```

**日志级别**：

| 级别 | 用途 | 生产默认 |
|------|------|----------|
| ERROR | 影响数据完整性的错误 | 开启 |
| WARN | 降级行为（Redis miss、限速触发、Registry 熔断）| 开启 |
| INFO | 连接建立/断开、batch 摘要 | 开启（采样）|
| DEBUG | 每事件级细节 | 关闭 |

**敏感数据脱敏**：
- Agent 证书 serial：保留末 8 位
- IP 地址：保留前 3 段
- tenant_id：完整记录
- 事件 payload：不记录

### 11.4 SLO 与告警矩阵

| SLO | 目标 | 告警阈值 | 级别 |
|-----|------|----------|------|
| 数据接入可用性 | 99.99% | Error rate > 0.01% 持续 5min | P1 (PagerDuty) |
| Gateway batch 处理 P99 | < 15ms | P99 > 20ms 持续 5min | P2 |
| Kafka produce 成功率 | 99.99% | Failure > 0.01% 持续 3min | P1 |
| gRPC 连接成功率 | 99.9% | Failure > 0.1% 持续 5min | P2 |
| Agent heartbeat 丢失率 | < 0.5% | Loss > 1% 持续 10min | P2 |
| commands.unicast consumer lag | < 1000 | Lag > 5000 持续 5min | P2 |
| Pod CPU 均值 | < 60% | > 80% 持续 5min | P3 |
| Unicast 事务 abort rate | < 0.1% | > 0.5% 持续 3min | P2 |
| scope_header_mismatch | 0 | > 0 | P2（安全事件）|
| target_scope violation | 0 | > 0 | P1（安全事件）|
| L3 signature verify fail | 0 | > 5 / 5min | P1（安全事件）|
| CriticalCommandDelayed | 0 | > 0 | P1 |

**告警通道**：

| 级别 | 通道 | 响应 |
|------|------|------|
| P1 | PagerDuty + Slack #soc-critical | < 5min |
| P2 | Slack #soc-alerts + Email | < 30min |
| P3 | Slack #infra-alerts | 下一工作日 |

### 11.5 诊断端点

| 端点 | 端口 | 方法 | 说明 |
|------|------|------|------|
| `/healthz` | 8080 | GET | Liveness |
| `/readyz` | 8080 | GET | Readiness（含 Kafka + Redis 连通性）|
| `/metrics` | 9090 | GET | Prometheus |
| `/debug/connections` | 8080 | GET | 活跃连接列表（脱敏） |
| `/debug/kafka` | 8080 | GET | Producer buffer / inflight / errors |
| `/debug/ratelimit` | 8080 | GET | Token bucket 状态 |
| `/debug/registry` | 8080 | GET | LocalOwnershipCache 摘要 + Registry 熔断状态 |
| `/admin/reload` | 8080 | POST | 热加载（GeoIP / CRL / 限速）|
| `/admin/drain` | 8080 | POST | 手动触发连接排水 |
| `/admin/l3/kill` | 8080 | POST | L3 kill switch（双人审批）|

**安全约束**：管理端点仅 ClusterIP；敏感操作（reload / drain / l3/kill）需 service mesh mTLS 认证。

---

## 十二、接口契约

> **单一事实来源**：`docs/architecture/aegis-transport-architecture.md §12`；此处保留实现落地要点。

### 12.1 Agent ↔ Gateway (UplinkMessage / DownlinkMessage)

```protobuf
service AgentService {
  rpc EventStream(stream UplinkMessage) returns (stream DownlinkMessage);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
  rpc UploadArtifact(stream ArtifactChunk) returns (UploadResult);
  rpc PullUpdate(UpdateRequest) returns (stream UpdateChunk);
}

message UplinkMessage {
  oneof kind {
    EventBatch event_batch = 1;
    ClientAck  client_ack  = 2;
  }
}

message DownlinkMessage {
  oneof kind {
    BatchAck            batch_ack      = 1;
    SignedServerCommand server_command = 2;
    FlowControlHint     flow_hint      = 3;
  }
}
```

**适用范围**：L0 gRPC / L1 WebSocket（帧内承载 UplinkMessage / DownlinkMessage）/ L2 Long-Polling（UplinkBundle / UplinkAckBundle / DownlinkPollRequest / DownlinkPollResponse 聚合）/ L3 Fronted（同 L2 + AES-256-GCM payload 层）。

### 12.2 BatchAck 状态机 & sequence_id 不变量

```protobuf
message EventBatch {
  string   batch_id          = 1;
  uint64   sequence_id       = 2;   // per-agent 单调递增
  uint32   event_count       = 3;
  bytes    compressed_events = 4;   // LZ4(Protobuf TelemetryEvent[])
  Priority priority          = 5;
  int64    batched_at        = 6;
}

message BatchAck {
  string  batch_id        = 1;
  uint64  sequence_id     = 2;
  Status  status          = 3;
  uint32  retry_after_ms  = 4;
  string  reason          = 5;
  int64   acked_at        = 6;

  enum Status {
    ACCEPTED                = 0;  // 已持久化 (acks=all + ISR 同步); Agent 推进 sequence_id
    REJECTED_RATE_LIMIT     = 1;  // 限速; 不推进
    REJECTED_BACKPRESSURE   = 2;  // 下游背压; 不推进
    REJECTED_MALFORMED      = 3;  // Schema 错误; 不重传
    REJECTED_AUTH           = 4;  // 证书/租户错; 重新 bootstrap
    REJECTED_QUOTA_EXCEEDED = 5;  // 租户配额; 大时间窗退避
    // 保留: ACCEPTED_NONDURABLE = 6  // 未来启用; Agent 不推进 sequence_id
  }
}

message ClientAck {
  string command_id   = 1;
  Status status       = 2;
  string error_detail = 3;
  int64  acked_at     = 4;
  enum Status { RECEIVED=0; EXECUTED=1; REJECTED=2; FAILED=3; }
}

message FlowControlHint {
  uint32 suggested_rate_eps = 1;
  uint32 cooldown_ms        = 2;
  string reason             = 3;
}
```

**回执时序契约**：
- Gateway 接收 EventBatch 后 **500ms 内**必须发 BatchAck（目标 P99 < 15ms）
- Agent 超时（默认 5s）后视为连接失效，关 stream 重连；按 sequence_id 回放 WAL
- **禁止**：接收 EventBatch 后不发 BatchAck / 返回 ACCEPTED 但部分事件未落库 / 在非 ACCEPTED 回执后推进 sequence_id

### 12.3 TargetScope 签名绑定

```protobuf
message SignedServerCommand {
  bytes  payload        = 1;  // ServerCommand 序列化字节
  bytes  signature      = 2;  // Ed25519 签名，覆盖 payload 全部字节
  string signing_key_id = 3;
}

message ServerCommand {
  string          command_id    = 1;
  string          tenant_id     = 2;
  string          agent_id      = 3;
  CommandType     type          = 4;
  bytes           command_data  = 5;
  int64           issued_at     = 6;
  uint32          ttl_ms        = 7;
  uint64          sequence_hint = 8;
  ApprovalPolicy  approval      = 9;
  TargetScope     target_scope  = 10;  // 签名覆盖的投递作用域
}

message TargetScope {
  enum Kind { AGENT=0; TENANT=1; AGENT_SET=2; GLOBAL=3; }
  Kind            kind       = 1;
  string          tenant_id  = 2;
  repeated string agent_ids  = 3;
  uint32          max_fanout = 4;
}
```

**Gateway 行为**：纯透传 + 收窄路由（见 9.5 节）。

### 12.4 Gateway → Kafka

| 字段 | 内容 |
|------|------|
| Topic | `raw-events.{tenant_id}` / `enriched-events` / `audit-log` / `commands.*` / `artifact-uploads` |
| Key | 见 §4.6 分区策略表 |
| Value | Protobuf 序列化 TelemetryEvent / SignedServerCommand / AuditEvent |
| Headers | `lineage_id`, `priority`, `event_type`, `gateway_pod`, `gateway_timestamp`, `transport`, `scope_hint`（仅缓存提示）|
| Compression | LZ4 |

### 12.5 GatewayInternal（Inter-Pod forward，`:9443`）

```protobuf
service GatewayInternal {
  rpc ForwardCommand(ForwardCommandRequest) returns (ForwardCommandAck);
}

message ForwardCommandRequest {
  string agent_id       = 1;
  uint64 owner_epoch    = 2;
  bytes  signed_command = 3;
  string lineage_id     = 4;
}

message ForwardCommandAck {
  enum Status { DELIVERED=0; NOT_OWNER=1; AGENT_BACKPRESSURED=2; INTERNAL_ERROR=3; }
  Status status = 1;
}
```

**鉴权**：独立内部 mTLS 证书（CN=`gateway.internal`），与 Agent 证书链隔离。

### 12.6 Admin / 健康检查

见 11.5 节。

---

## 十三、技术选型

### 13.1 Gateway 语言：Go

| 维度 | 说明 |
|------|------|
| 选择 | goroutine 并发模型天然适合 per-connection 处理（1M 连接 → 1M goroutine，开销可控）；gRPC-Go 生态成熟；单二进制 < 30s 编译；丰富网络库（net/http2, crypto/tls）；GC 暂停可控（< 1ms with GOGC tuning）|
| 场景 | I/O 密集型（网络 + Kafka 写入）非 CPU 密集；Go 的 I/O 调度器性能优异 |
| 团队效率 | 学习曲线低于 Rust；内存占用 + 启动时间优于 Java |
| 淘汰 | Rust（开发效率）/ Java-Netty（内存 + GC）/ C++（内存安全）/ Node.js（单线程 Protobuf 瓶颈）|

### 13.2 L4 LB：Envoy vs HAProxy

| 维度 | Envoy | HAProxy |
|------|-------|---------|
| gRPC | L7 原生 | 需 L4 TCP |
| 动态配置 | xDS（Istio）| 需 reload |
| 可观测 | Prometheus / Jaeger / access log | 基础统计 |
| 选择 | **首选** | 备选（极致性能）|

### 13.3 Kafka vs 备选

| 维度 | Kafka | Pulsar | NATS JetStream | RabbitMQ |
|------|-------|--------|----------------|----------|
| 吞吐 | 极高（10 GB/s+）| 高 | 高 | 中 |
| 持久性 | ISR 复制 | BookKeeper | RAFT | 镜像队列 |
| 保留 / 回放 | 原生 72h+ | 原生 | 有限 | 不支持 |
| 分区有序 | 是 | 是 | 是 | 否（默认）|
| 生态（Flink）| 极成熟 | 成熟 | 新兴 | 成熟 |
| 运维复杂度 | 中 | 高 | 低 | 低 |
| 选择 | **首选**（吞吐 + 生态 + 回放）| | | |

### 13.4 Redis Cluster for Connection Registry

| 维度 | Redis Cluster | etcd | Zookeeper | Cassandra |
|------|---------------|------|-----------|-----------|
| P99 latency | < 1ms | ~10ms | ~10ms | ~5ms |
| 吞吐（读）| 百万 ops/s | 10k ops/s | 10k ops/s | 10万 ops/s |
| 弱一致性容忍 | 是（AP）| 否（CP）| 否（CP）| 是（AP）|
| 数据结构 | Hash/ZSET/Lua | KV | KV/Watch | Wide-column |
| 选择 | **首选**（Registry 延迟敏感 + ZSET 原生支持 + Lua CAS）| | | |

### 13.5 GeoIP：MaxMind

| 维度 | MaxMind GeoIP2 | IP2Location | DB-IP |
|------|----------------|-------------|-------|
| 准确度 | ~80% | ~75% | ~70% |
| 更新 | 每周 | 每月 | 每月 |
| 格式 | MMDB（mmap 友好）| BIN | MMDB |
| 选择 | **首选** | | |

---

## 十四、关键性能基准

| 指标 | 目标 | 说明 |
|------|------|------|
| 单 batch 处理延迟 P50 | < 8ms | 含 Kafka acks=all ISR 同步，不含网络 RTT |
| 单 batch 处理延迟 P99 | < 20ms | 含 Redis 抖动、ISR 尾部 |
| 端到端 batch 延迟 P50 | < 12ms | 含 Agent → Gateway RTT |
| 端到端 batch 延迟 P99 | < 30ms | 含网络抖动 |
| 单 pod 事件吞吐 | ≥ 1.0M events/s | 8 vCPU 稳态；突发 1.5M |
| 单 pod gRPC 连接数 | 16,000 稳态 / 20,000 硬上限 | 16GB 内存；每条 ~80KB |
| 单 pod 网络吞吐 | ≤ 400 Mbps 稳态 / 800 Mbps 峰值 | 1Gbps NIC 留 20% |
| 集群总吞吐 | ≥ 8.3M events/s | 90 pods 稳态；最高 150 pods |
| Kafka produce 延迟 P50 | < 4ms | 统一 acks=all |
| Kafka produce 延迟 P99 | < 12ms | acks=all + ISR=2 |
| GeoIP lookup | < 1µs | mmap |
| Asset Tag lookup P50 | < 0.1ms | Redis hit |
| Asset Tag lookup P99 | < 1ms | Redis miss fallback |
| mTLS 握手 full | < 2ms | — |
| mTLS 握手 resumption | < 0.5ms | session ticket |
| Registry lookup P99 | < 1ms | Redis Cluster |
| Inter-Pod forward P99 | < 5ms | 集群内 gRPC |
| 下行命令投递 P50（unicast，本地）| < 10ms | 消费 → 本地 stream.send |
| 下行命令投递 P99（unicast，转发）| < 20ms | 含 Inter-Pod RTT |
| 广播命令扇出（单 pod，TENANT）| < 50ms | 遍历本 pod 连接表 |
| Pending 回放延迟（重连后）| < 200ms / 100 条 | Redis ZSET + stream batch send |
| Unicast 事务提交延迟 P99 | < 15ms | Kafka TXN commit |

---

## 附录 A：运行时配置样板

### A.1 Gateway 配置 (YAML)

```yaml
server:
  grpc:
    listen: ":8443"
    max_concurrent_streams: 100
    initial_window_size: 1048576     # 1MB
    max_frame_size: 16384            # 16KB
    keepalive_time: 30s
    keepalive_timeout: 10s
    max_connection_idle: 15m
    max_connection_age: 24h
    max_connection_age_grace: 30s
  admin:
    listen: ":8080"
  metrics:
    listen: ":9090"
  inter_pod:
    listen: ":9443"
  l3:
    listen: ":8444"
    enabled: false
    kill_switch: false

mtls:
  ca_cert: /etc/aegis/ca/ca.crt
  server_cert: /etc/aegis/tls/gateway.crt
  server_key: /etc/aegis/tls/gateway.key
  crl_path: /etc/aegis/crl/crl.pem
  crl_refresh_interval: 5m
  session_ticket_redis_key: gateway:session_ticket_key
  session_ticket_rotation: 6h

rate_limit:
  per_agent:
    algorithm: token_bucket
    rate_eps: 1000
    burst: 2000
    max_configurable_rate_eps: 5000
  per_tenant:
    algorithm: sliding_window
    window_ms: 60000
    quota_multiplier: 1.2
  accept_rate_per_pod: 500    # conn/s

kafka:
  bootstrap: kafka-1:9092,kafka-2:9092,kafka-3:9092
  tls: true
  sasl: SCRAM-SHA-512
  common_producer:
    acks: all
    enable_idempotence: true
    min_insync_replicas: 2
    compression_type: lz4
    retries: 2147483647
    delivery_timeout_ms: 120000
    max_in_flight: 5
  producers:
    high_priority:
      linger_ms: 0
      batch_size: 16384
      buffer_memory: 67108864
      max_in_flight: 1
    normal:
      linger_ms: 5
      batch_size: 65536
      buffer_memory: 536870912
    bulk:
      linger_ms: 10
      batch_size: 131072
      buffer_memory: 268435456
    transactional:
      transactional_id_prefix: gateway-
      linger_ms: 5
      batch_size: 65536
      buffer_memory: 134217728

consumers:
  unicast:
    group_id: gateway-unicast
    isolation_level: read_committed
    auto_offset_reset: earliest
  broadcast:
    group_id_prefix: gateway-bcast-
    isolation_level: read_committed
    auto_offset_reset: latest
  pending:
    group_id_prefix: gateway-pending-
    isolation_level: read_committed

registry:
  redis_cluster: redis-registry-1:6379,redis-registry-2:6379,redis-registry-3:6379
  conn_ttl: 48h
  heartbeat_refresh: 30s
  local_lease_ttl: 60s
  local_lease_refresh: 15s
  circuit_breaker:
    error_rate: 0.5
    timeout_ms: 100
    open_duration: 30s
    probes_half_open: 5

enrichment:
  geoip_db: /var/lib/maxmind/GeoLite2-City.mmdb
  geoip_refresh: 7d
  asset_cache_ttl: 300s
  asset_redis: redis-asset-cache:6379

observability:
  log_level: info
  log_sampling_rate: 0.1
  trace_sampling_rate: 0.01
  trace_critical_sampling_rate: 1.0
```

### A.2 Redis 事务 Lua 脚本（Registry DEL CAS）

```lua
-- registry_cas_delete.lua
-- KEYS[1] = conn:{agent_id}
-- ARGV[1] = expected_owner_pod
-- ARGV[2] = expected_epoch
local owner = redis.call('HGET', KEYS[1], 'owner_pod')
local epoch = redis.call('HGET', KEYS[1], 'epoch')
if owner == ARGV[1] and epoch == ARGV[2] then
    return redis.call('DEL', KEYS[1])
else
    return 0
end
```

### A.3 KafkaAdmin Topic 创建

```bash
# commands.pending with compact+delete
kafka-topics --create --topic commands.pending \
  --partitions 64 --replication-factor 3 \
  --config cleanup.policy=compact,delete \
  --config retention.ms=604800000 \
  --config min.insync.replicas=2 \
  --config min.cleanable.dirty.ratio=0.1

# commands.unicast shared group
kafka-topics --create --topic commands.unicast \
  --partitions 128 --replication-factor 3 \
  --config retention.ms=86400000 \
  --config min.insync.replicas=2

# commands.broadcast per-pod group
kafka-topics --create --topic commands.broadcast \
  --partitions 32 --replication-factor 3 \
  --config retention.ms=86400000 \
  --config min.insync.replicas=2
```

---

## 附录 B：与其他文档的交叉引用

| 本文档章节 | 引用文档 | 引用章节 | 说明 |
|-----------|---------|---------|------|
| 第一章 | `docs/architecture/aegis-transport-architecture.md` | §1-§3 | 架构总览 SSoT |
| 2.2 mTLS | `docs/architecture/aegis-transport-architecture.md` | §9.2 | 证书处理 |
| 2.5 DDoS | `docs/architecture/aegis-transport-architecture.md` | §9.5 | 防护体系 |
| 3.1 gRPC 端点 | `docs/architecture/aegis-sensor-architecture.md` | §4.5.5, §9.2 | Agent 侧接口对齐 |
| 3.6 BatchAck | `docs/architecture/aegis-transport-architecture.md` | §4.6.2.1 | 严格不丢弃契约 |
| 4.2 Producer | `docs/architecture/aegis-transport-architecture.md` | §4.4.3 | 持久化不妥协 |
| 4.4 Kafka 事务 | `docs/architecture/aegis-transport-architecture.md` | §4.5.4 | EOS 语义 |
| 5 下行路由 | `docs/architecture/aegis-transport-architecture.md` | §4.5 | Connection Ownership + Registry |
| 5.4 TargetScope | `docs/architecture/aegis-transport-architecture.md` | §12.1.3 | 签名覆盖 |
| 5.7 Registry 降级 | `docs/architecture/aegis-transport-architecture.md` | §4.5.7.4 | Fan-out-on-miss |
| 6 Fallback | `docs/architecture/aegis-transport-architecture.md` | §4.8 | L0-L3 |
| 6.4 L3 信任域 | `docs/architecture/aegis-transport-architecture.md` | §9.1, §9.4 | STRIDE |
| 7 背压 | `docs/architecture/aegis-architecture-design.md` | §5.3 | 全链路背压 |
| 8 韧性 | `docs/architecture/aegis-architecture-design.md` | §6.2-§6.4 | 多 AZ / 熔断 / 重试 |
| 9 安全 | `docs/architecture/aegis-architecture-design.md` | §7.1-§7.3 | 信任边界 / STRIDE / 多租户 |
| 10 部署 | `docs/architecture/aegis-architecture-design.md` | §8.1-§8.3 | K8s / HPA / 容量 |
| 11 可观测 | `docs/architecture/aegis-architecture-design.md` | §8.4 | 可观测性栈 / SLO |
| 12 接口 | `docs/architecture/aegis-transport-architecture.md` | §12 | 接口契约 SSoT |
| 交付范围 | `docs/技术方案/总技术解决方案.md` | §四 | Transport Plane 位置 |
| Agent 侧协议 | `docs/技术方案/sensor-final技术解决方案.md` | 六、通信子系统 | Agent 侧配套 |

---

## 附录 C：术语表

| 术语 | 说明 |
|------|------|
| Agent | 部署在终端的 Aegis Sensor 进程 |
| Gateway / Ingestion Gateway | 本文档主体对象，Transport Plane 的 L7 入口 |
| Transport Plane | Ingestion Gateway + Kafka Event Bus + 下行命令路由 + Fallback 的总称 |
| EventBatch | 一组遥测事件的 Protobuf 打包（100-500 事件/batch）|
| BatchAck | Gateway 对 EventBatch 的强制回执（见 §3.6, §12.2）|
| SignedServerCommand | Ed25519 签名封装的下行命令（payload + signature + signing_key_id）|
| ServerCommand | 被签名覆盖的命令 payload（含 target_scope）|
| TargetScope | 命令投递作用域（AGENT / TENANT / AGENT_SET / GLOBAL + max_fanout）|
| UplinkMessage / DownlinkMessage | Agent↔Gateway wire-level oneof 包络 |
| Connection Registry | Redis Cluster 中的 `conn:{agent_id}` → {owner_pod, epoch, ...} 视图 |
| LocalOwnershipCache | 每 pod 本地持有的连接 lease 表（60s），Registry 降级兜底 |
| Unicast | agent-scoped 下行命令（`commands.unicast`，shared consumer group）|
| Broadcast | tenant/global-scoped 下行命令（`commands.broadcast`，per-pod consumer group）|
| Inter-Pod Forward | 跨 pod 命令转发通道（`:9443` GatewayInternal gRPC）|
| Fan-out-on-miss | Registry 降级时对 CRITICAL 命令的 N-1 pod 广播兜底 |
| Fallback L0-L3 | 入口 transport 等级：gRPC / WebSocket / Long-Polling / Domain-Fronted |
| 主信任域 | L0-L2，点到点 mTLS |
| 独立信任域 (L3) | CDN 边缘终结 mTLS，Gateway 信任 CDN 签名 header；功能受限，默认禁用 |
| Strict No-Drop Contract | 严格不丢弃契约（整批 ACK/NACK，无部分接受）|
| sequence_id | per-agent 单调递增 ID，Agent 仅在 ACCEPTED 后推进；用于幂等去重 |
| lineage_id | 端到端事件追踪标识符（128bit）|
| WAL | Write-Ahead Log，Agent 侧离线事件缓冲 |
| ISR | In-Sync Replicas，Kafka 同步副本集（本项目 ≥ 2）|
| EOS | Exactly-Once Semantics（Kafka 事务语义）|
| PDB | Pod Disruption Budget |
| HPA | Horizontal Pod Autoscaler |
| OOB | Out-Of-Band，带外通道（紧急响应兜底）|

---

*文档版本：v1.0（2026-04-18）*
*基线：基于 `docs/architecture/aegis-transport-architecture.md v1.1`、`docs/architecture/aegis-sensor-architecture.md`、`docs/技术方案/总技术解决方案.md §4` 编写。*
*设计基线不妥协清单（摘要）：①acks=all + ISR=2 + idempotence（§4.2, I1/I10）；②Strict No-Drop（§3.6, I2）；③Connection Ownership + Kafka 事务（§5, I7）；④广播 per-pod group + target_scope 签名收窄（§5.4, I5/I6）；⑤L3 独立信任域 + 功能降级 + Kill-switch（§6.4/9.2, I8）；⑥容量按连接数预算（§10.4）；⑦签名透传（§9.5, I4）；⑧Registry 降级 Fan-out-on-miss（§5.7）。*
