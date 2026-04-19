use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

#[derive(
    Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub enum Priority {
    Critical,
    High,
    #[default]
    Normal,
    Low,
}

#[derive(
    Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(
    Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub enum EventType {
    ProcessCreate,
    ProcessExit,
    FileWrite,
    NetConnect,
    Alert,
    RegistryWrite,
    Auth,
    Script,
    Memory,
    Container,
    NamedPipe,
    ModuleLoad,
    DeviceControl,
    #[default]
    Unknown,
}

#[derive(
    Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub enum DecisionKind {
    #[default]
    Log,
    Alert,
    Response,
}

#[derive(
    Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub enum OperatingSystemKind {
    Windows,
    Linux,
    Macos,
    Container,
    #[default]
    Unknown,
}

#[derive(
    Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub enum TelemetryIntegrity {
    #[default]
    Full,
    Partial,
}

#[derive(
    Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub enum KillChainPhase {
    Reconnaissance,
    Weaponization,
    Delivery,
    Exploitation,
    Installation,
    CommandAndControl,
    ActionsOnObjectives,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostContext {
    pub hostname: String,
    pub os: OperatingSystemKind,
    pub ip_addresses: Vec<String>,
    pub mac_addresses: Vec<String>,
    pub asset_tags: Vec<String>,
}

impl Default for HostContext {
    fn default() -> Self {
        Self {
            hostname: "localhost".to_string(),
            os: OperatingSystemKind::Unknown,
            ip_addresses: Vec::new(),
            mac_addresses: Vec::new(),
            asset_tags: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureContext {
    pub publisher: Option<String>,
    pub trusted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessContext {
    pub pid: u32,
    pub ppid: u32,
    pub start_time_ns: u64,
    pub name: String,
    pub cmdline: String,
    pub exe_path: PathBuf,
    pub exe_hash: Option<String>,
    pub user: Option<String>,
    pub integrity: Option<String>,
    pub signature: Option<SignatureContext>,
    pub tree: Vec<u32>,
    pub cwd: Option<PathBuf>,
    pub env_vars: BTreeMap<String, String>,
    pub container_id: Option<String>,
    pub namespace_ids: Vec<String>,
    pub protection_level: Option<String>,
}

impl Default for ProcessContext {
    fn default() -> Self {
        Self {
            pid: 0,
            ppid: 0,
            start_time_ns: 0,
            name: String::new(),
            cmdline: String::new(),
            exe_path: PathBuf::new(),
            exe_hash: None,
            user: None,
            integrity: None,
            signature: None,
            tree: Vec::new(),
            cwd: None,
            env_vars: BTreeMap::new(),
            container_id: None,
            namespace_ids: Vec::new(),
            protection_level: None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct FileContext {
    pub path: PathBuf,
    pub hash: Option<String>,
    pub size: Option<u64>,
    pub entropy: Option<f32>,
    pub magic: Option<String>,
    pub action: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkContext {
    pub src_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
    pub dns_query: Option<String>,
    pub dns_response: Vec<String>,
    pub sni: Option<String>,
    pub ja3: Option<String>,
    pub ja3s: Option<String>,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryContext {
    pub key_path: String,
    pub value_name: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub operation: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthContext {
    pub logon_type: Option<String>,
    pub source_ip: Option<String>,
    pub user: Option<String>,
    pub domain: Option<String>,
    pub result: Option<String>,
    pub kerberos_type: Option<String>,
    pub elevation: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScriptContext {
    pub content: Option<String>,
    pub interpreter: Option<String>,
    pub obfuscation_layers: u32,
    pub deobfuscated_content: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryContext {
    pub region_address: Option<u64>,
    pub region_size: Option<u64>,
    pub protection: Option<String>,
    pub content_hash: Option<String>,
    pub injection_type: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerContext {
    pub container_id: String,
    pub image: Option<String>,
    pub pod_name: Option<String>,
    pub namespace: Option<String>,
    pub node_name: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlertContext {
    pub alert_id: Uuid,
    pub decision: DecisionKind,
    pub summary: String,
    pub storyline_id: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum EventPayload {
    None,
    File(FileContext),
    Network(NetworkContext),
    Alert(AlertContext),
    Registry(RegistryContext),
    Auth(AuthContext),
    Script(ScriptContext),
    Memory(MemoryContext),
    Container(ContainerContext),
    Generic(BTreeMap<String, String>),
}

impl Default for EventPayload {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeoContext {
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreatIntelHit {
    pub indicator: String,
    pub source: String,
    pub confidence: u8,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventEnrichment {
    pub geo: Option<GeoContext>,
    pub threat_intel: Vec<ThreatIntelHit>,
    pub mitre_ttps: Vec<String>,
    pub risk_score: u8,
    pub asset_criticality: Option<u8>,
    pub user_risk_score: Option<u8>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyscallOrigin {
    pub return_address: Option<u64>,
    pub expected_module: Option<String>,
    pub actual_module: Option<String>,
    pub is_direct: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorylineContext {
    pub storyline_id: u64,
    pub processes: Vec<u32>,
    pub tactics: Vec<String>,
    pub techniques: Vec<String>,
    pub kill_chain_phase: KillChainPhase,
    pub narrative: String,
}

#[derive(
    Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub enum LineageCheckpoint {
    #[default]
    RingBufferProduced,
    RingBufferConsumed,
    DetectionReceived,
    DecisionEmitted,
    WalWritten,
    GrpcAcked,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineageCheckpointMark {
    pub checkpoint: LineageCheckpoint,
    pub counter: u64,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineageTrace {
    pub lineage_id: Uuid,
    pub checkpoints: Vec<LineageCheckpointMark>,
    pub completeness: TelemetryIntegrity,
}

impl LineageTrace {
    pub fn new(lineage_id: Uuid, timestamp_ns: u64) -> Self {
        Self {
            lineage_id,
            checkpoints: vec![LineageCheckpointMark {
                checkpoint: LineageCheckpoint::RingBufferProduced,
                counter: 1,
                timestamp_ns,
            }],
            completeness: TelemetryIntegrity::Full,
        }
    }

    pub fn push(&mut self, checkpoint: LineageCheckpoint, counter: u64, timestamp_ns: u64) {
        self.checkpoints.push(LineageCheckpointMark {
            checkpoint,
            counter,
            timestamp_ns,
        });
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NormalizedEvent {
    pub event_id: Uuid,
    pub lineage_id: Uuid,
    pub timestamp_ns: u64,
    pub host: HostContext,
    pub event_type: EventType,
    pub priority: Priority,
    pub severity: Severity,
    pub process: ProcessContext,
    pub payload: EventPayload,
    pub container: Option<ContainerContext>,
    pub storyline: Option<StorylineContext>,
    pub enrichment: EventEnrichment,
    pub syscall_origin: Option<SyscallOrigin>,
    pub lineage: LineageTrace,
}

impl NormalizedEvent {
    pub fn new(
        timestamp_ns: u64,
        event_type: EventType,
        priority: Priority,
        severity: Severity,
        process: ProcessContext,
        payload: EventPayload,
    ) -> Self {
        let event_id = Uuid::now_v7();
        let lineage_id = Uuid::now_v7();

        Self {
            event_id,
            lineage_id,
            timestamp_ns,
            host: HostContext::default(),
            event_type,
            priority,
            severity,
            process,
            payload,
            container: None,
            storyline: None,
            enrichment: EventEnrichment::default(),
            syscall_origin: None,
            lineage: LineageTrace::new(lineage_id, timestamp_ns),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TelemetryEvent {
    pub event_id: Uuid,
    pub lineage_id: Uuid,
    pub timestamp_ns: u64,
    pub tenant_id: String,
    pub agent_id: String,
    pub integrity: TelemetryIntegrity,
    pub host: HostContext,
    pub event_type: EventType,
    pub priority: Priority,
    pub severity: Severity,
    pub process: ProcessContext,
    pub payload: EventPayload,
    pub container: Option<ContainerContext>,
    pub storyline: Option<StorylineContext>,
    pub enrichment: EventEnrichment,
    pub syscall_origin: Option<SyscallOrigin>,
    pub lineage: LineageTrace,
}

impl TelemetryEvent {
    pub fn from_normalized(event: &NormalizedEvent, tenant_id: String, agent_id: String) -> Self {
        Self {
            event_id: event.event_id,
            lineage_id: event.lineage_id,
            timestamp_ns: event.timestamp_ns,
            tenant_id,
            agent_id,
            integrity: event.lineage.completeness,
            host: event.host.clone(),
            event_type: event.event_type,
            priority: event.priority,
            severity: event.severity,
            process: event.process.clone(),
            payload: event.payload.clone(),
            container: event.container.clone(),
            storyline: event.storyline.clone(),
            enrichment: event.enrichment.clone(),
            syscall_origin: event.syscall_origin.clone(),
            lineage: event.lineage.clone(),
        }
    }

    pub fn from_alert(
        alert: &Alert,
        tenant_id: String,
        agent_id: String,
        timestamp_ns: u64,
    ) -> Self {
        let priority = match alert.severity {
            Severity::Critical => Priority::Critical,
            Severity::High => Priority::High,
            Severity::Medium => Priority::Normal,
            Severity::Low | Severity::Info => Priority::Low,
        };
        let lineage = LineageTrace::new(alert.lineage_id, timestamp_ns);

        Self {
            event_id: alert.alert_id,
            lineage_id: alert.lineage_id,
            timestamp_ns,
            tenant_id,
            agent_id,
            integrity: TelemetryIntegrity::Full,
            host: HostContext::default(),
            event_type: EventType::Alert,
            priority,
            severity: alert.severity,
            process: ProcessContext::default(),
            payload: EventPayload::Alert(AlertContext {
                alert_id: alert.alert_id,
                decision: alert.decision,
                summary: alert.summary.clone(),
                storyline_id: alert.storyline_id,
            }),
            container: None,
            storyline: None,
            enrichment: EventEnrichment::default(),
            syscall_origin: None,
            lineage,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Alert {
    pub alert_id: Uuid,
    pub lineage_id: Uuid,
    pub storyline_id: Option<u64>,
    pub severity: Severity,
    pub decision: DecisionKind,
    pub summary: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Storyline {
    pub id: u64,
    pub root_event: Uuid,
    pub events: Vec<Uuid>,
    pub processes: Vec<u32>,
    pub tactics: Vec<String>,
    pub techniques: Vec<String>,
    pub severity: Severity,
    pub kill_chain_phase: KillChainPhase,
    pub auto_narrative: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct EventBuffer {
    pub records: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SensorConfig {
    pub profile: String,
    pub queue_capacity: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SensorCapabilities {
    pub process: bool,
    pub file: bool,
    pub network: bool,
    pub registry: bool,
    pub auth: bool,
    pub script: bool,
    pub memory: bool,
    pub container: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkTarget {
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IsolationRulesV2 {
    pub ttl: Duration,
    pub allowed_control_plane_ips: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineReceipt {
    pub vault_path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackTarget {
    pub selector: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForensicSpec {
    pub include_memory: bool,
    pub include_registry: bool,
    pub include_network: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactBundle {
    pub artifact_id: Uuid,
    pub location: PathBuf,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityReport {
    pub passed: bool,
    pub details: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuspiciousProcess {
    pub pid: u32,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EtwStatus {
    pub healthy: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AmsiStatus {
    pub healthy: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BpfStatus {
    pub healthy: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponseAction {
    SuspendProcess { pid: u32 },
    KillProcess { pid: u32 },
    QuarantineFile { path: PathBuf },
    NetworkIsolate { ttl: Duration },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalProof {
    pub signature: Vec<u8>,
    pub signing_key_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApproverEntry {
    pub approver_id: String,
    pub role: String,
    pub proof: ApprovalProof,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalPolicy {
    pub min_approvers: u32,
    pub approvers: Vec<ApproverEntry>,
    pub policy_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandEnvelope {
    pub command_id: Uuid,
    pub command_type: String,
    pub target_scope: String,
    pub approval: ApprovalPolicy,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TargetScopeKind {
    Agent,
    Tenant,
    AgentSet,
    Global,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetScope {
    pub kind: TargetScopeKind,
    pub tenant_id: Option<String>,
    pub agent_ids: Vec<String>,
    pub max_fanout: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerCommand {
    pub command_id: Uuid,
    pub tenant_id: String,
    pub agent_id: String,
    pub command_type: String,
    pub command_data: Vec<u8>,
    pub issued_at_ms: i64,
    pub ttl_ms: u32,
    pub sequence_hint: u64,
    pub approval: ApprovalPolicy,
    pub target_scope: TargetScope,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedServerCommand {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub signing_key_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EventBatch {
    pub batch_id: Uuid,
    pub tenant_id: String,
    pub agent_id: String,
    pub sequence_hint: u64,
    pub events: Vec<TelemetryEvent>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientAckStatus {
    Received,
    Executed,
    Rejected,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientAck {
    pub command_id: Uuid,
    pub status: ClientAckStatus,
    pub detail: Option<String>,
    pub acked_at: i64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BatchAckStatus {
    Accepted,
    RejectedRateLimit,
    RejectedBackpressure,
    RejectedMalformed,
    RejectedAuth,
    RejectedQuotaExceeded,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchAck {
    pub batch_id: Uuid,
    pub sequence_id: u64,
    pub status: BatchAckStatus,
    pub retry_after_ms: u32,
    pub reason: Option<String>,
    pub acked_at: i64,
    pub accepted_events: u32,
    pub rejected_events: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowControlHint {
    pub pause_low_priority: bool,
    pub max_batch_events: usize,
    pub suggested_rate_eps: Option<u32>,
    pub cooldown_ms: Option<u32>,
    pub reason: Option<String>,
}

#[derive(
    Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub enum CommunicationChannelKind {
    #[default]
    Grpc,
    WebSocket,
    LongPolling,
    DomainFronting,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunicationChannelHealth {
    pub channel: CommunicationChannelKind,
    pub healthy: bool,
    pub consecutive_failures: u32,
    pub last_attempt_ms: Option<i64>,
    pub last_success_ms: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunicationRuntimeStatus {
    pub active_channel: CommunicationChannelKind,
    pub degraded: bool,
    pub fallback_chain: Vec<CommunicationChannelKind>,
    pub last_success_ms: Option<i64>,
    pub channels: Vec<CommunicationChannelHealth>,
}

impl Default for CommunicationRuntimeStatus {
    fn default() -> Self {
        let fallback_chain = vec![
            CommunicationChannelKind::Grpc,
            CommunicationChannelKind::WebSocket,
            CommunicationChannelKind::LongPolling,
            CommunicationChannelKind::DomainFronting,
        ];
        let channels = fallback_chain
            .iter()
            .copied()
            .map(|channel| CommunicationChannelHealth {
                channel,
                healthy: false,
                consecutive_failures: 0,
                last_attempt_ms: None,
                last_success_ms: None,
                last_error: None,
            })
            .collect();
        Self {
            active_channel: CommunicationChannelKind::Grpc,
            degraded: false,
            fallback_chain,
            last_success_ms: None,
            channels,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum UplinkMessage {
    EventBatch(EventBatch),
    ClientAck(ClientAck),
    FlowControlHint(FlowControlHint),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DownlinkMessage {
    BatchAck(BatchAck),
    ServerCommand(SignedServerCommand),
    FlowControlHint(FlowControlHint),
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LineageCounters {
    pub rb_produced: u64,
    pub rb_produced_by_event_type: BTreeMap<EventType, u64>,
    pub rb_consumed: u64,
    pub det_received: u64,
    pub dec_emitted: u64,
    pub dec_emitted_by_kind: BTreeMap<DecisionKind, u64>,
    pub wal_written: u64,
    pub grpc_acked: u64,
    pub rb_dropped: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AgentHealth {
    pub agent_version: String,
    pub policy_version: String,
    pub ruleset_version: String,
    pub model_version: String,
    pub cpu_percent_p95: f32,
    pub memory_rss_mb: u64,
    pub queue_depths: BTreeMap<String, usize>,
    pub dropped_events_total: u64,
    pub lineage_counters: LineageCounters,
    pub runtime_signals: RuntimeHealthSignals,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HeartbeatRequest {
    pub tenant_id: String,
    pub agent_id: String,
    pub health: AgentHealth,
    pub communication: CommunicationRuntimeStatus,
    pub wal_utilization_ratio: f32,
    pub restart_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeartbeatResponse {
    pub server_time_ms: i64,
    pub pending_update_ids: Vec<String>,
    pub config_changed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactChunk {
    pub upload_id: Uuid,
    pub artifact_kind: String,
    pub chunk_index: u32,
    pub bytes: Vec<u8>,
    pub eof: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UploadResult {
    pub upload_id: Uuid,
    pub accepted_chunks: u32,
    pub accepted_bytes: u64,
    pub digest_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateRequest {
    pub tenant_id: String,
    pub agent_id: String,
    pub channel: String,
    pub current_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateChunk {
    pub artifact_id: String,
    pub chunk_index: u32,
    pub bytes: Vec<u8>,
    pub eof: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeHealthSignals {
    pub communication_channel: CommunicationChannelKind,
    pub adaptive_whitelist_size: usize,
    pub etw_tamper_detected: bool,
    pub amsi_tamper_detected: bool,
    pub bpf_integrity_pass: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginHealthStatus {
    pub plugin_id: String,
    pub healthy: bool,
    pub state: String,
    pub crash_count: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HotUpdateManifest {
    pub artifact_id: String,
    pub target_version: String,
    pub rollout_channel: String,
    pub target_conf_version: u32,
    pub target_schema_version: i64,
    pub artifact_sha256: String,
    pub rollback_artifact_id: Option<String>,
    pub rollback_artifact_sha256: Option<String>,
    pub signature: Vec<u8>,
    pub signing_key_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSupervisorHeartbeat {
    pub tenant_id: String,
    pub agent_id: String,
    pub plugin_count: usize,
    pub degraded_plugins: usize,
    pub active_update_id: Option<String>,
    pub sent_at_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchdogHeartbeat {
    pub tenant_id: String,
    pub agent_id: String,
    pub watchdog_id: String,
    pub observed_agent_restart_epoch: u64,
    pub unhealthy_plugins: usize,
    pub sent_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WatchdogAlertKind {
    AgentMissedHeartbeat,
    WatchdogMissedHeartbeat,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchdogAlert {
    pub kind: WatchdogAlertKind,
    pub message: String,
    pub last_seen_ms: Option<i64>,
    pub observed_at_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SidecarControlMessage {
    pub tenant_id: String,
    pub agent_id: String,
    pub operation: String,
    pub metadata: BTreeMap<String, String>,
    pub sent_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuntimeProviderKind {
    AwsLambda,
    AwsFargate,
    AzureFunctions,
    AzureContainerInstances,
    GoogleCloudRun,
    Wasm,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuntimeSignalKind {
    HttpRequest,
    HttpResponse,
    FileAccess,
    ProcessSpawn,
    SocketConnect,
    EnvRead,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeMetadata {
    pub provider: RuntimeProviderKind,
    pub service: String,
    pub runtime: String,
    pub region: Option<String>,
    pub account_id: Option<String>,
    pub invocation_id: String,
    pub cold_start: bool,
    pub function_name: Option<String>,
    pub container_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSdkEvent {
    pub contract_version: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub sequence_hint: u64,
    pub signal_kind: RuntimeSignalKind,
    pub metadata: RuntimeMetadata,
    pub process: ProcessContext,
    pub labels: BTreeMap<String, String>,
    pub attributes: BTreeMap<String, String>,
    pub occurred_at_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeHeartbeat {
    pub contract_version: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub metadata: RuntimeMetadata,
    pub policy_version: String,
    pub active_invocations: u32,
    pub buffered_events: usize,
    pub dropped_events_total: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeBridgeStatus {
    pub control_socket_path: Option<String>,
    pub buffered_events: usize,
    pub emitted_batches: u64,
    pub last_runtime_heartbeat_ms: Option<i64>,
    pub last_connector_cursor: Option<CloudConnectorCursor>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicyContract {
    pub contract_version: String,
    pub policy_version: String,
    pub blocked_env_keys: Vec<String>,
    pub blocked_destinations: Vec<String>,
    pub max_request_body_bytes: u32,
    pub require_response_sampling: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CloudLogSourceKind {
    AwsCloudTrail,
    AwsCloudWatch,
    AzureMonitor,
    GcpAuditLog,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudApiRecord {
    pub contract_version: String,
    pub tenant_id: String,
    pub connector_id: String,
    pub source: CloudLogSourceKind,
    pub account_id: String,
    pub region: Option<String>,
    pub service: String,
    pub action: String,
    pub principal: Option<String>,
    pub resource_id: Option<String>,
    pub request_id: String,
    pub observed_at_ms: i64,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudConnectorCursor {
    pub source: CloudLogSourceKind,
    pub shard: String,
    pub checkpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudApiConnectorContract {
    pub contract_version: String,
    pub connector_id: String,
    pub source: CloudLogSourceKind,
    pub poll_interval_secs: u32,
    pub max_batch_records: usize,
    pub cursor: Option<CloudConnectorCursor>,
}

#[cfg(test)]
mod tests {
    use super::{
        AgentSupervisorHeartbeat, CloudApiConnectorContract, CloudApiRecord, CloudConnectorCursor,
        CloudLogSourceKind, CommunicationChannelKind, CommunicationRuntimeStatus, EventBatch,
        EventPayload, EventType, FileContext, HotUpdateManifest, NormalizedEvent,
        PluginHealthStatus, Priority, ProcessContext, RuntimeBridgeStatus, RuntimeHealthSignals,
        RuntimeHeartbeat, RuntimeMetadata, RuntimePolicyContract, RuntimeProviderKind,
        RuntimeSdkEvent, RuntimeSignalKind, Severity, SidecarControlMessage, TelemetryEvent,
        TelemetryIntegrity, UplinkMessage, WatchdogAlert, WatchdogAlertKind, WatchdogHeartbeat,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[test]
    fn telemetry_event_preserves_lineage_and_payload() {
        let event = NormalizedEvent::new(
            1_710_000_000,
            EventType::FileWrite,
            Priority::High,
            Severity::High,
            ProcessContext {
                pid: 1001,
                name: "powershell.exe".to_string(),
                exe_path: PathBuf::from("/usr/bin/pwsh"),
                ..ProcessContext::default()
            },
            EventPayload::File(FileContext {
                path: PathBuf::from("/tmp/dropper.bin"),
                hash: Some("abc123".to_string()),
                size: Some(4096),
                ..FileContext::default()
            }),
        );
        let telemetry =
            TelemetryEvent::from_normalized(&event, "tenant-a".to_string(), "agent-a".to_string());

        assert_eq!(telemetry.lineage_id, event.lineage_id);
        assert_eq!(telemetry.lineage.lineage_id, event.lineage_id);
        assert_eq!(telemetry.process.pid, 1001);
        assert!(matches!(telemetry.payload, EventPayload::File(_)));
        assert_eq!(telemetry.integrity, TelemetryIntegrity::Full);
    }

    #[test]
    fn normalized_event_bootstraps_first_lineage_checkpoint() {
        let event = NormalizedEvent::new(
            42,
            EventType::ProcessCreate,
            Priority::Normal,
            Severity::Info,
            ProcessContext::default(),
            EventPayload::None,
        );

        assert_eq!(event.lineage.lineage_id, event.lineage_id);
        assert_eq!(event.lineage.checkpoints.len(), 1);
    }

    #[test]
    fn uplink_message_wraps_event_batch() {
        let event = TelemetryEvent::from_normalized(
            &NormalizedEvent::new(
                99,
                EventType::Unknown,
                Priority::Low,
                Severity::Info,
                ProcessContext::default(),
                EventPayload::None,
            ),
            "tenant-a".to_string(),
            "agent-a".to_string(),
        );
        let message = UplinkMessage::EventBatch(EventBatch {
            batch_id: uuid::Uuid::now_v7(),
            tenant_id: "tenant-a".to_string(),
            agent_id: "agent-a".to_string(),
            sequence_hint: 7,
            events: vec![event],
        });

        match message {
            UplinkMessage::EventBatch(batch) => {
                assert_eq!(batch.tenant_id, "tenant-a");
                assert_eq!(batch.events.len(), 1);
            }
            _ => panic!("expected event batch"),
        }
    }

    #[test]
    fn runtime_and_cloud_contracts_capture_serverless_shapes() {
        let metadata = RuntimeMetadata {
            provider: RuntimeProviderKind::AwsLambda,
            service: "orders-api".to_string(),
            runtime: "python3.12".to_string(),
            region: Some("ap-southeast-1".to_string()),
            account_id: Some("123456789012".to_string()),
            invocation_id: "invoke-1".to_string(),
            cold_start: true,
            function_name: Some("orders-handler".to_string()),
            container_id: None,
        };
        let event = RuntimeSdkEvent {
            contract_version: "serverless.v1".to_string(),
            tenant_id: "tenant-a".to_string(),
            agent_id: "runtime-sdk".to_string(),
            sequence_hint: 10,
            signal_kind: RuntimeSignalKind::HttpRequest,
            metadata: metadata.clone(),
            process: ProcessContext {
                pid: 7,
                name: "python".to_string(),
                ..ProcessContext::default()
            },
            labels: BTreeMap::from([("route".to_string(), "/orders".to_string())]),
            attributes: BTreeMap::from([("method".to_string(), "POST".to_string())]),
            occurred_at_ms: 1_713_000_000_000,
        };
        let heartbeat = RuntimeHeartbeat {
            contract_version: "serverless.v1".to_string(),
            tenant_id: "tenant-a".to_string(),
            agent_id: "runtime-sdk".to_string(),
            metadata,
            policy_version: "policy-7".to_string(),
            active_invocations: 2,
            buffered_events: 8,
            dropped_events_total: 0,
        };
        let health_signals = RuntimeHealthSignals {
            communication_channel: CommunicationChannelKind::Grpc,
            adaptive_whitelist_size: 3,
            etw_tamper_detected: false,
            amsi_tamper_detected: false,
            bpf_integrity_pass: true,
        };
        let policy = RuntimePolicyContract {
            contract_version: "serverless.v1".to_string(),
            policy_version: "policy-7".to_string(),
            blocked_env_keys: vec!["AWS_SECRET_ACCESS_KEY".to_string()],
            blocked_destinations: vec!["169.254.169.254".to_string()],
            max_request_body_bytes: 8192,
            require_response_sampling: true,
        };
        let communication = CommunicationRuntimeStatus::default();
        let connector = CloudApiConnectorContract {
            contract_version: "serverless.v1".to_string(),
            connector_id: "aws-cloudtrail".to_string(),
            source: CloudLogSourceKind::AwsCloudTrail,
            poll_interval_secs: 60,
            max_batch_records: 500,
            cursor: Some(CloudConnectorCursor {
                source: CloudLogSourceKind::AwsCloudTrail,
                shard: "us-east-1".to_string(),
                checkpoint: "event-42".to_string(),
            }),
        };
        let record = CloudApiRecord {
            contract_version: "serverless.v1".to_string(),
            tenant_id: "tenant-a".to_string(),
            connector_id: "aws-cloudtrail".to_string(),
            source: CloudLogSourceKind::AwsCloudTrail,
            account_id: "123456789012".to_string(),
            region: Some("us-east-1".to_string()),
            service: "lambda.amazonaws.com".to_string(),
            action: "Invoke".to_string(),
            principal: Some("svc-orders".to_string()),
            resource_id: Some("arn:aws:lambda:us-east-1:123456789012:function:orders".to_string()),
            request_id: "req-42".to_string(),
            observed_at_ms: 1_713_000_100_000,
            attributes: BTreeMap::from([("sourceIp".to_string(), "10.0.0.8".to_string())]),
        };
        let plugin = PluginHealthStatus {
            plugin_id: "runtime-audit".to_string(),
            healthy: true,
            state: "running".to_string(),
            crash_count: 0,
        };
        let manifest = HotUpdateManifest {
            artifact_id: "artifact-42".to_string(),
            target_version: "1.2.3".to_string(),
            rollout_channel: "canary".to_string(),
            target_conf_version: 2,
            target_schema_version: 4,
            artifact_sha256: "abc123".to_string(),
            rollback_artifact_id: Some("artifact-41".to_string()),
            rollback_artifact_sha256: Some("def456".to_string()),
            signature: vec![1, 2, 3],
            signing_key_id: "server-k1".to_string(),
        };
        let agent_supervisor = AgentSupervisorHeartbeat {
            tenant_id: "tenant-a".to_string(),
            agent_id: "agent-a".to_string(),
            plugin_count: 1,
            degraded_plugins: 0,
            active_update_id: Some("artifact-42".to_string()),
            sent_at_ms: 1_713_000_200_000,
        };
        let watchdog = WatchdogHeartbeat {
            tenant_id: "tenant-a".to_string(),
            agent_id: "agent-a".to_string(),
            watchdog_id: "watchdog-local".to_string(),
            observed_agent_restart_epoch: 3,
            unhealthy_plugins: 0,
            sent_at_ms: 1_713_000_200_100,
        };
        let alert = WatchdogAlert {
            kind: WatchdogAlertKind::WatchdogMissedHeartbeat,
            message: "watchdog heartbeat overdue".to_string(),
            last_seen_ms: Some(1_713_000_199_000),
            observed_at_ms: 1_713_000_205_000,
        };
        let sidecar_message = SidecarControlMessage {
            tenant_id: "tenant-a".to_string(),
            agent_id: "agent-a".to_string(),
            operation: "flush-telemetry".to_string(),
            metadata: BTreeMap::from([("socket".to_string(), "/var/run/aegis.sock".to_string())]),
            sent_at_ms: 1_713_000_206_000,
        };
        let bridge_status = RuntimeBridgeStatus {
            control_socket_path: Some("/var/run/aegis.sock".to_string()),
            buffered_events: 3,
            emitted_batches: 2,
            last_runtime_heartbeat_ms: Some(1_713_000_207_000),
            last_connector_cursor: connector.cursor.clone(),
        };

        assert_eq!(event.contract_version, heartbeat.contract_version);
        assert_eq!(heartbeat.policy_version, policy.policy_version);
        assert_eq!(connector.contract_version, record.contract_version);
        assert_eq!(record.source, CloudLogSourceKind::AwsCloudTrail);
        assert_eq!(
            health_signals.communication_channel,
            CommunicationChannelKind::Grpc
        );
        assert_eq!(communication.active_channel, CommunicationChannelKind::Grpc);
        assert!(plugin.healthy);
        assert_eq!(
            manifest.rollback_artifact_id.as_deref(),
            Some("artifact-41")
        );
        assert_eq!(agent_supervisor.plugin_count, 1);
        assert_eq!(watchdog.observed_agent_restart_epoch, 3);
        assert_eq!(alert.kind, WatchdogAlertKind::WatchdogMissedHeartbeat);
        assert_eq!(sidecar_message.operation, "flush-telemetry");
        assert_eq!(bridge_status.emitted_batches, 2);
    }
}
