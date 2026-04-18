use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Priority {
    Critical,
    High,
    Normal,
    Low,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventType {
    ProcessCreate,
    ProcessExit,
    FileWrite,
    NetConnect,
    RegistryWrite,
    Auth,
    Script,
    Memory,
    Container,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ProcessContext {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: String,
    pub exe_path: PathBuf,
    pub exe_hash: Option<String>,
    pub user: Option<String>,
    pub cwd: Option<PathBuf>,
    pub container_id: Option<String>,
    pub protection_level: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct EventPayload {
    pub fields: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NormalizedEvent {
    pub event_id: Uuid,
    pub lineage_id: Uuid,
    pub timestamp_ns: u64,
    pub event_type: EventType,
    pub priority: Priority,
    pub severity: Severity,
    pub process: ProcessContext,
    pub payload: EventPayload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub event_id: Uuid,
    pub lineage_id: Uuid,
    pub tenant_id: String,
    pub agent_id: String,
    pub event_type: EventType,
    pub priority: Priority,
    pub severity: Severity,
    pub process: ProcessContext,
    pub payload: EventPayload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Alert {
    pub alert_id: Uuid,
    pub lineage_id: Uuid,
    pub severity: Severity,
    pub summary: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Storyline {
    pub id: u64,
    pub root_event: Uuid,
    pub events: Vec<Uuid>,
    pub processes: Vec<u32>,
    pub tactics: Vec<String>,
    pub techniques: Vec<String>,
    pub narrative: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct EventBuffer {
    pub records: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SensorConfig {
    pub profile: String,
    pub queue_capacity: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkTarget {
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IsolationRulesV2 {
    pub ttl: Duration,
    pub allowed_control_plane_ips: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuarantineReceipt {
    pub vault_path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RollbackTarget {
    pub selector: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForensicSpec {
    pub include_memory: bool,
    pub include_registry: bool,
    pub include_network: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactBundle {
    pub artifact_id: Uuid,
    pub location: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub passed: bool,
    pub details: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SuspiciousProcess {
    pub pid: u32,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EtwStatus {
    pub healthy: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AmsiStatus {
    pub healthy: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BpfStatus {
    pub healthy: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ResponseAction {
    SuspendProcess { pid: u32 },
    KillProcess { pid: u32 },
    QuarantineFile { path: PathBuf },
    NetworkIsolate { ttl: Duration },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalProof {
    pub signature: Vec<u8>,
    pub signing_key_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApproverEntry {
    pub approver_id: String,
    pub role: String,
    pub proof: ApprovalProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalPolicy {
    pub min_approvers: u32,
    pub approvers: Vec<ApproverEntry>,
    pub policy_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandEnvelope {
    pub command_id: Uuid,
    pub command_type: String,
    pub target_scope: String,
    pub approval: ApprovalPolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct LineageCounters {
    pub rb_produced: u64,
    pub rb_consumed: u64,
    pub rb_dropped: u64,
    pub det_received: u64,
    pub dec_emitted: u64,
    pub wal_written: u64,
    pub grpc_acked: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentHealth {
    pub agent_version: String,
    pub policy_version: String,
    pub ruleset_version: String,
    pub model_version: String,
    pub cpu_percent_p95: f32,
    pub memory_rss_mb: u64,
    pub dropped_events_total: u64,
    pub lineage_counters: LineageCounters,
}
