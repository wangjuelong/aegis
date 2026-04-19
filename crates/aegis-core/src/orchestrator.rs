use crate::comms::{
    AgentIdentity, CommandReplayLedger, CommandValidator, CommunicationRuntime, HeartbeatBuilder,
    TelemetryBatchBuilder,
};
use crate::config::AppConfig;
use crate::correlation::{CorrelationCache, StorylineEngine};
use crate::feedback::ThreatFeedbackApplier;
use crate::health::HealthReporter;
use crate::high_risk_ops::{
    ApprovalQueue, PlaybookRuntime, PreApprovedPlaybook, RemoteShellPolicy, RemoteShellRuntime,
    SessionLockRequest, SessionLockRuntime,
};
use crate::ioc::{Indicator, IndicatorKind, IndicatorRisk, TieredIndicatorIndex};
use crate::ml::{
    FeatureExtractor, ModelInput, ModelKind, ModelOutput, ModelRegistry, OnnxRuntimeSession,
    OodScorer, RegisteredModel,
};
use crate::response_executor::{
    ResponseActionKind, ResponseAuditLog, ResponseAuditRecord, ResponseExecutor, TerminationRequest,
};
use crate::rule_vm::{CompareOp, CompiledRule, Instruction, RuleField, RuleValue, RuleVm};
use crate::runtime_sdk::{CloudConnectorRunner, RuntimeEventEmitter, SERVERLESS_CONTRACT_VERSION};
use crate::script_decode::{ScriptDecodePipeline, ScriptDecodeReport};
use crate::self_protection::{DerivedKeyTier, KeyDerivationService};
use crate::specialized_detection::{
    DeceptionKind, DeceptionObject, DetectionFinding, SpecializedDetectionEngine,
};
use crate::temporal::{TemporalSnapshot, TemporalStateBuffer};
use crate::transport_drivers::TransportAgentContext;
use crate::wal::{
    ActionLogRecord, EmergencyAuditRing, ForensicJournal, ForensicPersistenceCoordinator,
    JournalActionKind, PendingBatchRecord, PendingBatchStore, ReplayLane, TelemetryWal,
    WalPressureLevel,
};
use crate::yara::{EnqueueDisposition, YaraMatch, YaraResult, YaraScanTarget, YaraScheduler};
use aegis_model::{
    Alert, ClientAck, ClientAckStatus, CloudApiConnectorContract, CloudLogSourceKind,
    CommandEnvelope, CommunicationChannelKind, DownlinkMessage, EventPayload, IsolationRulesV2,
    LineageCheckpoint, LineageCounters, NormalizedEvent, ResponseAction, RuntimeBridgeStatus,
    RuntimeHealthSignals, RuntimeHeartbeat, RuntimeMetadata, RuntimePolicyContract,
    RuntimeProviderKind, Severity, Storyline, StorylineContext, TelemetryEvent, ThreatIntelHit,
    UplinkMessage,
};
use aegis_platform::{MacosPlatform, PlatformRuntime};
use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{interval, timeout, Duration, MissedTickBehavior};
use tracing::{debug, info};
use uuid::Uuid;

const EVENT_QUEUE_CAPACITY: usize = 65_536;
const DETECTION_QUEUE_CAPACITY: usize = 8_192;
const DECISION_QUEUE_CAPACITY: usize = 8_192;
const ALERT_HI_QUEUE_CAPACITY: usize = 1_024;
const ALERT_NORMAL_QUEUE_CAPACITY: usize = 4_096;
const RESPONSE_QUEUE_CAPACITY: usize = 1_024;
const TELEMETRY_QUEUE_CAPACITY: usize = 2_048;
const COMMAND_POLL_INTERVAL_MS: u64 = 50;
const NORMAL_BATCH_MAX_EVENTS_DEFAULT: usize = 100;
const NORMAL_BATCH_MAX_EVENTS_LIMIT: usize = 500;
const NORMAL_BATCH_FLUSH_INTERVAL_MS: u64 = 1_000;
const UPLINK_REPLAY_POLL_INTERVAL_MS: u64 = 100;
const UPLINK_RETRY_INTERVAL_MS: i64 = 1_000;
const TELEMETRY_WAL_SEGMENT_BYTES: u64 = 256 * 1024;
const FORENSIC_EVIDENCE_CAPACITY_BYTES: u64 = 4 * 1024 * 1024;
const FORENSIC_ACTION_CAPACITY_BYTES: u64 = 4 * 1024 * 1024;
const NETWORK_ISOLATION_TTL_SECS: u64 = 5 * 60;
const LOOPBACK_SERVER_SIGNING_KEY_ID: &str = "server-k1";
const LOOPBACK_ADMIN_SIGNING_KEY_ID: &str = "approver-admin-k1";
const LOOPBACK_ANALYST_SIGNING_KEY_ID: &str = "approver-analyst-k1";
const LOOPBACK_SERVER_SIGNING_KEY_SEED: [u8; 32] = [11; 32];
const LOOPBACK_ADMIN_SIGNING_KEY_SEED: [u8; 32] = [12; 32];
const LOOPBACK_ANALYST_SIGNING_KEY_SEED: [u8; 32] = [13; 32];

#[derive(Clone)]
pub struct RuntimeChannels {
    pub event_tx: mpsc::Sender<NormalizedEvent>,
    pub alert_tx_hi: mpsc::Sender<Alert>,
    pub alert_tx_norm: mpsc::Sender<Alert>,
    pub response_tx: mpsc::Sender<ResponseAction>,
    pub telemetry_tx: mpsc::Sender<TelemetryEvent>,
}

pub struct RuntimeReceivers {
    pub event_rx: mpsc::Receiver<NormalizedEvent>,
    pub alert_rx_hi: mpsc::Receiver<Alert>,
    pub alert_rx_norm: mpsc::Receiver<Alert>,
    pub response_rx: mpsc::Receiver<ResponseAction>,
    pub telemetry_rx: mpsc::Receiver<TelemetryEvent>,
}

pub struct BootstrapArtifacts {
    pub channels: RuntimeChannels,
    pub receivers: RuntimeReceivers,
    pub summary: BootstrapSummary,
}

#[derive(Debug)]
pub struct BootstrapSummary {
    pub agent_id: String,
    pub tenant_id: String,
    pub control_plane_url: String,
    pub communication_channel: CommunicationChannelKind,
    pub lineage_counters: LineageCounters,
    pub runtime_bridge: RuntimeBridgeStatus,
    pub queue_capacities: BTreeMap<String, usize>,
    pub task_topology: Vec<String>,
}

struct RuntimeTask {
    name: &'static str,
    handle: JoinHandle<()>,
}

pub struct RuntimeHandle {
    shutdown_tx: watch::Sender<bool>,
    tasks: Vec<RuntimeTask>,
    #[cfg_attr(not(test), allow(dead_code))]
    comms_runtime: Arc<Mutex<CommunicationRuntime>>,
}

impl RuntimeHandle {
    pub async fn graceful_shutdown(mut self, grace_period: Duration) -> Result<Vec<String>> {
        let _ = self.shutdown_tx.send(true);

        let mut stopped_tasks = Vec::with_capacity(self.tasks.len());
        for task in self.tasks.drain(..) {
            timeout(grace_period, task.handle)
                .await
                .map_err(|_| anyhow!("task '{}' did not stop before timeout", task.name))??;
            stopped_tasks.push(task.name.to_string());
        }

        Ok(stopped_tasks)
    }

    #[cfg(test)]
    fn loopback_handle(
        &self,
        channel: CommunicationChannelKind,
    ) -> Option<crate::comms::LoopbackTransportHandle> {
        self.comms_runtime
            .lock()
            .expect("communication runtime poisoned")
            .loopback_handle(channel)
    }
}

pub struct Orchestrator {
    config: AppConfig,
}

impl Orchestrator {
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    pub fn bootstrap(&self) -> Result<BootstrapArtifacts> {
        let (event_tx, event_rx) = mpsc::channel::<NormalizedEvent>(EVENT_QUEUE_CAPACITY);
        let (alert_tx_hi, alert_rx_hi) = mpsc::channel::<Alert>(ALERT_HI_QUEUE_CAPACITY);
        let (alert_tx_norm, alert_rx_norm) = mpsc::channel::<Alert>(ALERT_NORMAL_QUEUE_CAPACITY);
        let (response_tx, response_rx) = mpsc::channel::<ResponseAction>(RESPONSE_QUEUE_CAPACITY);
        let (telemetry_tx, telemetry_rx) =
            mpsc::channel::<TelemetryEvent>(TELEMETRY_QUEUE_CAPACITY);

        let channels = RuntimeChannels {
            event_tx,
            alert_tx_hi,
            alert_tx_norm,
            response_tx,
            telemetry_tx,
        };
        let receivers = RuntimeReceivers {
            event_rx,
            alert_rx_hi,
            alert_rx_norm,
            response_rx,
            telemetry_rx,
        };

        let runtime_bridge_socket = runtime_bridge_socket_path(&self.config);
        let summary = BootstrapSummary {
            agent_id: self.config.agent_id.clone(),
            tenant_id: self.config.tenant_id.clone(),
            control_plane_url: self.config.control_plane_url.clone(),
            communication_channel: configured_primary_channel(&self.config),
            lineage_counters: LineageCounters::default(),
            runtime_bridge: RuntimeBridgeStatus {
                control_socket_path: Some(runtime_bridge_socket.display().to_string()),
                buffered_events: 0,
                emitted_batches: 0,
                last_runtime_heartbeat_ms: None,
                last_connector_cursor: None,
            },
            queue_capacities: BTreeMap::from([
                ("event".to_string(), EVENT_QUEUE_CAPACITY),
                ("detection".to_string(), DETECTION_QUEUE_CAPACITY),
                ("decision".to_string(), DECISION_QUEUE_CAPACITY),
                ("alert_hi".to_string(), ALERT_HI_QUEUE_CAPACITY),
                ("alert_norm".to_string(), ALERT_NORMAL_QUEUE_CAPACITY),
                ("response".to_string(), RESPONSE_QUEUE_CAPACITY),
                ("telemetry".to_string(), TELEMETRY_QUEUE_CAPACITY),
            ]),
            task_topology: vec![
                "sensor-dispatch".to_string(),
                "detection-pool".to_string(),
                "decision-router".to_string(),
                "comms-rx".to_string(),
                "comms-tx-high".to_string(),
                "comms-tx-normal".to_string(),
                "uplink-replay".to_string(),
                "comms-link-manager".to_string(),
                "response-executor".to_string(),
                "telemetry-drain".to_string(),
                "runtime-bridge".to_string(),
                "health-reporter".to_string(),
                "config-watcher".to_string(),
            ],
        };

        Ok(BootstrapArtifacts {
            channels,
            receivers,
            summary,
        })
    }

    pub fn start(&self, artifacts: BootstrapArtifacts) -> Result<RuntimeHandle> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let communication_runtime = CommunicationRuntime::from_config(
            &self.config.communication,
            &TransportAgentContext {
                tenant_id: self.config.tenant_id.clone(),
                agent_id: self.config.agent_id.clone(),
            },
        )?;
        let comms_runtime = Arc::new(Mutex::new(communication_runtime));
        let detection_runtime = Arc::new(Mutex::new(DetectionRuntime::new()));
        let metrics = Arc::new(Mutex::new(RuntimeMetrics::default()));
        let uplink_control = Arc::new(Mutex::new(UplinkControlState::default()));
        let replay_runtime = Arc::new(Mutex::new(UplinkReplayRuntime::new(&self.config)?));
        let platform = build_runtime_platform();
        let command_runtime = Arc::new(Mutex::new(CommandExecutionRuntime::new(
            &self.config,
            Arc::clone(&platform),
        )?));
        let runtime_bridge_socket = runtime_bridge_socket_path(&self.config);
        let response_audit_path = response_audit_path(&self.config);
        let (detection_tx, detection_rx) =
            mpsc::channel::<NormalizedEvent>(DETECTION_QUEUE_CAPACITY);
        let (decision_tx, decision_rx) = mpsc::channel::<DetectionOutcome>(DECISION_QUEUE_CAPACITY);

        let BootstrapArtifacts {
            channels,
            receivers,
            ..
        } = artifacts;
        let telemetry_alert_tx = channels.telemetry_tx.clone();
        let RuntimeChannels {
            alert_tx_hi,
            alert_tx_norm,
            response_tx,
            telemetry_tx,
            ..
        } = channels;
        let RuntimeReceivers {
            event_rx,
            alert_rx_hi,
            alert_rx_norm,
            response_rx,
            telemetry_rx,
        } = receivers;

        let mut tasks = Vec::new();
        tasks.push(RuntimeTask {
            name: "sensor-dispatch",
            handle: tokio::spawn(sensor_dispatch_task(
                event_rx,
                detection_tx,
                shutdown_rx.clone(),
            )),
        });
        tasks.push(RuntimeTask {
            name: "detection-pool",
            handle: tokio::spawn(detection_pool_task(
                detection_rx,
                decision_tx,
                detection_runtime,
                metrics.clone(),
                shutdown_rx.clone(),
            )),
        });
        tasks.push(RuntimeTask {
            name: "decision-router",
            handle: tokio::spawn(decision_router_task(
                self.config.tenant_id.clone(),
                self.config.agent_id.clone(),
                decision_rx,
                alert_tx_hi,
                alert_tx_norm,
                response_tx,
                telemetry_tx,
                metrics.clone(),
                shutdown_rx.clone(),
            )),
        });
        tasks.push(RuntimeTask {
            name: "comms-rx",
            handle: tokio::spawn(comms_rx_task(
                Arc::clone(&comms_runtime),
                Arc::clone(&uplink_control),
                Arc::clone(&replay_runtime),
                command_runtime,
                metrics.clone(),
                shutdown_rx.clone(),
            )),
        });
        tasks.push(RuntimeTask {
            name: "comms-tx-high",
            handle: tokio::spawn(alert_uplink_high_task(
                self.config.tenant_id.clone(),
                self.config.agent_id.clone(),
                alert_rx_hi,
                Arc::clone(&replay_runtime),
                shutdown_rx.clone(),
            )),
        });
        tasks.push(RuntimeTask {
            name: "comms-tx-normal",
            handle: tokio::spawn(alert_normalizer_task(
                self.config.tenant_id.clone(),
                self.config.agent_id.clone(),
                alert_rx_norm,
                telemetry_alert_tx,
                shutdown_rx.clone(),
            )),
        });
        tasks.push(RuntimeTask {
            name: "response-executor",
            handle: tokio::spawn(response_executor_task(
                response_audit_path,
                Arc::clone(&platform),
                Arc::clone(&replay_runtime),
                response_rx,
                shutdown_rx.clone(),
            )),
        });
        tasks.push(RuntimeTask {
            name: "uplink-replay",
            handle: tokio::spawn(uplink_replay_task(
                self.config.tenant_id.clone(),
                self.config.agent_id.clone(),
                Arc::clone(&comms_runtime),
                Arc::clone(&uplink_control),
                Arc::clone(&replay_runtime),
                shutdown_rx.clone(),
            )),
        });
        tasks.push(RuntimeTask {
            name: "comms-link-manager",
            handle: tokio::spawn(comms_link_manager_task(
                self.config.heartbeat_interval(),
                Arc::clone(&comms_runtime),
                shutdown_rx.clone(),
            )),
        });
        tasks.push(RuntimeTask {
            name: "telemetry-drain",
            handle: tokio::spawn(telemetry_drain_task(
                telemetry_rx,
                Arc::clone(&uplink_control),
                Arc::clone(&replay_runtime),
                shutdown_rx.clone(),
            )),
        });
        tasks.push(RuntimeTask {
            name: "runtime-bridge",
            handle: tokio::spawn(runtime_bridge_task(
                self.config.tenant_id.clone(),
                self.config.agent_id.clone(),
                runtime_bridge_socket,
                shutdown_rx.clone(),
            )),
        });
        tasks.push(RuntimeTask {
            name: "health-reporter",
            handle: tokio::spawn(health_reporter_task(
                self.config.tenant_id.clone(),
                self.config.agent_id.clone(),
                self.config.heartbeat_interval(),
                Arc::clone(&comms_runtime),
                metrics,
                shutdown_rx.clone(),
            )),
        });
        tasks.push(RuntimeTask {
            name: "config-watcher",
            handle: tokio::spawn(config_watcher_task(shutdown_rx)),
        });

        Ok(RuntimeHandle {
            shutdown_tx,
            tasks,
            comms_runtime,
        })
    }
}

#[derive(Clone, Debug)]
struct DetectionOutcome {
    event: NormalizedEvent,
    alerts: Vec<Alert>,
    responses: Vec<ResponseAction>,
}

#[derive(Clone, Debug)]
struct DetectionSignal {
    summary: String,
    severity: Severity,
    decision: aegis_model::DecisionKind,
}

#[derive(Default)]
struct RuntimeMetrics {
    lineage_counters: LineageCounters,
    adaptive_whitelist_size: usize,
}

#[derive(Debug)]
struct UplinkControlState {
    normal_max_batch_events: usize,
    pause_low_priority: bool,
    suggested_rate_eps: Option<u32>,
    cooldown_until_ms: Option<i64>,
    last_normal_batch_sent_ms: Option<i64>,
}

impl Default for UplinkControlState {
    fn default() -> Self {
        Self {
            normal_max_batch_events: NORMAL_BATCH_MAX_EVENTS_DEFAULT,
            pause_low_priority: false,
            suggested_rate_eps: None,
            cooldown_until_ms: None,
            last_normal_batch_sent_ms: None,
        }
    }
}

impl UplinkControlState {
    fn normal_batch_limit(&self) -> usize {
        self.normal_max_batch_events
            .clamp(1, NORMAL_BATCH_MAX_EVENTS_LIMIT)
    }

    fn normal_lane_ready(&self, now_ms: i64) -> bool {
        if self.pause_low_priority {
            return false;
        }
        if self
            .cooldown_until_ms
            .map(|until| now_ms < until)
            .unwrap_or(false)
        {
            return false;
        }
        if let Some(rate_eps) = self.suggested_rate_eps.filter(|rate| *rate > 0) {
            let spacing_ms = ((1_000_u64 + u64::from(rate_eps) - 1) / u64::from(rate_eps)) as i64;
            if self
                .last_normal_batch_sent_ms
                .map(|last_send_ms| now_ms - last_send_ms < spacing_ms)
                .unwrap_or(false)
            {
                return false;
            }
        }
        true
    }

    fn note_normal_batch_sent(&mut self, now_ms: i64) {
        self.last_normal_batch_sent_ms = Some(now_ms);
    }

    fn apply_flow_control_hint(&mut self, hint: &aegis_model::FlowControlHint, now_ms: i64) {
        if hint.max_batch_events > 0 {
            self.normal_max_batch_events = hint.max_batch_events.min(NORMAL_BATCH_MAX_EVENTS_LIMIT);
        } else {
            self.normal_max_batch_events = NORMAL_BATCH_MAX_EVENTS_DEFAULT;
        }
        self.pause_low_priority = hint.pause_low_priority;
        self.suggested_rate_eps = hint.suggested_rate_eps.filter(|rate| *rate > 0);
        self.cooldown_until_ms = hint
            .cooldown_ms
            .map(|cooldown_ms| now_ms.saturating_add(i64::from(cooldown_ms)));
    }
}

struct UplinkReplayRuntime {
    telemetry_wal: TelemetryWal,
    pending_batches: PendingBatchStore,
    forensic: ForensicPersistenceCoordinator,
}

impl UplinkReplayRuntime {
    fn new(config: &AppConfig) -> Result<Self> {
        let key_service = KeyDerivationService::from_config(config)?;
        let telemetry_key = key_service.derive_material(
            &config.tenant_id,
            &config.agent_id,
            DerivedKeyTier::TelemetryWal,
            1,
        );
        let journal_key = key_service.derive_material(
            &config.tenant_id,
            &config.agent_id,
            DerivedKeyTier::ForensicJournal,
            1,
        );
        Ok(Self {
            telemetry_wal: TelemetryWal::new(
                &config.storage.spill_path,
                TELEMETRY_WAL_SEGMENT_BYTES,
                telemetry_key,
            )?,
            pending_batches: PendingBatchStore::load(replay_store_path(config))?,
            forensic: ForensicPersistenceCoordinator::new(
                ForensicJournal::new(
                    forensic_uplink_root(config),
                    FORENSIC_EVIDENCE_CAPACITY_BYTES,
                    FORENSIC_ACTION_CAPACITY_BYTES,
                    journal_key,
                )?,
                EmergencyAuditRing::new(256),
            ),
        })
    }

    fn queue_batch(
        &mut self,
        lane: ReplayLane,
        events: Vec<TelemetryEvent>,
        created_at_ms: i64,
    ) -> Result<Uuid> {
        for event in &events {
            self.telemetry_wal.append(event, WalPressureLevel::Normal)?;
        }
        let record = self
            .pending_batches
            .queue_batch(lane, events, created_at_ms)?;
        self.record_transition(
            record.batch_id,
            format!(
                "queued {:?} telemetry batch with {} event(s)",
                lane,
                record.events.len()
            ),
        )?;
        Ok(record.batch_id)
    }

    fn next_ready_batch(&self, now_ms: i64, normal_lane_ready: bool) -> Option<PendingBatchRecord> {
        self.pending_batches
            .next_ready_batch(now_ms, normal_lane_ready)
    }

    fn mark_sent(&mut self, batch_id: Uuid, sent_at_ms: i64) -> Result<PendingBatchRecord> {
        let record =
            self.pending_batches
                .mark_sent(batch_id, sent_at_ms, UPLINK_RETRY_INTERVAL_MS)?;
        self.record_transition(
            batch_id,
            format!(
                "sent telemetry batch seq={} attempt={} events={}",
                record.in_flight_sequence_id.unwrap_or_default(),
                record.attempt_count,
                record.events.len()
            ),
        )?;
        Ok(record)
    }

    fn acknowledge(&mut self, sequence_id: u64) -> Result<Option<PendingBatchRecord>> {
        let record = self.pending_batches.acknowledge(sequence_id)?;
        if let Some(record) = &record {
            self.record_transition(
                record.batch_id,
                format!("acknowledged telemetry batch seq={sequence_id}"),
            )?;
        }
        Ok(record)
    }

    fn defer_retry(&mut self, sequence_id: u64, next_retry_ms: i64, error: String) -> Result<()> {
        self.pending_batches
            .defer_retry(sequence_id, next_retry_ms, error.clone())?;
        self.record_transition(
            Uuid::now_v7(),
            format!("scheduled telemetry replay retry for seq={sequence_id}: {error}"),
        )?;
        Ok(())
    }

    fn record_response_audit(&mut self, records: &[ResponseAuditRecord]) -> Result<()> {
        for record in records {
            self.persist_forensic_action(
                record.action_id,
                format!(
                    "response_audit action={:?} target={} success={} detail={}",
                    record.action, record.target, record.success, record.detail
                ),
                forensic_action_kind(record.action),
            )?;
        }
        Ok(())
    }

    fn record_transition(&mut self, action_id: Uuid, detail: String) -> Result<()> {
        self.persist_forensic_action(action_id, detail, JournalActionKind::TelemetryReplay)
    }

    fn persist_forensic_action(
        &mut self,
        action_id: Uuid,
        detail: String,
        kind: JournalActionKind,
    ) -> Result<()> {
        let _ = self.forensic.persist_action(ActionLogRecord {
            action_id,
            command_id: None,
            kind,
            detail,
        })?;
        Ok(())
    }
}

struct CommandExecutionRuntime {
    identity: AgentIdentity,
    validator: CommandValidator,
    replay_ledger: CommandReplayLedger,
    approval_queue: ApprovalQueue,
    remote_shell: RemoteShellRuntime,
    playbook: PlaybookRuntime,
    session_lock: SessionLockRuntime,
    platform: Arc<dyn PlatformRuntime>,
    response_audit: ResponseAuditLog,
}

#[derive(Deserialize, Serialize)]
struct KillProcessCommand {
    pid: u32,
}

#[derive(Deserialize, Serialize)]
struct QuarantineFileCommand {
    path: PathBuf,
}

#[derive(Deserialize, Serialize)]
struct NetworkIsolateCommand {
    ttl_secs: Option<u64>,
}

#[derive(Deserialize, Serialize)]
struct RemoteShellCommand {
    endpoint_id: String,
    operator: String,
    command: String,
}

#[derive(Deserialize, Serialize)]
struct PlaybookCommand {
    playbook_id: String,
    command: String,
    allowed_commands: Vec<String>,
    timeout_secs: u64,
    max_executions: usize,
}

#[derive(Deserialize, Serialize)]
struct SessionLockCommand {
    user_session: String,
    reason: String,
}

impl CommandExecutionRuntime {
    fn new(config: &AppConfig, platform: Arc<dyn PlatformRuntime>) -> Result<Self> {
        fs::create_dir_all(&config.storage.state_root)?;

        let mut validator = CommandValidator::new(300_000);
        register_loopback_command_trust_roots(&mut validator)?;

        Ok(Self {
            identity: AgentIdentity {
                tenant_id: config.tenant_id.clone(),
                agent_id: config.agent_id.clone(),
                allow_global_scope: false,
                min_policy_version: format!("v{}", config.policy_version.policy_bundle.max(1)),
            },
            validator,
            replay_ledger: CommandReplayLedger::new_persistent_with_security(
                command_replay_path(config),
                &config.security,
            )?,
            approval_queue: ApprovalQueue::new_persistent(approval_queue_path(config))?,
            remote_shell: RemoteShellRuntime::new(
                loopback_remote_shell_policy(),
                remote_shell_audit_root(config),
            ),
            playbook: PlaybookRuntime::default(),
            session_lock: SessionLockRuntime::default(),
            platform,
            response_audit: ResponseAuditLog::new(response_audit_path(config)),
        })
    }

    fn handle_signed_command(
        &mut self,
        signed_command: aegis_model::SignedServerCommand,
        now_ms: i64,
    ) -> Option<ClientAck> {
        let command_id = command_id_from_signed_command(&signed_command);
        match self.validator.validate(
            &signed_command,
            &self.identity,
            &mut self.replay_ledger,
            now_ms,
        ) {
            Ok(validated) => {
                let detail = self.execute_validated_command(&validated, now_ms);
                Some(match detail {
                    Ok(detail) => accepted_ack(validated.command.command_id, detail),
                    Err(error) => rejected_ack(validated.command.command_id, error.to_string()),
                })
            }
            Err(error) => command_id.map(|command_id| rejected_ack(command_id, error.to_string())),
        }
    }

    fn execute_validated_command(
        &mut self,
        validated: &crate::comms::ValidatedCommand,
        now_ms: i64,
    ) -> Result<String> {
        match validated.command.command_type.as_str() {
            "kill-process" => {
                let command =
                    serde_json::from_slice::<KillProcessCommand>(&validated.command.command_data)?;
                let report = apply_response_action(
                    self.platform.as_ref(),
                    self.response_audit.clone(),
                    ResponseAction::KillProcess { pid: command.pid },
                )?;
                Ok(last_response_detail(&report))
            }
            "quarantine-file" => {
                let command = serde_json::from_slice::<QuarantineFileCommand>(
                    &validated.command.command_data,
                )?;
                let report = apply_response_action(
                    self.platform.as_ref(),
                    self.response_audit.clone(),
                    ResponseAction::QuarantineFile { path: command.path },
                )?;
                Ok(last_response_detail(&report))
            }
            "network-isolate" => {
                let command = serde_json::from_slice::<NetworkIsolateCommand>(
                    &validated.command.command_data,
                )?;
                let report = apply_response_action(
                    self.platform.as_ref(),
                    self.response_audit.clone(),
                    ResponseAction::NetworkIsolate {
                        ttl: Duration::from_secs(
                            command.ttl_secs.unwrap_or(NETWORK_ISOLATION_TTL_SECS),
                        ),
                    },
                )?;
                Ok(last_response_detail(&report))
            }
            "remote-shell" => {
                let command =
                    serde_json::from_slice::<RemoteShellCommand>(&validated.command.command_data)?;
                let request =
                    self.materialize_approval_request(validated, &command.command, now_ms)?;
                let audit =
                    self.remote_shell
                        .execute(&request, &command.endpoint_id, &command.operator)?;
                if audit.allowed {
                    Ok(audit.detail)
                } else {
                    Err(anyhow!(audit.detail))
                }
            }
            "playbook" => {
                let command =
                    serde_json::from_slice::<PlaybookCommand>(&validated.command.command_data)?;
                let request =
                    self.materialize_approval_request(validated, &command.command, now_ms)?;
                let audit = self.playbook.execute(
                    &request,
                    &PreApprovedPlaybook {
                        playbook_id: command.playbook_id,
                        allowed_commands: command.allowed_commands,
                        timeout_secs: command.timeout_secs,
                        max_executions: command.max_executions.max(1),
                    },
                    ms_to_ns(now_ms),
                )?;
                if audit.allowed {
                    Ok(audit.detail)
                } else {
                    Err(anyhow!(audit.detail))
                }
            }
            "session-lock" => {
                let command =
                    serde_json::from_slice::<SessionLockCommand>(&validated.command.command_data)?;
                let request = self.materialize_approval_request(
                    validated,
                    &format!("lock {}", command.user_session),
                    now_ms,
                )?;
                if request.state != crate::high_risk_ops::ApprovalState::Approved {
                    return Err(anyhow!("approval request is not approved"));
                }
                let audit = self.session_lock.lock(SessionLockRequest {
                    user_session: command.user_session,
                    reason: command.reason,
                });
                Ok(audit.detail)
            }
            other => Err(anyhow!("unsupported command type: {other}")),
        }
    }

    fn materialize_approval_request(
        &mut self,
        validated: &crate::comms::ValidatedCommand,
        command: &str,
        now_ms: i64,
    ) -> Result<crate::high_risk_ops::ApprovalRequest> {
        let request_id = self.approval_queue.enqueue_with_ttl(
            command_envelope(&validated.command)?,
            "control-plane".to_string(),
            command.to_string(),
            Duration::from_millis(validated.command.ttl_ms as u64),
            ms_to_ns(now_ms),
        )?;
        for approver in &validated.command.approval.approvers {
            self.approval_queue.approve(
                request_id,
                approver.approver_id.clone(),
                ms_to_ns(now_ms),
            )?;
        }
        self.approval_queue
            .get(request_id)?
            .ok_or_else(|| anyhow!("approval request disappeared after materialization"))
    }
}

struct DetectionRuntime {
    ioc: TieredIndicatorIndex,
    rules: Vec<CompiledRule>,
    rule_vm: RuleVm,
    temporal: TemporalStateBuffer,
    decoder: ScriptDecodePipeline,
    yara: YaraScheduler,
    feature_extractor: FeatureExtractor,
    models: ModelRegistry,
    ood: OodScorer,
    correlation: CorrelationCache,
    storyline_engine: StorylineEngine,
    feedback: ThreatFeedbackApplier,
    specialized: SpecializedDetectionEngine,
    events: HashMap<Uuid, NormalizedEvent>,
}

impl DetectionRuntime {
    fn new() -> Self {
        let mut ioc = TieredIndicatorIndex::default();
        ioc.insert(
            IndicatorRisk::High,
            Indicator::new(IndicatorKind::Domain, "bad.example"),
        );
        ioc.insert(
            IndicatorRisk::Critical,
            Indicator::new(IndicatorKind::Sha256, "deadbeef"),
        );
        ioc.insert(
            IndicatorRisk::Critical,
            Indicator::new(IndicatorKind::Path, "/tmp/.aegis-canary"),
        );

        let mut specialized = SpecializedDetectionEngine::default();
        specialized.deception.register(DeceptionObject {
            kind: DeceptionKind::CanaryFile,
            locator: "/tmp/.aegis-canary".to_string(),
            description: "local canary file".to_string(),
        });

        let mut models = ModelRegistry::default();
        models.register(
            ModelKind::Static,
            RegisteredModel {
                model_id: "static-heuristic".to_string(),
                threshold: 0.9,
                session: Arc::new(HeuristicModelSession {
                    label: "static-heuristic".to_string(),
                    scale: 1.0,
                }),
            },
        );
        models.register(
            ModelKind::Behavioral,
            RegisteredModel {
                model_id: "behavioral-heuristic".to_string(),
                threshold: 0.9,
                session: Arc::new(HeuristicModelSession {
                    label: "behavioral-heuristic".to_string(),
                    scale: 1.0,
                }),
            },
        );
        models.register(
            ModelKind::Script,
            RegisteredModel {
                model_id: "script-heuristic".to_string(),
                threshold: 0.9,
                session: Arc::new(HeuristicModelSession {
                    label: "script-heuristic".to_string(),
                    scale: 1.0,
                }),
            },
        );

        Self {
            ioc,
            rules: default_rules(),
            rule_vm: RuleVm,
            temporal: TemporalStateBuffer::new(5 * 60 * 1_000_000_000, 64),
            decoder: ScriptDecodePipeline,
            yara: YaraScheduler::default(),
            feature_extractor: FeatureExtractor,
            models,
            ood: OodScorer::new(0.85),
            correlation: CorrelationCache::new(64),
            storyline_engine: StorylineEngine::new(),
            feedback: ThreatFeedbackApplier::new(128),
            specialized,
            events: HashMap::new(),
        }
    }

    fn analyze(
        &mut self,
        mut event: NormalizedEvent,
        metrics: &mut RuntimeMetrics,
    ) -> DetectionOutcome {
        metrics.lineage_counters.det_received =
            metrics.lineage_counters.det_received.saturating_add(1);
        event.lineage.push(
            LineageCheckpoint::DetectionReceived,
            metrics.lineage_counters.det_received,
            event.timestamp_ns,
        );

        let indicators = indicators_from_event(&event);
        let process_hash = event
            .process
            .exe_hash
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let target_path = target_path(&event);
        let script_report = decode_script(&self.decoder, &event);
        let temporal = self
            .temporal
            .ingest(format!("lineage:{}", event.lineage_id), &event);
        let mut signals = Vec::new();

        self.apply_ioc_matches(&mut event, &indicators, &mut signals);
        self.apply_rule_matches(&event, &process_hash, target_path.as_deref(), &mut signals);
        self.apply_specialized_findings(&event, &mut signals);
        self.apply_yara_matches(&event, script_report.as_ref(), &mut signals);
        self.apply_ml_prediction(&event, &temporal, script_report.as_ref(), &mut signals);

        self.correlation.ingest(&event);
        self.events.insert(event.event_id, event.clone());
        if let Some(storyline) = self.build_storyline(&event) {
            event.storyline = Some(storyline_context(&storyline));
        }

        if let Some(max_severity) = signals.iter().map(|signal| signal.severity).max() {
            event.severity = event.severity.max(max_severity);
        }
        metrics.adaptive_whitelist_size = self.feedback.len();

        let mut alerts = Vec::new();
        let mut responses = Vec::new();
        let mut response_keys = HashSet::new();
        for signal in signals {
            alerts.push(Alert {
                alert_id: Uuid::now_v7(),
                lineage_id: event.lineage_id,
                storyline_id: event
                    .storyline
                    .as_ref()
                    .map(|storyline| storyline.storyline_id),
                severity: signal.severity,
                decision: signal.decision,
                summary: signal.summary,
            });
            if signal.decision == aegis_model::DecisionKind::Response {
                if let Some(action) = response_action_for_event(&event) {
                    let key = response_action_key(&action);
                    if response_keys.insert(key) {
                        responses.push(action);
                    }
                }
            }
        }

        let emitted = (alerts.len() + responses.len()) as u64;
        if emitted > 0 {
            metrics.lineage_counters.dec_emitted =
                metrics.lineage_counters.dec_emitted.saturating_add(emitted);
            event.lineage.push(
                LineageCheckpoint::DecisionEmitted,
                metrics.lineage_counters.dec_emitted,
                event.timestamp_ns,
            );
        }

        DetectionOutcome {
            event,
            alerts,
            responses,
        }
    }

    fn apply_ioc_matches(
        &self,
        event: &mut NormalizedEvent,
        indicators: &[Indicator],
        signals: &mut Vec<DetectionSignal>,
    ) {
        for hit in self.ioc.match_candidates(indicators) {
            event.enrichment.threat_intel.push(ThreatIntelHit {
                indicator: hit.indicator.value.clone(),
                source: "local-tiered-ioc".to_string(),
                confidence: indicator_confidence(hit.risk),
            });
            event.enrichment.risk_score = event
                .enrichment
                .risk_score
                .max(indicator_risk_score(hit.risk));
            signals.push(DetectionSignal {
                summary: format!("IOC matched {}", hit.indicator.value),
                severity: indicator_severity(hit.risk),
                decision: if hit.risk >= IndicatorRisk::Critical {
                    aegis_model::DecisionKind::Response
                } else {
                    aegis_model::DecisionKind::Alert
                },
            });
        }
    }

    fn apply_rule_matches(
        &self,
        event: &NormalizedEvent,
        process_hash: &str,
        target_path: Option<&str>,
        signals: &mut Vec<DetectionSignal>,
    ) {
        for rule in &self.rules {
            let Ok(outcome) = self.rule_vm.evaluate(rule, event) else {
                continue;
            };
            if !outcome.matched
                || self
                    .feedback
                    .contains(&rule.name, process_hash, target_path, now_unix_secs())
            {
                continue;
            }
            signals.push(DetectionSignal {
                summary: format!("rule matched: {}", rule.name),
                severity: if outcome.decision == aegis_model::DecisionKind::Response {
                    Severity::High
                } else {
                    Severity::Medium
                },
                decision: outcome.decision,
            });
        }
    }

    fn apply_specialized_findings(
        &mut self,
        event: &NormalizedEvent,
        signals: &mut Vec<DetectionSignal>,
    ) {
        for finding in self.specialized.evaluate(event) {
            signals.push(signal_from_finding(&finding));
        }
    }

    fn apply_yara_matches(
        &mut self,
        event: &NormalizedEvent,
        script_report: Option<&ScriptDecodeReport>,
        signals: &mut Vec<DetectionSignal>,
    ) {
        let Some(target) = yara_target(event, script_report) else {
            return;
        };
        let cache_key = crate::yara::cache_key(&target);
        let result = match self
            .yara
            .enqueue(target.clone(), event.timestamp_ns, event.priority)
        {
            EnqueueDisposition::Cached => self.yara.cached(&target).cloned(),
            EnqueueDisposition::DuplicatePending => None,
            EnqueueDisposition::Queued(_) => {
                let job = self.yara.pop_next();
                job.map(|job| {
                    let result = synthesize_yara_result(&job, &target, event.timestamp_ns);
                    self.yara.complete(&job, result.clone());
                    result
                })
            }
        };

        let Some(result) = result else {
            return;
        };

        if !result.matches.is_empty() {
            signals.push(DetectionSignal {
                summary: format!(
                    "yara matched {} rule(s) for {cache_key}",
                    result.matches.len()
                ),
                severity: Severity::High,
                decision: aegis_model::DecisionKind::Alert,
            });
        }
    }

    fn apply_ml_prediction(
        &mut self,
        event: &NormalizedEvent,
        temporal: &TemporalSnapshot,
        script_report: Option<&ScriptDecodeReport>,
        signals: &mut Vec<DetectionSignal>,
    ) {
        let kind = self
            .feature_extractor
            .route(event, Some(temporal), script_report);
        let features = match kind {
            ModelKind::Static => self.feature_extractor.static_features(event),
            ModelKind::Behavioral => self.feature_extractor.behavioral_features(event, temporal),
            ModelKind::Script => script_report
                .map(|report| self.feature_extractor.script_features(event, report))
                .unwrap_or_else(|| self.feature_extractor.static_features(event)),
        };
        let input = ModelInput {
            kind,
            features: features.clone(),
        };
        let prediction = self.models.predict(kind, &input, &self.ood);
        self.ood.observe(kind, &features);
        if prediction.output.score >= 0.75 || prediction.is_ood {
            signals.push(DetectionSignal {
                summary: format!(
                    "ml {} score {:.2}{}",
                    prediction.output.label,
                    prediction.output.score,
                    if prediction.is_ood { " (ood)" } else { "" }
                ),
                severity: severity_from_score(prediction.output.score),
                decision: if prediction.output.score >= 0.9 {
                    aegis_model::DecisionKind::Response
                } else {
                    aegis_model::DecisionKind::Alert
                },
            });
        }
    }

    fn build_storyline(&mut self, event: &NormalizedEvent) -> Option<Storyline> {
        let related_ids = self.correlation.related_event_ids(event);
        let related_events = related_ids
            .into_iter()
            .filter_map(|event_id| self.events.get(&event_id).cloned())
            .collect::<Vec<_>>();
        if related_events.len() < 2 {
            return None;
        }
        self.storyline_engine.merge(&related_events)
    }
}

#[derive(Clone)]
struct HeuristicModelSession {
    label: String,
    scale: f32,
}

impl OnnxRuntimeSession for HeuristicModelSession {
    fn infer(&self, input: &ModelInput) -> Result<ModelOutput> {
        let mean = if input.features.is_empty() {
            0.0
        } else {
            input.features.iter().copied().sum::<f32>() / (input.features.len() as f32)
        };
        Ok(ModelOutput {
            score: (mean / self.scale).clamp(0.0, 1.0),
            label: self.label.clone(),
        })
    }
}

async fn sensor_dispatch_task(
    mut event_rx: mpsc::Receiver<NormalizedEvent>,
    detection_tx: mpsc::Sender<NormalizedEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    debug!("sensor-dispatch received shutdown");
                    break;
                }
            }
            maybe_event = event_rx.recv() => {
                match maybe_event {
                    Some(event) => {
                        if detection_tx.send(event).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
}

async fn detection_pool_task(
    mut detection_rx: mpsc::Receiver<NormalizedEvent>,
    decision_tx: mpsc::Sender<DetectionOutcome>,
    runtime: Arc<Mutex<DetectionRuntime>>,
    metrics: Arc<Mutex<RuntimeMetrics>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    debug!("detection-pool received shutdown");
                    break;
                }
            }
            maybe_event = detection_rx.recv() => {
                match maybe_event {
                    Some(event) => {
                        let outcome = {
                            let mut runtime = runtime.lock().expect("detection runtime poisoned");
                            let mut metrics = metrics.lock().expect("runtime metrics poisoned");
                            runtime.analyze(event, &mut metrics)
                        };
                        if decision_tx.send(outcome).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
}

async fn decision_router_task(
    tenant_id: String,
    agent_id: String,
    mut decision_rx: mpsc::Receiver<DetectionOutcome>,
    alert_tx_hi: mpsc::Sender<Alert>,
    alert_tx_norm: mpsc::Sender<Alert>,
    response_tx: mpsc::Sender<ResponseAction>,
    telemetry_tx: mpsc::Sender<TelemetryEvent>,
    metrics: Arc<Mutex<RuntimeMetrics>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    debug!("decision-router received shutdown");
                    break;
                }
            }
            maybe_outcome = decision_rx.recv() => {
                match maybe_outcome {
                    Some(outcome) => {
                        for alert in &outcome.alerts {
                            let send_result = if alert.severity >= Severity::High {
                                alert_tx_hi.send(alert.clone()).await
                            } else {
                                alert_tx_norm.send(alert.clone()).await
                            };
                            if send_result.is_err() {
                                break;
                            }
                        }
                        for response in &outcome.responses {
                            if response_tx.send(response.clone()).await.is_err() {
                                break;
                            }
                        }
                        if telemetry_tx
                            .send(TelemetryEvent::from_normalized(
                                &outcome.event,
                                tenant_id.clone(),
                                agent_id.clone(),
                            ))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        let mut metrics = metrics.lock().expect("runtime metrics poisoned");
                        let alert_total = metrics
                            .lineage_counters
                            .dec_emitted_by_kind
                            .get(&aegis_model::DecisionKind::Alert)
                            .copied()
                            .unwrap_or_default()
                            .saturating_add(outcome.alerts.len() as u64);
                        let response_total = metrics
                            .lineage_counters
                            .dec_emitted_by_kind
                            .get(&aegis_model::DecisionKind::Response)
                            .copied()
                            .unwrap_or_default()
                            .saturating_add(outcome.responses.len() as u64);
                        metrics.lineage_counters.dec_emitted_by_kind.insert(
                            aegis_model::DecisionKind::Alert,
                            alert_total,
                        );
                        metrics.lineage_counters.dec_emitted_by_kind.insert(
                            aegis_model::DecisionKind::Response,
                            response_total,
                        );
                    }
                    None => break,
                }
            }
        }
    }
}

async fn comms_rx_task(
    comms_runtime: Arc<Mutex<CommunicationRuntime>>,
    uplink_control: Arc<Mutex<UplinkControlState>>,
    replay_runtime: Arc<Mutex<UplinkReplayRuntime>>,
    command_runtime: Arc<Mutex<CommandExecutionRuntime>>,
    metrics: Arc<Mutex<RuntimeMetrics>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut ticker = interval(Duration::from_millis(COMMAND_POLL_INTERVAL_MS));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    debug!("comms-rx received shutdown");
                    break;
                }
            }
            _ = ticker.tick() => {
                let message = {
                    comms_runtime
                        .lock()
                        .expect("communication runtime poisoned")
                        .poll_downlink(now_unix_ms())
                };

                let Ok(Some((_channel, message))) = message else {
                    continue;
                };

                match message {
                    DownlinkMessage::ServerCommand(command) => {
                        let ack = {
                            command_runtime
                                .lock()
                                .expect("command runtime poisoned")
                                .handle_signed_command(command, now_unix_ms())
                        };
                        let Some(ack) = ack else {
                            continue;
                        };
                        let sent = comms_runtime
                            .lock()
                            .expect("communication runtime poisoned")
                            .send_uplink(&UplinkMessage::ClientAck(ack), now_unix_ms());
                        if let Err(error) = sent {
                            debug!(%error, "comms-rx failed to send client ack");
                        }
                    }
                    DownlinkMessage::BatchAck(batch_ack) => {
                        if batch_ack.status == aegis_model::BatchAckStatus::Accepted {
                            if let Err(error) = replay_runtime
                                .lock()
                                .expect("uplink replay runtime poisoned")
                                .acknowledge(batch_ack.sequence_id)
                            {
                                debug!(%error, sequence_id = batch_ack.sequence_id, "failed to acknowledge replay batch");
                            }
                            let mut snapshot = metrics.lock().expect("runtime metrics poisoned");
                            snapshot.lineage_counters.grpc_acked = snapshot
                                .lineage_counters
                                .grpc_acked
                                .saturating_add(u64::from(batch_ack.accepted_events.max(1)));
                        } else {
                            let retry_at_ms = now_unix_ms().saturating_add(
                                i64::from(batch_ack.retry_after_ms.max(UPLINK_RETRY_INTERVAL_MS as u32)),
                            );
                            let reason = batch_ack
                                .reason
                                .clone()
                                .unwrap_or_else(|| format!("status={:?}", batch_ack.status));
                            if let Err(error) = replay_runtime
                                .lock()
                                .expect("uplink replay runtime poisoned")
                                .defer_retry(batch_ack.sequence_id, retry_at_ms, reason)
                            {
                                debug!(%error, sequence_id = batch_ack.sequence_id, "failed to defer replay batch");
                            }
                        }
                        debug!(
                            batch_id = %batch_ack.batch_id,
                            status = ?batch_ack.status,
                            accepted = batch_ack.accepted_events,
                            rejected = batch_ack.rejected_events,
                            reason = batch_ack.reason.as_deref().unwrap_or_default(),
                            "comms-rx received batch ack"
                        );
                    }
                    DownlinkMessage::FlowControlHint(flow_control) => {
                        uplink_control
                            .lock()
                            .expect("uplink control poisoned")
                            .apply_flow_control_hint(&flow_control, now_unix_ms());
                        debug!(
                            pause_low_priority = flow_control.pause_low_priority,
                            max_batch_events = flow_control.max_batch_events,
                            suggested_rate_eps = flow_control.suggested_rate_eps,
                            cooldown_ms = flow_control.cooldown_ms,
                            "comms-rx received flow-control hint"
                        );
                    }
                }
            }
        }
    }
}

async fn alert_uplink_high_task(
    tenant_id: String,
    agent_id: String,
    mut alert_rx: mpsc::Receiver<Alert>,
    replay_runtime: Arc<Mutex<UplinkReplayRuntime>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    debug!("high-priority alert uplink received shutdown");
                    break;
                }
            }
            maybe_alert = alert_rx.recv() => {
                match maybe_alert {
                    Some(alert) => {
                        let alert_event = TelemetryEvent::from_alert(
                            &alert,
                            tenant_id.clone(),
                            agent_id.clone(),
                            now_unix_ns(),
                        );
                        if let Err(error) =
                            queue_event_batch(ReplayLane::HighPriority, vec![alert_event], &replay_runtime)
                        {
                            debug!(
                                %error,
                                alert_id = %alert.alert_id,
                                summary = %alert.summary,
                                "high-priority alert uplink failed"
                            );
                        }
                    }
                    None => break,
                }
            }
        }
    }
}

async fn alert_normalizer_task(
    tenant_id: String,
    agent_id: String,
    mut alert_rx: mpsc::Receiver<Alert>,
    telemetry_tx: mpsc::Sender<TelemetryEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    debug!("normal alert forwarder received shutdown");
                    break;
                }
            }
            maybe_alert = alert_rx.recv() => {
                match maybe_alert {
                    Some(alert) => {
                        let alert_event = TelemetryEvent::from_alert(
                            &alert,
                            tenant_id.clone(),
                            agent_id.clone(),
                            now_unix_ns(),
                        );
                        if telemetry_tx.send(alert_event).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
}

async fn response_executor_task(
    audit_path: PathBuf,
    platform: Arc<dyn PlatformRuntime>,
    replay_runtime: Arc<Mutex<UplinkReplayRuntime>>,
    mut response_rx: mpsc::Receiver<ResponseAction>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    if let Some(parent) = audit_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let audit = ResponseAuditLog::new(audit_path);

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    debug!("response-executor received shutdown");
                    break;
                }
            }
            maybe_response = response_rx.recv() => {
                match maybe_response {
                    Some(response) => {
                        let result = apply_response_action(platform.as_ref(), audit.clone(), response);
                        match result {
                            Ok(report) => {
                                if let Err(error) = replay_runtime
                                    .lock()
                                    .expect("uplink replay runtime poisoned")
                                    .record_response_audit(&report.records)
                                {
                                    debug!(%error, "response-executor failed to persist forensic action log");
                                }
                                debug!(records = report.records.len(), "response-executor applied action");
                            }
                            Err(error) => debug!(%error, "response-executor failed to apply action"),
                        }
                    }
                    None => break,
                }
            }
        }
    }
}

async fn telemetry_drain_task(
    mut telemetry_rx: mpsc::Receiver<TelemetryEvent>,
    uplink_control: Arc<Mutex<UplinkControlState>>,
    replay_runtime: Arc<Mutex<UplinkReplayRuntime>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut buffer = Vec::new();
    let mut flush_ticker = interval(Duration::from_millis(NORMAL_BATCH_FLUSH_INTERVAL_MS));
    flush_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    flush_ticker.tick().await;

    loop {
        let max_batch_events = uplink_control
            .lock()
            .expect("uplink control poisoned")
            .normal_batch_limit();
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    if !buffer.is_empty() {
                        let _ = flush_normal_telemetry_buffer(
                            &mut buffer,
                            &replay_runtime,
                        );
                    }
                    debug!("telemetry-drain received shutdown");
                    break;
                }
            }
            _ = flush_ticker.tick(), if !buffer.is_empty() => {
                let _ = flush_normal_telemetry_buffer(&mut buffer, &replay_runtime);
            }
            maybe_event = telemetry_rx.recv() => {
                match maybe_event {
                    Some(event) => {
                        buffer.push(event);
                        if buffer.len() >= max_batch_events {
                            let _ = flush_normal_telemetry_buffer(&mut buffer, &replay_runtime);
                        }
                    }
                    None => {
                        if !buffer.is_empty() {
                            let _ = flush_normal_telemetry_buffer(&mut buffer, &replay_runtime);
                        }
                        break;
                    }
                }
            }
        }
    }
}

async fn uplink_replay_task(
    tenant_id: String,
    agent_id: String,
    comms_runtime: Arc<Mutex<CommunicationRuntime>>,
    uplink_control: Arc<Mutex<UplinkControlState>>,
    replay_runtime: Arc<Mutex<UplinkReplayRuntime>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut ticker = interval(Duration::from_millis(UPLINK_REPLAY_POLL_INTERVAL_MS));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    debug!("uplink-replay received shutdown");
                    break;
                }
            }
            _ = ticker.tick() => {
                let now_ms = now_unix_ms();
                let normal_lane_ready = uplink_control
                    .lock()
                    .expect("uplink control poisoned")
                    .normal_lane_ready(now_ms);
                let next_batch = replay_runtime
                    .lock()
                    .expect("uplink replay runtime poisoned")
                    .next_ready_batch(now_ms, normal_lane_ready);
                let Some(next_batch) = next_batch else {
                    continue;
                };
                let sent_batch = match replay_runtime
                    .lock()
                    .expect("uplink replay runtime poisoned")
                    .mark_sent(next_batch.batch_id, now_ms)
                {
                    Ok(batch) => batch,
                    Err(error) => {
                        debug!(%error, batch_id = %next_batch.batch_id, "failed to mark replay batch as sent");
                        continue;
                    }
                };
                let Some(sequence_hint) = sent_batch.in_flight_sequence_id else {
                    continue;
                };
                let send_result = send_event_batch(
                    &tenant_id,
                    &agent_id,
                    sent_batch.events.clone(),
                    sent_batch.events.len().max(1),
                    sequence_hint,
                    now_ms,
                    &comms_runtime,
                );
                match send_result {
                    Ok(()) => {
                        if sent_batch.lane == ReplayLane::Normal {
                            uplink_control
                                .lock()
                                .expect("uplink control poisoned")
                                .note_normal_batch_sent(now_ms);
                        }
                    }
                    Err(error) => {
                        if let Err(retry_error) = replay_runtime
                            .lock()
                            .expect("uplink replay runtime poisoned")
                            .defer_retry(
                                sequence_hint,
                                now_ms.saturating_add(UPLINK_RETRY_INTERVAL_MS),
                                error.to_string(),
                            )
                        {
                            debug!(
                                %retry_error,
                                sequence_id = sequence_hint,
                                "failed to persist replay retry state"
                            );
                        }
                    }
                }
            }
        }
    }
}

fn send_event_batch(
    tenant_id: &str,
    agent_id: &str,
    events: Vec<TelemetryEvent>,
    max_batch_events: usize,
    sequence_hint: u64,
    sent_at_ms: i64,
    comms_runtime: &Arc<Mutex<CommunicationRuntime>>,
) -> Result<()> {
    let batch = TelemetryBatchBuilder::new(max_batch_events).build(
        tenant_id.to_string(),
        agent_id.to_string(),
        sequence_hint,
        events,
    )?;
    comms_runtime
        .lock()
        .expect("comms runtime poisoned")
        .send_uplink(&batch, sent_at_ms)?;
    Ok(())
}

fn queue_event_batch(
    lane: ReplayLane,
    events: Vec<TelemetryEvent>,
    replay_runtime: &Arc<Mutex<UplinkReplayRuntime>>,
) -> Result<()> {
    replay_runtime
        .lock()
        .expect("uplink replay runtime poisoned")
        .queue_batch(lane, events, now_unix_ms())?;
    Ok(())
}

fn flush_normal_telemetry_buffer(
    buffer: &mut Vec<TelemetryEvent>,
    replay_runtime: &Arc<Mutex<UplinkReplayRuntime>>,
) -> Result<()> {
    if buffer.is_empty() {
        return Ok(());
    }

    let events = std::mem::take(buffer);
    match queue_event_batch(ReplayLane::Normal, events.clone(), replay_runtime) {
        Ok(()) => Ok(()),
        Err(error) => {
            *buffer = events;
            debug!(%error, "telemetry-drain failed to queue batch");
            Err(error)
        }
    }
}

async fn health_reporter_task(
    tenant_id: String,
    agent_id: String,
    heartbeat_interval: Duration,
    comms_runtime: Arc<Mutex<CommunicationRuntime>>,
    metrics: Arc<Mutex<RuntimeMetrics>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut ticker = interval(heartbeat_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    debug!("health-reporter received shutdown");
                    break;
                }
            }
            _ = ticker.tick() => {
                let communication = comms_runtime
                    .lock()
                    .expect("comms runtime poisoned")
                    .snapshot();
                let snapshot = metrics
                    .lock()
                    .expect("runtime metrics poisoned");
                let health = HealthReporter::build_snapshot(
                    "0.1.0",
                    "policy-1",
                    "ruleset-1",
                    "model-1",
                    0.0,
                    0,
                    BTreeMap::from([("telemetry".to_string(), 0usize)]),
                    snapshot.lineage_counters.clone(),
                    RuntimeHealthSignals {
                        communication_channel: communication.active_channel,
                        adaptive_whitelist_size: snapshot.adaptive_whitelist_size,
                        etw_tamper_detected: false,
                        amsi_tamper_detected: false,
                        bpf_integrity_pass: true,
                    },
                );
                let heartbeat = HeartbeatBuilder::build(
                    tenant_id.clone(),
                    agent_id.clone(),
                    health,
                    communication,
                    0.0,
                    0,
                );
                let send_result = comms_runtime
                    .lock()
                    .expect("comms runtime poisoned")
                    .send_heartbeat(&heartbeat, now_unix_ms());
                match send_result {
                    Ok(channel) => info!(?channel, "health-reporter tick"),
                    Err(error) => debug!(%error, "health-reporter failed to send heartbeat"),
                }
            }
        }
    }
}

async fn comms_link_manager_task(
    heartbeat_interval: Duration,
    comms_runtime: Arc<Mutex<CommunicationRuntime>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut ticker = interval(heartbeat_interval / 2);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    debug!("comms-link-manager received shutdown");
                    break;
                }
            }
            _ = ticker.tick() => {
                let promoted = comms_runtime
                    .lock()
                    .expect("comms runtime poisoned")
                    .probe_upgrade(now_unix_ms());
                if let Some(channel) = promoted {
                    info!(?channel, "comms-link-manager promoted transport");
                }
            }
        }
    }
}

async fn config_watcher_task(mut shutdown_rx: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    debug!("config-watcher received shutdown");
                    break;
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                debug!("config-watcher poll tick");
            }
        }
    }
}

async fn runtime_bridge_task(
    tenant_id: String,
    agent_id: String,
    control_socket_path: PathBuf,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut ticker = interval(Duration::from_secs(30));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let policy = RuntimePolicyContract {
        contract_version: SERVERLESS_CONTRACT_VERSION.to_string(),
        policy_version: "runtime-bridge-policy.v1".to_string(),
        blocked_env_keys: vec!["AWS_SECRET_ACCESS_KEY".to_string()],
        blocked_destinations: vec!["169.254.169.254".to_string()],
        max_request_body_bytes: 8_192,
        require_response_sampling: true,
    };
    let heartbeat = RuntimeHeartbeat {
        contract_version: SERVERLESS_CONTRACT_VERSION.to_string(),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        metadata: RuntimeMetadata {
            provider: RuntimeProviderKind::AwsLambda,
            service: "runtime-bridge".to_string(),
            runtime: "rust".to_string(),
            region: None,
            account_id: None,
            invocation_id: format!("{agent_id}-bootstrap"),
            cold_start: false,
            function_name: Some(agent_id.clone()),
            container_id: None,
        },
        policy_version: policy.policy_version.clone(),
        active_invocations: 0,
        buffered_events: 0,
        dropped_events_total: 0,
    };
    let mut emitter = RuntimeEventEmitter::new(64, 16, 32).expect("runtime bridge emitter");
    let runner = CloudConnectorRunner::new(CloudApiConnectorContract {
        contract_version: SERVERLESS_CONTRACT_VERSION.to_string(),
        connector_id: format!("{agent_id}-runtime-bridge"),
        source: CloudLogSourceKind::AwsCloudWatch,
        poll_interval_secs: 60,
        max_batch_records: 64,
        cursor: None,
    })
    .expect("runtime bridge connector");
    emitter
        .accept_heartbeat(&heartbeat, &policy, now_unix_ms())
        .expect("runtime bridge heartbeat should bind");

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    debug!("runtime-bridge received shutdown");
                    break;
                }
            }
            _ = ticker.tick() => {
                let status = emitter.snapshot(
                    Some(&control_socket_path),
                    runner.emitted_batches(),
                    runner.last_cursor(),
                );
                debug!(
                    control_socket = %status.control_socket_path.as_deref().unwrap_or("-"),
                    buffered_events = status.buffered_events,
                    emitted_batches = status.emitted_batches,
                    last_runtime_heartbeat_ms = status.last_runtime_heartbeat_ms.unwrap_or_default(),
                    "runtime-bridge status"
                );
            }
        }
    }
}

fn default_rules() -> Vec<CompiledRule> {
    vec![
        CompiledRule {
            name: "powershell-high-risk".to_string(),
            program: vec![
                Instruction::LoadField(RuleField::ProcessName),
                Instruction::Push(RuleValue::String("powershell".to_string())),
                Instruction::Compare(CompareOp::Contains),
                Instruction::LoadField(RuleField::RiskScore),
                Instruction::Push(RuleValue::Number(80)),
                Instruction::Compare(CompareOp::Gte),
                Instruction::And,
            ],
            on_match: aegis_model::DecisionKind::Response,
        },
        CompiledRule {
            name: "dns-c2-domain".to_string(),
            program: vec![
                Instruction::LoadField(RuleField::DnsQuery),
                Instruction::Push(RuleValue::String("bad.example".to_string())),
                Instruction::Compare(CompareOp::Contains),
            ],
            on_match: aegis_model::DecisionKind::Alert,
        },
    ]
}

fn decode_script(
    decoder: &ScriptDecodePipeline,
    event: &NormalizedEvent,
) -> Option<ScriptDecodeReport> {
    match &event.payload {
        EventPayload::Script(script) => script
            .content
            .as_deref()
            .or(script.deobfuscated_content.as_deref())
            .or((!event.process.cmdline.is_empty()).then_some(event.process.cmdline.as_str()))
            .map(|content| decoder.decode(content)),
        _ => (!event.process.cmdline.is_empty()).then_some(decoder.decode(&event.process.cmdline)),
    }
}

fn indicators_from_event(event: &NormalizedEvent) -> Vec<Indicator> {
    let mut indicators = Vec::new();
    if let Some(hash) = &event.process.exe_hash {
        indicators.push(Indicator::new(IndicatorKind::Sha256, hash.clone()));
    }
    if let EventPayload::File(file) = &event.payload {
        if let Some(hash) = &file.hash {
            indicators.push(Indicator::new(IndicatorKind::Sha256, hash.clone()));
        }
        let path = file.path.display().to_string();
        if !path.is_empty() {
            indicators.push(Indicator::new(IndicatorKind::Path, path));
        }
    }
    if let EventPayload::Network(network) = &event.payload {
        if let Some(dns_query) = &network.dns_query {
            indicators.push(Indicator::new(IndicatorKind::Domain, dns_query.clone()));
        }
        if let Some(dst_ip) = &network.dst_ip {
            indicators.push(Indicator::new(IndicatorKind::Ip, dst_ip.clone()));
        }
    }
    indicators
}

fn target_path(event: &NormalizedEvent) -> Option<String> {
    match &event.payload {
        EventPayload::File(file) => {
            let path = file.path.display().to_string();
            (!path.is_empty()).then_some(path)
        }
        _ => None,
    }
}

fn signal_from_finding(finding: &DetectionFinding) -> DetectionSignal {
    DetectionSignal {
        summary: finding.summary.clone(),
        severity: finding.severity,
        decision: finding.decision,
    }
}

fn indicator_confidence(risk: IndicatorRisk) -> u8 {
    match risk {
        IndicatorRisk::Low => 45,
        IndicatorRisk::Medium => 65,
        IndicatorRisk::High => 80,
        IndicatorRisk::Critical => 95,
    }
}

fn indicator_risk_score(risk: IndicatorRisk) -> u8 {
    match risk {
        IndicatorRisk::Low => 35,
        IndicatorRisk::Medium => 55,
        IndicatorRisk::High => 80,
        IndicatorRisk::Critical => 95,
    }
}

fn indicator_severity(risk: IndicatorRisk) -> Severity {
    match risk {
        IndicatorRisk::Low => Severity::Low,
        IndicatorRisk::Medium => Severity::Medium,
        IndicatorRisk::High => Severity::High,
        IndicatorRisk::Critical => Severity::Critical,
    }
}

fn severity_from_score(score: f32) -> Severity {
    if score >= 0.95 {
        Severity::Critical
    } else if score >= 0.85 {
        Severity::High
    } else if score >= 0.65 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn yara_target(
    event: &NormalizedEvent,
    script_report: Option<&ScriptDecodeReport>,
) -> Option<YaraScanTarget> {
    match &event.payload {
        EventPayload::Script(script) => script_report
            .map(|report| YaraScanTarget::Content(report.decoded.clone()))
            .or_else(|| script.content.clone().map(YaraScanTarget::Content)),
        EventPayload::File(file) => {
            let path = file.path.display().to_string();
            (!path.is_empty()).then_some(YaraScanTarget::FilePath(path))
        }
        _ => script_report.map(|report| YaraScanTarget::Content(report.decoded.clone())),
    }
}

fn synthesize_yara_result(
    job: &crate::yara::YaraJob,
    target: &YaraScanTarget,
    scanned_at_ns: u64,
) -> YaraResult {
    let content = match target {
        YaraScanTarget::FilePath(path) => path.clone(),
        YaraScanTarget::Content(content) => content.clone(),
    };
    let mut matches = Vec::new();
    if content.contains("Invoke-Mimikatz") || content.contains("lsass") {
        matches.push(YaraMatch {
            rule_name: "CredentialAccess".to_string(),
            tags: vec!["credential-access".to_string()],
        });
    }
    if content.contains("IEX") || content.contains("AmsiUtils") || content.contains("Net.WebClient")
    {
        matches.push(YaraMatch {
            rule_name: "SuspiciousPowerShell".to_string(),
            tags: vec!["script".to_string()],
        });
    }
    YaraResult {
        cache_key: job.cache_key.clone(),
        matches,
        scanned_at_ns,
    }
}

fn response_action_for_event(event: &NormalizedEvent) -> Option<ResponseAction> {
    match &event.payload {
        EventPayload::File(file) => Some(ResponseAction::QuarantineFile {
            path: file.path.clone(),
        }),
        EventPayload::Network(_) | EventPayload::Auth(_) => Some(ResponseAction::NetworkIsolate {
            ttl: Duration::from_secs(NETWORK_ISOLATION_TTL_SECS),
        }),
        _ => (event.process.pid > 0).then_some(ResponseAction::KillProcess {
            pid: event.process.pid,
        }),
    }
}

fn response_action_key(action: &ResponseAction) -> String {
    match action {
        ResponseAction::SuspendProcess { pid } => format!("suspend:{pid}"),
        ResponseAction::KillProcess { pid } => format!("kill:{pid}"),
        ResponseAction::QuarantineFile { path } => format!("quarantine:{}", path.display()),
        ResponseAction::NetworkIsolate { ttl } => format!("network:{}", ttl.as_secs()),
    }
}

fn storyline_context(storyline: &Storyline) -> StorylineContext {
    StorylineContext {
        storyline_id: storyline.id,
        processes: storyline.processes.clone(),
        tactics: storyline.tactics.clone(),
        techniques: storyline.techniques.clone(),
        kill_chain_phase: storyline.kill_chain_phase,
        narrative: storyline.auto_narrative.clone(),
    }
}

fn register_loopback_command_trust_roots(validator: &mut CommandValidator) -> Result<()> {
    let server_signing_key = SigningKey::from_bytes(&LOOPBACK_SERVER_SIGNING_KEY_SEED);
    let admin_signing_key = SigningKey::from_bytes(&LOOPBACK_ADMIN_SIGNING_KEY_SEED);
    let analyst_signing_key = SigningKey::from_bytes(&LOOPBACK_ANALYST_SIGNING_KEY_SEED);
    validator.register_server_key(
        LOOPBACK_SERVER_SIGNING_KEY_ID,
        server_signing_key.verifying_key().to_bytes(),
    )?;
    validator.register_approver(
        "approver-admin",
        "security_admin",
        LOOPBACK_ADMIN_SIGNING_KEY_ID,
        admin_signing_key.verifying_key().to_bytes(),
    )?;
    validator.register_approver(
        "approver-analyst",
        "security_analyst",
        LOOPBACK_ANALYST_SIGNING_KEY_ID,
        analyst_signing_key.verifying_key().to_bytes(),
    )?;
    Ok(())
}

fn command_replay_path(config: &AppConfig) -> PathBuf {
    config.storage.state_root.join("command-replay-ledger.db")
}

fn replay_store_path(config: &AppConfig) -> PathBuf {
    config.storage.state_root.join("telemetry-replay.json")
}

fn approval_queue_path(config: &AppConfig) -> PathBuf {
    config.storage.state_root.join("approval-queue.db")
}

fn forensic_uplink_root(config: &AppConfig) -> PathBuf {
    config.storage.forensic_path.join("uplink-replay")
}

fn remote_shell_audit_root(config: &AppConfig) -> PathBuf {
    config.storage.state_root.join("remote-shell")
}

fn forensic_action_kind(action: ResponseActionKind) -> JournalActionKind {
    match action {
        ResponseActionKind::Suspend
        | ResponseActionKind::Assess
        | ResponseActionKind::Kill
        | ResponseActionKind::KillProtected => JournalActionKind::Kill,
        ResponseActionKind::Quarantine => JournalActionKind::Quarantine,
        ResponseActionKind::NetworkIsolate => JournalActionKind::Isolate,
    }
}

fn loopback_remote_shell_policy() -> RemoteShellPolicy {
    RemoteShellPolicy {
        allowed_prefixes: vec!["echo".to_string(), "collect".to_string()],
        denied_patterns: vec![
            "rm -rf".to_string(),
            "format".to_string(),
            "mkfs".to_string(),
            "dd if=/dev/zero".to_string(),
        ],
        timeout_secs: 30,
        max_session_secs: 30 * 60,
        max_concurrent_sessions: 1,
        whitelist_mode: true,
        allowed_hours: None,
    }
}

fn command_id_from_signed_command(
    signed_command: &aegis_model::SignedServerCommand,
) -> Option<Uuid> {
    serde_json::from_slice::<aegis_model::ServerCommand>(&signed_command.payload)
        .ok()
        .map(|command| command.command_id)
}

fn command_envelope(command: &aegis_model::ServerCommand) -> Result<CommandEnvelope> {
    Ok(CommandEnvelope {
        command_id: command.command_id,
        command_type: command.command_type.clone(),
        target_scope: serde_json::to_string(&command.target_scope)?,
        approval: command.approval.clone(),
    })
}

fn accepted_ack(command_id: Uuid, detail: String) -> ClientAck {
    ClientAck {
        command_id,
        status: ClientAckStatus::Executed,
        detail: Some(detail),
        acked_at: now_unix_ms(),
    }
}

fn rejected_ack(command_id: Uuid, detail: String) -> ClientAck {
    ClientAck {
        command_id,
        status: ClientAckStatus::Rejected,
        detail: Some(detail),
        acked_at: now_unix_ms(),
    }
}

fn ms_to_ns(now_ms: i64) -> u64 {
    now_ms.max(0) as u64 * 1_000_000
}

fn apply_response_action(
    platform: &dyn PlatformRuntime,
    audit: ResponseAuditLog,
    response: ResponseAction,
) -> Result<crate::response_executor::ResponseExecutionReport> {
    let executor = ResponseExecutor::new(platform, audit);
    match response {
        ResponseAction::SuspendProcess { pid } => executor.terminate_process(TerminationRequest {
            pid,
            protected_process: false,
            kill_required: false,
        }),
        ResponseAction::KillProcess { pid } => executor.terminate_process(TerminationRequest {
            pid,
            protected_process: false,
            kill_required: true,
        }),
        ResponseAction::QuarantineFile { path } => executor.quarantine_file(&path),
        ResponseAction::NetworkIsolate { ttl } => executor.network_isolate(&IsolationRulesV2 {
            ttl,
            allowed_control_plane_ips: vec!["127.0.0.1".to_string()],
        }),
    }
}

fn last_response_detail(report: &crate::response_executor::ResponseExecutionReport) -> String {
    report
        .records
        .last()
        .map(|record| record.detail.clone())
        .unwrap_or_else(|| "response action applied".to_string())
}

fn build_runtime_platform() -> Arc<dyn PlatformRuntime> {
    #[cfg(target_os = "windows")]
    {
        Arc::new(aegis_platform::WindowsPlatform::default())
    }
    #[cfg(target_os = "macos")]
    {
        Arc::new(MacosPlatform::default())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Arc::new(aegis_platform::LinuxPlatform::default())
    }
}

fn response_audit_path(config: &AppConfig) -> PathBuf {
    config.storage.state_root.join("response-audit.jsonl")
}

fn configured_primary_channel(config: &AppConfig) -> CommunicationChannelKind {
    if config.communication.grpc.enabled {
        CommunicationChannelKind::Grpc
    } else if config.communication.websocket.enabled {
        CommunicationChannelKind::WebSocket
    } else if config.communication.long_polling.enabled {
        CommunicationChannelKind::LongPolling
    } else if config.communication.domain_fronting.enabled {
        CommunicationChannelKind::DomainFronting
    } else if config.communication.development_allow_loopback {
        CommunicationChannelKind::Grpc
    } else {
        CommunicationChannelKind::Grpc
    }
}

fn runtime_bridge_socket_path(config: &AppConfig) -> PathBuf {
    config
        .storage
        .state_root
        .join(format!("runtime-bridge-{}.sock", config.agent_id))
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as i64
}

fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos() as u64
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comms::canonical_command_hash;
    use aegis_model::{
        Alert, ApprovalPolicy, ApprovalProof, ApproverEntry, BatchAck, BatchAckStatus, ClientAck,
        DecisionKind, DownlinkMessage, EventPayload, EventType, FlowControlHint, Priority,
        ProcessContext, ScriptContext, ServerCommand, SignedServerCommand, TargetScope,
        TargetScopeKind, TelemetryEvent, UplinkMessage,
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn temp_state_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("aegis-{name}-{}", Uuid::now_v7()))
    }

    fn loopback_test_config(name: &str) -> AppConfig {
        let mut config = AppConfig::default().with_state_root(temp_state_root(name));
        config.communication.development_allow_loopback = true;
        config
    }

    fn target_scope() -> TargetScope {
        TargetScope {
            kind: TargetScopeKind::Agent,
            tenant_id: Some("local-tenant".to_string()),
            agent_ids: Vec::new(),
            max_fanout: 1,
        }
    }

    fn sign_server_command(command: &ServerCommand) -> SignedServerCommand {
        let signing_key = SigningKey::from_bytes(&LOOPBACK_SERVER_SIGNING_KEY_SEED);
        let payload = serde_json::to_vec(command).expect("serialize server command");
        let signature = signing_key.sign(&payload).to_bytes().to_vec();
        SignedServerCommand {
            payload,
            signature,
            signing_key_id: LOOPBACK_SERVER_SIGNING_KEY_ID.to_string(),
        }
    }

    fn approver_entry(
        command: &ServerCommand,
        approver_id: &str,
        role: &str,
        signing_key_id: &str,
        signing_key_seed: [u8; 32],
    ) -> ApproverEntry {
        let signing_key = SigningKey::from_bytes(&signing_key_seed);
        let signature = signing_key
            .sign(&canonical_command_hash(command))
            .to_bytes()
            .to_vec();
        ApproverEntry {
            approver_id: approver_id.to_string(),
            role: role.to_string(),
            proof: ApprovalProof {
                signature,
                signing_key_id: signing_key_id.to_string(),
            },
        }
    }

    fn make_command(
        command_type: &str,
        command_data: Vec<u8>,
        approval: ApprovalPolicy,
    ) -> ServerCommand {
        ServerCommand {
            command_id: Uuid::now_v7(),
            tenant_id: "local-tenant".to_string(),
            agent_id: "local-agent".to_string(),
            command_type: command_type.to_string(),
            command_data,
            issued_at_ms: now_unix_ms(),
            ttl_ms: 60_000,
            sequence_hint: 1,
            approval,
            target_scope: target_scope(),
        }
    }

    fn approved_session_lock_policy(command: &ServerCommand) -> ApprovalPolicy {
        ApprovalPolicy {
            min_approvers: 1,
            approvers: vec![approver_entry(
                command,
                "approver-admin",
                "security_admin",
                LOOPBACK_ADMIN_SIGNING_KEY_ID,
                LOOPBACK_ADMIN_SIGNING_KEY_SEED,
            )],
            policy_version: "v1".to_string(),
        }
    }

    fn client_acks(handle: &crate::comms::LoopbackTransportHandle) -> Vec<ClientAck> {
        handle
            .take_uplinks()
            .into_iter()
            .filter_map(|message| match message {
                UplinkMessage::ClientAck(ack) => Some(ack),
                _ => None,
            })
            .collect()
    }

    fn event_batches(
        handle: &crate::comms::LoopbackTransportHandle,
    ) -> Vec<aegis_model::EventBatch> {
        handle
            .take_uplinks()
            .into_iter()
            .filter_map(|message| match message {
                UplinkMessage::EventBatch(batch) => Some(batch),
                _ => None,
            })
            .collect()
    }

    fn sample_alert(severity: Severity, summary: &str) -> Alert {
        Alert {
            alert_id: Uuid::now_v7(),
            lineage_id: Uuid::now_v7(),
            storyline_id: None,
            severity,
            decision: DecisionKind::Alert,
            summary: summary.to_string(),
        }
    }

    fn benign_telemetry_event(timestamp_ns: u64) -> TelemetryEvent {
        TelemetryEvent::from_normalized(
            &NormalizedEvent::new(
                timestamp_ns,
                EventType::ProcessCreate,
                Priority::Normal,
                Severity::Info,
                ProcessContext::default(),
                EventPayload::None,
            ),
            "local-tenant".to_string(),
            "local-agent".to_string(),
        )
    }

    fn malicious_script_event() -> NormalizedEvent {
        let mut event = NormalizedEvent::new(
            42,
            EventType::Script,
            Priority::High,
            Severity::Medium,
            ProcessContext {
                pid: 7331,
                name: "powershell.exe".to_string(),
                cmdline: "powershell -enc SQBFAFgA".to_string(),
                exe_hash: Some("deadbeef".to_string()),
                ..ProcessContext::default()
            },
            EventPayload::Script(ScriptContext {
                content: Some("IEX(New-Object Net.WebClient)".to_string()),
                interpreter: Some("powershell".to_string()),
                obfuscation_layers: 2,
                deobfuscated_content: None,
            }),
        );
        event.enrichment.risk_score = 95;
        event
    }

    #[test]
    fn bootstrap_creates_runtime_topology() {
        let orchestrator = Orchestrator::new(AppConfig::default());
        let artifacts = orchestrator.bootstrap().expect("bootstrap should work");

        assert_eq!(artifacts.summary.agent_id, "local-agent");
        assert_eq!(artifacts.summary.tenant_id, "local-tenant");
        assert_eq!(
            artifacts.summary.communication_channel,
            CommunicationChannelKind::Grpc
        );
        assert_eq!(artifacts.summary.queue_capacities["event"], 65_536);
        assert_eq!(
            artifacts.summary.queue_capacities["detection"],
            DETECTION_QUEUE_CAPACITY
        );
        assert_eq!(
            artifacts.summary.queue_capacities["decision"],
            DECISION_QUEUE_CAPACITY
        );
        assert_eq!(
            artifacts
                .summary
                .runtime_bridge
                .control_socket_path
                .as_deref(),
            Some("/var/lib/aegis/runtime-bridge-local-agent.sock")
        );
        assert!(artifacts
            .summary
            .task_topology
            .contains(&"detection-pool".to_string()));
        assert!(artifacts
            .summary
            .task_topology
            .contains(&"decision-router".to_string()));
        assert!(artifacts
            .summary
            .task_topology
            .contains(&"comms-rx".to_string()));
    }

    #[tokio::test]
    async fn runtime_executes_response_flow_for_malicious_script() {
        let state_root = temp_state_root("runtime-flow");
        let config = AppConfig::default().with_state_root(state_root.clone());
        let orchestrator = Orchestrator::new(config.clone());
        let artifacts = orchestrator.bootstrap().expect("bootstrap should work");
        let event_tx = artifacts.channels.event_tx.clone();
        let runtime = orchestrator.start(artifacts).expect("runtime should start");

        event_tx
            .send(malicious_script_event())
            .await
            .expect("send malicious event");
        tokio::time::sleep(Duration::from_millis(150)).await;

        let stopped = runtime
            .graceful_shutdown(Duration::from_secs(1))
            .await
            .expect("runtime shutdown should work");

        let audit_contents =
            fs::read_to_string(response_audit_path(&config)).expect("read response audit");
        assert!(audit_contents.contains("\"Kill\"") || audit_contents.contains("\"Quarantine\""));
        assert!(stopped.contains(&"sensor-dispatch".to_string()));
        assert!(stopped.contains(&"detection-pool".to_string()));
        assert!(stopped.contains(&"decision-router".to_string()));

        fs::remove_dir_all(state_root).ok();
    }

    #[tokio::test]
    async fn runtime_routes_high_alerts_and_batches_normal_uplinks() {
        let config = loopback_test_config("uplink-routing");
        let state_root = config.storage.state_root.clone();
        let orchestrator = Orchestrator::new(config);
        let artifacts = orchestrator.bootstrap().expect("bootstrap should work");
        let alert_tx_hi = artifacts.channels.alert_tx_hi.clone();
        let alert_tx_norm = artifacts.channels.alert_tx_norm.clone();
        let telemetry_tx = artifacts.channels.telemetry_tx.clone();
        let runtime = orchestrator.start(artifacts).expect("runtime should start");
        let handle = runtime
            .loopback_handle(CommunicationChannelKind::Grpc)
            .expect("grpc loopback handle");

        alert_tx_hi
            .send(sample_alert(Severity::High, "high severity alert"))
            .await
            .expect("send high alert");
        telemetry_tx
            .send(benign_telemetry_event(1))
            .await
            .expect("send telemetry event 1");
        telemetry_tx
            .send(benign_telemetry_event(2))
            .await
            .expect("send telemetry event 2");
        alert_tx_norm
            .send(sample_alert(Severity::Low, "low severity alert"))
            .await
            .expect("send normal alert");

        tokio::time::sleep(Duration::from_millis(1_250)).await;

        let first_batches = event_batches(&handle);
        let high_batch = first_batches
            .iter()
            .find(|batch| {
                batch.events.len() == 1
                    && matches!(batch.events[0].payload, EventPayload::Alert(_))
                    && batch.events[0].severity == Severity::High
            })
            .expect("high priority batch sent first")
            .clone();
        assert_eq!(high_batch.sequence_hint, 1);

        handle.inject_downlink(DownlinkMessage::BatchAck(BatchAck {
            batch_id: high_batch.batch_id,
            sequence_id: high_batch.sequence_hint,
            status: BatchAckStatus::Accepted,
            retry_after_ms: 0,
            reason: None,
            acked_at: now_unix_ms(),
            accepted_events: high_batch.events.len() as u32,
            rejected_events: 0,
        }));
        tokio::time::sleep(Duration::from_millis(1_250)).await;

        let second_batches = event_batches(&handle);
        let normal_batch = second_batches
            .iter()
            .find(|batch| {
                batch.events.len() >= 3
                    && batch.events.iter().any(|event| {
                        matches!(event.payload, EventPayload::Alert(_))
                            && event.severity == Severity::Low
                    })
                    && batch
                        .events
                        .iter()
                        .any(|event| event.event_type == EventType::ProcessCreate)
            })
            .expect("normal lane batch sent after ack");
        assert_eq!(normal_batch.sequence_hint, 2);

        runtime
            .graceful_shutdown(Duration::from_secs(1))
            .await
            .expect("runtime shutdown should work");
        fs::remove_dir_all(state_root).ok();
    }

    #[tokio::test]
    async fn runtime_applies_flow_control_to_normal_lane_and_counts_batch_acks() {
        let mut config = loopback_test_config("flow-control");
        config.runtime.heartbeat_interval_secs = 1;
        let state_root = config.storage.state_root.clone();
        let orchestrator = Orchestrator::new(config);
        let artifacts = orchestrator.bootstrap().expect("bootstrap should work");
        let telemetry_tx = artifacts.channels.telemetry_tx.clone();
        let runtime = orchestrator.start(artifacts).expect("runtime should start");
        let handle = runtime
            .loopback_handle(CommunicationChannelKind::Grpc)
            .expect("grpc loopback handle");

        handle.inject_downlink(DownlinkMessage::FlowControlHint(FlowControlHint {
            pause_low_priority: true,
            max_batch_events: 2,
            suggested_rate_eps: Some(10),
            cooldown_ms: Some(250),
            reason: Some("throttle normal lane".to_string()),
        }));
        tokio::time::sleep(Duration::from_millis(100)).await;

        telemetry_tx
            .send(benign_telemetry_event(10))
            .await
            .expect("send telemetry event 10");
        telemetry_tx
            .send(benign_telemetry_event(11))
            .await
            .expect("send telemetry event 11");
        telemetry_tx
            .send(benign_telemetry_event(12))
            .await
            .expect("send telemetry event 12");

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(event_batches(&handle).is_empty());

        handle.inject_downlink(DownlinkMessage::FlowControlHint(FlowControlHint {
            pause_low_priority: false,
            max_batch_events: 2,
            suggested_rate_eps: None,
            cooldown_ms: None,
            reason: Some("resume normal lane".to_string()),
        }));

        tokio::time::sleep(Duration::from_millis(1_250)).await;
        let first_batches = event_batches(&handle);
        let first_batch = first_batches
            .iter()
            .find(|batch| batch.events.len() == 2)
            .expect("first normal batch obeys flow-control batch size")
            .clone();
        assert_eq!(first_batch.sequence_hint, 1);

        handle.inject_downlink(DownlinkMessage::BatchAck(BatchAck {
            batch_id: first_batch.batch_id,
            sequence_id: first_batch.sequence_hint,
            status: BatchAckStatus::Accepted,
            retry_after_ms: 0,
            reason: None,
            acked_at: now_unix_ms(),
            accepted_events: first_batch.events.len() as u32,
            rejected_events: 0,
        }));

        tokio::time::sleep(Duration::from_millis(300)).await;
        let second_batches = event_batches(&handle);
        let second_batch = second_batches
            .iter()
            .find(|batch| batch.events.len() == 1)
            .expect("second normal batch waits for ack frontier")
            .clone();
        assert_eq!(second_batch.sequence_hint, 2);

        handle.inject_downlink(DownlinkMessage::BatchAck(BatchAck {
            batch_id: second_batch.batch_id,
            sequence_id: second_batch.sequence_hint,
            status: BatchAckStatus::Accepted,
            retry_after_ms: 0,
            reason: None,
            acked_at: now_unix_ms(),
            accepted_events: second_batch.events.len() as u32,
            rejected_events: 0,
        }));

        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let heartbeats = handle.take_heartbeats();
        assert!(heartbeats
            .iter()
            .any(|heartbeat| heartbeat.health.lineage_counters.grpc_acked >= 3));

        runtime
            .graceful_shutdown(Duration::from_secs(1))
            .await
            .expect("runtime shutdown should work");
        fs::remove_dir_all(state_root).ok();
    }

    #[tokio::test]
    async fn runtime_accepts_kill_command_and_rejects_replay() {
        let config = loopback_test_config("command-replay");
        let state_root = config.storage.state_root.clone();
        let orchestrator = Orchestrator::new(config.clone());
        let artifacts = orchestrator.bootstrap().expect("bootstrap should work");
        let runtime = orchestrator.start(artifacts).expect("runtime should start");
        let handle = runtime
            .loopback_handle(CommunicationChannelKind::Grpc)
            .expect("grpc loopback handle");

        let command = make_command(
            "kill-process",
            serde_json::to_vec(&KillProcessCommand { pid: 4242 }).expect("serialize kill command"),
            ApprovalPolicy {
                min_approvers: 0,
                approvers: Vec::new(),
                policy_version: "v1".to_string(),
            },
        );
        let signed = sign_server_command(&command);
        handle.inject_downlink(DownlinkMessage::ServerCommand(signed.clone()));
        tokio::time::sleep(Duration::from_millis(150)).await;
        handle.inject_downlink(DownlinkMessage::ServerCommand(signed));
        tokio::time::sleep(Duration::from_millis(150)).await;

        let acks = client_acks(&handle);
        assert!(acks.iter().any(|ack| {
            ack.command_id == command.command_id && ack.status == ClientAckStatus::Executed
        }));
        assert!(acks.iter().any(|ack| {
            ack.command_id == command.command_id
                && ack.status == ClientAckStatus::Rejected
                && ack.detail.as_deref().unwrap_or_default().contains("replay")
        }));

        let audit_contents =
            fs::read_to_string(response_audit_path(&config)).expect("read response audit");
        assert!(audit_contents.contains("\"Kill\""));

        runtime
            .graceful_shutdown(Duration::from_secs(1))
            .await
            .expect("runtime shutdown should work");
        fs::remove_dir_all(state_root).ok();
    }

    #[tokio::test]
    async fn runtime_rejects_remote_shell_without_required_approvers() {
        let config = loopback_test_config("remote-shell-reject");
        let state_root = config.storage.state_root.clone();
        let orchestrator = Orchestrator::new(config);
        let artifacts = orchestrator.bootstrap().expect("bootstrap should work");
        let runtime = orchestrator.start(artifacts).expect("runtime should start");
        let handle = runtime
            .loopback_handle(CommunicationChannelKind::Grpc)
            .expect("grpc loopback handle");

        let mut command = make_command(
            "remote-shell",
            serde_json::to_vec(&RemoteShellCommand {
                endpoint_id: "host-a".to_string(),
                operator: "operator-a".to_string(),
                command: "echo triage".to_string(),
            })
            .expect("serialize remote shell command"),
            ApprovalPolicy {
                min_approvers: 1,
                approvers: Vec::new(),
                policy_version: "v2".to_string(),
            },
        );
        command.approval.approvers = vec![approver_entry(
            &command,
            "approver-admin",
            "security_admin",
            LOOPBACK_ADMIN_SIGNING_KEY_ID,
            LOOPBACK_ADMIN_SIGNING_KEY_SEED,
        )];

        handle.inject_downlink(DownlinkMessage::ServerCommand(sign_server_command(
            &command,
        )));
        tokio::time::sleep(Duration::from_millis(150)).await;

        let acks = client_acks(&handle);
        assert!(acks.iter().any(|ack| {
            ack.command_id == command.command_id
                && ack.status == ClientAckStatus::Rejected
                && ack
                    .detail
                    .as_deref()
                    .unwrap_or_default()
                    .contains("approval")
        }));

        runtime
            .graceful_shutdown(Duration::from_secs(1))
            .await
            .expect("runtime shutdown should work");
        fs::remove_dir_all(state_root).ok();
    }

    #[tokio::test]
    async fn runtime_executes_session_lock_command() {
        let config = loopback_test_config("session-lock");
        let state_root = config.storage.state_root.clone();
        let orchestrator = Orchestrator::new(config);
        let artifacts = orchestrator.bootstrap().expect("bootstrap should work");
        let runtime = orchestrator.start(artifacts).expect("runtime should start");
        let handle = runtime
            .loopback_handle(CommunicationChannelKind::Grpc)
            .expect("grpc loopback handle");

        let mut command = make_command(
            "session-lock",
            serde_json::to_vec(&SessionLockCommand {
                user_session: "user-1".to_string(),
                reason: "contain suspected credential theft".to_string(),
            })
            .expect("serialize session lock command"),
            ApprovalPolicy {
                min_approvers: 1,
                approvers: Vec::new(),
                policy_version: "v1".to_string(),
            },
        );
        command.approval = approved_session_lock_policy(&command);

        handle.inject_downlink(DownlinkMessage::ServerCommand(sign_server_command(
            &command,
        )));
        tokio::time::sleep(Duration::from_millis(150)).await;

        let acks = client_acks(&handle);
        assert!(acks.iter().any(|ack| {
            ack.command_id == command.command_id
                && ack.status == ClientAckStatus::Executed
                && ack
                    .detail
                    .as_deref()
                    .unwrap_or_default()
                    .contains("session user-1 locked")
        }));

        runtime
            .graceful_shutdown(Duration::from_secs(1))
            .await
            .expect("runtime shutdown should work");
        fs::remove_dir_all(state_root).ok();
    }
}
