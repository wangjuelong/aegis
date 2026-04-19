use crate::comms::{CommunicationRuntime, HeartbeatBuilder, TelemetryBatchBuilder};
use crate::config::AppConfig;
use crate::correlation::{CorrelationCache, StorylineEngine};
use crate::feedback::ThreatFeedbackApplier;
use crate::health::HealthReporter;
use crate::ioc::{Indicator, IndicatorKind, IndicatorRisk, TieredIndicatorIndex};
use crate::ml::{
    FeatureExtractor, ModelInput, ModelKind, ModelOutput, ModelRegistry, OnnxRuntimeSession,
    OodScorer, RegisteredModel,
};
use crate::response_executor::{ResponseAuditLog, ResponseExecutor, TerminationRequest};
use crate::rule_vm::{CompareOp, CompiledRule, Instruction, RuleField, RuleValue, RuleVm};
use crate::runtime_sdk::{CloudConnectorRunner, RuntimeEventEmitter, SERVERLESS_CONTRACT_VERSION};
use crate::script_decode::{ScriptDecodePipeline, ScriptDecodeReport};
use crate::specialized_detection::{
    DeceptionKind, DeceptionObject, DetectionFinding, SpecializedDetectionEngine,
};
use crate::temporal::{TemporalSnapshot, TemporalStateBuffer};
use crate::yara::{EnqueueDisposition, YaraMatch, YaraResult, YaraScanTarget, YaraScheduler};
use aegis_model::{
    Alert, CloudApiConnectorContract, CloudLogSourceKind, CommunicationChannelKind, EventPayload,
    IsolationRulesV2, LineageCheckpoint, LineageCounters, NormalizedEvent, ResponseAction,
    RuntimeBridgeStatus, RuntimeHealthSignals, RuntimeHeartbeat, RuntimeMetadata,
    RuntimePolicyContract, RuntimeProviderKind, Severity, Storyline, StorylineContext,
    TelemetryEvent, ThreatIntelHit,
};
use aegis_platform::{MacosPlatform, PlatformRuntime};
use anyhow::{anyhow, Result};
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
const NETWORK_ISOLATION_TTL_SECS: u64 = 5 * 60;

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
            communication_channel: CommunicationChannelKind::Grpc,
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
                "comms-tx-high".to_string(),
                "comms-tx-normal".to_string(),
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

    pub fn start(&self, artifacts: BootstrapArtifacts) -> RuntimeHandle {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let comms_runtime = Arc::new(Mutex::new(CommunicationRuntime::with_loopback_drivers(3)));
        let detection_runtime = Arc::new(Mutex::new(DetectionRuntime::new()));
        let metrics = Arc::new(Mutex::new(RuntimeMetrics::default()));
        let platform = build_runtime_platform();
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
            name: "comms-tx-high",
            handle: tokio::spawn(alert_forwarder_task(
                "comms-tx-high",
                alert_rx_hi,
                shutdown_rx.clone(),
            )),
        });
        tasks.push(RuntimeTask {
            name: "comms-tx-normal",
            handle: tokio::spawn(alert_forwarder_task(
                "comms-tx-normal",
                alert_rx_norm,
                shutdown_rx.clone(),
            )),
        });
        tasks.push(RuntimeTask {
            name: "response-executor",
            handle: tokio::spawn(response_executor_task(
                response_audit_path,
                platform,
                response_rx,
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
                self.config.tenant_id.clone(),
                self.config.agent_id.clone(),
                telemetry_rx,
                Arc::clone(&comms_runtime),
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

        RuntimeHandle { shutdown_tx, tasks }
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

async fn alert_forwarder_task(
    name: &'static str,
    mut alert_rx: mpsc::Receiver<Alert>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    debug!(task = name, "alert forwarder received shutdown");
                    break;
                }
            }
            maybe_alert = alert_rx.recv() => {
                match maybe_alert {
                    Some(alert) => {
                        debug!(
                            task = name,
                            alert_id = %alert.alert_id,
                            storyline_id = alert.storyline_id.unwrap_or_default(),
                            summary = %alert.summary,
                            "forwarding alert"
                        );
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
    mut response_rx: mpsc::Receiver<ResponseAction>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    if let Some(parent) = audit_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let audit = ResponseAuditLog::new(audit_path);
    let executor = ResponseExecutor::new(platform.as_ref(), audit);

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
                        let result = match response {
                            ResponseAction::SuspendProcess { pid } => executor.terminate_process(
                                TerminationRequest {
                                    pid,
                                    protected_process: false,
                                    kill_required: false,
                                },
                            ),
                            ResponseAction::KillProcess { pid } => executor.terminate_process(
                                TerminationRequest {
                                    pid,
                                    protected_process: false,
                                    kill_required: true,
                                },
                            ),
                            ResponseAction::QuarantineFile { path } => executor.quarantine_file(&path),
                            ResponseAction::NetworkIsolate { ttl } => executor.network_isolate(&IsolationRulesV2 {
                                ttl,
                                allowed_control_plane_ips: vec!["127.0.0.1".to_string()],
                            }),
                        };
                        match result {
                            Ok(report) => debug!(records = report.records.len(), "response-executor applied action"),
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
    tenant_id: String,
    agent_id: String,
    mut telemetry_rx: mpsc::Receiver<TelemetryEvent>,
    comms_runtime: Arc<Mutex<CommunicationRuntime>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let builder = TelemetryBatchBuilder::new(1);
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    debug!("telemetry-drain received shutdown");
                    break;
                }
            }
            maybe_event = telemetry_rx.recv() => {
                match maybe_event {
                    Some(event) => {
                        match builder.build(
                            tenant_id.clone(),
                            agent_id.clone(),
                            event.lineage.checkpoints.len() as u64,
                            vec![event.clone()],
                        ) {
                            Ok(batch) => {
                                let send_result = comms_runtime
                                    .lock()
                                    .expect("comms runtime poisoned")
                                    .send_uplink(&batch, event.timestamp_ns as i64);
                                if let Err(error) = send_result {
                                    debug!(%error, "telemetry-drain failed to send batch");
                                }
                            }
                            Err(error) => debug!(%error, "telemetry-drain failed to build batch"),
                        }
                    }
                    None => break,
                }
            }
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

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_model::{EventType, Priority, ProcessContext, ScriptContext};

    fn temp_state_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("aegis-{name}-{}", Uuid::now_v7()))
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
    }

    #[tokio::test]
    async fn runtime_executes_response_flow_for_malicious_script() {
        let mut config = AppConfig::default();
        let state_root = temp_state_root("runtime-flow");
        config.storage.state_root = state_root.clone();
        let orchestrator = Orchestrator::new(config.clone());
        let artifacts = orchestrator.bootstrap().expect("bootstrap should work");
        let event_tx = artifacts.channels.event_tx.clone();
        let runtime = orchestrator.start(artifacts);

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
}
