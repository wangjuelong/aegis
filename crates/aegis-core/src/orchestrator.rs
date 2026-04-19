use crate::comms::{CommunicationRuntime, HeartbeatBuilder, TelemetryBatchBuilder};
use crate::config::AppConfig;
use crate::health::HealthReporter;
use aegis_model::{
    Alert, CommunicationChannelKind, LineageCounters, NormalizedEvent, ResponseAction,
    RuntimeHealthSignals, TelemetryEvent,
};
use anyhow::{anyhow, Result};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{interval, timeout, Duration, MissedTickBehavior};
use tracing::{debug, info};

const EVENT_QUEUE_CAPACITY: usize = 65_536;
const ALERT_HI_QUEUE_CAPACITY: usize = 1_024;
const ALERT_NORMAL_QUEUE_CAPACITY: usize = 4_096;
const RESPONSE_QUEUE_CAPACITY: usize = 1_024;
const TELEMETRY_QUEUE_CAPACITY: usize = 2_048;

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

        let summary = BootstrapSummary {
            agent_id: self.config.agent_id.clone(),
            tenant_id: self.config.tenant_id.clone(),
            control_plane_url: self.config.control_plane_url.clone(),
            communication_channel: CommunicationChannelKind::Grpc,
            lineage_counters: LineageCounters::default(),
            queue_capacities: BTreeMap::from([
                ("event".to_string(), EVENT_QUEUE_CAPACITY),
                ("alert_hi".to_string(), ALERT_HI_QUEUE_CAPACITY),
                ("alert_norm".to_string(), ALERT_NORMAL_QUEUE_CAPACITY),
                ("response".to_string(), RESPONSE_QUEUE_CAPACITY),
                ("telemetry".to_string(), TELEMETRY_QUEUE_CAPACITY),
            ]),
            task_topology: vec![
                "sensor-dispatch".to_string(),
                "comms-tx-high".to_string(),
                "comms-tx-normal".to_string(),
                "comms-link-manager".to_string(),
                "response-executor".to_string(),
                "telemetry-drain".to_string(),
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

        let mut tasks = Vec::new();
        tasks.push(RuntimeTask {
            name: "sensor-dispatch",
            handle: tokio::spawn(sensor_dispatch_task(
                artifacts.receivers.event_rx,
                shutdown_rx.clone(),
            )),
        });
        tasks.push(RuntimeTask {
            name: "comms-tx-high",
            handle: tokio::spawn(alert_forwarder_task(
                "comms-tx-high",
                artifacts.receivers.alert_rx_hi,
                shutdown_rx.clone(),
            )),
        });
        tasks.push(RuntimeTask {
            name: "comms-tx-normal",
            handle: tokio::spawn(alert_forwarder_task(
                "comms-tx-normal",
                artifacts.receivers.alert_rx_norm,
                shutdown_rx.clone(),
            )),
        });
        tasks.push(RuntimeTask {
            name: "response-executor",
            handle: tokio::spawn(response_executor_task(
                artifacts.receivers.response_rx,
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
                artifacts.receivers.telemetry_rx,
                Arc::clone(&comms_runtime),
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

async fn sensor_dispatch_task(
    mut event_rx: mpsc::Receiver<NormalizedEvent>,
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
                        debug!(event_id = %event.event_id, lineage_id = %event.lineage_id, "sensor-dispatch received normalized event");
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
                        debug!(task = name, alert_id = %alert.alert_id, "forwarding alert");
                    }
                    None => break,
                }
            }
        }
    }
}

async fn response_executor_task(
    mut response_rx: mpsc::Receiver<ResponseAction>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
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
                        debug!(?response, "response-executor received action");
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
                let health = HealthReporter::build_snapshot(
                    "0.1.0",
                    "policy-1",
                    "ruleset-1",
                    "model-1",
                    0.0,
                    0,
                    BTreeMap::from([("telemetry".to_string(), 0usize)]),
                    LineageCounters::default(),
                    RuntimeHealthSignals {
                        communication_channel: communication.active_channel,
                        adaptive_whitelist_size: 0,
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

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(artifacts
            .summary
            .task_topology
            .contains(&"health-reporter".to_string()));
        assert!(artifacts
            .summary
            .task_topology
            .contains(&"comms-link-manager".to_string()));
    }

    #[tokio::test]
    async fn runtime_handle_gracefully_stops_background_tasks() {
        let orchestrator = Orchestrator::new(AppConfig::default());
        let artifacts = orchestrator.bootstrap().expect("bootstrap should work");
        let runtime = orchestrator.start(artifacts);

        let stopped = runtime
            .graceful_shutdown(Duration::from_secs(1))
            .await
            .expect("runtime shutdown should work");

        assert!(stopped.contains(&"sensor-dispatch".to_string()));
        assert!(stopped.contains(&"health-reporter".to_string()));
        assert!(stopped.contains(&"comms-link-manager".to_string()));
        assert!(stopped.contains(&"config-watcher".to_string()));
    }
}
