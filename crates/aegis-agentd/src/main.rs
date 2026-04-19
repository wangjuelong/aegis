use aegis_core::comms::{CommandReplayLedger, CommunicationRuntime, RollbackProtectionStatus};
use aegis_core::config::AppConfig;
use aegis_core::health::HealthReporter;
use aegis_core::orchestrator::Orchestrator;
use aegis_core::plugin_host::PluginHost;
use aegis_core::self_protection::{DerivedKeyTier, KeyDerivationService, ProtectionPosture};
use aegis_core::transport_drivers::TransportAgentContext;
use aegis_core::upgrade::{
    AgentRuntimeSnapshot, DiagnoseCertificateStatus, DiagnoseCollector, DiagnoseConnectionStatus,
    DiagnoseKeyProtectionStatus, DiagnoseReplayStatus, DiagnoseSensorStatus, DiagnoseWalStatus,
    RuntimeStateStore,
};
use aegis_core::wal::{PendingBatchStore, ReplayLane};
use aegis_model::{
    AgentSupervisorHeartbeat, LineageCounters, PluginHealthStatus, RuntimeBridgeStatus,
    RuntimeHealthSignals, TelemetryIntegrity,
};
use anyhow::Result;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().any(|arg| arg == "--diagnose") {
        let config = load_runtime_config()?;
        let persisted_runtime_bridge = RuntimeStateStore::load_agent_snapshot(&config)
            .ok()
            .and_then(|snapshot| snapshot.runtime_bridge);
        let runtime_bridge = match persisted_runtime_bridge {
            Some(runtime_bridge) => runtime_bridge,
            None => {
                Orchestrator::new(config.clone())
                    .bootstrap()?
                    .summary
                    .runtime_bridge
            }
        };
        let snapshot = build_agent_runtime_snapshot(&config, Some(runtime_bridge));
        RuntimeStateStore::persist_agent_snapshot(&config, &snapshot)?;
        let mut bundle = snapshot.to_diagnose_bundle();
        bundle.watchdog = RuntimeStateStore::load_watchdog_snapshot(&config).ok();
        println!("{}", DiagnoseCollector::to_json(&bundle)?);
        return Ok(());
    }

    tracing_subscriber::fmt().with_env_filter("info").init();

    let config = load_runtime_config()?;
    let shutdown_grace_period = config.shutdown_grace_period();
    let orchestrator = Orchestrator::new(config.clone());
    let artifacts = orchestrator.bootstrap()?;
    let summary = &artifacts.summary;
    let runtime_snapshot =
        build_agent_runtime_snapshot(&config, Some(summary.runtime_bridge.clone()));
    RuntimeStateStore::persist_agent_snapshot(&config, &runtime_snapshot)?;
    let supervisor_heartbeat = runtime_snapshot.supervisor_heartbeat.clone();

    info!(
        agent_id = %summary.agent_id,
        tenant_id = %summary.tenant_id,
        control_plane_url = %summary.control_plane_url,
        communication_channel = ?summary.communication_channel,
        plugin_count = supervisor_heartbeat.plugin_count,
        degraded_plugins = supervisor_heartbeat.degraded_plugins,
        tasks = ?summary.task_topology,
        "aegis-agentd runtime bootstrapped"
    );

    let runtime = orchestrator.start(artifacts)?;
    tokio::signal::ctrl_c().await?;
    let stopped_tasks = runtime.graceful_shutdown(shutdown_grace_period).await?;

    info!(tasks = ?stopped_tasks, "aegis-agentd runtime stopped");

    Ok(())
}

fn load_runtime_config() -> Result<AppConfig> {
    let root_override = if let Ok(state_root) = std::env::var("AEGIS_STATE_ROOT") {
        Some(PathBuf::from(state_root))
    } else {
        let default = AppConfig::default();
        if state_root_writable(&default.storage.state_root) {
            None
        } else {
            Some(std::env::current_dir()?.join("target/aegis-dev/state"))
        }
    };

    let bootstrap = match &root_override {
        Some(state_root) => AppConfig::default().with_state_root(state_root.clone()),
        None => AppConfig::default(),
    };

    let explicit_config_path = std::env::var("AEGIS_CONFIG").ok().map(PathBuf::from);
    let candidate_path =
        explicit_config_path.unwrap_or_else(|| bootstrap.storage.config_path.clone());
    let mut config = if candidate_path.exists() {
        AppConfig::load_from_file(&candidate_path)?
    } else {
        bootstrap
    };

    if let Some(state_root) = root_override {
        config = config.with_state_root(state_root);
    }

    Ok(config)
}

fn state_root_writable(path: &Path) -> bool {
    if fs::create_dir_all(path).is_err() {
        return false;
    }
    let probe = path.join(".aegis-write-probe");
    match fs::write(&probe, b"ok") {
        Ok(()) => {
            let _ = fs::remove_file(probe);
            true
        }
        Err(_) => false,
    }
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as i64
}

fn collect_plugin_status(config: &AppConfig) -> Vec<PluginHealthStatus> {
    let mut plugin_host = PluginHost::default();
    let manifest_root = config.storage.state_root.join("plugins");
    if let Err(error) = plugin_host.load_manifests_from_dir(&manifest_root) {
        return vec![PluginHealthStatus {
            plugin_id: "__plugin_host__".to_string(),
            healthy: false,
            state: format!("load_error: {error}"),
            crash_count: 1,
        }];
    }
    plugin_host.run_all_once()
}

fn build_agent_runtime_snapshot(
    config: &AppConfig,
    runtime_bridge: Option<RuntimeBridgeStatus>,
) -> AgentRuntimeSnapshot {
    let communication = CommunicationRuntime::from_config(
        &config.communication,
        &TransportAgentContext {
            tenant_id: config.tenant_id.clone(),
            agent_id: config.agent_id.clone(),
        },
    )
    .map(|runtime| runtime.snapshot())
    .unwrap_or_default();
    let rollback_status = load_rollback_status(config);
    let (wal, key_protection) = diagnose_storage_security(config, &rollback_status);
    let replay = load_replay_status(config);
    let plugin_status = collect_plugin_status(config);
    let active_update_id = RuntimeStateStore::load_update_snapshot(config)
        .ok()
        .map(|snapshot| snapshot.manifest.artifact_id);
    let health = HealthReporter::build_snapshot(
        "0.1.0",
        &format!("bundle-{}", config.policy_version.policy_bundle),
        &format!("ruleset-{}", config.policy_version.ruleset_revision),
        &format!("model-{}", config.policy_version.model_revision),
        2.5,
        128,
        BTreeMap::from([("event".to_string(), 0usize)]),
        LineageCounters::default(),
        RuntimeHealthSignals {
            communication_channel: communication.active_channel,
            adaptive_whitelist_size: 0,
            etw_tamper_detected: false,
            amsi_tamper_detected: false,
            bpf_integrity_pass: true,
        },
    );

    AgentRuntimeSnapshot {
        captured_at_ms: now_unix_ms(),
        supervisor_heartbeat: AgentSupervisorHeartbeat {
            tenant_id: config.tenant_id.clone(),
            agent_id: config.agent_id.clone(),
            plugin_count: plugin_status.len(),
            degraded_plugins: plugin_status
                .iter()
                .filter(|plugin| !plugin.healthy)
                .count(),
            active_update_id,
            sent_at_ms: now_unix_ms(),
        },
        connection: DiagnoseConnectionStatus {
            control_plane_url: config.control_plane_url.clone(),
            reachable: communication.channels.iter().any(|channel| channel.healthy),
        },
        certificates: DiagnoseCertificateStatus {
            device_certificate_loaded: true,
            last_rotation_succeeded: true,
        },
        sensors: DiagnoseSensorStatus {
            enabled_sensors: vec![
                "process".to_string(),
                "file".to_string(),
                "network".to_string(),
            ],
            unhealthy_sensors: vec![],
        },
        communication,
        engine_versions: BTreeMap::from([
            (
                "policy_bundle".to_string(),
                config.policy_version.policy_bundle.to_string(),
            ),
            (
                "ruleset_revision".to_string(),
                config.policy_version.ruleset_revision.to_string(),
            ),
            (
                "model_revision".to_string(),
                config.policy_version.model_revision.to_string(),
            ),
        ]),
        ring_buffer_utilization_ratio: 0.0,
        wal,
        key_protection: key_protection.clone(),
        replay,
        resources: health,
        runtime_bridge,
        plugin_status,
        self_protection_posture: protection_posture_from_key_status(&key_protection),
    }
}

fn diagnose_storage_security(
    config: &AppConfig,
    rollback_status: &RollbackProtectionStatus,
) -> (DiagnoseWalStatus, DiagnoseKeyProtectionStatus) {
    let telemetry_segments = wal_segment_count(&config.storage.spill_path);
    let quarantined_segments = wal_quarantine_count(&config.storage.spill_path);
    let completeness = if quarantined_segments > 0 {
        TelemetryIntegrity::Partial
    } else {
        TelemetryIntegrity::Full
    };

    match KeyDerivationService::from_config(config) {
        Ok(service) => {
            let material = service.derive_material(
                &config.tenant_id,
                &config.agent_id,
                DerivedKeyTier::TelemetryWal,
                1,
            );
            (
                DiagnoseWalStatus {
                    telemetry_segments,
                    forensic_root: config.storage.forensic_path.clone(),
                    completeness,
                    encrypted: true,
                    key_version: material.version,
                    quarantined_segments,
                },
                DiagnoseKeyProtectionStatus::from_runtime(
                    service.protection_status(),
                    rollback_status,
                ),
            )
        }
        Err(error) => {
            let mut key_protection = DiagnoseKeyProtectionStatus::default();
            key_protection.rollback_anchor = rollback_status.anchor_kind;
            key_protection.rollback_floor_issued_at_ms = rollback_status.floor_issued_at_ms;
            key_protection.rollback_fs_cross_check_ms = rollback_status.fs_cross_check_ms;
            key_protection.rollback_cross_check_ok = rollback_status.cross_check_ok;
            key_protection.rollback_error = rollback_status.last_error.clone();
            key_protection.key_provider_error = Some(error.to_string());
            (
                DiagnoseWalStatus {
                    telemetry_segments,
                    forensic_root: config.storage.forensic_path.clone(),
                    completeness,
                    encrypted: false,
                    key_version: 0,
                    quarantined_segments,
                },
                key_protection,
            )
        }
    }
}

fn load_rollback_status(config: &AppConfig) -> RollbackProtectionStatus {
    match CommandReplayLedger::new_persistent_with_security(
        command_replay_path(config),
        &config.security,
    ) {
        Ok(ledger) => ledger.rollback_status().clone(),
        Err(error) => {
            let mut status = RollbackProtectionStatus::default();
            status.last_error = Some(error.to_string());
            status
        }
    }
}

fn wal_segment_count(root: &Path) -> usize {
    fs::read_dir(root)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(|entry| entry.ok()))
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| name.starts_with("segment-") && name.ends_with(".wal"))
                .unwrap_or(false)
        })
        .count()
}

fn wal_quarantine_count(root: &Path) -> usize {
    fs::read_dir(root.join("quarantine"))
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(|entry| entry.ok()))
        .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("corrupt"))
        .count()
}

fn protection_posture_from_key_status(status: &DiagnoseKeyProtectionStatus) -> ProtectionPosture {
    if status.degraded {
        ProtectionPosture::Hardened
    } else {
        ProtectionPosture::Normal
    }
}

fn command_replay_path(config: &AppConfig) -> PathBuf {
    config.storage.state_root.join("command-replay-ledger.db")
}

fn load_replay_status(config: &AppConfig) -> DiagnoseReplayStatus {
    match PendingBatchStore::load(replay_store_path(config)) {
        Ok(store) => {
            let snapshot = store.snapshot();
            let pending_batches = snapshot.pending_batches.len();
            let high_priority_pending_batches = snapshot
                .pending_batches
                .iter()
                .filter(|batch| batch.lane == ReplayLane::HighPriority)
                .count();
            let normal_pending_batches = snapshot
                .pending_batches
                .iter()
                .filter(|batch| batch.lane == ReplayLane::Normal)
                .count();
            let retry_pending_batches = snapshot
                .pending_batches
                .iter()
                .filter(|batch| batch.last_error.is_some())
                .count();
            let in_flight_sequence_id = snapshot
                .pending_batches
                .iter()
                .filter_map(|batch| batch.in_flight_sequence_id)
                .min();
            let oldest_pending_created_at_ms = snapshot
                .pending_batches
                .iter()
                .map(|batch| batch.created_at_ms)
                .min();
            let last_error = snapshot
                .pending_batches
                .iter()
                .filter_map(|batch| batch.last_error.clone())
                .next();

            DiagnoseReplayStatus {
                last_acked_sequence_id: snapshot.last_acked_sequence_id,
                pending_batches,
                high_priority_pending_batches,
                normal_pending_batches,
                retry_pending_batches,
                in_flight_sequence_id,
                oldest_pending_created_at_ms,
                last_error,
            }
        }
        Err(error) => DiagnoseReplayStatus {
            last_error: Some(error.to_string()),
            ..DiagnoseReplayStatus::default()
        },
    }
}

fn replay_store_path(config: &AppConfig) -> PathBuf {
    config.storage.state_root.join("telemetry-replay.json")
}
