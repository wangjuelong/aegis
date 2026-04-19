use aegis_core::comms::CommunicationRuntime;
use aegis_core::config::AppConfig;
use aegis_core::health::HealthReporter;
use aegis_core::orchestrator::Orchestrator;
use aegis_core::plugin_host::PluginHost;
use aegis_core::self_protection::ProtectionPosture;
use aegis_core::transport_drivers::TransportAgentContext;
use aegis_core::upgrade::{
    AgentRuntimeSnapshot, DiagnoseCertificateStatus, DiagnoseCollector, DiagnoseConnectionStatus,
    DiagnoseSensorStatus, DiagnoseWalStatus, RuntimeStateStore,
};
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
        wal: DiagnoseWalStatus {
            telemetry_segments: 0,
            forensic_root: config.storage.forensic_path.clone(),
            completeness: TelemetryIntegrity::Full,
            encrypted: true,
            key_version: 1,
            quarantined_segments: 0,
        },
        resources: health,
        runtime_bridge,
        plugin_status,
        self_protection_posture: ProtectionPosture::Normal,
    }
}
