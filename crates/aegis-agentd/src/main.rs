use aegis_core::comms::{CommandReplayLedger, CommunicationRuntime, RollbackProtectionStatus};
use aegis_core::config::AppConfig;
use aegis_core::health::HealthReporter;
use aegis_core::orchestrator::Orchestrator;
use aegis_core::plugin_host::PluginHost;
use aegis_core::self_protection::{
    linux_tpm_attestation_status_from_config, verify_linux_tpm_attestation_roundtrip,
    DerivedKeyTier, KeyDerivationService, ProtectionPosture,
};
use aegis_core::transport_drivers::TransportAgentContext;
use aegis_core::upgrade::{
    AgentRuntimeSnapshot, BootstrapCheckItem, BootstrapCheckReport, DiagnoseCertificateStatus,
    DiagnoseCollector, DiagnoseConnectionStatus, DiagnoseKeyProtectionStatus,
    DiagnoseReplayStatus, DiagnoseSensorStatus, DiagnoseWalStatus, InstallPlatform,
    RuntimeStateStore, UpdateVerificationSnapshot, WindowsInstallManifest,
};
use aegis_core::wal::{PendingBatchStore, ReplayLane};
use aegis_model::{
    AgentSupervisorHeartbeat, LineageCounters, PluginHealthStatus, RuntimeBridgeStatus,
    RuntimeHealthSignals, TelemetryIntegrity,
};
use anyhow::{bail, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum AgentMode {
    #[default]
    Run,
    Diagnose,
    WriteDefaultConfig,
    BootstrapCheck,
}

#[derive(Clone, Debug, Default)]
struct CliArgs {
    mode: AgentMode,
    state_root: Option<PathBuf>,
    config_path: Option<PathBuf>,
    install_root: Option<PathBuf>,
    manifest_path: Option<PathBuf>,
    control_plane_url: Option<String>,
    agent_id: Option<String>,
    tenant_id: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_args()?;

    match cli.mode {
        AgentMode::Diagnose => {
            let config = load_runtime_config(cli.state_root.clone(), cli.config_path.clone())?;
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
        AgentMode::WriteDefaultConfig => {
            let config = write_default_config(&cli)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "config_path": config.storage.config_path,
                    "state_root": config.storage.state_root,
                    "agent_id": config.agent_id,
                    "tenant_id": config.tenant_id,
                    "control_plane_url": config.control_plane_url,
                }))?
            );
            return Ok(());
        }
        AgentMode::BootstrapCheck => {
            let report = run_bootstrap_check(&cli)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.approved {
                bail!("bootstrap check failed");
            }
            return Ok(());
        }
        AgentMode::Run => {}
    }

    tracing_subscriber::fmt().with_env_filter("info").init();

    let config = load_runtime_config(cli.state_root.clone(), cli.config_path.clone())?;
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

fn parse_args() -> Result<CliArgs> {
    let mut args = CliArgs::default();
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--diagnose" => set_mode(&mut args.mode, AgentMode::Diagnose)?,
            "--write-default-config" => set_mode(&mut args.mode, AgentMode::WriteDefaultConfig)?,
            "--bootstrap-check" => set_mode(&mut args.mode, AgentMode::BootstrapCheck)?,
            "--state-root" => {
                args.state_root = Some(PathBuf::from(next_arg(&mut iter, "--state-root")?))
            }
            "--config" => args.config_path = Some(PathBuf::from(next_arg(&mut iter, "--config")?)),
            "--install-root" => {
                args.install_root = Some(PathBuf::from(next_arg(&mut iter, "--install-root")?))
            }
            "--manifest" => {
                args.manifest_path = Some(PathBuf::from(next_arg(&mut iter, "--manifest")?))
            }
            "--control-plane-url" => {
                args.control_plane_url = Some(next_arg(&mut iter, "--control-plane-url")?)
            }
            "--agent-id" => args.agent_id = Some(next_arg(&mut iter, "--agent-id")?),
            "--tenant-id" => args.tenant_id = Some(next_arg(&mut iter, "--tenant-id")?),
            other => bail!("unsupported argument: {other}"),
        }
    }
    Ok(args)
}

fn set_mode(target: &mut AgentMode, next: AgentMode) -> Result<()> {
    if *target != AgentMode::Run {
        bail!("multiple agent modes requested");
    }
    *target = next;
    Ok(())
}

fn next_arg(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    iter.next()
        .ok_or_else(|| anyhow::anyhow!("missing value for {flag}"))
}

fn load_runtime_config(
    explicit_state_root: Option<PathBuf>,
    explicit_config_path: Option<PathBuf>,
) -> Result<AppConfig> {
    let root_override = if let Some(state_root) = explicit_state_root {
        Some(state_root)
    } else if let Ok(state_root) = std::env::var("AEGIS_STATE_ROOT") {
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

    let config_path_override =
        explicit_config_path.or_else(|| std::env::var("AEGIS_CONFIG").ok().map(PathBuf::from));
    let candidate_path = config_path_override
        .clone()
        .unwrap_or_else(|| bootstrap.storage.config_path.clone());
    let mut config = if candidate_path.exists() {
        AppConfig::load_from_file(&candidate_path)?
    } else {
        bootstrap
    };

    if let Some(state_root) = root_override {
        config = config.with_state_root(state_root.clone());
        if let Some(config_path) = config_path_override.clone() {
            config.storage.config_path = config_path;
        }
    }

    Ok(config)
}

fn write_default_config(cli: &CliArgs) -> Result<AppConfig> {
    let mut config = AppConfig::default();
    if let Some(state_root) = cli.state_root.clone() {
        config = config.with_state_root(state_root);
    } else if !state_root_writable(&config.storage.state_root) {
        config = config.with_state_root(std::env::current_dir()?.join("target/aegis-dev/state"));
    }

    if let Some(config_path) = cli.config_path.clone() {
        config.storage.config_path = config_path;
    }
    if let Some(control_plane_url) = &cli.control_plane_url {
        config.control_plane_url = control_plane_url.clone();
    }
    if let Some(agent_id) = &cli.agent_id {
        config.agent_id = agent_id.clone();
    }
    if let Some(tenant_id) = &cli.tenant_id {
        config.tenant_id = tenant_id.clone();
    }

    ensure_storage_layout(&config)?;
    let serialized = config.to_toml_string()?;
    if let Some(parent) = config.storage.config_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&config.storage.config_path, serialized)?;
    Ok(config)
}

fn ensure_storage_layout(config: &AppConfig) -> Result<()> {
    fs::create_dir_all(&config.storage.state_root)?;
    fs::create_dir_all(&config.storage.ring_buffer_path)?;
    fs::create_dir_all(&config.storage.spill_path)?;
    fs::create_dir_all(&config.storage.forensic_path)?;
    Ok(())
}

fn run_bootstrap_check(cli: &CliArgs) -> Result<BootstrapCheckReport> {
    let config = load_runtime_config(cli.state_root.clone(), cli.config_path.clone())?;
    let manifest_path = cli
        .manifest_path
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--manifest is required for --bootstrap-check"))?;
    let manifest = WindowsInstallManifest::load_from_file(&manifest_path)?;
    let install_root = cli
        .install_root
        .clone()
        .unwrap_or_else(|| manifest.install_root.clone());
    let observed_at_ms = now_unix_ms();
    let mut items = Vec::new();

    push_check(
        &mut items,
        "state_root_writable",
        state_root_writable(&config.storage.state_root),
        format!("state root {}", config.storage.state_root.display()),
    );
    push_check(
        &mut items,
        "config_file_present",
        config.storage.config_path.exists(),
        format!("config path {}", config.storage.config_path.display()),
    );
    push_check(
        &mut items,
        "manifest_state_root_match",
        manifest.state_root == config.storage.state_root,
        format!(
            "manifest={} runtime={}",
            manifest.state_root.display(),
            config.storage.state_root.display()
        ),
    );
    push_check(
        &mut items,
        "manifest_install_root_match",
        manifest.install_root == install_root,
        format!(
            "manifest={} runtime={}",
            manifest.install_root.display(),
            install_root.display()
        ),
    );
    if let Some(config_root) = &manifest.config_root {
        let runtime_config_root = config
            .storage
            .config_path
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| config.storage.config_path.clone());
        push_check(
            &mut items,
            "manifest_config_root_match",
            runtime_config_root == *config_root,
            format!(
                "manifest={} runtime={}",
                config_root.display(),
                runtime_config_root.display()
            ),
        );
    }

    for component in &manifest.components {
        let installed_path = install_root.join(&component.install_relative_path);
        push_check(
            &mut items,
            format!("component:{}", component.name),
            !component.required || installed_path.exists(),
            format!("{}", installed_path.display()),
        );
    }

    if manifest.platform == InstallPlatform::Linux {
        for service_unit in &manifest.service_units {
            let installed_unit = PathBuf::from("/etc/systemd/system").join(&service_unit.unit_name);
            push_check(
                &mut items,
                format!("service_unit:{}", service_unit.name),
                !service_unit.required || installed_unit.exists(),
                installed_unit.display().to_string(),
            );
        }
    }

    for dependency in &manifest.release_dependencies {
        let (ok, detail) = match (&dependency.install_relative_path, dependency.required) {
            (Some(relative_path), true) => {
                let candidate = install_root.join(relative_path);
                (candidate.exists(), candidate.display().to_string())
            }
            (Some(relative_path), false) => (
                true,
                format!(
                    "not enforced for {} bundle: {}",
                    manifest.bundle_channel,
                    install_root.join(relative_path).display()
                ),
            ),
            (None, true) => (
                false,
                dependency
                    .detail
                    .clone()
                    .unwrap_or_else(|| "required dependency evidence is missing".to_string()),
            ),
            (None, false) => (
                true,
                dependency
                    .detail
                    .clone()
                    .unwrap_or_else(|| "dependency is informational".to_string()),
            ),
        };
        push_check(
            &mut items,
            format!("dependency:{}", dependency.name),
            ok,
            detail,
        );
    }

    let bootstrap = Orchestrator::new(config.clone()).bootstrap();
    let runtime_bridge_socket = match &bootstrap {
        Ok(artifacts) => artifacts
            .summary
            .runtime_bridge
            .control_socket_path
            .as_ref()
            .map(PathBuf::from),
        Err(_) => None,
    };
    push_check(
        &mut items,
        "runtime_bootstrap",
        bootstrap.is_ok(),
        runtime_bridge_socket
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "orchestrator bootstrap failed".to_string()),
    );

    if let Ok(artifacts) = bootstrap {
        let snapshot =
            build_agent_runtime_snapshot(&config, Some(artifacts.summary.runtime_bridge));
        RuntimeStateStore::persist_agent_snapshot(&config, &snapshot)?;
    }

    let report = BootstrapCheckReport {
        observed_at_ms,
        install_root,
        state_root: config.storage.state_root.clone(),
        config_path: config.storage.config_path.clone(),
        manifest_path,
        runtime_bridge_socket,
        approved: items.iter().all(|item| item.ok),
        items,
    };
    RuntimeStateStore::persist_bootstrap_report(&config, &report)?;
    Ok(report)
}

fn push_check(
    items: &mut Vec<BootstrapCheckItem>,
    name: impl Into<String>,
    ok: bool,
    detail: impl Into<String>,
) {
    items.push(BootstrapCheckItem {
        name: name.into(),
        ok,
        detail: detail.into(),
    });
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
    let update = load_update_status(config);
    let plugin_status = collect_plugin_status(config);
    let active_update_id = update.active_update_id();
    let health = HealthReporter::build_snapshot(
        current_agent_version(),
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

    let certificates = diagnose_certificate_status(config);

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
        certificates,
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
        update: update.to_diagnose_status(),
        resources: health,
        runtime_bridge,
        plugin_status,
        self_protection_posture: protection_posture_from_key_status(&key_protection),
    }
}

#[derive(Deserialize)]
struct LinuxAttestationVerifierReceipt {
    verified: bool,
}

fn diagnose_certificate_status(config: &AppConfig) -> DiagnoseCertificateStatus {
    if cfg!(target_os = "linux") {
        let identity_root = config.storage.state_root.join("identity");
        let attestation_root = config.storage.state_root.join("attestation").join("current");
        let device_certificate_path = identity_root.join("device.crt");
        let bundle_path = attestation_root.join("bundle.json");
        let receipt_path = attestation_root.join("verified-receipt.json");
        let receipt = fs::read(&receipt_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<LinuxAttestationVerifierReceipt>(&bytes).ok());
        return DiagnoseCertificateStatus {
            device_certificate_loaded: device_certificate_path.exists(),
            last_rotation_succeeded: device_certificate_path.exists(),
            attestation_bundle_loaded: bundle_path.exists(),
            attestation_verifier_receipt_loaded: receipt_path.exists(),
            attestation_verifier_receipt_verified: receipt
                .map(|receipt| receipt.verified)
                .unwrap_or(false),
        };
    }

    DiagnoseCertificateStatus {
        device_certificate_loaded: true,
        last_rotation_succeeded: true,
        attestation_bundle_loaded: false,
        attestation_verifier_receipt_loaded: false,
        attestation_verifier_receipt_verified: false,
    }
}

fn current_agent_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn load_update_status(config: &AppConfig) -> UpdateVerificationSnapshot {
    let mut snapshot = RuntimeStateStore::load_update_snapshot(config).unwrap_or_else(|_| {
        UpdateVerificationSnapshot::new(current_agent_version(), now_unix_ms())
    });
    if snapshot.current_version.is_empty() {
        snapshot.current_version = current_agent_version().to_string();
    }
    snapshot
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
            let mut key_protection = DiagnoseKeyProtectionStatus::from_runtime(
                service.protection_status(),
                rollback_status,
            );
            apply_linux_tpm_attestation_self_check(config, &mut key_protection);
            (
                DiagnoseWalStatus {
                    telemetry_segments,
                    forensic_root: config.storage.forensic_path.clone(),
                    completeness,
                    encrypted: true,
                    key_version: material.version,
                    quarantined_segments,
                },
                key_protection,
            )
        }
        Err(error) => {
            let mut key_protection = DiagnoseKeyProtectionStatus::default();
            let (attestation_quote_ready, attestation_pcrs, attestation_error) =
                linux_tpm_attestation_status_from_config(config);
            key_protection.attestation_quote_ready = attestation_quote_ready;
            key_protection.attestation_pcrs = attestation_pcrs;
            key_protection.attestation_error = attestation_error;
            key_protection.rollback_anchor = rollback_status.anchor_kind;
            key_protection.rollback_floor_issued_at_ms = rollback_status.floor_issued_at_ms;
            key_protection.rollback_fs_cross_check_ms = rollback_status.fs_cross_check_ms;
            key_protection.rollback_cross_check_ok = rollback_status.cross_check_ok;
            key_protection.rollback_error = rollback_status.last_error.clone();
            key_protection.key_provider_error = Some(error.to_string());
            apply_linux_tpm_attestation_self_check(config, &mut key_protection);
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

fn apply_linux_tpm_attestation_self_check(
    config: &AppConfig,
    key_protection: &mut DiagnoseKeyProtectionStatus,
) {
    if !key_protection.attestation_quote_ready {
        return;
    }

    if let Err(error) =
        verify_linux_tpm_attestation_roundtrip(config, b"aegis-diagnose-attestation")
    {
        key_protection.attestation_quote_ready = false;
        key_protection.degraded = true;
        merge_diagnose_error(
            &mut key_protection.attestation_error,
            format!("linux tpm attestation self-check failed: {error}"),
        );
    }
}

fn merge_diagnose_error(target: &mut Option<String>, next: String) {
    match target {
        Some(current) if !current.is_empty() => {
            current.push_str("; ");
            current.push_str(&next);
        }
        _ => *target = Some(next),
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
