use aegis_core::config::AppConfig;
use aegis_core::health::HealthReporter;
use aegis_core::orchestrator::Orchestrator;
use aegis_core::self_protection::ProtectionPosture;
use aegis_core::upgrade::{
    DiagnoseCertificateStatus, DiagnoseCollector, DiagnoseSensorStatus, DiagnoseWalStatus,
};
use aegis_model::{LineageCounters, TelemetryIntegrity};
use anyhow::Result;
use std::collections::BTreeMap;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().any(|arg| arg == "--diagnose") {
        let config = AppConfig::default();
        let health = HealthReporter::build_snapshot(
            "0.1.0",
            &format!("bundle-{}", config.policy_version.policy_bundle),
            &format!("ruleset-{}", config.policy_version.ruleset_revision),
            &format!("model-{}", config.policy_version.model_revision),
            2.5,
            128,
            BTreeMap::from([("event".to_string(), 0usize)]),
            LineageCounters::default(),
        );
        let bundle = DiagnoseCollector::collect(
            config.control_plane_url.clone(),
            true,
            DiagnoseCertificateStatus {
                device_certificate_loaded: true,
                last_rotation_succeeded: true,
            },
            DiagnoseSensorStatus {
                enabled_sensors: vec![
                    "process".to_string(),
                    "file".to_string(),
                    "network".to_string(),
                ],
                unhealthy_sensors: vec![],
            },
            BTreeMap::from([
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
            0.0,
            DiagnoseWalStatus {
                telemetry_segments: 0,
                forensic_root: config.storage.forensic_path.clone(),
                completeness: TelemetryIntegrity::Full,
            },
            health,
            ProtectionPosture::Normal,
        );
        println!("{}", DiagnoseCollector::to_json(&bundle)?);
        return Ok(());
    }

    tracing_subscriber::fmt().with_env_filter("info").init();

    let config = AppConfig::default();
    let shutdown_grace_period = config.shutdown_grace_period();
    let orchestrator = Orchestrator::new(config);
    let artifacts = orchestrator.bootstrap()?;
    let summary = &artifacts.summary;

    info!(
        agent_id = %summary.agent_id,
        tenant_id = %summary.tenant_id,
        control_plane_url = %summary.control_plane_url,
        tasks = ?summary.task_topology,
        "aegis-agentd runtime skeleton bootstrapped"
    );

    let runtime = orchestrator.start(artifacts);
    tokio::signal::ctrl_c().await?;
    let stopped_tasks = runtime.graceful_shutdown(shutdown_grace_period).await?;

    info!(tasks = ?stopped_tasks, "aegis-agentd runtime stopped");

    Ok(())
}
