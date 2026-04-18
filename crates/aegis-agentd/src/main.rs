use aegis_core::config::AppConfig;
use aegis_core::orchestrator::Orchestrator;
use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
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
