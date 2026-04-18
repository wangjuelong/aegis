use aegis_core::config::AppConfig;
use aegis_core::orchestrator::Orchestrator;
use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let orchestrator = Orchestrator::new(AppConfig::default());
    let (_channels, summary) = orchestrator.bootstrap()?;

    info!(
        agent_id = %summary.agent_id,
        tenant_id = %summary.tenant_id,
        "aegis-agentd runtime skeleton bootstrapped"
    );

    Ok(())
}

