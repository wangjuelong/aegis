use anyhow::Result;
use tracing::info;

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    info!("aegis-watchdog skeleton started");
    Ok(())
}
