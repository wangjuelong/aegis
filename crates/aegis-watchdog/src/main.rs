use aegis_core::upgrade::WatchdogLinkMonitor;
use aegis_model::{AgentSupervisorHeartbeat, WatchdogHeartbeat};
use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;
use tracing::warn;

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let now_ms = now_unix_ms();
    let mut monitor = WatchdogLinkMonitor::new(5_000);
    monitor.observe_agent(AgentSupervisorHeartbeat {
        tenant_id: "local-tenant".to_string(),
        agent_id: "local-agent".to_string(),
        plugin_count: 0,
        degraded_plugins: 0,
        active_update_id: None,
        sent_at_ms: now_ms,
    });
    monitor.observe_watchdog(WatchdogHeartbeat {
        tenant_id: "local-tenant".to_string(),
        agent_id: "local-agent".to_string(),
        watchdog_id: "watchdog-local".to_string(),
        observed_agent_restart_epoch: 0,
        unhealthy_plugins: 0,
        sent_at_ms: now_ms,
    });
    let alerts = monitor.evaluate(now_ms);
    if alerts.is_empty() {
        info!("aegis-watchdog runtime ready");
    } else {
        warn!(?alerts, "aegis-watchdog detected stale heartbeat");
    }
    Ok(())
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as i64
}
