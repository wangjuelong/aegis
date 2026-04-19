use aegis_core::config::AppConfig;
use aegis_core::upgrade::WatchdogLinkMonitor;
use aegis_core::upgrade::{RuntimeStateStore, WatchdogRuntimeSnapshot};
use aegis_model::WatchdogHeartbeat;
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;
use tracing::warn;

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let config = load_runtime_config()?;
    let agent_snapshot = RuntimeStateStore::load_agent_snapshot(&config)?;
    let now_ms = now_unix_ms();
    let mut monitor = WatchdogLinkMonitor::new(5_000);
    monitor.observe_agent(agent_snapshot.supervisor_heartbeat.clone());
    let watchdog_heartbeat = WatchdogHeartbeat {
        tenant_id: agent_snapshot.supervisor_heartbeat.tenant_id.clone(),
        agent_id: agent_snapshot.supervisor_heartbeat.agent_id.clone(),
        watchdog_id: "watchdog-local".to_string(),
        observed_agent_restart_epoch: 0,
        unhealthy_plugins: agent_snapshot.supervisor_heartbeat.degraded_plugins,
        sent_at_ms: now_ms,
    };
    monitor.observe_watchdog(watchdog_heartbeat.clone());
    let alerts = monitor.evaluate(now_ms);
    let snapshot = WatchdogRuntimeSnapshot {
        observed_at_ms: now_ms,
        agent_heartbeat: agent_snapshot.supervisor_heartbeat,
        watchdog_heartbeat,
        alerts: alerts.clone(),
    };
    RuntimeStateStore::persist_watchdog_snapshot(&config, &snapshot)?;
    println!("{snapshot:#?}");
    if alerts.is_empty() {
        info!("aegis-watchdog runtime ready");
    } else {
        warn!(?alerts, "aegis-watchdog detected stale heartbeat");
    }
    Ok(())
}

fn load_runtime_config() -> Result<AppConfig> {
    let config = AppConfig::default();
    if let Ok(state_root) = std::env::var("AEGIS_STATE_ROOT") {
        return Ok(config.with_state_root(PathBuf::from(state_root)));
    }
    if state_root_writable(&config.storage.state_root) {
        return Ok(config);
    }
    Ok(config.with_state_root(std::env::current_dir()?.join("target/aegis-dev/state")))
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
