use aegis_core::config::AppConfig;
use aegis_core::upgrade::{
    RuntimeStateStore, UpdatePhase, WatchdogLinkMonitor, WatchdogRuntimeSnapshot,
};
use aegis_model::WatchdogHeartbeat;
use anyhow::{bail, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

const DEFAULT_GRACE_PERIOD_MS: i64 = 5_000;
const DEFAULT_MONITOR_INTERVAL_MS: u64 = 2_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum WatchdogMode {
    #[default]
    Once,
    Monitor,
}

#[derive(Clone, Debug)]
struct CliArgs {
    mode: WatchdogMode,
    state_root: Option<PathBuf>,
    interval_ms: u64,
    grace_period_ms: i64,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            mode: WatchdogMode::Once,
            state_root: None,
            interval_ms: DEFAULT_MONITOR_INTERVAL_MS,
            grace_period_ms: DEFAULT_GRACE_PERIOD_MS,
        }
    }
}

fn main() -> Result<()> {
    let args = parse_args()?;
    if args.mode == WatchdogMode::Monitor {
        tracing_subscriber::fmt().with_env_filter("info").init();
    }
    let config = load_runtime_config(args.state_root.clone())?;

    match args.mode {
        WatchdogMode::Once => {
            let snapshot = collect_watchdog_snapshot(&config, args.grace_period_ms, false)?;
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
            if !snapshot.bootstrap_passed {
                bail!("bootstrap report is missing or not approved");
            }
            if !snapshot.alerts.is_empty() {
                bail!("watchdog detected stale runtime heartbeat");
            }
            info!("aegis-watchdog one-shot verification passed");
        }
        WatchdogMode::Monitor => loop {
            let snapshot = collect_watchdog_snapshot(&config, args.grace_period_ms, true)?;
            if snapshot.bootstrap_passed && snapshot.alerts.is_empty() {
                info!(
                    observed_at_ms = snapshot.observed_at_ms,
                    update_phase = ?snapshot.update_phase,
                    rollback_ready = snapshot.rollback_ready,
                    "aegis-watchdog monitor tick healthy"
                );
            } else {
                warn!(
                    observed_at_ms = snapshot.observed_at_ms,
                    bootstrap_passed = snapshot.bootstrap_passed,
                    alerts = ?snapshot.alerts,
                    update_phase = ?snapshot.update_phase,
                    rollback_ready = snapshot.rollback_ready,
                    "aegis-watchdog monitor detected degraded state"
                );
            }
            thread::sleep(Duration::from_millis(args.interval_ms.max(250)));
        },
    }

    Ok(())
}

fn parse_args() -> Result<CliArgs> {
    let mut args = CliArgs::default();
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--once" => set_mode(&mut args.mode, WatchdogMode::Once)?,
            "--monitor" => set_mode(&mut args.mode, WatchdogMode::Monitor)?,
            "--state-root" => {
                args.state_root = Some(PathBuf::from(next_arg(&mut iter, "--state-root")?))
            }
            "--interval-ms" => {
                args.interval_ms = next_arg(&mut iter, "--interval-ms")?.parse()?;
            }
            "--grace-period-ms" => {
                args.grace_period_ms = next_arg(&mut iter, "--grace-period-ms")?.parse()?;
            }
            other => bail!("unsupported argument: {other}"),
        }
    }
    Ok(args)
}

fn set_mode(target: &mut WatchdogMode, next: WatchdogMode) -> Result<()> {
    if *target != WatchdogMode::Once && *target != next {
        bail!("multiple watchdog modes requested");
    }
    *target = next;
    Ok(())
}

fn next_arg(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    iter.next()
        .ok_or_else(|| anyhow::anyhow!("missing value for {flag}"))
}

fn collect_watchdog_snapshot(
    config: &AppConfig,
    grace_period_ms: i64,
    include_previous_watchdog: bool,
) -> Result<WatchdogRuntimeSnapshot> {
    let agent_snapshot = RuntimeStateStore::load_agent_snapshot(config)?;
    let previous_watchdog = RuntimeStateStore::load_watchdog_snapshot(config).ok();
    let bootstrap_report = RuntimeStateStore::load_bootstrap_report(config).ok();
    let update_snapshot = RuntimeStateStore::load_update_snapshot(config).ok();
    let now_ms = now_unix_ms();

    let mut monitor = WatchdogLinkMonitor::new(grace_period_ms);
    monitor.observe_agent(agent_snapshot.supervisor_heartbeat.clone());
    if include_previous_watchdog {
        if let Some(previous_watchdog) = &previous_watchdog {
            monitor.observe_watchdog(previous_watchdog.watchdog_heartbeat.clone());
        }
    }

    let watchdog_heartbeat = WatchdogHeartbeat {
        tenant_id: agent_snapshot.supervisor_heartbeat.tenant_id.clone(),
        agent_id: agent_snapshot.supervisor_heartbeat.agent_id.clone(),
        watchdog_id: "watchdog-local".to_string(),
        observed_agent_restart_epoch: 0,
        unhealthy_plugins: agent_snapshot.supervisor_heartbeat.degraded_plugins,
        sent_at_ms: now_ms,
    };
    let alerts = monitor.evaluate(now_ms);
    let snapshot = WatchdogRuntimeSnapshot {
        observed_at_ms: now_ms,
        agent_heartbeat: agent_snapshot.supervisor_heartbeat,
        watchdog_heartbeat,
        alerts,
        bootstrap_passed: bootstrap_report
            .as_ref()
            .map(|report| report.approved)
            .unwrap_or(false),
        bootstrap_report,
        update_phase: update_snapshot
            .as_ref()
            .map(|snapshot| snapshot.phase)
            .unwrap_or(UpdatePhase::Idle),
        rollback_ready: update_snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.rollback_path.as_ref())
            .is_some(),
    };
    RuntimeStateStore::persist_watchdog_snapshot(config, &snapshot)?;
    Ok(snapshot)
}

fn load_runtime_config(explicit_state_root: Option<PathBuf>) -> Result<AppConfig> {
    let config = AppConfig::default();
    if let Some(state_root) = explicit_state_root {
        return Ok(config.with_state_root(state_root));
    }
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
