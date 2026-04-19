use aegis_core::config::AppConfig;
use aegis_core::upgrade::{
    default_update_manifest_verifier, RuntimeStateStore, UpdatePhase, UpdateVerificationSnapshot,
};
use aegis_model::HotUpdateManifest;
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

#[derive(Default)]
struct CliArgs {
    manifest: Option<PathBuf>,
    artifact: Option<PathBuf>,
    rollback: Option<PathBuf>,
    state_root: Option<PathBuf>,
}

struct StagedUpdateFiles {
    manifest: HotUpdateManifest,
    manifest_path: PathBuf,
    artifact_path: PathBuf,
    artifact_bytes: Vec<u8>,
    rollback_path: Option<PathBuf>,
    rollback_bytes: Option<Vec<u8>>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args = parse_args()?;
    let config = load_runtime_config(args.state_root.clone())?;
    let now_ms = now_unix_ms();
    let base_snapshot = load_update_snapshot(&config, now_ms);
    let staged = resolve_staged_update(&config, &args, &base_snapshot)?;

    let mut verifying_snapshot = base_snapshot.clone();
    verifying_snapshot.updated_at_ms = now_ms;
    verifying_snapshot.current_version = current_agent_version().to_string();
    verifying_snapshot.phase = UpdatePhase::Verifying;
    verifying_snapshot.manifest = Some(staged.manifest.clone());
    verifying_snapshot.manifest_path = Some(staged.manifest_path.clone());
    verifying_snapshot.artifact_path = Some(staged.artifact_path.clone());
    verifying_snapshot.rollback_path = staged.rollback_path.clone();
    verifying_snapshot.last_attempt_at_ms = Some(now_ms);
    verifying_snapshot.last_error = None;
    RuntimeStateStore::persist_update_snapshot(&config, &verifying_snapshot)?;

    let verifier = default_update_manifest_verifier()?;
    if let Err(error) = verifier.verify_manifest(
        &staged.manifest,
        &staged.artifact_bytes,
        staged.rollback_bytes.as_deref(),
    ) {
        let mut rejected_snapshot = verifying_snapshot;
        rejected_snapshot.updated_at_ms = now_unix_ms();
        rejected_snapshot.phase = UpdatePhase::Rejected;
        rejected_snapshot.retry_count = rejected_snapshot.retry_count.saturating_add(1);
        rejected_snapshot.last_error = Some(error.to_string());
        RuntimeStateStore::persist_update_snapshot(&config, &rejected_snapshot).ok();
        return Err(error);
    }

    let mut ready_snapshot = verifying_snapshot;
    ready_snapshot.updated_at_ms = now_unix_ms();
    ready_snapshot.phase = UpdatePhase::Ready;
    ready_snapshot.last_success_at_ms = Some(ready_snapshot.updated_at_ms);
    RuntimeStateStore::persist_update_snapshot(&config, &ready_snapshot)?;
    println!("{}", serde_json::to_string_pretty(&ready_snapshot)?);
    info!(
        artifact_id = %ready_snapshot.active_update_id().unwrap_or_else(|| "<none>".to_string()),
        target_version = %ready_snapshot
            .manifest
            .as_ref()
            .map(|manifest| manifest.target_version.as_str())
            .unwrap_or("<unknown>"),
        state_root = %config.storage.state_root.display(),
        "aegis-updater verified staged update"
    );
    Ok(())
}

fn parse_args() -> Result<CliArgs> {
    let mut args = CliArgs::default();
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--once" => {}
            "--manifest" => args.manifest = Some(PathBuf::from(next_arg(&mut iter, "--manifest")?)),
            "--artifact" => args.artifact = Some(PathBuf::from(next_arg(&mut iter, "--artifact")?)),
            "--rollback" => args.rollback = Some(PathBuf::from(next_arg(&mut iter, "--rollback")?)),
            "--state-root" => {
                args.state_root = Some(PathBuf::from(next_arg(&mut iter, "--state-root")?))
            }
            other => bail!("unsupported argument: {other}"),
        }
    }
    Ok(args)
}

fn next_arg(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    iter.next()
        .with_context(|| format!("missing value for {flag}"))
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

fn current_agent_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn load_manifest(path: &Path) -> Result<HotUpdateManifest> {
    let raw = fs::read(path).with_context(|| format!("read update manifest {}", path.display()))?;
    Ok(serde_json::from_slice(&raw)?)
}

fn load_update_snapshot(config: &AppConfig, now_ms: i64) -> UpdateVerificationSnapshot {
    let mut snapshot = RuntimeStateStore::load_update_snapshot(config)
        .unwrap_or_else(|_| UpdateVerificationSnapshot::new(current_agent_version(), now_ms));
    if snapshot.current_version.is_empty() {
        snapshot.current_version = current_agent_version().to_string();
    }
    snapshot
}

fn resolve_staged_update(
    config: &AppConfig,
    args: &CliArgs,
    snapshot: &UpdateVerificationSnapshot,
) -> Result<StagedUpdateFiles> {
    let manifest_path = args
        .manifest
        .clone()
        .or_else(|| snapshot.manifest_path.clone())
        .unwrap_or_else(|| RuntimeStateStore::staged_update_manifest_path(config));
    let manifest = if args.manifest.is_some() || manifest_path.exists() {
        load_manifest(&manifest_path)?
    } else {
        snapshot
            .manifest
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no staged update manifest is available"))?
    };

    if args.manifest.is_none()
        && !matches!(snapshot.phase, UpdatePhase::Ready | UpdatePhase::Verifying)
    {
        bail!(
            "update state is not ready for verification: phase={:?} error={}",
            snapshot.phase,
            snapshot.last_error.as_deref().unwrap_or("<none>")
        );
    }

    let artifact_path = args
        .artifact
        .clone()
        .or_else(|| snapshot.artifact_path.clone())
        .unwrap_or_else(|| RuntimeStateStore::staged_update_artifact_path(config));
    let artifact_bytes = fs::read(&artifact_path)
        .with_context(|| format!("read update artifact {}", artifact_path.display()))?;

    let rollback_path = args
        .rollback
        .clone()
        .or_else(|| snapshot.rollback_path.clone());
    let rollback_bytes = rollback_path
        .as_ref()
        .map(|path| {
            fs::read(path).with_context(|| format!("read rollback artifact {}", path.display()))
        })
        .transpose()?;

    if manifest.rollback_artifact_id.is_some() && rollback_bytes.is_none() {
        bail!("missing rollback artifact payload for staged update");
    }

    Ok(StagedUpdateFiles {
        manifest,
        manifest_path,
        artifact_path,
        artifact_bytes,
        rollback_path,
        rollback_bytes,
    })
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as i64
}
