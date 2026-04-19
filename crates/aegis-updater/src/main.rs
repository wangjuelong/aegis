use aegis_core::config::AppConfig;
use aegis_core::upgrade::{
    HotUpdateManifestVerifier, RuntimeStateStore, UpdateVerificationSnapshot,
};
use aegis_model::HotUpdateManifest;
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

const DEV_UPDATE_SIGNING_KEY: [u8; 32] = [21u8; 32];
const DEV_UPDATE_SIGNING_KEY_ID: &str = "server-k1";

#[derive(Default)]
struct CliArgs {
    manifest: Option<PathBuf>,
    artifact: Option<PathBuf>,
    rollback: Option<PathBuf>,
    state_root: Option<PathBuf>,
}

struct StagedUpdateFiles {
    manifest_path: PathBuf,
    artifact_path: PathBuf,
    rollback_path: Option<PathBuf>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args = parse_args()?;
    let config = load_runtime_config(args.state_root)?;
    let staged = ensure_staged_update(&config)?;

    let manifest_path = args.manifest.unwrap_or(staged.manifest_path);
    let manifest = load_manifest(&manifest_path)?;
    let artifact_path = args.artifact.unwrap_or(staged.artifact_path);
    let artifact_bytes = fs::read(&artifact_path)
        .with_context(|| format!("read update artifact {}", artifact_path.display()))?;
    let rollback_path = args.rollback.or_else(|| {
        manifest
            .rollback_artifact_id
            .as_ref()
            .and(staged.rollback_path.clone())
    });
    let rollback_bytes = rollback_path
        .as_ref()
        .map(|path| {
            fs::read(path).with_context(|| format!("read rollback artifact {}", path.display()))
        })
        .transpose()?;

    let signing_key = SigningKey::from_bytes(&DEV_UPDATE_SIGNING_KEY);
    let mut verifier = HotUpdateManifestVerifier::new();
    verifier.register_signing_key(
        DEV_UPDATE_SIGNING_KEY_ID,
        signing_key.verifying_key().to_bytes(),
    )?;
    verifier.verify_manifest(&manifest, &artifact_bytes, rollback_bytes.as_deref())?;

    let snapshot = UpdateVerificationSnapshot {
        verified_at_ms: now_unix_ms(),
        manifest,
        artifact_path,
        rollback_path,
    };
    RuntimeStateStore::persist_update_snapshot(&config, &snapshot)?;
    println!("{}", serde_json::to_string_pretty(&snapshot)?);
    info!(
        artifact_id = %snapshot.manifest.artifact_id,
        target_version = %snapshot.manifest.target_version,
        state_root = %config.storage.state_root.display(),
        "aegis-updater verified signed manifest"
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

fn ensure_staged_update(config: &AppConfig) -> Result<StagedUpdateFiles> {
    let manifest_path = RuntimeStateStore::staged_update_manifest_path(config);
    let artifact_path = RuntimeStateStore::staged_update_artifact_path(config);
    let rollback_path = RuntimeStateStore::staged_update_rollback_path(config);
    if manifest_path.exists() && artifact_path.exists() {
        let rollback = if rollback_path.exists() {
            Some(rollback_path)
        } else {
            None
        };
        return Ok(StagedUpdateFiles {
            manifest_path,
            artifact_path,
            rollback_path: rollback,
        });
    }

    let artifact = b"aegis-agent-binary";
    let rollback = b"aegis-agent-binary-prev";
    if let Some(parent) = artifact_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&artifact_path, artifact)?;
    fs::write(&rollback_path, rollback)?;

    let signing_key = SigningKey::from_bytes(&DEV_UPDATE_SIGNING_KEY);
    let mut manifest = HotUpdateManifest {
        artifact_id: "artifact-42".to_string(),
        target_version: "1.2.3".to_string(),
        rollout_channel: "canary".to_string(),
        target_conf_version: 1,
        target_schema_version: 1,
        artifact_sha256: sha256_hex(artifact),
        rollback_artifact_id: Some("artifact-41".to_string()),
        rollback_artifact_sha256: Some(sha256_hex(rollback)),
        signature: Vec::new(),
        signing_key_id: DEV_UPDATE_SIGNING_KEY_ID.to_string(),
    };
    manifest.signature = signing_key
        .sign(&HotUpdateManifestVerifier::canonical_payload(&manifest))
        .to_bytes()
        .to_vec();
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;

    Ok(StagedUpdateFiles {
        manifest_path,
        artifact_path,
        rollback_path: Some(rollback_path),
    })
}

fn load_manifest(path: &Path) -> Result<HotUpdateManifest> {
    let raw = fs::read(path).with_context(|| format!("read update manifest {}", path.display()))?;
    Ok(serde_json::from_slice(&raw)?)
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as i64
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
