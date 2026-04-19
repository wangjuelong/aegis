use aegis_core::upgrade::HotUpdateManifestVerifier;
use aegis_model::HotUpdateManifest;
use anyhow::Result;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use tracing::info;

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let artifact = b"aegis-agent-binary";
    let rollback = b"aegis-agent-binary-prev";
    let signing_key = SigningKey::from_bytes(&[21u8; 32]);
    let mut manifest = HotUpdateManifest {
        artifact_id: "artifact-42".to_string(),
        target_version: "1.2.3".to_string(),
        rollout_channel: "canary".to_string(),
        target_conf_version: 2,
        target_schema_version: 3,
        artifact_sha256: sha256_hex(artifact),
        rollback_artifact_id: Some("artifact-41".to_string()),
        rollback_artifact_sha256: Some(sha256_hex(rollback)),
        signature: Vec::new(),
        signing_key_id: "server-k1".to_string(),
    };
    manifest.signature = signing_key
        .sign(&HotUpdateManifestVerifier::canonical_payload(&manifest))
        .to_bytes()
        .to_vec();

    let mut verifier = HotUpdateManifestVerifier::new();
    verifier.register_signing_key("server-k1", signing_key.verifying_key().to_bytes())?;
    verifier.verify_manifest(&manifest, artifact, Some(rollback))?;

    info!(
        artifact_id = %manifest.artifact_id,
        target_version = %manifest.target_version,
        "aegis-updater verified signed manifest"
    );
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
