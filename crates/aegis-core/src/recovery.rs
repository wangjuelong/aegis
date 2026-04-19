use aegis_model::{ArtifactBundle, ForensicSpec, RollbackTarget};
use aegis_platform::PlatformRuntime;
use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryRollbackPlan {
    pub target: RollbackTarget,
    pub backup_blob: String,
}

pub struct RegistryRollbackPlanner;

impl RegistryRollbackPlanner {
    pub fn plan(
        selector: impl Into<String>,
        backup_blob: impl Into<String>,
    ) -> RegistryRollbackPlan {
        RegistryRollbackPlan {
            target: RollbackTarget {
                selector: selector.into(),
            },
            backup_blob: backup_blob.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemRollbackPlan {
    pub original_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub snapshot_sha256: String,
    pub snapshot_bytes: u64,
    pub created_at_ns: u64,
    pub manifest_sha256: String,
}

pub struct FilesystemRollbackPlanner;

impl FilesystemRollbackPlanner {
    pub fn plan(original_path: PathBuf, snapshot_path: PathBuf) -> Result<FilesystemRollbackPlan> {
        let snapshot_bytes = fs::metadata(&snapshot_path)?.len();
        let created_at_ns = now_unix_ns();
        let snapshot_sha256 = hash_path(&snapshot_path)?;
        let manifest_sha256 = hash_bytes(
            format!(
                "{}|{}|{}|{}|{}",
                original_path.display(),
                snapshot_path.display(),
                snapshot_sha256,
                snapshot_bytes,
                created_at_ns
            )
            .as_bytes(),
        );
        Ok(FilesystemRollbackPlan {
            original_path,
            snapshot_sha256,
            snapshot_path,
            snapshot_bytes,
            created_at_ns,
            manifest_sha256,
        })
    }

    pub fn restore(plan: &FilesystemRollbackPlan) -> Result<()> {
        let current_bytes = fs::metadata(&plan.snapshot_path)?.len();
        if current_bytes != plan.snapshot_bytes {
            return Err(anyhow!("snapshot size mismatch"));
        }
        let current_hash = hash_path(&plan.snapshot_path)?;
        if current_hash != plan.snapshot_sha256 {
            return Err(anyhow!("snapshot integrity mismatch"));
        }
        let expected_manifest = hash_bytes(
            format!(
                "{}|{}|{}|{}|{}",
                plan.original_path.display(),
                plan.snapshot_path.display(),
                plan.snapshot_sha256,
                plan.snapshot_bytes,
                plan.created_at_ns
            )
            .as_bytes(),
        );
        if expected_manifest != plan.manifest_sha256 {
            return Err(anyhow!("rollback manifest mismatch"));
        }

        let temp_target = plan.original_path.with_extension("rollback.tmp");
        fs::copy(&plan.snapshot_path, &temp_target)?;
        fs::rename(temp_target, &plan.original_path)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceEntry {
    pub artifact_id: Uuid,
    pub location: PathBuf,
    pub sha256: String,
    pub captured_at_ns: u64,
    pub previous_hash: Option<String>,
    pub chain_hash: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EvidenceChain {
    pub entries: Vec<EvidenceEntry>,
}

impl EvidenceChain {
    pub fn append(&mut self, bundle: &ArtifactBundle) -> Result<EvidenceEntry> {
        let captured_at_ns = now_unix_ns();
        let sha256 = hash_bundle(bundle)?;
        let previous_hash = self.entries.last().map(|entry| entry.chain_hash.clone());
        let chain_hash = chain_hash(
            bundle.artifact_id,
            &sha256,
            captured_at_ns,
            previous_hash.as_deref(),
        );
        let entry = EvidenceEntry {
            artifact_id: bundle.artifact_id,
            location: bundle.location.clone(),
            sha256,
            captured_at_ns,
            previous_hash,
            chain_hash,
        };
        self.entries.push(entry.clone());
        Ok(entry)
    }

    pub fn verify(&self) -> bool {
        let mut previous_hash: Option<String> = None;
        for entry in &self.entries {
            let actual_sha256 = match hash_path(&entry.location) {
                Ok(hash) => hash,
                Err(_) => return false,
            };
            if actual_sha256 != entry.sha256 {
                return false;
            }
            let expected = chain_hash(
                entry.artifact_id,
                &entry.sha256,
                entry.captured_at_ns,
                previous_hash.as_deref(),
            );
            if expected != entry.chain_hash {
                return false;
            }
            previous_hash = Some(entry.chain_hash.clone());
        }
        true
    }
}

pub struct RecoveryCoordinator<'a, P: PlatformRuntime> {
    platform: &'a P,
}

impl<'a, P: PlatformRuntime> RecoveryCoordinator<'a, P> {
    pub fn new(platform: &'a P) -> Self {
        Self { platform }
    }

    pub fn execute_registry_rollback(&self, plan: &RegistryRollbackPlan) -> Result<()> {
        self.platform.registry_rollback(&plan.target)
    }

    pub fn collect_forensics(
        &self,
        spec: &ForensicSpec,
        chain: &mut EvidenceChain,
    ) -> Result<EvidenceEntry> {
        let bundle = self.platform.collect_forensics(spec)?;
        chain.append(&bundle)
    }
}

fn hash_path(path: &Path) -> Result<String> {
    let bytes = fs::read(path)?;
    Ok(hash_bytes(&bytes))
}

fn hash_bundle(bundle: &ArtifactBundle) -> Result<String> {
    match fs::read(&bundle.location) {
        Ok(bytes) => Ok(hash_bytes(&bytes)),
        Err(_) => Ok(hash_bytes(bundle.location.display().to_string().as_bytes())),
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn chain_hash(
    artifact_id: Uuid,
    sha256: &str,
    captured_at_ns: u64,
    previous_hash: Option<&str>,
) -> String {
    hash_bytes(
        format!(
            "{}|{}|{}|{}",
            artifact_id,
            sha256,
            captured_at_ns,
            previous_hash.unwrap_or("root")
        )
        .as_bytes(),
    )
}

fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::{
        EvidenceChain, FilesystemRollbackPlanner, RecoveryCoordinator, RegistryRollbackPlanner,
    };
    use aegis_model::{ArtifactBundle, ForensicSpec};
    use aegis_platform::{LinuxPlatform, MockAction, MockPlatform};
    use std::fs;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn temp_file(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("aegis-{name}-{}", Uuid::now_v7()))
    }

    #[test]
    fn recovery_coordinator_executes_registry_rollback_plan() {
        let platform = MockPlatform::windows();
        let coordinator = RecoveryCoordinator::new(&platform);
        let plan = RegistryRollbackPlanner::plan("HKCU\\Software\\Aegis", "{\"enabled\":true}");

        coordinator
            .execute_registry_rollback(&plan)
            .expect("registry rollback");

        let actions = platform.take_actions();
        assert_eq!(
            actions,
            vec![MockAction::RegistryRollback(
                "HKCU\\Software\\Aegis".to_string()
            )]
        );
    }

    #[test]
    fn recovery_coordinator_updates_linux_platform_snapshot() {
        let platform = LinuxPlatform::default();
        let coordinator = RecoveryCoordinator::new(&platform);
        let plan = RegistryRollbackPlanner::plan("iptables", "{\"policy\":\"drop\"}");
        let mut chain = EvidenceChain::default();

        coordinator
            .execute_registry_rollback(&plan)
            .expect("registry rollback should be recorded");
        coordinator
            .collect_forensics(
                &ForensicSpec {
                    include_memory: true,
                    include_registry: false,
                    include_network: true,
                },
                &mut chain,
            )
            .expect("forensics should be collected");

        let snapshot = platform.execution_snapshot();
        assert_eq!(snapshot.rollback_targets[0].selector, "iptables");
        assert_eq!(snapshot.forensic_artifacts.len(), 1);
        assert!(snapshot.forensic_artifacts[0].location.exists());
        assert_eq!(chain.entries.len(), 1);
    }

    #[test]
    fn filesystem_rollback_restores_snapshot_contents() {
        let original = temp_file("original");
        let snapshot = temp_file("snapshot");
        fs::write(&original, "mutated").expect("write original");
        fs::write(&snapshot, "known-good").expect("write snapshot");

        let plan =
            FilesystemRollbackPlanner::plan(original.clone(), snapshot.clone()).expect("plan fs");
        FilesystemRollbackPlanner::restore(&plan).expect("restore fs");

        assert_eq!(
            fs::read_to_string(&original).expect("read original"),
            "known-good"
        );
    }

    #[test]
    fn filesystem_rollback_rejects_tampered_snapshot() {
        let original = temp_file("original-tampered");
        let snapshot = temp_file("snapshot-tampered");
        fs::write(&original, "mutated").expect("write original");
        fs::write(&snapshot, "known-good").expect("write snapshot");

        let plan =
            FilesystemRollbackPlanner::plan(original.clone(), snapshot.clone()).expect("plan fs");
        fs::write(&snapshot, "tampered-after-plan").expect("tamper snapshot");

        let restore = FilesystemRollbackPlanner::restore(&plan);

        assert!(restore.is_err());
    }

    #[test]
    fn evidence_chain_appends_and_verifies_artifact_history() {
        let bundle_a = ArtifactBundle {
            artifact_id: Uuid::now_v7(),
            location: temp_file("artifact-a"),
        };
        let bundle_b = ArtifactBundle {
            artifact_id: Uuid::now_v7(),
            location: temp_file("artifact-b"),
        };
        fs::write(&bundle_a.location, "artifact-a").expect("write artifact a");
        fs::write(&bundle_b.location, "artifact-b").expect("write artifact b");

        let mut chain = EvidenceChain::default();
        chain.append(&bundle_a).expect("append a");
        chain.append(&bundle_b).expect("append b");

        assert_eq!(chain.entries.len(), 2);
        assert!(chain.verify());
    }

    #[test]
    fn evidence_chain_detects_artifact_tampering() {
        let bundle = ArtifactBundle {
            artifact_id: Uuid::now_v7(),
            location: temp_file("artifact-tampered"),
        };
        fs::write(&bundle.location, "artifact-a").expect("write artifact");

        let mut chain = EvidenceChain::default();
        chain.append(&bundle).expect("append artifact");
        fs::write(&bundle.location, "artifact-a-modified").expect("tamper artifact");

        assert!(!chain.verify());
    }

    #[test]
    fn recovery_coordinator_collects_forensics_into_evidence_chain() {
        let platform = MockPlatform::linux();
        let coordinator = RecoveryCoordinator::new(&platform);
        let mut chain = EvidenceChain::default();

        let entry = coordinator
            .collect_forensics(
                &ForensicSpec {
                    include_memory: true,
                    include_registry: false,
                    include_network: true,
                },
                &mut chain,
            )
            .expect("collect forensics");

        let actions = platform.take_actions();
        assert_eq!(actions, vec![MockAction::CollectForensics]);
        assert_eq!(chain.entries.len(), 1);
        assert_eq!(entry.artifact_id, chain.entries[0].artifact_id);
    }
}
