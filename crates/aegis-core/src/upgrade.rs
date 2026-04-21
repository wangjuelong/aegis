use crate::comms::{RollbackProtectionAnchor, RollbackProtectionStatus};
use crate::config::{AgentConfig, CURRENT_CONF_VERSION};
use crate::migrations::{CURRENT_SCHEMA_VERSION, MIN_READER_SCHEMA_VERSION};
use crate::self_protection::{KeyProtectionStatus, KeyProtectionTier, ProtectionPosture};
use aegis_model::{
    AgentHealth, AgentSupervisorHeartbeat, CommunicationChannelKind, CommunicationRuntimeStatus,
    HotUpdateManifest, PluginHealthStatus, RuntimeBridgeStatus, RuntimeHealthSignals,
    TelemetryIntegrity, UpdateChunk, WatchdogAlert, WatchdogAlertKind, WatchdogHeartbeat,
};
use anyhow::{bail, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

pub const UPDATE_MANIFEST_KIND: &str = "manifest";
pub const UPDATE_ARTIFACT_KIND: &str = "artifact";
pub const UPDATE_ROLLBACK_KIND: &str = "rollback";
pub const DEVELOPMENT_UPDATE_SIGNING_KEY_ID: &str = "update-k1";
pub const DEVELOPMENT_UPDATE_SIGNING_KEY_BYTES: [u8; 32] = [21u8; 32];
pub const WINDOWS_INSTALL_MANIFEST_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpgradeArtifact {
    pub artifact_id: String,
    pub target_version: String,
    pub rollout_channel: String,
    pub target_conf_version: u32,
    pub target_schema_version: i64,
    pub rollback_artifact_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradePlan {
    pub artifact: UpgradeArtifact,
    pub requires_schema_migration: bool,
    pub requires_config_sync: bool,
    pub rollback_required: bool,
    pub steps: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum UpdatePhase {
    #[default]
    Idle,
    Announced,
    Downloading,
    Verifying,
    Ready,
    Rejected,
    Failed,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnoseUpdateStatus {
    pub phase: UpdatePhase,
    pub current_version: String,
    pub pending_update_ids: Vec<String>,
    pub config_changed: bool,
    pub transport_channel: Option<CommunicationChannelKind>,
    pub target_artifact_id: Option<String>,
    pub target_version: Option<String>,
    pub rollback_required: bool,
    pub staged_manifest_path: Option<PathBuf>,
    pub staged_artifact_path: Option<PathBuf>,
    pub staged_rollback_path: Option<PathBuf>,
    pub retry_count: u32,
    pub last_attempt_at_ms: Option<i64>,
    pub last_success_at_ms: Option<i64>,
    pub last_error: Option<String>,
}

pub struct UpgradePlanner;

impl UpgradePlanner {
    pub fn build_plan(config: &AgentConfig, artifact: UpgradeArtifact) -> Result<UpgradePlan> {
        if artifact.target_conf_version < config.compatibility.min_supported {
            bail!("target config version is below the local minimum supported range");
        }
        if artifact.target_schema_version < MIN_READER_SCHEMA_VERSION {
            bail!("target schema version is below the local minimum reader version");
        }

        let requires_schema_migration = artifact.target_schema_version > CURRENT_SCHEMA_VERSION;
        let requires_config_sync = artifact.target_conf_version > CURRENT_CONF_VERSION
            || artifact.target_conf_version != config.conf_version;
        let rollback_required = artifact.rollback_artifact_id.is_some();

        let mut steps = vec![
            format!("download artifact {}", artifact.artifact_id),
            "backup current agent binary and config snapshot".to_string(),
        ];
        if requires_schema_migration {
            steps.push(format!(
                "apply schema migration to version {}",
                artifact.target_schema_version
            ));
        }
        if requires_config_sync {
            steps.push(format!(
                "sync active config to conf_version {}",
                artifact.target_conf_version
            ));
        }
        steps.push(format!(
            "canary rollout target version {} on channel {}",
            artifact.target_version, artifact.rollout_channel
        ));
        if rollback_required {
            steps.push("retain rollback metadata for auto-revert".to_string());
        }

        Ok(UpgradePlan {
            artifact,
            requires_schema_migration,
            requires_config_sync,
            rollback_required,
            steps,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanaryObservation {
    pub health: AgentHealth,
    pub wal_utilization_ratio: f32,
    pub self_protection_posture: ProtectionPosture,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanaryGateThresholds {
    pub max_cpu_percent_p95: f32,
    pub max_memory_rss_mb: u64,
    pub max_dropped_events_total: u64,
    pub max_wal_utilization_ratio: f32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanaryGateDecision {
    Promote,
    Hold,
    Rollback,
}

pub struct RolloutGateEvaluator {
    thresholds: CanaryGateThresholds,
}

impl RolloutGateEvaluator {
    pub fn new(thresholds: CanaryGateThresholds) -> Self {
        Self { thresholds }
    }

    pub fn evaluate(&self, observation: &CanaryObservation) -> CanaryGateDecision {
        if observation.self_protection_posture == ProtectionPosture::Lockdown
            || observation.health.dropped_events_total > self.thresholds.max_dropped_events_total
        {
            return CanaryGateDecision::Rollback;
        }

        if observation.health.cpu_percent_p95 > self.thresholds.max_cpu_percent_p95
            || observation.health.memory_rss_mb > self.thresholds.max_memory_rss_mb
            || observation.wal_utilization_ratio > self.thresholds.max_wal_utilization_ratio
        {
            return CanaryGateDecision::Hold;
        }

        CanaryGateDecision::Promote
    }
}

pub struct HotUpdateManifestVerifier {
    signing_keys: HashMap<String, VerifyingKey>,
}

impl HotUpdateManifestVerifier {
    pub fn new() -> Self {
        Self {
            signing_keys: HashMap::new(),
        }
    }

    pub fn register_signing_key(
        &mut self,
        key_id: impl Into<String>,
        public_key_bytes: [u8; 32],
    ) -> Result<()> {
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)?;
        self.signing_keys.insert(key_id.into(), verifying_key);
        Ok(())
    }

    pub fn verify_manifest(
        &self,
        manifest: &HotUpdateManifest,
        artifact_bytes: &[u8],
        rollback_artifact_bytes: Option<&[u8]>,
    ) -> Result<()> {
        let verifying_key = self
            .signing_keys
            .get(&manifest.signing_key_id)
            .ok_or_else(|| anyhow::anyhow!("unknown update signing key"))?;
        if sha256_hex(artifact_bytes) != manifest.artifact_sha256 {
            bail!("artifact digest mismatch");
        }
        match (
            manifest.rollback_artifact_id.as_deref(),
            manifest.rollback_artifact_sha256.as_deref(),
        ) {
            (Some(_), Some(expected_digest)) => {
                let rollback_bytes = rollback_artifact_bytes
                    .ok_or_else(|| anyhow::anyhow!("missing rollback artifact payload"))?;
                if sha256_hex(rollback_bytes) != expected_digest {
                    bail!("rollback artifact digest mismatch");
                }
            }
            (Some(_), None) => bail!("rollback artifact digest missing"),
            (None, Some(_)) => bail!("rollback digest provided without rollback artifact"),
            (None, None) => {}
        }

        let signature = Signature::from_slice(&manifest.signature)
            .map_err(|_| anyhow::anyhow!("invalid manifest signature"))?;
        verifying_key
            .verify(&Self::canonical_payload(manifest), &signature)
            .map_err(|_| anyhow::anyhow!("invalid manifest signature"))?;
        Ok(())
    }

    pub fn canonical_payload(manifest: &HotUpdateManifest) -> Vec<u8> {
        #[derive(Serialize)]
        struct CanonicalHotUpdateManifest<'a> {
            artifact_id: &'a str,
            target_version: &'a str,
            rollout_channel: &'a str,
            target_conf_version: u32,
            target_schema_version: i64,
            artifact_sha256: &'a str,
            rollback_artifact_id: Option<&'a str>,
            rollback_artifact_sha256: Option<&'a str>,
            signing_key_id: &'a str,
        }

        serde_json::to_vec(&CanonicalHotUpdateManifest {
            artifact_id: &manifest.artifact_id,
            target_version: &manifest.target_version,
            rollout_channel: &manifest.rollout_channel,
            target_conf_version: manifest.target_conf_version,
            target_schema_version: manifest.target_schema_version,
            artifact_sha256: &manifest.artifact_sha256,
            rollback_artifact_id: manifest.rollback_artifact_id.as_deref(),
            rollback_artifact_sha256: manifest.rollback_artifact_sha256.as_deref(),
            signing_key_id: &manifest.signing_key_id,
        })
        .expect("hot update manifest should serialize")
    }
}

impl Default for HotUpdateManifestVerifier {
    fn default() -> Self {
        Self::new()
    }
}

pub fn default_update_manifest_verifier() -> Result<HotUpdateManifestVerifier> {
    let mut verifier = HotUpdateManifestVerifier::new();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&DEVELOPMENT_UPDATE_SIGNING_KEY_BYTES);
    verifier.register_signing_key(
        DEVELOPMENT_UPDATE_SIGNING_KEY_ID,
        signing_key.verifying_key().to_bytes(),
    )?;
    Ok(verifier)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedPulledUpdate {
    pub manifest: HotUpdateManifest,
    pub manifest_path: PathBuf,
    pub artifact_path: PathBuf,
    pub rollback_path: Option<PathBuf>,
    pub artifact_bytes: Vec<u8>,
    pub rollback_bytes: Option<Vec<u8>>,
}

pub fn stage_pulled_update(
    config: &AgentConfig,
    chunks: Vec<UpdateChunk>,
) -> Result<StagedPulledUpdate> {
    let manifest_bytes = assemble_update_payload(&chunks, UPDATE_MANIFEST_KIND)?;
    let manifest_path = RuntimeStateStore::staged_update_manifest_path(config);
    if let Some(parent) = manifest_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&manifest_path, &manifest_bytes)?;

    let manifest: HotUpdateManifest = serde_json::from_slice(&manifest_bytes)?;
    let artifact_bytes =
        assemble_named_payload(&chunks, UPDATE_ARTIFACT_KIND, &manifest.artifact_id)?;
    let artifact_path = RuntimeStateStore::staged_update_artifact_path(config);
    fs::write(&artifact_path, &artifact_bytes)?;

    let rollback = match manifest.rollback_artifact_id.as_deref() {
        Some(artifact_id) => {
            let rollback_bytes =
                assemble_named_payload(&chunks, UPDATE_ROLLBACK_KIND, artifact_id)?;
            let rollback_path = RuntimeStateStore::staged_update_rollback_path(config);
            fs::write(&rollback_path, &rollback_bytes)?;
            Some((rollback_path, rollback_bytes))
        }
        None => {
            let rollback_path = RuntimeStateStore::staged_update_rollback_path(config);
            let _ = fs::remove_file(rollback_path);
            None
        }
    };

    Ok(StagedPulledUpdate {
        manifest,
        manifest_path,
        artifact_path,
        rollback_path: rollback.as_ref().map(|(path, _)| path.clone()),
        artifact_bytes,
        rollback_bytes: rollback.map(|(_, bytes)| bytes),
    })
}

fn assemble_update_payload(chunks: &[UpdateChunk], expected_kind: &str) -> Result<Vec<u8>> {
    let selected = chunks
        .iter()
        .filter(|chunk| chunk.artifact_kind == expected_kind)
        .cloned()
        .collect::<Vec<_>>();
    assemble_ordered_chunks(selected, expected_kind)
}

fn assemble_named_payload(
    chunks: &[UpdateChunk],
    expected_kind: &str,
    expected_artifact_id: &str,
) -> Result<Vec<u8>> {
    let selected = chunks
        .iter()
        .filter(|chunk| {
            chunk.artifact_kind == expected_kind && chunk.artifact_id == expected_artifact_id
        })
        .cloned()
        .collect::<Vec<_>>();
    assemble_ordered_chunks(selected, &format!("{expected_kind}:{expected_artifact_id}"))
}

fn assemble_ordered_chunks(mut chunks: Vec<UpdateChunk>, label: &str) -> Result<Vec<u8>> {
    if chunks.is_empty() {
        bail!("missing {label} payload");
    }
    chunks.sort_by_key(|chunk| chunk.chunk_index);
    let mut bytes = Vec::new();
    let mut saw_eof = false;
    for (expected_index, chunk) in chunks.into_iter().enumerate() {
        if chunk.chunk_index != expected_index as u32 {
            bail!("non-contiguous {label} chunk index {}", chunk.chunk_index);
        }
        if saw_eof {
            bail!("unexpected trailing {label} chunk after eof");
        }
        bytes.extend_from_slice(&chunk.bytes);
        saw_eof = chunk.eof;
    }
    if !saw_eof {
        bail!("incomplete {label} stream without eof");
    }
    Ok(bytes)
}

pub fn upgrade_artifact_from_manifest(manifest: &HotUpdateManifest) -> UpgradeArtifact {
    UpgradeArtifact {
        artifact_id: manifest.artifact_id.clone(),
        target_version: manifest.target_version.clone(),
        rollout_channel: manifest.rollout_channel.clone(),
        target_conf_version: manifest.target_conf_version,
        target_schema_version: manifest.target_schema_version,
        rollback_artifact_id: manifest.rollback_artifact_id.clone(),
    }
}

pub struct WatchdogLinkMonitor {
    grace_period_ms: i64,
    last_agent: Option<AgentSupervisorHeartbeat>,
    last_watchdog: Option<WatchdogHeartbeat>,
}

impl WatchdogLinkMonitor {
    pub fn new(grace_period_ms: i64) -> Self {
        Self {
            grace_period_ms: grace_period_ms.max(1),
            last_agent: None,
            last_watchdog: None,
        }
    }

    pub fn observe_agent(&mut self, heartbeat: AgentSupervisorHeartbeat) {
        self.last_agent = Some(heartbeat);
    }

    pub fn observe_watchdog(&mut self, heartbeat: WatchdogHeartbeat) {
        self.last_watchdog = Some(heartbeat);
    }

    pub fn evaluate(&self, now_ms: i64) -> Vec<WatchdogAlert> {
        let mut alerts = Vec::new();

        if let Some(agent) = &self.last_agent {
            if now_ms.saturating_sub(agent.sent_at_ms) > self.grace_period_ms {
                alerts.push(WatchdogAlert {
                    kind: WatchdogAlertKind::AgentMissedHeartbeat,
                    message: format!("agent heartbeat overdue for {}", agent.agent_id),
                    last_seen_ms: Some(agent.sent_at_ms),
                    observed_at_ms: now_ms,
                });
            }
        }

        if let Some(watchdog) = &self.last_watchdog {
            if now_ms.saturating_sub(watchdog.sent_at_ms) > self.grace_period_ms {
                alerts.push(WatchdogAlert {
                    kind: WatchdogAlertKind::WatchdogMissedHeartbeat,
                    message: format!("watchdog heartbeat overdue for {}", watchdog.watchdog_id),
                    last_seen_ms: Some(watchdog.sent_at_ms),
                    observed_at_ms: now_ms,
                });
            }
        }

        alerts
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnoseConnectionStatus {
    pub control_plane_url: String,
    pub reachable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnoseCertificateStatus {
    pub device_certificate_loaded: bool,
    pub last_rotation_succeeded: bool,
    #[serde(default)]
    pub attestation_bundle_loaded: bool,
    #[serde(default)]
    pub attestation_verifier_receipt_loaded: bool,
    #[serde(default)]
    pub attestation_verifier_receipt_verified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnoseSensorStatus {
    pub enabled_sensors: Vec<String>,
    pub unhealthy_sensors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnoseWalStatus {
    pub telemetry_segments: usize,
    pub forensic_root: PathBuf,
    pub completeness: TelemetryIntegrity,
    pub encrypted: bool,
    pub key_version: u32,
    pub quarantined_segments: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnoseKeyProtectionStatus {
    pub active_tier: KeyProtectionTier,
    pub provider_detail: Option<String>,
    pub degraded: bool,
    pub hardware_root_available: bool,
    pub memory_lock_supported: bool,
    pub memory_lock_enabled: bool,
    pub attestation_quote_ready: bool,
    pub attestation_pcrs: Option<String>,
    pub rollback_anchor: RollbackProtectionAnchor,
    pub rollback_floor_issued_at_ms: Option<i64>,
    pub rollback_fs_cross_check_ms: Option<i64>,
    pub rollback_cross_check_ok: bool,
    pub attestation_error: Option<String>,
    pub key_provider_error: Option<String>,
    pub rollback_error: Option<String>,
}

impl Default for DiagnoseKeyProtectionStatus {
    fn default() -> Self {
        Self {
            active_tier: KeyProtectionTier::InMemoryTestOnly,
            provider_detail: None,
            degraded: true,
            hardware_root_available: false,
            memory_lock_supported: cfg!(unix),
            memory_lock_enabled: false,
            attestation_quote_ready: false,
            attestation_pcrs: None,
            rollback_anchor: RollbackProtectionAnchor::Ephemeral,
            rollback_floor_issued_at_ms: None,
            rollback_fs_cross_check_ms: None,
            rollback_cross_check_ok: false,
            attestation_error: None,
            key_provider_error: None,
            rollback_error: None,
        }
    }
}

impl DiagnoseKeyProtectionStatus {
    pub fn from_runtime(
        key_status: &KeyProtectionStatus,
        rollback_status: &RollbackProtectionStatus,
    ) -> Self {
        Self {
            active_tier: key_status.active_tier,
            provider_detail: key_status.provider_detail.clone(),
            degraded: key_status.degraded
                || rollback_status.degraded
                || !rollback_status.cross_check_ok,
            hardware_root_available: key_status.hardware_root_available,
            memory_lock_supported: key_status.memory_lock_supported,
            memory_lock_enabled: key_status.memory_lock_enabled,
            attestation_quote_ready: key_status.attestation_quote_ready,
            attestation_pcrs: key_status.attestation_pcrs.clone(),
            rollback_anchor: rollback_status.anchor_kind,
            rollback_floor_issued_at_ms: rollback_status.floor_issued_at_ms,
            rollback_fs_cross_check_ms: rollback_status.fs_cross_check_ms,
            rollback_cross_check_ok: rollback_status.cross_check_ok,
            attestation_error: key_status.attestation_error.clone(),
            key_provider_error: key_status.last_error.clone(),
            rollback_error: rollback_status.last_error.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnoseReplayStatus {
    pub last_acked_sequence_id: u64,
    pub pending_batches: usize,
    pub high_priority_pending_batches: usize,
    pub normal_pending_batches: usize,
    pub retry_pending_batches: usize,
    pub in_flight_sequence_id: Option<u64>,
    pub oldest_pending_created_at_ms: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DiagnoseBundle {
    pub connection: DiagnoseConnectionStatus,
    pub certificates: DiagnoseCertificateStatus,
    pub sensors: DiagnoseSensorStatus,
    pub communication: CommunicationRuntimeStatus,
    pub engine_versions: BTreeMap<String, String>,
    pub ring_buffer_utilization_ratio: f32,
    pub wal: DiagnoseWalStatus,
    #[serde(default)]
    pub key_protection: DiagnoseKeyProtectionStatus,
    #[serde(default)]
    pub replay: DiagnoseReplayStatus,
    #[serde(default)]
    pub update: DiagnoseUpdateStatus,
    pub resources: AgentHealth,
    pub runtime_signals: RuntimeHealthSignals,
    pub runtime_bridge: Option<RuntimeBridgeStatus>,
    pub watchdog: Option<WatchdogRuntimeSnapshot>,
    pub plugin_status: Vec<PluginHealthStatus>,
    pub self_protection_posture: ProtectionPosture,
    pub redacted_fields: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AgentRuntimeSnapshot {
    pub captured_at_ms: i64,
    pub supervisor_heartbeat: AgentSupervisorHeartbeat,
    pub connection: DiagnoseConnectionStatus,
    pub certificates: DiagnoseCertificateStatus,
    pub sensors: DiagnoseSensorStatus,
    pub communication: CommunicationRuntimeStatus,
    pub engine_versions: BTreeMap<String, String>,
    pub ring_buffer_utilization_ratio: f32,
    pub wal: DiagnoseWalStatus,
    #[serde(default)]
    pub key_protection: DiagnoseKeyProtectionStatus,
    #[serde(default)]
    pub replay: DiagnoseReplayStatus,
    #[serde(default)]
    pub update: DiagnoseUpdateStatus,
    pub resources: AgentHealth,
    pub runtime_bridge: Option<RuntimeBridgeStatus>,
    pub plugin_status: Vec<PluginHealthStatus>,
    pub self_protection_posture: ProtectionPosture,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchdogRuntimeSnapshot {
    pub observed_at_ms: i64,
    pub agent_heartbeat: AgentSupervisorHeartbeat,
    pub watchdog_heartbeat: WatchdogHeartbeat,
    pub alerts: Vec<WatchdogAlert>,
    #[serde(default)]
    pub bootstrap_report: Option<BootstrapCheckReport>,
    #[serde(default)]
    pub bootstrap_passed: bool,
    #[serde(default)]
    pub update_phase: UpdatePhase,
    #[serde(default)]
    pub rollback_ready: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateVerificationSnapshot {
    #[serde(alias = "verified_at_ms")]
    pub updated_at_ms: i64,
    #[serde(default)]
    pub current_version: String,
    #[serde(default)]
    pub phase: UpdatePhase,
    #[serde(default)]
    pub pending_update_ids: Vec<String>,
    #[serde(default)]
    pub config_changed: bool,
    #[serde(default)]
    pub transport_channel: Option<CommunicationChannelKind>,
    #[serde(default)]
    pub retry_count: u32,
    #[serde(default)]
    pub manifest: Option<HotUpdateManifest>,
    #[serde(default)]
    pub manifest_path: Option<PathBuf>,
    #[serde(default)]
    pub artifact_path: Option<PathBuf>,
    #[serde(default)]
    pub rollback_path: Option<PathBuf>,
    #[serde(default)]
    pub last_attempt_at_ms: Option<i64>,
    #[serde(default)]
    pub last_success_at_ms: Option<i64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

impl Default for UpdateVerificationSnapshot {
    fn default() -> Self {
        Self {
            updated_at_ms: 0,
            current_version: String::new(),
            phase: UpdatePhase::Idle,
            pending_update_ids: Vec::new(),
            config_changed: false,
            transport_channel: None,
            retry_count: 0,
            manifest: None,
            manifest_path: None,
            artifact_path: None,
            rollback_path: None,
            last_attempt_at_ms: None,
            last_success_at_ms: None,
            last_error: None,
        }
    }
}

impl UpdateVerificationSnapshot {
    pub fn new(current_version: impl Into<String>, now_ms: i64) -> Self {
        Self {
            updated_at_ms: now_ms,
            current_version: current_version.into(),
            ..Self::default()
        }
    }

    pub fn active_update_id(&self) -> Option<String> {
        self.manifest
            .as_ref()
            .map(|manifest| manifest.artifact_id.clone())
    }

    pub fn to_diagnose_status(&self) -> DiagnoseUpdateStatus {
        DiagnoseUpdateStatus {
            phase: self.phase,
            current_version: self.current_version.clone(),
            pending_update_ids: self.pending_update_ids.clone(),
            config_changed: self.config_changed,
            transport_channel: self.transport_channel,
            target_artifact_id: self
                .manifest
                .as_ref()
                .map(|manifest| manifest.artifact_id.clone()),
            target_version: self
                .manifest
                .as_ref()
                .map(|manifest| manifest.target_version.clone()),
            rollback_required: self
                .manifest
                .as_ref()
                .and_then(|manifest| manifest.rollback_artifact_id.as_ref())
                .is_some(),
            staged_manifest_path: self.manifest_path.clone(),
            staged_artifact_path: self.artifact_path.clone(),
            staged_rollback_path: self.rollback_path.clone(),
            retry_count: self.retry_count,
            last_attempt_at_ms: self.last_attempt_at_ms,
            last_success_at_ms: self.last_success_at_ms,
            last_error: self.last_error.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WindowsInstallComponentKind {
    #[default]
    Binary,
    Script,
    Driver,
    Metadata,
}

fn default_required_component() -> bool {
    true
}

fn path_is_windows_absolute(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    let bytes = raw.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsInstallComponent {
    pub name: String,
    #[serde(default)]
    pub kind: WindowsInstallComponentKind,
    pub source_relative_path: PathBuf,
    pub install_relative_path: PathBuf,
    #[serde(default = "default_required_component")]
    pub required: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsReleaseDependency {
    pub name: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub install_relative_path: Option<PathBuf>,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsInstallManifest {
    pub schema_version: u32,
    pub bundle_channel: String,
    pub install_root: PathBuf,
    pub state_root: PathBuf,
    pub driver_service_name: String,
    #[serde(default)]
    pub components: Vec<WindowsInstallComponent>,
    #[serde(default)]
    pub release_dependencies: Vec<WindowsReleaseDependency>,
}

impl WindowsInstallManifest {
    pub fn from_json_str(raw: &str) -> Result<Self> {
        let manifest = serde_json::from_str::<Self>(raw)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn load_from_file(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)?;
        Self::from_json_str(&raw)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != WINDOWS_INSTALL_MANIFEST_SCHEMA_VERSION {
            bail!(
                "unsupported windows install manifest schema version: {}",
                self.schema_version
            );
        }
        if self.bundle_channel.trim().is_empty() {
            bail!("windows install manifest bundle_channel is required");
        }
        if self.driver_service_name.trim().is_empty() {
            bail!("windows install manifest driver_service_name is required");
        }
        if self.components.is_empty() {
            bail!("windows install manifest must include at least one component");
        }

        let mut names = HashMap::new();
        for component in &self.components {
            if component.name.trim().is_empty() {
                bail!("windows install component name is required");
            }
            if component.source_relative_path.as_os_str().is_empty() {
                bail!("windows install component source_relative_path is required");
            }
            if component.install_relative_path.as_os_str().is_empty() {
                bail!("windows install component install_relative_path is required");
            }
            if component.source_relative_path.is_absolute()
                || path_is_windows_absolute(&component.source_relative_path)
            {
                bail!(
                    "windows install component source_relative_path must be relative: {}",
                    component.source_relative_path.display()
                );
            }
            if component.install_relative_path.is_absolute()
                || path_is_windows_absolute(&component.install_relative_path)
            {
                bail!(
                    "windows install component install_relative_path must be relative: {}",
                    component.install_relative_path.display()
                );
            }
            if names
                .insert(
                    component.name.clone(),
                    component.install_relative_path.clone(),
                )
                .is_some()
            {
                bail!("duplicate windows install component: {}", component.name);
            }
        }

        let mut dependency_names = HashMap::new();
        for dependency in &self.release_dependencies {
            if dependency.name.trim().is_empty() {
                bail!("windows release dependency name is required");
            }
            if dependency_names
                .insert(
                    dependency.name.clone(),
                    dependency.install_relative_path.clone(),
                )
                .is_some()
            {
                bail!("duplicate windows release dependency: {}", dependency.name);
            }
            if let Some(relative_path) = &dependency.install_relative_path {
                if relative_path.as_os_str().is_empty() {
                    bail!(
                        "windows release dependency install_relative_path cannot be empty: {}",
                        dependency.name
                    );
                }
                if relative_path.is_absolute() || path_is_windows_absolute(relative_path) {
                    bail!(
                        "windows release dependency install_relative_path must be relative: {}",
                        relative_path.display()
                    );
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapCheckItem {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapCheckReport {
    pub observed_at_ms: i64,
    pub install_root: PathBuf,
    pub state_root: PathBuf,
    pub config_path: PathBuf,
    pub manifest_path: PathBuf,
    #[serde(default)]
    pub runtime_bridge_socket: Option<PathBuf>,
    pub items: Vec<BootstrapCheckItem>,
    pub approved: bool,
}

pub struct RuntimeStateStore;

impl RuntimeStateStore {
    pub fn agent_snapshot_path(config: &AgentConfig) -> PathBuf {
        config.storage.state_root.join("runtime-state.json")
    }

    pub fn watchdog_snapshot_path(config: &AgentConfig) -> PathBuf {
        config.storage.state_root.join("watchdog-state.json")
    }

    pub fn update_snapshot_path(config: &AgentConfig) -> PathBuf {
        config.storage.state_root.join("update-state.json")
    }

    pub fn bootstrap_report_path(config: &AgentConfig) -> PathBuf {
        config.storage.state_root.join("bootstrap-check.json")
    }

    pub fn staged_update_manifest_path(config: &AgentConfig) -> PathBuf {
        config.storage.state_root.join("updates/manifest.json")
    }

    pub fn staged_update_artifact_path(config: &AgentConfig) -> PathBuf {
        config.storage.state_root.join("updates/artifact.bin")
    }

    pub fn staged_update_rollback_path(config: &AgentConfig) -> PathBuf {
        config.storage.state_root.join("updates/rollback.bin")
    }

    pub fn persist_agent_snapshot(
        config: &AgentConfig,
        snapshot: &AgentRuntimeSnapshot,
    ) -> Result<()> {
        write_json(Self::agent_snapshot_path(config), snapshot)
    }

    pub fn load_agent_snapshot(config: &AgentConfig) -> Result<AgentRuntimeSnapshot> {
        read_json(&Self::agent_snapshot_path(config))
    }

    pub fn persist_watchdog_snapshot(
        config: &AgentConfig,
        snapshot: &WatchdogRuntimeSnapshot,
    ) -> Result<()> {
        write_json(Self::watchdog_snapshot_path(config), snapshot)
    }

    pub fn load_watchdog_snapshot(config: &AgentConfig) -> Result<WatchdogRuntimeSnapshot> {
        read_json(&Self::watchdog_snapshot_path(config))
    }

    pub fn persist_update_snapshot(
        config: &AgentConfig,
        snapshot: &UpdateVerificationSnapshot,
    ) -> Result<()> {
        write_json(Self::update_snapshot_path(config), snapshot)
    }

    pub fn load_update_snapshot(config: &AgentConfig) -> Result<UpdateVerificationSnapshot> {
        read_json(&Self::update_snapshot_path(config))
    }

    pub fn persist_bootstrap_report(
        config: &AgentConfig,
        report: &BootstrapCheckReport,
    ) -> Result<()> {
        write_json(Self::bootstrap_report_path(config), report)
    }

    pub fn load_bootstrap_report(config: &AgentConfig) -> Result<BootstrapCheckReport> {
        read_json(&Self::bootstrap_report_path(config))
    }

    pub fn refresh_agent_runtime_status(
        config: &AgentConfig,
        sent_at_ms: i64,
        active_update_id: Option<String>,
        communication: CommunicationRuntimeStatus,
        resources: AgentHealth,
    ) -> Result<AgentRuntimeSnapshot> {
        let mut snapshot = Self::load_agent_snapshot(config)?;
        snapshot.captured_at_ms = sent_at_ms;
        snapshot.supervisor_heartbeat.sent_at_ms = sent_at_ms;
        snapshot.supervisor_heartbeat.active_update_id = active_update_id;
        snapshot.communication = communication;
        snapshot.resources = resources;
        if let Some(runtime_bridge) = snapshot.runtime_bridge.as_mut() {
            runtime_bridge.last_runtime_heartbeat_ms = Some(sent_at_ms);
        }
        Self::persist_agent_snapshot(config, &snapshot)?;
        Ok(snapshot)
    }
}

pub struct DiagnoseCollector;

impl DiagnoseCollector {
    #[allow(clippy::too_many_arguments)]
    pub fn collect(
        control_plane_url: impl Into<String>,
        reachable: bool,
        certificates: DiagnoseCertificateStatus,
        sensors: DiagnoseSensorStatus,
        communication: CommunicationRuntimeStatus,
        engine_versions: BTreeMap<String, String>,
        ring_buffer_utilization_ratio: f32,
        wal: DiagnoseWalStatus,
        key_protection: DiagnoseKeyProtectionStatus,
        replay: DiagnoseReplayStatus,
        update: DiagnoseUpdateStatus,
        resources: AgentHealth,
        runtime_bridge: Option<RuntimeBridgeStatus>,
        plugin_status: Vec<PluginHealthStatus>,
        self_protection_posture: ProtectionPosture,
    ) -> DiagnoseBundle {
        DiagnoseBundle {
            connection: DiagnoseConnectionStatus {
                control_plane_url: control_plane_url.into(),
                reachable,
            },
            certificates,
            sensors,
            communication,
            engine_versions,
            ring_buffer_utilization_ratio,
            wal,
            key_protection,
            replay,
            update,
            runtime_signals: resources.runtime_signals.clone(),
            resources,
            runtime_bridge,
            watchdog: None,
            plugin_status,
            self_protection_posture,
            redacted_fields: vec![
                "server_signing_keys".to_string(),
                "approval_private_keys".to_string(),
                "threat_intel_cache".to_string(),
            ],
        }
    }

    pub fn to_json(bundle: &DiagnoseBundle) -> Result<String> {
        Ok(serde_json::to_string_pretty(bundle)?)
    }
}

impl AgentRuntimeSnapshot {
    pub fn to_diagnose_bundle(&self) -> DiagnoseBundle {
        DiagnoseCollector::collect(
            self.connection.control_plane_url.clone(),
            self.connection.reachable,
            self.certificates.clone(),
            self.sensors.clone(),
            self.communication.clone(),
            self.engine_versions.clone(),
            self.ring_buffer_utilization_ratio,
            self.wal.clone(),
            self.key_protection.clone(),
            self.replay.clone(),
            self.update.clone(),
            self.resources.clone(),
            self.runtime_bridge.clone(),
            self.plugin_status.clone(),
            self.self_protection_posture,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AgentRuntimeSnapshot, BootstrapCheckItem, BootstrapCheckReport, CanaryGateDecision,
        CanaryGateThresholds, CanaryObservation, DiagnoseCertificateStatus, DiagnoseCollector,
        DiagnoseConnectionStatus, DiagnoseKeyProtectionStatus, DiagnoseReplayStatus,
        DiagnoseSensorStatus, DiagnoseWalStatus, HotUpdateManifestVerifier, RolloutGateEvaluator,
        RuntimeStateStore, UpdatePhase, UpdateVerificationSnapshot, UpgradeArtifact,
        UpgradePlanner, WatchdogLinkMonitor, WatchdogRuntimeSnapshot, WindowsInstallManifest,
        DEVELOPMENT_UPDATE_SIGNING_KEY_BYTES, DEVELOPMENT_UPDATE_SIGNING_KEY_ID,
    };
    use crate::config::AgentConfig;
    use crate::health::HealthReporter;
    use crate::self_protection::ProtectionPosture;
    use aegis_model::{
        AgentSupervisorHeartbeat, CloudConnectorCursor, CloudLogSourceKind,
        CommunicationChannelKind, CommunicationRuntimeStatus, HotUpdateManifest, LineageCounters,
        PluginHealthStatus, RuntimeBridgeStatus, RuntimeHealthSignals, TelemetryIntegrity,
        WatchdogAlertKind, WatchdogHeartbeat,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn health() -> aegis_model::AgentHealth {
        HealthReporter::build_snapshot(
            "0.1.0",
            "policy-1",
            "ruleset-1",
            "model-1",
            8.0,
            256,
            BTreeMap::from([("event".to_string(), 8usize)]),
            LineageCounters::default(),
            RuntimeHealthSignals {
                communication_channel: CommunicationChannelKind::Grpc,
                adaptive_whitelist_size: 5,
                etw_tamper_detected: false,
                amsi_tamper_detected: false,
                bpf_integrity_pass: true,
            },
        )
    }

    #[test]
    fn upgrade_planner_includes_migration_and_canary_steps() {
        let plan = UpgradePlanner::build_plan(
            &AgentConfig::default(),
            UpgradeArtifact {
                artifact_id: "artifact-1".to_string(),
                target_version: "1.2.0".to_string(),
                rollout_channel: "canary".to_string(),
                target_conf_version: 2,
                target_schema_version: 2,
                rollback_artifact_id: Some("artifact-rollback".to_string()),
            },
        )
        .expect("build upgrade plan");

        assert!(plan.requires_schema_migration);
        assert!(plan.requires_config_sync);
        assert!(plan.rollback_required);
        assert!(plan
            .steps
            .iter()
            .any(|step| step.contains("canary rollout")));
    }

    #[test]
    fn rollout_gate_evaluator_rolls_back_on_drop_spike_or_lockdown() {
        let evaluator = RolloutGateEvaluator::new(CanaryGateThresholds {
            max_cpu_percent_p95: 50.0,
            max_memory_rss_mb: 1_024,
            max_dropped_events_total: 5,
            max_wal_utilization_ratio: 0.85,
        });
        let mut bad_health = health();
        bad_health.dropped_events_total = 9;

        let decision = evaluator.evaluate(&CanaryObservation {
            health: bad_health,
            wal_utilization_ratio: 0.2,
            self_protection_posture: ProtectionPosture::Hardened,
        });
        let lockdown = evaluator.evaluate(&CanaryObservation {
            health: health(),
            wal_utilization_ratio: 0.2,
            self_protection_posture: ProtectionPosture::Lockdown,
        });

        assert_eq!(decision, CanaryGateDecision::Rollback);
        assert_eq!(lockdown, CanaryGateDecision::Rollback);
    }

    fn signed_manifest(
        signing_key: &SigningKey,
        artifact_bytes: &[u8],
        rollback_bytes: Option<&[u8]>,
    ) -> HotUpdateManifest {
        let mut manifest = HotUpdateManifest {
            artifact_id: "artifact-42".to_string(),
            target_version: "1.2.3".to_string(),
            rollout_channel: "canary".to_string(),
            target_conf_version: 2,
            target_schema_version: 3,
            artifact_sha256: super::sha256_hex(artifact_bytes),
            rollback_artifact_id: rollback_bytes.map(|_| "artifact-41".to_string()),
            rollback_artifact_sha256: rollback_bytes.map(super::sha256_hex),
            signature: Vec::new(),
            signing_key_id: DEVELOPMENT_UPDATE_SIGNING_KEY_ID.to_string(),
        };
        manifest.signature = signing_key
            .sign(&HotUpdateManifestVerifier::canonical_payload(&manifest))
            .to_bytes()
            .to_vec();
        manifest
    }

    #[test]
    fn hot_update_manifest_verifier_rejects_invalid_signature() {
        let server_signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let wrong_signing_key = SigningKey::from_bytes(&[10u8; 32]);
        let artifact = b"agent-binary";
        let rollback = b"agent-binary-prev";
        let manifest = signed_manifest(&wrong_signing_key, artifact, Some(rollback));
        let mut verifier = HotUpdateManifestVerifier::new();
        verifier
            .register_signing_key(
                DEVELOPMENT_UPDATE_SIGNING_KEY_ID,
                server_signing_key.verifying_key().to_bytes(),
            )
            .expect("register signing key");

        let result = verifier.verify_manifest(&manifest, artifact, Some(rollback));

        assert!(result.is_err());
    }

    #[test]
    fn hot_update_manifest_verifier_rejects_rollback_digest_mismatch() {
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let artifact = b"agent-binary";
        let rollback = b"agent-binary-prev";
        let manifest = signed_manifest(&signing_key, artifact, Some(rollback));
        let mut verifier = HotUpdateManifestVerifier::new();
        verifier
            .register_signing_key(
                DEVELOPMENT_UPDATE_SIGNING_KEY_ID,
                signing_key.verifying_key().to_bytes(),
            )
            .expect("register signing key");

        let result = verifier.verify_manifest(&manifest, artifact, Some(b"rollback-other"));

        assert!(result.is_err());
    }

    #[test]
    fn watchdog_link_monitor_detects_missed_watchdog_heartbeat() {
        let mut monitor = WatchdogLinkMonitor::new(1_000);
        monitor.observe_agent(AgentSupervisorHeartbeat {
            tenant_id: "tenant-a".to_string(),
            agent_id: "agent-a".to_string(),
            plugin_count: 2,
            degraded_plugins: 0,
            active_update_id: None,
            sent_at_ms: 2_200,
        });
        monitor.observe_watchdog(WatchdogHeartbeat {
            tenant_id: "tenant-a".to_string(),
            agent_id: "agent-a".to_string(),
            watchdog_id: "watchdog-a".to_string(),
            observed_agent_restart_epoch: 3,
            unhealthy_plugins: 0,
            sent_at_ms: 1_000,
        });

        let alerts = monitor.evaluate(2_500);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, WatchdogAlertKind::WatchdogMissedHeartbeat);
    }

    #[test]
    fn diagnose_collector_builds_redacted_bundle() {
        let bundle = DiagnoseCollector::collect(
            "https://control-plane.example",
            true,
            DiagnoseCertificateStatus {
                device_certificate_loaded: true,
                last_rotation_succeeded: true,
                attestation_bundle_loaded: false,
                attestation_verifier_receipt_loaded: false,
                attestation_verifier_receipt_verified: false,
            },
            DiagnoseSensorStatus {
                enabled_sensors: vec!["process".to_string(), "network".to_string()],
                unhealthy_sensors: vec![],
            },
            CommunicationRuntimeStatus {
                active_channel: CommunicationChannelKind::WebSocket,
                degraded: true,
                fallback_chain: vec![
                    CommunicationChannelKind::Grpc,
                    CommunicationChannelKind::WebSocket,
                    CommunicationChannelKind::LongPolling,
                    CommunicationChannelKind::DomainFronting,
                ],
                last_success_ms: Some(1_713_000_100_000),
                channels: vec![],
            },
            BTreeMap::from([
                ("detector".to_string(), "ruleset-1".to_string()),
                ("model".to_string(), "model-1".to_string()),
            ]),
            0.35,
            DiagnoseWalStatus {
                telemetry_segments: 3,
                forensic_root: PathBuf::from("/var/lib/aegis/forensics"),
                completeness: TelemetryIntegrity::Partial,
                encrypted: true,
                key_version: 1,
                quarantined_segments: 1,
            },
            DiagnoseKeyProtectionStatus::default(),
            DiagnoseReplayStatus::default(),
            UpdateVerificationSnapshot::new("0.1.0", 1_713_000_120_000).to_diagnose_status(),
            health(),
            Some(RuntimeBridgeStatus {
                control_socket_path: Some(
                    "/var/lib/aegis/runtime-bridge-local-agent.sock".to_string(),
                ),
                buffered_events: 2,
                emitted_batches: 1,
                last_runtime_heartbeat_ms: Some(1_713_000_120_000),
                last_connector_cursor: Some(CloudConnectorCursor {
                    source: CloudLogSourceKind::AwsCloudTrail,
                    shard: "us-east-1".to_string(),
                    checkpoint: "evt-9".to_string(),
                }),
            }),
            vec![PluginHealthStatus {
                plugin_id: "runtime-audit".to_string(),
                healthy: true,
                state: "running".to_string(),
                crash_count: 0,
            }],
            ProtectionPosture::Normal,
        );
        let json = DiagnoseCollector::to_json(&bundle).expect("serialize bundle");

        assert!(json.contains("\"telemetry_segments\": 3"));
        assert!(json.contains("\"encrypted\": true"));
        assert!(json.contains("\"active_channel\": \"WebSocket\""));
        assert!(json.contains("\"runtime_bridge\""));
        assert!(json.contains("\"redacted_fields\""));
        assert_eq!(
            bundle.runtime_signals.communication_channel,
            CommunicationChannelKind::Grpc
        );
        assert_eq!(
            bundle
                .runtime_bridge
                .as_ref()
                .map(|value| value.emitted_batches),
            Some(1)
        );
        assert_eq!(bundle.plugin_status.len(), 1);
        assert!(bundle
            .redacted_fields
            .contains(&"server_signing_keys".to_string()));
    }

    fn temp_state_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("aegis-upgrade-{name}-{}", Uuid::now_v7()))
    }

    #[test]
    fn runtime_state_store_roundtrips_agent_watchdog_and_update_snapshots() {
        let mut config = AgentConfig::default();
        let state_root = temp_state_root("state-store");
        config.storage.state_root = state_root.clone();

        let agent_snapshot = AgentRuntimeSnapshot {
            captured_at_ms: 1_713_000_300_000,
            supervisor_heartbeat: AgentSupervisorHeartbeat {
                tenant_id: "tenant-a".to_string(),
                agent_id: "agent-a".to_string(),
                plugin_count: 1,
                degraded_plugins: 0,
                active_update_id: Some("artifact-42".to_string()),
                sent_at_ms: 1_713_000_300_000,
            },
            connection: DiagnoseConnectionStatus {
                control_plane_url: "https://control-plane.example".to_string(),
                reachable: true,
            },
            certificates: DiagnoseCertificateStatus {
                device_certificate_loaded: true,
                last_rotation_succeeded: true,
                attestation_bundle_loaded: false,
                attestation_verifier_receipt_loaded: false,
                attestation_verifier_receipt_verified: false,
            },
            sensors: DiagnoseSensorStatus {
                enabled_sensors: vec!["process".to_string()],
                unhealthy_sensors: vec![],
            },
            communication: CommunicationRuntimeStatus {
                active_channel: CommunicationChannelKind::Grpc,
                degraded: false,
                fallback_chain: vec![CommunicationChannelKind::Grpc],
                last_success_ms: Some(1_713_000_299_000),
                channels: vec![],
            },
            engine_versions: BTreeMap::from([("policy_bundle".to_string(), "1".to_string())]),
            ring_buffer_utilization_ratio: 0.1,
            wal: DiagnoseWalStatus {
                telemetry_segments: 1,
                forensic_root: state_root.join("forensics"),
                completeness: TelemetryIntegrity::Full,
                encrypted: true,
                key_version: 1,
                quarantined_segments: 0,
            },
            key_protection: DiagnoseKeyProtectionStatus::default(),
            replay: DiagnoseReplayStatus::default(),
            update: UpdateVerificationSnapshot::new("0.1.0", 1_713_000_300_000)
                .to_diagnose_status(),
            resources: health(),
            runtime_bridge: None,
            plugin_status: vec![PluginHealthStatus {
                plugin_id: "runtime-audit".to_string(),
                healthy: true,
                state: "loaded".to_string(),
                crash_count: 0,
            }],
            self_protection_posture: ProtectionPosture::Normal,
        };
        RuntimeStateStore::persist_agent_snapshot(&config, &agent_snapshot)
            .expect("persist agent snapshot");
        let restored_agent =
            RuntimeStateStore::load_agent_snapshot(&config).expect("load agent snapshot");
        assert_eq!(restored_agent, agent_snapshot);

        let bootstrap_report = BootstrapCheckReport {
            observed_at_ms: 1_713_000_300_500,
            install_root: PathBuf::from("C:/Program Files/Aegis"),
            state_root: state_root.clone(),
            config_path: state_root.join("agent.toml"),
            manifest_path: PathBuf::from("C:/Program Files/Aegis/manifest.json"),
            runtime_bridge_socket: Some(state_root.join("runtime-bridge-agent-a.sock")),
            items: vec![BootstrapCheckItem {
                name: "runtime_bootstrap".to_string(),
                ok: true,
                detail: "runtime bridge ready".to_string(),
            }],
            approved: true,
        };
        RuntimeStateStore::persist_bootstrap_report(&config, &bootstrap_report)
            .expect("persist bootstrap report");
        let restored_bootstrap =
            RuntimeStateStore::load_bootstrap_report(&config).expect("load bootstrap report");
        assert_eq!(restored_bootstrap, bootstrap_report);

        let watchdog_snapshot = WatchdogRuntimeSnapshot {
            observed_at_ms: 1_713_000_301_000,
            agent_heartbeat: restored_agent.supervisor_heartbeat.clone(),
            watchdog_heartbeat: WatchdogHeartbeat {
                tenant_id: "tenant-a".to_string(),
                agent_id: "agent-a".to_string(),
                watchdog_id: "watchdog-a".to_string(),
                observed_agent_restart_epoch: 0,
                unhealthy_plugins: 0,
                sent_at_ms: 1_713_000_301_000,
            },
            alerts: vec![],
            bootstrap_report: Some(restored_bootstrap.clone()),
            bootstrap_passed: true,
            update_phase: UpdatePhase::Ready,
            rollback_ready: false,
        };
        RuntimeStateStore::persist_watchdog_snapshot(&config, &watchdog_snapshot)
            .expect("persist watchdog snapshot");
        let restored_watchdog =
            RuntimeStateStore::load_watchdog_snapshot(&config).expect("load watchdog snapshot");
        assert_eq!(restored_watchdog, watchdog_snapshot);

        let update_snapshot = UpdateVerificationSnapshot {
            updated_at_ms: 1_713_000_302_000,
            current_version: "0.1.0".to_string(),
            phase: UpdatePhase::Ready,
            pending_update_ids: vec!["artifact-42".to_string()],
            config_changed: false,
            transport_channel: Some(CommunicationChannelKind::Grpc),
            retry_count: 1,
            manifest: Some(signed_manifest(
                &SigningKey::from_bytes(&DEVELOPMENT_UPDATE_SIGNING_KEY_BYTES),
                b"artifact",
                None,
            )),
            manifest_path: Some(state_root.join("updates/manifest.json")),
            artifact_path: Some(state_root.join("updates/artifact.bin")),
            rollback_path: None,
            last_attempt_at_ms: Some(1_713_000_301_500),
            last_success_at_ms: Some(1_713_000_302_000),
            last_error: None,
        };
        RuntimeStateStore::persist_update_snapshot(&config, &update_snapshot)
            .expect("persist update snapshot");
        let restored_update =
            RuntimeStateStore::load_update_snapshot(&config).expect("load update snapshot");
        assert_eq!(restored_update, update_snapshot);

        let bundle = restored_agent.to_diagnose_bundle();
        assert_eq!(bundle.plugin_status.len(), 1);
        assert_eq!(
            bundle.connection.control_plane_url,
            "https://control-plane.example"
        );
        assert!(bundle.watchdog.is_none());

        std::fs::remove_dir_all(state_root).ok();
    }

    #[test]
    fn windows_install_manifest_requires_relative_component_paths() {
        let manifest = r#"
        {
          "schema_version": 1,
          "bundle_channel": "development",
          "install_root": "C:\\Program Files\\Aegis",
          "state_root": "C:\\ProgramData\\Aegis\\state",
          "driver_service_name": "AegisSensorKmod",
          "components": [
            {
              "name": "agentd",
              "kind": "binary",
              "source_relative_path": "bin/aegis-agentd.exe",
              "install_relative_path": "bin/aegis-agentd.exe",
              "required": true
            }
          ]
        }
        "#;

        let parsed = WindowsInstallManifest::from_json_str(manifest).expect("parse manifest");
        assert_eq!(parsed.bundle_channel, "development");
        assert_eq!(parsed.components.len(), 1);

        let invalid = r#"
        {
          "schema_version": 1,
          "bundle_channel": "development",
          "install_root": "C:\\Program Files\\Aegis",
          "state_root": "C:\\ProgramData\\Aegis\\state",
          "driver_service_name": "AegisSensorKmod",
          "components": [
            {
              "name": "agentd",
              "kind": "binary",
              "source_relative_path": "C:/payload/aegis-agentd.exe",
              "install_relative_path": "bin/aegis-agentd.exe",
              "required": true
            }
          ]
        }
        "#;

        let error = WindowsInstallManifest::from_json_str(invalid).expect_err("reject absolute");
        assert!(error.to_string().contains("must be relative"));
    }

    #[test]
    fn windows_install_manifest_requires_relative_release_dependency_paths() {
        let manifest = r#"
        {
          "schema_version": 1,
          "bundle_channel": "release",
          "install_root": "C:\\Program Files\\Aegis",
          "state_root": "C:\\ProgramData\\Aegis\\state",
          "driver_service_name": "AegisSensorKmod",
          "components": [
            {
              "name": "agentd",
              "kind": "binary",
              "source_relative_path": "bin/aegis-agentd.exe",
              "install_relative_path": "bin/aegis-agentd.exe",
              "required": true
            }
          ],
          "release_dependencies": [
            {
              "name": "trusted_bundle_receipt",
              "required": true,
              "install_relative_path": "metadata/signed-release.json"
            }
          ]
        }
        "#;

        let parsed = WindowsInstallManifest::from_json_str(manifest).expect("parse manifest");
        assert_eq!(parsed.release_dependencies.len(), 1);

        let invalid = r#"
        {
          "schema_version": 1,
          "bundle_channel": "release",
          "install_root": "C:\\Program Files\\Aegis",
          "state_root": "C:\\ProgramData\\Aegis\\state",
          "driver_service_name": "AegisSensorKmod",
          "components": [
            {
              "name": "agentd",
              "kind": "binary",
              "source_relative_path": "bin/aegis-agentd.exe",
              "install_relative_path": "bin/aegis-agentd.exe",
              "required": true
            }
          ],
          "release_dependencies": [
            {
              "name": "trusted_bundle_receipt",
              "required": true,
              "install_relative_path": "C:/payload/metadata/signed-release.json"
            }
          ]
        }
        "#;

        let error = WindowsInstallManifest::from_json_str(invalid).expect_err("reject absolute");
        assert!(error.to_string().contains("must be relative"));
    }

    #[test]
    fn refresh_agent_runtime_status_updates_heartbeat_and_runtime_bridge() {
        let mut config = AgentConfig::default();
        let state_root = temp_state_root("runtime-refresh");
        config.storage.state_root = state_root.clone();

        let mut snapshot = AgentRuntimeSnapshot {
            captured_at_ms: 1_713_000_300_000,
            supervisor_heartbeat: AgentSupervisorHeartbeat {
                tenant_id: "tenant-a".to_string(),
                agent_id: "agent-a".to_string(),
                plugin_count: 2,
                degraded_plugins: 1,
                active_update_id: None,
                sent_at_ms: 1_713_000_300_000,
            },
            connection: DiagnoseConnectionStatus {
                control_plane_url: "https://control-plane.example".to_string(),
                reachable: true,
            },
            certificates: DiagnoseCertificateStatus {
                device_certificate_loaded: true,
                last_rotation_succeeded: true,
                attestation_bundle_loaded: false,
                attestation_verifier_receipt_loaded: false,
                attestation_verifier_receipt_verified: false,
            },
            sensors: DiagnoseSensorStatus {
                enabled_sensors: vec!["process".to_string()],
                unhealthy_sensors: vec![],
            },
            communication: CommunicationRuntimeStatus {
                active_channel: CommunicationChannelKind::Grpc,
                degraded: false,
                fallback_chain: vec![CommunicationChannelKind::Grpc],
                last_success_ms: Some(1_713_000_299_000),
                channels: vec![],
            },
            engine_versions: BTreeMap::new(),
            ring_buffer_utilization_ratio: 0.0,
            wal: DiagnoseWalStatus {
                telemetry_segments: 0,
                forensic_root: state_root.join("forensics"),
                completeness: TelemetryIntegrity::Full,
                encrypted: true,
                key_version: 1,
                quarantined_segments: 0,
            },
            key_protection: DiagnoseKeyProtectionStatus::default(),
            replay: DiagnoseReplayStatus::default(),
            update: UpdateVerificationSnapshot::new("0.1.0", 1_713_000_300_000)
                .to_diagnose_status(),
            resources: health(),
            runtime_bridge: Some(RuntimeBridgeStatus {
                control_socket_path: Some(state_root.join("runtime.sock").display().to_string()),
                buffered_events: 0,
                emitted_batches: 0,
                last_runtime_heartbeat_ms: None,
                last_connector_cursor: None,
            }),
            plugin_status: vec![],
            self_protection_posture: ProtectionPosture::Normal,
        };
        RuntimeStateStore::persist_agent_snapshot(&config, &snapshot)
            .expect("persist agent snapshot");

        let next_health = health();
        let next_communication = CommunicationRuntimeStatus {
            active_channel: CommunicationChannelKind::WebSocket,
            degraded: false,
            fallback_chain: vec![
                CommunicationChannelKind::Grpc,
                CommunicationChannelKind::WebSocket,
            ],
            last_success_ms: Some(1_713_000_305_000),
            channels: vec![],
        };
        let refreshed = RuntimeStateStore::refresh_agent_runtime_status(
            &config,
            1_713_000_305_000,
            Some("artifact-99".to_string()),
            next_communication.clone(),
            next_health.clone(),
        )
        .expect("refresh runtime snapshot");

        snapshot.captured_at_ms = 1_713_000_305_000;
        snapshot.supervisor_heartbeat.sent_at_ms = 1_713_000_305_000;
        snapshot.supervisor_heartbeat.active_update_id = Some("artifact-99".to_string());
        snapshot.communication = next_communication;
        snapshot.resources = next_health;
        snapshot
            .runtime_bridge
            .as_mut()
            .expect("runtime bridge")
            .last_runtime_heartbeat_ms = Some(1_713_000_305_000);

        assert_eq!(refreshed, snapshot);

        std::fs::remove_dir_all(state_root).ok();
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write_json<T: Serialize>(path: PathBuf, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = fs::read(path)?;
    Ok(serde_json::from_slice(&raw)?)
}
