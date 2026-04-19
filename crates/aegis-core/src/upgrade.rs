use crate::config::{AgentConfig, CURRENT_CONF_VERSION};
use crate::migrations::{CURRENT_SCHEMA_VERSION, MIN_READER_SCHEMA_VERSION};
use crate::self_protection::ProtectionPosture;
use aegis_model::{
    AgentHealth, AgentSupervisorHeartbeat, CommunicationRuntimeStatus, HotUpdateManifest,
    PluginHealthStatus, RuntimeHealthSignals, TelemetryIntegrity, WatchdogAlert, WatchdogAlertKind,
    WatchdogHeartbeat,
};
use anyhow::{bail, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DiagnoseBundle {
    pub connection: DiagnoseConnectionStatus,
    pub certificates: DiagnoseCertificateStatus,
    pub sensors: DiagnoseSensorStatus,
    pub communication: CommunicationRuntimeStatus,
    pub engine_versions: BTreeMap<String, String>,
    pub ring_buffer_utilization_ratio: f32,
    pub wal: DiagnoseWalStatus,
    pub resources: AgentHealth,
    pub runtime_signals: RuntimeHealthSignals,
    pub plugin_status: Vec<PluginHealthStatus>,
    pub self_protection_posture: ProtectionPosture,
    pub redacted_fields: Vec<String>,
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
        resources: AgentHealth,
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
            runtime_signals: resources.runtime_signals.clone(),
            resources,
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

#[cfg(test)]
mod tests {
    use super::{
        CanaryGateDecision, CanaryGateThresholds, CanaryObservation, DiagnoseCertificateStatus,
        DiagnoseCollector, DiagnoseSensorStatus, DiagnoseWalStatus, HotUpdateManifestVerifier,
        RolloutGateEvaluator, UpgradeArtifact, UpgradePlanner, WatchdogLinkMonitor,
    };
    use crate::config::AgentConfig;
    use crate::health::HealthReporter;
    use crate::self_protection::ProtectionPosture;
    use aegis_model::{
        AgentSupervisorHeartbeat, CommunicationChannelKind, CommunicationRuntimeStatus,
        HotUpdateManifest, LineageCounters, PluginHealthStatus, RuntimeHealthSignals,
        TelemetryIntegrity, WatchdogAlertKind, WatchdogHeartbeat,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

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
            signing_key_id: "server-k1".to_string(),
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
            .register_signing_key("server-k1", server_signing_key.verifying_key().to_bytes())
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
            .register_signing_key("server-k1", signing_key.verifying_key().to_bytes())
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
            health(),
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
        assert!(json.contains("\"redacted_fields\""));
        assert_eq!(
            bundle.runtime_signals.communication_channel,
            CommunicationChannelKind::Grpc
        );
        assert_eq!(bundle.plugin_status.len(), 1);
        assert!(bundle
            .redacted_fields
            .contains(&"server_signing_keys".to_string()));
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
