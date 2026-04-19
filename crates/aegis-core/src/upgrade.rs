use crate::config::{AgentConfig, CURRENT_CONF_VERSION};
use crate::migrations::{CURRENT_SCHEMA_VERSION, MIN_READER_SCHEMA_VERSION};
use crate::self_protection::ProtectionPosture;
use aegis_model::{
    AgentHealth, CommunicationRuntimeStatus, PluginHealthStatus, RuntimeHealthSignals,
    TelemetryIntegrity,
};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
        DiagnoseCollector, DiagnoseSensorStatus, DiagnoseWalStatus, RolloutGateEvaluator,
        UpgradeArtifact, UpgradePlanner,
    };
    use crate::config::AgentConfig;
    use crate::health::HealthReporter;
    use crate::self_protection::ProtectionPosture;
    use aegis_model::{
        CommunicationChannelKind, CommunicationRuntimeStatus, LineageCounters, PluginHealthStatus,
        RuntimeHealthSignals, TelemetryIntegrity,
    };
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
