use crate::error::CoreError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const CURRENT_CONF_VERSION: u32 = 1;
pub const MIN_SUPPORTED_CONF_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfVersion {
    pub current: u32,
    pub min_supported: u32,
}

impl Default for ConfVersion {
    fn default() -> Self {
        Self {
            current: CURRENT_CONF_VERSION,
            min_supported: MIN_SUPPORTED_CONF_VERSION,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyVersion {
    pub policy_bundle: u64,
    pub ruleset_revision: u64,
    pub model_revision: u64,
}

impl Default for PolicyVersion {
    fn default() -> Self {
        Self {
            policy_bundle: 1,
            ruleset_revision: 1,
            model_revision: 1,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub heartbeat_interval_secs: u64,
    pub shutdown_grace_period_secs: u64,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_secs: 60,
            shutdown_grace_period_secs: 15,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrpcCommunicationConfig {
    pub enabled: bool,
    pub endpoint: String,
}

impl Default for GrpcCommunicationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: "http://127.0.0.1:7443".to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebSocketCommunicationConfig {
    pub enabled: bool,
    pub endpoint: String,
}

impl Default for WebSocketCommunicationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: "ws://127.0.0.1:7444/ws".to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpPollingCommunicationConfig {
    pub enabled: bool,
    pub uplink_url: String,
    pub heartbeat_url: String,
    pub downlink_url: String,
    pub probe_url: String,
    pub timeout_ms: u64,
}

impl Default for HttpPollingCommunicationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            uplink_url: "http://127.0.0.1:7445/uplink".to_string(),
            heartbeat_url: "http://127.0.0.1:7445/heartbeat".to_string(),
            downlink_url: "http://127.0.0.1:7445/downlink".to_string(),
            probe_url: "http://127.0.0.1:7445/probe".to_string(),
            timeout_ms: 2_000,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainFrontingCommunicationConfig {
    pub enabled: bool,
    pub uplink_url: String,
    pub heartbeat_url: String,
    pub downlink_url: String,
    pub probe_url: String,
    pub timeout_ms: u64,
    pub front_domain: String,
    pub host_header: String,
}

impl Default for DomainFrontingCommunicationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            uplink_url: "http://127.0.0.1:7446/uplink".to_string(),
            heartbeat_url: "http://127.0.0.1:7446/heartbeat".to_string(),
            downlink_url: "http://127.0.0.1:7446/downlink".to_string(),
            probe_url: "http://127.0.0.1:7446/probe".to_string(),
            timeout_ms: 5_000,
            front_domain: "cdn.example.com".to_string(),
            host_header: "control-plane.aegis.local".to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunicationConfig {
    pub failure_threshold: u32,
    pub development_allow_loopback: bool,
    pub grpc: GrpcCommunicationConfig,
    pub websocket: WebSocketCommunicationConfig,
    pub long_polling: HttpPollingCommunicationConfig,
    pub domain_fronting: DomainFrontingCommunicationConfig,
}

impl Default for CommunicationConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            development_allow_loopback: false,
            grpc: GrpcCommunicationConfig::default(),
            websocket: WebSocketCommunicationConfig::default(),
            long_polling: HttpPollingCommunicationConfig::default(),
            domain_fronting: DomainFrontingCommunicationConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityConfig {
    pub use_os_credential_store: bool,
    pub allow_file_fallback: bool,
    pub memory_lock_best_effort: bool,
    #[serde(default)]
    pub linux_tpm_tools_dir: Option<PathBuf>,
    #[serde(default)]
    pub linux_tpm_device_path: Option<PathBuf>,
    #[serde(default)]
    pub linux_tpm_master_key_sealed_object_path: Option<PathBuf>,
    #[serde(default)]
    pub linux_tpm_master_key_pcrs: Option<String>,
    #[serde(default)]
    pub linux_tpm_attestation_ak_path: Option<PathBuf>,
    #[serde(default)]
    pub linux_tpm_attestation_pcrs: Option<String>,
    #[serde(default)]
    pub linux_tpm_master_key_nv_index: Option<String>,
    #[serde(default)]
    pub linux_tpm_rollback_nv_index: Option<String>,
    #[serde(default)]
    pub linux_tpm_auto_provision_nv: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            use_os_credential_store: true,
            allow_file_fallback: true,
            memory_lock_best_effort: true,
            linux_tpm_tools_dir: None,
            linux_tpm_device_path: None,
            linux_tpm_master_key_sealed_object_path: None,
            linux_tpm_master_key_pcrs: None,
            linux_tpm_attestation_ak_path: None,
            linux_tpm_attestation_pcrs: None,
            linux_tpm_master_key_nv_index: None,
            linux_tpm_rollback_nv_index: None,
            linux_tpm_auto_provision_nv: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageConfig {
    pub state_root: PathBuf,
    pub config_path: PathBuf,
    pub agent_db_path: PathBuf,
    pub ring_buffer_path: PathBuf,
    pub spill_path: PathBuf,
    pub forensic_path: PathBuf,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            state_root: PathBuf::from("/var/lib/aegis"),
            config_path: PathBuf::from("/etc/aegis/agent.toml"),
            agent_db_path: PathBuf::from("/var/lib/aegis/agent.db"),
            ring_buffer_path: PathBuf::from("/var/lib/aegis/ring-buffer"),
            spill_path: PathBuf::from("/var/lib/aegis/spill"),
            forensic_path: PathBuf::from("/var/lib/aegis/forensics"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentConfig {
    pub conf_version: u32,
    pub compatibility: ConfVersion,
    pub agent_id: String,
    pub tenant_id: String,
    pub control_plane_url: String,
    pub policy_version: PolicyVersion,
    #[serde(default)]
    pub communication: CommunicationConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    pub runtime: RuntimeConfig,
    pub storage: StorageConfig,
}

pub type AppConfig = AgentConfig;

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            conf_version: CURRENT_CONF_VERSION,
            compatibility: ConfVersion::default(),
            agent_id: "local-agent".to_string(),
            tenant_id: "local-tenant".to_string(),
            control_plane_url: "https://127.0.0.1:7443".to_string(),
            policy_version: PolicyVersion::default(),
            communication: CommunicationConfig::default(),
            security: SecurityConfig::default(),
            runtime: RuntimeConfig::default(),
            storage: StorageConfig::default(),
        }
    }
}

impl AgentConfig {
    pub fn load_from_file(path: &Path) -> Result<Self, CoreError> {
        let raw = fs::read_to_string(path)?;
        let config = Self::from_toml_str(&raw)?;
        Ok(config)
    }

    pub fn from_toml_str(raw: &str) -> Result<Self, CoreError> {
        let config = toml::from_str::<Self>(raw)?;
        config.validate()?;
        Ok(config)
    }

    pub fn to_toml_string(&self) -> Result<String, CoreError> {
        self.validate()?;
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn validate(&self) -> Result<(), CoreError> {
        let supported = &self.compatibility;
        if self.conf_version < supported.min_supported || self.conf_version > supported.current {
            return Err(CoreError::UnsupportedConfigVersion {
                found: self.conf_version,
                min_supported: supported.min_supported,
                current: supported.current,
            });
        }
        let has_enabled_transport = self.communication.grpc.enabled
            || self.communication.websocket.enabled
            || self.communication.long_polling.enabled
            || self.communication.domain_fronting.enabled;
        if !self.communication.development_allow_loopback && !has_enabled_transport {
            return Err(CoreError::ChannelBootstrap(
                "communication config must enable at least one transport when loopback is disabled"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn heartbeat_interval(&self) -> Duration {
        Duration::from_secs(self.runtime.heartbeat_interval_secs)
    }

    pub fn shutdown_grace_period(&self) -> Duration {
        Duration::from_secs(self.runtime.shutdown_grace_period_secs)
    }

    pub fn with_state_root(mut self, state_root: PathBuf) -> Self {
        self.storage.state_root = state_root.clone();
        self.storage.config_path = state_root.join("agent.toml");
        self.storage.agent_db_path = state_root.join("agent.db");
        self.storage.ring_buffer_path = state_root.join("ring-buffer");
        self.storage.spill_path = state_root.join("spill");
        self.storage.forensic_path = state_root.join("forensics");
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentConfig, CURRENT_CONF_VERSION};
    use std::path::PathBuf;

    #[test]
    fn config_toml_roundtrip_preserves_versions() {
        let config = AgentConfig::default();
        let raw = config.to_toml_string().expect("serialize config");
        let restored = AgentConfig::from_toml_str(&raw).expect("parse config");

        assert_eq!(restored.conf_version, CURRENT_CONF_VERSION);
        assert_eq!(restored.policy_version.policy_bundle, 1);
        assert_eq!(restored.storage.agent_db_path, config.storage.agent_db_path);
        assert!(!restored.communication.development_allow_loopback);
        assert!(restored.security.use_os_credential_store);
        assert!(restored.security.linux_tpm_tools_dir.is_none());
        assert!(restored.security.linux_tpm_device_path.is_none());
        assert!(restored
            .security
            .linux_tpm_master_key_sealed_object_path
            .is_none());
        assert!(restored.security.linux_tpm_master_key_pcrs.is_none());
        assert!(restored.security.linux_tpm_attestation_ak_path.is_none());
        assert!(restored.security.linux_tpm_attestation_pcrs.is_none());
        assert!(restored.security.linux_tpm_master_key_nv_index.is_none());
        assert!(restored.security.linux_tpm_rollback_nv_index.is_none());
        assert!(!restored.security.linux_tpm_auto_provision_nv);
    }

    #[test]
    fn reject_unsupported_config_versions() {
        let raw = r#"
conf_version = 0
agent_id = "sensor-a"
tenant_id = "tenant-a"
control_plane_url = "https://sensor.example"

[compatibility]
current = 1
min_supported = 1

[policy_version]
policy_bundle = 1
ruleset_revision = 1
model_revision = 1

[communication]
failure_threshold = 3
development_allow_loopback = true

[communication.grpc]
enabled = true
endpoint = "http://127.0.0.1:7443"

[communication.websocket]
enabled = true
endpoint = "ws://127.0.0.1:7444/ws"

[communication.long_polling]
enabled = true
uplink_url = "http://127.0.0.1:7445/uplink"
heartbeat_url = "http://127.0.0.1:7445/heartbeat"
downlink_url = "http://127.0.0.1:7445/downlink"
probe_url = "http://127.0.0.1:7445/probe"
timeout_ms = 2000

[communication.domain_fronting]
enabled = false
uplink_url = "http://127.0.0.1:7446/uplink"
heartbeat_url = "http://127.0.0.1:7446/heartbeat"
downlink_url = "http://127.0.0.1:7446/downlink"
probe_url = "http://127.0.0.1:7446/probe"
timeout_ms = 5000
front_domain = "cdn.example.com"
host_header = "control-plane.aegis.local"

[runtime]
heartbeat_interval_secs = 60
shutdown_grace_period_secs = 15

[storage]
state_root = "/var/lib/aegis"
config_path = "/etc/aegis/agent.toml"
agent_db_path = "/var/lib/aegis/agent.db"
ring_buffer_path = "/var/lib/aegis/ring-buffer"
spill_path = "/var/lib/aegis/spill"
forensic_path = "/var/lib/aegis/forensics"
"#;

        let error = AgentConfig::from_toml_str(raw).expect_err("config version must fail");
        assert!(error.to_string().contains("unsupported config version"));
    }

    #[test]
    fn with_state_root_rebinds_storage_paths() {
        let config = AgentConfig::default().with_state_root(PathBuf::from("/tmp/aegis-dev"));

        assert_eq!(config.storage.state_root, PathBuf::from("/tmp/aegis-dev"));
        assert_eq!(
            config.storage.agent_db_path,
            PathBuf::from("/tmp/aegis-dev/agent.db")
        );
        assert_eq!(
            config.storage.forensic_path,
            PathBuf::from("/tmp/aegis-dev/forensics")
        );
    }
}
