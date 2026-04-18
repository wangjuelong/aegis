use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub agent_id: String,
    pub tenant_id: String,
    pub ring_buffer_path: PathBuf,
    pub heartbeat_interval: Duration,
    pub config_path: PathBuf,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            agent_id: "local-agent".to_string(),
            tenant_id: "local-tenant".to_string(),
            ring_buffer_path: PathBuf::from("/var/lib/aegis/ring-buffer"),
            heartbeat_interval: Duration::from_secs(60),
            config_path: PathBuf::from("/etc/aegis/agent.toml"),
        }
    }
}

