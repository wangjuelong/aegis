use aegis_model::PluginHealthStatus;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginManifest {
    pub plugin_id: String,
    pub module_path: PathBuf,
    pub expected_sha256: String,
    pub timeout_ms: u64,
    pub max_crash_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PluginRuntimeState {
    Loaded,
    Running,
    TimedOut,
    Crashed,
    Disabled,
}

impl PluginRuntimeState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::Running => "running",
            Self::TimedOut => "timed_out",
            Self::Crashed => "crashed",
            Self::Disabled => "disabled",
        }
    }

    fn healthy(self) -> bool {
        matches!(self, Self::Loaded | Self::Running)
    }
}

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq)]
pub enum PluginHostError {
    #[error("failed to read wasm module: {0}")]
    Io(String),
    #[error("invalid wasm header")]
    InvalidWasmHeader,
    #[error("wasm module hash mismatch")]
    HashMismatch,
    #[error("plugin {0} not registered")]
    PluginNotFound(String),
    #[error("plugin {0} disabled after repeated failures")]
    PluginDisabled(String),
    #[error("plugin {0} exceeded timeout budget")]
    TimedOut(String),
    #[error("plugin crashed: {0}")]
    Crashed(String),
}

impl From<std::io::Error> for PluginHostError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PluginRecord {
    manifest: PluginManifest,
    crash_count: u32,
    state: PluginRuntimeState,
    last_error: Option<String>,
}

pub trait PluginExecutor: Send + Sync {
    fn run(&self, manifest: &PluginManifest) -> Result<(), PluginHostError>;
}

#[derive(Default)]
pub struct WasmPluginExecutor;

impl PluginExecutor for WasmPluginExecutor {
    fn run(&self, manifest: &PluginManifest) -> Result<(), PluginHostError> {
        validate_wasm_module(&manifest.module_path, &manifest.expected_sha256)
    }
}

pub struct PluginHost<E = WasmPluginExecutor> {
    executor: E,
    plugins: HashMap<String, PluginRecord>,
}

impl Default for PluginHost<WasmPluginExecutor> {
    fn default() -> Self {
        Self::new(WasmPluginExecutor)
    }
}

impl<E: PluginExecutor> PluginHost<E> {
    pub fn new(executor: E) -> Self {
        Self {
            executor,
            plugins: HashMap::new(),
        }
    }

    pub fn register(&mut self, mut manifest: PluginManifest) -> Result<(), PluginHostError> {
        validate_wasm_module(&manifest.module_path, &manifest.expected_sha256)?;
        manifest.timeout_ms = manifest.timeout_ms.max(1);
        manifest.max_crash_count = manifest.max_crash_count.max(1);
        self.plugins.insert(
            manifest.plugin_id.clone(),
            PluginRecord {
                manifest,
                crash_count: 0,
                state: PluginRuntimeState::Loaded,
                last_error: None,
            },
        );
        Ok(())
    }

    pub fn run_once(&mut self, plugin_id: &str) -> Result<PluginHealthStatus, PluginHostError> {
        let record = self
            .plugins
            .get_mut(plugin_id)
            .ok_or_else(|| PluginHostError::PluginNotFound(plugin_id.to_string()))?;
        if record.state == PluginRuntimeState::Disabled {
            return Err(PluginHostError::PluginDisabled(plugin_id.to_string()));
        }

        record.state = PluginRuntimeState::Running;
        match self.executor.run(&record.manifest) {
            Ok(()) => {
                record.state = PluginRuntimeState::Loaded;
                record.last_error = None;
            }
            Err(error @ PluginHostError::TimedOut(_)) => {
                Self::record_failure(record, error, PluginRuntimeState::TimedOut);
            }
            Err(error) => {
                Self::record_failure(record, error, PluginRuntimeState::Crashed);
            }
        }

        Ok(Self::status_from_record(record))
    }

    pub fn status(&self, plugin_id: &str) -> Result<PluginHealthStatus, PluginHostError> {
        let record = self
            .plugins
            .get(plugin_id)
            .ok_or_else(|| PluginHostError::PluginNotFound(plugin_id.to_string()))?;
        Ok(Self::status_from_record(record))
    }

    pub fn statuses(&self) -> Vec<PluginHealthStatus> {
        let mut items = self
            .plugins
            .values()
            .map(Self::status_from_record)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
        items
    }

    fn record_failure(
        record: &mut PluginRecord,
        error: PluginHostError,
        failure_state: PluginRuntimeState,
    ) {
        record.crash_count = record.crash_count.saturating_add(1);
        record.last_error = Some(error.to_string());
        if record.crash_count >= record.manifest.max_crash_count {
            record.state = PluginRuntimeState::Disabled;
        } else {
            record.state = failure_state;
        }
    }

    fn status_from_record(record: &PluginRecord) -> PluginHealthStatus {
        PluginHealthStatus {
            plugin_id: record.manifest.plugin_id.clone(),
            healthy: record.state.healthy(),
            state: record.state.as_str().to_string(),
            crash_count: record.crash_count,
        }
    }
}

fn validate_wasm_module(path: &Path, expected_sha256: &str) -> Result<(), PluginHostError> {
    let bytes = fs::read(path)?;
    if bytes.len() < 8 || &bytes[..4] != b"\0asm" {
        return Err(PluginHostError::InvalidWasmHeader);
    }
    let actual_sha256 = hex::encode(Sha256::digest(&bytes));
    if actual_sha256 != expected_sha256 {
        return Err(PluginHostError::HashMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PluginExecutor, PluginHost, PluginHostError, PluginManifest};
    use sha2::{Digest, Sha256};
    use std::collections::VecDeque;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use uuid::Uuid;

    struct MockExecutor {
        outcomes: Mutex<VecDeque<Result<(), PluginHostError>>>,
    }

    impl MockExecutor {
        fn new(outcomes: Vec<Result<(), PluginHostError>>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into()),
            }
        }
    }

    impl PluginExecutor for MockExecutor {
        fn run(&self, _manifest: &PluginManifest) -> Result<(), PluginHostError> {
            self.outcomes
                .lock()
                .expect("lock outcomes")
                .pop_front()
                .unwrap_or(Ok(()))
        }
    }

    fn temp_wasm_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("aegis-{name}-{}.wasm", Uuid::now_v7()))
    }

    fn write_wasm_fixture(path: &PathBuf) -> String {
        let bytes = b"\0asm\x01\0\0\0";
        fs::write(path, bytes).expect("write wasm fixture");
        hex::encode(Sha256::digest(bytes))
    }

    fn manifest(path: PathBuf, expected_sha256: String, max_crash_count: u32) -> PluginManifest {
        PluginManifest {
            plugin_id: "runtime-audit".to_string(),
            module_path: path,
            expected_sha256,
            timeout_ms: 250,
            max_crash_count,
        }
    }

    #[test]
    fn plugin_host_marks_timeout_and_exposes_unhealthy_status() {
        let path = temp_wasm_path("plugin-timeout");
        let checksum = write_wasm_fixture(&path);
        let executor = MockExecutor::new(vec![Err(PluginHostError::TimedOut(
            "runtime-audit".to_string(),
        ))]);
        let mut host = PluginHost::new(executor);
        host.register(manifest(path.clone(), checksum, 3))
            .expect("register plugin");

        let status = host.run_once("runtime-audit").expect("run plugin");

        assert!(!status.healthy);
        assert_eq!(status.state, "timed_out");
        assert_eq!(status.crash_count, 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn plugin_host_disables_plugin_after_repeated_crashes() {
        let path = temp_wasm_path("plugin-crash");
        let checksum = write_wasm_fixture(&path);
        let executor = MockExecutor::new(vec![
            Err(PluginHostError::Crashed("trap".to_string())),
            Err(PluginHostError::Crashed("trap".to_string())),
        ]);
        let mut host = PluginHost::new(executor);
        host.register(manifest(path.clone(), checksum, 2))
            .expect("register plugin");

        let first = host.run_once("runtime-audit").expect("first run");
        let second = host.run_once("runtime-audit").expect("second run");

        assert_eq!(first.state, "crashed");
        assert_eq!(first.crash_count, 1);
        assert_eq!(second.state, "disabled");
        assert_eq!(second.crash_count, 2);
        assert!(!host.status("runtime-audit").expect("plugin status").healthy);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn plugin_host_rejects_non_wasm_modules() {
        let path = temp_wasm_path("plugin-invalid");
        fs::write(&path, b"not-wasm").expect("write invalid bytes");
        let checksum = hex::encode(Sha256::digest(b"not-wasm"));
        let mut host = PluginHost::default();

        let result = host.register(manifest(path.clone(), checksum, 2));

        assert!(matches!(result, Err(PluginHostError::InvalidWasmHeader)));
        let _ = fs::remove_file(path);
    }
}
