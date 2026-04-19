use aegis_model::PluginHealthStatus;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use wasmtime::{Config, Engine, Instance, Module, Store};

const PLUGIN_FUEL_PER_MS: u64 = 50_000;
const PLUGIN_MIN_FUEL: u64 = 100_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
    #[error("invalid plugin manifest: {0}")]
    ManifestParse(String),
    #[error("invalid wasm header")]
    InvalidWasmHeader,
    #[error("wasm module hash mismatch")]
    HashMismatch,
    #[error("invalid wasm module: {0}")]
    InvalidWasmModule(String),
    #[error("plugin {0} missing run entrypoint")]
    MissingEntrypoint(String),
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
    module_bytes: Vec<u8>,
    crash_count: u32,
    state: PluginRuntimeState,
    last_error: Option<String>,
}

pub trait PluginExecutor: Send + Sync {
    fn validate(
        &self,
        _manifest: &PluginManifest,
        _module_bytes: &[u8],
    ) -> Result<(), PluginHostError> {
        Ok(())
    }

    fn run(&self, manifest: &PluginManifest, module_bytes: &[u8]) -> Result<(), PluginHostError>;
}

pub struct WasmPluginExecutor {
    engine: Engine,
}

impl Default for WasmPluginExecutor {
    fn default() -> Self {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).expect("failed to initialize wasmtime engine");
        Self { engine }
    }
}

impl PluginExecutor for WasmPluginExecutor {
    fn validate(
        &self,
        _manifest: &PluginManifest,
        module_bytes: &[u8],
    ) -> Result<(), PluginHostError> {
        Module::new(&self.engine, module_bytes)
            .map(|_| ())
            .map_err(|error| PluginHostError::InvalidWasmModule(error.to_string()))
    }

    fn run(&self, manifest: &PluginManifest, module_bytes: &[u8]) -> Result<(), PluginHostError> {
        let module = Module::new(&self.engine, module_bytes)
            .map_err(|error| PluginHostError::InvalidWasmModule(error.to_string()))?;
        let mut store = Store::new(&self.engine, ());
        store
            .set_fuel(plugin_fuel_budget(manifest.timeout_ms))
            .map_err(|error| PluginHostError::Crashed(error.to_string()))?;
        let instance = Instance::new(&mut store, &module, &[]).map_err(|error| {
            map_runtime_error(
                &manifest.plugin_id,
                store.get_fuel().ok(),
                error.to_string(),
            )
        })?;

        if let Ok(run) = instance.get_typed_func::<(), ()>(&mut store, "run") {
            run.call(&mut store, ()).map_err(|error| {
                map_runtime_error(
                    &manifest.plugin_id,
                    store.get_fuel().ok(),
                    error.to_string(),
                )
            })?;
            return Ok(());
        }

        if let Ok(run) = instance.get_typed_func::<(), i32>(&mut store, "run") {
            let exit_code = run.call(&mut store, ()).map_err(|error| {
                map_runtime_error(
                    &manifest.plugin_id,
                    store.get_fuel().ok(),
                    error.to_string(),
                )
            })?;
            if exit_code == 0 {
                return Ok(());
            }
            return Err(PluginHostError::Crashed(format!(
                "plugin {} returned non-zero status {}",
                manifest.plugin_id, exit_code
            )));
        }

        Err(PluginHostError::MissingEntrypoint(
            manifest.plugin_id.clone(),
        ))
    }
}

pub struct PluginHost<E = WasmPluginExecutor> {
    executor: E,
    plugins: HashMap<String, PluginRecord>,
}

impl Default for PluginHost<WasmPluginExecutor> {
    fn default() -> Self {
        Self::new(WasmPluginExecutor::default())
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
        let module_bytes =
            read_validated_wasm_module(&manifest.module_path, &manifest.expected_sha256)?;
        self.executor.validate(&manifest, &module_bytes)?;
        manifest.timeout_ms = manifest.timeout_ms.max(1);
        manifest.max_crash_count = manifest.max_crash_count.max(1);
        self.plugins.insert(
            manifest.plugin_id.clone(),
            PluginRecord {
                manifest,
                module_bytes,
                crash_count: 0,
                state: PluginRuntimeState::Loaded,
                last_error: None,
            },
        );
        Ok(())
    }

    pub fn load_manifests_from_dir(&mut self, manifest_dir: &Path) -> Result<(), PluginHostError> {
        if !manifest_dir.exists() {
            return Ok(());
        }

        let mut manifest_paths = fs::read_dir(manifest_dir)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("toml"))
            .collect::<Vec<_>>();
        manifest_paths.sort();

        for manifest_path in manifest_paths {
            self.register(load_manifest_from_file(&manifest_path)?)?;
        }
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
        match self.executor.run(&record.manifest, &record.module_bytes) {
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

    pub fn run_all_once(&mut self) -> Vec<PluginHealthStatus> {
        let mut plugin_ids = self.plugins.keys().cloned().collect::<Vec<_>>();
        plugin_ids.sort();

        plugin_ids
            .into_iter()
            .filter_map(|plugin_id| match self.run_once(&plugin_id) {
                Ok(status) => Some(status),
                Err(_) => self.status(&plugin_id).ok(),
            })
            .collect()
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

fn load_manifest_from_file(path: &Path) -> Result<PluginManifest, PluginHostError> {
    let raw = fs::read_to_string(path)?;
    let mut manifest = toml::from_str::<PluginManifest>(&raw)
        .map_err(|error| PluginHostError::ManifestParse(error.to_string()))?;
    if manifest.module_path.is_relative() {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        manifest.module_path = parent.join(&manifest.module_path);
    }
    Ok(manifest)
}

fn read_validated_wasm_module(
    path: &Path,
    expected_sha256: &str,
) -> Result<Vec<u8>, PluginHostError> {
    let bytes = fs::read(path)?;
    if bytes.len() < 8 || &bytes[..4] != b"\0asm" {
        return Err(PluginHostError::InvalidWasmHeader);
    }
    let actual_sha256 = hex::encode(Sha256::digest(&bytes));
    if actual_sha256 != expected_sha256 {
        return Err(PluginHostError::HashMismatch);
    }
    Ok(bytes)
}

fn plugin_fuel_budget(timeout_ms: u64) -> u64 {
    timeout_ms
        .max(1)
        .saturating_mul(PLUGIN_FUEL_PER_MS)
        .max(PLUGIN_MIN_FUEL)
}

fn map_runtime_error(
    plugin_id: &str,
    remaining_fuel: Option<u64>,
    detail: String,
) -> PluginHostError {
    let normalized = detail.to_ascii_lowercase();
    if remaining_fuel == Some(0)
        || normalized.contains("fuel")
        || normalized.contains("out of fuel")
    {
        return PluginHostError::TimedOut(plugin_id.to_string());
    }
    PluginHostError::Crashed(detail)
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
        fn run(
            &self,
            _manifest: &PluginManifest,
            _module_bytes: &[u8],
        ) -> Result<(), PluginHostError> {
            self.outcomes
                .lock()
                .expect("lock outcomes")
                .pop_front()
                .unwrap_or(Ok(()))
        }
    }

    fn temp_fixture_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("aegis-plugin-{name}-{}", Uuid::now_v7()))
    }

    fn temp_wasm_path(name: &str) -> PathBuf {
        temp_fixture_root(name).join("plugin.wasm")
    }

    fn write_wasm_fixture(path: &PathBuf) -> String {
        let bytes = b"\0asm\x01\0\0\0";
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create fixture parent");
        }
        fs::write(path, bytes).expect("write wasm fixture");
        hex::encode(Sha256::digest(bytes))
    }

    fn write_wat_fixture(path: &PathBuf, wat_source: &str) -> String {
        let bytes = wat::parse_str(wat_source).expect("parse wat");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create fixture parent");
        }
        fs::write(path, &bytes).expect("write wat fixture");
        hex::encode(Sha256::digest(&bytes))
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
        let _ = fs::remove_dir_all(path.parent().expect("fixture parent"));
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
        let _ = fs::remove_dir_all(path.parent().expect("fixture parent"));
    }

    #[test]
    fn plugin_host_rejects_non_wasm_modules() {
        let path = temp_wasm_path("plugin-invalid");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create fixture parent");
        }
        fs::write(&path, b"not-wasm").expect("write invalid bytes");
        let checksum = hex::encode(Sha256::digest(b"not-wasm"));
        let mut host = PluginHost::default();

        let result = host.register(manifest(path.clone(), checksum, 2));

        assert!(matches!(result, Err(PluginHostError::InvalidWasmHeader)));
        let _ = fs::remove_dir_all(path.parent().expect("fixture parent"));
    }

    #[test]
    fn plugin_host_executes_real_wasm_module() {
        let path = temp_wasm_path("plugin-real-ok");
        let checksum = write_wat_fixture(&path, r#"(module (func (export "run")))"#);
        let mut host = PluginHost::default();
        host.register(manifest(path.clone(), checksum, 2))
            .expect("register plugin");

        let status = host.run_once("runtime-audit").expect("run plugin");

        assert!(status.healthy);
        assert_eq!(status.state, "loaded");
        assert_eq!(status.crash_count, 0);
        let _ = fs::remove_dir_all(path.parent().expect("fixture parent"));
    }

    #[test]
    fn plugin_host_maps_wasm_trap_to_crash() {
        let path = temp_wasm_path("plugin-real-trap");
        let checksum = write_wat_fixture(&path, r#"(module (func (export "run") unreachable))"#);
        let mut host = PluginHost::default();
        host.register(manifest(path.clone(), checksum, 2))
            .expect("register plugin");

        let status = host.run_once("runtime-audit").expect("run plugin");

        assert!(!status.healthy);
        assert_eq!(status.state, "crashed");
        assert_eq!(status.crash_count, 1);
        let _ = fs::remove_dir_all(path.parent().expect("fixture parent"));
    }

    #[test]
    fn plugin_host_times_out_infinite_wasm_loop() {
        let path = temp_wasm_path("plugin-real-timeout");
        let checksum = write_wat_fixture(
            &path,
            r#"(module (func (export "run") (loop $spin br $spin)))"#,
        );
        let mut host = PluginHost::default();
        host.register(manifest(path.clone(), checksum, 2))
            .expect("register plugin");

        let status = host.run_once("runtime-audit").expect("run plugin");

        assert!(!status.healthy);
        assert_eq!(status.state, "timed_out");
        assert_eq!(status.crash_count, 1);
        let _ = fs::remove_dir_all(path.parent().expect("fixture parent"));
    }

    #[test]
    fn plugin_host_loads_manifests_from_directory() {
        let fixture_root = temp_fixture_root("manifest-dir");
        let module_path = fixture_root.join("runtime-audit.wasm");
        let checksum = write_wat_fixture(&module_path, r#"(module (func (export "run")))"#);
        let manifest_path = fixture_root.join("runtime-audit.toml");
        let manifest = PluginManifest {
            plugin_id: "runtime-audit".to_string(),
            module_path: PathBuf::from("runtime-audit.wasm"),
            expected_sha256: checksum,
            timeout_ms: 250,
            max_crash_count: 2,
        };
        fs::write(
            &manifest_path,
            toml::to_string(&manifest).expect("serialize manifest"),
        )
        .expect("write manifest");

        let mut host = PluginHost::default();
        host.load_manifests_from_dir(&fixture_root)
            .expect("load manifests");
        let statuses = host.run_all_once();

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].plugin_id, "runtime-audit");
        assert!(statuses[0].healthy);
        let _ = fs::remove_dir_all(fixture_root);
    }
}
