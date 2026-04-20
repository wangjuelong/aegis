use crate::traits::{
    BlockLease, KernelIntegrity, KernelTransport, PlatformDescriptor, PlatformExecutionSnapshot,
    PlatformHealthSnapshot, PlatformProtection, PlatformResponse, PlatformRuntime, PlatformSensor,
    PlatformTarget, PreemptiveBlock,
};
use aegis_model::{
    AmsiStatus, ArtifactBundle, BpfStatus, EtwStatus, EventBuffer, ForensicSpec, IntegrityReport,
    IsolationRulesV2, NetworkTarget, QuarantineReceipt, RollbackTarget, SensorCapabilities,
    SensorConfig, SuspiciousProcess,
};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsProviderKind {
    EtwProcess,
    PsProcess,
    ObProcess,
    MinifilterFile,
    WfpNetwork,
    RegistryCallback,
    AmsiScript,
    MemorySensor,
    IpcSensor,
    ModuleLoadSensor,
    SnapshotProtection,
    DeviceControl,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsEventStub {
    pub provider: WindowsProviderKind,
    pub operation: String,
    pub subject: String,
}

impl WindowsEventStub {
    fn encode(&self) -> Vec<u8> {
        format!(
            "windows|{:?}|{}|{}",
            self.provider, self.operation, self.subject
        )
        .into_bytes()
    }
}

trait WindowsCommandRunner: Send + Sync {
    fn mode_name(&self) -> &'static str;
    fn run_powershell(&self, script: &str) -> Result<String>;
}

struct UnavailableWindowsRunner {
    reason: String,
}

impl UnavailableWindowsRunner {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl WindowsCommandRunner for UnavailableWindowsRunner {
    fn mode_name(&self) -> &'static str {
        "unavailable"
    }

    fn run_powershell(&self, _script: &str) -> Result<String> {
        bail!("{}", self.reason);
    }
}

struct LocalWindowsRunner;

impl WindowsCommandRunner for LocalWindowsRunner {
    fn mode_name(&self) -> &'static str {
        "local"
    }

    fn run_powershell(&self, script: &str) -> Result<String> {
        run_local_powershell(script)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WindowsSshConfig {
    host: String,
    user: String,
    password: String,
    port: u16,
}

impl WindowsSshConfig {
    fn from_env() -> Option<Self> {
        let host = std::env::var("AEGIS_WINDOWS_HOST").ok()?;
        let user = std::env::var("AEGIS_WINDOWS_USER").ok()?;
        let password = std::env::var("AEGIS_WINDOWS_PASSWORD").ok()?;
        let port = std::env::var("AEGIS_WINDOWS_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(22);
        Some(Self {
            host,
            user,
            password,
            port,
        })
    }
}

struct SshWindowsRunner {
    config: WindowsSshConfig,
}

impl SshWindowsRunner {
    fn new(config: WindowsSshConfig) -> Self {
        Self { config }
    }
}

impl WindowsCommandRunner for SshWindowsRunner {
    fn mode_name(&self) -> &'static str {
        "ssh"
    }

    fn run_powershell(&self, script: &str) -> Result<String> {
        let encoded = encode_powershell_script(script);
        let remote_command = format!(
            "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"
        );
        let output = Command::new("sshpass")
            .arg("-p")
            .arg(&self.config.password)
            .arg("ssh")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null")
            .arg("-o")
            .arg("LogLevel=ERROR")
            .arg("-p")
            .arg(self.config.port.to_string())
            .arg(format!("{}@{}", self.config.user, self.config.host))
            .arg(remote_command)
            .output()
            .with_context(|| format!("ssh to windows host {}", self.config.host))?;
        decode_command_output(output, "run powershell over ssh")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct WindowsHostCapabilities {
    reachable: bool,
    running_on_windows: bool,
    execution_mode: String,
    computer_name: Option<String>,
    user_name: Option<String>,
    is_admin: bool,
    has_process_inventory: bool,
    has_security_log: bool,
    has_powershell_log: bool,
    has_wmi_log: bool,
    has_task_scheduler_log: bool,
    has_sysmon_log: bool,
    has_process_creation_events: bool,
    has_net_connection: bool,
    has_firewall: bool,
    has_registry_cli: bool,
    has_amsi_runtime: bool,
    has_script_block_logging: bool,
    has_named_pipe_inventory: bool,
    has_module_inventory: bool,
    has_vss_inventory: bool,
    has_device_inventory: bool,
    last_error: Option<String>,
}

impl WindowsHostCapabilities {
    fn any_event_log(&self) -> bool {
        self.has_security_log
            || self.has_powershell_log
            || self.has_wmi_log
            || self.has_task_scheduler_log
            || self.has_sysmon_log
    }

    fn provider_health(&self, provider: WindowsProviderKind, running: bool) -> bool {
        if !running || !self.reachable || !self.running_on_windows {
            return false;
        }

        match provider {
            WindowsProviderKind::EtwProcess => {
                self.any_event_log() && self.has_process_creation_events
            }
            WindowsProviderKind::PsProcess => self.has_process_inventory,
            WindowsProviderKind::ObProcess => false,
            WindowsProviderKind::MinifilterFile => false,
            WindowsProviderKind::WfpNetwork => self.has_net_connection,
            WindowsProviderKind::RegistryCallback => false,
            WindowsProviderKind::AmsiScript => {
                self.has_amsi_runtime && self.has_script_block_logging
            }
            WindowsProviderKind::MemorySensor => false,
            WindowsProviderKind::IpcSensor => self.has_named_pipe_inventory,
            WindowsProviderKind::ModuleLoadSensor => self.has_module_inventory,
            WindowsProviderKind::SnapshotProtection => self.has_vss_inventory,
            WindowsProviderKind::DeviceControl => self.has_device_inventory,
        }
    }

    fn summary(&self) -> String {
        if !self.reachable {
            return self
                .last_error
                .clone()
                .unwrap_or_else(|| "windows host unavailable".to_string());
        }

        let mut facts = vec![format!("mode={}", self.execution_mode)];
        if let Some(name) = &self.computer_name {
            facts.push(format!("computer={name}"));
        }
        if let Some(user) = &self.user_name {
            facts.push(format!("user={user}"));
        }
        facts.push(format!("admin={}", self.is_admin));
        facts.push(format!("process_inventory={}", self.has_process_inventory));
        facts.push(format!("event_logs={}", self.any_event_log()));
        facts.push(format!(
            "process_creation_audit={}",
            self.has_process_creation_events
        ));
        facts.push(format!("amsi_runtime={}", self.has_amsi_runtime));
        facts.push(format!(
            "script_block_logging={}",
            self.has_script_block_logging
        ));
        facts.join(", ")
    }
}

#[derive(Clone, Debug, Deserialize)]
struct WindowsCapabilityProbe {
    #[serde(default)]
    computer_name: Option<String>,
    #[serde(default)]
    user_name: Option<String>,
    is_admin: bool,
    has_process_inventory: bool,
    has_security_log: bool,
    has_powershell_log: bool,
    has_wmi_log: bool,
    has_task_scheduler_log: bool,
    has_sysmon_log: bool,
    has_process_creation_events: bool,
    has_net_connection: bool,
    has_firewall: bool,
    has_registry_cli: bool,
    has_amsi_runtime: bool,
    has_script_block_logging: bool,
    has_named_pipe_inventory: bool,
    has_module_inventory: bool,
    has_vss_inventory: bool,
    has_device_inventory: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsProcessSnapshot {
    process_id: u32,
    parent_process_id: u32,
    name: String,
    #[serde(default)]
    command_line: Option<String>,
}

impl WindowsProcessSnapshot {
    fn start_subject(&self) -> String {
        truncate_subject(&format!(
            "pid={};ppid={};name={};cmdline={}",
            self.process_id,
            self.parent_process_id,
            self.name,
            self.command_line.as_deref().unwrap_or("-")
        ))
    }

    fn exit_subject(&self) -> String {
        truncate_subject(&format!("pid={};name={}", self.process_id, self.name))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsTasklistSnapshot {
    process_id: u32,
    image_name: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsProcessAuditCursor {
    record_id: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsSecurityProcessEvent {
    record_id: u64,
    #[serde(default)]
    process_name: Option<String>,
    #[serde(default)]
    command_line: Option<String>,
}

impl WindowsSecurityProcessEvent {
    fn subject(&self) -> String {
        truncate_subject(&format!(
            "record_id={};process={};cmdline={}",
            self.record_id,
            self.process_name.as_deref().unwrap_or("-"),
            self.command_line.as_deref().unwrap_or("-")
        ))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsNetworkConnection {
    protocol: String,
    local_address: String,
    local_port: u16,
    #[serde(default)]
    remote_address: Option<String>,
    #[serde(default)]
    remote_port: Option<u16>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    owning_process: Option<u32>,
}

impl WindowsNetworkConnection {
    fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.protocol,
            self.local_address,
            self.local_port,
            self.remote_address.as_deref().unwrap_or("-"),
            self.remote_port
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.state.as_deref().unwrap_or("-"),
            self.owning_process
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string())
        )
    }

    fn subject(&self) -> String {
        truncate_subject(&format!(
            "protocol={};local={}:{};remote={}:{};state={};pid={}",
            self.protocol,
            self.local_address,
            self.local_port,
            self.remote_address.as_deref().unwrap_or("-"),
            self.remote_port
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.state.as_deref().unwrap_or("-"),
            self.owning_process
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string())
        ))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsFirewallIsolationReceipt {
    backup_path: String,
    rule_group: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsNamedPipeSnapshot {
    pipe_name: String,
}

impl WindowsNamedPipeSnapshot {
    fn subject(&self) -> String {
        truncate_subject(&format!("pipe={}", self.pipe_name))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsModuleSnapshot {
    process_id: u32,
    process_name: String,
    module_path: String,
}

impl WindowsModuleSnapshot {
    fn key(&self) -> String {
        format!(
            "{}|{}|{}",
            self.process_id, self.process_name, self.module_path
        )
    }

    fn subject(&self) -> String {
        truncate_subject(&format!(
            "pid={};process={};module={}",
            self.process_id, self.process_name, self.module_path
        ))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsVssSnapshot {
    snapshot_id: String,
    #[serde(default)]
    volume_name: Option<String>,
}

impl WindowsVssSnapshot {
    fn subject(&self) -> String {
        truncate_subject(&format!(
            "snapshot_id={};volume={}",
            self.snapshot_id,
            self.volume_name.as_deref().unwrap_or("-")
        ))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsDeviceSnapshot {
    instance_id: String,
    #[serde(default)]
    class: Option<String>,
    #[serde(default)]
    friendly_name: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

impl WindowsDeviceSnapshot {
    fn subject(&self) -> String {
        truncate_subject(&format!(
            "instance_id={};class={};friendly_name={};status={}",
            self.instance_id,
            self.class.as_deref().unwrap_or("-"),
            self.friendly_name.as_deref().unwrap_or("-"),
            self.status.as_deref().unwrap_or("-")
        ))
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct WindowsProtectionSurfaceArtifact {
    protected_paths: Vec<String>,
    registry_protection_surface: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct WindowsRegistryRollbackArtifact {
    selector: String,
    protected_paths: Vec<String>,
    registry_protection_surface: Vec<String>,
}

struct WindowsState {
    base_dir: PathBuf,
    pending_events: VecDeque<Vec<u8>>,
    execution: PlatformExecutionSnapshot,
    host: WindowsHostCapabilities,
    host_capabilities_pinned: bool,
    known_processes: BTreeMap<u32, WindowsProcessSnapshot>,
    security_process_cursor: Option<u64>,
    known_connections: BTreeMap<String, WindowsNetworkConnection>,
    known_named_pipes: BTreeMap<String, WindowsNamedPipeSnapshot>,
    known_modules: BTreeMap<String, WindowsModuleSnapshot>,
    known_vss_snapshots: BTreeMap<String, WindowsVssSnapshot>,
    known_devices: BTreeMap<String, WindowsDeviceSnapshot>,
    firewall_backup_path: Option<String>,
    firewall_rule_group: Option<String>,
}

pub struct WindowsPlatform {
    providers: Vec<WindowsProviderKind>,
    runner: Box<dyn WindowsCommandRunner>,
    state: Mutex<WindowsState>,
}

impl Default for WindowsPlatform {
    fn default() -> Self {
        Self::new_with_runner(detect_command_runner(), false)
    }
}

impl WindowsPlatform {
    fn new_with_runner(
        runner: Box<dyn WindowsCommandRunner>,
        host_capabilities_pinned: bool,
    ) -> Self {
        let execution_mode = runner.mode_name().to_string();
        Self {
            providers: vec![
                WindowsProviderKind::EtwProcess,
                WindowsProviderKind::PsProcess,
                WindowsProviderKind::ObProcess,
                WindowsProviderKind::MinifilterFile,
                WindowsProviderKind::WfpNetwork,
                WindowsProviderKind::RegistryCallback,
                WindowsProviderKind::AmsiScript,
                WindowsProviderKind::MemorySensor,
                WindowsProviderKind::IpcSensor,
                WindowsProviderKind::ModuleLoadSensor,
                WindowsProviderKind::SnapshotProtection,
                WindowsProviderKind::DeviceControl,
            ],
            runner,
            state: Mutex::new(WindowsState {
                base_dir: platform_root("windows"),
                pending_events: VecDeque::new(),
                execution: PlatformExecutionSnapshot::default(),
                host: WindowsHostCapabilities {
                    execution_mode,
                    ..WindowsHostCapabilities::default()
                },
                host_capabilities_pinned,
                known_processes: BTreeMap::new(),
                security_process_cursor: None,
                known_connections: BTreeMap::new(),
                known_named_pipes: BTreeMap::new(),
                known_modules: BTreeMap::new(),
                known_vss_snapshots: BTreeMap::new(),
                known_devices: BTreeMap::new(),
                firewall_backup_path: None,
                firewall_rule_group: None,
            }),
        }
    }

    #[cfg(test)]
    fn with_runner_for_test(
        runner: Box<dyn WindowsCommandRunner>,
        host: WindowsHostCapabilities,
    ) -> Self {
        let platform = Self::new_with_runner(runner, true);
        platform.state.lock().expect("windows state poisoned").host = host;
        platform
    }

    pub fn provider_kinds(&self) -> &[WindowsProviderKind] {
        &self.providers
    }

    pub fn execution_snapshot(&self) -> PlatformExecutionSnapshot {
        self.state
            .lock()
            .expect("windows state poisoned")
            .execution
            .clone()
    }

    fn host_capabilities(&self) -> WindowsHostCapabilities {
        self.state
            .lock()
            .expect("windows state poisoned")
            .host
            .clone()
    }

    pub fn health_snapshot(&self) -> PlatformHealthSnapshot {
        let state = self.state.lock().expect("windows state poisoned");
        let running = state.execution.running;
        let host = state.host.clone();
        PlatformHealthSnapshot {
            provider_health: self
                .providers
                .iter()
                .map(|provider| (format!("{provider:?}"), host.provider_health(*provider, running)))
                .collect(),
            integrity_reports: BTreeMap::from([
                (
                    "ssdt".to_string(),
                    kernel_report(
                        false,
                        format!(
                            "ssdt inspection requires kernel transport and is not implemented; {}",
                            host.summary()
                        ),
                    ),
                ),
                (
                    "callbacks".to_string(),
                    kernel_report(
                        false,
                        format!(
                            "callback table inspection requires kernel callbacks and is not implemented; {}",
                            host.summary()
                        ),
                    ),
                ),
                (
                    "kernel_code".to_string(),
                    kernel_report(
                        false,
                        format!(
                            "kernel code integrity inspection requires driver support and is not implemented; {}",
                            host.summary()
                        ),
                    ),
                ),
                (
                    "platform_protection".to_string(),
                    protection_report(&host),
                ),
                ("etw_ingest".to_string(), etw_report(&host)),
                ("amsi_script".to_string(), amsi_report(&host)),
            ]),
        }
    }

    pub fn inject_event(&self, event: WindowsEventStub) {
        let mut state = self.state.lock().expect("windows state poisoned");
        state.pending_events.push_back(event.encode());
    }
}

impl PlatformSensor for WindowsPlatform {
    fn start(&mut self, _config: &SensorConfig) -> Result<()> {
        let mut state = self.state.lock().expect("windows state poisoned");
        if !state.host_capabilities_pinned {
            state.host = probe_host_capabilities(self.runner.as_ref())
                .with_context(|| "probe windows host capabilities")?;
        }
        if state.host.has_process_inventory {
            state.known_processes = snapshot_process_inventory(self.runner.as_ref())
                .with_context(|| "snapshot initial windows process inventory")?;
        } else {
            state.known_processes.clear();
        }
        if state.host.has_process_creation_events {
            state.security_process_cursor = latest_process_audit_record_id(self.runner.as_ref())
                .with_context(|| "snapshot initial windows process audit cursor")?;
        } else {
            state.security_process_cursor = None;
        }
        if state.host.has_net_connection {
            state.known_connections = snapshot_network_inventory(self.runner.as_ref())
                .with_context(|| "snapshot initial windows network inventory")?;
        } else {
            state.known_connections.clear();
        }
        if state.host.has_named_pipe_inventory {
            state.known_named_pipes = snapshot_named_pipe_inventory(self.runner.as_ref())
                .with_context(|| "snapshot initial windows named pipe inventory")?;
        } else {
            state.known_named_pipes.clear();
        }
        if state.host.has_module_inventory {
            state.known_modules = snapshot_module_inventory(self.runner.as_ref())
                .with_context(|| "snapshot initial windows module inventory")?;
        } else {
            state.known_modules.clear();
        }
        if state.host.has_vss_inventory {
            state.known_vss_snapshots = snapshot_vss_inventory(self.runner.as_ref())
                .with_context(|| "snapshot initial windows vss inventory")?;
        } else {
            state.known_vss_snapshots.clear();
        }
        if state.host.has_device_inventory {
            state.known_devices = snapshot_device_inventory(self.runner.as_ref())
                .with_context(|| "snapshot initial windows device inventory")?;
        } else {
            state.known_devices.clear();
        }
        state.execution.running = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.state
            .lock()
            .expect("windows state poisoned")
            .execution
            .running = false;
        Ok(())
    }

    fn poll_events(&self, buf: &mut EventBuffer) -> Result<usize> {
        let mut state = self.state.lock().expect("windows state poisoned");
        if !state.execution.running {
            return Ok(0);
        }

        collect_live_windows_events(&mut state, self.runner.as_ref())?;

        let mut drained = 0usize;
        while let Some(event) = state.pending_events.pop_front() {
            buf.records.push(event);
            drained += 1;
        }
        Ok(drained)
    }

    fn capabilities(&self) -> SensorCapabilities {
        let host = self
            .state
            .lock()
            .expect("windows state poisoned")
            .host
            .clone();
        SensorCapabilities {
            process: host.has_process_inventory,
            file: false,
            network: host.has_net_connection,
            registry: false,
            auth: host.any_event_log(),
            script: false,
            memory: false,
            container: false,
        }
    }
}

impl PlatformResponse for WindowsPlatform {
    fn suspend_process(&self, pid: u32) -> Result<()> {
        let mut state = self.state.lock().expect("windows state poisoned");
        ensure_windows_response_host(&state.host, "suspend windows process")?;
        let script = build_windows_suspend_process_script(pid);
        write_windows_response_script(&mut state, &format!("suspend-{pid}.ps1"), &script)?;
        self.runner
            .run_powershell(&script)
            .with_context(|| format!("suspend windows process {pid}"))?;
        state.execution.suspended_pids.push(pid);
        Ok(())
    }

    fn kill_process(&self, pid: u32) -> Result<()> {
        let mut state = self.state.lock().expect("windows state poisoned");
        ensure_windows_response_host(&state.host, "kill windows process")?;
        let script = build_windows_kill_process_script(pid, false);
        write_windows_response_script(&mut state, &format!("kill-{pid}.ps1"), &script)?;
        self.runner
            .run_powershell(&script)
            .with_context(|| format!("kill windows process {pid}"))?;
        state.execution.terminated_pids.push(pid);
        Ok(())
    }

    fn kill_ppl_process(&self, pid: u32) -> Result<()> {
        let mut state = self.state.lock().expect("windows state poisoned");
        ensure_windows_response_host(&state.host, "kill protected windows process")?;
        let script = build_windows_kill_process_script(pid, true);
        write_windows_response_script(&mut state, &format!("kill-protected-{pid}.ps1"), &script)?;
        self.runner
            .run_powershell(&script)
            .with_context(|| format!("kill protected windows process {pid}"))?;
        state.execution.terminated_protected_pids.push(pid);
        Ok(())
    }

    fn quarantine_file(&self, path: &Path) -> Result<QuarantineReceipt> {
        let mut state = self.state.lock().expect("windows state poisoned");
        ensure_windows_response_host(&state.host, "quarantine windows file")?;
        let script = build_windows_quarantine_script(path);
        write_windows_response_script(
            &mut state,
            &format!("quarantine-{}.ps1", Uuid::now_v7().simple()),
            &script,
        )?;
        let receipt: QuarantineReceipt = run_powershell_json(self.runner.as_ref(), &script)
            .with_context(|| format!("quarantine windows file {}", path.display()))?;
        state.execution.quarantined_files.push(receipt.clone());
        Ok(receipt)
    }

    fn network_isolate(&self, rules: &IsolationRulesV2) -> Result<()> {
        let mut state = self.state.lock().expect("windows state poisoned");
        if !state.host.has_firewall {
            bail!("windows firewall capability is unavailable");
        }
        let receipt = apply_windows_firewall_isolation(&mut state, self.runner.as_ref(), rules)
            .with_context(|| "apply windows firewall isolation")?;
        state.firewall_backup_path = Some(receipt.backup_path);
        state.firewall_rule_group = Some(receipt.rule_group);
        state.execution.network_isolation_active = true;
        state.execution.last_isolation_rules = Some(rules.clone());
        Ok(())
    }

    fn network_release(&self) -> Result<()> {
        let mut state = self.state.lock().expect("windows state poisoned");
        if !state.execution.network_isolation_active {
            bail!("windows network isolation is not active");
        }
        release_windows_firewall_isolation(&mut state, self.runner.as_ref())
            .with_context(|| "release windows firewall isolation")?;
        state.execution.network_isolation_active = false;
        state.firewall_backup_path = None;
        state.firewall_rule_group = None;
        Ok(())
    }

    fn registry_rollback(&self, target: &RollbackTarget) -> Result<()> {
        let mut state = self.state.lock().expect("windows state poisoned");
        state.execution.rollback_targets.push(target.clone());
        let artifact_path = write_windows_registry_rollback_artifact(&mut state, target)
            .with_context(|| "write windows registry rollback artifact")?;
        state.execution.audit_artifacts.push(artifact_path);
        Ok(())
    }

    fn collect_forensics(&self, spec: &ForensicSpec) -> Result<ArtifactBundle> {
        let mut state = self.state.lock().expect("windows state poisoned");
        ensure_windows_forensics_host(&state.host, spec)?;
        let artifact_id = Uuid::now_v7();
        let script = build_windows_forensics_script(spec, artifact_id);
        write_windows_response_script(
            &mut state,
            &format!("forensics-{}.ps1", artifact_id.simple()),
            &script,
        )?;
        let bundle: ArtifactBundle = run_powershell_json(self.runner.as_ref(), &script)
            .with_context(|| format!("collect windows forensics {}", artifact_id))?;
        state.execution.forensic_artifacts.push(bundle.clone());
        Ok(bundle)
    }
}

impl PreemptiveBlock for WindowsPlatform {
    fn block_hash(&self, hash: &str, ttl: Duration) -> Result<()> {
        push_block(
            &mut self.state.lock().expect("windows state poisoned").execution,
            "hash",
            hash.to_string(),
            ttl,
        );
        Ok(())
    }

    fn block_pid(&self, pid: u32, ttl: Duration) -> Result<()> {
        push_block(
            &mut self.state.lock().expect("windows state poisoned").execution,
            "pid",
            pid.to_string(),
            ttl,
        );
        Ok(())
    }

    fn block_path(&self, path: &Path, ttl: Duration) -> Result<()> {
        push_block(
            &mut self.state.lock().expect("windows state poisoned").execution,
            "path",
            path.display().to_string(),
            ttl,
        );
        Ok(())
    }

    fn block_network(&self, target: &NetworkTarget, ttl: Duration) -> Result<()> {
        push_block(
            &mut self.state.lock().expect("windows state poisoned").execution,
            "network",
            target.value.clone(),
            ttl,
        );
        Ok(())
    }

    fn clear_all_blocks(&self) -> Result<()> {
        self.state
            .lock()
            .expect("windows state poisoned")
            .execution
            .active_blocks
            .clear();
        Ok(())
    }
}

impl KernelIntegrity for WindowsPlatform {
    fn check_ssdt_integrity(&self) -> Result<IntegrityReport> {
        let host = self.host_capabilities();
        Ok(kernel_report(
            false,
            format!(
                "ssdt inspection requires kernel transport and is not implemented; {}",
                host.summary()
            ),
        ))
    }

    fn check_callback_tables(&self) -> Result<IntegrityReport> {
        let host = self.host_capabilities();
        Ok(kernel_report(
            false,
            format!(
                "callback table inspection requires kernel transport and is not implemented; {}",
                host.summary()
            ),
        ))
    }

    fn check_kernel_code(&self) -> Result<IntegrityReport> {
        let host = self.host_capabilities();
        Ok(kernel_report(
            false,
            format!(
                "kernel code integrity inspection requires driver support and is not implemented; {}",
                host.summary()
            ),
        ))
    }

    fn detect_hidden_processes(&self) -> Result<Vec<SuspiciousProcess>> {
        let host = self.host_capabilities();
        if !host.reachable || !host.has_process_inventory {
            bail!("windows process inventory is unavailable")
        }

        let wmi = snapshot_process_inventory(self.runner.as_ref())
            .with_context(|| "snapshot windows processes via win32_process")?;
        let tasklist = snapshot_tasklist_inventory(self.runner.as_ref())
            .with_context(|| "snapshot windows processes via tasklist")?;
        let wmi_pids = wmi.keys().copied().collect::<BTreeSet<_>>();
        let tasklist_pids = tasklist.keys().copied().collect::<BTreeSet<_>>();

        let mut suspicious = Vec::new();
        for pid in wmi_pids.difference(&tasklist_pids) {
            let reason = wmi
                .get(pid)
                .map(|process| {
                    format!(
                        "present in Win32_Process but absent from tasklist: {}",
                        process.name
                    )
                })
                .unwrap_or_else(|| "present in Win32_Process but absent from tasklist".to_string());
            suspicious.push(SuspiciousProcess { pid: *pid, reason });
        }
        for pid in tasklist_pids.difference(&wmi_pids) {
            let reason = tasklist
                .get(pid)
                .map(|process| {
                    format!(
                        "present in tasklist but absent from Win32_Process: {}",
                        process.image_name
                    )
                })
                .unwrap_or_else(|| "present in tasklist but absent from Win32_Process".to_string());
            suspicious.push(SuspiciousProcess { pid: *pid, reason });
        }
        Ok(suspicious)
    }
}

impl PlatformProtection for WindowsPlatform {
    fn protect_process(&self, pid: u32) -> Result<()> {
        self.state
            .lock()
            .expect("windows state poisoned")
            .execution
            .protected_pids
            .push(pid);
        Ok(())
    }

    fn protect_files(&self, paths: &[PathBuf]) -> Result<()> {
        let mut state = self.state.lock().expect("windows state poisoned");
        state
            .execution
            .protected_paths
            .extend(paths.iter().cloned());
        let artifact_path = write_windows_protection_surface_artifact(&mut state)
            .with_context(|| "write windows protection surface artifact")?;
        state.execution.audit_artifacts.push(artifact_path);
        Ok(())
    }

    fn verify_integrity(&self) -> Result<IntegrityReport> {
        let host = self.host_capabilities();
        Ok(protection_report(&host))
    }

    fn check_etw_integrity(&self) -> Result<EtwStatus> {
        let host = self.host_capabilities();
        Ok(EtwStatus {
            healthy: host.reachable
                && host.running_on_windows
                && host.has_security_log
                && host.has_powershell_log
                && host.has_process_creation_events,
        })
    }

    fn check_amsi_integrity(&self) -> Result<AmsiStatus> {
        let host = self.host_capabilities();
        Ok(AmsiStatus {
            healthy: host.reachable
                && host.running_on_windows
                && host.has_amsi_runtime
                && host.has_script_block_logging,
        })
    }

    fn check_bpf_integrity(&self) -> Result<BpfStatus> {
        Ok(BpfStatus { healthy: false })
    }
}

impl PlatformRuntime for WindowsPlatform {
    fn descriptor(&self) -> PlatformDescriptor {
        PlatformDescriptor {
            target: PlatformTarget::Windows,
            kernel_transport: KernelTransport::Driver,
            degrade_levels: 3,
            supports_registry: true,
            supports_amsi: true,
            supports_etw_integrity: true,
            supports_bpf_integrity: false,
            supports_container_sensor: false,
        }
    }
}

fn detect_command_runner() -> Box<dyn WindowsCommandRunner> {
    if cfg!(target_os = "windows") && command_exists("powershell") {
        Box::new(LocalWindowsRunner)
    } else if let Some(config) = WindowsSshConfig::from_env() {
        Box::new(SshWindowsRunner::new(config))
    } else {
        Box::new(UnavailableWindowsRunner::new(
            "windows host unavailable; run on Windows or set AEGIS_WINDOWS_HOST/USER/PASSWORD",
        ))
    }
}

fn probe_host_capabilities(runner: &dyn WindowsCommandRunner) -> Result<WindowsHostCapabilities> {
    let script = r#"
$hasLog = {
    param([string]$Name)
    try {
        (Get-WinEvent -ListLog $Name -ErrorAction Stop) -ne $null
    } catch {
        $false
    }
}

$hasProcessCreationEvents = $false
try {
    $hasProcessCreationEvents = (Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688 } -MaxEvents 1 -ErrorAction Stop | Select-Object -First 1) -ne $null
} catch {
    $hasProcessCreationEvents = $false
}

$hasAmsiRuntime = $false
try {
    $amsiDll = Join-Path $env:WINDIR 'System32\amsi.dll'
    $hasAmsiRuntime = (Test-Path -LiteralPath $amsiDll) -and ($null -ne [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils'))
} catch {
    $hasAmsiRuntime = $false
}

$hasScriptBlockLogging = $false
try {
    $policy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -ErrorAction Stop
    $hasScriptBlockLogging = [int]$policy.EnableScriptBlockLogging -eq 1
} catch {
    $hasScriptBlockLogging = $false
}

$hasNamedPipeInventory = $false
try {
    $null = Get-ChildItem -Path '\\.\pipe\' -ErrorAction Stop | Select-Object -First 1
    $hasNamedPipeInventory = $true
} catch {
    $hasNamedPipeInventory = $false
}

$hasModuleInventory = $false
if ((Get-Command Get-Process -ErrorAction SilentlyContinue) -ne $null) {
    try {
        $probeProcess = Get-Process -ErrorAction Stop | Where-Object { $_.Path } | Select-Object -First 1
        if ($null -ne $probeProcess) {
            $null = $probeProcess.Modules | Select-Object -First 1
            $hasModuleInventory = $true
        }
    } catch {
        $hasModuleInventory = $false
    }
}

$hasVssInventory = $false
if ((Get-Command Get-CimInstance -ErrorAction SilentlyContinue) -ne $null) {
    try {
        $null = Get-CimInstance Win32_ShadowCopy -ErrorAction Stop | Select-Object -First 1
        $hasVssInventory = $true
    } catch {
        $hasVssInventory = $false
    }
}

$hasDeviceInventory = $false
if ((Get-Command Get-PnpDevice -ErrorAction SilentlyContinue) -ne $null) {
    try {
        $null = Get-PnpDevice -ErrorAction Stop | Select-Object -First 1
        $hasDeviceInventory = $true
    } catch {
        $hasDeviceInventory = $false
    }
}

$data = [ordered]@{
    computer_name = $env:COMPUTERNAME
    user_name = (whoami)
    is_admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    has_process_inventory = (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) -ne $null
    has_security_log = & $hasLog 'Security'
    has_powershell_log = & $hasLog 'Microsoft-Windows-PowerShell/Operational'
    has_wmi_log = & $hasLog 'Microsoft-Windows-WMI-Activity/Operational'
    has_task_scheduler_log = & $hasLog 'Microsoft-Windows-TaskScheduler/Operational'
    has_sysmon_log = & $hasLog 'Microsoft-Windows-Sysmon/Operational'
    has_process_creation_events = $hasProcessCreationEvents
    has_net_connection = (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) -ne $null
    has_firewall = ((Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) -ne $null) -and ((Get-Command netsh.exe -ErrorAction SilentlyContinue) -ne $null)
    has_registry_cli = (Get-Command reg.exe -ErrorAction SilentlyContinue) -ne $null
    has_amsi_runtime = $hasAmsiRuntime
    has_script_block_logging = $hasScriptBlockLogging
    has_named_pipe_inventory = $hasNamedPipeInventory
    has_module_inventory = $hasModuleInventory
    has_vss_inventory = $hasVssInventory
    has_device_inventory = $hasDeviceInventory
}

$data | ConvertTo-Json -Compress
"#;

    let probe: WindowsCapabilityProbe = run_powershell_json(runner, script)?;
    Ok(WindowsHostCapabilities {
        reachable: true,
        running_on_windows: true,
        execution_mode: runner.mode_name().to_string(),
        computer_name: probe.computer_name,
        user_name: probe.user_name,
        is_admin: probe.is_admin,
        has_process_inventory: probe.has_process_inventory,
        has_security_log: probe.has_security_log,
        has_powershell_log: probe.has_powershell_log,
        has_wmi_log: probe.has_wmi_log,
        has_task_scheduler_log: probe.has_task_scheduler_log,
        has_sysmon_log: probe.has_sysmon_log,
        has_process_creation_events: probe.has_process_creation_events,
        has_net_connection: probe.has_net_connection,
        has_firewall: probe.has_firewall,
        has_registry_cli: probe.has_registry_cli,
        has_amsi_runtime: probe.has_amsi_runtime,
        has_script_block_logging: probe.has_script_block_logging,
        has_named_pipe_inventory: probe.has_named_pipe_inventory,
        has_module_inventory: probe.has_module_inventory,
        has_vss_inventory: probe.has_vss_inventory,
        has_device_inventory: probe.has_device_inventory,
        last_error: None,
    })
}

fn run_powershell_json<T: DeserializeOwned>(
    runner: &dyn WindowsCommandRunner,
    script: &str,
) -> Result<T> {
    let raw = runner.run_powershell(script)?;
    serde_json::from_str(raw.trim())
        .with_context(|| format!("parse powershell json output: {}", raw.trim()))
}

fn collect_live_windows_events(
    state: &mut WindowsState,
    runner: &dyn WindowsCommandRunner,
) -> Result<()> {
    if state.host.has_process_inventory {
        collect_process_delta_events(state, runner)?;
    }
    if state.host.has_process_creation_events {
        collect_security_process_audit_events(state, runner)?;
    }
    if state.host.has_net_connection {
        collect_network_delta_events(state, runner)?;
    }
    if state.host.has_named_pipe_inventory {
        collect_named_pipe_events(state, runner)?;
    }
    if state.host.has_module_inventory {
        collect_module_events(state, runner)?;
    }
    if state.host.has_vss_inventory {
        collect_vss_events(state, runner)?;
    }
    if state.host.has_device_inventory {
        collect_device_events(state, runner)?;
    }
    Ok(())
}

fn latest_process_audit_record_id(runner: &dyn WindowsCommandRunner) -> Result<Option<u64>> {
    let script = r#"
$event = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688 } -MaxEvents 1 -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $event) {
    'null'
} else {
    [ordered]@{
        record_id = [uint64]$event.RecordId
    } | ConvertTo-Json -Compress
}
"#;
    let cursor: Option<WindowsProcessAuditCursor> = run_powershell_json(runner, script)?;
    Ok(cursor.map(|value| value.record_id))
}

fn collect_process_delta_events(
    state: &mut WindowsState,
    runner: &dyn WindowsCommandRunner,
) -> Result<()> {
    let current = snapshot_process_inventory(runner)?;
    for (pid, process) in &current {
        if !state.known_processes.contains_key(pid) {
            state.pending_events.push_back(
                WindowsEventStub {
                    provider: WindowsProviderKind::PsProcess,
                    operation: "process-start".to_string(),
                    subject: process.start_subject(),
                }
                .encode(),
            );
        }
    }

    for (pid, process) in &state.known_processes {
        if !current.contains_key(pid) {
            state.pending_events.push_back(
                WindowsEventStub {
                    provider: WindowsProviderKind::PsProcess,
                    operation: "process-exit".to_string(),
                    subject: process.exit_subject(),
                }
                .encode(),
            );
        }
    }

    state.known_processes = current;
    Ok(())
}

fn collect_security_process_audit_events(
    state: &mut WindowsState,
    runner: &dyn WindowsCommandRunner,
) -> Result<()> {
    let Some(after_record_id) = state.security_process_cursor else {
        state.security_process_cursor = latest_process_audit_record_id(runner)?;
        return Ok(());
    };

    let events = snapshot_security_process_events_after(runner, after_record_id)?;
    if let Some(last) = events.last() {
        state.security_process_cursor = Some(last.record_id);
    }
    for event in events {
        state.pending_events.push_back(
            WindowsEventStub {
                provider: WindowsProviderKind::EtwProcess,
                operation: "process-audit".to_string(),
                subject: event.subject(),
            }
            .encode(),
        );
    }
    Ok(())
}

fn collect_network_delta_events(
    state: &mut WindowsState,
    runner: &dyn WindowsCommandRunner,
) -> Result<()> {
    let current = snapshot_network_inventory(runner)?;
    for (key, connection) in &current {
        if !state.known_connections.contains_key(key) {
            state.pending_events.push_back(
                WindowsEventStub {
                    provider: WindowsProviderKind::WfpNetwork,
                    operation: "network-open".to_string(),
                    subject: connection.subject(),
                }
                .encode(),
            );
        }
    }

    for (key, connection) in &state.known_connections {
        if !current.contains_key(key) {
            state.pending_events.push_back(
                WindowsEventStub {
                    provider: WindowsProviderKind::WfpNetwork,
                    operation: "network-close".to_string(),
                    subject: connection.subject(),
                }
                .encode(),
            );
        }
    }

    state.known_connections = current;
    Ok(())
}

fn collect_named_pipe_events(
    state: &mut WindowsState,
    runner: &dyn WindowsCommandRunner,
) -> Result<()> {
    let current = snapshot_named_pipe_inventory(runner)?;
    for (key, pipe) in &current {
        if !state.known_named_pipes.contains_key(key) {
            state.pending_events.push_back(
                WindowsEventStub {
                    provider: WindowsProviderKind::IpcSensor,
                    operation: "pipe-visible".to_string(),
                    subject: pipe.subject(),
                }
                .encode(),
            );
        }
    }

    for (key, pipe) in &state.known_named_pipes {
        if !current.contains_key(key) {
            state.pending_events.push_back(
                WindowsEventStub {
                    provider: WindowsProviderKind::IpcSensor,
                    operation: "pipe-gone".to_string(),
                    subject: pipe.subject(),
                }
                .encode(),
            );
        }
    }

    state.known_named_pipes = current;
    Ok(())
}

fn collect_module_events(
    state: &mut WindowsState,
    runner: &dyn WindowsCommandRunner,
) -> Result<()> {
    let current = snapshot_module_inventory(runner)?;
    for (key, module) in &current {
        if !state.known_modules.contains_key(key) {
            state.pending_events.push_back(
                WindowsEventStub {
                    provider: WindowsProviderKind::ModuleLoadSensor,
                    operation: "module-visible".to_string(),
                    subject: module.subject(),
                }
                .encode(),
            );
        }
    }

    for (key, module) in &state.known_modules {
        if !current.contains_key(key) {
            state.pending_events.push_back(
                WindowsEventStub {
                    provider: WindowsProviderKind::ModuleLoadSensor,
                    operation: "module-gone".to_string(),
                    subject: module.subject(),
                }
                .encode(),
            );
        }
    }

    state.known_modules = current;
    Ok(())
}

fn collect_vss_events(state: &mut WindowsState, runner: &dyn WindowsCommandRunner) -> Result<()> {
    let current = snapshot_vss_inventory(runner)?;
    for (key, snapshot) in &current {
        if !state.known_vss_snapshots.contains_key(key) {
            state.pending_events.push_back(
                WindowsEventStub {
                    provider: WindowsProviderKind::SnapshotProtection,
                    operation: "shadow-visible".to_string(),
                    subject: snapshot.subject(),
                }
                .encode(),
            );
        }
    }

    for (key, snapshot) in &state.known_vss_snapshots {
        if !current.contains_key(key) {
            state.pending_events.push_back(
                WindowsEventStub {
                    provider: WindowsProviderKind::SnapshotProtection,
                    operation: "shadow-gone".to_string(),
                    subject: snapshot.subject(),
                }
                .encode(),
            );
        }
    }

    state.known_vss_snapshots = current;
    Ok(())
}

fn collect_device_events(
    state: &mut WindowsState,
    runner: &dyn WindowsCommandRunner,
) -> Result<()> {
    let current = snapshot_device_inventory(runner)?;
    for (key, device) in &current {
        if !state.known_devices.contains_key(key) {
            state.pending_events.push_back(
                WindowsEventStub {
                    provider: WindowsProviderKind::DeviceControl,
                    operation: "device-visible".to_string(),
                    subject: device.subject(),
                }
                .encode(),
            );
        }
    }

    for (key, device) in &state.known_devices {
        if !current.contains_key(key) {
            state.pending_events.push_back(
                WindowsEventStub {
                    provider: WindowsProviderKind::DeviceControl,
                    operation: "device-gone".to_string(),
                    subject: device.subject(),
                }
                .encode(),
            );
        }
    }

    state.known_devices = current;
    Ok(())
}

fn snapshot_process_inventory(
    runner: &dyn WindowsCommandRunner,
) -> Result<BTreeMap<u32, WindowsProcessSnapshot>> {
    let script = r#"
$rows = @(
    Get-CimInstance Win32_Process |
        Sort-Object ProcessId |
        ForEach-Object {
            [ordered]@{
                process_id = [uint32]$_.ProcessId
                parent_process_id = [uint32]$_.ParentProcessId
                name = $_.Name
                command_line = $_.CommandLine
            }
        }
)

$rows | ConvertTo-Json -Compress
"#;
    let rows: Vec<WindowsProcessSnapshot> = run_powershell_json(runner, script)?;
    Ok(rows
        .into_iter()
        .map(|process| (process.process_id, process))
        .collect())
}

fn snapshot_security_process_events_after(
    runner: &dyn WindowsCommandRunner,
    after_record_id: u64,
) -> Result<Vec<WindowsSecurityProcessEvent>> {
    let script = format!(
        r#"
$afterRecordId = [uint64]{after_record_id}
$rows = @(
    Get-WinEvent -FilterHashtable @{{ LogName='Security'; Id=4688 }} -ErrorAction SilentlyContinue |
        Where-Object {{ [uint64]$_.RecordId -gt $afterRecordId }} |
        Sort-Object RecordId |
        ForEach-Object {{
            $xml = [xml]$_.ToXml()
            $eventData = @{{}}
            foreach ($item in $xml.Event.EventData.Data) {{
                if ($item.Name) {{
                    $eventData[$item.Name] = [string]$item.'#text'
                }}
            }}
            [ordered]@{{
                record_id = [uint64]$_.RecordId
                process_name = $eventData['NewProcessName']
                command_line = $eventData['ProcessCommandLine']
            }}
        }}
)

$rows | ConvertTo-Json -Compress
"#
    );
    run_powershell_json(runner, &script)
}

fn snapshot_network_inventory(
    runner: &dyn WindowsCommandRunner,
) -> Result<BTreeMap<String, WindowsNetworkConnection>> {
    let script = r#"
$tcpRows = @()
if ((Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) -ne $null) {
    $tcpRows = @(
        Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Sort-Object OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort, State |
            ForEach-Object {
                [ordered]@{
                    protocol = 'tcp'
                    local_address = [string]$_.LocalAddress
                    local_port = [uint16]$_.LocalPort
                    remote_address = [string]$_.RemoteAddress
                    remote_port = [uint16]$_.RemotePort
                    state = [string]$_.State
                    owning_process = if ($null -eq $_.OwningProcess) { $null } else { [uint32]$_.OwningProcess }
                }
            }
    )
}

$udpRows = @()
if ((Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) -ne $null) {
    $udpRows = @(
        Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
            Sort-Object OwningProcess, LocalAddress, LocalPort |
            ForEach-Object {
                [ordered]@{
                    protocol = 'udp'
                    local_address = [string]$_.LocalAddress
                    local_port = [uint16]$_.LocalPort
                    remote_address = $null
                    remote_port = $null
                    state = 'Listen'
                    owning_process = if ($null -eq $_.OwningProcess) { $null } else { [uint32]$_.OwningProcess }
                }
            }
    )
}

$rows = @($tcpRows + $udpRows)
$rows | ConvertTo-Json -Compress
"#;
    let rows: Vec<WindowsNetworkConnection> = run_powershell_json(runner, script)?;
    Ok(rows
        .into_iter()
        .map(|connection| (connection.key(), connection))
        .collect())
}

fn snapshot_named_pipe_inventory(
    runner: &dyn WindowsCommandRunner,
) -> Result<BTreeMap<String, WindowsNamedPipeSnapshot>> {
    let script = r#"
$rows = @(
    Get-ChildItem -Path '\\.\pipe\' -ErrorAction Stop |
        Sort-Object Name |
        ForEach-Object {
            [ordered]@{
                pipe_name = ('\\.\pipe\' + [string]$_.Name)
            }
        }
)

@($rows) | ConvertTo-Json -Compress
"#;
    let rows: Vec<WindowsNamedPipeSnapshot> = run_powershell_json(runner, script)?;
    Ok(rows
        .into_iter()
        .map(|pipe| (pipe.pipe_name.clone(), pipe))
        .collect())
}

fn snapshot_module_inventory(
    runner: &dyn WindowsCommandRunner,
) -> Result<BTreeMap<String, WindowsModuleSnapshot>> {
    let script = r#"
$rows = @(
    Get-Process -ErrorAction Stop |
        Sort-Object Id |
        ForEach-Object {
            $process = $_
            try {
                @(
                    $process.Modules |
                        Where-Object { $_.FileName } |
                        Sort-Object FileName |
                        ForEach-Object {
                            [ordered]@{
                                process_id = [uint32]$process.Id
                                process_name = [string]$process.ProcessName
                                module_path = [string]$_.FileName
                            }
                        }
                )
            } catch {
                @()
            }
        }
)

@($rows) | ConvertTo-Json -Compress
"#;
    let rows: Vec<WindowsModuleSnapshot> = run_powershell_json(runner, script)?;
    Ok(rows
        .into_iter()
        .map(|module| (module.key(), module))
        .collect())
}

fn snapshot_vss_inventory(
    runner: &dyn WindowsCommandRunner,
) -> Result<BTreeMap<String, WindowsVssSnapshot>> {
    let script = r#"
$rows = @(
    Get-CimInstance Win32_ShadowCopy -ErrorAction Stop |
        Sort-Object ID |
        ForEach-Object {
            [ordered]@{
                snapshot_id = [string]$_.ID
                volume_name = if ($_.VolumeName) { [string]$_.VolumeName } else { $null }
            }
        }
)

@($rows) | ConvertTo-Json -Compress
"#;
    let rows: Vec<WindowsVssSnapshot> = run_powershell_json(runner, script)?;
    Ok(rows
        .into_iter()
        .map(|snapshot| (snapshot.snapshot_id.clone(), snapshot))
        .collect())
}

fn snapshot_device_inventory(
    runner: &dyn WindowsCommandRunner,
) -> Result<BTreeMap<String, WindowsDeviceSnapshot>> {
    let script = r#"
$rows = @(
    Get-PnpDevice -ErrorAction Stop |
        Sort-Object InstanceId |
        ForEach-Object {
            [ordered]@{
                instance_id = [string]$_.InstanceId
                class = if ($_.Class) { [string]$_.Class } else { $null }
                friendly_name = if ($_.FriendlyName) { [string]$_.FriendlyName } else { $null }
                status = if ($_.Status) { [string]$_.Status } else { $null }
            }
        }
)

@($rows) | ConvertTo-Json -Compress
"#;
    let rows: Vec<WindowsDeviceSnapshot> = run_powershell_json(runner, script)?;
    Ok(rows
        .into_iter()
        .map(|device| (device.instance_id.clone(), device))
        .collect())
}

fn snapshot_tasklist_inventory(
    runner: &dyn WindowsCommandRunner,
) -> Result<BTreeMap<u32, WindowsTasklistSnapshot>> {
    let script = r#"
$rows = @(
    tasklist /FO CSV /NH |
        Where-Object { $_ -and $_.Trim() } |
        ConvertFrom-Csv -Header 'Image Name','PID','Session Name','Session#','Mem Usage' |
        ForEach-Object {
            [ordered]@{
                process_id = [uint32](($_.PID -replace '[^0-9]', ''))
                image_name = $_.'Image Name'
            }
        }
)

$rows | ConvertTo-Json -Compress
"#;
    let rows: Vec<WindowsTasklistSnapshot> = run_powershell_json(runner, script)?;
    Ok(rows
        .into_iter()
        .map(|process| (process.process_id, process))
        .collect())
}

fn apply_windows_firewall_isolation(
    state: &mut WindowsState,
    runner: &dyn WindowsCommandRunner,
    rules: &IsolationRulesV2,
) -> Result<WindowsFirewallIsolationReceipt> {
    let rule_group = format!("AegisIsolation-{}", Uuid::now_v7().simple());
    let backup_path = format!(
        r"C:\ProgramData\Aegis\firewall\{}-profiles.json",
        Uuid::now_v7().simple()
    );
    let script = build_windows_isolation_script(&rule_group, &backup_path, rules);
    write_windows_firewall_manifest(state, "isolate.ps1", &script)?;
    run_powershell_json(runner, &script)
}

fn release_windows_firewall_isolation(
    state: &mut WindowsState,
    runner: &dyn WindowsCommandRunner,
) -> Result<()> {
    let backup_path = state
        .firewall_backup_path
        .clone()
        .ok_or_else(|| anyhow!("windows firewall isolation backup path is missing"))?;
    let rule_group = state
        .firewall_rule_group
        .clone()
        .ok_or_else(|| anyhow!("windows firewall isolation rule group is missing"))?;
    let script = build_windows_release_script(&rule_group, &backup_path);
    write_windows_firewall_manifest(state, "release.ps1", &script)?;
    runner.run_powershell(&script)?;
    Ok(())
}

fn write_windows_firewall_manifest(
    state: &mut WindowsState,
    file_name: &str,
    script: &str,
) -> Result<PathBuf> {
    let path = state.base_dir.join("firewall").join(file_name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, script)?;
    Ok(path)
}

fn write_windows_response_script(
    state: &mut WindowsState,
    file_name: &str,
    script: &str,
) -> Result<PathBuf> {
    let path = state.base_dir.join("response").join(file_name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, script)?;
    Ok(path)
}

const WINDOWS_REGISTRY_PROTECTION_SURFACE: [&str; 5] = [
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"HKLM\Software\Classes\CLSID",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
];

fn write_windows_protection_surface_artifact(state: &mut WindowsState) -> Result<PathBuf> {
    let artifact = WindowsProtectionSurfaceArtifact {
        protected_paths: state
            .execution
            .protected_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        registry_protection_surface: WINDOWS_REGISTRY_PROTECTION_SURFACE
            .iter()
            .map(|path| (*path).to_string())
            .collect(),
    };
    let path = state
        .base_dir
        .join("registry")
        .join("protection-surface.json");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(&artifact)?;
    fs::write(&path, json)?;
    Ok(path)
}

fn write_windows_registry_rollback_artifact(
    state: &mut WindowsState,
    target: &RollbackTarget,
) -> Result<PathBuf> {
    let artifact = WindowsRegistryRollbackArtifact {
        selector: target.selector.clone(),
        protected_paths: state
            .execution
            .protected_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        registry_protection_surface: WINDOWS_REGISTRY_PROTECTION_SURFACE
            .iter()
            .map(|path| (*path).to_string())
            .collect(),
    };
    let path = state
        .base_dir
        .join("registry")
        .join(format!("rollback-{}.json", Uuid::now_v7().simple()));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(&artifact)?;
    fs::write(&path, json)?;
    Ok(path)
}

fn build_windows_isolation_script(
    rule_group: &str,
    backup_path: &str,
    rules: &IsolationRulesV2,
) -> String {
    let mut lines = vec![
        format!("$ruleGroup = '{}'", escape_windows_ps_string(rule_group)),
        format!("$backupPath = '{}'", escape_windows_ps_string(backup_path)),
        "$backupDir = Split-Path -Parent $backupPath".to_string(),
        "New-Item -ItemType Directory -Force -Path $backupDir | Out-Null".to_string(),
        "Get-NetFirewallRule -Group $ruleGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null".to_string(),
        "$profiles = @(Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)".to_string(),
        "$profiles | ConvertTo-Json -Compress | Set-Content -LiteralPath $backupPath -Encoding UTF8".to_string(),
        "New-NetFirewallRule -DisplayName ($ruleGroup + '-AllowLoopbackV4') -Group $ruleGroup -Direction Outbound -Action Allow -RemoteAddress 127.0.0.1 | Out-Null".to_string(),
        "New-NetFirewallRule -DisplayName ($ruleGroup + '-AllowLoopbackV6') -Group $ruleGroup -Direction Outbound -Action Allow -RemoteAddress ::1 | Out-Null".to_string(),
    ];
    for (index, ip) in rules.allowed_control_plane_ips.iter().enumerate() {
        lines.push(format!(
            "New-NetFirewallRule -DisplayName ($ruleGroup + '-AllowControlPlane-{index}') -Group $ruleGroup -Direction Outbound -Action Allow -RemoteAddress '{}' | Out-Null",
            escape_windows_ps_string(ip)
        ));
    }
    lines.extend([
        "@('Domain','Private','Public') | ForEach-Object { Set-NetFirewallProfile -Profile $_ -DefaultOutboundAction Block }".to_string(),
        "[ordered]@{".to_string(),
        "    backup_path = $backupPath".to_string(),
        "    rule_group = $ruleGroup".to_string(),
        "} | ConvertTo-Json -Compress".to_string(),
    ]);
    lines.join("\n")
}

fn build_windows_release_script(rule_group: &str, backup_path: &str) -> String {
    [
        format!("$ruleGroup = '{}'", escape_windows_ps_string(rule_group)),
        format!("$backupPath = '{}'", escape_windows_ps_string(backup_path)),
        "if (-not (Test-Path -LiteralPath $backupPath)) { throw \"windows firewall profile backup is missing\" }".to_string(),
        "$profiles = @(Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json)".to_string(),
        "Get-NetFirewallRule -Group $ruleGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null".to_string(),
        "foreach ($profile in $profiles) {".to_string(),
        "    Set-NetFirewallProfile -Profile $profile.Name -Enabled ([bool]$profile.Enabled) -DefaultInboundAction $profile.DefaultInboundAction -DefaultOutboundAction $profile.DefaultOutboundAction".to_string(),
        "}".to_string(),
        "Remove-Item -LiteralPath $backupPath -Force".to_string(),
    ]
    .join("\n")
}

fn escape_windows_ps_string(value: &str) -> String {
    value.replace('\'', "''")
}

fn ensure_windows_response_host(host: &WindowsHostCapabilities, action: &str) -> Result<()> {
    if !host.reachable {
        bail!(
            "{action} requires a reachable windows host: {}",
            host.summary()
        );
    }
    if !host.running_on_windows {
        bail!("{action} requires a windows host: {}", host.summary());
    }
    if !host.is_admin {
        bail!(
            "{action} requires an administrative windows session: {}",
            host.summary()
        );
    }
    Ok(())
}

fn ensure_windows_forensics_host(
    host: &WindowsHostCapabilities,
    spec: &ForensicSpec,
) -> Result<()> {
    ensure_windows_response_host(host, "collect windows forensics")?;
    if !host.has_process_inventory {
        bail!(
            "collect windows forensics requires process inventory capability: {}",
            host.summary()
        );
    }
    if spec.include_network && !host.has_net_connection {
        bail!(
            "collect windows forensics requires network inventory capability: {}",
            host.summary()
        );
    }
    if spec.include_registry && !host.has_registry_cli {
        bail!(
            "collect windows forensics requires registry cli capability: {}",
            host.summary()
        );
    }
    Ok(())
}

fn windows_ps_bool(value: bool) -> &'static str {
    if value {
        "$true"
    } else {
        "$false"
    }
}

fn build_windows_suspend_process_script(pid: u32) -> String {
    format!(
        r#"
$pid = [uint32]{pid}
$process = Get-Process -Id $pid -ErrorAction Stop
$nativeSource = @"
using System;
using System.Runtime.InteropServices;

public static class AegisProcessControl {{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    [DllImport("ntdll.dll")]
    public static extern uint NtSuspendProcess(IntPtr processHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
}}
"@
Add-Type -TypeDefinition $nativeSource -ErrorAction Stop
$PROCESS_SUSPEND_RESUME = [uint32]0x0800
$PROCESS_QUERY_LIMITED_INFORMATION = [uint32]0x1000
$access = [uint32]($PROCESS_SUSPEND_RESUME -bor $PROCESS_QUERY_LIMITED_INFORMATION)
$handle = [AegisProcessControl]::OpenProcess($access, $false, $process.Id)
if ($handle -eq [IntPtr]::Zero) {{
    throw ("OpenProcess failed with Win32Error={{0}}" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
}}
try {{
    $status = [AegisProcessControl]::NtSuspendProcess($handle)
    if ($status -ne 0) {{
        throw ("NtSuspendProcess failed with NTSTATUS=0x{{0:X8}}" -f $status)
    }}
}} finally {{
    [AegisProcessControl]::CloseHandle($handle) | Out-Null
}}
"#
    )
}

fn build_windows_kill_process_script(pid: u32, protected_process: bool) -> String {
    let process_kind = if protected_process {
        "protected process"
    } else {
        "process"
    };
    format!(
        r#"
$pid = [uint32]{pid}
if ((Get-Command Stop-Process -ErrorAction SilentlyContinue) -eq $null) {{
    throw "Stop-Process is unavailable on this host"
}}
$process = Get-Process -Id $pid -ErrorAction Stop
Stop-Process -Id $process.Id -Force -ErrorAction Stop
Wait-Process -Id $pid -Timeout 5 -ErrorAction SilentlyContinue
if (Get-Process -Id $pid -ErrorAction SilentlyContinue) {{
    throw "{process_kind} $pid is still running after Stop-Process"
}}
"#
    )
}

fn build_windows_quarantine_script(path: &Path) -> String {
    let original = escape_windows_ps_string(&path.display().to_string());
    let quarantine_id = Uuid::now_v7().simple().to_string();
    format!(
        r#"
$originalPath = '{original}'
$quarantineRoot = 'C:\ProgramData\Aegis\quarantine'
$quarantineId = '{quarantine_id}'
if (-not (Test-Path -LiteralPath $originalPath -PathType Leaf)) {{
    throw "quarantine target is missing: $originalPath"
}}
New-Item -ItemType Directory -Force -Path $quarantineRoot | Out-Null
$sha256 = (Get-FileHash -LiteralPath $originalPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
$fileName = [System.IO.Path]::GetFileName($originalPath)
if ([string]::IsNullOrWhiteSpace($fileName)) {{
    throw "quarantine target has no file name: $originalPath"
}}
$destination = Join-Path $quarantineRoot ($quarantineId + '-' + $fileName)
Move-Item -LiteralPath $originalPath -Destination $destination -Force -ErrorAction Stop
if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {{
    throw "quarantine destination is missing: $destination"
}}
[ordered]@{{
    vault_path = $destination
    sha256 = $sha256
}} | ConvertTo-Json -Compress
"#
    )
}

fn build_windows_forensics_script(spec: &ForensicSpec, artifact_id: Uuid) -> String {
    let bundle_root = format!(r"C:\ProgramData\Aegis\forensics\{}", artifact_id.simple());
    format!(
        r#"
$artifactId = '{artifact_id}'
$bundleRoot = '{}'
$bundleZip = $bundleRoot + '.zip'
$includeMemory = {}
$includeRegistry = {}
$includeNetwork = {}
if ((Get-Command Compress-Archive -ErrorAction SilentlyContinue) -eq $null) {{
    throw "Compress-Archive is unavailable on this host"
}}
if (Test-Path -LiteralPath $bundleRoot) {{
    Remove-Item -LiteralPath $bundleRoot -Recurse -Force
}}
if (Test-Path -LiteralPath $bundleZip) {{
    Remove-Item -LiteralPath $bundleZip -Force
}}
New-Item -ItemType Directory -Force -Path $bundleRoot | Out-Null

$processPath = Join-Path $bundleRoot 'processes.json'
$processes = @(
    Get-CimInstance Win32_Process -ErrorAction Stop |
        Sort-Object ProcessId |
        ForEach-Object {{
            [ordered]@{{
                process_id = [uint32]$_.ProcessId
                parent_process_id = [uint32]$_.ParentProcessId
                name = [string]$_.Name
                executable_path = if ($_.ExecutablePath) {{ [string]$_.ExecutablePath }} else {{ $null }}
                command_line = if ($_.CommandLine) {{ [string]$_.CommandLine }} else {{ $null }}
            }}
        }}
)
$processes | ConvertTo-Json -Depth 5 -Compress | Set-Content -LiteralPath $processPath -Encoding UTF8
$collectedFiles = @('processes.json')

if ($includeMemory) {{
    $memoryPath = Join-Path $bundleRoot 'memory-summary.json'
    $memoryRows = @(
        Get-Process -ErrorAction Stop |
            Sort-Object Id |
            ForEach-Object {{
                [ordered]@{{
                    process_id = [uint32]$_.Id
                    process_name = [string]$_.ProcessName
                    working_set_bytes = [int64]$_.WorkingSet64
                    private_memory_bytes = [int64]$_.PrivateMemorySize64
                    virtual_memory_bytes = [int64]$_.VirtualMemorySize64
                    paged_memory_bytes = [int64]$_.PagedMemorySize64
                    cpu_seconds = if ($null -eq $_.CPU) {{ $null }} else {{ [double]$_.CPU }}
                    path = if ($_.Path) {{ [string]$_.Path }} else {{ $null }}
                }}
            }}
    )
    $memoryRows | ConvertTo-Json -Depth 5 -Compress | Set-Content -LiteralPath $memoryPath -Encoding UTF8
    $collectedFiles += 'memory-summary.json'
}}

if ($includeNetwork) {{
    if ((Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) -eq $null) {{
        throw "Get-NetTCPConnection is unavailable on this host"
    }}
    if ((Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) -eq $null) {{
        throw "Get-NetUDPEndpoint is unavailable on this host"
    }}
    $networkPath = Join-Path $bundleRoot 'network.json'
    $network = [ordered]@{{
        tcp = @(
            Get-NetTCPConnection -ErrorAction Stop |
                Sort-Object OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort, State |
                ForEach-Object {{
                    [ordered]@{{
                        local_address = [string]$_.LocalAddress
                        local_port = [uint16]$_.LocalPort
                        remote_address = [string]$_.RemoteAddress
                        remote_port = [uint16]$_.RemotePort
                        state = [string]$_.State
                        owning_process = if ($null -eq $_.OwningProcess) {{ $null }} else {{ [uint32]$_.OwningProcess }}
                    }}
                }}
        )
        udp = @(
            Get-NetUDPEndpoint -ErrorAction Stop |
                Sort-Object OwningProcess, LocalAddress, LocalPort |
                ForEach-Object {{
                    [ordered]@{{
                        local_address = [string]$_.LocalAddress
                        local_port = [uint16]$_.LocalPort
                        owning_process = if ($null -eq $_.OwningProcess) {{ $null }} else {{ [uint32]$_.OwningProcess }}
                    }}
                }}
        )
    }}
    $network | ConvertTo-Json -Depth 5 -Compress | Set-Content -LiteralPath $networkPath -Encoding UTF8
    $collectedFiles += 'network.json'
}}

if ($includeRegistry) {{
    if ((Get-Command reg.exe -ErrorAction SilentlyContinue) -eq $null) {{
        throw "reg.exe is unavailable on this host"
    }}
    $registryDir = Join-Path $bundleRoot 'registry'
    New-Item -ItemType Directory -Force -Path $registryDir | Out-Null
    $runPath = Join-Path $registryDir 'current-version-run.reg'
    & reg.exe export 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run' $runPath /y | Out-Null
    if ($LASTEXITCODE -ne 0) {{
        throw "failed to export HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    }}
    $servicesPath = Join-Path $registryDir 'services.reg'
    & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services' $servicesPath /y | Out-Null
    if ($LASTEXITCODE -ne 0) {{
        throw "failed to export HKLM\\SYSTEM\\CurrentControlSet\\Services"
    }}
    $collectedFiles += 'registry/current-version-run.reg'
    $collectedFiles += 'registry/services.reg'
}}

$manifestPath = Join-Path $bundleRoot 'manifest.json'
[ordered]@{{
    artifact_id = $artifactId
    collected_at = (Get-Date).ToUniversalTime().ToString('o')
    include_memory = $includeMemory
    include_registry = $includeRegistry
    include_network = $includeNetwork
    files = $collectedFiles
}} | ConvertTo-Json -Depth 5 -Compress | Set-Content -LiteralPath $manifestPath -Encoding UTF8

$archiveInputs = @(
    Get-ChildItem -LiteralPath $bundleRoot -Force |
        Select-Object -ExpandProperty FullName
)
if ($archiveInputs.Count -eq 0) {{
    throw "forensics bundle is empty: $bundleRoot"
}}
Compress-Archive -LiteralPath $archiveInputs -DestinationPath $bundleZip -Force
if (-not (Test-Path -LiteralPath $bundleZip -PathType Leaf)) {{
    throw "forensics archive is missing: $bundleZip"
}}
[ordered]@{{
    artifact_id = $artifactId
    location = $bundleZip
}} | ConvertTo-Json -Compress
"#,
        escape_windows_ps_string(&bundle_root),
        windows_ps_bool(spec.include_memory),
        windows_ps_bool(spec.include_registry),
        windows_ps_bool(spec.include_network),
    )
}

fn run_local_powershell(script: &str) -> Result<String> {
    let encoded = encode_powershell_script(script);
    let output = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-EncodedCommand")
        .arg(encoded)
        .output()
        .context("spawn powershell")?;
    decode_command_output(output, "run powershell")
}

fn decode_command_output(output: std::process::Output, action: &str) -> Result<String> {
    if output.status.success() {
        let stdout = String::from_utf8(output.stdout)
            .map_err(|error| anyhow!("decode stdout for {action}: {error}"))?;
        Ok(stdout.trim().to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "{action} failed with status {}: {}{}",
            output.status,
            stderr.trim(),
            if stdout.trim().is_empty() {
                "".to_string()
            } else {
                format!(" | stdout={}", stdout.trim())
            }
        );
    }
}

fn encode_powershell_script(script: &str) -> String {
    let wrapped = wrap_powershell_script(script);
    let bytes = wrapped
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>();
    STANDARD.encode(bytes)
}

fn wrap_powershell_script(script: &str) -> String {
    format!(
        "$ProgressPreference='SilentlyContinue';$WarningPreference='SilentlyContinue';$ErrorActionPreference='Stop';[Console]::OutputEncoding=[System.Text.UTF8Encoding]::UTF8;{}",
        script.trim()
    )
}

fn command_exists(program: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let candidate = dir.join(program);
                let candidate_exe = dir.join(format!("{program}.exe"));
                candidate.is_file() || candidate_exe.is_file()
            })
        })
        .unwrap_or(false)
}

fn kernel_report(passed: bool, details: impl Into<String>) -> IntegrityReport {
    IntegrityReport {
        passed,
        details: details.into(),
    }
}

fn protection_report(host: &WindowsHostCapabilities) -> IntegrityReport {
    let details = if !host.reachable {
        host.summary()
    } else {
        format!(
            "windows protection plane still lacks kernel callbacks and blocking transport; {}",
            host.summary()
        )
    };
    IntegrityReport {
        passed: false,
        details,
    }
}

fn etw_report(host: &WindowsHostCapabilities) -> IntegrityReport {
    let passed = host.reachable
        && host.running_on_windows
        && host.has_security_log
        && host.has_powershell_log
        && host.has_process_creation_events;
    let details = if !host.reachable {
        host.summary()
    } else {
        format!(
            "security_log={};powershell_operational_log={};process_creation_audit={}",
            host.has_security_log, host.has_powershell_log, host.has_process_creation_events
        )
    };
    IntegrityReport { passed, details }
}

fn amsi_report(host: &WindowsHostCapabilities) -> IntegrityReport {
    let passed = host.reachable
        && host.running_on_windows
        && host.has_amsi_runtime
        && host.has_script_block_logging;
    let details = if !host.reachable {
        host.summary()
    } else {
        format!(
            "amsi_runtime={};script_block_logging={};powershell_operational_log={}",
            host.has_amsi_runtime, host.has_script_block_logging, host.has_powershell_log
        )
    };
    IntegrityReport { passed, details }
}

fn truncate_subject(value: &str) -> String {
    const LIMIT: usize = 256;
    if value.chars().count() <= LIMIT {
        value.to_string()
    } else {
        let truncated = value.chars().take(LIMIT).collect::<String>();
        format!("{truncated}...")
    }
}

fn platform_root(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("aegis-{prefix}-{}", Uuid::now_v7().simple()))
}

fn push_block(
    execution: &mut PlatformExecutionSnapshot,
    kind: &str,
    target: String,
    ttl: Duration,
) {
    execution.active_blocks.push(BlockLease {
        kind: kind.to_string(),
        target,
        ttl_secs: ttl.as_secs(),
    });
}

#[cfg(test)]
mod tests {
    use super::{
        WindowsCommandRunner, WindowsEventStub, WindowsHostCapabilities, WindowsPlatform,
        WindowsProviderKind,
    };
    use crate::{
        KernelIntegrity, PlatformProtection, PlatformResponse, PlatformSensor, PreemptiveBlock,
    };
    use aegis_model::{EventBuffer, ForensicSpec, IsolationRulesV2, RollbackTarget, SensorConfig};
    use anyhow::{anyhow, bail, Result};
    use std::collections::VecDeque;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::Duration;

    struct QueuedWindowsRunner {
        responses: Mutex<VecDeque<String>>,
    }

    impl QueuedWindowsRunner {
        fn new(responses: impl IntoIterator<Item = String>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
            }
        }
    }

    impl WindowsCommandRunner for QueuedWindowsRunner {
        fn mode_name(&self) -> &'static str {
            "ssh"
        }

        fn run_powershell(&self, _script: &str) -> Result<String> {
            self.responses
                .lock()
                .expect("queued runner poisoned")
                .pop_front()
                .ok_or_else(|| anyhow!("queued runner exhausted"))
        }
    }

    struct FailingWindowsRunner;

    impl WindowsCommandRunner for FailingWindowsRunner {
        fn mode_name(&self) -> &'static str {
            "unavailable"
        }

        fn run_powershell(&self, _script: &str) -> Result<String> {
            bail!("windows host unavailable")
        }
    }

    fn healthy_host() -> WindowsHostCapabilities {
        WindowsHostCapabilities {
            reachable: true,
            running_on_windows: true,
            execution_mode: "ssh".to_string(),
            computer_name: Some("DESKTOP-TLASHJG".to_string()),
            user_name: Some("desktop-tlashjg\\lamba".to_string()),
            is_admin: true,
            has_process_inventory: true,
            has_security_log: true,
            has_powershell_log: true,
            has_wmi_log: true,
            has_task_scheduler_log: true,
            has_sysmon_log: false,
            has_process_creation_events: true,
            has_net_connection: true,
            has_firewall: true,
            has_registry_cli: true,
            has_amsi_runtime: false,
            has_script_block_logging: false,
            has_named_pipe_inventory: false,
            has_module_inventory: false,
            has_vss_inventory: false,
            has_device_inventory: false,
            last_error: None,
        }
    }

    fn probe_output() -> String {
        probe_output_with_assets(false, false, false, false)
    }

    fn probe_output_with_assets(
        has_named_pipe_inventory: bool,
        has_module_inventory: bool,
        has_vss_inventory: bool,
        has_device_inventory: bool,
    ) -> String {
        probe_output_with_surface(
            false,
            false,
            has_named_pipe_inventory,
            has_module_inventory,
            has_vss_inventory,
            has_device_inventory,
        )
    }

    fn probe_output_with_surface(
        has_amsi_runtime: bool,
        has_script_block_logging: bool,
        has_named_pipe_inventory: bool,
        has_module_inventory: bool,
        has_vss_inventory: bool,
        has_device_inventory: bool,
    ) -> String {
        format!(
            concat!(
                r#"{{"computer_name":"DESKTOP-TLASHJG","user_name":"desktop-tlashjg\\lamba","is_admin":true,"#,
                r#""has_process_inventory":true,"has_security_log":true,"has_powershell_log":true,"#,
                r#""has_wmi_log":true,"has_task_scheduler_log":true,"has_sysmon_log":false,"#,
                r#""has_process_creation_events":true,"has_net_connection":true,"has_firewall":true,"#,
                r#""has_registry_cli":true,"has_amsi_runtime":{},"has_script_block_logging":{},"#,
                r#""has_named_pipe_inventory":{},"has_module_inventory":{},"has_vss_inventory":{},"#,
                r#""has_device_inventory":{}}}"#
            ),
            has_amsi_runtime,
            has_script_block_logging,
            has_named_pipe_inventory,
            has_module_inventory,
            has_vss_inventory,
            has_device_inventory
        )
    }

    fn audit_cursor_output(record_id: u64) -> String {
        format!(r#"{{"record_id":{record_id}}}"#)
    }

    fn security_process_event_output(entries: &[(u64, Option<&str>, Option<&str>)]) -> String {
        let rows = entries
            .iter()
            .map(|(record_id, process_name, command_line)| {
                let process_name = process_name
                    .map(|value| format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
                    .unwrap_or_else(|| "null".to_string());
                let command_line = command_line
                    .map(|value| format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
                    .unwrap_or_else(|| "null".to_string());
                format!(
                    "{{\"record_id\":{record_id},\"process_name\":{process_name},\"command_line\":{command_line}}}"
                )
            })
            .collect::<Vec<_>>();
        format!("[{}]", rows.join(","))
    }

    fn network_output(
        entries: &[(
            &str,
            &str,
            u16,
            Option<&str>,
            Option<u16>,
            Option<&str>,
            Option<u32>,
        )],
    ) -> String {
        let rows = entries
            .iter()
            .map(
                |(
                    protocol,
                    local_address,
                    local_port,
                    remote_address,
                    remote_port,
                    state,
                    owning_process,
                )| {
                    let remote_address = remote_address
                        .map(|value| {
                            format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
                        })
                        .unwrap_or_else(|| "null".to_string());
                    let remote_port = remote_port
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "null".to_string());
                    let state = state
                        .map(|value| {
                            format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
                        })
                        .unwrap_or_else(|| "null".to_string());
                    let owning_process = owning_process
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "null".to_string());
                    format!(
                        "{{\"protocol\":\"{}\",\"local_address\":\"{}\",\"local_port\":{local_port},\"remote_address\":{remote_address},\"remote_port\":{remote_port},\"state\":{state},\"owning_process\":{owning_process}}}",
                        protocol.replace('\\', "\\\\").replace('"', "\\\""),
                        local_address.replace('\\', "\\\\").replace('"', "\\\"")
                    )
                },
            )
            .collect::<Vec<_>>();
        format!("[{}]", rows.join(","))
    }

    fn named_pipe_output(entries: &[&str]) -> String {
        let rows = entries
            .iter()
            .map(|pipe_name| {
                format!(
                    "{{\"pipe_name\":\"{}\"}}",
                    pipe_name.replace('\\', "\\\\").replace('"', "\\\"")
                )
            })
            .collect::<Vec<_>>();
        format!("[{}]", rows.join(","))
    }

    fn module_output(entries: &[(u32, &str, &str)]) -> String {
        let rows = entries
            .iter()
            .map(|(process_id, process_name, module_path)| {
                format!(
                    "{{\"process_id\":{process_id},\"process_name\":\"{}\",\"module_path\":\"{}\"}}",
                    process_name.replace('\\', "\\\\").replace('"', "\\\""),
                    module_path.replace('\\', "\\\\").replace('"', "\\\"")
                )
            })
            .collect::<Vec<_>>();
        format!("[{}]", rows.join(","))
    }

    fn vss_output(entries: &[(&str, Option<&str>)]) -> String {
        let rows = entries
            .iter()
            .map(|(snapshot_id, volume_name)| {
                let volume_name = volume_name
                    .map(|value| {
                        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
                    })
                    .unwrap_or_else(|| "null".to_string());
                format!(
                    "{{\"snapshot_id\":\"{}\",\"volume_name\":{volume_name}}}",
                    snapshot_id.replace('\\', "\\\\").replace('"', "\\\"")
                )
            })
            .collect::<Vec<_>>();
        format!("[{}]", rows.join(","))
    }

    fn device_output(entries: &[(&str, Option<&str>, Option<&str>, Option<&str>)]) -> String {
        let rows = entries
            .iter()
            .map(|(instance_id, class, friendly_name, status)| {
                let class = class
                    .map(|value| format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
                    .unwrap_or_else(|| "null".to_string());
                let friendly_name = friendly_name
                    .map(|value| format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
                    .unwrap_or_else(|| "null".to_string());
                let status = status
                    .map(|value| format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
                    .unwrap_or_else(|| "null".to_string());
                format!(
                    "{{\"instance_id\":\"{}\",\"class\":{class},\"friendly_name\":{friendly_name},\"status\":{status}}}",
                    instance_id.replace('\\', "\\\\").replace('"', "\\\"")
                )
            })
            .collect::<Vec<_>>();
        format!("[{}]", rows.join(","))
    }

    fn firewall_isolation_output(backup_path: &str, rule_group: &str) -> String {
        format!(
            r#"{{"backup_path":"{}","rule_group":"{}"}}"#,
            backup_path.replace('\\', "\\\\").replace('"', "\\\""),
            rule_group.replace('\\', "\\\\").replace('"', "\\\"")
        )
    }

    fn quarantine_receipt_output(vault_path: &Path, sha256: &str) -> String {
        format!(
            r#"{{"vault_path":"{}","sha256":"{}"}}"#,
            vault_path
                .display()
                .to_string()
                .replace('\\', "\\\\")
                .replace('"', "\\\""),
            sha256.replace('\\', "\\\\").replace('"', "\\\"")
        )
    }

    fn artifact_bundle_output(artifact_id: uuid::Uuid, location: &Path) -> String {
        format!(
            r#"{{"artifact_id":"{artifact_id}","location":"{}"}}"#,
            location
                .display()
                .to_string()
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        )
    }

    fn process_output(processes: &[(&str, u32, u32, Option<&str>)]) -> String {
        let rows = processes
            .iter()
            .map(|(name, pid, ppid, cmdline)| {
                let cmdline = cmdline
                    .map(|value| format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
                    .unwrap_or_else(|| "null".to_string());
                format!(
                    "{{\"process_id\":{pid},\"parent_process_id\":{ppid},\"name\":\"{}\",\"command_line\":{cmdline}}}",
                    name.replace('\\', "\\\\").replace('"', "\\\"")
                )
            })
            .collect::<Vec<_>>();
        format!("[{}]", rows.join(","))
    }

    fn tasklist_output(entries: &[(&str, u32)]) -> String {
        let rows = entries
            .iter()
            .map(|(name, pid)| {
                format!(
                    "{{\"process_id\":{pid},\"image_name\":\"{}\"}}",
                    name.replace('\\', "\\\\").replace('"', "\\\"")
                )
            })
            .collect::<Vec<_>>();
        format!("[{}]", rows.join(","))
    }

    fn platform_with_probe_and_processes(
        processes: impl IntoIterator<Item = String>,
    ) -> WindowsPlatform {
        let processes = processes.into_iter().collect::<Vec<_>>();
        assert!(
            !processes.is_empty(),
            "platform_with_probe_and_processes requires at least one process snapshot"
        );

        let mut responses = vec![
            probe_output(),
            processes[0].clone(),
            audit_cursor_output(900),
            network_output(&[]),
        ];
        for snapshot in processes.into_iter().skip(1) {
            responses.push(snapshot);
            responses.push(security_process_event_output(&[]));
            responses.push(network_output(&[]));
        }
        WindowsPlatform::new_with_runner(Box::new(QueuedWindowsRunner::new(responses)), false)
    }

    fn platform_with_probe() -> WindowsPlatform {
        let response_root = std::env::temp_dir().join(format!(
            "aegis-windows-response-{}",
            uuid::Uuid::now_v7().simple()
        ));
        let quarantine_path = response_root.join("quarantine").join("payload.exe");
        if let Some(parent) = quarantine_path.parent() {
            fs::create_dir_all(parent).expect("create quarantine fixture dir");
        }
        fs::write(&quarantine_path, b"payload").expect("write quarantine fixture");
        let bundle_path = response_root.join("forensics").join("bundle.zip");
        if let Some(parent) = bundle_path.parent() {
            fs::create_dir_all(parent).expect("create forensics fixture dir");
        }
        fs::write(&bundle_path, b"forensics").expect("write forensics fixture");
        let artifact_id = uuid::Uuid::now_v7();
        WindowsPlatform::with_runner_for_test(
            Box::new(QueuedWindowsRunner::new([
                String::new(),
                String::new(),
                quarantine_receipt_output(&quarantine_path, "deadbeef"),
                artifact_bundle_output(artifact_id, &bundle_path),
                firewall_isolation_output(
                    r"C:\ProgramData\Aegis\firewall\backup.json",
                    "AegisIsolation-test",
                ),
                String::new(),
            ])),
            healthy_host(),
        )
    }

    #[test]
    fn windows_baseline_registers_required_providers() {
        let platform = WindowsPlatform::default();
        let providers = platform.provider_kinds();

        assert!(providers.contains(&WindowsProviderKind::EtwProcess));
        assert!(providers.contains(&WindowsProviderKind::RegistryCallback));
        assert!(providers.contains(&WindowsProviderKind::IpcSensor));
        assert!(providers.contains(&WindowsProviderKind::ModuleLoadSensor));
        assert!(providers.contains(&WindowsProviderKind::SnapshotProtection));
        assert!(providers.contains(&WindowsProviderKind::DeviceControl));
        assert_eq!(providers.len(), 12);
    }

    #[test]
    fn windows_start_requires_real_execution_mode() {
        let mut platform = WindowsPlatform::new_with_runner(Box::new(FailingWindowsRunner), false);
        let error = platform
            .start(&SensorConfig {
                profile: "windows".to_string(),
                queue_capacity: 1024,
            })
            .expect_err("start should fail without a reachable windows host");
        let message = error.to_string();
        assert!(
            message.contains("windows host unavailable")
                || message.contains("probe windows host capabilities")
        );
    }

    #[test]
    fn windows_baseline_polls_injected_events() {
        let baseline = process_output(&[("System", 4, 0, None)]);
        let mut platform = platform_with_probe_and_processes([baseline.clone(), baseline]);
        platform
            .start(&SensorConfig {
                profile: "windows".to_string(),
                queue_capacity: 1024,
            })
            .expect("start windows runtime");
        platform.inject_event(WindowsEventStub {
            provider: WindowsProviderKind::EtwProcess,
            operation: "process-create".to_string(),
            subject: "powershell.exe".to_string(),
        });

        let mut buffer = EventBuffer::default();
        let drained = platform.poll_events(&mut buffer).expect("poll events");

        assert_eq!(drained, 1);
        assert_eq!(buffer.records.len(), 1);
    }

    #[test]
    fn windows_execution_snapshot_tracks_response_and_block_state() {
        let platform = platform_with_probe();
        platform.suspend_process(4242).expect("suspend");
        platform.kill_ppl_process(4242).expect("kill protected");
        platform
            .protect_process(4242)
            .expect("protect process should record");
        platform
            .protect_files(&[PathBuf::from("C:/temp/payload.exe")])
            .expect("protect files should record");
        let receipt = platform
            .quarantine_file(Path::new("C:/temp/payload.exe"))
            .expect("quarantine should execute");
        let bundle = platform
            .collect_forensics(&ForensicSpec {
                include_memory: true,
                include_registry: true,
                include_network: false,
            })
            .expect("collect forensics should execute");
        platform
            .registry_rollback(&RollbackTarget {
                selector: r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
            })
            .expect("registry rollback should materialize audit artifact");
        platform
            .network_isolate(&IsolationRulesV2 {
                ttl: Duration::from_secs(300),
                allowed_control_plane_ips: vec!["10.0.0.10".to_string()],
            })
            .expect("network isolate");
        platform
            .network_release()
            .expect("network release should restore firewall state");
        platform
            .block_hash("deadbeef", Duration::from_secs(90))
            .expect("block hash");

        let snapshot = platform.execution_snapshot();

        assert_eq!(snapshot.suspended_pids, vec![4242]);
        assert_eq!(snapshot.terminated_protected_pids, vec![4242]);
        assert_eq!(snapshot.protected_pids, vec![4242]);
        assert_eq!(
            snapshot.protected_paths,
            vec![PathBuf::from("C:/temp/payload.exe")]
        );
        assert_eq!(snapshot.quarantined_files.len(), 1);
        assert_eq!(snapshot.quarantined_files[0], receipt);
        assert!(snapshot.quarantined_files[0].vault_path.exists());
        assert_eq!(snapshot.forensic_artifacts.len(), 1);
        assert_eq!(snapshot.forensic_artifacts[0], bundle);
        assert!(snapshot.forensic_artifacts[0].location.exists());
        assert_eq!(snapshot.rollback_targets.len(), 1);
        assert_eq!(
            snapshot.rollback_targets[0].selector,
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
        );
        assert_eq!(snapshot.audit_artifacts.len(), 2);
        let protection_artifact = snapshot
            .audit_artifacts
            .iter()
            .find(|path| {
                path.file_name().and_then(|value| value.to_str()) == Some("protection-surface.json")
            })
            .expect("protection artifact should exist");
        let rollback_artifact = snapshot
            .audit_artifacts
            .iter()
            .find(|path| {
                path.file_name()
                    .and_then(|value| value.to_str())
                    .map(|value| value.starts_with("rollback-"))
                    .unwrap_or(false)
            })
            .expect("rollback artifact should exist");
        assert!(protection_artifact.exists());
        assert!(rollback_artifact.exists());
        let protection_json =
            fs::read_to_string(protection_artifact).expect("read protection artifact");
        assert!(protection_json.contains("C:/temp/payload.exe"));
        assert!(protection_json.contains("Image File Execution Options"));
        let rollback_json = fs::read_to_string(rollback_artifact).expect("read rollback artifact");
        assert!(rollback_json.contains(r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
        assert!(rollback_json.contains("C:/temp/payload.exe"));
        assert!(!snapshot.network_isolation_active);
        assert_eq!(
            snapshot
                .active_blocks
                .iter()
                .find(|lease| lease.kind == "hash")
                .map(|lease| lease.ttl_secs),
            Some(90)
        );
    }

    #[test]
    fn windows_health_snapshot_reports_real_host_probe_state() {
        let mut platform =
            platform_with_probe_and_processes([process_output(&[("System", 4, 0, None)])]);
        platform
            .start(&SensorConfig {
                profile: "windows".to_string(),
                queue_capacity: 1024,
            })
            .expect("start windows runtime");

        let snapshot = platform.health_snapshot();

        assert_eq!(
            snapshot.provider_health.get("EtwProcess").copied(),
            Some(true)
        );
        assert_eq!(
            snapshot.provider_health.get("PsProcess").copied(),
            Some(true)
        );
        assert_eq!(
            snapshot.provider_health.get("WfpNetwork").copied(),
            Some(true)
        );
        assert_eq!(
            snapshot.provider_health.get("RegistryCallback").copied(),
            Some(false)
        );
        assert_eq!(
            snapshot
                .integrity_reports
                .get("platform_protection")
                .map(|report| report.passed),
            Some(false)
        );
        assert_eq!(
            snapshot
                .integrity_reports
                .get("etw_ingest")
                .map(|report| report.passed),
            Some(true)
        );
        assert_eq!(
            snapshot
                .integrity_reports
                .get("amsi_script")
                .map(|report| report.passed),
            Some(false)
        );
        assert!(
            platform
                .check_etw_integrity()
                .expect("etw integrity")
                .healthy
        );
        assert!(
            !platform
                .check_amsi_integrity()
                .expect("amsi integrity")
                .healthy
        );
        assert!(platform.capabilities().process);
        assert!(platform.capabilities().network);
        assert!(platform.capabilities().auth);
        assert!(!platform.capabilities().registry);
        assert!(
            !platform
                .check_ssdt_integrity()
                .expect("ssdt integrity")
                .passed
        );
    }

    #[test]
    fn windows_amsi_health_reflects_runtime_and_script_block_state() {
        let mut platform = WindowsPlatform::new_with_runner(
            Box::new(QueuedWindowsRunner::new([
                probe_output_with_surface(true, true, false, false, false, false),
                process_output(&[("System", 4, 0, None)]),
                audit_cursor_output(150),
                network_output(&[]),
            ])),
            false,
        );
        platform
            .start(&SensorConfig {
                profile: "windows".to_string(),
                queue_capacity: 1024,
            })
            .expect("start windows runtime");

        let snapshot = platform.health_snapshot();

        assert_eq!(
            snapshot.provider_health.get("AmsiScript").copied(),
            Some(true)
        );
        assert_eq!(
            snapshot
                .integrity_reports
                .get("amsi_script")
                .map(|report| report.passed),
            Some(true)
        );
        assert_eq!(
            snapshot
                .integrity_reports
                .get("etw_ingest")
                .map(|report| report.passed),
            Some(true)
        );
        assert!(
            platform
                .check_amsi_integrity()
                .expect("amsi integrity")
                .healthy
        );
        assert!(
            platform
                .check_etw_integrity()
                .expect("etw integrity")
                .healthy
        );
    }

    #[test]
    fn windows_poll_events_emits_real_process_delta() {
        let mut platform = platform_with_probe_and_processes([
            process_output(&[("System", 4, 0, None)]),
            process_output(&[
                ("System", 4, 0, None),
                (
                    "powershell.exe",
                    4242,
                    640,
                    Some("powershell.exe -NoProfile -EncodedCommand AAAA"),
                ),
            ]),
        ]);
        platform
            .start(&SensorConfig {
                profile: "windows".to_string(),
                queue_capacity: 1024,
            })
            .expect("start windows runtime");

        let mut buffer = EventBuffer::default();
        let drained = platform.poll_events(&mut buffer).expect("poll events");

        assert_eq!(drained, 1);
        let event = String::from_utf8(buffer.records[0].clone()).expect("event utf8");
        assert!(event.contains("PsProcess"));
        assert!(event.contains("process-start"));
        assert!(event.contains("powershell.exe"));
    }

    #[test]
    fn windows_hidden_process_detection_compares_wmi_and_tasklist_views() {
        let platform = WindowsPlatform::with_runner_for_test(
            Box::new(QueuedWindowsRunner::new([
                process_output(&[
                    ("System", 4, 0, None),
                    ("hidden.exe", 500, 4, Some("C:\\hidden.exe")),
                ]),
                tasklist_output(&[("System", 4), ("ghost.exe", 600)]),
            ])),
            healthy_host(),
        );

        let suspicious = platform
            .detect_hidden_processes()
            .expect("detect hidden processes");

        assert_eq!(suspicious.len(), 2);
        assert!(suspicious.iter().any(|entry| entry.pid == 500));
        assert!(suspicious.iter().any(|entry| entry.pid == 600));
    }

    #[test]
    fn windows_poll_events_emits_security_process_audit_delta_once() {
        let mut platform = WindowsPlatform::new_with_runner(
            Box::new(QueuedWindowsRunner::new([
                probe_output(),
                process_output(&[("System", 4, 0, None)]),
                audit_cursor_output(100),
                network_output(&[]),
                process_output(&[("System", 4, 0, None)]),
                security_process_event_output(&[(
                    101,
                    Some("C:\\Windows\\System32\\cmd.exe"),
                    Some("cmd.exe /c whoami"),
                )]),
                network_output(&[]),
                process_output(&[("System", 4, 0, None)]),
                security_process_event_output(&[]),
                network_output(&[]),
            ])),
            false,
        );
        platform
            .start(&SensorConfig {
                profile: "windows".to_string(),
                queue_capacity: 1024,
            })
            .expect("start windows runtime");

        let mut first_buffer = EventBuffer::default();
        let first_drained = platform
            .poll_events(&mut first_buffer)
            .expect("poll security audit events");

        assert_eq!(first_drained, 1);
        let first_event = String::from_utf8(first_buffer.records[0].clone()).expect("event utf8");
        assert!(first_event.contains("EtwProcess"));
        assert!(first_event.contains("process-audit"));
        assert!(first_event.contains("cmd.exe"));

        let mut second_buffer = EventBuffer::default();
        let second_drained = platform
            .poll_events(&mut second_buffer)
            .expect("poll security audit events again");

        assert_eq!(second_drained, 0);
        assert!(second_buffer.records.is_empty());
    }

    #[test]
    fn windows_poll_events_emits_real_network_delta() {
        let mut platform = WindowsPlatform::new_with_runner(
            Box::new(QueuedWindowsRunner::new([
                probe_output(),
                process_output(&[("System", 4, 0, None)]),
                audit_cursor_output(200),
                network_output(&[(
                    "tcp",
                    "10.0.0.5",
                    49822,
                    Some("10.0.0.10"),
                    Some(443),
                    Some("Established"),
                    Some(4242),
                )]),
                process_output(&[("System", 4, 0, None)]),
                security_process_event_output(&[]),
                network_output(&[
                    (
                        "tcp",
                        "10.0.0.5",
                        49822,
                        Some("10.0.0.10"),
                        Some(443),
                        Some("Established"),
                        Some(4242),
                    ),
                    (
                        "udp",
                        "10.0.0.5",
                        5353,
                        None,
                        None,
                        Some("Listen"),
                        Some(9000),
                    ),
                ]),
            ])),
            false,
        );
        platform
            .start(&SensorConfig {
                profile: "windows".to_string(),
                queue_capacity: 1024,
            })
            .expect("start windows runtime");

        let mut buffer = EventBuffer::default();
        let drained = platform.poll_events(&mut buffer).expect("poll events");

        assert_eq!(drained, 1);
        let event = String::from_utf8(buffer.records[0].clone()).expect("event utf8");
        assert!(event.contains("WfpNetwork"));
        assert!(event.contains("network-open"));
        assert!(event.contains("udp"));
        assert!(event.contains("5353"));
    }

    #[test]
    fn windows_asset_visibility_tracks_named_pipe_module_vss_and_device_deltas() {
        let mut platform = WindowsPlatform::new_with_runner(
            Box::new(QueuedWindowsRunner::new([
                probe_output_with_assets(true, true, true, true),
                process_output(&[("System", 4, 0, None)]),
                audit_cursor_output(300),
                network_output(&[]),
                named_pipe_output(&[r"\\.\pipe\svcctl"]),
                module_output(&[(4, "System", r"C:\Windows\System32\ntdll.dll")]),
                vss_output(&[(
                    r"{11111111-1111-1111-1111-111111111111}",
                    Some(r"\\?\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}\"),
                )]),
                device_output(&[(
                    r"USB\VID_0781&PID_5581\000000000001",
                    Some("USB"),
                    Some("SanDisk USB"),
                    Some("OK"),
                )]),
                process_output(&[("System", 4, 0, None)]),
                security_process_event_output(&[]),
                network_output(&[]),
                named_pipe_output(&[r"\\.\pipe\svcctl", r"\\.\pipe\msagent_1234"]),
                module_output(&[
                    (4, "System", r"C:\Windows\System32\ntdll.dll"),
                    (4242, "powershell", r"C:\Temp\evil.dll"),
                ]),
                vss_output(&[
                    (
                        r"{11111111-1111-1111-1111-111111111111}",
                        Some(r"\\?\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}\"),
                    ),
                    (
                        r"{22222222-2222-2222-2222-222222222222}",
                        Some(r"\\?\Volume{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}\"),
                    ),
                ]),
                device_output(&[
                    (
                        r"USB\VID_0781&PID_5581\000000000001",
                        Some("USB"),
                        Some("SanDisk USB"),
                        Some("OK"),
                    ),
                    (
                        r"USB\VID_1D6B&PID_0002\000000000002",
                        Some("USB"),
                        Some("YubiKey"),
                        Some("OK"),
                    ),
                ]),
            ])),
            false,
        );
        platform
            .start(&SensorConfig {
                profile: "windows".to_string(),
                queue_capacity: 1024,
            })
            .expect("start windows runtime");

        let snapshot = platform.health_snapshot();
        assert_eq!(
            snapshot.provider_health.get("IpcSensor").copied(),
            Some(true)
        );
        assert_eq!(
            snapshot.provider_health.get("ModuleLoadSensor").copied(),
            Some(true)
        );
        assert_eq!(
            snapshot.provider_health.get("SnapshotProtection").copied(),
            Some(true)
        );
        assert_eq!(
            snapshot.provider_health.get("DeviceControl").copied(),
            Some(true)
        );

        let mut buffer = EventBuffer::default();
        let drained = platform
            .poll_events(&mut buffer)
            .expect("poll asset visibility events");

        assert_eq!(drained, 4);
        let events = buffer
            .records
            .iter()
            .map(|record| String::from_utf8(record.clone()).expect("event utf8"))
            .collect::<Vec<_>>();
        assert!(events.iter().any(|event| {
            event.contains("IpcSensor")
                && event.contains("pipe-visible")
                && event.contains(r"\\.\pipe\msagent_1234")
        }));
        assert!(events.iter().any(|event| {
            event.contains("ModuleLoadSensor")
                && event.contains("module-visible")
                && event.contains(r"C:\Temp\evil.dll")
        }));
        assert!(events.iter().any(|event| {
            event.contains("SnapshotProtection")
                && event.contains("shadow-visible")
                && event.contains(r"{22222222-2222-2222-2222-222222222222}")
        }));
        assert!(events.iter().any(|event| {
            event.contains("DeviceControl")
                && event.contains("device-visible")
                && event.contains("YubiKey")
        }));
    }

    #[test]
    fn windows_etw_integrity_requires_process_creation_audit() {
        let mut host = healthy_host();
        host.has_process_creation_events = false;
        let platform = WindowsPlatform::with_runner_for_test(
            Box::new(QueuedWindowsRunner::new(Vec::<String>::new())),
            host,
        );

        assert!(
            !platform
                .check_etw_integrity()
                .expect("etw integrity")
                .healthy
        );
    }
}
