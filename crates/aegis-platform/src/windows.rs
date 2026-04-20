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
use serde::Deserialize;
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
    has_net_connection: bool,
    has_firewall: bool,
    has_registry_cli: bool,
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
            WindowsProviderKind::EtwProcess => self.any_event_log(),
            WindowsProviderKind::PsProcess => self.has_process_inventory,
            WindowsProviderKind::ObProcess => false,
            WindowsProviderKind::MinifilterFile => false,
            WindowsProviderKind::WfpNetwork => false,
            WindowsProviderKind::RegistryCallback => false,
            WindowsProviderKind::AmsiScript => false,
            WindowsProviderKind::MemorySensor => false,
            WindowsProviderKind::IpcSensor => false,
            WindowsProviderKind::ModuleLoadSensor => false,
            WindowsProviderKind::SnapshotProtection => false,
            WindowsProviderKind::DeviceControl => false,
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
    has_net_connection: bool,
    has_firewall: bool,
    has_registry_cli: bool,
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

struct WindowsState {
    base_dir: PathBuf,
    pending_events: VecDeque<Vec<u8>>,
    execution: PlatformExecutionSnapshot,
    host: WindowsHostCapabilities,
    host_capabilities_pinned: bool,
    known_processes: BTreeMap<u32, WindowsProcessSnapshot>,
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
    fn new_with_runner(runner: Box<dyn WindowsCommandRunner>, host_capabilities_pinned: bool) -> Self {
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
            }),
        }
    }

    #[cfg(test)]
    fn with_runner_for_test(
        runner: Box<dyn WindowsCommandRunner>,
        host: WindowsHostCapabilities,
    ) -> Self {
        let platform = Self::new_with_runner(runner, true);
        platform
            .state
            .lock()
            .expect("windows state poisoned")
            .host = host;
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
            network: false,
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
        self.state
            .lock()
            .expect("windows state poisoned")
            .execution
            .suspended_pids
            .push(pid);
        Ok(())
    }

    fn kill_process(&self, pid: u32) -> Result<()> {
        self.state
            .lock()
            .expect("windows state poisoned")
            .execution
            .terminated_pids
            .push(pid);
        Ok(())
    }

    fn kill_ppl_process(&self, pid: u32) -> Result<()> {
        self.state
            .lock()
            .expect("windows state poisoned")
            .execution
            .terminated_protected_pids
            .push(pid);
        Ok(())
    }

    fn quarantine_file(&self, path: &Path) -> Result<QuarantineReceipt> {
        let mut state = self.state.lock().expect("windows state poisoned");
        let receipt = materialize_quarantine(&mut state, path, "windows-quarantine")?;
        state.execution.quarantined_files.push(receipt.clone());
        Ok(receipt)
    }

    fn network_isolate(&self, rules: &IsolationRulesV2) -> Result<()> {
        let mut state = self.state.lock().expect("windows state poisoned");
        state.execution.network_isolation_active = true;
        state.execution.last_isolation_rules = Some(rules.clone());
        Ok(())
    }

    fn network_release(&self) -> Result<()> {
        self.state
            .lock()
            .expect("windows state poisoned")
            .execution
            .network_isolation_active = false;
        Ok(())
    }

    fn registry_rollback(&self, target: &RollbackTarget) -> Result<()> {
        self.state
            .lock()
            .expect("windows state poisoned")
            .execution
            .rollback_targets
            .push(target.clone());
        Ok(())
    }

    fn collect_forensics(&self, spec: &ForensicSpec) -> Result<ArtifactBundle> {
        let mut state = self.state.lock().expect("windows state poisoned");
        let bundle = materialize_artifact(&mut state, spec, "zip", "windows-forensics")?;
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
        self.state
            .lock()
            .expect("windows state poisoned")
            .execution
            .protected_paths
            .extend(paths.iter().cloned());
        Ok(())
    }

    fn verify_integrity(&self) -> Result<IntegrityReport> {
        let host = self.host_capabilities();
        Ok(protection_report(&host))
    }

    fn check_etw_integrity(&self) -> Result<EtwStatus> {
        let host = self.host_capabilities();
        Ok(EtwStatus {
            healthy: host.reachable && host.running_on_windows && host.any_event_log(),
        })
    }

    fn check_amsi_integrity(&self) -> Result<AmsiStatus> {
        Ok(AmsiStatus { healthy: false })
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
    has_net_connection = (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) -ne $null
    has_firewall = ((Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) -ne $null) -and ((Get-Command netsh.exe -ErrorAction SilentlyContinue) -ne $null)
    has_registry_cli = (Get-Command reg.exe -ErrorAction SilentlyContinue) -ne $null
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
        has_net_connection: probe.has_net_connection,
        has_firewall: probe.has_firewall,
        has_registry_cli: probe.has_registry_cli,
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
    Ok(())
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

fn materialize_quarantine(
    state: &mut WindowsState,
    original: &Path,
    marker: &str,
) -> Result<QuarantineReceipt> {
    let file_name = original
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("artifact.bin");
    let vault_path = state.base_dir.join("quarantine").join(file_name);
    if let Some(parent) = vault_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&vault_path, format!("{marker}:{}", original.display()))?;
    Ok(QuarantineReceipt {
        vault_path,
        sha256: format!("windows:{}", original.display()),
    })
}

fn materialize_artifact(
    state: &mut WindowsState,
    spec: &ForensicSpec,
    extension: &str,
    marker: &str,
) -> Result<ArtifactBundle> {
    let artifact_id = Uuid::now_v7();
    let location = state
        .base_dir
        .join("forensics")
        .join(format!("{artifact_id}.{extension}"));
    if let Some(parent) = location.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &location,
        format!(
            "{marker}|memory={}|registry={}|network={}",
            spec.include_memory, spec.include_registry, spec.include_network
        ),
    )?;
    Ok(ArtifactBundle {
        artifact_id,
        location,
    })
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
    use aegis_model::{EventBuffer, ForensicSpec, IsolationRulesV2, SensorConfig};
    use anyhow::{anyhow, bail, Result};
    use std::collections::VecDeque;
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
            has_net_connection: true,
            has_firewall: true,
            has_registry_cli: true,
            last_error: None,
        }
    }

    fn probe_output() -> String {
        r#"{"computer_name":"DESKTOP-TLASHJG","user_name":"desktop-tlashjg\\lamba","is_admin":true,"has_process_inventory":true,"has_security_log":true,"has_powershell_log":true,"has_wmi_log":true,"has_task_scheduler_log":true,"has_sysmon_log":false,"has_net_connection":true,"has_firewall":true,"has_registry_cli":true}"#.to_string()
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
        let mut responses = vec![probe_output()];
        responses.extend(processes);
        WindowsPlatform::new_with_runner(Box::new(QueuedWindowsRunner::new(responses)), false)
    }

    fn platform_with_probe() -> WindowsPlatform {
        WindowsPlatform::with_runner_for_test(
            Box::new(QueuedWindowsRunner::new(Vec::<String>::new())),
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
        let mut platform =
            platform_with_probe_and_processes([baseline.clone(), baseline]);
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
            .expect("quarantine should materialize receipt");
        let bundle = platform
            .collect_forensics(&ForensicSpec {
                include_memory: true,
                include_registry: true,
                include_network: false,
            })
            .expect("collect forensics should materialize bundle");
        platform
            .network_isolate(&IsolationRulesV2 {
                ttl: Duration::from_secs(300),
                allowed_control_plane_ips: vec!["10.0.0.10".to_string()],
            })
            .expect("network isolate");
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
        assert!(snapshot.network_isolation_active);
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
        let mut platform = platform_with_probe_and_processes([process_output(&[
            ("System", 4, 0, None),
        ])]);
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
}
