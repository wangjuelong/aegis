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
use aegis_script::ScriptDecodePipeline;
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;

const AEGIS_WINDOWS_DRIVER_SERVICE_NAME: &str = "AegisSensorKmod";
const AEGIS_WINDOWS_DRIVER_DEVICE_PATH: &str = r"\\.\AegisSensor";
const AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION: u32 = 0x0001_0000;
const AEGIS_WINDOWS_DRIVER_IOCTL_QUERY_VERSION: u32 = 0x0022_2000;
const AEGIS_WINDOWS_FILE_MONITOR_PORT_NAME: &str = r"\AegisFileMonitorPort";
const WINDOWS_QUERY_FILE_EVENTS_SCRIPT: &str =
    include_str!("../../../scripts/windows-query-file-events.ps1");
const WINDOWS_CONFIGURE_FILE_PROTECTION_SCRIPT: &str =
    include_str!("../../../scripts/windows-configure-file-protection.ps1");
const WINDOWS_QUERY_REGISTRY_EVENTS_SCRIPT: &str =
    include_str!("../../../scripts/windows-query-registry-events.ps1");
const WINDOWS_ROLLBACK_REGISTRY_SCRIPT: &str =
    include_str!("../../../scripts/windows-rollback-registry.ps1");
const WINDOWS_PROTECT_PROCESS_SCRIPT: &str =
    include_str!("../../../scripts/windows-protect-process.ps1");
const WINDOWS_QUERY_DRIVER_INTEGRITY_SCRIPT: &str =
    include_str!("../../../scripts/windows-query-driver-integrity.ps1");
const WINDOWS_SCAN_SCRIPT_WITH_AMSI_SCRIPT: &str =
    include_str!("../../../scripts/windows-scan-script-with-amsi.ps1");
const WINDOWS_QUERY_SCRIPT_EVENTS_SCRIPT: &str =
    include_str!("../../../scripts/windows-query-script-events.ps1");
const WINDOWS_QUERY_MEMORY_SNAPSHOT_SCRIPT: &str =
    include_str!("../../../scripts/windows-query-memory-snapshot.ps1");

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
    has_amsi_scan_interface: bool,
    has_memory_inventory: bool,
    has_named_pipe_inventory: bool,
    has_module_inventory: bool,
    has_vss_inventory: bool,
    has_device_inventory: bool,
    has_driver_service: bool,
    has_driver_service_running: bool,
    has_driver_control_device: bool,
    driver_protocol_version: Option<u32>,
    driver_version: Option<String>,
    driver_status_detail: Option<String>,
    has_file_monitor_port: bool,
    file_monitor_protocol_version: Option<u32>,
    file_monitor_queue_capacity: Option<u32>,
    file_monitor_current_sequence: Option<u32>,
    file_monitor_status_detail: Option<String>,
    registry_callback_registered: bool,
    registry_journal_capacity: Option<u32>,
    registry_current_sequence: Option<u32>,
    registry_status_detail: Option<String>,
    ob_callback_registered: bool,
    protected_process_count: Option<u32>,
    protected_file_path_count: Option<u32>,
    ssdt_inspection_succeeded: bool,
    ssdt_suspicious: bool,
    callback_inspection_succeeded: bool,
    callback_suspicious: bool,
    kernel_code_inspection_succeeded: bool,
    kernel_code_suspicious: bool,
    code_integrity_options: Option<u32>,
    driver_integrity_detail: Option<String>,
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

    fn driver_transport_ready(&self) -> bool {
        self.reachable
            && self.running_on_windows
            && self.has_driver_service_running
            && self.has_driver_control_device
            && self.driver_protocol_version == Some(AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION)
    }

    fn driver_transport_summary(&self) -> String {
        let protocol = self
            .driver_protocol_version
            .map(|value| format!("0x{value:08x}"))
            .unwrap_or_else(|| "none".to_string());
        let version = self
            .driver_version
            .clone()
            .unwrap_or_else(|| "-".to_string());
        let detail = self
            .driver_status_detail
            .clone()
            .unwrap_or_else(|| "-".to_string());
        format!(
            "driver_service={};driver_running={};driver_device={};driver_protocol={};driver_version={};detail={}",
            self.has_driver_service,
            self.has_driver_service_running,
            self.has_driver_control_device,
            protocol,
            version,
            detail
        )
    }

    fn file_monitor_ready(&self) -> bool {
        self.driver_transport_ready()
            && self.has_file_monitor_port
            && self.file_monitor_protocol_version == Some(AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION)
    }

    fn registry_provider_ready(&self) -> bool {
        self.driver_transport_ready() && self.registry_callback_registered
    }

    fn process_protection_ready(&self) -> bool {
        self.driver_transport_ready() && self.ob_callback_registered
    }

    fn script_sensor_ready(&self) -> bool {
        self.reachable
            && self.running_on_windows
            && self.has_powershell_log
            && self.has_amsi_runtime
            && self.has_script_block_logging
            && self.has_amsi_scan_interface
    }

    fn memory_sensor_ready(&self) -> bool {
        self.reachable
            && self.running_on_windows
            && self.has_process_inventory
            && self.has_memory_inventory
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
            WindowsProviderKind::ObProcess => self.process_protection_ready(),
            WindowsProviderKind::MinifilterFile => self.file_monitor_ready(),
            WindowsProviderKind::WfpNetwork => self.has_net_connection,
            WindowsProviderKind::RegistryCallback => self.registry_provider_ready(),
            WindowsProviderKind::AmsiScript => self.script_sensor_ready(),
            WindowsProviderKind::MemorySensor => self.memory_sensor_ready(),
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
        facts.push(format!(
            "amsi_scan_interface={}",
            self.has_amsi_scan_interface
        ));
        facts.push(format!("memory_inventory={}", self.has_memory_inventory));
        facts.push(self.driver_transport_summary());
        facts.push(format!(
            "file_monitor={};file_protocol={};file_queue={};protected_paths={};file_detail={}",
            self.file_monitor_ready(),
            self.file_monitor_protocol_version
                .map(|value| format!("0x{value:08x}"))
                .unwrap_or_else(|| "none".to_string()),
            self.file_monitor_queue_capacity
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.protected_file_path_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.file_monitor_status_detail
                .clone()
                .unwrap_or_else(|| "-".to_string())
        ));
        facts.push(format!(
            "registry_provider={};registry_journal_capacity={};registry_detail={}",
            self.registry_provider_ready(),
            self.registry_journal_capacity
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.registry_status_detail
                .clone()
                .unwrap_or_else(|| "-".to_string())
        ));
        facts.push(format!(
            "process_protection={};protected_pids={};driver_integrity={}",
            self.process_protection_ready(),
            self.protected_process_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.driver_integrity_detail
                .clone()
                .unwrap_or_else(|| "-".to_string())
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
    #[serde(default)]
    has_amsi_scan_interface: bool,
    #[serde(default)]
    has_memory_inventory: bool,
    has_named_pipe_inventory: bool,
    has_module_inventory: bool,
    has_vss_inventory: bool,
    has_device_inventory: bool,
    #[serde(default)]
    has_driver_service: bool,
    #[serde(default)]
    has_driver_service_running: bool,
    #[serde(default)]
    has_driver_control_device: bool,
    #[serde(default)]
    driver_protocol_version: Option<u32>,
    #[serde(default)]
    driver_version: Option<String>,
    #[serde(default)]
    driver_status_detail: Option<String>,
    #[serde(default)]
    has_file_monitor_port: bool,
    #[serde(default)]
    file_monitor_protocol_version: Option<u32>,
    #[serde(default)]
    file_monitor_queue_capacity: Option<u32>,
    #[serde(default)]
    file_monitor_current_sequence: Option<u32>,
    #[serde(default)]
    file_monitor_status_detail: Option<String>,
    #[serde(default)]
    registry_callback_registered: bool,
    #[serde(default)]
    registry_journal_capacity: Option<u32>,
    #[serde(default)]
    registry_current_sequence: Option<u32>,
    #[serde(default)]
    registry_status_detail: Option<String>,
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
struct WindowsScriptBlockCursor {
    record_id: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsRawScriptBlockEvent {
    record_id: u64,
    #[serde(default)]
    process_id: Option<u32>,
    #[serde(default)]
    script_block_id: Option<String>,
    #[serde(default)]
    message_number: Option<u32>,
    #[serde(default)]
    message_total: Option<u32>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    script_text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WindowsScriptBlockEvent {
    record_id: u64,
    process_id: Option<u32>,
    script_block_id: Option<String>,
    path: Option<String>,
    script_text: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct WindowsScriptBlockAssembly {
    message_total: u32,
    process_id: Option<u32>,
    path: Option<String>,
    fragments: BTreeMap<u32, String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsAmsiScanResponse {
    content_name: String,
    app_name: String,
    amsi_result: u32,
    blocked_by_admin: bool,
    malware: bool,
    should_block: bool,
    session_opened: bool,
    scan_interface_ready: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WindowsScriptAssessment {
    operation: String,
    risk_score: u8,
    script_sha256: String,
    preview: String,
    suspicious_tokens: Vec<String>,
    decode_layer_count: usize,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsMemorySnapshot {
    process_id: u32,
    process_name: String,
    working_set_bytes: u64,
    private_memory_bytes: u64,
    virtual_memory_bytes: u64,
    paged_memory_bytes: u64,
    #[serde(default)]
    path: Option<String>,
}

impl WindowsScriptAssessment {
    fn from_script(script: &str, scan: &WindowsAmsiScanResponse) -> Self {
        let decode = ScriptDecodePipeline.decode(script);
        let suspicious_tokens = decode.suspicious_tokens.clone();
        let mut risk_score = 0u8;
        risk_score = risk_score.saturating_add((decode.layers.len().min(3) as u8) * 20);
        risk_score = risk_score.saturating_add((suspicious_tokens.len().min(3) as u8) * 20);
        if scan.blocked_by_admin {
            risk_score = risk_score.saturating_add(20);
        }
        if scan.malware {
            risk_score = risk_score.saturating_add(30);
        }

        let blocks_on_tokens = suspicious_tokens.iter().any(|token| {
            matches!(
                token.as_str(),
                "AmsiUtils" | "Invoke-Mimikatz" | "VirtualAlloc"
            )
        });
        let operation = if scan.should_block || blocks_on_tokens {
            "script-block"
        } else if risk_score >= 40 || !suspicious_tokens.is_empty() || !decode.layers.is_empty() {
            "script-alert"
        } else {
            "script-allow"
        };

        let preview_source = if decode.decoded.is_empty() {
            script
        } else {
            decode.decoded.as_str()
        };
        let script_sha256 = {
            let mut hasher = Sha256::new();
            hasher.update(preview_source.as_bytes());
            format!("{:x}", hasher.finalize())
        };

        Self {
            operation: operation.to_string(),
            risk_score,
            script_sha256,
            preview: truncate_subject(preview_source),
            suspicious_tokens,
            decode_layer_count: decode.layers.len(),
        }
    }
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
struct WindowsFileMonitorStatus {
    protocol_version: u32,
    queue_capacity: u32,
    current_sequence: u32,
    #[serde(default)]
    protected_path_count: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsFileMonitorEvent {
    sequence: u32,
    timestamp: i64,
    process_id: u32,
    operation: String,
    path: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsFileMonitorQuery {
    protocol_version: u32,
    queue_capacity: u32,
    oldest_sequence: u32,
    current_sequence: u32,
    returned_count: u32,
    overflowed: bool,
    #[serde(default)]
    protected_path_count: u32,
    events: Vec<WindowsFileMonitorEvent>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsFileProtectionResponse {
    protocol_version: u32,
    protected_path_count: u32,
    #[serde(default)]
    resolved_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsRegistryMonitorStatus {
    protocol_version: u32,
    registry_callback_registered: bool,
    journal_capacity: u32,
    current_sequence: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsRegistryMonitorEvent {
    sequence: u32,
    timestamp: i64,
    operation: String,
    key_path: String,
    value_name: String,
    old_value_present: bool,
    new_value_present: bool,
    old_value: Option<String>,
    new_value: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsRegistryMonitorQuery {
    protocol_version: u32,
    oldest_sequence: u32,
    current_sequence: u32,
    returned_count: u32,
    overflowed: bool,
    events: Vec<WindowsRegistryMonitorEvent>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsRegistryRollbackResponse {
    protocol_version: u32,
    applied_count: u32,
    current_sequence: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsProcessProtectionResponse {
    protocol_version: u32,
    ob_callback_registered: bool,
    protected_process_count: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsDriverIntegrityStatus {
    protocol_version: u32,
    ob_callback_registered: bool,
    protected_process_count: u32,
    ssdt_inspection_succeeded: bool,
    ssdt_suspicious: bool,
    callback_inspection_succeeded: bool,
    callback_suspicious: bool,
    kernel_code_inspection_succeeded: bool,
    kernel_code_suspicious: bool,
    code_integrity_options: u32,
    code_integrity_enabled: bool,
    code_integrity_testsign: bool,
    code_integrity_kmci_enabled: bool,
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
    protected_pids: Vec<u32>,
    protected_paths: Vec<String>,
    registry_protection_surface: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct WindowsRegistryRollbackArtifact {
    selector: String,
    resolved_key_path: String,
    applied_count: u32,
    current_sequence: u32,
    protected_paths: Vec<String>,
    registry_protection_surface: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct WindowsFirewallBlockReceipt {
    rule_group: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct WindowsBlockAuditArtifact {
    kind: String,
    target: String,
    ttl_secs: u64,
    enforced: bool,
    enforcement_plane: String,
    firewall_rule_group: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct WindowsBlockClearArtifact {
    cleared_block_count: usize,
    cleared_rule_groups: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct WindowsIntegrityAuditArtifact {
    verify_integrity: IntegrityReport,
    ssdt: IntegrityReport,
    callback_tables: IntegrityReport,
    kernel_code: IntegrityReport,
    etw_ingest: IntegrityReport,
    amsi_script: IntegrityReport,
    memory_sensor: IntegrityReport,
}

struct WindowsState {
    base_dir: PathBuf,
    pending_events: VecDeque<Vec<u8>>,
    execution: PlatformExecutionSnapshot,
    host: WindowsHostCapabilities,
    host_capabilities_pinned: bool,
    known_processes: BTreeMap<u32, WindowsProcessSnapshot>,
    security_process_cursor: Option<u64>,
    script_block_cursor: Option<u64>,
    pending_script_blocks: BTreeMap<String, WindowsScriptBlockAssembly>,
    known_memory_processes: BTreeMap<u32, WindowsMemorySnapshot>,
    known_connections: BTreeMap<String, WindowsNetworkConnection>,
    known_named_pipes: BTreeMap<String, WindowsNamedPipeSnapshot>,
    known_modules: BTreeMap<String, WindowsModuleSnapshot>,
    known_vss_snapshots: BTreeMap<String, WindowsVssSnapshot>,
    known_devices: BTreeMap<String, WindowsDeviceSnapshot>,
    file_monitor_cursor: Option<u32>,
    registry_monitor_cursor: Option<u32>,
    firewall_backup_path: Option<String>,
    firewall_rule_group: Option<String>,
    block_rule_groups: Vec<String>,
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
                script_block_cursor: None,
                pending_script_blocks: BTreeMap::new(),
                known_memory_processes: BTreeMap::new(),
                known_connections: BTreeMap::new(),
                known_named_pipes: BTreeMap::new(),
                known_modules: BTreeMap::new(),
                known_vss_snapshots: BTreeMap::new(),
                known_devices: BTreeMap::new(),
                file_monitor_cursor: None,
                registry_monitor_cursor: None,
                firewall_backup_path: None,
                firewall_rule_group: None,
                block_rule_groups: Vec::new(),
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
                .map(|provider| {
                    (
                        format!("{provider:?}"),
                        host.provider_health(*provider, running),
                    )
                })
                .collect(),
            integrity_reports: BTreeMap::from([
                ("ssdt".to_string(), ssdt_report(&host)),
                ("callbacks".to_string(), callback_report(&host)),
                ("kernel_code".to_string(), kernel_code_report(&host)),
                ("platform_protection".to_string(), protection_report(&host)),
                (
                    "driver_transport".to_string(),
                    driver_transport_report(&host),
                ),
                ("etw_ingest".to_string(), etw_report(&host)),
                ("amsi_script".to_string(), amsi_report(&host)),
                ("memory_sensor".to_string(), memory_report(&host)),
            ]),
        }
    }

    pub fn inject_event(&self, event: WindowsEventStub) {
        let mut state = self.state.lock().expect("windows state poisoned");
        state.pending_events.push_back(event.encode());
    }
}

impl PlatformSensor for WindowsPlatform {
    fn start(&mut self, config: &SensorConfig) -> Result<()> {
        let mut state = self.state.lock().expect("windows state poisoned");
        if !state.host_capabilities_pinned {
            state.host = probe_host_capabilities(self.runner.as_ref())
                .with_context(|| "probe windows host capabilities")?;
        }
        if config.require_kernel_driver {
            ensure_windows_driver_transport(
                &state.host,
                "start windows platform in kernel-driver mode",
            )?;
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
        if state.host.script_sensor_ready() {
            state.script_block_cursor = latest_script_block_record_id(self.runner.as_ref())
                .with_context(|| "snapshot initial windows script-block cursor")?;
            state.pending_script_blocks.clear();
        } else {
            state.script_block_cursor = None;
            state.pending_script_blocks.clear();
        }
        if state.host.memory_sensor_ready() {
            state.known_memory_processes = snapshot_memory_inventory(self.runner.as_ref())
                .with_context(|| "snapshot initial windows memory inventory")?;
        } else {
            state.known_memory_processes.clear();
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
        state.file_monitor_cursor = state.host.file_monitor_current_sequence;
        state.registry_monitor_cursor = state.host.registry_current_sequence;
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
            file: host.file_monitor_ready(),
            network: host.has_net_connection,
            registry: host.registry_provider_ready(),
            auth: host.any_event_log(),
            script: host.script_sensor_ready(),
            memory: host.memory_sensor_ready(),
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
        ensure_windows_driver_transport(&state.host, "execute windows registry rollback")?;
        if !state.host.registry_provider_ready() {
            bail!(
                "execute windows registry rollback requires registry callback journal: {}",
                state.host.summary()
            );
        }
        let resolved_key_path =
            resolve_windows_registry_key_path(self.runner.as_ref(), &target.selector)
                .with_context(|| {
                    format!("resolve windows registry selector {}", target.selector)
                })?;
        let rollback = rollback_windows_registry_key(
            self.runner.as_ref(),
            &resolved_key_path,
            AEGIS_WINDOWS_DRIVER_SERVICE_NAME,
        )
        .with_context(|| format!("rollback windows registry key {}", resolved_key_path))?;
        state.execution.rollback_targets.push(target.clone());
        state.host.registry_current_sequence = Some(rollback.current_sequence);
        state.registry_monitor_cursor = Some(rollback.current_sequence);
        let artifact_path = write_windows_registry_rollback_artifact(
            &mut state,
            target,
            &resolved_key_path,
            &rollback,
        )
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
        let mut state = self.state.lock().expect("windows state poisoned");
        push_block(&mut state.execution, "hash", hash.to_string(), ttl);
        let artifact_path = write_windows_block_artifact(
            &mut state,
            "hash",
            hash.to_string(),
            ttl,
            false,
            "userspace-ledger",
            None,
        )?;
        state.execution.audit_artifacts.push(artifact_path);
        Ok(())
    }

    fn block_pid(&self, pid: u32, ttl: Duration) -> Result<()> {
        let mut state = self.state.lock().expect("windows state poisoned");
        push_block(&mut state.execution, "pid", pid.to_string(), ttl);
        let artifact_path = write_windows_block_artifact(
            &mut state,
            "pid",
            pid.to_string(),
            ttl,
            false,
            "userspace-ledger",
            None,
        )?;
        state.execution.audit_artifacts.push(artifact_path);
        Ok(())
    }

    fn block_path(&self, path: &Path, ttl: Duration) -> Result<()> {
        let mut state = self.state.lock().expect("windows state poisoned");
        let target = path.display().to_string();
        push_block(&mut state.execution, "path", target.clone(), ttl);
        let artifact_path = write_windows_block_artifact(
            &mut state,
            "path",
            target,
            ttl,
            false,
            "userspace-ledger",
            None,
        )?;
        state.execution.audit_artifacts.push(artifact_path);
        Ok(())
    }

    fn block_network(&self, target: &NetworkTarget, ttl: Duration) -> Result<()> {
        let mut state = self.state.lock().expect("windows state poisoned");
        ensure_windows_response_host(&state.host, "apply windows network block")?;
        if !state.host.has_firewall {
            bail!(
                "apply windows network block requires firewall capability: {}",
                state.host.summary()
            );
        }
        let target_value = target.value.clone();
        let receipt = apply_windows_firewall_block(&mut state, self.runner.as_ref(), &target_value)
            .with_context(|| format!("apply windows network block {}", target_value))?;
        state.block_rule_groups.push(receipt.rule_group.clone());
        push_block(&mut state.execution, "network", target_value.clone(), ttl);
        let artifact_path = write_windows_block_artifact(
            &mut state,
            "network",
            target_value,
            ttl,
            true,
            "windows-firewall",
            Some(receipt.rule_group),
        )?;
        state.execution.audit_artifacts.push(artifact_path);
        Ok(())
    }

    fn clear_all_blocks(&self) -> Result<()> {
        let mut state = self.state.lock().expect("windows state poisoned");
        let cleared_rule_groups = state.block_rule_groups.clone();
        if !cleared_rule_groups.is_empty() {
            clear_windows_firewall_blocks(&mut state, self.runner.as_ref(), &cleared_rule_groups)
                .with_context(|| "clear windows firewall block rules")?;
        }
        let cleared_block_count = state.execution.active_blocks.len();
        state.execution.active_blocks.clear();
        state.block_rule_groups.clear();
        let artifact_path = write_windows_block_clear_artifact(
            &mut state,
            cleared_block_count,
            cleared_rule_groups,
        )?;
        state.execution.audit_artifacts.push(artifact_path);
        Ok(())
    }
}

impl KernelIntegrity for WindowsPlatform {
    fn check_ssdt_integrity(&self) -> Result<IntegrityReport> {
        let host = self.host_capabilities();
        Ok(ssdt_report(&host))
    }

    fn check_callback_tables(&self) -> Result<IntegrityReport> {
        let host = self.host_capabilities();
        Ok(callback_report(&host))
    }

    fn check_kernel_code(&self) -> Result<IntegrityReport> {
        let host = self.host_capabilities();
        Ok(kernel_code_report(&host))
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
        let mut state = self.state.lock().expect("windows state poisoned");
        ensure_windows_driver_transport(&state.host, "protect windows process")?;
        let response =
            protect_windows_process(self.runner.as_ref(), pid, AEGIS_WINDOWS_DRIVER_SERVICE_NAME)
                .with_context(|| format!("protect windows process {pid}"))?;
        if response.protocol_version != AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION {
            bail!(
                "process protection protocol mismatch: expected 0x{expected:08x}, got 0x{actual:08x}",
                expected = AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION,
                actual = response.protocol_version
            );
        }

        state.host.ob_callback_registered = response.ob_callback_registered;
        state.host.protected_process_count = Some(response.protected_process_count);
        if !state.execution.protected_pids.contains(&pid) {
            state.execution.protected_pids.push(pid);
        }
        record_windows_protection_surface_artifact(&mut state)
            .with_context(|| "write windows protection surface artifact")?;
        Ok(())
    }

    fn protect_files(&self, paths: &[PathBuf]) -> Result<()> {
        let mut state = self.state.lock().expect("windows state poisoned");
        ensure_windows_driver_transport(&state.host, "protect windows files")?;
        if !state.host.file_monitor_ready() {
            bail!(
                "protect windows files requires minifilter control port {}; {}",
                AEGIS_WINDOWS_FILE_MONITOR_PORT_NAME,
                state.host.summary()
            );
        }

        let mut merged_paths = state.execution.protected_paths.clone();
        for path in paths {
            if !merged_paths.iter().any(|existing| existing == path) {
                merged_paths.push(path.clone());
            }
        }

        let clear = clear_windows_file_protection(
            self.runner.as_ref(),
            AEGIS_WINDOWS_FILE_MONITOR_PORT_NAME,
        )
        .with_context(|| "clear windows protected file paths before apply")?;
        if clear.protocol_version != AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION {
            bail!(
                "file protection clear protocol mismatch: expected 0x{expected:08x}, got 0x{actual:08x}",
                expected = AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION,
                actual = clear.protocol_version
            );
        }

        let mut protected_path_count = clear.protected_path_count;
        for path in &merged_paths {
            let response = protect_windows_file_path(
                self.runner.as_ref(),
                AEGIS_WINDOWS_FILE_MONITOR_PORT_NAME,
                path,
            )
            .with_context(|| format!("protect windows file path {}", path.display()))?;
            if response.protocol_version != AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION {
                bail!(
                    "file protection protocol mismatch: expected 0x{expected:08x}, got 0x{actual:08x}",
                    expected = AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION,
                    actual = response.protocol_version
                );
            }
            protected_path_count = response.protected_path_count;
        }

        state.execution.protected_paths = merged_paths;
        state.host.protected_file_path_count = Some(protected_path_count);
        refresh_windows_driver_surfaces(&mut state.host, self.runner.as_ref())
            .with_context(|| "refresh windows driver surfaces after protect_files")?;
        record_windows_protection_surface_artifact(&mut state)
            .with_context(|| "write windows protection surface artifact")?;
        Ok(())
    }

    fn verify_integrity(&self) -> Result<IntegrityReport> {
        let mut state = self.state.lock().expect("windows state poisoned");
        if state.host.driver_transport_ready() {
            refresh_windows_driver_surfaces(&mut state.host, self.runner.as_ref())
                .with_context(|| "refresh windows driver surfaces before verify_integrity")?;
        }
        let report = protection_report(&state.host);
        let artifact_path = write_windows_integrity_artifact(&mut state)
            .with_context(|| "write windows integrity artifact")?;
        state.execution.audit_artifacts.push(artifact_path);
        Ok(report)
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
            healthy: host.script_sensor_ready(),
        })
    }

    fn check_bpf_integrity(&self) -> Result<BpfStatus> {
        Ok(BpfStatus { healthy: false })
    }
}

impl PlatformRuntime for WindowsPlatform {
    fn descriptor(&self) -> PlatformDescriptor {
        let host = self.host_capabilities();
        PlatformDescriptor {
            target: PlatformTarget::Windows,
            kernel_transport: if host.driver_transport_ready() {
                KernelTransport::Driver
            } else {
                KernelTransport::CommandProbe
            },
            degrade_levels: 3,
            supports_registry: host.registry_provider_ready(),
            supports_amsi: host.script_sensor_ready(),
            supports_etw_integrity: host.driver_transport_ready(),
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

if (-not ("AegisProbe.AmsiBridge" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace AegisProbe {
    public static class AmsiBridge {
        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        public static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

        [DllImport("amsi.dll")]
        public static extern void AmsiUninitialize(IntPtr amsiContext);

        [DllImport("amsi.dll")]
        public static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr session);

        [DllImport("amsi.dll")]
        public static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr session);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        public static extern int AmsiScanBuffer(
            IntPtr amsiContext,
            byte[] buffer,
            uint length,
            string contentName,
            IntPtr session,
            out uint result);
    }
}
"@ | Out-Null
}

$hasAmsiScanInterface = $false
if ($hasAmsiRuntime) {
    $amsiContext = [IntPtr]::Zero
    $amsiSession = [IntPtr]::Zero
    try {
        $status = [AegisProbe.AmsiBridge]::AmsiInitialize('AegisProbe', [ref]$amsiContext)
        if ($status -eq 0 -and $amsiContext -ne [IntPtr]::Zero) {
            $null = [AegisProbe.AmsiBridge]::AmsiOpenSession($amsiContext, [ref]$amsiSession)
            $probeBytes = [System.Text.Encoding]::Unicode.GetBytes("Write-Output 'Aegis AMSI probe'")
            $probeResult = [uint32]0
            $status = [AegisProbe.AmsiBridge]::AmsiScanBuffer(
                $amsiContext,
                $probeBytes,
                [uint32]$probeBytes.Length,
                'AegisProbe.ps1',
                $amsiSession,
                [ref]$probeResult
            )
            $hasAmsiScanInterface = $status -eq 0
        }
    } catch {
        $hasAmsiScanInterface = $false
    } finally {
        if ($amsiSession -ne [IntPtr]::Zero -and $amsiContext -ne [IntPtr]::Zero) {
            [AegisProbe.AmsiBridge]::AmsiCloseSession($amsiContext, $amsiSession)
        }
        if ($amsiContext -ne [IntPtr]::Zero) {
            [AegisProbe.AmsiBridge]::AmsiUninitialize($amsiContext)
        }
    }
}

$hasMemoryInventory = $false
if ((Get-Command Get-Process -ErrorAction SilentlyContinue) -ne $null) {
    try {
        $null = Get-Process -ErrorAction Stop |
            Select-Object -First 1 |
            ForEach-Object {
                [void]$_.WorkingSet64
                [void]$_.PrivateMemorySize64
                [void]$_.VirtualMemorySize64
                [void]$_.PagedMemorySize64
            }
        $hasMemoryInventory = $true
    } catch {
        $hasMemoryInventory = $false
    }
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

if (-not ("AegisProbe.DriverBridge" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace AegisProbe {
    public static class DriverBridge {
        public static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeviceIoControl(
            IntPtr device,
            uint ioControlCode,
            byte[] inBuffer,
            uint inBufferSize,
            byte[] outBuffer,
            uint outBufferSize,
            out uint bytesReturned,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);
    }
}
"@ | Out-Null
}

$hasDriverService = $false
$hasDriverServiceRunning = $false
$hasDriverControlDevice = $false
$driverProtocolVersion = $null
$driverVersion = $null
$driverStatusDetail = $null

try {
    $driverService = Get-Service -Name 'AegisSensorKmod' -ErrorAction Stop
    $hasDriverService = $true
    $hasDriverServiceRunning = [string]$driverService.Status -eq 'Running'
    $driverStatusDetail = [string]$driverService.Status
} catch {
    $driverStatusDetail = $_.Exception.Message
}

if ($hasDriverServiceRunning) {
    $GENERIC_READ_WRITE = 0xC0000000
    $FILE_SHARE_READ_WRITE = 0x00000003
    $OPEN_EXISTING = 3
    $handle = [AegisProbe.DriverBridge]::CreateFile(
        '\\.\AegisSensor',
        [uint32]$GENERIC_READ_WRITE,
        [uint32]$FILE_SHARE_READ_WRITE,
        [IntPtr]::Zero,
        [uint32]$OPEN_EXISTING,
        0,
        [IntPtr]::Zero
    )

    if ($handle -eq [AegisProbe.DriverBridge]::InvalidHandleValue) {
        $driverStatusDetail = "CreateFile(\\.\AegisSensor) failed: Win32=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    } else {
        try {
            $buffer = New-Object byte[] 512
            $bytesReturned = [uint32]0
            $ok = [AegisProbe.DriverBridge]::DeviceIoControl(
                $handle,
                [uint32]0x00222000,
                $null,
                0,
                $buffer,
                [uint32]$buffer.Length,
                [ref]$bytesReturned,
                [IntPtr]::Zero
            )
            if (-not $ok) {
                throw "DeviceIoControl(0x00222000) failed: Win32=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            }
            if ($bytesReturned -lt 1) {
                throw "driver query returned empty payload"
            }

            $rawPayload = [System.Text.Encoding]::ASCII.GetString($buffer, 0, [int]$bytesReturned).Trim([char]0)
            if ([string]::IsNullOrWhiteSpace($rawPayload)) {
                throw "driver query returned blank payload"
            }

            $payload = $rawPayload | ConvertFrom-Json -ErrorAction Stop
            $hasDriverControlDevice = $true
            if ($payload.PSObject.Properties.Name -contains 'protocol_version') {
                $driverProtocolVersion = [uint32]$payload.protocol_version
            }
            if ($payload.PSObject.Properties.Name -contains 'driver_version') {
                $driverVersion = [string]$payload.driver_version
            }
            $driverStatusDetail = $rawPayload
        } catch {
            $driverStatusDetail = $_.Exception.Message
        } finally {
            [void][AegisProbe.DriverBridge]::CloseHandle($handle)
        }
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
    has_amsi_scan_interface = $hasAmsiScanInterface
    has_memory_inventory = $hasMemoryInventory
    has_named_pipe_inventory = $hasNamedPipeInventory
    has_module_inventory = $hasModuleInventory
    has_vss_inventory = $hasVssInventory
    has_device_inventory = $hasDeviceInventory
    has_driver_service = $hasDriverService
    has_driver_service_running = $hasDriverServiceRunning
    has_driver_control_device = $hasDriverControlDevice
    driver_protocol_version = $driverProtocolVersion
    driver_version = $driverVersion
    driver_status_detail = $driverStatusDetail
}

$data | ConvertTo-Json -Compress
"#;

    let probe: WindowsCapabilityProbe = run_powershell_json(runner, script)?;
    let mut host = WindowsHostCapabilities {
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
        has_amsi_scan_interface: probe.has_amsi_scan_interface,
        has_memory_inventory: probe.has_memory_inventory,
        has_named_pipe_inventory: probe.has_named_pipe_inventory,
        has_module_inventory: probe.has_module_inventory,
        has_vss_inventory: probe.has_vss_inventory,
        has_device_inventory: probe.has_device_inventory,
        has_driver_service: probe.has_driver_service,
        has_driver_service_running: probe.has_driver_service_running,
        has_driver_control_device: probe.has_driver_control_device,
        driver_protocol_version: probe.driver_protocol_version,
        driver_version: probe.driver_version,
        driver_status_detail: probe.driver_status_detail,
        has_file_monitor_port: probe.has_file_monitor_port,
        file_monitor_protocol_version: probe.file_monitor_protocol_version,
        file_monitor_queue_capacity: probe.file_monitor_queue_capacity,
        file_monitor_current_sequence: probe.file_monitor_current_sequence,
        file_monitor_status_detail: probe.file_monitor_status_detail,
        registry_callback_registered: probe.registry_callback_registered,
        registry_journal_capacity: probe.registry_journal_capacity,
        registry_current_sequence: probe.registry_current_sequence,
        registry_status_detail: probe.registry_status_detail,
        ob_callback_registered: false,
        protected_process_count: None,
        protected_file_path_count: None,
        ssdt_inspection_succeeded: false,
        ssdt_suspicious: false,
        callback_inspection_succeeded: false,
        callback_suspicious: false,
        kernel_code_inspection_succeeded: false,
        kernel_code_suspicious: false,
        code_integrity_options: None,
        driver_integrity_detail: None,
        last_error: None,
    };

    if host.driver_transport_ready() {
        refresh_windows_driver_surfaces(&mut host, runner)?;
    }

    Ok(host)
}

fn apply_windows_driver_integrity_status(
    host: &mut WindowsHostCapabilities,
    integrity: WindowsDriverIntegrityStatus,
) {
    host.ob_callback_registered = integrity.ob_callback_registered
        && integrity.protocol_version == AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION;
    host.protected_process_count = Some(integrity.protected_process_count);
    host.ssdt_inspection_succeeded = integrity.ssdt_inspection_succeeded;
    host.ssdt_suspicious = integrity.ssdt_suspicious;
    host.callback_inspection_succeeded = integrity.callback_inspection_succeeded;
    host.callback_suspicious = integrity.callback_suspicious;
    host.kernel_code_inspection_succeeded = integrity.kernel_code_inspection_succeeded;
    host.kernel_code_suspicious = integrity.kernel_code_suspicious;
    host.code_integrity_options = Some(integrity.code_integrity_options);
    host.driver_integrity_detail = Some(format!(
        "ob_registered={};protected_pids={};ssdt_ok={};ssdt_suspicious={};callbacks_ok={};callbacks_suspicious={};kernel_code_ok={};kernel_code_suspicious={};code_integrity=0x{:08x};kmci={};testsign={}",
        integrity.ob_callback_registered,
        integrity.protected_process_count,
        integrity.ssdt_inspection_succeeded,
        integrity.ssdt_suspicious,
        integrity.callback_inspection_succeeded,
        integrity.callback_suspicious,
        integrity.kernel_code_inspection_succeeded,
        integrity.kernel_code_suspicious,
        integrity.code_integrity_options,
        integrity.code_integrity_kmci_enabled,
        integrity.code_integrity_testsign
    ));
}

fn refresh_windows_driver_surfaces(
    host: &mut WindowsHostCapabilities,
    runner: &dyn WindowsCommandRunner,
) -> Result<()> {
    match query_windows_file_monitor_status(runner, AEGIS_WINDOWS_FILE_MONITOR_PORT_NAME) {
        Ok(status) => {
            host.has_file_monitor_port = true;
            host.file_monitor_protocol_version = Some(status.protocol_version);
            host.file_monitor_queue_capacity = Some(status.queue_capacity);
            host.file_monitor_current_sequence = Some(status.current_sequence);
            host.protected_file_path_count = Some(status.protected_path_count);
            host.file_monitor_status_detail = Some(format!(
                "port={};protocol=0x{:08x};queue_capacity={};current_sequence={};protected_paths={}",
                AEGIS_WINDOWS_FILE_MONITOR_PORT_NAME,
                status.protocol_version,
                status.queue_capacity,
                status.current_sequence,
                status.protected_path_count
            ));
        }
        Err(error) => {
            host.has_file_monitor_port = false;
            host.file_monitor_protocol_version = None;
            host.file_monitor_queue_capacity = None;
            host.file_monitor_current_sequence = None;
            host.protected_file_path_count = None;
            host.file_monitor_status_detail = Some(error.to_string());
        }
    }

    match query_windows_registry_monitor_status(runner, AEGIS_WINDOWS_DRIVER_SERVICE_NAME) {
        Ok(status) => {
            host.registry_callback_registered = status.registry_callback_registered
                && status.protocol_version == AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION;
            host.registry_journal_capacity = Some(status.journal_capacity);
            host.registry_current_sequence = Some(status.current_sequence);
            host.registry_status_detail = Some(format!(
                "service={};protocol=0x{:08x};journal_capacity={};current_sequence={};registered={}",
                AEGIS_WINDOWS_DRIVER_SERVICE_NAME,
                status.protocol_version,
                status.journal_capacity,
                status.current_sequence,
                status.registry_callback_registered
            ));
        }
        Err(error) => {
            host.registry_callback_registered = false;
            host.registry_journal_capacity = None;
            host.registry_current_sequence = None;
            host.registry_status_detail = Some(error.to_string());
        }
    }

    match query_windows_driver_integrity(runner, AEGIS_WINDOWS_DRIVER_SERVICE_NAME) {
        Ok(status) => {
            apply_windows_driver_integrity_status(host, status);
        }
        Err(error) => {
            host.ob_callback_registered = false;
            host.protected_process_count = None;
            host.ssdt_inspection_succeeded = false;
            host.ssdt_suspicious = false;
            host.callback_inspection_succeeded = false;
            host.callback_suspicious = false;
            host.kernel_code_inspection_succeeded = false;
            host.kernel_code_suspicious = false;
            host.code_integrity_options = None;
            host.driver_integrity_detail = Some(error.to_string());
        }
    }

    Ok(())
}

fn ensure_windows_driver_transport(host: &WindowsHostCapabilities, action: &str) -> Result<()> {
    if host.driver_transport_ready() {
        return Ok(());
    }

    bail!(
        "{action} requires kernel driver transport {service} at {device} with protocol 0x{protocol:08x}; {}",
        host.driver_transport_summary(),
        service = AEGIS_WINDOWS_DRIVER_SERVICE_NAME,
        device = AEGIS_WINDOWS_DRIVER_DEVICE_PATH,
        protocol = AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION,
    );
}

fn run_powershell_json<T: DeserializeOwned>(
    runner: &dyn WindowsCommandRunner,
    script: &str,
) -> Result<T> {
    let raw = runner.run_powershell(script)?;
    serde_json::from_str(raw.trim())
        .with_context(|| format!("parse powershell json output: {}", raw.trim()))
}

fn build_embedded_windows_script_invocation(script_body: &str, args: &[(&str, String)]) -> String {
    let mut script = format!(
        "$embedded = [scriptblock]::Create(@'\n{}\n'@)\n& $embedded",
        script_body.trim()
    );
    for (name, value) in args {
        script.push_str(&format!(" -{} '{}'", name, escape_windows_ps_string(value)));
    }
    script
}

fn run_embedded_powershell_json<T: DeserializeOwned>(
    runner: &dyn WindowsCommandRunner,
    script_body: &str,
    args: &[(&str, String)],
) -> Result<T> {
    let script = build_embedded_windows_script_invocation(script_body, args);
    run_powershell_json(runner, &script)
}

fn query_windows_script_events(
    runner: &dyn WindowsCommandRunner,
    after_record_id: u64,
    max_entries: u32,
) -> Result<Vec<WindowsRawScriptBlockEvent>> {
    run_embedded_powershell_json(
        runner,
        WINDOWS_QUERY_SCRIPT_EVENTS_SCRIPT,
        &[
            ("AfterRecordId", after_record_id.to_string()),
            ("MaxEntries", max_entries.to_string()),
        ],
    )
}

fn scan_windows_script_content(
    runner: &dyn WindowsCommandRunner,
    content_name: &str,
    script_content: &str,
) -> Result<WindowsAmsiScanResponse> {
    run_embedded_powershell_json(
        runner,
        WINDOWS_SCAN_SCRIPT_WITH_AMSI_SCRIPT,
        &[
            ("Mode", "scan".to_string()),
            ("ContentName", content_name.to_string()),
            (
                "ScriptContentBase64",
                STANDARD.encode(script_content.as_bytes()),
            ),
        ],
    )
}

fn query_windows_file_monitor_status(
    runner: &dyn WindowsCommandRunner,
    port_name: &str,
) -> Result<WindowsFileMonitorStatus> {
    run_embedded_powershell_json(
        runner,
        WINDOWS_QUERY_FILE_EVENTS_SCRIPT,
        &[
            ("Mode", "status".to_string()),
            ("PortName", port_name.to_string()),
        ],
    )
}

fn query_windows_file_monitor_events(
    runner: &dyn WindowsCommandRunner,
    port_name: &str,
    last_sequence: u32,
    max_entries: u32,
) -> Result<WindowsFileMonitorQuery> {
    run_embedded_powershell_json(
        runner,
        WINDOWS_QUERY_FILE_EVENTS_SCRIPT,
        &[
            ("Mode", "events".to_string()),
            ("PortName", port_name.to_string()),
            ("LastSequence", last_sequence.to_string()),
            ("MaxEntries", max_entries.to_string()),
        ],
    )
}

fn query_windows_registry_monitor_status(
    runner: &dyn WindowsCommandRunner,
    service_name: &str,
) -> Result<WindowsRegistryMonitorStatus> {
    run_embedded_powershell_json(
        runner,
        WINDOWS_QUERY_REGISTRY_EVENTS_SCRIPT,
        &[
            ("Mode", "status".to_string()),
            ("ServiceName", service_name.to_string()),
        ],
    )
}

fn query_windows_registry_monitor_events(
    runner: &dyn WindowsCommandRunner,
    service_name: &str,
    last_sequence: u32,
    max_entries: u32,
) -> Result<WindowsRegistryMonitorQuery> {
    run_embedded_powershell_json(
        runner,
        WINDOWS_QUERY_REGISTRY_EVENTS_SCRIPT,
        &[
            ("Mode", "events".to_string()),
            ("ServiceName", service_name.to_string()),
            ("LastSequence", last_sequence.to_string()),
            ("MaxEntries", max_entries.to_string()),
        ],
    )
}

fn rollback_windows_registry_key(
    runner: &dyn WindowsCommandRunner,
    key_path: &str,
    service_name: &str,
) -> Result<WindowsRegistryRollbackResponse> {
    run_embedded_powershell_json(
        runner,
        WINDOWS_ROLLBACK_REGISTRY_SCRIPT,
        &[
            ("KeyPath", key_path.to_string()),
            ("ServiceName", service_name.to_string()),
        ],
    )
}

fn protect_windows_process(
    runner: &dyn WindowsCommandRunner,
    process_id: u32,
    service_name: &str,
) -> Result<WindowsProcessProtectionResponse> {
    run_embedded_powershell_json(
        runner,
        WINDOWS_PROTECT_PROCESS_SCRIPT,
        &[
            ("ProcessId", process_id.to_string()),
            ("ServiceName", service_name.to_string()),
        ],
    )
}

fn query_windows_driver_integrity(
    runner: &dyn WindowsCommandRunner,
    service_name: &str,
) -> Result<WindowsDriverIntegrityStatus> {
    run_embedded_powershell_json(
        runner,
        WINDOWS_QUERY_DRIVER_INTEGRITY_SCRIPT,
        &[("ServiceName", service_name.to_string())],
    )
}

fn clear_windows_file_protection(
    runner: &dyn WindowsCommandRunner,
    port_name: &str,
) -> Result<WindowsFileProtectionResponse> {
    run_embedded_powershell_json(
        runner,
        WINDOWS_CONFIGURE_FILE_PROTECTION_SCRIPT,
        &[
            ("Mode", "clear".to_string()),
            ("PortName", port_name.to_string()),
        ],
    )
}

fn protect_windows_file_path(
    runner: &dyn WindowsCommandRunner,
    port_name: &str,
    path: &Path,
) -> Result<WindowsFileProtectionResponse> {
    run_embedded_powershell_json(
        runner,
        WINDOWS_CONFIGURE_FILE_PROTECTION_SCRIPT,
        &[
            ("Mode", "protect".to_string()),
            ("PortName", port_name.to_string()),
            ("Path", path.display().to_string()),
        ],
    )
}

fn resolve_windows_registry_key_path(
    runner: &dyn WindowsCommandRunner,
    selector: &str,
) -> Result<String> {
    #[derive(Deserialize)]
    struct ResolvedKeyPath {
        key_path: String,
    }

    let script = format!(
        r#"
function Resolve-AegisRegistryKeyPath {{
    param([Parameter(Mandatory = $true)][string]$Selector)

    $normalized = ($Selector -replace '/', '\').Trim()
    if ([string]::IsNullOrWhiteSpace($normalized)) {{
        throw "registry selector is empty"
    }}
    if ($normalized.ToUpperInvariant().StartsWith('\REGISTRY\')) {{
        return $normalized
    }}

    $patterns = @(
        [ordered]@{{ Prefix = 'HKLM:\'; KernelRoot = '\REGISTRY\MACHINE' }},
        [ordered]@{{ Prefix = 'HKLM\'; KernelRoot = '\REGISTRY\MACHINE' }},
        [ordered]@{{ Prefix = 'HKEY_LOCAL_MACHINE:\'; KernelRoot = '\REGISTRY\MACHINE' }},
        [ordered]@{{ Prefix = 'HKEY_LOCAL_MACHINE\'; KernelRoot = '\REGISTRY\MACHINE' }},
        [ordered]@{{ Prefix = 'HKCU:\'; KernelRoot = '\REGISTRY\USER\' + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value }},
        [ordered]@{{ Prefix = 'HKCU\'; KernelRoot = '\REGISTRY\USER\' + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value }},
        [ordered]@{{ Prefix = 'HKEY_CURRENT_USER:\'; KernelRoot = '\REGISTRY\USER\' + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value }},
        [ordered]@{{ Prefix = 'HKEY_CURRENT_USER\'; KernelRoot = '\REGISTRY\USER\' + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value }}
    )

    foreach ($pattern in $patterns) {{
        if ($normalized.StartsWith($pattern.Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {{
            $suffix = $normalized.Substring($pattern.Prefix.Length).TrimStart('\')
            if ([string]::IsNullOrWhiteSpace($suffix)) {{
                return $pattern.KernelRoot
            }}
            return $pattern.KernelRoot + '\' + $suffix
        }}
    }}

    throw "unsupported windows registry selector: $Selector"
}}

[ordered]@{{
    key_path = Resolve-AegisRegistryKeyPath -Selector '{}'
}} | ConvertTo-Json -Compress
"#,
        escape_windows_ps_string(selector)
    );

    let resolved: ResolvedKeyPath = run_powershell_json(runner, &script)?;
    Ok(resolved.key_path)
}

fn file_monitor_event_subject(event: &WindowsFileMonitorEvent) -> String {
    truncate_subject(&format!(
        "sequence={};pid={};operation={};path={}",
        event.sequence, event.process_id, event.operation, event.path
    ))
}

fn registry_monitor_event_subject(event: &WindowsRegistryMonitorEvent) -> String {
    truncate_subject(&format!(
        "sequence={};operation={};key={};value={};old={};new={}",
        event.sequence,
        event.operation,
        event.key_path,
        if event.value_name.is_empty() {
            "-"
        } else {
            &event.value_name
        },
        event.old_value.as_deref().unwrap_or("-"),
        event.new_value.as_deref().unwrap_or("-")
    ))
}

fn collect_file_monitor_events(
    state: &mut WindowsState,
    runner: &dyn WindowsCommandRunner,
) -> Result<()> {
    let last_sequence = state.file_monitor_cursor.unwrap_or(0);
    let response = query_windows_file_monitor_events(
        runner,
        AEGIS_WINDOWS_FILE_MONITOR_PORT_NAME,
        last_sequence,
        256,
    )?;
    if response.protocol_version != AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION {
        bail!(
            "file monitor protocol mismatch: expected 0x{expected:08x}, got 0x{actual:08x}",
            expected = AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION,
            actual = response.protocol_version
        );
    }

    state.host.has_file_monitor_port = true;
    state.host.file_monitor_protocol_version = Some(response.protocol_version);
    state.host.file_monitor_queue_capacity = Some(response.queue_capacity);
    state.host.file_monitor_current_sequence = Some(response.current_sequence);
    state.host.protected_file_path_count = Some(response.protected_path_count);
    state.host.file_monitor_status_detail = Some(format!(
        "port={};current_sequence={};returned_count={};overflowed={};protected_paths={}",
        AEGIS_WINDOWS_FILE_MONITOR_PORT_NAME,
        response.current_sequence,
        response.returned_count,
        response.overflowed,
        response.protected_path_count
    ));
    state.file_monitor_cursor = Some(response.current_sequence);

    for event in response.events {
        state.pending_events.push_back(
            WindowsEventStub {
                provider: WindowsProviderKind::MinifilterFile,
                operation: format!("file-{}", event.operation),
                subject: file_monitor_event_subject(&event),
            }
            .encode(),
        );
    }
    Ok(())
}

fn collect_registry_monitor_events(
    state: &mut WindowsState,
    runner: &dyn WindowsCommandRunner,
) -> Result<()> {
    let last_sequence = state.registry_monitor_cursor.unwrap_or(0);
    let response = query_windows_registry_monitor_events(
        runner,
        AEGIS_WINDOWS_DRIVER_SERVICE_NAME,
        last_sequence,
        256,
    )?;
    if response.protocol_version != AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION {
        bail!(
            "registry callback protocol mismatch: expected 0x{expected:08x}, got 0x{actual:08x}",
            expected = AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION,
            actual = response.protocol_version
        );
    }

    state.host.registry_callback_registered = true;
    state.host.registry_current_sequence = Some(response.current_sequence);
    state.host.registry_status_detail = Some(format!(
        "service={};current_sequence={};returned_count={};overflowed={}",
        AEGIS_WINDOWS_DRIVER_SERVICE_NAME,
        response.current_sequence,
        response.returned_count,
        response.overflowed
    ));
    state.registry_monitor_cursor = Some(response.current_sequence);

    for event in response.events {
        state.pending_events.push_back(
            WindowsEventStub {
                provider: WindowsProviderKind::RegistryCallback,
                operation: format!("registry-{}", event.operation),
                subject: registry_monitor_event_subject(&event),
            }
            .encode(),
        );
    }
    Ok(())
}

fn collect_live_windows_events(
    state: &mut WindowsState,
    runner: &dyn WindowsCommandRunner,
) -> Result<()> {
    if state.host.file_monitor_ready() {
        collect_file_monitor_events(state, runner)?;
    }
    if state.host.registry_provider_ready() {
        collect_registry_monitor_events(state, runner)?;
    }
    if state.host.has_process_inventory {
        collect_process_delta_events(state, runner)?;
    }
    if state.host.has_process_creation_events {
        collect_security_process_audit_events(state, runner)?;
    }
    if state.host.script_sensor_ready() {
        collect_script_block_events(state, runner)?;
    }
    if state.host.memory_sensor_ready() {
        collect_memory_events(state, runner)?;
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

fn latest_script_block_record_id(runner: &dyn WindowsCommandRunner) -> Result<Option<u64>> {
    let script = r#"
$event = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104 } -MaxEvents 1 -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $event) {
    'null'
} else {
    [ordered]@{
        record_id = [uint64]$event.RecordId
    } | ConvertTo-Json -Compress
}
"#;
    let cursor: Option<WindowsScriptBlockCursor> = run_powershell_json(runner, script)?;
    Ok(cursor.map(|value| value.record_id))
}

fn collect_script_block_events(
    state: &mut WindowsState,
    runner: &dyn WindowsCommandRunner,
) -> Result<()> {
    let Some(after_record_id) = state.script_block_cursor else {
        state.script_block_cursor = latest_script_block_record_id(runner)?;
        return Ok(());
    };

    let events = query_windows_script_events(runner, after_record_id, 64)?;
    if let Some(last) = events.last() {
        state.script_block_cursor = Some(last.record_id);
    }

    for raw in events {
        let Some(script_event) =
            assemble_windows_script_block_event(&mut state.pending_script_blocks, raw)
        else {
            continue;
        };

        let content_name = script_event
            .script_block_id
            .clone()
            .unwrap_or_else(|| format!("ScriptBlock-{}", script_event.record_id));
        let scan = scan_windows_script_content(runner, &content_name, &script_event.script_text)?;
        let assessment = WindowsScriptAssessment::from_script(&script_event.script_text, &scan);
        let tokens = if assessment.suspicious_tokens.is_empty() {
            "-".to_string()
        } else {
            assessment.suspicious_tokens.join(",")
        };
        let subject = truncate_subject(&format!(
            "record_id={};pid={};script_block_id={};decision={};risk={};amsi_result=0x{:04x};layers={};tokens={};sha256={};path={};preview={}",
            script_event.record_id,
            script_event
                .process_id
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            script_event
                .script_block_id
                .as_deref()
                .unwrap_or("-"),
            assessment.operation,
            assessment.risk_score,
            scan.amsi_result,
            assessment.decode_layer_count,
            tokens,
            assessment.script_sha256,
            script_event.path.as_deref().unwrap_or("-"),
            assessment.preview
        ));
        state.pending_events.push_back(
            WindowsEventStub {
                provider: WindowsProviderKind::AmsiScript,
                operation: assessment.operation,
                subject,
            }
            .encode(),
        );
    }

    Ok(())
}

fn assemble_windows_script_block_event(
    pending: &mut BTreeMap<String, WindowsScriptBlockAssembly>,
    raw: WindowsRawScriptBlockEvent,
) -> Option<WindowsScriptBlockEvent> {
    let total = raw.message_total.unwrap_or(1).max(1);
    let part = raw.message_number.unwrap_or(1).max(1);
    let block_id = raw.script_block_id.clone();

    if total == 1 || block_id.is_none() {
        return Some(WindowsScriptBlockEvent {
            record_id: raw.record_id,
            process_id: raw.process_id,
            script_block_id: raw.script_block_id,
            path: raw.path,
            script_text: raw.script_text,
        });
    }

    let block_id = block_id.expect("checked above");
    let entry = pending.entry(block_id.clone()).or_default();
    entry.message_total = total;
    if entry.process_id.is_none() {
        entry.process_id = raw.process_id;
    }
    if entry.path.is_none() {
        entry.path = raw.path.clone();
    }
    entry.fragments.insert(part, raw.script_text);

    if entry.fragments.len() as u32 != entry.message_total {
        return None;
    }

    let mut script_text = String::new();
    for index in 1..=entry.message_total {
        let fragment = entry.fragments.get(&index)?;
        script_text.push_str(fragment);
    }
    let assembled = pending.remove(&block_id)?;
    Some(WindowsScriptBlockEvent {
        record_id: raw.record_id,
        process_id: assembled.process_id,
        script_block_id: Some(block_id),
        path: assembled.path,
        script_text,
    })
}

fn collect_memory_events(
    state: &mut WindowsState,
    runner: &dyn WindowsCommandRunner,
) -> Result<()> {
    const MIN_PRIVATE_BYTES: u64 = 32 * 1024 * 1024;
    const MIN_PRIVATE_DELTA_BYTES: u64 = 16 * 1024 * 1024;
    const HOT_PRIVATE_BYTES: u64 = 64 * 1024 * 1024;

    let current = snapshot_memory_inventory(runner)?;
    for (pid, sample) in &current {
        match state.known_memory_processes.get(pid) {
            Some(previous) => {
                let private_delta = sample
                    .private_memory_bytes
                    .saturating_sub(previous.private_memory_bytes);
                let working_delta = sample
                    .working_set_bytes
                    .saturating_sub(previous.working_set_bytes);
                let grew_enough = if previous.private_memory_bytes == 0 {
                    sample.private_memory_bytes >= HOT_PRIVATE_BYTES
                } else {
                    sample.private_memory_bytes.saturating_mul(100)
                        >= previous.private_memory_bytes.saturating_mul(125)
                };
                if sample.private_memory_bytes >= MIN_PRIVATE_BYTES
                    && private_delta >= MIN_PRIVATE_DELTA_BYTES
                    && grew_enough
                {
                    state.pending_events.push_back(
                        WindowsEventStub {
                            provider: WindowsProviderKind::MemorySensor,
                            operation: "memory-growth".to_string(),
                            subject: truncate_subject(&format!(
                                "pid={};name={};private_memory_bytes={};private_delta_bytes={};working_set_bytes={};working_delta_bytes={};path={}",
                                sample.process_id,
                                sample.process_name,
                                sample.private_memory_bytes,
                                private_delta,
                                sample.working_set_bytes,
                                working_delta,
                                sample.path.as_deref().unwrap_or("-")
                            )),
                        }
                        .encode(),
                    );
                }
            }
            None => {
                if sample.private_memory_bytes >= HOT_PRIVATE_BYTES {
                    state.pending_events.push_back(
                        WindowsEventStub {
                            provider: WindowsProviderKind::MemorySensor,
                            operation: "memory-hot".to_string(),
                            subject: truncate_subject(&format!(
                                "pid={};name={};private_memory_bytes={};working_set_bytes={};path={}",
                                sample.process_id,
                                sample.process_name,
                                sample.private_memory_bytes,
                                sample.working_set_bytes,
                                sample.path.as_deref().unwrap_or("-")
                            )),
                        }
                        .encode(),
                    );
                }
            }
        }
    }

    state.known_memory_processes = current;
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

fn snapshot_memory_inventory(
    runner: &dyn WindowsCommandRunner,
) -> Result<BTreeMap<u32, WindowsMemorySnapshot>> {
    let rows: Vec<WindowsMemorySnapshot> =
        run_embedded_powershell_json(runner, WINDOWS_QUERY_MEMORY_SNAPSHOT_SCRIPT, &[])?;
    Ok(rows
        .into_iter()
        .map(|sample| (sample.process_id, sample))
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
        protected_pids: state.execution.protected_pids.clone(),
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

fn record_windows_protection_surface_artifact(state: &mut WindowsState) -> Result<()> {
    let artifact_path = write_windows_protection_surface_artifact(state)?;
    if !state.execution.audit_artifacts.contains(&artifact_path) {
        state.execution.audit_artifacts.push(artifact_path);
    }
    Ok(())
}

fn write_windows_registry_rollback_artifact(
    state: &mut WindowsState,
    target: &RollbackTarget,
    resolved_key_path: &str,
    rollback: &WindowsRegistryRollbackResponse,
) -> Result<PathBuf> {
    let artifact = WindowsRegistryRollbackArtifact {
        selector: target.selector.clone(),
        resolved_key_path: resolved_key_path.to_string(),
        applied_count: rollback.applied_count,
        current_sequence: rollback.current_sequence,
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

fn write_windows_block_artifact(
    state: &mut WindowsState,
    kind: &str,
    target: String,
    ttl: Duration,
    enforced: bool,
    enforcement_plane: &str,
    firewall_rule_group: Option<String>,
) -> Result<PathBuf> {
    let artifact = WindowsBlockAuditArtifact {
        kind: kind.to_string(),
        target,
        ttl_secs: ttl.as_secs(),
        enforced,
        enforcement_plane: enforcement_plane.to_string(),
        firewall_rule_group,
    };
    let path = state
        .base_dir
        .join("blocks")
        .join(format!("block-{}.json", Uuid::now_v7().simple()));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(&artifact)?;
    fs::write(&path, json)?;
    Ok(path)
}

fn write_windows_block_clear_artifact(
    state: &mut WindowsState,
    cleared_block_count: usize,
    cleared_rule_groups: Vec<String>,
) -> Result<PathBuf> {
    let artifact = WindowsBlockClearArtifact {
        cleared_block_count,
        cleared_rule_groups,
    };
    let path = state
        .base_dir
        .join("blocks")
        .join(format!("clear-{}.json", Uuid::now_v7().simple()));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(&artifact)?;
    fs::write(&path, json)?;
    Ok(path)
}

fn write_windows_integrity_artifact(state: &mut WindowsState) -> Result<PathBuf> {
    let artifact = WindowsIntegrityAuditArtifact {
        verify_integrity: protection_report(&state.host),
        ssdt: ssdt_report(&state.host),
        callback_tables: callback_report(&state.host),
        kernel_code: kernel_code_report(&state.host),
        etw_ingest: etw_report(&state.host),
        amsi_script: amsi_report(&state.host),
        memory_sensor: memory_report(&state.host),
    };
    let path = state
        .base_dir
        .join("integrity")
        .join(format!("integrity-{}.json", Uuid::now_v7().simple()));
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

fn apply_windows_firewall_block(
    state: &mut WindowsState,
    runner: &dyn WindowsCommandRunner,
    target: &str,
) -> Result<WindowsFirewallBlockReceipt> {
    let rule_group = format!("AegisBlock-{}", Uuid::now_v7().simple());
    let script = build_windows_network_block_script(&rule_group, target);
    write_windows_response_script(
        &mut *state,
        &format!("block-network-{rule_group}.ps1"),
        &script,
    )?;
    run_powershell_json(runner, &script)
}

fn clear_windows_firewall_blocks(
    state: &mut WindowsState,
    runner: &dyn WindowsCommandRunner,
    rule_groups: &[String],
) -> Result<()> {
    let script = build_windows_clear_block_script(rule_groups);
    write_windows_response_script(
        &mut *state,
        &format!("block-clear-{}.ps1", Uuid::now_v7().simple()),
        &script,
    )?;
    runner.run_powershell(&script)?;
    Ok(())
}

fn build_windows_network_block_script(rule_group: &str, target: &str) -> String {
    [
        format!("$ruleGroup = '{}'", escape_windows_ps_string(rule_group)),
        format!("$remoteAddress = '{}'", escape_windows_ps_string(target)),
        "Get-NetFirewallRule -Group $ruleGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null".to_string(),
        "New-NetFirewallRule -DisplayName ($ruleGroup + '-OutboundBlock') -Group $ruleGroup -Direction Outbound -Action Block -RemoteAddress $remoteAddress | Out-Null".to_string(),
        "[ordered]@{".to_string(),
        "    rule_group = $ruleGroup".to_string(),
        "} | ConvertTo-Json -Compress".to_string(),
    ]
    .join("\n")
}

fn build_windows_clear_block_script(rule_groups: &[String]) -> String {
    let groups = if rule_groups.is_empty() {
        "@()".to_string()
    } else {
        format!(
            "@({})",
            rule_groups
                .iter()
                .map(|group| format!("'{}'", escape_windows_ps_string(group)))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    [
        format!("$ruleGroups = {groups}"),
        "foreach ($ruleGroup in $ruleGroups) {".to_string(),
        "    Get-NetFirewallRule -Group $ruleGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null".to_string(),
        "}".to_string(),
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

fn ssdt_report(host: &WindowsHostCapabilities) -> IntegrityReport {
    if !host.reachable {
        return kernel_report(false, host.summary());
    }
    if !host.driver_transport_ready() {
        return kernel_report(
            false,
            format!(
                "ssdt inspection requires kernel driver transport; {}",
                host.summary()
            ),
        );
    }
    if !host.ssdt_inspection_succeeded {
        return kernel_report(
            false,
            format!(
                "driver could not complete syscall surface inspection; {}",
                host.summary()
            ),
        );
    }

    kernel_report(
        !host.ssdt_suspicious,
        format!(
            "ssdt_inspection_succeeded={};ssdt_suspicious={};{}",
            host.ssdt_inspection_succeeded,
            host.ssdt_suspicious,
            host.summary()
        ),
    )
}

fn callback_report(host: &WindowsHostCapabilities) -> IntegrityReport {
    if !host.reachable {
        return kernel_report(false, host.summary());
    }
    if !host.driver_transport_ready() {
        return kernel_report(
            false,
            format!(
                "callback inspection requires kernel driver transport; {}",
                host.summary()
            ),
        );
    }
    if !host.callback_inspection_succeeded {
        return kernel_report(
            false,
            format!(
                "driver could not complete callback inspection; {}",
                host.summary()
            ),
        );
    }

    kernel_report(
        !host.callback_suspicious,
        format!(
            "callback_inspection_succeeded={};callback_suspicious={};ob_callback_registered={};registry_callback_registered={};{}",
            host.callback_inspection_succeeded,
            host.callback_suspicious,
            host.ob_callback_registered,
            host.registry_callback_registered,
            host.summary()
        ),
    )
}

fn kernel_code_report(host: &WindowsHostCapabilities) -> IntegrityReport {
    if !host.reachable {
        return kernel_report(false, host.summary());
    }
    if !host.driver_transport_ready() {
        return kernel_report(
            false,
            format!(
                "kernel code inspection requires kernel driver transport; {}",
                host.summary()
            ),
        );
    }
    if !host.kernel_code_inspection_succeeded {
        return kernel_report(
            false,
            format!(
                "driver could not query system code integrity state; {}",
                host.summary()
            ),
        );
    }

    kernel_report(
        !host.kernel_code_suspicious,
        format!(
            "kernel_code_inspection_succeeded={};kernel_code_suspicious={};code_integrity_options={};{}",
            host.kernel_code_inspection_succeeded,
            host.kernel_code_suspicious,
            host.code_integrity_options
                .map(|value| format!("0x{value:08x}"))
                .unwrap_or_else(|| "none".to_string()),
            host.summary()
        ),
    )
}

fn protection_report(host: &WindowsHostCapabilities) -> IntegrityReport {
    let passed = host.process_protection_ready() && host.file_monitor_ready();
    let details = if !host.reachable {
        host.summary()
    } else if !host.driver_transport_ready() {
        format!(
            "windows protection plane is running without driver transport; {}",
            host.summary()
        )
    } else {
        format!(
            "process_protection_ready={};file_protection_ready={};protected_pids={};protected_paths={};{}",
            host.process_protection_ready(),
            host.file_monitor_ready(),
            host.protected_process_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            host.protected_file_path_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            host.summary()
        )
    };
    IntegrityReport { passed, details }
}

fn driver_transport_report(host: &WindowsHostCapabilities) -> IntegrityReport {
    let passed = host.driver_transport_ready();
    let details = if !host.reachable {
        host.summary()
    } else {
        format!(
            "expected_service={};expected_device={};expected_ioctl=0x{:08x};expected_protocol=0x{:08x};{}",
            AEGIS_WINDOWS_DRIVER_SERVICE_NAME,
            AEGIS_WINDOWS_DRIVER_DEVICE_PATH,
            AEGIS_WINDOWS_DRIVER_IOCTL_QUERY_VERSION,
            AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION,
            host.driver_transport_summary()
        )
    };
    IntegrityReport { passed, details }
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
    let passed = host.script_sensor_ready();
    let details = if !host.reachable {
        host.summary()
    } else {
        format!(
            "amsi_runtime={};script_block_logging={};powershell_operational_log={};amsi_scan_interface={}",
            host.has_amsi_runtime,
            host.has_script_block_logging,
            host.has_powershell_log,
            host.has_amsi_scan_interface
        )
    };
    IntegrityReport { passed, details }
}

fn memory_report(host: &WindowsHostCapabilities) -> IntegrityReport {
    let passed = host.memory_sensor_ready();
    let details = if !host.reachable {
        host.summary()
    } else {
        format!(
            "process_inventory={};memory_inventory={}",
            host.has_process_inventory, host.has_memory_inventory
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
        WindowsProviderKind, AEGIS_WINDOWS_DRIVER_DEVICE_PATH,
        AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION, AEGIS_WINDOWS_DRIVER_SERVICE_NAME,
    };
    use crate::{
        KernelIntegrity, KernelTransport, PlatformProtection, PlatformResponse, PlatformRuntime,
        PlatformSensor, PreemptiveBlock,
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
            has_amsi_scan_interface: false,
            has_memory_inventory: false,
            has_named_pipe_inventory: false,
            has_module_inventory: false,
            has_vss_inventory: false,
            has_device_inventory: false,
            has_driver_service: false,
            has_driver_service_running: false,
            has_driver_control_device: false,
            driver_protocol_version: None,
            driver_version: None,
            driver_status_detail: None,
            has_file_monitor_port: false,
            file_monitor_protocol_version: None,
            file_monitor_queue_capacity: None,
            file_monitor_current_sequence: None,
            file_monitor_status_detail: None,
            registry_callback_registered: false,
            registry_journal_capacity: None,
            registry_current_sequence: None,
            registry_status_detail: None,
            ob_callback_registered: false,
            protected_process_count: None,
            protected_file_path_count: None,
            ssdt_inspection_succeeded: false,
            ssdt_suspicious: false,
            callback_inspection_succeeded: false,
            callback_suspicious: false,
            kernel_code_inspection_succeeded: false,
            kernel_code_suspicious: false,
            code_integrity_options: None,
            driver_integrity_detail: None,
            last_error: None,
        }
    }

    fn healthy_host_with_driver() -> WindowsHostCapabilities {
        let mut host = healthy_host();
        host.has_driver_service = true;
        host.has_driver_service_running = true;
        host.has_driver_control_device = true;
        host.driver_protocol_version = Some(AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION);
        host.driver_version = Some("1.0.0-test".to_string());
        host.driver_status_detail =
            Some(r#"{"protocol_version":65536,"driver_version":"1.0.0-test"}"#.to_string());
        host
    }

    fn healthy_host_with_driver_surfaces() -> WindowsHostCapabilities {
        let mut host = healthy_host_with_driver();
        host.has_file_monitor_port = true;
        host.file_monitor_protocol_version = Some(AEGIS_WINDOWS_DRIVER_PROTOCOL_VERSION);
        host.file_monitor_queue_capacity = Some(256);
        host.file_monitor_current_sequence = Some(1200);
        host.protected_file_path_count = Some(1);
        host.file_monitor_status_detail = Some(
            "port=\\AegisFileMonitorPort;protocol=0x00010000;queue_capacity=256;current_sequence=1200;protected_paths=1"
                .to_string(),
        );
        host.registry_callback_registered = true;
        host.registry_journal_capacity = Some(256);
        host.registry_current_sequence = Some(640);
        host.registry_status_detail = Some(
            "service=AegisSensorKmod;protocol=0x00010000;journal_capacity=256;current_sequence=640;registered=True"
                .to_string(),
        );
        host.ob_callback_registered = true;
        host.protected_process_count = Some(1);
        host.ssdt_inspection_succeeded = true;
        host.ssdt_suspicious = false;
        host.callback_inspection_succeeded = true;
        host.callback_suspicious = false;
        host.kernel_code_inspection_succeeded = true;
        host.kernel_code_suspicious = false;
        host.code_integrity_options = Some(0x00000401);
        host.driver_integrity_detail = Some(
            "ob_registered=true;protected_pids=1;ssdt_ok=true;ssdt_suspicious=false;callbacks_ok=true;callbacks_suspicious=false;kernel_code_ok=true;kernel_code_suspicious=false;code_integrity=0x00000401;kmci=true;testsign=false"
                .to_string(),
        );
        host
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
                r#""has_amsi_scan_interface":false,"has_memory_inventory":false,"#,
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

    fn probe_output_with_script_memory_surface(
        has_amsi_runtime: bool,
        has_script_block_logging: bool,
        has_amsi_scan_interface: bool,
        has_memory_inventory: bool,
    ) -> String {
        format!(
            concat!(
                r#"{{"computer_name":"DESKTOP-TLASHJG","user_name":"desktop-tlashjg\\lamba","is_admin":true,"#,
                r#""has_process_inventory":true,"has_security_log":true,"has_powershell_log":true,"#,
                r#""has_wmi_log":true,"has_task_scheduler_log":true,"has_sysmon_log":false,"#,
                r#""has_process_creation_events":true,"has_net_connection":true,"has_firewall":true,"#,
                r#""has_registry_cli":true,"has_amsi_runtime":{},"has_script_block_logging":{},"#,
                r#""has_amsi_scan_interface":{},"has_memory_inventory":{},"#,
                r#""has_named_pipe_inventory":false,"has_module_inventory":false,"has_vss_inventory":false,"#,
                r#""has_device_inventory":false}}"#
            ),
            has_amsi_runtime,
            has_script_block_logging,
            has_amsi_scan_interface,
            has_memory_inventory
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

    fn script_block_events_output(
        entries: &[(
            u64,
            Option<u32>,
            Option<&str>,
            Option<u32>,
            Option<u32>,
            Option<&str>,
            &str,
        )],
    ) -> String {
        let rows = entries
            .iter()
            .map(
                |(
                    record_id,
                    process_id,
                    script_block_id,
                    message_number,
                    message_total,
                    path,
                    script_text,
                )| {
                    let process_id = process_id
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "null".to_string());
                    let script_block_id = script_block_id
                        .map(|value| format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
                        .unwrap_or_else(|| "null".to_string());
                    let message_number = message_number
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "null".to_string());
                    let message_total = message_total
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "null".to_string());
                    let path = path
                        .map(|value| format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
                        .unwrap_or_else(|| "null".to_string());
                    format!(
                        "{{\"record_id\":{record_id},\"process_id\":{process_id},\"script_block_id\":{script_block_id},\"message_number\":{message_number},\"message_total\":{message_total},\"path\":{path},\"script_text\":\"{}\"}}",
                        script_text.replace('\\', "\\\\").replace('"', "\\\"")
                    )
                },
            )
            .collect::<Vec<_>>();
        format!("[{}]", rows.join(","))
    }

    fn amsi_scan_output(result: u32, blocked_by_admin: bool, malware: bool) -> String {
        format!(
            r#"{{"content_name":"ScriptBlock-1","app_name":"AegisSensor","amsi_result":{result},"blocked_by_admin":{blocked_by_admin},"malware":{malware},"should_block":{},"session_opened":true,"scan_interface_ready":true}}"#,
            blocked_by_admin || malware
        )
    }

    fn memory_output(entries: &[(u32, &str, u64, u64, u64, u64, Option<&str>)]) -> String {
        let rows = entries
            .iter()
            .map(
                |(
                    process_id,
                    process_name,
                    working_set_bytes,
                    private_memory_bytes,
                    virtual_memory_bytes,
                    paged_memory_bytes,
                    path,
                )| {
                    let path = path
                        .map(|value| format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
                        .unwrap_or_else(|| "null".to_string());
                    format!(
                        "{{\"process_id\":{process_id},\"process_name\":\"{}\",\"working_set_bytes\":{working_set_bytes},\"private_memory_bytes\":{private_memory_bytes},\"virtual_memory_bytes\":{virtual_memory_bytes},\"paged_memory_bytes\":{paged_memory_bytes},\"path\":{path}}}",
                        process_name.replace('\\', "\\\\").replace('"', "\\\"")
                    )
                },
            )
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

    fn firewall_block_output(rule_group: &str) -> String {
        format!(
            r#"{{"rule_group":"{}"}}"#,
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

    fn file_status_output(
        current_sequence: u32,
        queue_capacity: u32,
        protected_path_count: u32,
    ) -> String {
        format!(
            r#"{{"port_name":"\\AegisFileMonitorPort","protocol_version":65536,"queue_capacity":{queue_capacity},"current_sequence":{current_sequence},"protected_path_count":{protected_path_count}}}"#
        )
    }

    fn file_events_output(
        current_sequence: u32,
        queue_capacity: u32,
        events: &[(u32, i64, u32, &str, &str)],
    ) -> String {
        let rows = events
            .iter()
            .map(|(sequence, timestamp, process_id, operation, path)| {
                format!(
                    "{{\"sequence\":{sequence},\"timestamp\":{timestamp},\"process_id\":{process_id},\"operation\":\"{}\",\"path\":\"{}\"}}",
                    operation.replace('\\', "\\\\").replace('"', "\\\""),
                    path.replace('\\', "\\\\").replace('"', "\\\"")
                )
            })
            .collect::<Vec<_>>();
        format!(
            r#"{{"port_name":"\\AegisFileMonitorPort","protocol_version":65536,"queue_capacity":{queue_capacity},"oldest_sequence":0,"current_sequence":{current_sequence},"returned_count":{},"overflowed":false,"protected_path_count":1,"events":[{}]}}"#,
            events.len(),
            rows.join(",")
        )
    }

    fn file_protection_output(protected_path_count: u32, resolved_path: Option<&str>) -> String {
        let resolved_path = resolved_path
            .map(|value| format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
            .unwrap_or_else(|| "null".to_string());
        format!(
            r#"{{"protocol_version":65536,"protected_path_count":{protected_path_count},"resolved_path":{resolved_path}}}"#
        )
    }

    fn registry_status_output(current_sequence: u32, journal_capacity: u32) -> String {
        format!(
            r#"{{"service_name":"AegisSensorKmod","protocol_version":65536,"registry_callback_registered":true,"journal_capacity":{journal_capacity},"journal_count":1,"oldest_sequence":1,"current_sequence":{current_sequence}}}"#
        )
    }

    fn process_protection_output(protected_process_count: u32) -> String {
        format!(
            r#"{{"service_name":"AegisSensorKmod","process_id":4242,"protocol_version":65536,"ob_callback_registered":true,"protected_process_count":{protected_process_count}}}"#
        )
    }

    fn driver_integrity_output(
        protected_process_count: u32,
        kernel_code_suspicious: bool,
        code_integrity_options: u32,
    ) -> String {
        format!(
            r#"{{"service_name":"AegisSensorKmod","protocol_version":65536,"ob_callback_registered":true,"protected_process_count":{protected_process_count},"ssdt_inspection_succeeded":true,"ssdt_suspicious":false,"callback_inspection_succeeded":true,"callback_suspicious":false,"kernel_code_inspection_succeeded":true,"kernel_code_suspicious":{kernel_code_suspicious},"code_integrity_options":{code_integrity_options},"code_integrity_enabled":true,"code_integrity_testsign":false,"code_integrity_kmci_enabled":true}}"#
        )
    }

    fn registry_events_output(
        current_sequence: u32,
        events: &[(u32, i64, &str, &str, &str, Option<&str>, Option<&str>)],
    ) -> String {
        let rows = events
            .iter()
            .map(
                |(sequence, timestamp, operation, key_path, value_name, old_value, new_value)| {
                    let old_value = old_value
                        .map(|value| format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
                        .unwrap_or_else(|| "null".to_string());
                    let new_value = new_value
                        .map(|value| format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
                        .unwrap_or_else(|| "null".to_string());
                    format!(
                        "{{\"sequence\":{sequence},\"timestamp\":{timestamp},\"operation\":\"{}\",\"key_path\":\"{}\",\"value_name\":\"{}\",\"old_value_present\":{},\"new_value_present\":{},\"old_value\":{old_value},\"new_value\":{new_value}}}",
                        operation.replace('\\', "\\\\").replace('"', "\\\""),
                        key_path.replace('\\', "\\\\").replace('"', "\\\""),
                        value_name.replace('\\', "\\\\").replace('"', "\\\""),
                        old_value != "null",
                        new_value != "null"
                    )
                },
            )
            .collect::<Vec<_>>();
        format!(
            r#"{{"service_name":"AegisSensorKmod","protocol_version":65536,"oldest_sequence":0,"current_sequence":{current_sequence},"returned_count":{},"overflowed":false,"events":[{}]}}"#,
            events.len(),
            rows.join(",")
        )
    }

    fn registry_rollback_output(applied_count: u32, current_sequence: u32) -> String {
        format!(
            r#"{{"service_name":"AegisSensorKmod","key_path":"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","protocol_version":65536,"applied_count":{applied_count},"current_sequence":{current_sequence}}}"#
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
                process_protection_output(1),
                file_protection_output(0, None),
                file_protection_output(1, Some(r"\Device\HarddiskVolume4\temp\payload.exe")),
                file_status_output(1200, 256, 1),
                registry_status_output(641, 256),
                driver_integrity_output(1, false, 0x00000401),
                quarantine_receipt_output(&quarantine_path, "deadbeef"),
                artifact_bundle_output(artifact_id, &bundle_path),
                r#"{"key_path":"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"}"#
                    .to_string(),
                registry_rollback_output(1, 641),
                firewall_isolation_output(
                    r"C:\ProgramData\Aegis\firewall\backup.json",
                    "AegisIsolation-test",
                ),
                String::new(),
            ])),
            healthy_host_with_driver_surfaces(),
        )
    }

    fn platform_with_probe_for_blocks() -> WindowsPlatform {
        WindowsPlatform::with_runner_for_test(
            Box::new(QueuedWindowsRunner::new([
                firewall_block_output("AegisBlock-test"),
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
    fn windows_descriptor_uses_command_probe_until_driver_bridge_is_ready() {
        let platform = WindowsPlatform::with_runner_for_test(
            Box::new(QueuedWindowsRunner::new(Vec::<String>::new())),
            healthy_host(),
        );

        let descriptor = platform.descriptor();

        assert_eq!(descriptor.kernel_transport, KernelTransport::CommandProbe);
        assert!(!descriptor.supports_registry);
        assert!(!descriptor.supports_amsi);
        assert!(!descriptor.supports_etw_integrity);
    }

    #[test]
    fn windows_start_requires_real_execution_mode() {
        let mut platform = WindowsPlatform::new_with_runner(Box::new(FailingWindowsRunner), false);
        let error = platform
            .start(&SensorConfig {
                profile: "windows".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: false,
            })
            .expect_err("start should fail without a reachable windows host");
        let message = error.to_string();
        assert!(
            message.contains("windows host unavailable")
                || message.contains("probe windows host capabilities")
        );
    }

    #[test]
    fn windows_start_rejects_required_driver_mode_when_bridge_is_absent() {
        let mut platform = WindowsPlatform::new_with_runner(
            Box::new(QueuedWindowsRunner::new([probe_output()])),
            false,
        );
        let error = platform
            .start(&SensorConfig {
                profile: "windows-system".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: true,
            })
            .expect_err("start should fail when kernel driver mode is required without bridge");
        let message = error.to_string();
        assert!(message.contains(AEGIS_WINDOWS_DRIVER_SERVICE_NAME));
        assert!(message.contains(AEGIS_WINDOWS_DRIVER_DEVICE_PATH));
    }

    #[test]
    fn windows_start_accepts_required_driver_mode_when_bridge_is_ready() {
        let mut platform = WindowsPlatform::with_runner_for_test(
            Box::new(QueuedWindowsRunner::new([
                process_output(&[("System", 4, 0, None)]),
                audit_cursor_output(450),
                network_output(&[]),
            ])),
            healthy_host_with_driver(),
        );
        platform
            .start(&SensorConfig {
                profile: "windows-system".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: true,
            })
            .expect("start windows runtime in kernel-driver mode");

        assert_eq!(
            platform.descriptor().kernel_transport,
            KernelTransport::Driver
        );
        let snapshot = platform.health_snapshot();
        assert_eq!(
            snapshot
                .integrity_reports
                .get("driver_transport")
                .map(|report| report.passed),
            Some(true)
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
                require_kernel_driver: false,
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
        assert_eq!(snapshot.audit_artifacts.len(), 3);
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
        assert!(rollback_json
            .contains(r"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"));
        assert!(rollback_json.contains("\"applied_count\": 1"));
        assert!(rollback_json.contains("C:/temp/payload.exe"));
        let block_artifact = snapshot
            .audit_artifacts
            .iter()
            .find(|path| {
                path.file_name()
                    .and_then(|value| value.to_str())
                    .map(|value| value.starts_with("block-"))
                    .unwrap_or(false)
            })
            .expect("block artifact should exist");
        let block_json = fs::read_to_string(block_artifact).expect("read block artifact");
        assert!(block_json.contains("\"kind\": \"hash\""));
        assert!(block_json.contains("deadbeef"));
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
    fn windows_block_and_integrity_artifacts_are_materialized() {
        let platform = platform_with_probe_for_blocks();
        platform
            .block_network(
                &aegis_model::NetworkTarget {
                    value: "10.0.0.9".to_string(),
                },
                Duration::from_secs(120),
            )
            .expect("block network should create firewall rule");
        let integrity = platform.verify_integrity().expect("verify integrity");
        assert!(!integrity.passed);
        platform.clear_all_blocks().expect("clear all blocks");

        let snapshot = platform.execution_snapshot();
        assert!(snapshot.active_blocks.is_empty());
        let block_artifact = snapshot
            .audit_artifacts
            .iter()
            .find(|path| {
                path.file_name()
                    .and_then(|value| value.to_str())
                    .map(|value| value.starts_with("block-"))
                    .unwrap_or(false)
            })
            .expect("network block artifact should exist");
        let block_json = fs::read_to_string(block_artifact).expect("read network block artifact");
        assert!(block_json.contains("\"kind\": \"network\""));
        assert!(block_json.contains("\"enforced\": true"));
        assert!(block_json.contains("AegisBlock-test"));
        let integrity_artifact = snapshot
            .audit_artifacts
            .iter()
            .find(|path| {
                path.file_name()
                    .and_then(|value| value.to_str())
                    .map(|value| value.starts_with("integrity-"))
                    .unwrap_or(false)
            })
            .expect("integrity artifact should exist");
        let integrity_json =
            fs::read_to_string(integrity_artifact).expect("read integrity artifact");
        assert!(integrity_json.contains("\"verify_integrity\""));
        assert!(integrity_json.contains("\"etw_ingest\""));
        let clear_artifact = snapshot
            .audit_artifacts
            .iter()
            .find(|path| {
                path.file_name()
                    .and_then(|value| value.to_str())
                    .map(|value| value.starts_with("clear-"))
                    .unwrap_or(false)
            })
            .expect("block clear artifact should exist");
        let clear_json = fs::read_to_string(clear_artifact).expect("read clear artifact");
        assert!(clear_json.contains("\"cleared_block_count\": 1"));
        assert!(clear_json.contains("AegisBlock-test"));
    }

    #[test]
    fn windows_health_snapshot_reports_real_host_probe_state() {
        let mut platform =
            platform_with_probe_and_processes([process_output(&[("System", 4, 0, None)])]);
        platform
            .start(&SensorConfig {
                profile: "windows".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: false,
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
                .get("driver_transport")
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
    fn windows_driver_surfaces_report_real_file_and_registry_capabilities() {
        let mut host = healthy_host_with_driver_surfaces();
        host.has_process_inventory = false;
        host.has_process_creation_events = false;
        host.has_net_connection = false;

        let mut platform = WindowsPlatform::with_runner_for_test(
            Box::new(QueuedWindowsRunner::new(Vec::<String>::new())),
            host,
        );
        platform
            .start(&SensorConfig {
                profile: "windows-system".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: true,
            })
            .expect("start windows runtime with driver surfaces");

        let descriptor = platform.descriptor();
        assert_eq!(descriptor.kernel_transport, KernelTransport::Driver);
        assert!(descriptor.supports_registry);
        assert!(descriptor.supports_etw_integrity);
        let capabilities = platform.capabilities();
        assert!(capabilities.file);
        assert!(capabilities.registry);

        let snapshot = platform.health_snapshot();
        assert_eq!(
            snapshot.provider_health.get("MinifilterFile").copied(),
            Some(true)
        );
        assert_eq!(
            snapshot.provider_health.get("RegistryCallback").copied(),
            Some(true)
        );
        assert_eq!(
            snapshot.provider_health.get("ObProcess").copied(),
            Some(true)
        );
        assert_eq!(
            snapshot
                .integrity_reports
                .get("platform_protection")
                .map(|report| report.passed),
            Some(true)
        );
        assert_eq!(
            snapshot
                .integrity_reports
                .get("ssdt")
                .map(|report| report.passed),
            Some(true)
        );
    }

    #[test]
    fn windows_poll_events_emits_driver_file_and_registry_deltas() {
        let mut host = healthy_host_with_driver_surfaces();
        host.has_process_inventory = false;
        host.has_process_creation_events = false;
        host.has_net_connection = false;

        let mut platform = WindowsPlatform::with_runner_for_test(
            Box::new(QueuedWindowsRunner::new([
                file_events_output(
                    1201,
                    256,
                    &[(
                        1201,
                        1713612010,
                        4242,
                        "write",
                        r"C:\ProgramData\Aegis\sample.txt",
                    )],
                ),
                registry_events_output(
                    641,
                    &[(
                        641,
                        1713612020,
                        "set",
                        r"\REGISTRY\MACHINE\SOFTWARE\AegisW10Test",
                        "SampleValue",
                        Some("before"),
                        Some("after"),
                    )],
                ),
            ])),
            host,
        );
        platform
            .start(&SensorConfig {
                profile: "windows-system".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: true,
            })
            .expect("start windows runtime with driver surfaces");

        let mut buffer = EventBuffer::default();
        let drained = platform
            .poll_events(&mut buffer)
            .expect("poll driver-backed windows events");

        assert_eq!(drained, 2);
        let events = buffer
            .records
            .iter()
            .map(|record| String::from_utf8(record.clone()).expect("event utf8"))
            .collect::<Vec<_>>();
        assert!(events.iter().any(|event| {
            event.contains("MinifilterFile")
                && event.contains("file-write")
                && event.contains(r"C:\ProgramData\Aegis\sample.txt")
        }));
        assert!(events.iter().any(|event| {
            event.contains("RegistryCallback")
                && event.contains("registry-set")
                && event.contains(r"\REGISTRY\MACHINE\SOFTWARE\AegisW10Test")
                && event.contains("before")
                && event.contains("after")
        }));
    }

    #[test]
    fn windows_amsi_health_reflects_runtime_and_script_block_state() {
        let mut platform = WindowsPlatform::new_with_runner(
            Box::new(QueuedWindowsRunner::new([
                probe_output_with_script_memory_surface(true, true, true, false),
                process_output(&[("System", 4, 0, None)]),
                audit_cursor_output(150),
                audit_cursor_output(250),
                network_output(&[]),
            ])),
            false,
        );
        platform
            .start(&SensorConfig {
                profile: "windows".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: false,
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
    fn windows_capabilities_reflect_real_script_and_memory_surfaces() {
        let mut host = healthy_host();
        host.has_amsi_runtime = true;
        host.has_script_block_logging = true;
        host.has_amsi_scan_interface = true;
        host.has_memory_inventory = true;

        let platform = WindowsPlatform::with_runner_for_test(
            Box::new(QueuedWindowsRunner::new(Vec::<String>::new())),
            host,
        );

        let capabilities = platform.capabilities();
        let descriptor = platform.descriptor();

        assert!(capabilities.script);
        assert!(capabilities.memory);
        assert!(descriptor.supports_amsi);
    }

    #[test]
    fn windows_poll_events_emits_script_and_memory_signals() {
        let mut host = healthy_host();
        host.has_amsi_runtime = true;
        host.has_script_block_logging = true;
        host.has_amsi_scan_interface = true;
        host.has_memory_inventory = true;

        let mut platform = WindowsPlatform::with_runner_for_test(
            Box::new(QueuedWindowsRunner::new([
                process_output(&[(
                    "powershell.exe",
                    4242,
                    640,
                    Some("powershell.exe -NoProfile"),
                )]),
                audit_cursor_output(300),
                audit_cursor_output(900),
                memory_output(&[(
                    4242,
                    "powershell",
                    12 * 1024 * 1024,
                    8 * 1024 * 1024,
                    64 * 1024 * 1024,
                    4 * 1024 * 1024,
                    Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
                )]),
                network_output(&[]),
                process_output(&[(
                    "powershell.exe",
                    4242,
                    640,
                    Some("powershell.exe -NoProfile"),
                )]),
                security_process_event_output(&[]),
                script_block_events_output(&[(
                    901,
                    Some(4242),
                    Some("script-block-1"),
                    Some(1),
                    Some(1),
                    Some(r"C:\Temp\script.ps1"),
                    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
                )]),
                amsi_scan_output(1, false, false),
                memory_output(&[(
                    4242,
                    "powershell",
                    120 * 1024 * 1024,
                    96 * 1024 * 1024,
                    160 * 1024 * 1024,
                    48 * 1024 * 1024,
                    Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
                )]),
                network_output(&[]),
            ])),
            host,
        );
        platform
            .start(&SensorConfig {
                profile: "windows".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: false,
            })
            .expect("start windows runtime");

        let mut buffer = EventBuffer::default();
        let drained = platform
            .poll_events(&mut buffer)
            .expect("poll windows script and memory events");

        assert_eq!(drained, 2);
        let events = buffer
            .records
            .iter()
            .map(|record| String::from_utf8(record.clone()).expect("event utf8"))
            .collect::<Vec<_>>();
        assert!(events.iter().any(|event| {
            event.contains("AmsiScript")
                && event.contains("script-block")
                && event.contains("AmsiUtils")
        }));
        assert!(events.iter().any(|event| {
            event.contains("MemorySensor")
                && event.contains("memory-growth")
                && event.contains("private_delta_bytes=")
        }));
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
                require_kernel_driver: false,
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
                require_kernel_driver: false,
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
                require_kernel_driver: false,
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
                require_kernel_driver: false,
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
