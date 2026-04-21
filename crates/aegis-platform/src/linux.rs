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
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxProviderKind {
    ProcessEbpf,
    FileEbpf,
    NetworkEbpf,
    AuthAudit,
    ContainerMetadata,
    FanotifyFallback,
    AuditFallback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxDegradeLevel {
    Full,
    TracepointOnly,
    FanotifyAudit,
    Minimal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxEventStub {
    pub provider: LinuxProviderKind,
    pub operation: String,
    pub subject: String,
    pub container_id: Option<String>,
}

impl LinuxEventStub {
    fn encode(&self) -> Vec<u8> {
        format!(
            "linux|{:?}|{}|{}|{}",
            self.provider,
            self.operation,
            self.subject,
            self.container_id.as_deref().unwrap_or("-")
        )
        .into_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinuxFirewallBackend {
    Nftables,
    Iptables,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LinuxHostCapabilities {
    running_on_linux: bool,
    has_bpf_fs: bool,
    has_btf: bool,
    has_bpftool: bool,
    has_fanotify: bool,
    has_auth_log: bool,
    has_journalctl: bool,
    has_nft: bool,
    has_iptables: bool,
    has_apparmor: bool,
    has_tpm: bool,
    has_container_metadata: bool,
    lsm_stack: Vec<String>,
}

impl LinuxHostCapabilities {
    fn determine_degrade_level(&self) -> LinuxDegradeLevel {
        if self.running_on_linux && self.has_bpf_fs && self.has_btf && self.has_bpftool {
            LinuxDegradeLevel::Full
        } else if self.running_on_linux && self.has_bpf_fs && self.has_bpftool {
            LinuxDegradeLevel::TracepointOnly
        } else if self.running_on_linux && (self.has_fanotify || self.auth_available()) {
            LinuxDegradeLevel::FanotifyAudit
        } else {
            LinuxDegradeLevel::Minimal
        }
    }

    fn auth_available(&self) -> bool {
        self.has_auth_log || self.has_journalctl
    }

    fn bpf_ready(&self) -> bool {
        self.running_on_linux && self.has_bpf_fs && self.has_btf && self.has_bpftool
    }

    fn firewall_backend(&self) -> Option<LinuxFirewallBackend> {
        if self.has_nft {
            Some(LinuxFirewallBackend::Nftables)
        } else if self.has_iptables {
            Some(LinuxFirewallBackend::Iptables)
        } else {
            None
        }
    }

    fn protection_ready(&self) -> bool {
        self.running_on_linux
            && (self.has_apparmor
                || self.lsm_stack.iter().any(|entry| {
                    matches!(entry.as_str(), "selinux" | "landlock" | "lockdown" | "ima")
                }))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LinuxKernelRuntimeOverrides {
    assets_root: Option<PathBuf>,
    pin_root: Option<PathBuf>,
    load_requested: Option<bool>,
    attach_requested: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LinuxKernelRuntimeState {
    assets_root: Option<PathBuf>,
    manifest_path: Option<PathBuf>,
    pin_root: PathBuf,
    load_requested: bool,
    attach_requested: bool,
    planned_bundles: Vec<LinuxEbpfPlannedBundle>,
    loaded_bundles: Vec<String>,
    planned_attachments: Vec<LinuxEbpfPlannedAttachment>,
    attached_links: Vec<String>,
    last_error: Option<String>,
}

impl LinuxKernelRuntimeState {
    fn integrity_healthy(&self, host: &LinuxHostCapabilities) -> bool {
        host.bpf_ready()
            && !self.planned_bundles.is_empty()
            && self.loaded_bundles.len() == self.planned_bundles.len()
            && (!self.attach_requested
                || (!self.planned_attachments.is_empty()
                    && self.attached_links.len() == self.planned_attachments.len()))
            && self.last_error.is_none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LinuxEbpfPlannedBundle {
    name: String,
    object_path: PathBuf,
    pin_path: PathBuf,
    map_pin_path: Option<PathBuf>,
    auto_attach: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LinuxEbpfPlannedAttachment {
    bundle_name: String,
    name: String,
    kind: String,
    target: String,
    program_pin_path: Option<PathBuf>,
    link_pin_path: PathBuf,
    attach_argv: Vec<String>,
    auto_attach: bool,
}

impl LinuxEbpfPlannedAttachment {
    fn identifier(&self) -> String {
        format!("{}:{}", self.bundle_name, self.name)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct LinuxEbpfManifest {
    schema_version: u32,
    #[serde(default)]
    bundles: Vec<LinuxEbpfBundleManifestEntry>,
}

#[derive(Clone, Debug, Deserialize)]
struct LinuxEbpfBundleManifestEntry {
    name: String,
    object: String,
    #[serde(default)]
    pin_subdir: Option<String>,
    #[serde(default)]
    map_pin_subdir: Option<String>,
    #[serde(default)]
    auto_attach: bool,
    #[serde(default)]
    modes: Vec<String>,
    #[serde(default)]
    attachments: Vec<LinuxEbpfAttachmentManifestEntry>,
}

#[derive(Clone, Debug, Deserialize)]
struct LinuxEbpfAttachmentManifestEntry {
    name: String,
    kind: String,
    target: String,
    #[serde(default)]
    program_pin: Option<String>,
    #[serde(default)]
    link_pin: Option<String>,
    #[serde(default)]
    attach_argv: Vec<String>,
}

impl LinuxEbpfBundleManifestEntry {
    fn enabled_for(&self, level: LinuxDegradeLevel) -> bool {
        if self.modes.is_empty() {
            return level != LinuxDegradeLevel::Minimal;
        }

        self.modes.iter().any(|mode| match mode.as_str() {
            "full" => level == LinuxDegradeLevel::Full,
            "tracepoint_only" => level == LinuxDegradeLevel::TracepointOnly,
            "fanotify_audit" => level == LinuxDegradeLevel::FanotifyAudit,
            "minimal" => level == LinuxDegradeLevel::Minimal,
            _ => false,
        })
    }
}

struct LinuxState {
    base_dir: PathBuf,
    degrade_level: LinuxDegradeLevel,
    pending_events: VecDeque<Vec<u8>>,
    execution: PlatformExecutionSnapshot,
    host: LinuxHostCapabilities,
    host_capabilities_pinned: bool,
    known_processes: BTreeMap<u32, Option<String>>,
    auth_offsets: BTreeMap<PathBuf, u64>,
    firewall_backend: Option<LinuxFirewallBackend>,
    kernel: LinuxKernelRuntimeState,
    kernel_overrides: LinuxKernelRuntimeOverrides,
}

pub struct LinuxPlatform {
    providers: Vec<LinuxProviderKind>,
    state: Mutex<LinuxState>,
}

impl Default for LinuxPlatform {
    fn default() -> Self {
        Self::new_with_capabilities(probe_host_capabilities(), false)
    }
}

impl LinuxPlatform {
    #[cfg(test)]
    fn with_host_capabilities_for_test(capabilities: LinuxHostCapabilities) -> Self {
        Self::new_with_capabilities(capabilities, true)
    }

    fn new_with_capabilities(
        capabilities: LinuxHostCapabilities,
        host_capabilities_pinned: bool,
    ) -> Self {
        let degrade_level = capabilities.determine_degrade_level();
        let firewall_backend = capabilities.firewall_backend();
        let base_dir = platform_root("linux");
        Self {
            providers: vec![
                LinuxProviderKind::ProcessEbpf,
                LinuxProviderKind::FileEbpf,
                LinuxProviderKind::NetworkEbpf,
                LinuxProviderKind::AuthAudit,
                LinuxProviderKind::ContainerMetadata,
                LinuxProviderKind::FanotifyFallback,
                LinuxProviderKind::AuditFallback,
            ],
            state: Mutex::new(LinuxState {
                kernel: LinuxKernelRuntimeState {
                    pin_root: default_kernel_pin_root(&capabilities, &base_dir, None),
                    ..LinuxKernelRuntimeState::default()
                },
                kernel_overrides: LinuxKernelRuntimeOverrides::default(),
                base_dir,
                degrade_level,
                pending_events: VecDeque::new(),
                execution: PlatformExecutionSnapshot::default(),
                host: capabilities,
                host_capabilities_pinned,
                known_processes: BTreeMap::new(),
                auth_offsets: BTreeMap::new(),
                firewall_backend,
            }),
        }
    }

    #[cfg(test)]
    fn configure_kernel_runtime_for_test(
        &self,
        assets_root: Option<PathBuf>,
        pin_root: Option<PathBuf>,
        load_requested: bool,
        attach_requested: bool,
    ) {
        let mut state = self.state.lock().expect("linux state poisoned");
        state.kernel_overrides.assets_root = assets_root;
        state.kernel_overrides.pin_root = pin_root;
        state.kernel_overrides.load_requested = Some(load_requested);
        state.kernel_overrides.attach_requested = Some(attach_requested);
    }

    #[cfg(test)]
    fn kernel_runtime_snapshot_for_test(&self) -> LinuxKernelRuntimeState {
        self.state
            .lock()
            .expect("linux state poisoned")
            .kernel
            .clone()
    }

    pub fn provider_kinds(&self) -> &[LinuxProviderKind] {
        &self.providers
    }

    pub fn execution_snapshot(&self) -> PlatformExecutionSnapshot {
        self.state
            .lock()
            .expect("linux state poisoned")
            .execution
            .clone()
    }

    pub fn health_snapshot(&self) -> PlatformHealthSnapshot {
        let state = self.state.lock().expect("linux state poisoned");
        let running = state.execution.running;
        let host = state.host.clone();
        let degrade_level = state.degrade_level;

        let provider_health = self
            .providers
            .iter()
            .map(|provider| {
                let healthy = match provider {
                    LinuxProviderKind::ProcessEbpf => {
                        running
                            && host.running_on_linux
                            && degrade_level != LinuxDegradeLevel::Minimal
                    }
                    LinuxProviderKind::FileEbpf => {
                        running
                            && matches!(
                                degrade_level,
                                LinuxDegradeLevel::Full | LinuxDegradeLevel::TracepointOnly
                            )
                    }
                    LinuxProviderKind::NetworkEbpf => {
                        running
                            && matches!(
                                degrade_level,
                                LinuxDegradeLevel::Full
                                    | LinuxDegradeLevel::TracepointOnly
                                    | LinuxDegradeLevel::FanotifyAudit
                            )
                    }
                    LinuxProviderKind::AuthAudit => running && host.auth_available(),
                    LinuxProviderKind::ContainerMetadata => running && host.has_container_metadata,
                    LinuxProviderKind::FanotifyFallback => {
                        running
                            && host.has_fanotify
                            && degrade_level == LinuxDegradeLevel::FanotifyAudit
                    }
                    LinuxProviderKind::AuditFallback => {
                        running
                            && host.auth_available()
                            && matches!(
                                degrade_level,
                                LinuxDegradeLevel::FanotifyAudit | LinuxDegradeLevel::Minimal
                            )
                    }
                };
                (format!("{provider:?}"), healthy)
            })
            .collect();

        let kernel_code = kernel_code_integrity_report(&host, degrade_level, &state.kernel);
        let platform_protection = protection_integrity_report(&host);

        PlatformHealthSnapshot {
            provider_health,
            integrity_reports: BTreeMap::from([
                (
                    "ssdt".to_string(),
                    IntegrityReport {
                        passed: true,
                        details: "n/a for linux".to_string(),
                    },
                ),
                (
                    "callbacks".to_string(),
                    IntegrityReport {
                        passed: true,
                        details: "n/a for linux".to_string(),
                    },
                ),
                ("kernel_code".to_string(), kernel_code),
                ("platform_protection".to_string(), platform_protection),
            ]),
        }
    }

    pub fn degrade_level(&self) -> LinuxDegradeLevel {
        self.state
            .lock()
            .expect("linux state poisoned")
            .degrade_level
    }

    pub fn set_degrade_level(&self, level: LinuxDegradeLevel) {
        self.state
            .lock()
            .expect("linux state poisoned")
            .degrade_level = level;
    }

    pub fn inject_event(&self, event: LinuxEventStub) {
        self.state
            .lock()
            .expect("linux state poisoned")
            .pending_events
            .push_back(event.encode());
    }
}

impl PlatformSensor for LinuxPlatform {
    fn start(&mut self, _config: &SensorConfig) -> Result<()> {
        let mut state = self.state.lock().expect("linux state poisoned");
        if !state.host_capabilities_pinned {
            state.host = probe_host_capabilities();
            state.degrade_level = state.host.determine_degrade_level();
            state.firewall_backend = state.host.firewall_backend();
        }
        refresh_kernel_runtime(&mut state);
        state.known_processes = snapshot_processes();
        state.execution.running = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.state
            .lock()
            .expect("linux state poisoned")
            .execution
            .running = false;
        Ok(())
    }

    fn poll_events(&self, buf: &mut EventBuffer) -> Result<usize> {
        let mut state = self.state.lock().expect("linux state poisoned");
        if !state.execution.running {
            return Ok(0);
        }

        collect_live_linux_events(&mut state);

        let mut drained = 0usize;
        while let Some(event) = state.pending_events.pop_front() {
            buf.records.push(event);
            drained += 1;
        }
        Ok(drained)
    }

    fn capabilities(&self) -> SensorCapabilities {
        let state = self.state.lock().expect("linux state poisoned");
        let host = &state.host;
        let degrade_level = state.degrade_level;
        SensorCapabilities {
            process: host.running_on_linux && degrade_level != LinuxDegradeLevel::Minimal,
            file: host.running_on_linux
                && matches!(
                    degrade_level,
                    LinuxDegradeLevel::Full
                        | LinuxDegradeLevel::TracepointOnly
                        | LinuxDegradeLevel::FanotifyAudit
                ),
            network: host.running_on_linux
                && matches!(
                    degrade_level,
                    LinuxDegradeLevel::Full
                        | LinuxDegradeLevel::TracepointOnly
                        | LinuxDegradeLevel::FanotifyAudit
                ),
            registry: false,
            auth: host.auth_available(),
            script: false,
            memory: host.bpf_ready(),
            container: host.has_container_metadata,
        }
    }
}

impl PlatformResponse for LinuxPlatform {
    fn suspend_process(&self, pid: u32) -> Result<()> {
        if cfg!(target_os = "linux") {
            send_signal(pid, "STOP").with_context(|| format!("suspend pid {pid}"))?;
        }
        self.state
            .lock()
            .expect("linux state poisoned")
            .execution
            .suspended_pids
            .push(pid);
        Ok(())
    }

    fn kill_process(&self, pid: u32) -> Result<()> {
        if cfg!(target_os = "linux") {
            send_signal(pid, "KILL").with_context(|| format!("kill pid {pid}"))?;
        }
        self.state
            .lock()
            .expect("linux state poisoned")
            .execution
            .terminated_pids
            .push(pid);
        Ok(())
    }

    fn kill_ppl_process(&self, pid: u32) -> Result<()> {
        if cfg!(target_os = "linux") {
            send_signal(pid, "KILL").with_context(|| format!("kill protected pid {pid}"))?;
        }
        self.state
            .lock()
            .expect("linux state poisoned")
            .execution
            .terminated_protected_pids
            .push(pid);
        Ok(())
    }

    fn quarantine_file(&self, path: &Path) -> Result<QuarantineReceipt> {
        let mut state = self.state.lock().expect("linux state poisoned");
        let receipt = materialize_quarantine(&mut state, path, "linux-quarantine")?;
        state.execution.quarantined_files.push(receipt.clone());
        Ok(receipt)
    }

    fn network_isolate(&self, rules: &IsolationRulesV2) -> Result<()> {
        let mut state = self.state.lock().expect("linux state poisoned");
        let manifest_path = write_network_isolation_manifest(&mut state, rules)?;
        if state.host.running_on_linux && should_apply_firewall() {
            apply_firewall_manifest(state.firewall_backend, &manifest_path)?;
        }
        state.execution.network_isolation_active = true;
        state.execution.last_isolation_rules = Some(rules.clone());
        Ok(())
    }

    fn network_release(&self) -> Result<()> {
        let mut state = self.state.lock().expect("linux state poisoned");
        let release_path = write_network_release_manifest(&mut state)?;
        if state.host.running_on_linux && should_apply_firewall() {
            release_firewall_manifest(state.firewall_backend, &release_path)?;
        }
        state.execution.network_isolation_active = false;
        Ok(())
    }

    fn registry_rollback(&self, target: &RollbackTarget) -> Result<()> {
        self.state
            .lock()
            .expect("linux state poisoned")
            .execution
            .rollback_targets
            .push(target.clone());
        Ok(())
    }

    fn collect_forensics(&self, spec: &ForensicSpec) -> Result<ArtifactBundle> {
        let mut state = self.state.lock().expect("linux state poisoned");
        let bundle = materialize_artifact(&mut state, spec, "tar", "linux-forensics")?;
        state.execution.forensic_artifacts.push(bundle.clone());
        Ok(bundle)
    }
}

impl PreemptiveBlock for LinuxPlatform {
    fn block_hash(&self, hash: &str, ttl: Duration) -> Result<()> {
        push_block(
            &mut self.state.lock().expect("linux state poisoned").execution,
            "hash",
            hash.to_string(),
            ttl,
        );
        Ok(())
    }

    fn block_pid(&self, pid: u32, ttl: Duration) -> Result<()> {
        push_block(
            &mut self.state.lock().expect("linux state poisoned").execution,
            "pid",
            pid.to_string(),
            ttl,
        );
        Ok(())
    }

    fn block_path(&self, path: &Path, ttl: Duration) -> Result<()> {
        push_block(
            &mut self.state.lock().expect("linux state poisoned").execution,
            "path",
            path.display().to_string(),
            ttl,
        );
        Ok(())
    }

    fn block_network(&self, target: &NetworkTarget, ttl: Duration) -> Result<()> {
        push_block(
            &mut self.state.lock().expect("linux state poisoned").execution,
            "network",
            target.value.clone(),
            ttl,
        );
        Ok(())
    }

    fn clear_all_blocks(&self) -> Result<()> {
        self.state
            .lock()
            .expect("linux state poisoned")
            .execution
            .active_blocks
            .clear();
        Ok(())
    }
}

impl KernelIntegrity for LinuxPlatform {
    fn check_ssdt_integrity(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            passed: true,
            details: "n/a for linux".to_string(),
        })
    }

    fn check_callback_tables(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            passed: true,
            details: "n/a for linux".to_string(),
        })
    }

    fn check_kernel_code(&self) -> Result<IntegrityReport> {
        let state = self.state.lock().expect("linux state poisoned");
        Ok(kernel_code_integrity_report(
            &state.host,
            state.degrade_level,
            &state.kernel,
        ))
    }

    fn detect_hidden_processes(&self) -> Result<Vec<SuspiciousProcess>> {
        if !cfg!(target_os = "linux") {
            return Ok(Vec::new());
        }

        let proc_pids = snapshot_processes().into_keys().collect::<BTreeSet<_>>();
        let ps_output = run_command_capture("ps", ["-eo", "pid="]).unwrap_or_default();
        let ps_pids = ps_output
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .collect::<BTreeSet<_>>();

        let mut suspicious = Vec::new();
        for pid in proc_pids.difference(&ps_pids) {
            suspicious.push(SuspiciousProcess {
                pid: *pid,
                reason: "present in /proc but absent from ps enumeration".to_string(),
            });
        }
        for pid in ps_pids.difference(&proc_pids) {
            suspicious.push(SuspiciousProcess {
                pid: *pid,
                reason: "present in ps output but absent from /proc".to_string(),
            });
        }
        Ok(suspicious)
    }
}

impl PlatformProtection for LinuxPlatform {
    fn protect_process(&self, pid: u32) -> Result<()> {
        let mut state = self.state.lock().expect("linux state poisoned");
        state.execution.protected_pids.push(pid);
        let lines = state
            .execution
            .protected_pids
            .iter()
            .map(|entry| entry.to_string())
            .collect::<Vec<_>>();
        materialize_protection_manifest(&mut state, "processes.txt", lines)
    }

    fn protect_files(&self, paths: &[PathBuf]) -> Result<()> {
        let mut state = self.state.lock().expect("linux state poisoned");
        state
            .execution
            .protected_paths
            .extend(paths.iter().cloned());
        let lines = state
            .execution
            .protected_paths
            .iter()
            .map(|entry| entry.display().to_string())
            .collect::<Vec<_>>();
        materialize_protection_manifest(&mut state, "paths.txt", lines)
    }

    fn protect_registry(&self, _selectors: &[String]) -> Result<()> {
        bail!("registry protection is unavailable on linux")
    }

    fn verify_integrity(&self) -> Result<IntegrityReport> {
        let state = self.state.lock().expect("linux state poisoned");
        Ok(protection_integrity_report(&state.host))
    }

    fn check_etw_integrity(&self) -> Result<EtwStatus> {
        Ok(EtwStatus { healthy: false })
    }

    fn check_amsi_integrity(&self) -> Result<AmsiStatus> {
        Ok(AmsiStatus { healthy: false })
    }

    fn check_bpf_integrity(&self) -> Result<BpfStatus> {
        let state = self.state.lock().expect("linux state poisoned");
        Ok(BpfStatus {
            healthy: state.kernel.integrity_healthy(&state.host),
        })
    }
}

impl PlatformRuntime for LinuxPlatform {
    fn descriptor(&self) -> PlatformDescriptor {
        let state = self.state.lock().expect("linux state poisoned");
        PlatformDescriptor {
            target: PlatformTarget::Linux,
            kernel_transport: KernelTransport::EBpf,
            degrade_levels: 4,
            supports_registry: false,
            supports_amsi: false,
            supports_etw_integrity: false,
            supports_bpf_integrity: state.host.bpf_ready(),
            supports_container_sensor: state.host.has_container_metadata,
        }
    }
}

fn probe_host_capabilities() -> LinuxHostCapabilities {
    if !cfg!(target_os = "linux") {
        return LinuxHostCapabilities::default();
    }

    let lsm_stack = read_string("/sys/kernel/security/lsm")
        .unwrap_or_default()
        .split(',')
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>();

    LinuxHostCapabilities {
        running_on_linux: true,
        has_bpf_fs: path_exists("/sys/fs/bpf"),
        has_btf: path_exists("/sys/kernel/btf/vmlinux"),
        has_bpftool: command_exists("bpftool"),
        has_fanotify: path_exists("/proc/sys/fs/fanotify/max_queued_events"),
        has_auth_log: candidate_auth_log_paths()
            .into_iter()
            .any(|path| path.exists()),
        has_journalctl: command_exists("journalctl"),
        has_nft: command_exists("nft"),
        has_iptables: command_exists("iptables"),
        has_apparmor: apparmor_enabled(&lsm_stack),
        has_tpm: path_exists("/sys/class/tpm/tpm0")
            || path_exists("/dev/tpm0")
            || path_exists("/dev/tpmrm0"),
        has_container_metadata: path_exists("/proc/self/cgroup"),
        lsm_stack,
    }
}

fn refresh_kernel_runtime(state: &mut LinuxState) {
    let attach_requested = state
        .kernel_overrides
        .attach_requested
        .unwrap_or_else(|| env_flag("AEGIS_LINUX_ATTACH_BPF"));
    state.kernel = LinuxKernelRuntimeState {
        pin_root: default_kernel_pin_root(
            &state.host,
            &state.base_dir,
            state.kernel_overrides.pin_root.as_deref(),
        ),
        load_requested: state
            .kernel_overrides
            .load_requested
            .unwrap_or_else(|| env_flag("AEGIS_LINUX_LOAD_BPF") || attach_requested),
        attach_requested,
        ..LinuxKernelRuntimeState::default()
    };

    match discover_ebpf_assets_root(state.kernel_overrides.assets_root.as_deref()) {
        Ok(assets_root) => state.kernel.assets_root = assets_root,
        Err(error) => {
            state.kernel.last_error = Some(error.to_string());
            return;
        }
    }

    let Some(assets_root) = state.kernel.assets_root.clone() else {
        if state.host.bpf_ready() {
            state.kernel.last_error = Some("ebpf asset manifest not found".to_string());
        }
        return;
    };

    let manifest_path = assets_root.join("manifest.json");
    let manifest = match load_ebpf_manifest(&manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => {
            state.kernel.last_error = Some(error.to_string());
            return;
        }
    };
    state.kernel.manifest_path = Some(manifest_path);

    let mut missing_objects = Vec::new();
    for bundle in manifest
        .bundles
        .into_iter()
        .filter(|bundle| bundle.enabled_for(state.degrade_level))
    {
        let object_path = assets_root.join(&bundle.object);
        if !object_path.is_file() {
            missing_objects.push(format!("{}({})", bundle.name, object_path.display()));
            continue;
        }
        let bundle_pin_path = state.kernel.pin_root.join(
            bundle
                .pin_subdir
                .clone()
                .unwrap_or_else(|| bundle.name.clone()),
        );
        let map_pin_path = bundle
            .map_pin_subdir
            .clone()
            .map(|subdir| state.kernel.pin_root.join(subdir));
        for attachment in bundle.attachments {
            state.kernel.planned_attachments.push(plan_attachment(
                &bundle.name,
                &bundle_pin_path,
                bundle.auto_attach,
                attachment,
            ));
        }
        state.kernel.planned_bundles.push(LinuxEbpfPlannedBundle {
            pin_path: bundle_pin_path,
            name: bundle.name,
            object_path,
            map_pin_path,
            auto_attach: bundle.auto_attach,
        });
    }

    if !missing_objects.is_empty() {
        append_kernel_error(
            &mut state.kernel.last_error,
            format!("missing ebpf bundle objects: {}", missing_objects.join(",")),
        );
    }

    reconcile_loaded_runtime(&mut state.kernel);

    if state.host.bpf_ready() && state.kernel.load_requested {
        if let Err(error) = attempt_bpf_bundle_load(&mut state.kernel) {
            append_kernel_error(&mut state.kernel.last_error, error.to_string());
        }
        reconcile_loaded_runtime(&mut state.kernel);
    }

    if state.host.bpf_ready() && state.kernel.attach_requested {
        if state.kernel.planned_attachments.is_empty() {
            append_kernel_error(
                &mut state.kernel.last_error,
                "ebpf attach requested but manifest has no attachment metadata".to_string(),
            );
        } else if let Err(error) = attempt_bpf_attachment_reconcile(&mut state.kernel) {
            append_kernel_error(&mut state.kernel.last_error, error.to_string());
        }
        reconcile_loaded_runtime(&mut state.kernel);
    }

    if state.host.bpf_ready() && state.kernel.planned_bundles.is_empty() {
        append_kernel_error(
            &mut state.kernel.last_error,
            format!(
                "no ebpf bundles planned for degrade={:?}",
                state.degrade_level
            ),
        );
    }
}

fn default_kernel_pin_root(
    host: &LinuxHostCapabilities,
    base_dir: &Path,
    override_root: Option<&Path>,
) -> PathBuf {
    if let Some(root) = override_root {
        return root.to_path_buf();
    }
    if host.running_on_linux && host.has_bpf_fs {
        PathBuf::from("/sys/fs/bpf/edr")
    } else {
        base_dir.join("bpffs").join("edr")
    }
}

fn discover_ebpf_assets_root(override_root: Option<&Path>) -> Result<Option<PathBuf>> {
    if let Some(root) = override_root {
        if root.is_dir() {
            return Ok(Some(root.to_path_buf()));
        }
        anyhow::bail!("configured ebpf assets root missing: {}", root.display());
    }

    for candidate in candidate_ebpf_asset_roots() {
        if candidate.is_dir() && candidate.join("manifest.json").is_file() {
            return Ok(Some(candidate));
        }
    }

    Ok(None)
}

fn candidate_ebpf_asset_roots() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("AEGIS_LINUX_EBPF_ASSETS") {
        candidates.push(PathBuf::from(path));
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("assets/linux-ebpf"));
        candidates.push(cwd.join("dist/linux-ebpf"));
        candidates.push(cwd.join("packaging/linux-ebpf"));
    }
    candidates.push(PathBuf::from("/opt/aegis/ebpf"));
    candidates
}

fn load_ebpf_manifest(path: &Path) -> Result<LinuxEbpfManifest> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("read ebpf manifest {}", path.display()))?;
    let manifest: LinuxEbpfManifest = serde_json::from_str(&content)
        .with_context(|| format!("parse ebpf manifest {}", path.display()))?;
    if manifest.schema_version != 1 {
        anyhow::bail!(
            "unsupported ebpf manifest schema {} for {}",
            manifest.schema_version,
            path.display()
        );
    }
    Ok(manifest)
}

fn plan_attachment(
    bundle_name: &str,
    bundle_pin_path: &Path,
    bundle_auto_attach: bool,
    attachment: LinuxEbpfAttachmentManifestEntry,
) -> LinuxEbpfPlannedAttachment {
    let link_pin_name = attachment
        .link_pin
        .unwrap_or_else(|| format!("{}.link", attachment.name));
    let program_pin_path = if bundle_auto_attach {
        None
    } else {
        let program_pin_name = attachment
            .program_pin
            .unwrap_or_else(|| attachment.name.clone());
        Some(bundle_pin_path.join(program_pin_name))
    };

    LinuxEbpfPlannedAttachment {
        bundle_name: bundle_name.to_string(),
        name: attachment.name,
        kind: attachment.kind,
        target: attachment.target,
        program_pin_path,
        link_pin_path: bundle_pin_path.join(link_pin_name),
        attach_argv: attachment.attach_argv,
        auto_attach: bundle_auto_attach,
    }
}

fn reconcile_loaded_runtime(kernel: &mut LinuxKernelRuntimeState) {
    kernel.loaded_bundles = kernel
        .planned_bundles
        .iter()
        .filter(|bundle| pin_dir_has_entries(&bundle.pin_path))
        .map(|bundle| bundle.name.clone())
        .collect();
    kernel.attached_links = kernel
        .planned_attachments
        .iter()
        .filter(|attachment| attachment.link_pin_path.exists())
        .map(LinuxEbpfPlannedAttachment::identifier)
        .collect();
}

fn pin_dir_has_entries(path: &Path) -> bool {
    path.is_dir()
        && fs::read_dir(path)
            .ok()
            .and_then(|mut entries| entries.next())
            .is_some()
}

fn attempt_bpf_bundle_load(kernel: &mut LinuxKernelRuntimeState) -> Result<()> {
    if kernel.planned_bundles.is_empty() {
        return Ok(());
    }
    if !command_exists("bpftool") {
        anyhow::bail!("bpftool not available for ebpf load");
    }

    fs::create_dir_all(&kernel.pin_root)
        .with_context(|| format!("create ebpf pin root {}", kernel.pin_root.display()))?;

    for bundle in &kernel.planned_bundles {
        if pin_dir_has_entries(&bundle.pin_path) {
            continue;
        }
        fs::create_dir_all(&bundle.pin_path)
            .with_context(|| format!("create ebpf pin dir {}", bundle.pin_path.display()))?;

        let mut command = Command::new("bpftool");
        command
            .arg("prog")
            .arg("loadall")
            .arg(&bundle.object_path)
            .arg(&bundle.pin_path);
        if let Some(map_pin_path) = &bundle.map_pin_path {
            fs::create_dir_all(map_pin_path)
                .with_context(|| format!("create ebpf map pin dir {}", map_pin_path.display()))?;
            command.arg("pinmaps").arg(map_pin_path);
        }
        if bundle.auto_attach {
            command.arg("autoattach");
        }
        let status = command.status().with_context(|| {
            format!(
                "load ebpf bundle {} from {}",
                bundle.name,
                bundle.object_path.display()
            )
        })?;
        if !status.success() {
            anyhow::bail!(
                "bpftool loadall failed for bundle {} with status {}",
                bundle.name,
                status
            );
        }
    }

    Ok(())
}

fn attempt_bpf_attachment_reconcile(kernel: &mut LinuxKernelRuntimeState) -> Result<()> {
    if kernel.planned_attachments.is_empty() {
        return Ok(());
    }

    let can_invoke_bpftool = command_exists("bpftool");
    let mut failures = Vec::new();
    for attachment in &kernel.planned_attachments {
        if attachment.link_pin_path.exists() {
            continue;
        }
        if attachment.auto_attach {
            failures.push(format!(
                "{} missing auto-attached link {}",
                attachment.identifier(),
                attachment.link_pin_path.display()
            ));
            continue;
        }
        let Some(program_pin_path) = &attachment.program_pin_path else {
            failures.push(format!(
                "{} missing program pin {}",
                attachment.identifier(),
                attachment.link_pin_path.display()
            ));
            continue;
        };
        if !program_pin_path.exists() {
            failures.push(format!(
                "{} missing program pin {}",
                attachment.identifier(),
                program_pin_path.display()
            ));
            continue;
        }
        if attachment.attach_argv.is_empty() {
            failures.push(format!(
                "{} missing attach argv for {} {}",
                attachment.identifier(),
                attachment.kind,
                attachment.target
            ));
            continue;
        }
        if !can_invoke_bpftool {
            failures.push(format!(
                "{} missing link pin {} and bpftool is unavailable for attach",
                attachment.identifier(),
                attachment.link_pin_path.display()
            ));
            continue;
        }

        let args = attachment
            .attach_argv
            .iter()
            .map(|arg| substitute_attachment_arg(attachment, arg))
            .collect::<Vec<_>>();
        let status = Command::new("bpftool")
            .args(&args)
            .status()
            .with_context(|| {
                format!(
                    "attach ebpf {} via bpftool {}",
                    attachment.identifier(),
                    args.join(" ")
                )
            })?;
        if !status.success() {
            failures.push(format!(
                "{} attach exited with status {}",
                attachment.identifier(),
                status
            ));
            continue;
        }
        if !attachment.link_pin_path.exists() {
            failures.push(format!(
                "{} attach succeeded but link pin {} is absent",
                attachment.identifier(),
                attachment.link_pin_path.display()
            ));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(failures.join("; "))
    }
}

fn substitute_attachment_arg(attachment: &LinuxEbpfPlannedAttachment, arg: &str) -> String {
    let bundle_pin = attachment
        .program_pin_path
        .as_deref()
        .and_then(Path::parent)
        .unwrap_or_else(|| {
            attachment
                .link_pin_path
                .parent()
                .unwrap_or_else(|| Path::new(""))
        });
    arg.replace(
        "{program_pin}",
        &attachment
            .program_pin_path
            .as_deref()
            .unwrap_or_else(|| Path::new(""))
            .to_string_lossy(),
    )
    .replace("{link_pin}", &attachment.link_pin_path.to_string_lossy())
    .replace("{bundle}", &attachment.bundle_name)
    .replace("{bundle_pin}", &bundle_pin.to_string_lossy())
    .replace("{kind}", &attachment.kind)
    .replace("{target}", &attachment.target)
}

fn append_kernel_error(current: &mut Option<String>, next: String) {
    match current {
        Some(existing) => {
            if !existing.contains(&next) {
                existing.push_str("; ");
                existing.push_str(&next);
            }
        }
        None => *current = Some(next),
    }
}

fn collect_live_linux_events(state: &mut LinuxState) {
    if !state.host.running_on_linux {
        return;
    }
    collect_process_delta_events(state);
    collect_auth_log_events(state);
}

fn collect_process_delta_events(state: &mut LinuxState) {
    let current = snapshot_processes();
    for (pid, container_id) in &current {
        if !state.known_processes.contains_key(pid) {
            state.pending_events.push_back(
                LinuxEventStub {
                    provider: LinuxProviderKind::ProcessEbpf,
                    operation: "process-start".to_string(),
                    subject: process_subject(*pid),
                    container_id: container_id.clone(),
                }
                .encode(),
            );
        }
    }

    for (pid, container_id) in &state.known_processes {
        if !current.contains_key(pid) {
            state.pending_events.push_back(
                LinuxEventStub {
                    provider: LinuxProviderKind::ProcessEbpf,
                    operation: "process-exit".to_string(),
                    subject: format!("pid={pid}"),
                    container_id: container_id.clone(),
                }
                .encode(),
            );
        }
    }

    state.known_processes = current;
}

fn collect_auth_log_events(state: &mut LinuxState) {
    for path in candidate_auth_log_paths() {
        if !path.exists() {
            continue;
        }

        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let metadata = match file.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let offset = state.auth_offsets.entry(path.clone()).or_insert(0);
        if metadata.len() < *offset {
            *offset = 0;
        }
        if file.seek(SeekFrom::Start(*offset)).is_err() {
            continue;
        }

        let mut new_bytes = Vec::new();
        if file.read_to_end(&mut new_bytes).is_err() {
            continue;
        }
        *offset += new_bytes.len() as u64;

        let content = String::from_utf8_lossy(&new_bytes);
        for line in content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .take(32)
        {
            state.pending_events.push_back(
                LinuxEventStub {
                    provider: LinuxProviderKind::AuthAudit,
                    operation: "auth-log".to_string(),
                    subject: truncate_subject(line.trim()),
                    container_id: None,
                }
                .encode(),
            );
        }
    }
}

fn snapshot_processes() -> BTreeMap<u32, Option<String>> {
    if !cfg!(target_os = "linux") {
        return BTreeMap::new();
    }

    let mut snapshot = BTreeMap::new();
    let entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => return snapshot,
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let pid = match file_name.to_string_lossy().parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => continue,
        };
        snapshot.insert(pid, read_container_id(pid));
    }
    snapshot
}

fn read_container_id(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/cgroup");
    let content = read_string(path)?;
    content.lines().find_map(parse_container_id)
}

fn parse_container_id(line: &str) -> Option<String> {
    line.split('/')
        .filter_map(normalize_container_id_segment)
        .next()
}

fn normalize_container_id_segment(segment: &str) -> Option<String> {
    let mut normalized = segment.trim().trim_end_matches(".scope").to_string();
    for prefix in ["docker-", "cri-containerd-", "libpod-", "kubepods-"] {
        if let Some(stripped) = normalized.strip_prefix(prefix) {
            normalized = stripped.to_string();
        }
    }

    let candidate = normalized
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .collect::<String>();
    if candidate.len() >= 12 {
        Some(candidate)
    } else {
        None
    }
}

fn process_subject(pid: u32) -> String {
    let comm_path = format!("/proc/{pid}/comm");
    if let Some(comm) = read_string(&comm_path).map(|value| value.trim().to_string()) {
        if !comm.is_empty() {
            return format!("pid={pid} comm={comm}");
        }
    }

    let cmdline_path = format!("/proc/{pid}/cmdline");
    if let Some(cmdline) = fs::read(&cmdline_path)
        .ok()
        .map(|bytes| {
            bytes
                .split(|byte| *byte == 0)
                .filter_map(|part| std::str::from_utf8(part).ok())
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|cmdline| !cmdline.is_empty())
    {
        return format!("pid={pid} cmd={cmdline}");
    }

    format!("pid={pid}")
}

fn kernel_code_integrity_report(
    host: &LinuxHostCapabilities,
    degrade_level: LinuxDegradeLevel,
    kernel: &LinuxKernelRuntimeState,
) -> IntegrityReport {
    let mut missing = Vec::new();
    if !host.running_on_linux {
        missing.push("not-running-on-linux".to_string());
    }
    if !host.has_bpf_fs {
        missing.push("bpffs".to_string());
    }
    if !host.has_btf {
        missing.push("btf".to_string());
    }
    if !host.has_bpftool {
        missing.push("bpftool".to_string());
    }

    if host.bpf_ready() {
        if kernel.manifest_path.is_none() {
            missing.push("ebpf-assets".to_string());
        }
        if kernel.planned_bundles.is_empty() {
            missing.push("ebpf-bundles".to_string());
        }
        if kernel.attach_requested && kernel.planned_attachments.is_empty() {
            missing.push("ebpf-attachments".to_string());
        }
        if !kernel.integrity_healthy(host) {
            let unloaded = kernel
                .planned_bundles
                .iter()
                .filter(|bundle| {
                    !kernel
                        .loaded_bundles
                        .iter()
                        .any(|loaded| loaded == &bundle.name)
                })
                .map(|bundle| bundle.name.clone())
                .collect::<Vec<_>>();
            if !unloaded.is_empty() {
                missing.push(format!("unloaded={}", unloaded.join("+")));
            }
            if kernel.attach_requested {
                let unattached = kernel
                    .planned_attachments
                    .iter()
                    .filter(|attachment| {
                        !kernel
                            .attached_links
                            .iter()
                            .any(|attached| attached == &attachment.identifier())
                    })
                    .map(LinuxEbpfPlannedAttachment::identifier)
                    .collect::<Vec<_>>();
                if !unattached.is_empty() {
                    missing.push(format!("unattached={}", unattached.join("+")));
                }
            }
        }
    }

    if missing.is_empty() {
        IntegrityReport {
            passed: true,
            details: format!(
                "linux eBPF baseline intact ({degrade_level:?}); bundles={}; attachments={}; pin_root={}",
                kernel.loaded_bundles.join(","),
                kernel.attached_links.join(","),
                kernel.pin_root.display()
            ),
        }
    } else {
        IntegrityReport {
            passed: false,
            details: format!(
                "linux kernel telemetry degraded ({degrade_level:?}); missing={}; pin_root={}; last_error={}",
                missing.join(","),
                kernel.pin_root.display(),
                kernel.last_error.as_deref().unwrap_or("-")
            ),
        }
    }
}

fn protection_integrity_report(host: &LinuxHostCapabilities) -> IntegrityReport {
    if !host.running_on_linux {
        return IntegrityReport {
            passed: false,
            details: "linux protection unavailable on non-linux host".to_string(),
        };
    }

    let mut factors = Vec::new();
    if host.has_apparmor {
        factors.push("apparmor".to_string());
    }
    if host.has_tpm {
        factors.push("tpm".to_string());
    }
    if !host.lsm_stack.is_empty() {
        factors.push(format!("lsm={}", host.lsm_stack.join("+")));
    }

    IntegrityReport {
        passed: host.protection_ready(),
        details: if factors.is_empty() {
            "linux protection baseline missing LSM/AppArmor signal".to_string()
        } else {
            format!("linux protection baseline: {}", factors.join(", "))
        },
    }
}

fn platform_root(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("aegis-{prefix}-{}", Uuid::now_v7().simple()))
}

fn materialize_quarantine(
    state: &mut LinuxState,
    original: &Path,
    _marker: &str,
) -> Result<QuarantineReceipt> {
    let file_name = original
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("artifact.bin");
    let vault_path = state.base_dir.join("quarantine").join(file_name);
    if let Some(parent) = vault_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = File::open(original)
        .with_context(|| format!("open quarantine source {}", original.display()))?;
    let mut hasher = Sha256::new();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    hasher.update(&bytes);
    fs::write(&vault_path, &bytes)?;
    fs::remove_file(original).ok();

    Ok(QuarantineReceipt {
        vault_path,
        sha256: format!("{:x}", hasher.finalize()),
    })
}

fn materialize_artifact(
    state: &mut LinuxState,
    spec: &ForensicSpec,
    extension: &str,
    marker: &str,
) -> Result<ArtifactBundle> {
    let artifact_id = Uuid::now_v7();
    let forensics_root = state.base_dir.join("forensics");
    let stage_dir = forensics_root.join(format!("{artifact_id}.d"));
    let location = forensics_root.join(format!("{artifact_id}.{extension}"));
    fs::create_dir_all(&stage_dir)?;

    write_text_file(
        stage_dir.join("summary.txt"),
        format!(
            "{marker}\nmemory={}\nregistry={}\nnetwork={}\ndegrade={:?}\n",
            spec.include_memory, spec.include_registry, spec.include_network, state.degrade_level
        ),
    )?;
    write_optional_snapshot(
        stage_dir.join("uname.txt"),
        run_command_capture("uname", ["-a"]),
    )?;
    write_optional_snapshot(
        stage_dir.join("os-release.txt"),
        read_string("/etc/os-release"),
    )?;
    write_optional_snapshot(
        stage_dir.join("proc-self-status.txt"),
        read_string("/proc/self/status"),
    )?;
    if spec.include_memory {
        write_optional_snapshot(stage_dir.join("meminfo.txt"), read_string("/proc/meminfo"))?;
    }
    if spec.include_network {
        write_optional_snapshot(
            stage_dir.join("ip-address.txt"),
            run_command_capture("ip", ["-brief", "address"]),
        )?;
        write_optional_snapshot(stage_dir.join("net-tcp.txt"), read_string("/proc/net/tcp"))?;
        write_optional_snapshot(
            stage_dir.join("net-tcp6.txt"),
            read_string("/proc/net/tcp6"),
        )?;
    }
    if spec.include_registry {
        write_text_file(
            stage_dir.join("registry.txt"),
            "registry collection is not applicable on linux".to_string(),
        )?;
    }
    if state.host.has_journalctl {
        write_optional_snapshot(
            stage_dir.join("journalctl.txt"),
            run_command_capture("journalctl", ["-n", "200", "--no-pager"]),
        )?;
    }

    if state.host.running_on_linux && state.host.has_journalctl && command_exists("tar") {
        let status = Command::new("tar")
            .arg("-cf")
            .arg(&location)
            .arg("-C")
            .arg(&stage_dir)
            .arg(".")
            .status()
            .context("spawn tar for forensics bundle")?;
        if !status.success() {
            anyhow::bail!("tar failed while creating {}", location.display());
        }
    } else {
        fs::write(
            &location,
            format!("{marker}|staged_dir={}", stage_dir.display()),
        )?;
    }

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

fn materialize_protection_manifest(
    state: &mut LinuxState,
    name: &str,
    lines: Vec<String>,
) -> Result<()> {
    let path = state.base_dir.join("protection").join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, lines.join("\n"))?;
    Ok(())
}

fn write_network_isolation_manifest(
    state: &mut LinuxState,
    rules: &IsolationRulesV2,
) -> Result<PathBuf> {
    let path = state.base_dir.join("firewall").join("isolate.nft");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let manifest = match state.firewall_backend {
        Some(LinuxFirewallBackend::Nftables) => build_nft_manifest(rules),
        Some(LinuxFirewallBackend::Iptables) => build_iptables_manifest(rules),
        None => "# no firewall backend detected\n".to_string(),
    };
    fs::write(&path, manifest)?;
    Ok(path)
}

fn write_network_release_manifest(state: &mut LinuxState) -> Result<PathBuf> {
    let path = state.base_dir.join("firewall").join("release.sh");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let manifest = match state.firewall_backend {
        Some(LinuxFirewallBackend::Nftables) => "delete table inet aegis_isolation\n".to_string(),
        Some(LinuxFirewallBackend::Iptables) => [
            "iptables -D OUTPUT -j AEGIS-ISOLATION 2>/dev/null || true",
            "iptables -F AEGIS-ISOLATION 2>/dev/null || true",
            "iptables -X AEGIS-ISOLATION 2>/dev/null || true",
            "",
        ]
        .join("\n"),
        None => "# no firewall backend detected\n".to_string(),
    };
    fs::write(&path, manifest)?;
    Ok(path)
}

fn build_nft_manifest(rules: &IsolationRulesV2) -> String {
    let mut lines = vec![
        "table inet aegis_isolation {".to_string(),
        "  chain output {".to_string(),
        "    type filter hook output priority 0; policy drop;".to_string(),
        "    ct state established,related accept".to_string(),
        "    oifname \"lo\" accept".to_string(),
    ];
    for ip in &rules.allowed_control_plane_ips {
        if ip.contains(':') {
            lines.push(format!("    ip6 daddr {ip} accept"));
        } else {
            lines.push(format!("    ip daddr {ip} accept"));
        }
    }
    lines.push("  }".to_string());
    lines.push("}".to_string());
    lines.push(String::new());
    lines.join("\n")
}

fn build_iptables_manifest(rules: &IsolationRulesV2) -> String {
    let mut lines = vec![
        "iptables -N AEGIS-ISOLATION 2>/dev/null || true".to_string(),
        "iptables -F AEGIS-ISOLATION".to_string(),
        "iptables -A AEGIS-ISOLATION -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
            .to_string(),
        "iptables -A AEGIS-ISOLATION -o lo -j ACCEPT".to_string(),
    ];
    for ip in &rules.allowed_control_plane_ips {
        lines.push(format!("iptables -A AEGIS-ISOLATION -d {ip} -j ACCEPT"));
    }
    lines.push("iptables -A AEGIS-ISOLATION -j DROP".to_string());
    lines.push("iptables -C OUTPUT -j AEGIS-ISOLATION 2>/dev/null || iptables -I OUTPUT 1 -j AEGIS-ISOLATION".to_string());
    lines.push(String::new());
    lines.join("\n")
}

fn apply_firewall_manifest(
    backend: Option<LinuxFirewallBackend>,
    manifest_path: &Path,
) -> Result<()> {
    match backend {
        Some(LinuxFirewallBackend::Nftables) => {
            run_command_status("nft", ["-f"], Some(manifest_path))
        }
        Some(LinuxFirewallBackend::Iptables) => run_command_status("sh", [], Some(manifest_path)),
        None => Ok(()),
    }
}

fn release_firewall_manifest(
    backend: Option<LinuxFirewallBackend>,
    manifest_path: &Path,
) -> Result<()> {
    match backend {
        Some(LinuxFirewallBackend::Nftables) => {
            run_command_status("nft", ["-f"], Some(manifest_path))
        }
        Some(LinuxFirewallBackend::Iptables) => run_command_status("sh", [], Some(manifest_path)),
        None => Ok(()),
    }
}

fn run_command_status<const N: usize>(
    program: &str,
    args: [&str; N],
    file_argument: Option<&Path>,
) -> Result<()> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(path) = file_argument {
        command.arg(path);
    }
    let status = command
        .status()
        .with_context(|| format!("spawn command `{program}`"))?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("command `{program}` exited with status {status}");
    }
}

fn should_apply_firewall() -> bool {
    std::env::var_os("AEGIS_LINUX_APPLY_FIREWALL")
        .map(|value| value == "1")
        .unwrap_or(false)
}

fn send_signal(pid: u32, signal: &str) -> Result<()> {
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .status()
        .context("spawn kill command")?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("kill -{signal} {pid} exited with status {status}");
    }
}

fn candidate_auth_log_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/var/log/auth.log"),
        PathBuf::from("/var/log/secure"),
    ]
}

fn apparmor_enabled(lsm_stack: &[String]) -> bool {
    if lsm_stack.iter().any(|entry| entry == "apparmor") {
        return true;
    }
    read_string("/sys/module/apparmor/parameters/enabled")
        .map(|value| value.trim().eq_ignore_ascii_case("y"))
        .unwrap_or(false)
}

fn command_exists(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|path| path.join(name).exists()))
        .unwrap_or(false)
}

fn read_string(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn path_exists(path: impl AsRef<Path>) -> bool {
    path.as_ref().exists()
}

fn write_text_file(path: PathBuf, content: String) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)?;
    Ok(())
}

fn write_optional_snapshot(path: PathBuf, content: Option<String>) -> Result<()> {
    if let Some(content) = content {
        write_text_file(path, content)?;
    }
    Ok(())
}

fn run_command_capture<const N: usize>(program: &str, args: [&str; N]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        None
    } else {
        Some(stdout)
    }
}

fn truncate_subject(value: &str) -> String {
    const LIMIT: usize = 240;
    if value.len() <= LIMIT {
        value.to_string()
    } else {
        format!("{}...", &value[..LIMIT.saturating_sub(3)])
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

#[allow(dead_code)]
fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::{
        LinuxDegradeLevel, LinuxEventStub, LinuxHostCapabilities, LinuxPlatform, LinuxProviderKind,
    };
    use crate::{
        KernelIntegrity, PlatformProtection, PlatformResponse, PlatformRuntime, PlatformSensor,
        PreemptiveBlock,
    };
    use aegis_model::{
        EventBuffer, ForensicSpec, IsolationRulesV2, NetworkTarget, RollbackTarget, SensorConfig,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;
    use uuid::Uuid;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("aegis-linux-test-{name}-{}", Uuid::now_v7()))
    }

    fn write_ebpf_manifest(root: &PathBuf, body: &str) {
        fs::create_dir_all(root).expect("create ebpf assets root");
        fs::write(root.join("manifest.json"), body).expect("write ebpf manifest");
    }

    fn full_capabilities() -> LinuxHostCapabilities {
        LinuxHostCapabilities {
            running_on_linux: true,
            has_bpf_fs: true,
            has_btf: true,
            has_bpftool: true,
            has_fanotify: true,
            has_auth_log: true,
            has_journalctl: true,
            has_nft: true,
            has_iptables: true,
            has_apparmor: true,
            has_tpm: true,
            has_container_metadata: true,
            lsm_stack: vec![
                "lockdown".to_string(),
                "apparmor".to_string(),
                "ima".to_string(),
            ],
        }
    }

    #[test]
    fn linux_baseline_registers_required_providers() {
        let platform = LinuxPlatform::default();
        let providers = platform.provider_kinds();

        assert!(providers.contains(&LinuxProviderKind::ProcessEbpf));
        assert!(providers.contains(&LinuxProviderKind::ContainerMetadata));
        assert!(providers.contains(&LinuxProviderKind::FanotifyFallback));
        assert_eq!(providers.len(), 7);
    }

    #[test]
    fn linux_capability_probe_maps_full_stack_to_full_degrade() {
        let capabilities = full_capabilities();
        let mut platform = LinuxPlatform::with_host_capabilities_for_test(capabilities);
        platform
            .start(&SensorConfig {
                profile: "linux".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: false,
            })
            .expect("start linux baseline");

        let descriptor = platform.descriptor();
        let snapshot = platform.health_snapshot();

        assert_eq!(descriptor.degrade_levels, 4);
        assert_eq!(platform.degrade_level(), LinuxDegradeLevel::Full);
        assert_eq!(
            snapshot.provider_health.get("ProcessEbpf").copied(),
            Some(true)
        );
        assert_eq!(
            snapshot.provider_health.get("ContainerMetadata").copied(),
            Some(true)
        );
    }

    #[test]
    fn linux_baseline_supports_four_degrade_levels() {
        let mut platform = LinuxPlatform::with_host_capabilities_for_test(full_capabilities());
        platform
            .start(&SensorConfig {
                profile: "linux".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: false,
            })
            .expect("start linux baseline");
        platform.set_degrade_level(LinuxDegradeLevel::FanotifyAudit);
        let snapshot = platform.health_snapshot();

        assert_eq!(platform.degrade_level(), LinuxDegradeLevel::FanotifyAudit);
        assert_eq!(
            snapshot.provider_health.get("FanotifyFallback").copied(),
            Some(true)
        );
        assert_eq!(
            snapshot.provider_health.get("FileEbpf").copied(),
            Some(false)
        );
    }

    #[test]
    fn linux_baseline_polls_container_aware_events() {
        let mut platform = LinuxPlatform::with_host_capabilities_for_test(full_capabilities());
        platform
            .start(&SensorConfig {
                profile: "linux".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: false,
            })
            .expect("start linux baseline");
        platform.inject_event(LinuxEventStub {
            provider: LinuxProviderKind::ContainerMetadata,
            operation: "container-exec".to_string(),
            subject: "/bin/sh".to_string(),
            container_id: Some("container-1".to_string()),
        });

        let mut buffer = EventBuffer::default();
        let drained = platform.poll_events(&mut buffer).expect("poll events");

        assert!(drained >= 1);
        assert_eq!(buffer.records.len(), drained);
        assert!(buffer
            .records
            .iter()
            .map(|record| String::from_utf8_lossy(record))
            .any(|record| record.contains("container-1")));
    }

    #[test]
    fn linux_execution_snapshot_tracks_isolation_blocks_and_forensics() {
        let platform = LinuxPlatform::with_host_capabilities_for_test(full_capabilities());
        platform
            .protect_process(4321)
            .expect("protect process should record");
        platform
            .protect_files(&[PathBuf::from("/tmp/payload.sh")])
            .expect("protect files should record");

        let original = temp_path("payload.sh");
        fs::write(&original, b"malware").expect("write payload");
        let receipt = platform
            .quarantine_file(&original)
            .expect("quarantine should materialize receipt");
        let bundle = platform
            .collect_forensics(&ForensicSpec {
                include_memory: true,
                include_registry: false,
                include_network: true,
            })
            .expect("collect forensics should materialize bundle");
        platform
            .registry_rollback(&RollbackTarget {
                selector: "iptables".to_string(),
            })
            .expect("rollback should record selector");
        platform
            .network_isolate(&IsolationRulesV2 {
                ttl: Duration::from_secs(120),
                allowed_control_plane_ips: vec!["10.0.0.10".to_string()],
            })
            .expect("network isolate");
        platform
            .block_network(
                &NetworkTarget {
                    value: "10.0.0.99:443".to_string(),
                },
                Duration::from_secs(120),
            )
            .expect("block network");

        let snapshot = platform.execution_snapshot();
        assert_eq!(snapshot.protected_pids, vec![4321]);
        assert_eq!(
            snapshot.protected_paths,
            vec![PathBuf::from("/tmp/payload.sh")]
        );
        assert_eq!(snapshot.quarantined_files.len(), 1);
        assert_eq!(snapshot.quarantined_files[0], receipt);
        assert!(snapshot.quarantined_files[0].vault_path.exists());
        assert_eq!(snapshot.forensic_artifacts.len(), 1);
        assert_eq!(snapshot.forensic_artifacts[0], bundle);
        assert!(snapshot.forensic_artifacts[0].location.exists());
        assert_eq!(snapshot.rollback_targets[0].selector, "iptables");
        assert!(snapshot.network_isolation_active);
        assert_eq!(
            snapshot
                .active_blocks
                .iter()
                .find(|lease| lease.kind == "network")
                .map(|lease| lease.target.as_str()),
            Some("10.0.0.99:443")
        );

        platform
            .network_release()
            .expect("release network isolation");
        assert!(!platform.execution_snapshot().network_isolation_active);
    }

    #[test]
    fn linux_kernel_runtime_discovers_manifest_and_plans_bundles() {
        let assets_root = temp_path("ebpf-assets");
        let pin_root = temp_path("bpffs");
        write_ebpf_manifest(
            &assets_root,
            r#"{
  "schema_version": 1,
  "bundles": [
    { "name": "process", "object": "process.bpf.o", "pin_subdir": "process", "modes": ["full", "tracepoint_only"] },
    { "name": "network", "object": "network.bpf.o", "pin_subdir": "network", "modes": ["full"] },
    { "name": "auth", "object": "auth.bpf.o", "pin_subdir": "auth", "modes": ["fanotify_audit"] }
  ]
}"#,
        );
        fs::write(assets_root.join("process.bpf.o"), b"process").expect("write process bundle");
        fs::write(assets_root.join("network.bpf.o"), b"network").expect("write network bundle");
        fs::write(assets_root.join("auth.bpf.o"), b"auth").expect("write auth bundle");

        let mut platform = LinuxPlatform::with_host_capabilities_for_test(full_capabilities());
        platform.configure_kernel_runtime_for_test(
            Some(assets_root.clone()),
            Some(pin_root.clone()),
            false,
            false,
        );
        platform
            .start(&SensorConfig {
                profile: "linux".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: false,
            })
            .expect("start linux baseline");

        let kernel = platform.kernel_runtime_snapshot_for_test();
        assert_eq!(kernel.assets_root, Some(assets_root.clone()));
        assert_eq!(
            kernel.manifest_path,
            Some(assets_root.join("manifest.json"))
        );
        assert_eq!(kernel.pin_root, pin_root);
        assert_eq!(kernel.planned_bundles.len(), 2);
        assert_eq!(kernel.planned_attachments.len(), 0);
        assert!(kernel
            .planned_bundles
            .iter()
            .any(|bundle| bundle.name == "process"));
        assert!(kernel
            .planned_bundles
            .iter()
            .any(|bundle| bundle.name == "network"));
        assert!(kernel.loaded_bundles.is_empty());
    }

    #[test]
    fn linux_kernel_runtime_detects_preexisting_pinned_bundle() {
        let assets_root = temp_path("ebpf-assets-loaded");
        let pin_root = temp_path("bpffs-loaded");
        write_ebpf_manifest(
            &assets_root,
            r#"{
  "schema_version": 1,
  "bundles": [
    { "name": "process", "object": "process.bpf.o", "pin_subdir": "process", "modes": ["full"] }
  ]
}"#,
        );
        fs::write(assets_root.join("process.bpf.o"), b"process").expect("write process bundle");
        fs::create_dir_all(pin_root.join("process")).expect("create pin dir");
        fs::write(pin_root.join("process/program"), b"pinned").expect("write pin marker");

        let mut platform = LinuxPlatform::with_host_capabilities_for_test(full_capabilities());
        platform.configure_kernel_runtime_for_test(
            Some(assets_root.clone()),
            Some(pin_root.clone()),
            false,
            false,
        );
        platform
            .start(&SensorConfig {
                profile: "linux".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: false,
            })
            .expect("start linux baseline");

        let kernel = platform.kernel_runtime_snapshot_for_test();
        assert_eq!(kernel.loaded_bundles, vec!["process".to_string()]);
        assert!(
            platform
                .check_bpf_integrity()
                .expect("bpf integrity should report")
                .healthy
        );
        assert!(
            platform
                .check_kernel_code()
                .expect("kernel integrity should report")
                .passed
        );
    }

    #[test]
    fn linux_kernel_code_integrity_reports_missing_bpf_stack() {
        let capabilities = LinuxHostCapabilities {
            running_on_linux: true,
            has_bpf_fs: false,
            has_btf: false,
            has_bpftool: false,
            has_fanotify: true,
            has_auth_log: true,
            has_journalctl: false,
            has_nft: false,
            has_iptables: true,
            has_apparmor: false,
            has_tpm: false,
            has_container_metadata: true,
            lsm_stack: vec!["lockdown".to_string()],
        };
        let platform = LinuxPlatform::with_host_capabilities_for_test(capabilities);
        let report = platform
            .check_kernel_code()
            .expect("kernel code integrity should report");
        let bpf = platform
            .check_bpf_integrity()
            .expect("bpf integrity status should report");

        assert!(!report.passed);
        assert!(report.details.contains("missing=bpffs,btf,bpftool"));
        assert!(!bpf.healthy);
    }

    #[test]
    fn linux_kernel_code_integrity_reports_missing_ebpf_assets_on_ready_host() {
        let assets_root = temp_path("missing-ebpf-assets");
        let pin_root = temp_path("missing-ebpf-pins");
        let mut platform = LinuxPlatform::with_host_capabilities_for_test(full_capabilities());
        platform.configure_kernel_runtime_for_test(
            Some(assets_root.clone()),
            Some(pin_root),
            false,
            false,
        );
        platform
            .start(&SensorConfig {
                profile: "linux".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: false,
            })
            .expect("start linux baseline");

        let report = platform
            .check_kernel_code()
            .expect("kernel code integrity should report");
        let kernel = platform.kernel_runtime_snapshot_for_test();

        assert!(!report.passed);
        assert!(report.details.contains("ebpf-assets"));
        assert!(kernel.last_error.is_some());
    }

    #[test]
    fn linux_kernel_runtime_detects_preexisting_attached_link() {
        let assets_root = temp_path("ebpf-assets-linked");
        let pin_root = temp_path("bpffs-linked");
        write_ebpf_manifest(
            &assets_root,
            r#"{
  "schema_version": 1,
  "bundles": [
    {
      "name": "process",
      "object": "process.bpf.o",
      "pin_subdir": "process",
      "auto_attach": true,
      "modes": ["full"],
      "attachments": [
        {
          "name": "aegis_sched_exec",
          "kind": "tracepoint",
          "target": "sched/sched_process_exec",
          "link_pin": "aegis_sched_exec"
        }
      ]
    }
  ]
}"#,
        );
        fs::write(assets_root.join("process.bpf.o"), b"process").expect("write process bundle");
        fs::create_dir_all(pin_root.join("process")).expect("create pin dir");
        fs::write(pin_root.join("process/aegis_sched_exec"), b"link").expect("write link pin");

        let mut platform = LinuxPlatform::with_host_capabilities_for_test(full_capabilities());
        platform.configure_kernel_runtime_for_test(Some(assets_root), Some(pin_root), false, true);
        platform
            .start(&SensorConfig {
                profile: "linux".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: false,
            })
            .expect("start linux baseline");

        let kernel = platform.kernel_runtime_snapshot_for_test();
        assert_eq!(kernel.loaded_bundles, vec!["process".to_string()]);
        assert_eq!(
            kernel.attached_links,
            vec!["process:aegis_sched_exec".to_string()]
        );
        assert!(
            platform
                .check_bpf_integrity()
                .expect("bpf integrity should report")
                .healthy
        );
    }

    #[test]
    fn linux_kernel_code_integrity_reports_missing_links_when_attach_requested() {
        let assets_root = temp_path("ebpf-assets-unattached");
        let pin_root = temp_path("bpffs-unattached");
        write_ebpf_manifest(
            &assets_root,
            r#"{
  "schema_version": 1,
  "bundles": [
    {
      "name": "process",
      "object": "process.bpf.o",
      "pin_subdir": "process",
      "auto_attach": true,
      "modes": ["full"],
      "attachments": [
        {
          "name": "aegis_sched_exec",
          "kind": "tracepoint",
          "target": "sched/sched_process_exec",
          "link_pin": "aegis_sched_exec"
        }
      ]
    }
  ]
}"#,
        );
        fs::write(assets_root.join("process.bpf.o"), b"process").expect("write process bundle");
        fs::create_dir_all(pin_root.join("process")).expect("create pin dir");

        let mut platform = LinuxPlatform::with_host_capabilities_for_test(full_capabilities());
        platform.configure_kernel_runtime_for_test(Some(assets_root), Some(pin_root), false, true);
        platform
            .start(&SensorConfig {
                profile: "linux".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: false,
            })
            .expect("start linux baseline");

        let report = platform
            .check_kernel_code()
            .expect("kernel code integrity should report");
        let kernel = platform.kernel_runtime_snapshot_for_test();

        assert!(!report.passed);
        assert!(report
            .details
            .contains("unattached=process:aegis_sched_exec"));
        assert!(kernel
            .last_error
            .as_deref()
            .unwrap_or_default()
            .contains("missing auto-attached link"));
    }
}
