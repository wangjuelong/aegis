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
use anyhow::{bail, Result};
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacosProviderKind {
    EndpointSecurityProcess,
    EndpointSecurityFile,
    NetworkExtensionFlow,
    SystemExtensionHealth,
    TccAuthorization,
    ExecPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacosSubscription {
    Exec,
    Fork,
    Exit,
    Open,
    Rename,
    Connect,
    DnsQuery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacosAuthorizationState {
    NotDetermined,
    AwaitingUserApproval,
    Approved,
    Denied,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacosEventStub {
    pub provider: MacosProviderKind,
    pub subscription: MacosSubscription,
    pub operation: String,
    pub subject: String,
    pub authorization_state: MacosAuthorizationState,
}

impl MacosEventStub {
    fn encode(&self) -> Vec<u8> {
        format!(
            "macos|{:?}|{:?}|{}|{}|{:?}",
            self.provider,
            self.subscription,
            self.operation,
            self.subject,
            self.authorization_state
        )
        .into_bytes()
    }
}

struct MacosState {
    base_dir: PathBuf,
    authorization_state: MacosAuthorizationState,
    pending_events: VecDeque<Vec<u8>>,
    execution: PlatformExecutionSnapshot,
}

pub struct MacosPlatform {
    providers: Vec<MacosProviderKind>,
    subscriptions: Vec<MacosSubscription>,
    state: Mutex<MacosState>,
}

impl Default for MacosPlatform {
    fn default() -> Self {
        Self {
            providers: vec![
                MacosProviderKind::EndpointSecurityProcess,
                MacosProviderKind::EndpointSecurityFile,
                MacosProviderKind::NetworkExtensionFlow,
                MacosProviderKind::SystemExtensionHealth,
                MacosProviderKind::TccAuthorization,
                MacosProviderKind::ExecPolicy,
            ],
            subscriptions: vec![
                MacosSubscription::Exec,
                MacosSubscription::Fork,
                MacosSubscription::Exit,
                MacosSubscription::Open,
                MacosSubscription::Rename,
                MacosSubscription::Connect,
                MacosSubscription::DnsQuery,
            ],
            state: Mutex::new(MacosState {
                base_dir: platform_root("macos"),
                authorization_state: MacosAuthorizationState::NotDetermined,
                pending_events: VecDeque::new(),
                execution: PlatformExecutionSnapshot::default(),
            }),
        }
    }
}

impl MacosPlatform {
    pub fn provider_kinds(&self) -> &[MacosProviderKind] {
        &self.providers
    }

    pub fn subscriptions(&self) -> &[MacosSubscription] {
        &self.subscriptions
    }

    pub fn execution_snapshot(&self) -> PlatformExecutionSnapshot {
        self.state
            .lock()
            .expect("macos state poisoned")
            .execution
            .clone()
    }

    pub fn health_snapshot(&self) -> PlatformHealthSnapshot {
        let state = self.state.lock().expect("macos state poisoned");
        let running = state.execution.running;
        let authorization_state = state.authorization_state;
        let provider_health = self
            .providers
            .iter()
            .map(|provider| {
                let healthy = match provider {
                    MacosProviderKind::EndpointSecurityProcess
                    | MacosProviderKind::EndpointSecurityFile => {
                        running && authorization_state == MacosAuthorizationState::Approved
                    }
                    MacosProviderKind::NetworkExtensionFlow
                    | MacosProviderKind::SystemExtensionHealth
                    | MacosProviderKind::TccAuthorization
                    | MacosProviderKind::ExecPolicy => running,
                };
                (format!("{provider:?}"), healthy)
            })
            .collect();

        PlatformHealthSnapshot {
            provider_health,
            integrity_reports: BTreeMap::from([
                (
                    "ssdt".to_string(),
                    IntegrityReport {
                        passed: true,
                        details: "n/a for macos".to_string(),
                    },
                ),
                (
                    "callbacks".to_string(),
                    IntegrityReport {
                        passed: true,
                        details: "system extension callback chain intact".to_string(),
                    },
                ),
                (
                    "kernel_code".to_string(),
                    IntegrityReport {
                        passed: true,
                        details: "endpoint security entitlement chain intact".to_string(),
                    },
                ),
                (
                    "platform_protection".to_string(),
                    IntegrityReport {
                        passed: authorization_state != MacosAuthorizationState::Denied,
                        details: format!("macos authorization state = {authorization_state:?}"),
                    },
                ),
            ]),
        }
    }

    pub fn authorization_state(&self) -> MacosAuthorizationState {
        self.state
            .lock()
            .expect("macos state poisoned")
            .authorization_state
    }

    pub fn request_authorization(&self) -> MacosAuthorizationState {
        let mut state = self.state.lock().expect("macos state poisoned");
        if state.authorization_state == MacosAuthorizationState::NotDetermined {
            state.authorization_state = MacosAuthorizationState::AwaitingUserApproval;
        }
        state.authorization_state
    }

    pub fn approve_authorization(&self) -> MacosAuthorizationState {
        let mut state = self.state.lock().expect("macos state poisoned");
        if state.authorization_state == MacosAuthorizationState::AwaitingUserApproval {
            state.authorization_state = MacosAuthorizationState::Approved;
        }
        state.authorization_state
    }

    pub fn deny_authorization(&self) -> MacosAuthorizationState {
        let mut state = self.state.lock().expect("macos state poisoned");
        if matches!(
            state.authorization_state,
            MacosAuthorizationState::NotDetermined | MacosAuthorizationState::AwaitingUserApproval
        ) {
            state.authorization_state = MacosAuthorizationState::Denied;
        }
        state.authorization_state
    }

    pub fn inject_event(&self, event: MacosEventStub) {
        self.state
            .lock()
            .expect("macos state poisoned")
            .pending_events
            .push_back(event.encode());
    }
}

impl PlatformSensor for MacosPlatform {
    fn start(&mut self, _config: &SensorConfig) -> Result<()> {
        self.request_authorization();
        self.state
            .lock()
            .expect("macos state poisoned")
            .execution
            .running = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.state
            .lock()
            .expect("macos state poisoned")
            .execution
            .running = false;
        Ok(())
    }

    fn poll_events(&self, buf: &mut EventBuffer) -> Result<usize> {
        let mut state = self.state.lock().expect("macos state poisoned");
        if !state.execution.running {
            return Ok(0);
        }

        let mut drained = 0usize;
        while let Some(event) = state.pending_events.pop_front() {
            buf.records.push(event);
            drained += 1;
        }
        Ok(drained)
    }

    fn capabilities(&self) -> SensorCapabilities {
        let authorized = self.authorization_state() == MacosAuthorizationState::Approved;
        SensorCapabilities {
            process: authorized,
            file: authorized,
            network: true,
            registry: false,
            auth: true,
            script: false,
            memory: false,
            container: false,
        }
    }
}

impl PlatformResponse for MacosPlatform {
    fn suspend_process(&self, pid: u32) -> Result<()> {
        self.state
            .lock()
            .expect("macos state poisoned")
            .execution
            .suspended_pids
            .push(pid);
        Ok(())
    }

    fn kill_process(&self, pid: u32) -> Result<()> {
        self.state
            .lock()
            .expect("macos state poisoned")
            .execution
            .terminated_pids
            .push(pid);
        Ok(())
    }

    fn kill_ppl_process(&self, pid: u32) -> Result<()> {
        self.state
            .lock()
            .expect("macos state poisoned")
            .execution
            .terminated_protected_pids
            .push(pid);
        Ok(())
    }

    fn quarantine_file(&self, path: &Path) -> Result<QuarantineReceipt> {
        let mut state = self.state.lock().expect("macos state poisoned");
        let receipt = materialize_quarantine(&mut state, path, "macos-quarantine")?;
        state.execution.quarantined_files.push(receipt.clone());
        Ok(receipt)
    }

    fn network_isolate(&self, rules: &IsolationRulesV2) -> Result<()> {
        let mut state = self.state.lock().expect("macos state poisoned");
        state.execution.network_isolation_active = true;
        state.execution.last_isolation_rules = Some(rules.clone());
        Ok(())
    }

    fn network_release(&self) -> Result<()> {
        self.state
            .lock()
            .expect("macos state poisoned")
            .execution
            .network_isolation_active = false;
        Ok(())
    }

    fn registry_rollback(&self, target: &RollbackTarget) -> Result<()> {
        self.state
            .lock()
            .expect("macos state poisoned")
            .execution
            .rollback_targets
            .push(target.clone());
        Ok(())
    }

    fn collect_forensics(&self, spec: &ForensicSpec) -> Result<ArtifactBundle> {
        let mut state = self.state.lock().expect("macos state poisoned");
        let bundle = materialize_artifact(&mut state, spec, "tar", "macos-forensics")?;
        state.execution.forensic_artifacts.push(bundle.clone());
        Ok(bundle)
    }
}

impl PreemptiveBlock for MacosPlatform {
    fn block_hash(&self, hash: &str, ttl: Duration) -> Result<()> {
        push_block(
            &mut self.state.lock().expect("macos state poisoned").execution,
            "hash",
            hash.to_string(),
            ttl,
        );
        Ok(())
    }

    fn block_pid(&self, pid: u32, ttl: Duration) -> Result<()> {
        push_block(
            &mut self.state.lock().expect("macos state poisoned").execution,
            "pid",
            pid.to_string(),
            ttl,
        );
        Ok(())
    }

    fn block_path(&self, path: &Path, ttl: Duration) -> Result<()> {
        push_block(
            &mut self.state.lock().expect("macos state poisoned").execution,
            "path",
            path.display().to_string(),
            ttl,
        );
        Ok(())
    }

    fn block_network(&self, target: &NetworkTarget, ttl: Duration) -> Result<()> {
        push_block(
            &mut self.state.lock().expect("macos state poisoned").execution,
            "network",
            target.value.clone(),
            ttl,
        );
        Ok(())
    }

    fn clear_all_blocks(&self) -> Result<()> {
        self.state
            .lock()
            .expect("macos state poisoned")
            .execution
            .active_blocks
            .clear();
        Ok(())
    }
}

impl KernelIntegrity for MacosPlatform {
    fn check_ssdt_integrity(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            passed: true,
            details: "n/a for macos".to_string(),
        })
    }

    fn check_callback_tables(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            passed: true,
            details: "system extension callback chain intact".to_string(),
        })
    }

    fn check_kernel_code(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            passed: true,
            details: "endpoint security entitlement chain intact".to_string(),
        })
    }

    fn detect_hidden_processes(&self) -> Result<Vec<SuspiciousProcess>> {
        Ok(Vec::new())
    }
}

impl PlatformProtection for MacosPlatform {
    fn protect_process(&self, pid: u32) -> Result<()> {
        self.state
            .lock()
            .expect("macos state poisoned")
            .execution
            .protected_pids
            .push(pid);
        Ok(())
    }

    fn protect_files(&self, paths: &[PathBuf]) -> Result<()> {
        self.state
            .lock()
            .expect("macos state poisoned")
            .execution
            .protected_paths
            .extend(paths.iter().cloned());
        Ok(())
    }

    fn protect_registry(&self, _selectors: &[String]) -> Result<()> {
        bail!("registry protection is unavailable on macos")
    }

    fn verify_integrity(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            passed: true,
            details: "macos baseline entitlements intact".to_string(),
        })
    }

    fn check_etw_integrity(&self) -> Result<EtwStatus> {
        Ok(EtwStatus { healthy: false })
    }

    fn check_amsi_integrity(&self) -> Result<AmsiStatus> {
        Ok(AmsiStatus { healthy: false })
    }

    fn check_bpf_integrity(&self) -> Result<BpfStatus> {
        Ok(BpfStatus { healthy: false })
    }
}

impl PlatformRuntime for MacosPlatform {
    fn descriptor(&self) -> PlatformDescriptor {
        PlatformDescriptor {
            target: PlatformTarget::Macos,
            kernel_transport: KernelTransport::SystemExtension,
            degrade_levels: 1,
            supports_registry: false,
            supports_amsi: false,
            supports_etw_integrity: false,
            supports_bpf_integrity: false,
            supports_container_sensor: false,
        }
    }
}

fn platform_root(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("aegis-{prefix}-{}", Uuid::now_v7().simple()))
}

fn materialize_quarantine(
    state: &mut MacosState,
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
        sha256: format!("macos:{}", original.display()),
    })
}

fn materialize_artifact(
    state: &mut MacosState,
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
        MacosAuthorizationState, MacosEventStub, MacosPlatform, MacosProviderKind,
        MacosSubscription,
    };
    use crate::{
        PlatformProtection, PlatformResponse, PlatformRuntime, PlatformSensor, PreemptiveBlock,
    };
    use aegis_model::{EventBuffer, ForensicSpec, IsolationRulesV2, SensorConfig};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    #[test]
    fn macos_baseline_tracks_authorization_state_machine() {
        let platform = MacosPlatform::default();

        assert_eq!(
            platform.authorization_state(),
            MacosAuthorizationState::NotDetermined
        );
        assert_eq!(
            platform.request_authorization(),
            MacosAuthorizationState::AwaitingUserApproval
        );
        assert_eq!(
            platform.approve_authorization(),
            MacosAuthorizationState::Approved
        );
    }

    #[test]
    fn macos_descriptor_and_capabilities_match_design() {
        let mut platform = MacosPlatform::default();
        platform
            .start(&SensorConfig {
                profile: "macos".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: false,
            })
            .expect("start macos baseline");
        let descriptor = platform.descriptor();

        assert_eq!(descriptor.target, crate::PlatformTarget::Macos);
        assert_eq!(
            descriptor.kernel_transport,
            crate::KernelTransport::SystemExtension
        );
        assert!(platform
            .provider_kinds()
            .contains(&MacosProviderKind::EndpointSecurityProcess));
        assert!(platform
            .subscriptions()
            .contains(&MacosSubscription::Connect));
        assert!(!platform.capabilities().process);
        platform.approve_authorization();
        let capabilities = platform.capabilities();
        let snapshot = platform.health_snapshot();
        assert!(capabilities.process);
        assert!(capabilities.file);
        assert!(capabilities.network);
        assert!(!capabilities.registry);
        assert_eq!(
            snapshot
                .provider_health
                .get("EndpointSecurityProcess")
                .copied(),
            Some(true)
        );
    }

    #[test]
    fn macos_baseline_polls_authorized_esf_events() {
        let mut platform = MacosPlatform::default();
        platform
            .start(&SensorConfig {
                profile: "macos".to_string(),
                queue_capacity: 1024,
                require_kernel_driver: false,
            })
            .expect("start macos baseline");
        assert_eq!(
            platform.approve_authorization(),
            MacosAuthorizationState::Approved
        );
        platform.inject_event(MacosEventStub {
            provider: MacosProviderKind::EndpointSecurityProcess,
            subscription: MacosSubscription::Exec,
            operation: "exec".to_string(),
            subject: "/usr/bin/osascript".to_string(),
            authorization_state: platform.authorization_state(),
        });

        let mut buffer = EventBuffer::default();
        let drained = platform.poll_events(&mut buffer).expect("poll events");

        assert_eq!(drained, 1);
        assert_eq!(buffer.records.len(), 1);
        let record = String::from_utf8_lossy(&buffer.records[0]);
        assert!(record.contains("osascript"));
        assert!(record.contains("Approved"));
    }

    #[test]
    fn macos_execution_snapshot_tracks_release_and_forensics() {
        let platform = MacosPlatform::default();
        platform
            .protect_process(5150)
            .expect("protect process should record");
        platform
            .protect_files(&[PathBuf::from("/tmp/agent.scpt")])
            .expect("protect files should record");
        let receipt = platform
            .quarantine_file(Path::new("/tmp/agent.scpt"))
            .expect("quarantine should materialize receipt");
        let bundle = platform
            .collect_forensics(&ForensicSpec {
                include_memory: false,
                include_registry: false,
                include_network: true,
            })
            .expect("collect forensics should materialize bundle");
        platform
            .network_isolate(&IsolationRulesV2 {
                ttl: Duration::from_secs(45),
                allowed_control_plane_ips: vec!["10.0.0.5".to_string()],
            })
            .expect("network isolate");
        platform
            .block_pid(5150, Duration::from_secs(45))
            .expect("block pid");

        let isolated = platform.execution_snapshot();
        assert!(isolated.network_isolation_active);
        assert_eq!(isolated.protected_pids, vec![5150]);
        assert_eq!(
            isolated.protected_paths,
            vec![PathBuf::from("/tmp/agent.scpt")]
        );
        assert_eq!(isolated.quarantined_files[0], receipt);
        assert!(isolated.quarantined_files[0].vault_path.exists());
        assert_eq!(isolated.forensic_artifacts[0], bundle);
        assert!(isolated.forensic_artifacts[0].location.exists());
        assert_eq!(
            isolated
                .active_blocks
                .iter()
                .find(|lease| lease.kind == "pid")
                .map(|lease| lease.ttl_secs),
            Some(45)
        );

        platform.network_release().expect("network release");
        assert!(!platform.execution_snapshot().network_isolation_active);
        assert!(
            !platform
                .check_etw_integrity()
                .expect("etw integrity")
                .healthy
        );
    }
}
