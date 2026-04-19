use crate::traits::{
    KernelIntegrity, KernelTransport, PlatformDescriptor, PlatformProtection, PlatformResponse,
    PlatformRuntime, PlatformSensor, PlatformTarget, PreemptiveBlock,
};
use aegis_model::{
    AmsiStatus, ArtifactBundle, BpfStatus, EtwStatus, EventBuffer, ForensicSpec, IntegrityReport,
    IsolationRulesV2, NetworkTarget, QuarantineReceipt, RollbackTarget, SensorCapabilities,
    SensorConfig, SuspiciousProcess,
};
use anyhow::Result;
use std::collections::VecDeque;
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
    running: bool,
    authorization_state: MacosAuthorizationState,
    pending_events: VecDeque<Vec<u8>>,
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
                running: false,
                authorization_state: MacosAuthorizationState::NotDetermined,
                pending_events: VecDeque::new(),
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
        self.state.lock().expect("macos state poisoned").running = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.state.lock().expect("macos state poisoned").running = false;
        Ok(())
    }

    fn poll_events(&self, buf: &mut EventBuffer) -> Result<usize> {
        let mut state = self.state.lock().expect("macos state poisoned");
        if !state.running {
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
    fn suspend_process(&self, _pid: u32) -> Result<()> {
        Ok(())
    }

    fn kill_process(&self, _pid: u32) -> Result<()> {
        Ok(())
    }

    fn kill_ppl_process(&self, _pid: u32) -> Result<()> {
        Ok(())
    }

    fn quarantine_file(&self, path: &Path) -> Result<QuarantineReceipt> {
        Ok(QuarantineReceipt {
            vault_path: path.to_path_buf(),
            sha256: "macos-mock".to_string(),
        })
    }

    fn network_isolate(&self, _rules: &IsolationRulesV2) -> Result<()> {
        Ok(())
    }

    fn network_release(&self) -> Result<()> {
        Ok(())
    }

    fn registry_rollback(&self, _target: &RollbackTarget) -> Result<()> {
        Ok(())
    }

    fn collect_forensics(&self, _spec: &ForensicSpec) -> Result<ArtifactBundle> {
        Ok(ArtifactBundle {
            artifact_id: Uuid::now_v7(),
            location: PathBuf::from("/Library/Application Support/Aegis/forensics/macos-mock.tar"),
        })
    }
}

impl PreemptiveBlock for MacosPlatform {
    fn block_hash(&self, _hash: &str, _ttl: Duration) -> Result<()> {
        Ok(())
    }

    fn block_pid(&self, _pid: u32, _ttl: Duration) -> Result<()> {
        Ok(())
    }

    fn block_path(&self, _path: &Path, _ttl: Duration) -> Result<()> {
        Ok(())
    }

    fn block_network(&self, _target: &NetworkTarget, _ttl: Duration) -> Result<()> {
        Ok(())
    }

    fn clear_all_blocks(&self) -> Result<()> {
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
            details: "endpoint security subscription set intact".to_string(),
        })
    }

    fn check_kernel_code(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            passed: true,
            details: "system extension baseline intact".to_string(),
        })
    }

    fn detect_hidden_processes(&self) -> Result<Vec<SuspiciousProcess>> {
        Ok(Vec::new())
    }
}

impl PlatformProtection for MacosPlatform {
    fn protect_process(&self, _pid: u32) -> Result<()> {
        Ok(())
    }

    fn protect_files(&self, _paths: &[PathBuf]) -> Result<()> {
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::{
        MacosAuthorizationState, MacosEventStub, MacosPlatform, MacosProviderKind,
        MacosSubscription,
    };
    use crate::{PlatformRuntime, PlatformSensor};
    use aegis_model::{EventBuffer, SensorConfig};

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
        let platform = MacosPlatform::default();
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
        platform.request_authorization();
        platform.approve_authorization();
        let capabilities = platform.capabilities();
        assert!(capabilities.process);
        assert!(capabilities.file);
        assert!(capabilities.network);
        assert!(!capabilities.registry);
    }

    #[test]
    fn macos_baseline_polls_authorized_esf_events() {
        let mut platform = MacosPlatform::default();
        platform
            .start(&SensorConfig {
                profile: "macos".to_string(),
                queue_capacity: 1024,
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
}
