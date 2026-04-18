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
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MockAction {
    Start(String),
    Stop,
    SuspendProcess(u32),
    KillProcess(u32),
    KillPplProcess(u32),
    QuarantineFile(PathBuf),
    NetworkIsolate,
    NetworkRelease,
    RegistryRollback(String),
    CollectForensics,
    BlockHash(String),
    BlockPid(u32),
    BlockPath(PathBuf),
    BlockNetwork(String),
    ClearAllBlocks,
    ProtectProcess(u32),
    ProtectFiles(usize),
}

#[derive(Default)]
struct MockState {
    running: bool,
    queued_events: VecDeque<Vec<u8>>,
    hidden_processes: Vec<SuspiciousProcess>,
    actions: Vec<MockAction>,
}

#[derive(Clone)]
pub struct MockPlatform {
    descriptor: PlatformDescriptor,
    state: Arc<Mutex<MockState>>,
}

impl Default for MockPlatform {
    fn default() -> Self {
        Self::new(PlatformDescriptor {
            target: PlatformTarget::Linux,
            kernel_transport: KernelTransport::EBpf,
            degrade_levels: 4,
            supports_registry: false,
            supports_amsi: false,
            supports_etw_integrity: false,
            supports_bpf_integrity: true,
            supports_container_sensor: true,
        })
    }
}

impl MockPlatform {
    pub fn new(descriptor: PlatformDescriptor) -> Self {
        Self {
            descriptor,
            state: Arc::new(Mutex::new(MockState::default())),
        }
    }

    pub fn windows() -> Self {
        Self::new(PlatformDescriptor {
            target: PlatformTarget::Windows,
            kernel_transport: KernelTransport::Driver,
            degrade_levels: 1,
            supports_registry: true,
            supports_amsi: true,
            supports_etw_integrity: true,
            supports_bpf_integrity: false,
            supports_container_sensor: false,
        })
    }

    pub fn linux() -> Self {
        Self::default()
    }

    pub fn macos() -> Self {
        Self::new(PlatformDescriptor {
            target: PlatformTarget::Macos,
            kernel_transport: KernelTransport::SystemExtension,
            degrade_levels: 1,
            supports_registry: false,
            supports_amsi: false,
            supports_etw_integrity: false,
            supports_bpf_integrity: false,
            supports_container_sensor: false,
        })
    }

    pub fn enqueue_event(&self, event: impl Into<Vec<u8>>) {
        let mut state = self.state.lock().expect("mock state poisoned");
        state.queued_events.push_back(event.into());
    }

    pub fn set_hidden_processes(&self, processes: Vec<SuspiciousProcess>) {
        let mut state = self.state.lock().expect("mock state poisoned");
        state.hidden_processes = processes;
    }

    pub fn take_actions(&self) -> Vec<MockAction> {
        let mut state = self.state.lock().expect("mock state poisoned");
        std::mem::take(&mut state.actions)
    }
}

impl PlatformSensor for MockPlatform {
    fn start(&mut self, config: &SensorConfig) -> Result<()> {
        let mut state = self.state.lock().expect("mock state poisoned");
        state.running = true;
        state
            .actions
            .push(MockAction::Start(config.profile.clone()));
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        let mut state = self.state.lock().expect("mock state poisoned");
        state.running = false;
        state.actions.push(MockAction::Stop);
        Ok(())
    }

    fn poll_events(&self, buf: &mut EventBuffer) -> Result<usize> {
        let mut state = self.state.lock().expect("mock state poisoned");
        if !state.running {
            return Ok(0);
        }

        let mut drained = 0usize;
        while let Some(event) = state.queued_events.pop_front() {
            buf.records.push(event);
            drained += 1;
        }
        Ok(drained)
    }

    fn capabilities(&self) -> SensorCapabilities {
        SensorCapabilities {
            process: true,
            file: true,
            network: true,
            registry: self.descriptor.supports_registry,
            auth: true,
            script: self.descriptor.supports_amsi,
            memory: true,
            container: self.descriptor.supports_container_sensor,
        }
    }
}

impl PlatformResponse for MockPlatform {
    fn suspend_process(&self, pid: u32) -> Result<()> {
        self.state
            .lock()
            .expect("mock state poisoned")
            .actions
            .push(MockAction::SuspendProcess(pid));
        Ok(())
    }

    fn kill_process(&self, pid: u32) -> Result<()> {
        self.state
            .lock()
            .expect("mock state poisoned")
            .actions
            .push(MockAction::KillProcess(pid));
        Ok(())
    }

    fn kill_ppl_process(&self, pid: u32) -> Result<()> {
        self.state
            .lock()
            .expect("mock state poisoned")
            .actions
            .push(MockAction::KillPplProcess(pid));
        Ok(())
    }

    fn quarantine_file(&self, path: &Path) -> Result<QuarantineReceipt> {
        self.state
            .lock()
            .expect("mock state poisoned")
            .actions
            .push(MockAction::QuarantineFile(path.to_path_buf()));
        Ok(QuarantineReceipt {
            vault_path: path.to_path_buf(),
            sha256: "mock".to_string(),
        })
    }

    fn network_isolate(&self, _rules: &IsolationRulesV2) -> Result<()> {
        self.state
            .lock()
            .expect("mock state poisoned")
            .actions
            .push(MockAction::NetworkIsolate);
        Ok(())
    }

    fn network_release(&self) -> Result<()> {
        self.state
            .lock()
            .expect("mock state poisoned")
            .actions
            .push(MockAction::NetworkRelease);
        Ok(())
    }

    fn registry_rollback(&self, target: &RollbackTarget) -> Result<()> {
        self.state
            .lock()
            .expect("mock state poisoned")
            .actions
            .push(MockAction::RegistryRollback(target.selector.clone()));
        Ok(())
    }

    fn collect_forensics(&self, _spec: &ForensicSpec) -> Result<ArtifactBundle> {
        self.state
            .lock()
            .expect("mock state poisoned")
            .actions
            .push(MockAction::CollectForensics);
        Ok(ArtifactBundle {
            artifact_id: Uuid::now_v7(),
            location: PathBuf::from("/tmp/mock-artifact"),
        })
    }
}

impl PreemptiveBlock for MockPlatform {
    fn block_hash(&self, hash: &str, _ttl: Duration) -> Result<()> {
        self.state
            .lock()
            .expect("mock state poisoned")
            .actions
            .push(MockAction::BlockHash(hash.to_string()));
        Ok(())
    }

    fn block_pid(&self, pid: u32, _ttl: Duration) -> Result<()> {
        self.state
            .lock()
            .expect("mock state poisoned")
            .actions
            .push(MockAction::BlockPid(pid));
        Ok(())
    }

    fn block_path(&self, path: &Path, _ttl: Duration) -> Result<()> {
        self.state
            .lock()
            .expect("mock state poisoned")
            .actions
            .push(MockAction::BlockPath(path.to_path_buf()));
        Ok(())
    }

    fn block_network(&self, target: &NetworkTarget, _ttl: Duration) -> Result<()> {
        self.state
            .lock()
            .expect("mock state poisoned")
            .actions
            .push(MockAction::BlockNetwork(target.value.clone()));
        Ok(())
    }

    fn clear_all_blocks(&self) -> Result<()> {
        self.state
            .lock()
            .expect("mock state poisoned")
            .actions
            .push(MockAction::ClearAllBlocks);
        Ok(())
    }
}

impl KernelIntegrity for MockPlatform {
    fn check_ssdt_integrity(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            passed: true,
            details: "mock ssdt".to_string(),
        })
    }

    fn check_callback_tables(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            passed: true,
            details: "mock callbacks".to_string(),
        })
    }

    fn check_kernel_code(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            passed: true,
            details: "mock kernel code".to_string(),
        })
    }

    fn detect_hidden_processes(&self) -> Result<Vec<SuspiciousProcess>> {
        Ok(self
            .state
            .lock()
            .expect("mock state poisoned")
            .hidden_processes
            .clone())
    }
}

impl PlatformProtection for MockPlatform {
    fn protect_process(&self, pid: u32) -> Result<()> {
        self.state
            .lock()
            .expect("mock state poisoned")
            .actions
            .push(MockAction::ProtectProcess(pid));
        Ok(())
    }

    fn protect_files(&self, paths: &[PathBuf]) -> Result<()> {
        self.state
            .lock()
            .expect("mock state poisoned")
            .actions
            .push(MockAction::ProtectFiles(paths.len()));
        Ok(())
    }

    fn verify_integrity(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            passed: true,
            details: "mock protection".to_string(),
        })
    }

    fn check_etw_integrity(&self) -> Result<EtwStatus> {
        Ok(EtwStatus {
            healthy: self.descriptor.supports_etw_integrity,
        })
    }

    fn check_amsi_integrity(&self) -> Result<AmsiStatus> {
        Ok(AmsiStatus {
            healthy: self.descriptor.supports_amsi,
        })
    }

    fn check_bpf_integrity(&self) -> Result<BpfStatus> {
        Ok(BpfStatus {
            healthy: self.descriptor.supports_bpf_integrity,
        })
    }
}

impl PlatformRuntime for MockPlatform {
    fn descriptor(&self) -> PlatformDescriptor {
        self.descriptor.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::{MockAction, MockPlatform};
    use crate::{KernelIntegrity, PlatformResponse, PlatformRuntime, PlatformSensor};
    use aegis_model::{EventBuffer, SensorConfig, SuspiciousProcess};

    #[test]
    fn mock_harness_drains_injected_events_when_running() {
        let mut platform = MockPlatform::linux();
        platform.enqueue_event(b"evt-1".to_vec());
        platform.enqueue_event(b"evt-2".to_vec());
        platform
            .start(&SensorConfig {
                profile: "test".to_string(),
                queue_capacity: 128,
            })
            .expect("start mock platform");

        let mut buffer = EventBuffer::default();
        let drained = platform.poll_events(&mut buffer).expect("poll events");

        assert_eq!(drained, 2);
        assert_eq!(buffer.records.len(), 2);
    }

    #[test]
    fn mock_harness_records_response_actions_and_descriptor() {
        let platform = MockPlatform::windows();
        platform.suspend_process(1001).expect("suspend");
        platform.kill_process(1002).expect("kill");

        let actions = platform.take_actions();
        assert!(actions.contains(&MockAction::SuspendProcess(1001)));
        assert!(actions.contains(&MockAction::KillProcess(1002)));
        assert!(platform.descriptor().supports_amsi);
    }

    #[test]
    fn mock_harness_returns_hidden_processes() {
        let platform = MockPlatform::linux();
        platform.set_hidden_processes(vec![SuspiciousProcess {
            pid: 4242,
            reason: "hidden".to_string(),
        }]);

        let processes = platform
            .detect_hidden_processes()
            .expect("hidden process list");
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].pid, 4242);
    }
}
