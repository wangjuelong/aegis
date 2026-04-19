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

struct WindowsState {
    running: bool,
    pending_events: VecDeque<Vec<u8>>,
}

pub struct WindowsPlatform {
    providers: Vec<WindowsProviderKind>,
    state: Mutex<WindowsState>,
}

impl Default for WindowsPlatform {
    fn default() -> Self {
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
            state: Mutex::new(WindowsState {
                running: false,
                pending_events: VecDeque::new(),
            }),
        }
    }
}

impl WindowsPlatform {
    pub fn provider_kinds(&self) -> &[WindowsProviderKind] {
        &self.providers
    }

    pub fn inject_event(&self, event: WindowsEventStub) {
        let mut state = self.state.lock().expect("windows state poisoned");
        state.pending_events.push_back(event.encode());
    }
}

impl PlatformSensor for WindowsPlatform {
    fn start(&mut self, _config: &SensorConfig) -> Result<()> {
        self.state.lock().expect("windows state poisoned").running = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.state.lock().expect("windows state poisoned").running = false;
        Ok(())
    }

    fn poll_events(&self, buf: &mut EventBuffer) -> Result<usize> {
        let mut state = self.state.lock().expect("windows state poisoned");
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
        SensorCapabilities {
            process: true,
            file: true,
            network: true,
            registry: true,
            auth: true,
            script: true,
            memory: true,
            container: false,
        }
    }
}

impl PlatformResponse for WindowsPlatform {
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
            sha256: "windows-mock".to_string(),
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
            location: PathBuf::from("C:/ProgramData/Aegis/forensics/mock.zip"),
        })
    }
}

impl PreemptiveBlock for WindowsPlatform {
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

impl KernelIntegrity for WindowsPlatform {
    fn check_ssdt_integrity(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            passed: true,
            details: "ssdt baseline intact".to_string(),
        })
    }

    fn check_callback_tables(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            passed: true,
            details: "callback baseline intact".to_string(),
        })
    }

    fn check_kernel_code(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            passed: true,
            details: "kernel code baseline intact".to_string(),
        })
    }

    fn detect_hidden_processes(&self) -> Result<Vec<SuspiciousProcess>> {
        Ok(Vec::new())
    }
}

impl PlatformProtection for WindowsPlatform {
    fn protect_process(&self, _pid: u32) -> Result<()> {
        Ok(())
    }

    fn protect_files(&self, _paths: &[PathBuf]) -> Result<()> {
        Ok(())
    }

    fn verify_integrity(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            passed: true,
            details: "windows protection baseline intact".to_string(),
        })
    }

    fn check_etw_integrity(&self) -> Result<EtwStatus> {
        Ok(EtwStatus { healthy: true })
    }

    fn check_amsi_integrity(&self) -> Result<AmsiStatus> {
        Ok(AmsiStatus { healthy: true })
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
            degrade_levels: 1,
            supports_registry: true,
            supports_amsi: true,
            supports_etw_integrity: true,
            supports_bpf_integrity: false,
            supports_container_sensor: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{WindowsEventStub, WindowsPlatform, WindowsProviderKind};
    use crate::{PlatformRuntime, PlatformSensor};
    use aegis_model::{EventBuffer, SensorConfig};

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
    fn windows_baseline_polls_injected_events() {
        let mut platform = WindowsPlatform::default();
        platform
            .start(&SensorConfig {
                profile: "windows".to_string(),
                queue_capacity: 1024,
            })
            .expect("start windows baseline");
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
    fn windows_descriptor_and_capabilities_match_design() {
        let platform = WindowsPlatform::default();
        let descriptor = platform.descriptor();
        let capabilities = platform.capabilities();

        assert!(descriptor.supports_amsi);
        assert!(descriptor.supports_etw_integrity);
        assert!(capabilities.registry);
        assert!(!capabilities.container);
    }
}
