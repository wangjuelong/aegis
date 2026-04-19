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

struct LinuxState {
    running: bool,
    degrade_level: LinuxDegradeLevel,
    pending_events: VecDeque<Vec<u8>>,
}

pub struct LinuxPlatform {
    providers: Vec<LinuxProviderKind>,
    state: Mutex<LinuxState>,
}

impl Default for LinuxPlatform {
    fn default() -> Self {
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
                running: false,
                degrade_level: LinuxDegradeLevel::Full,
                pending_events: VecDeque::new(),
            }),
        }
    }
}

impl LinuxPlatform {
    pub fn provider_kinds(&self) -> &[LinuxProviderKind] {
        &self.providers
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
        self.state.lock().expect("linux state poisoned").running = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.state.lock().expect("linux state poisoned").running = false;
        Ok(())
    }

    fn poll_events(&self, buf: &mut EventBuffer) -> Result<usize> {
        let mut state = self.state.lock().expect("linux state poisoned");
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
        let degrade_level = self.degrade_level();
        SensorCapabilities {
            process: true,
            file: degrade_level != LinuxDegradeLevel::Minimal,
            network: true,
            registry: false,
            auth: true,
            script: false,
            memory: degrade_level == LinuxDegradeLevel::Full,
            container: true,
        }
    }
}

impl PlatformResponse for LinuxPlatform {
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
            sha256: "linux-mock".to_string(),
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
            location: PathBuf::from("/var/lib/aegis/forensics/linux-mock.tar"),
        })
    }
}

impl PreemptiveBlock for LinuxPlatform {
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
        Ok(IntegrityReport {
            passed: true,
            details: "ebpf baseline intact".to_string(),
        })
    }

    fn detect_hidden_processes(&self) -> Result<Vec<SuspiciousProcess>> {
        Ok(Vec::new())
    }
}

impl PlatformProtection for LinuxPlatform {
    fn protect_process(&self, _pid: u32) -> Result<()> {
        Ok(())
    }

    fn protect_files(&self, _paths: &[PathBuf]) -> Result<()> {
        Ok(())
    }

    fn verify_integrity(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            passed: true,
            details: "linux protection baseline intact".to_string(),
        })
    }

    fn check_etw_integrity(&self) -> Result<EtwStatus> {
        Ok(EtwStatus { healthy: false })
    }

    fn check_amsi_integrity(&self) -> Result<AmsiStatus> {
        Ok(AmsiStatus { healthy: false })
    }

    fn check_bpf_integrity(&self) -> Result<BpfStatus> {
        Ok(BpfStatus { healthy: true })
    }
}

impl PlatformRuntime for LinuxPlatform {
    fn descriptor(&self) -> PlatformDescriptor {
        PlatformDescriptor {
            target: PlatformTarget::Linux,
            kernel_transport: KernelTransport::EBpf,
            degrade_levels: 4,
            supports_registry: false,
            supports_amsi: false,
            supports_etw_integrity: false,
            supports_bpf_integrity: true,
            supports_container_sensor: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LinuxDegradeLevel, LinuxEventStub, LinuxPlatform, LinuxProviderKind};
    use crate::{PlatformRuntime, PlatformSensor};
    use aegis_model::{EventBuffer, SensorConfig};

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
    fn linux_baseline_supports_four_degrade_levels() {
        let platform = LinuxPlatform::default();
        let descriptor = platform.descriptor();

        assert_eq!(descriptor.degrade_levels, 4);
        assert_eq!(platform.degrade_level(), LinuxDegradeLevel::Full);
    }

    #[test]
    fn linux_baseline_polls_container_aware_events() {
        let mut platform = LinuxPlatform::default();
        platform
            .start(&SensorConfig {
                profile: "linux".to_string(),
                queue_capacity: 1024,
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

        assert_eq!(drained, 1);
        assert_eq!(buffer.records.len(), 1);
        assert!(String::from_utf8_lossy(&buffer.records[0]).contains("container-1"));
    }
}
