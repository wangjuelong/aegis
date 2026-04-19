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
use anyhow::Result;
use std::collections::{BTreeMap, VecDeque};
use std::fs;
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
    base_dir: PathBuf,
    pending_events: VecDeque<Vec<u8>>,
    execution: PlatformExecutionSnapshot,
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
                base_dir: platform_root("windows"),
                pending_events: VecDeque::new(),
                execution: PlatformExecutionSnapshot::default(),
            }),
        }
    }
}

impl WindowsPlatform {
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

    pub fn health_snapshot(&self) -> PlatformHealthSnapshot {
        let running = self
            .state
            .lock()
            .expect("windows state poisoned")
            .execution
            .running;
        PlatformHealthSnapshot {
            provider_health: self
                .providers
                .iter()
                .map(|provider| (format!("{provider:?}"), running))
                .collect(),
            integrity_reports: BTreeMap::from([
                (
                    "ssdt".to_string(),
                    IntegrityReport {
                        passed: true,
                        details: "ssdt baseline intact".to_string(),
                    },
                ),
                (
                    "callbacks".to_string(),
                    IntegrityReport {
                        passed: true,
                        details: "callback baseline intact".to_string(),
                    },
                ),
                (
                    "kernel_code".to_string(),
                    IntegrityReport {
                        passed: true,
                        details: "kernel code baseline intact".to_string(),
                    },
                ),
                (
                    "platform_protection".to_string(),
                    IntegrityReport {
                        passed: true,
                        details: "windows protection baseline intact".to_string(),
                    },
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
        self.state
            .lock()
            .expect("windows state poisoned")
            .execution
            .running = true;
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
    use super::{WindowsEventStub, WindowsPlatform, WindowsProviderKind};
    use crate::{
        PlatformProtection, PlatformResponse, PlatformRuntime, PlatformSensor, PreemptiveBlock,
    };
    use aegis_model::{EventBuffer, ForensicSpec, IsolationRulesV2, SensorConfig};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

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
    fn windows_execution_snapshot_tracks_response_and_block_state() {
        let platform = WindowsPlatform::default();
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
    fn windows_health_snapshot_reports_provider_and_integrity_state() {
        let mut platform = WindowsPlatform::default();
        platform
            .start(&SensorConfig {
                profile: "windows".to_string(),
                queue_capacity: 1024,
            })
            .expect("start windows baseline");

        let snapshot = platform.health_snapshot();

        assert_eq!(
            snapshot.provider_health.get("EtwProcess").copied(),
            Some(true)
        );
        assert_eq!(
            snapshot
                .integrity_reports
                .get("platform_protection")
                .map(|report| report.passed),
            Some(true)
        );
        assert!(
            platform
                .check_etw_integrity()
                .expect("etw integrity")
                .healthy
        );
        assert!(
            !platform
                .check_bpf_integrity()
                .expect("bpf integrity")
                .healthy
        );
        assert!(platform.descriptor().supports_amsi);
        assert!(platform.capabilities().registry);
    }
}
