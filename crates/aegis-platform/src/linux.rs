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
    base_dir: PathBuf,
    degrade_level: LinuxDegradeLevel,
    pending_events: VecDeque<Vec<u8>>,
    execution: PlatformExecutionSnapshot,
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
                base_dir: platform_root("linux"),
                degrade_level: LinuxDegradeLevel::Full,
                pending_events: VecDeque::new(),
                execution: PlatformExecutionSnapshot::default(),
            }),
        }
    }
}

impl LinuxPlatform {
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
        let degrade_level = state.degrade_level;
        let provider_health = self
            .providers
            .iter()
            .map(|provider| {
                let healthy = match degrade_level {
                    LinuxDegradeLevel::Full => matches!(
                        provider,
                        LinuxProviderKind::ProcessEbpf
                            | LinuxProviderKind::FileEbpf
                            | LinuxProviderKind::NetworkEbpf
                            | LinuxProviderKind::AuthAudit
                            | LinuxProviderKind::ContainerMetadata
                    ),
                    LinuxDegradeLevel::TracepointOnly => matches!(
                        provider,
                        LinuxProviderKind::ProcessEbpf
                            | LinuxProviderKind::FileEbpf
                            | LinuxProviderKind::NetworkEbpf
                            | LinuxProviderKind::ContainerMetadata
                    ),
                    LinuxDegradeLevel::FanotifyAudit => matches!(
                        provider,
                        LinuxProviderKind::ProcessEbpf
                            | LinuxProviderKind::NetworkEbpf
                            | LinuxProviderKind::AuthAudit
                            | LinuxProviderKind::ContainerMetadata
                            | LinuxProviderKind::FanotifyFallback
                            | LinuxProviderKind::AuditFallback
                    ),
                    LinuxDegradeLevel::Minimal => matches!(
                        provider,
                        LinuxProviderKind::ProcessEbpf
                            | LinuxProviderKind::AuthAudit
                            | LinuxProviderKind::ContainerMetadata
                            | LinuxProviderKind::AuditFallback
                    ),
                } && running;
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
                (
                    "kernel_code".to_string(),
                    IntegrityReport {
                        passed: true,
                        details: "ebpf baseline intact".to_string(),
                    },
                ),
                (
                    "platform_protection".to_string(),
                    IntegrityReport {
                        passed: true,
                        details: format!("linux protection baseline intact ({degrade_level:?})"),
                    },
                ),
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
        self.state
            .lock()
            .expect("linux state poisoned")
            .execution
            .running = true;
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
            network: matches!(
                degrade_level,
                LinuxDegradeLevel::Full
                    | LinuxDegradeLevel::TracepointOnly
                    | LinuxDegradeLevel::FanotifyAudit
            ),
            registry: false,
            auth: true,
            script: false,
            memory: degrade_level == LinuxDegradeLevel::Full,
            container: true,
        }
    }
}

impl PlatformResponse for LinuxPlatform {
    fn suspend_process(&self, pid: u32) -> Result<()> {
        self.state
            .lock()
            .expect("linux state poisoned")
            .execution
            .suspended_pids
            .push(pid);
        Ok(())
    }

    fn kill_process(&self, pid: u32) -> Result<()> {
        self.state
            .lock()
            .expect("linux state poisoned")
            .execution
            .terminated_pids
            .push(pid);
        Ok(())
    }

    fn kill_ppl_process(&self, pid: u32) -> Result<()> {
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
        state.execution.network_isolation_active = true;
        state.execution.last_isolation_rules = Some(rules.clone());
        Ok(())
    }

    fn network_release(&self) -> Result<()> {
        self.state
            .lock()
            .expect("linux state poisoned")
            .execution
            .network_isolation_active = false;
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
    fn protect_process(&self, pid: u32) -> Result<()> {
        self.state
            .lock()
            .expect("linux state poisoned")
            .execution
            .protected_pids
            .push(pid);
        Ok(())
    }

    fn protect_files(&self, paths: &[PathBuf]) -> Result<()> {
        self.state
            .lock()
            .expect("linux state poisoned")
            .execution
            .protected_paths
            .extend(paths.iter().cloned());
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

fn platform_root(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("aegis-{prefix}-{}", Uuid::now_v7().simple()))
}

fn materialize_quarantine(
    state: &mut LinuxState,
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
        sha256: format!("linux:{}", original.display()),
    })
}

fn materialize_artifact(
    state: &mut LinuxState,
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
    use super::{LinuxDegradeLevel, LinuxEventStub, LinuxPlatform, LinuxProviderKind};
    use crate::{
        PlatformProtection, PlatformResponse, PlatformRuntime, PlatformSensor, PreemptiveBlock,
    };
    use aegis_model::{
        EventBuffer, ForensicSpec, IsolationRulesV2, NetworkTarget, RollbackTarget, SensorConfig,
    };
    use std::path::{Path, PathBuf};
    use std::time::Duration;

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
        let mut platform = LinuxPlatform::default();
        platform
            .start(&SensorConfig {
                profile: "linux".to_string(),
                queue_capacity: 1024,
            })
            .expect("start linux baseline");
        platform.set_degrade_level(LinuxDegradeLevel::FanotifyAudit);
        let descriptor = platform.descriptor();
        let snapshot = platform.health_snapshot();

        assert_eq!(descriptor.degrade_levels, 4);
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

    #[test]
    fn linux_execution_snapshot_tracks_isolation_blocks_and_forensics() {
        let platform = LinuxPlatform::default();
        platform
            .protect_process(4321)
            .expect("protect process should record");
        platform
            .protect_files(&[PathBuf::from("/tmp/payload.sh")])
            .expect("protect files should record");
        let receipt = platform
            .quarantine_file(Path::new("/tmp/payload.sh"))
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
}
