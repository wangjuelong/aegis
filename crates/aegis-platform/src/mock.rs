use crate::traits::{
    KernelIntegrity, PlatformProtection, PlatformResponse, PlatformSensor, PreemptiveBlock,
};
use aegis_model::{
    AmsiStatus, ArtifactBundle, BpfStatus, EtwStatus, EventBuffer, ForensicSpec, IntegrityReport,
    IsolationRulesV2, NetworkTarget, QuarantineReceipt, RollbackTarget, SensorCapabilities,
    SensorConfig, SuspiciousProcess,
};
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

#[derive(Default)]
pub struct MockPlatform {
    running: bool,
}

impl PlatformSensor for MockPlatform {
    fn start(&mut self, _config: &SensorConfig) -> Result<()> {
        self.running = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.running = false;
        Ok(())
    }

    fn poll_events(&self, buf: &mut EventBuffer) -> Result<usize> {
        if self.running {
            buf.records.push(b"mock-event".to_vec());
            return Ok(1);
        }
        Ok(0)
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
            container: true,
        }
    }
}

impl PlatformResponse for MockPlatform {
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
            sha256: "mock".to_string(),
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
            location: PathBuf::from("/tmp/mock-artifact"),
        })
    }
}

impl PreemptiveBlock for MockPlatform {
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
        Ok(Vec::new())
    }
}

impl PlatformProtection for MockPlatform {
    fn protect_process(&self, _pid: u32) -> Result<()> {
        Ok(())
    }

    fn protect_files(&self, _paths: &[PathBuf]) -> Result<()> {
        Ok(())
    }

    fn verify_integrity(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            passed: true,
            details: "mock protection".to_string(),
        })
    }

    fn check_etw_integrity(&self) -> Result<EtwStatus> {
        Ok(EtwStatus { healthy: true })
    }

    fn check_amsi_integrity(&self) -> Result<AmsiStatus> {
        Ok(AmsiStatus { healthy: true })
    }

    fn check_bpf_integrity(&self) -> Result<BpfStatus> {
        Ok(BpfStatus { healthy: true })
    }
}
