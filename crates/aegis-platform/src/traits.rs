use aegis_model::{
    AmsiStatus, ArtifactBundle, BpfStatus, EtwStatus, EventBuffer, ForensicSpec, IntegrityReport,
    IsolationRulesV2, NetworkTarget, QuarantineReceipt, RollbackTarget, SensorCapabilities,
    SensorConfig, SuspiciousProcess,
};
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub trait PlatformSensor: Send + Sync {
    fn start(&mut self, config: &SensorConfig) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
    fn poll_events(&self, buf: &mut EventBuffer) -> Result<usize>;
    fn capabilities(&self) -> SensorCapabilities;
}

pub trait PlatformResponse: Send + Sync {
    fn suspend_process(&self, pid: u32) -> Result<()>;
    fn kill_process(&self, pid: u32) -> Result<()>;
    fn kill_ppl_process(&self, pid: u32) -> Result<()>;
    fn quarantine_file(&self, path: &Path) -> Result<QuarantineReceipt>;
    fn network_isolate(&self, rules: &IsolationRulesV2) -> Result<()>;
    fn network_release(&self) -> Result<()>;
    fn registry_rollback(&self, target: &RollbackTarget) -> Result<()>;
    fn collect_forensics(&self, spec: &ForensicSpec) -> Result<ArtifactBundle>;
}

pub trait PreemptiveBlock: Send + Sync {
    fn block_hash(&self, hash: &str, ttl: Duration) -> Result<()>;
    fn block_pid(&self, pid: u32, ttl: Duration) -> Result<()>;
    fn block_path(&self, path: &Path, ttl: Duration) -> Result<()>;
    fn block_network(&self, target: &NetworkTarget, ttl: Duration) -> Result<()>;
    fn clear_all_blocks(&self) -> Result<()>;
}

pub trait KernelIntegrity: Send + Sync {
    fn check_ssdt_integrity(&self) -> Result<IntegrityReport>;
    fn check_callback_tables(&self) -> Result<IntegrityReport>;
    fn check_kernel_code(&self) -> Result<IntegrityReport>;
    fn detect_hidden_processes(&self) -> Result<Vec<SuspiciousProcess>>;
}

pub trait PlatformProtection: Send + Sync {
    fn protect_process(&self, pid: u32) -> Result<()>;
    fn protect_files(&self, paths: &[PathBuf]) -> Result<()>;
    fn verify_integrity(&self) -> Result<IntegrityReport>;
    fn check_etw_integrity(&self) -> Result<EtwStatus>;
    fn check_amsi_integrity(&self) -> Result<AmsiStatus>;
    fn check_bpf_integrity(&self) -> Result<BpfStatus>;
}
