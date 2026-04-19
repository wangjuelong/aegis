use crate::config::AgentConfig;
use crate::error::CoreError;
use crate::linux_tpm::{
    detect_linux_tpm_runtime, generate_attestation_quote, load_or_initialize_master_key_from_tpm,
    verify_attestation_quote,
};
use aegis_model::Severity;
use getrandom::fill as getrandom_fill;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TamperSignal {
    IntegrityFailure,
    UnsignedModule,
    HandleOpen,
    MemoryWrite,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtectionPosture {
    Normal,
    Hardened,
    Lockdown,
}

#[derive(Default)]
pub struct SelfProtectionManager {
    protected_pids: HashSet<u32>,
    protected_files: HashSet<PathBuf>,
    tamper_counts: HashMap<TamperSignal, u32>,
}

impl SelfProtectionManager {
    pub fn protect_process(&mut self, pid: u32) {
        self.protected_pids.insert(pid);
    }

    pub fn protect_file(&mut self, path: PathBuf) {
        self.protected_files.insert(path);
    }

    pub fn posture(&self) -> ProtectionPosture {
        let total_tamper = self.tamper_counts.values().sum::<u32>();
        if total_tamper >= 3 || self.tamper_counts.get(&TamperSignal::IntegrityFailure) >= Some(&1)
        {
            ProtectionPosture::Lockdown
        } else if total_tamper >= 1 {
            ProtectionPosture::Hardened
        } else {
            ProtectionPosture::Normal
        }
    }

    pub fn observe_tamper(&mut self, signal: TamperSignal) -> ProtectionPosture {
        *self.tamper_counts.entry(signal).or_insert(0) += 1;
        self.posture()
    }

    pub fn protected_pid_count(&self) -> usize {
        self.protected_pids.len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyContext {
    pub tenant_id: String,
    pub agent_id: String,
    pub purpose: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DerivedKeyTier {
    TelemetryWal,
    ForensicJournal,
    RecoveryEvidence,
}

impl DerivedKeyTier {
    fn label(self) -> &'static str {
        match self {
            Self::TelemetryWal => "telemetry-wal",
            Self::ForensicJournal => "forensic-journal",
            Self::RecoveryEvidence => "recovery-evidence",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKeyMaterial {
    #[zeroize(skip)]
    pub tier: DerivedKeyTier,
    #[zeroize(skip)]
    pub version: u32,
    pub key_bytes: [u8; 32],
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyProtectionTier {
    HardwareBound,
    OsCredentialStore,
    FileBackedFallback,
    InMemoryTestOnly,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyProtectionStatus {
    pub active_tier: KeyProtectionTier,
    pub hardware_root_available: bool,
    pub degraded: bool,
    pub memory_lock_supported: bool,
    pub memory_lock_enabled: bool,
    pub attestation_quote_ready: bool,
    pub attestation_pcrs: Option<String>,
    pub attestation_error: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct MemoryLockState {
    supported: bool,
    enabled: bool,
    last_error: Option<String>,
}

struct SensitiveBytes {
    bytes: Zeroizing<Vec<u8>>,
    locked: bool,
}

impl SensitiveBytes {
    fn new(bytes: Vec<u8>, best_effort_lock: bool) -> (Self, MemoryLockState) {
        let mut state = MemoryLockState {
            supported: cfg!(unix),
            ..MemoryLockState::default()
        };
        let mut secret = Self {
            bytes: Zeroizing::new(bytes),
            locked: false,
        };

        #[cfg(unix)]
        {
            if best_effort_lock && !secret.bytes.is_empty() {
                let rc = unsafe {
                    libc::mlock(
                        secret.bytes.as_ptr().cast::<libc::c_void>(),
                        secret.bytes.len(),
                    )
                };
                if rc == 0 {
                    secret.locked = true;
                    state.enabled = true;
                } else {
                    state.last_error =
                        Some(format!("mlock failed: {}", std::io::Error::last_os_error()));
                }
            }
        }

        (secret, state)
    }

    fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            if self.locked && !self.bytes.is_empty() {
                let _ = unsafe {
                    libc::munlock(self.bytes.as_ptr().cast::<libc::c_void>(), self.bytes.len())
                };
            }
        }
    }
}

pub struct KeyDerivationService {
    root_secret: SensitiveBytes,
    protection_status: KeyProtectionStatus,
}

impl KeyDerivationService {
    pub fn new(root_secret: impl Into<Vec<u8>>) -> Self {
        let (root_secret, memory_lock) = SensitiveBytes::new(root_secret.into(), false);
        Self {
            root_secret,
            protection_status: KeyProtectionStatus {
                active_tier: KeyProtectionTier::InMemoryTestOnly,
                hardware_root_available: false,
                degraded: true,
                memory_lock_supported: memory_lock.supported,
                memory_lock_enabled: memory_lock.enabled,
                attestation_quote_ready: false,
                attestation_pcrs: None,
                attestation_error: None,
                last_error: memory_lock.last_error,
            },
        }
    }

    pub fn from_config(config: &AgentConfig) -> Result<Self, CoreError> {
        let (root_secret, mut protection_status) = load_master_key(config)?;
        let (root_secret, memory_lock) =
            SensitiveBytes::new(root_secret, config.security.memory_lock_best_effort);
        protection_status.memory_lock_supported = memory_lock.supported;
        protection_status.memory_lock_enabled = memory_lock.enabled;
        merge_status_error(&mut protection_status.last_error, memory_lock.last_error);
        Ok(Self {
            root_secret,
            protection_status,
        })
    }

    pub fn derive(&self, context: &KeyContext) -> String {
        hex::encode(self.derive_bytes(context, 32))
    }

    pub fn derive_bytes(&self, context: &KeyContext, len: usize) -> Vec<u8> {
        let hk = Hkdf::<Sha256>::new(None, self.root_secret.as_slice());
        let info = format!(
            "aegis:{}:{}:{}",
            context.tenant_id, context.agent_id, context.purpose
        );
        let mut output = vec![0u8; len];
        hk.expand(info.as_bytes(), &mut output)
            .expect("hkdf length is bounded");
        output
    }

    pub fn derive_material(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tier: DerivedKeyTier,
        version: u32,
    ) -> DerivedKeyMaterial {
        let key_bytes = self.derive_bytes(
            &KeyContext {
                tenant_id: tenant_id.to_string(),
                agent_id: agent_id.to_string(),
                purpose: format!("{}.v{}", tier.label(), version),
            },
            32,
        );
        let mut material = [0u8; 32];
        material.copy_from_slice(&key_bytes);
        DerivedKeyMaterial {
            tier,
            version,
            key_bytes: material,
        }
    }

    pub fn protection_status(&self) -> &KeyProtectionStatus {
        &self.protection_status
    }
}

pub fn linux_tpm_attestation_status_from_config(
    config: &AgentConfig,
) -> (bool, Option<String>, Option<String>) {
    linux_attestation_status(&detect_linux_tpm_runtime(&config.security))
}

pub fn verify_linux_tpm_attestation_roundtrip(
    config: &AgentConfig,
    qualification: &[u8],
) -> Result<(), CoreError> {
    let quote = generate_attestation_quote(&config.security, qualification)
        .map_err(|error| CoreError::Crypto(error.to_string()))?;
    verify_attestation_quote(&config.security, &quote)
        .map_err(|error| CoreError::Crypto(error.to_string()))
}

fn load_master_key(config: &AgentConfig) -> Result<(Vec<u8>, KeyProtectionStatus), CoreError> {
    let mut last_error = None;
    let tpm_runtime = detect_linux_tpm_runtime(&config.security);
    let (attestation_quote_ready, attestation_pcrs, attestation_error) =
        linux_attestation_status(&tpm_runtime);

    if tpm_runtime.master_key_enabled() {
        match load_or_initialize_master_key_from_tpm(&config.security) {
            Ok(key) => {
                return Ok((
                    key,
                    KeyProtectionStatus {
                        active_tier: KeyProtectionTier::HardwareBound,
                        hardware_root_available: true,
                        degraded: false,
                        memory_lock_supported: false,
                        memory_lock_enabled: false,
                        attestation_quote_ready,
                        attestation_pcrs,
                        attestation_error,
                        last_error: None,
                    },
                ));
            }
            Err(error) => merge_status_error(
                &mut last_error,
                Some(format!("linux tpm master key unavailable: {error}")),
            ),
        }
    } else if tpm_runtime.master_key_configured() {
        merge_status_error(
            &mut last_error,
            Some(
                "linux tpm master key provider is configured but the required tools or device are unavailable"
                    .to_string(),
            ),
        );
    } else if tpm_runtime.nv_available() || tpm_runtime.sealed_object_available() {
        merge_status_error(
            &mut last_error,
            Some("linux tpm available but no master key provider is configured".to_string()),
        );
    }

    if config.security.use_os_credential_store {
        match load_master_key_from_keyring(config) {
            Ok(key) => {
                return Ok((
                    key,
                    KeyProtectionStatus {
                        active_tier: KeyProtectionTier::OsCredentialStore,
                        hardware_root_available: tpm_runtime.available(),
                        degraded: true,
                        memory_lock_supported: false,
                        memory_lock_enabled: false,
                        attestation_quote_ready,
                        attestation_pcrs,
                        attestation_error,
                        last_error: None,
                    },
                ));
            }
            Err(error) => merge_status_error(
                &mut last_error,
                Some(format!("os credential store unavailable: {error}")),
            ),
        }
    }

    if config.security.allow_file_fallback {
        match load_master_key_from_file(config) {
            Ok(key) => {
                return Ok((
                    key,
                    KeyProtectionStatus {
                        active_tier: KeyProtectionTier::FileBackedFallback,
                        hardware_root_available: tpm_runtime.available(),
                        degraded: true,
                        memory_lock_supported: false,
                        memory_lock_enabled: false,
                        attestation_quote_ready,
                        attestation_pcrs,
                        attestation_error,
                        last_error,
                    },
                ));
            }
            Err(error) => merge_status_error(
                &mut last_error,
                Some(format!("file-backed master key unavailable: {error}")),
            ),
        }
    }

    Err(CoreError::Crypto(last_error.unwrap_or_else(|| {
        "no master key provider available".to_string()
    })))
}

fn linux_attestation_status(
    tpm_runtime: &crate::linux_tpm::LinuxTpmRuntime,
) -> (bool, Option<String>, Option<String>) {
    (
        tpm_runtime.attestation_enabled(),
        tpm_runtime.attestation_pcrs.clone(),
        tpm_runtime.attestation_status_error(),
    )
}

fn load_master_key_from_keyring(config: &AgentConfig) -> Result<Vec<u8>, CoreError> {
    let entry = keyring::Entry::new(
        "aegis-sensor/master-key",
        &keyring_account(config, "master-key"),
    )
    .map_err(|error| CoreError::Crypto(error.to_string()))?;
    match entry.get_password() {
        Ok(secret) => decode_secret_hex(&secret),
        Err(_) => {
            let secret = generate_secret_bytes(32)?;
            entry
                .set_password(&hex::encode(&secret))
                .map_err(|error| CoreError::Crypto(error.to_string()))?;
            Ok(secret)
        }
    }
}

fn load_master_key_from_file(config: &AgentConfig) -> Result<Vec<u8>, CoreError> {
    let path = secure_root(&config.storage.state_root).join("master-key.bin");
    if path.exists() {
        let bytes = fs::read(&path)?;
        if bytes.len() != 32 {
            return Err(CoreError::Crypto(format!(
                "unexpected master key length {}, expected 32",
                bytes.len()
            )));
        }
        return Ok(bytes);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let secret = generate_secret_bytes(32)?;
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            file.write_all(&secret)?;
            restrict_owner_only(&path)?;
            Ok(secret)
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let bytes = fs::read(&path)?;
            if bytes.len() != 32 {
                return Err(CoreError::Crypto(format!(
                    "unexpected master key length {}, expected 32",
                    bytes.len()
                )));
            }
            Ok(bytes)
        }
        Err(error) => Err(CoreError::from(error)),
    }
}

fn secure_root(state_root: &Path) -> PathBuf {
    state_root.join("secure")
}

fn keyring_account(config: &AgentConfig, namespace: &str) -> String {
    let scope_hash = blake3::hash(config.storage.state_root.to_string_lossy().as_bytes())
        .to_hex()
        .to_string();
    format!(
        "{namespace}:{}:{}:{scope_hash}",
        config.tenant_id, config.agent_id
    )
}

fn decode_secret_hex(secret: &str) -> Result<Vec<u8>, CoreError> {
    let decoded =
        hex::decode(secret.trim()).map_err(|error| CoreError::Crypto(error.to_string()))?;
    if decoded.len() != 32 {
        return Err(CoreError::Crypto(format!(
            "unexpected secret length {}, expected 32",
            decoded.len()
        )));
    }
    Ok(decoded)
}

fn generate_secret_bytes(len: usize) -> Result<Vec<u8>, CoreError> {
    let mut secret = vec![0u8; len];
    getrandom_fill(&mut secret).map_err(|error| CoreError::Crypto(error.to_string()))?;
    Ok(secret)
}

fn merge_status_error(target: &mut Option<String>, next: Option<String>) {
    let Some(next) = next else {
        return;
    };
    match target {
        Some(current) if !current.is_empty() => {
            current.push_str("; ");
            current.push_str(&next);
        }
        _ => *target = Some(next),
    }
}

#[cfg(unix)]
fn restrict_owner_only(path: &Path) -> Result<(), CoreError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_owner_only(_path: &Path) -> Result<(), CoreError> {
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateLifecycleEvent {
    Issued,
    Rotated,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateRecord {
    pub thumbprint: String,
    pub not_after_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateLifecycleAudit {
    pub event: CertificateLifecycleEvent,
    pub thumbprint: String,
}

#[derive(Default)]
pub struct CertificateLifecycleHooks {
    active: HashMap<String, CertificateRecord>,
    retired: HashSet<String>,
    audit: Vec<CertificateLifecycleAudit>,
}

impl CertificateLifecycleHooks {
    pub fn issue(&mut self, record: CertificateRecord) {
        self.audit.push(CertificateLifecycleAudit {
            event: CertificateLifecycleEvent::Issued,
            thumbprint: record.thumbprint.clone(),
        });
        self.active.insert(record.thumbprint.clone(), record);
    }

    pub fn rotate(
        &mut self,
        old_thumbprint: &str,
        replacement: CertificateRecord,
    ) -> Result<(), &'static str> {
        if self.active.remove(old_thumbprint).is_none() {
            return Err("missing active certificate");
        }

        self.retired.insert(old_thumbprint.to_string());
        self.audit.push(CertificateLifecycleAudit {
            event: CertificateLifecycleEvent::Rotated,
            thumbprint: old_thumbprint.to_string(),
        });
        self.issue(replacement);
        Ok(())
    }

    pub fn revoke(&mut self, thumbprint: &str) -> bool {
        let existed = self.active.remove(thumbprint).is_some();
        if existed {
            self.retired.insert(thumbprint.to_string());
            self.audit.push(CertificateLifecycleAudit {
                event: CertificateLifecycleEvent::Revoked,
                thumbprint: thumbprint.to_string(),
            });
        }
        existed
    }

    pub fn active_thumbprints(&self) -> Vec<&str> {
        let mut items = self.active.keys().map(String::as_str).collect::<Vec<_>>();
        items.sort_unstable();
        items
    }

    pub fn is_retired(&self, thumbprint: &str) -> bool {
        self.retired.contains(thumbprint)
    }

    pub fn audit(&self) -> &[CertificateLifecycleAudit] {
        &self.audit
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrashSample {
    pub exception_code: String,
    pub module: String,
    pub instruction_pointer: u64,
    pub stack_pivot_detected: bool,
    pub shellcode_region_detected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrashAssessment {
    pub exploitable: bool,
    pub severity: Severity,
    pub summary: String,
}

pub struct CrashExploitAnalyzer;

impl CrashExploitAnalyzer {
    pub fn analyze(&self, sample: &CrashSample) -> CrashAssessment {
        let exploitable = sample.stack_pivot_detected
            || sample.shellcode_region_detected
            || (sample.exception_code.eq_ignore_ascii_case("0xc0000005")
                && !sample.module.eq_ignore_ascii_case("ntdll.dll"));

        CrashAssessment {
            exploitable,
            severity: if exploitable {
                Severity::Critical
            } else {
                Severity::Low
            },
            summary: if exploitable {
                format!(
                    "crash in {} at 0x{:x} looks exploitable",
                    sample.module, sample.instruction_pointer
                )
            } else {
                format!(
                    "crash in {} at 0x{:x} looks non-exploitable",
                    sample.module, sample.instruction_pointer
                )
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CertificateLifecycleEvent, CertificateLifecycleHooks, CertificateRecord,
        CrashExploitAnalyzer, CrashSample, DerivedKeyTier, KeyContext, KeyDerivationService,
        KeyProtectionTier, ProtectionPosture, SelfProtectionManager, TamperSignal,
    };
    use crate::config::AgentConfig;
    #[cfg(unix)]
    use crate::linux_tpm::TestTpmHarness;
    use aegis_model::Severity;
    use std::path::PathBuf;
    use uuid::Uuid;

    #[test]
    fn self_protection_manager_enters_lockdown_on_repeated_tamper() {
        let mut manager = SelfProtectionManager::default();
        manager.protect_process(7);
        manager.protect_file(PathBuf::from("/opt/aegis/agentd"));

        assert_eq!(
            manager.observe_tamper(TamperSignal::HandleOpen),
            ProtectionPosture::Hardened
        );
        assert_eq!(
            manager.observe_tamper(TamperSignal::IntegrityFailure),
            ProtectionPosture::Lockdown
        );
        assert_eq!(manager.protected_pid_count(), 1);
    }

    #[test]
    fn key_derivation_is_stable_and_namespaced() {
        let service = KeyDerivationService::new("root-secret");
        let a = service.derive(&KeyContext {
            tenant_id: "tenant-a".to_string(),
            agent_id: "agent-1".to_string(),
            purpose: "telemetry".to_string(),
        });
        let b = service.derive(&KeyContext {
            tenant_id: "tenant-a".to_string(),
            agent_id: "agent-1".to_string(),
            purpose: "telemetry".to_string(),
        });
        let c = service.derive(&KeyContext {
            tenant_id: "tenant-a".to_string(),
            agent_id: "agent-1".to_string(),
            purpose: "response".to_string(),
        });

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn tiered_key_material_is_stable_and_distinct() {
        let service = KeyDerivationService::new("root-secret");
        let telemetry_v1 =
            service.derive_material("tenant-a", "agent-1", DerivedKeyTier::TelemetryWal, 1);
        let telemetry_v1_again =
            service.derive_material("tenant-a", "agent-1", DerivedKeyTier::TelemetryWal, 1);
        let journal_v1 =
            service.derive_material("tenant-a", "agent-1", DerivedKeyTier::ForensicJournal, 1);
        let telemetry_v2 =
            service.derive_material("tenant-a", "agent-1", DerivedKeyTier::TelemetryWal, 2);

        assert_eq!(telemetry_v1, telemetry_v1_again);
        assert_ne!(telemetry_v1.key_bytes, journal_v1.key_bytes);
        assert_ne!(telemetry_v1.key_bytes, telemetry_v2.key_bytes);
    }

    #[test]
    fn config_backed_key_derivation_uses_file_fallback_when_requested() {
        let mut config = AgentConfig::default();
        config.storage.state_root =
            std::env::temp_dir().join(format!("aegis-key-derivation-{}", Uuid::now_v7()));
        config.security.use_os_credential_store = false;
        config.security.allow_file_fallback = true;
        config.security.memory_lock_best_effort = false;

        let first = KeyDerivationService::from_config(&config).expect("load config-backed key");
        let second = KeyDerivationService::from_config(&config).expect("reload config-backed key");
        let first_key =
            first.derive_material("tenant-a", "agent-1", DerivedKeyTier::TelemetryWal, 1);
        let second_key =
            second.derive_material("tenant-a", "agent-1", DerivedKeyTier::TelemetryWal, 1);

        assert_eq!(first_key.key_bytes, second_key.key_bytes);
        assert_eq!(
            first.protection_status().active_tier,
            KeyProtectionTier::FileBackedFallback
        );
        assert!(config
            .storage
            .state_root
            .join("secure/master-key.bin")
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn config_backed_key_derivation_prefers_linux_tpm_when_configured() {
        let harness = TestTpmHarness::install("self-protection");
        let mut config = AgentConfig::default();
        config.security.use_os_credential_store = false;
        config.security.allow_file_fallback = true;
        config.security.memory_lock_best_effort = false;
        config.security.linux_tpm_tools_dir = Some(harness.tools_dir);
        config.security.linux_tpm_device_path = Some(harness.device_path);
        config.security.linux_tpm_master_key_nv_index = Some("0x1500100".to_string());
        config.security.linux_tpm_auto_provision_nv = true;

        let first = KeyDerivationService::from_config(&config).expect("load tpm-backed key");
        let second = KeyDerivationService::from_config(&config).expect("reload tpm-backed key");
        let first_key =
            first.derive_material("tenant-a", "agent-1", DerivedKeyTier::TelemetryWal, 1);
        let second_key =
            second.derive_material("tenant-a", "agent-1", DerivedKeyTier::TelemetryWal, 1);

        assert_eq!(first_key.key_bytes, second_key.key_bytes);
        assert_eq!(
            first.protection_status().active_tier,
            KeyProtectionTier::HardwareBound
        );
        assert!(first.protection_status().hardware_root_available);
        assert!(!first.protection_status().degraded);
    }

    #[test]
    fn certificate_lifecycle_rotates_and_revokes_records() {
        let mut hooks = CertificateLifecycleHooks::default();
        hooks.issue(CertificateRecord {
            thumbprint: "cert-a".to_string(),
            not_after_unix: 1_800_000_000,
        });
        hooks
            .rotate(
                "cert-a",
                CertificateRecord {
                    thumbprint: "cert-b".to_string(),
                    not_after_unix: 1_900_000_000,
                },
            )
            .expect("rotation should succeed");

        assert_eq!(hooks.active_thumbprints(), vec!["cert-b"]);
        assert!(hooks.is_retired("cert-a"));
        assert!(hooks.revoke("cert-b"));
        assert!(hooks.active_thumbprints().is_empty());
        assert_eq!(
            hooks
                .audit()
                .iter()
                .map(|entry| entry.event)
                .collect::<Vec<_>>(),
            vec![
                CertificateLifecycleEvent::Issued,
                CertificateLifecycleEvent::Rotated,
                CertificateLifecycleEvent::Issued,
                CertificateLifecycleEvent::Revoked,
            ]
        );
    }

    #[test]
    fn crash_analyzer_flags_exploitable_patterns() {
        let analyzer = CrashExploitAnalyzer;
        let assessment = analyzer.analyze(&CrashSample {
            exception_code: "0xc0000005".to_string(),
            module: "agentd.dll".to_string(),
            instruction_pointer: 0x41414141,
            stack_pivot_detected: true,
            shellcode_region_detected: false,
        });

        assert!(assessment.exploitable);
        assert_eq!(assessment.severity, Severity::Critical);
        assert!(assessment.summary.contains("exploitable"));
    }
}
