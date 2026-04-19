use aegis_model::Severity;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TamperSignal {
    IntegrityFailure,
    UnsignedModule,
    HandleOpen,
    MemoryWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

pub struct KeyDerivationService {
    root_secret: Vec<u8>,
}

impl KeyDerivationService {
    pub fn new(root_secret: impl Into<Vec<u8>>) -> Self {
        Self {
            root_secret: root_secret.into(),
        }
    }

    pub fn derive(&self, context: &KeyContext) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.root_secret);
        hasher.update(context.tenant_id.as_bytes());
        hasher.update(context.agent_id.as_bytes());
        hasher.update(context.purpose.as_bytes());
        hex::encode(hasher.finalize())
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
        CrashExploitAnalyzer, CrashSample, KeyContext, KeyDerivationService, ProtectionPosture,
        SelfProtectionManager, TamperSignal,
    };
    use aegis_model::Severity;
    use std::path::PathBuf;

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
