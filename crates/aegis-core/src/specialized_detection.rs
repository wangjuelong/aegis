use aegis_model::{
    AuthContext, DecisionKind, EventPayload, EventType, FileContext, NetworkContext,
    NormalizedEvent, Severity,
};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetectionCategory {
    Ransomware,
    Asr,
    Identity,
    Deception,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectionFinding {
    pub category: DetectionCategory,
    pub summary: String,
    pub severity: Severity,
    pub decision: DecisionKind,
    pub storyline_id: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RansomwareStage {
    Normal,
    Suspicious,
    Encrypting,
}

#[derive(Clone, Debug, Default)]
struct RansomwareSignals {
    rename_count: u32,
    high_entropy_writes: u32,
    canary_touched: bool,
    shadow_copy_deleted: bool,
}

#[derive(Default)]
pub struct RansomwareStateMachine {
    states: HashMap<u32, RansomwareSignals>,
}

impl RansomwareStateMachine {
    fn evaluate(&mut self, event: &NormalizedEvent) -> Option<DetectionFinding> {
        let signals = self.states.entry(event.process.pid).or_default();
        if let EventPayload::File(FileContext {
            path,
            entropy,
            action,
            ..
        }) = &event.payload
        {
            if action.as_deref() == Some("rename") {
                signals.rename_count += 1;
            }
            if entropy.unwrap_or_default() >= 7.2 {
                signals.high_entropy_writes += 1;
            }
            if path.display().to_string().contains(".aegis-canary") {
                signals.canary_touched = true;
            }
        }
        if event.process.cmdline.contains("vssadmin delete shadows") {
            signals.shadow_copy_deleted = true;
        }

        let stage = if (signals.rename_count >= 2 && signals.high_entropy_writes >= 2)
            || signals.canary_touched
            || signals.shadow_copy_deleted
        {
            RansomwareStage::Encrypting
        } else if signals.rename_count >= 1 || signals.high_entropy_writes >= 1 {
            RansomwareStage::Suspicious
        } else {
            RansomwareStage::Normal
        };

        (stage == RansomwareStage::Encrypting).then(|| DetectionFinding {
            category: DetectionCategory::Ransomware,
            summary: format!(
                "pid {} entered ransomware stage with {} renames and {} high-entropy writes",
                event.process.pid, signals.rename_count, signals.high_entropy_writes
            ),
            severity: Severity::Critical,
            decision: DecisionKind::Response,
            storyline_id: event
                .storyline
                .as_ref()
                .map(|storyline| storyline.storyline_id),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AsrRule {
    OfficeChildScript,
    UnsignedScript,
    CredentialDump,
}

pub struct AsrPolicyDomain {
    enabled: HashSet<AsrRule>,
}

impl Default for AsrPolicyDomain {
    fn default() -> Self {
        Self {
            enabled: HashSet::from([
                AsrRule::OfficeChildScript,
                AsrRule::UnsignedScript,
                AsrRule::CredentialDump,
            ]),
        }
    }
}

impl AsrPolicyDomain {
    fn evaluate(&self, event: &NormalizedEvent) -> Vec<DetectionFinding> {
        let mut findings = Vec::new();
        let parent_process = match &event.payload {
            EventPayload::Generic(values) => values.get("parent_process").cloned(),
            _ => None,
        };

        if self.enabled.contains(&AsrRule::OfficeChildScript)
            && matches!(
                parent_process.as_deref(),
                Some("WINWORD.EXE") | Some("EXCEL.EXE") | Some("POWERPNT.EXE")
            )
            && matches!(
                event.process.name.as_str(),
                "powershell.exe" | "wscript.exe" | "cmd.exe"
            )
        {
            findings.push(DetectionFinding {
                category: DetectionCategory::Asr,
                summary: format!(
                    "ASR blocked Office child process launch: {} -> {}",
                    parent_process.unwrap_or_default(),
                    event.process.name
                ),
                severity: Severity::High,
                decision: DecisionKind::Response,
                storyline_id: event
                    .storyline
                    .as_ref()
                    .map(|storyline| storyline.storyline_id),
            });
        }

        if self.enabled.contains(&AsrRule::UnsignedScript)
            && event.event_type == EventType::Script
            && !event
                .process
                .signature
                .as_ref()
                .is_some_and(|signature| signature.trusted)
        {
            findings.push(DetectionFinding {
                category: DetectionCategory::Asr,
                summary: "ASR blocked unsigned script execution".to_string(),
                severity: Severity::High,
                decision: DecisionKind::Alert,
                storyline_id: event
                    .storyline
                    .as_ref()
                    .map(|storyline| storyline.storyline_id),
            });
        }

        if self.enabled.contains(&AsrRule::CredentialDump)
            && event.process.cmdline.to_lowercase().contains("lsass")
        {
            findings.push(DetectionFinding {
                category: DetectionCategory::Asr,
                summary: "ASR blocked credential dumping command line".to_string(),
                severity: Severity::Critical,
                decision: DecisionKind::Response,
                storyline_id: event
                    .storyline
                    .as_ref()
                    .map(|storyline| storyline.storyline_id),
            });
        }

        findings
    }
}

#[derive(Default)]
pub struct IdentityThreatDetector {
    failed_logons_by_ip: HashMap<String, u32>,
}

impl IdentityThreatDetector {
    fn evaluate(&mut self, event: &NormalizedEvent) -> Option<DetectionFinding> {
        let EventPayload::Auth(AuthContext {
            source_ip,
            result,
            elevation,
            logon_type,
            ..
        }) = &event.payload
        else {
            return None;
        };

        if result.as_deref() == Some("failure") {
            let source = source_ip.clone().unwrap_or_else(|| "unknown".to_string());
            let failures = self.failed_logons_by_ip.entry(source.clone()).or_insert(0);
            *failures += 1;
            if *failures >= 3 {
                return Some(DetectionFinding {
                    category: DetectionCategory::Identity,
                    summary: format!("identity brute-force suspected from {source}"),
                    severity: Severity::High,
                    decision: DecisionKind::Alert,
                    storyline_id: event
                        .storyline
                        .as_ref()
                        .map(|storyline| storyline.storyline_id),
                });
            }
        }

        if result.as_deref() == Some("success")
            && elevation.as_deref() == Some("admin")
            && logon_type.as_deref() == Some("remote")
        {
            return Some(DetectionFinding {
                category: DetectionCategory::Identity,
                summary: "privileged remote identity access detected".to_string(),
                severity: Severity::Critical,
                decision: DecisionKind::Response,
                storyline_id: event
                    .storyline
                    .as_ref()
                    .map(|storyline| storyline.storyline_id),
            });
        }

        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeceptionKind {
    CanaryFile,
    CanaryDns,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeceptionObject {
    pub kind: DeceptionKind,
    pub locator: String,
    pub description: String,
}

#[derive(Default)]
pub struct DeceptionRegistry {
    objects: Vec<DeceptionObject>,
}

impl DeceptionRegistry {
    pub fn register(&mut self, object: DeceptionObject) {
        self.objects.push(object);
    }

    fn evaluate(&self, event: &NormalizedEvent) -> Option<DetectionFinding> {
        self.objects.iter().find_map(|object| {
            let matched = match (&object.kind, &event.payload) {
                (DeceptionKind::CanaryFile, EventPayload::File(file)) => {
                    file.path.display().to_string() == object.locator
                }
                (
                    DeceptionKind::CanaryDns,
                    EventPayload::Network(NetworkContext { dns_query, .. }),
                ) => dns_query.as_deref() == Some(object.locator.as_str()),
                _ => false,
            };

            matched.then(|| DetectionFinding {
                category: DetectionCategory::Deception,
                summary: format!("deception object triggered: {}", object.description),
                severity: Severity::Critical,
                decision: DecisionKind::Response,
                storyline_id: event
                    .storyline
                    .as_ref()
                    .map(|storyline| storyline.storyline_id),
            })
        })
    }
}

#[derive(Default)]
pub struct SpecializedDetectionEngine {
    pub ransomware: RansomwareStateMachine,
    pub asr: AsrPolicyDomain,
    pub identity: IdentityThreatDetector,
    pub deception: DeceptionRegistry,
}

impl SpecializedDetectionEngine {
    pub fn evaluate(&mut self, event: &NormalizedEvent) -> Vec<DetectionFinding> {
        let mut findings = Vec::new();
        if let Some(finding) = self.ransomware.evaluate(event) {
            findings.push(finding);
        }
        findings.extend(self.asr.evaluate(event));
        if let Some(finding) = self.identity.evaluate(event) {
            findings.push(finding);
        }
        if let Some(finding) = self.deception.evaluate(event) {
            findings.push(finding);
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::{DeceptionKind, DeceptionObject, DetectionCategory, SpecializedDetectionEngine};
    use aegis_model::{
        AuthContext, EventPayload, EventType, FileContext, NormalizedEvent, Priority,
        ProcessContext, Severity, StorylineContext,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn base_event(event_type: EventType) -> NormalizedEvent {
        let mut event = NormalizedEvent::new(
            100,
            event_type,
            Priority::High,
            Severity::High,
            ProcessContext {
                pid: 7,
                name: "powershell.exe".to_string(),
                ..ProcessContext::default()
            },
            EventPayload::None,
        );
        event.storyline = Some(StorylineContext {
            storyline_id: 88,
            processes: vec![7],
            tactics: vec!["execution".to_string()],
            techniques: vec!["T1059".to_string()],
            kill_chain_phase: aegis_model::KillChainPhase::Exploitation,
            narrative: "exec".to_string(),
        });
        event
    }

    #[test]
    fn ransomware_detection_aggregates_multi_signal_state() {
        let mut engine = SpecializedDetectionEngine::default();
        let mut first = base_event(EventType::FileWrite);
        first.payload = EventPayload::File(FileContext {
            path: PathBuf::from("/tmp/a.txt"),
            entropy: Some(7.5),
            action: Some("rename".to_string()),
            ..FileContext::default()
        });
        let mut second = first.clone();
        second.payload = EventPayload::File(FileContext {
            path: PathBuf::from("/tmp/.aegis-canary"),
            entropy: Some(8.0),
            action: Some("rename".to_string()),
            ..FileContext::default()
        });

        assert!(engine.evaluate(&first).is_empty());
        let findings = engine.evaluate(&second);

        assert!(findings
            .iter()
            .any(|finding| finding.category == DetectionCategory::Ransomware));
    }

    #[test]
    fn asr_policy_hits_office_child_script() {
        let mut engine = SpecializedDetectionEngine::default();
        let mut event = base_event(EventType::ProcessCreate);
        event.payload = EventPayload::Generic(BTreeMap::from([(
            "parent_process".to_string(),
            "WINWORD.EXE".to_string(),
        )]));

        let findings = engine.evaluate(&event);

        assert!(findings
            .iter()
            .any(|finding| finding.category == DetectionCategory::Asr));
    }

    #[test]
    fn identity_detector_alerts_on_bruteforce() {
        let mut engine = SpecializedDetectionEngine::default();
        let mut event = base_event(EventType::Auth);
        event.payload = EventPayload::Auth(AuthContext {
            source_ip: Some("10.0.0.8".to_string()),
            result: Some("failure".to_string()),
            ..AuthContext::default()
        });

        assert!(engine.evaluate(&event).is_empty());
        assert!(engine.evaluate(&event).is_empty());
        let findings = engine.evaluate(&event);

        assert!(findings
            .iter()
            .any(|finding| finding.category == DetectionCategory::Identity));
    }

    #[test]
    fn deception_registry_triggers_on_canary_path() {
        let mut engine = SpecializedDetectionEngine::default();
        engine.deception.register(DeceptionObject {
            kind: DeceptionKind::CanaryFile,
            locator: "/srv/honey/token.txt".to_string(),
            description: "filesystem canary".to_string(),
        });
        let mut event = base_event(EventType::FileWrite);
        event.payload = EventPayload::File(FileContext {
            path: PathBuf::from("/srv/honey/token.txt"),
            ..FileContext::default()
        });

        let findings = engine.evaluate(&event);

        assert!(findings
            .iter()
            .any(|finding| finding.category == DetectionCategory::Deception));
        assert_eq!(findings[0].storyline_id, Some(88));
    }
}
