use aegis_model::{DecisionKind, EventPayload, NetworkContext, NormalizedEvent, Severity};
use std::collections::{BTreeSet, HashMap};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoftwareComponent {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CveRecord {
    pub cve_id: String,
    pub package: String,
    pub vulnerable_below: String,
    pub severity: Severity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VulnerabilityMatch {
    pub cve_id: String,
    pub package: String,
    pub installed_version: String,
    pub severity: Severity,
}

#[derive(Default)]
pub struct VulnerabilityMatcher {
    advisories: Vec<CveRecord>,
}

impl VulnerabilityMatcher {
    pub fn add_advisory(&mut self, advisory: CveRecord) {
        self.advisories.push(advisory);
    }

    pub fn match_inventory(&self, components: &[SoftwareComponent]) -> Vec<VulnerabilityMatch> {
        let mut matches = Vec::new();
        for component in components {
            for advisory in &self.advisories {
                if component.name == advisory.package
                    && version_lt(&component.version, &advisory.vulnerable_below)
                {
                    matches.push(VulnerabilityMatch {
                        cve_id: advisory.cve_id.clone(),
                        package: component.name.clone(),
                        installed_version: component.version.clone(),
                        severity: advisory.severity,
                    });
                }
            }
        }
        matches
    }
}

fn version_lt(left: &str, right: &str) -> bool {
    let left = parse_version(left);
    let right = parse_version(right);
    left < right
}

fn parse_version(value: &str) -> Vec<u32> {
    value
        .split('.')
        .map(|part| part.parse::<u32>().unwrap_or_default())
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedAsset {
    pub ip: String,
    pub dns_names: Vec<String>,
    pub sni_names: Vec<String>,
    pub protocols: Vec<String>,
    pub sightings: u32,
    pub last_seen_ns: u64,
}

#[derive(Default)]
pub struct PassiveDiscoveryCache {
    assets: HashMap<String, ObservedAsset>,
}

impl PassiveDiscoveryCache {
    pub fn observe(&mut self, event: &NormalizedEvent) {
        let EventPayload::Network(NetworkContext {
            dst_ip,
            protocol,
            dns_query,
            sni,
            ..
        }) = &event.payload
        else {
            return;
        };
        let Some(ip) = dst_ip.clone() else {
            return;
        };

        let asset = self
            .assets
            .entry(ip.clone())
            .or_insert_with(|| ObservedAsset {
                ip,
                dns_names: Vec::new(),
                sni_names: Vec::new(),
                protocols: Vec::new(),
                sightings: 0,
                last_seen_ns: 0,
            });
        asset.sightings += 1;
        asset.last_seen_ns = event.timestamp_ns;

        let mut dns_names = asset.dns_names.iter().cloned().collect::<BTreeSet<_>>();
        let mut sni_names = asset.sni_names.iter().cloned().collect::<BTreeSet<_>>();
        let mut protocols = asset.protocols.iter().cloned().collect::<BTreeSet<_>>();
        if let Some(name) = dns_query {
            dns_names.insert(name.clone());
        }
        if let Some(name) = sni {
            sni_names.insert(name.clone());
        }
        if let Some(protocol) = protocol {
            protocols.insert(protocol.clone());
        }
        asset.dns_names = dns_names.into_iter().collect();
        asset.sni_names = sni_names.into_iter().collect();
        asset.protocols = protocols.into_iter().collect();
    }

    pub fn asset(&self, ip: &str) -> Option<&ObservedAsset> {
        self.assets.get(ip)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AiRiskCategory {
    ToolUsage,
    ModelIntegrity,
    Dlp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AiMonitorFinding {
    pub category: AiRiskCategory,
    pub summary: String,
    pub severity: Severity,
    pub decision: DecisionKind,
}

#[derive(Default)]
pub struct AiMonitor {
    expected_model_hashes: HashMap<String, String>,
}

impl AiMonitor {
    pub fn register_model_hash(&mut self, model_id: impl Into<String>, hash: impl Into<String>) {
        self.expected_model_hashes
            .insert(model_id.into(), hash.into());
    }

    pub fn evaluate(&self, event: &NormalizedEvent) -> Vec<AiMonitorFinding> {
        let mut findings = Vec::new();

        if event.process.cmdline.contains("openai")
            || event.process.cmdline.contains("anthropic")
            || event.process.name.eq_ignore_ascii_case("ollama")
        {
            findings.push(AiMonitorFinding {
                category: AiRiskCategory::ToolUsage,
                summary: format!("AI tool usage observed via {}", event.process.name),
                severity: Severity::Medium,
                decision: DecisionKind::Alert,
            });
        }

        if let EventPayload::Generic(values) = &event.payload {
            if let (Some(model_id), Some(model_hash)) =
                (values.get("model_id"), values.get("model_hash"))
            {
                if self
                    .expected_model_hashes
                    .get(model_id)
                    .is_some_and(|expected| expected != model_hash)
                {
                    findings.push(AiMonitorFinding {
                        category: AiRiskCategory::ModelIntegrity,
                        summary: format!("model hash mismatch detected for {model_id}"),
                        severity: Severity::Critical,
                        decision: DecisionKind::Response,
                    });
                }
            }

            if let Some(prompt) = values.get("prompt") {
                let contains_sensitive = ["api_key", "secret", "ssn"]
                    .iter()
                    .any(|marker| prompt.to_lowercase().contains(marker));
                let external_ip = values
                    .get("dst_ip")
                    .is_some_and(|ip| !is_private_ip(ip.as_str()));
                if contains_sensitive && external_ip {
                    findings.push(AiMonitorFinding {
                        category: AiRiskCategory::Dlp,
                        summary: "sensitive data egress via AI prompt".to_string(),
                        severity: Severity::High,
                        decision: DecisionKind::Response,
                    });
                }
            }
        }

        findings
    }
}

fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("10.")
        || ip.starts_with("127.")
        || ip.starts_with("192.168.")
        || ip
            .strip_prefix("172.")
            .and_then(|rest| rest.split('.').next())
            .and_then(|octet| octet.parse::<u8>().ok())
            .is_some_and(|octet| (16..=31).contains(&octet))
}

#[cfg(test)]
mod tests {
    use super::{
        AiMonitor, AiRiskCategory, CveRecord, PassiveDiscoveryCache, SoftwareComponent,
        VulnerabilityMatcher,
    };
    use aegis_model::{
        EventPayload, EventType, NetworkContext, NormalizedEvent, Priority, ProcessContext,
        Severity,
    };
    use std::collections::BTreeMap;

    fn network_event() -> NormalizedEvent {
        NormalizedEvent::new(
            100,
            EventType::NetConnect,
            Priority::High,
            Severity::Medium,
            ProcessContext {
                pid: 9,
                name: "curl".to_string(),
                cmdline: "curl https://api.example".to_string(),
                ..ProcessContext::default()
            },
            EventPayload::Network(NetworkContext {
                dst_ip: Some("203.0.113.10".to_string()),
                protocol: Some("tcp".to_string()),
                dns_query: Some("api.example".to_string()),
                sni: Some("api.example".to_string()),
                ..NetworkContext::default()
            }),
        )
    }

    #[test]
    fn vulnerability_matcher_matches_inventory_against_advisory() {
        let mut matcher = VulnerabilityMatcher::default();
        matcher.add_advisory(CveRecord {
            cve_id: "CVE-2026-0001".to_string(),
            package: "openssl".to_string(),
            vulnerable_below: "3.0.9".to_string(),
            severity: Severity::High,
        });

        let matches = matcher.match_inventory(&[SoftwareComponent {
            name: "openssl".to_string(),
            version: "3.0.7".to_string(),
        }]);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].cve_id, "CVE-2026-0001");
    }

    #[test]
    fn passive_discovery_aggregates_network_assets() {
        let mut cache = PassiveDiscoveryCache::default();
        let event = network_event();
        cache.observe(&event);
        cache.observe(&event);

        let asset = cache.asset("203.0.113.10").expect("asset");

        assert_eq!(asset.sightings, 2);
        assert_eq!(asset.dns_names, vec!["api.example".to_string()]);
        assert_eq!(asset.protocols, vec!["tcp".to_string()]);
    }

    #[test]
    fn ai_monitor_flags_model_integrity_mismatch() {
        let mut monitor = AiMonitor::default();
        monitor.register_model_hash("llm-1", "expected-hash");
        let mut event = network_event();
        event.process.name = "ollama".to_string();
        event.process.cmdline = "ollama run llm-1".to_string();
        event.payload = EventPayload::Generic(BTreeMap::from([
            ("model_id".to_string(), "llm-1".to_string()),
            ("model_hash".to_string(), "tampered-hash".to_string()),
        ]));

        let findings = monitor.evaluate(&event);

        assert!(findings
            .iter()
            .any(|finding| finding.category == AiRiskCategory::ModelIntegrity));
    }

    #[test]
    fn ai_monitor_flags_sensitive_prompt_egress() {
        let monitor = AiMonitor::default();
        let mut event = network_event();
        event.payload = EventPayload::Generic(BTreeMap::from([
            (
                "prompt".to_string(),
                "send api_key=abc123 to summarizer".to_string(),
            ),
            ("dst_ip".to_string(), "198.51.100.20".to_string()),
        ]));

        let findings = monitor.evaluate(&event);

        assert!(findings
            .iter()
            .any(|finding| finding.category == AiRiskCategory::Dlp));
    }
}
