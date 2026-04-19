use crate::adaptive_whitelist::{AdaptiveWhitelist, AdaptiveWhitelistEntry};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreatFeedback {
    pub rule_id: String,
    pub process_hash: String,
    pub target_path: Option<String>,
    pub allow_ttl_secs: u64,
}

pub struct ThreatFeedbackApplier {
    whitelist: AdaptiveWhitelist,
}

impl ThreatFeedbackApplier {
    pub fn new(max_entries: usize) -> Self {
        Self {
            whitelist: AdaptiveWhitelist::new(max_entries),
        }
    }

    pub fn apply(&mut self, feedback: ThreatFeedback, now_unix: u64) {
        self.whitelist.insert(AdaptiveWhitelistEntry {
            rule_id: feedback.rule_id,
            process_hash: feedback.process_hash,
            target_path: feedback.target_path,
            expires_at_unix: now_unix + feedback.allow_ttl_secs,
        });
    }

    pub fn contains(
        &self,
        rule_id: &str,
        process_hash: &str,
        target_path: Option<&str>,
        now_unix: u64,
    ) -> bool {
        self.whitelist
            .contains(rule_id, process_hash, target_path, now_unix)
    }

    pub fn len(&self) -> usize {
        self.whitelist.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{ThreatFeedback, ThreatFeedbackApplier};

    #[test]
    fn threat_feedback_applies_entries_to_adaptive_whitelist() {
        let mut applier = ThreatFeedbackApplier::new(4);
        applier.apply(
            ThreatFeedback {
                rule_id: "rule-123".to_string(),
                process_hash: "hash-abc".to_string(),
                target_path: Some("/tmp/tool".to_string()),
                allow_ttl_secs: 60,
            },
            1_000,
        );

        assert!(applier.contains("rule-123", "hash-abc", Some("/tmp/tool"), 1_010));
    }
}
