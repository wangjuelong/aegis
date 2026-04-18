use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdaptiveWhitelistEntry {
    pub rule_id: String,
    pub process_hash: String,
    pub target_path: Option<String>,
    pub expires_at_unix: u64,
}

pub struct AdaptiveWhitelist {
    max_entries: usize,
    entries: VecDeque<AdaptiveWhitelistEntry>,
}

impl AdaptiveWhitelist {
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries,
            entries: VecDeque::new(),
        }
    }

    pub fn insert(&mut self, entry: AdaptiveWhitelistEntry) {
        self.purge_expired(Self::now_unix());
        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    pub fn contains(
        &self,
        rule_id: &str,
        process_hash: &str,
        target_path: Option<&str>,
        now_unix: u64,
    ) -> bool {
        self.entries.iter().any(|entry| {
            entry.expires_at_unix >= now_unix
                && entry.rule_id == rule_id
                && entry.process_hash == process_hash
                && entry.target_path.as_deref() == target_path
        })
    }

    pub fn purge_expired(&mut self, now_unix: u64) {
        self.entries
            .retain(|entry| entry.expires_at_unix >= now_unix);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::{AdaptiveWhitelist, AdaptiveWhitelistEntry};

    #[test]
    fn evicts_oldest_entry_when_capacity_is_reached() {
        let mut whitelist = AdaptiveWhitelist::new(1);
        whitelist.insert(AdaptiveWhitelistEntry {
            rule_id: "rule-1".to_string(),
            process_hash: "hash-1".to_string(),
            target_path: Some("/tmp/a".to_string()),
            expires_at_unix: 999,
        });
        whitelist.insert(AdaptiveWhitelistEntry {
            rule_id: "rule-2".to_string(),
            process_hash: "hash-2".to_string(),
            target_path: Some("/tmp/b".to_string()),
            expires_at_unix: 999,
        });

        assert_eq!(whitelist.len(), 1);
        assert!(whitelist.contains("rule-2", "hash-2", Some("/tmp/b"), 100));
    }
}
