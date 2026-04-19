use aegis_model::{IsolationRulesV2, NetworkTarget};
use aegis_platform::PlatformRuntime;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockTargetKind {
    Hash(String),
    Pid(u32),
    Path(PathBuf),
    Network(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDecision {
    pub target: BlockTargetKind,
    pub expires_at_unix: u64,
    pub reason: String,
}

#[derive(Default)]
pub struct BlockDecisionMap {
    entries: Vec<BlockDecision>,
}

impl BlockDecisionMap {
    pub fn insert(&mut self, decision: BlockDecision) {
        self.entries.push(decision);
    }

    pub fn contains(&self, target: &BlockTargetKind, now_unix: u64) -> bool {
        self.entries
            .iter()
            .any(|entry| &entry.target == target && entry.expires_at_unix >= now_unix)
    }

    pub fn purge_expired(&mut self, now_unix: u64) {
        self.entries
            .retain(|entry| entry.expires_at_unix >= now_unix);
    }

    pub fn iter_active(&self, now_unix: u64) -> impl Iterator<Item = &BlockDecision> {
        self.entries
            .iter()
            .filter(move |entry| entry.expires_at_unix >= now_unix)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum IsolationMode {
    Full,
    ManagementOnly,
    BreakGlass,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsolationPolicy {
    pub mode: IsolationMode,
    pub ttl: Duration,
    pub allowed_control_plane_ips: Vec<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainmentAuditRecord {
    pub audit_id: Uuid,
    pub mode: IsolationMode,
    pub detail: String,
    pub timestamp_ns: u64,
}

pub struct FirewallPolicyOrchestrator<'a, P: PlatformRuntime> {
    platform: &'a P,
}

impl<'a, P: PlatformRuntime> FirewallPolicyOrchestrator<'a, P> {
    pub fn new(platform: &'a P) -> Self {
        Self { platform }
    }

    pub fn apply_block_decisions(
        &self,
        decisions: &BlockDecisionMap,
        now_unix: u64,
    ) -> Result<Vec<ContainmentAuditRecord>> {
        let mut audits = Vec::new();
        for decision in decisions.iter_active(now_unix) {
            let ttl = Duration::from_secs(decision.expires_at_unix.saturating_sub(now_unix));
            match &decision.target {
                BlockTargetKind::Hash(hash) => self.platform.block_hash(hash, ttl)?,
                BlockTargetKind::Pid(pid) => self.platform.block_pid(*pid, ttl)?,
                BlockTargetKind::Path(path) => self.platform.block_path(path, ttl)?,
                BlockTargetKind::Network(value) => self.platform.block_network(
                    &NetworkTarget {
                        value: value.clone(),
                    },
                    ttl,
                )?,
            }
            audits.push(self.audit(
                IsolationMode::ManagementOnly,
                format!("applied block decision: {}", decision.reason),
            ));
        }
        Ok(audits)
    }

    pub fn apply_isolation(&self, policy: &IsolationPolicy) -> Result<ContainmentAuditRecord> {
        match policy.mode {
            IsolationMode::Full | IsolationMode::ManagementOnly => {
                self.platform.network_isolate(&IsolationRulesV2 {
                    ttl: policy.ttl,
                    allowed_control_plane_ips: policy.allowed_control_plane_ips.clone(),
                })?;
                Ok(self.audit(
                    policy.mode,
                    format!(
                        "network isolation applied with {} control plane exceptions",
                        policy.allowed_control_plane_ips.len()
                    ),
                ))
            }
            IsolationMode::BreakGlass => {
                self.platform.network_release()?;
                Ok(self.audit(
                    IsolationMode::BreakGlass,
                    format!("break-glass release granted: {}", policy.reason),
                ))
            }
        }
    }

    fn audit(&self, mode: IsolationMode, detail: String) -> ContainmentAuditRecord {
        ContainmentAuditRecord {
            audit_id: Uuid::now_v7(),
            mode,
            detail,
            timestamp_ns: now_unix_ns(),
        }
    }
}

fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::{
        BlockDecision, BlockDecisionMap, BlockTargetKind, FirewallPolicyOrchestrator,
        IsolationMode, IsolationPolicy,
    };
    use aegis_platform::{MockAction, MockPlatform};
    use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn block_decision_map_respects_ttl() {
        let mut map = BlockDecisionMap::default();
        let target = BlockTargetKind::Hash("abc".to_string());
        map.insert(BlockDecision {
            target: target.clone(),
            expires_at_unix: 120,
            reason: "malware hash".to_string(),
        });

        assert!(map.contains(&target, 100));
        map.purge_expired(121);
        assert!(!map.contains(&target, 121));
    }

    #[test]
    fn firewall_orchestrator_applies_block_and_isolation_actions() {
        let platform = MockPlatform::linux();
        let orchestrator = FirewallPolicyOrchestrator::new(&platform);
        let mut decisions = BlockDecisionMap::default();
        decisions.insert(BlockDecision {
            target: BlockTargetKind::Hash("deadbeef".to_string()),
            expires_at_unix: 200,
            reason: "known malware".to_string(),
        });
        decisions.insert(BlockDecision {
            target: BlockTargetKind::Path(PathBuf::from("/tmp/dropper")),
            expires_at_unix: 200,
            reason: "blocked path".to_string(),
        });

        let audits = orchestrator
            .apply_block_decisions(&decisions, 100)
            .expect("apply blocks");
        let isolation = orchestrator
            .apply_isolation(&IsolationPolicy {
                mode: IsolationMode::ManagementOnly,
                ttl: Duration::from_secs(300),
                allowed_control_plane_ips: vec!["10.0.0.5".to_string()],
                reason: "contain host".to_string(),
            })
            .expect("apply isolation");

        let actions = platform.take_actions();
        assert_eq!(
            actions,
            vec![
                MockAction::BlockHash("deadbeef".to_string()),
                MockAction::BlockPath(PathBuf::from("/tmp/dropper")),
                MockAction::NetworkIsolate,
            ]
        );
        assert_eq!(audits.len(), 2);
        assert_eq!(isolation.mode, IsolationMode::ManagementOnly);
    }

    #[test]
    fn firewall_orchestrator_records_break_glass_release() {
        let platform = MockPlatform::windows();
        let orchestrator = FirewallPolicyOrchestrator::new(&platform);

        let audit = orchestrator
            .apply_isolation(&IsolationPolicy {
                mode: IsolationMode::BreakGlass,
                ttl: Duration::from_secs(0),
                allowed_control_plane_ips: Vec::new(),
                reason: "incident commander override".to_string(),
            })
            .expect("break glass");

        let actions = platform.take_actions();
        assert_eq!(actions, vec![MockAction::NetworkRelease]);
        assert_eq!(audit.mode, IsolationMode::BreakGlass);
        assert!(audit.detail.contains("override"));
    }
}
