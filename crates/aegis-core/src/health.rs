use aegis_model::{AgentHealth, LineageCounters, RuntimeHealthSignals};
use std::collections::BTreeMap;

pub struct HealthReporter;

impl HealthReporter {
    pub fn build_snapshot(
        agent_version: &str,
        policy_version: &str,
        ruleset_version: &str,
        model_version: &str,
        cpu_percent_p95: f32,
        memory_rss_mb: u64,
        queue_depths: BTreeMap<String, usize>,
        lineage_counters: LineageCounters,
        runtime_signals: RuntimeHealthSignals,
    ) -> AgentHealth {
        let dropped_events_total = lineage_counters.rb_dropped;

        AgentHealth {
            agent_version: agent_version.to_string(),
            policy_version: policy_version.to_string(),
            ruleset_version: ruleset_version.to_string(),
            model_version: model_version.to_string(),
            cpu_percent_p95,
            memory_rss_mb,
            queue_depths,
            dropped_events_total,
            lineage_counters,
            runtime_signals,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HealthReporter;
    use aegis_model::{CommunicationChannelKind, LineageCounters, RuntimeHealthSignals};
    use std::collections::BTreeMap;

    #[test]
    fn health_snapshot_uses_lineage_drop_counter() {
        let mut counters = LineageCounters::default();
        counters.rb_dropped = 7;

        let snapshot = HealthReporter::build_snapshot(
            "0.1.0",
            "policy-1",
            "ruleset-1",
            "model-1",
            2.5,
            128,
            BTreeMap::from([("event".to_string(), 32usize)]),
            counters,
            RuntimeHealthSignals {
                communication_channel: CommunicationChannelKind::Grpc,
                adaptive_whitelist_size: 4,
                etw_tamper_detected: false,
                amsi_tamper_detected: false,
                bpf_integrity_pass: true,
            },
        );

        assert_eq!(snapshot.dropped_events_total, 7);
        assert_eq!(snapshot.queue_depths["event"], 32);
        assert_eq!(
            snapshot.runtime_signals.communication_channel,
            CommunicationChannelKind::Grpc
        );
    }
}
