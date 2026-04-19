use aegis_model::{EventType, NormalizedEvent};
use std::collections::{HashMap, VecDeque};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemporalObservation {
    pub event_id: Uuid,
    pub lineage_id: Uuid,
    pub timestamp_ns: u64,
    pub event_type: EventType,
    pub process_pid: u32,
    pub risk_score: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemporalSnapshot {
    pub key: String,
    pub observations: Vec<TemporalObservation>,
}

#[derive(Clone, Debug)]
pub struct TemporalStateBuffer {
    window_ns: u64,
    capacity_per_key: usize,
    entries: HashMap<String, VecDeque<TemporalObservation>>,
}

impl TemporalStateBuffer {
    pub fn new(window_ns: u64, capacity_per_key: usize) -> Self {
        Self {
            window_ns,
            capacity_per_key,
            entries: HashMap::new(),
        }
    }

    pub fn ingest(&mut self, key: impl Into<String>, event: &NormalizedEvent) -> TemporalSnapshot {
        let key = key.into();
        let observation = TemporalObservation {
            event_id: event.event_id,
            lineage_id: event.lineage_id,
            timestamp_ns: event.timestamp_ns,
            event_type: event.event_type,
            process_pid: event.process.pid,
            risk_score: event.enrichment.risk_score,
        };

        let entries = self.entries.entry(key.clone()).or_default();
        entries.push_back(observation);
        Self::prune(entries, self.window_ns, self.capacity_per_key);

        TemporalSnapshot {
            key,
            observations: entries.iter().cloned().collect(),
        }
    }

    pub fn recent(&self, key: &str) -> Vec<TemporalObservation> {
        self.entries
            .get(key)
            .map(|entries| entries.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn sequence_contains(&self, key: &str, expected: &[EventType]) -> bool {
        let Some(entries) = self.entries.get(key) else {
            return false;
        };

        let mut cursor = 0usize;
        for observation in entries {
            if cursor < expected.len() && observation.event_type == expected[cursor] {
                cursor += 1;
            }
        }

        cursor == expected.len()
    }

    fn prune(entries: &mut VecDeque<TemporalObservation>, window_ns: u64, capacity_per_key: usize) {
        let Some(latest) = entries.back().map(|entry| entry.timestamp_ns) else {
            return;
        };
        let min_timestamp = latest.saturating_sub(window_ns);

        while entries
            .front()
            .is_some_and(|entry| entry.timestamp_ns < min_timestamp)
        {
            entries.pop_front();
        }

        while entries.len() > capacity_per_key {
            entries.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TemporalStateBuffer;
    use aegis_model::{
        EventPayload, EventType, NormalizedEvent, Priority, ProcessContext, Severity,
    };

    fn event_at(timestamp_ns: u64, event_type: EventType, pid: u32) -> NormalizedEvent {
        let mut event = NormalizedEvent::new(
            timestamp_ns,
            event_type,
            Priority::High,
            Severity::Medium,
            ProcessContext {
                pid,
                name: format!("proc-{pid}"),
                ..ProcessContext::default()
            },
            EventPayload::None,
        );
        event.enrichment.risk_score = 70;
        event
    }

    #[test]
    fn temporal_buffer_evicts_expired_observations() {
        let mut buffer = TemporalStateBuffer::new(100, 8);
        buffer.ingest("pid:7", &event_at(100, EventType::ProcessCreate, 7));
        buffer.ingest("pid:7", &event_at(250, EventType::NetConnect, 7));

        let recent = buffer.recent("pid:7");

        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].event_type, EventType::NetConnect);
    }

    #[test]
    fn temporal_buffer_detects_event_sequence() {
        let mut buffer = TemporalStateBuffer::new(1_000, 8);
        buffer.ingest("storyline:42", &event_at(100, EventType::ProcessCreate, 42));
        buffer.ingest("storyline:42", &event_at(150, EventType::FileWrite, 42));
        buffer.ingest("storyline:42", &event_at(200, EventType::NetConnect, 42));

        assert!(buffer.sequence_contains(
            "storyline:42",
            &[
                EventType::ProcessCreate,
                EventType::FileWrite,
                EventType::NetConnect
            ]
        ));
    }
}
