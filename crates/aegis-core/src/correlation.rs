use aegis_model::{KillChainPhase, NormalizedEvent, Severity, Storyline};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
struct CorrelatedEventRecord {
    event_id: Uuid,
    lineage_id: Uuid,
    hostname: String,
    root_pid: u32,
    timestamp_ns: u64,
}

#[derive(Clone, Debug)]
pub struct CorrelationCache {
    max_entries_per_shard: usize,
    by_host: HashMap<String, VecDeque<CorrelatedEventRecord>>,
    by_root_pid: HashMap<u32, VecDeque<CorrelatedEventRecord>>,
    by_lineage: HashMap<Uuid, VecDeque<CorrelatedEventRecord>>,
}

impl CorrelationCache {
    pub fn new(max_entries_per_shard: usize) -> Self {
        Self {
            max_entries_per_shard,
            by_host: HashMap::new(),
            by_root_pid: HashMap::new(),
            by_lineage: HashMap::new(),
        }
    }

    pub fn ingest(&mut self, event: &NormalizedEvent) {
        let record = CorrelatedEventRecord {
            event_id: event.event_id,
            lineage_id: event.lineage_id,
            hostname: event.host.hostname.clone(),
            root_pid: root_pid(event),
            timestamp_ns: event.timestamp_ns,
        };

        self.push_host(record.hostname.clone(), record.clone());
        self.push_root(record.root_pid, record.clone());
        self.push_lineage(record.lineage_id, record);
    }

    pub fn related_event_ids(&self, event: &NormalizedEvent) -> Vec<Uuid> {
        let mut ids = HashSet::new();
        let hostname = &event.host.hostname;
        let root_pid = root_pid(event);

        if let Some(records) = self.by_host.get(hostname) {
            ids.extend(records.iter().map(|record| record.event_id));
        }
        if let Some(records) = self.by_root_pid.get(&root_pid) {
            ids.extend(records.iter().map(|record| record.event_id));
        }
        if let Some(records) = self.by_lineage.get(&event.lineage_id) {
            ids.extend(records.iter().map(|record| record.event_id));
        }

        ids.into_iter().collect()
    }

    fn push_host(&mut self, key: String, record: CorrelatedEventRecord) {
        let entries = self.by_host.entry(key).or_default();
        entries.push_back(record);
        trim(entries, self.max_entries_per_shard);
    }

    fn push_root(&mut self, key: u32, record: CorrelatedEventRecord) {
        let entries = self.by_root_pid.entry(key).or_default();
        entries.push_back(record);
        trim(entries, self.max_entries_per_shard);
    }

    fn push_lineage(&mut self, key: Uuid, record: CorrelatedEventRecord) {
        let entries = self.by_lineage.entry(key).or_default();
        entries.push_back(record);
        trim(entries, self.max_entries_per_shard);
    }
}

fn trim(entries: &mut VecDeque<CorrelatedEventRecord>, max_entries: usize) {
    while entries.len() > max_entries {
        entries.pop_front();
    }
}

fn root_pid(event: &NormalizedEvent) -> u32 {
    event
        .process
        .tree
        .first()
        .copied()
        .unwrap_or(event.process.pid)
}

pub struct StorylineEngine {
    next_id: u64,
}

impl StorylineEngine {
    pub fn new() -> Self {
        Self { next_id: 1 }
    }

    pub fn merge(&mut self, events: &[NormalizedEvent]) -> Option<Storyline> {
        let root_event = events.first()?.event_id;
        let id = self.next_id;
        self.next_id += 1;

        let events_ids = events
            .iter()
            .map(|event| event.event_id)
            .collect::<Vec<_>>();
        let processes = events
            .iter()
            .flat_map(|event| {
                let mut values = event.process.tree.clone();
                values.push(event.process.pid);
                values
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let techniques = events
            .iter()
            .flat_map(|event| event.enrichment.mitre_ttps.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let tactics = events
            .iter()
            .filter_map(|event| event.storyline.as_ref())
            .flat_map(|storyline| storyline.tactics.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let severity = events
            .iter()
            .map(|event| event.severity)
            .max()
            .unwrap_or(Severity::Info);
        let kill_chain_phase = events
            .iter()
            .filter_map(|event| event.storyline.as_ref())
            .map(|storyline| storyline.kill_chain_phase)
            .find(|phase| *phase != KillChainPhase::Unknown)
            .unwrap_or(KillChainPhase::Unknown);
        let names = events
            .iter()
            .map(|event| format!("{:?}", event.event_type).to_lowercase())
            .collect::<Vec<_>>();
        let auto_narrative = format!(
            "{} drove {} correlated events across {}",
            events[0].process.name,
            events.len(),
            names.join(", ")
        );

        Some(Storyline {
            id,
            root_event,
            events: events_ids,
            processes,
            tactics,
            techniques,
            severity,
            kill_chain_phase,
            auto_narrative,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{CorrelationCache, StorylineEngine};
    use aegis_model::{
        EventPayload, EventType, HostContext, KillChainPhase, NormalizedEvent, Priority,
        ProcessContext, Severity, StorylineContext,
    };

    fn event(
        timestamp_ns: u64,
        event_type: EventType,
        pid: u32,
        lineage_id: uuid::Uuid,
    ) -> NormalizedEvent {
        let mut event = NormalizedEvent::new(
            timestamp_ns,
            event_type,
            Priority::High,
            Severity::High,
            ProcessContext {
                pid,
                tree: vec![1],
                name: "powershell.exe".to_string(),
                ..ProcessContext::default()
            },
            EventPayload::None,
        );
        event.lineage_id = lineage_id;
        event.host = HostContext {
            hostname: "host-a".to_string(),
            ..HostContext::default()
        };
        event.storyline = Some(StorylineContext {
            storyline_id: 0,
            processes: vec![1, pid],
            tactics: vec!["execution".to_string()],
            techniques: vec!["T1059".to_string()],
            kill_chain_phase: KillChainPhase::Exploitation,
            narrative: "script execution".to_string(),
        });
        event.enrichment.mitre_ttps = vec!["T1059".to_string()];
        event
    }

    #[test]
    fn correlation_cache_returns_related_event_ids() {
        let lineage = uuid::Uuid::now_v7();
        let first = event(100, EventType::ProcessCreate, 7, lineage);
        let second = event(110, EventType::NetConnect, 7, lineage);
        let mut cache = CorrelationCache::new(8);
        cache.ingest(&first);
        cache.ingest(&second);

        let related = cache.related_event_ids(&second);

        assert_eq!(related.len(), 2);
        assert!(related.contains(&first.event_id));
        assert!(related.contains(&second.event_id));
    }

    #[test]
    fn storyline_engine_merges_events_with_narrative() {
        let lineage = uuid::Uuid::now_v7();
        let first = event(100, EventType::ProcessCreate, 7, lineage);
        let second = event(120, EventType::FileWrite, 7, lineage);
        let mut engine = StorylineEngine::new();

        let storyline = engine
            .merge(&[first.clone(), second.clone()])
            .expect("storyline");

        assert_eq!(storyline.events.len(), 2);
        assert_eq!(storyline.processes, vec![1, 7]);
        assert_eq!(storyline.techniques, vec!["T1059".to_string()]);
        assert!(storyline.auto_narrative.contains("powershell.exe"));
    }
}
