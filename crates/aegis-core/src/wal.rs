use crate::error::CoreError;
use aegis_model::{EventType, Priority, Severity, TelemetryEvent, TelemetryIntegrity};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{create_dir_all, metadata, read_dir, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalPressureLevel {
    Normal,
    Elevated,
    High,
    Critical,
    Emergency,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TelemetrySummaryRecord {
    pub event_id: Uuid,
    pub lineage_id: Uuid,
    pub timestamp_ns: u64,
    pub tenant_id: String,
    pub agent_id: String,
    pub event_type: EventType,
    pub priority: Priority,
    pub severity: Severity,
    pub summary_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TelemetryWalEntry {
    Full { event: TelemetryEvent },
    Summary { summary: TelemetrySummaryRecord },
}

#[derive(Clone, Debug, PartialEq)]
pub struct TelemetryReplayItem {
    pub integrity: TelemetryIntegrity,
    pub event: Option<TelemetryEvent>,
    pub summary: Option<TelemetrySummaryRecord>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TelemetryReplayResult {
    pub completeness: TelemetryIntegrity,
    pub summarized_events: u64,
    pub evicted_segments: u64,
    pub items: Vec<TelemetryReplayItem>,
}

pub struct TelemetryWal {
    root: PathBuf,
    max_segment_bytes: u64,
    summarized_events: u64,
    evicted_segments: u64,
}

impl TelemetryWal {
    pub fn new(root: impl Into<PathBuf>, max_segment_bytes: u64) -> Result<Self, CoreError> {
        let root = root.into();
        create_dir_all(&root)?;
        Ok(Self {
            root,
            max_segment_bytes,
            summarized_events: 0,
            evicted_segments: 0,
        })
    }

    pub fn append(
        &mut self,
        event: &TelemetryEvent,
        pressure: WalPressureLevel,
    ) -> Result<PathBuf, CoreError> {
        let entry = self.entry_for(event, pressure);
        if matches!(entry, TelemetryWalEntry::Summary { .. }) {
            self.summarized_events += 1;
        }
        self.append_entry(&entry)
    }

    pub fn replay(&self) -> Result<TelemetryReplayResult, CoreError> {
        let mut items = Vec::new();
        for segment in self.segment_paths()? {
            let file = File::open(segment)?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }

                match serde_json::from_str::<TelemetryWalEntry>(&line)? {
                    TelemetryWalEntry::Full { event } => items.push(TelemetryReplayItem {
                        integrity: TelemetryIntegrity::Full,
                        event: Some(event),
                        summary: None,
                    }),
                    TelemetryWalEntry::Summary { summary } => items.push(TelemetryReplayItem {
                        integrity: TelemetryIntegrity::Partial,
                        event: None,
                        summary: Some(summary),
                    }),
                }
            }
        }

        let completeness = if self.summarized_events > 0 || self.evicted_segments > 0 {
            TelemetryIntegrity::Partial
        } else {
            TelemetryIntegrity::Full
        };

        Ok(TelemetryReplayResult {
            completeness,
            summarized_events: self.summarized_events,
            evicted_segments: self.evicted_segments,
            items,
        })
    }

    fn entry_for(&self, event: &TelemetryEvent, pressure: WalPressureLevel) -> TelemetryWalEntry {
        let summarize = match pressure {
            WalPressureLevel::Normal => false,
            WalPressureLevel::Elevated => event.priority == Priority::Low,
            WalPressureLevel::High => {
                !matches!(event.priority, Priority::Critical | Priority::High)
            }
            WalPressureLevel::Critical | WalPressureLevel::Emergency => {
                event.priority != Priority::Critical
            }
        };

        if summarize {
            TelemetryWalEntry::Summary {
                summary: TelemetrySummaryRecord {
                    event_id: event.event_id,
                    lineage_id: event.lineage_id,
                    timestamp_ns: event.timestamp_ns,
                    tenant_id: event.tenant_id.clone(),
                    agent_id: event.agent_id.clone(),
                    event_type: event.event_type,
                    priority: event.priority,
                    severity: event.severity,
                    summary_hash: blake3::hash(
                        serde_json::to_vec(event)
                            .expect("telemetry event should serialize for summary hash")
                            .as_slice(),
                    )
                    .to_hex()
                    .to_string(),
                },
            }
        } else {
            TelemetryWalEntry::Full {
                event: event.clone(),
            }
        }
    }

    fn append_entry(&mut self, entry: &TelemetryWalEntry) -> Result<PathBuf, CoreError> {
        let path = self.current_segment_path()?;
        let serialized = serde_json::to_vec(entry)?;
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        file.write_all(&serialized)?;
        file.write_all(b"\n")?;
        Ok(path)
    }

    fn current_segment_path(&self) -> Result<PathBuf, CoreError> {
        let segments = self.segment_paths()?;
        if let Some(last) = segments.last() {
            let current_size = metadata(last)?.len();
            if current_size < self.max_segment_bytes {
                return Ok(last.clone());
            }
        }

        Ok(self
            .root
            .join(format!("segment-{:04}.jsonl", segments.len() + 1)))
    }

    fn segment_paths(&self) -> Result<Vec<PathBuf>, CoreError> {
        let mut segments = read_dir(&self.root)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.starts_with("segment-") && name.ends_with(".jsonl"))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        segments.sort();
        Ok(segments)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JournalActionKind {
    Kill,
    Quarantine,
    Isolate,
    FilesystemRollback,
    SessionLock,
}

impl JournalActionKind {
    fn is_lightweight(self) -> bool {
        matches!(self, Self::Kill | Self::Quarantine)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub evidence_id: Uuid,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionLogRecord {
    pub action_id: Uuid,
    pub command_id: Option<Uuid>,
    pub kind: JournalActionKind,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalWriteResult {
    Stored,
    EvidenceZoneFull,
    ActionZoneFull,
}

pub struct ForensicJournal {
    root: PathBuf,
    evidence_capacity_bytes: u64,
    action_capacity_bytes: u64,
}

impl ForensicJournal {
    pub fn new(
        root: impl Into<PathBuf>,
        evidence_capacity_bytes: u64,
        action_capacity_bytes: u64,
    ) -> Result<Self, CoreError> {
        let root = root.into();
        create_dir_all(&root)?;
        Ok(Self {
            root,
            evidence_capacity_bytes,
            action_capacity_bytes,
        })
    }

    pub fn append_evidence(
        &self,
        record: &EvidenceRecord,
    ) -> Result<JournalWriteResult, CoreError> {
        self.append_record(
            "evidence.jsonl",
            self.evidence_capacity_bytes,
            record,
            JournalWriteResult::EvidenceZoneFull,
        )
    }

    pub fn append_action(&self, record: &ActionLogRecord) -> Result<JournalWriteResult, CoreError> {
        self.append_record(
            "action.jsonl",
            self.action_capacity_bytes,
            record,
            JournalWriteResult::ActionZoneFull,
        )
    }

    fn append_record<T: Serialize>(
        &self,
        file_name: &str,
        capacity_bytes: u64,
        record: &T,
        full_result: JournalWriteResult,
    ) -> Result<JournalWriteResult, CoreError> {
        let path = self.root.join(file_name);
        let serialized = serde_json::to_vec(record)?;
        let required_bytes = serialized.len() as u64 + 1;
        let current_bytes = metadata(&path).map(|meta| meta.len()).unwrap_or(0);
        if current_bytes + required_bytes > capacity_bytes {
            return Ok(full_result);
        }

        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        file.write_all(&serialized)?;
        file.write_all(b"\n")?;
        Ok(JournalWriteResult::Stored)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmergencyAuditRecord {
    pub action_id: Uuid,
    pub command_id: Option<Uuid>,
    pub kind: JournalActionKind,
    pub detail: String,
}

pub struct EmergencyAuditRing {
    capacity: usize,
    records: VecDeque<EmergencyAuditRecord>,
    overwrites: u64,
}

impl EmergencyAuditRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            records: VecDeque::with_capacity(capacity),
            overwrites: 0,
        }
    }

    pub fn append(&mut self, record: EmergencyAuditRecord) {
        if self.records.len() == self.capacity {
            self.records.pop_front();
            self.overwrites += 1;
        }
        self.records.push_back(record);
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn overwrites(&self) -> u64 {
        self.overwrites
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionPersistence {
    ForensicJournal,
    EmergencyAuditRing,
    PendingApproval,
}

pub struct ForensicPersistenceCoordinator {
    journal: ForensicJournal,
    emergency_ring: EmergencyAuditRing,
}

impl ForensicPersistenceCoordinator {
    pub fn new(journal: ForensicJournal, emergency_ring: EmergencyAuditRing) -> Self {
        Self {
            journal,
            emergency_ring,
        }
    }

    pub fn persist_action(
        &mut self,
        record: ActionLogRecord,
    ) -> Result<ActionPersistence, CoreError> {
        match self.journal.append_action(&record)? {
            JournalWriteResult::Stored => Ok(ActionPersistence::ForensicJournal),
            JournalWriteResult::ActionZoneFull if record.kind.is_lightweight() => {
                self.emergency_ring.append(EmergencyAuditRecord {
                    action_id: record.action_id,
                    command_id: record.command_id,
                    kind: record.kind,
                    detail: record.detail,
                });
                Ok(ActionPersistence::EmergencyAuditRing)
            }
            JournalWriteResult::ActionZoneFull => Ok(ActionPersistence::PendingApproval),
            JournalWriteResult::EvidenceZoneFull => Ok(ActionPersistence::ForensicJournal),
        }
    }

    pub fn emergency_ring(&self) -> &EmergencyAuditRing {
        &self.emergency_ring
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActionLogRecord, ActionPersistence, EmergencyAuditRing, EvidenceRecord, ForensicJournal,
        ForensicPersistenceCoordinator, JournalActionKind, JournalWriteResult, TelemetryWal,
        WalPressureLevel,
    };
    use aegis_model::{
        EventPayload, EventType, FileContext, NormalizedEvent, Priority, ProcessContext, Severity,
        TelemetryEvent, TelemetryIntegrity,
    };
    use std::fs::remove_dir_all;

    fn test_root(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("aegis-{name}-{}", uuid::Uuid::now_v7()));
        if path.exists() {
            let _ = remove_dir_all(&path);
        }
        path
    }

    fn telemetry(priority: Priority) -> TelemetryEvent {
        TelemetryEvent::from_normalized(
            &NormalizedEvent::new(
                123,
                EventType::FileWrite,
                priority,
                Severity::High,
                ProcessContext::default(),
                EventPayload::File(FileContext::default()),
            ),
            "tenant-a".to_string(),
            "agent-1".to_string(),
        )
    }

    #[test]
    fn telemetry_wal_replays_segmented_events_in_order() {
        let root = test_root("telemetry-wal-replay");
        let mut wal = TelemetryWal::new(&root, 300).expect("create wal");
        wal.append(&telemetry(Priority::High), WalPressureLevel::Normal)
            .expect("append first");
        wal.append(&telemetry(Priority::Critical), WalPressureLevel::Normal)
            .expect("append second");

        let replay = wal.replay().expect("replay wal");

        assert_eq!(replay.completeness, TelemetryIntegrity::Full);
        assert_eq!(replay.items.len(), 2);
        assert!(replay.items.iter().all(|item| item.event.is_some()));
        let _ = remove_dir_all(root);
    }

    #[test]
    fn telemetry_wal_marks_partial_when_pressure_summarizes_events() {
        let root = test_root("telemetry-wal-partial");
        let mut wal = TelemetryWal::new(&root, 4_096).expect("create wal");
        wal.append(&telemetry(Priority::Low), WalPressureLevel::High)
            .expect("append summarized event");

        let replay = wal.replay().expect("replay wal");

        assert_eq!(replay.completeness, TelemetryIntegrity::Partial);
        assert_eq!(replay.summarized_events, 1);
        assert_eq!(replay.items[0].integrity, TelemetryIntegrity::Partial);
        assert!(replay.items[0].summary.is_some());
        let _ = remove_dir_all(root);
    }

    #[test]
    fn forensic_persistence_uses_emergency_ring_when_action_zone_is_full() {
        let root = test_root("forensic-ring");
        let journal = ForensicJournal::new(&root, 4_096, 16).expect("create journal");
        let mut coordinator =
            ForensicPersistenceCoordinator::new(journal, EmergencyAuditRing::new(2));
        let outcome = coordinator
            .persist_action(ActionLogRecord {
                action_id: uuid::Uuid::now_v7(),
                command_id: Some(uuid::Uuid::now_v7()),
                kind: JournalActionKind::Kill,
                detail: "terminate pid 7".to_string(),
            })
            .expect("persist action");

        assert_eq!(outcome, ActionPersistence::EmergencyAuditRing);
        assert_eq!(coordinator.emergency_ring().len(), 1);
        let _ = remove_dir_all(root);
    }

    #[test]
    fn forensic_journal_stops_new_evidence_when_evidence_zone_is_full() {
        let root = test_root("forensic-evidence");
        let journal = ForensicJournal::new(&root, 16, 4_096).expect("create journal");
        let result = journal
            .append_evidence(&EvidenceRecord {
                evidence_id: uuid::Uuid::now_v7(),
                detail: "x".repeat(128),
            })
            .expect("append evidence");

        assert_eq!(result, JournalWriteResult::EvidenceZoneFull);
        let _ = remove_dir_all(root);
    }
}
