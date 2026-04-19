use crate::error::CoreError;
use crate::self_protection::DerivedKeyMaterial;
use aegis_model::{EventType, Priority, Severity, TelemetryEvent, TelemetryIntegrity};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{create_dir_all, metadata, read_dir, rename, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct EncryptedStorageRecord {
    version: u32,
    key_version: u32,
    sequence: u64,
    nonce_b64: String,
    payload_b64: String,
    crc32: u32,
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
    pub quarantined_segments: u64,
    pub items: Vec<TelemetryReplayItem>,
}

#[derive(Clone)]
struct StorageCipher {
    key_material: DerivedKeyMaterial,
}

impl StorageCipher {
    fn new(key_material: DerivedKeyMaterial) -> Self {
        Self { key_material }
    }

    fn key_version(&self) -> u32 {
        self.key_material.version
    }

    fn encrypt<T: Serialize>(
        &self,
        namespace: &str,
        sequence: u64,
        value: &T,
    ) -> Result<EncryptedStorageRecord, CoreError> {
        let plaintext = serde_json::to_vec(value)?;
        let nonce = self.nonce_bytes(namespace, sequence);
        let aad = self.aad(namespace, sequence);
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key_material.key_bytes)
            .map_err(|error| CoreError::Crypto(error.to_string()))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|error| CoreError::Crypto(error.to_string()))?;

        Ok(EncryptedStorageRecord {
            version: 1,
            key_version: self.key_material.version,
            sequence,
            nonce_b64: STANDARD.encode(nonce),
            payload_b64: STANDARD.encode(ciphertext),
            crc32: crc32fast::hash(&plaintext),
        })
    }

    fn decrypt<T: DeserializeOwned>(
        &self,
        namespace: &str,
        record: &EncryptedStorageRecord,
    ) -> Result<T, CoreError> {
        if record.key_version != self.key_material.version {
            return Err(CoreError::Crypto(format!(
                "unexpected key version {}, expected {}",
                record.key_version, self.key_material.version
            )));
        }
        let nonce = STANDARD
            .decode(&record.nonce_b64)
            .map_err(|error| CoreError::Crypto(error.to_string()))?;
        if nonce.len() != 24 {
            return Err(CoreError::Crypto("invalid nonce length".to_string()));
        }
        let ciphertext = STANDARD
            .decode(&record.payload_b64)
            .map_err(|error| CoreError::Crypto(error.to_string()))?;
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key_material.key_bytes)
            .map_err(|error| CoreError::Crypto(error.to_string()))?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: self.aad(namespace, record.sequence).as_bytes(),
                },
            )
            .map_err(|error| CoreError::Crypto(error.to_string()))?;
        let actual_crc = crc32fast::hash(&plaintext);
        if actual_crc != record.crc32 {
            return Err(CoreError::Crypto("wal crc mismatch".to_string()));
        }

        Ok(serde_json::from_slice(&plaintext)?)
    }

    fn aad(&self, namespace: &str, sequence: u64) -> String {
        format!(
            "aegis:{}:{}:{}",
            namespace, sequence, self.key_material.version
        )
    }

    fn nonce_bytes(&self, namespace: &str, sequence: u64) -> [u8; 24] {
        let hash = blake3::hash(
            format!("{}:{}:{}", namespace, sequence, self.key_material.version).as_bytes(),
        );
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&hash.as_bytes()[..24]);
        nonce
    }
}

pub struct TelemetryWal {
    root: PathBuf,
    quarantine_root: PathBuf,
    max_segment_bytes: u64,
    summarized_events: u64,
    evicted_segments: u64,
    quarantined_segments: u64,
    cipher: StorageCipher,
}

impl TelemetryWal {
    pub fn new(
        root: impl Into<PathBuf>,
        max_segment_bytes: u64,
        key_material: DerivedKeyMaterial,
    ) -> Result<Self, CoreError> {
        let root = root.into();
        let quarantine_root = root.join("quarantine");
        create_dir_all(&root)?;
        create_dir_all(&quarantine_root)?;
        Ok(Self {
            root,
            quarantine_root,
            max_segment_bytes,
            summarized_events: 0,
            evicted_segments: 0,
            quarantined_segments: 0,
            cipher: StorageCipher::new(key_material),
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

    pub fn replay(&mut self) -> Result<TelemetryReplayResult, CoreError> {
        let mut items = Vec::new();
        for segment in self.segment_paths()? {
            let namespace = file_name(&segment)?;
            let file = File::open(&segment)?;
            let reader = BufReader::new(file);
            let mut segment_items = Vec::new();
            let mut corrupted = false;

            for line in reader.lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }

                let record = match serde_json::from_str::<EncryptedStorageRecord>(&line) {
                    Ok(record) => record,
                    Err(_) => {
                        corrupted = true;
                        break;
                    }
                };
                match self
                    .cipher
                    .decrypt::<TelemetryWalEntry>(&namespace, &record)
                {
                    Ok(TelemetryWalEntry::Full { event }) => {
                        segment_items.push(TelemetryReplayItem {
                            integrity: TelemetryIntegrity::Full,
                            event: Some(event),
                            summary: None,
                        });
                    }
                    Ok(TelemetryWalEntry::Summary { summary }) => {
                        segment_items.push(TelemetryReplayItem {
                            integrity: TelemetryIntegrity::Partial,
                            event: None,
                            summary: Some(summary),
                        });
                    }
                    Err(_) => {
                        corrupted = true;
                        break;
                    }
                }
            }

            if corrupted {
                self.quarantine_segment(&segment)?;
                self.quarantined_segments += 1;
                continue;
            }

            items.extend(segment_items);
        }

        let completeness = if self.summarized_events > 0
            || self.evicted_segments > 0
            || self.quarantined_segments > 0
        {
            TelemetryIntegrity::Partial
        } else {
            TelemetryIntegrity::Full
        };

        Ok(TelemetryReplayResult {
            completeness,
            summarized_events: self.summarized_events,
            evicted_segments: self.evicted_segments,
            quarantined_segments: self.quarantined_segments,
            items,
        })
    }

    pub fn encrypted(&self) -> bool {
        true
    }

    pub fn key_version(&self) -> u32 {
        self.cipher.key_version()
    }

    pub fn quarantined_segments(&self) -> u64 {
        self.quarantined_segments
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
        let namespace = file_name(&path)?;
        let sequence = next_sequence(&path)?;
        let encrypted = self.cipher.encrypt(&namespace, sequence, entry)?;
        let serialized = serde_json::to_vec(&encrypted)?;
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
            .join(format!("segment-{:04}.wal", segments.len() + 1)))
    }

    fn segment_paths(&self) -> Result<Vec<PathBuf>, CoreError> {
        let mut segments = read_dir(&self.root)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.starts_with("segment-") && name.ends_with(".wal"))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        segments.sort();
        Ok(segments)
    }

    fn quarantine_segment(&self, path: &Path) -> Result<(), CoreError> {
        let target = self
            .quarantine_root
            .join(format!("{}.corrupt", file_name(path)?));
        rename(path, target)?;
        Ok(())
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
    cipher: StorageCipher,
}

impl ForensicJournal {
    pub fn new(
        root: impl Into<PathBuf>,
        evidence_capacity_bytes: u64,
        action_capacity_bytes: u64,
        key_material: DerivedKeyMaterial,
    ) -> Result<Self, CoreError> {
        let root = root.into();
        create_dir_all(&root)?;
        Ok(Self {
            root,
            evidence_capacity_bytes,
            action_capacity_bytes,
            cipher: StorageCipher::new(key_material),
        })
    }

    pub fn append_evidence(
        &self,
        record: &EvidenceRecord,
    ) -> Result<JournalWriteResult, CoreError> {
        self.append_record(
            "evidence.log",
            self.evidence_capacity_bytes,
            record,
            JournalWriteResult::EvidenceZoneFull,
        )
    }

    pub fn append_action(&self, record: &ActionLogRecord) -> Result<JournalWriteResult, CoreError> {
        self.append_record(
            "action.log",
            self.action_capacity_bytes,
            record,
            JournalWriteResult::ActionZoneFull,
        )
    }

    pub fn encrypted(&self) -> bool {
        true
    }

    pub fn key_version(&self) -> u32 {
        self.cipher.key_version()
    }

    fn append_record<T: Serialize>(
        &self,
        file_name: &str,
        capacity_bytes: u64,
        record: &T,
        full_result: JournalWriteResult,
    ) -> Result<JournalWriteResult, CoreError> {
        let path = self.root.join(file_name);
        let encrypted = self
            .cipher
            .encrypt(file_name, next_sequence(&path)?, record)?;
        let serialized = serde_json::to_vec(&encrypted)?;
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

    pub fn journal(&self) -> &ForensicJournal {
        &self.journal
    }
}

fn next_sequence(path: &Path) -> Result<u64, CoreError> {
    match File::open(path) {
        Ok(file) => Ok(BufReader::new(file).lines().count() as u64),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(CoreError::from(error)),
    }
}

fn file_name(path: &Path) -> Result<String, CoreError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
        .ok_or_else(|| CoreError::Crypto("invalid segment file name".to_string()))
}

#[cfg(test)]
mod tests {
    use super::{
        ActionLogRecord, ActionPersistence, EmergencyAuditRing, EvidenceRecord, ForensicJournal,
        ForensicPersistenceCoordinator, JournalActionKind, JournalWriteResult, TelemetryWal,
        WalPressureLevel,
    };
    use crate::self_protection::{DerivedKeyTier, KeyDerivationService};
    use aegis_model::{
        EventPayload, EventType, FileContext, NormalizedEvent, Priority, ProcessContext, Severity,
        TelemetryEvent, TelemetryIntegrity,
    };
    use std::fs::{read_dir, remove_dir_all, OpenOptions};
    use std::io::Write;

    fn test_root(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("aegis-{name}-{}", uuid::Uuid::now_v7()));
        if path.exists() {
            let _ = remove_dir_all(&path);
        }
        path
    }

    fn telemetry_key() -> crate::self_protection::DerivedKeyMaterial {
        KeyDerivationService::new("root-secret").derive_material(
            "tenant-a",
            "agent-1",
            DerivedKeyTier::TelemetryWal,
            1,
        )
    }

    fn journal_key() -> crate::self_protection::DerivedKeyMaterial {
        KeyDerivationService::new("root-secret").derive_material(
            "tenant-a",
            "agent-1",
            DerivedKeyTier::ForensicJournal,
            1,
        )
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
        let mut wal = TelemetryWal::new(&root, 300, telemetry_key()).expect("create wal");
        wal.append(&telemetry(Priority::High), WalPressureLevel::Normal)
            .expect("append first");
        wal.append(&telemetry(Priority::Critical), WalPressureLevel::Normal)
            .expect("append second");

        let replay = wal.replay().expect("replay wal");

        assert_eq!(replay.completeness, TelemetryIntegrity::Full);
        assert_eq!(replay.items.len(), 2);
        assert!(replay.items.iter().all(|item| item.event.is_some()));
        assert!(wal.encrypted());
        assert_eq!(wal.key_version(), 1);
        let _ = remove_dir_all(root);
    }

    #[test]
    fn telemetry_wal_marks_partial_when_pressure_summarizes_events() {
        let root = test_root("telemetry-wal-partial");
        let mut wal = TelemetryWal::new(&root, 4_096, telemetry_key()).expect("create wal");
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
    fn telemetry_wal_quarantines_corrupted_segment() {
        let root = test_root("telemetry-wal-corrupt");
        let mut wal = TelemetryWal::new(&root, 4_096, telemetry_key()).expect("create wal");
        wal.append(&telemetry(Priority::High), WalPressureLevel::Normal)
            .expect("append event");
        let segment = read_dir(&root)
            .expect("read root")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.extension().and_then(|ext| ext.to_str()) == Some("wal"))
            .expect("segment exists");
        let mut file = OpenOptions::new()
            .append(true)
            .open(&segment)
            .expect("open segment");
        writeln!(file, "tampered-record").expect("write tampered record");

        let replay = wal.replay().expect("replay wal");
        let quarantine = root.join("quarantine");

        assert_eq!(replay.completeness, TelemetryIntegrity::Partial);
        assert_eq!(replay.quarantined_segments, 1);
        assert_eq!(wal.quarantined_segments(), 1);
        assert!(read_dir(quarantine)
            .expect("read quarantine")
            .next()
            .is_some());
        let _ = remove_dir_all(root);
    }

    #[test]
    fn forensic_persistence_uses_emergency_ring_when_action_zone_is_full() {
        let root = test_root("forensic-ring");
        let journal =
            ForensicJournal::new(&root, 4_096, 16, journal_key()).expect("create journal");
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
        assert!(coordinator.journal().encrypted());
        assert_eq!(coordinator.journal().key_version(), 1);
        let _ = remove_dir_all(root);
    }

    #[test]
    fn forensic_journal_stops_new_evidence_when_evidence_zone_is_full() {
        let root = test_root("forensic-evidence");
        let journal =
            ForensicJournal::new(&root, 16, 4_096, journal_key()).expect("create journal");
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
