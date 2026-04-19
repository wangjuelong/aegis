use crate::config::{CommunicationConfig, SecurityConfig};
use crate::transport_drivers::{build_transport_drivers, TransportAgentContext};
use aegis_model::{
    AgentHealth, ApproverEntry, CommunicationChannelHealth, CommunicationChannelKind,
    CommunicationRuntimeStatus, DownlinkMessage, EventBatch, HeartbeatRequest, ServerCommand,
    SignedServerCommand, TargetScopeKind, TelemetryEvent, UplinkMessage,
};
use anyhow::{anyhow, bail, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::any::Any;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentIdentity {
    pub tenant_id: String,
    pub agent_id: String,
    pub allow_global_scope: bool,
    pub min_policy_version: String,
}

pub struct TelemetryBatchBuilder {
    max_batch_events: usize,
}

impl TelemetryBatchBuilder {
    pub fn new(max_batch_events: usize) -> Self {
        Self { max_batch_events }
    }

    pub fn build(
        &self,
        tenant_id: impl Into<String>,
        agent_id: impl Into<String>,
        sequence_hint: u64,
        events: Vec<TelemetryEvent>,
    ) -> Result<UplinkMessage> {
        if events.is_empty() {
            bail!("telemetry batch must contain at least one event");
        }
        if events.len() > self.max_batch_events {
            bail!("telemetry batch exceeds configured limit");
        }

        Ok(UplinkMessage::EventBatch(EventBatch {
            batch_id: Uuid::now_v7(),
            tenant_id: tenant_id.into(),
            agent_id: agent_id.into(),
            sequence_hint,
            events,
        }))
    }
}

pub struct HeartbeatBuilder;

impl HeartbeatBuilder {
    pub fn build(
        tenant_id: impl Into<String>,
        agent_id: impl Into<String>,
        health: AgentHealth,
        communication: CommunicationRuntimeStatus,
        wal_utilization_ratio: f32,
        restart_epoch: u64,
    ) -> HeartbeatRequest {
        HeartbeatRequest {
            tenant_id: tenant_id.into(),
            agent_id: agent_id.into(),
            health,
            communication,
            wal_utilization_ratio,
            restart_epoch,
        }
    }
}

pub trait TransportDriver: Send + Sync {
    fn channel(&self) -> CommunicationChannelKind;
    fn send_uplink(&self, message: &UplinkMessage) -> Result<()>;
    fn send_heartbeat(&self, heartbeat: &HeartbeatRequest) -> Result<()>;
    fn recv_downlink(&self) -> Result<Option<DownlinkMessage>>;
    fn probe(&self) -> bool;
    fn as_any(&self) -> &dyn Any;
}

#[derive(Clone, Default)]
pub struct LoopbackTransportHandle {
    uplinks: Arc<Mutex<Vec<UplinkMessage>>>,
    heartbeats: Arc<Mutex<Vec<HeartbeatRequest>>>,
    downlinks: Arc<Mutex<VecDeque<DownlinkMessage>>>,
}

impl LoopbackTransportHandle {
    pub fn inject_downlink(&self, message: DownlinkMessage) {
        self.downlinks
            .lock()
            .expect("loopback downlink queue poisoned")
            .push_back(message);
    }

    pub fn take_uplinks(&self) -> Vec<UplinkMessage> {
        let mut uplinks = self.uplinks.lock().expect("loopback uplink queue poisoned");
        std::mem::take(&mut *uplinks)
    }

    pub fn take_heartbeats(&self) -> Vec<HeartbeatRequest> {
        let mut heartbeats = self
            .heartbeats
            .lock()
            .expect("loopback heartbeat queue poisoned");
        std::mem::take(&mut *heartbeats)
    }
}

pub struct LoopbackTransportDriver {
    channel: CommunicationChannelKind,
    handle: LoopbackTransportHandle,
}

impl LoopbackTransportDriver {
    pub fn new(channel: CommunicationChannelKind) -> Self {
        Self {
            channel,
            handle: LoopbackTransportHandle::default(),
        }
    }

    pub fn handle(&self) -> LoopbackTransportHandle {
        self.handle.clone()
    }
}

impl TransportDriver for LoopbackTransportDriver {
    fn channel(&self) -> CommunicationChannelKind {
        self.channel
    }

    fn send_uplink(&self, message: &UplinkMessage) -> Result<()> {
        self.handle
            .uplinks
            .lock()
            .expect("loopback uplink queue poisoned")
            .push(message.clone());
        Ok(())
    }

    fn send_heartbeat(&self, heartbeat: &HeartbeatRequest) -> Result<()> {
        self.handle
            .heartbeats
            .lock()
            .expect("loopback heartbeat queue poisoned")
            .push(heartbeat.clone());
        Ok(())
    }

    fn recv_downlink(&self) -> Result<Option<DownlinkMessage>> {
        Ok(self
            .handle
            .downlinks
            .lock()
            .expect("loopback downlink queue poisoned")
            .pop_front())
    }

    fn probe(&self) -> bool {
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ChannelRuntimeState {
    healthy: bool,
    consecutive_failures: u32,
    last_attempt_ms: Option<i64>,
    last_success_ms: Option<i64>,
    last_error: Option<String>,
}

pub struct CommunicationRuntime {
    fallback_order: Vec<CommunicationChannelKind>,
    drivers: HashMap<CommunicationChannelKind, Box<dyn TransportDriver>>,
    failure_threshold: u32,
    active_index: usize,
    channel_state: HashMap<CommunicationChannelKind, ChannelRuntimeState>,
}

impl CommunicationRuntime {
    pub fn new(failure_threshold: u32) -> Self {
        let fallback_order = Self::default_fallback_order();
        let channel_state = fallback_order
            .iter()
            .copied()
            .map(|channel| (channel, ChannelRuntimeState::default()))
            .collect();
        Self {
            fallback_order,
            drivers: HashMap::new(),
            failure_threshold: failure_threshold.max(1),
            active_index: 0,
            channel_state,
        }
    }

    pub fn with_loopback_drivers(failure_threshold: u32) -> Self {
        Self::with_loopback_drivers_and_handles(failure_threshold).0
    }

    pub fn from_config(
        config: &CommunicationConfig,
        agent: &TransportAgentContext,
    ) -> Result<Self> {
        if config.development_allow_loopback {
            return Ok(Self::with_loopback_drivers(config.failure_threshold));
        }

        let mut runtime = Self::new(config.failure_threshold);
        let drivers = build_transport_drivers(config, agent)?;
        if drivers.is_empty() {
            bail!("no communication drivers enabled and loopback is disabled");
        }

        for driver in drivers {
            runtime.register_driver(driver);
        }
        Ok(runtime)
    }

    pub fn with_loopback_drivers_and_handles(
        failure_threshold: u32,
    ) -> (
        Self,
        HashMap<CommunicationChannelKind, LoopbackTransportHandle>,
    ) {
        let mut runtime = Self::new(failure_threshold);
        let mut handles = HashMap::new();
        for channel in Self::default_fallback_order() {
            let driver = LoopbackTransportDriver::new(channel);
            handles.insert(channel, driver.handle());
            runtime.register_driver(Box::new(driver));
        }
        (runtime, handles)
    }

    pub fn register_driver(&mut self, driver: Box<dyn TransportDriver>) {
        let channel = driver.channel();
        self.drivers.insert(channel, driver);
        self.channel_state.entry(channel).or_default();
    }

    pub fn active_channel(&self) -> CommunicationChannelKind {
        self.fallback_order[self.active_index]
    }

    pub fn send_uplink(
        &mut self,
        message: &UplinkMessage,
        now_ms: i64,
    ) -> Result<CommunicationChannelKind> {
        self.send_with_active_channel(now_ms, |driver| driver.send_uplink(message))
    }

    pub fn send_heartbeat(
        &mut self,
        heartbeat: &HeartbeatRequest,
        now_ms: i64,
    ) -> Result<CommunicationChannelKind> {
        self.send_with_active_channel(now_ms, |driver| driver.send_heartbeat(heartbeat))
    }

    pub fn poll_downlink(
        &mut self,
        now_ms: i64,
    ) -> Result<Option<(CommunicationChannelKind, DownlinkMessage)>> {
        let channel = self.active_channel();
        self.channel_state
            .entry(channel)
            .or_default()
            .last_attempt_ms = Some(now_ms);

        let result = match self.drivers.get(&channel) {
            Some(driver) => driver.recv_downlink(),
            None => Err(anyhow!("no transport driver registered for {:?}", channel)),
        };

        match result {
            Ok(message) => {
                let state = self.channel_state.entry(channel).or_default();
                state.healthy = true;
                state.consecutive_failures = 0;
                state.last_success_ms = Some(now_ms);
                state.last_error = None;
                Ok(message.map(|message| (channel, message)))
            }
            Err(error) => {
                let state = self.channel_state.entry(channel).or_default();
                state.healthy = false;
                state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                state.last_error = Some(error.to_string());
                if state.consecutive_failures >= self.failure_threshold
                    && self.active_index + 1 < self.fallback_order.len()
                {
                    self.active_index += 1;
                }
                Err(error)
            }
        }
    }

    pub fn probe_upgrade(&mut self, now_ms: i64) -> Option<CommunicationChannelKind> {
        if self.active_index == 0 {
            return None;
        }

        for index in 0..self.active_index {
            let channel = self.fallback_order[index];
            let healthy = self
                .drivers
                .get(&channel)
                .map(|driver| driver.probe())
                .unwrap_or(false);
            let state = self.channel_state.entry(channel).or_default();
            state.last_attempt_ms = Some(now_ms);
            state.healthy = healthy;
            if healthy {
                state.last_error = None;
                self.active_index = index;
                return Some(channel);
            }
            state.last_error = Some("probe failed".to_string());
        }

        None
    }

    pub fn snapshot(&self) -> CommunicationRuntimeStatus {
        let channels = self
            .fallback_order
            .iter()
            .copied()
            .map(|channel| {
                let state = self
                    .channel_state
                    .get(&channel)
                    .cloned()
                    .unwrap_or_default();
                CommunicationChannelHealth {
                    channel,
                    healthy: state.healthy,
                    consecutive_failures: state.consecutive_failures,
                    last_attempt_ms: state.last_attempt_ms,
                    last_success_ms: state.last_success_ms,
                    last_error: state.last_error,
                }
            })
            .collect::<Vec<_>>();
        let last_success_ms = channels
            .iter()
            .filter_map(|channel| channel.last_success_ms)
            .max();

        CommunicationRuntimeStatus {
            active_channel: self.active_channel(),
            degraded: self.active_index > 0,
            fallback_chain: self.fallback_order.clone(),
            last_success_ms,
            channels,
        }
    }

    pub fn loopback_handle(
        &self,
        channel: CommunicationChannelKind,
    ) -> Option<LoopbackTransportHandle> {
        self.drivers
            .get(&channel)
            .and_then(|driver| driver.as_any().downcast_ref::<LoopbackTransportDriver>())
            .map(LoopbackTransportDriver::handle)
    }

    fn default_fallback_order() -> Vec<CommunicationChannelKind> {
        vec![
            CommunicationChannelKind::Grpc,
            CommunicationChannelKind::WebSocket,
            CommunicationChannelKind::LongPolling,
            CommunicationChannelKind::DomainFronting,
        ]
    }

    fn send_with_active_channel<F>(
        &mut self,
        now_ms: i64,
        send: F,
    ) -> Result<CommunicationChannelKind>
    where
        F: FnOnce(&dyn TransportDriver) -> Result<()>,
    {
        let channel = self.active_channel();
        self.channel_state
            .entry(channel)
            .or_default()
            .last_attempt_ms = Some(now_ms);

        let result: Result<()> = match self.drivers.get(&channel) {
            Some(driver) => send(driver.as_ref()),
            None => Err(anyhow!("no transport driver registered for {:?}", channel)),
        };

        match result {
            Ok(()) => {
                let state = self.channel_state.entry(channel).or_default();
                state.healthy = true;
                state.consecutive_failures = 0;
                state.last_success_ms = Some(now_ms);
                state.last_error = None;
                Ok(channel)
            }
            Err(error) => {
                let state = self.channel_state.entry(channel).or_default();
                state.healthy = false;
                state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                state.last_error = Some(error.to_string());
                if state.consecutive_failures >= self.failure_threshold
                    && self.active_index + 1 < self.fallback_order.len()
                {
                    self.active_index += 1;
                }
                Err(error)
            }
        }
    }
}

enum CommandReplayLedgerBackend {
    Memory(HashMap<Uuid, i64>),
    Sqlite(PathBuf),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RollbackProtectionAnchor {
    TpmNvCounter,
    OsStoreCrossChecked,
    FileBackedCrossChecked,
    Ephemeral,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackProtectionStatus {
    pub anchor_kind: RollbackProtectionAnchor,
    pub floor_issued_at_ms: Option<i64>,
    pub fs_cross_check_ms: Option<i64>,
    pub cross_check_ok: bool,
    pub degraded: bool,
    pub last_error: Option<String>,
}

impl Default for RollbackProtectionStatus {
    fn default() -> Self {
        Self {
            anchor_kind: RollbackProtectionAnchor::Ephemeral,
            floor_issued_at_ms: None,
            fs_cross_check_ms: None,
            cross_check_ok: false,
            degraded: true,
            last_error: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct RollbackAnchorRecord {
    floor_issued_at_ms: Option<i64>,
    updated_at_ms: i64,
}

pub struct CommandReplayLedger {
    backend: CommandReplayLedgerBackend,
    rollback_status: RollbackProtectionStatus,
}

impl Default for CommandReplayLedger {
    fn default() -> Self {
        Self {
            backend: CommandReplayLedgerBackend::Memory(HashMap::new()),
            rollback_status: RollbackProtectionStatus::default(),
        }
    }
}

impl CommandReplayLedger {
    pub fn new_persistent(path: PathBuf) -> Result<Self> {
        Self::new_persistent_with_security(path, &SecurityConfig::default())
    }

    pub fn new_persistent_with_security(path: PathBuf, security: &SecurityConfig) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        initialize_replay_ledger_backend(&path)?;
        let rollback_status = load_or_initialize_rollback_status(&path, security)?;
        Ok(Self {
            backend: CommandReplayLedgerBackend::Sqlite(path),
            rollback_status,
        })
    }

    pub fn register(
        &mut self,
        command_id: Uuid,
        issued_at_ms: i64,
        expires_at_ms: i64,
        now_ms: i64,
    ) -> Result<(), CommandValidationError> {
        self.prune(now_ms)?;
        if let Some(floor_issued_at_ms) = self.rollback_status.floor_issued_at_ms {
            if issued_at_ms < floor_issued_at_ms {
                return Err(CommandValidationError::RollbackProtectionTriggered);
            }
        }
        match &mut self.backend {
            CommandReplayLedgerBackend::Memory(seen) => {
                if seen.contains_key(&command_id) {
                    return Err(CommandValidationError::ReplayDetected);
                }
                seen.insert(command_id, expires_at_ms);
                self.rollback_status.floor_issued_at_ms = Some(
                    self.rollback_status
                        .floor_issued_at_ms
                        .map(|current| current.max(issued_at_ms))
                        .unwrap_or(issued_at_ms),
                );
                Ok(())
            }
            CommandReplayLedgerBackend::Sqlite(path) => {
                let connection = Connection::open(path.as_path())
                    .map_err(|_| CommandValidationError::PersistenceFailure)?;
                let existing = connection
                    .query_row(
                        "SELECT expires_at_ms FROM command_replay_ledger WHERE command_id = ?1",
                        params![command_id.to_string()],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()
                    .map_err(|_| CommandValidationError::PersistenceFailure)?;
                if existing.is_some() {
                    return Err(CommandValidationError::ReplayDetected);
                }
                connection
                    .execute(
                        "INSERT INTO command_replay_ledger(command_id, expires_at_ms)
                         VALUES (?1, ?2)",
                        params![command_id.to_string(), expires_at_ms],
                    )
                    .map_err(|_| CommandValidationError::PersistenceFailure)?;
                advance_rollback_status(
                    &mut self.rollback_status,
                    path.as_path(),
                    issued_at_ms,
                    now_ms,
                )
                .map_err(|_| CommandValidationError::PersistenceFailure)?;
                Ok(())
            }
        }
    }

    pub fn rollback_status(&self) -> &RollbackProtectionStatus {
        &self.rollback_status
    }

    fn prune(&mut self, now_ms: i64) -> Result<(), CommandValidationError> {
        match &mut self.backend {
            CommandReplayLedgerBackend::Memory(seen) => {
                seen.retain(|_, expires_at_ms| *expires_at_ms > now_ms);
                Ok(())
            }
            CommandReplayLedgerBackend::Sqlite(path) => {
                let connection = Connection::open(path)
                    .map_err(|_| CommandValidationError::PersistenceFailure)?;
                connection
                    .execute(
                        "DELETE FROM command_replay_ledger WHERE expires_at_ms <= ?1",
                        params![now_ms],
                    )
                    .map_err(|_| CommandValidationError::PersistenceFailure)?;
                Ok(())
            }
        }
    }
}

fn initialize_replay_ledger_backend(path: &Path) -> Result<()> {
    let connection = Connection::open(path)?;
    connection.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS command_replay_ledger (
            command_id TEXT PRIMARY KEY,
            expires_at_ms INTEGER NOT NULL
        );
        ",
    )?;
    Ok(())
}

fn load_or_initialize_rollback_status(
    path: &Path,
    security: &SecurityConfig,
) -> Result<RollbackProtectionStatus> {
    let now_ms = now_unix_ms();
    let default_record = RollbackAnchorRecord {
        floor_issued_at_ms: None,
        updated_at_ms: now_ms,
    };

    if security.use_os_credential_store {
        match load_or_initialize_rollback_record_from_keyring(path, &default_record) {
            Ok(keyring_record) => {
                let (mut sidecar_record, fs_cross_check_ms) =
                    load_or_initialize_rollback_record_from_sidecar(path, &keyring_record)?;
                let floor_issued_at_ms = max_floor(
                    keyring_record.floor_issued_at_ms,
                    sidecar_record.floor_issued_at_ms,
                );
                let cross_check_ok =
                    keyring_record.floor_issued_at_ms == sidecar_record.floor_issued_at_ms;
                let mut last_error = None;
                if !cross_check_ok {
                    last_error = Some(
                        "rollback anchor mismatch detected between credential store and sidecar"
                            .to_string(),
                    );
                    sidecar_record = RollbackAnchorRecord {
                        floor_issued_at_ms,
                        updated_at_ms: now_ms,
                    };
                    persist_rollback_record_to_keyring(path, &sidecar_record)?;
                    persist_rollback_record_to_sidecar(path, &sidecar_record)?;
                }
                return Ok(RollbackProtectionStatus {
                    anchor_kind: RollbackProtectionAnchor::OsStoreCrossChecked,
                    floor_issued_at_ms,
                    fs_cross_check_ms,
                    cross_check_ok,
                    degraded: true,
                    last_error,
                });
            }
            Err(error) => {
                if security.allow_file_fallback {
                    let (record, fs_cross_check_ms) =
                        load_or_initialize_rollback_record_from_sidecar(path, &default_record)?;
                    return Ok(RollbackProtectionStatus {
                        anchor_kind: RollbackProtectionAnchor::FileBackedCrossChecked,
                        floor_issued_at_ms: record.floor_issued_at_ms,
                        fs_cross_check_ms,
                        cross_check_ok: fs_cross_check_ms.is_some(),
                        degraded: true,
                        last_error: Some(format!(
                            "credential store unavailable, fallback to file anchor: {error}"
                        )),
                    });
                }
                bail!("credential store unavailable and file fallback disabled: {error}");
            }
        }
    }

    let (record, fs_cross_check_ms) =
        load_or_initialize_rollback_record_from_sidecar(path, &default_record)?;
    Ok(RollbackProtectionStatus {
        anchor_kind: RollbackProtectionAnchor::FileBackedCrossChecked,
        floor_issued_at_ms: record.floor_issued_at_ms,
        fs_cross_check_ms,
        cross_check_ok: fs_cross_check_ms.is_some(),
        degraded: true,
        last_error: None,
    })
}

fn advance_rollback_status(
    status: &mut RollbackProtectionStatus,
    path: &Path,
    issued_at_ms: i64,
    now_ms: i64,
) -> Result<()> {
    let next_floor = status
        .floor_issued_at_ms
        .map(|current| current.max(issued_at_ms))
        .unwrap_or(issued_at_ms);
    let record = RollbackAnchorRecord {
        floor_issued_at_ms: Some(next_floor),
        updated_at_ms: now_ms,
    };

    match status.anchor_kind {
        RollbackProtectionAnchor::OsStoreCrossChecked => {
            persist_rollback_record_to_keyring(path, &record)?;
            persist_rollback_record_to_sidecar(path, &record)?;
            status.fs_cross_check_ms = sidecar_mtime_ms(&rollback_anchor_sidecar_path(path));
            status.cross_check_ok = true;
        }
        RollbackProtectionAnchor::FileBackedCrossChecked => {
            persist_rollback_record_to_sidecar(path, &record)?;
            status.fs_cross_check_ms = sidecar_mtime_ms(&rollback_anchor_sidecar_path(path));
            status.cross_check_ok = status.fs_cross_check_ms.is_some();
        }
        RollbackProtectionAnchor::TpmNvCounter | RollbackProtectionAnchor::Ephemeral => {
            status.cross_check_ok = false;
        }
    }

    status.floor_issued_at_ms = record.floor_issued_at_ms;
    Ok(())
}

fn rollback_anchor_sidecar_path(path: &Path) -> PathBuf {
    path.with_extension("rollback-anchor.json")
}

fn rollback_anchor_keyring_account(path: &Path) -> String {
    format!(
        "rollback-anchor:{}",
        blake3::hash(path.to_string_lossy().as_bytes()).to_hex()
    )
}

fn load_or_initialize_rollback_record_from_keyring(
    path: &Path,
    default_record: &RollbackAnchorRecord,
) -> Result<RollbackAnchorRecord> {
    let entry = keyring::Entry::new(
        "aegis-sensor/rollback-anchor",
        &rollback_anchor_keyring_account(path),
    )?;
    match entry.get_password() {
        Ok(serialized) => Ok(serde_json::from_str(&serialized)?),
        Err(_) => {
            persist_rollback_record_to_keyring(path, default_record)?;
            Ok(default_record.clone())
        }
    }
}

fn persist_rollback_record_to_keyring(path: &Path, record: &RollbackAnchorRecord) -> Result<()> {
    let entry = keyring::Entry::new(
        "aegis-sensor/rollback-anchor",
        &rollback_anchor_keyring_account(path),
    )?;
    entry.set_password(&serde_json::to_string(record)?)?;
    Ok(())
}

fn load_or_initialize_rollback_record_from_sidecar(
    path: &Path,
    default_record: &RollbackAnchorRecord,
) -> Result<(RollbackAnchorRecord, Option<i64>)> {
    let sidecar = rollback_anchor_sidecar_path(path);
    if !sidecar.exists() {
        persist_rollback_record_to_sidecar(path, default_record)?;
        return Ok((default_record.clone(), sidecar_mtime_ms(&sidecar)));
    }

    let record = serde_json::from_slice::<RollbackAnchorRecord>(&fs::read(&sidecar)?)?;
    Ok((record, sidecar_mtime_ms(&sidecar)))
}

fn persist_rollback_record_to_sidecar(path: &Path, record: &RollbackAnchorRecord) -> Result<()> {
    let sidecar = rollback_anchor_sidecar_path(path);
    if let Some(parent) = sidecar.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&sidecar, serde_json::to_vec_pretty(record)?)?;
    Ok(())
}

fn sidecar_mtime_ms(path: &Path) -> Option<i64> {
    fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as i64)
}

fn max_floor(left: Option<i64>, right: Option<i64>) -> Option<i64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as i64
}

#[derive(Clone)]
struct ApproverDirectoryEntry {
    role: String,
    signing_key_id: String,
    verifying_key: VerifyingKey,
}

pub struct CommandValidator {
    server_keys: HashMap<String, VerifyingKey>,
    approvers: HashMap<String, ApproverDirectoryEntry>,
    max_clock_skew_ms: i64,
}

impl CommandValidator {
    pub fn new(max_clock_skew_ms: i64) -> Self {
        Self {
            server_keys: HashMap::new(),
            approvers: HashMap::new(),
            max_clock_skew_ms,
        }
    }

    pub fn register_server_key(
        &mut self,
        key_id: impl Into<String>,
        public_key_bytes: [u8; 32],
    ) -> Result<()> {
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)?;
        self.server_keys.insert(key_id.into(), verifying_key);
        Ok(())
    }

    pub fn register_approver(
        &mut self,
        approver_id: impl Into<String>,
        role: impl Into<String>,
        signing_key_id: impl Into<String>,
        public_key_bytes: [u8; 32],
    ) -> Result<()> {
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)?;
        self.approvers.insert(
            approver_id.into(),
            ApproverDirectoryEntry {
                role: role.into(),
                signing_key_id: signing_key_id.into(),
                verifying_key,
            },
        );
        Ok(())
    }

    pub fn validate(
        &self,
        signed_command: &SignedServerCommand,
        identity: &AgentIdentity,
        ledger: &mut CommandReplayLedger,
        now_ms: i64,
    ) -> Result<ValidatedCommand, CommandValidationError> {
        let verifying_key = self
            .server_keys
            .get(&signed_command.signing_key_id)
            .ok_or(CommandValidationError::UnknownSigningKey)?;
        let signature = Signature::from_slice(&signed_command.signature)
            .map_err(|_| CommandValidationError::InvalidSignature)?;
        verifying_key
            .verify(&signed_command.payload, &signature)
            .map_err(|_| CommandValidationError::InvalidSignature)?;

        let command: ServerCommand = serde_json::from_slice(&signed_command.payload)
            .map_err(|_| CommandValidationError::InvalidPayload)?;

        if command.tenant_id != identity.tenant_id {
            return Err(CommandValidationError::TenantMismatch);
        }
        validate_scope(&command, identity)?;
        validate_time(&command, self.max_clock_skew_ms, now_ms)?;

        let expires_at_ms = command
            .issued_at_ms
            .saturating_add(i64::from(command.ttl_ms));
        ledger.register(
            command.command_id,
            command.issued_at_ms,
            expires_at_ms,
            now_ms,
        )?;
        self.validate_approval_policy(&command, &identity.min_policy_version)?;

        Ok(ValidatedCommand {
            command,
            expires_at_ms,
        })
    }

    fn validate_approval_policy(
        &self,
        command: &ServerCommand,
        min_policy_version: &str,
    ) -> Result<(), CommandValidationError> {
        let requirement = approval_requirement(&command.command_type);
        let min_required = requirement
            .min_approvers
            .max(command.approval.min_approvers);
        if min_required == 0 {
            return Ok(());
        }

        if policy_version_rank(&command.approval.policy_version)
            < policy_version_rank(&requirement.min_policy_version)
                .max(policy_version_rank(min_policy_version))
        {
            return Err(CommandValidationError::PolicyVersionTooLow);
        }

        let canonical_hash = canonical_command_hash(command);
        let mut valid_approvers = HashSet::new();
        let mut valid_admin_present = false;

        for approver in &command.approval.approvers {
            let directory_entry = self
                .approvers
                .get(&approver.approver_id)
                .ok_or(CommandValidationError::ApprovalProofFailed)?;
            validate_approver_role(directory_entry, approver, &requirement)?;
            validate_approval_signature(directory_entry, approver, &canonical_hash)?;

            valid_admin_present |= approver.role == "security_admin";
            valid_approvers.insert(approver.approver_id.clone());
        }

        if valid_approvers.len() < min_required as usize {
            return Err(CommandValidationError::ApprovalProofFailed);
        }
        if requirement.require_distinct && valid_approvers.len() != command.approval.approvers.len()
        {
            return Err(CommandValidationError::ApprovalProofFailed);
        }
        if requirement.require_admin && !valid_admin_present {
            return Err(CommandValidationError::ApprovalProofFailed);
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedCommand {
    pub command: ServerCommand,
    pub expires_at_ms: i64,
}

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq)]
pub enum CommandValidationError {
    #[error("unknown signing key")]
    UnknownSigningKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid payload")]
    InvalidPayload,
    #[error("tenant mismatch")]
    TenantMismatch,
    #[error("scope violation")]
    ScopeViolation,
    #[error("global scope disabled")]
    GlobalScopeDisabled,
    #[error("expired command")]
    Expired,
    #[error("clock skew exceeds bound")]
    ClockSkewExceeded,
    #[error("replay detected")]
    ReplayDetected,
    #[error("rollback protection triggered")]
    RollbackProtectionTriggered,
    #[error("command replay ledger persistence failure")]
    PersistenceFailure,
    #[error("approval proof failed")]
    ApprovalProofFailed,
    #[error("approval policy version too low")]
    PolicyVersionTooLow,
}

struct ApprovalRequirement {
    min_approvers: u32,
    require_admin: bool,
    require_distinct: bool,
    min_policy_version: &'static str,
}

fn approval_requirement(command_type: &str) -> ApprovalRequirement {
    match command_type {
        "remote-shell" => ApprovalRequirement {
            min_approvers: 2,
            require_admin: true,
            require_distinct: true,
            min_policy_version: "v2",
        },
        "network-isolate"
        | "session-lock"
        | "filesystem-rollback"
        | "registry-rollback"
        | "remote-forensics" => ApprovalRequirement {
            min_approvers: 1,
            require_admin: false,
            require_distinct: false,
            min_policy_version: "v1",
        },
        _ => ApprovalRequirement {
            min_approvers: 0,
            require_admin: false,
            require_distinct: false,
            min_policy_version: "v0",
        },
    }
}

fn validate_scope(
    command: &ServerCommand,
    identity: &AgentIdentity,
) -> Result<(), CommandValidationError> {
    let scope = &command.target_scope;
    let tenant_matches = scope
        .tenant_id
        .as_deref()
        .map(|tenant_id| tenant_id == identity.tenant_id)
        .unwrap_or(false);

    match scope.kind {
        TargetScopeKind::Agent => {
            if command.agent_id == identity.agent_id && tenant_matches {
                Ok(())
            } else {
                Err(CommandValidationError::ScopeViolation)
            }
        }
        TargetScopeKind::Tenant => {
            if tenant_matches {
                Ok(())
            } else {
                Err(CommandValidationError::ScopeViolation)
            }
        }
        TargetScopeKind::AgentSet => {
            if tenant_matches
                && scope.agent_ids.len() <= scope.max_fanout as usize
                && scope
                    .agent_ids
                    .iter()
                    .any(|agent_id| agent_id == &identity.agent_id)
            {
                Ok(())
            } else {
                Err(CommandValidationError::ScopeViolation)
            }
        }
        TargetScopeKind::Global => {
            if identity.allow_global_scope {
                Ok(())
            } else {
                Err(CommandValidationError::GlobalScopeDisabled)
            }
        }
    }
}

fn validate_time(
    command: &ServerCommand,
    max_clock_skew_ms: i64,
    now_ms: i64,
) -> Result<(), CommandValidationError> {
    if (now_ms - command.issued_at_ms).abs() > max_clock_skew_ms {
        return Err(CommandValidationError::ClockSkewExceeded);
    }

    let expires_at_ms = command
        .issued_at_ms
        .saturating_add(i64::from(command.ttl_ms));
    if now_ms >= expires_at_ms {
        return Err(CommandValidationError::Expired);
    }

    Ok(())
}

fn validate_approver_role(
    directory_entry: &ApproverDirectoryEntry,
    approver: &ApproverEntry,
    requirement: &ApprovalRequirement,
) -> Result<(), CommandValidationError> {
    if directory_entry.role != approver.role {
        return Err(CommandValidationError::ApprovalProofFailed);
    }

    let role_allowed = match requirement.require_admin {
        true => approver.role == "security_admin" || approver.role == "security_analyst",
        false => matches!(
            approver.role.as_str(),
            "security_admin" | "security_analyst"
        ),
    };

    if role_allowed {
        Ok(())
    } else {
        Err(CommandValidationError::ApprovalProofFailed)
    }
}

fn validate_approval_signature(
    directory_entry: &ApproverDirectoryEntry,
    approver: &ApproverEntry,
    canonical_hash: &[u8],
) -> Result<(), CommandValidationError> {
    if directory_entry.signing_key_id != approver.proof.signing_key_id {
        return Err(CommandValidationError::ApprovalProofFailed);
    }

    let signature = Signature::from_slice(&approver.proof.signature)
        .map_err(|_| CommandValidationError::ApprovalProofFailed)?;
    directory_entry
        .verifying_key
        .verify(canonical_hash, &signature)
        .map_err(|_| CommandValidationError::ApprovalProofFailed)
}

pub(crate) fn canonical_command_hash(command: &ServerCommand) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(command.command_id.as_bytes());
    update_len_prefixed(&mut hasher, command.tenant_id.as_bytes());
    update_len_prefixed(&mut hasher, command.agent_id.as_bytes());
    update_len_prefixed(&mut hasher, command.command_type.as_bytes());
    update_len_prefixed(&mut hasher, &command.command_data);
    hasher.update(command.ttl_ms.to_be_bytes());
    update_len_prefixed(&mut hasher, command.approval.policy_version.as_bytes());
    hasher.finalize().into()
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

fn policy_version_rank(version: &str) -> u64 {
    version
        .trim_start_matches(|ch: char| !ch.is_ascii_digit())
        .chars()
        .skip_while(|ch| !ch.is_ascii_digit())
        .collect::<String>()
        .parse::<u64>()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_command_hash, AgentIdentity, CommandReplayLedger, CommandValidationError,
        CommandValidator, CommunicationRuntime, HeartbeatBuilder, TelemetryBatchBuilder,
        TransportDriver,
    };
    use crate::config::SecurityConfig;
    use aegis_model::{
        AgentHealth, ApprovalPolicy, ApprovalProof, ApproverEntry, CommunicationChannelKind,
        DownlinkMessage, EventPayload, EventType, FileContext, NormalizedEvent, Priority,
        ProcessContext, RuntimeHealthSignals, ServerCommand, Severity, SignedServerCommand,
        TargetScope, TargetScopeKind, TelemetryEvent, UplinkMessage,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::any::Any;
    use std::collections::{BTreeMap, VecDeque};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use uuid::Uuid;

    fn identity() -> AgentIdentity {
        AgentIdentity {
            tenant_id: "tenant-a".to_string(),
            agent_id: "agent-1".to_string(),
            allow_global_scope: false,
            min_policy_version: "v1".to_string(),
        }
    }

    fn target_scope() -> TargetScope {
        TargetScope {
            kind: TargetScopeKind::Agent,
            tenant_id: Some("tenant-a".to_string()),
            agent_ids: Vec::new(),
            max_fanout: 1,
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("aegis-{name}-{}", Uuid::now_v7()))
    }

    fn low_risk_command() -> ServerCommand {
        ServerCommand {
            command_id: Uuid::now_v7(),
            tenant_id: "tenant-a".to_string(),
            agent_id: "agent-1".to_string(),
            command_type: "kill-process".to_string(),
            command_data: b"{\"pid\":7}".to_vec(),
            issued_at_ms: 1_800_000_000,
            ttl_ms: 60_000,
            sequence_hint: 1,
            approval: ApprovalPolicy {
                min_approvers: 0,
                approvers: Vec::new(),
                policy_version: "v1".to_string(),
            },
            target_scope: target_scope(),
        }
    }

    fn sign_server_command(
        command: &ServerCommand,
        signing_key: &SigningKey,
    ) -> SignedServerCommand {
        let payload = serde_json::to_vec(command).expect("serialize server command");
        let signature = signing_key.sign(&payload).to_bytes().to_vec();
        SignedServerCommand {
            payload,
            signature,
            signing_key_id: "server-k1".to_string(),
        }
    }

    fn approver_entry(
        command: &ServerCommand,
        approver_id: &str,
        role: &str,
        signing_key_id: &str,
        signing_key: &SigningKey,
    ) -> ApproverEntry {
        let signature = signing_key
            .sign(&canonical_command_hash(command))
            .to_bytes()
            .to_vec();
        ApproverEntry {
            approver_id: approver_id.to_string(),
            role: role.to_string(),
            proof: ApprovalProof {
                signature,
                signing_key_id: signing_key_id.to_string(),
            },
        }
    }

    fn health() -> AgentHealth {
        AgentHealth {
            agent_version: "0.1.0".to_string(),
            policy_version: "v2".to_string(),
            ruleset_version: "r1".to_string(),
            model_version: "m1".to_string(),
            cpu_percent_p95: 12.5,
            memory_rss_mb: 128,
            queue_depths: BTreeMap::from([("telemetry".to_string(), 4)]),
            dropped_events_total: 0,
            lineage_counters: Default::default(),
            runtime_signals: RuntimeHealthSignals {
                communication_channel: CommunicationChannelKind::Grpc,
                adaptive_whitelist_size: 2,
                etw_tamper_detected: false,
                amsi_tamper_detected: false,
                bpf_integrity_pass: true,
            },
        }
    }

    struct MockTransportDriver {
        channel: CommunicationChannelKind,
        send_results: Mutex<VecDeque<anyhow::Result<()>>>,
        probe_results: Mutex<VecDeque<bool>>,
    }

    impl MockTransportDriver {
        fn new(
            channel: CommunicationChannelKind,
            send_results: Vec<anyhow::Result<()>>,
            probe_results: Vec<bool>,
        ) -> Self {
            Self {
                channel,
                send_results: Mutex::new(send_results.into()),
                probe_results: Mutex::new(probe_results.into()),
            }
        }

        fn next_send_result(&self) -> anyhow::Result<()> {
            self.send_results
                .lock()
                .expect("send queue poisoned")
                .pop_front()
                .unwrap_or(Ok(()))
        }
    }

    impl TransportDriver for MockTransportDriver {
        fn channel(&self) -> CommunicationChannelKind {
            self.channel
        }

        fn send_uplink(&self, _message: &UplinkMessage) -> anyhow::Result<()> {
            self.next_send_result()
        }

        fn send_heartbeat(&self, _heartbeat: &aegis_model::HeartbeatRequest) -> anyhow::Result<()> {
            self.next_send_result()
        }

        fn recv_downlink(&self) -> anyhow::Result<Option<DownlinkMessage>> {
            Ok(None)
        }

        fn probe(&self) -> bool {
            self.probe_results
                .lock()
                .expect("probe queue poisoned")
                .pop_front()
                .unwrap_or(true)
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn telemetry_batch_and_heartbeat_builders_emit_expected_models() {
        let builder = TelemetryBatchBuilder::new(4);
        let event = TelemetryEvent::from_normalized(
            &NormalizedEvent::new(
                42,
                EventType::FileWrite,
                Priority::High,
                Severity::High,
                ProcessContext::default(),
                EventPayload::File(FileContext::default()),
            ),
            "tenant-a".to_string(),
            "agent-1".to_string(),
        );

        let uplink = builder
            .build("tenant-a", "agent-1", 9, vec![event])
            .expect("build uplink");
        let communication = CommunicationRuntime::with_loopback_drivers(3).snapshot();
        let heartbeat =
            HeartbeatBuilder::build("tenant-a", "agent-1", health(), communication, 0.2, 3);

        match uplink {
            UplinkMessage::EventBatch(batch) => {
                assert_eq!(batch.agent_id, "agent-1");
                assert_eq!(batch.sequence_hint, 9);
                assert_eq!(batch.events.len(), 1);
            }
            _ => panic!("expected event batch"),
        }
        assert_eq!(heartbeat.agent_id, "agent-1");
        assert_eq!(heartbeat.restart_epoch, 3);
        assert_eq!(
            heartbeat.communication.active_channel,
            CommunicationChannelKind::Grpc
        );
    }

    #[test]
    fn communication_runtime_falls_back_after_three_failures() {
        let mut runtime = CommunicationRuntime::new(3);
        runtime.register_driver(Box::new(MockTransportDriver::new(
            CommunicationChannelKind::Grpc,
            vec![
                Err(anyhow::anyhow!("grpc-1")),
                Err(anyhow::anyhow!("grpc-2")),
                Err(anyhow::anyhow!("grpc-3")),
            ],
            vec![false],
        )));
        runtime.register_driver(Box::new(MockTransportDriver::new(
            CommunicationChannelKind::WebSocket,
            vec![Ok(())],
            vec![true],
        )));
        runtime.register_driver(Box::new(MockTransportDriver::new(
            CommunicationChannelKind::LongPolling,
            vec![Ok(())],
            vec![true],
        )));
        runtime.register_driver(Box::new(MockTransportDriver::new(
            CommunicationChannelKind::DomainFronting,
            vec![Ok(())],
            vec![true],
        )));
        let uplink = UplinkMessage::ClientAck(aegis_model::ClientAck {
            command_id: Uuid::now_v7(),
            status: aegis_model::ClientAckStatus::Received,
            detail: None,
            acked_at: 0,
        });

        for now_ms in [1_000, 2_000, 3_000] {
            assert!(runtime.send_uplink(&uplink, now_ms).is_err());
        }

        let active = runtime
            .send_uplink(&uplink, 4_000)
            .expect("websocket should take over");
        let snapshot = runtime.snapshot();

        assert_eq!(active, CommunicationChannelKind::WebSocket);
        assert_eq!(snapshot.active_channel, CommunicationChannelKind::WebSocket);
        assert!(snapshot.degraded);
        let grpc = snapshot
            .channels
            .iter()
            .find(|status| status.channel == CommunicationChannelKind::Grpc)
            .expect("grpc state");
        assert_eq!(grpc.consecutive_failures, 3);
        assert_eq!(grpc.last_error.as_deref(), Some("grpc-3"));
    }

    #[test]
    fn communication_runtime_promotes_recovered_higher_priority_channel() {
        let mut runtime = CommunicationRuntime::new(2);
        runtime.register_driver(Box::new(MockTransportDriver::new(
            CommunicationChannelKind::Grpc,
            vec![
                Err(anyhow::anyhow!("grpc-down-1")),
                Err(anyhow::anyhow!("grpc-down-2")),
            ],
            vec![true],
        )));
        runtime.register_driver(Box::new(MockTransportDriver::new(
            CommunicationChannelKind::WebSocket,
            vec![Ok(())],
            vec![true],
        )));
        runtime.register_driver(Box::new(MockTransportDriver::new(
            CommunicationChannelKind::LongPolling,
            vec![Ok(())],
            vec![true],
        )));
        runtime.register_driver(Box::new(MockTransportDriver::new(
            CommunicationChannelKind::DomainFronting,
            vec![Ok(())],
            vec![true],
        )));
        let heartbeat = HeartbeatBuilder::build(
            "tenant-a",
            "agent-1",
            health(),
            CommunicationRuntime::with_loopback_drivers(2).snapshot(),
            0.2,
            1,
        );

        assert!(runtime.send_heartbeat(&heartbeat, 1_000).is_err());
        assert!(runtime.send_heartbeat(&heartbeat, 2_000).is_err());
        assert_eq!(
            runtime.active_channel(),
            CommunicationChannelKind::WebSocket
        );

        let promoted = runtime.probe_upgrade(3_000).expect("grpc recovered");
        let snapshot = runtime.snapshot();

        assert_eq!(promoted, CommunicationChannelKind::Grpc);
        assert_eq!(snapshot.active_channel, CommunicationChannelKind::Grpc);
        assert!(!snapshot.degraded);
    }

    #[test]
    fn communication_runtime_polls_loopback_downlink_and_records_uplink() {
        let (mut runtime, handles) = CommunicationRuntime::with_loopback_drivers_and_handles(2);
        let grpc = handles
            .get(&CommunicationChannelKind::Grpc)
            .expect("grpc handle");
        let command_id = Uuid::now_v7();
        grpc.inject_downlink(DownlinkMessage::ServerCommand(SignedServerCommand {
            payload: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            signing_key_id: "server-k1".to_string(),
        }));

        let polled = runtime
            .poll_downlink(1_000)
            .expect("poll downlink")
            .expect("downlink message");
        assert_eq!(polled.0, CommunicationChannelKind::Grpc);
        match polled.1 {
            DownlinkMessage::ServerCommand(command) => {
                assert_eq!(command.signing_key_id, "server-k1");
            }
            _ => panic!("expected server command"),
        }

        let uplink = UplinkMessage::ClientAck(aegis_model::ClientAck {
            command_id,
            status: aegis_model::ClientAckStatus::Executed,
            detail: None,
            acked_at: 0,
        });
        runtime
            .send_uplink(&uplink, 1_100)
            .expect("send loopback uplink");
        assert_eq!(grpc.take_uplinks(), vec![uplink]);
    }

    #[test]
    fn command_replay_ledger_persists_across_reopen() {
        let path = temp_path("command-replay.db");
        let command_id = Uuid::now_v7();
        let mut first = CommandReplayLedger::new_persistent(path.clone()).expect("create ledger");
        first
            .register(command_id, 5_000, 10_000, 1_000)
            .expect("first register");

        let mut reopened =
            CommandReplayLedger::new_persistent(path).expect("reopen persistent ledger");
        let error = reopened
            .register(command_id, 5_000, 10_000, 1_100)
            .expect_err("replay should be persisted");
        assert_eq!(error, CommandValidationError::ReplayDetected);
    }

    #[test]
    fn command_replay_ledger_rejects_rollbacked_issued_at() {
        let path = temp_path("command-replay-floor.db");
        let security = SecurityConfig {
            use_os_credential_store: false,
            allow_file_fallback: true,
            memory_lock_best_effort: false,
        };
        let mut first = CommandReplayLedger::new_persistent_with_security(path.clone(), &security)
            .expect("create ledger");
        first
            .register(Uuid::now_v7(), 8_000, 20_000, 1_000)
            .expect("first register");

        let mut reopened = CommandReplayLedger::new_persistent_with_security(path, &security)
            .expect("reopen persistent ledger");
        let error = reopened
            .register(Uuid::now_v7(), 7_000, 21_000, 1_100)
            .expect_err("older issued_at should be rejected");

        assert_eq!(error, CommandValidationError::RollbackProtectionTriggered);
        assert_eq!(reopened.rollback_status().floor_issued_at_ms, Some(8_000));
        assert!(reopened.rollback_status().cross_check_ok);
    }

    #[test]
    fn command_validator_accepts_valid_signed_command_with_approval() {
        let server_signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let admin_signing_key = SigningKey::from_bytes(&[2u8; 32]);
        let analyst_signing_key = SigningKey::from_bytes(&[3u8; 32]);

        let mut command = ServerCommand {
            command_type: "remote-shell".to_string(),
            approval: ApprovalPolicy {
                min_approvers: 2,
                approvers: Vec::new(),
                policy_version: "v2".to_string(),
            },
            ..low_risk_command()
        };
        command.approval.approvers = vec![
            approver_entry(
                &command,
                "approver-admin",
                "security_admin",
                "approver-admin-k1",
                &admin_signing_key,
            ),
            approver_entry(
                &command,
                "approver-analyst",
                "security_analyst",
                "approver-analyst-k1",
                &analyst_signing_key,
            ),
        ];

        let signed = sign_server_command(&command, &server_signing_key);
        let mut validator = CommandValidator::new(300_000);
        validator
            .register_server_key("server-k1", server_signing_key.verifying_key().to_bytes())
            .expect("register server key");
        validator
            .register_approver(
                "approver-admin",
                "security_admin",
                "approver-admin-k1",
                admin_signing_key.verifying_key().to_bytes(),
            )
            .expect("register admin");
        validator
            .register_approver(
                "approver-analyst",
                "security_analyst",
                "approver-analyst-k1",
                analyst_signing_key.verifying_key().to_bytes(),
            )
            .expect("register analyst");

        let validated = validator
            .validate(
                &signed,
                &identity(),
                &mut CommandReplayLedger::default(),
                1_800_059_000,
            )
            .expect("valid command");

        assert_eq!(validated.command.command_type, "remote-shell");
    }

    #[test]
    fn command_validator_rejects_scope_violation() {
        let signing_key = SigningKey::from_bytes(&[4u8; 32]);
        let mut command = low_risk_command();
        command.target_scope = TargetScope {
            kind: TargetScopeKind::AgentSet,
            tenant_id: Some("tenant-a".to_string()),
            agent_ids: vec!["agent-2".to_string()],
            max_fanout: 1,
        };
        let signed = sign_server_command(&command, &signing_key);

        let mut validator = CommandValidator::new(300_000);
        validator
            .register_server_key("server-k1", signing_key.verifying_key().to_bytes())
            .expect("register server key");

        let error = validator
            .validate(
                &signed,
                &identity(),
                &mut CommandReplayLedger::default(),
                1_800_010_000,
            )
            .expect_err("scope violation expected");

        assert_eq!(error, CommandValidationError::ScopeViolation);
    }

    #[test]
    fn command_validator_rejects_replay() {
        let signing_key = SigningKey::from_bytes(&[5u8; 32]);
        let command = low_risk_command();
        let signed = sign_server_command(&command, &signing_key);
        let mut ledger = CommandReplayLedger::default();
        let mut validator = CommandValidator::new(300_000);
        validator
            .register_server_key("server-k1", signing_key.verifying_key().to_bytes())
            .expect("register server key");

        validator
            .validate(&signed, &identity(), &mut ledger, 1_800_010_000)
            .expect("first validation");
        let error = validator
            .validate(&signed, &identity(), &mut ledger, 1_800_020_000)
            .expect_err("replay should be rejected");

        assert_eq!(error, CommandValidationError::ReplayDetected);
    }

    #[test]
    fn command_validator_rejects_invalid_approval_proof() {
        let server_signing_key = SigningKey::from_bytes(&[6u8; 32]);
        let admin_signing_key = SigningKey::from_bytes(&[7u8; 32]);

        let mut command = ServerCommand {
            command_type: "remote-shell".to_string(),
            approval: ApprovalPolicy {
                min_approvers: 2,
                approvers: Vec::new(),
                policy_version: "v2".to_string(),
            },
            ..low_risk_command()
        };
        command.approval.approvers = vec![approver_entry(
            &command,
            "approver-admin",
            "security_admin",
            "wrong-key-id",
            &admin_signing_key,
        )];
        let signed = sign_server_command(&command, &server_signing_key);

        let mut validator = CommandValidator::new(300_000);
        validator
            .register_server_key("server-k1", server_signing_key.verifying_key().to_bytes())
            .expect("register server key");
        validator
            .register_approver(
                "approver-admin",
                "security_admin",
                "approver-admin-k1",
                admin_signing_key.verifying_key().to_bytes(),
            )
            .expect("register approver");

        let error = validator
            .validate(
                &signed,
                &identity(),
                &mut CommandReplayLedger::default(),
                1_800_010_000,
            )
            .expect_err("approval failure expected");

        assert_eq!(error, CommandValidationError::ApprovalProofFailed);
    }
}
