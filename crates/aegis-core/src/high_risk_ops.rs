use aegis_model::CommandEnvelope;
use anyhow::{anyhow, bail, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const DEFAULT_APPROVAL_TTL_SECS: u64 = 30 * 60;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApprovalState {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub request_id: Uuid,
    pub envelope: CommandEnvelope,
    pub requested_by: String,
    pub command: String,
    pub state: ApprovalState,
    pub approved_by: Vec<String>,
    pub requested_at_ns: u64,
    pub expires_at_ns: u64,
}

impl ApprovalRequest {
    pub fn is_expired(&self, now_ns: u64) -> bool {
        now_ns >= self.expires_at_ns
    }
}

enum ApprovalBackend {
    Memory(VecDeque<ApprovalRequest>),
    Sqlite(PathBuf),
}

pub struct ApprovalQueue {
    backend: ApprovalBackend,
    default_ttl: Duration,
}

impl Default for ApprovalQueue {
    fn default() -> Self {
        Self {
            backend: ApprovalBackend::Memory(VecDeque::new()),
            default_ttl: Duration::from_secs(DEFAULT_APPROVAL_TTL_SECS),
        }
    }
}

impl ApprovalQueue {
    pub fn new_persistent(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        initialize_sqlite_backend(&path)?;
        Ok(Self {
            backend: ApprovalBackend::Sqlite(path),
            default_ttl: Duration::from_secs(DEFAULT_APPROVAL_TTL_SECS),
        })
    }

    pub fn enqueue(
        &mut self,
        envelope: CommandEnvelope,
        requested_by: impl Into<String>,
        command: impl Into<String>,
    ) -> Result<Uuid> {
        self.enqueue_with_ttl(
            envelope,
            requested_by.into(),
            command.into(),
            self.default_ttl,
            now_unix_ns(),
        )
    }

    pub fn enqueue_with_ttl(
        &mut self,
        envelope: CommandEnvelope,
        requested_by: String,
        command: String,
        ttl: Duration,
        now_ns: u64,
    ) -> Result<Uuid> {
        let request = ApprovalRequest {
            request_id: Uuid::now_v7(),
            envelope,
            requested_by,
            command,
            state: ApprovalState::Pending,
            approved_by: Vec::new(),
            requested_at_ns: now_ns,
            expires_at_ns: now_ns.saturating_add(ttl.as_nanos() as u64),
        };
        let request_id = request.request_id;
        self.upsert_request(request)?;
        Ok(request_id)
    }

    pub fn pending_len(&self) -> Result<usize> {
        Ok(self
            .load_requests()?
            .into_iter()
            .filter(|request| request.state == ApprovalState::Pending)
            .count())
    }

    pub fn get(&self, request_id: Uuid) -> Result<Option<ApprovalRequest>> {
        Ok(self
            .load_requests()?
            .into_iter()
            .find(|request| request.request_id == request_id))
    }

    pub fn approve(
        &mut self,
        request_id: Uuid,
        approver_id: impl Into<String>,
        now_ns: u64,
    ) -> Result<Option<ApprovalRequest>> {
        let approver_id = approver_id.into();
        let Some(mut request) = self.get(request_id)? else {
            return Ok(None);
        };
        if request.is_expired(now_ns) {
            request.state = ApprovalState::Expired;
            self.upsert_request(request.clone())?;
            return Ok(Some(request));
        }
        if request.state == ApprovalState::Rejected {
            return Ok(Some(request));
        }
        if request
            .approved_by
            .iter()
            .all(|value| value != &approver_id)
        {
            request.approved_by.push(approver_id);
        }
        let min_approvers = request.envelope.approval.min_approvers.max(1) as usize;
        request.state = if request.approved_by.len() >= min_approvers {
            ApprovalState::Approved
        } else {
            ApprovalState::Pending
        };
        self.upsert_request(request.clone())?;
        Ok(Some(request))
    }

    pub fn reject(&mut self, request_id: Uuid) -> Result<Option<ApprovalRequest>> {
        let Some(mut request) = self.get(request_id)? else {
            return Ok(None);
        };
        request.state = ApprovalState::Rejected;
        self.upsert_request(request.clone())?;
        Ok(Some(request))
    }

    pub fn expire_stale(&mut self, now_ns: u64) -> Result<usize> {
        let mut requests = self.load_requests()?;
        let mut expired = 0usize;
        for request in &mut requests {
            if matches!(
                request.state,
                ApprovalState::Pending | ApprovalState::Approved
            ) && request.is_expired(now_ns)
            {
                request.state = ApprovalState::Expired;
                expired += 1;
            }
        }
        self.replace_all(requests)?;
        Ok(expired)
    }

    fn load_requests(&self) -> Result<Vec<ApprovalRequest>> {
        match &self.backend {
            ApprovalBackend::Memory(pending) => Ok(pending.iter().cloned().collect()),
            ApprovalBackend::Sqlite(path) => {
                let connection = Connection::open(path)?;
                let mut statement = connection.prepare(
                    "SELECT payload FROM approval_requests ORDER BY requested_at_ns ASC",
                )?;
                let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
                let mut requests = Vec::new();
                for row in rows {
                    let payload = row?;
                    requests.push(serde_json::from_str::<ApprovalRequest>(&payload)?);
                }
                Ok(requests)
            }
        }
    }

    fn upsert_request(&mut self, request: ApprovalRequest) -> Result<()> {
        match &mut self.backend {
            ApprovalBackend::Memory(pending) => {
                if let Some(existing) = pending
                    .iter_mut()
                    .find(|existing| existing.request_id == request.request_id)
                {
                    *existing = request;
                } else {
                    pending.push_back(request);
                }
                Ok(())
            }
            ApprovalBackend::Sqlite(path) => {
                let connection = Connection::open(path)?;
                connection.execute(
                    "INSERT INTO approval_requests(request_id, requested_at_ns, payload)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(request_id) DO UPDATE SET
                       requested_at_ns = excluded.requested_at_ns,
                       payload = excluded.payload",
                    params![
                        request.request_id.to_string(),
                        request.requested_at_ns as i64,
                        serde_json::to_string(&request)?,
                    ],
                )?;
                Ok(())
            }
        }
    }

    fn replace_all(&mut self, requests: Vec<ApprovalRequest>) -> Result<()> {
        match &mut self.backend {
            ApprovalBackend::Memory(pending) => {
                *pending = requests.into();
                Ok(())
            }
            ApprovalBackend::Sqlite(path) => {
                let mut connection = Connection::open(path)?;
                let transaction = connection.transaction()?;
                transaction.execute("DELETE FROM approval_requests", [])?;
                for request in requests {
                    transaction.execute(
                        "INSERT INTO approval_requests(request_id, requested_at_ns, payload)
                         VALUES (?1, ?2, ?3)",
                        params![
                            request.request_id.to_string(),
                            request.requested_at_ns as i64,
                            serde_json::to_string(&request)?,
                        ],
                    )?;
                }
                transaction.commit()?;
                Ok(())
            }
        }
    }
}

fn initialize_sqlite_backend(path: &Path) -> Result<()> {
    let connection = Connection::open(path)?;
    connection.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS approval_requests (
            request_id TEXT PRIMARY KEY,
            requested_at_ns INTEGER NOT NULL,
            payload TEXT NOT NULL
        );
        ",
    )?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkingHours {
    pub start_hour_utc: u8,
    pub end_hour_utc: u8,
}

impl WorkingHours {
    fn contains(&self, now_ns: u64) -> bool {
        let hour = ((now_ns / 1_000_000_000) / 3_600 % 24) as u8;
        if self.start_hour_utc <= self.end_hour_utc {
            hour >= self.start_hour_utc && hour < self.end_hour_utc
        } else {
            hour >= self.start_hour_utc || hour < self.end_hour_utc
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteShellPolicy {
    pub allowed_prefixes: Vec<String>,
    pub denied_patterns: Vec<String>,
    pub timeout_secs: u64,
    pub max_session_secs: u64,
    pub max_concurrent_sessions: usize,
    pub whitelist_mode: bool,
    pub allowed_hours: Option<WorkingHours>,
}

impl Default for RemoteShellPolicy {
    fn default() -> Self {
        Self {
            allowed_prefixes: Vec::new(),
            denied_patterns: vec![
                "rm -rf".to_string(),
                "format".to_string(),
                "mkfs".to_string(),
                "dd if=/dev/zero".to_string(),
                "chmod 777".to_string(),
                "psexec".to_string(),
            ],
            timeout_secs: 30,
            max_session_secs: 30 * 60,
            max_concurrent_sessions: 1,
            whitelist_mode: true,
            allowed_hours: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreApprovedPlaybook {
    pub playbook_id: String,
    pub allowed_commands: Vec<String>,
    pub timeout_secs: u64,
    pub max_executions: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum HighRiskActionKind {
    RemoteShell,
    SessionLock,
    Playbook,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HighRiskAuditRecord {
    pub audit_id: Uuid,
    pub action: HighRiskActionKind,
    pub allowed: bool,
    pub detail: String,
    pub timestamp_ns: u64,
    pub session_id: Option<Uuid>,
    pub audit_path: Option<PathBuf>,
    pub status_code: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandRunOutput {
    pub status_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

pub trait CommandRunner: Send + Sync {
    fn run(&self, command: &str, timeout: Duration) -> Result<CommandRunOutput>;
}

pub struct StdCommandRunner;

impl CommandRunner for StdCommandRunner {
    fn run(&self, command: &str, timeout: Duration) -> Result<CommandRunOutput> {
        let mut parts = command.split_whitespace();
        let executable = parts
            .next()
            .ok_or_else(|| anyhow!("remote shell command is empty"))?;
        let mut child = Command::new(executable)
            .args(parts)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let start = SystemTime::now();

        loop {
            if child.try_wait()?.is_some() {
                let output = child.wait_with_output()?;
                return Ok(CommandRunOutput {
                    status_code: output.status.code().unwrap_or_default(),
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                    timed_out: false,
                });
            }

            if start.elapsed().unwrap_or_default() >= timeout {
                child.kill()?;
                let output = child.wait_with_output()?;
                return Ok(CommandRunOutput {
                    status_code: output.status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                    timed_out: true,
                });
            }

            thread::sleep(Duration::from_millis(10));
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteShellSession {
    pub session_id: Uuid,
    pub endpoint_id: String,
    pub operator: String,
    pub started_at_ns: u64,
    pub expires_at_ns: u64,
    pub audit_path: PathBuf,
}

pub struct RemoteShellRuntime<R = StdCommandRunner> {
    policy: RemoteShellPolicy,
    audit_root: PathBuf,
    runner: R,
    sessions: Mutex<HashMap<Uuid, RemoteShellSession>>,
}

impl RemoteShellRuntime<StdCommandRunner> {
    pub fn new(policy: RemoteShellPolicy, audit_root: PathBuf) -> Self {
        Self::with_runner(policy, audit_root, StdCommandRunner)
    }
}

impl<R: CommandRunner> RemoteShellRuntime<R> {
    pub fn with_runner(policy: RemoteShellPolicy, audit_root: PathBuf, runner: R) -> Self {
        Self {
            policy,
            audit_root,
            runner,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn begin_session(
        &self,
        request: &ApprovalRequest,
        endpoint_id: impl Into<String>,
        operator: impl Into<String>,
        now_ns: u64,
    ) -> Result<RemoteShellSession> {
        validate_approval_request(request, now_ns)?;
        if let Some(hours) = self.policy.allowed_hours {
            if !hours.contains(now_ns) {
                bail!("remote shell is outside the approved working hours window");
            }
        }

        let endpoint_id = endpoint_id.into();
        let operator = operator.into();
        let mut sessions = self
            .sessions
            .lock()
            .expect("remote shell sessions poisoned");
        let active_for_endpoint = sessions
            .values()
            .filter(|session| session.endpoint_id == endpoint_id)
            .count();
        if active_for_endpoint >= self.policy.max_concurrent_sessions {
            bail!("endpoint already has an active remote shell session");
        }

        fs::create_dir_all(&self.audit_root)?;
        let session = RemoteShellSession {
            session_id: Uuid::now_v7(),
            endpoint_id,
            operator,
            started_at_ns: now_ns,
            expires_at_ns: now_ns.saturating_add(self.policy.max_session_secs * 1_000_000_000),
            audit_path: self.audit_root.join(format!("{}.cast", Uuid::now_v7())),
        };
        write_asciicast_header(&session.audit_path, &session)?;
        sessions.insert(session.session_id, session.clone());
        Ok(session)
    }

    pub fn run_command(
        &self,
        session_id: Uuid,
        command: &str,
        now_ns: u64,
    ) -> Result<HighRiskAuditRecord> {
        let session = {
            let sessions = self
                .sessions
                .lock()
                .expect("remote shell sessions poisoned");
            sessions
                .get(&session_id)
                .cloned()
                .ok_or_else(|| anyhow!("remote shell session is not active"))?
        };
        if now_ns >= session.expires_at_ns {
            bail!("remote shell session has expired");
        }
        validate_command_policy(command, &self.policy)?;

        append_asciicast_event(
            &session.audit_path,
            session.started_at_ns,
            now_ns,
            "i",
            command,
        )?;
        let output = self
            .runner
            .run(command, Duration::from_secs(self.policy.timeout_secs))?;
        let output_payload = format!("{}{}", output.stdout, output.stderr);
        append_asciicast_event(
            &session.audit_path,
            session.started_at_ns,
            now_unix_ns(),
            "o",
            &output_payload,
        )?;

        Ok(HighRiskAuditRecord {
            audit_id: Uuid::now_v7(),
            action: HighRiskActionKind::RemoteShell,
            allowed: !output.timed_out,
            detail: if output.timed_out {
                format!("remote shell command timed out: {command}")
            } else {
                format!("remote shell command completed: {command}")
            },
            timestamp_ns: now_unix_ns(),
            session_id: Some(session_id),
            audit_path: Some(session.audit_path),
            status_code: Some(output.status_code),
        })
    }

    pub fn end_session(&self, session_id: Uuid, now_ns: u64) -> Result<HighRiskAuditRecord> {
        let session = self
            .sessions
            .lock()
            .expect("remote shell sessions poisoned")
            .remove(&session_id)
            .ok_or_else(|| anyhow!("remote shell session is not active"))?;
        append_asciicast_event(
            &session.audit_path,
            session.started_at_ns,
            now_ns,
            "o",
            "[EOF]",
        )?;
        Ok(HighRiskAuditRecord {
            audit_id: Uuid::now_v7(),
            action: HighRiskActionKind::RemoteShell,
            allowed: true,
            detail: format!("remote shell session closed for {}", session.endpoint_id),
            timestamp_ns: now_ns,
            session_id: Some(session_id),
            audit_path: Some(session.audit_path),
            status_code: None,
        })
    }

    pub fn execute(
        &self,
        request: &ApprovalRequest,
        endpoint_id: &str,
        operator: &str,
    ) -> Result<HighRiskAuditRecord> {
        let now_ns = now_unix_ns();
        let session = self.begin_session(request, endpoint_id, operator, now_ns)?;
        let result = self.run_command(session.session_id, &request.command, now_ns)?;
        self.end_session(session.session_id, now_unix_ns())?;
        Ok(result)
    }
}

fn validate_approval_request(request: &ApprovalRequest, now_ns: u64) -> Result<()> {
    if request.state != ApprovalState::Approved {
        bail!("approval request is not approved");
    }
    if request.is_expired(now_ns) {
        bail!("approval request has expired");
    }
    let min_approvers = request.envelope.approval.min_approvers.max(1) as usize;
    let distinct_approvers = request
        .approved_by
        .iter()
        .cloned()
        .collect::<HashSet<_>>()
        .len();
    if distinct_approvers < min_approvers {
        bail!("approval request is missing required approvers");
    }
    Ok(())
}

fn validate_command_policy(command: &str, policy: &RemoteShellPolicy) -> Result<()> {
    if policy
        .denied_patterns
        .iter()
        .any(|pattern| command.contains(pattern))
    {
        bail!("remote shell command matched the deny list");
    }
    if policy.whitelist_mode
        && !policy
            .allowed_prefixes
            .iter()
            .any(|prefix| command.starts_with(prefix))
    {
        bail!("remote shell command is not on the allow list");
    }
    Ok(())
}

fn write_asciicast_header(path: &Path, session: &RemoteShellSession) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    writeln!(
        file,
        "{{\"version\":2,\"width\":120,\"height\":30,\"timestamp\":{},\"env\":{{\"AegisEndpoint\":\"{}\",\"Operator\":\"{}\"}}}}",
        session.started_at_ns / 1_000_000_000,
        session.endpoint_id,
        session.operator,
    )?;
    Ok(())
}

fn append_asciicast_event(
    path: &Path,
    started_at_ns: u64,
    now_ns: u64,
    kind: &str,
    payload: &str,
) -> Result<()> {
    let offset = (now_ns.saturating_sub(started_at_ns) as f64) / 1_000_000_000_f64;
    let escaped = serde_json::to_string(payload)?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "[{offset:.6},\"{kind}\",{escaped}]")?;
    Ok(())
}

pub struct PlaybookRuntime {
    executions: Mutex<HashMap<String, usize>>,
}

impl Default for PlaybookRuntime {
    fn default() -> Self {
        Self {
            executions: Mutex::new(HashMap::new()),
        }
    }
}

impl PlaybookRuntime {
    pub fn execute(
        &self,
        request: &ApprovalRequest,
        playbook: &PreApprovedPlaybook,
        now_ns: u64,
    ) -> Result<HighRiskAuditRecord> {
        validate_approval_request(request, now_ns)?;
        let allowed = playbook
            .allowed_commands
            .iter()
            .any(|prefix| request.command.starts_with(prefix));
        if !allowed {
            return Ok(HighRiskAuditRecord {
                audit_id: Uuid::now_v7(),
                action: HighRiskActionKind::Playbook,
                allowed: false,
                detail: format!(
                    "playbook {} rejected command {}",
                    playbook.playbook_id, request.command
                ),
                timestamp_ns: now_ns,
                session_id: None,
                audit_path: None,
                status_code: None,
            });
        }

        let mut executions = self
            .executions
            .lock()
            .expect("playbook executions poisoned");
        let entry = executions.entry(playbook.playbook_id.clone()).or_insert(0);
        if *entry >= playbook.max_executions {
            bail!("playbook execution limit reached");
        }
        *entry += 1;

        Ok(HighRiskAuditRecord {
            audit_id: Uuid::now_v7(),
            action: HighRiskActionKind::Playbook,
            allowed: true,
            detail: format!(
                "playbook {} executed under {}s timeout ({}/{})",
                playbook.playbook_id, playbook.timeout_secs, *entry, playbook.max_executions
            ),
            timestamp_ns: now_ns,
            session_id: None,
            audit_path: None,
            status_code: None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionLockRequest {
    pub user_session: String,
    pub reason: String,
}

pub struct SessionLockRuntime {
    locks: Mutex<HashMap<String, SessionLockRequest>>,
}

impl Default for SessionLockRuntime {
    fn default() -> Self {
        Self {
            locks: Mutex::new(HashMap::new()),
        }
    }
}

impl SessionLockRuntime {
    pub fn lock(&self, request: SessionLockRequest) -> HighRiskAuditRecord {
        self.locks
            .lock()
            .expect("session lock store poisoned")
            .insert(request.user_session.clone(), request.clone());
        HighRiskAuditRecord {
            audit_id: Uuid::now_v7(),
            action: HighRiskActionKind::SessionLock,
            allowed: true,
            detail: format!(
                "session {} locked: {}",
                request.user_session, request.reason
            ),
            timestamp_ns: now_unix_ns(),
            session_id: None,
            audit_path: None,
            status_code: None,
        }
    }

    pub fn release(&self, user_session: &str, reason: &str) -> Result<HighRiskAuditRecord> {
        let existed = self
            .locks
            .lock()
            .expect("session lock store poisoned")
            .remove(user_session)
            .is_some();
        if !existed {
            bail!("session is not locked");
        }
        Ok(HighRiskAuditRecord {
            audit_id: Uuid::now_v7(),
            action: HighRiskActionKind::SessionLock,
            allowed: true,
            detail: format!("session {user_session} released: {reason}"),
            timestamp_ns: now_unix_ns(),
            session_id: None,
            audit_path: None,
            status_code: None,
        })
    }

    pub fn is_locked(&self, user_session: &str) -> bool {
        self.locks
            .lock()
            .expect("session lock store poisoned")
            .contains_key(user_session)
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
        ApprovalQueue, ApprovalState, CommandRunOutput, CommandRunner, HighRiskActionKind,
        PlaybookRuntime, PreApprovedPlaybook, RemoteShellPolicy, RemoteShellRuntime,
        SessionLockRequest, SessionLockRuntime, WorkingHours,
    };
    use aegis_model::{ApprovalPolicy, CommandEnvelope};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use uuid::Uuid;

    fn envelope(min_approvers: u32) -> CommandEnvelope {
        CommandEnvelope {
            command_id: Uuid::now_v7(),
            command_type: "remote-shell".to_string(),
            target_scope: "host-a".to_string(),
            approval: ApprovalPolicy {
                min_approvers,
                approvers: Vec::new(),
                policy_version: "v1".to_string(),
            },
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("aegis-{name}-{}", Uuid::now_v7()))
    }

    #[derive(Default)]
    struct MockCommandRunner {
        invocations: Mutex<Vec<String>>,
    }

    impl CommandRunner for MockCommandRunner {
        fn run(
            &self,
            command: &str,
            _timeout: std::time::Duration,
        ) -> anyhow::Result<CommandRunOutput> {
            self.invocations
                .lock()
                .expect("mock runner poisoned")
                .push(command.to_string());
            Ok(CommandRunOutput {
                status_code: 0,
                stdout: "triage ok\n".to_string(),
                stderr: String::new(),
                timed_out: false,
            })
        }
    }

    #[test]
    fn approval_queue_persists_and_requires_distinct_approvers() {
        let db_path = temp_path("approval-queue.db");
        let mut queue = ApprovalQueue::new_persistent(db_path.clone()).expect("persistent queue");
        let now_ns = 10_000;
        let request_id = queue
            .enqueue_with_ttl(
                envelope(2),
                "operator-a".to_string(),
                "collect triage".to_string(),
                std::time::Duration::from_secs(600),
                now_ns,
            )
            .expect("enqueue");

        assert_eq!(queue.pending_len().expect("pending len"), 1);

        let first = queue
            .approve(request_id, "approver-a", now_ns + 1)
            .expect("approve")
            .expect("request exists");
        assert_eq!(first.state, ApprovalState::Pending);

        let duplicate = queue
            .approve(request_id, "approver-a", now_ns + 2)
            .expect("approve duplicate")
            .expect("request exists");
        assert_eq!(duplicate.approved_by.len(), 1);

        let second = queue
            .approve(request_id, "approver-b", now_ns + 3)
            .expect("approve second")
            .expect("request exists");
        assert_eq!(second.state, ApprovalState::Approved);

        let reopened = ApprovalQueue::new_persistent(db_path).expect("reopen queue");
        let restored = reopened
            .get(request_id)
            .expect("get request")
            .expect("request restored");
        assert_eq!(restored.state, ApprovalState::Approved);
        assert_eq!(restored.approved_by.len(), 2);
    }

    #[test]
    fn remote_shell_runtime_enforces_concurrency_and_writes_asciicast() {
        let mut queue = ApprovalQueue::default();
        let request_id = queue
            .enqueue_with_ttl(
                envelope(1),
                "operator-a".to_string(),
                "collect triage".to_string(),
                std::time::Duration::from_secs(600),
                8 * 3_600 * 1_000_000_000,
            )
            .expect("enqueue");
        let approved = queue
            .approve(request_id, "security-admin", 8 * 3_600 * 1_000_000_000 + 1)
            .expect("approve")
            .expect("approved request");
        let audit_root = temp_path("remote-shell-audit");
        let runtime = RemoteShellRuntime::with_runner(
            RemoteShellPolicy {
                allowed_prefixes: vec!["collect".to_string()],
                denied_patterns: vec!["rm -rf".to_string()],
                timeout_secs: 30,
                max_session_secs: 600,
                max_concurrent_sessions: 1,
                whitelist_mode: true,
                allowed_hours: Some(WorkingHours {
                    start_hour_utc: 8,
                    end_hour_utc: 18,
                }),
            },
            audit_root,
            MockCommandRunner::default(),
        );

        let session = runtime
            .begin_session(
                &approved,
                "host-a",
                "operator-a",
                8 * 3_600 * 1_000_000_000 + 2,
            )
            .expect("begin session");

        let second = runtime.begin_session(
            &approved,
            "host-a",
            "operator-b",
            8 * 3_600 * 1_000_000_000 + 3,
        );
        assert!(second.is_err());

        let audit = runtime
            .run_command(
                session.session_id,
                "collect triage",
                8 * 3_600 * 1_000_000_000 + 4,
            )
            .expect("run command");
        assert!(audit.allowed);
        assert_eq!(audit.action, HighRiskActionKind::RemoteShell);
        let audit_path = audit.audit_path.expect("audit path");
        let contents = std::fs::read_to_string(&audit_path).expect("read cast");
        assert!(contents.contains("\"version\":2"));
        assert!(contents.contains("triage ok"));

        runtime
            .end_session(session.session_id, 8 * 3_600 * 1_000_000_000 + 5)
            .expect("end session");
    }

    #[test]
    fn remote_shell_runtime_rejects_outside_working_hours() {
        let mut queue = ApprovalQueue::default();
        let request_id = queue
            .enqueue(envelope(1), "operator-a", "collect triage")
            .expect("enqueue");
        let approved = queue
            .approve(request_id, "security-admin", 1)
            .expect("approve")
            .expect("approved request");
        let runtime = RemoteShellRuntime::with_runner(
            RemoteShellPolicy {
                allowed_prefixes: vec!["collect".to_string()],
                denied_patterns: Vec::new(),
                timeout_secs: 30,
                max_session_secs: 600,
                max_concurrent_sessions: 1,
                whitelist_mode: true,
                allowed_hours: Some(WorkingHours {
                    start_hour_utc: 8,
                    end_hour_utc: 18,
                }),
            },
            temp_path("remote-shell-hours"),
            MockCommandRunner::default(),
        );

        let error = runtime
            .begin_session(&approved, "host-a", "operator-a", 2 * 3_600 * 1_000_000_000)
            .expect_err("outside working hours must fail");
        assert!(error.to_string().contains("working hours"));
    }

    #[test]
    fn playbook_runtime_enforces_max_executions() {
        let mut queue = ApprovalQueue::default();
        let request_id = queue
            .enqueue(envelope(1), "operator-a", "collect triage")
            .expect("enqueue");
        let approved = queue
            .approve(request_id, "approver-a", 1)
            .expect("approve")
            .expect("approved request");
        let runtime = PlaybookRuntime::default();
        let playbook = PreApprovedPlaybook {
            playbook_id: "triage".to_string(),
            allowed_commands: vec!["collect triage".to_string()],
            timeout_secs: 120,
            max_executions: 1,
        };

        let first = runtime
            .execute(&approved, &playbook, 2)
            .expect("first execution");
        assert!(first.allowed);

        let second = runtime.execute(&approved, &playbook, 3);
        assert!(second.is_err());
    }

    #[test]
    fn session_lock_runtime_tracks_lock_and_release() {
        let runtime = SessionLockRuntime::default();
        let audit = runtime.lock(SessionLockRequest {
            user_session: "user-1".to_string(),
            reason: "contain suspected credential theft".to_string(),
        });

        assert!(audit.allowed);
        assert_eq!(audit.action, HighRiskActionKind::SessionLock);
        assert!(runtime.is_locked("user-1"));

        let release = runtime
            .release("user-1", "incident closed")
            .expect("release lock");
        assert!(release.detail.contains("incident closed"));
        assert!(!runtime.is_locked("user-1"));
    }
}
