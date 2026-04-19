use aegis_model::CommandEnvelope;
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalState {
    Pending,
    Approved,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub request_id: Uuid,
    pub envelope: CommandEnvelope,
    pub requested_by: String,
    pub command: String,
    pub state: ApprovalState,
}

#[derive(Default)]
pub struct ApprovalQueue {
    pending: VecDeque<ApprovalRequest>,
}

impl ApprovalQueue {
    pub fn enqueue(
        &mut self,
        envelope: CommandEnvelope,
        requested_by: impl Into<String>,
        command: impl Into<String>,
    ) -> Uuid {
        let request = ApprovalRequest {
            request_id: Uuid::now_v7(),
            envelope,
            requested_by: requested_by.into(),
            command: command.into(),
            state: ApprovalState::Pending,
        };
        let request_id = request.request_id;
        self.pending.push_back(request);
        request_id
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn approve(&mut self, request_id: Uuid) -> Option<ApprovalRequest> {
        let request = self
            .pending
            .iter_mut()
            .find(|request| request.request_id == request_id)?;
        request.state = ApprovalState::Approved;
        Some(request.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteShellPolicy {
    pub allowed_prefixes: Vec<String>,
    pub timeout_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreApprovedPlaybook {
    pub playbook_id: String,
    pub allowed_commands: Vec<String>,
    pub timeout_secs: u64,
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
}

pub struct RemoteShellRuntime {
    policy: RemoteShellPolicy,
}

impl RemoteShellRuntime {
    pub fn new(policy: RemoteShellPolicy) -> Self {
        Self { policy }
    }

    pub fn execute(&self, request: &ApprovalRequest) -> Result<HighRiskAuditRecord> {
        if request.state != ApprovalState::Approved {
            bail!("approval request is not approved");
        }
        let allowed = self
            .policy
            .allowed_prefixes
            .iter()
            .any(|prefix| request.command.starts_with(prefix));

        Ok(HighRiskAuditRecord {
            audit_id: Uuid::now_v7(),
            action: HighRiskActionKind::RemoteShell,
            allowed,
            detail: if allowed {
                format!(
                    "remote shell command allowed with timeout {}s: {}",
                    self.policy.timeout_secs, request.command
                )
            } else {
                format!("remote shell command rejected: {}", request.command)
            },
            timestamp_ns: now_unix_ns(),
        })
    }
}

pub struct PlaybookRuntime;

impl PlaybookRuntime {
    pub fn execute(
        request: &ApprovalRequest,
        playbook: &PreApprovedPlaybook,
    ) -> Result<HighRiskAuditRecord> {
        if request.state != ApprovalState::Approved {
            return Err(anyhow!("playbook execution requires approval"));
        }
        let allowed = playbook
            .allowed_commands
            .iter()
            .any(|prefix| request.command.starts_with(prefix));

        Ok(HighRiskAuditRecord {
            audit_id: Uuid::now_v7(),
            action: HighRiskActionKind::Playbook,
            allowed,
            detail: if allowed {
                format!(
                    "playbook {} executed under {}s timeout",
                    playbook.playbook_id, playbook.timeout_secs
                )
            } else {
                format!(
                    "playbook {} rejected command {}",
                    playbook.playbook_id, request.command
                )
            },
            timestamp_ns: now_unix_ns(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionLockRequest {
    pub user_session: String,
    pub reason: String,
}

pub struct SessionLockRuntime;

impl SessionLockRuntime {
    pub fn lock(request: &SessionLockRequest) -> HighRiskAuditRecord {
        HighRiskAuditRecord {
            audit_id: Uuid::now_v7(),
            action: HighRiskActionKind::SessionLock,
            allowed: true,
            detail: format!(
                "session {} locked: {}",
                request.user_session, request.reason
            ),
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
        ApprovalQueue, ApprovalState, HighRiskActionKind, PlaybookRuntime, PreApprovedPlaybook,
        RemoteShellPolicy, RemoteShellRuntime, SessionLockRequest, SessionLockRuntime,
    };
    use aegis_model::{ApprovalPolicy, CommandEnvelope};

    fn envelope() -> CommandEnvelope {
        CommandEnvelope {
            command_id: uuid::Uuid::now_v7(),
            command_type: "remote-shell".to_string(),
            target_scope: "host-a".to_string(),
            approval: ApprovalPolicy {
                min_approvers: 1,
                approvers: Vec::new(),
                policy_version: "v1".to_string(),
            },
        }
    }

    #[test]
    fn approval_queue_tracks_pending_requests() {
        let mut queue = ApprovalQueue::default();
        let request_id = queue.enqueue(envelope(), "operator-a", "sh -c whoami");

        assert_eq!(queue.pending_len(), 1);
        let approved = queue.approve(request_id).expect("approved request");
        assert_eq!(approved.state, ApprovalState::Approved);
    }

    #[test]
    fn remote_shell_runtime_rejects_disallowed_command() {
        let mut queue = ApprovalQueue::default();
        let request_id = queue.enqueue(envelope(), "operator-a", "rm -rf /");
        let approved = queue.approve(request_id).expect("approved request");
        let runtime = RemoteShellRuntime::new(RemoteShellPolicy {
            allowed_prefixes: vec!["sh -c whoami".to_string(), "uname -a".to_string()],
            timeout_secs: 30,
        });

        let audit = runtime.execute(&approved).expect("audit");

        assert_eq!(audit.action, HighRiskActionKind::RemoteShell);
        assert!(!audit.allowed);
    }

    #[test]
    fn playbook_runtime_executes_approved_command() {
        let mut queue = ApprovalQueue::default();
        let request_id = queue.enqueue(envelope(), "operator-a", "collect triage");
        let approved = queue.approve(request_id).expect("approved request");

        let audit = PlaybookRuntime::execute(
            &approved,
            &PreApprovedPlaybook {
                playbook_id: "triage".to_string(),
                allowed_commands: vec!["collect triage".to_string()],
                timeout_secs: 120,
            },
        )
        .expect("execute playbook");

        assert!(audit.allowed);
        assert_eq!(audit.action, HighRiskActionKind::Playbook);
    }

    #[test]
    fn session_lock_runtime_records_lock_action() {
        let audit = SessionLockRuntime::lock(&SessionLockRequest {
            user_session: "user-1".to_string(),
            reason: "contain suspected credential theft".to_string(),
        });

        assert!(audit.allowed);
        assert_eq!(audit.action, HighRiskActionKind::SessionLock);
        assert!(audit.detail.contains("credential theft"));
    }
}
