use aegis_model::{
    AgentHealth, ApproverEntry, EventBatch, HeartbeatRequest, ServerCommand, SignedServerCommand,
    TargetScopeKind, TelemetryEvent, UplinkMessage,
};
use anyhow::{bail, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
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
        wal_utilization_ratio: f32,
        restart_epoch: u64,
    ) -> HeartbeatRequest {
        HeartbeatRequest {
            tenant_id: tenant_id.into(),
            agent_id: agent_id.into(),
            health,
            wal_utilization_ratio,
            restart_epoch,
        }
    }
}

#[derive(Default)]
pub struct CommandReplayLedger {
    seen: HashMap<Uuid, i64>,
}

impl CommandReplayLedger {
    pub fn register(
        &mut self,
        command_id: Uuid,
        expires_at_ms: i64,
        now_ms: i64,
    ) -> Result<(), CommandValidationError> {
        self.prune(now_ms);
        if self.seen.contains_key(&command_id) {
            return Err(CommandValidationError::ReplayDetected);
        }
        self.seen.insert(command_id, expires_at_ms);
        Ok(())
    }

    pub fn prune(&mut self, now_ms: i64) {
        self.seen.retain(|_, expires_at_ms| *expires_at_ms > now_ms);
    }
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
        ledger.register(command.command_id, expires_at_ms, now_ms)?;
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

fn canonical_command_hash(command: &ServerCommand) -> [u8; 32] {
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
        CommandValidator, HeartbeatBuilder, TelemetryBatchBuilder,
    };
    use aegis_model::{
        AgentHealth, ApprovalPolicy, ApprovalProof, ApproverEntry, EventPayload, EventType,
        FileContext, NormalizedEvent, Priority, ProcessContext, ServerCommand, Severity,
        SignedServerCommand, TargetScope, TargetScopeKind, TelemetryEvent, UplinkMessage,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;
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
        let heartbeat = HeartbeatBuilder::build("tenant-a", "agent-1", health(), 0.2, 3);

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
