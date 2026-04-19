use aegis_model::QuarantineReceipt;
use aegis_platform::PlatformRuntime;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminationRequest {
    pub pid: u32,
    pub protected_process: bool,
    pub kill_required: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponseActionKind {
    Suspend,
    Assess,
    Kill,
    KillProtected,
    Quarantine,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseAuditRecord {
    pub action_id: Uuid,
    pub action: ResponseActionKind,
    pub target: String,
    pub success: bool,
    pub detail: String,
    pub timestamp_ns: u64,
    pub vault_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResponseExecutionReport {
    pub records: Vec<ResponseAuditRecord>,
}

#[derive(Clone, Debug)]
pub struct ResponseAuditLog {
    path: PathBuf,
}

impl ResponseAuditLog {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, record: &ResponseAuditRecord) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        serde_json::to_writer(&mut file, record)?;
        file.write_all(b"\n")?;
        Ok(())
    }
}

pub struct ResponseExecutor<'a, P: PlatformRuntime> {
    platform: &'a P,
    audit: ResponseAuditLog,
}

impl<'a, P: PlatformRuntime> ResponseExecutor<'a, P> {
    pub fn new(platform: &'a P, audit: ResponseAuditLog) -> Self {
        Self { platform, audit }
    }

    pub fn terminate_process(
        &self,
        request: TerminationRequest,
    ) -> Result<ResponseExecutionReport> {
        let mut records = Vec::new();
        self.platform.suspend_process(request.pid)?;
        records.push(self.record(
            ResponseActionKind::Suspend,
            format!("pid:{}", request.pid),
            true,
            "process suspended".to_string(),
            None,
        ));

        records.push(self.record(
            ResponseActionKind::Assess,
            format!("pid:{}", request.pid),
            true,
            if request.kill_required {
                "assessment requires termination".to_string()
            } else {
                "assessment kept process suspended".to_string()
            },
            None,
        ));

        if request.kill_required {
            if request.protected_process {
                self.platform.kill_ppl_process(request.pid)?;
                records.push(self.record(
                    ResponseActionKind::KillProtected,
                    format!("pid:{}", request.pid),
                    true,
                    "protected process terminated".to_string(),
                    None,
                ));
            } else {
                self.platform.kill_process(request.pid)?;
                records.push(self.record(
                    ResponseActionKind::Kill,
                    format!("pid:{}", request.pid),
                    true,
                    "process terminated".to_string(),
                    None,
                ));
            }
        }

        for record in &records {
            self.audit.append(record)?;
        }

        Ok(ResponseExecutionReport { records })
    }

    pub fn quarantine_file(&self, path: &Path) -> Result<ResponseExecutionReport> {
        let receipt = self.platform.quarantine_file(path)?;
        let record = self.record_quarantine(path, &receipt);
        self.audit.append(&record)?;
        Ok(ResponseExecutionReport {
            records: vec![record],
        })
    }

    fn record(
        &self,
        action: ResponseActionKind,
        target: String,
        success: bool,
        detail: String,
        vault_path: Option<PathBuf>,
    ) -> ResponseAuditRecord {
        ResponseAuditRecord {
            action_id: Uuid::now_v7(),
            action,
            target,
            success,
            detail,
            timestamp_ns: now_unix_ns(),
            vault_path,
        }
    }

    fn record_quarantine(&self, path: &Path, receipt: &QuarantineReceipt) -> ResponseAuditRecord {
        self.record(
            ResponseActionKind::Quarantine,
            path.display().to_string(),
            true,
            format!("file quarantined with sha256 {}", receipt.sha256),
            Some(receipt.vault_path.clone()),
        )
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
    use super::{ResponseActionKind, ResponseAuditLog, ResponseExecutor, TerminationRequest};
    use aegis_platform::{MockAction, MockPlatform};
    use std::fs;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn audit_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("aegis-{name}-{}.jsonl", Uuid::now_v7()))
    }

    #[test]
    fn response_executor_runs_suspend_assess_kill_flow() {
        let platform = MockPlatform::linux();
        let audit = ResponseAuditLog::new(audit_path("terminate"));
        let executor = ResponseExecutor::new(&platform, audit.clone());

        let report = executor
            .terminate_process(TerminationRequest {
                pid: 4242,
                protected_process: false,
                kill_required: true,
            })
            .expect("terminate process");

        let actions = platform.take_actions();
        assert_eq!(
            actions,
            vec![
                MockAction::SuspendProcess(4242),
                MockAction::KillProcess(4242),
            ]
        );
        assert_eq!(report.records.len(), 3);
        let audit_contents = fs::read_to_string(audit.path()).expect("read audit");
        assert!(audit_contents.contains("\"Suspend\""));
        assert!(audit_contents.contains("\"Kill\""));
    }

    #[test]
    fn response_executor_quarantines_file_and_persists_audit() {
        let platform = MockPlatform::windows();
        let audit = ResponseAuditLog::new(audit_path("quarantine"));
        let executor = ResponseExecutor::new(&platform, audit.clone());
        let target = PathBuf::from("C:/temp/payload.exe");

        let report = executor.quarantine_file(&target).expect("quarantine file");

        let actions = platform.take_actions();
        assert_eq!(actions, vec![MockAction::QuarantineFile(target.clone())]);
        assert_eq!(report.records[0].action, ResponseActionKind::Quarantine);
        assert_eq!(report.records[0].vault_path.as_ref(), Some(&target));
        let audit_contents = fs::read_to_string(audit.path()).expect("read audit");
        assert!(audit_contents.contains("payload.exe"));
    }
}
