use crate::script_decode::{ScriptDecodePipeline, ScriptDecodeReport};
use crate::yara::{EnqueueDisposition, YaraScanTarget, YaraScheduler};
use aegis_model::Priority;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmsiScanSignal {
    pub content_name: String,
    pub script_content: String,
    pub process_name: String,
    pub risk_score: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmsiFastPathDecision {
    Allow,
    QueueYara,
    Block,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmsiFastPathOutcome {
    pub decision: AmsiFastPathDecision,
    pub queued_job_id: Option<Uuid>,
    pub decode_report: ScriptDecodeReport,
}

#[derive(Default)]
pub struct AmsiInterlock {
    yara: YaraScheduler,
    decoder: ScriptDecodePipeline,
}

impl AmsiInterlock {
    pub fn evaluate(
        &mut self,
        signal: AmsiScanSignal,
        submitted_at_ns: u64,
    ) -> AmsiFastPathOutcome {
        let decode_report = self.decoder.decode(&signal.script_content);
        let blocks_immediately = decode_report
            .suspicious_tokens
            .iter()
            .any(|token| matches!(token.as_str(), "AmsiUtils" | "Invoke-Mimikatz"));

        if blocks_immediately {
            return AmsiFastPathOutcome {
                decision: AmsiFastPathDecision::Block,
                queued_job_id: None,
                decode_report,
            };
        }

        if signal.risk_score >= 70 || !decode_report.layers.is_empty() {
            let target = YaraScanTarget::Content(decode_report.decoded.clone());
            let queued_job_id = match self
                .yara
                .enqueue(target, submitted_at_ns, Priority::Critical)
            {
                EnqueueDisposition::Queued(job_id) => Some(job_id),
                EnqueueDisposition::Cached | EnqueueDisposition::DuplicatePending => None,
            };

            return AmsiFastPathOutcome {
                decision: AmsiFastPathDecision::QueueYara,
                queued_job_id,
                decode_report,
            };
        }

        AmsiFastPathOutcome {
            decision: AmsiFastPathDecision::Allow,
            queued_job_id: None,
            decode_report,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AmsiFastPathDecision, AmsiInterlock, AmsiScanSignal};

    #[test]
    fn amsi_interlock_blocks_known_bypass_tokens() {
        let mut interlock = AmsiInterlock::default();
        let outcome = interlock.evaluate(
            AmsiScanSignal {
                content_name: "amsi-bypass.ps1".to_string(),
                script_content: "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
                    .to_string(),
                process_name: "powershell.exe".to_string(),
                risk_score: 40,
            },
            10,
        );

        assert_eq!(outcome.decision, AmsiFastPathDecision::Block);
    }

    #[test]
    fn amsi_interlock_queues_yara_for_decoded_high_risk_scripts() {
        let mut interlock = AmsiInterlock::default();
        let outcome = interlock.evaluate(
            AmsiScanSignal {
                content_name: "encoded.ps1".to_string(),
                script_content: "String.fromCharCode(73,69,88)".to_string(),
                process_name: "powershell.exe".to_string(),
                risk_score: 80,
            },
            20,
        );

        assert_eq!(outcome.decision, AmsiFastPathDecision::QueueYara);
        assert!(outcome.queued_job_id.is_some());
        assert_eq!(outcome.decode_report.decoded, "IEX");
    }
}
