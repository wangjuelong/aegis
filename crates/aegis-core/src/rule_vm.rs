use aegis_model::{DecisionKind, EventPayload, NormalizedEvent};
use anyhow::{anyhow, bail, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleField {
    EventType,
    ProcessName,
    ProcessCmdline,
    ProcessUser,
    FilePath,
    DstIp,
    DnsQuery,
    ContainerId,
    RiskScore,
    Severity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleValue {
    String(String),
    Number(u64),
    Bool(bool),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Contains,
    Gte,
    Exists,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instruction {
    LoadField(RuleField),
    Push(RuleValue),
    Compare(CompareOp),
    And,
    Or,
    Not,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledRule {
    pub name: String,
    pub program: Vec<Instruction>,
    pub on_match: DecisionKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleOutcome {
    pub matched: bool,
    pub decision: DecisionKind,
    pub comparisons: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StackValue {
    Value(Option<RuleValue>),
    Bool(bool),
}

#[derive(Default)]
pub struct RuleVm;

impl RuleVm {
    pub fn evaluate(&self, rule: &CompiledRule, event: &NormalizedEvent) -> Result<RuleOutcome> {
        let mut stack = Vec::new();
        let mut comparisons = 0usize;

        for instruction in &rule.program {
            match instruction {
                Instruction::LoadField(field) => {
                    stack.push(StackValue::Value(self.extract_field(field, event)));
                }
                Instruction::Push(value) => stack.push(StackValue::Value(Some(value.clone()))),
                Instruction::Compare(op) => {
                    comparisons += 1;
                    let result = match op {
                        CompareOp::Exists => self.compare_exists(&mut stack)?,
                        CompareOp::Eq => self.compare_eq(&mut stack)?,
                        CompareOp::Contains => self.compare_contains(&mut stack)?,
                        CompareOp::Gte => self.compare_gte(&mut stack)?,
                    };
                    stack.push(StackValue::Bool(result));
                }
                Instruction::And => {
                    let rhs = Self::pop_bool(&mut stack)?;
                    let lhs = Self::pop_bool(&mut stack)?;
                    stack.push(StackValue::Bool(lhs && rhs));
                }
                Instruction::Or => {
                    let rhs = Self::pop_bool(&mut stack)?;
                    let lhs = Self::pop_bool(&mut stack)?;
                    stack.push(StackValue::Bool(lhs || rhs));
                }
                Instruction::Not => {
                    let value = Self::pop_bool(&mut stack)?;
                    stack.push(StackValue::Bool(!value));
                }
            }
        }

        let matched = Self::pop_bool(&mut stack)?;
        Ok(RuleOutcome {
            matched,
            decision: if matched {
                rule.on_match
            } else {
                DecisionKind::Log
            },
            comparisons,
        })
    }

    fn extract_field(&self, field: &RuleField, event: &NormalizedEvent) -> Option<RuleValue> {
        match field {
            RuleField::EventType => Some(RuleValue::String(format!("{:?}", event.event_type))),
            RuleField::ProcessName => Some(RuleValue::String(event.process.name.clone())),
            RuleField::ProcessCmdline => Some(RuleValue::String(event.process.cmdline.clone())),
            RuleField::ProcessUser => event.process.user.clone().map(RuleValue::String),
            RuleField::FilePath => match &event.payload {
                EventPayload::File(file) => {
                    let path = file.path.display().to_string();
                    (!path.is_empty()).then_some(RuleValue::String(path))
                }
                _ => None,
            },
            RuleField::DstIp => match &event.payload {
                EventPayload::Network(network) => network.dst_ip.clone().map(RuleValue::String),
                _ => None,
            },
            RuleField::DnsQuery => match &event.payload {
                EventPayload::Network(network) => network.dns_query.clone().map(RuleValue::String),
                _ => None,
            },
            RuleField::ContainerId => event
                .container
                .as_ref()
                .map(|container| RuleValue::String(container.container_id.clone()))
                .or_else(|| event.process.container_id.clone().map(RuleValue::String)),
            RuleField::RiskScore => Some(RuleValue::Number(event.enrichment.risk_score as u64)),
            RuleField::Severity => Some(RuleValue::Number(match event.severity {
                aegis_model::Severity::Info => 0,
                aegis_model::Severity::Low => 1,
                aegis_model::Severity::Medium => 2,
                aegis_model::Severity::High => 3,
                aegis_model::Severity::Critical => 4,
            })),
        }
    }

    fn compare_exists(&self, stack: &mut Vec<StackValue>) -> Result<bool> {
        Ok(Self::pop_value(stack)?.is_some())
    }

    fn compare_eq(&self, stack: &mut Vec<StackValue>) -> Result<bool> {
        let rhs = Self::pop_required_value(stack)?;
        let lhs = Self::pop_required_value(stack)?;
        Ok(lhs == rhs)
    }

    fn compare_contains(&self, stack: &mut Vec<StackValue>) -> Result<bool> {
        let rhs = Self::pop_required_value(stack)?;
        let lhs = Self::pop_required_value(stack)?;
        match (lhs, rhs) {
            (RuleValue::String(lhs), RuleValue::String(rhs)) => Ok(lhs.contains(&rhs)),
            _ => bail!("contains requires string operands"),
        }
    }

    fn compare_gte(&self, stack: &mut Vec<StackValue>) -> Result<bool> {
        let rhs = Self::pop_required_value(stack)?;
        let lhs = Self::pop_required_value(stack)?;
        match (lhs, rhs) {
            (RuleValue::Number(lhs), RuleValue::Number(rhs)) => Ok(lhs >= rhs),
            _ => bail!("gte requires numeric operands"),
        }
    }

    fn pop_bool(stack: &mut Vec<StackValue>) -> Result<bool> {
        match stack.pop() {
            Some(StackValue::Bool(value)) => Ok(value),
            Some(StackValue::Value(_)) => bail!("boolean value expected"),
            None => Err(anyhow!("stack underflow")),
        }
    }

    fn pop_value(stack: &mut Vec<StackValue>) -> Result<Option<RuleValue>> {
        match stack.pop() {
            Some(StackValue::Value(value)) => Ok(value),
            Some(StackValue::Bool(_)) => bail!("operand value expected"),
            None => Err(anyhow!("stack underflow")),
        }
    }

    fn pop_required_value(stack: &mut Vec<StackValue>) -> Result<RuleValue> {
        Self::pop_value(stack)?.ok_or_else(|| anyhow!("missing field value"))
    }
}

#[cfg(test)]
mod tests {
    use super::{CompareOp, CompiledRule, Instruction, RuleField, RuleValue, RuleVm};
    use aegis_model::{
        DecisionKind, EventPayload, EventType, FileContext, NetworkContext, NormalizedEvent,
        Priority, ProcessContext, Severity,
    };
    use std::path::PathBuf;

    fn script_event() -> NormalizedEvent {
        let mut event = NormalizedEvent::new(
            42,
            EventType::Script,
            Priority::High,
            Severity::High,
            ProcessContext {
                name: "powershell.exe".to_string(),
                cmdline: "powershell -enc ZABlAG0AbwA=".to_string(),
                ..ProcessContext::default()
            },
            EventPayload::File(FileContext {
                path: PathBuf::from("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
                ..FileContext::default()
            }),
        );
        event.enrichment.risk_score = 92;
        event
    }

    #[test]
    fn rule_vm_matches_multi_clause_program() {
        let vm = RuleVm;
        let rule = CompiledRule {
            name: "powershell-high-risk".to_string(),
            program: vec![
                Instruction::LoadField(RuleField::ProcessName),
                Instruction::Push(RuleValue::String("powershell".to_string())),
                Instruction::Compare(CompareOp::Contains),
                Instruction::LoadField(RuleField::RiskScore),
                Instruction::Push(RuleValue::Number(80)),
                Instruction::Compare(CompareOp::Gte),
                Instruction::And,
            ],
            on_match: DecisionKind::Alert,
        };

        let outcome = vm.evaluate(&rule, &script_event()).expect("evaluate rule");

        assert!(outcome.matched);
        assert_eq!(outcome.decision, DecisionKind::Alert);
        assert_eq!(outcome.comparisons, 2);
    }

    #[test]
    fn rule_vm_supports_exists_checks_for_network_fields() {
        let vm = RuleVm;
        let rule = CompiledRule {
            name: "network-dns".to_string(),
            program: vec![
                Instruction::LoadField(RuleField::DnsQuery),
                Instruction::Compare(CompareOp::Exists),
            ],
            on_match: DecisionKind::Response,
        };

        let mut event = script_event();
        event.payload = EventPayload::Network(NetworkContext {
            dns_query: Some("cnc.example".to_string()),
            ..NetworkContext::default()
        });

        let outcome = vm.evaluate(&rule, &event).expect("evaluate exists");

        assert!(outcome.matched);
        assert_eq!(outcome.decision, DecisionKind::Response);
    }
}
