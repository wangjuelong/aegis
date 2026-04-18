use crate::config::AppConfig;
use aegis_model::{Alert, LineageCounters, NormalizedEvent, ResponseAction, TelemetryEvent};
use anyhow::Result;
use tokio::sync::mpsc;

pub struct RuntimeChannels {
    pub event_tx: mpsc::Sender<NormalizedEvent>,
    pub alert_tx_hi: mpsc::Sender<Alert>,
    pub alert_tx_norm: mpsc::Sender<Alert>,
    pub response_tx: mpsc::Sender<ResponseAction>,
    pub telemetry_tx: mpsc::Sender<TelemetryEvent>,
}

#[derive(Debug)]
pub struct BootstrapSummary {
    pub agent_id: String,
    pub tenant_id: String,
    pub lineage_counters: LineageCounters,
}

pub struct Orchestrator {
    config: AppConfig,
}

impl Orchestrator {
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    pub fn bootstrap(&self) -> Result<(RuntimeChannels, BootstrapSummary)> {
        let (event_tx, _event_rx) = mpsc::channel::<NormalizedEvent>(65_536);
        let (alert_tx_hi, _alert_rx_hi) = mpsc::channel::<Alert>(1_024);
        let (alert_tx_norm, _alert_rx_norm) = mpsc::channel::<Alert>(4_096);
        let (response_tx, _response_rx) = mpsc::channel::<ResponseAction>(1_024);
        let (telemetry_tx, _telemetry_rx) = mpsc::channel::<TelemetryEvent>(2_048);

        let channels = RuntimeChannels {
            event_tx,
            alert_tx_hi,
            alert_tx_norm,
            response_tx,
            telemetry_tx,
        };

        let summary = BootstrapSummary {
            agent_id: self.config.agent_id.clone(),
            tenant_id: self.config.tenant_id.clone(),
            lineage_counters: LineageCounters::default(),
        };

        Ok((channels, summary))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_creates_runtime_channels() {
        let orchestrator = Orchestrator::new(AppConfig::default());
        let (_channels, summary) = orchestrator.bootstrap().expect("bootstrap should work");
        assert_eq!(summary.agent_id, "local-agent");
        assert_eq!(summary.tenant_id, "local-tenant");
    }
}
