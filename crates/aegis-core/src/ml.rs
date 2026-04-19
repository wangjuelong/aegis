use crate::script_decode::ScriptDecodeReport;
use crate::temporal::TemporalSnapshot;
use aegis_model::{EventPayload, NormalizedEvent, ScriptContext};
use anyhow::Result;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ModelKind {
    Static,
    Behavioral,
    Script,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ModelInput {
    pub kind: ModelKind,
    pub features: Vec<f32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ModelOutput {
    pub score: f32,
    pub label: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ModelPrediction {
    pub kind: ModelKind,
    pub output: ModelOutput,
    pub ood_score: f32,
    pub is_ood: bool,
    pub fallback_used: bool,
}

pub trait OnnxRuntimeSession: Send + Sync {
    fn infer(&self, input: &ModelInput) -> Result<ModelOutput>;
}

pub struct RegisteredModel {
    pub model_id: String,
    pub threshold: f32,
    pub session: Arc<dyn OnnxRuntimeSession>,
}

#[derive(Default)]
pub struct ModelRegistry {
    models: HashMap<ModelKind, RegisteredModel>,
}

impl ModelRegistry {
    pub fn register(&mut self, kind: ModelKind, model: RegisteredModel) {
        self.models.insert(kind, model);
    }

    pub fn predict(&self, kind: ModelKind, input: &ModelInput, ood: &OodScorer) -> ModelPrediction {
        let ood_score = ood.score(kind, &input.features);
        let is_ood = self
            .models
            .get(&kind)
            .map(|model| ood_score > model.threshold)
            .unwrap_or(false);

        match self.models.get(&kind) {
            Some(model) => match model.session.infer(input) {
                Ok(output) => ModelPrediction {
                    kind,
                    output,
                    ood_score,
                    is_ood,
                    fallback_used: false,
                },
                Err(_) => fallback_prediction(kind, ood_score, is_ood),
            },
            None => fallback_prediction(kind, ood_score, is_ood),
        }
    }
}

fn fallback_prediction(kind: ModelKind, ood_score: f32, is_ood: bool) -> ModelPrediction {
    ModelPrediction {
        kind,
        output: ModelOutput {
            score: 0.0,
            label: "fallback".to_string(),
        },
        ood_score,
        is_ood,
        fallback_used: true,
    }
}

pub struct FeatureExtractor;

impl FeatureExtractor {
    pub fn route(
        &self,
        event: &NormalizedEvent,
        temporal: Option<&TemporalSnapshot>,
        decode: Option<&ScriptDecodeReport>,
    ) -> ModelKind {
        if decode.is_some() || matches!(event.payload, EventPayload::Script(_)) {
            ModelKind::Script
        } else if temporal.is_some_and(|snapshot| snapshot.observations.len() >= 2) {
            ModelKind::Behavioral
        } else {
            ModelKind::Static
        }
    }

    pub fn static_features(&self, event: &NormalizedEvent) -> Vec<f32> {
        let (size, entropy) = match &event.payload {
            EventPayload::File(file) => (
                file.size.unwrap_or_default() as f32 / 1_000_000.0,
                file.entropy.unwrap_or_default(),
            ),
            _ => (0.0, 0.0),
        };

        vec![
            size,
            entropy,
            (event.enrichment.risk_score as f32) / 100.0,
            if event
                .process
                .signature
                .as_ref()
                .is_some_and(|signature| signature.trusted)
            {
                1.0
            } else {
                0.0
            },
        ]
    }

    pub fn behavioral_features(
        &self,
        event: &NormalizedEvent,
        temporal: &TemporalSnapshot,
    ) -> Vec<f32> {
        let unique_types = temporal
            .observations
            .iter()
            .map(|observation| observation.event_type)
            .collect::<BTreeSet<_>>()
            .len() as f32;
        let (bytes_sent, bytes_received) = match &event.payload {
            EventPayload::Network(network) => (
                network.bytes_sent.unwrap_or_default() as f32 / 10_000.0,
                network.bytes_received.unwrap_or_default() as f32 / 10_000.0,
            ),
            _ => (0.0, 0.0),
        };

        vec![
            temporal.observations.len() as f32,
            unique_types,
            bytes_sent,
            bytes_received,
            (event.enrichment.risk_score as f32) / 100.0,
        ]
    }

    pub fn script_features(
        &self,
        event: &NormalizedEvent,
        decode: &ScriptDecodeReport,
    ) -> Vec<f32> {
        let obfuscation_layers = match &event.payload {
            EventPayload::Script(ScriptContext {
                obfuscation_layers, ..
            }) => *obfuscation_layers as f32,
            _ => 0.0,
        };

        vec![
            decode.layers.len() as f32,
            decode.suspicious_tokens.len() as f32,
            decode.decoded.len() as f32 / 100.0,
            obfuscation_layers,
            (event.enrichment.risk_score as f32) / 100.0,
        ]
    }
}

#[derive(Clone, Debug)]
pub struct OodScorer {
    threshold: f32,
    centroids: HashMap<ModelKind, Vec<f32>>,
    counts: HashMap<ModelKind, usize>,
}

impl OodScorer {
    pub fn new(threshold: f32) -> Self {
        Self {
            threshold,
            centroids: HashMap::new(),
            counts: HashMap::new(),
        }
    }

    pub fn observe(&mut self, kind: ModelKind, features: &[f32]) {
        let count = self.counts.entry(kind).or_insert(0);
        *count += 1;

        let centroid = self
            .centroids
            .entry(kind)
            .or_insert_with(|| vec![0.0; features.len()]);

        if centroid.len() != features.len() {
            *centroid = vec![0.0; features.len()];
            *count = 1;
        }

        let count_f32 = *count as f32;
        for (slot, value) in centroid.iter_mut().zip(features.iter()) {
            *slot += (*value - *slot) / count_f32;
        }
    }

    pub fn score(&self, kind: ModelKind, features: &[f32]) -> f32 {
        let Some(centroid) = self.centroids.get(&kind) else {
            return 0.0;
        };
        if centroid.len() != features.len() || centroid.is_empty() {
            return 1.0;
        }

        centroid
            .iter()
            .zip(features.iter())
            .map(|(baseline, value)| {
                let delta = baseline - value;
                delta * delta
            })
            .sum::<f32>()
            .sqrt()
            / (centroid.len() as f32)
    }

    pub fn is_ood(&self, kind: ModelKind, features: &[f32]) -> bool {
        self.score(kind, features) > self.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FeatureExtractor, ModelInput, ModelKind, ModelOutput, ModelRegistry, OnnxRuntimeSession,
        OodScorer, RegisteredModel,
    };
    use crate::script_decode::ScriptDecodeReport;
    use crate::temporal::{TemporalObservation, TemporalSnapshot};
    use aegis_model::{
        EventPayload, EventType, FileContext, NetworkContext, NormalizedEvent, Priority,
        ProcessContext, ScriptContext, Severity, SignatureContext,
    };
    use anyhow::{anyhow, Result};
    use std::path::PathBuf;
    use std::sync::Arc;
    use uuid::Uuid;

    struct FixedSession;

    impl OnnxRuntimeSession for FixedSession {
        fn infer(&self, input: &ModelInput) -> Result<ModelOutput> {
            Ok(ModelOutput {
                score: input.features.iter().sum::<f32>(),
                label: "ok".to_string(),
            })
        }
    }

    struct FailingSession;

    impl OnnxRuntimeSession for FailingSession {
        fn infer(&self, _input: &ModelInput) -> Result<ModelOutput> {
            Err(anyhow!("inference failed"))
        }
    }

    fn base_event() -> NormalizedEvent {
        let mut event = NormalizedEvent::new(
            100,
            EventType::FileWrite,
            Priority::High,
            Severity::High,
            ProcessContext {
                pid: 7,
                name: "powershell.exe".to_string(),
                signature: Some(SignatureContext {
                    publisher: Some("Microsoft".to_string()),
                    trusted: true,
                }),
                ..ProcessContext::default()
            },
            EventPayload::File(FileContext {
                path: PathBuf::from("/tmp/payload.bin"),
                size: Some(4_096),
                entropy: Some(7.8),
                ..FileContext::default()
            }),
        );
        event.enrichment.risk_score = 88;
        event
    }

    #[test]
    fn feature_extractor_routes_and_extracts_script_features() {
        let extractor = FeatureExtractor;
        let mut event = base_event();
        event.event_type = EventType::Script;
        event.payload = EventPayload::Script(ScriptContext {
            content: Some("String.fromCharCode(73,69,88)".to_string()),
            interpreter: Some("powershell".to_string()),
            obfuscation_layers: 2,
            deobfuscated_content: Some("IEX".to_string()),
        });
        let decode = ScriptDecodeReport {
            original: event.process.cmdline.clone(),
            decoded: "IEX".to_string(),
            layers: vec![],
            suspicious_tokens: vec!["IEX".to_string()],
        };

        let route = extractor.route(&event, None, Some(&decode));
        let features = extractor.script_features(&event, &decode);

        assert_eq!(route, ModelKind::Script);
        assert_eq!(features[1], 1.0);
        assert_eq!(features[3], 2.0);
    }

    #[test]
    fn ood_scorer_flags_outliers() {
        let mut scorer = OodScorer::new(0.3);
        scorer.observe(ModelKind::Behavioral, &[1.0, 1.0, 1.0]);
        scorer.observe(ModelKind::Behavioral, &[1.2, 1.1, 0.9]);

        assert!(scorer.is_ood(ModelKind::Behavioral, &[5.0, 5.0, 5.0]));
        assert!(!scorer.is_ood(ModelKind::Behavioral, &[1.1, 1.0, 0.95]));
    }

    #[test]
    fn model_registry_routes_behavioral_prediction_and_supports_fallback() {
        let extractor = FeatureExtractor;
        let mut registry = ModelRegistry::default();
        registry.register(
            ModelKind::Behavioral,
            RegisteredModel {
                model_id: "behavior-v1".to_string(),
                threshold: 0.5,
                session: Arc::new(FixedSession),
            },
        );
        registry.register(
            ModelKind::Script,
            RegisteredModel {
                model_id: "script-v1".to_string(),
                threshold: 0.5,
                session: Arc::new(FailingSession),
            },
        );

        let mut event = base_event();
        event.payload = EventPayload::Network(NetworkContext {
            bytes_sent: Some(8_000),
            bytes_received: Some(2_000),
            ..NetworkContext::default()
        });
        let snapshot = TemporalSnapshot {
            key: "storyline:7".to_string(),
            observations: vec![
                TemporalObservation {
                    event_id: Uuid::now_v7(),
                    lineage_id: Uuid::now_v7(),
                    timestamp_ns: 100,
                    event_type: EventType::ProcessCreate,
                    process_pid: 7,
                    risk_score: 40,
                },
                TemporalObservation {
                    event_id: Uuid::now_v7(),
                    lineage_id: Uuid::now_v7(),
                    timestamp_ns: 120,
                    event_type: EventType::NetConnect,
                    process_pid: 7,
                    risk_score: 88,
                },
            ],
        };
        let kind = extractor.route(&event, Some(&snapshot), None);
        let features = extractor.behavioral_features(&event, &snapshot);
        let mut scorer = OodScorer::new(0.5);
        scorer.observe(kind, &features);
        let prediction = registry.predict(kind, &ModelInput { kind, features }, &scorer);

        assert_eq!(kind, ModelKind::Behavioral);
        assert!(!prediction.fallback_used);

        let fallback = registry.predict(
            ModelKind::Script,
            &ModelInput {
                kind: ModelKind::Script,
                features: vec![0.0, 1.0, 0.5],
            },
            &scorer,
        );

        assert!(fallback.fallback_used);
        assert_eq!(fallback.output.label, "fallback");
    }
}
