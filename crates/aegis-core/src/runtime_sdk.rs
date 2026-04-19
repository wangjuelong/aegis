use aegis_model::{
    CloudApiConnectorContract, CloudApiRecord, CloudConnectorCursor, CloudLogSourceKind,
    ContainerContext, EventPayload, EventType, FileContext, HostContext, NetworkContext,
    NormalizedEvent, OperatingSystemKind, Priority, ProcessContext, RuntimeHeartbeat,
    RuntimePolicyContract, RuntimeSdkEvent, RuntimeSignalKind, Severity, TelemetryEvent,
};
use anyhow::{bail, Result};
use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;

pub const SERVERLESS_CONTRACT_VERSION: &str = "serverless.v1";

pub struct RuntimeSdkEncoder {
    max_labels: usize,
    max_attributes: usize,
}

impl RuntimeSdkEncoder {
    pub fn new(max_labels: usize, max_attributes: usize) -> Self {
        Self {
            max_labels,
            max_attributes,
        }
    }

    pub fn encode_event(&self, event: &RuntimeSdkEvent) -> Result<TelemetryEvent> {
        self.validate_event_contract(event)?;

        let timestamp_ns = to_timestamp_ns(event.occurred_at_ms)?;
        let process = process_with_container(&event.process, event.metadata.container_id.clone());
        let (event_type, priority, severity) = classify_runtime_signal(event.signal_kind);
        let payload = runtime_payload(event);
        let mut normalized = NormalizedEvent::new(
            timestamp_ns,
            event_type,
            priority,
            severity,
            process,
            payload,
        );
        normalized.host = runtime_host(&event.metadata);
        normalized.container = runtime_container(&event.metadata);

        Ok(TelemetryEvent::from_normalized(
            &normalized,
            event.tenant_id.clone(),
            event.agent_id.clone(),
        ))
    }

    pub fn validate_policy_binding(
        &self,
        heartbeat: &RuntimeHeartbeat,
        policy: &RuntimePolicyContract,
    ) -> Result<()> {
        validate_contract_version(&heartbeat.contract_version)?;
        validate_contract_version(&policy.contract_version)?;
        if heartbeat.policy_version != policy.policy_version {
            bail!("runtime heartbeat policy version does not match policy contract");
        }
        if heartbeat.metadata.service.is_empty() || heartbeat.metadata.runtime.is_empty() {
            bail!("runtime heartbeat must include service and runtime");
        }
        Ok(())
    }

    fn validate_event_contract(&self, event: &RuntimeSdkEvent) -> Result<()> {
        validate_contract_version(&event.contract_version)?;
        if event.tenant_id.is_empty() || event.agent_id.is_empty() {
            bail!("runtime sdk event requires tenant_id and agent_id");
        }
        if event.metadata.service.is_empty()
            || event.metadata.runtime.is_empty()
            || event.metadata.invocation_id.is_empty()
        {
            bail!("runtime sdk event metadata is incomplete");
        }
        if event.labels.len() > self.max_labels || event.attributes.len() > self.max_attributes {
            bail!("runtime sdk event exceeds encoder limits");
        }
        Ok(())
    }
}

pub struct CloudApiConnector {
    contract: CloudApiConnectorContract,
}

impl CloudApiConnector {
    pub fn new(contract: CloudApiConnectorContract) -> Result<Self> {
        validate_contract_version(&contract.contract_version)?;
        if contract.connector_id.is_empty() {
            bail!("cloud connector requires connector_id");
        }
        if contract.poll_interval_secs == 0 || contract.max_batch_records == 0 {
            bail!("cloud connector requires positive poll interval and batch size");
        }
        Ok(Self { contract })
    }

    pub fn map_record(&self, record: &CloudApiRecord) -> Result<TelemetryEvent> {
        validate_contract_version(&record.contract_version)?;
        if record.connector_id != self.contract.connector_id
            || record.source != self.contract.source
        {
            bail!("cloud api record does not match connector contract");
        }
        if record.tenant_id.is_empty()
            || record.account_id.is_empty()
            || record.service.is_empty()
            || record.action.is_empty()
            || record.request_id.is_empty()
        {
            bail!("cloud api record is incomplete");
        }

        let timestamp_ns = to_timestamp_ns(record.observed_at_ms)?;
        let mut normalized = NormalizedEvent::new(
            timestamp_ns,
            classify_cloud_record(record),
            Priority::Normal,
            severity_for_cloud_record(record),
            ProcessContext {
                name: self.contract.connector_id.clone(),
                cmdline: format!("cloud-connector {}", self.contract.connector_id),
                user: record.principal.clone(),
                ..ProcessContext::default()
            },
            EventPayload::Generic(cloud_record_attributes(record)),
        );
        normalized.host = HostContext {
            hostname: record.account_id.clone(),
            os: OperatingSystemKind::Container,
            ip_addresses: Vec::new(),
            mac_addresses: Vec::new(),
            asset_tags: vec![
                format!("cloud-source:{:?}", record.source),
                format!("cloud-service:{}", record.service),
            ],
        };

        Ok(TelemetryEvent::from_normalized(
            &normalized,
            record.tenant_id.clone(),
            self.contract.connector_id.clone(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BufferedCloudBatch {
    pub records: Vec<CloudApiRecord>,
    pub cursor: Option<CloudConnectorCursor>,
}

pub struct CloudConnectorBuffer {
    max_records: usize,
    records: VecDeque<CloudApiRecord>,
    cursor: Option<CloudConnectorCursor>,
}

impl CloudConnectorBuffer {
    pub fn new(max_records: usize) -> Result<Self> {
        if max_records == 0 {
            bail!("cloud connector buffer must allow at least one record");
        }
        Ok(Self {
            max_records,
            records: VecDeque::new(),
            cursor: None,
        })
    }

    pub fn push(
        &mut self,
        record: CloudApiRecord,
        cursor: Option<CloudConnectorCursor>,
    ) -> Result<Option<BufferedCloudBatch>> {
        validate_contract_version(&record.contract_version)?;
        self.records.push_back(record);
        if let Some(cursor) = cursor {
            self.cursor = Some(cursor);
        }

        if self.records.len() >= self.max_records {
            return Ok(self.flush());
        }

        Ok(None)
    }

    pub fn flush(&mut self) -> Option<BufferedCloudBatch> {
        if self.records.is_empty() {
            return None;
        }

        let records = self.records.drain(..).collect::<Vec<_>>();
        Some(BufferedCloudBatch {
            records,
            cursor: self.cursor.take(),
        })
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }
}

fn validate_contract_version(contract_version: &str) -> Result<()> {
    if contract_version != SERVERLESS_CONTRACT_VERSION {
        bail!("unsupported serverless contract version");
    }
    Ok(())
}

fn to_timestamp_ns(timestamp_ms: i64) -> Result<u64> {
    if timestamp_ms < 0 {
        bail!("timestamp must be non-negative");
    }
    Ok((timestamp_ms as u64) * 1_000_000)
}

fn process_with_container(
    process: &ProcessContext,
    metadata_container_id: Option<String>,
) -> ProcessContext {
    let mut process = process.clone();
    if process.container_id.is_none() {
        process.container_id = metadata_container_id;
    }
    process
}

fn runtime_host(metadata: &aegis_model::RuntimeMetadata) -> HostContext {
    HostContext {
        hostname: metadata
            .function_name
            .clone()
            .unwrap_or_else(|| metadata.service.clone()),
        os: OperatingSystemKind::Container,
        ip_addresses: Vec::new(),
        mac_addresses: Vec::new(),
        asset_tags: vec![
            "serverless".to_string(),
            format!("provider:{:?}", metadata.provider),
            format!("service:{}", metadata.service),
            format!("runtime:{}", metadata.runtime),
        ],
    }
}

fn runtime_container(metadata: &aegis_model::RuntimeMetadata) -> Option<ContainerContext> {
    metadata
        .container_id
        .clone()
        .map(|container_id| ContainerContext {
            container_id,
            image: None,
            pod_name: metadata.function_name.clone(),
            namespace: metadata.region.clone(),
            node_name: None,
        })
}

fn classify_runtime_signal(signal_kind: RuntimeSignalKind) -> (EventType, Priority, Severity) {
    match signal_kind {
        RuntimeSignalKind::HttpRequest => (EventType::NetConnect, Priority::Normal, Severity::Info),
        RuntimeSignalKind::HttpResponse => (EventType::NetConnect, Priority::Low, Severity::Info),
        RuntimeSignalKind::FileAccess => (EventType::FileWrite, Priority::High, Severity::Medium),
        RuntimeSignalKind::ProcessSpawn => {
            (EventType::ProcessCreate, Priority::High, Severity::High)
        }
        RuntimeSignalKind::SocketConnect => {
            (EventType::NetConnect, Priority::High, Severity::Medium)
        }
        RuntimeSignalKind::EnvRead => (EventType::Unknown, Priority::High, Severity::Medium),
    }
}

fn runtime_payload(event: &RuntimeSdkEvent) -> EventPayload {
    match event.signal_kind {
        RuntimeSignalKind::SocketConnect => EventPayload::Network(NetworkContext {
            dst_ip: event.attributes.get("dst_ip").cloned(),
            dst_port: event
                .attributes
                .get("dst_port")
                .and_then(|value| value.parse::<u16>().ok()),
            protocol: event.attributes.get("protocol").cloned(),
            dns_query: event.attributes.get("host").cloned(),
            ..NetworkContext::default()
        }),
        RuntimeSignalKind::FileAccess => EventPayload::File(FileContext {
            path: event
                .attributes
                .get("path")
                .map(PathBuf::from)
                .unwrap_or_default(),
            action: event.attributes.get("action").cloned(),
            ..FileContext::default()
        }),
        _ => EventPayload::Generic(runtime_generic_attributes(event)),
    }
}

fn runtime_generic_attributes(event: &RuntimeSdkEvent) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::from([
        (
            "provider".to_string(),
            format!("{:?}", event.metadata.provider),
        ),
        ("service".to_string(), event.metadata.service.clone()),
        ("runtime".to_string(), event.metadata.runtime.clone()),
        (
            "invocation_id".to_string(),
            event.metadata.invocation_id.clone(),
        ),
        (
            "cold_start".to_string(),
            event.metadata.cold_start.to_string(),
        ),
        ("signal".to_string(), format!("{:?}", event.signal_kind)),
    ]);

    if let Some(region) = &event.metadata.region {
        attributes.insert("region".to_string(), region.clone());
    }
    if let Some(account_id) = &event.metadata.account_id {
        attributes.insert("account_id".to_string(), account_id.clone());
    }
    if let Some(function_name) = &event.metadata.function_name {
        attributes.insert("function_name".to_string(), function_name.clone());
    }

    for (key, value) in &event.labels {
        attributes.insert(format!("label.{key}"), value.clone());
    }
    for (key, value) in &event.attributes {
        attributes.insert(format!("attr.{key}"), value.clone());
    }

    attributes
}

fn classify_cloud_record(record: &CloudApiRecord) -> EventType {
    match record.source {
        CloudLogSourceKind::AwsCloudTrail
        | CloudLogSourceKind::AzureMonitor
        | CloudLogSourceKind::GcpAuditLog => EventType::Auth,
        CloudLogSourceKind::AwsCloudWatch => EventType::Unknown,
    }
}

fn severity_for_cloud_record(record: &CloudApiRecord) -> Severity {
    if record.action.contains("Delete")
        || record.action.contains("Stop")
        || record.action.contains("Detach")
    {
        Severity::High
    } else {
        Severity::Medium
    }
}

fn cloud_record_attributes(record: &CloudApiRecord) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::from([
        ("source".to_string(), format!("{:?}", record.source)),
        ("account_id".to_string(), record.account_id.clone()),
        ("service".to_string(), record.service.clone()),
        ("action".to_string(), record.action.clone()),
        ("request_id".to_string(), record.request_id.clone()),
    ]);

    if let Some(region) = &record.region {
        attributes.insert("region".to_string(), region.clone());
    }
    if let Some(principal) = &record.principal {
        attributes.insert("principal".to_string(), principal.clone());
    }
    if let Some(resource_id) = &record.resource_id {
        attributes.insert("resource_id".to_string(), resource_id.clone());
    }
    for (key, value) in &record.attributes {
        attributes.insert(format!("attr.{key}"), value.clone());
    }

    attributes
}

#[cfg(test)]
mod tests {
    use super::{
        CloudApiConnector, CloudConnectorBuffer, RuntimeSdkEncoder, SERVERLESS_CONTRACT_VERSION,
    };
    use aegis_model::{
        CloudApiConnectorContract, CloudApiRecord, CloudConnectorCursor, CloudLogSourceKind,
        EventPayload, EventType, ProcessContext, RuntimeHeartbeat, RuntimeMetadata,
        RuntimePolicyContract, RuntimeProviderKind, RuntimeSdkEvent, RuntimeSignalKind,
    };
    use std::collections::BTreeMap;

    fn runtime_metadata() -> RuntimeMetadata {
        RuntimeMetadata {
            provider: RuntimeProviderKind::AwsLambda,
            service: "orders-api".to_string(),
            runtime: "python3.12".to_string(),
            region: Some("ap-southeast-1".to_string()),
            account_id: Some("123456789012".to_string()),
            invocation_id: "invoke-1".to_string(),
            cold_start: true,
            function_name: Some("orders-handler".to_string()),
            container_id: Some("container-7".to_string()),
        }
    }

    #[test]
    fn runtime_sdk_encoder_maps_socket_connect_and_policy_binding() {
        let encoder = RuntimeSdkEncoder::new(8, 16);
        let telemetry = encoder
            .encode_event(&RuntimeSdkEvent {
                contract_version: SERVERLESS_CONTRACT_VERSION.to_string(),
                tenant_id: "tenant-a".to_string(),
                agent_id: "runtime-sdk".to_string(),
                sequence_hint: 10,
                signal_kind: RuntimeSignalKind::SocketConnect,
                metadata: runtime_metadata(),
                process: ProcessContext {
                    pid: 7,
                    name: "python".to_string(),
                    ..ProcessContext::default()
                },
                labels: BTreeMap::from([("route".to_string(), "/orders".to_string())]),
                attributes: BTreeMap::from([
                    ("dst_ip".to_string(), "10.0.0.4".to_string()),
                    ("dst_port".to_string(), "443".to_string()),
                    ("protocol".to_string(), "tcp".to_string()),
                    ("host".to_string(), "orders.internal".to_string()),
                ]),
                occurred_at_ms: 1_713_000_000_000,
            })
            .expect("runtime sdk event should encode");

        assert_eq!(telemetry.event_type, EventType::NetConnect);
        assert_eq!(
            telemetry.process.container_id.as_deref(),
            Some("container-7")
        );
        assert!(matches!(telemetry.payload, EventPayload::Network(_)));
        assert_eq!(
            telemetry.host.os,
            aegis_model::OperatingSystemKind::Container
        );

        encoder
            .validate_policy_binding(
                &RuntimeHeartbeat {
                    contract_version: SERVERLESS_CONTRACT_VERSION.to_string(),
                    tenant_id: "tenant-a".to_string(),
                    agent_id: "runtime-sdk".to_string(),
                    metadata: runtime_metadata(),
                    policy_version: "policy-7".to_string(),
                    active_invocations: 2,
                    buffered_events: 8,
                    dropped_events_total: 0,
                },
                &RuntimePolicyContract {
                    contract_version: SERVERLESS_CONTRACT_VERSION.to_string(),
                    policy_version: "policy-7".to_string(),
                    blocked_env_keys: vec!["AWS_SECRET_ACCESS_KEY".to_string()],
                    blocked_destinations: vec!["169.254.169.254".to_string()],
                    max_request_body_bytes: 8192,
                    require_response_sampling: true,
                },
            )
            .expect("matching policy binding should pass");
    }

    #[test]
    fn cloud_api_connector_maps_record_and_flushes_buffer() {
        let connector = CloudApiConnector::new(CloudApiConnectorContract {
            contract_version: SERVERLESS_CONTRACT_VERSION.to_string(),
            connector_id: "aws-cloudtrail".to_string(),
            source: CloudLogSourceKind::AwsCloudTrail,
            poll_interval_secs: 60,
            max_batch_records: 2,
            cursor: None,
        })
        .expect("connector contract should be valid");
        let record = CloudApiRecord {
            contract_version: SERVERLESS_CONTRACT_VERSION.to_string(),
            tenant_id: "tenant-a".to_string(),
            connector_id: "aws-cloudtrail".to_string(),
            source: CloudLogSourceKind::AwsCloudTrail,
            account_id: "123456789012".to_string(),
            region: Some("us-east-1".to_string()),
            service: "iam.amazonaws.com".to_string(),
            action: "AssumeRole".to_string(),
            principal: Some("svc-orders".to_string()),
            resource_id: Some("arn:aws:iam::123456789012:role/orders".to_string()),
            request_id: "req-1".to_string(),
            observed_at_ms: 1_713_000_010_000,
            attributes: BTreeMap::from([("sourceIp".to_string(), "10.0.0.8".to_string())]),
        };
        let telemetry = connector
            .map_record(&record)
            .expect("cloud record should map to telemetry");

        assert_eq!(telemetry.event_type, EventType::Auth);
        assert_eq!(telemetry.host.hostname, "123456789012");

        let mut buffer = CloudConnectorBuffer::new(2).expect("buffer should initialize");
        assert!(buffer
            .push(
                record.clone(),
                Some(CloudConnectorCursor {
                    source: CloudLogSourceKind::AwsCloudTrail,
                    shard: "us-east-1".to_string(),
                    checkpoint: "evt-1".to_string(),
                }),
            )
            .expect("push should succeed")
            .is_none());
        let flushed = buffer
            .push(
                CloudApiRecord {
                    request_id: "req-2".to_string(),
                    ..record
                },
                Some(CloudConnectorCursor {
                    source: CloudLogSourceKind::AwsCloudTrail,
                    shard: "us-east-1".to_string(),
                    checkpoint: "evt-2".to_string(),
                }),
            )
            .expect("push should succeed")
            .expect("second push should flush");

        assert_eq!(flushed.records.len(), 2);
        assert_eq!(
            flushed
                .cursor
                .as_ref()
                .map(|cursor| cursor.checkpoint.as_str()),
            Some("evt-2")
        );
    }

    #[test]
    fn runtime_sdk_rejects_incompatible_contract_versions() {
        let encoder = RuntimeSdkEncoder::new(4, 4);
        let error = encoder
            .validate_policy_binding(
                &RuntimeHeartbeat {
                    contract_version: "serverless.v2".to_string(),
                    tenant_id: "tenant-a".to_string(),
                    agent_id: "runtime-sdk".to_string(),
                    metadata: runtime_metadata(),
                    policy_version: "policy-7".to_string(),
                    active_invocations: 1,
                    buffered_events: 1,
                    dropped_events_total: 0,
                },
                &RuntimePolicyContract {
                    contract_version: SERVERLESS_CONTRACT_VERSION.to_string(),
                    policy_version: "policy-7".to_string(),
                    blocked_env_keys: Vec::new(),
                    blocked_destinations: Vec::new(),
                    max_request_body_bytes: 1024,
                    require_response_sampling: false,
                },
            )
            .expect_err("unexpected contract versions should fail");

        assert!(error.to_string().contains("unsupported"));
    }
}
