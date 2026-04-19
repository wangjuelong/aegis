use aegis_core::runtime_sdk::{
    CloudApiConnector, CloudConnectorBuffer, RuntimeSdkEncoder, SERVERLESS_CONTRACT_VERSION,
};
use aegis_model::{
    CloudApiConnectorContract, CloudApiRecord, CloudConnectorCursor, CloudLogSourceKind,
    ProcessContext, RuntimeHeartbeat, RuntimeMetadata, RuntimePolicyContract, RuntimeProviderKind,
    RuntimeSdkEvent, RuntimeSignalKind,
};
use anyhow::Result;
use std::collections::BTreeMap;

fn main() -> Result<()> {
    let metadata = RuntimeMetadata {
        provider: RuntimeProviderKind::AwsLambda,
        service: "orders-api".to_string(),
        runtime: "python3.12".to_string(),
        region: Some("ap-southeast-1".to_string()),
        account_id: Some("123456789012".to_string()),
        invocation_id: "invoke-1".to_string(),
        cold_start: true,
        function_name: Some("orders-handler".to_string()),
        container_id: None,
    };
    let encoder = RuntimeSdkEncoder::new(8, 16);
    let telemetry = encoder.encode_event(&RuntimeSdkEvent {
        contract_version: SERVERLESS_CONTRACT_VERSION.to_string(),
        tenant_id: "tenant-a".to_string(),
        agent_id: "runtime-sdk".to_string(),
        sequence_hint: 1,
        signal_kind: RuntimeSignalKind::HttpRequest,
        metadata: metadata.clone(),
        process: ProcessContext {
            pid: 7,
            name: "python".to_string(),
            ..ProcessContext::default()
        },
        labels: BTreeMap::from([("route".to_string(), "/orders".to_string())]),
        attributes: BTreeMap::from([("method".to_string(), "POST".to_string())]),
        occurred_at_ms: 1_713_000_000_000,
    })?;
    encoder.validate_policy_binding(
        &RuntimeHeartbeat {
            contract_version: SERVERLESS_CONTRACT_VERSION.to_string(),
            tenant_id: "tenant-a".to_string(),
            agent_id: "runtime-sdk".to_string(),
            metadata,
            policy_version: "policy-7".to_string(),
            active_invocations: 1,
            buffered_events: 1,
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
    )?;

    let connector = CloudApiConnector::new(CloudApiConnectorContract {
        contract_version: SERVERLESS_CONTRACT_VERSION.to_string(),
        connector_id: "aws-cloudtrail".to_string(),
        source: CloudLogSourceKind::AwsCloudTrail,
        poll_interval_secs: 60,
        max_batch_records: 2,
        cursor: None,
    })?;
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
        observed_at_ms: 1_713_000_100_000,
        attributes: BTreeMap::new(),
    };
    let mapped = connector.map_record(&record)?;
    let mut buffer = CloudConnectorBuffer::new(2)?;
    let flushed = buffer.push(
        record,
        Some(CloudConnectorCursor {
            source: CloudLogSourceKind::AwsCloudTrail,
            shard: "us-east-1".to_string(),
            checkpoint: "evt-1".to_string(),
        }),
    )?;

    println!(
        "runtime_event={} connector_event={} flushed={}",
        telemetry.event_id,
        mapped.event_id,
        flushed.is_some()
    );
    Ok(())
}
