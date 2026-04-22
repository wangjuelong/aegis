export const CONTRACT_VERSION = "serverless.v1";

export function buildRuntimeEvent() {
  return {
    contract_version: CONTRACT_VERSION,
    tenant_id: "tenant-a",
    agent_id: "runtime-sdk-node",
    sequence_hint: 1,
    signal_kind: "HttpRequest",
    metadata: {
      provider: "AwsLambda",
      service: "orders-api",
      runtime: "nodejs22",
      region: "ap-southeast-1",
      account_id: "123456789012",
      invocation_id: "invoke-1",
      cold_start: true,
      function_name: "orders-handler",
      container_id: null,
    },
    process: {
      pid: 7,
      name: "node",
    },
    labels: { route: "/orders" },
    attributes: { method: "POST" },
    occurred_at_ms: 1713000000000,
  };
}

export function buildRuntimeHeartbeat() {
  const event = buildRuntimeEvent();
  return {
    contract_version: CONTRACT_VERSION,
    tenant_id: "tenant-a",
    agent_id: "runtime-sdk-node",
    metadata: event.metadata,
    policy_version: "policy-7",
    active_invocations: 1,
    buffered_events: 1,
    dropped_events_total: 0,
  };
}
