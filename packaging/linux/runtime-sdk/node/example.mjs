import { buildRuntimeEvent, buildRuntimeHeartbeat } from "./aegis-runtime.mjs";

const event = buildRuntimeEvent();
const heartbeat = buildRuntimeHeartbeat();
console.log(JSON.stringify({
  language: "node",
  signal_kind: event.signal_kind,
  policy_version: heartbeat.policy_version,
  connector_id: "azure-activity"
}));
