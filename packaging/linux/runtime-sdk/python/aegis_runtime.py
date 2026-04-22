from __future__ import annotations

from dataclasses import asdict, dataclass, field


CONTRACT_VERSION = "serverless.v1"


@dataclass
class RuntimeMetadata:
    provider: str
    service: str
    runtime: str
    region: str | None
    account_id: str | None
    invocation_id: str
    cold_start: bool
    function_name: str | None
    container_id: str | None


@dataclass
class ProcessContext:
    pid: int
    name: str


def build_runtime_event() -> dict:
    metadata = RuntimeMetadata(
        provider="AwsLambda",
        service="orders-api",
        runtime="python3.12",
        region="ap-southeast-1",
        account_id="123456789012",
        invocation_id="invoke-1",
        cold_start=True,
        function_name="orders-handler",
        container_id=None,
    )
    return {
        "contract_version": CONTRACT_VERSION,
        "tenant_id": "tenant-a",
        "agent_id": "runtime-sdk-python",
        "sequence_hint": 1,
        "signal_kind": "HttpRequest",
        "metadata": asdict(metadata),
        "process": asdict(ProcessContext(pid=7, name="python")),
        "labels": {"route": "/orders"},
        "attributes": {"method": "POST"},
        "occurred_at_ms": 1713000000000,
    }


def build_runtime_heartbeat() -> dict:
    event = build_runtime_event()
    return {
        "contract_version": CONTRACT_VERSION,
        "tenant_id": "tenant-a",
        "agent_id": "runtime-sdk-python",
        "metadata": event["metadata"],
        "policy_version": "policy-7",
        "active_invocations": 1,
        "buffered_events": 1,
        "dropped_events_total": 0,
    }
