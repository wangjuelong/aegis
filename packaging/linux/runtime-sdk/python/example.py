#!/usr/bin/env python3
import json

from aegis_runtime import build_runtime_event, build_runtime_heartbeat


event = build_runtime_event()
heartbeat = build_runtime_heartbeat()
print(
    json.dumps(
        {
            "language": "python",
            "signal_kind": event["signal_kind"],
            "policy_version": heartbeat["policy_version"],
            "connector_id": "aws-cloudtrail",
        },
        ensure_ascii=False,
    )
)
