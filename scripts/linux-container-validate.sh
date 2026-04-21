#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=${REPO_ROOT:-$(cd -- "$SCRIPT_DIR/.." && pwd)}
AEGIS_RUSTUP_TOOLCHAIN=${AEGIS_RUSTUP_TOOLCHAIN:-}

run_cargo() {
  if [[ -n "$AEGIS_RUSTUP_TOOLCHAIN" ]]; then
    rustup run "$AEGIS_RUSTUP_TOOLCHAIN" cargo "$@"
  else
    cargo "$@"
  fi
}

cd "$REPO_ROOT"

run_cargo test -p aegis-core sidecar_and_daemonset_contracts_validate_expected_constraints -- --nocapture >/dev/null
run_cargo test -p aegis-core container_detection_engine_flags_escape_and_lateral_signals -- --nocapture >/dev/null
run_cargo run -p aegis-core --example runtime_sdk_connector >/tmp/aegis-runtime-sdk-example.out 2>/dev/null

python3 - <<'PY' "$REPO_ROOT" "/tmp/aegis-runtime-sdk-example.out"
import json
import pathlib
import re
import sys

repo_root = pathlib.Path(sys.argv[1])
example_output = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").strip()
required_failures = []

daemonset_path = repo_root / "packaging/linux/kubernetes/daemonset-host-agent.yaml"
sidecar_path = repo_root / "packaging/linux/kubernetes/sidecar-lite-pod.yaml"
runtime_dir = repo_root / "packaging/linux/runtime-sdk"

daemonset = json.loads(daemonset_path.read_text(encoding="utf-8"))
sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
runtime_event = json.loads((runtime_dir / "runtime-event.sample.json").read_text(encoding="utf-8"))
runtime_heartbeat = json.loads((runtime_dir / "runtime-heartbeat.sample.json").read_text(encoding="utf-8"))
runtime_policy = json.loads((runtime_dir / "runtime-policy.contract.json").read_text(encoding="utf-8"))
cloud_connector = json.loads((runtime_dir / "cloud-connector.contract.json").read_text(encoding="utf-8"))

daemonset_spec = daemonset["spec"]["template"]["spec"]
daemonset_container = daemonset_spec["containers"][0]
daemonset_security = daemonset_container["securityContext"]
daemonset_mount_paths = {entry["mountPath"] for entry in daemonset_container["volumeMounts"]}
daemonset_added_caps = set(daemonset_security["capabilities"]["add"])
daemonset_dropped_caps = set(daemonset_security["capabilities"]["drop"])
required_caps = {"BPF", "PERFMON", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_RESOURCE"}
required_mounts = {"/sys/fs/bpf", "/proc", "/var/lib/aegis", "/var/run/aegis"}

if daemonset["kind"] != "DaemonSet":
    required_failures.append("daemonset_kind")
if daemonset_spec.get("hostPID") is not True:
    required_failures.append("daemonset_host_pid")
if daemonset_spec.get("hostNetwork") is not False:
    required_failures.append("daemonset_host_network")
if daemonset_security.get("privileged") is not False:
    required_failures.append("daemonset_privileged")
if daemonset_security.get("readOnlyRootFilesystem") is not True:
    required_failures.append("daemonset_read_only_rootfs")
if daemonset_security.get("runAsNonRoot") is not False:
    required_failures.append("daemonset_run_as_non_root")
if "ALL" not in daemonset_dropped_caps:
    required_failures.append("daemonset_drop_all")
if not required_caps.issubset(daemonset_added_caps):
    required_failures.append("daemonset_required_caps")
if not required_mounts.issubset(daemonset_mount_paths):
    required_failures.append("daemonset_required_mounts")

sidecar_spec = sidecar["spec"]
sidecar_container = next(
    container for container in sidecar_spec["containers"] if container["name"] == "aegis-sidecar-lite"
)
sidecar_security = sidecar_container["securityContext"]
sidecar_mount_paths = {entry["mountPath"] for entry in sidecar_container["volumeMounts"]}
if sidecar["kind"] != "Pod":
    required_failures.append("sidecar_kind")
if sidecar_spec.get("hostPID") is not False:
    required_failures.append("sidecar_host_pid")
if sidecar_spec.get("hostNetwork") is not False:
    required_failures.append("sidecar_host_network")
if sidecar_security.get("privileged") is not False:
    required_failures.append("sidecar_privileged")
if sidecar_security.get("readOnlyRootFilesystem") is not True:
    required_failures.append("sidecar_read_only_rootfs")
if sidecar_security["capabilities"].get("drop") != ["ALL"]:
    required_failures.append("sidecar_drop_all")
if not {"/var/run/aegis", "/var/lib/aegis-sidecar/cache"}.issubset(sidecar_mount_paths):
    required_failures.append("sidecar_required_mounts")

if runtime_event.get("contract_version") != "serverless.v1":
    required_failures.append("runtime_event_contract")
if runtime_heartbeat.get("contract_version") != "serverless.v1":
    required_failures.append("runtime_heartbeat_contract")
if runtime_policy.get("contract_version") != "serverless.v1":
    required_failures.append("runtime_policy_contract")
if cloud_connector.get("contract_version") != "serverless.v1":
    required_failures.append("cloud_connector_contract")
if cloud_connector.get("source") != "AwsCloudTrail":
    required_failures.append("cloud_connector_source")

match = re.search(
    r"runtime_event=(?P<event>\S+) first_flush=(?P<first>\S+) second_flush=(?P<second>\S+) buffered_events=(?P<buffered>\d+) emitted_batches=(?P<batches>\d+)",
    example_output,
)
if not match:
    required_failures.append("runtime_sdk_example_output")

payload = {
    "daemonset_manifest": str(daemonset_path),
    "sidecar_manifest": str(sidecar_path),
    "runtime_samples_root": str(runtime_dir),
    "runtime_example_output": example_output,
    "required_failures": required_failures,
}
print(json.dumps(payload, indent=2, ensure_ascii=False))
if required_failures:
    raise SystemExit(1)
PY
