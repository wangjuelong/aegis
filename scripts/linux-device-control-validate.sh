#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=${REPO_ROOT:-$(cd -- "$SCRIPT_DIR/.." && pwd)}
VALIDATION_OUTPUT=${AEGIS_LINUX_DEVICE_CONTROL_OUTPUT:-"$REPO_ROOT/target/linux-validation/192.168.2.123.json"}

cd "$REPO_ROOT"

cargo test -p aegis-platform linux_device_control -- --nocapture >/dev/null
./scripts/linux-package-verify.sh >/dev/null

python3 - "$VALIDATION_OUTPUT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if not path.exists():
    raise SystemExit(f"missing validation output: {path}")

payload = json.loads(path.read_text(encoding="utf-8"))
required_failures = list(payload.get("required_failures") or [])
device_control_paths = list(payload.get("device_control_paths") or [])
if not device_control_paths:
    required_failures.append("device_control_paths")

result = {
    "validation_output": str(path),
    "device_control_paths": device_control_paths,
    "required_failures": required_failures,
}
print(json.dumps(result, indent=2, ensure_ascii=False))
if required_failures:
    raise SystemExit(1)
PY
