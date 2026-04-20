#!/usr/bin/env bash
set -euo pipefail

HOST=${AEGIS_WINDOWS_HOST:-192.168.2.218}
USER_NAME=${AEGIS_WINDOWS_USER:-lamba}
PASSWORD=${AEGIS_WINDOWS_PASSWORD:-lamba}
OUTPUT_PATH=${AEGIS_WINDOWS_VALIDATE_OUTPUT:-target/windows-validation/${HOST}.json}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REMOTE_SCRIPT_PATH="${SCRIPT_DIR}/windows-runtime-verify.ps1"

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

for tool in sshpass ssh python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    exit 1
  fi
done

if [[ ! -f "$REMOTE_SCRIPT_PATH" ]]; then
  echo "missing powershell validation script: $REMOTE_SCRIPT_PATH" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"

RESULT_JSON=$(sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" \
  "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -" \
  < "$REMOTE_SCRIPT_PATH")

printf '%s\n' "$RESULT_JSON" | tee "$OUTPUT_PATH"

python3 - "$OUTPUT_PATH" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    payload = json.load(fh)

failures = payload.get("required_failures") or []
if failures:
    raise SystemExit("windows runtime validation failed: " + ", ".join(failures))
PY
