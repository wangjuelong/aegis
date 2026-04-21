#!/usr/bin/env bash
set -euo pipefail

HOST=${AEGIS_WINDOWS_HOST:-192.168.2.222}
USER_NAME=${AEGIS_WINDOWS_USER:-admin}
PASSWORD=${AEGIS_WINDOWS_PASSWORD:-admin}
OUTPUT_PATH=${AEGIS_WINDOWS_VALIDATE_OUTPUT:-target/windows-validation/${HOST}.json}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
REMOTE_SCRIPT_PATH="${SCRIPT_DIR}/windows-runtime-verify.ps1"
BUILD_SCRIPT_PATH="${SCRIPT_DIR}/windows-build-driver.ps1"
BUILD_MINIFILTER_SCRIPT_PATH="${SCRIPT_DIR}/windows-build-minifilter.ps1"
INSTALL_SCRIPT_PATH="${SCRIPT_DIR}/windows-install-driver.ps1"
UNINSTALL_SCRIPT_PATH="${SCRIPT_DIR}/windows-uninstall-driver.ps1"
AMSI_SCAN_SCRIPT_PATH="${SCRIPT_DIR}/windows-scan-script-with-amsi.ps1"
SCRIPT_EVENT_QUERY_PATH="${SCRIPT_DIR}/windows-query-script-events.ps1"
MEMORY_SNAPSHOT_SCRIPT_PATH="${SCRIPT_DIR}/windows-query-memory-snapshot.ps1"
REGISTRY_EVENT_QUERY_PATH="${SCRIPT_DIR}/windows-query-registry-events.ps1"
REGISTRY_PROTECTION_SCRIPT_PATH="${SCRIPT_DIR}/windows-configure-registry-protection.ps1"
FILE_EVENT_QUERY_PATH="${SCRIPT_DIR}/windows-query-file-events.ps1"
MINIFILTER_INSTALL_SCRIPT_PATH="${SCRIPT_DIR}/windows-install-minifilter.ps1"
MINIFILTER_UNINSTALL_SCRIPT_PATH="${SCRIPT_DIR}/windows-uninstall-minifilter.ps1"
PREEMPTIVE_BLOCK_SCRIPT_PATH="${SCRIPT_DIR}/windows-configure-preemptive-block.ps1"
DRIVER_SOURCE_DIR="${REPO_ROOT}/windows/driver"
MINIFILTER_SOURCE_DIR="${REPO_ROOT}/windows/minifilter"

REMOTE_PAYLOAD_ID="windows-runtime-verify-$(date +%Y%m%d-%H%M%S)"
REMOTE_PAYLOAD_POSIX="/c:/ProgramData/Aegis/validation/${REMOTE_PAYLOAD_ID}"
REMOTE_PAYLOAD_WIN="C:\\ProgramData\\Aegis\\validation\\${REMOTE_PAYLOAD_ID}"

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
for path in \
  "$BUILD_SCRIPT_PATH" \
  "$BUILD_MINIFILTER_SCRIPT_PATH" \
  "$INSTALL_SCRIPT_PATH" \
  "$UNINSTALL_SCRIPT_PATH" \
  "$AMSI_SCAN_SCRIPT_PATH" \
  "$SCRIPT_EVENT_QUERY_PATH" \
  "$MEMORY_SNAPSHOT_SCRIPT_PATH" \
  "$REGISTRY_EVENT_QUERY_PATH" \
  "$REGISTRY_PROTECTION_SCRIPT_PATH" \
  "$FILE_EVENT_QUERY_PATH" \
  "$MINIFILTER_INSTALL_SCRIPT_PATH" \
  "$MINIFILTER_UNINSTALL_SCRIPT_PATH" \
  "$PREEMPTIVE_BLOCK_SCRIPT_PATH"; do
  if [[ ! -f "$path" ]]; then
    echo "missing validation helper script: $path" >&2
    exit 1
  fi
done
if [[ ! -d "$DRIVER_SOURCE_DIR" ]]; then
  echo "missing driver source directory: $DRIVER_SOURCE_DIR" >&2
  exit 1
fi
if [[ ! -d "$MINIFILTER_SOURCE_DIR" ]]; then
  echo "missing minifilter source directory: $MINIFILTER_SOURCE_DIR" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"

sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" \
  "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"New-Item -ItemType Directory -Force -Path ${REMOTE_PAYLOAD_WIN} | Out-Null\"" >/dev/null

sshpass -p "$PASSWORD" scp -r "${SSH_OPTS[@]}" \
  "$REMOTE_SCRIPT_PATH" \
  "$BUILD_SCRIPT_PATH" \
  "$BUILD_MINIFILTER_SCRIPT_PATH" \
  "$INSTALL_SCRIPT_PATH" \
  "$UNINSTALL_SCRIPT_PATH" \
  "$AMSI_SCAN_SCRIPT_PATH" \
  "$SCRIPT_EVENT_QUERY_PATH" \
  "$MEMORY_SNAPSHOT_SCRIPT_PATH" \
  "$REGISTRY_EVENT_QUERY_PATH" \
  "$REGISTRY_PROTECTION_SCRIPT_PATH" \
  "$FILE_EVENT_QUERY_PATH" \
  "$MINIFILTER_INSTALL_SCRIPT_PATH" \
  "$MINIFILTER_UNINSTALL_SCRIPT_PATH" \
  "$PREEMPTIVE_BLOCK_SCRIPT_PATH" \
  "$DRIVER_SOURCE_DIR" \
  "$MINIFILTER_SOURCE_DIR" \
  "$USER_NAME@$HOST:${REMOTE_PAYLOAD_POSIX}/" >/dev/null

RESULT_JSON=$(sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" \
  "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"${REMOTE_PAYLOAD_WIN}\\windows-runtime-verify.ps1\" -DriverRoot \"${REMOTE_PAYLOAD_WIN}\\driver\" -MinifilterRoot \"${REMOTE_PAYLOAD_WIN}\\minifilter\" -BuildScriptPath \"${REMOTE_PAYLOAD_WIN}\\windows-build-driver.ps1\" -BuildMinifilterScriptPath \"${REMOTE_PAYLOAD_WIN}\\windows-build-minifilter.ps1\" -InstallScriptPath \"${REMOTE_PAYLOAD_WIN}\\windows-install-driver.ps1\" -UninstallScriptPath \"${REMOTE_PAYLOAD_WIN}\\windows-uninstall-driver.ps1\" -InstallMinifilterScriptPath \"${REMOTE_PAYLOAD_WIN}\\windows-install-minifilter.ps1\" -UninstallMinifilterScriptPath \"${REMOTE_PAYLOAD_WIN}\\windows-uninstall-minifilter.ps1\" -FileEventQueryPath \"${REMOTE_PAYLOAD_WIN}\\windows-query-file-events.ps1\" -RegistryEventQueryPath \"${REMOTE_PAYLOAD_WIN}\\windows-query-registry-events.ps1\" -RegistryProtectionScriptPath \"${REMOTE_PAYLOAD_WIN}\\windows-configure-registry-protection.ps1\" -PreemptiveBlockScriptPath \"${REMOTE_PAYLOAD_WIN}\\windows-configure-preemptive-block.ps1\"")

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
