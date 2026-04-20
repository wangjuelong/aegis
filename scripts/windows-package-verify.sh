#!/usr/bin/env bash
set -euo pipefail

HOST=${AEGIS_WINDOWS_HOST:-192.168.2.218}
USER_NAME=${AEGIS_WINDOWS_USER:-lamba}
PASSWORD=${AEGIS_WINDOWS_PASSWORD:-lamba}
OUTPUT_PATH=${AEGIS_WINDOWS_PACKAGE_VALIDATE_OUTPUT:-target/windows-package-validation/${HOST}.json}
REMOTE_TOOLCHAIN_ROOT=${AEGIS_WINDOWS_TOOLCHAIN_ROOT:-}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
REMOTE_PAYLOAD_ID="windows-package-verify-$(date +%Y%m%d-%H%M%S)"
REMOTE_ROOT_POSIX="C:/ProgramData/Aegis/validation/${REMOTE_PAYLOAD_ID}"
REMOTE_ROOT_WIN="C:\\ProgramData\\Aegis\\validation\\${REMOTE_PAYLOAD_ID}"

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

for tool in sshpass ssh scp python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    exit 1
  fi
done

mkdir -p "$(dirname "$OUTPUT_PATH")"

VENDOR_STAGE_ROOT="$REPO_ROOT/target/windows-package-vendor/${REMOTE_PAYLOAD_ID}"
VENDOR_DIR="$VENDOR_STAGE_ROOT/vendor"
VENDOR_CONFIG_DIR="$VENDOR_STAGE_ROOT/.cargo"
cleanup() {
  rm -rf "$VENDOR_STAGE_ROOT"
}
trap cleanup EXIT

mkdir -p "$VENDOR_CONFIG_DIR"
cargo vendor --locked --versioned-dirs "$VENDOR_DIR" >/dev/null
cat > "$VENDOR_CONFIG_DIR/config.toml" <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" \
  "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"New-Item -ItemType Directory -Force -Path '${REMOTE_ROOT_WIN}\\crates','${REMOTE_ROOT_WIN}\\scripts','${REMOTE_ROOT_WIN}\\packaging','${REMOTE_ROOT_WIN}\\windows','${REMOTE_ROOT_WIN}\\.cargo' | Out-Null\"" >/dev/null

scp_upload() {
  local source_path=$1
  local destination_path=$2
  sshpass -p "$PASSWORD" scp -r "${SSH_OPTS[@]}" "$source_path" "$USER_NAME@$HOST:$destination_path" >/dev/null
}

if [[ -f "$REPO_ROOT/Cargo.lock" ]]; then
  scp_upload "$REPO_ROOT/Cargo.lock" "${REMOTE_ROOT_POSIX}/"
fi
scp_upload "$REPO_ROOT/Cargo.toml" "${REMOTE_ROOT_POSIX}/"
scp_upload "$REPO_ROOT/crates/aegis-agentd" "${REMOTE_ROOT_POSIX}/crates/"
scp_upload "$REPO_ROOT/crates/aegis-core" "${REMOTE_ROOT_POSIX}/crates/"
scp_upload "$REPO_ROOT/crates/aegis-model" "${REMOTE_ROOT_POSIX}/crates/"
scp_upload "$REPO_ROOT/crates/aegis-platform" "${REMOTE_ROOT_POSIX}/crates/"
scp_upload "$REPO_ROOT/crates/aegis-script" "${REMOTE_ROOT_POSIX}/crates/"
scp_upload "$REPO_ROOT/crates/aegis-updater" "${REMOTE_ROOT_POSIX}/crates/"
scp_upload "$REPO_ROOT/crates/aegis-watchdog" "${REMOTE_ROOT_POSIX}/crates/"
scp_upload "$REPO_ROOT/proto" "${REMOTE_ROOT_POSIX}/"
scp_upload "$REPO_ROOT/packaging/windows" "${REMOTE_ROOT_POSIX}/packaging/"
scp_upload "$REPO_ROOT/scripts" "${REMOTE_ROOT_POSIX}/"
scp_upload "$VENDOR_DIR" "${REMOTE_ROOT_POSIX}/"
scp_upload "$VENDOR_CONFIG_DIR/config.toml" "${REMOTE_ROOT_POSIX}/.cargo/"
scp_upload "$REPO_ROOT/windows/driver" "${REMOTE_ROOT_POSIX}/windows/"

VALIDATE_COMMAND="powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"${REMOTE_ROOT_WIN}\\packaging\\windows\\validate.ps1\" -RepoRoot \"${REMOTE_ROOT_WIN}\""
if [[ -n "$REMOTE_TOOLCHAIN_ROOT" ]]; then
  VALIDATE_COMMAND+=" -ToolchainRoot \"${REMOTE_TOOLCHAIN_ROOT}\""
fi

RESULT_JSON=$(sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" "$VALIDATE_COMMAND")

printf '%s\n' "$RESULT_JSON" | tee "$OUTPUT_PATH"

python3 - "$OUTPUT_PATH" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    payload = json.load(fh)

failures = payload.get("required_failures") or []
if failures:
    raise SystemExit("windows package validation failed: " + ", ".join(failures))
PY
