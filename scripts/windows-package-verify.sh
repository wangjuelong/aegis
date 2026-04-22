#!/usr/bin/env bash
set -euo pipefail

HOST=${AEGIS_WINDOWS_HOST:-192.168.2.218}
USER_NAME=${AEGIS_WINDOWS_USER:-lamba}
PASSWORD=${AEGIS_WINDOWS_PASSWORD:-lamba}
OUTPUT_PATH=${AEGIS_WINDOWS_PACKAGE_VALIDATE_OUTPUT:-target/windows-package-validation/${HOST}.json}
REMOTE_TOOLCHAIN_ROOT=${AEGIS_WINDOWS_TOOLCHAIN_ROOT:-}
BUNDLE_CHANNEL=${AEGIS_WINDOWS_BUNDLE_CHANNEL:-development}
SIGNING_CERT_THUMBPRINT=${AEGIS_WINDOWS_SIGNING_CERT_THUMBPRINT:-}
SIGNING_CERT_STORE_PATH=${AEGIS_WINDOWS_SIGNING_CERT_STORE_PATH:-Cert:\\CurrentUser\\My}
TIMESTAMP_SERVER=${AEGIS_WINDOWS_TIMESTAMP_SERVER:-}
ELAM_APPROVAL_FILE=${AEGIS_WINDOWS_ELAM_APPROVAL_FILE:-}
WATCHDOG_PPL_APPROVAL_FILE=${AEGIS_WINDOWS_WATCHDOG_PPL_APPROVAL_FILE:-}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
REMOTE_PAYLOAD_ID="windows-package-verify-$(date +%Y%m%d-%H%M%S)"
REMOTE_ROOT_POSIX="C:/ProgramData/Aegis/validation/${REMOTE_PAYLOAD_ID}"
REMOTE_ROOT_WIN="C:\\ProgramData\\Aegis\\validation\\${REMOTE_PAYLOAD_ID}"

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

for tool in sshpass ssh scp python3 tar; do
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
  "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"New-Item -ItemType Directory -Force -Path '${REMOTE_ROOT_WIN}\\crates','${REMOTE_ROOT_WIN}\\scripts','${REMOTE_ROOT_WIN}\\packaging','${REMOTE_ROOT_WIN}\\windows','${REMOTE_ROOT_WIN}\\.cargo','${REMOTE_ROOT_WIN}\\approval-inputs' | Out-Null\"" >/dev/null

scp_upload() {
  local source_path=$1
  local destination_path=$2
  sshpass -p "$PASSWORD" scp -r "${SSH_OPTS[@]}" "$source_path" "$USER_NAME@$HOST:$destination_path" >/dev/null
}

tar_upload_dir() {
  local source_path=$1
  local destination_root=$2
  COPYFILE_DISABLE=1 COPY_EXTENDED_ATTRIBUTES_DISABLE=1 tar -cf - -C "$(dirname -- "$source_path")" "$(basename -- "$source_path")" | \
    sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" "tar -xf - -C $destination_root"
}

if [[ -f "$REPO_ROOT/Cargo.lock" ]]; then
  scp_upload "$REPO_ROOT/Cargo.lock" "${REMOTE_ROOT_POSIX}/"
fi
scp_upload "$REPO_ROOT/Cargo.toml" "${REMOTE_ROOT_POSIX}/"
tar_upload_dir "$REPO_ROOT/crates/aegis-agentd" "${REMOTE_ROOT_POSIX}/crates"
tar_upload_dir "$REPO_ROOT/crates/aegis-core" "${REMOTE_ROOT_POSIX}/crates"
tar_upload_dir "$REPO_ROOT/crates/aegis-model" "${REMOTE_ROOT_POSIX}/crates"
tar_upload_dir "$REPO_ROOT/crates/aegis-platform" "${REMOTE_ROOT_POSIX}/crates"
tar_upload_dir "$REPO_ROOT/crates/aegis-script" "${REMOTE_ROOT_POSIX}/crates"
tar_upload_dir "$REPO_ROOT/crates/aegis-updater" "${REMOTE_ROOT_POSIX}/crates"
tar_upload_dir "$REPO_ROOT/crates/aegis-watchdog" "${REMOTE_ROOT_POSIX}/crates"
tar_upload_dir "$REPO_ROOT/proto" "${REMOTE_ROOT_POSIX}"
tar_upload_dir "$REPO_ROOT/packaging/windows" "${REMOTE_ROOT_POSIX}/packaging"
tar_upload_dir "$REPO_ROOT/scripts" "${REMOTE_ROOT_POSIX}"
tar_upload_dir "$VENDOR_DIR" "${REMOTE_ROOT_POSIX}"
scp_upload "$VENDOR_CONFIG_DIR/config.toml" "${REMOTE_ROOT_POSIX}/.cargo/"
tar_upload_dir "$REPO_ROOT/windows/driver" "${REMOTE_ROOT_POSIX}/windows"
if [[ -n "$ELAM_APPROVAL_FILE" ]]; then
  scp_upload "$ELAM_APPROVAL_FILE" "${REMOTE_ROOT_POSIX}/approval-inputs/elam-approved.txt"
fi
if [[ -n "$WATCHDOG_PPL_APPROVAL_FILE" ]]; then
  scp_upload "$WATCHDOG_PPL_APPROVAL_FILE" "${REMOTE_ROOT_POSIX}/approval-inputs/ppl-approved.txt"
fi

VALIDATE_COMMAND="powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"${REMOTE_ROOT_WIN}\\packaging\\windows\\validate.ps1\" -RepoRoot \"${REMOTE_ROOT_WIN}\" -BundleChannel \"${BUNDLE_CHANNEL}\""
if [[ -n "$REMOTE_TOOLCHAIN_ROOT" ]]; then
  VALIDATE_COMMAND+=" -ToolchainRoot \"${REMOTE_TOOLCHAIN_ROOT}\""
fi
if [[ -n "$SIGNING_CERT_THUMBPRINT" ]]; then
  VALIDATE_COMMAND+=" -SigningCertificateThumbprint \"${SIGNING_CERT_THUMBPRINT}\""
fi
if [[ -n "$SIGNING_CERT_STORE_PATH" ]]; then
  VALIDATE_COMMAND+=" -SigningCertificateStorePath \"${SIGNING_CERT_STORE_PATH}\""
fi
if [[ -n "$TIMESTAMP_SERVER" ]]; then
  VALIDATE_COMMAND+=" -TimestampServer \"${TIMESTAMP_SERVER}\""
fi
if [[ -n "$ELAM_APPROVAL_FILE" ]]; then
  VALIDATE_COMMAND+=" -ElamApprovalPath \"${REMOTE_ROOT_WIN}\\approval-inputs\\elam-approved.txt\""
fi
if [[ -n "$WATCHDOG_PPL_APPROVAL_FILE" ]]; then
  VALIDATE_COMMAND+=" -WatchdogPplApprovalPath \"${REMOTE_ROOT_WIN}\\approval-inputs\\ppl-approved.txt\""
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
