#!/usr/bin/env bash
set -euo pipefail

HOST=${AEGIS_WINDOWS_HOST:-192.168.2.218}
USER_NAME=${AEGIS_WINDOWS_USER:-lamba}
PASSWORD=${AEGIS_WINDOWS_PASSWORD:-lamba}
OUTPUT_PATH=${AEGIS_WINDOWS_PACKAGE_BUILD_OUTPUT:-target/windows-package-build/${HOST}.json}
PACKAGE_OUTPUT_DIR=${AEGIS_WINDOWS_PACKAGE_OUTPUT_DIR:-target/windows-package-build/packages/${HOST}}
REMOTE_TOOLCHAIN_ROOT=${AEGIS_WINDOWS_TOOLCHAIN_ROOT:-}
BUNDLE_CHANNEL=${AEGIS_WINDOWS_BUNDLE_CHANNEL:-development}
SIGNING_CERT_THUMBPRINT=${AEGIS_WINDOWS_SIGNING_CERT_THUMBPRINT:-}
SIGNING_CERT_STORE_PATH=${AEGIS_WINDOWS_SIGNING_CERT_STORE_PATH:-Cert:\\CurrentUser\\My}
TIMESTAMP_SERVER=${AEGIS_WINDOWS_TIMESTAMP_SERVER:-}
ELAM_APPROVAL_FILE=${AEGIS_WINDOWS_ELAM_APPROVAL_FILE:-}
WATCHDOG_PPL_APPROVAL_FILE=${AEGIS_WINDOWS_WATCHDOG_PPL_APPROVAL_FILE:-}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
REMOTE_PAYLOAD_ID="windows-package-build-$(date +%Y%m%d-%H%M%S)"
REMOTE_ROOT_POSIX="C:/ProgramData/Aegis/package-build/${REMOTE_PAYLOAD_ID}"
REMOTE_ROOT_WIN="C:\\ProgramData\\Aegis\\package-build\\${REMOTE_PAYLOAD_ID}"
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

for tool in sshpass ssh scp python3 tar cargo; do
  require_command "$tool"
done

mkdir -p "$(dirname "$OUTPUT_PATH")" "$PACKAGE_OUTPUT_DIR"

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

BUILD_COMMAND="powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"${REMOTE_ROOT_WIN}\\packaging\\windows\\build-package.ps1\" -RepoRoot \"${REMOTE_ROOT_WIN}\" -BundleChannel \"${BUNDLE_CHANNEL}\""
if [[ -n "$REMOTE_TOOLCHAIN_ROOT" ]]; then
  BUILD_COMMAND+=" -ToolchainRoot \"${REMOTE_TOOLCHAIN_ROOT}\""
fi
if [[ -n "$SIGNING_CERT_THUMBPRINT" ]]; then
  BUILD_COMMAND+=" -SigningCertificateThumbprint \"${SIGNING_CERT_THUMBPRINT}\""
fi
if [[ -n "$SIGNING_CERT_STORE_PATH" ]]; then
  BUILD_COMMAND+=" -SigningCertificateStorePath \"${SIGNING_CERT_STORE_PATH}\""
fi
if [[ -n "$TIMESTAMP_SERVER" ]]; then
  BUILD_COMMAND+=" -TimestampServer \"${TIMESTAMP_SERVER}\""
fi
if [[ -n "$ELAM_APPROVAL_FILE" ]]; then
  BUILD_COMMAND+=" -ElamApprovalPath \"${REMOTE_ROOT_WIN}\\approval-inputs\\elam-approved.txt\""
fi
if [[ -n "$WATCHDOG_PPL_APPROVAL_FILE" ]]; then
  BUILD_COMMAND+=" -WatchdogPplApprovalPath \"${REMOTE_ROOT_WIN}\\approval-inputs\\ppl-approved.txt\""
fi

RESULT_JSON=$(sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" "$BUILD_COMMAND")
printf '%s\n' "$RESULT_JSON" > "$OUTPUT_PATH"

REMOTE_MSI_PATH=$(python3 - "$OUTPUT_PATH" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], "r", encoding="utf-8"))
print(payload["package_path"])
PY
)
REMOTE_MSI_PATH_POSIX=$(python3 - "$REMOTE_MSI_PATH" <<'PY'
import sys

path = sys.argv[1].replace("\\", "/")
print(path)
PY
)

LOCAL_MSI_PATH="$PACKAGE_OUTPUT_DIR/$(basename -- "$REMOTE_MSI_PATH_POSIX")"
sshpass -p "$PASSWORD" scp "${SSH_OPTS[@]}" "$USER_NAME@$HOST:$REMOTE_MSI_PATH_POSIX" "$LOCAL_MSI_PATH" >/dev/null

python3 - "$OUTPUT_PATH" "$LOCAL_MSI_PATH" <<'PY'
import json
import pathlib
import sys

json_path = pathlib.Path(sys.argv[1])
local_msi_path = pathlib.Path(sys.argv[2])
payload = json.loads(json_path.read_text(encoding="utf-8"))
payload["local_package_path"] = str(local_msi_path)
json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
print(json.dumps(payload, indent=2, ensure_ascii=False))
PY
