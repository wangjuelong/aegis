#!/usr/bin/env bash
set -euo pipefail

BUILD_HOST=${AEGIS_LINUX_BUILD_HOST:-${AEGIS_LINUX_HOST:-192.168.2.123}}
BUILD_USER=${AEGIS_LINUX_BUILD_USER:-${AEGIS_LINUX_USER:-root}}
BUILD_PASSWORD=${AEGIS_LINUX_BUILD_PASSWORD:-${AEGIS_LINUX_PASSWORD:-toor}}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
OUTPUT_PATH=${AEGIS_LINUX_PACKAGE_BUILD_OUTPUT:-"$REPO_ROOT/target/linux-package-build/${BUILD_HOST}.json"}
PACKAGE_OUTPUT_DIR=${AEGIS_LINUX_PACKAGE_OUTPUT_DIR:-"$REPO_ROOT/target/linux-package-build/packages/${BUILD_HOST}"}
BUILD_REMOTE_ROOT=${AEGIS_LINUX_BUILD_REMOTE_WORKDIR:-/root/aegis-linux-package-build-$(date +%Y%m%d-%H%M%S)}
RUST_TOOLCHAIN=${AEGIS_LINUX_RUST_TOOLCHAIN:-1.94.1-x86_64-unknown-linux-gnu}
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

for tool in sshpass ssh scp python3 tar; do
  require_command "$tool"
done

mkdir -p "$(dirname "$OUTPUT_PATH")" "$PACKAGE_OUTPUT_DIR"

ssh_run() {
  local command=$1
  sshpass -p "$BUILD_PASSWORD" ssh "${SSH_OPTS[@]}" "$BUILD_USER@$BUILD_HOST" "$command"
}

scp_download() {
  local source_path=$1
  local destination_path=$2
  sshpass -p "$BUILD_PASSWORD" scp -r "${SSH_OPTS[@]}" "$BUILD_USER@$BUILD_HOST:$source_path" "$destination_path" >/dev/null
}

ssh_run "rm -rf '$BUILD_REMOTE_ROOT' && mkdir -p '$BUILD_REMOTE_ROOT'"
COPYFILE_DISABLE=1 tar --exclude .git --exclude target -cf - -C "$REPO_ROOT" . | \
  sshpass -p "$BUILD_PASSWORD" ssh "${SSH_OPTS[@]}" "$BUILD_USER@$BUILD_HOST" "tar -xf - -C '$BUILD_REMOTE_ROOT'"

PROFILE_PROXY_URL=$(
  ssh_run "source /etc/profile >/dev/null 2>&1 || true; printf '%s' \"\${https_proxy:-\${http_proxy:-}}\""
)
REMOTE_PROXY_URL=${AEGIS_LINUX_PROFILE_PROXY:-$PROFILE_PROXY_URL}

BUILD_JSON=$(
  ssh_run "
    export http_proxy='$REMOTE_PROXY_URL' https_proxy='$REMOTE_PROXY_URL' all_proxy='$REMOTE_PROXY_URL'
    export HTTP_PROXY='$REMOTE_PROXY_URL' HTTPS_PROXY='$REMOTE_PROXY_URL' ALL_PROXY='$REMOTE_PROXY_URL'
    export ftp_proxy='$REMOTE_PROXY_URL' FTP_PROXY='$REMOTE_PROXY_URL'
    cd '$BUILD_REMOTE_ROOT'
    dnf install -y rpm-build dpkg clang gcc gcc-c++ make cmake pkgconf-pkg-config dbus-devel openssl-devel >/dev/null
    RUSTUP_SKIP_UPDATE_CHECK=1 rustup toolchain install '$RUST_TOOLCHAIN' --profile minimal --component cargo,rustc,rust-std >/dev/null
    AEGIS_RUSTUP_TOOLCHAIN='$RUST_TOOLCHAIN' bash packaging/linux/validate.sh --validation-mode build-only --repo-root '$BUILD_REMOTE_ROOT'
  "
)
printf '%s\n' "$BUILD_JSON" > "$OUTPUT_PATH"

REMOTE_DEB_PATH=$(python3 - "$OUTPUT_PATH" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], "r", encoding="utf-8"))
print(payload["deb_package"])
PY
)

REMOTE_RPM_PATH=$(python3 - "$OUTPUT_PATH" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], "r", encoding="utf-8"))
print(payload["rpm_package"])
PY
)

LOCAL_DEB_PATH="$PACKAGE_OUTPUT_DIR/$(basename -- "$REMOTE_DEB_PATH")"
LOCAL_RPM_PATH="$PACKAGE_OUTPUT_DIR/$(basename -- "$REMOTE_RPM_PATH")"
scp_download "$REMOTE_DEB_PATH" "$LOCAL_DEB_PATH"
scp_download "$REMOTE_RPM_PATH" "$LOCAL_RPM_PATH"

python3 - "$OUTPUT_PATH" "$LOCAL_DEB_PATH" "$LOCAL_RPM_PATH" <<'PY'
import json
import pathlib
import sys

json_path = pathlib.Path(sys.argv[1])
local_deb_path = pathlib.Path(sys.argv[2])
local_rpm_path = pathlib.Path(sys.argv[3])
payload = json.loads(json_path.read_text(encoding="utf-8"))
payload["local_deb_package"] = str(local_deb_path)
payload["local_rpm_package"] = str(local_rpm_path)
json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
print(json.dumps(payload, indent=2, ensure_ascii=False))
PY
