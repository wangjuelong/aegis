#!/usr/bin/env bash
set -euo pipefail

HOST=${AEGIS_LINUX_HOST:-192.168.2.123}
USER_NAME=${AEGIS_LINUX_USER:-root}
PASSWORD=${AEGIS_LINUX_PASSWORD:-toor}
REMOTE_ROOT=${AEGIS_REMOTE_WORKDIR:-/root/aegis-linux-package-verify}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
OUTPUT_ROOT="$REPO_ROOT/target/linux-validation"
RUST_TOOLCHAIN=${AEGIS_LINUX_RUST_TOOLCHAIN:-1.94.1-x86_64-unknown-linux-gnu}
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

require_command sshpass
require_command python3

mkdir -p "$OUTPUT_ROOT"

sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" "rm -rf '$REMOTE_ROOT' && mkdir -p '$REMOTE_ROOT'"
COPYFILE_DISABLE=1 tar --exclude .git --exclude target -C "$REPO_ROOT" -cf - . | \
  sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" "tar -xf - -C '$REMOTE_ROOT'"

PROFILE_PROXY_URL=$(
  sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" "source /etc/profile >/dev/null 2>&1 || true; printf '%s' \"\${https_proxy:-\${http_proxy:-}}\""
)
REMOTE_PROXY_URL=${AEGIS_LINUX_PROFILE_PROXY:-$PROFILE_PROXY_URL}

remote_json=$(
  sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" "
    export http_proxy='$REMOTE_PROXY_URL' https_proxy='$REMOTE_PROXY_URL' all_proxy='$REMOTE_PROXY_URL'
    export HTTP_PROXY='$REMOTE_PROXY_URL' HTTPS_PROXY='$REMOTE_PROXY_URL' ALL_PROXY='$REMOTE_PROXY_URL'
    export ftp_proxy='$REMOTE_PROXY_URL' FTP_PROXY='$REMOTE_PROXY_URL'
    cd '$REMOTE_ROOT'
    dnf install -y rpm-build dpkg clang gcc gcc-c++ make cmake pkgconf-pkg-config dbus-devel openssl-devel >/dev/null
    RUSTUP_SKIP_UPDATE_CHECK=1 rustup toolchain install '$RUST_TOOLCHAIN' --profile minimal --component cargo,rustc,rust-std >/dev/null
    AEGIS_RUSTUP_TOOLCHAIN='$RUST_TOOLCHAIN' bash packaging/linux/validate.sh --repo-root '$REMOTE_ROOT'
  "
)

python3 - "$remote_json" <<'PY' | tee "$OUTPUT_ROOT/${HOST}.json"
import json
import sys

payload = json.loads(sys.argv[1])
print(json.dumps(payload, indent=2, ensure_ascii=False))
PY

echo "linux package validation completed on $USER_NAME@$HOST"
