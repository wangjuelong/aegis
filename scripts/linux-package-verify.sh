#!/usr/bin/env bash
set -euo pipefail

BUILD_HOST=${AEGIS_LINUX_BUILD_HOST:-${AEGIS_LINUX_HOST:-192.168.2.123}}
BUILD_USER=${AEGIS_LINUX_BUILD_USER:-${AEGIS_LINUX_USER:-root}}
BUILD_PASSWORD=${AEGIS_LINUX_BUILD_PASSWORD:-${AEGIS_LINUX_PASSWORD:-toor}}
VERIFY_HOST=${AEGIS_LINUX_VERIFY_HOST:-$BUILD_HOST}
if [[ "$VERIFY_HOST" == "$BUILD_HOST" ]]; then
  VERIFY_USER_DEFAULT=$BUILD_USER
  VERIFY_PASSWORD_DEFAULT=$BUILD_PASSWORD
else
  VERIFY_USER_DEFAULT=ubuntu
  VERIFY_PASSWORD_DEFAULT=ubuntu
fi
VERIFY_USER=${AEGIS_LINUX_VERIFY_USER:-$VERIFY_USER_DEFAULT}
VERIFY_PASSWORD=${AEGIS_LINUX_VERIFY_PASSWORD:-$VERIFY_PASSWORD_DEFAULT}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
OUTPUT_ROOT="$REPO_ROOT/target/linux-validation"
PACKAGE_OUTPUT_ROOT="$OUTPUT_ROOT/packages"
BUILD_REMOTE_ROOT=${AEGIS_LINUX_BUILD_REMOTE_WORKDIR:-/root/aegis-linux-package-build-$(date +%Y%m%d-%H%M%S)}
VERIFY_REMOTE_ROOT=${AEGIS_LINUX_VERIFY_REMOTE_WORKDIR:-/home/${VERIFY_USER}/aegis-linux-package-verify-$(date +%Y%m%d-%H%M%S)}
RUST_TOOLCHAIN=${AEGIS_LINUX_RUST_TOOLCHAIN:-1.94.1-x86_64-unknown-linux-gnu}
PACKAGE_FORMAT=${AEGIS_LINUX_PACKAGE_FORMAT:-auto}
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

ssh_run() {
  local password=$1
  local user_name=$2
  local host=$3
  local command=$4
  sshpass -p "$password" ssh "${SSH_OPTS[@]}" "$user_name@$host" "$command"
}

scp_upload() {
  local password=$1
  local source_path=$2
  local user_name=$3
  local host=$4
  local destination_path=$5
  sshpass -p "$password" scp -r "${SSH_OPTS[@]}" "$source_path" "$user_name@$host:$destination_path" >/dev/null
}

scp_download() {
  local password=$1
  local user_name=$2
  local host=$3
  local source_path=$4
  local destination_path=$5
  sshpass -p "$password" scp -r "${SSH_OPTS[@]}" "$user_name@$host:$source_path" "$destination_path" >/dev/null
}

sync_repo_to_host() {
  local password=$1
  local user_name=$2
  local host=$3
  local remote_root=$4

  ssh_run "$password" "$user_name" "$host" "rm -rf '$remote_root' && mkdir -p '$remote_root'"
  COPYFILE_DISABLE=1 tar --exclude .git --exclude target -C "$REPO_ROOT" -cf - . | \
    sshpass -p "$password" ssh "${SSH_OPTS[@]}" "$user_name@$host" "tar -xf - -C '$remote_root'"
}

profile_proxy_url() {
  local password=$1
  local user_name=$2
  local host=$3
  ssh_run "$password" "$user_name" "$host" "source /etc/profile >/dev/null 2>&1 || true; printf '%s' \"\${https_proxy:-\${http_proxy:-}}\""
}

infer_package_format() {
  if [[ "$PACKAGE_FORMAT" != "auto" ]]; then
    return
  fi
  local verify_os_id
  verify_os_id=$(ssh_run "$VERIFY_PASSWORD" "$VERIFY_USER" "$VERIFY_HOST" "source /etc/os-release >/dev/null 2>&1 && printf '%s' \"\$ID\"")
  case "$verify_os_id" in
    ubuntu|debian)
      PACKAGE_FORMAT=deb
      ;;
    *)
      PACKAGE_FORMAT=rpm
      ;;
  esac
}

run_build_host_validate() {
  local build_proxy_url=$1
  ssh_run "$BUILD_PASSWORD" "$BUILD_USER" "$BUILD_HOST" "
    export http_proxy='$build_proxy_url' https_proxy='$build_proxy_url' all_proxy='$build_proxy_url'
    export HTTP_PROXY='$build_proxy_url' HTTPS_PROXY='$build_proxy_url' ALL_PROXY='$build_proxy_url'
    export ftp_proxy='$build_proxy_url' FTP_PROXY='$build_proxy_url'
    cd '$BUILD_REMOTE_ROOT'
    dnf install -y rpm-build dpkg clang gcc gcc-c++ make cmake pkgconf-pkg-config dbus-devel openssl-devel >/dev/null
    RUSTUP_SKIP_UPDATE_CHECK=1 rustup toolchain install '$RUST_TOOLCHAIN' --profile minimal --component cargo,rustc,rust-std >/dev/null
    AEGIS_RUSTUP_TOOLCHAIN='$RUST_TOOLCHAIN' bash packaging/linux/validate.sh --validation-mode rpm --repo-root '$BUILD_REMOTE_ROOT'
  "
}

run_build_only() {
  local build_proxy_url=$1
  ssh_run "$BUILD_PASSWORD" "$BUILD_USER" "$BUILD_HOST" "
    export http_proxy='$build_proxy_url' https_proxy='$build_proxy_url' all_proxy='$build_proxy_url'
    export HTTP_PROXY='$build_proxy_url' HTTPS_PROXY='$build_proxy_url' ALL_PROXY='$build_proxy_url'
    export ftp_proxy='$build_proxy_url' FTP_PROXY='$build_proxy_url'
    cd '$BUILD_REMOTE_ROOT'
    dnf install -y rpm-build dpkg clang gcc gcc-c++ make cmake pkgconf-pkg-config dbus-devel openssl-devel >/dev/null
    RUSTUP_SKIP_UPDATE_CHECK=1 rustup toolchain install '$RUST_TOOLCHAIN' --profile minimal --component cargo,rustc,rust-std >/dev/null
    AEGIS_RUSTUP_TOOLCHAIN='$RUST_TOOLCHAIN' bash packaging/linux/validate.sh --validation-mode build-only --repo-root '$BUILD_REMOTE_ROOT'
  "
}

run_verify_host_deb_validate() {
  local remote_deb_path=$1
  ssh_run "$VERIFY_PASSWORD" "$VERIFY_USER" "$VERIFY_HOST" "
    set -u
    mkdir -p '$VERIFY_REMOTE_ROOT/output'
    validate_exit=0
    printf '%s\n' '$VERIFY_PASSWORD' | sudo -S -p '' bash '$VERIFY_REMOTE_ROOT/validate.sh' \
      --validation-mode deb \
      --deb-package '$remote_deb_path' \
      --output-root '$VERIFY_REMOTE_ROOT/output' > '$VERIFY_REMOTE_ROOT/result.json' || validate_exit=\$?
    printf '%s\n' '$VERIFY_PASSWORD' | sudo -S -p '' chown -R '$VERIFY_USER:$VERIFY_USER' '$VERIFY_REMOTE_ROOT'
    cat '$VERIFY_REMOTE_ROOT/result.json'
    exit \$validate_exit
  "
}

assert_required_failures_empty() {
  local json_path=$1
  python3 - "$json_path" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], "r", encoding="utf-8"))
failures = payload.get("required_failures") or []
if failures:
    raise SystemExit("linux package validation failed: " + ", ".join(failures))
PY
}

require_command sshpass
require_command python3

mkdir -p "$OUTPUT_ROOT" "$PACKAGE_OUTPUT_ROOT"
infer_package_format

if [[ "$PACKAGE_FORMAT" == "rpm" && "$VERIFY_HOST" == "$BUILD_HOST" && "$VERIFY_USER" == "$BUILD_USER" ]]; then
  sync_repo_to_host "$BUILD_PASSWORD" "$BUILD_USER" "$BUILD_HOST" "$BUILD_REMOTE_ROOT"
  BUILD_PROXY_URL=${AEGIS_LINUX_PROFILE_PROXY:-$(profile_proxy_url "$BUILD_PASSWORD" "$BUILD_USER" "$BUILD_HOST")}
  remote_json=$(run_build_host_validate "$BUILD_PROXY_URL")
  printf '%s\n' "$remote_json" | python3 -c 'import json,sys; print(json.dumps(json.loads(sys.stdin.read()), indent=2, ensure_ascii=False))' | tee "$OUTPUT_ROOT/${VERIFY_HOST}.json"
  assert_required_failures_empty "$OUTPUT_ROOT/${VERIFY_HOST}.json"
  echo "linux package validation completed on $BUILD_USER@$BUILD_HOST"
  exit 0
fi

if [[ "$PACKAGE_FORMAT" != "deb" ]]; then
  echo "unsupported package format for multi-host validation: $PACKAGE_FORMAT" >&2
  exit 1
fi

sync_repo_to_host "$BUILD_PASSWORD" "$BUILD_USER" "$BUILD_HOST" "$BUILD_REMOTE_ROOT"
BUILD_PROXY_URL=${AEGIS_LINUX_PROFILE_PROXY:-$(profile_proxy_url "$BUILD_PASSWORD" "$BUILD_USER" "$BUILD_HOST")}
build_json=$(run_build_only "$BUILD_PROXY_URL")
printf '%s\n' "$build_json" | python3 -c 'import json,sys; print(json.dumps(json.loads(sys.stdin.read()), indent=2, ensure_ascii=False))' | tee "$OUTPUT_ROOT/${BUILD_HOST}-build.json"

deb_package_path=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["deb_package"])' <<<"$build_json")
local_package_dir="$PACKAGE_OUTPUT_ROOT/$VERIFY_HOST"
rm -rf "$local_package_dir"
mkdir -p "$local_package_dir"
scp_download "$BUILD_PASSWORD" "$BUILD_USER" "$BUILD_HOST" "$deb_package_path" "$local_package_dir/"
local_deb_path="$local_package_dir/$(basename -- "$deb_package_path")"

ssh_run "$VERIFY_PASSWORD" "$VERIFY_USER" "$VERIFY_HOST" "rm -rf '$VERIFY_REMOTE_ROOT' && mkdir -p '$VERIFY_REMOTE_ROOT/output'"
scp_upload "$VERIFY_PASSWORD" "$REPO_ROOT/packaging/linux/validate.sh" "$VERIFY_USER" "$VERIFY_HOST" "$VERIFY_REMOTE_ROOT/validate.sh"
scp_upload "$VERIFY_PASSWORD" "$local_deb_path" "$VERIFY_USER" "$VERIFY_HOST" "$VERIFY_REMOTE_ROOT/"
scp_upload "$VERIFY_PASSWORD" "$OUTPUT_ROOT/${BUILD_HOST}-build.json" "$VERIFY_USER" "$VERIFY_HOST" "$VERIFY_REMOTE_ROOT/output/package-build.json"

remote_verify_json=$(run_verify_host_deb_validate "$VERIFY_REMOTE_ROOT/$(basename -- "$local_deb_path")")
printf '%s\n' "$remote_verify_json" | python3 -c 'import json,sys; print(json.dumps(json.loads(sys.stdin.read()), indent=2, ensure_ascii=False))' | tee "$OUTPUT_ROOT/${VERIFY_HOST}.json"
rm -rf "$OUTPUT_ROOT/${VERIFY_HOST}-artifacts"
mkdir -p "$OUTPUT_ROOT/${VERIFY_HOST}-artifacts"
scp_download "$VERIFY_PASSWORD" "$VERIFY_USER" "$VERIFY_HOST" "$VERIFY_REMOTE_ROOT/output/." "$OUTPUT_ROOT/${VERIFY_HOST}-artifacts/"
assert_required_failures_empty "$OUTPUT_ROOT/${VERIFY_HOST}.json"

echo "linux deb package validation completed on $VERIFY_USER@$VERIFY_HOST"
