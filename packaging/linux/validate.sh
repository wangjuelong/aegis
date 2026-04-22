#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=${REPO_ROOT:-$(cd -- "$SCRIPT_DIR/../.." && pwd)}
PAYLOAD_ROOT=${PAYLOAD_ROOT:-"$REPO_ROOT/target/linux-package-validate/payload"}
OUTPUT_ROOT=${OUTPUT_ROOT:-"$REPO_ROOT/target/linux-package-validate/output"}
INSTALL_ROOT=${INSTALL_ROOT:-/opt/aegis}
STATE_ROOT=${STATE_ROOT:-/var/lib/aegis}
CONFIG_ROOT=${CONFIG_ROOT:-/etc/aegis}
PACKAGE_NAME=${PACKAGE_NAME:-aegis-sensor}
PACKAGE_VERSION=${PACKAGE_VERSION:-0.1.0}
PACKAGE_RELEASE=${PACKAGE_RELEASE:-1}
CARGO_BIN=${CARGO_BIN:-cargo}
CARGO_BUILD_OFFLINE=${CARGO_BUILD_OFFLINE:-0}
AEGIS_RUSTUP_TOOLCHAIN=${AEGIS_RUSTUP_TOOLCHAIN:-}
VALIDATION_MODE=${VALIDATION_MODE:-rpm}
DEB_PACKAGE=${DEB_PACKAGE:-}
RPM_PACKAGE=${RPM_PACKAGE:-}
BUILD_RESULT_JSON=

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

resolve_existing_path() {
  local path=$1
  local description=$2
  if [[ ! -e "$path" ]]; then
    echo "missing ${description}: ${path}" >&2
    exit 1
  fi
  (
    cd "$(dirname -- "$path")" >/dev/null 2>&1
    printf '%s/%s\n' "$(pwd)" "$(basename -- "$path")"
  )
}

ensure_root() {
  if [[ $(id -u) -ne 0 ]]; then
    echo "linux package validate must run as root" >&2
    exit 1
  fi
}

ensure_output_root() {
  mkdir -p "$OUTPUT_ROOT"
  OUTPUT_ROOT=$(cd -- "$OUTPUT_ROOT" >/dev/null 2>&1 && pwd)
}

resolve_toolchain() {
  if [[ -z "$AEGIS_RUSTUP_TOOLCHAIN" ]]; then
    require_command cargo
    require_command rustc
    mapfile -t toolchain_candidates < <(compgen -G "${HOME}/.rustup/toolchains/*/bin/cargo" || true)
    if [[ ${#toolchain_candidates[@]} -gt 0 && -x "${toolchain_candidates[0]}" ]]; then
      CARGO_BIN=${toolchain_candidates[0]}
      export PATH="$(dirname -- "$CARGO_BIN"):$PATH"
    fi
  else
    require_command rustup
  fi
}

purge_rpm_install() {
  if command -v rpm >/dev/null 2>&1 && rpm -q "$PACKAGE_NAME" >/dev/null 2>&1; then
    rpm -e "$PACKAGE_NAME" >/dev/null 2>&1 || true
  fi
  if [[ -f "$REPO_ROOT/packaging/linux/uninstall.sh" && -f "$REPO_ROOT/packaging/linux/manifest.json" ]]; then
    bash "$REPO_ROOT/packaging/linux/uninstall.sh" \
      --manifest "$REPO_ROOT/packaging/linux/manifest.json" \
      --install-root "$INSTALL_ROOT" \
      --state-root "$STATE_ROOT" \
      --config-root "$CONFIG_ROOT" >/dev/null 2>&1 || true
  fi
}

purge_deb_install() {
  if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W "$PACKAGE_NAME" >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive dpkg -P "$PACKAGE_NAME" >/dev/null 2>&1 || true
  fi
  rm -rf "$INSTALL_ROOT" "$STATE_ROOT" "$CONFIG_ROOT"
}

build_packages() {
  require_command python3
  require_command systemctl
  require_command rpm
  require_command rpmbuild
  require_command dpkg-deb
  require_command bpftool
  require_command clang
  resolve_toolchain

  rm -rf "$PAYLOAD_ROOT" "$OUTPUT_ROOT" "$REPO_ROOT/target/linux-package-validate/target"
  mkdir -p \
    "$PAYLOAD_ROOT/bin" \
    "$PAYLOAD_ROOT/ebpf" \
    "$PAYLOAD_ROOT/systemd" \
    "$PAYLOAD_ROOT/device-control" \
    "$PAYLOAD_ROOT/scripts"
  ensure_output_root
  purge_rpm_install
  purge_deb_install

  export CARGO_TARGET_DIR="$REPO_ROOT/target/linux-package-validate/target"
  export RUSTUP_SKIP_UPDATE_CHECK=1
  local -a cargo_build_args=(
    build
    --release
    -p aegis-agentd
    -p aegis-watchdog
    -p aegis-updater
    --manifest-path "$REPO_ROOT/Cargo.toml"
  )
  if [[ "$CARGO_BUILD_OFFLINE" == "1" ]]; then
    cargo_build_args+=(--offline)
  fi
  if [[ -n "$AEGIS_RUSTUP_TOOLCHAIN" ]]; then
    rustup run "$AEGIS_RUSTUP_TOOLCHAIN" cargo "${cargo_build_args[@]}" >&2
  else
    "$CARGO_BIN" "${cargo_build_args[@]}" >&2
  fi
  bash "$REPO_ROOT/packaging/linux-ebpf/build.sh" >&2

  python3 - "$REPO_ROOT/packaging/linux/manifest.json" "$PAYLOAD_ROOT/manifest.json" "$INSTALL_ROOT" "$STATE_ROOT" "$CONFIG_ROOT" <<'PY'
import json
import pathlib
import sys

template = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
install_root = sys.argv[3]
state_root = sys.argv[4]
config_root = sys.argv[5]

manifest = json.loads(template.read_text(encoding="utf-8"))
manifest["install_root"] = install_root
manifest["state_root"] = state_root
manifest["config_root"] = config_root
output.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
PY

  cp -f "$REPO_ROOT/target/linux-package-validate/target/release/aegis-agentd" "$PAYLOAD_ROOT/bin/aegis-agentd"
  cp -f "$REPO_ROOT/target/linux-package-validate/target/release/aegis-watchdog" "$PAYLOAD_ROOT/bin/aegis-watchdog"
  cp -f "$REPO_ROOT/target/linux-package-validate/target/release/aegis-updater" "$PAYLOAD_ROOT/bin/aegis-updater"
  cp -f "$REPO_ROOT/packaging/linux-ebpf/"*.bpf.o "$PAYLOAD_ROOT/ebpf/"
  cp -f "$REPO_ROOT/packaging/linux-ebpf/manifest.json" "$PAYLOAD_ROOT/ebpf/manifest.json"
  cp -f "$REPO_ROOT/packaging/linux-ebpf/README.md" "$PAYLOAD_ROOT/ebpf/README.md"
  cp -f "$REPO_ROOT/packaging/linux/systemd/"*.service "$PAYLOAD_ROOT/systemd/"
  cp -f "$REPO_ROOT/packaging/linux/device-control/README.md" "$PAYLOAD_ROOT/device-control/README.md"
  mkdir -p "$PAYLOAD_ROOT/device-control/udev" "$PAYLOAD_ROOT/device-control/usbguard"
  cp -f "$REPO_ROOT/packaging/linux/device-control/udev/"* "$PAYLOAD_ROOT/device-control/udev/"
  cp -f "$REPO_ROOT/packaging/linux/device-control/usbguard/"* "$PAYLOAD_ROOT/device-control/usbguard/"
  cp -f "$REPO_ROOT/packaging/linux/device-control/mount-monitor.conf" "$PAYLOAD_ROOT/device-control/mount-monitor.conf"
  cp -f "$REPO_ROOT/packaging/linux/install.sh" "$PAYLOAD_ROOT/scripts/install.sh"
  cp -f "$REPO_ROOT/packaging/linux/uninstall.sh" "$PAYLOAD_ROOT/scripts/uninstall.sh"
  cp -f "$REPO_ROOT/packaging/linux/build-packages.sh" "$PAYLOAD_ROOT/scripts/build-packages.sh"
  chmod +x "$PAYLOAD_ROOT/scripts/install.sh" "$PAYLOAD_ROOT/scripts/uninstall.sh" "$PAYLOAD_ROOT/scripts/build-packages.sh"

  BUILD_RESULT_JSON=$(
    bash "$REPO_ROOT/packaging/linux/build-packages.sh" \
      --payload-root "$PAYLOAD_ROOT" \
      --manifest "$PAYLOAD_ROOT/manifest.json" \
      --output-root "$OUTPUT_ROOT" \
      --version "$PACKAGE_VERSION" \
      --release "$PACKAGE_RELEASE"
  )
  printf '%s\n' "$BUILD_RESULT_JSON" >"$OUTPUT_ROOT/package-build.json"
  DEB_PACKAGE=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["deb_package"])' <<<"$BUILD_RESULT_JSON")
  RPM_PACKAGE=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["rpm_package"])' <<<"$BUILD_RESULT_JSON")
}

collect_install_artifacts() {
  local install_result_remote="$STATE_ROOT/install-result.json"
  local bootstrap_report_remote="$STATE_ROOT/bootstrap-check.json"
  local watchdog_snapshot_remote="$STATE_ROOT/watchdog-state.json"
  local diagnose_path="$OUTPUT_ROOT/diagnose.json"

  "$INSTALL_ROOT/bin/aegis-agentd" --diagnose --state-root "$STATE_ROOT" --config "$CONFIG_ROOT/agent.toml" >"$diagnose_path"
  cp -f "$install_result_remote" "$OUTPUT_ROOT/install-result.json"
  cp -f "$bootstrap_report_remote" "$OUTPUT_ROOT/bootstrap-check.json"
  cp -f "$watchdog_snapshot_remote" "$OUTPUT_ROOT/watchdog-state.json"
}

device_control_paths_from_install_result() {
  local install_result_path=$1
  python3 - "$install_result_path" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], "r", encoding="utf-8"))
print(" ".join(payload.get("device_control_paths") or []))
PY
}

emit_validation_json() {
  local package_format=$1
  local package_path=$2
  local package_metadata_path=$3
  local device_control_paths=$4
  local required_failures=$5

  python3 - "$package_format" "$package_path" "$package_metadata_path" \
    "$OUTPUT_ROOT/install-result.json" "$OUTPUT_ROOT/bootstrap-check.json" \
    "$OUTPUT_ROOT/watchdog-state.json" "$OUTPUT_ROOT/diagnose.json" \
    "$device_control_paths" "$required_failures" <<'PY'
import json
import pathlib
import sys

package_format = sys.argv[1]
package_path = sys.argv[2]
package_metadata_path = sys.argv[3]
install_result_path = pathlib.Path(sys.argv[4])
bootstrap_report_path = pathlib.Path(sys.argv[5])
watchdog_snapshot_path = pathlib.Path(sys.argv[6])
diagnose_path = pathlib.Path(sys.argv[7])
device_control_paths = [item for item in sys.argv[8].split(" ") if item]
required_failures = [item for item in sys.argv[9].split(" ") if item]

metadata = {}
if package_metadata_path:
    metadata = json.loads(pathlib.Path(package_metadata_path).read_text(encoding="utf-8"))

payload = {
    "package_format": package_format,
    "package_path": package_path,
    "package_build_metadata": metadata,
    "install_result_path": str(install_result_path),
    "bootstrap_report_path": str(bootstrap_report_path),
    "watchdog_snapshot_path": str(watchdog_snapshot_path),
    "diagnose": json.loads(diagnose_path.read_text(encoding="utf-8")),
    "device_control_paths": device_control_paths,
    "required_failures": required_failures,
}
print(json.dumps(payload, indent=2, ensure_ascii=False))
if required_failures:
    raise SystemExit(1)
PY
}

validate_rpm_package() {
  require_command python3
  require_command systemctl
  require_command rpm

  ensure_output_root
  purge_rpm_install
  rpm -Uvh --force "$RPM_PACKAGE" >/dev/null
  systemctl is-enabled aegis-agentd.service >/dev/null
  systemctl is-enabled aegis-watchdog.service >/dev/null
  systemctl is-active --quiet aegis-agentd.service
  systemctl is-active --quiet aegis-watchdog.service
  collect_install_artifacts
  rpm -e "$PACKAGE_NAME" >/dev/null

  local install_result_path="$OUTPUT_ROOT/install-result.json"
  local device_control_paths
  device_control_paths=$(device_control_paths_from_install_result "$install_result_path")
  local -a required_failures=()
  [[ -f "$install_result_path" ]] || required_failures+=("install_result")
  [[ -f "$OUTPUT_ROOT/bootstrap-check.json" ]] || required_failures+=("bootstrap_report")
  [[ -f "$OUTPUT_ROOT/watchdog-state.json" ]] || required_failures+=("watchdog_snapshot")
  [[ ! -e "$INSTALL_ROOT" ]] || required_failures+=("install_root_cleanup")
  [[ ! -e "$CONFIG_ROOT" ]] || required_failures+=("config_root_cleanup")
  [[ ! -e "$STATE_ROOT" ]] || required_failures+=("state_root_cleanup")
  [[ -n "$device_control_paths" ]] || required_failures+=("device_control_paths")

  emit_validation_json "rpm" "$RPM_PACKAGE" "$OUTPUT_ROOT/package-build.json" "$device_control_paths" "${required_failures[*]}"
}

validate_deb_package() {
  require_command python3
  require_command systemctl
  require_command dpkg
  require_command dpkg-query

  ensure_output_root
  purge_deb_install
  DEBIAN_FRONTEND=noninteractive dpkg -i "$DEB_PACKAGE" >/dev/null
  systemctl is-enabled aegis-agentd.service >/dev/null
  systemctl is-enabled aegis-watchdog.service >/dev/null
  systemctl is-active --quiet aegis-agentd.service
  systemctl is-active --quiet aegis-watchdog.service
  collect_install_artifacts
  DEBIAN_FRONTEND=noninteractive dpkg -P "$PACKAGE_NAME" >/dev/null

  local install_result_path="$OUTPUT_ROOT/install-result.json"
  local device_control_paths
  device_control_paths=$(device_control_paths_from_install_result "$install_result_path")
  local -a required_failures=()
  [[ -f "$install_result_path" ]] || required_failures+=("install_result")
  [[ -f "$OUTPUT_ROOT/bootstrap-check.json" ]] || required_failures+=("bootstrap_report")
  [[ -f "$OUTPUT_ROOT/watchdog-state.json" ]] || required_failures+=("watchdog_snapshot")
  [[ ! -e "$INSTALL_ROOT" ]] || required_failures+=("install_root_cleanup")
  [[ ! -e "$CONFIG_ROOT" ]] || required_failures+=("config_root_cleanup")
  [[ ! -e "$STATE_ROOT" ]] || required_failures+=("state_root_cleanup")
  [[ -n "$device_control_paths" ]] || required_failures+=("device_control_paths")
  if dpkg-query -W "$PACKAGE_NAME" >/dev/null 2>&1; then
    required_failures+=("package_purge")
  fi

  emit_validation_json "deb" "$DEB_PACKAGE" "$OUTPUT_ROOT/package-build.json" "$device_control_paths" "${required_failures[*]}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root)
      REPO_ROOT=$2
      shift 2
      ;;
    --payload-root)
      PAYLOAD_ROOT=$2
      shift 2
      ;;
    --output-root)
      OUTPUT_ROOT=$2
      shift 2
      ;;
    --install-root)
      INSTALL_ROOT=$2
      shift 2
      ;;
    --state-root)
      STATE_ROOT=$2
      shift 2
      ;;
    --config-root)
      CONFIG_ROOT=$2
      shift 2
      ;;
    --validation-mode)
      VALIDATION_MODE=$2
      shift 2
      ;;
    --deb-package)
      DEB_PACKAGE=$2
      shift 2
      ;;
    --rpm-package)
      RPM_PACKAGE=$2
      shift 2
      ;;
    *)
      echo "unsupported argument: $1" >&2
      exit 1
      ;;
  esac
done

case "$VALIDATION_MODE" in
  build-only|rpm|deb)
    ;;
  *)
    echo "unsupported validation mode: $VALIDATION_MODE" >&2
    exit 1
    ;;
esac

ensure_root

if [[ -n "$DEB_PACKAGE" ]]; then
  DEB_PACKAGE=$(resolve_existing_path "$DEB_PACKAGE" "deb package")
fi
if [[ -n "$RPM_PACKAGE" ]]; then
  RPM_PACKAGE=$(resolve_existing_path "$RPM_PACKAGE" "rpm package")
fi

if [[ "$VALIDATION_MODE" == "build-only" || ( "$VALIDATION_MODE" == "rpm" && -z "$RPM_PACKAGE" ) || ( "$VALIDATION_MODE" == "deb" && -z "$DEB_PACKAGE" ) ]]; then
  build_packages
fi

case "$VALIDATION_MODE" in
  build-only)
    printf '%s\n' "$BUILD_RESULT_JSON"
    ;;
  rpm)
    validate_rpm_package
    ;;
  deb)
    validate_deb_package
    ;;
esac
