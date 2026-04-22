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

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
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
    *)
      echo "unsupported argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -n "$AEGIS_RUSTUP_TOOLCHAIN" ]]; then
  require_command rustup
else
  require_command cargo
  require_command rustc
fi
require_command python3
require_command systemctl
require_command rpm
require_command rpmbuild
require_command dpkg-deb
require_command bpftool
require_command clang

if [[ $(id -u) -ne 0 ]]; then
  echo "linux package validate must run as root" >&2
  exit 1
fi

if [[ -z "$AEGIS_RUSTUP_TOOLCHAIN" ]]; then
  mapfile -t toolchain_candidates < <(compgen -G "${HOME}/.rustup/toolchains/*/bin/cargo" || true)
  if [[ ${#toolchain_candidates[@]} -gt 0 && -x "${toolchain_candidates[0]}" ]]; then
    CARGO_BIN=${toolchain_candidates[0]}
    export PATH="$(dirname -- "$CARGO_BIN"):$PATH"
  fi
fi

rm -rf "$PAYLOAD_ROOT" "$OUTPUT_ROOT" "$REPO_ROOT/target/linux-package-validate/target"
mkdir -p "$PAYLOAD_ROOT/bin" "$PAYLOAD_ROOT/ebpf" "$PAYLOAD_ROOT/systemd" "$PAYLOAD_ROOT/device-control" "$PAYLOAD_ROOT/scripts" "$OUTPUT_ROOT"

rpm -q "$PACKAGE_NAME" >/dev/null 2>&1 && rpm -e "$PACKAGE_NAME" >/dev/null 2>&1 || true
bash "$REPO_ROOT/packaging/linux/uninstall.sh" --manifest "$REPO_ROOT/packaging/linux/manifest.json" --install-root "$INSTALL_ROOT" --state-root "$STATE_ROOT" --config-root "$CONFIG_ROOT" >/dev/null 2>&1 || true

export CARGO_TARGET_DIR="$REPO_ROOT/target/linux-package-validate/target"
export RUSTUP_SKIP_UPDATE_CHECK=1
cargo_build_args=(
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
  rustup run "$AEGIS_RUSTUP_TOOLCHAIN" cargo "${cargo_build_args[@]}"
else
  "$CARGO_BIN" "${cargo_build_args[@]}"
fi
bash "$REPO_ROOT/packaging/linux-ebpf/build.sh"

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

package_build_json=$(
  bash "$REPO_ROOT/packaging/linux/build-packages.sh" \
    --payload-root "$PAYLOAD_ROOT" \
    --manifest "$PAYLOAD_ROOT/manifest.json" \
    --output-root "$OUTPUT_ROOT" \
    --version "$PACKAGE_VERSION" \
    --release "$PACKAGE_RELEASE"
)
deb_package_path=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["deb_package"])' <<<"$package_build_json")
rpm_package_path=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["rpm_package"])' <<<"$package_build_json")

dpkg-deb --info "$deb_package_path" >/dev/null
rpm -Uvh --force "$rpm_package_path" >/dev/null
systemctl is-enabled aegis-agentd.service >/dev/null
systemctl is-enabled aegis-watchdog.service >/dev/null
systemctl is-active --quiet aegis-agentd.service
systemctl is-active --quiet aegis-watchdog.service

install_result_path="$STATE_ROOT/install-result.json"
bootstrap_report_path="$STATE_ROOT/bootstrap-check.json"
watchdog_snapshot_path="$STATE_ROOT/watchdog-state.json"
diagnose_path="$OUTPUT_ROOT/diagnose.json"
"$INSTALL_ROOT/bin/aegis-agentd" --diagnose --state-root "$STATE_ROOT" --config "$CONFIG_ROOT/agent.toml" >"$diagnose_path"

cp -f "$install_result_path" "$OUTPUT_ROOT/install-result.json"
cp -f "$bootstrap_report_path" "$OUTPUT_ROOT/bootstrap-check.json"
cp -f "$watchdog_snapshot_path" "$OUTPUT_ROOT/watchdog-state.json"

install_result_path="$OUTPUT_ROOT/install-result.json"
bootstrap_report_path="$OUTPUT_ROOT/bootstrap-check.json"
watchdog_snapshot_path="$OUTPUT_ROOT/watchdog-state.json"
device_control_paths=$(python3 - "$install_result_path" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], "r", encoding="utf-8"))
print(" ".join(payload.get("device_control_paths") or []))
PY
)

rpm -e "$PACKAGE_NAME" >/dev/null

required_failures=()
[[ -f "$install_result_path" ]] || required_failures+=("install_result")
[[ -f "$bootstrap_report_path" ]] || required_failures+=("bootstrap_report")
[[ -f "$watchdog_snapshot_path" ]] || required_failures+=("watchdog_snapshot")
[[ ! -e "$INSTALL_ROOT" ]] || required_failures+=("install_root_cleanup")
[[ ! -e "$CONFIG_ROOT" ]] || required_failures+=("config_root_cleanup")
[[ ! -e "$STATE_ROOT" ]] || required_failures+=("state_root_cleanup")
[[ -n "$device_control_paths" ]] || required_failures+=("device_control_paths")

python3 - "$deb_package_path" "$rpm_package_path" "$install_result_path" "$bootstrap_report_path" "$watchdog_snapshot_path" "$diagnose_path" "$device_control_paths" "${required_failures[*]}" <<'PY'
import json
import pathlib
import sys

device_control_paths = [item for item in sys.argv[7].split(" ") if item]
required_failures = [item for item in sys.argv[8].split(" ") if item]
payload = {
    "deb_package": sys.argv[1],
    "rpm_package": sys.argv[2],
    "install_result_path": sys.argv[3],
    "bootstrap_report_path": sys.argv[4],
    "watchdog_snapshot_path": sys.argv[5],
    "diagnose": json.loads(pathlib.Path(sys.argv[6]).read_text(encoding="utf-8")),
    "device_control_paths": device_control_paths,
    "required_failures": required_failures,
}
print(json.dumps(payload, indent=2, ensure_ascii=False))
if required_failures:
    raise SystemExit(1)
PY
