#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PAYLOAD_ROOT=${PAYLOAD_ROOT:-$SCRIPT_DIR}
MANIFEST_PATH=${MANIFEST_PATH:-"$PAYLOAD_ROOT/manifest.json"}
INSTALL_ROOT=${INSTALL_ROOT:-}
STATE_ROOT=${STATE_ROOT:-}
CONFIG_ROOT=${CONFIG_ROOT:-}

copied_paths=()
installed_units=()
device_control_paths=()
install_completed=0
tmp_root=

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

ensure_directory() {
  install -d "$1"
}

manifest_stream() {
  python3 - "$MANIFEST_PATH" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    manifest = json.load(handle)

print(f"bundle_channel={manifest['bundle_channel']}")
print(f"install_root={manifest['install_root']}")
print(f"state_root={manifest['state_root']}")
print(f"config_root={manifest.get('config_root', '')}")
for component in manifest.get("components", []):
    print(
        "component\t{0}\t{1}\t{2}\t{3}".format(
            component["name"],
            component["source_relative_path"],
            component["install_relative_path"],
            "1" if component.get("required", True) else "0",
        )
    )
for service in manifest.get("service_units", []):
    print(
        "service\t{0}\t{1}\t{2}".format(
            service["name"],
            service["unit_name"],
            "1" if service.get("required", True) else "0",
        )
    )
PY
}

cleanup_on_error() {
  local exit_code=$?
  trap - EXIT
  if [[ $exit_code -ne 0 && $install_completed -eq 0 ]]; then
    for unit in "${installed_units[@]}"; do
      systemctl disable --now "$unit" >/dev/null 2>&1 || true
      rm -f "/etc/systemd/system/$unit"
    done
    systemctl daemon-reload >/dev/null 2>&1 || true
    [[ -n "$INSTALL_ROOT" ]] && rm -rf "$INSTALL_ROOT"
    [[ -n "$STATE_ROOT" ]] && rm -rf "$STATE_ROOT"
    [[ -n "$CONFIG_ROOT" ]] && rm -rf "$CONFIG_ROOT"
    rm -f /etc/udev/rules.d/99-aegis-removable.rules /etc/usbguard/rules.conf
  fi
  [[ -n "$tmp_root" ]] && rm -rf "$tmp_root"
  exit "$exit_code"
}

trap cleanup_on_error EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --payload-root)
      PAYLOAD_ROOT=$2
      shift 2
      ;;
    --manifest)
      MANIFEST_PATH=$2
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

require_command python3
require_command systemctl
require_command mountpoint
require_command bpftool

PAYLOAD_ROOT=$(resolve_existing_path "$PAYLOAD_ROOT" "payload root")
MANIFEST_PATH=$(resolve_existing_path "$MANIFEST_PATH" "install manifest")

components=()
service_units=()
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if [[ "$line" == component$'\t'* ]]; then
    components+=("$line")
  elif [[ "$line" == service$'\t'* ]]; then
    service_units+=("$line")
  else
    key=${line%%=*}
    value=${line#*=}
    case "$key" in
      install_root)
        [[ -z "$INSTALL_ROOT" ]] && INSTALL_ROOT=$value
        ;;
      state_root)
        [[ -z "$STATE_ROOT" ]] && STATE_ROOT=$value
        ;;
      config_root)
        [[ -z "$CONFIG_ROOT" ]] && CONFIG_ROOT=$value
        ;;
    esac
  fi
done < <(manifest_stream)

if [[ -z "$INSTALL_ROOT" || -z "$STATE_ROOT" || -z "$CONFIG_ROOT" ]]; then
  echo "install_root/state_root/config_root must be resolved before install" >&2
  exit 1
fi

ensure_directory "$INSTALL_ROOT"
ensure_directory "$STATE_ROOT"
ensure_directory "$CONFIG_ROOT"
tmp_root=$(mktemp -d)

for entry in "${components[@]}"; do
  IFS=$'\t' read -r _ name source_relative_path install_relative_path required <<<"$entry"
  source_path="$PAYLOAD_ROOT/$source_relative_path"
  install_path="$INSTALL_ROOT/$install_relative_path"
  if [[ "$required" == "1" && ! -e "$source_path" ]]; then
    echo "required payload component is missing: $name -> $source_path" >&2
    exit 1
  fi
  [[ -e "$source_path" ]] || continue
  ensure_directory "$(dirname -- "$install_path")"
  rm -rf "$install_path"
  cp -a "$source_path" "$install_path"
  copied_paths+=("$install_path")
done

cp -f "$MANIFEST_PATH" "$INSTALL_ROOT/manifest.json"
copied_paths+=("$INSTALL_ROOT/manifest.json")

if [[ ! -d /sys/fs/bpf ]]; then
  ensure_directory /sys/fs/bpf
fi
if ! mountpoint -q /sys/fs/bpf; then
  mount -t bpf bpf /sys/fs/bpf
fi
if [[ -e /sys/fs/bpf/edr ]]; then
  rm -rf /sys/fs/bpf/edr
fi
ensure_directory /sys/fs/bpf/edr/process
ensure_directory /sys/fs/bpf/edr/file
ensure_directory /sys/fs/bpf/edr/network
ensure_directory /sys/fs/bpf/edr/maps/file
ensure_directory /sys/fs/bpf/edr/maps/network

agent_path="$INSTALL_ROOT/bin/aegis-agentd"
watchdog_path="$INSTALL_ROOT/bin/aegis-watchdog"
config_path="$CONFIG_ROOT/agent.toml"

"$agent_path" --write-default-config --state-root "$STATE_ROOT" --config "$config_path" >"$tmp_root/config.json"

bpftool prog loadall "$INSTALL_ROOT/ebpf/process.bpf.o" /sys/fs/bpf/edr/process autoattach >/dev/null
bpftool prog loadall "$INSTALL_ROOT/ebpf/file.bpf.o" /sys/fs/bpf/edr/file pinmaps /sys/fs/bpf/edr/maps/file autoattach >/dev/null
bpftool prog loadall "$INSTALL_ROOT/ebpf/network.bpf.o" /sys/fs/bpf/edr/network pinmaps /sys/fs/bpf/edr/maps/network autoattach >/dev/null

device_control_root="$INSTALL_ROOT/device-control"
if [[ -d "$device_control_root" ]]; then
  udev_rule_source="$device_control_root/udev/99-aegis-removable.rules"
  usbguard_policy_source="$device_control_root/usbguard/rules.conf"
  mount_monitor_source="$device_control_root/mount-monitor.conf"

  if [[ -f "$udev_rule_source" ]]; then
    ensure_directory "/etc/udev/rules.d"
    install -m 0644 "$udev_rule_source" "/etc/udev/rules.d/99-aegis-removable.rules"
    device_control_paths+=("/etc/udev/rules.d/99-aegis-removable.rules")
    if command -v udevadm >/dev/null 2>&1; then
      udevadm control --reload-rules >/dev/null 2>&1 || true
    fi
  fi

  if [[ -f "$usbguard_policy_source" ]]; then
    ensure_directory "/etc/usbguard"
    install -m 0644 "$usbguard_policy_source" "/etc/usbguard/rules.conf"
    device_control_paths+=("/etc/usbguard/rules.conf")
  fi

  if [[ -f "$mount_monitor_source" ]]; then
    ensure_directory "$CONFIG_ROOT/device-control"
    install -m 0644 "$mount_monitor_source" "$CONFIG_ROOT/device-control/mount-monitor.conf"
    device_control_paths+=("$CONFIG_ROOT/device-control/mount-monitor.conf")
  fi
fi

for entry in "${service_units[@]}"; do
  IFS=$'\t' read -r _ name unit_name required <<<"$entry"
  source_unit="$INSTALL_ROOT/systemd/$unit_name"
  if [[ "$required" == "1" && ! -f "$source_unit" ]]; then
    echo "required systemd unit is missing from bundle: $source_unit" >&2
    exit 1
  fi
  [[ -f "$source_unit" ]] || continue
  install -m 0644 "$source_unit" "/etc/systemd/system/$unit_name"
  installed_units+=("$unit_name")
done

systemctl daemon-reload

"$agent_path" \
  --bootstrap-check \
  --state-root "$STATE_ROOT" \
  --config "$config_path" \
  --install-root "$INSTALL_ROOT" \
  --manifest "$INSTALL_ROOT/manifest.json" >"$tmp_root/bootstrap.json"

if [[ ${#installed_units[@]} -gt 0 ]]; then
  systemctl enable "${installed_units[@]}" >/dev/null
fi
systemctl restart aegis-agentd.service
sleep 2
systemctl restart aegis-watchdog.service
systemctl is-active --quiet aegis-agentd.service
systemctl is-active --quiet aegis-watchdog.service

"$watchdog_path" --once --state-root "$STATE_ROOT" >"$tmp_root/watchdog.json"

python3 - "$STATE_ROOT/install-result.json" "$PAYLOAD_ROOT" "$INSTALL_ROOT" "$STATE_ROOT" "$config_path" "$MANIFEST_PATH" "$tmp_root/config.json" "$tmp_root/bootstrap.json" "$tmp_root/watchdog.json" "${copied_paths[*]}" "${installed_units[*]}" "${device_control_paths[*]}" <<'PY'
import json
import pathlib
import sys
import time

output_path = pathlib.Path(sys.argv[1])
payload_root = sys.argv[2]
install_root = sys.argv[3]
state_root = sys.argv[4]
config_path = sys.argv[5]
manifest_path = sys.argv[6]
config_result = json.loads(pathlib.Path(sys.argv[7]).read_text(encoding="utf-8"))
bootstrap_report = json.loads(pathlib.Path(sys.argv[8]).read_text(encoding="utf-8"))
watchdog_report = json.loads(pathlib.Path(sys.argv[9]).read_text(encoding="utf-8"))
copied_paths = [item for item in sys.argv[10].split(" ") if item]
service_units = [item for item in sys.argv[11].split(" ") if item]
device_control_paths = [item for item in sys.argv[12].split(" ") if item]

payload = {
    "observed_at_ms": int(time.time() * 1000),
    "payload_root": payload_root,
    "install_root": install_root,
    "state_root": state_root,
    "config_path": config_path,
    "manifest_path": manifest_path,
    "copied_paths": copied_paths,
    "service_units": service_units,
    "device_control_paths": device_control_paths,
    "config_result": config_result,
    "bootstrap_report_path": str(pathlib.Path(state_root) / "bootstrap-check.json"),
    "watchdog_snapshot_path": str(pathlib.Path(state_root) / "watchdog-state.json"),
    "bootstrap_report": bootstrap_report,
    "watchdog_report": watchdog_report,
}
output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
print(json.dumps(payload, indent=2, ensure_ascii=False))
PY

install_completed=1
