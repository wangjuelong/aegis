#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
MANIFEST_PATH=${MANIFEST_PATH:-"$SCRIPT_DIR/manifest.json"}
INSTALL_ROOT=${INSTALL_ROOT:-}
STATE_ROOT=${STATE_ROOT:-}
CONFIG_ROOT=${CONFIG_ROOT:-}

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

manifest_stream() {
  python3 - "$MANIFEST_PATH" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    manifest = json.load(handle)

print(f"install_root={manifest['install_root']}")
print(f"state_root={manifest['state_root']}")
print(f"config_root={manifest.get('config_root', '')}")
for service in manifest.get("service_units", []):
    print("service\t{0}".format(service["unit_name"]))
PY
}

while [[ $# -gt 0 ]]; do
  case "$1" in
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

MANIFEST_PATH=$(resolve_existing_path "$MANIFEST_PATH" "install manifest")

service_units=()
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if [[ "$line" == service$'\t'* ]]; then
    service_units+=("${line#service$'\t'}")
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

removed_paths=()
for unit in "${service_units[@]}"; do
  systemctl disable --now "$unit" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$unit"
done
systemctl daemon-reload

for path in \
  "/etc/udev/rules.d/99-aegis-removable.rules" \
  "/etc/usbguard/rules.conf" \
  "/sys/fs/bpf/edr"; do
  if [[ -e "$path" ]]; then
    rm -rf "$path"
    removed_paths+=("$path")
  fi
done

for path in "$INSTALL_ROOT" "$STATE_ROOT" "$CONFIG_ROOT"; do
  if [[ -n "$path" && -e "$path" ]]; then
    rm -rf "$path"
    removed_paths+=("$path")
  fi
done

python3 - <<'PY' "${removed_paths[*]}" "${service_units[*]}"
import json
import sys

removed_paths = [item for item in sys.argv[1].split(" ") if item]
service_units = [item for item in sys.argv[2].split(" ") if item]
print(json.dumps({
    "removed_paths": removed_paths,
    "service_units": service_units,
}, indent=2, ensure_ascii=False))
PY
