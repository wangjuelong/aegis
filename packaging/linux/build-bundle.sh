#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=${REPO_ROOT:-$(cd -- "$SCRIPT_DIR/../.." && pwd)}
PAYLOAD_ROOT=${PAYLOAD_ROOT:-"$REPO_ROOT/target/linux-package-validate/payload"}
OUTPUT_ROOT=${OUTPUT_ROOT:-"$REPO_ROOT/target/linux-package-validate/output"}
INSTALL_ROOT=${INSTALL_ROOT:-/opt/aegis}
STATE_ROOT=${STATE_ROOT:-/var/lib/aegis}
CONFIG_ROOT=${CONFIG_ROOT:-/etc/aegis}
PACKAGE_VERSION=${PACKAGE_VERSION:-0.1.0}
PACKAGE_RELEASE=${PACKAGE_RELEASE:-1}
LINUX_EBPF_ARTIFACT_ROOT=${AEGIS_LINUX_EBPF_ARTIFACT_ROOT:-}
CARGO_CLEAN_TARGET=${CARGO_CLEAN_TARGET:-0}

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

mapfile -t container_toolchain_candidates < <(compgen -G "/usr/local/rustup/toolchains/*/bin/cargo" || true)
if [[ ${#container_toolchain_candidates[@]} -gt 0 && -x "${container_toolchain_candidates[0]}" ]]; then
  export PATH="$(dirname -- "${container_toolchain_candidates[0]}"):/usr/local/cargo/bin:$PATH"
elif ! command -v cargo >/dev/null 2>&1 && [[ -x /usr/local/cargo/bin/cargo ]]; then
  export PATH="/usr/local/cargo/bin:$PATH"
fi

require_command cargo
require_command rustc
require_command python3
require_command clang
require_command rpmbuild
require_command dpkg-deb
if [[ -z "${AEGIS_BTF_VMLINUX_HEADER:-}" && -z "$LINUX_EBPF_ARTIFACT_ROOT" ]]; then
  require_command bpftool
fi

rm -rf "$PAYLOAD_ROOT" "$OUTPUT_ROOT"
if [[ "$CARGO_CLEAN_TARGET" == "1" ]]; then
  rm -rf "$REPO_ROOT/target/linux-package-validate/target"
fi
mkdir -p "$PAYLOAD_ROOT/bin" "$PAYLOAD_ROOT/ebpf" "$PAYLOAD_ROOT/systemd" "$PAYLOAD_ROOT/scripts" "$OUTPUT_ROOT"

export CARGO_TARGET_DIR="$REPO_ROOT/target/linux-package-validate/target"
export RUSTUP_SKIP_UPDATE_CHECK=1
cargo build --release -p aegis-agentd -p aegis-watchdog -p aegis-updater --manifest-path "$REPO_ROOT/Cargo.toml"

ebpf_source_root="$REPO_ROOT/packaging/linux-ebpf"
if [[ -n "$LINUX_EBPF_ARTIFACT_ROOT" ]]; then
  ebpf_source_root="$LINUX_EBPF_ARTIFACT_ROOT"
fi
if [[ "$ebpf_source_root" == "$REPO_ROOT/packaging/linux-ebpf" ]]; then
  bash "$REPO_ROOT/packaging/linux-ebpf/build.sh"
fi

for required_path in \
  "$ebpf_source_root/manifest.json" \
  "$ebpf_source_root/README.md" \
  "$ebpf_source_root/file.bpf.o" \
  "$ebpf_source_root/network.bpf.o" \
  "$ebpf_source_root/process.bpf.o"; do
  [[ -f "$required_path" ]] || {
    echo "missing required ebpf artifact: $required_path" >&2
    exit 1
  }
done

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
cp -f "$ebpf_source_root/"*.bpf.o "$PAYLOAD_ROOT/ebpf/"
cp -f "$ebpf_source_root/manifest.json" "$PAYLOAD_ROOT/ebpf/manifest.json"
cp -f "$ebpf_source_root/README.md" "$PAYLOAD_ROOT/ebpf/README.md"
cp -f "$REPO_ROOT/packaging/linux/systemd/"*.service "$PAYLOAD_ROOT/systemd/"
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

python3 - <<'PY' "$REPO_ROOT" "$PAYLOAD_ROOT" "$OUTPUT_ROOT" "$package_build_json"
import json
import pathlib
import sys

repo_root = pathlib.Path(sys.argv[1])
payload_root = pathlib.Path(sys.argv[2])
output_root = pathlib.Path(sys.argv[3])
packages = json.loads(sys.argv[4])

result = {
    "payload_root": str(payload_root.relative_to(repo_root)),
    "manifest_path": str((payload_root / "manifest.json").relative_to(repo_root)),
    "output_root": str(output_root.relative_to(repo_root)),
    "deb_package": str(pathlib.Path(packages["deb_package"]).relative_to(repo_root)),
    "deb_sha256": packages["deb_sha256"],
    "rpm_package": str(pathlib.Path(packages["rpm_package"]).relative_to(repo_root)),
    "rpm_sha256": packages["rpm_sha256"],
}
print(json.dumps(result, indent=2, ensure_ascii=False))
PY
