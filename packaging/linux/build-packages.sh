#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PAYLOAD_ROOT=${PAYLOAD_ROOT:-}
OUTPUT_ROOT=${OUTPUT_ROOT:-"$SCRIPT_DIR/out"}
VERSION=${VERSION:-0.1.0}
RELEASE=${RELEASE:-1}
PACKAGE_NAME=${PACKAGE_NAME:-aegis-sensor}
MANIFEST_PATH=${MANIFEST_PATH:-}
BUNDLE_ROOT=/usr/lib/aegis/package-bundle

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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --payload-root)
      PAYLOAD_ROOT=$2
      shift 2
      ;;
    --output-root)
      OUTPUT_ROOT=$2
      shift 2
      ;;
    --version)
      VERSION=$2
      shift 2
      ;;
    --release)
      RELEASE=$2
      shift 2
      ;;
    --manifest)
      MANIFEST_PATH=$2
      shift 2
      ;;
    *)
      echo "unsupported argument: $1" >&2
      exit 1
      ;;
  esac
done

require_command python3
require_command dpkg-deb
require_command rpmbuild
require_command sha256sum
require_command tar

[[ -n "$PAYLOAD_ROOT" ]] || {
  echo "--payload-root is required" >&2
  exit 1
}

PAYLOAD_ROOT=$(resolve_existing_path "$PAYLOAD_ROOT" "payload root")
if [[ -z "$MANIFEST_PATH" ]]; then
  MANIFEST_PATH="$PAYLOAD_ROOT/manifest.json"
fi
MANIFEST_PATH=$(resolve_existing_path "$MANIFEST_PATH" "install manifest")
OUTPUT_ROOT=$(mkdir -p "$OUTPUT_ROOT" && cd "$OUTPUT_ROOT" >/dev/null 2>&1 && pwd)

tmp_root=$(mktemp -d)
deb_stage="$tmp_root/deb/${PACKAGE_NAME}_${VERSION}-${RELEASE}_amd64"
rpm_topdir="$tmp_root/rpm"
bundle_archive="$tmp_root/${PACKAGE_NAME}-bundle.tar.gz"
deb_package_path="$OUTPUT_ROOT/${PACKAGE_NAME}_${VERSION}-${RELEASE}_amd64.deb"

cleanup() {
  rm -rf "$tmp_root"
}
trap cleanup EXIT

install -d "$deb_stage/DEBIAN" "$deb_stage$BUNDLE_ROOT" "$rpm_topdir"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
cp -a "$PAYLOAD_ROOT/." "$deb_stage$BUNDLE_ROOT/"

cat >"$deb_stage/DEBIAN/control" <<EOF
Package: $PACKAGE_NAME
Version: ${VERSION}-${RELEASE}
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Aegis
Description: Aegis Linux sensor bundle
EOF

cat >"$deb_stage/DEBIAN/postinst" <<EOF
#!/usr/bin/env bash
set -euo pipefail
"$BUNDLE_ROOT/scripts/install.sh" --payload-root "$BUNDLE_ROOT" --manifest "$BUNDLE_ROOT/manifest.json"
EOF

cat >"$deb_stage/DEBIAN/prerm" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == "remove" || "\${1:-}" == "purge" ]]; then
  "$BUNDLE_ROOT/scripts/uninstall.sh" --manifest "$BUNDLE_ROOT/manifest.json" || true
fi
EOF

chmod 0755 "$deb_stage/DEBIAN/postinst" "$deb_stage/DEBIAN/prerm"
dpkg-deb --build "$deb_stage" "$deb_package_path" >/dev/null

tar -C "$PAYLOAD_ROOT" -czf "$bundle_archive" .
cp "$bundle_archive" "$rpm_topdir/SOURCES/${PACKAGE_NAME}-bundle.tar.gz"

cat >"$rpm_topdir/SPECS/$PACKAGE_NAME.spec" <<EOF
%global __strip /bin/true
%global debug_package %{nil}
Name: $PACKAGE_NAME
Version: $VERSION
Release: $RELEASE%{?dist}
Summary: Aegis Linux sensor bundle
License: Apache-2.0
BuildArch: x86_64
Source0: ${PACKAGE_NAME}-bundle.tar.gz

%description
Aegis Linux sensor package bundle.

%prep
rm -rf package-bundle
mkdir -p package-bundle
tar -xzf %{SOURCE0} -C package-bundle

%install
mkdir -p %{buildroot}$BUNDLE_ROOT
cp -a package-bundle/. %{buildroot}$BUNDLE_ROOT/

%post
$BUNDLE_ROOT/scripts/install.sh --payload-root $BUNDLE_ROOT --manifest $BUNDLE_ROOT/manifest.json

%preun
if [ \$1 -eq 0 ]; then
  $BUNDLE_ROOT/scripts/uninstall.sh --manifest $BUNDLE_ROOT/manifest.json || true
fi

%files
$BUNDLE_ROOT
EOF

rpmbuild \
  --define "_topdir $rpm_topdir" \
  -bb "$rpm_topdir/SPECS/$PACKAGE_NAME.spec" >/dev/null

rpm_package_path=$(find "$rpm_topdir/RPMS" -type f -name "${PACKAGE_NAME}-*.rpm" | head -n 1)
cp "$rpm_package_path" "$OUTPUT_ROOT/"
rpm_package_path="$OUTPUT_ROOT/$(basename -- "$rpm_package_path")"

python3 - <<'PY' "$deb_package_path" "$rpm_package_path"
import hashlib
import json
import pathlib
import sys

def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

deb_path = pathlib.Path(sys.argv[1])
rpm_path = pathlib.Path(sys.argv[2])
print(json.dumps({
    "deb_package": str(deb_path),
    "deb_sha256": sha256(deb_path),
    "rpm_package": str(rpm_path),
    "rpm_sha256": sha256(rpm_path),
}, indent=2, ensure_ascii=False))
PY
