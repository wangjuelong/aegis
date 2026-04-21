#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=${REPO_ROOT:-$(cd -- "$SCRIPT_DIR/../../.." && pwd)}
AEGIS_RUSTUP_TOOLCHAIN=${AEGIS_RUSTUP_TOOLCHAIN:-}

cd "$REPO_ROOT"

if [[ -n "$AEGIS_RUSTUP_TOOLCHAIN" ]]; then
  rustup run "$AEGIS_RUSTUP_TOOLCHAIN" cargo run -p aegis-core --example runtime_sdk_connector
else
  cargo run -p aegis-core --example runtime_sdk_connector
fi
