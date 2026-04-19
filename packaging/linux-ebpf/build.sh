#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
BUILD_DIR="$ROOT_DIR/build"
INCLUDE_DIR="$BUILD_DIR/include"

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required tool: $1" >&2
    exit 1
  }
}

target_arch() {
  case "$(uname -m)" in
    x86_64) echo "x86" ;;
    aarch64|arm64) echo "arm64" ;;
    *)
      echo "unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

require_tool bpftool
require_tool clang

mkdir -p "$INCLUDE_DIR"
bpftool btf dump file /sys/kernel/btf/vmlinux format c >"$INCLUDE_DIR/vmlinux.h"

ARCH=$(target_arch)
CFLAGS=(
  -O2
  -g
  -target
  bpf
  -D__TARGET_ARCH_"$ARCH"
  -I"$INCLUDE_DIR"
  -I/usr/include/x86_64-linux-gnu
)

for source in "$ROOT_DIR"/src/*.bpf.c; do
  output="$ROOT_DIR/$(basename "${source%.c}").o"
  clang "${CFLAGS[@]}" -c "$source" -o "$output"
done

if command -v llvm-strip >/dev/null 2>&1; then
  llvm-strip -g "$ROOT_DIR"/*.bpf.o
fi
