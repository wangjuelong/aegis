#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
BUILD_DIR="$ROOT_DIR/build"
INCLUDE_DIR="$BUILD_DIR/include"
VENDORED_INCLUDE_DIR="$ROOT_DIR/include"
VMLINUX_HEADER_OVERRIDE=${AEGIS_BTF_VMLINUX_HEADER:-}

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

require_tool clang
if [[ -z "$VMLINUX_HEADER_OVERRIDE" ]]; then
  require_tool bpftool
fi

mkdir -p "$INCLUDE_DIR"
if [[ ! -f "$VENDORED_INCLUDE_DIR/bpf/bpf_helpers.h" ]]; then
  echo "missing vendored libbpf headers under $VENDORED_INCLUDE_DIR/bpf" >&2
  exit 1
fi
if [[ -n "$VMLINUX_HEADER_OVERRIDE" ]]; then
  if [[ ! -f "$VMLINUX_HEADER_OVERRIDE" ]]; then
    echo "missing AEGIS_BTF_VMLINUX_HEADER: $VMLINUX_HEADER_OVERRIDE" >&2
    exit 1
  fi
  cp "$VMLINUX_HEADER_OVERRIDE" "$INCLUDE_DIR/vmlinux.h"
else
  bpftool btf dump file /sys/kernel/btf/vmlinux format c >"$INCLUDE_DIR/vmlinux.h"
fi

ARCH=$(target_arch)
CFLAGS=(
  -O2
  -g
  -target
  bpf
  -D__TARGET_ARCH_"$ARCH"
  -I"$INCLUDE_DIR"
  -I"$VENDORED_INCLUDE_DIR"
  -I/usr/include/x86_64-linux-gnu
)

for source in "$ROOT_DIR"/src/*.bpf.c; do
  output="$ROOT_DIR/$(basename "${source%.c}").o"
  clang "${CFLAGS[@]}" -c "$source" -o "$output"
done

if command -v llvm-strip >/dev/null 2>&1; then
  llvm-strip -g "$ROOT_DIR"/*.bpf.o
fi
