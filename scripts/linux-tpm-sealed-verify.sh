#!/usr/bin/env bash
set -euo pipefail

HOST=${AEGIS_LINUX_HOST:-192.168.1.15}
USER_NAME=${AEGIS_LINUX_USER:-ubuntu}
PASSWORD=${AEGIS_LINUX_PASSWORD:-ubuntu}
REMOTE_ROOT=${AEGIS_REMOTE_TPM_WORKDIR:-/home/${USER_NAME}/aegis-linux-tpm}
REMOTE_DEVICE_PATH=${AEGIS_REMOTE_TPM_DEVICE_PATH:-/dev/tpmrm0}

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" bash <<EOF
set -euo pipefail

if [ ! -e "$REMOTE_DEVICE_PATH" ]; then
  echo "missing TPM device: $REMOTE_DEVICE_PATH" >&2
  exit 1
fi

for tool in tpm2_createprimary tpm2_create tpm2_load tpm2_unseal; do
  if ! command -v "\$tool" >/dev/null 2>&1; then
    echo "missing TPM tool: \$tool" >&2
    exit 1
  fi
done

export TPM2TOOLS_TCTI="device:$REMOTE_DEVICE_PATH"

WORKDIR="$REMOTE_ROOT/sealed-verify"
rm -rf "\$WORKDIR"
mkdir -p "\$WORKDIR"

cleanup() {
  if command -v tpm2_flushcontext >/dev/null 2>&1; then
    tpm2_flushcontext "\$WORKDIR/object.ctx" >/dev/null 2>&1 || true
    tpm2_flushcontext "\$WORKDIR/primary.ctx" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

python3 - <<'PY' > "\$WORKDIR/secret.bin"
import os
import sys
sys.stdout.buffer.write(os.urandom(32))
PY

tpm2_createprimary -C o -c "\$WORKDIR/primary.ctx"
tpm2_create \
  -C "\$WORKDIR/primary.ctx" \
  -G keyedhash \
  -u "\$WORKDIR/master-key.pub" \
  -r "\$WORKDIR/master-key.priv" \
  -i "\$WORKDIR/secret.bin"
tpm2_load \
  -C "\$WORKDIR/primary.ctx" \
  -u "\$WORKDIR/master-key.pub" \
  -r "\$WORKDIR/master-key.priv" \
  -c "\$WORKDIR/object.ctx"
tpm2_unseal -c "\$WORKDIR/object.ctx" > "\$WORKDIR/unsealed.bin"

cmp "\$WORKDIR/secret.bin" "\$WORKDIR/unsealed.bin"
echo "linux tpm sealed-object verification passed"
EOF
