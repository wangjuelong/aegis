#!/usr/bin/env bash
set -euo pipefail

HOST=${AEGIS_LINUX_HOST:-192.168.1.6}
USER_NAME=${AEGIS_LINUX_USER:-ubuntu}
PASSWORD=${AEGIS_LINUX_PASSWORD:-ubuntu}
REMOTE_ROOT=${AEGIS_REMOTE_TPM_WORKDIR:-/home/${USER_NAME}/aegis-linux-tpm}
REMOTE_DEVICE_PATH=${AEGIS_REMOTE_TPM_DEVICE_PATH:-/dev/tpmrm0}
REMOTE_PCRS=${AEGIS_REMOTE_TPM_ATTESTATION_PCRS:-sha256:0,7}

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" bash <<EOF
set -euo pipefail

if [ ! -e "$REMOTE_DEVICE_PATH" ]; then
  echo "missing TPM device: $REMOTE_DEVICE_PATH" >&2
  exit 1
fi

for tool in tpm2_createek tpm2_createak tpm2_quote tpm2_checkquote; do
  if ! command -v "\$tool" >/dev/null 2>&1; then
    echo "missing TPM tool: \$tool" >&2
    exit 1
  fi
done

sudo_tpm() {
  printf '%s\n' "$PASSWORD" | sudo -S -p '' env TPM2TOOLS_TCTI="device:$REMOTE_DEVICE_PATH" "\$@"
}

WORKDIR="$REMOTE_ROOT/quote-verify"
rm -rf "\$WORKDIR"
mkdir -p "\$WORKDIR"

cleanup() {
  if command -v tpm2_flushcontext >/dev/null 2>&1; then
    sudo_tpm tpm2_flushcontext "\$WORKDIR/ak.ctx" >/dev/null 2>&1 || true
    sudo_tpm tpm2_flushcontext "\$WORKDIR/ek.ctx" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

printf 'aegis-attestation-nonce' > "\$WORKDIR/nonce.bin"
printf 'aegis-attestation-wrong-nonce' > "\$WORKDIR/bad-nonce.bin"

sudo_tpm tpm2_createek -c "\$WORKDIR/ek.ctx" -u "\$WORKDIR/ek.pub"
sudo_tpm tpm2_createak \
  -C "\$WORKDIR/ek.ctx" \
  -c "\$WORKDIR/ak.ctx" \
  -u "\$WORKDIR/ak.pub" \
  -r "\$WORKDIR/ak.priv" \
  -n "\$WORKDIR/ak.name" \
  -G rsa \
  -g sha256 \
  -s rsassa
sudo_tpm tpm2_quote \
  -c "\$WORKDIR/ak.ctx" \
  -l "$REMOTE_PCRS" \
  -q "\$WORKDIR/nonce.bin" \
  -m "\$WORKDIR/quote.msg" \
  -s "\$WORKDIR/quote.sig" \
  -o "\$WORKDIR/quote.pcr"
sudo_tpm tpm2_checkquote \
  -u "\$WORKDIR/ak.pub" \
  -m "\$WORKDIR/quote.msg" \
  -s "\$WORKDIR/quote.sig" \
  -f "\$WORKDIR/quote.pcr" \
  -g sha256 \
  -q "\$WORKDIR/nonce.bin" >/dev/null

if sudo_tpm tpm2_checkquote \
  -u "\$WORKDIR/ak.pub" \
  -m "\$WORKDIR/quote.msg" \
  -s "\$WORKDIR/quote.sig" \
  -f "\$WORKDIR/quote.pcr" \
  -g sha256 \
  -q "\$WORKDIR/bad-nonce.bin" >/dev/null 2>&1; then
  echo "expected quote verification with wrong nonce to fail" >&2
  exit 1
fi

echo "linux tpm quote verification passed"
EOF
