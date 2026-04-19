#!/usr/bin/env bash
set -euo pipefail

HOST=${AEGIS_LINUX_HOST:-192.168.1.6}
USER_NAME=${AEGIS_LINUX_USER:-ubuntu}
PASSWORD=${AEGIS_LINUX_PASSWORD:-ubuntu}
REMOTE_ROOT=${AEGIS_REMOTE_TPM_WORKDIR:-/home/${USER_NAME}/aegis-linux-tpm}
REMOTE_DEVICE_PATH=${AEGIS_REMOTE_TPM_DEVICE_PATH:-/dev/tpmrm0}
REMOTE_PCRS=${AEGIS_REMOTE_TPM_MASTER_KEY_PCRS:-sha256:0,7}
REMOTE_BAD_PCRS=${AEGIS_REMOTE_TPM_BAD_PCRS:-sha256:0,8}

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" bash <<EOF
set -euo pipefail

if [ ! -e "$REMOTE_DEVICE_PATH" ]; then
  echo "missing TPM device: $REMOTE_DEVICE_PATH" >&2
  exit 1
fi

for tool in \
  tpm2_createprimary \
  tpm2_createpolicy \
  tpm2_create \
  tpm2_load \
  tpm2_startauthsession \
  tpm2_policypcr \
  tpm2_unseal
do
  if ! command -v "\$tool" >/dev/null 2>&1; then
    echo "missing TPM tool: \$tool" >&2
    exit 1
  fi
done

sudo_tpm() {
  printf '%s\n' "$PASSWORD" | sudo -S -p '' env TPM2TOOLS_TCTI="device:$REMOTE_DEVICE_PATH" "\$@"
}

WORKDIR="$REMOTE_ROOT/policy-verify"
rm -rf "\$WORKDIR"
mkdir -p "\$WORKDIR"

cleanup() {
  if command -v tpm2_flushcontext >/dev/null 2>&1; then
    sudo_tpm tpm2_flushcontext "\$WORKDIR/good.session" >/dev/null 2>&1 || true
    sudo_tpm tpm2_flushcontext "\$WORKDIR/bad.session" >/dev/null 2>&1 || true
    sudo_tpm tpm2_flushcontext "\$WORKDIR/object.ctx" >/dev/null 2>&1 || true
    sudo_tpm tpm2_flushcontext "\$WORKDIR/primary.ctx" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

printf '0123456789abcdef0123456789abcdef' > "\$WORKDIR/secret.bin"

sudo_tpm tpm2_createprimary -C o -c "\$WORKDIR/primary.ctx" >/dev/null
sudo_tpm tpm2_createpolicy --policy-pcr -l "$REMOTE_PCRS" -L "\$WORKDIR/policy.dat" >/dev/null
sudo_tpm tpm2_create \
  -C "\$WORKDIR/primary.ctx" \
  -L "\$WORKDIR/policy.dat" \
  -u "\$WORKDIR/object.pub" \
  -r "\$WORKDIR/object.priv" \
  -i "\$WORKDIR/secret.bin" >/dev/null
sudo_tpm tpm2_load \
  -C "\$WORKDIR/primary.ctx" \
  -u "\$WORKDIR/object.pub" \
  -r "\$WORKDIR/object.priv" \
  -c "\$WORKDIR/object.ctx" >/dev/null

sudo_tpm tpm2_startauthsession --policy-session -S "\$WORKDIR/good.session" >/dev/null
sudo_tpm tpm2_policypcr -S "\$WORKDIR/good.session" -l "$REMOTE_PCRS" >/dev/null
good_secret=\$(sudo_tpm tpm2_unseal -c "\$WORKDIR/object.ctx" -p session:"\$WORKDIR/good.session")
if [ "\$good_secret" != "0123456789abcdef0123456789abcdef" ]; then
  echo "unexpected secret from policy session unseal" >&2
  exit 1
fi

sudo_tpm tpm2_startauthsession --policy-session -S "\$WORKDIR/bad.session" >/dev/null
sudo_tpm tpm2_policypcr -S "\$WORKDIR/bad.session" -l "$REMOTE_BAD_PCRS" >/dev/null
if sudo_tpm tpm2_unseal -c "\$WORKDIR/object.ctx" -p session:"\$WORKDIR/bad.session" >/dev/null 2>&1; then
  echo "expected policy session unseal with wrong PCRs to fail" >&2
  exit 1
fi

echo "linux tpm policy verification passed"
EOF
