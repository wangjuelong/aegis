#!/usr/bin/env bash
set -euo pipefail

STATE_ROOT=${AEGIS_LINUX_STATE_ROOT:-/var/lib/aegis}
IDENTITY_ROOT=${AEGIS_LINUX_IDENTITY_ROOT:-$STATE_ROOT/identity}
BUNDLE_ROOT=${AEGIS_LINUX_ATTESTATION_BUNDLE_ROOT:-$STATE_ROOT/attestation/current}
TPM_DEVICE=${AEGIS_LINUX_TPM_DEVICE_PATH:-/dev/tpmrm0}
PCRS=${AEGIS_LINUX_TPM_ATTESTATION_PCRS:-sha256:0,7}
AGENT_ID=${AEGIS_AGENT_ID:-linux-agent}
TENANT_ID=${AEGIS_TENANT_ID:-tenant-a}
NONCE_HEX=${AEGIS_ATTESTATION_NONCE_HEX:-$(openssl rand -hex 16)}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required tool: $1" >&2
    exit 1
  }
}

for tool in tpm2_createek tpm2_createak tpm2_quote openssl python3 xxd; do
  require_tool "$tool"
done

if [[ ! -e "$TPM_DEVICE" ]]; then
  echo "missing TPM device: $TPM_DEVICE" >&2
  exit 1
fi

mkdir -p "$IDENTITY_ROOT" "$BUNDLE_ROOT"

DEVICE_KEY="$IDENTITY_ROOT/device.key"
DEVICE_CSR="$IDENTITY_ROOT/device.csr"
QUALIFICATION_PATH="$BUNDLE_ROOT/qualification.bin"
EK_CTX="$BUNDLE_ROOT/ek.ctx"
EK_PUB="$BUNDLE_ROOT/ek.pub"
AK_CTX="$BUNDLE_ROOT/ak.ctx"
AK_PUB="$BUNDLE_ROOT/ak.pub"
AK_PRIV="$BUNDLE_ROOT/ak.priv"
AK_NAME="$BUNDLE_ROOT/ak.name"
QUOTE_MSG="$BUNDLE_ROOT/quote.msg"
QUOTE_SIG="$BUNDLE_ROOT/quote.sig"
QUOTE_PCR="$BUNDLE_ROOT/quote.pcr"
BUNDLE_JSON="$BUNDLE_ROOT/bundle.json"

printf '%s' "$NONCE_HEX" | xxd -r -p >"$QUALIFICATION_PATH"

if [[ ! -f "$DEVICE_KEY" ]]; then
  openssl genpkey -algorithm ED25519 -out "$DEVICE_KEY" >/dev/null 2>&1
fi

openssl req \
  -new \
  -key "$DEVICE_KEY" \
  -subj "/CN=${AGENT_ID}/O=${TENANT_ID}" \
  -out "$DEVICE_CSR" >/dev/null 2>&1

export TPM2TOOLS_TCTI="device:$TPM_DEVICE"
tpm2_createek -c "$EK_CTX" -u "$EK_PUB" >/dev/null
tpm2_createak \
  -C "$EK_CTX" \
  -c "$AK_CTX" \
  -u "$AK_PUB" \
  -r "$AK_PRIV" \
  -n "$AK_NAME" \
  -G rsa \
  -g sha256 \
  -s rsassa >/dev/null
tpm2_quote \
  -c "$AK_CTX" \
  -l "$PCRS" \
  -q "$QUALIFICATION_PATH" \
  -m "$QUOTE_MSG" \
  -s "$QUOTE_SIG" \
  -o "$QUOTE_PCR" >/dev/null

python3 - <<'PY' "$BUNDLE_JSON" "$AGENT_ID" "$TENANT_ID" "$PCRS" "$DEVICE_CSR" "$AK_PUB" "$QUOTE_MSG" "$QUOTE_SIG" "$QUOTE_PCR" "$QUALIFICATION_PATH"
import hashlib
import json
import os
import sys
from pathlib import Path

bundle_json, agent_id, tenant_id, pcrs, device_csr, ak_pub, quote_msg, quote_sig, quote_pcr, qualification = sys.argv[1:]

def digest(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

payload = {
    "schema_version": 1,
    "agent_id": agent_id,
    "tenant_id": tenant_id,
    "pcrs": pcrs,
    "device_csr_path": device_csr,
    "ak_public_path": ak_pub,
    "quote_message_path": quote_msg,
    "quote_signature_path": quote_sig,
    "quote_pcr_path": quote_pcr,
    "qualification_path": qualification,
    "digests": {
        "device_csr_sha256": digest(device_csr),
        "ak_public_sha256": digest(ak_pub),
        "quote_message_sha256": digest(quote_msg),
        "quote_signature_sha256": digest(quote_sig),
        "quote_pcr_sha256": digest(quote_pcr),
        "qualification_sha256": digest(qualification),
    },
}
Path(bundle_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
PY

printf '%s\n' "$BUNDLE_JSON"
