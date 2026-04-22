#!/usr/bin/env bash
set -euo pipefail

STATE_ROOT=${AEGIS_LINUX_STATE_ROOT:-/var/lib/aegis}
IDENTITY_ROOT=${AEGIS_LINUX_IDENTITY_ROOT:-$STATE_ROOT/identity}
BUNDLE_ROOT=${AEGIS_LINUX_ATTESTATION_BUNDLE_ROOT:-$STATE_ROOT/attestation/current}
VERIFIER_ROOT=${AEGIS_LINUX_ATTESTATION_VERIFIER_ROOT:-$STATE_ROOT/attestation/verifier}
TRUST_ROOT_KEY=${AEGIS_LINUX_ATTESTATION_CA_KEY:-$VERIFIER_ROOT/ca.key}
TRUST_ROOT_CERT=${AEGIS_LINUX_ATTESTATION_CA_CERT:-$VERIFIER_ROOT/ca.crt}
QUALIFICATION_PATH_OVERRIDE=${AEGIS_LINUX_ATTESTATION_QUALIFICATION_PATH:-}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required tool: $1" >&2
    exit 1
  }
}

for tool in tpm2_checkquote openssl python3; do
  require_tool "$tool"
done

mkdir -p "$IDENTITY_ROOT" "$VERIFIER_ROOT"

BUNDLE_JSON="$BUNDLE_ROOT/bundle.json"
if [[ ! -f "$BUNDLE_JSON" ]]; then
  echo "missing attestation bundle: $BUNDLE_JSON" >&2
  exit 1
fi

DEVICE_CERT="$IDENTITY_ROOT/device.crt"
RECEIPT_PATH="$BUNDLE_ROOT/verified-receipt.json"

if [[ ! -f "$TRUST_ROOT_KEY" || ! -f "$TRUST_ROOT_CERT" ]]; then
  openssl req \
    -x509 \
    -newkey rsa:3072 \
    -nodes \
    -keyout "$TRUST_ROOT_KEY" \
    -out "$TRUST_ROOT_CERT" \
    -days 3650 \
    -subj "/CN=Aegis Linux Attestation Local CA" >/dev/null 2>&1
fi

python3 - <<'PY' "$BUNDLE_JSON" "$TRUST_ROOT_CERT" "$TRUST_ROOT_KEY" "$DEVICE_CERT" "$RECEIPT_PATH" "$QUALIFICATION_PATH_OVERRIDE"
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

bundle_path, ca_cert, ca_key, device_cert, receipt_path, qualification_override = sys.argv[1:]
bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))

qualification_path = qualification_override or bundle["qualification_path"]
device_csr_path = bundle["device_csr_path"]
ak_public_path = bundle["ak_public_path"]
quote_message_path = bundle["quote_message_path"]
quote_signature_path = bundle["quote_signature_path"]
quote_pcr_path = bundle["quote_pcr_path"]

subprocess.run(
    [
        "openssl",
        "x509",
        "-req",
        "-in",
        device_csr_path,
        "-CA",
        ca_cert,
        "-CAkey",
        ca_key,
        "-CAcreateserial",
        "-out",
        device_cert,
        "-days",
        "365",
    ],
    check=True,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

subprocess.run(
    ["openssl", "verify", "-CAfile", ca_cert, device_cert],
    check=True,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

subprocess.run(
    [
        "tpm2_checkquote",
        "-u",
        ak_public_path,
        "-m",
        quote_message_path,
        "-s",
        quote_signature_path,
        "-f",
        quote_pcr_path,
        "-g",
        "sha256",
        "-q",
        qualification_path,
    ],
    check=True,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

fingerprint = subprocess.check_output(
    ["openssl", "x509", "-in", device_cert, "-fingerprint", "-sha256", "-noout"],
    text=True,
).strip().split("=", 1)[1].replace(":", "").lower()

payload = {
    "schema_version": 1,
    "verified": True,
    "verified_at_ms": int(time.time() * 1000),
    "trust_root_cert": ca_cert,
    "device_certificate_path": device_cert,
    "device_certificate_sha256": hashlib.sha256(Path(device_cert).read_bytes()).hexdigest(),
    "device_certificate_thumbprint": fingerprint,
    "ak_public_sha256": hashlib.sha256(Path(ak_public_path).read_bytes()).hexdigest(),
    "quote_message_sha256": hashlib.sha256(Path(quote_message_path).read_bytes()).hexdigest(),
    "quote_signature_sha256": hashlib.sha256(Path(quote_signature_path).read_bytes()).hexdigest(),
    "quote_pcr_sha256": hashlib.sha256(Path(quote_pcr_path).read_bytes()).hexdigest(),
    "qualification_sha256": hashlib.sha256(Path(qualification_path).read_bytes()).hexdigest(),
    "agent_id": bundle["agent_id"],
    "tenant_id": bundle["tenant_id"],
    "pcrs": bundle["pcrs"],
}
Path(receipt_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
PY

printf '%s\n' "$RECEIPT_PATH"
