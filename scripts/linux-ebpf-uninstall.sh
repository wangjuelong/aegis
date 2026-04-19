#!/usr/bin/env bash
set -euo pipefail

HOST=${AEGIS_LINUX_HOST:-192.168.1.6}
USER_NAME=${AEGIS_LINUX_USER:-ubuntu}
PASSWORD=${AEGIS_LINUX_PASSWORD:-ubuntu}
REMOTE_ASSET_DIR=${AEGIS_REMOTE_ASSET_DIR:-/opt/aegis/ebpf}
REMOTE_PIN_ROOT=${AEGIS_REMOTE_PIN_ROOT:-/sys/fs/bpf/edr}

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" "printf '%s\n' '$PASSWORD' | sudo -S -p '' rm -rf '$REMOTE_ASSET_DIR' '$REMOTE_PIN_ROOT'"

echo "removed linux ebpf assets from $USER_NAME@$HOST"
