#!/usr/bin/env bash
set -euo pipefail

HOST=${AEGIS_LINUX_HOST:-192.168.1.15}
USER_NAME=${AEGIS_LINUX_USER:-ubuntu}
PASSWORD=${AEGIS_LINUX_PASSWORD:-ubuntu}
REMOTE_ROOT=${AEGIS_REMOTE_WORKDIR:-/home/${USER_NAME}/aegis-linux-ebpf}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
LOCAL_ASSET_DIR="$REPO_ROOT/packaging/linux-ebpf"

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" "rm -rf '$REMOTE_ROOT' && mkdir -p '$REMOTE_ROOT'"
sshpass -p "$PASSWORD" scp -r "${SSH_OPTS[@]}" "$LOCAL_ASSET_DIR" "$USER_NAME@$HOST:$REMOTE_ROOT/"

echo "synced linux ebpf assets to $USER_NAME@$HOST:$REMOTE_ROOT/linux-ebpf"
