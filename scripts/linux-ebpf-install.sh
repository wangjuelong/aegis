#!/usr/bin/env bash
set -euo pipefail

HOST=${AEGIS_LINUX_HOST:-192.168.1.15}
USER_NAME=${AEGIS_LINUX_USER:-ubuntu}
PASSWORD=${AEGIS_LINUX_PASSWORD:-ubuntu}
REMOTE_ROOT=${AEGIS_REMOTE_WORKDIR:-/home/${USER_NAME}/aegis-linux-ebpf}
REMOTE_ASSET_DIR=${AEGIS_REMOTE_ASSET_DIR:-/opt/aegis/ebpf}
REMOTE_PIN_ROOT=${AEGIS_REMOTE_PIN_ROOT:-/sys/fs/bpf/edr}

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" bash <<EOF
set -euo pipefail
cd "$REMOTE_ROOT/linux-ebpf"
chmod +x build.sh
./build.sh

ACTIVE_LSMS=\$(cat /sys/kernel/security/lsm 2>/dev/null || true)
if [[ ",\$ACTIVE_LSMS," != *",bpf,"* ]]; then
  echo "warning: bpf LSM is not active; bundles can load but LSM enforcement will not take effect" >&2
  echo "active lsm order: \$ACTIVE_LSMS" >&2
fi

printf '%s\n' "$PASSWORD" | sudo -S -p '' rm -rf "$REMOTE_ASSET_DIR" "$REMOTE_PIN_ROOT"
printf '%s\n' "$PASSWORD" | sudo -S -p '' install -d "$REMOTE_ASSET_DIR"
printf '%s\n' "$PASSWORD" | sudo -S -p '' cp manifest.json *.bpf.o README.md "$REMOTE_ASSET_DIR/"

printf '%s\n' "$PASSWORD" | sudo -S -p '' install -d "$REMOTE_PIN_ROOT/process" "$REMOTE_PIN_ROOT/file" "$REMOTE_PIN_ROOT/network"
printf '%s\n' "$PASSWORD" | sudo -S -p '' install -d "$REMOTE_PIN_ROOT/maps/file" "$REMOTE_PIN_ROOT/maps/network"

printf '%s\n' "$PASSWORD" | sudo -S -p '' bpftool prog loadall "$REMOTE_ASSET_DIR/process.bpf.o" "$REMOTE_PIN_ROOT/process" autoattach
printf '%s\n' "$PASSWORD" | sudo -S -p '' bpftool prog loadall "$REMOTE_ASSET_DIR/file.bpf.o" "$REMOTE_PIN_ROOT/file" pinmaps "$REMOTE_PIN_ROOT/maps/file" autoattach
printf '%s\n' "$PASSWORD" | sudo -S -p '' bpftool prog loadall "$REMOTE_ASSET_DIR/network.bpf.o" "$REMOTE_PIN_ROOT/network" pinmaps "$REMOTE_PIN_ROOT/maps/network" autoattach
EOF

echo "installed linux ebpf bundles on $USER_NAME@$HOST"
