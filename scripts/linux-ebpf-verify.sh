#!/usr/bin/env bash
set -euo pipefail

HOST=${AEGIS_LINUX_HOST:-192.168.1.15}
USER_NAME=${AEGIS_LINUX_USER:-ubuntu}
PASSWORD=${AEGIS_LINUX_PASSWORD:-ubuntu}
REMOTE_PIN_ROOT=${AEGIS_REMOTE_PIN_ROOT:-/sys/fs/bpf/edr}

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USER_NAME@$HOST" bash <<EOF
set -euo pipefail

ACTIVE_LSMS=\$(cat /sys/kernel/security/lsm 2>/dev/null || true)
if [[ ",\$ACTIVE_LSMS," != *",bpf,"* ]]; then
  echo "bpf LSM is not active on $USER_NAME@$HOST; refusing to run enforcement smoke tests" >&2
  echo "active lsm order: \$ACTIVE_LSMS" >&2
  echo "expected kernel cmdline to include: lsm=lockdown,capability,bpf,landlock,yama,apparmor,ima,evm" >&2
  exit 1
fi

inode_key_hex() {
  python3 - "\$1" <<'PY'
import struct, sys
ino = int(sys.argv[1])
print(" ".join(f"{byte:02x}" for byte in struct.pack("<Q", ino)))
PY
}

u64_one_hex() {
  python3 - <<'PY'
import struct
print(" ".join(f"{byte:02x}" for byte in struct.pack("<Q", 1)))
PY
}

ipv4_key_hex() {
  python3 - "\$1" <<'PY'
import socket, sys
print(" ".join(f"{byte:02x}" for byte in socket.inet_aton(sys.argv[1])))
PY
}

VALUE_HEX=\$(u64_one_hex)

printf '%s\n' "$PASSWORD" | sudo -S -p '' find "$REMOTE_PIN_ROOT" -maxdepth 3 | sed -n '1,120p'
printf '%s\n' "$PASSWORD" | sudo -S -p '' bpftool link show | sed -n '1,120p'
echo "active lsm order: \$ACTIVE_LSMS"

EXEC_FILE=/tmp/aegis-ebpf-blocked.bin
cp /bin/true "\$EXEC_FILE"
chmod +x "\$EXEC_FILE"
read -r _ EXEC_INO < <(stat -c '%d %i' "\$EXEC_FILE")
EXEC_KEY_HEX=\$(inode_key_hex "\$EXEC_INO")
printf '%s\n' "$PASSWORD" | sudo -S -p '' bpftool map update pinned "$REMOTE_PIN_ROOT/maps/file/blocked_exec_inodes" key hex \$EXEC_KEY_HEX value hex \$VALUE_HEX any
if "\$EXEC_FILE" >/dev/null 2>&1; then
  echo "expected exec block to deny \$EXEC_FILE" >&2
  exit 1
fi
printf '%s\n' "$PASSWORD" | sudo -S -p '' bpftool map delete pinned "$REMOTE_PIN_ROOT/maps/file/blocked_exec_inodes" key hex \$EXEC_KEY_HEX

PROTECTED_FILE=/tmp/aegis-ebpf-protected.txt
echo "aegis" >"\$PROTECTED_FILE"
read -r _ FILE_INO < <(stat -c '%d %i' "\$PROTECTED_FILE")
FILE_KEY_HEX=\$(inode_key_hex "\$FILE_INO")
printf '%s\n' "$PASSWORD" | sudo -S -p '' bpftool map update pinned "$REMOTE_PIN_ROOT/maps/file/protected_inodes" key hex \$FILE_KEY_HEX value hex \$VALUE_HEX any
if cat "\$PROTECTED_FILE" >/dev/null 2>&1; then
  echo "expected file protection to deny open on \$PROTECTED_FILE" >&2
  exit 1
fi
printf '%s\n' "$PASSWORD" | sudo -S -p '' bpftool map delete pinned "$REMOTE_PIN_ROOT/maps/file/protected_inodes" key hex \$FILE_KEY_HEX

SERVER_PID=
cleanup() {
  if [ -n "\${SERVER_PID:-}" ]; then
    kill "\$SERVER_PID" 2>/dev/null || true
    wait "\$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

python3 -m http.server 18080 --bind 127.0.0.1 >/tmp/aegis-ebpf-http.log 2>&1 &
SERVER_PID=\$!
sleep 1
curl -fsS http://127.0.0.1:18080 >/dev/null

IPV4_KEY_HEX=\$(ipv4_key_hex 127.0.0.1)
printf '%s\n' "$PASSWORD" | sudo -S -p '' bpftool map update pinned "$REMOTE_PIN_ROOT/maps/network/blocked_ipv4" key hex \$IPV4_KEY_HEX value hex \$VALUE_HEX any
if curl -fsS http://127.0.0.1:18080 >/dev/null 2>&1; then
  echo "expected network block to deny loopback connect" >&2
  exit 1
fi
printf '%s\n' "$PASSWORD" | sudo -S -p '' bpftool map delete pinned "$REMOTE_PIN_ROOT/maps/network/blocked_ipv4" key hex \$IPV4_KEY_HEX

echo "linux ebpf verification passed"
EOF
