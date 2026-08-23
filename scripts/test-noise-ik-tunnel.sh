#!/usr/bin/env bash
# Privileged end-to-end check for the committed Noise-IK encrypted V2 path.
set -Eeuo pipefail

CLIENT_NS="cn-noise-client"
SERVER_NS="cn-noise-server"
CLIENT_VETH="cn-noise-client-veth"
SERVER_VETH="cn-noise-server-veth"
CLIENT_PID=""
SERVER_PID=""
CAPTURE_PID=""
LOG_DIR=""
CURRENT_STAGE="initialization"
REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

cleanup() {
  local status=$?
  set +e
  for pid in "$CAPTURE_PID" "$CLIENT_PID" "$SERVER_PID"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill -INT "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
    fi
  done
  ip netns delete "$CLIENT_NS" 2>/dev/null
  ip netns delete "$SERVER_NS" 2>/dev/null
  if (( status != 0 )); then
    echo "FAILED during: $CURRENT_STAGE" >&2
  fi
  [[ -n "$LOG_DIR" ]] && echo "Logs: $LOG_DIR"
  exit "$status"
}
trap cleanup EXIT

run() { echo "+ $*"; "$@"; }
require() { command -v "$1" >/dev/null || { echo "Missing command: $1" >&2; exit 1; }; }

if (( EUID != 0 )); then
  echo "Run explicitly with sudo: sudo scripts/test-noise-ik-tunnel.sh" >&2
  exit 1
fi
for command in ip python3 ping grep sed mktemp tr; do require "$command"; done
for namespace in "$CLIENT_NS" "$SERVER_NS"; do
  if ip netns list | awk '{ print $1 }' | grep -Fxq "$namespace"; then
    echo "Refusing to use existing namespace: $namespace" >&2
    exit 1
  fi
done
if [[ ! -x "$REPO_ROOT/target/debug/crabnet" || ! -x "$REPO_ROOT/target/debug/generate_noise_keys" ]]; then
  echo "Build binaries as your normal user first: cargo build --bins" >&2
  exit 1
fi

LOG_DIR="$(mktemp -d -t crabnet-noise-test.XXXXXX)"
KEY_DIR="$LOG_DIR/keys"
mkdir "$KEY_DIR"
run "$REPO_ROOT/target/debug/generate_noise_keys" \
  --client-private "$KEY_DIR/client.key" --client-public "$KEY_DIR/client.pub" \
  --server-private "$KEY_DIR/server.key" --server-public "$KEY_DIR/server.pub"
CLIENT_PUBLIC="$(tr -d '\n' < "$KEY_DIR/client.pub")"
SERVER_PUBLIC="$(tr -d '\n' < "$KEY_DIR/server.pub")"

cat > "$LOG_DIR/server.toml" <<EOF
log_level = "debug"
[mode]
type = "server"
bind_addr = "192.0.2.2:51821"
[tun]
name = "crabnet0"
address = "10.0.0.1"
prefix_len = 24
mtu = 1400
[security]
mode = "noise_ik"
private_key_path = "$KEY_DIR/server.key"
allowed_client_public_keys = ["$CLIENT_PUBLIC"]
EOF
cat > "$LOG_DIR/client.toml" <<EOF
log_level = "debug"
[mode]
type = "client"
bind_addr = "192.0.2.1:51820"
server_addr = "192.0.2.2:51821"
[tun]
name = "crabnet0"
address = "10.0.0.2"
prefix_len = 24
mtu = 1400
[security]
mode = "noise_ik"
private_key_path = "$KEY_DIR/client.key"
server_public_key = "$SERVER_PUBLIC"
EOF

CURRENT_STAGE="creating isolated namespaces"
run ip netns add "$CLIENT_NS"
run ip netns add "$SERVER_NS"
run ip link add "$CLIENT_VETH" type veth peer name "$SERVER_VETH"
run ip link set "$CLIENT_VETH" netns "$CLIENT_NS"
run ip link set "$SERVER_VETH" netns "$SERVER_NS"
run ip -n "$CLIENT_NS" address add 192.0.2.1/24 dev "$CLIENT_VETH"
run ip -n "$SERVER_NS" address add 192.0.2.2/24 dev "$SERVER_VETH"
for namespace in "$CLIENT_NS" "$SERVER_NS"; do run ip -n "$namespace" link set lo up; done
run ip -n "$CLIENT_NS" link set "$CLIENT_VETH" up
run ip -n "$SERVER_NS" link set "$SERVER_VETH" up
run ip netns exec "$CLIENT_NS" ping -c 1 -W 2 192.0.2.2

CURRENT_STAGE="starting committed Noise-IK peers"
ip netns exec "$SERVER_NS" "$REPO_ROOT/target/debug/crabnet" --config-path "$LOG_DIR/server.toml" >"$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 0.1
ip netns exec "$CLIENT_NS" "$REPO_ROOT/target/debug/crabnet" --config-path "$LOG_DIR/client.toml" >"$LOG_DIR/client.log" 2>&1 &
CLIENT_PID=$!
for _ in {1..100}; do
  if ! kill -0 "$CLIENT_PID" 2>/dev/null || ! kill -0 "$SERVER_PID" 2>/dev/null; then
    sed -n '1,160p' "$LOG_DIR/client.log" >&2
    sed -n '1,160p' "$LOG_DIR/server.log" >&2
    exit 1
  fi
  if ip -n "$CLIENT_NS" link show crabnet0 >/dev/null 2>&1 && ip -n "$SERVER_NS" link show crabnet0 >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
run ip -n "$CLIENT_NS" link show crabnet0
run ip -n "$SERVER_NS" link show crabnet0

CURRENT_STAGE="proving encrypted packet delivery at the MTU boundary"
run ip netns exec "$CLIENT_NS" ping -c 3 -W 2 -I 10.0.0.2 -s 1372 10.0.0.1
if ip netns exec "$CLIENT_NS" ping -c 1 -W 1 -I 10.0.0.2 -s 1373 10.0.0.1; then
  echo "MTU-plus-one encrypted packet unexpectedly succeeded" >&2
  exit 1
fi

CURRENT_STAGE="dropping malformed encrypted datagram without ending the session"
run ip netns exec "$CLIENT_NS" python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b"not-a-v2-data-frame", ("192.0.2.2", 51821))'
sleep 0.2
run grep -F "dropping malformed encrypted datagram" "$LOG_DIR/server.log"
run ip netns exec "$CLIENT_NS" ping -c 2 -W 2 -I 10.0.0.2 10.0.0.1

CURRENT_STAGE="graceful shutdown"
run kill -INT "$CLIENT_PID"
run kill -INT "$SERVER_PID"
run wait "$CLIENT_PID"
CLIENT_PID=""
run wait "$SERVER_PID"
SERVER_PID=""
echo "PASS: committed Noise-IK handshake, encrypted TUN delivery, malformed-datagram drop, and continued service succeeded."
