#!/usr/bin/env bash
# Privileged end-to-end coverage for encrypted Noise-IK replay, authentication,
# routing, NAT, and cleanup behavior. It creates only isolated namespaces.
set -Eeuo pipefail

CLIENT_NS="cn-adv-client"
SERVER_NS="cn-adv-server"
BACKEND_NS="cn-adv-backend"
SERVICE_NS="cn-adv-service"
CLIENT_VETH="cn-adv-c-veth"
SERVER_VETH="cn-adv-s-veth"
SERVER_BACKEND_VETH="cn-adv-s-back"
BACKEND_VETH="cn-adv-b-veth"
BACKEND_SERVICE_VETH="cn-adv-b-svc"
SERVICE_VETH="cn-adv-svc-v"
CLIENT_PID=""
SERVER_PID=""
RELAY_PID=""
HTTP_PID=""
LOG_DIR=""
INITIAL_FORWARDING=""
CURRENT_STAGE="initialization"
REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

run() { echo "+ $*"; "$@"; }
require() { command -v "$1" >/dev/null || { echo "Missing command: $1" >&2; exit 1; }; }
namespace_exists() { ip netns list | awk '{ print $1 }' | grep -Fxq "$1"; }

wait_for_log() {
  local pattern=$1
  local path=$2
  for _ in {1..50}; do
    if grep -Fq "$pattern" "$path"; then
      return
    fi
    sleep 0.1
  done
  echo "Timed out waiting for log: $pattern" >&2
  sed -n '1,200p' "$path" >&2
  exit 1
}

wait_for_http_response() {
  local namespace=$1
  local url=$2
  local output_path=$3
  for _ in {1..50}; do
    if ip netns exec "$namespace" curl --fail --silent --connect-timeout 1 --max-time 1 "$url" >"$output_path"; then
      return
    fi
    sleep 0.1
  done
  echo "Timed out waiting for HTTP service at $url" >&2
  ip netns exec "$namespace" curl --fail --silent --show-error --connect-timeout 1 --max-time 1 "$url" >"$output_path"
}

stop_process() {
  local pid=$1
  if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
    return
  fi

  kill -INT "$pid" 2>/dev/null
  for _ in {1..50}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null || true
      return
    fi
    sleep 0.1
  done

  echo "Timed out waiting for process $pid after SIGINT; sending SIGTERM" >&2
  kill -TERM "$pid" 2>/dev/null
  for _ in {1..50}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null || true
      return
    fi
    sleep 0.1
  done

  echo "Timed out waiting for process $pid after SIGTERM; sending SIGKILL" >&2
  kill -KILL "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null || true
}

cleanup() {
  local status=$?
  set +e
  stop_process "$HTTP_PID"
  stop_process "$CLIENT_PID"
  stop_process "$SERVER_PID"
  stop_process "$RELAY_PID"
  if ip link show "$CLIENT_VETH" >/dev/null 2>&1; then
    ip link delete "$CLIENT_VETH"
  fi
  for namespace in "$CLIENT_NS" "$SERVER_NS" "$BACKEND_NS" "$SERVICE_NS"; do
    ip netns delete "$namespace" 2>/dev/null
  done
  if (( status != 0 )); then
    echo "FAILED during: $CURRENT_STAGE" >&2
  fi
  [[ -n "$LOG_DIR" ]] && echo "Logs: $LOG_DIR"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

if (( EUID != 0 )); then
  echo "Run explicitly with sudo: sudo scripts/test-noise-ik-adversarial.sh" >&2
  exit 1
fi
for command in ip nft sysctl ping curl python3 awk grep sed mktemp sleep tr test; do require "$command"; done
for namespace in "$CLIENT_NS" "$SERVER_NS" "$BACKEND_NS" "$SERVICE_NS"; do
  if namespace_exists "$namespace"; then
    echo "Refusing to use existing namespace: $namespace" >&2
    exit 1
  fi
done
if [[ ! -x "$REPO_ROOT/target/debug/crabnet" || ! -x "$REPO_ROOT/target/debug/generate_noise_keys" ]]; then
  echo "Build binaries as your normal user first: cargo build --bins" >&2
  exit 1
fi

LOG_DIR="$(mktemp -d -t crabnet-noise-adversarial.XXXXXX)"
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
bind_addr = "127.0.0.1:51822"
[tun]
name = "crabnet0"
address = "10.0.0.1"
prefix_len = 24
mtu = 1400
[routing]
server_routes = [{ destination = "10.10.0.0/24", gateway = "172.16.0.2" }]
enable_forwarding = true
enable_nat = true
nat_egress_interface = "cn-adv-s-back"
[security]
mode = "noise_ik"
private_key_path = "$KEY_DIR/server.key"
allowed_client_public_keys = ["$CLIENT_PUBLIC"]
[security.session_limits]
max_outbound_packets = 100000
max_outbound_plaintext_bytes = 104857600
max_inbound_packets = 100000
max_inbound_plaintext_bytes = 104857600
idle_timeout_seconds = 300
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
[routing]
full_tunnel = true
[security]
mode = "noise_ik"
private_key_path = "$KEY_DIR/client.key"
server_public_key = "$SERVER_PUBLIC"
[security.session_limits]
max_outbound_packets = 100000
max_outbound_plaintext_bytes = 104857600
max_inbound_packets = 100000
max_inbound_plaintext_bytes = 104857600
idle_timeout_seconds = 300
EOF

CURRENT_STAGE="creating isolated namespaces"
for namespace in "$CLIENT_NS" "$SERVER_NS" "$BACKEND_NS" "$SERVICE_NS"; do run ip netns add "$namespace"; done
run ip link add "$CLIENT_VETH" type veth peer name "$SERVER_VETH"
run ip link set "$CLIENT_VETH" netns "$CLIENT_NS"
run ip link set "$SERVER_VETH" netns "$SERVER_NS"
run ip link add "$SERVER_BACKEND_VETH" type veth peer name "$BACKEND_VETH"
run ip link set "$SERVER_BACKEND_VETH" netns "$SERVER_NS"
run ip link set "$BACKEND_VETH" netns "$BACKEND_NS"
run ip link add "$BACKEND_SERVICE_VETH" type veth peer name "$SERVICE_VETH"
run ip link set "$BACKEND_SERVICE_VETH" netns "$BACKEND_NS"
run ip link set "$SERVICE_VETH" netns "$SERVICE_NS"
run ip -n "$CLIENT_NS" address add 192.0.2.1/24 dev "$CLIENT_VETH"
run ip -n "$SERVER_NS" address add 192.0.2.2/24 dev "$SERVER_VETH"
run ip -n "$SERVER_NS" address add 172.16.0.1/24 dev "$SERVER_BACKEND_VETH"
run ip -n "$BACKEND_NS" address add 172.16.0.2/24 dev "$BACKEND_VETH"
run ip -n "$BACKEND_NS" address add 10.10.0.1/24 dev "$BACKEND_SERVICE_VETH"
run ip -n "$SERVICE_NS" address add 10.10.0.2/24 dev "$SERVICE_VETH"
for namespace in "$CLIENT_NS" "$SERVER_NS" "$BACKEND_NS" "$SERVICE_NS"; do run ip -n "$namespace" link set lo up; done
run ip -n "$CLIENT_NS" link set "$CLIENT_VETH" up
run ip -n "$SERVER_NS" link set "$SERVER_VETH" up
run ip -n "$SERVER_NS" link set "$SERVER_BACKEND_VETH" up
run ip -n "$BACKEND_NS" link set "$BACKEND_VETH" up
run ip -n "$BACKEND_NS" link set "$BACKEND_SERVICE_VETH" up
run ip -n "$SERVICE_NS" link set "$SERVICE_VETH" up
run ip netns exec "$BACKEND_NS" sysctl -w net.ipv4.ip_forward=1
run ip -n "$SERVICE_NS" route add default via 10.10.0.1
run ip netns exec "$CLIENT_NS" ping -c 1 -W 2 192.0.2.2
INITIAL_FORWARDING="$(ip netns exec "$SERVER_NS" sysctl -n net.ipv4.ip_forward)"

CURRENT_STAGE="starting controlled UDP relay"
RELAY_COMMAND="$LOG_DIR/relay-command"
RELAY_CAPTURE="$LOG_DIR/relay-data.bin"
RELAY_HELD="$LOG_DIR/relay-held.bin"
ip netns exec "$SERVER_NS" bash -c 'trap - INT TERM; exec python3 -u - "$@"' bash "$RELAY_COMMAND" "$RELAY_CAPTURE" "$RELAY_HELD" \
  >"$LOG_DIR/relay.log" 2>&1 <<'PY_RELAY' &
import os
import select
import signal
import socket
import sys

command_path, capture_path, held_path = sys.argv[1:]
external = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
external.bind(("192.0.2.2", 51821))
internal = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
internal.bind(("127.0.0.1", 0))
internal.connect(("127.0.0.1", 51822))
client = None
last_data = None
held_data = None
hold_next = False
running = True

def stop(*_args):
    global running
    running = False

signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)

def is_client_data(packet):
    return len(packet) > 51 and packet[:6] == b"CRBN\x02\x01" and packet[42] == 0

while running:
    readable, _, _ = select.select([external, internal], [], [], 0.05)
    if external in readable:
        packet, client = external.recvfrom(65535)
        if is_client_data(packet):
            last_data = packet
            with open(capture_path, "wb") as capture:
                capture.write(packet)
            if hold_next:
                held_data = packet
                with open(held_path, "wb") as held:
                    held.write(packet)
                hold_next = False
                print("held one encrypted client data datagram", flush=True)
                continue
        internal.send(packet)
    if internal in readable:
        packet = internal.recv(65535)
        if client is not None:
            external.sendto(packet, client)
    if os.path.exists(command_path):
        with open(command_path, encoding="ascii") as command_file:
            command = command_file.read().strip()
        os.unlink(command_path)
        if command == "hold-next":
            hold_next = True
            print("relay armed to hold next encrypted client data datagram", flush=True)
        elif command == "replay" and last_data is not None:
            internal.send(last_data)
            print("replayed encrypted client data datagram", flush=True)
        elif command == "tamper" and held_data is not None:
            tampered = bytearray(held_data)
            tampered[-1] ^= 1
            internal.send(tampered)
            print("tampered held encrypted client data datagram", flush=True)
        else:
            raise RuntimeError(f"invalid relay command or missing captured data: {command}")
external.close()
internal.close()
PY_RELAY
RELAY_PID=$!

CURRENT_STAGE="starting Noise-IK endpoints"
ip netns exec "$SERVER_NS" bash -c 'trap - INT TERM; exec "$@"' bash "$REPO_ROOT/target/debug/crabnet" --config-path "$LOG_DIR/server.toml" >"$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 0.1
ip netns exec "$CLIENT_NS" bash -c 'trap - INT TERM; exec "$@"' bash "$REPO_ROOT/target/debug/crabnet" --config-path "$LOG_DIR/client.toml" >"$LOG_DIR/client.log" 2>&1 &
CLIENT_PID=$!
for _ in {1..100}; do
  if ! kill -0 "$CLIENT_PID" 2>/dev/null || ! kill -0 "$SERVER_PID" 2>/dev/null || ! kill -0 "$RELAY_PID" 2>/dev/null; then
    sed -n "1,160p" "$LOG_DIR/client.log" "$LOG_DIR/server.log" "$LOG_DIR/relay.log" >&2
    exit 1
  fi
  endpoint_route="$(ip -n "$CLIENT_NS" route show exact 192.0.2.2/32)"
  default_route="$(ip -n "$CLIENT_NS" route show default)"
  server_route="$(ip -n "$SERVER_NS" route show exact 10.10.0.0/24)"
  if [[ "$endpoint_route" == *"192.0.2.2 dev $CLIENT_VETH"* ]] \
    && [[ "$default_route" == *"dev crabnet0"* ]] \
    && [[ "$server_route" == *"via 172.16.0.2"* ]] \
    && [[ "$(ip netns exec "$SERVER_NS" sysctl -n net.ipv4.ip_forward)" == "1" ]] \
    && ip netns exec "$SERVER_NS" nft list table ip crabnet_nat >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

CURRENT_STAGE="checking Noise-IK routing and NAT installation"
endpoint_route="$(ip -n "$CLIENT_NS" route show exact 192.0.2.2/32)"
[[ "$endpoint_route" == *"192.0.2.2 dev $CLIENT_VETH"* ]] || { echo "VPN endpoint route missing: $endpoint_route" >&2; exit 1; }
default_route="$(ip -n "$CLIENT_NS" route show default)"
[[ "$default_route" == *"dev crabnet0"* ]] || { echo "TUN default route missing: $default_route" >&2; exit 1; }
server_route="$(ip -n "$SERVER_NS" route show exact 10.10.0.0/24)"
[[ "$server_route" == *"via 172.16.0.2"* ]] || { echo "server route missing: $server_route" >&2; exit 1; }
[[ "$(ip netns exec "$SERVER_NS" sysctl -n net.ipv4.ip_forward)" == "1" ]] || { echo "server forwarding was not enabled" >&2; exit 1; }
run ip netns exec "$SERVER_NS" nft list table ip crabnet_nat >"$LOG_DIR/nft-running.txt"
run grep -F masquerade "$LOG_DIR/nft-running.txt"
[[ -z "$(ip -n "$BACKEND_NS" route show exact 10.0.0.0/24)" ]] || { echo "backend unexpectedly has a VPN return route" >&2; exit 1; }

CURRENT_STAGE="proving encrypted routed traffic"
run ip netns exec "$CLIENT_NS" ping -c 3 -W 2 -I 10.0.0.2 10.10.0.2
ip netns exec "$SERVICE_NS" bash -c 'trap - INT TERM; exec python3 -u -m http.server "$@"' bash 8080 --bind 10.10.0.2 >"$LOG_DIR/http.log" 2>&1 &
HTTP_PID=$!
wait_for_http_response "$CLIENT_NS" "http://10.10.0.2:8080/" "$LOG_DIR/http-response.html"
run test -s "$LOG_DIR/http-response.html"
wait_for_log 172.16.0.1 "$LOG_DIR/http.log"
for _ in {1..50}; do [[ -s "$RELAY_CAPTURE" ]] && break; sleep 0.1; done
[[ -s "$RELAY_CAPTURE" ]] || { echo "relay did not capture encrypted client data" >&2; exit 1; }

CURRENT_STAGE="rejecting replayed encrypted data without ending the session"
printf replay > "$RELAY_COMMAND"
wait_for_log "replayed encrypted client data datagram" "$LOG_DIR/relay.log"
wait_for_log "dropping replayed encrypted datagram" "$LOG_DIR/server.log"
run ip netns exec "$CLIENT_NS" ping -c 2 -W 2 -I 10.0.0.2 10.10.0.2

CURRENT_STAGE="rejecting tampered encrypted data without ending the session"
printf hold-next > "$RELAY_COMMAND"
wait_for_log "relay armed to hold next encrypted client data datagram" "$LOG_DIR/relay.log"
if ip netns exec "$CLIENT_NS" ping -c 1 -W 1 -I 10.0.0.2 10.10.0.2; then
  echo "held encrypted packet unexpectedly reached the service" >&2
  exit 1
fi
for _ in {1..50}; do [[ -s "$RELAY_HELD" ]] && break; sleep 0.1; done
[[ -s "$RELAY_HELD" ]] || { echo "relay did not hold encrypted client data" >&2; exit 1; }
printf tamper > "$RELAY_COMMAND"
wait_for_log "tampered held encrypted client data datagram" "$LOG_DIR/relay.log"
wait_for_log "dropping unauthenticated encrypted datagram" "$LOG_DIR/server.log"
run ip netns exec "$CLIENT_NS" ping -c 2 -W 2 -I 10.0.0.2 10.10.0.2

CURRENT_STAGE="graceful shutdown and cleanup verification"
stop_process "$CLIENT_PID"; CLIENT_PID=""
stop_process "$SERVER_PID"; SERVER_PID=""
stop_process "$RELAY_PID"; RELAY_PID=""
endpoint_route="$(ip -n "$CLIENT_NS" route show exact 192.0.2.2/32)"
[[ "$endpoint_route" != *"192.0.2.2 dev $CLIENT_VETH"* ]] || { echo "endpoint route remains after shutdown: $endpoint_route" >&2; exit 1; }
[[ -z "$(ip -n "$CLIENT_NS" route show default)" ]] || { echo "default route remains after shutdown" >&2; exit 1; }
[[ -z "$(ip -n "$SERVER_NS" route show exact 10.10.0.0/24)" ]] || { echo "server route remains after shutdown" >&2; exit 1; }
if ip netns exec "$SERVER_NS" nft list table ip crabnet_nat >/dev/null 2>&1; then echo "NAT table remains after shutdown" >&2; exit 1; fi
[[ "$(ip netns exec "$SERVER_NS" sysctl -n net.ipv4.ip_forward)" == "$INITIAL_FORWARDING" ]] || { echo "server forwarding was not restored" >&2; exit 1; }
echo "PASS: encrypted routed traffic, replay/tamper rejection, and route/NAT cleanup succeeded."
