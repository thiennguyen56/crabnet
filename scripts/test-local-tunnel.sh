#!/usr/bin/env bash

set -Eeuo pipefail

CLIENT_NS="cn-client"
SERVER_NS="cn-server"
CLIENT_VETH="cn-client-veth"
SERVER_VETH="cn-server-veth"
CURRENT_STAGE="initialization"
CLIENT_CREATED=0
SERVER_CREATED=0
VETH_CREATED=0
CLIENT_PID=""
SERVER_PID=""
HTTP_PID=""
LOG_DIR=""

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

cleanup() {
	local status=$?
	set +e

	for pid in "$CLIENT_PID" "$SERVER_PID" "$HTTP_PID"; do
		if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
			kill -INT "$pid" 2>/dev/null
			wait "$pid" 2>/dev/null
		fi
	done

	if (( VETH_CREATED )) && ip link show "$CLIENT_VETH" >/dev/null 2>&1; then
		ip link delete "$CLIENT_VETH"
	fi

	if (( CLIENT_CREATED )); then
		ip netns delete "$CLIENT_NS"
	fi
	if (( SERVER_CREATED )); then
		ip netns delete "$SERVER_NS"
	fi

	if (( status != 0 )); then
		echo "FAILED during: $CURRENT_STAGE" >&2
	fi
	if [[ -n "$LOG_DIR" ]]; then
		echo "Logs: $LOG_DIR"
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

run() {
	echo "+ $*"
	"$@"
}

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "Required command not found: $1" >&2
		exit 1
	fi
}

namespace_exists() {
	ip netns list | awk '{ print $1 }' | grep -Fxq "$1"
}

stop_crabnet() {
	CURRENT_STAGE="graceful Crabnet shutdown"

	for pid in "$CLIENT_PID" "$SERVER_PID"; do
		if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
			run kill -INT "$pid"
		fi
	done

	if [[ -n "$CLIENT_PID" ]]; then
		run wait "$CLIENT_PID"
		CLIENT_PID=""
	fi
	if [[ -n "$SERVER_PID" ]]; then
		run wait "$SERVER_PID"
		SERVER_PID=""
	fi
}

if (( EUID != 0 )); then
	echo "Run this test explicitly with sudo:" >&2
	echo "  sudo scripts/test-local-tunnel.sh" >&2
	exit 1
fi

for command in ip ping curl python3 awk grep mktemp sleep; do
	require_command "$command"
done

LOG_DIR="$(mktemp -d -t crabnet-test.XXXXXX)"

if namespace_exists "$CLIENT_NS" || namespace_exists "$SERVER_NS"; then
	echo "Refusing to continue: $CLIENT_NS or $SERVER_NS already exists." >&2
	echo "Remove or rename the existing namespace yourself, then retry." >&2
	exit 1
fi

if [[ ! -x "$REPO_ROOT/target/debug/crabnet" ]]; then
	echo "Crabnet has not been built. Build it as your normal user first:" >&2
	echo "  cargo build" >&2
	exit 1
fi

CURRENT_STAGE="creating network namespaces"
run ip netns add "$CLIENT_NS"
CLIENT_CREATED=1
run ip netns add "$SERVER_NS"
SERVER_CREATED=1

run ip link add "$CLIENT_VETH" type veth peer name "$SERVER_VETH"
VETH_CREATED=1
run ip link set "$CLIENT_VETH" netns "$CLIENT_NS"
run ip link set "$SERVER_VETH" netns "$SERVER_NS"

run ip -n "$CLIENT_NS" address add 192.0.2.1/24 dev "$CLIENT_VETH"
run ip -n "$SERVER_NS" address add 192.0.2.2/24 dev "$SERVER_VETH"
run ip -n "$CLIENT_NS" link set lo up
run ip -n "$SERVER_NS" link set lo up
run ip -n "$CLIENT_NS" link set "$CLIENT_VETH" up
run ip -n "$SERVER_NS" link set "$SERVER_VETH" up

CURRENT_STAGE="underlay ping"
run ip netns exec "$CLIENT_NS" ping -c 2 -W 2 192.0.2.2

CURRENT_STAGE="starting Crabnet endpoints"
echo "+ ip netns exec $SERVER_NS target/debug/crabnet --config-path config/server/config.toml"
ip netns exec "$SERVER_NS" \
	"$REPO_ROOT/target/debug/crabnet" \
	--config-path "$REPO_ROOT/config/server/config.toml" \
	>"$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!

echo "+ ip netns exec $CLIENT_NS target/debug/crabnet --config-path config/client/config.toml"
ip netns exec "$CLIENT_NS" \
	"$REPO_ROOT/target/debug/crabnet" \
	--config-path "$REPO_ROOT/config/client/config.toml" \
	>"$LOG_DIR/client.log" 2>&1 &
CLIENT_PID=$!

CURRENT_STAGE="waiting for TUN interfaces"
for _ in {1..50}; do
	if ip -n "$CLIENT_NS" link show crabnet0 >/dev/null 2>&1 && \
		ip -n "$SERVER_NS" link show crabnet0 >/dev/null 2>&1; then
		break
	fi
	sleep 0.1
done
run ip -n "$CLIENT_NS" address show crabnet0
run ip -n "$SERVER_NS" address show crabnet0
run ip -n "$CLIENT_NS" route show
run ip -n "$SERVER_NS" route show

CURRENT_STAGE="overlay ping"
run ip netns exec "$CLIENT_NS" ping -c 4 -W 2 -I 10.0.0.2 10.0.0.1

CURRENT_STAGE="HTTP over the overlay"
echo "+ ip netns exec $SERVER_NS python3 -m http.server 8080 --bind 10.0.0.1"
ip netns exec "$SERVER_NS" python3 -m http.server 8080 --bind 10.0.0.1 \
	>"$LOG_DIR/http.log" 2>&1 &
HTTP_PID=$!

for _ in {1..20}; do
	if ip netns exec "$CLIENT_NS" curl --fail --silent --show-error \
		--connect-timeout 1 http://10.0.0.1:8080/ \
		>"$LOG_DIR/http-response.html"; then
		break
	fi
	sleep 0.1
done
run test -s "$LOG_DIR/http-response.html"

stop_crabnet

CURRENT_STAGE="checking shutdown summaries"
run grep -F "Client forwarding summary" "$LOG_DIR/client.log"
run grep -F "Server forwarding summary" "$LOG_DIR/server.log"

echo "PASS: underlay ping, overlay ping, HTTP, and graceful shutdown succeeded."
