#!/usr/bin/env bash

set -Eeuo pipefail

CLIENT_NS="cn-client"
SERVER_NS="cn-server"
BACKEND_NS="cn-backend"
CLIENT_VETH="cn-client-veth"
SERVER_VETH="cn-server-veth"
SERVER_BACKEND_VETH="cn-srv-back"
BACKEND_VETH="cn-back-veth"
CURRENT_STAGE="initialization"
CLIENT_CREATED=0
SERVER_CREATED=0
BACKEND_CREATED=0
VETH_CREATED=0
CLIENT_PID=""
SERVER_PID=""
HTTP_PID=""
LOG_DIR=""
INITIAL_FORWARDING=""

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
	if (( BACKEND_CREATED )); then
		ip netns delete "$BACKEND_NS"
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

for command in ip sysctl ping curl python3 awk grep mktemp sleep test; do
	require_command "$command"
done

LOG_DIR="$(mktemp -d -t crabnet-test.XXXXXX)"

if namespace_exists "$CLIENT_NS" || namespace_exists "$SERVER_NS" || \
	namespace_exists "$BACKEND_NS"; then
	echo "Refusing to continue: a test namespace already exists." >&2
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
run ip netns add "$BACKEND_NS"
BACKEND_CREATED=1

run ip link add "$CLIENT_VETH" type veth peer name "$SERVER_VETH"
VETH_CREATED=1
run ip link set "$CLIENT_VETH" netns "$CLIENT_NS"
run ip link set "$SERVER_VETH" netns "$SERVER_NS"

run ip link add "$SERVER_BACKEND_VETH" type veth peer name "$BACKEND_VETH"
run ip link set "$SERVER_BACKEND_VETH" netns "$SERVER_NS"
run ip link set "$BACKEND_VETH" netns "$BACKEND_NS"

run ip -n "$CLIENT_NS" address add 192.0.2.1/24 dev "$CLIENT_VETH"
run ip -n "$SERVER_NS" address add 192.0.2.2/24 dev "$SERVER_VETH"
run ip -n "$SERVER_NS" address add 172.16.0.1/24 dev "$SERVER_BACKEND_VETH"
run ip -n "$BACKEND_NS" address add 172.16.0.2/24 dev "$BACKEND_VETH"
run ip -n "$CLIENT_NS" link set lo up
run ip -n "$SERVER_NS" link set lo up
run ip -n "$BACKEND_NS" link set lo up
run ip -n "$CLIENT_NS" link set "$CLIENT_VETH" up
run ip -n "$SERVER_NS" link set "$SERVER_VETH" up
run ip -n "$SERVER_NS" link set "$SERVER_BACKEND_VETH" up
run ip -n "$BACKEND_NS" link set "$BACKEND_VETH" up

CURRENT_STAGE="configuring backend return route"
run ip -n "$BACKEND_NS" route add 10.0.0.0/24 via 172.16.0.1

CURRENT_STAGE="underlay ping"
run ip netns exec "$CLIENT_NS" ping -c 2 -W 2 192.0.2.2
run ip netns exec "$SERVER_NS" ping -c 2 -W 2 172.16.0.2

CURRENT_STAGE="recording IPv4 forwarding state"
INITIAL_FORWARDING="$(ip netns exec "$SERVER_NS" sysctl -n net.ipv4.ip_forward)"
if [[ "$INITIAL_FORWARDING" != "0" && "$INITIAL_FORWARDING" != "1" ]]; then
	echo "Unexpected initial forwarding value: $INITIAL_FORWARDING" >&2
	exit 1
fi
echo "Initial server IPv4 forwarding: $INITIAL_FORWARDING"

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

CURRENT_STAGE="checking automatic routes and forwarding"
client_route="$(ip -n "$CLIENT_NS" route show exact 172.16.0.0/24)"
if [[ "$client_route" != *"dev crabnet0"* ]]; then
	echo "Protected client route was not installed: $client_route" >&2
	exit 1
fi

underlay_route="$(ip -n "$CLIENT_NS" route get 192.0.2.2)"
if [[ "$underlay_route" != *"$CLIENT_VETH"* ]]; then
	echo "VPN endpoint is not using the underlay: $underlay_route" >&2
	exit 1
fi

current_forwarding="$(ip netns exec "$SERVER_NS" sysctl -n net.ipv4.ip_forward)"
if [[ "$current_forwarding" != "1" ]]; then
	echo "Server forwarding was not enabled: $current_forwarding" >&2
	exit 1
fi

CURRENT_STAGE="overlay ping"
run ip netns exec "$CLIENT_NS" ping -c 4 -W 2 -I 10.0.0.2 10.0.0.1

CURRENT_STAGE="HTTP behind server"
echo "+ ip netns exec $BACKEND_NS python3 -m http.server 8080 --bind 172.16.0.2"
ip netns exec "$BACKEND_NS" python3 -m http.server 8080 --bind 172.16.0.2 \
	>"$LOG_DIR/http.log" 2>&1 &
HTTP_PID=$!

for _ in {1..20}; do
	if ip netns exec "$CLIENT_NS" curl --fail --silent --show-error \
		--connect-timeout 1 http://172.16.0.2:8080/ \
		>"$LOG_DIR/http-response.html"; then
		break
	fi
	sleep 0.1
done
run test -s "$LOG_DIR/http-response.html"

stop_crabnet

CURRENT_STAGE="checking shutdown state"
if [[ -n "$(ip -n "$CLIENT_NS" route show exact 172.16.0.0/24)" ]]; then
	echo "Protected route remains after client shutdown" >&2
	exit 1
fi

if [[ "$INITIAL_FORWARDING" == "0" ]]; then
	final_forwarding="$(ip netns exec "$SERVER_NS" sysctl -n net.ipv4.ip_forward)"
	if [[ "$final_forwarding" != "0" ]]; then
		echo "Server forwarding was not restored: $final_forwarding" >&2
		exit 1
	fi
else
	final_forwarding="$(ip netns exec "$SERVER_NS" sysctl -n net.ipv4.ip_forward)"
	if [[ "$final_forwarding" != "1" ]]; then
		echo "Pre-existing server forwarding state changed: $final_forwarding" >&2
		exit 1
	fi
fi

CURRENT_STAGE="checking shutdown summaries"
run grep -F "Client forwarding summary" "$LOG_DIR/client.log"
run grep -F "Server forwarding summary" "$LOG_DIR/server.log"
run grep -F "Removed route 172.16.0.0/24 through crabnet0" "$LOG_DIR/client.log"
if [[ "$INITIAL_FORWARDING" == "0" ]]; then
	run grep -F "Restored IPv4 forwarding to 0" "$LOG_DIR/server.log"
fi

if [[ -n "$HTTP_PID" ]] && kill -0 "$HTTP_PID" 2>/dev/null; then
	run kill -INT "$HTTP_PID"
	run wait "$HTTP_PID"
fi
HTTP_PID=""

echo "PASS: underlay, overlay, split route, forwarding, backend HTTP, and cleanup succeeded."
