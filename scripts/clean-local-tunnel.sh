#!/usr/bin/env bash

set -Eeuo pipefail

if (( EUID != 0 )); then
  echo "Run this cleanup explicitly with sudo:" >&2
  echo "  sudo scripts/clean-local-tunnel.sh" >&2
  exit 1
fi

namespace_exists() {
  ip netns list | awk '{ print $1 }' | grep -Fxq "$1"
}

delete_namespace() {
  local namespace=$1

  if namespace_exists "$namespace"; then
    echo "+ ip netns delete $namespace"
    ip netns delete "$namespace"
  else
    echo "- namespace $namespace is already absent"
  fi
}

for command in ip awk grep; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done

delete_namespace cn-client
delete_namespace cn-server
delete_namespace cn-backend
delete_namespace cn-service

# These are exact test-interface names. They can remain in the host namespace
# only if setup was interrupted before the links were moved into namespaces.
for link in cn-client-veth cn-server-veth cn-srv-back cn-back-veth \
  cn-back-service cn-service-veth \
  cn-server-backend cn-backend-veth; do
  if ip link show "$link" >/dev/null 2>&1; then
    echo "+ ip link delete $link"
    ip link delete "$link"
  fi
done

echo "Crabnet local test resources are clean."
echo "Host routes, forwarding, and firewall state were not modified."
