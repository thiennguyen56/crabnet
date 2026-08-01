# 🦀 Crabnet

> **A modular, open-source networking framework for building VPNs, overlay networks, and distributed networking systems in Rust.**

Crabnet is a learning-driven Rust/Tokio TUN-over-UDP prototype. It currently
supports a single unauthenticated UDP peer, binary packet forwarding, logging,
client split routes through `iproute2`, and server IPv4 forwarding.

## Documentation

- [Architecture](docs/architecture.md)
- [Configuration reference](docs/configuration.md)
- [Testing](docs/testing.md)
- [Current protocol](docs/protocol.md)
- [Security limitations](docs/security-limitations.md)
- [Routing sequence diagrams](docs/routing-sequences.md)

`docs/STAGE1.md`, `docs/STAGE1_MINOBOOK.md`, and `docs/milestones1.md` are
learning notes and historical planning documents; the files above describe the
current implementation.

## Why Crabnet?

Networking software is difficult to understand when protocols, routing, NAT,
and transport are tightly coupled. Crabnet keeps these pieces replaceable and
testable so the tunnel can be built incrementally.

## Local TUN tunnel test

This is one end-to-end workflow using four Linux network namespaces:

```text
cn-client                    cn-server             cn-backend             cn-service
TUN 10.0.0.2                 TUN 10.0.0.1           172.16.0.2             10.10.0.2
underlay 192.0.2.1 ────────  underlay 192.0.2.2
                             172.16.0.1 ────────── 172.16.0.2
                                                       10.10.0.1 ──────── 10.10.0.2
```

It verifies, in order:

```text
underlay connectivity
→ TUN creation
→ client protected-route installation
→ server_routes installation
→ server IPv4 forwarding
→ overlay ping
→ HTTP through the backend network
→ route and sysctl restoration
```

The test requires Linux, `sudo`, `iproute2`, `sysctl`, `ping`, `curl`, and
Python. TUN, namespace, route, and forwarding operations require root or
`CAP_NET_ADMIN`. Do not test `google.com` yet; full-internet tunneling also
needs default-route management, firewall rules, NAT, DNS, and return-path
automation.

### 1. Build and check

Run these as your normal user:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo build
```

The remaining commands use `target/debug/crabnet`.

### 2. Confirm configuration

The client configuration must contain:

```toml
[routing]
protected_routes = ["10.10.0.0/24"]
```

The server configuration must contain:

```toml
[routing]
server_routes = [
  { destination = "10.10.0.0/24", gateway = "172.16.0.2" }
]
enable_forwarding = true
enable_nat = false
```

The client route sends `10.10.0.0/24` into `crabnet0`. The server route sends
that destination through the backend router at `172.16.0.2`. The server
forwarding setting enables `net.ipv4.ip_forward`; NAT is deliberately not
implemented.

### 3. Create the three namespaces and links

Start with no existing `cn-client`, `cn-server`, or `cn-backend` namespaces.

```bash
sudo ip netns add cn-client
sudo ip netns add cn-server
sudo ip netns add cn-backend
sudo ip netns add cn-service

sudo ip link add cn-client-veth type veth peer name cn-server-veth
sudo ip link set cn-client-veth netns cn-client
sudo ip link set cn-server-veth netns cn-server

sudo ip link add cn-srv-back type veth peer name cn-back-veth
sudo ip link set cn-srv-back netns cn-server
sudo ip link set cn-back-veth netns cn-backend

sudo ip link add cn-back-service type veth peer name cn-service-veth
sudo ip link set cn-back-service netns cn-backend
sudo ip link set cn-service-veth netns cn-service
```

The first veth carries Crabnet's UDP underlay. The second veth connects the
server namespace to the private backend network.

### 4. Configure addresses and interfaces

```bash
sudo ip netns exec cn-client \
  ip address add 192.0.2.1/24 dev cn-client-veth
sudo ip netns exec cn-server \
  ip address add 192.0.2.2/24 dev cn-server-veth

sudo ip netns exec cn-server \
  ip address add 172.16.0.1/24 dev cn-srv-back
sudo ip netns exec cn-backend \
  ip address add 172.16.0.2/24 dev cn-back-veth
sudo ip netns exec cn-backend \
  ip address add 10.10.0.1/24 dev cn-back-service
sudo ip netns exec cn-service \
  ip address add 10.10.0.2/24 dev cn-service-veth

sudo ip netns exec cn-client ip link set lo up
sudo ip netns exec cn-client ip link set cn-client-veth up

sudo ip netns exec cn-server ip link set lo up
sudo ip netns exec cn-server ip link set cn-server-veth up
sudo ip netns exec cn-server ip link set cn-srv-back up

sudo ip netns exec cn-backend ip link set lo up
sudo ip netns exec cn-backend ip link set cn-back-veth up
sudo ip netns exec cn-backend ip link set cn-back-service up
sudo ip netns exec cn-service ip link set lo up
sudo ip netns exec cn-service ip link set cn-service-veth up
```

The backend needs a return route for VPN client addresses:

```bash
sudo ip netns exec cn-backend \
  ip route add 10.0.0.0/24 via 172.16.0.1
sudo ip netns exec cn-service \
  ip route add 10.0.0.0/24 via 10.10.0.1

sudo ip netns exec cn-backend \
  sysctl -w net.ipv4.ip_forward=1
```

Without this route, requests can reach the backend but responses cannot return
through the server.

This route is intentionally still configured manually in the namespace test:
the backend is outside the Crabnet process, so Crabnet cannot safely change its
routing table. The application does automate the client protected route and
server IPv4 forwarding.

### 5. Verify physical links

```bash
sudo ip netns exec cn-client ping -c 2 192.0.2.2
sudo ip netns exec cn-server ping -c 2 172.16.0.2
sudo ip netns exec cn-backend ping -c 2 10.10.0.2
```

If either ping fails, stop here. Crabnet cannot work until both underlay links
are reachable.

### 6. Record forwarding state

Before starting the server, record its original value:

```bash
sudo ip netns exec cn-server \
  sysctl -n net.ipv4.ip_forward
```

A fresh namespace normally prints `0`. If it prints `1`, Crabnet should leave
it enabled after shutdown because it did not own that setting.

### 7. Start server and client

Start the server in one terminal:

```bash
sudo ip netns exec cn-server \
  ./target/debug/crabnet \
  --config-path config/server/config.toml
```

Start the client in another terminal:

```bash
sudo ip netns exec cn-client \
  ./target/debug/crabnet \
  --config-path config/client/config.toml
```

`ip netns exec` is required so each process creates its UDP socket, TUN, and
network state inside the intended namespace.

### 8. Verify TUN, routes, and forwarding

```bash
sudo ip netns exec cn-client ip address show crabnet0
sudo ip netns exec cn-server ip address show crabnet0

sudo ip netns exec cn-client ip route show
sudo ip netns exec cn-server ip route show

sudo ip netns exec cn-server \
  sysctl -n net.ipv4.ip_forward
```

Expected forwarding output while the server runs:

```text
1
```

Verify the client-managed protected route:

```bash
sudo ip netns exec cn-client \
  ip route show exact 10.10.0.0/24
```

Expected output:

```text
10.10.0.0/24 dev crabnet0
```

Verify the server-managed route:

```bash
sudo ip netns exec cn-server \
  ip route show exact 10.10.0.0/24
```

Expected output:

```text
10.10.0.0/24 via 172.16.0.2
```

Also verify that the VPN server endpoint remains on the underlay:

```bash
sudo ip netns exec cn-client \
  ip route get 192.0.2.2
```

The result must use `cn-client-veth`, not `crabnet0`. This prevents Crabnet's
own UDP traffic from recursively entering the tunnel.

### 9. Ping through the overlay

Run the ping inside the client namespace:

```bash
sudo ip netns exec cn-client \
  ping -c 4 -I 10.0.0.2 10.0.0.1
```

The expected first-packet log order is:

```text
Client TUN -> UDP
Server peer registration
Server UDP -> TUN
Server TUN -> UDP
Client UDP -> TUN
```

From Crabnet's perspective, TUN read means `local OS -> Crabnet`, while TUN
write means `Crabnet -> local OS`. Therefore, `Client UDP -> TUN` injects the
server response into the client kernel.

### 10. Test HTTP behind the server

Start the backend server:

```bash
sudo ip netns exec cn-service \
  python3 -m http.server 8080 --bind 10.10.0.2
```

Request it from the client:

```bash
sudo ip netns exec cn-client \
  curl --fail http://10.10.0.2:8080
```

The packet path is:

```text
client OS
→ client TUN
→ client UDP
→ server UDP
→ server TUN
→ server IPv4 forwarding
→ server_routes via 172.16.0.2
→ backend router
→ service HTTP server
```

The explicit backend route sends the HTTP response back through the server.

### 11. Diagnose failures

Use `tcpdump` inside a separate terminal when needed:

```bash
sudo ip netns exec cn-client tcpdump -ni crabnet0
sudo ip netns exec cn-client \
  tcpdump -ni cn-client-veth udp port 51821
sudo ip netns exec cn-server tcpdump -ni crabnet0
```

The first missing observation identifies the failing layer:

- No client TUN packet: client route or namespace problem.
- Client TUN but no server UDP: underlay or socket problem.
- Server UDP but no server TUN: server TUN write problem.
- Server TUN but no backend traffic: forwarding or backend route problem.
- Backend receives but client times out: return-route problem.

### 12. Shut down and verify restoration

Stop the client with Ctrl+C first. Its log should include removal of the
protected route:

```text
Removed route 10.10.0.0/24 dev crabnet0
```

Then stop the server with Ctrl+C. Its log should include restoration of IPv4
forwarding. Check the value again:

```bash
sudo ip netns exec cn-server \
  sysctl -n net.ipv4.ip_forward
```

If the original value was `0`, it should now be `0`. If it was `1`, it should
remain `1`. A route or forwarding operation that fails during cleanup remains
tracked for retry. Cleanup cannot run after `SIGKILL`, a kernel crash, or power
loss.

### 13. Clean up

Stop the backend HTTP server, then remove all namespaces:

```bash
sudo ip netns delete cn-client
sudo ip netns delete cn-server
sudo ip netns delete cn-backend
sudo ip netns delete cn-service
```

Deleting the namespaces also removes their veth interfaces, TUN interfaces,
addresses, and routes.

If a previous run was interrupted and left test resources behind, use the
targeted cleanup helper before starting again:

```bash
sudo scripts/clean-local-tunnel.sh
```

It removes only the Crabnet test namespaces and exact test veth names. Deleting
`cn-server` also removes its namespace-local `net.ipv4.ip_forward` state. The
helper does not change host routes, the host forwarding setting, or the host
firewall.

## Repeat the four-namespace test automatically

The script creates the client, server, backend-router, and service namespaces,
configures `server_routes` and both return routes, verifies routed overlay ping
and backend HTTP, and checks route/sysctl cleanup:

```bash
cargo build
sudo scripts/test-local-tunnel.sh
```

Build as your normal user so `sudo` does not create root-owned Cargo artifacts.
The script refuses to reuse existing namespaces, does not change the host
default route or firewall, and removes only resources it created.
