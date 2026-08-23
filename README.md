# 🦀 Crabnet

> **A modular, open-source networking framework for building VPNs, overlay networks, and distributed networking systems in Rust.**

Crabnet is a learning-driven Rust/Tokio TUN-over-UDP prototype. It currently
supports a single unauthenticated UDP peer, binary packet forwarding, logging,
versioned packet framing, client split/full-tunnel routes, server IPv4
forwarding, and IPv4 masquerading. Noise-IK uses the V2 UDP adapter, commits the authenticated four-message
handshake, and forwards only encrypted data frames. Legacy V1 forwarding remains
a separate explicitly selected mode.

## Documentation

- [Architecture](docs/architecture.md)
- [Current service diagrams](docs/diagrams.md)
- [Pure handshake learning guide](docs/handshake.md)
- [Configuration reference](docs/configuration.md)
- [Testing](docs/testing.md)
- [Current protocol](docs/protocol.md)
- [Security limitations](docs/security-limitations.md)
- [Routing sequence diagrams](docs/routing-sequences.md)
- [Version 2 handshake framing design](docs/handshake-framing-design.md)
- [Noise IK provider design](docs/noise-ik-provider-design.md)
- [Current roadmap](docs/roadmap.md)
- [Encrypted V2 data-plane design](docs/encrypted-v2-data-plane-design.md)

## Current milestone status

| Area | Status | Meaning |
| --- | --- | --- |
| Version 1 TUN/UDP forwarding | Active runtime | Moves raw IP packets in framed UDP datagrams |
| Routes, forwarding diagnostics, and IPv4 NAT | Active runtime | Linux lab functionality with ownership-aware cleanup |
| Session policy and fake crypto traits | Complete pure subsystem | Synchronous and testable without sockets or privileges |
| Handshake coordination | Complete pure subsystem | Four fake handshake messages establish matching metadata |
| Version 2 handshake framing and adapter | Integrated handshake runtime | Exact bounded bytes, direction checks, provider dispatch, and ciphertext encoding |
| Noise-IK authentication and encrypted data | Active runtime | Commits Noise-IK, binds the authenticated V2 header, and forwards directional encrypted packets with replay checks |
| Production VPN security | Not implemented | No rekeying, DNS handling, firewall-policy automation, or multi-peer support |

Use [the handshake guide](docs/handshake.md) to understand the state machines and runtime boundary,
then read the encrypted V2 data-plane design. Noise-IK never falls back to V1 forwarding.

## Why Crabnet?

Networking software is difficult to understand when protocols, routing, NAT,
and transport are tightly coupled. Crabnet keeps these pieces replaceable and
testable so the tunnel can be built incrementally.

## Container image

Build the small runtime image with the locked dependency versions:

```bash
docker build --tag crabnet:local .
```

Crabnet must manage a TUN device, routes, and (when configured) nftables state. Run it with
only the additional capability and device it needs rather than `--privileged`:

```bash
docker run --rm --name crabnet \
  --cap-drop ALL \
  --cap-add NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  --publish 51820:51820/udp \
  --volume ./crabnet.toml:/etc/crabnet/config.toml:ro \
  crabnet:local --config-path /etc/crabnet/config.toml
```

The configuration used in a normal Docker network should bind UDP to `0.0.0.0` and refer to
interfaces that exist inside the container (the ordinary egress interface is commonly `eth0`).
The files under `config/` target the namespace integration lab and are not ready-made Docker
settings. If server forwarding is enabled, `--sysctl net.ipv4.ip_forward=1` may be supplied at
container creation; Crabnet will observe that pre-existing value without claiming ownership of
it.

The image intentionally runs as root because its `ip`, `sysctl`, and `nft` child processes need
`CAP_NET_ADMIN`; dropping every other capability limits that privilege. Do not use host
networking casually: client routes or server NAT would then modify the host network namespace.
The current full-tunnel client also refuses to replace Docker's existing default route, so it
requires a deliberately prepared, isolated network namespace rather than a standard bridge
network.

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
→ malformed-first-frame rejection without peer registration
→ version 1 encoding and decoding in both directions
→ client endpoint-exclusion and default-route installation
→ server_routes installation
→ server IPv4 forwarding
→ server nftables masquerading
→ advisory nftables forwarding-policy diagnostic
→ overlay ping
→ HTTP through the backend network
→ translated source-address verification
→ route, sysctl, and nftables restoration
```

The test requires Linux, `sudo`, `iproute2`, `nftables`, `sysctl`, `ping`,
`curl`, and Python. TUN, namespace, route, forwarding, and NAT operations
require root or `CAP_NET_ADMIN`. Do not claim general internet access yet:
Crabnet does not manage firewall forwarding policy or full-tunnel DNS, and the
namespace test exercises a controlled private service rather than the internet.

When server IPv4 forwarding is enabled, startup performs a bounded, read-only
inspection of IPv4-relevant nftables forward base-chain policies. The result is
advisory: inspection failures are logged but do not stop startup. Crabnet does
not evaluate individual rules, legacy iptables, eBPF filters, or other firewall
systems, and it never installs administrator firewall policy.

### 1. Build and check

Run these as your normal user:

```bash
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo build
```

The remaining commands use `target/debug/crabnet`.

### 2. Confirm configuration

The client configuration must contain:

```toml
[routing]
full_tunnel = true
```

The server configuration must contain:

```toml
[routing]
server_routes = [
  { destination = "10.10.0.0/24", gateway = "172.16.0.2" }
]
enable_forwarding = true
enable_nat = true
nat_egress_interface = "cn-srv-back"
```

The client installs a `/32` underlay route for the VPN server, then a default
route through `crabnet0`. The server route sends `10.10.0.0/24` through the
backend router at `172.16.0.2`. The server forwarding setting enables
`net.ipv4.ip_forward`; NAT masquerades traffic arriving from `crabnet0` and
leaving through `cn-srv-back`.

Crabnet resolves the server's underlay gateway and interface before installing
the default route. This ordering prevents the VPN's own UDP transport from
being selected by the TUN default route. The current implementation refuses to
replace an existing default route, so this full-tunnel procedure is limited to
the isolated client namespace used below.

### 3. Create the four namespaces and links

Start with no existing `cn-client`, `cn-server`, `cn-backend`, or `cn-service`
namespaces.

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

The first veth carries Crabnet's UDP underlay. The second connects the server
to the backend router, and the third connects that router to the private
service network.

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

Give the service its ordinary default gateway and enable forwarding on the
backend router:

```bash
sudo ip netns exec cn-service \
  ip route add default via 10.10.0.1

sudo ip netns exec cn-backend \
  sysctl -w net.ipv4.ip_forward=1
```

Do not add a `10.0.0.0/24` route to the backend or service. Crabnet translates
the client source `10.0.0.2` to the server egress address `172.16.0.1`, so
the response follows ordinary connected and default routes. This absence of
VPN return routes is what makes the lab prove NAT rather than routing alone.

### 5. Verify physical links

```bash
sudo ip netns exec cn-client ping -c 2 192.0.2.2
sudo ip netns exec cn-server ping -c 2 172.16.0.2
sudo ip netns exec cn-backend ping -c 2 10.10.0.2
```

If any ping fails, stop here. Crabnet cannot work until all three physical
links are reachable.

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

Verify the dedicated NAT table:

```bash
sudo ip netns exec cn-server \
  nft list table ip crabnet_nat
```

The postrouting chain must contain a rule matching `crabnet0`,
`cn-srv-back`, `10.0.0.0/24`, and `masquerade`.

Verify the client-managed endpoint exclusion and default route:

```bash
sudo ip netns exec cn-client \
  ip route show exact 192.0.2.2/32
sudo ip netns exec cn-client \
  ip route show default
```

Expected output:

```text
192.0.2.2 dev cn-client-veth
default dev crabnet0
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

Verify that a destination outside the client's directly connected TUN network
uses the full-tunnel default route:

```bash
sudo ip netns exec cn-client \
  ip route get 10.10.0.2
```

The result must use `crabnet0`. Together, these two lookups prove that the VPN
endpoint stays on the underlay while ordinary traffic enters the tunnel.

### 9. Verify direct overlay connectivity

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

This ping uses the directly connected `10.0.0.0/24` TUN network. It validates
the tunnel transport, but not the full-tunnel default-route selection; the
route lookup above and private-service request below validate that behavior.

### 10. Test HTTP behind the server

Start the backend server:

```bash
sudo ip netns exec cn-service \
  python3 -u -m http.server 8080 --bind 10.10.0.2
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
→ nftables masquerade 10.0.0.2 to 172.16.0.1
→ backend router
→ service HTTP server
```

The service log must show `172.16.0.1` as the HTTP client address, not
`10.0.0.2`. The service returns traffic through its normal default gateway,
and nftables connection tracking reverses the translation before the server
routes the response back through TUN. Because `10.10.0.2` is outside the
client's directly connected TUN network, this request also exercises the
full-tunnel default route.

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
- Server TUN but no backend traffic: forwarding, server route, or firewall problem.
- Backend receives `10.0.0.2` as source: NAT rule or egress-interface mismatch.
- Service receives the request but client times out: NAT return-state or routing problem.

### 12. Shut down and verify restoration

Stop the client with Ctrl+C first. Its log should include reverse-order removal
of the default and endpoint routes:

```text
Removed route 0.0.0.0/0 dev crabnet0
Removed route 192.0.2.2/32 dev cn-client-veth
```

Then stop the server with Ctrl+C. Its log should include restoration of IPv4
forwarding and removal of the owned NAT table. Check both:

```bash
sudo ip netns exec cn-server \
  sysctl -n net.ipv4.ip_forward
sudo ip netns exec cn-server \
  nft list table ip crabnet_nat
```

If the original value was `0`, it should now be `0`. If it was `1`, it should
remain `1`. The nft command should fail because the table no longer exists.
Crabnet refuses to remove the table if another process changed it after
installation. A route, forwarding, or NAT operation that fails during cleanup
remains tracked for retry. Cleanup cannot run after `SIGKILL`, a kernel crash,
or power loss.

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
configures the client full-tunnel routes, server routing, forwarding, and NAT,
verifies the translated HTTP source without VPN return routes, and checks
route, sysctl, and nftables cleanup. Before starting the legitimate client, it
sends one malformed UDP datagram to the server from an ephemeral source port.
The server must count and drop that datagram without registering its sender;
the configured client at `192.0.2.1:51820` must subsequently become the active
peer.

```bash
cargo build
sudo scripts/test-local-tunnel.sh
```

Build as your normal user so `sudo` does not create root-owned Cargo artifacts.
The script refuses to reuse existing namespaces, does not change the host
default route or firewall, and removes only resources it created. It also
checks debug logs for all four framed packet boundaries:

```text
client TUN -> version 1 frame -> UDP
server UDP -> decoded inner packet -> TUN
server TUN -> version 1 frame -> UDP
client UDP -> decoded inner packet -> TUN
```

Together with successful ping and HTTP traffic, these assertions prove that
both endpoints agree on the current frame format. They do not prove
authentication, encryption, replay protection, internet DNS handling, or
compatibility with future protocol versions.
