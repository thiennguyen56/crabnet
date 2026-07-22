# 🦀 Crabnet

> **A modular, open-source networking framework for building VPNs, overlay networks, and distributed networking systems in Rust.**

Crabnet is a learning-driven, production-inspired networking framework designed to help developers understand and build modern networking systems from the ground up.

Rather than being "yet another VPN," Crabnet provides a collection of reusable networking components that can be combined to build secure tunnels, mesh networks, cloud networking solutions, or experimental distributed systems.

---

# Why Crabnet?

Networking software is often difficult to understand because protocols, encryption, routing, NAT traversal, and transport layers are tightly coupled.

Crabnet separates these concerns into modular building blocks, making every component independently understandable, replaceable, and testable.

The goals are:

- Learn systems programming through real implementations
- Build networking components instead of black boxes
- Experiment with protocol design
- Explore performance engineering
- Understand modern VPN architecture
- Provide reusable networking libraries for Rust applications

---

# Vision

Crabnet aims to become an educational and extensible networking framework similar to how projects like Tokio provide asynchronous primitives.

Instead of shipping one fixed VPN implementation, Crabnet provides the foundation for building many networking applications.

Examples include:

- VPN
- Secure tunnels
- Overlay networks
- Mesh networking
- Peer-to-peer communication
- Remote development networking
- Distributed system transports
- Experimental routing protocols

---

# Local TUN tunnel testing

The first integration test verifies a single client tunneling IP packets to a
single server. It intentionally tests only the directly connected VPN subnet;
full internet tunneling also requires forwarding, NAT, DNS, and additional
route management.

This procedure requires Linux, `sudo`, and the `iproute2` tools. TUN
interfaces and network namespaces require root privileges or
`CAP_NET_ADMIN`.

## Test topology

Two Linux network namespaces simulate two independent machines:

```text
cn-client namespace                         cn-server namespace

TUN:      10.0.0.2/24                       TUN:      10.0.0.1/24
UDP:      192.0.2.1:51820                   UDP:      192.0.2.2:51821
                 \                            /
                  +------ virtual veth -------+
```

There are two networks:

- The **underlay** `192.0.2.0/24` carries Crabnet UDP datagrams.
- The **overlay** `10.0.0.0/24` is the private IP network carried inside
  those datagrams.

Namespaces are important because running both endpoints in the host network
namespace lets one kernel own both VPN addresses. The kernel could then deliver
packets locally and bypass Crabnet, producing a false-positive test.

## 1. Build and check the project

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features
cargo build
```

This separates Rust, formatting, and configuration failures from privileged
networking failures. The remaining commands use `target/debug/crabnet`.

## 2. Check the test configuration

`config/client/config.toml` should use:

```toml
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
```

`config/server/config.toml` should use:

```toml
log_level = "debug"

[mode]
type = "server"
bind_addr = "192.0.2.2:51821"

[tun]
name = "crabnet0"
address = "10.0.0.1"
prefix_len = 24
mtu = 1400
```

The same TUN name is safe here because each interface is created in a different
network namespace.

## 3. Create two isolated network stacks

```bash
sudo ip netns add cn-client
sudo ip netns add cn-server

sudo ip link add cn-client-veth type veth peer name cn-server-veth
sudo ip link set cn-client-veth netns cn-client
sudo ip link set cn-server-veth netns cn-server
```

A veth pair acts as a virtual Ethernet cable between the namespaces. Without
it, the client UDP socket has no network path to the server UDP socket.

Assign an underlay address to each end:

```bash
sudo ip netns exec cn-client \
  ip address add 192.0.2.1/24 dev cn-client-veth

sudo ip netns exec cn-server \
  ip address add 192.0.2.2/24 dev cn-server-veth
```

Enable the veth and loopback interfaces:

```bash
sudo ip netns exec cn-client ip link set lo up
sudo ip netns exec cn-client ip link set cn-client-veth up

sudo ip netns exec cn-server ip link set lo up
sudo ip netns exec cn-server ip link set cn-server-veth up
```

## 4. Verify the underlay first

```bash
sudo ip netns exec cn-client ping -c 2 192.0.2.2
```

This checks only the veth network. If it fails, fix the namespace setup before
debugging Crabnet because UDP cannot reach the server without a working
underlay.

## 5. Start the server and client

Start the server in one terminal:

```bash
sudo ip netns exec cn-server \
  ./target/debug/crabnet --config-path config/server/config.toml
```

Start the client in a second terminal:

```bash
sudo ip netns exec cn-client \
  ./target/debug/crabnet --config-path config/client/config.toml
```

`ip netns exec` is required so each process creates its socket, TUN device,
addresses, and routes inside the intended isolated network stack.

## 6. Verify TUN addresses and routes

```bash
sudo ip netns exec cn-client ip address show crabnet0
sudo ip netns exec cn-server ip address show crabnet0

sudo ip netns exec cn-client ip route show
sudo ip netns exec cn-server ip route show
```

Expected connected routes:

```text
client: 10.0.0.0/24 dev crabnet0 src 10.0.0.2
server: 10.0.0.0/24 dev crabnet0 src 10.0.0.1
```

The route tells each kernel to place packets for `10.0.0.0/24` on its TUN
interface. Without it, Crabnet never receives those packets.

If the connected route was not created automatically, add it in the affected
namespace:

```bash
sudo ip netns exec cn-client ip route add 10.0.0.0/24 dev crabnet0
sudo ip netns exec cn-server ip route add 10.0.0.0/24 dev crabnet0
```

Only run these commands when the route is missing; adding an existing route
returns a `File exists` error.

## 7. Ping across the overlay

From a third terminal:

```bash
sudo ip netns exec cn-client \
  ping -c 4 -I 10.0.0.2 10.0.0.1
```

The ping must run inside `cn-client`. A ping started in the host namespace
does not use the client namespace's TUN interface.

For the first request, the logical log order is:

```text
CLIENT  Client TUN -> UDP: sending ... bytes to 192.0.2.2:51821
SERVER  Registered active peer 192.0.2.1:51820
SERVER  Server UDP -> TUN: writing ... bytes from 192.0.2.1:51820
SERVER  Server TUN -> UDP: sending ... bytes to 192.0.2.1:51820
CLIENT  Client UDP -> TUN: writing ... bytes from 192.0.2.2:51821
```

`Registered active peer` appears only for the first accepted datagram. The
remaining four forwarding messages repeat for subsequent ping requests.

TUN direction is from Crabnet's perspective:

```text
tun.recv() / read  = local OS -> Crabnet
tun.send() / write = Crabnet -> local OS
```

Therefore, `Client UDP -> TUN` means Crabnet injects the remote response into
the client kernel, which then delivers it to `ping`.

## 8. Test an application protocol

Ping verifies ICMP and basic bidirectional forwarding. HTTP additionally
exercises a TCP handshake, acknowledgements, multiple packets, and application
data.

Start an HTTP server in the server namespace:

```bash
sudo ip netns exec cn-server \
  python3 -m http.server 8080 --bind 10.0.0.1
```

Request it from the client namespace:

```bash
sudo ip netns exec cn-client curl http://10.0.0.1:8080
```

## 9. Diagnose where a packet stops

If available, use `tcpdump` at each layer.

Observe inner packets entering the client TUN:

```bash
sudo ip netns exec cn-client tcpdump -ni crabnet0
```

Observe outer UDP datagrams on the underlay:

```bash
sudo ip netns exec cn-client \
  tcpdump -ni cn-client-veth udp port 51821
```

Observe inner packets on the server TUN:

```bash
sudo ip netns exec cn-server tcpdump -ni crabnet0
```

Interpret the first missing observation:

- No client TUN packet: the ping ran in the wrong namespace or the client route
  is missing.
- Client TUN log but no server UDP log: check veth connectivity and socket
  addresses.
- Server UDP-to-TUN log but no TUN-to-UDP log: the server kernel did not
  generate or route a response.
- Server TUN-to-UDP log but no client UDP log: check the return underlay path.
- Client UDP-to-TUN log but ping times out: check the client address, route, and
  packet integrity.

## 10. Shut down and clean up

Stop Crabnet and the HTTP server with Ctrl+C, then remove the dedicated test
namespaces:

```bash
sudo ip netns delete cn-client
sudo ip netns delete cn-server
```

Deleting the namespaces removes their veth endpoints, TUN interfaces,
namespace-specific addresses, and routes. Cleanup prevents stale test state
from affecting the next run.

Do not test full internet access yet. Reaching a site such as `google.com`
also requires a client default route, an exclusion route for the Crabnet server
endpoint, server IP forwarding, firewall forwarding, NAT, DNS handling, and a
working return path.
