# Architecture

Crabnet is currently a Linux/Tokio TUN-over-UDP prototype.

```text
CLI/config
   ↓
Application::bind
   ├─ Client
   │  ├─ resolve full-tunnel VPN-server underlay route
   │  └─ RouteManager::install → iproute2
   └─ Server
      ├─ FirewallDiagnostics → read-only nftables inspection
      ├─ NatManager::install → nftables
      └─ RouteManager::install → iproute2/sysctl

Client/Server::run
   ├─ TUN read → packet validation → frame encode → UDP send
   └─ UDP receive → frame/peer validation → frame decode → TUN write

Shutdown
   ├─ Client: RouteManager::restore
   └─ Server
      ├─ RouteManager::restore
      └─ NatManager::restore
```

## Runtime components

- `src/main.rs`: parses CLI arguments, validates configuration, initializes logging.
- `src/config.rs`: TOML/CLI configuration and mode validation.
- `src/application.rs`: binds endpoints and coordinates route, forwarding, and NAT cleanup.
- `src/client.rs`: connected UDP client and bidirectional forwarding loop.
- `src/server.rs`: single-peer UDP server and bidirectional forwarding loop.
- `src/tun.rs`: TUN creation, MTU validation, and packet I/O.
- `src/firewall/diagnostics.rs`: forwarding-path context, nftables chain parsing,
  policy assessment, and advisory reporting.
- `src/firewall/linux.rs`: bounded read-only `nft -j list chains` command integration.
- `src/nat/manager.rs`: NAT intent, ownership, retry, and restoration.
- `src/nat/linux.rs`: atomic nftables installation, inspection, and cleanup.
- `src/routing/manager.rs`: route operations, ownership, rollback, and restoration.
- `src/routing/linux.rs`: `ip` and `sysctl` command backend.
- `src/protocol.rs`: version 1 frame encoding, decoding, and MTU-aware buffer boundaries.
- `src/session.rs`: bounded pending-handshake ownership, capacity, expiration, and shutdown policy.
- `src/session/client.rs`: pure client handshake states, authenticated-result transitions,
  per-phase deadlines, pre-session data decisions, and terminal shutdown.
- `src/crypto.rs`: reserved extension point for a future reviewed cryptographic protocol.

The pure session policies are not connected to UDP forwarding yet. Version 1 remains the only
active wire protocol, so no authentication, encryption, or secure handshake is active at runtime.

The server intentionally supports one active UDP peer and has no authentication.
This is a lab/test boundary, not a security boundary.

For a full-tunnel client, route setup is intentionally ordered. Crabnet resolves
the VPN server's route before installing any routes, installs a host route for
that endpoint through the original underlay, and only then installs the TUN
default route. Rollback occurs in reverse order. Resolving after the default
route was installed could select the TUN itself and recursively route Crabnet's
UDP transport.

When server IPv4 forwarding is enabled, startup first performs a bounded,
read-only inspection of IPv4-relevant nftables forward base-chain policies.
Diagnostics are advisory and do not evaluate individual rules or change
firewall state. Startup then installs the dedicated NAT table before routes and
IPv4 forwarding. Because the forwarding operation is last in the route
operation list, reverse restoration disables owned forwarding before removing
routes; NAT cleanup follows. If route installation fails after NAT succeeds,
startup attempts NAT rollback before returning the error.

The NAT backend fingerprints normalized nftables JSON after installation.
Packet and byte counters may change, but any structural change causes cleanup
to refuse deletion rather than removing externally modified state.
