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
      ├─ NatManager::install → nftables
      └─ RouteManager::install → iproute2/sysctl

Client/Server::run
   ├─ TUN read → packet validation → UDP send
   └─ UDP receive → peer/MTU validation → TUN write

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
- `src/nat/manager.rs`: NAT intent, ownership, retry, and restoration.
- `src/nat/linux.rs`: atomic nftables installation, inspection, and cleanup.
- `src/routing/manager.rs`: route operations, ownership, rollback, and restoration.
- `src/routing/linux.rs`: `ip` and `sysctl` command backend.
- `src/protocol.rs`, `src/crypto.rs`, `src/session.rs`: reserved extension points; no wire encryption or handshake is active yet.

The server intentionally supports one active UDP peer and has no authentication.
This is a lab/test boundary, not a security boundary.

For a full-tunnel client, route setup is intentionally ordered. Crabnet resolves
the VPN server's route before installing any routes, installs a host route for
that endpoint through the original underlay, and only then installs the TUN
default route. Rollback occurs in reverse order. Resolving after the default
route was installed could select the TUN itself and recursively route Crabnet's
UDP transport.

Server startup installs the dedicated NAT table before routes and IPv4
forwarding. Because the forwarding operation is last in the route operation
list, reverse restoration disables owned forwarding before removing routes;
NAT cleanup follows. If route installation fails after NAT succeeds, startup
attempts NAT rollback before returning the error.

The NAT backend fingerprints normalized nftables JSON after installation.
Packet and byte counters may change, but any structural change causes cleanup
to refuse deletion rather than removing externally modified state.
