# Architecture

Crabnet is currently a Linux/Tokio TUN-over-UDP prototype.

```text
CLI/config
   ↓
Application::bind
   ├─ Client::bind or Server::bind
   ├─ full-tunnel client: resolve VPN-server underlay route
   └─ RouteManager::install
           ↓
      iproute2/sysctl

Client/Server::run
   ├─ TUN read → packet validation → UDP send
   └─ UDP receive → peer/MTU validation → TUN write

Shutdown
   └─ RouteManager::restore
```

## Runtime components

- `src/main.rs`: parses CLI arguments, validates configuration, initializes logging.
- `src/config.rs`: TOML/CLI configuration and mode validation.
- `src/application.rs`: binds the selected client/server and owns route cleanup.
- `src/client.rs`: connected UDP client and bidirectional forwarding loop.
- `src/server.rs`: single-peer UDP server and bidirectional forwarding loop.
- `src/tun.rs`: TUN creation, MTU validation, and packet I/O.
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
