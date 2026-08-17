# Architecture

Crabnet is a Linux/Tokio TUN-over-UDP learning prototype with two deliberately separate tracks:

- an active version 1 packet-forwarding runtime; and
- a completed pure authenticated-handshake subsystem that is not wired into that runtime yet.

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

Pure handshake tests only
   ├─ Client/Server session policy
   ├─ Client/Server handshake coordinator
   └─ Fake crypto provider
```

The vertical runtime path moves real packets and changes Linux network state. The pure handshake
path moves owned Rust values in memory and changes no OS state. A future transport adapter will
connect a reviewed protocol to the coordinator; fake crypto must never be used for live security.

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
- `src/session/server.rs`: source-bound candidate admission, duplicate handling, authenticated
  session policy, timeout reconciliation, and shutdown.
- `src/crypto/client.rs` and `src/crypto/server.rs`: provider-independent crypto traits.
- `src/crypto/types.rs`: prepared/authenticated results, shared failure domains, phases, and
  non-secret cleanup outcomes.
- `src/crypto/fake.rs`: deterministic in-memory provider used only for pure tests.
- `src/handshake/client.rs` and `src/handshake/server.rs`: policy/crypto transaction coordinators.
- `src/handshake/types.rs`: transport-neutral messages, reports, events, and fatal errors.

See [`handshake.md`](handshake.md) for the learning-oriented explanation and
[`milestone-2.3-pure-handshake-coordination-design.md`](milestone-2.3-pure-handshake-coordination-design.md)
for the exhaustive contract. [`diagrams.md`](diagrams.md) provides the current runtime, handshake,
state-machine, failure, and planned-integration views in one place.

## Current execution boundary

Version 1 remains the only active wire protocol. It contains data frames only, so no authentication,
encryption, or secure handshake is active in the executable. The pure subsystem nevertheless proves
the intended four-message coordination:

```text
ClientHello → ServerHello → ClientFinish → ServerFinish
```

The coordinator validates source and lifecycle through policy before invoking crypto, validates all
crypto result correlations, commits identical authenticated metadata in policy and crypto, and
fails closed on local errors or invariant violations. Successful remote rejection is reported as a
typed drop rather than a fatal local error.

The next architecture boundary is not “call the fake coordinator from the socket loop.” It is:

1. select a reviewed authenticated protocol or library;
2. define version 2 bytes, configuration, downgrade behavior, and data-session binding;
3. implement a parser/serializer that produces and consumes the owned handshake messages;
4. integrate coordinator deadlines and outbound effects into cancellation-aware Tokio loops; and
5. activate packet forwarding only after establishment.

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

## Ownership and failure model

Runtime OS managers record only state Crabnet actually applied. Restoration compares current state
before removal and proceeds in reverse order. Handshake coordinators similarly own their policy and
crypto instances exclusively: a local failure shuts down both layers and returns the primary error
plus both cleanup outcomes.

These are related design habits, but they are not the same transaction. Runtime route/NAT cleanup
is currently independent of pure handshake lifecycle because the subsystems are not integrated.
