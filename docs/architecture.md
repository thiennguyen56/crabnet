# Architecture

Crabnet is a Linux/Tokio TUN-over-UDP learning prototype with two deliberately separate data paths:

- an active legacy version 1 packet-forwarding runtime; and
- a Noise-IK runtime that authenticates the V2 handshake before forwarding encrypted data frames.

```text
CLI/config
   ↓
Application::bind
   ├─ Client
   │  ├─ resolve full-tunnel VPN-server underlay route
   │  └─ RouteManager::install → iproute2
   ├─ NoiseIk runtime
   │  ├─ UDP socket and V2 adapter
   │  ├─ Noise-IK coordinator
   │  └─ encrypted data session after commitment
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

Pure handshake and adapter tests
   ├─ Client/Server session policy
   ├─ Client/Server handshake coordinator
   ├─ Noise-IK and fake providers
   └─ Version 2 handshake codec and runtime adapter
```

The vertical runtime path moves real packets and changes Linux network state. The pure handshake
path moves owned Rust values in memory and changes no OS state. The Noise-IK adapter already
connects the reviewed profile to the coordinator; fake crypto remains test-only.

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
- `src/protocol.rs`: active version 1 data framing and the pure, bounded version 2 handshake
  codec.
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
- `src/handshake/adapter.rs`: V2 decode, direction and exact-size validation, coordinator dispatch, and encoding.
- `src/crypto/noise_ik/`: Noise-IK profile, key loading, and client/server providers.
- `src/noise_runtime.rs`: Tokio V2 handshake runtime; it converts validated session limits, commits
  Noise-IK, and transfers the committed transport plus limits to the data plane.
- `src/data_plane/session.rs`: sequence allocation, replay state, and the established-session
  lifetime module for packet, byte, and idle limits.
- `src/data_plane/runtime.rs`: encrypted TUN/UDP forwarding, controlled session close, and the
  idle-deadline `tokio::select!` branch.

See [`handshake.md`](handshake.md) for the learning-oriented explanation and the coordinator contract. [`diagrams.md`](diagrams.md) provides the current runtime, handshake,
state-machine, failure, and planned-integration views in one place.

## Current execution boundary

Version 1 remains an explicit legacy data protocol. Noise-IK validates and authenticates the
four V2 handshake messages, then starts an encrypted data session rather than entering V1
forwarding. The pure subsystem proves the intended four-message coordination:

```text
ClientHello → ServerHello → ClientFinish → ServerFinish
```

The coordinator validates source and lifecycle through policy before invoking crypto, validates all
crypto result correlations, commits identical authenticated metadata in policy and crypto, and
fails closed on local errors or invariant violations. Successful remote rejection is reported as a
typed drop rather than a fatal local error.

The encrypted data path owns frame encoding, header binding, sequence allocation, replay checks,
session limits, and TUN/UDP forwarding after coordinator commitment. A controlled limit, idle, or
sequence-exhaustion close returns normally to `Application`, which restores owned routes,
forwarding, and NAT. Rekeying and multi-peer routing remain future work. Dedicated basic and
adversarial Noise-IK namespace tests cover encrypted delivery, replay/tamper drops, routing, NAT,
and cleanup.

The legacy V1 server intentionally supports one active UDP peer and has no authentication.
Noise-IK also supports one active peer, but authenticates it with the configured public-key allowlist.
Both are lab/test boundaries, not production-security claims.

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

These are related design habits, but they are not the same transaction. The committed Noise-IK
runtime is integrated with application route/NAT cleanup; the pure handshake subsystem remains
privilege-free and independently testable.
