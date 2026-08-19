# Testing

## Unprivileged checks

These do not create a TUN device or network namespace:

```bash
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo build
```

Firewall diagnostic unit tests use fake inspectors and command runners. They
cover chain filtering, policy assessment, malformed JSON, inspection failure,
timeout behavior, context construction, and the exact read-only nft command;
they do not require root or inspect the host firewall.

Protocol unit tests cover the exact version 1 data layout and pure version 2 handshake layout,
binary round trips, size boundaries, undersized output buffers, malformed headers, unsupported
fields, declared-length mismatches, every V2 truncation, role classification, cross-version
rejection, unchanged output on encode errors, borrowed payloads, and diagnostic redaction. These
V2 tests use no sockets and do not prove runtime integration. Server state tests prove that only a
valid decoded frame can register the first peer.

Pending-session policy tests cover configuration rejection, duplicate ownership, bounded capacity,
exact expiration, capacity release, monotonic identifier exhaustion, and idempotent shutdown.

Pure handshake coverage is split by responsibility:

- policy tests cover source/attempt authorization, candidates, deadlines, lifecycle, data
  decisions, duplicates, and exact cleanup;
- fake-crypto tests cover transcript phases, remote authentication failure, multiple server
  candidates, explicit commit, exact context removal, shutdown, and ID exhaustion;
- client coordinator tests cover both receive methods, precheck-before-crypto ordering, terminal
  remote failure, timeout, commit, shutdown from every stable phase, malformed result domains and
  correlations, and injected local errors;
- server coordinator tests cover ClientHello admission/replay/capacity/expiration, ClientFinish
  establishment and duplicate confirmation, candidate-scoped remote failure, cleanup dispositions,
  timeout reconciliation, shutdown, and injected transaction failures; and
- the in-memory driver transfers all four owned messages and proves matching session IDs with
  opposite authenticated peer identities.

All handshake time is supplied as `Instant`; these tests do not sleep or require sockets. Payload
and credential debug-redaction tests ensure generic diagnostics do not reveal provider values.
The pure policies and coordinators are not used by legacy V1 forwarding. Noise-IK provider tests prove the
real cryptographic exchange in memory; they do not prove encrypted data forwarding or replay protection.

## Choosing the right test

| Change | Minimum focused test |
| --- | --- |
| Packet framing or size boundary | `cargo test protocol::` |
| Candidate/session policy | `cargo test session::` |
| Fake provider transcript | `cargo test crypto::fake::tests` |
| Client coordinator | `cargo test handshake::client::tests` |
| Server coordinator | `cargo test handshake::server::tests` |
| Complete pure handshake | `cargo test handshake::tests` |
| Noise-IK provider and adapter | `cargo test crypto::noise_ik::tests` and `cargo test handshake::adapter::tests` |
| Route/NAT/firewall pure logic | Relevant module tests with fake backends |
| Runtime namespace behavior | Privileged script after explicit authorization |

Before declaring a change complete, still run the complete unprivileged gate set because
cross-module invariants can compile and fail outside the focused test.

## Privileged routed test

The repeatable test creates `cn-client`, `cn-server`, `cn-backend`, and
`cn-service`:

```bash
sudo scripts/clean-local-tunnel.sh
cargo build
sudo scripts/test-local-tunnel.sh
```

It first sends a malformed UDP datagram before the legitimate client starts and
proves that the server drops it without registering a peer. It then verifies
version 1 framing in both directions through debug-log assertions, underlay
connectivity, TUN creation, the client endpoint exclusion and TUN default
route, `server_routes`, IPv4 forwarding, nftables masquerading, the advisory
firewall diagnostic, overlay ping, translated HTTP, and cleanup.
The backend and service deliberately have no route to the VPN subnet; the
service observes `172.16.0.1` rather than `10.0.0.2`, which proves source
translation.

Successful traffic proves that both Crabnet endpoints agree on the current
frame format. It does not test Noise-IK authentication, encrypted data, or replay protection. The namespace script
continues to exercise only the explicitly unauthenticated legacy V1 path.

The default route and NAT table exist only inside their test namespaces. The
script never changes the host default route, forwarding state, or firewall.

For manual setup, follow the local test in `README.md`. Preserve the printed
log directory when diagnosing failures. A successful run ends with `PASS` and
exit status zero. The privileged test additionally requires the `nft` command
and kernel nftables NAT support.
