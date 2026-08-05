# Testing

## Unprivileged checks

These do not create a TUN device or network namespace:

```bash
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

Firewall diagnostic unit tests use fake inspectors and command runners. They
cover chain filtering, policy assessment, malformed JSON, inspection failure,
timeout behavior, context construction, and the exact read-only nft command;
they do not require root or inspect the host firewall.

Protocol unit tests cover the exact version 1 wire layout, binary round trips,
MTU boundaries, undersized output buffers, malformed headers, unsupported
fields, and declared-length mismatches. Server state tests prove that only a
valid decoded frame can register the first peer.

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
frame format. It does not test authentication, encryption, or replay
protection.

The default route and NAT table exist only inside their test namespaces. The
script never changes the host default route, forwarding state, or firewall.

For manual setup, follow the local test in `README.md`. Preserve the printed
log directory when diagnosing failures. A successful run ends with `PASS` and
exit status zero. The privileged test additionally requires the `nft` command
and kernel nftables NAT support.
