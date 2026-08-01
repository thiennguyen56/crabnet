# Testing

## Unprivileged checks

These do not create a TUN device or network namespace:

```bash
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

## Privileged routed test

The repeatable test creates `cn-client`, `cn-server`, `cn-backend`, and
`cn-service`:

```bash
sudo scripts/clean-local-tunnel.sh
cargo build
sudo scripts/test-local-tunnel.sh
```

It verifies underlay connectivity, TUN creation, client routes,
`server_routes`, backend forwarding, return routes, overlay ping, HTTP, and
cleanup. The script never changes the host default route or host firewall.

For manual setup, follow the local test in `README.md`. Preserve the printed
log directory when diagnosing failures. A successful run ends with `PASS` and
exit status zero.
