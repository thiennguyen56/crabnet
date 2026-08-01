# Crabnet agent guide

## Scope

These instructions apply to the entire repository. Add a nested `AGENTS.md` only when a
subtree develops genuinely different build, test, or safety requirements.

## Project orientation

Crabnet is a Linux-only learning prototype that forwards raw IP packets between a TUN
device and UDP using Rust and Tokio. It is not a production VPN: the server supports one
unauthenticated peer, and encryption, replay protection, NAT, firewall automation, and
full-tunnel DNS handling are not implemented.

Important paths:

- `src/application.rs`: binds client/server runtime components and owns route cleanup.
- `src/client.rs` and `src/server.rs`: bidirectional TUN/UDP forwarding loops.
- `src/tun.rs`: TUN construction, MTU validation, and packet I/O.
- `src/routing/manager.rs`: platform-neutral route operations, ownership, rollback, and
  restoration.
- `src/routing/linux.rs`: Linux `iproute2` and `sysctl` backend.
- `src/config.rs`: TOML/CLI parsing and cross-field validation.
- `config/`: namespace-lab client and server examples.
- `scripts/test-local-tunnel.sh`: privileged four-namespace integration test.
- `docs/architecture.md`, `docs/configuration.md`, `docs/testing.md`,
  `docs/protocol.md`, `docs/security-limitations.md`, and
  `docs/routing-sequences.md`: current documentation.
- `docs/STAGE1.md`, `docs/STAGE1_MINOBOOK.md`, and `docs/milestones1.md`:
  historical learning and planning notes; do not treat them as current behavior.

## Working agreements

- Inspect the working tree before editing. Preserve unrelated or pre-existing changes.
- Keep changes scoped to the requested behavior. Do not add dependencies or broaden
  protocol/security claims without discussing the tradeoff first.
- For review or diagnosis requests, remain read-only unless implementation is explicitly
  requested. Report completed, missing, and incorrect behavior with file-level evidence.
- Prefer small pure helpers for route parsing, packet decisions, and validation so unit
  tests do not require root, TUN creation, or network namespaces.
- Use `anyhow::Context` at OS, parsing, and I/O boundaries. Error messages should identify
  the failed operation and relevant address, interface, route, or configuration field.
- Update current docs, example configuration, and the integration script when behavior or
  operator-visible output changes. Leave historical notes unchanged unless the task is
  specifically about them.

## Rust conventions

### Style and naming

- Follow `rustfmt.toml`: Rust 2021, two-space indentation, 100-column width, and reordered
  imports. Do not hand-format against `rustfmt` output.
- Use standard Rust naming: `snake_case` for modules, functions, variables, and tests;
  `UpperCamelCase` for types and traits; and `SCREAMING_SNAKE_CASE` for constants.
- Prefer names that express networking direction or ownership, such as `tun_to_udp`,
  `underlay`, `applied`, and `previous`, over generic names such as `data` or `state2`.
- Keep imports grouped as standard library, external crates, then `crate`/`super` imports.
  Let rustfmt order imports within those groups. Avoid glob imports outside test modules.
- Keep functions focused on one responsibility. Extract pure parsing, classification, and
  argument-building helpers when doing so makes privileged behavior testable in memory.
- Prefer exhaustive `match` expressions for protocol, packet, peer, and route state. Avoid
  catch-all arms when adding a variant should force callers to make an explicit decision.

### Ownership and data

- Borrow with `&T` or `&mut T` when ownership is not transferred. Clone only at a real
  ownership boundary, especially for route/interface strings and packet buffers.
- Use slices for packet data and avoid unnecessary allocation in forwarding loops. Allocate
  reusable receive buffers before `tokio::select!`, not once per packet.
- Keep mutable policy and counters in small state structs so decisions can be tested without
  sockets or TUN devices.
- Use saturating arithmetic for long-lived packet and byte counters.
- Preserve raw packet bytes. Never interpret forwarded payloads as UTF-8.

### Errors, logging, and unsafe code

- Do not use `unwrap`, `expect`, `panic!`, `todo!`, or `unimplemented!` in production paths.
  Return an error, reject unsupported configuration during validation, or handle the state
  explicitly. They are acceptable in tests when failure means the fixture itself is invalid.
- Use `anyhow::Result` at application and OS-integration boundaries. Use `ensure!` or `bail!`
  for invariant violations and add `anyhow::Context` where an operation crosses an I/O,
  parsing, command, socket, TUN, or configuration boundary.
- Error messages must say what failed and include safe identifying context such as an
  address, route, interface, peer, or configuration field. Never log raw packet payloads.
- Propagate socket and TUN I/O failures with context. Deliberately dropped traffic must be
  observable through logs or counters.
- Treat partial UDP or TUN writes as errors; never report a truncated packet as forwarded.
- Avoid `unsafe`. If it becomes unavoidable, isolate it behind a small safe API, document a
  `SAFETY:` invariant at every unsafe block, and add focused tests for the boundary.

### Async and Tokio

- Keep `tokio::select!` branches small and cancellation-aware. Move substantial branch logic
  into ordinary async or pure helper functions when it improves readability or testing.
- Create and pin the Ctrl+C future once outside the forwarding loop; do not recreate it on
  every iteration.
- Do not hold a synchronous lock or mutable borrow across `.await` unless its lifetime and
  cancellation behavior are deliberate and documented.
- Do not call blocking filesystem, process, or network APIs from packet-forwarding tasks.
  Startup-only synchronous configuration reads are acceptable.
- Receive UDP into an `MTU + 1` buffer so oversized datagrams can be detected and dropped
  without truncation being mistaken for a valid packet.
- Keep the current single-peer server invariant: the first valid datagram selects the peer;
  empty, oversized, and unexpected-peer datagrams must not replace it.

### Documentation and tests

- Maintain the crate-level `missing_docs` lint. Document public modules, types, variants,
  fields, and functions, plus private helpers whose invariants, side effects, ownership, or
  failure behavior are not obvious.
- Rustdoc should explain purpose and behavior rather than restating the signature. Mention
  ordering requirements, privileged effects, cleanup ownership, and important error cases.
- Keep `#[cfg(test)] mod tests` beside the code it covers. Name tests after observable
  behavior, and cover success, boundary, rejection, rollback, and retry paths as applicable.
- Prefer fake backends and command runners for OS integration. Unit tests must not require
  root, create a real TUN device, or modify network namespaces.

## Routing invariants

- Resolve the VPN server's underlay route before installing a full-tunnel default route.
- Install the server endpoint `/32` or `/128` underlay route before the TUN default route;
  restore owned operations in reverse order.
- `protected_routes` is split-tunnel-only and must remain mutually exclusive with
  `full_tunnel`.
- Never delete or claim ownership of a pre-existing identical route or sysctl value.
- Refuse conflicting routes and refuse to remove state that changed after Crabnet installed
  it.
- The current full-tunnel implementation is for isolated routing domains without a
  conflicting default route. Do not silently replace a host default route.
- `server_routes`, IPv4 forwarding, and future NAT behavior are server-only.
  `enable_nat = true` must remain rejected until NAT is actually implemented and tested.
- Backend and service return routes are environment-owned; Crabnet must not mutate them.

## Verification

Run focused tests while iterating. Before declaring a code change complete, run:

```bash
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo build
git diff --check
```

For shell changes, also run:

```bash
bash -n scripts/test-local-tunnel.sh scripts/clean-local-tunnel.sh
```

The privileged integration test is:

```bash
sudo scripts/test-local-tunnel.sh
```

It creates and deletes the `cn-client`, `cn-server`, `cn-backend`, and `cn-service`
network namespaces and requires Linux, root or `CAP_NET_ADMIN`, `iproute2`, `sysctl`,
`ping`, `curl`, and Python. Do not run it implicitly: state the host-level effects and get
explicit authorization first. Preserve the printed log directory when it fails.

If a privileged check cannot be run, report that clearly and distinguish it from the
unprivileged checks that passed. A sandbox error such as
`bwrap: loopback: Failed RTM_NEWADDR` is a tooling failure, not a repository failure.

## Done criteria

A change is complete only when:

- requested behavior and failure paths are covered by focused tests;
- relevant unprivileged checks pass;
- privileged verification was either run successfully or explicitly reported as not run;
- cleanup and rollback behavior remain correct;
- current docs and example configuration match the implementation; and
- the final diff contains no accidental or unrelated edits.

## Code Review Rules

- Flag any path that can route the VPN server endpoint into the TUN default route. Safe
  path: resolve the underlay first and install a more-specific endpoint exclusion.
- Flag rollback that removes unowned or externally changed routes/sysctls. Safe path:
  record only applied operations, compare before removal, and restore in reverse order.
- Flag packet handling that can truncate or reinterpret binary data. Safe path: preserve
  byte slices and use `MTU + 1` for oversize detection.
- Flag claims that full internet tunneling or production security is complete while NAT,
  firewall, DNS, authentication, or encryption remains absent.
- Flag unit tests that create real TUN devices or namespaces when the branch can be tested
  through a pure helper or fake backend.
