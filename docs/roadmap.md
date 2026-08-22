# Crabnet roadmap

This is the current implementation roadmap. It describes forward work from the existing
Noise-IK handshake runtime and does not replace historical milestone notes.

## Current state

- Legacy V1 TUN-over-UDP forwarding, routing, forwarding diagnostics, and IPv4 NAT are available
  for the isolated namespace lab.
- Noise-IK key loading, provider logic, V2 framing, adapter validation, and the Tokio handshake
  runtime are implemented.
- Noise-IK currently stops after `SessionEstablished`; it does not forward plaintext or encrypted
  data yet.
- The namespace lab configs intentionally remain in explicit `legacy` mode.

## 1. Encrypted V2 data plane

Implement the encrypted packet protocol described in
[`encrypted-v2-data-plane-design.md`](encrypted-v2-data-plane-design.md).

Deliverables:

- freeze the V2 data-frame layout and authenticated-data fields;
- derive and own directional transport state from the established Noise-IK session;
- add sequence numbers, nonce uniqueness, replay-window checks, and key-exhaustion behavior;
- encrypt TUN packets before UDP transmission;
- authenticate, decrypt, validate, and write received packets to TUN;
- keep malformed, replayed, unknown-session, and authentication-failed packets non-fatal;
- keep local crypto, I/O, invariant, and cleanup failures fatal; and
- preserve explicit V1/V2 mode separation with no plaintext fallback.

Acceptance criteria:

- no data packet is accepted before a committed Noise-IK session;
- no nonce or sequence number is reused under one directional key;
- replay-window state advances only after successful authentication;
- complete UDP/TUN writes are required before success is counted; and
- focused pure tests and unprivileged Tokio tests pass.

## 2. End-to-end encrypted namespace test

Add a dedicated Noise-IK namespace scenario after the pure data-plane tests pass.

The test should:

- generate fresh ephemeral lab keys;
- configure client and server Noise-IK pins/allowlists;
- prove encrypted ping and HTTP traffic;
- tamper with ciphertext and verify that packets are dropped;
- replay captured datagrams and verify that the endpoints remain alive; and
- preserve the existing legacy namespace test for V1 routing, forwarding, and NAT.

The Noise-IK test must not silently reuse the legacy configs or assertions.

## 3. Session lifecycle and rekeying

After encrypted traffic works, define the long-lived session behavior:

- maximum sequence and packet/byte limits;
- rekey protocol or controlled session restart;
- idle timeout and orderly shutdown;
- endpoint migration policy;
- key erasure during close, failure, and rekey; and
- duplicate, delayed, reordered, and lost packet behavior during transitions.

No counter may wrap or silently reuse a nonce. If rekeying is not yet implemented, the safe
behavior is to stop and close before key exhaustion.

## 4. Operational hardening

Harden the encrypted runtime before describing it as suitable beyond the lab:

- bound pending candidates, established sessions, buffers, and work per peer;
- add rate-limited diagnostics and non-secret counters;
- fuzz V2 parsing, data-frame decoding, and replay-window transitions;
- test cancellation races and cleanup failures;
- define MTU/path-MTU behavior and fragmentation policy;
- document key rotation and provisioning procedures;
- run dependency/advisory/license checks in CI; and
- obtain an independent security review of the protocol and implementation.

Remote hostile input must remain a drop-and-continue path. Local invariant, crypto-state, and
resource failures must remain fail-closed with route/NAT restoration.

## 5. VPN feature completeness

Once the encrypted single-peer lab path is stable, expand product capability deliberately:

- multi-peer identity and session management;
- IPv6 data-plane coverage;
- DNS configuration and full-tunnel DNS handling;
- explicit firewall policy integration and documentation;
- deployment and packaging workflows;
- observability for session and packet health; and
- migration/version-negotiation policy for future protocol changes.

These features must not weaken authentication, replay protection, route ownership, or the explicit
legacy/V2 mode boundary.

## Release boundary

The encrypted data plane plus its dedicated namespace test can establish an encrypted lab VPN
milestone. Production or public-network claims require the lifecycle, hardening, operational, and
security-review work above. A successful Noise-IK handshake alone is not a usable VPN session.
