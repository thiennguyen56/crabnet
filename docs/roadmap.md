# Crabnet roadmap

This is the current implementation roadmap. It describes forward work from the completed encrypted
single-peer lab path and does not replace historical milestone notes.

## Current state

- Legacy V1 TUN-over-UDP forwarding, routing, forwarding diagnostics, and IPv4 NAT are available
  for the isolated namespace lab.
- Noise-IK key loading, provider logic, V2 framing, adapter validation, encrypted data frames,
  replay checks, and Tokio forwarding are implemented.
- Noise-IK application binding owns the configured TUN and applies/restores the same client routes
  or server forwarding/NAT state as legacy mode; it forwards only after session commitment.
- `scripts/test-noise-ik-tunnel.sh` proves a committed encrypted overlay ping, MTU boundary,
  malformed-datagram drop, and continued service. The legacy namespace configs remain explicit V1.

## 1. Adversarial encrypted namespace coverage

Extend the dedicated Noise-IK namespace scenario beyond its current happy-path and malformed-input
coverage. `scripts/test-noise-ik-adversarial.sh` covers replay/tamper drops plus routed NAT and
cleanup; retain it as the regression suite while preserving the legacy namespace test for V1
routing, forwarding, and NAT.

The Noise-IK test must not silently reuse legacy configurations or assertions.

## 2. Session lifecycle and rekeying

After encrypted traffic works, define the long-lived session behavior:

- maximum sequence and packet/byte limits;
- rekey protocol or controlled session restart;
- idle timeout and orderly shutdown;
- endpoint migration policy;
- key erasure during close, failure, and rekey; and
- duplicate, delayed, reordered, and lost packet behavior during transitions.

No counter may wrap or silently reuse a nonce. If rekeying is not yet implemented, the safe
behavior is to stop and close before key exhaustion.

## 3. Operational hardening

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

## 4. VPN feature completeness

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
