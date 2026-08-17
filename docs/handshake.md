# Pure handshake guide

This guide is the shortest path to understanding Crabnet's completed Milestone 2.3 handshake
subsystem. For the exhaustive design contract and pseudocode, see
[`milestone-2.3-pure-handshake-coordination-design.md`](milestone-2.3-pure-handshake-coordination-design.md).

## Current status

The authenticated handshake is implemented and tested as synchronous, transport-neutral Rust
code. It is **not connected to the UDP forwarding runtime**. The executable still uses version 1
data frames and the first valid frame selects the server peer without authentication.

This separation is deliberate:

```text
implemented pure subsystem                 active runtime

session policy                             TUN packet
      ↕                                         ↓
handshake coordinator                     version 1 frame
      ↕                                         ↓
fake crypto provider                      UDP datagram

no sockets, no bytes, no Tokio             no secure handshake
```

A passing pure handshake test proves state-machine and coordination behavior. It does not make the
running VPN encrypted or authenticated.

## Why there are three layers

Each layer owns a different kind of truth:

| Layer | Owns | Must not own |
| --- | --- | --- |
| Session policy | endpoints, attempts, candidates, deadlines, lifecycle, admission | credentials, proofs, wire bytes, socket I/O |
| Crypto provider | opaque payloads, proof checks, transcript contexts, authenticated metadata | network-source authorization, timeouts, UDP sends |
| Coordinator | ordering policy and crypto calls, validating correlations, reports, fail-closed cleanup | cryptographic algorithms, transport scheduling |

Keeping these responsibilities separate makes the difficult behavior testable without root,
sockets, a TUN device, sleeps, or real secrets.

## The four-message flow

```text
Client                          Server
  |                               |
  | ClientHello(attempt, payload) |
  |------------------------------>|
  |                               | admit source as candidate
  |                               | authenticate ClientHello
  | ServerHello(attempt, payload) |
  |<------------------------------|
  | authorize source and attempt  |
  | authenticate ServerHello      |
  | ClientFinish(attempt, payload)|
  |------------------------------>|
  |                               | select candidate by source
  |                               | authenticate and commit session
  | ServerFinish(attempt, payload)|
  |<------------------------------|
  | authenticate and commit       |
  |                               |
  | both report the same session ID
```

Transport envelopes carry only a client attempt ID and an opaque provider payload. Candidate IDs
are server-local ownership tokens and never come from untrusted transport metadata.

## Important identifiers

- `ClientAttemptId` identifies one client attempt. The client creates it and every response must
  correlate to it.
- `CandidateId` identifies a server-side pending candidate. Server policy assigns it after
  admitting a source address.
- `SessionId` identifies the committed authenticated session. The fake server provider allocates
  it for tests.
- `PeerIdentity` is authenticated metadata produced by the provider. It is not a socket address.
- `SocketAddr` remains policy metadata. Receiving a valid proof from the wrong source is still
  rejected before crypto.

## Stable cross-layer states

The coordinator allows only these externally visible pairs:

| Client policy | Client crypto |
| --- | --- |
| `Idle` | `Idle` |
| `AwaitingServerHello` | `AwaitingServerHello` |
| `AwaitingServerFinish` | `AwaitingServerFinish` |
| `Established` | `Established` |
| `Closed` | `Closed` |

| Server policy | Server crypto |
| --- | --- |
| `Listening` | `Running` with the same pending count |
| `Established` | `Established` with no pending candidate or pending commit |
| `Closed` | `Closed` with no live context |

`AuthenticatedPendingCommit` is deliberately transient. No public coordinator method may return
while crypto is in that phase.

## Validation order

Inbound processing follows a strict trust order:

1. Policy checks source, lifecycle, expected message kind, deadline, and attempt ownership.
2. Only a permitted payload reaches crypto.
3. Crypto authenticates the opaque payload and returns success or an expected remote failure.
4. The coordinator compares every returned attempt, candidate, session, and metadata value with
   locally trusted values.
5. Policy records the authenticated transition.
6. Crypto commits the same metadata.
7. The coordinator verifies the stable policy/crypto pair before returning.

This ordering prevents an unauthenticated field from selecting state and prevents policy and
crypto from silently disagreeing.

## `Ok` versus `Err`

An invalid remote message is normal hostile input, not a local program failure:

- expected remote rejection returns `Ok(report)` with a typed `Dropped` event;
- local policy errors, crypto state errors, or invariant violations return
  `Err(FatalCoordinatorError)`;
- a fatal path shuts down both owned layers and retains both cleanup outcomes;
- payload `Debug` implementations print `<opaque>` rather than provider data.

The shared `AuthenticationFailure` enum is matched by both variant and correlation. Client crypto
may fail only a `ClientAttempt`; server crypto may fail only a `ServerCandidate`. The wrong variant
is a provider-contract violation even if one ID happens to match.

## Server candidates and duplicates

While listening, the server may track a bounded number of pending candidates. A candidate is bound
to source address, candidate ID, and client attempt ID.

- Repeating an identical `ClientHello` reuses the candidate and original deadline.
- A different attempt from the same pending source is stale.
- Capacity rejection does not replace an existing candidate.
- Expiration removes the exact policy and crypto candidate together.
- A malformed new hello expects no crypto context to have been created.
- A malformed duplicate expects the existing crypto context to be removed.
- After establishment, only an exact duplicate `ClientFinish` from the established peer may cause
  the confirmation to be prepared again.

These distinctions explain why cleanup results such as `Removed` and `AlreadyAbsent` are part of
the coordinator contract rather than ignored implementation details.

## Timeouts and shutdown

Tests inject `Instant`; they never sleep. A deadline is expired when `now >= deadline`.

Client timeout is terminal for the current coordinator. Server timeout removes only expired
candidates and can leave other candidates listening. Shutdown is terminal and idempotent for both
roles. Crypto shutdown reports only non-secret counts and flags describing what was erased.

## Where to read the code

Read in this order:

1. `src/handshake/types.rs` — transport envelopes, reports, events, and fatal errors.
2. `src/session/client.rs` — client authorization and lifecycle policy.
3. `src/session/server.rs` — candidate admission, duplicate handling, and server lifecycle.
4. `src/crypto/client.rs` and `src/crypto/server.rs` — provider contracts.
5. `src/crypto/fake.rs` — deterministic provider and transcript contexts.
6. `src/handshake/client.rs` and `src/handshake/server.rs` — transaction ordering and cleanup.
7. `src/handshake.rs` tests — complete in-memory message transfer.

## What Milestone 2.3 proves

- all four fake handshake messages complete;
- both endpoints commit the same session ID and opposite peer identities;
- source, attempt, candidate, result, and metadata correlations are checked;
- malformed input, duplicates, deadlines, capacity, cleanup mismatches, and local injected errors
  have deterministic outcomes;
- shutdown and fail-closed paths erase provider contexts; and
- opaque payloads and credentials are redacted from diagnostics.

## What it does not prove

- a real cryptographic construction is safe;
- handshake bytes can be encoded or decoded;
- UDP loss, duplication, reordering, cancellation, or retry behavior works;
- data frames are bound to an established session;
- encryption, nonces, replay windows, rekeying, or downgrade protection exists; or
- the running server authenticates its peer.

## Next milestone boundary

Before runtime integration, select a reviewed authenticated protocol or library and define a
version 2 wire/configuration contract. Then add a transport adapter that parses untrusted bytes,
feeds owned messages into these coordinators, sends returned outbound messages, and schedules the
nearest deadline without holding coordinator borrows across `.await`.

Do not place fake crypto on the live network and do not invent production cryptography merely to
connect the coordinator to UDP.
