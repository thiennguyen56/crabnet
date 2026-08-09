# Milestone 2.2c: Pure server handshake state machine

## Scope

This milestone defines a pure, synchronous server handshake policy. It accepts classified or
authenticated results from future protocol and crypto boundaries, owns bounded pending state,
enforces one authenticated active peer, and returns symbolic effects for a future runtime.

This is a design contract, not the final implementation. Every proposed type, field, function,
parameter, return value, helper, and transition is defined below. It does not define wire bytes,
choose cryptography, perform UDP/TUN I/O, activate secure mode, encrypt data, implement replay
protection, or change routes/NAT. A valid `ClientHello` creates pending state only. Only an
authenticated `ClientFinish` may establish a session.

Implementation belongs in `src/session/server.rs` beside the pure client state machine.

## 1. Component responsibilities

### Protocol and crypto boundaries

Future `protocol.rs` code validates public framing and classifies `ClientHello`, `ClientFinish`,
`Data`, and other handshake messages. Structural validity is not authentication and never selects
the peer. Future crypto code validates hello material, authenticates a finish for an exact
candidate/attempt, produces fresh established metadata, and prepares outbound bytes. The state
machine receives no keys, proofs, transcripts, or packet payloads.

### Shared types

Use one shared definition of each type:

```rust
pub(crate) struct CandidateId(u64);
pub(crate) struct ClientAttemptId(u64);
pub(crate) struct SessionId(u64);
pub(crate) struct PeerIdentity(u64);

pub(crate) struct EstablishedSessionMetadata {
  session_id: SessionId,
  peer_identity: PeerIdentity,
}
```

Before implementation, move the last four types from `session/client.rs` to `session.rs` or
`session/types.rs`. Client and server must not define separate nominal types. These values are
non-secret correlation/policy tokens, not final wire representations. A `SocketAddr` is never a
`PeerIdentity`.

### Required `SessionManager` extensions

Reuse the existing manager for capacity, source ownership, `created_at`, and deadline policy. Add
only this view and conditional removal:

```rust
pub(crate) struct PendingCandidateSnapshot {
  pub(crate) candidate_id: CandidateId,
  pub(crate) created_at: Instant,
  pub(crate) deadline: Instant,
}

pub(crate) enum CandidateRemoval {
  Removed,
  NotFound,
  CandidateMismatch {
    expected: CandidateId,
    observed: CandidateId,
  },
  Closed,
}

impl SessionManager {
  pub(crate) fn candidate(
    &self,
    source: SocketAddr,
  ) -> Option<PendingCandidateSnapshot>;

  pub(crate) fn remove_candidate(
    &mut self,
    source: SocketAddr,
    observed: CandidateId,
  ) -> CandidateRemoval;
}
```

`candidate` does not expire or mutate. `remove_candidate` removes only when source and ID match,
never by source alone, and does not close the manager.

### Server state

```rust
struct ServerCandidate {
  candidate_id: CandidateId,
  source: SocketAddr,
  client_attempt_id: ClientAttemptId,
}

pub(crate) struct EstablishedServerSession {
  metadata: EstablishedSessionMetadata,
  peer_endpoint: SocketAddr,
  completed_candidate_id: CandidateId,
  client_attempt_id: ClientAttemptId,
  established_at: Instant,
}

pub(crate) enum ServerHandshakeState {
  Listening,
  Established { session: EstablishedServerSession },
  Closed,
}

pub(crate) struct ServerHandshake {
  pending: SessionManager,
  candidate_by_id: HashMap<CandidateId, ServerCandidate>,
  state: ServerHandshakeState,
}
```

Membership in `candidate_by_id` means `AwaitingClientFinish`; no second pending phase exists.
`pending` is authoritative for source, ID, and deadline. `candidate_by_id` adds the attempt binding.
The established state retains its completion tuple so an exact duplicate finish can resend
`ServerFinish` without creating another session.

### Inputs, effects, and decisions

```rust
pub(crate) enum ServerInboundKind {
  ClientHello,
  ClientFinish,
  Data,
  OtherHandshake,
}

pub(crate) enum ServerEffect {
  SendServerHello {
    destination: SocketAddr,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
  },
  SendServerFinish {
    destination: SocketAddr,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    session_id: SessionId,
  },
  SessionEstablished {
    source: SocketAddr,
    session_id: SessionId,
  },
  Dropped {
    source: SocketAddr,
    reason: ServerDropReason,
  },
  Closed {
    removed_candidates: usize,
    removed_session: bool,
  },
  AlreadyClosed,
}

pub(crate) struct ServerReport {
  pub(crate) expired: Vec<ExpiredServerCandidate>,
  pub(crate) effects: Vec<ServerEffect>,
}

pub(crate) struct ExpiredServerCandidate {
  pub(crate) candidate_id: CandidateId,
  pub(crate) source: SocketAddr,
  pub(crate) client_attempt_id: ClientAttemptId,
}

pub(crate) enum ServerDropReason {
  PendingCapacityReached { maximum_pending: usize },
  NoPendingCandidate,
  StaleCandidate { expected: CandidateId, observed: CandidateId },
  StaleClientAttempt { expected: ClientAttemptId, observed: ClientAttemptId },
  AuthenticationFailed,
  UnexpectedMessage {
    expected: Option<ServerInboundKind>,
    observed: ServerInboundKind,
  },
  PreSessionData,
  AnotherPeerIsActive { active_source: SocketAddr },
  SessionUnavailable,
}

pub(crate) enum ServerDataDecision {
  RejectPreSession,
  PermitEstablished { session_id: SessionId },
  RejectUnexpectedSource { expected: SocketAddr, observed: SocketAddr },
  RejectUnknownSession { expected: SessionId, observed: SessionId },
  RejectClosed,
}
```

`ServerReport.expired` records timeout removals performed before the main decision. Effects are
owned, non-secret runtime instructions in execution order. First establishment returns
`SendServerFinish` then `SessionEstablished`; duplicate completion returns only `SendServerFinish`.

### Local diagnostics

```rust
pub(crate) enum ServerStateName { Listening, Established, Closed }

pub(crate) enum ServerOperation {
  ApplyValidClientHello,
  ApplyAuthenticatedClientFinish,
  ApplyAuthenticationFailure,
  ApplyUnexpectedMessage,
  CheckTimeouts,
  Shutdown,
}

pub(crate) enum ServerStateError {
  PendingManager {
    operation: ServerOperation,
    source: Option<SocketAddr>,
    error: SessionManagerError,
  },
  CandidateRegistryMissing { candidate_id: CandidateId, source: SocketAddr },
  CandidateRegistryOrphaned { candidate_id: CandidateId, source: SocketAddr },
  CandidateSourceMismatch {
    candidate_id: CandidateId,
    manager_source: SocketAddr,
    registry_source: SocketAddr,
  },
  CandidateRegistryCountMismatch {
    manager_count: usize,
    registry_count: usize,
  },
  PendingManagerClosedWhileListening,
  PendingCandidatesOutsideListening { state: ServerStateName, count: usize },
}
```

Remote rejection is a `Dropped` effect. `ServerStateError` is only trusted local failure or
registry corruption. `Display` includes safe operation/source/ID context, never secrets or raw
bytes. No server config error is needed because `SessionPolicy` is already validated.

### Complete method surface

```rust
impl ServerHandshake {
  pub(crate) fn new(policy: SessionPolicy) -> Self;
  pub(crate) fn state_name(&self) -> ServerStateName;

  pub(crate) fn handle_valid_client_hello(
    &mut self,
    source: SocketAddr,
    client_attempt_id: ClientAttemptId,
    now: Instant,
  ) -> Result<ServerReport, ServerStateError>;

  pub(crate) fn handle_authenticated_client_finish(
    &mut self,
    source: SocketAddr,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    metadata: EstablishedSessionMetadata,
    now: Instant,
  ) -> Result<ServerReport, ServerStateError>;

  pub(crate) fn handle_authentication_failure(
    &mut self,
    source: SocketAddr,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    now: Instant,
  ) -> Result<ServerReport, ServerStateError>;

  pub(crate) fn handle_unexpected_message(
    &mut self,
    source: SocketAddr,
    observed: ServerInboundKind,
    now: Instant,
  ) -> Result<ServerReport, ServerStateError>;

  pub(crate) fn check_timeouts(&mut self, now: Instant)
    -> Result<ServerReport, ServerStateError>;
  pub(crate) fn classify_data(
    &self,
    source: SocketAddr,
    session_id: SessionId,
  ) -> ServerDataDecision;
  pub(crate) fn next_deadline(&self) -> Option<Instant>;
  pub(crate) fn shutdown(&mut self) -> Result<ServerReport, ServerStateError>;

  fn expire_and_reconcile(&mut self, now: Instant)
    -> Result<Vec<ExpiredServerCandidate>, ServerStateError>;
  fn current_candidate(&self, source: SocketAddr)
    -> Result<Option<ServerCandidate>, ServerStateError>;
  fn remove_exact_candidate(&mut self, candidate: ServerCandidate)
    -> Result<(), ServerStateError>;
  fn verify_candidate_maps(&self) -> Result<(), ServerStateError>;
}
```

Every function is synchronous. The caller supplies `now`; no function reads a clock or does I/O.

## 2. Data flow

```text
ClientHello + source + attempt + now
→ expire/reconcile
→ admit while Listening
├─ new: bind candidate and SendServerHello
├─ duplicate same attempt: resend without refreshing deadline
├─ duplicate different attempt: drop stale attempt
└─ full: drop capacity reached

authenticated ClientFinish + source/candidate/attempt/metadata + now
→ expire/reconcile
→ compare every correlation value before mutation
→ remove exact candidate and all other pending state
→ commit Established
→ SendServerFinish, then SessionEstablished

exact duplicate finish in Established
→ resend ServerFinish only

authentication failure
→ remove exact candidate only; stale callbacks change nothing

data
→ permit only exact established source + session ID

shutdown
→ clear candidate/session state → Closed
```

## 3. Language-neutral pseudocode

`report(expired, effects)` constructs `ServerReport`. Every declared function is defined here.

### `SessionManager.candidate(source)`

```text
IF manager is Closed: RETURN None
record = pending_by_source.get(source)
IF absent: RETURN None
RETURN snapshot(record.id, record.created_at, record.deadline)
```

### `SessionManager.remove_candidate(source, observed)`

```text
IF manager is Closed: RETURN Closed
record = pending_by_source.get(source)
IF absent: RETURN NotFound
IF record.id != observed:
  RETURN CandidateMismatch(expected = record.id, observed)
pending_by_source.remove(source)
RETURN Removed
```

### `new(policy)` and `state_name()`

```text
new(policy):
  RETURN { pending = SessionManager.new(policy), candidate_by_id = {}, state = Listening }

state_name():
  MATCH state: Listening → Listening; Established → Established; Closed → Closed
```

### `handle_valid_client_hello(source, client_attempt_id, now)`

```text
expired = expire_and_reconcile(now)?
IF Closed: RETURN report(expired, [Dropped(source, SessionUnavailable)])
IF Established(session): RETURN report(expired,
  [Dropped(source, AnotherPeerIsActive(session.peer_endpoint))])

admission = pending.admit(source, now)
  MAP ERROR TO PendingManager(ApplyValidClientHello, Some(source), error)
REQUIRE admission.expired is empty because expiration already ran at the same now

MATCH admission.outcome:
  Added(candidate_id, deadline):
    INSERT ServerCandidate(candidate_id, source, client_attempt_id)
    verify_candidate_maps()?
    RETURN report(expired, [SendServerHello(source, candidate_id, client_attempt_id)])
  AlreadyPending(candidate_id, unchanged_deadline):
    binding = current_candidate(source)?; REQUIRE Some
    IF binding.client_attempt_id != client_attempt_id:
      RETURN report(expired, [Dropped(source,
        StaleClientAttempt(binding.client_attempt_id, client_attempt_id))])
    RETURN report(expired, [SendServerHello(source, candidate_id, client_attempt_id)])
  AtCapacity(maximum_pending):
    RETURN report(expired, [Dropped(source, PendingCapacityReached(maximum_pending))])
  Closed: RETURN PendingManagerClosedWhileListening
```

The duplicate path never refreshes `created_at` or `deadline`.

### `handle_authenticated_client_finish(...)`

```text
expired = expire_and_reconcile(now)?
IF Closed: RETURN report(expired, [Dropped(source, SessionUnavailable)])
IF Established(session):
  IF source == session.peer_endpoint
     AND candidate_id == session.completed_candidate_id
     AND client_attempt_id == session.client_attempt_id:
    RETURN report(expired, [SendServerFinish(
      source, candidate_id, client_attempt_id, session.metadata.session_id)])
  RETURN report(expired, [Dropped(source,
    AnotherPeerIsActive(session.peer_endpoint))])

binding = current_candidate(source)?
IF absent: RETURN report(expired, [Dropped(source, NoPendingCandidate)])
IF binding.candidate_id != candidate_id:
  RETURN report(expired, [Dropped(source,
    StaleCandidate(binding.candidate_id, candidate_id))])
IF binding.client_attempt_id != client_attempt_id:
  RETURN report(expired, [Dropped(source,
    StaleClientAttempt(binding.client_attempt_id, client_attempt_id))])

session_id = metadata.session_id
remove_exact_candidate(binding)?
pending.shutdown()
candidate_by_id.clear()
state = Established {
  metadata,
  peer_endpoint = source,
  completed_candidate_id = candidate_id,
  client_attempt_id,
  established_at = now
}
RETURN report(expired, [
  SendServerFinish(source, candidate_id, client_attempt_id, session_id),
  SessionEstablished(source, session_id)
])
```

All comparisons happen before removal. No rejection path mutates a current candidate.

### `handle_authentication_failure(...)`

```text
expired = expire_and_reconcile(now)?
IF Closed: RETURN report(expired, [Dropped(source, SessionUnavailable)])
IF Established(session): RETURN report(expired,
  [Dropped(source, AnotherPeerIsActive(session.peer_endpoint))])
binding = current_candidate(source)?
IF absent: RETURN report(expired, [Dropped(source, NoPendingCandidate)])
IF binding.candidate_id != candidate_id:
  RETURN report(expired, [Dropped(source,
    StaleCandidate(binding.candidate_id, candidate_id))])
IF binding.client_attempt_id != client_attempt_id:
  RETURN report(expired, [Dropped(source,
    StaleClientAttempt(binding.client_attempt_id, client_attempt_id))])
remove_exact_candidate(binding)?
verify_candidate_maps()?
RETURN report(expired, [Dropped(source, AuthenticationFailed)])
```

### `handle_unexpected_message(source, observed, now)`

```text
expired = expire_and_reconcile(now)?
IF Closed: RETURN report(expired, [Dropped(source, SessionUnavailable)])
IF Listening:
  IF observed == Data: reason = PreSessionData
  ELSE IF current_candidate(source)? exists:
    reason = UnexpectedMessage(Some(ClientFinish), observed)
  ELSE: reason = UnexpectedMessage(Some(ClientHello), observed)
  RETURN report(expired, [Dropped(source, reason)])
IF Established(session):
  IF source != session.peer_endpoint:
    reason = AnotherPeerIsActive(session.peer_endpoint)
  ELSE: reason = UnexpectedMessage(Some(Data), observed)
  RETURN report(expired, [Dropped(source, reason)])
```

### `check_timeouts(now)`, `classify_data`, and `next_deadline`

```text
check_timeouts(now):
  RETURN report(expire_and_reconcile(now)?, [])

classify_data(source, session_id):
  MATCH state:
    Listening: RETURN RejectPreSession
    Closed: RETURN RejectClosed
    Established(session):
      IF source != session.peer_endpoint:
        RETURN RejectUnexpectedSource(session.peer_endpoint, source)
      IF session_id != session.metadata.session_id:
        RETURN RejectUnknownSession(session.metadata.session_id, session_id)
      RETURN PermitEstablished(session.metadata.session_id)

next_deadline():
  IF Listening: RETURN pending.next_deadline()
  IF Established or Closed: RETURN None
```

Source is checked before session ID so an unrelated source learns nothing about valid IDs.

### `shutdown()`

```text
IF Closed: RETURN report([], [AlreadyClosed])
removed_candidates = pending.pending_count()
removed_session = state is Established
pending.shutdown()
candidate_by_id.clear()
state = Closed
RETURN report([], [Closed(removed_candidates, removed_session)])
```

Compute report values before discarding state. Shutdown performs no I/O or route/NAT cleanup.

### `expire_and_reconcile(now)`

```text
IF Established or Closed:
  IF candidate_by_id is not empty:
    RETURN PendingCandidatesOutsideListening(state_name, len)
  RETURN []
manager_report = pending.expire_pending(now)
expired_server = []
FOR item IN manager_report.expired:
  binding = candidate_by_id.remove(item.candidate_id)
  IF absent: RETURN CandidateRegistryMissing(item.candidate_id, item.source)
  IF binding.source != item.source:
    RETURN CandidateSourceMismatch(item.candidate_id, item.source, binding.source)
  PUSH ExpiredServerCandidate(item.candidate_id, item.source,
    binding.client_attempt_id)
verify_candidate_maps()?
RETURN expired_server
```

Expiration is exact at `now >= deadline`, matching `SessionManager`.

### `current_candidate(source)`

```text
snapshot = pending.candidate(source)
IF absent: RETURN None
binding = candidate_by_id.get(snapshot.candidate_id)
IF absent: RETURN CandidateRegistryMissing(snapshot.candidate_id, source)
IF binding.source != source:
  RETURN CandidateSourceMismatch(snapshot.candidate_id, source, binding.source)
RETURN Some(copy(binding))
```

### `remove_exact_candidate(candidate)`

```text
outcome = pending.remove_candidate(candidate.source, candidate.candidate_id)
MATCH outcome:
  Removed: CONTINUE
  NotFound: RETURN CandidateRegistryOrphaned(candidate.id, candidate.source)
  CandidateMismatch(expected, observed):
    RETURN CandidateRegistryOrphaned(observed, candidate.source)
  Closed: RETURN PendingManagerClosedWhileListening
removed = candidate_by_id.remove(candidate.candidate_id)
IF absent: RETURN CandidateRegistryMissing(candidate.id, candidate.source)
IF removed.source != candidate.source:
  RETURN CandidateSourceMismatch(candidate.id, candidate.source, removed.source)
RETURN success
```

### `verify_candidate_maps()`

```text
IF state is not Listening AND candidate_by_id is not empty:
  RETURN PendingCandidatesOutsideListening(state_name, len)
FOR binding IN candidate_by_id.values:
  snapshot = pending.candidate(binding.source)
  IF absent OR snapshot.candidate_id != binding.candidate_id:
    RETURN CandidateRegistryOrphaned(binding.id, binding.source)
IF pending.pending_count() != candidate_by_id.len():
  RETURN CandidateRegistryCountMismatch(
    pending.pending_count(), candidate_by_id.len())
RETURN success
```

Because SessionManager guarantees unique sources and candidate IDs, checking every server binding
plus equal collection lengths proves the reverse direction without exposing the manager map.

## 4. Important states and invariants

```text
Listening + new hello            → Listening + AwaitingClientFinish
Listening + duplicate same hello → unchanged candidate + resend hello
Listening + exact auth finish    → Established
Listening + exact auth failure   → Listening, candidate removed
Listening + deadline reached     → Listening, candidate removed
Listening/Established + shutdown → Closed
Closed + any input               → Closed
```

Invariants:

1. Only authenticated `ClientFinish` establishes.
2. A pending candidate is never the active peer.
3. Pending count never exceeds `maximum_pending`.
4. Manager candidates and attempt bindings are one-to-one.
5. One source owns at most one candidate.
6. Duplicate hello retains ID, `created_at`, and deadline.
7. Stale IDs never remove current state.
8. Expiration runs first and uses `now >= deadline`.
9. `Established` owns one session and zero pending candidates.
10. Unauthenticated traffic cannot replace the active peer.
11. Duplicate completion resends but never re-establishes.
12. Endpoint is transport information, not identity.
13. Data requires exact endpoint and session ID.
14. `Closed` is terminal and owns no state.
15. Effects contain no secrets/payloads and state commits before future I/O.
16. Unexpected input never refreshes a deadline.

## 5. Error and shutdown cases

Capacity, missing/stale candidate, stale attempt, authentication failure, unexpected message,
pre-session data, another active peer, and post-close input are expected `Dropped` effects.

Manager failure, registry disagreement, lifecycle disagreement, deadline overflow, and candidate ID
exhaustion are local errors. Preserve valid state except candidates removed by the mandatory
expiration-first pass. Never flatten local corruption into a remote drop.

Exact authentication failure removes only its candidate. Timeout removes only candidates at/past
deadline and never closes an established session. Shutdown clears candidate/session state, enters
`Closed`, is idempotent, and never manages routes/NAT.

If shutdown and timeout are simultaneously ready in later `tokio::select!`, choose shutdown first.
The runtime builds owned bytes before `send_to`, holds no mutable state borrow across `.await`,
keeps committed state after cancellation, and relies on duplicate finish handling to resend lost
confirmation.

## 6. Tests you should write

All tests are unprivileged unit tests using supplied `Instant` and fake IDs.

Manager extensions:

- Snapshot returns exact ID, creation time, and deadline.
- Unknown/closed snapshot is `None`.
- Exact removal succeeds; unknown, stale, and closed outcomes do not mutate.
- Removal preserves unrelated candidates and manager lifecycle.

Construction and hello:

- New server is empty `Listening`, has no deadline, and rejects pre-session data.
- First hello creates one exact binding/effect but no session.
- Duplicate same attempt resends without refreshing ID/deadline.
- Different attempt is stale; different sources fill but never exceed capacity.
- Expiration releases capacity before admission.
- Established/closed hello cannot create state.

Finish and failure:

- Exact finish establishes once with supplied metadata/time and ordered effects.
- Success clears every pending candidate and deadline.
- Missing, wrong-source, stale-candidate, and stale-attempt finishes do not mutate/establish.
- Finish exactly at deadline expires and cannot establish.
- Exact duplicate after establishment emits only `SendServerFinish`.
- Nonmatching finish cannot replace active metadata.
- Exact authentication failure removes only its candidate; stale failure changes nothing.

Messages, data, timeout, shutdown, and invariants:

- Expected message is hello without a candidate, finish with one, and data when established.
- Exact source/session permits data; source mismatch is checked before ID mismatch.
- Candidate survives before and expires exactly at deadline; registries stay synchronized.
- Timeout in established/closed state does nothing.
- Shutdown reports removals, clears deadline/data eligibility, and is idempotent.
- No post-close operation recreates state.
- Module-private corruption tests cover every `ServerStateError`.
- Deadline overflow and ID exhaustion leave no partial binding.
- Error text contains safe context and no secrets/raw bytes.

Verification:

```bash
cargo fmt --all -- --check
cargo test session::server
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo build
git diff --check
```

The privileged namespace test is not required because this milestone is pure policy.

## 7. Rust concepts and Tokio APIs you may need

Use newtypes, exhaustive matches, bounded `HashMap` state, immutable validation before mutation,
`Instant::checked_add` in the manager, `Result` for local errors, `Dropped` for remote rejection,
owned effects, private fields, and safe `Debug` before secrets are added. Relevant APIs include
`HashMap::{get, insert, remove, values}`, `SocketAddr`, `Duration`, `Instant`, `Option`, `Result`,
`Display`, and `Error`. No mutex, channel, async trait, atomics, or task is needed in 2.2c.

Later integration may use `UdpSocket::{recv_from, send_to}`, `time::sleep_until`, pinned `Sleep`,
`tokio::select!`, and one pinned `signal::ctrl_c` future. Keep branches small and hold no mutable
session borrow across `.await`.

## Completion boundary

Milestone 2.2c is complete when shared IDs have one definition, both manager extensions and every
method above are implemented/tested, registries stay synchronized, only an exact authenticated
finish establishes, duplicate completion safely resends, one active peer cannot be replaced, data
checks source and session ID, all unprivileged gates pass, and live networking remains unchanged.

The next small milestone should define a fake crypto contract and typed authenticated events shared
by both pure handshake machines, still without changing live UDP forwarding.
