## Scope and security goal

The future secure session should provide:

- Mutual authentication based initially on a pre-shared key.
- Fresh session keys for each connection.
- Separate client-to-server and server-to-client keys.
- Confidentiality and integrity for inner IP packets.
- Replay detection.
- No peer admission before authentication completes.
- No automatic downgrade to insecure v1 framing.

It does not need to solve:

- Multiple active clients.
- User accounts or certificates.
- Traffic-analysis resistance.
- Denial-of-service prevention.
- Endpoint roaming.
- Key rotation while connected.
- Firewall or DNS automation.

Because encrypted packets have fundamentally different security semantics, I recommend treating the authenticated protocol as version 2, while keeping version 1 explicitly lab-only. A
secure client must never silently fall back to v1.

———

# 1. Component responsibilities

These are architectural boundaries for later milestones, not implementations to add now.

## protocol.rs: wire syntax

Responsible for:

- Recognizing protocol versions and message types.
- Encoding and decoding public frame headers.
- Validating structural lengths.
- Returning borrowed payload or ciphertext slices.
- Rejecting unsupported versions, flags, types, and malformed lengths.

Not responsible for:

- Deciding whether a message is valid in the current session state.
- Authenticating a peer.
- Encrypting data.
- Updating replay state.
- Selecting the active peer.

Fundamental separation:

Protocol codec: “Are these bytes structurally valid?”
Session: “Is this message allowed now?”
Crypto: “Is this message authentic?”
Runtime: “Where should this valid result be sent?”

## session.rs: authentication and session policy

Responsible for:

- Client and server handshake states.
- Allowed state transitions.
- Pending-handshake ownership.
- Deciding when a peer becomes authenticated.
- Holding established session metadata.
- Handshake deadlines and idle deadlines.
- Deciding whether a message is expected in the current state.
- Returning actions for the runtime to perform.

Not responsible for:

- UDP reads and writes.
- TUN reads and writes.
- Parsing raw wire bytes.
- Implementing cryptographic algorithms.
- Installing routes or NAT.

## crypto.rs: cryptographic boundary

Future responsibility:

- Creating ephemeral handshake material.
- Authenticating the handshake transcript.
- Deriving directional session keys.
- Encrypting and authenticating data.
- Authenticating and decrypting received data.
- Constructing or validating nonces according to the chosen standard protocol.

Milestone 2.1 should define only the required capabilities. Do not design a custom cryptographic construction.

## Replay window

A future small component, possibly under session.rs, responsible for:

- Non-mutating preliminary sequence checks.
- Committing an authenticated sequence number.
- Rejecting duplicates.
- Supporting bounded packet reordering.
- Rejecting packets older than the receive window.

Replay state must never be updated from unauthenticated input.

## Client/server runtime

Responsible for:

- Receiving UDP datagrams.
- Calling the protocol decoder.
- Passing decoded messages to session policy.
- Executing session actions.
- Sending handshake responses.
- Forwarding data only for an established session.
- Managing timers and shutdown.

The server runtime must not directly say “first valid frame becomes the peer” once secure sessions are enabled.

## Application lifecycle

Responsible for:

- Validating security configuration before privileged changes.
- Starting the session runtime.
- Coordinating route, NAT, TUN, and session cleanup.
- Preventing secure mode from falling back to insecure forwarding.
- Eventually deciding when traffic routes become active relative to handshake completion.

## Observability

Responsible for counters such as:

handshake_started
handshake_completed
handshake_timed_out
authentication_failed
unexpected_handshake_message
unknown_session
decryption_failed
replay_rejected
pre_session_data_dropped

Logs must never contain:

- Pre-shared keys.
- Derived keys.
- Raw inner packets.
- Handshake secrets.
- Authentication tags or secret-bearing transcript fields.

———

# 2. Data flow

## Client handshake

Validated configuration
↓
UDP socket connected to configured server
↓
Create fresh client handshake candidate
↓
Send ClientHello
↓
Wait for authenticated ServerHello
↓
Verify server proof
↓
Send ClientFinish
↓
Wait for ServerFinish/key confirmation
↓
Create established session
↓
Permit TUN packet forwarding

The exact handshake messages and cryptographic operations should come from a reviewed protocol or library. The names above describe roles, not final wire structures.

## Server handshake

UDP datagram and source address
↓
Protocol framing validation
↓
Handshake message classification
↓
Find or create bounded pending candidate
↓
Verify message is valid for candidate state
↓
Perform cryptographic handshake operation
↓
Authentication complete?
├─ No → send required response or await next message
└─ Yes → create established session and active peer

A pending candidate is not the active peer.

## Sending established data

Read one packet from TUN
↓
Confirm session is established
↓
Reserve next send sequence number
↓
Build public authenticated header
↓
Derive nonce according to protocol rules
↓
Encrypt packet and authenticate header
↓
Send one UDP datagram

If encryption or sending fails after reserving a sequence number, that number must never be reused. Skipping a number is safe; nonce reuse is not.

## Receiving established data

Receive UDP datagram
↓
Decode public frame structure
↓
Find session using session identifier
↓
Confirm source address matches session policy
↓
Perform non-mutating replay precheck
↓
Authenticate and decrypt
↓
Commit sequence number to replay window
↓
Write unchanged plaintext packet to TUN

Authentication must happen before committing replay state or writing to TUN.

———

# 3. Language-neutral pseudocode

## Validate the security contract

FUNCTION validate_security_configuration(config):
IF secure mode is disabled:
RETURN insecure-lab configuration

      IF pre-shared-key source is absent:
          RETURN configuration error

      IF insecure fallback is enabled:
          RETURN configuration error

      IF handshake timeout is zero:
          RETURN configuration error

      IF replay-window size is outside supported bounds:
          RETURN configuration error

      LOAD key material from configured secret source

      IF key material has invalid encoding or length:
          RETURN configuration error

      RETURN validated secure configuration

Loading the key should occur before TUN, routing, forwarding, or NAT mutations.

## Start a client handshake

FUNCTION start_client_handshake(now, crypto, server_address):
REQUIRE client state is Idle

      ephemeral_state = crypto.create_client_handshake_state()
      hello = crypto.create_client_hello(ephemeral_state)

      state = AwaitingServerHello {
          server_address,
          ephemeral_state,
          deadline = now + handshake_timeout
      }

      RETURN action SendHandshake(server_address, hello)

If creating secure randomness fails, the handshake must fail. Never substitute a predictable value.

## Handle a client handshake message

FUNCTION handle_client_handshake_message(state, source, message, now):
IF source is not configured server:
RETURN Drop(UnexpectedSource)

      MATCH state:

          AwaitingServerHello:
              IF message is not ServerHello:
                  RETURN Drop(UnexpectedMessage)

              result = crypto.process_server_hello(message)

              IF authentication fails:
                  transition to Idle or Closed according to retry policy
                  RETURN Drop(AuthenticationFailed)

              client_finish = result.client_finish
              provisional_keys = result.provisional_keys

              transition to AwaitingServerFinish {
                  provisional_keys,
                  deadline = now + handshake_timeout
              }

              RETURN SendHandshake(client_finish)

          AwaitingServerFinish:
              IF message is not ServerFinish:
                  RETURN Drop(UnexpectedMessage)

              result = crypto.verify_server_finish(message)

              IF verification fails:
                  erase provisional secrets
                  transition to Idle or Closed
                  RETURN Drop(AuthenticationFailed)

              session = create_established_session(result)
              erase handshake-only secrets
              transition to Established(session)

              RETURN SessionEstablished

          Established:
              RETURN Drop(UnexpectedHandshakeMessage)

          Closing OR Closed:
              RETURN Drop(SessionUnavailable)

          OTHERWISE:
              RETURN Drop(UnexpectedMessage)

The client should not consider the session established merely because it sent its final proof. It should receive key confirmation from the server.

## Handle an initial server handshake message

FUNCTION handle_server_handshake_message(source, message, now):
IF an established session exists:
IF source belongs to established session:
handle according to established-session policy
ELSE:
RETURN Drop(AnotherPeerIsActive)

      candidate = pending_candidates.find(source)

      IF candidate does not exist:
          IF message is not ClientHello:
              RETURN Drop(UnexpectedInitialMessage)

          IF pending candidate limit is reached:
              RETURN Drop(PendingCapacityReached)

          candidate = create_pending_candidate(
              source,
              deadline = now + handshake_timeout
          )

      result = candidate.process(message)

      MATCH result:

          ResponseRequired(response):
              RETURN SendHandshake(source, response)

          AuthenticationComplete(session_material, server_finish):
              session = create_established_session(
                  peer = source,
                  session_material
              )

              remove pending candidate
              erase handshake-only secrets
              set active session to session

              RETURN actions [
                  SendHandshake(source, server_finish),
                  SessionEstablished(source)
              ]

          AuthenticationFailed:
              remove pending candidate
              erase candidate secrets
              RETURN Drop(AuthenticationFailed)

          UnexpectedMessage:
              RETURN Drop(UnexpectedHandshakeMessage)

A server should use a bounded number of pending candidates. Otherwise, unauthenticated traffic could grow memory indefinitely.

## Send an encrypted packet

FUNCTION protect_outbound_packet(session, packet, output):
REQUIRE session is Established
REQUIRE packet is non-empty
REQUIRE packet length does not exceed TUN MTU

      sequence = session.reserve_next_send_sequence()

      IF sequence space is exhausted:
          transition session to Closing
          RETURN SequenceExhausted

      header = create_data_header(
          version = secure protocol version,
          session_id = session.id,
          sequence = sequence,
          payload_length = expected ciphertext length
      )

      ciphertext = crypto.seal(
          key = session.send_key,
          sequence = sequence,
          associated_data = encoded header,
          plaintext = packet,
          output = output
      )

      RETURN encoded header followed by ciphertext

reserve_next_send_sequence() must permanently consume the value, even if the later UDP send is cancelled.

## Receive an encrypted packet

FUNCTION process_inbound_data(source, decoded_frame):
session = sessions.find(decoded_frame.session_id)

      IF no session exists:
          RETURN Drop(UnknownSession)

      IF source violates session endpoint policy:
          RETURN Drop(UnexpectedSource)

      replay_decision = session.replay_window.precheck(decoded_frame.sequence)

      IF replay_decision is DefinitelyTooOld:
          RETURN Drop(ReplayTooOld)

      plaintext = crypto.open(
          key = session.receive_key,
          sequence = decoded_frame.sequence,
          associated_data = decoded_frame.encoded_header,
          ciphertext = decoded_frame.payload
      )

      IF authentication fails:
          RETURN Drop(AuthenticationFailed)

      commit_result =
          session.replay_window.commit(decoded_frame.sequence)

      IF commit_result is Duplicate OR TooOld:
          discard plaintext
          RETURN Drop(ReplayRejected)

      IF plaintext is empty OR exceeds TUN MTU:
          RETURN Drop(InvalidInnerPacketLength)

      RETURN ForwardToTun(plaintext)

The replay precheck must not mutate the window. Only an authenticated packet may change it.

## Expire pending handshakes

FUNCTION expire_pending_handshakes(now):
FOR each pending candidate:
IF candidate.deadline <= now:
erase candidate secrets
remove candidate
increment handshake_timeout counter

Expiration is normal maintenance, not a fatal server error.

## Shutdown

FUNCTION shutdown_session_runtime():
stop accepting new handshakes
stop reading new TUN packets

      optionally send bounded best-effort close notification

      cancel handshake timers
      erase pending handshake secrets
      erase established directional keys
      mark all sessions Closed

      allow application cleanup to continue:
          restore routes
          restore forwarding state
          restore NAT
          close TUN and UDP resources

      RETURN cleanup errors without exposing secrets

Shutdown must not wait indefinitely for a peer acknowledgment.

———

# 4. Important states and invariants

## Client states

Idle
→ AwaitingServerHello
→ AwaitingServerFinish
→ Established
→ Closing
→ Closed

Failure transitions may return to Idle for an explicit bounded retry policy or move to Closed. Retries must not occur in a tight loop.

## Server states

The server has two related layers:

Server:
Listening
Established
Closing
Closed

Pending candidate:
AwaitingClientFinish
Authenticated
Expired
Rejected

Pending candidates are not active sessions.

## Core invariants

1.    Framing validity is not authentication.

      A structurally valid frame cannot select the active peer.

2.    No data before establishment.

      Client and server must reject data messages until handshake completion.

3.    No downgrade.

      Secure mode must reject v1 data instead of falling back automatically.

4.    One authenticated active peer.

      Many bounded handshake candidates may exist, but only one session may become active.

5.    Established sessions cannot be evicted by unauthenticated traffic.
6.    Endpoint address is not identity.

      Authentication comes from proving possession of credentials, not merely sending from a particular IP and port.

7.    Directional keys are distinct.

      Client-to-server and server-to-client traffic never use the same key/nonce space.

8.    Sequence values never repeat under one directional key.
9.    Replay state changes only after successful authentication.
10.   Packet bytes remain binary.

     Never decode inner packets as UTF-8 or log their contents.

11.   Resource use is bounded.

     Pending candidates, message sizes, handshake duration, replay windows, and retry counts all have limits.

12.   Freshness after restart.

     Restarting must generate fresh handshake material and fresh session keys. Old data packets must not become valid in a new session.

13.   Secrets do not implement ordinary Debug.
14.   Security failure is fail-closed.

     Entropy, key derivation, or authentication failures cannot cause plaintext forwarding.

———

# 5. Error and shutdown cases

## Remote-input errors: drop and continue

These must not terminate the server:

- Malformed frame.
- Unsupported secure-protocol version.
- Unknown message type.
- Unexpected handshake message.
- Invalid authentication proof.
- Unknown session identifier.
- Unexpected UDP source.
- Duplicate packet.
- Packet outside replay window.
- Data before session establishment.
- Handshake candidate capacity reached.

Record counters and use rate-limited logging to avoid log flooding.

Do not respond to arbitrary malformed packets. Responses can create amplification or reveal unnecessary protocol state.

## Local fatal errors

These should stop secure startup or the affected runtime:

- PSK cannot be loaded.
- Invalid secret length or encoding.
- Secure randomness unavailable.
- Cryptographic provider initialization fails.
- Derived buffer size overflows.
- Session invariants are violated.
- TUN or UDP returns an unrecoverable I/O error.
- Sequence space is exhausted without a supported rekey mechanism.

## Timeouts

Handshake timeout:

- Remove only the pending candidate.
- Erase its secrets.
- Keep the server listening.
- Allow a future legitimate attempt.

Idle timeout:

- Close and erase the established session.
- Do not delete unrelated route/NAT state from inside session.rs.
- Let application lifecycle code coordinate network cleanup.

## Cancellation

A tokio::select! branch may be cancelled at any .await. Therefore:

- Do not borrow mutable session state across socket sends.
- Build the outbound message and commit required state before awaiting send.
- Never reuse a reserved sequence number after cancellation.
- Keep cleanup independent of whether a close message was transmitted.
- Pin one shutdown future outside the loop.

## Startup ordering concern

A full-tunnel route installed before authentication may temporarily direct user traffic into a TUN that cannot forward it yet. Later integration should choose explicitly between:

- Establishing the secure session before installing protected/default TUN routes; or
- Installing routes first and deliberately dropping/counting pre-session traffic.

The first option gives cleaner fail-closed startup behavior, but may require splitting the existing route installation sequence into underlay protection and overlay traffic activation.
That is a later integration milestone, not part of 2.1.

———

# 6. Tests you should write

Milestone 2.1 itself is documentation, so these are contract scenarios to record now and implement incrementally in later milestones.

## Pure state-machine tests

- Client starts only from Idle.
- ClientHello moves client to AwaitingServerHello.
- Valid ServerHello produces ClientFinish.
- Invalid ServerHello never establishes a session.
- Client waits for ServerFinish before establishment.
- Data is rejected in every pre-established state.
- Server ClientHello creates only a pending candidate.
- Pending candidate does not become active_peer.
- Valid final client proof establishes exactly one session.
- Invalid proof removes or rejects the candidate.
- Established peer cannot be replaced by another ClientHello.
- Closed session cannot transition back to established.
- Shutdown works from every state.

## Timeout tests

Use a fake clock or supplied Instant values:

- Candidate survives before its deadline.
- Candidate expires exactly at its deadline.
- Expiration removes secrets and state.
- One expired candidate does not affect others.
- Established session remains unaffected by pending expiry.
- Retry backoff never becomes a tight loop.

## Capacity tests

- Pending candidate count never exceeds the configured bound.
- Duplicate messages from one address do not allocate new candidates.
- Capacity rejection does not evict the established session.
- Expired candidates release capacity.
- Oversized handshake payloads allocate no candidate.

## Authentication contract tests

Later, with a fake crypto backend:

- Correct credential establishes a session.
- Wrong credential fails.
- Modified transcript fails.
- Authentication failure creates no traffic keys.
- Client and server derive matching directional key pairs.
- Send and receive keys differ.
- Restart generates a different session.
- An old ServerFinish cannot establish a new attempt.

## Replay tests

- First sequence accepted.
- Duplicate rejected.
- Newer sequence accepted.
- Reordered packet within the window accepted once.
- Packet older than the window rejected.
- Failed authentication does not modify the window.
- Large sequence values do not overflow.
- Sequence exhaustion prevents additional encryption.

## Cancellation tests

- Shutdown while awaiting ServerHello.
- Shutdown while awaiting ServerFinish.
- Shutdown with pending server candidates.
- Shutdown immediately after reserving a send sequence.
- Cancelled UDP send does not cause sequence reuse.
- Timeout and shutdown becoming ready together still erase secrets once.
- Cleanup does not wait for a peer response.

## Integration tests for later milestones

- Secure client and server with matching PSKs establish.
- Wrong PSK never selects the server peer.
- Plain v1 data cannot select a peer in secure mode.
- Tampered handshake is rejected.
- Tampered encrypted packet never reaches TUN.
- Replay never reaches TUN twice.
- Valid overlay ping succeeds.
- Full-tunnel NAT HTTP still succeeds.
- Ctrl+C still restores owned routing, forwarding, and NAT state.

———

# 7. Rust concepts and Tokio APIs to study

## Rust concepts

- Enums and exhaustive match for state machines.
- Newtypes for SessionId, sequence numbers, and secret material.
- Ownership-based state transitions.
- Borrowed decoding with lifetimes.
- Trait-based dependency injection for crypto, clocks, and entropy.
- Avoiding secret-bearing Debug implementations.
- Checked arithmetic for frame and buffer lengths.
- Saturating arithmetic for diagnostic counters.
- Error enums for expected protocol rejection.
- anyhow::Context at configuration, file, socket, and runtime boundaries.
- Zeroization and secret-container types from established security libraries.
- Typestate as a learning topic, although ordinary enums are likely simpler here.

Suggested conceptual interfaces:

trait HandshakeCrypto {
// TODO: create and advance a reviewed handshake protocol.
}

trait Clock {
fn now(&self) -> Instant;
}

struct SessionManager<C, T> {
// TODO: pure state and injected crypto/clock dependencies.
}

Avoid making every state an async object. State transitions should remain synchronous where possible; the runtime performs returned async actions.

## Tokio APIs

Study:

- tokio::net::UdpSocket::{recv, recv_from, send, send_to}
- tokio::select!
- tokio::signal::ctrl_c
- tokio::time::Instant
- tokio::time::Sleep
- tokio::time::sleep_until
- tokio::time::timeout
- tokio::pin!
- tokio::sync::watch for explicit shutdown notification
- tokio::task::JoinSet only if session work is eventually split into owned tasks

A resettable pinned Sleep is useful for the nearest handshake deadline, but a small server could initially calculate the nearest deadline and use sleep_until. Keep timeout policy in
session.rs; keep timer polling in server.rs or client.rs.

## Milestone 2.1 deliverable

The concrete output of this milestone should be one design document containing:

- Threat model and non-goals.
- Authentication identity definition.
- Protocol-version and downgrade policy.
- State-transition tables.
- Handshake completion rules.
- Directional key and nonce requirements.
- Replay requirements.
- Timeout and retry policy.
- Error classification.
- Shutdown guarantees.
- Test matrix.

After reviewing and freezing that contract, Milestone 2.2 can implement only the pure state model with a fake crypto backend—still without changing UDP traffic or performing real
cryptography.
