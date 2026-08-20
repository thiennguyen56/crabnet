# Encrypted V2 data-plane design

Status: design only; do not enable packet forwarding until the invariants and tests in this
document are implemented.

This milestone adds encrypted packet transport after a Noise-IK handshake has established a
session. It does not change the four-message handshake. The legacy V1 runtime remains an explicit,
unauthenticated lab mode; Noise-IK must never fall back to V1 plaintext forwarding.

## 1. Component responsibilities

### Data-frame profile

Define one canonical V2 data message. The frame must bind the session, direction, sequence number,
and ciphertext to the authenticated session state. The outer V2 header remains structurally
validated by the V2 codec; the authenticated data must also cover every security-relevant field.

Recommended logical fields:

| Field | Purpose |
| --- | --- |
| Magic/version/type/flags | Existing V2 structural envelope; type is `Data` |
| Session identifier | Selects the established session; never selects a pending candidate |
| Direction marker | Prevents reflection between client-to-server and server-to-client keys |
| Sequence number | Unique nonce input and replay-order signal |
| Ciphertext | Encrypted raw TUN packet, including its authentication tag |

The exact byte layout, maximum plaintext size, and authenticated-data encoding must be frozen
before implementation.

### Established data session

Owns the encrypted transport state created from the completed Noise-IK handshake:

- session ID and authenticated peer metadata;
- one send sequence counter;
- one receive replay window and highest accepted sequence;
- directional Noise transport state or equivalent AEAD keys;
- peer endpoint binding;
- lifecycle and shutdown state;
- counters for encrypted, rejected, replayed, and oversized datagrams.

It must not own TUN devices, routes, NAT, or configuration parsing.

### Client/server session registry

The client owns exactly one established session. The server keeps the existing single-established-
peer invariant and maps the authenticated peer endpoint plus session ID to one data session. A
pending Noise candidate is never permitted to send data.

### Data-frame codec

Responsibilities:

1. decode the bounded structural frame;
2. validate the data-message shape and field widths;
3. borrow ciphertext while decoding;
4. reject impossible lengths before decryption; and
5. encode an already-produced ciphertext without interpreting it.

The codec does not perform cryptography, replay checks, session lookup, or TUN I/O.

### Crypto/data adapter

Converts a validated data frame into an authenticated-decryption request and converts plaintext
bytes into an encrypted frame. It owns the boundary between borrowed wire bytes and owned session
state. It must authenticate the exact frame fields selected by the profile and must never reuse a
nonce or sequence number in one direction.

### Tokio data-plane runtime

Owns the UDP socket, TUN device, reusable buffers, cancellation future, and session registry. It
coordinates I/O but delegates pure decisions to the data session and codec. It must not hold a
synchronous lock or mutable session borrow across `.await`.

### Counters and diagnostics

Record bounded, non-secret counters and coarse reasons:

- encrypted packets and bytes;
- decrypted packets and bytes;
- structural rejects;
- unknown-session rejects;
- authentication failures;
- replay/old-sequence rejects;
- oversize and partial-write failures; and
- orderly versus fatal shutdown.

Never log raw ciphertext, plaintext, keys, or complete packet contents.

## 2. Data flow

### Startup and session establishment

```text
parse configuration
  -> choose explicit legacy or noise_ik mode
  -> perform Noise-IK handshake
  -> verify both confirmation messages
  -> commit identical session metadata
  -> derive directional data state
  -> create exactly one established data session
  -> only then create/enable encrypted TUN forwarding
```

### TUN to UDP

```text
read one raw TUN packet
  -> reject empty or over-MTU packet
  -> reserve next client/server send sequence
  -> build authenticated associated data from session + direction + sequence
  -> encrypt packet with the directional transport state
  -> encode V2 Data frame
  -> send exactly one UDP datagram
  -> increment encrypted counters only after a complete send
```

### UDP to TUN

```text
receive into maximum-datagram-plus-one buffer
  -> reject oversized datagram before decode
  -> decode V2 Data frame
  -> classify direction and locate established session
  -> reject unknown endpoint/session
  -> check sequence against replay window without advancing it
  -> authenticate and decrypt using the receive direction
  -> commit replay-window advancement only after authentication succeeds
  -> validate plaintext packet length against TUN MTU
  -> write the complete plaintext packet to TUN
  -> increment decrypted counters after a complete write
```

### Shutdown

```text
stop accepting new input
  -> cancel or drain the select loop
  -> stop TUN/UDP forwarding
  -> erase transport keys and replay state
  -> restore routes, NAT, and forwarding state
  -> report primary and cleanup errors without plaintext fallback
```

## 3. Language-neutral pseudocode

### Send

```text
SEND_DATA(packet):
  require session.state == ESTABLISHED
  require 0 < LENGTH(packet) <= inner_mtu

  sequence = session.send_sequence
  require sequence is unused and sequence <= MAX_SEQUENCE

  aad = AUTHENTICATED_HEADER(session.id, DATA_KIND, session.send_direction, sequence)
  ciphertext = ENCRYPT(session.send_state, sequence, aad, packet)
  frame = ENCODE_DATA(session.id, session.send_direction, sequence, ciphertext)

  SEND_UDP(frame)
  session.send_sequence = sequence + 1
  counters.encrypted_packets += 1
```

The counter is reserved and committed according to the transport API's failure semantics. A failed
send must never cause the same nonce to encrypt a different plaintext; either consume the sequence
or abort the session and erase its keys.

### Receive

```text
RECEIVE_DATA(datagram, source):
  if LENGTH(datagram) > MAX_FRAME_LENGTH:
    counters.oversized += 1
    return DROP_REMOTE

  frame = DECODE_DATA(datagram)
  if frame is malformed or frame.kind != DATA:
    counters.structural_rejects += 1
    return DROP_REMOTE

  session = LOOKUP_ESTABLISHED_SESSION(source, frame.session_id)
  if session is absent:
    counters.unknown_session += 1
    return DROP_REMOTE

  if frame.direction != session.expected_receive_direction:
    counters.structural_rejects += 1
    return DROP_REMOTE

  if not replay_window.may_attempt(frame.sequence):
    counters.replay_rejects += 1
    return DROP_REMOTE

  aad = AUTHENTICATED_HEADER(frame.session_id, frame.kind, frame.direction, frame.sequence)
  plaintext = DECRYPT(session.receive_state, frame.sequence, aad, frame.ciphertext)
  if plaintext is AUTH_FAILURE:
    counters.authentication_failures += 1
    return DROP_REMOTE

  replay_window.commit(frame.sequence)
  if LENGTH(plaintext) == 0 or LENGTH(plaintext) > inner_mtu:
    counters.plaintext_size_rejects += 1
    return DROP_REMOTE

  WRITE_TUN_COMPLETELY(plaintext)
  counters.decrypted_packets += 1
  return ACCEPT
```

### Runtime loop

```text
RUN_ENCRYPTED_SESSION:
  create Ctrl-C future once
  allocate reusable TUN and UDP buffers

  loop:
    select:
      ctrl_c:
        return ORDERLY_SHUTDOWN

      tun_packet:
        result = SEND_DATA(tun_packet)
        if result is local crypto, framing, or complete-write failure:
          return FATAL

      udp_datagram:
        result = RECEIVE_DATA(datagram, source)
        if result is remote rejection:
          continue
        if result is local session or crypto-state failure:
          return FATAL
```

## 4. Important states and invariants

### Session states

```text
Handshaking -> Established -> Closing -> Closed
Handshaking -> Closed on timeout, authentication failure, or shutdown
Established -> Closed on key exhaustion, unrecoverable crypto error, or shutdown
```

Invariants:

1. No data frame is accepted before `Established`.
2. No pending candidate owns data keys.
3. The client and server commit the same session ID and opposite peer identities.
4. One direction has exactly one send key/state and one receive key/state.
5. A sequence number is never reused with the same directional key.
6. Replay-window state advances only after successful authentication.
7. Session ID, direction, sequence, and message kind are authenticated.
8. Unknown endpoints and session IDs cannot create or replace a session.
9. Plaintext is written to TUN only after successful authentication and MTU validation.
10. Any local invariant or key-state failure is fatal; hostile remote input is dropped.
11. Legacy V1 and encrypted V2 data are explicit startup modes; no inbound downgrade exists.
12. Key material and replay state are erased on shutdown or terminal failure.

### Replay window

Use a fixed-size sliding window, for example `W` sequence values. The pure algorithm must define:

- behavior for the first packet;
- acceptance of a new highest sequence;
- acceptance of an unseen packet inside the window;
- rejection of duplicates;
- rejection of packets older than the window; and
- overflow behavior near the maximum sequence value.

Do not mark a sequence as received before authentication succeeds.

### Key exhaustion and rekeying

The first implementation must define a hard sequence limit. At or before exhaustion, stop sending
with the current key and close the session unless a separately designed rekey protocol exists. Do
not silently wrap a counter or reuse a nonce.

## 5. Error and shutdown cases

### Remote input: drop and continue

- short, oversized, bad-magic, wrong-version, wrong-direction, or wrong-length frame;
- unknown endpoint or session ID;
- replayed, duplicate, or too-old sequence;
- invalid authentication tag or ciphertext;
- plaintext empty or over the configured MTU.

These errors must be observable through counters or rate-limited logs and must not terminate the
service.

### Local fatal errors

- inability to bind or receive from the UDP socket;
- TUN read/write failure or partial write;
- inability to encode a locally constructed frame;
- transport-state misuse, sequence overflow, or invariant mismatch;
- key exhaustion without a rekey path; and
- coordinator/session cleanup failure.

On a local fatal error, stop forwarding, erase key state, and restore owned networking state. Never
fall back to V1 forwarding.

### Cancellation

Create the Ctrl-C future once outside `tokio::select!`. Cancellation must stop both directions,
prevent new sends, erase data state, and still run route/NAT restoration. If forwarding and cleanup
both fail, preserve both errors with the forwarding error primary.

## 6. Tests to write

### Pure frame and crypto tests

- exact data-frame encode/decode vectors;
- authenticated-data mismatch for every security-relevant field;
- empty, MTU-sized, over-MTU, and maximum-datagram payloads;
- wrong session ID and wrong direction;
- successful encrypt/decrypt in both directions;
- tampered ciphertext and tag rejection;
- sequence/nonce uniqueness and overflow behavior;
- ciphertext never interpreted as text or modified by the adapter.

### Replay-window tests

- first packet acceptance;
- increasing sequences;
- reordered packets inside the window;
- duplicate rejection;
- packets older than the window;
- window advancement after a high sequence;
- failed authentication does not advance the window;
- sequence wrap or exhaustion closes the session.

### Session-policy tests

- data rejected while handshaking or after close;
- unknown endpoint cannot create a data session;
- established duplicate session behavior;
- shutdown erases keys and replay state;
- local invariant failures are fatal while remote failures are drops.

### Tokio/runtime tests

Use fake UDP/TUN or pure channel adapters; do not require root or real TUN devices.

- TUN packet encrypts and reaches the peer;
- UDP packet decrypts and reaches TUN;
- malformed UDP input does not stop the loop;
- a server with no client remains listening;
- cancellation exits both branches and performs cleanup;
- partial TUN/UDP writes are fatal;
- established handshake gates data forwarding;
- legacy mode never accepts encrypted V2 data accidentally.

### Namespace integration tests

Only after pure and fake-runtime tests pass:

- run a dedicated Noise-IK namespace test with generated ephemeral lab keys;
- prove authenticated encrypted packet delivery;
- prove tampering and replay are dropped without terminating either endpoint;
- retain the existing legacy namespace test separately for routing and NAT behavior.

## 7. Rust concepts and Tokio APIs

- fixed-size integer types and checked arithmetic for sequence counters;
- `u64` or a protocol-defined fixed-width sequence encoding;
- owned byte buffers (`Vec<u8>`, `Box<[u8]>`) at async ownership boundaries;
- pure replay-window structs with exhaustive `match` transitions;
- `Result` error domains separating remote drops from local fatal failures;
- `tokio::net::UdpSocket::recv_from`, `send_to`, `send`, and `recv`;
- `tokio::select!` with a single pinned Ctrl-C future;
- `tokio::time::sleep_until` only for session/rekey deadlines, never as a process-wide listening timeout;
- `tokio::sync` only when ownership requires shared state, and never across `.await` accidentally;
- `anyhow::Context` at socket, TUN, and OS boundaries;
- zeroization or the selected crypto library's key-erasure APIs;
- fake transport traits or channels for unprivileged runtime tests.

## Completion criteria

This milestone is complete only when encrypted data forwarding is enabled exclusively after a
committed Noise-IK session, all remote malformed/authentication/replay failures are non-fatal drops,
all local failures clean up safely, the legacy path remains unchanged, and the focused plus full
unprivileged test suites pass. A successful handshake alone is not completion.
