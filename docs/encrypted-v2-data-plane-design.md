# Encrypted V2 data-plane design

Status: core encrypted forwarding is implemented. V1 remains an explicit unauthenticated lab mode, and Noise-IK never falls back to V1 plaintext forwarding. Dedicated fake-runtime and namespace coverage remain follow-up work.

## 1. Scope and fixed decisions

This milestone carries raw TUN packets only after a committed Noise-IK session. It does not alter
the four-message V2 handshake, add rekeying, add multi-peer routing, or make Crabnet a production
VPN.

The first implementation has these fixed decisions:

- Reuse existing `ProtocolVersion::V2` and `MessageType::Data`; their stable wire values are `2` and `1`.
- Reuse existing `SessionId`, `PeerIdentity`, and `EstablishedSessionMetadata` from
  `crate::session::types`. Do not redeclare or wrap them.
- The outer datagram is V2 framed and the complete fixed data header is authenticated.
- The client has one active data session. The server has at most one active data session and does
  not use a map until multi-peer support is separately designed.
- Remote malformed, unauthenticated, unknown-session, or replayed input is dropped and counted.
  It never terminates the runtime.
- Local state, cryptographic-provider, socket, TUN, and partial-write failures are fatal to the
  encrypted session.
- The data-plane module owns no TUN creation, routing, NAT, or configuration parsing.

## 2. Module responsibilities and seams

| Module | Interface responsibility | Must not own |
| --- | --- | --- |
| `src/data_plane/frame.rs` | Data frame limits, encode, decode, and authenticated-header bytes. | Crypto, replay state, sockets, or TUN. |
| `src/data_plane/session.rs` | Established-session lifecycle, sequences, replay window, endpoint binding, and counters. | Tokio I/O or raw keys. |
| `src/data_plane/crypto.rs` | A narrow encrypt/decrypt interface over directional transport state. | Frame parsing, session lookup, or replay mutation. |
| `src/crypto/noise_ik/transport.rs` | Adapt committed Noise-IK state into opaque directional transport. | Runtime policy and wire encoding. |
| `src/data_plane/runtime.rs` | Tokio orchestration, buffers, UDP/TUN I/O, outcomes, and orderly shutdown. | Frame or replay decisions inside `tokio::select!`. |
| `src/data_plane.rs` | Declarations and narrow crate-private re-exports. | Business logic. |

Frame and session modules are pure. Runtime is the only module that crosses the socket and TUN I/O
seam. This keeps the interfaces small and makes the policy testable without root or namespaces.

## 3. Data model and ownership

These are Rust-shaped definitions of the required properties. Field visibility is illustrative; all
secret transport fields remain private to the crypto adapter.

```rust
const COMMON_HEADER_LENGTH: usize = 10;
const DATA_HEADER_LENGTH: usize = 51;
const DATA_BODY_FIXED_LENGTH: usize = 41;
const FIRST_SEQUENCE: u64 = 1;
const MAX_SEQUENCE: u64 = u64::MAX - 1;
const SEQUENCE_EXHAUSTED: u64 = u64::MAX;
const UDP_PAYLOAD_CEILING: usize = 65_507;

use crate::session::types::{EstablishedSessionMetadata, PeerIdentity, SessionId};

// These are existing handshake and session types. The data plane reuses them.


enum DataDirection {
  ClientToServer,
  ServerToClient,
}

const DATA_AEAD_TAG_LENGTH: usize = crate::crypto::noise_ik::profile::AEAD_TAG_LENGTH;
const DATA_TRANSPORT_OVERHEAD: usize = DATA_AEAD_TAG_LENGTH;
const MINIMUM_DATA_CIPHERTEXT_LENGTH: usize = DATA_TRANSPORT_OVERHEAD + 1;

struct DataFrameCodec {
  maximum_plaintext_payload: usize,
  maximum_ciphertext: usize,
  maximum_body_length: u16,
  maximum_datagram_length: usize,
}

struct DataFrameHeader {
  body_length: u16,
  session_id: SessionId,
  direction: DataDirection,
  sequence: u64,
}

struct DecodedDataFrame<'datagram> {
  header: DataFrameHeader,
  ciphertext: &'datagram [u8],
}

struct SequenceBitmap {
  words: Vec<u64>,
}

struct ReplayWindow {
  width: usize,
  highest_accepted: Option<u64>,
  received: SequenceBitmap,
}

struct DirectionalTransport {
  state: NoiseTransportState,
}

enum DataPlaneRole {
  Client,
  Server,
}

enum DataSessionState {
  Established,
  Closing,
  Closed,
}

struct DataPlaneCounters {
  encrypted_packets: u64,
  encrypted_bytes: u64,
  decrypted_packets: u64,
  decrypted_bytes: u64,
  wrong_directions: u64,
  authentication_failures: u64,
  header_binding_failures: u64,
  replay_duplicates: u64,
  replay_too_old: u64,
  invalid_inner_packets: u64,
  outbound_input_drops: u64,
}

struct EstablishedDataSession {
  metadata: EstablishedSessionMetadata,
  peer_endpoint: std::net::SocketAddr,
  state: DataSessionState,
  send_direction: DataDirection,
  receive_direction: DataDirection,
  next_send_sequence: u64,
  replay_window: ReplayWindow,
  transport: DirectionalTransport,
  counters: DataPlaneCounters,
}

struct DataPlaneRuntimeCounters {
  malformed_frames: u64,
  unknown_sessions: u64,
  oversized_datagrams: u64,
}

struct DataSessionRegistry {
  active: Option<EstablishedDataSession>,
}

struct DataPlaneRuntime<Tun> {
  socket: tokio::net::UdpSocket,
  tun: Tun,
  codec: DataFrameCodec,
  registry: DataSessionRegistry,
  receive_counters: DataPlaneRuntimeCounters,
}

struct DataPlaneCleanupOutcome {
  already_closed: bool,
  final_counters: DataPlaneCounters,
}

enum ShutdownReason {
  CtrlC,
  SessionClosed,
}

struct DataPlaneShutdownOutcome {
  reason: ShutdownReason,
  cleanup: DataPlaneCleanupOutcome,
  receive_counters: DataPlaneRuntimeCounters,
}
```

`SessionId`, `PeerIdentity`, and `EstablishedSessionMetadata` are existing types from
`src/session/types.rs`; this design adds no competing definitions. Data-frame decode and encode
reject an all-zero `SessionId` at the wire boundary.

`DecodedDataFrame` borrows ciphertext from the UDP receive buffer and owns no allocation. The
runtime must finish decryption before reusing that buffer. `SequenceBitmap` stores `ceil(width / 64)` words and is an internal pure representation,
not part of the runtime interface. `NoiseTransportState` wraps one Snow `TransportState`, whose private CipherStates provide both
directions. The crypto adapter alone may call its nonce or message methods. `PeerIdentity` is carried by the existing committed handshake metadata. Do not reuse
`EstablishedServerSession`: it is handshake-policy state with candidate bookkeeping; the data session
receives only its established metadata and endpoint. Counter increments use saturating arithmetic.
`encrypted_bytes` and `decrypted_bytes` count inner plaintext bytes only; datagram sizes are not mixed
into these counters.

`Tun` is the existing `TunDevice` in production. A test-only adapter may expose the same
MTU, read, and complete-write behavior at the runtime seam. `DataDirection` converts only
wire value `0` to client-to-server and `1` to server-to-client. `MAX_SEQUENCE` is the final usable
sequence; `u64::MAX` is a non-wire sentinel meaning that the send direction is exhausted.

## 4. V2 encrypted data-frame profile

The Data message uses the existing V2 common header with the following exact layout.

```text
Offset  Size  Field
0       4     Magic ASCII CRBN
4       1     Version 2
5       1     Message type Data, wire value 1
6       2     Flags 0
8       2     Body length, big-endian, equal to 41 + ciphertext length
10      32    Non-zero session ID
42      1     Direction: 0 client-to-server, 1 server-to-client
43      8     Sequence number, big-endian, in 1 through MAX_SEQUENCE
51      N     Ciphertext including the transport authentication tag
```

The total datagram length is `10 + body_length`. The data codec rejects a frame when any of these
are false:

- total length is between `DATA_HEADER_LENGTH + 1` and the configured maximum;
- body length exactly matches the remaining datagram bytes;
- magic, version, Data kind, and flags have their fixed values;
- session ID is non-zero;
- direction is `0` or `1`;
- sequence is in `FIRST_SEQUENCE..=MAX_SEQUENCE`; and
- ciphertext is non-empty and no longer than `maximum_ciphertext`.

### Header binding

Snow `TransportState` does not take external AEAD associated data. `HEADER_BINDING_BYTES(header)`
therefore returns the exact first 51 outer-header bytes: magic, version, message type, flags, body
length, session ID, direction, and sequence.

`ENCRYPT` prefixes those 51 bytes to the raw TUN packet and encrypts that complete Noise payload.
`DECRYPT` verifies the decrypted prefix byte-for-byte against the received outer header before it
returns the inner packet. This binds every outer-header field without inventing an unsupported Snow
API.

The ciphertext length is `plaintext length + DATA_AEAD_TAG_LENGTH`; the datagram adds the 51-byte outer header.
`BUILD_DATA_HEADER` calculates this value before encryption. The codec creates the canonical header
once; crypto never independently serializes it.

## 5. Outcomes and error model

Untrusted network input is a normal outcome, not a top-level error. The runtime-facing interface is:

```rust
enum ReceiveOutcome {
  Delivered,
  RemoteDrop(RemoteDropReason),
}

enum SendOutcome {
  Sent,
  OutboundInputDrop(OutboundInputDropReason),
}

type DataPlaneResult<T> = Result<T, DataPlaneError>;
```

### Frame errors: `src/data_plane/frame.rs`

```rust
enum DataFrameCodecConfigError {
  ZeroMaximumPlaintextPayload,
  CiphertextLengthOverflow { maximum_plaintext_payload: usize },
  BodyLengthOverflow { maximum_ciphertext: usize },
  BodyLengthNotRepresentable { maximum_ciphertext: usize, maximum_body_length: usize },
  DatagramLengthOverflow { maximum_ciphertext: usize },
  DatagramExceedsUdpCeiling { maximum_datagram_length: usize, ceiling: usize },
}

enum DataFrameEncodeError {
  ZeroSessionId,
  InvalidSequence { observed: u64 },
  EmptyPlaintext,
  PlaintextTooLarge { size: usize, maximum: usize },
  CiphertextTooLarge { size: usize, maximum: usize },
  CiphertextLengthMismatch { declared: usize, actual: usize },
  BodyLengthNotRepresentable { body_length: usize },
  EncodedLengthOverflow { ciphertext_length: usize },
  OutputBufferTooSmall { required: usize, available: usize },
}

enum DataFrameDecodeError {
  DatagramTooShort { size: usize, minimum: usize },
  DatagramTooLarge { size: usize, maximum: usize },
  InvalidMagic,
  UnsupportedVersion { observed: u8 },
  UnsupportedMessageType { observed: u8 },
  UnsupportedFlags { observed: u16 },
  BodyLengthMismatch { declared: usize, actual: usize },
  DataBodyTooShort { size: usize, minimum: usize },
  ZeroSessionId,
  InvalidDirection { observed: u8 },
  InvalidSequence { observed: u64 },
}
```

Codec construction and local frame encoding errors are fatal. Every decode error becomes
`ReceiveOutcome::RemoteDrop(RemoteDropReason::MalformedFrame)` and is counted without logging
packet bytes.

### Session and crypto errors

```rust
enum DataSessionOperation {
  Create,
  Register,
  AllocateSendSequence,
  CommitReplay,
}

enum ReplayDecision {
  Acceptable,
  Duplicate,
  TooOld,
}

enum DataSessionError {
  ZeroSessionId,
  SessionAlreadyRegistered,
  InvalidState { operation: DataSessionOperation, state: DataSessionState },
  SendSequenceExhausted,
  ReplayWindowInvariant { sequence: u64 },
}

enum TransportOperation {
  BuildDirectionalTransport,
  Encrypt,
  Decrypt,
}

enum TransportError {
  InvalidState { operation: TransportOperation },
  DirectionMismatch,
  SendNonceMismatch { expected: u64, observed: u64 },
  ProviderFailure { operation: TransportOperation },
}

enum DecryptOutcome {
  Plaintext(Vec<u8>),
  HeaderBindingFailure,
  AuthFailure,
  LocalFailure(TransportError),
}
```

`HeaderBindingFailure` is a remote failure: a successfully decrypted prefix differs from the outer
header. `AuthFailure` is only for attacker-controlled ciphertext or tag verification failure. An unavailable
transport, impossible direction, or provider-state failure is `LocalFailure` and fatal. The crypto
adapter maps Snow decrypt or tag failures to `AuthFailure`; Snow state or nonce exhaustion failures are
local. It never returns a provider error that contains keys, nonce material, plaintext, or ciphertext.

### Runtime outcomes and fatal errors

```rust
enum RemoteDropReason {
  OversizedDatagram,
  MalformedFrame,
  UnknownSession,
  WrongDirection,
  ReplayDuplicate,
  ReplayTooOld,
  AuthenticationFailure,
  HeaderBindingFailure,
  InvalidInnerPacket,
}

enum OutboundInputDropReason {
  EmptyPacket,
  PacketExceedsMtu { size: usize, mtu: usize },
}

enum PacketOrigin {
  LocalTun,
  AuthenticatedPeer,
}

enum PlaintextValidation {
  Accepted,
  OutboundInputDrop(OutboundInputDropReason),
  InboundRemoteDrop(RemoteDropReason),
}

enum DataPlaneBuildError {
  FrameCodec(DataFrameCodecConfigError),
  TunMtuMismatch { tun_mtu: usize, codec_maximum_plaintext: usize },
  Session(DataSessionError),
  Transport(TransportError),
  NoEstablishedSession,
}

enum DataPlaneError {
  FrameEncode(DataFrameEncodeError),
  Session(DataSessionError),
  Transport(TransportError),
  UdpReceive { source: std::io::Error },
  UdpSend { source: std::io::Error },
  PartialUdpSend { expected: usize, actual: usize },
  TunRead { source: std::io::Error },
  TunWrite { source: std::io::Error },
  PartialTunWrite { expected: usize, actual: usize },
}
```

`RemoteDropReason` and `OutboundInputDropReason` are safe counter and rate-limited-log categories.
Do not log a full session ID, packet, ciphertext, key, nonce, or provider error detail. The project
uses explicit `Display` and `std::error::Error` implementations for crate-local enums. Use
`anyhow::Context` only at application, socket, TUN, or operating-system boundaries.

## 6. Function contracts

The contracts below deliberately use explicit `if` branches. `Err(...)` means a local failure: stop
startup or end the runtime. `RemoteDrop(...)` means unauthenticated or malformed peer traffic: count it,
optionally rate-limit-log its category, and keep the runtime alive. `checked_add(a, b)` means return the
shown error if the addition cannot be represented; it never wraps or panics.

### Frame module

```text
BUILD_DATA_CODEC(maximum_plaintext_payload)
  -> Result<DataFrameCodec, DataFrameCodecConfigError>
  # Local startup configuration. Every error prevents the runtime from starting.
  if maximum_plaintext_payload == 0:
    return Err(ZeroMaximumPlaintextPayload)

  maximum_ciphertext = checked_add(maximum_plaintext_payload, DATA_TRANSPORT_OVERHEAD)
    or return Err(CiphertextLengthOverflow { maximum_plaintext_payload })
  maximum_body_length = checked_add(DATA_BODY_FIXED_LENGTH, maximum_ciphertext)
    or return Err(BodyLengthOverflow { maximum_ciphertext })
  if maximum_body_length does not fit in u16:
    return Err(BodyLengthNotRepresentable { maximum_ciphertext, maximum_body_length })
  maximum_datagram_length = checked_add(DATA_HEADER_LENGTH, maximum_ciphertext)
    or return Err(DatagramLengthOverflow { maximum_ciphertext })
  if maximum_datagram_length > UDP_PAYLOAD_CEILING:
    return Err(DatagramExceedsUdpCeiling { maximum_datagram_length,
                                            ceiling: UDP_PAYLOAD_CEILING })

  return Ok(DataFrameCodec {
    maximum_plaintext_payload,
    maximum_ciphertext,
    maximum_body_length: maximum_body_length as u16,
    maximum_datagram_length,
  })

BUILD_DATA_HEADER(codec, session_id, direction, sequence, plaintext_length)
  -> Result<DataFrameHeader, DataFrameEncodeError>
  # `direction` is a typed DataDirection, not a raw byte, so it is valid by construction.
  # InvalidDirection is only a DECODE_DATA error for a raw byte received from the network.
  if session_id is all zero bytes:
    return Err(ZeroSessionId)
  if sequence == 0 or sequence > MAX_SEQUENCE:
    return Err(InvalidSequence { observed: sequence })
  if plaintext_length == 0:
    return Err(EmptyPlaintext)
  if plaintext_length > codec.maximum_plaintext_payload:
    return Err(PlaintextTooLarge { size: plaintext_length,
                                   maximum: codec.maximum_plaintext_payload })

  ciphertext_length = checked_add(plaintext_length, DATA_TRANSPORT_OVERHEAD)
    or return Err(EncodedLengthOverflow { ciphertext_length: plaintext_length })
  body_length = checked_add(DATA_BODY_FIXED_LENGTH, ciphertext_length)
    or return Err(EncodedLengthOverflow { ciphertext_length })
  if body_length does not fit in u16:
    return Err(BodyLengthNotRepresentable { body_length })

  return Ok(DataFrameHeader {
    body_length: body_length as u16, session_id, direction, sequence,
  })

ENCODE_DATA(codec, header, ciphertext, output)
  -> Result<encoded_length, DataFrameEncodeError>
  # DataFrameHeader fields are private; only BUILD_DATA_HEADER can create one.
  if LENGTH(ciphertext) < MINIMUM_DATA_CIPHERTEXT_LENGTH:
    return Err(CiphertextLengthMismatch { declared: MINIMUM_DATA_CIPHERTEXT_LENGTH,
                                          actual: LENGTH(ciphertext) })
  if LENGTH(ciphertext) > codec.maximum_ciphertext:
    return Err(CiphertextTooLarge { size: LENGTH(ciphertext),
                                    maximum: codec.maximum_ciphertext })
  declared_ciphertext_length = usize(header.body_length) - DATA_BODY_FIXED_LENGTH
  if LENGTH(ciphertext) != declared_ciphertext_length:
    return Err(CiphertextLengthMismatch { declared: declared_ciphertext_length,
                                          actual: LENGTH(ciphertext) })
  encoded_length = checked_add(DATA_HEADER_LENGTH, LENGTH(ciphertext))
    or return Err(EncodedLengthOverflow { ciphertext_length: LENGTH(ciphertext) })
  if LENGTH(output) < encoded_length:
    return Err(OutputBufferTooSmall { required: encoded_length, available: LENGTH(output) })

  # No write happened before this point, so every error leaves output unchanged.
  write magic, V2, Data message type, zero flags, header, and ciphertext into output
  return Ok(encoded_length)

DECODE_DATA(codec, datagram)
  -> Result<DecodedDataFrame, DataFrameDecodeError>
  # This handles only untrusted bytes. It neither looks up a session nor mutates state.
  if LENGTH(datagram) < COMMON_HEADER_LENGTH:
    return Err(DatagramTooShort { size: LENGTH(datagram), minimum: COMMON_HEADER_LENGTH })
  if LENGTH(datagram) > codec.maximum_datagram_length:
    return Err(DatagramTooLarge { size: LENGTH(datagram), maximum: codec.maximum_datagram_length })
  if datagram[0..4] != ASCII("CRBN"):
    return Err(InvalidMagic)
  if datagram[4] != ProtocolVersionV2:
    return Err(UnsupportedVersion { observed: datagram[4] })
  if datagram[5] != DataMessageType:
    return Err(UnsupportedMessageType { observed: datagram[5] })
  flags = U16_BE(datagram[6..8])
  if flags != 0:
    return Err(UnsupportedFlags { observed: flags })
  declared_body_length = usize(U16_BE(datagram[8..10]))
  actual_body_length = LENGTH(datagram) - COMMON_HEADER_LENGTH
  if declared_body_length != actual_body_length:
    return Err(BodyLengthMismatch { declared: declared_body_length, actual: actual_body_length })
  if actual_body_length < DATA_BODY_FIXED_LENGTH + MINIMUM_DATA_CIPHERTEXT_LENGTH:
    return Err(DataBodyTooShort { size: actual_body_length,
                                  minimum: DATA_BODY_FIXED_LENGTH + MINIMUM_DATA_CIPHERTEXT_LENGTH })

  session_id = datagram[10..42]
  if session_id is all zero bytes:
    return Err(ZeroSessionId)
  direction_byte = datagram[42]
  direction = DataDirection::try_from(direction_byte)
    or return Err(InvalidDirection { observed: direction_byte })
  sequence = U64_BE(datagram[43..51])
  if sequence == 0 or sequence > MAX_SEQUENCE:
    return Err(InvalidSequence { observed: sequence })
  ciphertext = datagram[51..]
  # The datagram-length check already enforces codec.maximum_ciphertext.

  return Ok(DecodedDataFrame {
    header: { session_id, direction, sequence, body_length: declared_body_length }, ciphertext,
  })

HEADER_BINDING_BYTES(header)
  -> [u8; DATA_HEADER_LENGTH]
  return the exact 51 bytes: magic, V2, Data type, zero flags, body length, session ID, direction, sequence
```

### Session module

```text
CREATE_DATA_SESSION(metadata, peer_endpoint, role, transport)
  -> Result<EstablishedDataSession, DataSessionError>
  if metadata.session_id is all zero bytes:
    return Err(ZeroSessionId)
  if role is Client:
    send_direction = ClientToServer
    receive_direction = ServerToClient
  else:  # role is Server; the type has no other value
    send_direction = ServerToClient
    receive_direction = ClientToServer
  return Ok(EstablishedDataSession { metadata, peer_endpoint, transport, send_direction,
                                     receive_direction, next_send_sequence: FIRST_SEQUENCE,
                                     replay_window: empty, state: Established })

REGISTER_ESTABLISHED_SESSION(registry, session)
  -> Result<(), DataSessionError>
  if registry.active is present:
    return Err(SessionAlreadyRegistered)
  registry.active = session
  return Ok(())

LOOKUP_ESTABLISHED_SESSION(registry, source, session_id)
  -> Option<session_handle>
  if registry.active is absent:
    return None
  if source != registry.active.peer_endpoint:
    return None
  if session_id != registry.active.metadata.session_id:
    return None
  return Some(registry.active)

ALLOCATE_SEND_SEQUENCE(session)
  -> Result<u64, DataSessionError>
  if session.state is not Established:
    return Err(InvalidState { operation: AllocateSendSequence, state: session.state })
  if session.next_send_sequence == SEQUENCE_EXHAUSTED:
    return Err(SendSequenceExhausted)
  sequence = session.next_send_sequence
  if sequence == MAX_SEQUENCE:
    session.next_send_sequence = SEQUENCE_EXHAUSTED
  else:
    session.next_send_sequence = sequence + 1
  return Ok(sequence)

REPLAY_MAY_ATTEMPT(window, sequence)
  -> ReplayDecision
  if sequence was already recorded in window:
    return Duplicate
  if sequence is older than the lowest sequence retained by window:
    return TooOld
  return Acceptable

REPLAY_COMMIT(window, sequence)
  -> Result<(), DataSessionError>
  if REPLAY_MAY_ATTEMPT(window, sequence) is not Acceptable:
    return Err(ReplayWindowInvariant { sequence })
  # Caller invokes this only after authentication and header binding succeed.
  record sequence in the window
  return Ok(())

CLOSE_DATA_SESSION(session)
  -> DataPlaneCleanupOutcome
  if session.state is Closed:
    return its existing counter snapshot
  session.state = Closing
  erase transport and replay state; stop new sends
  session.state = Closed
  return counter snapshot
```

### Crypto module

```text
BUILD_DIRECTIONAL_TRANSPORT(committed_noise_state)
  -> Result<DirectionalTransport, TransportError>
  if committed_noise_state cannot become a Snow transport state:
    return Err(ProviderFailure { operation: BuildDirectionalTransport })
  return Ok(DirectionalTransport { state: converted Snow transport state })

ENCRYPT(transport, sequence, header_bytes, plaintext)
  -> Result<Vec<u8>, TransportError>
  expected_nonce = sequence - FIRST_SEQUENCE  # sequence was validated before this call
  observed_nonce = transport.state.sending_nonce()
  if observed_nonce != expected_nonce:
    return Err(SendNonceMismatch { expected: expected_nonce, observed: observed_nonce })
  payload = header_bytes || plaintext
  ciphertext = transport.state.write_message(payload)
    or return Err(ProviderFailure { operation: Encrypt })
  return Ok(ciphertext)

DECRYPT(transport, sequence, header_bytes, ciphertext)
  -> DecryptOutcome
  expected_nonce = sequence - FIRST_SEQUENCE  # sequence was validated before this call
  # Snow exposes this lossy-transport nonce setter without an error return.
  # The earlier frame, direction, and replay checks guarantee expected_nonce is usable.
  transport.state.set_receiving_nonce(expected_nonce)
  decrypt_result = transport.state.read_message(ciphertext)
  if decrypt_result is a Snow authentication or tag-verification error:
    return AuthFailure
  if decrypt_result is any other Snow error:
    return LocalFailure(ProviderFailure { operation: Decrypt })
  decrypted = plaintext bytes from successful decrypt_result
  if LENGTH(decrypted) < DATA_HEADER_LENGTH:
    return HeaderBindingFailure
  if decrypted[0..DATA_HEADER_LENGTH] != header_bytes:
    return HeaderBindingFailure
  return Plaintext(decrypted[DATA_HEADER_LENGTH..])
```

### Runtime module

```text
BUILD_ENCRYPTED_RUNTIME(socket, tun, codec, registry)
  -> Result<DataPlaneRuntime, DataPlaneBuildError>
  if tun.mtu() != codec.maximum_plaintext_payload:
    return Err(TunMtuMismatch { tun_mtu: tun.mtu(),
                                codec_maximum_plaintext: codec.maximum_plaintext_payload })
  if registry.active is absent:
    return Err(NoEstablishedSession)
  return Ok(DataPlaneRuntime { socket, tun, codec, registry, receive_counters: zero })

VALIDATE_PLAINTEXT(codec, packet, origin)
  -> PlaintextValidation
  if LENGTH(packet) == 0 and origin is LocalTun:
    return OutboundInputDrop(EmptyPacket)
  if LENGTH(packet) == 0 and origin is AuthenticatedPeer:
    return InboundRemoteDrop(InvalidInnerPacket)
  if LENGTH(packet) > codec.maximum_plaintext_payload and origin is LocalTun:
    return OutboundInputDrop(PacketExceedsMtu { size: LENGTH(packet),
                                                mtu: codec.maximum_plaintext_payload })
  if LENGTH(packet) > codec.maximum_plaintext_payload and origin is AuthenticatedPeer:
    return InboundRemoteDrop(InvalidInnerPacket)
  return Accepted

SEND_DATA(session, packet, socket, codec)
  -> Result<SendOutcome, DataPlaneError>
  # Use the fully expanded decision procedure in section 7.
  # It maps each session, frame, transport, and socket failure to the DataPlaneError shown there.

RECEIVE_DATA(runtime, datagram, source)
  -> Result<ReceiveOutcome, DataPlaneError>
  # The detailed receive algorithm in section 7 defines every RemoteDrop branch.
  decode first, then match endpoint plus session ID, direction, replay eligibility, authentication, and inner packet
  release mutable session state before the TUN write await

SEND_UDP_COMPLETELY(socket, frame)
  -> Result<(), DataPlaneError>
  sent = socket.send(frame) or return Err(UdpSend { source: error })
  if sent != LENGTH(frame):
    return Err(PartialUdpSend { expected: LENGTH(frame), actual: sent })
  return Ok(())

WRITE_TUN_COMPLETELY(tun, packet)
  -> Result<(), DataPlaneError>
  written = tun.write(packet) or return Err(TunWrite { source: error })
  if written != LENGTH(packet):
    return Err(PartialTunWrite { expected: LENGTH(packet), actual: written })
  return Ok(())

RUN_ENCRYPTED_SESSION(runtime)
  -> Result<DataPlaneShutdownOutcome, DataPlaneError>
  create reusable mtu-plus-one and maximum-datagram-plus-one buffers
  create and pin one Ctrl-C future outside the loop
  loop until Ctrl-C:
    a local invalid TUN packet: count it and continue
    a RemoteDrop: count it and continue
    a DataPlaneError: close the session, then return that error
  on Ctrl-C: close the session and return clean shutdown
```

## 7. Data flow

```text
startup
  -> validate TunConfig and build codec from usize::from(TunConfig.mtu)
  -> run Noise-IK handshake and commit matching metadata
  -> create TUN only after handshake commit; its mtu must match codec maximum plaintext
  -> derive directional transport and create one established session
  -> register the session and start encrypted runtime

TUN to UDP
  -> validate local packet length
  -> allocate and consume sequence
  -> build header-binding bytes from the data header
  -> encrypt, encode, send one complete datagram
  -> count only after successful send

UDP to TUN
  -> receive into maximum-datagram-length plus one buffer
  -> drop oversize before decode
  -> decode and locate endpoint-bound established session
  -> reject wrong direction or replay without state change
  -> set the Snow receiving nonce from sequence, decrypt, and verify header binding
  -> commit replay after authentication
  -> validate packet length, write full packet, count successful delivery
```

### Complete send and receive pseudocode

```text
SEND_DATA(session, packet, socket, codec):
  validation = VALIDATE_PLAINTEXT(codec, packet, LocalTun)
  if validation is OutboundInputDrop(reason):
    session.counters.outbound_input_drops += 1
    return Ok(OutboundInputDrop(reason))

  sequence = ALLOCATE_SEND_SEQUENCE(session)
  if sequence is Err(error):
    return Err(DataPlaneError::Session(error))
  header = BUILD_DATA_HEADER(codec, session.metadata.session_id,
                             session.send_direction, sequence, LENGTH(packet))
  if header is Err(error):
    return Err(DataPlaneError::FrameEncode(error))
  header_bytes = HEADER_BINDING_BYTES(header)
  ciphertext = ENCRYPT(session.transport, sequence, header_bytes, packet)
  if ciphertext is Err(error):
    return Err(DataPlaneError::Transport(error))
  frame_length = ENCODE_DATA(codec, header, ciphertext, reusable_frame_buffer)
  if frame_length is Err(error):
    return Err(DataPlaneError::FrameEncode(error))

  # Do not keep a mutable session borrow while awaiting socket I/O.
  release mutable session borrow
  send_result = SEND_UDP_COMPLETELY(socket, reusable_frame_buffer[0..frame_length])
  if send_result is Err(error):
    return Err(error)
  reborrow the established session
  increment encrypted packet and byte counters
  return Ok(Sent)

RECEIVE_DATA(runtime, datagram, source):
  if LENGTH(datagram) > runtime.codec.maximum_datagram_length:
    runtime.receive_counters.oversized_datagrams += 1
    return Ok(RemoteDrop(OversizedDatagram))

  frame = DECODE_DATA(runtime.codec, datagram)
  if frame is Err(any decode error):
    runtime.receive_counters.malformed_frames += 1
    return Ok(RemoteDrop(MalformedFrame))

  session = LOOKUP_ESTABLISHED_SESSION(runtime.registry, source, frame.header.session_id)
  if session is absent:
    runtime.receive_counters.unknown_sessions += 1
    return Ok(RemoteDrop(UnknownSession))
  if frame.header.direction != session.receive_direction:
    session.counters.wrong_directions += 1
    return Ok(RemoteDrop(WrongDirection))

  replay = REPLAY_MAY_ATTEMPT(session.replay_window, frame.header.sequence)
  if replay is Duplicate:
    session.counters.replay_duplicates += 1
    return Ok(RemoteDrop(ReplayDuplicate))
  if replay is TooOld:
    session.counters.replay_too_old += 1
    return Ok(RemoteDrop(ReplayTooOld))

  header_bytes = HEADER_BINDING_BYTES(frame.header)
  decrypted = DECRYPT(session.transport, frame.header.sequence, header_bytes, frame.ciphertext)
  if decrypted is HeaderBindingFailure:
    session.counters.header_binding_failures += 1
    return Ok(RemoteDrop(HeaderBindingFailure))
  if decrypted is AuthFailure:
    session.counters.authentication_failures += 1
    return Ok(RemoteDrop(AuthenticationFailure))
  if decrypted is LocalFailure(error):
    return Err(DataPlaneError::Transport(error))
  plaintext = bytes from decrypted Plaintext(bytes)

  commit = REPLAY_COMMIT(session.replay_window, frame.header.sequence)
  if commit is Err(error):
    return Err(DataPlaneError::Session(error))
  validation = VALIDATE_PLAINTEXT(runtime.codec, plaintext, AuthenticatedPeer)
  if validation is InboundRemoteDrop(reason):
    session.counters.invalid_inner_packets += 1
    return Ok(RemoteDrop(reason))

  # Decryption and replay mutation are complete before TUN I/O.
  release mutable session borrow
  write_result = WRITE_TUN_COMPLETELY(runtime.tun, plaintext)
  if write_result is Err(error):
    return Err(error)
  reborrow the established session
  increment decrypted packet and byte counters
  return Ok(Delivered)
```

The oversized-datagram branch has no trusted session to charge when no active session exists. It is
counted by a runtime-level receive counter in that case. A successful authentication always commits
the sequence before plaintext-size rejection, preventing one authenticated but invalid packet from
being processed repeatedly.

## 8. States and invariants

```text
Handshake coordinator: Handshaking -> Established -> Closing -> Closed
Data session:           Established -> Closing -> Closed
```

- A data session is created only after the coordinator commits Noise-IK metadata and transport.
- A pending candidate has no usable data transport and cannot select a data session.
- One Noise transport state contains paired send and receive CipherStates. Direction values are
  opposite for client and server.
- Session ID, direction, sequence, kind, flags, and body length are bound by the encrypted header
  prefix.
- The outer sequence maps to Snow nonce `sequence - FIRST_SEQUENCE`. Send verifies the Snow sending
  nonce matches this value. Receive sets the Snow receiving nonce only after endpoint, direction,
  and replay prechecks pass.
- Sequence values are never reused for one send transport. A failed encrypt or send does not release
  a reserved sequence.
- Replay state changes only after authenticated decrypt success.
- Unknown endpoint or session ID cannot replace the active session.
- Plaintext reaches TUN only after authentication and MTU validation.
- Local invariant failure is fatal. Remote hostile input is a non-fatal drop.
- V1 and encrypted V2 are selected only at startup. No inbound downgrade exists.

The replay window accepts the first sequence, a new high sequence, and unseen reordered sequences
inside the configured width. It rejects duplicates and values older than the width. Its pure tests
must define behavior around `MAX_SEQUENCE`.

## 9. Shutdown and failure policy

Ctrl-C is an orderly `DataPlaneShutdownOutcome`, not an error. Fatal `DataPlaneError` stops both I/O
directions. In either case, runtime calls `CLOSE_DATA_SESSION`, then the application layer restores
only the routes, NAT, and forwarding state it owns.

Session close is infallible because transport key erasure and replay clearing are local memory
operations. Route, NAT, and TUN teardown remain application-layer concerns and may be reported with
`anyhow::Context` while preserving the primary forwarding failure.

## 10. Tests

### Pure module tests

- data codec exact vectors, every fixed field, short/oversize/length mismatch, and output unchanged
  after encode failure;
- authenticated header changes when any of its 51 bytes changes;
- both directional encrypt/decrypt paths, tampered ciphertext or tag rejection, outer-header
  binding mismatch rejection, and reordered receive sequences using the mapped Snow nonce;
- empty, MTU-size, and over-MTU packet validation;
- replay first/high/reordered/duplicate/too-old/exhaustion behavior;
- session creation, register collision, endpoint binding, sequence-to-Snow-nonce mismatch as a
  fatal error, sequence consumption after failed send, and key/replay erasure on close;
- every error variant has a focused test and no remote failure is returned as `DataPlaneError`.

### Runtime tests without privileges

Use fake TUN and UDP adapters or channels.

- encrypted TUN packet reaches peer and decrypted UDP packet reaches TUN;
- malformed, unknown-session, wrong-direction, bad-authentication, replay, and bad-plaintext input
  is dropped while the loop remains alive;
- socket, TUN, crypto-state, and partial-write failures terminate and close session state;
- server remains listening without a client candidate;
- Ctrl-C closes the session and produces an orderly outcome;
- legacy mode never accepts encrypted V2 data, and Noise-IK mode never falls back to V1.

### Namespace integration test

After pure and fake-runtime tests pass, add a separate Noise-IK namespace test with generated
throwaway keys. Prove encrypted delivery, tamper and replay drop behavior, and continued service.
Keep the existing V1 namespace test for routing and NAT separately.

## 11. Rust and Tokio guidance

- Keep all frame, replay, and session tests beside their modules and independent of root, TUN, or
  namespaces.
- Use checked arithmetic for derived lengths and sequence transitions. Use fixed byte arrays for
  IDs and headers and slices for borrowed frame ciphertext.
- Receive UDP into `maximum_datagram_length + 1`; treat a returned larger size as an oversize drop.
- Use `tokio::net::UdpSocket::recv_from` and `send_to`; require send length to equal frame length.
- Create and pin one Ctrl-C future outside `tokio::select!`. Keep select branches short and never
  hold a synchronous lock or mutable session borrow across await.
- Use owned `Vec<u8>` only when decryption crosses the async ownership seam. Do not interpret raw
  TUN or ciphertext bytes as UTF-8.
- Keep enums crate-private, implement `Display` plus `std::error::Error`, and avoid blanket `From`
  conversion from remote decode or authentication outcomes into `DataPlaneError`.

## 12. Completion criteria

This milestone is complete only when data forwarding begins exclusively after a committed Noise-IK
session; all remote malformed, authentication, replay, and invalid-inner-packet cases are non-fatal
drops; all local fatal cases close session state safely; legacy behavior remains unchanged; focused
and full unprivileged checks pass; and the privileged namespace test is run only with explicit
authorization. A successful handshake alone is not completion.
