# Current protocol

This document distinguishes the active wire protocol from the completed pure handshake model:

| Protocol layer | Status |
| --- | --- |
| Version 1 data frame below | Implemented and used by the executable |
| Four-message fake handshake | Implemented only as owned in-memory Rust values |
| Version 2 handshake framing codec | Implemented and pure-tested, but not used by the executable |
| Authenticated and encrypted runtime protocol | Not implemented |

Crabnet transports one raw inner IP packet in one version 1 data frame carried
by one UDP datagram. The frame distinguishes Crabnet traffic, enforces explicit
length boundaries, and permits incompatible versions to be rejected safely.

```text
TUN packet
→ Crabnet version 1 data frame
→ UDP datagram
→ validate and decode
→ peer TUN
```

## Version 1 data frame

All multi-byte integers use network byte order (big-endian).

| Offset | Size | Field | Version 1 requirement |
| ---: | ---: | --- | --- |
| 0 | 4 | Magic | ASCII `CRBN` |
| 4 | 1 | Version | `1` |
| 5 | 1 | Message type | `1` for data |
| 6 | 2 | Flags | Must be zero |
| 8 | 2 | Payload length | Exact inner-packet length |
| 10 | N | Payload | One non-empty raw inner IP packet |

The decoder rejects short headers, incorrect magic, unsupported versions,
unknown message types, non-zero reserved flags, empty payloads, mismatched
lengths, trailing bytes, and payloads larger than the configured TUN MTU.
Malformed remote frames are counted and dropped rather than terminating the
forwarding loop.

## Packet and buffer boundaries

For an inner TUN MTU of `M` bytes:

```text
maximum inner packet       = M
maximum framed UDP datagram = 10 + M
UDP receive buffer          = 10 + M + 1
```

The extra receive byte distinguishes an oversized UDP datagram from a valid
maximum-sized frame. Encoding uses a reusable `10 + M` output buffer. Decoding
returns a payload slice borrowed from the UDP buffer and does not allocate or
reinterpret the binary inner packet.

The server registers its first peer only after that address sends a completely
valid frame. Empty, oversized, malformed, and unsupported frames cannot select
the peer. Once selected, later datagrams from other addresses are rejected
without replacing it.

## Version 2 handshake frame

The pure version 2 codec defines a bounded byte envelope for the four handshake messages. It does
not select a cryptographic protocol, interpret provider payloads, or send datagrams.

All multi-byte integers use network byte order.

| Offset | Size | Field | Version 2 requirement |
| ---: | ---: | --- | --- |
| 0 | 4 | Magic | ASCII `CRBN` |
| 4 | 1 | Version | `2` |
| 5 | 1 | Message type | `2` through `5` for the four handshake messages |
| 6 | 2 | Flags | Must be zero |
| 8 | 2 | Body length | Exact length after the 10-byte header |
| 10 | 8 | Client attempt ID | Non-zero unsigned integer |
| 18 | N | Opaque payload | Non-empty and within the configured maximum |

For a configured maximum opaque payload of `P`:

```text
maximum body length            = 8 + P
maximum valid datagram length  = 10 + 8 + P
UDP receive buffer             = maximum valid datagram length + 1
```

Construction rejects a zero maximum, arithmetic overflow, a body that does not fit its 16-bit
field, and a maximum datagram above the IPv4-safe UDP payload ceiling of 65,507 bytes. Decoding
requires exact lengths and borrows the opaque payload without allocation. The client accepts only
`ServerHello` and `ServerFinish`; the server accepts only `ClientHello` and `ClientFinish`.
Version 1 data and version 2 handshake message types are mutually rejected.

See [the framing design](handshake-framing-design.md) for the exhaustive contract. This codec is
not connected to sockets or the coordinators, so successful parsing is neither authentication nor
permission to forward packets.

## Security boundary

Version 1 framing does not provide authentication, confidentiality, integrity,
or replay protection. Anyone able to send a valid version 1 frame to an
unregistered server can still select the single peer and inject inner packets.

There is currently:

- no handshake on the wire or in the runtime;
- no encryption;
- no authentication;
- no replay protection;
- no key rotation; and
- no fragmentation or reassembly.

This format remains suitable only for the isolated lab milestone. A future
authenticated protocol must define peer identity, key establishment,
directional keys, nonce construction, sequence validation, and replay rules
before use on untrusted networks.

## Pure handshake messages and byte envelopes remain separate

Milestone 2.3 defines these generic transport-neutral values:

```text
ClientHello<Payload>  { client_attempt_id, payload }
ServerHello<Payload>  { client_attempt_id, payload }
ClientFinish<Payload> { client_attempt_id, payload }
ServerFinish<Payload> { client_attempt_id, payload }
```

Their payloads are opaque associated types owned by the crypto provider. They deliberately define
no magic bytes, message numbers, field widths, length encoding, fragmentation, retransmission, or
downgrade behavior. `CandidateId` is server-local and must not be copied into a wire format merely
because the fake provider uses it internally.

The V2 codec can wrap an attempt ID and already-serialized opaque bytes, but a future provider
adapter must perform that conversion. The in-memory flow proves coordinator ordering:

```text
ClientHello → ServerHello → ClientFinish → ServerFinish
```

## Remaining requirements for an authenticated version 2 runtime

Before the V2 codec reaches the coordinator or runtime, the protocol design must specify:

- reviewed authentication and key-agreement semantics;
- authenticated binding of the outer frame fields, roles, and selected configuration;
- an operational opaque-payload limit with path-MTU reasoning;
- how identities and the UDP endpoint are bound to the transcript;
- how an established `SessionId` selects encrypted data state;
- directional key and nonce derivation;
- monotonically validated sequence numbers and replay windows;
- retransmission, duplicate, reordering, timeout, and denial-of-service behavior;
- rekeying and key-erasure rules; and
- coexistence or migration behavior for version 1.

Until all of those are implemented and tested, version 1 must continue to be described as
unauthenticated lab framing.
