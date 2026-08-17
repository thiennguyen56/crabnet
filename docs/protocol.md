# Current protocol

This document distinguishes the active wire protocol from the completed pure handshake model:

| Protocol layer | Status |
| --- | --- |
| Version 1 data frame below | Implemented and used by the executable |
| Four-message fake handshake | Implemented only as owned in-memory Rust values |
| Version 2 authenticated wire format | Not designed or implemented |

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

## Pure handshake messages are not wire frames

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

The in-memory flow proves coordinator ordering and correlation rules, not serialization:

```text
ClientHello → ServerHello → ClientFinish → ServerFinish
```

## Requirements for a future version 2

Before a version 2 parser reaches the coordinator, the protocol design must specify:

- an unambiguous frame discriminator and version negotiation/downgrade policy;
- exact handshake message encodings and maximum sizes;
- reviewed authentication and key-agreement semantics;
- how identities and the UDP endpoint are bound to the transcript;
- how an established `SessionId` selects encrypted data state;
- directional key and nonce derivation;
- monotonically validated sequence numbers and replay windows;
- retransmission, duplicate, reordering, timeout, and denial-of-service behavior;
- rekeying and key-erasure rules; and
- coexistence or migration behavior for version 1.

Until all of those are implemented and tested, version 1 must continue to be described as
unauthenticated lab framing.
