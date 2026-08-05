# Current protocol

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

- no handshake;
- no encryption;
- no authentication;
- no replay protection;
- no key rotation; and
- no fragmentation or reassembly.

This format remains suitable only for the isolated lab milestone. A future
authenticated protocol must define peer identity, key establishment,
directional keys, nonce construction, sequence validation, and replay rules
before use on untrusted networks.
