# Current protocol

Crabnet currently transports an inner IP packet as the payload of one UDP
datagram. The inner bytes are forwarded unchanged.

```text
TUN packet → UDP payload → peer TUN
```

There is currently:

- no Crabnet packet header;
- no version field;
- no handshake;
- no encryption;
- no authentication;
- no replay protection; and
- no fragmentation or reassembly.

The client uses a connected UDP socket. The server accepts the first valid peer
and rejects datagrams from other addresses. Packets larger than the configured
TUN MTU are dropped and counted.

This format is suitable only for the current lab milestone. A future protocol
must define framing, versioning, authentication, encryption, and replay rules
before production use.
