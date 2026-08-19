# Routing sequence diagrams

These diagrams show the implemented namespace traffic path and the remaining
internet-facing path. The private-service test covers full-tunnel selection,
server routing, IPv4 forwarding, and source NAT. General internet use remains
future work because firewall policy and full-tunnel DNS are not managed.

The packet-path diagrams show the legacy unauthenticated V1 runtime. Noise-IK is a separate
handshake-only runtime path: it exchanges and authenticates V2 handshake frames, then stops before
TUN creation and packet forwarding. These diagrams must not be read as encrypted tunnels.

## Private service routing

```mermaid
sequenceDiagram
    participant App as Client application
    participant CTun as Client TUN
    participant C as Crabnet client
    participant U as Underlay UDP
    participant S as Crabnet server
    participant STun as Server TUN
    participant NAT as Server nftables NAT
    participant R as Backend router
    participant P as Private service

    App->>CTun: Send packet<br/>10.0.0.2 → 10.10.0.2
    CTun->>C: Read inner IP packet
    C->>U: Encapsulate and send UDP
    U->>S: Deliver UDP datagram
    S->>STun: Write inner packet
    STun->>NAT: Forward 10.0.0.2 → 10.10.0.2
    NAT->>R: Masquerade as 172.16.0.1<br/>route via 172.16.0.2
    R->>P: Forward translated request
    P-->>R: Response to 172.16.0.1
    R-->>NAT: Return through connected network
    NAT-->>STun: Restore destination 10.0.0.2
    STun->>S: Read response from TUN
    S->>U: Encapsulate response in UDP
    U->>C: Deliver UDP datagram
    C->>CTun: Write response packet
    CTun->>App: Application receives response
```

## Global/full-tunnel routing

Startup resolves and protects the transport path before redirecting the
client's remaining traffic:

```mermaid
sequenceDiagram
    participant C as Client OS
    participant App as Crabnet
    participant Tun as crabnet0
    App->>C: Resolve current route to VPN server
    C-->>App: Underlay gateway and interface
    App->>C: Add VPN server /32 or /128 via underlay
    App->>C: Add 0.0.0.0/0 or ::/0 via Tun
```

The lookup must precede the TUN default route; otherwise route resolution could
return `crabnet0` and send the tunnel's own UDP packets back into the tunnel.

```mermaid
sequenceDiagram
    participant App as Client application
    participant CTun as Client TUN
    participant C as Crabnet client
    participant U as Underlay UDP
    participant S as Crabnet server
    participant STun as Server TUN
    participant NAT as Server nftables NAT
    participant I as Internet service

    App->>CTun: Send packet<br/>10.0.0.2 → 8.8.8.8
    CTun->>C: Read inner IP packet
    C->>U: Encapsulate and send UDP
    U->>S: Deliver UDP datagram
    S->>STun: Write inner packet
    STun->>NAT: Forward and masquerade<br/>10.0.0.2 → server public IP
    NAT->>I: Send translated packet
    I-->>NAT: Internet response
    NAT-->>STun: Restore destination 10.0.0.2
    STun->>S: Read response from TUN
    S->>U: Encapsulate response in UDP
    U->>C: Deliver UDP datagram
    C->>CTun: Write response packet
    CTun->>App: Application receives response
```

The client default route and VPN-server endpoint exclusion are implemented for
the isolated namespace test. Server IPv4 forwarding, masquerading, ownership
checks, and graceful NAT cleanup are also implemented. The remaining global
path requires:

- administrator-managed firewall forwarding policy;
- full-tunnel DNS handling; and
- a reviewed version 2 handshake and encrypted data protocol;
- runtime integration that gates forwarding on established session metadata; and
- authentication, replay protection, and rekeying before use on untrusted networks.
