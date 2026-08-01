# Routing sequence diagrams

These diagrams show the two intended traffic paths. The private-service path
is covered by the current four-namespace full-tunnel test. Global internet
access is future work because it still requires NAT, firewall rules, and DNS
handling.

## Private service routing

```mermaid
sequenceDiagram
    participant App as Client application
    participant CTun as Client TUN
    participant C as Crabnet client
    participant U as Underlay UDP
    participant S as Crabnet server
    participant STun as Server TUN
    participant R as Backend router
    participant P as Private service

    App->>CTun: Send packet<br/>10.0.0.2 → 10.10.0.2
    CTun->>C: Read inner IP packet
    C->>U: Encapsulate and send UDP
    U->>S: Deliver UDP datagram
    S->>STun: Write inner packet
    STun->>S: Server forwarding
    S->>R: Route 10.10.0.0/24<br/>via 172.16.0.2
    R->>P: Forward to 10.10.0.2
    P-->>R: Response to 10.0.0.2
    R-->>S: Return via 172.16.0.1
    S->>STun: Write response to TUN
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
    participant NAT as Server NAT/firewall
    participant I as Internet service

    App->>CTun: Send packet<br/>10.0.0.2 → 8.8.8.8
    CTun->>C: Read inner IP packet
    C->>U: Encapsulate and send UDP
    U->>S: Deliver UDP datagram
    S->>STun: Write inner packet
    STun->>S: Forward toward default route
    S->>NAT: Apply source NAT<br/>10.0.0.2 → server public IP
    NAT->>I: Send packet to 8.8.8.8
    I-->>NAT: Internet response
    NAT-->>S: Restore destination 10.0.0.2
    S->>STun: Write response to server TUN
    S->>U: Encapsulate response in UDP
    U->>C: Deliver UDP datagram
    C->>CTun: Write response packet
    CTun->>App: Application receives response
```

The client default route and VPN-server endpoint exclusion are implemented for
the isolated namespace test. The remaining global path requires:

- server NAT/masquerading;
- firewall forwarding rules;
- DNS handling; and
- route and firewall cleanup during shutdown.
