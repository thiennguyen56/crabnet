# Current service diagrams

These diagrams visualize Crabnet as it exists now. Mermaid diagrams render directly on GitHub and
remain reviewable as text.

The most important boundary is repeated throughout this page:

- version 1 packet forwarding is active in the executable; and
- the Milestone 2.3 handshake is complete only as a pure in-memory subsystem.

## 1. System context and implementation status

```mermaid
flowchart LR
    subgraph Runtime[Active version 1 runtime]
        ClientOS[Client OS]
        ClientTun[Client TUN]
        ClientRuntime[Crabnet client]
        UDP[UDP underlay]
        ServerRuntime[Crabnet server]
        ServerTun[Server TUN]
        ServerOS[Server OS routing]

        ClientOS --> ClientTun --> ClientRuntime --> UDP --> ServerRuntime --> ServerTun --> ServerOS
        ServerOS --> ServerTun --> ServerRuntime --> UDP --> ClientRuntime --> ClientTun --> ClientOS
    end

    subgraph Pure[Completed pure subsystem - tests only]
        ClientPolicy[Client policy]
        ClientCoordinator[Client coordinator]
        FakeClientCrypto[Fake client crypto]
        OwnedMessages[Owned handshake messages]
        ServerCoordinator[Server coordinator]
        ServerPolicy[Server policy]
        FakeServerCrypto[Fake server crypto]

        ClientPolicy <--> ClientCoordinator
        FakeClientCrypto <--> ClientCoordinator
        ClientCoordinator <--> OwnedMessages <--> ServerCoordinator
        ServerCoordinator <--> ServerPolicy
        ServerCoordinator <--> FakeServerCrypto
    end

    subgraph Future[Not implemented]
        RealProtocol[Reviewed protocol or library]
        WireCodec[Version 2 wire codec]
        RuntimeAdapter[Tokio transport adapter]
        EncryptedData[Encrypted and replay-protected data]

        RealProtocol --> WireCodec --> RuntimeAdapter --> EncryptedData
    end

    Pure -. design contract for .-> Future
    Future -. will eventually gate .-> Runtime
```

The dashed arrows are roadmap boundaries, not current calls. The executable does not construct or
drive either handshake coordinator.

## 2. Active version 1 packet flow

```mermaid
sequenceDiagram
    autonumber
    participant App as Client application
    participant CKernel as Client kernel
    participant CTun as Client TUN
    participant Client as Crabnet client
    participant UDP as UDP underlay
    participant Server as Crabnet server
    participant STun as Server TUN
    participant SKernel as Server kernel

    App->>CKernel: Send raw IP packet
    CKernel->>CTun: Route packet into crabnet0
    CTun->>Client: Read packet bytes
    Client->>Client: Validate MTU and encode version 1 frame
    Client->>UDP: Send one framed UDP datagram
    UDP->>Server: Receive datagram
    Server->>Server: Validate source and decode frame
    Note over Server: First completely valid frame selects the peer
    Server->>STun: Write original packet bytes
    STun->>SKernel: Inject packet into server network stack

    SKernel-->>STun: Route response into crabnet0
    STun-->>Server: Read response bytes
    Server-->>UDP: Encode and send version 1 frame
    UDP-->>Client: Receive datagram from configured server
    Client-->>CTun: Decode and write packet bytes
    CTun-->>CKernel: Inject response
    CKernel-->>App: Deliver response
```

This flow is framed but unauthenticated and unencrypted. A malformed first datagram cannot select
the peer, but any sender that can produce a valid version 1 data frame can.

## 3. Pure four-message handshake

```mermaid
sequenceDiagram
    autonumber
    participant CP as Client policy
    participant CC as Client coordinator
    participant CX as Client crypto
    participant SC as Server coordinator
    participant SP as Server policy
    participant SX as Server crypto

    CC->>CP: start(now)
    CP-->>CC: SendClientHello(attempt)
    CC->>CX: start_attempt(attempt)
    CX-->>CC: PreparedClientHello(attempt, opaque payload)
    CC->>SC: ClientHello(attempt, opaque payload)

    SC->>SP: handle_valid_client_hello(source, attempt, now)
    SP-->>SC: candidate and SendServerHello
    SC->>SX: prepare_server_hello(candidate, attempt, payload)
    SX-->>SC: PreparedServerHello(candidate, attempt, payload)
    SC->>CC: ServerHello(attempt, opaque payload)

    CC->>CP: precheck(source, attempt, ServerHello, now)
    CP-->>CC: Permit(trusted attempt)
    CC->>CX: authenticate_server_hello(attempt, payload)
    CX-->>CC: AuthenticatedServerHello(attempt)
    CC->>CP: handle_authenticated_server_hello(...)
    CP-->>CC: SendClientFinish(attempt)
    CC->>CX: prepare_client_finish(attempt)
    CX-->>CC: PreparedClientFinish(attempt, payload)
    CC->>SC: ClientFinish(attempt, opaque payload)

    SC->>SP: precheck_client_finish(source, attempt, now)
    SP-->>SC: PermitNew(candidate, trusted attempt)
    SC->>SX: authenticate_client_finish(candidate, attempt, payload)
    SX-->>SC: Authenticated metadata
    SC->>SP: commit authenticated session
    SC->>SX: commit same metadata
    SC->>SX: prepare_server_finish(...)
    SX-->>SC: PreparedServerFinish
    SC->>CC: ServerFinish(attempt, opaque payload)

    CC->>CP: precheck(source, attempt, ServerFinish, now)
    CP-->>CC: Permit(trusted attempt)
    CC->>CX: authenticate_server_finish(attempt, payload)
    CX-->>CC: Authenticated same session metadata
    CC->>CP: commit authenticated session
    CC->>CX: commit same metadata

    Note over CC,SC: Both report the same session ID and opposite peer identities
```

Every arrow here is a synchronous Rust call or movement of an owned Rust value in a test. It does
not represent UDP bytes yet.

## 4. Client stable states

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> AwaitingServerHello: start / send ClientHello
    AwaitingServerHello --> AwaitingServerFinish: authenticated ServerHello / send ClientFinish
    AwaitingServerFinish --> Established: authenticated ServerFinish / commit metadata

    AwaitingServerHello --> Closed: deadline reached
    AwaitingServerFinish --> Closed: deadline reached
    AwaitingServerHello --> Closed: remote authentication failure
    AwaitingServerFinish --> Closed: remote authentication failure
    Idle --> Closed: shutdown
    AwaitingServerHello --> Closed: shutdown
    AwaitingServerFinish --> Closed: shutdown
    Established --> Closed: shutdown
    Closed --> Closed: repeated shutdown
```

Wrong source, stale attempt, or unexpected message produces a drop without advancing a valid
attempt. A local policy, crypto, or invariant error takes the fail-closed path instead.

## 5. Server candidate and session lifecycle

```mermaid
stateDiagram-v2
    [*] --> Listening

    state Listening {
        [*] --> NoCandidates
        NoCandidates --> PendingCandidates: valid ClientHello admitted
        PendingCandidates --> PendingCandidates: another candidate admitted
        PendingCandidates --> PendingCandidates: identical ClientHello duplicate
        PendingCandidates --> PendingCandidates: one candidate expires or fails authentication
        PendingCandidates --> NoCandidates: final candidate expires or fails authentication
    }

    Listening --> Established: authenticated ClientFinish and matching commits
    Listening --> Closed: shutdown or fatal local error
    Established --> Established: exact duplicate ClientFinish / resend confirmation
    Established --> Closed: shutdown or fatal local error
    Closed --> Closed: repeated shutdown
```

The server can own several pending candidates in the pure subsystem, but only one session can be
established. Candidate identity is the tuple of source ownership, server-assigned `CandidateId`,
and client attempt ID.

## 6. Inbound decision and fail-closed behavior

```mermaid
flowchart TD
    Inbound[Inbound handshake message] --> Policy[Policy precheck]
    Policy -->|Drop| Drop[Ok report with typed Dropped event]
    Policy -->|Timeout| Timeout[Remove exact crypto context]
    Policy -->|Permit trusted IDs| Crypto[Authenticate opaque payload]
    Policy -->|Local error| Fatal[Create FatalCoordinatorError]

    Crypto -->|Expected remote failure| RemoteCheck{Correct failure domain and IDs?}
    Crypto -->|Success| Correlation{All returned IDs and metadata match?}
    Crypto -->|Local error| Fatal

    RemoteCheck -->|Yes| ScopedCleanup[Apply exact policy and crypto cleanup]
    RemoteCheck -->|No| Fatal
    ScopedCleanup --> Verify[Verify stable policy and crypto phases]
    Timeout --> Verify
    Correlation -->|No| Fatal
    Correlation -->|Yes| Apply[Apply policy transition and crypto commit]
    Apply --> Verify

    Verify -->|Valid| Outcome{Result path}
    Verify -->|Mismatch| Fatal
    Outcome -->|Expected remote rejection| Drop
    Outcome -->|Accepted or timed out| Success[Ok report with outbound messages and events]

    Fatal --> PolicyShutdown[Attempt policy shutdown]
    PolicyShutdown --> CryptoShutdown[Always erase crypto contexts]
    CryptoShutdown --> Closed[Coordinator lifecycle Closed]
    Closed --> Error[Err with primary and both cleanup outcomes]
```

Remote authentication failure is ordinary hostile input when its domain and IDs are valid. A
provider returning the wrong failure variant or wrong correlation is a local contract violation and
therefore fatal.

## 7. Planned integration boundary

```mermaid
flowchart LR
    Datagram[Untrusted UDP datagram]
    Parser[Bounded version 2 parser]
    Message[Owned handshake message]
    Coordinator[Pure coordinator]
    Report[Outbound messages and events]
    Serializer[Version 2 serializer]
    Socket[Tokio UDP socket]
    Deadline[Nearest coordinator deadline]
    Forwarding[Encrypted data forwarding]

    Datagram --> Parser --> Message --> Coordinator --> Report --> Serializer --> Socket
    Deadline --> Coordinator
    Report -->|SessionEstablished| Forwarding
```

The adapter must keep parsing, socket I/O, timers, and cancellation outside the pure coordinator.
It must not hold a coordinator borrow across `.await`, and forwarding must remain disabled until a
real provider establishes authenticated session state.
