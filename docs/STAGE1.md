# 🦀 Crabnet — Stage 1: Networking Foundations

> _Before building a VPN or networking framework, understand how data moves, how it is structured, and how software keeps track of connections._

---

# Goal

The goal of Stage 1 is **not** to build a VPN.

The goal is to understand the fundamental building blocks used by almost every modern networking system, including:

- VPNs
- WireGuard
- OpenVPN
- Tailscale
- SSH
- QUIC
- TCP
- Distributed systems

By the end of this stage, I should understand **how packets move through a networking application** and what responsibilities my software has.

---

# The Big Picture

Every packet follows roughly this journey:

```text
Application
      │
      ▼
Virtual Network Interface (TUN)
      │
      ▼
Crabnet
 ├── Packet Format
 ├── Session Manager
 ├── Routing
 ├── State Machine
 └── Transport
      │
      ▼
UDP Socket
      │
      ▼
Internet
      │
      ▼
UDP Socket
      │
      ▼
Crabnet
      │
      ▼
Virtual Network Interface
      │
      ▼
Application
```

Everything learned in Stage 1 exists somewhere along this pipeline.

---

# Part 1 — Moving Data (The I/O Layer)

## UDP Socket

### What is it?

A UDP socket is the application's direct interface to the real network.

Unlike TCP, UDP is **connectionless**.

There is:

- no connection establishment
- no reliability
- no ordering
- no retransmission

The operating system simply sends whatever bytes we provide.

### Mental Model

Think of UDP as mailing a postcard.

You write the destination address.

You drop it into the mailbox.

Whether it arrives is not guaranteed.

### Crabnet's responsibility

- Open a UDP socket.
- Send bytes.
- Receive bytes.
- Everything else must be implemented by Crabnet.

---

## TUN Interface

### What is it?

A TUN device is a **virtual Layer-3 network interface** created by the operating system.

Applications see it exactly like a normal network card.

The only difference is that software reads and writes packets instead of hardware.

### Mental Model

Instead of:

```text
Application
      │
Ethernet Card
```

we have:

```text
Application
      │
Virtual Network Card (TUN)
      │
Crabnet
```

### Crabnet's responsibility

Read raw IP packets from the TUN device.

Write raw IP packets back into the TUN device.

The operating system automatically handles the applications using that interface.

---

# Part 2 — Structuring Data (The Wire Protocol)

## Packet Headers

### Why?

The internet only transmits bytes.

Those bytes need structure.

Every Crabnet packet starts with a custom header.

Example:

```text
+--------------------+
| Crabnet Header     |
+--------------------+
| IP Packet Payload  |
+--------------------+
```

The header tells the receiver how to interpret the packet.

Typical fields include:

- Version
- Packet Type
- Session ID
- Sequence Number
- Payload Length
- Flags

---

## Serialization

### What is it?

Turning an in-memory Rust structure into raw bytes.

```rust
struct Packet {
    header,
    payload,
}
```

↓

```text
010101010100011001...
```

The reverse process is called **deserialization**.

### Crabnet's responsibility

Convert Rust structs into bytes before sending.

Convert received bytes back into Rust structs.

---

# Part 3 — Keeping Order (The Logic Layer)

UDP has no concept of "connections."

Crabnet must build that logic itself.

---

## Session Management

A session represents one active communication channel.

Example:

```text
Session

ID

Peer Address

Shared Key

Last Seen

Current State
```

Sessions are typically stored in memory.

For Stage 1, a simple `HashMap` is sufficient.

---

## State Machines

Networking protocols are built around **state transitions**.

Instead of allowing every packet at any time, the software controls what is valid in each state.

Example:

```text
Disconnected
      │
      ▼
Handshake
      │
      ▼
Authenticating
      │
      ▼
Established
      │
      ▼
Closing
```

If a packet arrives in the wrong state, it should be rejected.

This prevents many synchronization and security bugs.

---

## Keep-Alive

UDP never tells us whether the other side disappeared.

Crabnet periodically sends a tiny heartbeat packet.

Purpose:

> "I'm still here."

The peer replies to confirm it is still alive.

---

## Timeouts

Every session stores:

```text
last_seen
```

Whenever a valid packet is received:

```text
last_seen = now
```

A background task periodically checks:

```text
now - last_seen
```

If it exceeds the timeout:

- Remove the session.
- Release resources.
- Notify the application if necessary.

---

# Part 4 — Directing Traffic (The Infrastructure Layer)

## Routing Tables

Once a packet is decrypted, Crabnet needs to know where it should go.

A routing table maps a destination to a next hop.

Stage 1 keeps this simple:

```text
Destination IP

↓

Session
```

Later stages may introduce:

- CIDR
- Longest-prefix matching
- Route metrics
- Default routes

---

## Multiplexing

Multiplexing means handling **multiple logical communication streams** over a small number of physical I/O channels.

Example:

```text
          UDP Socket
              │
      ┌───────┼────────┐
      │       │        │
   Session A Session B Session C
```

One socket.

Many sessions.

Crabnet decides which incoming packet belongs to which session.

---

## Concurrency

Concurrency is **how** the program makes progress on multiple tasks without one blocking the others.

Examples of concurrent tasks:

- Reading from the TUN device
- Reading from the UDP socket
- Sending packets
- Processing sessions
- Running timeout checks

Possible implementations include:

- Multiple threads
- Async runtimes (Tokio)
- Event loops
- Non-blocking I/O

Concurrency is an implementation strategy.

Multiplexing is the networking concept.

---

# Stage 1 Responsibilities

At the end of Stage 1, I should understand how to:

- Read packets from a TUN interface.
- Send packets through a UDP socket.
- Design packet headers.
- Serialize and deserialize data.
- Track active sessions.
- Build state machines.
- Implement keep-alives.
- Detect connection timeouts.
- Perform basic routing lookups.
- Understand multiplexing.
- Choose a concurrency model.

I do **not** need encryption, authentication, NAT traversal, peer discovery, or advanced routing yet.

---

# What Comes Next?

Stage 2 has a single objective:

> **Successfully move one IP packet through Crabnet.**

Nothing more.

The milestones are:

1. Read packets from the TUN device.
2. Send those bytes over a UDP socket.
3. Receive them on another machine.
4. Write them into another TUN device.
5. Successfully transmit a `ping` through the tunnel.

Once that works, Crabnet has its first working data path.

Everything else—encryption, handshakes, routing, observability, NAT traversal, and mesh networking—will be built on top of this foundation.

---

# Key Takeaways

- **UDP moves bytes, not connections.**
- **TUN provides raw IP packets.**
- **Packet headers define the wire protocol.**
- **Serialization converts data structures into bytes.**
- **Sessions represent active peers.**
- **State machines control protocol behavior.**
- **Keep-alives and timeouts detect dead peers.**
- **Routing decides where packets go.**
- **Multiplexing manages many logical streams over shared I/O.**
- **Concurrency keeps the system responsive.**

These concepts are the foundation of modern networking software. Mastering them first makes every later stage—from encryption to distributed networking—much easier to understand.
