# 🦀 Crabnet Stage 1 — Learning Philosophy

> **Don't memorize APIs. Understand the problems they solve.**

Networking is simply moving information between computers. Everything else—VPNs, SSH, HTTP, databases, distributed systems—is built on a small set of fundamental concepts.

This stage focuses on mastering those fundamentals.

---

# Chapter Structure

Every chapter follows the same learning pattern.

## 1. The Problem

Every networking concept exists because a real problem needed solving.

Questions to answer:

- Why was this invented?
- What would happen without it?
- What limitations existed before?

If you cannot explain the problem, the solution won't make much sense.

---

## 2. The Theory

This explains the underlying computer science.

Topics include:

- Operating systems
- Network layers
- Protocol design
- State machines
- Serialization
- Concurrency

The goal is understanding _how computers think_, not memorizing functions.

---

## 3. Mental Model

Every difficult topic should have an intuitive explanation.

Examples:

UDP

> Mailing postcards.

TCP

> A phone call.

TUN

> A virtual network card.

Routing Table

> Google Maps.

Session

> A conversation between two people.

These analogies should help build intuition before diving into implementation.

---

## 4. How Linux Actually Works

Understand what happens inside the operating system.

Questions to answer:

- Which kernel subsystem is responsible?
- Where does the packet go?
- Which syscall is involved?
- What does the kernel expect?

Example:

Application

↓

write()

↓

Kernel

↓

UDP Stack

↓

NIC

↓

Internet

---

## 5. How Crabnet Uses It

After understanding the operating system, explain why Crabnet needs this concept.

Questions:

- What responsibility belongs to Linux?
- What responsibility belongs to Crabnet?
- What are we building ourselves?

This separates platform behavior from application logic.

---

## 6. Implementation Preview

Do **not** build the complete feature.

Only show enough code to connect the theory with reality.

Example:

```rust
let socket = UdpSocket::bind("0.0.0.0:9000")?;
socket.send_to(data, peer)?;
```

The objective is familiarity, not completeness.

---

## 7. Common Misconceptions

Every chapter should explain what beginners often misunderstand.

Examples:

### UDP

❌ UDP creates connections.

✅ UDP sends independent datagrams.

---

### TUN

❌ TUN is a VPN.

✅ TUN is simply a virtual Layer-3 network interface.

---

### Sessions

❌ UDP tracks clients.

✅ Your application tracks clients.

---

## 8. Connections to Future Stages

Every chapter should answer:

> Why am I learning this now?

Example:

Understanding UDP today makes encryption, NAT traversal, and mesh networking much easier later.

Learning should always build on previous knowledge.

---

# Stage 1 Topics

## Part 1 — Moving Data

### Chapter 1

UDP Sockets

Learn:

- Why UDP exists
- Datagram communication
- Connectionless networking
- Ports
- IP addresses
- Kernel networking stack

---

### Chapter 2

TUN Interface

Learn:

- Virtual network devices
- Layer 3 networking
- File descriptors
- Linux networking
- Packet injection
- Packet extraction

---

# Part 2 — Structuring Data

### Chapter 3

Packet Design

Learn:

- Binary protocols
- Fixed vs variable headers
- Versioning
- Protocol evolution
- Alignment
- Endianness

---

### Chapter 4

Serialization

Learn:

- Bytes
- Memory layout
- Encoding
- Parsing
- Network byte order
- Zero-copy concepts

---

# Part 3 — Managing Communication

### Chapter 5

Sessions

Learn:

- Connection tracking
- Peer identity
- Session lifetime
- Session storage
- Resource management

---

### Chapter 6

State Machines

Learn:

- Finite state machines
- Protocol correctness
- Illegal transitions
- Failure handling

---

### Chapter 7

Keep-Alive

Learn:

- Heartbeats
- Liveness
- Failure detection

---

### Chapter 8

Timeouts

Learn:

- Timers
- Scheduling
- Resource cleanup
- Idle detection

---

# Part 4 — Moving Packets

### Chapter 9

Routing

Learn:

- Destination lookup
- Next hop
- Forwarding
- Basic routing logic

---

### Chapter 10

Multiplexing

Learn:

- Multiple logical streams
- Packet dispatch
- Shared transports

---

### Chapter 11

Concurrency

Learn:

- Threads
- Event loops
- Async I/O
- Non-blocking sockets
- Synchronization

---

# Learning Goal

By the end of Stage 1, I should be able to explain—not just implement—the following questions:

- Why does UDP exist?
- Why isn't UDP enough for a VPN?
- Why do we need a TUN interface?
- Why must applications define packet formats?
- Why doesn't UDP have sessions?
- Why are protocol state machines essential?
- Why do heartbeats detect dead peers?
- Why does routing determine packet delivery?
- Why is multiplexing different from concurrency?
- Why do networking applications often use asynchronous I/O?

If I can answer these questions confidently without looking them up, I have built the conceptual foundation needed for Stage 2.

The code comes next. The understanding comes first.
