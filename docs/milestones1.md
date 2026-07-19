This is actually where I think we should think like systems engineers.

**Stage 2 is not "build features."**

Stage 2 is **building the packet pipeline**, one piece at a time.

If Stage 1 answered _"Why?"_, then Stage 2 answers _"Can we actually move a packet?"_

---

# Stage 2 Goal

One sentence:

> **Successfully move an IP packet from one TUN interface to another through Crabnet.**

That's it.

No encryption.

No authentication.

No relay.

No mesh.

No NAT traversal.

No fancy routing.

---

# Architecture

```text
Machine A

Application
      │
      ▼
TUN
      │
      ▼
Crabnet
      │
UDP
~~~~~~~~~~~~ Internet ~~~~~~~~~~~~
UDP
      │
Crabnet
      │
TUN
      ▼
Application

Machine B
```

Everything in Stage 2 exists to make this pipeline work.

---

# Milestone 1 — UDP Transport

### Goal

Learn raw UDP communication.

Features:

- UDP server
- UDP client
- Send bytes
- Receive bytes
- Logging

Demo:

```
Hello
↓

UDP

↓

Hello
```

No packet parsing.

No protocol.

---

# Milestone 2 — TUN Device

Goal:

Read packets.

Features:

- Create TUN interface
- Configure IP
- Read packets
- Write packets
- Hex dump packets

Demo:

```
ping

↓

TUN

↓

println(packet)
```

Nothing leaves the machine yet.

---

# Milestone 3 — UDP Tunnel

Goal:

Forward packets.

Features:

- Read from TUN
- Send through UDP
- Receive UDP
- Write into TUN

Demo:

```
ping

↓

Machine A

↓

Machine B
```

Congratulations.

You now have a tunnel.

---

# Milestone 4 — Packet Protocol

Currently UDP contains

```
Raw IP Packet
```

Now introduce

```
+--------------------+
| Crab Header        |
+--------------------+
| IP Packet          |
+--------------------+
```

Features:

- Packet struct
- Header parser
- Serialization
- Deserialization
- Version field
- Packet type

Still

No encryption.

---

# Milestone 5 — Session Manager

Instead of

```
Socket

↓

Packet
```

Now

```
Socket

↓

Session Manager

↓

Packet
```

Features:

- Session ID
- Peer table
- Session lookup
- Session creation
- Session removal

Still

No handshake.

---

# Milestone 6 — State Machine

Now each session has

```
Disconnected

↓

Connected

↓

Closing
```

Features:

- State enum
- State transition validation
- Invalid packet rejection

Still

No authentication.

---

# Milestone 7 — Heartbeats

Features:

- KeepAlive packet
- Ack packet
- Timer
- last_seen
- Timeout detection

Now sessions expire correctly.

---

# Milestone 8 — Basic Routing

Instead of

```
Always send to peer
```

Now

```
Destination IP

↓

Routing Table

↓

Peer
```

Features:

- Route table
- Lookup
- Forwarding

Still no CIDR.

A simple map is enough.

---

# Milestone 9 — Concurrency

Until now

Everything can run on one thread.

Now improve architecture.

Example

```
Thread A

Read TUN

↓

Channel

↓

Worker

↓

Channel

↓

UDP Sender
```

or later

```
Tokio

↓

select!

↓

UDP

↓

TUN

↓

Timers
```

---

# Milestone 10 — Testing

Features:

- Integration tests
- Packet roundtrip
- Session tests
- Parser tests
- Benchmark packet throughput

---

# What we intentionally postpone

These deserve their own later stages:

### Stage 3

Security

- Encryption
- Key exchange
- Authentication

---

### Stage 4

Networking

- NAT traversal
- STUN
- Relay

---

### Stage 5

Distributed networking

- Peer discovery
- Mesh
- Overlay routing

---

### Stage 6

Cloud

- Kubernetes
- Control plane
- Service discovery

---

# The entire roadmap

```
Stage 1

Understand networking

↓

Stage 2

Move packets

↓

Stage 3

Secure packets

↓

Stage 4

Move through the Internet

↓

Stage 5

Multiple peers

↓

Stage 6

Cloud networking

↓

Stage 7

Production quality
```

---

## One thing I'd change

I actually **wouldn't call Stage 2 "Build VPN."**

I'd call it:

> **Stage 2 — Building the Data Plane**

Because that's exactly what you're doing.

Everything here is about the **data plane**:

- reading packets
- moving packets
- forwarding packets
- packet formats
- sessions
- routing

The **control plane**—authentication, peer discovery, configuration, management APIs, and similar concerns—comes later. Thinking in terms of data plane vs. control plane is a useful mental model that you'll encounter in many networking systems, from VPNs to service meshes and cloud networking platforms. memcite
