Below is the current end-to-end flow using a ping or application request from the client machine to the
server’s virtual IP.

Client machine Server machine

Application
│
│ IP packet to 10.0.0.1
▼
Client kernel
│ route through TUN
▼
Client TUN
│ recv()
▼
Crabnet client
│ UDP send
├──────────────────────────────────────► Crabnet server
│ recv_from()
▼
Server TUN
│ send()
▼
Server kernel
│
▼
Server application

Return:

Server application
│
Server kernel
│ route through TUN
Server TUN
│ recv()
Crabnet server
│ UDP send_to
├──────────────────────────────────────► Crabnet client
│
Client TUN
│
Client kernel
│
Client application

## 1. Startup

On the server machine:

main
└─ Application::bind(server config)
└─ Server::bind
├─ Bind UDP socket to 0.0.0.0:51821
└─ Create server TUN
├─ name: crabnet-server
├─ address: 10.0.0.1
├─ prefix: /24
└─ MTU: 1400

On the client machine:

main
└─ Application::bind(client config)
└─ Client::bind
├─ Bind UDP socket
├─ Connect UDP socket to server public address
└─ Create client TUN
├─ name: crabnet-client
├─ address: 10.0.0.2
├─ prefix: /24
└─ MTU: 1400

Both processes then enter their tokio::select! forwarding loops.

## 2. Client creates an inner packet

Suppose the client runs:

ping 10.0.0.1

The client kernel creates an IP packet:

Inner IP packet
┌───────────────────────────┐
│ Source: 10.0.0.2 │
│ Destination: 10.0.0.1 │
│ Protocol: ICMP │
│ Payload: echo request │
└───────────────────────────┘

Because 10.0.0.1 belongs to the TUN subnet, the client kernel routes it through crabnet-client.

ping
↓
client kernel routing
↓
crabnet-client TUN
↓
TunDevice::recv()

## 3. Client sends the packet over UDP

The client forwarding loop receives the complete inner IP packet:

let size = self.tun.recv(&mut tun_buffer).await?;
self.socket.send(&tun_buffer[..size]).await?;

The operating system wraps it in an outer UDP/IP packet:

Outer packet
┌──────────────────────────────────────┐
│ Outer IP header │
│ source: client physical address │
│ destination: server physical IP │
├──────────────────────────────────────┤
│ UDP header │
│ source port: client bind port │
│ destination port: 51821 │
├──────────────────────────────────────┤
│ Original inner IP packet │
│ 10.0.0.2 → 10.0.0.1 │
└──────────────────────────────────────┘

The inner packet is currently sent without a Crabnet protocol header, encryption, or authentication.

## 4. Server receives and injects it into TUN

The server receives the UDP datagram:

let (size, peer) = socket.recv_from(&mut udp_buffer).await?;

For the first accepted datagram:

active_peer = Some(peer);

It writes the UDP payload into the server TUN:

self.tun.send(&udp_buffer[..size]).await?;

Writing to TUN means injecting the packet into the server kernel:

Crabnet server
↓ TunDevice::send()
server TUN
↓
server kernel network stack

Because the inner destination is 10.0.0.1, the server kernel treats the packet as locally addressed and
processes the ICMP echo request.

## 5. Server generates the response

The server kernel creates:

Inner response packet
┌───────────────────────────┐
│ Source: 10.0.0.1 │
│ Destination: 10.0.0.2 │
│ Protocol: ICMP │
│ Payload: echo reply │
└───────────────────────────┘

The route to 10.0.0.2 points through the server TUN, so the packet becomes available to Crabnet:

let size = self.tun.recv(&mut tun_buffer).await?;

The server sends it to the remembered client UDP endpoint:

self.socket
.send_to(&tun_buffer[..size], active_peer)
.await?;

## 6. Client receives the response

The client’s connected UDP socket receives the response:

let size = self.socket.recv(&mut udp_buffer).await?;

Crabnet injects the inner response into the client kernel:

self.tun.send(&udp_buffer[..size]).await?;

The client kernel sees:

source: 10.0.0.1
destination: 10.0.0.2

It delivers the ICMP response to ping.

Crabnet client
↓ TunDevice::send()
client TUN
↓
client kernel
↓
ping receives reply

## Accessing a network behind the server

For a destination behind the server, such as 192.168.1.10, the flow becomes:

Client application
→ client TUN
→ Crabnet client
→ UDP network
→ Crabnet server
→ server TUN
→ server kernel forwarding
→ private network
→ 192.168.1.10

That requires additional server configuration:

- IP forwarding enabled.
- A route from the client to 192.168.1.0/24 through its TUN.
- A return route from the private network to the Crabnet subnet, or NAT on the server.
- Firewall rules permitting forwarding.

The current code implements the packet transport portion, but route management, forwarding/NAT, authentication,
encryption, and multi-client routing are still future layers.
