# Security limitations

Crabnet is not production-safe at the current milestone.

- UDP traffic is unauthenticated.
- Inner packets are not encrypted.
- The server has one active peer and no identity verification.
- A peer can be selected by sending the first valid datagram.
- There is no replay protection or key rotation.
- NAT and firewall automation are not implemented.
- Full-tunnel DNS and route protection are not implemented.
- TUN and routing operations require elevated Linux privileges.

Use the namespace test for isolated lab validation only. Do not expose the
current server to an untrusted network or use it to protect sensitive traffic.
Authentication and encrypted framing must be implemented before expanding the
deployment scope.
