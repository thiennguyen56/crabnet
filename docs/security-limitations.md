# Security limitations

Crabnet is not production-safe at the current milestone.

- UDP traffic is unauthenticated.
- Inner packets are not encrypted.
- The server has one active peer and no identity verification.
- A peer can be selected by sending the first valid datagram.
- There is no replay protection or key rotation.
- IPv4 masquerading is implemented, but firewall-policy automation is not.
- NAT supports one explicitly configured egress interface and one Crabnet-owned
  nftables table per network namespace.
- Full tunnel is limited to isolated environments without a conflicting
  pre-existing default route.
- Full-tunnel DNS handling is not implemented.
- TUN, routing, forwarding, and nftables operations require elevated Linux privileges.

Use the namespace test for isolated lab validation only. Do not expose the
current server to an untrusted network or use it to protect sensitive traffic.
Authentication and encrypted framing must be implemented before expanding the
deployment scope.
