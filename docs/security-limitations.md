# Security limitations

Crabnet is not production-safe at the current milestone.

The fake-crypto handshake remains a software-design test boundary. The executable uses the real
Noise-IK provider and encrypted V2 data frames, but that does not make Crabnet production-safe.

- Legacy V1 UDP data traffic is unauthenticated and unencrypted; committed Noise-IK V2 data traffic is encrypted and replay checked.
- Legacy V1 inner packets are not encrypted; V2 inner packets are encrypted and bind the complete data header.
- Legacy mode has one active peer and no identity verification; Noise-IK server mode uses an explicit public-key allowlist.
- A peer can still be selected by sending the first valid version 1 frame in legacy mode.
- Noise-IK V2 has encrypted data framing, sequence validation, and replay protection, but no key rotation.
- IPv4 masquerading is implemented, but firewall-policy automation is not.
- Startup firewall diagnostics inspect only IPv4-relevant nftables forward
  base-chain declarations. They do not evaluate individual rules, legacy
  iptables, eBPF filters, or other firewall systems, and a successful diagnostic
  does not prove that traffic will be allowed.
- NAT supports one explicitly configured egress interface and one Crabnet-owned
  nftables table per network namespace.
- Full tunnel is limited to isolated environments without a conflicting
  pre-existing default route.
- Full-tunnel DNS handling is not implemented.
- TUN, routing, forwarding, and nftables operations require elevated Linux privileges.
- Handshake payload redaction prevents accidental generic `Debug` output, but it is not a complete
  secret-management or side-channel strategy.

Use the namespace tests for isolated lab validation only. Do not expose the
current server to an untrusted network or use it to protect sensitive traffic.
Authentication, encrypted framing, replay protection, and finite session limits
are implemented; they do not replace the remaining operational and security work.

## What the active Noise-IK path improves

The pure subsystem establishes implementation rules, and the active Noise-IK path applies them to
encrypted traffic:

- untrusted source and attempt metadata is authorized before crypto;
- server candidates are selected by local source ownership, not a message-supplied candidate ID;
- policy and crypto must commit identical authenticated metadata;
- wrong result domains or correlations fail closed;
- expected remote authentication failure is scoped and observable;
- timeout and shutdown erase matching contexts; and
- credentials and opaque payloads are redacted from ordinary debug output.

These properties reduce integration risk, but they cannot compensate for missing lifecycle,
operational, or independent-security-review work.

## Security work still required

Use the implemented Noise-IK profile with carefully managed keys, then add rekeying or a controlled
fresh-session restart, explicit key erasure, multi-peer admission, endpoint-migration policy,
resource/DoS hardening, fuzzing, and independent review. Firewall policy and DNS handling remain
separate operator/runtime responsibilities.
