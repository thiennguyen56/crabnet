# Configuration reference

Configuration is TOML. The sample files are in `config/client/config.toml` and
`config/server/config.toml`.

The executable supports two explicit security modes. `legacy` runs the existing unauthenticated V1
data path. `noise_ik` loads real static key material, performs the V2 Noise-IK handshake, and then
forwards only authenticated encrypted V2 data frames.

The namespace-lab sample files intentionally select `legacy` because `scripts/test-local-tunnel.sh`
tests the V1 TUN/UDP forwarding, routing, and NAT path. A dedicated Noise-IK namespace scenario
remains to be added.

## Loading and CLI overrides

`--config-path PATH` loads a complete TOML file. Without it, Crabnet starts from built-in client
defaults. The following CLI values override either source:

| CLI option | Effective field |
| --- | --- |
| `--mode client|server` | `[mode].type` |
| `--local-addr`, `--local-port` | local `[mode].bind_addr` components |
| `--remote-addr`, `--remote-port` | client `[mode].server_addr` components |
| `--tun` | `tun.name` |
| `--tun-address` | `tun.address` |
| `--tun-prefix-len` | `tun.prefix_len` |
| `--tun-mtu` | `tun.mtu` |
| `--log-level` | `log_level` |

Routing settings currently come from TOML rather than individual CLI flags. Validation runs after
all overrides are merged.

## Common fields

```toml
log_level = "debug" # info, warn, debug, error
```

## Mode

Client:

```toml
[mode]
type = "client"
bind_addr = "192.0.2.1:51820"
server_addr = "192.0.2.2:51821"
```

Server:

```toml
[mode]
type = "server"
bind_addr = "192.0.2.2:51821"
```

## TUN

```toml
[tun]
name = "crabnet0"
address = "10.0.0.2"
prefix_len = 24
mtu = 1400
```

`prefix_len` must fit the address family. MTU must be non-zero; IPv6 requires
an MTU of at least 1280.

## Routing

Split-tunnel client routes are installed through the TUN interface:

```toml
[routing]
protected_routes = ["10.10.0.0/24"]
```

Full tunnel is a mutually exclusive client mode:

```toml
[routing]
full_tunnel = true
```

Before changing the default route, Crabnet resolves the operating system's
current route to the VPN server. It then installs a host route for that server
through the resolved gateway and interface, followed by a default route through
TUN. The host route is more specific than the default route, so Crabnet's UDP
transport stays on the underlay instead of recursively entering its own tunnel.

`protected_routes` must be empty in this mode because the TUN default route
already covers every destination in the TUN address family. The current route
backend refuses to replace a pre-existing default route, so use full tunnel only
in an isolated routing domain without a conflicting default route.

Server routes describe networks reachable through a server-side gateway:

```toml
[routing]
server_routes = [
  { destination = "10.10.0.0/24", gateway = "172.16.0.2" }
]
enable_forwarding = true
enable_nat = true
nat_egress_interface = "cn-srv-back"
```

Each `server_routes` entry requires `destination` and may specify `gateway`, `interface`, or both:

```toml
server_routes = [
  { destination = "10.10.0.0/24", gateway = "172.16.0.2" },
  { destination = "10.20.0.0/24", interface = "eth1" }
]
```

`enable_nat` is server-only and currently supports IPv4. It requires
`enable_forwarding = true`, a non-default TUN prefix, and an explicit
`nat_egress_interface` different from the TUN name. The egress interface
keeps masquerading scoped to the intended underlay instead of guessing on
multi-homed servers.

Crabnet creates a dedicated `ip crabnet_nat` nftables table. The rule matches
the TUN input interface, canonical TUN source network, and configured egress
interface. Startup fails if that table already exists because a new process
cannot prove ownership. During graceful shutdown, Crabnet removes the table
only if it still matches the state installed at startup.

NAT does not configure DNS or host firewall policy. A restrictive firewall
may still require administrator-managed forwarding rules.

## Validation and ownership summary

- Client-only: `protected_routes` and `full_tunnel`.
- Server-only: `server_routes`, `enable_forwarding`, `enable_nat`, and
  `nat_egress_interface`.
- `protected_routes` and `full_tunnel` are mutually exclusive.
- NAT is IPv4-only, requires forwarding, and requires an egress interface different from TUN.
- A pre-existing identical route or forwarding value is not claimed or removed.
- A conflicting route, pre-existing `ip crabnet_nat` table, or externally changed owned object is
  rejected rather than overwritten or deleted.

Configuration validation happens before privileged TUN, route, forwarding, or nftables effects.
The sample files target the four-namespace lab; interface names and addresses must be changed for a
different namespace or container topology.

## Security

```toml
[security]
mode = "legacy" # or "noise_ik"
private_key_path = "/etc/crabnet/noise-ik-private.key"
server_public_key = "<64 lowercase hex characters>" # client only
allowed_client_public_keys = ["<64 lowercase hex characters>"] # server only
```

Noise-IK requires a 32-byte private key encoded as exactly 64 lowercase hexadecimal characters.
The file must not be readable by group or other users. Clients require one pinned server public key;
servers require at least one unique allowed client public key. Noise-IK configuration is validated
before any TUN, route, NAT, or forwarding state is created.

Noise-IK currently performs only the authenticated handshake over UDP and exits before packet
forwarding. It must not be used as a claim that V1 data frames are authenticated or encrypted.

### Generating local Noise-IK keys

The repository includes a local-lab generator that uses the same Snow Noise profile as the provider:

```bash
cargo run --bin generate_noise_keys
```

It generates one 32-byte X25519 private key and matching 32-byte public key for each role. Keys are
written as exactly 64 lowercase hexadecimal characters. Private files are set to mode `0600` and
are ignored by Git; public files are temporary output used to update the two sample configs. Never
commit a private key or reuse these lab keys in production. Regenerate both pairs together, then
replace the client pin and server allowlist with the new public keys.
