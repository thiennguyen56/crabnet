# Configuration reference

Configuration is TOML. The sample files are in `config/client/config.toml` and
`config/server/config.toml`.

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
enable_nat = false
```

`enable_nat = true` is rejected because NAT is not implemented. The backend's
return route is outside Crabnet's process and must be configured by the
environment.
