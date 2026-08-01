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

Client routes are installed through the TUN interface:

```toml
[routing]
protected_routes = ["10.10.0.0/24"]
```

Server routes describe networks reachable through a server-side gateway:

```toml
[routing]
server_routes = [
  { destination = "10.10.0.0/24", gateway = "172.16.0.2" }
]
enable_forwarding = true
enable_nat = false
```

`enable_nat` is validated but not applied yet. The backend's return route is
outside Crabnet's process and must be configured by the environment.
