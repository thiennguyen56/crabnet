//! Command-line and TOML configuration.
//!
//! CLI values override file values. Cross-field validation happens after both
//! sources are merged and before privileged resources are created.

use crate::{routing::RoutingConfig, tun::TunConfig};
use anyhow::{bail, ensure};
use clap::{Parser, ValueEnum};
use serde::Deserialize;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

const DEFAULT_PORT: u16 = 51820;

/// Selects which Crabnet endpoint role to run.
#[derive(ValueEnum, Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
  /// Run a connected UDP client with one configured server.
  Client,
  /// Run a UDP server that learns one active peer.
  Server,
}

/// Logging verbosity accepted by the CLI and configuration file.
#[derive(ValueEnum, Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
  /// Emit informational, warning, and error messages.
  Info,
  /// Emit warning and error messages.
  Warn,
  /// Emit debug and higher-severity messages.
  Debug,
  /// Emit only error messages.
  Error,
}

impl LogLevel {
  /// Converts this value into the filter used by env_logger.
  pub fn to_level_filter(self) -> log::LevelFilter {
    match self {
      LogLevel::Info => log::LevelFilter::Info,
      LogLevel::Warn => log::LevelFilter::Warn,
      LogLevel::Debug => log::LevelFilter::Debug,
      LogLevel::Error => log::LevelFilter::Error,
    }
  }
}

/// Raw command-line arguments accepted by Crabnet.
///
/// Optional values are merged over either the selected configuration file or
/// Config::default.
#[derive(Parser, Debug)]
pub struct Args {
  #[arg(long, help = "Local address [default: 0.0.0.0]")]
  local_addr: Option<IpAddr>,

  #[arg(long, help = "Local port [default: 51820]")]
  local_port: Option<u16>,

  #[arg(long, help = "Remote address [default: 127.0.0.1]")]
  remote_addr: Option<IpAddr>,

  #[arg(long, help = "Remote port [default: 51820]")]
  remote_port: Option<u16>,

  #[arg(value_enum, long, help = "VPN mode [default: client]")]
  mode: Option<Mode>,

  #[arg(value_enum, long, help = "Log level [default: info]")]
  log_level: Option<LogLevel>,

  #[arg(long, help = "TUN device name [default: crabnet0]")]
  tun: Option<String>,

  #[arg(long, help = "TUN interface address [default: 10.0.0.1]")]
  tun_address: Option<IpAddr>,

  #[arg(long, help = "TUN interface prefix len [default: 24")]
  tun_prefix_len: Option<u8>,

  #[arg(long, help = "TUN interface mtu [default: 1400]")]
  tun_mtu: Option<u16>,

  #[arg(long)]
  config_path: Option<PathBuf>,
}

/// Complete runtime configuration after file parsing and CLI overrides.
#[derive(Deserialize, Debug, Clone)]
pub struct Config {
  /// Selects the client or server endpoint and its UDP addresses.
  pub mode: ModeConfig,
  /// Configures the TUN interface shared by the selected endpoint.
  pub tun: TunConfig,
  /// Configures client routes or server-side forwarding behavior.
  #[serde(default)]
  pub routing: RoutingConfig,
  /// Sets the process-wide logging filter.
  pub log_level: LogLevel,
}

/// Mode-specific UDP endpoint configuration.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ModeConfig {
  /// Client UDP binding and fixed server endpoint.
  Client {
    /// Local address on which the client UDP socket is bound.
    bind_addr: SocketAddr,
    /// Remote Crabnet server to which the client socket connects.
    server_addr: SocketAddr,
  },
  /// Server UDP binding configuration.
  Server {
    /// Local address on which the server accepts UDP datagrams.
    bind_addr: SocketAddr,
  },
}

impl Default for Config {
  fn default() -> Self {
    Self {
      mode: ModeConfig::Client {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEFAULT_PORT),
        server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_PORT),
      },
      tun: TunConfig {
        name: "crabnet0".to_string(),
        address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        prefix_len: 24,
        mtu: 1400,
      },
      routing: RoutingConfig::default(),
      log_level: LogLevel::Info,
    }
  }
}

impl Config {
  /// Reads and deserializes a complete TOML configuration file.
  ///
  /// Validation is deferred until CLI overrides have been applied by
  /// Self::from_args.
  pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
    let content = fs::read_to_string(path)?;
    Ok(toml::from_str(&content)?)
  }

  /// Builds the effective configuration by merging CLI arguments over a file
  /// or over Self::default when no file is selected.
  pub fn from_args(args: &Args) -> anyhow::Result<Self> {
    let mut config = if let Some(path) = &args.config_path {
      Self::from_file(path)?
    } else {
      Self::default()
    };

    config.log_level = args.log_level.unwrap_or(config.log_level);
    config.tun.name = args.tun.clone().unwrap_or(config.tun.name);
    config.tun.address = args.tun_address.unwrap_or(config.tun.address);
    config.tun.prefix_len = args.tun_prefix_len.unwrap_or(config.tun.prefix_len);
    config.tun.mtu = args.tun_mtu.unwrap_or(config.tun.mtu);

    let default = Self::default();
    let selected_mode = args.mode.unwrap_or_else(|| config.mode.kind());
    config.mode = match selected_mode {
      Mode::Client => {
        let (bind_addr, server_addr) = match config.mode {
          ModeConfig::Client {
            bind_addr,
            server_addr,
          } => (bind_addr, server_addr),
          ModeConfig::Server { bind_addr } => {
            let ModeConfig::Client { server_addr, .. } = default.mode else {
              unreachable!()
            };
            (bind_addr, server_addr)
          }
        };

        ModeConfig::Client {
          bind_addr: socket_addr(bind_addr, args.local_addr, args.local_port),
          server_addr: socket_addr(server_addr, args.remote_addr, args.remote_port),
        }
      }
      Mode::Server => {
        let bind_addr = config.mode.bind_addr();
        ModeConfig::Server {
          bind_addr: socket_addr(bind_addr, args.local_addr, args.local_port),
        }
      }
    };

    Ok(config)
  }

  /// Validates TUN settings, mode-specific options, and routing invariants.
  ///
  /// This rejects unimplemented NAT, cross-mode options, duplicate/default
  /// protected routes, and split routes that contain the VPN server and would
  /// recursively capture the transport.
  pub fn validate(&self) -> anyhow::Result<()> {
    self.tun.validate()?;
    ensure!(
      !self.routing.enable_nat,
      "routing.enable_nat is not implemented yet"
    );

    for (index, route) in self.routing.protected_routes.iter().enumerate() {
      ensure!(
        route.prefix_len() != 0,
        "routing.protected_routes[{index}] is a default route; \
         use routing.full_tunnel instead"
      );
      ensure!(
        route.addr().is_ipv4() == self.tun.address.is_ipv4(),
        "routing.protected_routes[{index}] address family must match the TUN address"
      );

      if self.routing.protected_routes[..index].contains(route) {
        bail!("routing.protected_routes contains duplicate route {route}");
      }
    }

    match &self.mode {
      ModeConfig::Client { server_addr, .. } => {
        ensure!(
          !self.routing.enable_forwarding && !self.routing.enable_nat,
          "routing.enable_forwarding and routing.enable_nat are server-only options"
        );

        ensure!(
          self.routing.server_routes.is_empty(),
          "routing.server_routes is server-only"
        );

        if self.routing.full_tunnel {
          ensure!(
            self.routing.protected_routes.is_empty(),
            "routing.protected_routes must be empty when \
             routing.full_tunnel is enabled"
          );
        }

        if let Some(route) = self
          .routing
          .protected_routes
          .iter()
          .find(|route| route.contains(&server_addr.ip()))
        {
          bail!(
            "VPN server address {server_addr} is inside protected route {route}; this would recursively route tunnel traffic"
          );
        }
      }
      ModeConfig::Server { .. } => {
        ensure!(
          self.routing.protected_routes.is_empty(),
          "routing.protected_routes is a client-only option"
        );

        ensure!(
          !self.routing.full_tunnel,
          "routing.full_tunnel is a client-only option"
        );
      }
    }

    Ok(())
  }
}

impl ModeConfig {
  /// Returns the mode discriminator without exposing variant fields.
  pub fn kind(&self) -> Mode {
    match self {
      Self::Client { .. } => Mode::Client,
      Self::Server { .. } => Mode::Server,
    }
  }

  /// Returns the local UDP bind address for either endpoint mode.
  pub fn bind_addr(&self) -> SocketAddr {
    match self {
      Self::Client { bind_addr, .. } | Self::Server { bind_addr } => *bind_addr,
    }
  }
}

/// Merges optional address and port overrides with an existing socket address.
fn socket_addr(current: SocketAddr, ip: Option<IpAddr>, port: Option<u16>) -> SocketAddr {
  SocketAddr::new(
    ip.unwrap_or_else(|| current.ip()),
    port.unwrap_or(current.port()),
  )
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_client_config() {
    let config: Config = toml::from_str(
      r#"
                log_level = "debug"

                [mode]
                type = "client"
                bind_addr = "0.0.0.0:51820"
                server_addr = "127.0.0.1:51821"

                [tun]
                name = "crabnet0"
                address = "10.0.0.2"
                prefix_len = 14
                mtu = 1400

                [routing]
                protected_routes = ["172.16.0.0/24"]
            "#,
    )
    .unwrap();

    assert_eq!(config.mode.kind(), Mode::Client);
    assert_eq!(config.mode.bind_addr(), "0.0.0.0:51820".parse().unwrap());
    assert_eq!(config.tun.address, "10.0.0.2".parse::<IpAddr>().unwrap());
    assert_eq!(config.log_level, LogLevel::Debug);
    assert_eq!(config.tun.prefix_len, 14);
    assert_eq!(config.tun.mtu, 1400);
    assert_eq!(
      config.routing.protected_routes,
      vec!["172.16.0.0/24".parse().unwrap()]
    );
    assert!(!config.routing.enable_forwarding);
    assert!(!config.routing.enable_nat);
  }

  #[test]
  fn cli_overrides_default_config() {
    let args = Args::try_parse_from([
      "crabnet",
      "--mode",
      "server",
      "--local-addr",
      "127.0.0.1",
      "--local-port",
      "9001",
      "--tun-address",
      "10.0.0.1",
    ])
    .unwrap();

    let config = Config::from_args(&args).unwrap();
    assert_eq!(
      config.mode,
      ModeConfig::Server {
        bind_addr: "127.0.0.1:9001".parse().unwrap()
      }
    );
  }

  #[test]
  fn routing_defaults_preserve_existing_config_files() {
    let config: Config = toml::from_str(
      r#"
        log_level = "info"

        [mode]
        type = "client"
        bind_addr = "0.0.0.0:51820"
        server_addr = "192.0.2.2:51821"

        [tun]
        name = "crabnet0"
        address = "10.0.0.2"
        prefix_len = 24
        mtu = 1400
      "#,
    )
    .unwrap();

    assert_eq!(config.routing, RoutingConfig::default());
    config.validate().unwrap();
  }

  #[test]
  fn rejects_route_containing_vpn_server() {
    let mut config = Config::default();
    config.routing.protected_routes = vec!["127.0.0.0/8".parse().unwrap()];

    let error = config.validate().unwrap_err();
    assert!(error
      .to_string()
      .contains("recursively route tunnel traffic"));
  }

  #[test]
  fn rejects_default_inside_protected_routes() {
    let mut config = Config::default();
    config.routing.protected_routes = vec!["0.0.0.0/0".parse().unwrap()];

    let error = config.validate().unwrap_err();
    assert!(error
      .to_string()
      .contains("use routing.full_tunnel instead"));
  }

  #[test]
  fn rejects_nat_while_unimplemented() {
    let mut config = Config {
      mode: ModeConfig::Server {
        bind_addr: "0.0.0.0:51821".parse().unwrap(),
      },
      ..Config::default()
    };
    config.routing.enable_nat = true;

    let error = config.validate().unwrap_err();
    assert!(error
      .to_string()
      .contains("routing.enable_nat is not implemented yet"));
  }

  #[test]
  fn rejects_server_protected_routes() {
    let mut config = Config {
      mode: ModeConfig::Server {
        bind_addr: "0.0.0.0:51821".parse().unwrap(),
      },
      ..Config::default()
    };
    config.routing.protected_routes = vec!["172.16.0.0/24".parse().unwrap()];

    let error = config.validate().unwrap_err();
    assert!(error.to_string().contains("client-only"));
  }

  #[test]
  fn accepts_client_full_tunnel() {
    let mut config = Config::default();
    config.routing.full_tunnel = true;

    config.validate().unwrap();
  }

  #[test]
  fn rejects_full_tunnel_with_protected_routes() {
    let mut config = Config::default();
    config.routing.full_tunnel = true;
    config.routing.protected_routes = vec!["10.10.0.0/24".parse().unwrap()];

    let error = config.validate().unwrap_err();
    assert!(error.to_string().contains("protected_routes must be empty"));
  }

  #[test]
  fn rejects_server_full_tunnel() {
    let mut config = Config {
      mode: ModeConfig::Server {
        bind_addr: "0.0.0.0:51821".parse().unwrap(),
      },
      ..Config::default()
    };
    config.routing.full_tunnel = true;

    let error = config.validate().unwrap_err();
    assert!(error.to_string().contains("full_tunnel is a client-only"));
  }
}
