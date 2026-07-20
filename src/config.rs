use clap::{Parser, ValueEnum};
use serde::Deserialize;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

const DEFAULT_PORT: u16 = 51820;

#[derive(ValueEnum, Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Client,
    Server,
}

#[derive(ValueEnum, Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Info,
    Warn,
    Debug,
    Error,
}

impl LogLevel {
    pub fn to_level_filter(self) -> log::LevelFilter {
        match self {
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Error => log::LevelFilter::Error,
        }
    }
}

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

    #[arg(long)]
    config_path: Option<PathBuf>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub mode: ModeConfig,
    pub tun: TunConfig,
    pub log_level: LogLevel,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ModeConfig {
    Client {
        bind_addr: SocketAddr,
        server_addr: SocketAddr,
    },
    Server {
        bind_addr: SocketAddr,
    },
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    pub name: String,
    pub address: IpAddr,
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
            },
            log_level: LogLevel::Info,
        }
    }
}

impl Config {
    pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }

    pub fn from_args(args: &Args) -> anyhow::Result<Self> {
        let mut config = if let Some(path) = &args.config_path {
            Self::from_file(path)?
        } else {
            Self::default()
        };

        config.log_level = args.log_level.unwrap_or(config.log_level);
        config.tun.name = args.tun.clone().unwrap_or(config.tun.name);
        config.tun.address = args.tun_address.unwrap_or(config.tun.address);

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
}

impl ModeConfig {
    pub fn kind(&self) -> Mode {
        match self {
            Self::Client { .. } => Mode::Client,
            Self::Server { .. } => Mode::Server,
        }
    }

    pub fn bind_addr(&self) -> SocketAddr {
        match self {
            Self::Client { bind_addr, .. } | Self::Server { bind_addr } => *bind_addr,
        }
    }
}

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
            "#,
        )
        .unwrap();

        assert_eq!(config.mode.kind(), Mode::Client);
        assert_eq!(config.mode.bind_addr(), "0.0.0.0:51820".parse().unwrap());
        assert_eq!(config.tun.address, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(config.log_level, LogLevel::Debug);
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
}
