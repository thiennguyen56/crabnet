use clap::{Parser, ValueEnum};
use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(ValueEnum, Clone, Debug, Deserialize, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Client,
    Server,
}

#[derive(ValueEnum, Clone, Debug, Deserialize, Copy)]
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

#[derive(Clone, Debug)]
enum KeySource {
    Direct(String),
    File(PathBuf),
}

impl FromStr for KeySource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("file:") {
            let path = PathBuf::from(rest);
            let _key = fs::read_to_string(&path).map_err(|e| e.to_string())?;
            Ok(KeySource::File(path))
        } else {
            Ok(KeySource::Direct(s.to_string()))
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

    #[arg(value_parser, long)]
    key: Option<KeySource>,

    #[arg(long, help = "TUN device name [default: crabnet0]")]
    tun: Option<String>,

    #[arg(long)]
    config_path: Option<PathBuf>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    pub mode: Option<Mode>,
    pub local_addr: Option<IpAddr>,
    pub local_port: Option<u16>,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub key: Option<String>,
    pub tun: Option<String>,
    pub log_level: Option<LogLevel>,
}

impl Config {
    pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn from_args(args: &Args) -> anyhow::Result<Self> {
        let file_config = if let Some(path) = &args.config_path {
            Some(Config::from_file(path)?)
        } else {
            None
        };

        Ok(Config {
            mode: args.mode.or(file_config.as_ref().and_then(|c| c.mode)),
            local_addr: args
                .local_addr
                .or(file_config.as_ref().and_then(|c| c.local_addr)),
            local_port: args
                .local_port
                .or(file_config.as_ref().and_then(|c| c.local_port)),
            remote_addr: args
                .remote_addr
                .or(file_config.as_ref().and_then(|c| c.remote_addr)),
            remote_port: args
                .remote_port
                .or(file_config.as_ref().and_then(|c| c.remote_port)),
            key: args
                .key
                .as_ref()
                .map(|k| match k {
                    KeySource::Direct(s) => s.clone(),
                    KeySource::File(p) => p.to_string_lossy().to_string(),
                })
                .or(file_config.as_ref().and_then(|c| c.key.clone())),
            tun: args
                .tun
                .clone()
                .or(file_config.as_ref().and_then(|c| c.tun.clone())),
            log_level: args
                .log_level
                .or(file_config.as_ref().and_then(|c| c.log_level)),
        })
    }

    pub fn resolve(self) -> anyhow::Result<ResolvedConfig> {
        Ok(ResolvedConfig {
            mode: self.mode.unwrap_or(Mode::Client),
            local_addr: self
                .local_addr
                .unwrap_or(IpAddr::from_str("0.0.0.0").unwrap()),
            local_port: self.local_port.unwrap_or(51820),
            remote_addr: self
                .remote_addr
                .unwrap_or(IpAddr::from_str("127.0.0.1").unwrap()),
            remote_port: self.remote_port.unwrap_or(51820),
            key: self.key,
            tun: self.tun.unwrap_or("crabnet0".to_string()),
            log_level: self.log_level.unwrap_or(LogLevel::Info),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub mode: Mode,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub key: Option<String>, // key can still be optional
    pub tun: String,
    pub log_level: LogLevel,
}
