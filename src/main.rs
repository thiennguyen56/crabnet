mod client;
mod config;
mod crypto;
mod error;
mod protocol;
mod server;
mod session;
mod tun;
mod utils;

use clap::Parser;
use config::{Args, Config};

fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    let config = Config::from_args(&args)?.resolve()?;

    // Initialize logging based on config log level
    env_logger::Builder::new()
        .filter_level(config.log_level.to_level_filter())
        .init();

    log::info!("CrabNet VPN starting...");
    log::debug!("Config: {:?}", config);

    Ok(())
}
