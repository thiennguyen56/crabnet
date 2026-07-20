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
use config::{Args, Config, ModeConfig};

use client::Client;
use server::Server;

fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    let config = Config::from_args(&args)?;

    // Initialize logging based on config log level
    env_logger::Builder::new()
        .filter_level(config.log_level.to_level_filter())
        .init();

    log::info!("CrabNet VPN starting...");
    log::debug!("Config: {:?}", config);

    match &config.mode {
        ModeConfig::Client { .. } => {
            log::info!("client");
            let client = Client::new(&config);
            let response = client.start();
            match response {
                Ok(()) => {
                    log::info!("Receiving result: {}", "Ok");
                }
                Err(e) => {
                    log::error!("Receiving error: {}", e);
                }
            }
        }
        ModeConfig::Server { .. } => {
            log::info!("server");
            let server = Server::new(&config);
            server.start()?;
        }
    }
    Ok(())
}
