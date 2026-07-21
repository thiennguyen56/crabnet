mod application;
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

use crate::application::Application;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = Config::from_args(&args)?;

    env_logger::Builder::new()
        .filter_level(config.log_level.to_level_filter())
        .init();

    log::info!("CrabNet starting");
    log::debug!("Config: {:?}", config);

    let application = Application::bind(config).await?;
    application.run().await
}
