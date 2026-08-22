//! Crabnet executable entry point.
//!
//! The binary combines CLI/file configuration, validates it before creating
//! privileged resources, initializes logging, and runs the selected endpoint.

#![warn(missing_docs)]

mod application;
mod client;
mod config;
#[allow(
  dead_code,
  reason = "the provider traits remain reusable outside the Tokio runtime"
)]
mod crypto;
mod data_plane;
mod firewall;
#[allow(
  dead_code,
  clippy::result_large_err,
  reason = "handshake keeps rich typed errors across the runtime adapter"
)]
mod handshake;
mod nat;
mod noise_runtime;
mod protocol;
mod routing;
mod server;
#[allow(
  dead_code,
  reason = "the pure session policy is intentionally not runtime-integrated yet"
)]
mod session;
mod tun;

use clap::Parser;
use config::{Args, Config};

use crate::application::Application;

/// Parses configuration, initializes logging, and runs Crabnet until shutdown.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let args = Args::parse();
  let config = Config::from_args(&args)?;
  config.validate()?;

  env_logger::Builder::new()
    .filter_level(config.log_level.to_level_filter())
    .init();

  log::info!("CrabNet starting");
  log::debug!("Config: {:?}", config);

  let application = Application::bind(config).await?;
  application.run().await
}
