use crate::config::TunConfig;

use anyhow::{Context, Ok};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub tun: TunConfig,
}

pub struct Server {
    config: ServerConfig,
    socket: UdpSocket,
}

impl Server {
    pub async fn bind(config: ServerConfig) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind(config.bind_addr).await?;

        log::info!("Server bound to {}", config.bind_addr);

        Ok(Self { config, socket })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        log::info!("UDP server listening on {}", self.config.bind_addr);
        let mut buffer = [0u8; 65535];

        let shutdown = tokio::signal::ctrl_c();
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                receive_result = self.socket.recv_from(&mut buffer) => {
                    let (received, peer) = receive_result
                        .context("failed to receive UDP packet")?;

                    let payload = &buffer[..received];

                    log::info!(
                        "Received {} bytes from {}",
                        received,
                        peer,
                    );

                    log::debug!(
                        "Request payload: {:?}",
                        String::from_utf8_lossy(payload),
                    );

                    // Echo the exact bytes without converting them to UTF-8.
                    let sent = self.socket
                        .send_to(payload, peer)
                        .await
                        .with_context(|| {
                            format!("failed to send UDP response to {peer}")
                        })?;

                    log::info!(
                        "Sent {} bytes to {}",
                        sent,
                        peer,
                    );
                }

                shutdown_result = &mut shutdown => {
                    shutdown_result
                        .context("failed to listen for Ctrl+C")?;

                    log::info!("Shutdown signal received");
                    break;
                }
            }
        }
        Ok(())
    }
}
