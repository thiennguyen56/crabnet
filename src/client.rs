use std::time::Duration;

use super::config::{Config, ModeConfig};
use crate::config::TunConfig;
use anyhow::Context;
use std::net::SocketAddr;
use tokio::{net::UdpSocket, time::timeout};

pub struct ClientConfig {
    pub bind_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub tun: TunConfig,
}

pub struct Client {
    config: ClientConfig,
    socket: UdpSocket,
}

impl Client {
    pub async fn bind(config: ClientConfig) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind(config.bind_addr).await?;
        socket.connect(config.server_addr).await?;

        log::info!(
            "Client bound to {} and connected to {}",
            config.bind_addr,
            config.server_addr,
        );

        Ok(Self { config, socket })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let payload = b"Hello, server!";
        let sent =
            self.socket.send(payload).await.with_context(|| {
                format!("failed to send UDP packet to {}", self.config.server_addr)
            })?;

        log::info!("Send {} bytes to {}", sent, self.config.server_addr,);

        let mut buffer = vec![0_u8; 65_535];

        let received = timeout(Duration::from_secs(3), self.socket.recv(&mut buffer))
            .await
            .context("Time out waiting for server response")?
            .context("failed to receive UDP response")?;

        let response = &buffer[..received];

        log::info!(
            "Received {} bytes from {}",
            received,
            self.config.server_addr,
        );

        log::debug!("Response payload: {:?}", String::from_utf8_lossy(response),);

        Ok(())
    }
}
