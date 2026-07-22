use std::time::Duration;

use super::config::{Config, ModeConfig};
use crate::{tun::TunConfig, tun::TunDevice};
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
    tun: TunDevice,
}

impl Client {
    pub async fn bind(config: ClientConfig) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind(config.bind_addr).await?;
        socket.connect(config.server_addr).await?;

        let tun = TunDevice::create(&config.tun)?;
        log::info!(
            "Client bound to {} and connected to {}",
            config.bind_addr,
            config.server_addr,
        );

        Ok(Self {
            config,
            socket,
            tun,
        })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let mtu = self.tun.mtu();

        let mut tun_buffer = vec![0_u8; mtu];
        let mut udp_buffer = vec![0_u8; mtu + 1];

        let shutdown = tokio::signal::ctrl_c();
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                result = self.tun.recv(&mut tun_buffer) => {
                    let size = result?;

                     if size > mtu {
                      log::warn!(
                          "Dropping oversized TUN packet: {size} bytes, MTU is {mtu}"
                      );
                      continue;
                  }

                    let sent = self.socket.send(&tun_buffer[..size]).await?;

                    if sent != size {
                      anyhow::bail!(
                          "partial UDP send: sent {sent} of {size} bytes"
                      );
                  }

                }

                result = self.socket.recv(&mut udp_buffer) => {
                    let size = result?;

                    if size > mtu {
                      log::warn!(
                          "Dropping oversized UDP packet from {}: \
                           {size} bytes, TUN MTU is {mtu}",
                          self.config.server_addr,
                      );
                      continue;
                  }

                    self.tun.send(&udp_buffer[..size]).await?;
                }

                result = &mut shutdown => {
                    result?;
                    log::info!("Client shutting down");
                    break;
                }
            }
        }
        Ok(())
    }
}
