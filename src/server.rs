use crate::{tun::TunConfig, tun::TunDevice};
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
    tun: TunDevice,
}

impl Server {
    pub async fn bind(config: ServerConfig) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind(config.bind_addr).await?;
        let tun = TunDevice::create(&config.tun)?;
        log::info!("Server bound to {}", config.bind_addr);

        Ok(Self {
            config,
            socket,
            tun,
        })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        log::info!("UDP server listening on {}", self.config.bind_addr);
        let mtu = self.tun.mtu();

        let mut tun_buffer = vec![0_u8; mtu];
        let mut udp_buffer = vec![0_u8; mtu + 1];
        let mut active_peer = None;

        let shutdown = tokio::signal::ctrl_c();
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                result = self.socket.recv_from(&mut udp_buffer) => {
                    let (size, peer) = result?;

                    if size > mtu {
                        log::warn!(
                            "Dropping oversized UDP packet from {peer}: \
                             {size} bytes, TUN MTU is {mtu}"
                        );
                        continue;
                    }

                    match active_peer {
                        None => {
                            log::info!("Registered active peer {peer}");
                            active_peer = Some(peer);
                        }
                        Some(expected) if expected != peer => {
                            log::warn!("Ignoring unexpected peer {peer}");
                            continue;
                        }
                        _ => {}
                    }

                    log::debug!(
                        "Server UDP -> TUN: writing {size} bytes from {peer}"
                    );

                    self.tun.send(&udp_buffer[..size]).await?;
                }

                result = self.tun.recv(&mut tun_buffer) => {
                    let size = result?;

                    if size > mtu {
                        log::warn!(
                            "Dropping oversized TUN packet: {size} bytes, MTU is {mtu}"
                        );
                        continue;
                    }

                    if let Some(peer) = active_peer {
                        log::debug!(
                            "Server TUN -> UDP: sending {size} bytes to {peer}"
                        );

                        let sent = self.socket
                            .send_to(&tun_buffer[..size], peer)
                            .await?;

                        if sent != size {
                            anyhow::bail!(
                                "partial UDP send: sent {sent} of {size} bytes"
                            );
                        }
                    } else {
                        log::debug!("Dropping TUN packet: no active peer");
                    }
                }

                result = &mut shutdown => {
                    result?;
                    log::info!("Server shutting down");
                    break;
                }
            }
        }

        Ok(())
    }
}
