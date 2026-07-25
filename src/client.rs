use crate::{tun::TunConfig, tun::TunDevice};
use anyhow::Context;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub struct ClientConfig {
	pub bind_addr: SocketAddr,
	pub server_addr: SocketAddr,
	pub tun: TunConfig,
}

#[derive(Debug, Default)]
struct ForwardingStats {
	tun_to_udp_packets: u64,
	tun_to_udp_bytes: u64,

	udp_to_tun_packets: u64,
	udp_to_tun_bytes: u64,

	oversized_tun_packets: u64,
	oversized_udp_packets: u64,
}

impl ForwardingStats {
	fn record_tun_to_udp(&mut self, size: usize) {
		self.tun_to_udp_packets = self.tun_to_udp_packets.saturating_add(1);
		self.tun_to_udp_bytes = self.tun_to_udp_bytes.saturating_add(size as u64);
	}

	fn record_udp_to_tun(&mut self, size: usize) {
		self.udp_to_tun_packets = self.udp_to_tun_packets.saturating_add(1);
		self.udp_to_tun_bytes = self.udp_to_tun_bytes.saturating_add(size as u64);
	}

	fn log_summary(&self) {
		log::info!(
			"Client forwarding summary: \
               TUN->UDP={} packets/{} bytes, \
               UDP->TUN={} packets/{} bytes, \
               oversized TUN={}, oversized UDP={}",
			self.tun_to_udp_packets,
			self.tun_to_udp_bytes,
			self.udp_to_tun_packets,
			self.udp_to_tun_bytes,
			self.oversized_tun_packets,
			self.oversized_udp_packets,
		);
	}
}

pub struct Client {
	config: ClientConfig,
	socket: UdpSocket,
	tun: TunDevice,
}

impl Client {
	pub async fn bind(config: ClientConfig) -> anyhow::Result<Self> {
		let socket = UdpSocket::bind(config.bind_addr)
			.await
			.with_context(|| format!("failed to bind client UDP socket to {}", config.bind_addr))?;
		socket
			.connect(config.server_addr)
			.await
			.with_context(|| format!("failed to connect UDP socket to {}", config.server_addr))?;

		let tun = TunDevice::create(&config.tun)
			.with_context(|| format!("failed to create client TUN {}", config.tun.name))?;
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
		let mut stats = ForwardingStats::default();

		let result = self.forward(&mut stats).await;

		stats.log_summary();
		result
	}

	async fn forward(&self, stats: &mut ForwardingStats) -> anyhow::Result<()> {
		let mtu = self.tun.mtu();

		let mut tun_buffer = vec![0; mtu + 1];
		let mut udp_buffer = vec![0; mtu + 1];

		let shutdown = tokio::signal::ctrl_c();
		tokio::pin!(shutdown);

		loop {
			tokio::select! {
				// Receive a request from tunnel device (comming from OS) then send it to server
				result = self.tun.read_packet(&mut tun_buffer) => {
					let size = result
						.context("failed to read packet from client TUN")?;
					if size > mtu {
						stats.oversized_tun_packets =
							stats.oversized_tun_packets.saturating_add(1);

						log::warn!(
							"Dropping oversized TUN packet: \
							{size} bytes, MTU is {mtu}"
						);

						continue;
					}

					let packet = &tun_buffer[..size];
					log::debug!(
						"Client TUN -> UDP: sending {size} bytes to {}",
						self.config.server_addr,
					);


					let sent = self.socket.send(packet).await
					.with_context(|| {
						format!("failed to send packet to {}", self.config.server_addr)
					})?;

					if sent != size {
						anyhow::bail!(
							"partial UDP send: sent {sent} of {size} bytes"
						);
					}
					stats.record_tun_to_udp(size);
				}

				// Receive a request from a server and then send it back to OS
				result = self.socket.recv(&mut udp_buffer) => {
					let size = result
						.context("failed to receive packet from VPN server")?;

					if size > mtu {
						stats.oversized_udp_packets =
							stats.oversized_udp_packets.saturating_add(1);

						log::warn!(
							"Dropping oversized UDP packet from {}: \
							{size} bytes, TUN MTU is {mtu}",
							self.config.server_addr,
						);

						continue;
					}

					let packet = &udp_buffer[..size];

					log::debug!(
						"Client UDP -> TUN: writing {size} bytes from {}",
						self.config.server_addr,
					);

					self.tun
						.write_packet(packet)
						.await
						.context(
							"failed to inject server packet into client TUN"
						)?;

					stats.record_udp_to_tun(size);
				}

				result = &mut shutdown => {
					result.context("failed to listen for Ctrl+C")?;
					log::info!("Client shutting down");
					break;
				}
			}
		}
		Ok(())
	}
}
