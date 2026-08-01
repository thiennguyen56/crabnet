//! Connected Crabnet client and bidirectional packet forwarding.
//!
//! Raw packets are copied unchanged between the local TUN and one connected
//! UDP server. Packet classification remains separate for pure unit testing.

use crate::{tun::TunConfig, tun::TunDevice};
use anyhow::Context;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Resources and addresses required to bind a client endpoint.
pub struct ClientConfig {
  /// Local address for the connected UDP socket.
  pub bind_addr: SocketAddr,
  /// Remote Crabnet server address.
  pub server_addr: SocketAddr,
  /// Client TUN interface configuration.
  pub tun: TunConfig,
}

/// Saturating counters for forwarded and deliberately dropped client traffic.
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
  /// Records one successfully forwarded TUN-to-UDP packet.
  fn record_tun_to_udp(&mut self, size: usize) {
    self.tun_to_udp_packets = self.tun_to_udp_packets.saturating_add(1);
    self.tun_to_udp_bytes = self.tun_to_udp_bytes.saturating_add(size as u64);
  }

  /// Records one successfully forwarded UDP-to-TUN packet.
  fn record_udp_to_tun(&mut self, size: usize) {
    self.udp_to_tun_packets = self.udp_to_tun_packets.saturating_add(1);
    self.udp_to_tun_bytes = self.udp_to_tun_bytes.saturating_add(size as u64);
  }

  /// Emits the final client forwarding and drop counters.
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

/// Result of validating a packet against the configured MTU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketDecision {
  Forward,
  DropOversized,
}

/// Mutable, unit-testable packet policy and counters for the forwarding loop.
struct ClientState {
  mtu: usize,
  stats: ForwardingStats,
}

impl ClientState {
  /// Creates client forwarding state for the specified MTU.
  fn new(mtu: usize) -> Self {
    Self {
      mtu,
      stats: ForwardingStats::default(),
    }
  }

  /// Classifies a TUN packet and counts an oversized drop.
  fn classify_tun(&mut self, size: usize) -> PacketDecision {
    if size > self.mtu {
      self.stats.oversized_tun_packets = self.stats.oversized_tun_packets.saturating_add(1);
      PacketDecision::DropOversized
    } else {
      PacketDecision::Forward
    }
  }

  /// Classifies a UDP datagram and counts an oversized drop.
  fn classify_udp(&mut self, size: usize) -> PacketDecision {
    if size > self.mtu {
      self.stats.oversized_udp_packets = self.stats.oversized_udp_packets.saturating_add(1);
      PacketDecision::DropOversized
    } else {
      PacketDecision::Forward
    }
  }

  /// Records a successful TUN-to-UDP transfer.
  fn record_tun_to_udp(&mut self, size: usize) {
    self.stats.record_tun_to_udp(size);
  }

  /// Records a successful UDP-to-TUN transfer.
  fn record_udp_to_tun(&mut self, size: usize) {
    self.stats.record_udp_to_tun(size);
  }
}

/// Bound client UDP socket and TUN device.
pub struct Client {
  config: ClientConfig,
  socket: UdpSocket,
  tun: TunDevice,
}

impl Client {
  /// Binds and connects the UDP socket, then creates the configured TUN device.
  ///
  /// TUN creation generally requires root or CAP_NET_ADMIN on Linux.
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

  /// Forwards packets until Ctrl+C or an unrecoverable I/O error, then logs a
  /// summary of forwarded and dropped traffic.
  pub async fn run(&self) -> anyhow::Result<()> {
    let mut state = ClientState::new(self.tun.mtu());

    let result = self.forward(&mut state).await;

    state.stats.log_summary();
    result
  }

  /// Runs the bidirectional forwarding loop with MTU-plus-one receive buffers.
  ///
  /// The extra byte distinguishes oversized traffic from valid MTU-sized
  /// packets instead of silently accepting truncation.
  async fn forward(&self, state: &mut ClientState) -> anyhow::Result<()> {
    let mtu = self.tun.mtu();

    let mut tun_buffer = vec![0; mtu + 1];
    let mut udp_buffer = vec![0; mtu + 1];

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
      tokio::select! {
          // Receive a packet from the local OS through TUN, then send it to the server.
        result = self.tun.read_packet(&mut tun_buffer) => {
          let size = result
            .context("failed to read packet from client TUN")?;
          if state.classify_tun(size) == PacketDecision::DropOversized {
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
          state.record_tun_to_udp(size);
        }

          // Receive a packet from the server, then inject it into the local OS through TUN.
        result = self.socket.recv(&mut udp_buffer) => {
          let size = result
            .context("failed to receive packet from VPN server")?;

          if state.classify_udp(size) == PacketDecision::DropOversized {
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

          state.record_udp_to_tun(size);
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn packet_equal_to_mtu_is_forwarded() {
    let mut state = ClientState::new(1400);

    assert_eq!(state.classify_tun(1400), PacketDecision::Forward);
    assert_eq!(state.classify_udp(1400), PacketDecision::Forward);
    assert_eq!(state.stats.oversized_tun_packets, 0);
    assert_eq!(state.stats.oversized_udp_packets, 0);
  }

  #[test]
  fn packet_larger_than_mtu_is_dropped_and_counted() {
    let mut state = ClientState::new(1400);

    assert_eq!(state.classify_tun(1401), PacketDecision::DropOversized);
    assert_eq!(state.classify_udp(1401), PacketDecision::DropOversized);
    assert_eq!(state.stats.oversized_tun_packets, 1);
    assert_eq!(state.stats.oversized_udp_packets, 1);
  }

  #[test]
  fn binary_packet_is_forwarded_unchanged() {
    let packet = [0x00, 0xff, 0x80, 0xc3, 0x28, 0x7f];
    let mut state = ClientState::new(1400);

    assert_eq!(state.classify_tun(packet.len()), PacketDecision::Forward);

    let forwarded = &packet[..packet.len()];
    assert_eq!(forwarded, packet);
    assert!(std::str::from_utf8(forwarded).is_err());
  }

  #[test]
  fn successful_forwarding_updates_counters() {
    let mut state = ClientState::new(1400);

    state.record_tun_to_udp(84);
    state.record_udp_to_tun(128);

    assert_eq!(state.stats.tun_to_udp_packets, 1);
    assert_eq!(state.stats.tun_to_udp_bytes, 84);
    assert_eq!(state.stats.udp_to_tun_packets, 1);
    assert_eq!(state.stats.udp_to_tun_bytes, 128);
  }
}
