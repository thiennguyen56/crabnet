//! Connected Crabnet client and bidirectional packet forwarding.
//!
//! Packets read from TUN are encoded into versioned Crabnet frames before UDP
//! transmission. Received frames are validated and decoded before their raw
//! inner payload is written to TUN.

use crate::protocol::types::MessageType;
use crate::protocol::v1::FrameCodec;
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
  invalid_udp_frames: u64,
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
               oversized TUN={}, oversized UDP={}, invalid frames={}",
      self.tun_to_udp_packets,
      self.tun_to_udp_bytes,
      self.udp_to_tun_packets,
      self.udp_to_tun_bytes,
      self.oversized_tun_packets,
      self.oversized_udp_packets,
      self.invalid_udp_frames,
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
  inner_mtu: usize,
  maximum_frame_len: usize,
  stats: ForwardingStats,
}

impl ClientState {
  /// Creates client forwarding state for inner and framed packet limits.
  fn new(inner_mtu: usize, maximum_frame_len: usize) -> Self {
    Self {
      inner_mtu,
      maximum_frame_len,
      stats: ForwardingStats::default(),
    }
  }

  /// Classifies a TUN packet and counts an oversized drop.
  fn classify_tun(&mut self, size: usize) -> PacketDecision {
    if size > self.inner_mtu {
      self.stats.oversized_tun_packets = self.stats.oversized_tun_packets.saturating_add(1);
      PacketDecision::DropOversized
    } else {
      PacketDecision::Forward
    }
  }

  /// Classifies a UDP datagram and counts an oversized drop.
  fn classify_udp_frame(&mut self, size: usize) -> PacketDecision {
    if size > self.maximum_frame_len {
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

  /// Records one malformed or unsupported frame received from the server.
  fn record_invalid_udp_frame(&mut self) {
    self.stats.invalid_udp_frames = self.stats.invalid_udp_frames.saturating_add(1);
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
    let mtu = self.tun.mtu();
    let codec = FrameCodec::new(mtu)
      .with_context(|| format!("failed to configure client framing for TUN MTU {mtu}"))?;
    let mut state = ClientState::new(mtu, codec.max_datagram_len());

    let result = self.forward(&codec, &mut state).await;

    state.stats.log_summary();
    result
  }

  /// Runs the bidirectional framed forwarding loop with reusable buffers.
  ///
  /// The TUN buffer is inner MTU plus one byte. The UDP buffer is frame header
  /// plus inner MTU plus one byte so oversized input is detected rather than
  /// accepted after truncation.
  async fn forward(&self, codec: &FrameCodec, state: &mut ClientState) -> anyhow::Result<()> {
    let mtu = self.tun.mtu();

    let mut tun_buffer = vec![0; mtu + 1];
    let mut encoded_buffer = vec![0_u8; codec.max_datagram_len()];
    let mut udp_buffer = vec![0; codec.receive_buffer_len()];

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

          let inner_packet = &tun_buffer[..size];
          let encoded_size = codec
            .encode_data(inner_packet, &mut encoded_buffer)
            .with_context(|| {
              format!(
                "failed to encode {size}-byte packet from client TUN {}",
                self.config.tun.name,
              )
            })?;
          let encoded_packet = &encoded_buffer[..encoded_size];
          log::debug!(
            "Client TUN -> UDP: sending {}-byte inner packet \
             as {}-byte frame to {}",
            size,
            encoded_size,
            self.config.server_addr,
          );
          let sent = self.socket.send(encoded_packet).await
          .with_context(|| {
            format!("failed to send {encoded_size}-byte frame to {}", self.config.server_addr)
          })?;

          if sent != encoded_size {
            anyhow::bail!(
                  "partial UDP send to {}: sent {sent} of {encoded_size} framed bytes",
                  self.config.server_addr,
            );
          }
          state.record_tun_to_udp(size);
        }

          // Receive a packet from the server, then inject it into the local OS through TUN.
        result = self.socket.recv(&mut udp_buffer) => {
          let size = result
            .context("failed to receive packet from VPN server")?;

          if state.classify_udp_frame(size) == PacketDecision::DropOversized {
            log::warn!(
              "Dropping oversized UDP frame from {}: \
               {size} bytes, maximum frame length is {}",
              self.config.server_addr,
              codec.max_datagram_len(),
            );
            continue;
          }

          let decoded = match codec.decode(&udp_buffer[..size]) {
            Ok(decoded) => decoded,
            Err(error) => {
              state.record_invalid_udp_frame();
              log::debug!(
                "Dropping invalid Crabnet frame from {}: {error}",
                self.config.server_addr,
              );
              continue;
            }
          };

          let payload = match decoded.message_type() {
            MessageType::Data => decoded.payload(),
          };

          log::debug!(
            "Client UDP -> TUN: received {size}-byte frame containing \
             {}-byte inner packet from {}",
            payload.len(),
            self.config.server_addr,
          );

          self.tun
            .write_packet(payload)
            .await
            .context(
              "failed to inject server packet into client TUN"
            )?;

          state.record_udp_to_tun(payload.len());
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
    let mut state = ClientState::new(1400, 1410);

    assert_eq!(state.classify_tun(1400), PacketDecision::Forward);
    assert_eq!(state.classify_udp_frame(1410), PacketDecision::Forward);
    assert_eq!(state.stats.oversized_tun_packets, 0);
    assert_eq!(state.stats.oversized_udp_packets, 0);
  }

  #[test]
  fn packet_larger_than_mtu_is_dropped_and_counted() {
    let mut state = ClientState::new(1400, 1410);

    assert_eq!(state.classify_tun(1401), PacketDecision::DropOversized);
    assert_eq!(
      state.classify_udp_frame(1411),
      PacketDecision::DropOversized
    );
    assert_eq!(state.stats.oversized_tun_packets, 1);
    assert_eq!(state.stats.oversized_udp_packets, 1);
  }

  #[test]
  fn binary_packet_is_forwarded_unchanged() {
    let packet = [0x00, 0xff, 0x80, 0xc3, 0x28, 0x7f];
    let mut state = ClientState::new(1400, 1410);

    assert_eq!(state.classify_tun(packet.len()), PacketDecision::Forward);

    let forwarded = &packet[..packet.len()];
    assert_eq!(forwarded, packet);
    assert!(std::str::from_utf8(forwarded).is_err());
  }

  #[test]
  fn successful_forwarding_updates_counters() {
    let mut state = ClientState::new(1400, 1410);

    state.record_tun_to_udp(84);
    state.record_udp_to_tun(128);

    assert_eq!(state.stats.tun_to_udp_packets, 1);
    assert_eq!(state.stats.tun_to_udp_bytes, 84);
    assert_eq!(state.stats.udp_to_tun_packets, 1);
    assert_eq!(state.stats.udp_to_tun_bytes, 128);
  }

  #[test]
  fn invalid_frames_are_counted_without_affecting_forwarded_traffic() {
    let mut state = ClientState::new(1400, 1410);

    state.record_invalid_udp_frame();

    assert_eq!(state.stats.invalid_udp_frames, 1);
    assert_eq!(state.stats.udp_to_tun_packets, 0);
    assert_eq!(state.stats.udp_to_tun_bytes, 0);
  }
}
