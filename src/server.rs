//! Single-peer Crabnet server and bidirectional packet forwarding.
//!
//! The first completely validated Crabnet frame registers the only active UDP
//! peer. Later traffic from other addresses is rejected without replacing it.

use crate::protocol::types::MessageType;
use crate::protocol::v1::{DecodeError, FrameCodec};
use crate::{tun::TunConfig, tun::TunDevice};
use anyhow::Context;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Resources and address required to bind a server endpoint.
pub struct ServerConfig {
  /// Local address on which the server receives UDP datagrams.
  pub bind_addr: SocketAddr,
  /// Server TUN interface configuration.
  pub tun: TunConfig,
}

/// Tracks the first valid UDP peer for this process lifetime.
#[derive(Debug, Default)]
struct SinglePeer {
  address: Option<SocketAddr>,
}

/// Result of observing a UDP source address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerDecision {
  Registered,
  Accepted,
  Rejected,
}

impl SinglePeer {
  /// Registers the first candidate, accepts that peer again, and rejects every
  /// different address.
  fn observe(&mut self, candidate: SocketAddr) -> PeerDecision {
    match self.address {
      None => {
        self.address = Some(candidate);
        PeerDecision::Registered
      }

      Some(current) if current == candidate => PeerDecision::Accepted,

      Some(_) => PeerDecision::Rejected,
    }
  }

  /// Returns the registered peer, if a valid datagram has selected one.
  fn address(&self) -> Option<SocketAddr> {
    self.address
  }
}

/// Saturating counters for forwarded and deliberately dropped server traffic.
#[derive(Debug, Default)]
struct ServerStats {
  udp_to_tun_packets: u64,
  udp_to_tun_bytes: u64,

  tun_to_udp_packets: u64,
  tun_to_udp_bytes: u64,

  dropped_oversized_udp: u64,
  dropped_oversized_tun: u64,
  dropped_empty_udp: u64,
  dropped_invalid_frames: u64,
  dropped_unexpected_peer: u64,
  dropped_before_peer_registration: u64,
}

impl ServerStats {
  /// Emits the final server forwarding and drop counters.
  fn log_summary(&self) {
    log::info!(
      "Server forwarding summary: \
             UDP->TUN={} packets/{} bytes, \
             TUN->UDP={} packets/{} bytes, \
             oversized UDP={}, \
             oversized TUN={}, \
             empty UDP={}, \
             invalid frames={}, \
             unexpected peer={}, \
             no peer={}",
      self.udp_to_tun_packets,
      self.udp_to_tun_bytes,
      self.tun_to_udp_packets,
      self.tun_to_udp_bytes,
      self.dropped_oversized_udp,
      self.dropped_oversized_tun,
      self.dropped_empty_udp,
      self.dropped_invalid_frames,
      self.dropped_unexpected_peer,
      self.dropped_before_peer_registration,
    );
  }
}

/// Action selected after validating an inbound framed UDP datagram.
#[derive(Debug, PartialEq, Eq)]
enum UdpFrameDecision<'a> {
  ForwardToTun {
    payload: &'a [u8],
    newly_registered: bool,
  },
  DropEmpty,
  DropOversized,
  DropUnexpectedPeer,
  DropInvalid(DecodeError),
}

/// Action selected for a packet read from the server TUN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunPacketDecision {
  SendToPeer(SocketAddr),
  DropOversized,
  DropNoPeer,
}

/// Mutable, unit-testable peer policy, MTU policy, and forwarding counters.
struct ServerState {
  inner_mtu: usize,
  peer: SinglePeer,
  stats: ServerStats,
}

impl ServerState {
  /// Creates server forwarding state with no registered peer.
  fn new(inner_mtu: usize) -> Self {
    Self {
      inner_mtu,
      peer: SinglePeer::default(),
      stats: ServerStats::default(),
    }
  }

  /// Validates an inbound frame before registering or accepting its peer.
  fn classify_udp_frame<'a>(
    &mut self,
    codec: &FrameCodec,
    datagram: &'a [u8],
    candidate: SocketAddr,
  ) -> UdpFrameDecision<'a> {
    if matches!(self.peer.address(), Some(active) if active != candidate) {
      self.stats.dropped_unexpected_peer = self.stats.dropped_unexpected_peer.saturating_add(1);
      return UdpFrameDecision::DropUnexpectedPeer;
    }

    if datagram.is_empty() {
      self.stats.dropped_empty_udp = self.stats.dropped_empty_udp.saturating_add(1);
      return UdpFrameDecision::DropEmpty;
    }

    if datagram.len() > codec.max_datagram_len() {
      self.stats.dropped_oversized_udp = self.stats.dropped_oversized_udp.saturating_add(1);
      return UdpFrameDecision::DropOversized;
    }

    let decoded = match codec.decode(datagram) {
      Ok(decoded) => decoded,
      Err(error) => {
        self.stats.dropped_invalid_frames = self.stats.dropped_invalid_frames.saturating_add(1);
        return UdpFrameDecision::DropInvalid(error);
      }
    };

    let payload = match decoded.message_type() {
      MessageType::Data => decoded.payload(),
      unsupported => {
        self.stats.dropped_invalid_frames = self.stats.dropped_invalid_frames.saturating_add(1);
        return UdpFrameDecision::DropInvalid(DecodeError::UnknownMessageType {
          observed: unsupported.wire_value(),
        });
      }
    };

    let newly_registered = match self.peer.observe(candidate) {
      PeerDecision::Registered => true,
      PeerDecision::Accepted => false,
      PeerDecision::Rejected => {
        self.stats.dropped_unexpected_peer = self.stats.dropped_unexpected_peer.saturating_add(1);
        return UdpFrameDecision::DropUnexpectedPeer;
      }
    };

    UdpFrameDecision::ForwardToTun {
      payload,
      newly_registered,
    }
  }

  /// Selects the registered peer for a valid TUN packet, or records why the
  /// packet must be dropped.
  fn classify_tun(&mut self, size: usize) -> TunPacketDecision {
    if size > self.inner_mtu {
      self.stats.dropped_oversized_tun = self.stats.dropped_oversized_tun.saturating_add(1);
      return TunPacketDecision::DropOversized;
    }

    match self.peer.address() {
      Some(peer) => TunPacketDecision::SendToPeer(peer),
      None => {
        self.stats.dropped_before_peer_registration = self
          .stats
          .dropped_before_peer_registration
          .saturating_add(1);
        TunPacketDecision::DropNoPeer
      }
    }
  }

  /// Records a successful UDP-to-TUN transfer.
  fn record_udp_to_tun(&mut self, size: usize) {
    self.stats.udp_to_tun_packets = self.stats.udp_to_tun_packets.saturating_add(1);
    self.stats.udp_to_tun_bytes = self.stats.udp_to_tun_bytes.saturating_add(size as u64);
  }

  /// Records a successful TUN-to-UDP transfer.
  fn record_tun_to_udp(&mut self, size: usize) {
    self.stats.tun_to_udp_packets = self.stats.tun_to_udp_packets.saturating_add(1);
    self.stats.tun_to_udp_bytes = self.stats.tun_to_udp_bytes.saturating_add(size as u64);
  }
}

/// Bound server UDP socket and TUN device.
pub struct Server {
  config: ServerConfig,
  socket: UdpSocket,
  tun: TunDevice,
}

impl Server {
  /// Binds the UDP socket and creates the configured TUN device.
  ///
  /// TUN creation generally requires root or CAP_NET_ADMIN on Linux.
  pub async fn bind(config: ServerConfig) -> anyhow::Result<Self> {
    let socket = UdpSocket::bind(config.bind_addr)
      .await
      .with_context(|| format!("failed to bind server UDP socket to {}", config.bind_addr))?;
    let tun = TunDevice::create(&config.tun)
      .with_context(|| format!("failed to create server TUN {}", config.tun.name))?;
    log::info!(
      "Server addr {},
            tun addr {},
            tun prefix {},
            tun MTU {}",
      config.bind_addr,
      config.tun.address,
      config.tun.prefix_len,
      config.tun.mtu
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
      .with_context(|| format!("failed to configure server framing for TUN MTU {mtu}"))?;
    let mut state = ServerState::new(mtu);

    let result = self.forward_packets(&codec, &mut state).await;

    state.stats.log_summary();

    result
  }

  /// Runs the bidirectional single-peer forwarding loop.
  ///
  /// The TUN buffer is inner MTU plus one byte. The UDP buffer is frame header
  /// plus inner MTU plus one byte so oversized input is detected rather than
  /// accepted after truncation.
  async fn forward_packets(
    &self,
    codec: &FrameCodec,
    state: &mut ServerState,
  ) -> anyhow::Result<()> {
    log::info!("UDP server listening on {}", self.config.bind_addr);
    let mtu = self.tun.mtu();
    let mut tun_buffer = vec![0_u8; mtu + 1];
    let mut encoded_buffer = vec![0_u8; codec.max_datagram_len()];
    let mut udp_buffer = vec![0_u8; codec.receive_buffer_len()];

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
      tokio::select! {
        result = self.socket.recv_from(&mut udp_buffer) => {
          let (size, peer) = result.context("failed to receive UDP packet")?;

          let payload = match state.classify_udp_frame(codec, &udp_buffer[..size], peer) {
            UdpFrameDecision::ForwardToTun {
              payload,
              newly_registered,
            } => {
              if newly_registered {
                log::info!("Registered active peer {peer}");
              }
              payload
            }

            UdpFrameDecision::DropEmpty => {
              log::warn!("Dropping empty UDP packet from {peer}");
              continue;
            }

            UdpFrameDecision::DropOversized => {
              log::warn!(
                "Dropping oversized UDP frame from {peer}: \
                 {size} bytes, maximum frame length is {}",
                codec.max_datagram_len(),
              );
              continue;
            }

            UdpFrameDecision::DropUnexpectedPeer => {
              log::warn!("Ignoring unexpected peer {peer}");
              continue;
            }

            UdpFrameDecision::DropInvalid(error) => {
              log::debug!("Dropping invalid Crabnet frame from {peer}: {error}");
              continue;
            }
          };

          log::debug!(
            "Server UDP -> TUN: received {size}-byte frame \
             containing {}-byte inner packet from {peer}",
            payload.len(),
          );

          self
            .tun
            .write_packet(payload)
            .await
            .with_context(|| {
              format!(
                "failed to inject {}-byte packet from {peer} into server TUN",
                payload.len(),
              )
            })?;

          state.record_udp_to_tun(payload.len());
        }

        result = self.tun.read_packet(&mut tun_buffer) => {
          let size = result.context("failed to read packet from server TUN")?;

          let peer = match state.classify_tun(size) {
            TunPacketDecision::SendToPeer(peer) => peer,
            TunPacketDecision::DropOversized => {
              log::warn!("Dropping oversized TUN packet: {size} bytes, MTU is {mtu}");
              continue;
            }
            TunPacketDecision::DropNoPeer => {
              log::debug!("Dropping {size}-byte TUN packet: no active peer");
              continue;
            }
          };

          let inner_packet = &tun_buffer[..size];

          let encoded_size = codec
            .encode_data(inner_packet, &mut encoded_buffer)
            .with_context(|| {
              format!(
                "failed to encode {size}-byte packet from server TUN {}",
                self.config.tun.name,
              )
            })?;

          let encoded_packet = &encoded_buffer[..encoded_size];

          log::debug!(
            "Server TUN -> UDP: sending {size}-byte inner packet \
             as {encoded_size}-byte frame to {peer}",
          );
          let sent = self
            .socket
            .send_to(encoded_packet, peer)
            .await
            .with_context(|| {
              format!("failed to send {encoded_size}-byte frame to {peer}")
            })?;

          if sent != encoded_size {
            anyhow::bail!(
              "partial UDP send to {peer}: sent {sent} of {encoded_size} framed bytes"
            );
          }
          state.record_tun_to_udp(size);
        }

        result = &mut shutdown => {
          result.context("failed to listen for Ctrl+C")?;
          log::info!("Server shutting down");
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

  fn peer(address: &str) -> SocketAddr {
    address.parse().unwrap()
  }

  fn valid_frame(codec: &FrameCodec, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0_u8; codec.max_datagram_len()];
    let size = codec.encode_data(payload, &mut frame).unwrap();
    frame.truncate(size);
    frame
  }

  #[test]
  fn valid_first_frame_registers_peer_and_returns_inner_payload() {
    let codec = FrameCodec::new(1400).unwrap();
    let frame = valid_frame(&codec, &[0x45, 0x00, 0x00, 0x14]);
    let mut state = ServerState::new(1400);
    let client = peer("192.0.2.1:51820");

    assert_eq!(
      state.classify_udp_frame(&codec, &frame, client),
      UdpFrameDecision::ForwardToTun {
        payload: &[0x45, 0x00, 0x00, 0x14],
        newly_registered: true,
      },
    );
    assert_eq!(state.peer.address(), Some(client));
  }

  #[test]
  fn valid_registered_peer_is_accepted_again() {
    let codec = FrameCodec::new(1400).unwrap();
    let frame = valid_frame(&codec, &[0x45]);
    let mut state = ServerState::new(1400);
    let client = peer("192.0.2.1:51820");

    state.classify_udp_frame(&codec, &frame, client);

    assert_eq!(
      state.classify_udp_frame(&codec, &frame, client),
      UdpFrameDecision::ForwardToTun {
        payload: &[0x45],
        newly_registered: false,
      },
    );
  }

  #[test]
  fn malformed_first_frame_does_not_register_peer() {
    let codec = FrameCodec::new(1400).unwrap();
    let mut state = ServerState::new(1400);
    let candidate = peer("192.0.2.1:51820");

    assert!(matches!(
      state.classify_udp_frame(&codec, b"not a frame", candidate),
      UdpFrameDecision::DropInvalid(_)
    ));
    assert_eq!(state.peer.address(), None);
    assert_eq!(state.stats.dropped_invalid_frames, 1);
  }

  #[test]
  fn different_peer_is_rejected_without_decoding_or_replacement() {
    let codec = FrameCodec::new(1400).unwrap();
    let frame = valid_frame(&codec, &[0x45]);
    let mut state = ServerState::new(1400);
    let original = peer("192.0.2.1:51820");
    let unexpected = peer("192.0.2.3:60000");

    state.classify_udp_frame(&codec, &frame, original);

    assert_eq!(
      state.classify_udp_frame(&codec, b"malformed", unexpected),
      UdpFrameDecision::DropUnexpectedPeer,
    );
    assert_eq!(state.peer.address(), Some(original));
    assert_eq!(state.stats.dropped_unexpected_peer, 1);
    assert_eq!(state.stats.dropped_invalid_frames, 0);
  }

  #[test]
  fn empty_and_oversized_datagrams_do_not_register_peer() {
    let codec = FrameCodec::new(1400).unwrap();
    let mut state = ServerState::new(1400);
    let candidate = peer("192.0.2.3:60000");

    assert_eq!(
      state.classify_udp_frame(&codec, &[], candidate),
      UdpFrameDecision::DropEmpty,
    );
    assert_eq!(state.peer.address(), None);

    let oversized = vec![0_u8; codec.receive_buffer_len()];
    assert_eq!(
      state.classify_udp_frame(&codec, &oversized, candidate),
      UdpFrameDecision::DropOversized,
    );
    assert_eq!(state.peer.address(), None);
    assert_eq!(state.stats.dropped_empty_udp, 1);
    assert_eq!(state.stats.dropped_oversized_udp, 1);
  }

  #[test]
  fn tun_packet_before_registration_is_dropped() {
    let mut state = ServerState::new(1400);

    assert_eq!(state.classify_tun(84), TunPacketDecision::DropNoPeer);
    assert_eq!(state.stats.dropped_before_peer_registration, 1);
  }

  #[test]
  fn tun_packet_is_sent_to_registered_peer() {
    let codec = FrameCodec::new(1400).unwrap();
    let frame = valid_frame(&codec, &[0x45]);
    let mut state = ServerState::new(1400);
    let client = peer("192.0.2.1:51820");
    state.classify_udp_frame(&codec, &frame, client);

    assert_eq!(
      state.classify_tun(84),
      TunPacketDecision::SendToPeer(client),
    );
  }

  #[test]
  fn successful_forwarding_updates_counters() {
    let mut state = ServerState::new(1400);

    state.record_udp_to_tun(84);
    state.record_tun_to_udp(128);

    assert_eq!(state.stats.udp_to_tun_packets, 1);
    assert_eq!(state.stats.udp_to_tun_bytes, 84);
    assert_eq!(state.stats.tun_to_udp_packets, 1);
    assert_eq!(state.stats.tun_to_udp_bytes, 128);
  }
}
