use crate::{tun::TunConfig, tun::TunDevice};
use anyhow::Context;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub struct ServerConfig {
  pub bind_addr: SocketAddr,
  pub tun: TunConfig,
}

#[derive(Debug, Default)]
struct SinglePeer {
  address: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerDecision {
  Registered,
  Accepted,
  Rejected,
}

impl SinglePeer {
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

  fn address(&self) -> Option<SocketAddr> {
    self.address
  }
}

#[derive(Debug, Default)]
struct ServerStats {
  udp_to_tun_packets: u64,
  udp_to_tun_bytes: u64,

  tun_to_udp_packets: u64,
  tun_to_udp_bytes: u64,

  dropped_oversized_udp: u64,
  dropped_oversized_tun: u64,
  dropped_empty_udp: u64,
  dropped_unexpected_peer: u64,
  dropped_before_peer_registration: u64,
}

impl ServerStats {
  fn log_summary(&self) {
    log::info!(
      "Server forwarding summary: \
             UDP->TUN={} packets/{} bytes, \
             TUN->UDP={} packets/{} bytes, \
             oversized UDP={}, \
             oversized TUN={}, \
             empty UDP={}, \
             unexpected peer={}, \
             no peer={}",
      self.udp_to_tun_packets,
      self.udp_to_tun_bytes,
      self.tun_to_udp_packets,
      self.tun_to_udp_bytes,
      self.dropped_oversized_udp,
      self.dropped_oversized_tun,
      self.dropped_empty_udp,
      self.dropped_unexpected_peer,
      self.dropped_before_peer_registration,
    );
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpPacketDecision {
  ForwardToTun { newly_registered: bool },
  DropEmpty,
  DropOversized,
  DropUnexpectedPeer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunPacketDecision {
  SendToPeer(SocketAddr),
  DropOversized,
  DropNoPeer,
}

struct ServerState {
  mtu: usize,
  peer: SinglePeer,
  stats: ServerStats,
}

impl ServerState {
  fn new(mtu: usize) -> Self {
    Self {
      mtu,
      peer: SinglePeer::default(),
      stats: ServerStats::default(),
    }
  }

  fn classify_udp(&mut self, size: usize, peer: SocketAddr) -> UdpPacketDecision {
    if size == 0 {
      self.stats.dropped_empty_udp = self.stats.dropped_empty_udp.saturating_add(1);
      return UdpPacketDecision::DropEmpty;
    }

    if size > self.mtu {
      self.stats.dropped_oversized_udp = self.stats.dropped_oversized_udp.saturating_add(1);
      return UdpPacketDecision::DropOversized;
    }

    match self.peer.observe(peer) {
      PeerDecision::Registered => UdpPacketDecision::ForwardToTun {
        newly_registered: true,
      },
      PeerDecision::Accepted => UdpPacketDecision::ForwardToTun {
        newly_registered: false,
      },
      PeerDecision::Rejected => {
        self.stats.dropped_unexpected_peer = self.stats.dropped_unexpected_peer.saturating_add(1);
        UdpPacketDecision::DropUnexpectedPeer
      }
    }
  }

  fn classify_tun(&mut self, size: usize) -> TunPacketDecision {
    if size > self.mtu {
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

  fn record_udp_to_tun(&mut self, size: usize) {
    self.stats.udp_to_tun_packets = self.stats.udp_to_tun_packets.saturating_add(1);
    self.stats.udp_to_tun_bytes = self.stats.udp_to_tun_bytes.saturating_add(size as u64);
  }

  fn record_tun_to_udp(&mut self, size: usize) {
    self.stats.tun_to_udp_packets = self.stats.tun_to_udp_packets.saturating_add(1);
    self.stats.tun_to_udp_bytes = self.stats.tun_to_udp_bytes.saturating_add(size as u64);
  }
}

pub struct Server {
  config: ServerConfig,
  socket: UdpSocket,
  tun: TunDevice,
}

impl Server {
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

  pub async fn run(&self) -> anyhow::Result<()> {
    let mut state = ServerState::new(self.tun.mtu());

    let result = self.forward_packets(&mut state).await;

    state.stats.log_summary();

    result
  }

  async fn forward_packets(&self, state: &mut ServerState) -> anyhow::Result<()> {
    log::info!("UDP server listening on {}", self.config.bind_addr);
    let mtu = self.tun.mtu();

    let mut tun_buffer = vec![0_u8; mtu + 1];
    let mut udp_buffer = vec![0_u8; mtu + 1];

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
      tokio::select! {
        result = self.socket.recv_from(&mut udp_buffer) => {
          let (size, peer) = result.context("failed to receive UDP packet")?;

          match state.classify_udp(size, peer) {
            UdpPacketDecision::ForwardToTun {
              newly_registered,
            } => {
              if newly_registered {
                log::info!("Registered active peer {peer}");
              }
            }

            UdpPacketDecision::DropEmpty => {
              log::warn!("Dropping empty UDP packet from {peer}");
              continue;
            }

            UdpPacketDecision::DropOversized => {
              log::warn!(
                "Dropping oversized UDP packet from {peer}: \
                 {size} bytes, TUN MTU is {mtu}"
              );
              continue;
            }

            UdpPacketDecision::DropUnexpectedPeer => {
              log::warn!("Ignoring unexpected peer {peer}");
              continue;
            }
          }

          log::debug!("Server UDP -> TUN: writing {size} bytes from {peer}");
          self.tun
            .write_packet(&udp_buffer[..size])
            .await
            .context("failed to write UDP packet to server TUN")?;

          state.record_udp_to_tun(size);
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

          log::debug!("Server TUN -> UDP: sending {size} bytes to {peer}");
          let sent = self
            .socket
            .send_to(&tun_buffer[..size], peer)
            .await
            .with_context(|| format!("failed to send UDP packet to {peer}"))?;

          if sent != size {
            anyhow::bail!("partial UDP send: sent {sent} of {size} bytes");
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

  #[test]
  fn first_peer_is_registered() {
    let mut state = ServerState::new(1400);
    let client = peer("192.0.2.1:51820");

    assert_eq!(
      state.classify_udp(84, client),
      UdpPacketDecision::ForwardToTun {
        newly_registered: true,
      },
    );
    assert_eq!(state.peer.address(), Some(client));
  }

  #[test]
  fn registered_peer_is_accepted_again() {
    let mut state = ServerState::new(1400);
    let client = peer("192.0.2.1:51820");

    state.classify_udp(84, client);

    assert_eq!(
      state.classify_udp(84, client),
      UdpPacketDecision::ForwardToTun {
        newly_registered: false,
      },
    );
  }

  #[test]
  fn different_peer_is_rejected_without_replacement() {
    let mut state = ServerState::new(1400);
    let original = peer("192.0.2.1:51820");
    let unexpected = peer("192.0.2.3:60000");

    state.classify_udp(84, original);

    assert_eq!(
      state.classify_udp(84, unexpected),
      UdpPacketDecision::DropUnexpectedPeer,
    );
    assert_eq!(state.peer.address(), Some(original));
    assert_eq!(state.stats.dropped_unexpected_peer, 1);
  }

  #[test]
  fn empty_datagram_does_not_register_peer() {
    let mut state = ServerState::new(1400);
    let candidate = peer("192.0.2.3:60000");

    assert_eq!(
      state.classify_udp(0, candidate),
      UdpPacketDecision::DropEmpty,
    );
    assert_eq!(state.peer.address(), None);
    assert_eq!(state.stats.dropped_empty_udp, 1);
  }

  #[test]
  fn oversized_datagram_does_not_register_peer() {
    let mut state = ServerState::new(1400);
    let candidate = peer("192.0.2.3:60000");

    assert_eq!(
      state.classify_udp(1401, candidate),
      UdpPacketDecision::DropOversized,
    );
    assert_eq!(state.peer.address(), None);
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
    let mut state = ServerState::new(1400);
    let client = peer("192.0.2.1:51820");
    state.classify_udp(84, client);

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
