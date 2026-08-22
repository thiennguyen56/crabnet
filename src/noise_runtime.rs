//! Tokio Noise-IK handshake and encrypted data-session transport.
//!
//! A Noise-IK endpoint forwards only after the coordinator commits a matching
//! session and transport state. It never falls back to legacy V1 plaintext.

use std::{
  net::SocketAddr,
  time::{Duration, Instant},
};

use anyhow::Context;
use tokio::net::UdpSocket;

use crate::handshake::types::ClientCoordinatorEvent;
use crate::{
  config::{ModeConfig, SecurityConfig},
  crypto::noise_ik::{
    client::ClientProvider,
    keys::{StaticPrivateKey, StaticPublicKey},
    server::ServerProvider,
  },
  data_plane::{
    crypto::DirectionalTransport, frame::DataFrameCodec, runtime, session::EstablishedDataSession,
  },
  handshake::{
    adapter::{receive_client_frame, receive_server_frame, start_client_frame},
    client::ClientHandshakeCoordinator,
    server::ServerHandshakeCoordinator,
  },
  protocol::v2::V2HandshakeCodec,
  session::{client::ClientHandshake, server::ServerHandshake, SessionPolicy},
  tun::{TunConfig, TunDevice},
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_PENDING: usize = 1;

fn is_remote_frame_rejection(error: &crate::handshake::adapter::AdapterError) -> bool {
  matches!(
    error,
    crate::handshake::adapter::AdapterError::Decode(_)
      | crate::handshake::adapter::AdapterError::Direction(_)
      | crate::handshake::adapter::AdapterError::PayloadLength { .. }
  )
}

pub(crate) enum NoiseIkRuntime {
  Client {
    socket: UdpSocket,
    server_addr: SocketAddr,
    coordinator: Box<ClientHandshakeCoordinator<ClientProvider>>,
    tun: TunConfig,
  },
  Server {
    socket: UdpSocket,
    coordinator: Box<ServerHandshakeCoordinator<ServerProvider>>,
    tun: TunConfig,
  },
}

impl NoiseIkRuntime {
  pub(crate) async fn bind(
    mode: ModeConfig,
    security: SecurityConfig,
    tun: TunConfig,
  ) -> anyhow::Result<Self> {
    let private_path = security
      .private_key_path
      .as_deref()
      .context("Noise-IK private_key_path is required")?;
    let private = StaticPrivateKey::load(private_path)?;
    V2HandshakeCodec::new(112).context("configure Noise-IK V2 codec")?;
    match mode {
      ModeConfig::Client {
        bind_addr,
        server_addr,
      } => {
        let server_key = security
          .server_public_key
          .as_deref()
          .context("Noise-IK client server_public_key is required")?;
        let server_key =
          StaticPublicKey::from_hex(server_key).context("parse Noise-IK server public key")?;
        let policy = ClientHandshake::new(server_addr, HANDSHAKE_TIMEOUT)
          .context("create client handshake policy")?;
        let crypto = ClientProvider::new(
          private.as_bytes().to_vec().into_boxed_slice(),
          server_key.as_bytes().to_vec().into_boxed_slice(),
        );
        let coordinator = ClientHandshakeCoordinator::build(policy, crypto)
          .map_err(|error| anyhow::anyhow!("create client Noise-IK coordinator: {error:?}"))?;
        let socket = UdpSocket::bind(bind_addr)
          .await
          .with_context(|| format!("bind Noise-IK client UDP socket at {bind_addr}"))?;
        Ok(Self::Client {
          socket,
          server_addr,
          coordinator: Box::new(coordinator),
          tun,
        })
      }
      ModeConfig::Server { bind_addr } => {
        let mut allowed = Vec::with_capacity(security.allowed_client_public_keys.len());
        for value in security.allowed_client_public_keys {
          let key = StaticPublicKey::from_hex(&value)
            .context("parse Noise-IK allowed client public key")?;
          allowed.push(key.as_bytes().to_vec().into_boxed_slice());
        }
        let policy = SessionPolicy::new(MAX_PENDING, HANDSHAKE_TIMEOUT, IDLE_TIMEOUT)
          .context("create server session policy")?;
        let crypto = ServerProvider::new(private.as_bytes().to_vec().into_boxed_slice(), allowed);
        let coordinator =
          ServerHandshakeCoordinator::build(ServerHandshake::new(policy), crypto)
            .map_err(|error| anyhow::anyhow!("create server Noise-IK coordinator: {error:?}"))?;
        let socket = UdpSocket::bind(bind_addr)
          .await
          .with_context(|| format!("bind Noise-IK server UDP socket at {bind_addr}"))?;
        Ok(Self::Server {
          socket,
          coordinator: Box::new(coordinator),
          tun,
        })
      }
    }
  }

  pub(crate) async fn run(self) -> anyhow::Result<()> {
    let codec = V2HandshakeCodec::new(112).context("configure Noise-IK V2 codec")?;
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    match self {
      Self::Client {
        socket,
        server_addr,
        mut coordinator,
        tun,
      } => {
        let report = start_client_frame(&mut coordinator, &codec, Instant::now())
          .map_err(|e| anyhow::anyhow!("start Noise-IK client handshake: {e:?}"))?;
        for datagram in report.datagrams {
          socket
            .send_to(&datagram, server_addr)
            .await
            .with_context(|| format!("send Noise-IK ClientHello to {server_addr}"))?;
        }
        let mut buffer = vec![0_u8; codec.max_datagram_len() + 1];
        loop {
          let (length, source) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer))
            .await
            .context("Noise-IK client handshake timed out")??;
          if source != server_addr {
            log::warn!("dropping Noise-IK client handshake datagram from unexpected peer {source}");
            continue;
          }
          let report = match receive_client_frame(
            &mut coordinator,
            &codec,
            server_addr,
            &buffer[..length],
            Instant::now(),
          ) {
            Ok(report) => report,
            Err(error) if is_remote_frame_rejection(&error) => {
              log::warn!("dropping malformed Noise-IK server datagram: {error:?}");
              continue;
            }
            Err(error) => {
              return Err(anyhow::anyhow!("process Noise-IK server frame: {error:?}"));
            }
          };
          for datagram in report.datagrams {
            socket
              .send_to(&datagram, server_addr)
              .await
              .with_context(|| format!("send Noise-IK client handshake frame to {server_addr}"))?;
          }
          if let Some(metadata) = report.events.iter().find_map(|event| match event {
            ClientCoordinatorEvent::SessionEstablished { metadata } => Some(*metadata),
            ClientCoordinatorEvent::Dropped { .. }
            | ClientCoordinatorEvent::HandshakeTimedOut { .. }
            | ClientCoordinatorEvent::Closed { .. }
            | ClientCoordinatorEvent::AlreadyClosed => None,
          }) {
            let (transport, committed_metadata) = coordinator
              .into_crypto()
              .into_established_transport()
              .context("extract committed client Noise-IK transport")?;
            if metadata != committed_metadata {
              return Err(anyhow::anyhow!(
                "client Noise-IK coordinator metadata did not match committed transport"
              ));
            }
            let codec = DataFrameCodec::new(usize::from(tun.mtu))
              .map_err(|error| anyhow::anyhow!("configure encrypted data codec: {error:?}"))?;
            let tun_name = tun.name.clone();
            let tun = TunDevice::create(&tun)
              .with_context(|| format!("create client TUN {tun_name} after Noise-IK handshake"))?;
            let session = EstablishedDataSession::client(
              metadata,
              server_addr,
              DirectionalTransport::new(transport),
            );
            return runtime::run(socket, tun, codec, session).await;
          }
        }
      }
      Self::Server {
        socket,
        mut coordinator,
        tun,
      } => {
        let mut buffer = vec![0_u8; codec.max_datagram_len() + 1];
        loop {
          let received = match coordinator.next_deadline() {
            Some(candidate_deadline) => {
              tokio::select! {
                result = socket.recv_from(&mut buffer) => Some(result.context("receive Noise-IK server datagram")?),
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(candidate_deadline)) => {
                  coordinator.check_timeouts(Instant::now()).map_err(|error| anyhow::anyhow!("expire Noise-IK server candidates: {error:?}"))?;
                  None
                }
              }
            }
            None => Some(
              socket
                .recv_from(&mut buffer)
                .await
                .context("receive Noise-IK server datagram")?,
            ),
          };
          let Some((length, source)) = received else {
            continue;
          };
          let report = match receive_server_frame(
            &mut coordinator,
            &codec,
            source,
            &buffer[..length],
            Instant::now(),
          ) {
            Ok(report) => report,
            Err(error) if is_remote_frame_rejection(&error) => {
              log::warn!("dropping malformed Noise-IK client datagram from {source}: {error:?}");
              continue;
            }
            Err(error) => {
              return Err(anyhow::anyhow!("process Noise-IK client frame: {error:?}"));
            }
          };
          for outbound in report.datagrams {
            socket
              .send_to(&outbound.datagram, outbound.destination)
              .await
              .context("send Noise-IK server handshake frame")?;
          }
          if let Some((peer_endpoint, metadata)) =
            report.events.iter().find_map(|event| match event {
              crate::handshake::types::ServerCoordinatorEvent::SessionEstablished {
                source,
                metadata,
              } => Some((*source, *metadata)),
              crate::handshake::types::ServerCoordinatorEvent::Dropped { .. }
              | crate::handshake::types::ServerCoordinatorEvent::CandidateExpired { .. }
              | crate::handshake::types::ServerCoordinatorEvent::Closed { .. }
              | crate::handshake::types::ServerCoordinatorEvent::AlreadyClosed => None,
            })
          {
            let (transport, committed_metadata) = coordinator
              .into_crypto()
              .into_established_transport()
              .context("extract committed server Noise-IK transport")?;
            if metadata != committed_metadata {
              return Err(anyhow::anyhow!(
                "server Noise-IK coordinator metadata did not match committed transport"
              ));
            }
            let codec = DataFrameCodec::new(usize::from(tun.mtu))
              .map_err(|error| anyhow::anyhow!("configure encrypted data codec: {error:?}"))?;
            let tun_name = tun.name.clone();
            let tun = TunDevice::create(&tun)
              .with_context(|| format!("create server TUN {tun_name} after Noise-IK handshake"))?;
            let session = EstablishedDataSession::server(
              metadata,
              peer_endpoint,
              DirectionalTransport::new(transport),
            );
            return runtime::run(socket, tun, codec, session).await;
          }
        }
      }
    }
  }
}
