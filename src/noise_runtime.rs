//! Tokio transport for the Noise-IK handshake.
//!
//! This module intentionally stops after authentication.  The encrypted data
//! frame format, replay window, and rekey policy are a separate milestone; a
//! Noise-IK endpoint must not fall back to the legacy plaintext forwarding
//! loop while those pieces are absent.

use std::{
  net::SocketAddr,
  time::{Duration, Instant},
};

use anyhow::{bail, Context};
use tokio::net::UdpSocket;

use crate::{
  config::{ModeConfig, SecurityConfig},
  crypto::noise_ik::{
    client::ClientProvider,
    keys::{StaticPrivateKey, StaticPublicKey},
    server::ServerProvider,
  },
  handshake::{
    adapter::{receive_client_frame, receive_server_frame, start_client_frame},
    client::ClientHandshakeCoordinator,
    server::ServerHandshakeCoordinator,
  },
  protocol::v2::V2HandshakeCodec,
  session::{client::ClientHandshake, server::ServerHandshake, SessionPolicy},
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
  },
  Server {
    socket: UdpSocket,
    coordinator: Box<ServerHandshakeCoordinator<ServerProvider>>,
  },
}

impl NoiseIkRuntime {
  pub(crate) async fn bind(mode: ModeConfig, security: SecurityConfig) -> anyhow::Result<Self> {
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
        socket
          .connect(server_addr)
          .await
          .with_context(|| format!("connect Noise-IK client UDP socket to {server_addr}"))?;
        Ok(Self::Client {
          socket,
          server_addr,
          coordinator: Box::new(coordinator),
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
        })
      }
    }
  }

  pub(crate) async fn run(mut self) -> anyhow::Result<()> {
    let codec = V2HandshakeCodec::new(112).context("configure Noise-IK V2 codec")?;
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    match &mut self {
      Self::Client {
        socket,
        server_addr,
        coordinator,
      } => {
        let report = start_client_frame(coordinator, &codec, Instant::now())
          .map_err(|e| anyhow::anyhow!("start Noise-IK client handshake: {e:?}"))?;
        for datagram in report.datagrams {
          socket
            .send(&datagram)
            .await
            .context("send Noise-IK ClientHello")?;
        }
        let mut buffer = vec![0_u8; codec.max_datagram_len() + 1];
        loop {
          let length = tokio::time::timeout_at(deadline, socket.recv(&mut buffer))
            .await
            .context("Noise-IK client handshake timed out")??;
          let report = match receive_client_frame(
            coordinator,
            &codec,
            *server_addr,
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
              .send(&datagram)
              .await
              .context("send Noise-IK client handshake frame")?;
          }
          if report.events.iter().any(|event| {
            matches!(
              event,
              crate::handshake::types::ClientCoordinatorEvent::SessionEstablished { .. }
            )
          }) {
            break;
          }
        }
      }
      Self::Server {
        socket,
        coordinator,
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
            coordinator,
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
          if report.events.iter().any(|event| {
            matches!(
              event,
              crate::handshake::types::ServerCoordinatorEvent::SessionEstablished { .. }
            )
          }) {
            break;
          }
        }
      }
    }
    bail!("Noise-IK handshake established; encrypted data-plane framing is not implemented yet")
  }
}
