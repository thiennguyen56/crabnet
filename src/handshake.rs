pub(crate) mod adapter;
pub(crate) mod client;
pub(crate) mod server;
pub(crate) mod types;

#[cfg(test)]
mod tests {
  use std::{
    net::SocketAddr,
    num::NonZeroU64,
    time::{Duration, Instant},
  };

  use crate::{
    crypto::{
      client::ClientHandshakeCrypto,
      fake::{
        FakeClientCrypto, FakeClientCryptoConfig, FakeCredential, FakeServerCrypto,
        FakeServerCryptoConfig,
      },
      server::ServerHandshakeCrypto,
      types::CryptoOutcome,
    },
    handshake::{
      client::ClientHandshakeCoordinator,
      server::ServerHandshakeCoordinator,
      types::{
        ClientCoordinatorEvent, ClientHandshakeMessage, ServerCoordinatorEvent,
        ServerHandshakeMessage,
      },
    },
    session::{
      client::ClientHandshake,
      server::ServerHandshake,
      types::{ClientAttemptId, PeerIdentity},
      CandidateId, SessionPolicy,
    },
  };

  const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
  const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
  const CLIENT_IDENTITY: PeerIdentity = PeerIdentity::from_u64(11);
  const SERVER_IDENTITY: PeerIdentity = PeerIdentity::from_u64(22);

  fn endpoint(port: u16) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 1], port))
  }

  fn credential() -> FakeCredential {
    FakeCredential::new(NonZeroU64::new(7).unwrap())
  }

  fn client_crypto() -> FakeClientCrypto {
    FakeClientCrypto::new(
      FakeClientCryptoConfig::new(credential(), CLIENT_IDENTITY, SERVER_IDENTITY).unwrap(),
    )
  }

  fn server_crypto() -> FakeServerCrypto {
    FakeServerCrypto::new(
      FakeServerCryptoConfig::new(
        credential(),
        SERVER_IDENTITY,
        CLIENT_IDENTITY,
        NonZeroU64::new(100).unwrap(),
      )
      .unwrap(),
    )
  }

  fn coordinators() -> (
    ClientHandshakeCoordinator<FakeClientCrypto>,
    ServerHandshakeCoordinator<FakeServerCrypto>,
  ) {
    let client = ClientHandshakeCoordinator::build(
      ClientHandshake::new(endpoint(4000), HANDSHAKE_TIMEOUT).unwrap(),
      client_crypto(),
    )
    .unwrap();
    let server = ServerHandshakeCoordinator::build(
      ServerHandshake::new(SessionPolicy::new(2, HANDSHAKE_TIMEOUT, IDLE_TIMEOUT).unwrap()),
      server_crypto(),
    )
    .unwrap();
    (client, server)
  }

  #[test]
  fn complete_fake_handshake_establishes_matching_session_and_opposite_peers() {
    let (mut client, mut server) = coordinators();
    let now = Instant::now();

    let mut client_start = client.start(now).unwrap().outbound.into_iter();
    let client_hello = match client_start.next().unwrap() {
      ClientHandshakeMessage::ClientHello(message) => message,
      ClientHandshakeMessage::ClientFinish(_) => panic!("expected ClientHello"),
    };
    assert!(client_start.next().is_none());

    let mut server_hello_report = server
      .receive_client_hello(endpoint(5000), client_hello, now)
      .unwrap()
      .outbound
      .into_iter();
    let server_hello = match server_hello_report.next().unwrap().message {
      ServerHandshakeMessage::ServerHello(message) => message,
      ServerHandshakeMessage::ServerFinish(_) => panic!("expected ServerHello"),
    };
    assert!(server_hello_report.next().is_none());

    let mut client_finish_report = client
      .receive_server_hello(endpoint(4000), server_hello, now + Duration::from_secs(1))
      .unwrap()
      .outbound
      .into_iter();
    let client_finish = match client_finish_report.next().unwrap() {
      ClientHandshakeMessage::ClientFinish(message) => message,
      ClientHandshakeMessage::ClientHello(_) => panic!("expected ClientFinish"),
    };
    assert!(client_finish_report.next().is_none());

    let server_report = server
      .receive_client_finish(endpoint(5000), client_finish, now + Duration::from_secs(2))
      .unwrap();
    let server_metadata = match server_report.events.as_slice() {
      [ServerCoordinatorEvent::SessionEstablished { source, metadata }]
        if *source == endpoint(5000) =>
      {
        *metadata
      }
      events => panic!("unexpected server events: {events:?}"),
    };
    let mut server_finish_report = server_report.outbound.into_iter();
    let server_finish = match server_finish_report.next().unwrap().message {
      ServerHandshakeMessage::ServerFinish(message) => message,
      ServerHandshakeMessage::ServerHello(_) => panic!("expected ServerFinish"),
    };
    assert!(server_finish_report.next().is_none());

    let client_report = client
      .receive_server_finish(endpoint(4000), server_finish, now + Duration::from_secs(3))
      .unwrap();
    let client_metadata = match client_report.events.as_slice() {
      [ClientCoordinatorEvent::SessionEstablished { metadata }] => *metadata,
      events => panic!("unexpected client events: {events:?}"),
    };

    assert_eq!(client_metadata.session_id, server_metadata.session_id);
    assert_eq!(client_metadata.peer_identity, SERVER_IDENTITY);
    assert_eq!(server_metadata.peer_identity, CLIENT_IDENTITY);
  }

  #[test]
  fn construction_rejects_preused_crypto_providers() {
    let mut used_client = client_crypto();
    used_client.start_attempt(ClientAttemptId(1)).unwrap();
    assert!(ClientHandshakeCoordinator::build(
      ClientHandshake::new(endpoint(4000), HANDSHAKE_TIMEOUT).unwrap(),
      used_client,
    )
    .is_err());

    let mut hello_client = client_crypto();
    let hello = hello_client
      .start_attempt(ClientAttemptId(1))
      .unwrap()
      .into_payload();
    let mut used_server = server_crypto();
    assert!(matches!(
      used_server
        .prepare_server_hello(CandidateId::new(1), ClientAttemptId(1), hello)
        .unwrap(),
      CryptoOutcome::Success(_)
    ));
    assert!(ServerHandshakeCoordinator::build(
      ServerHandshake::new(SessionPolicy::new(1, HANDSHAKE_TIMEOUT, IDLE_TIMEOUT).unwrap(),),
      used_server,
    )
    .is_err());
  }
}
