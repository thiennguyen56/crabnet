use std::{fmt, net::SocketAddr};

use crate::session::{
  client::{ClientAction, ClientDropReason, ClientStateError, ClientStateName},
  server::{ServerDropReason, ServerReport, ServerStateError, ServerStateName},
  types::{ClientAttemptId, EstablishedSessionMetadata},
  CandidateId,
};

use crate::crypto::server::ServerCryptoStatus;
use crate::crypto::types::{
  ClientContextRemoval, ClientCryptoPhase, CryptoShutdownOutcome, CryptoStateError,
  ServerCandidateRemoval, ServerCryptoPhase,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CoordinatorLifecycle {
  Running,
  Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClientHandshakeMessage<ClientHelloPayload, ClientFinishPayload> {
  ClientHello(ClientHello<ClientHelloPayload>),
  ClientFinish(ClientFinish<ClientFinishPayload>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ServerHandshakeMessage<ServerHelloPayload, ServerFinishPayload> {
  ServerHello(ServerHello<ServerHelloPayload>),
  ServerFinish(ServerFinish<ServerFinishPayload>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerOutbound<Message> {
  pub(crate) destination: SocketAddr,
  pub(crate) message: Message,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CoordinatorBuildError {
  UnexpectedInitialClientPolicyState { observed: ClientStateName },
  UnexpectedInitialClientCryptoPhase { observed: ClientCryptoPhase },
  UnexpectedInitialServerPolicyState { observed: ServerStateName },
  ServerCryptoNotFresh { observed: ServerCryptoStatus },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClientCoordinatorEvent {
  Dropped {
    reason: ClientDropReason,
  },
  HandshakeTimedOut {
    attempt_id: ClientAttemptId,
  },
  SessionEstablished {
    metadata: EstablishedSessionMetadata,
  },
  Closed {
    policy_was_active: bool,
    crypto_cleanup: CryptoShutdownOutcome,
  },
  AlreadyClosed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientCoordinatorReport<ClientHelloPayload, ClientFinishPayload> {
  pub(crate) outbound: Vec<ClientHandshakeMessage<ClientHelloPayload, ClientFinishPayload>>,
  pub(crate) events: Vec<ClientCoordinatorEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ServerCoordinatorEvent {
  Dropped {
    source: SocketAddr,
    reason: ServerDropReason,
  },
  CandidateExpired {
    candidate_id: CandidateId,
    source: SocketAddr,
    client_attempt_id: ClientAttemptId,
  },
  SessionEstablished {
    source: SocketAddr,
    metadata: EstablishedSessionMetadata,
  },
  Closed {
    policy_removed_candidates: usize,
    policy_removed_session: bool,
    crypto_cleanup: CryptoShutdownOutcome,
  },
  AlreadyClosed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerCoordinatorReport<ServerHelloPayload, ServerFinishPayload> {
  pub(crate) outbound:
    Vec<ServerOutbound<ServerHandshakeMessage<ServerHelloPayload, ServerFinishPayload>>>,
  pub(crate) events: Vec<ServerCoordinatorEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CoordinatorInvariantError {
  UnexpectedClientAction,
  UnexpectedServerEffect,
  UnexpectedServerReport,
  AttemptMismatch {
    expected: ClientAttemptId,
    observed: ClientAttemptId,
  },
  SessionMetadataMismatch {
    expected: EstablishedSessionMetadata,
    observed: EstablishedSessionMetadata,
  },
  ClientPhaseMismatch {
    policy: ClientStateName,
    crypto: ClientCryptoPhase,
  },
  ServerPhaseMismatch {
    policy: ServerStateName,
    crypto: ServerCryptoPhase,
  },
  ServerPendingContextCountMismatch {
    policy_pending: usize,
    crypto_pending: usize,
  },
  ServerCryptoStatusMismatch {
    policy: ServerStateName,
    observed: ServerCryptoStatus,
  },
  CandidateCleanupMismatch {
    candidate_id: CandidateId,
    expected: ServerCandidateRemoval,
    observed: ServerCandidateRemoval,
  },
  ClientContextCleanupMismatch {
    attempt_id: ClientAttemptId,
    expected: ClientContextRemoval,
    observed: ClientContextRemoval,
  },
  CryptoFailureCorrelationMismatch,
  CryptoResultCorrelationMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CoordinatorPrimaryError {
  ClientPolicy(ClientStateError),
  ServerPolicy(ServerStateError),
  Crypto(CryptoStateError),
  Invariant(CoordinatorInvariantError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CoordinatorPolicyCleanup {
  Client {
    action: ClientAction,
  },
  Server {
    report: Option<ServerReport>,
    error: Option<ServerStateError>,
  },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FatalCoordinatorError {
  pub(crate) primary: CoordinatorPrimaryError,
  pub(crate) policy_cleanup: CoordinatorPolicyCleanup,
  pub(crate) crypto_cleanup: CryptoShutdownOutcome,
}

pub(crate) type ClientCoordinatorResult<ClientHelloPayload, ClientFinishPayload> =
  Result<ClientCoordinatorReport<ClientHelloPayload, ClientFinishPayload>, FatalCoordinatorError>;

pub(crate) type ServerCoordinatorResult<ServerHelloPayload, ServerFinishPayload> =
  Result<ServerCoordinatorReport<ServerHelloPayload, ServerFinishPayload>, FatalCoordinatorError>;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ClientHello<P> {
  pub(crate) client_attempt_id: ClientAttemptId,
  pub(crate) payload: P,
}

impl<P> fmt::Debug for ClientHello<P> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ClientHello")
      .field("client_attempt_id", &self.client_attempt_id)
      .field("payload", &"<opaque>")
      .finish()
  }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ServerHello<P> {
  pub(crate) client_attempt_id: ClientAttemptId,
  pub(crate) payload: P,
}

impl<P> fmt::Debug for ServerHello<P> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ServerHello")
      .field("client_attempt_id", &self.client_attempt_id)
      .field("payload", &"<opaque>")
      .finish()
  }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ClientFinish<P> {
  pub(crate) client_attempt_id: ClientAttemptId,
  pub(crate) payload: P,
}

impl<P> fmt::Debug for ClientFinish<P> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ClientFinish")
      .field("client_attempt_id", &self.client_attempt_id)
      .field("payload", &"<opaque>")
      .finish()
  }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ServerFinish<P> {
  pub(crate) client_attempt_id: ClientAttemptId,
  pub(crate) payload: P,
}

impl<P> fmt::Debug for ServerFinish<P> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ServerFinish")
      .field("client_attempt_id", &self.client_attempt_id)
      .field("payload", &"<opaque>")
      .finish()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::session::types::ClientAttemptId;

  struct SecretPayload;

  impl fmt::Debug for SecretPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
      formatter.write_str("SECRET_PAYLOAD")
    }
  }

  #[test]
  fn transport_debug_redacts_opaque_payloads() {
    let message = ClientHello {
      client_attempt_id: ClientAttemptId(7),
      payload: SecretPayload,
    };
    let rendered = format!("{message:?}");

    assert!(rendered.contains("<opaque>"));
    assert!(!rendered.contains("SECRET_PAYLOAD"));
  }
}
