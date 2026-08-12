//! Provider-independent types for authenticated handshake cryptography.

use std::fmt;

use crate::session::types::{ClientAttemptId, EstablishedSessionMetadata, SessionId};
use crate::session::CandidateId;

/// ClientHello payload prepared for one client attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedClientHello<P> {
  attempt_id: ClientAttemptId,
  payload: P,
}

impl<P> PreparedClientHello<P> {
  pub(super) fn new(attempt_id: ClientAttemptId, payload: P) -> Self {
    Self {
      attempt_id,
      payload,
    }
  }

  pub(crate) const fn attempt_id(&self) -> ClientAttemptId {
    self.attempt_id
  }

  pub(crate) const fn payload(&self) -> &P {
    &self.payload
  }

  pub(crate) fn into_payload(self) -> P {
    self.payload
  }
}

/// ServerHello payload bound to an admitted server candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedServerHello<P> {
  candidate_id: CandidateId,
  client_attempt_id: ClientAttemptId,
  payload: P,
}

impl<P> PreparedServerHello<P> {
  pub(super) fn new(
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    payload: P,
  ) -> Self {
    Self {
      candidate_id,
      client_attempt_id,
      payload,
    }
  }

  pub(crate) const fn candidate_id(&self) -> CandidateId {
    self.candidate_id
  }

  pub(crate) const fn client_attempt_id(&self) -> ClientAttemptId {
    self.client_attempt_id
  }

  pub(crate) const fn payload(&self) -> &P {
    &self.payload
  }

  pub(crate) fn into_payload(self) -> P {
    self.payload
  }
}

/// ClientFinish payload prepared for an authenticated server hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedClientFinish<P> {
  attempt_id: ClientAttemptId,
  payload: P,
}

impl<P> PreparedClientFinish<P> {
  pub(super) fn new(attempt_id: ClientAttemptId, payload: P) -> Self {
    Self {
      attempt_id,
      payload,
    }
  }

  pub(crate) const fn attempt_id(&self) -> ClientAttemptId {
    self.attempt_id
  }

  pub(crate) const fn payload(&self) -> &P {
    &self.payload
  }

  pub(crate) fn into_payload(self) -> P {
    self.payload
  }
}

/// ServerFinish payload prepared for one committed authenticated session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedServerFinish<P> {
  candidate_id: CandidateId,
  client_attempt_id: ClientAttemptId,
  session_id: SessionId,
  payload: P,
}

impl<P> PreparedServerFinish<P> {
  pub(super) fn new(
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    session_id: SessionId,
    payload: P,
  ) -> Self {
    Self {
      candidate_id,
      client_attempt_id,
      session_id,
      payload,
    }
  }

  pub(crate) const fn candidate_id(&self) -> CandidateId {
    self.candidate_id
  }

  pub(crate) const fn client_attempt_id(&self) -> ClientAttemptId {
    self.client_attempt_id
  }

  pub(crate) const fn session_id(&self) -> SessionId {
    self.session_id
  }

  pub(crate) const fn payload(&self) -> &P {
    &self.payload
  }

  pub(crate) fn into_payload(self) -> P {
    self.payload
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticatedServerHello {
  attempt_id: ClientAttemptId,
}
impl AuthenticatedServerHello {
  pub(super) const fn new(attempt_id: ClientAttemptId) -> Self {
    Self { attempt_id }
  }
  pub(crate) const fn attempt_id(&self) -> ClientAttemptId {
    self.attempt_id
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticatedClientFinish {
  candidate_id: CandidateId,
  client_attempt_id: ClientAttemptId,
  metadata: EstablishedSessionMetadata,
}
impl AuthenticatedClientFinish {
  pub(super) const fn new(
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    metadata: EstablishedSessionMetadata,
  ) -> Self {
    Self {
      candidate_id,
      client_attempt_id,
      metadata,
    }
  }
  pub(crate) const fn candidate_id(&self) -> CandidateId {
    self.candidate_id
  }
  pub(crate) const fn client_attempt_id(&self) -> ClientAttemptId {
    self.client_attempt_id
  }
  pub(crate) const fn metadata(&self) -> EstablishedSessionMetadata {
    self.metadata
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticatedServerFinish {
  attempt_id: ClientAttemptId,
  metadata: EstablishedSessionMetadata,
}
impl AuthenticatedServerFinish {
  pub(super) const fn new(
    attempt_id: ClientAttemptId,
    metadata: EstablishedSessionMetadata,
  ) -> Self {
    Self {
      attempt_id,
      metadata,
    }
  }
  pub(crate) const fn attempt_id(&self) -> ClientAttemptId {
    self.attempt_id
  }
  pub(crate) const fn metadata(&self) -> EstablishedSessionMetadata {
    self.metadata
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticationFailure {
  ClientAttempt {
    attempt_id: ClientAttemptId,
    reason: AuthenticationFailureReason,
  },
  ServerCandidate {
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    reason: AuthenticationFailureReason,
  },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticationFailureReason {
  InvalidCredential,
  InvalidProof,
  InvalidConfirmation,
  TranscriptMismatch,
  IdentityMismatch,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CryptoOutcome<T> {
  Success(T),
  RemoteFailure(AuthenticationFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CryptoOperation {
  Client(ClientCryptoOperation),
  Server(ServerCryptoOperation),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientCryptoOperation {
  StartAttempt,
  AuthenticateServerHello,
  PrepareClientFinish,
  AuthenticateServerFinish,
  CommitSession,
  RejectAuthenticatedSession,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerCryptoOperation {
  PrepareServerHello,
  AuthenticateClientFinish,
  CommitSession,
  RejectAuthenticatedCandidate,
  PrepareServerFinish,
  RemoveCandidate,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientCryptoPhase {
  Idle,
  AwaitingServerHello,
  AwaitingServerFinish,
  AuthenticatedPendingCommit,
  Established,
  Closed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerCryptoPhase {
  Running,
  AuthenticatedPendingCommit,
  Established,
  Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CryptoStateError {
  Closed {
    operation: CryptoOperation,
  },
  InvalidClientState {
    operation: ClientCryptoOperation,
    phase: ClientCryptoPhase,
  },
  InvalidServerState {
    operation: ServerCryptoOperation,
    phase: ServerCryptoPhase,
  },
  AttemptIdMismatch {
    expected: ClientAttemptId,
    observed: ClientAttemptId,
  },
  CandidateIdMismatch {
    expected: CandidateId,
    observed: CandidateId,
  },
  SessionIdMismatch {
    expected: SessionId,
    observed: SessionId,
  },
  AuthenticatedMetadataMismatch,
  AuthenticationCommitPending,
  MissingServerCandidateContext {
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
  },
  SessionIdExhausted,
}
impl fmt::Display for CryptoStateError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "crypto state error: {self:?}")
  }
}
impl std::error::Error for CryptoStateError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientContextRemoval {
  Removed,
  AlreadyAbsent,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerCandidateRemoval {
  Removed,
  AlreadyAbsent,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct CryptoShutdownOutcome {
  pub(crate) removed_pending_contexts: usize,
  pub(crate) removed_pending_commit: bool,
  pub(crate) removed_established_context: bool,
  pub(crate) already_closed: bool,
}
