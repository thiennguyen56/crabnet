//! Server-side cryptographic handshake boundary.

use crate::crypto::types::{
  AuthenticatedClientFinish, CryptoOutcome, CryptoShutdownOutcome, CryptoStateError,
  PreparedServerFinish, PreparedServerHello, ServerCandidateRemoval, ServerCryptoPhase,
};
use crate::session::types::{ClientAttemptId, EstablishedSessionMetadata, SessionId};
use crate::session::CandidateId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerCryptoStatus {
  pub(crate) phase: ServerCryptoPhase,
  pub(crate) pending_contexts: usize,
  pub(crate) has_pending_commit: bool,
  pub(crate) has_established_context: bool,
}

impl ServerCryptoStatus {
  pub(crate) fn new(
    phase: ServerCryptoPhase,
    pending_contexts: usize,
    has_pending_commit: bool,
    has_established_context: bool,
  ) -> Self {
    Self {
      phase,
      pending_contexts,
      has_pending_commit,
      has_established_context,
    }
  }

  pub(crate) fn is_fresh(&self) -> bool {
    self.phase == ServerCryptoPhase::Running
      && self.pending_contexts == 0
      && !self.has_pending_commit
      && !self.has_established_context
  }
}

pub(crate) trait ServerHandshakeCrypto {
  type ClientHelloPayload;
  type ServerHelloPayload;
  type ClientFinishPayload;
  type ServerFinishPayload;

  fn phase(&self) -> ServerCryptoPhase;

  fn non_secret_status(&self) -> ServerCryptoStatus;
  fn prepare_server_hello(
    &mut self,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    payload: Self::ClientHelloPayload,
  ) -> Result<CryptoOutcome<PreparedServerHello<Self::ServerHelloPayload>>, CryptoStateError>;
  fn authenticate_client_finish(
    &mut self,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    payload: Self::ClientFinishPayload,
  ) -> Result<CryptoOutcome<AuthenticatedClientFinish>, CryptoStateError>;
  fn commit_session(
    &mut self,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    metadata: EstablishedSessionMetadata,
  ) -> Result<(), CryptoStateError>;
  fn reject_authenticated_candidate(
    &mut self,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
  ) -> Result<ServerCandidateRemoval, CryptoStateError>;
  fn prepare_server_finish(
    &self,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    session_id: SessionId,
  ) -> Result<PreparedServerFinish<Self::ServerFinishPayload>, CryptoStateError>;
  fn remove_candidate(
    &mut self,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
  ) -> Result<ServerCandidateRemoval, CryptoStateError>;
  fn shutdown(&mut self) -> CryptoShutdownOutcome;
}
