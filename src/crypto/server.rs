//! Server-side cryptographic handshake boundary.

use crate::crypto::types::{
  AuthenticatedClientFinish, CryptoOutcome, CryptoShutdownOutcome, CryptoStateError,
  PreparedServerFinish, PreparedServerHello, ServerCandidateRemoval, ServerCryptoPhase,
};
use crate::session::types::{ClientAttemptId, EstablishedSessionMetadata, SessionId};
use crate::session::CandidateId;

pub(crate) trait ServerHandshakeCrypto {
  type ClientHelloPayload;
  type ServerHelloPayload;
  type ClientFinishPayload;
  type ServerFinishPayload;

  fn phase(&self) -> ServerCryptoPhase;
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
