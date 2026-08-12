//! Client-side cryptographic handshake boundary.

use crate::crypto::types::{
  AuthenticatedServerFinish, AuthenticatedServerHello, ClientContextRemoval, ClientCryptoPhase,
  CryptoOutcome, CryptoShutdownOutcome, CryptoStateError, PreparedClientFinish,
  PreparedClientHello,
};
use crate::session::types::{ClientAttemptId, EstablishedSessionMetadata};

pub(crate) trait ClientHandshakeCrypto {
  type ClientHelloPayload;
  type ServerHelloPayload;
  type ClientFinishPayload;
  type ServerFinishPayload;

  fn phase(&self) -> ClientCryptoPhase;
  fn start_attempt(
    &mut self,
    attempt_id: ClientAttemptId,
  ) -> Result<PreparedClientHello<Self::ClientHelloPayload>, CryptoStateError>;
  fn authenticate_server_hello(
    &mut self,
    attempt_id: ClientAttemptId,
    payload: Self::ServerHelloPayload,
  ) -> Result<CryptoOutcome<AuthenticatedServerHello>, CryptoStateError>;
  fn prepare_client_finish(
    &self,
    attempt_id: ClientAttemptId,
  ) -> Result<PreparedClientFinish<Self::ClientFinishPayload>, CryptoStateError>;
  fn authenticate_server_finish(
    &mut self,
    attempt_id: ClientAttemptId,
    payload: Self::ServerFinishPayload,
  ) -> Result<CryptoOutcome<AuthenticatedServerFinish>, CryptoStateError>;
  fn commit_session(
    &mut self,
    attempt_id: ClientAttemptId,
    metadata: EstablishedSessionMetadata,
  ) -> Result<(), CryptoStateError>;
  fn reject_authenticated_session(
    &mut self,
    attempt_id: ClientAttemptId,
  ) -> Result<ClientContextRemoval, CryptoStateError>;
  fn close_context(
    &mut self,
    attempt_id: ClientAttemptId,
  ) -> Result<ClientContextRemoval, CryptoStateError>;
  fn shutdown(&mut self) -> CryptoShutdownOutcome;
}
