//! Deterministic in-memory crypto provider for policy and adapter tests.

use std::collections::HashMap;
use std::fmt;
use std::num::NonZeroU64;

use crate::crypto::client::ClientHandshakeCrypto;
use crate::crypto::server::{ServerCryptoStatus, ServerHandshakeCrypto};
use crate::crypto::types::{
  AuthenticatedClientFinish, AuthenticatedServerFinish, AuthenticatedServerHello,
  AuthenticationFailure, AuthenticationFailureReason, ClientContextRemoval, ClientCryptoOperation,
  ClientCryptoPhase, CryptoOperation, CryptoOutcome, CryptoShutdownOutcome, CryptoStateError,
  PreparedClientFinish, PreparedClientHello, PreparedServerFinish, PreparedServerHello,
  ServerCandidateRemoval, ServerCryptoOperation, ServerCryptoPhase,
};
use crate::session::types::{ClientAttemptId, EstablishedSessionMetadata, PeerIdentity, SessionId};
use crate::session::CandidateId;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct FakeCredential(NonZeroU64);

impl FakeCredential {
  pub(crate) const fn new(marker: NonZeroU64) -> Self {
    Self(marker)
  }
}

impl fmt::Debug for FakeCredential {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("FakeCredential(REDACTED)")
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FakeClientCryptoConfig {
  credential: FakeCredential,
  client_identity: PeerIdentity,
  expected_server_identity: PeerIdentity,
}

impl FakeClientCryptoConfig {
  pub(crate) fn new(
    credential: FakeCredential,
    client_identity: PeerIdentity,
    expected_server_identity: PeerIdentity,
  ) -> Result<Self, FakeCryptoConfigError> {
    if client_identity == expected_server_identity {
      return Err(FakeCryptoConfigError::SameLocalAndExpectedIdentity);
    }
    Ok(Self {
      credential,
      client_identity,
      expected_server_identity,
    })
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FakeServerCryptoConfig {
  credential: FakeCredential,
  server_identity: PeerIdentity,
  expected_client_identity: PeerIdentity,
  first_session_id: NonZeroU64,
}

impl FakeServerCryptoConfig {
  pub(crate) fn new(
    credential: FakeCredential,
    server_identity: PeerIdentity,
    expected_client_identity: PeerIdentity,
    first_session_id: NonZeroU64,
  ) -> Result<Self, FakeCryptoConfigError> {
    if server_identity == expected_client_identity {
      return Err(FakeCryptoConfigError::SameLocalAndExpectedIdentity);
    }
    Ok(Self {
      credential,
      server_identity,
      expected_client_identity,
      first_session_id,
    })
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FakeCryptoConfigError {
  SameLocalAndExpectedIdentity,
}

impl fmt::Display for FakeCryptoConfigError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::SameLocalAndExpectedIdentity => {
        formatter.write_str("fake crypto local and expected peer identities must differ")
      }
    }
  }
}

impl std::error::Error for FakeCryptoConfigError {}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FakeProof {
  credential: FakeCredential,
  domain: FakeProofDomain,
  binding: FakeProofBinding,
}

impl fmt::Debug for FakeProof {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("FakeProof(REDACTED)")
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FakeProofDomain {
  ClientHello,
  ServerHello,
  ClientFinish,
  ServerFinish,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FakeProofBinding {
  ClientHello {
    attempt_id: ClientAttemptId,
    client_identity: PeerIdentity,
  },
  Transcript {
    attempt_id: ClientAttemptId,
    candidate_id: CandidateId,
    client_identity: PeerIdentity,
    server_identity: PeerIdentity,
    session_id: Option<SessionId>,
  },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FakeClientHello {
  attempt_id: ClientAttemptId,
  client_identity: PeerIdentity,
  proof: FakeProof,
}

#[cfg(test)]
impl FakeClientHello {
  pub(crate) fn with_corrupted_proof(mut self) -> Self {
    self.proof.domain = FakeProofDomain::ServerFinish;
    self
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FakeServerHello {
  candidate_id: CandidateId,
  client_attempt_id: ClientAttemptId,
  server_identity: PeerIdentity,
  proof: FakeProof,
}

#[cfg(test)]
impl FakeServerHello {
  pub(crate) fn with_corrupted_proof(mut self) -> Self {
    self.proof.domain = FakeProofDomain::ClientFinish;
    self
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FakeClientFinish {
  candidate_id: CandidateId,
  client_attempt_id: ClientAttemptId,
  client_identity: PeerIdentity,
  proof: FakeProof,
}

#[cfg(test)]
impl FakeClientFinish {
  pub(crate) fn with_corrupted_proof(mut self) -> Self {
    self.proof.domain = FakeProofDomain::ServerFinish;
    self
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FakeServerFinish {
  candidate_id: CandidateId,
  client_attempt_id: ClientAttemptId,
  session_id: SessionId,
  server_identity: PeerIdentity,
  proof: FakeProof,
}

#[cfg(test)]
impl FakeServerFinish {
  pub(crate) fn with_corrupted_proof(mut self) -> Self {
    self.proof.domain = FakeProofDomain::ClientFinish;
    self
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FakeTranscript {
  attempt_id: ClientAttemptId,
  candidate_id: CandidateId,
  client_identity: PeerIdentity,
  server_identity: PeerIdentity,
}

fn transcript_binding(
  transcript: FakeTranscript,
  session_id: Option<SessionId>,
) -> FakeProofBinding {
  FakeProofBinding::Transcript {
    attempt_id: transcript.attempt_id,
    candidate_id: transcript.candidate_id,
    client_identity: transcript.client_identity,
    server_identity: transcript.server_identity,
    session_id,
  }
}

fn proof(
  credential: FakeCredential,
  domain: FakeProofDomain,
  binding: FakeProofBinding,
) -> FakeProof {
  FakeProof {
    credential,
    domain,
    binding,
  }
}

fn verify_proof(
  observed: FakeProof,
  credential: FakeCredential,
  domain: FakeProofDomain,
  binding: FakeProofBinding,
) -> Result<(), AuthenticationFailureReason> {
  if observed.binding != binding {
    return Err(AuthenticationFailureReason::TranscriptMismatch);
  }
  if observed.credential != credential {
    return Err(AuthenticationFailureReason::InvalidCredential);
  }
  if observed.domain != domain {
    return Err(AuthenticationFailureReason::InvalidProof);
  }
  Ok(())
}

fn client_failure(
  attempt_id: ClientAttemptId,
  reason: AuthenticationFailureReason,
) -> CryptoOutcome<AuthenticatedServerHello> {
  CryptoOutcome::RemoteFailure(AuthenticationFailure::ClientAttempt { attempt_id, reason })
}

fn server_failure<T>(
  candidate_id: CandidateId,
  client_attempt_id: ClientAttemptId,
  reason: AuthenticationFailureReason,
) -> CryptoOutcome<T> {
  CryptoOutcome::RemoteFailure(AuthenticationFailure::ServerCandidate {
    candidate_id,
    client_attempt_id,
    reason,
  })
}

#[derive(Debug)]
pub(crate) struct FakeClientCrypto {
  config: FakeClientCryptoConfig,
  state: FakeClientCryptoState,
}

#[derive(Debug)]
enum FakeClientCryptoState {
  Idle,
  AwaitingServerHello {
    attempt_id: ClientAttemptId,
    context: AwaitingServerHelloContext,
  },
  AwaitingServerFinish {
    attempt_id: ClientAttemptId,
    context: AwaitingServerFinishContext,
  },
  AuthenticatedPendingCommit {
    attempt_id: ClientAttemptId,
    context: AuthenticatedClientContext,
  },
  Established {
    attempt_id: ClientAttemptId,
    context: ClientSessionContext,
  },
  Closed,
}

#[derive(Debug, Clone, Copy)]
struct AwaitingServerHelloContext {
  prepared_client_hello: FakeClientHello,
}

#[derive(Debug, Clone, Copy)]
struct AwaitingServerFinishContext {
  transcript: FakeTranscript,
  authenticated_server_hello: FakeServerHello,
  prepared_client_finish: FakeClientFinish,
}

#[derive(Debug, Clone, Copy)]
struct AuthenticatedClientContext {
  transcript: FakeTranscript,
  _authenticated_server_finish: FakeServerFinish,
  metadata: EstablishedSessionMetadata,
}

#[derive(Debug, Clone, Copy)]
struct ClientSessionContext {
  _transcript: FakeTranscript,
  _authenticated_server_finish: FakeServerFinish,
  metadata: EstablishedSessionMetadata,
}

impl FakeClientCrypto {
  pub(crate) const fn new(config: FakeClientCryptoConfig) -> Self {
    Self {
      config,
      state: FakeClientCryptoState::Idle,
    }
  }

  fn attempt(&self) -> Option<ClientAttemptId> {
    match self.state {
      FakeClientCryptoState::AwaitingServerHello { attempt_id, .. }
      | FakeClientCryptoState::AwaitingServerFinish { attempt_id, .. }
      | FakeClientCryptoState::AuthenticatedPendingCommit { attempt_id, .. }
      | FakeClientCryptoState::Established { attempt_id, .. } => Some(attempt_id),
      FakeClientCryptoState::Idle | FakeClientCryptoState::Closed => None,
    }
  }

  fn check_attempt(&self, observed: ClientAttemptId) -> Result<(), CryptoStateError> {
    if let Some(expected) = self.attempt()
      && expected != observed
    {
      return Err(CryptoStateError::AttemptIdMismatch { expected, observed });
    }
    Ok(())
  }
}

impl ClientHandshakeCrypto for FakeClientCrypto {
  type ClientHelloPayload = FakeClientHello;
  type ServerHelloPayload = FakeServerHello;
  type ClientFinishPayload = FakeClientFinish;
  type ServerFinishPayload = FakeServerFinish;

  fn phase(&self) -> ClientCryptoPhase {
    match self.state {
      FakeClientCryptoState::Idle => ClientCryptoPhase::Idle,
      FakeClientCryptoState::AwaitingServerHello { .. } => ClientCryptoPhase::AwaitingServerHello,
      FakeClientCryptoState::AwaitingServerFinish { .. } => ClientCryptoPhase::AwaitingServerFinish,
      FakeClientCryptoState::AuthenticatedPendingCommit { .. } => {
        ClientCryptoPhase::AuthenticatedPendingCommit
      }
      FakeClientCryptoState::Established { .. } => ClientCryptoPhase::Established,
      FakeClientCryptoState::Closed => ClientCryptoPhase::Closed,
    }
  }

  fn start_attempt(
    &mut self,
    attempt_id: ClientAttemptId,
  ) -> Result<PreparedClientHello<FakeClientHello>, CryptoStateError> {
    if self.phase() == ClientCryptoPhase::Closed {
      return Err(CryptoStateError::Closed {
        operation: CryptoOperation::Client(ClientCryptoOperation::StartAttempt),
      });
    }
    if self.phase() != ClientCryptoPhase::Idle {
      return Err(CryptoStateError::InvalidClientState {
        operation: ClientCryptoOperation::StartAttempt,
        phase: self.phase(),
      });
    }
    let binding = FakeProofBinding::ClientHello {
      attempt_id,
      client_identity: self.config.client_identity,
    };
    let payload = FakeClientHello {
      attempt_id,
      client_identity: self.config.client_identity,
      proof: proof(
        self.config.credential,
        FakeProofDomain::ClientHello,
        binding,
      ),
    };
    self.state = FakeClientCryptoState::AwaitingServerHello {
      attempt_id,
      context: AwaitingServerHelloContext {
        prepared_client_hello: payload,
      },
    };
    Ok(PreparedClientHello::new(attempt_id, payload))
  }

  fn authenticate_server_hello(
    &mut self,
    attempt_id: ClientAttemptId,
    payload: FakeServerHello,
  ) -> Result<CryptoOutcome<AuthenticatedServerHello>, CryptoStateError> {
    self.check_attempt(attempt_id)?;
    let FakeClientCryptoState::AwaitingServerHello { context, .. } = self.state else {
      return Err(CryptoStateError::InvalidClientState {
        operation: ClientCryptoOperation::AuthenticateServerHello,
        phase: self.phase(),
      });
    };
    if payload.server_identity != self.config.expected_server_identity {
      return Ok(client_failure(
        attempt_id,
        AuthenticationFailureReason::IdentityMismatch,
      ));
    }
    if payload.client_attempt_id != attempt_id {
      return Ok(client_failure(
        attempt_id,
        AuthenticationFailureReason::TranscriptMismatch,
      ));
    }
    let transcript = FakeTranscript {
      attempt_id,
      candidate_id: payload.candidate_id,
      client_identity: self.config.client_identity,
      server_identity: self.config.expected_server_identity,
    };
    if let Err(reason) = verify_proof(
      payload.proof,
      self.config.credential,
      FakeProofDomain::ServerHello,
      transcript_binding(transcript, None),
    ) {
      return Ok(client_failure(attempt_id, reason));
    }
    let finish = FakeClientFinish {
      candidate_id: transcript.candidate_id,
      client_attempt_id: attempt_id,
      client_identity: self.config.client_identity,
      proof: proof(
        self.config.credential,
        FakeProofDomain::ClientFinish,
        transcript_binding(transcript, None),
      ),
    };
    let _ = context.prepared_client_hello;
    self.state = FakeClientCryptoState::AwaitingServerFinish {
      attempt_id,
      context: AwaitingServerFinishContext {
        transcript,
        authenticated_server_hello: payload,
        prepared_client_finish: finish,
      },
    };
    Ok(CryptoOutcome::Success(AuthenticatedServerHello::new(
      attempt_id,
    )))
  }

  fn prepare_client_finish(
    &self,
    attempt_id: ClientAttemptId,
  ) -> Result<PreparedClientFinish<FakeClientFinish>, CryptoStateError> {
    self.check_attempt(attempt_id)?;
    let FakeClientCryptoState::AwaitingServerFinish { context, .. } = self.state else {
      return Err(CryptoStateError::InvalidClientState {
        operation: ClientCryptoOperation::PrepareClientFinish,
        phase: self.phase(),
      });
    };
    Ok(PreparedClientFinish::new(
      attempt_id,
      context.prepared_client_finish,
    ))
  }

  fn authenticate_server_finish(
    &mut self,
    attempt_id: ClientAttemptId,
    payload: FakeServerFinish,
  ) -> Result<CryptoOutcome<AuthenticatedServerFinish>, CryptoStateError> {
    self.check_attempt(attempt_id)?;
    let FakeClientCryptoState::AwaitingServerFinish { context, .. } = self.state else {
      return Err(CryptoStateError::InvalidClientState {
        operation: ClientCryptoOperation::AuthenticateServerFinish,
        phase: self.phase(),
      });
    };
    if payload.server_identity != self.config.expected_server_identity {
      return Ok(CryptoOutcome::RemoteFailure(
        AuthenticationFailure::ClientAttempt {
          attempt_id,
          reason: AuthenticationFailureReason::IdentityMismatch,
        },
      ));
    }
    if payload.client_attempt_id != attempt_id
      || payload.candidate_id != context.transcript.candidate_id
    {
      return Ok(CryptoOutcome::RemoteFailure(
        AuthenticationFailure::ClientAttempt {
          attempt_id,
          reason: AuthenticationFailureReason::TranscriptMismatch,
        },
      ));
    }
    if let Err(mut reason) = verify_proof(
      payload.proof,
      self.config.credential,
      FakeProofDomain::ServerFinish,
      transcript_binding(context.transcript, Some(payload.session_id)),
    ) {
      if reason == AuthenticationFailureReason::InvalidProof {
        reason = AuthenticationFailureReason::InvalidConfirmation;
      }
      return Ok(CryptoOutcome::RemoteFailure(
        AuthenticationFailure::ClientAttempt { attempt_id, reason },
      ));
    }
    let metadata = EstablishedSessionMetadata {
      session_id: payload.session_id,
      peer_identity: self.config.expected_server_identity,
    };
    let _ = context.authenticated_server_hello;
    self.state = FakeClientCryptoState::AuthenticatedPendingCommit {
      attempt_id,
      context: AuthenticatedClientContext {
        transcript: context.transcript,
        _authenticated_server_finish: payload,
        metadata,
      },
    };
    Ok(CryptoOutcome::Success(AuthenticatedServerFinish::new(
      attempt_id, metadata,
    )))
  }

  fn commit_session(
    &mut self,
    attempt_id: ClientAttemptId,
    metadata: EstablishedSessionMetadata,
  ) -> Result<(), CryptoStateError> {
    self.check_attempt(attempt_id)?;
    let FakeClientCryptoState::AuthenticatedPendingCommit { context, .. } = self.state else {
      return Err(CryptoStateError::InvalidClientState {
        operation: ClientCryptoOperation::CommitSession,
        phase: self.phase(),
      });
    };
    if metadata != context.metadata {
      return Err(CryptoStateError::AuthenticatedMetadataMismatch);
    }
    self.state = FakeClientCryptoState::Established {
      attempt_id,
      context: ClientSessionContext {
        _transcript: context.transcript,
        _authenticated_server_finish: context._authenticated_server_finish,
        metadata,
      },
    };
    Ok(())
  }

  fn reject_authenticated_session(
    &mut self,
    attempt_id: ClientAttemptId,
  ) -> Result<ClientContextRemoval, CryptoStateError> {
    if self.phase() == ClientCryptoPhase::Closed {
      return Ok(ClientContextRemoval::AlreadyAbsent);
    }
    self.check_attempt(attempt_id)?;
    if !matches!(
      self.state,
      FakeClientCryptoState::AuthenticatedPendingCommit { .. }
    ) {
      return Err(CryptoStateError::InvalidClientState {
        operation: ClientCryptoOperation::RejectAuthenticatedSession,
        phase: self.phase(),
      });
    }
    self.state = FakeClientCryptoState::Closed;
    Ok(ClientContextRemoval::Removed)
  }

  fn close_context(
    &mut self,
    attempt_id: ClientAttemptId,
  ) -> Result<ClientContextRemoval, CryptoStateError> {
    if matches!(
      self.state,
      FakeClientCryptoState::Idle | FakeClientCryptoState::Closed
    ) {
      return Ok(ClientContextRemoval::AlreadyAbsent);
    }
    self.check_attempt(attempt_id)?;
    self.state = FakeClientCryptoState::Closed;
    Ok(ClientContextRemoval::Removed)
  }

  fn shutdown(&mut self) -> CryptoShutdownOutcome {
    let phase = self.phase();
    self.state = FakeClientCryptoState::Closed;
    CryptoShutdownOutcome {
      removed_pending_contexts: usize::from(matches!(
        phase,
        ClientCryptoPhase::AwaitingServerHello | ClientCryptoPhase::AwaitingServerFinish
      )),
      removed_pending_commit: phase == ClientCryptoPhase::AuthenticatedPendingCommit,
      removed_established_context: phase == ClientCryptoPhase::Established,
      already_closed: phase == ClientCryptoPhase::Closed,
    }
  }
}

#[derive(Debug)]
pub(crate) struct FakeServerCrypto {
  config: FakeServerCryptoConfig,
  pending: HashMap<CandidateId, FakeServerCandidateContext>,
  pending_commit: Option<FakeAuthenticatedServerContext>,
  established: Option<FakeServerSessionContext>,
  next_session_id: Option<NonZeroU64>,
  closed: bool,
}

#[derive(Debug, Clone, Copy)]
struct FakeServerCandidateContext {
  attempt_id: ClientAttemptId,
  authenticated_client_hello: FakeClientHello,
  prepared_server_hello: FakeServerHello,
  transcript: FakeTranscript,
}

#[derive(Debug, Clone, Copy)]
struct FakeAuthenticatedServerContext {
  candidate_id: CandidateId,
  attempt_id: ClientAttemptId,
  authenticated_client_finish: FakeClientFinish,
  metadata: EstablishedSessionMetadata,
  transcript: FakeTranscript,
}

#[derive(Debug, Clone, Copy)]
struct FakeServerSessionContext {
  candidate_id: CandidateId,
  attempt_id: ClientAttemptId,
  authenticated_client_finish: FakeClientFinish,
  metadata: EstablishedSessionMetadata,
  prepared_server_finish: FakeServerFinish,
}

impl FakeServerCrypto {
  pub(crate) fn new(config: FakeServerCryptoConfig) -> Self {
    Self {
      config,
      pending: HashMap::new(),
      pending_commit: None,
      established: None,
      next_session_id: Some(config.first_session_id),
      closed: false,
    }
  }

  fn reserve_session_id(&mut self) -> Result<SessionId, CryptoStateError> {
    let current = self
      .next_session_id
      .ok_or(CryptoStateError::SessionIdExhausted)?;
    self.next_session_id = NonZeroU64::new(current.get().wrapping_add(1));
    Ok(SessionId(current.get()))
  }

  fn check_tuple(
    expected_candidate: CandidateId,
    expected_attempt: ClientAttemptId,
    observed_candidate: CandidateId,
    observed_attempt: ClientAttemptId,
  ) -> Result<(), CryptoStateError> {
    if expected_candidate != observed_candidate {
      return Err(CryptoStateError::CandidateIdMismatch {
        expected: expected_candidate,
        observed: observed_candidate,
      });
    }
    if expected_attempt != observed_attempt {
      return Err(CryptoStateError::AttemptIdMismatch {
        expected: expected_attempt,
        observed: observed_attempt,
      });
    }
    Ok(())
  }
}

impl ServerHandshakeCrypto for FakeServerCrypto {
  type ClientHelloPayload = FakeClientHello;
  type ServerHelloPayload = FakeServerHello;
  type ClientFinishPayload = FakeClientFinish;
  type ServerFinishPayload = FakeServerFinish;

  fn phase(&self) -> ServerCryptoPhase {
    if self.closed {
      ServerCryptoPhase::Closed
    } else if self.established.is_some() {
      ServerCryptoPhase::Established
    } else if self.pending_commit.is_some() {
      ServerCryptoPhase::AuthenticatedPendingCommit
    } else {
      ServerCryptoPhase::Running
    }
  }

  fn non_secret_status(&self) -> ServerCryptoStatus {
    ServerCryptoStatus::new(
      self.phase(),
      self.pending.len(),
      self.pending_commit.is_some(),
      self.established.is_some(),
    )
  }

  fn prepare_server_hello(
    &mut self,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    payload: FakeClientHello,
  ) -> Result<CryptoOutcome<PreparedServerHello<FakeServerHello>>, CryptoStateError> {
    if self.closed {
      return Err(CryptoStateError::Closed {
        operation: CryptoOperation::Server(ServerCryptoOperation::PrepareServerHello),
      });
    }
    if self.phase() == ServerCryptoPhase::AuthenticatedPendingCommit {
      return Err(CryptoStateError::AuthenticationCommitPending);
    }
    if self.phase() != ServerCryptoPhase::Running {
      return Err(CryptoStateError::InvalidServerState {
        operation: ServerCryptoOperation::PrepareServerHello,
        phase: self.phase(),
      });
    }
    if let Some(existing) = self.pending.get(&candidate_id) {
      Self::check_tuple(
        candidate_id,
        existing.attempt_id,
        candidate_id,
        client_attempt_id,
      )?;
      if existing.authenticated_client_hello != payload {
        return Ok(server_failure(
          candidate_id,
          client_attempt_id,
          AuthenticationFailureReason::TranscriptMismatch,
        ));
      }
      return Ok(CryptoOutcome::Success(PreparedServerHello::new(
        candidate_id,
        client_attempt_id,
        existing.prepared_server_hello,
      )));
    }
    if payload.client_identity != self.config.expected_client_identity {
      return Ok(server_failure(
        candidate_id,
        client_attempt_id,
        AuthenticationFailureReason::IdentityMismatch,
      ));
    }
    if payload.attempt_id != client_attempt_id {
      return Ok(server_failure(
        candidate_id,
        client_attempt_id,
        AuthenticationFailureReason::TranscriptMismatch,
      ));
    }
    if let Err(reason) = verify_proof(
      payload.proof,
      self.config.credential,
      FakeProofDomain::ClientHello,
      FakeProofBinding::ClientHello {
        attempt_id: client_attempt_id,
        client_identity: self.config.expected_client_identity,
      },
    ) {
      return Ok(server_failure(candidate_id, client_attempt_id, reason));
    }
    let transcript = FakeTranscript {
      attempt_id: client_attempt_id,
      candidate_id,
      client_identity: self.config.expected_client_identity,
      server_identity: self.config.server_identity,
    };
    let response = FakeServerHello {
      candidate_id,
      client_attempt_id,
      server_identity: self.config.server_identity,
      proof: proof(
        self.config.credential,
        FakeProofDomain::ServerHello,
        transcript_binding(transcript, None),
      ),
    };
    self.pending.insert(
      candidate_id,
      FakeServerCandidateContext {
        attempt_id: client_attempt_id,
        authenticated_client_hello: payload,
        prepared_server_hello: response,
        transcript,
      },
    );
    Ok(CryptoOutcome::Success(PreparedServerHello::new(
      candidate_id,
      client_attempt_id,
      response,
    )))
  }

  fn authenticate_client_finish(
    &mut self,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    payload: FakeClientFinish,
  ) -> Result<CryptoOutcome<AuthenticatedClientFinish>, CryptoStateError> {
    if self.closed {
      return Err(CryptoStateError::Closed {
        operation: CryptoOperation::Server(ServerCryptoOperation::AuthenticateClientFinish),
      });
    }
    if let Some(established) = self.established {
      Self::check_tuple(
        established.candidate_id,
        established.attempt_id,
        candidate_id,
        client_attempt_id,
      )?;
      if established.authenticated_client_finish != payload {
        return Ok(server_failure(
          candidate_id,
          client_attempt_id,
          AuthenticationFailureReason::TranscriptMismatch,
        ));
      }
      return Ok(CryptoOutcome::Success(AuthenticatedClientFinish::new(
        candidate_id,
        client_attempt_id,
        established.metadata,
      )));
    }
    if let Some(pending) = self.pending_commit {
      Self::check_tuple(
        pending.candidate_id,
        pending.attempt_id,
        candidate_id,
        client_attempt_id,
      )?;
      if pending.authenticated_client_finish != payload {
        return Ok(server_failure(
          candidate_id,
          client_attempt_id,
          AuthenticationFailureReason::TranscriptMismatch,
        ));
      }
      return Ok(CryptoOutcome::Success(AuthenticatedClientFinish::new(
        candidate_id,
        client_attempt_id,
        pending.metadata,
      )));
    }
    let context =
      *self
        .pending
        .get(&candidate_id)
        .ok_or(CryptoStateError::MissingServerCandidateContext {
          candidate_id,
          client_attempt_id,
        })?;
    Self::check_tuple(
      candidate_id,
      context.attempt_id,
      candidate_id,
      client_attempt_id,
    )?;
    if payload.client_identity != self.config.expected_client_identity {
      return Ok(server_failure(
        candidate_id,
        client_attempt_id,
        AuthenticationFailureReason::IdentityMismatch,
      ));
    }
    if payload.candidate_id != candidate_id || payload.client_attempt_id != client_attempt_id {
      return Ok(server_failure(
        candidate_id,
        client_attempt_id,
        AuthenticationFailureReason::TranscriptMismatch,
      ));
    }
    if let Err(reason) = verify_proof(
      payload.proof,
      self.config.credential,
      FakeProofDomain::ClientFinish,
      transcript_binding(context.transcript, None),
    ) {
      return Ok(server_failure(candidate_id, client_attempt_id, reason));
    }
    let session_id = self.reserve_session_id()?;
    let metadata = EstablishedSessionMetadata {
      session_id,
      peer_identity: self.config.expected_client_identity,
    };
    self.pending.remove(&candidate_id);
    self.pending_commit = Some(FakeAuthenticatedServerContext {
      candidate_id,
      attempt_id: client_attempt_id,
      authenticated_client_finish: payload,
      metadata,
      transcript: context.transcript,
    });
    Ok(CryptoOutcome::Success(AuthenticatedClientFinish::new(
      candidate_id,
      client_attempt_id,
      metadata,
    )))
  }

  fn commit_session(
    &mut self,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    metadata: EstablishedSessionMetadata,
  ) -> Result<(), CryptoStateError> {
    let pending = self
      .pending_commit
      .ok_or(CryptoStateError::InvalidServerState {
        operation: ServerCryptoOperation::CommitSession,
        phase: self.phase(),
      })?;
    Self::check_tuple(
      pending.candidate_id,
      pending.attempt_id,
      candidate_id,
      client_attempt_id,
    )?;
    if pending.metadata != metadata {
      return Err(CryptoStateError::AuthenticatedMetadataMismatch);
    }
    let finish = FakeServerFinish {
      candidate_id,
      client_attempt_id,
      session_id: metadata.session_id,
      server_identity: self.config.server_identity,
      proof: proof(
        self.config.credential,
        FakeProofDomain::ServerFinish,
        transcript_binding(pending.transcript, Some(metadata.session_id)),
      ),
    };
    self.pending.clear();
    self.pending_commit = None;
    self.established = Some(FakeServerSessionContext {
      candidate_id,
      attempt_id: client_attempt_id,
      authenticated_client_finish: pending.authenticated_client_finish,
      metadata,
      prepared_server_finish: finish,
    });
    Ok(())
  }

  fn reject_authenticated_candidate(
    &mut self,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
  ) -> Result<ServerCandidateRemoval, CryptoStateError> {
    let Some(pending) = self.pending_commit else {
      if self.closed {
        return Ok(ServerCandidateRemoval::AlreadyAbsent);
      }
      return Err(CryptoStateError::InvalidServerState {
        operation: ServerCryptoOperation::RejectAuthenticatedCandidate,
        phase: self.phase(),
      });
    };
    Self::check_tuple(
      pending.candidate_id,
      pending.attempt_id,
      candidate_id,
      client_attempt_id,
    )?;
    self.pending_commit = None;
    Ok(ServerCandidateRemoval::Removed)
  }

  fn prepare_server_finish(
    &self,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    session_id: SessionId,
  ) -> Result<PreparedServerFinish<FakeServerFinish>, CryptoStateError> {
    let established = self
      .established
      .ok_or(CryptoStateError::InvalidServerState {
        operation: ServerCryptoOperation::PrepareServerFinish,
        phase: self.phase(),
      })?;
    Self::check_tuple(
      established.candidate_id,
      established.attempt_id,
      candidate_id,
      client_attempt_id,
    )?;
    if established.metadata.session_id != session_id {
      return Err(CryptoStateError::SessionIdMismatch {
        expected: established.metadata.session_id,
        observed: session_id,
      });
    }
    Ok(PreparedServerFinish::new(
      candidate_id,
      client_attempt_id,
      session_id,
      established.prepared_server_finish,
    ))
  }

  fn remove_candidate(
    &mut self,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
  ) -> Result<ServerCandidateRemoval, CryptoStateError> {
    if self.closed {
      return Ok(ServerCandidateRemoval::AlreadyAbsent);
    }
    if self.pending_commit.is_some() {
      return Err(CryptoStateError::AuthenticationCommitPending);
    }
    if self.established.is_some() {
      return Err(CryptoStateError::InvalidServerState {
        operation: ServerCryptoOperation::RemoveCandidate,
        phase: self.phase(),
      });
    }
    let Some(context) = self.pending.get(&candidate_id) else {
      return Ok(ServerCandidateRemoval::AlreadyAbsent);
    };
    Self::check_tuple(
      candidate_id,
      context.attempt_id,
      candidate_id,
      client_attempt_id,
    )?;
    self.pending.remove(&candidate_id);
    Ok(ServerCandidateRemoval::Removed)
  }

  fn shutdown(&mut self) -> CryptoShutdownOutcome {
    let outcome = CryptoShutdownOutcome {
      removed_pending_contexts: self.pending.len(),
      removed_pending_commit: self.pending_commit.is_some(),
      removed_established_context: self.established.is_some(),
      already_closed: self.closed,
    };
    self.pending.clear();
    self.pending_commit = None;
    self.established = None;
    self.closed = true;
    outcome
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn credential(value: u64) -> FakeCredential {
    FakeCredential::new(NonZeroU64::new(value).unwrap())
  }

  fn pair(first_session_id: u64) -> (FakeClientCrypto, FakeServerCrypto) {
    let client = FakeClientCrypto::new(
      FakeClientCryptoConfig::new(credential(7), PeerIdentity(1), PeerIdentity(2)).unwrap(),
    );
    let server = FakeServerCrypto::new(
      FakeServerCryptoConfig::new(
        credential(7),
        PeerIdentity(2),
        PeerIdentity(1),
        NonZeroU64::new(first_session_id).unwrap(),
      )
      .unwrap(),
    );
    (client, server)
  }

  fn success<T>(outcome: CryptoOutcome<T>) -> T {
    match outcome {
      CryptoOutcome::Success(value) => value,
      CryptoOutcome::RemoteFailure(failure) => {
        panic!("expected success, got {failure:?}")
      }
    }
  }

  #[test]
  fn full_handshake_requires_explicit_commits() {
    let (mut client, mut server) = pair(11);
    let attempt = ClientAttemptId(3);
    let candidate = CandidateId::new(5);

    let client_hello = client.start_attempt(attempt).unwrap().into_payload();
    let server_hello = success(
      server
        .prepare_server_hello(candidate, attempt, client_hello)
        .unwrap(),
    )
    .into_payload();
    let authenticated_hello = success(
      client
        .authenticate_server_hello(attempt, server_hello)
        .unwrap(),
    );
    assert_eq!(authenticated_hello.attempt_id(), attempt);

    let client_finish = client
      .prepare_client_finish(attempt)
      .unwrap()
      .into_payload();
    let authenticated_client = success(
      server
        .authenticate_client_finish(candidate, attempt, client_finish)
        .unwrap(),
    );
    assert_eq!(
      server.phase(),
      ServerCryptoPhase::AuthenticatedPendingCommit
    );
    server
      .commit_session(candidate, attempt, authenticated_client.metadata())
      .unwrap();

    let server_finish = server
      .prepare_server_finish(
        candidate,
        attempt,
        authenticated_client.metadata().session_id,
      )
      .unwrap()
      .into_payload();
    let authenticated_server = success(
      client
        .authenticate_server_finish(attempt, server_finish)
        .unwrap(),
    );
    assert_eq!(
      client.phase(),
      ClientCryptoPhase::AuthenticatedPendingCommit
    );
    client
      .commit_session(attempt, authenticated_server.metadata())
      .unwrap();

    assert_eq!(client.phase(), ClientCryptoPhase::Established);
    let FakeClientCryptoState::Established { context, .. } = client.state else {
      panic!("client must retain its established context");
    };
    assert_eq!(context.metadata, authenticated_server.metadata());
    assert_eq!(server.phase(), ServerCryptoPhase::Established);
    assert_eq!(authenticated_client.metadata().session_id, SessionId(11));
    assert_eq!(
      authenticated_client.metadata().peer_identity,
      PeerIdentity(1)
    );
    assert_eq!(
      authenticated_server.metadata().peer_identity,
      PeerIdentity(2)
    );
  }

  #[test]
  fn server_keeps_multiple_candidates_until_commit() {
    let (mut first_client, mut server) = pair(20);
    let (mut second_client, _) = pair(30);
    let first_attempt = ClientAttemptId(1);
    let second_attempt = ClientAttemptId(2);
    let first_candidate = CandidateId::new(1);
    let second_candidate = CandidateId::new(2);

    let first_hello = first_client
      .start_attempt(first_attempt)
      .unwrap()
      .into_payload();
    let second_hello = second_client
      .start_attempt(second_attempt)
      .unwrap()
      .into_payload();
    server
      .prepare_server_hello(first_candidate, first_attempt, first_hello)
      .unwrap();
    server
      .prepare_server_hello(second_candidate, second_attempt, second_hello)
      .unwrap();
    assert_eq!(server.pending.len(), 2);

    let first_server_hello = success(
      server
        .prepare_server_hello(first_candidate, first_attempt, first_hello)
        .unwrap(),
    )
    .into_payload();
    success(
      first_client
        .authenticate_server_hello(first_attempt, first_server_hello)
        .unwrap(),
    );
    let finish = first_client
      .prepare_client_finish(first_attempt)
      .unwrap()
      .into_payload();
    let authenticated = success(
      server
        .authenticate_client_finish(first_candidate, first_attempt, finish)
        .unwrap(),
    );
    assert_eq!(server.pending.len(), 1);
    server
      .commit_session(first_candidate, first_attempt, authenticated.metadata())
      .unwrap();
    assert!(server.pending.is_empty());
  }

  #[test]
  fn wrong_credential_is_remote_failure_and_preserves_candidate() {
    let mut client = FakeClientCrypto::new(
      FakeClientCryptoConfig::new(credential(9), PeerIdentity(1), PeerIdentity(2)).unwrap(),
    );
    let (_, mut server) = pair(1);
    let attempt = ClientAttemptId(1);
    let candidate = CandidateId::new(1);
    let hello = client.start_attempt(attempt).unwrap().into_payload();

    let outcome = server
      .prepare_server_hello(candidate, attempt, hello)
      .unwrap();
    assert!(matches!(
      outcome,
      CryptoOutcome::RemoteFailure(AuthenticationFailure::ServerCandidate {
        reason: AuthenticationFailureReason::InvalidCredential,
        ..
      })
    ));
    assert!(server.pending.is_empty());
  }

  #[test]
  fn shutdown_is_terminal_and_idempotent() {
    let (mut client, mut server) = pair(1);
    let attempt = ClientAttemptId(1);
    let candidate = CandidateId::new(1);
    let hello = client.start_attempt(attempt).unwrap().into_payload();
    server
      .prepare_server_hello(candidate, attempt, hello)
      .unwrap();

    assert_eq!(client.shutdown().removed_pending_contexts, 1);
    assert_eq!(server.shutdown().removed_pending_contexts, 1);
    assert!(client.shutdown().already_closed);
    assert!(server.shutdown().already_closed);
  }

  #[test]
  fn exact_cleanup_and_rejection_preserve_unrelated_state() {
    let (mut first_client, mut server) = pair(40);
    let (mut second_client, _) = pair(50);
    let first_attempt = ClientAttemptId(1);
    let second_attempt = ClientAttemptId(2);
    let first_candidate = CandidateId::new(1);
    let second_candidate = CandidateId::new(2);

    let first_hello = first_client.start_attempt(first_attempt).unwrap();
    assert_eq!(first_hello.attempt_id(), first_attempt);
    assert_eq!(first_hello.payload().attempt_id, first_attempt);
    let second_hello = second_client.start_attempt(second_attempt).unwrap();

    let first_server_hello = success(
      server
        .prepare_server_hello(first_candidate, first_attempt, first_hello.into_payload())
        .unwrap(),
    );
    assert_eq!(first_server_hello.candidate_id(), first_candidate);
    assert_eq!(first_server_hello.client_attempt_id(), first_attempt);
    let _ = first_server_hello.payload();

    server
      .prepare_server_hello(
        second_candidate,
        second_attempt,
        second_hello.into_payload(),
      )
      .unwrap();

    success(
      first_client
        .authenticate_server_hello(first_attempt, first_server_hello.into_payload())
        .unwrap(),
    );
    let first_finish = first_client.prepare_client_finish(first_attempt).unwrap();
    assert_eq!(first_finish.attempt_id(), first_attempt);
    let _ = first_finish.payload();
    let authenticated = success(
      server
        .authenticate_client_finish(first_candidate, first_attempt, first_finish.into_payload())
        .unwrap(),
    );
    assert_eq!(authenticated.candidate_id(), first_candidate);
    assert_eq!(authenticated.client_attempt_id(), first_attempt);

    assert_eq!(
      server
        .reject_authenticated_candidate(first_candidate, first_attempt)
        .unwrap(),
      ServerCandidateRemoval::Removed
    );
    assert!(server.pending.contains_key(&second_candidate));
    assert_eq!(
      first_client.close_context(first_attempt).unwrap(),
      ClientContextRemoval::Removed
    );
    assert_eq!(
      first_client.close_context(first_attempt).unwrap(),
      ClientContextRemoval::AlreadyAbsent
    );
    assert_eq!(
      server
        .remove_candidate(second_candidate, second_attempt)
        .unwrap(),
      ServerCandidateRemoval::Removed
    );
  }

  #[test]
  fn client_rejection_is_terminal_and_server_finish_accessors_are_exact() {
    let (mut client, mut server) = pair(60);
    let attempt = ClientAttemptId(6);
    let candidate = CandidateId::new(7);
    let hello = client.start_attempt(attempt).unwrap().into_payload();
    let server_hello = success(
      server
        .prepare_server_hello(candidate, attempt, hello)
        .unwrap(),
    )
    .into_payload();
    success(
      client
        .authenticate_server_hello(attempt, server_hello)
        .unwrap(),
    );
    let finish = client
      .prepare_client_finish(attempt)
      .unwrap()
      .into_payload();
    let authenticated = success(
      server
        .authenticate_client_finish(candidate, attempt, finish)
        .unwrap(),
    );
    server
      .commit_session(candidate, attempt, authenticated.metadata())
      .unwrap();
    let prepared = server
      .prepare_server_finish(candidate, attempt, authenticated.metadata().session_id)
      .unwrap();
    assert_eq!(prepared.candidate_id(), candidate);
    assert_eq!(prepared.client_attempt_id(), attempt);
    assert_eq!(prepared.session_id(), SessionId(60));
    let _ = prepared.payload();
    let server_finish = prepared.into_payload();

    let client_event = success(
      client
        .authenticate_server_finish(attempt, server_finish)
        .unwrap(),
    );
    assert_eq!(client_event.attempt_id(), attempt);
    assert_eq!(
      client.reject_authenticated_session(attempt).unwrap(),
      ClientContextRemoval::Removed
    );
    assert_eq!(client.phase(), ClientCryptoPhase::Closed);
  }

  #[test]
  fn maximum_session_id_is_issued_once_without_wrapping() {
    let (mut first_client, mut server) = pair(u64::MAX);
    let attempt = ClientAttemptId(1);
    let candidate = CandidateId::new(1);
    let hello = first_client.start_attempt(attempt).unwrap().into_payload();
    let server_hello = success(
      server
        .prepare_server_hello(candidate, attempt, hello)
        .unwrap(),
    )
    .into_payload();
    success(
      first_client
        .authenticate_server_hello(attempt, server_hello)
        .unwrap(),
    );
    let finish = first_client
      .prepare_client_finish(attempt)
      .unwrap()
      .into_payload();
    let event = success(
      server
        .authenticate_client_finish(candidate, attempt, finish)
        .unwrap(),
    );
    assert_eq!(event.metadata().session_id, SessionId(u64::MAX));
    server
      .reject_authenticated_candidate(candidate, attempt)
      .unwrap();

    let (mut next_client, _) = pair(1);
    let next_attempt = ClientAttemptId(2);
    let next_candidate = CandidateId::new(2);
    let next_hello = next_client
      .start_attempt(next_attempt)
      .unwrap()
      .into_payload();
    let next_server_hello = success(
      server
        .prepare_server_hello(next_candidate, next_attempt, next_hello)
        .unwrap(),
    )
    .into_payload();
    success(
      next_client
        .authenticate_server_hello(next_attempt, next_server_hello)
        .unwrap(),
    );
    let next_finish = next_client
      .prepare_client_finish(next_attempt)
      .unwrap()
      .into_payload();
    assert_eq!(
      server.authenticate_client_finish(next_candidate, next_attempt, next_finish),
      Err(CryptoStateError::SessionIdExhausted)
    );
    assert!(server.pending.contains_key(&next_candidate));
  }

  #[test]
  fn credential_debug_is_redacted() {
    assert_eq!(format!("{:?}", credential(42)), "FakeCredential(REDACTED)");
  }
}
