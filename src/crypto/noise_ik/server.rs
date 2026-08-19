use super::types::NoiseIkPayload;
use crate::crypto::noise_ik::profile::{
  Profile, CLIENT_FINISH_PAYLOAD_LENGTH, CLIENT_HELLO_PAYLOAD_LENGTH, NOISE_PROTOCOL_NAME,
  SERVER_FINISH_PAYLOAD_LENGTH, SERVER_HELLO_PAYLOAD_LENGTH,
};
use crate::crypto::server::{ServerCryptoStatus, ServerHandshakeCrypto};
use crate::crypto::types::{
  AuthenticatedClientFinish, AuthenticationFailure, AuthenticationFailureReason, CryptoOperation,
  CryptoOutcome, CryptoShutdownOutcome, CryptoStateError, PreparedServerFinish,
  PreparedServerHello, ServerCandidateRemoval, ServerCryptoOperation, ServerCryptoPhase,
};
use crate::protocol::types::MessageType;
use crate::session::types::{ClientAttemptId, EstablishedSessionMetadata, PeerIdentity, SessionId};
use crate::session::CandidateId;
use snow::StatelessTransportState;
use std::collections::HashMap;

enum CandidateContext {
  Pending {
    attempt: ClientAttemptId,
    transport: StatelessTransportState,
    hash: [u8; 32],
    identity: PeerIdentity,
    client_hello: Box<[u8]>,
    server_hello: Box<[u8]>,
    client_finish: Option<Box<[u8]>>,
    server_finish: Option<Box<[u8]>>,
    metadata: EstablishedSessionMetadata,
  },
  Established {
    attempt: ClientAttemptId,
    transport: StatelessTransportState,
    metadata: EstablishedSessionMetadata,
    server_finish: Box<[u8]>,
  },
}

pub(crate) struct ServerProvider {
  phase: ServerCryptoPhase,
  local_private_key: Box<[u8]>,
  allowed_client_keys: Vec<Box<[u8]>>,
  candidates: HashMap<CandidateId, CandidateContext>,
  pending_commit: Option<CandidateId>,
  established: Option<(CandidateId, CandidateContext)>,
}
impl ServerProvider {
  pub(crate) fn new(local_private_key: Box<[u8]>, allowed_client_keys: Vec<Box<[u8]>>) -> Self {
    Self {
      phase: ServerCryptoPhase::Running,
      local_private_key,
      allowed_client_keys,
      candidates: HashMap::new(),
      pending_commit: None,
      established: None,
    }
  }
  fn fail(op: ServerCryptoOperation) -> CryptoStateError {
    CryptoStateError::NoiseIkServerFailure { operation: op }
  }
  fn sid(hash: &[u8; 32]) -> SessionId {
    let mut b = [0; 8];
    b.copy_from_slice(&hash[..8]);
    SessionId(*hash)
  }
  fn identity(key: &[u8]) -> PeerIdentity {
    let mut identity = [0_u8; 32];
    let length = key.len().min(identity.len());
    identity[..length].copy_from_slice(&key[..length]);
    PeerIdentity(identity)
  }
  fn failure<T>(
    candidate: CandidateId,
    attempt: ClientAttemptId,
    reason: AuthenticationFailureReason,
  ) -> CryptoOutcome<T> {
    CryptoOutcome::RemoteFailure(AuthenticationFailure::ServerCandidate {
      candidate_id: candidate,
      client_attempt_id: attempt,
      reason,
    })
  }
  fn candidate_attempt(&self, candidate: CandidateId) -> Option<ClientAttemptId> {
    self.candidates.get(&candidate).map(|c| match c {
      CandidateContext::Pending { attempt, .. } | CandidateContext::Established { attempt, .. } => {
        *attempt
      }
    })
  }
  fn check(
    &self,
    op: ServerCryptoOperation,
    candidate: CandidateId,
    attempt: ClientAttemptId,
  ) -> Result<(), CryptoStateError> {
    if self.phase == ServerCryptoPhase::Closed {
      return Err(CryptoStateError::Closed {
        operation: CryptoOperation::Server(op),
      });
    }
    if let Some(expected) = self.candidate_attempt(candidate)
      && expected != attempt
    {
      return Err(CryptoStateError::AttemptIdMismatch {
        expected,
        observed: attempt,
      });
    }
    Ok(())
  }
}
impl ServerHandshakeCrypto for ServerProvider {
  type ClientHelloPayload = NoiseIkPayload;
  type ServerHelloPayload = NoiseIkPayload;
  type ClientFinishPayload = NoiseIkPayload;
  type ServerFinishPayload = NoiseIkPayload;
  fn phase(&self) -> ServerCryptoPhase {
    self.phase
  }
  fn non_secret_status(&self) -> ServerCryptoStatus {
    ServerCryptoStatus::new(
      self.phase,
      self.candidates.len(),
      self.pending_commit.is_some(),
      self.established.is_some(),
    )
  }
  fn prepare_server_hello(
    &mut self,
    candidate: CandidateId,
    attempt: ClientAttemptId,
    payload: NoiseIkPayload,
  ) -> Result<CryptoOutcome<PreparedServerHello<NoiseIkPayload>>, CryptoStateError> {
    let op = ServerCryptoOperation::PrepareServerHello;
    self.check(op, candidate, attempt)?;
    if self.phase != ServerCryptoPhase::Running {
      return Err(CryptoStateError::InvalidServerState {
        operation: op,
        phase: self.phase,
      });
    }
    if let Some(existing) = self.candidates.get(&candidate) {
      let CandidateContext::Pending {
        attempt: expected,
        client_hello,
        server_hello,
        ..
      } = existing
      else {
        return Err(Self::fail(op));
      };
      if *expected != attempt {
        return Err(CryptoStateError::AttemptIdMismatch {
          expected: *expected,
          observed: attempt,
        });
      }
      if client_hello.as_ref() == payload.0.as_ref() {
        return Ok(CryptoOutcome::Success(PreparedServerHello::new(
          candidate,
          attempt,
          NoiseIkPayload(server_hello.clone()),
        )));
      }
      return Ok(Self::failure(
        candidate,
        attempt,
        AuthenticationFailureReason::TranscriptMismatch,
      ));
    }
    if payload.0.len() != CLIENT_HELLO_PAYLOAD_LENGTH {
      return Err(Self::fail(op));
    }
    let params = NOISE_PROTOCOL_NAME.parse().map_err(|_| Self::fail(op))?;
    let pro = Profile::build_prologue(attempt).map_err(|_| Self::fail(op))?;
    let mut state = snow::Builder::new(params)
      .local_private_key(&self.local_private_key)
      .map_err(|_| Self::fail(op))?
      .prologue(&pro)
      .map_err(|_| Self::fail(op))?
      .build_responder()
      .map_err(|_| Self::fail(op))?;
    let mut plain = [0; CLIENT_HELLO_PAYLOAD_LENGTH];
    let n = state
      .read_message(&payload.0, &mut plain)
      .map_err(|_| Self::fail(op))?;
    if n != 16 || Profile::validate_control(&plain[..n], MessageType::ClientHello, attempt).is_err()
    {
      return Ok(Self::failure(
        candidate,
        attempt,
        AuthenticationFailureReason::InvalidProof,
      ));
    }
    let Some(remote) = state.get_remote_static() else {
      return Ok(Self::failure(
        candidate,
        attempt,
        AuthenticationFailureReason::IdentityMismatch,
      ));
    };
    if !self
      .allowed_client_keys
      .iter()
      .any(|key| key.as_ref() == remote)
    {
      return Ok(Self::failure(
        candidate,
        attempt,
        AuthenticationFailureReason::IdentityMismatch,
      ));
    }
    let identity = Self::identity(remote);
    let c =
      Profile::encode_control(MessageType::ServerHello, attempt).map_err(|_| Self::fail(op))?;
    let mut out = [0; SERVER_HELLO_PAYLOAD_LENGTH];
    let n = state
      .write_message(&c, &mut out)
      .map_err(|_| Self::fail(op))?;
    if n != out.len() {
      return Err(Self::fail(op));
    }
    let Ok(hash) = <[u8; 32]>::try_from(state.get_handshake_hash()) else {
      return Err(Self::fail(op));
    };

    let transport = state
      .into_stateless_transport_mode()
      .map_err(|_| Self::fail(op))?;
    let metadata = EstablishedSessionMetadata {
      session_id: Self::sid(&hash),
      peer_identity: identity,
    };
    let server_hello: Box<[u8]> = out.into();
    self.candidates.insert(
      candidate,
      CandidateContext::Pending {
        attempt,
        transport,
        hash,
        identity,
        client_hello: payload.0,
        server_hello: server_hello.clone(),
        client_finish: None,
        server_finish: None,
        metadata,
      },
    );
    Ok(CryptoOutcome::Success(PreparedServerHello::new(
      candidate,
      attempt,
      NoiseIkPayload(server_hello),
    )))
  }
  fn authenticate_client_finish(
    &mut self,
    candidate: CandidateId,
    attempt: ClientAttemptId,
    payload: NoiseIkPayload,
  ) -> Result<CryptoOutcome<AuthenticatedClientFinish>, CryptoStateError> {
    let op = ServerCryptoOperation::AuthenticateClientFinish;
    self.check(op, candidate, attempt)?;
    let Some(ctx) = self.candidates.get_mut(&candidate) else {
      return Err(CryptoStateError::MissingServerCandidateContext {
        candidate_id: candidate,
        client_attempt_id: attempt,
      });
    };
    let CandidateContext::Pending {
      attempt: expected,
      transport,
      hash: _,
      identity: _,
      client_finish,
      server_finish,
      metadata,
      ..
    } = ctx
    else {
      return Err(CryptoStateError::InvalidServerState {
        operation: op,
        phase: self.phase,
      });
    };
    if *expected != attempt {
      return Err(CryptoStateError::AttemptIdMismatch {
        expected: *expected,
        observed: attempt,
      });
    }
    if let Some(cached) = client_finish {
      if cached.as_ref() == payload.0.as_ref() {
        return Ok(CryptoOutcome::Success(AuthenticatedClientFinish::new(
          candidate, attempt, *metadata,
        )));
      }
      return Ok(Self::failure(
        candidate,
        attempt,
        AuthenticationFailureReason::TranscriptMismatch,
      ));
    }
    if payload.0.len() != CLIENT_FINISH_PAYLOAD_LENGTH {
      return Err(Self::fail(op));
    }
    let mut plain = [0; CLIENT_FINISH_PAYLOAD_LENGTH];
    let n = transport
      .read_message(0, &payload.0, &mut plain)
      .map_err(|_| Self::fail(op))?;
    if n != 16
      || Profile::validate_control(&plain[..n], MessageType::ClientFinish, attempt).is_err()
    {
      return Ok(Self::failure(
        candidate,
        attempt,
        AuthenticationFailureReason::InvalidConfirmation,
      ));
    }
    let c =
      Profile::encode_control(MessageType::ServerFinish, attempt).map_err(|_| Self::fail(op))?;
    let mut out = [0; SERVER_FINISH_PAYLOAD_LENGTH];
    let n = transport
      .write_message(0, &c, &mut out)
      .map_err(|_| Self::fail(op))?;
    if n != out.len() {
      return Err(Self::fail(op));
    }
    *client_finish = Some(payload.0);
    *server_finish = Some(out.into());
    self.pending_commit = Some(candidate);
    self.phase = ServerCryptoPhase::AuthenticatedPendingCommit;
    Ok(CryptoOutcome::Success(AuthenticatedClientFinish::new(
      candidate, attempt, *metadata,
    )))
  }
  fn commit_session(
    &mut self,
    candidate: CandidateId,
    attempt: ClientAttemptId,
    metadata: EstablishedSessionMetadata,
  ) -> Result<(), CryptoStateError> {
    if self.phase != ServerCryptoPhase::AuthenticatedPendingCommit {
      return Err(CryptoStateError::InvalidServerState {
        operation: ServerCryptoOperation::CommitSession,
        phase: self.phase,
      });
    }
    if self.pending_commit != Some(candidate) {
      return Err(CryptoStateError::CandidateIdMismatch {
        expected: candidate,
        observed: candidate,
      });
    }
    let Some(ctx) = self.candidates.remove(&candidate) else {
      return Err(Self::fail(ServerCryptoOperation::CommitSession));
    };
    let CandidateContext::Pending {
      attempt: expected,
      transport,
      metadata: stored,
      server_finish: Some(finish),
      ..
    } = ctx
    else {
      return Err(Self::fail(ServerCryptoOperation::CommitSession));
    };
    if expected != attempt {
      return Err(CryptoStateError::AttemptIdMismatch {
        expected,
        observed: attempt,
      });
    }
    if stored != metadata {
      return Err(CryptoStateError::AuthenticatedMetadataMismatch);
    }
    self.candidates.clear();
    self.established = Some((
      candidate,
      CandidateContext::Established {
        attempt,
        transport,
        metadata,
        server_finish: finish,
      },
    ));
    self.pending_commit = None;
    self.phase = ServerCryptoPhase::Established;
    Ok(())
  }
  fn reject_authenticated_candidate(
    &mut self,
    candidate: CandidateId,
    attempt: ClientAttemptId,
  ) -> Result<ServerCandidateRemoval, CryptoStateError> {
    if self.phase == ServerCryptoPhase::Closed {
      return Ok(ServerCandidateRemoval::AlreadyAbsent);
    }
    self.check(
      ServerCryptoOperation::RejectAuthenticatedCandidate,
      candidate,
      attempt,
    )?;
    if self.pending_commit != Some(candidate) {
      return Err(CryptoStateError::InvalidServerState {
        operation: ServerCryptoOperation::RejectAuthenticatedCandidate,
        phase: self.phase,
      });
    }
    self.candidates.remove(&candidate);
    self.pending_commit = None;
    self.phase = ServerCryptoPhase::Running;
    Ok(ServerCandidateRemoval::Removed)
  }
  fn prepare_server_finish(
    &self,
    candidate: CandidateId,
    attempt: ClientAttemptId,
    session_id: SessionId,
  ) -> Result<PreparedServerFinish<NoiseIkPayload>, CryptoStateError> {
    let Some((
      expected_candidate,
      CandidateContext::Established {
        attempt: expected_attempt,
        metadata,
        server_finish,
        ..
      },
    )) = self.established.as_ref()
    else {
      return Err(CryptoStateError::InvalidServerState {
        operation: ServerCryptoOperation::PrepareServerFinish,
        phase: self.phase,
      });
    };
    if *expected_candidate != candidate {
      return Err(CryptoStateError::CandidateIdMismatch {
        expected: *expected_candidate,
        observed: candidate,
      });
    }
    if *expected_attempt != attempt {
      return Err(CryptoStateError::AttemptIdMismatch {
        expected: *expected_attempt,
        observed: attempt,
      });
    }
    if metadata.session_id != session_id {
      return Err(CryptoStateError::SessionIdMismatch {
        expected: metadata.session_id,
        observed: session_id,
      });
    }
    Ok(PreparedServerFinish::new(
      candidate,
      attempt,
      session_id,
      NoiseIkPayload(server_finish.clone()),
    ))
  }
  fn remove_candidate(
    &mut self,
    candidate: CandidateId,
    attempt: ClientAttemptId,
  ) -> Result<ServerCandidateRemoval, CryptoStateError> {
    if self.phase == ServerCryptoPhase::Closed {
      return Ok(ServerCandidateRemoval::AlreadyAbsent);
    }
    self.check(ServerCryptoOperation::RemoveCandidate, candidate, attempt)?;
    if self.candidates.remove(&candidate).is_none() {
      return Ok(ServerCandidateRemoval::AlreadyAbsent);
    }
    if self.pending_commit == Some(candidate) {
      self.pending_commit = None;
      self.phase = ServerCryptoPhase::Running;
    }
    Ok(ServerCandidateRemoval::Removed)
  }
  fn shutdown(&mut self) -> CryptoShutdownOutcome {
    let p = self.phase;
    if p == ServerCryptoPhase::Closed {
      return CryptoShutdownOutcome {
        already_closed: true,
        ..Default::default()
      };
    }
    self.candidates.clear();
    self.pending_commit = None;
    self.established = None;
    self.phase = ServerCryptoPhase::Closed;
    CryptoShutdownOutcome {
      removed_pending_contexts: usize::from(p == ServerCryptoPhase::Running),
      removed_pending_commit: p == ServerCryptoPhase::AuthenticatedPendingCommit,
      removed_established_context: p == ServerCryptoPhase::Established,
      already_closed: false,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::crypto::client::ClientHandshakeCrypto;
  use crate::crypto::server::ServerHandshakeCrypto;
  use crate::crypto::types::ClientCryptoPhase;
  use snow::params::NoiseParams;
  use snow::Builder;

  #[test]
  fn completes_noise_ik_confirmation_flow() {
    let params: NoiseParams = NOISE_PROTOCOL_NAME.parse().unwrap();
    let client_keys = Builder::new(params.clone()).generate_keypair().unwrap();
    let server_keys = Builder::new(params).generate_keypair().unwrap();
    let mut client = crate::crypto::noise_ik::client::ClientProvider::new(
      client_keys.private.clone().into(),
      server_keys.public.into(),
    );
    let mut server = ServerProvider::new(
      server_keys.private.into(),
      vec![client_keys.public.clone().into()],
    );
    let candidate = CandidateId::new(7);
    let attempt = ClientAttemptId(9);

    let hello = client.start_attempt(attempt).unwrap();
    let server_hello = match server
      .prepare_server_hello(candidate, attempt, hello.into_payload())
      .unwrap()
    {
      CryptoOutcome::Success(value) => value,
      CryptoOutcome::RemoteFailure(_) => panic!("server rejected valid client hello"),
    };
    let hello_auth = client
      .authenticate_server_hello(attempt, server_hello.into_payload())
      .unwrap();
    assert!(
      matches!(hello_auth, CryptoOutcome::Success(_)),
      "hello auth: {hello_auth:?}"
    );
    let finish = client.prepare_client_finish(attempt).unwrap();
    let server_auth = match server
      .authenticate_client_finish(candidate, attempt, finish.into_payload())
      .unwrap()
    {
      CryptoOutcome::Success(value) => value,
      CryptoOutcome::RemoteFailure(_) => panic!("server rejected valid client finish"),
    };
    server
      .commit_session(candidate, attempt, server_auth.metadata())
      .unwrap();
    let server_finish = server
      .prepare_server_finish(candidate, attempt, server_auth.metadata().session_id)
      .unwrap();
    let client_auth = match client
      .authenticate_server_finish(attempt, server_finish.into_payload())
      .unwrap()
    {
      CryptoOutcome::Success(value) => value,
      CryptoOutcome::RemoteFailure(_) => panic!("client rejected valid server finish"),
    };
    client
      .commit_session(attempt, client_auth.metadata())
      .unwrap();
    assert_eq!(client.phase(), ClientCryptoPhase::Established);
    assert_eq!(server.phase(), ServerCryptoPhase::Established);
  }
}
