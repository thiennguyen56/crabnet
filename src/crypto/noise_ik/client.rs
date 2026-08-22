use crate::crypto::client::ClientHandshakeCrypto;
use crate::crypto::noise_ik::profile::{
  Profile, CLIENT_FINISH_PAYLOAD_LENGTH, CLIENT_HELLO_PAYLOAD_LENGTH, NOISE_PROTOCOL_NAME,
  SERVER_FINISH_PAYLOAD_LENGTH, SERVER_HELLO_PAYLOAD_LENGTH,
};
use crate::crypto::noise_ik::types::NoiseIkPayload;
use crate::crypto::types::{
  AuthenticatedServerFinish, AuthenticatedServerHello, AuthenticationFailure,
  AuthenticationFailureReason, ClientContextRemoval, ClientCryptoOperation, ClientCryptoPhase,
  CryptoOperation, CryptoOutcome, CryptoShutdownOutcome, CryptoStateError, PreparedClientFinish,
  PreparedClientHello,
};
use crate::protocol::types::MessageType;
use crate::session::types::{ClientAttemptId, EstablishedSessionMetadata, PeerIdentity, SessionId};
use snow::{HandshakeState, StatelessTransportState};
enum Context {
  Hello {
    id: ClientAttemptId,
    state: Box<HandshakeState>,
    hello: Box<[u8]>,
  },
  Finish {
    id: ClientAttemptId,
    transport: StatelessTransportState,
    hash: [u8; 32],
    identity: PeerIdentity,
    client_finish: Box<[u8]>,
  },
  Pending {
    id: ClientAttemptId,
    transport: StatelessTransportState,
    metadata: EstablishedSessionMetadata,
    client_finish: Box<[u8]>,
    server_finish: Box<[u8]>,
  },
  Established {
    id: ClientAttemptId,
    transport: StatelessTransportState,
    metadata: EstablishedSessionMetadata,
  },
}
pub(crate) struct ClientProvider {
  phase: ClientCryptoPhase,
  local_private_key: Box<[u8]>,
  pinned_server_static_public: Box<[u8]>,
  context: Option<Context>,
}
impl ClientProvider {
  pub(crate) fn new(local_private_key: Box<[u8]>, pinned_server_static_public: Box<[u8]>) -> Self {
    Self {
      phase: ClientCryptoPhase::Idle,
      local_private_key,
      pinned_server_static_public,
      context: None,
    }
  }
  pub(crate) fn into_established_transport(
    self,
  ) -> Option<(StatelessTransportState, EstablishedSessionMetadata)> {
    match self.context {
      Some(Context::Established {
        transport,
        metadata,
        ..
      }) if self.phase == ClientCryptoPhase::Established => Some((transport, metadata)),
      _ => None,
    }
  }

  fn fail(op: ClientCryptoOperation) -> CryptoStateError {
    CryptoStateError::NoiseIkFailure { operation: op }
  }
  fn id(&self) -> Option<ClientAttemptId> {
    match self.context.as_ref() {
      Some(Context::Hello { id, .. })
      | Some(Context::Finish { id, .. })
      | Some(Context::Pending { id, .. })
      | Some(Context::Established { id, .. }) => Some(*id),
      None => None,
    }
  }
  fn check(&self, op: ClientCryptoOperation, id: ClientAttemptId) -> Result<(), CryptoStateError> {
    if let Some(expected) = self.id()
      && expected != id
    {
      return Err(CryptoStateError::AttemptIdMismatch {
        expected,
        observed: id,
      });
    }
    if self.phase == ClientCryptoPhase::Closed {
      return Err(CryptoStateError::Closed {
        operation: CryptoOperation::Client(op),
      });
    }
    Ok(())
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
  fn hello_failure(
    id: ClientAttemptId,
    reason: AuthenticationFailureReason,
  ) -> CryptoOutcome<AuthenticatedServerHello> {
    CryptoOutcome::RemoteFailure(AuthenticationFailure::ClientAttempt {
      attempt_id: id,
      reason,
    })
  }
  fn finish_failure(
    id: ClientAttemptId,
    reason: AuthenticationFailureReason,
  ) -> CryptoOutcome<AuthenticatedServerFinish> {
    CryptoOutcome::RemoteFailure(AuthenticationFailure::ClientAttempt {
      attempt_id: id,
      reason,
    })
  }
}
impl ClientHandshakeCrypto for ClientProvider {
  type ClientHelloPayload = NoiseIkPayload;
  type ServerHelloPayload = NoiseIkPayload;
  type ClientFinishPayload = NoiseIkPayload;
  type ServerFinishPayload = NoiseIkPayload;
  fn phase(&self) -> ClientCryptoPhase {
    self.phase
  }
  fn start_attempt(
    &mut self,
    id: ClientAttemptId,
  ) -> Result<PreparedClientHello<NoiseIkPayload>, CryptoStateError> {
    let op = ClientCryptoOperation::StartAttempt;
    if self.phase == ClientCryptoPhase::Closed {
      return Err(CryptoStateError::Closed {
        operation: CryptoOperation::Client(op),
      });
    }
    if self.phase != ClientCryptoPhase::Idle {
      return Err(CryptoStateError::InvalidClientState {
        operation: op,
        phase: self.phase,
      });
    }
    let p = NOISE_PROTOCOL_NAME.parse().map_err(|_| Self::fail(op))?;
    let pro = Profile::build_prologue(id).map_err(|_| Self::fail(op))?;
    let mut state = snow::Builder::new(p)
      .local_private_key(&self.local_private_key)
      .map_err(|_| Self::fail(op))?
      .remote_public_key(&self.pinned_server_static_public)
      .map_err(|_| Self::fail(op))?
      .prologue(&pro)
      .map_err(|_| Self::fail(op))?
      .build_initiator()
      .map_err(|_| Self::fail(op))?;
    let c = Profile::encode_control(MessageType::ClientHello, id).map_err(|_| Self::fail(op))?;
    let mut out = [0; CLIENT_HELLO_PAYLOAD_LENGTH];
    let n = state
      .write_message(&c, &mut out)
      .map_err(|_| Self::fail(op))?;
    if n != out.len() {
      return Err(Self::fail(op));
    }
    let hello: Box<[u8]> = out.into();
    self.context = Some(Context::Hello {
      id,
      state: Box::new(state),
      hello: hello.clone(),
    });
    self.phase = ClientCryptoPhase::AwaitingServerHello;
    Ok(PreparedClientHello::new(id, NoiseIkPayload(hello)))
  }
  fn authenticate_server_hello(
    &mut self,
    id: ClientAttemptId,
    payload: NoiseIkPayload,
  ) -> Result<CryptoOutcome<AuthenticatedServerHello>, CryptoStateError> {
    let op = ClientCryptoOperation::AuthenticateServerHello;
    self.check(op, id)?;
    if self.phase != ClientCryptoPhase::AwaitingServerHello {
      return Err(CryptoStateError::InvalidClientState {
        operation: op,
        phase: self.phase,
      });
    }
    if payload.0.len() != SERVER_HELLO_PAYLOAD_LENGTH {
      return Err(Self::fail(op));
    }
    let Some(Context::Hello {
      id: ctx_id,
      mut state,
      hello,
    }) = self.context.take()
    else {
      return Err(Self::fail(op));
    };
    let mut plain = [0; SERVER_HELLO_PAYLOAD_LENGTH];
    let valid = state
      .read_message(&payload.0, &mut plain)
      .ok()
      .and_then(|n| (n == 16).then_some(()))
      .and_then(|_| Profile::validate_control(&plain[..16], MessageType::ServerHello, id).ok());
    let Some(()) = valid else {
      self.context = Some(Context::Hello {
        id: ctx_id,
        state,
        hello,
      });
      return Ok(Self::hello_failure(
        id,
        AuthenticationFailureReason::InvalidProof,
      ));
    };
    let Some(remote) = state.get_remote_static() else {
      self.context = Some(Context::Hello {
        id: ctx_id,
        state,
        hello,
      });
      return Ok(Self::hello_failure(
        id,
        AuthenticationFailureReason::IdentityMismatch,
      ));
    };
    if remote != self.pinned_server_static_public.as_ref() {
      self.context = Some(Context::Hello {
        id: ctx_id,
        state,
        hello,
      });
      return Ok(Self::hello_failure(
        id,
        AuthenticationFailureReason::IdentityMismatch,
      ));
    }
    let server_identity = Self::identity(remote);
    let Ok(hash) = <[u8; 32]>::try_from(state.get_handshake_hash()) else {
      return Err(Self::fail(op));
    };
    let transport = (*state)
      .into_stateless_transport_mode()
      .map_err(|_| Self::fail(op))?;
    let c = Profile::encode_control(MessageType::ClientFinish, id).map_err(|_| Self::fail(op))?;
    let mut out = [0; CLIENT_FINISH_PAYLOAD_LENGTH];
    let n = transport
      .write_message(0, &c, &mut out)
      .map_err(|_| Self::fail(op))?;
    if n != out.len() {
      return Err(Self::fail(op));
    }
    self.context = Some(Context::Finish {
      id,
      transport,
      hash,
      identity: server_identity,
      client_finish: out.into(),
    });
    self.phase = ClientCryptoPhase::AwaitingServerFinish;
    Ok(CryptoOutcome::Success(AuthenticatedServerHello::new(id)))
  }
  fn prepare_client_finish(
    &self,
    id: ClientAttemptId,
  ) -> Result<PreparedClientFinish<NoiseIkPayload>, CryptoStateError> {
    self.check(ClientCryptoOperation::PrepareClientFinish, id)?;
    let Some(Context::Finish { client_finish, .. }) = self.context.as_ref() else {
      return Err(CryptoStateError::InvalidClientState {
        operation: ClientCryptoOperation::PrepareClientFinish,
        phase: self.phase,
      });
    };
    Ok(PreparedClientFinish::new(
      id,
      NoiseIkPayload(client_finish.clone()),
    ))
  }
  fn authenticate_server_finish(
    &mut self,
    id: ClientAttemptId,
    payload: NoiseIkPayload,
  ) -> Result<CryptoOutcome<AuthenticatedServerFinish>, CryptoStateError> {
    let op = ClientCryptoOperation::AuthenticateServerFinish;
    self.check(op, id)?;
    if self.phase != ClientCryptoPhase::AwaitingServerFinish {
      return Err(CryptoStateError::InvalidClientState {
        operation: op,
        phase: self.phase,
      });
    }
    if payload.0.len() != SERVER_FINISH_PAYLOAD_LENGTH {
      return Err(Self::fail(op));
    }
    let Some(Context::Finish {
      id: ctx_id,
      transport,
      hash,
      identity,
      client_finish,
    }) = self.context.take()
    else {
      return Err(Self::fail(op));
    };
    let mut plain = [0; SERVER_FINISH_PAYLOAD_LENGTH];
    let valid = transport
      .read_message(0, &payload.0, &mut plain)
      .ok()
      .and_then(|n| (n == 16).then_some(()))
      .and_then(|_| Profile::validate_control(&plain[..16], MessageType::ServerFinish, id).ok());
    if valid.is_none() {
      self.context = Some(Context::Finish {
        id: ctx_id,
        transport,
        hash,
        identity,
        client_finish,
      });
      return Ok(Self::finish_failure(
        id,
        AuthenticationFailureReason::InvalidConfirmation,
      ));
    }
    let metadata = EstablishedSessionMetadata {
      session_id: Self::sid(&hash),
      peer_identity: identity,
    };
    self.context = Some(Context::Pending {
      id,
      transport,
      metadata,
      client_finish,
      server_finish: payload.0,
    });
    self.phase = ClientCryptoPhase::AuthenticatedPendingCommit;
    Ok(CryptoOutcome::Success(AuthenticatedServerFinish::new(
      id, metadata,
    )))
  }
  fn commit_session(
    &mut self,
    id: ClientAttemptId,
    metadata: EstablishedSessionMetadata,
  ) -> Result<(), CryptoStateError> {
    self.check(ClientCryptoOperation::CommitSession, id)?;
    let Some(Context::Pending {
      transport,
      metadata: expected,
      ..
    }) = self.context.take()
    else {
      return Err(CryptoStateError::InvalidClientState {
        operation: ClientCryptoOperation::CommitSession,
        phase: self.phase,
      });
    };
    if expected != metadata {
      return Err(CryptoStateError::AuthenticatedMetadataMismatch);
    }
    self.context = Some(Context::Established {
      id,
      transport,
      metadata,
    });
    self.phase = ClientCryptoPhase::Established;
    Ok(())
  }
  fn reject_authenticated_session(
    &mut self,
    id: ClientAttemptId,
  ) -> Result<ClientContextRemoval, CryptoStateError> {
    if self.phase == ClientCryptoPhase::Closed {
      return Ok(ClientContextRemoval::AlreadyAbsent);
    }
    self.check(ClientCryptoOperation::RejectAuthenticatedSession, id)?;
    if self.phase != ClientCryptoPhase::AuthenticatedPendingCommit {
      return Err(CryptoStateError::InvalidClientState {
        operation: ClientCryptoOperation::RejectAuthenticatedSession,
        phase: self.phase,
      });
    }
    self.context = None;
    self.phase = ClientCryptoPhase::Closed;
    Ok(ClientContextRemoval::Removed)
  }
  fn close_context(
    &mut self,
    id: ClientAttemptId,
  ) -> Result<ClientContextRemoval, CryptoStateError> {
    if matches!(
      self.phase,
      ClientCryptoPhase::Idle | ClientCryptoPhase::Closed
    ) {
      return Ok(ClientContextRemoval::AlreadyAbsent);
    }
    self.check(ClientCryptoOperation::RejectAuthenticatedSession, id)?;
    self.context = None;
    self.phase = ClientCryptoPhase::Closed;
    Ok(ClientContextRemoval::Removed)
  }
  fn shutdown(&mut self) -> CryptoShutdownOutcome {
    let p = self.phase;
    if p == ClientCryptoPhase::Closed {
      return CryptoShutdownOutcome {
        already_closed: true,
        ..Default::default()
      };
    }
    self.context = None;
    self.phase = ClientCryptoPhase::Closed;
    CryptoShutdownOutcome {
      removed_pending_contexts: usize::from(matches!(
        p,
        ClientCryptoPhase::AwaitingServerHello | ClientCryptoPhase::AwaitingServerFinish
      )),
      removed_pending_commit: p == ClientCryptoPhase::AuthenticatedPendingCommit,
      removed_established_context: p == ClientCryptoPhase::Established,
      already_closed: false,
    }
  }
}
