use crate::session::{
  server::ServerOperation::ApplyValidClientHello,
  types::{ClientAttemptId, EstablishedSessionMetadata, SessionId},
  AdmissionOutcome::{self, Added, AlreadyPending, AtCapacity},
  CandidateId, CandidateRemoval, SessionManager, SessionManagerError, SessionPolicy,
};
use std::{collections::HashMap, net::SocketAddr, time::Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ServerCandidate {
  candidate_id: CandidateId,
  source: SocketAddr,
  client_attempt_id: ClientAttemptId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EstablishedServerSession {
  metadata: EstablishedSessionMetadata,
  peer_endpoint: SocketAddr,
  completed_candidate_id: CandidateId,
  client_attempt_id: ClientAttemptId,
  established_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerHandshakeState {
  Listening,
  Established { session: EstablishedServerSession },
  Closed,
}

pub(crate) struct ServerHandshake {
  pending: SessionManager,
  candidate_by_id: HashMap<CandidateId, ServerCandidate>,
  state: ServerHandshakeState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerInboundKind {
  ClientHello,
  ClientFinish,
  Data,
  OtherHandshake,
}

pub(crate) enum ServerEffect {
  SendServerHello {
    destination: SocketAddr,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
  },
  SendServerFinish {
    destination: SocketAddr,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    session_id: SessionId,
  },
  SessionEstablished {
    source: SocketAddr,
    session_id: SessionId,
  },
  Dropped {
    source: SocketAddr,
    reason: ServerDropReason,
  },
  Closed {
    removed_candidates: usize,
    removed_session: bool,
  },
  AlreadyClosed,
}

pub(crate) struct ServerReport {
  pub(crate) expired: Vec<ExpiredServerCandidate>,
  pub(crate) effects: Vec<ServerEffect>,
}

pub(crate) struct ExpiredServerCandidate {
  pub(crate) candidate_id: CandidateId,
  pub(crate) source: SocketAddr,
  pub(crate) client_attempt_id: ClientAttemptId,
}

pub(crate) enum ServerDropReason {
  PendingCapacityReached {
    maximum_pending: usize,
  },
  NoPendingCandidate,
  StaleCandidate {
    expected: CandidateId,
    observed: CandidateId,
  },
  StaleClientAttempt {
    expected: ClientAttemptId,
    observed: ClientAttemptId,
  },
  AuthenticationFailed,
  UnexpectedMessage {
    expected: Option<ServerInboundKind>,
    observed: ServerInboundKind,
  },
  PreSessionData,
  AnotherPeerIsActive {
    active_source: SocketAddr,
  },
  SessionUnavailable,
}

pub(crate) enum ServerDataDecision {
  RejectPreSession,
  PermitEstablished {
    session_id: SessionId,
  },
  RejectUnexpectedSource {
    expected: SocketAddr,
    observed: SocketAddr,
  },
  RejectUnknownSession {
    expected: SessionId,
    observed: SessionId,
  },
  RejectClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerStateName {
  Listening,
  Established,
  Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerOperation {
  ApplyValidClientHello,
  ApplyAuthenticatedClientFinish,
  ApplyAuthenticationFailure,
  ApplyUnexpectedMessage,
  CheckTimeouts,
  Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerStateError {
  PendingManager {
    operation: ServerOperation,
    source: Option<SocketAddr>,
    error: SessionManagerError,
  },
  CandidateRegistryMissing {
    candidate_id: CandidateId,
    source: SocketAddr,
  },
  CandidateRegistryOrphaned {
    candidate_id: CandidateId,
    source: SocketAddr,
  },
  CandidateSourceMismatch {
    candidate_id: CandidateId,
    manager_source: SocketAddr,
    registry_source: SocketAddr,
  },
  CandidateRegistryCountMismatch {
    manager_count: usize,
    registry_count: usize,
  },
  PendingManagerClosedWhileListening,
  PendingCandidatesOutsideListening {
    state: ServerStateName,
    count: usize,
  },
}

impl std::fmt::Display for ServerStateError {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(formatter, "server handshake state error: {self:?}")
  }
}

impl std::error::Error for ServerStateError {}

impl ServerHandshake {
  /// Creates a listening handshake with no pending candidates or established session.
  pub(crate) fn new(policy: SessionPolicy) -> Self {
    Self {
      pending: SessionManager::new(policy),
      candidate_by_id: HashMap::new(),
      state: ServerHandshakeState::Listening,
    }
  }
  /// Returns the fieldless lifecycle state for diagnostics.
  pub(crate) fn state_name(&self) -> ServerStateName {
    match self.state {
      ServerHandshakeState::Listening => ServerStateName::Listening,
      ServerHandshakeState::Closed => ServerStateName::Closed,
      ServerHandshakeState::Established { .. } => ServerStateName::Established,
    }
  }

  /// Admits a valid hello while preserving duplicate candidate identity and deadlines.
  ///
  /// Returns symbolic effects and performs no network or cryptographic I/O.
  pub(crate) fn handle_valid_client_hello(
    &mut self,
    source: SocketAddr,
    client_attempt_id: ClientAttemptId,
    now: Instant,
  ) -> Result<ServerReport, ServerStateError> {
    let expired = self.expire_and_reconcile(now)?;
    match self.state {
      ServerHandshakeState::Closed => {
        return Ok(ServerReport {
          expired,
          effects: vec![ServerEffect::Dropped {
            source,
            reason: ServerDropReason::SessionUnavailable,
          }],
        });
      }
      ServerHandshakeState::Established { session } => {
        return Ok(ServerReport {
          expired,
          effects: vec![ServerEffect::Dropped {
            source,
            reason: ServerDropReason::AnotherPeerIsActive {
              active_source: session.peer_endpoint,
            },
          }],
        })
      }
      _ => (),
    }

    let admission = self.pending.admit(source, now).map_err(|e| {
      return ServerStateError::PendingManager {
        operation: ApplyValidClientHello,
        source: Some(source),
        error: e,
      };
    })?;

    match admission.outcome {
      Added {
        candidate_id,
        deadline: _,
      } => {
        self.candidate_by_id.insert(
          candidate_id,
          ServerCandidate {
            candidate_id,
            source,
            client_attempt_id,
          },
        );
        self.verify_candidate_maps()?;
        return Ok(ServerReport {
          expired,
          effects: vec![ServerEffect::SendServerHello {
            destination: source,
            candidate_id,
            client_attempt_id,
          }],
        });
      }
      AlreadyPending { candidate_id, .. } => {
        let binding = self.current_candidate(source)?;
        match binding {
          Some(val) => {
            if val.client_attempt_id != client_attempt_id {
              return Ok(ServerReport {
                expired,
                effects: vec![ServerEffect::Dropped {
                  source,
                  reason: ServerDropReason::StaleClientAttempt {
                    expected: val.client_attempt_id,
                    observed: client_attempt_id,
                  },
                }],
              });
            }
          }
          _ => (),
        }
        return Ok(ServerReport {
          expired,
          effects: vec![ServerEffect::SendServerHello {
            destination: source,
            candidate_id,
            client_attempt_id,
          }],
        });
      }
      AtCapacity { maximum_pending } => {
        return Ok(ServerReport {
          expired,
          effects: vec![ServerEffect::Dropped {
            source,
            reason: ServerDropReason::PendingCapacityReached { maximum_pending },
          }],
        })
      }
      AdmissionOutcome::Closed => return Err(ServerStateError::PendingManagerClosedWhileListening),
    }
  }

  /// Applies an authenticated finish for an exact pending candidate.
  ///
  /// Exact completion establishes the peer; duplicate completion only resends confirmation.
  pub(crate) fn handle_authenticated_client_finish(
    &mut self,
    source: SocketAddr,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    metadata: EstablishedSessionMetadata,
    now: Instant,
  ) -> Result<ServerReport, ServerStateError> {
    let expired = self.expire_and_reconcile(now)?;
    if self.state == ServerHandshakeState::Closed {
      return Ok(ServerReport {
        expired,
        effects: vec![ServerEffect::Dropped {
          source,
          reason: ServerDropReason::SessionUnavailable,
        }],
      });
    }
    if let ServerHandshakeState::Established { session } = self.state {
      if source == session.peer_endpoint
        && candidate_id == session.completed_candidate_id
        && client_attempt_id == session.client_attempt_id
      {
        return Ok(ServerReport {
          expired,
          effects: vec![ServerEffect::SendServerFinish {
            destination: source,
            candidate_id,
            client_attempt_id,
            session_id: session.metadata.session_id,
          }],
        });
      }

      return Ok(ServerReport {
        expired,
        effects: vec![ServerEffect::Dropped {
          source,
          reason: ServerDropReason::AnotherPeerIsActive {
            active_source: session.peer_endpoint,
          },
        }],
      });
    }

    let Some(binding) = self.current_candidate(source)? else {
      return Ok(ServerReport {
        expired,
        effects: vec![ServerEffect::Dropped {
          source,
          reason: ServerDropReason::NoPendingCandidate,
        }],
      });
    };

    if binding.candidate_id != candidate_id {
      return Ok(ServerReport {
        expired,
        effects: vec![ServerEffect::Dropped {
          source,
          reason: ServerDropReason::StaleCandidate {
            expected: binding.candidate_id,
            observed: candidate_id,
          },
        }],
      });
    }
    if binding.client_attempt_id != client_attempt_id {
      return Ok(ServerReport {
        expired,
        effects: vec![ServerEffect::Dropped {
          source,
          reason: ServerDropReason::StaleClientAttempt {
            expected: binding.client_attempt_id,
            observed: client_attempt_id,
          },
        }],
      });
    }

    let session_id = metadata.session_id;
    self.remove_exact_candidate(binding)?;
    self.pending.shutdown();
    self.candidate_by_id.clear();
    self.state = ServerHandshakeState::Established {
      session: EstablishedServerSession {
        metadata,
        peer_endpoint: source,
        completed_candidate_id: candidate_id,
        client_attempt_id,
        established_at: now,
      },
    };

    Ok(ServerReport {
      expired,
      effects: vec![
        ServerEffect::SendServerFinish {
          destination: source,
          candidate_id,
          client_attempt_id,
          session_id,
        },
        ServerEffect::SessionEstablished { source, session_id },
      ],
    })
  }

  /// Removes one candidate after an exact authentication failure.
  ///
  /// Stale callbacks are reported as drops and cannot remove another candidate.
  pub(crate) fn handle_authentication_failure(
    &mut self,
    source: SocketAddr,
    candidate_id: CandidateId,
    client_attempt_id: ClientAttemptId,
    now: Instant,
  ) -> Result<ServerReport, ServerStateError> {
    let expired = self.expire_and_reconcile(now)?;
    if self.state == ServerHandshakeState::Closed {
      return Ok(ServerReport {
        expired,
        effects: vec![ServerEffect::Dropped {
          source,
          reason: ServerDropReason::SessionUnavailable,
        }],
      });
    }
    if let ServerHandshakeState::Established { session } = self.state {
      return Ok(ServerReport {
        expired,
        effects: vec![ServerEffect::Dropped {
          source,
          reason: ServerDropReason::AnotherPeerIsActive {
            active_source: session.peer_endpoint,
          },
        }],
      });
    }
    let Some(binding) = self.current_candidate(source)? else {
      return Ok(ServerReport {
        expired,
        effects: vec![ServerEffect::Dropped {
          source,
          reason: ServerDropReason::NoPendingCandidate,
        }],
      });
    };

    if binding.candidate_id != candidate_id {
      return Ok(ServerReport {
        expired,
        effects: vec![ServerEffect::Dropped {
          source,
          reason: ServerDropReason::StaleCandidate {
            expected: binding.candidate_id,
            observed: candidate_id,
          },
        }],
      });
    }

    if binding.client_attempt_id != client_attempt_id {
      return Ok(ServerReport {
        expired,
        effects: vec![ServerEffect::Dropped {
          source,
          reason: ServerDropReason::StaleClientAttempt {
            expected: binding.client_attempt_id,
            observed: client_attempt_id,
          },
        }],
      });
    }

    self.remove_exact_candidate(binding)?;
    self.verify_candidate_maps()?;
    Ok(ServerReport {
      expired,
      effects: vec![ServerEffect::Dropped {
        source,
        reason: ServerDropReason::AuthenticationFailed,
      }],
    })
  }

  /// Classifies a structurally valid message that is invalid for the current state.
  pub(crate) fn handle_unexpected_message(
    &mut self,
    source: SocketAddr,
    observed: ServerInboundKind,
    now: Instant,
  ) -> Result<ServerReport, ServerStateError> {
    let expired = self.expire_and_reconcile(now)?;
    match self.state {
      ServerHandshakeState::Closed => {
        return Ok(ServerReport {
          expired,
          effects: vec![ServerEffect::Dropped {
            source,
            reason: ServerDropReason::SessionUnavailable,
          }],
        });
      }
      ServerHandshakeState::Listening => {
        let reason: ServerDropReason;
        if observed == ServerInboundKind::Data {
          reason = ServerDropReason::PreSessionData;
        } else if self.current_candidate(source)?.is_some() {
          reason = ServerDropReason::UnexpectedMessage {
            expected: Some(ServerInboundKind::ClientFinish),
            observed,
          };
        } else {
          reason = ServerDropReason::UnexpectedMessage {
            expected: Some(ServerInboundKind::ClientHello),
            observed,
          };
        }

        return Ok(ServerReport {
          expired,
          effects: vec![ServerEffect::Dropped { source, reason }],
        });
      }
      ServerHandshakeState::Established { session } => {
        let reason: ServerDropReason;
        if source != session.peer_endpoint {
          reason = ServerDropReason::AnotherPeerIsActive {
            active_source: session.peer_endpoint,
          };
        } else {
          reason = ServerDropReason::UnexpectedMessage {
            expected: Some(ServerInboundKind::Data),
            observed,
          };
        }
        return Ok(ServerReport {
          expired,
          effects: vec![ServerEffect::Dropped { source, reason }],
        });
      }
    }
  }

  /// Expires pending candidates at or before `now` and returns no runtime effects.
  pub(crate) fn check_timeouts(&mut self, now: Instant) -> Result<ServerReport, ServerStateError> {
    Ok(ServerReport {
      expired: self.expire_and_reconcile(now)?,
      effects: vec![],
    })
  }
  /// Determines whether data matches the established endpoint and session ID.
  ///
  /// The source is checked before the session identifier.
  pub(crate) fn classify_data(
    &self,
    source: SocketAddr,
    session_id: SessionId,
  ) -> ServerDataDecision {
    match self.state {
      ServerHandshakeState::Listening => return ServerDataDecision::RejectPreSession,
      ServerHandshakeState::Closed => return ServerDataDecision::RejectClosed,
      ServerHandshakeState::Established { session } => {
        if source != session.peer_endpoint {
          return ServerDataDecision::RejectUnexpectedSource {
            expected: session.peer_endpoint,
            observed: source,
          };
        }
        if session_id != session.metadata.session_id {
          return ServerDataDecision::RejectUnknownSession {
            expected: session.metadata.session_id,
            observed: session_id,
          };
        }
        return ServerDataDecision::PermitEstablished { session_id };
      }
    }
  }
  /// Returns the nearest pending deadline while the server is listening.
  pub(crate) fn next_deadline(&self) -> Option<Instant> {
    match self.state {
      ServerHandshakeState::Listening => return self.pending.next_deadline(),
      _ => return None,
    }
  }
  /// Clears pending and established state and enters the terminal closed state.
  ///
  /// Repeated shutdown is idempotent.
  pub(crate) fn shutdown(&mut self) -> Result<ServerReport, ServerStateError> {
    if self.state == ServerHandshakeState::Closed {
      return Ok(ServerReport {
        expired: vec![],
        effects: vec![ServerEffect::AlreadyClosed],
      });
    }
    let removed_candidates = self.pending.pending_count();
    let removed_session = matches!(self.state, ServerHandshakeState::Established { .. });
    self.pending.shutdown();
    self.candidate_by_id.clear();
    self.state = ServerHandshakeState::Closed;
    return Ok(ServerReport {
      expired: vec![],
      effects: vec![ServerEffect::Closed {
        removed_candidates,
        removed_session,
      }],
    });
  }

  /// Expires manager candidates and reconciles the server attempt registry.
  fn expire_and_reconcile(
    &mut self,
    now: Instant,
  ) -> Result<Vec<ExpiredServerCandidate>, ServerStateError> {
    if matches!(self.state, ServerHandshakeState::Closed)
      | matches!(self.state, ServerHandshakeState::Established { .. })
    {
      if !self.candidate_by_id.is_empty() {
        return Err(ServerStateError::PendingCandidatesOutsideListening {
          state: if matches!(self.state, ServerHandshakeState::Established { .. }) {
            ServerStateName::Established
          } else {
            ServerStateName::Listening
          },
          count: self.candidate_by_id.len(),
        });
      }
      return Ok(Vec::new());
    }

    let manager_report = self.pending.expire_pending(now);
    let mut expired_server = Vec::new();
    for item in manager_report.expired {
      let Some(binding) = self.candidate_by_id.remove(&item.candidate_id) else {
        return Err(ServerStateError::CandidateRegistryMissing {
          candidate_id: item.candidate_id,
          source: item.source,
        });
      };
      if binding.source != item.source {
        return Err(ServerStateError::CandidateSourceMismatch {
          candidate_id: item.candidate_id,
          manager_source: item.source,
          registry_source: binding.source,
        });
      }
      expired_server.push(ExpiredServerCandidate {
        candidate_id: item.candidate_id,
        source: binding.source,
        client_attempt_id: binding.client_attempt_id,
      });
    }
    self.verify_candidate_maps()?;
    Ok(expired_server)
  }
  /// Looks up a source binding and validates registry ownership.
  fn current_candidate(
    &self,
    source: SocketAddr,
  ) -> Result<Option<ServerCandidate>, ServerStateError> {
    let Some(snapshot) = self.pending.candidate(source) else {
      return Ok(None);
    };
    let Some(binding) = self.candidate_by_id.get(&snapshot.candidate_id) else {
      return Err(ServerStateError::CandidateRegistryMissing {
        candidate_id: snapshot.candidate_id,
        source: source,
      });
    };
    if binding.source != source {
      return Err(ServerStateError::CandidateSourceMismatch {
        candidate_id: snapshot.candidate_id,
        manager_source: source,
        registry_source: binding.source,
      });
    }
    Ok(Some((*binding).clone()))
  }
  /// Removes one candidate from both the manager and registry after exact checks.
  fn remove_exact_candidate(&mut self, candidate: ServerCandidate) -> Result<(), ServerStateError> {
    let outcome = self
      .pending
      .remove_candidate(candidate.source, candidate.candidate_id);
    match outcome {
      CandidateRemoval::Removed => {}
      CandidateRemoval::NotFound => {
        return Err(ServerStateError::CandidateRegistryOrphaned {
          candidate_id: candidate.candidate_id,
          source: candidate.source,
        })
      }
      CandidateRemoval::CandidateMismatch {
        expected: _,
        observed,
      } => {
        return Err(ServerStateError::CandidateRegistryOrphaned {
          candidate_id: observed,
          source: candidate.source,
        })
      }
      CandidateRemoval::Closed => return Err(ServerStateError::PendingManagerClosedWhileListening),
    }
    let Some(removed) = self.candidate_by_id.remove(&candidate.candidate_id) else {
      return Err(ServerStateError::CandidateRegistryMissing {
        candidate_id: candidate.candidate_id,
        source: candidate.source,
      });
    };
    if removed.source != candidate.source {
      return Err(ServerStateError::CandidateSourceMismatch {
        candidate_id: candidate.candidate_id,
        manager_source: candidate.source,
        registry_source: removed.source,
      });
    }
    Ok(())
  }
  /// Verifies that manager and registry contain the same pending candidates.
  fn verify_candidate_maps(&self) -> Result<(), ServerStateError> {
    if !matches!(self.state, ServerHandshakeState::Listening) && !self.candidate_by_id.is_empty() {
      return Err(ServerStateError::PendingCandidatesOutsideListening {
        state: self.state_name(),
        count: self.candidate_by_id.len(),
      });
    }

    for binding in self.candidate_by_id.values() {
      let Some(snapshot) = self.pending.candidate(binding.source) else {
        return Err(ServerStateError::CandidateRegistryOrphaned {
          candidate_id: binding.candidate_id,
          source: binding.source,
        });
      };
      if snapshot.candidate_id != binding.candidate_id {
        return Err(ServerStateError::CandidateRegistryOrphaned {
          candidate_id: binding.candidate_id,
          source: binding.source,
        });
      }
    }
    if self.pending.pending_count() != self.candidate_by_id.len() {
      return Err(ServerStateError::CandidateRegistryCountMismatch {
        manager_count: self.pending.pending_count(),
        registry_count: self.candidate_by_id.len(),
      });
    }

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::session::types::{
    ClientAttemptId, EstablishedSessionMetadata, PeerIdentity, SessionId,
  };
  use std::time::Duration;

  const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
  const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

  fn policy(maximum_pending: usize) -> SessionPolicy {
    SessionPolicy::new(maximum_pending, HANDSHAKE_TIMEOUT, IDLE_TIMEOUT).unwrap()
  }

  fn source(port: u16) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 1], port))
  }

  fn hello(server: &mut ServerHandshake, source: SocketAddr, now: Instant) -> CandidateId {
    let report = server
      .handle_valid_client_hello(source, ClientAttemptId(1), now)
      .unwrap();
    match report.effects.as_slice() {
      [ServerEffect::SendServerHello { candidate_id, .. }] => *candidate_id,
      _ => panic!("expected one server hello effect"),
    }
  }

  fn metadata(session_id: u64) -> EstablishedSessionMetadata {
    EstablishedSessionMetadata {
      session_id: SessionId(session_id),
      peer_identity: PeerIdentity(7),
    }
  }

  #[test]
  fn new_server_rejects_data_before_establishment() {
    let server = ServerHandshake::new(policy(2));
    assert_eq!(server.state_name(), ServerStateName::Listening);
    assert_eq!(server.next_deadline(), None);
    assert!(matches!(
      server.classify_data(source(4000), SessionId(1)),
      ServerDataDecision::RejectPreSession
    ));
  }

  #[test]
  fn hello_duplicate_keeps_candidate_and_deadline() {
    let mut server = ServerHandshake::new(policy(2));
    let start = Instant::now();
    let candidate_id = hello(&mut server, source(4000), start);
    let deadline = server.next_deadline().unwrap();

    let report = server
      .handle_valid_client_hello(
        source(4000),
        ClientAttemptId(1),
        start + Duration::from_secs(1),
      )
      .unwrap();

    assert!(matches!(
      report.effects.as_slice(),
      [ServerEffect::SendServerHello { candidate_id: observed, client_attempt_id: ClientAttemptId(1), .. }] if *observed == candidate_id
    ));
    assert_eq!(server.next_deadline(), Some(deadline));
  }

  #[test]
  fn exact_finish_establishes_and_duplicate_only_resends_finish() {
    let mut server = ServerHandshake::new(policy(2));
    let start = Instant::now();
    let peer = source(4000);
    let candidate_id = hello(&mut server, peer, start);
    let session_metadata = metadata(9);

    let report = server
      .handle_authenticated_client_finish(
        peer,
        candidate_id,
        ClientAttemptId(1),
        session_metadata,
        start + Duration::from_secs(1),
      )
      .unwrap();

    assert!(matches!(report.effects.as_slice(), [
      ServerEffect::SendServerFinish { session_id: SessionId(9), .. },
      ServerEffect::SessionEstablished { source, session_id: SessionId(9) }
    ] if *source == peer));
    assert_eq!(server.state_name(), ServerStateName::Established);
    assert_eq!(server.next_deadline(), None);
    assert!(matches!(
      server.classify_data(peer, SessionId(9)),
      ServerDataDecision::PermitEstablished {
        session_id: SessionId(9)
      }
    ));

    let duplicate = server
      .handle_authenticated_client_finish(
        peer,
        candidate_id,
        ClientAttemptId(1),
        session_metadata,
        start + Duration::from_secs(2),
      )
      .unwrap();
    assert!(matches!(
      duplicate.effects.as_slice(),
      [ServerEffect::SendServerFinish {
        session_id: SessionId(9),
        ..
      }]
    ));
  }

  #[test]
  fn authentication_failure_removes_only_exact_candidate() {
    let mut server = ServerHandshake::new(policy(2));
    let start = Instant::now();
    let peer = source(4000);
    let candidate_id = hello(&mut server, peer, start);

    let report = server
      .handle_authentication_failure(peer, candidate_id, ClientAttemptId(1), start)
      .unwrap();
    assert!(matches!(
      report.effects.as_slice(),
      [ServerEffect::Dropped {
        reason: ServerDropReason::AuthenticationFailed,
        ..
      }]
    ));
    assert_eq!(server.next_deadline(), None);

    let next = server
      .handle_valid_client_hello(peer, ClientAttemptId(2), start)
      .unwrap();
    assert!(matches!(
      next.effects.as_slice(),
      [ServerEffect::SendServerHello {
        client_attempt_id: ClientAttemptId(2),
        ..
      }]
    ));
  }

  #[test]
  fn timeout_at_deadline_removes_candidate() {
    let mut server = ServerHandshake::new(policy(1));
    let start = Instant::now();
    let peer = source(4000);
    let candidate_id = hello(&mut server, peer, start);
    let deadline = server.next_deadline().unwrap();

    let report = server.check_timeouts(deadline).unwrap();
    assert!(matches!(report.effects.as_slice(), []));
    assert!(matches!(
      report.expired.as_slice(),
      [ExpiredServerCandidate { candidate_id: observed, source, client_attempt_id: ClientAttemptId(1) }] if *observed == candidate_id && *source == peer
    ));
    assert_eq!(server.next_deadline(), None);
  }

  #[test]
  fn shutdown_is_terminal_and_idempotent() {
    let mut server = ServerHandshake::new(policy(1));
    let start = Instant::now();
    hello(&mut server, source(4000), start);

    let closed = server.shutdown().unwrap();
    assert!(matches!(
      closed.effects.as_slice(),
      [ServerEffect::Closed {
        removed_candidates: 1,
        removed_session: false
      }]
    ));
    assert_eq!(server.state_name(), ServerStateName::Closed);
    assert!(matches!(
      server.classify_data(source(4000), SessionId(1)),
      ServerDataDecision::RejectClosed
    ));

    let again = server.shutdown().unwrap();
    assert!(matches!(
      again.effects.as_slice(),
      [ServerEffect::AlreadyClosed]
    ));
  }
}
