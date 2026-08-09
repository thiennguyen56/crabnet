//! Pure client-side authenticated-handshake policy.
//!
//! This module owns only synchronous state transitions. It does not decode
//! wire messages, perform cryptography, access sockets, or forward packets.

use crate::session::types::{ClientAttemptId, EstablishedSessionMetadata, SessionId};
use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Client-side handshake lifecycle.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ClientHandshakeState {
  /// No handshake has started.
  Idle,
  /// A client hello was issued and an authenticated server hello is pending.
  AwaitingServerHello {
    /// Local attempt that owns this transition.
    attempt_id: ClientAttemptId,
    /// Time at which the complete attempt began.
    started_at: Instant,
    /// Exact instant at or after which the phase is timed out.
    deadline: Instant,
  },
  /// A client finish was issued and authenticated server confirmation is pending.
  AwaitingServerFinish {
    /// Local attempt that owns this transition.
    attempt_id: ClientAttemptId,
    /// Time at which the complete attempt began.
    started_at: Instant,
    /// Time at which the final-confirmation phase began.
    phase_started_at: Instant,
    /// Exact instant at or after which the phase is timed out.
    deadline: Instant,
  },
  /// Authenticated server confirmation completed the handshake.
  Established {
    /// Authenticated, non-secret session metadata.
    metadata: EstablishedSessionMetadata,
    /// Time at which confirmation completed.
    established_at: Instant,
  },
  /// Terminal state for this milestone.
  Closed,
}

impl ClientHandshakeState {
  /// Returns a fieldless diagnostic name without exposing state payloads.
  pub(crate) const fn name(&self) -> ClientStateName {
    match self {
      Self::Idle => ClientStateName::Idle,
      Self::AwaitingServerHello { .. } => ClientStateName::AwaitingServerHello,
      Self::AwaitingServerFinish { .. } => ClientStateName::AwaitingServerFinish,
      Self::Established { .. } => ClientStateName::Established,
      Self::Closed => ClientStateName::Closed,
    }
  }

  /// Returns the structurally expected inbound message for the current state.
  /// Returns the message kind structurally expected in this state.
  /// Returns the message kind structurally expected in this state.
  const fn expected_inbound(&self) -> Option<ClientInboundKind> {
    match self {
      Self::AwaitingServerHello { .. } => Some(ClientInboundKind::ServerHello),
      Self::AwaitingServerFinish { .. } => Some(ClientInboundKind::ServerFinish),
      Self::Idle | Self::Established { .. } | Self::Closed => None,
    }
  }
}

/// Pure client handshake state machine.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ClientHandshake {
  server_endpoint: SocketAddr,
  handshake_timeout: Duration,
  state: ClientHandshakeState,
  next_attempt_id: u64,
}

impl ClientHandshake {
  /// Creates an idle client after validating the per-phase timeout.
  pub(crate) fn new(
    server_endpoint: SocketAddr,
    handshake_timeout: Duration,
  ) -> Result<Self, ClientHandshakeConfigError> {
    if handshake_timeout.is_zero() {
      return Err(ClientHandshakeConfigError::HandshakeTimeout);
    }

    Ok(Self {
      server_endpoint,
      handshake_timeout,
      state: ClientHandshakeState::Idle,
      next_attempt_id: 1,
    })
  }

  /// Starts one fresh attempt from the idle state.
  pub(crate) fn start(&mut self, now: Instant) -> Result<ClientAction, ClientStateError> {
    if !matches!(self.state, ClientHandshakeState::Idle) {
      return Err(ClientStateError::InvalidLocalTransition {
        operation: ClientOperation::Start,
        state: self.state.name(),
      });
    }

    let deadline =
      now
        .checked_add(self.handshake_timeout)
        .ok_or(ClientStateError::DeadlineOverflow {
          phase: ClientHandshakePhase::ServerHello,
        })?;
    let attempt_id = self.reserve_attempt_id()?;

    self.state = ClientHandshakeState::AwaitingServerHello {
      attempt_id,
      started_at: now,
      deadline,
    };

    Ok(ClientAction::SendClientHello { attempt_id })
  }

  /// Applies a server hello that a future crypto boundary authenticated.
  pub(crate) fn handle_authenticated_server_hello(
    &mut self,
    source: SocketAddr,
    attempt_id: ClientAttemptId,
    now: Instant,
  ) -> Result<ClientAction, ClientStateError> {
    if source != self.server_endpoint {
      return Ok(self.unexpected_source(source));
    }

    let (current_attempt_id, started_at, deadline) = match &self.state {
      ClientHandshakeState::AwaitingServerHello {
        attempt_id,
        started_at,
        deadline,
      } => (*attempt_id, *started_at, *deadline),
      state => {
        return Err(ClientStateError::InvalidLocalTransition {
          operation: ClientOperation::ApplyAuthenticatedServerHello,
          state: state.name(),
        });
      }
    };

    if attempt_id != current_attempt_id {
      return Ok(ClientAction::Dropped {
        reason: ClientDropReason::StaleAttempt {
          expected: current_attempt_id,
          observed: attempt_id,
        },
      });
    }

    if now >= deadline {
      self.state = ClientHandshakeState::Closed;
      return Ok(ClientAction::HandshakeTimedOut { attempt_id });
    }

    let new_deadline =
      now
        .checked_add(self.handshake_timeout)
        .ok_or(ClientStateError::DeadlineOverflow {
          phase: ClientHandshakePhase::ServerFinish,
        })?;

    self.state = ClientHandshakeState::AwaitingServerFinish {
      attempt_id: current_attempt_id,
      started_at,
      phase_started_at: now,
      deadline: new_deadline,
    };

    Ok(ClientAction::SendClientFinish {
      attempt_id: current_attempt_id,
    })
  }

  /// Applies server key confirmation authenticated for the current attempt.
  pub(crate) fn handle_authenticated_server_finish(
    &mut self,
    source: SocketAddr,
    attempt_id: ClientAttemptId,
    metadata: EstablishedSessionMetadata,
    now: Instant,
  ) -> Result<ClientAction, ClientStateError> {
    if source != self.server_endpoint {
      return Ok(self.unexpected_source(source));
    }

    let (current_attempt_id, deadline) = match &self.state {
      ClientHandshakeState::AwaitingServerFinish {
        attempt_id,
        deadline,
        ..
      } => (*attempt_id, *deadline),
      state => {
        return Err(ClientStateError::InvalidLocalTransition {
          operation: ClientOperation::ApplyAuthenticatedServerFinish,
          state: state.name(),
        });
      }
    };

    if attempt_id != current_attempt_id {
      return Ok(ClientAction::Dropped {
        reason: ClientDropReason::StaleAttempt {
          expected: current_attempt_id,
          observed: attempt_id,
        },
      });
    }

    if now >= deadline {
      self.state = ClientHandshakeState::Closed;
      return Ok(ClientAction::HandshakeTimedOut { attempt_id });
    }

    let session_id = metadata.session_id;
    self.state = ClientHandshakeState::Established {
      metadata,
      established_at: now,
    };

    Ok(ClientAction::SessionEstablished { session_id })
  }

  /// Closes the current attempt after an authentication failure.
  pub(crate) fn handle_authentication_failure(
    &mut self,
    source: SocketAddr,
    attempt_id: ClientAttemptId,
  ) -> ClientAction {
    if source != self.server_endpoint {
      return self.unexpected_source(source);
    }

    let current_attempt_id = match &self.state {
      ClientHandshakeState::AwaitingServerHello { attempt_id, .. }
      | ClientHandshakeState::AwaitingServerFinish { attempt_id, .. } => *attempt_id,
      ClientHandshakeState::Idle
      | ClientHandshakeState::Established { .. }
      | ClientHandshakeState::Closed => {
        return ClientAction::Dropped {
          reason: ClientDropReason::AuthenticationFailed,
        };
      }
    };

    if attempt_id != current_attempt_id {
      return ClientAction::Dropped {
        reason: ClientDropReason::StaleAttempt {
          expected: current_attempt_id,
          observed: attempt_id,
        },
      };
    }

    self.state = ClientHandshakeState::Closed;
    ClientAction::Dropped {
      reason: ClientDropReason::AuthenticationFailed,
    }
  }

  /// Classifies a structurally valid message that is inappropriate for the state.
  pub(crate) fn handle_unexpected_message(
    &self,
    source: SocketAddr,
    observed: ClientInboundKind,
  ) -> ClientAction {
    if source != self.server_endpoint {
      return self.unexpected_source(source);
    }

    if observed == ClientInboundKind::Data
      && !matches!(self.state, ClientHandshakeState::Established { .. })
    {
      return ClientAction::Dropped {
        reason: ClientDropReason::PreSessionData,
      };
    }

    ClientAction::Dropped {
      reason: ClientDropReason::UnexpectedMessage {
        expected: self.state.expected_inbound(),
        observed,
      },
    }
  }

  /// Applies the exact per-phase timeout boundary.
  pub(crate) fn check_timeout(&mut self, now: Instant) -> ClientAction {
    let (attempt_id, deadline) = match &self.state {
      ClientHandshakeState::AwaitingServerHello {
        attempt_id,
        deadline,
        ..
      }
      | ClientHandshakeState::AwaitingServerFinish {
        attempt_id,
        deadline,
        ..
      } => (*attempt_id, *deadline),
      ClientHandshakeState::Idle | ClientHandshakeState::Established { .. } => {
        return ClientAction::Unchanged;
      }
      ClientHandshakeState::Closed => return ClientAction::AlreadyClosed,
    };

    if now < deadline {
      return ClientAction::Unchanged;
    }

    self.state = ClientHandshakeState::Closed;
    ClientAction::HandshakeTimedOut { attempt_id }
  }

  /// Reports whether secure data may be processed in the current state.
  pub(crate) fn classify_data(&self) -> ClientDataDecision {
    match &self.state {
      ClientHandshakeState::Established { metadata, .. } => ClientDataDecision::PermitEstablished {
        session_id: metadata.session_id,
      },
      ClientHandshakeState::Closed => ClientDataDecision::RejectClosed,
      ClientHandshakeState::Idle
      | ClientHandshakeState::AwaitingServerHello { .. }
      | ClientHandshakeState::AwaitingServerFinish { .. } => ClientDataDecision::RejectPreSession,
    }
  }

  /// Returns the active phase deadline, if any.
  pub(crate) fn next_deadline(&self) -> Option<Instant> {
    match &self.state {
      ClientHandshakeState::AwaitingServerHello { deadline, .. }
      | ClientHandshakeState::AwaitingServerFinish { deadline, .. } => Some(*deadline),
      ClientHandshakeState::Idle
      | ClientHandshakeState::Established { .. }
      | ClientHandshakeState::Closed => None,
    }
  }

  /// Transitions any non-closed state to the terminal closed state.
  pub(crate) fn shutdown(&mut self) -> ClientAction {
    if matches!(self.state, ClientHandshakeState::Closed) {
      return ClientAction::AlreadyClosed;
    }

    self.state = ClientHandshakeState::Closed;
    ClientAction::Closed
  }

  /// Reserves the next client attempt identifier without wrapping.
  /// Reserves the next client attempt identifier without wrapping.
  fn reserve_attempt_id(&mut self) -> Result<ClientAttemptId, ClientStateError> {
    let current = self.next_attempt_id;
    let next = current
      .checked_add(1)
      .ok_or(ClientStateError::AttemptIdExhausted)?;
    self.next_attempt_id = next;
    Ok(ClientAttemptId(current))
  }

  /// Builds a drop decision for input from an unexpected endpoint.
  /// Builds a drop decision for input from an unexpected endpoint.
  fn unexpected_source(&self, observed: SocketAddr) -> ClientAction {
    ClientAction::Dropped {
      reason: ClientDropReason::UnexpectedSource {
        expected: self.server_endpoint,
        observed,
      },
    }
  }
}

/// Invalid client-handshake configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientHandshakeConfigError {
  /// The per-phase timeout is zero.
  HandshakeTimeout,
}

impl fmt::Display for ClientHandshakeConfigError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::HandshakeTimeout => {
        write!(
          formatter,
          "client handshake timeout must be greater than zero"
        )
      }
    }
  }
}

impl Error for ClientHandshakeConfigError {}

/// Owned instruction returned to a future async runtime.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ClientAction {
  /// Prepare and send a client hello for this attempt.
  SendClientHello { attempt_id: ClientAttemptId },
  /// Prepare and send a client finish for this attempt.
  SendClientFinish { attempt_id: ClientAttemptId },
  /// Authentication completed for this session.
  SessionEstablished { session_id: SessionId },
  /// Remote input was deliberately rejected.
  Dropped { reason: ClientDropReason },
  /// The pending phase reached its deadline.
  HandshakeTimedOut { attempt_id: ClientAttemptId },
  /// No transition was required.
  Unchanged,
  /// Shutdown closed a previously active state.
  Closed,
  /// The client was already closed.
  AlreadyClosed,
}

/// Expected rejection reason for untrusted input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientDropReason {
  /// The message kind is inappropriate for the current state.
  UnexpectedMessage {
    /// Message expected by the state, or none outside a pending state.
    expected: Option<ClientInboundKind>,
    /// Structurally decoded message that was observed.
    observed: ClientInboundKind,
  },
  /// The datagram did not come from the configured server transport endpoint.
  UnexpectedSource {
    /// Configured server endpoint.
    expected: SocketAddr,
    /// Datagram source that was observed.
    observed: SocketAddr,
  },
  /// An authenticated result belongs to an older or unrelated attempt.
  StaleAttempt {
    /// Attempt currently owned by the state machine.
    expected: ClientAttemptId,
    /// Attempt associated with the received result.
    observed: ClientAttemptId,
  },
  /// Cryptographic authentication failed for the current attempt.
  AuthenticationFailed,
  /// Data arrived before session establishment.
  PreSessionData,
}

/// Structurally decoded message category used by state policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientInboundKind {
  /// Server response to a client hello.
  ServerHello,
  /// Server key confirmation after client finish.
  ServerFinish,
  /// Secure data message.
  Data,
  /// Other structurally valid handshake message.
  OtherHandshake,
}

/// Local client state-machine failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientStateError {
  /// A trusted caller requested an operation from an incompatible state.
  InvalidLocalTransition {
    /// Operation that was requested.
    operation: ClientOperation,
    /// Fieldless name of the current state.
    state: ClientStateName,
  },
  /// The phase deadline cannot be represented by the platform instant.
  DeadlineOverflow {
    /// Phase whose deadline could not be represented.
    phase: ClientHandshakePhase,
  },
  /// The monotonically increasing attempt identifier cannot advance.
  AttemptIdExhausted,
}

impl fmt::Display for ClientStateError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidLocalTransition { operation, state } => {
        write!(
          formatter,
          "cannot apply {operation:?} while client state is {state:?}"
        )
      }
      Self::DeadlineOverflow { phase } => {
        write!(
          formatter,
          "client handshake deadline overflows for phase {phase:?}"
        )
      }
      Self::AttemptIdExhausted => write!(formatter, "client handshake attempt ID is exhausted"),
    }
  }
}

impl Error for ClientStateError {}

/// Pure decision about whether secure data is eligible for processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientDataDecision {
  /// No authenticated session exists yet.
  RejectPreSession,
  /// Data belongs to an established authenticated session.
  PermitEstablished { session_id: SessionId },
  /// Shutdown has made data processing terminal.
  RejectClosed,
}

/// Handshake proof whose per-phase deadline is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientHandshakePhase {
  /// Awaiting authenticated server hello.
  ServerHello,
  /// Awaiting authenticated server finish.
  ServerFinish,
}

/// Trusted local operation used in invalid-transition diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientOperation {
  /// Begin a new client attempt.
  Start,
  /// Apply an authenticated server hello result.
  ApplyAuthenticatedServerHello,
  /// Apply an authenticated server finish result.
  ApplyAuthenticatedServerFinish,
}

/// Fieldless diagnostic name for a client handshake state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientStateName {
  /// No attempt has started.
  Idle,
  /// Awaiting authenticated server hello.
  AwaitingServerHello,
  /// Awaiting authenticated server finish.
  AwaitingServerFinish,
  /// Authentication completed.
  Established,
  /// Terminal state.
  Closed,
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::session::types::PeerIdentity;

  const TIMEOUT: Duration = Duration::from_secs(10);

  fn server() -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 2], 51820))
  }

  fn other_server() -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 3], 51820))
  }

  fn client() -> ClientHandshake {
    ClientHandshake::new(server(), TIMEOUT).expect("test handshake policy should be valid")
  }

  fn metadata(session: u64, peer: u64) -> EstablishedSessionMetadata {
    EstablishedSessionMetadata {
      session_id: SessionId(session),
      peer_identity: PeerIdentity(peer),
    }
  }

  fn start(client: &mut ClientHandshake, now: Instant) -> ClientAttemptId {
    let ClientAction::SendClientHello { attempt_id } =
      client.start(now).expect("idle client should start")
    else {
      panic!("expected client hello action");
    };
    attempt_id
  }

  fn advance_to_server_finish(
    client: &mut ClientHandshake,
    started_at: Instant,
  ) -> ClientAttemptId {
    let attempt_id = start(client, started_at);
    let action = client
      .handle_authenticated_server_hello(server(), attempt_id, started_at + Duration::from_secs(1))
      .expect("current server hello should transition");
    assert_eq!(action, ClientAction::SendClientFinish { attempt_id });
    attempt_id
  }

  #[test]
  fn zero_timeout_is_rejected() {
    assert_eq!(
      ClientHandshake::new(server(), Duration::ZERO),
      Err(ClientHandshakeConfigError::HandshakeTimeout)
    );
  }

  #[test]
  fn start_records_attempt_and_exact_deadline() {
    let mut client = client();
    let now = Instant::now();
    let attempt_id = start(&mut client, now);

    assert_eq!(attempt_id, ClientAttemptId(1));
    assert_eq!(client.next_deadline(), Some(now + TIMEOUT));
    assert!(matches!(
      client.state,
      ClientHandshakeState::AwaitingServerHello {
        started_at,
        ..
      } if started_at == now
    ));
  }

  #[test]
  fn starting_twice_reports_fieldless_state_name() {
    let mut client = client();
    let now = Instant::now();
    start(&mut client, now);

    assert_eq!(
      client.start(now),
      Err(ClientStateError::InvalidLocalTransition {
        operation: ClientOperation::Start,
        state: ClientStateName::AwaitingServerHello,
      })
    );
  }

  #[test]
  fn authenticated_server_hello_preserves_start_and_resets_phase_deadline() {
    let mut client = client();
    let started_at = Instant::now();
    let attempt_id = start(&mut client, started_at);
    let phase_started_at = started_at + Duration::from_secs(2);

    let action = client
      .handle_authenticated_server_hello(server(), attempt_id, phase_started_at)
      .expect("current server hello should transition");

    assert_eq!(action, ClientAction::SendClientFinish { attempt_id });
    assert!(matches!(
      client.state,
      ClientHandshakeState::AwaitingServerFinish {
        started_at: observed_start,
        phase_started_at: observed_phase,
        deadline,
        ..
      } if observed_start == started_at
        && observed_phase == phase_started_at
        && deadline == phase_started_at + TIMEOUT
    ));
  }

  #[test]
  fn server_hello_at_deadline_times_out() {
    let mut client = client();
    let now = Instant::now();
    let attempt_id = start(&mut client, now);

    assert_eq!(
      client
        .handle_authenticated_server_hello(server(), attempt_id, now + TIMEOUT)
        .expect("timeout is a policy outcome"),
      ClientAction::HandshakeTimedOut { attempt_id }
    );
    assert_eq!(client.state.name(), ClientStateName::Closed);
  }

  #[test]
  fn stale_server_hello_does_not_advance() {
    let mut client = client();
    let now = Instant::now();
    let current = start(&mut client, now);
    let stale = ClientAttemptId(99);

    assert_eq!(
      client
        .handle_authenticated_server_hello(server(), stale, now)
        .expect("stale remote input is a drop outcome"),
      ClientAction::Dropped {
        reason: ClientDropReason::StaleAttempt {
          expected: current,
          observed: stale,
        }
      }
    );
    assert_eq!(client.state.name(), ClientStateName::AwaitingServerHello);
  }

  #[test]
  fn unexpected_message_reports_state_specific_expectation() {
    let mut client = client();
    let now = Instant::now();
    advance_to_server_finish(&mut client, now);

    assert_eq!(
      client.handle_unexpected_message(server(), ClientInboundKind::ServerHello),
      ClientAction::Dropped {
        reason: ClientDropReason::UnexpectedMessage {
          expected: Some(ClientInboundKind::ServerFinish),
          observed: ClientInboundKind::ServerHello,
        }
      }
    );
  }

  #[test]
  fn unexpected_source_never_advances() {
    let mut client = client();
    let now = Instant::now();
    let attempt_id = start(&mut client, now);

    assert_eq!(
      client
        .handle_authenticated_server_hello(other_server(), attempt_id, now)
        .expect("unexpected source is a drop outcome"),
      ClientAction::Dropped {
        reason: ClientDropReason::UnexpectedSource {
          expected: server(),
          observed: other_server(),
        }
      }
    );
    assert_eq!(client.state.name(), ClientStateName::AwaitingServerHello);
  }

  #[test]
  fn authenticated_server_finish_establishes_distinct_metadata() {
    let mut client = client();
    let now = Instant::now();
    let attempt_id = advance_to_server_finish(&mut client, now);
    let established_at = now + Duration::from_secs(2);

    let action = client
      .handle_authenticated_server_finish(server(), attempt_id, metadata(7, 11), established_at)
      .expect("current server finish should establish");

    assert_eq!(
      action,
      ClientAction::SessionEstablished {
        session_id: SessionId(7)
      }
    );
    assert_eq!(
      client.classify_data(),
      ClientDataDecision::PermitEstablished {
        session_id: SessionId(7)
      }
    );
    assert!(matches!(
      &client.state,
      ClientHandshakeState::Established {
        metadata,
        established_at: observed,
      } if metadata.peer_identity == PeerIdentity(11) && *observed == established_at
    ));
  }

  #[test]
  fn stale_authentication_failure_reports_expected_and_observed_in_order() {
    let mut client = client();
    let now = Instant::now();
    let current = start(&mut client, now);
    let stale = ClientAttemptId(99);

    assert_eq!(
      client.handle_authentication_failure(server(), stale),
      ClientAction::Dropped {
        reason: ClientDropReason::StaleAttempt {
          expected: current,
          observed: stale,
        }
      }
    );
    assert_eq!(client.state.name(), ClientStateName::AwaitingServerHello);
  }

  #[test]
  fn current_authentication_failure_closes() {
    let mut client = client();
    let attempt_id = start(&mut client, Instant::now());

    assert_eq!(
      client.handle_authentication_failure(server(), attempt_id),
      ClientAction::Dropped {
        reason: ClientDropReason::AuthenticationFailed
      }
    );
    assert_eq!(client.state.name(), ClientStateName::Closed);
  }

  #[test]
  fn data_is_rejected_before_establishment() {
    let mut client = client();
    assert_eq!(client.classify_data(), ClientDataDecision::RejectPreSession);
    assert_eq!(
      client.handle_unexpected_message(server(), ClientInboundKind::Data),
      ClientAction::Dropped {
        reason: ClientDropReason::PreSessionData
      }
    );

    start(&mut client, Instant::now());
    assert_eq!(client.classify_data(), ClientDataDecision::RejectPreSession);
  }

  #[test]
  fn timeout_is_exact_and_terminal() {
    let mut client = client();
    let now = Instant::now();
    let attempt_id = start(&mut client, now);
    let deadline = now + TIMEOUT;

    assert_eq!(
      client.check_timeout(deadline - Duration::from_nanos(1)),
      ClientAction::Unchanged
    );
    assert_eq!(
      client.check_timeout(deadline),
      ClientAction::HandshakeTimedOut { attempt_id }
    );
    assert_eq!(client.next_deadline(), None);
    assert_eq!(client.check_timeout(deadline), ClientAction::AlreadyClosed);
  }

  #[test]
  fn shutdown_is_idempotent_and_rejects_data() {
    let mut client = client();
    start(&mut client, Instant::now());

    assert_eq!(client.shutdown(), ClientAction::Closed);
    assert_eq!(client.shutdown(), ClientAction::AlreadyClosed);
    assert_eq!(client.next_deadline(), None);
    assert_eq!(client.classify_data(), ClientDataDecision::RejectClosed);
  }

  #[test]
  fn attempt_id_exhaustion_leaves_client_idle() {
    let mut client = client();
    client.next_attempt_id = u64::MAX;

    assert_eq!(
      client.start(Instant::now()),
      Err(ClientStateError::AttemptIdExhausted)
    );
    assert_eq!(client.state.name(), ClientStateName::Idle);
  }

  #[test]
  fn deadline_overflow_leaves_client_idle() {
    let mut client =
      ClientHandshake::new(server(), Duration::MAX).expect("non-zero timeout is valid policy");

    assert_eq!(
      client.start(Instant::now()),
      Err(ClientStateError::DeadlineOverflow {
        phase: ClientHandshakePhase::ServerHello
      })
    );
    assert_eq!(client.state.name(), ClientStateName::Idle);
  }
}
