use std::{net::SocketAddr, time::Instant};

use crate::{
  crypto::{
    client::ClientHandshakeCrypto,
    types::{AuthenticationFailure, ClientContextRemoval, ClientCryptoPhase, CryptoOutcome},
  },
  handshake::types::{
    ClientCoordinatorEvent, ClientCoordinatorReport, ClientCoordinatorResult, ClientFinish,
    ClientHandshakeMessage, ClientHello, CoordinatorBuildError,
    CoordinatorInvariantError::{self, CryptoFailureCorrelationMismatch, UnexpectedClientAction},
    CoordinatorLifecycle, CoordinatorPolicyCleanup, CoordinatorPrimaryError, FatalCoordinatorError,
    ServerFinish, ServerHello,
  },
  session::client::{
    ClientAction, ClientDropReason, ClientHandshake, ClientPreAuthDecision, ClientPreAuthKind,
    ClientStateName,
  },
};

pub(crate) struct ClientHandshakeCoordinator<C>
where
  C: ClientHandshakeCrypto,
{
  policy: ClientHandshake,
  crypto: C,
  lifecycle: CoordinatorLifecycle,
}

impl<C> ClientHandshakeCoordinator<C>
where
  C: ClientHandshakeCrypto,
{
  pub(crate) fn build(
    policy: ClientHandshake,
    crypto: C,
  ) -> Result<ClientHandshakeCoordinator<C>, CoordinatorBuildError> {
    if policy.state_name() != ClientStateName::Idle {
      return Err(CoordinatorBuildError::UnexpectedInitialClientPolicyState {
        observed: policy.state_name(),
      });
    }
    if crypto.phase() != ClientCryptoPhase::Idle {
      return Err(CoordinatorBuildError::UnexpectedInitialClientCryptoPhase {
        observed: crypto.phase(),
      });
    }
    Ok(ClientHandshakeCoordinator {
      policy,
      crypto,
      lifecycle: CoordinatorLifecycle::Running,
    })
  }

  pub(crate) fn start(
    &mut self,
    now: Instant,
  ) -> ClientCoordinatorResult<C::ClientHelloPayload, C::ClientFinishPayload> {
    let action = match self.policy.start(now) {
      Ok(val) => val,
      Err(error) => {
        return Err(self.fail_closed(CoordinatorPrimaryError::ClientPolicy(error)));
      }
    };

    let attempt_id = match action {
      ClientAction::SendClientHello { attempt_id } => attempt_id,
      _ => {
        return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
          CoordinatorInvariantError::UnexpectedClientAction,
        )));
      }
    };

    let prepared = match self.crypto.start_attempt(attempt_id) {
      Ok(prepared) => prepared,
      Err(error) => {
        return Err(self.fail_closed(CoordinatorPrimaryError::Crypto(error)));
      }
    };

    if prepared.attempt_id() != attempt_id {
      return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
        CoordinatorInvariantError::AttemptMismatch {
          expected: attempt_id,
          observed: prepared.attempt_id(),
        },
      )));
    }

    if let Err(error) = verify_client_phases(&self.policy, &self.crypto) {
      return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(error)));
    }

    Ok(ClientCoordinatorReport {
      outbound: vec![ClientHandshakeMessage::ClientHello(ClientHello {
        client_attempt_id: attempt_id,
        payload: prepared.into_payload(),
      })],
      events: vec![],
    })
  }

  pub(crate) fn receive_server_hello(
    &mut self,
    source: SocketAddr,
    message: ServerHello<C::ServerHelloPayload>,
    now: Instant,
  ) -> ClientCoordinatorResult<C::ClientHelloPayload, C::ClientFinishPayload> {
    let decision = self.policy.precheck(
      source,
      message.client_attempt_id,
      ClientPreAuthKind::ServerHello,
      now,
    );

    let attempt_id = match decision {
      ClientPreAuthDecision::Drop { reason } => {
        return Ok(ClientCoordinatorReport {
          outbound: vec![],
          events: vec![ClientCoordinatorEvent::Dropped { reason }],
        });
      }
      ClientPreAuthDecision::Timeout { attempt_id } => {
        let removal = match self.crypto.close_context(attempt_id) {
          Ok(removal) => removal,
          Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Crypto(err))),
        };

        if removal != ClientContextRemoval::Removed {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
            CoordinatorInvariantError::ClientContextCleanupMismatch {
              attempt_id,
              expected: ClientContextRemoval::Removed,
              observed: removal,
            },
          )));
        }

        if let Err(error) = verify_client_phases(&self.policy, &self.crypto) {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(error)));
        }
        self.lifecycle = CoordinatorLifecycle::Closed;
        return Ok(ClientCoordinatorReport {
          outbound: vec![],
          events: vec![ClientCoordinatorEvent::HandshakeTimedOut { attempt_id }],
        });
      }
      ClientPreAuthDecision::Permit { attempt_id } => attempt_id,
    };

    let outcome = match self
      .crypto
      .authenticate_server_hello(attempt_id, message.payload)
    {
      Ok(outcome) => outcome,
      Err(error) => {
        return Err(self.fail_closed(CoordinatorPrimaryError::Crypto(error)));
      }
    };

    let authenticated = match outcome {
      CryptoOutcome::Success(authenticated) => authenticated,

      CryptoOutcome::RemoteFailure(AuthenticationFailure::ClientAttempt {
        attempt_id: observed_attempt,
        reason: _,
      }) => {
        if observed_attempt != attempt_id {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
            CoordinatorInvariantError::AttemptMismatch {
              expected: attempt_id,
              observed: observed_attempt,
            },
          )));
        }

        let action = self
          .policy
          .handle_authentication_failure(source, attempt_id);

        if action
          != (ClientAction::Dropped {
            reason: ClientDropReason::AuthenticationFailed,
          })
        {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
            CoordinatorInvariantError::UnexpectedClientAction,
          )));
        }

        let removal = match self.crypto.close_context(attempt_id) {
          Ok(removal) => removal,
          Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Crypto(err))),
        };

        if removal != ClientContextRemoval::Removed {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
            CoordinatorInvariantError::ClientContextCleanupMismatch {
              attempt_id,
              expected: ClientContextRemoval::Removed,
              observed: removal,
            },
          )));
        }

        if let Err(error) = verify_client_phases(&self.policy, &self.crypto) {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(error)));
        }
        self.lifecycle = CoordinatorLifecycle::Closed;
        return Ok(ClientCoordinatorReport {
          outbound: vec![],
          events: vec![ClientCoordinatorEvent::Dropped {
            reason: ClientDropReason::AuthenticationFailed,
          }],
        });
      }

      CryptoOutcome::RemoteFailure(AuthenticationFailure::ServerCandidate { .. }) => {
        return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
          CoordinatorInvariantError::CryptoFailureCorrelationMismatch,
        )));
      }
    };

    if authenticated.attempt_id() != attempt_id {
      return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
        CoordinatorInvariantError::AttemptMismatch {
          expected: attempt_id,
          observed: authenticated.attempt_id(),
        },
      )));
    }

    let action = match self
      .policy
      .handle_authenticated_server_hello(source, attempt_id, now)
    {
      Ok(action) => action,
      Err(error) => {
        return Err(self.fail_closed(CoordinatorPrimaryError::ClientPolicy(error)));
      }
    };

    match action {
      ClientAction::SendClientFinish {
        attempt_id: observed_attempt,
      } => {
        if observed_attempt != attempt_id {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
            CoordinatorInvariantError::AttemptMismatch {
              expected: attempt_id,
              observed: observed_attempt,
            },
          )));
        }
      }
      _ => {
        return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
          CoordinatorInvariantError::UnexpectedClientAction,
        )));
      }
    }

    let prepared = match self.crypto.prepare_client_finish(attempt_id) {
      Ok(prepared) => prepared,
      Err(err) => {
        return Err(self.fail_closed(CoordinatorPrimaryError::Crypto(err)));
      }
    };

    if prepared.attempt_id() != attempt_id {
      return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
        CoordinatorInvariantError::AttemptMismatch {
          expected: attempt_id,
          observed: prepared.attempt_id(),
        },
      )));
    }

    if let Err(error) = verify_client_phases(&self.policy, &self.crypto) {
      return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(error)));
    }

    Ok(ClientCoordinatorReport {
      outbound: vec![ClientHandshakeMessage::ClientFinish(ClientFinish {
        client_attempt_id: attempt_id,
        payload: prepared.into_payload(),
      })],
      events: vec![],
    })
  }

  pub(crate) fn receive_server_finish(
    &mut self,
    source: SocketAddr,
    message: ServerFinish<C::ServerFinishPayload>,
    now: Instant,
  ) -> ClientCoordinatorResult<C::ClientHelloPayload, C::ClientFinishPayload> {
    let decision = self.policy.precheck(
      source,
      message.client_attempt_id,
      ClientPreAuthKind::ServerFinish,
      now,
    );
    let permitted_attempt = match decision {
      ClientPreAuthDecision::Drop { reason } => {
        return Ok(ClientCoordinatorReport {
          outbound: vec![],
          events: vec![ClientCoordinatorEvent::Dropped { reason }],
        });
      }
      ClientPreAuthDecision::Timeout { attempt_id } => {
        let removal_result = self.crypto.close_context(attempt_id);
        match removal_result {
          Ok(removal) => {
            if removal != ClientContextRemoval::Removed {
              return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
                CoordinatorInvariantError::ClientContextCleanupMismatch {
                  attempt_id,
                  expected: ClientContextRemoval::Removed,
                  observed: removal,
                },
              )));
            }
          }
          Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Crypto(err))),
        }

        match verify_client_phases(&self.policy, &self.crypto) {
          Ok(()) => {
            self.lifecycle = CoordinatorLifecycle::Closed;
            return Ok(ClientCoordinatorReport {
              outbound: vec![],
              events: vec![ClientCoordinatorEvent::HandshakeTimedOut { attempt_id }],
            });
          }
          Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(err))),
        }
      }
      ClientPreAuthDecision::Permit { attempt_id } => attempt_id,
    };

    let outcome = match self
      .crypto
      .authenticate_server_finish(permitted_attempt, message.payload)
    {
      Ok(outcome) => outcome,
      Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Crypto(err))),
    };

    let authenticated = match outcome {
      CryptoOutcome::RemoteFailure(AuthenticationFailure::ServerCandidate { .. }) => {
        return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
          CryptoFailureCorrelationMismatch,
        )));
      }
      CryptoOutcome::RemoteFailure(AuthenticationFailure::ClientAttempt {
        attempt_id: observed_attempt,
        reason: _,
      }) => {
        if observed_attempt != permitted_attempt {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
            CoordinatorInvariantError::AttemptMismatch {
              expected: permitted_attempt,
              observed: observed_attempt,
            },
          )));
        }

        let action = self
          .policy
          .handle_authentication_failure(source, permitted_attempt);

        match action {
          ClientAction::Dropped {
            reason: ClientDropReason::AuthenticationFailed,
          } => {}
          _ => {
            return Err(
              self.fail_closed(CoordinatorPrimaryError::Invariant(UnexpectedClientAction)),
            );
          }
        }

        let removal_result = self.crypto.close_context(permitted_attempt);
        match removal_result {
          Ok(removal) => {
            if removal != ClientContextRemoval::Removed {
              return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
                CoordinatorInvariantError::ClientContextCleanupMismatch {
                  attempt_id: permitted_attempt,
                  expected: ClientContextRemoval::Removed,
                  observed: removal,
                },
              )));
            }
          }
          Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Crypto(err))),
        }

        match verify_client_phases(&self.policy, &self.crypto) {
          Ok(()) => {
            self.lifecycle = CoordinatorLifecycle::Closed;
            return Ok(ClientCoordinatorReport {
              outbound: vec![],
              events: vec![ClientCoordinatorEvent::Dropped {
                reason: ClientDropReason::AuthenticationFailed,
              }],
            });
          }
          Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(err))),
        }
      }
      CryptoOutcome::Success(authenicated) => authenicated,
    };

    if authenticated.attempt_id() != permitted_attempt {
      return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
        CoordinatorInvariantError::AttemptMismatch {
          expected: permitted_attempt,
          observed: authenticated.attempt_id(),
        },
      )));
    }

    let action = match self.policy.handle_authenticated_server_finish(
      source,
      authenticated.attempt_id(),
      authenticated.metadata(),
      now,
    ) {
      Ok(action) => action,
      Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::ClientPolicy(err))),
    };

    match action {
      ClientAction::SessionEstablished {
        session_id: observed_session,
      } => {
        if observed_session != authenticated.metadata().session_id {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(UnexpectedClientAction)));
        }
      }
      _ => {
        return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(UnexpectedClientAction)));
      }
    }

    match self
      .crypto
      .commit_session(authenticated.attempt_id(), authenticated.metadata())
    {
      Ok(()) => (),
      Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Crypto(err))),
    }

    match verify_client_phases(&self.policy, &self.crypto) {
      Ok(()) => Ok(ClientCoordinatorReport {
        outbound: vec![],
        events: vec![ClientCoordinatorEvent::SessionEstablished {
          metadata: authenticated.metadata(),
        }],
      }),
      Err(err) => Err(self.fail_closed(CoordinatorPrimaryError::Invariant(err))),
    }
  }

  pub(crate) fn check_timeout(
    &mut self,
    now: Instant,
  ) -> ClientCoordinatorResult<C::ClientHelloPayload, C::ClientFinishPayload> {
    match self.policy.check_timeout(now) {
      ClientAction::Unchanged => {
        if let Err(error) = verify_client_phases(&self.policy, &self.crypto) {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(error)));
        }

        Ok(ClientCoordinatorReport {
          outbound: vec![],
          events: vec![],
        })
      }
      ClientAction::AlreadyClosed => {
        if let Err(error) = verify_client_phases(&self.policy, &self.crypto) {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(error)));
        }

        self.lifecycle = CoordinatorLifecycle::Closed;
        Ok(ClientCoordinatorReport {
          outbound: vec![],
          events: vec![ClientCoordinatorEvent::AlreadyClosed],
        })
      }
      ClientAction::HandshakeTimedOut { attempt_id } => {
        let removal = match self.crypto.close_context(attempt_id) {
          Ok(removal) => removal,
          Err(error) => return Err(self.fail_closed(CoordinatorPrimaryError::Crypto(error))),
        };

        if removal != ClientContextRemoval::Removed {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
            CoordinatorInvariantError::ClientContextCleanupMismatch {
              attempt_id,
              expected: ClientContextRemoval::Removed,
              observed: removal,
            },
          )));
        }

        if let Err(error) = verify_client_phases(&self.policy, &self.crypto) {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(error)));
        }

        self.lifecycle = CoordinatorLifecycle::Closed;
        Ok(ClientCoordinatorReport {
          outbound: vec![],
          events: vec![ClientCoordinatorEvent::HandshakeTimedOut { attempt_id }],
        })
      }
      ClientAction::SendClientHello { .. }
      | ClientAction::SendClientFinish { .. }
      | ClientAction::SessionEstablished { .. }
      | ClientAction::Dropped { .. }
      | ClientAction::Closed => Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
        CoordinatorInvariantError::UnexpectedClientAction,
      ))),
    }
  }

  pub(crate) fn shutdown(
    &mut self,
  ) -> ClientCoordinatorResult<C::ClientHelloPayload, C::ClientFinishPayload> {
    let policy_action = self.policy.shutdown();
    let crypto_cleanup = self.crypto.shutdown();
    self.lifecycle = CoordinatorLifecycle::Closed;

    if let Err(error) = verify_client_phases(&self.policy, &self.crypto) {
      return Err(FatalCoordinatorError {
        primary: CoordinatorPrimaryError::Invariant(error),
        policy_cleanup: CoordinatorPolicyCleanup::Client {
          action: policy_action,
        },
        crypto_cleanup,
      });
    }

    let event = match policy_action {
      ClientAction::Closed => ClientCoordinatorEvent::Closed {
        policy_was_active: true,
        crypto_cleanup,
      },
      ClientAction::AlreadyClosed if crypto_cleanup.already_closed => {
        ClientCoordinatorEvent::AlreadyClosed
      }
      ClientAction::AlreadyClosed => ClientCoordinatorEvent::Closed {
        policy_was_active: false,
        crypto_cleanup,
      },
      _ => {
        return Err(FatalCoordinatorError {
          primary: CoordinatorPrimaryError::Invariant(
            CoordinatorInvariantError::UnexpectedClientAction,
          ),
          policy_cleanup: CoordinatorPolicyCleanup::Client {
            action: policy_action,
          },
          crypto_cleanup,
        });
      }
    };

    Ok(ClientCoordinatorReport {
      outbound: vec![],
      events: vec![event],
    })
  }

  fn fail_closed(&mut self, primary: CoordinatorPrimaryError) -> FatalCoordinatorError {
    let policy_action = self.policy.shutdown();
    let crypto_cleanup = self.crypto.shutdown();

    self.lifecycle = CoordinatorLifecycle::Closed;

    FatalCoordinatorError {
      primary,
      policy_cleanup: CoordinatorPolicyCleanup::Client {
        action: policy_action,
      },
      crypto_cleanup,
    }
  }
}

fn verify_client_phases<C>(
  policy: &ClientHandshake,
  crypto: &C,
) -> Result<(), CoordinatorInvariantError>
where
  C: ClientHandshakeCrypto,
{
  let policy_phase = policy.state_name();
  let crypto_phase = crypto.phase();
  let expected_crypto = match policy_phase {
    ClientStateName::Idle => ClientCryptoPhase::Idle,
    ClientStateName::AwaitingServerHello => ClientCryptoPhase::AwaitingServerHello,
    ClientStateName::AwaitingServerFinish => ClientCryptoPhase::AwaitingServerFinish,
    ClientStateName::Established => ClientCryptoPhase::Established,
    ClientStateName::Closed => ClientCryptoPhase::Closed,
  };

  if crypto_phase != expected_crypto {
    return Err(CoordinatorInvariantError::ClientPhaseMismatch {
      policy: policy_phase,
      crypto: crypto_phase,
    });
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use std::{num::NonZeroU64, time::Duration};

  use super::*;
  use crate::{
    crypto::{
      fake::{
        FakeClientCrypto, FakeClientCryptoConfig, FakeClientFinish, FakeClientHello,
        FakeCredential, FakeServerCrypto, FakeServerCryptoConfig, FakeServerFinish,
        FakeServerHello,
      },
      server::ServerHandshakeCrypto,
      types::{
        AuthenticatedServerFinish, AuthenticatedServerHello, AuthenticationFailureReason,
        ClientContextRemoval, ClientCryptoOperation, CryptoShutdownOutcome, CryptoStateError,
        PreparedClientFinish, PreparedClientHello,
      },
    },
    handshake::{
      server::ServerHandshakeCoordinator,
      types::{ServerCoordinatorEvent, ServerHandshakeMessage},
    },
    session::{
      client::ClientDropReason,
      server::ServerHandshake,
      types::{ClientAttemptId, EstablishedSessionMetadata, PeerIdentity},
      CandidateId, SessionPolicy,
    },
  };

  const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
  const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
  const CLIENT_IDENTITY: PeerIdentity = PeerIdentity(11);
  const SERVER_IDENTITY: PeerIdentity = PeerIdentity(22);

  fn coordinator() -> ClientHandshakeCoordinator<FakeClientCrypto> {
    let policy =
      ClientHandshake::new(SocketAddr::from(([192, 0, 2, 1], 4000)), HANDSHAKE_TIMEOUT).unwrap();
    let crypto = FakeClientCrypto::new(
      FakeClientCryptoConfig::new(
        FakeCredential::new(NonZeroU64::new(7).unwrap()),
        CLIENT_IDENTITY,
        SERVER_IDENTITY,
      )
      .unwrap(),
    );
    ClientHandshakeCoordinator::build(policy, crypto).unwrap()
  }

  fn server_coordinator() -> ServerHandshakeCoordinator<FakeServerCrypto> {
    let crypto = FakeServerCrypto::new(
      FakeServerCryptoConfig::new(
        FakeCredential::new(NonZeroU64::new(7).unwrap()),
        SERVER_IDENTITY,
        CLIENT_IDENTITY,
        NonZeroU64::new(100).unwrap(),
      )
      .unwrap(),
    );
    ServerHandshakeCoordinator::build(
      ServerHandshake::new(SessionPolicy::new(1, HANDSHAKE_TIMEOUT, IDLE_TIMEOUT).unwrap()),
      crypto,
    )
    .unwrap()
  }

  fn started_with_server_hello() -> (
    ClientHandshakeCoordinator<FakeClientCrypto>,
    ServerHandshakeCoordinator<FakeServerCrypto>,
    ServerHello<FakeServerHello>,
    Instant,
  ) {
    let mut client = coordinator();
    let mut server = server_coordinator();
    let now = Instant::now();
    let mut outbound = client.start(now).unwrap().outbound.into_iter();
    let client_hello = match outbound.next().unwrap() {
      ClientHandshakeMessage::ClientHello(message) => message,
      ClientHandshakeMessage::ClientFinish(_) => panic!("expected ClientHello"),
    };
    let mut response = server
      .receive_client_hello(SocketAddr::from(([192, 0, 2, 1], 5000)), client_hello, now)
      .unwrap()
      .outbound
      .into_iter();
    let server_hello = match response.next().unwrap().message {
      ServerHandshakeMessage::ServerHello(message) => message,
      ServerHandshakeMessage::ServerFinish(_) => panic!("expected ServerHello"),
    };
    (client, server, server_hello, now)
  }

  fn awaiting_server_finish() -> (
    ClientHandshakeCoordinator<FakeClientCrypto>,
    ServerFinish<FakeServerFinish>,
    Instant,
  ) {
    let (mut client, mut server, server_hello, now) = started_with_server_hello();
    let mut client_outbound = client
      .receive_server_hello(
        SocketAddr::from(([192, 0, 2, 1], 4000)),
        server_hello,
        now + Duration::from_secs(1),
      )
      .unwrap()
      .outbound
      .into_iter();
    let client_finish = match client_outbound.next().unwrap() {
      ClientHandshakeMessage::ClientFinish(message) => message,
      ClientHandshakeMessage::ClientHello(_) => panic!("expected ClientFinish"),
    };
    let server_report = server
      .receive_client_finish(
        SocketAddr::from(([192, 0, 2, 1], 5000)),
        client_finish,
        now + Duration::from_secs(2),
      )
      .unwrap();
    assert!(matches!(
      server_report.events.as_slice(),
      [ServerCoordinatorEvent::SessionEstablished { .. }]
    ));
    let mut server_outbound = server_report.outbound.into_iter();
    let server_finish = match server_outbound.next().unwrap().message {
      ServerHandshakeMessage::ServerFinish(message) => message,
      ServerHandshakeMessage::ServerHello(_) => panic!("expected ServerFinish"),
    };
    (client, server_finish, now)
  }

  #[test]
  fn receive_server_hello_rejects_untrusted_metadata_before_crypto_then_advances() {
    let (mut client, _server, server_hello, now) = started_with_server_hello();
    let wrong_source = client
      .receive_server_hello(
        SocketAddr::from(([192, 0, 2, 1], 4001)),
        server_hello.clone(),
        now,
      )
      .unwrap();
    assert!(matches!(
      wrong_source.events.as_slice(),
      [ClientCoordinatorEvent::Dropped {
        reason: ClientDropReason::UnexpectedSource { .. },
      }]
    ));
    assert_eq!(
      client.crypto.phase(),
      ClientCryptoPhase::AwaitingServerHello
    );

    let stale = client
      .receive_server_hello(
        SocketAddr::from(([192, 0, 2, 1], 4000)),
        ServerHello {
          client_attempt_id: ClientAttemptId(2),
          payload: server_hello.payload,
        },
        now,
      )
      .unwrap();
    assert!(matches!(
      stale.events.as_slice(),
      [ClientCoordinatorEvent::Dropped {
        reason: ClientDropReason::StaleAttempt { .. },
      }]
    ));
    assert_eq!(
      client.crypto.phase(),
      ClientCryptoPhase::AwaitingServerHello
    );

    let (_fresh_client, _fresh_server, fresh_hello, fresh_now) = started_with_server_hello();
    let mut fresh_client = _fresh_client;
    let advanced = fresh_client
      .receive_server_hello(
        SocketAddr::from(([192, 0, 2, 1], 4000)),
        fresh_hello,
        fresh_now + Duration::from_secs(1),
      )
      .unwrap();
    assert!(matches!(
      advanced.outbound.as_slice(),
      [ClientHandshakeMessage::ClientFinish(_)]
    ));
    assert_eq!(
      fresh_client.crypto.phase(),
      ClientCryptoPhase::AwaitingServerFinish
    );
  }

  #[test]
  fn server_hello_authentication_failure_closes_every_client_layer() {
    let mut client = coordinator();
    let now = Instant::now();
    client.start(now).unwrap();

    let wrong_credential = FakeCredential::new(NonZeroU64::new(8).unwrap());
    let mut transcript_client = FakeClientCrypto::new(
      FakeClientCryptoConfig::new(wrong_credential, CLIENT_IDENTITY, SERVER_IDENTITY).unwrap(),
    );
    let hello = transcript_client
      .start_attempt(ClientAttemptId(1))
      .unwrap()
      .into_payload();
    let mut transcript_server = FakeServerCrypto::new(
      FakeServerCryptoConfig::new(
        wrong_credential,
        SERVER_IDENTITY,
        CLIENT_IDENTITY,
        NonZeroU64::new(100).unwrap(),
      )
      .unwrap(),
    );
    let server_hello = match transcript_server
      .prepare_server_hello(CandidateId::new(1), ClientAttemptId(1), hello)
      .unwrap()
    {
      CryptoOutcome::Success(prepared) => ServerHello {
        client_attempt_id: ClientAttemptId(1),
        payload: prepared.into_payload(),
      },
      CryptoOutcome::RemoteFailure(_) => panic!("expected prepared ServerHello"),
    };

    let report = client
      .receive_server_hello(
        SocketAddr::from(([192, 0, 2, 1], 4000)),
        server_hello,
        now + Duration::from_secs(1),
      )
      .unwrap();
    assert!(matches!(
      report.events.as_slice(),
      [ClientCoordinatorEvent::Dropped {
        reason: ClientDropReason::AuthenticationFailed,
      }]
    ));
    assert_eq!(client.policy.state_name(), ClientStateName::Closed);
    assert_eq!(client.crypto.phase(), ClientCryptoPhase::Closed);
    assert_eq!(client.lifecycle, CoordinatorLifecycle::Closed);

    let (mut modified_client, _server, server_hello, modified_now) = started_with_server_hello();
    let modified = ServerHello {
      client_attempt_id: server_hello.client_attempt_id,
      payload: server_hello.payload.with_corrupted_proof(),
    };
    let modified_report = modified_client
      .receive_server_hello(
        SocketAddr::from(([192, 0, 2, 1], 4000)),
        modified,
        modified_now + Duration::from_secs(1),
      )
      .unwrap();
    assert!(matches!(
      modified_report.events.as_slice(),
      [ClientCoordinatorEvent::Dropped {
        reason: ClientDropReason::AuthenticationFailed,
      }]
    ));
    assert_eq!(modified_client.policy.state_name(), ClientStateName::Closed);
    assert_eq!(modified_client.crypto.phase(), ClientCryptoPhase::Closed);
    assert_eq!(modified_client.lifecycle, CoordinatorLifecycle::Closed);
  }

  #[test]
  fn receive_server_finish_establishes_once_and_modified_confirmation_closes() {
    let (mut client, server_finish, now) = awaiting_server_finish();
    let duplicate = server_finish.clone();
    let wrong_source = client
      .receive_server_finish(
        SocketAddr::from(([192, 0, 2, 1], 4001)),
        server_finish.clone(),
        now + Duration::from_secs(3),
      )
      .unwrap();
    assert!(matches!(
      wrong_source.events.as_slice(),
      [ClientCoordinatorEvent::Dropped {
        reason: ClientDropReason::UnexpectedSource { .. },
      }]
    ));
    let stale = client
      .receive_server_finish(
        SocketAddr::from(([192, 0, 2, 1], 4000)),
        ServerFinish {
          client_attempt_id: ClientAttemptId(2),
          payload: server_finish.payload,
        },
        now + Duration::from_secs(3),
      )
      .unwrap();
    assert!(matches!(
      stale.events.as_slice(),
      [ClientCoordinatorEvent::Dropped {
        reason: ClientDropReason::StaleAttempt { .. },
      }]
    ));
    assert_eq!(
      client.crypto.phase(),
      ClientCryptoPhase::AwaitingServerFinish
    );

    let established = client
      .receive_server_finish(
        SocketAddr::from(([192, 0, 2, 1], 4000)),
        server_finish,
        now + Duration::from_secs(3),
      )
      .unwrap();
    assert!(matches!(
      established.events.as_slice(),
      [ClientCoordinatorEvent::SessionEstablished { .. }]
    ));
    assert_eq!(client.crypto.phase(), ClientCryptoPhase::Established);

    let duplicate_report = client
      .receive_server_finish(
        SocketAddr::from(([192, 0, 2, 1], 4000)),
        duplicate,
        now + Duration::from_secs(4),
      )
      .unwrap();
    assert!(matches!(
      duplicate_report.events.as_slice(),
      [ClientCoordinatorEvent::Dropped {
        reason: ClientDropReason::UnexpectedMessage { .. },
      }]
    ));
    assert_eq!(client.crypto.phase(), ClientCryptoPhase::Established);

    let (mut invalid_client, invalid_finish, invalid_now) = awaiting_server_finish();
    let invalid = ServerFinish {
      client_attempt_id: invalid_finish.client_attempt_id,
      payload: invalid_finish.payload.with_corrupted_proof(),
    };
    let dropped = invalid_client
      .receive_server_finish(
        SocketAddr::from(([192, 0, 2, 1], 4000)),
        invalid,
        invalid_now + Duration::from_secs(3),
      )
      .unwrap();
    assert!(matches!(
      dropped.events.as_slice(),
      [ClientCoordinatorEvent::Dropped {
        reason: ClientDropReason::AuthenticationFailed,
      }]
    ));
    assert_eq!(invalid_client.policy.state_name(), ClientStateName::Closed);
    assert_eq!(invalid_client.crypto.phase(), ClientCryptoPhase::Closed);
    assert_eq!(invalid_client.lifecycle, CoordinatorLifecycle::Closed);
  }

  #[test]
  fn check_timeout_closes_the_exact_attempt_at_the_deadline() {
    let mut client = coordinator();
    let now = Instant::now();
    client.start(now).unwrap();

    let unchanged = client
      .check_timeout(now + HANDSHAKE_TIMEOUT - Duration::from_nanos(1))
      .unwrap();
    assert!(unchanged.outbound.is_empty());
    assert!(unchanged.events.is_empty());

    let timed_out = client.check_timeout(now + HANDSHAKE_TIMEOUT).unwrap();
    assert!(timed_out.outbound.is_empty());
    assert!(matches!(
      timed_out.events.as_slice(),
      [ClientCoordinatorEvent::HandshakeTimedOut {
        attempt_id: crate::session::types::ClientAttemptId(1),
      }]
    ));
    assert_eq!(client.policy.state_name(), ClientStateName::Closed);
    assert_eq!(client.crypto.phase(), ClientCryptoPhase::Closed);
    assert_eq!(client.lifecycle, CoordinatorLifecycle::Closed);

    let already_closed = client.check_timeout(now + HANDSHAKE_TIMEOUT).unwrap();
    assert_eq!(
      already_closed.events.as_slice(),
      [ClientCoordinatorEvent::AlreadyClosed]
    );
  }

  #[test]
  fn shutdown_cleans_an_active_attempt_and_is_idempotent() {
    let mut client = coordinator();
    client.start(Instant::now()).unwrap();

    let closed = client.shutdown().unwrap();
    assert!(matches!(
      closed.events.as_slice(),
      [ClientCoordinatorEvent::Closed {
        policy_was_active: true,
        crypto_cleanup,
      }] if crypto_cleanup.removed_pending_contexts == 1 && !crypto_cleanup.already_closed
    ));
    assert_eq!(client.policy.state_name(), ClientStateName::Closed);
    assert_eq!(client.crypto.phase(), ClientCryptoPhase::Closed);

    let already_closed = client.shutdown().unwrap();
    assert_eq!(
      already_closed.events.as_slice(),
      [ClientCoordinatorEvent::AlreadyClosed]
    );
  }

  #[test]
  fn shutdown_covers_idle_awaiting_finish_and_established_phases() {
    let mut idle = coordinator();
    let idle_report = idle.shutdown().unwrap();
    assert!(matches!(
      idle_report.events.as_slice(),
      [ClientCoordinatorEvent::Closed {
        policy_was_active: true,
        crypto_cleanup,
      }] if crypto_cleanup.removed_pending_contexts == 0
    ));

    let (mut awaiting, _finish, _) = awaiting_server_finish();
    let awaiting_report = awaiting.shutdown().unwrap();
    assert!(matches!(
      awaiting_report.events.as_slice(),
      [ClientCoordinatorEvent::Closed { crypto_cleanup, .. }]
        if crypto_cleanup.removed_pending_contexts == 1
    ));

    let (mut established, finish, now) = awaiting_server_finish();
    established
      .receive_server_finish(
        SocketAddr::from(([192, 0, 2, 1], 4000)),
        finish,
        now + Duration::from_secs(3),
      )
      .unwrap();
    let established_report = established.shutdown().unwrap();
    assert!(matches!(
      established_report.events.as_slice(),
      [ClientCoordinatorEvent::Closed { crypto_cleanup, .. }]
        if crypto_cleanup.removed_established_context
          && crypto_cleanup.removed_pending_contexts == 0
    ));
  }

  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  enum ClientFault {
    StartAttempt,
    WrongStartCorrelation,
    WrongHelloFailureDomain,
    WrongHelloFailureAttempt,
    WrongAuthenticatedHelloAttempt,
    WrongHelloCleanupDisposition,
    PrepareClientFinish,
    WrongPreparedFinishAttempt,
    AuthenticateServerFinish,
    WrongFinishFailureDomain,
    WrongFinishFailureAttempt,
    WrongAuthenticatedFinishAttempt,
    CommitSession,
  }

  struct FaultyClientCrypto {
    inner: FakeClientCrypto,
    fault: ClientFault,
  }

  impl FaultyClientCrypto {
    fn new(fault: ClientFault) -> Self {
      Self {
        inner: coordinator().crypto,
        fault,
      }
    }
  }

  impl ClientHandshakeCrypto for FaultyClientCrypto {
    type ClientHelloPayload = FakeClientHello;
    type ServerHelloPayload = FakeServerHello;
    type ClientFinishPayload = FakeClientFinish;
    type ServerFinishPayload = FakeServerFinish;

    fn phase(&self) -> ClientCryptoPhase {
      self.inner.phase()
    }

    fn start_attempt(
      &mut self,
      attempt_id: ClientAttemptId,
    ) -> Result<PreparedClientHello<Self::ClientHelloPayload>, CryptoStateError> {
      if self.fault == ClientFault::StartAttempt {
        return Err(CryptoStateError::InvalidClientState {
          operation: ClientCryptoOperation::StartAttempt,
          phase: self.inner.phase(),
        });
      }
      let prepared = self.inner.start_attempt(attempt_id)?;
      if self.fault == ClientFault::WrongStartCorrelation {
        return Ok(PreparedClientHello::for_test(
          ClientAttemptId(999),
          *prepared.payload(),
        ));
      }
      Ok(prepared)
    }

    fn authenticate_server_hello(
      &mut self,
      attempt_id: ClientAttemptId,
      payload: Self::ServerHelloPayload,
    ) -> Result<CryptoOutcome<AuthenticatedServerHello>, CryptoStateError> {
      match self.fault {
        ClientFault::WrongHelloFailureDomain => Ok(CryptoOutcome::RemoteFailure(
          AuthenticationFailure::ServerCandidate {
            candidate_id: CandidateId::new(999),
            client_attempt_id: attempt_id,
            reason: AuthenticationFailureReason::InvalidProof,
          },
        )),
        ClientFault::WrongHelloFailureAttempt => Ok(CryptoOutcome::RemoteFailure(
          AuthenticationFailure::ClientAttempt {
            attempt_id: ClientAttemptId(999),
            reason: AuthenticationFailureReason::InvalidProof,
          },
        )),
        ClientFault::WrongHelloCleanupDisposition => Ok(CryptoOutcome::RemoteFailure(
          AuthenticationFailure::ClientAttempt {
            attempt_id,
            reason: AuthenticationFailureReason::InvalidProof,
          },
        )),
        ClientFault::WrongAuthenticatedHelloAttempt => {
          match self.inner.authenticate_server_hello(attempt_id, payload)? {
            CryptoOutcome::Success(_) => Ok(CryptoOutcome::Success(
              AuthenticatedServerHello::for_test(ClientAttemptId(999)),
            )),
            CryptoOutcome::RemoteFailure(failure) => Ok(CryptoOutcome::RemoteFailure(failure)),
          }
        }
        _ => self.inner.authenticate_server_hello(attempt_id, payload),
      }
    }

    fn prepare_client_finish(
      &self,
      attempt_id: ClientAttemptId,
    ) -> Result<PreparedClientFinish<Self::ClientFinishPayload>, CryptoStateError> {
      if self.fault == ClientFault::PrepareClientFinish {
        return Err(CryptoStateError::InvalidClientState {
          operation: ClientCryptoOperation::PrepareClientFinish,
          phase: self.inner.phase(),
        });
      }
      let prepared = self.inner.prepare_client_finish(attempt_id)?;
      if self.fault == ClientFault::WrongPreparedFinishAttempt {
        return Ok(PreparedClientFinish::for_test(
          ClientAttemptId(999),
          *prepared.payload(),
        ));
      }
      Ok(prepared)
    }

    fn authenticate_server_finish(
      &mut self,
      attempt_id: ClientAttemptId,
      payload: Self::ServerFinishPayload,
    ) -> Result<CryptoOutcome<AuthenticatedServerFinish>, CryptoStateError> {
      if self.fault == ClientFault::AuthenticateServerFinish {
        return Err(CryptoStateError::InvalidClientState {
          operation: ClientCryptoOperation::AuthenticateServerFinish,
          phase: self.inner.phase(),
        });
      }
      match self.fault {
        ClientFault::WrongFinishFailureDomain => Ok(CryptoOutcome::RemoteFailure(
          AuthenticationFailure::ServerCandidate {
            candidate_id: CandidateId::new(999),
            client_attempt_id: attempt_id,
            reason: AuthenticationFailureReason::InvalidProof,
          },
        )),
        ClientFault::WrongFinishFailureAttempt => Ok(CryptoOutcome::RemoteFailure(
          AuthenticationFailure::ClientAttempt {
            attempt_id: ClientAttemptId(999),
            reason: AuthenticationFailureReason::InvalidProof,
          },
        )),
        ClientFault::WrongAuthenticatedFinishAttempt => {
          match self.inner.authenticate_server_finish(attempt_id, payload)? {
            CryptoOutcome::Success(authenticated) => Ok(CryptoOutcome::Success(
              AuthenticatedServerFinish::for_test(ClientAttemptId(999), authenticated.metadata()),
            )),
            CryptoOutcome::RemoteFailure(failure) => Ok(CryptoOutcome::RemoteFailure(failure)),
          }
        }
        _ => self.inner.authenticate_server_finish(attempt_id, payload),
      }
    }

    fn commit_session(
      &mut self,
      attempt_id: ClientAttemptId,
      metadata: EstablishedSessionMetadata,
    ) -> Result<(), CryptoStateError> {
      if self.fault == ClientFault::CommitSession {
        return Err(CryptoStateError::AuthenticatedMetadataMismatch);
      }
      self.inner.commit_session(attempt_id, metadata)
    }

    fn reject_authenticated_session(
      &mut self,
      attempt_id: ClientAttemptId,
    ) -> Result<ClientContextRemoval, CryptoStateError> {
      self.inner.reject_authenticated_session(attempt_id)
    }

    fn close_context(
      &mut self,
      attempt_id: ClientAttemptId,
    ) -> Result<ClientContextRemoval, CryptoStateError> {
      if self.fault == ClientFault::WrongHelloCleanupDisposition {
        return Ok(ClientContextRemoval::AlreadyAbsent);
      }
      self.inner.close_context(attempt_id)
    }

    fn shutdown(&mut self) -> CryptoShutdownOutcome {
      self.inner.shutdown()
    }
  }

  fn client_fault_error(fault: ClientFault) -> FatalCoordinatorError {
    let policy =
      ClientHandshake::new(SocketAddr::from(([192, 0, 2, 1], 4000)), HANDSHAKE_TIMEOUT).unwrap();
    let mut client =
      ClientHandshakeCoordinator::build(policy, FaultyClientCrypto::new(fault)).unwrap();
    let now = Instant::now();
    let start = match client.start(now) {
      Ok(report) => report,
      Err(error) => return error,
    };
    let client_hello = match start.outbound.into_iter().next().unwrap() {
      ClientHandshakeMessage::ClientHello(message) => message,
      ClientHandshakeMessage::ClientFinish(_) => panic!("expected ClientHello"),
    };
    let mut server = server_coordinator();
    let server_hello = match server
      .receive_client_hello(SocketAddr::from(([192, 0, 2, 1], 5000)), client_hello, now)
      .unwrap()
      .outbound
      .into_iter()
      .next()
      .unwrap()
      .message
    {
      ServerHandshakeMessage::ServerHello(message) => message,
      ServerHandshakeMessage::ServerFinish(_) => panic!("expected ServerHello"),
    };
    let client_finish = match client.receive_server_hello(
      SocketAddr::from(([192, 0, 2, 1], 4000)),
      server_hello,
      now + Duration::from_secs(1),
    ) {
      Ok(report) => match report.outbound.into_iter().next().unwrap() {
        ClientHandshakeMessage::ClientFinish(message) => message,
        ClientHandshakeMessage::ClientHello(_) => panic!("expected ClientFinish"),
      },
      Err(error) => return error,
    };
    let server_finish = match server
      .receive_client_finish(
        SocketAddr::from(([192, 0, 2, 1], 5000)),
        client_finish,
        now + Duration::from_secs(2),
      )
      .unwrap()
      .outbound
      .into_iter()
      .next()
      .unwrap()
      .message
    {
      ServerHandshakeMessage::ServerFinish(message) => message,
      ServerHandshakeMessage::ServerHello(_) => panic!("expected ServerFinish"),
    };
    client
      .receive_server_finish(
        SocketAddr::from(([192, 0, 2, 1], 4000)),
        server_finish,
        now + Duration::from_secs(3),
      )
      .unwrap_err()
  }

  #[test]
  fn client_crypto_local_errors_fail_closed_at_every_transaction_boundary() {
    assert!(matches!(
      client_fault_error(ClientFault::StartAttempt).primary,
      CoordinatorPrimaryError::Crypto(CryptoStateError::InvalidClientState {
        operation: ClientCryptoOperation::StartAttempt,
        ..
      })
    ));
    assert!(matches!(
      client_fault_error(ClientFault::PrepareClientFinish).primary,
      CoordinatorPrimaryError::Crypto(CryptoStateError::InvalidClientState {
        operation: ClientCryptoOperation::PrepareClientFinish,
        ..
      })
    ));
    assert!(matches!(
      client_fault_error(ClientFault::AuthenticateServerFinish).primary,
      CoordinatorPrimaryError::Crypto(CryptoStateError::InvalidClientState {
        operation: ClientCryptoOperation::AuthenticateServerFinish,
        ..
      })
    ));
    let commit_error = client_fault_error(ClientFault::CommitSession);
    assert!(matches!(
      commit_error.primary,
      CoordinatorPrimaryError::Crypto(CryptoStateError::AuthenticatedMetadataMismatch)
    ));
    assert!(commit_error.crypto_cleanup.removed_pending_commit);
  }

  #[test]
  fn client_crypto_contract_violations_fail_closed_with_typed_invariants() {
    assert!(matches!(
      client_fault_error(ClientFault::WrongStartCorrelation).primary,
      CoordinatorPrimaryError::Invariant(CoordinatorInvariantError::AttemptMismatch { .. })
    ));
    assert!(matches!(
      client_fault_error(ClientFault::WrongHelloFailureDomain).primary,
      CoordinatorPrimaryError::Invariant(CryptoFailureCorrelationMismatch)
    ));
    assert!(matches!(
      client_fault_error(ClientFault::WrongHelloFailureAttempt).primary,
      CoordinatorPrimaryError::Invariant(CoordinatorInvariantError::AttemptMismatch { .. })
    ));
    assert!(matches!(
      client_fault_error(ClientFault::WrongAuthenticatedHelloAttempt).primary,
      CoordinatorPrimaryError::Invariant(CoordinatorInvariantError::AttemptMismatch { .. })
    ));
    assert!(matches!(
      client_fault_error(ClientFault::WrongHelloCleanupDisposition).primary,
      CoordinatorPrimaryError::Invariant(CoordinatorInvariantError::ClientContextCleanupMismatch {
        expected: ClientContextRemoval::Removed,
        observed: ClientContextRemoval::AlreadyAbsent,
        ..
      })
    ));
    assert!(matches!(
      client_fault_error(ClientFault::WrongPreparedFinishAttempt).primary,
      CoordinatorPrimaryError::Invariant(CoordinatorInvariantError::AttemptMismatch { .. })
    ));
    assert!(matches!(
      client_fault_error(ClientFault::WrongFinishFailureDomain).primary,
      CoordinatorPrimaryError::Invariant(CryptoFailureCorrelationMismatch)
    ));
    assert!(matches!(
      client_fault_error(ClientFault::WrongFinishFailureAttempt).primary,
      CoordinatorPrimaryError::Invariant(CoordinatorInvariantError::AttemptMismatch { .. })
    ));
    assert!(matches!(
      client_fault_error(ClientFault::WrongAuthenticatedFinishAttempt).primary,
      CoordinatorPrimaryError::Invariant(CoordinatorInvariantError::AttemptMismatch { .. })
    ));
  }
}
