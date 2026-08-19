use std::{net::SocketAddr, time::Instant};

use crate::{
  crypto::{
    server::ServerHandshakeCrypto,
    types::{AuthenticationFailure, CryptoOutcome, ServerCandidateRemoval, ServerCryptoPhase},
  },
  handshake::types::{
    ClientFinish, ClientHello, CoordinatorBuildError,
    CoordinatorInvariantError::{
      self, CryptoFailureCorrelationMismatch, CryptoResultCorrelationMismatch,
      UnexpectedServerEffect, UnexpectedServerReport,
    },
    CoordinatorLifecycle, CoordinatorPolicyCleanup, CoordinatorPrimaryError, FatalCoordinatorError,
    ServerCoordinatorEvent, ServerCoordinatorReport, ServerCoordinatorResult, ServerFinish,
    ServerHandshakeMessage, ServerHello, ServerOutbound,
  },
  session::{
    server::{
      ExpiredServerCandidate, ServerCandidateAbortOutcome, ServerClientFinishDecision,
      ServerDropReason, ServerEffect, ServerHandshake, ServerHelloAdmission, ServerStateName,
    },
    types::EstablishedSessionMetadata,
  },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerClientFinishMode {
  PendingCandidate,
  EstablishedDuplicate {
    expected_metadata: EstablishedSessionMetadata,
  },
}

pub(crate) struct ServerHandshakeCoordinator<C>
where
  C: ServerHandshakeCrypto,
{
  policy: ServerHandshake,
  crypto: C,
  lifecycle: CoordinatorLifecycle,
}

impl<C> ServerHandshakeCoordinator<C>
where
  C: ServerHandshakeCrypto,
{
  pub(crate) fn build(
    policy: ServerHandshake,
    crypto: C,
  ) -> Result<ServerHandshakeCoordinator<C>, CoordinatorBuildError> {
    if policy.state_name() != ServerStateName::Listening {
      return Err(CoordinatorBuildError::UnexpectedInitialServerPolicyState {
        observed: policy.state_name(),
      });
    }

    let status = crypto.non_secret_status();
    if !status.is_fresh() {
      return Err(CoordinatorBuildError::ServerCryptoNotFresh { observed: status });
    }

    Ok(Self {
      policy,
      crypto,
      lifecycle: CoordinatorLifecycle::Running,
    })
  }

  pub(crate) fn receive_client_hello(
    &mut self,
    source: SocketAddr,
    message: ClientHello<C::ClientHelloPayload>,
    now: Instant,
  ) -> ServerCoordinatorResult<C::ServerHelloPayload, C::ServerFinishPayload> {
    let policy_result =
      match self
        .policy
        .handle_valid_client_hello(source, message.client_attempt_id, now)
      {
        Ok(policy_result) => policy_result,
        Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::ServerPolicy(err))),
      };

    let mut report: ServerCoordinatorReport<C::ServerHelloPayload, C::ServerFinishPayload> =
      match self.reconcile_expired(policy_result.expired) {
        Ok(expiration_events) => ServerCoordinatorReport {
          outbound: vec![],
          events: expiration_events,
        },
        Err(primary) => return Err(self.fail_closed(primary)),
      };

    let (destination, candidate_id, client_attempt_id, admission) = match policy_result
      .effects
      .as_slice()
    {
      [ServerEffect::Dropped {
        source: effect_source,
        reason,
      }] => {
        if *effect_source != source {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(UnexpectedServerEffect)));
        }
        report.events.push(ServerCoordinatorEvent::Dropped {
          source,
          reason: *reason,
        });

        match verify_server_stable(&self.policy, &self.crypto) {
          Ok(_) => return Ok(report),
          Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(err))),
        };
      }
      [ServerEffect::SendServerHello {
        destination,
        candidate_id,
        client_attempt_id,
        admission,
      }] => {
        if *destination != source || *client_attempt_id != message.client_attempt_id {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(UnexpectedServerEffect)));
        }
        (*destination, *candidate_id, *client_attempt_id, *admission)
      }
      _ => {
        return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(UnexpectedServerEffect)));
      }
    };

    let outcome =
      match self
        .crypto
        .prepare_server_hello(candidate_id, client_attempt_id, message.payload)
      {
        Ok(outcome) => outcome,
        Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Crypto(err))),
      };

    let prepared = match outcome {
      CryptoOutcome::RemoteFailure(AuthenticationFailure::ClientAttempt { .. }) => {
        return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
          CoordinatorInvariantError::CryptoFailureCorrelationMismatch,
        )));
      }
      CryptoOutcome::RemoteFailure(AuthenticationFailure::ServerCandidate {
        candidate_id: observed_candidate,
        client_attempt_id: observed_attempt,
        reason: _,
      }) => {
        if observed_candidate != candidate_id || observed_attempt != client_attempt_id {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
            CoordinatorInvariantError::CryptoFailureCorrelationMismatch,
          )));
        }

        match self
          .policy
          .abort_exact_candidate(source, candidate_id, client_attempt_id)
        {
          Ok(ServerCandidateAbortOutcome::Removed) => {}
          Err(error) => {
            return Err(self.fail_closed(CoordinatorPrimaryError::ServerPolicy(error)));
          }
        }

        match self
          .crypto
          .remove_candidate(candidate_id, client_attempt_id)
        {
          Ok(removal) => {
            let expected_removal = match admission {
              ServerHelloAdmission::NewCandidate => ServerCandidateRemoval::AlreadyAbsent,
              ServerHelloAdmission::ExistingCandidate => ServerCandidateRemoval::Removed,
            };
            if removal != expected_removal {
              return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
                CoordinatorInvariantError::CandidateCleanupMismatch {
                  candidate_id,
                  expected: expected_removal,
                  observed: removal,
                },
              )));
            }
          }
          Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Crypto(err))),
        };

        match verify_server_stable(&self.policy, &self.crypto) {
          Ok(()) => {
            report.events.push(ServerCoordinatorEvent::Dropped {
              source,
              reason: ServerDropReason::AuthenticationFailed,
            });
            return Ok(report);
          }
          Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(err))),
        };
      }
      CryptoOutcome::Success(prepared) => prepared,
    };

    if prepared.candidate_id() != candidate_id || prepared.client_attempt_id() != client_attempt_id
    {
      return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
        CryptoResultCorrelationMismatch,
      )));
    }

    match verify_server_stable(&self.policy, &self.crypto) {
      Ok(()) => {
        report.outbound.push(ServerOutbound {
          destination,
          message: ServerHandshakeMessage::ServerHello(ServerHello {
            client_attempt_id,
            payload: prepared.into_payload(),
          }),
        });
        Ok(report)
      }
      Err(err) => Err(self.fail_closed(CoordinatorPrimaryError::Invariant(err))),
    }
  }

  fn fail_closed(&mut self, primary: CoordinatorPrimaryError) -> FatalCoordinatorError {
    let policy_action = self.policy.shutdown();
    let (policy_report, policy_error) = match policy_action {
      Ok(report) => (Some(report), None),
      Err(err) => (None, Some(err)),
    };
    let crypto_cleanup = self.crypto.shutdown();

    self.lifecycle = CoordinatorLifecycle::Closed;

    FatalCoordinatorError {
      primary,
      policy_cleanup: CoordinatorPolicyCleanup::Server {
        report: policy_report,
        error: policy_error,
      },
      crypto_cleanup,
    }
  }

  pub(crate) fn receive_client_finish(
    &mut self,
    source: SocketAddr,
    message: ClientFinish<C::ClientFinishPayload>,
    now: Instant,
  ) -> ServerCoordinatorResult<C::ServerHelloPayload, C::ServerFinishPayload> {
    let precheck = match self
      .policy
      .precheck_client_finish(source, message.client_attempt_id, now)
    {
      Ok(precheck) => precheck,
      Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::ServerPolicy(err))),
    };

    let mut report: ServerCoordinatorReport<C::ServerHelloPayload, C::ServerFinishPayload> =
      match self.reconcile_expired(precheck.expired) {
        Ok(expiration_events) => ServerCoordinatorReport {
          outbound: vec![],
          events: expiration_events,
        },
        Err(err) => return Err(self.fail_closed(err)),
      };

    let (candidate_id, mode, permitted_attempt) = match precheck.decision {
      ServerClientFinishDecision::Drop { reason } => {
        report
          .events
          .push(ServerCoordinatorEvent::Dropped { source, reason });
        match verify_server_stable(&self.policy, &self.crypto) {
          Ok(()) => return Ok(report),
          Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(err))),
        }
      }
      ServerClientFinishDecision::PermitNew {
        candidate_id,
        client_attempt_id: permitted_attempt,
      } => (
        candidate_id,
        ServerClientFinishMode::PendingCandidate,
        permitted_attempt,
      ),
      ServerClientFinishDecision::PermitDuplicate {
        candidate_id,
        client_attempt_id: permitted_attempt,
        expected_metadata: committed_metadata,
      } => (
        candidate_id,
        ServerClientFinishMode::EstablishedDuplicate {
          expected_metadata: committed_metadata,
        },
        permitted_attempt,
      ),
    };

    let outcome =
      match self
        .crypto
        .authenticate_client_finish(candidate_id, permitted_attempt, message.payload)
      {
        Ok(outcome) => outcome,
        Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Crypto(err))),
      };

    let authenticated = match outcome {
      CryptoOutcome::RemoteFailure(AuthenticationFailure::ClientAttempt { .. }) => {
        return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
          CryptoFailureCorrelationMismatch,
        )));
      }
      CryptoOutcome::RemoteFailure(AuthenticationFailure::ServerCandidate {
        candidate_id: observed_candidate,
        client_attempt_id: observed_attempt,
        reason: _,
      }) => {
        if observed_candidate != candidate_id || observed_attempt != permitted_attempt {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
            CryptoFailureCorrelationMismatch,
          )));
        }
        match mode {
          ServerClientFinishMode::EstablishedDuplicate { .. } => {
            match verify_server_stable(&self.policy, &self.crypto) {
              Ok(()) => {
                report.events.push(ServerCoordinatorEvent::Dropped {
                  source,
                  reason: ServerDropReason::AuthenticationFailed,
                });
                return Ok(report);
              }
              Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(err))),
            }
          }
          ServerClientFinishMode::PendingCandidate => {
            match self
              .policy
              .abort_exact_candidate(source, candidate_id, permitted_attempt)
            {
              Ok(ServerCandidateAbortOutcome::Removed) => {}
              Err(err) => {
                return Err(self.fail_closed(CoordinatorPrimaryError::ServerPolicy(err)));
              }
            }

            match self
              .crypto
              .remove_candidate(candidate_id, permitted_attempt)
            {
              Ok(removal) => {
                if removal != ServerCandidateRemoval::Removed {
                  return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
                    CoordinatorInvariantError::CandidateCleanupMismatch {
                      candidate_id,
                      expected: ServerCandidateRemoval::Removed,
                      observed: removal,
                    },
                  )));
                }
              }
              Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Crypto(err))),
            }

            match verify_server_stable(&self.policy, &self.crypto) {
              Ok(()) => {
                report.events.push(ServerCoordinatorEvent::Dropped {
                  source,
                  reason: ServerDropReason::AuthenticationFailed,
                });
                return Ok(report);
              }
              Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(err))),
            }
          }
        }
      }
      CryptoOutcome::Success(authenticated) => authenticated,
    };

    if authenticated.candidate_id() != candidate_id
      || authenticated.client_attempt_id() != permitted_attempt
    {
      return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
        CryptoResultCorrelationMismatch,
      )));
    }

    match mode {
      ServerClientFinishMode::EstablishedDuplicate { expected_metadata } => {
        if authenticated.metadata() != expected_metadata {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
            CoordinatorInvariantError::SessionMetadataMismatch {
              expected: expected_metadata,
              observed: authenticated.metadata(),
            },
          )));
        }

        let prepared = match self.crypto.prepare_server_finish(
          candidate_id,
          permitted_attempt,
          authenticated.metadata().session_id,
        ) {
          Ok(prepared) => prepared,
          Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Crypto(err))),
        };

        if prepared.candidate_id() != candidate_id
          || prepared.client_attempt_id() != permitted_attempt
          || prepared.session_id() != authenticated.metadata().session_id
        {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
            CryptoResultCorrelationMismatch,
          )));
        }

        match verify_server_stable(&self.policy, &self.crypto) {
          Ok(()) => {
            report.outbound.push(ServerOutbound {
              destination: source,
              message: ServerHandshakeMessage::ServerFinish(ServerFinish {
                client_attempt_id: permitted_attempt,
                payload: prepared.into_payload(),
              }),
            });
            Ok(report)
          }
          Err(err) => Err(self.fail_closed(CoordinatorPrimaryError::Invariant(err))),
        }
      }
      ServerClientFinishMode::PendingCandidate => {
        let policy_report = match self.policy.handle_authenticated_client_finish(
          source,
          candidate_id,
          permitted_attempt,
          authenticated.metadata(),
          now,
        ) {
          Ok(policy_report) => policy_report,
          Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::ServerPolicy(err))),
        };

        if !policy_report.expired.is_empty() {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(UnexpectedServerReport)));
        }

        match policy_report.effects.as_slice() {
          [ServerEffect::SendServerFinish {
            destination,
            candidate_id: effect_candidate,
            client_attempt_id: effect_attempt,
            session_id: effect_session,
          }, ServerEffect::SessionEstablished {
            source: effect_source,
            session_id: established_session,
          }] => {
            if *destination != source
              || *effect_source != source
              || *effect_candidate != candidate_id
              || *effect_attempt != permitted_attempt
              || *effect_session != authenticated.metadata().session_id
              || *established_session != authenticated.metadata().session_id
            {
              return Err(
                self.fail_closed(CoordinatorPrimaryError::Invariant(UnexpectedServerEffect)),
              );
            }
          }
          _ => {
            return Err(
              self.fail_closed(CoordinatorPrimaryError::Invariant(UnexpectedServerEffect)),
            );
          }
        };

        match self
          .crypto
          .commit_session(candidate_id, permitted_attempt, authenticated.metadata())
        {
          Ok(()) => {}
          Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Crypto(err))),
        };
        let prepared = match self.crypto.prepare_server_finish(
          candidate_id,
          permitted_attempt,
          authenticated.metadata().session_id,
        ) {
          Ok(prepared) => prepared,
          Err(err) => return Err(self.fail_closed(CoordinatorPrimaryError::Crypto(err))),
        };

        if prepared.candidate_id() != candidate_id
          || prepared.client_attempt_id() != permitted_attempt
          || prepared.session_id() != authenticated.metadata().session_id
        {
          return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
            CryptoResultCorrelationMismatch,
          )));
        };

        match verify_server_stable(&self.policy, &self.crypto) {
          Ok(()) => {
            report
              .events
              .push(ServerCoordinatorEvent::SessionEstablished {
                source,
                metadata: authenticated.metadata(),
              });
            report.outbound.push(ServerOutbound {
              destination: source,
              message: ServerHandshakeMessage::ServerFinish(ServerFinish {
                client_attempt_id: permitted_attempt,
                payload: prepared.into_payload(),
              }),
            });
            Ok(report)
          }
          Err(err) => Err(self.fail_closed(CoordinatorPrimaryError::Invariant(err))),
        }
      }
    }
  }

  fn reconcile_expired(
    &mut self,
    expired: Vec<ExpiredServerCandidate>,
  ) -> Result<Vec<ServerCoordinatorEvent>, CoordinatorPrimaryError> {
    let mut events = vec![];

    for candidate in expired {
      match self
        .crypto
        .remove_candidate(candidate.candidate_id, candidate.client_attempt_id)
      {
        Ok(removal) => {
          if removal != ServerCandidateRemoval::Removed {
            return Err(CoordinatorPrimaryError::Invariant(
              CoordinatorInvariantError::CandidateCleanupMismatch {
                candidate_id: candidate.candidate_id,
                expected: ServerCandidateRemoval::Removed,
                observed: removal,
              },
            ));
          }
        }
        Err(err) => return Err(CoordinatorPrimaryError::Crypto(err)),
      };

      events.push(ServerCoordinatorEvent::CandidateExpired {
        candidate_id: candidate.candidate_id,
        source: candidate.source,
        client_attempt_id: candidate.client_attempt_id,
      });
    }

    Ok(events)
  }

  /// Returns the nearest deadline owned by the server session policy.
  pub(crate) fn next_deadline(&self) -> Option<Instant> {
    self.policy.next_deadline()
  }

  pub(crate) fn check_timeouts(
    &mut self,
    now: Instant,
  ) -> ServerCoordinatorResult<C::ServerHelloPayload, C::ServerFinishPayload> {
    let policy_report = match self.policy.check_timeouts(now) {
      Ok(report) => report,
      Err(error) => return Err(self.fail_closed(CoordinatorPrimaryError::ServerPolicy(error))),
    };

    if !policy_report.effects.is_empty() {
      return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(
        CoordinatorInvariantError::UnexpectedServerEffect,
      )));
    }

    let events = match self.reconcile_expired(policy_report.expired) {
      Ok(events) => events,
      Err(primary) => return Err(self.fail_closed(primary)),
    };

    if let Err(error) = verify_server_stable(&self.policy, &self.crypto) {
      return Err(self.fail_closed(CoordinatorPrimaryError::Invariant(error)));
    }

    Ok(ServerCoordinatorReport {
      outbound: vec![],
      events,
    })
  }

  pub(crate) fn shutdown(
    &mut self,
  ) -> ServerCoordinatorResult<C::ServerHelloPayload, C::ServerFinishPayload> {
    let policy_result = self.policy.shutdown();
    let crypto_cleanup = self.crypto.shutdown();
    self.lifecycle = CoordinatorLifecycle::Closed;

    let policy_report = match policy_result {
      Ok(report) => report,
      Err(error) => {
        return Err(FatalCoordinatorError {
          primary: CoordinatorPrimaryError::ServerPolicy(error),
          policy_cleanup: CoordinatorPolicyCleanup::Server {
            report: None,
            error: Some(error),
          },
          crypto_cleanup,
        });
      }
    };

    if let Err(error) = verify_server_stable(&self.policy, &self.crypto) {
      return Err(FatalCoordinatorError {
        primary: CoordinatorPrimaryError::Invariant(error),
        policy_cleanup: CoordinatorPolicyCleanup::Server {
          report: Some(policy_report),
          error: None,
        },
        crypto_cleanup,
      });
    }

    if !policy_report.expired.is_empty() {
      return Err(FatalCoordinatorError {
        primary: CoordinatorPrimaryError::Invariant(
          CoordinatorInvariantError::UnexpectedServerReport,
        ),
        policy_cleanup: CoordinatorPolicyCleanup::Server {
          report: Some(policy_report),
          error: None,
        },
        crypto_cleanup,
      });
    }

    let event = match policy_report.effects.as_slice() {
      [ServerEffect::Closed {
        removed_candidates,
        removed_session,
      }] => ServerCoordinatorEvent::Closed {
        policy_removed_candidates: *removed_candidates,
        policy_removed_session: *removed_session,
        crypto_cleanup,
      },
      [ServerEffect::AlreadyClosed] if crypto_cleanup.already_closed => {
        ServerCoordinatorEvent::AlreadyClosed
      }
      [ServerEffect::AlreadyClosed] => ServerCoordinatorEvent::Closed {
        policy_removed_candidates: 0,
        policy_removed_session: false,
        crypto_cleanup,
      },
      _ => {
        return Err(FatalCoordinatorError {
          primary: CoordinatorPrimaryError::Invariant(
            CoordinatorInvariantError::UnexpectedServerEffect,
          ),
          policy_cleanup: CoordinatorPolicyCleanup::Server {
            report: Some(policy_report),
            error: None,
          },
          crypto_cleanup,
        });
      }
    };

    Ok(ServerCoordinatorReport {
      outbound: vec![],
      events: vec![event],
    })
  }
}

fn verify_server_stable<C>(
  policy: &ServerHandshake,
  crypto: &C,
) -> Result<(), CoordinatorInvariantError>
where
  C: ServerHandshakeCrypto,
{
  let policy_name = policy.state_name();
  let status = crypto.non_secret_status();
  let expected_phase = match policy_name {
    ServerStateName::Listening => ServerCryptoPhase::Running,
    ServerStateName::Established => ServerCryptoPhase::Established,
    ServerStateName::Closed => ServerCryptoPhase::Closed,
  };

  if status.phase != expected_phase {
    return Err(CoordinatorInvariantError::ServerPhaseMismatch {
      policy: policy_name,
      crypto: status.phase,
    });
  }

  if policy_name == ServerStateName::Listening
    && policy.pending_candidate_count() != status.pending_contexts
  {
    return Err(
      CoordinatorInvariantError::ServerPendingContextCountMismatch {
        policy_pending: policy.pending_candidate_count(),
        crypto_pending: status.pending_contexts,
      },
    );
  }

  let expected_shape = match policy_name {
    ServerStateName::Listening => !status.has_pending_commit && !status.has_established_context,
    ServerStateName::Established => {
      status.pending_contexts == 0 && !status.has_pending_commit && status.has_established_context
    }
    ServerStateName::Closed => {
      status.pending_contexts == 0 && !status.has_pending_commit && !status.has_established_context
    }
  };

  if !expected_shape {
    return Err(CoordinatorInvariantError::ServerCryptoStatusMismatch {
      policy: policy_name,
      observed: status,
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
      client::ClientHandshakeCrypto,
      fake::{
        FakeClientCrypto, FakeClientCryptoConfig, FakeClientFinish, FakeClientHello,
        FakeCredential, FakeServerCrypto, FakeServerCryptoConfig, FakeServerFinish,
        FakeServerHello,
      },
      server::{ServerCryptoStatus, ServerHandshakeCrypto},
      types::{
        AuthenticatedClientFinish, AuthenticationFailureReason, CryptoShutdownOutcome,
        CryptoStateError, PreparedServerFinish, PreparedServerHello, ServerCryptoOperation,
      },
    },
    session::{
      types::{ClientAttemptId, PeerIdentity, SessionId},
      CandidateId, SessionPolicy,
    },
  };

  const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
  const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
  const CLIENT_IDENTITY: PeerIdentity = PeerIdentity::from_u64(11);
  const SERVER_IDENTITY: PeerIdentity = PeerIdentity::from_u64(22);

  type TestServerCoordinator = ServerHandshakeCoordinator<FakeServerCrypto>;

  fn source(port: u16) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 1], port))
  }

  fn credential() -> FakeCredential {
    FakeCredential::new(NonZeroU64::new(7).unwrap())
  }

  fn client_crypto() -> FakeClientCrypto {
    let config =
      FakeClientCryptoConfig::new(credential(), CLIENT_IDENTITY, SERVER_IDENTITY).unwrap();
    FakeClientCrypto::new(config)
  }

  fn server_crypto() -> FakeServerCrypto {
    let config = FakeServerCryptoConfig::new(
      credential(),
      SERVER_IDENTITY,
      CLIENT_IDENTITY,
      NonZeroU64::new(100).unwrap(),
    )
    .unwrap();
    FakeServerCrypto::new(config)
  }

  fn server_policy(maximum_pending: usize) -> ServerHandshake {
    ServerHandshake::new(
      SessionPolicy::new(maximum_pending, HANDSHAKE_TIMEOUT, IDLE_TIMEOUT).unwrap(),
    )
  }

  fn server_coordinator(maximum_pending: usize) -> TestServerCoordinator {
    ServerHandshakeCoordinator::build(server_policy(maximum_pending), server_crypto()).unwrap()
  }

  fn prepare_client_finish<C>(
    server: &mut ServerHandshakeCoordinator<C>,
    peer: SocketAddr,
    attempt_id: ClientAttemptId,
    now: Instant,
  ) -> ClientFinish<FakeClientFinish>
  where
    C: ServerHandshakeCrypto<
      ClientHelloPayload = FakeClientHello,
      ServerHelloPayload = FakeServerHello,
      ClientFinishPayload = FakeClientFinish,
      ServerFinishPayload = FakeServerFinish,
    >,
  {
    let mut client = client_crypto();
    let client_hello = client.start_attempt(attempt_id).unwrap().into_payload();
    let server_report = server
      .receive_client_hello(
        peer,
        ClientHello {
          client_attempt_id: attempt_id,
          payload: client_hello,
        },
        now,
      )
      .unwrap();

    let mut outbound = server_report.outbound.into_iter();
    let server_hello = match outbound.next().unwrap().message {
      ServerHandshakeMessage::ServerHello(server_hello) => server_hello,
      ServerHandshakeMessage::ServerFinish(_) => panic!("expected ServerHello"),
    };
    assert!(outbound.next().is_none());

    assert!(matches!(
      client
        .authenticate_server_hello(attempt_id, server_hello.payload)
        .unwrap(),
      CryptoOutcome::Success(_)
    ));

    ClientFinish {
      client_attempt_id: attempt_id,
      payload: client
        .prepare_client_finish(attempt_id)
        .unwrap()
        .into_payload(),
    }
  }

  fn client_hello(attempt_id: ClientAttemptId) -> ClientHello<FakeClientHello> {
    ClientHello {
      client_attempt_id: attempt_id,
      payload: client_crypto()
        .start_attempt(attempt_id)
        .unwrap()
        .into_payload(),
    }
  }

  #[test]
  fn receive_client_hello_admits_once_and_replays_identical_response() {
    let mut server = server_coordinator(1);
    let now = Instant::now();
    let peer = source(4000);
    let hello = client_hello(ClientAttemptId(1));

    let first = server
      .receive_client_hello(peer, hello.clone(), now)
      .unwrap();
    let duplicate = server
      .receive_client_hello(peer, hello, now + Duration::from_secs(1))
      .unwrap();

    assert!(first.events.is_empty());
    assert!(duplicate.events.is_empty());
    assert_eq!(first.outbound, duplicate.outbound);
    assert_eq!(server.policy.pending_candidate_count(), 1);
    assert_eq!(server.crypto.non_secret_status().pending_contexts, 1);
  }

  #[test]
  fn receive_client_hello_remote_failure_removes_exact_candidate() {
    let mut server = server_coordinator(1);
    let now = Instant::now();
    let peer = source(4000);
    let valid = client_hello(ClientAttemptId(1));
    let modified = ClientHello {
      client_attempt_id: valid.client_attempt_id,
      payload: valid.payload.with_corrupted_proof(),
    };

    let report = server.receive_client_hello(peer, modified, now).unwrap();

    assert!(report.outbound.is_empty());
    assert!(matches!(
      report.events.as_slice(),
      [ServerCoordinatorEvent::Dropped {
        source,
        reason: ServerDropReason::AuthenticationFailed,
      }] if *source == peer
    ));
    assert_eq!(server.policy.pending_candidate_count(), 0);
    assert_eq!(server.crypto.non_secret_status().pending_contexts, 0);
    assert_eq!(server.policy.state_name(), ServerStateName::Listening);
    assert_eq!(server.crypto.phase(), ServerCryptoPhase::Running);
  }

  #[test]
  fn receive_modified_duplicate_client_hello_removes_existing_candidate_context() {
    let mut server = server_coordinator(1);
    let now = Instant::now();
    let peer = source(4000);
    let hello = client_hello(ClientAttemptId(1));
    server
      .receive_client_hello(peer, hello.clone(), now)
      .unwrap();
    let modified = ClientHello {
      client_attempt_id: hello.client_attempt_id,
      payload: hello.payload.with_corrupted_proof(),
    };

    let report = server
      .receive_client_hello(peer, modified, now + Duration::from_secs(1))
      .unwrap();

    assert!(report.outbound.is_empty());
    assert!(matches!(
      report.events.as_slice(),
      [ServerCoordinatorEvent::Dropped {
        source,
        reason: ServerDropReason::AuthenticationFailed,
      }] if *source == peer
    ));
    assert_eq!(server.policy.pending_candidate_count(), 0);
    assert_eq!(server.crypto.non_secret_status().pending_contexts, 0);
  }

  #[test]
  fn receive_client_hello_capacity_drop_does_not_replace_pending_candidate() {
    let mut server = server_coordinator(1);
    let now = Instant::now();
    server
      .receive_client_hello(source(4000), client_hello(ClientAttemptId(1)), now)
      .unwrap();

    let report = server
      .receive_client_hello(source(4001), client_hello(ClientAttemptId(2)), now)
      .unwrap();

    assert!(report.outbound.is_empty());
    assert!(matches!(
      report.events.as_slice(),
      [ServerCoordinatorEvent::Dropped {
        source: dropped_source,
        reason: ServerDropReason::PendingCapacityReached { maximum_pending: 1 },
      }] if *dropped_source == source(4001)
    ));
    assert_eq!(server.policy.pending_candidate_count(), 1);
    assert_eq!(server.crypto.non_secret_status().pending_contexts, 1);
  }

  #[test]
  fn receive_client_hello_reports_expiration_before_new_outbound() {
    let mut server = server_coordinator(1);
    let now = Instant::now();
    server
      .receive_client_hello(source(4000), client_hello(ClientAttemptId(1)), now)
      .unwrap();

    let report = server
      .receive_client_hello(
        source(4001),
        client_hello(ClientAttemptId(2)),
        now + HANDSHAKE_TIMEOUT,
      )
      .unwrap();

    assert!(matches!(
      report.events.as_slice(),
      [ServerCoordinatorEvent::CandidateExpired {
        source: expired_source,
        client_attempt_id: ClientAttemptId(1),
        ..
      }] if *expired_source == source(4000)
    ));
    assert!(matches!(
      report.outbound.as_slice(),
      [ServerOutbound {
        destination,
        message: ServerHandshakeMessage::ServerHello(ServerHello {
          client_attempt_id: ClientAttemptId(2),
          ..
        }),
      }] if *destination == source(4001)
    ));
    assert_eq!(server.policy.pending_candidate_count(), 1);
    assert_eq!(server.crypto.non_secret_status().pending_contexts, 1);
  }

  #[test]
  fn receive_client_finish_establishes_and_exact_duplicate_only_resends() {
    let mut server = server_coordinator(1);
    let now = Instant::now();
    let peer = source(4000);
    let finish = prepare_client_finish(&mut server, peer, ClientAttemptId(1), now);
    let duplicate = finish.clone();

    let established = server
      .receive_client_finish(peer, finish, now + Duration::from_secs(1))
      .unwrap();
    assert!(matches!(
      established.events.as_slice(),
      [ServerCoordinatorEvent::SessionEstablished { source, metadata }]
        if *source == peer && metadata.session_id == SessionId::from_u64(100)
    ));
    assert!(matches!(
      established.outbound.as_slice(),
      [ServerOutbound {
        destination,
        message: ServerHandshakeMessage::ServerFinish(ServerFinish {
          client_attempt_id: ClientAttemptId(1),
          ..
        }),
      }] if *destination == peer
    ));

    let duplicate_report = server
      .receive_client_finish(peer, duplicate, now + Duration::from_secs(2))
      .unwrap();
    assert!(duplicate_report.events.is_empty());
    assert!(matches!(
      duplicate_report.outbound.as_slice(),
      [ServerOutbound {
        destination,
        message: ServerHandshakeMessage::ServerFinish(_),
      }] if *destination == peer
    ));
    assert_eq!(server.policy.state_name(), ServerStateName::Established);
    assert_eq!(server.crypto.phase(), ServerCryptoPhase::Established);
  }

  #[test]
  fn receive_client_finish_modified_duplicate_preserves_established_session() {
    let mut server = server_coordinator(1);
    let now = Instant::now();
    let peer = source(4000);
    let finish = prepare_client_finish(&mut server, peer, ClientAttemptId(1), now);
    let modified = ClientFinish {
      client_attempt_id: finish.client_attempt_id,
      payload: finish.payload.with_corrupted_proof(),
    };

    server
      .receive_client_finish(peer, finish, now + Duration::from_secs(1))
      .unwrap();
    let report = server
      .receive_client_finish(peer, modified, now + Duration::from_secs(2))
      .unwrap();

    assert!(report.outbound.is_empty());
    assert!(matches!(
      report.events.as_slice(),
      [ServerCoordinatorEvent::Dropped {
        source,
        reason: ServerDropReason::AuthenticationFailed,
      }] if *source == peer
    ));
    assert_eq!(server.policy.state_name(), ServerStateName::Established);
    assert_eq!(server.crypto.phase(), ServerCryptoPhase::Established);
  }

  #[test]
  fn receive_client_finish_rejects_source_and_attempt_before_crypto() {
    let mut server = server_coordinator(1);
    let now = Instant::now();
    let peer = source(4000);
    let finish = prepare_client_finish(&mut server, peer, ClientAttemptId(1), now);

    let wrong_source = server
      .receive_client_finish(source(4001), finish.clone(), now)
      .unwrap();
    assert!(matches!(
      wrong_source.events.as_slice(),
      [ServerCoordinatorEvent::Dropped {
        reason: ServerDropReason::NoPendingCandidate,
        ..
      }]
    ));

    let wrong_attempt = server
      .receive_client_finish(
        peer,
        ClientFinish {
          client_attempt_id: ClientAttemptId(2),
          payload: finish.payload,
        },
        now,
      )
      .unwrap();
    assert!(matches!(
      wrong_attempt.events.as_slice(),
      [ServerCoordinatorEvent::Dropped {
        reason: ServerDropReason::StaleClientAttempt {
          expected: ClientAttemptId(1),
          observed: ClientAttemptId(2),
        },
        ..
      }]
    ));
    assert_eq!(server.policy.pending_candidate_count(), 1);
    assert_eq!(server.crypto.non_secret_status().pending_contexts, 1);
  }

  #[test]
  fn receive_client_finish_at_deadline_expires_before_authentication() {
    let mut server = server_coordinator(1);
    let now = Instant::now();
    let peer = source(4000);
    let finish = prepare_client_finish(&mut server, peer, ClientAttemptId(1), now);

    let report = server
      .receive_client_finish(peer, finish, now + HANDSHAKE_TIMEOUT)
      .unwrap();

    assert!(report.outbound.is_empty());
    assert!(matches!(
      report.events.as_slice(),
      [
        ServerCoordinatorEvent::CandidateExpired {
          source: expired_source,
          client_attempt_id: ClientAttemptId(1),
          ..
        },
        ServerCoordinatorEvent::Dropped {
          source: dropped_source,
          reason: ServerDropReason::NoPendingCandidate,
        },
      ] if *expired_source == peer && *dropped_source == peer
    ));
    assert_eq!(server.policy.pending_candidate_count(), 0);
    assert_eq!(server.crypto.non_secret_status().pending_contexts, 0);
  }

  #[test]
  fn receive_client_finish_authentication_failure_preserves_other_candidate() {
    let mut server = server_coordinator(2);
    let now = Instant::now();
    let first_peer = source(4000);
    let second_peer = source(4001);
    let first = prepare_client_finish(&mut server, first_peer, ClientAttemptId(1), now);
    let second = prepare_client_finish(&mut server, second_peer, ClientAttemptId(2), now);
    let invalid_first = ClientFinish {
      client_attempt_id: first.client_attempt_id,
      payload: first.payload.with_corrupted_proof(),
    };

    let dropped = server
      .receive_client_finish(first_peer, invalid_first, now + Duration::from_secs(1))
      .unwrap();
    assert!(matches!(
      dropped.events.as_slice(),
      [ServerCoordinatorEvent::Dropped {
        source,
        reason: ServerDropReason::AuthenticationFailed,
      }] if *source == first_peer
    ));
    assert_eq!(server.policy.pending_candidate_count(), 1);
    assert_eq!(server.crypto.non_secret_status().pending_contexts, 1);

    let established = server
      .receive_client_finish(second_peer, second, now + Duration::from_secs(1))
      .unwrap();
    assert!(matches!(
      established.events.as_slice(),
      [ServerCoordinatorEvent::SessionEstablished { source, .. }] if *source == second_peer
    ));
  }

  #[test]
  fn check_timeouts_expires_only_candidates_at_the_deadline() {
    let mut server = server_coordinator(2);
    let now = Instant::now();
    let first_peer = source(4000);
    let second_peer = source(4001);
    prepare_client_finish(&mut server, first_peer, ClientAttemptId(1), now);
    prepare_client_finish(
      &mut server,
      second_peer,
      ClientAttemptId(2),
      now + Duration::from_secs(1),
    );

    let report = server.check_timeouts(now + HANDSHAKE_TIMEOUT).unwrap();
    assert!(report.outbound.is_empty());
    assert!(matches!(
      report.events.as_slice(),
      [ServerCoordinatorEvent::CandidateExpired {
        source,
        client_attempt_id: ClientAttemptId(1),
        ..
      }] if *source == first_peer
    ));
    assert_eq!(server.policy.pending_candidate_count(), 1);
    assert_eq!(server.crypto.non_secret_status().pending_contexts, 1);
    assert_eq!(server.policy.state_name(), ServerStateName::Listening);
    assert_eq!(server.crypto.phase(), ServerCryptoPhase::Running);
  }

  #[test]
  fn shutdown_cleans_pending_candidates_and_is_idempotent() {
    let mut server = server_coordinator(2);
    let now = Instant::now();
    prepare_client_finish(&mut server, source(4000), ClientAttemptId(1), now);
    prepare_client_finish(&mut server, source(4001), ClientAttemptId(2), now);

    let closed = server.shutdown().unwrap();
    assert!(closed.outbound.is_empty());
    assert!(matches!(
      closed.events.as_slice(),
      [ServerCoordinatorEvent::Closed {
        policy_removed_candidates: 2,
        policy_removed_session: false,
        crypto_cleanup,
      }] if crypto_cleanup.removed_pending_contexts == 2 && !crypto_cleanup.already_closed
    ));
    assert_eq!(server.policy.state_name(), ServerStateName::Closed);
    assert_eq!(server.crypto.phase(), ServerCryptoPhase::Closed);
    assert_eq!(server.lifecycle, CoordinatorLifecycle::Closed);

    let already_closed = server.shutdown().unwrap();
    assert_eq!(
      already_closed.events.as_slice(),
      [ServerCoordinatorEvent::AlreadyClosed]
    );
  }

  #[test]
  fn shutdown_covers_empty_and_established_server_phases() {
    let mut empty = server_coordinator(1);
    let empty_report = empty.shutdown().unwrap();
    assert!(matches!(
      empty_report.events.as_slice(),
      [ServerCoordinatorEvent::Closed {
        policy_removed_candidates: 0,
        policy_removed_session: false,
        crypto_cleanup,
      }] if crypto_cleanup.removed_pending_contexts == 0
    ));

    let mut established = server_coordinator(1);
    let now = Instant::now();
    let peer = source(4000);
    let finish = prepare_client_finish(&mut established, peer, ClientAttemptId(1), now);
    established
      .receive_client_finish(peer, finish, now + Duration::from_secs(1))
      .unwrap();
    let established_report = established.shutdown().unwrap();
    assert!(matches!(
      established_report.events.as_slice(),
      [ServerCoordinatorEvent::Closed {
        policy_removed_candidates: 0,
        policy_removed_session: true,
        crypto_cleanup,
      }] if crypto_cleanup.removed_established_context
    ));
  }

  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  enum FinishFault {
    PrepareServerHelloError,
    WrongHelloFailureDomain,
    WrongHelloFailureCorrelation,
    WrongPreparedHelloCorrelation,
    WrongHelloCleanupDisposition,
    AuthenticateClientFinishError,
    WrongFailureDomain,
    WrongFailureCorrelation,
    WrongAuthenticatedCorrelation,
    CleanupAlreadyAbsent,
    CommitError,
    PrepareFinishError,
    WrongPreparedCorrelation,
    RemoveExpiredCandidateError,
  }

  struct FaultyServerCrypto {
    inner: FakeServerCrypto,
    fault: FinishFault,
  }

  impl FaultyServerCrypto {
    fn new(fault: FinishFault) -> Self {
      Self {
        inner: server_crypto(),
        fault,
      }
    }
  }

  impl ServerHandshakeCrypto for FaultyServerCrypto {
    type ClientHelloPayload = FakeClientHello;
    type ServerHelloPayload = FakeServerHello;
    type ClientFinishPayload = FakeClientFinish;
    type ServerFinishPayload = FakeServerFinish;

    fn phase(&self) -> ServerCryptoPhase {
      self.inner.phase()
    }

    fn non_secret_status(&self) -> ServerCryptoStatus {
      self.inner.non_secret_status()
    }

    fn prepare_server_hello(
      &mut self,
      candidate_id: CandidateId,
      client_attempt_id: ClientAttemptId,
      payload: Self::ClientHelloPayload,
    ) -> Result<CryptoOutcome<PreparedServerHello<Self::ServerHelloPayload>>, CryptoStateError>
    {
      if self.fault == FinishFault::PrepareServerHelloError {
        return Err(CryptoStateError::InvalidServerState {
          operation: ServerCryptoOperation::PrepareServerHello,
          phase: self.inner.phase(),
        });
      }
      match self.fault {
        FinishFault::WrongHelloFailureDomain => Ok(CryptoOutcome::RemoteFailure(
          AuthenticationFailure::ClientAttempt {
            attempt_id: client_attempt_id,
            reason: AuthenticationFailureReason::InvalidProof,
          },
        )),
        FinishFault::WrongHelloFailureCorrelation => Ok(CryptoOutcome::RemoteFailure(
          AuthenticationFailure::ServerCandidate {
            candidate_id: CandidateId::new(999),
            client_attempt_id,
            reason: AuthenticationFailureReason::InvalidProof,
          },
        )),
        FinishFault::WrongHelloCleanupDisposition => Ok(CryptoOutcome::RemoteFailure(
          AuthenticationFailure::ServerCandidate {
            candidate_id,
            client_attempt_id,
            reason: AuthenticationFailureReason::InvalidProof,
          },
        )),
        FinishFault::WrongPreparedHelloCorrelation => {
          match self
            .inner
            .prepare_server_hello(candidate_id, client_attempt_id, payload)?
          {
            CryptoOutcome::Success(prepared) => {
              Ok(CryptoOutcome::Success(PreparedServerHello::for_test(
                CandidateId::new(999),
                prepared.client_attempt_id(),
                *prepared.payload(),
              )))
            }
            CryptoOutcome::RemoteFailure(failure) => Ok(CryptoOutcome::RemoteFailure(failure)),
          }
        }
        _ => self
          .inner
          .prepare_server_hello(candidate_id, client_attempt_id, payload),
      }
    }

    fn authenticate_client_finish(
      &mut self,
      candidate_id: CandidateId,
      client_attempt_id: ClientAttemptId,
      payload: Self::ClientFinishPayload,
    ) -> Result<CryptoOutcome<AuthenticatedClientFinish>, CryptoStateError> {
      if self.fault == FinishFault::AuthenticateClientFinishError {
        return Err(CryptoStateError::InvalidServerState {
          operation: ServerCryptoOperation::AuthenticateClientFinish,
          phase: self.inner.phase(),
        });
      }
      match self.fault {
        FinishFault::WrongFailureDomain => Ok(CryptoOutcome::RemoteFailure(
          AuthenticationFailure::ClientAttempt {
            attempt_id: client_attempt_id,
            reason: AuthenticationFailureReason::InvalidProof,
          },
        )),
        FinishFault::WrongFailureCorrelation => Ok(CryptoOutcome::RemoteFailure(
          AuthenticationFailure::ServerCandidate {
            candidate_id: CandidateId::new(999),
            client_attempt_id,
            reason: AuthenticationFailureReason::InvalidProof,
          },
        )),
        FinishFault::CleanupAlreadyAbsent => Ok(CryptoOutcome::RemoteFailure(
          AuthenticationFailure::ServerCandidate {
            candidate_id,
            client_attempt_id,
            reason: AuthenticationFailureReason::InvalidProof,
          },
        )),
        FinishFault::WrongAuthenticatedCorrelation => {
          match self
            .inner
            .authenticate_client_finish(candidate_id, client_attempt_id, payload)?
          {
            CryptoOutcome::Success(authenticated) => {
              Ok(CryptoOutcome::Success(AuthenticatedClientFinish::for_test(
                CandidateId::new(999),
                authenticated.client_attempt_id(),
                authenticated.metadata(),
              )))
            }
            CryptoOutcome::RemoteFailure(failure) => Ok(CryptoOutcome::RemoteFailure(failure)),
          }
        }
        FinishFault::CommitError
        | FinishFault::PrepareFinishError
        | FinishFault::WrongPreparedCorrelation
        | FinishFault::PrepareServerHelloError
        | FinishFault::WrongHelloFailureDomain
        | FinishFault::WrongHelloFailureCorrelation
        | FinishFault::WrongPreparedHelloCorrelation
        | FinishFault::WrongHelloCleanupDisposition
        | FinishFault::AuthenticateClientFinishError
        | FinishFault::RemoveExpiredCandidateError => {
          self
            .inner
            .authenticate_client_finish(candidate_id, client_attempt_id, payload)
        }
      }
    }

    fn commit_session(
      &mut self,
      candidate_id: CandidateId,
      client_attempt_id: ClientAttemptId,
      metadata: EstablishedSessionMetadata,
    ) -> Result<(), CryptoStateError> {
      if self.fault == FinishFault::CommitError {
        return Err(CryptoStateError::AuthenticatedMetadataMismatch);
      }
      self
        .inner
        .commit_session(candidate_id, client_attempt_id, metadata)
    }

    fn reject_authenticated_candidate(
      &mut self,
      candidate_id: CandidateId,
      client_attempt_id: ClientAttemptId,
    ) -> Result<ServerCandidateRemoval, CryptoStateError> {
      self
        .inner
        .reject_authenticated_candidate(candidate_id, client_attempt_id)
    }

    fn prepare_server_finish(
      &self,
      candidate_id: CandidateId,
      client_attempt_id: ClientAttemptId,
      session_id: SessionId,
    ) -> Result<PreparedServerFinish<Self::ServerFinishPayload>, CryptoStateError> {
      if self.fault == FinishFault::PrepareFinishError {
        return Err(CryptoStateError::InvalidServerState {
          operation: ServerCryptoOperation::PrepareServerFinish,
          phase: self.inner.phase(),
        });
      }

      let prepared =
        self
          .inner
          .prepare_server_finish(candidate_id, client_attempt_id, session_id)?;
      if self.fault == FinishFault::WrongPreparedCorrelation {
        return Ok(PreparedServerFinish::for_test(
          CandidateId::new(999),
          prepared.client_attempt_id(),
          prepared.session_id(),
          *prepared.payload(),
        ));
      }
      Ok(prepared)
    }

    fn remove_candidate(
      &mut self,
      candidate_id: CandidateId,
      client_attempt_id: ClientAttemptId,
    ) -> Result<ServerCandidateRemoval, CryptoStateError> {
      if self.fault == FinishFault::CleanupAlreadyAbsent {
        return Ok(ServerCandidateRemoval::AlreadyAbsent);
      }
      if self.fault == FinishFault::WrongHelloCleanupDisposition {
        return Ok(ServerCandidateRemoval::Removed);
      }
      if self.fault == FinishFault::RemoveExpiredCandidateError {
        return Err(CryptoStateError::InvalidServerState {
          operation: ServerCryptoOperation::RemoveCandidate,
          phase: self.inner.phase(),
        });
      }
      self.inner.remove_candidate(candidate_id, client_attempt_id)
    }

    fn shutdown(&mut self) -> CryptoShutdownOutcome {
      self.inner.shutdown()
    }
  }

  fn finish_error(fault: FinishFault) -> FatalCoordinatorError {
    let mut server =
      ServerHandshakeCoordinator::build(server_policy(1), FaultyServerCrypto::new(fault)).unwrap();
    let now = Instant::now();
    let peer = source(4000);
    let finish = prepare_client_finish(&mut server, peer, ClientAttemptId(1), now);
    server
      .receive_client_finish(peer, finish, now + Duration::from_secs(1))
      .unwrap_err()
  }

  fn hello_error(fault: FinishFault) -> FatalCoordinatorError {
    let mut server =
      ServerHandshakeCoordinator::build(server_policy(1), FaultyServerCrypto::new(fault)).unwrap();
    server
      .receive_client_hello(
        source(4000),
        client_hello(ClientAttemptId(1)),
        Instant::now(),
      )
      .unwrap_err()
  }

  #[test]
  fn receive_client_finish_fails_closed_for_crypto_contract_violations() {
    assert!(matches!(
      hello_error(FinishFault::PrepareServerHelloError).primary,
      CoordinatorPrimaryError::Crypto(CryptoStateError::InvalidServerState {
        operation: ServerCryptoOperation::PrepareServerHello,
        ..
      })
    ));
    assert!(matches!(
      hello_error(FinishFault::WrongHelloFailureDomain).primary,
      CoordinatorPrimaryError::Invariant(CryptoFailureCorrelationMismatch)
    ));
    assert!(matches!(
      hello_error(FinishFault::WrongHelloFailureCorrelation).primary,
      CoordinatorPrimaryError::Invariant(CryptoFailureCorrelationMismatch)
    ));
    assert!(matches!(
      hello_error(FinishFault::WrongPreparedHelloCorrelation).primary,
      CoordinatorPrimaryError::Invariant(CryptoResultCorrelationMismatch)
    ));
    assert!(matches!(
      hello_error(FinishFault::WrongHelloCleanupDisposition).primary,
      CoordinatorPrimaryError::Invariant(CoordinatorInvariantError::CandidateCleanupMismatch {
        expected: ServerCandidateRemoval::AlreadyAbsent,
        observed: ServerCandidateRemoval::Removed,
        ..
      })
    ));
    assert!(matches!(
      finish_error(FinishFault::AuthenticateClientFinishError).primary,
      CoordinatorPrimaryError::Crypto(CryptoStateError::InvalidServerState {
        operation: ServerCryptoOperation::AuthenticateClientFinish,
        ..
      })
    ));
    assert!(matches!(
      finish_error(FinishFault::WrongFailureDomain).primary,
      CoordinatorPrimaryError::Invariant(CryptoFailureCorrelationMismatch)
    ));
    assert!(matches!(
      finish_error(FinishFault::WrongFailureCorrelation).primary,
      CoordinatorPrimaryError::Invariant(CryptoFailureCorrelationMismatch)
    ));
    assert!(matches!(
      finish_error(FinishFault::WrongAuthenticatedCorrelation).primary,
      CoordinatorPrimaryError::Invariant(CryptoResultCorrelationMismatch)
    ));
    assert!(matches!(
      finish_error(FinishFault::CleanupAlreadyAbsent).primary,
      CoordinatorPrimaryError::Invariant(CoordinatorInvariantError::CandidateCleanupMismatch {
        expected: ServerCandidateRemoval::Removed,
        observed: ServerCandidateRemoval::AlreadyAbsent,
        ..
      })
    ));
    let commit_error = finish_error(FinishFault::CommitError);
    assert!(matches!(
      commit_error.primary,
      CoordinatorPrimaryError::Crypto(CryptoStateError::AuthenticatedMetadataMismatch)
    ));
    assert!(commit_error.crypto_cleanup.removed_pending_commit);
    let prepare_finish_error = finish_error(FinishFault::PrepareFinishError);
    assert!(matches!(
      prepare_finish_error.primary,
      CoordinatorPrimaryError::Crypto(CryptoStateError::InvalidServerState {
        operation: ServerCryptoOperation::PrepareServerFinish,
        ..
      })
    ));
    assert!(
      prepare_finish_error
        .crypto_cleanup
        .removed_established_context
    );
    assert!(matches!(
      finish_error(FinishFault::WrongPreparedCorrelation).primary,
      CoordinatorPrimaryError::Invariant(CryptoResultCorrelationMismatch)
    ));
  }

  #[test]
  fn expired_candidate_removal_error_fails_closed_and_erases_all_crypto_state() {
    let mut server = ServerHandshakeCoordinator::build(
      server_policy(1),
      FaultyServerCrypto::new(FinishFault::RemoveExpiredCandidateError),
    )
    .unwrap();
    let now = Instant::now();
    prepare_client_finish(&mut server, source(4000), ClientAttemptId(1), now);

    let error = server.check_timeouts(now + HANDSHAKE_TIMEOUT).unwrap_err();

    assert!(matches!(
      error.primary,
      CoordinatorPrimaryError::Crypto(CryptoStateError::InvalidServerState {
        operation: ServerCryptoOperation::RemoveCandidate,
        ..
      })
    ));
    assert_eq!(error.crypto_cleanup.removed_pending_contexts, 1);
    assert_eq!(server.policy.state_name(), ServerStateName::Closed);
    assert_eq!(server.crypto.phase(), ServerCryptoPhase::Closed);
    assert_eq!(server.lifecycle, CoordinatorLifecycle::Closed);
  }
}
