//! Pure authenticated-session policy and lifecycle.
//!
//! This module does not perform network I/O or cryptographic operations.
//! Callers report authentication results as events, and the session manager
//! returns decisions for the runtime to execute.

pub(crate) mod client;

#[cfg(test)]
mod manager_tests;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Opaque identifier for one pending authentication attempt.
///
/// Candidate IDs are local policy tokens, not authenticated peer identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CandidateId(u64);

/// Validated limits governing pending and established session lifetimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionPolicy {
  maximum_pending: usize,
  handshake_timeout: Duration,
  idle_timeout: Duration,
}

impl SessionPolicy {
  /// Constructs a policy after rejecting zero capacity or timeout values.
  pub(crate) fn new(
    maximum_pending: usize,
    handshake_timeout: Duration,
    idle_timeout: Duration,
  ) -> Result<Self, SessionConfigError> {
    if maximum_pending == 0 {
      return Err(SessionConfigError::PendingLimit);
    }

    if handshake_timeout.is_zero() {
      return Err(SessionConfigError::HandshakeTimeout);
    }

    if idle_timeout.is_zero() {
      return Err(SessionConfigError::IdleTimeout);
    }

    Ok(Self {
      maximum_pending,
      handshake_timeout,
      idle_timeout,
    })
  }

  /// Returns the maximum number of simultaneous unauthenticated candidates.
  pub(crate) const fn maximum_pending(&self) -> usize {
    self.maximum_pending
  }

  /// Returns the maximum lifetime of one pending handshake phase.
  pub(crate) const fn handshake_timeout(&self) -> Duration {
    self.handshake_timeout
  }

  /// Returns the maximum future lifetime of an inactive established session.
  pub(crate) const fn idle_timeout(&self) -> Duration {
    self.idle_timeout
  }
}

/// Invalid session-policy configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionConfigError {
  /// No pending handshake could be admitted.
  PendingLimit,
  /// Pending handshakes would expire immediately.
  HandshakeTimeout,
  /// Established sessions would expire immediately.
  IdleTimeout,
}

impl std::fmt::Display for SessionConfigError {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::PendingLimit => {
        write!(
          formatter,
          "session maximum_pending must be greater than zero"
        )
      }
      Self::HandshakeTimeout => {
        write!(
          formatter,
          "session handshake_timeout must be greater than zero"
        )
      }

      Self::IdleTimeout => {
        write!(formatter, "session idle_timeout must be greater than zero")
      }
    }
  }
}

impl std::error::Error for SessionConfigError {}

/// One unauthenticated attempt owned by a transport source.
///
/// Duplicate messages retain both the original creation time and deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingCandidate {
  id: CandidateId,
  created_at: Instant,
  deadline: Instant,
}

/// Running or terminal lifecycle of the pending-candidate manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagerState {
  Running,
  Closed,
}

/// Owns bounded pending handshake attempts and their lifecycle policy.
///
/// The manager is synchronous and receives time from its caller so admission,
/// expiration, and shutdown remain deterministic and testable.
pub(crate) struct SessionManager {
  policy: SessionPolicy,
  state: ManagerState,
  pending_by_source: HashMap<SocketAddr, PendingCandidate>,
  next_candidate_id: u64,
}

impl SessionManager {
  /// Creates an empty running manager governed by a validated policy.
  pub(crate) fn new(policy: SessionPolicy) -> Self {
    Self {
      policy,
      state: ManagerState::Running,
      pending_by_source: HashMap::new(),
      next_candidate_id: 1,
    }
  }

  /// Admits a source or reports why no new candidate was created.
  ///
  /// Expired candidates are removed before duplicate and capacity checks. A
  /// duplicate source retains its original identifier and deadline.
  pub(crate) fn admit(
    &mut self,
    source: SocketAddr,
    now: Instant,
  ) -> Result<AdmissionReport, SessionManagerError> {
    let expiration = self.expire_pending(now);
    if self.state == ManagerState::Closed {
      return Ok(AdmissionReport {
        expired: expiration.expired,
        outcome: AdmissionOutcome::Closed,
      });
    }

    if let Some(existing) = self.pending_by_source.get(&source) {
      return Ok(AdmissionReport {
        expired: expiration.expired,
        outcome: AdmissionOutcome::AlreadyPending {
          candidate_id: existing.id,
          deadline: existing.deadline,
        },
      });
    }

    if self.pending_by_source.len() >= self.policy.maximum_pending() {
      return Ok(AdmissionReport {
        expired: expiration.expired,
        outcome: AdmissionOutcome::AtCapacity {
          maximum_pending: self.policy.maximum_pending(),
        },
      });
    }

    let deadline = Self::calculate_deadline(now, self.policy.handshake_timeout(), source)?;

    let candidate_id = self.reserve_candidate_id()?;
    let candidate = PendingCandidate {
      id: candidate_id,
      created_at: now,
      deadline,
    };

    self.pending_by_source.insert(source, candidate);

    Ok(AdmissionReport {
      expired: expiration.expired,
      outcome: AdmissionOutcome::Added {
        candidate_id,
        deadline,
      },
    })
  }

  /// Removes candidates whose deadline is at or before `now`.
  ///
  /// The report includes removed candidates and the nearest remaining
  /// deadline. A closed manager has no pending deadlines.
  pub(crate) fn expire_pending(&mut self, now: Instant) -> ExpirationReport {
    if self.state == ManagerState::Closed {
      return ExpirationReport {
        expired: Vec::new(),
        next_deadline: None,
      };
    }

    let mut expired = Vec::new();

    for (source, candidate) in self.pending_by_source.iter() {
      if now >= candidate.deadline {
        expired.push(ExpiredCandidate {
          candidate_id: candidate.id,
          source: *source,
        });
      }
    }

    for candidate in expired.iter() {
      self.pending_by_source.remove(&candidate.source);
    }

    let nearest = self.pending_by_source.values().map(|e| e.deadline).min();
    ExpirationReport {
      expired,
      next_deadline: nearest,
    }
  }

  /// Returns the nearest pending deadline while the manager is running.
  pub(crate) fn next_deadline(&self) -> Option<Instant> {
    if self.state == ManagerState::Closed {
      return None;
    }
    self
      .pending_by_source
      .values()
      .map(|candidate| candidate.deadline)
      .min()
  }

  /// Returns the number of currently pending handshake candidates.
  pub(crate) fn pending_count(&self) -> usize {
    self.pending_by_source.len()
  }

  /// Closes the manager and removes every pending candidate.
  ///
  /// Repeated shutdown is safe and reports that the manager was already closed.
  pub(crate) fn shutdown(&mut self) -> ShutdownOutcome {
    if self.state == ManagerState::Closed {
      return ShutdownOutcome::AlreadyClosed;
    }
    let removed_count = self.pending_by_source.len();
    self.pending_by_source.clear();
    self.state = ManagerState::Closed;

    ShutdownOutcome::Closed {
      removed_candidates: removed_count,
    }
  }

  /// Reserves the next monotonic candidate ID without wrapping.
  fn reserve_candidate_id(&mut self) -> Result<CandidateId, SessionManagerError> {
    let current = self.next_candidate_id;

    let next = match current.checked_add(1) {
      Some(next_val) => next_val,
      None => return Err(SessionManagerError::CandidateIdExhausted),
    };
    self.next_candidate_id = next;

    Ok(CandidateId(current))
  }

  /// Calculates one representable deadline for the supplied source.
  fn calculate_deadline(
    now: Instant,
    timeout: Duration,
    source: SocketAddr,
  ) -> Result<Instant, SessionManagerError> {
    now
      .checked_add(timeout)
      .ok_or(SessionManagerError::DeadlineOverflow { source })
  }
}

/// Result of applying admission policy to one transport source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionOutcome {
  /// A new pending candidate was created.
  Added {
    /// Identifier reserved for the new attempt.
    candidate_id: CandidateId,
    /// Instant at which the attempt expires.
    deadline: Instant,
  },

  /// The source already owns an unexpired pending candidate.
  AlreadyPending {
    /// Existing identifier, which is not replaced.
    candidate_id: CandidateId,
    /// Original deadline, which is not refreshed.
    deadline: Instant,
  },

  /// The configured pending-candidate bound has been reached.
  AtCapacity {
    /// Configured bound that prevented admission.
    maximum_pending: usize,
  },

  /// Shutdown has made the manager terminal.
  Closed,
}

/// Expiration side effects and final decision from one admission attempt.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AdmissionReport {
  /// Candidates expired before admission policy was evaluated.
  pub(crate) expired: Vec<ExpiredCandidate>,
  /// Admission decision for the supplied source.
  pub(crate) outcome: AdmissionOutcome,
}

/// Public, non-secret description of an expired pending candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExpiredCandidate {
  /// Identifier of the expired attempt.
  pub(crate) candidate_id: CandidateId,
  /// Transport address that owned the attempt.
  pub(crate) source: SocketAddr,
}

/// Result of removing all candidates expired at a supplied instant.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ExpirationReport {
  /// Candidates removed during this expiration pass.
  pub(crate) expired: Vec<ExpiredCandidate>,
  /// Nearest deadline among candidates that remain.
  pub(crate) next_deadline: Option<Instant>,
}

/// Local failure while managing pending candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionManagerError {
  /// Adding the configured timeout exceeds the platform instant range.
  DeadlineOverflow {
    /// Candidate source whose deadline could not be represented.
    source: SocketAddr,
  },

  /// The monotonically increasing candidate identifier cannot advance.
  CandidateIdExhausted,
}

impl std::fmt::Display for SessionManagerError {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::DeadlineOverflow { source } => {
        write!(
          formatter,
          "handshake deadline overflows for candidate source {source}"
        )
      }
      Self::CandidateIdExhausted => {
        write!(
          formatter,
          "pending handshake candidate ID space is exhausted"
        )
      }
    }
  }
}

impl std::error::Error for SessionManagerError {}

/// Result of requesting pending-manager shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShutdownOutcome {
  /// The running manager closed and removed its candidates.
  Closed {
    /// Number of pending candidates removed.
    removed_candidates: usize,
  },

  /// The manager was already closed and no state changed.
  AlreadyClosed,
}

#[cfg(test)]
mod tests {
  use super::*;

  const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
  const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

  fn policy(maximum_pending: usize) -> SessionPolicy {
    SessionPolicy::new(maximum_pending, HANDSHAKE_TIMEOUT, IDLE_TIMEOUT)
      .expect("test session policy should be valid")
  }

  fn manager(maximum_pending: usize) -> SessionManager {
    SessionManager::new(policy(maximum_pending))
  }

  fn source(port: u16) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 1], port))
  }

  #[test]
  fn policy_accepts_positive_limits() {
    let policy = policy(2);

    assert_eq!(policy.maximum_pending(), 2);
    assert_eq!(policy.handshake_timeout(), HANDSHAKE_TIMEOUT);
    assert_eq!(policy.idle_timeout(), IDLE_TIMEOUT);
  }

  #[test]
  fn duplicate_source_keeps_original_candidate_and_deadline() {
    let mut manager = manager(2);
    let source = source(4000);
    let start = Instant::now();

    let first = manager.admit(source, start).unwrap();
    let duplicate = manager
      .admit(source, start + Duration::from_secs(1))
      .unwrap();

    let (
      AdmissionOutcome::Added {
        candidate_id: first_id,
        deadline: first_deadline,
      },
      AdmissionOutcome::AlreadyPending {
        candidate_id: duplicate_id,
        deadline: duplicate_deadline,
      },
    ) = (first.outcome, duplicate.outcome)
    else {
      panic!("expected added followed by already-pending outcomes");
    };

    assert_eq!(duplicate_id, first_id);
    assert_eq!(duplicate_deadline, first_deadline);
    assert_eq!(manager.pending_count(), 1);
  }
}
