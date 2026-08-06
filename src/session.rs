//! Pure authenticated-session policy and lifecycle.
//!
//! This module does not perform network I/O or cryptographic operations.
//! Callers report authentication results as events, and the session manager
//! returns decisions for the runtime to execute.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CandidateId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionPolicy {
  maximum_pending: usize,
  handshake_timeout: Duration,
  idle_timeout: Duration,
}

impl SessionPolicy {
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

  pub(crate) const fn maximum_pending(&self) -> usize {
    self.maximum_pending
  }

  pub(crate) const fn handshake_timeout(&self) -> Duration {
    self.handshake_timeout
  }

  pub(crate) const fn idle_timeout(&self) -> Duration {
    self.idle_timeout
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionConfigError {
  PendingLimit,
  HandshakeTimeout,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingCandidate {
  id: CandidateId,
  created_at: Instant,
  deadline: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagerState {
  Running,
  Closed,
}

pub(crate) struct SessionManager {
  policy: SessionPolicy,
  state: ManagerState,
  pending_by_source: HashMap<SocketAddr, PendingCandidate>,
  next_candidate_id: u64,
}

impl SessionManager {
  pub(crate) fn new(policy: SessionPolicy) -> Self {
    Self {
      policy,
      state: ManagerState::Running,
      pending_by_source: HashMap::new(),
      next_candidate_id: 1,
    }
  }

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

    let deadline = self.calculate_deadline(now, self.policy.handshake_timeout(), source)?;

    let candidate_id = self.reserve_candidate_id()?;
    let candidate = PendingCandidate {
      id: candidate_id,
      created_at: now,
      deadline: deadline,
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
      expired: expired,
      next_deadline: nearest,
    }
  }

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

  fn reserve_candidate_id(&mut self) -> Result<CandidateId, SessionManagerError> {
    let current = self.next_candidate_id;

    let next = match current.checked_add(1) {
      Some(next_val) => next_val,
      None => return Err(SessionManagerError::CandidateIdExhausted),
    };
    self.next_candidate_id = next;

    Ok(CandidateId(current))
  }

  fn calculate_deadline(
    &self,
    now: Instant,
    timeout: Duration,
    source: SocketAddr,
  ) -> Result<Instant, SessionManagerError> {
    now
      .checked_add(timeout)
      .ok_or(SessionManagerError::DeadlineOverflow { source })
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionOutcome {
  Added {
    candidate_id: CandidateId,
    deadline: Instant,
  },

  AlreadyPending {
    candidate_id: CandidateId,
    deadline: Instant,
  },

  AtCapacity {
    maximum_pending: usize,
  },

  Closed,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AdmissionReport {
  pub(crate) expired: Vec<ExpiredCandidate>,
  pub(crate) outcome: AdmissionOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExpiredCandidate {
  pub(crate) candidate_id: CandidateId,
  pub(crate) source: SocketAddr,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ExpirationReport {
  pub(crate) expired: Vec<ExpiredCandidate>,
  pub(crate) next_deadline: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionManagerError {
  DeadlineOverflow { source: SocketAddr },

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShutdownOutcome {
  Closed { removed_candidates: usize },

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
