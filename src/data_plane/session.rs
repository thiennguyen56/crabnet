//! Session sequencing and replay protection for the encrypted V2 data plane.

use crate::{
  data_plane::{crypto::DirectionalTransport, frame::DataDirection},
  session::types::EstablishedSessionMetadata,
};
use std::{
  collections::HashSet,
  net::SocketAddr,
  time::{Duration, Instant},
};

pub(crate) const FIRST_SEQUENCE: u64 = 1;
pub(crate) const MAX_SEQUENCE: u64 = u64::MAX - 1;
const SEQUENCE_EXHAUSTED: u64 = u64::MAX;
pub(crate) const REPLAY_WINDOW_WIDTH: u64 = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayDecision {
  Acceptable,
  Duplicate,
  TooOld,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DataSessionError {
  SendSequenceExhausted,
  ReplayWindowInvariant { sequence: u64 },
}

pub(crate) struct ReplayWindow {
  highest_accepted: Option<u64>,
  received: HashSet<u64>,
}

impl ReplayWindow {
  pub(crate) fn new() -> Self {
    Self {
      highest_accepted: None,
      received: HashSet::new(),
    }
  }

  pub(crate) fn may_attempt(&self, sequence: u64) -> ReplayDecision {
    if self.received.contains(&sequence) {
      return ReplayDecision::Duplicate;
    }
    if let Some(highest) = self.highest_accepted
      && sequence.saturating_add(REPLAY_WINDOW_WIDTH) <= highest
    {
      return ReplayDecision::TooOld;
    }
    ReplayDecision::Acceptable
  }

  pub(crate) fn commit(&mut self, sequence: u64) -> Result<(), DataSessionError> {
    if self.may_attempt(sequence) != ReplayDecision::Acceptable {
      return Err(DataSessionError::ReplayWindowInvariant { sequence });
    }
    self.highest_accepted = Some(
      self
        .highest_accepted
        .map_or(sequence, |highest| highest.max(sequence)),
    );
    let lowest = self
      .highest_accepted
      .unwrap_or(sequence)
      .saturating_sub(REPLAY_WINDOW_WIDTH - 1);
    self.received.retain(|received| *received >= lowest);
    self.received.insert(sequence);
    Ok(())
  }
}

pub(crate) struct EstablishedDataSession {
  pub(crate) metadata: EstablishedSessionMetadata,
  pub(crate) peer_endpoint: SocketAddr,
  pub(crate) send_direction: DataDirection,
  pub(crate) receive_direction: DataDirection,
  next_send_sequence: u64,
  pub(crate) replay_window: ReplayWindow,
  pub(crate) transport: DirectionalTransport,
  lifetime: SessionLifetime,
}

impl EstablishedDataSession {
  pub(crate) fn client(
    metadata: EstablishedSessionMetadata,
    peer_endpoint: SocketAddr,
    transport: DirectionalTransport,
    lifetime: SessionLifetime,
  ) -> Self {
    Self {
      metadata,
      peer_endpoint,
      send_direction: DataDirection::ClientToServer,
      receive_direction: DataDirection::ServerToClient,
      next_send_sequence: FIRST_SEQUENCE,
      replay_window: ReplayWindow::new(),
      transport,
      lifetime,
    }
  }

  pub(crate) fn server(
    metadata: EstablishedSessionMetadata,
    peer_endpoint: SocketAddr,
    transport: DirectionalTransport,
    lifetime: SessionLifetime,
  ) -> Self {
    Self {
      metadata,
      peer_endpoint,
      send_direction: DataDirection::ServerToClient,
      receive_direction: DataDirection::ClientToServer,
      next_send_sequence: FIRST_SEQUENCE,
      replay_window: ReplayWindow::new(),
      transport,
      lifetime,
    }
  }

  pub(crate) fn allocate_send_sequence(&mut self) -> Result<u64, DataSessionError> {
    if self.next_send_sequence == SEQUENCE_EXHAUSTED {
      return Err(DataSessionError::SendSequenceExhausted);
    }
    let sequence = self.next_send_sequence;
    self.next_send_sequence = if sequence == MAX_SEQUENCE {
      SEQUENCE_EXHAUSTED
    } else {
      sequence + 1
    };
    Ok(sequence)
  }

  pub(crate) fn permit(
    &mut self,
    direction: TrafficDirection,
    plaintext_bytes: u64,
    now: Instant,
  ) -> Result<SessionDecision, SessionLifetimeError> {
    self.lifetime.permit(direction, plaintext_bytes, now)
  }

  pub(crate) fn record_success(
    &mut self,
    direction: TrafficDirection,
    plaintext_bytes: u64,
    now: Instant,
  ) -> Result<(), SessionLifetimeError> {
    self
      .lifetime
      .record_success(direction, plaintext_bytes, now)
  }

  pub(crate) fn expire_if_due(
    &mut self,
    now: Instant,
  ) -> Result<SessionDecision, SessionLifetimeError> {
    self.lifetime.expire_if_due(now)
  }

  pub(crate) fn next_deadline(&self) -> Result<Option<Instant>, SessionLifetimeError> {
    self.lifetime.next_deadline()
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrafficDirection {
  Outbound,
  Inbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionDecision {
  Permit,
  Close(SessionCloseReason),
}

pub(crate) struct SessionLimits {
  maximum_outbound_packets: u64,
  maximum_outbound_plaintext_bytes: u64,
  maximum_inbound_packets: u64,
  maximum_inbound_plaintext_bytes: u64,
  idle_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionLimitsConfigError {
  ZeroLimit { field: SessionLimitField },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionLimitField {
  OutboundPackets,
  OutboundPlaintextBytes,
  InboundPackets,
  InboundPlaintextBytes,
  IdleTimeout,
}

impl SessionLimits {
  pub(crate) fn new(
    maximum_outbound_packets: u64,
    maximum_outbound_plaintext_bytes: u64,
    maximum_inbound_packets: u64,
    maximum_inbound_plaintext_bytes: u64,
    idle_timeout: Duration,
  ) -> Result<Self, SessionLimitsConfigError> {
    if maximum_inbound_packets == 0 {
      return Err(SessionLimitsConfigError::ZeroLimit {
        field: SessionLimitField::InboundPackets,
      });
    }
    if maximum_inbound_plaintext_bytes == 0 {
      return Err(SessionLimitsConfigError::ZeroLimit {
        field: SessionLimitField::InboundPlaintextBytes,
      });
    }
    if idle_timeout == Duration::default() {
      return Err(SessionLimitsConfigError::ZeroLimit {
        field: SessionLimitField::IdleTimeout,
      });
    }
    if maximum_outbound_packets == 0 {
      return Err(SessionLimitsConfigError::ZeroLimit {
        field: SessionLimitField::OutboundPackets,
      });
    }
    if maximum_outbound_plaintext_bytes == 0 {
      return Err(SessionLimitsConfigError::ZeroLimit {
        field: SessionLimitField::OutboundPlaintextBytes,
      });
    }
    Ok(Self {
      maximum_outbound_packets,
      maximum_outbound_plaintext_bytes,
      maximum_inbound_packets,
      maximum_inbound_plaintext_bytes,
      idle_timeout,
    })
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionCloseReason {
  OutboundPacketLimit,
  OutboundByteLimit,
  InboundPacketLimit,
  InboundByteLimit,
  IdleTimeout,
  SendSequenceExhausted,
  LocalShutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionLifetimeError {
  RecordAfterClose {
    direction: TrafficDirection,
    reason: SessionCloseReason,
  },
  CounterOverflow {
    counter: u64,
    attempted_increment: u64,
  },
  DeadlineOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionLifetimeState {
  Established,
  Closed(SessionCloseReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrafficCounters {
  packets: u64,
  bytes: u64,
}

impl TrafficCounters {
  fn next(self, plaintext_bytes: u64) -> Result<Self, SessionLifetimeError> {
    let packets = self
      .packets
      .checked_add(1)
      .ok_or(SessionLifetimeError::CounterOverflow {
        counter: self.packets,
        attempted_increment: 1,
      })?;
    let bytes =
      self
        .bytes
        .checked_add(plaintext_bytes)
        .ok_or(SessionLifetimeError::CounterOverflow {
          counter: self.bytes,
          attempted_increment: plaintext_bytes,
        })?;
    Ok(Self { packets, bytes })
  }
}

pub(crate) struct SessionLifetime {
  limits: SessionLimits,
  state: SessionLifetimeState,
  outbound: TrafficCounters,
  inbound: TrafficCounters,
  last_successful_activity: Instant,
}

impl SessionLifetime {
  pub(crate) fn new(now: Instant, limits: SessionLimits) -> Self {
    Self {
      limits,
      state: SessionLifetimeState::Established,
      outbound: TrafficCounters {
        packets: 0,
        bytes: 0,
      },
      inbound: TrafficCounters {
        packets: 0,
        bytes: 0,
      },
      last_successful_activity: now,
    }
  }

  fn counters(&self, direction: TrafficDirection) -> &TrafficCounters {
    match direction {
      TrafficDirection::Outbound => &self.outbound,
      TrafficDirection::Inbound => &self.inbound,
    }
  }

  fn counters_mut(&mut self, direction: TrafficDirection) -> &mut TrafficCounters {
    match direction {
      TrafficDirection::Outbound => &mut self.outbound,
      TrafficDirection::Inbound => &mut self.inbound,
    }
  }

  fn close(&mut self, reason: SessionCloseReason) -> SessionDecision {
    match self.state {
      SessionLifetimeState::Established => {
        self.state = SessionLifetimeState::Closed(reason);
        SessionDecision::Close(reason)
      }
      SessionLifetimeState::Closed(reason) => SessionDecision::Close(reason),
    }
  }

  pub(crate) fn permit(
    &mut self,
    direction: TrafficDirection,
    plaintext_bytes: u64,
    now: Instant,
  ) -> Result<SessionDecision, SessionLifetimeError> {
    let decision = self.expire_if_due(now)?;
    if matches!(decision, SessionDecision::Close(_)) {
      return Ok(decision);
    }

    let next = self.counters(direction).next(plaintext_bytes)?;
    match direction {
      TrafficDirection::Outbound => {
        if next.packets > self.limits.maximum_outbound_packets {
          return Ok(self.close(SessionCloseReason::OutboundPacketLimit));
        }
        if next.bytes > self.limits.maximum_outbound_plaintext_bytes {
          return Ok(self.close(SessionCloseReason::OutboundByteLimit));
        }
      }
      TrafficDirection::Inbound => {
        if next.packets > self.limits.maximum_inbound_packets {
          return Ok(self.close(SessionCloseReason::InboundPacketLimit));
        }
        if next.bytes > self.limits.maximum_inbound_plaintext_bytes {
          return Ok(self.close(SessionCloseReason::InboundByteLimit));
        }
      }
    }
    Ok(SessionDecision::Permit)
  }

  pub(crate) fn record_success(
    &mut self,
    direction: TrafficDirection,
    plaintext_bytes: u64,
    now: Instant,
  ) -> Result<(), SessionLifetimeError> {
    if let SessionLifetimeState::Closed(reason) = &self.state {
      return Err(SessionLifetimeError::RecordAfterClose {
        direction,
        reason: *reason,
      });
    }

    let next = self.counters(direction).next(plaintext_bytes)?;
    *self.counters_mut(direction) = next;
    self.last_successful_activity = now;
    Ok(())
  }

  pub(crate) fn expire_if_due(
    &mut self,
    now: Instant,
  ) -> Result<SessionDecision, SessionLifetimeError> {
    match self.state {
      SessionLifetimeState::Closed(reason) => Ok(SessionDecision::Close(reason)),
      SessionLifetimeState::Established => {
        let Some(deadline) = self
          .last_successful_activity
          .checked_add(self.limits.idle_timeout)
        else {
          return Err(SessionLifetimeError::DeadlineOverflow);
        };

        if now >= deadline {
          return Ok(self.close(SessionCloseReason::IdleTimeout));
        }

        Ok(SessionDecision::Permit)
      }
    }
  }

  pub(crate) fn next_deadline(&self) -> Result<Option<Instant>, SessionLifetimeError> {
    match self.state {
      SessionLifetimeState::Closed(_) => Ok(None),
      SessionLifetimeState::Established => self
        .last_successful_activity
        .checked_add(self.limits.idle_timeout)
        .map(Some)
        .ok_or(SessionLifetimeError::DeadlineOverflow),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn limits() -> SessionLimits {
    SessionLimits::new(2, 10, 3, 20, Duration::from_secs(30)).unwrap()
  }

  #[test]
  fn replay_window_accepts_reordering_but_rejects_duplicates() {
    let mut window = ReplayWindow::new();
    window.commit(3).unwrap();
    assert_eq!(window.may_attempt(2), ReplayDecision::Acceptable);
    window.commit(2).unwrap();
    assert_eq!(window.may_attempt(2), ReplayDecision::Duplicate);
  }

  #[test]
  fn replay_window_rejects_packets_outside_its_retained_range() {
    let mut window = ReplayWindow::new();
    window.commit(REPLAY_WINDOW_WIDTH + 1).unwrap();
    assert_eq!(window.may_attempt(1), ReplayDecision::TooOld);
  }

  #[test]
  fn successful_outbound_record_updates_only_outbound_counters() {
    let now = Instant::now();
    let mut lifetime = SessionLifetime::new(now, limits());

    assert_eq!(
      lifetime.permit(TrafficDirection::Outbound, 4, now).unwrap(),
      SessionDecision::Permit
    );
    lifetime
      .record_success(TrafficDirection::Outbound, 4, now)
      .unwrap();

    assert_eq!(
      lifetime.outbound,
      TrafficCounters {
        packets: 1,
        bytes: 4,
      }
    );
    assert_eq!(
      lifetime.inbound,
      TrafficCounters {
        packets: 0,
        bytes: 0,
      }
    );
  }

  #[test]
  fn packet_limit_closes_session_and_rejects_later_recording() {
    let now = Instant::now();
    let limits = SessionLimits::new(1, 10, 3, 20, Duration::from_secs(30)).unwrap();
    let mut lifetime = SessionLifetime::new(now, limits);

    lifetime
      .record_success(TrafficDirection::Outbound, 4, now)
      .unwrap();

    assert_eq!(
      lifetime.permit(TrafficDirection::Outbound, 4, now).unwrap(),
      SessionDecision::Close(SessionCloseReason::OutboundPacketLimit)
    );
    assert_eq!(
      lifetime.record_success(TrafficDirection::Inbound, 1, now),
      Err(SessionLifetimeError::RecordAfterClose {
        direction: TrafficDirection::Inbound,
        reason: SessionCloseReason::OutboundPacketLimit,
      })
    );
  }

  #[test]
  fn idle_expiry_closes_session_and_removes_deadline() {
    let now = Instant::now();
    let mut lifetime = SessionLifetime::new(now, limits());
    let deadline = lifetime.next_deadline().unwrap().unwrap();

    assert_eq!(
      lifetime.expire_if_due(deadline).unwrap(),
      SessionDecision::Close(SessionCloseReason::IdleTimeout)
    );
    assert_eq!(lifetime.next_deadline().unwrap(), None);
  }

  #[test]
  fn close_is_terminal_and_idempotent() {
    let now = Instant::now();
    let mut lifetime = SessionLifetime::new(now, limits());

    assert_eq!(
      lifetime.close(SessionCloseReason::LocalShutdown),
      SessionDecision::Close(SessionCloseReason::LocalShutdown)
    );
    assert_eq!(
      lifetime.close(SessionCloseReason::SendSequenceExhausted),
      SessionDecision::Close(SessionCloseReason::LocalShutdown)
    );
  }
}
