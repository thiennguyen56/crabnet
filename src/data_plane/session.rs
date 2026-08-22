//! Session sequencing and replay protection for the encrypted V2 data plane.

use std::{collections::HashSet, net::SocketAddr};

use crate::{
  data_plane::{crypto::DirectionalTransport, frame::DataDirection},
  session::types::EstablishedSessionMetadata,
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
}

impl EstablishedDataSession {
  pub(crate) fn client(
    metadata: EstablishedSessionMetadata,
    peer_endpoint: SocketAddr,
    transport: DirectionalTransport,
  ) -> Self {
    Self {
      metadata,
      peer_endpoint,
      send_direction: DataDirection::ClientToServer,
      receive_direction: DataDirection::ServerToClient,
      next_send_sequence: FIRST_SEQUENCE,
      replay_window: ReplayWindow::new(),
      transport,
    }
  }

  pub(crate) fn server(
    metadata: EstablishedSessionMetadata,
    peer_endpoint: SocketAddr,
    transport: DirectionalTransport,
  ) -> Self {
    Self {
      metadata,
      peer_endpoint,
      send_direction: DataDirection::ServerToClient,
      receive_direction: DataDirection::ClientToServer,
      next_send_sequence: FIRST_SEQUENCE,
      replay_window: ReplayWindow::new(),
      transport,
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
}

#[cfg(test)]
mod tests {
  use super::*;

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
}
