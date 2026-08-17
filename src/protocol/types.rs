//! Types shared by Crabnet wire-protocol versions.

/// Message carried by a Crabnet frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageType {
  /// One raw inner IP packet.
  Data,
}

/// Successfully validated frame borrowing its payload from a UDP buffer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DecodedFrame<'a> {
  pub(super) message_type: MessageType,
  pub(super) payload: &'a [u8],
}

impl<'a> DecodedFrame<'a> {
  /// Returns the validated message type.
  pub(crate) const fn message_type(&self) -> MessageType {
    self.message_type
  }

  /// Returns the unchanged inner-packet bytes.
  pub(crate) const fn payload(&self) -> &'a [u8] {
    self.payload
  }
}
