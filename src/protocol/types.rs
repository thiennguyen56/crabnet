//! Types shared by Crabnet wire-protocol versions.

/// Supported Crabnet wire-protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtocolVersion {
  /// Original data-only framing.
  V1,
  /// Handshake framing introduced for authenticated sessions.
  V2,
}

impl ProtocolVersion {
  /// Returns the stable wire value shared by protocol-version codecs.
  pub(crate) const fn wire_value(self) -> u8 {
    match self {
      Self::V1 => 1,
      Self::V2 => 2,
    }
  }
}

/// Message carried by a Crabnet frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageType {
  /// One raw inner IP packet.
  Data,
  /// Starts client authentication.
  ClientHello,
  /// Continues authentication with the server response.
  ServerHello,
  /// Completes the client's authentication proof.
  ClientFinish,
  /// Confirms that the server established the session.
  ServerFinish,
}

impl MessageType {
  /// Returns the stable wire value shared by protocol-version codecs.
  pub(crate) const fn wire_value(self) -> u8 {
    match self {
      Self::Data => 1,
      Self::ClientHello => 2,
      Self::ServerHello => 3,
      Self::ClientFinish => 4,
      Self::ServerFinish => 5,
    }
  }
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

#[cfg(test)]
mod tests {
  use super::{MessageType, ProtocolVersion};

  #[test]
  fn shared_wire_values_are_stable() {
    assert_eq!(ProtocolVersion::V1.wire_value(), 1);
    assert_eq!(ProtocolVersion::V2.wire_value(), 2);
    assert_eq!(MessageType::Data.wire_value(), 1);
    assert_eq!(MessageType::ClientHello.wire_value(), 2);
    assert_eq!(MessageType::ServerHello.wire_value(), 3);
    assert_eq!(MessageType::ClientFinish.wire_value(), 4);
    assert_eq!(MessageType::ServerFinish.wire_value(), 5);
  }
}
