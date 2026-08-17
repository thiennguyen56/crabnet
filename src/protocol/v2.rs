//! Protocol version 2 handshake frame types.
//!
//! The wire decoder uses [`super::types::MessageType`] to classify a frame and
//! constructs a decoded enum whose variant preserves that identity. A role
//! classifier then validates whether the message is legal for the receiving
//! endpoint and constructs the corresponding directional enum variant.

use crate::session::types::ClientAttemptId;

use super::types::MessageType;

/// Validated metadata and opaque bytes shared by v2 handshake messages.
pub(crate) struct DecodedV2HandshakeBody<'datagram> {
  client_attempt_id: ClientAttemptId,
  opaque_payload: &'datagram [u8],
}

/// Structurally valid version 2 handshake frame before role classification.
pub(crate) enum DecodedV2HandshakeFrame<'datagram> {
  /// A decoded client hello.
  ClientHello(DecodedV2HandshakeBody<'datagram>),
  /// A decoded server hello.
  ServerHello(DecodedV2HandshakeBody<'datagram>),
  /// A decoded client finish.
  ClientFinish(DecodedV2HandshakeBody<'datagram>),
  /// A decoded server finish.
  ServerFinish(DecodedV2HandshakeBody<'datagram>),
}

impl DecodedV2HandshakeFrame<'_> {
  /// Returns the shared message type represented by this decoded variant.
  pub(crate) const fn message_type(&self) -> MessageType {
    match self {
      Self::ClientHello(_) => MessageType::ClientHello,
      Self::ServerHello(_) => MessageType::ServerHello,
      Self::ClientFinish(_) => MessageType::ClientFinish,
      Self::ServerFinish(_) => MessageType::ServerFinish,
    }
  }
}

/// Version 2 handshake messages that a client may receive.
pub(crate) enum ClientInboundFrame<'datagram> {
  /// The server's response to a client hello.
  ServerHello(DecodedV2HandshakeBody<'datagram>),
  /// Confirmation that the server established the session.
  ServerFinish(DecodedV2HandshakeBody<'datagram>),
}

/// Version 2 handshake messages that a server may receive.
pub(crate) enum ServerInboundFrame<'datagram> {
  /// A client's initial authentication message.
  ClientHello(DecodedV2HandshakeBody<'datagram>),
  /// A client's final authentication proof.
  ClientFinish(DecodedV2HandshakeBody<'datagram>),
}
