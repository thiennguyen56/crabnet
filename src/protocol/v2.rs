//! Protocol version 2 handshake frame types.
//!
//! The wire decoder uses [`super::types::MessageType`] to classify a frame and
//! constructs a decoded enum whose variant preserves that identity. A role
//! classifier then validates whether the message is legal for the receiving
//! endpoint and constructs the corresponding directional enum variant.

use crate::session::types::ClientAttemptId;

use super::types::{MessageType, ProtocolVersion};

const COMMON_HEADER_LENGTH: usize = 10;
const ATTEMPT_ID_LENGTH: usize = 8;
const MINIMUM_BODY_LENGTH: usize = 9;
const MINIMUM_DATAGRAM_LENGTH: usize = 19;

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
  /// Returns the protocol version represented by this decoded frame.
  pub(crate) const fn version(&self) -> ProtocolVersion {
    ProtocolVersion::V2
  }

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

pub(crate) enum V2CodecConfigError {
  ZeroMaximumOpaquePayload,
  BodyLengthNotRepresentable {
    maximum_opaque_payload: usize,
    maximum_body_length: usize,
  },
  DatagramExceedsUdpCeiling {
    maximum_datagram_length: usize,
    ceiling: usize,
  },
  DerivedLengthOverflow {
    maximum_opaque_payload: usize,
  },
}

pub(crate) enum V2EncodeError {
  UnsupportedMessageType { observed: MessageType },
  ZeroClientAttemptId,
  EmptyOpaquePayload,
  OpaquePayloadTooLarge { size: usize, maximum: usize },
  BodyLengthNotRepresentable { body_length: usize },
  EncodedLengthOverflow { opaque_length: usize },
  OutputBufferTooSmall { required: usize, available: usize },
}

pub(crate) enum V2DecodeError {
  DatagramTooShort { size: usize, minimum: usize },
  InvalidMagic { observed: [u8; 4] },
  UnsupportedVersion { observed: u8 },
  UnsupportedMessageType { observed: u8 },
  UnsupportedFlags { observed: u16 },
  BodyLengthMismatch { declared: usize, actual: usize },
  HandshakeBodyTooShort { size: usize, minimum: usize },
  ZeroClientAttemptId,
  OpaquePayloadTooLarge { size: usize, maximum: usize },
}

pub(crate) enum DirectionError {
  UnexpectedDirection {
    receiver: Receiver,
    observed: MessageType,
  },
}

pub(crate) enum Receiver {
  Client,
  Server,
}

pub(crate) struct V2HandshakeCodec {
  maximum_opaque_payload: usize,
  maximum_datagram_length: usize,
  receive_buffer_len: usize,
}

impl V2HandshakeCodec {
  pub(crate) fn new(maximum_opaque_payload: usize) -> Result<Self, V2CodecConfigError> {
    if maximum_opaque_payload == 0 {
      return Err(V2CodecConfigError::ZeroMaximumOpaquePayload);
    }

    let maximum_body_length = ATTEMPT_ID_LENGTH
      .checked_add(maximum_opaque_payload)
      .ok_or(V2CodecConfigError::DerivedLengthOverflow {
        maximum_opaque_payload,
      })?;
    u16::try_from(maximum_body_length).map_err(|_| {
      V2CodecConfigError::BodyLengthNotRepresentable {
        maximum_opaque_payload,
        maximum_body_length,
      }
    })?;

    let maximum_datagram_length = COMMON_HEADER_LENGTH
      .checked_add(maximum_body_length)
      .ok_or(V2CodecConfigError::DerivedLengthOverflow {
        maximum_opaque_payload,
      })?;
    if maximum_datagram_length > 65507 {
      return Err(V2CodecConfigError::DatagramExceedsUdpCeiling {
        maximum_datagram_length,
        ceiling: 65507,
      });
    }

    let receive_buffer_len =
      maximum_datagram_length
        .checked_add(1)
        .ok_or(V2CodecConfigError::DerivedLengthOverflow {
          maximum_opaque_payload,
        })?;

    Ok(V2HandshakeCodec {
      maximum_opaque_payload,
      maximum_datagram_length,
      receive_buffer_len,
    })
  }

  pub(crate) fn encode(
    &self,
    message_type: MessageType,
    client_attempt_id: ClientAttemptId,
    opaque_payload: &[u8],
    output: &mut [u8],
  ) -> Result<usize, V2EncodeError> {
    todo!()
  }

  pub(crate) fn encoded_len(&self, opaque_length: usize) -> Result<usize, V2EncodeError> {
    todo!()
  }

  pub(crate) fn decode<'a>(
    &self,
    datagram: &'a [u8],
  ) -> Result<DecodedV2HandshakeFrame<'a>, V2DecodeError> {
    todo!()
  }
}
