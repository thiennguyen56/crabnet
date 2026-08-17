//! Protocol version 2 handshake frame types.
//!
//! The wire decoder uses [`super::types::MessageType`] to classify a frame and
//! constructs a decoded enum whose variant preserves that identity. A role
//! classifier then validates whether the message is legal for the receiving
//! endpoint and constructs the corresponding directional enum variant.

use std::error::Error;
use std::fmt;

use crate::session::types::ClientAttemptId;

use super::types::{MessageType, ProtocolVersion};

const MAGIC: [u8; 4] = *b"CRBN";
const FLAGS_NONE: u16 = 0;

const COMMON_HEADER_LENGTH: usize = 10;
const ATTEMPT_ID_LENGTH: usize = 8;
const MINIMUM_BODY_LENGTH: usize = 9;
const MINIMUM_DATAGRAM_LENGTH: usize = 19;
const UDP_PAYLOAD_CEILING: usize = 65_507;

/// Validated metadata and opaque bytes shared by v2 handshake messages.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DecodedV2HandshakeBody<'datagram> {
  client_attempt_id: ClientAttemptId,
  opaque_payload: &'datagram [u8],
}

impl fmt::Debug for DecodedV2HandshakeBody<'_> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("DecodedV2HandshakeBody")
      .field("client_attempt_id", &self.client_attempt_id)
      .field("opaque_payload", &"<opaque>")
      .finish()
  }
}

impl<'datagram> DecodedV2HandshakeBody<'datagram> {
  /// Returns the non-zero client attempt identifier carried by the frame.
  pub(crate) const fn client_attempt_id(&self) -> ClientAttemptId {
    self.client_attempt_id
  }

  /// Returns the unchanged opaque payload borrowed from the input datagram.
  pub(crate) const fn opaque_payload(&self) -> &'datagram [u8] {
    self.opaque_payload
  }
}

/// Structurally valid version 2 handshake frame before role classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientInboundFrame<'datagram> {
  /// The server's response to a client hello.
  ServerHello(DecodedV2HandshakeBody<'datagram>),
  /// Confirmation that the server established the session.
  ServerFinish(DecodedV2HandshakeBody<'datagram>),
}

/// Version 2 handshake messages that a server may receive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerInboundFrame<'datagram> {
  /// A client's initial authentication message.
  ClientHello(DecodedV2HandshakeBody<'datagram>),
  /// A client's final authentication proof.
  ClientFinish(DecodedV2HandshakeBody<'datagram>),
}

/// Invalid version 2 codec configuration or derived buffer length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum V2CodecConfigError {
  /// The configured opaque-payload maximum is zero.
  ZeroMaximumOpaquePayload,
  /// The attempt ID and maximum payload do not fit the body-length field.
  BodyLengthNotRepresentable {
    maximum_opaque_payload: usize,
    maximum_body_length: usize,
  },
  /// The largest valid frame exceeds the IPv4-safe UDP payload ceiling.
  DatagramExceedsUdpCeiling {
    maximum_datagram_length: usize,
    ceiling: usize,
  },
  /// Adding framing overhead overflowed the platform length type.
  DerivedLengthOverflow { maximum_opaque_payload: usize },
}

impl fmt::Display for V2CodecConfigError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::ZeroMaximumOpaquePayload => {
        write!(formatter, "V2 maximum opaque payload cannot be zero")
      }
      Self::BodyLengthNotRepresentable {
        maximum_opaque_payload,
        maximum_body_length,
      } => write!(
        formatter,
        "V2 maximum opaque payload {maximum_opaque_payload} derives body length \
         {maximum_body_length}, which does not fit the 16-bit body-length field"
      ),
      Self::DatagramExceedsUdpCeiling {
        maximum_datagram_length,
        ceiling,
      } => write!(
        formatter,
        "V2 maximum datagram length {maximum_datagram_length} exceeds UDP payload ceiling {ceiling}"
      ),
      Self::DerivedLengthOverflow {
        maximum_opaque_payload,
      } => write!(
        formatter,
        "V2 framing length overflows for maximum opaque payload {maximum_opaque_payload}"
      ),
    }
  }
}

impl Error for V2CodecConfigError {}

/// Failure to encode a local version 2 handshake frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum V2EncodeError {
  /// The message type does not belong to the version 2 handshake protocol.
  UnsupportedMessageType { observed: MessageType },
  /// A zero client attempt ID cannot correlate a handshake.
  ZeroClientAttemptId,
  /// Handshake messages must carry at least one opaque byte.
  EmptyOpaquePayload,
  /// The payload exceeds the codec's configured maximum.
  OpaquePayloadTooLarge { size: usize, maximum: usize },
  /// The fixed attempt ID and payload do not fit the body-length field.
  BodyLengthNotRepresentable { body_length: usize },
  /// Adding framing overhead overflowed the platform length type.
  EncodedLengthOverflow { opaque_length: usize },
  /// The caller-owned output buffer cannot hold the complete frame.
  OutputBufferTooSmall { required: usize, available: usize },
}

impl fmt::Display for V2EncodeError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::UnsupportedMessageType { observed } => write!(
        formatter,
        "message type {observed:?} is not valid in a V2 handshake frame"
      ),
      Self::ZeroClientAttemptId => write!(formatter, "V2 client attempt ID cannot be zero"),
      Self::EmptyOpaquePayload => write!(formatter, "V2 opaque handshake payload cannot be empty"),
      Self::OpaquePayloadTooLarge { size, maximum } => write!(
        formatter,
        "V2 opaque handshake payload has {size} bytes but the configured maximum is {maximum}"
      ),
      Self::BodyLengthNotRepresentable { body_length } => write!(
        formatter,
        "V2 body length {body_length} does not fit the 16-bit body-length field"
      ),
      Self::EncodedLengthOverflow { opaque_length } => write!(
        formatter,
        "V2 encoded length overflows for opaque payload length {opaque_length}"
      ),
      Self::OutputBufferTooSmall {
        required,
        available,
      } => write!(
        formatter,
        "V2 output buffer has {available} bytes but {required} bytes are required"
      ),
    }
  }
}

impl Error for V2EncodeError {}

/// Reason an untrusted datagram is not a valid version 2 handshake frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum V2DecodeError {
  /// The datagram cannot contain the complete common header.
  DatagramTooShort { size: usize, minimum: usize },
  /// The four-byte Crabnet magic value does not match.
  InvalidMagic { observed: [u8; 4] },
  /// The frame is not protocol version 2.
  UnsupportedVersion { observed: u8 },
  /// The discriminator is not a version 2 handshake message type.
  UnsupportedMessageType { observed: u8 },
  /// Reserved header flags are non-zero.
  UnsupportedFlags { observed: u16 },
  /// The declared body length differs from the datagram contents.
  BodyLengthMismatch { declared: usize, actual: usize },
  /// The body cannot contain both an attempt ID and a non-empty payload.
  HandshakeBodyTooShort { size: usize, minimum: usize },
  /// A zero client attempt ID cannot correlate a handshake.
  ZeroClientAttemptId,
  /// The payload exceeds the codec's configured maximum.
  OpaquePayloadTooLarge { size: usize, maximum: usize },
}

impl fmt::Display for V2DecodeError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::DatagramTooShort { size, minimum } => write!(
        formatter,
        "datagram has {size} bytes but the V2 header requires at least {minimum}"
      ),
      Self::InvalidMagic { observed } => {
        write!(formatter, "invalid Crabnet V2 frame magic {observed:02x?}")
      }
      Self::UnsupportedVersion { observed } => write!(
        formatter,
        "unsupported Crabnet protocol version {observed} for V2 codec"
      ),
      Self::UnsupportedMessageType { observed } => {
        write!(formatter, "unsupported Crabnet V2 message type {observed}")
      }
      Self::UnsupportedFlags { observed } => {
        write!(
          formatter,
          "unsupported Crabnet V2 frame flags 0x{observed:04x}"
        )
      }
      Self::BodyLengthMismatch { declared, actual } => write!(
        formatter,
        "V2 frame declares {declared} body bytes but contains {actual}"
      ),
      Self::HandshakeBodyTooShort { size, minimum } => write!(
        formatter,
        "V2 handshake body has {size} bytes but requires at least {minimum}"
      ),
      Self::ZeroClientAttemptId => write!(formatter, "V2 client attempt ID cannot be zero"),
      Self::OpaquePayloadTooLarge { size, maximum } => write!(
        formatter,
        "V2 opaque handshake payload has {size} bytes but the configured maximum is {maximum}"
      ),
    }
  }
}

impl Error for V2DecodeError {}

/// A structurally valid frame is not legal for the receiving role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectionError {
  /// The decoded message was sent in the opposite handshake direction.
  UnexpectedDirection {
    receiver: Receiver,
    observed: MessageType,
  },
}

impl fmt::Display for DirectionError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::UnexpectedDirection { receiver, observed } => write!(
        formatter,
        "{receiver} cannot receive V2 handshake message type {observed:?}"
      ),
    }
  }
}

impl Error for DirectionError {}

/// Endpoint role used when reporting a direction violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Receiver {
  /// The initiating client.
  Client,
  /// The accepting server.
  Server,
}

impl fmt::Display for Receiver {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Client => write!(formatter, "client"),
      Self::Server => write!(formatter, "server"),
    }
  }
}

/// Pure version 2 handshake encoder and decoder with immutable size bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct V2HandshakeCodec {
  maximum_opaque_payload: usize,
  maximum_datagram_length: usize,
  receive_buffer_len: usize,
}

impl V2HandshakeCodec {
  /// Creates a codec and validates every derived frame and buffer length.
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
    if maximum_datagram_length > UDP_PAYLOAD_CEILING {
      return Err(V2CodecConfigError::DatagramExceedsUdpCeiling {
        maximum_datagram_length,
        ceiling: UDP_PAYLOAD_CEILING,
      });
    }

    let receive_buffer_len =
      maximum_datagram_length
        .checked_add(1)
        .ok_or(V2CodecConfigError::DerivedLengthOverflow {
          maximum_opaque_payload,
        })?;

    Ok(Self {
      maximum_opaque_payload,
      maximum_datagram_length,
      receive_buffer_len,
    })
  }

  /// Returns the configured maximum opaque handshake payload length.
  pub(crate) const fn maximum_opaque_payload(&self) -> usize {
    self.maximum_opaque_payload
  }

  /// Returns the largest valid encoded V2 handshake datagram length.
  pub(crate) const fn max_datagram_len(&self) -> usize {
    self.maximum_datagram_length
  }

  /// Returns the receive-buffer length used to detect oversized datagrams.
  pub(crate) const fn receive_buffer_len(&self) -> usize {
    self.receive_buffer_len
  }

  /// Encodes one complete V2 handshake frame into a caller-owned buffer.
  ///
  /// All validation occurs before the output buffer is modified.
  pub(crate) fn encode(
    &self,
    message_type: MessageType,
    client_attempt_id: ClientAttemptId,
    opaque_payload: &[u8],
    output: &mut [u8],
  ) -> Result<usize, V2EncodeError> {
    match message_type {
      MessageType::ClientHello
      | MessageType::ClientFinish
      | MessageType::ServerHello
      | MessageType::ServerFinish => (),
      MessageType::Data => {
        return Err(V2EncodeError::UnsupportedMessageType {
          observed: message_type,
        })
      }
    }
    if client_attempt_id.0 == 0 {
      return Err(V2EncodeError::ZeroClientAttemptId);
    }

    let (body_length, encoded_length) = self.encoded_lengths(opaque_payload.len())?;
    if output.len() < encoded_length {
      return Err(V2EncodeError::OutputBufferTooSmall {
        required: encoded_length,
        available: output.len(),
      });
    }

    output[0..4].copy_from_slice(&MAGIC);
    output[4] = ProtocolVersion::V2.wire_value();
    output[5] = message_type.wire_value();
    output[6..8].copy_from_slice(&FLAGS_NONE.to_be_bytes());
    output[8..10].copy_from_slice(&body_length.to_be_bytes());
    output[10..18].copy_from_slice(&client_attempt_id.0.to_be_bytes());
    output[18..encoded_length].copy_from_slice(opaque_payload);

    Ok(encoded_length)
  }

  /// Returns the complete encoded length for a valid opaque payload size.
  pub(crate) fn encoded_len(&self, opaque_length: usize) -> Result<usize, V2EncodeError> {
    self
      .encoded_lengths(opaque_length)
      .map(|(_, encoded_length)| encoded_length)
  }

  /// Validates an opaque length and returns its wire body and datagram lengths.
  fn encoded_lengths(&self, opaque_length: usize) -> Result<(u16, usize), V2EncodeError> {
    if opaque_length == 0 {
      return Err(V2EncodeError::EmptyOpaquePayload);
    }
    if opaque_length > self.maximum_opaque_payload {
      return Err(V2EncodeError::OpaquePayloadTooLarge {
        size: opaque_length,
        maximum: self.maximum_opaque_payload,
      });
    }

    let body_length = ATTEMPT_ID_LENGTH
      .checked_add(opaque_length)
      .ok_or(V2EncodeError::EncodedLengthOverflow { opaque_length })?;

    let wire_body_length = u16::try_from(body_length)
      .map_err(|_| V2EncodeError::BodyLengthNotRepresentable { body_length })?;

    let encoded_length = COMMON_HEADER_LENGTH
      .checked_add(body_length)
      .ok_or(V2EncodeError::EncodedLengthOverflow { opaque_length })?;

    Ok((wire_body_length, encoded_length))
  }

  /// Validates one complete datagram and borrows its opaque handshake payload.
  pub(crate) fn decode<'datagram>(
    &self,
    datagram: &'datagram [u8],
  ) -> Result<DecodedV2HandshakeFrame<'datagram>, V2DecodeError> {
    if datagram.len() < COMMON_HEADER_LENGTH {
      return Err(V2DecodeError::DatagramTooShort {
        size: datagram.len(),
        minimum: COMMON_HEADER_LENGTH,
      });
    }

    let mut observed_magic = [0u8; 4];
    observed_magic.copy_from_slice(&datagram[0..4]);
    if observed_magic != MAGIC {
      return Err(V2DecodeError::InvalidMagic {
        observed: observed_magic,
      });
    }

    decode_version(datagram[4])?;
    let message_type = decode_message_type(datagram[5])?;

    let flags = u16::from_be_bytes([datagram[6], datagram[7]]);
    if flags != FLAGS_NONE {
      return Err(V2DecodeError::UnsupportedFlags { observed: flags });
    }

    let declared_body_length = usize::from(u16::from_be_bytes([datagram[8], datagram[9]]));
    let actual_body_length = datagram.len() - COMMON_HEADER_LENGTH;
    if declared_body_length != actual_body_length {
      return Err(V2DecodeError::BodyLengthMismatch {
        declared: declared_body_length,
        actual: actual_body_length,
      });
    }

    if actual_body_length < MINIMUM_BODY_LENGTH {
      return Err(V2DecodeError::HandshakeBodyTooShort {
        size: actual_body_length,
        minimum: MINIMUM_BODY_LENGTH,
      });
    }

    let opaque_length = actual_body_length - ATTEMPT_ID_LENGTH;
    if opaque_length > self.maximum_opaque_payload {
      return Err(V2DecodeError::OpaquePayloadTooLarge {
        size: opaque_length,
        maximum: self.maximum_opaque_payload,
      });
    }

    let mut raw_attempt = [0u8; 8];
    raw_attempt.copy_from_slice(&datagram[10..18]);
    let attempt = u64::from_be_bytes(raw_attempt);
    if attempt == 0 {
      return Err(V2DecodeError::ZeroClientAttemptId);
    }

    let body = DecodedV2HandshakeBody {
      client_attempt_id: ClientAttemptId(attempt),
      opaque_payload: &datagram[18..datagram.len()],
    };

    match message_type {
      MessageType::ClientHello => Ok(DecodedV2HandshakeFrame::ClientHello(body)),
      MessageType::ServerHello => Ok(DecodedV2HandshakeFrame::ServerHello(body)),
      MessageType::ClientFinish => Ok(DecodedV2HandshakeFrame::ClientFinish(body)),
      MessageType::ServerFinish => Ok(DecodedV2HandshakeFrame::ServerFinish(body)),
      MessageType::Data => Err(V2DecodeError::UnsupportedMessageType {
        observed: MessageType::Data.wire_value(),
      }),
    }
  }
}

/// Decodes only protocol version 2.
fn decode_version(value: u8) -> Result<ProtocolVersion, V2DecodeError> {
  match value {
    2 => Ok(ProtocolVersion::V2),
    _ => Err(V2DecodeError::UnsupportedVersion { observed: value }),
  }
}

/// Decodes only message types belonging to the version 2 handshake.
fn decode_message_type(value: u8) -> Result<MessageType, V2DecodeError> {
  match value {
    2 => Ok(MessageType::ClientHello),
    3 => Ok(MessageType::ServerHello),
    4 => Ok(MessageType::ClientFinish),
    5 => Ok(MessageType::ServerFinish),
    _ => Err(V2DecodeError::UnsupportedMessageType { observed: value }),
  }
}

/// Accepts only server-to-client handshake messages.
pub(crate) fn classify_for_client<'datagram>(
  frame: DecodedV2HandshakeFrame<'datagram>,
) -> Result<ClientInboundFrame<'datagram>, DirectionError> {
  match frame {
    DecodedV2HandshakeFrame::ServerHello(body) => Ok(ClientInboundFrame::ServerHello(body)),
    DecodedV2HandshakeFrame::ServerFinish(body) => Ok(ClientInboundFrame::ServerFinish(body)),
    DecodedV2HandshakeFrame::ClientHello(_) => Err(DirectionError::UnexpectedDirection {
      receiver: Receiver::Client,
      observed: MessageType::ClientHello,
    }),
    DecodedV2HandshakeFrame::ClientFinish(_) => Err(DirectionError::UnexpectedDirection {
      receiver: Receiver::Client,
      observed: MessageType::ClientFinish,
    }),
  }
}

/// Accepts only client-to-server handshake messages.
pub(crate) fn classify_for_server<'datagram>(
  frame: DecodedV2HandshakeFrame<'datagram>,
) -> Result<ServerInboundFrame<'datagram>, DirectionError> {
  match frame {
    DecodedV2HandshakeFrame::ClientHello(body) => Ok(ServerInboundFrame::ClientHello(body)),
    DecodedV2HandshakeFrame::ClientFinish(body) => Ok(ServerInboundFrame::ClientFinish(body)),
    DecodedV2HandshakeFrame::ServerHello(_) => Err(DirectionError::UnexpectedDirection {
      receiver: Receiver::Server,
      observed: MessageType::ServerHello,
    }),
    DecodedV2HandshakeFrame::ServerFinish(_) => Err(DirectionError::UnexpectedDirection {
      receiver: Receiver::Server,
      observed: MessageType::ServerFinish,
    }),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const TEST_MAXIMUM_OPAQUE_PAYLOAD: usize = 4;
  const TEST_ATTEMPT_ID: ClientAttemptId = ClientAttemptId(0x0102_0304_0506_0708);
  const TEST_PAYLOAD: [u8; 3] = [0x00, 0xff, 0x80];

  fn codec() -> V2HandshakeCodec {
    V2HandshakeCodec::new(TEST_MAXIMUM_OPAQUE_PAYLOAD)
      .expect("test V2 codec configuration should be valid")
  }

  fn encode(message_type: MessageType, attempt: ClientAttemptId, payload: &[u8]) -> Vec<u8> {
    let codec = codec();
    let mut output = vec![0_u8; codec.max_datagram_len()];
    let encoded_length = codec
      .encode(message_type, attempt, payload, &mut output)
      .expect("test V2 frame should encode");
    output.truncate(encoded_length);
    output
  }

  fn frame_body(frame: DecodedV2HandshakeFrame<'_>) -> DecodedV2HandshakeBody<'_> {
    match frame {
      DecodedV2HandshakeFrame::ClientHello(body)
      | DecodedV2HandshakeFrame::ServerHello(body)
      | DecodedV2HandshakeFrame::ClientFinish(body)
      | DecodedV2HandshakeFrame::ServerFinish(body) => body,
    }
  }

  fn datagram_with_body(body: &[u8]) -> Vec<u8> {
    let body_length = u16::try_from(body.len()).expect("test body length should fit");
    let mut datagram = vec![
      0x43,
      0x52,
      0x42,
      0x4e,
      0x02,
      0x02,
      0x00,
      0x00,
      body_length.to_be_bytes()[0],
      body_length.to_be_bytes()[1],
    ];
    datagram.extend_from_slice(body);
    datagram
  }

  #[test]
  fn rejects_invalid_codec_configuration() {
    assert_eq!(
      V2HandshakeCodec::new(0),
      Err(V2CodecConfigError::ZeroMaximumOpaquePayload)
    );

    let unrepresentable_payload = usize::from(u16::MAX);
    assert_eq!(
      V2HandshakeCodec::new(unrepresentable_payload),
      Err(V2CodecConfigError::BodyLengthNotRepresentable {
        maximum_opaque_payload: unrepresentable_payload,
        maximum_body_length: ATTEMPT_ID_LENGTH + unrepresentable_payload,
      })
    );

    assert_eq!(
      V2HandshakeCodec::new(usize::MAX),
      Err(V2CodecConfigError::DerivedLengthOverflow {
        maximum_opaque_payload: usize::MAX,
      })
    );
  }

  #[test]
  fn derives_exact_minimum_and_maximum_buffer_boundaries() {
    let minimum_codec =
      V2HandshakeCodec::new(1).expect("minimum V2 codec configuration should be valid");
    assert_eq!(minimum_codec.maximum_opaque_payload(), 1);
    assert_eq!(minimum_codec.max_datagram_len(), MINIMUM_DATAGRAM_LENGTH);
    assert_eq!(
      minimum_codec.receive_buffer_len(),
      MINIMUM_DATAGRAM_LENGTH + 1
    );

    let largest_opaque_payload = UDP_PAYLOAD_CEILING - COMMON_HEADER_LENGTH - ATTEMPT_ID_LENGTH;
    let maximum_codec = V2HandshakeCodec::new(largest_opaque_payload)
      .expect("largest UDP-safe V2 codec configuration should be valid");
    assert_eq!(
      maximum_codec.maximum_opaque_payload(),
      largest_opaque_payload
    );
    assert_eq!(maximum_codec.max_datagram_len(), UDP_PAYLOAD_CEILING);
    assert_eq!(maximum_codec.receive_buffer_len(), UDP_PAYLOAD_CEILING + 1);

    assert_eq!(
      V2HandshakeCodec::new(largest_opaque_payload + 1),
      Err(V2CodecConfigError::DatagramExceedsUdpCeiling {
        maximum_datagram_length: UDP_PAYLOAD_CEILING + 1,
        ceiling: UDP_PAYLOAD_CEILING,
      })
    );
  }

  #[test]
  fn encodes_exact_vectors_for_every_v2_message_type() {
    for (message_type, discriminator) in [
      (MessageType::ClientHello, 0x02),
      (MessageType::ServerHello, 0x03),
      (MessageType::ClientFinish, 0x04),
      (MessageType::ServerFinish, 0x05),
    ] {
      let encoded = encode(message_type, TEST_ATTEMPT_ID, &TEST_PAYLOAD);

      assert_eq!(
        encoded,
        [
          0x43,
          0x52,
          0x42,
          0x4e,
          0x02,
          discriminator,
          0x00,
          0x00,
          0x00,
          0x0b,
          0x01,
          0x02,
          0x03,
          0x04,
          0x05,
          0x06,
          0x07,
          0x08,
          0x00,
          0xff,
          0x80,
        ]
      );
    }
  }

  #[test]
  fn encodes_attempt_ids_in_network_byte_order() {
    for attempt in [
      ClientAttemptId(1),
      ClientAttemptId(0x0102_0304_0506_0708),
      ClientAttemptId(u64::MAX),
    ] {
      let encoded = encode(MessageType::ClientHello, attempt, &[0xaa]);
      assert_eq!(&encoded[10..18], &attempt.0.to_be_bytes());
    }
  }

  #[test]
  fn encoded_length_includes_header_attempt_id_and_payload() {
    let codec = codec();

    for opaque_length in 1..=TEST_MAXIMUM_OPAQUE_PAYLOAD {
      assert_eq!(
        codec.encoded_len(opaque_length),
        Ok(COMMON_HEADER_LENGTH + ATTEMPT_ID_LENGTH + opaque_length)
      );
    }
  }

  #[test]
  fn encoding_preserves_binary_payload_and_trailing_output() {
    let codec = codec();
    let payload = [0x00, 0xff, 0x80, 0xc3];
    let mut output = [0xaa; 24];

    let encoded_length = codec
      .encode(
        MessageType::ServerHello,
        TEST_ATTEMPT_ID,
        &payload,
        &mut output,
      )
      .expect("binary V2 payload should encode");

    assert_eq!(encoded_length, 22);
    assert_eq!(&output[18..encoded_length], payload);
    assert_eq!(&output[encoded_length..], &[0xaa, 0xaa]);
  }

  #[test]
  fn every_encode_error_leaves_output_unchanged() {
    let codec = codec();

    let mut unsupported_output = [0xaa; 32];
    let before = unsupported_output;
    assert_eq!(
      codec.encode(
        MessageType::Data,
        TEST_ATTEMPT_ID,
        &[1],
        &mut unsupported_output,
      ),
      Err(V2EncodeError::UnsupportedMessageType {
        observed: MessageType::Data,
      })
    );
    assert_eq!(unsupported_output, before);

    let mut zero_id_output = [0xaa; 32];
    let before = zero_id_output;
    assert_eq!(
      codec.encode(
        MessageType::ClientHello,
        ClientAttemptId(0),
        &[1],
        &mut zero_id_output,
      ),
      Err(V2EncodeError::ZeroClientAttemptId)
    );
    assert_eq!(zero_id_output, before);

    let mut empty_output = [0xaa; 32];
    let before = empty_output;
    assert_eq!(
      codec.encode(
        MessageType::ClientHello,
        TEST_ATTEMPT_ID,
        &[],
        &mut empty_output,
      ),
      Err(V2EncodeError::EmptyOpaquePayload)
    );
    assert_eq!(empty_output, before);

    let mut oversized_output = [0xaa; 32];
    let before = oversized_output;
    assert_eq!(
      codec.encode(
        MessageType::ClientHello,
        TEST_ATTEMPT_ID,
        &[1; TEST_MAXIMUM_OPAQUE_PAYLOAD + 1],
        &mut oversized_output,
      ),
      Err(V2EncodeError::OpaquePayloadTooLarge {
        size: TEST_MAXIMUM_OPAQUE_PAYLOAD + 1,
        maximum: TEST_MAXIMUM_OPAQUE_PAYLOAD,
      })
    );
    assert_eq!(oversized_output, before);

    let mut short_output = [0xaa; MINIMUM_DATAGRAM_LENGTH - 1];
    let before = short_output;
    assert_eq!(
      codec.encode(
        MessageType::ClientHello,
        TEST_ATTEMPT_ID,
        &[1],
        &mut short_output,
      ),
      Err(V2EncodeError::OutputBufferTooSmall {
        required: MINIMUM_DATAGRAM_LENGTH,
        available: MINIMUM_DATAGRAM_LENGTH - 1,
      })
    );
    assert_eq!(short_output, before);
  }

  #[test]
  fn all_message_types_round_trip_at_payload_boundaries() {
    let codec = codec();

    for message_type in [
      MessageType::ClientHello,
      MessageType::ServerHello,
      MessageType::ClientFinish,
      MessageType::ServerFinish,
    ] {
      for payload in [&[0x01][..], &[0x00, 0xff, 0x80, 0xc3][..]] {
        let datagram = encode(message_type, TEST_ATTEMPT_ID, payload);
        let decoded = codec
          .decode(&datagram)
          .expect("valid V2 frame should decode");
        let body = frame_body(decoded);

        assert_eq!(decoded.version(), ProtocolVersion::V2);
        assert_eq!(decoded.message_type(), message_type);
        assert_eq!(body.client_attempt_id(), TEST_ATTEMPT_ID);
        assert_eq!(body.opaque_payload(), payload);
        assert_eq!(
          body.opaque_payload().as_ptr(),
          datagram[18..].as_ptr(),
          "decoded payload must borrow the input datagram"
        );
      }
    }
  }

  #[test]
  fn rejects_every_datagram_shorter_than_the_common_header() {
    let codec = codec();

    for size in 0..COMMON_HEADER_LENGTH {
      assert_eq!(
        codec.decode(&vec![0_u8; size]),
        Err(V2DecodeError::DatagramTooShort {
          size,
          minimum: COMMON_HEADER_LENGTH,
        })
      );
    }
  }

  #[test]
  fn rejects_unsupported_header_fields() {
    let codec = codec();
    let valid = encode(MessageType::ClientHello, TEST_ATTEMPT_ID, &[1]);

    for index in 0..MAGIC.len() {
      let mut invalid = valid.clone();
      invalid[index] ^= 0xff;
      assert!(matches!(
        codec.decode(&invalid),
        Err(V2DecodeError::InvalidMagic { .. })
      ));
    }

    let mut invalid_version = valid.clone();
    invalid_version[4] = ProtocolVersion::V1.wire_value();
    assert_eq!(
      codec.decode(&invalid_version),
      Err(V2DecodeError::UnsupportedVersion { observed: 1 })
    );

    for observed in [0, 1, 6, u8::MAX] {
      let mut invalid_type = valid.clone();
      invalid_type[5] = observed;
      assert_eq!(
        codec.decode(&invalid_type),
        Err(V2DecodeError::UnsupportedMessageType { observed })
      );
    }

    let mut invalid_flags = valid;
    invalid_flags[6..8].copy_from_slice(&0x0102_u16.to_be_bytes());
    assert_eq!(
      codec.decode(&invalid_flags),
      Err(V2DecodeError::UnsupportedFlags { observed: 0x0102 })
    );
  }

  #[test]
  fn rejects_mismatched_body_lengths_and_trailing_bytes() {
    let codec = codec();
    let valid = encode(MessageType::ClientHello, TEST_ATTEMPT_ID, &[1, 2]);

    let mut declared_short = valid.clone();
    declared_short[8..10].copy_from_slice(&9_u16.to_be_bytes());
    assert_eq!(
      codec.decode(&declared_short),
      Err(V2DecodeError::BodyLengthMismatch {
        declared: 9,
        actual: 10,
      })
    );

    let mut declared_long = valid.clone();
    declared_long[8..10].copy_from_slice(&11_u16.to_be_bytes());
    assert_eq!(
      codec.decode(&declared_long),
      Err(V2DecodeError::BodyLengthMismatch {
        declared: 11,
        actual: 10,
      })
    );

    let mut trailing = valid;
    trailing.push(0xaa);
    assert_eq!(
      codec.decode(&trailing),
      Err(V2DecodeError::BodyLengthMismatch {
        declared: 10,
        actual: 11,
      })
    );
  }

  #[test]
  fn rejects_short_bodies_zero_attempt_ids_and_oversized_payloads() {
    let codec = codec();

    for body_length in 0..MINIMUM_BODY_LENGTH {
      let datagram = datagram_with_body(&vec![0_u8; body_length]);
      assert_eq!(
        codec.decode(&datagram),
        Err(V2DecodeError::HandshakeBodyTooShort {
          size: body_length,
          minimum: MINIMUM_BODY_LENGTH,
        })
      );
    }

    let zero_attempt = datagram_with_body(&[0_u8; MINIMUM_BODY_LENGTH]);
    assert_eq!(
      codec.decode(&zero_attempt),
      Err(V2DecodeError::ZeroClientAttemptId)
    );

    let mut oversized_body = TEST_ATTEMPT_ID.0.to_be_bytes().to_vec();
    oversized_body.extend_from_slice(&[0xaa; TEST_MAXIMUM_OPAQUE_PAYLOAD + 1]);
    let oversized = datagram_with_body(&oversized_body);
    assert_eq!(oversized.len(), codec.receive_buffer_len());
    assert_eq!(
      codec.decode(&oversized),
      Err(V2DecodeError::OpaquePayloadTooLarge {
        size: TEST_MAXIMUM_OPAQUE_PAYLOAD + 1,
        maximum: TEST_MAXIMUM_OPAQUE_PAYLOAD,
      })
    );
  }

  #[test]
  fn every_truncation_of_every_valid_message_is_rejected() {
    let codec = codec();

    for message_type in [
      MessageType::ClientHello,
      MessageType::ServerHello,
      MessageType::ClientFinish,
      MessageType::ServerFinish,
    ] {
      let valid = encode(message_type, TEST_ATTEMPT_ID, &TEST_PAYLOAD);
      for truncated_length in 0..valid.len() {
        assert!(
          codec.decode(&valid[..truncated_length]).is_err(),
          "{message_type:?} truncation at {truncated_length} bytes was accepted"
        );
      }
    }
  }

  #[test]
  fn classifiers_enforce_the_complete_direction_matrix() {
    let codec = codec();

    for message_type in [
      MessageType::ClientHello,
      MessageType::ServerHello,
      MessageType::ClientFinish,
      MessageType::ServerFinish,
    ] {
      let datagram = encode(message_type, TEST_ATTEMPT_ID, &[1]);
      let client_frame = codec.decode(&datagram).expect("test frame should decode");
      let server_frame = codec.decode(&datagram).expect("test frame should decode");

      match message_type {
        MessageType::ClientHello => {
          assert_eq!(
            classify_for_client(client_frame),
            Err(DirectionError::UnexpectedDirection {
              receiver: Receiver::Client,
              observed: message_type,
            })
          );
          assert!(matches!(
            classify_for_server(server_frame),
            Ok(ServerInboundFrame::ClientHello(_))
          ));
        }
        MessageType::ServerHello => {
          assert!(matches!(
            classify_for_client(client_frame),
            Ok(ClientInboundFrame::ServerHello(_))
          ));
          assert_eq!(
            classify_for_server(server_frame),
            Err(DirectionError::UnexpectedDirection {
              receiver: Receiver::Server,
              observed: message_type,
            })
          );
        }
        MessageType::ClientFinish => {
          assert_eq!(
            classify_for_client(client_frame),
            Err(DirectionError::UnexpectedDirection {
              receiver: Receiver::Client,
              observed: message_type,
            })
          );
          assert!(matches!(
            classify_for_server(server_frame),
            Ok(ServerInboundFrame::ClientFinish(_))
          ));
        }
        MessageType::ServerFinish => {
          assert!(matches!(
            classify_for_client(client_frame),
            Ok(ClientInboundFrame::ServerFinish(_))
          ));
          assert_eq!(
            classify_for_server(server_frame),
            Err(DirectionError::UnexpectedDirection {
              receiver: Receiver::Server,
              observed: message_type,
            })
          );
        }
        MessageType::Data => unreachable!("test matrix contains only V2 handshake types"),
      }
    }
  }

  #[test]
  fn v2_rejects_a_valid_v1_data_frame_without_downgrade() {
    let codec = codec();
    let v1_frame = [
      0x43, 0x52, 0x42, 0x4e, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x45,
    ];

    assert_eq!(
      codec.decode(&v1_frame),
      Err(V2DecodeError::UnsupportedVersion { observed: 1 })
    );
  }

  #[test]
  fn diagnostics_do_not_expose_opaque_payload_bytes() {
    let payload = [0xde, 0xad, 0xbe, 0xef];
    let datagram = encode(MessageType::ClientHello, TEST_ATTEMPT_ID, &payload);
    let frame = codec().decode(&datagram).expect("test frame should decode");
    let rendered = format!("{frame:?}");

    assert!(rendered.contains("<opaque>"));
    assert!(!rendered.contains("[222, 173, 190, 239]"));

    let error = V2DecodeError::OpaquePayloadTooLarge {
      size: payload.len(),
      maximum: payload.len() - 1,
    };
    assert!(!error.to_string().contains("deadbeef"));
    assert!(!format!("{error:?}").contains("[222, 173, 190, 239]"));
  }
}
