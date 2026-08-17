//! Version 1 Crabnet framing for raw inner IP packets.
//!
//! Version 1 wraps one non-empty inner packet in one UDP datagram using a
//! fixed-size header containing magic bytes, a version, a message type,
//! reserved flags, and a big-endian payload length. Decoding validates the
//! complete frame and returns a borrowed payload slice.
//!
//! This format provides framing only. It does not authenticate, encrypt, or
//! protect packets from replay.
use std::error::Error;
use std::fmt;

use super::types::{DecodedFrame, MessageType, ProtocolVersion};

const MAGIC: [u8; 4] = *b"CRBN";
const HEADER_LEN: usize = 10;
const FLAGS_NONE: u16 = 0;

/// Decodes only the protocol version supported by the version 1 codec.
fn decode_version(value: u8) -> Result<ProtocolVersion, DecodeError> {
  match value {
    1 => Ok(ProtocolVersion::V1),
    _ => Err(DecodeError::UnsupportedVersion { observed: value }),
  }
}

/// Decodes only message types supported by protocol version 1.
fn decode_message_type(value: u8) -> Result<MessageType, DecodeError> {
  match value {
    1 => Ok(MessageType::Data),
    _ => Err(DecodeError::UnknownMessageType { observed: value }),
  }
}

/// Stateless frame encoder and decoder bounded by one inner-packet MTU.
///
/// Construction validates every derived buffer length. Encoding writes into a
/// caller-owned reusable buffer, while decoding borrows directly from the UDP
/// receive buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FrameCodec {
  mtu: usize,
  maximum_datagram_len: usize,
  receive_buffer_len: usize,
}

impl FrameCodec {
  /// Creates a codec and validates its payload and buffer-size limits.
  pub(crate) fn new(mtu: usize) -> Result<Self, CodecConfigError> {
    if mtu == 0 {
      return Err(CodecConfigError::ZeroMtu);
    }

    u16::try_from(mtu).map_err(|_| CodecConfigError::MtuNotRepresentable { mtu })?;

    let maximum_datagram_len = HEADER_LEN
      .checked_add(mtu)
      .ok_or(CodecConfigError::DatagramLengthOverflow { mtu })?;
    let receive_buffer_len = maximum_datagram_len
      .checked_add(1)
      .ok_or(CodecConfigError::DatagramLengthOverflow { mtu })?;

    Ok(Self {
      mtu,
      maximum_datagram_len,
      receive_buffer_len,
    })
  }

  /// Returns the largest valid framed UDP datagram length.
  pub(crate) const fn max_datagram_len(&self) -> usize {
    self.maximum_datagram_len
  }

  /// Returns the receive-buffer length used to detect oversized datagrams.
  pub(crate) const fn receive_buffer_len(&self) -> usize {
    self.receive_buffer_len
  }

  /// Returns the encoded frame length for a valid payload size.
  pub(crate) fn encoded_len(&self, payload_len: usize) -> Result<usize, EncodeError> {
    if payload_len == 0 {
      return Err(EncodeError::EmptyPayload);
    }

    if payload_len > self.mtu {
      return Err(EncodeError::PayloadTooLarge {
        size: payload_len,
        mtu: self.mtu,
      });
    }

    HEADER_LEN
      .checked_add(payload_len)
      .ok_or(EncodeError::EncodedLengthOverflow {
        payload_size: payload_len,
      })
  }

  /// Encodes one data frame into a caller-owned output buffer.
  ///
  /// All validation occurs before the output buffer is modified.
  pub(crate) fn encode_data(
    &self,
    payload: &[u8],
    output: &mut [u8],
  ) -> Result<usize, EncodeError> {
    let encoded_len = self.encoded_len(payload.len())?;

    if output.len() < encoded_len {
      return Err(EncodeError::OutputBufferTooSmall {
        required: encoded_len,
        available: output.len(),
      });
    }

    let payload_len =
      u16::try_from(payload.len()).map_err(|_| EncodeError::PayloadLengthNotRepresentable {
        size: payload.len(),
      })?;

    output[0..4].copy_from_slice(&MAGIC);
    output[4] = ProtocolVersion::V1.wire_value();
    output[5] = MessageType::Data.wire_value();
    output[6..8].copy_from_slice(&FLAGS_NONE.to_be_bytes());
    output[8..10].copy_from_slice(&payload_len.to_be_bytes());
    output[HEADER_LEN..encoded_len].copy_from_slice(payload);

    Ok(encoded_len)
  }

  /// Validates one complete datagram and borrows its inner payload.
  pub(crate) fn decode<'a>(&self, datagram: &'a [u8]) -> Result<DecodedFrame<'a>, DecodeError> {
    if datagram.len() < HEADER_LEN {
      return Err(DecodeError::DatagramTooShort {
        size: datagram.len(),
        minimum: HEADER_LEN,
      });
    }

    let mut observed_magic = [0_u8; 4];
    observed_magic.copy_from_slice(&datagram[0..4]);
    if observed_magic != MAGIC {
      return Err(DecodeError::InvalidMagic {
        observed: observed_magic,
      });
    }

    decode_version(datagram[4])?;
    let message_type = decode_message_type(datagram[5])?;

    let flags = u16::from_be_bytes([datagram[6], datagram[7]]);
    if flags != FLAGS_NONE {
      return Err(DecodeError::UnsupportedFlags { observed: flags });
    }

    let declared = usize::from(u16::from_be_bytes([datagram[8], datagram[9]]));
    let actual = datagram.len() - HEADER_LEN;

    if declared != actual {
      return Err(DecodeError::PayloadLengthMismatch { declared, actual });
    }

    if actual == 0 {
      return Err(DecodeError::EmptyPayload);
    }

    if actual > self.mtu {
      return Err(DecodeError::PayloadTooLarge {
        size: actual,
        mtu: self.mtu,
      });
    }

    Ok(DecodedFrame {
      message_type,
      payload: &datagram[HEADER_LEN..],
    })
  }
}

/// Invalid codec configuration or derived buffer size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CodecConfigError {
  /// The inner-packet MTU is zero.
  ZeroMtu,
  /// The MTU cannot be represented by the version 1 payload-length field.
  MtuNotRepresentable { mtu: usize },
  /// Adding framing overhead would overflow the platform length type.
  DatagramLengthOverflow { mtu: usize },
}

impl fmt::Display for CodecConfigError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::ZeroMtu => write!(formatter, "frame codec MTU cannot be zero"),
      Self::MtuNotRepresentable { mtu } => write!(
        formatter,
        "MTU {mtu} cannot be represented by the 16-bit frame payload-length field"
      ),
      Self::DatagramLengthOverflow { mtu } => {
        write!(formatter, "frame datagram length overflows for MTU {mtu}")
      }
    }
  }
}

impl Error for CodecConfigError {}

/// Failure to encode a local inner packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EncodeError {
  /// Empty inner packets are not valid data messages.
  EmptyPayload,
  /// The inner packet exceeds the configured TUN MTU.
  PayloadTooLarge { size: usize, mtu: usize },
  /// The payload length cannot be represented in the version 1 header.
  PayloadLengthNotRepresentable { size: usize },
  /// Adding the header length overflowed the platform length type.
  EncodedLengthOverflow { payload_size: usize },
  /// The caller-provided reusable buffer cannot hold the complete frame.
  OutputBufferTooSmall { required: usize, available: usize },
}

impl fmt::Display for EncodeError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::EmptyPayload => write!(formatter, "cannot encode an empty inner packet"),
      Self::PayloadTooLarge { size, mtu } => {
        write!(formatter, "inner packet size {size} exceeds TUN MTU {mtu}")
      }
      Self::PayloadLengthNotRepresentable { size } => write!(
        formatter,
        "inner packet size {size} cannot be represented by the frame payload-length field"
      ),
      Self::EncodedLengthOverflow { payload_size } => {
        write!(
          formatter,
          "encoded length overflows for payload size {payload_size}"
        )
      }
      Self::OutputBufferTooSmall {
        required,
        available,
      } => write!(
        formatter,
        "frame output buffer has {available} bytes but {required} bytes are required"
      ),
    }
  }
}

impl Error for EncodeError {}

/// Reason an untrusted UDP datagram is not a valid Crabnet frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DecodeError {
  /// The datagram cannot contain a complete fixed-size header.
  DatagramTooShort { size: usize, minimum: usize },
  /// The four-byte Crabnet magic value does not match.
  InvalidMagic { observed: [u8; 4] },
  /// The peer uses a protocol version this process does not support.
  UnsupportedVersion { observed: u8 },
  /// The frame declares an unknown message type.
  UnknownMessageType { observed: u8 },
  /// Reserved flags are non-zero.
  UnsupportedFlags { observed: u16 },
  /// A data message does not contain an inner packet.
  EmptyPayload,
  /// The declared payload length differs from the datagram contents.
  PayloadLengthMismatch { declared: usize, actual: usize },
  /// The decoded inner packet exceeds the configured TUN MTU.
  PayloadTooLarge { size: usize, mtu: usize },
}

impl fmt::Display for DecodeError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::DatagramTooShort { size, minimum } => write!(
        formatter,
        "datagram has {size} bytes but the frame header requires at least {minimum}"
      ),
      Self::InvalidMagic { observed } => {
        write!(formatter, "invalid Crabnet frame magic {observed:02x?}")
      }
      Self::UnsupportedVersion { observed } => {
        write!(formatter, "unsupported Crabnet protocol version {observed}")
      }
      Self::UnknownMessageType { observed } => {
        write!(formatter, "unknown Crabnet message type {observed}")
      }
      Self::UnsupportedFlags { observed } => {
        write!(
          formatter,
          "unsupported Crabnet frame flags 0x{observed:04x}"
        )
      }
      Self::EmptyPayload => write!(formatter, "Crabnet data frame has an empty payload"),
      Self::PayloadLengthMismatch { declared, actual } => write!(
        formatter,
        "frame declares {declared} payload bytes but contains {actual}"
      ),
      Self::PayloadTooLarge { size, mtu } => {
        write!(formatter, "frame payload size {size} exceeds TUN MTU {mtu}")
      }
    }
  }
}

impl Error for DecodeError {}

#[cfg(test)]
mod tests {
  use super::*;

  fn codec() -> FrameCodec {
    FrameCodec::new(1400).unwrap()
  }

  fn encode(payload: &[u8]) -> Vec<u8> {
    let codec = codec();
    let mut output = vec![0_u8; codec.max_datagram_len()];
    let size = codec.encode_data(payload, &mut output).unwrap();
    output.truncate(size);
    output
  }

  #[test]
  fn rejects_invalid_codec_mtu() {
    assert_eq!(FrameCodec::new(0), Err(CodecConfigError::ZeroMtu));
    assert_eq!(
      FrameCodec::new(usize::from(u16::MAX) + 1),
      Err(CodecConfigError::MtuNotRepresentable {
        mtu: usize::from(u16::MAX) + 1,
      })
    );
  }

  #[test]
  fn calculates_frame_and_receive_buffer_boundaries() {
    let codec = codec();

    assert_eq!(codec.max_datagram_len(), 1410);
    assert_eq!(codec.receive_buffer_len(), 1411);
  }

  #[test]
  fn encodes_exact_version_one_data_frame() {
    let codec = codec();
    let payload = [0x45, 0x00, 0x00, 0x14];
    let mut output = [0_u8; 14];

    let size = codec.encode_data(&payload, &mut output).unwrap();

    assert_eq!(size, 14);
    assert_eq!(
      output,
      [0x43, 0x52, 0x42, 0x4e, 0x01, 0x01, 0x00, 0x00, 0x00, 0x04, 0x45, 0x00, 0x00, 0x14,]
    );
  }

  #[test]
  fn binary_payload_round_trips_unchanged() {
    let codec = codec();
    let payload = [0x00, 0xff, 0x80, 0xc3, 0x28];
    let frame = encode(&payload);

    let decoded = codec.decode(&frame).unwrap();

    assert_eq!(decoded.message_type(), MessageType::Data);
    assert_eq!(decoded.payload(), payload);
  }

  #[test]
  fn payload_equal_to_mtu_round_trips() {
    let codec = codec();
    let payload = vec![0xab; 1400];
    let frame = encode(&payload);

    assert_eq!(frame.len(), 1410);
    assert_eq!(codec.decode(&frame).unwrap().payload(), payload);
  }

  #[test]
  fn rejects_empty_and_oversized_payloads() {
    let codec = codec();

    assert_eq!(codec.encoded_len(0), Err(EncodeError::EmptyPayload));
    assert_eq!(
      codec.encoded_len(1401),
      Err(EncodeError::PayloadTooLarge {
        size: 1401,
        mtu: 1400,
      })
    );
  }

  #[test]
  fn too_small_output_buffer_is_not_modified() {
    let codec = codec();
    let payload = [1, 2, 3, 4];
    let mut output = [0xaa; 13];
    let before = output;

    assert_eq!(
      codec.encode_data(&payload, &mut output),
      Err(EncodeError::OutputBufferTooSmall {
        required: 14,
        available: 13,
      })
    );
    assert_eq!(output, before);
  }

  #[test]
  fn rejects_each_unsupported_header_field() {
    let codec = codec();
    let frame = encode(&[0x45]);

    let mut invalid_magic = frame.clone();
    invalid_magic[0] = 0;
    assert!(matches!(
      codec.decode(&invalid_magic),
      Err(DecodeError::InvalidMagic { .. })
    ));

    let mut invalid_version = frame.clone();
    invalid_version[4] = 2;
    assert_eq!(
      codec.decode(&invalid_version),
      Err(DecodeError::UnsupportedVersion { observed: 2 })
    );

    let mut invalid_type = frame.clone();
    invalid_type[5] = 99;
    assert_eq!(
      codec.decode(&invalid_type),
      Err(DecodeError::UnknownMessageType { observed: 99 })
    );

    let mut invalid_flags = frame;
    invalid_flags[7] = 1;
    assert_eq!(
      codec.decode(&invalid_flags),
      Err(DecodeError::UnsupportedFlags { observed: 1 })
    );
  }

  #[test]
  fn rejects_version_two_handshake_message_types() {
    let codec = codec();

    for message_type in [
      MessageType::ClientHello,
      MessageType::ServerHello,
      MessageType::ClientFinish,
      MessageType::ServerFinish,
    ] {
      let mut frame = encode(&[0x45]);
      frame[5] = message_type.wire_value();

      assert_eq!(
        codec.decode(&frame),
        Err(DecodeError::UnknownMessageType {
          observed: message_type.wire_value(),
        })
      );
    }
  }

  #[test]
  fn rejects_empty_and_mismatched_declared_lengths() {
    let codec = codec();
    let header_only = [0x43, 0x52, 0x42, 0x4e, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(codec.decode(&header_only), Err(DecodeError::EmptyPayload));

    let mut declared_short = encode(&[0x45, 0x00]);
    declared_short[9] = 1;
    assert_eq!(
      codec.decode(&declared_short),
      Err(DecodeError::PayloadLengthMismatch {
        declared: 1,
        actual: 2,
      })
    );

    let mut declared_long = encode(&[0x45]);
    declared_long[9] = 2;
    assert_eq!(
      codec.decode(&declared_long),
      Err(DecodeError::PayloadLengthMismatch {
        declared: 2,
        actual: 1,
      })
    );
  }

  #[test]
  fn decoder_rejects_payload_larger_than_mtu() {
    let codec = codec();
    let mut frame = vec![0_u8; HEADER_LEN + 1401];
    frame[0..4].copy_from_slice(&MAGIC);
    frame[4] = ProtocolVersion::V1.wire_value();
    frame[5] = MessageType::Data.wire_value();
    frame[8..10].copy_from_slice(&1401_u16.to_be_bytes());

    assert_eq!(
      codec.decode(&frame),
      Err(DecodeError::PayloadTooLarge {
        size: 1401,
        mtu: 1400,
      })
    );
  }

  #[test]
  fn every_short_datagram_is_rejected_without_panicking() {
    let codec = codec();

    for size in 0..HEADER_LEN {
      let datagram = vec![0_u8; size];
      assert_eq!(
        codec.decode(&datagram),
        Err(DecodeError::DatagramTooShort {
          size,
          minimum: HEADER_LEN,
        })
      );
    }
  }
}
