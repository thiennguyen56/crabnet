use crate::protocol::types::{MessageType, ProtocolVersion};
use crate::session::types::SessionId;

// Design
// Offset  Size  Field
// 0       4     Magic `CRBN`
// 4       1     Version `2`
// 5       1     Message type `Data`
// 6       2     Flags `0`
// 8       2     Body length = 32 + 1 + 8 + ciphertext length
// 10      32    Session ID
// 42      1     Direction (`0` client-to-server, `1` server-to-client)
// 43      8     Sequence number, big-endian
// 51      N     Ciphertext plus authentication tag

pub(crate) const DATA_HEADER_LENGTH: usize = 51;
const DATA_BODY_FIXED_LENGTH: usize = 41;
const MAX_SEQUENCE: u64 = u64::MAX - 1;
const UDP_PAYLOAD_CEILING: usize = 65_507;

const DATA_AEAD_TAG_LENGTH: usize = crate::crypto::noise_ik::profile::AEAD_TAG_LENGTH;
const DATA_TRANSPORT_OVERHEAD: usize = DATA_AEAD_TAG_LENGTH;
const MINIMUM_DATA_CIPHERTEXT_LENGTH: usize = DATA_TRANSPORT_OVERHEAD + 1;

const MAGIC: [u8; 4] = *b"CRBN";
const MAGIC_RANGE: std::ops::Range<usize> = 0..4;
const VERSION_OFFSET: usize = 4;
const MESSAGE_TYPE_OFFSET: usize = 5;
const FLAGS_RANGE: std::ops::Range<usize> = 6..8;
const BODY_LENGTH_RANGE: std::ops::Range<usize> = 8..10;
const SESSION_ID_RANGE: std::ops::Range<usize> = 10..42;
const DIRECTION_OFFSET: usize = 42;
const SEQUENCE_RANGE: std::ops::Range<usize> = 43..51;
const CIPHERTEXT_OFFSET: usize = DATA_HEADER_LENGTH;
const FLAGS_NONE: u16 = 0;

#[allow(
  dead_code,
  reason = "configuration failures retain context for callers"
)]
#[derive(Debug)]
pub(crate) enum DataFrameCodecConfigError {
  ZeroMaximumPlaintext,
  ZeroMaximumCiphertext,
  BodyLengthNotRepresentable {
    maximum_ciphertext: usize,
    maximum_body_length: usize,
  },
  DatagramExceedsUdpCeiling {
    maximum_datagram_length: usize,
    ceiling: usize,
  },
  DerivedLengthOverflow {
    maximum_ciphertext: usize,
  },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DataDirection {
  ClientToServer,
  ServerToClient,
}

impl DataDirection {
  const fn wire_value(self) -> u8 {
    match self {
      Self::ClientToServer => 0,
      Self::ServerToClient => 1,
    }
  }

  fn from_wire_value(observed: u8) -> Result<Self, DataFrameDecodeError> {
    match observed {
      0 => Ok(Self::ClientToServer),
      1 => Ok(Self::ServerToClient),
      _ => Err(DataFrameDecodeError::InvalidDirection { observed }),
    }
  }
}

pub(crate) struct DataFrameHeader {
  body_length: u16,
  session_id: SessionId,
  direction: DataDirection,
  sequence: u64,
}

pub(crate) struct DecodedDataFrame<'datagram> {
  header: DataFrameHeader,
  ciphertext: &'datagram [u8],
}

#[allow(dead_code, reason = "encoding failures retain context for callers")]
#[derive(Debug)]
pub(crate) enum DataFrameEncodeError {
  ZeroSessionId,
  InvalidSequence { observed: u64 },
  EmptyPlaintext,
  PlaintextTooLarge { size: usize, maximum: usize },
  CiphertextTooLarge { size: usize, maximum: usize },
  CiphertextLengthMismatch { declared: usize, actual: usize },
  BodyLengthNotRepresentable { body_length: usize },
  EncodedLengthOverflow { ciphertext_length: usize },
  OutputBufferTooSmall { required: usize, available: usize },
}

#[allow(dead_code, reason = "decoding failures retain context for callers")]
#[derive(Debug)]
pub(crate) enum DataFrameDecodeError {
  DatagramTooShort { size: usize, minimum: usize },
  DatagramTooLarge { size: usize, maximum: usize },
  InvalidMagic,
  UnsupportedVersion { observed: u8 },
  UnsupportedMessageType { observed: u8 },
  UnsupportedFlags { observed: u16 },
  BodyLengthMismatch { declared: usize, actual: usize },
  DataBodyTooShort { size: usize, minimum: usize },
  ZeroSessionId,
  InvalidDirection { observed: u8 },
  InvalidSequence { observed: u64 },
}

pub(crate) struct DataFrameCodec {
  maximum_plaintext_payload: usize,
  maximum_ciphertext: usize,
  maximum_datagram_length: usize,
}

impl DataFrameCodec {
  pub(crate) fn new(maximum_plaintext_payload: usize) -> Result<Self, DataFrameCodecConfigError> {
    if maximum_plaintext_payload == 0 {
      return Err(DataFrameCodecConfigError::ZeroMaximumPlaintext);
    }
    let Some(maximum_ciphertext) = maximum_plaintext_payload.checked_add(DATA_TRANSPORT_OVERHEAD)
    else {
      return Err(DataFrameCodecConfigError::ZeroMaximumCiphertext);
    };
    let Some(maximum_body_length) = DATA_BODY_FIXED_LENGTH.checked_add(maximum_ciphertext) else {
      return Err(DataFrameCodecConfigError::BodyLengthNotRepresentable {
        maximum_ciphertext,
        maximum_body_length: DATA_BODY_FIXED_LENGTH,
      });
    };

    if u16::try_from(maximum_body_length).is_err() {
      return Err(DataFrameCodecConfigError::BodyLengthNotRepresentable {
        maximum_ciphertext,
        maximum_body_length: DATA_BODY_FIXED_LENGTH,
      });
    };

    let Some(maximum_datagram_length) = DATA_HEADER_LENGTH.checked_add(maximum_ciphertext) else {
      return Err(DataFrameCodecConfigError::DerivedLengthOverflow { maximum_ciphertext });
    };

    if maximum_datagram_length > UDP_PAYLOAD_CEILING {
      return Err(DataFrameCodecConfigError::DatagramExceedsUdpCeiling {
        maximum_datagram_length,
        ceiling: UDP_PAYLOAD_CEILING,
      });
    }
    Ok(Self {
      maximum_plaintext_payload,
      maximum_ciphertext,
      maximum_datagram_length,
    })
  }

  pub(crate) fn build_data_header(
    &self,
    session_id: SessionId,
    direction: DataDirection,
    sequence: u64,
    plaintext_length: usize,
  ) -> Result<DataFrameHeader, DataFrameEncodeError> {
    if session_id.0.iter().all(|&b| b == 0) {
      return Err(DataFrameEncodeError::ZeroSessionId);
    }
    if sequence == 0 || sequence > MAX_SEQUENCE {
      return Err(DataFrameEncodeError::InvalidSequence { observed: sequence });
    }
    if plaintext_length == 0 {
      return Err(DataFrameEncodeError::EmptyPlaintext);
    }
    if plaintext_length > self.maximum_plaintext_payload {
      return Err(DataFrameEncodeError::PlaintextTooLarge {
        size: plaintext_length,
        maximum: self.maximum_plaintext_payload,
      });
    }

    let Some(ciphertext_length) = plaintext_length.checked_add(DATA_TRANSPORT_OVERHEAD) else {
      return Err(DataFrameEncodeError::EncodedLengthOverflow {
        ciphertext_length: plaintext_length,
      });
    };
    let Some(body_length) = DATA_BODY_FIXED_LENGTH.checked_add(ciphertext_length) else {
      return Err(DataFrameEncodeError::EncodedLengthOverflow { ciphertext_length });
    };

    let Ok(body_length) = u16::try_from(body_length) else {
      return Err(DataFrameEncodeError::BodyLengthNotRepresentable { body_length });
    };

    Ok(DataFrameHeader {
      body_length,
      session_id,
      direction,
      sequence,
    })
  }
  pub(crate) fn encode_data(
    &self,
    header: DataFrameHeader,
    ciphertext: &[u8],
    output: &mut [u8],
  ) -> Result<usize, DataFrameEncodeError> {
    if ciphertext.len() < MINIMUM_DATA_CIPHERTEXT_LENGTH {
      return Err(DataFrameEncodeError::CiphertextLengthMismatch {
        declared: MINIMUM_DATA_CIPHERTEXT_LENGTH,
        actual: ciphertext.len(),
      });
    }
    if ciphertext.len() > self.maximum_ciphertext {
      return Err(DataFrameEncodeError::CiphertextTooLarge {
        size: ciphertext.len(),
        maximum: self.maximum_ciphertext,
      });
    }

    let declared_ciphertext_length = usize::from(header.body_length) - DATA_BODY_FIXED_LENGTH;
    if ciphertext.len() != declared_ciphertext_length {
      return Err(DataFrameEncodeError::CiphertextLengthMismatch {
        declared: declared_ciphertext_length,
        actual: ciphertext.len(),
      });
    }

    let Some(encoded_length) = ciphertext.len().checked_add(DATA_HEADER_LENGTH) else {
      return Err(DataFrameEncodeError::EncodedLengthOverflow {
        ciphertext_length: ciphertext.len(),
      });
    };
    if encoded_length > output.len() {
      return Err(DataFrameEncodeError::OutputBufferTooSmall {
        required: encoded_length,
        available: output.len(),
      });
    }
    let header_bytes = header_binding_bytes(&header);
    output[..DATA_HEADER_LENGTH].copy_from_slice(&header_bytes);
    output[CIPHERTEXT_OFFSET..encoded_length].copy_from_slice(ciphertext);

    Ok(encoded_length)
  }

  pub(crate) fn maximum_plaintext_payload(&self) -> usize {
    self.maximum_plaintext_payload
  }

  pub(crate) fn maximum_datagram_length(&self) -> usize {
    self.maximum_datagram_length
  }

  pub(crate) fn decode_data<'a>(
    &self,
    datagram: &'a [u8],
  ) -> Result<DecodedDataFrame<'a>, DataFrameDecodeError> {
    if datagram.len() < BODY_LENGTH_RANGE.end {
      return Err(DataFrameDecodeError::DatagramTooShort {
        size: datagram.len(),
        minimum: BODY_LENGTH_RANGE.end,
      });
    }
    if datagram.len() > self.maximum_datagram_length {
      return Err(DataFrameDecodeError::DatagramTooLarge {
        size: datagram.len(),
        maximum: self.maximum_datagram_length,
      });
    }
    if datagram[MAGIC_RANGE] != MAGIC {
      return Err(DataFrameDecodeError::InvalidMagic);
    }
    if datagram[VERSION_OFFSET] != ProtocolVersion::V2.wire_value() {
      return Err(DataFrameDecodeError::UnsupportedVersion {
        observed: datagram[VERSION_OFFSET],
      });
    }
    if datagram[MESSAGE_TYPE_OFFSET] != MessageType::Data.wire_value() {
      return Err(DataFrameDecodeError::UnsupportedMessageType {
        observed: datagram[MESSAGE_TYPE_OFFSET],
      });
    }

    let flags = u16::from_be_bytes([datagram[FLAGS_RANGE.start], datagram[FLAGS_RANGE.start + 1]]);
    if flags != FLAGS_NONE {
      return Err(DataFrameDecodeError::UnsupportedFlags { observed: flags });
    }

    let declared_body_length = usize::from(u16::from_be_bytes([
      datagram[BODY_LENGTH_RANGE.start],
      datagram[BODY_LENGTH_RANGE.start + 1],
    ]));
    let actual_body_length = datagram.len() - BODY_LENGTH_RANGE.end;
    if declared_body_length != actual_body_length {
      return Err(DataFrameDecodeError::BodyLengthMismatch {
        declared: declared_body_length,
        actual: actual_body_length,
      });
    }

    let minimum_body_length = DATA_BODY_FIXED_LENGTH + MINIMUM_DATA_CIPHERTEXT_LENGTH;
    if actual_body_length < minimum_body_length {
      return Err(DataFrameDecodeError::DataBodyTooShort {
        size: actual_body_length,
        minimum: minimum_body_length,
      });
    }

    let mut session_id = [0_u8; SESSION_ID_RANGE.end - SESSION_ID_RANGE.start];
    session_id.copy_from_slice(&datagram[SESSION_ID_RANGE]);
    if session_id.iter().all(|&byte| byte == 0) {
      return Err(DataFrameDecodeError::ZeroSessionId);
    }

    let direction = DataDirection::from_wire_value(datagram[DIRECTION_OFFSET])?;
    let mut sequence_bytes = [0_u8; SEQUENCE_RANGE.end - SEQUENCE_RANGE.start];
    sequence_bytes.copy_from_slice(&datagram[SEQUENCE_RANGE]);
    let sequence = u64::from_be_bytes(sequence_bytes);
    if sequence == 0 || sequence > MAX_SEQUENCE {
      return Err(DataFrameDecodeError::InvalidSequence { observed: sequence });
    }

    let ciphertext = &datagram[CIPHERTEXT_OFFSET..];

    Ok(DecodedDataFrame {
      header: DataFrameHeader {
        body_length: declared_body_length as u16,
        session_id: SessionId(session_id),
        direction,
        sequence,
      },
      ciphertext,
    })
  }
}

impl<'datagram> DecodedDataFrame<'datagram> {
  pub(crate) fn header(&self) -> &DataFrameHeader {
    &self.header
  }

  pub(crate) fn ciphertext(&self) -> &'datagram [u8] {
    self.ciphertext
  }
}

impl DataFrameHeader {
  pub(crate) fn session_id(&self) -> SessionId {
    self.session_id
  }
  pub(crate) fn direction(&self) -> DataDirection {
    self.direction
  }
  pub(crate) fn sequence(&self) -> u64 {
    self.sequence
  }
}

/// Returns the outer header bytes encrypted alongside every inner packet.
pub(crate) fn header_binding_bytes(header: &DataFrameHeader) -> [u8; DATA_HEADER_LENGTH] {
  let mut output = [0_u8; DATA_HEADER_LENGTH];

  output[MAGIC_RANGE].copy_from_slice(&MAGIC);
  output[VERSION_OFFSET] = ProtocolVersion::V2.wire_value();
  output[MESSAGE_TYPE_OFFSET] = MessageType::Data.wire_value();
  output[FLAGS_RANGE].copy_from_slice(&FLAGS_NONE.to_be_bytes());
  output[BODY_LENGTH_RANGE].copy_from_slice(&header.body_length.to_be_bytes());
  output[SESSION_ID_RANGE].copy_from_slice(&header.session_id.0);
  output[DIRECTION_OFFSET] = header.direction.wire_value();
  output[SEQUENCE_RANGE].copy_from_slice(&header.sequence.to_be_bytes());

  output
}

#[cfg(test)]
mod tests {
  use super::*;

  const MAXIMUM_PLAINTEXT: usize = 1_400;

  fn codec() -> DataFrameCodec {
    match DataFrameCodec::new(MAXIMUM_PLAINTEXT) {
      Ok(codec) => codec,
      Err(_) => panic!("test codec configuration must be valid"),
    }
  }

  fn header(codec: &DataFrameCodec) -> DataFrameHeader {
    match codec.build_data_header(SessionId::from_u64(7), DataDirection::ClientToServer, 1, 1) {
      Ok(header) => header,
      Err(_) => panic!("test data header must be valid"),
    }
  }

  fn encoded_frame(codec: &DataFrameCodec) -> Vec<u8> {
    let ciphertext = vec![0xA5; MINIMUM_DATA_CIPHERTEXT_LENGTH];
    let mut output = vec![0_u8; DATA_HEADER_LENGTH + ciphertext.len()];
    let encoded_length = match codec.encode_data(header(codec), &ciphertext, &mut output) {
      Ok(encoded_length) => encoded_length,
      Err(_) => panic!("test frame encoding must succeed"),
    };
    output.truncate(encoded_length);
    output
  }

  #[test]
  fn decode_data_accepts_a_frame_encoded_by_the_codec() {
    let codec = codec();
    let frame = encoded_frame(&codec);

    let decoded = match codec.decode_data(&frame) {
      Ok(decoded) => decoded,
      Err(_) => panic!("encoded frame must decode"),
    };

    assert_eq!(decoded.header.body_length, 58);
    assert_eq!(decoded.header.session_id, SessionId::from_u64(7));
    assert_eq!(decoded.header.direction, DataDirection::ClientToServer);
    assert_eq!(decoded.header.sequence, 1);
    assert_eq!(
      decoded.ciphertext,
      vec![0xA5; MINIMUM_DATA_CIPHERTEXT_LENGTH]
    );
  }

  #[test]
  fn decode_data_rejects_an_invalid_direction_before_session_lookup() {
    let codec = codec();
    let mut frame = encoded_frame(&codec);
    frame[DIRECTION_OFFSET] = 2;

    assert!(matches!(
      codec.decode_data(&frame),
      Err(DataFrameDecodeError::InvalidDirection { observed: 2 })
    ));
  }

  #[test]
  fn header_binding_bytes_match_the_outer_frame_header() {
    let codec = codec();
    let frame = encoded_frame(&codec);
    let decoded = match codec.decode_data(&frame) {
      Ok(decoded) => decoded,
      Err(_) => panic!("encoded frame must decode"),
    };

    assert_eq!(
      header_binding_bytes(&decoded.header),
      frame[..DATA_HEADER_LENGTH]
    );
  }
}
