use crate::{
  protocol::types::{MessageType, ProtocolVersion},
  session::types::ClientAttemptId,
};

pub(crate) const NOISE_PROTOCOL_NAME: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub(crate) const CRABNET_NOISE_PROFILE: u8 = 1;
pub(crate) const CONTROL_MAGIC: &[u8; 4] = b"CNIK";
pub(crate) const CONTROL_RECORD_LENGTH: usize = 16;
pub(crate) const AEAD_TAG_LENGTH: usize = 16;
pub(crate) const X25519_PUBLIC_KEY_LENGTH: usize = 32;
pub(crate) const CLIENT_HELLO_PAYLOAD_LENGTH: usize = 112;
pub(crate) const SERVER_HELLO_PAYLOAD_LENGTH: usize = 64;
pub(crate) const CLIENT_FINISH_PAYLOAD_LENGTH: usize = 32;
pub(crate) const SERVER_FINISH_PAYLOAD_LENGTH: usize = 32;
pub(crate) const PROLOGUE_LENGTH: usize = 24;
pub(crate) const PROLOGUE_PREFIX: &[u8; 13] = b"CRBN-NOISE-IK";
const CRABNET_PROTOCOL_VERSION: u8 = ProtocolVersion::V2.wire_value();

const PROLOGUE_SEPARATOR_OFFSET: usize = PROLOGUE_PREFIX.len();
const PROLOGUE_VERSION_OFFSET: usize = PROLOGUE_SEPARATOR_OFFSET + 1;
const PROLOGUE_PROFILE_OFFSET: usize = PROLOGUE_VERSION_OFFSET + 1;
const PROLOGUE_ATTEMPT_OFFSET: usize = PROLOGUE_PROFILE_OFFSET + 1;

const CONTROL_MAGIC_RANGE: std::ops::Range<usize> = 0..4;
const CONTROL_PROFILE_OFFSET: usize = 4;
const CONTROL_KIND_OFFSET: usize = 5;
const CONTROL_RESERVED_RANGE: std::ops::Range<usize> = 6..8;
const CONTROL_ATTEMPT_RANGE: std::ops::Range<usize> = 8..16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NoiseIkProfileError {
  ZeroClientAttemptId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlEncodeError {
  UnsupportedMessageType { observed: MessageType },
  ZeroClientAttemptId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValidateControlError {
  RemoteAuthenticationFailure,
  InvalidExpectedMessageType { observed: MessageType },
  ZeroExpectedClientAttemptId,
}

pub(crate) struct Profile;

impl Profile {
  pub(crate) fn build_prologue(
    attempt_id: ClientAttemptId,
  ) -> Result<[u8; PROLOGUE_LENGTH], NoiseIkProfileError> {
    if attempt_id.0 == 0 {
      return Err(NoiseIkProfileError::ZeroClientAttemptId);
    }

    let mut prologue = [0_u8; PROLOGUE_LENGTH];

    prologue[..PROLOGUE_PREFIX.len()].copy_from_slice(PROLOGUE_PREFIX);
    prologue[PROLOGUE_SEPARATOR_OFFSET] = 0;
    prologue[PROLOGUE_VERSION_OFFSET] = CRABNET_PROTOCOL_VERSION;
    prologue[PROLOGUE_PROFILE_OFFSET] = CRABNET_NOISE_PROFILE;
    prologue[PROLOGUE_ATTEMPT_OFFSET..].copy_from_slice(&attempt_id.0.to_be_bytes());

    Ok(prologue)
  }

  pub(crate) fn encode_control(
    kind: MessageType,
    attempt_id: ClientAttemptId,
  ) -> Result<[u8; CONTROL_RECORD_LENGTH], ControlEncodeError> {
    if attempt_id.0 == 0 {
      return Err(ControlEncodeError::ZeroClientAttemptId);
    }
    match kind {
      MessageType::ClientHello
      | MessageType::ServerHello
      | MessageType::ClientFinish
      | MessageType::ServerFinish => {}
      MessageType::Data => {
        return Err(ControlEncodeError::UnsupportedMessageType { observed: kind })
      }
    }

    let mut record = [0u8; CONTROL_RECORD_LENGTH];

    record[CONTROL_MAGIC_RANGE].copy_from_slice(CONTROL_MAGIC);
    record[CONTROL_PROFILE_OFFSET] = CRABNET_NOISE_PROFILE;
    record[CONTROL_KIND_OFFSET] = kind.wire_value();
    record[CONTROL_RESERVED_RANGE].copy_from_slice(&0_u16.to_be_bytes());
    record[CONTROL_ATTEMPT_RANGE].copy_from_slice(&attempt_id.0.to_be_bytes());

    Ok(record)
  }

  pub(crate) fn validate_control(
    plaintext: &[u8],
    expected_kind: MessageType,
    expected_attempt: ClientAttemptId,
  ) -> Result<(), ValidateControlError> {
    if !is_handshake_message_type(expected_kind) {
      return Err(ValidateControlError::InvalidExpectedMessageType {
        observed: expected_kind,
      });
    }
    if expected_attempt.0 == 0 {
      return Err(ValidateControlError::ZeroExpectedClientAttemptId);
    }

    if plaintext.len() != CONTROL_RECORD_LENGTH
      || plaintext[CONTROL_MAGIC_RANGE] != CONTROL_MAGIC[..]
      || plaintext[CONTROL_PROFILE_OFFSET] != CRABNET_NOISE_PROFILE
      || plaintext[CONTROL_KIND_OFFSET] != expected_kind.wire_value()
      || plaintext[CONTROL_RESERVED_RANGE] != 0_u16.to_be_bytes()
      || plaintext[CONTROL_ATTEMPT_RANGE] != expected_attempt.0.to_be_bytes()
    {
      return Err(ValidateControlError::RemoteAuthenticationFailure);
    }

    Ok(())
  }
}

fn is_handshake_message_type(message_type: MessageType) -> bool {
  matches!(
    message_type,
    MessageType::ClientHello
      | MessageType::ServerHello
      | MessageType::ClientFinish
      | MessageType::ServerFinish
  )
}

#[cfg(test)]
mod tests {
  use super::*;

  const ATTEMPT: ClientAttemptId = ClientAttemptId(0x0102_0304_0506_0708);

  #[test]
  fn builds_exact_prologue_vector() {
    assert_eq!(
      Profile::build_prologue(ATTEMPT),
      Ok([
        b'C', b'R', b'B', b'N', b'-', b'N', b'O', b'I', b'S', b'E', b'-', b'I', b'K', 0, 2, 1, 1,
        2, 3, 4, 5, 6, 7, 8,
      ])
    );
  }

  #[test]
  fn rejects_zero_attempt_ids() {
    assert_eq!(
      Profile::build_prologue(ClientAttemptId(0)),
      Err(NoiseIkProfileError::ZeroClientAttemptId)
    );
    assert_eq!(
      Profile::encode_control(MessageType::ClientHello, ClientAttemptId(0)),
      Err(ControlEncodeError::ZeroClientAttemptId)
    );
    assert_eq!(
      Profile::validate_control(
        &Profile::encode_control(MessageType::ClientHello, ATTEMPT).unwrap(),
        MessageType::ClientHello,
        ClientAttemptId(0),
      ),
      Err(ValidateControlError::ZeroExpectedClientAttemptId)
    );
  }

  #[test]
  fn encodes_exact_control_vectors_for_all_handshake_kinds() {
    for kind in [
      MessageType::ClientHello,
      MessageType::ServerHello,
      MessageType::ClientFinish,
      MessageType::ServerFinish,
    ] {
      let mut expected = *b"CNIK\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
      expected[CONTROL_KIND_OFFSET] = kind.wire_value();
      expected[CONTROL_ATTEMPT_RANGE].copy_from_slice(&ATTEMPT.0.to_be_bytes());
      assert_eq!(Profile::encode_control(kind, ATTEMPT), Ok(expected));
    }
  }

  #[test]
  fn rejects_data_as_control_kind() {
    assert_eq!(
      Profile::encode_control(MessageType::Data, ATTEMPT),
      Err(ControlEncodeError::UnsupportedMessageType {
        observed: MessageType::Data,
      })
    );

    assert_eq!(
      Profile::validate_control(&[0; CONTROL_RECORD_LENGTH], MessageType::Data, ATTEMPT),
      Err(ValidateControlError::InvalidExpectedMessageType {
        observed: MessageType::Data,
      })
    );
  }

  #[test]
  fn validates_control_and_rejects_mutations() {
    let control = Profile::encode_control(MessageType::ClientFinish, ATTEMPT).unwrap();
    assert_eq!(
      Profile::validate_control(&control, MessageType::ClientFinish, ATTEMPT),
      Ok(())
    );

    for index in 0..CONTROL_RECORD_LENGTH {
      let mut mutated = control;
      mutated[index] ^= 1;
      assert_eq!(
        Profile::validate_control(&mutated, MessageType::ClientFinish, ATTEMPT),
        Err(ValidateControlError::RemoteAuthenticationFailure),
        "control mutation at byte {index} must be rejected"
      );
    }

    assert_eq!(
      Profile::validate_control(
        &control[..CONTROL_RECORD_LENGTH - 1],
        MessageType::ClientFinish,
        ATTEMPT,
      ),
      Err(ValidateControlError::RemoteAuthenticationFailure)
    );
  }
}
