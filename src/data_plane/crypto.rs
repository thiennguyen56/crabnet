//! Noise transport adapter for encrypted V2 data packets.

use snow::StatelessTransportState;

use crate::data_plane::frame::DATA_HEADER_LENGTH;

#[derive(Debug)]
pub(crate) enum TransportError {
  Encrypt,
}

pub(crate) enum DecryptOutcome {
  Plaintext(Vec<u8>),
  HeaderBindingFailure,
  AuthenticationFailure,
}

pub(crate) struct DirectionalTransport {
  state: StatelessTransportState,
}

impl DirectionalTransport {
  pub(crate) fn new(state: StatelessTransportState) -> Self {
    Self { state }
  }

  pub(crate) fn encrypt(
    &mut self,
    sequence: u64,
    header_bytes: &[u8; DATA_HEADER_LENGTH],
    plaintext: &[u8],
  ) -> Result<Vec<u8>, TransportError> {
    let mut payload = Vec::with_capacity(DATA_HEADER_LENGTH + plaintext.len());
    payload.extend_from_slice(header_bytes);
    payload.extend_from_slice(plaintext);
    let mut ciphertext =
      vec![0_u8; payload.len() + crate::crypto::noise_ik::profile::AEAD_TAG_LENGTH];
    let length = self
      .state
      .write_message(sequence - 1, &payload, &mut ciphertext)
      .map_err(|_| TransportError::Encrypt)?;
    ciphertext.truncate(length);
    Ok(ciphertext)
  }

  pub(crate) fn decrypt(
    &mut self,
    sequence: u64,
    header_bytes: &[u8; DATA_HEADER_LENGTH],
    ciphertext: &[u8],
  ) -> DecryptOutcome {
    let mut plaintext = vec![0_u8; ciphertext.len()];
    let length = match self
      .state
      .read_message(sequence - 1, ciphertext, &mut plaintext)
    {
      Ok(length) => length,
      Err(_) => return DecryptOutcome::AuthenticationFailure,
    };
    plaintext.truncate(length);
    if plaintext.len() < DATA_HEADER_LENGTH || plaintext[..DATA_HEADER_LENGTH] != header_bytes[..] {
      return DecryptOutcome::HeaderBindingFailure;
    }
    DecryptOutcome::Plaintext(plaintext.split_off(DATA_HEADER_LENGTH))
  }
}
