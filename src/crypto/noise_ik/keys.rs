use anyhow::Context;
use std::fmt;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
const KEY_LENGTH: usize = 32;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyMaterialError {
  InvalidLength { observed: usize },
  InvalidHex { index: usize },
}
impl fmt::Display for KeyMaterialError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidLength { observed } => {
        write!(formatter, "key must contain 32 bytes, observed {observed}")
      }
      Self::InvalidHex { index } => write!(
        formatter,
        "key contains invalid lowercase hex at byte {index}"
      ),
    }
  }
}
impl std::error::Error for KeyMaterialError {}
pub(crate) struct StaticPrivateKey(Box<[u8; KEY_LENGTH]>);
impl StaticPrivateKey {
  pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, KeyMaterialError> {
    let array = bytes
      .try_into()
      .map_err(|_| KeyMaterialError::InvalidLength {
        observed: bytes.len(),
      })?;
    Ok(Self(Box::new(array)))
  }
  pub(crate) fn from_hex(value: &str) -> Result<Self, KeyMaterialError> {
    Self::from_bytes(&decode_hex(value)?)
  }
  pub(crate) fn load(path: &Path) -> anyhow::Result<Self> {
    #[cfg(unix)]
    {
      let mode = fs::metadata(path)
        .with_context(|| {
          format!(
            "inspect Noise-IK private key permissions for {}",
            path.display()
          )
        })?
        .permissions()
        .mode();
      anyhow::ensure!(
        mode & 0o077 == 0,
        "Noise-IK private key {} is accessible by group or other users",
        path.display()
      );
    }
    let value = fs::read_to_string(path)
      .with_context(|| format!("read Noise-IK private key from {}", path.display()))?;
    Self::from_hex(value.trim()).map_err(|error| {
      anyhow::anyhow!(
        "invalid Noise-IK private key in {}: {error}",
        path.display()
      )
    })
  }
  pub(crate) fn as_bytes(&self) -> &[u8] {
    self.0.as_slice()
  }
}
impl Drop for StaticPrivateKey {
  fn drop(&mut self) {
    self.0.fill(0);
  }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct StaticPublicKey([u8; KEY_LENGTH]);
impl StaticPublicKey {
  pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, KeyMaterialError> {
    let array = bytes
      .try_into()
      .map_err(|_| KeyMaterialError::InvalidLength {
        observed: bytes.len(),
      })?;
    Ok(Self(array))
  }
  pub(crate) fn from_hex(value: &str) -> Result<Self, KeyMaterialError> {
    Self::from_bytes(&decode_hex(value)?)
  }
  pub(crate) fn as_bytes(&self) -> &[u8] {
    &self.0
  }
}
impl fmt::Debug for StaticPublicKey {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("StaticPublicKey(REDACTED)")
  }
}
fn decode_hex(value: &str) -> Result<Box<[u8]>, KeyMaterialError> {
  if value.len() != KEY_LENGTH * 2 {
    return Err(KeyMaterialError::InvalidLength {
      observed: value.len() / 2,
    });
  }
  let mut output = vec![0_u8; KEY_LENGTH];
  let bytes = value.as_bytes();
  for index in 0..KEY_LENGTH {
    let high = nibble(bytes[index * 2]).ok_or(KeyMaterialError::InvalidHex { index: index * 2 })?;
    let low = nibble(bytes[index * 2 + 1]).ok_or(KeyMaterialError::InvalidHex {
      index: index * 2 + 1,
    })?;
    output[index] = (high << 4) | low;
  }
  Ok(output.into_boxed_slice())
}
fn nibble(byte: u8) -> Option<u8> {
  match byte {
    b'0'..=b'9' => Some(byte - b'0'),
    b'a'..=b'f' => Some(byte - b'a' + 10),
    _ => None,
  }
}
#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn accepts_exact_lowercase_key() {
    assert_eq!(
      StaticPublicKey::from_hex(&"00".repeat(32))
        .unwrap()
        .as_bytes(),
      &[0; 32]
    );
  }
  #[test]
  fn rejects_uppercase_and_wrong_lengths() {
    assert!(StaticPublicKey::from_hex(&"AA".repeat(32)).is_err());
    assert!(StaticPublicKey::from_hex("00").is_err());
  }
}
