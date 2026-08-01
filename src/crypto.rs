//! Reserved cryptography extension point.

/// Placeholder for a future authenticated-encryption implementation.
pub struct Crypto {}

impl Crypto {
  /// Creates the current no-op cryptography placeholder.
  pub fn new() -> Self {
    Self {}
  }
}
