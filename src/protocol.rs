//! Reserved wire-protocol extension point.

/// Placeholder for future packet framing and protocol negotiation.
pub struct Protocol {}

impl Protocol {
  /// Creates the current no-op protocol placeholder.
  pub fn new() -> Self {
    Self {}
  }
}
