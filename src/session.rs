//! Reserved peer-session extension point.

/// Placeholder for future authenticated peer session state.
pub struct Session {}

impl Session {
  /// Creates the current no-op session placeholder.
  pub fn new() -> Self {
    Self {}
  }
}
