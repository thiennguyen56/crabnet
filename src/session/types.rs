/// Local identifier for one client handshake attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ClientAttemptId(pub u64);

/// Non-secret policy token identifying one authenticated session.
///
/// The integer is not a frozen wire representation. A later secure-protocol
/// milestone will replace its construction with authenticated session output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SessionId(pub u64);

/// Non-secret policy token identifying the authenticated server credential.
///
/// This token is not a socket address, PSK, or derived key. Its final
/// representation belongs to the security-configuration milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PeerIdentity(pub u64);

/// Non-secret metadata produced only after authenticated key confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EstablishedSessionMetadata {
  /// Non-secret identifier for the established session.
  pub session_id: SessionId,
  /// Non-secret identity token from the authenticated boundary.
  pub peer_identity: PeerIdentity,
}
