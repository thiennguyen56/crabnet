/// Local identifier for one client handshake attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ClientAttemptId(pub u64);

/// Full authenticated Noise handshake hash identifying one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SessionId(pub [u8; 32]);

impl SessionId {
  pub(crate) const fn from_u64(value: u64) -> Self {
    let bytes = value.to_be_bytes();
    let mut output = [0_u8; 32];
    output[24] = bytes[0];
    output[25] = bytes[1];
    output[26] = bytes[2];
    output[27] = bytes[3];
    output[28] = bytes[4];
    output[29] = bytes[5];
    output[30] = bytes[6];
    output[31] = bytes[7];
    Self(output)
  }
}

/// Authenticated 32-byte Noise static public key identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PeerIdentity(pub [u8; 32]);

impl PeerIdentity {
  pub(crate) const fn from_u64(value: u64) -> Self {
    let bytes = value.to_be_bytes();
    let mut output = [0_u8; 32];
    output[24] = bytes[0];
    output[25] = bytes[1];
    output[26] = bytes[2];
    output[27] = bytes[3];
    output[28] = bytes[4];
    output[29] = bytes[5];
    output[30] = bytes[6];
    output[31] = bytes[7];
    Self(output)
  }
}

/// Non-secret metadata produced only after authenticated key confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EstablishedSessionMetadata {
  /// Non-secret identifier for the established session.
  pub session_id: SessionId,
  /// Non-secret identity token from the authenticated boundary.
  pub peer_identity: PeerIdentity,
}
