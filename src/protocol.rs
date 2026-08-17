//! Versioned Crabnet framing for raw inner IP packets.
//!
//! This format provides framing only. It does not authenticate, encrypt, or
//! protect packets from replay.

pub(crate) mod types;
pub(crate) mod v1;
pub(crate) mod v2;
