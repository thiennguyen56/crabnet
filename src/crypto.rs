//! Typed cryptographic handshake boundary.
//!
//! Session policy owns lifecycle authorization and deadlines. Crypto providers
//! own credentials, transcript authentication, and provider-private contexts.

pub(crate) mod client;
pub(crate) mod fake;
pub(crate) mod server;
pub(crate) mod types;
