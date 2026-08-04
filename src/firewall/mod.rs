//! Bounded, read-only diagnostics for Linux forwarding firewall policy.
//!
//! The diagnostics inspect nftables base-chain declarations before server
//! network state is installed. They never modify firewall policy and failures
//! remain advisory.

mod diagnostics;
mod linux;

pub(crate) use diagnostics::*;
pub(crate) use linux::*;
