//! Platform-neutral NAT intent, ownership, and cleanup.

use std::net::IpAddr;

use anyhow::{bail, ensure, Context};
use ipnet::Ipv4Net;

use crate::routing::RoutingConfig;
use crate::tun::TunConfig;

// Complete server-side IPv4 masquerde intent
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NatSpec {
  /// Canonical source network derived from the TUN address and prefix.
  pub(crate) source_network: Ipv4Net,

  /// TUN interface from which forwarded client packets arrive.
  pub(crate) tun_interface: String,

  /// Server interface through which translated packets leave.
  pub(crate) egress_interface: String,
}

/// Backend-specific evidence captured after Crabnet installs NAT state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppliedNat {
  /// Normalized nftables JSON used to detect external changes.
  pub(crate) fingerprint: serde_json::Value,
}

/// Operating-system adapter for installing and restoring NAT state.
pub(crate) trait NatBackend {
  /// Installs NAT and returns evidence proving what Crabnet created.
  async fn apply(&mut self, spec: &NatSpec) -> anyhow::Result<AppliedNat>;
  /// Removes previously applied NAT state if it is still unchanged.
  async fn revert(&mut self, applied: &AppliedNat) -> anyhow::Result<()>;
}

/// Owns one Nat installation and restores it during shutdown
pub(crate) struct NatManager<B> {
  backend: B,
  applied: Option<AppliedNat>,
}

impl<B> NatManager<B>
where
  B: NatBackend,
{
  /// Creates an empty NAT manager.
  pub(crate) fn new(backend: B) -> Self {
    Self {
      backend,
      applied: None,
    }
  }

  /// Installs one NAT specification
  ///
  /// A second installation is rejected while this manager still owns state
  pub(crate) async fn install(&mut self, spec: &NatSpec) -> anyhow::Result<()> {
    ensure!(self.applied.is_none(), "NAT states is already installed");

    let applied = self.backend.apply(spec).await?;
    self.applied = Some(applied);
    Ok(())
  }

  /// Restores owned NAT state
  ///
  /// Failed cleanup remains recorded so a later call can retry it
  pub(crate) async fn restore(&mut self) -> anyhow::Result<()> {
    let Some(applied) = self.applied.take() else {
      return Ok(());
    };

    if let Err(error) = self.backend.revert(&applied).await {
      self.applied = Some(applied);
      return Err(error.context("failed to restore NAT state"));
    }

    Ok(())
  }
}

/// Builds optional NAT intent from validated application configuration
pub(crate) fn build_nat_spec(
  tun: &TunConfig,
  routing: &RoutingConfig,
) -> anyhow::Result<Option<NatSpec>> {
  if !routing.enable_nat {
    return Ok(None);
  }

  let IpAddr::V4(address) = tun.address else {
    bail!("routing.enable_nat currently supports only IPv4 TUN addresses");
  };

  let egress_interface = routing
    .nat_egress_interface
    .clone()
    .context("routing.enable_nat requires routing.nat_egress_interface")?;

  let source_network = Ipv4Net::new(address, tun.prefix_len)
    .context("failed to derive the IPv4 NAT source network")?
    .trunc();

  Ok(Some(NatSpec {
    source_network,
    tun_interface: tun.name.clone(),
    egress_interface,
  }))
}

/// Validates the conservative interface-name subset accepted by the nftables
/// renderer
///
/// Restricting configuration to this subset prevents interface names from
/// becoming nftables syntax.
pub(crate) fn validate_nft_interface_name(field: &str, name: &str) -> anyhow::Result<()> {
  ensure!(!name.is_empty(), "{field} must not be empty");
  ensure!(
    name.len() <= 15,
    "{field} must be at most 15 bytes for a Linux interface name"
  );
  ensure!(
    name
      .bytes()
      .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.') }),
    "{field} may contain only ASCII alphanumeric characters or '_', '-', '.'"
  );

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[derive(Default)]
  struct FakeNatBackend {
    apply_calls: Vec<NatSpec>,
    revert_calls: usize,
    fail_apply: bool,
    fail_revert: bool,
  }

  impl NatBackend for FakeNatBackend {
    async fn apply(&mut self, spec: &NatSpec) -> anyhow::Result<AppliedNat> {
      self.apply_calls.push(spec.clone());

      if self.fail_apply {
        anyhow::bail!("injected NAT apply failure");
      }

      Ok(AppliedNat {
        fingerprint: serde_json::json!({"owned": true}),
      })
    }

    async fn revert(&mut self, _applied: &AppliedNat) -> anyhow::Result<()> {
      self.revert_calls += 1;
      if self.fail_revert {
        anyhow::bail!("injected NAT revert failure");
      }

      Ok(())
    }
  }

  fn tun_config() -> TunConfig {
    TunConfig {
      name: "crabnet0".to_owned(),
      address: "10.0.0.1".parse().unwrap(),
      prefix_len: 24,
      mtu: 1400,
    }
  }

  fn routing_config() -> RoutingConfig {
    RoutingConfig {
      enable_forwarding: true,
      enable_nat: true,
      nat_egress_interface: Some("eth0".to_owned()),
      ..RoutingConfig::default()
    }
  }

  fn nat_spec() -> NatSpec {
    NatSpec {
      source_network: "10.0.0.0/24".parse().unwrap(),
      tun_interface: "crabnet0".to_owned(),
      egress_interface: "eth0".to_owned(),
    }
  }
  #[test]
  fn builds_canonical_nat_source_network() {
    assert_eq!(
      build_nat_spec(&tun_config(), &routing_config()).unwrap(),
      Some(nat_spec())
    );
  }

  #[test]
  fn disabled_nat_produces_no_specification() {
    let routing = RoutingConfig::default();

    assert_eq!(build_nat_spec(&tun_config(), &routing).unwrap(), None);
  }

  #[test]
  fn interface_validation_accepts_normal_linux_names() {
    for name in ["eth0", "ens18", "cn-srv-back", "bond0.10"] {
      validate_nft_interface_name("interface", name).unwrap();
    }
  }

  #[test]
  fn interface_validation_rejects_nft_syntax() {
    for name in ["", "eth0; add rule", "eth0\"", "interface-name-is-too-long"] {
      assert!(validate_nft_interface_name("interface", name).is_err());
    }
  }

  #[tokio::test]
  async fn manager_installs_and_restores_owned_state() {
    let mut manager = NatManager::new(FakeNatBackend::default());

    manager.install(&nat_spec()).await.unwrap();
    manager.restore().await.unwrap();

    assert_eq!(manager.backend.apply_calls, vec![nat_spec()]);
    assert_eq!(manager.backend.revert_calls, 1);
    assert!(manager.applied.is_none());
  }

  #[tokio::test]
  async fn failed_install_does_not_claim_ownership() {
    let backend = FakeNatBackend {
      fail_apply: true,
      ..FakeNatBackend::default()
    };
    let mut manager = NatManager::new(backend);

    manager.install(&nat_spec()).await.unwrap_err();

    assert!(manager.applied.is_none());
  }

  #[tokio::test]
  async fn failed_cleanup_is_retained_for_retry() {
    let backend = FakeNatBackend {
      fail_revert: true,
      ..FakeNatBackend::default()
    };
    let mut manager = NatManager::new(backend);

    manager.install(&nat_spec()).await.unwrap();
    manager.restore().await.unwrap_err();

    assert!(manager.applied.is_some());

    manager.backend.fail_revert = false;
    manager.restore().await.unwrap();

    assert!(manager.applied.is_none());
    assert_eq!(manager.backend.revert_calls, 2);
  }

  #[tokio::test]
  async fn second_install_is_rejected_while_state_is_owned() {
    let mut manager = NatManager::new(FakeNatBackend::default());

    manager.install(&nat_spec()).await.unwrap();

    let error = manager.install(&nat_spec()).await.unwrap_err();
    assert!(error.to_string().contains("already installed"));
  }
}
