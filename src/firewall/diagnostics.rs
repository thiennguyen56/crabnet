use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::Context;
use ipnet::Ipv4Net;
use serde::Deserialize;
use tokio::time::timeout;
use tun_rs::ToIpv4Address;

use crate::routing::RoutingConfig;
use crate::tun::TunConfig;

/// Expected IPv4 forwarding path used to make warnings actionable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirewallDiagnosticContext {
  /// Canonical VPN client source network.
  pub(crate) source_network: Ipv4Net,

  /// Interface on which forwarded VPN packets enter the server.
  pub(crate) input_interface: String,

  /// Known output interfaces collected from NAT and server routes.
  ///
  /// This may be empty when the kernel chooses the output interface through
  /// a gateway route that does not specify `interface`.
  pub(crate) output_interfaces: Vec<String>,
}

/// nftables base chain attached to the IPv4 forwarding path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ForwardBaseChain {
  /// nftables address family containing the chain.
  pub(crate) family: FirewallFamily,
  /// Table containing the chain.
  pub(crate) table: String,
  /// Name of the chain.
  pub(crate) chain: String,
  /// Default policy declared for the base chain.
  pub(crate) policy: BaseChainPolicy,
}

/// nftables family whose forward hook can process IPv4 traffic.
#[derive(Debug, Clone, PartialEq, Eq, Copy, PartialOrd, Ord)]
pub(crate) enum FirewallFamily {
  /// IPv4-only nftables table.
  Ip,
  /// Combined IPv4/IPv6 nftables table.
  Inet,
}

/// Default policy declared by an nftables forward base chain.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BaseChainPolicy {
  /// Explicit `policy accept`.
  Accept,
  /// No policy in JSON; nftables default base-chain policy to accept.
  ImplicitAccept,
  /// Explicit `policy drop`.
  Drop,
  /// A value not understood by this Crabnet version.
  Unknown(String),
}

/// High-level interpretation of current nftables forwarding policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FirewallAssessment {
  /// No IPv4-relevant nftables forward base chain was found.
  NoForwardHookObserved,

  /// Forward base chains exist but none has a default-drop policy.
  NoDefaultDropObserved,

  /// At least one base chain has a default-drop policy.
  DefaultDropObserved,

  /// Chain declarations were found but could not be classified safely.
  Inconclusive,
}

/// Complete read-only result of one firewall inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirewallDiagnosticReport {
  /// Conservative interpretation of the observed base-chain policies.
  pub(crate) assessment: FirewallAssessment,
  /// Relevant base chains in deterministic order.
  pub(crate) forward_chains: Vec<ForwardBaseChain>,

  /// Caveats that should be logged with the assessment.
  pub(crate) caveats: Vec<FirewallCaveat>,
}

/// Limitation that narrows what can be concluded from a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FirewallCaveat {
  /// Individual nftables rule expressions were not interpreted.
  RulesNotEvaluated,

  /// Legacy iptables firewall state was not inspected.
  LegacyIptablesNotInspected,

  /// Other packet filters such as eBPF were not inspected.
  OtherFilteringSystemsNotInspected,

  /// One or more output interfaces could not be derived.
  OutputInterfaceIncomplete,
}

#[derive(Debug, Deserialize)]
struct NftChainListing {
  nftables: Vec<NftObject>,
}

#[derive(Debug, Deserialize)]
struct NftObject {
  chain: Option<NftChain>,
}

#[derive(Debug, Deserialize)]
struct NftChain {
  family: String,
  table: String,
  name: String,

  #[serde(rename = "type")]
  chain_type: Option<String>,

  hook: Option<String>,
  policy: Option<String>,
}

/// Read-only provider of nftables chain declarations.
pub(crate) trait FirewallInspector {
  /// Returns JSON from `nft -j list chains`.
  async fn inspect_chains(&mut self) -> anyhow::Result<String>;
}

/// Runs bounded read-only firewall inspection.
pub(crate) struct FirewallDiagnostics<I> {
  inspector: I,
  timeout: Duration,
}

impl<I> FirewallDiagnostics<I>
where
  I: FirewallInspector,
{
  /// Creates diagnostics with the supplied inspector and time bound.
  ///
  /// A zero duration is permitted and produces an immediate timeout; callers
  /// should normally supply a small non-zero startup budget.
  pub(crate) fn new(inspector: I, timeout: Duration) -> Self {
    Self { inspector, timeout }
  }

  /// Inspects and classifies relevant chains without changing firewall state.
  ///
  /// Returns an error when inspection fails, exceeds the configured timeout,
  /// or returns malformed JSON. The application treats these errors as
  /// advisory and continues startup.
  pub(crate) async fn diagnose(
    &mut self,
    context: &FirewallDiagnosticContext,
  ) -> anyhow::Result<FirewallDiagnosticReport> {
    let raw_chains = match timeout(self.timeout, self.inspector.inspect_chains()).await {
      Ok(Ok(chain)) => chain,
      Ok(Err(error)) => anyhow::bail!(
        "failed to inspect firewall for TUN interface {}: {error:#}",
        context.input_interface,
      ),
      Err(_) => anyhow::bail!(
        "firewall inspection for TUN interface {} exceeded {:?}",
        context.input_interface,
        self.timeout
      ),
    };
    let chains = parse_forward_base_chains(&raw_chains)?;

    let assessment = assess_forward_chains(&chains);
    let mut caveats = vec![
      FirewallCaveat::RulesNotEvaluated,
      FirewallCaveat::LegacyIptablesNotInspected,
      FirewallCaveat::OtherFilteringSystemsNotInspected,
    ];

    if context.output_interfaces.is_empty() {
      caveats.push(FirewallCaveat::OutputInterfaceIncomplete);
    }

    Ok(FirewallDiagnosticReport {
      assessment,
      forward_chains: chains,
      caveats,
    })
  }
}

/// Builds the expected IPv4 forwarding path from validated server settings.
///
/// Returns `None` when forwarding is disabled. Output interfaces are
/// deduplicated and sorted; the set may remain empty when routes rely on
/// kernel-selected interfaces.
pub(crate) fn build_diagnostic_context(
  tun: &TunConfig,
  routing: &RoutingConfig,
) -> anyhow::Result<Option<FirewallDiagnosticContext>> {
  if !routing.enable_forwarding {
    return Ok(None);
  }

  if !tun.address.is_ipv4() {
    anyhow::bail!("firewall diagnostics currently support only IPv4 forwarding");
  }

  let canonical_network = Ipv4Net::new(tun.address.ipv4()?, tun.prefix_len)
    .context("invalid tun address")?
    .trunc();

  let mut output_interfaces = BTreeSet::new();
  if let Some(interface) = &routing.nat_egress_interface {
    output_interfaces.insert(interface.clone());
  }

  for route in &routing.server_routes {
    if let Some(interface) = &route.interface {
      output_interfaces.insert(interface.clone());
    }
  }

  Ok(Some(FirewallDiagnosticContext {
    source_network: canonical_network,
    input_interface: tun.name.clone(),
    output_interfaces: output_interfaces.into_iter().collect(),
  }))
}

fn parse_forward_base_chains(json: &str) -> anyhow::Result<Vec<ForwardBaseChain>> {
  let chains: NftChainListing =
    serde_json::from_str(json).context("failed to parse JSON returned from nft -j list chains")?;

  let mut result = Vec::new();
  for chain in chains.nftables {
    let Some(chain) = chain.chain else {
      continue;
    };
    if !is_ipv4_forward_base_chain(&chain) {
      continue;
    }
    let family = match chain.family.as_str() {
      "inet" => FirewallFamily::Inet,
      "ip" => FirewallFamily::Ip,
      _ => continue,
    };
    let policy = classify_policy(chain.policy.as_deref());
    result.push(ForwardBaseChain {
      family,
      table: chain.table.clone(),
      chain: chain.name.clone(),
      policy,
    });
  }
  result.sort();
  Ok(result)
}

fn is_ipv4_forward_base_chain(chain: &NftChain) -> bool {
  matches!(chain.family.as_str(), "ip" | "inet")
    && chain.hook.as_deref() == Some("forward")
    && chain.chain_type.as_deref() == Some("filter")
}

fn classify_policy(policy: Option<&str>) -> BaseChainPolicy {
  match policy {
    Some(policy_value) => {
      let lowercase_policy = policy_value.to_lowercase();
      match lowercase_policy.as_str() {
        "accept" => BaseChainPolicy::Accept,
        "drop" => BaseChainPolicy::Drop,
        _ => BaseChainPolicy::Unknown(lowercase_policy),
      }
    }
    None => BaseChainPolicy::ImplicitAccept,
  }
}

fn assess_forward_chains(chains: &[ForwardBaseChain]) -> FirewallAssessment {
  if chains.is_empty() {
    return FirewallAssessment::NoForwardHookObserved;
  }
  if chains
    .iter()
    .any(|chain| matches!(chain.policy, BaseChainPolicy::Unknown(_)))
  {
    return FirewallAssessment::Inconclusive;
  }
  if chains
    .iter()
    .any(|chain| chain.policy == BaseChainPolicy::Drop)
  {
    return FirewallAssessment::DefaultDropObserved;
  }

  FirewallAssessment::NoDefaultDropObserved
}

/// Logs an assessment, its observed path, and all diagnostic limitations.
pub(crate) fn log_firewall_report(
  context: &FirewallDiagnosticContext,
  report: &FirewallDiagnosticReport,
) {
  match report.assessment {
    FirewallAssessment::NoForwardHookObserved => {
      log::info!("no nftables IPv4 forward base chain was observed");
    }
    FirewallAssessment::NoDefaultDropObserved => {
      log::info!("no nftables forward base chain with default-drop policy was observed");
    }
    FirewallAssessment::DefaultDropObserved => {
      log::warn!(
        "one or more nftables forward base chains use policy drop; \
         Crabnet traffic may require administrator-managed allow rules"
      );

      for chain in &report.forward_chains {
        log::debug!(
          "observed forward base chain: family={:?}, table={}, chain={}, policy={:?}",
          chain.family,
          chain.table,
          chain.chain,
          chain.policy
        );
      }
      log::warn!(
        "expected forwarding path: source={}, input_interface={}, output_interfaces={:?}",
        context.source_network,
        context.input_interface,
        context.output_interfaces
      );
    }
    FirewallAssessment::Inconclusive => {
      log::warn!(
        "nftables forward chains were found but their policies could not be classified safely"
      );

      for chain in &report.forward_chains {
        log::debug!(
          "observed forward base chain: family={:?}, table={}, chain={}, policy={:?}",
          chain.family,
          chain.table,
          chain.chain,
          chain.policy
        );
      }
    }
  }

  for caveat in &report.caveats {
    match caveat {
      FirewallCaveat::RulesNotEvaluated => {
        log::debug!(
          "firewall diagnostics inspect base-chain policies only; \
           individual nftables rules were not evaluated"
        );
      }
      FirewallCaveat::LegacyIptablesNotInspected => {
        log::debug!("legacy iptables rules were not inspected");
      }
      FirewallCaveat::OtherFilteringSystemsNotInspected => {
        log::debug!("eBPF and other packet-filtering systems were not inspected");
      }
      FirewallCaveat::OutputInterfaceIncomplete => {
        log::warn!(
          "the complete forwarded output-interface set could not be derived; \
           inspect the server routing table manually"
        );
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use std::future;
  use std::net::IpAddr;

  use super::*;

  struct FakeFirewallInspector {
    result: Option<anyhow::Result<String>>,
  }

  impl FirewallInspector for FakeFirewallInspector {
    async fn inspect_chains(&mut self) -> anyhow::Result<String> {
      self
        .result
        .take()
        .unwrap_or_else(|| Err(anyhow::anyhow!("fake inspector called more than once")))
    }
  }

  struct PendingFirewallInspector;

  impl FirewallInspector for PendingFirewallInspector {
    async fn inspect_chains(&mut self) -> anyhow::Result<String> {
      future::pending().await
    }
  }

  fn tun(address: &str, prefix_len: u8) -> TunConfig {
    TunConfig {
      name: "crabnet0".to_owned(),
      address: address.parse::<IpAddr>().unwrap(),
      prefix_len,
      mtu: 1400,
    }
  }

  fn context() -> FirewallDiagnosticContext {
    FirewallDiagnosticContext {
      source_network: "10.0.0.0/24".parse().unwrap(),
      input_interface: "crabnet0".to_owned(),
      output_interfaces: vec!["eth0".to_owned()],
    }
  }

  fn chain(family: FirewallFamily, policy: BaseChainPolicy) -> ForwardBaseChain {
    ForwardBaseChain {
      family,
      table: "filter".to_owned(),
      chain: "forward".to_owned(),
      policy,
    }
  }

  #[test]
  fn context_is_disabled_when_forwarding_is_disabled() {
    let result = build_diagnostic_context(&tun("10.0.0.1", 24), &RoutingConfig::default()).unwrap();

    assert_eq!(result, None);
  }

  #[test]
  fn context_canonicalizes_network_and_deduplicates_interfaces() {
    let routing: RoutingConfig = toml::from_str(
      r#"
        enable_forwarding = true
        enable_nat = true
        nat_egress_interface = "eth0"

        [[server_routes]]
        destination = "172.16.0.0/24"
        interface = "eth0"

        [[server_routes]]
        destination = "192.168.0.0/24"
        interface = "eth1"
      "#,
    )
    .unwrap();

    let result = build_diagnostic_context(&tun("10.0.0.9", 24), &routing)
      .unwrap()
      .unwrap();

    assert_eq!(result.source_network, "10.0.0.0/24".parse().unwrap());
    assert_eq!(result.input_interface, "crabnet0");
    assert_eq!(result.output_interfaces, ["eth0", "eth1"]);
  }

  #[test]
  fn context_rejects_ipv6_forwarding() {
    let routing = RoutingConfig {
      enable_forwarding: true,
      ..RoutingConfig::default()
    };

    let error = build_diagnostic_context(&tun("fd00::1", 64), &routing).unwrap_err();

    assert!(error.to_string().contains("only IPv4 forwarding"));
  }

  #[test]
  fn parser_keeps_only_ipv4_relevant_forward_filter_base_chains() {
    let parsed = parse_forward_base_chains(
      r#"{
        "nftables": [
          {"metainfo": {"version": "1.0.9"}},
          {"chain": {"family": "ip", "table": "z", "name": "forward",
                     "type": "filter", "hook": "forward", "policy": "accept"}},
          {"chain": {"family": "inet", "table": "a", "name": "forward",
                     "type": "filter", "hook": "forward", "policy": "drop"}},
          {"chain": {"family": "ip", "table": "filter", "name": "regular"}},
          {"chain": {"family": "ip", "table": "filter", "name": "input",
                     "type": "filter", "hook": "input", "policy": "drop"}},
          {"chain": {"family": "ip", "table": "nat", "name": "forward",
                     "type": "nat", "hook": "forward"}},
          {"chain": {"family": "ip6", "table": "filter", "name": "forward",
                     "type": "filter", "hook": "forward", "policy": "drop"}}
        ]
      }"#,
    )
    .unwrap();

    assert_eq!(
      parsed,
      vec![
        ForwardBaseChain {
          family: FirewallFamily::Ip,
          table: "z".to_owned(),
          chain: "forward".to_owned(),
          policy: BaseChainPolicy::Accept,
        },
        ForwardBaseChain {
          family: FirewallFamily::Inet,
          table: "a".to_owned(),
          chain: "forward".to_owned(),
          policy: BaseChainPolicy::Drop,
        },
      ]
    );
  }

  #[test]
  fn parser_rejects_malformed_json_with_command_context() {
    let error = parse_forward_base_chains("not JSON").unwrap_err();

    assert!(format!("{error:#}").contains("nft -j list chains"));
  }

  #[test]
  fn assessment_handles_empty_accept_drop_and_unknown_policies() {
    assert_eq!(
      assess_forward_chains(&[]),
      FirewallAssessment::NoForwardHookObserved
    );
    assert_eq!(
      assess_forward_chains(&[
        chain(FirewallFamily::Ip, BaseChainPolicy::Accept),
        chain(FirewallFamily::Inet, BaseChainPolicy::ImplicitAccept),
      ]),
      FirewallAssessment::NoDefaultDropObserved
    );
    assert_eq!(
      assess_forward_chains(&[chain(FirewallFamily::Ip, BaseChainPolicy::Drop)]),
      FirewallAssessment::DefaultDropObserved
    );
    assert_eq!(
      assess_forward_chains(&[
        chain(FirewallFamily::Ip, BaseChainPolicy::Drop),
        chain(
          FirewallFamily::Inet,
          BaseChainPolicy::Unknown("reject".to_owned()),
        ),
      ]),
      FirewallAssessment::Inconclusive
    );
  }

  #[tokio::test]
  async fn diagnose_reports_caveats_for_an_incomplete_path() {
    let inspector = FakeFirewallInspector {
      result: Some(Ok(r#"{"nftables": []}"#.to_owned())),
    };
    let mut diagnostics = FirewallDiagnostics::new(inspector, Duration::from_secs(1));
    let context = FirewallDiagnosticContext {
      output_interfaces: Vec::new(),
      ..context()
    };

    let report = diagnostics.diagnose(&context).await.unwrap();

    assert_eq!(report.assessment, FirewallAssessment::NoForwardHookObserved);
    assert!(report
      .caveats
      .contains(&FirewallCaveat::OutputInterfaceIncomplete));
  }

  #[tokio::test]
  async fn diagnose_preserves_inspector_failure_context() {
    let inspector = FakeFirewallInspector {
      result: Some(Err(anyhow::anyhow!("permission denied"))),
    };
    let mut diagnostics = FirewallDiagnostics::new(inspector, Duration::from_secs(1));

    let error = diagnostics.diagnose(&context()).await.unwrap_err();
    let message = format!("{error:#}");

    assert!(message.contains("crabnet0"));
    assert!(message.contains("permission denied"));
  }

  #[tokio::test]
  async fn diagnose_times_out_pending_inspection() {
    let mut diagnostics =
      FirewallDiagnostics::new(PendingFirewallInspector, Duration::from_millis(1));

    let error = diagnostics.diagnose(&context()).await.unwrap_err();

    assert!(error.to_string().contains("exceeded"));
  }
}
