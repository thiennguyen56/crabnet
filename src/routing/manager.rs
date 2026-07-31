use ipnet::IpNet;
use serde::Deserialize;

// RoutingConfig
//     ↓ translates into
// RouteOperation
//     ↓ executed by
// RouteBackend
//     ↓ coordinated by
// RouteManager

// RoutingConfig describes what the user wants.
// RouteOperation describes one concrete networking change.
// RouteBackend knows how to interact with an operating system.
// RouteManager applies operations, remembers ownership, and restores them.

#[derive(Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(default)]
pub struct RoutingConfig {
  pub protected_routes: Vec<IpNet>,
  pub enable_forwarding: bool,
  pub enable_nat: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteOperation {
  AddRoute {
    destination: IpNet,
    interface: String,
  },
  SetIpv4Forwarding {
    enabled: bool,
  },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApplyOutcome {
  Applied(AppliedOperation),
  Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AppliedOperation {
  RouteAdded {
    destination: IpNet,
    interface: String,
  },
  Ipv4ForwardingChanged {
    previous: bool,
  },
}

pub(crate) trait RouteBackend {
  async fn apply(&mut self, operation: &RouteOperation) -> anyhow::Result<ApplyOutcome>;
  async fn revert(&mut self, operation: &AppliedOperation) -> anyhow::Result<()>;
}

pub(crate) struct RouteManager<B> {
  backend: B,
  applied: Vec<AppliedOperation>,
}

impl<B> RouteManager<B>
where
  B: RouteBackend,
{
  pub(crate) fn new(backend: B) -> Self {
    Self {
      backend,
      applied: Vec::new(),
    }
  }

  pub(crate) async fn install(&mut self, operations: &[RouteOperation]) -> anyhow::Result<()> {
    anyhow::ensure!(
      self.applied.is_empty(),
      "routing state is already installed"
    );

    for operation in operations {
      match self.backend.apply(operation).await {
        Ok(ApplyOutcome::Applied(applied)) => self.applied.push(applied),
        Ok(ApplyOutcome::Unchanged) => {}
        Err(install_error) => {
          let rollback_result = self.restore().await;
          return match rollback_result {
            Ok(()) => Err(install_error),
            Err(rollback_error) => Err(install_error.context(format!(
              "route installation rollback also failed: {rollback_error:#}"
            ))),
          };
        }
      }
    }

    Ok(())
  }

  pub(crate) async fn restore(&mut self) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    let mut failed = Vec::new();

    while let Some(operation) = self.applied.pop() {
      if let Err(error) = self.backend.revert(&operation).await {
        errors.push(format!("{operation:?}: {error:#}"));
        failed.push(operation);
      }
    }

    failed.reverse();
    self.applied = failed;

    if errors.is_empty() {
      Ok(())
    } else {
      anyhow::bail!("failed to restore routing state: {}", errors.join("; "))
    }
  }
}

pub(crate) fn client_operations(config: &RoutingConfig, tun_name: &str) -> Vec<RouteOperation> {
  config
    .protected_routes
    .iter()
    .cloned()
    .map(|destination| RouteOperation::AddRoute {
      destination,
      interface: tun_name.to_owned(),
    })
    .collect()
}

pub(crate) fn server_operations(config: &RoutingConfig) -> Vec<RouteOperation> {
  if config.enable_forwarding {
    vec![RouteOperation::SetIpv4Forwarding { enabled: true }]
  } else {
    Vec::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[derive(Debug, Default)]
  struct FakeRouteBackend {
    existing: Vec<AppliedOperation>,
    ipv4_forwarding: bool,
    apply_calls: Vec<RouteOperation>,
    revert_calls: Vec<AppliedOperation>,
    fail_apply_at: Option<usize>,
    fail_revert_at: Option<usize>,
  }

  impl RouteBackend for FakeRouteBackend {
    async fn apply(&mut self, operation: &RouteOperation) -> anyhow::Result<ApplyOutcome> {
      let call_index = self.apply_calls.len();
      self.apply_calls.push(operation.clone());
      if self.fail_apply_at == Some(call_index) {
        anyhow::bail!("injected apply failure at call {call_index}");
      }

      match operation {
        RouteOperation::AddRoute {
          destination,
          interface,
        } => {
          let requested = AppliedOperation::RouteAdded {
            destination: *destination,
            interface: interface.clone(),
          };
          let existing = self.existing.iter().find(|existing| match existing {
            AppliedOperation::RouteAdded {
              destination: current,
              ..
            } => current == destination,
            AppliedOperation::Ipv4ForwardingChanged { .. } => false,
          });

          match existing {
            Some(existing) if existing == &requested => Ok(ApplyOutcome::Unchanged),
            Some(existing) => anyhow::bail!(
              "route conflict: requested {requested:?}, but {existing:?} already exists"
            ),
            None => {
              self.existing.push(requested.clone());
              Ok(ApplyOutcome::Applied(requested))
            }
          }
        }
        RouteOperation::SetIpv4Forwarding { enabled } => {
          if self.ipv4_forwarding == *enabled {
            Ok(ApplyOutcome::Unchanged)
          } else {
            let previous = self.ipv4_forwarding;
            self.ipv4_forwarding = *enabled;
            Ok(ApplyOutcome::Applied(
              AppliedOperation::Ipv4ForwardingChanged { previous },
            ))
          }
        }
      }
    }

    async fn revert(&mut self, operation: &AppliedOperation) -> anyhow::Result<()> {
      let call_index = self.revert_calls.len();
      self.revert_calls.push(operation.clone());
      if self.fail_revert_at == Some(call_index) {
        anyhow::bail!("injected revert failure at call {call_index}");
      }

      match operation {
        AppliedOperation::RouteAdded { .. } => {
          let position = self
            .existing
            .iter()
            .position(|existing| existing == operation)
            .ok_or_else(|| anyhow::anyhow!("cannot revert missing operation {operation:?}"))?;
          self.existing.remove(position);
          Ok(())
        }
        AppliedOperation::Ipv4ForwardingChanged { previous } => {
          self.ipv4_forwarding = *previous;
          Ok(())
        }
      }
    }
  }

  impl<B> RouteManager<B> {
    fn backend(&self) -> &B {
      &self.backend
    }

    fn backend_mut(&mut self) -> &mut B {
      &mut self.backend
    }

    fn applied(&self) -> &[AppliedOperation] {
      &self.applied
    }
  }

  fn route(destination: &str, interface: &str) -> RouteOperation {
    RouteOperation::AddRoute {
      destination: destination.parse().unwrap(),
      interface: interface.to_owned(),
    }
  }

  fn applied_route(destination: &str, interface: &str) -> AppliedOperation {
    AppliedOperation::RouteAdded {
      destination: destination.parse().unwrap(),
      interface: interface.to_owned(),
    }
  }

  #[test]
  fn client_routes_are_translated_in_order() {
    let config = RoutingConfig {
      protected_routes: vec![
        "172.16.0.0/24".parse().unwrap(),
        "172.17.0.0/24".parse().unwrap(),
      ],
      ..RoutingConfig::default()
    };
    assert_eq!(
      client_operations(&config, "crabnet0"),
      vec![
        route("172.16.0.0/24", "crabnet0"),
        route("172.17.0.0/24", "crabnet0"),
      ]
    );
  }

  #[test]
  fn empty_client_routes_produce_no_operations() {
    assert!(client_operations(&RoutingConfig::default(), "crabnet0").is_empty());
  }

  #[tokio::test]
  async fn installs_and_restores_routes_in_reverse_order() {
    let mut manager = RouteManager::new(FakeRouteBackend::default());
    let operations = vec![
      route("172.16.0.0/24", "crabnet0"),
      route("172.17.0.0/24", "crabnet0"),
    ];
    manager.install(&operations).await.unwrap();
    assert_eq!(manager.backend().apply_calls, operations);
    manager.restore().await.unwrap();
    assert_eq!(
      manager.backend().revert_calls,
      vec![
        applied_route("172.17.0.0/24", "crabnet0"),
        applied_route("172.16.0.0/24", "crabnet0"),
      ]
    );
  }

  #[tokio::test]
  async fn identical_existing_route_is_not_owned_or_removed() {
    let existing = applied_route("172.16.0.0/24", "crabnet0");
    let backend = FakeRouteBackend {
      existing: vec![existing.clone()],
      ..FakeRouteBackend::default()
    };
    let mut manager = RouteManager::new(backend);
    manager
      .install(&[route("172.16.0.0/24", "crabnet0")])
      .await
      .unwrap();
    assert!(manager.applied().is_empty());
    manager.restore().await.unwrap();
    assert!(manager.backend().revert_calls.is_empty());
    assert_eq!(manager.backend().existing, vec![existing]);
  }

  #[tokio::test]
  async fn conflicting_existing_route_is_rejected() {
    let existing = applied_route("172.16.0.0/24", "eth0");
    let backend = FakeRouteBackend {
      existing: vec![existing.clone()],
      ..FakeRouteBackend::default()
    };
    let mut manager = RouteManager::new(backend);
    let error = manager
      .install(&[route("172.16.0.0/24", "crabnet0")])
      .await
      .unwrap_err();
    assert!(error.to_string().contains("route conflict"));
    assert_eq!(manager.backend().existing, vec![existing]);
  }

  #[tokio::test]
  async fn installation_failure_rolls_back_previous_routes() {
    let backend = FakeRouteBackend {
      fail_apply_at: Some(1),
      ..FakeRouteBackend::default()
    };
    let mut manager = RouteManager::new(backend);
    manager
      .install(&[
        route("172.16.0.0/24", "crabnet0"),
        route("172.17.0.0/24", "crabnet0"),
      ])
      .await
      .unwrap_err();
    assert!(manager.applied().is_empty());
    assert!(manager.backend().existing.is_empty());
  }

  #[tokio::test]
  async fn installation_reports_apply_and_rollback_failures() {
    let backend = FakeRouteBackend {
      fail_apply_at: Some(1),
      fail_revert_at: Some(0),
      ..FakeRouteBackend::default()
    };
    let mut manager = RouteManager::new(backend);
    let error = manager
      .install(&[
        route("172.16.0.0/24", "crabnet0"),
        route("172.17.0.0/24", "crabnet0"),
      ])
      .await
      .unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("apply failure"));
    assert!(message.contains("rollback"));
    assert!(message.contains("revert failure"));
  }

  #[tokio::test]
  async fn restore_continues_after_failure_and_can_be_retried() {
    let backend = FakeRouteBackend {
      fail_revert_at: Some(1),
      ..FakeRouteBackend::default()
    };
    let mut manager = RouteManager::new(backend);
    manager
      .install(&[
        route("172.16.0.0/24", "crabnet0"),
        route("172.17.0.0/24", "crabnet0"),
        route("172.18.0.0/24", "crabnet0"),
      ])
      .await
      .unwrap();
    manager.restore().await.unwrap_err();
    assert_eq!(
      manager.applied(),
      &[applied_route("172.17.0.0/24", "crabnet0")]
    );
    manager.backend_mut().fail_revert_at = None;
    manager.restore().await.unwrap();
    assert!(manager.applied().is_empty());
  }

  #[tokio::test]
  async fn repeated_successful_restore_is_a_no_op() {
    let mut manager = RouteManager::new(FakeRouteBackend::default());
    manager
      .install(&[route("172.16.0.0/24", "crabnet0")])
      .await
      .unwrap();
    manager.restore().await.unwrap();
    let calls = manager.backend().revert_calls.len();
    manager.restore().await.unwrap();
    assert_eq!(manager.backend().revert_calls.len(), calls);
  }

  #[tokio::test]
  async fn second_install_is_rejected_while_routes_are_owned() {
    let mut manager = RouteManager::new(FakeRouteBackend::default());
    manager
      .install(&[route("172.16.0.0/24", "crabnet0")])
      .await
      .unwrap();
    let error = manager
      .install(&[route("172.17.0.0/24", "crabnet0")])
      .await
      .unwrap_err();
    assert!(error.to_string().contains("already installed"));
  }

  #[test]
  fn server_forwarding_enabled_produces_operation() {
    let config = RoutingConfig {
      enable_forwarding: true,
      ..RoutingConfig::default()
    };

    assert_eq!(
      server_operations(&config),
      vec![RouteOperation::SetIpv4Forwarding { enabled: true },]
    );
  }

  #[test]
  fn server_forwarding_disabled_produces_no_operation() {
    let config = RoutingConfig::default();

    assert!(server_operations(&config).is_empty());
  }

  #[tokio::test]
  async fn manager_restores_forwarding_state() {
    let mut manager = RouteManager::new(FakeRouteBackend::default());
    manager
      .install(&[RouteOperation::SetIpv4Forwarding { enabled: true }])
      .await
      .unwrap();
    assert!(manager.backend().ipv4_forwarding);

    manager.restore().await.unwrap();
    assert!(!manager.backend().ipv4_forwarding);
  }
}
