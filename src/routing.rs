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

// These abstractions are exercised by rootless tests now and will be used by
// the Linux backend in the next Milestone 2 step.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteOperation {
  AddRoute {
    destination: IpNet,
    interface: String,
  },
}

#[allow(dead_code)]
impl RouteOperation {
  fn destination(&self) -> &IpNet {
    match self {
      Self::AddRoute { destination, .. } => destination,
    }
  }

  fn as_applied(&self) -> AppliedOperation {
    match self {
      Self::AddRoute {
        destination,
        interface,
      } => AppliedOperation::RouteAdded {
        destination: *destination,
        interface: interface.clone(),
      },
    }
  }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApplyOutcome {
  Applied(AppliedOperation),
  Unchanged,
}
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AppliedOperation {
  RouteAdded {
    destination: IpNet,
    interface: String,
  },
}

#[allow(dead_code)]
impl AppliedOperation {
  fn destination(&self) -> &IpNet {
    match self {
      Self::RouteAdded { destination, .. } => destination,
    }
  }
}

#[allow(dead_code)]
pub(crate) trait RouteBackend {
  async fn apply(&mut self, operation: &RouteOperation) -> anyhow::Result<ApplyOutcome>;
  async fn revert(&mut self, operation: &AppliedOperation) -> anyhow::Result<()>;
}

#[allow(dead_code)]
pub(crate) struct RouteManager<B> {
  backend: B,
  applied: Vec<AppliedOperation>,
}

#[allow(dead_code)]
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

    for opt in operations {
      match self.backend.apply(opt).await {
        Ok(ApplyOutcome::Applied(applied)) => {
          self.applied.push(applied);
        }

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
        errors.push(format!("{operation:?}:{error:#}"));
        failed.push(operation);
      }
    }

    // Operations were popped in reverse application order. Restore the
    // original application order so another restore() retries in reverse.
    failed.reverse();
    self.applied = failed;

    if errors.is_empty() {
      Ok(())
    } else {
      anyhow::bail!("failed to restore routing state: {}", errors.join(";"))
    }
  }
}

#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
  use super::*;

  impl<B> RouteManager<B> {
    #[cfg(test)]
    fn backend(&self) -> &B {
      &self.backend
    }

    #[cfg(test)]
    fn applied(&self) -> &[AppliedOperation] {
      &self.applied
    }
  }

  #[cfg(test)]
  #[derive(Debug, Default)]
  struct FakeRouteBackend {
    existing: Vec<AppliedOperation>,
    apply_calls: Vec<RouteOperation>,
    revert_calls: Vec<AppliedOperation>,
    fail_apply_at: Option<usize>,
    fail_revert_at: Option<usize>,
  }

  impl FakeRouteBackend {
    fn empty() -> Self {
      Self::default()
    }

    fn with_existing(existing: Vec<AppliedOperation>) -> Self {
      Self {
        existing,
        ..Self::default()
      }
    }

    fn failing_apply_at(index: usize) -> Self {
      Self {
        fail_apply_at: Some(index),
        ..Self::default()
      }
    }
  }

  impl RouteBackend for FakeRouteBackend {
    async fn apply(&mut self, operation: &RouteOperation) -> anyhow::Result<ApplyOutcome> {
      let call_index = self.apply_calls.len();
      self.apply_calls.push(operation.clone());

      if self.fail_apply_at == Some(call_index) {
        anyhow::bail!("injected apply failure at call {call_index}");
      }

      let requested = operation.as_applied();
      let existing = self
        .existing
        .iter()
        .find(|existing| existing.destination() == operation.destination());

      match existing {
        Some(existing) if existing == &requested => Ok(ApplyOutcome::Unchanged),

        Some(existing) => {
          anyhow::bail!("route conflict: requested {requested:?}, but {existing:?} already exists")
        }

        None => {
          self.existing.push(requested.clone());
          Ok(ApplyOutcome::Applied(requested))
        }
      }
    }

    async fn revert(&mut self, operation: &AppliedOperation) -> anyhow::Result<()> {
      let call_index = self.revert_calls.len();
      self.revert_calls.push(operation.clone());

      if self.fail_revert_at == Some(call_index) {
        anyhow::bail!("injected revert failure at call {call_index}");
      }

      let position = self
        .existing
        .iter()
        .position(|existing| existing == operation)
        .ok_or_else(|| anyhow::anyhow!("cannot revert missing operation {operation:?}"))?;

      self.existing.remove(position);
      Ok(())
    }
  }

  fn route(destination: &str, interface: &str) -> RouteOperation {
    RouteOperation::AddRoute {
      destination: destination.parse().unwrap(),
      interface: interface.to_string(),
    }
  }

  fn applied_route(destination: &str, interface: &str) -> AppliedOperation {
    AppliedOperation::RouteAdded {
      destination: destination.parse().unwrap(),
      interface: interface.to_string(),
    }
  }

  #[test]
  fn client_routes_are_translated_in_order() {
    let config = RoutingConfig {
      protected_routes: vec![
        "172.16.0.0/24".parse().unwrap(),
        "172.17.0.0/24".parse().unwrap(),
      ],
      enable_forwarding: false,
      enable_nat: false,
    };

    let operations = client_operations(&config, "crabnet0");

    assert_eq!(
      operations,
      vec![
        route("172.16.0.0/24", "crabnet0"),
        route("172.17.0.0/24", "crabnet0"),
      ]
    );
  }

  #[test]
  fn empty_client_routes_produce_no_operations() {
    let operations = client_operations(&RoutingConfig::default(), "crabnet0");

    assert!(operations.is_empty());
  }

  #[tokio::test]
  async fn installs_routes_in_order() {
    let backend = FakeRouteBackend::empty();
    let mut manager = RouteManager::new(backend);

    let operations = vec![
      route("172.16.0.0/24", "crabnet0"),
      route("172.17.0.0/24", "crabnet0"),
    ];

    manager.install(&operations).await.unwrap();

    assert_eq!(manager.backend().apply_calls, operations);

    assert_eq!(
      manager.applied(),
      &[
        applied_route("172.16.0.0/24", "crabnet0"),
        applied_route("172.17.0.0/24", "crabnet0"),
      ]
    );
  }

  #[tokio::test]
  async fn restores_routes_in_reverse_order() {
    let backend = FakeRouteBackend::empty();
    let mut manager = RouteManager::new(backend);

    manager
      .install(&[
        route("172.16.0.0/24", "crabnet0"),
        route("172.17.0.0/24", "crabnet0"),
      ])
      .await
      .unwrap();

    manager.restore().await.unwrap();

    assert_eq!(
      manager.backend().revert_calls,
      vec![
        applied_route("172.17.0.0/24", "crabnet0"),
        applied_route("172.16.0.0/24", "crabnet0"),
      ]
    );

    assert!(manager.applied().is_empty());
    assert!(manager.backend().existing.is_empty());
  }

  #[tokio::test]
  async fn identical_existing_route_is_not_owned_or_removed() {
    let existing = applied_route("172.16.0.0/24", "crabnet0");

    let backend = FakeRouteBackend::with_existing(vec![existing.clone()]);

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

    let backend = FakeRouteBackend::with_existing(vec![existing.clone()]);

    let mut manager = RouteManager::new(backend);

    let error = manager
      .install(&[route("172.16.0.0/24", "crabnet0")])
      .await
      .unwrap_err();

    assert!(error.to_string().contains("route conflict"));
    assert!(manager.applied().is_empty());
    assert_eq!(manager.backend().existing, vec![existing]);
  }

  #[tokio::test]
  async fn installation_failure_rolls_back_previous_routes() {
    let backend = FakeRouteBackend::failing_apply_at(1);

    let mut manager = RouteManager::new(backend);

    let error = manager
      .install(&[
        route("172.16.0.0/24", "crabnet0"),
        route("172.17.0.0/24", "crabnet0"),
      ])
      .await
      .unwrap_err();

    assert!(error.to_string().contains("injected apply failure"));

    assert_eq!(
      manager.backend().revert_calls,
      vec![applied_route("172.16.0.0/24", "crabnet0"),]
    );

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

    assert!(message.contains("injected apply failure"));
    assert!(message.contains("rollback"));
    assert!(message.contains("injected revert failure"));
  }

  #[tokio::test]
  async fn restore_continues_after_one_revert_fails() {
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

    let error = manager.restore().await.unwrap_err();

    assert!(error
      .to_string()
      .contains("failed to restore routing state"));

    assert_eq!(
      manager.backend().revert_calls,
      vec![
        applied_route("172.18.0.0/24", "crabnet0"),
        applied_route("172.17.0.0/24", "crabnet0"),
        applied_route("172.16.0.0/24", "crabnet0"),
      ]
    );

    assert_eq!(
      manager.backend().existing,
      vec![applied_route("172.17.0.0/24", "crabnet0"),]
    );

    assert_eq!(
      manager.applied(),
      &[applied_route("172.17.0.0/24", "crabnet0")]
    );
  }

  #[tokio::test]
  async fn repeated_restore_is_a_no_op() {
    let backend = FakeRouteBackend::empty();
    let mut manager = RouteManager::new(backend);

    manager
      .install(&[route("172.16.0.0/24", "crabnet0")])
      .await
      .unwrap();

    manager.restore().await.unwrap();

    let calls_after_first_restore = manager.backend().revert_calls.len();

    manager.restore().await.unwrap();

    assert_eq!(
      manager.backend().revert_calls.len(),
      calls_after_first_restore
    );
  }

  #[tokio::test]
  async fn second_install_is_rejected_while_routes_are_owned() {
    let mut manager = RouteManager::new(FakeRouteBackend::empty());

    manager
      .install(&[route("172.16.0.0/24", "crabnet0")])
      .await
      .unwrap();

    let error = manager
      .install(&[route("172.17.0.0/24", "crabnet0")])
      .await
      .unwrap_err();

    assert!(error.to_string().contains("already installed"));
    assert_eq!(
      manager.backend().existing,
      vec![applied_route("172.16.0.0/24", "crabnet0")]
    );
  }

  #[tokio::test]
  async fn failed_restore_can_be_retried() {
    let backend = FakeRouteBackend {
      fail_revert_at: Some(0),
      ..FakeRouteBackend::default()
    };
    let mut manager = RouteManager::new(backend);

    manager
      .install(&[route("172.16.0.0/24", "crabnet0")])
      .await
      .unwrap();

    manager.restore().await.unwrap_err();
    assert_eq!(manager.applied().len(), 1);

    manager.backend.fail_revert_at = None;
    manager.restore().await.unwrap();

    assert!(manager.applied().is_empty());
    assert!(manager.backend().existing.is_empty());
  }
}
