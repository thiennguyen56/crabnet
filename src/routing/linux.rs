use anyhow::Context;
use ipnet::IpNet;
use serde::Deserialize;
use tokio::process::Command;

use super::manager::{AppliedOperation, ApplyOutcome, RouteBackend, RouteOperation};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommandResult {
  success: bool,
  exit_code: Option<i32>,
  stdout: String,
  stderr: String,
}

pub(crate) trait CommandRunner {
  async fn run(&mut self, program: &str, args: &[String]) -> anyhow::Result<CommandResult>;
}

#[derive(Debug, Default)]
pub(crate) struct TokioCommandRunner;

impl CommandRunner for TokioCommandRunner {
  async fn run(&mut self, program: &str, args: &[String]) -> anyhow::Result<CommandResult> {
    log::debug!("Executing network command: {} {}", program, args.join(" "));
    let output = Command::new(program)
      .args(args)
      .kill_on_drop(true)
      .output()
      .await
      .with_context(|| format!("failed to execute `{program}`; ensure iproute2 is installed"))?;

    Ok(CommandResult {
      success: output.status.success(),
      exit_code: output.status.code(),
      stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
      stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
  }
}

pub(crate) struct LinuxRouteBackend<R> {
  runner: R,
}

impl<R> LinuxRouteBackend<R> {
  pub(crate) fn new(runner: R) -> Self {
    Self { runner }
  }
}

impl<R> RouteBackend for LinuxRouteBackend<R>
where
  R: CommandRunner,
{
  async fn apply(&mut self, operation: &RouteOperation) -> anyhow::Result<ApplyOutcome> {
    match operation {
      RouteOperation::AddRoute {
        destination,
        interface,
      } => match inspect_route(&mut self.runner, destination, interface).await? {
        ExistingRoute::Identical => {
          log::debug!("Route {destination} through {interface} already exists");
          Ok(ApplyOutcome::Unchanged)
        }
        ExistingRoute::Conflicting => anyhow::bail!(
          "cannot install route {destination} through {interface}: a conflicting route already exists"
        ),
        ExistingRoute::Missing => {
          run_checked(
            &mut self.runner,
            &add_route_args(destination, interface),
            &format!("failed to add route {destination} through {interface}"),
          )
          .await?;
          log::info!("Installed route {destination} through {interface}");
          Ok(ApplyOutcome::Applied(AppliedOperation::RouteAdded {
            destination: *destination,
            interface: interface.clone(),
          }))
        }
      },
    }
  }

  async fn revert(&mut self, operation: &AppliedOperation) -> anyhow::Result<()> {
    match operation {
      AppliedOperation::RouteAdded {
        destination,
        interface,
      } => match inspect_route(&mut self.runner, destination, interface).await? {
        ExistingRoute::Missing => {
          log::warn!("Route {destination} through {interface} was already removed");
          Ok(())
        }
        ExistingRoute::Conflicting => anyhow::bail!(
          "refusing to remove route {destination}: routing state changed after Crabnet installed it"
        ),
        ExistingRoute::Identical => {
          run_checked(
            &mut self.runner,
            &delete_route_args(destination, interface),
            &format!("failed to remove route {destination} through {interface}"),
          )
          .await?;
          log::info!("Removed route {destination} through {interface}");
          Ok(())
        }
      },
    }
  }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct IpRoute {
  dst: Option<String>,
  dev: Option<String>,
  gateway: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExistingRoute {
  Missing,
  Identical,
  Conflicting,
}

fn classify_existing_route(
  routes: &[IpRoute],
  destination: &IpNet,
  interface: &str,
) -> ExistingRoute {
  let destination = destination.to_string();
  if routes.is_empty() {
    return ExistingRoute::Missing;
  }

  let identical = routes.iter().any(|route| {
    route.dst.as_deref() == Some(destination.as_str())
      && route.dev.as_deref() == Some(interface)
      && route.gateway.is_none()
  });
  let conflicting = routes.iter().any(|route| {
    route.dst.as_deref() == Some(destination.as_str())
      && !(route.dev.as_deref() == Some(interface) && route.gateway.is_none())
  });

  if conflicting {
    ExistingRoute::Conflicting
  } else if identical {
    ExistingRoute::Identical
  } else {
    ExistingRoute::Missing
  }
}

async fn inspect_route<R>(
  runner: &mut R,
  destination: &IpNet,
  interface: &str,
) -> anyhow::Result<ExistingRoute>
where
  R: CommandRunner,
{
  let result = run_checked(
    runner,
    &show_route_args(destination),
    &format!("failed to inspect route {destination}"),
  )
  .await?;
  let routes: Vec<IpRoute> = serde_json::from_str(&result.stdout)
    .context("failed to parse JSON returned by `ip -j route show`")?;
  Ok(classify_existing_route(&routes, destination, interface))
}

fn show_route_args(destination: &IpNet) -> Vec<String> {
  vec!["-j", "route", "show", "exact"]
    .into_iter()
    .map(str::to_owned)
    .chain(std::iter::once(destination.to_string()))
    .collect()
}

fn route_change_args(action: &str, destination: &IpNet, interface: &str) -> Vec<String> {
  vec![
    "route".to_owned(),
    action.to_owned(),
    destination.to_string(),
    "dev".to_owned(),
    interface.to_owned(),
  ]
}

fn add_route_args(destination: &IpNet, interface: &str) -> Vec<String> {
  route_change_args("add", destination, interface)
}

fn delete_route_args(destination: &IpNet, interface: &str) -> Vec<String> {
  route_change_args("del", destination, interface)
}

async fn run_checked<R>(
  runner: &mut R,
  args: &[String],
  action: &str,
) -> anyhow::Result<CommandResult>
where
  R: CommandRunner,
{
  let result = runner.run("ip", args).await?;
  if !result.success {
    let stderr = result.stderr.trim();
    anyhow::bail!(
      "{action} failed with exit code {:?}: {}",
      result.exit_code,
      if stderr.is_empty() {
        "<no stderr>"
      } else {
        stderr
      }
    );
  }
  Ok(result)
}

#[cfg(test)]
mod tests {
  use std::collections::VecDeque;

  use super::*;

  #[derive(Debug, Clone, PartialEq, Eq)]
  struct CommandCall {
    program: String,
    args: Vec<String>,
  }

  #[derive(Default)]
  struct FakeCommandRunner {
    responses: VecDeque<anyhow::Result<CommandResult>>,
    calls: Vec<CommandCall>,
  }

  impl CommandRunner for FakeCommandRunner {
    async fn run(&mut self, program: &str, args: &[String]) -> anyhow::Result<CommandResult> {
      self.calls.push(CommandCall {
        program: program.to_owned(),
        args: args.to_vec(),
      });
      self
        .responses
        .pop_front()
        .unwrap_or_else(|| Err(anyhow::anyhow!("fake runner has no queued response")))
    }
  }

  fn success(stdout: &str) -> anyhow::Result<CommandResult> {
    Ok(CommandResult {
      success: true,
      exit_code: Some(0),
      stdout: stdout.to_owned(),
      stderr: String::new(),
    })
  }

  fn failure(stderr: &str) -> anyhow::Result<CommandResult> {
    Ok(CommandResult {
      success: false,
      exit_code: Some(2),
      stdout: String::new(),
      stderr: stderr.to_owned(),
    })
  }

  fn operation() -> RouteOperation {
    RouteOperation::AddRoute {
      destination: "172.16.0.0/24".parse().unwrap(),
      interface: "crabnet0".to_owned(),
    }
  }

  fn applied() -> AppliedOperation {
    AppliedOperation::RouteAdded {
      destination: "172.16.0.0/24".parse().unwrap(),
      interface: "crabnet0".to_owned(),
    }
  }

  fn backend(
    responses: Vec<anyhow::Result<CommandResult>>,
  ) -> LinuxRouteBackend<FakeCommandRunner> {
    LinuxRouteBackend::new(FakeCommandRunner {
      responses: responses.into(),
      calls: Vec::new(),
    })
  }

  #[test]
  fn builds_exact_iproute2_arguments() {
    let destination = "172.16.0.0/24".parse().unwrap();
    assert_eq!(
      show_route_args(&destination),
      ["-j", "route", "show", "exact", "172.16.0.0/24"]
    );
    assert_eq!(
      add_route_args(&destination, "crabnet0"),
      ["route", "add", "172.16.0.0/24", "dev", "crabnet0"]
    );
  }

  #[tokio::test]
  async fn missing_route_is_added() {
    let mut backend = backend(vec![success("[]"), success("")]);
    assert_eq!(
      backend.apply(&operation()).await.unwrap(),
      ApplyOutcome::Applied(applied())
    );
    assert_eq!(backend.runner.calls.len(), 2);
  }

  #[tokio::test]
  async fn identical_route_is_unchanged() {
    let mut backend = backend(vec![success(
      r#"[{"dst":"172.16.0.0/24","dev":"crabnet0"}]"#,
    )]);
    assert_eq!(
      backend.apply(&operation()).await.unwrap(),
      ApplyOutcome::Unchanged
    );
    assert_eq!(backend.runner.calls.len(), 1);
  }

  #[tokio::test]
  async fn conflicting_device_or_gateway_is_rejected() {
    for json in [
      r#"[{"dst":"172.16.0.0/24","dev":"eth0"}]"#,
      r#"[{"dst":"172.16.0.0/24","dev":"crabnet0","gateway":"10.0.0.1"}]"#,
    ] {
      let mut backend = backend(vec![success(json)]);
      assert!(backend
        .apply(&operation())
        .await
        .unwrap_err()
        .to_string()
        .contains("conflicting route"));
    }
  }

  #[tokio::test]
  async fn inspection_and_json_errors_are_propagated() {
    let mut command_failure = backend(vec![failure("permission denied")]);
    assert!(format!(
      "{:#}",
      command_failure.apply(&operation()).await.unwrap_err()
    )
    .contains("permission denied"));

    let mut invalid_json = backend(vec![success("not-json")]);
    assert!(
      format!("{:#}", invalid_json.apply(&operation()).await.unwrap_err())
        .contains("failed to parse JSON")
    );

    let mut missing_program = backend(vec![Err(anyhow::anyhow!("No such file or directory"))]);
    assert!(format!(
      "{:#}",
      missing_program.apply(&operation()).await.unwrap_err()
    )
    .contains("No such file"));
  }

  #[tokio::test]
  async fn add_failure_is_propagated() {
    let mut backend = backend(vec![success("[]"), failure("Operation not permitted")]);
    let message = format!("{:#}", backend.apply(&operation()).await.unwrap_err());
    assert!(message.contains("172.16.0.0/24"));
    assert!(message.contains("crabnet0"));
    assert!(message.contains("Operation not permitted"));
  }

  #[tokio::test]
  async fn identical_owned_route_is_deleted() {
    let mut backend = backend(vec![
      success(r#"[{"dst":"172.16.0.0/24","dev":"crabnet0"}]"#),
      success(""),
    ]);
    backend.revert(&applied()).await.unwrap();
    assert_eq!(
      backend.runner.calls[1].args,
      ["route", "del", "172.16.0.0/24", "dev", "crabnet0"]
    );
  }

  #[tokio::test]
  async fn missing_route_during_restore_is_success() {
    let mut backend = backend(vec![success("[]")]);
    backend.revert(&applied()).await.unwrap();
    assert_eq!(backend.runner.calls.len(), 1);
  }

  #[tokio::test]
  async fn changed_route_is_not_deleted() {
    let mut backend = backend(vec![success(r#"[{"dst":"172.16.0.0/24","dev":"eth0"}]"#)]);
    assert!(backend.revert(&applied()).await.is_err());
    assert_eq!(backend.runner.calls.len(), 1);
  }

  #[tokio::test]
  async fn delete_failure_is_propagated() {
    let mut backend = backend(vec![
      success(r#"[{"dst":"172.16.0.0/24","dev":"crabnet0"}]"#),
      failure("delete failed"),
    ]);
    assert!(
      format!("{:#}", backend.revert(&applied()).await.unwrap_err()).contains("delete failed")
    );
  }
}
