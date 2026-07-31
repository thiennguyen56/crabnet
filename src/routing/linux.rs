use anyhow::Context;
use ipnet::IpNet;
use serde::Deserialize;
use tokio::process::Command;

use super::manager::{AppliedOperation, ApplyOutcome, RouteBackend, RouteOperation};

const IPV4_FORWARDING_KEY: &str = "net.ipv4.ip_forward";

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
      .with_context(|| format!("failed to execute `{program}`"))?;

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
      } => self.apply_route(destination, interface).await,
      RouteOperation::SetIpv4Forwarding { enabled } => self.apply_ipv4_forwarding(*enabled).await,
    }
  }

  async fn revert(&mut self, operation: &AppliedOperation) -> anyhow::Result<()> {
    match operation {
      AppliedOperation::RouteAdded {
        destination,
        interface,
      } => self.revert_route(destination, interface).await,

      AppliedOperation::Ipv4ForwardingChanged { previous } => {
        self.revert_ipv4_forwarding(*previous).await
      }
    }
  }
}

impl<R> LinuxRouteBackend<R>
where
  R: CommandRunner,
{
  async fn apply_route(
    &mut self,
    destination: &IpNet,
    interface: &str,
  ) -> anyhow::Result<ApplyOutcome> {
    match inspect_route(&mut self.runner, destination, interface).await? {
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
            "ip",
            &add_route_args(destination, interface),
            &format!("failed to add route {destination} through {interface}"),
          )
          .await?;
          log::info!("Installed route {destination} through {interface}");
          Ok(ApplyOutcome::Applied(AppliedOperation::RouteAdded {
            destination: *destination,
            interface: interface.to_string(),
          }))
        }
      }
  }

  async fn apply_ipv4_forwarding(&mut self, requested: bool) -> anyhow::Result<ApplyOutcome> {
    let current = read_ipv4_forwarding(&mut self.runner).await?;

    if current == requested {
      log::debug!(
        "IPv4 forwarding is already {}",
        if requested { "enabled" } else { "disabled" }
      );

      return Ok(ApplyOutcome::Unchanged);
    }

    write_ipv4_forwarding(&mut self.runner, requested).await?;

    log::info!("Set IPv4 forwarding to {}", u8::from(requested));

    Ok(ApplyOutcome::Applied(
      AppliedOperation::Ipv4ForwardingChanged { previous: current },
    ))
  }

  async fn revert_route(&mut self, destination: &IpNet, interface: &str) -> anyhow::Result<()> {
    match inspect_route(&mut self.runner, destination, interface).await? {
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
          "ip",
          &delete_route_args(destination, interface),
          &format!("failed to remove route {destination} through {interface}"),
        )
        .await?;
        log::info!("Removed route {destination} through {interface}");
        Ok(())
      }
    }
  }

  async fn revert_ipv4_forwarding(&mut self, previous: bool) -> anyhow::Result<()> {
    let current = read_ipv4_forwarding(&mut self.runner).await?;

    if current == previous {
      log::debug!(
        "IPv4 forwarding is already restored to {}",
        u8::from(previous)
      );

      return Ok(());
    }

    write_ipv4_forwarding(&mut self.runner, previous).await?;

    log::info!("Restored IPv4 forwarding to {}", u8::from(previous));

    Ok(())
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
    "ip",
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

fn read_ipv4_forwarding_args() -> Vec<String> {
  vec!["-n".to_owned(), IPV4_FORWARDING_KEY.to_owned()]
}

fn write_ipv4_forwarding_args(enabled: bool) -> Vec<String> {
  vec![
    "-w".to_owned(),
    format!("{IPV4_FORWARDING_KEY}={}", u8::from(enabled)),
  ]
}

fn parse_ipv4_forwarding(stdout: &str) -> anyhow::Result<bool> {
  match stdout.trim() {
    "0" => Ok(false),
    "1" => Ok(true),

    value => anyhow::bail!(
      "unexpected value for {IPV4_FORWARDING_KEY}: \
      expected 0 or 1, received {value:?}"
    ),
  }
}

async fn read_ipv4_forwarding<R>(runner: &mut R) -> anyhow::Result<bool>
where
  R: CommandRunner,
{
  let result = run_checked(
    runner,
    "sysctl",
    &read_ipv4_forwarding_args(),
    "failed to read IPv4 forwarding state",
  )
  .await?;

  parse_ipv4_forwarding(&result.stdout)
}

async fn write_ipv4_forwarding<R>(runner: &mut R, enabled: bool) -> anyhow::Result<()>
where
  R: CommandRunner,
{
  run_checked(
    runner,
    "sysctl",
    &write_ipv4_forwarding_args(enabled),
    &format!("failed to set IPv4 forwarding to {}", u8::from(enabled)),
  )
  .await?;

  Ok(())
}

async fn run_checked<R>(
  runner: &mut R,
  program: &str,
  args: &[String],
  action: &str,
) -> anyhow::Result<CommandResult>
where
  R: CommandRunner,
{
  let result = runner.run(program, args).await?;
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

  #[test]
  fn parses_ipv4_forwarding_values() {
    assert!(!parse_ipv4_forwarding("0\n").unwrap());
    assert!(parse_ipv4_forwarding("1\n").unwrap());
  }

  #[test]
  fn rejects_invalid_ipv4_forwarding_value() {
    let error = parse_ipv4_forwarding("enabled\n").unwrap_err();

    assert!(error.to_string().contains("expected 0 or 1"));
  }

  #[tokio::test]
  async fn disabled_forwarding_is_enabled() {
    let mut backend = backend(vec![success("0\n"), success("net.ipv4.ip_forward = 1\n")]);

    let outcome = backend
      .apply(&RouteOperation::SetIpv4Forwarding { enabled: true })
      .await
      .unwrap();

    assert_eq!(
      outcome,
      ApplyOutcome::Applied(AppliedOperation::Ipv4ForwardingChanged { previous: false })
    );
    assert_eq!(backend.runner.calls[0].program, "sysctl");
    assert_eq!(backend.runner.calls[0].args, ["-n", "net.ipv4.ip_forward"]);
    assert_eq!(backend.runner.calls[1].program, "sysctl");
    assert_eq!(
      backend.runner.calls[1].args,
      ["-w", "net.ipv4.ip_forward=1"]
    );
  }

  #[tokio::test]
  async fn enabled_forwarding_is_unchanged() {
    let mut backend = backend(vec![success("1\n")]);

    let outcome = backend
      .apply(&RouteOperation::SetIpv4Forwarding { enabled: true })
      .await
      .unwrap();

    assert_eq!(outcome, ApplyOutcome::Unchanged);
    assert_eq!(backend.runner.calls.len(), 1);
  }

  #[tokio::test]
  async fn invalid_forwarding_value_is_rejected() {
    let mut backend = backend(vec![success("enabled\n")]);

    let error = backend
      .apply(&RouteOperation::SetIpv4Forwarding { enabled: true })
      .await
      .unwrap_err();

    assert!(error.to_string().contains("expected 0 or 1"));
  }

  #[tokio::test]
  async fn forwarding_read_and_write_failures_are_propagated() {
    let mut read_failure = backend(vec![failure("read denied")]);
    assert!(format!(
      "{:#}",
      read_failure
        .apply(&RouteOperation::SetIpv4Forwarding { enabled: true })
        .await
        .unwrap_err()
    )
    .contains("read denied"));

    let mut write_failure = backend(vec![success("0\n"), failure("write denied")]);
    let message = format!(
      "{:#}",
      write_failure
        .apply(&RouteOperation::SetIpv4Forwarding { enabled: true })
        .await
        .unwrap_err()
    );
    assert!(message.contains("failed to set IPv4 forwarding to 1"));
    assert!(message.contains("write denied"));
  }

  #[tokio::test]
  async fn forwarding_is_restored_to_previous_value() {
    let mut backend = backend(vec![success("1\n"), success("net.ipv4.ip_forward = 0\n")]);

    backend
      .revert(&AppliedOperation::Ipv4ForwardingChanged { previous: false })
      .await
      .unwrap();

    assert_eq!(backend.runner.calls[0].program, "sysctl");
    assert_eq!(backend.runner.calls[1].program, "sysctl");
    assert_eq!(
      backend.runner.calls[1].args,
      ["-w", "net.ipv4.ip_forward=0"]
    );
  }

  #[tokio::test]
  async fn forwarding_already_restored_needs_no_write() {
    let mut backend = backend(vec![success("0\n")]);

    backend
      .revert(&AppliedOperation::Ipv4ForwardingChanged { previous: false })
      .await
      .unwrap();

    assert_eq!(backend.runner.calls.len(), 1);
  }

  #[tokio::test]
  async fn forwarding_restore_failure_is_propagated() {
    let mut backend = backend(vec![success("1\n"), failure("restore denied")]);

    let message = format!(
      "{:#}",
      backend
        .revert(&AppliedOperation::Ipv4ForwardingChanged { previous: false })
        .await
        .unwrap_err()
    );
    assert!(message.contains("restore denied"));
  }
}
