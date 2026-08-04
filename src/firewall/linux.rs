use std::process::Stdio;

use anyhow::Context;
use tokio::process::Command;

use crate::firewall::diagnostics::FirewallInspector;

/// Captured result of one read-only firewall command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirewallCommandResult {
  success: bool,
  exit_code: Option<i32>,
  stdout: String,
  stderr: String,
}

/// Subprocess boundary used to test nftables inspection without invoking it.
pub(crate) trait FirewallCommandRunner {
  /// Executes one command and captures its exit status and output.
  async fn run(&mut self, program: &str, args: &[String]) -> anyhow::Result<FirewallCommandResult>;
}

/// Tokio subprocess runner used by the Linux firewall inspector.
#[derive(Debug, Default)]
pub(crate) struct TokioFirewallCommandRunner;

/// Linux nftables inspector backed by a replaceable command runner.
pub(crate) struct LinuxFirewallInspector<R> {
  runner: R,
}

impl<R> LinuxFirewallInspector<R> {
  /// Creates an inspector that delegates command execution to `runner`.
  pub(crate) fn new(runner: R) -> Self {
    Self { runner }
  }
}

impl<R> FirewallInspector for LinuxFirewallInspector<R>
where
  R: FirewallCommandRunner,
{
  async fn inspect_chains(&mut self) -> anyhow::Result<String> {
    let args = vec!["-j".to_owned(), "list".to_owned(), "chains".to_owned()];

    let result = self
      .runner
      .run("nft", &args)
      .await
      .context("failed to execute nftables firewall inspection")?;

    if !result.success {
      let stderr = result.stderr.trim();
      let stderr = if stderr.is_empty() {
        "<no stderr>"
      } else {
        stderr
      };
      anyhow::bail!(
        "`nft -j list chains` exited unsuccessfully with status {:?}: {}",
        result.exit_code,
        stderr
      )
    }

    Ok(result.stdout)
  }
}

impl FirewallCommandRunner for TokioFirewallCommandRunner {
  async fn run(&mut self, program: &str, args: &[String]) -> anyhow::Result<FirewallCommandResult> {
    log::debug!("Executing {} {}", program, args.join(" "));
    let mut command = Command::new(program);
    let output = command
      .args(args)
      .kill_on_drop(true)
      .stdout(Stdio::piped())
      .stderr(Stdio::piped())
      .output()
      .await
      .with_context(|| format!("failed to execute `{program}`"))?;

    Ok(FirewallCommandResult {
      success: output.status.success(),
      exit_code: output.status.code(),
      stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
      stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  struct FakeFirewallCommandRunner {
    result: Option<anyhow::Result<FirewallCommandResult>>,
    calls: Vec<(String, Vec<String>)>,
  }

  impl FirewallCommandRunner for FakeFirewallCommandRunner {
    async fn run(
      &mut self,
      program: &str,
      args: &[String],
    ) -> anyhow::Result<FirewallCommandResult> {
      self.calls.push((program.to_owned(), args.to_vec()));
      self
        .result
        .take()
        .unwrap_or_else(|| Err(anyhow::anyhow!("fake runner called more than once")))
    }
  }

  fn result(
    success: bool,
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
  ) -> FirewallCommandResult {
    FirewallCommandResult {
      success,
      exit_code,
      stdout: stdout.to_owned(),
      stderr: stderr.to_owned(),
    }
  }

  fn inspector(
    result: anyhow::Result<FirewallCommandResult>,
  ) -> LinuxFirewallInspector<FakeFirewallCommandRunner> {
    LinuxFirewallInspector::new(FakeFirewallCommandRunner {
      result: Some(result),
      calls: Vec::new(),
    })
  }

  #[tokio::test]
  async fn inspect_chains_runs_exact_read_only_command() {
    let mut inspector = inspector(Ok(result(true, Some(0), "chains", "")));

    let stdout = inspector.inspect_chains().await.unwrap();

    assert_eq!(stdout, "chains");
    assert_eq!(
      inspector.runner.calls,
      vec![(
        "nft".to_owned(),
        vec!["-j".to_owned(), "list".to_owned(), "chains".to_owned()]
      )]
    );
  }

  #[tokio::test]
  async fn inspect_chains_reports_exit_status_and_stderr() {
    let mut inspector = inspector(Ok(result(false, Some(1), "", "permission denied\n")));

    let error = inspector.inspect_chains().await.unwrap_err();
    let message = error.to_string();

    assert!(message.contains("status Some(1)"));
    assert!(message.contains("permission denied"));
  }

  #[tokio::test]
  async fn inspect_chains_reports_missing_stderr() {
    let mut inspector = inspector(Ok(result(false, None, "", "  ")));

    let error = inspector.inspect_chains().await.unwrap_err();

    assert!(error.to_string().contains("<no stderr>"));
  }

  #[tokio::test]
  async fn inspect_chains_preserves_runner_failure_context() {
    let mut inspector = inspector(Err(anyhow::anyhow!("nft executable missing")));

    let error = inspector.inspect_chains().await.unwrap_err();
    let message = format!("{error:#}");

    assert!(message.contains("failed to execute nftables firewall inspection"));
    assert!(message.contains("nft executable missing"));
  }
}
