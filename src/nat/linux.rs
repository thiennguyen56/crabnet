//! Linux NAT backend using nftables.
//!
//! Command execution, JSON parsing, ruleset construction, and fingerprint
//! normalization are separated so unit tests do not require root.

use std::process::Stdio;

use anyhow::Context;
use serde::Deserialize;
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::manager::{AppliedNat, NatBackend, NatSpec};

const NFT_TABLE_FAMILY: &str = "ip";
const NFT_TABLE_NAME: &str = "crabnet_nat";
const NFT_POSTROUTING_CHAIN: &str = "postrouting";

/// Captured result of one operating-system command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NatCommandResult {
  success: bool,
  exit_code: Option<i32>,
  stdout: String,
  stderr: String,
}

/// Injectable command executor with optional standard input.
pub(crate) trait NatCommandRunner {
  /// Executes one program with exact arguments and optional input.
  async fn run(
    &mut self,
    program: &str,
    args: &[String],
    stdin: Option<&str>,
  ) -> anyhow::Result<NatCommandResult>;
}

/// Production command runner backed by Tokio
#[derive(Debug, Default)]
pub(crate) struct TokioNatCommandRunner;

impl NatCommandRunner for TokioNatCommandRunner {
  async fn run(
    &mut self,
    program: &str,
    args: &[String],
    stdin: Option<&str>,
  ) -> anyhow::Result<NatCommandResult> {
    log::debug!("Executing NAT command: {} {}", program, args.join(" "));

    let mut command = Command::new(program);
    command
      .args(args)
      .kill_on_drop(true)
      .stdout(Stdio::piped())
      .stderr(Stdio::piped());

    if stdin.is_some() {
      command.stdin(Stdio::piped());
    }

    let mut child = command
      .spawn()
      .with_context(|| format!("failed to execute `{program}`"))?;

    if let Some(input) = stdin {
      let mut child_stdin = child
        .stdin
        .take()
        .context("failed to open child command stdin")?;

      child_stdin
        .write_all(input.as_bytes())
        .await
        .with_context(|| format!("failed to write ruleset to `{program}`"))?;

      child_stdin
        .shutdown()
        .await
        .with_context(|| format!("failed to close `{program}` stdin"))?;
    }

    let output = child
      .wait_with_output()
      .await
      .with_context(|| format!("failed to wait for `{program}`"))?;

    Ok(NatCommandResult {
      success: output.status.success(),
      exit_code: output.status.code(),
      stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
      stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
  }
}

/// Linux nftables implementation of server-side IPv4 masquerading
pub(crate) struct LinuxNatBackend<R> {
  runner: R,
}

impl<R> LinuxNatBackend<R> {
  /// Creates a Linux NAT backend around an injectable command runner
  pub(crate) fn new(runner: R) -> Self {
    Self { runner }
  }
}

impl<R> NatBackend for LinuxNatBackend<R>
where
  R: NatCommandRunner,
{
  async fn apply(&mut self, spec: &NatSpec) -> anyhow::Result<AppliedNat> {
    inspect_interface(&mut self.runner, &spec.tun_interface).await?;
    inspect_interface(&mut self.runner, &spec.egress_interface).await?;

    if table_exists(&mut self.runner).await? {
      anyhow::bail!(
        "cannot install NAT: nftables table \
         {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} already exists; \
         Crabnet cannot prove ownership"
      );
    }

    let ruleset = render_ruleset(spec);
    run_checked(
      &mut self.runner,
      "nft",
      &["-f".to_owned(), "-".to_owned()],
      Some(&ruleset),
      "failed to install Crabnet NAT ruleset",
    )
    .await?;

    let fingerprint = match inspect_table(&mut self.runner).await {
      Ok(fingerprint) => fingerprint,
      Err(inspect_error) => {
        let cleanup_result = delete_table(&mut self.runner).await;

        return match cleanup_result {
          Ok(()) => Err(
            inspect_error
              .context("NAT was installed but its ownership fingerprint could not be captured"),
          ),
          Err(cleanup_error) => Err(inspect_error.context(format!(
            "NAT was installed but fingerprint inspection failed; \
                   emergency cleanup also failed: {cleanup_error:#}"
          ))),
        };
      }
    };

    log::info!(
      "Installed IPv4 NAT for {} from {} to {}",
      spec.source_network,
      spec.tun_interface,
      spec.egress_interface
    );

    Ok(AppliedNat { fingerprint })
  }

  async fn revert(&mut self, applied: &AppliedNat) -> anyhow::Result<()> {
    if !table_exists(&mut self.runner).await? {
      log::warn!("NAT table {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} was already removed");
      return Ok(());
    }

    let current = inspect_table(&mut self.runner).await?;

    if current != applied.fingerprint {
      anyhow::bail!(
        "refusing to remove nftables table \
               {NFT_TABLE_FAMILY} {NFT_TABLE_NAME}: \
               NAT state changed after Crabnet installed it"
      );
    }

    delete_table(&mut self.runner).await?;

    log::info!("Removed nftables table {NFT_TABLE_FAMILY} {NFT_TABLE_NAME}");

    Ok(())
  }
}

/// Minimal JSON returned by `nft -j list tables`.
#[derive(Debug, Deserialize)]
struct NftListing {
  nftables: Vec<NftObject>,
}

/// One object inside nftables JSON output.
#[derive(Debug, Deserialize)]
struct NftObject {
  table: Option<NftTable>,
}

/// Table identity used for ownership conflict detection.
#[derive(Debug, Deserialize)]
struct NftTable {
  family: String,
  name: String,
}

/// Confirms that an interface exists in the current network namespace.
async fn inspect_interface<R>(runner: &mut R, interface: &str) -> anyhow::Result<()>
where
  R: NatCommandRunner,
{
  run_checked(
    runner,
    "ip",
    &[
      "-j".to_owned(),
      "link".to_owned(),
      "show".to_owned(),
      "dev".to_owned(),
      interface.to_owned(),
    ],
    None,
    &format!("NAT interface {interface} does not exist"),
  )
  .await?;

  Ok(())
}

/// Returns whether the reserved Crabnet NAT table already exists.
async fn table_exists<R>(runner: &mut R) -> anyhow::Result<bool>
where
  R: NatCommandRunner,
{
  let result = run_checked(
    runner,
    "nft",
    &["-j".to_owned(), "list".to_owned(), "tables".to_owned()],
    None,
    "failed to inspect nftables tables",
  )
  .await?;

  let listing: NftListing = serde_json::from_str(&result.stdout)
    .context("failed to parse JSON returned by `nft -j list tables`")?;

  Ok(listing.nftables.iter().any(|object| {
    object
      .table
      .as_ref()
      .is_some_and(|table| table.family == NFT_TABLE_FAMILY && table.name == NFT_TABLE_NAME)
  }))
}

/// Reads and normalizes the complete Crabnet NAT table.
async fn inspect_table<R>(runner: &mut R) -> anyhow::Result<Value>
where
  R: NatCommandRunner,
{
  let result = run_checked(
    runner,
    "nft",
    &[
      "-j".to_owned(),
      "list".to_owned(),
      "table".to_owned(),
      NFT_TABLE_FAMILY.to_owned(),
      NFT_TABLE_NAME.to_owned(),
    ],
    None,
    "failed to inspect the Crabnet NAT table",
  )
  .await?;

  let value: Value = serde_json::from_str(&result.stdout)
    .context("failed to parse JSON returned by `nft -j list table`")?;

  Ok(normalize_fingerprint(value))
}

/// Removes the complete table owned by Crabnet.
async fn delete_table<R>(runner: &mut R) -> anyhow::Result<()>
where
  R: NatCommandRunner,
{
  run_checked(
    runner,
    "nft",
    &[
      "delete".to_owned(),
      "table".to_owned(),
      NFT_TABLE_FAMILY.to_owned(),
      NFT_TABLE_NAME.to_owned(),
    ],
    None,
    "failed to delete the Crabnet NAT table",
  )
  .await?;

  Ok(())
}

/// Renders one atomic nftables batch.
///
/// Interface names have already passed conservative validation, so they cannot
/// break out of the quoted string expressions below.
fn render_ruleset(spec: &NatSpec) -> String {
  format!(
    "add table {NFT_TABLE_FAMILY} {NFT_TABLE_NAME}\n\
       add chain {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} \
       {NFT_POSTROUTING_CHAIN} {{ type nat hook postrouting priority srcnat; }}\n\
       add rule {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} \
       {NFT_POSTROUTING_CHAIN} \
       iifname \"{}\" oifname \"{}\" ip saddr {} \
       counter masquerade\n",
    spec.tun_interface, spec.egress_interface, spec.source_network,
  )
}

/// Removes values expected to change while packets traverse the rule.
///
/// Rules, chains, expressions, handles, and table identity remain in the
/// fingerprint. Only metadata and counter values are ignored.
fn normalize_fingerprint(mut value: Value) -> Value {
  if let Some(objects) = value.get_mut("nftables").and_then(Value::as_array_mut) {
    objects.retain(|object| object.get("metainfo").is_none());
  }

  normalize_counter_values(&mut value);
  value
}

/// Recursively removes packet and byte values from counter expressions.
fn normalize_counter_values(value: &mut Value) {
  match value {
    Value::Array(values) => {
      for value in values {
        normalize_counter_values(value);
      }
    }

    Value::Object(map) => {
      if let Some(Value::Object(counter)) = map.get_mut("counter") {
        counter.remove("packets");
        counter.remove("bytes");
      }

      for value in map.values_mut() {
        normalize_counter_values(value);
      }
    }

    Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
  }
}

/// Runs a command and turns a non-zero status into a contextual error.
async fn run_checked<R>(
  runner: &mut R,
  program: &str,
  args: &[String],
  stdin: Option<&str>,
  action: &str,
) -> anyhow::Result<NatCommandResult>
where
  R: NatCommandRunner,
{
  let result = runner.run(program, args, stdin).await?;

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
    stdin: Option<String>,
  }

  #[derive(Default)]
  struct FakeNatCommandRunner {
    responses: VecDeque<anyhow::Result<NatCommandResult>>,
    calls: Vec<CommandCall>,
  }

  impl NatCommandRunner for FakeNatCommandRunner {
    async fn run(
      &mut self,
      program: &str,
      args: &[String],
      stdin: Option<&str>,
    ) -> anyhow::Result<NatCommandResult> {
      self.calls.push(CommandCall {
        program: program.to_owned(),
        args: args.to_vec(),
        stdin: stdin.map(str::to_owned),
      });
      self
        .responses
        .pop_front()
        .unwrap_or_else(|| Err(anyhow::anyhow!("fake NAT runner has no queued response")))
    }
  }

  fn success(stdout: &str) -> anyhow::Result<NatCommandResult> {
    Ok(NatCommandResult {
      success: true,
      exit_code: Some(0),
      stdout: stdout.to_owned(),
      stderr: String::new(),
    })
  }

  fn failure(stderr: &str) -> anyhow::Result<NatCommandResult> {
    Ok(NatCommandResult {
      success: false,
      exit_code: Some(1),
      stdout: String::new(),
      stderr: stderr.to_owned(),
    })
  }

  fn spec() -> NatSpec {
    NatSpec {
      source_network: "10.0.0.0/24".parse().unwrap(),
      tun_interface: "crabnet0".to_owned(),
      egress_interface: "eth0".to_owned(),
    }
  }
  fn empty_tables() -> &'static str {
    r#"{"nftables":[{"metainfo":{"json_schema_version":1}}]}"#
  }

  fn existing_table() -> &'static str {
    r#"{
                    "nftables": [
                      {
                        "table": {
                          "family": "ip",
                          "name": "crabnet_nat"
                        }
                      }
                    ]
                  }"#
  }
  fn installed_table(packets: u64) -> String {
    format!(
      r#"{{
                          "nftables": [
                            {{
                              "metainfo": {{
                                "json_schema_version": 1
                              }}
                            }},
                            {{
                              "table": {{
                                "family": "ip",
                                "name": "crabnet_nat",
                                "handle": 1
                              }}
                            }},
                            {{
                              "rule": {{
                                "family": "ip",
                                "table": "crabnet_nat",
                                "chain": "postrouting",
                                "handle": 3,
                                "expr": [
                                  {{
                                    "counter": {{
                                      "packets": {packets},
                                      "bytes": 128
                                    }}
                                  }}
                                ]
                              }}
                            }}
                          ]
                        }}"#
    )
  }
  fn backend(
    responses: Vec<anyhow::Result<NatCommandResult>>,
  ) -> LinuxNatBackend<FakeNatCommandRunner> {
    LinuxNatBackend::new(FakeNatCommandRunner {
      responses: responses.into(),
      calls: Vec::new(),
    })
  }

  #[test]
  fn renders_narrow_masquerade_rule() {
    let ruleset = render_ruleset(&spec());

    assert!(ruleset.contains("add table ip crabnet_nat"));
    assert!(ruleset.contains("type nat hook postrouting priority srcnat"));
    assert!(ruleset.contains(r#"iifname "crabnet0""#));
    assert!(ruleset.contains(r#"oifname "eth0""#));
    assert!(ruleset.contains("ip saddr 10.0.0.0/24"));
    assert!(ruleset.contains("counter masquerade"));
  }

  #[test]
  fn changing_counters_do_not_change_fingerprint() {
    let first = normalize_fingerprint(serde_json::from_str(&installed_table(0)).unwrap());
    let second = normalize_fingerprint(serde_json::from_str(&installed_table(12)).unwrap());

    assert_eq!(first, second);
  }
  #[tokio::test]
  async fn existing_table_is_rejected() {
    let mut backend = backend(vec![
      success("[]"),
      success("[]"),
      success(existing_table()),
    ]);

    let error = backend.apply(&spec()).await.unwrap_err();

    assert!(error.to_string().contains("already exists"));
    assert_eq!(backend.runner.calls.len(), 3);
  }

  #[tokio::test]
  async fn missing_table_is_installed_atomically() {
    let snapshot = installed_table(0);
    let mut backend = backend(vec![
      success("[]"),
      success("[]"),
      success(empty_tables()),
      success(""),
      success(&snapshot),
    ]);

    let applied = backend.apply(&spec()).await.unwrap();

    assert_eq!(
      applied.fingerprint,
      normalize_fingerprint(serde_json::from_str(&snapshot).unwrap())
    );
    let apply_call = &backend.runner.calls[3];
    assert_eq!(apply_call.program, "nft");
    assert_eq!(apply_call.args, ["-f", "-"]);

    let input = apply_call.stdin.as_deref().unwrap();
    assert!(input.contains("add table ip crabnet_nat"));
    assert!(input.contains("counter masquerade"));
  }

  #[tokio::test]
  async fn unchanged_owned_table_is_removed() {
    let snapshot = installed_table(0);
    let fingerprint = normalize_fingerprint(serde_json::from_str(&snapshot).unwrap());
    let applied = AppliedNat { fingerprint };

    let mut backend = backend(vec![
      success(existing_table()),
      success(&installed_table(9)),
      success(""),
    ]);

    backend.revert(&applied).await.unwrap();

    assert_eq!(
      backend.runner.calls[2].args,
      ["delete", "table", "ip", "crabnet_nat"]
    );
  }
  #[tokio::test]
  async fn externally_changed_table_is_not_removed() {
    let expected = normalize_fingerprint(serde_json::from_str(&installed_table(0)).unwrap());

    let changed = r#"{
                                          "nftables": [
                                            {
                                              "table": {
                                                "family": "ip",
                                                "name": "crabnet_nat",
                                                "handle": 1
                                              }
                                            },
                                            {
                                              "chain": {
                                                "family": "ip",
                                                "table": "crabnet_nat",
                                                "name": "external"
                                              }
                                            }
                                          ]
                                        }"#;

    let mut backend = backend(vec![success(existing_table()), success(changed)]);
    let error = backend
      .revert(&AppliedNat {
        fingerprint: expected,
      })
      .await
      .unwrap_err();

    assert!(error
      .to_string()
      .contains("state changed after Crabnet installed it"));
    assert_eq!(backend.runner.calls.len(), 2);
  }

  #[tokio::test]
  async fn command_stderr_is_preserved() {
    let mut backend = backend(vec![failure("permission denied")]);

    let error = backend.apply(&spec()).await.unwrap_err();

    assert!(format!("{error:#}").contains("permission denied"));
  }
}
