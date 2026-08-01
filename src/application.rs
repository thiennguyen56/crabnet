//! Top-level application lifecycle and network-state ownership.
//!
//! Binding creates the endpoint first, resolves any full-tunnel underlay route,
//! and then installs owned networking state. Running always attempts restoration
//! after the forwarding loop stops.

use anyhow::Context;

use crate::client::{Client, ClientConfig};
use crate::config::{Config, ModeConfig};
use crate::nat::{build_nat_spec, LinuxNatBackend, NatManager, TokioNatCommandRunner};
use crate::routing::{
  full_tunnel_operations, server_operations, split_tunnel_operations, LinuxRouteBackend,
  RouteManager, TokioCommandRunner,
};
use crate::server::{Server, ServerConfig};

type LinuxRouteManager = RouteManager<LinuxRouteBackend<TokioCommandRunner>>;
type ClientRouteManager = LinuxRouteManager;
type ServerRouteManager = LinuxRouteManager;
type LinuxNatManager = NatManager<LinuxNatBackend<TokioNatCommandRunner>>;

/// Bound Crabnet endpoint together with the network state it owns.
pub enum Application {
  /// Client forwarding runtime and its installed routes.
  Client {
    /// Connected client endpoint.
    client: Client,
    /// Manager that restores client routes on shutdown.
    routes: ClientRouteManager,
  },
  /// Server forwarding runtime and its installed networking state.
  Server {
    /// Single-peer server endpoint.
    server: Server,
    /// Manager that restores server routes and forwarding state on shutdown.
    routing: ServerRouteManager,

    /// Manager that restores that Crabnet-owned nftables tables.
    nat: LinuxNatManager,
  },
}

impl Application {
  /// Creates the configured endpoint and installs its networking operations.
  ///
  /// Full-tunnel clients resolve the server underlay before installing the
  /// endpoint exclusion and default route. Installation failures are rolled
  /// back by RouteManager.
  pub async fn bind(config: Config) -> anyhow::Result<Self> {
    let Config {
      mode,
      tun,
      log_level: _,
      routing,
    } = config;

    match mode {
      ModeConfig::Client {
        bind_addr,
        server_addr,
      } => {
        let tun_name = tun.name.clone();
        let tun_address = tun.address;

        let config = ClientConfig {
          bind_addr,
          server_addr,
          tun,
        };
        let client = Client::bind(config).await?;

        let mut backend = LinuxRouteBackend::new(TokioCommandRunner);

        let operations = if routing.full_tunnel {
          let underlay = backend
            .resolve_underlay_route(server_addr.ip())
            .await
            .context("failed to resolve VPN server underlay route")?;
          full_tunnel_operations(&tun_name, tun_address, server_addr.ip(), &underlay)?
        } else {
          split_tunnel_operations(&routing, &tun_name)
        };

        let mut routes = RouteManager::new(backend);

        routes
          .install(&operations)
          .await
          .context("failed to install client routes")?;
        Ok(Self::Client { client, routes })
      }

      ModeConfig::Server { bind_addr } => {
        let nat_spec = build_nat_spec(&tun, &routing)?;

        let config = ServerConfig { bind_addr, tun };
        let server = Server::bind(config).await?;

        let mut nat = NatManager::new(LinuxNatBackend::new(TokioNatCommandRunner));

        if let Some(spec) = nat_spec.as_ref() {
          nat
            .install(spec)
            .await
            .context("failed to configure server NAT")?;
        }

        let operations = server_operations(&routing);
        let backend = LinuxRouteBackend::new(TokioCommandRunner);
        let mut routing = RouteManager::new(backend);

        if let Err(routing_error) = routing.install(&operations).await {
          let nat_cleanup = nat.restore().await;

          return match nat_cleanup {
            Ok(()) => Err(routing_error.context("failed to configure server networking")),

            Err(nat_error) => Err(routing_error.context(format!(
              "failed to configure server networking; \
                   NAT rollback also failed: {nat_error:#}"
            ))),
          };
        }

        Ok(Self::Server {
          server,
          routing,
          nat,
        })
      }
    }
  }

  /// Runs packet forwarding and restores all owned network state afterward.
  ///
  /// Cleanup is attempted whether forwarding succeeds or fails. When both fail,
  /// the forwarding error remains primary and cleanup context is attached.
  pub async fn run(self) -> anyhow::Result<()> {
    match self {
      Self::Client { client, mut routes } => {
        let run_result = client.run().await;
        let cleanup_result = routes.restore().await;
        combine_run_and_cleanup("client", run_result, cleanup_result)?
      }
      Self::Server {
        server,
        mut routing,
        mut nat,
      } => {
        let run_result = server.run().await;
        let routing_cleanup = routing.restore().await;

        let nat_cleanup = nat.restore().await;
        let cleanup_result =
          combine_cleanup_results("server routing", routing_cleanup, "server NAT", nat_cleanup);

        combine_run_and_cleanup("server", run_result, cleanup_result)?;
      }
    }

    Ok(())
  }
}

/// Combines two cleanup results without skipping or losing either failure.
fn combine_cleanup_results(
  first_component: &str,
  first: anyhow::Result<()>,
  second_component: &str,
  second: anyhow::Result<()>,
) -> anyhow::Result<()> {
  match (first, second) {
    (Ok(()), Ok(())) => Ok(()),

    (Err(error), Ok(())) => Err(error.context(format!("{first_component} cleanup failed"))),

    (Ok(()), Err(error)) => Err(error.context(format!("{second_component} cleanup failed"))),

    (Err(first_error), Err(second_error)) => Err(first_error.context(format!(
      "{first_component} cleanup failed; \
           {second_component} cleanup also failed: \
           {second_error:#}"
    ))),
  }
}

/// Combines forwarding and cleanup results without losing either failure.
fn combine_run_and_cleanup(
  component: &str,
  run_result: anyhow::Result<()>,
  cleanup_result: anyhow::Result<()>,
) -> anyhow::Result<()> {
  match (run_result, cleanup_result) {
    (Ok(()), Ok(())) => Ok(()),

    (Err(run_error), Ok(())) => Err(run_error),

    (Ok(()), Err(cleanup_error)) => {
      Err(cleanup_error.context(format!("{component} stopped but network cleanup failed")))
    }

    (Err(run_error), Err(cleanup_error)) => Err(run_error.context(format!(
      "{component} also failed to clean up \
         network state: {cleanup_error:#}"
    ))),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn failure(message: &str) -> anyhow::Result<()> {
    Err(anyhow::anyhow!(message.to_owned()))
  }

  #[test]
  fn run_and_restore_success_returns_success() {
    combine_run_and_cleanup("client", Ok(()), Ok(())).unwrap();
  }

  #[test]
  fn run_failure_is_preserved_when_restore_succeeds() {
    let error = combine_run_and_cleanup("client", failure("run failed"), Ok(())).unwrap_err();
    assert!(format!("{error:#}").contains("run failed"));
  }

  #[test]
  fn restore_failure_is_returned_when_run_succeeds() {
    let error = combine_run_and_cleanup("client", Ok(()), failure("restore failed")).unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("client stopped but network cleanup failed"));
    assert!(message.contains("restore failed"));
  }

  #[test]
  fn run_and_restore_failures_are_both_preserved() {
    let error = combine_run_and_cleanup("client", failure("run failed"), failure("restore failed"))
      .unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("run failed"));
    assert!(message.contains("restore failed"));
  }

  #[test]
  fn cleanup_combiner_preserves_both_failures() {
    let error = combine_cleanup_results(
      "routing",
      failure("route cleanup failed"),
      "NAT",
      failure("NAT cleanup failed"),
    )
    .unwrap_err();

    let message = format!("{error:#}");
    assert!(message.contains("route cleanup failed"));
    assert!(message.contains("NAT cleanup failed"));
  }

  #[test]
  fn cleanup_combiner_reports_nat_failure() {
    let error =
      combine_cleanup_results("routing", Ok(()), "NAT", failure("NAT cleanup failed")).unwrap_err();

    let message = format!("{error:#}");
    assert!(message.contains("NAT cleanup failed"));
  }
}
