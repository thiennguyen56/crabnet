use anyhow::Context;

use crate::client::{Client, ClientConfig};
use crate::config::{Config, ModeConfig};
use crate::routing::{
  full_tunnel_operations, server_operations, split_tunnel_operations, LinuxRouteBackend,
  RouteManager, TokioCommandRunner,
};
use crate::server::{Server, ServerConfig};

type LinuxRouteManager = RouteManager<LinuxRouteBackend<TokioCommandRunner>>;
type ClientRouteManager = LinuxRouteManager;
type ServerRouteManager = LinuxRouteManager;

pub enum Application {
  Client {
    client: Client,
    routes: ClientRouteManager,
  },
  Server {
    server: Server,
    routing: ServerRouteManager,
  },
}

impl Application {
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
        let config = ServerConfig { bind_addr, tun };
        let server = Server::bind(config).await?;

        let operations = server_operations(&routing);

        let backend = LinuxRouteBackend::new(TokioCommandRunner);

        let mut routing = RouteManager::new(backend);

        routing
          .install(&operations)
          .await
          .context("failed to configure server networking")?;
        Ok(Self::Server { server, routing })
      }
    }
  }

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
      } => {
        let run_result = server.run().await;
        let cleanup_result = routing.restore().await;
        combine_run_and_cleanup("server", run_result, cleanup_result)?;
      }
    }

    Ok(())
  }
}

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
}
