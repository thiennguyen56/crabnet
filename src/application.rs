use anyhow::Context;

use crate::client::{Client, ClientConfig};
use crate::config::{Config, ModeConfig};
use crate::routing::{
  client_operations, server_operations, LinuxRouteBackend, RouteManager, TokioCommandRunner,
};
use crate::server::{Server, ServerConfig};

type ClientRouteManager = RouteManager<LinuxRouteBackend<TokioCommandRunner>>;
type ServerRouteManager = RouteManager<LinuxRouteBackend<TokioCommandRunner>>;

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

    if matches!(&mode, ModeConfig::Server { .. })
      && (routing.enable_forwarding || routing.enable_nat)
    {
      log::warn!("Server forwarding and NAT configuration is validated but not applied yet");
    }

    match mode {
      ModeConfig::Client {
        bind_addr,
        server_addr,
      } => {
        let tun_name = tun.name.clone();
        let config = ClientConfig {
          bind_addr,
          server_addr,
          tun,
        };
        let client = Client::bind(config).await?;

        let operations = client_operations(&routing, &tun_name);

        let backend = LinuxRouteBackend::new(TokioCommandRunner);

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
        Ok(Self::Server { server, routing })
      }
    }
  }

  pub async fn run(self) -> anyhow::Result<()> {
    match self {
      Self::Client { client, mut routes } => {
        let run_result = client.run().await;
        let restore_result = routes.restore().await;
        combine_run_and_restore(run_result, restore_result)?
      }
      Self::Server { server, routing: _ } => server.run().await?,
    }

    Ok(())
  }
}

fn combine_run_and_restore(
  run_result: anyhow::Result<()>,
  restore_result: anyhow::Result<()>,
) -> anyhow::Result<()> {
  match (run_result, restore_result) {
    (Ok(()), Ok(())) => Ok(()),

    (Err(run_error), Ok(())) => Err(run_error),

    (Ok(()), Err(restore_error)) => {
      Err(restore_error.context("client stopped but route restoration failed"))
    }

    (Err(run_error), Err(restore_error)) => Err(run_error.context(format!(
      "client also failed to restore routes: \
         {restore_error:#}"
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
    combine_run_and_restore(Ok(()), Ok(())).unwrap();
  }

  #[test]
  fn run_failure_is_preserved_when_restore_succeeds() {
    let error = combine_run_and_restore(failure("run failed"), Ok(())).unwrap_err();
    assert!(format!("{error:#}").contains("run failed"));
  }

  #[test]
  fn restore_failure_is_returned_when_run_succeeds() {
    let error = combine_run_and_restore(Ok(()), failure("restore failed")).unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("client stopped but route restoration failed"));
    assert!(message.contains("restore failed"));
  }

  #[test]
  fn run_and_restore_failures_are_both_preserved() {
    let error =
      combine_run_and_restore(failure("run failed"), failure("restore failed")).unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("run failed"));
    assert!(message.contains("restore failed"));
  }
}
