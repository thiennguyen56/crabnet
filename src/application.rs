use crate::client::{Client, ClientConfig};
use crate::config::{Config, ModeConfig};
use crate::routing::RoutingConfig;
use crate::server::{Server, ServerConfig};

pub enum Application {
  Client(Client),
  Server(Server),
}

impl Application {
  pub async fn bind(config: Config) -> anyhow::Result<Self> {
    if config.routing != RoutingConfig::default() {
      log::warn!(
        "Routing configuration is validated but not applied yet; automatic route, forwarding, and NAT setup will be added in the next Milestone 2 step"
      );
    }

    let Config {
      mode,
      tun,
      log_level: _,
      routing: _,
    } = config;

    match mode {
      ModeConfig::Client {
        bind_addr,
        server_addr,
      } => {
        let config = ClientConfig {
          bind_addr,
          server_addr,
          tun,
        };
        let client = Client::bind(config).await?;
        Ok(Self::Client(client))
      }

      ModeConfig::Server { bind_addr } => {
        let config = ServerConfig { bind_addr, tun };
        let server = Server::bind(config).await?;
        Ok(Self::Server(server))
      }
    }
  }

  pub async fn run(self) -> anyhow::Result<()> {
    match self {
      Self::Client(client) => client.run().await?,
      Self::Server(server) => server.run().await?,
    }

    Ok(())
  }
}
