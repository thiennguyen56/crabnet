use anyhow::Ok;

use crate::client::{Client, ClientConfig};
use crate::config::{Config, ModeConfig};
use crate::server::{Server, ServerConfig};
use crate::tun::TunConfig;

pub enum Application {
    Client(Client),
    Server(Server),
}

impl Application {
    pub async fn bind(config: Config) -> anyhow::Result<Self> {
        let Config {
            mode,
            tun,
            log_level: _,
        } = config;

        match mode {
            ModeConfig::Client {
                bind_addr,
                server_addr,
            } => {
                let config = ClientConfig {
                    bind_addr,
                    server_addr,
                    tun: TunConfig {
                        name: tun.name,
                        address: tun.address,
                        prefix_len: tun.prefix_len,
                        mtu: tun.mtu,
                    },
                };
                let client = Client::bind(config).await?;
                Ok(Self::Client(client))
            }

            ModeConfig::Server { bind_addr } => {
                let config = ServerConfig {
                    bind_addr,
                    tun: TunConfig {
                        name: tun.name,
                        address: tun.address,
                        prefix_len: tun.prefix_len,
                        mtu: tun.mtu,
                    },
                };
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
