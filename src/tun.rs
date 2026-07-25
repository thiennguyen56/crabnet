use std::net::IpAddr;

use serde::Deserialize;
use tokio::io;
use tun_rs::DeviceBuilder;

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    pub name: String,
    pub address: IpAddr,
    pub prefix_len: u8,
    pub mtu: u16,
}

impl TunConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.name.is_empty() {
            anyhow::bail!("TUN interface name cannot be empty")
        }
        match self.address {
            IpAddr::V4(_) if self.prefix_len > 32 => {
                anyhow::bail!("IPv4 prefix must be between 0 and 32")
            }
            IpAddr::V6(_) if self.prefix_len > 128 => {
                anyhow::bail!("IPv6 prefix must be between 0 and 128")
            }
            _ => {}
        }
        if self.address.is_ipv6() && self.mtu < 1280 {
            anyhow::bail!("IPv6 TUN MTU must be at least 1280")
        }
        if self.mtu == 0 {
            anyhow::bail!("TUN MTU cannot be zero")
        }
        Ok(())
    }
}

pub struct TunDevice {
    inner: tun_rs::AsyncDevice,
    mtu: usize,
}

impl TunDevice {
    pub fn create(config: &TunConfig) -> anyhow::Result<Self> {
        let mut builder = DeviceBuilder::new().name(&config.name).mtu(config.mtu);

        builder = match config.address {
            IpAddr::V4(address) => builder.ipv4(address, config.prefix_len, None),
            IpAddr::V6(address) => builder.ipv6(address, config.prefix_len),
        };

        let inner = builder.build_async()?;

        Ok(Self {
            inner,
            mtu: config.mtu as usize,
        })
    }

    pub async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.recv(buffer).await
    }

    pub async fn send(&self, packet: &[u8]) -> io::Result<()> {
        if packet.len() > self.mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("packet size {} exceeds TUN MTU {}", packet.len(), self.mtu,),
            ));
        }

        let written = self.inner.send(packet).await?;

        if written != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "partial TUN write: wrote {written} of {} bytes",
                    packet.len(),
                ),
            ));
        }

        Ok(())
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }
}
