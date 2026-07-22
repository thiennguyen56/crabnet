use std::net::IpAddr;

// use anyhow::Ok;
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

pub struct TunDevice {
    inner: tun_rs::AsyncDevice,
    mtu: usize,
    config: TunConfig,
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
            config: (*config).clone(),
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
