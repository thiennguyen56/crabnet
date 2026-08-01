//! TUN configuration, construction, and packet I/O.
//!
//! Reads receive packets from the local kernel; writes inject packets into it.

use std::net::IpAddr;

use serde::Deserialize;
use tokio::io;
use tun_rs::DeviceBuilder;

/// Configuration required to create one TUN interface.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
  /// Interface name requested from the operating system.
  pub name: String,
  /// IPv4 or IPv6 address assigned to the interface.
  pub address: IpAddr,
  /// Network prefix length matching the address family.
  pub prefix_len: u8,
  /// Maximum packet size accepted by the tunnel.
  pub mtu: u16,
}

impl TunConfig {
  /// Validates the interface name, prefix length, and MTU without creating a
  /// privileged device.
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

/// Async TUN device with the configured MTU retained for write validation.
pub struct TunDevice {
  inner: tun_rs::AsyncDevice,
  mtu: usize,
}

/// Rejects packets larger than the configured TUN MTU.
fn validate_packet_size(size: usize, mtu: usize) -> io::Result<()> {
  if size > mtu {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      format!("packet size {size} exceeds TUN MTU {mtu}"),
    ));
  }

  Ok(())
}

impl TunDevice {
  /// Builds and configures an asynchronous operating-system TUN device.
  ///
  /// This operation generally requires root or CAP_NET_ADMIN on Linux.
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

  /// Reads one raw IP packet from the local operating system into buffer.
  ///
  /// The direction is local OS to Crabnet.
  pub async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
    self.inner.recv(buffer).await
  }

  /// Writes one complete raw IP packet into the local operating system.
  ///
  /// Oversized and partial writes are rejected so callers cannot treat
  /// truncated packets as successful.
  pub async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
    validate_packet_size(packet.len(), self.mtu)?;

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

  /// Returns the configured MTU as a buffer-friendly usize.
  pub fn mtu(&self) -> usize {
    self.mtu
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::{Ipv4Addr, Ipv6Addr};

  fn ipv4_config() -> TunConfig {
    TunConfig {
      name: "crabnet0".to_string(),
      address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
      prefix_len: 24,
      mtu: 1400,
    }
  }

  fn ipv6_config() -> TunConfig {
    TunConfig {
      name: "crabnet0".to_string(),
      address: IpAddr::V6(Ipv6Addr::LOCALHOST),
      prefix_len: 64,
      mtu: 1280,
    }
  }

  #[test]
  fn valid_ipv4_config_is_accepted() {
    assert!(ipv4_config().validate().is_ok());
  }

  #[test]
  fn valid_ipv6_config_is_accepted() {
    assert!(ipv6_config().validate().is_ok());
  }

  #[test]
  fn empty_interface_name_is_rejected() {
    let mut config = ipv4_config();
    config.name.clear();

    let error = config.validate().unwrap_err();

    assert_eq!(error.to_string(), "TUN interface name cannot be empty");
  }

  #[test]
  fn ipv4_prefix_larger_than_32_is_rejected() {
    let mut config = ipv4_config();
    config.prefix_len = 33;

    let error = config.validate().unwrap_err();

    assert_eq!(error.to_string(), "IPv4 prefix must be between 0 and 32");
  }

  #[test]
  fn ipv6_prefix_larger_than_128_is_rejected() {
    let mut config = ipv6_config();
    config.prefix_len = 129;

    let error = config.validate().unwrap_err();

    assert_eq!(error.to_string(), "IPv6 prefix must be between 0 and 128");
  }

  #[test]
  fn ipv6_mtu_smaller_than_1280_is_rejected() {
    let mut config = ipv6_config();
    config.mtu = 1279;

    let error = config.validate().unwrap_err();

    assert_eq!(error.to_string(), "IPv6 TUN MTU must be at least 1280");
  }

  #[test]
  fn zero_ipv4_mtu_is_rejected() {
    let mut config = ipv4_config();
    config.mtu = 0;

    let error = config.validate().unwrap_err();

    assert_eq!(error.to_string(), "TUN MTU cannot be zero");
  }

  #[test]
  fn packet_smaller_than_mtu_is_valid() {
    assert!(validate_packet_size(1399, 1400).is_ok());
  }

  #[test]
  fn packet_equal_to_mtu_is_valid() {
    assert!(validate_packet_size(1400, 1400).is_ok());
  }

  #[test]
  fn packet_larger_than_mtu_is_invalid() {
    let error = validate_packet_size(1401, 1400).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "packet size 1401 exceeds TUN MTU 1400");
  }
}
