use tun_rs::DeviceBuilder;

use crate::config::Config;

pub struct Tun {
    config: Config,
}

pub trait TunTrait {
    fn new(conf: &Config) -> Self;
}

impl Tun {
    pub fn new(conf: &Config) -> Self {
        Self {
            config: conf.clone(),
        }
    }

    pub fn start(&self) -> std::io::Result<()> {
        let dev = DeviceBuilder::new()
            .ipv4(self.config.tun.address, 24, None)
            .mtu(1400)
            .build_sync()?;

        let mut buf = [0; 1400];
        log::info!("TUN interface created successfully");

        loop {
            let amount = dev.recv(&mut buf)?;
            let packet = &buf[..amount];
            println!("Received packet size: {} bytes", amount);
            println!("Raw packet bytes: {:?}", packet);
        }
    }
}
