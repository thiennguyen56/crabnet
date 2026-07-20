use super::config::{Config, ModeConfig};
use std::net::UdpSocket;

pub struct Server {
    config: Config,
}

impl Server {
    pub fn new(conf: &Config) -> Self {
        Self {
            config: conf.clone(),
        }
    }

    pub fn start(&self) -> std::io::Result<()> {
        let ModeConfig::Server { bind_addr } = &self.config.mode else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "server requires server mode configuration",
            ));
        };

        let socket = UdpSocket::bind(bind_addr)?;

        log::info!("Server started on {}", bind_addr);

        let mut buf = [0u8; 65535];
        loop {
            let (amt, src) = socket.recv_from(&mut buf)?;

            let message = std::str::from_utf8(&buf[..amt]).unwrap_or("<invalid utf-8>");
            log::info!("Received {} bytes from {}: {}", amt, src, message);

            let response = format!("Echo: {}", message);
            socket.send_to(response.as_bytes(), &src)?;
        }
    }
}
