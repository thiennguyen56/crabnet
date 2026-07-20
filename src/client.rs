use super::config::{Config, ModeConfig};
use std::{net::UdpSocket, time::Duration};

pub struct Client {
    config: Config,
}

impl Client {
    pub fn new(conf: &Config) -> Self {
        Self {
            config: conf.clone(),
        }
    }

    pub fn start(&self) -> std::io::Result<()> {
        let ModeConfig::Client {
            bind_addr,
            server_addr,
        } = &self.config.mode
        else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "client requires client mode configuration",
            ));
        };

        let socket = UdpSocket::bind(bind_addr)?;

        let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));

        let message = "Hello, server!";

        socket.send_to(message.as_bytes(), server_addr)?;
        log::info!("Sent message to {}: {}", server_addr, message);

        let mut buf = [0u8; 65535];
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                let reply = std::str::from_utf8(&buf[..n]).unwrap_or("<invalid>");
                log::info!("Receiving response from backend {}:{}", from, reply);
            }
            Err(e) => {
                log::error!("Receiving error: {}", e);
            }
        }
        Ok(())
    }
}
