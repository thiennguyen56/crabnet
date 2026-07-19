use std::{net::UdpSocket, time::Duration};

pub struct Client {}

impl Client {
    pub fn new() -> Self {
        Self {}
    }

    pub fn start(&self) -> std::io::Result<()> {
        let socket = UdpSocket::bind("0.0.0.0")?;

        let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));

        let server_addr = "localhost:9001";
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
