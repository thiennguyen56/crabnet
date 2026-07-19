use std::net::UdpSocket;

pub struct Server;

impl Server {
    pub fn new() -> Self {
        Self {}
    }

    pub fn start(&self) -> std::io::Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:9001")?;

        log::info!("Server started on 0.0.0.0:9001");

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
