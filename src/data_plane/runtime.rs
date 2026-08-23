//! Tokio encrypted V2 forwarding loop.

use anyhow::{anyhow, Context};
use tokio::net::UdpSocket;

use crate::{
  data_plane::{
    crypto::DecryptOutcome,
    frame::{header_binding_bytes, DataFrameCodec},
    session::{EstablishedDataSession, ReplayDecision},
  },
  tun::TunDevice,
};

/// Forwards packets for one committed Noise-IK session until Ctrl-C or a local failure.
pub(crate) async fn run(
  socket: UdpSocket,
  tun: TunDevice,
  codec: DataFrameCodec,
  mut session: EstablishedDataSession,
) -> anyhow::Result<()> {
  if tun.mtu() != codec.maximum_plaintext_payload() {
    return Err(anyhow!(
      "TUN MTU does not match encrypted data codec plaintext limit"
    ));
  }

  let mut tun_buffer = vec![0_u8; tun.mtu() + 1];
  let mut udp_buffer = vec![0_u8; codec.maximum_datagram_length() + 1];
  let shutdown = tokio::signal::ctrl_c();
  tokio::pin!(shutdown);

  loop {
    tokio::select! {
      _ = &mut shutdown => return Ok(()),
      read = tun.read_packet(&mut tun_buffer) => {
        let length = read.context("read encrypted-mode TUN packet")?;
        if length == 0 || length > codec.maximum_plaintext_payload() {
          log::warn!("dropping invalid local TUN packet of {length} bytes");
          continue;
        }
        let sequence = session.allocate_send_sequence().map_err(|error| anyhow!("allocate encrypted send sequence: {error:?}"))?;
        let header = codec.build_data_header(session.metadata.session_id, session.send_direction, sequence, length)
          .map_err(|error| anyhow!("build encrypted data header: {error:?}"))?;
        let header_bytes = header_binding_bytes(&header);
        let ciphertext = session.transport.encrypt(sequence, &header_bytes, &tun_buffer[..length])
          .map_err(|error| anyhow!("encrypt V2 data packet: {error:?}"))?;
        let mut frame = vec![0_u8; codec.maximum_datagram_length()];
        let frame_length = codec.encode_data(header, &ciphertext, &mut frame)
          .map_err(|error| anyhow!("encode encrypted V2 data frame: {error:?}"))?;
        let sent = socket.send_to(&frame[..frame_length], session.peer_endpoint).await
          .with_context(|| format!("send encrypted V2 datagram to {}", session.peer_endpoint))?;
        if sent != frame_length { return Err(anyhow!("partial encrypted UDP send: sent {sent} of {frame_length} bytes")); }
      }
      received = socket.recv_from(&mut udp_buffer) => {
        let (length, source) = received.context("receive encrypted V2 datagram")?;
        if length > codec.maximum_datagram_length() { log::warn!("dropping oversized encrypted datagram from {source}"); continue; }
        let frame = match codec.decode_data(&udp_buffer[..length]) { Ok(frame) => frame, Err(_) => { log::warn!("dropping malformed encrypted datagram from {source}"); continue; } };
        if source != session.peer_endpoint || frame.header().session_id() != session.metadata.session_id { log::warn!("dropping encrypted datagram for an unknown peer"); continue; }
        if frame.header().direction() != session.receive_direction { log::warn!("dropping encrypted datagram with wrong direction"); continue; }
        match session.replay_window.may_attempt(frame.header().sequence()) { ReplayDecision::Acceptable => {}, ReplayDecision::Duplicate | ReplayDecision::TooOld => { log::warn!("dropping replayed encrypted datagram"); continue; } }
        let header_bytes = header_binding_bytes(frame.header());
        let plaintext = match session.transport.decrypt(frame.header().sequence(), &header_bytes, frame.ciphertext()) { DecryptOutcome::Plaintext(plaintext) => plaintext, DecryptOutcome::AuthenticationFailure | DecryptOutcome::HeaderBindingFailure => { log::warn!("dropping unauthenticated encrypted datagram"); continue; } };
        session.replay_window.commit(frame.header().sequence()).map_err(|error| anyhow!("commit encrypted replay state: {error:?}"))?;
        if plaintext.is_empty() || plaintext.len() > codec.maximum_plaintext_payload() { log::warn!("dropping invalid authenticated inner packet"); continue; }
        tun.write_packet(&plaintext).await.context("write decrypted TUN packet")?;
      }
    }
  }
}
