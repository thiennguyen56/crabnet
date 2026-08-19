use crate::crypto::client::ClientHandshakeCrypto;
use crate::crypto::noise_ik::{
  profile::{
    CLIENT_FINISH_PAYLOAD_LENGTH, CLIENT_HELLO_PAYLOAD_LENGTH, SERVER_FINISH_PAYLOAD_LENGTH,
    SERVER_HELLO_PAYLOAD_LENGTH,
  },
  types::NoiseIkPayload,
};
use crate::crypto::server::ServerHandshakeCrypto;
use crate::handshake::{
  client::ClientHandshakeCoordinator,
  server::ServerHandshakeCoordinator,
  types::{
    ClientCoordinatorEvent, ClientHandshakeMessage, ServerCoordinatorEvent, ServerHandshakeMessage,
  },
};
use crate::protocol::types::MessageType;
use crate::protocol::v2::{
  classify_for_client, classify_for_server, ClientInboundFrame, DecodedV2HandshakeBody,
  DirectionError, ServerInboundFrame, V2DecodeError, V2EncodeError, V2HandshakeCodec,
};
use crate::session::types::ClientAttemptId;
use std::net::SocketAddr;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdapterError {
  Decode(V2DecodeError),
  Direction(DirectionError),
  PayloadLength {
    message_type: MessageType,
    expected: usize,
    observed: usize,
  },
  Coordinator(Box<crate::handshake::types::FatalCoordinatorError>),
  Encode(V2EncodeError),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientAdapterReport {
  pub(crate) datagrams: Vec<Vec<u8>>,
  pub(crate) events: Vec<ClientCoordinatorEvent>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerAdapterDatagram {
  pub(crate) destination: SocketAddr,
  pub(crate) datagram: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerAdapterReport {
  pub(crate) datagrams: Vec<ServerAdapterDatagram>,
  pub(crate) events: Vec<ServerCoordinatorEvent>,
}
fn body_payload(
  body: DecodedV2HandshakeBody<'_>,
  message_type: MessageType,
) -> Result<NoiseIkPayload, AdapterError> {
  let expected = match message_type {
    MessageType::ClientHello => CLIENT_HELLO_PAYLOAD_LENGTH,
    MessageType::ServerHello => SERVER_HELLO_PAYLOAD_LENGTH,
    MessageType::ClientFinish => CLIENT_FINISH_PAYLOAD_LENGTH,
    MessageType::ServerFinish => SERVER_FINISH_PAYLOAD_LENGTH,
    MessageType::Data => 0,
  };
  let observed = body.opaque_payload().len();
  if observed != expected {
    return Err(AdapterError::PayloadLength {
      message_type,
      expected,
      observed,
    });
  }
  Ok(NoiseIkPayload(
    body.opaque_payload().to_vec().into_boxed_slice(),
  ))
}
fn encode(
  codec: &V2HandshakeCodec,
  kind: MessageType,
  attempt: ClientAttemptId,
  payload: NoiseIkPayload,
) -> Result<Vec<u8>, AdapterError> {
  let mut output = vec![0_u8; codec.max_datagram_len()];
  let length = codec
    .encode(kind, attempt, &payload.0, &mut output)
    .map_err(AdapterError::Encode)?;
  output.truncate(length);
  Ok(output)
}
pub(crate) fn start_client_frame<C>(
  coordinator: &mut ClientHandshakeCoordinator<C>,
  codec: &V2HandshakeCodec,
  now: Instant,
) -> Result<ClientAdapterReport, AdapterError>
where
  C: ClientHandshakeCrypto<
    ClientHelloPayload = NoiseIkPayload,
    ServerHelloPayload = NoiseIkPayload,
    ClientFinishPayload = NoiseIkPayload,
    ServerFinishPayload = NoiseIkPayload,
  >,
{
  let report = coordinator
    .start(now)
    .map_err(|error| AdapterError::Coordinator(Box::new(error)))?;
  let mut datagrams = Vec::with_capacity(report.outbound.len());
  for message in report.outbound {
    let (kind, attempt, payload) = match message {
      ClientHandshakeMessage::ClientHello(value) => (
        MessageType::ClientHello,
        value.client_attempt_id,
        value.payload,
      ),
      ClientHandshakeMessage::ClientFinish(value) => (
        MessageType::ClientFinish,
        value.client_attempt_id,
        value.payload,
      ),
    };
    datagrams.push(encode(codec, kind, attempt, payload)?);
  }
  Ok(ClientAdapterReport {
    datagrams,
    events: report.events,
  })
}
pub(crate) fn receive_client_frame<C>(
  coordinator: &mut ClientHandshakeCoordinator<C>,
  codec: &V2HandshakeCodec,
  source: SocketAddr,
  datagram: &[u8],
  now: Instant,
) -> Result<ClientAdapterReport, AdapterError>
where
  C: ClientHandshakeCrypto<
    ClientHelloPayload = NoiseIkPayload,
    ServerHelloPayload = NoiseIkPayload,
    ClientFinishPayload = NoiseIkPayload,
    ServerFinishPayload = NoiseIkPayload,
  >,
{
  let frame = codec.decode(datagram).map_err(AdapterError::Decode)?;
  let inbound = classify_for_client(frame).map_err(AdapterError::Direction)?;
  let report = match inbound {
    ClientInboundFrame::ServerHello(body) => coordinator.receive_server_hello(
      source,
      crate::handshake::types::ServerHello {
        client_attempt_id: body.client_attempt_id(),
        payload: body_payload(body, MessageType::ServerHello)?,
      },
      now,
    ),
    ClientInboundFrame::ServerFinish(body) => coordinator.receive_server_finish(
      source,
      crate::handshake::types::ServerFinish {
        client_attempt_id: body.client_attempt_id(),
        payload: body_payload(body, MessageType::ServerFinish)?,
      },
      now,
    ),
  }
  .map_err(|error| AdapterError::Coordinator(Box::new(error)))?;
  let mut datagrams = Vec::with_capacity(report.outbound.len());
  for message in report.outbound {
    let (kind, attempt, payload) = match message {
      ClientHandshakeMessage::ClientHello(value) => (
        MessageType::ClientHello,
        value.client_attempt_id,
        value.payload,
      ),
      ClientHandshakeMessage::ClientFinish(value) => (
        MessageType::ClientFinish,
        value.client_attempt_id,
        value.payload,
      ),
    };
    datagrams.push(encode(codec, kind, attempt, payload)?);
  }
  Ok(ClientAdapterReport {
    datagrams,
    events: report.events,
  })
}
pub(crate) fn receive_server_frame<C>(
  coordinator: &mut ServerHandshakeCoordinator<C>,
  codec: &V2HandshakeCodec,
  source: SocketAddr,
  datagram: &[u8],
  now: Instant,
) -> Result<ServerAdapterReport, AdapterError>
where
  C: ServerHandshakeCrypto<
    ClientHelloPayload = NoiseIkPayload,
    ServerHelloPayload = NoiseIkPayload,
    ClientFinishPayload = NoiseIkPayload,
    ServerFinishPayload = NoiseIkPayload,
  >,
{
  let frame = codec.decode(datagram).map_err(AdapterError::Decode)?;
  let inbound = classify_for_server(frame).map_err(AdapterError::Direction)?;
  let report = match inbound {
    ServerInboundFrame::ClientHello(body) => coordinator.receive_client_hello(
      source,
      crate::handshake::types::ClientHello {
        client_attempt_id: body.client_attempt_id(),
        payload: body_payload(body, MessageType::ClientHello)?,
      },
      now,
    ),
    ServerInboundFrame::ClientFinish(body) => coordinator.receive_client_finish(
      source,
      crate::handshake::types::ClientFinish {
        client_attempt_id: body.client_attempt_id(),
        payload: body_payload(body, MessageType::ClientFinish)?,
      },
      now,
    ),
  }
  .map_err(|error| AdapterError::Coordinator(Box::new(error)))?;
  let mut datagrams = Vec::with_capacity(report.outbound.len());
  for outbound in report.outbound {
    let (kind, attempt, payload) = match outbound.message {
      ServerHandshakeMessage::ServerHello(value) => (
        MessageType::ServerHello,
        value.client_attempt_id,
        value.payload,
      ),
      ServerHandshakeMessage::ServerFinish(value) => (
        MessageType::ServerFinish,
        value.client_attempt_id,
        value.payload,
      ),
    };
    datagrams.push(ServerAdapterDatagram {
      destination: outbound.destination,
      datagram: encode(codec, kind, attempt, payload)?,
    });
  }
  Ok(ServerAdapterReport {
    datagrams,
    events: report.events,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn exact_profile_sizes_are_enforced_before_dispatch() {
    let codec = V2HandshakeCodec::new(CLIENT_HELLO_PAYLOAD_LENGTH).unwrap();
    let payload = vec![0_u8; CLIENT_HELLO_PAYLOAD_LENGTH - 1];
    let mut frame = vec![0_u8; codec.max_datagram_len()];
    let length = codec
      .encode(
        MessageType::ClientHello,
        ClientAttemptId(1),
        &payload,
        &mut frame,
      )
      .unwrap();
    let decoded = codec.decode(&frame[..length]).unwrap();
    let body = match classify_for_server(decoded).unwrap() {
      ServerInboundFrame::ClientHello(body) => body,
      _ => unreachable!(),
    };
    assert!(matches!(
      body_payload(body, MessageType::ClientHello),
      Err(AdapterError::PayloadLength {
        expected: CLIENT_HELLO_PAYLOAD_LENGTH,
        ..
      })
    ));
  }

  #[test]
  fn valid_payload_is_owned() {
    let codec = V2HandshakeCodec::new(SERVER_FINISH_PAYLOAD_LENGTH).unwrap();
    let input = vec![7_u8; SERVER_FINISH_PAYLOAD_LENGTH];
    let mut frame = vec![0_u8; codec.max_datagram_len()];
    let length = codec
      .encode(
        MessageType::ServerFinish,
        ClientAttemptId(1),
        &input,
        &mut frame,
      )
      .unwrap();
    let decoded = codec.decode(&frame[..length]).unwrap();
    let body = match classify_for_client(decoded).unwrap() {
      ClientInboundFrame::ServerFinish(body) => body,
      _ => unreachable!(),
    };
    let payload = body_payload(body, MessageType::ServerFinish).unwrap();
    assert_eq!(payload.0.as_ref(), input.as_slice());
  }
}
