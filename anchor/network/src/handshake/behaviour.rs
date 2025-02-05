use discv5::libp2p_identity::Keypair;
use discv5::multiaddr::Multiaddr;
use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::request_response::{self, Behaviour, Config, Event, OutboundRequestId, ProtocolSupport, ResponseChannel};
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{PeerId, StreamProtocol};
use prost::Message;
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;
use tracing::debug;
use crate::handshake::codec::EnvelopeCodec;
use crate::handshake::record::envelope::Envelope;
use crate::handshake::record::signing::{parse_envelope};
use crate::handshake::types::NodeInfo;

/// Event emitted on handshake completion or failure.
#[derive(Debug)]
pub enum HandshakeEvent {
    Completed { peer: PeerId, their_info: NodeInfo },
    Failed { peer: PeerId, error: String },
}

/// Network behaviour handling the handshake protocol.
pub struct HandshakeBehaviour {
    /// Request-response behaviour for the handshake protocol.
    behaviour: Behaviour<EnvelopeCodec>,
    /// Pending outgoing handshake requests.
    pending_handshakes: HashMap<OutboundRequestId, PeerId>,
    /// Keypair for signing envelopes.
    keypair: Keypair,
    /// Local node's information.
    local_node_info: Arc<Mutex<NodeInfo>>,
    /// Events to emit.
    events: Vec<HandshakeEvent>,
}

impl HandshakeBehaviour
{
    pub fn new(
        keypair: Keypair,
        local_node_info: Arc<Mutex<NodeInfo>>,
    ) -> Self {
        // NodeInfoProtocol is the protocol.ID used for handshake
        const NODE_INFO_PROTOCOL: &'static str = "/ssv/info/0.0.1";

        let protocol = StreamProtocol::new(NODE_INFO_PROTOCOL);
        let behaviour = Behaviour::new([(protocol, ProtocolSupport::Full)], Config::default());

        Self {
            behaviour: behaviour,
            pending_handshakes: HashMap::new(),
            keypair,
            local_node_info,
            events: Vec::new(),
        }
    }

    /// Create a signed envelope containing local node info.
    fn sealed_node_record(&self) -> Envelope {
        let node_info = self.local_node_info.lock().unwrap().clone();
        node_info.seal(&self.keypair).unwrap()
    }

    /// Verify an incoming envelope and apply filters.
    fn verify_node_info(
        &mut self,
        node_info: &NodeInfo,
        peer: PeerId,
    ) -> Result<(), Box<dyn Error>> {

        if node_info.network_id != self.local_node_info.lock().unwrap().network_id {
            return Err("network id mismatch".into())
        }

        Ok(())
    }

    fn handle_handshake_request(&mut self, peer: PeerId, channel: ResponseChannel<Envelope>) {
        // Handle incoming request: send response then verify
        let response = self.sealed_node_record();
        match self.behaviour.send_response(channel, response.clone()) {
            Ok(_) => {}
            Err(e) => {
                self.events.push(HandshakeEvent::Failed {
                    peer,
                    error: "error".to_string(),
                });
            }
        }
        let mut their_info = NodeInfo::default();
        their_info.unmarshal_record(&response.payload);
        match self.verify_node_info(&their_info, peer) {
            Ok(_) => self.events.push(HandshakeEvent::Completed { peer, their_info }),
            Err(e) => self.events.push(HandshakeEvent::Failed {
                peer,
                error: "error".to_string(),
            }),
        }
    }

    fn handle_handshake_response(&mut self, request_id: &OutboundRequestId, response: &Envelope) {
        // Handle outgoing response
        if let Some(peer) = self.pending_handshakes.remove(&request_id) {
            let mut their_info = NodeInfo::default();
            their_info.unmarshal_record(&response.payload);

            match self.verify_node_info(&their_info, peer) {
                Ok(_) => {
                    debug!(?their_info, "Handshake completed");
                    self.events.push(HandshakeEvent::Completed { peer, their_info })
                }
                Err(e) => {
                    self.events.push(HandshakeEvent::Failed {
                        peer,
                        error: "error".to_string(),
                    });
                    debug!(?e, "Handshake failed");
                },
            }
        }
    }
}

impl NetworkBehaviour for HandshakeBehaviour
{
    type ConnectionHandler = <Behaviour<EnvelopeCodec> as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = HandshakeEvent;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.behaviour.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.behaviour.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        // Initiate handshake on new connection
        if let FromSwarm::ConnectionEstablished(conn_est) = &event {
            let peer = conn_est.peer_id;
            let request = self.sealed_node_record();
            let request_id = self.behaviour.send_request(&peer, request);
            self.pending_handshakes.insert(request_id, peer);
        }

        // Delegate other events to inner behaviour
        self.behaviour.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.behaviour
            .on_connection_handler_event(peer_id, connection_id, event);
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        // Process events from inner request-response behaviour
        while let Poll::Ready(event) = self.behaviour.poll(cx) {
            match event {
                ToSwarm::GenerateEvent(event) => match event {
                    Event::Message {
                        peer,
                        message:
                            request_response::Message::Request {
                                request, channel, ..
                            },
                    } => {
                        debug!("Received handshake request");
                        self.handle_handshake_request(peer, channel);
                    }
                    Event::Message {
                        message:
                            request_response::Message::Response {
                                request_id,
                                response,
                                ..
                            },
                        ..
                    } => {
                        debug!(?response, "Received handshake response");
                        self.handle_handshake_response(&request_id, &response);
                    }
                    Event::OutboundFailure {
                        request_id,
                        peer,
                        error,
                        ..
                    } => {
                        if let Some(peer) = self.pending_handshakes.remove(&request_id) {
                            self.events.push(HandshakeEvent::Failed {
                                peer,
                                error: format!("Outbound failure: {error}"),
                            });
                            debug!(?error, "Outbound failure");
                        }
                    }
                    Event::InboundFailure { peer, error, .. } => {
                        self.events.push(HandshakeEvent::Failed {
                            peer,
                            error: format!("Inbound failure: {error}"),
                        });
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        // Emit queued events
        if !self.events.is_empty() {
            return Poll::Ready(ToSwarm::GenerateEvent(self.events.remove(0)));
        }

        Poll::Pending
    }
}
