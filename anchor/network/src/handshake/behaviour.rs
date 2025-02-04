use discv5::libp2p_identity::Keypair;
use discv5::multiaddr::Multiaddr;
use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::request_response::{
    self, Behaviour, Config, Event, OutboundRequestId, ProtocolSupport,
};
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
use crate::handshake::record::signing::{consume_envelope, seal_record};
use crate::handshake::types::NodeInfo;

/// Event emitted on handshake completion or failure.
#[derive(Debug)]
pub enum HandshakeEvent {
    Completed { peer: PeerId, info: NodeInfo },
    Failed { peer: PeerId, error: String },
}

/// Trait for updating peer information.
pub trait PeerInfoStore: Send + Sync {
    fn update(&self, peer: PeerId, f: impl FnOnce(&mut PeerInfo));
}

/// Trait for updating peer subnets.
pub trait SubnetsIndex: Send + Sync {
    fn update_peer_subnets(&self, peer: PeerId, subnets: Subnets);
}

/// Information about a peer.
#[derive(Clone, Debug, Default)]
pub struct PeerInfo {
    pub last_handshake: Option<Instant>,
    pub last_error: Option<String>,
}

/// Subnets type (example implementation).
#[derive(Clone, Debug, Default)]
pub struct Subnets;

impl Subnets {
    pub fn from_str(s: &str) -> Result<Self, Box<dyn Error>> {
        // Parse subnets from string
        Ok(Subnets)
    }
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
    /// Filters to apply on received node info.
    //filters: Vec<Box<dyn Fn(PeerId, &NodeInfo) -> Result<(), Box<dyn Error>> + Send + Sync>>,
    /// Peer info storage.
    //peer_info: Arc<P>,
    /// Subnets index.
    //subnets_index: Arc<S>,
    /// Events to emit.
    events: Vec<HandshakeEvent>,
}

//impl<S, P> HandshakeBehaviour<S, P>
impl HandshakeBehaviour
// where
//     P: PeerInfoStore,
//     S: SubnetsIndex,
{
    pub fn new(
        keypair: Keypair,
        local_node_info: Arc<Mutex<NodeInfo>>,
        // peer_info: Arc<P>,
        // subnets_index: Arc<S>,
        // filters: Vec<Box<dyn Fn(PeerId, &NodeInfo) -> Result<(), Box<dyn Error>> + Send + Sync>>,
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
            // filters,
            // peer_info,
            // subnets_index,
            events: Vec::new(),
        }
    }

    /// Create a signed envelope containing local node info.
    fn sealed_node_record(&self) -> Envelope {
        let node_info = self.local_node_info.lock().unwrap().clone();
        seal_record(&node_info, &self.keypair).unwrap()
    }

    /// Verify an incoming envelope and apply filters.
    fn verify_envelope(
        &mut self,
        envelope: &Envelope,
        peer: PeerId,
    ) -> Result<NodeInfo, Box<dyn Error>> {
        let (_, mut node_info) = consume_envelope::<NodeInfo>(&envelope.encode_to_vec()?)?;

        // Apply all filters
        // for filter in &self.filters {
        //     filter(peer, &node_info)?;
        // }

        // Update peer info
        // self.peer_info.update(peer, |info| {
        //     info.last_handshake = Some(Instant::now());
        //     info.last_error = None;
        // });

        // Update subnets
        // if let Ok(subnets) = Subnets::from_str(node_info.metadata.subnets.as_str()) {
        //     self.subnets_index.update_peer_subnets(peer, subnets);
        // }

        Ok(node_info)
    }
}

impl NetworkBehaviour for HandshakeBehaviour
//impl<S, P> NetworkBehaviour for HandshakeBehaviour<S, P>
// where
//     P: PeerInfoStore,
//     S: SubnetsIndex,
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
                        // Handle incoming request: send response then verify
                        let response = self.sealed_node_record();
                        match self.behaviour.send_response(channel, response) {
                            Ok(_) => {}
                            Err(e) => {
                                self.events.push(HandshakeEvent::Failed {
                                    peer,
                                    error: "error".to_string(),
                                });
                            }
                        }

                        match self.verify_envelope(&request, peer) {
                            Ok(info) => self.events.push(HandshakeEvent::Completed { peer, info }),
                            Err(e) => self.events.push(HandshakeEvent::Failed {
                                peer,
                                error: "error".to_string(),
                            }),
                        }
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
                        // Handle outgoing response
                        if let Some(peer) = self.pending_handshakes.remove(&request_id) {
                            debug!(?response, "Received handshake response");
                            match self.verify_envelope(&response, peer) {
                                Ok(info) => {
                                    self.events.push(HandshakeEvent::Completed { peer, info })
                                }
                                Err(e) => self.events.push(HandshakeEvent::Failed {
                                    peer,
                                    error: "error".to_string(),
                                }),
                            }
                        }
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
                ToSwarm::Dial { opts } => return Poll::Ready(ToSwarm::Dial { opts }),
                ToSwarm::NotifyHandler {
                    peer_id,
                    handler,
                    event,
                } => {
                    return Poll::Ready(ToSwarm::NotifyHandler {
                        peer_id,
                        handler,
                        event,
                    });
                }
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
