pub mod node_info;
mod envelope;
mod error;

use discv5::libp2p_identity::Keypair;
use discv5::multiaddr::Multiaddr;
use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::request_response::{self, Behaviour as RequestResponseBehaviour, Config, Event as RequestResponseEvent, OutboundRequestId, ProtocolSupport, ResponseChannel};
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
use crate::handshake::envelope::{Envelope};
use crate::handshake::envelope::Codec;
use crate::handshake::error::HandshakeError;
use crate::handshake::node_info::NodeInfo;

pub trait NodeInfoProvider: Send + Sync {
    /// Returns a clone of the current node information.
    fn get_node_info(&self) -> NodeInfo;
}

/// Event emitted on handshake completion or failure.
#[derive(Debug)]
pub enum Event {
    Completed { peer_id: PeerId, their_info: NodeInfo },
    Failed { peer_id: PeerId, error: HandshakeError },
}

/// Network behaviour handling the handshake protocol.
pub struct Behaviour {
    /// Request-response behaviour for the handshake protocol.
    behaviour: RequestResponseBehaviour<Codec>,
    /// Keypair for signing envelopes.
    keypair: Keypair,
    /// Local node's information provider.
    node_info_provider: Box<dyn NodeInfoProvider>,
    /// Events to emit.
    events: Vec<Event>,
}

impl Behaviour
{
    pub fn new(
        keypair: Keypair,
        local_node_info: Box<dyn NodeInfoProvider>,
    ) -> Self {
        // NodeInfoProtocol is the protocol.ID used for handshake
        const NODE_INFO_PROTOCOL: &'static str = "/ssv/info/0.0.1";

        let protocol = StreamProtocol::new(NODE_INFO_PROTOCOL);
        let behaviour = RequestResponseBehaviour::new([(protocol, ProtocolSupport::Full)], Config::default());

        Self {
            behaviour,
            keypair,
            node_info_provider: local_node_info,
            events: Vec::new(),
        }
    }

    /// Create a signed envelope containing local node info.
    fn sealed_node_record(&self) -> Envelope {
        let node_info = self.node_info_provider.get_node_info();
        node_info.seal(&self.keypair).unwrap()
    }

    /// Verify an incoming envelope and apply filters.
    fn verify_node_info(
        &mut self,
        node_info: &NodeInfo,
        peer: PeerId,
    ) -> Result<(), HandshakeError> {
        let ours = self.node_info_provider.get_node_info().network_id;
        if node_info.network_id != *ours {
            return Err(HandshakeError::NetworkMismatch { ours, theirs: node_info.network_id.clone()})
        }
        Ok(())
    }

    fn handle_handshake_request(&mut self, peer_id: PeerId, request: Envelope, channel: ResponseChannel<Envelope>) {
        // Handle incoming request: send response then verify
        let response = self.sealed_node_record();
        match self.behaviour.send_response(channel, response.clone()) {
            Ok(_) => {
                self.unmarshall_and_verify(peer_id, &response);
            }
            Err(e) => {
                // There was an error sending the response. The InboundFailure handler will be called
            }
        }
    }

    fn handle_handshake_response(&mut self, peer_id: PeerId, request_id: &OutboundRequestId, response: &Envelope) {
        self.unmarshall_and_verify(peer_id, &response);
    }

    fn unmarshall_and_verify(&mut self, peer_id: PeerId, response: &Envelope) {
        let mut their_info = NodeInfo::default();

        if let Err(e) = their_info.unmarshal(&response.payload) {
            self.events.push(Event::Failed {
                peer_id,
                error: HandshakeError::UnmarshalError(e),
            });
        }

        match self.verify_node_info(&their_info, peer_id) {
            Ok(_) => self.events.push(Event::Completed { peer_id, their_info }),
            Err(e) => self.events.push(Event::Failed {
                peer_id,
                error: e,
            }),
        }
    }
}

impl NetworkBehaviour for Behaviour
{
    type ConnectionHandler = <RequestResponseBehaviour<Codec> as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = Event;

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
            self.behaviour.send_request(&peer, request);
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
                    RequestResponseEvent::Message {
                        peer,
                        message:
                        request_response::Message::Request {
                            request, channel, ..
                        },
                    } => {
                        debug!("Received handshake request");
                        self.handle_handshake_request(peer, request, channel);
                    }
                    RequestResponseEvent::Message {
                        peer,
                        message:
                        request_response::Message::Response {
                            request_id,
                            response,
                            ..
                        },
                    } => {
                        debug!(?response, "Received handshake response");
                        self.handle_handshake_response(peer, &request_id, &response);
                    }
                    RequestResponseEvent::OutboundFailure {
                        request_id,
                        peer,
                        error,
                        ..
                    } => {
                        self.events.push(Event::Failed {
                            peer_id: peer,
                            error: HandshakeError::Outbound(error),
                        });
                    }
                    RequestResponseEvent::InboundFailure { peer, error, .. } => {
                        self.events.push(Event::Failed {
                            peer_id: peer,
                            error: HandshakeError::Inbound(error),
                        });
                    }
                    _ => {}
                },
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
