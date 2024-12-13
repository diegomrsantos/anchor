use std::task::{Context, Poll};

use discv5::Discv5;
use discv5::libp2p_identity::PeerId;
use discv5::multiaddr::Multiaddr;
use libp2p::core::Endpoint;
use libp2p::core::transport::PortUse;
use libp2p::swarm::{ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm};
use libp2p::swarm::dummy::ConnectionHandler;

pub struct Discovery {
    pub discv5: Discv5,
}

impl NetworkBehaviour for Discovery {
    type ConnectionHandler = ConnectionHandler;
    type ToSwarm = ();

    fn handle_established_inbound_connection(&mut self, _connection_id: ConnectionId, peer: PeerId, local_addr: &Multiaddr, remote_addr: &Multiaddr) -> Result<THandler<Self>, ConnectionDenied> {
        todo!()
    }

    fn handle_established_outbound_connection(&mut self, _connection_id: ConnectionId, peer: PeerId, addr: &Multiaddr, role_override: Endpoint, port_use: PortUse) -> Result<THandler<Self>, ConnectionDenied> {
        todo!()
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {

    }

    fn on_connection_handler_event(&mut self, _peer_id: PeerId, _connection_id: ConnectionId, _event: THandlerOutEvent<Self>) {
        todo!()
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        todo!()
    }
}
