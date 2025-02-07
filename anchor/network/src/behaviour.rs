use crate::discovery::Discovery;
use libp2p::request_response::Behaviour;
use crate::handshake::behaviour::Behaviour;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{gossipsub, identify, ping};

#[derive(NetworkBehaviour)]
pub struct AnchorBehaviour {
    /// Provides IP addresses and peer information.
    pub identify: identify::Behaviour,
    /// Used for connection health checks.
    pub ping: ping::Behaviour,
    /// The routing pub-sub mechanism for Anchor.
    pub gossipsub: gossipsub::Behaviour,
    /// Discv5 Discovery protocol.
    pub discovery: Discovery,

    pub handshake: Behaviour,
}
