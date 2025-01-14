use crate::discovery::Discovery;
use crate::peer_manager::PeerManager;
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
    /// The peer manager that keeps track of peer's reputation and status.
    pub peer_manager: PeerManager,
}
