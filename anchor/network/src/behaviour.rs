use discv5::libp2p_identity::PeerId;
use crate::discovery::Discovery;
use crate::handshake::behaviour::{HandshakeBehaviour, PeerInfo, PeerInfoStore, Subnets, SubnetsIndex};
use libp2p::request_response::Behaviour;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{gossipsub, identify, ping, request_response};

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

    pub handshake: HandshakeBehaviour,
}

#[derive(Default)]
struct DummyPeerInfoStore {}
impl PeerInfoStore for DummyPeerInfoStore {
    fn update(&self, peer: PeerId, f: impl FnOnce(&mut PeerInfo)) {

    }
}

#[derive(Default)]
struct DummySubnetsIndex {}
impl SubnetsIndex for DummySubnetsIndex {
    fn update_peer_subnets(&self, peer: PeerId, subnets: Subnets) {

    }
}