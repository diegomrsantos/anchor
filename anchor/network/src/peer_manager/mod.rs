mod network_behaviour;
mod peerdb;

use crate::peer_manager::peerdb::PeerDB;
use delay_map::HashSetDelay;
use discv5::libp2p_identity::PeerId;
use discv5::multiaddr::Multiaddr;
use discv5::Enr;
use lighthouse_network::peer_manager::config::Config;
use lighthouse_network::rpc::GoodbyeReason;
use lighthouse_network::{metrics, EnrExt, SubnetDiscovery};
use parking_lot::RwLock;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::{debug, error};

/// The heartbeat performs regular updates such as updating reputations and performing discovery
/// requests. This defines the interval in seconds.
const HEARTBEAT_INTERVAL: u64 = 30;

/// A fraction of `PeerManager::target_peers_count` that we allow to connect to us in excess of
/// `PeerManager::target_peers_count`. For clarity, if `PeerManager::target_peers_count` is 50 and
/// PEER_EXCESS_FACTOR = 0.1 we allow 10% more nodes, i.e 55.
pub const PEER_EXCESS_FACTOR: f32 = 0.1;

/// A fraction of `PeerManager::target_peers` that we want to be outbound-only connections.
pub const TARGET_OUTBOUND_ONLY_FACTOR: f32 = 0.3;

/// A fraction of `PeerManager::target_peers` that if we get below, we start a discovery query to
/// reach our target. MIN_OUTBOUND_ONLY_FACTOR must be < TARGET_OUTBOUND_ONLY_FACTOR.
pub const MIN_OUTBOUND_ONLY_FACTOR: f32 = 0.2;

/// The fraction of extra peers beyond the PEER_EXCESS_FACTOR that we allow us to dial for when
/// requiring subnet peers. More specifically, if our target peer limit is 50, and our excess peer
/// limit is 55, and we are at 55 peers, the following parameter provisions a few more slots of
/// dialing priority peers we need for validator duties.
pub const PRIORITY_PEER_EXCESS: f32 = 0.2;

pub struct PeerManager {
    /// The target number of peers we would like to connect to.
    target_peers_count: usize,
    /// Peers queued to be dialed.
    peers_to_dial: Vec<Enr>,
    /// A queue of events that the `PeerManager` is waiting to produce.
    events: SmallVec<[PeerManagerEvent; 16]>,
    /// A collection of inbound-connected peers awaiting to be Ping'd.
    inbound_ping_peers: HashSetDelay<PeerId>,
    /// A collection of outbound-connected peers awaiting to be Ping'd.
    outbound_ping_peers: HashSetDelay<PeerId>,
    /// A collection of peers awaiting to be Status'd.
    status_peers: HashSetDelay<PeerId>,
    /// The collection of known peers.
    pub peers: RwLock<PeerDB>,
    /// The heartbeat interval to perform routine maintenance.
    heartbeat: tokio::time::Interval,
    /// Keeps track of whether the discovery service is enabled or not.
    discovery_enabled: bool,
    /// Keeps track of whether the QUIC protocol is enabled or not.
    quic_enabled: bool,
}

/// The events that the `PeerManager` outputs (requests).
#[derive(Debug)]
pub enum PeerManagerEvent {
    /// A peer has dialed us.
    PeerConnectedIncoming(PeerId),
    /// A peer has been dialed.
    PeerConnectedOutgoing(PeerId),
    /// A peer has disconnected.
    PeerDisconnected(PeerId),
    /// Sends a STATUS to a peer.
    Status(PeerId),
    /// Sends a PING to a peer.
    Ping(PeerId),
    /// Request METADATA from a peer.
    MetaData(PeerId),
    /// The peer should be disconnected.
    DisconnectPeer(PeerId, GoodbyeReason),
    /// Inform the behaviour to ban this peer and associated ip addresses.
    Banned(PeerId, Vec<IpAddr>),
    /// The peer should be unbanned with the associated ip addresses.
    UnBanned(PeerId, Vec<IpAddr>),
    /// Request the behaviour to discover more peers and the amount of peers to discover.
    DiscoverPeers(usize),
    /// Request the behaviour to discover peers on subnets.
    DiscoverSubnetPeers(Vec<SubnetDiscovery>),
}

impl PeerManager {
    pub fn new(cfg: Config, trusted_peers: Vec<PeerId>, disable_peer_scoring: bool) -> Self {
        // Set up the peer manager heartbeat interval
        let heartbeat = tokio::time::interval(tokio::time::Duration::from_secs(HEARTBEAT_INTERVAL));
        Self {
            target_peers_count: cfg.target_peer_count,
            peers_to_dial: Default::default(),
            events: SmallVec::new(),
            inbound_ping_peers: HashSetDelay::new(Duration::from_secs(cfg.ping_interval_inbound)),
            outbound_ping_peers: HashSetDelay::new(Duration::from_secs(cfg.ping_interval_outbound)),
            status_peers: HashSetDelay::new(Duration::from_secs(cfg.status_interval)),
            peers: RwLock::new(PeerDB::new(trusted_peers, disable_peer_scoring)),
            heartbeat,
            discovery_enabled: cfg.discovery_enabled,
            quic_enabled: true,
        }
    }

    /// The maximum number of peers we allow to connect to us. This is `target_peers` * (1 +
    /// PEER_EXCESS_FACTOR)
    fn max_peers(&self) -> usize {
        (self.target_peers_count as f32 * (1.0 + PEER_EXCESS_FACTOR)).ceil() as usize
    }

    /// The maximum number of peers we allow when dialing a priority peer (i.e a peer that is
    /// subscribed to subnets that our validator requires. This is `target_peers` * (1 +
    /// PEER_EXCESS_FACTOR + PRIORITY_PEER_EXCESS)
    fn max_priority_peers(&self) -> usize {
        (self.target_peers_count as f32 * (1.0 + PEER_EXCESS_FACTOR + PRIORITY_PEER_EXCESS)).ceil()
            as usize
    }

    /// The minimum number of outbound peers that we reach before we start another discovery query.
    fn min_outbound_only_peers(&self) -> usize {
        (self.target_peers_count as f32 * MIN_OUTBOUND_ONLY_FACTOR).ceil() as usize
    }

    /// The minimum number of outbound peers that we reach before we start another discovery query.
    fn target_outbound_peers(&self) -> usize {
        (self.target_peers_count as f32 * TARGET_OUTBOUND_ONLY_FACTOR).ceil() as usize
    }

    /// The maximum number of peers that are connected or dialing before we refuse to do another
    /// discovery search for more outbound peers. We can use up to half the priority peer excess allocation.
    fn max_outbound_dialing_peers(&self) -> usize {
        (self.target_peers_count as f32 * (1.0 + PEER_EXCESS_FACTOR + PRIORITY_PEER_EXCESS / 2.0))
            .ceil() as usize
    }

    /// A peer is being dialed.
    /// Returns true, if this peer will be dialed.
    pub fn dial_peer(&mut self, peer: Enr) -> bool {
        if self.peers.read().should_dial(&peer.peer_id()) {
            self.peers_to_dial.push(peer);
            true
        } else {
            false
        }
    }

    /// Peers that have been returned by discovery requests that are suitable for dialing are
    /// returned here.
    ///
    /// This function decides whether or not to dial these peers.
    pub fn peers_discovered(&mut self, results: HashMap<Enr, Option<Instant>>) {
        let mut to_dial_peers = 0;
        let results_count = results.len();
        let connected_or_dialing = self.connected_or_dialing_peers();
        for (enr, min_ttl) in results {
            // There are two conditions in deciding whether to dial this peer.
            // 1. If we are less than our max connections. Discovery queries are executed to reach
            //    our target peers, so its fine to dial up to our max peers (which will get pruned
            //    in the next heartbeat down to our target).
            // 2. If the peer is one our validators require for a specific subnet, then it is
            //    considered a priority. We have pre-allocated some extra priority slots for these
            //    peers as specified by PRIORITY_PEER_EXCESS. Therefore we dial these peers, even
            //    if we are already at our max_peer limit.
            if !self.peers_to_dial.contains(&enr)
                && (min_ttl.is_some()
                // TODO && connected_or_dialing + to_dial_peers < self.max_priority_peers())
                || connected_or_dialing + to_dial_peers < self.max_peers())
            {
                // This should be updated with the peer dialing. In fact created once the peer is
                // dialed
                let peer_id = enr.peer_id();
                if let Some(min_ttl) = min_ttl {
                    self.peers.write().update_min_ttl(&peer_id, min_ttl);
                }
                if self.dial_peer(enr) {
                    debug!(
                        %peer_id,
                        "Added discovered ENR peer to dial queue"
                    );
                    to_dial_peers += 1;
                }
            }
        }

        // The heartbeat will attempt new discovery queries every N seconds if the node needs more
        // peers. As an optimization, this function can recursively trigger new discovery queries
        // immediatelly if we don't fulfill our peers needs after completing a query. This
        // recursiveness results in an infinite loop in networks where there not enough peers to
        // reach out target. To prevent the infinite loop, if a query returns no useful peers, we
        // will cancel the recursiveness and wait for the heartbeat to trigger another query latter.
        if results_count > 0 && to_dial_peers == 0 {
            debug!(
                results = results_count,
                "Skipping recursive discovery query after finding no useful results"
            );
            metrics::inc_counter(&metrics::DISCOVERY_NO_USEFUL_ENRS);
        } else {
            // Queue another discovery if we need to
            self.maintain_peer_count(to_dial_peers);
        }
    }

    /// Returns the number of libp2p connected peers.
    pub fn connected_peers(&self) -> usize {
        self.peers.read().connected_peer_ids().count()
    }

    /// Returns the number of libp2p connected peers with outbound-only connections.
    pub fn connected_outbound_only_peers(&self) -> usize {
        self.peers.read().connected_outbound_only_peers().count()
    }

    /// Returns the number of libp2p peers that are either connected or being dialed.
    pub fn connected_or_dialing_peers(&self) -> usize {
        self.peers.read().connected_or_dialing_peers().count()
    }

    /// This function checks the status of our current peers and optionally requests a discovery
    /// query if we need to find more peers to maintain the current number of peers
    fn maintain_peer_count(&mut self, dialing_peers: usize) {
        // Check if we need to do a discovery lookup
        if self.discovery_enabled {
            let peer_count = self.connected_or_dialing_peers();
            let outbound_only_peer_count = self.connected_outbound_only_peers();
            let wanted_peers = if peer_count < self.target_peers_count.saturating_sub(dialing_peers)
            {
                // We need more peers in general.
                self.max_peers().saturating_sub(dialing_peers) - peer_count
            } else if outbound_only_peer_count < self.min_outbound_only_peers()
                && peer_count < self.max_outbound_dialing_peers()
            {
                self.max_outbound_dialing_peers()
                    .saturating_sub(dialing_peers)
                    .saturating_sub(peer_count)
            } else {
                0
            };

            if wanted_peers != 0 {
                // We need more peers, re-queue a discovery lookup.
                debug!(
                    connected = peer_count,
                    target = self.target_peers_count,
                    outbound = outbound_only_peer_count,
                    wanted = wanted_peers,
                    "Starting a new peer discovery query"
                );
                self.events
                    .push(PeerManagerEvent::DiscoverPeers(wanted_peers));
            }
        }
    }

    /* Internal functions */

    /// Sets a peer as connected as long as their reputation allows it
    /// Informs if the peer was accepted
    fn inject_connect_ingoing(
        &mut self,
        peer_id: &PeerId,
        multiaddr: Multiaddr,
        enr: Option<Enr>,
    ) -> bool {
        self.inject_peer_connection(peer_id, ConnectingType::IngoingConnected { multiaddr }, enr)
    }

    /// Sets a peer as connected as long as their reputation allows it
    /// Informs if the peer was accepted
    fn inject_connect_outgoing(
        &mut self,
        peer_id: &PeerId,
        multiaddr: Multiaddr,
        enr: Option<Enr>,
    ) -> bool {
        self.inject_peer_connection(
            peer_id,
            ConnectingType::OutgoingConnected { multiaddr },
            enr,
        )
    }

    /// Updates the state of the peer as disconnected.
    ///
    /// This is also called when dialing a peer fails.
    fn inject_disconnect(&mut self, peer_id: &PeerId) {
        let (_ban_operation, purged_peers) = self.peers.write().inject_disconnect(peer_id);

        // if let Some(ban_operation) = ban_operation {
        //     // The peer was awaiting a ban, continue to ban the peer.
        //     self.handle_ban_operation(peer_id, ban_operation, None);
        // }

        // Remove the ping and status timer for the peer
        self.inbound_ping_peers.remove(peer_id);
        self.outbound_ping_peers.remove(peer_id);
        self.status_peers.remove(peer_id);
        self.events.extend(
            purged_peers
                .into_iter()
                .map(|(peer_id, unbanned_ips)| PeerManagerEvent::UnBanned(peer_id, unbanned_ips)),
        );
    }

    /// Registers a peer as connected. The `ingoing` parameter determines if the peer is being
    /// dialed or connecting to us.
    ///
    /// This is called by `connect_ingoing` and `connect_outgoing`.
    ///
    /// Informs if the peer was accepted in to the db or not.
    fn inject_peer_connection(
        &mut self,
        peer_id: &PeerId,
        connection: ConnectingType,
        enr: Option<Enr>,
    ) -> bool {
        {
            let mut peerdb = self.peers.write();
            if peerdb.ban_status(peer_id).is_some() {
                // don't connect if the peer is banned
                error!(
                    peer_id = %peer_id,
                    "Connection has been allowed to a banned peer"
                );
            }

            match connection {
                ConnectingType::Dialing => {
                    peerdb.dialing_peer(peer_id, enr);
                    return true;
                }
                ConnectingType::IngoingConnected { multiaddr } => {
                    peerdb.connect_ingoing(peer_id, multiaddr, enr);
                    // start a timer to ping inbound peers.
                    self.inbound_ping_peers.insert(*peer_id);
                }
                ConnectingType::OutgoingConnected { multiaddr } => {
                    peerdb.connect_outgoing(peer_id, multiaddr, enr);
                    // start a timer for to ping outbound peers.
                    self.outbound_ping_peers.insert(*peer_id);
                }
            }
        }

        // start a ping and status timer for the peer
        self.status_peers.insert(*peer_id);

        true
    }

    // Reduce memory footprint by routinely shrinking associating mappings.
    fn shrink_mappings(&mut self) {
        self.inbound_ping_peers.shrink_to(5);
        self.outbound_ping_peers.shrink_to(5);
        self.status_peers.shrink_to(5);
        //self.temporary_banned_peers.shrink_to_fit();
    }

    /// The Peer manager's heartbeat maintains the peer count and maintains peer reputations.
    ///
    /// It will request discovery queries if the peer count has not reached the desired number of
    /// overall peers, as well as the desired number of outbound-only peers.
    ///
    /// NOTE: Discovery will only add a new query if one isn't already queued.
    fn heartbeat(&mut self) {
        // Optionally run a discovery query if we need more peers.
        self.maintain_peer_count(0);

        // Cleans up the connection state of dialing peers.
        // Libp2p dials peer-ids, but sometimes the response is from another peer-id or libp2p
        // returns dial errors without a peer-id attached. This function reverts peers that have a
        // dialing status long than DIAL_TIMEOUT seconds to a disconnected status. This is important because
        // we count the number of dialing peers in our inbound connections.
        self.peers.write().cleanup_dialing_peers();

        // Updates peer's scores and unban any peers if required.
        //let actions = self.peers.write().update_scores();
        //for (peer_id, action) in actions {
        //    self.handle_score_action(&peer_id, action, None);
        //}

        // Update peer score metrics;
        //self.update_peer_score_metrics();

        // Prune any excess peers back to our target in such a way that incentivises good scores and
        // a uniform distribution of subnets.
        //self.prune_excess_peers();

        // Unban any peers that have served their temporary ban timeout
        //self.unban_temporary_banned_peers();

        // Maintains memory by shrinking mappings
        self.shrink_mappings();
    }
}

enum ConnectingType {
    /// We are in the process of dialing this peer.
    Dialing,
    /// A peer has dialed us.
    IngoingConnected {
        // The multiaddr the peer connected to us on.
        multiaddr: Multiaddr,
    },
    /// We have successfully dialed a peer.
    OutgoingConnected {
        /// The multiaddr we dialed to reach the peer.
        multiaddr: Multiaddr,
    },
}
