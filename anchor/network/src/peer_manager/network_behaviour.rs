use crate::peer_manager::{ConnectingType, PeerManager, PeerManagerEvent};
use discv5::libp2p_identity::PeerId;
use discv5::multiaddr::{Multiaddr};
use futures::StreamExt;
use libp2p::core::transport::PortUse;
use libp2p::core::{ConnectedPoint, Endpoint};
use libp2p::swarm::behaviour::ConnectionEstablished;
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::dummy::ConnectionHandler;
use libp2p::swarm::{
    ConnectionClosed, ConnectionDenied, ConnectionId, DialFailure, FromSwarm, NetworkBehaviour,
    THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use lighthouse_network::EnrExt;
use std::task::{Context, Poll};
use tracing::{debug, error, trace};

impl NetworkBehaviour for PeerManager {
    type ConnectionHandler = ConnectionHandler;
    type ToSwarm = PeerManagerEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer_id: PeerId,
        _local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        trace!(
            %peer_id,
            %remote_addr,
            "Inbound connection"
        );
        // We already checked if the peer was banned on `handle_pending_inbound_connection`.
        // if self.ban_status(&peer_id).is_some() {
        //     return Err(ConnectionDenied::new(
        //         "Connection to peer rejected: peer has a bad score",
        //     ));
        // }

        // Check the connection limits
        if self.connected_or_dialing_peers() >= self.max_peers()
            && self
            .peers
            .read()
            .peer_info(&peer_id)
            .map_or(true, |peer| !peer.has_future_duty())
        {
            return Err(ConnectionDenied::new(
                "Connection to peer rejected: too many connections",
            ));
        }

        // We have an inbound connection, this is indicative of having our libp2p NAT ports open. We
        // distinguish between ipv4 and ipv6 here:
        // match remote_addr.iter().next() {
        //     Some(Protocol::Ip4(_)) => set_gauge_vec(&NAT_OPEN, &["libp2p_ipv4"], 1),
        //     Some(Protocol::Ip6(_)) => set_gauge_vec(&NAT_OPEN, &["libp2p_ipv6"], 1),
        //     _ => {}
        // }

        Ok(ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer_id: PeerId,
        addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        trace!(
            %peer_id,
            multiaddr = %addr,
            "Outbound connection");
        // if let Some(cause) = self.ban_status(&peer_id) {
        //     error!(
        //         %peer_id,
        //         "Connected a banned peer. Rejecting connection"
        //     );
        //     return Err(ConnectionDenied::new(cause));
        // }

        // Check the connection limits
        if self.connected_peers() >= self.max_outbound_dialing_peers()
            && self
            .peers
            .read()
            .peer_info(&peer_id)
            .map_or(true, |peer| !peer.has_future_duty())
        {
            return Err(ConnectionDenied::new(
                "Connection to peer rejected: too many connections",
            ));
        }

        Ok(ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id,
                endpoint,
                other_established,
                ..
            }) => self.on_connection_established(peer_id, endpoint, other_established),
            FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id,
                endpoint,

                remaining_established,
                ..
            }) => self.on_connection_closed(peer_id, endpoint, remaining_established),
            FromSwarm::DialFailure(DialFailure {
                peer_id,
                error,
                connection_id: _,
            }) => {
                debug!(
                    ?peer_id,
                    %error,// = %ClearDialError(error),
                    "Failed to dial peer"
                );
                self.on_dial_failure(peer_id);
            }
            _ => {
                // NOTE: FromSwarm is a non exhaustive enum so updates should be based on release
                // notes more than compiler feedback
                // The rest of the events we ignore since they are handled in their associated
                // `SwarmEvent`
            }
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        _event: THandlerOutEvent<Self>,
    ) {
        // no events from the dummy handler
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        // perform the heartbeat when necessary
        while self.heartbeat.poll_tick(cx).is_ready() {
            self.heartbeat();
        }

        // poll the timeouts for pings and status'
        loop {
            match self.inbound_ping_peers.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(peer_id))) => {
                    self.inbound_ping_peers.insert(peer_id);
                    self.events.push(PeerManagerEvent::Ping(peer_id));
                }
                Poll::Ready(Some(Err(e))) => {
                    error!(
                        error = e.to_string(),
                        "Failed to check for inbound peers to ping"
                    )
                }
                Poll::Ready(None) | Poll::Pending => break,
            }
        }

        loop {
            match self.outbound_ping_peers.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(peer_id))) => {
                    self.outbound_ping_peers.insert(peer_id);
                    self.events.push(PeerManagerEvent::Ping(peer_id));
                }
                Poll::Ready(Some(Err(e))) => {
                    error!(
                        error = e.to_string(),
                        "Failed to check for outbound peers to ping"
                    )
                }
                Poll::Ready(None) | Poll::Pending => break,
            }
        }

        // if !matches!(
        //     self.network_globals.sync_state(),
        //     SyncState::SyncingFinalized { .. } | SyncState::SyncingHead { .. }
        // ) {
        //     loop {
        //         match self.status_peers.poll_next_unpin(cx) {
        //             Poll::Ready(Some(Ok(peer_id))) => {
        //                 self.status_peers.insert(peer_id);
        //                 self.events.push(PeerManagerEvent::Status(peer_id))
        //             }
        //             Poll::Ready(Some(Err(e))) => {
        //                 error!(self.log, "Failed to check for peers to ping"; "error" => e.to_string())
        //             }
        //             Poll::Ready(None) | Poll::Pending => break,
        //         }
        //     }
        // }

        if !self.events.is_empty() {
            return Poll::Ready(ToSwarm::GenerateEvent(self.events.remove(0)));
        } else {
            self.events.shrink_to_fit();
        }

        if let Some(enr) = self.peers_to_dial.pop() {
            self.inject_peer_connection(&enr.peer_id(), ConnectingType::Dialing, Some(enr.clone()));

            // Prioritize Quic connections over Tcp ones.
            let multiaddrs = [
                self.quic_enabled
                    .then_some(enr.multiaddr_quic())
                    .unwrap_or_default(),
                enr.multiaddr_tcp(),
            ]
            .concat();

            debug!(
                peer_id = %enr.peer_id(),
                multiaddrs = ?multiaddrs,
                "Dialing peer"
            );
            return Poll::Ready(ToSwarm::Dial {
                opts: DialOpts::peer_id(enr.peer_id())
                    .condition(PeerCondition::Disconnected)
                    .addresses(multiaddrs)
                    .build(),
            });
        }

        Poll::Pending
    }
}

impl PeerManager {
    fn on_connection_established(
        &mut self,
        peer_id: PeerId,
        endpoint: &ConnectedPoint,
        _other_established: usize,
    ) {
        debug!(
            %peer_id,
            multiaddr = %endpoint.get_remote_address(),
            connection = ?endpoint.to_endpoint(),
            "Connection established"
        );

        // Update the prometheus metrics
        // if self.metrics_enabled {
        //     metrics::inc_counter(&metrics::PEER_CONNECT_EVENT_COUNT);
        //
        //     self.update_peer_count_metrics();
        // }

        // NOTE: We don't register peers that we are disconnecting immediately. The network service
        // does not need to know about these peers.
        match endpoint {
            ConnectedPoint::Listener { send_back_addr, .. } => {
                self.inject_connect_ingoing(&peer_id, send_back_addr.clone(), None);
                self.events
                    .push(PeerManagerEvent::PeerConnectedIncoming(peer_id));
            }
            ConnectedPoint::Dialer { address, .. } => {
                self.inject_connect_outgoing(&peer_id, address.clone(), None);
                self.events
                    .push(PeerManagerEvent::PeerConnectedOutgoing(peer_id));
            }
        };
    }

    fn on_connection_closed(
        &mut self,
        peer_id: PeerId,
        _endpoint: &ConnectedPoint,
        remaining_established: usize,
    ) {
        if remaining_established > 0 {
            return;
        }

        // There are no more connections
        if self
            .peers
            .read()
            .is_connected_or_disconnecting(&peer_id)
        {
            // We are disconnecting the peer or the peer has already been connected.
            // Both these cases, the peer has been previously registered by the peer manager and
            // potentially the application layer.
            // Inform the application.
            self.events
                .push(PeerManagerEvent::PeerDisconnected(peer_id));
            debug!(
                %peer_id,
                "Peer disconnected"
            );
        }

        // NOTE: It may be the case that a rejected node, due to too many peers is disconnected
        // here and the peer manager has no knowledge of its connection. We insert it here for
        // reference so that peer manager can track this peer.
        self.inject_disconnect(&peer_id);

        // Update the prometheus metrics
        // if self.metrics_enabled {
        //     // Legacy standard metrics.
        //     metrics::inc_counter(&metrics::PEER_DISCONNECT_EVENT_COUNT);
        //
        //     self.update_peer_count_metrics();
        // }
    }

    /// A dial attempt has failed.
    ///
    /// NOTE: It can be the case that we are dialing a peer and during the dialing process the peer
    /// connects and the dial attempt later fails. To handle this, we only update the peer_db if
    /// the peer is not already connected.
    fn on_dial_failure(&mut self, peer_id: Option<PeerId>) {
        if let Some(peer_id) = peer_id {
            if !self.peers.read().is_connected(&peer_id) {
                self.inject_disconnect(&peer_id);
            }
        }
    }
}

