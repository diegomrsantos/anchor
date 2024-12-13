use std::task::{Context, Poll};

use discv5::{Discv5, Enr};
use discv5::enr::CombinedKey;
use discv5::libp2p_identity::PeerId;
use discv5::multiaddr::Multiaddr;
use libp2p::core::Endpoint;
use libp2p::core::transport::PortUse;
use libp2p::swarm::{ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm};
use libp2p::swarm::dummy::ConnectionHandler;
use lighthouse_network::discovery::enr_ext::{QUIC6_ENR_KEY, QUIC_ENR_KEY};
use crate::Config;

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

/// Builds a anchor ENR given a `network::Config`.
pub fn build_enr(
    enr_key: &CombinedKey,
    config: &Config,
) -> Result<Enr, String> {
    let mut builder = discv5::enr::Enr::builder();
    let (maybe_ipv4_address, maybe_ipv6_address) = &config.enr_address;

    if let Some(ip) = maybe_ipv4_address {
        builder.ip4(*ip);
    }

    if let Some(ip) = maybe_ipv6_address {
        builder.ip6(*ip);
    }

    if let Some(udp4_port) = config.enr_udp4_port {
        builder.udp4(udp4_port.get());
    }

    if let Some(udp6_port) = config.enr_udp6_port {
        builder.udp6(udp6_port.get());
    }

    // Add QUIC fields to the ENR.
    // Since QUIC is used as an alternative transport for the libp2p protocols,
    // the related fields should only be added when both QUIC and libp2p are enabled
    if !config.disable_quic_support {
        // If we are listening on ipv4, add the quic ipv4 port.
        if let Some(quic4_port) = config.enr_quic4_port.or_else(|| {
            config
                .listen_addresses
                .v4()
                .and_then(|v4_addr| v4_addr.quic_port.try_into().ok())
        }) {
            builder.add_value(QUIC_ENR_KEY, &quic4_port.get());
        }

        // If we are listening on ipv6, add the quic ipv6 port.
        if let Some(quic6_port) = config.enr_quic6_port.or_else(|| {
            config
                .listen_addresses
                .v6()
                .and_then(|v6_addr| v6_addr.quic_port.try_into().ok())
        }) {
            builder.add_value(QUIC6_ENR_KEY, &quic6_port.get());
        }
    }

    // If the ENR port is not set, and we are listening over that ip version, use the listening port instead.
    let tcp4_port = config.enr_tcp4_port.or_else(|| {
        config
            .listen_addresses
            .v4()
            .and_then(|v4_addr| v4_addr.tcp_port.try_into().ok())
    });
    if let Some(tcp4_port) = tcp4_port {
        builder.tcp4(tcp4_port.get());
    }

    let tcp6_port = config.enr_tcp6_port.or_else(|| {
        config
            .listen_addresses
            .v6()
            .and_then(|v6_addr| v6_addr.tcp_port.try_into().ok())
    });
    if let Some(tcp6_port) = tcp6_port {
        builder.tcp6(tcp6_port.get());
    }

    builder
        .build(enr_key)
        .map_err(|e| format!("Could not build Local ENR: {:?}", e))
}
