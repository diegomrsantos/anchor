use libp2p::request_response::{InboundFailure, OutboundFailure};
use crate::handshake::node_info::Error;

#[derive(Debug)]
pub enum HandshakeError {
    NetworkMismatch { ours: String, theirs: String },
    UnmarshalError(Error),
    Inbound(InboundFailure),
    Outbound(OutboundFailure),
}