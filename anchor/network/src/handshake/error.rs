use libp2p::request_response::{InboundFailure, OutboundFailure};
use crate::handshake::types::UnmarshalError;

#[derive(Debug)]
pub enum HandshakeError {
    InvalidSignature,

    NetworkMismatch { ours: String, theirs: String },

    SubnetsFormat,

    PeerRejected,

    Crypto(String),

    InvalidMessageFormat,
    ResponseFailed,

    UnmarshalError(UnmarshalError),
    Inbound(InboundFailure),
    Outbound(OutboundFailure),
}