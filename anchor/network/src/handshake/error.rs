use thiserror::Error;

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Network ID mismatch")]
    NetworkMismatch,

    #[error("Subnets format error")]
    SubnetsFormat,

    #[error("Peer rejected")]
    PeerRejected,

    #[error("Crypto error: {0}")]
    Crypto(String),

    InvalidMessageFormat,
    ResponseFailed,
}