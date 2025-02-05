use prost::Message;
use strum::Display;

/// The Envelope structure exactly matching Go's Envelope fields and tags:
///   1 => public_key
///   2 => payload_type
///   3 => payload
///   4 => signature
///
/// All are `bytes`, just like in Go.
#[derive(Clone, PartialEq, Message)]
pub struct Envelope {
    #[prost(bytes = "vec", tag = "1")]
    pub public_key: Vec<u8>,

    #[prost(bytes = "vec", tag = "2")]
    pub payload_type: Vec<u8>,

    #[prost(bytes = "vec", tag = "3")]
    pub payload: Vec<u8>,

    #[prost(bytes = "vec", tag = "5")]
    pub signature: Vec<u8>,
}

impl Envelope {
    /// Encode the Envelope to a Protobuf byte array (like `proto.Marshal` in Go).
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, prost::EncodeError> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        self.encode(&mut buf)?;
        Ok(buf)
    }

    /// Decode an Envelope from a Protobuf byte array (like `proto.Unmarshal` in Go).
    pub fn decode_from_slice(data: &[u8]) -> Result<Self, prost::DecodeError> {
        Envelope::decode(data)
    }
}