use std::error::Error;
use discv5::libp2p_identity::PublicKey;
use prost::Message;
use strum::Display;
use crate::handshake::types::NodeInfo;

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

/// Consumes an Envelope => verify signature => parse the record.
pub fn parse_envelope(
    bytes: &[u8],
) -> Result<(Envelope), Box<dyn Error>> {
    let env = Envelope::decode_from_slice(bytes)?;

    let domain = NodeInfo::DOMAIN;
    let payload_type = NodeInfo::CODEC;

    let unsigned = make_unsigned(domain.as_bytes(), payload_type, &env.payload);

    let pk = PublicKey::try_decode_protobuf(&*env.public_key.to_vec()).unwrap();

    if !pk.verify(&unsigned, &env.signature) {
        return Err("signature verification failed".into());
    }

    Ok(env)
}

pub fn make_unsigned(domain: &[u8], payload_type: &[u8], payload: &[u8]) -> Vec<u8> {
    use prost::encoding::encode_varint;
    let mut out = Vec::new();

    encode_varint(domain.len() as u64, &mut out);
    out.extend_from_slice(domain);

    encode_varint(payload_type.len() as u64, &mut out);
    out.extend_from_slice(payload_type);

    encode_varint(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);

    out
}
