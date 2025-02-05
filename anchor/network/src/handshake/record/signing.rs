use crate::handshake::record::envelope::Envelope;
use libp2p::identity::{Keypair, PublicKey};
use std::error::Error;
use std::fmt::format;
use crate::handshake::types::NodeInfo;

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

