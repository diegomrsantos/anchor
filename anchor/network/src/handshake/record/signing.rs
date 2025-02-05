use crate::handshake::record::envelope::Envelope;
use crate::handshake::record::record::Record;
use libp2p::identity::{Keypair, PublicKey};
use std::error::Error;
use std::fmt::format;

/// Seals a `Record` into an Envelope by:
///  1) marshalling record to bytes,
///  2) building "unsigned" data (domain + codec + payload),
///  3) signing with ed25519,
///  4) storing into `Envelope`.
pub fn seal_record<R: Record>(record: &R, keypair: &Keypair) -> Result<Envelope, Box<dyn Error>> {
    let domain = R::DOMAIN;
    if domain.is_empty() {
        return Err("domain must not be empty".into());
    }
    let payload_type = R::CODEC;
    if payload_type.is_empty() {
        return Err("payload_type must not be empty".into());
    }

    // 1) marshal
    let raw_payload = record.marshal_record()?;

    // 2) build the "unsigned" data
    let unsigned = make_unsigned(domain.as_bytes(), payload_type, &raw_payload);

    // 3) sign
    let sig = keypair.sign(&unsigned)?;

    // 4) build Envelope
    let env = Envelope {
        public_key: keypair.public().encode_protobuf(),
        payload_type: payload_type.to_vec(),
        payload: raw_payload,
        signature: sig,
    };
    Ok(env)
}

/// Consumes an Envelope => verify signature => parse the record.
pub fn parse_envelope<R: Record>(
    bytes: &[u8],
) -> Result<(Envelope), Box<dyn Error>> {
    let env = Envelope::decode_from_slice(bytes)?;

    let domain = R::DOMAIN;
    let payload_type = R::CODEC;

    let unsigned = make_unsigned(domain.as_bytes(), payload_type, &env.payload);

    let pk = PublicKey::try_decode_protobuf(&*env.public_key.to_vec()).unwrap();

    if !pk.verify(&unsigned, &env.signature) {
        return Err("signature verification failed".into());
    }

    Ok(env)
}

fn make_unsigned(domain: &[u8], payload_type: &[u8], payload: &[u8]) -> Vec<u8> {
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

