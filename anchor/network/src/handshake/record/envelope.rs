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

#[cfg(test)]
mod tests {
    use std::error::Error;
    use libp2p::identity::Keypair;
    use super::*;  // brings `seal`, `consume_envelope`, `Record`, etc. into scope
    use rand::rngs::OsRng;
    use crate::handshake::record::record::Record;
    use crate::handshake::record::signing::{consume_envelope, seal_record};

    // A minimal “Record” that matches the logic in the Go test
    #[derive(Default, Debug, Clone)]
    struct SimpleRecord {
        domain: String,
        codec: Vec<u8>,
        message: String,
    }

    impl Record for SimpleRecord {
        const DOMAIN: &'static str = "libp2p-testing";
        const CODEC: &'static [u8] = b"/libp2p/testdata";

        fn marshal_record(&self) -> Result<Vec<u8>, Box<dyn Error>> {
            Ok(self.message.as_bytes().to_vec())
        }
        fn unmarshal_record(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
            self.message = String::from_utf8(data.to_vec())
                .map_err(|e| format!("utf8 error: {e}"))?;
            Ok(())
        }
    }

    #[test]
    fn test_envelope_happy_path() {
        // 1. Create a new keypair for testing
        let keypair = Keypair::generate_ed25519();

        // 2. Create a record
        let mut rec = SimpleRecord {
            domain: "libp2p-testing".into(),
            codec: b"/libp2p/testdata".to_vec(),
            message: "hello world!".into(),
        };

        // 3. Seal it
        let env = seal_record(&rec, &keypair).expect("seal should succeed");

        // 4. Check envelope fields
        assert_eq!(env.payload_type, rec.codec);
        // domain is not stored directly in Envelope,
        // but in canonical_data used for signature checking

        // 5. Serialize the Envelope to bytes
        let serialized = env.encode_to_vec().unwrap();

        // 6. Consume and verify
        let (roundtrip_env, rec2) =
            consume_envelope::<SimpleRecord>(&serialized).expect("consume_envelope should succeed");

        // 7. Check the payload is the same
        assert_eq!(roundtrip_env.payload, env.payload, "payload mismatch");
        assert_eq!(
            roundtrip_env.signature, env.signature,
            "signature mismatch"
        );

        // 8. Check the domain record
        assert_eq!(rec2.message, "hello world!", "unexpected message");
    }
}