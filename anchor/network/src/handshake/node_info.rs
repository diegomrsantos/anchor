use serde::{Deserialize, Serialize};
use serde_json;
use discv5::libp2p_identity::{Keypair, SigningError};
use crate::handshake::envelope::{make_unsigned, Envelope};

use thiserror::Error;
use crate::handshake::node_info::Error::Validation;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("Seal error: {0}")]
    Seal(#[from] SigningError),

    #[error("Validation error: {0}")]
    Validation(String),
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct NodeMetadata {
    #[serde(rename = "NodeVersion")]
    pub node_version: String,
    #[serde(rename = "ExecutionNode")]
    pub execution_node: String,
    #[serde(rename = "ConsensusNode")]
    pub consensus_node: String,
    #[serde(rename = "Subnets")]
    pub subnets: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct NodeInfo {
    pub network_id: String,
    pub metadata: Option<NodeMetadata>,
}

// This is the direct Rust equivalent to Go 'serializable' struct
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Serializable {
    #[serde(rename = "Entries")]
    entries: Vec<String>,
}

impl NodeInfo {
    pub fn new(network_id: String, metadata: Option<NodeMetadata>) -> Self {
        NodeInfo {
            network_id,
            metadata,
        }
    }

    pub(crate) const DOMAIN: &'static str = "ssv";

    pub(crate) const CODEC: &'static [u8] = b"ssv/nodeinfo";

    /// Serialize `NodeInfo` to JSON bytes.
    fn marshal(&self) -> Result<Vec<u8>, Error> {
        let mut entries = vec![
            "".to_string(),             // formerly forkVersion, now deprecated
            self.network_id.clone(),    // network id
        ];

        if let Some(meta) = &self.metadata {
            let raw_meta = serde_json::to_vec(meta)?;
            entries.push(String::from_utf8(raw_meta)?);
        }

        // Serialize as JSON
        let ser = Serializable { entries };
        let data = serde_json::to_vec(&ser)?;
        Ok(data)
    }

    /// Deserialize `NodeInfo` from JSON bytes, replacing `self`.
    pub fn unmarshal(&mut self, data: &[u8]) -> Result<(), Error> {
        let ser: Serializable = serde_json::from_slice(data)?;
        if ser.entries.len() < 2 {
            return Err(Validation("node info must have at least 2 entries".into()));
        }
        // skip ser.entries[0]: old forkVersion
        self.network_id = ser.entries[1].clone();
        if ser.entries.len() >= 3 {
            let meta = serde_json::from_slice(ser.entries[2].as_bytes())?;
            self.metadata = Some(meta);
        }
        Ok(())
    }

    /// Seals a `Record` into an Envelope by:
    ///  1) marshalling record to bytes,
    ///  2) building "unsigned" data (domain + codec + payload),
    ///  3) signing with ed25519,
    ///  4) storing into `Envelope`.
    pub fn seal(&self,  keypair: &Keypair) -> Result<Envelope, Error> {
        let domain = Self::DOMAIN;
        if domain.is_empty() {
            return Err(Validation("domain must not be empty".into()));
        }
        let payload_type = Self::CODEC;
        if payload_type.is_empty() {
            return Err(Validation("payload_type must not be empty".into()));
        }

        // 1) marshal
        let raw_payload = self.marshal()?;

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
}

#[cfg(test)]
mod tests {
    use libp2p::identity::Keypair;
    use crate::handshake::envelope::parse_envelope;
    use crate::handshake::node_info::{NodeInfo, NodeMetadata};

    #[test]
    fn test_node_info_seal_consume() {
        // Create a sample NodeInfo instance
        let node_info = NodeInfo::new(
            "holesky".to_string(),
            Some(NodeMetadata {
                node_version: "geth/x".to_string(),
                execution_node: "geth/x".to_string(),
                consensus_node: "prysm/x".to_string(),
                subnets: "00000000000000000000000000000000".to_string(),
            }),
        );

        // Marshal the NodeInfo into bytes
        let envelope = node_info.seal(&Keypair::generate_secp256k1()).expect("Seal failed");

        let data = envelope.encode_to_vec().unwrap();

        let parsed_env = parse_envelope(&data).expect("Consume failed");
        let mut parsed_node_info = NodeInfo::default();
        parsed_node_info.unmarshal(&parsed_env.payload).expect("TODO: panic message");

        assert_eq!(node_info, parsed_node_info);
    }

    #[test]
    fn test_node_info_marshal_unmarshal() {
        // The old serialized data from the Go code
        // (note the "Subnets":"ffffffffffffffffffffffffffffffff")
        let old_serialized_data = br#"{"Entries":["", "testnet", "{\"NodeVersion\":\"v0.1.12\",\"ExecutionNode\":\"geth/x\",\"ConsensusNode\":\"prysm/x\",\"Subnets\":\"ffffffffffffffffffffffffffffffff\"}"]}"#;

        // The "current" NodeInfo data
        let current_data = NodeInfo {
            network_id: "testnet".to_string(),
            metadata: Some(NodeMetadata {
                node_version: "v0.1.12".into(),
                execution_node: "geth/x".into(),
                consensus_node: "prysm/x".into(),
                subnets: "ffffffffffffffffffffffffffffffff".into(),
            }),
        };

        // 1) Marshal current_data
        let data = current_data.marshal()
            .expect("marshal_record should succeed");

        // 2) Unmarshal into parsed_rec
        let mut parsed_rec = NodeInfo::default();
        parsed_rec.unmarshal(&data)
            .expect("unmarshal_record should succeed");

        // 3) Now unmarshal the old format data into the same struct
        parsed_rec.unmarshal(old_serialized_data)
            .expect("unmarshal old data should succeed");

        // 4) Compare
        // The Go test checks reflect.DeepEqual(currentSerializedData, parsedRec)
        // We can do the same in Rust using assert_eq.
        assert_eq!(current_data, parsed_rec);
    }
}