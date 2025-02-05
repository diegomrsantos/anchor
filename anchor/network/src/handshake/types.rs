use crate::handshake::record::record::Record;
use serde::{Deserialize, Serialize};
use serde_json;
use std::error::Error;

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

// This is the direct Rust equivalent to your 'serializable' struct
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
}

impl Record for NodeInfo {
    const DOMAIN: &'static str = "ssv";

    const CODEC: &'static [u8] = b"ssv:nodeinfo";

    /// Serialize `NodeInfo` to JSON bytes.
    fn marshal_record(&self) -> Result<Vec<u8>, Box<dyn Error>> {
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
    fn unmarshal_record(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let ser: Serializable = serde_json::from_slice(data)?;
        if ser.entries.len() < 2 {
            return Err("node info must have at least 2 entries".into());
        }
        // skip ser.entries[0]: old forkVersion
        self.network_id = ser.entries[1].clone();
        if ser.entries.len() >= 3 {
            let meta = serde_json::from_slice(ser.entries[2].as_bytes())?;
            self.metadata = Some(meta);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum HandshakeMessage {
    Request(NodeInfo),
    Response(NodeInfo),
}


#[cfg(test)]
mod tests {
    use libp2p::identity::Keypair;
    use crate::handshake::record::record::Record;
    use crate::handshake::record::signing::{consume_envelope, seal_record};
    use crate::handshake::types::{NodeInfo, NodeMetadata};

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
        let envelope = seal_record(&node_info, &Keypair::generate_secp256k1()).expect("Seal failed");

        let data = envelope.encode_to_vec().unwrap();

        let (parsed_env, parsed_node_info) = consume_envelope(&data).expect("Consume failed");

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
        let data = current_data.marshal_record()
            .expect("marshal_record should succeed");

        // 2) Unmarshal into parsed_rec
        let mut parsed_rec = NodeInfo::default();
        parsed_rec.unmarshal_record(&data)
            .expect("unmarshal_record should succeed");

        // 3) Now unmarshal the old format data into the same struct
        parsed_rec.unmarshal_record(old_serialized_data)
            .expect("unmarshal old data should succeed");

        // 4) Compare
        // The Go test checks reflect.DeepEqual(currentSerializedData, parsedRec)
        // We can do the same in Rust using assert_eq.
        assert_eq!(current_data, parsed_rec);
    }
}