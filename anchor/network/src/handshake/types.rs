use crate::handshake::record::record::Record;
use serde::{Deserialize, Serialize};
use serde_json;
use std::error::Error;

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct NodeMetadata {
    pub node_version: String,
    pub execution_node: String,
    pub consensus_node: String,
    pub subnets: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct NodeInfo {
    fork_version: String, //deprecated
    pub network_id: String,
    pub metadata: NodeMetadata,
}

impl NodeInfo {
    pub fn new(network_id: String, metadata: NodeMetadata) -> Self {
        NodeInfo {
            fork_version: "".to_string(),
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
        let data = serde_json::to_vec(self)?;
        Ok(data)
    }

    /// Deserialize `NodeInfo` from JSON bytes, replacing `self`.
    fn unmarshal_record(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let parsed: NodeInfo = serde_json::from_slice(data)?;
        *self = parsed;
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
    use crate::handshake::record::record::Record;
    use crate::handshake::types::{NodeInfo, NodeMetadata};

    #[test]
    fn test_node_info_marshal_unmarshal() {
        // Create a sample NodeInfo instance
        let node_info = NodeInfo::new(
            "holesky".to_string(),
            NodeMetadata {
                node_version: "geth/x".to_string(),
                execution_node: "geth/x".to_string(),
                consensus_node: "prysm/x".to_string(),
                subnets: "00000000000000000000000000000000".to_string(),
            },
        );

        // Marshal the NodeInfo into bytes
        let data = node_info.marshal_record().expect("Marshal failed");

        // Unmarshal the bytes back into a NodeInfo instance
        let mut parsed_node_info = NodeInfo::default();
        parsed_node_info
            .unmarshal_record(&data)
            .expect("Unmarshal failed");

        assert_eq!(node_info, parsed_node_info);
    }
}