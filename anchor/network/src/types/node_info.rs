// use serde::{Deserialize, Serialize};
//
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct NodeMetadata {
//     // NodeVersion is the ssv-node version, it is a required field
//     pub node_version: String,
//     // ExecutionNode is the "name/version" of the eth1 node
//     pub execution_node: String,
//     // ConsensusNode is the "name/version" of the beacon node
//     pub consensus_node: String,
//     // Subnets represents the subnets that our node is subscribed to
//     pub subnets: String,
// }
//
// impl NodeMetadata {
//     /// Example validation you might do:
//     pub fn validate(&self) -> Result<(), String> {
//         if self.subnets.len() != 5 {
//             Err(format!("Invalid subnets length: got {}, expected 5", self.subnets.len()))
//         } else {
//             Ok(())
//         }
//     }
// }
//
// /// The node info that we exchange during handshake.
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct NodeInfo {
//     pub network_id: String,         // e.g. "anchor-testnet"
//     pub metadata: Option<NodeMetadata>,
// }
//
// impl NodeInfo {
//     pub fn new(network_id: impl Into<String>) -> Self {
//         Self {
//             network_id: network_id.into(),
//             metadata: None,
//         }
//     }
//
//     /// Validate fields if you want to ensure subnets or network id are correct
//     pub fn validate(&self) -> Result<(), String> {
//         // Example: check the metadata if present
//         if let Some(md) = &self.metadata {
//             md.validate()?;
//         }
//         Ok(())
//     }
// }
//
// // ----------------------------------------------------------------------
// // 2. An "Envelope" type (like Go’s "record.Envelope") if you want to sign
// //    or store signature fields. If the snippet doesn't show them, skip.
// //    Shown here just to illustrate how you might separate them.
// // ----------------------------------------------------------------------
//
// /// If you had a signature in your real code, you'd keep it in Envelope, not in NodeInfo.
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct NodeInfoEnvelope {
//     /// The raw JSON of NodeInfo (or a sealed version if you sign).
//     pub data: Vec<u8>,
// }
//
// /// Convert a `NodeInfo` into a JSON "envelope" (without signature).
// impl From<NodeInfo> for NodeInfoEnvelope {
//     fn from(node_info: NodeInfo) -> Self {
//         let data = serde_json::to_vec(&node_info).expect("serialization cannot fail");
//         Self { data }
//     }
// }
//
// /// Convert back from envelope to `NodeInfo`, doing any signature checks if needed.
// impl TryFrom<NodeInfoEnvelope> for NodeInfo {
//     type Error = String;
//
//     fn try_from(env: NodeInfoEnvelope) -> Result<Self, Self::Error> {
//         let info: NodeInfo = serde_json::from_slice(&env.data)
//             .map_err(|e| format!("Failed to parse NodeInfo: {e}"))?;
//         info.validate()?;
//         Ok(info)
//     }
// }
//
// // ----------------------------------------------------------------------
// // 3. PeerInfo store, matching your snippet's "peerInfos.UpdatePeerInfo" usage
// // ----------------------------------------------------------------------
//
// #[derive(Debug)]
// pub struct PeerInfo {
//     pub last_handshake: Option<SystemTime>,
//     pub last_handshake_error: Option<String>,
// }
//
// impl PeerInfo {
//     pub fn new() -> Self {
//         Self {
//             last_handshake: None,
//             last_handshake_error: None,
//         }
//     }
// }
//
// #[derive(Default)]
// pub struct PeerInfoIndex {
//     inner: RwLock<HashMap<PeerId, PeerInfo>>,
// }
//
// impl PeerInfoIndex {
//     pub fn new() -> Self {
//         Self {
//             inner: Default::default(),
//         }
//     }
//
//     /// This parallels the Go code snippet's "h.updatePeerInfo(pid, err)" logic.
//     /// If there's an error, store it. Otherwise mark success.
//     pub fn update_peer_info(&self, peer_id: &PeerId, err: Option<&str>) {
//         let mut map = self.inner.write().unwrap();
//         let pinfo = map.entry(*peer_id).or_insert(PeerInfo::new());
//         pinfo.last_handshake = Some(SystemTime::now());
//         pinfo.last_handshake_error = err.map(str::to_string);
//     }
// }
