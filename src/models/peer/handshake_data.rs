use serde::Deserialize;
use serde::Serialize;

use crate::config_models::network::Network;
use crate::models::blockchain::block::block_header::BlockHeader;

/// Datastruct defining the handshake peers exchange when establishing a new
/// connection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct HandshakeData {
    pub tip_header: BlockHeader,
    pub listen_port: Option<u16>,
    pub network: Network,
    pub instance_id: u128,
    pub version: String,
    pub is_archival_node: bool,
}
