use std::time::SystemTime;

use arraystring::typenum::U30;
use arraystring::ArrayString;
use serde::Deserialize;
use serde::Serialize;

use crate::config_models::network::Network;
use crate::models::blockchain::block::block_header::BlockHeader;

pub(crate) type VersionString = ArrayString<U30>;

/// Datastruct defining the handshake peers exchange when establishing a new
/// connection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct HandshakeData {
    pub tip_header: BlockHeader,
    pub listen_port: Option<u16>,
    pub network: Network,
    pub instance_id: u128,
    pub version: VersionString,
    pub is_archival_node: bool,

    /// Client's timestamp when the handshake was generated. Can be used to
    /// compare own timestamp to peer's or to a list of peers.
    pub timestamp: SystemTime,
}
