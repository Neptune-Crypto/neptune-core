use std::time::SystemTime;

use arraystring::typenum::U255;
use arraystring::typenum::U30;
use arraystring::ArrayString;
use serde::Deserialize;
use serde::Serialize;

use crate::application::config::network::Network;
use crate::protocol::consensus::block::block_header::BlockHeader;

pub(crate) type VersionString = ArrayString<U30>;
pub(crate) type ExtraDataString = ArrayString<U255>;

/// Datastruct defining the handshake peers exchange when establishing a new
/// connection.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct HandshakeData {
    pub tip_header: BlockHeader,
    pub listen_port: Option<u16>,
    pub network: Network,
    pub instance_id: u128,
    pub version: VersionString,
    pub is_archival_node: bool,

    /// Indicates whether node acts as a bootstrapping node in a network
    /// context.
    pub is_bootstrapper_node: bool,

    /// Client's timestamp when the handshake was generated. Can be used to
    /// compare own timestamp to peer's or to a list of peers.
    pub timestamp: SystemTime,

    /// Use this field to add extra data in a backwards compatible manner. An
    /// encoding should be selected for this. Currently unused.
    pub extra_data: ExtraDataString,
}
