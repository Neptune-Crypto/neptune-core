use super::{
    blockchain::{Block, BlockHash, BlockHeight},
    shared::LatestBlockInfo,
};
use crate::config_models::network::Network;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, time::SystemTime};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Peer {
    pub address: SocketAddr,
    pub banscore: u8,
    pub instance_id: u128,
    pub inbound: bool,
    pub last_seen: SystemTime,
    pub version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HandshakeData {
    pub latest_block_info: Option<LatestBlockInfo>,
    pub listen_address: Option<SocketAddr>,
    pub network: Network,
    pub instance_id: u128,
    pub version: String,
}

/// Used to tell peers that a new block has been found without having to
/// send the entire block
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PeerBlockNotification {
    pub hash: BlockHash,
    pub height: BlockHeight,
}

impl From<Block> for PeerBlockNotification {
    fn from(block: Block) -> Self {
        PeerBlockNotification {
            hash: block.hash,
            height: block.height,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum ConnectionRefusedReason {
    AlreadyConnected,
    MaxPeerNumberExceeded,
    SelfConnect,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum ConnectionStatus {
    Refused(ConnectionRefusedReason),
    Accepted,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum PeerMessage {
    Handshake((Vec<u8>, HandshakeData)),
    Block(Box<Block>),
    BlockNotification(PeerBlockNotification),
    BlockRequestByHeight(BlockHeight),
    BlockResponseByHeight(Option<Box<Block>>),
    BlockRequestByHash(BlockHash),
    BlockResponseByHash(Option<Box<Block>>),
    NewTransaction(i32),
    PeerListRequest,
    PeerListResponse(Vec<SocketAddr>),
    Bye,
    ConnectionStatus(ConnectionStatus),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerStateData {
    pub highest_shared_block_height: BlockHeight,
}
