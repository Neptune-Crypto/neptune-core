use super::{
    blockchain::{
        block::{Block, BlockBody, BlockHeader, BlockHeight, TransferBlock},
        digest::RescuePrimeDigest,
    },
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

/// Used to tell peers that a new block has been found without having toPeerMessage
/// send the entire block
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PeerBlockNotification {
    pub hash: RescuePrimeDigest,
    pub height: BlockHeight,
}

impl From<Block> for PeerBlockNotification {
    fn from(block: Block) -> Self {
        PeerBlockNotification {
            hash: block.hash,
            height: block.header.height,
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

// #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PeerMessage {
    Handshake((Vec<u8>, HandshakeData)),
    Block(Box<TransferBlock>),
    BlockNotification(PeerBlockNotification),
    BlockRequestByHeight(BlockHeight),
    BlockResponseByHeight(Option<Box<TransferBlock>>),
    BlockRequestByHash(RescuePrimeDigest),
    BlockResponseByHash(Option<Box<TransferBlock>>),
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
