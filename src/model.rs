use super::config_models::network::Network;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::SystemTime;

use crate::big_array::BigArray;

type BlockHeight = u64;
type BlockHash = [u8; 32];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HandshakeData {
    pub listen_address: Option<SocketAddr>,
    pub network: Network,
    pub version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Utxo {
    #[serde(with = "BigArray")]
    pub pol0: [u32; 2048],
    #[serde(with = "BigArray")]
    pub pol1: [u32; 2048],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    pub input: Vec<Utxo>,
    pub output: Vec<Utxo>,
    pub public_scripts: Vec<Vec<u8>>,
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Block {
    pub version_bits: [u8; 4],
    pub timestamp: SystemTime,
    pub height: BlockHeight,
    pub nonce: [u8; 32],
    pub predecessor: BlockHash,
    pub predecessor_proof: Vec<u8>,
    pub accumulated_pow_line: u128,
    pub accumulated_pow_family: u128,
    pub uncles: Vec<BlockHash>,
    pub target_difficulty: u128,
    pub retarget_proof: Vec<u8>,
    pub transaction: Transaction,
    pub mixed_edges: Vec<Utxo>,
    pub mix_proof: Vec<u8>,
    pub edge_mmra: Utxo,
    pub edge_mmra_update: Vec<u8>,
    pub hash: BlockHash,
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

#[derive(Clone, Debug)]
pub enum ToMiner {
    Empty,
    NewBlock(Box<Block>),
}

#[derive(Clone, Debug)]
pub enum FromMinerToMain {
    NewBlock(Box<Block>),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum PeerMessage {
    Handshake((Vec<u8>, HandshakeData)),
    Block(Box<Block>),
    BlockNotification(PeerBlockNotification),
    BlockRequestByHeight(BlockHeight),
    BlockRequestByHash(BlockHash),
    NewTransaction(i32),
    PeerListRequest,
    PeerListResponse(Vec<SocketAddr>),
    Bye,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerStateData {
    pub highest_shared_block_height: BlockHeight,
}

#[derive(Clone, Debug)]
pub enum MainToPeerThread {
    NewBlock(Box<Block>),
    NewTransaction(i32),
}

#[derive(Clone, Debug)]
pub enum PeerThreadToMain {
    NewBlock(Box<Block>),
    NewTransaction(i32),
}
