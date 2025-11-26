use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::api::export::BlockHeight;
use crate::api::export::Timestamp;
use crate::protocol::consensus::block::block_header::BlockHeader;
use crate::protocol::consensus::block::block_header::BlockPow;
use crate::protocol::consensus::block::difficulty_control::Difficulty;
use crate::protocol::consensus::block::difficulty_control::ProofOfWork;
use crate::protocol::consensus::block::guesser_receiver_data::GuesserReceiverData;
use crate::protocol::consensus::block::pow::POW_MEMORY_TREE_HEIGHT;

// TODO: Mirror consensus impl
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockPow {
    pub root: Digest,
    #[serde(with = "serde_arrays")]
    pub path_a: [Digest; POW_MEMORY_TREE_HEIGHT],
    #[serde(with = "serde_arrays")]
    pub path_b: [Digest; POW_MEMORY_TREE_HEIGHT],
    pub nonce: Digest,
}

impl From<BlockPow> for RpcBlockPow {
    fn from(pow: BlockPow) -> Self {
        Self {
            root: pow.root,
            path_a: pow.path_a,
            path_b: pow.path_b,
            nonce: pow.nonce,
        }
    }
}

impl From<RpcBlockPow> for BlockPow {
    fn from(rpc: RpcBlockPow) -> Self {
        Self {
            root: rpc.root,
            path_a: rpc.path_a,
            path_b: rpc.path_b,
            nonce: rpc.nonce,
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RpcGuesserReceiverData {
    pub receiver_digest: Digest,
    pub lock_script_hash: Digest,
}

impl From<GuesserReceiverData> for RpcGuesserReceiverData {
    fn from(data: GuesserReceiverData) -> Self {
        RpcGuesserReceiverData {
            receiver_digest: data.receiver_digest,
            lock_script_hash: data.lock_script_hash,
        }
    }
}

impl From<RpcGuesserReceiverData> for GuesserReceiverData {
    fn from(rpc: RpcGuesserReceiverData) -> Self {
        Self {
            receiver_digest: rpc.receiver_digest,
            lock_script_hash: rpc.lock_script_hash,
        }
    }
}

pub type RpcBlockHeight = BlockHeight;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockHeader {
    pub version: BFieldElement,
    pub height: RpcBlockHeight,
    pub prev_block_digest: Digest,
    pub timestamp: Timestamp,
    pub pow: RpcBlockPow,
    pub cumulative_proof_of_work: String,
    pub difficulty: String,
    pub guesser_receiver_data: RpcGuesserReceiverData,
}

impl From<&BlockHeader> for RpcBlockHeader {
    fn from(header: &BlockHeader) -> Self {
        RpcBlockHeader {
            version: header.version,
            height: header.height,
            prev_block_digest: header.prev_block_digest,
            timestamp: header.timestamp,
            pow: header.pow.into(),
            cumulative_proof_of_work: header.cumulative_proof_of_work.to_string(),
            difficulty: header.difficulty.to_string(),
            guesser_receiver_data: header.guesser_receiver_data.into(),
        }
    }
}

impl From<RpcBlockHeader> for BlockHeader {
    fn from(header: RpcBlockHeader) -> Self {
        BlockHeader {
            version: header.version,
            height: header.height,
            prev_block_digest: header.prev_block_digest,
            timestamp: header.timestamp,
            pow: header.pow.into(),
            cumulative_proof_of_work: ProofOfWork::zero(), // TODO: proper handling...
            difficulty: Difficulty::from(0_u32),
            guesser_receiver_data: header.guesser_receiver_data.into(),
        }
    }
}
