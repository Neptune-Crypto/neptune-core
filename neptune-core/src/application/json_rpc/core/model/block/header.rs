use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::api::export::Timestamp;
use crate::protocol::consensus::block::block_header::BlockHeader;
use crate::protocol::consensus::block::block_header::BlockPow;
use crate::protocol::consensus::block::guesser_receiver_data::GuesserReceiverData;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockPow {
    pub root: Digest,
    pub path_a: Vec<Digest>,
    pub path_b: Vec<Digest>,
    pub nonce: Digest,
}

impl From<BlockPow> for RpcBlockPow {
    fn from(pow: BlockPow) -> Self {
        Self {
            root: pow.root,
            path_a: pow.path_a.to_vec(),
            path_b: pow.path_b.to_vec(),
            nonce: pow.nonce,
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockHeader {
    pub version: BFieldElement,
    pub height: BFieldElement,
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
            height: header.height.into(),
            prev_block_digest: header.prev_block_digest,
            timestamp: header.timestamp,
            pow: header.pow.into(),
            cumulative_proof_of_work: header.cumulative_proof_of_work.to_string(),
            difficulty: header.difficulty.to_string(),
            guesser_receiver_data: header.guesser_receiver_data.into(),
        }
    }
}
