use neptune_consensus::block::block_appendix::BlockAppendix;
use neptune_consensus::block::block_body::BlockBody;
use neptune_consensus::block::block_header::BlockHeader;
use neptune_consensus::block::block_kernel::BlockKernel;
use neptune_consensus::block::Block;
use neptune_consensus::block::BlockProof;
use neptune_primitives::mast_hash::MastHash;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::application::json_rpc::core::model::block::appendix::RpcBlockAppendix;
use crate::application::json_rpc::core::model::block::body::RpcBlockBody;
use crate::application::json_rpc::core::model::block::header::RpcBlockHeader;
use crate::application::json_rpc::core::model::common::RpcBFieldElements;

pub mod appendix;
pub mod body;
pub mod header;
pub mod transaction_kernel;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockKernel {
    pub header: RpcBlockHeader,
    pub body: RpcBlockBody,
    pub appendix: RpcBlockAppendix,
}

impl RpcBlockKernel {
    /// Mast hash of the block kernel
    pub fn mast_hash(&self) -> Digest {
        let kernel: BlockKernel = self.to_owned().into();
        kernel.mast_hash()
    }
}

impl From<RpcBlockKernel> for BlockKernel {
    fn from(value: RpcBlockKernel) -> Self {
        BlockKernel::new(
            BlockHeader::from(value.header),
            BlockBody::from(value.body),
            BlockAppendix::from(value.appendix),
        )
    }
}

impl From<&BlockKernel> for RpcBlockKernel {
    fn from(kernel: &BlockKernel) -> Self {
        RpcBlockKernel {
            header: RpcBlockHeader::from(&kernel.header),
            body: RpcBlockBody::from(&kernel.body),
            appendix: RpcBlockAppendix::from(kernel.appendix()),
        }
    }
}

pub type RpcBlockProof = Option<RpcBFieldElements>;

/// Convert a consensus [`BlockProof`] into its RPC representation.
pub fn rpc_block_proof_from(proof: &BlockProof) -> RpcBlockProof {
    match proof {
        BlockProof::Genesis | BlockProof::Invalid => None,
        BlockProof::SingleProof(proof) => Some(proof.0.clone().into()),
    }
}

/// Convert an RPC block proof into the consensus [`BlockProof`].
pub fn block_proof_from_rpc(proof: RpcBlockProof) -> BlockProof {
    match proof {
        None => BlockProof::Invalid,
        Some(bfes) => BlockProof::SingleProof(bfes.0.into()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlock {
    pub kernel: RpcBlockKernel,
    pub proof: RpcBlockProof,
}

impl From<&Block> for RpcBlock {
    fn from(block: &Block) -> Self {
        RpcBlock {
            kernel: RpcBlockKernel::from(&block.kernel),
            proof: rpc_block_proof_from(&block.proof),
        }
    }
}

impl From<RpcBlock> for Block {
    fn from(block: RpcBlock) -> Self {
        Block::new(
            block.kernel.header.into(),
            block.kernel.body.into(),
            block.kernel.appendix.into(),
            block_proof_from_rpc(block.proof),
        )
    }
}
