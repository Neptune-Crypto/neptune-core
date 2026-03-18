use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::application::json_rpc::core::model::block::appendix::RpcBlockAppendix;
use crate::application::json_rpc::core::model::block::body::RpcBlockBody;
use crate::application::json_rpc::core::model::block::header::RpcBlockHeader;
use crate::application::json_rpc::core::model::common::RpcBFieldElements;
use crate::protocol::consensus::block::block_appendix::BlockAppendix;
use crate::protocol::consensus::block::block_body::BlockBody;
use crate::protocol::consensus::block::block_header::BlockHeader;
use crate::protocol::consensus::block::block_kernel::BlockKernel;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::block::BlockProof;
use crate::protocol::proof_abstractions::mast_hash::MastHash;

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
        BlockKernel {
            header: BlockHeader::from(value.header),
            body: BlockBody::from(value.body),
            appendix: BlockAppendix::from(value.appendix),
        }
    }
}

impl From<&BlockKernel> for RpcBlockKernel {
    fn from(kernel: &BlockKernel) -> Self {
        RpcBlockKernel {
            header: RpcBlockHeader::from(&kernel.header),
            body: RpcBlockBody::from(&kernel.body),
            appendix: RpcBlockAppendix::from(&kernel.appendix),
        }
    }
}

pub type RpcBlockProof = Option<RpcBFieldElements>;

impl From<&BlockProof> for RpcBlockProof {
    fn from(proof: &BlockProof) -> Self {
        match proof {
            BlockProof::Genesis | BlockProof::Invalid => None,
            BlockProof::SingleProof(proof) => Some(proof.0.clone().into()),
        }
    }
}

impl From<RpcBlockProof> for BlockProof {
    fn from(proof: RpcBlockProof) -> Self {
        match proof {
            None => BlockProof::Invalid,
            Some(bfes) => BlockProof::SingleProof(bfes.0.into()),
        }
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
            proof: RpcBlockProof::from(&block.proof),
        }
    }
}

impl From<RpcBlock> for Block {
    fn from(block: RpcBlock) -> Self {
        Block::new(
            block.kernel.header.into(),
            block.kernel.body.into(),
            block.kernel.appendix.into(),
            block.proof.into(),
        )
    }
}
