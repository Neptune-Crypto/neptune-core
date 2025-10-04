use serde::Deserialize;
use serde::Serialize;

use crate::application::json_rpc::core::model::block::body::RpcBlockBody;
use crate::application::json_rpc::core::model::block::header::RpcBlockHeader;
use crate::application::json_rpc::core::model::common::RpcBFieldElements;
use crate::protocol::consensus::block::block_kernel::BlockKernel;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::block::BlockProof;

pub mod body;
pub mod header;
pub mod transaction_kernel;

pub type RpcBlockProof = Option<RpcBFieldElements>;

impl From<&BlockProof> for RpcBlockProof {
    fn from(proof: &BlockProof) -> Self {
        match proof {
            BlockProof::Genesis | BlockProof::Invalid => None,
            BlockProof::SingleProof(proof) => Some(proof.0.clone().into()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockKernel {
    pub header: RpcBlockHeader,
    pub body: RpcBlockBody,
}

impl From<&BlockKernel> for RpcBlockKernel {
    fn from(kernel: &BlockKernel) -> Self {
        RpcBlockKernel {
            header: RpcBlockHeader::from(&kernel.header),
            body: RpcBlockBody::from(&kernel.body),
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
