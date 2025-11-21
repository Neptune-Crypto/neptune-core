use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::proof::Claim;

use crate::application::json_rpc::core::model::block::body::RpcBlockBody;
use crate::application::json_rpc::core::model::block::header::RpcBlockHeader;
use crate::application::json_rpc::core::model::common::RpcBFieldElements;
use crate::protocol::consensus::block::block_appendix::BlockAppendix;
use crate::protocol::consensus::block::block_kernel::BlockKernel;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::block::BlockProof;

pub mod body;
pub mod header;
pub mod transaction_kernel;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcClaim {
    pub program_digest: Digest,
    pub version: u32,
    pub input: RpcBFieldElements,
    pub output: RpcBFieldElements,
}

impl From<Claim> for RpcClaim {
    fn from(claim: Claim) -> Self {
        RpcClaim {
            program_digest: claim.program_digest,
            version: claim.version,
            input: claim.input.into(),
            output: claim.output.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcBlockAppendix(Vec<RpcClaim>);

impl From<&BlockAppendix> for RpcBlockAppendix {
    fn from(appendix: &BlockAppendix) -> Self {
        RpcBlockAppendix(
            appendix
                ._claims()
                .clone()
                .into_iter()
                .map(Into::into)
                .collect(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockKernel {
    pub header: RpcBlockHeader,
    pub body: RpcBlockBody,
    pub appendix: RpcBlockAppendix,
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
