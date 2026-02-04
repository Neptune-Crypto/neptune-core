use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldCodec;

use crate::application::json_rpc::core::model::block::RpcBlockKernel;
use crate::protocol::consensus::block::Block;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcWalletBlock {
    pub kernel: RpcBlockKernel,
    pub proof_leaf: Digest,
}

impl From<&Block> for RpcWalletBlock {
    fn from(block: &Block) -> Self {
        RpcWalletBlock {
            kernel: RpcBlockKernel::from(&block.kernel),
            proof_leaf: Tip5::hash_varlen(&block.proof.encode()),
        }
    }
}
