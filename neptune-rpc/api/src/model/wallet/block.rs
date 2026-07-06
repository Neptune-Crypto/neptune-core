use neptune_consensus::block::Block;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldCodec;

use crate::model::block::RpcBlockKernel;

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

impl RpcWalletBlock {
    pub fn hash(&self) -> Digest {
        Tip5::hash_pair(
            Tip5::hash_varlen(&self.kernel.mast_hash().encode()),
            self.proof_leaf,
        )
    }
}
