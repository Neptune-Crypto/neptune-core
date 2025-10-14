use crate::{
    application::json_rpc::core::model::common::RpcBFieldElements,
    protocol::consensus::block::BlockProof,
};

pub mod header;
pub mod transaction_kernel;

pub type RpcBlockProof = Option<RpcBFieldElements>;

impl From<BlockProof> for RpcBlockProof {
    fn from(proof: BlockProof) -> Self {
        match proof {
            BlockProof::Genesis | BlockProof::Invalid => None,
            BlockProof::SingleProof(proof) => Some(proof.0.clone().into()),
        }
    }
}
