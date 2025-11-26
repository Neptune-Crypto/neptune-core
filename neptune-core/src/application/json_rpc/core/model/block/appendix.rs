use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::proof::Claim;

use crate::application::json_rpc::core::model::common::RpcBFieldElements;
use crate::protocol::consensus::block::block_appendix::BlockAppendix;

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

impl From<RpcClaim> for Claim {
    fn from(claim: RpcClaim) -> Self {
        Claim {
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

impl From<RpcBlockAppendix> for BlockAppendix {
    fn from(appendix: RpcBlockAppendix) -> Self {
        BlockAppendix::new(appendix.0.into_iter().map(Into::into).collect())
    }
}
