use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::triton_vm::proof::Proof;

use super::{block_body::BlockBody, block_header::BlockHeader};
use crate::models::blockchain::block::BFieldCodec;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Eq, BFieldCodec, GetSize)]
pub enum ProofType {
    Unimplemented, // temporary, can should be removed once all Proof's are implemented.
    Proof(Proof),
}

/// Data structure for communicating blocks with peers. The hash digest is not
/// communicated such that the receiver is forced to calculate it themselves.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Eq)]
pub struct TransferBlock {
    pub header: BlockHeader,
    pub body: BlockBody,
    pub proof_type: ProofType,
}
