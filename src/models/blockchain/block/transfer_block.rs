use serde::{Deserialize, Serialize};
use tasm_lib::triton_vm::proof::Proof;

use super::{block_body::BlockBody, block_header::BlockHeader};

/// Data structure for communicating blocks with peers. The hash digest is not
/// communicated such that the receiver is forced to calculate it themselves.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Eq)]
pub struct TransferBlock {
    pub header: BlockHeader,
    pub body: BlockBody,
    pub proof: Proof,
}
