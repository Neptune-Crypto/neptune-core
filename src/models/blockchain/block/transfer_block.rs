use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::proof::Proof;

use super::block_appendix::BlockAppendix;
use super::block_body::BlockBody;
use super::block_header::BlockHeader;

/// Data structure for communicating blocks with peers. The hash digest is not
/// communicated such that the receiver is forced to calculate it themselves.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Eq)]
pub struct TransferBlock {
    pub header: BlockHeader,
    pub body: BlockBody,
    pub(crate) appendix: BlockAppendix,
    pub proof: Proof,
}
