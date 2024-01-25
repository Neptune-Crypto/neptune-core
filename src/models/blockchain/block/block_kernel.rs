use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::twenty_first::shared_math::{bfield_codec::BFieldCodec, tip5::Digest};

use super::{block_body::BlockBody, block_header::BlockHeader};

/// The kernel of a block contains all data that is not proof data
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize)]
pub struct BlockKernel {
    pub header: BlockHeader,
    pub body: BlockBody,
}
impl BlockKernel {
    pub(crate) fn mast_hash(&self) -> Digest {
        todo!()
    }
}
