use serde::{Deserialize, Serialize};

use super::{block_body::BlockBody, block_header::BlockHeader};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TransferBlock {
    pub header: BlockHeader,
    pub body: BlockBody,
}
