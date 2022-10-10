use serde::{Deserialize, Serialize};

use super::{block_body::BlockBody, block_header::BlockHeader};

/// Data structure for communicating blocks with peers. The hash digest is not
/// communicated such that the receiver is forced to calculate it themselves.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferBlock {
    pub header: BlockHeader,
    pub body: BlockBody,
}
