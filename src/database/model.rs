use std::fmt;

pub use super::block_hash_to_block::BlockHash;
pub use super::block_height_to_hash::BlockHeight;
use leveldb::database::Database;

pub struct Databases {
    pub block_height_to_hash: Database<BlockHeight>,
    pub block_hash_to_block: Database<BlockHash>,
}

// We have to implement `Debug` for `Databases` as the `State` struct
// contains a database object, and `State` is used as input argument
// to multiple functions where logging is enabled with the `instrument`
// attributes from the `tracing` crate, and this requires all input
// arguments to the function to implement the `Debug` trait as this
// info is written on all logging events.
impl fmt::Debug for Databases {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("").finish()
    }
}
