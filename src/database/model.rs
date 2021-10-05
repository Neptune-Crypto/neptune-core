pub use super::block_hash_to_block::BlockHash;
pub use super::block_height_to_hash::BlockHeight;
use leveldb::database::Database;

pub struct Databases {
    pub block_height_to_hash: Database<BlockHeight>,
    pub block_hash_to_block: Database<BlockHash>,
}
