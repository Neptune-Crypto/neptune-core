use anyhow::{bail, Result};
use db_key::Key;
use leveldb::{database::Database, kv::KV, options::ReadOptions};
use std::fmt;

use super::blockchain::{
    block::{block_header::BlockHeader, block_height::BlockHeight, Block},
    digest::{keyable_digest::KeyableDigest, Hashable},
};

pub struct Databases {
    pub block_height_to_hash: Database<BlockHeight>,
    pub block_hash_to_block: Database<KeyableDigest>,
    pub latest_block_header: Database<DatabaseUnit>,
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

#[derive(Clone, Copy, Debug)]
pub struct DatabaseUnit();
impl Key for DatabaseUnit {
    fn from_u8(_key: &[u8]) -> Self {
        DatabaseUnit()
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        f(&[])
    }
}

impl Databases {
    /// Given a mutex lock on the database, return the latest block
    pub fn get_latest_block(
        databases: tokio::sync::MutexGuard<Databases>,
    ) -> Result<Option<Block>> {
        let bytes = databases
            .latest_block_header
            .get(ReadOptions::new(), DatabaseUnit())
            .expect("Failed to get latest block info on init");
        let block_header_res: Option<BlockHeader> = bytes.map(|bts| {
            bincode::deserialize(&bts).expect("Failed to deserialize latest block info")
        });
        let block_header = match block_header_res {
            None => return Ok(None),
            Some(bh) => bh,
        };

        let block_bytes: Option<Vec<u8>> = databases
            .block_hash_to_block
            .get::<KeyableDigest>(ReadOptions::new(), block_header.hash().into())?;
        let block: Block = match block_bytes {
            None => {
                bail!("Database entry for block_hash_to_block must be set for block header found in latest_block_header");
            }
            Some(bytes) => bincode::deserialize(&bytes)
                .expect("Failed to deserialize block from block_hash_to_block"),
        };

        Ok(Some(block))
    }
}
