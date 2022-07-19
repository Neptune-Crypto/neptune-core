use crate::database::{leveldb::LevelDB, rusty::RustyLevelDB};
use anyhow::{Context, Result};
use std::{fmt, net::IpAddr};

use super::{
    blockchain::{
        block::{block_header::BlockHeader, block_height::BlockHeight, Block},
        digest::{Digest, Hashable},
    },
    peer::PeerStanding,
};

pub struct BlockDatabases {
    pub block_height_to_hash: RustyLevelDB<BlockHeight, Digest>,
    pub block_hash_to_block: RustyLevelDB<Digest, Block>,
    pub latest_block_header: RustyLevelDB<(), BlockHeader>,
}

pub struct PeerDatabases {
    pub peer_standings: RustyLevelDB<IpAddr, PeerStanding>,
}

// We have to implement `Debug` for `Databases` as the `State` struct
// contains a database object, and `State` is used as input argument
// to multiple functions where logging is enabled with the `instrument`
// attributes from the `tracing` crate, and this requires all input
// arguments to the function to implement the `Debug` trait as this
// info is written on all logging events.
impl fmt::Debug for BlockDatabases {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("").finish()
    }
}

impl fmt::Debug for PeerDatabases {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("").finish()
    }
}

impl BlockDatabases {
    /// Given a mutex lock on the database, return the latest block
    pub fn get_latest_block(
        databases: &mut tokio::sync::MutexGuard<BlockDatabases>,
    ) -> Result<Option<Block>> {
        let block_header_res = databases.latest_block_header.get(());
        let block_header = match block_header_res {
            None => return Ok(None),
            Some(bh) => bh,
        };

        let block = databases
            .block_hash_to_block
            .get(block_header.hash())
            .context("Database entry for block_hash_to_block must be set for block header found in latest_block_header")?;

        Ok(Some(block))
    }
}
