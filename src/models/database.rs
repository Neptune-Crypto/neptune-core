use crate::database::{leveldb::LevelDB, rusty::RustyLevelDB};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr};
use twenty_first::shared_math::b_field_element::BFieldElement;

use super::{
    blockchain::{
        block::{block_header::BlockHeader, block_height::BlockHeight, Block},
        digest::{Digest, Hashable},
    },
    peer::PeerStanding,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileLocation {
    pub file_index: u32,
    pub offset: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockRecord {
    pub block_header: BlockHeader,
    pub file_location: FileLocation,
    pub tx_count: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileRecord {
    blocks_in_file_count: u32,
    file_size: u64,

    // min and max block height in file, both inclusive
    min_block_height: BlockHeight,
    max_block_height: BlockHeight,

    // min and max block timestamp in file, both inclusive
    min_block_timestamp: BFieldElement,
    max_block_timestamp: BFieldElement,
}

impl FileRecord {
    /// Get a file record representing a single block stored in the file
    pub fn new(block_size: u64, block_header: &BlockHeader) -> Self {
        Self {
            blocks_in_file_count: 1,
            file_size: block_size,
            min_block_height: block_header.height,
            max_block_height: block_header.height,
            min_block_timestamp: block_header.timestamp,
            max_block_timestamp: block_header.timestamp,
        }
    }

    /// Return a new file record describing the file after having added a new block to file
    pub fn add(&self, block_size: u64, block_header: &BlockHeader) -> Self {
        let mut ret = self.to_owned();
        ret.blocks_in_file_count += 1;
        ret.file_size += block_size;
        ret.min_block_height = std::cmp::min(self.max_block_height, block_header.height);
        ret.max_block_height = std::cmp::max(self.max_block_height, block_header.height);
        ret.min_block_timestamp = std::cmp::min_by(
            ret.min_block_timestamp,
            block_header.timestamp,
            |x: &BFieldElement, y: &BFieldElement| x.value().cmp(&y.value()),
        );
        ret.max_block_timestamp = std::cmp::max_by(
            ret.min_block_timestamp,
            block_header.timestamp,
            |x: &BFieldElement, y: &BFieldElement| x.value().cmp(&y.value()),
        );
        ret
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct LastRecord {
    pub last_file: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BlockIndexKey {
    BlockRecord(Digest),       // points to block headers and file locations
    FileRecord(u32),           // points to file information
    HeightRecord(BlockHeight), // Maps from block height to list of blocks
    LastRecord,                // points to last file used
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BlockIndexValue {
    BlockRecord(BlockRecord),
    FileRecord(FileRecord),
    HeightRecord(Vec<Digest>),
    LastRecord(LastRecord),
}

impl BlockIndexValue {
    pub fn as_block_record(&self) -> BlockRecord {
        match self {
            BlockIndexValue::BlockRecord(rec) => rec.to_owned(),
            BlockIndexValue::FileRecord(_) => panic!("Requested block record, found FileRecord"),
            BlockIndexValue::HeightRecord(_) => {
                panic!("Requested block record, found HeightRecord")
            }
            BlockIndexValue::LastRecord(_) => panic!("Requested block record, found LastRecord"),
        }
    }

    pub fn as_file_record(&self) -> FileRecord {
        match self {
            BlockIndexValue::BlockRecord(_) => panic!("Requested file record, found BlockRecord"),
            BlockIndexValue::FileRecord(rec) => rec.to_owned(),
            BlockIndexValue::HeightRecord(_) => {
                panic!("Requested file record, found HeightRecord")
            }
            BlockIndexValue::LastRecord(_) => panic!("Requested file record, found LastRecord"),
        }
    }

    pub fn as_height_record(&self) -> Vec<Digest> {
        match self {
            BlockIndexValue::BlockRecord(_) => {
                panic!("Requested height record, found BlockRecord")
            }
            BlockIndexValue::FileRecord(_) => panic!("Requested height record, found FileRecord"),
            BlockIndexValue::HeightRecord(rec) => rec.to_owned(),
            BlockIndexValue::LastRecord(_) => panic!("Requested height record, found LastRecord"),
        }
    }

    pub fn as_last_record(&self) -> LastRecord {
        match self {
            BlockIndexValue::BlockRecord(_) => panic!("Requested last record, found BlockRecord"),
            BlockIndexValue::FileRecord(_) => panic!("Requested last record, found FileRecord"),
            BlockIndexValue::HeightRecord(_) => {
                panic!("Requested last record, found HeightRecord")
            }
            BlockIndexValue::LastRecord(rec) => rec.to_owned(),
        }
    }
}

pub struct BlockDatabases {
    pub block_height_to_hash: RustyLevelDB<BlockHeight, Digest>,
    pub block_hash_to_block: RustyLevelDB<Digest, Block>,
    pub latest_block_header: RustyLevelDB<(), BlockHeader>,
    pub block_index: RustyLevelDB<BlockIndexKey, BlockIndexValue>,
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
