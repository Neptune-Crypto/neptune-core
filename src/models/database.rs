use crate::database::rusty::RustyLevelDB;
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr};
use twenty_first::shared_math::b_field_element::BFieldElement;

use super::{
    blockchain::{
        block::{block_header::BlockHeader, block_height::BlockHeight, Block},
        digest::Digest,
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
pub struct LastFileRecord {
    pub last_file: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BlockIndexKey {
    Block(Digest),       // points to block headers and file locations
    File(u32),           // points to file information
    Height(BlockHeight), // Maps from block height to list of blocks
    LastFile,            // points to last file used
    BlockTipDigest,      // points to block digest of most canonical block known
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BlockIndexValue {
    Block(Box<BlockRecord>),
    File(FileRecord),
    Height(Vec<Digest>),
    LastFile(LastFileRecord),
    BlockTipDigest(Digest),
}

impl BlockIndexValue {
    pub fn as_block_record(&self) -> BlockRecord {
        match self {
            BlockIndexValue::Block(rec) => *rec.to_owned(),
            _ => panic!("Requested BlockTipDigest, found {:?}", self),
        }
    }

    pub fn as_file_record(&self) -> FileRecord {
        match self {
            BlockIndexValue::File(rec) => rec.to_owned(),
            _ => panic!("Requested BlockTipDigest, found {:?}", self),
        }
    }

    pub fn as_height_record(&self) -> Vec<Digest> {
        match self {
            BlockIndexValue::Height(rec) => rec.to_owned(),
            _ => panic!("Requested BlockTipDigest, found {:?}", self),
        }
    }

    pub fn as_last_file_record(&self) -> LastFileRecord {
        match self {
            BlockIndexValue::LastFile(rec) => rec.to_owned(),
            _ => panic!("Requested BlockTipDigest, found {:?}", self),
        }
    }

    pub fn as_tip_digest(&self) -> Digest {
        match self {
            BlockIndexValue::BlockTipDigest(digest) => digest.to_owned(),
            _ => panic!("Requested BlockTipDigest, found {:?}", self),
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
