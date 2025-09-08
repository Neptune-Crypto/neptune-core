use std::fmt;
use std::net::IpAddr;

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::twenty_first::tip5::digest::Digest;

use crate::application::database::NeptuneLevelDb;
use crate::protocol::consensus::block::block_header::BlockHeader;
use crate::protocol::consensus::block::block_header::HeaderToBlockHashWitness;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::peer::PeerStanding;
use crate::protocol::proof_abstractions::timestamp::Timestamp;

pub const DATABASE_DIRECTORY_ROOT_NAME: &str = "databases";

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct BlockFileLocation {
    pub file_index: u32,
    pub offset: u64,
    pub block_length: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockRecord {
    pub block_header: BlockHeader,
    pub file_location: BlockFileLocation,

    /// First AOCL index for this block's outputs
    pub min_aocl_index: u64,

    /// The number of addition records in this block
    pub num_additions: u64,

    /// The data missing from BlockHeader in order to calculate the block hash.
    pub(crate) block_hash_witness: HeaderToBlockHashWitness,
}

impl BlockRecord {
    /// The last AOCL index for this block's outputs. This addition record *is*
    /// contained in this block.
    pub fn max_aocl_index(&self) -> u64 {
        // If the genesis block has any outputs (any premine), this is
        // guaranteed to not overflow.
        self.min_aocl_index + self.num_additions - 1
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub blocks_in_file_count: u32,
    pub file_size: u64,

    // min and max block height in file, both inclusive
    pub min_block_height: BlockHeight,
    pub max_block_height: BlockHeight,

    // min and max block timestamp in file, both inclusive
    pub min_block_timestamp: Timestamp,
    pub max_block_timestamp: Timestamp,
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
        ret.min_block_timestamp =
            std::cmp::min_by(ret.min_block_timestamp, block_header.timestamp, |x, y| {
                x.cmp(y)
            });
        ret.max_block_timestamp =
            std::cmp::max_by(ret.min_block_timestamp, block_header.timestamp, |x, y| {
                x.cmp(y)
            });
        ret
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct LastFileRecord {
    pub last_file: u32,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum BlockIndexKey {
    Block(Digest),       // points to block headers and file locations
    File(u32),           // points to file information
    Height(BlockHeight), // Maps from block height to list of blocks
    LastFile,            // points to last file used

    // Tip-hash could also be fetched from archival block MMR instead. Maybe
    // this key is superfluous?
    BlockTipDigest, // points to block digest of most canonical block known
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

#[derive(Clone)]
pub struct PeerDatabases {
    pub peer_standings: NeptuneLevelDb<IpAddr, PeerStanding>,
}

impl fmt::Debug for PeerDatabases {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("").finish()
    }
}
