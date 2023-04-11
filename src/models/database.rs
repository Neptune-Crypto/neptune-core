use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{fmt, net::IpAddr};
use twenty_first::shared_math::rescue_prime_digest::Digest;
use twenty_first::util_types::storage_schema::RustyValue;

use mutator_set_tf::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use twenty_first::shared_math::b_field_element::BFieldElement;

use super::blockchain::block::block_header::BlockHeader;
use super::blockchain::block::block_height::BlockHeight;
use super::blockchain::block::Block;
use super::blockchain::transaction::utxo::Utxo;
use super::peer::PeerStanding;
use crate::database::rusty::RustyLevelDB;
use crate::models::blockchain::shared::Hash;

pub const DATABASE_DIRECTORY_ROOT_NAME: &str = "databases";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockFileLocation {
    pub file_index: u32,
    pub offset: u64,
    pub block_length: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockRecord {
    pub block_header: BlockHeader,
    pub file_location: BlockFileLocation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileRecord {
    pub blocks_in_file_count: u32,
    pub file_size: u64,

    // min and max block height in file, both inclusive
    pub min_block_height: BlockHeight,
    pub max_block_height: BlockHeight,

    // min and max block timestamp in file, both inclusive
    pub min_block_timestamp: BFieldElement,
    pub max_block_timestamp: BFieldElement,
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

pub struct PeerDatabases {
    pub peer_standings: RustyLevelDB<IpAddr, PeerStanding>,
}

impl fmt::Debug for PeerDatabases {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("").finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredUtxo {
    pub utxo: Utxo,

    // if we have a membership proof, which block is it synced to?
    pub sync_digest: Digest,

    // we might not have a membership proof
    pub membership_proof: Option<MsMembershipProof<Hash>>,

    // hash of the block, if any, in which this UTXO was spent
    pub spent_in_block: Option<(Digest, Duration)>,

    // hash of the block, if any, in which this UTXO was confirmed
    pub confirmed_in_block: Option<(Digest, Duration)>,
}

impl MonitoredUtxo {
    pub fn new(utxo: Utxo) -> Self {
        Self {
            utxo,
            sync_digest: Digest::default(),
            membership_proof: None,
            spent_in_block: None,
            confirmed_in_block: None,
        }
    }

    // determine whether the attached membership proof is synced to the given block
    pub fn is_synced_to(&self, block: &Block) -> bool {
        self.sync_digest == block.hash
    }
}

impl From<RustyValue> for MonitoredUtxo {
    fn from(value: RustyValue) -> Self {
        bincode::deserialize(&value.0).expect(
            "failed to deserialize database object to monitored utxo; database seems corrupted",
        )
    }
}

impl From<MonitoredUtxo> for RustyValue {
    fn from(value: MonitoredUtxo) -> Self {
        RustyValue(bincode::serialize(&value).expect("Totally nonsensical that serialize can fail, but that is how the interface has been defined."))
    }
}
