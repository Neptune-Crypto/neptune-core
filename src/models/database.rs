use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, fmt, net::IpAddr};
use twenty_first::shared_math::rescue_prime_digest::Digest;

use mutator_set_tf::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use twenty_first::shared_math::b_field_element::BFieldElement;

use super::blockchain::block::block_header::BlockHeader;
use super::blockchain::block::block_height::BlockHeight;
use super::blockchain::transaction::utxo::Utxo;
use super::peer::PeerStanding;
use super::state::wallet::wallet_block_utxos::WalletBlockUtxos;
use crate::database::rusty::RustyLevelDB;
use crate::Hash;

pub const DATABASE_DIRECTORY_ROOT_NAME: &str = "databases";
const MAX_NUMBER_OF_MPS_STORED: usize = 500; // TODO: Move this to CLI config

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

#[derive(Debug, Serialize, Deserialize)]
pub enum WalletDbKey {
    SyncDigest,

    // digest represents a block hash
    WalletBlockUtxos(Digest),

    MonitoredUtxos,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredUtxo {
    pub utxo: Utxo,

    // Record a mapping from block hash to membership proof
    // We're using this as a FIFO queue, and using `VecDeque` for this allows us to pop
    // from the front of the vector in constant time.
    pub blockhash_to_membership_proof: VecDeque<(Digest, MsMembershipProof<Hash>)>,

    pub max_number_of_mps_stored: usize,

    pub has_synced_membership_proof: bool,

    // TODO: Change last type to whatever we use for timestamp in the block header.
    pub spent_in_block: Option<(Digest, BlockHeight, BFieldElement)>,
}

impl MonitoredUtxo {
    pub fn new(utxo: Utxo) -> Self {
        Self {
            utxo,
            blockhash_to_membership_proof: VecDeque::<(Digest, MsMembershipProof<Hash>)>::from([]),
            max_number_of_mps_stored: MAX_NUMBER_OF_MPS_STORED,
            has_synced_membership_proof: true,
            spent_in_block: None,
        }
    }

    pub fn add_membership_proof_for_tip(
        &mut self,
        block_digest: Digest,
        updated_membership_proof: MsMembershipProof<Hash>,
    ) {
        while self.blockhash_to_membership_proof.len() >= self.max_number_of_mps_stored {
            self.blockhash_to_membership_proof.pop_front();
        }

        self.blockhash_to_membership_proof
            .push_back((block_digest, updated_membership_proof));
    }

    pub fn get_membership_proof_for_block(
        &self,
        block_digest: &Digest,
    ) -> Option<MsMembershipProof<Hash>> {
        self.blockhash_to_membership_proof
            .iter()
            .find(|x| x.0 == *block_digest)
            .map(|x| x.1.clone())
    }

    pub fn get_latest_membership_proof(&self) -> MsMembershipProof<Hash> {
        self.blockhash_to_membership_proof[self.blockhash_to_membership_proof.len() - 1]
            .1
            .clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletDbValue {
    // Stores the block hash representing the state of the wallet
    SyncDigest(Digest),

    // Stores the relevant (own) UTXOs associated with a block
    // TODO: Alan wants this gone bc. transaction histories don't need to be
    // part of the client's functionality -- that can be handled by
    // an overlay program. Alan suggests that we instead record
    // "initiated transactions". That doesn't, however, record historic
    // *incoming* transactions (i.e. spent UTXOs).
    WalletBlockUtxos(WalletBlockUtxos),

    // Stores all confirmed UTXOs controlled by this wallet, and the associated membership proofs
    // This is stored as a vector an not as a (aocl_leaf_index => MonitoredUtxo) map since in case of forks
    // UTXOs can have their `aocl_leaf_index` changed, and managing that in the wallet would be messy.
    MonitoredUtxos(Vec<MonitoredUtxo>),
}

impl WalletDbValue {
    pub fn as_sync_digest(&self) -> Digest {
        match self {
            WalletDbValue::SyncDigest(digest) => *digest,
            _val => panic!("Requested sync digest, found {:?}", self),
        }
    }

    /// Returns true iff value is a wallet block UTXO entry
    /// Intended to be used when all balance changes are presented
    pub fn is_wallet_block_utxos(&self) -> bool {
        matches!(self, WalletDbValue::WalletBlockUtxos(_))
    }

    pub fn as_wallet_block_utxos(&self) -> WalletBlockUtxos {
        match self {
            WalletDbValue::WalletBlockUtxos(wb_utxos) => wb_utxos.to_owned(),
            _val => panic!("Requested wallet block UTXOs, found {:?}", self),
        }
    }

    pub fn as_monitored_utxos(&self) -> Vec<MonitoredUtxo> {
        match self {
            WalletDbValue::MonitoredUtxos(vals) => vals.to_vec(),
            _val => panic!("Requested monitored UTXOs, found {:?}", self),
        }
    }
}
