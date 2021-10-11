use super::big_array::BigArray;
use std::{cmp::Ordering, convert::TryInto, fmt::Display, time::SystemTime};

use db_key::Key;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHash([u8; 32]);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Utxo {
    #[serde(with = "BigArray")]
    pub pol0: [u32; 2048],
    #[serde(with = "BigArray")]
    pub pol1: [u32; 2048],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    pub input: Vec<Utxo>,
    pub output: Vec<Utxo>,
    pub public_scripts: Vec<Vec<u8>>,
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Block {
    pub version_bits: [u8; 4],
    pub timestamp: SystemTime,
    pub height: BlockHeight,
    pub nonce: [u8; 32],
    pub predecessor: BlockHash,
    pub predecessor_proof: Vec<u8>,
    pub accumulated_pow_line: u128,
    pub accumulated_pow_family: u128,
    pub uncles: Vec<BlockHash>,
    pub target_difficulty: u128,
    pub retarget_proof: Vec<u8>,
    pub transaction: Transaction,
    pub mixed_edges: Vec<Utxo>,
    pub mix_proof: Vec<u8>,
    pub edge_mmra: Utxo,
    pub edge_mmra_update: Vec<u8>,
    pub hash: BlockHash,
}

pub const HASH_LENGTH: usize = 32;

impl From<[u8; HASH_LENGTH]> for BlockHash {
    fn from(item: [u8; HASH_LENGTH]) -> Self {
        BlockHash(item)
    }
}

impl Key for BlockHash {
    fn from_u8(key: &[u8]) -> Self {
        BlockHash(
            key.try_into()
                .expect("slice with incorrect length used as block hash"),
        )
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        f(&self.0)
    }
}

impl From<BlockHash> for [u8; HASH_LENGTH] {
    fn from(item: BlockHash) -> Self {
        item.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeight(u64);

impl From<u64> for BlockHeight {
    fn from(item: u64) -> Self {
        BlockHeight(item)
    }
}

impl From<BlockHeight> for u64 {
    fn from(item: BlockHeight) -> u64 {
        item.0
    }
}

impl Key for BlockHeight {
    fn from_u8(key: &[u8]) -> Self {
        let val = u64::from_be_bytes(
            key.to_owned()
                .try_into()
                .expect("slice with incorrect length used as block height"),
        );
        BlockHeight(val)
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        let val = u64::to_be_bytes(self.0);
        f(&val)
    }
}

impl Ord for BlockHeight {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.0).cmp(&(other.0))
    }
}

impl PartialOrd for BlockHeight {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for BlockHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
