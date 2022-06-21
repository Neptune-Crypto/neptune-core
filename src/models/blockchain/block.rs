use std::{cmp::Ordering, fmt::Display};

use db_key::Key;
use serde::{Deserialize, Serialize};
use twenty_first::{
    amount::u32s::U32s,
    shared_math::b_field_element::BFieldElement,
    util_types::{
        mutator_set::{
            mutator_set_accumulator::MutatorSetAccumulator, mutator_set_trait::MutatorSet,
        },
        simple_hasher::Hasher,
    },
};

use super::{
    digest::{RescuePrimeDigest, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES},
    mutator_set_update::MutatorSetUpdate,
    shared::Hash,
    transaction::Transaction,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BlockHeader {
    pub version: BFieldElement,
    pub height: BlockHeight,
    pub mutator_set_commitment: RescuePrimeDigest,
    pub prev_block_digest: RescuePrimeDigest,
    pub timestamp: BFieldElement,
    // TODO: Consider making a type for `nonce`
    pub nonce: [BFieldElement; 3],
    pub max_block_size: u32,
    pub proof_of_work_line: U32s<5>,
    pub proof_of_work_family: U32s<5>,
    pub target_difficulty: U32s<5>,
    pub block_body_merkle_root: RescuePrimeDigest,
    pub uncles: Vec<RescuePrimeDigest>,
}

impl BlockHeader {
    fn accumulate(&self) -> Vec<BFieldElement> {
        let mut ret: Vec<BFieldElement> = vec![self.version, self.height.0];
        ret.append(&mut self.mutator_set_commitment.values().to_vec());
        ret.append(&mut self.prev_block_digest.values().to_vec());
        ret.push(self.timestamp);
        ret.append(&mut self.nonce.to_vec());
        let max_block_value: BFieldElement = self.max_block_size.into();
        ret.push(max_block_value);
        let pow_line_values: [BFieldElement; 5] = self.proof_of_work_line.into();
        ret.append(&mut pow_line_values.to_vec());
        let pow_family_values: [BFieldElement; 5] = self.proof_of_work_family.into();
        ret.append(&mut pow_family_values.to_vec());
        let target_difficulty: [BFieldElement; 5] = self.target_difficulty.into();
        ret.append(&mut target_difficulty.to_vec());
        ret.append(&mut self.block_body_merkle_root.values().to_vec());

        ret.append(
            &mut self
                .uncles
                .iter()
                .map(|uncle| uncle.values().to_vec())
                .collect::<Vec<_>>()
                .concat(),
        );

        ret
    }

    pub fn hash(&self) -> RescuePrimeDigest {
        let hasher = Hash::new();
        RescuePrimeDigest::new(
            hasher
                .hash(&self.accumulate(), RESCUE_PRIME_OUTPUT_SIZE_IN_BFES)
                .try_into()
                .unwrap(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BlockBody {
    pub transactions: Vec<Transaction>,
    pub mutator_set_accumulator: MutatorSetAccumulator<Hash>,
    pub mutator_set_update: MutatorSetUpdate,
}

impl BlockBody {
    // /// Calculate a Merkle root of block body data structure
    pub fn hash(&self) -> [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES] {
        let transactions_digests: Vec<[BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]> =
            self.transactions.iter().map(|tx| tx.hash()).collect();
        let ms_acc_digest: [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES] = self
            .mutator_set_accumulator
            .get_commitment()
            .try_into()
            .unwrap();
        let ms_update_digest: [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES] =
            self.mutator_set_update.hash();

        let hasher = Hash::new();
        let all_digests: Vec<Vec<_>> = vec![
            transactions_digests,
            vec![ms_acc_digest],
            vec![ms_update_digest],
        ]
        .concat()
        .iter()
        .map(|array| array.to_vec())
        .collect();

        hasher.hash_many(&all_digests).try_into().unwrap()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Block {
    pub hash: RescuePrimeDigest,
    pub header: BlockHeader,
    pub body: BlockBody,
}

impl Block {
    pub fn new(header: BlockHeader, body: BlockBody) -> Self {
        let digest = header.hash();
        Self {
            body,
            header,
            hash: digest,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TransferBlock {
    pub header: BlockHeader,
    pub body: BlockBody,
}

impl From<TransferBlock> for Block {
    fn from(t_block: TransferBlock) -> Self {
        Self {
            hash: t_block.header.hash(),
            header: t_block.header,
            body: t_block.body,
        }
    }
}

impl From<Block> for TransferBlock {
    fn from(block: Block) -> Self {
        Self {
            header: block.header,
            body: block.body,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeight(BFieldElement);

impl From<BFieldElement> for BlockHeight {
    fn from(item: BFieldElement) -> Self {
        BlockHeight(item)
    }
}

impl From<BlockHeight> for BFieldElement {
    fn from(item: BlockHeight) -> BFieldElement {
        item.0
    }
}

impl From<u64> for BlockHeight {
    fn from(val: u64) -> Self {
        BlockHeight(BFieldElement::new(val))
    }
}

impl From<BlockHeight> for u64 {
    fn from(bh: BlockHeight) -> Self {
        bh.0.value()
    }
}

impl Key for BlockHeight {
    fn from_u8(key: &[u8]) -> Self {
        // First convert the slice to an array and verify that the length is correct
        let array: [u8; 8] = key
            .to_vec()
            .try_into()
            .expect("slice with incorrect length used as block height");

        // Then convert the array to a B field element and wrap in type constructore
        Self(array.into())
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        let array: [u8; 8] = self.0.into();
        f(&array)
    }
}

impl Ord for BlockHeight {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.0.value()).cmp(&(other.0.value()))
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
