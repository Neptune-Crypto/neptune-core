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

use crate::mine_loop::MOCK_BLOCK_THRESHOLD;

use super::{
    digest::{KeyableDigest, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES},
    mutator_set_update::MutatorSetUpdate,
    shared::Hash,
    transaction::Transaction,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BlockHeader {
    pub version: BFieldElement,
    pub height: BlockHeight,
    pub mutator_set_commitment: KeyableDigest,
    pub prev_block_digest: KeyableDigest,

    // TODO: Reject blocks that are more than 10 seconds into the future
    pub timestamp: BFieldElement,

    // TODO: Consider making a type for `nonce`
    pub nonce: [BFieldElement; 3],
    pub max_block_size: u32,

    // use to compare two forks of different height
    pub proof_of_work_line: U32s<5>,

    // use to compare two forks of the same height
    pub proof_of_work_family: U32s<5>,

    // This is the target difficulty for the current (*this*) block.
    pub target_difficulty: U32s<5>,
    pub block_body_merkle_root: KeyableDigest,
    pub uncles: Vec<KeyableDigest>,
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

    pub fn hash(&self) -> KeyableDigest {
        let hasher = Hash::new();
        KeyableDigest::new(
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
    pub next_mutator_set_accumulator: MutatorSetAccumulator<Hash>,
    pub previous_mutator_set_accumulator: MutatorSetAccumulator<Hash>,
    pub mutator_set_update: MutatorSetUpdate,
    pub stark_proof: Vec<BFieldElement>,
}

impl BlockBody {
    // /// Calculate a Merkle root of block body data structure
    pub fn hash(&self) -> [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES] {
        let transactions_digests: Vec<[BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]> =
            self.transactions.iter().map(|tx| tx.hash()).collect();
        let next_ms_acc_digest: [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES] = self
            .next_mutator_set_accumulator
            .get_commitment()
            .try_into()
            .unwrap();
        let previous_ms_acc_digest: [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES] = self
            .previous_mutator_set_accumulator
            .get_commitment()
            .try_into()
            .unwrap();
        let ms_update_digest: [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES] =
            self.mutator_set_update.hash();

        let hasher = Hash::new();
        let all_digests: Vec<Vec<_>> = vec![
            transactions_digests,
            vec![next_ms_acc_digest],
            vec![previous_ms_acc_digest],
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
    pub hash: KeyableDigest,
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

    fn devnet_is_valid(&self) -> bool {
        // What belongs here are the things that would otherwise
        // be verified by the block validity proof.

        // 1. The transaction is valid.
        // 1'. All transactions are valid.
        // (with coinbase UTXO flag set)
        //   a) verify that MS membership proof is valid, done against `previous_mutator_set_accumulator`,
        //   b) Verify that MS removal record is valid, done against `previous_mutator_set_accumulator`,
        //   c) verify that all transactinos are represented in mutator_set_update
        //     i) Verify that all input UTXOs are present in `removals`
        //     ii) Verify that all output UTXOs are present in `additions`
        //     iii) That there are no entries in `mutator_set_update` not present in a transaction.
        //   d) verify that adding `mutator_set_update` to `previous_mutator_set_accumulator`
        //      gives `next_mutator_set_accumulator`,
        //   e) transaction timestamp <= block timestamp
        //   f) call: `transaction.devnet_is_valid()`

        // 2. accumulated proof-of-work was computed correctly
        //  - look two blocks back, take proof_of_work_line
        //  - look 1 block back, estimate proof-of-work
        //  - add -> new proof_of_work_line
        //  - look two blocks back, take proof_of_work_family
        //  - look at all uncles, estimate proof-of-work
        //  - add -> new proof_of_work_family

        // 3. variable network parameters are computed correctly
        // 3.a) target_difficulty <- pow_line
        // 3.b) max_block_size <- difference between `pow_family[n-2] - pow_line[n-2] - (pow_family[n] - pow_line[n])`

        // 4. for every uncle
        //  4.1. verify that uncle's prev_block_digest matches with parent's prev_block_digest
        //  4.2. verify that all uncles' hash are below parent's target_difficulty

        // 5. height = previous height + 1

        // 6. `block_body_merkle_root`
        // Verify that membership p
        true
    }

    pub fn is_valid(&self) -> bool {
        // check that hash is below threshold
        // TODO: Replace RHS with block `target_difficulty` from this block
        if self.hash > MOCK_BLOCK_THRESHOLD {
            return false;
        }

        // TODO: timestamp > previous and not more than 10 seconds into future

        // TODO: `block_body_merkle_root` is hash of block body.

        // Verify that STARK proof is valid
        // TODO: Add STARK verification here

        // Verify that `transactions` match
        //     pub transactions: Vec<Transaction>,
        // pub mutator_set_accumulator: MutatorSetAccumulator<Hash>,
        // pub mutator_set_update: MutatorSetUpdate,
        if !self.devnet_is_valid() {
            return false;
        }

        true
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
