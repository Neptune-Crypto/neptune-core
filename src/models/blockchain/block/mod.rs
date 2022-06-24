use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use tracing::warn;
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

pub mod block_body;
pub mod block_header;
pub mod block_height;
pub mod mutator_set_update;
pub mod transfer_block;

use self::{
    block_body::BlockBody, block_header::BlockHeader, block_height::BlockHeight,
    mutator_set_update::MutatorSetUpdate, transfer_block::TransferBlock,
};
use super::{
    digest::{ordered_digest::OrderedDigest, *},
    transaction::AMOUNT_SIZE_FOR_U32,
};
use crate::models::blockchain::shared::Hash;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Block {
    pub hash: Digest,
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

impl Block {
    pub fn get_mining_reward(block_height: BlockHeight) -> U32s<AMOUNT_SIZE_FOR_U32> {
        let mut reward: U32s<AMOUNT_SIZE_FOR_U32> = U32s::new([100, 0, 0, 0]);
        let generation = block_height.get_generation();
        for _ in 0..generation {
            reward.div_two()
        }

        reward
    }

    pub fn genesis_block() -> Self {
        let empty_mutator = MutatorSetAccumulator::default();
        let body: BlockBody = BlockBody {
            transactions: vec![],
            next_mutator_set_accumulator: empty_mutator.clone(),
            previous_mutator_set_accumulator: empty_mutator.clone(),
            mutator_set_update: MutatorSetUpdate::default(),
            stark_proof: vec![],
        };

        // This is just the UNIX timestamp when this code was written
        let timestamp: BFieldElement = BFieldElement::new(1655916990u64);

        let header: BlockHeader = BlockHeader {
            version: BFieldElement::ring_zero(),
            height: BFieldElement::ring_zero().into(),
            mutator_set_commitment: empty_mutator.get_commitment().into(),
            prev_block_digest: Digest::default(),
            timestamp,
            nonce: [
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero(),
            ],
            max_block_size: 10_000,
            proof_of_work_line: U32s::zero(),
            proof_of_work_family: U32s::zero(),
            target_difficulty: U32s::one(),
            block_body_merkle_root: body.hash(),
            uncles: vec![],
        };

        Self::new(header, body)
    }

    pub fn new(header: BlockHeader, body: BlockBody) -> Self {
        let digest = header.hash();
        Self {
            body,
            header,
            hash: digest,
        }
    }

    fn count_outputs(&self) -> usize {
        self.body
            .transactions
            .iter()
            .map(|tx| tx.outputs.len())
            .sum()
    }

    fn count_inputs(&self) -> usize {
        self.body
            .transactions
            .iter()
            .map(|tx| tx.inputs.len())
            .sum()
    }

    fn devnet_is_valid(&self) -> bool {
        // What belongs here are the things that would otherwise
        // be verified by the block validity proof.

        // 1. The transaction is valid.
        // 1'. All transactions are valid.
        // (with coinbase UTXO flag set)
        //   a) verify that MS membership proof is valid, done against `previous_mutator_set_accumulator`,
        //   b) Verify that MS removal record is valid, done against `previous_mutator_set_accumulator`,
        //   c) verify that all transactions are represented in mutator_set_update
        //     i) Verify that all input UTXOs are present in `removals`
        //     ii) Verify that all output UTXOs are present in `additions`
        //     iii) That there are no entries in `mutator_set_update` not present in a transaction.
        //   d) verify that adding `mutator_set_update` to `previous_mutator_set_accumulator`
        //      gives `next_mutator_set_accumulator`,
        //   e) transaction timestamp <= block timestamp
        //   f) call: `transaction.devnet_is_valid()`

        for tx in self.body.transactions.iter() {
            for input in tx.inputs.iter() {
                // 1.a) Verify validity of membership proofs
                if !self.body.previous_mutator_set_accumulator.verify(
                    &input.utxo.hash().into(),
                    &input.membership_proof.clone().into(),
                ) {
                    return false;
                }
            }
        }

        // 1.c) Verify that transactions and mutator_set_update agree
        if self.count_inputs() != self.body.mutator_set_update.removals.len() {
            return false;
        }

        if self.count_outputs() != self.body.mutator_set_update.additions.len() {
            return false;
        }

        // Go over all input UTXOs and verify that the removal record is found at the same index
        // in the `mutator_set_update` data structure
        let mut i = 0;
        for tx in self.body.transactions.iter() {
            for input in tx.inputs.iter() {
                if input.removal_record != self.body.mutator_set_update.removals[i] {
                    return false;
                }
                i += 1;
            }
        }

        // Go over all output UTXOs and verify that the addition record is found at the same index
        // in the `mutator_set_update` data structure
        i = 0;
        let hasher = Hash::new();
        for tx in self.body.transactions.iter() {
            for (utxo, randomness) in tx.outputs.iter() {
                let expected_commitment =
                    hasher.hash_pair(&utxo.hash().into(), &randomness.to_owned().into());
                if self.body.mutator_set_update.additions[i].commitment != expected_commitment {
                    return false;
                }
                if !self.body.mutator_set_update.additions[i]
                    .has_matching_aocl(&self.body.previous_mutator_set_accumulator.aocl)
                {
                    return false;
                }
                i += 1;
            }
        }

        // 1.d) Verify that the two mutator sets, previous and current, are
        // consistent with the transactions.
        let mut ms = self.body.previous_mutator_set_accumulator.clone();
        for tx in self.body.transactions.iter() {
            for input in tx.inputs.iter() {
                // TODO: This will probably fail with more than one removal record
                // in the block, since we are not updating the removal records.
                ms.remove(&input.removal_record);
            }
        }

        // Construct all the addition records for all the transaction outputs. Then
        // use these addition records to insert into the mutator set.
        for tx in self.body.transactions.iter() {
            for (utxo, randomness) in tx.outputs.iter() {
                let addition_record = ms.commit(&utxo.hash().into(), &randomness.to_owned().into());
                ms.add(&addition_record);
            }
        }

        if ms.get_commitment() != self.body.next_mutator_set_accumulator.get_commitment() {
            return false;
        }

        if ms.get_commitment()
            != Into::<Vec<BFieldElement>>::into(self.header.mutator_set_commitment)
        {
            return false;
        }

        // 1.f) Verify all transactions
        for (i, tx) in self.body.transactions.iter().enumerate() {
            let miner_reward = if i == 0 {
                Some(Self::get_mining_reward(self.header.height))
            } else {
                None
            };
            if !tx.devnet_is_valid(miner_reward) {
                warn!("Invalid transaction found in block");
                return false;
            }
        }

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
        // Check that self is the child of parent
        // if parent.hash != self.header.prev_block_digest {
        //     return false;
        // }

        // check that hash is below threshold
        // TODO: Replace RHS with block `target_difficulty` from this block
        if Into::<OrderedDigest>::into(self.hash)
            > OrderedDigest::to_digest_threshold(self.header.target_difficulty)
        {
            warn!("Block digest exceeds target difficulty");
            return false;
        }

        // TODO: `block_body_merkle_root` is hash of block body.

        // Verify that STARK proof is valid
        // TODO: Add STARK verification here

        // Verify that `transactions` match
        //     pub transactions: Vec<Transaction>,
        // pub mutator_set_accumulator: MutatorSetAccumulator<Hash>,
        // pub mutator_set_update: MutatorSetUpdate,
        if !self.devnet_is_valid() {
            warn!("Block devnet test failed");
            return false;
        }

        true
    }
}
