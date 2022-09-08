use mutator_set_tf::util_types::mutator_set::{
    mutator_set_accumulator::MutatorSetAccumulator, mutator_set_trait::MutatorSet,
};
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use twenty_first::{
    amount::u32s::U32s, shared_math::b_field_element::BFieldElement,
    util_types::simple_hasher::Hasher,
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
    transaction::{utxo::Utxo, Amount, Transaction},
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
    pub fn get_mining_reward(block_height: BlockHeight) -> Amount {
        let mut reward: Amount = U32s::new([100, 0, 0, 0]);
        let generation = block_height.get_generation();
        for _ in 0..generation {
            reward.div_two()
        }

        reward
    }

    pub fn genesis_block() -> Self {
        let empty_mutator_set = MutatorSetAccumulator::default();
        let mut genesis_mutator_set = MutatorSetAccumulator::default();
        let mut ms_update = MutatorSetUpdate::default();
        // This is just the UNIX timestamp when this code was written
        let timestamp: BFieldElement = BFieldElement::new(1655916990u64);

        let mut genesis_coinbase_tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            public_scripts: vec![],
            fee: 0u32.into(),
            timestamp,
        };

        for premine_utxo in Self::premine_utxos() {
            // A commitment to the pre-mine UTXO
            let utxo_commitment = premine_utxo.hash();

            // This isn't random.
            let bad_randomness = Digest::default();

            // Add pre-mine UTXO to MutatorSet
            let mut addition_record =
                genesis_mutator_set.commit(&utxo_commitment.into(), &bad_randomness.into());
            ms_update.additions.push(addition_record.clone());
            genesis_mutator_set.add(&mut addition_record);

            // Add pre-mine UTXO + commitment to coinbase transaction
            genesis_coinbase_tx
                .outputs
                .push((premine_utxo, bad_randomness))
        }

        let body: BlockBody = BlockBody {
            transaction: genesis_coinbase_tx,
            next_mutator_set_accumulator: genesis_mutator_set.clone(),
            previous_mutator_set_accumulator: empty_mutator_set,
            mutator_set_update: ms_update,
            stark_proof: vec![],
        };

        let header: BlockHeader = BlockHeader {
            version: BFieldElement::ring_zero(),
            height: BFieldElement::ring_zero().into(),
            mutator_set_commitment: genesis_mutator_set.get_commitment().into(),
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

    fn premine_utxos() -> Vec<Utxo> {
        vec![Utxo::new_from_hex(
            20000.into(),
            "03c7635c31ad6c52fa86f982275e3c2620dd712718b68be19e57f14595da133522",
        )]
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
        self.body.transaction.outputs.len()
    }

    fn count_inputs(&self) -> usize {
        self.body.transaction.inputs.len()
    }

    /// Verify a block. It is assumed that `previous_block` is valid.
    /// Note that this function does **not** check that the PoW digest is below the threshold.
    /// That must be done separately by the caller.
    pub(crate) fn devnet_is_valid(&self, previous_block: &Block) -> bool {
        // The block value doesn't actually change. Some function calls just require
        // mutable references because that's how the interface was defined for them.
        let mut block_copy = self.to_owned();
        // What belongs here are the things that would otherwise
        // be verified by the block validity proof.

        // 0. `previous_block` is consistent with current block
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

        // `previous_block` is parent of new block
        if previous_block.header.height.next() != block_copy.header.height {
            warn!("Height does not match previous height");
            return false;
        }

        if previous_block.hash != block_copy.header.prev_block_digest {
            warn!("Hash digest does not match previous digest");
            return false;
        }

        // `previous_block`'s accumuluator must agree with current block's `parent_accumulator`
        if previous_block.body.next_mutator_set_accumulator
            != block_copy.body.previous_mutator_set_accumulator
        {
            warn!("Value for previous mutator set does not match previous block");
            return false;
        }

        for input in block_copy.body.transaction.inputs.iter() {
            // 1.a) Verify validity of membership proofs
            if !block_copy.body.previous_mutator_set_accumulator.verify(
                &input.utxo.hash().into(),
                &input.membership_proof.clone().into(),
            ) {
                warn!("Invalid membership proof found in block");
                return false;
            }
        }

        // 1.c) Verify that transactions and mutator_set_update agree
        if block_copy.count_inputs() != block_copy.body.mutator_set_update.removals.len() {
            warn!("Bad removal record count");
            return false;
        }

        if block_copy.count_outputs() != block_copy.body.mutator_set_update.additions.len() {
            warn!("Bad addition record count");
            return false;
        }

        // Go over all input UTXOs and verify that the removal record is found at the same index
        // in the `mutator_set_update` data structure
        let mut i = 0;
        for input in block_copy.body.transaction.inputs.iter() {
            if input.removal_record != block_copy.body.mutator_set_update.removals[i] {
                warn!("Invalid removal record found in block");
                return false;
            }
            i += 1;
        }

        // Go over all output UTXOs and verify that the addition record is found at the same index
        // in the `mutator_set_update` data structure
        i = 0;
        let hasher = Hash::new();
        for (utxo, randomness) in block_copy.body.transaction.outputs.iter() {
            let expected_commitment =
                hasher.hash_pair(&utxo.hash().into(), &randomness.to_owned().into());
            if block_copy.body.mutator_set_update.additions[i].canonical_commitment
                != expected_commitment
            {
                warn!("Bad commitment found in addition record");
                return false;
            }
            i += 1;
        }

        // 1.d) Verify that the two mutator sets, previous and current, are
        // consistent with the transactions.
        // Construct all the addition records for all the transaction outputs. Then
        // use these addition records to insert into the mutator set.
        let mut ms = block_copy.body.previous_mutator_set_accumulator.clone();
        let ms_update_result = block_copy.body.mutator_set_update.apply(&mut ms);
        match ms_update_result {
            Ok(_) => (),
            Err(err) => {
                warn!("Failed to apply mutator set update: {}", err);
                return false;
            }
        };

        // Verify that the locally constructed mutator set matches that in the received
        // block's body.
        if ms.get_commitment()
            != block_copy
                .body
                .next_mutator_set_accumulator
                .get_commitment()
        {
            warn!("Reported mutator set does not match calculated object.");
            debug!(
                "Read: {:?}. \nCalculated: {:?}",
                block_copy.body.next_mutator_set_accumulator, ms
            );
            return false;
        }

        // Verify that the locally constructed mutator set matches that in the received block's header
        if ms.get_commitment()
            != Into::<Vec<BFieldElement>>::into(block_copy.header.mutator_set_commitment)
        {
            warn!("Mutator set commitment does not match calculated object");
            return false;
        }

        // 1.e) verify that the transaction timestamp is less than or equal to the block's timestamp.
        if block_copy.body.transaction.timestamp.value() > block_copy.header.timestamp.value() {
            warn!("Transaction with invalid timestamp found");
            return false;
        }

        // 1.f) Verify transaction
        let miner_reward: Amount = Self::get_mining_reward(block_copy.header.height);
        if !block_copy
            .body
            .transaction
            .devnet_is_valid(Some(miner_reward))
        {
            warn!("Invalid transaction found in block");
            return false;
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

        // 5. `block_body_merkle_root`
        if block_copy.header.block_body_merkle_root != block_copy.body.hash() {
            warn!("Block body does not match referenced block body Merkle root");
            return false;
        }

        true
    }

    /// The archival-version of block validation. Archival nodes should run this version.
    pub fn archival_is_valid(&self, previous_block: &Block) -> bool {
        // check that hash is below threshold
        if Into::<OrderedDigest>::into(self.hash)
            > OrderedDigest::to_digest_threshold(self.header.target_difficulty)
        {
            warn!("Block digest exceeds target difficulty");
            return false;
        }

        // `devnet_is_valid` contains the rest of the block validation logic. `devnet_is_valid`
        // is factored out such that we can also test if block templates are valid without having
        // to build a block with a valid PoW digest.
        if !self.devnet_is_valid(previous_block) {
            warn!("Block devnet test failed");
            return false;
        }

        true
    }
}
