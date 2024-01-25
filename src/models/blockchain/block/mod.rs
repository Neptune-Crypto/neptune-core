use crate::prelude::twenty_first;

use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::{abs, Zero};

use serde::{Deserialize, Serialize};
use std::cmp::max;

use tracing::{debug, warn};

use twenty_first::amount::u32s::U32s;
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::digest::Digest;
use twenty_first::shared_math::tip5::DIGEST_LENGTH;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

pub mod block_body;
pub mod block_header;
pub mod block_height;
pub mod mutator_set_update;
pub mod transfer_block;

use self::block_body::BlockBody;
use self::block_header::{
    BlockHeader, MINIMUM_DIFFICULTY, TARGET_BLOCK_INTERVAL, TARGET_DIFFICULTY_U32_SIZE,
};
use self::block_height::BlockHeight;
use self::mutator_set_update::MutatorSetUpdate;
use self::transfer_block::TransferBlock;
use super::transaction::transaction_kernel::TransactionKernel;
use super::transaction::utxo::Utxo;
use super::transaction::{amount::Amount, Transaction};
use crate::models::blockchain::shared::Hash;
use crate::models::state::wallet::address::generation_address;
use crate::models::state::wallet::WalletSecret;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::mutator_set_trait::{commit, MutatorSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub hash: Digest,
    pub header: BlockHeader,
    pub body: BlockBody,
}

impl From<TransferBlock> for Block {
    fn from(t_block: TransferBlock) -> Self {
        Self {
            hash: Hash::hash(&t_block.header),
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
    #[inline]
    pub fn hash(&self) -> Digest {
        self.hash
    }

    #[inline]
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    #[inline]
    pub fn body(&self) -> &BlockBody {
        &self.body
    }

    #[inline]
    pub fn set_block(&mut self, block: Block) {
        self.hash = block.hash;
        self.header = block.header;
        self.body = block.body;
    }

    pub fn get_mining_reward(block_height: BlockHeight) -> Amount {
        let mut reward: Amount = Amount(U32s::new([100, 0, 0, 0]));
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

        let premine_distribution = Self::premine_distribution();
        let total_premine_amount = premine_distribution
            .iter()
            .map(|(_receiving_address, amount)| *amount)
            .sum();

        // This is the UNIX timestamp in ms when this code was written the 1st time
        let timestamp: BFieldElement = BFieldElement::new(1655916990000u64);

        let mut genesis_coinbase_tx = Transaction {
            kernel: TransactionKernel {
                inputs: vec![],
                outputs: vec![],
                fee: 0u32.into(),
                timestamp,
                pubscript_hashes_and_inputs: vec![],
                coinbase: Some(total_premine_amount),
                mutator_set_hash: MutatorSetAccumulator::<Hash>::new().hash(),
            },
            witness: super::transaction::Witness::Faith,
        };

        for (receiving_address, amount) in premine_distribution {
            // generate utxo
            let utxo = Utxo::new_native_coin(receiving_address.lock_script(), amount);
            let utxo_digest = Hash::hash(&utxo);

            // generate randomness for mutator set commitment
            // Sender randomness cannot be random because there is no sender.
            let bad_randomness = Digest::default();
            let receiver_digest = receiving_address.privacy_digest;

            // Add pre-mine UTXO to MutatorSet
            let addition_record = commit::<Hash>(utxo_digest, bad_randomness, receiver_digest);
            ms_update.additions.push(addition_record);
            genesis_mutator_set.add(&addition_record);

            // Add pre-mine UTXO + commitment to coinbase transaction
            genesis_coinbase_tx.kernel.outputs.push(addition_record)
        }

        let body: BlockBody = BlockBody {
            transaction: genesis_coinbase_tx,
            next_mutator_set_accumulator: genesis_mutator_set.clone(),
            previous_mutator_set_accumulator: empty_mutator_set,
            stark_proof: vec![],
        };

        let header: BlockHeader = BlockHeader {
            version: BFieldElement::zero(),
            height: BFieldElement::zero().into(),
            mutator_set_hash: genesis_mutator_set.hash(),
            prev_block_digest: Digest::default(),
            timestamp,
            nonce: [
                BFieldElement::zero(),
                BFieldElement::zero(),
                BFieldElement::zero(),
            ],
            max_block_size: 10_000,
            proof_of_work_line: U32s::zero(),
            proof_of_work_family: U32s::zero(),
            difficulty: MINIMUM_DIFFICULTY.into(),
            block_body_merkle_root: Hash::hash(&body),
            uncles: vec![],
        };

        Self::new(header, body)
    }

    pub fn premine_distribution() -> Vec<(generation_address::ReceivingAddress, Amount)> {
        // The premine UTXOs can be hardcoded here.
        let authority_wallet = WalletSecret::devnet_wallet();
        let authority_receiving_address =
            authority_wallet.nth_generation_spending_key(0).to_address();
        vec![(authority_receiving_address, 20000.into())]
    }

    pub fn new(header: BlockHeader, body: BlockBody) -> Self {
        let hash = Hash::hash(&header);
        Self { hash, header, body }
    }

    /// Merge a transaction into this block's transaction.
    /// The mutator set data must be valid in all inputs.
    pub fn accumulate_transaction(&mut self, transaction: Transaction) {
        // merge
        let merged_timestamp = BFieldElement::new(max(
            self.header.timestamp.value(),
            max(
                self.body.transaction.kernel.timestamp.value(),
                transaction.kernel.timestamp.value(),
            ),
        ));
        let new_transaction = self.body.transaction.clone().merge_with(transaction);

        // accumulate
        let additions = new_transaction.kernel.outputs.clone();
        let removals = new_transaction.kernel.inputs.clone();
        let mut next_mutator_set_accumulator = self.body.previous_mutator_set_accumulator.clone();

        let mutator_set_update = MutatorSetUpdate::new(removals, additions);

        // Apply the mutator set update to get the `next_mutator_set_accumulator`
        mutator_set_update
            .apply(&mut next_mutator_set_accumulator)
            .expect("Mutator set mutation must work");

        let block_body: BlockBody = BlockBody {
            transaction: new_transaction,
            next_mutator_set_accumulator: next_mutator_set_accumulator.clone(),
            previous_mutator_set_accumulator: self.body.previous_mutator_set_accumulator.clone(),
            stark_proof: vec![],
        };

        let block_header = BlockHeader {
            version: self.header.version,
            height: self.header.height,
            mutator_set_hash: next_mutator_set_accumulator.hash(),
            prev_block_digest: self.header.prev_block_digest,
            timestamp: merged_timestamp,
            nonce: self.header.nonce,
            max_block_size: self.header.max_block_size,
            proof_of_work_line: self.header.proof_of_work_line,
            proof_of_work_family: self.header.proof_of_work_family,
            difficulty: self.header.difficulty,
            block_body_merkle_root: Hash::hash(&block_body),
            uncles: vec![],
        };

        self.body = block_body;
        self.hash = Hash::hash(&block_header);
        self.header = block_header;
    }

    /// Verify a block. It is assumed that `previous_block` is valid.
    /// Note that this function does **not** check that the PoW digest is below the threshold.
    /// That must be done separately by the caller.
    pub(crate) fn is_valid(&self, previous_block: &Block) -> bool {
        // The block value doesn't actually change. Some function calls just require
        // mutable references because that's how the interface was defined for them.
        let block_copy = self.to_owned();
        // What belongs here are the things that would otherwise
        // be verified by the block validity proof.

        // 0. `previous_block` is consistent with current block
        //   a) Block height is previous plus one
        //   b) Block header points to previous block
        //   c) Block timestamp is greater than previous block timestamp
        //   d) Next mutator set of previous block matches previous MS of current block
        //   e) Target difficulty was adjusted correctly
        // 1. The transaction is valid.
        // 1'. All transactions are valid.
        //   a) verify that MS membership proof is valid, done against `previous_mutator_set_accumulator`,
        //   b) Verify that MS removal record is valid, done against `previous_mutator_set_accumulator`,
        //   c) Verify that all removal records have unique index sets
        //   d) verify that adding `mutator_set_update` to `previous_mutator_set_accumulator`
        //      gives `next_mutator_set_accumulator`,
        //   e) transaction timestamp <= block timestamp
        //   f) transaction coinbase <= miner reward
        //   g) transaction is valid (internally consistent)

        // 0.a) Block height is previous plus one
        if previous_block.header.height.next() != block_copy.header.height {
            warn!("Height does not match previous height");
            return false;
        }

        // 0.b) Block header points to previous block
        if previous_block.hash != block_copy.header.prev_block_digest {
            warn!("Hash digest does not match previous digest");
            return false;
        }

        // 0.c) Block timestamp is greater than that of previuos block
        if previous_block.header.timestamp.value() >= block_copy.header.timestamp.value() {
            warn!("Block does not have greater timestamp than that of previous block");
            return false;
        }

        // 0.d) Next mutator set of previous block matches previous MS of current block
        if previous_block.body.next_mutator_set_accumulator
            != block_copy.body.previous_mutator_set_accumulator
        {
            warn!("Value for previous mutator set does not match previous block");
            return false;
        }

        // 0.e) Target difficulty was updated correctly
        if block_copy.header.difficulty
            != Self::difficulty_control(previous_block, block_copy.header.timestamp.value())
        {
            warn!("Value for new difficulty is incorrect.");
            return false;
        }

        // 1.b) Verify validity of removal records: That their MMR MPs match the SWBF, and
        // that at least one of their listed indices is absent.
        for removal_record in block_copy.body.transaction.kernel.inputs.iter() {
            if !block_copy
                .body
                .previous_mutator_set_accumulator
                .kernel
                .can_remove(removal_record)
            {
                warn!("Removal record cannot be removed from mutator set");
                return false;
            }
        }

        // 1.c) Verify that the removal records do not contain duplicate `AbsoluteIndexSet`s
        let mut absolute_index_sets = block_copy
            .body
            .transaction
            .kernel
            .inputs
            .iter()
            .map(|removal_record| removal_record.absolute_indices.to_vec())
            .collect_vec();
        absolute_index_sets.sort();
        absolute_index_sets.dedup();
        if absolute_index_sets.len() != block_copy.body.transaction.kernel.inputs.len() {
            warn!("Removal records contain duplicates");
            return false;
        }

        // 1.d) Verify that the two mutator sets, previous and current, are
        // consistent with the transactions.
        // Construct all the addition records for all the transaction outputs. Then
        // use these addition records to insert into the mutator set.
        let mutator_set_update = MutatorSetUpdate::new(
            block_copy.body.transaction.kernel.inputs.clone(),
            block_copy.body.transaction.kernel.outputs.clone(),
        );
        let mut ms = block_copy.body.previous_mutator_set_accumulator.clone();
        let ms_update_result = mutator_set_update.apply(&mut ms);
        match ms_update_result {
            Ok(()) => (),
            Err(err) => {
                warn!("Failed to apply mutator set update: {}", err);
                return false;
            }
        };

        // Verify that the locally constructed mutator set matches that in the received
        // block's body.
        if ms.hash() != block_copy.body.next_mutator_set_accumulator.hash() {
            warn!("Reported mutator set does not match calculated object.");
            debug!(
                "From Block\n{:?}. \n\n\nCalculated\n{:?}",
                block_copy.body.next_mutator_set_accumulator, ms
            );
            return false;
        }

        // Verify that the locally constructed mutator set matches that in the received block's header
        if ms.hash() != block_copy.header.mutator_set_hash {
            warn!("Mutator set commitment does not match calculated object");
            return false;
        }

        // 1.e) verify that the transaction timestamp is less than or equal to the block's timestamp.
        if block_copy.body.transaction.kernel.timestamp.value()
            > block_copy.header.timestamp.value()
        {
            warn!("Transaction with invalid timestamp found");
            return false;
        }

        // 1.f) Verify that the coinbase claimed by the transaction does not exceed
        // the allowed coinbase based on block height, epoch, etc., and fee
        let miner_reward: Amount =
            Self::get_mining_reward(block_copy.header.height) + self.body.transaction.kernel.fee;
        if let Some(claimed_reward) = block_copy.body.transaction.kernel.coinbase {
            if claimed_reward > miner_reward {
                warn!("Block is invalid because the claimed miner reward is too high relative to current network parameters.");
                return false;
            }
        }

        // 1.g) Verify transaction, but without relating it to the blockchain tip (that was done above).
        if !block_copy.body.transaction.is_valid() {
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
        if block_copy.header.block_body_merkle_root != Hash::hash(&block_copy.body) {
            warn!("Block body does not match referenced block body Merkle root");
            return false;
        }

        true
    }

    /// Determine if the the proof-of-work puzzle was solved correctly. Specifically,
    /// compare the hash of the current block against the difficulty determined by
    /// the previous.
    pub fn has_proof_of_work(&self, previous_block: &Block) -> bool {
        // check that hash is below threshold
        if self.hash > Self::difficulty_to_digest_threshold(previous_block.header.difficulty) {
            warn!("Block digest exceeds target difficulty");
            return false;
        }

        true
    }

    /// Converts `difficulty` to type `Digest` so that the hash of a block can be
    /// tested against the target difficulty using `<`. The unit of `difficulty`
    /// is expected number of hashes for solving the proof-of-work puzzle.
    pub fn difficulty_to_digest_threshold(difficulty: U32s<5>) -> Digest {
        assert!(!difficulty.is_zero(), "Difficulty cannot be less than 1");

        let difficulty_as_bui: BigUint = difficulty.into();
        let max_threshold_as_bui: BigUint =
            Digest([BFieldElement::new(BFieldElement::MAX); DIGEST_LENGTH]).into();
        let threshold_as_bui: BigUint = max_threshold_as_bui / difficulty_as_bui;

        threshold_as_bui.try_into().unwrap()
    }

    /// Control system for block difficulty. This function computes the new block's
    /// difficulty from its timestamp and the previous block. It is a PID controller
    /// (with i=d=0) regulating the block interval by tuning the difficulty.
    /// We assume that the block timestamp is valid.
    pub fn difficulty_control(
        old_block: &Block,
        new_timestamp: u64,
    ) -> U32s<TARGET_DIFFICULTY_U32_SIZE> {
        // no adjustment if the previous block is the genesis block
        if old_block.header.height.is_genesis() {
            return old_block.header.difficulty;
        }

        // otherwise, compute PID control signal
        let t = new_timestamp - old_block.header.timestamp.value();

        let new_error = t as i64 - TARGET_BLOCK_INTERVAL as i64;

        let adjustment = -new_error / 100;
        let absolute_adjustment = abs(adjustment) as u64;
        let adjustment_is_positive = adjustment >= 0;
        let adj_hi = (absolute_adjustment >> 32) as u32;
        let adj_lo = absolute_adjustment as u32;
        let adjustment_u32s =
            U32s::<TARGET_DIFFICULTY_U32_SIZE>::new([adj_lo, adj_hi, 0u32, 0u32, 0u32]);
        if adjustment_is_positive {
            old_block.header.difficulty + adjustment_u32s
        } else if adjustment_u32s > old_block.header.difficulty - MINIMUM_DIFFICULTY.into() {
            MINIMUM_DIFFICULTY.into()
        } else {
            old_block.header.difficulty - adjustment_u32s
        }
    }
}

#[cfg(test)]
mod block_tests {
    use crate::{
        config_models::network::Network,
        models::{
            blockchain::transaction::PubScript, state::wallet::WalletSecret,
            state::UtxoReceiverData,
        },
        tests::shared::{get_mock_global_state, make_mock_block},
    };

    use super::*;

    use rand::random;
    use tracing_test::traced_test;
    use twenty_first::util_types::emojihash_trait::Emojihash;

    #[traced_test]
    #[tokio::test]
    async fn merge_transaction_test() {
        // We need the global state to construct a transaction. This global state
        // has a wallet which receives a premine-UTXO.
        let network = Network::Alpha;
        let global_state_lock = get_mock_global_state(network, 2, None).await;
        let spending_key = global_state_lock
            .lock_guard()
            .await
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key(0);
        let address = spending_key.to_address();
        let other_wallet_secret = WalletSecret::new_random();
        let other_address = other_wallet_secret
            .nth_generation_spending_key(0)
            .to_address();
        let genesis_block = Block::genesis_block();

        let (mut block_1, _, _) = make_mock_block(&genesis_block, None, address);
        assert!(
            block_1.is_valid(&genesis_block),
            "Block 1 must be valid with only coinbase output"
        );

        // create a new transaction, merge it into block 1 and check that block 1 is still valid
        let new_utxo = Utxo::new_native_coin(other_address.lock_script(), 10.into());
        let reciever_data = UtxoReceiverData {
            pubscript: PubScript::default(),
            pubscript_input: vec![],
            receiver_privacy_digest: other_address.privacy_digest,
            sender_randomness: random(),
            utxo: new_utxo,
        };
        let new_tx = global_state_lock
            .lock_guard_mut()
            .await
            .create_transaction(vec![reciever_data], 1.into())
            .await
            .unwrap();
        assert!(new_tx.is_valid(), "Created tx must be valid");

        block_1.accumulate_transaction(new_tx);
        assert!(
            block_1.is_valid(&genesis_block),
            "Block 1 must be valid after adding a transaction; previous mutator set hash: {} and next mutator set hash: {}",
            block_1
                .body
                .previous_mutator_set_accumulator
                .hash()
                .emojihash(),
                block_1
                    .body
                    .next_mutator_set_accumulator
                    .hash()
                    .emojihash()
        );

        // Sanity checks
        assert_eq!(
            3,
            block_1.body.transaction.kernel.outputs.len(),
            "New block must have three outputs: coinbase, transaction, and change"
        );
        assert_eq!(
            1,
            block_1.body.transaction.kernel.inputs.len(),
            "New block must have one input: spending of genesis UTXO"
        );
    }

    #[test]
    fn difficulty_to_threshold_test() {
        // Verify that a difficulty of 2 accepts half of the digests
        let difficulty: u32 = 2;
        let difficulty_u32s = U32s::<5>::from(difficulty);
        let threshold_for_difficulty_two: Digest =
            Block::difficulty_to_digest_threshold(difficulty_u32s);

        for elem in threshold_for_difficulty_two.values() {
            assert_eq!(BFieldElement::MAX / u64::from(difficulty), elem.value());
        }

        // Verify that a difficulty of BFieldElement::MAX accepts all digests where the last BFieldElement is zero
        let some_difficulty = U32s::<5>::new([1, u32::MAX, 0, 0, 0]);
        let some_threshold_actual: Digest = Block::difficulty_to_digest_threshold(some_difficulty);

        let bfe_max_elem = BFieldElement::new(BFieldElement::MAX);
        let some_threshold_expected = Digest::new([
            bfe_max_elem,
            bfe_max_elem,
            bfe_max_elem,
            bfe_max_elem,
            BFieldElement::zero(),
        ]);

        assert_eq!(0u64, some_threshold_actual.values()[4].value());
        assert_eq!(some_threshold_actual, some_threshold_expected);
        assert_eq!(bfe_max_elem, some_threshold_actual.values()[3]);
    }
}
