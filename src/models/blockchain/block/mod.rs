use itertools::Itertools;
use mutator_set_tf::util_types::mutator_set::shared::{BATCH_SIZE, CHUNK_SIZE};
use num_traits::{One, Zero};
use secp256k1::ecdsa;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};
use twenty_first::shared_math::lattice::kem::PublicKey;
use twenty_first::shared_math::lattice::ModuleElement;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::mmr::mmr_trait::Mmr;

use mutator_set_tf::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use mutator_set_tf::util_types::mutator_set::mutator_set_trait::{commit, MutatorSet};
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::{amount::u32s::U32s, shared_math::rescue_prime_digest::Digest};

pub mod block_body;
pub mod block_header;
pub mod block_height;
pub mod mutator_set_update;
pub mod transfer_block;

use self::block_body::BlockBody;
use self::block_header::BlockHeader;
use self::block_height::BlockHeight;
use self::mutator_set_update::MutatorSetUpdate;
use self::transfer_block::TransferBlock;
use super::digest::ordered_digest::OrderedDigest;
use super::transaction::transaction_kernel::TransactionKernel;
use super::transaction::utxo::Utxo;
use super::transaction::{amount::Amount, Transaction};
use crate::models::blockchain::address::generation_address;
use crate::models::blockchain::shared::Hash;

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
        // This is just the UNIX timestamp when this code was written
        let timestamp: BFieldElement = BFieldElement::new(1655916990u64);
        let authority_proof = vec![];

        let mut genesis_coinbase_tx = Transaction {
            kernel: TransactionKernel {
                inputs: vec![],
                outputs: vec![],
                public_scripts: vec![],
                fee: 0u32.into(),
                timestamp,
            },
            proof: authority_proof,
        };

        for (receiving_address, amount) in Self::premine_distribution() {
            // generate utxo
            let utxo = Utxo::new_native_coin(receiving_address.lock_script(), amount);
            let utxo_digest = Hash::hash(&utxo);

            // generate "randomness" for mutator set commitment
            // Sender randomness cannot be random because there is
            // no sender.
            let bad_randomness = Digest::default();
            let receiver_digest = receiving_address.privacy_digest;

            // Add pre-mine UTXO to MutatorSet
            let addition_record = commit::<Hash>(&utxo_digest, &bad_randomness, &receiver_digest);
            ms_update.additions.push(addition_record.clone());
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
            target_difficulty: U32s::one(),
            block_body_merkle_root: Hash::hash(&body),
            uncles: vec![],
        };

        Self::new(header, body)
    }

    pub fn premine_distribution() -> Vec<(generation_address::ReceivingAddress, Amount)> {
        // The premine UTXOs can be hardcoded here.
        vec![(
            generation_address::ReceivingAddress {
                receiver_identifier: BFieldElement::new(1),
                encryption_key: PublicKey {
                    seed: [0u8; 32],
                    ga: ModuleElement::zero(),
                },
                privacy_digest: Hash::hash(&Digest::default()),
                spending_digest: Hash::hash(&Digest::default()),
            },
            Amount::zero(),
        )]
    }

    pub fn new(header: BlockHeader, body: BlockBody) -> Self {
        let hash = Hash::hash(&header);
        Self { hash, header, body }
    }

    /// Merge a transaction into this block's transaction using the authority signature on the transaction
    /// Mutator set data must be valid in all inputs.
    pub fn accumulate_transaction(&mut self, transaction: Transaction) {
        // merge
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

        let block_timestamp = BFieldElement::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Got bad time timestamp in mining process")
                .as_millis()
                .try_into()
                .expect("Must call this function before 584 million years from genesis."),
        );

        let block_header = BlockHeader {
            version: self.header.version,
            height: self.header.height,
            mutator_set_hash: next_mutator_set_accumulator.hash(),
            prev_block_digest: self.header.prev_block_digest,
            timestamp: block_timestamp,
            nonce: self.header.nonce,
            max_block_size: self.header.max_block_size,
            proof_of_work_line: self.header.proof_of_work_line,
            proof_of_work_family: self.header.proof_of_work_family,
            target_difficulty: self.header.target_difficulty,
            block_body_merkle_root: Hash::hash(&block_body),
            uncles: vec![],
        };

        self.body = block_body;
        self.hash = Hash::hash(&block_header);
        self.header = block_header;
    }

    fn count_outputs(&self) -> usize {
        self.body.transaction.kernel.outputs.len()
    }

    fn count_inputs(&self) -> usize {
        self.body.transaction.kernel.inputs.len()
    }

    /// Verify a block. It is assumed that `previous_block` is valid.
    /// Note that this function does **not** check that the PoW digest is below the threshold.
    /// That must be done separately by the caller.
    pub(crate) fn is_valid_for_devnet(&self, previous_block: &Block) -> bool {
        // The block value doesn't actually change. Some function calls just require
        // mutable references because that's how the interface was defined for them.
        let mut block_copy = self.to_owned();
        // What belongs here are the things that would otherwise
        // be verified by the block validity proof.

        // 0. `previous_block` is consistent with current block
        //   a) Block height is previous plus one
        //   b) Block header points to previous block
        //   c) Next mutator set of previous block matches previous MS of current block
        // 1. The transaction is valid.
        // 1'. All transactions are valid.
        // (with coinbase UTXO flag set)
        //   a) verify that MS membership proof is valid, done against `previous_mutator_set_accumulator`,
        //   b) Verify that MS removal record is valid, done against `previous_mutator_set_accumulator`,
        //   c) Verify that all removal records have unique index sets
        //   d) verify that adding `mutator_set_update` to `previous_mutator_set_accumulator`
        //      gives `next_mutator_set_accumulator`,
        //   e) transaction timestamp <= block timestamp
        //   f) call: `transaction.devnet_is_valid()`

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

        // 0.c) Next mutator set of previous block matches previous MS of current block
        if previous_block.body.next_mutator_set_accumulator
            != block_copy.body.previous_mutator_set_accumulator
        {
            warn!("Value for previous mutator set does not match previous block");
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
        let mut mutator_set_update = MutatorSetUpdate::new(
            block_copy.body.transaction.kernel.inputs.clone(),
            block_copy.body.transaction.kernel.outputs.clone(),
        );
        let mut ms = block_copy.body.previous_mutator_set_accumulator.clone();
        let ms_update_result = mutator_set_update.apply(&mut ms);
        match ms_update_result {
            Ok(_) => (),
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

        // 1.f) Verify transaction, but without relating it to the blockchain tip (that was done above).
        let miner_reward: Amount = Self::get_mining_reward(block_copy.header.height);
        if !block_copy.body.transaction.is_valid(Some(miner_reward)) {
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
        if !self.is_valid_for_devnet(previous_block) {
            warn!("Block devnet test failed");
            return false;
        }

        true
    }
}

#[cfg(test)]
mod block_tests {
    use crate::{
        config_models::network::Network,
        models::state::wallet::{self, WalletSecret},
        tests::shared::get_mock_global_state,
    };

    use super::*;

    use anyhow::Result;
    use tracing_test::traced_test;

    // #[traced_test]
    // #[tokio::test]
    // async fn merge_transaction_test() -> Result<()> {
    //     // We need the global state to construct a transaction. This global state
    //     // has a wallet which receives a premine-UTXO.
    //     let global_state = get_mock_global_state(Network::Main, 2, None).await;
    //     let genesis_block = Block::genesis_block();
    //     let mut block_1 = make_mock_block(
    //         &genesis_block,
    //         None,
    //         global_state.wallet_state.wallet_secret.get_public_key(),
    //     );
    //     assert!(
    //         block_1.is_valid_for_devnet(&genesis_block),
    //         "Block 1 must be valid with only coinbase output"
    //     );

    //     // create a new transaction, merge it into block 1 and check that block 1 is still valid
    //     let other_wallet = WalletSecret::new(wallet::generate_secret_key());
    //     let new_utxo = Utxo {
    //         amount: 5.into(),
    //         public_key: other_wallet.get_public_key(),
    //     };
    //     let new_tx = global_state
    //         .create_transaction(vec![new_utxo], 1.into())
    //         .await
    //         .unwrap();
    //     block_1.authority_merge_transaction(new_tx);
    //     assert!(
    //         block_1.is_valid_for_devnet(&genesis_block),
    //         "Block 1 must be valid after adding a transaction"
    //     );

    //     // Sanity checks
    //     assert_eq!(
    //         3,
    //         block_1.body.transaction.outputs.len(),
    //         "New block must have three outputs: coinbase, transaction, and change"
    //     );
    //     assert_eq!(
    //         1,
    //         block_1.body.transaction.inputs.len(),
    //         "New block must have one input: spending of genesis UTXO"
    //     );

    //     Ok(())
    // }
}
