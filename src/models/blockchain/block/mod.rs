use num_traits::{One, Zero};
use secp256k1::ecdsa;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use mutator_set_tf::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use mutator_set_tf::util_types::mutator_set::mutator_set_trait::MutatorSet;
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
use super::transaction::utxo::Utxo;
use super::transaction::{amount::Amount, Transaction};
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
        let authority_proof: Option<ecdsa::Signature> = None;

        let mut genesis_coinbase_tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            public_scripts: vec![],
            fee: 0u32.into(),
            timestamp,
            authority_proof,
        };

        for premine_utxo in Self::premine_utxos() {
            // A commitment to the pre-mine UTXO
            let utxo_commitment = Hash::hash(&premine_utxo);

            // This isn't random.
            let bad_randomness = Digest::default();

            // Add pre-mine UTXO to MutatorSet
            let mut addition_record = genesis_mutator_set.commit(&utxo_commitment, &bad_randomness);
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
            version: BFieldElement::zero(),
            height: BFieldElement::zero().into(),
            mutator_set_commitment: genesis_mutator_set.get_commitment(),
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

    pub fn premine_utxos() -> Vec<Utxo> {
        // The premine UTXOs can be hardcoded here.
        // let devnet_authority_wallet = Wallet::devnet_authority_wallet();
        vec![Utxo::new_from_hex(
            20000.into(),
            "02411147a47b398f5ee938241aaeb76a68af37645bdee5b0d29407c2c7a8496db4",
            // &devnet_authority_wallet.get_public_key().to_string(),
        )]
    }

    pub fn new(header: BlockHeader, body: BlockBody) -> Self {
        let hash = Hash::hash(&header);
        Self { hash, header, body }
    }

    /// Merge a transaction into this block's transaction using the authority signature on the transaction
    /// Mutator set data must be valid in all inputs.
    pub fn authority_merge_transaction(&mut self, transaction: Transaction) {
        let new_transaction = self.body.transaction.clone().merge_with(transaction);

        let mut additions = Vec::with_capacity(new_transaction.outputs.len());
        let mut removals = Vec::with_capacity(new_transaction.inputs.len());
        let mut next_mutator_set_accumulator = self.body.previous_mutator_set_accumulator.clone();

        for (output_utxo, randomness) in new_transaction.outputs.iter() {
            let addition_record =
                next_mutator_set_accumulator.commit(&Hash::hash(output_utxo), randomness);
            additions.push(addition_record);
        }

        for devnet_input in new_transaction.inputs.iter() {
            removals.push(devnet_input.removal_record.clone());
        }

        let mutator_set_update = MutatorSetUpdate::new(removals, additions);

        // Apply the mutator set update to get the `next_mutator_set_accumulator`
        mutator_set_update
            .apply(&mut next_mutator_set_accumulator)
            .expect("Mutator set mutation must work");

        let block_body: BlockBody = BlockBody {
            transaction: new_transaction,
            next_mutator_set_accumulator: next_mutator_set_accumulator.clone(),
            previous_mutator_set_accumulator: self.body.previous_mutator_set_accumulator.clone(),
            mutator_set_update,
            stark_proof: vec![],
        };

        let block_timestamp = BFieldElement::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Got bad time timestamp in mining process")
                .as_secs(),
        );

        let block_header = BlockHeader {
            version: self.header.version,
            height: self.header.height,
            mutator_set_commitment: next_mutator_set_accumulator.get_commitment(),
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
        self.body.transaction.outputs.len()
    }

    fn count_inputs(&self) -> usize {
        self.body.transaction.inputs.len()
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
        //   c) verify that all transactions are represented in mutator_set_update
        //     i) Verify that all input UTXOs are present in `removals`
        //     ii) Verify that all output UTXOs are present in `additions`
        //     iii) That there are no entries in `mutator_set_update` not present in a transaction.
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

        for (i, input) in block_copy.body.transaction.inputs.iter().enumerate() {
            // 1.a) Verify validity of membership proofs
            if !block_copy.body.previous_mutator_set_accumulator.verify(
                &Hash::hash(&input.utxo),
                &input.membership_proof.clone().into(),
            ) {
                warn!("Invalid membership proof found in block for input {}", i);
                return false;
            }
        }

        // 1.b) Verify validity of removal records: That their MMR MPs match the SWBF, and
        // that at least one of their bits is not set yet.
        // TODO

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
        for (utxo, randomness) in block_copy.body.transaction.outputs.iter() {
            let expected_commitment = Hash::hash_pair(&Hash::hash(utxo), &randomness.to_owned());
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
                "From Block\n{:?}. \n\n\nCalculated\n{:?}",
                block_copy.body.next_mutator_set_accumulator, ms
            );
            return false;
        }

        // Verify that the locally constructed mutator set matches that in the received block's header
        if ms.get_commitment() != block_copy.header.mutator_set_commitment {
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
            .is_valid_for_devnet(Some(miner_reward))
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
        models::state::wallet::{self, Wallet},
        tests::shared::{get_mock_global_state, make_mock_block},
    };

    use super::*;

    use anyhow::Result;
    use tracing_test::traced_test;

    #[traced_test]
    #[tokio::test]
    async fn merge_transaction_test() -> Result<()> {
        // We need the global state to construct a transaction. This global state
        // has a wallet which receives a premine-UTXO.
        let global_state = get_mock_global_state(Network::Main, 2, None).await;
        let genesis_block = Block::genesis_block();
        let mut block_1 = make_mock_block(
            &genesis_block,
            None,
            global_state.wallet_state.wallet.get_public_key(),
        );
        assert!(
            block_1.is_valid_for_devnet(&genesis_block),
            "Block 1 must be valid with only coinbase output"
        );

        // create a new transaction, merge it into block 1 and check that block 1 is still valid
        let other_wallet = Wallet::new(wallet::generate_secret_key());
        let new_utxo = Utxo {
            amount: 5.into(),
            public_key: other_wallet.get_public_key(),
        };
        let new_tx = global_state
            .create_transaction(vec![new_utxo], 1.into())
            .await
            .unwrap();
        block_1.authority_merge_transaction(new_tx);
        assert!(
            block_1.is_valid_for_devnet(&genesis_block),
            "Block 1 must be valid after adding a transaction"
        );

        // Sanity checks
        assert_eq!(
            3,
            block_1.body.transaction.outputs.len(),
            "New block must have three outputs: coinbase, transaction, and change"
        );
        assert_eq!(
            1,
            block_1.body.transaction.inputs.len(),
            "New block must have one input: spending of genesis UTXO"
        );

        Ok(())
    }
}
