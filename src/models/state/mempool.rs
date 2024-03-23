//! An implementation of a mempool to store broadcast transactions waiting to be
//! mined.  The implementation maintains a mapping called `table` between
//! 'transaction digests' and the full 'transactions' object, as well as a
//! double-ended priority queue called `queue` containing sorted pairs of
//! 'transaction digests' and the associated 'fee density'.  The `table` can be
//! seen as an associative cache that provides fast random-lookups, while
//! `queue` maintains transactions id's ordered by 'fee density'. Usually, we
//! are interested in the transaction with either the highest or the lowest 'fee
//! density'.

use crate::{
    models::{blockchain::type_scripts::neptune_coins::NeptuneCoins, consensus::WitnessType},
    prelude::twenty_first,
    util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator,
};

use bytesize::ByteSize;
use get_size::GetSize;
use num_traits::Zero;
use priority_queue::{double_priority_queue::iterators::IntoSortedIter, DoublePriorityQueue};
use std::{
    collections::{hash_map::RandomState, HashMap, HashSet},
    iter::Rev,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use twenty_first::shared_math::digest::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use crate::models::blockchain::block::Block;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::Transaction;

/// `FeeDensity` is a measure of 'Fee/Bytes' or 'reward per storage unit' for a
/// transactions.  Different strategies are possible for selecting transactions
/// to mine, but a simple one is to pick transactions in descending order of
/// highest `FeeDensity`.
/// Note 1:  The `FeeDensity` is not part of the consensus mechanism, and may
/// even be ignored by the miner.
/// Note 2:  That `FeeDensity` does not exhibit 'greedy choice property':
///
/// # Counterexample
///
/// TransactionA = { Fee: 10, Size: 3 } => FeeDensity: 10/3
/// TransactionB = { Fee: 6,  Size: 2 } => FeeDensity:  6/2
/// TransactionC = { Fee: 6,  Size: 2 } => FeeDensity:  6/2
///
/// If available space is 4, then the greedy choice on `FeeDensity` would select
/// the set { TransactionA } while the optimal solution is { TransactionB,
/// TransactionC }.
use num_rational::BigRational as FeeDensity;

// 72 hours in secs
pub const MEMPOOL_TX_THRESHOLD_AGE_IN_SECS: u64 = 72 * 60 * 60;
// 5 minutes in secs
pub const MEMPOOL_IGNORE_TRANSACTIONS_THIS_MANY_SECS_AHEAD: u64 = 5 * 60;

pub const TRANSACTION_NOTIFICATION_AGE_LIMIT_IN_SECS: u64 = 60 * 60 * 24;

type LookupItem<'a> = (Digest, &'a Transaction);

/// Timestamp of 'now' encoded as the duration since epoch.
fn now() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

#[derive(Debug, Clone, PartialEq, Eq, GetSize)]
pub struct Mempool {
    max_total_size: usize,

    // Maintain for constant lookup
    tx_dictionary: HashMap<Digest, Transaction>,

    // Maintain for fast min and max
    #[get_size(ignore)] // This is relatively small compared to `LookupTable`
    queue: DoublePriorityQueue<Digest, FeeDensity>,
}

impl Mempool {
    /// instantiate a new `Mempool`
    pub fn new(max_total_size: ByteSize) -> Self {
        let table = Default::default();
        let queue = Default::default();
        let max_total_size = max_total_size.0.try_into().unwrap();
        Self {
            max_total_size,
            tx_dictionary: table,
            queue,
        }
    }

    /// check if transaction exists in mempool
    ///
    /// Computes in O(1) from HashMap
    pub fn contains(&self, transaction_id: Digest) -> bool {
        self.tx_dictionary.contains_key(&transaction_id)
    }

    /// get transaction from mempool
    ///
    /// Computes in O(1) from HashMap
    pub fn get(&self, transaction_id: Digest) -> Option<&Transaction> {
        self.tx_dictionary.get(&transaction_id)
    }

    /// Returns `Some(txid, transaction)` iff a transcation conflicts with a block that's already in
    /// the mempool. Returns `None` otherwise.
    fn transaction_conflicts_with(
        &self,
        transaction: &Transaction,
    ) -> Option<(Digest, Transaction)> {
        // This check could be made a lot more efficient, for example with an invertible Bloom filter
        let tx_sbf_indices: HashSet<_> = transaction
            .kernel
            .inputs
            .iter()
            .map(|x| x.absolute_indices.to_array())
            .collect();

        for (txid, tx) in self.tx_dictionary.iter() {
            for mempool_tx_input in tx.kernel.inputs.iter() {
                if tx_sbf_indices.contains(&mempool_tx_input.absolute_indices.to_array()) {
                    return Some((*txid, tx.to_owned()));
                }
            }
        }

        None
    }

    /// Insert a transaction into the mempool. It is the caller's responsibility to validate
    /// the transaction. Also, the caller must ensure that the witness type is correct --
    /// this method accepts only fully proven transactions (or, for the time being, faith witnesses).
    pub fn insert(&mut self, transaction: &Transaction) -> Option<Digest> {
        match transaction.witness.vast.witness_type {
            WitnessType::RawWitness(_) => panic!("Can only insert fully proven transactions into mempool; not accepting raw witnesses."),
            WitnessType::Decomposition => panic!("Can only insert fully proven transactions into mempool; not accepting decompositions."),
            WitnessType::None => panic!("Can only insert fully proven transactions into mempool; not accepting none."),
            WitnessType::Faith => {},
            WitnessType::Proof(_) => {},
        }
        // If transaction to be inserted conflicts with a transaction that's already
        // in the mempool we preserve only the one with the highest fee density.
        if let Some((txid, tx)) = self.transaction_conflicts_with(transaction) {
            if tx.fee_density() < transaction.fee_density() {
                // If new transaction has a higher fee density than the one previously seen
                // remove the old one.
                self.remove(txid);
            } else {
                // If new transaction has a lower fee density than the one previous seen,
                // ignore it. Stop execution here.
                return Some(txid);
            }
        };

        let transaction_id: Digest = Hash::hash(transaction);

        self.queue.push(transaction_id, transaction.fee_density());
        self.tx_dictionary
            .insert(transaction_id, transaction.to_owned());
        assert_eq!(
            self.tx_dictionary.len(),
            self.queue.len(),
            "mempool's table and queue length must agree prior to shrink"
        );
        self.shrink_to_max_size();
        assert_eq!(
            self.tx_dictionary.len(),
            self.queue.len(),
            "mempool's table and queue length must agree after shrink"
        );
        None
    }

    /// remove a transaction from the `Mempool`
    pub fn remove(&mut self, transaction_id: Digest) -> Option<Transaction> {
        if let rv @ Some(_) = self.tx_dictionary.remove(&transaction_id) {
            self.queue.remove(&transaction_id);
            debug_assert_eq!(self.tx_dictionary.len(), self.queue.len());
            return rv;
        }

        None
    }

    /// Return the number of transactions currently stored in the Mempool.
    /// Computes in O(1)
    pub fn len(&self) -> usize {
        self.tx_dictionary.len()
    }

    /// check if `Mempool` is empty
    ///
    /// Computes in O(1)
    pub fn is_empty(&self) -> bool {
        self.tx_dictionary.is_empty()
    }

    /// Return a vector with copies of the transactions, in descending order by fee
    /// density and using at most `remaining_storage` bytes.
    pub fn get_transactions_for_block(&self, mut remaining_storage: usize) -> Vec<Transaction> {
        let mut transactions = vec![];
        let mut _fee_acc = NeptuneCoins::zero();

        for (transaction_digest, _fee_density) in self.get_sorted_iter() {
            // No more transactions can possibly be packed
            if remaining_storage == 0 {
                break;
            }

            if let Some(transaction_ptr) = self.get(transaction_digest) {
                let transaction_copy = transaction_ptr.to_owned();
                let transaction_size = transaction_copy.get_size();

                // Current transaction is too big
                if transaction_size > remaining_storage {
                    continue;
                }

                // Include transaction
                remaining_storage -= transaction_size;
                _fee_acc = _fee_acc + transaction_copy.kernel.fee;
                transactions.push(transaction_copy)
            }
        }

        transactions
    }

    /// Computes in θ(lg N)
    #[allow(dead_code)]
    pub fn pop_max(&mut self) -> Option<(Transaction, FeeDensity)> {
        if let Some((transaction_digest, fee_density)) = self.queue.pop_max() {
            let transaction = self.tx_dictionary.remove(&transaction_digest).unwrap();
            debug_assert_eq!(self.tx_dictionary.len(), self.queue.len());
            Some((transaction, fee_density))
        } else {
            None
        }
    }

    /// Computes in θ(lg N)
    pub fn pop_min(&mut self) -> Option<(Transaction, FeeDensity)> {
        if let Some((transaction_digest, fee_density)) = self.queue.pop_min() {
            let transaction = self.tx_dictionary.remove(&transaction_digest).unwrap();
            debug_assert_eq!(self.tx_dictionary.len(), self.queue.len());
            Some((transaction, fee_density))
        } else {
            None
        }
    }

    /// Modelled after [HashMap::retain](std::collections::HashMap::retain())
    ///
    /// Computes in O(capacity) >= O(N)
    pub fn retain<F>(&mut self, mut predicate: F)
    where
        F: FnMut(LookupItem) -> bool,
    {
        let mut victims = vec![];

        for (&transaction_id, _fee_density) in self.queue.iter() {
            let transaction = self.get(transaction_id).unwrap();
            if !predicate((transaction_id, transaction)) {
                victims.push(transaction_id);
            }
        }

        for t in victims {
            self.remove(t);
        }

        debug_assert_eq!(self.tx_dictionary.len(), self.queue.len());
        self.shrink_to_fit()
    }

    /// Prune based on `Transaction.timestamp`
    /// Computes in O(n)
    pub fn prune_stale_transactions(&mut self) {
        let cutoff = now() - Duration::from_secs(MEMPOOL_TX_THRESHOLD_AGE_IN_SECS);

        let keep = |(_transaction_id, transaction): LookupItem| -> bool {
            cutoff.as_secs() < transaction.kernel.timestamp.value()
        };

        self.retain(keep);
    }

    /// Remove from the mempool all transactions that become invalid because
    /// of this newly mined block. Also update all mutator set data for monitored
    /// transactions that were not removed in the previous step.
    pub async fn update_with_block(
        &mut self,
        previous_mutator_set_accumulator: MutatorSetAccumulator,
        block: &Block,
    ) {
        // The general strategy is to check whether the SWBF index set of a given
        // transaction in the mempool is disjoint (*i.e.*, not contained by) the
        // SWBF indices coming from the block transaction. If they are not disjoint,
        // then remove the transaction from the mempool.

        // Compute the union of all index sets generated by the block transaction.
        let swbf_index_set_union: HashSet<_> = block
            .kernel
            .body
            .transaction
            .kernel
            .inputs
            .iter()
            .flat_map(|rr| rr.absolute_indices.to_array())
            .collect();

        // The indices that the block transaction inserts are used to determine
        // which mempool transactions contain UTXOs that were spent in this block. Any
        // transaction that contains just *one* input-UTXO that was spent in
        // this block is invalid
        let keep = |(_transaction_id, tx): LookupItem| -> bool {
            let transaction_index_sets: HashSet<_> = tx
                .kernel
                .inputs
                .iter()
                .map(|rr| rr.absolute_indices.to_array())
                .collect();

            transaction_index_sets.iter().all(|index_set| {
                index_set
                    .iter()
                    .any(|index| !swbf_index_set_union.contains(index))
            })
        };

        // Remove the transactions that become invalid with this block
        self.retain(keep);

        // Update the remaining transactions so their mutator set data is still valid
        for tx in self.tx_dictionary.values_mut() {
            *tx = tx
                .new_with_updated_mutator_set_records(&previous_mutator_set_accumulator, block)
                .await
                .expect("Updating mempool transaction must succeed");
        }

        // Maintaining the mutator set data could have increased the size of the
        // transactions in the mempool. So we should shrink it to max size after
        // applying the block.
        self.shrink_to_max_size();
    }

    /// Shrink the memory pool to the value of its `max_size` field.
    /// Likely computes in O(n)
    fn shrink_to_max_size(&mut self) {
        // Repeately remove the least valuable transaction
        while self.get_size() > self.max_total_size && self.pop_min().is_some() {
            continue;
        }

        self.shrink_to_fit()
    }

    /// Shrinks internal data structures as much as possible.
    /// Computes in O(n) (Likely)
    fn shrink_to_fit(&mut self) {
        self.queue.shrink_to_fit();
        self.tx_dictionary.shrink_to_fit()
    }

    /// Produce a sorted iterator over a snapshot of the Double-Ended Priority Queue.
    ///
    /// # Example
    ///
    /// ```
    /// use neptune_core::models::state::mempool::Mempool;
    /// use bytesize::ByteSize;
    ///
    /// let mempool = Mempool::new(ByteSize::gb(1));
    /// // insert transactions here.
    /// let mut most_valuable_transactions = vec![];
    /// for (transaction_digest, fee_density) in mempool.get_sorted_iter() {
    ///    let t = mempool.get(transaction_digest);
    ///    most_valuable_transactions.push(t);
    /// }
    /// ```
    ///
    /// Yields the `transaction_digest` in order of descending `fee_density`, since
    /// users (miner or transaction merger) will likely only care about the most valuable transactions
    /// Computes in O(N lg N)
    pub fn get_sorted_iter(&self) -> Rev<IntoSortedIter<Digest, FeeDensity, RandomState>> {
        let dpq_clone = self.queue.clone();
        dpq_clone.into_sorted_iter().rev()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config_models::network::Network,
        models::{
            blockchain::{
                block::block_height::BlockHeight,
                transaction::{utxo::Utxo, PublicAnnouncement, Transaction},
                type_scripts::neptune_coins::NeptuneCoins,
            },
            shared::SIZE_20MB_IN_BYTES,
            state::{
                wallet::{utxo_notification_pool::UtxoNotifier, WalletSecret},
                UtxoReceiverData,
            },
        },
        tests::shared::{
            get_mock_global_state, get_mock_wallet_state, make_mock_block,
            make_mock_transaction_with_wallet,
        },
        util_types::mutator_set::mutator_set_trait::*,
    };
    use anyhow::Result;
    use itertools::Itertools;
    use num_bigint::BigInt;
    use num_traits::Zero;
    use rand::{random, rngs::StdRng, thread_rng, Rng, SeedableRng};
    use tracing::debug;
    use tracing_test::traced_test;
    use twenty_first::{
        shared_math::b_field_element::BFieldElement, util_types::emojihash_trait::Emojihash,
    };

    #[tokio::test]
    pub async fn insert_then_get_then_remove_then_get() {
        let mut mempool = Mempool::new(ByteSize::gb(1));
        let network = Network::Alpha;
        let wallet_state = get_mock_wallet_state(WalletSecret::devnet_wallet(), network).await;
        let transaction = make_mock_transaction_with_wallet(
            vec![],
            vec![],
            NeptuneCoins::zero(),
            &wallet_state,
            None,
        );
        let transaction_digest = Hash::hash(&transaction);
        assert!(!mempool.contains(transaction_digest));
        mempool.insert(&transaction);
        assert!(mempool.contains(transaction_digest));

        let transaction_get_option = mempool.get(transaction_digest);
        assert_eq!(Some(&transaction), transaction_get_option);
        assert!(mempool.contains(transaction_digest));

        let transaction_remove_option = mempool.remove(transaction_digest);
        assert_eq!(Some(transaction), transaction_remove_option);
        assert!(!mempool.contains(transaction_digest));

        let transaction_second_remove_option = mempool.remove(transaction_digest);
        assert_eq!(None, transaction_second_remove_option);
        assert!(!mempool.contains(transaction_digest))
    }

    // Create a mempool with n transactions.
    async fn setup(transactions_count: u32, network: Network) -> Mempool {
        let mut mempool = Mempool::new(ByteSize::gb(1));
        let wallet_state = get_mock_wallet_state(WalletSecret::devnet_wallet(), network).await;
        for i in 0..transactions_count {
            let t = make_mock_transaction_with_wallet(
                vec![],
                vec![],
                NeptuneCoins::new(i),
                &wallet_state,
                None,
            );
            mempool.insert(&t);
        }
        mempool
    }

    // #[traced_test]
    #[tokio::test]
    async fn get_densest_transactions() {
        // Verify that transactions are returned ordered by fee density, with highest fee density first
        let mempool = setup(10, Network::RegTest).await;

        let max_fee_density: FeeDensity = FeeDensity::new(BigInt::from(u128::MAX), BigInt::from(1));
        let mut prev_fee_density = max_fee_density;
        for curr_transaction in mempool.get_transactions_for_block(SIZE_20MB_IN_BYTES) {
            let curr_fee_density = curr_transaction.fee_density();
            assert!(curr_fee_density <= prev_fee_density);
            prev_fee_density = curr_fee_density;
        }
        assert!(!mempool.is_empty())
    }

    #[traced_test]
    #[tokio::test]
    async fn get_sorted_iter() {
        // Verify that the function `get_sorted_iter` returns transactions sorted by fee density
        let mempool = setup(10, Network::Alpha).await;

        let max_fee_density: FeeDensity = FeeDensity::new(BigInt::from(u128::MAX), BigInt::from(1));
        let mut prev_fee_density = max_fee_density;
        for (_transaction_id, curr_fee_density) in mempool.get_sorted_iter() {
            assert!(curr_fee_density <= prev_fee_density);
            prev_fee_density = curr_fee_density;
        }
        assert!(!mempool.is_empty())
    }

    #[traced_test]
    #[tokio::test]
    async fn prune_stale_transactions() {
        let wallet_state =
            get_mock_wallet_state(WalletSecret::devnet_wallet(), Network::Alpha).await;
        let mut mempool = Mempool::new(ByteSize::gb(1));
        assert!(
            mempool.is_empty(),
            "Mempool must be empty after initialization"
        );

        let eight_days_ago = now() - Duration::from_secs(8 * 24 * 60 * 60);
        let timestamp = Some(BFieldElement::new(eight_days_ago.as_secs()));

        for i in 0u32..5 {
            let t = make_mock_transaction_with_wallet(
                vec![],
                vec![],
                NeptuneCoins::new(i),
                &wallet_state,
                timestamp,
            );
            mempool.insert(&t);
        }

        for i in 0u32..5 {
            let t = make_mock_transaction_with_wallet(
                vec![],
                vec![],
                NeptuneCoins::new(i),
                &wallet_state,
                None,
            );
            mempool.insert(&t);
        }
        assert_eq!(mempool.len(), 10);
        mempool.prune_stale_transactions();
        assert_eq!(mempool.len(), 5)
    }

    #[traced_test]
    #[tokio::test]
    async fn remove_transactions_with_block_test() -> Result<()> {
        let seed = {
            let mut rng: StdRng =
                SeedableRng::from_rng(thread_rng()).expect("failure lifting thread_rng to StdRng");
            let seed: [u8; 32] = rng.gen();
            // let seed = [
            //     0x19, 0xba, 0xc1, 0x55, 0xa7, 0xa0, 0x33, 0xcc, 0x85, 0x73, 0x47, 0xad, 0xd2, 0x1b,
            //     0x4e, 0x30, 0x54, 0x4b, 0xd3, 0x2e, 0xe0, 0xc2, 0x21, 0xe6, 0x96, 0x82, 0x2a, 0x6, 0xe,
            //     0xe2, 0xa, 0xda,
            // ];
            println!(
                "seed: [{}]",
                seed.iter().map(|h| format!("{:#x}", h)).join(", ")
            );
            seed
        };

        let mut rng: StdRng = SeedableRng::from_seed(seed);
        // We need the global state to construct a transaction. This global state
        // has a wallet which receives a premine-UTXO.
        let devnet_wallet = WalletSecret::devnet_wallet();
        let premine_receiver_global_state_lock =
            get_mock_global_state(Network::Alpha, 2, devnet_wallet).await;
        let mut premine_receiver_global_state =
            premine_receiver_global_state_lock.lock_guard_mut().await;

        let premine_wallet_secret = &premine_receiver_global_state.wallet_state.wallet_secret;
        let premine_receiver_spending_key = premine_wallet_secret.nth_generation_spending_key(0);
        let premine_receiver_address = premine_receiver_spending_key.to_address();
        let other_wallet_secret = WalletSecret::new_pseudorandom(rng.gen());

        let other_global_state_lock =
            get_mock_global_state(Network::Alpha, 2, other_wallet_secret.clone()).await;
        let mut other_global_state = other_global_state_lock.lock_guard_mut().await;
        let other_receiver_spending_key = other_wallet_secret.nth_generation_spending_key(0);
        let other_receiver_address = other_receiver_spending_key.to_address();

        // Ensure that both wallets have a non-zero balance
        let genesis_block = Block::genesis_block().await;
        let (block_1, coinbase_utxo_1, cb_sender_randomness_1) =
            make_mock_block(&genesis_block, None, other_receiver_address, rng.gen()).await;

        // Update both states with block 1
        premine_receiver_global_state
            .wallet_state
            .update_wallet_state_with_new_block(
                &genesis_block.kernel.body.mutator_set_accumulator,
                &block_1,
            )
            .await?;
        premine_receiver_global_state
            .chain
            .light_state_mut()
            .set_block(block_1.clone());
        other_global_state
            .wallet_state
            .expected_utxos
            .add_expected_utxo(
                coinbase_utxo_1,
                cb_sender_randomness_1,
                other_receiver_spending_key.privacy_preimage,
                UtxoNotifier::OwnMiner,
            )
            .expect("UTXO notification from miner must be accepted");
        other_global_state
            .wallet_state
            .update_wallet_state_with_new_block(
                &genesis_block.kernel.body.mutator_set_accumulator,
                &block_1,
            )
            .await?;
        other_global_state
            .chain
            .light_state_mut()
            .set_block(block_1.clone());

        // Create a transaction that's valid to be included in block 2
        let mut output_utxos_generated_by_me: Vec<UtxoReceiverData> = vec![];
        for i in 0..7 {
            let amount: NeptuneCoins = NeptuneCoins::new(i);
            let new_utxo = Utxo {
                coins: amount.to_native_coins(),
                lock_script_hash: premine_receiver_address.lock_script().hash(),
            };

            output_utxos_generated_by_me.push(UtxoReceiverData {
                public_announcement: PublicAnnouncement::default(),
                receiver_privacy_digest: premine_receiver_address.privacy_digest,
                sender_randomness: random(),
                utxo: new_utxo,
            });
        }
        let mut now = Duration::from_millis(genesis_block.kernel.header.timestamp.value());
        let seven_months = Duration::from_millis(7 * 30 * 24 * 60 * 60 * 1000);
        let tx_by_preminer = premine_receiver_global_state
            .create_transaction(
                output_utxos_generated_by_me,
                NeptuneCoins::new(1),
                now + seven_months,
            )
            .await?;

        // Add this transaction to the mempool
        let mut mempool = Mempool::new(ByteSize::gb(1));
        mempool.insert(&tx_by_preminer);

        // Create another transaction that's valid to be included in block 2, but isn't actually
        // included by the miner. This transaction is inserted into the mempool, but since it's
        // not included in block 2 it must still be in the mempool after the mempool has been
        // updated with block 2. Also: The transaction must be valid after block 2 as the mempool
        // manager must keep mutator set data updated.
        let output_utxo_data_by_miner = vec![UtxoReceiverData {
            utxo: Utxo {
                coins: NeptuneCoins::new(68).to_native_coins(),
                lock_script_hash: other_receiver_address.lock_script().hash(),
            },
            sender_randomness: random(),
            receiver_privacy_digest: other_receiver_address.privacy_digest,
            public_announcement: PublicAnnouncement::default(),
        }];
        let tx_by_other_original = other_global_state
            .create_transaction(
                output_utxo_data_by_miner,
                NeptuneCoins::new(1),
                now + seven_months,
            )
            .await
            .unwrap();
        mempool.insert(&tx_by_other_original);

        // Create next block which includes preminer's transaction
        let (mut block_2, _, _) =
            make_mock_block(&block_1, None, premine_receiver_address, rng.gen()).await;
        block_2
            .accumulate_transaction(tx_by_preminer, &block_1.kernel.body.mutator_set_accumulator)
            .await;

        // Update the mempool with block 2 and verify that the mempool now only contains one tx
        assert_eq!(2, mempool.len());
        mempool
            .update_with_block(block_1.kernel.body.mutator_set_accumulator, &block_2)
            .await;
        assert_eq!(1, mempool.len());

        // Create a new block to verify that the non-mined transaction contains
        // updated and valid-again mutator set data
        let mut tx_by_other_updated: Transaction =
            mempool.get_transactions_for_block(usize::MAX)[0].clone();

        debug!(
            "mempool now has transaction relative to mutator set hash {}",
            tx_by_other_updated.kernel.mutator_set_hash.emojihash()
        );

        let (block_3_with_no_input, _, _) =
            make_mock_block(&block_2, None, premine_receiver_address, rng.gen()).await;
        let mut block_3_with_updated_tx = block_3_with_no_input.clone();

        debug!(
            "Just made block with previous mutator set hash {}",
            block_2
                .kernel
                .body
                .mutator_set_accumulator
                .hash()
                .await
                .emojihash()
        );
        debug!(
            "Just made block with next mutator set hash {}",
            block_3_with_updated_tx
                .kernel
                .body
                .mutator_set_accumulator
                .hash()
                .await
                .emojihash()
        );

        debug!(
            "tx_by_other_updated has mutator set hash: {}",
            tx_by_other_updated.kernel.mutator_set_hash.emojihash()
        );
        block_3_with_updated_tx
            .accumulate_transaction(
                tx_by_other_updated.clone(),
                &block_2.kernel.body.mutator_set_accumulator,
            )
            .await;
        now = Duration::from_millis(block_2.kernel.header.timestamp.value());
        assert!(
            block_3_with_updated_tx
                .is_valid(&block_2, now + seven_months)
                .await,
            "Block with tx with updated mutator set data must be valid"
        );

        // Mine 10 more blocks without including the transaction but while still keeping the
        // mempool updated. After these 10 blocks are mined, the transaction must still be
        // valid.
        let mut previous_block = block_3_with_no_input;
        for _ in 0..10 {
            let (next_block, _, _) =
                make_mock_block(&previous_block, None, other_receiver_address, rng.gen()).await;
            mempool
                .update_with_block(
                    previous_block.kernel.body.mutator_set_accumulator,
                    &next_block,
                )
                .await;
            previous_block = next_block;
        }

        let (mut block_14, _, _) =
            make_mock_block(&previous_block, None, other_receiver_address, rng.gen()).await;
        assert_eq!(Into::<BlockHeight>::into(14), block_14.kernel.header.height);
        tx_by_other_updated = mempool.get_transactions_for_block(usize::MAX)[0].clone();
        block_14
            .accumulate_transaction(
                tx_by_other_updated,
                &previous_block.kernel.body.mutator_set_accumulator,
            )
            .await;
        now = Duration::from_millis(previous_block.kernel.header.timestamp.value());
        assert!(
            block_14.is_valid(&previous_block, now+seven_months).await,
            "Block with tx with updated mutator set data must be valid after 10 blocks have been mined"
        );

        mempool
            .update_with_block(
                previous_block.kernel.body.mutator_set_accumulator,
                &block_14,
            )
            .await;

        assert!(
            mempool.is_empty(),
            "Mempool must be empty after 2nd tx was mined"
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn conflicting_txs_preserve_highest_fee() -> Result<()> {
        // Create a global state object, controlled by a preminer who receives a premine-UTXO.
        let preminer_state_lock =
            get_mock_global_state(Network::Alpha, 2, WalletSecret::devnet_wallet()).await;
        let now =
            Duration::from_millis(Block::genesis_block().await.kernel.header.timestamp.value());
        let seven_months = Duration::from_millis(7 * 30 * 24 * 60 * 60 * 1000);
        let mut preminer_state = preminer_state_lock.lock_guard_mut().await;
        let premine_wallet_secret = &preminer_state.wallet_state.wallet_secret;
        let premine_spending_key = premine_wallet_secret.nth_generation_spending_key(0);
        let premine_address = premine_spending_key.to_address();

        // Create a transaction and insert it into the mempool
        let utxo = Utxo {
            coins: NeptuneCoins::new(1).to_native_coins(),
            lock_script_hash: premine_address.lock_script().hash(),
        };
        let receiver_data = UtxoReceiverData {
            utxo,
            receiver_privacy_digest: premine_address.privacy_digest,
            sender_randomness: random(),
            public_announcement: PublicAnnouncement::default(),
        };
        let tx_by_preminer_low_fee = preminer_state
            .create_transaction(
                vec![receiver_data.clone()],
                NeptuneCoins::new(1),
                now + seven_months,
            )
            .await?;

        assert_eq!(0, preminer_state.mempool.len());
        preminer_state.mempool.insert(&tx_by_preminer_low_fee);

        assert_eq!(1, preminer_state.mempool.len());
        assert_eq!(
            &tx_by_preminer_low_fee,
            preminer_state
                .mempool
                .get(Hash::hash(&tx_by_preminer_low_fee))
                .unwrap()
        );

        // Insert a transaction that spends the same UTXO and has a higher fee.
        // Verify that this replaces the previous transaction.
        let tx_by_preminer_high_fee = preminer_state
            .create_transaction(
                vec![receiver_data.clone()],
                NeptuneCoins::new(10),
                now + seven_months,
            )
            .await?;
        preminer_state.mempool.insert(&tx_by_preminer_high_fee);
        assert_eq!(1, preminer_state.mempool.len());
        assert_eq!(
            &tx_by_preminer_high_fee,
            preminer_state
                .mempool
                .get(Hash::hash(&tx_by_preminer_high_fee))
                .unwrap()
        );

        // Insert a conflicting transaction with a lower fee and verify that it
        // does *not* replace the existing transaction.
        let tx_by_preminer_medium_fee = preminer_state
            .create_transaction(
                vec![receiver_data],
                NeptuneCoins::new(4),
                now + seven_months,
            )
            .await?;
        preminer_state.mempool.insert(&tx_by_preminer_medium_fee);
        assert_eq!(1, preminer_state.mempool.len());
        assert_eq!(
            &tx_by_preminer_high_fee,
            preminer_state
                .mempool
                .get(Hash::hash(&tx_by_preminer_high_fee))
                .unwrap()
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn get_mempool_size() {
        // Verify that the `get_size` method on mempool returns sane results
        let tx_count_small = 10;
        let mempool_small = setup(10, Network::Alpha).await;
        let size_gs_small = mempool_small.get_size();
        let size_serialized_small = bincode::serialize(&mempool_small.tx_dictionary)
            .unwrap()
            .len();
        assert!(size_gs_small >= size_serialized_small);
        println!(
            "size of mempool with {tx_count_small} empty txs reported as: {}",
            size_gs_small
        );
        println!(
            "actual size of mempool with {tx_count_small} empty txs when serialized: {}",
            size_serialized_small
        );

        let tx_count_big = 100;
        let mempool_big = setup(tx_count_big, Network::Alpha).await;
        let size_gs_big = mempool_big.get_size();
        let size_serialized_big = bincode::serialize(&mempool_big.tx_dictionary)
            .unwrap()
            .len();
        assert!(size_gs_big >= size_serialized_big);
        assert!(size_gs_big >= 5 * size_gs_small);
        println!("size of mempool with {tx_count_big} empty txs reported as: {size_gs_big}",);
        println!(
            "actual size of mempool with {tx_count_big} empty txs when serialized: {size_serialized_big}",
        );
    }
}
