//! An implementation of a mempool to store broadcast transactions waiting to be
//! mined.  The implementation maintains a mapping called `table` between
//! 'transaction digests' and the full 'transactions' object, as well as a
//! double-ended priority queue called `queue` containing sorted pairs of
//! 'transaction digests' and the associated 'fee density'.  The `table` can be
//! seen as an associative cache that provides fast random-lookups, while
//! `queue` maintains transactions id's ordered by 'fee density'. Usually, we
//! are interested in the transaction with either the highest or the lowest 'fee
//! density'.

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::collections::HashSet;
use std::iter::Rev;

use bytesize::ByteSize;
use get_size::GetSize;
/// `FeeDensity` is a measure of 'Fee/Bytes' or 'reward per storage unit' for
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
use num_traits::Zero;
use priority_queue::double_priority_queue::iterators::IntoSortedIter;
use priority_queue::DoublePriorityQueue;
use tracing::error;
use twenty_first::math::digest::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use crate::models::blockchain::block::Block;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

// 72 hours in secs
pub const MEMPOOL_TX_THRESHOLD_AGE_IN_SECS: u64 = 72 * 60 * 60;

// 5 minutes in secs
pub const MEMPOOL_IGNORE_TRANSACTIONS_THIS_MANY_SECS_AHEAD: u64 = 5 * 60;

pub const TRANSACTION_NOTIFICATION_AGE_LIMIT_IN_SECS: u64 = 60 * 60 * 24;

type LookupItem<'a> = (Digest, &'a Transaction);

#[derive(Debug, Clone, PartialEq, Eq, GetSize)]
pub struct Mempool {
    max_total_size: usize,

    /// Contains transactions, with a mapping from transaction ID to transaction.
    /// Maintain for constant lookup
    tx_dictionary: HashMap<Digest, Transaction>,

    /// Allows the mempool to report transactions sorted by [`FeeDensity`] in
    /// both descending and ascending order.
    #[get_size(ignore)] // This is relatively small compared to `LookupTable`
    queue: DoublePriorityQueue<Digest, FeeDensity>,

    /// Records the digest of the block that the transactions were synced to.
    /// Used to discover reorganizations.
    tip_digest: Digest,
}

impl Mempool {
    /// instantiate a new, empty `Mempool`
    pub fn new(max_total_size: ByteSize, tip_digest: Digest) -> Self {
        let table = Default::default();
        let queue = Default::default();
        let max_total_size = max_total_size.0.try_into().unwrap();
        Self {
            max_total_size,
            tx_dictionary: table,
            queue,
            tip_digest,
        }
    }

    /// Update the block digest to which all transactions are synced.
    fn set_tip_digest_sync_label(&mut self, tip_digest: Digest) {
        self.tip_digest = tip_digest;
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

    /// Returns `Some(txid, transaction)` iff a transaction conflicts with a transaction
    /// that's already in the mempool. Returns `None` otherwise.
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
    /// transaction with proofs of type [TransactionProof::ProofCollection],
    /// [TransactionProof::SingleProof], [TransactionProof::Witness] maybe be
    /// inserted.
    ///
    /// The caller must also ensure that the transaction does not have a timestamp
    /// in the too distant future.
    ///
    /// # Panics
    ///
    /// Panics if the transaction's proof is of the wrong type.
    pub fn insert(&mut self, transaction: &Transaction) -> Option<Digest> {
        match transaction.proof {
            TransactionProof::Invalid => panic!("cannot insert invalid transaction into mempool"),
            TransactionProof::Witness(_) => {}
            TransactionProof::SingleProof(_) => {}
            TransactionProof::ProofCollection(_) => {}
        };

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

    /// Delete all transactions from the mempool.
    pub fn clear(&mut self) {
        self.queue.clear();
        self.tx_dictionary.clear();
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

    /// Removes the transaction with the highest [`FeeDensity`] from the mempool.
    /// Returns the removed value.
    ///
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

    /// Removes the transaction with the lowest [`FeeDensity`] from the mempool.
    /// Returns the removed value.
    ///
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

    /// Removes all transactions from the mempool that do not satisfy the
    /// predicate.
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

    /// Remove transactions from mempool that are older than the specified
    /// timestamp. Prunes base on the transaction's timestamp.
    ///
    /// Computes in O(n)
    pub fn prune_stale_transactions(&mut self) {
        let cutoff = Timestamp::now() - Timestamp::seconds(MEMPOOL_TX_THRESHOLD_AGE_IN_SECS);

        let keep = |(_transaction_id, transaction): LookupItem| -> bool {
            cutoff < transaction.kernel.timestamp
        };

        self.retain(keep);
    }

    /// Remove from the mempool all transactions that become invalid because
    /// of a newly received block. Also update all mutator set data for mempool
    /// transactions that were not removed.
    pub async fn update_with_block(
        &mut self,
        previous_mutator_set_accumulator: MutatorSetAccumulator,
        block: &Block,
    ) {
        // If we discover a reorganization, we currently just clear the mempool,
        // as we don't have the ability to roll transaction removal record integrity
        // proofs back to previous blocks. It would be nice if we could handle a
        // reorganization that's at least a few blocks deep though.
        let previous_block_digest = block.header().prev_block_digest;
        if self.tip_digest != previous_block_digest {
            self.clear();
        }

        // The general strategy is to check whether the SWBF index set of a given
        // transaction in the mempool is disjoint (*i.e.*, not contained by) the
        // SWBF indices coming from the block transaction. If they are not disjoint,
        // then remove the transaction from the mempool.

        // Compute the union of all index sets generated by the block transaction.
        let swbf_index_set_union: HashSet<_> = block
            .kernel
            .body
            .transaction_kernel
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

            // A transaction should be kept in the mempool if it is true that
            // *all* of its index sets have at least one index that's not
            // present in the mined block's transaction.
            transaction_index_sets.iter().all(|index_set| {
                index_set
                    .iter()
                    .any(|index| !swbf_index_set_union.contains(index))
            })
        };

        // Remove the transactions that become invalid with this block
        self.retain(keep);

        // Update the remaining transactions so their mutator set data is still valid
        // But kick out those transactions that we were unable to update.
        let mut kick_outs = vec![];
        for (tx_id, tx) in self.tx_dictionary.iter_mut() {
            if let Ok(new_tx) = tx
                .clone()
                .new_with_updated_mutator_set_records(&previous_mutator_set_accumulator, block)
            {
                *tx = new_tx;
            } else {
                error!("Failed to update transaction {tx_id}. Removing from mempool.");
                kick_outs.push(*tx_id);
            }
        }

        self.retain(|(tx_id, _)| !kick_outs.contains(&tx_id));

        // Maintaining the mutator set data could have increased the size of the
        // transactions in the mempool. So we should shrink it to max size after
        // applying the block.
        self.shrink_to_max_size();

        // Update the sync-label to keep track of reorganizations
        let current_block_digest = block.hash();
        self.set_tip_digest_sync_label(current_block_digest);
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
    /// use bytesize::ByteSize;
    /// use neptune_core::models::blockchain::block::Block;
    /// use neptune_core::models::state::mempool::Mempool;
    /// use neptune_core::config_models::network::Network;
    ///
    /// let network = Network::Main;
    /// let genesis_block = Block::genesis_block(network);
    /// let mempool = Mempool::new(ByteSize::gb(1), genesis_block.hash());
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
    use anyhow::Result;
    use itertools::Itertools;
    use num_bigint::BigInt;
    use num_traits::Zero;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tracing::debug;
    use tracing_test::traced_test;
    use twenty_first::prelude::Tip5;

    use super::*;
    use crate::config_models::network::Network;
    use crate::models::blockchain::block::block_height::BlockHeight;
    use crate::models::blockchain::transaction::utxo::Utxo;
    use crate::models::blockchain::transaction::PublicAnnouncement;
    use crate::models::blockchain::transaction::Transaction;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::shared::SIZE_20MB_IN_BYTES;
    use crate::models::state::tx_proving_capability::TxProvingCapability;
    use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
    use crate::models::state::wallet::expected_utxo::UtxoNotifier;
    use crate::models::state::wallet::WalletSecret;
    use crate::tests::shared::make_mock_block;
    use crate::tests::shared::make_mock_transaction_with_wallet;
    use crate::tests::shared::make_mock_txs_with_primitive_witness_with_timestamp;
    use crate::tests::shared::make_plenty_mock_transaction_with_primitive_witness;
    use crate::tests::shared::mock_genesis_global_state;
    use crate::tests::shared::mock_genesis_wallet_state;
    use crate::util_types::mutator_set::shared::BATCH_SIZE;
    use crate::util_types::mutator_set::shared::CHUNK_SIZE;
    use crate::util_types::mutator_set::shared::WINDOW_SIZE;

    #[tokio::test]
    pub async fn insert_then_get_then_remove_then_get() {
        let network = Network::Main;
        let genesis_block = Block::genesis_block(network);
        let mut mempool = Mempool::new(ByteSize::gb(1), genesis_block.hash());

        let txs = make_plenty_mock_transaction_with_primitive_witness(2);
        let transaction_digests = txs.iter().map(Tip5::hash).collect_vec();
        assert!(!mempool.contains(transaction_digests[0]));
        mempool.insert(&txs[0]);
        assert!(mempool.contains(transaction_digests[0]));

        let transaction_get_option = mempool.get(transaction_digests[0]);
        assert_eq!(Some(&txs[0]), transaction_get_option);
        assert!(mempool.contains(transaction_digests[0]));

        let transaction_remove_option = mempool.remove(transaction_digests[0]);
        assert_eq!(Some(txs[0].clone()), transaction_remove_option);
        assert!(!mempool.contains(transaction_digests[0]));

        let transaction_second_remove_option = mempool.remove(transaction_digests[0]);
        assert_eq!(None, transaction_second_remove_option);
        assert!(!mempool.contains(transaction_digests[0]));

        let transaction_second_get_option = mempool.get(transaction_digests[0]);
        assert_eq!(None, transaction_second_get_option);

        for tx_id in transaction_digests {
            assert!(!mempool.contains(tx_id));
        }

        assert!(mempool.is_empty());
        assert!(mempool.len().is_zero());
    }

    /// Create a mempool with n transactions.
    async fn setup_mock_mempool(transactions_count: usize, network: Network) -> Mempool {
        let genesis_block = Block::genesis_block(network);
        let mut mempool = Mempool::new(ByteSize::gb(1), genesis_block.hash());
        let txs = make_plenty_mock_transaction_with_primitive_witness(transactions_count);
        for tx in txs {
            mempool.insert(&tx);
        }

        assert_eq!(transactions_count, mempool.len());

        mempool
    }

    #[traced_test]
    #[tokio::test]
    async fn get_densest_transactions() {
        // Verify that transactions are returned ordered by fee density, with highest fee density first
        let mempool = setup_mock_mempool(10, Network::Main).await;

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
        let mempool = setup_mock_mempool(10, Network::Main).await;

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
        let network = Network::Main;
        let genesis_block = Block::genesis_block(network);
        let mut mempool = Mempool::new(ByteSize::gb(1), genesis_block.hash());
        assert!(
            mempool.is_empty(),
            "Mempool must be empty after initialization"
        );

        let now = Timestamp::now();
        let eight_days_ago = now - Timestamp::days(8);
        let old_txs = make_mock_txs_with_primitive_witness_with_timestamp(6, eight_days_ago);

        for tx in old_txs {
            mempool.insert(&tx);
        }

        let new_txs = make_mock_txs_with_primitive_witness_with_timestamp(5, now);

        for tx in new_txs {
            mempool.insert(&tx);
        }

        assert_eq!(mempool.len(), 11);
        mempool.prune_stale_transactions();
        assert_eq!(mempool.len(), 5)
    }

    #[traced_test]
    #[tokio::test]
    async fn remove_transactions_with_block_test() {
        // Bob is premine receiver, Alice is not
        let mut rng: StdRng = StdRng::seed_from_u64(0x03ce19960c467f90u64);

        let network = Network::Main;
        let devnet_wallet = WalletSecret::devnet_wallet();
        let bob_global_state = mock_genesis_global_state(network, 2, devnet_wallet).await;
        let mut bob = bob_global_state.lock_guard_mut().await;

        let bob_wallet_secret = &bob.wallet_state.wallet_secret;
        let bob_spending_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
        let bob_address = bob_spending_key.to_address();
        let alice_wallet_secret = WalletSecret::new_pseudorandom(rng.gen());

        let alice_global_state_lock =
            mock_genesis_global_state(network, 2, alice_wallet_secret.clone()).await;
        let mut alice = alice_global_state_lock.lock_guard_mut().await;
        let alice_spending_key = alice_wallet_secret.nth_generation_spending_key_for_tests(0);
        let alice_address = alice_spending_key.to_address();

        // Ensure that both wallets have a non-zero balance
        let genesis_block = Block::genesis_block(network);
        let (block_1, coinbase_utxo_1, cb_sender_randomness_1) =
            make_mock_block(&genesis_block, None, alice_address, rng.gen());

        // Update both states with block 1
        alice
            .wallet_state
            .add_expected_utxo(ExpectedUtxo::new(
                coinbase_utxo_1,
                cb_sender_randomness_1,
                alice_spending_key.privacy_preimage,
                UtxoNotifier::OwnMiner,
            ))
            .expect("UTXO notification from miner must be accepted");
        alice.set_new_tip(block_1.clone()).await.unwrap();
        bob.set_new_tip(block_1.clone()).await.unwrap();

        // Create a transaction that's valid to be included in block 2
        let mut utxos_from_bob: Vec<UtxoReceiverData> = vec![];
        for i in 0..4 {
            let amount: NeptuneCoins = NeptuneCoins::new(i);
            let new_utxo = Utxo {
                coins: amount.to_native_coins(),
                lock_script_hash: bob_address.lock_script().hash(),
            };

            utxos_from_bob.push(UtxoReceiverData {
                public_announcement: PublicAnnouncement::default(),
                receiver_privacy_digest: bob_address.privacy_digest,
                sender_randomness: rng.gen(),
                utxo: new_utxo,
            });
        }

        let now = genesis_block.kernel.header.timestamp;
        let in_seven_months = now + Timestamp::months(7);
        let in_eight_months = now + Timestamp::months(8);
        let tx_by_bob = bob
            .create_transaction(utxos_from_bob, NeptuneCoins::new(1), in_seven_months)
            .await
            .unwrap();

        // inform wallet of any expected utxos from this tx.
        premine_receiver_global_state
            .add_expected_utxos_to_wallet(expected_utxos)
            .await
            .unwrap();

        // Add this transaction to a mempool
        let mut mempool = Mempool::new(ByteSize::gb(1), block_1.hash());
        mempool.insert(&tx_by_bob);

        // Create another transaction that's valid to be included in block 2, but isn't actually
        // included by the miner. This transaction is inserted into the mempool, but since it's
        // not included in block 2 it must still be in the mempool after the mempool has been
        // updated with block 2. Also: The transaction must be valid after block 2 as the mempool
        // manager must keep mutator set data updated.
        let utxo_from_alice = vec![UtxoReceiverData {
            utxo: Utxo {
                coins: NeptuneCoins::new(68).to_native_coins(),
                lock_script_hash: alice_address.lock_script().hash(),
            },
            sender_randomness: rng.gen(),
            receiver_privacy_digest: alice_address.privacy_digest,
            public_announcement: PublicAnnouncement::default(),
        }];
        let tx_from_alice_original = alice
            .create_transaction(utxo_from_alice, NeptuneCoins::new(1), in_seven_months)
            .await
            .unwrap();
        mempool.insert(&tx_from_alice_original);

        // Create next block which includes preminer's transaction
        let (coinbase_transaction, _expected_utxo) =
            bob.make_coinbase_transaction(NeptuneCoins::zero(), in_eight_months);
        let block_transaction = tx_by_bob.merge_with(coinbase_transaction, Default::default());
        let block_2 =
            Block::new_block_from_template(&block_1, block_transaction, in_eight_months, None);

        // Update the mempool with block 2 and verify that the mempool now only contains one tx
        assert_eq!(2, mempool.len());
        mempool
            .update_with_block(
                block_1.kernel.body.mutator_set_accumulator.clone(),
                &block_2,
            )
            .await;
        assert_eq!(1, mempool.len());

        // Create a new block to verify that the non-mined transaction contains
        // updated and valid-again mutator set data
        let mut tx_by_alice_updated: Transaction =
            mempool.get_transactions_for_block(usize::MAX)[0].clone();
        assert!(
            tx_by_alice_updated.is_confirmable_relative_to(&block_2.body().mutator_set_accumulator),
            "Block with tx with updated mutator set data must be confirmable wrt. block_2"
        );

        alice.set_new_tip(block_2.clone()).await.unwrap();
        bob.set_new_tip(block_2.clone()).await.unwrap();
        let (coinbase_transaction2, _expected_utxo2) =
            bob.make_coinbase_transaction(NeptuneCoins::zero(), in_eight_months);
        let block_transaction2 = tx_by_alice_updated
            .clone()
            .merge_with(coinbase_transaction2, Default::default());
        let block_3_orphaned =
            Block::new_block_from_template(&block_2, block_transaction2, in_eight_months, None);

        debug!(
            "tx_by_other_updated has mutator set hash: {}",
            tx_by_alice_updated.kernel.mutator_set_hash
        );

        assert!(
            block_3_orphaned.is_valid(&block_2, in_eight_months),
            "Block with tx with updated mutator set data must be valid"
        );

        // Mine 4 blocks without including the transaction but while still keeping the
        // mempool updated. After these 4 blocks are mined, the transaction must still be
        // valid. Notic that `block_3_orphaned` was forked away, never added to mempool,
        // since we want to keep the transaction in the mempool.
        let mut previous_block = block_2;
        for _ in 0..4 {
            let (next_block, _, _) =
                make_mock_block(&previous_block, None, alice_address, rng.gen());
            alice.set_new_tip(next_block.clone()).await.unwrap();
            bob.set_new_tip(next_block.clone()).await.unwrap();
            mempool
                .update_with_block(
                    previous_block.kernel.body.mutator_set_accumulator.clone(),
                    &next_block,
                )
                .await;
            previous_block = next_block;
        }

        tx_by_alice_updated = mempool.get_transactions_for_block(usize::MAX)[0].clone();
        let (coinbase_transaction3, _expected_utxo3) =
            alice.make_coinbase_transaction(NeptuneCoins::zero(), in_eight_months);
        let block_transaction3 =
            coinbase_transaction3.merge_with(tx_by_alice_updated, Default::default());
        let block_7 = Block::new_block_from_template(
            &previous_block,
            block_transaction3,
            in_eight_months,
            None,
        );
        assert_eq!(Into::<BlockHeight>::into(7), block_7.kernel.header.height);
        assert!(
            block_7.is_valid(&previous_block, in_eight_months),
            "Block with tx with updated mutator set data must be valid after 10 blocks have been mined"
        );

        mempool
            .update_with_block(
                previous_block.kernel.body.mutator_set_accumulator.clone(),
                &block_7,
            )
            .await;

        assert!(
            mempool.is_empty(),
            "Mempool must be empty after 2nd tx was mined"
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn reorganization_does_not_crash_mempool() {
        // Verify that reorganizations do not crash the client, and other
        // qualities.

        // First put a transaction into the mempool. Then mine block 1a does
        // not contain this transaction, such that mempool is still non-empty.
        // Then mine a a block 1b that also does not contain this transaction.
        let network = Network::Main;
        let devnet_wallet = WalletSecret::devnet_wallet();
        let mut premine_receiver_global_state =
            mock_genesis_global_state(network, 2, devnet_wallet).await;
        let mut premine_receiver_global_state =
            premine_receiver_global_state.lock_guard_mut().await;
        let premine_address = premine_receiver_global_state
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key_for_tests(0)
            .to_address();

        let mut rng: StdRng = StdRng::seed_from_u64(u64::from_str_radix("42", 6).unwrap());
        let other_wallet_secret = WalletSecret::new_pseudorandom(rng.gen());
        let other_address = other_wallet_secret
            .nth_generation_spending_key_for_tests(0)
            .to_address();

        let utxo = Utxo::new(
            premine_address.lock_script(),
            NeptuneCoins::new(1).to_native_coins(),
        );
        let tx_receiver_data = UtxoReceiverData {
            utxo,
            receiver_privacy_digest: premine_address.privacy_digest,
            sender_randomness: rng.gen(),
            public_announcement: PublicAnnouncement::default(),
        };

        let genesis_block = premine_receiver_global_state
            .chain
            .archival_state()
            .genesis_block()
            .to_owned();
        let now = genesis_block.kernel.header.timestamp;
        let in_seven_years = now + Timestamp::months(7 * 12);
        let unmined_tx = premine_receiver_global_state
            .create_transaction_with_prover_capability(
                vec![tx_receiver_data],
                NeptuneCoins::new(1),
                in_seven_years,
                TxProvingCapability::SingleProof,
            )
            .await
            .unwrap();

        premine_receiver_global_state.mempool.insert(&unmined_tx);

        // Add some blocks. The transaction must stay in the mempool, since it
        // is not being mined.
        let mut current_block = genesis_block.clone();
        for _ in 0..2 {
            let (next_block, _, _) = make_mock_block(
                &current_block,
                Some(in_seven_years),
                other_address,
                rng.gen(),
            );
            premine_receiver_global_state
                .set_new_tip(next_block.clone())
                .await
                .unwrap();

            let mempool_txs = premine_receiver_global_state
                .mempool
                .get_transactions_for_block(usize::MAX);
            assert_eq!(
                1,
                mempool_txs.len(),
                "The inserted tx must stay in the mempool"
            );
            assert!(
                mempool_txs[0]
                    .is_confirmable_relative_to(&next_block.body().mutator_set_accumulator),
                "Mempool tx must stay confirmable after each new block has been applied"
            );
            assert!(mempool_txs[0].is_valid().await, "Tx should be valid.");
            assert_eq!(
                next_block.hash(),
                premine_receiver_global_state.mempool.tip_digest,
                "Mempool's sync digest must be set correctly"
            );

            current_block = next_block;
        }

        // Now make a deep reorganization and verify that nothing crashes
        let (block_1b, _, _) = make_mock_block(
            &genesis_block,
            Some(in_seven_years),
            other_address,
            rng.gen(),
        );
        assert!(
            block_1b.header().height.previous().is_genesis(),
            "Sanity check that new tip has height 1"
        );
        premine_receiver_global_state
            .set_new_tip(block_1b.clone())
            .await
            .unwrap();

        // Verify that all retained txs (if any) are confirmable against
        // the new tip.
        assert!(
            premine_receiver_global_state
                .mempool
                .get_transactions_for_block(usize::MAX)
                .iter()
                .all(|tx| tx.is_confirmable_relative_to(&block_1b.body().mutator_set_accumulator)),
            "All retained txs in the mempool must be confirmable relative to the new block.
             Or the mempool must be empty."
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn conflicting_txs_preserve_highest_fee() -> Result<()> {
        // Create a global state object, controlled by a preminer who receives a premine-UTXO.
        let network = Network::Main;
        let preminer_state_lock =
            mock_genesis_global_state(network, 2, WalletSecret::devnet_wallet()).await;
        let in_seven_months =
            Block::genesis_block(network).kernel.header.timestamp + Timestamp::months(7);
        let mut preminer_state = preminer_state_lock.lock_guard_mut().await;
        let premine_wallet_secret = &preminer_state.wallet_state.wallet_secret;
        let premine_spending_key = premine_wallet_secret.nth_generation_spending_key_for_tests(0);
        let premine_address = premine_spending_key.to_address();
        let mut rng = StdRng::seed_from_u64(589111u64);

        // Create a transaction and insert it into the mempool
        let utxo = Utxo {
            coins: NeptuneCoins::new(1).to_native_coins(),
            lock_script_hash: premine_address.lock_script().hash(),
        };
        let receiver_data = UtxoReceiverData {
            utxo,
            receiver_privacy_digest: premine_address.privacy_digest,
            sender_randomness: rng.gen(),
            public_announcement: PublicAnnouncement::default(),
        };
        let tx_by_preminer_low_fee = preminer_state
            .create_transaction_with_prover_capability(
                vec![receiver_data.clone()],
                NeptuneCoins::new(1),
                in_seven_months,
                TxProvingCapability::ProofCollection,
            )
            .await?;

        // inform wallet of any expected utxos from this tx.
        preminer_state
            .add_expected_utxos_to_wallet(expected_utxos_low_fee)
            .await
            .unwrap();

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
            .create_transaction_with_prover_capability(
                vec![receiver_data.clone()],
                NeptuneCoins::new(10),
                in_seven_months,
                TxProvingCapability::ProofCollection,
            )
            .await?;

        // inform wallet of any expected utxos from this tx.
        preminer_state
            .add_expected_utxos_to_wallet(expected_utxos_high_fee)
            .await
            .unwrap();

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
            .create_transaction_with_prover_capability(
                vec![receiver_data],
                NeptuneCoins::new(4),
                in_seven_months,
                TxProvingCapability::ProofCollection,
            )
            .await?;

        // inform wallet of any expected utxos from this tx.
        preminer_state
            .add_expected_utxos_to_wallet(expected_utxos_med_fee)
            .await
            .unwrap();

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
        let network = Network::Main;
        let tx_count_small = 2;
        let mempool_small = setup_mock_mempool(tx_count_small, network).await;
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

        let tx_count_big = 6;
        let mempool_big = setup_mock_mempool(tx_count_big, network).await;
        let size_gs_big = mempool_big.get_size();
        let size_serialized_big = bincode::serialize(&mempool_big.tx_dictionary)
            .unwrap()
            .len();
        assert!(size_gs_big >= size_serialized_big);
        assert!(
            (size_gs_big * tx_count_small) as f64 * 1.2 >= (size_gs_small * tx_count_big) as f64,
            "size_gs_big: {size_gs_big}\nsize_gs_small: {size_gs_small}"
        );
        println!("size of mempool with {tx_count_big} empty txs reported as: {size_gs_big}",);
        println!(
            "actual size of mempool with {tx_count_big} empty txs when serialized: {size_serialized_big}",
        );
    }
}
