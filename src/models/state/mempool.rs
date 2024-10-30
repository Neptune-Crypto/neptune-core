//! An implementation of a mempool to store broadcast transactions waiting to be
//! mined.
//!
//! The implementation maintains a mapping called `table` between
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
use tasm_lib::triton_vm::proof::Proof;
use tracing::error;
use twenty_first::math::digest::Digest;

use super::transaction_kernel_id::TransactionKernelId;
use crate::job_queue::triton_vm::TritonVmJobPriority;
use crate::job_queue::triton_vm::TritonVmJobQueue;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::validity::proof_collection::ProofCollection;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::peer::transfer_transaction::TransactionProofQuality;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

// 72 hours in secs
pub const MEMPOOL_TX_THRESHOLD_AGE_IN_SECS: u64 = 72 * 60 * 60;

// 5 minutes in secs
pub const MEMPOOL_IGNORE_TRANSACTIONS_THIS_MANY_SECS_AHEAD: u64 = 5 * 60;

pub const TRANSACTION_NOTIFICATION_AGE_LIMIT_IN_SECS: u64 = 60 * 60 * 24;

type LookupItem<'a> = (TransactionKernelId, &'a Transaction);

/// Represents a mempool state change.
///
/// For purpose of notifying interested parties
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolEvent {
    /// a transaction was added to the mempool
    AddTx(Transaction),

    /// a transaction was removed from the mempool
    RemoveTx(Transaction),

    /// the mutator-set of a transaction was updated in the mempool.
    ///
    /// (kernel-ID, Tx after mutator-set updated)
    UpdateTxMutatorSet(TransactionKernelId, Transaction),
}

#[derive(Debug, GetSize)]
pub struct Mempool {
    /// Maximum size this data structure may take up in memory.
    max_total_size: usize,

    /// If set, represents the maximum number of transactions allowed in the
    /// mempool. If None, mempool is only restricted by size.
    max_length: Option<usize>,

    /// Contains transactions, with a mapping from transaction ID to transaction.
    /// Maintain for constant lookup
    tx_dictionary: HashMap<TransactionKernelId, Transaction>,

    /// Allows the mempool to report transactions sorted by [`FeeDensity`] in
    /// both descending and ascending order.
    #[get_size(ignore)] // This is relatively small compared to `tx_dictionary`
    queue: DoublePriorityQueue<TransactionKernelId, FeeDensity>,

    /// Records the digest of the block that the transactions were synced to.
    /// Used to discover reorganizations.
    tip_digest: Digest,
}

/// note that all methods that modify state and result in a MempoolEvent
/// notification are private or pub(super).  This enforces that these methods
/// can only be called from/via GlobalState.
///
/// Mempool updates must go through GlobalState so that it can
/// forward mempool events to the wallet in atomic fashion.
impl Mempool {
    /// instantiate a new, empty `Mempool`
    pub fn new(
        max_total_size: ByteSize,
        max_num_transactions: Option<usize>,
        tip_digest: Digest,
    ) -> Self {
        let table = Default::default();
        let queue = Default::default();
        let max_total_size = max_total_size.0.try_into().unwrap();
        Self {
            max_total_size,
            max_length: max_num_transactions,
            tx_dictionary: table,
            queue,
            tip_digest,
        }
    }

    /// Update the block digest to which all transactions are synced.
    pub(super) fn set_tip_digest_sync_label(&mut self, tip_digest: Digest) {
        self.tip_digest = tip_digest;
    }

    /// Check if mempool contains the specified transaction with a higher
    /// proof quality.
    ///
    /// Returns true if transaction is already known *and* if the proof quality
    /// contained in the mempool is higher than the argument.
    pub(crate) fn contains_with_higher_proof_quality(
        &self,
        transaction_id: TransactionKernelId,
        proof_quality: TransactionProofQuality,
    ) -> bool {
        if let Some(tx) = self.tx_dictionary.get(&transaction_id) {
            match tx.proof.proof_quality() {
                Ok(mempool_proof_quality) => mempool_proof_quality >= proof_quality,
                Err(_) => {
                    // Any proof quality is better than none.
                    // This would indicate that this client has a transaction with
                    // e.g. primitive witness in mempool and now the same transaction
                    // with an associated proof is queried. That probably shouldn't
                    // happen.
                    error!("Failed to read proof quality for tx in mempool");
                    true
                }
            }
        } else {
            false
        }
    }

    /// Return the proof collection-supported transaction with highest
    /// fee-density if mempool contains any such transactions. Otherwise None.
    pub(crate) fn most_dense_proof_collection(
        &self,
    ) -> Option<(&TransactionKernel, &ProofCollection)> {
        for (txid, _fee_density) in self.get_sorted_iter() {
            let candidate = self.tx_dictionary.get(&txid).unwrap();
            if let TransactionProof::ProofCollection(proof_collection) = &candidate.proof {
                return Some((&candidate.kernel, proof_collection));
            }
        }

        None
    }

    /// Return the two most dense single-proof transactions. Returns `None` if
    /// no such pair exists in the mempool.
    pub(crate) fn most_dense_single_proof_pair(&self) -> Option<[(&TransactionKernel, &Proof); 2]> {
        let mut ret = vec![];
        for (txid, _fee_density) in self.get_sorted_iter() {
            let candidate = self.tx_dictionary.get(&txid).unwrap();
            if let TransactionProof::SingleProof(proof) = &candidate.proof {
                ret.push((&candidate.kernel, proof));
            }

            if ret.len() == 2 {
                return Some(ret.try_into().unwrap());
            }
        }

        None
    }

    /// check if transaction exists in mempool
    ///
    /// Computes in O(1) from HashMap
    pub fn contains(&self, transaction_id: TransactionKernelId) -> bool {
        self.tx_dictionary.contains_key(&transaction_id)
    }

    /// get transaction from mempool
    ///
    /// Computes in O(1) from HashMap
    pub fn get(&self, transaction_id: TransactionKernelId) -> Option<&Transaction> {
        self.tx_dictionary.get(&transaction_id)
    }

    /// Returns the list of transactions already in the mempool that a
    /// transaction conflicts with.
    ///
    /// Returns the empty list if there are no conflicts
    fn transaction_conflicts_with(
        &self,
        transaction: &Transaction,
    ) -> Vec<(TransactionKernelId, Transaction)> {
        // This check could be made a lot more efficient, for example with an invertible Bloom filter
        let tx_sbf_indices: HashSet<_> = transaction
            .kernel
            .inputs
            .iter()
            .map(|x| x.absolute_indices.to_array())
            .collect();

        let mut conflict_txs_in_mempool = vec![];
        for (txid, tx) in self.tx_dictionary.iter() {
            for mempool_tx_input in tx.kernel.inputs.iter() {
                if tx_sbf_indices.contains(&mempool_tx_input.absolute_indices.to_array()) {
                    conflict_txs_in_mempool.push((*txid, tx.to_owned()));
                }
            }
        }

        conflict_txs_in_mempool
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
    /// this method may return:
    ///   n events: RemoveTx,AddTx.  tx replaces a list of older txs with lower fee.
    ///   1 event:  AddTx. tx does not replace an older one.
    ///   0 events: tx not added because an older matching tx has a higher fee.
    ///
    /// # Panics
    ///
    /// Panics if the transaction's proof is of the wrong type.
    pub(super) fn insert(&mut self, transaction: Transaction) -> Vec<MempoolEvent> {
        let mut events = vec![];

        match transaction.proof {
            TransactionProof::Invalid => panic!("cannot insert invalid transaction into mempool"),
            TransactionProof::Witness(_) => {}
            TransactionProof::SingleProof(_) => {}
            TransactionProof::ProofCollection(_) => {}
        };

        // If transaction to be inserted conflicts with transactions already in
        // the mempool, we replace them -- but only if the new transaction has a
        // higher fee-density than the ones already in mempool. This should have
        // the effect that merged transactions always replace those transactions
        // that were merged since the merged transaction is *very* likely to
        // have a higher fee density that the lowest one of the ones that were
        // merged.
        let conflicts = self.transaction_conflicts_with(&transaction);
        let min_fee_of_conflicts = conflicts.iter().map(|x| x.1.fee_density()).min();
        if let Some(min_fee_of_conflicting_tx) = min_fee_of_conflicts {
            if min_fee_of_conflicting_tx < transaction.fee_density() {
                for (conflicting_txid, _) in conflicts {
                    if let Some(e) = self.remove(conflicting_txid) {
                        events.push(e);
                    }
                }
            } else {
                // If new transaction has a lower fee density than the one previous seen,
                // ignore it. Stop execution here.
                return events;
            }
        }

        let txid = transaction.kernel.txid();

        self.queue.push(txid, transaction.fee_density());
        self.tx_dictionary.insert(txid, transaction.to_owned());
        events.push(MempoolEvent::AddTx(transaction));

        assert_eq!(
            self.tx_dictionary.len(),
            self.queue.len(),
            "mempool's table and queue length must agree prior to shrink"
        );
        self.shrink_to_max_size();
        self.shrink_to_max_length();
        assert_eq!(
            self.tx_dictionary.len(),
            self.queue.len(),
            "mempool's table and queue length must agree after shrink"
        );

        events
    }

    /// remove a transaction from the `Mempool`
    pub(super) fn remove(&mut self, transaction_id: TransactionKernelId) -> Option<MempoolEvent> {
        self.tx_dictionary.remove(&transaction_id).map(|tx| {
            self.queue.remove(&transaction_id);
            debug_assert_eq!(self.tx_dictionary.len(), self.queue.len());
            MempoolEvent::RemoveTx(tx)
        })
    }

    /// Delete all transactions from the mempool.
    ///
    /// note that this will return a MempoolEvent for every removed Tx.
    /// In the case of a full block, that could be a lot of Tx and
    /// significant memory usage.  Of course the mempool itself will
    /// be emptied at the same time.
    ///
    /// If the mem usage ever becomes a problem we could accept a closure
    /// to handle the events individually as each Tx is removed.
    pub(super) fn clear(&mut self) -> Vec<MempoolEvent> {
        // note: this causes event listeners to be notified of each removed tx.
        self.retain(|_| false)
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
    /// density.
    ///
    /// Number of transactions returned can be capped by either size (measured
    /// in bytes), or by transaction count. The function guarantees that neither
    /// of the specified limits will be exceeded.
    pub fn get_transactions_for_block(
        &self,
        mut remaining_storage: usize,
        max_num_txs: Option<usize>,
    ) -> Vec<Transaction> {
        let mut transactions = vec![];
        let mut _fee_acc = NeptuneCoins::zero();

        for (transaction_digest, _fee_density) in self.get_sorted_iter() {
            // No more transactions can possibly be packed
            if remaining_storage == 0 || max_num_txs.is_some_and(|max| transactions.len() == max) {
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
    fn pop_max(&mut self) -> Option<(MempoolEvent, FeeDensity)> {
        if let Some((transaction_digest, fee_density)) = self.queue.pop_max() {
            if let Some(transaction) = self.tx_dictionary.remove(&transaction_digest) {
                debug_assert_eq!(self.tx_dictionary.len(), self.queue.len());

                let event = MempoolEvent::RemoveTx(transaction);

                return Some((event, fee_density));
            }
        }
        None
    }

    /// Removes the transaction with the lowest [`FeeDensity`] from the mempool.
    /// Returns the removed value.
    ///
    /// Computes in θ(lg N)
    fn pop_min(&mut self) -> Option<(MempoolEvent, FeeDensity)> {
        if let Some((transaction_digest, fee_density)) = self.queue.pop_min() {
            if let Some(transaction) = self.tx_dictionary.remove(&transaction_digest) {
                debug_assert_eq!(self.tx_dictionary.len(), self.queue.len());

                let event = MempoolEvent::RemoveTx(transaction);

                return Some((event, fee_density));
            }
        }
        None
    }

    /// Removes all transactions from the mempool that do not satisfy the
    /// predicate.
    /// Modelled after [HashMap::retain](std::collections::HashMap::retain())
    ///
    /// Computes in O(capacity) >= O(N)
    fn retain<F>(&mut self, mut predicate: F) -> Vec<MempoolEvent>
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

        let mut events = Vec::with_capacity(victims.len());
        for t in victims {
            if let Some(e) = self.remove(t) {
                events.push(e);
            }
        }

        debug_assert_eq!(self.tx_dictionary.len(), self.queue.len());
        self.shrink_to_fit();

        events
    }

    /// Remove transactions from mempool that are older than the specified
    /// timestamp. Prunes base on the transaction's timestamp.
    ///
    /// Computes in O(n)
    pub(super) fn prune_stale_transactions(&mut self) -> Vec<MempoolEvent> {
        let cutoff = Timestamp::now() - Timestamp::seconds(MEMPOOL_TX_THRESHOLD_AGE_IN_SECS);

        let keep = |(_transaction_id, transaction): LookupItem| -> bool {
            cutoff < transaction.kernel.timestamp
        };

        self.retain(keep)
    }

    /// Remove from the mempool all transactions that become invalid because
    /// of a newly received block. Also update all mutator set data for mempool
    /// transactions that were not removed.
    pub(super) async fn update_with_block(
        &mut self,
        previous_mutator_set_accumulator: MutatorSetAccumulator,
        block: &Block,
        vm_job_queue: &TritonVmJobQueue,
        priority: TritonVmJobPriority,
    ) -> Vec<MempoolEvent> {
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
        let mut events = self.retain(keep);

        // Update the remaining transactions so their mutator set data is still valid
        // But kick out those transactions that we were unable to update.
        let mut kick_outs = Vec::with_capacity(self.tx_dictionary.len());
        for (tx_id, tx) in self.tx_dictionary.iter_mut() {
            if let Ok(new_tx) = tx
                .clone()
                .new_with_updated_mutator_set_records(
                    &previous_mutator_set_accumulator,
                    block,
                    vm_job_queue,
                    priority,
                )
                .await
            {
                *tx = new_tx;
                events.push(MempoolEvent::UpdateTxMutatorSet(*tx_id, (*tx).clone()));
            } else {
                error!("Failed to update transaction {tx_id}. Removing from mempool.");
                kick_outs.push(*tx_id);
                events.push(MempoolEvent::RemoveTx(tx.clone()));
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

        events
    }

    /// Shrink the memory pool to the value of its `max_size` field.
    /// Likely computes in O(n).
    fn shrink_to_max_size(&mut self) {
        // Repeately remove the least valuable transaction
        while self.get_size() > self.max_total_size && self.pop_min().is_some() {
            continue;
        }

        self.shrink_to_fit();
    }

    /// Shrink the memory pool to the value of its `max_length` field,
    /// if that field is set.
    fn shrink_to_max_length(&mut self) {
        if let Some(max_length) = self.max_length {
            while self.len() > max_length && self.pop_min().is_some() {
                continue;
            }
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
    /// let mempool = Mempool::new(ByteSize::gb(1), None, genesis_block.hash());
    /// // insert transactions here.
    /// let mut most_valuable_transactions = vec![];
    /// for (transaction_id, fee_density) in mempool.get_sorted_iter() {
    ///    let t = mempool.get(transaction_id);
    ///    most_valuable_transactions.push(t);
    /// }
    /// ```
    ///
    /// Yields the `transaction_digest` in order of descending `fee_density`, since
    /// users (miner or transaction merger) will likely only care about the most valuable transactions
    /// Computes in O(N lg N)
    pub fn get_sorted_iter(
        &self,
    ) -> Rev<IntoSortedIter<TransactionKernelId, FeeDensity, RandomState>> {
        let dpq_clone = self.queue.clone();
        dpq_clone.into_sorted_iter().rev()
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use num_bigint::BigInt;
    use num_traits::Zero;
    use proptest::prelude::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tracing::debug;
    use tracing_test::traced_test;

    use super::*;
    use crate::config_models::network::Network;
    use crate::mine_loop::make_coinbase_transaction;
    use crate::models::blockchain::block::block_height::BlockHeight;
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::blockchain::transaction::transaction_output::TxOutput;
    use crate::models::blockchain::transaction::transaction_output::TxOutputList;
    use crate::models::blockchain::transaction::transaction_output::UtxoNotificationMedium;
    use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
    use crate::models::blockchain::transaction::Transaction;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::shared::SIZE_20MB_IN_BYTES;
    use crate::models::state::tx_proving_capability::TxProvingCapability;
    use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
    use crate::models::state::wallet::expected_utxo::UtxoNotifier;
    use crate::models::state::wallet::WalletSecret;
    use crate::models::state::GlobalStateLock;
    use crate::models::state::TritonVmJobQueue;
    use crate::tests::shared::make_mock_block;
    use crate::tests::shared::make_mock_txs_with_primitive_witness_with_timestamp;
    use crate::tests::shared::make_plenty_mock_transaction_with_primitive_witness;
    use crate::tests::shared::mock_genesis_global_state;

    #[tokio::test]
    pub async fn insert_then_get_then_remove_then_get() {
        let network = Network::Main;
        let genesis_block = Block::genesis_block(network);
        let mut mempool = Mempool::new(ByteSize::gb(1), None, genesis_block.hash());

        let txs = make_plenty_mock_transaction_with_primitive_witness(2);
        let transaction_digests = txs.iter().map(|tx| tx.kernel.txid()).collect_vec();
        assert!(!mempool.contains(transaction_digests[0]));
        assert!(!mempool.contains(transaction_digests[1]));
        mempool.insert(txs[0].clone());
        assert!(mempool.contains(transaction_digests[0]));
        assert!(!mempool.contains(transaction_digests[1]));

        let transaction_get_option = mempool.get(transaction_digests[0]);
        assert_eq!(Some(&txs[0]), transaction_get_option);
        assert!(mempool.contains(transaction_digests[0]));
        assert!(!mempool.contains(transaction_digests[1]));

        let remove_event = mempool.remove(transaction_digests[0]);
        assert_eq!(Some(MempoolEvent::RemoveTx(txs[0].clone())), remove_event);
        for tx_id in transaction_digests.iter() {
            assert!(!mempool.contains(*tx_id));
        }

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
        let mut mempool = Mempool::new(ByteSize::gb(1), None, genesis_block.hash());
        let txs = make_plenty_mock_transaction_with_primitive_witness(transactions_count);
        for tx in txs {
            mempool.insert(tx);
        }

        assert_eq!(transactions_count, mempool.len());

        mempool
    }

    #[traced_test]
    #[tokio::test]
    async fn get_densest_transactions_no_tx_cap() {
        // Verify that transactions are returned ordered by fee density, with highest fee density first
        let num_txs = 10;
        let mempool = setup_mock_mempool(num_txs, Network::Main).await;

        let max_fee_density: FeeDensity = FeeDensity::new(BigInt::from(u128::MAX), BigInt::from(1));
        let mut prev_fee_density = max_fee_density;
        for curr_transaction in mempool.get_transactions_for_block(SIZE_20MB_IN_BYTES, None) {
            let curr_fee_density = curr_transaction.fee_density();
            assert!(curr_fee_density <= prev_fee_density);
            prev_fee_density = curr_fee_density;
        }

        assert!(!mempool.is_empty())
    }

    #[traced_test]
    #[tokio::test]
    async fn get_densest_transactions_with_tx_cap() {
        // Verify that transactions are returned ordered by fee density, with highest fee density first
        let num_txs = 12;
        let mempool = setup_mock_mempool(num_txs, Network::Main).await;

        let max_fee_density: FeeDensity = FeeDensity::new(BigInt::from(u128::MAX), BigInt::from(1));
        let mut prev_fee_density = max_fee_density;
        for curr_transaction in
            mempool.get_transactions_for_block(SIZE_20MB_IN_BYTES, Some(num_txs))
        {
            let curr_fee_density = curr_transaction.fee_density();
            assert!(curr_fee_density <= prev_fee_density);
            prev_fee_density = curr_fee_density;
        }

        assert!(!mempool.is_empty())
    }

    #[traced_test]
    #[tokio::test]
    async fn most_dense_proof_collection_test() {
        let network = Network::Main;
        let mut mempool = setup_mock_mempool(0, network).await;
        let genesis_block = Block::genesis_block(network);
        let bob_wallet_secret = WalletSecret::devnet_wallet();
        let bob_spending_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
        let bob = mock_genesis_global_state(network, 2, bob_wallet_secret.clone()).await;
        let in_seven_months = genesis_block.kernel.header.timestamp + Timestamp::months(7);
        let high_fee = NeptuneCoins::new(15);
        let (tx_by_bob, _maybe_change_output) = bob
            .lock_guard()
            .await
            .create_transaction_with_prover_capability(
                vec![].into(),
                bob_spending_key.into(),
                UtxoNotificationMedium::OnChain,
                high_fee,
                in_seven_months,
                TxProvingCapability::ProofCollection,
                &TritonVmJobQueue::dummy(),
            )
            .await
            .unwrap();

        // No candidate when mempool is empty
        assert!(
            mempool.most_dense_proof_collection().is_none(),
            "No proof collection when mempool is empty"
        );

        let tx_by_bob_txid = tx_by_bob.kernel.txid();
        mempool.insert(tx_by_bob);
        assert_eq!(
            mempool.most_dense_proof_collection().unwrap().0.txid(),
            tx_by_bob_txid
        );
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
    async fn max_num_transactions_is_respected() {
        let num_txs = 12;
        let mempool = setup_mock_mempool(num_txs, Network::Main).await;
        for i in 0..num_txs {
            assert_eq!(
                i,
                mempool
                    .get_transactions_for_block(SIZE_20MB_IN_BYTES, Some(i))
                    .len()
            );
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn prune_stale_transactions() {
        let network = Network::Alpha;
        let genesis_block = Block::genesis_block(network);
        let mut mempool = Mempool::new(ByteSize::gb(1), None, genesis_block.hash());
        assert!(
            mempool.is_empty(),
            "Mempool must be empty after initialization"
        );

        let now = Timestamp::now();
        let eight_days_ago = now - Timestamp::days(8);
        let old_txs = make_mock_txs_with_primitive_witness_with_timestamp(6, eight_days_ago);

        for tx in old_txs {
            mempool.insert(tx);
        }

        let new_txs = make_mock_txs_with_primitive_witness_with_timestamp(5, now);

        for tx in new_txs {
            mempool.insert(tx);
        }

        assert_eq!(mempool.len(), 11);
        mempool.prune_stale_transactions();
        assert_eq!(mempool.len(), 5);
    }

    #[traced_test]
    #[tokio::test]
    async fn remove_transactions_with_block_test() {
        // Check that the mempool removes transactions that were incorporated or
        // made unconfirmable by the new block.

        // Do not check whether blocks are valid: that would require
        // producing (expensive) proofs and moreover block validity is not
        // what is being tested here. What is being tested here is the correct
        // mempool update and for that purpose we can do with an invalid block
        // proof.

        // Bob is premine receiver, Alice is not
        let mut rng: StdRng = StdRng::seed_from_u64(0x03ce19960c467f90u64);

        let network = Network::Main;
        let bob_wallet_secret = WalletSecret::devnet_wallet();
        let bob_spending_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
        let mut bob = mock_genesis_global_state(network, 2, bob_wallet_secret).await;

        let bob_address = bob_spending_key.to_address();

        let alice_wallet = WalletSecret::new_pseudorandom(rng.gen());
        let alice_spending_key = alice_wallet.nth_generation_spending_key_for_tests(0);
        let alice_address = alice_spending_key.to_address();
        let mut alice = mock_genesis_global_state(network, 2, alice_wallet).await;

        // Ensure that both wallets have a non-zero balance
        let genesis_block = Block::genesis_block(network);
        let (block_1, coinbase_utxo_1, cb_sender_randomness_1) =
            make_mock_block(&genesis_block, None, alice_address, rng.gen());

        // Update both states with block 1
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxo(ExpectedUtxo::new(
                coinbase_utxo_1,
                cb_sender_randomness_1,
                alice_spending_key.privacy_preimage,
                UtxoNotifier::OwnMiner,
            ))
            .await;
        alice.set_new_tip(block_1.clone()).await.unwrap();
        bob.set_new_tip(block_1.clone()).await.unwrap();

        // Create a transaction that's valid to be included in block 2
        let mut utxos_from_bob = TxOutputList::from(vec![]);
        for i in 0..4 {
            let amount: NeptuneCoins = NeptuneCoins::new(i);
            utxos_from_bob.push(TxOutput::onchain_native_currency(
                amount,
                rng.gen(),
                bob_address.into(),
            ));
        }

        let now = genesis_block.kernel.header.timestamp;
        let in_seven_months = now + Timestamp::months(7);
        let in_eight_months = now + Timestamp::months(8);
        let in_nine_months = now + Timestamp::months(9);
        let (tx_by_bob, maybe_change_output) = bob
            .lock_guard()
            .await
            .create_transaction_with_prover_capability(
                utxos_from_bob.clone(),
                bob_spending_key.into(),
                UtxoNotificationMedium::OnChain,
                NeptuneCoins::new(1),
                in_seven_months,
                TxProvingCapability::SingleProof,
                &TritonVmJobQueue::dummy(),
            )
            .await
            .unwrap();

        // inform wallet of any expected utxos from this tx.
        let expected_utxos = bob.lock_guard().await.wallet_state.extract_expected_utxos(
            utxos_from_bob.concat_with(maybe_change_output),
            UtxoNotifier::Myself,
        );
        bob.lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_utxos)
            .await;

        // Add this transaction to a mempool
        let mut mempool = Mempool::new(ByteSize::gb(1), None, block_1.hash());
        mempool.insert(tx_by_bob.clone());

        // Create another transaction that's valid to be included in block 2, but isn't actually
        // included by the miner. This transaction is inserted into the mempool, but since it's
        // not included in block 2 it must still be in the mempool after the mempool has been
        // updated with block 2. Also: The transaction must be valid after block 2 as the mempool
        // manager must keep mutator set data updated.
        let utxos_from_alice = vec![TxOutput::onchain_native_currency(
            NeptuneCoins::new(68),
            rng.gen(),
            alice_address.into(),
        )];
        let (tx_from_alice_original, _maybe_change_output) = alice
            .lock_guard()
            .await
            .create_transaction_with_prover_capability(
                utxos_from_alice.into(),
                alice_spending_key.into(),
                UtxoNotificationMedium::OffChain,
                NeptuneCoins::new(1),
                in_seven_months,
                TxProvingCapability::SingleProof,
                &TritonVmJobQueue::dummy(),
            )
            .await
            .unwrap();
        mempool.insert(tx_from_alice_original);

        {
            // Verify that `most_dense_single_proof_pair` returns expected value
            // now that two single proofs are in the mempool.
            let densest_txs = mempool.get_sorted_iter().map(|x| x.0).collect_vec();
            assert_eq!(
                densest_txs,
                mempool
                    .most_dense_single_proof_pair()
                    .unwrap()
                    .map(|x| x.0.txid())
                    .to_vec()
            );
        }

        // Create next block which includes preminer's transaction
        let (coinbase_transaction, _expected_utxo) =
            make_coinbase_transaction(&bob, NeptuneCoins::zero(), in_eight_months)
                .await
                .unwrap();
        let block_transaction = tx_by_bob
            .merge_with(
                coinbase_transaction,
                Default::default(),
                &TritonVmJobQueue::dummy(),
                TritonVmJobPriority::default(),
            )
            .await
            .unwrap();
        let block_2 =
            Block::block_template_invalid_proof(&block_1, block_transaction, in_eight_months, None);

        // Update the mempool with block 2 and verify that the mempool now only contains one tx
        assert_eq!(2, mempool.len());
        mempool
            .update_with_block(
                block_1.kernel.body.mutator_set_accumulator.clone(),
                &block_2,
                &TritonVmJobQueue::dummy(),
                TritonVmJobPriority::default(),
            )
            .await;
        assert_eq!(1, mempool.len());

        // Create a new block to verify that the non-mined transaction contains
        // updated and valid-again mutator set data
        let mut tx_by_alice_updated: Transaction =
            mempool.get_transactions_for_block(usize::MAX, None)[0].clone();
        assert!(
            tx_by_alice_updated.is_confirmable_relative_to(&block_2.body().mutator_set_accumulator),
            "Block with tx with updated mutator set data must be confirmable wrt. block_2"
        );

        alice.set_new_tip(block_2.clone()).await.unwrap();
        bob.set_new_tip(block_2.clone()).await.unwrap();
        let (coinbase_transaction2, _expected_utxo2) =
            make_coinbase_transaction(&bob, NeptuneCoins::zero(), in_eight_months)
                .await
                .unwrap();
        let block_transaction2 = tx_by_alice_updated
            .clone()
            .merge_with(
                coinbase_transaction2,
                Default::default(),
                &TritonVmJobQueue::dummy(),
                TritonVmJobPriority::default(),
            )
            .await
            .unwrap();
        let _block_3_orphaned =
            Block::block_template_invalid_proof(&block_2, block_transaction2, in_nine_months, None);

        debug!(
            "tx_by_other_updated has mutator set hash: {}",
            tx_by_alice_updated.kernel.mutator_set_hash
        );

        // Mine 2 blocks without including the transaction but while still keeping the
        // mempool updated. After these 2 blocks are mined, the transaction must still be
        // valid. Notic that `block_3_orphaned` was forked away, never added to mempool,
        // since we want to keep the transaction in the mempool.
        let mut previous_block = block_2;
        for _ in 0..2 {
            let (next_block, _, _) =
                make_mock_block(&previous_block, None, alice_address, rng.gen());
            alice.set_new_tip(next_block.clone()).await.unwrap();
            bob.set_new_tip(next_block.clone()).await.unwrap();
            mempool
                .update_with_block(
                    previous_block.kernel.body.mutator_set_accumulator.clone(),
                    &next_block,
                    &TritonVmJobQueue::dummy(),
                    TritonVmJobPriority::default(),
                )
                .await;
            previous_block = next_block;
        }

        tx_by_alice_updated = mempool.get_transactions_for_block(usize::MAX, None)[0].clone();
        let block_5_timestamp = previous_block.header().timestamp + Timestamp::hours(1);
        let (cbtx, _eutxo) =
            make_coinbase_transaction(&alice, NeptuneCoins::zero(), block_5_timestamp)
                .await
                .unwrap();
        let block_tx_5 = cbtx
            .merge_with(
                tx_by_alice_updated,
                Default::default(),
                &TritonVmJobQueue::dummy(),
                TritonVmJobPriority::default(),
            )
            .await
            .unwrap();
        let block_5 = Block::block_template_invalid_proof(
            &previous_block,
            block_tx_5,
            block_5_timestamp,
            None,
        );
        assert_eq!(Into::<BlockHeight>::into(5), block_5.kernel.header.height);

        mempool
            .update_with_block(
                previous_block.kernel.body.mutator_set_accumulator.clone(),
                &block_5,
                &TritonVmJobQueue::dummy(),
                TritonVmJobPriority::default(),
            )
            .await;

        assert!(
            mempool.is_empty(),
            "Mempool must be empty after 2nd tx was mined"
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn merged_tx_kicks_out_merge_inputs() {
        /// Returns three transactions: Two transactions that are input to the
        /// transaction-merge function, and the resulting merged transaction.
        async fn merge_tx_triplet() -> ((Transaction, Transaction), Transaction) {
            let mut test_runner = TestRunner::deterministic();
            let [left, right] = PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets([
                (2, 2, 2),
                (2, 2, 2),
            ])
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

            let left_single_proof = SingleProof::produce(
                &left,
                &TritonVmJobQueue::dummy(),
                TritonVmJobPriority::default(),
            )
            .await
            .unwrap();
            let right_single_proof = SingleProof::produce(
                &right,
                &TritonVmJobQueue::dummy(),
                TritonVmJobPriority::default(),
            )
            .await
            .unwrap();

            let left = Transaction {
                kernel: left.kernel,
                proof: TransactionProof::SingleProof(left_single_proof),
            };
            let right = Transaction {
                kernel: right.kernel,
                proof: TransactionProof::SingleProof(right_single_proof),
            };

            let shuffle_seed = arb::<[u8; 32]>()
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
            let merged = Transaction::merge_with(
                left.clone(),
                right.clone(),
                shuffle_seed,
                &TritonVmJobQueue::dummy(),
                TritonVmJobPriority::default(),
            )
            .await
            .unwrap();

            ((left, right), merged)
        }
        // Verify that a merged transaction replaces the two transactions that
        // are the input into the merge.
        let network = Network::Main;
        let genesis_block = Block::genesis_block(network);
        let mut mempool = Mempool::new(ByteSize::gb(1), None, genesis_block.hash());

        let ((left, right), merged) = merge_tx_triplet().await;
        mempool.insert(left);
        mempool.insert(right);
        assert_eq!(2, mempool.len());

        // Verify that `most_dense_single_proof_pair` returns expected value
        // now that two single proofs are in the mempool.
        let densest_txs = mempool.get_sorted_iter().map(|x| x.0).collect_vec();
        assert_eq!(
            densest_txs,
            mempool
                .most_dense_single_proof_pair()
                .unwrap()
                .map(|x| x.0.txid())
                .to_vec()
        );

        mempool.insert(merged.clone());
        assert_eq!(1, mempool.len());
        assert_eq!(&merged, mempool.get(merged.kernel.txid()).unwrap());

        // Verify that `most_dense_single_proof_pair` returns expected value
        // now that there's only *one* tx in the mempool.
        assert!(mempool.most_dense_single_proof_pair().is_none());
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
        let alice_wallet = WalletSecret::devnet_wallet();
        let alice_key = alice_wallet.nth_generation_spending_key_for_tests(0);
        let mut alice = mock_genesis_global_state(network, 2, alice_wallet).await;

        let mut rng: StdRng = StdRng::seed_from_u64(u64::from_str_radix("42", 6).unwrap());
        let bob_wallet_secret = WalletSecret::new_pseudorandom(rng.gen());
        let bob_address = bob_wallet_secret
            .nth_generation_spending_key_for_tests(0)
            .to_address();

        let tx_receiver_data =
            TxOutput::onchain_native_currency(NeptuneCoins::new(1), rng.gen(), bob_address.into());

        let genesis_block = alice
            .lock_guard()
            .await
            .chain
            .archival_state()
            .genesis_block()
            .to_owned();
        let now = genesis_block.kernel.header.timestamp;
        let in_seven_years = now + Timestamp::months(7 * 12);
        let (unmined_tx, _maybe_change_output) = alice
            .lock_guard()
            .await
            .create_transaction_with_prover_capability(
                vec![tx_receiver_data].into(),
                alice_key.into(),
                UtxoNotificationMedium::OffChain,
                NeptuneCoins::new(1),
                in_seven_years,
                TxProvingCapability::SingleProof,
                &TritonVmJobQueue::dummy(),
            )
            .await
            .unwrap();

        alice.lock_guard_mut().await.mempool.insert(unmined_tx);

        // Add some blocks. The transaction must stay in the mempool, since it
        // is not being mined.
        let mut current_block = genesis_block.clone();
        for _ in 0..2 {
            let (next_block, _, _) =
                make_mock_block(&current_block, Some(in_seven_years), bob_address, rng.gen());
            alice.set_new_tip(next_block.clone()).await.unwrap();

            let mempool_txs = alice
                .lock_guard()
                .await
                .mempool
                .get_transactions_for_block(usize::MAX, None);
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
                alice.lock_guard().await.mempool.tip_digest,
                "Mempool's sync digest must be set correctly"
            );

            current_block = next_block;
        }

        // Now make a deep reorganization and verify that nothing crashes
        let (block_1b, _, _) =
            make_mock_block(&genesis_block, Some(in_seven_years), bob_address, rng.gen());
        assert!(
            block_1b.header().height.previous().is_genesis(),
            "Sanity check that new tip has height 1"
        );
        alice.set_new_tip(block_1b.clone()).await.unwrap();

        // Verify that all retained txs (if any) are confirmable against
        // the new tip.
        assert!(
            alice
                .lock_guard()
                .await
                .mempool
                .get_transactions_for_block(usize::MAX, None)
                .iter()
                .all(|tx| tx.is_confirmable_relative_to(&block_1b.body().mutator_set_accumulator)),
            "All retained txs in the mempool must be confirmable relative to the new block.
             Or the mempool must be empty."
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn conflicting_txs_preserve_highest_fee() {
        // Create a global state object, controlled by a preminer who receives a premine-UTXO.
        let network = Network::Main;
        let mut preminer =
            mock_genesis_global_state(network, 2, WalletSecret::devnet_wallet()).await;
        let premine_spending_key = preminer
            .lock_guard()
            .await
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key_for_tests(0);
        let premine_address = premine_spending_key.to_address();
        let mut rng = StdRng::seed_from_u64(589111u64);

        let make_transaction_with_fee =
            |fee: NeptuneCoins, preminer_clone: GlobalStateLock, sender_randomness: Digest| async move {
                let in_seven_months =
                    Block::genesis_block(network).kernel.header.timestamp + Timestamp::months(7);

                let receiver_data = TxOutput::offchain_native_currency(
                    NeptuneCoins::new(1),
                    sender_randomness,
                    premine_address.into(),
                );
                let tx_outputs: TxOutputList = vec![receiver_data.clone()].into();
                let (tx, _maybe_change_output) = preminer_clone
                    .clone()
                    .lock_guard()
                    .await
                    .create_transaction_with_prover_capability(
                        tx_outputs.clone(),
                        premine_spending_key.into(),
                        UtxoNotificationMedium::OnChain,
                        fee,
                        in_seven_months,
                        TxProvingCapability::ProofCollection,
                        &TritonVmJobQueue::dummy(),
                    )
                    .await
                    .expect("producing proof collection should succeed");
                tx
            };

        assert_eq!(0, preminer.lock_guard().await.mempool.len());

        // Insert transaction into mempool
        let tx_low_fee =
            make_transaction_with_fee(NeptuneCoins::new(1), preminer.clone(), rng.gen()).await;
        {
            let mempool = &mut preminer.lock_guard_mut().await.mempool;
            mempool.insert(tx_low_fee.clone());
            assert_eq!(1, mempool.len());
            assert_eq!(&tx_low_fee, mempool.get(tx_low_fee.kernel.txid()).unwrap());
        }

        // Insert a transaction that spends the same UTXO and has a higher fee.
        // Verify that this replaces the previous transaction.
        let tx_high_fee =
            make_transaction_with_fee(NeptuneCoins::new(10), preminer.clone(), rng.gen()).await;
        {
            let mempool = &mut preminer.lock_guard_mut().await.mempool;
            mempool.insert(tx_high_fee.clone());
            assert_eq!(1, mempool.len());
            assert_eq!(
                &tx_high_fee,
                mempool.get(tx_high_fee.kernel.txid()).unwrap()
            );
        }

        // Insert a conflicting transaction with a lower fee and verify that it
        // does *not* replace the existing transaction.
        {
            let tx_medium_fee =
                make_transaction_with_fee(NeptuneCoins::new(4), preminer.clone(), rng.gen()).await;
            let mempool = &mut preminer.lock_guard_mut().await.mempool;
            mempool.insert(tx_medium_fee.clone());
            assert_eq!(1, mempool.len());
            assert_eq!(
                &tx_high_fee,
                mempool.get(tx_high_fee.kernel.txid()).unwrap()
            );
            assert!(mempool.get(tx_medium_fee.kernel.txid()).is_none());
            assert!(mempool.get(tx_low_fee.kernel.txid()).is_none());
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn max_len_none() {
        let network = Network::Main;
        let genesis_block = Block::genesis_block(network);
        let txs = make_plenty_mock_transaction_with_primitive_witness(11);
        let mut mempool = Mempool::new(ByteSize::gb(1), None, genesis_block.hash());

        for tx in txs {
            mempool.insert(tx);
        }

        assert_eq!(
            11,
            mempool.len(),
            "All transactions are inserted into mempool"
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn max_len_is_respected() {
        let network = Network::Main;
        let genesis_block = Block::genesis_block(network);
        let txs = make_plenty_mock_transaction_with_primitive_witness(20);

        let mut expected_txs = txs.clone();
        expected_txs.sort_by_key(|x| x.fee_density());
        expected_txs.reverse();

        for i in 0..10 {
            let mut mempool = Mempool::new(ByteSize::gb(1), Some(i), genesis_block.hash());
            for tx in txs.clone() {
                mempool.insert(tx);
            }

            assert_eq!(
                i,
                mempool.len(),
                "Only {i} transactions are permitted in the mempool"
            );

            let expected_txs = expected_txs.iter().take(i).cloned().collect_vec();

            let mut mempool_iter = mempool.get_sorted_iter();
            for expected_tx in expected_txs.iter() {
                let (txid, fee_density) = mempool_iter.next().unwrap();
                assert_eq!(expected_tx, mempool.get(txid).unwrap());
                assert_eq!(expected_tx.fee_density(), fee_density);
            }
        }
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
