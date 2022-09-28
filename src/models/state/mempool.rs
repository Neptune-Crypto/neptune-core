//! An implementation of a mempool to store broadcast transactions waiting to be
//! mined.  The implementation maintains a mapping called `table` between
//! 'transaction digests' and the full 'transactions' object, as well as a
//! double-ended priority queue called `queue` containing sorted pairs of
//! 'transaction digests' and the associated 'fee density'.  The `table` can be
//! seen as an associative cache that provides fast random-lookups, while
//! `queue` maintains transactions id's ordered by 'fee density'. Usually, we
//! are interested in the transaction with either the highest or the lowest 'fee
//! density'.
//!
//! The `Mempool` type is a thread-safe wrapper around `MempoolInternal`, and
//! all interaction should go through the wrapper.

use crate::models::blockchain::digest::Hashable;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::{Amount, Transaction, TransactionDigest};
use crate::models::shared::SIZE_1GB_IN_BYTES;

use get_size::GetSize;
use num_traits::Zero;
use priority_queue::{double_priority_queue::iterators::IntoSortedIter, DoublePriorityQueue};
use std::sync::RwLock as StdRwLock;
use std::{
    collections::{
        hash_map::{Entry, RandomState},
        HashMap, HashSet,
    },
    iter::Rev,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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

type LookupItem<'a> = (TransactionDigest, &'a Transaction);

/// Timestamp of 'now' encoded as the duration since epoch.
fn now() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

#[derive(Debug, Clone)]
pub struct Mempool {
    pub internal: Arc<StdRwLock<MempoolInternal>>,
}

impl Default for Mempool {
    fn default() -> Self {
        Self {
            internal: Arc::new(StdRwLock::new(MempoolInternal::default())),
        }
    }
}

impl Mempool {
    pub fn get_size(&self) -> usize {
        self.internal.get_size()
    }

    /// Computes in O(1) from HashMap
    pub fn contains(&self, transaction_id: &TransactionDigest) -> bool {
        let lock = self.internal.read().unwrap();
        lock.contains(transaction_id)
    }

    /// Computes in O(1) from HashMap
    pub fn get(&self, transaction_id: &TransactionDigest) -> Option<Transaction> {
        let lock = self.internal.read().unwrap();
        lock.get(transaction_id).cloned()
    }

    /// Returns `None` if transaction was not already in the mempool and `Some(&Transaction)`
    /// to the existing item otherwise.
    /// Computes in θ(log(N)) time.
    pub fn insert(&self, transaction: &Transaction) -> Option<Transaction> {
        let mut lock = self.internal.write().unwrap();
        lock.insert(transaction).cloned()
    }

    /// The operation is performed in Ο(log(N)) time (worst case).
    /// Computes in θ(lg N)
    pub fn remove(&self, transaction_id: &TransactionDigest) -> Option<Transaction> {
        let mut lock = self.internal.write().unwrap();
        lock.remove(transaction_id)
    }

    /// Return the number of transactions currently stored in the Mempool.
    /// Computes in O(1)
    pub fn len(&self) -> usize {
        let lock = self.internal.read().unwrap();
        lock.len()
    }

    /// Computes in O(1)
    pub fn is_empty(&self) -> bool {
        let lock = self.internal.read().unwrap();
        lock.is_empty()
    }

    /// Return a vector with copies of the transactions, in descending order, with
    /// the highest fee density not using more than `remaining_storage` bytes.
    /// Typically a block is about 0MB, meaning that the return value of this function is also less than 1MB.
    pub fn get_densest_transactions(&self, remaining_storage: usize) -> Vec<Transaction> {
        let lock = self.internal.read().unwrap();
        lock.get_densest_transactions(remaining_storage)
    }

    /// Prune based on `Transaction.timestamp`
    /// Computes in O(n)
    pub fn prune_stale_transactions(&self) {
        let mut lock = self.internal.write().unwrap();
        lock.prune_stale_transactions()
    }

    /// Remove any transaction from the mempool that are invalid due to the latest block
    /// containing a new transaction.
    pub fn remove_transactions_with(
        &self,
        transaction: &Transaction,
        lock: &mut std::sync::RwLockWriteGuard<MempoolInternal>,
    ) {
        lock.remove_transactions_with(transaction)
    }

    /// Shrink the memory pool to the value of its `max_size` field.
    /// Likely computes in O(n)
    pub fn shrink_to_max_size(&self) {
        let mut lock = self.internal.write().unwrap();
        lock.shrink_to_max_size()
    }

    /// Shrinks internal data structures as much as possible.
    /// Computes in O(n) (Likely)
    pub fn shrink_to_fit(&self) {
        let mut lock = self.internal.write().unwrap();
        lock.shrink_to_fit()
    }

    /// Produce a sorted iterator over a snapshot of the Double-Ended Priority Queue.
    ///
    /// # Example
    ///
    /// ```
    /// use neptune_core::models::state::mempool::Mempool;
    ///
    /// let mempool = Mempool::default();
    /// // insert transactions here.
    /// let mut most_valuable_transactions = vec![];
    /// for (transaction_digest, fee_density) in mempool.get_sorted_iter() {
    ///    let t = mempool.get(&transaction_digest);
    ///    most_valuable_transactions.push(t);
    /// }
    /// ```
    ///
    /// Yields the `transaction_digest` in order of descending `fee_density`, since
    /// users (miner or transaction merger) will likely only care about the most valuable transactions
    /// Computes in O(N lg N)
    pub fn get_sorted_iter(
        &self,
    ) -> Rev<IntoSortedIter<TransactionDigest, FeeDensity, RandomState>> {
        let lock = self.internal.read().unwrap();
        lock.get_sorted_iter()
    }
}

/// The fundamental data type in this module.
///
/// # Example
///
/// ```
/// // Instantiate Mempool, insert and get a transaction.
/// use neptune_core::models::blockchain::{transaction::Transaction, digest::Hashable};
/// use neptune_core::models::state::mempool::Mempool;
/// use twenty_first::{shared_math::b_field_element::BFieldElement, amount::u32s::U32s};
///
/// let mempool = Mempool::default();
/// let timestamp = BFieldElement::new(0);
/// let transaction = Transaction {
///     inputs: vec![],
///     outputs: vec![],
///     public_scripts: vec![],
///     fee: U32s::from(0u32),
///     timestamp,
///     authority_proof: None,
/// };
/// mempool.insert(&transaction);
/// let transaction_digest = transaction.neptune_hash();
/// let stored_transaction = mempool.get(&transaction_digest).unwrap();
/// assert_eq!(transaction, stored_transaction)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, GetSize)]
pub struct MempoolInternal {
    max_size: usize,
    // Maintain for constant lookup
    table: HashMap<TransactionDigest, Transaction>,
    // Maintain for fast min and max
    #[get_size(ignore)] // This is relatively small compared to `LookupTable`
    queue: DoublePriorityQueue<TransactionDigest, FeeDensity>,
}

impl Default for MempoolInternal {
    fn default() -> Self {
        Self {
            table: HashMap::default(),
            queue: DoublePriorityQueue::default(),
            // 1GB in bytes
            max_size: SIZE_1GB_IN_BYTES,
        }
    }
}

impl MempoolInternal {
    fn contains(&self, transaction_id: &TransactionDigest) -> bool {
        self.table.contains_key(transaction_id)
    }

    fn get(&self, transaction_id: &TransactionDigest) -> Option<&Transaction> {
        self.table.get(transaction_id)
    }

    fn insert(&mut self, transaction: &Transaction) -> Option<&Transaction> {
        {
            // Early exit on transactions too long into the future.
            let horizon =
                now() + Duration::from_secs(MEMPOOL_IGNORE_TRANSACTIONS_THIS_MANY_SECS_AHEAD);

            if transaction.timestamp.value() > horizon.as_secs() {
                return None;
            }
        }

        let transaction_id: TransactionDigest =
            <Transaction as Hashable>::neptune_hash(transaction);

        if let Entry::Vacant(slot) = self.table.entry(transaction_id) {
            self.queue.push(transaction_id, transaction.fee_density());
            slot.insert(transaction.to_owned());
            debug_assert_eq!(self.table.len(), self.queue.len());
            self.shrink_to_max_size();
            None
        } else {
            self.table.get(&transaction_id)
        }
    }

    fn remove(&mut self, transaction_id: &TransactionDigest) -> Option<Transaction> {
        if let rv @ Some(_) = self.table.remove(transaction_id) {
            self.queue.remove(transaction_id);
            debug_assert_eq!(self.table.len(), self.queue.len());
            return rv;
        }

        None
    }

    fn len(&self) -> usize {
        self.table.len()
    }

    fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    fn get_densest_transactions(&self, mut remaining_storage: usize) -> Vec<Transaction> {
        let mut transactions = vec![];
        let mut _fee_acc = Amount::zero();

        for (transaction_digest, _fee_density) in self.get_sorted_iter() {
            // No more transactions can possibly be packed
            if remaining_storage == 0 {
                break;
            }

            if let Some(transaction_ptr) = self.get(&transaction_digest.clone()) {
                let transaction_copy = transaction_ptr.to_owned();
                let transaction_size = transaction_copy.get_size();

                // Current transaction is too big
                if transaction_size > remaining_storage {
                    continue;
                }

                // Include transaction
                remaining_storage -= transaction_size;
                _fee_acc = _fee_acc + transaction_copy.fee;
                transactions.push(transaction_copy)
            }
        }

        transactions
    }

    /// Computes in θ(lg N)
    #[allow(dead_code)]
    fn pop_max(&mut self) -> Option<(Transaction, FeeDensity)> {
        if let Some((transaction_digest, fee_density)) = self.queue.pop_max() {
            let transaction = self.table.remove(&transaction_digest).unwrap();
            debug_assert_eq!(self.table.len(), self.queue.len());
            Some((transaction, fee_density))
        } else {
            None
        }
    }

    /// Computes in θ(lg N)
    fn pop_min(&mut self) -> Option<(Transaction, FeeDensity)> {
        if let Some((transaction_digest, fee_density)) = self.queue.pop_min() {
            let transaction = self.table.remove(&transaction_digest).unwrap();
            debug_assert_eq!(self.table.len(), self.queue.len());
            Some((transaction, fee_density))
        } else {
            None
        }
    }

    /// Modelled after [HashMap::retain][HashMap::retain]
    /// [HashMap::retain]: https://doc.rust-lang.org/std/collections/struct.HashMap.html#method.retain
    /// Computes in O(capacity) >= O(N)
    fn retain<F>(&mut self, mut predicate: F)
    where
        F: FnMut(LookupItem) -> bool,
    {
        let mut victims = vec![];

        for (transaction_id, _fee_density) in self.queue.iter() {
            let transaction = self.get(transaction_id).unwrap();
            if !predicate((*transaction_id, transaction)) {
                victims.push(*transaction_id);
            }
        }

        for t in victims {
            self.remove(&t);
        }

        debug_assert_eq!(self.table.len(), self.queue.len());
        self.shrink_to_fit()
    }

    fn prune_stale_transactions(&mut self) {
        let cutoff = now() - Duration::from_secs(MEMPOOL_TX_THRESHOLD_AGE_IN_SECS);

        let keep = |(_transaction_id, transaction): LookupItem| -> bool {
            cutoff.as_secs() < transaction.timestamp.value()
        };

        self.retain(keep);
    }

    // TODO: This function remove from the mempool all those transactions that become invalid because
    // of this newly mined block.
    fn remove_transactions_with(&mut self, transaction: &Transaction) {
        //! Checks if the `input_utxos` in `canonical_transaction`
        //! and any `transaction` in the mempool is disjoint.
        //! Removes the `transaction` from mempool otherwise.

        let mined_utxos: HashSet<Utxo> = transaction.get_input_utxos().into_iter().collect();

        let keep = |(_transaction_id, tx): LookupItem| -> bool {
            let transaction_set: HashSet<Utxo> = tx.get_input_utxos().into_iter().collect();

            transaction_set.is_disjoint(&mined_utxos)
        };

        self.retain(keep);
    }

    fn shrink_to_max_size(&mut self) {
        // Repeately remove the least valuable transaction
        while self.get_size() > self.max_size && self.pop_min().is_some() {
            continue;
        }

        self.shrink_to_fit()
    }

    fn shrink_to_fit(&mut self) {
        self.queue.shrink_to_fit();
        self.table.shrink_to_fit()
    }

    fn get_sorted_iter(&self) -> Rev<IntoSortedIter<TransactionDigest, FeeDensity, RandomState>> {
        let dpq_clone = self.queue.clone();
        dpq_clone.into_sorted_iter().rev()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        models::{
            blockchain::transaction::{Amount, Transaction},
            shared::SIZE_1MB_IN_BYTES,
        },
        tests::shared::{get_mock_wallet_state, make_mock_transaction_with_wallet},
    };
    use num_bigint::BigInt;
    use num_traits::Zero;
    use twenty_first::shared_math::b_field_element::BFieldElement;

    #[test]
    pub fn insert_then_get_then_remove_then_get() {
        let mempool = Mempool::default();
        let wallet_state = get_mock_wallet_state();
        let transaction =
            make_mock_transaction_with_wallet(vec![], vec![], Amount::zero(), &wallet_state, None);
        let transaction_digest = &<Transaction as Hashable>::neptune_hash(&transaction);
        assert!(!mempool.contains(transaction_digest));
        mempool.insert(&transaction);
        assert!(mempool.contains(transaction_digest));

        let transaction_get_option = mempool.get(transaction_digest);
        assert_eq!(Some(transaction.clone()), transaction_get_option);
        assert!(mempool.contains(transaction_digest));

        let transaction_remove_option = mempool.remove(transaction_digest);
        assert_eq!(Some(transaction), transaction_remove_option);
        assert!(!mempool.contains(transaction_digest));

        let transaction_second_remove_option = mempool.remove(transaction_digest);
        assert_eq!(None, transaction_second_remove_option);
        assert!(!mempool.contains(transaction_digest))
    }

    // Create a mempool with 10 transactions.
    fn setup(transactions_count: u32) -> Mempool {
        let mempool = Mempool::default();
        let wallet_state = get_mock_wallet_state();
        for i in 0..transactions_count {
            let t = make_mock_transaction_with_wallet(
                vec![],
                vec![],
                Amount::from(i),
                &wallet_state,
                None,
            );
            mempool.insert(&t);
        }
        println!("Mempool size: {}", mempool.len());
        mempool
    }

    #[test]
    pub fn get_densest_transactions() {
        let mempool = setup(10);

        let max_fee_density: FeeDensity = FeeDensity::new(BigInt::from(999), BigInt::from(1));
        let mut prev_fee_density = max_fee_density;
        for curr_transaction in mempool.get_densest_transactions(SIZE_1MB_IN_BYTES) {
            let curr_fee_density = curr_transaction.fee_density();
            println!("curr:{} <= prev: {}", curr_fee_density, prev_fee_density);
            assert!(curr_fee_density <= prev_fee_density);
            prev_fee_density = curr_fee_density;
        }
        assert!(!mempool.is_empty())
    }

    #[test]
    pub fn prune_stale_transactions() {
        let wallet_state = get_mock_wallet_state();
        let mempool = Mempool::default();
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
                Amount::from(i),
                &wallet_state,
                timestamp,
            );
            mempool.insert(&t);
        }

        for i in 0u32..5 {
            let t = make_mock_transaction_with_wallet(
                vec![],
                vec![],
                Amount::from(i),
                &wallet_state,
                None,
            );
            mempool.insert(&t);
        }
        println!("Mempool size: {}", mempool.len());
        assert_eq!(mempool.len(), 10);
        mempool.prune_stale_transactions();
        assert_eq!(mempool.len(), 5)
    }

    #[test]
    pub fn remove_transactions_with_test() {
        let wallet_state = get_mock_wallet_state();
        let wallet_state_unrelated = get_mock_wallet_state();

        let related_utxo = Utxo {
            amount: Amount::from(13u32),
            public_key: wallet_state.wallet.get_public_key(),
        };

        let unrelated_utxo = Utxo {
            amount: Amount::from(42u32),
            public_key: wallet_state_unrelated.wallet.get_public_key(),
        };

        let mempool = {
            let m = Mempool::default();

            // Insert partially related transactions.
            for i in 0u32..2 {
                let t = make_mock_transaction_with_wallet(
                    vec![unrelated_utxo, related_utxo],
                    vec![],
                    Amount::from(i),
                    &wallet_state,
                    None,
                );
                m.insert(&t);
            }

            for i in 0u32..3 {
                let t = make_mock_transaction_with_wallet(
                    vec![unrelated_utxo],
                    vec![related_utxo],
                    Amount::from(i),
                    &wallet_state,
                    None,
                );
                m.insert(&t);
            }

            // Insert unrelated transtions.
            for i in 0u32..5 {
                let t = make_mock_transaction_with_wallet(
                    vec![unrelated_utxo, unrelated_utxo],
                    vec![],
                    Amount::from(i),
                    &wallet_state_unrelated,
                    None,
                );
                m.insert(&t);
            }
            println!("Mempool size: {}", m.len());
            m
        };

        let canonicalized_transaction = make_mock_transaction_with_wallet(
            vec![related_utxo],
            vec![],
            Amount::from(454542u32),
            &wallet_state,
            None,
        );

        assert_eq!(mempool.len(), 10);
        {
            let mut m_lock: std::sync::RwLockWriteGuard<MempoolInternal> =
                mempool.internal.write().unwrap();
            mempool.remove_transactions_with(&canonicalized_transaction, &mut m_lock);
        }
        assert_eq!(mempool.len(), 8)
    }

    #[test]
    pub fn get_sorted_iter() {
        let mempool = setup(10);

        let max_fee_density: FeeDensity = FeeDensity::new(BigInt::from(999), BigInt::from(1));
        let mut prev_fee_density = max_fee_density;
        for (_transaction_id, curr_fee_density) in mempool.get_sorted_iter() {
            println!("curr:{} <= prev: {}", curr_fee_density, prev_fee_density);
            assert!(curr_fee_density <= prev_fee_density);
            prev_fee_density = curr_fee_density;
        }
        assert!(!mempool.is_empty())
    }

    #[test]
    pub fn get_mempool_size() {
        // Verify that the `get_size` method on mempool returns sane results
        let mempool_small = setup(10);
        let size_gs_small = mempool_small.get_size();
        let size_serialized_small =
            bincode::serialize(&mempool_small.internal.read().unwrap().table)
                .unwrap()
                .len();
        println!("size_gs_small = {}", size_gs_small);
        assert!(size_gs_small >= size_serialized_small);

        let mempool_big = setup(100);
        let size_gs_big = mempool_big.get_size();
        let size_serialized_big = bincode::serialize(&mempool_big.internal.read().unwrap().table)
            .unwrap()
            .len();
        println!("size_gs_big = {}", size_gs_big);
        assert!(size_gs_big >= size_serialized_big);
        assert!(size_gs_big >= 5 * size_gs_small);
    }
}
