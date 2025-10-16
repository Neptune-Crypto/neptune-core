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

pub mod mempool_event;
pub(crate) mod mempool_update_job;
pub(crate) mod mempool_update_job_result;
pub(crate) mod merge_input_cache;
pub(crate) mod primitive_witness_update;
pub mod upgrade_priority;

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::collections::HashSet;

use bytesize::ByteSize;
use get_size2::GetSize;
use itertools::Itertools;
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
use priority_queue::priority_queue::iterators::IntoSortedIter as SingleEndedIterator;
use priority_queue::DoublePriorityQueue;
use priority_queue::PriorityQueue;
use tasm_lib::prelude::Digest;
use tracing::debug;
use tracing::error;
use tracing::warn;

use crate::api::export::NeptuneProof;
use crate::application::config::tx_upgrade_filter::TxUpgradeFilter;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::peer::transfer_transaction::TransactionProofQuality;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::state::mempool::mempool_event::MempoolEvent;
use crate::state::mempool::mempool_update_job::MempoolUpdateJob;
use crate::state::mempool::merge_input_cache::MergeInputCache;
use crate::state::mempool::merge_input_cache::MergeInputCacheElement;
use crate::state::mempool::primitive_witness_update::PrimitiveWitnessUpdate;
use crate::state::mempool::upgrade_priority::UpgradePriority;
use crate::state::transaction::transaction_kernel_id::TransactionKernelId;
use crate::state::transaction::tx_proving_capability::TxProvingCapability;

// 72 hours in secs
pub const MEMPOOL_TX_THRESHOLD_AGE_IN_SECS: u64 = 72 * 60 * 60;

pub const TRANSACTION_NOTIFICATION_AGE_LIMIT_IN_SECS: u64 = 60 * 60 * 24;

type LookupItem<'a> = (TransactionKernelId, &'a Transaction);

#[derive(Debug, GetSize, Clone)]
#[cfg_attr(test, derive(serde::Serialize))]
struct MempoolTransaction {
    transaction: Transaction,

    /// The value of a transaction for the node operator.
    upgrade_priority: UpgradePriority,

    /// Primitive witness of the transaction. Can be used to update proof-
    /// collection backed transactions. If set, indicates that the transaction
    /// originated on this node.
    primitive_witness: Option<PrimitiveWitness>,
}

/// Unpersisted view of valid transactions that have not been confirmed yet.
///
/// Transactions can be inserted into the mempool, and a max size of the
/// mempool can be declared.
///
/// The mempool uses [`TransactionKernelId`] as its main key, meaning that two
/// different transactions with the same [`TransactionKernelId`] can never be
/// stored in the mempool. The mempool keeps a sorted view of which transactions
/// are the most fee-paying as measured by [`FeeDensity`], thus allowing for the
/// least valuable (from a miner's and proof upgrader's perspective)
/// transactions to be dropped. However, the mempool always favors transactions
/// of higher "proof-quality" such that a single-proof backed transaction will
/// always replace a primitive-witness or proof-collection backed transaction,
/// without considering fee densities. This is because a) single-proof backed
/// transactions can always be synced to the latest block (assuming no
/// reorganization has occurred), and b) because single-proof backed
/// transactions are more likely to be picked for inclusion in the next block.
///
/// The mempool also keeps a view of the "upgrade priorities" of transactions,
/// from the perspective the the caller inserting the transaction. However, this
/// value is not used to determine which transactions gets to stay in the
/// mempool in the case of a full mempool, since such a value is subjective,
/// and a goal is to have different nodes running with the same mempool policy
/// to agree on the content of the mempool at any time, up to networking
/// conditions.
///
/// The mempool does not attempt to confirm validity or confirmability of its
/// transactions, that must be handled by the caller. It does, however,
/// guarantee that no conflicting transactions can be contained in the mempool.
/// This means that two transactions that spend the same input will never be
/// allowed into the mempool simultaneously.
///
/// To prevent valid transactions from being needlessly forgotten the mempool
/// maintains a cache of transactions that have been  deemed "merge inputs".
/// In short, consider the merger of transaction a and b into c. If the mempool
/// sees all three transactions, first a and b, then c, c will replace a and b
/// in the mempool in accordance with the above stated policy of no conflicting
/// transactions. However, a and b are kept around in a cache that's not
/// considered a part of the mempool as they will not e.g. be returned for block
/// construction. The cache is only used to avoid dropping transaction a if b is
/// mined instead of c. See `MergeInputCache` for a more detailed explanation.
///
/// The mempool returns a list of events which should be handled by associated
/// wallets to see unconfirmed balance updates. So all functions that can
/// return events should be invoked from a context where listeners (like
/// wallets) can be informed.
#[derive(Debug, GetSize)]
// *never* use Clone outside of tests as only one instance of the mempool should
// ever be needed by the aplication. Also: The mempool can have a size in the
// gigabytes so any application logic cloning it should have terrible
// performance.
#[cfg_attr(test, derive(Clone))]
pub struct Mempool {
    /// Maximum size this data structure may take up in memory. In bytes.
    max_total_size: usize,

    /// Contains transactions, with a mapping from transaction ID to
    /// transaction. Contains all transactions considered to be "in the
    /// mempool".
    tx_dictionary: HashMap<TransactionKernelId, MempoolTransaction>,

    /// Allows the mempool to report transactions sorted by [`FeeDensity`] in
    /// both descending and ascending order. Contains all transactions
    /// considered to be "in the mempool".
    // This is relatively small compared to `tx_dictionary`
    #[get_size(ignore)]
    fee_densities: DoublePriorityQueue<TransactionKernelId, FeeDensity>,

    /// Allows the mempool to report transactions sorted by value in descending
    /// upgrade priority. Only transactions that are somehow relevant to this
    /// node are recorded here.
    // This is relatively small compared to `tx_dictionary`
    #[get_size(ignore)]
    upgrade_priorities: PriorityQueue<TransactionKernelId, UpgradePriority>,

    /// The digest of the chain's tip. Used to discover reorganizations.
    tip_digest: Digest,

    /// The digest of the tip's mutator set hash. Used to check transaction
    /// confirmability.
    tip_mutator_set_hash: Digest,

    /// The proving capability of the client. Used to determine if
    /// self-initiated single-proof backed transactions should be updated when
    /// a new block is processed.
    tx_proving_capability: TxProvingCapability,

    /// A list of single-proof backed transactions that were removed from the
    /// mempool because they were inputs to a merge. So they are not in the
    /// mempool because they conflict with another transaction there. When a
    /// new block comes in, however, some of these transactions may become
    /// "unconflicted" again. This list can only grow when [`Self::insert`] is
    /// called and can shrink when [`Self::update_with_block`] is called.
    merge_input_cache: MergeInputCache,
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
        tx_proving_capability: TxProvingCapability,
        tip: &Block,
    ) -> Self {
        let table = Default::default();
        let fee_densities = Default::default();
        let upgrade_priorities = Default::default();
        let max_total_size = max_total_size.0.try_into().unwrap();
        let tip_digest = tip.hash();
        let tip_mutator_set_hash = tip
            .mutator_set_accumulator_after()
            .expect("Provided block must have mutator set after")
            .hash();
        let merge_input_cache = MergeInputCache::default();

        Self {
            max_total_size,
            tx_dictionary: table,
            fee_densities,
            upgrade_priorities,
            tip_digest,
            tip_mutator_set_hash,
            tx_proving_capability,
            merge_input_cache,
        }
    }

    /// Update mempool with chain information.
    ///
    /// Returns an error if the provided block does not have a mutator set
    /// after.
    fn set_sync_labels(&mut self, tip: &Block) -> anyhow::Result<()> {
        self.tip_digest = tip.hash();
        self.tip_mutator_set_hash = tip.mutator_set_accumulator_after()?.hash();
        Ok(())
    }

    /// Check if mempool will accept a transaction for insertion.
    ///
    /// Returns true if the new transaction is either not known, or if it is
    /// known but has a higher proof quality than the one already in the
    /// mempool. Synced transactions (with up-to-date mutator sets) are
    /// considered of higher quality than unsynced transactions.
    ///
    /// Even though this function returns true, a transaction might still be
    /// rejected for insertion if the mempool is full *and* the transaction has
    /// a lower fee density that all transactions in the mempool.
    pub(crate) fn accept_transaction(
        &self,
        new_tx_txid: TransactionKernelId,
        new_tx_proof_quality: TransactionProofQuality,
        new_tx_mutator_set_hash: Digest,
    ) -> bool {
        let Some(existing_tx) = self.tx_dictionary.get(&new_tx_txid) else {
            // Transaction is not in mempool. Is it in the cache of conflicting
            // transactions?
            return !self.merge_input_cache.contains(&new_tx_txid);
        };

        match existing_tx.transaction.proof.proof_quality() {
            Ok(mempool_proof_quality) => {
                if mempool_proof_quality > new_tx_proof_quality {
                    // New tx has lower proof quality.
                    false
                } else if mempool_proof_quality == new_tx_proof_quality {
                    // New tx has same proof quality. Check if new tx
                    // represents a valid mutator set, if it does, return
                    // true as the new transaction is more likely to be
                    // included in a block when it's synced.
                    existing_tx.transaction.kernel.mutator_set_hash != self.tip_mutator_set_hash
                        && new_tx_mutator_set_hash == self.tip_mutator_set_hash
                } else {
                    // New tx has higher proof quality.
                    true
                }
            }
            Err(_) => {
                // Any proof quality is better than none.
                // This would indicate that this client has a transaction with
                // e.g. primitive witness in mempool and now the same transaction
                // with an associated proof is queried. That probably shouldn't
                // happen. Only if two nodes share the same secret key can
                // this happen, in which case, we want to accept the new
                // transaction, so we return true here.
                error!(
                    "Failed to read proof quality for tx in mempool. txid: {}",
                    new_tx_txid
                );
                true
            }
        }
    }

    /// Return the preferred single-proof backed transaction for the "update"
    /// proof upgrade. Returns a transaction that is not synced to the tip
    /// such that the caller can make the transaction synced again.
    ///
    /// Only transactions matching the filter will be returned. Unless the
    /// mempool has been deemed to have a financial interest in the transaction,
    /// in which case the filter is ignored.
    ///
    /// Favors transactions based on upgrade priority first, fee density
    /// second.
    pub(crate) fn preferred_update(
        &self,
        tx_upgrade_filter: TxUpgradeFilter,
    ) -> Option<(&TransactionKernel, &NeptuneProof, UpgradePriority)> {
        for candidate_txid in self
            .upgrade_priority_iter()
            .map(|(txid, _)| txid)
            .chain(self.fee_density_iter().map(|(txid, _)| txid))
        {
            let candidate = self.tx_dictionary.get(&candidate_txid).unwrap();
            if self.tx_is_synced(&candidate.transaction.kernel) {
                continue;
            }

            // Transactions with no inputs cannot be updated.
            if candidate.transaction.kernel.inputs.is_empty() {
                continue;
            }

            let TransactionProof::SingleProof(single_proof) = &candidate.transaction.proof else {
                continue;
            };

            if candidate.upgrade_priority.is_irrelevant()
                && !tx_upgrade_filter.matches(candidate_txid)
            {
                continue;
            }

            return Some((
                &candidate.transaction.kernel,
                single_proof,
                candidate.upgrade_priority,
            ));
        }

        None
    }

    /// Return the preferred proof collection for proof upgrading. Favors
    /// transactions based on upgrade priority first, fee density second. This
    /// means that transactions initialized by this node's wallet will always be
    /// targeted for proof-upgrading first.
    ///
    /// Only transactions matching the filter will be returned. Unless the
    /// mempool has been deemed to have a financial interest in the transaction,
    /// in which case the filter is ignored.
    ///
    /// Will only return transactions that are synced to the latest tip.
    ///
    /// Also returns the upgrade priority of this transactions, for the node
    /// operator.
    pub(crate) fn preferred_proof_collection(
        &self,
        num_proofs_threshold: usize,
        tx_upgrade_filter: TxUpgradeFilter,
    ) -> Option<(&TransactionKernel, &ProofCollection, UpgradePriority)> {
        for candidate_txid in self
            .upgrade_priority_iter()
            .map(|(txid, _)| txid)
            .chain(self.fee_density_iter().map(|(txid, _)| txid))
        {
            let candidate = self.tx_dictionary.get(&candidate_txid).unwrap();
            if !self.tx_is_synced(&candidate.transaction.kernel) {
                continue;
            }

            let TransactionProof::ProofCollection(proof_collection) = &candidate.transaction.proof
            else {
                continue;
            };

            if proof_collection.num_proofs() > num_proofs_threshold {
                continue;
            }

            if candidate.upgrade_priority.is_irrelevant()
                && !tx_upgrade_filter.matches(candidate_txid)
            {
                continue;
            }

            return Some((
                &candidate.transaction.kernel,
                proof_collection,
                candidate.upgrade_priority,
            ));
        }

        None
    }

    /// Returns the preferred single proof pair for proof upgrading through a
    /// merge. Always prefers transactions with a positive upgrade priority.
    /// Then transactions with a higher fee density. Will only ever return
    /// transactions that either
    ///   a) have a positive upgrader priority, or
    ///   b) pay a positive transaction fee.
    ///
    /// Will only return transactions that are synced to the latest tip.
    ///
    /// Returns the pair of transaction along with their sum of priorities.
    pub(crate) fn preferred_single_proof_pair(
        &self,
        tx_upgrade_filter: TxUpgradeFilter,
    ) -> Option<([(TransactionKernel, Proof); 2], UpgradePriority)> {
        let mut ret = vec![];
        let mut filter_mismatches = vec![];
        let mut priority = UpgradePriority::Irrelevant;
        for candidate_txid in self
            .upgrade_priority_iter()
            .map(|(txid, _)| txid)
            .chain(self.fee_density_iter().map(|(txid, _)| txid))
        {
            let candidate = self.tx_dictionary.get(&candidate_txid).unwrap();

            if !self.tx_is_synced(&candidate.transaction.kernel) {
                continue;
            }

            let TransactionProof::SingleProof(_) = &candidate.transaction.proof else {
                continue;
            };

            // Do not attempt to merge transactions that neither have a value to
            // us nor pay a fee.
            if candidate.upgrade_priority.is_irrelevant()
                && candidate.transaction.kernel.fee.is_zero()
            {
                continue;
            }

            // Avoid selecting same transaction twice.
            if ret.contains(&candidate_txid) {
                continue;
            }

            if candidate.upgrade_priority.is_irrelevant()
                && !tx_upgrade_filter.matches(candidate_txid)
            {
                filter_mismatches.push(candidate_txid);
                continue;
            }

            priority = priority + candidate.upgrade_priority;

            ret.push(candidate_txid);

            if ret.len() == 2 {
                break;
            }
        }

        // If only one transaction was found and one or more were avoided
        // because they did not match the filter, see if the combined
        // transaction (filter match + filter mismatch) matches the filter.
        // This way, the filter avoids double work in the merge case, and it
        // ensures that all possible mergers are performed in a "fully covering"
        // upgrade filter setup.
        if 1 == ret.len() {
            let first_candidate = ret[0];
            for second_candidate in filter_mismatches {
                if tx_upgrade_filter.matches(TransactionKernelId::combine(
                    first_candidate,
                    second_candidate,
                )) {
                    ret.push(second_candidate);
                    break;
                }
            }
        }

        let [left, right] = ret.try_into().ok()?;
        let left = &self.tx_dictionary.get(&left).unwrap().transaction;
        let right = &self.tx_dictionary.get(&right).unwrap().transaction;
        let candidates =
            [left, right].map(|t| (t.kernel.to_owned(), t.proof.to_owned().into_single_proof()));
        Some((candidates, priority))
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
        self.tx_dictionary
            .get(&transaction_id)
            .map(|x| &x.transaction)
    }

    /// get transaction from mempool, with its associated upgrade priority.
    ///
    /// Computes in O(1) from HashMap
    pub(crate) fn get_with_priority(
        &self,
        transaction_id: TransactionKernelId,
    ) -> Option<(&Transaction, UpgradePriority)> {
        self.tx_dictionary
            .get(&transaction_id)
            .map(|x| (&x.transaction, x.upgrade_priority))
    }

    /// Returns the list of transactions already in the mempool that a
    /// transaction conflicts with.
    ///
    /// Returns the empty list if there are no conflicts
    fn transaction_conflicts_with(
        &self,
        transaction: &Transaction,
    ) -> HashMap<TransactionKernelId, &Transaction> {
        // This check could be made a lot more efficient, for example with an invertible Bloom filter
        let tx_sbf_indices: HashSet<_> = transaction
            .kernel
            .inputs
            .iter()
            .map(|x| x.absolute_indices.to_array())
            .collect();

        let mut conflict_txs_in_mempool = HashMap::new();
        for (txid, tx) in &self.tx_dictionary {
            for mempool_tx_input in &tx.transaction.kernel.inputs {
                if tx_sbf_indices.contains(&mempool_tx_input.absolute_indices.to_array()) {
                    conflict_txs_in_mempool.insert(*txid, &tx.transaction);
                    break;
                }
            }
        }

        conflict_txs_in_mempool
    }

    /// Insert a transaction into the mempool. It is the caller's responsibility to validate
    /// the transaction.
    ///
    /// The caller must also ensure that the transaction does not have a timestamp
    /// in the too distant future, as such a transaction cannot be mined.
    ///
    /// Caller must specify the priority of the transaction to them.
    ///
    /// this method may return:
    ///   n events: RemoveTx,AddTx.  tx replaces a list of older txs with lower fee.
    ///   1 event:  AddTx. tx does not replace an older one.
    ///   0 events: tx not added because an older matching tx has a higher fee.
    pub(super) fn insert(
        &mut self,
        new_tx: Transaction,
        priority: UpgradePriority,
    ) -> Vec<MempoolEvent> {
        fn new_tx_has_higher_proof_quality_than_conflicts(
            new_tx: &Transaction,
            conflicts: &HashMap<TransactionKernelId, &Transaction>,
            current_msa_hash: Digest,
        ) -> bool {
            match &new_tx.proof {
                TransactionProof::Witness(witness) => {
                    // A primitive witness backed transaction *can* replace
                    // another transaction, if the other transaction is also
                    // primitive witness backed, *and* it is synced against a
                    // the current mutator set, and the previous one is not.
                    conflicts.iter().all(|(_, existing_tx)| {
                        matches!(&existing_tx.proof, TransactionProof::Witness(_))
                            && existing_tx.kernel.mutator_set_hash != current_msa_hash
                            && witness.kernel.mutator_set_hash == current_msa_hash
                    })
                }
                TransactionProof::ProofCollection(_) => {
                    // A ProofCollection backed transaction will always replace
                    // a primitive witness backed transaction, and will replace
                    // other proof collection backed transaction if the mutator
                    // set is updated, and the old transaction does not have an
                    // updated mutator set.
                    conflicts
                        .iter()
                        .any(|x| matches!(&x.1.proof, TransactionProof::Witness(_)))
                        || conflicts.iter().all(|(_, existing_tx)| {
                            matches!(&existing_tx.proof, TransactionProof::ProofCollection(_))
                                && existing_tx.kernel.mutator_set_hash != current_msa_hash
                                && new_tx.kernel.mutator_set_hash == current_msa_hash
                        })
                }
                TransactionProof::SingleProof(_) => {
                    // A SingleProof-backed transaction kicks out conflicts if
                    // a) any conflicts are not SingleProof, or
                    // b) the conflict (as there can be only one) has the same
                    //    txk-id, which indicates mutator set update, and the
                    //    new transaction has an updated mutator set hash.
                    conflicts.iter().any(|(conflicting_txkid, conflicting_tx)| {
                        !matches!(&conflicting_tx.proof, TransactionProof::SingleProof(_))
                            || *conflicting_txkid == new_tx.kernel.txid()
                                && new_tx.kernel.mutator_set_hash == current_msa_hash
                    })
                }
            }
        }

        // If transaction to be inserted conflicts with transactions already in
        // the mempool, we replace them -- but only if the new transaction has a
        // higher fee-density than the ones already in mempool, or if it has
        // a higher proof-quality, meaning that it's in a state more likely to
        // be picked up by a composer.
        // Consequently, merged transactions always replace those transactions
        // that were merged since the merged transaction is *very* likely to
        // have a higher fee density that the lowest one of the ones that were
        // merged.
        let conflicts = self.transaction_conflicts_with(&new_tx);

        // Do not insert an existing transaction again, if its an exact copy.
        let txid = new_tx.txid();
        if let Some(existing_tx) = conflicts.get(&txid) {
            if **existing_tx == new_tx {
                return vec![];
            }
        }

        // Ensure we never throw away a primitive witness if we have one. This
        // must happen before conflicting transactions are removed.
        let primitive_witness = if let TransactionProof::Witness(pw) = &new_tx.proof {
            Some(pw.clone())
        } else {
            self.tx_dictionary
                .get(&txid)
                .and_then(|tx| tx.primitive_witness.clone())
        };
        let new_tx = MempoolTransaction {
            transaction: new_tx,
            upgrade_priority: priority,
            primitive_witness,
        };

        let mut events = vec![];
        let new_tx_has_higher_proof_quality = new_tx_has_higher_proof_quality_than_conflicts(
            &new_tx.transaction,
            &conflicts,
            self.tip_mutator_set_hash,
        );
        let min_fee_of_conflicts = conflicts.values().map(|tx| tx.fee_density()).min();
        let conflicts = conflicts
            .into_iter()
            .map(|x| (x.0, x.1.proof.as_single_proof()))
            .collect_vec();
        if let Some(min_fee_of_conflicting_tx) = min_fee_of_conflicts {
            let better_fee_density = min_fee_of_conflicting_tx < new_tx.transaction.fee_density();
            let should_replace_conflict = new_tx_has_higher_proof_quality || better_fee_density;
            if should_replace_conflict {
                for (conflicting_txid, single_proof) in conflicts {
                    let e = self.remove(conflicting_txid).unwrap_or_else(|| {
                        panic!("Reported conflict {conflicting_txid} must exist")
                    });
                    let MempoolEvent::RemoveTx(removed) = &e else {
                        panic!("remove must return remove event");
                    };

                    // Conditionally store existing transaction in conflict
                    // cache.
                    if let Some(old_proof) = single_proof {
                        if new_tx.transaction.proof.is_single_proof()
                            && TransactionKernel::have_merge_relationship(
                                &new_tx.transaction.kernel,
                                removed,
                            )
                        {
                            let upgrade_priority = self
                                .upgrade_priorities
                                .get(&conflicting_txid)
                                .map(|x| *x.1)
                                .unwrap_or_default();
                            self.merge_input_cache.insert(
                                removed.to_owned(),
                                old_proof,
                                upgrade_priority,
                            );
                        }
                    }

                    events.push(e);
                }
            } else {
                // If new transaction has a lower fee density than the one previous seen,
                // ignore it. Stop execution here.
                debug!(
                    "Attempted to insert transaction into mempool but it's \
                     fee density was eclipsed by another transaction."
                );
                return events;
            }
        }

        // Insert the new transaction, if transaction with this txid already
        // existed, add the implied removal to events list.
        self.fee_densities
            .push(txid, new_tx.transaction.fee_density());
        events.push(MempoolEvent::AddTx(new_tx.transaction.kernel.clone()));
        if let Some(removed) = self.tx_dictionary.insert(txid, new_tx) {
            events.push(MempoolEvent::RemoveTx(removed.transaction.kernel));
        }

        if !priority.is_irrelevant() {
            self.upgrade_priorities.push(txid, priority);
        }

        assert_eq!(
            self.tx_dictionary.len(),
            self.fee_densities.len(),
            "mempool's table and queue length must agree prior to shrink"
        );
        assert!(
            self.upgrade_priorities.len() <= self.tx_dictionary.len(),
            "Length of upgrade priority queue may not exceed num txs"
        );

        let dropped_bc_size_restriction = self.shrink_to_max_size();
        events.extend(dropped_bc_size_restriction);

        assert_eq!(
            self.tx_dictionary.len(),
            self.fee_densities.len(),
            "mempool's table and queue length must agree after shrink"
        );
        assert!(
            self.upgrade_priorities.len() <= self.tx_dictionary.len(),
            "Length of upgrade priority queue may not exceed num txs"
        );

        MempoolEvent::normalize(events)
    }

    /// remove a transaction from the `Mempool`
    ///
    /// Does nothing if the transaction cannot be found in the mempool.
    pub(super) fn remove(&mut self, transaction_id: TransactionKernelId) -> Option<MempoolEvent> {
        self.tx_dictionary.remove(&transaction_id).map(|tx| {
            self.fee_densities.remove(&transaction_id);
            self.upgrade_priorities.remove(&transaction_id);
            debug_assert_eq!(self.tx_dictionary.len(), self.fee_densities.len());
            MempoolEvent::RemoveTx(tx.transaction.kernel)
        })
    }

    /// Update the primitive witness of a transaction already in the mempool.
    /// If transaction is not already present in the mempool, it is inserted as
    /// a primitive-witness backed transaction in order to ensure that the
    /// primitive-witness data is not lost if the same transaction is later
    /// inserted with a higher proof quality.
    ///
    /// Returns the events, which will at maximum be 1 event adding a
    /// transaction.
    pub(super) fn update_primitive_witness(
        &mut self,
        transaction_id: TransactionKernelId,
        new_primitive_witness: PrimitiveWitness,
    ) -> Vec<MempoolEvent> {
        if let Some(tx) = self.tx_dictionary.get_mut(&transaction_id) {
            tx.primitive_witness = Some(new_primitive_witness);
            vec![]
        } else {
            // All transactions where the primitive witness is known are
            // considered critical, because knowing the primitive witness
            // implies that the transaction originated from this node.
            self.insert(new_primitive_witness.into(), UpgradePriority::Critical)
        }
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
        self.merge_input_cache.clear();
        self.retain(|_| false)
    }

    /// Return the number of transactions currently stored in the Mempool.
    /// Computes in O(1)
    pub fn len(&self) -> usize {
        self.tx_dictionary.len()
    }

    /// Return the number of transaction stored in the mempool that are deemed
    /// relevant for this node.
    ///
    /// Computes in O(1)
    pub(crate) fn num_own_txs(&self) -> usize {
        self.upgrade_priorities.len()
    }

    /// check if `Mempool` is empty
    ///
    /// Computes in O(1)
    pub fn is_empty(&self) -> bool {
        self.tx_dictionary.is_empty()
    }

    /// Return a vector with copies of the transactions, in descending order by
    /// fee density. Only returns transactions that are
    /// - backed by single proofs, and
    /// - synced to the tip.
    ///
    /// Number of transactions returned can be capped by either size (measured
    /// in bytes), or by transaction count. The function guarantees that neither
    /// of the specified limits will be exceeded.
    pub(crate) fn get_transactions_for_block_composition(
        &self,
        mut remaining_storage: usize,
        max_num_txs: Option<usize>,
    ) -> Vec<Transaction> {
        let mut transactions = vec![];

        for (transaction_digest, _fee_density) in self.fee_density_iter() {
            // No more transactions can possibly be packed
            if remaining_storage == 0 || max_num_txs.is_some_and(|max| transactions.len() == max) {
                break;
            }

            if let Some(transaction_ptr) = self.get(transaction_digest) {
                // Only return transaction synced to tip
                if !self.tx_is_synced(&transaction_ptr.kernel) {
                    continue;
                }

                if !matches!(transaction_ptr.proof, TransactionProof::SingleProof(_)) {
                    continue;
                }

                let transaction_copy = transaction_ptr.to_owned();
                let transaction_size = transaction_copy.get_size();

                // Current transaction is too big
                if transaction_size > remaining_storage {
                    continue;
                }

                // Include transaction
                remaining_storage -= transaction_size;
                transactions.push(transaction_copy)
            }
        }

        transactions
    }

    /// Removes the transaction with the lowest [`FeeDensity`] from the mempool.
    /// Returns the removed value.
    ///
    /// Computes in θ(lg N)
    fn pop_min(&mut self) -> Option<(MempoolEvent, FeeDensity)> {
        if let Some((txkid, fee_density)) = self.fee_densities.pop_min() {
            if let Some(tx) = self.tx_dictionary.remove(&txkid) {
                self.upgrade_priorities.remove(&txkid);

                debug_assert_eq!(self.tx_dictionary.len(), self.fee_densities.len());

                let event = MempoolEvent::RemoveTx(tx.transaction.kernel);

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

        for (&transaction_id, _fee_density) in &self.fee_densities {
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

        debug_assert_eq!(self.tx_dictionary.len(), self.fee_densities.len());
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
    /// of a newly received block. Return a description of the transactions for
    /// which a primitive witness is present such that the caller can update
    /// their mutator set data.
    ///
    /// Fails if the provided block does not have a mutator set after.
    pub(super) fn update_with_block(
        &mut self,
        new_block: &Block,
    ) -> anyhow::Result<(Vec<MempoolEvent>, Vec<MempoolUpdateJob>)> {
        // If the mempool is empty, there is nothing to do.
        if self.is_empty() && self.merge_input_cache.is_empty() {
            self.set_sync_labels(new_block)?;
            return Ok((vec![], vec![]));
        }

        // If we discover a reorganization, we currently just clear the mempool,
        // as we don't have the ability to roll transaction removal record integrity
        // proofs back to previous blocks. It would be nice if we could handle a
        // reorganization that's at least a few blocks deep though.
        let mut events: Vec<_> = vec![];
        let previous_block_digest = new_block.header().prev_block_digest;
        if self.tip_digest != previous_block_digest {
            let removed = self.clear();
            events.extend(removed);
        }

        // The general strategy is to check whether the SWBF index set of a
        // given transaction in the mempool is disjoint from (*i.e.*, not
        // contained by) SWBF indices coming from the block transaction. If they
        // are not disjoint, then remove the transaction from the mempool, as
        // it is now a double-spending transaction.
        let block_bf_set_union: HashSet<_> = new_block
            .kernel
            .body
            .transaction_kernel
            .inputs
            .iter()
            .flat_map(|rr| rr.absolute_indices.to_array())
            .collect();
        let still_valid = |(_transaction_id, tx): LookupItem| -> bool {
            let transaction_index_sets: HashSet<_> = tx
                .kernel
                .inputs
                .iter()
                .map(|rr| rr.absolute_indices.to_array())
                .collect();

            transaction_index_sets.iter().all(|index_set| {
                index_set
                    .iter()
                    .any(|index| !block_bf_set_union.contains(index))
            })
        };

        // Remove the transactions that become invalid with this block
        {
            let removed = self.retain(still_valid);
            events.extend(removed);
        }

        // Restore transactions from blocks. Do this prior to the collection of
        // update jobs since we migth restore a transaction that we need to
        // return as an update job, in case one of our own transactions got
        // merged but the merged transaction was not picked up by the composer.
        let restored_from_cache = self
            .merge_input_cache
            .update_with_block(&block_bf_set_union);
        for elem in restored_from_cache {
            let MergeInputCacheElement {
                tx_kernel,
                single_proof,
                upgrade_priority,
            } = elem;
            let restored_tx = Transaction {
                kernel: tx_kernel,
                proof: TransactionProof::SingleProof(single_proof),
            };
            let inserted = self.insert(restored_tx, upgrade_priority);
            events.extend(inserted);
        }

        // Build a list of jobs to update critical transactions to the mutator
        // set of the new block.
        let mut update_jobs = vec![];
        let mut kick_outs = Vec::with_capacity(self.tx_dictionary.len());
        for (tx_id, tx) in &self.tx_dictionary {
            if tx.transaction.kernel.inputs.is_empty() {
                debug!("Not updating transaction since empty transactions cannot be updated.");
                kick_outs.push(*tx_id);
                continue;
            }

            let (update_job, keep_in_mempool) = match &tx.transaction.proof {
                // Proof-collection backed transaction cannot be updated
                // directly. But if the transaction was initiated locally, the
                // primitive witness will be known, and it can be updated. Also,
                // if the proof collection is first upgraded to a SingleProof,
                // and then update, it could also become synced again that way.
                // So we could consider keeping PC-backed transactions around
                // even if we don't have the primitive witness.
                TransactionProof::ProofCollection(_) => {
                    if let Some(pw) = &tx.primitive_witness {
                        let pw_update_job = PrimitiveWitnessUpdate::new(pw.to_owned());
                        let pw_update_job = MempoolUpdateJob::ProofCollection(pw_update_job);
                        (Some(pw_update_job), true)
                    } else {
                        (None, false)
                    }
                }

                // Primitive witness-backed transactions can easily be updated.
                TransactionProof::Witness(pw) => {
                    let pw_update_job = PrimitiveWitnessUpdate::new(pw.to_owned());
                    let pw_update_job = MempoolUpdateJob::PrimitiveWitness(pw_update_job);
                    (Some(pw_update_job), true)
                }

                // Single proofs can be updated. So they are kept in the
                // mempool in the expectation that someone will update them to
                // be valid under a new mutator set.
                //
                // If (the transaction was initiated locally, i.e. deemed
                // critical), *and* node can produce single-proofs, transaction
                // should be updated immediately (and be kept in mempool).
                //
                // Note: Do not check for the presence of a primitive witness.
                // This information is irrelevant for Update tasks and moreover
                // not always present for critical transactions. For instance:
                // the edge case in which the transaction was merged (the
                // primitive witness is dropped) but the merge-sibling was mined
                // (the current transaction is retrieved from cache).
                TransactionProof::SingleProof(sp) => {
                    if self.tx_proving_capability == TxProvingCapability::SingleProof
                        && tx.upgrade_priority == UpgradePriority::Critical
                    {
                        // Node initiated transaction and can update.
                        let update_sp = MempoolUpdateJob::SingleProof {
                            old_kernel: tx.transaction.kernel.clone(),
                            old_single_proof: sp.to_owned(),
                        };

                        (Some(update_sp), true)
                    } else {
                        (None, true)
                    }
                }
            };

            if let Some(update_job) = update_job {
                update_jobs.push(update_job);
            }

            if !keep_in_mempool {
                kick_outs.push(*tx_id);
                if !tx.upgrade_priority.is_irrelevant() {
                    warn!("Unable to update own transaction to new mutator set. You may need to create this transaction again. Removing {tx_id} from mempool.");
                }
            }
        }

        {
            let removed = self.retain(|(tx_id, _)| !kick_outs.contains(&tx_id));
            events.extend(removed);
        }

        {
            let removed = self.shrink_to_max_size();
            events.extend(removed);
        }

        // Update the sync-label to keep track of reorganizations
        self.set_sync_labels(new_block)?;

        let events = MempoolEvent::normalize(events);

        Ok((events, update_jobs))
    }

    /// Shrink the memory pool to the value of its `max_size` field.
    /// Likely computes in O(n).
    ///
    /// Returns events for removed transactions.
    fn shrink_to_max_size(&mut self) -> Vec<MempoolEvent> {
        // Repeately remove the least valuable transaction
        let mut removal_events: Vec<_> = vec![];

        // You have to dereference before calling `get_size` here, otherwise
        // you get the size of the pointer.
        while (*self).get_size() > self.max_total_size {
            const MAX_SIZE_OF_CACHE_FACTOR: usize = 3;
            let dominated_by_cache =
                self.merge_input_cache.get_size() * MAX_SIZE_OF_CACHE_FACTOR > (*self).get_size();
            if dominated_by_cache {
                assert!(
                    self.merge_input_cache.pop_oldest().is_some(),
                    "Dominated by cache but cannot remove element"
                );
            } else {
                let Some((removed, _)) = self.pop_min() else {
                    error!("Mempool is empty but exceeds max allowed size");
                    return removal_events;
                };

                removal_events.push(removed);
            }
        }

        self.shrink_to_fit();

        removal_events
    }

    /// Shrinks internal data structures as much as possible.
    /// Computes in O(n) (Likely)
    fn shrink_to_fit(&mut self) {
        self.fee_densities.shrink_to_fit();
        self.tx_dictionary.shrink_to_fit();
        self.upgrade_priorities.shrink_to_fit();
    }

    /// Return whether the transaction is synced to the tip block.
    fn tx_is_synced(&self, transaction_kernel: &TransactionKernel) -> bool {
        self.tip_mutator_set_hash == transaction_kernel.mutator_set_hash
    }

    /// Produce a sorted iterator over a snapshot of the Double-Ended Priority Queue.
    ///
    /// # Example
    ///
    /// ```
    /// use bytesize::ByteSize;
    /// use neptune_cash::application::config::network::Network;
    /// use neptune_cash::protocol::consensus::block::Block;
    /// use neptune_cash::state::mempool::Mempool;
    /// use neptune_cash::state::transaction::tx_proving_capability::TxProvingCapability;
    ///
    /// let network = Network::Main;
    /// let genesis_block = Block::genesis(network);
    /// let mempool = Mempool::new(
    ///     ByteSize::gb(1),
    ///     TxProvingCapability::ProofCollection,
    ///     &genesis_block
    /// );
    /// // insert transactions here.
    /// let mut most_valuable_transactions = vec![];
    /// for (transaction_id, fee_density) in mempool.fee_density_iter() {
    ///    let t = mempool.get(transaction_id);
    ///    most_valuable_transactions.push(t);
    /// }
    /// ```
    ///
    /// Yields the `transaction_digest` in order of descending `fee_density`, since
    /// users (miner or transaction merger) will likely only care about the most valuable transactions
    /// Computes in O(N lg N)
    pub fn fee_density_iter(
        &self,
    ) -> impl std::iter::DoubleEndedIterator<Item = (TransactionKernelId, FeeDensity)> {
        let dpq_clone = self.fee_densities.clone();
        dpq_clone.into_sorted_iter().rev()
    }

    /// Yields the transaction kernel IDs in order of descending upgrade
    /// priority.
    fn upgrade_priority_iter(
        &self,
    ) -> SingleEndedIterator<TransactionKernelId, UpgradePriority, RandomState> {
        let dpq_clone = self.upgrade_priorities.clone();
        dpq_clone.into_sorted_iter()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use num_bigint::BigInt;
    use num_traits::One;
    use num_traits::Zero;
    use proptest::prelude::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tracing_test::traced_test;

    use super::*;
    use crate::application::config::cli_args;
    use crate::application::config::network::Network;
    use crate::application::loops::main_loop::proof_upgrader::PrimitiveWitnessToProofCollection;
    use crate::application::loops::main_loop::proof_upgrader::UpdateMutatorSetDataJob;
    use crate::application::loops::main_loop::upgrade_incentive::UpgradeIncentive;
    use crate::application::loops::mine_loop::tests::make_coinbase_transaction_from_state;
    use crate::application::triton_vm_job_queue::TritonVmJobPriority;
    use crate::application::triton_vm_job_queue::TritonVmJobQueue;
    use crate::protocol::consensus::block::block_height::BlockHeight;
    use crate::protocol::consensus::block::block_transaction::BlockTransaction;
    use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
    use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::protocol::consensus::transaction::validity::single_proof::produce_single_proof;
    use crate::protocol::consensus::transaction::Transaction;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
    use crate::protocol::shared::SIZE_20MB_IN_BYTES;
    use crate::state::transaction::tx_creation_config::TxCreationConfig;
    use crate::state::transaction::tx_proving_capability::TxProvingCapability;
    use crate::state::wallet::expected_utxo::UtxoNotifier;
    use crate::state::wallet::transaction_output::TxOutput;
    use crate::state::wallet::transaction_output::TxOutputList;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::state::GlobalStateLock;
    use crate::tests::shared::blocks::invalid_empty_block_with_timestamp;
    use crate::tests::shared::blocks::make_mock_block;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared::mock_tx::make_plenty_mock_transaction_supported_by_invalid_single_proofs;
    use crate::tests::shared::mock_tx::mock_transactions_with_sized_single_proof;
    use crate::tests::shared::mock_tx::testrunning::make_mock_txs_with_primitive_witness_with_timestamp;
    use crate::tests::shared::mock_tx::testrunning::make_plenty_mock_transaction_supported_by_primitive_witness;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

    impl Mempool {
        /// get mutable reference to a transaction from mempool
        ///
        /// Computes in O(1) from HashMap
        fn get_mut(&mut self, transaction_id: TransactionKernelId) -> Option<&mut Transaction> {
            self.tx_dictionary
                .get_mut(&transaction_id)
                .map(|x| &mut x.transaction)
        }
    }

    #[apply(shared_tokio_runtime)]
    pub async fn insert_then_get_then_remove_then_get() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::ProofCollection,
            &genesis_block,
        );

        let txs = make_plenty_mock_transaction_supported_by_primitive_witness(2);
        let transaction_digests = txs.iter().map(|tx| tx.kernel.txid()).collect_vec();
        assert!(!mempool.contains(transaction_digests[0]));
        assert!(!mempool.contains(transaction_digests[1]));
        mempool.insert(txs[0].clone(), UpgradePriority::Irrelevant);
        assert!(mempool.contains(transaction_digests[0]));
        assert!(!mempool.contains(transaction_digests[1]));

        let transaction_get_option = mempool.get(transaction_digests[0]);
        assert_eq!(Some(&txs[0]), transaction_get_option);
        assert!(mempool.contains(transaction_digests[0]));
        assert!(!mempool.contains(transaction_digests[1]));

        let remove_event = mempool.remove(transaction_digests[0]);
        assert_eq!(
            Some(MempoolEvent::RemoveTx(txs[0].kernel.clone())),
            remove_event
        );
        for tx_id in &transaction_digests {
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

    /// Create a mempool with n transactions, all "synced" to the provided
    /// block.
    ///
    /// All transactions inserted into the mempool this way are invalid and
    /// cannot be included in any block.
    fn setup_mock_mempool(transactions_count: usize, sync_block: &Block) -> Mempool {
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::ProofCollection,
            sync_block,
        );
        let txs =
            make_plenty_mock_transaction_supported_by_invalid_single_proofs(transactions_count);
        let mutator_set_hash = sync_block.mutator_set_accumulator_after().unwrap().hash();
        for mut tx in txs {
            tx.kernel = TransactionKernelModifier::default()
                .mutator_set_hash(mutator_set_hash)
                .modify(tx.kernel);
            mempool.insert(tx, UpgradePriority::Irrelevant);
        }

        assert_eq!(transactions_count, mempool.len());

        mempool
    }

    /// Mocking what the caller might do with the update jobs.
    ///
    /// Assumes that all transactions in the mempool are valid.
    async fn mocked_mempool_update_handler(
        update_jobs: Vec<MempoolUpdateJob>,
        mempool: &mut Mempool,
        new_block: &Block,
        old_mutator_set: &MutatorSetAccumulator,
        network: Network,
    ) {
        let mut updated_txs = vec![];
        let mutator_set_update = new_block.mutator_set_update().unwrap();
        for job in update_jobs {
            match job {
                MempoolUpdateJob::PrimitiveWitness(primitive_witness_update) => {
                    let new_pw = primitive_witness_update
                        .old_primitive_witness
                        .update_with_new_ms_data(mutator_set_update.clone());
                    updated_txs.push((new_pw.clone().into(), Some(new_pw)))
                }
                MempoolUpdateJob::ProofCollection(primitive_witness_update) => {
                    let new_pw = primitive_witness_update
                        .old_primitive_witness
                        .update_with_new_ms_data(mutator_set_update.clone());
                    let pc_job = PrimitiveWitnessToProofCollection {
                        primitive_witness: new_pw.clone(),
                    };
                    let upgrade_result = pc_job
                        .upgrade(
                            TritonVmJobQueue::get_instance(),
                            &TritonVmProofJobOptions::default(),
                        )
                        .await
                        .unwrap();
                    updated_txs.push((upgrade_result, Some(new_pw)));
                }
                MempoolUpdateJob::SingleProof {
                    old_kernel,
                    old_single_proof,
                } => {
                    let consensus_rule_set =
                        ConsensusRuleSet::infer_from(network, new_block.header().height);
                    let upgrade_result = UpdateMutatorSetDataJob::new(
                        old_kernel,
                        old_single_proof,
                        old_mutator_set.clone(),
                        mutator_set_update.clone(),
                        UpgradeIncentive::Critical,
                        consensus_rule_set,
                    )
                    .upgrade(
                        TritonVmJobQueue::get_instance(),
                        TritonVmProofJobOptions::default(),
                    )
                    .await
                    .unwrap();
                    updated_txs.push((upgrade_result, None));
                }
            }
        }

        for (new_tx, new_pw) in updated_txs {
            let txid = new_tx.kernel.txid();
            let tx = mempool.get_mut(txid).unwrap();
            *tx = new_tx.clone();
            if let Some(new_pw) = new_pw {
                mempool.update_primitive_witness(txid, new_pw);
            }
        }
    }

    /// Update all single-proof backed transactions in the mempool.
    async fn update_all_sp_txs(
        mempool: &mut Mempool,
        previous_block: &Block,
        new_block: &Block,
        network: Network,
    ) {
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, new_block.header().height);
        let old_mutator_set = previous_block.mutator_set_accumulator_after().unwrap();
        let mutator_set_update = new_block.mutator_set_update().unwrap();

        while let Some((old_kernel, old_single_proof, upgrade_priority)) =
            mempool.preferred_update(TxUpgradeFilter::match_all())
        {
            let job = UpdateMutatorSetDataJob::new(
                old_kernel.to_owned(),
                old_single_proof.to_owned(),
                old_mutator_set.clone(),
                mutator_set_update.clone(),
                upgrade_priority.incentive_given_gobble_potential(NativeCurrencyAmount::zero()),
                consensus_rule_set,
            );
            let new_tx = job
                .upgrade(
                    TritonVmJobQueue::get_instance(),
                    TritonVmProofJobOptions::default(),
                )
                .await
                .unwrap();
            mempool.insert(new_tx, upgrade_priority);
        }
    }

    /// Returns three transactions: Two transactions that are input to the
    /// transaction-merge function, and the resulting merged transaction. Also
    /// returns the mutator set these transactions are synced against.
    async fn merge_tx_triplet(
        consensus_rule_set: ConsensusRuleSet,
    ) -> (
        ((Transaction, Transaction), Transaction),
        MutatorSetAccumulator,
    ) {
        let mut test_runner = TestRunner::deterministic();
        let [left, right] =
            PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets([(2, 2, 2), (2, 2, 2)])
                .new_tree(&mut test_runner)
                .unwrap()
                .current();

        let mutator_set = left.mutator_set_accumulator.clone();
        let left_single_proof = produce_single_proof(
            &left,
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
            consensus_rule_set,
        )
        .await
        .unwrap();
        let right_single_proof = produce_single_proof(
            &right,
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
            consensus_rule_set,
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
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
            consensus_rule_set,
        )
        .await
        .unwrap();

        (((left, right), merged), mutator_set)
    }

    /// Return a tree of transactions, where the parents are defined as the
    /// merger of the children. All three layers are returned.
    ///
    ///       final_tx
    ///      /      \
    ///   left      right
    ///   /  \      /  \
    /// tx0  tx1  tx0  tx1
    async fn nested_mergers(
        consensus_rule_set: ConsensusRuleSet,
    ) -> (
        [Transaction; 4],
        [Transaction; 2],
        Transaction,
        MutatorSetAccumulator,
    ) {
        let mut test_runner = TestRunner::deterministic();
        let txs: [PrimitiveWitness; 4] =
            PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets([
                (2, 2, 2),
                (3, 3, 3),
                (4, 4, 4),
                (5, 5, 5),
            ])
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

        let mutator_set = txs[0].mutator_set_accumulator.clone();
        let mut single_proofs = vec![];
        for tx in &txs {
            single_proofs.push(
                produce_single_proof(
                    tx,
                    TritonVmJobQueue::get_instance(),
                    TritonVmJobPriority::default().into(),
                    consensus_rule_set,
                )
                .await
                .unwrap(),
            )
        }

        let txs: [Transaction; 4] = txs
            .into_iter()
            .zip_eq(single_proofs)
            .map(|(pw, sp)| Transaction {
                kernel: pw.kernel,
                proof: TransactionProof::SingleProof(sp),
            })
            .collect_vec()
            .try_into()
            .unwrap();

        let shuffle_seed = arb::<[u8; 32]>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let left = Transaction::merge_with(
            txs[0].clone(),
            txs[1].clone(),
            shuffle_seed,
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
            consensus_rule_set,
        )
        .await
        .unwrap();
        let right = Transaction::merge_with(
            txs[2].clone(),
            txs[3].clone(),
            shuffle_seed,
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
            consensus_rule_set,
        )
        .await
        .unwrap();
        let final_tx = Transaction::merge_with(
            left.clone(),
            right.clone(),
            shuffle_seed,
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
            consensus_rule_set,
        )
        .await
        .unwrap();

        (txs, [left, right], final_tx, mutator_set)
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn get_densest_transactions_no_tx_cap() {
        // Verify that transactions are returned ordered by fee density, with highest fee density first
        let num_txs = 10;
        let network = Network::Main;
        let sync_block = Block::genesis(network);
        let mempool = setup_mock_mempool(num_txs, &sync_block);

        let max_fee_density: FeeDensity = FeeDensity::new(BigInt::from(u128::MAX), BigInt::from(1));
        let mut prev_fee_density = max_fee_density;
        for curr_transaction in
            mempool.get_transactions_for_block_composition(SIZE_20MB_IN_BYTES, None)
        {
            let curr_fee_density = curr_transaction.fee_density();
            assert!(curr_fee_density <= prev_fee_density);
            prev_fee_density = curr_fee_density;
        }

        assert!(!mempool.is_empty())
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn get_densest_transactions_with_tx_cap() {
        // Verify that transactions are returned ordered by fee density, with
        // highest fee density first, and that the transaction cap is respected.
        let num_txs_in_mempool = 12;
        let network = Network::Main;
        let sync_block = Block::genesis(network);
        let mempool = setup_mock_mempool(num_txs_in_mempool, &sync_block);

        for num_mergers in 0..=num_txs_in_mempool {
            let returned_transactions = mempool
                .get_transactions_for_block_composition(SIZE_20MB_IN_BYTES, Some(num_mergers));
            assert_eq!(num_mergers, returned_transactions.len());

            let max_fee_density: FeeDensity =
                FeeDensity::new(BigInt::from(u128::MAX), BigInt::from(1));
            let mut prev_fee_density = max_fee_density;
            for curr_transaction in returned_transactions {
                let curr_fee_density = curr_transaction.fee_density();
                assert!(curr_fee_density <= prev_fee_density);
                prev_fee_density = curr_fee_density;
            }
        }

        assert!(
            !mempool.is_empty(),
            "Getting transactions for composition may not empty mempool."
        )
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn most_dense_proof_collection_test() {
        let network = Network::Main;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, BlockHeight::genesis());
        let sync_block = Block::genesis(network);
        let num_txs = 0;
        let mut mempool = setup_mock_mempool(num_txs, &sync_block);
        let genesis_block = Block::genesis(network);
        let bob_wallet_secret = WalletEntropy::devnet_wallet();
        let bob_spending_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
        let bob = mock_genesis_global_state(
            2,
            bob_wallet_secret.clone(),
            cli_args::Args::default_with_network(network),
        )
        .await;
        let in_seven_months = genesis_block.kernel.header.timestamp + Timestamp::months(7);
        let high_fee = NativeCurrencyAmount::coins(15);
        let config = TxCreationConfig::default()
            .recover_change_on_chain(bob_spending_key.into())
            .with_prover_capability(TxProvingCapability::ProofCollection);
        let tx_by_bob = bob
            .api()
            .tx_initiator_internal()
            .create_transaction(
                Vec::<TxOutput>::new().into(),
                high_fee,
                in_seven_months,
                config,
                consensus_rule_set,
            )
            .await
            .unwrap()
            .transaction;

        // No candidate when mempool is empty
        assert!(
            mempool
                .preferred_proof_collection(bob.cli.max_num_proofs, TxUpgradeFilter::match_all())
                .is_none(),
            "No proof collection when mempool is empty"
        );

        let tx_by_bob_txid = tx_by_bob.kernel.txid();
        mempool.insert(tx_by_bob.into(), UpgradePriority::Irrelevant);
        assert_eq!(
            mempool
                .preferred_proof_collection(bob.cli.max_num_proofs, TxUpgradeFilter::match_all())
                .unwrap()
                .0
                .txid(),
            tx_by_bob_txid
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn get_sorted_iter() {
        // Verify that the function `get_sorted_iter` returns transactions sorted by fee density
        let network = Network::Main;
        let sync_block = Block::genesis(network);
        let num_txs = 10;
        let mempool = setup_mock_mempool(num_txs, &sync_block);

        let max_fee_density: FeeDensity = FeeDensity::new(BigInt::from(u128::MAX), BigInt::from(1));
        let mut prev_fee_density = max_fee_density;
        for (_transaction_id, curr_fee_density) in mempool.fee_density_iter() {
            assert!(curr_fee_density <= prev_fee_density);
            prev_fee_density = curr_fee_density;
        }

        assert!(!mempool.is_empty())
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn max_num_transactions_is_respected() {
        let network = Network::Main;
        let sync_block = Block::genesis(network);
        let num_txs = 12;
        let mempool = setup_mock_mempool(num_txs, &sync_block);

        for i in 0..num_txs {
            assert_eq!(
                i,
                mempool
                    .get_transactions_for_block_composition(SIZE_20MB_IN_BYTES, Some(i))
                    .len()
            );
        }
    }

    #[traced_test]
    #[test]
    fn only_txs_with_up_to_date_mutator_set_hashes_are_returned_for_block_inclusion() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let mutator_set_hash = genesis_block
            .mutator_set_accumulator_after()
            .unwrap()
            .hash();

        for i in 0..5 {
            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::ProofCollection,
                &genesis_block,
            );
            let mut txs = make_plenty_mock_transaction_supported_by_invalid_single_proofs(i);

            for tx in txs.clone() {
                mempool.insert(tx, UpgradePriority::Irrelevant);
            }

            let max_total_tx_size = 1_000_000_000;
            let txs_returned =
                mempool.get_transactions_for_block_composition(max_total_tx_size, None);
            assert_eq!(
                0,
                txs_returned.len(),
                "Must return 0/{i} transaction when mutator set hashes don't match. Got {}/{i}",
                txs_returned.len()
            );

            mempool.clear();
            for tx in &mut txs {
                tx.kernel = TransactionKernelModifier::default()
                    .mutator_set_hash(mutator_set_hash)
                    .modify(tx.kernel.clone());
                mempool.insert(tx.to_owned(), UpgradePriority::Irrelevant);
            }
            assert_eq!(
                i,
                mempool
                    .get_transactions_for_block_composition(max_total_tx_size, None)
                    .len(),
                "Must return {i}/{i} transaction when mutator set hashes do match"
            );
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn prune_stale_transactions() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::ProofCollection,
            &genesis_block,
        );
        assert!(
            mempool.is_empty(),
            "Mempool must be empty after initialization"
        );

        let now = Timestamp::now();
        let eight_days_ago = now - Timestamp::days(8);
        let old_txs = make_mock_txs_with_primitive_witness_with_timestamp(6, eight_days_ago);

        for tx in old_txs {
            mempool.insert(tx, UpgradePriority::Irrelevant);
        }

        let new_txs = make_mock_txs_with_primitive_witness_with_timestamp(5, now);

        for tx in new_txs {
            mempool.insert(tx, UpgradePriority::Irrelevant);
        }

        assert_eq!(mempool.len(), 11);
        mempool.prune_stale_transactions();
        assert_eq!(mempool.len(), 5);
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn remove_transactions_with_block_test() {
        // Check that the mempool removes transactions that were incorporated or
        // made unconfirmable by the new block.

        // This test makes valid transaction proofs but not valid block proofs.
        // What is being tested here is the correct mempool update.

        // Bob is premine receiver, Alice is not. The mempool is that of a
        // transaction-proof upgrader such that single-proof backed transactions
        // survive across block updates.
        let mut rng: StdRng = StdRng::seed_from_u64(0x03ce19960c467f90u64);
        let network = Network::Main;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, BlockHeight::genesis());
        let bob_wallet_secret = WalletEntropy::devnet_wallet();
        let bob_spending_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
        let cli_args = cli_args::Args {
            guesser_fraction: 0.0,
            network,
            ..Default::default()
        };
        let mut bob = mock_genesis_global_state(2, bob_wallet_secret, cli_args.clone()).await;

        let bob_address = bob_spending_key.to_address();

        let alice_wallet = WalletEntropy::new_pseudorandom(rng.random());
        let alice_key = alice_wallet.nth_generation_spending_key_for_tests(0);
        let alice_address = alice_key.to_address();
        let mut alice = mock_genesis_global_state(2, alice_wallet, cli_args.clone()).await;

        // Ensure that both wallets have a non-zero balance by letting Alice
        // mine a block.
        let genesis_block = Block::genesis(network);
        let (block_1, expected_1) =
            make_mock_block(&genesis_block, None, alice_key, rng.random(), network).await;

        // Update both states with block 1
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_1)
            .await;
        alice.set_new_tip(block_1.clone()).await.unwrap();
        bob.set_new_tip(block_1.clone()).await.unwrap();

        // Create a transaction that's valid to be included in block 2
        let mut utxos_from_bob = TxOutputList::from(Vec::<TxOutput>::new());
        for i in 0..4 {
            let amount: NativeCurrencyAmount = NativeCurrencyAmount::coins(i);
            utxos_from_bob.push(TxOutput::onchain_native_currency(
                amount,
                rng.random(),
                bob_address.into(),
                true,
            ));
        }

        let now = genesis_block.kernel.header.timestamp;
        let in_seven_months = now + Timestamp::months(7);
        let in_eight_months = now + Timestamp::months(8);
        let config_bob = TxCreationConfig::default()
            .recover_change_on_chain(bob_spending_key.into())
            .with_prover_capability(TxProvingCapability::SingleProof);
        let artifacts_bob = bob
            .api()
            .tx_initiator_internal()
            .create_transaction(
                utxos_from_bob.clone(),
                NativeCurrencyAmount::coins(1),
                in_seven_months,
                config_bob,
                consensus_rule_set,
            )
            .await
            .unwrap();
        let tx_by_bob: Transaction = artifacts_bob.transaction.into();

        // inform wallet of any expected utxos from this tx.
        let expected_utxos = bob.lock_guard().await.wallet_state.extract_expected_utxos(
            utxos_from_bob
                .concat_with(Vec::from(artifacts_bob.details.tx_outputs.clone()))
                .iter(),
            UtxoNotifier::Myself,
        );
        bob.lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_utxos)
            .await;

        // Add this transaction to a mempool
        let mut mempool = Mempool::new(ByteSize::gb(1), TxProvingCapability::SingleProof, &block_1);
        mempool.insert(tx_by_bob.clone(), UpgradePriority::Irrelevant);

        // Create another transaction that's valid to be included in block 2, but isn't actually
        // included by the miner. This transaction is inserted into the mempool, but since it's
        // not included in block 2 it must still be in the mempool after the mempool has been
        // updated with block 2. Also: The transaction must be valid after block 2 as the mempool
        // manager must keep mutator set data updated.
        let send_amount = NativeCurrencyAmount::coins(30);
        let utxos_from_alice = vec![TxOutput::onchain_native_currency(
            send_amount,
            rng.random(),
            alice_address.into(),
            true,
        )];
        let config_alice = TxCreationConfig::default()
            .recover_change_off_chain(alice_key.into())
            .with_prover_capability(TxProvingCapability::SingleProof);
        let tx_from_alice_original = alice
            .api()
            .tx_initiator_internal()
            .create_transaction(
                utxos_from_alice.into(),
                NativeCurrencyAmount::coins(1),
                in_seven_months,
                config_alice,
                consensus_rule_set,
            )
            .await
            .unwrap()
            .transaction;
        mempool.insert(tx_from_alice_original.into(), UpgradePriority::Critical);

        {
            // Verify that `most_dense_single_proof_pair` returns expected value
            // now that two single proofs are in the mempool.
            let densest_txs = mempool.fee_density_iter().map(|x| x.0).collect_vec();
            assert_eq!(
                densest_txs,
                mempool
                    .preferred_single_proof_pair(TxUpgradeFilter::match_all())
                    .unwrap()
                    .0
                    .map(|x| x.0.txid())
                    .to_vec()
            );
        }

        // Create next block which includes Bob's, but not Alice's, transaction.
        let (coinbase_transaction, _expected_utxo) = make_coinbase_transaction_from_state(
            &bob.global_state_lock
                .lock_guard()
                .await
                .chain
                .light_state()
                .clone(),
            &bob,
            in_eight_months,
            TritonVmJobPriority::Normal.into(),
        )
        .await
        .unwrap();
        let block_transaction = BlockTransaction::merge(
            coinbase_transaction.into(),
            tx_by_bob,
            Default::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
            consensus_rule_set,
        )
        .await
        .unwrap();
        let block_2 = Block::block_template_invalid_proof(
            &block_1,
            block_transaction,
            in_eight_months,
            None,
            network,
        );

        // Update the mempool with block 2 and verify that the mempool now only contains one tx
        assert_eq!(2, mempool.len());
        let _ = mempool.update_with_block(&block_2);
        assert_eq!(1, mempool.len());

        update_all_sp_txs(&mut mempool, &block_1, &block_2, network).await;
        assert_eq!(1, mempool.len());

        // Create a new block to verify that the non-mined transaction contains
        // updated and valid-again mutator set data
        let block2_msa = block_2.mutator_set_accumulator_after().unwrap();
        let mut tx_by_alice_updated: Transaction =
            mempool.get_transactions_for_block_composition(usize::MAX, None)[0].clone();
        assert!(
            tx_by_alice_updated.is_confirmable_relative_to(&block2_msa),
            "Block with tx with updated mutator set data must be confirmable wrt. block_2"
        );

        alice.set_new_tip(block_2.clone()).await.unwrap();
        bob.set_new_tip(block_2.clone()).await.unwrap();

        // Mine 2 blocks without including the transaction but while still keeping the
        // mempool updated. After these 2 blocks are mined, the transaction must still be
        // valid.
        let mut previous_block = block_2;
        for _ in 0..2 {
            let (next_block, _) =
                make_mock_block(&previous_block, None, alice_key, rng.random(), network).await;
            alice.set_new_tip(next_block.clone()).await.unwrap();
            bob.set_new_tip(next_block.clone()).await.unwrap();
            let _ = mempool.update_with_block(&next_block);
            update_all_sp_txs(&mut mempool, &previous_block, &next_block, network).await;
            previous_block = next_block;
        }

        tx_by_alice_updated =
            mempool.get_transactions_for_block_composition(usize::MAX, None)[0].clone();
        let block_5_timestamp = previous_block.header().timestamp + Timestamp::hours(1);
        let (cbtx, _eutxo) = make_coinbase_transaction_from_state(
            &alice
                .global_state_lock
                .lock_guard()
                .await
                .chain
                .light_state()
                .clone(),
            &alice,
            block_5_timestamp,
            TritonVmJobPriority::Normal.into(),
        )
        .await
        .unwrap();
        let block_tx_5 = BlockTransaction::merge(
            cbtx.into(),
            tx_by_alice_updated,
            Default::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
            consensus_rule_set,
        )
        .await
        .unwrap();
        let block_5 = Block::block_template_invalid_proof(
            &previous_block,
            block_tx_5,
            block_5_timestamp,
            None,
            network,
        );
        assert_eq!(Into::<BlockHeight>::into(5), block_5.kernel.header.height);

        let _ = mempool.update_with_block(&block_5);

        assert!(
            mempool.is_empty(),
            "Mempool must be empty after 2nd tx was mined"
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn merged_tx_removes_merge_inputs_but_keeps_them_in_cache() {
        // Verify that a merged transaction replaces the two transactions that
        // are the input into the merge.
        let network = Network::Main;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, BlockHeight::genesis());
        let genesis_block = Block::genesis(network);
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::SingleProof,
            &genesis_block,
        );

        let (((left, right), merged), _) = merge_tx_triplet(consensus_rule_set).await;
        mempool.insert(left.clone(), UpgradePriority::Irrelevant);
        mempool.insert(right.clone(), UpgradePriority::Irrelevant);
        assert_eq!(2, mempool.len());

        // mock that tip's mutator set hash matches that of transactions
        let tx_mutator_set_hash = merged.kernel.mutator_set_hash;
        mempool.tip_mutator_set_hash = tx_mutator_set_hash;

        // Verify that `most_dense_single_proof_pair` returns expected value
        // now that two single proofs are in the mempool.
        let densest_txs = mempool.fee_density_iter().map(|x| x.0).collect_vec();
        assert_eq!(
            densest_txs,
            mempool
                .preferred_single_proof_pair(TxUpgradeFilter::match_all())
                .unwrap()
                .0
                .map(|x| x.0.txid())
                .to_vec()
        );

        mempool.insert(merged.clone(), UpgradePriority::Irrelevant);
        assert_eq!(1, mempool.len());
        assert_eq!(&merged, mempool.get(merged.kernel.txid()).unwrap());

        assert!(mempool
            .preferred_single_proof_pair(TxUpgradeFilter::match_all())
            .is_none());

        assert_eq!(
            2,
            mempool.merge_input_cache.len(),
            "Merge input cache must contain two entries after the merger of the\
             two transactions in mempool was inserted."
        );
        assert!(
            !mempool.accept_transaction(
                left.txid(),
                left.proof.proof_quality().unwrap(),
                tx_mutator_set_hash
            ),
            "may not accept transaction as all have been inserted"
        );
        assert!(
            !mempool.accept_transaction(
                right.txid(),
                right.proof.proof_quality().unwrap(),
                tx_mutator_set_hash
            ),
            "may not accept transaction as all have been inserted"
        );
        assert!(
            !mempool.accept_transaction(
                merged.txid(),
                merged.proof.proof_quality().unwrap(),
                tx_mutator_set_hash
            ),
            "may not accept transaction as all have been inserted"
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn mempool_insertion_is_stable_on_mergers() {
        // Ensure that the mempool state does not change once all
        // transactions in a merge tree has been seen by the mempool.
        let consensus_rule_set = ConsensusRuleSet::Reboot;
        let network = Network::Main;
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::SingleProof,
            &Block::genesis(network),
        );
        let (bottom, middle, final_tx, _) = nested_mergers(consensus_rule_set).await;
        let tx_msa_hash = final_tx.kernel.mutator_set_hash;

        for tx in bottom.clone() {
            assert!(
                mempool.accept_transaction(
                    tx.txid(),
                    tx.proof.proof_quality().unwrap(),
                    tx_msa_hash
                ),
                "must accept transaction as it hasn't been inserted yet"
            );
            mempool.insert(tx, UpgradePriority::Irrelevant);
        }
        for tx in middle.clone() {
            assert!(
                mempool.accept_transaction(
                    tx.txid(),
                    tx.proof.proof_quality().unwrap(),
                    tx_msa_hash
                ),
                "must accept transaction as it hasn't been inserted yet"
            );
            mempool.insert(tx, UpgradePriority::Irrelevant);
        }

        let final_txid = final_tx.txid();
        assert!(
            mempool.accept_transaction(
                final_tx.txid(),
                final_tx.proof.proof_quality().unwrap(),
                tx_msa_hash
            ),
            "must accept transaction as it hasn't been inserted yet"
        );
        mempool.insert(final_tx.clone(), UpgradePriority::Irrelevant);
        assert!(mempool.contains(final_txid));
        assert_eq!(1, mempool.len());

        // Insert all transactions again and verify that nothing happens
        for tx in bottom.clone() {
            assert!(
                !mempool.accept_transaction(
                    tx.txid(),
                    tx.proof.proof_quality().unwrap(),
                    tx_msa_hash
                ),
                "may not accept transaction as all have already been inserted"
            );
            let events = mempool.insert(tx, UpgradePriority::Irrelevant);
            assert_eq!(0, events.len());
            assert!(mempool.contains(final_txid));
            assert_eq!(1, mempool.len());
        }
        for tx in middle.clone() {
            assert!(
                !mempool.accept_transaction(
                    tx.txid(),
                    tx.proof.proof_quality().unwrap(),
                    tx_msa_hash
                ),
                "may not accept transaction as all have already been inserted"
            );
            let events = mempool.insert(tx.clone(), UpgradePriority::Irrelevant);
            assert_eq!(0, events.len());
            assert!(mempool.contains(final_txid));
            assert_eq!(1, mempool.len());
        }

        assert!(
            !mempool.accept_transaction(
                final_tx.txid(),
                final_tx.proof.proof_quality().unwrap(),
                tx_msa_hash
            ),
            "may not accept transaction as all have already been inserted"
        );
        let events = mempool.insert(final_tx, UpgradePriority::Irrelevant);
        assert_eq!(0, events.len());
        assert!(mempool.contains(final_txid));
        assert_eq!(1, mempool.len());
    }

    #[apply(shared_tokio_runtime)]
    async fn reorganization_clears_mempool_and_merge_input_cache() {
        let network = Network::Main;
        let genesis = Block::genesis(network);
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, BlockHeight::genesis());

        let block_1a = invalid_empty_block_with_timestamp(
            &genesis,
            network.launch_date() + Timestamp::hours(1),
            network,
        );
        let block_1b = invalid_empty_block_with_timestamp(
            &genesis,
            network.launch_date() + Timestamp::hours(1),
            network,
        );
        let mut mempool =
            Mempool::new(ByteSize::gb(1), TxProvingCapability::SingleProof, &block_1a);
        let (((a, b), c), _) = merge_tx_triplet(consensus_rule_set).await;
        mempool.insert(a.clone(), UpgradePriority::Irrelevant);
        mempool.insert(b.clone(), UpgradePriority::Irrelevant);
        mempool.insert(c.clone(), UpgradePriority::Irrelevant);

        assert!(
            !mempool.is_empty(),
            "Test assumption: Not empty prior to reorganization"
        );
        assert!(
            !mempool.merge_input_cache.is_empty(),
            "Test assumption: Not empty prior to reorganization"
        );

        mempool.update_with_block(&block_1b).unwrap();
        assert!(
            mempool.is_empty(),
            "Mempool must be cleared after reorganization"
        );
        assert!(
            mempool.merge_input_cache.is_empty(),
            "Merge input must be cleared after reorganization"
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn reorganization_does_not_crash_mempool() {
        // Verify that reorganizations do not crash the client, and other
        // qualities.

        // First put a transaction into the mempool. Then mine block 1a that
        // does not contain this transaction, such that mempool is still
        // non-empty. Then mine a a block 1b that also does not contain this
        // transaction. Mempool state updater must not crash when changing tip
        // from 1a to 1b.
        let network = Network::Main;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, BlockHeight::genesis());
        let alice_wallet = WalletEntropy::devnet_wallet();
        let alice_key = alice_wallet.nth_generation_spending_key_for_tests(0);
        let proving_capability = TxProvingCapability::SingleProof;
        let cli_with_proof_capability = cli_args::Args {
            tx_proving_capability: Some(proving_capability),
            network,
            tx_proof_upgrading: true,
            ..Default::default()
        };
        let mut alice = mock_genesis_global_state(2, alice_wallet, cli_with_proof_capability).await;

        let mut rng: StdRng = StdRng::seed_from_u64(u64::from_str_radix("42", 6).unwrap());
        let bob_wallet_secret = WalletEntropy::new_pseudorandom(rng.random());
        let bob_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
        let bob_address = bob_key.to_address();

        let send_amt = NativeCurrencyAmount::coins(1);
        let tx_receiver_data =
            TxOutput::onchain_native_currency(send_amt, rng.random(), bob_address.into(), false);

        let genesis_block = alice
            .lock_guard()
            .await
            .chain
            .archival_state()
            .genesis_block()
            .to_owned();
        let now = genesis_block.kernel.header.timestamp;
        let in_seven_years = now + Timestamp::months(7 * 12);
        let config = TxCreationConfig::default()
            .recover_change_off_chain(alice_key.into())
            .with_prover_capability(proving_capability);
        let never_mined_tx = alice
            .api()
            .tx_initiator_internal()
            .create_transaction(
                vec![tx_receiver_data].into(),
                NativeCurrencyAmount::coins(1),
                in_seven_years,
                config,
                consensus_rule_set,
            )
            .await
            .unwrap()
            .transaction;
        assert!(never_mined_tx.is_valid(network, consensus_rule_set).await);
        assert!(never_mined_tx
            .is_confirmable_relative_to(&genesis_block.mutator_set_accumulator_after().unwrap()));

        alice
            .lock_guard_mut()
            .await
            .mempool
            .insert(never_mined_tx.into(), UpgradePriority::Irrelevant);

        // Add some blocks. The transaction must stay in the mempool, since it
        // is not being mined.
        let mut current_block = genesis_block.clone();
        for i in 0..2 {
            assert_eq!(
                1,
                alice.lock_guard().await.mempool.len(),
                "The inserted tx must be in the mempool"
            );

            let (next_block, _) = make_mock_block(
                &current_block,
                Some(in_seven_years),
                bob_key,
                rng.random(),
                network,
            )
            .await;
            let update_jobs = alice.set_new_tip(next_block.clone()).await.unwrap();
            assert!(
                update_jobs.is_empty(),
                "Must return zero update jobs, i = {i}"
            );
            update_all_sp_txs(
                &mut alice.lock_guard_mut().await.mempool,
                &current_block,
                &next_block,
                network,
            )
            .await;

            let mempool_txs = alice
                .lock_guard()
                .await
                .mempool
                .get_transactions_for_block_composition(usize::MAX, None);
            assert_eq!(
                1,
                mempool_txs.len(),
                "The inserted tx must stay in the mempool"
            );
            assert!(
                mempool_txs[0].is_confirmable_relative_to(
                    &next_block.mutator_set_accumulator_after().unwrap(),
                ),
                "Mempool tx must stay confirmable after new block of height {} has been applied \
                and SP-backed transactions have been updated.",
                next_block.header().height
            );
            assert!(
                mempool_txs[0].is_valid(network, consensus_rule_set).await,
                "Tx should be valid."
            );
            assert_eq!(
                next_block.hash(),
                alice.lock_guard().await.mempool.tip_digest,
                "Mempool's sync digest must be set correctly"
            );

            current_block = next_block;
        }

        // Now make a reorganization and verify that nothing crashes
        let (block_1b, _) = make_mock_block(
            &genesis_block,
            Some(in_seven_years),
            bob_key,
            rng.random(),
            network,
        )
        .await;
        assert!(
            block_1b.header().height.previous().unwrap().is_genesis(),
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
                .get_transactions_for_block_composition(usize::MAX, None)
                .iter()
                .all(|tx| tx.is_confirmable_relative_to(
                    &block_1b.mutator_set_accumulator_after().unwrap(),
                )),
            "All retained txs in the mempool must be confirmable relative to the new block.
             Or the mempool must be empty."
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn conflicting_txs_preserve_highest_fee() {
        // Create a global state object, controlled by a preminer who receives a premine-UTXO.
        let network = Network::Main;
        let mut preminer = mock_genesis_global_state(
            2,
            WalletEntropy::devnet_wallet(),
            cli_args::Args::default_with_network(network),
        )
        .await;
        let premine_spending_key = preminer
            .lock_guard()
            .await
            .wallet_state
            .wallet_entropy
            .nth_generation_spending_key_for_tests(0);
        let premine_address = premine_spending_key.to_address();
        let mut rng = StdRng::seed_from_u64(589111u64);

        let make_transaction_with_fee =
            |fee: NativeCurrencyAmount,
             preminer_clone: GlobalStateLock,
             sender_randomness: Digest| async move {
                let consensus_rule_set =
                    ConsensusRuleSet::infer_from(network, BlockHeight::genesis());
                let in_seven_months =
                    Block::genesis(network).kernel.header.timestamp + Timestamp::months(7);

                let receiver_data = TxOutput::offchain_native_currency(
                    NativeCurrencyAmount::coins(1),
                    sender_randomness,
                    premine_address.into(),
                    false,
                );
                let tx_outputs: TxOutputList = vec![receiver_data.clone()].into();
                let config = TxCreationConfig::default()
                    .recover_change_on_chain(premine_spending_key.into())
                    .with_prover_capability(TxProvingCapability::ProofCollection);
                preminer_clone
                    .api()
                    .tx_initiator_internal()
                    .create_transaction(
                        tx_outputs.clone(),
                        fee,
                        in_seven_months,
                        config,
                        consensus_rule_set,
                    )
                    .await
                    .expect("producing proof collection should succeed")
            };

        assert_eq!(0, preminer.lock_guard().await.mempool.len());

        // Insert transaction into mempool
        let tx_low_fee = make_transaction_with_fee(
            NativeCurrencyAmount::coins(1),
            preminer.clone(),
            rng.random(),
        )
        .await
        .transaction;
        {
            let mempool = &mut preminer.lock_guard_mut().await.mempool;
            let events = mempool.insert(tx_low_fee.clone().into(), UpgradePriority::Irrelevant);
            assert_eq!(1, events.len());
            assert_eq!(1, MempoolEvent::num_adds(&events));
            assert_eq!(1, mempool.len());
            assert_eq!(*tx_low_fee, *mempool.get(tx_low_fee.kernel.txid()).unwrap());
        }

        // Insert a transaction that spends the same UTXO and has a higher fee.
        // Verify that this replaces the previous transaction.
        let tx_high_fee = make_transaction_with_fee(
            NativeCurrencyAmount::coins(10),
            preminer.clone(),
            rng.random(),
        )
        .await
        .transaction;
        {
            let mempool = &mut preminer.lock_guard_mut().await.mempool;
            let events = mempool.insert(tx_high_fee.clone().into(), UpgradePriority::Irrelevant);
            assert_eq!(2, events.len());
            assert_eq!(1, MempoolEvent::num_removes(&events));
            assert_eq!(1, MempoolEvent::num_adds(&events));
            assert_eq!(1, mempool.len());
            assert_eq!(
                *tx_high_fee,
                *mempool.get(tx_high_fee.kernel.txid()).unwrap()
            );
        }

        // Insert a conflicting transaction with a lower fee and verify that it
        // does *not* replace the existing transaction.
        {
            let tx_medium_fee = make_transaction_with_fee(
                NativeCurrencyAmount::coins(4),
                preminer.clone(),
                rng.random(),
            )
            .await
            .transaction;
            let mempool = &mut preminer.lock_guard_mut().await.mempool;
            let events = mempool.insert(tx_medium_fee.clone().into(), UpgradePriority::Irrelevant);
            assert!(events.is_empty());
            assert_eq!(1, mempool.len());
            assert_eq!(
                *tx_high_fee,
                *mempool.get(tx_high_fee.kernel.txid()).unwrap()
            );
            assert!(mempool.get(tx_medium_fee.kernel.txid()).is_none());
            assert!(mempool.get(tx_low_fee.kernel.txid()).is_none());
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn single_proof_status_is_respected_for_block_composition() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);

        // Set up mempool with primitive-witness-backed transactions and
        // up-to-date mutator set hash, i.e., cannot use set_up_mempool().
        let txs = make_plenty_mock_transaction_supported_by_primitive_witness(11);
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::SingleProof,
            &genesis_block,
        );

        let mutator_set_hash = genesis_block
            .mutator_set_accumulator_after()
            .unwrap()
            .hash();
        for mut tx in txs {
            tx.kernel = TransactionKernelModifier::default()
                .mutator_set_hash(mutator_set_hash)
                .modify(tx.kernel);
            mempool.insert(tx, UpgradePriority::Irrelevant);
        }

        assert!(!mempool.is_empty());
        assert!(mempool
            .get_transactions_for_block_composition(usize::MAX, None)
            .is_empty());
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn insert_11_transactions() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let txs = make_plenty_mock_transaction_supported_by_primitive_witness(11);
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::ProofCollection,
            &genesis_block,
        );

        for tx in txs {
            let txid = tx.txid();
            assert!(!mempool.contains(txid));
            let events = mempool.insert(tx, UpgradePriority::Irrelevant);
            assert_eq!(1, events.len());
            assert!(mempool.contains(txid));
        }

        assert_eq!(
            11,
            mempool.len(),
            "All transactions are inserted into mempool"
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn max_size_is_respected() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let num_insertions = 20;
        let txs = mock_transactions_with_sized_single_proof(num_insertions, ByteSize::kb(100));

        let mut expected_txs = txs.clone();
        expected_txs.sort_by_key(|x| x.fee_density());
        expected_txs.reverse();

        let max_size = ByteSize::mb(1);
        let mut mempool = Mempool::new(
            max_size,
            TxProvingCapability::ProofCollection,
            &genesis_block,
        );
        for tx in txs.clone() {
            mempool.insert(tx, UpgradePriority::Irrelevant);
            println!("mempool len: {}", mempool.len());
            println!("mempool size: {}", mempool.get_size());
        }

        assert!(
            num_insertions > mempool.len(),
            "Test assumption: Transactions' sizes must exceed max allowed size"
        );
        assert!(!mempool.is_empty(), "Test assumption: Mempool not empty");

        let max_size: usize = max_size.0.try_into().unwrap();
        assert!(mempool.get_size() < max_size);

        let mempool_iter = mempool.fee_density_iter();
        for (expected, (txid, fee_density)) in expected_txs.iter().zip(mempool_iter) {
            assert_eq!(expected.txid(), txid);
            assert_eq!(expected.fee_density(), fee_density);
        }
    }

    #[test]
    fn txs_kicked_out_bc_max_size_exceeded_return_events() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let mut mempool = Mempool::new(
            ByteSize::mb(3),
            TxProvingCapability::ProofCollection,
            &genesis_block,
        );

        let num_insertions = 7;
        let mut txs = mock_transactions_with_sized_single_proof(num_insertions, ByteSize::mb(1));
        txs.sort_unstable_by_key(|x| x.fee_density());
        let mut all_events = vec![];
        for tx in txs {
            all_events.extend(mempool.insert(tx, UpgradePriority::Critical));
        }

        let removal_events = all_events
            .into_iter()
            .filter(|x| matches!(x, MempoolEvent::RemoveTx(_)))
            .collect_vec();
        let num_removal_events = removal_events.len();
        assert_ne!(
            0, num_removal_events,
            "Test assumption: Not all txs can fit into mempool"
        );
        assert_eq!(
            num_insertions,
            num_removal_events + mempool.len(),
            "All insertions must be either in mempool or in the removal events. \
            Got #removal events: {num_removal_events}; mempool length: {}",
            mempool.len()
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn get_mempool_size() {
        // Verify that the `get_size` method on mempool returns sane results
        let network = Network::Main;
        let tx_count_small = 2;
        let genesis_block = Block::genesis(network);
        let mempool_small = setup_mock_mempool(tx_count_small, &genesis_block);
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
        let mempool_big = setup_mock_mempool(tx_count_big, &genesis_block);
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

    mod merge_input_cache {
        use super::*;
        use crate::tests::shared::blocks::invalid_block_with_kernel_and_mutator_set;

        #[apply(shared_tokio_runtime)]
        async fn a_b_merged_b_mined() {
            // merge: (a, b) -> c
            // Scenario: a is mined => b is in mempool after block update
            let network = Network::Main;
            let consensus_rule_set = ConsensusRuleSet::Reboot;
            let (((a, b), c), mutator_set) = merge_tx_triplet(consensus_rule_set).await;
            let block1 = invalid_block_with_kernel_and_mutator_set(b.kernel.clone(), mutator_set);

            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &Block::genesis(network),
            );
            mempool.tip_digest = block1.header().prev_block_digest;

            mempool.insert(a.clone(), UpgradePriority::Irrelevant);
            mempool.insert(b.clone(), UpgradePriority::Irrelevant);
            mempool.insert(c.clone(), UpgradePriority::Irrelevant);
            assert!(!mempool.contains(a.txid()));
            assert!(!mempool.contains(b.txid()));
            assert!(mempool.contains(c.txid()));

            assert_eq!(2, mempool.merge_input_cache.len());
            let (events, _) = mempool.update_with_block(&block1).unwrap();
            assert!(mempool.contains(a.txid()));
            assert!(!mempool.contains(b.txid()));
            assert!(!mempool.contains(c.txid()));
            assert_eq!(1, mempool.len());

            assert_eq!(2, events.len());
            assert_eq!(1, MempoolEvent::num_removes(&events));
            assert_eq!(1, MempoolEvent::num_adds(&events));
            assert!(mempool.merge_input_cache.is_empty());
        }

        #[apply(shared_tokio_runtime)]
        async fn a_b_merged_c_mined() {
            // merge: (a, b) -> c
            // Scenario: c is mined => mempool is empty after block update
            let network = Network::Main;
            let consensus_rule_set = ConsensusRuleSet::Reboot;
            let (((a, b), c), mutator_set) = merge_tx_triplet(consensus_rule_set).await;
            let block1 = invalid_block_with_kernel_and_mutator_set(c.kernel.clone(), mutator_set);

            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &Block::genesis(network),
            );
            mempool.tip_digest = block1.header().prev_block_digest;

            mempool.insert(a.clone(), UpgradePriority::Irrelevant);
            mempool.insert(b.clone(), UpgradePriority::Irrelevant);
            mempool.insert(c.clone(), UpgradePriority::Irrelevant);
            assert!(!mempool.contains(a.txid()));
            assert!(!mempool.contains(b.txid()));
            assert!(mempool.contains(c.txid()));

            let (events, _) = mempool.update_with_block(&block1).unwrap();
            assert!(!mempool.contains(a.txid()));
            assert!(!mempool.contains(b.txid()));
            assert!(!mempool.contains(c.txid()));
            assert!(mempool.is_empty());

            assert_eq!(1, events.len());
            assert_eq!(1, MempoolEvent::num_removes(&events));
            assert_eq!(0, MempoolEvent::num_adds(&events));
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn nested_mergers_behave() {
            let consensus_rule_set = ConsensusRuleSet::Reboot;
            let network = Network::Main;
            let (bottom, [left, right], final_tx, mutator_set) =
                nested_mergers(consensus_rule_set).await;
            let block_bottom = invalid_block_with_kernel_and_mutator_set(
                bottom[0].kernel.clone(),
                mutator_set.clone(),
            );
            let block_middle =
                invalid_block_with_kernel_and_mutator_set(left.kernel.clone(), mutator_set.clone());
            let block_top = invalid_block_with_kernel_and_mutator_set(
                final_tx.kernel.clone(),
                mutator_set.clone(),
            );

            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &Block::genesis(network),
            );
            mempool.tip_digest = block_bottom.header().prev_block_digest;

            for tx in &bottom {
                let events = mempool.insert(tx.clone(), UpgradePriority::Irrelevant);
                assert_eq!(1, events.len());
                assert_eq!(1, MempoolEvent::num_adds(&events));
            }
            assert_eq!(4, mempool.len());
            assert_eq!(0, mempool.merge_input_cache.len());

            for tx in [&left, &right] {
                let events = mempool.insert(tx.clone(), UpgradePriority::Irrelevant);
                assert_eq!(3, events.len());
                assert_eq!(1, MempoolEvent::num_adds(&events));
                assert_eq!(2, MempoolEvent::num_removes(&events));
            }
            assert_eq!(2, mempool.len());
            assert_eq!(4, mempool.merge_input_cache.len());

            let events = mempool.insert(final_tx.clone(), UpgradePriority::Irrelevant);
            assert_eq!(3, events.len());
            assert_eq!(1, MempoolEvent::num_adds(&events));
            assert_eq!(2, MempoolEvent::num_removes(&events));
            assert_eq!(1, mempool.len());
            assert_eq!(6, mempool.merge_input_cache.len());

            // Scenario: non-merged transaction mined (bottom layer)
            let mut mempool_bottom = mempool.clone();
            let (events1, _) = mempool_bottom.update_with_block(&block_bottom).unwrap();
            assert!(!mempool_bottom.contains(bottom[0].txid()));
            assert!(mempool_bottom.contains(bottom[1].txid()));
            assert!(mempool_bottom.contains(right.txid()));
            assert_eq!(3, events1.len());
            assert_eq!(2, MempoolEvent::num_adds(&events1));
            assert_eq!(1, MempoolEvent::num_removes(&events1));
            assert_eq!(2, mempool_bottom.merge_input_cache.len());

            // Scenario: one-time-merged transaction mined (middle layer)
            let mut mempool_middle = mempool.clone();
            let (events2, _) = mempool_middle.update_with_block(&block_middle).unwrap();
            assert_eq!(2, events2.len());
            assert_eq!(1, MempoolEvent::num_adds(&events2));
            assert_eq!(1, MempoolEvent::num_removes(&events2));
            assert!(!mempool_middle.contains(bottom[0].txid()));
            assert!(!mempool_middle.contains(bottom[1].txid()));
            assert!(mempool_middle.contains(right.txid()));
            assert_eq!(2, mempool_middle.merge_input_cache.len());

            // Scenario: two-time-merged transaction mined (top layer)
            let mut mempool_top = mempool.clone();
            let (events3, _) = mempool_top.update_with_block(&block_top).unwrap();
            assert_eq!(1, events3.len());
            assert_eq!(0, MempoolEvent::num_adds(&events3));
            assert_eq!(1, MempoolEvent::num_removes(&events3));
            assert!(mempool_top.is_empty());
            assert!(mempool_top.merge_input_cache.is_empty());
        }
    }

    mod mutator_set_updates {
        use super::*;
        use crate::tests::shared::blocks::fake_valid_deterministic_successor;
        use crate::tests::shared::mock_tx::genesis_tx_with_proof_type;

        #[apply(shared_tokio_runtime)]
        async fn tx_ms_updating() {
            let network = Network::Main;
            let fee = NativeCurrencyAmount::coins(1);

            let genesis_block = Block::genesis(network);
            let block1 = fake_valid_deterministic_successor(&genesis_block, network).await;
            for tx_proving_capability in [
                TxProvingCapability::PrimitiveWitness,
                TxProvingCapability::ProofCollection,
                TxProvingCapability::SingleProof,
            ] {
                let mut mempool = Mempool::new(
                    ByteSize::gb(1),
                    TxProvingCapability::SingleProof,
                    &genesis_block,
                );

                // First insert a PW backed transaction to ensure PW is
                // present, as this determines what MS-data updating jobs are
                // returned.
                let pw_tx =
                    genesis_tx_with_proof_type(TxProvingCapability::PrimitiveWitness, network, fee)
                        .await;
                mempool.insert(pw_tx.into(), UpgradePriority::Critical);
                let tx = genesis_tx_with_proof_type(tx_proving_capability, network, fee).await;
                let txid = tx.txid();

                mempool.insert(tx.into(), UpgradePriority::Critical);

                let (_, update_jobs) = mempool.update_with_block(&block1).unwrap();
                assert_eq!(1, update_jobs.len(), "Must return 1 job for MS-updating");

                mocked_mempool_update_handler(
                    update_jobs,
                    &mut mempool,
                    &block1,
                    &genesis_block.mutator_set_accumulator_after().unwrap(),
                    network,
                )
                .await;

                assert!(
                    mempool
                        .get(txid)
                        .unwrap()
                        .clone()
                        .is_confirmable_relative_to(
                            &block1.mutator_set_accumulator_after().unwrap()
                        ),
                    "transaction must be updatable"
                );
            }
        }
    }

    mod proof_upgrade_candidates {
        use std::str::FromStr;

        use proptest::prop_assert;
        use proptest::prop_assert_eq;
        use test_strategy::proptest;

        use super::*;
        use crate::tests::shared::blocks::fake_valid_successor_for_tests;
        use crate::tests::shared::mock_tx::genesis_tx_with_proof_type;

        #[apply(shared_tokio_runtime)]
        async fn sp_update_only_returns_unsynced_txs() {
            let network = Network::Main;
            let fee = NativeCurrencyAmount::coins(1);
            let sp_tx =
                genesis_tx_with_proof_type(TxProvingCapability::SingleProof, network, fee).await;

            let mut rng = rand::rng();
            let genesis_block = Block::genesis(network);
            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &genesis_block,
            );

            // Insert synced transaction into mempool, verify no transaction
            // is returned.
            mempool.insert(sp_tx.into(), UpgradePriority::Irrelevant);
            assert!(mempool
                .preferred_update(TxUpgradeFilter::match_all())
                .is_none());

            // Ensure tx in mempool becomes unsynced.
            let block1_timestamp = genesis_block.header().timestamp + Timestamp::hours(1);
            let block1 = fake_valid_successor_for_tests(
                &genesis_block,
                block1_timestamp,
                rng.random(),
                network,
            )
            .await;
            let (_, returned_jobs) = mempool.update_with_block(&block1).unwrap();
            assert!(returned_jobs.is_empty());
            assert!(mempool
                .preferred_update(TxUpgradeFilter::match_all())
                .is_some());

            // Verify filter behavior
            let accept_first_half = TxUpgradeFilter::from_str("2:0").unwrap();
            let accept_second_half = TxUpgradeFilter::from_str("2:1").unwrap();
            let num_matches = u8::from(mempool.preferred_update(accept_first_half).is_some())
                + u8::from(mempool.preferred_update(accept_second_half).is_some());
            assert_eq!(1, num_matches, "Exactly one filter must match transaction");
        }

        #[proptest(cases = 15, async = "tokio")]
        async fn preferred_update_is_tx_with_highest_upgrade_priority(
            #[strategy(arb())] upgrade_priority_a: UpgradePriority,
            #[strategy(arb())] upgrade_priority_b: UpgradePriority,
            #[strategy(PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets(
                [(2, 2, 2),
                 (1, 1, 1),],
    ))]
            pws: [PrimitiveWitness; 2],
        ) {
            // Transactions in the mempool do not need to be valid, so we just
            // pretend that the primitive-witness backed transactions have a
            // SingleProof.
            let into_single_proof_transaction = |pw: PrimitiveWitness| {
                let mock_proof = TransactionProof::invalid();
                Transaction {
                    kernel: pw.kernel,
                    proof: mock_proof,
                }
            };
            let [tx_a, tx_b] = pws;
            let tx_a = into_single_proof_transaction(tx_a);
            let tx_b = into_single_proof_transaction(tx_b);

            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &Block::genesis(Network::Main),
            );
            mempool.insert(tx_a.clone(), upgrade_priority_a);
            mempool.insert(tx_b.clone(), upgrade_priority_b);

            // All transactions in the mempool should be considered unsynced at
            // this point, so a transaction will be returned from below call.
            let (preferred_txk, _, upgrade_priority) = mempool
                .preferred_update(TxUpgradeFilter::match_all())
                .unwrap();

            if preferred_txk.txid() == tx_a.txid() {
                prop_assert!(upgrade_priority_a >= upgrade_priority_b);
                prop_assert_eq!(upgrade_priority_a, upgrade_priority);
            } else if preferred_txk.txid() == tx_b.txid() {
                prop_assert!(upgrade_priority_a <= upgrade_priority_b);
                prop_assert_eq!(upgrade_priority_b, upgrade_priority);
            } else {
                panic!("Must return either tx_a or tx_b");
            }
        }

        #[proptest(cases = 8, async = "tokio")]
        async fn preferred_proof_collection_respects_tx_upgrade_filter(
            #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 3, 9))]
            primitive_witness: PrimitiveWitness,
        ) {
            let tx = Transaction {
                kernel: primitive_witness.kernel,
                proof: TransactionProof::ProofCollection(ProofCollection::invalid()),
            };
            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &Block::genesis(Network::Main),
            );
            mempool.tip_mutator_set_hash = tx.kernel.mutator_set_hash;
            mempool.insert(tx, UpgradePriority::Irrelevant);

            let accept_all = TxUpgradeFilter::match_all();
            let accept_first_third = TxUpgradeFilter::from_str("3:0").unwrap();
            let accept_second_third = TxUpgradeFilter::from_str("3:1").unwrap();
            let accept_third_third = TxUpgradeFilter::from_str("3:2").unwrap();

            let num_proofs_threshold = 20;
            prop_assert!(mempool
                .preferred_proof_collection(num_proofs_threshold, accept_all)
                .is_some());
            let num_matches = u8::from(
                mempool
                    .preferred_proof_collection(num_proofs_threshold, accept_first_third)
                    .is_some(),
            ) + u8::from(
                mempool
                    .preferred_proof_collection(num_proofs_threshold, accept_second_third)
                    .is_some(),
            ) + u8::from(
                mempool
                    .preferred_proof_collection(num_proofs_threshold, accept_third_third)
                    .is_some(),
            );
            assert_eq!(
                1, num_matches,
                "Only one match from mutually exclusive filters"
            );
        }
    }

    mod proof_quality_tests {
        use proptest::prop_assert;
        use proptest::prop_assert_eq;
        use proptest::prop_assert_ne;
        use proptest::prop_assume;
        use test_strategy::proptest;

        use super::*;
        use crate::protocol::consensus::block::mutator_set_update::MutatorSetUpdate;
        use crate::tests::shared::mock_tx::genesis_tx_with_proof_type;

        #[apply(shared_tokio_runtime)]
        async fn always_preserve_primitive_witness_if_available() {
            let network = Network::Main;
            let fee = NativeCurrencyAmount::coins(1);
            let pw_tx =
                genesis_tx_with_proof_type(TxProvingCapability::PrimitiveWitness, network, fee)
                    .await;
            let txid = pw_tx.txid();

            let genesis_block = Block::genesis(network);
            let mut mempool = setup_mock_mempool(0, &genesis_block);
            mempool.insert(pw_tx.into(), UpgradePriority::Critical);

            let pc_tx =
                genesis_tx_with_proof_type(TxProvingCapability::ProofCollection, network, fee)
                    .await;
            mempool.insert(pc_tx.into(), UpgradePriority::Critical);
            assert_eq!(
                1,
                mempool.len(),
                "assumption: original transaction replaced"
            );

            assert!(
                mempool.tx_dictionary[&txid].primitive_witness.is_some(),
                "proof collection may not delete primitive witness"
            );

            let sp_tx =
                genesis_tx_with_proof_type(TxProvingCapability::SingleProof, network, fee).await;
            mempool.insert(sp_tx.into(), UpgradePriority::Critical);
            assert_eq!(
                1,
                mempool.len(),
                "assumption: original transaction replaced"
            );

            assert_eq!(1, mempool.len());
            assert!(
                mempool.tx_dictionary[&txid].primitive_witness.is_some(),
                "single proof may not delete primitive witness"
            );
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn single_proof_always_replaces_primitive_witness() {
            let network = Network::Main;
            let pw_high_fee = genesis_tx_with_proof_type(
                TxProvingCapability::PrimitiveWitness,
                network,
                NativeCurrencyAmount::coins(15),
            )
            .await;
            let genesis_block = Block::genesis(network);
            let mut mempool = setup_mock_mempool(0, &genesis_block);
            mempool.insert(pw_high_fee.into(), UpgradePriority::Critical);
            assert!(mempool.len().is_one(), "One tx after insertion");

            let low_fee = NativeCurrencyAmount::coins(1);
            let sp_low_fee =
                genesis_tx_with_proof_type(TxProvingCapability::SingleProof, network, low_fee)
                    .await;
            let txid = sp_low_fee.kernel.txid();
            mempool.insert(sp_low_fee.into(), UpgradePriority::Critical);
            assert!(
                mempool.len().is_one(),
                "One tx after 2nd insertion. Because pw-tx was replaced."
            );
            let tx_in_mempool = mempool.get(txid).unwrap();
            assert!(matches!(
                tx_in_mempool.proof,
                TransactionProof::SingleProof(_)
            ));
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn single_proof_always_replaces_proof_collection() {
            let network = Network::Main;
            let pc_high_fee = genesis_tx_with_proof_type(
                TxProvingCapability::ProofCollection,
                network,
                NativeCurrencyAmount::coins(15),
            )
            .await;
            let genesis_block = Block::genesis(network);
            let mut mempool = setup_mock_mempool(0, &genesis_block);
            mempool.insert(pc_high_fee.into(), UpgradePriority::Irrelevant);
            assert!(mempool.len().is_one(), "One tx after insertion");

            let low_fee = NativeCurrencyAmount::coins(1);
            let sp_low_fee =
                genesis_tx_with_proof_type(TxProvingCapability::SingleProof, network, low_fee)
                    .await;
            let txid = sp_low_fee.kernel.txid();
            mempool.insert(sp_low_fee.into(), UpgradePriority::Irrelevant);
            assert!(
                mempool.len().is_one(),
                "One tx after 2nd insertion. Because pc-tx was replaced."
            );
            let tx_in_mempool = mempool.get(txid).unwrap();
            assert!(matches!(
                tx_in_mempool.proof,
                TransactionProof::SingleProof(_)
            ));
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn proof_collection_always_replaces_primitive_witness() {
            let network = Network::Main;
            let pc_high_fee = genesis_tx_with_proof_type(
                TxProvingCapability::PrimitiveWitness,
                network,
                NativeCurrencyAmount::coins(15),
            )
            .await;
            let genesis_block = Block::genesis(network);
            let mut mempool = setup_mock_mempool(0, &genesis_block);
            mempool.insert(pc_high_fee.into(), UpgradePriority::Critical);
            assert!(mempool.len().is_one(), "One tx after insertion");

            let low_fee = NativeCurrencyAmount::coins(1);
            let sp_low_fee =
                genesis_tx_with_proof_type(TxProvingCapability::ProofCollection, network, low_fee)
                    .await;
            let txid = sp_low_fee.kernel.txid();
            mempool.insert(sp_low_fee.into(), UpgradePriority::Critical);
            assert!(
                mempool.len().is_one(),
                "One tx after 2nd insertion. Because pw-tx was replaced."
            );
            let tx_in_mempool = mempool.get(txid).unwrap();
            assert!(matches!(
                tx_in_mempool.proof,
                TransactionProof::ProofCollection(_)
            ));
        }

        #[proptest(cases = 15, async = "tokio")]
        async fn ms_updated_transaction_always_replaces_progenitor(
            #[strategy(0usize..20)] _num_inputs_own: usize,
            #[strategy(0usize..20)] _num_outputs_own: usize,
            #[strategy(0usize..20)] _num_announcements_own: usize,
            #[filter(#_num_inputs_mined+#_num_outputs_mined>0)]
            #[strategy(1usize..20)]
            _num_inputs_mined: usize,
            #[strategy(0usize..20)] _num_outputs_mined: usize,
            #[strategy(0usize..20)] _num_announcements_mined: usize,
            #[strategy(0usize..200_000)] size_old_proof: usize,
            #[strategy(0usize..200_000)] size_new_proof: usize,
            #[strategy(arb())] upgrade_priority: UpgradePriority,
            #[strategy(PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets(
            [(#_num_inputs_own, #_num_outputs_own, #_num_announcements_own),
            (#_num_inputs_mined, #_num_outputs_mined, #_num_announcements_mined),],
    ))]
            pws: [PrimitiveWitness; 2],
        ) {
            // Transactions in the mempool do not need to be valid, so we just
            // pretend that the primitive-witness backed transactions have a
            // SingleProof.
            let into_single_proof_transaction = |pw: PrimitiveWitness, size_of_proof: usize| {
                let mock_proof = TransactionProof::invalid_single_proof_of_size(size_of_proof);
                Transaction {
                    kernel: pw.kernel,
                    proof: mock_proof,
                }
            };
            let [mempool_tx, mined_tx] = pws;

            // Build the mutator set update and skip test case if it's empty, as
            // this test assumes an update to the mutator set takes place.
            let ms_update = MutatorSetUpdate::new(
                mined_tx.kernel.inputs.clone(),
                mined_tx.kernel.outputs.clone(),
            );
            prop_assume!(!ms_update.is_empty());

            let updated_tx =
                PrimitiveWitness::update_with_new_ms_data(mempool_tx.clone(), ms_update);

            let original_tx = into_single_proof_transaction(mempool_tx, size_old_proof);
            let updated_tx = into_single_proof_transaction(updated_tx, size_new_proof);

            assert_eq!(original_tx.kernel.txid(), updated_tx.kernel.txid());
            let txid = original_tx.kernel.txid();

            let genesis_block = Block::genesis(Network::Main);
            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &genesis_block,
            );

            // First insert original transaction, then updated which should
            // always replace the original transaction, regardless of its size.
            prop_assert!(
                mempool.accept_transaction(
                    txid,
                    original_tx.proof.proof_quality().unwrap(),
                    original_tx.kernel.mutator_set_hash
                ),
                "Must return true since tx not known"
            );
            mempool.insert(original_tx.clone(), upgrade_priority);
            let in_mempool_start = mempool.get(txid).map(|tx| tx.to_owned()).unwrap();
            prop_assert_eq!(&original_tx, &in_mempool_start);
            prop_assert_ne!(&updated_tx, &in_mempool_start);

            // Mock that the new transaction is synced to the tip.
            mempool.tip_mutator_set_hash = updated_tx.kernel.mutator_set_hash;

            prop_assert!(
                mempool.accept_transaction(
                    txid,
                    updated_tx.proof.proof_quality().unwrap(),
                    updated_tx.kernel.mutator_set_hash
                ),
                "Must return true since updated tx not yet known to mempool"
            );

            assert_eq!(
                1,
                mempool.len(),
                "Mempool length must be 1 prior to MS update insertion"
            );
            let events = mempool.insert(updated_tx.clone(), upgrade_priority);
            assert_eq!(
                1,
                mempool.len(),
                "Mempool length must be 1 after MS update insertion"
            );
            assert_eq!(
                2,
                events.len(),
                "Must return one event for addition, one for removal. Got: {events:#?}"
            );
            assert_eq!(1, MempoolEvent::num_removes(&events));
            assert_eq!(1, MempoolEvent::num_adds(&events));
            let in_mempool_end = mempool.get(txid).map(|tx| tx.to_owned()).unwrap();
            prop_assert_eq!(&updated_tx, &in_mempool_end);
            prop_assert_ne!(&original_tx, &in_mempool_end);
            prop_assert!(
                !mempool.accept_transaction(
                    txid,
                    updated_tx.proof.proof_quality().unwrap(),
                    updated_tx.kernel.mutator_set_hash
                ),
                "Must return false on updated after insertion of updated tx"
            );
            prop_assert!(
                !mempool.accept_transaction(
                    txid,
                    original_tx.proof.proof_quality().unwrap(),
                    updated_tx.kernel.mutator_set_hash
                ),
                "Must return false on original after insertion of updated tx"
            );
        }
    }
}
