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

use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::RandomState;

use bytesize::ByteSize;
use get_size2::GetSize;
use itertools::Itertools;
use neptune_consensus::block::Block;
use neptune_consensus::chaintx::link_tx::LinkTx;
use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
use neptune_consensus::proof_abstractions::tx_proving_capability::TxProvingCapability;
use neptune_consensus::transaction::Transaction;
use neptune_consensus::transaction::TransactionProof;
use neptune_consensus::transaction::primitive_witness::PrimitiveWitness;
use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
use neptune_consensus::transaction::transaction_proof::TransactionProofType;
use neptune_consensus::transaction::validity::neptune_proof::NeptuneProof;
use neptune_consensus::transaction::validity::neptune_proof::Proof;
use neptune_consensus::transaction::validity::proof_collection::ProofCollection;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
use neptune_primitives::timestamp::Timestamp;
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
use priority_queue::DoublePriorityQueue;
use priority_queue::PriorityQueue;
use priority_queue::priority_queue::iterators::IntoSortedIter as SingleEndedIterator;
use tasm_lib::prelude::Digest;
use tasm_lib::twenty_first::prelude::BFieldCodec;
use tracing::debug;
use tracing::error;

use crate::any_tx::AnyTx;
use crate::mempool_event::MempoolEvent;
use crate::mempool_update_job::MempoolUpdateJob;
use crate::merge_input_cache::MergeInputCache;
use crate::merge_input_cache::MergeInputCacheElement;
use crate::primitive_witness_update::PrimitiveWitnessUpdate;
use crate::transaction_kernel_id::TransactionKernelId;
use crate::transaction_kernel_id::Txid;
use crate::transaction_proof_quality::TransactionProofQuality;
use crate::transaction_proof_quality::TransactionProofQualityExt;
use crate::tx_upgrade_filter::TxUpgradeFilter;
use crate::upgrade_priority::UpgradePriority;

/// Transactions with a timestamp older than this are removed from the mempool.
pub const MEMPOOL_TX_THRESHOLD_AGE: Timestamp = Timestamp::hours(10);

/// How long a transaction that carries a retirement announcement must still
/// have left before it retires, for this node to hold it and to compose with
/// it.
///
/// Policy, not consensus logic.
pub const MEMPOOL_RETIREMENT_MARGIN: Timestamp = Timestamp::minutes(100);

/// How long a transaction that carries a retirement announcement must still
/// have left before it retires, for this node to merge it into another
/// transaction.
///
/// Deliberately longer than [`MEMPOOL_RETIREMENT_MARGIN`] since it takes some
/// time before a merged transaction is picked up by composers: proving time,
/// tx-propagation, the finding of the next block.
///
/// Policy, not consensus logic.
pub const MERGE_RETIREMENT_MARGIN: Timestamp = Timestamp::minutes(150);

pub const TRANSACTION_NOTIFICATION_AGE_LIMIT_IN_SECS: u64 = 60 * 60 * 24;

type LookupItem<'a> = (TransactionKernelId, &'a AnyTx);

#[derive(Debug, GetSize, Clone)]
#[cfg_attr(any(test, feature = "test-helpers"), derive(serde::Serialize))]
struct MempoolTransaction {
    transaction: AnyTx,

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
#[cfg_attr(any(test, feature = "test-helpers"), derive(Clone))]
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

    /// Transactions whose proof upgrade was attempted and failed since the
    /// last block.
    ///
    /// Proof upgrade candidate selection is deterministic, so a transaction
    /// whose upgrade fails is picked again on every following attempt, and no
    /// other transaction behind it is ever upgraded. Recording the failure
    /// keeps the upgrader moving and gives other txs a chance. Cleared whenever
    /// a new block is processed such that a transient failure doesn't prevent
    /// the transaction from ever being upgraded. A transaction is never dropped
    /// on account of upgrade failures.
    #[get_size(ignore)]
    upgrade_failures: HashSet<TransactionKernelId>,
}

/// The quality a mempool member or arrival occupies in the mempool's
/// replacement hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContestTier {
    /// primitive-witness backed, either link transaction or regular transaction.
    Witness,

    /// One proving step away from block eligibility. Proof collection or
    /// LinkTx.
    Intermediate,
    SingleProof,
}

impl AnyTx {
    fn contest_tier(&self) -> ContestTier {
        match self {
            AnyTx::Standard(transaction) => match &transaction.proof {
                TransactionProof::Witness(_) => ContestTier::Witness,
                TransactionProof::ProofCollection(_) => ContestTier::Intermediate,
                TransactionProof::SingleProof(_) => ContestTier::SingleProof,
            },
            AnyTx::Link(link_tx) => {
                if link_tx.proof.is_proof() {
                    ContestTier::Intermediate
                } else {
                    ContestTier::Witness
                }
            }
        }
    }
}

/// Whether an arrival replaces its conflicts on proof quality alone,
/// irrespective of fee densities.
///
/// Considers both the proofs proximity to block inclusion and sync status.
fn new_tx_wins_by_quality(
    new_tier: ContestTier,
    new_txid: TransactionKernelId,
    new_tx_mutator_set_hash: Digest,
    conflicts: &HashMap<TransactionKernelId, &AnyTx>,
    current_msa_hash: Digest,
) -> bool {
    match new_tier {
        ContestTier::Witness => conflicts.values().all(|existing_tx| {
            existing_tx.contest_tier() == ContestTier::Witness
                && existing_tx.kernel().mutator_set_hash != current_msa_hash
                && new_tx_mutator_set_hash == current_msa_hash
        }),
        ContestTier::Intermediate => {
            conflicts
                .values()
                .any(|x| x.contest_tier() == ContestTier::Witness)
                || conflicts.values().all(|existing_tx| {
                    existing_tx.contest_tier() == ContestTier::Intermediate
                        && existing_tx.kernel().mutator_set_hash != current_msa_hash
                        && new_tx_mutator_set_hash == current_msa_hash
                })
        }
        ContestTier::SingleProof => conflicts.iter().any(|(conflicting_txkid, conflicting_tx)| {
            // A proof-backed link only yields on quality to its own fixed
            // form (same txid); any other single proof must outbid it on fee
            // density.
            let concedes_tier = match conflicting_tx {
                AnyTx::Link(link_tx) => !link_tx.proof.is_proof(),
                AnyTx::Standard(_) => conflicting_tx.contest_tier() != ContestTier::SingleProof,
            };
            concedes_tier
                || *conflicting_txkid == new_txid && new_tx_mutator_set_hash == current_msa_hash
        }),
    }
}

/// Enumerate ways that transactions in the mempool can be filtered.
enum TxMatcher<'a> {
    Inputs(&'a HashSet<AbsoluteIndexSet>),
    Outputs(&'a HashSet<AdditionRecord>),
}

impl<'a> TxMatcher<'a> {
    fn is_empty(&self) -> bool {
        match self {
            TxMatcher::Inputs(hash_set) => hash_set.is_empty(),
            TxMatcher::Outputs(hash_set) => hash_set.is_empty(),
        }
    }
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
            upgrade_failures: HashSet::default(),
        }
    }

    /// Record that upgrading the proofs of these transactions failed, so that
    /// they are passed over when picking the next upgrade candidate.
    ///
    /// The transactions are not removed, and the record is discarded by
    /// [`Self::update_with_block`], so a failure that was transient only delays
    /// an upgrade by one block.
    pub fn record_upgrade_failure(&mut self, txids: impl IntoIterator<Item = TransactionKernelId>) {
        self.upgrade_failures.extend(txids);
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
    /// a lower fee density than all transactions in the mempool.
    pub fn accept_transaction(
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

        let Some(existing_tx) = existing_tx.transaction.as_standard() else {
            // Existing transaction is a link transaction.
            return matches!(new_tx_proof_quality, TransactionProofQuality::SingleProof);
        };

        match existing_tx.proof.proof_quality() {
            Ok(mempool_proof_quality) => {
                if mempool_proof_quality > new_tx_proof_quality {
                    // New tx has lower proof quality.
                    false
                } else if mempool_proof_quality == new_tx_proof_quality {
                    // New tx has same proof quality. Check if new tx
                    // represents a valid mutator set, if it does, return
                    // true as the new transaction is more likely to be
                    // included in a block when it's synced.
                    existing_tx.kernel.mutator_set_hash != self.tip_mutator_set_hash
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

    /// Check if mempool will accept a link transaction for insertion.
    ///
    /// Returns true if the link transaction is not known, or if the member
    /// is a link transaction that the arrival would replace: a witness one, or
    /// one that is unsynced.
    pub fn accept_link_transaction(
        &self,
        new_link_txid: TransactionKernelId,
        new_link_mutator_set_hash: Digest,
    ) -> bool {
        match self.tx_dictionary.get(&new_link_txid) {
            None => true,
            Some(member) => match &member.transaction {
                AnyTx::Standard(_) => false,
                AnyTx::Link(member_tx) => {
                    member_tx.proof.is_witness()
                        || member_tx.kernel.kernel.mutator_set_hash != self.tip_mutator_set_hash
                            && new_link_mutator_set_hash == self.tip_mutator_set_hash
                }
            },
        }
    }

    /// Return a transaction that can be merged with the specified transaction
    /// if any is present in the mempool.
    ///
    /// The specified transaction should be backed by a single proof. Otherwise
    /// the returned transaction cannot actually be merged with the input
    /// transaction.
    ///
    /// The returned transaction is guaranteed to:
    /// 1. Not conflict with the input transaction
    /// 2. Be synced to the same mutator set
    /// 3. Pay at least the specified fee
    /// 4. Not exceed allowed sizes after being merged with the specified
    /// 5. Not retire within [`MERGE_RETIREMENT_MARGIN`]
    ///
    /// Returns `None` if the specified transaction itself retires within
    /// [`MERGE_RETIREMENT_MARGIN`].
    ///
    /// Note that the returned a returned transaction is not guaranteed to be
    /// synced to the tip. If the input transaction is not synced to the tip,
    /// neither will any returned transaction be.
    pub fn merge_partner(
        &self,
        kernel: &TransactionKernel,
        consensus_rule_set: ConsensusRuleSet,
        minimum_fee: NativeCurrencyAmount,
    ) -> Option<(TransactionKernel, Proof, UpgradePriority)> {
        // Constants to avoid going to the limit of the consensus rules in
        // terms of outputs and announcements, since the composer probably wants
        // to set a few outputs and announcement themselves.
        const NUM_OUTPUTS_BUFFER: usize = 6;
        const NUM_ANNOUNCEMENTS_BUFFER: usize = 6;

        let max_num_inputs = consensus_rule_set.max_num_inputs();
        let max_num_outputs = consensus_rule_set.max_num_outputs();
        let max_num_announcements = consensus_rule_set.max_num_announcements();

        // Prevent the spread of too early retirement to other transactions.
        let now = Timestamp::now();
        if kernel.retires_before(now + MERGE_RETIREMENT_MARGIN) {
            return None;
        }

        let tx_index_sets: HashSet<_> = kernel.inputs.iter().map(|x| x.absolute_indices).collect();

        for (txid, priority) in self.upgrade_priority_iter().chain(
            self.fee_density_iter()
                .map(|(txid, _)| (txid, UpgradePriority::Irrelevant)),
        ) {
            let candidate = self
                .get_any(txid)
                .expect("Referenced tx in iterators must exist");

            let Some(candidate) = candidate.as_standard() else {
                continue;
            };

            let TransactionProof::SingleProof(single_proof) = &candidate.proof else {
                continue;
            };

            let candidate = &candidate.kernel;

            if candidate.fee < minimum_fee {
                continue;
            }

            if candidate.mutator_set_hash != kernel.mutator_set_hash {
                continue;
            }

            if candidate.retires_before(now + MERGE_RETIREMENT_MARGIN) {
                continue;
            }

            let conflicts = candidate
                .inputs
                .iter()
                .any(|input| tx_index_sets.contains(&input.absolute_indices));
            if conflicts {
                continue;
            }

            if candidate.inputs.len() + kernel.inputs.len() > max_num_inputs {
                continue;
            }

            if candidate.outputs.len() + kernel.outputs.len() + NUM_OUTPUTS_BUFFER > max_num_outputs
            {
                continue;
            }

            if candidate.announcements.len() + kernel.announcements.len() + NUM_ANNOUNCEMENTS_BUFFER
                > max_num_announcements
            {
                continue;
            }

            return Some((candidate.to_owned(), single_proof.to_owned(), priority));
        }

        None
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
    pub fn preferred_update(
        &self,
        tx_upgrade_filter: TxUpgradeFilter,
    ) -> Option<(&TransactionKernel, &NeptuneProof, UpgradePriority)> {
        for candidate_txid in self
            .upgrade_priority_iter()
            .map(|(txid, _)| txid)
            .chain(self.fee_density_iter().map(|(txid, _)| txid))
        {
            let candidate = self.tx_dictionary.get(&candidate_txid).unwrap();
            if self.upgrade_failures.contains(&candidate_txid) {
                continue;
            }

            let Some(transaction) = candidate.transaction.as_standard() else {
                continue;
            };

            if self.tx_is_synced(&transaction.kernel) {
                continue;
            }

            // Transactions with no inputs cannot be updated.
            if transaction.kernel.inputs.is_empty() {
                continue;
            }

            let TransactionProof::SingleProof(single_proof) = &transaction.proof else {
                continue;
            };

            if candidate.upgrade_priority.is_irrelevant()
                && !tx_upgrade_filter.matches(candidate_txid)
            {
                continue;
            }

            return Some((
                &transaction.kernel,
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
    /// May return transactions that are *not* synced to the latest tip. Raising
    /// a `ProofCollection` to a `SingleProof` does not depend on the mutator
    /// set, so an unsynced `ProofCollection` can be raised and then cheaply
    /// updated to the current tip afterwards.
    ///
    /// Also returns the upgrade priority of this transactions, for the node
    /// operator.
    pub fn preferred_proof_collection(
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

            if self.upgrade_failures.contains(&candidate_txid) {
                continue;
            }

            let Some(candidate_tx) = candidate.transaction.as_standard() else {
                continue;
            };

            let TransactionProof::ProofCollection(proof_collection) = &candidate_tx.proof else {
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
                &candidate_tx.kernel,
                proof_collection,
                candidate.upgrade_priority,
            ));
        }

        None
    }

    /// Return the preferred link transaction for the "fix" proof upgrade,
    /// along with this node's priority for it: a proof-backed link
    /// transaction with no thruputs left, synced to the tip. Favors upgrade
    /// priority first, fee density second.
    ///
    /// Only transactions matching the filter will be returned, unless the
    /// mempool has been deemed to have a financial interest in the
    /// transaction, in which case the filter is ignored.
    pub fn preferred_link_fix(
        &self,
        tx_upgrade_filter: TxUpgradeFilter,
    ) -> Option<(&LinkTx, UpgradePriority)> {
        for candidate_txid in self
            .upgrade_priority_iter()
            .map(|(txid, _)| txid)
            .chain(self.fee_density_iter().map(|(txid, _)| txid))
        {
            let candidate = self.tx_dictionary.get(&candidate_txid).unwrap();

            if self.upgrade_failures.contains(&candidate_txid) {
                continue;
            }

            let AnyTx::Link(link_tx) = &candidate.transaction else {
                continue;
            };

            if !link_tx.proof.is_proof()
                || !link_tx.kernel.thruputs.is_empty()
                || !self.tx_is_synced(&link_tx.kernel.kernel)
            {
                continue;
            }

            if candidate.upgrade_priority.is_irrelevant()
                && !tx_upgrade_filter.matches(candidate_txid)
            {
                continue;
            }

            return Some((link_tx, candidate.upgrade_priority));
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
    /// Will only return transactions that are synced to the latest tip, and
    /// none that retire within [`MERGE_RETIREMENT_MARGIN`].
    ///
    /// Returns the pair of transaction along with their sum of priorities.
    pub fn preferred_single_proof_pair(
        &self,
        tx_upgrade_filter: TxUpgradeFilter,
    ) -> Option<([(TransactionKernel, Proof); 2], UpgradePriority)> {
        let mut ret = vec![];
        let mut filter_mismatches = vec![];
        let mut priority = UpgradePriority::Irrelevant;
        let now = Timestamp::now();
        for candidate_txid in self
            .upgrade_priority_iter()
            .map(|(txid, _)| txid)
            .chain(self.fee_density_iter().map(|(txid, _)| txid))
        {
            let candidate = self.tx_dictionary.get(&candidate_txid).unwrap();

            if self.upgrade_failures.contains(&candidate_txid) {
                continue;
            }

            let Some(candidate_tx) = candidate.transaction.as_standard() else {
                continue;
            };

            if !self.tx_is_synced(&candidate_tx.kernel) {
                continue;
            }

            let TransactionProof::SingleProof(_) = &candidate_tx.proof else {
                continue;
            };

            // The merged transaction inherits this one's retirement, so a
            // candidate this close to retiring makes for a transaction that no
            // composer will pick.
            if candidate_tx
                .kernel
                .retires_before(now + MERGE_RETIREMENT_MARGIN)
            {
                continue;
            }

            // Do not attempt to merge transactions that neither have a value to
            // us nor pay a fee.
            if candidate.upgrade_priority.is_irrelevant() && candidate_tx.kernel.fee.is_zero() {
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
        let candidates = [left, right].map(|txid| {
            let t = self
                .tx_dictionary
                .get(&txid)
                .unwrap()
                .transaction
                .as_standard()
                .expect("selected candidates must be single-proof backed transactions");
            (t.kernel.to_owned(), t.proof.to_owned().into_single_proof())
        });
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
    /// Returns `None` for link-transactions.
    ///
    /// Computes in O(1) from HashMap
    pub fn get(&self, transaction_id: TransactionKernelId) -> Option<&Transaction> {
        self.tx_dictionary
            .get(&transaction_id)
            .and_then(|x| x.transaction.as_standard())
    }

    /// get transaction from mempool, with its associated upgrade priority.
    ///
    /// Returns `None` for link-transactions.
    ///
    /// Computes in O(1) from HashMap
    pub fn get_with_priority(
        &self,
        transaction_id: TransactionKernelId,
    ) -> Option<(&Transaction, UpgradePriority)> {
        self.tx_dictionary
            .get(&transaction_id)
            .and_then(|x| x.transaction.as_standard().map(|t| (t, x.upgrade_priority)))
    }

    /// get transaction from mempool, on whichever pipeline it is.
    ///
    /// Computes in O(1) from HashMap
    fn get_any(&self, transaction_id: TransactionKernelId) -> Option<&AnyTx> {
        self.tx_dictionary
            .get(&transaction_id)
            .map(|x| &x.transaction)
    }

    /// get link transaction from mempool, if that is what resides under this
    /// id.
    ///
    /// Computes in O(1) from HashMap
    pub fn get_link(&self, transaction_id: TransactionKernelId) -> Option<&LinkTx> {
        self.tx_dictionary
            .get(&transaction_id)
            .and_then(|x| match &x.transaction {
                AnyTx::Link(link) => Some(link.as_ref()),
                AnyTx::Standard(_) => None,
            })
    }

    /// Whether every given addition record is an output of some transaction
    /// currently in the mempool, on either pipeline.
    ///
    /// True for an empty list.
    ///
    /// Computes in O(total number of outputs in the mempool)
    pub fn contains_outputs(&self, addition_records: &[AdditionRecord]) -> bool {
        let mut missing: HashSet<&AdditionRecord> = addition_records.iter().collect();
        for mptx in self.tx_dictionary.values() {
            if missing.is_empty() {
                break;
            }
            for output in &mptx.transaction.kernel().outputs {
                missing.remove(output);
            }
        }

        missing.is_empty()
    }

    /// Returns an iterator over mempool items that are in conflict (not
    /// simultaneously confirmable) with the given transaction kernel.
    fn transactions_in_conflict_with(
        &self,
        kernel: &TransactionKernel,
    ) -> impl Iterator<Item = (&TransactionKernelId, &MempoolTransaction)> {
        // This check could be made a lot more efficient, for example with an invertible Bloom filter
        let tx_sbf_index_sets: HashSet<_> = kernel
            .inputs
            .iter()
            .map(|x| x.absolute_indices.to_array())
            .collect();

        self.tx_dictionary.iter().filter(move |(_txkid, mptx)| {
            mptx.transaction
                .kernel()
                .inputs
                .iter()
                .any(|rr| tx_sbf_index_sets.contains(&rr.absolute_indices.to_array()))
        })
    }

    /// Returns an iterator over mempool items that are either confirmed or made
    /// unconfirmable by the given block.
    fn transactions_kicked_by_block(
        &self,
        block: &Block,
    ) -> impl Iterator<Item = (&TransactionKernelId, &MempoolTransaction)> {
        self.transactions_in_conflict_with(block.body().transaction_kernel())
    }

    /// Returns an iterator over mempool items that are confirmed by the given
    /// block.
    fn transactions_confirmed_by_block(
        &self,
        block: &Block,
    ) -> impl Iterator<Item = (&TransactionKernelId, &MempoolTransaction)> {
        // Only consider transactions confirmed if all of their inputs are in
        // block transaction, and all of their outputs are also. Otherwise we
        // run the risk of mis-classifying transactions with overlapping inputs
        // or outputs.
        let kernel = block.body().transaction_kernel();
        let block_inputs = kernel
            .inputs
            .iter()
            .map(|removal_record| removal_record.absolute_indices)
            .collect::<HashSet<_>>();
        let block_outputs = kernel.outputs.iter().copied().collect::<HashSet<_>>();
        self.transactions_kicked_by_block(block)
            .filter(move |(_txkid, mptx)| {
                mptx.transaction
                    .kernel()
                    .outputs
                    .iter()
                    .all(|ar| block_outputs.contains(ar))
                    && mptx
                        .transaction
                        .kernel()
                        .inputs
                        .iter()
                        .all(|rr| block_inputs.contains(&rr.absolute_indices))
            })
    }

    /// Returns a list of [`TransactionKernelId`]s corresponding to mempool
    /// transactions that were initiated by us and are confirmed by the given
    /// block
    ///
    /// The presence of a [`PrimitiveWitness`] is used as an indicator to
    /// determine whether the transaction was initiated by us or not.
    pub fn own_transactions_confirmed_by_block(&self, block: &Block) -> Vec<TransactionKernelId> {
        self.transactions_confirmed_by_block(block)
            .filter_map(|(txkid, mptx)| {
                if mptx.primitive_witness.is_some() {
                    Some(*txkid)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Insert a transaction into the mempool. It is the caller's responsibility
    /// to validate the transaction.
    ///
    /// The caller must also ensure that the transaction does not have a
    /// timestamp in the too distant future, as such a transaction cannot be
    /// mined.
    ///
    /// Caller must specify the priority of the transaction to them.
    ///
    /// This method may return:
    ///   n events: RemoveTx,AddTx. Tx replaces a list of older txs with lower
    ///             fee.
    ///   1 event:  AddTx. tx does not replace an older one.
    ///   0 events: tx not added because an older conflicting tx has a higher
    ///             fee.
    pub fn insert(&mut self, new_tx: Transaction, priority: UpgradePriority) -> Vec<MempoolEvent> {
        // If transaction to be inserted conflicts with transactions already in
        // the mempool, we replace them -- but only if the new transaction has a
        // higher fee-density than the ones already in mempool, or if it has
        // a higher proof-quality, meaning that it's in a state more likely to
        // be picked up by a composer.
        // Consequently, merged transactions always replace those transactions
        // that were merged since the merged transaction is *very* likely to
        // have a higher fee density that the lowest one of the ones that were
        // merged.
        let conflicts: HashMap<TransactionKernelId, &AnyTx> = self
            .transactions_in_conflict_with(&new_tx.kernel)
            .map(|(txkid, mptx)| (*txkid, &mptx.transaction))
            .collect();

        // Do not insert an existing transaction again, if its an exact copy.
        let txid = new_tx.txid();
        if let Some(existing_tx) = conflicts.get(&txid)
            && existing_tx.as_standard() == Some(&new_tx)
        {
            return vec![];
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

        // A transaction's upgrade priority reflects our financial interest in
        // seeing it confirmed, and that interest does not vanish when the
        // transaction is superseded. A copy that reaches us over the wire is
        // inserted with `Irrelevant` priority — whether it's our own
        // transaction gossiped back, or, more importantly, a third party's
        // merge that folded our inputs and outputs into a larger transaction.
        // A merge carries a *new* txid, but it still conflicts with (and, when
        // inserted below, kicks out) our original transaction. So the inserted
        // transaction must inherit at least the highest priority among the
        // conflicts it replaces; otherwise the mempool would stop
        // mutator-set-updating the transaction carrying our funds. Compute this
        // before the conflicting transactions are removed below.
        let priority = conflicts
            .keys()
            .filter_map(|conflicting_txid| self.tx_dictionary.get(conflicting_txid))
            .map(|conflicting| conflicting.upgrade_priority)
            .fold(priority, |acc, conflicting| acc.max(conflicting));

        let mut events = vec![];
        let new_tier = match &new_tx.proof {
            TransactionProof::Witness(_) => ContestTier::Witness,
            TransactionProof::ProofCollection(_) => ContestTier::Intermediate,
            TransactionProof::SingleProof(_) => ContestTier::SingleProof,
        };
        let new_tx_has_higher_proof_quality = new_tx_wins_by_quality(
            new_tier,
            txid,
            new_tx.kernel.mutator_set_hash,
            &conflicts,
            self.tip_mutator_set_hash,
        );
        let new_tx_fee_density = new_tx.fee_density();
        let min_fee_of_conflicts = conflicts.values().map(|tx| tx.fee_density()).min();
        let conflicts = conflicts
            .into_iter()
            .map(|x| {
                (
                    x.0,
                    x.1.as_standard().and_then(|t| t.proof.as_single_proof()),
                )
            })
            .collect_vec();
        if let Some(min_fee_of_conflicting_tx) = min_fee_of_conflicts {
            let better_fee_density = min_fee_of_conflicting_tx < new_tx_fee_density;
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
                    if let Some(old_proof) = single_proof
                        && new_tx.proof.is_single_proof()
                        && TransactionKernel::have_merge_relationship(&new_tx.kernel, removed)
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
        self.fee_densities.push(txid, new_tx_fee_density);
        events.push(MempoolEvent::AddTx(new_tx.kernel.clone()));
        let new_tx = MempoolTransaction {
            transaction: AnyTx::Standard(Box::new(new_tx)),
            upgrade_priority: priority,
            primitive_witness,
        };
        if let Some(removed) = self.tx_dictionary.insert(txid, new_tx) {
            events.push(MempoolEvent::RemoveTx(removed.transaction.into_kernel()));
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

    /// Insert a link transaction into the mempool. It is the caller's
    /// responsibility to validate the transaction.
    ///
    /// Every thruput must be an output of a transaction currently in the
    /// mempoolm an unmined, known predecessor. A link transaction whose
    /// thruputs are not all accounted for is refused: it may be stranded
    /// already (its predecessor confirmed or never seen), and holding it risks
    /// filling the mempool.
    ///
    /// Conflicts on shared confirmed inputs follow the same replacement
    /// contest as [`Self::insert`].
    ///
    /// This method may return the same events as [`Self::insert`].
    pub fn insert_link(
        &mut self,
        new_link: LinkTx,
        priority: UpgradePriority,
    ) -> Vec<MempoolEvent> {
        let txid = new_link.txid();

        if !self.contains_outputs(&new_link.kernel.thruputs) {
            debug!("Attempted to insert link transaction with unknown thruputs.");
            return vec![];
        }

        let mut same_id_win = false;
        if let Some(existing) = self.get_any(txid) {
            let AnyTx::Link(existing) = existing else {
                return vec![];
            };

            // Do not insert an existing link transaction again, if its an
            // exact copy.
            if **existing == new_link {
                return vec![];
            }

            same_id_win = match (existing.proof.is_proof(), new_link.proof.is_proof()) {
                (false, true) => true,
                (true, false) => false,
                _ => {
                    !self.tx_is_synced(&existing.kernel.kernel)
                        && self.tx_is_synced(&new_link.kernel.kernel)
                }
            };
            if !same_id_win {
                return vec![];
            }
        }

        let mut conflicts: HashMap<TransactionKernelId, &AnyTx> = self
            .transactions_in_conflict_with(&new_link.kernel.kernel)
            .map(|(txkid, mptx)| (*txkid, &mptx.transaction))
            .collect();
        if same_id_win && let Some(existing) = self.tx_dictionary.get(&txid) {
            conflicts.insert(txid, &existing.transaction);
        }

        let new_tier = if new_link.proof.is_proof() {
            ContestTier::Intermediate
        } else {
            ContestTier::Witness
        };
        let quality_win = same_id_win
            || new_tx_wins_by_quality(
                new_tier,
                txid,
                new_link.kernel.kernel.mutator_set_hash,
                &conflicts,
                self.tip_mutator_set_hash,
            );
        let new_link_fee_density = new_link.fee_density();
        let min_fee_of_conflicts = conflicts.values().map(|tx| tx.fee_density()).min();
        let victims = conflicts.keys().copied().collect_vec();

        // The inserted link must inherit at least the highest priority among
        // the conflicts it replaces; see [`Self::insert`].
        let priority = victims
            .iter()
            .filter_map(|conflicting_txid| self.tx_dictionary.get(conflicting_txid))
            .map(|conflicting| conflicting.upgrade_priority)
            .fold(priority, |acc, conflicting| acc.max(conflicting));

        let mut events = vec![];
        if let Some(min_fee_of_conflicting_tx) = min_fee_of_conflicts {
            let better_fee_density = min_fee_of_conflicting_tx < new_link_fee_density;
            if !(quality_win || better_fee_density) {
                debug!(
                    "Attempted to insert link transaction into mempool but it's \
                     fee density was eclipsed by another transaction."
                );
                return events;
            }

            // Links do not participate in the merge-input cache; conflicts
            // are simply removed.
            for conflicting_txid in victims {
                let e = self
                    .remove(conflicting_txid)
                    .unwrap_or_else(|| panic!("Reported conflict {conflicting_txid} must exist"));
                events.push(e);
            }
        }

        self.fee_densities.push(txid, new_link_fee_density);
        events.push(MempoolEvent::AddTx(new_link.kernel.kernel.clone()));
        let new_link = MempoolTransaction {
            transaction: AnyTx::Link(Box::new(new_link)),
            upgrade_priority: priority,
            primitive_witness: None,
        };
        if let Some(removed) = self.tx_dictionary.insert(txid, new_link) {
            events.push(MempoolEvent::RemoveTx(removed.transaction.into_kernel()));
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
    pub fn remove(&mut self, transaction_id: TransactionKernelId) -> Option<MempoolEvent> {
        self.tx_dictionary.remove(&transaction_id).map(|tx| {
            self.fee_densities.remove(&transaction_id);
            self.upgrade_priorities.remove(&transaction_id);
            debug_assert_eq!(self.tx_dictionary.len(), self.fee_densities.len());
            MempoolEvent::RemoveTx(tx.transaction.into_kernel())
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
    pub fn update_primitive_witness(
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
    pub fn clear(&mut self) -> Vec<MempoolEvent> {
        // note: this causes event listeners to be notified of each removed tx.
        self.merge_input_cache.clear();
        self.retain(|_| false)
    }

    /// Return the number of transactions currently stored in the Mempool.
    /// Computes in O(1)
    pub fn len(&self) -> usize {
        self.tx_dictionary.len()
    }

    /// Return the number of transactions with the specified proof quality that
    /// are present in the mempool.
    pub fn num_with_proof_type(&self, proof_quality: TransactionProofType) -> usize {
        let mut count = 0;
        for (txid, _) in self.fee_density_iter() {
            let tx = self
                .get_any(txid)
                .expect("Transaction referenced in fee density iter must exist in mempool.");
            if tx
                .as_standard()
                .is_some_and(|t| t.proof.proof_type() == proof_quality)
            {
                count += 1;
            }
        }

        count
    }

    /// Return the number of transaction stored in the mempool that are deemed
    /// relevant for this node.
    ///
    /// Computes in O(1)
    pub fn num_own_txs(&self) -> usize {
        self.upgrade_priorities.len()
    }

    /// Return the transactions in the mempool matching the selection criteria.
    fn with_matching_puts_inner(
        &self,
        match_method: TxMatcher,
    ) -> Vec<(TransactionKernel, Option<usize>)> {
        if match_method.is_empty() {
            return vec![];
        }

        // Build the matcher closure once
        let is_match: Box<dyn Fn(&MempoolTransaction) -> bool> = match match_method {
            TxMatcher::Inputs(index_sets) => Box::new(move |tx| {
                tx.transaction
                    .kernel()
                    .inputs
                    .iter()
                    .any(|ais| index_sets.contains(&ais.absolute_indices))
            }),
            TxMatcher::Outputs(addition_records) => Box::new(move |tx| {
                tx.transaction
                    .kernel()
                    .outputs
                    .iter()
                    .any(|ar| addition_records.contains(ar))
            }),
        };

        let mut matching_txs_with_queue_position = vec![];
        let mut queue_count = 0;
        for (txid, _fee_density) in self.fee_density_iter() {
            let tx = self
                .tx_dictionary
                .get(&txid)
                .expect("Txid returned by fee density iter must match tx in mempool");

            let sp_backed_and_synced = tx
                .transaction
                .as_standard()
                .is_some_and(|t| t.proof.is_single_proof())
                && tx.transaction.kernel().mutator_set_hash == self.tip_mutator_set_hash;
            if is_match(tx) {
                let queue_position = if sp_backed_and_synced {
                    Some(queue_count)
                } else {
                    None
                };

                matching_txs_with_queue_position
                    .push((tx.transaction.kernel().clone(), queue_position));
            }

            if sp_backed_and_synced {
                queue_count += 1;
            }
        }

        matching_txs_with_queue_position
    }

    /// Return (transaction, queue position) pairs for all transactions in the
    /// mempool that have at least one of the specified addition records. Only
    /// single proof-backed transactions with synced/updated proofs have an
    /// associated queue position. If the transaction is not single
    /// proof-backed, or it is not synced, the queue position is `None`.
    pub fn with_matching_addition_records(
        &self,
        addition_records: &HashSet<AdditionRecord>,
    ) -> Vec<(TransactionKernel, Option<usize>)> {
        self.with_matching_puts_inner(TxMatcher::Outputs(addition_records))
    }

    /// Return (transaction, queue position) pairs for all transactions in the
    /// mempool that have at least one of the specified absolute index sets.
    /// Only single proof-backed transactions with synced/updated proofs have an
    /// associated queue position. If the transaction is not single proof-
    /// backed, or it is not synced, the queue position is `None`.
    pub fn with_matching_absolute_index_sets(
        &self,
        absolute_index_sets: &HashSet<AbsoluteIndexSet>,
    ) -> Vec<(TransactionKernel, Option<usize>)> {
        self.with_matching_puts_inner(TxMatcher::Inputs(absolute_index_sets))
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
    /// Number of transactions returned can be capped by either kernel size
    /// (measured in number of b-field elements when encoded), or by transaction
    /// count. The function guarantees that neither of the specified limits will
    /// be exceeded. Additionally, the total number of inputs, outputs, and
    /// announcements across the returned transactions is guaranteed to respect
    /// the caps imposed by the consensus rules, with room to spare for the
    /// coinbase transaction that the returned transactions are expected to be
    /// merged with.
    ///
    /// The size limit is checked against the projected kernel size of the
    /// block transaction resulting from merging all returned transactions.
    /// This projection accounts for the packing of the input removal records,
    /// cf. [`RemovalRecordList::pack`], which deduplicates authentication data
    /// shared between removal records. So many more transactions may fit
    /// within the limit than their stand-alone kernel sizes would suggest.
    ///
    /// # Panics
    ///
    /// Panics if the removal records of the tip-synced transactions in the
    /// mempool are invalid or mutually inconsistent, as this indicates a
    /// programmer error.
    pub fn get_transactions_for_block_composition(
        &self,
        consensus_rule_set: ConsensusRuleSet,
        max_kernel_size: usize,
        max_num_txs: Option<usize>,
    ) -> Vec<Transaction> {
        // Numbers of outputs and announcements reserved for the coinbase
        // transaction that the returned transactions will be merged with. No
        // reservation is needed for inputs since the coinbase transaction has
        // none.
        const COINBASE_NUM_OUTPUTS_RESERVATION: usize = 128;
        const COINBASE_NUM_ANNOUNCEMENTS_RESERVATION: usize = 128;

        // Packing usually shrinks the inputs but can, in degenerate cases,
        // grow them by a few b-field elements per tree in the SWBFI MMR. So
        // the sum of stand-alone kernel sizes plus this slack bounds the
        // projected kernel size from above.
        const FAST_PATH_SLACK: usize = 1_000;

        let mut remaining_num_inputs = consensus_rule_set.max_num_inputs();
        let mut remaining_num_outputs = consensus_rule_set
            .max_num_outputs()
            .saturating_sub(COINBASE_NUM_OUTPUTS_RESERVATION);
        let mut remaining_num_announcements = consensus_rule_set
            .max_num_announcements()
            .saturating_sub(COINBASE_NUM_ANNOUNCEMENTS_RESERVATION);

        // The kernel of the block transaction contains the packed union of the
        // merged transactions' inputs and the concatenation of their other
        // dynamically sized fields. So the projected kernel size is the sum of
        // the selected kernels' sizes without their inputs fields, plus the
        // size of the packed union of all selected inputs. Fixed-size fields
        // (fee, timestamp, etc.) are counted once per selected transaction
        // even though merging collapses them into one, making the projection
        // a slight overestimate.
        let mut selected_inputs: Vec<RemovalRecord> = vec![];
        let mut kernel_wo_inputs_size_acc = 0;
        let mut full_kernel_size_acc = 0;

        let mut transactions = vec![];

        let now = Timestamp::now();

        for (txkid, _fee_density) in self.fee_density_iter() {
            if max_num_txs.is_some_and(|max| transactions.len() == max) {
                break;
            }

            if let Some(transaction_ptr) = self.get(txkid) {
                // Only return transaction synced to tip
                if !self.tx_is_synced(&transaction_ptr.kernel) {
                    continue;
                }

                if !matches!(transaction_ptr.proof, TransactionProof::SingleProof(_)) {
                    continue;
                }

                if transaction_ptr
                    .kernel
                    .retires_before(now + MEMPOOL_RETIREMENT_MARGIN)
                {
                    continue;
                }

                let kernel = &transaction_ptr.kernel;
                if kernel.inputs.len() > remaining_num_inputs
                    || kernel.outputs.len() > remaining_num_outputs
                    || kernel.announcements.len() > remaining_num_announcements
                {
                    continue;
                }

                let full_kernel_size = kernel.encode().len();

                // A dynamically sized kernel field's encoding is prepended
                // with one length-indicating b-field element, hence the +/- 1.
                let kernel_wo_inputs_size = full_kernel_size - kernel.inputs.encode().len() - 1;

                // Only compute the exact size when the cheap and conservative
                // check is inconclusive.
                if full_kernel_size_acc + full_kernel_size + FAST_PATH_SLACK > max_kernel_size {
                    let mut all_inputs = selected_inputs.clone();
                    all_inputs.extend_from_slice(&kernel.inputs);
                    let packed_inputs_field_size =
                        RemovalRecordList::pack(all_inputs).encode().len() + 1;

                    // Current transaction is too big
                    if kernel_wo_inputs_size_acc + kernel_wo_inputs_size + packed_inputs_field_size
                        > max_kernel_size
                    {
                        continue;
                    }
                }

                // Include transaction
                selected_inputs.extend_from_slice(&kernel.inputs);
                full_kernel_size_acc += full_kernel_size;
                kernel_wo_inputs_size_acc += kernel_wo_inputs_size;
                remaining_num_inputs -= kernel.inputs.len();
                remaining_num_outputs -= kernel.outputs.len();
                remaining_num_announcements -= kernel.announcements.len();
                transactions.push(transaction_ptr.to_owned())
            }
        }

        transactions
    }

    /// Removes the transaction with the lowest [`FeeDensity`] from the mempool.
    /// Returns the removed value.
    ///
    /// Computes in θ(lg N)
    fn pop_min(&mut self) -> Option<(MempoolEvent, FeeDensity)> {
        if let Some((txkid, fee_density)) = self.fee_densities.pop_min()
            && let Some(tx) = self.tx_dictionary.remove(&txkid)
        {
            self.upgrade_priorities.remove(&txkid);

            debug_assert_eq!(self.tx_dictionary.len(), self.fee_densities.len());

            let event = MempoolEvent::RemoveTx(tx.transaction.into_kernel());

            return Some((event, fee_density));
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
            let transaction = self.get_any(transaction_id).unwrap();
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
    /// timestamp, or that retire so soon that they will not be composed with
    /// again. Prunes based on the transaction's timestamp and on its
    /// retirement announcements, if any.
    ///
    /// Computes in O(n)
    pub fn prune_stale_transactions(&mut self) -> Vec<MempoolEvent> {
        let now = Timestamp::now();
        let cutoff = now - MEMPOOL_TX_THRESHOLD_AGE;

        let keep = |(_transaction_id, transaction): LookupItem| -> bool {
            let kernel = transaction.kernel();

            cutoff < kernel.timestamp && !kernel.retires_before(now + MEMPOOL_RETIREMENT_MARGIN)
        };

        self.retain(keep)
    }

    /// Remove from the mempool all transactions that become invalid because
    /// of a newly received block. Return a description of the transactions for
    /// which a primitive witness is present such that the caller can update
    /// their mutator set data.
    ///
    /// Fails if the provided block does not have a mutator set after.
    pub fn update_with_block(
        &mut self,
        new_block: &Block,
    ) -> anyhow::Result<(Vec<MempoolEvent>, Vec<MempoolUpdateJob>)> {
        // Ensure transactions are not permanently block on transient upgrade
        // failures.
        self.upgrade_failures.clear();

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
                .kernel()
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

        // Remove link transactions with a mined thruput. Such a thruput can
        // never be cut through.
        let block_outputs: HashSet<AdditionRecord> = new_block
            .kernel
            .body
            .transaction_kernel
            .outputs
            .iter()
            .copied()
            .collect();
        let no_mined_thruput = |(_transaction_id, tx): LookupItem| -> bool {
            match tx {
                AnyTx::Standard(_) => true,
                AnyTx::Link(link) => link
                    .kernel
                    .thruputs
                    .iter()
                    .all(|thruput| !block_outputs.contains(thruput)),
            }
        };
        {
            let removed = self.retain(no_mined_thruput);
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
            // Transactions without inputs are always kicked out of the mempool,
            // as they cannot be updated. All other transactions are kept in the
            // mempool and only removed once they become double-spends (one of
            // their inputs were mined), or they expire (their age exceeds a
            // threshold).
            // An all-thruputs link transaction also has no confirmed inputs,
            // but that one can be updated, so it gets to stay.
            let is_all_thruputs_link =
                matches!(&tx.transaction, AnyTx::Link(link) if !link.kernel.thruputs.is_empty());
            if tx.transaction.kernel().inputs.is_empty() && !is_all_thruputs_link {
                debug!("Not updating transaction since empty transactions cannot be updated.");
                kick_outs.push(*tx_id);
                continue;
            }

            let AnyTx::Standard(transaction) = &tx.transaction else {
                // If the link transaction was initiated locally, i.e. deemed
                // critical, *and* the node can produce single-proof class
                // proofs, it should be updated immediately (and be kept in the
                // mempool). A witness-backed link needs no job: its witness is
                // updated by the wallet when it forges.
                if let AnyTx::Link(link) = &tx.transaction
                    && self.tx_proving_capability == TxProvingCapability::SingleProof
                    && tx.upgrade_priority == UpgradePriority::Critical
                    && link.proof.is_proof()
                {
                    update_jobs.push(MempoolUpdateJob::Link {
                        old_link_tx: link.clone(),
                    });
                }
                continue;
            };

            let update_job = match &transaction.proof {
                // Proof-collection backed transaction cannot be updated
                // directly. But if the transaction was initiated locally, the
                // primitive witness will be known, and it can be updated to the
                // new mutator set immediately.
                TransactionProof::ProofCollection(_) => {
                    if let Some(pw) = &tx.primitive_witness {
                        let pw_update_job = PrimitiveWitnessUpdate::new(pw.to_owned());
                        let pw_update_job = MempoolUpdateJob::ProofCollection(pw_update_job);
                        Some(pw_update_job)
                    } else {
                        None
                    }
                }

                // Primitive witness-backed transactions can easily be updated.
                TransactionProof::Witness(pw) => {
                    let pw_update_job = PrimitiveWitnessUpdate::new(pw.to_owned());
                    let pw_update_job = MempoolUpdateJob::PrimitiveWitness(pw_update_job);
                    Some(pw_update_job)
                }

                // If the transaction was initiated locally, i.e. deemed
                // critical, *and* node can produce single-proofs, transaction
                // should be updated immediately (and be kept in mempool).
                TransactionProof::SingleProof(sp) => {
                    if self.tx_proving_capability == TxProvingCapability::SingleProof
                        && tx.upgrade_priority == UpgradePriority::Critical
                    {
                        // Node initiated transaction and can update.
                        let update_sp = MempoolUpdateJob::SingleProof {
                            old_kernel: transaction.kernel.clone(),
                            old_single_proof: sp.to_owned(),
                        };

                        Some(update_sp)
                    } else {
                        None
                    }
                }
            };

            if let Some(update_job) = update_job {
                update_jobs.push(update_job);
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
    /// use neptune_primitives::network::Network;
    /// use neptune_consensus::block::Block;
    /// use neptune_mempool::mempool::Mempool;
    /// use neptune_consensus::proof_abstractions::tx_proving_capability::TxProvingCapability;
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

/// Test-support surface for the mempool.
///
/// These accessors and mutators reach into `Mempool`'s private internals for
/// the benefit of tests — including tests in downstream crates (e.g.
/// `neptune-core`), which is why they are `pub` and gated behind the
/// `test-helpers` feature rather than left as private test-module helpers.
/// None of this is part of the mempool's production API.
#[cfg(any(test, feature = "test-helpers"))]
impl Mempool {
    /// Mutable reference to a stored transaction. Computes in O(1).
    ///
    /// Returns `None` for link-transactions.
    pub fn get_mut(&mut self, transaction_id: TransactionKernelId) -> Option<&mut Transaction> {
        self.tx_dictionary
            .get_mut(&transaction_id)
            .and_then(|x| x.transaction.as_standard_mut())
    }

    /// The digest of the chain tip the mempool is currently synced to.
    pub fn tip_digest(&self) -> Digest {
        self.tip_digest
    }

    /// Overwrite the recorded tip digest, to simulate reorganizations.
    pub fn set_tip_digest(&mut self, tip_digest: Digest) {
        self.tip_digest = tip_digest;
    }

    /// Overwrite the recorded tip mutator-set hash, to simulate confirmability.
    pub fn set_tip_mutator_set_hash(&mut self, tip_mutator_set_hash: Digest) {
        self.tip_mutator_set_hash = tip_mutator_set_hash;
    }

    /// Number of entries in the merge-input cache.
    pub fn merge_input_cache_len(&self) -> usize {
        self.merge_input_cache.len()
    }

    /// Whether the merge-input cache is empty.
    pub fn merge_input_cache_is_empty(&self) -> bool {
        self.merge_input_cache.is_empty()
    }

    /// Whether the stored transaction still retains its primitive witness.
    pub fn primitive_witness_is_some(&self, transaction_id: TransactionKernelId) -> bool {
        self.tx_dictionary
            .get(&transaction_id)
            .is_some_and(|tx| tx.primitive_witness.is_some())
    }

    /// Bincode-serialized byte length of the internal transaction table. Used
    /// to assert relative in-memory sizes across mempools.
    pub fn tx_dictionary_serialized_len(&self) -> usize {
        bincode::serialize(&self.tx_dictionary)
            .expect("serializing tx_dictionary must succeed")
            .len()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashSet;

    use bytesize::ByteSize;
    use get_size2::GetSize;
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use neptune_consensus::block::Block;
    use neptune_consensus::block::test_helpers::invalid_empty_block_with_timestamp;
    use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
    use neptune_consensus::proof_abstractions::tx_proving_capability::TxProvingCapability;
    use neptune_consensus::transaction::Transaction;
    use neptune_consensus::transaction::TransactionProof;
    use neptune_consensus::transaction::announcement::Announcement;
    use neptune_consensus::transaction::primitive_witness::PrimitiveWitness;
    use neptune_consensus::transaction::test_helpers::make_mock_txs_with_primitive_witness_with_timestamp;
    use neptune_consensus::transaction::test_helpers::make_plenty_mock_transaction_supported_by_invalid_single_proofs;
    use neptune_consensus::transaction::test_helpers::make_plenty_mock_transaction_supported_by_primitive_witness;
    use neptune_consensus::transaction::test_helpers::mock_transactions_with_sized_single_proof;
    use neptune_consensus::transaction::test_helpers::txkernel;
    use neptune_consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use neptune_consensus::transaction::transaction_proof::TransactionProofType;
    use neptune_consensus::transaction::validity::proof_collection::ProofCollection;
    use neptune_mutator_set::addition_record::AdditionRecord;
    use neptune_mutator_set::msa_and_records::MsaAndRecords;
    use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
    use neptune_primitives::network::Network;
    use neptune_primitives::timestamp::Timestamp;
    use num_bigint::BigInt;
    use num_rational::BigRational as FeeDensity;
    use num_traits::Zero;
    use proptest::arbitrary::Arbitrary;
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use rand::Rng;
    use tasm_lib::prelude::Digest;
    use tasm_lib::twenty_first::prelude::BFieldCodec;
    use tracing_test::traced_test;

    use crate::mempool::MEMPOOL_RETIREMENT_MARGIN;
    use crate::mempool::MERGE_RETIREMENT_MARGIN;
    use crate::mempool::Mempool;
    use crate::mempool_event::MempoolEvent;
    use crate::test_utils::shared_tokio_runtime;
    use crate::transaction_kernel_id::Txid;
    use crate::transaction_proof_quality::TransactionProofQualityExt;
    use crate::tx_upgrade_filter::TxUpgradeFilter;
    use crate::upgrade_priority::UpgradePriority;

    const SIZE_20MB_IN_BYTES: usize = 20_000_000;

    /// Create a mempool with n transactions backed by either primitive witness,
    /// proof collection, or single proof. Transactions may be either synced or
    /// not synced from the the perspective of the mempool but in a broader
    /// context they are invalid.
    fn mock_mempool_mixed(num_txs: usize, sync_block: &Block) -> Mempool {
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::ProofCollection,
            sync_block,
        );

        let mut rng = rand::rng();

        let mutator_set_hash = sync_block.mutator_set_accumulator_after().unwrap().hash();
        let txs = make_plenty_mock_transaction_supported_by_primitive_witness(num_txs);
        for mut tx in txs {
            let proof_type = match rng.random_range(0..=2) {
                0 => TransactionProofType::PrimitiveWitness,
                1 => TransactionProofType::ProofCollection,
                2 => TransactionProofType::SingleProof,
                _ => unreachable!(),
            };
            tx.proof = proof_type.invalid();

            let is_synced = rng.random_bool(0.5);
            if is_synced {
                tx.kernel = TransactionKernelModifier::default()
                    .mutator_set_hash(mutator_set_hash)
                    .modify(tx.kernel);
            }

            mempool.insert(tx, UpgradePriority::Irrelevant);
        }

        mempool
    }

    /// Create a mempool with n single proof-backed transactions, all "synced"
    /// to the provided block.
    ///
    /// All transactions inserted into the mempool this way are invalid and
    /// cannot be included in any block.
    fn mock_mempool_singleproofs(num_txs: usize, sync_block: &Block) -> Mempool {
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::ProofCollection,
            sync_block,
        );
        let txs = make_plenty_mock_transaction_supported_by_invalid_single_proofs(num_txs);
        let mutator_set_hash = sync_block.mutator_set_accumulator_after().unwrap().hash();
        for mut tx in txs {
            tx.kernel = TransactionKernelModifier::default()
                .mutator_set_hash(mutator_set_hash)
                .modify(tx.kernel);
            mempool.insert(tx, UpgradePriority::Irrelevant);
        }

        assert_eq!(num_txs, mempool.len());

        mempool
    }

    #[traced_test]
    #[test]
    fn failed_upgrade_lets_the_next_upgrade_candidate_through() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let mutator_set_hash = genesis_block
            .mutator_set_accumulator_after()
            .unwrap()
            .hash();

        let mut mempool = mock_mempool_singleproofs(0, &genesis_block);
        for mut tx in make_plenty_mock_transaction_supported_by_primitive_witness(2) {
            tx.kernel = TransactionKernelModifier::default()
                .mutator_set_hash(mutator_set_hash)
                .modify(tx.kernel);
            tx.proof = TransactionProof::ProofCollection(ProofCollection::invalid());
            mempool.insert(tx, UpgradePriority::Irrelevant);
        }
        assert_eq!(2, mempool.len(), "sanity: two distinct candidates");

        let preferred = |pool: &Mempool| {
            pool.preferred_proof_collection(usize::MAX, TxUpgradeFilter::match_all())
                .map(|(kernel, _, _)| kernel.txid())
        };

        let first = preferred(&mempool).expect("sanity: a candidate must be picked");
        mempool.record_upgrade_failure([first]);

        let second = preferred(&mempool)
            .expect("a transaction whose upgrade failed must not block the next candidate");
        assert_ne!(
            first, second,
            "the failed candidate must not be picked again"
        );

        mempool.record_upgrade_failure([second]);
        assert!(
            preferred(&mempool).is_none(),
            "no candidate remains once every transaction's upgrade has failed"
        );

        // A new block gives both transactions another chance.
        let block1 = invalid_empty_block_with_timestamp(
            &genesis_block,
            genesis_block.header().timestamp + Timestamp::hours(1),
            network,
        );
        mempool.update_with_block(&block1).unwrap();
        assert_eq!(
            Some(first),
            preferred(&mempool),
            "a new block must clear the recorded upgrade failures"
        );
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

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn get_densest_transactions_no_tx_cap() {
        // Verify that transactions are returned ordered by fee density, with highest fee density first
        let num_txs = 10;
        let network = Network::Main;
        let sync_block = Block::genesis(network);
        let mempool = mock_mempool_singleproofs(num_txs, &sync_block);

        let max_fee_density: FeeDensity = FeeDensity::new(BigInt::from(u128::MAX), BigInt::from(1));
        let mut prev_fee_density = max_fee_density;
        for curr_transaction in mempool.get_transactions_for_block_composition(
            ConsensusRuleSet::default(),
            SIZE_20MB_IN_BYTES,
            None,
        ) {
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
        let mempool = mock_mempool_singleproofs(num_txs_in_mempool, &sync_block);

        for num_mergers in 0..=num_txs_in_mempool {
            let returned_transactions = mempool.get_transactions_for_block_composition(
                ConsensusRuleSet::default(),
                SIZE_20MB_IN_BYTES,
                Some(num_mergers),
            );
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
    async fn get_sorted_iter() {
        // Verify that the function `get_sorted_iter` returns transactions sorted by fee density
        let network = Network::Main;
        let sync_block = Block::genesis(network);
        let num_txs = 10;
        let mempool = mock_mempool_singleproofs(num_txs, &sync_block);

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
        let mempool = mock_mempool_singleproofs(num_txs, &sync_block);

        for i in 0..num_txs {
            assert_eq!(
                i,
                mempool
                    .get_transactions_for_block_composition(
                        ConsensusRuleSet::default(),
                        SIZE_20MB_IN_BYTES,
                        Some(i),
                    )
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
            let txs_returned = mempool.get_transactions_for_block_composition(
                ConsensusRuleSet::default(),
                max_total_tx_size,
                None,
            );
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
                    .get_transactions_for_block_composition(
                        ConsensusRuleSet::default(),
                        max_total_tx_size,
                        None,
                    )
                    .len(),
                "Must return {i}/{i} transaction when mutator set hashes do match"
            );
        }
    }

    #[test]
    fn transactions_retiring_within_the_margin_are_not_selected_for_block_composition() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let mutator_set_hash = genesis_block
            .mutator_set_accumulator_after()
            .unwrap()
            .hash();
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::ProofCollection,
            &genesis_block,
        );

        let now = Timestamp::now();
        let retirements = [
            now - Timestamp::hours(1),
            now + MEMPOOL_RETIREMENT_MARGIN - Timestamp::minutes(1),
            now + MEMPOOL_RETIREMENT_MARGIN + Timestamp::minutes(1),
        ];
        let txs = make_plenty_mock_transaction_supported_by_invalid_single_proofs(3);
        let txs = txs
            .into_iter()
            .zip(retirements)
            .map(|(mut tx, retirement)| {
                tx.kernel = TransactionKernelModifier::default()
                    .mutator_set_hash(mutator_set_hash)
                    .announcements(vec![Announcement::retirement(retirement)])
                    .modify(tx.kernel);
                tx
            })
            .collect_vec();
        for tx in &txs {
            mempool.insert(tx.to_owned(), UpgradePriority::Irrelevant);
        }
        assert_eq!(3, mempool.len());

        let selected = mempool.get_transactions_for_block_composition(
            ConsensusRuleSet::default(),
            SIZE_20MB_IN_BYTES,
            None,
        );

        assert_eq!(
            vec![txs[2].kernel.txid()],
            selected.iter().map(|tx| tx.kernel.txid()).collect_vec()
        );
    }

    #[test]
    fn transactions_without_retirement_announcements_are_selected_for_block_composition() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let mempool = mock_mempool_singleproofs(3, &genesis_block);

        assert_eq!(
            3,
            mempool
                .get_transactions_for_block_composition(
                    ConsensusRuleSet::default(),
                    SIZE_20MB_IN_BYTES,
                    None,
                )
                .len()
        );
    }

    #[test]
    fn transactions_retiring_within_the_margin_are_pruned() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::ProofCollection,
            &genesis_block,
        );

        let now = Timestamp::now();
        let announcements = [
            vec![Announcement::retirement(now - Timestamp::hours(1))],
            vec![Announcement::retirement(
                now + MEMPOOL_RETIREMENT_MARGIN - Timestamp::minutes(1),
            )],
            vec![Announcement::retirement(
                now + MEMPOOL_RETIREMENT_MARGIN + Timestamp::minutes(1),
            )],
            vec![],
        ];
        let txs = make_mock_txs_with_primitive_witness_with_timestamp(4, now);
        let txs = txs
            .into_iter()
            .zip(announcements)
            .map(|(mut tx, announcements)| {
                tx.kernel = TransactionKernelModifier::default()
                    .announcements(announcements)
                    .modify(tx.kernel);
                tx
            })
            .collect_vec();
        for tx in &txs {
            mempool.insert(tx.to_owned(), UpgradePriority::Irrelevant);
        }
        assert_eq!(4, mempool.len());

        mempool.prune_stale_transactions();

        assert!(!mempool.contains(txs[0].kernel.txid()));
        assert!(!mempool.contains(txs[1].kernel.txid()));
        assert!(mempool.contains(txs[2].kernel.txid()));
        assert!(mempool.contains(txs[3].kernel.txid()));
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
        assert!(
            mempool
                .get_transactions_for_block_composition(
                    ConsensusRuleSet::default(),
                    usize::MAX,
                    None
                )
                .is_empty()
        );
    }

    #[test]
    fn size_limit_accounts_for_input_packing() {
        // Build mutually consistent removal records, all valid against the
        // same mutator set, and distribute them across several transactions.
        let num_txs = 4;
        let inputs_per_tx = 4;
        let num_inputs = num_txs * inputs_per_tx;
        let aocl_size = 1u64 << 30;
        let removables =
            vec![(Digest::default(), Digest::default(), Digest::default()); num_inputs];
        let mut test_runner = TestRunner::deterministic();
        let msa_and_records = MsaAndRecords::arbitrary_with((removables, aocl_size))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let mutator_set_hash = msa_and_records.mutator_set_accumulator.hash();
        let removal_records = msa_and_records.unpacked_removal_records();

        let mut txs = make_plenty_mock_transaction_supported_by_invalid_single_proofs(num_txs);
        for (i, tx) in txs.iter_mut().enumerate() {
            let inputs = removal_records[i * inputs_per_tx..(i + 1) * inputs_per_tx].to_vec();
            tx.kernel = TransactionKernelModifier::default()
                .inputs(inputs)
                .mutator_set_hash(mutator_set_hash)
                .modify(tx.kernel.clone());
        }

        let genesis_block = Block::genesis(Network::Main);
        let mut mempool = Mempool::new(
            ByteSize::gb(1),
            TxProvingCapability::ProofCollection,
            &genesis_block,
        );
        mempool.tip_mutator_set_hash = mutator_set_hash;
        for tx in txs.clone() {
            mempool.insert(tx, UpgradePriority::Irrelevant);
        }
        assert_eq!(num_txs, mempool.len());

        // Projected size of the kernel of the block transaction merged from
        // all transactions, mirroring the calculation under test.
        let standalone_kernel_len_sum =
            txs.iter().map(|tx| tx.kernel.encode().len()).sum::<usize>();
        let non_inputs_kernel_len_sum = txs
            .iter()
            .map(|tx| tx.kernel.encode().len() - tx.kernel.inputs.encode().len() - 1)
            .sum::<usize>();
        let packed_inputs_field_len = RemovalRecordList::pack(removal_records).encode().len() + 1;
        let projected_kernel_len = non_inputs_kernel_len_sum + packed_inputs_field_len;
        assert!(
            projected_kernel_len < standalone_kernel_len_sum,
            "Test assumption: packing the inputs must save space"
        );

        let num_returned = |max_kernel_len: usize| {
            mempool
                .get_transactions_for_block_composition(
                    ConsensusRuleSet::default(),
                    max_kernel_len,
                    None,
                )
                .len()
        };

        // A limit that accommodates the packed projection but not the sum of
        // the stand-alone kernel sizes must admit all transactions.
        assert_eq!(num_txs, num_returned(standalone_kernel_len_sum - 1));
        assert_eq!(num_txs, num_returned(projected_kernel_len));

        // A limit just below the packed projection must reject exactly one
        // transaction.
        assert_eq!(num_txs - 1, num_returned(projected_kernel_len - 1));

        // Sanity check of tx-selector
        assert_eq!(0, num_returned(0));
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
        let txs = mock_transactions_with_sized_single_proof(
            num_insertions,
            ByteSize::kb(100).as_u64() as usize,
        );

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
        let mut txs = mock_transactions_with_sized_single_proof(
            num_insertions,
            ByteSize::mb(1).as_u64() as usize,
        );
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
        let mempool_small = mock_mempool_singleproofs(tx_count_small, &genesis_block);
        let size_gs_small = mempool_small.get_size();
        let size_serialized_small = mempool_small.tx_dictionary_serialized_len();
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
        let mempool_big = mock_mempool_singleproofs(tx_count_big, &genesis_block);
        let size_gs_big = mempool_big.get_size();
        let size_serialized_big = mempool_big.tx_dictionary_serialized_len();
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

    mod get_txs_based_on_inputs_or_outputs {
        use super::*;

        #[test_strategy::proptest(async = "tokio", cases = 2)]
        async fn return_empty_vec_on_empty_input_output_set(
            #[strategy(txkernel::with_lengths(1, 1, 1, true))]
        kernel: neptune_consensus::transaction::transaction_kernel::TransactionKernel,
            #[strategy(arb())] quality: TransactionProofType,
        ) {
            let tx = Transaction {
                kernel: kernel.clone(),
                proof: quality.invalid(),
            };
            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &Block::genesis(Network::Main),
            );
            mempool.set_tip_mutator_set_hash(kernel.mutator_set_hash);
            mempool.insert(tx, UpgradePriority::Irrelevant);

            assert!(
                mempool
                    .with_matching_absolute_index_sets(&HashSet::new())
                    .is_empty()
            );
            assert!(
                mempool
                    .with_matching_addition_records(&HashSet::new())
                    .is_empty()
            );
        }

        #[test_strategy::proptest(async = "tokio", cases = 20)]
        async fn one_tx_in_mempool(
            #[strategy(txkernel::with_lengths(3, 3, 3, true))]
        kernel: neptune_consensus::transaction::transaction_kernel::TransactionKernel,
            #[strategy(arb())] quality: TransactionProofType,
            #[strategy(arb())] has_synced_mutator_set: bool,
        ) {
            let tx = Transaction {
                kernel: kernel.clone(),
                proof: quality.invalid(),
            };
            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &Block::genesis(Network::Main),
            );
            mempool.insert(tx, UpgradePriority::Irrelevant);
            if has_synced_mutator_set {
                mempool.set_tip_mutator_set_hash(kernel.mutator_set_hash);
            }

            /* Test input picker */
            let all_sets: HashSet<AbsoluteIndexSet> =
                kernel.inputs.iter().map(|x| x.absolute_indices).collect();
            let mut index_setss: Vec<HashSet<AbsoluteIndexSet>> = vec![all_sets];
            for index_set in kernel.inputs.iter().map(|x| x.absolute_indices) {
                let index_set: HashSet<_> = [index_set].into_iter().collect();
                index_setss.push(index_set);
            }

            let has_expected_queue_order =
                has_synced_mutator_set && quality == TransactionProofType::SingleProof;

            for index_set in index_setss {
                let res = mempool.with_matching_absolute_index_sets(&index_set);
                if has_expected_queue_order {
                    assert_eq!(1, res.len());
                    let (returned_kernel, queue_pos) = &res[0];
                    assert_eq!(&kernel, returned_kernel);
                    assert_eq!(Some(0), *queue_pos);
                } else {
                    assert_eq!(1, res.len());
                    let (returned_kernel, queue_pos) = &res[0];
                    assert_eq!(&kernel, returned_kernel);
                    assert!(queue_pos.is_none());
                }
            }

            /* Test output picker */
            let all_outputs: HashSet<AdditionRecord> = kernel.outputs.iter().copied().collect();
            let mut output_sets: Vec<HashSet<AdditionRecord>> = vec![all_outputs];
            for output in &kernel.outputs {
                let output: HashSet<AdditionRecord> = [*output].into_iter().collect();
                output_sets.push(output);
            }

            for output_set in output_sets {
                let res = mempool.with_matching_addition_records(&output_set);
                if has_expected_queue_order {
                    assert_eq!(1, res.len());
                    let (returned_kernel, queue_pos) = &res[0];
                    assert_eq!(&kernel, returned_kernel);
                    assert_eq!(Some(0), *queue_pos);
                } else {
                    assert_eq!(1, res.len());
                    let (returned_kernel, queue_pos) = &res[0];
                    assert_eq!(&kernel, returned_kernel);
                    assert!(queue_pos.is_none());
                }
            }
        }

        #[apply(shared_tokio_runtime)]
        async fn queue_order_matches_density_ordering_when_all_txs_are_sp_and_synced() {
            // Generate mempool with 10 synced single proofs
            let mempool = mock_mempool_singleproofs(10, &Block::genesis(Network::Main));

            for (expected_queue_order, (txid, _)) in mempool.fee_density_iter().enumerate() {
                let tx = mempool.get(txid).unwrap();

                for output in &tx.kernel.outputs {
                    let output = [*output].into_iter().collect();
                    let res = mempool.with_matching_addition_records(&output);
                    assert_eq!(1, res.len());
                    let (returned_kernel, queue_pos) = &res[0];
                    assert_eq!(&tx.kernel, returned_kernel);
                    assert_eq!(Some(expected_queue_order), *queue_pos);
                }
            }
        }

        #[apply(shared_tokio_runtime)]
        async fn queue_order_matches_block_selection_order() {
            let mempool = mock_mempool_mixed(20, &Block::genesis(Network::Main));

            let txs_for_block_inclusion = mempool.get_transactions_for_block_composition(
                ConsensusRuleSet::default(),
                usize::MAX,
                None,
            );
            let txs_for_block_inclusion = txs_for_block_inclusion
                .into_iter()
                .map(|x| x.txid())
                .collect_vec();

            for (txid, _) in mempool.fee_density_iter() {
                let tx = mempool.get(txid).unwrap();
                let an_output = tx.kernel.outputs[0];
                let an_output = [an_output].into_iter().collect();
                let (_, queue_pos) = mempool.with_matching_addition_records(&an_output)[0].clone();
                let expected_queue_pos = txs_for_block_inclusion.iter().position(|x| *x == txid);

                assert_eq!(expected_queue_pos, queue_pos);
            }
        }
    }

    mod proof_upgrade_candidates {

        use proptest::prop_assert;
        use proptest::prop_assert_eq;
        use test_strategy::proptest;

        use super::*;

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

        #[test]
        fn merge_partner_is_never_a_transaction_retiring_within_the_margin() {
            use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

            let network = Network::Main;
            let genesis_block = Block::genesis(network);
            let mutator_set_hash = genesis_block
                .mutator_set_accumulator_after()
                .unwrap()
                .hash();
            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::ProofCollection,
                &genesis_block,
            );

            // The first transaction is the one seeking a partner. The second
            // retires within the margin, the third beyond it.
            let now = Timestamp::now();
            let txs = mock_txs_with_announcements(
                vec![
                    vec![],
                    vec![Announcement::retirement(
                        now + MERGE_RETIREMENT_MARGIN - Timestamp::minutes(1),
                    )],
                    vec![Announcement::retirement(
                        now + MERGE_RETIREMENT_MARGIN + Timestamp::minutes(1),
                    )],
                ],
                mutator_set_hash,
            );

            // Sole candidate retires within the margin, so there is no partner to
            // be had, however attractive it is on every other count.
            mempool.insert(txs[1].to_owned(), UpgradePriority::Irrelevant);
            let merge_partner = |mempool: &Mempool| {
                mempool.merge_partner(
                    &txs[0].kernel,
                    ConsensusRuleSet::default(),
                    NativeCurrencyAmount::zero(),
                )
            };
            assert!(merge_partner(&mempool).is_none());

            // Adding one that retires beyond the margin, that one is picked.
            mempool.insert(txs[2].to_owned(), UpgradePriority::Irrelevant);
            let (partner, _, _) = merge_partner(&mempool)
                .expect("transaction retiring beyond the margin is eligible");
            assert_eq!(txs[2].kernel.txid(), partner.txid());
        }

        #[test]
        fn preferred_single_proof_pair_skips_transactions_retiring_within_the_margin() {
            let network = Network::Main;
            let genesis_block = Block::genesis(network);
            let mutator_set_hash = genesis_block
                .mutator_set_accumulator_after()
                .unwrap()
                .hash();
            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::ProofCollection,
                &genesis_block,
            );

            // Only the last two are worth merging.
            let now = Timestamp::now();
            let txs = mock_txs_with_announcements(
                vec![
                    vec![Announcement::retirement(
                        now + MERGE_RETIREMENT_MARGIN - Timestamp::minutes(1),
                    )],
                    vec![Announcement::retirement(
                        now + MERGE_RETIREMENT_MARGIN + Timestamp::minutes(1),
                    )],
                    vec![],
                ],
                mutator_set_hash,
            );

            // With only one eligible transaction there is no pair to be had, the
            // transaction retiring within the margin notwithstanding.
            for tx in &txs[..2] {
                mempool.insert(tx.to_owned(), UpgradePriority::Irrelevant);
            }
            assert!(
                mempool
                    .preferred_single_proof_pair(TxUpgradeFilter::match_all())
                    .is_none()
            );

            // A second eligible transaction completes the pair.
            mempool.insert(txs[2].to_owned(), UpgradePriority::Irrelevant);
            let ([(left, _), (right, _)], _) = mempool
                .preferred_single_proof_pair(TxUpgradeFilter::match_all())
                .expect("two transactions retiring beyond the margin make a pair");

            assert_eq!(
                [txs[1].kernel.txid(), txs[2].kernel.txid()]
                    .into_iter()
                    .collect::<HashSet<_>>(),
                [left.txid(), right.txid()]
                    .into_iter()
                    .collect::<HashSet<_>>(),
            );
        }

        #[test]
        fn transaction_retiring_within_the_margin_gets_no_merge_partner() {
            use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

            let network = Network::Main;
            let genesis_block = Block::genesis(network);
            let mutator_set_hash = genesis_block
                .mutator_set_accumulator_after()
                .unwrap()
                .hash();
            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::ProofCollection,
                &genesis_block,
            );

            let now = Timestamp::now();
            let txs = mock_txs_with_announcements(
                vec![
                    vec![Announcement::retirement(
                        now + MERGE_RETIREMENT_MARGIN - Timestamp::minutes(1),
                    )],
                    vec![],
                    vec![],
                ],
                mutator_set_hash,
            );
            mempool.insert(txs[2].to_owned(), UpgradePriority::Irrelevant);

            let merge_partner = |kernel| {
                mempool.merge_partner(
                    kernel,
                    ConsensusRuleSet::default(),
                    NativeCurrencyAmount::zero(),
                )
            };

            assert!(
                merge_partner(&txs[0].kernel).is_none(),
                "transaction retiring within the margin must not be merged at all"
            );
            assert!(
                merge_partner(&txs[1].kernel).is_some(),
                "and the same mempool must serve a partner to a transaction that does not retire"
            );
        }

        /// One single-proof transaction per announcement list, all synced to the
        /// same mutator set and all paying a fee that clears any minimum.
        fn mock_txs_with_announcements(
            announcements: Vec<Vec<Announcement>>,
            mutator_set_hash: Digest,
        ) -> Vec<Transaction> {
            use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

            make_plenty_mock_transaction_supported_by_invalid_single_proofs(announcements.len())
                .into_iter()
                .zip(announcements)
                .map(|(mut tx, announcements)| {
                    tx.kernel = TransactionKernelModifier::default()
                        .mutator_set_hash(mutator_set_hash)
                        .announcements(announcements)
                        .fee(NativeCurrencyAmount::coins(1))
                        .modify(tx.kernel);
                    tx
                })
                .collect_vec()
        }
    }

    mod proof_quality_tests {
        use neptune_consensus::block::mutator_set_update::MutatorSetUpdate;
        use proptest::prop_assert;
        use proptest::prop_assert_eq;
        use proptest::prop_assert_ne;
        use proptest::prop_assume;
        use test_strategy::proptest;

        use super::*;

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
            mempool.set_tip_mutator_set_hash(updated_tx.kernel.mutator_set_hash);

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

        /// Regression test: a transaction inserted with a *lower* priority that
        /// kicks out higher-priority conflicts must inherit their priority.
        ///
        /// The motivating case: we initiate transaction `a` (`Critical`). A
        /// third party merges `a` with their own transaction `b` into `c`. `c`
        /// carries our inputs and outputs (so it conflicts with, and replaces,
        /// `a`) but has a *new* txid and reaches us over the wire as
        /// `Irrelevant`. If `c` kept `Irrelevant`, the mempool would stop
        /// mutator-set-updating the transaction that now carries our funds
        /// (both `update_with_block` and `preferred_update` gate updating single
        /// proofs on the stored `Critical` priority).
        #[proptest(cases = 15, async = "tokio")]
        async fn merge_received_over_wire_inherits_replaced_priority(
            #[strategy(1usize..10)] _num_inputs_own: usize,
            #[strategy(1usize..10)] _num_outputs_own: usize,
            #[strategy(1usize..10)] _num_inputs_foreign: usize,
            #[strategy(1usize..10)] _num_outputs_foreign: usize,
            #[strategy(PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets(
            [(#_num_inputs_own, #_num_outputs_own, 0),
            (#_num_inputs_foreign, #_num_outputs_foreign, 0),],
    ))]
            pws: [PrimitiveWitness; 2],
        ) {
            use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

            // Transactions in the mempool do not need to be valid, so we just
            // pretend that the primitive-witness backed transactions have a
            // SingleProof. Skip cases where the (arbitrary) mutator set happens
            // to match the genesis tip, so the transactions count as unsynced.
            let genesis_block = Block::genesis(Network::Main);
            let genesis_ms_hash = genesis_block
                .mutator_set_accumulator_after()
                .unwrap()
                .hash();
            let [own_pw, foreign_pw] = pws;
            prop_assume!(own_pw.kernel.mutator_set_hash != genesis_ms_hash);

            // Our transaction, with a small fee.
            let own_kernel = TransactionKernelModifier::default()
                .fee(NativeCurrencyAmount::from_nau(1))
                .modify(own_pw.kernel);
            let own_tx = Transaction {
                kernel: own_kernel.clone(),
                proof: TransactionProof::invalid(),
            };

            // A third party's merge of our transaction with theirs: it carries
            // both parties' inputs and outputs (so it conflicts with `own_tx`),
            // a large combined fee (so it wins the fee-density replacement), and
            // therefore a new txid.
            let merged_kernel = TransactionKernelModifier::default()
                .inputs([own_kernel.inputs.clone(), foreign_pw.kernel.inputs.clone()].concat())
                .outputs(
                    [
                        own_kernel.outputs.clone(),
                        foreign_pw.kernel.outputs.clone(),
                    ]
                    .concat(),
                )
                .fee(NativeCurrencyAmount::coins(1))
                .modify(own_kernel);
            let merged_tx = Transaction {
                kernel: merged_kernel,
                proof: TransactionProof::invalid(),
            };
            prop_assert_ne!(own_tx.kernel.txid(), merged_tx.kernel.txid());

            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &genesis_block,
            );

            // We initiated `own_tx`, so it enters the mempool as `Critical`.
            mempool.insert(own_tx.clone(), UpgradePriority::Critical);

            // The merge arrives over the wire as `Irrelevant`. It kicks out
            // `own_tx` (shared inputs, higher combined fee density) ...
            mempool.insert(merged_tx.clone(), UpgradePriority::Irrelevant);
            prop_assert!(
                !mempool.contains(own_tx.kernel.txid()),
                "merge must replace our transaction"
            );
            prop_assert!(mempool.contains(merged_tx.kernel.txid()));

            // ... but must inherit our `Critical` interest so the mempool keeps
            // mutator-set-updating the transaction carrying our funds. The
            // transactions are unsynced relative to the genesis tip, so
            // `preferred_update` returns the merge along with its stored
            // priority.
            let (returned_kernel, _, priority) = mempool
                .preferred_update(TxUpgradeFilter::match_all())
                .expect("unsynced single-proof tx must be returned for update");
            prop_assert_eq!(returned_kernel.txid(), merged_tx.kernel.txid());
            prop_assert_eq!(
                UpgradePriority::Critical,
                priority,
                "merge that replaces a Critical tx must inherit its priority"
            );
        }
    }

    mod link_tx_tests {
        use neptune_consensus::chaintx::link_kernel::LinkKernel;
        use neptune_consensus::chaintx::link_primitive_witness::LinkPrimitiveWitness;
        use neptune_consensus::chaintx::link_tx::LinkTx;
        use neptune_consensus::chaintx::link_tx::LinkTxProof;
        use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
        use neptune_consensus::transaction::validity::neptune_proof::NeptuneProof;
        use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

        use super::*;

        /// A proof-backed link transaction wrapping the given kernel.
        /// Invalid, like the mock standard transactions.
        fn proof_backed_link(kernel: TransactionKernel, thruputs: Vec<AdditionRecord>) -> LinkTx {
            LinkTx {
                kernel: LinkKernel { kernel, thruputs },
                proof: LinkTxProof::Proof(NeptuneProof::invalid()),
            }
        }

        /// `n` distinct addition records; deterministic across calls, so two
        /// calls yield overlapping records.
        fn arbitrary_addition_records(n: usize) -> Vec<AdditionRecord> {
            let mut test_runner = TestRunner::deterministic();
            proptest::collection::vec(arb::<AdditionRecord>(), n)
                .new_tree(&mut test_runner)
                .unwrap()
                .current()
        }

        fn genesis_mempool() -> (Mempool, Digest) {
            let genesis_block = Block::genesis(Network::Main);
            let mutator_set_hash = genesis_block
                .mutator_set_accumulator_after()
                .unwrap()
                .hash();
            let mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::ProofCollection,
                &genesis_block,
            );

            (mempool, mutator_set_hash)
        }

        /// Insert a standard mock transaction remodeled to have exactly the
        /// given outputs, making those records known unmined outputs.
        fn insert_predecessor_with_outputs(
            mempool: &mut Mempool,
            base_tx: Transaction,
            outputs: Vec<AdditionRecord>,
        ) {
            let predecessor = Transaction {
                kernel: TransactionKernelModifier::default()
                    .outputs(outputs)
                    .modify(base_tx.kernel),
                proof: base_tx.proof,
            };
            let events = mempool.insert(predecessor, UpgradePriority::Irrelevant);
            assert!(!events.is_empty(), "sanity: predecessor must be inserted");
        }

        #[test]
        fn link_with_unknown_thruputs_is_refused() {
            let (mut mempool, _) = genesis_mempool();
            let [tx] = make_plenty_mock_transaction_supported_by_invalid_single_proofs(1)
                .try_into()
                .unwrap();
            let link = proof_backed_link(tx.kernel, arbitrary_addition_records(1));

            let events = mempool.insert_link(link, UpgradePriority::Critical);
            assert!(events.is_empty());
            assert!(mempool.is_empty(), "unknown thruputs must refuse the link");
        }

        #[test]
        fn inserted_link_is_held_but_invisible_to_standard_getters() {
            let (mut mempool, _) = genesis_mempool();
            let [tx, predecessor_base] =
                make_plenty_mock_transaction_supported_by_invalid_single_proofs(2)
                    .try_into()
                    .unwrap();
            let thruputs = arbitrary_addition_records(1);
            insert_predecessor_with_outputs(&mut mempool, predecessor_base, thruputs.clone());
            let link = proof_backed_link(tx.kernel.clone(), thruputs);
            let txid = link.txid();
            assert_eq!(tx.kernel.txid(), txid, "sanity: wrapped-kernel identity");

            let events = mempool.insert_link(link.clone(), UpgradePriority::Critical);
            assert_eq!(1, events.len());
            let MempoolEvent::AddTx(added_kernel) = &events[0] else {
                panic!("insertion must produce an AddTx event");
            };
            assert_eq!(
                link.kernel.kernel, *added_kernel,
                "event carries the wrapped kernel"
            );

            assert_eq!(2, mempool.len());
            assert!(mempool.contains(txid));
            assert_eq!(1, mempool.num_own_txs());
            assert!(
                mempool.get(txid).is_none(),
                "link tx is invisible to the standard getter"
            );
            assert!(mempool.get_link(txid).is_some());

            assert!(
                mempool
                    .insert_link(link, UpgradePriority::Critical)
                    .is_empty(),
                "reinserting an exact copy is a no-op"
            );
            assert_eq!(2, mempool.len());
        }

        #[test]
        fn fixed_transaction_replaces_its_link() {
            let (mut mempool, tip_msh) = genesis_mempool();
            let [mut tx] = make_plenty_mock_transaction_supported_by_invalid_single_proofs(1)
                .try_into()
                .unwrap();
            tx.kernel = TransactionKernelModifier::default()
                .mutator_set_hash(tip_msh)
                .modify(tx.kernel);
            let txid = tx.txid();

            mempool.insert_link(
                proof_backed_link(tx.kernel.clone(), vec![]),
                UpgradePriority::Irrelevant,
            );
            assert!(mempool.get_link(txid).is_some());

            mempool.insert(tx, UpgradePriority::Irrelevant);
            assert_eq!(1, mempool.len());
            assert!(
                mempool.get(txid).is_some(),
                "the Fix'd transaction must replace its link"
            );
            assert!(mempool.get_link(txid).is_none());
        }

        #[test]
        fn cast_shaped_link_does_not_replace_standard_transaction() {
            let (mut mempool, tip_msh) = genesis_mempool();
            let [mut tx] = make_plenty_mock_transaction_supported_by_invalid_single_proofs(1)
                .try_into()
                .unwrap();
            tx.kernel = TransactionKernelModifier::default()
                .mutator_set_hash(tip_msh)
                .modify(tx.kernel);
            let txid = tx.txid();

            mempool.insert(tx.clone(), UpgradePriority::Irrelevant);
            let events = mempool.insert_link(
                proof_backed_link(tx.kernel.clone(), vec![]),
                UpgradePriority::Irrelevant,
            );

            assert!(events.is_empty());
            assert_eq!(1, mempool.len());
            assert!(
                mempool.get(txid).is_some(),
                "the standard Tx must survive a Cast-shaped link arrival"
            );
        }

        #[test]
        fn single_proof_echo_does_not_evict_conflicting_link() {
            let (mut mempool, tip_msh) = genesis_mempool();
            let [mut tx, other] =
                make_plenty_mock_transaction_supported_by_invalid_single_proofs(2)
                    .try_into()
                    .unwrap();
            tx.kernel = TransactionKernelModifier::default()
                .fee(NativeCurrencyAmount::coins(1))
                .mutator_set_hash(tip_msh)
                .modify(tx.kernel);
            let txid = tx.txid();

            // a chained link spends the same inputs, at a higher fee density.
            let link_kernel = TransactionKernelModifier::default()
                .inputs(tx.kernel.inputs.clone())
                .fee(NativeCurrencyAmount::coins(2))
                .mutator_set_hash(tip_msh)
                .modify(other.kernel);
            let link = proof_backed_link(link_kernel, vec![]);
            let link_txid = link.txid();

            mempool.insert(tx.clone(), UpgradePriority::Irrelevant);
            mempool.insert_link(link, UpgradePriority::Critical);
            assert!(
                mempool.get_link(link_txid).is_some(),
                "sanity: the link must outbid the standard transaction"
            );
            assert!(!mempool.contains(txid));

            // a gossip echo of the replaced transaction must not bounce the
            // link back out on proof quality; it lost the fee contest.
            let events = mempool.insert(tx, UpgradePriority::Irrelevant);
            assert!(events.is_empty());
            assert!(mempool.get_link(link_txid).is_some());
            assert!(!mempool.contains(txid));
        }

        #[test]
        fn same_id_link_contest_follows_sync_status() {
            let (mut mempool, tip_msh) = genesis_mempool();
            let [tx, predecessor_base] =
                make_plenty_mock_transaction_supported_by_invalid_single_proofs(2)
                    .try_into()
                    .unwrap();
            let thruputs = arbitrary_addition_records(1);
            insert_predecessor_with_outputs(&mut mempool, predecessor_base, thruputs.clone());
            let unsynced = proof_backed_link(tx.kernel.clone(), thruputs.clone());
            let synced_kernel = TransactionKernelModifier::default()
                .mutator_set_hash(tip_msh)
                .modify(tx.kernel);
            let synced = proof_backed_link(synced_kernel, thruputs);
            let txid = synced.txid();
            assert_eq!(txid, unsynced.txid(), "sanity: same id across sync status");

            // A synced link replaces an unsynced one of the same id ...
            mempool.insert_link(unsynced.clone(), UpgradePriority::Irrelevant);
            mempool.insert_link(synced.clone(), UpgradePriority::Irrelevant);
            assert_eq!(2, mempool.len());
            assert!(mempool.tx_is_synced(&mempool.get_link(txid).unwrap().kernel.kernel));

            // ... and the unsynced one does not replace it back.
            let events = mempool.insert_link(unsynced, UpgradePriority::Irrelevant);
            assert!(events.is_empty());
            assert!(mempool.tx_is_synced(&mempool.get_link(txid).unwrap().kernel.kernel));
        }

        #[test]
        fn proof_backed_link_replaces_witness_backed_and_not_conversely() {
            let (mut mempool, _) = genesis_mempool();
            let [tx] = make_plenty_mock_transaction_supported_by_primitive_witness(1)
                .try_into()
                .unwrap();
            let TransactionProof::Witness(pw) = tx.proof else {
                panic!("mock transaction must be witness-backed");
            };
            let link_witness = LinkPrimitiveWitness::from_primitive_witness(pw, 0);
            let witness_backed = LinkTx {
                kernel: link_witness.kernel.clone(),
                proof: LinkTxProof::Witness(Box::new(link_witness)),
            };
            let proof_backed = proof_backed_link(witness_backed.kernel.kernel.clone(), vec![]);
            let txid = proof_backed.txid();
            assert_eq!(
                txid,
                witness_backed.txid(),
                "sanity: same id across proof forms"
            );

            mempool.insert_link(witness_backed.clone(), UpgradePriority::Critical);
            mempool.insert_link(proof_backed.clone(), UpgradePriority::Critical);
            assert!(
                mempool.get_link(txid).unwrap().proof.is_proof(),
                "proof-backed link must replace the witness-backed form"
            );

            let events = mempool.insert_link(witness_backed, UpgradePriority::Critical);
            assert!(events.is_empty());
            assert!(
                mempool.get_link(txid).unwrap().proof.is_proof(),
                "witness-backed link must not replace the proof-backed form"
            );
        }

        #[test]
        fn cross_pipeline_conflict_is_decided_by_fee_density() {
            let (mut mempool, tip_msh) = genesis_mempool();
            let [tx, predecessor_base] =
                make_plenty_mock_transaction_supported_by_invalid_single_proofs(2)
                    .try_into()
                    .unwrap();
            let thruputs = arbitrary_addition_records(1);
            insert_predecessor_with_outputs(&mut mempool, predecessor_base, thruputs.clone());
            let member_kernel = TransactionKernelModifier::default()
                .mutator_set_hash(tip_msh)
                .fee(NativeCurrencyAmount::coins(5))
                .modify(tx.kernel);
            let member = Transaction {
                kernel: member_kernel.clone(),
                proof: tx.proof,
            };
            let member_txid = member.txid();
            mempool.insert(member, UpgradePriority::Irrelevant);

            // Same confirmed inputs, different fee => a conflicting link with
            // a different id.
            let link_kernel = |fee| {
                TransactionKernelModifier::default()
                    .fee(fee)
                    .modify(member_kernel.clone())
            };

            let cheap = proof_backed_link(
                link_kernel(NativeCurrencyAmount::coins(1)),
                thruputs.clone(),
            );
            assert_ne!(
                member_txid,
                cheap.txid(),
                "sanity: fee change changes the id"
            );
            let events = mempool.insert_link(cheap, UpgradePriority::Irrelevant);
            assert!(events.is_empty(), "low fee density loses the contest");
            assert!(mempool.get(member_txid).is_some());

            let rich = proof_backed_link(link_kernel(NativeCurrencyAmount::coins(50)), thruputs);
            let rich_txid = rich.txid();
            mempool.insert_link(rich, UpgradePriority::Irrelevant);
            assert_eq!(2, mempool.len());
            assert!(
                mempool.get_link(rich_txid).is_some(),
                "high fee density wins the contest"
            );
            assert!(!mempool.contains(member_txid));
        }

        #[test]
        fn own_proof_backed_link_gets_update_job() {
            use neptune_consensus::block::test_helpers::invalid_empty_block;

            use crate::mempool_update_job::MempoolUpdateJob;

            let network = Network::Main;
            let genesis_block = Block::genesis(network);
            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::SingleProof,
                &genesis_block,
            );

            let [tx_a, tx_b, predecessor_base] =
                make_plenty_mock_transaction_supported_by_invalid_single_proofs(3)
                    .try_into()
                    .unwrap();
            let thruputs = arbitrary_addition_records(1);
            insert_predecessor_with_outputs(&mut mempool, predecessor_base, thruputs.clone());

            let own_link = proof_backed_link(tx_a.kernel, thruputs.clone());
            mempool.insert_link(own_link.clone(), UpgradePriority::Critical);

            let foreign_link = proof_backed_link(tx_b.kernel, thruputs);
            mempool.insert_link(foreign_link, UpgradePriority::Irrelevant);
            assert_eq!(3, mempool.len());

            let block1 = invalid_empty_block(&genesis_block, network);
            let (_events, update_jobs) = mempool.update_with_block(&block1).unwrap();

            let [update_job] = update_jobs.try_into().unwrap();
            let MempoolUpdateJob::Link { old_link_tx } = update_job else {
                panic!("own proof-backed link must produce a link update job");
            };
            assert_eq!(own_link.txid(), old_link_tx.txid());
        }

        #[test]
        fn preferred_link_fix_returns_only_resolved_synced_links() {
            let (mut mempool, tip_msh) = genesis_mempool();
            let [tx_a, tx_b, predecessor_base] =
                make_plenty_mock_transaction_supported_by_invalid_single_proofs(3)
                    .try_into()
                    .unwrap();
            let thruputs = arbitrary_addition_records(1);
            insert_predecessor_with_outputs(&mut mempool, predecessor_base, thruputs.clone());

            // A synced link with a thruput left: not fixable.
            let unresolved_kernel = TransactionKernelModifier::default()
                .mutator_set_hash(tip_msh)
                .modify(tx_a.kernel);
            mempool.insert_link(
                proof_backed_link(unresolved_kernel, thruputs),
                UpgradePriority::Irrelevant,
            );
            assert!(
                mempool
                    .preferred_link_fix(crate::tx_upgrade_filter::TxUpgradeFilter::match_all())
                    .is_none(),
                "a link with unresolved thruputs must not be offered for fixing"
            );

            // An unsynced, resolved link: not fixable either.
            let unsynced = proof_backed_link(tx_b.kernel.clone(), vec![]);
            let unsynced_txid = unsynced.txid();
            mempool.insert_link(unsynced, UpgradePriority::Irrelevant);
            assert!(
                mempool
                    .preferred_link_fix(crate::tx_upgrade_filter::TxUpgradeFilter::match_all())
                    .is_none(),
                "an unsynced link must not be offered for fixing"
            );

            // A synced, resolved link: fixable.
            let resolved_kernel = TransactionKernelModifier::default()
                .mutator_set_hash(tip_msh)
                .modify(tx_b.kernel);
            let resolved = proof_backed_link(resolved_kernel, vec![]);
            let resolved_txid = resolved.txid();
            assert_eq!(
                unsynced_txid, resolved_txid,
                "sanity: replaces its unsynced form"
            );
            mempool.insert_link(resolved, UpgradePriority::Irrelevant);
            let (preferred, priority) = mempool
                .preferred_link_fix(crate::tx_upgrade_filter::TxUpgradeFilter::match_all())
                .expect("a synced, resolved link must be offered for fixing");
            assert_eq!(resolved_txid, preferred.txid());
            assert_eq!(UpgradePriority::Irrelevant, priority);
        }

        #[test]
        fn link_with_mined_thruput_is_evicted() {
            use neptune_consensus::block::block_transaction::BlockTransaction;
            use neptune_consensus::transaction::test_helpers::make_mock_transaction_with_mutator_set_hash_and_timestamp;

            let network = Network::Main;
            let genesis_block = Block::genesis(network);
            let mut mempool = Mempool::new(
                ByteSize::gb(1),
                TxProvingCapability::ProofCollection,
                &genesis_block,
            );

            let [tx_a, tx_b, predecessor_base] =
                make_plenty_mock_transaction_supported_by_invalid_single_proofs(3)
                    .try_into()
                    .unwrap();
            let [mined_thruput, pending_thruput] =
                arbitrary_addition_records(2).try_into().unwrap();
            insert_predecessor_with_outputs(
                &mut mempool,
                predecessor_base,
                vec![mined_thruput, pending_thruput],
            );
            let doomed = proof_backed_link(tx_a.kernel, vec![mined_thruput]);
            let unaffected = proof_backed_link(tx_b.kernel, vec![pending_thruput]);
            mempool.insert_link(doomed.clone(), UpgradePriority::Irrelevant);
            mempool.insert_link(unaffected.clone(), UpgradePriority::Irrelevant);
            assert_eq!(3, mempool.len());

            // A block whose transaction mines the doomed link tx's thruput,
            // without the cut-through.
            let block_timestamp = genesis_block.header().timestamp + Timestamp::hours(1);
            let block_tx = make_mock_transaction_with_mutator_set_hash_and_timestamp(
                vec![],
                vec![mined_thruput],
                genesis_block
                    .mutator_set_accumulator_after()
                    .unwrap()
                    .hash(),
                block_timestamp,
            );
            let block1 = Block::block_template_invalid_proof(
                &genesis_block,
                BlockTransaction::upgrade(block_tx),
                block_timestamp,
                None,
                network,
            );

            let (events, update_jobs) = mempool.update_with_block(&block1).unwrap();
            assert!(update_jobs.is_empty());
            assert_eq!(2, mempool.len());
            assert!(
                !mempool.contains(doomed.txid()),
                "a link whose thruput was mined must be evicted"
            );
            assert!(
                mempool.contains(unaffected.txid()),
                "a link whose thruput is still pending must survive"
            );
            assert!(events.iter().any(|e| matches!(
                e,
                MempoolEvent::RemoveTx(kernel) if *kernel == doomed.kernel.kernel
            )));
        }
    }
}
