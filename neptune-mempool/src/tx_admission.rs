//! The rules deciding which transactions this node admits to its mempool.
//!
//! These are *policy*, not consensus. A transaction refused here is not
//! thereby invalid: peers may hold it, and it may well be mined into a block
//! that this node accepts. What the rules express is which transactions this
//! node is willing to store and relay.
//!
//! Transactions reach the mempool from more than one direction — gossip from
//! peers, and submission over the RPC interface — and each direction reports
//! rejection in its own vocabulary: peer sanctions in one case, RPC errors in
//! the other. Hence [`TxAdmissionError`], which names the reason and leaves
//! the reporting to the caller.
//!
//! Proving a transaction can take longer than the time between blocks. So a
//! transaction built against one of the tip's
//! [`MAX_TX_SYNC_DEPTH`](crate::recent_mutator_sets::MAX_TX_SYNC_DEPTH)
//! nearest ancestors is judged against that ancestor's mutator set, and
//! admitted if no input was spent since. It is held unsynced for a proof
//! upgrader to update. Any other transaction is judged against the tip's
//! mutator set. Link transactions must be synced to the tip, since their
//! thruputs resolve against the mempool as it stands.
//!
//! The order in which the rules are applied is deliberate, and is the reason
//! they live in one place. Verifying a transaction's proof costs orders of
//! magnitude more than every other check combined, and the peer supplying the
//! transaction decides when we do it. So validity is established last, once no
//! cheaper reason to reject the transaction remains.

use neptune_consensus::block::FUTUREDATING_LIMIT;
use neptune_consensus::block::mutator_set_update::MutatorSetUpdate;
use neptune_consensus::block::pow::LustrationStatus;
use neptune_consensus::chaintx::link_tx::LinkTxProof;
use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
use neptune_consensus::proof_abstractions::verifier::verify_transaction_proof;
use neptune_consensus::transaction::transaction_kernel::TransactionConfirmabilityError;
use neptune_consensus::transaction::transaction_kernel::TransactionLustrationError;
use neptune_consensus::transaction::validity::single_proof::link_tx_claim;
use neptune_primitives::mast_hash::MastHash;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use tracing::warn;

use crate::any_tx::AnyTxRef;
use crate::mempool::MEMPOOL_RETIREMENT_MARGIN;
use crate::mempool::MEMPOOL_TX_THRESHOLD_AGE;
use crate::recent_mutator_sets::CatchUpError;
use crate::recent_mutator_sets::RecentMutatorSets;
use crate::transaction_kernel_id::Txid;

/// Why a transaction was refused admission to the mempool.
///
/// Rejection is not a claim that the transaction is invalid: several of these
/// reasons describe transactions that are perfectly valid but not admissible on
/// this node right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxAdmissionError {
    /// Only the miner may produce transactions that mint a coinbase.
    HasCoinbase,

    /// Only proof upgraders may produce transactions with negative fees.
    NegativeFee,

    /// Already held, at no worse proof quality. Routine rather than
    /// suspicious: a node requests the same transaction from several peers, so
    /// duplicates arrive whenever more than one of them answers.
    AlreadyKnown,

    /// Cannot be confirmed against the mutator set it is judged against.
    NotConfirmable(TransactionConfirmabilityError),

    /// Cannot be applied to the mutator set it is judged against. Not expected
    /// to occur when the transaction is confirmable; checked to be sure.
    CannotApplyToMutatorSet,

    /// The input at this index was spent by a block after the transaction was
    /// built. Routine during block propagation.
    SpentSinceSync(usize),

    TooManyInputs,

    TooManyOutputs,

    TooManyAnnouncements,

    /// Older than the mempool is willing to hold.
    TooOld,

    /// Retires too soon to be worth holding.
    Retired,

    /// Dated too far into the future.
    FutureDated,

    /// Required lustrations were not present.
    Lustration(TransactionLustrationError),

    /// Confirming the transaction would drive the lustration counter below
    /// zero.
    LustrationsWouldMakeCounterNegative,

    /// A link transaction under a rule set without the `Fix` branch.
    NotYetActive,

    /// A link transaction not built against the tip. Also a transaction
    /// without inputs that is not at the tip, since it can never be updated.
    NotSynced,

    /// The transaction's proof does not attest to its kernel.
    Invalid,
}

/// How many items are reserved for the transactions that a mempool
/// transaction is merged with before it is mined. It is merged with the miner's
/// coinbase transaction, which typically has two outputs, and it may also be
/// merged with a negative-fee transaction whose author claims part of its fee.
const MERGE_HEADROOM: usize = 5;

/// The largest number of inputs, outputs, or announcements a mempool
/// transaction may have, given a block's limit on that item.
fn admissible_count(max_num_per_block: usize) -> usize {
    max_num_per_block.saturating_sub(MERGE_HEADROOM)
}

/// Determine whether a transaction, on either pipeline, may be admitted to
/// the mempool.
///
/// A standard transaction built against a mutator set in
/// `recent_mutator_sets` is judged against it, any other against the tip's. A
/// link transaction must be built against the tip's.
///
/// `already_known` answers whether the mempool already holds this transaction
/// at no worse proof quality; it is supplied by the caller so that this
/// function need not reason about how the mempool is locked. For the same
/// reason, this function does *not* check that a link transaction's thruputs
/// are outputs of mempool members..
///
/// `lustration_status` is `None` on networks and heights where lustrations do
/// not yet apply.
///
/// Checks run cheapest first, so that the transaction's proof is verified only
/// once nothing cheaper rejects it. Callers must therefore not verify the
/// proof themselves beforehand; doing so reinstates the cost this ordering
/// exists to avoid.
pub async fn admissible(
    tx: AnyTxRef<'_>,
    recent_mutator_sets: &RecentMutatorSets,
    lustration_status: Option<LustrationStatus>,
    already_known: bool,
    now: Timestamp,
    network: Network,
    consensus_rule_set: ConsensusRuleSet,
) -> Result<(), TxAdmissionError> {
    let tip_mutator_set_hash = recent_mutator_sets.tip_mutator_set_hash();

    // Link-pipeline gates, cheaper than anything below.
    if let AnyTxRef::Link(link_tx) = tx {
        if !consensus_rule_set.has_chain_branches() {
            return Err(TxAdmissionError::NotYetActive);
        }

        if link_tx.kernel.kernel.mutator_set_hash != tip_mutator_set_hash {
            return Err(TxAdmissionError::NotSynced);
        }
    }

    let kernel = tx.kernel();

    if kernel.coinbase.is_some() {
        return Err(TxAdmissionError::HasCoinbase);
    }

    if kernel.fee.is_negative() {
        return Err(TxAdmissionError::NegativeFee);
    }

    if kernel.inputs.len() > admissible_count(consensus_rule_set.max_num_inputs()) {
        return Err(TxAdmissionError::TooManyInputs);
    }
    if kernel.outputs.len() > admissible_count(consensus_rule_set.max_num_outputs()) {
        return Err(TxAdmissionError::TooManyOutputs);
    }
    if kernel.announcements.len() > admissible_count(consensus_rule_set.max_num_announcements()) {
        return Err(TxAdmissionError::TooManyAnnouncements);
    }

    let timestamp = kernel.timestamp;
    if timestamp < now - MEMPOOL_TX_THRESHOLD_AGE {
        return Err(TxAdmissionError::TooOld);
    }
    if timestamp >= now + FUTUREDATING_LIMIT {
        return Err(TxAdmissionError::FutureDated);
    }

    // Policy, and so applied under every rule set: a transaction that retires
    // too soon to be worth composing with is not worth storing and relaying
    // either.
    if kernel.retires_before(MEMPOOL_RETIREMENT_MARGIN + now) {
        return Err(TxAdmissionError::Retired);
    }

    if already_known {
        return Err(TxAdmissionError::AlreadyKnown);
    }

    let synced_to_tip = kernel.mutator_set_hash == tip_mutator_set_hash;

    // A transaction built against a held ancestor is judged against that
    // mutator set. Any other is judged against the tip's, where its removal
    // records may still validate.
    let held_mutator_set = recent_mutator_sets.mutator_set(kernel.mutator_set_hash);
    let judged_against = held_mutator_set.unwrap_or_else(|| recent_mutator_sets.tip_mutator_set());

    // A transaction without inputs can never be updated.
    if !synced_to_tip && kernel.inputs.is_empty() {
        return Err(TxAdmissionError::NotSynced);
    }

    // For a link transaction this covers the confirmed inputs; thruputs are
    // not removal records.
    if let Err(confirmability_error) = kernel.is_confirmable_relative_to(judged_against) {
        return Err(TxAdmissionError::NotConfirmable(confirmability_error));
    }

    let mutator_set_update = MutatorSetUpdate::new(kernel.inputs.clone(), kernel.outputs.clone());
    if mutator_set_update
        .apply_to_accumulator(&mut judged_against.clone())
        .is_err()
    {
        // Should not be reachable because of above check
        return Err(TxAdmissionError::CannotApplyToMutatorSet);
    }

    // Blocks have landed since the held ancestor: make sure none of them spent
    // an input. The caught-up records are discarded, since only a proof can
    // replace the kernel's.
    if held_mutator_set.is_some() && !synced_to_tip {
        match recent_mutator_sets.catch_up(kernel.mutator_set_hash, &kernel.inputs) {
            Ok(_) => (),
            Err(CatchUpError::SpentSince(index)) => {
                return Err(TxAdmissionError::SpentSinceSync(index));
            }
            Err(CatchUpError::UnknownMutatorSet) => {
                // Unreachable: the mutator set was found above.
                return Err(TxAdmissionError::NotSynced);
            }
            Err(CatchUpError::Inconsistent) => {
                warn!(
                    "Could not bring removal records of transaction {} forward to the tip; \
                     refusing it as unsynced",
                    kernel.txid()
                );
                return Err(TxAdmissionError::NotSynced);
            }
        }
    }

    if let Some(lustration_status) = lustration_status {
        let lustrated = kernel.verified_lustration_amount(
            lustration_status.max_lustrating_aocl_leaf_index,
            consensus_rule_set.fix_lustration_double_counting(),
        );
        match lustrated {
            Ok(lustrated) if lustrated > lustration_status.counter => {
                return Err(TxAdmissionError::LustrationsWouldMakeCounterNegative);
            }
            Ok(_) => (),
            Err(lustration_error) => {
                return Err(TxAdmissionError::Lustration(lustration_error));
            }
        }
    }

    // Verifying the proof is by far the most expensive check, so it runs once
    // every cheaper reason to reject has been ruled out.
    let valid = match tx {
        AnyTxRef::Standard(transaction) => transaction.is_valid(network, consensus_rule_set).await,
        AnyTxRef::Link(link_tx) => match &link_tx.proof {
            LinkTxProof::Witness(link_primitive_witness) => {
                link_primitive_witness.validate().await.is_ok()
                    && link_primitive_witness.kernel.mast_hash() == link_tx.kernel.mast_hash()
            }
            LinkTxProof::Proof(proof) => {
                let claim = link_tx_claim(link_tx.kernel.mast_hash(), consensus_rule_set);
                verify_transaction_proof(claim, proof.clone(), network).await
            }
        },
    };
    if !valid {
        return Err(TxAdmissionError::Invalid);
    }

    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;
    use neptune_consensus::chaintx::link_kernel::LinkKernel;
    use neptune_consensus::chaintx::link_tx::LinkTx;
    use neptune_consensus::transaction::Transaction;
    use neptune_consensus::transaction::TransactionProof;
    use neptune_consensus::transaction::announcement::Announcement;
    use neptune_consensus::transaction::test_helpers::txkernel;
    use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
    use neptune_consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use neptune_consensus::transaction::validity::neptune_proof::NeptuneProof;
    use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use neptune_mutator_set::addition_record::AdditionRecord;
    use neptune_mutator_set::msa_and_records::MsaAndRecords;
    use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use neptune_mutator_set::removal_record::RemovalRecord;
    use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
    use neptune_mutator_set::shared::CHUNK_SIZE;
    use neptune_mutator_set::shared::NUM_TRIALS;
    use neptune_mutator_set::shared::WINDOW_SIZE;
    use proptest::arbitrary::Arbitrary;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::prelude::Digest;
    use test_strategy::proptest;

    use super::*;
    use crate::recent_mutator_sets::MAX_TX_SYNC_DEPTH;
    use crate::test_utils::shared_tokio_runtime;

    const _: () = assert!(
        MAX_TX_SYNC_DEPTH >= 1,
        "these tests need at least one ancestor in the window"
    );

    fn transaction_retiring_at(retirement: Timestamp, timestamp: Timestamp) -> Transaction {
        let mut test_runner = TestRunner::deterministic();
        let kernel = txkernel::with_lengths(0..1, 0..1, 0..1, true)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let kernel = TransactionKernelModifier::default()
            .announcements(vec![Announcement::retirement(retirement)])
            .coinbase(None)
            .fee(NativeCurrencyAmount::coins(1))
            .timestamp(timestamp)
            .modify(kernel);

        Transaction {
            kernel,
            proof: TransactionProof::invalid(),
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn transaction_retiring_within_the_margin_is_not_admitted() {
        let now = Timestamp::now();
        let retirements = [
            now - Timestamp::hours(1),
            now,
            now + MEMPOOL_RETIREMENT_MARGIN - Timestamp::minutes(1),
        ];
        let recent_mutator_sets =
            RecentMutatorSets::for_mutator_set(MutatorSetAccumulator::default());

        for retirement in retirements {
            let transaction = transaction_retiring_at(retirement, now);

            assert_eq!(
                Err(TxAdmissionError::Retired),
                admissible(
                    (&transaction).into(),
                    &recent_mutator_sets,
                    None,
                    false,
                    now,
                    Network::Main,
                    ConsensusRuleSet::default(),
                )
                .await
            );
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn transaction_retiring_beyond_the_margin_is_not_refused_for_retirement() {
        let now = Timestamp::now();
        let retirement = now + MEMPOOL_RETIREMENT_MARGIN + Timestamp::minutes(1);
        let transaction = transaction_retiring_at(retirement, now);
        let recent_mutator_sets =
            RecentMutatorSets::for_mutator_set(MutatorSetAccumulator::default());

        let rejection = admissible(
            (&transaction).into(),
            &recent_mutator_sets,
            None,
            false,
            now,
            Network::Main,
            ConsensusRuleSet::default(),
        )
        .await
        .expect_err("transaction with an invalid proof is never admitted");

        assert_ne!(TxAdmissionError::Retired, rejection);
    }

    /// A transaction whose counts exceed what a block may hold can never be
    /// mined, so the mempool must not store and relay it. Counts at the limit
    /// are admissible as far as these checks are concerned.
    #[proptest(cases = 1, async = "tokio")]
    async fn transactions_exceeding_per_block_limits_are_not_admitted(
        #[strategy(txkernel::with_lengths(0..1, 0..1, 0..1, true))] kernel: TransactionKernel,
        #[strategy(arb())] now: Timestamp,
    ) {
        let consensus_rule_set = ConsensusRuleSet::default();
        let input = RemovalRecord {
            absolute_indices: AbsoluteIndexSet::new([0; NUM_TRIALS as usize]),
            target_chunks: ChunkDictionary::empty(),
        };
        let output = AdditionRecord::new(Digest::default());
        let announcement = Announcement { message: vec![] };
        let recent_mutator_sets =
            RecentMutatorSets::for_mutator_set(MutatorSetAccumulator::default());

        let max_num_inputs = admissible_count(consensus_rule_set.max_num_inputs());
        let max_num_outputs = admissible_count(consensus_rule_set.max_num_outputs());
        let max_num_announcements = admissible_count(consensus_rule_set.max_num_announcements());
        assert!(max_num_inputs < consensus_rule_set.max_num_inputs());

        let cases = [
            (
                max_num_inputs + 1,
                0,
                0,
                Some(TxAdmissionError::TooManyInputs),
            ),
            (
                0,
                max_num_outputs + 1,
                0,
                Some(TxAdmissionError::TooManyOutputs),
            ),
            (
                0,
                0,
                max_num_announcements + 1,
                Some(TxAdmissionError::TooManyAnnouncements),
            ),
            (max_num_inputs, max_num_outputs, max_num_announcements, None),
        ];

        for (num_inputs, num_outputs, num_announcements, expected) in cases {
            let kernel = TransactionKernelModifier::default()
                .inputs(vec![input.clone(); num_inputs])
                .outputs(vec![output; num_outputs])
                .announcements(vec![announcement.clone(); num_announcements])
                .coinbase(None)
                .fee(NativeCurrencyAmount::coins(1))
                .timestamp(now)
                .modify(kernel.clone());

            // Everything this test is about happens before proof verification.
            let transaction = Transaction {
                kernel,
                proof: TransactionProof::invalid(),
            };

            let rejection = admissible(
                (&transaction).into(),
                &recent_mutator_sets,
                None,
                false,
                now,
                Network::Main,
                consensus_rule_set,
            )
            .await
            .expect_err("transaction with an invalid proof is never admitted");

            match expected {
                Some(expected) => prop_assert_eq!(expected, rejection),
                None => prop_assert!(
                    !matches!(
                        rejection,
                        TxAdmissionError::TooManyInputs
                            | TxAdmissionError::TooManyOutputs
                            | TxAdmissionError::TooManyAnnouncements
                    ),
                    "counts at the limit must not be rejected for being too many. Got: {:?}",
                    rejection
                ),
            }
        }
    }

    /// Admission runs on untrusted data. So it is not allowed to panic.
    #[proptest(cases = 15, async = "tokio")]
    async fn admissible_never_panics(
        #[strategy(txkernel::with_lengths(0..5, 0..5, 0..5, false))] kernel: TransactionKernel,
        #[strategy(proptest::collection::vec(arb::<Digest>(), 0..40))] canonical_commitments: Vec<
            Digest,
        >,
        #[strategy(arb())] now: Timestamp,
        already_known: bool,
        with_lustration_status: bool,
        #[strategy(arb())] max_lustrating_aocl_leaf_index: u64,
        #[strategy(arb::<u8>())] boundary_selector: u8,
        synced_to_tip: bool,
    ) {
        let lustration_status = with_lustration_status.then(|| LustrationStatus {
            counter: NativeCurrencyAmount::coins(42),
            max_lustrating_aocl_leaf_index,
        });

        // The mutator set is ours, not the sender's, so it is always internally
        // consistent.
        let mut tip_mutator_set = MutatorSetAccumulator::default();
        for canonical_commitment in canonical_commitments {
            tip_mutator_set.add(&AdditionRecord::new(canonical_commitment));
        }

        // Purely random absolute indices never land on the edges of the active
        // window, which is where this code's bugs have lived. So aim some of
        // them there: at the window's first and last representable index, and
        // at the first index just past it.
        let batch_index = u128::from(tip_mutator_set.get_batch_index());
        let active_window_start = batch_index * u128::from(CHUNK_SIZE);
        let boundary_index = match boundary_selector % 5 {
            0 => active_window_start.saturating_sub(1),
            1 => active_window_start,
            2 => active_window_start + u128::from(WINDOW_SIZE) - 1,
            3 => active_window_start + u128::from(WINDOW_SIZE),
            _ => active_window_start + u128::from(WINDOW_SIZE) + 1,
        };

        // Half the cases are synced to an ancestor, to reach the catch-up path.
        let mut recent_mutator_sets = RecentMutatorSets::for_mutator_set(tip_mutator_set.clone());
        let mutator_set_hash = if synced_to_tip {
            tip_mutator_set.hash()
        } else {
            let ancestor_hash = tip_mutator_set.hash();
            recent_mutator_sets.push_update(MutatorSetUpdate::new(
                vec![],
                vec![AdditionRecord::new(Digest::default())],
            ));
            ancestor_hash
        };

        // The cheap checks come first and reject almost every arbitrary
        // transaction, so satisfy them: otherwise the code that reads the
        // mutator set -- where the interesting panics are -- is never reached.
        let kernel = TransactionKernelModifier::default()
            .inputs(vec![RemovalRecord {
                absolute_indices: AbsoluteIndexSet::new([boundary_index; NUM_TRIALS as usize]),
                target_chunks: ChunkDictionary::empty(),
            }])
            .coinbase(None)
            .fee(NativeCurrencyAmount::coins(1))
            .timestamp(now)
            .mutator_set_hash(mutator_set_hash)
            .modify(kernel);

        // Everything this test is about happens before proof verification.
        let transaction = Transaction {
            kernel,
            proof: TransactionProof::invalid(),
        };

        let _ = admissible(
            (&transaction).into(),
            &recent_mutator_sets,
            lustration_status,
            already_known,
            now,
            Network::Main,
            ConsensusRuleSet::default(),
        )
        .await;
    }

    /// A mutator set with removal records that are valid against it.
    fn mutator_set_with_records(num_records: usize) -> MsaAndRecords {
        let removables =
            vec![(Digest::default(), Digest::default(), Digest::default()); num_records];
        let mut test_runner = TestRunner::deterministic();
        MsaAndRecords::arbitrary_with((removables, 1u64 << 20))
            .new_tree(&mut test_runner)
            .unwrap()
            .current()
    }

    /// A transaction with an invalid proof.
    fn spending(
        inputs: Vec<RemovalRecord>,
        mutator_set_hash: Digest,
        now: Timestamp,
    ) -> Transaction {
        let mut test_runner = TestRunner::deterministic();
        let kernel = txkernel::with_lengths(0..1, 0..1, 0..1, true)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let kernel = TransactionKernelModifier::default()
            .inputs(inputs)
            .coinbase(None)
            .fee(NativeCurrencyAmount::coins(1))
            .timestamp(now)
            .mutator_set_hash(mutator_set_hash)
            .modify(kernel);

        Transaction {
            kernel,
            proof: TransactionProof::invalid(),
        }
    }

    fn additions(seed: u64, count: u64) -> Vec<AdditionRecord> {
        (0..count)
            .map(|i| AdditionRecord::new(Digest::new([(seed * 1000 + i).into(); 5])))
            .collect()
    }

    /// A transaction built against a recent ancestor passes every check up to
    /// proof verification, as long as its inputs are unspent at the tip.
    #[apply(shared_tokio_runtime)]
    async fn transaction_synced_to_recent_ancestor_is_admitted_up_to_its_proof() {
        let now = Timestamp::now();
        let admission = async |transaction: &Transaction, recent: &RecentMutatorSets| {
            admissible(
                transaction.into(),
                recent,
                None,
                false,
                now,
                Network::Main,
                ConsensusRuleSet::default(),
            )
            .await
        };

        let msa_and_records = mutator_set_with_records(3);
        let ancestor_hash = msa_and_records.mutator_set_accumulator.hash();
        let records = msa_and_records.unpacked_removal_records();
        let mut recent =
            RecentMutatorSets::for_mutator_set(msa_and_records.mutator_set_accumulator);

        // Synced to the tip: the only rejection left is the invalid proof.
        let at_tip = spending(records[..2].to_vec(), ancestor_hash, now);
        assert_eq!(
            Err(TxAdmissionError::Invalid),
            admission(&at_tip, &recent).await
        );

        // Addition-only blocks land, as many as the window holds.
        let base = recent.clone();
        for seed in 0..MAX_TX_SYNC_DEPTH as u64 {
            recent.push_update(MutatorSetUpdate::new(vec![], additions(seed, 9)));
        }
        assert_eq!(Some(MAX_TX_SYNC_DEPTH), recent.depth_of(ancestor_hash));
        assert_eq!(
            Err(TxAdmissionError::Invalid),
            admission(&at_tip, &recent).await
        );

        // Inputs that do not validate against the claimed mutator set.
        let bogus = spending(
            vec![RemovalRecord {
                absolute_indices: records[0].absolute_indices,
                target_chunks: ChunkDictionary::empty(),
            }],
            recent.tip_mutator_set_hash(),
            now,
        );
        let rejection = admission(&bogus, &recent).await;
        assert!(
            matches!(rejection, Err(TxAdmissionError::NotConfirmable(_))),
            "got {rejection:?}"
        );

        // Not built against any mutator set in the window: judged against the
        // tip, where only removal records that validate there will do.
        let at_the_tip = recent.catch_up(ancestor_hash, &records[..2]).unwrap();
        let unknown = spending(at_the_tip.clone(), Digest::default(), now);
        assert_eq!(
            Err(TxAdmissionError::Invalid),
            admission(&unknown, &recent).await
        );
        let unknown_and_stale = spending(bogus.kernel.inputs.clone(), Digest::default(), now);
        let rejection = admission(&unknown_and_stale, &recent).await;
        assert!(
            matches!(rejection, Err(TxAdmissionError::NotConfirmable(_))),
            "got {rejection:?}"
        );

        // No inputs and not at the tip: could never be brought up to date.
        let empty = spending(vec![], ancestor_hash, now);
        assert_eq!(
            Err(TxAdmissionError::NotSynced),
            admission(&empty, &recent).await
        );

        // One more block pushes the ancestor out of the window. Removal
        // records that validate against the tip are still enough.
        let previous_tip = recent.tip_mutator_set_hash();
        recent.push_update(MutatorSetUpdate::new(vec![], additions(100, 1)));
        assert_eq!(None, recent.depth_of(ancestor_hash));
        let at_the_tip = recent.catch_up(previous_tip, &at_the_tip).unwrap();
        let evicted = spending(at_the_tip, ancestor_hash, now);
        assert_eq!(
            Err(TxAdmissionError::Invalid),
            admission(&evicted, &recent).await
        );

        // A block spends one of the transaction's inputs.
        let mut recent = base;
        recent.push_update(MutatorSetUpdate::new(
            vec![records[1].clone()],
            additions(101, 2),
        ));
        assert_eq!(
            Err(TxAdmissionError::SpentSinceSync(1)),
            admission(&at_tip, &recent).await
        );

        // The untouched input alone is still fine.
        let untouched = spending(vec![records[0].clone()], ancestor_hash, now);
        assert_eq!(
            Err(TxAdmissionError::Invalid),
            admission(&untouched, &recent).await
        );
    }

    #[proptest(cases = 1, async = "tokio")]
    async fn link_transaction_admission(
        #[strategy(txkernel::with_lengths(0..1, 0..1, 0..1, true))] kernel: TransactionKernel,
    ) {
        let tip_mutator_set = MutatorSetAccumulator::default();
        let mut recent_mutator_sets = RecentMutatorSets::for_mutator_set(tip_mutator_set.clone());
        let now = Timestamp::hours(10_000);
        let link = |kernel: TransactionKernel| LinkTx {
            kernel: LinkKernel {
                kernel,
                thruputs: vec![AdditionRecord::new(Digest::default())],
            },
            proof: LinkTxProof::Proof(NeptuneProof::invalid()),
        };
        let admission = async |link_tx: &LinkTx, recent: &RecentMutatorSets, consensus_rule_set| {
            admissible(
                link_tx.into(),
                recent,
                None,
                false,
                now,
                Network::Main,
                consensus_rule_set,
            )
            .await
        };

        let base_kernel = TransactionKernelModifier::default()
            .inputs(vec![])
            .coinbase(None)
            .fee(NativeCurrencyAmount::coins(1))
            .timestamp(now)
            .mutator_set_hash(tip_mutator_set.hash())
            .modify(kernel);

        // Under a rule set without the `Fix` branch, no link is admitted.
        prop_assert_eq!(
            Err(TxAdmissionError::NotYetActive),
            admission(
                &link(base_kernel.clone()),
                &recent_mutator_sets,
                ConsensusRuleSet::HardforkGamma
            )
            .await,
        );

        let delta = ConsensusRuleSet::HardforkDelta;

        // A link not synced to the tip is not admitted.
        let unsynced = TransactionKernelModifier::default()
            .mutator_set_hash(Digest::default())
            .modify(base_kernel.clone());
        prop_assert_eq!(
            Err(TxAdmissionError::NotSynced),
            admission(&link(unsynced), &recent_mutator_sets, delta).await,
        );

        let too_old = TransactionKernelModifier::default()
            .timestamp(now - MEMPOOL_TX_THRESHOLD_AGE - Timestamp::hours(1))
            .modify(base_kernel.clone());
        prop_assert_eq!(
            Err(TxAdmissionError::TooOld),
            admission(&link(too_old), &recent_mutator_sets, delta).await,
        );

        // With every cheaper check passed, the proof is verified last -- and
        // this one does not attest to its kernel.
        prop_assert_eq!(
            Err(TxAdmissionError::Invalid),
            admission(&link(base_kernel.clone()), &recent_mutator_sets, delta).await,
        );

        // A link synced to a recent ancestor is not admitted.
        recent_mutator_sets.push_update(MutatorSetUpdate::new(
            vec![],
            vec![AdditionRecord::new(Digest::default())],
        ));
        prop_assert_eq!(
            Some(1),
            recent_mutator_sets.depth_of(tip_mutator_set.hash())
        );
        prop_assert_eq!(
            Err(TxAdmissionError::NotSynced),
            admission(&link(base_kernel), &recent_mutator_sets, delta).await,
        );
    }
}
