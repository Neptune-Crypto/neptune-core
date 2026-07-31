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
//! The order in which the rules are applied is deliberate, and is the reason
//! they live in one place. Verifying a transaction's proof costs orders of
//! magnitude more than every other check combined, and the peer supplying the
//! transaction decides when we do it. So validity is established last, once no
//! cheaper reason to reject the transaction remains.

use neptune_consensus::block::FUTUREDATING_LIMIT;
use neptune_consensus::block::mutator_set_update::MutatorSetUpdate;
use neptune_consensus::block::pow::LustrationStatus;
use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
use neptune_consensus::transaction::Transaction;
use neptune_consensus::transaction::transaction_kernel::TransactionConfirmabilityError;
use neptune_consensus::transaction::transaction_kernel::TransactionLustrationError;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;

use crate::mempool::MEMPOOL_TX_THRESHOLD_AGE;

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

    /// Cannot be confirmed against the current mutator set.
    NotConfirmable(TransactionConfirmabilityError),

    /// Cannot be applied to the current mutator set. Not expected to occur
    /// when the transaction is confirmable; checked to be sure.
    CannotApplyToMutatorSet,

    /// Older than the mempool is willing to hold.
    TooOld,

    /// Dated too far into the future.
    FutureDated,

    /// Required lustrations were not present.
    Lustration(TransactionLustrationError),

    /// Confirming the transaction would drive the lustration counter below
    /// zero.
    LustrationsWouldMakeCounterNegative,

    /// The transaction's proof does not attest to its kernel.
    Invalid,
}

/// Determine whether a transaction may be admitted to the mempool.
///
/// `already_known` answers whether the mempool already holds this transaction
/// at no worse proof quality; it is supplied by the caller so that this
/// function need not reason about how the mempool is locked.
///
/// `lustration_status` is `None` on networks and heights where lustrations do
/// not yet apply.
///
/// Checks run cheapest first, so that the transaction's proof is verified only
/// once nothing cheaper rejects it. Callers must therefore not verify the
/// proof themselves beforehand; doing so reinstates the cost this ordering
/// exists to avoid.
pub async fn admissible(
    transaction: &Transaction,
    tip_mutator_set: &MutatorSetAccumulator,
    lustration_status: Option<LustrationStatus>,
    already_known: bool,
    now: Timestamp,
    network: Network,
    consensus_rule_set: ConsensusRuleSet,
) -> Result<(), TxAdmissionError> {
    if transaction.kernel.coinbase.is_some() {
        return Err(TxAdmissionError::HasCoinbase);
    }

    if transaction.kernel.fee.is_negative() {
        return Err(TxAdmissionError::NegativeFee);
    }

    let timestamp = transaction.kernel.timestamp;
    if timestamp < now - MEMPOOL_TX_THRESHOLD_AGE {
        return Err(TxAdmissionError::TooOld);
    }
    if timestamp >= now + FUTUREDATING_LIMIT {
        return Err(TxAdmissionError::FutureDated);
    }

    if already_known {
        return Err(TxAdmissionError::AlreadyKnown);
    }

    if let Err(confirmability_error) = transaction
        .kernel
        .is_confirmable_relative_to(tip_mutator_set)
    {
        return Err(TxAdmissionError::NotConfirmable(confirmability_error));
    }

    let mutator_set_update = MutatorSetUpdate::new(
        transaction.kernel.inputs.clone(),
        transaction.kernel.outputs.clone(),
    );
    if mutator_set_update
        .apply_to_accumulator(&mut tip_mutator_set.clone())
        .is_err()
    {
        // Should not be reachable because of above check
        return Err(TxAdmissionError::CannotApplyToMutatorSet);
    }

    if let Some(lustration_status) = lustration_status {
        let lustrated = transaction.kernel.verified_lustration_amount(
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
    if !transaction.is_valid(network, consensus_rule_set).await {
        return Err(TxAdmissionError::Invalid);
    }

    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use neptune_consensus::transaction::TransactionProof;
    use neptune_consensus::transaction::test_helpers::txkernel;
    use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
    use neptune_consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use neptune_mutator_set::addition_record::AdditionRecord;
    use neptune_mutator_set::removal_record::RemovalRecord;
    use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
    use neptune_mutator_set::shared::CHUNK_SIZE;
    use neptune_mutator_set::shared::NUM_TRIALS;
    use neptune_mutator_set::shared::WINDOW_SIZE;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::prelude::Digest;
    use test_strategy::proptest;

    use super::*;

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
            .modify(kernel);

        // Everything this test is about happens before proof verification.
        let transaction = Transaction {
            kernel,
            proof: TransactionProof::invalid(),
        };

        let _ = admissible(
            &transaction,
            &tip_mutator_set,
            lustration_status,
            already_known,
            now,
            Network::Main,
            ConsensusRuleSet::default(),
        )
        .await;
    }
}
