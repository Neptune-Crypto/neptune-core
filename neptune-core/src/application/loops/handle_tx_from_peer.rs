use tracing::{debug, warn};

use crate::api::export::Timestamp;
use crate::application::loops::channel::{self, PeerTaskToMain};
use crate::protocol::consensus::transaction::transaction_kernel::TransactionConfirmabilityError;
use crate::protocol::peer::NegativePeerSanction;

/// Return the depth of the problem.
/// - `None`: the `transaction` was sent to the main loop
/// - `Some(None)`: it's not good enough to be shared further
/// - `_`: it deserves `.punish`
pub(crate) async fn the(
    global_state_lock: crate::state::GlobalStateLock,
    to_main: tokio::sync::mpsc::Sender<channel::PeerTaskToMain>,
    now: Timestamp,
    transaction: crate::protocol::peer::transfer_transaction::TransferTransaction,
) -> Option<Option<NegativePeerSanction>> {
    let transaction = crate::api::export::Transaction::from(transaction);

    let (tip, mutator_set_accumulator_after, current_block_height) = {
        let state = global_state_lock.lock_guard().await;

        (
            state.chain.light_state().hash(),
            state
                .chain
                .light_state()
                .mutator_set_accumulator_after()
                .expect("Block from state must have mutator set after"),
            state.chain.light_state().header().height,
        )
    };

    // 1. If transaction is invalid -- punish.
    let network = global_state_lock.cli().network;
    if transaction
        .is_valid(
            network,
            crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet::infer_from(
                network,
                current_block_height,
            ),
        )
        .await
    {
        // 2. If transaction has coinbase -- punish.
        // Transactions received from peers have not been mined yet.
        // Only the miner is allowed to produce transactions with non-empty coinbase fields.
        if transaction.kernel.coinbase.is_some() {
            warn!("Received non-mined transaction with coinbase.");
            Some(Some(NegativePeerSanction::NonMinedTransactionHasCoinbase))
        } else if transaction.kernel.fee.is_negative() {
            // 3. If negative fee -- punish.
            warn!("Received negative-fee transaction.");
            Some(Some(NegativePeerSanction::TransactionWithNegativeFee))
        } else if global_state_lock
            .lock_guard()
            .await
            .mempool
            .accept_transaction(
                transaction.kernel.txid(),
                transaction
                    .proof
                    .proof_quality()
                    .expect("guarded by `TransferTransaction`"),
                transaction.kernel.mutator_set_hash,
            )
        {
            // 4. Checked if transaction is already known.
            // 5. if transaction is not confirmable -- punish.
            if transaction.is_confirmable_relative_to(&mutator_set_accumulator_after) {
                // If transaction cannot be applied to mutator set -- punish.
                // I don't think this can happen when above checks pass but we include the check to ensure that transaction can be applied.
                if crate::protocol::consensus::block::mutator_set_update::MutatorSetUpdate::new(
                    transaction.kernel.inputs.clone(),
                    transaction.kernel.outputs.clone(),
                )
                .apply_to_accumulator(&mut mutator_set_accumulator_after.clone())
                .is_ok()
                {
                    // TODO #followUp can add few `millis` to `now` already, but to @skaunov this seems not an issue

                    // 6. Ignore if transaction is too old
                    if transaction.kernel.timestamp
                        < now
                            - Timestamp::seconds(
                                crate::state::mempool::MEMPOOL_TX_THRESHOLD_AGE_IN_SECS,
                            )
                    {
                        warn!("Received too old tx");
                        // "TODO: Consider punishing here" #fromPeerLoop
                        Some(None)
                    } else if transaction.kernel.timestamp
                        >= now + crate::protocol::consensus::block::FUTUREDATING_LIMIT
                    {
                        // 7. Ignore if transaction is too far into the future
                        warn!(
                            "Received tx too far into the future. Got timestamp: {:?}",
                            transaction.kernel.timestamp
                        );
                        // "TODO: Consider punishing here" #fromPeerLoop
                        Some(None)
                    } else {
                        // Otherwise, relay to main.
                        to_main
                            .send(PeerTaskToMain::Transaction(Box::new(
                                channel::PeerTaskToMainTransaction {
                                    transaction,
                                    confirmable_for_block: tip,
                                },
                            )))
                            .await
                            .expect(
                                // "if the main loop dropped its end of the channel then it's a futile errand"
                                super::MSG_CHAN_CRITICAL,
                            );
                        None
                    }
                } else {
                    warn!("Cannot apply transaction to current mutator set.");
                    warn!("Transaction ID: {}", transaction.kernel.txid());
                    Some(Some(
                        NegativePeerSanction::CannotApplyTransactionToMutatorSet,
                    ))
                }
            } else {
                warn!(
                    "Received unconfirmable transaction with TXID {}. Unconfirmable because:",
                    transaction.kernel.txid()
                );
                // get fine-grained error code for informative logging
                Some(Some(
                    match transaction
                        .kernel
                        .is_confirmable_relative_to(&mutator_set_accumulator_after)
                        .expect_err(crate::application::loops::MSG_CONDIT)
                    {
                        TransactionConfirmabilityError::InvalidRemovalRecord(invalid) => {
                            warn!("invalid removal record (at index {invalid})");
                            debug!(
                                "absolute index set of removal record {invalid}: {:?}",
                                transaction.kernel.inputs[invalid].absolute_indices
                            );
                            debug!(
                                "invalid because {}",
                                transaction.kernel.inputs[invalid]
                                    .validate_inner(&mutator_set_accumulator_after)
                                    .err()
                                    .unwrap()
                            );
                            NegativePeerSanction::UnconfirmableTransaction
                        }
                        // TODO #followUp fold these into `thiserror` as with `RemovalRecordValidityError`
                        TransactionConfirmabilityError::DuplicateInputs => {
                            warn!("duplicate inputs");
                            NegativePeerSanction::DoubleSpendingTransaction
                        }
                        TransactionConfirmabilityError::AlreadySpentInput(index) => {
                            warn!("already spent input (at index {index})");
                            NegativePeerSanction::DoubleSpendingTransaction
                        }
                        TransactionConfirmabilityError::RemovalRecordUnpackFailure => {
                            warn!("Failed to unpack removal records");
                            NegativePeerSanction::InvalidTransaction
                        }
                    },
                ))
            }
        } else {
            warn!("Received transaction that was already known");

            // We received a transaction that we *probably* haven't requested. Consider punishing here, if this is abused.
            Some(None)
            // check this case is at least of for `Swarm`, ignoring it doesn't sits well with @skaunov, but
            // /* **Here's a disrepancy between legacy/current p-2-p and `libp2p`.** Duplicated *messages* are basically filtered by `Swarm` itself, but @skaunov see
            // no reason to `Ignore` another shout-out of a tx (it might be for the new ) ... */
            // None
            /* Okay, so @skaunov current opinion is let those new peers gossip this. As a miner I don't want to receive this endless times. */
        }
    } else {
        warn!("Received invalid tx");
        Some(Some(NegativePeerSanction::InvalidTransaction))
    }
}
