use std::sync::Arc;

use itertools::Itertools;
use neptune_consensus::proof_abstractions::tx_proving_capability::TxProvingCapability;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::address::ReceivingAddress;
use neptune_wallet::change_policy::ChangePolicy;
use neptune_wallet::utxo_notification::UtxoNotificationMedium;
use num_traits::CheckedSub;
use tracing::debug;
use tracing::error;

use crate::api::export::InputSelectionPriority;
use crate::api::tx_initiation::builder::input_selector::InputSelectionPolicy;
use crate::api::tx_initiation::builder::input_selector::InputSelector;
use crate::api::tx_initiation::builder::input_selector::SortOrder;
use crate::api::tx_initiation::builder::tx_output_list_builder::TxOutputListBuilder;
use crate::api::tx_initiation::error::CreateTxError;
use crate::api::tx_initiation::error::SendError;
use crate::api::tx_initiation::initiator::TransactionInitiator;

pub const CONSOLIDATION_FEE_PC: NativeCurrencyAmount =
    NativeCurrencyAmount::from_nau(NativeCurrencyAmount::coin_as_nau() / 10);
pub const CONSOLIDATION_FEE_SP: NativeCurrencyAmount =
    NativeCurrencyAmount::from_nau(NativeCurrencyAmount::coin_as_nau() / 200);

/// Inputs with less than this number of confirmations will not be selected for
/// consolidation.
pub const NUM_CONFIRMATIONS_REQUIRED_FOR_CONSOLIDATION: usize = 10;

impl TransactionInitiator {
    /// Initiate a transaction that spends a batch of UTXOs to the node's own
    /// wallet, thereby reducing the total number of UTXOs under management.
    ///
    /// Prioritizes the spending of the oldest UTXOs first.
    ///
    /// Returns the number of inputs consumed by the consolidating transaction.
    pub async fn consolidate(
        &mut self,
        num_inputs: usize,
        consolidation_address: Option<ReceivingAddress>,
        timestamp: Timestamp,
        accept_lustrations: bool,
    ) -> Result<usize, ConsolidationError> {
        const MIN_NUM_INPUTS: usize = 2;

        debug!("consolidate: Attempting to consolidate {num_inputs} UTXOs in wallet");
        let input_candidates = self.input_candidates(timestamp).await;
        let lustration_threshold = self
            .global_state_lock
            .lock_guard()
            .await
            .chain
            .lustration_threshold();
        let policy =
            InputSelectionPolicy::from(InputSelectionPriority::ByAge(SortOrder::Descending))
                .require_confirmations(NUM_CONFIRMATIONS_REQUIRED_FOR_CONSOLIDATION)
                .set_lustration_acceptance(accept_lustrations);
        let selected_inputs = InputSelector::new(lustration_threshold)
            .input_candidates(input_candidates)
            .policy(policy)
            .take(num_inputs)
            .into_iter()
            .collect_vec();

        // Ensure we never attempt to consolidate zero or one input
        let num_selected_inputs = selected_inputs.len();
        if num_selected_inputs < MIN_NUM_INPUTS || num_selected_inputs < num_inputs {
            debug!("Nothing to consolidate in wallet as only {num_selected_inputs} were available for consolidation");
            return Err(ConsolidationError::NotEnoughUtxos {
                requested: num_inputs,
                present: selected_inputs.len(),
            });
        }

        let unlocked_inputs = self
            .global_state_lock
            .lock_guard()
            .await
            .unlock_inputs(selected_inputs)
            .await;

        let num_used_inputs = unlocked_inputs.len();
        let unlocked_amount = unlocked_inputs.total_native_coins();
        debug!(
            "Selected {} inputs for consolidation, in total amount {}.",
            num_used_inputs, unlocked_amount
        );

        let receiving_address = match consolidation_address {
            Some(addr) => addr,
            None => {
                let mut state = self.global_state_lock.lock_guard_mut().await;

                state
                    .wallet_state
                    .next_unused_viewing_address_key()
                    .await
                    .to_address()
                    .into()
            }
        };

        let capability = self.global_state_lock.cli().proving_capability();
        let fee = match capability {
            TxProvingCapability::LockScript | TxProvingCapability::PrimitiveWitness => {
                return Err(ConsolidationError::NoTransactionInitiation);
            }
            TxProvingCapability::ProofCollection => CONSOLIDATION_FEE_PC,
            TxProvingCapability::SingleProof => CONSOLIDATION_FEE_SP,
        };

        let Some(output_amount) = unlocked_amount.checked_sub(&fee) else {
            return Err(ConsolidationError::Dust {
                amount: unlocked_amount,
                fee,
            });
        };

        let outputs = TxOutputListBuilder::new()
            .owned_utxo_notification_medium(UtxoNotificationMedium::OnChain)
            .outputs(vec![(receiving_address, output_amount)])
            .build(&self.global_state_lock.clone().into())
            .await;

        let tx_details = self
            .generate_tx_details(
                unlocked_inputs,
                outputs,
                ChangePolicy::ExactChange,
                fee,
                timestamp,
            )
            .await?;

        if tx_details.contains_lustrations() && !accept_lustrations {
            return Err(ConsolidationError::CreateTxError(
                CreateTxError::RequiresLustration,
            ));
        };

        let pw = self.generate_witness_proof(Arc::new(tx_details.clone()));
        let artifacts = self.assemble_transaction_artifacts(tx_details, pw)?;

        tracing::info!("creating consolidation transaction");

        if let Err(e) = self.record_and_broadcast_transaction(&artifacts).await {
            return match e {
                // CLI flag `--no-transaction-initiation`
                SendError::Unsupported => Err(ConsolidationError::NoTransactionInitiation),

                // Application error: could not send broadcast message to main loop.
                SendError::NotBroadcast => Err(ConsolidationError::BroadcastFailure),

                SendError::Tx(create_tx_error) => {
                    Err(ConsolidationError::CreateTxError(create_tx_error))
                }
                SendError::Proof(create_proof_error) => Err(ConsolidationError::CreateProofError(
                    format!("Error creating proof: {create_proof_error}."),
                )),

                // We just made an invalid transaction.
                SendError::RecordTransaction(record_transaction_error) => {
                    panic!("We just made an invalid transaction: {record_transaction_error}.");
                }
                SendError::RateLimit { .. } => {
                    error!(
                        "Cannot initiate consolidation transaction because rate limit exceeded."
                    );
                    Err(ConsolidationError::NoTransactionInitiation)
                }
            };
        }

        tracing::info!("done");

        Ok(num_used_inputs)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ConsolidationError {
    #[error("Not enough UTXOs for consolidation: node has {present} UTXOs under management but attempting to consolidate {requested}.")]
    NotEnoughUtxos { requested: usize, present: usize },
    #[error(
        "Cannot initiate consolidation transaction because node is not initiating transactions."
    )]
    NoTransactionInitiation,
    #[error(
        "Cannot consolidate dust UTXOs because total amount {amount} is not worth fee of {fee}."
    )]
    Dust {
        amount: NativeCurrencyAmount,
        fee: NativeCurrencyAmount,
    },
    #[error("Error creating transaction: {0}.")]
    CreateTxError(#[from] CreateTxError),

    #[error("Error creating proof: {0}.")]
    CreateProofError(String),

    #[error("Error while attempting to broadcast consolidation transaction.")]
    BroadcastFailure,
}
