use std::sync::Arc;

use itertools::Itertools;
use num_traits::CheckedSub;
use tracing::debug;
use tracing::error;

use crate::api::export::ChangePolicy;
use crate::api::export::InputSelectionPriority;
use crate::api::export::NativeCurrencyAmount;
use crate::api::export::ReceivingAddress;
use crate::api::export::Timestamp;
use crate::api::export::TxProvingCapability;
use crate::api::tx_initiation::builder::input_selector::InputSelectionPolicy;
use crate::api::tx_initiation::builder::input_selector::InputSelector;
use crate::api::tx_initiation::builder::input_selector::SortOrder;
use crate::api::tx_initiation::builder::tx_output_list_builder::TxOutputListBuilder;
use crate::api::tx_initiation::error::CreateTxError;
use crate::api::tx_initiation::error::SendError;
use crate::api::tx_initiation::initiator::TransactionInitiator;
use crate::state::wallet::utxo_notification::UtxoNotificationMedium;

pub const CONSOLIDATION_FEE_PC: NativeCurrencyAmount =
    NativeCurrencyAmount::from_nau(NativeCurrencyAmount::coin_as_nau() / 10);
pub const CONSOLIDATION_FEE_SP: NativeCurrencyAmount =
    NativeCurrencyAmount::from_nau(NativeCurrencyAmount::coin_as_nau() / 200);

impl TransactionInitiator {
    /// Initiate a transaction that spends a batch of UTXOs to the node's own
    /// wallet, thereby reducing the total number of UTXOs under management.
    pub async fn consolidate(
        &mut self,
        num_inputs: Option<usize>,
        consolidation_address: Option<ReceivingAddress>,
        timestamp: Timestamp,
    ) -> Result<usize, ConsolidationError> {
        const CONSOLIDATION_INPUT_COUNT: usize = 4;
        let num_inputs = num_inputs.unwrap_or(CONSOLIDATION_INPUT_COUNT);

        debug!("consolidate: Attempting to consolidate {num_inputs} UTXOs in wallet");
        let input_candidates = self.input_candidates(timestamp).await;
        if input_candidates.len() < num_inputs {
            debug!("Nothing to consolidate as wallet has less than {num_inputs} spendable inputs.");
            return Err(ConsolidationError::NotEnoughUtxos {
                requested: num_inputs,
                present: input_candidates.len(),
            });
        }

        let policy =
            InputSelectionPolicy::from(InputSelectionPriority::ByAge(SortOrder::Descending))
                .require_confirmations(10);
        let selected_inputs = InputSelector::default()
            .input_candidates(input_candidates)
            .policy(policy)
            .take(num_inputs)
            .into_iter()
            .collect_vec();

        let unlocked_inputs = self
            .global_state_lock
            .lock_guard()
            .await
            .unlock_inputs(selected_inputs)
            .await;

        debug!(
            "Selected {} inputs for consolidation, in total amount {}.",
            unlocked_inputs.len(),
            unlocked_inputs.total_native_coins()
        );

        let receiving_address = match consolidation_address {
            Some(addr) => addr,
            None => {
                let mut state = self.global_state_lock.lock_guard_mut().await;

                state.wallet_state.next_unused_symmetric_key().await.into()
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

        let unlocked_amount = unlocked_inputs.total_native_coins();
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
            .generate_tx_details(unlocked_inputs, outputs, ChangePolicy::ExactChange, fee)
            .await?;

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

        Ok(num_inputs)
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
