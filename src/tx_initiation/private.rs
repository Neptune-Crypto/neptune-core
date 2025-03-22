//! This is the start of an API layer for creating and sending transactions.  It
//! is callable by rust users of this crate as well as the RPC server.
//!
//! The intent is to present the same API for both rust callers and RPC callers.

use std::sync::Arc;

use super::error;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::tx_creation_artifacts::TxCreationArtifacts;
use crate::models::state::tx_creation_config::TxCreationConfig;
use crate::models::state::tx_proving_capability::TxProvingCapability;
use crate::models::state::wallet::transaction_output::TxOutputList;
use crate::tx_initiation::builder::transaction_builder::TransactionBuilder;
use crate::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
use crate::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::GlobalStateLock;
use crate::RPCServerToMain;

pub(super) struct TransactionInitiatorPrivate {
    global_state_lock: GlobalStateLock,
}

impl TransactionInitiatorPrivate {
    pub(super) fn new(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }

    /// note: this is a internal internal (private) API.
    ///
    /// it is now just a wrapper around TransactionDetailsBuilder,
    /// TransactionProofBuilder and TransactionBuilder
    pub(super) async fn create_transaction(
        &mut self,
        tx_outputs: TxOutputList,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        tx_creation_config: TxCreationConfig,
    ) -> anyhow::Result<TxCreationArtifacts> {
        let mut gsm = self.global_state_lock.lock_guard_mut().await;

        let light_state = gsm.chain.light_state_clone(); // cheap Arc clone
        let tx_details = TransactionDetailsBuilder::new()
            .inputs(
                gsm.wallet_state
                    .allocate_sufficient_input_funds(
                        tx_outputs.total_native_coins(),
                        light_state.hash(),
                        &light_state.mutator_set_accumulator_after(),
                        timestamp,
                    )
                    .await?
                    .into(),
            )
            .outputs(tx_outputs)
            .fee(fee)
            .change_policy(tx_creation_config.change_policy())
            .build(&light_state, &mut gsm.wallet_state)
            .await?;
        drop(gsm);

        let tx_details_rc = Arc::new(tx_details);

        let proof = TransactionProofBuilder::new()
            .transaction_details(tx_details_rc.clone())
            .job_queue(tx_creation_config.job_queue())
            .proof_job_options(tx_creation_config.proof_job_options())
            .tx_proving_capability(tx_creation_config.prover_capability())
            .build()
            .await?;

        let transaction = TransactionBuilder::new()
            .transaction_details(tx_details_rc.clone())
            .transaction_proof(proof)
            .build()?;

        let transaction_creation_artifacts = TxCreationArtifacts {
            transaction: Arc::new(transaction),
            details: tx_details_rc,
        };

        Ok(transaction_creation_artifacts)
    }

    // note: not pub, as one should never call broadcast without
    // recording first.
    pub(super) async fn broadcast_transaction(
        &self,
        transaction: Arc<Transaction>,
    ) -> Result<(), error::SendError> {
        // Send BroadcastTx message to main
        let response = self
            .global_state_lock
            .rpc_server_to_main_tx()
            .send(RPCServerToMain::BroadcastTx(transaction))
            .await;

        if let Err(e) = response {
            tracing::error!("Could not send Tx to main task: error: {}", e.to_string());
            return Err(error::SendError::NotBroadcast);
        };

        Ok(())
    }

    pub(super) async fn check_proceed_with_send(
        &self,
        fee: NativeCurrencyAmount,
    ) -> Result<(), error::SendError> {
        if self.global_state_lock.cli().no_transaction_initiation {
            tracing::warn!(
                "Cannot initiate transaction because `--no-transaction-initiation` flag is set."
            );
            return Err(error::SendError::Unsupported);
        }

        // abort early on negative fee
        if fee.is_negative() {
            tracing::warn!("Cannot send negative-fee transaction.");
            return Err(error::CreateTxError::NegativeFee.into());
        }

        if matches!(
            self.global_state_lock.cli().proving_capability(),
            TxProvingCapability::LockScript | TxProvingCapability::PrimitiveWitness
        ) {
            tracing::warn!(
                "Cannot initiate transaction because transaction proving capability is too weak."
            );
            return Err(error::CreateProofError::TooWeak.into());
        }

        self.check_rate_limit().await
    }

    // check if send would exceed the send rate-limit (per block)
    pub(super) async fn check_rate_limit(&self) -> Result<(), error::SendError> {
        // send rate limiting only applies below height 25000
        // which is approx 5.6 months after launch.
        // after that, the training wheel come off.
        const RATE_LIMIT_UNTIL_HEIGHT: u64 = 25000;
        let state = self.global_state_lock.lock_guard().await;

        if state.chain.light_state().header().height < RATE_LIMIT_UNTIL_HEIGHT.into() {
            const RATE_LIMIT: usize = 2;
            let tip_digest = state.chain.light_state().hash();
            let send_count_at_tip = state
                .wallet_state
                .count_sent_transactions_at_block(tip_digest)
                .await;
            tracing::debug!(
                "send-tx rate-limit check:  found {} sent-tx at current tip.  limit = {}",
                send_count_at_tip,
                RATE_LIMIT
            );
            if send_count_at_tip >= RATE_LIMIT {
                let height = state.chain.light_state().header().height;
                let e = error::SendError::RateLimit {
                    height,
                    tip_digest,
                    max: RATE_LIMIT,
                };
                tracing::warn!("{}", e.to_string());
                return Err(e);
            }
        }
        Ok(())
    }
}
