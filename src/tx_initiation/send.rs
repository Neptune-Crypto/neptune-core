//! This is the start of an API layer for sending transactions
//! that is callable by rust users of this crate as well
//! as the RPC server.

use std::sync::Arc;

use tasm_lib::prelude::Digest;

use crate::job_queue::triton_vm::vm_job_queue;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::tx_creation_artifacts::TxCreationArtifacts;
use crate::models::state::tx_creation_config::TxCreationConfig;
use crate::models::state::tx_proving_capability::TxProvingCapability;
use crate::models::state::wallet::address::KeyType;
use crate::models::state::wallet::address::ReceivingAddress;
use crate::models::state::wallet::utxo_notification::PrivateNotificationData;
use crate::models::state::wallet::utxo_notification::UtxoNotificationMedium;
use crate::GlobalStateLock;
use crate::RPCServerToMain;

#[derive(Debug)]
pub struct TransactionSender {
    global_state_lock: GlobalStateLock,
}

impl TransactionSender {
    // goal is for this type to be usable outside this crate, but
    // we should not expose RPCServerToMain, so we will need to expose
    // this type in some other way
    pub(crate) fn new(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }

    pub async fn record_and_broadcast_tx(
        &mut self,
        tx: &TxCreationArtifacts,
    ) -> anyhow::Result<()> {
        // note: acquires write-lock.
        self.global_state_lock.record_transaction(tx).await?;

        self.broadcast_transaction(tx.transaction.clone()).await?;

        Ok(())
    }

    pub async fn broadcast_transaction(
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

    pub async fn send_to_many(
        &mut self,
        outputs: Vec<(ReceivingAddress, NativeCurrencyAmount)>,
        utxo_notification_media: (UtxoNotificationMedium, UtxoNotificationMedium),
        fee: NativeCurrencyAmount,
        now: Timestamp,
    ) -> Result<(Arc<Transaction>, Vec<PrivateNotificationData>), error::SendError> {
        if self.global_state_lock.cli().no_transaction_initiation {
            tracing::warn!(
                "Cannot initiate transaction because `--no-transaction-initiation` flag is set."
            );
            return Err(error::SendError::Unsupported.into());
        }

        // abort early on negative fee
        if fee.is_negative() {
            tracing::warn!("Cannot send negative-fee transaction.");
            return Err(error::SendError::NegativeFee.into());
        }

        if matches!(
            self.global_state_lock.cli().proving_capability(),
            TxProvingCapability::LockScript | TxProvingCapability::PrimitiveWitness
        ) {
            tracing::warn!(
                "Cannot initiate transaction because transaction proving capability is too weak."
            );
            return Err(error::SendError::TooWeak.into());
        }

        // The proving capability is set to the lowest possible value here,
        // since we don't want the client (CLI or dashboard) to hang while
        // producing proofs. Instead, we let (a task started by) main loop
        // handle the proving.
        let tx_proving_capability = TxProvingCapability::PrimitiveWitness;

        let (owned_utxo_notification_medium, unowned_utxo_notification_medium) =
            utxo_notification_media;

        // check if this send would exceed the send rate-limit (per block)
        {
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
        }

        tracing::debug!("stmi: step 1. get change key. need write-lock");

        // obtain next unused symmetric key for change utxo
        let change_key = {
            let mut s = self.global_state_lock.lock_guard_mut().await;
            let key = s
                .wallet_state
                .next_unused_spending_key(KeyType::Symmetric)
                .await
                .expect("wallet should be capable of generating symmetric spending keys");

            // write state to disk. create_transaction() may be slow.
            s.persist_wallet().await.expect("flushed");
            key
        };

        tracing::debug!("stmi: step 2. generate outputs. need read-lock");

        let state = self.global_state_lock.lock_guard().await;
        let tx_outputs = state.generate_tx_outputs(
            outputs,
            owned_utxo_notification_medium,
            unowned_utxo_notification_medium,
        );

        tracing::debug!("stmi: step 3. create tx. have read-lock");

        // Create the transaction
        //
        // Note that create_transaction() does not modify any state and only
        // requires acquiring a read-lock which does not block other tasks.
        // This is important because internally it calls prove() which is a very
        // lengthy operation.
        //
        // note: A change output will be added to tx_outputs if needed.
        let config = TxCreationConfig::default()
            .recover_change(Arc::new(change_key), owned_utxo_notification_medium)
            .with_prover_capability(tx_proving_capability)
            .use_job_queue(vm_job_queue());

        let tx_artifacts = match state
            .create_transaction(tx_outputs.clone(), fee, now, config)
            .await
        {
            Ok(tx) => tx,
            Err(e) => {
                tracing::error!("Could not create transaction: {}", e);
                return Err(e.into());
            }
        };
        drop(state);

        let offchain_notifications = tx_artifacts
            .details
            .tx_outputs
            .private_notifications(self.global_state_lock.cli().network);

        tracing::debug!(
            "Generated {} offchain notifications",
            offchain_notifications.len()
        );

        self.record_and_broadcast_tx(&tx_artifacts).await?;

        Ok((tx_artifacts.transaction, offchain_notifications))
    }
}

pub mod error {
    use serde::Deserialize;
    use serde::Serialize;

    use super::*;

    /// enumerates possible transaction send errors
    #[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
    #[non_exhaustive]
    pub enum SendError {
        #[error("send() is not supported by this node")]
        Unsupported,

        #[error("transaction could not be broadcast.")]
        NotBroadcast,

        // catch-all error, eg for anyhow errors
        #[error("transaction could not be sent.  reason: {0}")]
        Failed(String),

        #[error("Transaction with negative fees not allowed")]
        NegativeFee,

        #[error("machine too weak to initiate transactions")]
        TooWeak,

        #[error("Send rate limit reached for block height {height} ({digest}). A maximum of {max} tx may be sent per block.", digest = tip_digest.to_hex())]
        RateLimit {
            height: BlockHeight,
            tip_digest: Digest,
            max: usize,
        },
    }

    // convert anyhow::Error to a SendError::Failed.
    // note that anyhow Error is not serializable.
    impl From<anyhow::Error> for SendError {
        fn from(e: anyhow::Error) -> Self {
            Self::Failed(e.to_string())
        }
    }
}
