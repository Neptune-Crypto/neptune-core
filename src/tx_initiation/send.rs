//! This is the start of an API layer for sending transactions
//! that is callable by rust users of this crate as well
//! as the RPC server.

use std::sync::Arc;

use tasm_lib::prelude::Digest;

use crate::job_queue::triton_vm::vm_job_queue;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::transaction_proof::TransactionProofType;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::transaction_kernel_id::TransactionKernelId;
use crate::models::state::tx_creation_artifacts::TxCreationArtifacts;
use crate::models::state::tx_creation_config::ChangePolicy;
use crate::models::state::tx_creation_config::TxCreationConfig;
use crate::models::state::tx_proving_capability::TxProvingCapability;
use crate::models::state::wallet::transaction_input::TxInput;
use crate::models::state::wallet::transaction_input::TxInputList;
use crate::models::state::wallet::transaction_output::TxOutputList;
use crate::tx_initiation::builder::transaction_builder::TransactionBuilder;
use crate::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
use crate::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::tx_initiation::builder::tx_input_list_builder::InputSelectionPolicy;
use crate::tx_initiation::builder::tx_input_list_builder::TxInputListBuilder;
use crate::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::tx_initiation::builder::tx_output_list_builder::TxOutputListBuilder;
use crate::GlobalStateLock;
use crate::RPCServerToMain;

#[derive(Debug)]
pub struct TransactionSender {
    global_state_lock: GlobalStateLock,
}

impl TransactionSender {
    // goal is for this type to be usable outside this crate
    pub(crate) fn new(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }

    pub async fn spendable_inputs(&self) -> TxInputList {
        // sadly we have to collect here because we can't hold ref after lock guard is dropped.
        self.global_state_lock
            .lock_guard()
            .await
            .wallet_spendable_inputs()
            .await
            .into_iter()
            .into()
    }

    /// retrieve spendable inputs sufficient to cover spend_amount by applying selection policy.
    ///
    /// see [InputSelectionPolicy]
    ///
    /// pub enum InputSelectionPolicy {
    ///     Random,
    ///     ByNativeCoinAmount(SortOrder),
    ///     ByUtxoSize(SortOrder),
    /// }
    pub async fn select_spendable_inputs(
        &self,
        policy: InputSelectionPolicy,
        spend_amount: NativeCurrencyAmount,
    ) -> impl IntoIterator<Item = TxInput> {
        TxInputListBuilder::new()
            .spendable_inputs(self.spendable_inputs().await.into())
            .policy(policy)
            .spend_amount(spend_amount)
            .build()
    }

    /// generate TxOutputList from a list of [OutputFormat].
    ///
    /// this is a wrapper around [TxOutputListBuilder], which callers can also
    /// use directly.
    ///
    /// This is a helper method for generating the `TxOutputList` that is
    /// required by `create_transaction`.
    ///
    /// Each output may use either `OnChain` or `OffChain` notifications.
    pub async fn generate_tx_outputs(
        &self,
        outputs: impl IntoIterator<Item = OutputFormat>,
    ) -> TxOutputList {
        let mut builder = TxOutputListBuilder::new();

        for output_format in outputs {
            builder = builder.output_format(output_format);
        }

        let gs = self.global_state_lock.lock_guard().await;
        builder.build(&gs.wallet_state, gs.chain.light_state().header().height)
    }

    pub async fn generate_tx_details(
        &mut self,
        inputs: TxInputList,
        outputs: TxOutputList,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
    ) -> anyhow::Result<TransactionDetails> {
        let mut gsm = self.global_state_lock.lock_guard_mut().await;

        let light_state = gsm.chain.light_state_clone(); // cheap Arc clone
        TransactionDetailsBuilder::new()
            .inputs(inputs)
            .outputs(outputs)
            .fee(fee)
            .change_policy(change_policy)
            .build(&light_state, &mut gsm.wallet_state)
            .await
    }

    pub fn generate_witness_proof(&self, tx_details: Arc<TransactionDetails>) -> TransactionProof {
        let primitive_witness = PrimitiveWitness::from_transaction_details(&tx_details);
        TransactionProof::Witness(primitive_witness)
    }

    pub fn assemble_transaction(
        &self,
        transaction_details: Arc<TransactionDetails>,
        transaction_proof: TransactionProof,
    ) -> anyhow::Result<Transaction> {
        TransactionBuilder::new()
            .transaction_details(transaction_details)
            .transaction_proof(transaction_proof)
            .build()
    }

    pub async fn record_and_broadcast_transaction(
        &mut self,
        tx: &TxCreationArtifacts,
    ) -> Result<(), error::SendError> {
        // should have been checked before, but just in case.
        self.check_rate_limit().await?;

        // note: acquires write-lock.
        self.global_state_lock.record_transaction(tx).await?;

        self.broadcast_transaction(tx.transaction.clone()).await?;

        Ok(())
    }

    // caller should call offchain-notifications() on the returned value
    // to retrieve (and store) offchain notifications, if any.
    pub async fn send(
        &mut self,
        outputs: impl IntoIterator<Item = OutputFormat>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        now: Timestamp,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        self.check_proceed_with_send(fee).await?;

        // The proving capability is set to the lowest possible value here,
        // since we don't want the client (CLI or dashboard) to hang while
        // producing proofs. Instead, we let (a task started by) main loop
        // handle the proving.
        let tx_proving_capability = TxProvingCapability::PrimitiveWitness;

        tracing::debug!("step 1. generate outputs. need read-lock");

        let tx_outputs = self.generate_tx_outputs(outputs).await;

        tracing::debug!("step 2. create tx.");

        // Create the transaction
        //
        // Note that create_transaction() does not modify any state and only
        // requires acquiring a read-lock which does not block other tasks.
        // This is important because internally it calls prove() which is a very
        // lengthy operation.
        //
        // note: A change output will be added to tx_outputs if needed.
        let config = TxCreationConfig::default()
            .use_change_policy(change_policy)
            .with_prover_capability(tx_proving_capability)
            .use_job_queue(vm_job_queue());

        let tx_artifacts = match self.create_transaction(tx_outputs, fee, now, config).await {
            Ok(tx) => tx,
            Err(e) => {
                tracing::error!("Could not create transaction: {}", e);
                return Err(e.into());
            }
        };

        tracing::debug!(
            "Generated {} offchain notifications",
            tx_artifacts
                .offchain_notifications(self.global_state_lock.cli().network)
                .len()
        );

        tracing::debug!("step 3. record and broadcast tx.");

        self.record_and_broadcast_transaction(&tx_artifacts).await?;

        Ok(tx_artifacts)
    }

    /// upgrades a transaction's proof.
    ///
    /// ignored if the transaction is already upgraded to level of supplied
    /// proof (or higher)
    pub async fn upgrade_tx_proof(
        &mut self,
        transaction_id: TransactionKernelId,
        transaction_proof: TransactionProof,
    ) -> anyhow::Result<()> {
        let mut gsm = self.global_state_lock.lock_guard_mut().await;

        let Some(tx) = gsm.mempool.get_mut(transaction_id) else {
            anyhow::bail!("transaction not found in mempool");
        };

        let new = TransactionProofType::from(&transaction_proof);
        let old = TransactionProofType::from(&tx.proof);

        if new <= old {
            anyhow::bail!("input proof is not an upgrade");
        }

        // tbd: how long does this verify take?   If too slow,
        // we could obtain tx with a read-lock first, verify,
        // then obtain again with write-lock to mutate it.
        if !transaction_proof.verify(tx.kernel.mast_hash()).await {
            anyhow::bail!("invalid proof");
        }

        // mutate
        tx.proof = transaction_proof;

        Ok(())
    }

    /// returns the type of proof that the queried transaction (in mempool)
    /// presently has.
    ///
    /// returns an error if the transaction is not in the mempool.
    pub async fn proof_type(
        &self,
        txid: TransactionKernelId,
    ) -> anyhow::Result<TransactionProofType> {
        self.global_state_lock
            .lock_guard()
            .await
            .mempool
            .get(txid)
            .map(|tx| (&tx.proof).into())
            .ok_or_else(|| anyhow::anyhow!("transaction not in mempool"))
    }

    /// note: this is a helper wrapper around TransactionDetailsBuilder,
    /// TransactionProofBuilder and TransactionBuilder
    pub(crate) async fn create_transaction(
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

    /// note: this is a helper wrapper around TransactionProofBuilder and TransactionBuilder
    pub(crate) async fn create_raw_transaction(
        tx_details_arc: Arc<TransactionDetails>,
        config: TxCreationConfig,
    ) -> anyhow::Result<Transaction> {
        let proof = TransactionProofBuilder::new()
            .transaction_details(tx_details_arc.clone())
            .job_queue(config.job_queue())
            .proof_job_options(config.proof_job_options())
            .tx_proving_capability(config.prover_capability())
            .build()
            .await?;

        TransactionBuilder::new()
            .transaction_details(tx_details_arc)
            .transaction_proof(proof)
            .build()
    }

    // note: not pub, as one should never call broadcast without
    // recording first.
    async fn broadcast_transaction(
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

    async fn check_proceed_with_send(
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
            return Err(error::SendError::NegativeFee);
        }

        if matches!(
            self.global_state_lock.cli().proving_capability(),
            TxProvingCapability::LockScript | TxProvingCapability::PrimitiveWitness
        ) {
            tracing::warn!(
                "Cannot initiate transaction because transaction proving capability is too weak."
            );
            return Err(error::SendError::TooWeak);
        }

        self.check_rate_limit().await
    }

    // check if send would exceed the send rate-limit (per block)
    async fn check_rate_limit(&self) -> Result<(), error::SendError> {
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
