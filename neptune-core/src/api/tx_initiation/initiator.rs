//! provides flexible APIs for creating and sending neptune transactions.
//!
//! [TransactionInitiator] wraps the [builder](super::builder) API.
//!
//! The builder API is a bit more verbose but is also easy to use.
//!
//! This API is callable by rust users of this crate as well as the RPC server.
//!
//! The intent is to present the same (or similar) API for both rust usage and
//! RPC usage when creating transactions.
//!
//! see [tx_initiation](super) for other APIs.

use std::sync::Arc;

use super::error;
use crate::api::export::Timestamp;
use crate::api::tx_initiation::builder::transaction_builder::TransactionBuilder;
use crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
use crate::api::tx_initiation::builder::tx_artifacts_builder::TxCreationArtifactsBuilder;
use crate::api::tx_initiation::builder::tx_input_list_builder::InputSelectionPolicy;
use crate::api::tx_initiation::builder::tx_input_list_builder::TxInputListBuilder;
use crate::api::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::api::tx_initiation::builder::tx_output_list_builder::TxOutputListBuilder;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::transaction_proof::TransactionProofType;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::transaction_kernel_id::TransactionKernelId;
use crate::models::state::tx_creation_artifacts::TxCreationArtifacts;
use crate::models::state::wallet::change_policy::ChangePolicy;
use crate::models::state::wallet::transaction_input::TxInput;
use crate::models::state::wallet::transaction_input::TxInputList;
use crate::models::state::wallet::transaction_output::TxOutputList;
use crate::GlobalStateLock;

/// provides an API for building and sending neptune transactions.
#[derive(Debug)]
pub struct TransactionInitiator {
    global_state_lock: GlobalStateLock,
}

impl From<GlobalStateLock> for TransactionInitiator {
    fn from(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }
}

impl TransactionInitiator {
    /// returns all spendable inputs in the wallet.
    ///
    /// the order of inputs is undefined.
    pub async fn spendable_inputs(&self) -> TxInputList {
        // sadly we have to collect here because we can't hold ref after lock guard is dropped.
        self.global_state_lock
            .lock_guard()
            .await
            .wallet_spendable_inputs(Timestamp::now())
            .await
            .into_iter()
            .into()
    }

    /// retrieve spendable inputs sufficient to cover spend_amount by applying selection policy.
    ///
    /// see [InputSelectionPolicy] for a description of available policies.
    ///
    /// see [TxInputListBuilder] for details.
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

    /// generate a list of outputs from a list of [OutputFormat].
    ///
    /// note that the outputs can be expressed in tuple format, so long
    /// as there exists a suitable From adapter on `OutputFormat`.
    ///
    /// Each output may use either `OnChain` or `OffChain` notifications.
    ///
    /// See [TxOutputListBuilder] for details.
    pub async fn generate_tx_outputs(
        &self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
    ) -> TxOutputList {
        TxOutputListBuilder::new()
            .outputs(outputs)
            .build(&self.global_state_lock.clone().into())
            .await
    }

    /// generates [TransactionDetails] from inputs and outputs
    ///
    /// see [TransactionDetailsBuilder] for details.
    pub async fn generate_tx_details(
        &mut self,
        inputs: TxInputList,
        outputs: TxOutputList,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
    ) -> Result<TransactionDetails, error::CreateTxError> {
        TransactionDetailsBuilder::new()
            .timestamp(Timestamp::now())
            .inputs(inputs)
            .outputs(outputs)
            .fee(fee)
            .change_policy(change_policy)
            .build(&mut self.global_state_lock.clone().into())
            .await
    }

    /// generates a witness proof from [TransactionDetails]
    ///
    /// a witness proof is sufficient for initiating a transaction
    /// although it will not actually be broadcast to peer until
    /// neptune-core can upgrade it to a `ProofCollection`.
    ///
    /// this function should return immediately.
    ///
    /// see [builder::transaction_proof_builder](super::builder::transaction_proof_builder) for details.
    pub fn generate_witness_proof(&self, tx_details: Arc<TransactionDetails>) -> TransactionProof {
        let primitive_witness = PrimitiveWitness::from_transaction_details(&tx_details);
        TransactionProof::Witness(primitive_witness)
    }

    /// assembles transaction details and a proof into a transaction.
    ///
    /// note: normally assemble_transaction_artifacts() should be preferred
    /// because its output can be directly used as input for
    /// record_and_broadcast_transaction().
    ///
    /// see [TransactionBuilder] for details.
    pub fn assemble_transaction(
        &self,
        transaction_details: &TransactionDetails,
        transaction_proof: TransactionProof,
    ) -> Result<Transaction, error::CreateTxError> {
        TransactionBuilder::new()
            .transaction_details(transaction_details)
            .transaction_proof(transaction_proof)
            .build()
    }

    /// assembles transaction details and a proof into transaction artifacts.
    ///
    /// see [TransactionBuilder] for details.
    pub fn assemble_transaction_artifacts(
        &self,
        transaction_details: TransactionDetails,
        transaction_proof: TransactionProof,
    ) -> Result<TxCreationArtifacts, error::CreateTxError> {
        let transaction = TransactionBuilder::new()
            .transaction_details(&transaction_details)
            .transaction_proof(transaction_proof)
            .build()?;

        TxCreationArtifactsBuilder::new()
            .transaction(transaction)
            .transaction_details(transaction_details)
            .build()
    }

    /// records a transaction into the wallet, mempool, and begins
    /// preparing to broadcast to peers.
    ///
    /// This is the core API that needs to be called in order for a neptune-core
    /// node to send a transaction.
    ///
    /// Note that in a typical scenario, the transaction will not be broadcast
    /// or confirmed into a block right away. The proof must be upgraded first.
    ///
    /// Those with a powerful machine have the option to upgrade the proof
    /// themself before calling this method, in which case the transaction will
    /// be broadcast and available for confirmation right away.
    ///
    /// see [Transaction Initiation Sequence](super#transaction-initiation-sequence)
    pub async fn record_and_broadcast_transaction(
        &mut self,
        tx: &TxCreationArtifacts,
    ) -> Result<(), error::SendError> {
        // may have been checked before, but just in case.
        self.worker().check_rate_limit().await?;

        // note: acquires write-lock.
        // note: tx is validated internally.
        self.global_state_lock.record_own_transaction(tx).await?;

        // note: cheap arc clone of tx.
        self.worker()
            .broadcast_transaction(tx.transaction.clone())
            .await?;

        tracing::info!(
            "transaction accepted for sending!  recorded tx and initiated broadcast sequence:\n{}",
            tx.details
        );

        Ok(())
    }

    /// returns the type of proof that the queried transaction (in mempool)
    /// presently has.
    ///
    /// returns an error if the transaction is not in the mempool.
    pub async fn proof_type(
        &self,
        txid: TransactionKernelId,
    ) -> Result<TransactionProofType, error::UpgradeProofError> {
        self.global_state_lock
            .lock_guard()
            .await
            .mempool
            .get(txid)
            .map(|tx| (&tx.proof).into())
            .ok_or(error::UpgradeProofError::TxNotInMempool)
    }

    fn worker(&self) -> super::private::TransactionInitiatorPrivate {
        super::private::TransactionInitiatorPrivate::new(self.global_state_lock.clone())
    }
}
