//! This is the mid-level neptune-core API layer for creating and sending transactions.
//! It provides callers with a great deal of flexibility.
//!
//! This API wraps the [builder] API, which is a bit more verbose but also easy
//! to use.
//!
//! It is callable by rust users of this crate as well as the RPC server.
//!
//! The intent is to present the same API for both rust callers and RPC callers.
//!
//! The high-level [send] API is also available, which provides a single
//! send() method that should suffice for the majority of use cases.

use std::sync::Arc;

use super::error;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::transaction_proof::TransactionProofType;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::transaction_kernel_id::TransactionKernelId;
use crate::models::state::tx_creation_artifacts::TxCreationArtifacts;
use crate::models::state::wallet::change_policy::ChangePolicy;
use crate::models::state::wallet::transaction_input::TxInput;
use crate::models::state::wallet::transaction_input::TxInputList;
use crate::models::state::wallet::transaction_output::TxOutputList;
use crate::tx_initiation::builder::transaction_builder::TransactionBuilder;
use crate::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
use crate::tx_initiation::builder::tx_input_list_builder::InputSelectionPolicy;
use crate::tx_initiation::builder::tx_input_list_builder::TxInputListBuilder;
use crate::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::tx_initiation::builder::tx_output_list_builder::TxOutputListBuilder;
use crate::tx_initiation::export::Timestamp;
use crate::GlobalStateLock;

/// provides an API for building and sending neptune transactions.
///
/// This type cannot not be instantiated directly, but is instead
/// retrieved via [GlobalStateLock::tx_initiator()]
#[derive(Debug)]
pub struct TransactionInitiator {
    global_state_lock: GlobalStateLock,
}

impl TransactionInitiator {
    // this type should not be instantiated directly, but instead retrieved via
    // GlobalStateLock::tx_initiator()
    pub(crate) fn new(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }

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
    /// see [InputSelectionPolicy]
    ///
    /// pub enum InputSelectionPolicy {
    ///     Random,
    ///     ByProvidedOrder,
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

    /// generate a list of outputs from a list of [OutputFormat].
    ///
    /// this is a wrapper around [TxOutputListBuilder], which callers can also
    /// use directly.
    ///
    /// note that the outputs can be expressed in tuple format, so long
    /// as there exists a suitable From adapter on `OutputFormat`.
    ///
    /// it is recommended to collect the results into a [TxOutputList]
    /// which provides additional methods.
    ///
    /// Each output may use either `OnChain` or `OffChain` notifications.
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
    /// see [TransactionDetailsBuilder].
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
    /// see [builder::transaction_proof_builder] for details.
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
        transaction_details: Arc<TransactionDetails>,
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
        transaction_details: Arc<TransactionDetails>,
        transaction_proof: TransactionProof,
    ) -> Result<TxCreationArtifacts, error::CreateTxError> {
        TransactionBuilder::new()
            .transaction_details(transaction_details)
            .transaction_proof(transaction_proof)
            .build_tx_artifacts(self.global_state_lock.cli().network)
    }

    /// records a transaction into the wallet, mempool, and begins
    /// preparing to broadcast to peers.
    ///
    /// see [transaction_builder] for details.
    pub async fn record_and_broadcast_transaction(
        &mut self,
        tx: &TxCreationArtifacts,
    ) -> Result<(), error::SendError> {
        // may have been checked before, but just in case.
        self.worker().check_rate_limit().await?;

        // note: acquires write-lock.
        // note: this should validate tx, but presently does not.
        self.global_state_lock.record_transaction(tx).await?;

        // note: cheap arc clone of tx.
        self.worker()
            .broadcast_transaction(tx.transaction.clone())
            .await?;

        Ok(())
    }

    /// upgrades a transaction's proof.
    ///
    /// ignored if the transaction is already upgraded to level of supplied
    /// proof (or higher)
    ///
    /// note: experimental and untested!  do not use yet!
    pub async fn upgrade_tx_proof(
        &mut self,
        transaction_id: TransactionKernelId,
        transaction_proof: TransactionProof,
    ) -> Result<(), error::UpgradeProofError> {
        let mut gsm = self.global_state_lock.lock_guard_mut().await;

        let Some(tx) = gsm.mempool.get_mut(transaction_id) else {
            return Err(error::UpgradeProofError::TxNotInMempool);
        };

        let new = TransactionProofType::from(&transaction_proof);
        let old = TransactionProofType::from(&tx.proof);

        if new <= old {
            return Err(error::UpgradeProofError::ProofNotAnUpgrade);
        }

        // tbd: how long does this verify take?   If too slow,
        // we could obtain tx with a read-lock first, verify,
        // then obtain again with write-lock to mutate it.
        if !transaction_proof.verify(tx.kernel.mast_hash()).await {
            return Err(error::UpgradeProofError::InvalidProof);
        }

        // tbd: do we need to remove this tx from mempool and re-add
        // in order to trigger necessary events?

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
