//! This is the start of an API layer for creating and sending transactions.  It
//! is callable by rust users of this crate as well as the RPC server.
//!
//! The intent is to present the same API for both rust callers and RPC callers.

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
use crate::models::state::tx_creation_config::ChangePolicy;
use crate::models::state::wallet::transaction_input::TxInput;
use crate::models::state::wallet::transaction_input::TxInputList;
use crate::models::state::wallet::transaction_output::TxOutputList;
use crate::tx_initiation::builder::transaction_builder::TransactionBuilder;
use crate::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
use crate::tx_initiation::builder::tx_input_list_builder::InputSelectionPolicy;
use crate::tx_initiation::builder::tx_input_list_builder::TxInputListBuilder;
use crate::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::tx_initiation::builder::tx_output_list_builder::TxOutputListBuilder;
use crate::GlobalStateLock;

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
    ) -> Result<TransactionDetails, error::CreateTxError> {
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
    ) -> Result<Transaction, error::CreateTxError> {
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
        self.worker().check_rate_limit().await?;

        // note: acquires write-lock.
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
