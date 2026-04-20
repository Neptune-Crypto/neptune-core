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

use tracing::trace;

use super::error;
use crate::api::export::Timestamp;
use crate::api::tx_initiation::builder::input_selector::InputSelectionPolicy;
use crate::api::tx_initiation::builder::input_selector::InputSelector;
use crate::api::tx_initiation::builder::transaction_builder::TransactionBuilder;
use crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
use crate::api::tx_initiation::builder::tx_artifacts_builder::TxCreationArtifactsBuilder;
use crate::api::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::api::tx_initiation::builder::tx_output_list_builder::TxOutputListBuilder;
use crate::application::triton_vm_job_queue::vm_job_queue;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::transaction_proof::TransactionProofType;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::state::transaction::transaction_details::TransactionDetails;
use crate::state::transaction::transaction_kernel_id::TransactionKernelId;
use crate::state::transaction::tx_creation_artifacts::TxCreationArtifacts;
use crate::state::wallet::change_policy::ChangePolicy;
use crate::state::wallet::input_candidate::InputCandidate;
use crate::state::wallet::transaction_output::TxOutputList;
use crate::state::wallet::unlocked_utxo::TxInputs;
use crate::state::StateLock;
use crate::GlobalStateLock;

/// provides an API for building and sending neptune transactions.
#[derive(Debug)]
pub struct TransactionInitiator {
    pub(super) global_state_lock: GlobalStateLock,
}

impl From<GlobalStateLock> for TransactionInitiator {
    fn from(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }
}

impl TransactionInitiator {
    /// Return all spendable inputs in the wallet.
    pub async fn input_candidates(&self, timestamp: Timestamp) -> Vec<InputCandidate> {
        let state = self.global_state_lock.lock_guard().await;
        let current_height = state.chain.tip().header().height;
        let validator = state.utxo_validator();
        let wallet_status = state.wallet_state.get_wallet_status(&validator).await;
        let spendable_inputs = wallet_status.spendable_inputs(timestamp);
        spendable_inputs
            .into_iter()
            .map(|synced_utxo| InputCandidate::from_synced_utxo(synced_utxo, current_height))
            .collect()
    }

    /// Get enough inputs to cover spend_amount.
    ///
    /// Enfoce selection policy.
    ///
    /// see [InputSelectionPolicy] for a description of available policies.
    ///
    /// see [InputSelector] for details.
    pub async fn select_inputs(
        &self,
        policy: InputSelectionPolicy,
        spend_amount: NativeCurrencyAmount,
        timestamp: Timestamp,
        lustration_threshold: Option<u64>,
    ) -> Result<Vec<InputCandidate>, error::CreateTxError> {
        InputSelector::new(lustration_threshold)
            .input_candidates(self.input_candidates(timestamp).await)
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
        inputs: TxInputs,
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

    /// Build and broadcast a regular transaction.
    pub async fn send(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        accept_lustrations: bool,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        let transparent = false;
        self.send_inner(
            outputs,
            change_policy,
            fee,
            timestamp,
            transparent,
            accept_lustrations,
        )
        .await
    }

    /// Build and broadcast a *transparent* transaction.
    ///
    /// While transactions are private by default, an initiator can opt to make
    /// it transparent. In this case, the transaction contains an announcement
    /// containing the consumed and produced UTXOs along with the commitment
    /// randomness.
    pub async fn send_transparent(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        // Lustrations are always accepted on transparent transactions, since
        // all inputs are public anyway.
        let accept_lustrations = true;
        self.send_inner(
            outputs,
            change_policy,
            fee,
            timestamp,
            true,
            accept_lustrations,
        )
        .await
    }

    /// Build a transaction and broadcast it.
    async fn send_inner(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        transparent: bool,
        accept_lustrations: bool,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        tracing::info!("send: recording tx");

        let input_policy =
            InputSelectionPolicy::default().set_lustration_acceptance(accept_lustrations);
        let tx_creation_artifacts = self
            .construct_transaction_mutable_state(
                outputs,
                change_policy,
                fee,
                timestamp,
                transparent,
                input_policy,
            )
            .await?;

        if tx_creation_artifacts.details.contains_lustrations() && !accept_lustrations {
            return Err(error::SendError::Tx(
                error::CreateTxError::RequiresLustration,
            ));
        }

        self.record_and_broadcast_transaction(&tx_creation_artifacts)
            .await?;

        tracing::info!("send: all done!");

        Ok(tx_creation_artifacts)
    }

    /// Private, inner function for building a transaction. Should not be
    /// exposed since it relies on very domain-specific knowledge about locks
    /// and the mutation of global state, and since it may panic if used
    /// incorrectly.
    ///
    /// This function *must* hold the same lock in order to avoid race
    /// conditions during the construction of a transaction.
    ///
    /// # Panics
    /// - If a lock type imcompatible with the selected [`ChangePolicy`] is
    ///   used.
    async fn construct_transaction_inner<'a>(
        mut state_lock: StateLock<'a>,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        transparent: bool,
        input_selection_policy: InputSelectionPolicy,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        assert!(
            !change_policy.requires_state_mutation()
            || !matches!(state_lock, StateLock::ReadGuard(_)),
            "If change policy requires state mutation, then a read lock does not work for this function.");
        let tx_outputs = TxOutputListBuilder::new()
            .outputs(outputs)
            .build(&state_lock)
            .await;

        // select inputs
        let spend_amount = tx_outputs.total_native_coins() + fee;
        trace!("spend_amount: {spend_amount}");

        let current_height = state_lock.gs().chain.tip().header().height;
        let validator = state_lock.gs().utxo_validator();
        let lustration_threshold = state_lock.gs().chain.lustration_threshold();
        let wallet_status = state_lock
            .gs()
            .wallet_state
            .get_wallet_status(&validator)
            .await;
        let spendable_inputs = wallet_status.spendable_inputs(timestamp);
        let input_candidates = spendable_inputs
            .into_iter()
            .map(|synced_utxo| InputCandidate::from_synced_utxo(synced_utxo, current_height))
            .collect();
        let selected_inputs = InputSelector::new(lustration_threshold)
            .input_candidates(input_candidates)
            .policy(input_selection_policy)
            .spend_amount(spend_amount)
            .build()?;
        trace!("selected {} inputs for transaction.", selected_inputs.len());

        let unlocked_inputs = state_lock.gs().unlock_inputs(selected_inputs).await;

        // generate tx details (may add change output). Mutates wallet state
        // depending on the chosen change policy.
        let tx_details = TransactionDetailsBuilder::new()
            .timestamp(timestamp)
            .inputs(unlocked_inputs)
            .outputs(tx_outputs)
            .fee(fee)
            .change_policy(change_policy)
            .transparent(transparent)
            .build(&mut state_lock)
            .await?;

        let block_height = state_lock.gs().chain.tip().header().height;
        let network = state_lock.cli().network;
        let proof_job_options = state_lock.cli().as_proof_job_options();

        // Release lock ASAP
        drop(state_lock);

        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);

        // The target proof-type is set to the lowest possible value here,
        // since we don't want the client (CLI or dashboard) to hang while
        // producing proofs. Instead, we let (a task started by) main loop
        // handle the proving.
        let target_proof_type = TransactionProofType::PrimitiveWitness;
        tracing::info!("send: creating primitive witness for:\n{}", tx_details);

        // use cli options for building proof, but override proof-type
        let options = TritonVmProofJobOptionsBuilder::new()
            .template(&proof_job_options)
            .proof_type(target_proof_type)
            .build();

        // generate proof
        let proof = TransactionProofBuilder::new()
            .consensus_rule_set(consensus_rule_set)
            .transaction_details(&tx_details)
            .job_queue(vm_job_queue())
            .proof_job_options(options)
            .build()
            .await?;

        // create transaction
        let transaction = TransactionBuilder::new()
            .transaction_details(&tx_details)
            .transaction_proof(proof)
            .build()?;

        // assemble transaction artifacts
        let tx_creation_artifacts = TxCreationArtifactsBuilder::new()
            .transaction_details(tx_details)
            .transaction(transaction)
            .build()?;

        Ok(tx_creation_artifacts)
    }

    /// Build a transaction without broadcasting it or inserting it into the
    /// mempool.
    ///
    /// This function does not mutate the global state, so it only needs a read
    /// lock. This function should *only* be used if you know that the
    /// transaction initialization is guaranteed to not mutate the global state.
    ///
    /// # Panics
    /// - If the selected [`ChangePolicy`] requires mutation of the global
    ///   state.
    pub(crate) async fn construct_transaction_immutable_state(
        &self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        transparent: bool,
        input_selection_policy: InputSelectionPolicy,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        self.private().check_proceed_with_send(fee).await?;

        tracing::debug!("tx send initiated.");

        // Hold read lock across entire transaction construction to avoid race
        // conditions from e.g. a new block being set as tip.
        // generate outputs
        let read_lock = self.global_state_lock.lock_guard().await;
        let read_lock = StateLock::ReadGuard(read_lock);

        Self::construct_transaction_inner(
            read_lock,
            outputs,
            change_policy,
            fee,
            timestamp,
            transparent,
            input_selection_policy,
        )
        .await
    }

    /// Build a transaction without broadcasting it or inserting it into the
    /// mempool.
    ///
    /// This function grabs a write lock on the global state and may thus mutate
    /// the global state.
    pub(crate) async fn construct_transaction_mutable_state(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        transparent: bool,
        input_selection_policy: InputSelectionPolicy,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        self.private().check_proceed_with_send(fee).await?;

        tracing::debug!("tx send initiated.");

        // Hold read lock across entire transaction construction to avoid race
        // conditions from e.g. a new block being set as tip.
        // generate outputs
        let write_lock = self.global_state_lock.lock_guard_mut().await;
        let write_lock = StateLock::WriteGuard(write_lock);

        Self::construct_transaction_inner(
            write_lock,
            outputs,
            change_policy,
            fee,
            timestamp,
            transparent,
            input_selection_policy,
        )
        .await
    }

    fn private(&self) -> super::private::TransactionInitiatorPrivate {
        super::private::TransactionInitiatorPrivate::new(self.global_state_lock.clone())
    }
}
