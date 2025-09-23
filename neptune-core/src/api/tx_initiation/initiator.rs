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
use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
use crate::api::tx_initiation::builder::tx_artifacts_builder::TxCreationArtifactsBuilder;
use crate::api::tx_initiation::builder::tx_input_list_builder::InputSelectionPolicy;
use crate::api::tx_initiation::builder::tx_input_list_builder::TxInputListBuilder;
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
use crate::state::wallet::transaction_input::TxInput;
use crate::state::wallet::transaction_input::TxInputList;
use crate::state::wallet::transaction_output::TxOutputList;
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
    /// returns all spendable inputs in the wallet.
    ///
    /// the order of inputs is undefined.
    pub async fn spendable_inputs(&self, timestamp: Timestamp) -> TxInputList {
        // sadly we have to collect here because we can't hold ref after lock guard is dropped.
        self.global_state_lock
            .lock_guard()
            .await
            .wallet_spendable_inputs(timestamp)
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
        timestamp: Timestamp,
    ) -> impl IntoIterator<Item = TxInput> {
        TxInputListBuilder::new()
            .spendable_inputs(self.spendable_inputs(timestamp).await.into())
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

    /// Build and broadcast a regular transaction.
    pub async fn send(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        self.send_inner(outputs, change_policy, fee, timestamp, false)
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
        self.send_inner(outputs, change_policy, fee, timestamp, true)
            .await
    }

    /// Build a transaction and broadcast it.
    ///
    // Locking: this function uses an incrementally lower-level interface, which
    // takes locks where-ever needed and releases them as soon as possible
    // afterwards. As a result, no single lock is held over the bulk of the
    // function's duration, potentially leading to funky race conditions if
    // multiple invocations are made in parallel.
    async fn send_inner(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        transparent: bool,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        self.private().check_proceed_with_send(fee).await?;

        tracing::debug!("tx send initiated.");

        // The target proof-type is set to the lowest possible value here,
        // since we don't want the client (CLI or dashboard) to hang while
        // producing proofs. Instead, we let (a task started by) main loop
        // handle the proving.
        let target_proof_type = TransactionProofType::PrimitiveWitness;

        // generate outputs
        let tx_outputs = self.generate_tx_outputs(outputs).await;

        // select inputs
        let spend_amount = tx_outputs.total_native_coins() + fee;
        let policy = InputSelectionPolicy::Random;
        let tx_inputs = self
            .select_spendable_inputs(policy, spend_amount, timestamp)
            .await
            .into_iter()
            .collect::<Vec<_>>();

        // generate tx details (may add change output)
        let tx_details = TransactionDetailsBuilder::new()
            .timestamp(timestamp)
            .inputs(tx_inputs.into())
            .outputs(tx_outputs)
            .fee(fee)
            .change_policy(change_policy)
            .transparent(transparent)
            .build(&mut self.global_state_lock.clone().into())
            .await?;

        let block_height = self
            .global_state_lock
            .lock_guard()
            .await
            .chain
            .light_state()
            .header()
            .height;
        let cli_args = self.global_state_lock.cli();
        let network = cli_args.network;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
        // drop(state_lock); // release lock asap.

        tracing::info!("send: proving tx:\n{}", tx_details);

        // use cli options for building proof, but override proof-type
        let options = TritonVmProofJobOptionsBuilder::new()
            .template(&cli_args.as_proof_job_options())
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

        tracing::info!("send: assembling tx");

        // create transaction
        let transaction = self.assemble_transaction(&tx_details, proof)?;

        // assemble transaction artifacts
        let tx_creation_artifacts = TxCreationArtifactsBuilder::new()
            .transaction_details(tx_details)
            .transaction(transaction)
            .build()?;

        tracing::info!("send: recording tx");

        self.record_and_broadcast_transaction(&tx_creation_artifacts)
            .await?;

        tracing::info!("send: all done!");

        Ok(tx_creation_artifacts)
    }

    fn private(&self) -> super::private::TransactionInitiatorPrivate {
        super::private::TransactionInitiatorPrivate::new(self.global_state_lock.clone())
    }
}
