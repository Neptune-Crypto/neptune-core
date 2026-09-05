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

use itertools::Itertools;
use neptune_consensus::chaintx::link_tx::LinkTx;
use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
use neptune_consensus::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use neptune_consensus::proof_abstractions::triton_vm_job_queue::vm_job_queue;
use neptune_consensus::transaction::lock_script::LockScript;
use neptune_consensus::transaction::transaction_proof::TransactionProofType;
use neptune_consensus::transaction::utxo::Utxo;
use neptune_consensus::transaction::Transaction;
use neptune_consensus::transaction::TransactionProof;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_mempool::transaction_kernel_id::TransactionKernelId;
use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::chained_transaction_details::ChainedTransactionDetails;
use neptune_wallet::chained_transaction_details::ThruputInput;
use neptune_wallet::change_policy::ChangePolicy;
use neptune_wallet::transaction_details::TransactionDetails;
use neptune_wallet::transaction_output::TxOutput;
use neptune_wallet::transaction_output::TxOutputList;
use neptune_wallet::unlocked_utxo::TxInputs;
use num_traits::CheckedAdd;
use num_traits::CheckedSub;
use num_traits::Zero;
use tasm_lib::prelude::Digest;
use tracing::trace;

use super::error;
use crate::api::tx_initiation::builder::input_selector::InputSelectionPolicy;
use crate::api::tx_initiation::builder::input_selector::InputSelector;
use crate::api::tx_initiation::builder::transaction_builder::TransactionBuilder;
use crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
use crate::api::tx_initiation::builder::tx_artifacts_builder::TxCreationArtifactsBuilder;
use crate::api::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::api::tx_initiation::builder::tx_output_list_builder::TxOutputListBuilder;
use crate::api::tx_initiation::error::CreateTxError;
use crate::application::loops::main_loop::proof_upgrader::CastJob;
use crate::application::loops::main_loop::proof_upgrader::ChainJob;
use crate::application::loops::main_loop::proof_upgrader::FixJob;
use crate::application::loops::main_loop::proof_upgrader::ForgeJob;
use crate::application::loops::main_loop::proof_upgrader::UpdateLinkJob;
use crate::application::loops::main_loop::proof_upgrader::SEARCH_DEPTH_FOR_BLOCKS_FOR_MS_UPDATE;
use crate::state::transaction::chained_tx_artifacts::ChainedTxArtifacts;
use crate::state::transaction::link_tx_artifacts::LinkTxArtifacts;
use crate::state::transaction::tx_creation_artifacts::TxCreationArtifacts;
use crate::state::wallet::input_candidate::InputCandidate;
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

/// A mempool transaction a chained transaction spends an unconfirmed output of.
///
/// A standard predecessor must be cast into the chain pipeline before it can
/// be chained onto; a link predecessor is chained onto directly.
enum ChainPredecessor {
    Standard(Box<Transaction>),
    Link(Box<LinkTx>),
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
        timestamp: Timestamp,
    ) -> Result<TransactionDetails, error::CreateTxError> {
        TransactionDetailsBuilder::new()
            .timestamp(timestamp)
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
        let primitive_witness = tx_details.primitive_witness();
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
            .mempool()
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

    /// Verify, between the proving steps of a chained send, that proving on
    /// is still worthwhile: every predecessor must still sit in the mempool.
    ///
    /// A vanished predecessor is unrecoverable -- mined away, double-spent,
    /// or replaced, the thruput it resolves can never confirm. A moved tip,
    /// by contrast, is no reason to stop: every kernel in the chain still
    /// agrees on the old mutator set, and the result is one `Update`-class
    /// proof away from the new tip.
    ///
    /// Proof construction can take a long time, so the world may well move
    /// while a step runs; checking costs one read lock.
    async fn chained_send_still_viable(
        &self,
        predecessor_txids: &[TransactionKernelId],
    ) -> Result<(), error::SendError> {
        let state = self.global_state_lock.lock_guard().await;
        if let Some(gone) = predecessor_txids
            .iter()
            .find(|txid| !state.mempool().contains(**txid))
        {
            return Err(error::SendError::Chained(format!(
                "predecessor transaction {gone} left the mempool while proving"
            )));
        }

        Ok(())
    }

    /// Build and broadcast a chained transaction, paying with unconfirmed
    /// funds: UTXOs created by transactions that sit in the mempool but are
    /// not yet confirmed by any block.
    ///
    /// Internally this runs the chain pipeline on this node alone: the
    /// unconfirmed UTXOs become thruputs of a forged link transaction, the
    /// predecessor transactions are cast into the pipeline and chained on --
    /// cut-through cancelling each thruput against the predecessor output it
    /// spends -- and the resolved link is fixed into an ordinary
    /// `SingleProof`-backed transaction. Only that final transaction is
    /// recorded and broadcast; no link transaction leaves the node.
    pub async fn send_chained(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> Result<ChainedTxArtifacts, error::SendError> {
        let (link, details, consensus_rule_set, proof_job_options, predecessor_txids) = self
            .build_chained_link(outputs, change_policy, fee, timestamp)
            .await?;
        let job_queue = vm_job_queue();

        if !link.kernel.thruputs.is_empty() {
            return Err(error::SendError::Chained(
                "chained transaction has unresolved thruputs".into(),
            ));
        }
        self.chained_send_still_viable(&predecessor_txids).await?;
        let transaction = FixJob {
            link_tx: link,
            consensus_rule_set,
        }
        .upgrade(job_queue, proof_job_options)
        .await
        .map_err(|err| error::SendError::Chained(err.to_string()))?;

        self.chained_send_still_viable(&predecessor_txids).await?;
        let tx_artifacts = ChainedTxArtifacts {
            transaction: Arc::new(transaction),
            details: Arc::new(details),
        };
        self.global_state_lock
            .record_own_chained_transaction(&tx_artifacts)
            .await?;
        self.worker()
            .broadcast_transaction(tx_artifacts.transaction.clone())
            .await?;

        Ok(tx_artifacts)
    }

    /// Like [`Self::send_chained`], but the result stays a [`LinkTx`]: the
    /// chain pipeline runs without the final `Fix`, and the chained,
    /// cut-through link transaction is inserted into the mempool and shared
    /// with peers. Whoever finalizes the chain pays for the `Fix`; unresolved
    /// thruputs are not an error here.
    pub async fn send_chained_link(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> Result<LinkTxArtifacts, error::SendError> {
        let (link, details, _consensus_rule_set, _proof_job_options, predecessor_txids) = self
            .build_chained_link(outputs, change_policy, fee, timestamp)
            .await?;

        self.chained_send_still_viable(&predecessor_txids).await?;
        let tx_artifacts = LinkTxArtifacts {
            link_tx: Arc::new(link),
            details: Arc::new(details),
        };
        self.global_state_lock
            .record_own_link_transaction(&tx_artifacts)
            .await?;
        self.worker()
            .broadcast_link_transaction(tx_artifacts.link_tx.clone())
            .await?;

        Ok(tx_artifacts)
    }

    /// The shared front of [`Self::send_chained`] and
    /// [`Self::send_chained_link`]: select unconfirmed inputs, build the link
    /// witness, forge, chain with every predecessor, and -- if blocks arrived
    /// while proving -- re-target the chained link at the current mutator
    /// set.
    async fn build_chained_link(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> Result<
        (
            LinkTx,
            ChainedTransactionDetails,
            ConsensusRuleSet,
            TritonVmProofJobOptions,
            Vec<TransactionKernelId>,
        ),
        error::SendError,
    > {
        self.private().check_proceed_with_send(fee).await?;

        let (
            link_primitive_witness,
            details,
            predecessors,
            consensus_rule_set,
            proof_job_options,
            predecessor_txids,
        ) = {
            let write_lock = self.global_state_lock.lock_guard_mut().await;
            let state_lock = StateLock::WriteGuard(write_lock);

            let tx_outputs = TxOutputListBuilder::new()
                .outputs(outputs)
                .build(&state_lock)
                .await;
            let spend_amount = tx_outputs
                .total_native_coins()
                .checked_add(&fee)
                .ok_or(CreateTxError::TotalSpendTooLarge)?;

            let StateLock::WriteGuard(mut gsm) = state_lock else {
                unreachable!()
            };
            let network = gsm.cli().network;
            let block_height = gsm.chain.tip().header().height;
            let mutator_set_accumulator = gsm.chain.tip_mutator_set_after();
            let tip_mutator_set_hash = mutator_set_accumulator.hash();

            // Select unconfirmed incoming UTXOs whose creating transaction is
            // a tip-synced, proof-backed mempool member -- on either
            // pipeline: single-proof transactions are cast into the chain,
            // link transactions are chained onto directly.
            let mut selected: Vec<(TransactionKernelId, ThruputInput)> = vec![];
            let mut selected_amount = NativeCurrencyAmount::zero();
            for (predecessor_txid, incoming_utxo) in
                gsm.wallet_state.mempool_incoming_utxos_with_txid()
            {
                if selected_amount >= spend_amount {
                    break;
                }
                if incoming_utxo.is_guesser_fee || !incoming_utxo.utxo.can_spend_at(timestamp) {
                    continue;
                }
                let predecessor_is_chainable = match gsm.mempool().get(predecessor_txid) {
                    Some(predecessor) => {
                        matches!(predecessor.proof, TransactionProof::SingleProof(_))
                            && predecessor.kernel.mutator_set_hash == tip_mutator_set_hash
                    }
                    None => gsm
                        .mempool()
                        .get_link(predecessor_txid)
                        .is_some_and(|link| {
                            link.proof.is_proof()
                                && link.kernel.kernel.mutator_set_hash == tip_mutator_set_hash
                        }),
                };
                if !predecessor_is_chainable {
                    continue;
                }
                let Some(spending_key) = gsm
                    .wallet_state
                    .find_spending_key_for_utxo(&incoming_utxo.utxo)
                else {
                    continue;
                };

                selected_amount += incoming_utxo.utxo.get_native_currency_amount();
                selected.push((
                    predecessor_txid,
                    ThruputInput {
                        incoming_utxo: incoming_utxo.clone(),
                        lock_script_and_witness: spending_key.lock_script_and_witness(),
                    },
                ));
            }
            if selected_amount < spend_amount {
                return Err(CreateTxError::InsufficientFunds {
                    requested: spend_amount,
                    available: selected_amount,
                }
                .into());
            }

            let mut tx_outputs = tx_outputs;
            let change_amount = selected_amount
                .checked_sub(&spend_amount)
                .expect("selected amount covers spend amount");
            if change_amount.is_positive() {
                let change_output = match change_policy {
                    ChangePolicy::ExactChange => {
                        return Err(CreateTxError::NotExactChange.into());
                    }
                    ChangePolicy::RecoverToNextUnusedKey { key_type, medium } => {
                        let key = gsm.wallet_state.next_unused_spending_key(key_type).await;
                        TransactionDetailsBuilder::create_change_output(
                            &gsm.wallet_state,
                            block_height,
                            change_amount,
                            key,
                            medium,
                        )
                    }
                    ChangePolicy::RecoverToProvidedKey { key, medium } => {
                        TransactionDetailsBuilder::create_change_output(
                            &gsm.wallet_state,
                            block_height,
                            change_amount,
                            (*key).clone(),
                            medium,
                        )
                    }
                    ChangePolicy::Burn => TxOutput::no_notification_as_change(
                        Utxo::new_native_currency(LockScript::burn().hash(), change_amount),
                        Digest::default(),
                        Digest::default(),
                    ),
                };
                tx_outputs.push(change_output);
            }

            let details = ChainedTransactionDetails {
                thruput_inputs: selected
                    .iter()
                    .map(|(_, thruput)| thruput.clone())
                    .collect(),
                tx_outputs,
                fee,
                timestamp,
                mutator_set_accumulator,
                network,
            };

            // The reference validation is the integrity gate: under mock proofs,
            // nothing else checks the kernel this pipeline produces.
            let link_primitive_witness = details.link_primitive_witness();
            link_primitive_witness
                .validate()
                .await
                .map_err(|err| error::SendError::Chained(err.to_string()))?;

            let predecessors: Vec<ChainPredecessor> = selected
                .iter()
                .map(|(txid, _)| *txid)
                .unique()
                .map(|txid| {
                    if let Some(transaction) = gsm.mempool().get(txid) {
                        ChainPredecessor::Standard(Box::new(transaction.clone()))
                    } else {
                        ChainPredecessor::Link(Box::new(
                            gsm.mempool()
                                .get_link(txid)
                                .expect("selected predecessor must be in mempool")
                                .clone(),
                        ))
                    }
                })
                .collect();

            let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
            let proof_job_options = gsm.cli().as_proof_job_options();

            let predecessor_txids: Vec<TransactionKernelId> =
                selected.iter().map(|(txid, _)| *txid).unique().collect();

            (
                link_primitive_witness,
                details,
                predecessors,
                consensus_rule_set,
                proof_job_options,
                predecessor_txids,
            )
        };

        // Run the chain pipeline, one upgrade job at a time, checking between
        // the (potentially long-running) steps that the chain is still worth
        // proving.
        let job_queue = vm_job_queue();
        self.chained_send_still_viable(&predecessor_txids).await?;
        let mut link = ForgeJob {
            link_primitive_witness,
            consensus_rule_set,
        }
        .upgrade(job_queue.clone(), proof_job_options.clone())
        .await
        .map_err(|err| error::SendError::Chained(err.to_string()))?;
        for predecessor in predecessors {
            self.chained_send_still_viable(&predecessor_txids).await?;
            let predecessor_link = match predecessor {
                ChainPredecessor::Link(link_tx) => *link_tx,
                ChainPredecessor::Standard(transaction) => CastJob {
                    transaction: *transaction,
                    consensus_rule_set,
                }
                .upgrade(job_queue.clone(), proof_job_options.clone())
                .await
                .map_err(|err| error::SendError::Chained(err.to_string()))?,
            };
            link = ChainJob {
                left: link,
                right: predecessor_link,
                shuffle_seed: rand::random(),
                consensus_rule_set,
            }
            .upgrade(job_queue.clone(), proof_job_options.clone())
            .await
            .map_err(|err| error::SendError::Chained(err.to_string()))?;
        }
        // If blocks arrived while proving, re-target the chain at the current
        // mutator set -- repeatedly, since blocks may keep arriving while the
        // update itself proves. The predecessors still being in the mempool
        // means the chain's inputs are still unspent, so the update must
        // succeed. Peers only accept tip-synced link transactions, so a
        // shared link must leave this loop synced.
        loop {
            let lookup = {
                let state = self.global_state_lock.lock_guard().await;
                if state.chain.tip_mutator_set_after().hash() == link.kernel.kernel.mutator_set_hash
                {
                    break;
                }
                state
                    .chain
                    .archival_state()
                    .old_mutator_set_and_mutator_set_update_to_tip(
                        link.kernel.kernel.mutator_set_hash,
                        SEARCH_DEPTH_FOR_BLOCKS_FOR_MS_UPDATE,
                    )
                    .await
            };
            let Some((old_mutator_set_accumulator, mutator_set_update)) = lookup else {
                return Err(error::SendError::Chained(
                    "could not find mutator-set path from chained link to tip".into(),
                ));
            };

            self.chained_send_still_viable(&predecessor_txids).await?;
            link = UpdateLinkJob {
                link_tx: link,
                old_mutator_set_accumulator,
                mutator_set_update,
                consensus_rule_set,
            }
            .upgrade(job_queue.clone(), proof_job_options.clone())
            .await
            .map_err(|err| error::SendError::Chained(err.to_string()))?;
        }

        Ok((
            link,
            details,
            consensus_rule_set,
            proof_job_options,
            predecessor_txids,
        ))
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
