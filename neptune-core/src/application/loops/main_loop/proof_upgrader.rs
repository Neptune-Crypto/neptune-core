use std::sync::Arc;

use itertools::Itertools;
use num_traits::Zero;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use tasm_lib::prelude::Digest;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
use crate::application::config::fee_notification_policy::FeeNotificationPolicy;
use crate::application::config::network::Network;
use crate::application::loops::main_loop::upgrade_incentive::UpgradeIncentive;
use crate::application::triton_vm_job_queue::TritonVmJobPriority;
use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::mutator_set_update::MutatorSetUpdate;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transaction_proof::TransactionProofType;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::state::transaction::transaction_details::TransactionDetails;
use crate::state::transaction::transaction_kernel_id::TransactionKernelId;
use crate::state::transaction::tx_proving_capability::TxProvingCapability;
use crate::state::wallet::address::SpendingKey;
use crate::state::wallet::expected_utxo::ExpectedUtxo;
use crate::state::wallet::expected_utxo::UtxoNotifier;
use crate::state::wallet::utxo_notification::UtxoNotificationMethod;
use crate::state::wallet::wallet_entropy::WalletEntropy;
use crate::state::GlobalState;
use crate::state::GlobalStateLock;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::MainToPeerTask;

pub(crate) const SEARCH_DEPTH_FOR_BLOCKS_FOR_MS_UPDATE: usize = 100;

/// Enumerates the types of 'proof upgrades' that can be done.
///
/// A transaction proof can be in need of upgrading, either because it cannot
/// be shared in its current state without leaking secret keys, or to make it
/// more likely that a miner picks up this transaction.
#[derive(Clone, Debug)]
pub enum UpgradeJob {
    PrimitiveWitnessToProofCollection(PrimitiveWitnessToProofCollection),
    PrimitiveWitnessToSingleProof(PrimitiveWitnessToSingleProof),
    ProofCollectionToSingleProof(ProofCollectionToSingleProof),
    Merge {
        left_kernel: TransactionKernel,
        single_proof_left: Proof,
        right_kernel: TransactionKernel,
        single_proof_right: Proof,
        shuffle_seed: [u8; 32],
        mutator_set: MutatorSetAccumulator,
        upgrade_incentive: UpgradeIncentive,
    },
    UpdateMutatorSetData(UpdateMutatorSetDataJob),
}

#[derive(Clone, Debug)]
pub struct ProofCollectionToSingleProof {
    kernel: TransactionKernel,
    proof: ProofCollection,
    mutator_set: MutatorSetAccumulator,
    upgrade_incentive: UpgradeIncentive,
}

impl ProofCollectionToSingleProof {
    pub(crate) fn new(
        kernel: TransactionKernel,
        proof: ProofCollection,
        mutator_set: MutatorSetAccumulator,
        upgrade_incentive: UpgradeIncentive,
    ) -> Self {
        Self {
            kernel,
            proof,
            mutator_set,
            upgrade_incentive,
        }
    }
}

/// Task
#[derive(Clone, Debug)]
pub struct PrimitiveWitnessToSingleProof {
    pub primitive_witness: PrimitiveWitness,
}

impl PrimitiveWitnessToSingleProof {
    /// Execute the upgrade from a primitive witness to a single proof.
    ///
    /// Takes a very long time to execute, so no locks maybe be held when this
    /// is invoked.
    pub(crate) async fn upgrade(
        self,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: &TritonVmProofJobOptions,
        consensus_rule_set: ConsensusRuleSet,
    ) -> anyhow::Result<Transaction> {
        let options = TritonVmProofJobOptionsBuilder::new()
            .template(proof_job_options)
            .proof_type(TransactionProofType::SingleProof)
            .build();

        info!("Proof-upgrader: Start producing single proof");
        let single_proof = TransactionProofBuilder::new()
            .consensus_rule_set(consensus_rule_set)
            .primitive_witness_ref(&self.primitive_witness)
            .job_queue(triton_vm_job_queue.clone())
            .proof_job_options(options)
            .build()
            .await?;
        info!("Proof-upgrader, single proof: Done");

        Ok(Transaction {
            kernel: self.primitive_witness.kernel,
            proof: single_proof,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PrimitiveWitnessToProofCollection {
    pub primitive_witness: PrimitiveWitness,
}

impl PrimitiveWitnessToProofCollection {
    pub(crate) async fn upgrade(
        self,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: &TritonVmProofJobOptions,
    ) -> anyhow::Result<Transaction> {
        let options = TritonVmProofJobOptionsBuilder::new()
            .template(proof_job_options)
            .proof_type(TransactionProofType::ProofCollection)
            .build();

        info!("Proof-upgrader: Start producing proof collection");
        let proof_collection = TransactionProofBuilder::new()
            .primitive_witness_ref(&self.primitive_witness)
            .job_queue(triton_vm_job_queue.clone())
            .proof_job_options(options)
            .build()
            .await?;
        info!("Proof-upgrader, proof collection: Done");

        Ok(Transaction {
            kernel: self.primitive_witness.kernel,
            proof: proof_collection,
        })
    }
}

/// A job to update an unsynced single-proof backed transaction to a synced one.
#[derive(Clone, Debug)]
pub struct UpdateMutatorSetDataJob {
    old_kernel: TransactionKernel,
    old_single_proof: Proof,
    old_mutator_set: MutatorSetAccumulator,
    mutator_set_update: MutatorSetUpdate,
    upgrade_incentive: UpgradeIncentive,

    /// Consensus rules that apply *after* the transaction has been updated.
    consensus_rule_set: ConsensusRuleSet,
}

impl UpdateMutatorSetDataJob {
    pub(crate) fn new(
        old_kernel: TransactionKernel,
        old_single_proof: Proof,
        old_mutator_set: MutatorSetAccumulator,
        mutator_set_update: MutatorSetUpdate,
        upgrade_incentive: UpgradeIncentive,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Self {
        Self {
            old_kernel,
            old_single_proof,
            old_mutator_set,
            mutator_set_update,
            upgrade_incentive,
            consensus_rule_set,
        }
    }

    pub(crate) async fn upgrade(
        self,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
    ) -> anyhow::Result<Transaction> {
        let UpdateMutatorSetDataJob {
            old_kernel,
            old_single_proof,
            old_mutator_set,
            mutator_set_update,
            consensus_rule_set,
            ..
        } = self;
        info!("Proof-upgrader: Start update proof");
        let ret = Transaction::new_with_updated_mutator_set_records_given_proof(
            old_kernel,
            &old_mutator_set,
            &mutator_set_update,
            old_single_proof,
            triton_vm_job_queue,
            proof_job_options,
            None,
            consensus_rule_set,
        )
        .await?;
        info!("Proof-upgrader, update: Done");

        Ok(ret)
    }
}

impl UpgradeJob {
    /// Create an upgrade job from a primitive witness, for upgrading proof-
    /// support for a transaction that this client has initiated.
    ///
    /// Since [PrimitiveWitness] contains secret data, this upgrade job can only
    /// be used for transactions that originate locally.
    pub(super) fn from_primitive_witness(
        network: Network,
        tx_proving_capability: TxProvingCapability,
        primitive_witness: PrimitiveWitness,
    ) -> UpgradeJob {
        match tx_proving_capability {
            TxProvingCapability::ProofCollection => {
                UpgradeJob::PrimitiveWitnessToProofCollection(PrimitiveWitnessToProofCollection {
                    primitive_witness,
                })
            }
            TxProvingCapability::SingleProof => {
                UpgradeJob::PrimitiveWitnessToSingleProof(PrimitiveWitnessToSingleProof {
                    primitive_witness,
                })
            }
            TxProvingCapability::PrimitiveWitness if network.use_mock_proof() => {
                UpgradeJob::PrimitiveWitnessToSingleProof(PrimitiveWitnessToSingleProof {
                    primitive_witness,
                })
            }
            TxProvingCapability::PrimitiveWitness => {
                panic!("Client cannot have primitive witness capability only")
            }
            TxProvingCapability::LockScript => todo!("TODO: Add support for this"),
        }
    }

    /// The gobbling fee charged for an upgrade job
    ///
    /// Gobbling fees are charged when a transaction is upgraded from
    /// proof-collection to single-proof, or when two single proofs are merged.
    /// The other cases are either not worth it, as you need to create a single-
    /// proof to gobble, or the proof upgrade relates to a transaction that we
    /// already have a financial interest in, so we don't charge a fee.
    ///
    /// In particular, no fees are charged for updating a transaction's mutator
    /// set data because doing so would require a single proof and a merge step,
    /// which would delay that transaction's propagation and confirmation by the
    /// network. This policy could be revised when proving gets faster.
    fn gobbling_fee(&self) -> NativeCurrencyAmount {
        match self {
            UpgradeJob::ProofCollectionToSingleProof(ProofCollectionToSingleProof {
                upgrade_incentive: UpgradeIncentive::Gobble(amount),
                ..
            }) => *amount,
            UpgradeJob::Merge {
                upgrade_incentive: UpgradeIncentive::Gobble(amount),
                ..
            } => *amount,
            _ => NativeCurrencyAmount::zero(),
        }
    }

    fn old_tx_timestamp(&self) -> Timestamp {
        match self {
            UpgradeJob::PrimitiveWitnessToProofCollection(pw_to_pc) => {
                pw_to_pc.primitive_witness.kernel.timestamp
            }
            UpgradeJob::PrimitiveWitnessToSingleProof(pw_to_sp) => {
                pw_to_sp.primitive_witness.kernel.timestamp
            }
            UpgradeJob::ProofCollectionToSingleProof(ProofCollectionToSingleProof {
                kernel,
                ..
            }) => kernel.timestamp,
            UpgradeJob::Merge {
                left_kernel,
                right_kernel,
                ..
            } => Timestamp::max(left_kernel.timestamp, right_kernel.timestamp),
            UpgradeJob::UpdateMutatorSetData(update_mutator_set_data_job) => {
                update_mutator_set_data_job.old_kernel.timestamp
            }
        }
    }

    fn upgrade_incentive(&self) -> UpgradeIncentive {
        match self {
            UpgradeJob::PrimitiveWitnessToProofCollection(_) => {
                // If primitive witness is known, transaction must originate
                // from this node.
                UpgradeIncentive::Critical
            }
            UpgradeJob::PrimitiveWitnessToSingleProof { .. } => {
                // If primitive witness is known, transaction must originate
                // from this node.
                UpgradeIncentive::Critical
            }
            UpgradeJob::ProofCollectionToSingleProof(ProofCollectionToSingleProof {
                upgrade_incentive,
                ..
            }) => *upgrade_incentive,
            UpgradeJob::Merge {
                upgrade_incentive, ..
            } => *upgrade_incentive,
            UpgradeJob::UpdateMutatorSetData(UpdateMutatorSetDataJob {
                upgrade_incentive, ..
            }) => *upgrade_incentive,
        }
    }

    /// Return a list of the transaction IDs that will have their proofs
    /// upgraded with this decision.
    ///
    /// Will return a list of length two in the case of merge, otherwise a list
    /// of length one.
    pub(super) fn affected_txids(&self) -> Vec<TransactionKernelId> {
        match self {
            UpgradeJob::ProofCollectionToSingleProof(ProofCollectionToSingleProof {
                kernel,
                ..
            }) => vec![kernel.txid()],
            UpgradeJob::Merge {
                left_kernel,
                right_kernel,
                ..
            } => vec![left_kernel.txid(), right_kernel.txid()],
            UpgradeJob::PrimitiveWitnessToProofCollection(pw_to_pc) => {
                vec![pw_to_pc.primitive_witness.kernel.txid()]
            }
            UpgradeJob::PrimitiveWitnessToSingleProof(pw_to_sp) => {
                vec![pw_to_sp.primitive_witness.kernel.txid()]
            }
            UpgradeJob::UpdateMutatorSetData(update_job) => vec![update_job.old_kernel.txid()],
        }
    }

    /// Return the mutator set that this transaction is assumed to be valid
    /// under, after the upgrade.
    fn mutator_set(&self) -> MutatorSetAccumulator {
        match self {
            UpgradeJob::PrimitiveWitnessToProofCollection(pw_to_pc) => {
                pw_to_pc.primitive_witness.mutator_set_accumulator.clone()
            }
            UpgradeJob::PrimitiveWitnessToSingleProof(pw_to_sp) => {
                pw_to_sp.primitive_witness.mutator_set_accumulator.clone()
            }
            UpgradeJob::ProofCollectionToSingleProof(ProofCollectionToSingleProof {
                mutator_set,
                ..
            }) => mutator_set.clone(),
            UpgradeJob::Merge { mutator_set, .. } => mutator_set.clone(),
            UpgradeJob::UpdateMutatorSetData(update_mutator_set_data_job) => {
                let mut new_msa = update_mutator_set_data_job.old_mutator_set.clone();
                update_mutator_set_data_job
                    .mutator_set_update
                    .apply_to_accumulator(&mut new_msa)
                    .unwrap();
                new_msa
            }
        }
    }

    /// Produce an appropriate log message for the case where the transaction is
    /// no longer confirmable after a successful proof-upgrade. This could be
    /// because a faster proof-upgrader upgraded the transaction and it got
    /// mined in the meantime, or in the case of a merge, one of the inputs to
    /// the merge upgrade got mined.
    fn double_spend_warn_msg(&self) -> &str {
        match self {
            UpgradeJob::Merge { .. } => "Maybe an input to the merge got mined already?",
            UpgradeJob::PrimitiveWitnessToProofCollection { .. } => {
                "Your own transaction already got mined?"
            }
            UpgradeJob::PrimitiveWitnessToSingleProof { .. } => {
                "Your own transaction already got mined?"
            }
            UpgradeJob::ProofCollectionToSingleProof { .. } => {
                "Someone else upgraded the proof-collection and mined it?"
            }
            UpgradeJob::UpdateMutatorSetData(_) => {
                "Transaction got mined while this update job was running?"
            }
        }
    }

    /// Upgrade transaction proofs, inserts upgraded tx into the mempool and
    /// informs peers of this new transaction.
    pub(crate) async fn handle_upgrade(
        self,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        mut global_state_lock: GlobalStateLock,
        main_to_peer_channel: tokio::sync::broadcast::Sender<MainToPeerTask>,
    ) {
        let mut upgrade_job = self;

        let upgrade_incentive = upgrade_job.upgrade_incentive();
        let priority = match upgrade_incentive {
            UpgradeIncentive::Critical => TritonVmJobPriority::High,
            _ => TritonVmJobPriority::Low,
        };

        // process in a loop.  in case a new block comes in while processing
        // the current tx, then we can move on to the next, and so on.
        loop {
            /* Prepare upgrade */
            let affected_txids = upgrade_job.affected_txids();
            let mutator_set_for_tx = upgrade_job.mutator_set();

            // note: if this task is cancelled, the job will continue
            // because TritonVmJobOptions::cancel_job_rx is None.
            // see how compose_task handles cancellation in mine_loop.
            let job_options = global_state_lock.cli().proof_job_options(priority);

            // It's a important to *not* hold any locks when proving happens.
            // Otherwise, entire application freezes!!
            let (wallet_entropy, block_height) = {
                let state = global_state_lock.lock_guard().await;
                (
                    state.wallet_state.wallet_entropy.clone(),
                    state.chain.light_state().header().height,
                )
            };

            /* Perform upgrade */
            // No locks may be held here!
            let offchain_notifications = global_state_lock.cli().fee_notification;
            let (upgraded, expected_utxos) = match upgrade_job
                .clone()
                .upgrade(
                    triton_vm_job_queue.clone(),
                    job_options,
                    &wallet_entropy,
                    block_height,
                    offchain_notifications,
                )
                .await
            {
                Ok((upgraded_tx, expected_utxos)) => {
                    info!(
                        "Successfully upgraded transaction {}",
                        upgraded_tx.kernel.txid()
                    );
                    (upgraded_tx, expected_utxos)
                }
                Err(e) => {
                    error!("UpgradeProof job failed. error: {e}");
                    error!(
                        "Consider lowering your proving capability to {}, in case it is set higher.\nCurrent proving \
                        capability is set to: {}.",
                        TxProvingCapability::ProofCollection,
                        global_state_lock.cli().proving_capability()
                    );
                    return;
                }
            };

            /* Check if upgrade resulted in valid transaction */
            upgrade_job = {
                let mut global_state = global_state_lock.lock_guard_mut().await;
                let tip_mutator_set = global_state
                    .chain
                    .light_state()
                    .mutator_set_accumulator_after()
                    .expect("Block from state must have mutator set after");

                let transaction_is_up_to_date =
                    upgraded.kernel.mutator_set_hash == tip_mutator_set.hash();

                let network = global_state.cli().network;
                let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
                if transaction_is_up_to_date {
                    // Did the transaction get mined while the proof upgrade
                    // job was running? If so, don't share it or insert it into
                    // the mempool. Notice that this double-spend check can
                    // only be made if the mutator set is up to date.

                    if !upgraded.is_confirmable_relative_to(&tip_mutator_set) {
                        let verbose_log_msg = upgrade_job.double_spend_warn_msg();
                        warn!("Upgraded transaction is no longer confirmable. {verbose_log_msg}");
                        global_state.mempool_remove(upgraded.kernel.txid()).await;
                        return;
                    }

                    /* Handle successful upgrade */
                    // Insert tx into mempool before notifying peers, so we're
                    // sure to have it when they ask.
                    global_state
                        .mempool_insert(upgraded.clone(), upgrade_incentive.into())
                        .await;

                    global_state
                        .wallet_state
                        .add_expected_utxos(expected_utxos)
                        .await;
                    drop(global_state); // sooner is better.

                    // Inform all peers about our hard work
                    let peer_msg =
                        MainToPeerTask::TransactionNotification((&upgraded).try_into().unwrap());

                    if let Err(e) = main_to_peer_channel.send(peer_msg) {
                        // panic only if receiver_count is non-zero.
                        let receiver_count = main_to_peer_channel.receiver_count();
                        assert_eq!(
                            receiver_count, 0,
                            "failed to broadcast message from main to {} peers: {:?}",
                            receiver_count, e
                        );
                    }

                    info!("Successfully handled proof upgrade.");
                    return;
                }

                info!(
                    "Transaction is deprecated after upgrade because of new block(s). Affected txs: [{}]",
                    affected_txids.iter().join("\n"));

                let Some(ms_update) = global_state
                    .chain
                    .archival_state_mut()
                    .get_mutator_set_update_to_tip(
                        &mutator_set_for_tx,
                        SEARCH_DEPTH_FOR_BLOCKS_FOR_MS_UPDATE,
                    )
                    .await
                else {
                    info!("Couldn't find path from old mutator set to current tip. Did a reorganization happen?");
                    return;
                };

                if let TransactionProof::SingleProof(single_proof) = upgraded.proof {
                    // Transaction is single-proof supported but MS data is deprecated. Create new
                    // upgrade job to fix that.
                    let upgrade_incentive = upgrade_incentive.after_upgrade();
                    let ms_update_job = UpdateMutatorSetDataJob {
                        old_kernel: upgraded.kernel,
                        old_single_proof: single_proof,
                        old_mutator_set: mutator_set_for_tx,
                        mutator_set_update: ms_update,
                        upgrade_incentive,
                        consensus_rule_set,
                    };
                    UpgradeJob::UpdateMutatorSetData(ms_update_job)
                } else {
                    match upgrade_job {
                        UpgradeJob::PrimitiveWitnessToProofCollection(pw_to_pc) => {
                            // Transaction is proof collection supported but MS data is deprecated.
                            // Since proof collections cannot be updated, we instead update the
                            // primitive witness and create a new job to upgrade the updated
                            // primitive witness to a proof collection.
                            let new_pw = PrimitiveWitness::update_with_new_ms_data(
                                pw_to_pc.primitive_witness,
                                ms_update,
                            );
                            UpgradeJob::PrimitiveWitnessToProofCollection(
                                PrimitiveWitnessToProofCollection {
                                    primitive_witness: new_pw,
                                },
                            )
                        }
                        UpgradeJob::PrimitiveWitnessToSingleProof { .. } => unreachable!(),
                        UpgradeJob::ProofCollectionToSingleProof { .. } => unreachable!(),
                        UpgradeJob::Merge { .. } => unreachable!(),
                        UpgradeJob::UpdateMutatorSetData(_) => unreachable!(),
                    }
                }
            };
        }
    }

    fn gobbler_notification_method_with_receiver_preimage(
        own_wallet_entropy: &WalletEntropy,
        notification_policy: FeeNotificationPolicy,
    ) -> (UtxoNotificationMethod, Digest) {
        let gobble_beneficiary_key = match notification_policy {
            FeeNotificationPolicy::OffChain => {
                SpendingKey::from(own_wallet_entropy.nth_symmetric_key(0))
            }
            FeeNotificationPolicy::OnChainSymmetric => {
                SpendingKey::from(own_wallet_entropy.nth_symmetric_key(0))
            }
            FeeNotificationPolicy::OnChainGeneration => {
                SpendingKey::from(own_wallet_entropy.nth_generation_spending_key(0))
            }
        };
        let receiver_preimage = gobble_beneficiary_key.privacy_preimage();
        let gobble_beneficiary_address = gobble_beneficiary_key.to_address();

        let fee_notification_method = match notification_policy {
            FeeNotificationPolicy::OffChain => {
                UtxoNotificationMethod::OffChain(gobble_beneficiary_address)
            }
            FeeNotificationPolicy::OnChainSymmetric => {
                UtxoNotificationMethod::OnChain(gobble_beneficiary_address)
            }
            FeeNotificationPolicy::OnChainGeneration => {
                UtxoNotificationMethod::OnChain(gobble_beneficiary_address)
            }
        };

        (fee_notification_method, receiver_preimage)
    }

    /// Build a single-proof backed gobbler transaction that can be used to
    /// charge another transaction for upgrading a proof.
    #[expect(clippy::too_many_arguments)]
    async fn build_gobbler(
        gobbling_fee: NativeCurrencyAmount,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
        own_wallet_entropy: &WalletEntropy,
        current_block_height: BlockHeight,
        fee_notification_policy: FeeNotificationPolicy,
        mutator_set: MutatorSetAccumulator,
        old_tx_timestamp: Timestamp,
    ) -> anyhow::Result<(Transaction, Vec<ExpectedUtxo>)> {
        info!("Producing gobbler-transaction for a value of {gobbling_fee}");
        let (utxo_notification_method, receiver_preimage) =
            Self::gobbler_notification_method_with_receiver_preimage(
                own_wallet_entropy,
                fee_notification_policy,
            );
        let receiver_digest = receiver_preimage.hash();
        let gobbler = TransactionDetails::fee_gobbler(
            gobbling_fee,
            own_wallet_entropy.generate_sender_randomness(current_block_height, receiver_digest),
            mutator_set,
            old_tx_timestamp,
            utxo_notification_method,
            proof_job_options.job_settings.network,
        );

        let gobbler_witness = gobbler.primitive_witness();

        let expected_utxos = if fee_notification_policy == FeeNotificationPolicy::OffChain {
            gobbler
                .tx_outputs
                .expected_utxos(UtxoNotifier::FeeGobbler, receiver_preimage)
        } else {
            vec![]
        };

        // ensure that proof-type is SingleProof
        let options = TritonVmProofJobOptionsBuilder::new()
            .template(&proof_job_options)
            .proof_type(TransactionProofType::SingleProof)
            .build();

        let consensus_rule_set = ConsensusRuleSet::infer_from(
            proof_job_options.job_settings.network,
            current_block_height,
        );
        let proof = TransactionProofBuilder::new()
            .consensus_rule_set(consensus_rule_set)
            .primitive_witness_ref(&gobbler_witness)
            .job_queue(triton_vm_job_queue.clone())
            .proof_job_options(options)
            .build()
            .await?;

        info!("Done producing gobbler-transaction for a value of {gobbling_fee}");
        let gobbler_tx = Transaction {
            kernel: gobbler_witness.kernel,
            proof,
        };

        Ok((gobbler_tx, expected_utxos))
    }

    /// Execute the proof upgrade.
    ///
    /// Upgrades transactions to a proof of higher quality that is more likely
    /// to be picked up by a miner. Returns the upgraded proof, or an error if
    /// the prover is already in use and the proof_job_options is set to not wait if
    /// prover is busy.
    ///
    /// Charges a fee for the upgrade task if this is desirable.
    pub(crate) async fn upgrade(
        self,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
        own_wallet_entropy: &WalletEntropy,
        current_block_height: BlockHeight,
        fee_notification_policy: FeeNotificationPolicy,
    ) -> anyhow::Result<(Transaction, Vec<ExpectedUtxo>)> {
        let gobbling_fee = self.gobbling_fee();
        let mutator_set = self.mutator_set();
        let old_tx_timestamp = self.old_tx_timestamp();
        let network = proof_job_options.job_settings.network;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, current_block_height);

        let (maybe_gobbler, expected_utxos) = if gobbling_fee.is_positive() {
            let (gobbler, eutxos) = Self::build_gobbler(
                gobbling_fee,
                triton_vm_job_queue.clone(),
                proof_job_options.clone(),
                own_wallet_entropy,
                current_block_height,
                fee_notification_policy,
                mutator_set,
                old_tx_timestamp,
            )
            .await?;

            (Some(gobbler), eutxos)
        } else {
            (None, vec![])
        };

        let mut rng: StdRng =
            SeedableRng::from_seed(own_wallet_entropy.shuffle_seed(current_block_height.next()));
        let gobble_shuffle_seed: [u8; 32] = rng.random();

        match self {
            UpgradeJob::ProofCollectionToSingleProof(ProofCollectionToSingleProof {
                kernel,
                proof,
                ..
            }) => {
                let single_proof = TransactionProofBuilder::new()
                    .consensus_rule_set(consensus_rule_set)
                    .proof_collection(proof)
                    .job_queue(triton_vm_job_queue.clone())
                    .proof_job_options(proof_job_options.clone())
                    .build()
                    .await?;
                info!("Proof-upgrader, to single proof: Done");

                let upgraded_tx = Transaction {
                    kernel,
                    proof: single_proof,
                };

                let tx = if let Some(gobbler) = maybe_gobbler {
                    let lhs = gobbler;
                    let rhs = upgraded_tx;

                    info!("Proof-upgrader: Start merging with gobbler");
                    let ret = lhs
                        .merge_with(
                            rhs,
                            gobble_shuffle_seed,
                            triton_vm_job_queue.clone(),
                            proof_job_options,
                            consensus_rule_set,
                        )
                        .await?;
                    info!("Proof-upgrader merging with gobbler: Done");
                    ret
                } else {
                    upgraded_tx
                };

                Ok((tx, expected_utxos))
            }
            UpgradeJob::Merge {
                left_kernel,
                single_proof_left,
                right_kernel,
                single_proof_right,
                shuffle_seed,
                ..
            } => {
                let left = Transaction {
                    kernel: left_kernel.to_owned(),
                    proof: TransactionProof::SingleProof(single_proof_left.to_owned()),
                };
                let right = Transaction {
                    kernel: right_kernel.to_owned(),
                    proof: TransactionProof::SingleProof(single_proof_right.to_owned()),
                };
                info!("Proof-upgrader: Start merging");
                let mut ret = Transaction::merge_with(
                    left,
                    right,
                    shuffle_seed.to_owned(),
                    triton_vm_job_queue.clone(),
                    proof_job_options.clone(),
                    consensus_rule_set,
                )
                .await?;
                info!("Proof-upgrader, merge: Done");

                if let Some(gobbler) = maybe_gobbler {
                    info!("Proof-upgrader: Start merging with gobbler");
                    ret = gobbler
                        .merge_with(
                            ret,
                            gobble_shuffle_seed,
                            triton_vm_job_queue,
                            proof_job_options,
                            consensus_rule_set,
                        )
                        .await?;
                    info!("Proof-upgrader merging with gobbler: Done");
                };

                Ok((ret, expected_utxos))
            }
            UpgradeJob::PrimitiveWitnessToProofCollection(pw_to_pc) => Ok((
                pw_to_pc
                    .upgrade(triton_vm_job_queue.clone(), &proof_job_options)
                    .await?,
                expected_utxos,
            )),
            UpgradeJob::PrimitiveWitnessToSingleProof(pw_to_sp) => Ok((
                pw_to_sp
                    .upgrade(
                        triton_vm_job_queue.clone(),
                        &proof_job_options,
                        consensus_rule_set,
                    )
                    .await?,
                expected_utxos,
            )),
            UpgradeJob::UpdateMutatorSetData(update_job) => {
                let ret = update_job
                    .upgrade(triton_vm_job_queue, proof_job_options)
                    .await?;
                Ok((ret, expected_utxos))
            }
        }
    }
}

/// Return an [UpgradeJob] that describes work that can be done to upgrade the
/// proof-quality of a transaction found in mempool. Also reports the value
/// of this job to the wallet of this node. The value reported will be zero for
/// all 3rd party transactions.
pub(super) async fn get_upgrade_task_from_mempool(
    global_state: &mut GlobalState,
) -> Option<UpgradeJob> {
    let tip_mutator_set = global_state
        .chain
        .light_state()
        .mutator_set_accumulator_after()
        .expect("Block from state must have mutator set after");
    let gobbling_fraction = global_state.gobbling_fraction();
    let min_gobbling_fee = global_state.min_gobbling_fee();
    let num_proofs_threshold = global_state.max_num_proofs();

    let upgrade_filter = global_state.cli().tx_upgrade_filter;

    // Do we have any `ProofCollection`s?
    let proof_collection_job = if let Some((kernel, proof, upgrade_priority)) = global_state
        .mempool
        .preferred_proof_collection(num_proofs_threshold, upgrade_filter)
    {
        if kernel.mutator_set_hash != tip_mutator_set.hash() {
            error!("Deprecated transaction found in mempool. Has ProofCollection in need of updating. Consider clearing mempool.");
            return None;
        }

        let gobbling_potential = kernel.fee.lossy_f64_fraction_mul(gobbling_fraction);
        let upgrade_incentive =
            upgrade_priority.incentive_given_gobble_potential(gobbling_potential);
        if upgrade_incentive.upgrade_is_worth_it(min_gobbling_fee) {
            let upgrade_job =
                UpgradeJob::ProofCollectionToSingleProof(ProofCollectionToSingleProof {
                    kernel: kernel.to_owned(),
                    proof: proof.to_owned(),
                    mutator_set: tip_mutator_set.clone(),
                    upgrade_incentive,
                });
            Some(upgrade_job)
        } else {
            None
        }
    } else {
        None
    };

    if let Some(upgrade_job) = &proof_collection_job {
        if let UpgradeIncentive::Critical = upgrade_job.upgrade_incentive() {
            return proof_collection_job;
        }
    }

    // Do we have any unsynced single proofs, worthy of an update?
    let update_job = global_state
        .preferred_update_job_from_mempool(min_gobbling_fee, upgrade_filter)
        .await;
    let update_job = update_job.map(UpgradeJob::UpdateMutatorSetData);

    // Can we merge two single proofs?
    let merge_job = if let Some((
        [(left_kernel, left_single_proof), (right_kernel, right_single_proof)],
        upgrade_priority,
    )) = global_state
        .mempool
        .preferred_single_proof_pair(upgrade_filter)
    {
        // Sanity check
        assert_eq!(
            left_kernel.mutator_set_hash, right_kernel.mutator_set_hash,
            "Mempool must return transactions with matching mutator set hashes."
        );
        if left_kernel.mutator_set_hash != tip_mutator_set.hash() {
            error!(
                "Deprecated transactions returned by mempool for merging. This shouldn't happen."
            );
            return None;
        }

        let gobbling_potential =
            (left_kernel.fee + right_kernel.fee).lossy_f64_fraction_mul(gobbling_fraction);
        let upgrade_incentive =
            upgrade_priority.incentive_given_gobble_potential(gobbling_potential);
        if upgrade_incentive.upgrade_is_worth_it(min_gobbling_fee) {
            let mut rng: StdRng = SeedableRng::from_seed(global_state.shuffle_seed());
            let upgrade_decision = UpgradeJob::Merge {
                left_kernel: left_kernel.to_owned(),
                single_proof_left: left_single_proof.to_owned(),
                right_kernel: right_kernel.to_owned(),
                single_proof_right: right_single_proof.to_owned(),
                shuffle_seed: rng.random(),
                mutator_set: tip_mutator_set,
                upgrade_incentive,
            };
            Some(upgrade_decision)
        } else {
            None
        }
    } else {
        None
    };

    // pick the most profitable option
    let mut jobs = [proof_collection_job, merge_job, update_job]
        .into_iter()
        .flatten()
        .collect_vec();
    jobs.sort_by_key(|job| job.upgrade_incentive());

    jobs.first().cloned()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashSet;

    use macro_rules_attr::apply;
    use tokio::sync::broadcast;
    use tokio::sync::broadcast::error::TryRecvError;
    use tracing_test::traced_test;

    use super::*;
    use crate::application::config::cli_args;
    use crate::application::config::network::Network;
    use crate::protocol::consensus::block::Block;
    use crate::state::mempool::upgrade_priority::UpgradePriority;
    use crate::state::transaction::tx_creation_config::TxCreationConfig;
    use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::state::wallet::transaction_output::TxOutput;
    use crate::tests::shared::blocks::fake_block_successor_with_merged_tx;
    use crate::tests::shared::blocks::invalid_empty_block_with_timestamp;
    use crate::tests::shared::globalstate::get_test_genesis_setup;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared::globalstate::state_with_premine_and_self_mined_blocks;
    use crate::tests::shared_tokio_runtime;
    use crate::PEER_CHANNEL_CAPACITY;

    /// Returns a transaction initiated by the global state provided as
    /// argument. Assumes balance is sufficient to make this transaction.
    async fn transaction_from_state(
        mut state: GlobalStateLock,
        seed: u64,
        proof_quality: TxProvingCapability,
        fee: NativeCurrencyAmount,
    ) -> Arc<Transaction> {
        let mut rng: StdRng = SeedableRng::seed_from_u64(seed);
        let receiving_address = GenerationReceivingAddress::derive_from_seed(rng.random());
        let tx_outputs = vec![TxOutput::onchain_native_currency(
            NativeCurrencyAmount::coins(1),
            rng.random(),
            receiving_address.into(),
            true,
        )]
        .into();

        let (change_key, block_height) = {
            let mut gsm = state.lock_guard_mut().await;
            let change_key = gsm.wallet_state.next_unused_symmetric_key().await;
            let block_height = gsm.chain.light_state().header().height;
            (change_key, block_height)
        };
        let dummy = TritonVmJobQueue::get_instance();
        let timestamp = Network::Main.launch_date() + Timestamp::months(7);
        let config = TxCreationConfig::default()
            .recover_change_off_chain(change_key.into())
            .with_prover_capability(proof_quality)
            .use_job_queue(dummy);
        let consensus_rule_set = ConsensusRuleSet::infer_from(state.cli().network, block_height);
        let tx = state
            .api()
            .tx_initiator_internal()
            .create_transaction(tx_outputs, fee, timestamp, config, consensus_rule_set)
            .await
            .unwrap();

        tx.transaction
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn dont_upgrade_foreign_proof_collection_if_fee_too_low() {
        let network = Network::Main;

        // Alice is premine recipient, so she can make a transaction (after
        // expiry of timelock). Rando is not premine recipient.
        let cli_args = cli_args::Args {
            min_gobbling_fee: NativeCurrencyAmount::from_nau(5),
            network,
            ..Default::default()
        };
        let alice =
            mock_genesis_global_state(2, WalletEntropy::devnet_wallet(), cli_args.clone()).await;
        let pc_tx_low_fee = transaction_from_state(
            alice.clone(),
            512777439428,
            TxProvingCapability::ProofCollection,
            NativeCurrencyAmount::from_nau(2),
        )
        .await;

        for upgrade_priority in [UpgradePriority::Irrelevant, UpgradePriority::Critical] {
            let mut rando =
                mock_genesis_global_state(2, WalletEntropy::new_random(), cli_args.clone()).await;
            let mut rando = rando.lock_guard_mut().await;
            rando
                .mempool_insert(pc_tx_low_fee.clone().into(), upgrade_priority)
                .await;
            assert!(
                !upgrade_priority.is_irrelevant()
                    && get_upgrade_task_from_mempool(&mut rando).await.is_some()
                    || upgrade_priority.is_irrelevant()
                        && get_upgrade_task_from_mempool(&mut rando).await.is_none()
            );

            // A high-fee paying transaction must be returned for upgrading
            // regardless of value to the caller.
            let pc_tx_high_fee = transaction_from_state(
                alice.clone(),
                512777439428,
                TxProvingCapability::ProofCollection,
                NativeCurrencyAmount::from_nau(1_000_000_000),
            )
            .await;
            rando
                .mempool_insert(pc_tx_high_fee.clone().into(), UpgradePriority::Irrelevant)
                .await;
            let job = get_upgrade_task_from_mempool(&mut rando).await.unwrap();
            let UpgradeJob::ProofCollectionToSingleProof(ProofCollectionToSingleProof {
                kernel,
                ..
            }) = job
            else {
                panic!("Expected proof-collection to single-proof job");
            };

            assert_eq!(
                pc_tx_high_fee.kernel.txid(),
                kernel.txid(),
                "Returned job must be the one with a high fee"
            );
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn happy_path() {
        let network = Network::Main;

        for proving_capability in [
            TxProvingCapability::ProofCollection,
            TxProvingCapability::SingleProof,
        ] {
            let mut cli = cli_args::Args::default_with_network(network);
            cli.tx_proving_capability = Some(proving_capability);

            // Alice is premine recipient, so she can make a transaction (after
            // expiry of timelock).
            let (main_to_peer_tx, mut main_to_peer_rx, _, _, mut alice, _) =
                get_test_genesis_setup(network, 2, cli).await.unwrap();
            let pwtx = transaction_from_state(
                alice.clone(),
                512777439428,
                TxProvingCapability::PrimitiveWitness,
                NativeCurrencyAmount::from_nau(100),
            )
            .await;

            alice
                .lock_guard_mut()
                .await
                .mempool_insert((*pwtx).clone(), UpgradePriority::Critical)
                .await;
            let TransactionProof::Witness(pw) = &pwtx.proof else {
                panic!("Expected PW-backed tx");
            };
            let pw_to_tx_upgrade_job =
                UpgradeJob::from_primitive_witness(network, proving_capability, pw.to_owned());
            pw_to_tx_upgrade_job
                .handle_upgrade(
                    TritonVmJobQueue::get_instance(),
                    alice.clone(),
                    main_to_peer_tx,
                )
                .await;

            let peer_msg = main_to_peer_rx.recv().await.unwrap();
            let MainToPeerTask::TransactionNotification(tx_notification) = peer_msg else {
                panic!("Proof upgrader must inform peer tasks about upgraded tx");
            };

            assert_eq!(
                pwtx.kernel.txid(),
                tx_notification.txid,
                "TXID in peer msg must match that from transaction"
            );

            // Ensure PC/SP-backed tx exists in mempool
            let mempool_tx = alice
                .lock_guard()
                .await
                .mempool
                .get(pwtx.kernel.txid())
                .unwrap()
                .to_owned();
            match proving_capability {
                TxProvingCapability::LockScript => unreachable!(),
                TxProvingCapability::PrimitiveWitness => unreachable!(),
                TxProvingCapability::ProofCollection => assert!(
                    matches!(mempool_tx.proof, TransactionProof::ProofCollection(_)),
                    "Tx in mempool must be backed with {proving_capability} after upgrade"
                ),
                TxProvingCapability::SingleProof => assert!(
                    matches!(mempool_tx.proof, TransactionProof::SingleProof(_)),
                    "Tx in mempool must be backed with {proving_capability} after upgrade"
                ),
            }

            let block_height = alice
                .lock_guard_mut()
                .await
                .chain
                .light_state()
                .header()
                .height;
            let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
            assert!(mempool_tx.is_valid(network, consensus_rule_set).await);
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn race_condition_with_one_new_block() {
        let network = Network::Main;
        let proving_capabilities = [
            TxProvingCapability::ProofCollection,
            TxProvingCapability::SingleProof,
        ];
        for proving_capability in proving_capabilities {
            let mut cli = cli_args::Args::default_with_network(network);
            cli.tx_proving_capability = Some(proving_capability);

            // Alice is premine recipient, so she can make a transaction (after
            // expiry of timelock).
            let (main_to_peer_tx, mut main_to_peer_rx, _, _, mut alice, _) =
                get_test_genesis_setup(network, 2, cli).await.unwrap();
            let pwtx = transaction_from_state(
                alice.clone(),
                512777439429,
                TxProvingCapability::PrimitiveWitness,
                NativeCurrencyAmount::from_nau(100),
            )
            .await;
            assert!(
                pwtx.is_valid(
                    network,
                    ConsensusRuleSet::infer_from(network, BlockHeight::genesis())
                )
                .await
            );
            alice
                .lock_guard_mut()
                .await
                .mempool_insert((*pwtx).clone(), UpgradePriority::Critical)
                .await;
            let TransactionProof::Witness(pw) = &pwtx.proof else {
                panic!("Expected PW-backed tx");
            };

            let upgrade_job =
                UpgradeJob::from_primitive_witness(network, proving_capability, pw.to_owned());

            // Before handle upgrade completes, a new block comes in. Making the
            // method have to do more work.
            let genesis_block = Block::genesis(network);
            let block1 =
                invalid_empty_block_with_timestamp(&genesis_block, pwtx.kernel.timestamp, network);
            let block1_msu = block1.mutator_set_update().unwrap();
            println!(
                "block1_msu #addition records: {}; block1_msu #removal records: {}",
                block1_msu.additions.len(),
                block1_msu.removals.len()
            );
            alice.set_new_tip(block1.clone()).await.unwrap();

            upgrade_job
                .handle_upgrade(
                    TritonVmJobQueue::get_instance(),
                    alice.clone(),
                    main_to_peer_tx,
                )
                .await;

            let peer_msg = main_to_peer_rx.recv().await.unwrap();
            let MainToPeerTask::TransactionNotification(tx_notification) = peer_msg else {
                panic!("Proof upgrader must inform peer tasks about upgraded tx");
            };

            assert_eq!(
                pwtx.kernel.txid(),
                tx_notification.txid,
                "TXID in peer msg must match that from transaction"
            );

            // Ensure correct proof-type
            let mempool_tx = alice
                .lock_guard()
                .await
                .mempool
                .get(pwtx.kernel.txid())
                .unwrap()
                .to_owned();
            match proving_capability {
                TxProvingCapability::LockScript => unreachable!(),
                TxProvingCapability::PrimitiveWitness => unreachable!(),
                TxProvingCapability::ProofCollection => assert!(
                    matches!(mempool_tx.proof, TransactionProof::ProofCollection(_)),
                    "Tx in mempool must be backed with {proving_capability} after upgrade"
                ),
                TxProvingCapability::SingleProof => assert!(
                    matches!(mempool_tx.proof, TransactionProof::SingleProof(_)),
                    "Tx in mempool must be backed with {proving_capability} after upgrade"
                ),
            }

            let consensus_rule_set = ConsensusRuleSet::infer_from(network, block1.header().height);
            assert!(mempool_tx.is_valid(network, consensus_rule_set).await);

            // Ensure tx was updated to latest mutator set
            let mutator_set_accumulator_after = alice
                .lock_guard()
                .await
                .chain
                .light_state()
                .mutator_set_accumulator_after()
                .unwrap();
            assert!(mempool_tx.is_confirmable_relative_to(&mutator_set_accumulator_after));
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn dont_share_partly_mined_merge_upgrade() {
        let network = Network::Main;

        // Alice is premine recipient and has mined one block, so she can make
        // (at least) two transaction.
        let mut rng: StdRng = StdRng::seed_from_u64(512777439429);
        let cli_args = cli_args::Args {
            network,
            tx_proving_capability: Some(TxProvingCapability::SingleProof),
            tx_proof_upgrading: true,
            ..Default::default()
        };
        let mut alice =
            state_with_premine_and_self_mined_blocks(cli_args, rng.random::<[Digest; 1]>()).await;

        let mut transactions = vec![];
        for _ in 0..=1 {
            let tx_fee = NativeCurrencyAmount::coins(2);
            let single_proof_tx = transaction_from_state(
                alice.clone(),
                rng.random(),
                TxProvingCapability::SingleProof,
                tx_fee,
            )
            .await;
            alice
                .lock_guard_mut()
                .await
                .mempool_insert(single_proof_tx.clone().into(), UpgradePriority::Critical)
                .await;
            transactions.push(single_proof_tx);
        }

        // Test assumption: Transactions do not use overlapping inputs.
        let mut hashset = HashSet::new();
        for tx in &transactions {
            for input in &tx.kernel.inputs {
                let new_input = hashset.insert(input.absolute_indices.to_vec());
                assert!(new_input);
            }
        }

        let merge_upgrade_job = {
            let mut alice = alice.lock_guard_mut().await;
            get_upgrade_task_from_mempool(&mut alice).await.unwrap()
        };
        assert!(
            matches!(merge_upgrade_job, UpgradeJob::Merge { .. }),
            "Return upgrade job must be of type merge."
        );

        // Now, one of the transactions get mined. Before the upgrade job that
        // merges the two transactions completes. This means that the merged
        // transaction will be a double-spending transactions as at least one
        // of its inputs has already been spent. This transaction must not be
        // transmitted to peers, as this would cause peers to ban the upgrader
        // for sharing unconfirmable transactions.
        let mined_tx = transactions[0].clone();
        let unmined_tx = transactions[1].clone();
        let block1 = alice.lock_guard().await.chain.light_state().to_owned();

        let now = block1.header().timestamp + Timestamp::hours(1);
        let block2 = fake_block_successor_with_merged_tx(
            &block1,
            now,
            false,
            vec![mined_tx.into()],
            rng.random(),
            network,
        )
        .await;
        alice.set_new_tip(block2).await.unwrap();

        let (main_to_peer_tx, mut main_to_peer_rx) =
            broadcast::channel::<MainToPeerTask>(PEER_CHANNEL_CAPACITY);
        merge_upgrade_job
            .handle_upgrade(
                TritonVmJobQueue::get_instance(),
                alice.clone(),
                main_to_peer_tx.clone(),
            )
            .await;

        let peer_msg = main_to_peer_rx.try_recv().unwrap_err();
        assert_eq!(TryRecvError::Empty, peer_msg);

        drop(main_to_peer_tx);

        // Since one transacion got mined, and the other didn't, we should still
        // have the unmined transaction in the mempool. Since this transcation
        // is owned by this client, we want to keep it in the mempool.
        assert_eq!(1, alice.lock_guard().await.mempool.len());
        assert!(alice
            .lock_guard()
            .await
            .mempool
            .contains(unmined_tx.kernel.txid()));
    }
}
