use std::time::SystemTime;

use itertools::Itertools;
use num_traits::Zero;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use tasm_lib::triton_vm::proof::Proof;
use tracing::error;
use tracing::info;

use super::TransactionOrigin;
use crate::job_queue::triton_vm::TritonVmJobPriority;
use crate::job_queue::triton_vm::TritonVmJobQueue;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::validity::proof_collection::ProofCollection;
use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
use crate::models::blockchain::transaction::validity::single_proof::SingleProofWitness;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::proof_abstractions::SecretWitness;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::transaction_kernel_id::TransactionKernelId;
use crate::models::state::tx_proving_capability::TxProvingCapability;
use crate::models::state::wallet::address::SpendingKey;
use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
use crate::models::state::wallet::expected_utxo::UtxoNotifier;
use crate::models::state::wallet::utxo_notification::UtxoNotifyMethod;
use crate::models::state::wallet::wallet_entropy::WalletEntropy;
use crate::models::state::GlobalState;
use crate::models::state::GlobalStateLock;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::MainToPeerTask;

const SEARCH_DEPTH_FOR_BLOCKS_FOR_MS_UPDATE_PROOF: usize = 100;

/// Enumerates the types of 'proof upgrades' that can be done.
///
/// A transaction proof can be in need of upgrading, either because it cannot
/// be shared in its current state without leaking secret keys, or to make it
/// more likely that a miner picks up this transaction.
#[derive(Clone, Debug)]
pub enum UpgradeJob {
    PrimitiveWitnessToProofCollection {
        primitive_witness: PrimitiveWitness,
    },
    PrimitiveWitnessToSingleProof {
        primitive_witness: PrimitiveWitness,
    },
    ProofCollectionToSingleProof {
        kernel: TransactionKernel,
        proof: ProofCollection,
        mutator_set: MutatorSetAccumulator,
        gobbling_fee: NativeCurrencyAmount,
    },
    Merge {
        left_kernel: TransactionKernel,
        single_proof_left: Proof,
        right_kernel: TransactionKernel,
        single_proof_right: Proof,
        shuffle_seed: [u8; 32],
        mutator_set: MutatorSetAccumulator,
        gobbling_fee: NativeCurrencyAmount,
    },
    UpdateMutatorSetData(UpdateMutatorSetDataJob),
}

#[derive(Clone, Debug)]
pub struct UpdateMutatorSetDataJob {
    old_kernel: TransactionKernel,
    old_single_proof: Proof,
    old_mutator_set: MutatorSetAccumulator,
    mutator_set_update: MutatorSetUpdate,
}

impl UpdateMutatorSetDataJob {
    pub(crate) fn new(
        old_kernel: TransactionKernel,
        old_single_proof: Proof,
        old_mutator_set: MutatorSetAccumulator,
        mutator_set_update: MutatorSetUpdate,
    ) -> Self {
        Self {
            old_kernel,
            old_single_proof,
            old_mutator_set,
            mutator_set_update,
        }
    }

    pub(crate) async fn upgrade(
        self,
        triton_vm_job_queue: &TritonVmJobQueue,
        proof_job_options: TritonVmProofJobOptions,
    ) -> anyhow::Result<Transaction> {
        let UpdateMutatorSetDataJob {
            old_kernel,
            old_single_proof,
            old_mutator_set,
            mutator_set_update,
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
        )
        .await?;
        info!("Proof-upgrader, update: Done");

        Ok(ret)
    }
}

impl From<UpdateMutatorSetDataJob> for UpgradeJob {
    fn from(value: UpdateMutatorSetDataJob) -> Self {
        Self::UpdateMutatorSetData(value)
    }
}

impl UpgradeJob {
    /// Create an upgrade job from a primitive witness, for upgrading proof-
    /// support for a transaction that this client has initiated.
    ///
    /// Since [PrimitiveWitness] contains secret data, this upgrade job can only
    /// be used for transactions that originate locally.
    pub(super) fn from_primitive_witness(
        tx_proving_capability: TxProvingCapability,
        primitive_witness: PrimitiveWitness,
    ) -> UpgradeJob {
        match tx_proving_capability {
            TxProvingCapability::ProofCollection => {
                UpgradeJob::PrimitiveWitnessToProofCollection { primitive_witness }
            }
            TxProvingCapability::SingleProof => {
                UpgradeJob::PrimitiveWitnessToSingleProof { primitive_witness }
            }
            TxProvingCapability::PrimitiveWitness => {
                panic!("Client cannot have primitive witness capability only")
            }
            TxProvingCapability::LockScript => todo!("TODO: Add support for this"),
        }
    }

    fn gobbling_fee(&self) -> NativeCurrencyAmount {
        match self {
            UpgradeJob::ProofCollectionToSingleProof { gobbling_fee, .. } => *gobbling_fee,
            UpgradeJob::Merge { gobbling_fee, .. } => *gobbling_fee,
            _ => NativeCurrencyAmount::zero(),
        }
    }

    fn old_tx_timestamp(&self) -> Timestamp {
        match self {
            UpgradeJob::PrimitiveWitnessToProofCollection { primitive_witness } => {
                primitive_witness.kernel.timestamp
            }
            UpgradeJob::PrimitiveWitnessToSingleProof { primitive_witness } => {
                primitive_witness.kernel.timestamp
            }
            UpgradeJob::ProofCollectionToSingleProof { kernel, .. } => kernel.timestamp,
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

    /// Compute the ratio of gobbling fee to number of proofs.
    ///
    /// This number stands in for rate charged for upgrading proofs.
    fn profitability(&self) -> NativeCurrencyAmount {
        match self {
            UpgradeJob::ProofCollectionToSingleProof {
                proof: collection,
                gobbling_fee,
                ..
            } => {
                let reciprocal = 1.0 / (collection.num_proofs() as f64);
                gobbling_fee.lossy_f64_fraction_mul(reciprocal)
            }
            UpgradeJob::Merge { gobbling_fee, .. } => {
                let mut rate = *gobbling_fee;
                rate.div_two();
                rate
            }
            _ => NativeCurrencyAmount::zero(),
        }
    }

    /// Return a list of the transaction IDs that will have their proofs
    /// upgraded with this decision.
    ///
    /// Will return a list of length two in the case of merge, otherwise a list
    /// of length one.
    pub(super) fn affected_txids(&self) -> Vec<TransactionKernelId> {
        match self {
            UpgradeJob::ProofCollectionToSingleProof { kernel, .. } => {
                vec![kernel.txid()]
            }
            UpgradeJob::Merge {
                left_kernel,
                right_kernel,
                ..
            } => vec![left_kernel.txid(), right_kernel.txid()],
            UpgradeJob::PrimitiveWitnessToProofCollection { primitive_witness } => {
                vec![primitive_witness.kernel.txid()]
            }
            UpgradeJob::PrimitiveWitnessToSingleProof { primitive_witness } => {
                vec![primitive_witness.kernel.txid()]
            }
            UpgradeJob::UpdateMutatorSetData(update_job) => vec![update_job.old_kernel.txid()],
        }
    }

    /// Return the mutator set that this transaction is assumed to be valid
    /// under, after the upgrade.
    fn mutator_set(&self) -> MutatorSetAccumulator {
        match self {
            UpgradeJob::PrimitiveWitnessToProofCollection { primitive_witness } => {
                primitive_witness.mutator_set_accumulator.clone()
            }
            UpgradeJob::PrimitiveWitnessToSingleProof { primitive_witness } => {
                primitive_witness.mutator_set_accumulator.clone()
            }
            UpgradeJob::ProofCollectionToSingleProof { mutator_set, .. } => mutator_set.clone(),
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

    /// Upgrade transaction proofs, inserts upgraded tx into the mempool and
    /// informs peers of this new transaction.
    pub(crate) async fn handle_upgrade(
        self,
        triton_vm_job_queue: &TritonVmJobQueue,
        tx_origin: TransactionOrigin,
        perform_ms_update_if_needed: bool,
        mut global_state_lock: GlobalStateLock,
        main_to_peer_channel: tokio::sync::broadcast::Sender<MainToPeerTask>,
    ) {
        let mut upgrade_job = self;

        let priority = match tx_origin {
            TransactionOrigin::Foreign => TritonVmJobPriority::Lowest,
            TransactionOrigin::Own => TritonVmJobPriority::High,
        };

        // process in a loop.  in case a new block comes in while processing
        // the current tx, then we can move on to the next, and so on.
        loop {
            // Record that we're attempting an upgrade.
            global_state_lock
                .lock_guard_mut()
                .await
                .net
                .last_tx_proof_upgrade_attempt = SystemTime::now();

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

            // No locks may be held here!
            let (upgraded, expected_utxos) = match upgrade_job
                .clone()
                .upgrade(
                    triton_vm_job_queue,
                    job_options,
                    &wallet_entropy,
                    block_height,
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
                    error!("upgrading of witness or proof in {tx_origin} transaction failed.");
                    error!(
                        "Consider lowering your proving capability to {}, in case it is set higher.\nCurrent proving \
                        capability is set to: {}.",
                        TxProvingCapability::ProofCollection,
                        global_state_lock.cli().proving_capability()
                    );
                    return;
                }
            };

            upgrade_job = {
                let mut global_state = global_state_lock.lock_guard_mut().await;
                // Did we receive a new block while proving? If so, perform an
                // update also, if this was requested.

                let transaction_is_deprecated = upgraded.kernel.mutator_set_hash
                    != global_state
                        .chain
                        .light_state()
                        .mutator_set_accumulator_after()
                        .hash();

                if !transaction_is_deprecated {
                    // Happy path

                    // Insert tx into mempool before notifying peers, so we're
                    // sure to have it when they ask.
                    global_state
                        .mempool_insert(upgraded.clone(), tx_origin)
                        .await;

                    global_state
                        .wallet_state
                        .add_expected_utxos(expected_utxos)
                        .await;
                    drop(global_state); // sooner is better.

                    // Inform all peers about our hard work
                    main_to_peer_channel
                        .send(MainToPeerTask::TransactionNotification(
                            (&upgraded).try_into().unwrap(),
                        ))
                        .unwrap();

                    info!("Successfully handled proof upgrade.");
                    return;
                }

                info!(
                    "Transaction is deprecated after upgrade because of new block(s). Affected txs: [{}]",
                    affected_txids.iter().join("\n"));

                if !perform_ms_update_if_needed {
                    info!("Not performing update as this was not requested");
                    return;
                }

                let Some(ms_update) = global_state
                    .chain
                    .archival_state_mut()
                    .get_mutator_set_update_to_tip(
                        &mutator_set_for_tx,
                        SEARCH_DEPTH_FOR_BLOCKS_FOR_MS_UPDATE_PROOF,
                    )
                    .await
                else {
                    info!("Couldn't find path from old mutator set to current tip. Did a reorganization happen?");
                    return;
                };

                if let TransactionProof::SingleProof(single_proof) = upgraded.proof {
                    // Transaction is single-proof supported but MS data is deprecated. Create new
                    // upgrade job to fix that.
                    let ms_update_job = UpdateMutatorSetDataJob {
                        old_kernel: upgraded.kernel,
                        old_single_proof: single_proof,
                        old_mutator_set: mutator_set_for_tx,
                        mutator_set_update: ms_update,
                    };
                    UpgradeJob::UpdateMutatorSetData(ms_update_job)
                } else {
                    match upgrade_job {
                        UpgradeJob::PrimitiveWitnessToProofCollection { primitive_witness } => {
                            // Transaction is proof collection supported but MS data is deprecated.
                            // Since proof collections cannot be updated, we instead update the
                            // primitive witness and create a new job to upgrade the updated
                            // primitive witness to a proof collection.
                            let new_pw = PrimitiveWitness::update_with_new_ms_data(
                                primitive_witness,
                                ms_update,
                            );
                            UpgradeJob::PrimitiveWitnessToProofCollection {
                                primitive_witness: new_pw,
                            }
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

    /// Execute the proof upgrade.
    ///
    /// Upgrades transactions to a proof of higher quality that is more likely
    /// to be picked up by a miner. Returns the upgraded proof, or an error if
    /// the prover is already in use and the proof_job_options is set to not wait if
    /// prover is busy.
    pub(crate) async fn upgrade(
        self,
        triton_vm_job_queue: &TritonVmJobQueue,
        proof_job_options: TritonVmProofJobOptions,
        own_wallet_entropy: &WalletEntropy,
        current_block_height: BlockHeight,
    ) -> anyhow::Result<(Transaction, Vec<ExpectedUtxo>)> {
        let gobbling_fee = self.gobbling_fee();
        let mutator_set = self.mutator_set();
        let old_tx_timestamp = self.old_tx_timestamp();

        let (gobbler, expected_utxos) = if gobbling_fee.is_positive() {
            info!("Producing gobbler-transaction for a value of {gobbling_fee}");
            let gobble_receiver = own_wallet_entropy.nth_symmetric_key(0);
            let receiver_preimage = gobble_receiver.privacy_preimage();
            let gobble_receiver = SpendingKey::Symmetric(gobble_receiver);
            let gobble_receiver = gobble_receiver.to_address().expect(
                "gobble receiver should have a corresponding address because it is a symmetric key",
            );
            let gobbler = TransactionDetails::fee_gobbler(
                gobbling_fee,
                own_wallet_entropy.generate_sender_randomness(
                    current_block_height,
                    gobble_receiver.privacy_digest(),
                ),
                mutator_set,
                old_tx_timestamp,
                // TODO: Consider using `None` here as UTXOs are already
                // stored as expected UTXOs by wallet.
                UtxoNotifyMethod::OnChain(gobble_receiver),
            );
            let expected_utxos = gobbler
                .tx_outputs
                .iter()
                .map(|x| {
                    ExpectedUtxo::new(
                        x.utxo(),
                        x.sender_randomness(),
                        receiver_preimage,
                        UtxoNotifier::FeeGobbler,
                    )
                })
                .collect_vec();
            let gobbler = PrimitiveWitness::from_transaction_details(&gobbler);
            let gobbler_proof =
                SingleProof::produce(&gobbler, triton_vm_job_queue, proof_job_options.clone())
                    .await?;
            info!("Done producing gobbler-transaction for a value of {gobbling_fee}");
            let gobbler = Transaction {
                kernel: gobbler.kernel,
                proof: TransactionProof::SingleProof(gobbler_proof),
            };
            (Some(gobbler), expected_utxos)
        } else {
            (None, vec![])
        };

        let mut rng: StdRng =
            SeedableRng::from_seed(own_wallet_entropy.shuffle_seed(current_block_height.next()));
        let gobble_shuffle_seed: [u8; 32] = rng.random();

        match self {
            UpgradeJob::ProofCollectionToSingleProof { kernel, proof, .. } => {
                let single_proof_witness = SingleProofWitness::from_collection(proof.to_owned());
                let claim = single_proof_witness.claim();
                let nondeterminism = single_proof_witness.nondeterminism();
                info!("Proof-upgrader: Start generate single proof");
                let single_proof = SingleProof
                    .prove(
                        claim,
                        nondeterminism,
                        triton_vm_job_queue,
                        proof_job_options.clone(),
                    )
                    .await?;
                info!("Proof-upgrader, to single proof: Done");

                let upgraded_tx = Transaction {
                    kernel,
                    proof: TransactionProof::SingleProof(single_proof),
                };

                let tx = if let Some(gobbler) = gobbler {
                    let lhs = gobbler;
                    let rhs = upgraded_tx;

                    info!("Proof-upgrader: Start merging with gobbler");
                    let ret = lhs
                        .merge_with(
                            rhs,
                            gobble_shuffle_seed,
                            triton_vm_job_queue,
                            proof_job_options,
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
                    triton_vm_job_queue,
                    proof_job_options.clone(),
                )
                .await?;
                info!("Proof-upgrader, merge: Done");

                if let Some(gobbler) = gobbler {
                    ret = gobbler
                        .merge_with(
                            ret,
                            gobble_shuffle_seed,
                            triton_vm_job_queue,
                            proof_job_options,
                        )
                        .await?
                };

                Ok((ret, expected_utxos))
            }
            UpgradeJob::PrimitiveWitnessToProofCollection {
                primitive_witness: witness,
            } => {
                info!("Proof-upgrader: Start producing proof collection");
                let proof_collection =
                    ProofCollection::produce(&witness, triton_vm_job_queue, proof_job_options)
                        .await?;
                info!("Proof-upgrader, proof collection: Done");
                Ok((
                    Transaction {
                        kernel: witness.kernel,
                        proof: TransactionProof::ProofCollection(proof_collection),
                    },
                    vec![],
                ))
            }
            UpgradeJob::PrimitiveWitnessToSingleProof {
                primitive_witness: witness,
            } => {
                info!("Proof-upgrader: Start producing single proof");
                let proof =
                    SingleProof::produce(&witness, triton_vm_job_queue, proof_job_options).await?;
                info!("Proof-upgrader, single proof: Done");
                Ok((
                    Transaction {
                        kernel: witness.kernel,
                        proof: TransactionProof::SingleProof(proof),
                    },
                    vec![],
                ))
            }
            UpgradeJob::UpdateMutatorSetData(update_job) => {
                let ret = update_job
                    .upgrade(triton_vm_job_queue, proof_job_options)
                    .await?;
                Ok((ret, vec![]))
            }
        }
    }
}

/// Return an [UpgradeJob] that describes work that can be done to upgrade the
/// proof-quality of a transaction found in mempool. Also indicates whether the
/// upgrade job affects one of our own transaction, or a foreign transaction.
pub(super) fn get_upgrade_task_from_mempool(
    global_state: &GlobalState,
) -> Option<(UpgradeJob, TransactionOrigin)> {
    // Do we have any `ProofCollection`s?
    let tip = global_state.chain.light_state();
    let gobbling_fraction = global_state.gobbling_fraction();
    let min_gobbling_fee = global_state.min_gobbling_fee();
    let num_proofs_threshold = global_state.max_num_proofs();

    let proof_collection_job = if let Some((kernel, proof, tx_origin)) = global_state
        .mempool
        .most_dense_proof_collection(num_proofs_threshold)
    {
        let gobbling_fee = kernel.fee.lossy_f64_fraction_mul(gobbling_fraction);
        let gobbling_fee =
            if gobbling_fee >= min_gobbling_fee && tx_origin == TransactionOrigin::Foreign {
                gobbling_fee
            } else {
                NativeCurrencyAmount::zero()
            };
        let upgrade_decision = UpgradeJob::ProofCollectionToSingleProof {
            kernel: kernel.to_owned(),
            proof: proof.to_owned(),
            mutator_set: tip.mutator_set_accumulator_after().to_owned(),
            gobbling_fee,
        };

        if upgrade_decision.mutator_set().hash() != kernel.mutator_set_hash {
            error!("Deprecated transaction found in mempool. Has ProofCollection in need of updating. Consider clearing mempool.");
            return None;
        }

        Some((upgrade_decision, tx_origin))
    } else {
        None
    };

    if let Some((_, TransactionOrigin::Own)) = &proof_collection_job {
        return proof_collection_job;
    }

    // Can we merge two single proofs?
    let merge_job = if let Some((
        [(left_kernel, left_single_proof), (right_kernel, right_single_proof)],
        tx_origin,
    )) = global_state.mempool.most_dense_single_proof_pair()
    {
        let gobbling_fee = left_kernel.fee + right_kernel.fee;
        let gobbling_fee = gobbling_fee.lossy_f64_fraction_mul(gobbling_fraction);
        let gobbling_fee = if gobbling_fee >= min_gobbling_fee {
            gobbling_fee
        } else {
            NativeCurrencyAmount::zero()
        };
        let mut rng: StdRng = SeedableRng::from_seed(global_state.shuffle_seed());
        let upgrade_decision = UpgradeJob::Merge {
            left_kernel: left_kernel.to_owned(),
            single_proof_left: left_single_proof.to_owned(),
            right_kernel: right_kernel.to_owned(),
            single_proof_right: right_single_proof.to_owned(),
            shuffle_seed: rng.random(),
            mutator_set: tip.mutator_set_accumulator_after().to_owned(),
            gobbling_fee,
        };

        if left_kernel.mutator_set_hash != right_kernel.mutator_set_hash
            || right_kernel.mutator_set_hash != upgrade_decision.mutator_set().hash()
        {
            error!("Deprecated transaction found in mempool. Has SingleProof in need of updating. Consider clearing mempool.");
            return None;
        }

        Some((upgrade_decision, tx_origin))
    } else {
        None
    };

    // pick the most profitable option
    let mut jobs = [proof_collection_job, merge_job]
        .into_iter()
        .flatten()
        .collect_vec();
    jobs.sort_by_key(|(job, _)| job.profitability());

    jobs.first().cloned()
}

#[cfg(test)]
mod test {
    use tracing_test::traced_test;

    use super::*;
    use crate::config_models::cli_args;
    use crate::config_models::network::Network;
    use crate::models::blockchain::block::Block;
    use crate::models::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::models::state::wallet::transaction_output::TxOutput;
    use crate::models::state::wallet::utxo_notification::UtxoNotificationMedium;
    use crate::tests::shared::get_test_genesis_setup;
    use crate::tests::shared::invalid_empty_block_with_timestamp;

    /// Returns a PrimitiveWitness-backed transaction initiated by the global
    /// state provided as argument. Assumes balance is sufficient to make this
    /// transaction.
    async fn primitive_witness_backed_tx(mut state: GlobalStateLock, seed: u64) -> Transaction {
        let mut rng: StdRng = SeedableRng::seed_from_u64(seed);
        let receiving_address = GenerationReceivingAddress::derive_from_seed(rng.random());
        let tx_outputs = vec![TxOutput::onchain_native_currency(
            NativeCurrencyAmount::coins(1),
            rng.random(),
            receiving_address.into(),
            false,
        )]
        .into();
        let mut state = state.lock_guard_mut().await;
        let change_key = state.wallet_state.next_unused_symmetric_key().await;
        let fee = NativeCurrencyAmount::from_nau(100);
        let timestamp = Network::Main.launch_date() + Timestamp::months(7);
        let (tx, _, _) = state
            .create_transaction_with_prover_capability(
                tx_outputs,
                change_key.into(),
                UtxoNotificationMedium::OffChain,
                fee,
                timestamp,
                TxProvingCapability::PrimitiveWitness,
                &TritonVmJobQueue::dummy(),
            )
            .await
            .unwrap();

        tx
    }

    #[traced_test]
    #[tokio::test]
    async fn happy_path() {
        let network = Network::Main;

        for proving_capability in [
            TxProvingCapability::ProofCollection,
            TxProvingCapability::SingleProof,
        ] {
            // Alice is premine recipient, so she can make a transaction (after
            // expiry of timelock).
            let (main_to_peer_tx, mut main_to_peer_rx, _, _, mut alice, _) =
                get_test_genesis_setup(network, 2, cli_args::Args::default_with_network(network))
                    .await
                    .unwrap();
            let pwtx = primitive_witness_backed_tx(alice.clone(), 512777439428).await;
            alice
                .lock_guard_mut()
                .await
                .mempool_insert(pwtx.clone(), TransactionOrigin::Own)
                .await;
            let TransactionProof::Witness(pw) = &pwtx.proof else {
                panic!("Expected PW-backed tx");
            };
            let pw_to_tx_upgrade_job =
                UpgradeJob::from_primitive_witness(proving_capability, pw.to_owned());
            pw_to_tx_upgrade_job
                .handle_upgrade(
                    &TritonVmJobQueue::dummy(),
                    TransactionOrigin::Own,
                    true,
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

            // Ensure PC-backed tx exists in mempool
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

            assert!(mempool_tx.is_valid().await);
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn race_condition_with_one_new_block() {
        let network = Network::Main;

        for proving_capability in [
            TxProvingCapability::ProofCollection,
            TxProvingCapability::SingleProof,
        ] {
            // Alice is premine recipient, so she can make a transaction (after
            // expiry of timelock).
            let (main_to_peer_tx, mut main_to_peer_rx, _, _, mut alice, _) =
                get_test_genesis_setup(network, 2, cli_args::Args::default_with_network(network))
                    .await
                    .unwrap();
            let pwtx = primitive_witness_backed_tx(alice.clone(), 512777439429).await;
            alice
                .lock_guard_mut()
                .await
                .mempool_insert(pwtx.clone(), TransactionOrigin::Own)
                .await;
            let TransactionProof::Witness(pw) = &pwtx.proof else {
                panic!("Expected PW-backed tx");
            };

            let upgrade_job = UpgradeJob::from_primitive_witness(proving_capability, pw.to_owned());

            // Before handle upgrade completes, a new block comes in. Making the
            // method have to do more work.
            let genesis_block = Block::genesis(network);
            let block1 = invalid_empty_block_with_timestamp(&genesis_block, pwtx.kernel.timestamp);
            alice.set_new_tip(block1).await.unwrap();
            upgrade_job
                .handle_upgrade(
                    &TritonVmJobQueue::dummy(),
                    TransactionOrigin::Own,
                    true,
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

            assert!(mempool_tx.is_valid().await);

            // Ensure tx was updated to latest mutator set
            let mutator_set_accumulator_after = alice
                .lock_guard()
                .await
                .chain
                .light_state()
                .mutator_set_accumulator_after();
            assert!(mempool_tx.is_confirmable_relative_to(&mutator_set_accumulator_after));
        }
    }
}
