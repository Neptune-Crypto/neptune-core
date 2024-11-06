use std::time::SystemTime;

use itertools::Itertools;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use tasm_lib::triton_vm::proof::Proof;
use tracing::error;
use tracing::info;

use crate::job_queue::triton_vm::TritonVmJobPriority;
use crate::job_queue::triton_vm::TritonVmJobQueue;
use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::validity::proof_collection::ProofCollection;
use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
use crate::models::blockchain::transaction::validity::single_proof::SingleProofWitness;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::SecretWitness;
use crate::models::state::transaction_kernel_id::TransactionKernelId;
use crate::models::state::tx_proving_capability::TxProvingCapability;
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
    },
    Merge {
        left_kernel: TransactionKernel,
        single_proof_left: Proof,
        right_kernel: TransactionKernel,
        single_proof_right: Proof,
        shuffle_seed: [u8; 32],
        mutator_set: MutatorSetAccumulator,
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

    /// Return a list of the transaction IDs that will have their proofs
    /// upgraded with this decision.
    ///
    /// Will return a list of length two in the case of merge, otherwise a list
    /// of length one.
    pub(super) fn affected_txids(&self) -> Vec<TransactionKernelId> {
        match self {
            UpgradeJob::ProofCollectionToSingleProof {
                kernel,
                proof: _,
                mutator_set: _,
            } => {
                vec![kernel.txid()]
            }
            UpgradeJob::Merge {
                left_kernel,
                single_proof_left: _,
                right_kernel,
                single_proof_right: _,
                shuffle_seed: _,
                mutator_set: _,
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
        priority: TritonVmJobPriority,
        perform_ms_update_if_needed: bool,
        mut global_state_lock: GlobalStateLock,
        main_to_peer_channel: tokio::sync::broadcast::Sender<MainToPeerTask>,
    ) {
        let mut upgrade_job = self;

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

            let upgraded = match upgrade_job.upgrade(triton_vm_job_queue, priority).await {
                Ok(upgraded_tx) => {
                    info!(
                        "Successfully upgraded transaction {}",
                        upgraded_tx.kernel.txid()
                    );
                    upgraded_tx
                }
                Err(e) => {
                    panic!("UpgradeProof job failed. error: {}", e);
                }
            };

            let new_update_job: UpdateMutatorSetDataJob = {
                let mut global_state = global_state_lock.lock_guard_mut().await;
                // Did we receive a new block while proving? If so, perform an
                // update also, if this was requested (and we have a single proof)
                // if we only have a ProofCollection, then we throw away the work
                // regardless.

                let transaction_is_deprecated = upgraded.kernel.mutator_set_hash
                    != global_state
                        .chain
                        .light_state()
                        .body()
                        .mutator_set_accumulator
                        .hash();

                if !transaction_is_deprecated {
                    // Happy path

                    // Inform all peers about our hard work
                    main_to_peer_channel
                        .send(MainToPeerTask::TransactionNotification(
                            (&upgraded).try_into().unwrap(),
                        ))
                        .unwrap();

                    global_state.mempool_insert(upgraded).await;

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

                let TransactionProof::SingleProof(single_proof) = upgraded.proof else {
                    info!("Cannot perform update, as we don't have a SingleProof");
                    return;
                };

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

                UpdateMutatorSetDataJob {
                    old_kernel: upgraded.kernel,
                    old_single_proof: single_proof,
                    old_mutator_set: mutator_set_for_tx,
                    mutator_set_update: ms_update,
                }
            };

            upgrade_job = UpgradeJob::UpdateMutatorSetData(new_update_job);
        }
    }

    /// Execute the proof upgrade.
    ///
    /// Upgrades transactions to a proof of higher quality that is more likely
    /// to be picked up by a miner. Returns the upgraded proof, or an error if
    /// the prover is already in use and the priority is set to not wait if
    /// prover is busy.
    pub(crate) async fn upgrade(
        self,
        triton_vm_job_queue: &TritonVmJobQueue,
        priority: TritonVmJobPriority,
    ) -> anyhow::Result<Transaction> {
        match self {
            UpgradeJob::ProofCollectionToSingleProof { kernel, proof, .. } => {
                let single_proof_witness = SingleProofWitness::from_collection(proof.to_owned());
                let claim = single_proof_witness.claim();
                let nondeterminism = single_proof_witness.nondeterminism();
                info!("Proof-upgrader: Start generate single proof");
                let single_proof = SingleProof
                    .prove(&claim, nondeterminism, triton_vm_job_queue, priority)
                    .await?;
                info!("Proof-upgrader: Done");

                Ok(Transaction {
                    kernel: kernel.to_owned(),
                    proof: TransactionProof::SingleProof(single_proof),
                })
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
                let ret = Transaction::merge_with(
                    left,
                    right,
                    shuffle_seed.to_owned(),
                    triton_vm_job_queue,
                    priority,
                )
                .await?;
                info!("Proof-upgrader: Done");

                Ok(ret)
            }
            UpgradeJob::PrimitiveWitnessToProofCollection {
                primitive_witness: witness,
            } => {
                info!("Proof-upgrader: Start producing proof collection");
                let proof_collection =
                    ProofCollection::produce(&witness, triton_vm_job_queue, priority).await?;
                info!("Proof-upgrader: Done");
                Ok(Transaction {
                    kernel: witness.kernel,
                    proof: TransactionProof::ProofCollection(proof_collection),
                })
            }
            UpgradeJob::PrimitiveWitnessToSingleProof {
                primitive_witness: witness,
            } => {
                info!("Proof-upgrader: Start producing single proof");
                let proof = SingleProof::produce(&witness, triton_vm_job_queue, priority).await?;
                info!("Proof-upgrader: Done");
                Ok(Transaction {
                    kernel: witness.kernel,
                    proof: TransactionProof::SingleProof(proof),
                })
            }
            UpgradeJob::UpdateMutatorSetData(UpdateMutatorSetDataJob {
                old_kernel,
                old_single_proof,
                old_mutator_set,
                mutator_set_update,
            }) => {
                info!("Proof-upgrader: Start update proof");
                let ret = Transaction::new_with_updated_mutator_set_records_given_proof(
                    old_kernel,
                    &old_mutator_set,
                    &mutator_set_update,
                    old_single_proof,
                    triton_vm_job_queue,
                    priority,
                )
                .await?;
                info!("Proof-upgrader: Done");

                Ok(ret)
            }
        }
    }
}

/// Return an [UpgradeJob] that describes work that can be done to upgrade the
/// proof-quality of a transaction found in mempool.
pub(super) fn get_upgrade_task_from_mempool(global_state: &GlobalState) -> Option<UpgradeJob> {
    // Do we have any `ProofCollection`s?
    let tip = global_state.chain.light_state().body();

    if let Some((kernel, proof)) = global_state.mempool.most_dense_proof_collection() {
        let upgrade_decision = UpgradeJob::ProofCollectionToSingleProof {
            kernel: kernel.to_owned(),
            proof: proof.to_owned(),
            mutator_set: tip.mutator_set_accumulator.to_owned(),
        };

        if upgrade_decision.mutator_set().hash() != kernel.mutator_set_hash {
            error!("Deprecated transaction found in mempool. Has ProofCollection in need of updating. Consider clearing mempool.");
            return None;
        }

        return Some(upgrade_decision);
    }

    // Can we merge two single proofs?
    if let Some([(left_kernel, left_single_proof), (right_kernel, right_single_proof)]) =
        global_state.mempool.most_dense_single_proof_pair()
    {
        let mut rng: StdRng = SeedableRng::from_seed(global_state.shuffle_seed());
        let upgrade_decision = UpgradeJob::Merge {
            left_kernel: left_kernel.to_owned(),
            single_proof_left: left_single_proof.to_owned(),
            right_kernel: right_kernel.to_owned(),
            single_proof_right: right_single_proof.to_owned(),
            shuffle_seed: rng.gen(),
            mutator_set: tip.mutator_set_accumulator.to_owned(),
        };

        if left_kernel.mutator_set_hash != right_kernel.mutator_set_hash
            || right_kernel.mutator_set_hash != upgrade_decision.mutator_set().hash()
        {
            error!("Deprecated transaction found in mempool. Has SingleProof in need of updating. Consider clearing mempool.");
            return None;
        }

        return Some(upgrade_decision);
    }

    None
}
