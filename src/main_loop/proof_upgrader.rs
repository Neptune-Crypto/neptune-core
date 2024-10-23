use std::time::SystemTime;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use tasm_lib::triton_vm::proof::Proof;
use tokio::sync::TryLockError;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::validity::proof_collection::ProofCollection;
use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
use crate::models::blockchain::transaction::validity::single_proof::SingleProofWitness;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::tasm::program::TritonProverSync;
use crate::models::proof_abstractions::SecretWitness;
use crate::models::state::transaction_kernel_id::TransactionKernelId;
use crate::models::state::GlobalState;
use crate::models::state::GlobalStateLock;
use crate::MainToPeerTask;

pub(super) enum UpgradeDecision {
    ProduceSingleProof {
        kernel: TransactionKernel,
        proof: ProofCollection,
    },
    Merge {
        left_kernel: TransactionKernel,
        single_proof_left: Proof,
        right_kernel: TransactionKernel,
        single_proof_right: Proof,
        shuffle_seed: [u8; 32],
    },
}

impl UpgradeDecision {
    /// Return a list of the transaction IDs that will have their proofs
    /// upgraded with this decision.
    ///
    /// Will return a list of length one in case of a
    /// ProofCollection -> SingleProof upgrade and a list of length two in case
    /// of a (SingleProof, SingleProof) -> SingleProof merge upgrade.
    pub(super) fn affected_txids(&self) -> Vec<TransactionKernelId> {
        match self {
            UpgradeDecision::ProduceSingleProof { kernel, proof: _ } => vec![kernel.txid()],
            UpgradeDecision::Merge {
                left_kernel,
                single_proof_left: _,
                right_kernel,
                single_proof_right: _,
                shuffle_seed: _,
            } => vec![left_kernel.txid(), right_kernel.txid()],
        }
    }

    /// Upgrade transaction proofs, inserts upgraded tx into the mempool and
    /// informs peers of this new transaction.
    pub(super) async fn handle_upgrade(
        self,
        priority: TritonProverSync,
        mut global_state_lock: GlobalStateLock,
        main_to_peer_channel: tokio::sync::broadcast::Sender<MainToPeerTask>,
    ) {
        // Record that we're attempting an upgrade.
        global_state_lock
            .lock_guard_mut()
            .await
            .net
            .last_tx_proof_upgrade_attempt = SystemTime::now();

        let upgraded = match self.upgrade(priority).await {
            Ok(upgraded_tx) => {
                info!(
                    "Successfully upgraded transaction {}",
                    upgraded_tx.kernel.txid()
                );
                upgraded_tx
            }
            Err(err) => {
                info!("Failed to upgrade mempool transaction because prover was occupied:\n{err}");
                return;
            }
        };

        // Insert the upgraded transactions into the mempool
        {
            let mut global_state = global_state_lock.lock_guard_mut().await;
            // Did we receive a new block while proving? If so, throw away the
            // result, as it is wasted (it would need an update).

            if upgraded.kernel.mutator_set_hash
                != global_state
                    .chain
                    .light_state()
                    .body()
                    .mutator_set_accumulator
                    .hash()
            {
                warn!("Got new block while proving. Discarding result.");
                return;
            }

            global_state.mempool.insert(&upgraded);
        }

        // Inform all peers about our hard work
        main_to_peer_channel
            .send(MainToPeerTask::TransactionNotification(
                (&upgraded).try_into().unwrap(),
            ))
            .unwrap();

        info!("Successfully handled proof upgrade.");
    }

    /// Perform the proof upgrade.
    ///
    /// Upgrades transactions to a proof of higher quality that is more likely
    /// to be picked up by a miner. Returns the upgraded proof, or an error if
    /// the prover is already in use and the priority is set to not wait if
    /// prover is busy.
    async fn upgrade(self, priority: TritonProverSync) -> Result<Transaction, TryLockError> {
        match self {
            UpgradeDecision::ProduceSingleProof { kernel, proof } => {
                let single_proof_witness = SingleProofWitness::from_collection(proof.to_owned());
                let claim = single_proof_witness.claim();
                let nondeterminism = single_proof_witness.nondeterminism();
                info!("Proof-upgrader: Start generate single proof");
                let single_proof = SingleProof.prove(&claim, nondeterminism, &priority).await?;
                info!("Proof-upgrader: Done");

                Ok(Transaction {
                    kernel: kernel.to_owned(),
                    proof: TransactionProof::SingleProof(single_proof),
                })
            }
            UpgradeDecision::Merge {
                left_kernel,
                single_proof_left,
                right_kernel,
                single_proof_right,
                shuffle_seed,
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
                let ret = Transaction::merge_with(left, right, shuffle_seed.to_owned(), &priority)
                    .await?;
                info!("Proof-upgrader: Done");

                Ok(ret)
            }
        }
    }
}

/// Return an [UpgradeTask] that describes work that can be done to upgrade the
/// proof-quality of a transaction.
pub(super) fn get_transaction_upgrade_task(global_state: &GlobalState) -> Option<UpgradeDecision> {
    // Do we have any `ProofCollection`s?
    if let Some((kernel, proof)) = global_state.mempool.most_dense_proof_collection() {
        let upgrade_decision = UpgradeDecision::ProduceSingleProof {
            kernel: kernel.to_owned(),
            proof: proof.to_owned(),
        };

        return Some(upgrade_decision);
    }

    // Can we merge two single proofs?
    if let Some([(left_kernel, left_single_proof), (right_kernel, right_single_proof)]) =
        global_state.mempool.most_dense_single_proof_pair()
    {
        let mut rng: StdRng = SeedableRng::from_seed(global_state.shuffle_seed());
        let upgrade_decision = UpgradeDecision::Merge {
            left_kernel: left_kernel.to_owned(),
            single_proof_left: left_single_proof.to_owned(),
            right_kernel: right_kernel.to_owned(),
            single_proof_right: right_single_proof.to_owned(),
            shuffle_seed: rng.gen(),
        };

        if left_kernel.mutator_set_hash != right_kernel.mutator_set_hash {
            error!("Deprecated transaction found in mempool. Has SingleProof in need of updating. Consider clearing mempool.");
            return None;
        }

        return Some(upgrade_decision);
    }

    None
}
