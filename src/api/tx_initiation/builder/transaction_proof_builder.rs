//! This module implements a builder for transaction proofs.
//!
//! There are different levels of [TransactionProof] that
//! can be generated.  The desired proof can be specified with [TransactionProofType].
//!
//! With exception of `TransactionProofType::PrimitiveWitness`, proof generation is a very CPU and RAM intensive process.  Each type
//! of proof has different hardware requirements.  Also the complexity is
//! affected by the type and size of transaction.
//!
//! It is necessary to inform the builder of the device's [TxProvingCapability]
//! so that weak devices will not attempt to build proofs they are not capable of.
//!
//! Before a transaction can be confirmed in a block it must have a SingleProof
//! which is the hardest proof to generate.
//!
//! see [Transaction Initiation Sequence](super::super#transaction-initiation-sequence)
//!
//! If you have a powerful enough machine, you can generate a ProofCollection or
//! SingleProof yourself before passing the transaction to neptune-core.  This
//! takes load off the entire network and may lower the transaction fee
//! requirements.
//!
//! see [Client Provides Proof Initiation Sequence](super::super#client-provides-proof-initiation-sequence)
//!
//! see [builder](super) for examples of using the builders together.

use std::sync::Arc;

use crate::api::tx_initiation::error::CreateProofError;
use crate::config_models::network::Network;
use crate::job_queue::triton_vm::TritonVmJobQueue;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::transaction_proof::TransactionProofType;
use crate::models::blockchain::transaction::validity::proof_collection::ProofCollection;
use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::models::proof_abstractions::verifier::cache_true_claim;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::tx_proving_capability::TxProvingCapability;
use crate::triton_vm::proof::Proof;

/// a builder for [TransactionProof]
///
/// see [module docs](self) for details.
#[derive(Debug, Default)]
pub struct TransactionProofBuilder<'a> {
    transaction_details: Option<&'a TransactionDetails>,
    primitive_witness: Option<PrimitiveWitness>,
    primitive_witness_ref: Option<&'a PrimitiveWitness>,
    job_queue: Option<Arc<TritonVmJobQueue>>,
    proof_job_options: TritonVmProofJobOptions,
    tx_proving_capability: TxProvingCapability,
    proof_type: Option<TransactionProofType>,
    network: Option<Network>,
}

impl<'a> TransactionProofBuilder<'a> {
    /// instantiate
    pub fn new() -> Self {
        Default::default()
    }

    /// add transaction details (required)
    pub fn transaction_details(mut self, transaction_details: &'a TransactionDetails) -> Self {
        self.transaction_details = Some(transaction_details);
        self
    }

    /// add primitive witness (optional)
    ///
    /// If not provided, the builder will generate a `PrimitiveWitness` from the
    /// `TransactionDetails`.
    ///
    /// Note that a `PrimitiveWitness` contais a `TransactionKernel` which is
    /// an input to a `Transaction`.  Thus when generating a transaction
    /// it can avoid duplicate work to generate a witness, clone the kernel,
    /// provide the witness here, and then provide the kernel to the
    /// `TransactionBuilder`.
    ///
    /// It is also possible and may be more convenient to work only with
    /// `TransactionDetails`.
    pub fn primitive_witness(mut self, witness: PrimitiveWitness) -> Self {
        self.primitive_witness = Some(witness);
        self
    }

    /// add transaction details reference (optional)
    ///
    /// Note that if the target proof-type is `PrimitiveWitness` then the
    /// reference will be cloned when building and it may be better to use the
    /// `primitive_witness()` method.
    pub fn primitive_witness_ref(mut self, witness: &'a PrimitiveWitness) -> Self {
        self.primitive_witness_ref = Some(witness);
        self
    }

    /// add job queue (required)
    pub fn job_queue(mut self, job_queue: Arc<TritonVmJobQueue>) -> Self {
        self.job_queue = Some(job_queue);
        self
    }

    /// add job options. (optional)
    pub fn proof_job_options(mut self, proof_job_options: TritonVmProofJobOptions) -> Self {
        self.proof_job_options = proof_job_options;
        self
    }

    /// specify the target proof type.  (optional)
    ///
    /// if not specified, then builder attempts to generate the
    /// best proof the device is capable of, as specified by
    /// tx_proving_capability().
    pub fn proof_type(mut self, proof_type: TransactionProofType) -> Self {
        self.proof_type = Some(proof_type);
        self
    }

    /// specify the device's proving capability.  (optional)
    pub fn tx_proving_capability(mut self, tx_proving_capability: TxProvingCapability) -> Self {
        self.tx_proving_capability = tx_proving_capability;
        self
    }

    /// add network (required)
    pub fn network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    /// generate the proof.
    ///
    /// if the target proof-type is Witness, this will return immediately.
    ///
    /// if the network is [Network::RegTest], this will return immediately with
    /// a mock SingleProof.
    ///
    /// otherwise it will initiate an async job that could take many minutes.
    ///
    /// note that these jobs occur in a global (per process) job queue that only
    /// permits one VM job to process at a time.  This prevents parallel jobs
    /// from bringing the machine to its knees when each is using all available
    /// CPU cores and RAM.
    ///
    /// Given the serialized nature of the job-queue, it is possible or even likely
    /// that other jobs may precede this one.
    ///
    /// One can query the job_queue to determine how many jobs are in the queue.
    ///
    /// RegTest mode:
    ///
    /// mock proofs are used on the regtest network (only) because
    /// they can be generated instantly.
    ///
    /// When network is RegTest, these options are ignored by the builder:
    /// * proof_type(),
    /// * tx_proving_capability()
    /// * proof_job_options()
    /// * job_queue()
    ///
    /// External Process:
    ///
    /// Proofs are generated in the Triton VM. The proof generation occurs in a
    /// separate executable, `triton-vm-prover`, which is spawned by the
    /// job-queue for each proving job.  Only one `triton-vm-prover` process
    /// should be executing at a time for a given neptune-core instance.
    ///
    /// If the external process is killed for any reason, the proof-generation job will fail
    /// and this method will return an error.
    ///
    /// Cancellation:
    ///
    /// note that cancelling the future returned by build() will NOT cancel the
    /// job in the job-queue, as that runs in a separately spawned tokio task
    /// managed by the job-queue.
    ///
    /// Although the job-queue provides a method for cancelling jobs, this builder
    /// does not presently expose it.  As such, there is no way to cancel a job
    /// once build() is called.  That funtionality may be exposed later.
    pub async fn build(self) -> Result<TransactionProof, CreateProofError> {
        let (Some(tx_details), Some(network)) = (self.transaction_details, self.network) else {
            return Err(CreateProofError::MissingRequirement);
        };

        if network.is_regtest() {
            return Ok(Self::build_mock_proof(tx_details).await);
        }

        let Some(job_queue) = self.job_queue else {
            return Err(CreateProofError::MissingRequirement);
        };

        let TransactionProofBuilder {
            proof_job_options,
            proof_type,
            tx_proving_capability,
            ..
        } = self;

        // if proof_type is not provided, then we default to the max we are
        // capable of.
        let proof_type = proof_type.unwrap_or(tx_proving_capability.into());

        if !tx_proving_capability.can_prove(proof_type) {
            return Err(CreateProofError::TooWeak);
        }

        let transaction_proof = match proof_type {
            TransactionProofType::PrimitiveWitness => {
                // use primitive_witness, else primitive_witness_ref, else tx_details
                let witness = self.primitive_witness.unwrap_or_else(|| {
                    self.primitive_witness_ref
                        .cloned()
                        .unwrap_or_else(|| tx_details.into())
                });
                TransactionProof::Witness(witness)
            }
            TransactionProofType::ProofCollection => {
                TransactionProof::ProofCollection(match self.primitive_witness_ref {
                    Some(witness) => {
                        ProofCollection::produce(witness, job_queue, proof_job_options).await?
                    }
                    None => {
                        let witness = self.primitive_witness.unwrap_or_else(|| tx_details.into());
                        ProofCollection::produce(&witness, job_queue, proof_job_options).await?
                    }
                })
            }
            TransactionProofType::SingleProof => {
                TransactionProof::SingleProof(match self.primitive_witness_ref {
                    Some(witness) => {
                        SingleProof::produce(witness, job_queue, proof_job_options).await?
                    }
                    None => {
                        let witness = self.primitive_witness.unwrap_or_else(|| tx_details.into());
                        SingleProof::produce(&witness, job_queue, proof_job_options).await?
                    }
                })
            }
        };

        Ok(transaction_proof)
    }

    async fn build_mock_proof(tx_details: &TransactionDetails) -> TransactionProof {
        let kernel = PrimitiveWitness::from_transaction_details(tx_details).kernel;
        let claim = SingleProof::claim(kernel.mast_hash());
        cache_true_claim(claim.clone()).await;
        TransactionProof::SingleProof(Proof(vec![]))
    }
}
