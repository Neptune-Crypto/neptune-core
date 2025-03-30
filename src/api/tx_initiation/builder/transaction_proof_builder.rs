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
//! If the caller has a powerful enough machine, they can generate
//! a ProofCollection or SingleProof themself before passing the transaction
//! to neptune-core.  This takes load off the entire network and may
//! lower the caller's fee.
//!
//! see [Caller Provides Proof Initiation Sequence](super::super#caller-provides-proof-initiation-sequence)
//!
//! see [builder](super) for examples of using the builders together.

use std::sync::Arc;

use crate::job_queue::triton_vm::TritonVmJobQueue;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::transaction_proof::TransactionProofType;
use crate::models::blockchain::transaction::validity::proof_collection::ProofCollection;
use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::tx_proving_capability::TxProvingCapability;
use crate::api::tx_initiation::error::CreateProofError;

/// a builder for [TransactionProof]
///
/// see [module docs](self) for details.
#[derive(Debug, Default)]
pub struct TransactionProofBuilder {
    transaction_details: Option<Arc<TransactionDetails>>,
    job_queue: Option<Arc<TritonVmJobQueue>>,
    proof_job_options: TritonVmProofJobOptions,
    tx_proving_capability: TxProvingCapability,
    proof_type: Option<TransactionProofType>,
}

impl TransactionProofBuilder {
    /// instantiate
    pub fn new() -> Self {
        Default::default()
    }

    /// add transaction details (required)
    pub fn transaction_details(mut self, transaction_details: Arc<TransactionDetails>) -> Self {
        self.transaction_details = Some(transaction_details);
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

    /// generate the proof.
    ///
    /// if the target proof-type is Witness, this will return immediately.
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
    /// The caller can query the job_queue to determine how many jobs are in the
    /// queue.
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
        let (Some(tx_details), Some(job_queue)) = (self.transaction_details, self.job_queue) else {
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

        let primitive_witness = PrimitiveWitness::from_transaction_details(&tx_details);

        let transaction_proof = match proof_type {
            TransactionProofType::PrimitiveWitness => TransactionProof::Witness(primitive_witness),
            TransactionProofType::ProofCollection => TransactionProof::ProofCollection(
                ProofCollection::produce(&primitive_witness, job_queue, proof_job_options).await?,
            ),
            TransactionProofType::SingleProof => TransactionProof::SingleProof(
                SingleProof::produce(&primitive_witness, job_queue, proof_job_options).await?,
            ),
        };

        Ok(transaction_proof)
    }
}
