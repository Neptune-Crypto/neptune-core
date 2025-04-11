//! This module implements a builder for neptune proofs
//!
//! A neptune proof is a mockable triton-vm proof.
use std::sync::Arc;

use crate::api::tx_initiation::error::CreateProofError;
use crate::job_queue::triton_vm::vm_job_queue;
use crate::job_queue::triton_vm::TritonVmJobQueue;
use crate::models::blockchain::transaction::transaction_proof::TransactionProofType;
use crate::models::blockchain::transaction::validity::neptune_proof::Proof;
use crate::models::proof_abstractions::tasm::program::prove_consensus_program;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::models::state::tx_proving_capability::TxProvingCapability;
use crate::triton_vm::prelude::Program;
use crate::triton_vm::proof::Claim;
use crate::triton_vm::vm::NonDeterminism;

/// a builder for [Proof]
///
/// see [module docs](self) for details.
#[derive(Debug, Default)]
pub struct ProofBuilder {
    program: Option<Program>,
    claim: Option<Claim>,
    nondeterminism: Option<NonDeterminism>,
    job_queue: Option<Arc<TritonVmJobQueue>>,
    proof_job_options: Option<TritonVmProofJobOptions>,
    tx_proving_capability: Option<TxProvingCapability>,
    proof_type: Option<TransactionProofType>,
    valid_mock: Option<bool>,
}

impl ProofBuilder {
    /// instantiate
    pub fn new() -> Self {
        Default::default()
    }

    /// add program (required)
    pub fn program(mut self, program: Program) -> Self {
        self.program = Some(program);
        self
    }

    /// add claim (required)
    pub fn claim(mut self, claim: Claim) -> Self {
        self.claim = Some(claim);
        self
    }

    /// add nondeterminism (required)
    pub fn nondeterminism(mut self, nondeterminism: NonDeterminism) -> Self {
        self.nondeterminism = Some(nondeterminism);
        self
    }

    /// add job queue (optional)
    ///
    /// if not provided then the process-wide [vm_job_queue()] will be used.
    pub fn job_queue(mut self, job_queue: Arc<TritonVmJobQueue>) -> Self {
        self.job_queue = Some(job_queue);
        self
    }

    /// add job options. (required)
    ///
    /// note: can be obtained via `TritonVmProofJobOptions::from(Args)`
    pub fn proof_job_options(mut self, proof_job_options: TritonVmProofJobOptions) -> Self {
        self.proof_job_options = Some(proof_job_options);
        self
    }

    /// specify the machine's proving capability.  (optional)
    ///
    /// if present, this will override the value in `ProverJobSettings` which is
    /// part of [TritonVmProofJobOptions]
    pub fn proving_capability(mut self, tx_proving_capability: TxProvingCapability) -> Self {
        self.tx_proving_capability = Some(tx_proving_capability);
        self
    }

    /// specify the target proof type.  (optional)
    ///
    /// if present, this will override the value in `ProverJobSettings` which is
    /// part of [TritonVmProofJobOptions]
    ///
    /// if the type is not single-proof or proof-collection an error will result
    /// when building.
    pub fn proof_type(mut self, proof_type: TransactionProofType) -> Self {
        self.proof_type = Some(proof_type);
        self
    }

    /// create valid or invalid mock proof. (optional)
    ///
    /// default = true
    ///
    /// only applies if the network uses mock proofs, eg regtest.
    ///
    /// does not apply to TransactionProof::PrimitiveWitness
    pub fn valid_mock(mut self, valid_mock: bool) -> Self {
        self.valid_mock = Some(valid_mock);
        self
    }

    /// generate the proof.
    ///
    /// if the network uses mock proofs (eg Network::RegTest), this will return
    /// immediately with a mock [Proof].
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
    /// See [TritonVmProofJobOptions::cancel_job_rx].
    ///
    /// note that cancelling the future returned by build() will NOT cancel the
    /// job in the job-queue, as that runs in a separately spawned tokio task
    /// managed by the job-queue.
    pub async fn build(self) -> Result<Proof, CreateProofError> {
        let Self {
            program,
            claim,
            nondeterminism,
            job_queue,
            proof_job_options,
            valid_mock,
            tx_proving_capability,
            proof_type,
        } = self;

        let (Some(program), Some(claim), Some(nondeterminism)) = (program, claim, nondeterminism)
        else {
            return Err(CreateProofError::MissingRequirement);
        };

        let proof_job_options = match proof_job_options {
            Some(mut pjo) => {
                // if tx_proving_capability is provided, it overrides value in job_settings
                if let Some(tx_proving_capability) = tx_proving_capability {
                    pjo.job_settings.tx_proving_capability = tx_proving_capability;
                }
                // if proof_type is provided, it overrides value in job_settings
                if let Some(proof_type) = proof_type {
                    pjo.job_settings.proof_type = proof_type;
                }
                pjo
            }
            None => return Err(CreateProofError::MissingRequirement),
        };

        if proof_job_options.job_settings.network.use_mock_proof() {
            let proof = Proof::mock(valid_mock.unwrap_or(true));
            return Ok(proof);
        }

        #[allow(clippy::shadow_unrelated)]
        let proof_type = proof_job_options.job_settings.proof_type;
        let capability = proof_job_options.job_settings.tx_proving_capability;
        if !capability.can_prove(proof_type) {
            return Err(CreateProofError::TooWeak {
                proof_type,
                capability,
            });
        }
        // this builder only supports proofs that can be executed in triton-vm.
        if !proof_type.is_vm_proof() {
            return Err(CreateProofError::NotVmProof(proof_type));
        }

        let job_queue = job_queue.unwrap_or_else(vm_job_queue);

        Ok(
            prove_consensus_program(program, claim, nondeterminism, job_queue, proof_job_options)
                .await?,
        )
    }
}
