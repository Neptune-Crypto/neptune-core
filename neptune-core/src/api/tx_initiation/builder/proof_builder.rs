//! This module implements a builder for neptune proofs
//!
//! A neptune proof is a mockable triton-vm proof.
use std::fmt;
use std::sync::Arc;

use crate::api::tx_initiation::error::CreateProofError;
use crate::api::tx_initiation::error::ProofRequirement;
use crate::application::triton_vm_job_queue::vm_job_queue;
use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
use crate::protocol::proof_abstractions::tasm::program::prove_consensus_program;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::triton_vm::prelude::Program;
use crate::triton_vm::proof::Claim;
use crate::triton_vm::vm::NonDeterminism;

/// a builder for [Proof]
///
/// Facilitates building a proof directly from a triton-vm program, a claim, and
/// nondeterminism.
///
/// This is a lower level builder than `TransactionProofBuilder` which should
/// typically be used when initiating transactions.
///
/// Example:
///
/// ```
/// use neptune_cash::api::export::NeptuneProof;
/// use neptune_cash::api::export::GlobalStateLock;
/// use neptune_cash::api::export::Program;
/// use neptune_cash::api::export::Claim;
/// use neptune_cash::api::export::NonDeterminism;
/// use neptune_cash::api::tx_initiation::builder::proof_builder::ProofBuilder;
/// use neptune_cash::api::tx_initiation::error::CreateProofError;
/// use neptune_cash::application::triton_vm_job_queue::vm_job_queue;
///
/// async fn prove_claim(program: Program, claim: Claim, nondeterminism: NonDeterminism, gsl: &GlobalStateLock) -> Result<NeptuneProof, CreateProofError> {
///
///     // generate a proof
///     ProofBuilder::new()
///         .program(program)
///         .claim(claim)
///         .nondeterminism(|| nondeterminism)
///         .job_queue(vm_job_queue())
///         .proof_job_options(gsl.cli().into())
///         .build()
///         .await
/// }
/// ```
#[derive(Default)]
pub struct ProofBuilder<'a> {
    program: Option<Program>,
    claim: Option<Claim>,
    nondeterminism_callback: Option<Box<dyn FnOnce() -> NonDeterminism + Send + Sync + 'a>>,
    job_queue: Option<Arc<TritonVmJobQueue>>,
    proof_job_options: Option<TritonVmProofJobOptions>,
    valid_mock: Option<bool>,
}

impl fmt::Debug for ProofBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProofBuilder")
            .field("program", &self.program)
            .field("claim", &self.claim)
            // skip nondeterminism_callback
            .field("job_queue", &self.job_queue)
            .field("proof_job_options", &self.proof_job_options)
            .field("valid_mock", &self.valid_mock)
            .finish()
    }
}

impl<'a> ProofBuilder<'a> {
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

    /// add nondeterminism via callback or closure (required)
    ///
    /// when build() is called, the builder will invoke the callback for real
    /// proofs but not for mock proofs.
    pub fn nondeterminism<F>(mut self, callback: F) -> Self
    where
        F: FnOnce() -> NonDeterminism + Send + Sync + 'a,
    {
        self.nondeterminism_callback = Some(Box::new(callback));
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
    ///
    /// There is also `TritonVmProofJobOptionsBuilder`
    pub fn proof_job_options(mut self, proof_job_options: TritonVmProofJobOptions) -> Self {
        self.proof_job_options = Some(proof_job_options);
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
            nondeterminism_callback,
            job_queue,
            proof_job_options,
            valid_mock,
        } = self;

        let program = program.ok_or(ProofRequirement::Program)?;
        let claim = claim.ok_or(ProofRequirement::Claim)?;
        let nondeterminism_callback =
            nondeterminism_callback.ok_or(ProofRequirement::NonDeterminism)?;
        let proof_job_options = proof_job_options.ok_or(ProofRequirement::ProofJobOptions)?;

        if proof_job_options.job_settings.network.use_mock_proof() {
            let proof = Proof::mock(valid_mock.unwrap_or(true));
            return Ok(proof);
        }

        // non-determinism cannot reliably be obtained for mock proofs, so
        // we invoke a callback to obtain it here only once certain we are
        // building a real proof.
        let nondeterminism = nondeterminism_callback();

        let proof_type = proof_job_options.job_settings.proof_type;
        let capability = proof_job_options.job_settings.tx_proving_capability;
        if !capability.can_prove(proof_type) {
            return Err(CreateProofError::TooWeak {
                proof_type,
                capability,
            });
        }
        // this builder only supports proofs that can be executed in triton-vm.
        if !proof_type.executes_in_vm() {
            return Err(CreateProofError::NotVmProof(proof_type));
        }

        let job_queue = job_queue.unwrap_or_else(vm_job_queue);

        prove_consensus_program(program, claim, nondeterminism, job_queue, proof_job_options).await
    }
}
