//! This module implements a builder for transaction proofs.
//!
//! There are different levels of [TransactionProof] that
//! can be generated.  The desired proof can be specified with [TransactionProofType].
//!
//! With exception of `TransactionProofType::PrimitiveWitness`, proof generation
//! is a very CPU and RAM intensive process.  Each type of proof has different
//! hardware requirements.  Also the complexity is affected by the type and size
//! of transaction.
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

use std::borrow::Borrow;
use std::borrow::Cow;
use std::sync::Arc;

use super::proof_builder::ProofBuilder;
use crate::api::export::NeptuneProof;
use crate::api::tx_initiation::error::CreateProofError;
use crate::api::tx_initiation::error::ProofRequirement;
use crate::application::triton_vm_job_queue::vm_job_queue;
use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::transaction_proof::TransactionProofType;
use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;
use crate::protocol::consensus::transaction::validity::single_proof::produce_single_proof;
use crate::protocol::consensus::transaction::validity::single_proof::produce_single_proof_mock;
use crate::protocol::consensus::transaction::validity::single_proof::SingleProof;
use crate::protocol::consensus::transaction::validity::single_proof::SingleProofWitness;
use crate::protocol::consensus::transaction::validity::tasm::single_proof::update_branch::UpdateWitness;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::protocol::proof_abstractions::SecretWitness;
use crate::state::transaction::transaction_details::TransactionDetails;
use crate::triton_vm::proof::Claim;
use crate::triton_vm::vm::NonDeterminism;

/// a builder for [TransactionProof]
///
/// see [module docs](self) for details.
#[derive(Debug, Default)]
pub struct TransactionProofBuilder<'a> {
    // these 3 types apply to any TransactionProofType
    transaction_details: Option<&'a TransactionDetails>,
    primitive_witness: Option<PrimitiveWitness>,
    primitive_witness_ref: Option<&'a PrimitiveWitness>,

    // these 4 types apply only to SingleProof
    proof_collection: Option<ProofCollection>,
    update_witness: Option<&'a UpdateWitness>,
    claim_and_nondeterminism: Option<(Claim, NonDeterminism)>,

    /// Determines which set of consensus rules apply. Typically inferred from
    /// network and block height.
    consensus_rule_set: Option<ConsensusRuleSet>,

    job_queue: Option<Arc<TritonVmJobQueue>>,

    // Required
    proof_job_options: Option<TritonVmProofJobOptions>,
    valid_mock: Option<bool>,
}

impl<'a> TransactionProofBuilder<'a> {
    /// instantiate
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    /// add transaction details (optional)
    pub fn transaction_details(mut self, transaction_details: &'a TransactionDetails) -> Self {
        self.transaction_details = Some(transaction_details);
        self
    }

    /// add primitive witness (optional)
    ///
    /// Note that a `PrimitiveWitness` contains a `TransactionKernel` which is a
    /// field of `Transaction`.  Thus when generating a transaction it can avoid
    /// duplicate work to generate a witness, clone the kernel, provide the
    /// witness here, and then provide the kernel to the `TransactionBuilder`.
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

    /// add proof collection (optional)
    ///
    /// only used for building single-proof
    pub fn proof_collection(mut self, proof_collection: ProofCollection) -> Self {
        self.proof_collection = Some(proof_collection);
        self
    }

    /// add update witness (optional)
    ///
    /// only used for building single-proof
    pub fn update_witness(mut self, update_witness: &'a UpdateWitness) -> Self {
        self.update_witness = Some(update_witness);
        self
    }

    /// add claim and non-determinism (optional)
    ///
    /// only used for building single-proof
    pub fn claim_and_nondeterminism(
        mut self,
        claim_and_nondeterminism: (Claim, NonDeterminism),
    ) -> Self {
        self.claim_and_nondeterminism = Some(claim_and_nondeterminism);
        self
    }

    /// Add a [`ConsensusRuleSet`] (optional)
    pub fn consensus_rule_set(mut self, consensus_rule_set: ConsensusRuleSet) -> Self {
        self.consensus_rule_set = Some(consensus_rule_set);
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
    /// valid mock proofs pass proof verification; invalid mock proofs do not.
    ///
    /// see [NeptuneProof]
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
    /// ## Required (one-of)
    ///
    /// The following are individually optional, but at least one must be
    /// provided, else an error will result. (ProofRequirement::TransactionProofInput)
    ///
    /// * transaction_details()
    /// * primitive_witness()
    /// * primitive_witness_ref()
    /// * proof_collection()
    /// * update_witness()
    /// * claim_and_nondeterminism()
    ///
    /// ## Evaluation
    ///
    /// if the network uses mock proofs (eg Network::RegTest), this will return
    /// immediately with a mock `TransactionProof`.
    ///
    /// if the target proof-type is Witness, this will return immediately.
    ///
    /// otherwise it will initiate an async job that could take many minutes.
    ///
    /// The provided inputs are evaluated in the following order, which
    /// generally is in order of most to least efficient. Evaluation ends at the
    /// first match in these lists:
    ///
    /// if target proof_type is SingleProof:
    /// * claim_and_nondeterminism()
    /// * update_witness()
    /// * proof_collection()
    /// * primitive_witness()
    /// * primitive_witness_ref()
    /// * transaction_details()
    ///
    /// for any other proof type:
    /// * primitive_witness()
    /// * primitive_witness_ref()
    /// * transaction_details()
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
    /// ## RegTest mode
    ///
    /// mock proofs are used on the regtest network (only) because they can be
    /// generated instantly.
    ///
    /// ## External Process
    ///
    /// Proofs are generated in the Triton VM. The proof generation occurs in a
    /// separate executable, `triton-vm-prover`, which is spawned by the
    /// job-queue for each proving job.  Only one `triton-vm-prover` process
    /// should be executing at a time for a given neptune-core instance.
    ///
    /// If the external process is killed for any reason, the proof-generation job will fail
    /// and this method will return an error.
    ///
    /// ## Cancellation
    ///
    /// See [TritonVmProofJobOptions::cancel_job_rx].
    ///
    /// note that cancelling the future returned by build() will NOT cancel the
    /// job in the job-queue, as that runs in a separately spawned tokio task
    /// managed by the job-queue.
    pub async fn build(self) -> Result<TransactionProof, CreateProofError> {
        let TransactionProofBuilder {
            transaction_details,
            primitive_witness,
            primitive_witness_ref,
            claim_and_nondeterminism,
            update_witness,
            proof_collection,
            consensus_rule_set,
            job_queue,
            proof_job_options,
            valid_mock,
        } = self;

        let proof_job_options = proof_job_options.ok_or(ProofRequirement::ProofJobOptions)?;

        let valid_mock = valid_mock.unwrap_or(true);
        let job_queue = job_queue.unwrap_or_else(vm_job_queue);

        // note: evaluation order must match order stated in the method doc-comment.

        if proof_job_options.job_settings.proof_type.is_single_proof() {
            #[expect(unused_variables, reason = "anticipate future fork")]
            let consensus_rule_set =
                consensus_rule_set.ok_or(ProofRequirement::ConsensusRuleSet)?;

            // claim, nondeterminism --> single proof
            if let Some((c, nd)) = claim_and_nondeterminism {
                return gen_single(c, || nd, job_queue, proof_job_options, valid_mock).await;
            }
            // update-witness --> single proof
            else if let Some(w) = update_witness {
                let spw = SingleProofWitness::from_update(w.clone());
                let c = spw.claim();
                let nd = spw.nondeterminism();
                return gen_single(c, || nd, job_queue, proof_job_options, valid_mock).await;
            }
            // proof-collection --> single proof
            else if let Some(pc) = proof_collection {
                let spw = SingleProofWitness::from_collection(pc);
                let c = spw.claim();
                let nd = spw.nondeterminism();
                return gen_single(c, || nd, job_queue, proof_job_options, valid_mock).await;
            }
        }

        // In this case, we **have** to be able to construct a primitive
        // witness, otherwise we're missing witness data.
        // Collapse {PrimitiveWitness (reference or not), TransactionDetails}
        // into PrimitiveWitness.
        let primitive_witness = if let Some(pw) = primitive_witness {
            Cow::Owned(pw)
        } else if let Some(pw_ref) = primitive_witness_ref {
            Cow::Borrowed(pw_ref)
        } else {
            // must have transaction details if no primitive witness.
            let transaction_details =
                transaction_details.ok_or(ProofRequirement::TransactionProofInput)?;
            Cow::Owned(transaction_details.primitive_witness())
        };

        // PrimitiveWitness -> single proof
        match proof_job_options.job_settings.proof_type {
            TransactionProofType::PrimitiveWitness => {
                Ok(TransactionProof::Witness(primitive_witness.into_owned()))
            }
            TransactionProofType::ProofCollection => {
                let pc = proof_collection_from_witness(
                    primitive_witness,
                    job_queue,
                    proof_job_options,
                    valid_mock,
                )
                .await?;
                Ok(TransactionProof::ProofCollection(pc))
            }
            TransactionProofType::SingleProof => {
                let consensus_rule_set =
                    consensus_rule_set.ok_or(ProofRequirement::ConsensusRuleSet)?;
                let sp = single_proof_from_witness(
                    primitive_witness,
                    job_queue,
                    proof_job_options,
                    valid_mock,
                    consensus_rule_set,
                )
                .await?;
                Ok(TransactionProof::SingleProof(sp))
            }
        }
    }
}

// builds TransactionProof::SingleProof from Claim, NonDeterminism
//
// will generate a mock proof if Network::use_mock_proof() is true.
async fn gen_single<'a, F>(
    claim: Claim,
    nondeterminism: F,
    job_queue: Arc<TritonVmJobQueue>,
    proof_job_options: TritonVmProofJobOptions,
    valid_mock: bool,
) -> Result<TransactionProof, CreateProofError>
where
    F: FnOnce() -> NonDeterminism + Send + Sync + 'a,
{
    Ok(TransactionProof::SingleProof(
        ProofBuilder::new()
            .program(SingleProof.program())
            .claim(claim)
            .nondeterminism(nondeterminism)
            .job_queue(job_queue)
            .proof_job_options(proof_job_options)
            .valid_mock(valid_mock)
            .build()
            .await?,
    ))
}

/// Builds a [`TransactionProof::ProofCollection`] from `Cow<PrimitiveWitness>`
///
/// will generate a mock proof if Network::use_mock_proof() is true.
///
/// # Panics
///
///  - If `proof_job_options.job_settings.proof_type
///           != TransactionProofType::ProofCollection`
async fn proof_collection_from_witness(
    witness_cow: Cow<'_, PrimitiveWitness>,
    job_queue: Arc<TritonVmJobQueue>,
    proof_job_options: TritonVmProofJobOptions,
    valid_mock: bool,
) -> Result<ProofCollection, CreateProofError> {
    let proof_type = TransactionProofType::ProofCollection;
    assert_eq!(proof_type, proof_job_options.job_settings.proof_type);

    // generate mock proof, if network uses mock proofs.
    if proof_job_options.job_settings.network.use_mock_proof() {
        let pc = ProofCollection::produce_mock(witness_cow.borrow(), valid_mock);
        return Ok(pc);
    }

    // abort early if machine is too weak
    let capability = proof_job_options.job_settings.tx_proving_capability;
    if !capability.can_prove(proof_type) {
        return Err(CreateProofError::TooWeak {
            proof_type,
            capability,
        });
    }

    let pc = ProofCollection::produce(witness_cow.borrow(), job_queue, proof_job_options).await?;

    Ok(pc)
}

/// builds [`TransactionProof::SingleProof`] from `Cow<PrimitiveWitness>`
///
/// will generate a mock proof if Network::use_mock_proof() is true.
///
/// # Panics
///
///  - If `proof_job_options.job_settings.proof_type
///           != TransactionProofType::SingleProof`
async fn single_proof_from_witness(
    witness_cow: Cow<'_, PrimitiveWitness>,
    job_queue: Arc<TritonVmJobQueue>,
    proof_job_options: TritonVmProofJobOptions,
    valid_mock: bool,
    consensus_rule_set: ConsensusRuleSet,
) -> Result<NeptuneProof, CreateProofError> {
    let single_proof_type = TransactionProofType::SingleProof;
    assert_eq!(single_proof_type, proof_job_options.job_settings.proof_type);

    // generate mock proof, if network uses mock proofs.
    if proof_job_options.job_settings.network.use_mock_proof() {
        let sp = produce_single_proof_mock(valid_mock);
        return Ok(sp);
    }

    // abort early if machine is too weak
    let capability = proof_job_options.job_settings.tx_proving_capability;
    if !capability.can_prove(single_proof_type) {
        return Err(CreateProofError::TooWeak {
            proof_type: single_proof_type,
            capability,
        });
    }

    // produce proof of requested type
    let sp = produce_single_proof(
        witness_cow.borrow(),
        job_queue,
        proof_job_options,
        consensus_rule_set,
    )
    .await?;

    Ok(sp)
}
