use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;

use crate::api::tx_initiation::builder::proof_builder::ProofBuilder;
use crate::api::tx_initiation::error::CreateProofError;
use crate::models::blockchain::consensus_rule_set::ConsensusRuleSet;
use crate::models::blockchain::transaction::merge_version::MergeVersion;
use crate::models::blockchain::transaction::validity::neptune_proof::Proof;
use crate::triton_vm::prelude::*;
use itertools::Itertools;
use tasm_lib::field;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::prelude::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::twenty_first::error::BFieldCodecError;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tracing::info;

use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelField;
use crate::models::blockchain::transaction::validity::tasm::single_proof::merge_branch::MergeBranch;
use crate::models::blockchain::transaction::validity::tasm::single_proof::update_branch::UpdateBranch;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_collect_lock_scripts_claim::GenerateCollectLockScriptsClaim;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_collect_type_scripts_claim::GenerateCollectTypeScriptsClaim;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_k2o_claim::GenerateK2oClaim;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_lock_script_claim_template::GenerateLockScriptClaimTemplate;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_type_script_claim_template::GenerateTypeScriptClaimTemplate;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_rri_claim::GenerateRriClaim;
use crate::models::blockchain::transaction::Claim;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::triton_vm_job_queue::TritonVmJobQueue;
use crate::models::proof_abstractions::SecretWitness;
use crate::BFieldElement;
use crate::models::blockchain::transaction::validity::proof_collection::ProofCollection;

use super::tasm::single_proof::merge_branch::MergeWitness;
use super::tasm::single_proof::update_branch::UpdateWitness;

pub(crate) const DISCRIMINANT_FOR_PROOF_COLLECTION: u64 = 0;
pub(crate) const DISCRIMINANT_FOR_UPDATE: u64 = 1;
pub(crate) const DISCRIMINANT_FOR_MERGE: u64 = 2;

const INVALID_WITNESS_DISCRIMINANT_ERROR: i128 = 1_000_050;
const NO_BRANCH_TAKEN_ERROR: i128 = 1_000_051;
const MANIPULATED_PROOF_COLLECTION_WITNESS_ERROR: i128 = 1_000_052;

#[derive(Debug, Clone, BFieldCodec)]
pub enum SingleProofWitness<const VERSION: usize> {
    Collection(Box<ProofCollection>),
    Update(UpdateWitness),
    Merger(MergeWitness),
    // Wait for Hard Fork One:
    // IntegralMempool(IntegralMempoolMembershipWitness)
}

impl<const VERSION: usize> SingleProofWitness<VERSION> {
    pub fn from_collection(proof_collection: ProofCollection) -> Self {
        Self::Collection(Box::new(proof_collection))
    }

    pub fn from_update(witness: UpdateWitness) -> Self {
        Self::Update(witness)
    }

    pub(crate) fn from_merge(merge_witness: MergeWitness) -> Self {
        Self::Merger(merge_witness)
    }
}

// This implementation of `TasmObject` is required for `decode_iter` and the
// method `decode_from_memory` that relies on it.
impl<const VERSION: usize> TasmObject for SingleProofWitness<VERSION> {
    fn label_friendly_name() -> String {
        "SingleProofWitness".to_string()
    }

    fn compute_size_and_assert_valid_size_indicator(
        _library: &mut Library,
    ) -> Vec<LabelledInstruction> {
        unimplemented!()
    }

    fn decode_iter<Itr: Iterator<Item = BFieldElement>>(
        iterator: &mut Itr,
    ) -> Result<Box<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let discriminant = iterator
            .next()
            .ok_or(Box::new(BFieldCodecError::EmptySequence))?;
        let field_size = iterator
            .next()
            .ok_or(Box::new(BFieldCodecError::SequenceTooShort))?
            .value()
            .try_into()
            .map_err(|_| Box::new(BFieldCodecError::ElementOutOfRange))?;
        let field_data = iterator.take(field_size).collect_vec();

        match discriminant.value() {
            DISCRIMINANT_FOR_PROOF_COLLECTION => Ok(Box::new(Self::Collection(Box::new(
                *BFieldCodec::decode(&field_data)?,
            )))),
            DISCRIMINANT_FOR_UPDATE => {
                Ok(Box::new(Self::Update(*BFieldCodec::decode(&field_data)?)))
            }
            DISCRIMINANT_FOR_MERGE => {
                Ok(Box::new(Self::Merger(*BFieldCodec::decode(&field_data)?)))
            }
            _ => Err(Box::new(BFieldCodecError::ElementOutOfRange)),
        }
    }
}

impl<const VERSION: usize> SecretWitness for SingleProofWitness<VERSION> {
    fn standard_input(&self) -> PublicInput {
        let kernel_mast_hash = match self {
            Self::Collection(pc) => pc.kernel_mast_hash,
            Self::Update(witness) => witness.new_kernel_mast_hash,
            Self::Merger(witness) => witness.new_kernel.mast_hash(),
        };
        kernel_mast_hash.reversed().values().into()
    }

    fn output(&self) -> Vec<BFieldElement> {
        std::vec![]
    }

    fn program(&self) -> Program {
        SingleProof::<VERSION>.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        // populate nondeterministic memory with witness
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self,
        );

        let mut nondeterminism = NonDeterminism::default().with_ram(memory);
        let stark_verify_snippet = StarkVerify::new_with_dynamic_layout(Stark::default());
        let single_proof_program_hash = SingleProof::<VERSION>.hash();

        match self {
            SingleProofWitness::Collection(proof_collection) => {
                nondeterminism
                    .digests
                    .extend_from_slice(&proof_collection.merge_bit_mast_path);

                // removal records integrity
                let rri_claim = proof_collection.removal_records_integrity_claim();
                let rri_proof = &proof_collection.removal_records_integrity;
                stark_verify_snippet.update_nondeterminism(
                    &mut nondeterminism,
                    rri_proof,
                    &rri_claim,
                );

                // kernel to outputs
                let k2o_claim = proof_collection.kernel_to_outputs_claim();
                let k2o_proof = &proof_collection.kernel_to_outputs;
                stark_verify_snippet.update_nondeterminism(
                    &mut nondeterminism,
                    k2o_proof,
                    &k2o_claim,
                );

                // collect lock scripts
                let cls_claim = proof_collection.collect_lock_scripts_claim();
                let cls_proof = &proof_collection.collect_lock_scripts;
                stark_verify_snippet.update_nondeterminism(
                    &mut nondeterminism,
                    cls_proof,
                    &cls_claim,
                );

                // collect type scripts
                let cts_claim = proof_collection.collect_type_scripts_claim();
                let cts_proof = &proof_collection.collect_type_scripts;
                stark_verify_snippet.update_nondeterminism(
                    &mut nondeterminism,
                    cts_proof,
                    &cts_claim,
                );

                // lock scripts
                for (claim, proof) in proof_collection
                    .lock_script_claims()
                    .into_iter()
                    .zip(&proof_collection.lock_scripts_halt)
                {
                    stark_verify_snippet.update_nondeterminism(&mut nondeterminism, proof, &claim);
                }

                // type scripts
                for (claim, proof) in proof_collection
                    .type_script_claims()
                    .into_iter()
                    .zip(&proof_collection.type_scripts_halt)
                {
                    stark_verify_snippet.update_nondeterminism(&mut nondeterminism, proof, &claim);
                }
            }
            SingleProofWitness::Update(witness) => {
                witness.populate_nd_streams(&mut nondeterminism, single_proof_program_hash);
            }
            SingleProofWitness::Merger(witness_of_merge) => {
                witness_of_merge
                    .populate_nd_streams(&mut nondeterminism, single_proof_program_hash);
            }
        }

        nondeterminism
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SingleProof<const VERSION: usize>;

pub type GenesisSingleProof = SingleProof<{ MergeVersion::Genesis as usize }>;
pub type HardFork2SingleProof = SingleProof<{ MergeVersion::HardFork2 as usize }>;

impl<const VERSION: usize> SingleProof<VERSION> {
    /// Not to be confused with SingleProofWitness::claim
    fn claim(tx_kernel_mast_hash: Digest) -> Claim {
        Claim::about_program(&SingleProof::<VERSION>.program())
            .with_input(tx_kernel_mast_hash.reversed().values())
    }

    /// Generate a [SingleProof] for the transaction, given its primitive
    /// witness.
    ///
    /// This involves generating a [ProofCollection] as an intermediate step.
    ///
    /// Use [produce_single_proof] to automatically select the right merge
    /// version.
    async fn produce(
        primitive_witness: &PrimitiveWitness,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
    ) -> Result<Proof, CreateProofError> {
        let proof_collection = ProofCollection::produce(
            primitive_witness,
            triton_vm_job_queue.clone(),
            proof_job_options.clone(),
        )
        .await?;
        let single_proof_witness = SingleProofWitness::<VERSION>::from_collection(proof_collection);
        let claim = single_proof_witness.claim();

        let nondeterminism = single_proof_witness.nondeterminism();
        info!("Start: generate single proof from proof collection");

        let proof = ProofBuilder::new()
            .program(SingleProof::<VERSION>.program())
            .claim(claim)
            .nondeterminism(|| nondeterminism)
            .job_queue(triton_vm_job_queue)
            .proof_job_options(proof_job_options)
            .build()
            .await?;
        info!("Done");

        Ok(proof)
    }
}

/// Generate a [SingleProof] for the transaction, given its primitive
/// witness.
///
/// This involves generating a [ProofCollection] as an intermediate step.
//
// This function calls SingleProof::produce but with the correct merge
// version.
pub(crate) async fn produce_single_proof(
    primitive_witness: &PrimitiveWitness,
    triton_vm_job_queue: Arc<TritonVmJobQueue>,
    proof_job_options: TritonVmProofJobOptions,
    consensus_rule_set: ConsensusRuleSet,
) -> Result<Proof, CreateProofError> {
    type GenesisSingleProof = SingleProof<{ MergeVersion::Genesis as usize }>;
    type HardFork2SingleProof = SingleProof<{ MergeVersion::HardFork2 as usize }>;
    match consensus_rule_set.merge_version() {
        MergeVersion::Genesis => {
            GenesisSingleProof::produce(primitive_witness, triton_vm_job_queue, proof_job_options)
                .await
        }
        MergeVersion::HardFork2 => {
            HardFork2SingleProof::produce(primitive_witness, triton_vm_job_queue, proof_job_options)
                .await
        }
    }
}

/// Not to be confused with SingleProofWitness::claim
///
/// Consensus rule set refers to the rule set for which the claim must be valid.
//
// This function calls SingleProof::claim but with the correct merge version.
pub(crate) fn single_proof_claim(
    tx_kernel_mast_hash: Digest,
    consensus_rule_set: ConsensusRuleSet,
) -> Claim {
    match consensus_rule_set.merge_version() {
        MergeVersion::Genesis => GenesisSingleProof::claim(tx_kernel_mast_hash),
        MergeVersion::HardFork2 => HardFork2SingleProof::claim(tx_kernel_mast_hash),
    }
}

pub(crate) fn produce_single_proof_mock(valid_mock: bool) -> Proof {
    let claim = Claim::new(Digest::default());
    if valid_mock {
        Proof::valid_mock(claim)
    } else {
        Proof::invalid_mock(claim)
    }
}

impl<const VERSION: usize> ConsensusProgram for SingleProof<VERSION> {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();

        // imports
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));
        let assemble_rri_claim = library.import(Box::new(GenerateRriClaim));
        let assemble_k2o_claim = library.import(Box::new(GenerateK2oClaim));
        let assemble_cls_claim = library.import(Box::new(GenerateCollectLockScriptsClaim));
        let assemble_cts_claim = library.import(Box::new(GenerateCollectTypeScriptsClaim));
        let assemble_lock_script_claim_template =
            library.import(Box::new(GenerateLockScriptClaimTemplate));
        let assemble_type_script_claim_template =
            library.import(Box::new(GenerateTypeScriptClaimTemplate));

        let proof_collection_field_kernel_mast_hash = field!(ProofCollection::kernel_mast_hash);
        let proof_collection_field_removal_records_integrity =
            field!(ProofCollection::removal_records_integrity);
        let proof_collection_field_collect_lock_scripts =
            field!(ProofCollection::collect_lock_scripts);
        let proof_collection_field_kernel_to_outputs = field!(ProofCollection::kernel_to_outputs);
        let proof_collection_field_collect_type_scripts =
            field!(ProofCollection::collect_type_scripts);
        let proof_collection_field_lock_scripts_halt = field!(ProofCollection::lock_scripts_halt);
        let proof_collection_field_type_scripts_halt = field!(ProofCollection::type_scripts_halt);

        let update_branch = library.import(Box::new(UpdateBranch));
        let merge_branch = library.import(Box::new(MergeBranch::<VERSION>));

        let audit_witness_of_proof_collection =
            library.import(Box::new(VerifyNdSiIntegrity::<ProofCollection>::default()));

        let claim_field_with_size_output = triton_asm!(read_mem 1 addi 1 place 1 addi -1);
        let merkle_verify =
            library.import(Box::new(tasm_lib::hashing::merkle_verify::MerkleVerify));

        let verify_scripts_loop_label = "neptune_transaction_verify_lock_scripts_loop";
        let verify_scripts_loop_body = triton_asm! {
            // INVARIANT: _ *claim_template *claim_program_digest *current_program_digest *eof *current_proof current_proof_size
            {verify_scripts_loop_label}:
                hint current_proof_size = stack[0]
                hint current_proof_ptr = stack[1]
                hint eof = stack[2]
                hint current_program_digest = stack[3]
                hint claim_program_digest = stack[4]
                hint claim_template = stack[5]

                dup 3 dup 3 eq skiz return
                // _ *claim_template *claim_program_digest *current_program_digest *eof *current_proof current_proof_size

                dup 3
                push {Digest::LEN - 1}
                add
                read_mem {Digest::LEN}
                pop 1
                // _ *claim_template *claim_program_digest *current_program_digest *eof *current_proof current_proof_size [current_program_digest]

                dup 9
                write_mem {Digest::LEN}
                pop 1
                // _ *claim_template *claim_program_digest *current_program_digest *eof *current_proof current_proof_size

                dup 5
                dup 2
                call {stark_verify}
                // _ *claim_template *claim_program_digest *current_program_digest *eof *current_proof current_proof_size

                add
                // _ *claim_template *claim_program_digest *current_program_digest *eof *next_proof_si

                read_mem 1
                // _ *claim_template *claim_program_digest *current_program_digest *eof next_proof_size (*next_proof_si-1)
                push 2 add
                // _ *claim_template *claim_program_digest *current_program_digest *eof next_proof_size *next_proof
                swap 1
                // _ *claim_template *claim_program_digest *current_program_digest *eof *next_proof next_proof_size

                swap 3
                push {Digest::LEN} add
                swap 3
                // _ *claim_template *claim_program_digest *next_program_digest *eof *next_proof next_proof_size

                recurse
        };

        let verify_merge_bit_false = triton_asm! {
            // _ [txk_digest] garb garb

                dup 6
                dup 6
                dup 6
                dup 6
                dup 6
                // _ [txk_digest] garb garb [txk_digest]

                push {TransactionKernel::MAST_HEIGHT as u32}
                push {TransactionKernelField::MergeBit as u32}
                // _ [txk_digest] garb garb [txk_digest] height index

                push 0
                push 0
                push 0
                push 0
                push 0
                push 0
                push 0
                push 0
                push 1
                push {u32::from(false)}
                // _ [txk_digest] garb garb [txk_digest] height index [padded-false-encoded]

                sponge_init
                sponge_absorb
                sponge_squeeze

                pick 5 pop 1
                pick 5 pop 1
                pick 5 pop 1
                pick 5 pop 1
                pick 5 pop 1
                // _ [txk_digest] garb garb [txk_digest] height index [false-digest]

                call {merkle_verify}
                // _ [txk_digest] garb garb
        };

        let proof_collection_case_label =
            "neptune_transaction_single_proof_case_collection".to_string();
        let proof_collection_case_body = triton_asm! {
            // BEFORE: [txk_digest] *single_proof_witness discriminant
            // AFTER: [txk_digest] *single_proof_witness discriminant
            {proof_collection_case_label}:
                hint discriminant = stack[0]
                hint single_proof_witness = stack[1]
                hint txk_digest = stack[2..7]
                // _ [txk_digest] *single_proof_witness discriminant

                {&verify_merge_bit_false}
                // _ [txk_digest] *single_proof_witness discriminant

                dup 1 addi 2
                hint proof_collection_ptr = stack[0]
                // _ [txk_digest] *spw disc *proof_collection

                dup 0
                call {audit_witness_of_proof_collection}
                // _ [txk_digest] *spw disc *proof_collection proof_collection_size

                place 8
                // _ pc_size [txk_digest] *spw disc *proof_collection
                // _ [txk_digest] *spw disc *proof_collection <-- rename


                /* check kernel MAST hash */

                dup 0 {&proof_collection_field_kernel_mast_hash}
                // [txk_digest] *spw disc *proof_collection *kernel_mast_hash

                push {Digest::LEN - 1} add
                read_mem {Digest::LEN}
                pop 1
                hint kernel_mast_hash: Digest = stack[0..5]
                // [txk_digest] *spw disc *proof_collection [kernel_mast_hash]

                dup 12
                dup 12
                dup 12
                dup 12
                dup 12
                // [txk_digest] *spw disc *proof_collection [kernel_mast_hash] [txk_digest]

                assert_vector
                pop {Digest::LEN}
                // [txk_digest] *spw disc *proof_collection


                /* create and verify removal records integrity claim */
                call {assemble_rri_claim}
                hint rri_claim = stack[0]
                // [txk_digest] *spw disc *proof_collection *rri_claim

                dup 1 {&proof_collection_field_removal_records_integrity}
                // [txk_digest] *spw disc *proof_collection *rri_claim *rri_proof

                call {stark_verify}
                // [txk_digest] *spw disc *proof_collection


                /* create and verify kernel to outputs claim */
                call {assemble_k2o_claim}
                // [txk_digest] *spw disc *proof_collection *k2o_claim

                dup 1 {&proof_collection_field_kernel_to_outputs}
                // [txk_digest] *spw disc *proof_collection *k2o_claim *proof

                call {stark_verify}
                // [txk_digest] *spw disc *proof_collection


                /* assemble and verify collect lock scripts claim */
                dup 0
                // [txk_digest] *spw disc *proof_collection

                call {assemble_cls_claim}
                hint cls_claim = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim

                dup 1 dup 1 swap 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *cls_claim *proof_collection

                {&proof_collection_field_collect_lock_scripts}
                // [txk_digest] *spw disc *proof_collection *cls_claim *cls_claim *cls_proof

                call {stark_verify}
                // [txk_digest] *spw disc *proof_collection *cls_claim


                /* assemble and verify collect type scripts claim */

                dup 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *proof_collection

                call {assemble_cts_claim}
                hint cts_claim = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim

                dup 0 dup 3
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *cts_claim *proof_collection

                {&proof_collection_field_collect_type_scripts}
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *cts_claim *cts_proof

                call {stark_verify}
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim


                /* for all lock scripts, assemble claim and verify */
                dup 2
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *proof_collection

                call {assemble_lock_script_claim_template}
                hint program_digest_ptr = stack[0]
                hint lock_script_claim_ptr = stack[1]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr

                dup 3 {&claim_field_with_size_output}
                hint output_size = stack[0]
                hint lock_script_hashes = stack[1]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes size

                dup 1 add push 2 add
                hint eof = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes *eof

                swap 1 push 2 add
                hint lock_script_hashes_i = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *eof *lock_script_hashes[0]

                swap 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes[0] *eof


                dup 6
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes[0] *eof *proof_collection

                {&proof_collection_field_lock_scripts_halt} push 1 add
                hint lock_script_proofs_i_si = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes *eof *lock_script_proofs[0]_si

                read_mem 1
                hint proof_size = stack[1]
                push 2 add
                swap 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes *eof *lock_script_proofs[0] proof_size

                call {verify_scripts_loop_label}

                pop 5 pop 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim


                /* for all type scripts, assemble claim and verify */
                dup 2
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *proof_collection

                call {assemble_type_script_claim_template}
                hint program_digest_ptr = stack[0]
                hint type_script_claim_ptr = stack[1]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr

                dup 2 {&claim_field_with_size_output}
                hint output_size = stack[0]
                hint type_script_hashes = stack[1]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes size

                dup 1 add addi 2
                hint eof = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes *eof

                pick 1 addi 2
                hint type_script_hashes_i = stack[0]
                place 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes[0] *eof


                dup 6
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes[0] *eof *proof_collection

                {&proof_collection_field_type_scripts_halt}
                addi 1
                hint type_script_proofs_i_si = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes *eof *type_script_proofs[0]_si

                read_mem 1
                hint proof_size = stack[1]
                addi 2
                place 1
                hint type_script_proofs_i = stack[1]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes *eof *type_script_proofs[0] proof_size

                call {verify_scripts_loop_label}

                pop 5 pop 4
                addi {-(DISCRIMINANT_FOR_PROOF_COLLECTION as isize) - 1}
                // [txk_digest] *spw -1

                dup 1 addi 2
                // _ [txk_digest] *spw -1 *proof_collection
                // _ pc_size_init [txk_digest] *spw -1 *proof_collection <-- rename

                call {audit_witness_of_proof_collection}
                // _ pc_size_init [txk_digest] *spw -1 pc_size_end

                pick 8
                eq
                assert error_id {MANIPULATED_PROOF_COLLECTION_WITNESS_ERROR}
                // _ [txk_digest] *spw -1

                return
        };

        let verify_discriminant_has_legal_value = triton_asm!(
            // _ discr

            dup 0
            push {DISCRIMINANT_FOR_PROOF_COLLECTION}
            eq

            dup 1
            push {DISCRIMINANT_FOR_UPDATE}
            eq

            dup 2
            push {DISCRIMINANT_FOR_MERGE}
            eq
            // _ discr (discr == proof_coll) (discr == update) (discr == merge)

            add
            add
            // _ discr (discr == proof_coll || discr == update || discr == merge)

            assert error_id {INVALID_WITNESS_DISCRIMINANT_ERROR}
            // _ discr
        );

        let main = triton_asm! {
            // _

            dup 15 dup 15 dup 15 dup 15 dup 15
            // _ [own_digest]

            read_io 5
            // _ [own_digest] [txk_digest]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // _ [own_digest] [txk_digest] *single_proof_witness

            read_mem 1 addi 1 swap 1
            // _ [own_digest] [txk_digest] *single_proof_witness discriminant

            {&verify_discriminant_has_legal_value}
            // _ [own_digest] [txk_digest] *single_proof_witness discriminant

            /* match discriminant */
            dup 0 push {DISCRIMINANT_FOR_PROOF_COLLECTION} eq
            skiz call {proof_collection_case_label}

            dup 0 push {DISCRIMINANT_FOR_UPDATE} eq
            skiz call {update_branch}

            dup 0 push {DISCRIMINANT_FOR_MERGE} eq
            skiz call {merge_branch}

            // _ [own_digest] [txk_digest] *single_proof_witness discriminant

            // a discriminant of -1 indicates that some branch was executed
            push -1
            eq
            assert error_id {NO_BRANCH_TAKEN_ERROR}

            pop 1 pop 5 pop 5
            // _

            halt
        };

        let code = triton_asm! {
            {&main}
            {&proof_collection_case_body}
            {&verify_scripts_loop_body}
            {&library.all_imports()}
        };

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }

    fn program(&self) -> Program {
        // Overwrite trait-implementation since this leads to much faster code.
        // Throughout the lifetime of a client, the `SingleProof` program never
        // changes, so this is OK.
        static PROGRAM: OnceLock<Program> = OnceLock::new();

        PROGRAM
            .get_or_init(|| {
                let (_, code) = self.library_and_code();
                Program::new(&code)
            })
            .clone()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use assert2::let_assert;
    use macro_rules_attr::apply;
    use proptest::prelude::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use tracing_test::traced_test;

    use super::*;
    use crate::config_models::network::Network;
    use crate::triton_vm_job_queue::TritonVmJobPriority;
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
    use crate::models::blockchain::transaction::validity::single_proof::SingleProofWitness;
    use crate::models::blockchain::transaction::validity::tasm::single_proof::merge_branch::tests::deterministic_merge_witness;
    use crate::models::blockchain::transaction::validity::tasm::single_proof::update_branch::tests::deterministic_update_witness_only_additions_to_mutator_set;
    use crate::models::blockchain::type_scripts::time_lock::neptune_arbitrary::arbitrary_primitive_witness_with_expired_timelocks;
    use crate::models::proof_abstractions::tasm::builtins as tasm;
    use crate::models::proof_abstractions::tasm::program::tests::test_program_snapshot;
    use crate::models::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;
    use crate::models::proof_abstractions::tasm::program::ConsensusError;
    use crate::models::proof_abstractions::timestamp::Timestamp;
    use crate::tests::shared_tokio_runtime;
    use crate::models::blockchain::transaction::merge_version::for_each_version;
    use crate::models::blockchain::transaction::merge_version::for_each;

    impl<const VERSION: usize> ConsensusProgramSpecification for SingleProof<VERSION> {
        fn source(&self) {
            let stark: Stark = Stark::default();
            let own_program_digest: Digest = tasm::own_program_digest();
            let txk_digest: Digest = tasm::tasmlib_io_read_stdin___digest();

            match tasm::decode_from_memory::<SingleProofWitness<VERSION>>(
                FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            ) {
                SingleProofWitness::Collection(pc) => {
                    assert_eq!(txk_digest, pc.kernel_mast_hash);

                    let claimed_merge_bit = false;
                    tasm::tasmlib_hashing_merkle_verify(
                        txk_digest,
                        TransactionKernelField::MergeBit as u32,
                        Tip5::hash(&claimed_merge_bit),
                        TransactionKernel::MAST_HEIGHT as u32,
                    );

                    let removal_records_integrity_claim: Claim =
                        pc.removal_records_integrity_claim();
                    tasm::verify_stark(
                        stark,
                        &removal_records_integrity_claim,
                        &pc.removal_records_integrity,
                    );

                    let kernel_to_outputs_claim: Claim = pc.kernel_to_outputs_claim();
                    tasm::verify_stark(stark, &kernel_to_outputs_claim, &pc.kernel_to_outputs);

                    let collect_lock_scripts_claim: Claim = pc.collect_lock_scripts_claim();
                    tasm::verify_stark(
                        stark,
                        &collect_lock_scripts_claim,
                        &pc.collect_lock_scripts,
                    );

                    let collect_type_scripts_claim: Claim = pc.collect_type_scripts_claim();
                    tasm::verify_stark(
                        stark,
                        &collect_type_scripts_claim,
                        &pc.collect_type_scripts,
                    );

                    let mut i = 0;
                    let lock_script_claims: Vec<Claim> = pc.lock_script_claims();
                    assert_eq!(lock_script_claims.len(), pc.lock_script_hashes.len());
                    while i < pc.lock_script_hashes.len() {
                        let claim: &Claim = &lock_script_claims[i];
                        let lock_script_halts_proof: &Proof = &pc.lock_scripts_halt[i];
                        tasm::verify_stark(stark, claim, lock_script_halts_proof);

                        i += 1;
                    }

                    i = 0;
                    let type_script_claims = pc.type_script_claims();
                    assert_eq!(type_script_claims.len(), pc.type_script_hashes.len());
                    while i < pc.type_script_hashes.len() {
                        let claim: &Claim = &type_script_claims[i];
                        let type_script_halts_proof: &Proof = &pc.type_scripts_halt[i];
                        tasm::verify_stark(stark, claim, type_script_halts_proof);
                        i += 1;
                    }
                }
                SingleProofWitness::Update(witness) => {
                    debug_assert_eq!(txk_digest, witness.new_kernel_mast_hash);
                    witness.branch_source(own_program_digest, txk_digest);
                }
                SingleProofWitness::Merger(witness) => {
                    witness.branch_source::<VERSION>(own_program_digest, txk_digest)
                }
            }
        }
    }

    impl<const VERSION: usize> SingleProofWitness<VERSION> {
        pub(crate) fn into_update(self) -> UpdateWitness {
            let SingleProofWitness::Update(witness) = self else {
                panic!("Expected update witness.");
            };

            witness
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn invalid_discriminant_crashes_execution() {
        let pub_input = PublicInput::new(bfe_vec![0, 0, 0, 0, 0]);
        for illegal_discriminant_value in bfe_array![-1, 3, 4, 1u64 << 40] {
            let init_ram: HashMap<_, _> = [(
                FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
                illegal_discriminant_value,
            )]
            .into_iter()
            .collect();

            let nondeterminism = NonDeterminism::default().with_ram(init_ram);

            for_each_version!({
                let consensus_err =
                    SingleProof::<VERSION>.run_tasm(&pub_input, nondeterminism.clone());

                let_assert!(Err(ConsensusError::TritonVMPanic(_, instruction_err)) = consensus_err);
                let_assert!(InstructionError::AssertionFailed(assertion_err) = instruction_err);
                let_assert!(Some(err_id) = assertion_err.id);
                assert_eq!(INVALID_WITNESS_DISCRIMINANT_ERROR, err_id);
            });
        }
    }

    fn positive_prop<const VERSION: usize>(witness: SingleProofWitness<VERSION>) {
        let claim = witness.claim();
        let public_input = PublicInput::new(claim.input);
        let rust_result = SingleProof::<VERSION>.run_rust(&public_input, witness.nondeterminism());
        let tasm_result = SingleProof::<VERSION>.run_tasm(&public_input, witness.nondeterminism());
        assert_eq!(rust_result.unwrap(), tasm_result.unwrap());
    }

    mod proof_collection_tests {
        use tasm_lib::hashing::merkle_verify::MerkleVerify;

        use super::*;

        #[apply(shared_tokio_runtime)]
        async fn disallow_set_merge_bit_in_pc_path() {
            let mut test_runner = TestRunner::deterministic();

            for_each_version!({
                let good_primitive_witness =
                    PrimitiveWitness::arbitrary_with_size_numbers_and_merge_bit(
                        Some(6),
                        6,
                        7,
                        false,
                    )
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current();

                let good_proof_collection = ProofCollection::produce(
                    &good_primitive_witness,
                    TritonVmJobQueue::get_instance(),
                    TritonVmJobPriority::default().into(),
                )
                .await
                .unwrap();
                let good_witness =
                    SingleProofWitness::<VERSION>::from_collection(good_proof_collection.clone());
                positive_prop(good_witness);

                // Setting the `merge_bit` must make program crash, as this bit may
                // only be set to true through the execution of the merge branch.
                let bad_primitive_witness =
                    PrimitiveWitness::arbitrary_with_size_numbers_and_merge_bit(
                        Some(6),
                        6,
                        7,
                        true,
                    )
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current();

                let bad_proof_collection = ProofCollection::produce(
                    &bad_primitive_witness,
                    TritonVmJobQueue::get_instance(),
                    TritonVmJobPriority::default().into(),
                )
                .await
                .unwrap();

                let bad_witness =
                    SingleProofWitness::<VERSION>::from_collection(bad_proof_collection);

                // This witness fails with a Merkle auth path error since the never
                // reads the actual bit but rather just verifies that it is set to
                // false in this execution path.
                SingleProof::<VERSION>
                    .test_assertion_failure(
                        bad_witness.standard_input(),
                        bad_witness.nondeterminism(),
                        &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
                    )
                    .unwrap();
            });
        }

        #[apply(shared_tokio_runtime)]
        async fn can_verify_via_valid_proof_collection() {
            let network = Network::Main;
            let mut test_runner = TestRunner::deterministic();

            for_each_version!({
                let primitive_witness =
                    PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
                        .new_tree(&mut test_runner)
                        .unwrap()
                        .current();
                let txk_mast_hash = primitive_witness.kernel.mast_hash();

                let proof_collection = ProofCollection::produce(
                    &primitive_witness,
                    TritonVmJobQueue::get_instance(),
                    TritonVmJobPriority::default().into(),
                )
                .await
                .unwrap();
                assert!(proof_collection.verify(txk_mast_hash, network).await);

                let witness =
                    SingleProofWitness::<VERSION>::from_collection(proof_collection.clone());
                let claim = witness.claim();
                let public_input = PublicInput::new(claim.input);
                let rust_result =
                    SingleProof::<VERSION>.run_rust(&public_input, witness.nondeterminism());
                let tasm_result =
                    SingleProof::<VERSION>.run_tasm(&public_input, witness.nondeterminism());
                assert_eq!(rust_result.unwrap(), tasm_result.unwrap());

                // Verify equivalence of claim functions
                assert_eq!(
                    witness.claim(),
                    SingleProof::<VERSION>::claim(txk_mast_hash),
                    "Claim functions must agree"
                );
            });
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn can_verify_via_valid_proof_collection_if_timelocked_expired() {
            let network = Network::Main;
            let mut test_runner = TestRunner::deterministic();
            for_each_version!({
                let deterministic_now = arb::<Timestamp>()
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current();
                let primitive_witness =
                    arbitrary_primitive_witness_with_expired_timelocks(2, 2, 2, deterministic_now)
                        .new_tree(&mut test_runner)
                        .unwrap()
                        .current();
                let txk_mast_hash = primitive_witness.kernel.mast_hash();

                let proof_collection = ProofCollection::produce(
                    &primitive_witness,
                    TritonVmJobQueue::get_instance(),
                    TritonVmJobPriority::default().into(),
                )
                .await
                .unwrap();
                assert!(proof_collection.verify(txk_mast_hash, network).await);

                let witness =
                    SingleProofWitness::<VERSION>::from_collection(proof_collection.clone());
                let claim = witness.claim();
                let public_input = PublicInput::new(claim.input);
                let rust_result =
                    SingleProof::<VERSION>.run_rust(&public_input, witness.nondeterminism());
                let tasm_result =
                    SingleProof::<VERSION>.run_tasm(&public_input, witness.nondeterminism());
                assert_eq!(rust_result.unwrap(), tasm_result.unwrap());
            });
        }
    }

    mod merge_tests {
        use crate::models::blockchain::transaction::validity::tasm::single_proof::merge_branch::tests::deterministic_merge_witness_with_coinbase;
        use crate::api::export::BlockHeight;

        use super::*;

        #[apply(shared_tokio_runtime)]
        async fn can_verify_transaction_merger_without_coinbase() {
            let network = Network::Main;
            let block_height = BlockHeight::new(bfe!(100000));
            let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
            let merge_witness =
                deterministic_merge_witness((2, 2, 2), (2, 2, 2), consensus_rule_set, network)
                    .await;

            for_each_version!({
                let merge_witness = SingleProofWitness::<VERSION>::Merger(merge_witness.clone());

                let claim = merge_witness.claim();
                let public_input = PublicInput::new(claim.input);
                let rust_result =
                    SingleProof::<VERSION>.run_rust(&public_input, merge_witness.nondeterminism());
                let tasm_result =
                    SingleProof::<VERSION>.run_tasm(&public_input, merge_witness.nondeterminism());

                assert_eq!(rust_result.unwrap(), tasm_result.unwrap());
            });
        }

        #[apply(shared_tokio_runtime)]
        async fn can_verify_transaction_merger_with_coinbase() {
            let network = Network::Main;

            for_each_version!({
                println!("VERSION: {VERSION}");
                let merge_witness =
                    deterministic_merge_witness_with_coinbase::<VERSION>(3, 3, 3, network).await;
                let merge_witness = SingleProofWitness::<VERSION>::Merger(merge_witness.clone());

                let claim = merge_witness.claim();
                let public_input = PublicInput::new(claim.input);
                let rust_result =
                    SingleProof::<VERSION>.run_rust(&public_input, merge_witness.nondeterminism());
                let tasm_result =
                    SingleProof::<VERSION>.run_tasm(&public_input, merge_witness.nondeterminism());

                assert_eq!(rust_result.unwrap(), tasm_result.unwrap());
            });
        }
    }

    mod update_tests {
        use proptest::prelude::*;
        use rand::random;
        use tasm_lib::hashing::merkle_verify::MerkleVerify;
        use tasm_lib::twenty_first::prelude::Mmr;

        use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelModifier;
        use crate::models::blockchain::transaction::validity::tasm::single_proof::update_branch::tests::deterministic_update_witness_additions_and_removals;
        use crate::util_types::mutator_set::removal_record::RemovalRecord;

        use super::*;

        fn positive_prop(witness: UpdateWitness, consensus_rule_set: ConsensusRuleSet) {
            let (_claim, input, nondeterminism) = if consensus_rule_set.merge_version()
                == MergeVersion::Genesis
            {
                let witness =
                    SingleProofWitness::<{ MergeVersion::Genesis as usize }>::from_update(witness);
                let claim = witness.claim();
                let input = PublicInput::new(claim.input.clone());
                let nondeterminism = witness.nondeterminism();
                (claim, input, nondeterminism)
            } else {
                let witness =
                    SingleProofWitness::<{ MergeVersion::HardFork2 as usize }>::from_update(
                        witness,
                    );
                let claim = witness.claim();
                let input = PublicInput::new(claim.input.clone());
                let nondeterminism = witness.nondeterminism();
                (claim, input, nondeterminism)
            };

            let (rust_result, tasm_result) =
                if consensus_rule_set.merge_version() == MergeVersion::Genesis {
                    let rust_result = SingleProof::<{ MergeVersion::Genesis as usize }>
                        .run_rust(&input, nondeterminism.clone());

                    let tasm_result = SingleProof::<{ MergeVersion::Genesis as usize }>
                        .run_tasm(&input, nondeterminism);
                    (rust_result, tasm_result)
                } else {
                    let rust_result = SingleProof::<{ MergeVersion::HardFork2 as usize }>
                        .run_rust(&input, nondeterminism.clone());

                    let tasm_result = SingleProof::<{ MergeVersion::HardFork2 as usize }>
                        .run_tasm(&input, nondeterminism);
                    (rust_result, tasm_result)
                };

            assert_eq!(rust_result.unwrap(), tasm_result.unwrap());
        }

        #[apply(shared_tokio_runtime)]
        async fn only_additions_small() {
            for consensus_rule_set in ConsensusRuleSet::iter_merge_versions() {
                positive_prop(
                    deterministic_update_witness_only_additions_to_mutator_set(
                        2,
                        2,
                        2,
                        consensus_rule_set,
                    )
                    .await,
                    consensus_rule_set,
                );
            }
        }

        #[apply(shared_tokio_runtime)]
        async fn only_additions_medium() {
            for consensus_rule_set in ConsensusRuleSet::iter_merge_versions() {
                positive_prop(
                    deterministic_update_witness_only_additions_to_mutator_set(
                        4,
                        4,
                        4,
                        consensus_rule_set,
                    )
                    .await,
                    consensus_rule_set,
                );
            }
        }

        #[apply(shared_tokio_runtime)]
        async fn addition_and_removals_tiny() {
            for consensus_rule_set in ConsensusRuleSet::iter_merge_versions() {
                positive_prop(
                    deterministic_update_witness_additions_and_removals(
                        1,
                        1,
                        1,
                        consensus_rule_set,
                    )
                    .await,
                    consensus_rule_set,
                );
            }
        }

        #[apply(shared_tokio_runtime)]
        async fn addition_and_removals_small() {
            for consensus_rule_set in ConsensusRuleSet::iter_merge_versions() {
                positive_prop(
                    deterministic_update_witness_additions_and_removals(
                        2,
                        2,
                        2,
                        consensus_rule_set,
                    )
                    .await,
                    consensus_rule_set,
                );
            }
        }

        #[apply(shared_tokio_runtime)]
        async fn addition_and_removals_midi() {
            for consensus_rule_set in ConsensusRuleSet::iter_merge_versions() {
                positive_prop(
                    deterministic_update_witness_additions_and_removals(
                        3,
                        3,
                        3,
                        consensus_rule_set,
                    )
                    .await,
                    consensus_rule_set,
                );
            }
        }

        #[apply(shared_tokio_runtime)]
        async fn addition_and_removals_medium() {
            for consensus_rule_set in ConsensusRuleSet::iter_merge_versions() {
                positive_prop(
                    deterministic_update_witness_additions_and_removals(
                        4,
                        4,
                        4,
                        consensus_rule_set,
                    )
                    .await,
                    consensus_rule_set,
                );
            }
        }

        fn new_timestamp_older_than_old(good_witness: &UpdateWitness) {
            let mut bad_witness = good_witness.to_owned();

            bad_witness.new_kernel = TransactionKernelModifier::default()
                .timestamp(bad_witness.old_kernel.timestamp - Timestamp::hours(1))
                .modify(bad_witness.new_kernel);
            bad_witness.new_kernel_mast_hash = bad_witness.new_kernel.mast_hash();

            for_each_version!({
                let bad_witness = SingleProofWitness::<VERSION>::from_update(bad_witness.clone());
                let claim = bad_witness.claim();
                let input = PublicInput::new(claim.input.clone());
                let nondeterminism = bad_witness.nondeterminism();
                let test_result = SingleProof::<VERSION>.test_assertion_failure(
                    input,
                    nondeterminism,
                    &[UpdateBranch::NEW_TIMESTAMP_NOT_GEQ_THAN_OLD_ERROR],
                );
                test_result.unwrap();
            });
        }

        fn bad_new_aocl(good_witness: &UpdateWitness) {
            for_each_version!({
                let good_witness =
                    SingleProofWitness::<VERSION>::from_update(good_witness.to_owned());
                let claim = good_witness.claim();
                let input = PublicInput::new(claim.input.clone());
                let mut nondeterminism = good_witness.nondeterminism();

                let witness_again: SingleProofWitness<VERSION> =
                    *SingleProofWitness::<VERSION>::decode_from_memory(
                        &nondeterminism.ram,
                        FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
                    )
                    .unwrap();
                let mut witness_again = witness_again.into_update();
                witness_again.new_aocl.append(random());
                let witness_again = SingleProofWitness::<VERSION>::from_update(witness_again);
                encode_to_memory(
                    &mut nondeterminism.ram,
                    FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
                    &witness_again,
                );
                let test_result = SingleProof::<VERSION>.test_assertion_failure(
                    input,
                    nondeterminism,
                    &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
                );
                test_result.unwrap();
            });
        }

        fn bad_old_aocl(good_witness: &UpdateWitness) {
            for_each_version!({
                let good_witness =
                    SingleProofWitness::<VERSION>::from_update(good_witness.to_owned());
                let claim = good_witness.claim();
                let input = PublicInput::new(claim.input.clone());
                let mut nondeterminism = good_witness.nondeterminism();

                let witness_again: SingleProofWitness<VERSION> =
                    *SingleProofWitness::<VERSION>::decode_from_memory(
                        &nondeterminism.ram,
                        FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
                    )
                    .unwrap();
                let mut witness_again = witness_again.into_update();
                witness_again.old_aocl.append(random());
                let witness_again = SingleProofWitness::<VERSION>::from_update(witness_again);
                encode_to_memory(
                    &mut nondeterminism.ram,
                    FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
                    &witness_again,
                );
                let test_result = SingleProof::<VERSION>.test_assertion_failure(
                    input,
                    nondeterminism,
                    &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
                );
                test_result.unwrap();
            });
        }

        fn bad_absolute_index_set_value(good_witness: &UpdateWitness) {
            let mut bad_witness = good_witness.clone();

            let mut new_inputs = bad_witness.new_kernel.inputs.clone();
            new_inputs[0]
                .absolute_indices
                .decrement_bloom_filter_index(10);

            bad_witness.new_kernel = TransactionKernelModifier::default()
                .inputs(new_inputs)
                .modify(bad_witness.new_kernel);
            bad_witness.new_kernel_mast_hash = bad_witness.new_kernel.mast_hash();

            for_each_version!({
                let bad_witness = SingleProofWitness::<VERSION>::from_update(bad_witness.clone());
                let claim = bad_witness.claim();
                let input = PublicInput::new(claim.input.clone());
                let nondeterminism = bad_witness.nondeterminism();
                let test_result = SingleProof::<VERSION>.test_assertion_failure(
                    input,
                    nondeterminism,
                    &[UpdateBranch::INPUT_SETS_NOT_EQUAL_ERROR],
                );
                test_result.unwrap();
            });
        }

        fn bad_absolute_index_set_length_too_short(good_witness: &UpdateWitness) {
            let mut bad_witness = good_witness.clone();

            let mut new_inputs = bad_witness.new_kernel.inputs.clone();
            new_inputs.remove(0);
            bad_witness.new_kernel = TransactionKernelModifier::default()
                .inputs(new_inputs)
                .modify(bad_witness.new_kernel);
            bad_witness.new_kernel_mast_hash = bad_witness.new_kernel.mast_hash();

            for_each_version!({
                let bad_witness = SingleProofWitness::<VERSION>::from_update(bad_witness.clone());
                let claim = bad_witness.claim();
                let input = PublicInput::new(claim.input.clone());
                let nondeterminism = bad_witness.nondeterminism();
                let test_result = SingleProof::<VERSION>.test_assertion_failure(
                    input,
                    nondeterminism,
                    &[UpdateBranch::INPUT_SETS_NOT_EQUAL_ERROR],
                );
                test_result.unwrap();
            });
        }

        fn bad_absolute_index_set_length_too_long(good_witness: &UpdateWitness, rr: RemovalRecord) {
            let mut bad_witness = good_witness.clone();

            let mut new_inputs = bad_witness.new_kernel.inputs.clone();
            new_inputs.push(rr);

            bad_witness.new_kernel = TransactionKernelModifier::default()
                .inputs(new_inputs)
                .modify(bad_witness.new_kernel);
            bad_witness.new_kernel_mast_hash = bad_witness.new_kernel.mast_hash();

            for_each_version!({
                let bad_witness = SingleProofWitness::<VERSION>::from_update(bad_witness.clone());
                let claim = bad_witness.claim();
                let input = PublicInput::new(claim.input.clone());
                let nondeterminism = bad_witness.nondeterminism();
                let test_result = SingleProof::<VERSION>.test_assertion_failure(
                    input,
                    nondeterminism,
                    &[UpdateBranch::INPUT_SETS_NOT_EQUAL_ERROR],
                );
                test_result.unwrap();
            });
        }

        #[apply(shared_tokio_runtime)]
        async fn update_witness_negative_tests() {
            for consensus_rule_set in ConsensusRuleSet::iter_merge_versions() {
                // It takes a long time to generate the witness, so we reuse it across
                // multiple tests
                let good_witness = deterministic_update_witness_only_additions_to_mutator_set(
                    2,
                    2,
                    2,
                    consensus_rule_set,
                )
                .await;
                positive_prop(good_witness.clone(), consensus_rule_set);
                new_timestamp_older_than_old(&good_witness);
                bad_new_aocl(&good_witness);
                bad_old_aocl(&good_witness);
                bad_absolute_index_set_value(&good_witness);
                bad_absolute_index_set_length_too_short(&good_witness);
                proptest::proptest! {
                    ProptestConfig { cases: 3, .. ProptestConfig::default() },
                    |(rr in arb::<RemovalRecord>())| {
                        bad_absolute_index_set_length_too_long(&good_witness, rr);
                    }
                }
            }
        }

        #[apply(shared_tokio_runtime)]
        async fn disallow_update_of_tx_with_zero_inputs() {
            for consensus_rule_set in ConsensusRuleSet::iter_merge_versions() {
                let only_new_additions_0_outputs =
                    deterministic_update_witness_only_additions_to_mutator_set(
                        0,
                        0,
                        0,
                        consensus_rule_set,
                    )
                    .await;
                let only_new_additions_2_outputs =
                    deterministic_update_witness_only_additions_to_mutator_set(
                        0,
                        2,
                        2,
                        consensus_rule_set,
                    )
                    .await;
                let new_additions_and_removals_2_outputs =
                    deterministic_update_witness_additions_and_removals(
                        0,
                        2,
                        2,
                        consensus_rule_set,
                    )
                    .await;
                if consensus_rule_set.merge_version() == MergeVersion::Genesis {
                    const VERSION: usize = MergeVersion::Genesis as usize;
                    for bad_witness in [
                        only_new_additions_0_outputs.clone(),
                        only_new_additions_2_outputs.clone(),
                        new_additions_and_removals_2_outputs.clone(),
                    ] {
                        let bad_witness = SingleProofWitness::<VERSION>::from_update(bad_witness);
                        let claim = bad_witness.claim();
                        let input = PublicInput::new(claim.input.clone());
                        let nondeterminism = bad_witness.nondeterminism();
                        let test_result = SingleProof::<VERSION>.test_assertion_failure(
                            input,
                            nondeterminism,
                            &[UpdateBranch::INPUT_SET_IS_EMPTY_ERROR],
                        );
                        test_result.unwrap();
                    }
                } else {
                    const VERSION: usize = MergeVersion::HardFork2 as usize;
                    for bad_witness in [
                        only_new_additions_0_outputs.clone(),
                        only_new_additions_2_outputs.clone(),
                        new_additions_and_removals_2_outputs.clone(),
                    ] {
                        let bad_witness = SingleProofWitness::<VERSION>::from_update(bad_witness);
                        let claim = bad_witness.claim();
                        let input = PublicInput::new(claim.input.clone());
                        let nondeterminism = bad_witness.nondeterminism();
                        let test_result = SingleProof::<VERSION>.test_assertion_failure(
                            input,
                            nondeterminism,
                            &[UpdateBranch::INPUT_SET_IS_EMPTY_ERROR],
                        );
                        test_result.unwrap();
                    }
                }
            }
        }
    }

    test_program_snapshot!(
        SingleProof::<{ MergeVersion::Genesis as usize }>,
        // snapshot taken from master on 2025-04-11 e2a712efc34f78c6a28801544418e7051127d284
        "c0f8cbc73a844ab6c3586d8891e29b677a3aa08f25f9aec0f854a72bf2e2f84c2a48c9dd1bbe0a66"
    );
}
