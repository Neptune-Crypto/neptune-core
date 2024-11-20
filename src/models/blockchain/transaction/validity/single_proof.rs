use std::collections::HashMap;
use std::sync::OnceLock;

use itertools::Itertools;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::Library;
use tasm_lib::prelude::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::error::BFieldCodecError;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tasm_lib::Digest;
use tracing::info;

use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_collect_lock_scripts_claim::GenerateCollectLockScriptsClaim;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_collect_type_scripts_claim::GenerateCollectTypeScriptsClaim;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_k2o_claim::GenerateK2oClaim;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_lock_script_claim_template::GenerateLockScriptClaimTemplate;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_type_script_claim_template::GenerateTypeScriptClaimTemplate;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_rri_claim::GenerateRriClaim;
use crate::models::blockchain::transaction::Claim;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::builtins as tasmlib;
use crate::models::blockchain::transaction::validity::tasm::claims::new_claim::NewClaim;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::job_queue::triton_vm::TritonVmJobQueue;
use crate::models::proof_abstractions::SecretWitness;
use crate::BFieldElement;
use crate::models::blockchain::transaction::validity::merge::Merge;
use crate::models::blockchain::transaction::validity::proof_collection::ProofCollection;
use crate::models::blockchain::transaction::validity::update::Update;

#[derive(Debug, Clone, BFieldCodec, TasmObject)]
pub(crate) struct WitnessOfUpdate {
    proof: Proof,
    new_kernel_mast_hash: Digest,
}

impl WitnessOfUpdate {
    /// [`Claim`] that some transaction was updated.
    pub(crate) fn claim_of_update(&self) -> Claim {
        let own_program_digest = SingleProof.hash();
        let public_input = [self.new_kernel_mast_hash, own_program_digest]
            .map(|d| d.reversed().values())
            .concat();

        Claim::new(Update.hash()).with_input(public_input)
    }
}

#[derive(Debug, Clone, BFieldCodec, TasmObject)]
pub(crate) struct WitnessOfMerge {
    proof: Proof,
    new_kernel_mast_hash: Digest,
}

impl WitnessOfMerge {
    /// [`Claim`] that two transactions were merged.
    pub(crate) fn claim_of_merge(&self) -> Claim {
        let own_program_digest = SingleProof.hash();
        let public_input = [self.new_kernel_mast_hash, own_program_digest]
            .map(|d| d.reversed().values())
            .concat();

        Claim::new(Merge.hash()).with_input(public_input)
    }
}

#[derive(Debug, Clone, BFieldCodec)]
pub(crate) enum SingleProofWitness {
    Collection(Box<ProofCollection>),
    Update(WitnessOfUpdate),
    Merger(WitnessOfMerge),
    // Wait for Hard Fork One:
    // IntegralMempool(IntegralMempoolMembershipWitness)
}

impl SingleProofWitness {
    pub fn from_collection(proof_collection: ProofCollection) -> Self {
        Self::Collection(Box::new(proof_collection))
    }

    pub fn from_update(update_proof: Proof, new_kernel: &TransactionKernel) -> Self {
        Self::Update(WitnessOfUpdate {
            proof: update_proof,
            new_kernel_mast_hash: new_kernel.mast_hash(),
        })
    }

    pub(crate) fn from_merge(merge_proof: Proof, new_kernel: &TransactionKernel) -> Self {
        Self::Merger(WitnessOfMerge {
            proof: merge_proof,
            new_kernel_mast_hash: new_kernel.mast_hash(),
        })
    }
}

// This implementation of `TasmObject` is required for `decode_iter` and the
// method `decode_from_memory` that relies on it. The field getters are not
// relevant because the type in question is an enum.
impl TasmObject for SingleProofWitness {
    fn label_friendly_name() -> String {
        "SingleProofWitness".to_string()
    }

    fn get_field(_field_name: &str) -> Vec<LabelledInstruction> {
        unimplemented!()
    }

    fn get_field_with_size(_field_name: &str) -> Vec<LabelledInstruction> {
        unimplemented!()
    }

    fn get_field_start_with_jump_distance(_field_name: &str) -> Vec<LabelledInstruction> {
        unimplemented!()
    }

    fn compute_size_and_assert_valid_size_indicator(
        _library: &mut Library,
    ) -> Vec<LabelledInstruction> {
        unimplemented!()
    }

    fn decode_iter<Itr: Iterator<Item = BFieldElement>>(
        iterator: &mut Itr,
    ) -> Result<Box<Self>, Box<dyn std::error::Error + Send + Sync>> {
        const COLLECTION_DISCRIMINANT: u64 = 0;
        const UPDATE_DISCRIMINANT: u64 = 1;
        const MERGE_DISCRIMINANT: u64 = 2;

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
            COLLECTION_DISCRIMINANT => Ok(Box::new(Self::Collection(Box::new(
                *BFieldCodec::decode(&field_data)?,
            )))),
            UPDATE_DISCRIMINANT => Ok(Box::new(Self::Update(*BFieldCodec::decode(&field_data)?))),
            MERGE_DISCRIMINANT => Ok(Box::new(Self::Merger(*BFieldCodec::decode(&field_data)?))),
            _ => Err(Box::new(BFieldCodecError::ElementOutOfRange)),
        }
    }
}

impl SecretWitness for SingleProofWitness {
    fn standard_input(&self) -> PublicInput {
        let kernel_mast_hash = match self {
            Self::Collection(pc) => pc.kernel_mast_hash,
            Self::Update(witness) => witness.new_kernel_mast_hash,
            SingleProofWitness::Merger(witness) => witness.new_kernel_mast_hash,
        };
        kernel_mast_hash.reversed().values().into()
    }

    fn output(&self) -> Vec<BFieldElement> {
        std::vec![]
    }

    fn program(&self) -> Program {
        Program::new(&SingleProof.code())
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

        match self {
            SingleProofWitness::Collection(proof_collection) => {
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
            SingleProofWitness::Update(witness_of_update) => {
                stark_verify_snippet.update_nondeterminism(
                    &mut nondeterminism,
                    &witness_of_update.proof,
                    &witness_of_update.claim_of_update(),
                );
            }
            SingleProofWitness::Merger(witness_of_merge) => {
                stark_verify_snippet.update_nondeterminism(
                    &mut nondeterminism,
                    &witness_of_merge.proof,
                    &witness_of_merge.claim_of_merge(),
                );
            }
        }

        nondeterminism
    }
}

#[derive(Debug, Clone)]
pub struct SingleProof;

impl SingleProof {
    /// Not to be confused with SingleProofWitness::claim
    pub(crate) fn claim(tx_kernel_mast_hash: Digest) -> Claim {
        Claim::new(tx_kernel_mast_hash).with_input(tx_kernel_mast_hash.reversed().values())
    }

    /// Generate a [SingleProof] for the transaction, given its primitive
    /// witness.
    ///
    /// This involves generating a [ProofCollection] as an intermediate step.
    pub(crate) async fn produce(
        primitive_witness: &PrimitiveWitness,
        triton_vm_job_queue: &TritonVmJobQueue,
        proof_job_options: TritonVmProofJobOptions,
    ) -> anyhow::Result<Proof> {
        let proof_collection =
            ProofCollection::produce(primitive_witness, triton_vm_job_queue, proof_job_options)
                .await?;
        let single_proof_witness = SingleProofWitness::from_collection(proof_collection);
        let claim = single_proof_witness.claim();
        let nondeterminism = single_proof_witness.nondeterminism();

        info!("Start: generate single proof");
        let single_proof = SingleProof
            .prove(
                &claim,
                nondeterminism,
                triton_vm_job_queue,
                proof_job_options,
            )
            .await?;
        info!("Done");

        Ok(single_proof)
    }
}

impl ConsensusProgram for SingleProof {
    fn source(&self) {
        let stark: Stark = Stark::default();
        let own_program_digest: Digest = tasmlib::own_program_digest();
        let txk_digest: Digest = tasmlib::tasmlib_io_read_stdin___digest();
        let input_for_claims_about_update_or_merge: Vec<BFieldElement> =
            [txk_digest, own_program_digest]
                .map(|d| d.reversed().values())
                .concat();

        match tasmlib::decode_from_memory(FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS) {
            SingleProofWitness::Collection(pc) => {
                assert_eq!(txk_digest, pc.kernel_mast_hash);

                let removal_records_integrity_claim: Claim = pc.removal_records_integrity_claim();
                tasmlib::verify_stark(
                    stark,
                    &removal_records_integrity_claim,
                    &pc.removal_records_integrity,
                );

                let kernel_to_outputs_claim: Claim = pc.kernel_to_outputs_claim();
                tasmlib::verify_stark(stark, &kernel_to_outputs_claim, &pc.kernel_to_outputs);

                let collect_lock_scripts_claim: Claim = pc.collect_lock_scripts_claim();
                tasmlib::verify_stark(stark, &collect_lock_scripts_claim, &pc.collect_lock_scripts);

                let collect_type_scripts_claim: Claim = pc.collect_type_scripts_claim();
                tasmlib::verify_stark(stark, &collect_type_scripts_claim, &pc.collect_type_scripts);

                let mut i = 0;
                let lock_script_claims: Vec<Claim> = pc.lock_script_claims();
                assert_eq!(lock_script_claims.len(), pc.lock_script_hashes.len());
                while i < pc.lock_script_hashes.len() {
                    let claim: &Claim = &lock_script_claims[i];
                    let lock_script_halts_proof: &Proof = &pc.lock_scripts_halt[i];
                    tasmlib::verify_stark(stark, claim, lock_script_halts_proof);

                    i += 1;
                }

                i = 0;
                let type_script_claims = pc.type_script_claims();
                assert_eq!(type_script_claims.len(), pc.type_script_hashes.len());
                while i < pc.type_script_hashes.len() {
                    let claim: &Claim = &type_script_claims[i];
                    let type_script_halts_proof: &Proof = &pc.type_scripts_halt[i];
                    tasmlib::verify_stark(stark, claim, type_script_halts_proof);
                    i += 1;
                }
            }
            SingleProofWitness::Update(witness_of_update) => {
                debug_assert_eq!(txk_digest, witness_of_update.new_kernel_mast_hash);
                let claim_of_update: Claim =
                    Claim::new(Update.hash()).with_input(input_for_claims_about_update_or_merge);
                tasmlib::verify_stark(stark, &claim_of_update, &witness_of_update.proof);
            }
            SingleProofWitness::Merger(witness_of_merge) => {
                debug_assert_eq!(txk_digest, witness_of_merge.new_kernel_mast_hash);
                let claim_of_merge: Claim =
                    Claim::new(Merge.hash()).with_input(input_for_claims_about_update_or_merge);
                tasmlib::verify_stark(stark, &claim_of_merge, &witness_of_merge.proof);
            }
        }
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        const DISCRIMINANT_FOR_PROOF_COLLECTION: isize = 0;
        const DISCRIMINANT_FOR_UPDATE: isize = 1;
        const DISCRIMINANT_FOR_MERGE: isize = 2;

        let mut library = Library::new();

        // imports
        let compare_digests = DataType::Digest.compare();
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));

        let load_digest = triton_asm! {
            // _ *digest
            push {Digest::LEN - 1} add
            read_mem {Digest::LEN}
            pop 1
            hint digest = stack[0..5]
            // _ [digest]
        };

        let new_claim = library.import(Box::new(NewClaim));
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

        let audit_witness_of_proof_collection =
            library.import(Box::new(VerifyNdSiIntegrity::<ProofCollection>::default()));
        let audit_witness_of_update =
            library.import(Box::new(VerifyNdSiIntegrity::<WitnessOfUpdate>::default()));
        let audit_witness_of_merge =
            library.import(Box::new(VerifyNdSiIntegrity::<WitnessOfMerge>::default()));

        let claim_field_with_size_output = triton_asm!(read_mem 1 push 1 add swap 1 push -1 add);

        let verify_scripts_loop_label = "neptune_transaction_verify_lock_scripts_loop".to_string();
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

                dup 1 addi 2
                hint proof_collection_ptr = stack[0]
                // _ [txk_digest] *spw disc *proof_collection

                dup 0
                call {audit_witness_of_proof_collection}
                // _ [txk_digest] *spw disc *proof_collection proof_collection_size

                pop 1
                // _ [txk_digest] *spw disc *proof_collection


                /* check kernel MAST hash */

                dup 0 {&proof_collection_field_kernel_mast_hash}
                // [txk_digest] *spw disc *proof_collection *kernel_mast_hash

                {&load_digest}
                // [txk_digest] *spw disc *proof_collection [kernel_mast_hash]

                dup 12
                dup 12
                dup 12
                dup 12
                dup 12
                // [txk_digest] *spw disc *proof_collection [kernel_mast_hash] [txk_digest]

                {&compare_digests}
                assert
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

                dup 1 add push 2 add
                hint eof = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes *eof

                swap 1 push 2 add
                hint type_script_hashes_i = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *eof *type_script_hashes[0]

                swap 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes[0] *eof


                dup 6
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes[0] *eof *proof_collection

                {&proof_collection_field_type_scripts_halt} push 1 add
                hint type_script_proofs_i_si = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes *eof *type_script_proofs[0]_si

                read_mem 1
                hint proof_size = stack[1]
                push 2 add
                swap 1
                hint type_script_proofs_i = stack[1]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes *eof *type_script_proofs[0] proof_size

                call {verify_scripts_loop_label}

                pop 5 pop 4
                addi {-DISCRIMINANT_FOR_PROOF_COLLECTION - 1}
                // [txk_digest] *spw -1

                return
        };

        let construct_claim_about_program_digest = |Digest([d0, d1, d2, d3, d4])| {
            triton_asm! {
                // BEFORE: _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant
                // AFTER:  _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant *claim

                /* construct Claim */
                push {Digest::LEN * 2}      hint claim_input_len = stack[0]
                push 0                      hint claim_output_len = stack[0]
                call {new_claim}
                // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant *claim *output *input *program_digest

                /* populate Claim's program digest */
                push {d4} push {d3} push {d2} push {d1} push {d0}
                pick 5
                write_mem 5
                pop 1
                // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant *claim *output *input

                /* populate Claim's input */
                dup 5
                dup 7
                dup 9
                dup 11
                dup 13
                pick 5
                write_mem {Digest::LEN}
                // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant *claim *output *input'

                dup 14 dup 14 dup 14 dup 14 dup 14
                pick 1 pick 2 pick 3 pick 4         // reverse digest
                pick 5 write_mem {Digest::LEN}
                pop 1
                // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant *claim *output

                pop 1
                // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant *claim
            }
        };

        let update_case_label = "neptune_transaction_single_proof_case_update";
        let update_case_body = triton_asm! {
            // BEFORE: _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant
            // AFTER:  _ [own_digest; 5] [txk_digest] *single_proof_witness -1
            {update_case_label}:
                {&construct_claim_about_program_digest(Update.hash())}
                // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant *claim

                dup 2
                addi 2                      hint witness_of_update = stack[0]
                // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant *claim *witness_of_update

                dup 0
                call {audit_witness_of_update}
                // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant *claim *witness_of_update size

                pop 1
                // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant *claim *witness_of_update

                {&field!(WitnessOfUpdate::proof)}
                // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant *claim *proof_of_update

                call {stark_verify}
                // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant

                addi {-DISCRIMINANT_FOR_UPDATE - 1}
                // _ [own_digest; 5] [txk_digest] *single_proof_witness -1

                return
        };

        let merge_case_label = "neptune_transaction_single_proof_case_merge";
        let merge_case_body = triton_asm! {
            {merge_case_label}:
                {&construct_claim_about_program_digest(Merge.hash())}
                // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant *claim

                dup 2
                addi 2                      hint witness_of_merge = stack[0]
                // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant *claim *witness_of_merge

                dup 0
                call {audit_witness_of_merge}
                // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant *claim *witness_of_merge size

                pop 1
                // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant *claim *witness_of_merge

                {&field!(WitnessOfMerge::proof)}
                // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant *claim *proof_of_merge

                call {stark_verify}
                // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant

                addi {-DISCRIMINANT_FOR_MERGE - 1}
                // _ [own_digest; 5] [txk_digest] *single_proof_witness -1

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

            assert
            // _ discr
        );

        let main = triton_asm! {
            // _

            dup 15 dup 15 dup 15 dup 15 dup 15
            // _ [own_digest; 5]

            read_io 5
            // _ [own_digest; 5] [txk_digest]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // _ [own_digest; 5] [txk_digest] *single_proof_witness

            read_mem 1 addi 1 swap 1
            // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant

            {&verify_discriminant_has_legal_value}
            // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant

            /* match discriminant */
            dup 0 push {DISCRIMINANT_FOR_PROOF_COLLECTION} eq
            skiz call {proof_collection_case_label}

            dup 0 push {DISCRIMINANT_FOR_UPDATE} eq
            skiz call {update_case_label}

            dup 0 push {DISCRIMINANT_FOR_MERGE} eq
            skiz call {merge_case_label}

            // _ [own_digest; 5] [txk_digest] *single_proof_witness discriminant

            // a discriminant of -1 indicates that some branch was executed
            push -1
            eq
            assert

            pop 1 pop 5 pop 5
            // _

            halt
        };

        triton_asm! {
            {&main}
            {&proof_collection_case_body}
            {&update_case_body}
            {&merge_case_body}
            {&verify_scripts_loop_body}
            {&library.all_imports()}
        }
    }

    /// Get the program hash digest.
    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}

#[cfg(test)]
mod test {
    use assert2::let_assert;
    use proptest::prelude::Arbitrary;
    use proptest::prelude::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::triton_vm::prelude::BFieldCodec;

    use super::*;
    use crate::job_queue::triton_vm::TritonVmJobPriority;
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::blockchain::transaction::validity::merge::test::deterministic_merge_witness;
    use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
    use crate::models::blockchain::transaction::validity::single_proof::SingleProofWitness;
    use crate::models::blockchain::transaction::validity::update::test::deterministic_update_witness_only_additions;
    use crate::models::blockchain::transaction::validity::update::Update;
    use crate::models::blockchain::type_scripts::time_lock::arbitrary_primitive_witness_with_expired_timelocks;
    use crate::models::proof_abstractions::mast_hash::MastHash;
    use crate::models::proof_abstractions::tasm::program::ConsensusError;
    use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
    use crate::models::proof_abstractions::timestamp::Timestamp;

    #[tokio::test]
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
            let consensus_err = SingleProof.run_tasm(&pub_input, nondeterminism);

            let_assert!(Err(ConsensusError::TritonVMPanic(_, instruction_err)) = consensus_err);
            let_assert!(InstructionError::AssertionFailed(assertion_err) = instruction_err);
            let_assert!(Some(err_id) = assertion_err.id);
            assert_eq!(42, err_id);
        }
    }

    #[tokio::test]
    async fn can_verify_via_valid_proof_collection() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with((2, 2, 2))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let txk_mast_hash = primitive_witness.kernel.mast_hash();

        let proof_collection = ProofCollection::produce(
            &primitive_witness,
            &TritonVmJobQueue::dummy(),
            TritonVmJobPriority::default().into(),
        )
        .await
        .unwrap();
        assert!(proof_collection.verify(txk_mast_hash));

        let single_proof_witness = SingleProofWitness::from_collection(proof_collection);
        let txk_mast_hash_as_input_as_public_input =
            PublicInput::new(txk_mast_hash.reversed().values().encode());

        let nondeterminism = single_proof_witness.nondeterminism();

        let rust_result = SingleProof
            .run_rust(
                &txk_mast_hash_as_input_as_public_input,
                nondeterminism.clone(),
            )
            .expect("rust run should pass");

        let tasm_result = SingleProof
            .run_tasm(&txk_mast_hash_as_input_as_public_input, nondeterminism)
            .expect("tasm run should pass");

        assert_eq!(rust_result, tasm_result);
    }

    #[tokio::test]
    async fn can_verify_via_valid_proof_collection_if_timelocked_expired() {
        let mut test_runner = TestRunner::deterministic();
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
            &TritonVmJobQueue::dummy(),
            TritonVmJobPriority::default().into(),
        )
        .await
        .unwrap();
        assert!(proof_collection.verify(txk_mast_hash));

        println!("Have proof collection. \\o/");

        let single_proof_witness = SingleProofWitness::from_collection(proof_collection);
        let txk_mast_hash_as_input_as_public_input =
            PublicInput::new(txk_mast_hash.reversed().values().encode());

        let nondeterminism = single_proof_witness.nondeterminism();

        let rust_result = SingleProof
            .run_rust(
                &txk_mast_hash_as_input_as_public_input,
                nondeterminism.clone(),
            )
            .expect("rust run should pass");

        let tasm_result = SingleProof
            .run_tasm(&txk_mast_hash_as_input_as_public_input, nondeterminism)
            .expect("tasm run should pass");

        assert_eq!(rust_result, tasm_result);
    }

    #[tokio::test]
    async fn can_verify_via_valid_update() {
        let witness_for_update = deterministic_update_witness_only_additions(2, 2, 2).await;

        let claim_for_update = witness_for_update.claim();
        let nondeterminism_for_update = witness_for_update.nondeterminism();
        let proof = Update
            .prove(
                &claim_for_update,
                nondeterminism_for_update,
                &TritonVmJobQueue::dummy(),
                TritonVmJobPriority::default().into(),
            )
            .await
            .unwrap();
        Stark::default().verify(&claim_for_update, &proof).unwrap();

        let witness_of_update = WitnessOfUpdate {
            proof,
            new_kernel_mast_hash: witness_for_update.new_kernel_mast_hash(),
        };
        assert_eq!(
            witness_for_update.claim(),
            witness_of_update.claim_of_update()
        );

        let single_proof_witness = SingleProofWitness::Update(witness_of_update);
        let single_proof_claim = single_proof_witness.claim();
        let nondeterminism = single_proof_witness.nondeterminism();

        let public_input = single_proof_claim.input.into();
        let rust_result = SingleProof.run_rust(&public_input, nondeterminism.clone());
        let tasm_result = SingleProof.run_tasm(&public_input, nondeterminism);
        assert_eq!(rust_result.unwrap(), tasm_result.unwrap());
    }

    #[tokio::test]
    async fn can_verify_via_valid_merge() {
        let witness_for_merge = deterministic_merge_witness((2, 2, 2), (2, 2, 2)).await;

        let claim_for_merge = witness_for_merge.claim();
        let nondeterminism_for_witness = witness_for_merge.nondeterminism();
        let proof = Merge
            .prove(
                &claim_for_merge,
                nondeterminism_for_witness,
                &TritonVmJobQueue::dummy(),
                TritonVmJobPriority::default().into(),
            )
            .await
            .unwrap();
        Stark::default().verify(&claim_for_merge, &proof).unwrap();

        let witness_of_merge = WitnessOfMerge {
            proof,
            new_kernel_mast_hash: witness_for_merge.new_kernel_mast_hash(),
        };
        assert_eq!(witness_for_merge.claim(), witness_of_merge.claim_of_merge());

        let single_proof_witness = SingleProofWitness::Merger(witness_of_merge);
        let single_proof_claim = single_proof_witness.claim();
        let nondeterminism = single_proof_witness.nondeterminism();

        let public_input = single_proof_claim.input.into();
        let rust_result = SingleProof.run_rust(&public_input, nondeterminism.clone());
        let tasm_result = SingleProof.run_tasm(&public_input, nondeterminism);
        assert_eq!(rust_result.unwrap(), tasm_result.unwrap());
    }
}
