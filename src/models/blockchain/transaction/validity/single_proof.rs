use std::collections::HashMap;

use crate::models::blockchain::transaction::validity::tasm::claims::generate_collect_lock_scripts_claim::GenerateCollectLockScriptsClaim;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_collect_type_scripts_claim::GenerateCollectTypeScriptsClaim;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_k2o_claim::GenerateK2oClaim;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_lock_script_claim_template::GenerateLockScriptClaimTemplate;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_type_script_claim_template::GenerateTypeScriptClaimTemplate;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_rri_claim::GenerateRriClaim;
use crate::models::blockchain::transaction::Claim;
use crate::models::proof_abstractions::tasm::builtins::{self as tasmlib};
use itertools::Itertools;
use tasm_lib::data_type::DataType;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::TasmObject;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::program::PublicInput;
use tasm_lib::triton_vm::program::Program;
use tasm_lib::triton_vm::program::NonDeterminism;
use tasm_lib::triton_vm::proof::Proof;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::twenty_first::error::BFieldCodecError;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tasm_lib::Digest;
use tasm_lib::field;

use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::SecretWitness;
use crate::tasm_lib::memory::encode_to_memory;
use crate::triton_vm::triton_asm;
use crate::BFieldElement;

use super::proof_collection::ProofCollection;

#[derive(Debug, Clone, BFieldCodec)]
pub enum SingleProofWitness {
    Collection(ProofCollection),
    // Update(Box<SingleProofWitness>),
    // Merger(MergerWitness)

    // Wait for Hard Fork One:
    // IntegralMempool(IntegralMempoolMembershipWitness)
}

impl SingleProofWitness {
    pub fn from_collection(proof_collection: ProofCollection) -> Self {
        SingleProofWitness::Collection(proof_collection)
    }
}

/// This implementation of `TasmObject` is required for `decode_iter` and the
/// method `decode_from_memory` that relies on it. The field getters are not
/// relevant because the type in question is an enum.
impl TasmObject for SingleProofWitness {
    fn get_field(_field_name: &str) -> Vec<LabelledInstruction> {
        todo!()
    }

    fn get_field_with_size(_field_name: &str) -> Vec<LabelledInstruction> {
        todo!()
    }

    fn get_field_start_with_jump_distance(_field_name: &str) -> Vec<LabelledInstruction> {
        todo!()
    }

    fn decode_iter<Itr: Iterator<Item = BFieldElement>>(
        iterator: &mut Itr,
    ) -> std::result::Result<Box<Self>, Box<dyn std::error::Error + Send + Sync>> {
        // let Some(size) = iterator.next() else {
        //     return Err(Box::new(BFieldCodecError::EmptySequence));
        // };
        // if size.value() == 0 {
        //     return Err(Box::new(BFieldCodecError::EmptySequence));
        // }
        // println!("single proof witness size: {}", size);
        let Some(discriminant) = iterator.next() else {
            return Err(Box::new(BFieldCodecError::EmptySequence));
        };
        println!("single proof witness discriminant: {}", discriminant);
        match discriminant.value() {
            // Collection
            0 => {
                let Some(proof_collection_size) = iterator.next() else {
                    return Err(Box::new(BFieldCodecError::EmptySequence));
                };
                let proof_collection_data = iterator
                    .take(proof_collection_size.value() as usize)
                    .collect_vec();
                let proof_collection = *ProofCollection::decode(&proof_collection_data)?;
                Ok(Box::new(SingleProofWitness::Collection(proof_collection)))
            }
            _ => Err(Box::new(BFieldCodecError::ElementOutOfRange)),
        }
    }

    fn label_friendly_name() -> String {
        "SingleProofWitness".to_string()
    }

    fn compute_size_and_assert_valid_size_indicator(
        _library: &mut Library,
    ) -> Vec<LabelledInstruction> {
        todo!()
    }
}

impl SecretWitness for SingleProofWitness {
    fn standard_input(&self) -> PublicInput {
        match self {
            SingleProofWitness::Collection(pc) => {
                PublicInput::new(pc.kernel_mast_hash.reversed().values().to_vec())
            } // SingleProofWitness::Update(_) => todo!(),
        }
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

        #[allow(irrefutable_let_patterns)] // drop this line when there is more than 1 variant
        if let SingleProofWitness::Collection(proof_collection) = self {
            // removal records integrity
            let rri_claim = proof_collection.removal_records_integrity_claim();
            let rri_proof = &proof_collection.removal_records_integrity;
            let stark_verify_snippet = StarkVerify::new_with_dynamic_layout(Stark::default());
            stark_verify_snippet.update_nondeterminism(&mut nondeterminism, rri_proof, &rri_claim);

            // kernel to outputs
            let k2o_claim = proof_collection.kernel_to_outputs_claim();
            let k2o_proof = &proof_collection.kernel_to_outputs;
            stark_verify_snippet.update_nondeterminism(&mut nondeterminism, k2o_proof, &k2o_claim);

            // collect lock scripts
            let cls_claim = proof_collection.collect_lock_scripts_claim();
            let cls_proof = &proof_collection.collect_lock_scripts;
            stark_verify_snippet.update_nondeterminism(&mut nondeterminism, cls_proof, &cls_claim);

            // collect type scripts
            let cts_claim = proof_collection.collect_type_scripts_claim();
            let cts_proof = &proof_collection.collect_type_scripts;
            stark_verify_snippet.update_nondeterminism(&mut nondeterminism, cts_proof, &cts_claim);

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

        nondeterminism
    }

    fn output(&self) -> Vec<BFieldElement> {
        std::vec![]
    }

    fn claim(&self) -> Claim {
        Claim::new(self.program().hash())
            .with_input(self.standard_input().individual_tokens)
            .with_output(self.output())
    }
}

#[derive(Debug, Clone)]
pub struct SingleProof;

impl ConsensusProgram for SingleProof {
    fn source(&self) {
        let txk_digest: Digest = tasmlib::tasmlib_io_read_stdin___digest();
        let start_address: BFieldElement = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let spw: SingleProofWitness = tasmlib::decode_from_memory(start_address);

        match spw {
            SingleProofWitness::Collection(pc) => {
                assert_eq!(txk_digest, pc.kernel_mast_hash);

                let removal_records_integrity_claim: Claim = pc.removal_records_integrity_claim();
                tasmlib::verify_stark(
                    Stark::default(),
                    &removal_records_integrity_claim,
                    &pc.removal_records_integrity,
                );

                let kernel_to_outputs_claim: Claim = pc.kernel_to_outputs_claim();
                tasmlib::verify_stark(
                    Stark::default(),
                    &kernel_to_outputs_claim,
                    &pc.kernel_to_outputs,
                );

                let collect_lock_scripts_claim: Claim = pc.collect_lock_scripts_claim();
                tasmlib::verify_stark(
                    Stark::default(),
                    &collect_lock_scripts_claim,
                    &pc.collect_lock_scripts,
                );

                let collect_type_scripts_claim: Claim = pc.collect_type_scripts_claim();
                tasmlib::verify_stark(
                    Stark::default(),
                    &collect_type_scripts_claim,
                    &pc.collect_type_scripts,
                );

                let mut i = 0;
                let lock_script_claims: Vec<Claim> = pc.lock_script_claims();
                assert_eq!(lock_script_claims.len(), pc.lock_script_hashes.len());
                while i < pc.lock_script_hashes.len() {
                    let claim: &Claim = &lock_script_claims[i];
                    let lock_script_halts_proof: &Proof = &pc.lock_scripts_halt[i];
                    tasmlib::verify_stark(Stark::default(), claim, lock_script_halts_proof);

                    i += 1;
                }

                i = 0;
                let type_script_claims = pc.type_script_claims();
                assert_eq!(type_script_claims.len(), pc.type_script_hashes.len());
                while i < pc.type_script_hashes.len() {
                    let claim: &Claim = &type_script_claims[i];
                    let type_script_halts_proof: &Proof = &pc.type_scripts_halt[i];
                    tasmlib::verify_stark(Stark::default(), claim, type_script_halts_proof);
                    i += 1;
                }
            } // SingleProofWitness::Update(_) => todo!(),
        }
    }

    fn code(&self) -> Vec<LabelledInstruction> {
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

        let discriminant_for_proof_collection = 0;

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
                // [txk_digest] *single_proof_witness discriminant

                dup 1 push 2 add
                hint proof_collection_ptr = stack[0]
                // [txk_digest] *spw disc *proof_collection


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

                pop 5 pop 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim

                return
        };

        let main = triton_asm! {
            //

            read_io 5
            // [txk_digest]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // [txk_digest] *single_proof_witness

            read_mem 1 push 1 add swap 1
            // [txk_digest] *single_proof_witness discriminant

            dup 0 push {discriminant_for_proof_collection} eq
            skiz call {proof_collection_case_label}
            // [txk_digest] *single_proof_witness discriminant

            halt
        };

        triton_asm! {
            {&main}
            {&proof_collection_case_body}
            {&verify_scripts_loop_body}
            {&library.all_imports()}
        }
    }
}

#[cfg(test)]
mod test {
    use crate::models::blockchain::type_scripts::time_lock::arbitrary_primitive_witness_with_timelocks;
    use crate::models::proof_abstractions::mast_hash::MastHash;
    use crate::models::proof_abstractions::timestamp::Timestamp;
    use crate::models::proof_abstractions::SecretWitness;
    use proptest::prelude::Arbitrary;
    use proptest::prelude::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::triton_vm::{prelude::BFieldCodec, program::PublicInput};

    use crate::models::{
        blockchain::transaction::{
            primitive_witness::PrimitiveWitness,
            validity::{
                proof_collection::ProofCollection,
                single_proof::{SingleProof, SingleProofWitness},
            },
        },
        proof_abstractions::tasm::program::ConsensusProgram,
    };

    #[test]
    fn can_verify_transaction_via_valid_proof_collection() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with((2, 2, 2))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let txk_mast_hash = primitive_witness.kernel.mast_hash();

        let proof_collection = ProofCollection::produce(&primitive_witness);
        assert!(proof_collection.verify(txk_mast_hash));

        let single_proof_witness = SingleProofWitness::from_collection(proof_collection);
        let txk_mast_hash_as_input_as_public_input =
            PublicInput::new(txk_mast_hash.reversed().values().encode());

        let nondeterminism = single_proof_witness.nondeterminism();

        SingleProof
            .run_rust(
                &txk_mast_hash_as_input_as_public_input,
                nondeterminism.clone(),
            )
            .expect("rust run should pass");

        SingleProof
            .run_tasm(&txk_mast_hash_as_input_as_public_input, nondeterminism)
            .expect("tasm run should pass");
    }

    #[test]
    fn can_verify_timelocked_transaction_via_valid_proof_collection() {
        let mut test_runner = TestRunner::deterministic();
        let deterministic_now = arb::<Timestamp>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let primitive_witness =
            arbitrary_primitive_witness_with_timelocks(2, 2, 2, deterministic_now)
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
        let txk_mast_hash = primitive_witness.kernel.mast_hash();

        let proof_collection = ProofCollection::produce(&primitive_witness);
        assert!(proof_collection.verify(txk_mast_hash));

        let single_proof_witness = SingleProofWitness::from_collection(proof_collection);
        let txk_mast_hash_as_input_as_public_input =
            PublicInput::new(txk_mast_hash.reversed().values().encode());

        let nondeterminism = single_proof_witness.nondeterminism();

        SingleProof
            .run_rust(
                &txk_mast_hash_as_input_as_public_input,
                nondeterminism.clone(),
            )
            .expect("rust run should pass");

        SingleProof
            .run_tasm(&txk_mast_hash_as_input_as_public_input, nondeterminism)
            .expect("tasm run should pass");
    }
}
