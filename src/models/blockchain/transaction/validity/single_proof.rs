use std::collections::HashMap;

use crate::models::blockchain::transaction::validity::kernel_to_outputs::KernelToOutputs;
use crate::models::blockchain::transaction::validity::tasm::proof_collection::generate_rri_claim::GenerateRriClaim;
use crate::models::blockchain::transaction::Claim;
use crate::models::proof_abstractions::tasm::builtins::{self as tasmlib};
use itertools::Itertools;
use tasm_lib::data_type::DataType;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::{DynMalloc, Library, TasmObject};
use tasm_lib::triton_vm::prelude::{BFieldCodec, LabelledInstruction};
use tasm_lib::triton_vm::program::{NonDeterminism, Program, PublicInput};
use tasm_lib::triton_vm::proof::Proof;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::twenty_first::error::BFieldCodecError;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tasm_lib::{field, Digest};

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
        let dyn_malloc = library.import(Box::new(DynMalloc));
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));

        // aliases
        let push_digest = |d: Digest| {
            triton_asm! {
                push {d.values()[4]}
                push {d.values()[3]}
                push {d.values()[2]}
                push {d.values()[1]}
                push {d.values()[0]}
            }
        };
        let dup_digest_reverse = |s: usize| {
            assert!(s < 8);
            triton_asm! {
                dup {s}
                dup {s+2}
                dup {s+4}
                dup {s+6}
                dup {s+8}
            }
        };

        // Creates a new Claim object in memory and populates the size and length
        // indicators of the input and output vectors, respectively. Returns pointers
        // to
        //  - the claim
        //  - the output
        //  - the input
        //  - the program digest.
        let new_claim_with_io_lengths = |il: usize, ol: usize| {
            triton_asm! {
                // BEFORE: _
                // AFTER: _ *new_claim *output *input *program_digest

                call {dyn_malloc}
                hint new_claim = stack[0]
                // _ *new_claim

                push {ol} push {ol+1} dup 2
                // _ *new_claim il (ol+1) *output_si

                write_mem 2
                hint output = stack[0]
                // _ *new_claim *output


                push {il} push {il+1} dup 2
                // _ *new_claim *output il (il+1) *output

                push {ol} add
                // _ *new_claim *output il (il+1) *input_si

                write_mem 2
                hint input = stack[0]
                // _ *new_claim *output *input

                dup 0 push {il} add
                hint program_digest = stack[0]
                // _ *new_claim *output *input *program_digest
            }
        };

        let load_digest = triton_asm! {
            // _ *digest
            push {Digest::LEN - 1} add
            read_mem {Digest::LEN}
            pop 1
            hint digest = stack[0..5]
            // _ [digest]
        };

        let store_digest = triton_asm! {
            // _ [digest] *addr
            write_mem {Digest::LEN}
            pop 1
            // _
        };

        let discriminant_for_proof_collection = 0;
        let proof_collection_case_label =
            "neptune_transaction_single_proof_case_collection".to_string();
        let proof_collection_field_kernel_mast_hash = field!(ProofCollection::kernel_mast_hash);
        let proof_collection_field_removal_records_integrity =
            field!(ProofCollection::removal_records_integrity);

        let assemble_rri_claim = library.import(Box::new(GenerateRriClaim));

        let proof_collection_field_salted_outputs_hash =
            field!(ProofCollection::salted_outputs_hash);
        let push_k2o_hash = push_digest(KernelToOutputs.program().hash());

        let assemble_k2o_claim = triton_asm!(
            // [txk_digest] *spw disc *proof_collection

            {&new_claim_with_io_lengths(Digest::LEN, Digest::LEN)}
            hint k2o_claim = stack[3]
            // [txk_digest] *spw disc *proof_collection *k2o_claim *output *input *program_digest

             dup 4 {&proof_collection_field_salted_outputs_hash}
             // [txk_digest] *spw disc *proof_collection *k2o_claim *output *input *program_digest *soh

             {&load_digest}
             // [txk_digest] *spw disc *proof_collection *k2o_claim *output *input *program_digest [soh]

             dup {Digest::LEN+2} {&store_digest}
             // [txk_digest] *spw disc *proof_collection *k2o_claim *output *input *program_digest

             swap 2 pop 1
             // [txk_digest] *spw disc *proof_collection *k2o_claim *program_digest *input

             {&dup_digest_reverse(6)}
             dup 5
             // [txk_digest] *spw disc *proof_collection *k2o_claim *program_digest *input [txk_digest_reversed] *input

             {&store_digest}
             // [txk_digest] *spw disc *proof_collection *k2o_claim *program_digest *input

             pop 1
             // [txk_digest] *spw disc *proof_collection *k2o_claim *program_digest

             {&push_k2o_hash}
             // [txk_digest] *spw disc *proof_collection *k2o_claim *program_digest [k2o_digest]

             dup {Digest::LEN} write_mem {Digest::LEN}
             // [txk_digest] *spw disc *proof_collection *k2o_claim *program_digest *next_free_address
        );

        let proof_collection_field_kernel_to_outputs = field!(ProofCollection::kernel_to_outputs);
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
                {&assemble_k2o_claim}
                // [txk_digest] *spw disc *proof_collection *k2o_claim *program_hash *first_free_address

                pop 2
                // [txk_digest] *spw disc *proof_collection *k2o_claim

                dup 1 {&proof_collection_field_kernel_to_outputs}
                // [txk_digest] *spw disc *proof_collection *k2o_claim *proof

                call {stark_verify}

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
            {&library.all_imports()}
        }
    }
}

#[cfg(test)]
mod test {
    use crate::models::proof_abstractions::mast_hash::MastHash;
    use crate::models::proof_abstractions::SecretWitness;
    use proptest::{
        prelude::{Arbitrary, Strategy},
        test_runner::TestRunner,
    };
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

        println!("run_rust succeeded!!1one");

        SingleProof
            .run_tasm(&txk_mast_hash_as_input_as_public_input, nondeterminism)
            .expect("tasm run should pass");
    }
}
