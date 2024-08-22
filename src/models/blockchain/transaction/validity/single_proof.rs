use std::collections::HashMap;

use crate::models::blockchain::transaction::validity::collect_type_scripts::CollectTypeScripts;
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

use crate::models::blockchain::transaction::validity::collect_lock_scripts::CollectLockScripts;
use crate::models::blockchain::transaction::validity::kernel_to_outputs::KernelToOutputs;
use crate::models::blockchain::transaction::validity::removal_records_integrity::RemovalRecordsIntegrity;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::SecretWitness;
use crate::tasm_lib::memory::encode_to_memory;
use crate::triton_vm::triton_asm;
use crate::BFieldElement;
use tasm_lib::triton_vm;

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
            let rri_claim = proof_collection.removal_records_integrity_claim();
            let rri_proof = &proof_collection.removal_records_integrity;
            let stark_verify_snippet = StarkVerify::new_with_dynamic_layout(Stark::default());
            stark_verify_snippet.update_nondeterminism(&mut nondeterminism, rri_proof, &rri_claim);
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

                let txk_mast_hash_as_input: Vec<BFieldElement> =
                    txk_digest.reversed().values().to_vec();
                let salted_inputs_hash_as_input: Vec<BFieldElement> =
                    pc.salted_inputs_hash.reversed().values().to_vec();
                let salted_inputs_hash_as_output: Vec<BFieldElement> =
                    pc.salted_inputs_hash.values().to_vec();
                let salted_outputs_hash_as_input: Vec<BFieldElement> =
                    pc.salted_outputs_hash.reversed().values().to_vec();
                let salted_outputs_hash_as_output: Vec<BFieldElement> =
                    pc.salted_outputs_hash.values().to_vec();

                let removal_records_integrity_claim: Claim = Claim {
                    program_digest: RemovalRecordsIntegrity.program().hash(),
                    input: txk_mast_hash_as_input.clone(),
                    output: salted_inputs_hash_as_output.clone(),
                };
                assert!(triton_vm::verify(
                    Stark::default(),
                    &removal_records_integrity_claim,
                    &pc.removal_records_integrity
                ));
                tasmlib::verify_stark(
                    Stark::default(),
                    &removal_records_integrity_claim,
                    &pc.removal_records_integrity,
                );

                let kernel_to_outputs_claim: Claim = Claim {
                    program_digest: KernelToOutputs.program().hash(),
                    input: txk_mast_hash_as_input.clone(),
                    output: salted_outputs_hash_as_output.clone(),
                };
                tasmlib::verify_stark(
                    Stark::default(),
                    &kernel_to_outputs_claim,
                    &pc.kernel_to_outputs,
                );

                let mut lock_script_hashes_as_output: Vec<BFieldElement> =
                    Vec::<BFieldElement>::new();
                let mut i: usize = 0;
                while i < pc.lock_script_hashes.len() {
                    let lock_script_hash: Digest = pc.lock_script_hashes[i];
                    let mut j: usize = 0;
                    while j < Digest::LEN {
                        lock_script_hashes_as_output.push(lock_script_hash.values()[j]);
                        j += 1;
                    }
                    i += 1;
                }
                let collect_lock_scripts_claim: Claim = Claim {
                    program_digest: CollectLockScripts.program().hash(),
                    input: salted_inputs_hash_as_input.clone(),
                    output: lock_script_hashes_as_output,
                };
                tasmlib::verify_stark(
                    Stark::default(),
                    &collect_lock_scripts_claim,
                    &pc.collect_lock_scripts,
                );

                let mut type_script_hashes_as_output: Vec<BFieldElement> =
                    Vec::<BFieldElement>::new();
                i = 0;
                while i < pc.type_script_hashes.len() {
                    let type_script_hash: Digest = pc.type_script_hashes[i];
                    let mut j: usize = 0;
                    while j < Digest::LEN {
                        type_script_hashes_as_output.push(type_script_hash.values()[j]);
                        j += 1;
                    }
                    i += 1;
                }
                let collect_type_scripts_claim: Claim = Claim {
                    program_digest: CollectTypeScripts.program().hash(),
                    input: [
                        salted_inputs_hash_as_input.clone(),
                        salted_outputs_hash_as_input.clone(),
                    ]
                    .concat(),
                    output: type_script_hashes_as_output,
                };
                tasmlib::verify_stark(
                    Stark::default(),
                    &collect_type_scripts_claim,
                    &pc.collect_type_scripts,
                );

                i = 0;
                while i < pc.lock_script_hashes.len() {
                    let lock_script_hash = pc.lock_script_hashes[i];
                    let claim: Claim = Claim {
                        program_digest: lock_script_hash,
                        input: txk_mast_hash_as_input.clone(),
                        output: Vec::<BFieldElement>::new(),
                    };
                    let lock_script_halts_proof: &Proof = &pc.lock_scripts_halt[i];
                    tasmlib::verify_stark(Stark::default(), &claim, lock_script_halts_proof);

                    i += 1;
                }

                let type_script_input: Vec<BFieldElement> = [
                    txk_mast_hash_as_input,
                    salted_inputs_hash_as_input,
                    salted_outputs_hash_as_input,
                ]
                .concat();
                i = 0;
                while i < pc.type_script_hashes.len() {
                    let type_script_hash = pc.type_script_hashes[i];
                    let claim: Claim = Claim {
                        program_digest: type_script_hash,
                        input: type_script_input.clone(),
                        output: Vec::<BFieldElement>::new(),
                    };
                    let type_script_halts_proof: &Proof = &pc.type_scripts_halt[i];
                    tasmlib::verify_stark(Stark::default(), &claim, type_script_halts_proof);
                    i += 1;
                }
            } // SingleProofWitness::Update(_) => todo!(),
        }
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        let mut library = Library::new();

        let push_digest = |d: Digest| {
            triton_asm! {
                push {d.values()[4]}
                push {d.values()[3]}
                push {d.values()[2]}
                push {d.values()[1]}
                push {d.values()[0]}
            }
        };

        let compare_digests = DataType::Digest.compare();
        let dyn_malloc = library.import(Box::new(DynMalloc));
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));

        let discriminant_for_proof_collection = 0;
        let proof_collection_case_label =
            "neptune_transaction_single_proof_case_collection".to_string();
        let proof_collection_field_kernel_mast_hash = field!(ProofCollection::kernel_mast_hash);
        let proof_collection_field_salted_inputs_hash = field!(ProofCollection::salted_inputs_hash);
        let proof_collection_field_removal_records_integrity =
            field!(ProofCollection::removal_records_integrity);
        let push_rri_hash = push_digest(RemovalRecordsIntegrity.program().hash());
        let proof_collection_case_body = triton_asm! {
            // BEFORE: [txk_digest] *single_proof_witness discriminant
            // AFTER: [txk_digest] *single_proof_witness discriminant
            {proof_collection_case_label}:
                // [txk_digest] *single_proof_witness discriminant

                dup 1 push 1 add
                // [txk_digest] *spw disc *proof_collection

                // Not *proof_collection_si? Unclear.


                /* check kernel MAST hash */

                dup 0 {&proof_collection_field_kernel_mast_hash}
                // [txk_digest] *spw disc *proof_collection *kernel_mast_hash

                push {Digest::LEN - 1}
                read_mem {Digest::LEN}
                pop 1
                // [txk_digest] *spw disc *proof_collection [kernel_mast_hash]

                dup 11
                dup 11
                dup 11
                dup 11
                dup 11
                // [txk_digest] *spw disc *proof_collection [kernel_mast_hash] [txk_digest]

                {&compare_digests}
                assert
                // [txk_digest] *spw disc *proof_collection


                /* create and verify removal records integrity claim */

                call {dyn_malloc} dup 0
                // [txk_digest] *spw disc *proof_collection *rri_claim *rri_claim

                push {Digest::LEN} swap 1
                // [txk_digest] *spw disc *proof_collection *rri_claim output_si *rri_claim

                write_mem 1
                // [txk_digest] *spw disc *proof_collection *rri_claim *output

                dup 2 {&proof_collection_field_salted_inputs_hash}
                // [txk_digest] *spw disc *proof_collection *rri_claim *output *salted_inputs_hash

                push {Digest::LEN - 1} add read_mem {Digest::LEN} pop 1
                // [txk_digest] *spw disc *proof_collection *rri_claim *output [salted_inputs_hash]

                dup 5
                // [txk_digest] *spw disc *proof_collection *rri_claim *output [salted_inputs_hash] *output

                write_mem {Digest::LEN}
                // [txk_digest] *spw disc *proof_collection *rri_claim *output *input_si

                swap 1 pop 1
                // [txk_digest] *spw disc *proof_collection *rri_claim *input_si

                push {Digest::LEN} swap 1 write_mem 1
                // [txk_digest] *spw disc *proof_collection *rri_claim *input

                dup 5 dup 7 dup 9 dup 11 dup 13 dup 5
                // [txk_digest] *spw disc *proof_collection *rri_claim *input [txk_digest_reversed] *input

                write_mem 5
                // [txk_digest] *spw disc *proof_collection *rri_claim *input *program_hash

                swap 1 pop 1
                // [txk_digest] *spw disc *proof_collection *rri_claim *program_hash

                {&push_rri_hash}
                // [txk_digest] *spw disc *proof_collection *rri_claim *program_hash [rri_hash]

                dup {Digest::LEN} write_mem {Digest::LEN}
                // [txk_digest] *spw disc *proof_collection *rri_claim *first_free_address

                dup 1 dup 3 {&proof_collection_field_removal_records_integrity}
                // [txk_digest] *spw disc *proof_collection *rri_claim *first_free_address *rri_claim *rri_proof

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
    use proptest::{
        prelude::{Arbitrary, Strategy},
        test_runner::TestRunner,
    };
    use tasm_lib::triton_vm::{prelude::BFieldCodec, program::PublicInput};

    use crate::models::proof_abstractions::mast_hash::MastHash;
    use crate::models::proof_abstractions::SecretWitness;
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
        println!(
            "number of nondeterministic digests: {}",
            nondeterminism.digests.len()
        );

        println!(
            "First digest of nd digest stream: {}",
            nondeterminism.digests[0]
        );

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
