use std::collections::HashMap;

use crate::models::blockchain::transaction::Claim;
use crate::models::proof_abstractions::tasm::builtins::{self as tasmlib};
use itertools::Itertools;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::TasmObject;
use tasm_lib::triton_vm::prelude::{BFieldCodec, LabelledInstruction};
use tasm_lib::triton_vm::program::{NonDeterminism, Program, PublicInput};
use tasm_lib::triton_vm::proof::Proof;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::twenty_first::error::BFieldCodecError;
use tasm_lib::Digest;

use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::SecretWitness;
use crate::tasm_lib::memory::encode_to_memory;
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
            } // SingleProofWitness::Upodate(_) => todo!(),
        }
    }

    fn program(&self) -> Program {
        Program::new(&SingleProof.code())
    }

    fn nondeterminism(&self) -> NonDeterminism {
        // set memory
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self.clone(),
        );

        NonDeterminism::default().with_ram(memory)
    }

    fn output(&self) -> Vec<tasm_lib::triton_vm::prelude::BFieldElement> {
        std::vec![]
    }

    fn claim(&self) -> tasm_lib::triton_vm::prelude::Claim {
        tasm_lib::triton_vm::prelude::Claim::new(
            self.program()
                .hash::<crate::models::blockchain::shared::Hash>(),
        )
        .with_input(self.standard_input().individual_tokens)
        .with_output(self.output())
    }
}

#[derive(Debug, Clone)]
pub struct SingleProof;

impl ConsensusProgram for SingleProof {
    fn source(&self) {
        let txk_digest: Digest = tasmlib::tasm_io_read_stdin___digest();
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
                    program_digest: ProofCollection::REMOVAL_RECORDS_INTEGRITY_PROGRAM_DIGEST,
                    input: txk_mast_hash_as_input.clone(),
                    output: salted_inputs_hash_as_output.clone(),
                };
                let rri = tasmlib::verify(
                    Stark::default(),
                    removal_records_integrity_claim,
                    &pc.removal_records_integrity,
                );
                assert!(rri);

                let kernel_to_outputs_claim: Claim = Claim {
                    program_digest: ProofCollection::KERNEL_TO_OUTPUTS_PROGRAM_DIGEST,
                    input: txk_mast_hash_as_input.clone(),
                    output: salted_outputs_hash_as_output.clone(),
                };
                let k2o = tasmlib::verify(
                    Stark::default(),
                    kernel_to_outputs_claim,
                    &pc.kernel_to_outputs,
                );
                assert!(k2o);

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
                    program_digest: ProofCollection::COLLECT_LOCK_SCRIPTS_PROGRAM_DIGEST,
                    input: salted_inputs_hash_as_input.clone(),
                    output: lock_script_hashes_as_output,
                };
                let cls: bool = tasmlib::verify(
                    Stark::default(),
                    collect_lock_scripts_claim,
                    &pc.collect_lock_scripts,
                );
                assert!(cls);

                let mut type_script_hashes_as_output: Vec<BFieldElement> =
                    Vec::<BFieldElement>::new();
                let mut i: usize = 0;
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
                    program_digest: ProofCollection::COLLECT_TYPE_SCRIPTS_PROGRAM_DIGEST,
                    input: [
                        salted_inputs_hash_as_input.clone(),
                        salted_outputs_hash_as_input.clone(),
                    ]
                    .concat(),
                    output: type_script_hashes_as_output,
                };
                let cts: bool = tasmlib::verify(
                    Stark::default(),
                    collect_type_scripts_claim,
                    &pc.collect_type_scripts,
                );
                assert!(cts);

                let mut i: usize = 0;
                while i < pc.lock_script_hashes.len() {
                    let lock_script_hash = pc.lock_script_hashes[i];
                    let claim: Claim = Claim {
                        program_digest: lock_script_hash,
                        input: txk_mast_hash_as_input.clone(),
                        output: Vec::<BFieldElement>::new(),
                    };
                    let lock_script_halts_proof: &Proof = &pc.lock_scripts_halt[i];
                    let lock_script_halts: bool =
                        tasmlib::verify(Stark::default(), claim, lock_script_halts_proof);
                    assert!(lock_script_halts);

                    i += 1;
                }

                let type_script_input: Vec<BFieldElement> = [
                    txk_mast_hash_as_input,
                    salted_inputs_hash_as_input,
                    salted_outputs_hash_as_input,
                ]
                .concat();
                let mut i = 0;
                while i < pc.type_script_hashes.len() {
                    let type_script_hash = pc.type_script_hashes[i];
                    let claim: Claim = Claim {
                        program_digest: type_script_hash,
                        input: type_script_input.clone(),
                        output: Vec::<BFieldElement>::new(),
                    };
                    let type_script_halts_proof: &Proof = &pc.type_scripts_halt[i];
                    let type_script_halts: bool =
                        tasmlib::verify(Stark::default(), claim, type_script_halts_proof);
                    assert!(type_script_halts);
                    i += 1;
                }
            } // SingleProofWitness::Upodate(_) => todo!(),
        }
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        todo!()
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

        SingleProof
            .run_rust(
                &txk_mast_hash_as_input_as_public_input,
                single_proof_witness.nondeterminism(),
            )
            .expect("rust run failed");
    }
}
