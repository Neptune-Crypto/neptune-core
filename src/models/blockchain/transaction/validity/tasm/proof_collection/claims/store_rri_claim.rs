use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::memory::write_words_to_memory_leave_pointer;
use tasm_lib::prelude::*;
use tasm_lib::traits::basic_snippet::BasicSnippet;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::Digest;

use crate::models::blockchain::transaction::validity::proof_collection::ProofCollection;
use crate::models::blockchain::transaction::validity::removal_records_integrity::RemovalRecordsIntegrity;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;

pub(super) struct StoreRriClaim;

impl BasicSnippet for StoreRriClaim {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "transaction_kernel_digest".to_owned()),
            (DataType::VoidPointer, "proof_collection_pointer".to_owned()),
        ]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "claim".to_owned())]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_proof_collection_store_rri_claim".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();
        let dyn_malloc = library.import(Box::new(DynMalloc));

        let push_digest = |d: Digest| {
            let [d0, d1, d2, d3, d4] = d.values();
            triton_asm! {
                push {d4}
                push {d3}
                push {d2}
                push {d1}
                push {d0}
            }
        };
        let push_rri_program_hash = push_digest(RemovalRecordsIntegrity.program().hash());

        let proof_collection_field_salted_inputs_hash = field!(ProofCollection::salted_inputs_hash);

        let load_digest = triton_asm!(
            // _ *digest

            addi {Digest::LEN - 1}
            read_mem {Digest::LEN}
            pop 1
            // _ [digest]
        );

        const ENCODED_CLAIM_SIZE: isize = 19;
        let write_claim_to_memory =
            write_words_to_memory_leave_pointer(ENCODED_CLAIM_SIZE.try_into().unwrap());

        triton_asm!(
            {entrypoint}:
                // _ [txk_digest] *proof_collection

                /* Put the entire encoding onto the stack, then write to memory */
                {&push_rri_program_hash}
                // _ [txk_digest] *proof_collection [program_digest]

                dup 6
                dup 8
                dup 10
                dup 12
                dup 14
                // _ [txk_digest] *proof_collection [program_digest] [reversed(txk_digest)]

                push {Digest::LEN}
                push {Digest::LEN + 1}
                // _ [txk_digest] *proof_collection [program_digest] [reversed(txk_digest)] input_len input_si

                dup 12
                {&proof_collection_field_salted_inputs_hash}
                // _ [txk_digest] *proof_collection [program_digest] [reversed(txk_digest)] input_len input_si *salted_inputs_hash

                {&load_digest}
                // _ [txk_digest] *proof_collection [program_digest] [reversed(txk_digest)] input_len input_si [salted_inputs_hash]

                push {Digest::LEN}
                push {Digest::LEN + 1}
                // _ [txk_digest] *proof_collection [program_digest] [reversed(txk_digest)] input_len input_si [salted_inputs_hash] output_si output_len

                call {dyn_malloc}
                // _ [txk_digest] *proof_collection [program_digest] [reversed(txk_digest)] input_len input_si [salted_inputs_hash] output_si output_len *claim

                {&write_claim_to_memory}
                // _ [txk_digest] *proof_collection (*claim + 19)

                addi {-ENCODED_CLAIM_SIZE}
                // _ [txk_digest] *proof_collection *claim

                swap 6
                pop 5
                pop 1
                // _ *claim

                return
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use itertools::Itertools;
    use proptest::prelude::Arbitrary;
    use proptest::prelude::Strategy;
    use proptest::test_runner::TestRunner;
    use rand::rngs::StdRng;
    use rand::RngCore;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::rust_shadowing_helper_functions;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::traits::function::Function;
    use tasm_lib::traits::function::FunctionInitialState;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;

    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;

    use super::*;

    #[test]
    fn unit_test() {
        ShadowedFunction::new(StoreRriClaim).test();
    }

    impl Function for StoreRriClaim {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) {
            // _ [txk_digest] *proof_collection
            let proof_collection_pointer = stack.pop().unwrap();
            let txk_digest = Digest::new([
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
            ]);

            let proof_collection: ProofCollection =
                *ProofCollection::decode_from_memory(memory, proof_collection_pointer).unwrap();
            assert_eq!(
                txk_digest, proof_collection.kernel_mast_hash,
                "Inconsistent initial state detected"
            );

            let claim = proof_collection.removal_records_integrity_claim();
            let claim_pointer =
                rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator(memory);
            encode_to_memory(memory, claim_pointer, &claim);

            stack.push(claim_pointer);
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut test_runner = TestRunner::deterministic();
            let primitive_witness = PrimitiveWitness::arbitrary_with((2, 2, 2))
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
            let proof_collection = ProofCollection::produce(&primitive_witness);

            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let pw_pointer = rng.next_u32();
            let pw_pointer = bfe!(pw_pointer);

            let mut memory = HashMap::default();
            encode_to_memory(&mut memory, pw_pointer, &proof_collection);

            let transaction_kernel_digest = proof_collection.kernel_mast_hash;

            let txk_digest_on_stack = transaction_kernel_digest
                .values()
                .into_iter()
                .rev()
                .collect_vec();
            FunctionInitialState {
                stack: [
                    self.init_stack_for_isolated_run(),
                    txk_digest_on_stack,
                    vec![pw_pointer],
                ]
                .concat(),
                memory,
            }
        }
    }
}
