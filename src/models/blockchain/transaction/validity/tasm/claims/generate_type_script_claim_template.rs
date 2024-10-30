use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use super::new_claim::NewClaim;
use crate::models::blockchain::transaction::validity::proof_collection::ProofCollection;

pub(crate) struct GenerateTypeScriptClaimTemplate;

impl BasicSnippet for GenerateTypeScriptClaimTemplate {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "*proof_collection".to_string())]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*claim".to_string()),
            (DataType::VoidPointer, "*program_digest".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_transaction_generate_type_script_claim_template".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_claim = library.import(Box::new(NewClaim));
        let proof_collection_field_kernel_mast_hash = field!(ProofCollection::kernel_mast_hash);
        let load_digest = triton_asm!(push {Digest::LEN - 1} add read_mem {Digest::LEN} pop 1);
        let dup_reversed_digest = triton_asm!(dup 0 dup 2 dup 4 dup 6 dup 8);
        let proof_collection_field_salted_outputs_hash =
            field!(ProofCollection::salted_outputs_hash);
        let proof_collection_field_salted_inputs_hash = field!(ProofCollection::salted_inputs_hash);
        let entrypoint = self.entrypoint();

        triton_asm! {
            // BEFORE: _ *proof_collection
            // AFTER: _ *claim *program_digest
            {entrypoint}:

                push {3*Digest::LEN} push 0
                call {new_claim}
                // _ *proof_collection *claim *output *input *program_digest

                swap 2 pop 1
                // _ *proof_collection *claim *program_digest *input


                /* write txk mast hash (reversed) to input */
                dup 3 {&proof_collection_field_kernel_mast_hash}
                // _ *proof_collection *claim *program_digest *input *txkmh

                {&load_digest}
                // _ *proof_collection *claim *program_digest *input [txkmh]

                {&dup_reversed_digest}
                // _ *proof_collection *claim *program_digest *input [txkmh] [txkmh_rev]

                dup 10
                // _ *proof_collection *claim *program_digest *input [txkmh] [txkmh_rev] *input

                write_mem {Digest::LEN}
                // _ *proof_collection *claim *program_digest *input [txkmh] (*input+5)

                swap 6
                pop 1
                pop 5
                // _ *proof_collection *claim *program_digest (*input+5)


                /* write salted inputs hash (reversed) to input */
                dup 3 {&proof_collection_field_salted_inputs_hash}
                // _ *proof_collection *claim *program_digest (*input+5) *salted_inputs_hash

                {&load_digest}
                // _ *proof_collection *claim *program_digest (*input+5) [salted_inputs_hash]

                {&dup_reversed_digest}
                // _ *proof_collection *claim *program_digest (*input+5) [salted_inputs_hash] [salted_inputs_hash_reversed]

                dup {2*Digest::LEN} write_mem {Digest::LEN}
                // _ *proof_collection *claim *program_digest (*input+5) [salted_inputs_hash] (*input+10)

                swap 6
                pop 1 pop 5
                // _ *proof_collection *claim *program_digest (*input+10)


                /* write salted outputs hash (reversed) to input */
                dup 3 {&proof_collection_field_salted_outputs_hash}
                // _ *proof_collection *claim *program_digest (*input+10) *salted_outputs_hash

                {&load_digest}
                // _ *proof_collection *claim *program_digest (*input+10) [salted_outputs_hash]

                {&dup_reversed_digest}
                // _ *proof_collection *claim *program_digest (*input+10) [salted_outputs_hash] [salted_outputs_hash_reversed]

                dup {2*Digest::LEN} write_mem {Digest::LEN}
                // _ *proof_collection *claim *program_digest (*input+10) [salted_outputs_hash] (*input+15)

                swap 6
                pop 2 pop 5
                // _ *proof_collection *claim *program_digest


                swap 2 pop 1 swap 1
                // _ *claim *program_digest

                return
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use proptest::arbitrary::Arbitrary;
    use proptest::prelude::Strategy;
    use proptest::test_runner::TestRunner;
    use rand::rngs::StdRng;
    use rand::RngCore;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::prelude::BasicSnippet;
    use tasm_lib::prelude::TasmObject;
    use tasm_lib::rust_shadowing_helper_functions;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::traits::function::Function;
    use tasm_lib::traits::function::FunctionInitialState;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use tasm_lib::twenty_first::bfe;
    use tasm_lib::Digest;

    use super::GenerateTypeScriptClaimTemplate;
    use crate::job_queue::triton_vm::TritonVmJobPriority;
    use crate::job_queue::triton_vm::TritonVmJobQueue;
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::blockchain::transaction::validity::proof_collection::ProofCollection;

    impl Function for GenerateTypeScriptClaimTemplate {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) {
            let proof_collection_pointer = stack.pop().unwrap();

            let proof_collection =
                *ProofCollection::decode_from_memory(memory, proof_collection_pointer).unwrap();

            let claim_pointer =
                rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator(memory);

            // length / size indicators
            memory.insert(claim_pointer, bfe!(1));
            memory.insert(claim_pointer + bfe!(1), bfe!(0));
            memory.insert(claim_pointer + bfe!(2), bfe!(3 * Digest::LEN as u64 + 1));
            memory.insert(claim_pointer + bfe!(3), bfe!(3 * Digest::LEN as u64));

            // insert reversed hashes: txk mast, salted inputs, salted outputs
            for (i, b) in [
                proof_collection.kernel_mast_hash,
                proof_collection.salted_inputs_hash,
                proof_collection.salted_outputs_hash,
            ]
            .into_iter()
            .flat_map(|d| d.reversed().values())
            .enumerate()
            {
                memory.insert(claim_pointer + bfe!(i as u64) + bfe!(4), b);
            }

            stack.push(claim_pointer);
            stack.push(claim_pointer + bfe!(4u64 + 3 * Digest::LEN as u64));
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
            let rt = tokio::runtime::Runtime::new().unwrap();
            let _guard = rt.enter();
            let proof_collection = rt
                .block_on(ProofCollection::produce(
                    &primitive_witness,
                    &TritonVmJobQueue::dummy(),
                    TritonVmJobPriority::default(),
                ))
                .unwrap();

            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let pw_pointer = rng.next_u32();
            let pw_pointer = bfe!(pw_pointer);

            let mut memory = HashMap::default();
            encode_to_memory(&mut memory, pw_pointer, &proof_collection);

            let mut stack = self.init_stack_for_isolated_run();
            stack.push(pw_pointer);

            FunctionInitialState { stack, memory }
        }
    }

    #[test]
    fn unit_test() {
        ShadowedFunction::new(GenerateTypeScriptClaimTemplate).test();
    }
}
