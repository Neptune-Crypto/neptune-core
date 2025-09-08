use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use super::new_claim::NewClaim;
use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;

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

        let load_digest = triton_asm!(addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1);
        let reverse_digest = triton_asm!(pick 1 pick 2 pick 3 pick 4);

        let entrypoint = self.entrypoint();
        triton_asm! {
            // BEFORE: _ *proof_collection
            // AFTER:  _ *claim *program_digest
            {entrypoint}:

                push {3 * Digest::LEN}
                push 0
                call {new_claim}
                // _ *proof_collection *claim *output *input *program_digest

                place 2
                // _ *proof_collection *claim *program_digest *output *input


                /* write txk mast hash (reversed) to input */
                dup 4
                {&field!(ProofCollection::kernel_mast_hash)}
                // _ *proof_collection *claim *program_digest *output *input *txkmh

                {&load_digest}
                {&reverse_digest}
                // _ *proof_collection *claim *program_digest *output *input [txkmh_rev]

                pick 5
                write_mem {Digest::LEN}
                // _ *proof_collection *claim *program_digest *output (*input+5)


                /* write salted inputs hash (reversed) to input */
                dup 4
                {&field!(ProofCollection::salted_inputs_hash)}
                // _ *proof_collection *claim *program_digest *output (*input+5) *salted_inputs_hash

                {&load_digest}
                {&reverse_digest}
                // _ *proof_collection *claim *program_digest *output (*input+5) [salted_inputs_hash_reversed]

                pick 5
                write_mem {Digest::LEN}
                // _ *proof_collection *claim *program_digest *output (*input+10)


                /* write salted outputs hash (reversed) to input */
                pick 4
                {&field!(ProofCollection::salted_outputs_hash)}
                // _ *claim *program_digest *output (*input+10) *salted_outputs_hash

                {&load_digest}
                {&reverse_digest}
                // _ *claim *program_digest *output (*input+10) [salted_outputs_hash_reversed]

                pick 5
                write_mem {Digest::LEN}
                // _ *claim *program_digest *output (*input+15)

                pop 2
                // _ *claim *program_digest

                return
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use proptest::prelude::Strategy;
    use proptest::test_runner::TestRunner;
    use rand::rngs::StdRng;
    use rand::RngCore;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::prelude::BasicSnippet;
    use tasm_lib::prelude::TasmObject;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::traits::function::Function;
    use tasm_lib::traits::function::FunctionInitialState;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;

    use super::*;
    use crate::application::triton_vm_job_queue::TritonVmJobPriority;
    use crate::application::triton_vm_job_queue::TritonVmJobQueue;
    use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
    use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;

    impl Function for GenerateTypeScriptClaimTemplate {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) {
            let proof_collection_pointer = stack.pop().unwrap();

            let input_length = bfe!(3 * Digest::LEN);
            let output_length = bfe!(0);

            stack.push(input_length);
            stack.push(output_length);
            NewClaim.rust_shadow(stack, memory);

            let digest_pointer = stack.pop().unwrap();
            let input_pointer = stack.pop().unwrap();
            let _output_pointer = stack.pop().unwrap();

            let proof_collection =
                *ProofCollection::decode_from_memory(memory, proof_collection_pointer).unwrap();
            let mast_hash_reverse = proof_collection.kernel_mast_hash.reversed();
            let input_hash_reverse = proof_collection.salted_inputs_hash.reversed();
            let outputs_hash_reverse = proof_collection.salted_outputs_hash.reversed();

            encode_to_memory(memory, input_pointer, &mast_hash_reverse);
            encode_to_memory(memory, input_pointer + bfe!(5), &input_hash_reverse);
            encode_to_memory(memory, input_pointer + bfe!(10), &outputs_hash_reverse);

            stack.push(digest_pointer);
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut test_runner = TestRunner::deterministic();
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
            let rt = crate::tests::tokio_runtime();
            let _guard = rt.enter();
            let proof_collection = rt
                .block_on(ProofCollection::produce(
                    &primitive_witness,
                    TritonVmJobQueue::get_instance(),
                    TritonVmJobPriority::default().into(),
                ))
                .unwrap();

            // Sample an address for primitive witness pointer from first page,
            // but leave enough margin till the end so we don't accidentally
            // overwrite memory in the next page.
            let pw_pointer = rng.next_u32() >> 1;
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
