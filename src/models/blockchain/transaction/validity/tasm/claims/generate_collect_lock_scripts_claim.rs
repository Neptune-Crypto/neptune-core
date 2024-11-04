use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::memory::write_words_to_memory_leave_pointer;
use tasm_lib::prelude::*;
use tasm_lib::traits::basic_snippet::BasicSnippet;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::Digest;

use crate::models::blockchain::transaction::validity::collect_lock_scripts::CollectLockScripts;
use crate::models::blockchain::transaction::validity::proof_collection::ProofCollection;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;

pub(crate) struct GenerateCollectLockScriptsClaim;

impl BasicSnippet for GenerateCollectLockScriptsClaim {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "proof_collection_pointer".to_owned())]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "claim".to_owned())]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_proof_collection_generate_collect_lock_scripts_claim".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();
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
        let push_collect_lock_scripts_hash = push_digest(CollectLockScripts.program().hash());

        let load_digest_reversed = triton_asm!(
            read_mem 1
            addi 2
            read_mem 1
            addi 2
            read_mem 1
            addi 2
            read_mem 1
            addi 2
            read_mem 1
            pop 1
        );
        let dyn_malloc = library.import(Box::new(DynMalloc));
        let claim_pointer_alloc = library.kmalloc(1);

        let proof_collection_field_salted_inputs_hash = field!(ProofCollection::salted_inputs_hash);
        let proof_collection_field_and_size_lock_script_hashes =
            field_with_size!(ProofCollection::lock_script_hashes);

        const SIZE_OF_PROGRAM_DIGEST_AND_INPUT_FIELD: isize = 12;
        let write_rest_of_claim = write_words_to_memory_leave_pointer(
            SIZE_OF_PROGRAM_DIGEST_AND_INPUT_FIELD.try_into().unwrap(),
        );

        let lock_script_hashes_loop_label = format!("{entrypoint}_lock_script_hashes_loop");
        let lock_script_hashes_loop = triton_asm!(
            // INVARIANT: _ (*ls_hashes[last+1]_lw) *ls_hashes[n]_lw (*claim.output[n])
            {lock_script_hashes_loop_label}:
                /* Loop end-condition */
                dup 2
                dup 2
                eq
                skiz
                    return

                dup 1
                read_mem {Digest::LEN}
                addi {Digest::LEN * 2}
                swap 7
                pop 1
                // _ (*ls_hashes[last+1]_lw) *ls_hashes[n+1]_lw (*claim.output[n]) [ls_hash[n]]

                dup 5
                write_mem {Digest::LEN}
                swap 1
                pop 1
                // _ (*ls_hashes[last+1]_lw) *ls_hashes[n+1]_lw (*claim.output[n+1])

                recurse
        );

        let assert_correct_size_indicator = triton_asm!(
            // _ ls_hashes_len ls_hashes_si

            /* Calculate expected size-indicator */
            swap 1
            push {Digest::LEN}
            mul
            addi 1
            // _ ls_hashes_si (5 * ls_hashes_len + 1)

            dup 1
            eq
            assert
            // _ ls_hashes_si
        );

        triton_asm!(
            {entrypoint}:
                // _ *proof_collection

                /* Put the entire encoding onto the stack, then write to memory */
                {&push_collect_lock_scripts_hash}
                // _ *proof_collection [program_digest]

                dup 5
                {&proof_collection_field_salted_inputs_hash}
                // _ *proof_collection [program_digest] *salted_inputs_hash

                /* Load claim-input reversed, since given as input in stream-form */
                {&load_digest_reversed}
                // _ *proof_collection [program_digest] [reversed(salted_inputs_hash)]

                push {Digest::LEN}
                push {Digest::LEN + 1}
                // _ *proof_collection [program_digest] [salted_inputs_hash] input_len input_si

                dup 12
                {&proof_collection_field_and_size_lock_script_hashes}
                // _ *proof_collection [program_digest] [salted_inputs_hash] input_len input_si *ls_hashes ls_hashes_si

                /* Calculate end of `ls_hashes` list */
                dup 1
                dup 1
                add
                addi {Digest::LEN - 1}
                // _ *proof_collection [program_digest] [salted_inputs_hash] input_len input_si *ls_hashes ls_hashes_si (*ls_hashes[last+1]_lw)


                /* Get length of list of lock script hashes */
                swap 2
                // _ *proof_collection [program_digest] [salted_inputs_hash] input_len input_si (*ls_hashes[last+1]_lw) ls_hashes_si *ls_hashes

                read_mem 1
                addi {1 + Digest::LEN}
                // _ *proof_collection [program_digest] [salted_inputs_hash] input_len input_si (*ls_hashes[last+1]_lw) ls_hashes_si ls_hashes_len *ls_hashes[0]_lw

                swap 2
                // _ *proof_collection [program_digest] [salted_inputs_hash] input_len input_si (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw ls_hashes_len ls_hashes_si

                {&assert_correct_size_indicator}
                // _ *proof_collection [program_digest] [salted_inputs_hash] input_len input_si (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw ls_hashes_si

                dup 0
                addi -1
                swap 1
                // _ *proof_collection [program_digest] [salted_inputs_hash] input_len input_si (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw output_len output_si

                call {dyn_malloc}
                // _ *proof_collection [program_digest] [salted_inputs_hash] input_len input_si (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw output_len output_si *claim

                dup 0
                push {claim_pointer_alloc.write_address()}
                write_mem {claim_pointer_alloc.num_words()}
                pop 1
                // _ *proof_collection [program_digest] [salted_inputs_hash] input_len input_si (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw output_len output_si *claim

                /* Write size-indicator and length for claims `output` field */
                write_mem 2
                // _ *proof_collection [program_digest] [salted_inputs_hash] input_len input_si (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw (*claim + 2)

                call {lock_script_hashes_loop_label}
                // _ *proof_collection [program_digest] [salted_inputs_hash] input_len input_si (*ls_hashes[last+1]_lw) *ls_hashes[last+1]_lw (*claim.input)

                swap 2
                pop 2
                // _ *proof_collection [program_digest] [salted_inputs_hash] input_len input_si (*claim.input)

                {&write_rest_of_claim}
                // _ *proof_collection (*claim + n)

                pop 2

                push {claim_pointer_alloc.read_address()}
                read_mem {claim_pointer_alloc.num_words()}
                pop 1
                // _ *claim

                return

                {&lock_script_hashes_loop}
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use proptest::prelude::Arbitrary;
    use proptest::prelude::Strategy;
    use proptest::test_runner::TestRunner;
    use rand::Rng;
    use rand::RngCore;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::rust_shadowing_helper_functions;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::traits::function::Function;
    use tasm_lib::traits::function::FunctionInitialState;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;

    use super::*;
    use crate::job_queue::triton_vm::TritonVmJobPriority;
    use crate::job_queue::triton_vm::TritonVmJobQueue;
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;

    #[test]
    fn unit_test() {
        ShadowedFunction::new(GenerateCollectLockScriptsClaim).test();
    }

    impl Function for GenerateCollectLockScriptsClaim {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) {
            let claim_ptr_ptr_in_isolated_run = tasm_lib::library::STATIC_MEMORY_FIRST_ADDRESS;

            // _ *proof_collection
            let proof_collection_pointer = stack.pop().unwrap();

            let proof_collection: ProofCollection =
                *ProofCollection::decode_from_memory(memory, proof_collection_pointer).unwrap();

            let claim = proof_collection.collect_lock_scripts_claim();
            let claim_pointer =
                rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator(memory);
            encode_to_memory(memory, claim_pointer, &claim);

            // Mimic population of static memory
            memory.insert(claim_ptr_ptr_in_isolated_run, claim_pointer);

            stack.push(claim_pointer);
        }

        fn pseudorandom_initial_state(
            &self,
            _seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut test_runner = TestRunner::deterministic();

            // Use test-runner's rng to avoid having to build too many proofs
            let mut rng = test_runner.new_rng();

            let num_inputs = rng.gen_range(0usize..4);
            let primitive_witness = PrimitiveWitness::arbitrary_with((num_inputs, 2, 2))
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

            let pw_pointer = rng.next_u32();
            let pw_pointer = bfe!(pw_pointer);

            let mut memory = HashMap::default();
            encode_to_memory(&mut memory, pw_pointer, &proof_collection);

            FunctionInitialState {
                stack: [self.init_stack_for_isolated_run(), vec![pw_pointer]].concat(),
                memory,
            }
        }
    }
}
