use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::prelude::*;
use tasm_lib::traits::basic_snippet::BasicSnippet;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::Digest;

use crate::models::blockchain::transaction::validity::collect_type_scripts::CollectTypeScripts;
use crate::models::blockchain::transaction::validity::proof_collection::ProofCollection;
use crate::models::blockchain::transaction::validity::tasm::claims::new_claim::NewClaim;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;

pub(crate) struct GenerateCollectTypeScriptsClaim;

impl BasicSnippet for GenerateCollectTypeScriptsClaim {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "proof_collection_pointer".to_owned())]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "claim".to_owned())]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_claims_generate_collect_lock_scripts_claim".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();

        let new_claim = library.import(Box::new(NewClaim));

        let proof_collection_field_salted_inputs_hash = field!(ProofCollection::salted_inputs_hash);
        let proof_collection_field_salted_outputs_hash =
            field!(ProofCollection::salted_outputs_hash);
        let proof_collection_field_and_size_lock_script_hashes =
            field_with_size!(ProofCollection::type_script_hashes);

        const INPUT_SIZE: usize = Digest::LEN * 2;

        let assert_correct_size_indicator = triton_asm!(
            // _ *type_script_hashes type_script_hashes_si

            dup 1
            read_mem 1
            pop 1
            // _ *type_script_hashes type_script_hashes_si type_script_hashes_len

            push {Digest::LEN}
            mul
            addi 1
            // _ *type_script_hashes type_script_hashes_si (type_script_hashes_len * 5 + 1)
            // _ *type_script_hashes type_script_hashes_si (type_script_hashes_calculated_size)

            dup 1
            eq
            assert
            // _ *type_script_hashes type_script_hashes_si
        );

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
        let push_cts_program_hash = push_digest(CollectTypeScripts.program().hash());

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

        let type_script_hashes_loop_label = format!("{entrypoint}_type_script_hashes_loop");
        let type_script_hashes_loop = triton_asm!(
            // INVARIANT: _ (*ts_hashes[last+1]_lw) *ts_hashes[n]_lw (*claim.output[n])
            {type_script_hashes_loop_label}:
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
                // _ (*ts_hashes[last+1]_lw) *ts_hashes[n+1]_lw (*claim.output[n]) [ts_hash[n]]

                dup 5
                write_mem {Digest::LEN}
                swap 1
                pop 1
                // _ (*ts_hashes[last+1]_lw) *ts_hashes[n+1]_lw (*claim.output[n+1])

                recurse
        );

        let type_script_hashes_si_alloc = library.kmalloc(1);
        triton_asm!(
            // BEFORE: _ *proof_collection_pointer
            // AFTER:  _ *claim
            {entrypoint}:
                // _ *proof_collection_pointer


                /* Prepare call to `new_claim` */
                dup 0
                {&proof_collection_field_and_size_lock_script_hashes}
                // _ *proof_collection_pointer *type_script_hashes type_script_hashes_si

                {&assert_correct_size_indicator}

                push {INPUT_SIZE}
                swap 1
                // _ *proof_collection_pointer *type_script_hashes input_size type_script_hashes_si

                dup 0
                push {type_script_hashes_si_alloc.write_address()}
                write_mem {type_script_hashes_si_alloc.num_words()}
                pop 1
                // _ *proof_collection_pointer *type_script_hashes input_size type_script_hashes_si

                addi -1
                // _ *proof_collection_pointer *type_script_hashes input_size (type_script_hashes_si - 1)
                // _ *proof_collection_pointer *type_script_hashes input_size output_size  <-- rename

                call {new_claim}
                // _ *proof_collection_pointer *type_script_hashes *claim *claim_output *claim_input *program_digest


                /* Write program digest */
                {&push_cts_program_hash}
                dup 5
                write_mem {Digest::LEN}
                pop 2
                // _ *proof_collection_pointer *type_script_hashes *claim *claim_output *claim_input

                /* Write program input */
                dup 4
                {&proof_collection_field_salted_inputs_hash}
                // _ *proof_collection_pointer *type_script_hashes *claim *claim_output *claim_input *salted_inputs_hash

                {&load_digest_reversed}
                // _ *proof_collection_pointer *type_script_hashes *claim *claim_output *claim_input [salted_inputs]
                // _ *proof_collection_pointer *type_script_hashes *claim *claim_output *claim_input[0] [reversed(salted_inputs)]

                dup 5
                write_mem {Digest::LEN}
                swap 1
                pop 1
                // _ *proof_collection_pointer *type_script_hashes *claim *claim_output *claim_input[1]

                dup 4
                {&proof_collection_field_salted_outputs_hash}
                {&load_digest_reversed}
                // _ *proof_collection_pointer *type_script_hashes *claim *claim_output *claim_input[1] [reversed(salted_outputs_hash)]

                dup 5
                write_mem {Digest::LEN}
                pop 2
                // _ *proof_collection_pointer *type_script_hashes *claim *claim_output

                push {type_script_hashes_si_alloc.read_address()}
                read_mem {type_script_hashes_si_alloc.num_words()}
                pop 1
                // _ *proof_collection_pointer *type_script_hashes *claim *claim_output type_script_hashes_si

                dup 3
                add
                addi {Digest::LEN - 1}
                // _ *proof_collection_pointer *type_script_hashes *claim *claim_output (*ts_hashes[last+1]_lw)

                dup 3
                addi {Digest::LEN}
                // _ *proof_collection_pointer *type_script_hashes *claim *claim_output (*ts_hashes[last+1]_lw) ts_hashes[0]_lw

                swap 1
                swap 2
                // _ *proof_collection_pointer *type_script_hashes *claim (*ts_hashes[last+1]_lw) ts_hashes[0]_lw *claim_output

                call {type_script_hashes_loop_label}
                // _ *proof_collection_pointer *type_script_hashes *claim (*ts_hashes[last+1]_lw) ts_hashes[last+1]_lw *claim_output

                pop 3
                // _ *proof_collection_pointer *type_script_hashes *claim

                swap 2
                pop 2
                // _ *claim

                return

                {&type_script_hashes_loop}
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use itertools::Itertools;
    use proptest::prelude::Arbitrary;
    use proptest::prelude::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
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
    use crate::models::blockchain::type_scripts::time_lock::arbitrary_primitive_witness_with_active_timelocks;
    use crate::models::proof_abstractions::timestamp::Timestamp;

    #[test]
    fn unit_test() {
        ShadowedFunction::new(GenerateCollectTypeScriptsClaim).test();
    }

    impl Function for GenerateCollectTypeScriptsClaim {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) {
            fn type_script_hashes_size_indicator_pointer_isolated_run() -> BFieldElement {
                bfe!(-2)
            }

            // _ *proof_collection
            let proof_collection_pointer = stack.pop().unwrap();

            let proof_collection: ProofCollection =
                *ProofCollection::decode_from_memory(memory, proof_collection_pointer).unwrap();

            let claim = proof_collection.collect_type_scripts_claim();
            let claim_pointer =
                rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator(memory);
            encode_to_memory(memory, claim_pointer, &claim);

            println!("encoded claim: [\n{}\n]", claim.encode().iter().join(", "));

            // Mimic population of static memory
            let ts_hashes_size_indicator_as_u32: u32 = (claim.output.len() + 1).try_into().unwrap();
            memory.insert(
                type_script_hashes_size_indicator_pointer_isolated_run(),
                bfe!(ts_hashes_size_indicator_as_u32),
            );

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

            let num_inputs = 2;
            let primitive_witness = if rng.gen_bool(0.5) {
                PrimitiveWitness::arbitrary_with((num_inputs, 2, 2))
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current()
            } else {
                let deterministic_now = arb::<Timestamp>()
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current();
                arbitrary_primitive_witness_with_active_timelocks(
                    num_inputs,
                    2,
                    2,
                    deterministic_now,
                )
                .new_tree(&mut test_runner)
                .unwrap()
                .current()
            };
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
