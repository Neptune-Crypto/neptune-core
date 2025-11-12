use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::*;
use tasm_lib::traits::basic_snippet::BasicSnippet;
use tasm_lib::triton_vm::prelude::*;

use crate::protocol::consensus::transaction::validity::collect_type_scripts::CollectTypeScripts;
use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;
use crate::protocol::consensus::transaction::validity::tasm::claims::new_claim::NewClaim;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;

pub(crate) struct GenerateCollectTypeScriptsClaim;

impl GenerateCollectTypeScriptsClaim {
    const BAD_SIZE_INDICATOR_TYPE_SCRIPT_HASHES: i128 = 1_000_500;
}

impl BasicSnippet for GenerateCollectTypeScriptsClaim {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "proof_collection_pointer".to_owned())]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "claim".to_owned())]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_claims_generate_collect_type_scripts_claim".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_claim = library.import(Box::new(NewClaim));

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
            assert error_id {Self::BAD_SIZE_INDICATOR_TYPE_SCRIPT_HASHES}
            // _ *type_script_hashes type_script_hashes_si
        );

        let push_cts_program_hash = {
            let Digest([d0, d1, d2, d3, d4]) = CollectTypeScripts.program().hash();
            triton_asm! { push {d4} push {d3} push {d2} push {d1} push {d0} }
        };

        let load_digest_reversed = triton_asm! {
            addi {Digest::LEN - 1}
            read_mem {Digest::LEN}
            pop 1
            pick 1 pick 2 pick 3 pick 4
        };

        let entrypoint = self.entrypoint();
        let type_script_hashes_loop = format!("{entrypoint}_type_script_hashes_loop");
        triton_asm!(
            // BEFORE: _ *proof_collection
            // AFTER:  _ *claim
            {entrypoint}:
                // _ *proof_collection

                /* Prepare call to `new_claim` */
                dup 0
                {&field_with_size!(ProofCollection::type_script_hashes)}
                // _ *proof_collection *type_script_hashes type_script_hashes_si

                {&assert_correct_size_indicator}

                dup 0
                addi -1
                // _ *proof_collection *type_script_hashes tsh_si output_size

                push {Digest::LEN * 2}
                place 1
                // _ *proof_collection *type_script_hashes tsh_si input_size output_size

                call {new_claim}
                // _ *proof_collection *type_script_hashes tsh_si *claim *claim_output *claim_input *program_digest


                /* Write program digest */
                {&push_cts_program_hash}
                pick 5
                write_mem {Digest::LEN}
                pop 1
                // _ *proof_collection *type_script_hashes tsh_si *claim *claim_output *claim_input

                /* Write program input */
                dup 5
                {&field!(ProofCollection::salted_inputs_hash)}
                // _ *proof_collection *type_script_hashes tsh_si *claim *claim_output *claim_input *salted_inputs_hash

                {&load_digest_reversed}
                // _ *proof_collection *type_script_hashes tsh_si *claim *claim_output *claim_input [salted_inputs]
                // _ *proof_collection *type_script_hashes tsh_si *claim *claim_output *claim_input[0] [reversed(salted_inputs)]

                pick 5
                write_mem {Digest::LEN}
                // _ *proof_collection *type_script_hashes tsh_si *claim *claim_output *claim_input[1]

                pick 5
                {&field!(ProofCollection::salted_outputs_hash)}
                {&load_digest_reversed}
                // _ *type_script_hashes tsh_si *claim *claim_output *claim_input[1] [reversed(salted_outputs_hash)]

                pick 5
                write_mem {Digest::LEN}
                pop 1
                // _ *type_script_hashes tsh_si *claim *claim_output

                pick 2
                dup 3
                add
                addi {Digest::LEN - 1}
                // _ *claim *claim_output (*ts_hashes[last+1]_lw)

                pick 3
                addi {Digest::LEN}
                // _ *claim *claim_output (*ts_hashes[last+1]_lw) *ts_hashes[0]_lw

                pick 2
                // _ *claim (*ts_hashes[last+1]_lw) ts_hashes[0]_lw *claim_output

                call {type_script_hashes_loop}
                // _ *claim (*ts_hashes[last+1]_lw) ts_hashes[last+1]_lw *claim_output

                pop 3
                // _ *claim

                return

            // INVARIANT: _ (*ts_hashes[last+1]_lw) *ts_hashes[n]_lw (*claim.output[n])
            {type_script_hashes_loop}:
                /* Loop end-condition */
                dup 2
                dup 2
                eq
                skiz
                    return

                pick 1
                read_mem {Digest::LEN}
                addi {Digest::LEN * 2}
                place 6
                // _ (*ts_hashes[last+1]_lw) *ts_hashes[n+1]_lw (*claim.output[n]) [ts_hash[n]]

                pick 5
                write_mem {Digest::LEN}
                // _ (*ts_hashes[last+1]_lw) *ts_hashes[n+1]_lw (*claim.output[n+1])

                recurse
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use itertools::Itertools;
    use proptest::prelude::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::RngCore;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::rust_shadowing_helper_functions;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::traits::function::Function;
    use tasm_lib::traits::function::FunctionInitialState;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tracing_test::traced_test;

    use super::*;
    use crate::application::triton_vm_job_queue::TritonVmJobPriority;
    use crate::application::triton_vm_job_queue::TritonVmJobQueue;
    use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
    use crate::protocol::consensus::type_scripts::time_lock::neptune_arbitrary::arbitrary_primitive_witness_with_expired_timelocks;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;

    #[traced_test]
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
            let proof_collection_pointer = stack.pop().unwrap();
            let proof_collection =
                *ProofCollection::decode_from_memory(memory, proof_collection_pointer).unwrap();

            let claim = proof_collection.collect_type_scripts_claim();
            let claim_pointer =
                rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator(memory);
            encode_to_memory(memory, claim_pointer, &claim);

            println!("encoded claim: [\n{}\n]", claim.encode().iter().join(", "));

            stack.push(claim_pointer);
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut test_runner = TestRunner::deterministic();

            // Use test-runner's rng to avoid having to build too many proofs
            let mut rng: StdRng = SeedableRng::from_seed(seed);

            let num_inputs = 2;
            let primitive_witness = if rng.random_bool(0.5) {
                PrimitiveWitness::arbitrary_with_size_numbers(Some(num_inputs), 2, 2)
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current()
            } else {
                let deterministic_now = arb::<Timestamp>()
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current();
                arbitrary_primitive_witness_with_expired_timelocks(
                    num_inputs,
                    2,
                    2,
                    deterministic_now,
                )
                .new_tree(&mut test_runner)
                .unwrap()
                .current()
            };

            assert!(
                !primitive_witness.kernel.merge_bit,
                "No primitive witness should have its merge bit set."
            );
            let rt = crate::tests::tokio_runtime();
            let _guard = rt.enter();
            assert!(
                rt.block_on(primitive_witness.validate()).is_ok(),
                "Primitive witness must be valid"
            );
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

            FunctionInitialState {
                stack: [self.init_stack_for_isolated_run(), vec![pw_pointer]].concat(),
                memory,
            }
        }
    }
}
