use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::*;
use tasm_lib::traits::basic_snippet::BasicSnippet;
use tasm_lib::triton_vm::prelude::*;

use crate::protocol::consensus::transaction::validity::collect_lock_scripts::CollectLockScripts;
use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;
use crate::protocol::consensus::transaction::validity::tasm::claims::new_claim::NewClaim;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;

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
        let push_collect_lock_scripts_hash = {
            let Digest([d0, d1, d2, d3, d4]) = CollectLockScripts.program().hash();
            triton_asm!(push {d4} push {d3} push {d2} push {d1} push {d0})
        };

        let new_claim = library.import(Box::new(NewClaim));
        let lock_script_hashes_loop = format!("{entrypoint}_lock_script_hashes_loop");

        triton_asm!(
            {entrypoint}:
                // _ *proof_collection

                dup 0
                {&field_with_size!(ProofCollection::lock_script_hashes)}
                // _ *proof_collection *ls_hashes ls_hashes_si

                /* calculate end of `ls_hashes` list */
                dup 1
                dup 1
                add
                addi {Digest::LEN - 1}
                // _ *proof_collection *ls_hashes ls_hashes_si (*ls_hashes[last+1]_lw)

                pick 2
                read_mem 1
                addi {1 + Digest::LEN}
                // _ *proof_collection ls_hashes_si (*ls_hashes[last+1]_lw) ls_hashes_len *ls_hashes[0]_lw

                /* assert correct size indicator */
                pick 1
                push {Digest::LEN}
                mul
                addi 1
                // _ *proof_collection ls_hashes_si (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw (5 * ls_hashes_len + 1)

                dup 3
                eq
                assert
                // _ *proof_collection ls_hashes_si (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw

                pick 2
                addi -1
                hint output_len = stack[0]
                // _ *proof_collection (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw output_len

                push {Digest::LEN}
                place 1
                // _ *proof_collection (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw input_len output_len

                call {new_claim}
                // _ *proof_collection (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw *claim *output *input *program_digest

                {&push_collect_lock_scripts_hash}
                hint collect_lock_scripts_hash: Digest = stack[0..5]
                pick 5
                write_mem {Digest::LEN}
                pop 1
                // _ *proof_collection (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw *claim *output *input

                /* Load claim's input reversed, since given as input in stream-form */
                pick 5
                {&field!(ProofCollection::salted_inputs_hash)}
                addi {Digest::LEN - 1}
                read_mem {Digest::LEN}
                hint salted_inputs_hash: Digest = stack[1..6]
                pop 1
                pick 1 pick 2 pick 3 pick 4
                // _ (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw *claim *output *input [reversed(salted_inputs_hash)]

                pick 5
                write_mem {Digest::LEN}
                pop 1
                // _ (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw *claim *output

                pick 1
                place 3
                // _ *claim (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw *output

                call {lock_script_hashes_loop}
                // _ *claim (*ls_hashes[last+1]_lw) (*ls_hashes[last+1]_lw) *garbage

                pop 3
                return

            // INVARIANT: _ (*ls_hashes[last+1]_lw) *ls_hashes[n]_lw (*claim.output[n])
            {lock_script_hashes_loop}:
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
                // _ (*ls_hashes[last+1]_lw) *ls_hashes[n+1]_lw (*claim.output[n]) [ls_hash[n]]

                pick 5
                write_mem {Digest::LEN}
                // _ (*ls_hashes[last+1]_lw) *ls_hashes[n+1]_lw (*claim.output[n+1])

                recurse
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use proptest::prelude::Strategy;
    use proptest::test_runner::TestRunner;
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

    use super::*;
    use crate::application::triton_vm_job_queue::TritonVmJobPriority;
    use crate::application::triton_vm_job_queue::TritonVmJobQueue;
    use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;

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
            let proof_collection_pointer = stack.pop().unwrap();
            let proof_collection =
                *ProofCollection::decode_from_memory(memory, proof_collection_pointer).unwrap();

            let claim = proof_collection.collect_lock_scripts_claim();
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
            let mut rng: StdRng = SeedableRng::from_seed(seed);

            let mut test_runner = TestRunner::deterministic();
            let num_inputs = rng.random_range(0usize..4);
            let primitive_witness =
                PrimitiveWitness::arbitrary_with_size_numbers(Some(num_inputs), 2, 2)
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

            FunctionInitialState {
                stack: [self.init_stack_for_isolated_run(), vec![pw_pointer]].concat(),
                memory,
            }
        }
    }
}
