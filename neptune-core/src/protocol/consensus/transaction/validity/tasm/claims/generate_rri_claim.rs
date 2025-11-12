use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::*;
use tasm_lib::traits::basic_snippet::BasicSnippet;
use tasm_lib::triton_vm::prelude::*;

use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;
use crate::protocol::consensus::transaction::validity::removal_records_integrity::RemovalRecordsIntegrity;
use crate::protocol::consensus::transaction::validity::tasm::claims::new_claim::NewClaim;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;

/// Generates a `RemovalRecordsIntegrity` `Claim` from a `ProofCollection` object.
///
/// Assumes the transaction kernel MAST hash is on the stack somewhere, but not
/// necessarily immediately preceding the proof collection pointer.
#[derive(Debug, Copy, Clone)]
pub struct GenerateRriClaim;

impl BasicSnippet for GenerateRriClaim {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "transaction_kernel_digest".to_owned()),
            (DataType::Bfe, "garb1".to_string()),
            (DataType::Bfe, "garb0".to_string()),
            (DataType::VoidPointer, "proof_collection_pointer".to_owned()),
        ]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "transaction_kernel_digest".to_owned()),
            (DataType::Bfe, "garb1".to_string()),
            (DataType::Bfe, "garb0".to_string()),
            (DataType::VoidPointer, "proof_collection_pointer".to_owned()),
            (DataType::VoidPointer, "claim".to_owned()),
        ]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_proof_collection_store_rri_claim".to_owned()
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
        let push_rri_program_hash = push_digest(RemovalRecordsIntegrity.program().hash());

        let proof_collection_field_salted_inputs_hash = field!(ProofCollection::salted_inputs_hash);

        let load_digest = triton_asm!(
            // _ *digest

            addi {Digest::LEN - 1}
            read_mem {Digest::LEN}
            pop 1
            // _ [digest]
        );

        let new_claim = library.import(Box::new(NewClaim));
        let input_length = Digest::LEN;
        let output_length = Digest::LEN;

        triton_asm!(
            // BEFORE: _ [txk_digest] garb garb *proof_collection
            // AFTER:  _ [txk_digest] garb garb *proof_collection *rri_claim
            {entrypoint}:

                push {input_length}
                push {output_length}
                call {new_claim}
                // _ [txk_digest] garb garb *proof_collection *claim *output *input *program_digest


                /* put the program digest on stack, then write to memory */
                {&push_rri_program_hash}
                // _ [txk_digest] garb garb *proof_collection *claim *output *input *program_digest [program_digest]

                dup 5 write_mem 5 pop 2
                // _ [txk_digest] garb garb *proof_collection *claim *output *input


                /* put input on stack, then write to memory */
                dup 6
                dup 8
                dup 10
                dup 12
                dup 14
                // _ [txk_digest] garb garb *proof_collection *claim *output *input [txk_digest_reversed]

                dup 5
                write_mem 5
                pop 2
                // _ [txk_digest] garb garb *proof_collection *claim *output

                /* put the output on stack, then write to memory */
                dup 2 {&proof_collection_field_salted_inputs_hash}
                // _ [txk_digest] garb garb *proof_collection *claim *output *salted_inputs_hash

                {&load_digest}
                // _ [txk_digest] garb garb *proof_collection *claim *output [salted_inputs_hash]

                dup 5 write_mem 5 pop 2
                // _ [txk_digest] garb garb *proof_collection *claim

                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use itertools::Itertools;
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
        ShadowedFunction::new(GenerateRriClaim).test();
    }

    impl Function for GenerateRriClaim {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) {
            // _ [txk_digest] garb garb *proof_collection
            let proof_collection_pointer = stack.pop().unwrap();
            let garb0 = stack.pop().unwrap();
            let garb1 = stack.pop().unwrap();
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

            stack.push(txk_digest.values()[4]);
            stack.push(txk_digest.values()[3]);
            stack.push(txk_digest.values()[2]);
            stack.push(txk_digest.values()[1]);
            stack.push(txk_digest.values()[0]);
            stack.push(garb1);
            stack.push(garb0);
            stack.push(proof_collection_pointer);
            stack.push(claim_pointer);
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
                    vec![rng.random(), rng.random()],
                    vec![pw_pointer],
                ]
                .concat(),
                memory,
            }
        }
    }
}
