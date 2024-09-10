use tasm_lib::data_type::DataType;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::list::multiset_equality_digests::MultisetEqualityDigests;
use tasm_lib::mmr::MAX_MMR_HEIGHT;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DynMalloc;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::util_types::mutator_set::removal_record::RemovalRecord;
use crate::util_types::mutator_set::shared::BATCH_SIZE;
use crate::util_types::mutator_set::shared::CHUNK_SIZE;
use crate::util_types::mutator_set::shared::NUM_TRIALS;
use crate::util_types::mutator_set::shared::WINDOW_SIZE;

/// Crash the VM iff the removal records index set are not equal
#[derive(Clone, Copy, Debug)]
pub(crate) struct AssertRemovalRecordIndexSetEquality;

impl BasicSnippet for AssertRemovalRecordIndexSetEquality {
    fn inputs(&self) -> Vec<(DataType, String)> {
        // // Type of both "inputs" argument is Vec<RemovalRecord>
        vec![
            (DataType::VoidPointer, "rr_a".to_owned()),
            (DataType::VoidPointer, "rr_b".to_owned()),
        ]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_transaction_assert_rr_index_set_equality".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();

        let dyn_malloc = library.import(Box::new(DynMalloc));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let multiset_eq_digests = library.import(Box::new(MultisetEqualityDigests));

        // Chosen based on a rough estimate. The size of a removal
        // records integrity list should not be allowed to exceed u32::MAX
        // though, as don't allow any piece of data to exceed this size.
        const MAX_LENGTH_REMOVAL_RECORDS_LIST: usize = 1 << 17;

        // Theoretical max size for a chunk dictionary. It can contain
        // `NUM_TRIALS` entries. `WINDOW_SIZE / CHUNK_SIZE` batches can write
        // to a specific chunk. There are `BATCH_SIZE` outputs in each batch.
        // Each output write `NUM_TRIALS` indices. An authentication path can
        // max be 64 digests long. And then some words are used on length
        // indicators
        const MAX_REMOVAL_RECORD_ELEM_SIZE: u32 = NUM_TRIALS
            * (NUM_TRIALS * BATCH_SIZE * (WINDOW_SIZE / CHUNK_SIZE)
                + Digest::LEN as u32 * MAX_MMR_HEIGHT as u32
                + 10);

        let hash_absolute_indices_loop_label = format!("{entrypoint}_hash_loop");

        let absolute_indices_and_size = field_with_size!(RemovalRecord::absolute_indices);

        let advance_to_next_removal_record_element = triton_asm!(
            // _ *rr_x[n]_si
            read_mem 1
            push {MAX_REMOVAL_RECORD_ELEM_SIZE}
            dup 2
            lt
            // _ rr_b[n]_si (*rr_b[n]_si-1) (rr_b[n]_si < MAX)

            assert
            // _ rr_b[n]_si (*rr_b[n]_si-1)

            addi 2
            add
            // _ *rr_x[n+1]_si
        );
        let hash_absolute_indices_loop = triton_asm!(
            // INVARIANT: _ *a_digests[len] *a_digests[n] *b_digests_[n] offset_end 0 *rr_a[n]_si *rr_b[n]_si
            // START: _ *a_digests[len] *a_digests[0] *b_digests_[0] offset_end 0 *rr_a[0]_si *rr_b[0]_si
            {hash_absolute_indices_loop_label}:
                // _ *a_digests[len] *a_digests[n] *b_digests[n] [b; 2] *rr_a[n]_si *rr_b[n]_si

                /* Push `b_digest` */
                dup 0
                addi 1
                {&absolute_indices_and_size}
                call {hash_varlen}
                // _ *a_digests[len] *a_digests[n] *b_digests[n] [b; 2] *rr_a[n]_si *rr_b[n]_si [b_digest]

                dup 9
                write_mem {Digest::LEN}
                swap 5
                pop 1
                // _ *a_digests[len] *a_digests[n] *b_digests[n+1] [b; 2] *rr_a[n]_si *rr_b[n]_si

                {&advance_to_next_removal_record_element}
                // _ *a_digests[len] *a_digests[n] *b_digests[n+1] [b; 2] *rr_a[n]_si *rr_b[n+1]_si

                swap 1
                // _ *a_digests[len] *a_digests[n] *b_digests[n+1] [b; 2] *rr_b[n+1]_si *rr_a[n]_si

                /* Push `a_digest` */
                dup 0
                addi 1
                {&absolute_indices_and_size}
                call {hash_varlen}
                // _ *a_digests[len] *a_digests[n] *b_digests[n+1] [b; 2] *rr_b[n+1]_si *rr_a[n]_si [a_digest]

                dup 10
                write_mem {Digest::LEN}
                swap 6
                pop 1
                // _ *a_digests[len] *a_digests[n+1] *b_digests[n+1] [b; 2] *rr_b[n+1]_si *rr_a[n]_si

                {&advance_to_next_removal_record_element}
                // _ *a_digests[len] *a_digests[n+1] *b_digests[n+1] [b; 2] *rr_b[n+1]_si *rr_a[n+1]_si

                swap 1
                // _ *a_digests[len] *a_digests[n+1] *b_digests[n+1] [b; 2] *rr_a[n+1]_si *rr_b[n+1]_si

                recurse_or_return
        );

        triton_asm!(
            {entrypoint}:
                // _ *rr_a *rr_b

                /* Verify length equality */
                read_mem 1
                addi 2
                // _ *rr_a b_len *rr_b[0]_si

                swap 2
                read_mem 1
                addi 2
                // _ *rr_b[0]_si b_len a_len *rr_a[0]_si

                swap 2
                dup 1
                eq
                // _ *rr_b[0]_si *rr_a[0]_si a_len (b_len == a_len)

                assert
                // _ *rr_b[0]_si *rr_a[0]_si len

                /* Verify max length is not exceeded */
                push {MAX_LENGTH_REMOVAL_RECORDS_LIST}
                dup 1
                lt
                assert
                // _ *rr_b[0]_si *rr_a[0]_si len

                /* Allocate space for digest lists, and write lengths */
                dup 0
                call {dyn_malloc}
                write_mem 1
                // _ *rr_b[0]_si *rr_a[0]_si len *b_digests[0]

                dup 1
                call {dyn_malloc}
                write_mem 1
                // _ *rr_b[0]_si *rr_a[0]_si len *b_digests[0] *a_digests[0]

                swap 1
                swap 2
                // _ *rr_b[0]_si *rr_a[0]_si *b_digests[0] *a_digests[0] len

                /* Calculate offset for end of `a_digests` and `b_digests` */
                push {Digest::LEN}
                mul
                // _ *rr_b[0]_si *rr_a[0]_si *b_digests[0] *a_digests[0] offset_end

                dup 1
                dup 1
                add
                // _ *rr_b[0]_si *rr_a[0]_si *b_digests[0] *a_digests[0] offset_end *a_digests[len]

                /* Rearrange stack for loop */
                swap 5
                swap 2
                swap 4
                swap 1
                swap 2
                push 0
                swap 2
                swap 1
                // _ *a_digests[len] *a_digests[0] *b_digests[0] offset_end 0 *rr_a[0]_si *rr_b[0]_si

                /* Only enter loop if len != 0 */
                dup 3
                push 0
                eq
                push 0
                eq
                // _ *a_digests[len] *a_digests[0] *b_digests[0] offset_end 0 *rr_a[0]_si *rr_b[0]_si (offset_end != 0)

                skiz
                    call {hash_absolute_indices_loop_label}
                // _ *a_digests[len] *a_digests[len] *b_digests[len] offset_end 0 *rr_a[len]_si *rr_b[len]_si

                pop 3
                // _ *a_digests[len] *a_digests[len] *b_digests[len] offset_end

                push -1
                mul
                // _ *a_digests[len] *a_digests[len] *b_digests[len] (-offset_end)

                swap 1
                dup 1
                add
                addi -1
                // _ *a_digests[len] *a_digests[len] (-offset_end) *b_digests

                swap 3
                add
                addi -1
                // _ *b_digests *a_digests[len] *a_digests

                swap 1
                pop 1
                // _ *b_digests *a_digests

                call {multiset_eq_digests}
                // _ set_equality(*b_digests, *a_digests)

                assert
                // _

                return

                {&hash_absolute_indices_loop}
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use proptest::prelude::{Arbitrary, Strategy};
    use proptest::test_runner::{RngAlgorithm, TestRng, TestRunner};
    use rand::seq::SliceRandom;
    use rand::{random, thread_rng, Rng};
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::rust_shadowing_helper_functions;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::structure::tasm_object::TasmObject;
    use tasm_lib::test_helpers::negative_test;
    use tasm_lib::traits::function::{Function, FunctionInitialState, ShadowedFunction};
    use tasm_lib::traits::rust_shadow::RustShadow;
    use twenty_first::prelude::AlgebraicHasher;

    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;

    use super::*;

    impl AssertRemovalRecordIndexSetEquality {
        fn init_state(
            &self,
            rra_ptr: BFieldElement,
            rrb_ptr: BFieldElement,
            rra: Vec<RemovalRecord>,
            rrb: Vec<RemovalRecord>,
        ) -> FunctionInitialState {
            let mut memory = HashMap::default();
            encode_to_memory(&mut memory, rra_ptr, &rra);
            encode_to_memory(&mut memory, rrb_ptr, &rrb);

            let stack = [self.init_stack_for_isolated_run(), vec![rra_ptr, rrb_ptr]].concat();

            FunctionInitialState { stack, memory }
        }
    }

    impl Function for AssertRemovalRecordIndexSetEquality {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) {
            let rrb_ptr = stack.pop().unwrap();
            let rra_ptr = stack.pop().unwrap();

            let rra = *Vec::<RemovalRecord>::decode_from_memory(memory, rra_ptr).unwrap();
            let rrb = *Vec::<RemovalRecord>::decode_from_memory(memory, rrb_ptr).unwrap();

            let mut a_digests: Vec<Digest> = Vec::new();
            let mut b_digests: Vec<Digest> = Vec::new();
            assert_eq!(rra.len(), rrb.len());
            let mut i: usize = 0;
            while i < rra.len() {
                a_digests.push(Tip5::hash(&rra[i].absolute_indices));
                b_digests.push(Tip5::hash(&rrb[i].absolute_indices));
                i += 1;
            }

            // Emulate effect on memory
            let b_digests_ptr =
                rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator(memory);
            let a_digests_ptr =
                rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator(memory);

            rust_shadowing_helper_functions::list::list_insert(
                b_digests_ptr,
                b_digests.clone(),
                memory,
            );
            rust_shadowing_helper_functions::list::list_insert(
                a_digests_ptr,
                a_digests.clone(),
                memory,
            );

            // Assert set-equality
            a_digests.sort();
            b_digests.sort();
            assert_eq!(a_digests, b_digests);
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut rng: TestRng = TestRng::from_seed(RngAlgorithm::ChaCha, &seed);
            let rra_ptr: BFieldElement = bfe!(rng.gen_range(0..(1 << 30)));
            let rrb_ptr: BFieldElement = rra_ptr + bfe!(rng.gen_range(0..(1 << 30)));

            let (num_inputs, num_outputs, num_pub_announcements) = match bench_case {
                Some(BenchmarkCase::CommonCase) => (2, 0, 0),
                Some(BenchmarkCase::WorstCase) => (20, 0, 0),
                None => (
                    rng.gen_range(0..10),
                    rng.gen_range(0..10),
                    rng.gen_range(0..10),
                ),
            };

            let primitive_witness: PrimitiveWitness = {
                let mut test_runner = TestRunner::new_with_rng(Default::default(), rng.clone());
                PrimitiveWitness::arbitrary_with((num_inputs, num_outputs, num_pub_announcements))
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current()
            };

            let rra = primitive_witness.kernel.inputs.clone();
            let mut rrb = rra.clone();
            rrb.shuffle(&mut rng);

            self.init_state(rra_ptr, rrb_ptr, rra, rrb)
        }

        fn corner_case_initial_states(&self) -> Vec<FunctionInitialState> {
            let no_inputs = { self.init_state(random(), random(), vec![], vec![]) };

            let one_input = {
                let mut test_runner = TestRunner::deterministic();
                let pw = PrimitiveWitness::arbitrary_with((1, 1, 0))
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current();

                let rra = pw.kernel.inputs.clone();

                self.init_state(random(), random(), rra.clone(), rra)
            };

            let two_inputs_same_order = {
                let mut test_runner = TestRunner::deterministic();
                let pw = PrimitiveWitness::arbitrary_with((2, 1, 0))
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current();

                let rra = pw.kernel.inputs.clone();

                self.init_state(random(), random(), rra.clone(), rra)
            };

            let two_inputs_swapped = {
                let mut test_runner = TestRunner::deterministic();
                let pw = PrimitiveWitness::arbitrary_with((2, 1, 0))
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current();

                let rra = pw.kernel.inputs.clone();
                let rrb = vec![rra[1].clone(), rra[0].clone()];
                assert_ne!(rra, rrb);

                self.init_state(random(), random(), rra, rrb)
            };

            vec![
                no_inputs,
                one_input,
                two_inputs_same_order,
                two_inputs_swapped,
            ]
        }
    }

    #[test]
    fn positive_pbt() {
        ShadowedFunction::new(AssertRemovalRecordIndexSetEquality).test();
    }

    #[test]
    fn negative_test_mutated_absolute_index_set() {
        let snippet = AssertRemovalRecordIndexSetEquality;
        let mut rng = thread_rng();
        let num_inputs = rng.gen_range(1..4);
        let primitive_witness: PrimitiveWitness = {
            let mut test_runner = TestRunner::deterministic();
            PrimitiveWitness::arbitrary_with((num_inputs, 1, 0))
                .new_tree(&mut test_runner)
                .unwrap()
                .current()
        };
        let rra = primitive_witness.kernel.inputs;

        let an_input_index = rng.gen_range(0..num_inputs);
        let an_absolute_index_index = rng.gen_range(0..NUM_TRIALS);
        let mut rrb = rra.clone();
        rrb[an_input_index]
            .absolute_indices
            .decrement_bloom_filter_index(an_absolute_index_index as usize);
        let bad_init_state0 = snippet.init_state(random(), random(), rra.clone(), rrb.clone());
        negative_test(
            &ShadowedFunction::new(snippet),
            bad_init_state0.into(),
            &[InstructionError::AssertionFailed],
        );

        let bad_init_state1 = snippet.init_state(random(), random(), rrb, rra);
        negative_test(
            &ShadowedFunction::new(snippet),
            bad_init_state1.into(),
            &[InstructionError::AssertionFailed],
        );
    }
}

#[cfg(test)]
mod benches {
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;

    use super::*;

    #[test]
    fn assert_rri_index_set_eq_bench() {
        ShadowedFunction::new(AssertRemovalRecordIndexSetEquality).bench();
    }
}
