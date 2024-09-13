use tasm_lib::data_type::DataType;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::list::new::New;
use tasm_lib::list::push::Push;
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

/// Hash the absolute index sets of `NUM_INPUT_LISTS` lists of [`RemovalRecord`]s,
/// putting all resulting digests in one list, which is returned.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HashRemovalRecordIndexSets<const NUM_INPUT_LISTS: usize>;

impl<const NUM_INPUT_LISTS: usize> BasicSnippet for HashRemovalRecordIndexSets<NUM_INPUT_LISTS> {
    fn inputs(&self) -> Vec<(DataType, String)> {
        // Type of all "inputs" argument is Vec<RemovalRecord>
        vec![(DataType::VoidPointer, "rr_list".to_owned()); NUM_INPUT_LISTS]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        let list_of_digests = DataType::List(Box::new(DataType::Digest));
        vec![(list_of_digests, "list_of_digests".to_string())]
    }

    fn entrypoint(&self) -> String {
        format!("neptune_transaction_hash_removal_record_index_sets_{NUM_INPUT_LISTS}")
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();

        let hash_varlen = library.import(Box::new(HashVarlen));
        let new_list = library.import(Box::new(New::new(DataType::Digest)));
        let push = library.import(Box::new(Push::new(DataType::Digest)));

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

        let hash_absolute_indices_loop = triton_asm! {
            // BEFORE:    _ 0       rss_len *digests *rrs[0]_si
            // INVARIANT: _ i       rss_len *digests *rrs[i]_si
            // AFTER:     _ rss_len rss_len *digests garbage
            {hash_absolute_indices_loop_label}:
                dup 3
                dup 3
                eq
                skiz return

                dup 1
                dup 1
                addi 1
                {&field_with_size!(RemovalRecord::absolute_indices)}
                call {hash_varlen}
                // _ i rss_len *digests *rrs[i]_si *digests [digest; 5]

                call {push}
                // _ i rss_len *digests *rrs[i]_si

                /* advance_to_next_removal_record_element */
                read_mem 1
                push {MAX_REMOVAL_RECORD_ELEM_SIZE}
                dup 2
                lt
                // _ i rss_len *digests rrs[n]_si (*rrs[n]_si-1) (rrs[n]_si < MAX)

                assert
                // _ i rss_len *digests rrs[n]_si (*rrs[n]_si-1)

                addi 2
                add
                // _ i rss_len *digests *rrs[i+1]_si

                swap 3
                addi 1
                swap 3
                // _ (i+1) rss_len *digests *rrs[i+1]_si

                recurse
        };

        let rss_hashing_loop = triton_asm! {
            // BEFORE: _ [*rrs; N] *digests
            // AFTER:  _ [*rrs; N-1] *digests

            /* Verify max length is not exceeded */
            push {MAX_LENGTH_REMOVAL_RECORDS_LIST}
            dup 2
            read_mem 1
            pop 1
            lt
            assert
            // _ [*rrs; N-1] *rrs *digests

            /* fetch rss' length */
            dup 1
            read_mem 1
            pop 1
            // _ [*rrs; N-1] *rrs *digests rss_len

            push 0
            swap 3
            // _ [*rrs; N-1] 0 *digests rss_len *rrs

            swap 1
            swap 2
            swap 1
            addi 1
            // _ [*rrs; N-1] 0 rss_len *digests *rrs[0]_si

            call {hash_absolute_indices_loop_label}
            // _ [*rrs; N-1] rss_len rss_len *digests garbage

            pop 1
            swap 2
            pop 2
            // _ [*rrs; N-1] *digests
        };

        // BEFORE: _ [*rrs; N] *digests
        // AFTER:  _ *digests
        let rss_hashing_loop_unrolled = vec![rss_hashing_loop; NUM_INPUT_LISTS].concat();

        triton_asm!(
            // BEFORE: _ [*rrs; N]
            // AFTER:  _ *digests
            {entrypoint}:

                call {new_list}
                // _ [*rrs; N] *digests

                {&rss_hashing_loop_unrolled}
                // _ *digests

                return

                {&hash_absolute_indices_loop}
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use itertools::Itertools;
    use num_traits::ConstZero;
    use proptest::prelude::Arbitrary;
    use proptest::prelude::Strategy;
    use proptest::test_runner::RngAlgorithm;
    use proptest::test_runner::TestRng;
    use proptest::test_runner::TestRunner;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::rust_shadowing_helper_functions;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::structure::tasm_object::TasmObject;
    use tasm_lib::traits::function::Function;
    use tasm_lib::traits::function::FunctionInitialState;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use twenty_first::prelude::AlgebraicHasher;

    use super::*;
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;

    impl<const N: usize> HashRemovalRecordIndexSets<N> {
        fn init_state(
            &self,
            rrs_ptrs: [BFieldElement; N],
            rrss: [Vec<RemovalRecord>; N],
        ) -> FunctionInitialState {
            let mut memory = HashMap::default();
            for (ptr, rrs) in rrs_ptrs.into_iter().zip(rrss) {
                encode_to_memory(&mut memory, ptr, &rrs);
            }

            let stack = [self.init_stack_for_isolated_run(), rrs_ptrs.to_vec()].concat();

            FunctionInitialState { stack, memory }
        }

        fn pseudorandom_rrs_pointers(rng: &mut TestRng) -> [BFieldElement; N] {
            let mut rrs_ptrs = [BFieldElement::ZERO; N];
            let mut previous_ptr = BFieldElement::ZERO;
            for ptr in &mut rrs_ptrs {
                *ptr = previous_ptr + bfe!(rng.gen_range(1..(1 << 26)));
                previous_ptr = *ptr;
            }
            rrs_ptrs
        }
    }

    impl<const N: usize> Function for HashRemovalRecordIndexSets<N> {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) {
            let digests = (0..N)
                .into_iter()
                .map(|_| stack.pop().unwrap())
                .flat_map(|rrs_ptr| {
                    *Vec::<RemovalRecord>::decode_from_memory(memory, rrs_ptr).unwrap()
                })
                .map(|rrs| rrs.absolute_indices)
                .map(|indices| Tip5::hash(&indices))
                .collect_vec();

            // Emulate effect on memory
            let digests_ptr =
                rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator(memory);
            rust_shadowing_helper_functions::list::list_insert(digests_ptr, digests, memory);

            stack.push(digests_ptr);
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut rng: TestRng = TestRng::from_seed(RngAlgorithm::ChaCha, &seed);

            let rrs_ptrs = Self::pseudorandom_rrs_pointers(&mut rng);

            let arb_params = match bench_case {
                Some(BenchmarkCase::CommonCase) => (2, 0, 0),
                Some(BenchmarkCase::WorstCase) => (20, 0, 0),
                None => (
                    rng.gen_range(0..10),
                    rng.gen_range(0..10),
                    rng.gen_range(0..10),
                ),
            };

            let mut test_runner = TestRunner::new_with_rng(Default::default(), rng);
            let mut removal_records = vec![];
            for _ in 0..N {
                let removal_record = PrimitiveWitness::arbitrary_with(arb_params)
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current()
                    .kernel
                    .inputs;
                removal_records.push(removal_record);
            }
            let removal_records = removal_records.try_into().unwrap();

            self.init_state(rrs_ptrs, removal_records)
        }

        fn corner_case_initial_states(&self) -> Vec<FunctionInitialState> {
            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
            let rrs_ptrs = Self::pseudorandom_rrs_pointers(&mut rng);
            let rrss = vec![vec![]; N].try_into().unwrap();
            let no_inputs = self.init_state(rrs_ptrs, rrss);

            vec![no_inputs]
        }
    }

    #[test]
    fn positive_pbt_0() {
        ShadowedFunction::new(HashRemovalRecordIndexSets::<0>).test();
    }

    #[test]
    fn positive_pbt_1() {
        ShadowedFunction::new(HashRemovalRecordIndexSets::<1>).test();
    }

    #[test]
    fn positive_pbt_2() {
        ShadowedFunction::new(HashRemovalRecordIndexSets::<2>).test();
    }

    #[test]
    fn positive_pbt_5() {
        ShadowedFunction::new(HashRemovalRecordIndexSets::<5>).test();
    }
}

#[cfg(test)]
mod benches {
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;

    use super::*;

    #[test]
    fn hash_removal_record_index_sets_bench_1() {
        ShadowedFunction::new(HashRemovalRecordIndexSets::<1>).bench();
    }

    #[test]
    fn hash_removal_record_index_sets_bench_2() {
        ShadowedFunction::new(HashRemovalRecordIndexSets::<2>).bench();
    }
}
