use tasm_lib::data_type::DataType;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::list::higher_order::inner_function::InnerFunction;
use tasm_lib::list::higher_order::inner_function::RawCode;
use tasm_lib::list::higher_order::map::ChainMap;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::util_types::mutator_set::removal_record::RemovalRecord;

/// Hash the absolute index sets of `NUM_INPUT_LISTS` lists of [`RemovalRecord`]s,
/// putting all resulting digests in one list, which is returned.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HashRemovalRecordIndexSets<const NUM_INPUT_LISTS: usize>;

impl<const NUM_INPUT_LISTS: usize> HashRemovalRecordIndexSets<NUM_INPUT_LISTS> {
    pub const OUT_OF_ELEMENT_POINTER_ERROR_ID: i128 = 1_000_250;
}

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
        let hash_varlen = library.import(Box::new(HashVarlen));

        let hash_one_index_set = triton_asm! {
            // BEFORE: _ *removal_record rr_len
            // AFTER:  _ [index_set_digest: Digest]
            hash_one_index_set:
                dup 1
                {&field_with_size!(RemovalRecord::absolute_indices)}
                            // _ *removal_record rr_len *ai ai_len

                /* check that *ai points into this removal record */
                pick 2      // _ *removal_record *ai ai_len rr_len
                dup 2       // _ *removal_record *ai ai_len rr_len *ai
                pick 4      // _ *ai ai_len rr_len *ai *removal_record
                push -1
                mul
                add         // _ *ai ai_len rr_len (*ai-*removal_record)
                lt          // _ *ai ai_len (*ai-*removal_record < rr_len)
                assert error_id {Self::OUT_OF_ELEMENT_POINTER_ERROR_ID}
                            // _ *ai ai_len

                call {hash_varlen}
                return
        };
        let map = library.import(Box::new(ChainMap::<NUM_INPUT_LISTS>::new(
            InnerFunction::RawCode(RawCode::new(
                hash_one_index_set,
                DataType::Tuple(vec![DataType::VoidPointer, DataType::Bfe]),
                DataType::Digest,
            )),
        )));

        triton_asm! {
            // BEFORE: _ [*rrs; N]
            // AFTER:  _ *digests
            {self.entrypoint()}: call {map} return
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use itertools::Itertools;
    use num_traits::ConstZero;
    use proptest::prelude::Strategy;
    use proptest::test_runner::RngAlgorithm;
    use proptest::test_runner::TestRng;
    use proptest::test_runner::TestRunner;
    use rand::rngs::StdRng;
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

    use super::*;
    use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;

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

        fn pseudorandom_rrs_pointers(rng: &mut StdRng) -> [BFieldElement; N] {
            const ESTIMATED_MAX_NUMBER_OF_REMOVAL_RECORDS: u64 = 20;
            const ESTIMATED_MAX_SIZE_OF_REMOVAL_RECORD: u64 = 10_000;
            const ESTIMATED_MAX_SIZE_OF_REMOVAL_RECORDS_LIST: u64 =
                ESTIMATED_MAX_NUMBER_OF_REMOVAL_RECORDS * ESTIMATED_MAX_SIZE_OF_REMOVAL_RECORD;
            let mut rrs_ptrs = [BFieldElement::ZERO; N];
            let mut previous_ptr = BFieldElement::ZERO;
            for ptr in &mut rrs_ptrs {
                *ptr = previous_ptr
                    + bfe!(rng.random_range(ESTIMATED_MAX_SIZE_OF_REMOVAL_RECORDS_LIST..(1 << 26)));
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
            let mut rng: StdRng = SeedableRng::from_seed(seed);

            let rrs_ptrs = Self::pseudorandom_rrs_pointers(&mut rng);

            let arb_params = match bench_case {
                Some(BenchmarkCase::CommonCase) => (2, 0, 0),
                Some(BenchmarkCase::WorstCase) => (20, 0, 0),
                None => (
                    rng.random_range(0..10),
                    rng.random_range(0..10),
                    rng.random_range(0..10),
                ),
            };
            let (num_inputs, num_outputs, num_announcements) = arb_params;

            let seedd: [u8; 32] = rng.random();
            let mut test_runner = TestRunner::new_with_rng(
                Default::default(),
                TestRng::from_seed(RngAlgorithm::ChaCha, &seedd),
            );
            let mut removal_records = vec![];
            for _ in 0..N {
                let removal_record = PrimitiveWitness::arbitrary_with_size_numbers(
                    Some(num_inputs),
                    num_outputs,
                    num_announcements,
                )
                .new_tree(&mut test_runner)
                .unwrap()
                .current()
                .kernel
                .inputs
                .clone();
                removal_records.push(removal_record);
            }
            let removal_records = removal_records.try_into().unwrap();

            self.init_state(rrs_ptrs, removal_records)
        }

        fn corner_case_initial_states(&self) -> Vec<FunctionInitialState> {
            let mut rng: StdRng = SeedableRng::seed_from_u64(5550001);
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
#[cfg_attr(coverage_nightly, coverage(off))]
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
