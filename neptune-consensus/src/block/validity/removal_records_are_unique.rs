use itertools::Itertools;
use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::shared::NUM_TRIALS;
use tasm_lib::arithmetic::u128::lt::Lt as U128Lt;
use tasm_lib::arithmetic::u128::safe_add::SafeAdd as U128SafeAdd;
use tasm_lib::field;
use tasm_lib::list::new::New;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use super::removal_record_pointers::RemovalRecordPointers;
use crate::block::block_validation_error::BlockValidationRule;

/// Asserts that no two removal records in a list have the same absolute index
/// set. Rule 2.c.
///
/// The order that makes this checkable in one pass comes from
/// non-determinism: the prover supplies a permutation of the list's positions,
/// as one token per record. The snippet asserts that the tokens form a
/// permutation, and that the index sets are strictly increasing along it,
/// comparing the index values lexicographically, as the archival check sorts
/// them. Strictly increasing along a permutation means all distinct.
///
/// ```text
/// BEFORE: _ *removal_records
/// AFTER:  _
/// ```
///
/// Crashes with the error ID of rule 2.c if two index sets are equal, or if
/// the divined tokens are not a permutation of the list's positions.
#[derive(Debug, Copy, Clone)]
pub(super) struct RemovalRecordsAreUnique;

impl RemovalRecordsAreUnique {
    /// The tokens the prover supplies: the positions of the removal records in
    /// ascending order of their index sets. Any permutation is returned for a
    /// list with duplicates; the snippet then rejects the list.
    pub(crate) fn divined_tokens(removal_records: &[RemovalRecord]) -> Vec<BFieldElement> {
        (0..removal_records.len())
            .sorted_by_key(|&i| removal_records[i].absolute_indices.to_vec())
            .map(|i| bfe!(i as u64))
            .collect()
    }
}

impl BasicSnippet for RemovalRecordsAreUnique {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "*removal_records".to_string())]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_removal_records_are_unique".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let record_pointers = library.import(Box::new(RemovalRecordPointers));
        let new_list = library.import(Box::new(New));
        let u128_safe_add = library.import(Box::new(U128SafeAdd));
        let u128_lt = library.import(Box::new(U128Lt));

        let error_id = BlockValidationRule::RemovalRecordsUniqueness.error_id();
        let entrypoint = self.entrypoint();
        let check_nonempty = format!("{entrypoint}_nonempty");
        let check_loop = format!("{entrypoint}_loop");
        let index_set_lt = format!("{entrypoint}_index_set_lt");
        let index_set_lt_loop = format!("{index_set_lt}_loop");

        // Expects a pointer to the first word of the u128.
        let u128_size = DataType::U128.stack_size();
        let read_u128 = triton_asm!(
            addi {u128_size - 1}
            {&DataType::U128.read_value_from_memory_pop_pointer()}
        );

        // The `k`th absolute index of the index set, as a u128: the minimum
        // plus the `k`th distance.
        // BEFORE: _ *index_set k
        // AFTER:  _ [index: u128]
        let read_absolute_index = triton_asm!(
            dup 1 {&field!(AbsoluteIndexSet::minimum)} {&read_u128}
            // _ *index_set k [minimum]

            push 0 push 0 push 0
            // _ *index_set k [minimum] 0 0 0

            pick 8 {&field!(AbsoluteIndexSet::distances)}
            pick 8 add read_mem 1 pop 1
            // _ [minimum] 0 0 0 distance[k]

            call {u128_safe_add}
            // _ [index]
        );

        // Compares the index sets of two removal records lexicographically on
        // their index values. The result is 0 while undecided, 1 once `a < b`
        // is known, 2 once `b < a` is known; all 45 indices equal leaves it 0.
        let index_set_lt_code = triton_asm!(
            // BEFORE: _ *record_a *record_b
            // AFTER:  _ (a < b)
            {index_set_lt}:
                {&field!(RemovalRecord::absolute_indices)}
                pick 1 {&field!(RemovalRecord::absolute_indices)} pick 1
                // _ *index_set_a *index_set_b

                push 0 push 0
                call {index_set_lt_loop}
                // _ *index_set_a *index_set_b k result

                push 1 eq
                place 3 pop 3
                // _ (a < b)

                return

            // INVARIANT: _ *index_set_a *index_set_b k result
            {index_set_lt_loop}:
                dup 0 push 0 eq push 0 eq skiz return
                dup 1 push {NUM_TRIALS} eq skiz return
                // _ *index_set_a *index_set_b k 0

                dup 3 dup 2 {&read_absolute_index}
                // _ *index_set_a *index_set_b k 0 [a_k]

                dup 6 dup 6 {&read_absolute_index}
                // _ *index_set_a *index_set_b k 0 [a_k] [b_k]

                dup 3 dup 3 dup 3 dup 3
                dup 11 dup 11 dup 11 dup 11
                call {u128_lt}
                // _ *index_set_a *index_set_b k 0 [a_k] [b_k] (a_k < b_k)

                place 8
                call {u128_lt}
                // _ *index_set_a *index_set_b k 0 (a_k < b_k) (b_k < a_k)

                push 2 mul add
                // _ *index_set_a *index_set_b k 0 result'

                place 1 pop 1
                // _ *index_set_a *index_set_b k result'

                pick 1 addi 1 place 1
                // _ *index_set_a *index_set_b (k + 1) result'

                recurse
        );

        triton_asm!(
            {entrypoint}:
                // _ *removal_records
                dup 0 call {record_pointers}
                // _ *removal_records *pointers

                pick 1 read_mem 1 pop 1
                // _ *pointers n

                // The positions already taken by a divined token, as a list
                // of flags; fresh memory reads as zero.
                call {new_list}
                // _ *pointers n *taken

                dup 1 push 0 eq push 0 eq
                skiz call {check_nonempty}
                // _ *pointers n *taken

                pop 3
                // _

                return

            // BEFORE: _ *pointers n *taken
            // AFTER:  _ *pointers n *taken
            {check_nonempty}:
                push 0 push 0
                // _ *pointers n *taken 0 0

                // Take the first position without comparing.
                {&Self::divine_position(error_id)}
                // _ *pointers n *taken 0 0 *record

                place 1 pop 1
                // _ *pointers n *taken 0 *record

                pick 1 addi 1 place 1
                // _ *pointers n *taken 1 *record

                call {check_loop}
                // _ *pointers n *taken n *record

                pop 2
                // _ *pointers n *taken

                return

            // INVARIANT: _ *pointers n *taken i *previous
            {check_loop}:
                dup 3 dup 2 eq skiz return
                // _ *pointers n *taken i *previous

                {&Self::divine_position(error_id)}
                // _ *pointers n *taken i *previous *current

                dup 1 dup 1 call {index_set_lt}
                assert error_id {error_id}
                // _ *pointers n *taken i *previous *current

                place 1 pop 1
                // _ *pointers n *taken i *current

                pick 1 addi 1 place 1
                // _ *pointers n *taken (i + 1) *current

                recurse

            {&index_set_lt_code}
        )
    }
}

impl RemovalRecordsAreUnique {
    /// Reads the next divined position, asserts that it is within the list
    /// and not taken already, marks it taken, and resolves it to the removal
    /// record at that position.
    ///
    /// ```text
    /// BEFORE: _ *pointers n *taken x y
    /// AFTER:  _ *pointers n *taken x y *record
    /// ```
    fn divine_position(error_id: i128) -> Vec<LabelledInstruction> {
        triton_asm!(
            divine 1
            // _ *pointers n *taken x y position

            dup 4 dup 1 lt
            assert error_id {error_id}
            // _ *pointers n *taken x y position

            dup 3 dup 1 add addi 1 read_mem 1 pop 1
            push 0 eq assert error_id {error_id}
            // _ *pointers n *taken x y position

            push 1 dup 4 dup 2 add addi 1 write_mem 1 pop 1
            // _ *pointers n *taken x y position

            dup 5 add addi 1 read_mem 1 pop 1
            // _ *pointers n *taken x y *record
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;
    use std::collections::VecDeque;

    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::structure::tasm_object::TasmObject;
    use tasm_lib::test_helpers::test_assertion_failure;
    use tasm_lib::test_helpers::test_rust_equivalence_given_execution_state;
    use tasm_lib::traits::procedure::Procedure;
    use tasm_lib::traits::procedure::ProcedureInitialState;
    use tasm_lib::traits::procedure::ShadowedProcedure;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::traits::rust_shadow::RustShadowError;

    use super::super::removal_record_pointers::tests::random_removal_records;
    use super::super::removal_record_pointers::tests::record_pointers;
    use super::*;

    const LIST_POINTER: BFieldElement = BFieldElement::new(1_000);

    impl Procedure for RemovalRecordsAreUnique {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
            nondeterminism: &NonDeterminism,
            _public_input: &[BFieldElement],
            _sponge: &mut Option<Tip5>,
        ) -> Result<Vec<BFieldElement>, RustShadowError> {
            let error_id = BlockValidationRule::RemovalRecordsUniqueness.error_id();
            let fail = || RustShadowError::AssertionError(error_id);

            let list_pointer = stack.pop().unwrap();
            let removal_records = *Vec::<RemovalRecord>::decode_from_memory(memory, list_pointer)
                .map_err(|_| RustShadowError::AssertionError(0))?;

            // The memory that the pointer table and the taken-flags occupy.
            let pointers = record_pointers(list_pointer, &removal_records);
            let pointers_list = dynamic_allocator(memory);
            memory.insert(pointers_list, bfe!(pointers.len() as u64));
            for (i, pointer) in pointers.iter().enumerate() {
                memory.insert(pointers_list + bfe!(i as u64 + 1), *pointer);
            }
            let taken_list = dynamic_allocator(memory);
            memory.insert(taken_list, bfe!(0));

            let mut tokens: VecDeque<_> = nondeterminism.individual_tokens.clone().into();
            let mut previous: Option<Vec<u128>> = None;
            for _ in 0..removal_records.len() {
                let position = tokens.pop_front().unwrap();
                let position = usize::try_from(position.value()).map_err(|_| fail())?;
                if position >= removal_records.len() {
                    return Err(fail());
                }
                let taken_flag = taken_list + bfe!(position as u64 + 1);
                if memory.get(&taken_flag).copied().unwrap_or_default() != bfe!(0) {
                    return Err(fail());
                }
                memory.insert(taken_flag, bfe!(1));

                let current = removal_records[position].absolute_indices.to_vec();
                if previous.is_some_and(|previous| previous >= current) {
                    return Err(fail());
                }
                previous = Some(current);
            }

            Ok(vec![])
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            bench_case: Option<BenchmarkCase>,
        ) -> ProcedureInitialState {
            let mut rng = StdRng::from_seed(seed);
            let num_records = match bench_case {
                Some(BenchmarkCase::CommonCase) => 10,
                Some(BenchmarkCase::WorstCase) => 100,
                None => rng.random_range(0..12),
            };
            let removal_records = random_removal_records(&mut rng, num_records);
            let tokens = Self::divined_tokens(&removal_records);
            self.initial_state(&removal_records, tokens)
        }

        fn corner_case_initial_states(&self) -> Vec<ProcedureInitialState> {
            vec![self.initial_state(&[], vec![])]
        }
    }

    impl RemovalRecordsAreUnique {
        fn initial_state(
            &self,
            removal_records: &[RemovalRecord],
            tokens: Vec<BFieldElement>,
        ) -> ProcedureInitialState {
            let mut memory = HashMap::new();
            encode_to_memory(&mut memory, LIST_POINTER, &removal_records.to_vec());

            ProcedureInitialState {
                stack: [self.init_stack_for_isolated_run(), vec![LIST_POINTER]].concat(),
                nondeterminism: NonDeterminism::new(tokens).with_ram(memory),
                public_input: vec![],
                sponge: None,
            }
        }
    }

    #[test]
    fn rust_shadow_agrees_with_tasm() {
        ShadowedProcedure::new(RemovalRecordsAreUnique).test();
    }

    #[test]
    fn empty_list_is_accepted() {
        test_rust_equivalence_given_execution_state(
            &ShadowedProcedure::new(RemovalRecordsAreUnique),
            RemovalRecordsAreUnique.initial_state(&[], vec![]).into(),
        );
    }

    #[test]
    fn single_record_is_accepted() {
        let mut rng = StdRng::seed_from_u64(5);
        let removal_records = random_removal_records(&mut rng, 1);
        let tokens = RemovalRecordsAreUnique::divined_tokens(&removal_records);
        assert_eq!(vec![bfe!(0)], tokens);

        test_rust_equivalence_given_execution_state(
            &ShadowedProcedure::new(RemovalRecordsAreUnique),
            RemovalRecordsAreUnique
                .initial_state(&removal_records, tokens)
                .into(),
        );
    }

    #[test]
    fn single_record_with_position_out_of_range_is_rejected() {
        let mut rng = StdRng::seed_from_u64(6);
        let removal_records = random_removal_records(&mut rng, 1);

        test_assertion_failure(
            &ShadowedProcedure::new(RemovalRecordsAreUnique),
            RemovalRecordsAreUnique
                .initial_state(&removal_records, vec![bfe!(1)])
                .into(),
            &[BlockValidationRule::RemovalRecordsUniqueness.error_id()],
        );
    }

    #[test]
    fn two_equal_records_are_rejected_in_either_order() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut removal_records = random_removal_records(&mut rng, 2);
        removal_records[1].absolute_indices = removal_records[0].absolute_indices;

        for tokens in [vec![bfe!(0), bfe!(1)], vec![bfe!(1), bfe!(0)]] {
            test_assertion_failure(
                &ShadowedProcedure::new(RemovalRecordsAreUnique),
                RemovalRecordsAreUnique
                    .initial_state(&removal_records, tokens)
                    .into(),
                &[BlockValidationRule::RemovalRecordsUniqueness.error_id()],
            );
        }
    }

    #[test]
    fn duplicate_index_set_is_rejected() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut removal_records = random_removal_records(&mut rng, 4);
        removal_records[2].absolute_indices = removal_records[0].absolute_indices;
        let tokens = RemovalRecordsAreUnique::divined_tokens(&removal_records);

        test_assertion_failure(
            &ShadowedProcedure::new(RemovalRecordsAreUnique),
            RemovalRecordsAreUnique
                .initial_state(&removal_records, tokens)
                .into(),
            &[BlockValidationRule::RemovalRecordsUniqueness.error_id()],
        );
    }

    #[test]
    fn distinct_index_sets_with_equal_minimum_are_accepted() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut removal_records = random_removal_records(&mut rng, 3);
        let mut distances = [0_u32; NUM_TRIALS as usize];
        for (i, distance) in distances.iter_mut().enumerate() {
            *distance = i as u32;
        }
        removal_records[0].absolute_indices = AbsoluteIndexSet::new_raw(7, distances);
        distances[NUM_TRIALS as usize - 1] += 1;
        removal_records[1].absolute_indices = AbsoluteIndexSet::new_raw(7, distances);
        let tokens = RemovalRecordsAreUnique::divined_tokens(&removal_records);

        test_rust_equivalence_given_execution_state(
            &ShadowedProcedure::new(RemovalRecordsAreUnique),
            RemovalRecordsAreUnique
                .initial_state(&removal_records, tokens)
                .into(),
        );
    }

    #[test]
    fn index_sets_differing_only_in_high_limbs_of_minimum_are_ordered() {
        let mut rng = StdRng::seed_from_u64(4);
        let mut removal_records = random_removal_records(&mut rng, 2);
        let distances = [3_u32; NUM_TRIALS as usize];
        removal_records[0].absolute_indices = AbsoluteIndexSet::new_raw(1 << 100, distances);
        removal_records[1].absolute_indices =
            AbsoluteIndexSet::new_raw((1 << 100) + (1 << 70), distances);

        let tokens = RemovalRecordsAreUnique::divined_tokens(&removal_records);
        assert_eq!(vec![bfe!(0), bfe!(1)], tokens);
        test_rust_equivalence_given_execution_state(
            &ShadowedProcedure::new(RemovalRecordsAreUnique),
            RemovalRecordsAreUnique
                .initial_state(&removal_records, tokens)
                .into(),
        );

        let reversed_tokens = vec![bfe!(1), bfe!(0)];
        test_assertion_failure(
            &ShadowedProcedure::new(RemovalRecordsAreUnique),
            RemovalRecordsAreUnique
                .initial_state(&removal_records, reversed_tokens)
                .into(),
            &[BlockValidationRule::RemovalRecordsUniqueness.error_id()],
        );
    }

    #[test]
    fn position_out_of_range_is_rejected() {
        let mut rng = StdRng::seed_from_u64(2);
        let removal_records = random_removal_records(&mut rng, 3);
        let mut tokens = RemovalRecordsAreUnique::divined_tokens(&removal_records);
        tokens[1] = bfe!(3);

        test_assertion_failure(
            &ShadowedProcedure::new(RemovalRecordsAreUnique),
            RemovalRecordsAreUnique
                .initial_state(&removal_records, tokens)
                .into(),
            &[BlockValidationRule::RemovalRecordsUniqueness.error_id()],
        );
    }

    #[test]
    fn repeated_position_is_rejected() {
        let mut rng = StdRng::seed_from_u64(3);
        let removal_records = random_removal_records(&mut rng, 3);
        let mut tokens = RemovalRecordsAreUnique::divined_tokens(&removal_records);
        tokens[2] = tokens[0];

        test_assertion_failure(
            &ShadowedProcedure::new(RemovalRecordsAreUnique),
            RemovalRecordsAreUnique
                .initial_state(&removal_records, tokens)
                .into(),
            &[BlockValidationRule::RemovalRecordsUniqueness.error_id()],
        );
    }
}
