use tasm_lib::list::new::New;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use super::copy_words::CopyWords;
use crate::block::block_validation_error::BlockValidationRule;

/// Inserts a sorted list of indices into the sorted list of an active
/// window, producing a fresh window encoding.
///
/// ```text
/// BEFORE: _ *window_encoding *sorted_indices
/// AFTER:  _ *window_encoding'
/// ```
///
/// The window is given by a pointer to its encoding, whose first word is the
/// length of the rest, followed by the list of set indices in ascending
/// order. The new window is a fresh encoding of the same shape, holding the
/// window's entries and the indices, so that it is sorted whenever the
/// window is.
///
/// The prover supplies for each index, in order, the position in the
/// window's list where it goes: the number of the window's entries that
/// precede it. Positions must not decrease, and the entries around a
/// position must enclose the index, with repetitions allowed. The entries
/// between positions are copied, so no entry is compared to anything: the
/// cost is two comparisons per index and a copy of the window.
///
/// Crashes with the error ID of rule 2.e if a position is out of order or
/// its neighbours do not enclose the index.
#[derive(Debug, Copy, Clone)]
pub(super) struct InsertIntoWindow;

impl InsertIntoWindow {
    fn error_id() -> i128 {
        BlockValidationRule::MutatorSetUpdateIntegrity.error_id()
    }

    /// The window's list with the sorted indices inserted: what the snippet
    /// produces for a sorted window.
    #[cfg(test)]
    fn merged(window: &[u32], sorted_indices: &[u32]) -> Vec<u32> {
        let mut merged = window.to_vec();
        merged.extend_from_slice(sorted_indices);
        merged.sort_unstable();
        merged
    }

    /// The tokens the prover supplies: the position of each index.
    pub(crate) fn divined_tokens(window: &[u32], sorted_indices: &[u32]) -> Vec<BFieldElement> {
        sorted_indices
            .iter()
            .map(|&index| bfe!(window.partition_point(|&entry| entry < index) as u64))
            .collect()
    }
}

impl BasicSnippet for InsertIntoWindow {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*window_encoding".to_string()),
            (
                DataType::List(Box::new(DataType::U32)),
                "*sorted_indices".to_string(),
            ),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "*window_encoding'".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_insert_into_window".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_list = library.import(Box::new(New));
        let copy_words = library.import(Box::new(CopyWords));

        let entrypoint = self.entrypoint();
        let insert_loop = format!("{entrypoint}_insert_loop");
        let check_left = format!("{entrypoint}_check_left_neighbour");
        let check_right = format!("{entrypoint}_check_right_neighbour");
        let error_id = Self::error_id();

        triton_asm!(
            {entrypoint}:
                // _ *window_encoding *sorted_indices
                pick 1 addi 1 read_mem 1 addi 2
                // _ *sorted_indices n *window[0]

                pick 2 read_mem 1 addi 2
                // _ n *window[0] m *sorted[0]

                call {new_list}
                // _ n *window[0] m *sorted[0] *window'

                // The new encoding: the length of the rest, then the list's
                // length, then the entries.
                dup 4 dup 3 add dup 0 addi 1 dup 2 write_mem 1 write_mem 1
                // _ n *window[0] m *sorted[0] *window' *window'[0]

                pick 1 place 5 pick 2 place 1 push 0 push 0 pick 2
                // _ *window' n *window[0] *sorted[0] m 0 0 *window'[0]
                //                                       j previous *out

                call {insert_loop}
                // _ *window' n *window[0] *sorted[m] m m previous *out

                // Copy the entries from the last position to the end.
                dup 5 dup 2 add dup 1
                // _ ... *sorted[m] m m previous *out *window[previous] *out

                dup 8 dup 4 push -1 mul add
                // _ ... *sorted[m] m m previous *out *window[previous] *out (n - previous)

                call {copy_words}
                // _ *window' n *window[0] *sorted[m] m m previous *out

                pop 5 pop 2
                // _ *window'

                return

            // Inserts the index at its divined position, after copying the
            // window's entries from the previous position up to there.
            // INVARIANT: _ *window' n *window[0] *sorted[j] m j previous *out
            {insert_loop}:
                dup 3 dup 3 eq skiz return
                // _ *window' n *window[0] *sorted[j] m j previous *out

                divine 1
                // _ ... previous *out position

                // Positions do not decrease, and do not exceed the window's
                // length.
                dup 2 dup 1 lt push 0 eq assert error_id {error_id}
                dup 0 dup 8 lt push 0 eq assert error_id {error_id}
                // _ ... previous *out position

                dup 5 read_mem 1 pop 1
                // _ ... previous *out position index

                dup 1 push 0 eq push 0 eq skiz call {check_left}
                dup 1 dup 9 eq push 0 eq skiz call {check_right}
                // _ ... previous *out position index

                // Copy the entries from the previous position to this one.
                dup 7 dup 4 add dup 3
                // _ ... previous *out position index *window[previous] *out

                dup 3 dup 6 push -1 mul add
                // _ ... previous *out position index *window[previous] *out (position - previous)

                call {copy_words}
                // _ ... previous *out position index

                // The index goes after the copied entries.
                dup 1 dup 4 push -1 mul add dup 3 add write_mem 1
                // _ ... previous *out position *out'

                place 3 pick 2 pop 1 swap 1 pop 1 swap 1
                // _ *window' n *window[0] *sorted[j] m j position *out'

                pick 2 addi 1 place 2
                pick 4 addi 1 place 4
                // _ *window' n *window[0] *sorted[j + 1] m (j + 1) position *out'

                recurse

            // The entry before the position must not exceed the index.
            // BEFORE: _ ... *window[0] *sorted[j] m j previous *out position index
            // AFTER:  _ ... *window[0] *sorted[j] m j previous *out position index
            {check_left}:
                dup 7 dup 2 add addi -1 read_mem 1 pop 1
                // _ ... position index window[position - 1]

                dup 1 lt push 0 eq assert error_id {error_id}
                // _ ... position index

                return

            // The entry at the position must not fall below the index.
            // BEFORE: _ ... *window[0] *sorted[j] m j previous *out position index
            // AFTER:  _ ... *window[0] *sorted[j] m j previous *out position index
            {check_right}:
                dup 7 dup 2 add read_mem 1 pop 1
                // _ ... position index window[position]

                dup 1 swap 1 lt push 0 eq assert error_id {error_id}
                // _ ... position index

                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;
    use std::collections::VecDeque;

    use neptune_mutator_set::active_window::ActiveWindow;
    use neptune_mutator_set::shared::WINDOW_SIZE;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::test_helpers::test_assertion_failure;
    use tasm_lib::test_helpers::test_rust_equivalence_given_execution_state;
    use tasm_lib::traits::procedure::Procedure;
    use tasm_lib::traits::procedure::ProcedureInitialState;
    use tasm_lib::traits::procedure::ShadowedProcedure;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::traits::rust_shadow::RustShadowError;

    use super::*;

    const WINDOW_POINTER: BFieldElement = BFieldElement::new(1 << 20);
    const INDICES_POINTER: BFieldElement = BFieldElement::new(1 << 22);

    impl Procedure for InsertIntoWindow {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
            nondeterminism: &NonDeterminism,
            _public_input: &[BFieldElement],
            _sponge: &mut Option<Tip5>,
        ) -> Result<Vec<BFieldElement>, RustShadowError> {
            let fail = || RustShadowError::AssertionError(Self::error_id());
            let indices_pointer = stack.pop().unwrap();
            let window_pointer = stack.pop().unwrap();
            let read_list = |memory: &HashMap<BFieldElement, BFieldElement>,
                             pointer: BFieldElement| {
                let length = memory[&pointer].value();
                (0..length)
                    .map(|i| memory[&(pointer + bfe!(1 + i))])
                    .collect::<Vec<_>>()
            };
            let window = read_list(memory, window_pointer + bfe!(1));
            let indices = read_list(memory, indices_pointer);

            let mut tokens: VecDeque<_> = nondeterminism.individual_tokens.clone().into();
            let merged = dynamic_allocator(memory);
            memory.insert(merged, bfe!(window.len() as u64 + indices.len() as u64 + 1));
            memory.insert(
                merged + bfe!(1),
                bfe!(window.len() as u64 + indices.len() as u64),
            );
            let mut out = merged + bfe!(2);
            let mut previous = 0;
            for &index in &indices {
                let position = tokens.pop_front().unwrap().value() as usize;
                if position < previous || position > window.len() {
                    return Err(fail());
                }
                if position > 0 && window[position - 1].value() > index.value() {
                    return Err(fail());
                }
                if position < window.len() && window[position].value() < index.value() {
                    return Err(fail());
                }
                for &entry in &window[previous..position] {
                    memory.insert(out, entry);
                    out += bfe!(1);
                }
                memory.insert(out, index);
                out += bfe!(1);
                previous = position;
            }
            for &entry in &window[previous..] {
                memory.insert(out, entry);
                out += bfe!(1);
            }

            stack.push(merged);
            Ok(vec![])
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            bench_case: Option<BenchmarkCase>,
        ) -> ProcedureInitialState {
            let mut rng = StdRng::from_seed(seed);
            let (window_length, num_indices) = match bench_case {
                Some(BenchmarkCase::CommonCase) => (1000, 45),
                Some(BenchmarkCase::WorstCase) => (10_000, 450),
                None => (rng.random_range(0..200), rng.random_range(0..50)),
            };
            let window = sorted_random(&mut rng, window_length);
            let indices = sorted_random(&mut rng, num_indices);
            self.honest_state(&window, &indices)
        }

        fn corner_case_initial_states(&self) -> Vec<ProcedureInitialState> {
            [
                (vec![], vec![]),
                (vec![], vec![7]),
                (vec![7], vec![]),
                (vec![7], vec![7]),
                (vec![7], vec![3]),
                (vec![7], vec![9]),
                (vec![7], vec![3, 9]),
                (vec![7], vec![3, 7, 9]),
                (vec![1, 5, 9], vec![0, 1, 2, 5, 5, 9, 10]),
                (vec![5, 5, 5], vec![5, 5]),
                (vec![0, WINDOW_SIZE - 1], vec![0, WINDOW_SIZE - 1]),
                ((0..1000).collect(), (0..10).map(|i| 100 * i).collect()),
            ]
            .into_iter()
            .map(|(window, indices)| self.honest_state(&window, &indices))
            .collect()
        }
    }

    fn sorted_random(rng: &mut StdRng, length: usize) -> Vec<u32> {
        let mut entries = (0..length)
            .map(|_| rng.random_range(0..WINDOW_SIZE))
            .collect::<Vec<_>>();
        entries.sort_unstable();
        entries
    }

    impl InsertIntoWindow {
        fn honest_state(&self, window: &[u32], indices: &[u32]) -> ProcedureInitialState {
            self.initial_state(window, indices, Self::divined_tokens(window, indices))
        }

        fn initial_state(
            &self,
            window: &[u32],
            indices: &[u32],
            tokens: Vec<BFieldElement>,
        ) -> ProcedureInitialState {
            let mut memory = HashMap::new();
            encode_to_memory(
                &mut memory,
                WINDOW_POINTER,
                &ActiveWindow::from_vec_u32(window.to_vec()),
            );
            encode_to_memory(&mut memory, INDICES_POINTER, &indices.to_vec());
            let stack = [
                self.init_stack_for_isolated_run(),
                vec![WINDOW_POINTER, INDICES_POINTER],
            ]
            .concat();

            ProcedureInitialState {
                stack,
                nondeterminism: NonDeterminism::new(tokens).with_ram(memory),
                public_input: vec![],
                sponge: None,
            }
        }
    }

    fn assert_accepts(window: &[u32], indices: &[u32]) {
        test_rust_equivalence_given_execution_state(
            &ShadowedProcedure::new(InsertIntoWindow),
            InsertIntoWindow.honest_state(window, indices).into(),
        );
    }

    fn assert_rejects_with_tokens(window: &[u32], indices: &[u32], tokens: Vec<BFieldElement>) {
        test_assertion_failure(
            &ShadowedProcedure::new(InsertIntoWindow),
            InsertIntoWindow
                .initial_state(window, indices, tokens)
                .into(),
            &[InsertIntoWindow::error_id()],
        );
    }

    #[test]
    fn rust_shadow_agrees_with_tasm() {
        ShadowedProcedure::new(InsertIntoWindow).test();
    }

    #[test]
    fn produced_window_is_the_sorted_merge() {
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..30 {
            let window_length = rng.random_range(0..100);
            let num_indices = rng.random_range(0..30);
            let window = sorted_random(&mut rng, window_length);
            let indices = sorted_random(&mut rng, num_indices);
            let state = InsertIntoWindow.honest_state(&window, &indices);
            let final_state = tasm_lib::test_helpers::tasm_final_state(
                &ShadowedProcedure::new(InsertIntoWindow),
                &state.stack,
                &state.public_input,
                state.nondeterminism,
                &state.sponge,
            )
            .unwrap();
            let merged_pointer = *final_state.op_stack.stack.last().unwrap();
            let memory = &final_state.ram;
            let length = memory[&(merged_pointer + bfe!(1))].value() as usize;
            let produced = (0..length)
                .map(|i| memory[&(merged_pointer + bfe!(2 + i as u64))].value() as u32)
                .collect::<Vec<_>>();
            assert_eq!(InsertIntoWindow::merged(&window, &indices), produced);
            assert_eq!(
                bfe!(length as u64 + 1),
                memory[&merged_pointer],
                "the encoding's first word is the length of the rest"
            );
            let encoding = ActiveWindow::from_vec_u32(produced).encode();
            let produced_encoding = (0..encoding.len())
                .map(|i| memory[&(merged_pointer + bfe!(i as u64))])
                .collect::<Vec<_>>();
            assert_eq!(encoding, produced_encoding);
        }
    }

    #[test]
    fn any_enclosing_position_is_accepted() {
        // With repetitions, several positions enclose an index.
        let window = vec![3, 5, 5, 5, 8];
        let indices = vec![5];
        for position in 1..=4 {
            test_rust_equivalence_given_execution_state(
                &ShadowedProcedure::new(InsertIntoWindow),
                InsertIntoWindow
                    .initial_state(&window, &indices, vec![bfe!(position)])
                    .into(),
            );
        }
        for position in [0, 5] {
            assert_rejects_with_tokens(&window, &indices, vec![bfe!(position)]);
        }
    }

    #[test]
    fn wrong_positions_are_rejected() {
        let window = vec![1, 4, 6, 9, 12];
        let indices = vec![0, 5, 10, 13];
        let honest = InsertIntoWindow::divined_tokens(&window, &indices);
        assert_eq!(vec![bfe!(0), bfe!(2), bfe!(4), bfe!(5)], honest);
        assert_accepts(&window, &indices);

        // Each position moved by one, either way: no index repeats an
        // entry, so exactly one position encloses each.
        for at in 0..indices.len() {
            for delta in [-1_i64, 1] {
                let mut tokens = honest.clone();
                let shifted = tokens[at].value() as i64 + delta;
                if shifted < 0 {
                    continue;
                }
                tokens[at] = bfe!(shifted as u64);
                assert_rejects_with_tokens(&window, &indices, tokens);
            }
        }

        // A position beyond the window's length.
        let mut tokens = honest.clone();
        tokens[3] = bfe!(6);
        assert_rejects_with_tokens(&window, &indices, tokens);

        // Positions that decrease, though each encloses its index.
        let window = vec![5, 5];
        let indices = vec![5, 5];
        assert_accepts(&window, &indices);
        assert_rejects_with_tokens(&window, &indices, vec![bfe!(2), bfe!(0)]);
    }

    #[test]
    fn empty_inputs_are_accepted() {
        assert_accepts(&[], &[]);
        assert_accepts(&[], &[1, 2, 3]);
        assert_accepts(&[1, 2, 3], &[]);
    }
}
