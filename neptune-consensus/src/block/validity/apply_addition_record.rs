use neptune_mutator_set::shared::BATCH_SIZE;
use neptune_mutator_set::shared::CHUNK_SIZE;
use tasm_lib::arithmetic::u64::incr::Incr as U64Incr;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::list::new::New;
use tasm_lib::memory::memcpy::MemCpy;
use tasm_lib::mmr::calculate_new_peaks_from_append::CalculateNewPeaksFromAppend;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

/// Slides the active window of a mutator set accumulator: the window's
/// indices below the chunk size become a new chunk appended to the inactive
/// SWBF, and the remaining indices move down by the chunk size.
///
/// The window is given by a pointer to its encoding, whose first word is the
/// length of the rest, followed by the list of set indices in ascending
/// order. The new window is a fresh encoding of the same shape. The peaks
/// list is modified in place, as the MMR append is.
///
/// ```text
/// BEFORE: _ *window_encoding *swbfi_peaks [swbfi_leaf_count: u64]
/// AFTER:  _ *window_encoding' *swbfi_peaks [swbfi_leaf_count + 1]
/// ```
///
/// Crashes if an index at or beyond the chunk boundary is followed by one
/// below it, which a sorted window never has.
#[derive(Debug, Copy, Clone)]
pub(super) struct SlideWindow;

impl SlideWindow {
    const UNSORTED_WINDOW_ERROR_ID: i128 = 1_000_601;
}

impl BasicSnippet for SlideWindow {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*window_encoding".to_string()),
            (
                DataType::List(Box::new(DataType::Digest)),
                "*swbfi_peaks".to_string(),
            ),
            (DataType::U64, "swbfi_leaf_count".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*window_encoding".to_string()),
            (
                DataType::List(Box::new(DataType::Digest)),
                "*swbfi_peaks".to_string(),
            ),
            (DataType::U64, "swbfi_leaf_count".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_slide_window".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_list = library.import(Box::new(New));
        let memcpy = library.import(Box::new(MemCpy));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let append = library.import(Box::new(CalculateNewPeaksFromAppend));
        let u64_incr = library.import(Box::new(U64Incr));

        let entrypoint = self.entrypoint();
        let count_loop = format!("{entrypoint}_count_loop");
        let copy_loop = format!("{entrypoint}_copy_loop");

        triton_asm!(
            {entrypoint}:
                // _ *window *swbfi_peaks [swbfi_leaf_count]
                dup 3 addi 1 read_mem 1 addi 2 push 0
                // _ *window *swbfi_peaks [swbfi_leaf_count] n *index[0] 0

                call {count_loop}
                // _ *window *swbfi_peaks [swbfi_leaf_count] n *index[k] k

                // The slid chunk's encoding: the length of the rest, the
                // number of indices, and the first k indices.
                call {new_list}
                // _ *window *swbfi_peaks [swbfi_leaf_count] n *index[k] k *chunk

                dup 1 addi 1 dup 1 write_mem 1 pop 1
                dup 1 dup 1 addi 1 write_mem 1 pop 1
                // _ *window *swbfi_peaks [swbfi_leaf_count] n *index[k] k *chunk

                dup 2 dup 2 push -1 mul add
                dup 1 addi 2
                dup 3
                call {memcpy}
                // _ *window *swbfi_peaks [swbfi_leaf_count] n *index[k] k *chunk

                dup 0 dup 2 addi 2 call {hash_varlen}
                // _ *window *swbfi_peaks [swbfi_leaf_count] n *index[k] k *chunk [chunk_digest]

                pick 5 pop 1
                // _ *window *swbfi_peaks [swbfi_leaf_count] n *index[k] k [chunk_digest]

                dup 9 dup 9
                pick 12
                pick 7 pick 7 pick 7 pick 7 pick 7
                // _ *window [swbfi_leaf_count] n *index[k] k [swbfi_leaf_count] *swbfi_peaks [chunk_digest]

                call {append} pop 1
                // _ *window [swbfi_leaf_count] n *index[k] k *swbfi_peaks

                pick 5 pick 5 call {u64_incr}
                // _ *window n *index[k] k *swbfi_peaks [swbfi_leaf_count']

                // The new window's encoding: the length of the rest, the
                // number of remaining indices, and those indices moved down.
                call {new_list}
                // _ *window n *index[k] k *swbfi_peaks [swbfi_leaf_count'] *window'

                dup 6 dup 5 push -1 mul add
                // _ *window n *index[k] k *swbfi_peaks [swbfi_leaf_count'] *window' n'

                dup 0 addi 1 dup 2 write_mem 1 pop 1
                dup 0 dup 2 addi 1 write_mem 1 pop 1
                // _ *window n *index[k] k *swbfi_peaks [swbfi_leaf_count'] *window' n'

                pick 6
                dup 2 addi 2
                pick 2
                // _ *window n k *swbfi_peaks [swbfi_leaf_count'] *window' *index[k] *window'[0] n'

                call {copy_loop}
                pop 3
                // _ *window n k *swbfi_peaks [swbfi_leaf_count'] *window'

                pick 6 pop 1 pick 5 pop 1 pick 4 pop 1
                // _ *swbfi_peaks [swbfi_leaf_count'] *window'

                place 3
                // _ *window' *swbfi_peaks [swbfi_leaf_count']

                return

            // Counts the indices below the chunk size at the start of the
            // sorted window.
            // INVARIANT: _ n *index[k] k
            {count_loop}:
                dup 2 dup 1 eq skiz return
                // _ n *index[k] k

                dup 1 read_mem 1 pop 1
                push {CHUNK_SIZE} swap 1 lt
                // _ n *index[k] k (index[k] < CHUNK_SIZE)

                push 0 eq skiz return
                // _ n *index[k] k

                pick 1 addi 1 place 1 addi 1
                // _ n *index[k + 1] (k + 1)

                recurse

            // Copies the remaining indices, moved down by the chunk size.
            // INVARIANT: _ *source *destination remaining
            {copy_loop}:
                dup 0 push 0 eq skiz return
                // _ *source *destination remaining

                dup 2 read_mem 1 pop 1
                // _ *source *destination remaining index

                dup 0 push {CHUNK_SIZE} swap 1 lt push 0 eq
                assert error_id {Self::UNSORTED_WINDOW_ERROR_ID}
                // _ *source *destination remaining index

                addi {-i64::from(CHUNK_SIZE)}
                dup 2 write_mem 1
                // _ *source *destination remaining (*destination + 1)

                place 1 pick 2 pop 1
                // _ *source (*destination + 1) remaining

                pick 2 addi 1 place 2
                // _ (*source + 1) (*destination + 1) remaining

                addi -1
                recurse
        )
    }
}

/// Adds an addition record to a mutator set accumulator given as its
/// components, the way [`MutatorSetAccumulator::add`] does: the record is
/// appended to the AOCL, and the window slides if the record's index calls
/// for it.
///
/// The peaks lists are modified in place, so they must be copies when the
/// original accumulator is still needed.
///
/// ```text
/// BEFORE: _ *window_encoding *swbfi_peaks [swbfi_leaf_count: u64] [aocl_leaf_count: u64] *aocl_peaks [addition_record: Digest]
/// AFTER:  _ *window_encoding' *swbfi_peaks [swbfi_leaf_count'] [aocl_leaf_count + 1] *aocl_peaks
/// ```
///
/// [`MutatorSetAccumulator::add`]: neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator::add
#[derive(Debug, Copy, Clone)]
pub(super) struct ApplyAdditionRecord;

impl BasicSnippet for ApplyAdditionRecord {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*window_encoding".to_string()),
            (
                DataType::List(Box::new(DataType::Digest)),
                "*swbfi_peaks".to_string(),
            ),
            (DataType::U64, "swbfi_leaf_count".to_string()),
            (DataType::U64, "aocl_leaf_count".to_string()),
            (
                DataType::List(Box::new(DataType::Digest)),
                "*aocl_peaks".to_string(),
            ),
            (DataType::Digest, "addition_record".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*window_encoding".to_string()),
            (
                DataType::List(Box::new(DataType::Digest)),
                "*swbfi_peaks".to_string(),
            ),
            (DataType::U64, "swbfi_leaf_count".to_string()),
            (DataType::U64, "aocl_leaf_count".to_string()),
            (
                DataType::List(Box::new(DataType::Digest)),
                "*aocl_peaks".to_string(),
            ),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_apply_addition_record".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let append = library.import(Box::new(CalculateNewPeaksFromAppend));
        let u64_incr = library.import(Box::new(U64Incr));
        let slide_window = library.import(Box::new(SlideWindow));

        let entrypoint = self.entrypoint();
        let slide = format!("{entrypoint}_slide");

        triton_asm!(
            {entrypoint}:
                // _ *window *swbfi_peaks [swbfi_leaf_count] [aocl_leaf_count] *aocl_peaks [record]
                dup 7 dup 7 place 9 place 9
                // _ *window *swbfi_peaks [swbfi_leaf_count] [old_aocl_leaf_count] [aocl_leaf_count] *aocl_peaks [record]

                call {append} pop 1
                // _ *window *swbfi_peaks [swbfi_leaf_count] [old_aocl_leaf_count] *aocl_peaks

                dup 2 dup 2 call {u64_incr}
                pick 2
                // _ *window *swbfi_peaks [swbfi_leaf_count] [old_aocl_leaf_count] [aocl_leaf_count'] *aocl_peaks

                // The window slides when the old count is a nonzero multiple
                // of the batch size.
                dup 4 dup 4
                push {BATCH_SIZE} dup 1 div_mod swap 1 pop 1
                push 0 eq
                place 2
                push 0 eq swap 1 push 0 eq mul
                push 0 eq mul
                // _ *window *swbfi_peaks [swbfi_leaf_count] [old_aocl_leaf_count] [aocl_leaf_count'] *aocl_peaks slides

                skiz call {slide}
                // _ *window' *swbfi_peaks [swbfi_leaf_count'] [old_aocl_leaf_count] [aocl_leaf_count'] *aocl_peaks

                pick 4 pop 1 pick 3 pop 1
                // _ *window' *swbfi_peaks [swbfi_leaf_count'] [aocl_leaf_count'] *aocl_peaks

                return

            // BEFORE: _ *window *swbfi_peaks [swbfi_leaf_count] [old_aocl_leaf_count] [aocl_leaf_count'] *aocl_peaks
            // AFTER:  _ *window' *swbfi_peaks [swbfi_leaf_count'] [old_aocl_leaf_count] [aocl_leaf_count'] *aocl_peaks
            {slide}:
                pick 8 pick 8 pick 8 pick 8
                // _ [old_aocl_leaf_count] [aocl_leaf_count'] *aocl_peaks *window *swbfi_peaks [swbfi_leaf_count]

                call {slide_window}
                // _ [old_aocl_leaf_count] [aocl_leaf_count'] *aocl_peaks *window' *swbfi_peaks [swbfi_leaf_count']

                pick 3 place 8
                pick 2 place 7
                pick 1 place 6
                place 5
                // _ *window' *swbfi_peaks [swbfi_leaf_count'] [old_aocl_leaf_count] [aocl_leaf_count'] *aocl_peaks

                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) mod tests {
    use std::collections::HashMap;

    use neptune_mutator_set::active_window::ActiveWindow;
    use neptune_mutator_set::addition_record::AdditionRecord;
    use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use neptune_mutator_set::removal_record::chunk::Chunk;
    use neptune_mutator_set::shared::WINDOW_SIZE;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator;
    use tasm_lib::rust_shadowing_helper_functions::list::list_pop;
    use tasm_lib::rust_shadowing_helper_functions::list::list_push;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::structure::tasm_object::TasmObject;
    use tasm_lib::test_helpers::test_assertion_failure;
    use tasm_lib::test_helpers::test_rust_equivalence_given_execution_state;
    use tasm_lib::traits::function::Function;
    use tasm_lib::traits::function::FunctionInitialState;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::traits::rust_shadow::RustShadowError;
    use tasm_lib::twenty_first::prelude::Mmr;
    use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

    use super::super::mutator_set_hash::tests::random_mutator_set_accumulator;
    use super::*;

    /// Where the components of the accumulator are placed in memory for the
    /// tests, far enough apart for anything realistic.
    const WINDOW_POINTER: BFieldElement = BFieldElement::new(1 << 20);
    const SWBFI_PEAKS_POINTER: BFieldElement = BFieldElement::new(1 << 21);
    const AOCL_PEAKS_POINTER: BFieldElement = BFieldElement::new(1 << 22);

    /// Appends a leaf to an MMR's peaks list in memory exactly as the tasm
    /// snippet does, list operation by list operation, so the memory left
    /// behind agrees. Returns the pointer of the auth path list the snippet
    /// allocates.
    pub(in crate::block::validity) fn mirror_mmr_append(
        peaks_pointer: BFieldElement,
        old_leaf_count: u64,
        leaf: Digest,
        memory: &mut HashMap<BFieldElement, BFieldElement>,
    ) -> Result<BFieldElement, RustShadowError> {
        list_push(peaks_pointer, leaf.values().to_vec(), memory)?;
        let auth_path = dynamic_allocator(memory);
        memory.insert(auth_path, bfe!(0));

        let pop_digest = |memory: &mut HashMap<_, _>| -> Result<Digest, RustShadowError> {
            let words = list_pop(peaks_pointer, memory, Digest::LEN)?;
            Ok(*Digest::decode(&words).unwrap())
        };
        for _ in 0..(old_leaf_count + 1).trailing_zeros() {
            let new_hash = pop_digest(memory)?;
            let previous_peak = pop_digest(memory)?;
            list_push(auth_path, previous_peak.values().to_vec(), memory)?;
            let new_peak = Tip5::hash_pair(previous_peak, new_hash);
            list_push(peaks_pointer, new_peak.values().to_vec(), memory)?;
        }

        Ok(auth_path)
    }

    /// The window encoded at this pointer.
    fn window_at(
        memory: &HashMap<BFieldElement, BFieldElement>,
        pointer: BFieldElement,
    ) -> ActiveWindow {
        *ActiveWindow::decode_from_memory(memory, pointer).unwrap()
    }

    /// Writes the window's encoding to fresh memory, the way the snippets
    /// do.
    fn mirror_new_window(
        window: &ActiveWindow,
        memory: &mut HashMap<BFieldElement, BFieldElement>,
    ) -> BFieldElement {
        let pointer = dynamic_allocator(memory);
        encode_to_memory(memory, pointer, window);
        pointer
    }

    /// The slide as the snippet computes it, with the same memory effects.
    fn mirror_slide(
        window_pointer: BFieldElement,
        swbfi_peaks_pointer: BFieldElement,
        swbfi_leaf_count: u64,
        memory: &mut HashMap<BFieldElement, BFieldElement>,
    ) -> Result<(BFieldElement, u64), RustShadowError> {
        let mut window = window_at(memory, window_pointer);
        let num_below = window
            .sbf
            .iter()
            .take_while(|&&index| index < CHUNK_SIZE)
            .count();
        if window.sbf[num_below..]
            .iter()
            .any(|&index| index < CHUNK_SIZE)
        {
            return Err(RustShadowError::AssertionError(
                SlideWindow::UNSORTED_WINDOW_ERROR_ID,
            ));
        }

        let chunk = Chunk {
            relative_indices: window.sbf[..num_below].to_vec(),
        };
        let chunk_pointer = dynamic_allocator(memory);
        encode_to_memory(memory, chunk_pointer, &chunk);
        mirror_mmr_append(
            swbfi_peaks_pointer,
            swbfi_leaf_count,
            Tip5::hash(&chunk),
            memory,
        )?;

        window.sbf.drain(..num_below);
        for index in &mut window.sbf {
            *index -= CHUNK_SIZE;
        }
        let new_window_pointer = mirror_new_window(&window, memory);

        Ok((new_window_pointer, swbfi_leaf_count + 1))
    }

    fn pop_u64(stack: &mut Vec<BFieldElement>) -> u64 {
        let lo: u32 = stack.pop().unwrap().try_into().unwrap();
        let hi: u32 = stack.pop().unwrap().try_into().unwrap();
        (u64::from(hi) << 32) | u64::from(lo)
    }

    fn push_u64(stack: &mut Vec<BFieldElement>, value: u64) {
        stack.push(bfe!(value >> 32));
        stack.push(bfe!(value & u64::from(u32::MAX)));
    }

    /// The components of the accumulator laid out in memory, as the stack
    /// words the snippets take.
    fn component_words(msa: &MutatorSetAccumulator) -> Vec<BFieldElement> {
        let mut words = vec![WINDOW_POINTER, SWBFI_PEAKS_POINTER];
        push_u64(&mut words, msa.swbf_inactive.num_leafs());
        push_u64(&mut words, msa.aocl.num_leafs());
        words.push(AOCL_PEAKS_POINTER);
        words
    }

    fn component_memory(msa: &MutatorSetAccumulator) -> HashMap<BFieldElement, BFieldElement> {
        let mut memory = HashMap::new();
        encode_to_memory(&mut memory, WINDOW_POINTER, &msa.swbf_active);
        encode_to_memory(&mut memory, SWBFI_PEAKS_POINTER, &msa.swbf_inactive.peaks());
        encode_to_memory(&mut memory, AOCL_PEAKS_POINTER, &msa.aocl.peaks());
        memory
    }

    /// The accumulator the component words on top of this stack describe.
    fn accumulator_from_components(
        stack: &mut Vec<BFieldElement>,
        memory: &HashMap<BFieldElement, BFieldElement>,
    ) -> MutatorSetAccumulator {
        let aocl_peaks_pointer = stack.pop().unwrap();
        let aocl_leaf_count = pop_u64(stack);
        let swbfi_leaf_count = pop_u64(stack);
        let swbfi_peaks_pointer = stack.pop().unwrap();
        let window_pointer = stack.pop().unwrap();
        let peaks = |pointer| *Vec::<Digest>::decode_from_memory(memory, pointer).unwrap();

        MutatorSetAccumulator {
            aocl: MmrAccumulator::init(peaks(aocl_peaks_pointer), aocl_leaf_count),
            swbf_inactive: MmrAccumulator::init(peaks(swbfi_peaks_pointer), swbfi_leaf_count),
            swbf_active: window_at(memory, window_pointer),
        }
    }

    impl Function for SlideWindow {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) -> Result<(), RustShadowError> {
            let swbfi_leaf_count = pop_u64(stack);
            let swbfi_peaks_pointer = stack.pop().unwrap();
            let window_pointer = stack.pop().unwrap();

            let (new_window_pointer, new_leaf_count) = mirror_slide(
                window_pointer,
                swbfi_peaks_pointer,
                swbfi_leaf_count,
                memory,
            )?;

            stack.push(new_window_pointer);
            stack.push(swbfi_peaks_pointer);
            push_u64(stack, new_leaf_count);
            Ok(())
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut rng = StdRng::from_seed(seed);
            let (num_additions, num_window_indices) = match bench_case {
                Some(BenchmarkCase::CommonCase) => (100, 1_000),
                Some(BenchmarkCase::WorstCase) => (1_000, 20_000),
                None => (rng.random_range(0..50), rng.random_range(0..100)),
            };
            let msa = random_mutator_set_accumulator(&mut rng, num_additions, num_window_indices);
            self.initial_state(&msa)
        }

        fn corner_case_initial_states(&self) -> Vec<FunctionInitialState> {
            let mut rng = StdRng::seed_from_u64(0);
            let mut states = vec![];
            for num_additions in [0, 1, 8, 9, 16] {
                let mut msa = random_mutator_set_accumulator(&mut rng, num_additions, 0);
                states.push(self.initial_state(&msa));
                for index in [0, 1, CHUNK_SIZE - 1] {
                    msa.swbf_active.insert(index);
                }
                states.push(self.initial_state(&msa));
                for index in [CHUNK_SIZE, CHUNK_SIZE + 1, WINDOW_SIZE - 1, CHUNK_SIZE] {
                    msa.swbf_active.insert(index);
                }
                states.push(self.initial_state(&msa));
                let mut above_only = random_mutator_set_accumulator(&mut rng, num_additions, 0);
                above_only.swbf_active.insert(CHUNK_SIZE);
                above_only.swbf_active.insert(WINDOW_SIZE - 1);
                states.push(self.initial_state(&above_only));
            }
            states
        }
    }

    impl SlideWindow {
        fn initial_state(&self, msa: &MutatorSetAccumulator) -> FunctionInitialState {
            let mut stack = [self.init_stack_for_isolated_run(), component_words(msa)].concat();
            // The AOCL components are not among the parameters.
            let aocl_words = 3;
            stack.truncate(stack.len() - aocl_words);

            FunctionInitialState {
                stack,
                memory: component_memory(msa),
            }
        }
    }

    #[test]
    fn slide_window_rust_shadow_agrees_with_tasm() {
        ShadowedFunction::new(SlideWindow).test();
    }

    #[test]
    fn slide_window_agrees_with_native_slide() {
        let mut rng = StdRng::seed_from_u64(0);
        for (num_additions, num_window_indices) in [(0, 0), (0, 5), (8, 0), (8, 7), (24, 300)] {
            let msa = random_mutator_set_accumulator(&mut rng, num_additions, num_window_indices);
            let final_state = test_rust_equivalence_given_execution_state(
                &ShadowedFunction::new(SlideWindow),
                SlideWindow.initial_state(&msa).into(),
            );

            let mut stack = final_state.op_stack.stack.clone();
            let new_leaf_count = pop_u64(&mut stack);
            let swbfi_peaks_pointer = stack.pop().unwrap();
            let window_pointer = stack.pop().unwrap();
            let new_peaks =
                *Vec::<Digest>::decode_from_memory(&final_state.ram, swbfi_peaks_pointer).unwrap();
            let new_window = window_at(&final_state.ram, window_pointer);

            let mut expected_swbfi = msa.swbf_inactive.clone();
            expected_swbfi.append(Tip5::hash(&msa.swbf_active.slid_chunk()));
            let mut expected_window = msa.swbf_active.clone();
            expected_window.slide_window();

            assert_eq!(expected_swbfi.num_leafs(), new_leaf_count);
            assert_eq!(expected_swbfi.peaks(), new_peaks);
            assert_eq!(expected_window, new_window);
        }
    }

    #[test]
    fn slide_window_rejects_unsorted_window() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut msa = random_mutator_set_accumulator(&mut rng, 8, 0);
        msa.swbf_active.sbf = vec![CHUNK_SIZE, 3];

        test_assertion_failure(
            &ShadowedFunction::new(SlideWindow),
            SlideWindow.initial_state(&msa).into(),
            &[SlideWindow::UNSORTED_WINDOW_ERROR_ID],
        );
    }

    impl Function for ApplyAdditionRecord {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) -> Result<(), RustShadowError> {
            let record: Digest = tasm_lib::pop_encodable(stack)?;
            let aocl_peaks_pointer = stack.pop().unwrap();
            let aocl_leaf_count = pop_u64(stack);
            let swbfi_leaf_count = pop_u64(stack);
            let swbfi_peaks_pointer = stack.pop().unwrap();
            let window_pointer = stack.pop().unwrap();

            mirror_mmr_append(aocl_peaks_pointer, aocl_leaf_count, record, memory)?;
            let (window_pointer, swbfi_leaf_count) =
                if MutatorSetAccumulator::window_slides(aocl_leaf_count) {
                    mirror_slide(
                        window_pointer,
                        swbfi_peaks_pointer,
                        swbfi_leaf_count,
                        memory,
                    )?
                } else {
                    (window_pointer, swbfi_leaf_count)
                };

            stack.push(window_pointer);
            stack.push(swbfi_peaks_pointer);
            push_u64(stack, swbfi_leaf_count);
            push_u64(stack, aocl_leaf_count + 1);
            stack.push(aocl_peaks_pointer);
            Ok(())
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut rng = StdRng::from_seed(seed);
            let (num_additions, num_window_indices) = match bench_case {
                Some(BenchmarkCase::CommonCase) => (100, 1_000),
                Some(BenchmarkCase::WorstCase) => (1_000, 20_000),
                None => (rng.random_range(0..50), rng.random_range(0..100)),
            };
            let msa = random_mutator_set_accumulator(&mut rng, num_additions, num_window_indices);
            self.initial_state(&msa, rng.random())
        }

        fn corner_case_initial_states(&self) -> Vec<FunctionInitialState> {
            let mut rng = StdRng::seed_from_u64(0);
            let mut states = vec![];
            for num_additions in [0, 1, 7, 8, 9, 15, 16, 17, 63, 64, 65, 127, 128] {
                for num_window_indices in [0, 1, 20] {
                    let msa =
                        random_mutator_set_accumulator(&mut rng, num_additions, num_window_indices);
                    states.push(self.initial_state(&msa, rng.random()));
                }
            }
            states
        }
    }

    impl ApplyAdditionRecord {
        fn initial_state(
            &self,
            msa: &MutatorSetAccumulator,
            record: Digest,
        ) -> FunctionInitialState {
            let stack = [
                self.init_stack_for_isolated_run(),
                component_words(msa),
                record.reversed().values().to_vec(),
            ]
            .concat();

            FunctionInitialState {
                stack,
                memory: component_memory(msa),
            }
        }
    }

    #[test]
    fn apply_addition_record_rust_shadow_agrees_with_tasm() {
        ShadowedFunction::new(ApplyAdditionRecord).test();
    }

    #[test]
    fn apply_addition_record_agrees_with_native_add() {
        let mut rng = StdRng::seed_from_u64(0);
        for num_additions in 0..40 {
            for num_window_indices in [0, 3, 50] {
                let msa =
                    random_mutator_set_accumulator(&mut rng, num_additions, num_window_indices);
                let record = AdditionRecord::new(rng.random());
                let final_state = test_rust_equivalence_given_execution_state(
                    &ShadowedFunction::new(ApplyAdditionRecord),
                    ApplyAdditionRecord
                        .initial_state(&msa, record.canonical_commitment)
                        .into(),
                );

                let mut stack = final_state.op_stack.stack.clone();
                let updated = accumulator_from_components(&mut stack, &final_state.ram);
                let mut expected = msa.clone();
                expected.add(&record);
                assert_eq!(expected, updated);
                assert_eq!(expected.hash(), updated.hash());
            }
        }
    }

    #[test]
    fn repeated_additions_agree_with_native_adds() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut msa = random_mutator_set_accumulator(&mut rng, 5, 10);
        let mut memory = component_memory(&msa);
        let mut components = component_words(&msa);
        for _ in 0..20 {
            let record = AdditionRecord::new(rng.random());
            let mut stack = [
                ApplyAdditionRecord.init_stack_for_isolated_run(),
                components.clone(),
                record.canonical_commitment.reversed().values().to_vec(),
            ]
            .concat();
            let init_state = FunctionInitialState {
                stack: stack.clone(),
                memory: memory.clone(),
            };
            let final_state = test_rust_equivalence_given_execution_state(
                &ShadowedFunction::new(ApplyAdditionRecord),
                init_state.into(),
            );
            memory = final_state.ram.clone();
            stack = final_state.op_stack.stack.clone();
            let num_component_words = 7;
            components = stack[stack.len() - num_component_words..].to_vec();

            msa.add(&record);
            let mut component_stack = components.clone();
            let updated = accumulator_from_components(&mut component_stack, &memory);
            assert_eq!(msa, updated);
        }
    }
}
