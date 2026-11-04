use neptune_mutator_set::active_window::ActiveWindow;
use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::shared::CHUNK_SIZE;
use neptune_mutator_set::shared::NUM_TRIALS;
use neptune_mutator_set::shared::WINDOW_SIZE;
use tasm_lib::arithmetic::u128::lt::Lt as U128Lt;
use tasm_lib::arithmetic::u128::safe_add::SafeAdd as U128SafeAdd;
use tasm_lib::arithmetic::u128::shift_left_static::ShiftLeftStatic;
use tasm_lib::arithmetic::u128::sub::Sub as U128Sub;
use tasm_lib::field;
use tasm_lib::list::new::New;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::block::block_validation_error::BlockValidationRule;

/// Asserts that no removal record's item has been removed already: each
/// record has an index that is not set in the sliding-window Bloom filter
/// before the block. Rules 2.b and 2.d, on the mutator set the records are
/// synced to.
///
/// The prover points at such an index per record, and at a gap position in
/// the sorted list the index would sit in, whose neighbours must enclose
/// the index strictly: the chunk the witness carries if the index lies in
/// the inactive part, the active window's list otherwise. The mutator set
/// keeps its chunks sorted, and a chunk's contents are pinned by its hash
/// separately; the window is checked once to be sorted, with repetitions
/// as the mutator set produces them, and inside the window.
///
/// ```text
/// BEFORE: _ *removal_records *chunk_indices *chunks *active_window [swbfi_leaf_count: u64]
/// AFTER:  _
/// ```
///
/// `*chunks` lists pointers to the unpacked chunks, in the order of
/// `*chunk_indices`. The authenticity check that pins their contents comes
/// separately.
///
/// Tokens per record: the position of the index among the record's 45, then
/// the position of its chunk among the chunk indices if it lies in the
/// inactive part, then the gap position in the chunk or in the window.
/// Crashes with the error ID of rule 2.b if a record's index at the divined
/// position is set, and with a dedicated error ID if the window is not
/// sorted or holds an entry outside the window.
#[derive(Debug, Copy, Clone)]
pub(super) struct RemovalRecordsAreUnspent;

impl RemovalRecordsAreUnspent {
    const LOG2_CHUNK_SIZE: u8 = CHUNK_SIZE.ilog2() as u8;
    pub(super) const UNSORTED_WINDOW_ERROR_ID: i128 = 1_000_620;

    /// The gap position of an index in a sorted list: where it would be
    /// inserted. If the index is set, the position given still fails.
    fn gap_position(sorted: &[u32], index: u32) -> usize {
        sorted.partition_point(|&set| set < index)
    }

    /// The tokens the prover supplies, given the chunks by chunk index and
    /// the active window before the block: a record's first unset index. A
    /// record whose indices are all set gets its first index, which the
    /// snippet then
    /// rejects.
    pub(crate) fn divined_tokens(
        removal_records: &[RemovalRecord],
        chunk_indices: &[u64],
        chunks: &[Vec<u32>],
        active_window: &ActiveWindow,
        swbfi_leaf_count: u64,
    ) -> Vec<BFieldElement> {
        let window_start = u128::from(swbfi_leaf_count) << Self::LOG2_CHUNK_SIZE;
        let mut tokens = vec![];
        for record in removal_records {
            let indices = record.absolute_indices.to_array();
            // The tokens of the index at the position, and whether it is
            // unset.
            let tokens_of = |position: usize| {
                let index = indices[position];
                if index < window_start {
                    let chunk_index = (index >> Self::LOG2_CHUNK_SIZE) as u64;
                    let chunk_position = chunk_indices
                        .binary_search(&chunk_index)
                        .unwrap_or_else(|insertion_point| insertion_point);
                    let relative_index = (index % u128::from(CHUNK_SIZE)) as u32;
                    let chunk = chunks.get(chunk_position).map(Vec::as_slice).unwrap_or(&[]);
                    let gap = Self::gap_position(chunk, relative_index);
                    let is_unset = !chunk.contains(&relative_index);
                    (
                        vec![
                            bfe!(position as u64),
                            bfe!(chunk_position as u64),
                            bfe!(gap as u64),
                        ],
                        is_unset,
                    )
                } else {
                    let relative_index = (index - window_start).min(u128::from(u32::MAX)) as u32;
                    let gap = Self::gap_position(&active_window.sbf, relative_index);
                    let is_unset = !active_window.sbf.contains(&relative_index);
                    (vec![bfe!(position as u64), bfe!(gap as u64)], is_unset)
                }
            };
            let (record_tokens, _) = (0..indices.len())
                .map(tokens_of)
                .find(|(_, is_unset)| *is_unset)
                .unwrap_or_else(|| tokens_of(0));
            tokens.extend(record_tokens);
        }
        tokens
    }
}

impl BasicSnippet for RemovalRecordsAreUnspent {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*removal_records".to_string()),
            (
                DataType::List(Box::new(DataType::U64)),
                "*chunk_indices".to_string(),
            ),
            (
                DataType::List(Box::new(DataType::Bfe)),
                "*chunks".to_string(),
            ),
            (DataType::VoidPointer, "*active_window".to_string()),
            (DataType::U64, "swbfi_leaf_count".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_removal_records_are_unspent".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_list = library.import(Box::new(New));
        let u128_lt = library.import(Box::new(U128Lt));
        let u128_sub = library.import(Box::new(U128Sub));
        let u128_safe_add = library.import(Box::new(U128SafeAdd));
        let to_window_start =
            library.import(Box::new(ShiftLeftStatic::<{ Self::LOG2_CHUNK_SIZE }>));

        let entrypoint = self.entrypoint();
        let assert_sorted = format!("{entrypoint}_assert_sorted");
        let sorted_by_5 = format!("{entrypoint}_sorted_by_5");
        let sorted_by_1 = format!("{entrypoint}_sorted_by_1");
        let records_loop = format!("{entrypoint}_records_loop");
        let inactive = format!("{entrypoint}_inactive");
        let active = format!("{entrypoint}_active");
        let gap = format!("{entrypoint}_gap");
        let gap_left = format!("{entrypoint}_gap_left");
        let gap_right = format!("{entrypoint}_gap_right");

        let chunk_size = CHUNK_SIZE;
        let read_u128 = triton_asm!(addi 3 read_mem 4 pop 1);

        // Asserts y <= x, keeping the larger one.
        // BEFORE: _ x y
        // AFTER:  _ x
        let assert_below_keep_upper =
            triton_asm!(dup 1 lt push 0 eq assert error_id {Self::UNSORTED_WINDOW_ERROR_ID});

        // Asserts y <= x, keeping the smaller one.
        // BEFORE: _ x y
        // AFTER:  _ y
        let assert_below_keep_lower = triton_asm!(
            dup 0 place 2 swap 1 lt push 0 eq assert error_id {Self::UNSORTED_WINDOW_ERROR_ID}
        );

        // BEFORE: _ neg_index ... e (element - index) * ...
        // Folds one more element into the product.
        // The context: the chunk indices and their number, the chunks, the
        // active window's list, and the window start.
        let chunk_indices_offset = 0;
        let num_chunks_offset = 1;
        let chunks_offset = 2;
        let window_offset = 3;
        let window_start_offset = 4;

        triton_asm!(
            {entrypoint}:
                // _ *removal_records *chunk_indices *chunks *active_window [swbfi_leaf_count]
                push 0 push 0 pick 3 pick 3 call {to_window_start}
                // _ *removal_records *chunk_indices *chunks *active_window [window_start]

                pick 4 {&field!(ActiveWindow::sbf)}
                dup 0 call {assert_sorted}
                // _ *removal_records *chunk_indices *chunks [window_start] *window

                pick 5 dup 6 read_mem 1 pop 1 pick 7
                // _ *removal_records [window_start] *window *chunks num_chunks *chunk_indices

                call {new_list}
                write_mem 5 write_mem 3 addi -8
                // _ *removal_records *context

                swap 1 read_mem 1 addi 2 place 1 push 0
                // _ *context *record[0]_si num_records 0

                call {records_loop}
                pop 4
                // _

                return

            // The window's list must be sorted, with every entry inside the
            // window, for the gap test to mean anything. The entries are
            // checked from the last one down, against the largest index in
            // the window first.
            // BEFORE: _ *list
            // AFTER:  _
            {assert_sorted}:
                read_mem 1 addi 1 dup 1 add
                // _ len *last

                push {WINDOW_SIZE - 1}
                // _ len *next prev

                call {sorted_by_5}
                call {sorted_by_1}
                // _ 0 *list prev

                pop 3
                return

            // INVARIANT: _ len *next prev
            {sorted_by_5}:
                push 5 dup 3 lt skiz return
                // _ len *next prev

                swap 1 read_mem 5 place 6
                // _ len (*next - 5) prev m[next] m[next - 1] m[next - 2] m[next - 3] m[next - 4]

                dup 0 place 6
                // _ len (*next - 5) m[next - 4] prev m[next] m[next - 1] m[next - 2] m[next - 3] m[next - 4]

                {&assert_below_keep_upper}
                {&assert_below_keep_upper}
                {&assert_below_keep_upper}
                {&assert_below_keep_upper}
                {&assert_below_keep_upper}
                // _ len (*next - 5) m[next - 4] prev

                pop 1
                pick 2 addi -5 place 2
                // _ (len - 5) (*next - 5) m[next - 4]

                recurse

            // INVARIANT: _ len *next prev
            {sorted_by_1}:
                dup 2 push 0 eq skiz return
                // _ len *next prev

                swap 1 read_mem 1 place 2
                // _ len (*next - 1) prev m[next]

                {&assert_below_keep_lower}
                // _ len (*next - 1) m[next]

                pick 2 addi -1 place 2
                // _ (len - 1) (*next - 1) m0

                recurse

            // INVARIANT: _ *context *record[i]_si num_records i
            {records_loop}:
                dup 1 dup 1 eq skiz return
                // _ *context *record[i]_si num_records i

                divine 1
                dup 0 push {NUM_TRIALS} swap 1 lt assert error_id {BlockValidationRule::RemovalRecordsValidity.error_id()}
                // _ *context *record[i]_si num_records i position

                dup 3 addi 1 {&field!(RemovalRecord::absolute_indices)}
                // _ *context *record[i]_si num_records i position *index_set

                dup 0 {&field!(AbsoluteIndexSet::minimum)} {&read_u128}
                // _ *context *record[i]_si num_records i position *index_set [minimum]

                push 0 push 0 push 0
                pick 7 {&field!(AbsoluteIndexSet::distances)} pick 8 add read_mem 1 pop 1
                // _ *context *record[i]_si num_records i [minimum] 0 0 0 distance

                call {u128_safe_add}
                // _ *context *record[i]_si num_records i [index]

                dup 7 addi {window_start_offset + 3} read_mem 4 pop 1
                dup 7 dup 7 dup 7 dup 7
                call {u128_lt}
                // _ *context *record[i]_si num_records i [index] (index < window_start)

                dup 0 skiz call {inactive}
                push 0 eq skiz call {active}
                // _ *context *record[i]_si num_records i

                pick 2 read_mem 1
                // _ *context num_records i record_size (*record[i]_si - 1)

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1

                addi 2 add place 2 addi 1
                // _ *context *record[i + 1]_si num_records (i + 1)

                recurse

            // The index lies in a chunk of the inactive part: the one at the
            // divined position, whose chunk index must agree.
            // BEFORE: _ *context *record_si num_records i [index] 1
            // AFTER:  _ *context *record_si num_records i 1
            {inactive}:
                pop 1
                // _ *context *record_si num_records i i3 i2 i1 i0

                push {chunk_size} swap 1 div_mod
                // _ ... i3 i2 i1 q0 r0

                pick 2 push {chunk_size} swap 1 div_mod
                // _ ... i3 i2 q0 r0 q1 r1

                push {1_u64 << (32 - Self::LOG2_CHUNK_SIZE)} mul
                pick 3 add
                // _ ... i3 i2 r0 q1 chunk_lo

                pick 3 push {chunk_size} swap 1 div_mod swap 1 pop 1
                push {1_u64 << (32 - Self::LOG2_CHUNK_SIZE)} mul
                pick 2 add
                // _ ... i3 r0 chunk_lo chunk_hi

                pick 3 pop 1
                // _ *context *record_si num_records i r0 chunk_lo chunk_hi

                divine 1
                // _ ... r0 chunk_lo chunk_hi position

                dup 7 addi {num_chunks_offset} read_mem 1 pop 1
                dup 1 lt assert error_id {BlockValidationRule::RemovalRecordsValidity.error_id()}
                // _ ... r0 chunk_lo chunk_hi position

                dup 7 addi {chunk_indices_offset} read_mem 1 pop 1
                dup 1 push 2 mul add addi 2 read_mem 2 pop 1
                // _ ... r0 chunk_lo chunk_hi position listed_hi listed_lo

                pick 4 eq place 2 pick 3 eq
                // _ ... r0 lo_agree position hi_agree

                swap 1 place 2 mul assert error_id {BlockValidationRule::RemovalRecordsValidity.error_id()}
                // _ ... r0 position

                dup 5 addi {chunks_offset} read_mem 1 pop 1
                add addi 1 read_mem 1 pop 1
                // _ ... r0 *chunk

                swap 1 call {gap}
                // _ *context *record_si num_records i

                push 1
                return

            // The index lies in the active window.
            // BEFORE: _ *context *record_si num_records i [index]
            // AFTER:  _ *context *record_si num_records i
            {active}:
                dup 7 addi {window_start_offset + 3} read_mem 4 pop 1
                pick 7 pick 7 pick 7 pick 7
                call {u128_sub}
                // _ *context *record_si num_records i [index - window_start]

                // The difference must fit the window.
                place 3 add add push 0 eq assert error_id {BlockValidationRule::RemovalRecordsValidity.error_id()}
                dup 0 push {WINDOW_SIZE} swap 1 lt assert error_id {BlockValidationRule::RemovalRecordsValidity.error_id()}
                // _ *context *record_si num_records i relative_index

                dup 4 addi {window_offset} read_mem 1 pop 1
                swap 1 call {gap}
                // _ *context *record_si num_records i

                return

            // The index must lie strictly between the entries around the
            // divined gap position of the sorted list.
            // BEFORE: _ *list index
            // AFTER:  _
            {gap}:
                divine 1
                // _ *list index gap

                dup 2 read_mem 1 pop 1
                // _ *list index gap len

                dup 0 addi 1 dup 2 lt assert error_id {BlockValidationRule::RemovalRecordsValidity.error_id()}
                // _ *list index gap len

                dup 1 push 0 eq push 0 eq skiz call {gap_left}
                dup 1 dup 1 eq push 0 eq skiz call {gap_right}
                // _ *list index gap len

                pop 4
                return

            // BEFORE: _ *list index gap len
            // AFTER:  _ *list index gap len
            {gap_left}:
                dup 3 dup 2 add read_mem 1 pop 1
                // _ *list index gap len list[gap - 1]

                dup 3 swap 1 lt assert error_id {BlockValidationRule::RemovalRecordsValidity.error_id()}
                // _ *list index gap len

                return

            // BEFORE: _ *list index gap len
            // AFTER:  _ *list index gap len
            {gap_right}:
                dup 3 dup 2 add addi 1 read_mem 1 pop 1
                // _ *list index gap len list[gap]

                dup 3 lt assert error_id {BlockValidationRule::RemovalRecordsValidity.error_id()}
                // _ *list index gap len

                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;
    use std::collections::VecDeque;

    use neptune_mutator_set::msa_and_records::MsaAndRecords;
    use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use neptune_mutator_set::removal_record::chunk::Chunk;
    use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
    use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
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
    use tasm_lib::twenty_first::prelude::Mmr;

    use super::super::chunk_witness::tests::random_msa_and_records;
    use super::*;

    const RECORDS_POINTER: BFieldElement = BFieldElement::new(1 << 20);
    const CHUNK_INDICES_POINTER: BFieldElement = BFieldElement::new(1 << 21);
    const CHUNKS_POINTER: BFieldElement = BFieldElement::new(1 << 22);
    const FIRST_CHUNK_POINTER: BFieldElement = BFieldElement::new(1 << 23);
    const WINDOW_POINTER: BFieldElement = BFieldElement::new(1 << 24);

    /// The chunks of the records by ascending chunk index, from the
    /// unpacked records: sorted, as the mutator set keeps them.
    fn chunks_of(msa_and_records: &MsaAndRecords) -> (Vec<u64>, Vec<Vec<u32>>) {
        let mut by_index: Vec<(u64, Vec<u32>)> = msa_and_records
            .unpacked_removal_records()
            .iter()
            .flat_map(|record| record.target_chunks.indices_and_chunks())
            .map(|(index, chunk)| (index, chunk.relative_indices))
            .collect();
        by_index.sort();
        by_index.dedup();
        by_index.into_iter().unzip()
    }

    /// The active window of the fixture as the mutator set produces it: a
    /// sorted multiset of indices inside the window. The fixture's window is
    /// random, and neither.
    fn window_of(msa_and_records: &MsaAndRecords) -> ActiveWindow {
        let mut sbf = msa_and_records
            .mutator_set_accumulator
            .swbf_active
            .sbf
            .iter()
            .map(|index| index % WINDOW_SIZE)
            .collect::<Vec<_>>();
        sbf.sort_unstable();
        ActiveWindow::from_vec_u32(sbf)
    }

    fn pop_u64(stack: &mut Vec<BFieldElement>) -> u64 {
        let lo: u32 = stack.pop().unwrap().try_into().unwrap();
        let hi: u32 = stack.pop().unwrap().try_into().unwrap();
        (u64::from(hi) << 32) | u64::from(lo)
    }

    impl Procedure for RemovalRecordsAreUnspent {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
            nondeterminism: &NonDeterminism,
            _public_input: &[BFieldElement],
            _sponge: &mut Option<Tip5>,
        ) -> Result<Vec<BFieldElement>, RustShadowError> {
            let fail = || {
                RustShadowError::AssertionError(
                    BlockValidationRule::RemovalRecordsValidity.error_id(),
                )
            };
            let swbfi_leaf_count = pop_u64(stack);
            let window_pointer = stack.pop().unwrap();
            let chunks_pointer = stack.pop().unwrap();
            let chunk_indices_pointer = stack.pop().unwrap();
            let records_pointer = stack.pop().unwrap();

            let removal_records =
                *Vec::<RemovalRecord>::decode_from_memory(memory, records_pointer).unwrap();
            let chunk_indices =
                *Vec::<u64>::decode_from_memory(memory, chunk_indices_pointer).unwrap();
            let chunk_pointers =
                *Vec::<BFieldElement>::decode_from_memory(memory, chunks_pointer).unwrap();
            let chunks = chunk_pointers
                .iter()
                .map(|pointer| *Vec::<u32>::decode_from_memory(memory, *pointer).unwrap())
                .collect::<Vec<_>>();
            let window = *ActiveWindow::decode_from_memory(memory, window_pointer).unwrap();
            let window_start = u128::from(swbfi_leaf_count) << Self::LOG2_CHUNK_SIZE;

            // The context.
            let context = dynamic_allocator(memory);
            let context_words = [
                vec![
                    chunk_indices_pointer,
                    bfe!(chunk_indices.len() as u64),
                    chunks_pointer,
                    window_pointer + bfe!(1),
                ],
                window_start.encode(),
            ]
            .concat();
            for (i, word) in context_words.into_iter().enumerate() {
                memory.insert(context + bfe!(i as u64), word);
            }

            let window_is_sorted = window.sbf.windows(2).all(|pair| pair[0] <= pair[1]);
            let window_is_inside = window.sbf.iter().all(|&set| set < WINDOW_SIZE);
            if !window_is_sorted || !window_is_inside {
                return Err(RustShadowError::AssertionError(
                    Self::UNSORTED_WINDOW_ERROR_ID,
                ));
            }

            let mut tokens: VecDeque<_> = nondeterminism.individual_tokens.clone().into();
            let mut next = || tokens.pop_front().unwrap().value() as usize;
            let gap_test =
                |sorted: &[u32], index: u32, gap: usize| -> Result<(), RustShadowError> {
                    if gap > sorted.len() {
                        return Err(fail());
                    }
                    if gap > 0 && sorted[gap - 1] >= index {
                        return Err(fail());
                    }
                    if gap < sorted.len() && sorted[gap] <= index {
                        return Err(fail());
                    }
                    Ok(())
                };
            for record in &removal_records {
                let position = next();
                if position >= NUM_TRIALS as usize {
                    return Err(fail());
                }
                let index = record.absolute_indices.to_array()[position];
                if index < window_start {
                    let chunk_index = (index >> Self::LOG2_CHUNK_SIZE) as u64;
                    let chunk_position = next();
                    if chunk_indices.get(chunk_position) != Some(&chunk_index) {
                        return Err(fail());
                    }
                    let relative_index = (index % u128::from(CHUNK_SIZE)) as u32;
                    gap_test(&chunks[chunk_position], relative_index, next())?;
                } else {
                    let relative_index = index - window_start;
                    if relative_index >= u128::from(WINDOW_SIZE) {
                        return Err(fail());
                    }
                    gap_test(&window.sbf, relative_index as u32, next())?;
                }
            }
            Ok(vec![])
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            bench_case: Option<BenchmarkCase>,
        ) -> ProcedureInitialState {
            let mut rng = StdRng::from_seed(seed);
            let (num_records, aocl_size) = match bench_case {
                Some(BenchmarkCase::CommonCase) => (10, 1 << 20),
                Some(BenchmarkCase::WorstCase) => (100, 1 << 30),
                None => {
                    let log_max_aocl_size = rng.random_range(4..40);
                    (
                        rng.random_range(1..8),
                        rng.random_range(8..(1_u64 << log_max_aocl_size)),
                    )
                }
            };
            let msa_and_records = random_msa_and_records(&mut rng, num_records, aocl_size);
            self.honest_initial_state(&msa_and_records)
        }

        fn corner_case_initial_states(&self) -> Vec<ProcedureInitialState> {
            let mut rng = StdRng::seed_from_u64(0);
            let mut states =
                vec![self.initial_state(&[], &[], &[], &ActiveWindow::new(), 0, vec![])];
            for (num_records, aocl_size) in [(1, 1), (1, 9), (2, 17), (3, 1 << 12), (5, 1 << 45)] {
                let msa_and_records = random_msa_and_records(&mut rng, num_records, aocl_size);
                states.push(self.honest_initial_state(&msa_and_records));
            }
            states
        }
    }

    impl RemovalRecordsAreUnspent {
        fn honest_initial_state(&self, msa_and_records: &MsaAndRecords) -> ProcedureInitialState {
            let packed = RemovalRecordList::pack(msa_and_records.unpacked_removal_records(), true);
            let (chunk_indices, chunks) = chunks_of(msa_and_records);
            let window = window_of(msa_and_records);
            let leaf_count = msa_and_records
                .mutator_set_accumulator
                .swbf_inactive
                .num_leafs();
            let tokens =
                Self::divined_tokens(&packed, &chunk_indices, &chunks, &window, leaf_count);
            self.initial_state(
                &packed,
                &chunk_indices,
                &chunks,
                &window,
                leaf_count,
                tokens,
            )
        }

        fn initial_state(
            &self,
            packed_records: &[RemovalRecord],
            chunk_indices: &[u64],
            chunks: &[Vec<u32>],
            active_window: &ActiveWindow,
            swbfi_leaf_count: u64,
            tokens: Vec<BFieldElement>,
        ) -> ProcedureInitialState {
            let mut memory = HashMap::new();
            encode_to_memory(&mut memory, RECORDS_POINTER, &packed_records.to_vec());
            encode_to_memory(&mut memory, CHUNK_INDICES_POINTER, &chunk_indices.to_vec());
            encode_to_memory(&mut memory, WINDOW_POINTER, active_window);
            let mut chunk_pointer = FIRST_CHUNK_POINTER;
            let mut chunk_pointers = vec![];
            for chunk in chunks {
                encode_to_memory(&mut memory, chunk_pointer, chunk);
                chunk_pointers.push(chunk_pointer);
                chunk_pointer += bfe!(chunk.len() as u64 + 1);
            }
            encode_to_memory(&mut memory, CHUNKS_POINTER, &chunk_pointers);

            let stack = [
                self.init_stack_for_isolated_run(),
                vec![
                    RECORDS_POINTER,
                    CHUNK_INDICES_POINTER,
                    CHUNKS_POINTER,
                    WINDOW_POINTER,
                ],
                swbfi_leaf_count.encode().into_iter().rev().collect(),
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

    /// An honest fixture with its parts, for tampering.
    #[derive(Clone)]
    struct Fixture {
        packed: Vec<RemovalRecord>,
        chunk_indices: Vec<u64>,
        chunks: Vec<Vec<u32>>,
        mutator_set: MutatorSetAccumulator,
    }

    impl Fixture {
        fn new(seed: u64, num_records: usize, aocl_size: u64) -> Self {
            let mut rng = StdRng::seed_from_u64(seed);
            let msa_and_records = random_msa_and_records(&mut rng, num_records, aocl_size);
            let packed = RemovalRecordList::pack(msa_and_records.unpacked_removal_records(), true);
            let (chunk_indices, chunks) = chunks_of(&msa_and_records);
            let mut mutator_set = msa_and_records.mutator_set_accumulator.clone();
            mutator_set.swbf_active = window_of(&msa_and_records);
            Self {
                packed,
                chunk_indices,
                chunks,
                mutator_set,
            }
        }

        fn leaf_count(&self) -> u64 {
            self.mutator_set.swbf_inactive.num_leafs()
        }

        fn tokens(&self) -> Vec<BFieldElement> {
            RemovalRecordsAreUnspent::divined_tokens(
                &self.packed,
                &self.chunk_indices,
                &self.chunks,
                &self.mutator_set.swbf_active,
                self.leaf_count(),
            )
        }

        fn initial_state(&self, tokens: Vec<BFieldElement>) -> ProcedureInitialState {
            RemovalRecordsAreUnspent.initial_state(
                &self.packed,
                &self.chunk_indices,
                &self.chunks,
                &self.mutator_set.swbf_active,
                self.leaf_count(),
                tokens,
            )
        }

        fn assert_accepts(&self) {
            self.assert_accepts_with_tokens(self.tokens());
        }

        fn assert_accepts_with_tokens(&self, tokens: Vec<BFieldElement>) {
            test_rust_equivalence_given_execution_state(
                &ShadowedProcedure::new(RemovalRecordsAreUnspent),
                self.initial_state(tokens).into(),
            );
        }

        /// Sets some entries in the active window, so that it is not empty.
        fn populate_window(&mut self) {
            for entry in [5, 500, 5_000, 50_000, 500_000] {
                self.mutator_set.swbf_active.insert(entry);
            }
        }

        fn assert_rejects(&self) {
            self.assert_rejects_with_tokens(self.tokens());
        }

        fn assert_rejects_with_tokens(&self, tokens: Vec<BFieldElement>) {
            self.assert_rejects_with_tokens_and_error(
                tokens,
                BlockValidationRule::RemovalRecordsValidity.error_id(),
            );
        }

        fn assert_rejects_with_tokens_and_error(&self, tokens: Vec<BFieldElement>, error_id: i128) {
            test_assertion_failure(
                &ShadowedProcedure::new(RemovalRecordsAreUnspent),
                self.initial_state(tokens).into(),
                &[error_id],
            );
        }

        fn window_start(&self) -> u128 {
            u128::from(self.leaf_count()) << RemovalRecordsAreUnspent::LOG2_CHUNK_SIZE
        }

        /// Whether the honest tokens of the record point into the active
        /// window. Every record has two tokens.
        fn record_uses_window(&self, record: usize) -> bool {
            let position = self.tokens()[2 * record].value() as usize;
            self.packed[record].absolute_indices.to_array()[position] >= self.window_start()
        }

        /// A record the honest tokens resolve in the active window, and one
        /// they resolve in a chunk, if any.
        fn window_record(&self) -> Option<usize> {
            (0..self.packed.len()).find(|&record| self.record_uses_window(record))
        }

        fn chunk_record(&self) -> Option<usize> {
            (0..self.packed.len()).find(|&record| !self.record_uses_window(record))
        }

        /// Sets all indices of the record in the inactive part in their
        /// chunks, and those in the active window in the window.
        fn spend(&mut self, record: usize) {
            let window_start =
                u128::from(self.leaf_count()) << RemovalRecordsAreUnspent::LOG2_CHUNK_SIZE;
            for index in self.packed[record].absolute_indices.to_array() {
                if index < window_start {
                    let chunk_index = (index >> RemovalRecordsAreUnspent::LOG2_CHUNK_SIZE) as u64;
                    let position = self.chunk_indices.binary_search(&chunk_index).unwrap();
                    let relative_index = (index % u128::from(CHUNK_SIZE)) as u32;
                    let chunk = &mut self.chunks[position];
                    let at = RemovalRecordsAreUnspent::gap_position(chunk, relative_index);
                    chunk.insert(at, relative_index);
                } else {
                    self.mutator_set
                        .swbf_active
                        .insert((index - window_start) as u32);
                }
            }
        }
    }

    #[test]
    fn rust_shadow_agrees_with_tasm() {
        ShadowedProcedure::new(RemovalRecordsAreUnspent).test();
    }

    #[test]
    fn unspent_records_are_accepted() {
        for (seed, num_records, aocl_size) in
            [(0, 1, 1), (1, 2, 100), (2, 4, 1 << 20), (3, 6, 1 << 50)]
        {
            Fixture::new(seed, num_records, aocl_size).assert_accepts();
        }
    }

    #[test]
    fn spent_record_is_rejected() {
        for (seed, num_records, aocl_size) in [(4, 1, 1), (5, 3, 1 << 20), (6, 4, 1 << 50)] {
            for record in 0..num_records {
                let mut fixture = Fixture::new(seed, num_records, aocl_size);
                fixture.spend(record);
                fixture.assert_rejects();
            }
        }
    }

    #[test]
    fn record_with_one_unset_index_is_accepted() {
        let mut fixture = Fixture::new(7, 3, 1 << 20);
        let record = 1;
        fixture.spend(record);
        // Unset one index again.
        let window_start =
            u128::from(fixture.leaf_count()) << RemovalRecordsAreUnspent::LOG2_CHUNK_SIZE;
        let index = fixture.packed[record].absolute_indices.to_array()[NUM_TRIALS as usize / 2];
        if index < window_start {
            let chunk_index = (index >> RemovalRecordsAreUnspent::LOG2_CHUNK_SIZE) as u64;
            let position = fixture.chunk_indices.binary_search(&chunk_index).unwrap();
            let relative = (index % u128::from(CHUNK_SIZE)) as u32;
            let chunk = &mut fixture.chunks[position];
            let at = chunk.iter().position(|&set| set == relative).unwrap();
            chunk.remove(at);
            if chunk.contains(&relative) {
                return;
            }
        } else {
            let relative = (index - window_start) as u32;
            fixture.mutator_set.swbf_active.remove(relative);
            if fixture.mutator_set.swbf_active.contains(relative) {
                return;
            }
        }
        fixture.assert_accepts();
    }

    #[test]
    fn wrong_positions_are_rejected() {
        let fixture = Fixture::new(8, 2, 1 << 20);
        let honest = fixture.tokens();
        // The index position out of range.
        let mut tokens = honest.clone();
        tokens[0] = bfe!(NUM_TRIALS);
        fixture.assert_rejects_with_tokens(tokens);

        // The chunk position out of range, and pointing at another chunk.
        let record = fixture
            .chunk_record()
            .expect("a fixture record resolves in a chunk");
        assert!(fixture.chunks.len() >= 2);
        let mut tokens = honest.clone();
        tokens[2 * record + 1] = bfe!(fixture.chunks.len() as u64);
        fixture.assert_rejects_with_tokens(tokens);
        let mut tokens = honest.clone();
        tokens[2 * record + 1] =
            bfe!((honest[2 * record + 1].value() + 1) % fixture.chunks.len() as u64);
        fixture.assert_rejects_with_tokens(tokens);

        // The gap position beyond the window's list.
        let mut fixture = Fixture::new(8, 2, 8);
        fixture.populate_window();
        let record = fixture
            .window_record()
            .expect("a fixture record resolves in the window");
        let mut tokens = fixture.tokens();
        tokens[2 * record + 1] = bfe!(u32::MAX);
        fixture.assert_rejects_with_tokens(tokens);
    }

    #[test]
    fn gap_position_off_by_one_is_rejected() {
        let mut fixture = Fixture::new(9, 3, 8);
        fixture.populate_window();
        let honest = fixture.tokens();
        let record = fixture
            .window_record()
            .expect("a fixture record resolves in the window");
        // The window neighbours enclose the index only at the right gap
        // position.
        let gap_token = 2 * record + 1;
        for delta in [-1_i64, 1] {
            let mut tokens = honest.clone();
            let shifted = tokens[gap_token].value() as i64 + delta;
            if shifted < 0 {
                continue;
            }
            tokens[gap_token] = bfe!(shifted as u64);
            let initial_state: tasm_lib::InitVmState = fixture.initial_state(tokens).into();
            let result = tasm_lib::test_helpers::tasm_final_state(
                &ShadowedProcedure::new(RemovalRecordsAreUnspent),
                &initial_state.stack,
                &initial_state.public_input,
                initial_state.nondeterminism,
                &initial_state.sponge,
            );
            assert!(result.is_err());
        }
    }

    /// The index just below the window start is looked up in the last
    /// chunk, the one at the window start at the window's first position.
    #[test]
    fn indices_at_the_window_start_take_the_chunk_or_the_window() {
        let mut fixture = Fixture::new(21, 1, 1 << 20);
        let leaf_count = fixture.leaf_count();
        let window_start = fixture.window_start();
        let mut indices = [window_start - 1; NUM_TRIALS as usize];
        indices[1] = window_start;
        for (i, index) in indices.iter_mut().enumerate().skip(2) {
            *index = window_start - 1 + i as u128;
        }
        fixture.packed = vec![RemovalRecord {
            absolute_indices: AbsoluteIndexSet::new(indices),
            target_chunks: ChunkDictionary::default(),
        }];
        fixture.chunk_indices = vec![leaf_count - 1];
        fixture.chunks = vec![vec![]];
        fixture.mutator_set.swbf_active = ActiveWindow::from_vec_u32(vec![]);

        // Position 0 lies in the last chunk; position 1 at the window's start.
        let honest = fixture.tokens();
        assert_eq!(vec![bfe!(0), bfe!(0), bfe!(0)], honest);
        fixture.assert_accepts();
        fixture.assert_accepts_with_tokens(vec![bfe!(1), bfe!(0)]);

        // The last chunk's last index set: no gap shows it unset.
        let mut spent_below = fixture.clone();
        spent_below.chunks[0] = vec![CHUNK_SIZE - 1];
        for gap in 0..=1 {
            spent_below.assert_rejects_with_tokens(vec![bfe!(0), bfe!(0), bfe!(gap)]);
        }
        spent_below.assert_accepts_with_tokens(vec![bfe!(1), bfe!(0)]);

        // The window's first position set: no gap shows it unset either.
        let mut spent_at = fixture.clone();
        spent_at.mutator_set.swbf_active.insert(0);
        for gap in 0..=1 {
            spent_at.assert_rejects_with_tokens(vec![bfe!(1), bfe!(gap)]);
        }
        spent_at.assert_accepts_with_tokens(vec![bfe!(0), bfe!(0), bfe!(0)]);
    }

    #[test]
    fn chunk_gap_position_off_by_one_is_rejected() {
        let fixture = Fixture::new(13, 3, 1 << 20);
        let record = fixture
            .chunk_record()
            .expect("a fixture record resolves in a chunk");
        let honest = fixture.tokens();
        let gap_token = 3 * record + 2;
        for other in [honest[gap_token] + bfe!(1), honest[gap_token] - bfe!(1)] {
            let mut tokens = honest.clone();
            tokens[gap_token] = other;
            fixture.assert_rejects_with_tokens(tokens);
        }
    }

    #[test]
    fn unsorted_window_is_rejected() {
        let mut fixture = Fixture::new(14, 2, 8);
        fixture.populate_window();
        let tokens = fixture.tokens();
        fixture.mutator_set.swbf_active.sbf.reverse();
        fixture.assert_rejects_with_tokens_and_error(
            tokens,
            RemovalRecordsAreUnspent::UNSORTED_WINDOW_ERROR_ID,
        );

        // A single entry out of place is caught, wherever it is.
        let num_entries = Fixture::new(14, 2, 8).mutator_set.swbf_active.sbf.len() + 5;
        for at in 0..num_entries - 1 {
            let mut fixture = Fixture::new(14, 2, 8);
            fixture.populate_window();
            assert_eq!(num_entries, fixture.mutator_set.swbf_active.sbf.len());
            let tokens = fixture.tokens();
            fixture.mutator_set.swbf_active.sbf[at] = WINDOW_SIZE - 1;
            fixture.assert_rejects_with_tokens_and_error(
                tokens,
                RemovalRecordsAreUnspent::UNSORTED_WINDOW_ERROR_ID,
            );
        }
    }

    #[test]
    fn repeated_window_entries_are_accepted() {
        // The mutator set sets an index twice by keeping it twice.
        let mut fixture = Fixture::new(17, 2, 8);
        fixture.populate_window();
        let sbf = fixture.mutator_set.swbf_active.sbf.clone();
        fixture.mutator_set.swbf_active.sbf = sbf.iter().flat_map(|&set| [set, set]).collect();
        fixture.assert_accepts();

        // A spent record stays spent: its indices repeated in the window
        // are no gap.
        let record = fixture
            .window_record()
            .expect("a fixture record resolves in the window");
        fixture.spend(record);
        fixture.assert_rejects();
        let sbf = fixture.mutator_set.swbf_active.sbf.clone();
        fixture.mutator_set.swbf_active.sbf = sbf.iter().flat_map(|&set| [set, set]).collect();
        fixture.assert_rejects();
    }

    #[test]
    fn window_entry_outside_the_window_is_rejected() {
        let mut fixture = Fixture::new(15, 2, 8);
        let tokens = fixture.tokens();
        fixture.mutator_set.swbf_active.sbf.push(WINDOW_SIZE);
        fixture.assert_rejects_with_tokens_and_error(
            tokens,
            RemovalRecordsAreUnspent::UNSORTED_WINDOW_ERROR_ID,
        );
    }

    #[test]
    fn window_lists_of_every_length_modulo_5_are_checked() {
        // The sorted check reads five entries at a time, then the rest.
        for length in 0..12_u32 {
            let mut fixture = Fixture::new(16 + u64::from(length), 1, 8);
            fixture.mutator_set.swbf_active.sbf = (0..length).map(|i| 3 * i + 1).collect();
            fixture.assert_accepts();

            // Breaking the order anywhere is caught.
            for at in 1..length as usize {
                let tokens = fixture.tokens();
                let mut fixture = Fixture::new(16 + u64::from(length), 1, 8);
                fixture.mutator_set.swbf_active.sbf = (0..length).map(|i| 3 * i + 1).collect();
                fixture.mutator_set.swbf_active.sbf[at] = 0;
                fixture.assert_rejects_with_tokens_and_error(
                    tokens,
                    RemovalRecordsAreUnspent::UNSORTED_WINDOW_ERROR_ID,
                );
            }
        }
    }

    /// A set index has no gap in the sorted chunk: whatever gap the prover
    /// names, a neighbour fails to enclose it strictly.
    #[test]
    fn set_index_in_a_sorted_chunk_has_no_gap() {
        let fixture = Fixture::new(30, 1, 1 << 20);
        assert!(
            fixture.chunk_record().is_some(),
            "the record must resolve in a chunk"
        );
        let tokens = fixture.tokens();
        let (index_position, position) = (tokens[0].value() as usize, tokens[1].value() as usize);
        let index = fixture.packed[0].absolute_indices.to_array()[index_position];
        let relative_index = (index % u128::from(CHUNK_SIZE)) as u32;
        let chunk_of_length = |length: u32| -> Vec<u32> {
            let mut chunk = (0..length)
                .map(|i| (relative_index + 1 + i) % CHUNK_SIZE)
                .collect::<Vec<_>>();
            chunk.sort_unstable();
            chunk
        };
        for length in 0..12 {
            let mut fixture = Fixture::new(30, 1, 1 << 20);
            fixture.chunks[position] = chunk_of_length(length);
            fixture.assert_accepts();

            let mut fixture = Fixture::new(30, 1, 1 << 20);
            let mut chunk = chunk_of_length(length);
            let at = RemovalRecordsAreUnspent::gap_position(&chunk, relative_index);
            chunk.insert(at, relative_index);
            fixture.chunks[position] = chunk;
            for gap in 0..=u64::from(length) + 1 {
                let mut tokens = tokens.clone();
                tokens[2] = bfe!(gap);
                fixture.assert_rejects_with_tokens(tokens);
            }
        }
    }

    #[test]
    fn empty_list_is_accepted() {
        RemovalRecordsAreUnspent.initial_state(
            &[],
            &[],
            &[],
            &ActiveWindow::new(),
            1 << 20,
            vec![],
        );
        test_rust_equivalence_given_execution_state(
            &ShadowedProcedure::new(RemovalRecordsAreUnspent),
            RemovalRecordsAreUnspent
                .initial_state(&[], &[], &[], &ActiveWindow::new(), 1 << 20, vec![])
                .into(),
        );
    }

    #[test]
    fn record_in_the_active_window_needs_no_chunks() {
        let mut rng = StdRng::seed_from_u64(11);
        let msa_and_records = random_msa_and_records(&mut rng, 3, 8);
        assert_eq!(
            0,
            msa_and_records
                .mutator_set_accumulator
                .swbf_inactive
                .num_leafs()
        );
        RemovalRecordsAreUnspent.honest_initial_state(&msa_and_records);
        test_rust_equivalence_given_execution_state(
            &ShadowedProcedure::new(RemovalRecordsAreUnspent),
            RemovalRecordsAreUnspent
                .honest_initial_state(&msa_and_records)
                .into(),
        );
    }

    #[test]
    fn index_beyond_the_window_is_rejected() {
        let mut fixture = Fixture::new(12, 1, 8);
        assert_eq!(0, fixture.leaf_count());
        let mut indices = fixture.packed[0].absolute_indices.to_array();
        indices[0] = u128::from(WINDOW_SIZE);
        fixture.packed[0].absolute_indices = AbsoluteIndexSet::new(indices);
        let mut tokens = fixture.tokens();
        tokens[0] = bfe!(0);
        fixture.assert_rejects_with_tokens(tokens);
        let _ = Chunk::empty_chunk();
    }
}
