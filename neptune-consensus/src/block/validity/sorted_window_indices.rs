use std::collections::HashMap;

use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::shared::NUM_TRIALS;
use neptune_mutator_set::shared::WINDOW_SIZE;
use tasm_lib::arithmetic::u128::lt::Lt as U128Lt;
use tasm_lib::arithmetic::u128::sub::Sub as U128Sub;
use tasm_lib::field;
use tasm_lib::list::new::New;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::block::block_validation_error::BlockValidationRule;

/// Collects the indices of a list of removal records that lie in the active
/// window, relative to the window's start, as a sorted list.
///
/// ```text
/// BEFORE: _ *removal_records [window_start: u128]
/// AFTER:  _ *sorted_indices
/// ```
///
/// The prover supplies the sorted list, then the position in it of every
/// index in the window, in the order of the records and of their indices.
/// Each position must hold that index and may be pointed at once, and every
/// position must be pointed at, so the list is a permutation of the indices
/// in the window. The list is checked to be sorted with repetitions and
/// inside the window.
///
/// Crashes with the error ID of rule 2.b if an index lies at or beyond the
/// end of the window, which no removal record synced to the mutator set has,
/// and with the error ID of rule 2.e if the prover's list is not the sorted
/// list of the indices in the window.
#[derive(Debug, Copy, Clone)]
pub(super) struct SortedWindowIndices;

impl SortedWindowIndices {
    fn beyond_window_error_id() -> i128 {
        BlockValidationRule::RemovalRecordsValidity.error_id()
    }

    fn error_id() -> i128 {
        BlockValidationRule::MutatorSetUpdateIntegrity.error_id()
    }

    /// The indices of the records at or past the window start, relative to
    /// it, in the order of the records and of their indices. An index beyond
    /// the window's end is `None`; the snippet rejects it.
    fn window_indices(removal_records: &[RemovalRecord], window_start: u128) -> Vec<Option<u32>> {
        let window_end = window_start.saturating_add(u128::from(WINDOW_SIZE));
        removal_records
            .iter()
            .flat_map(|record| record.absolute_indices.to_array())
            .filter(|&index| index >= window_start)
            .map(|index| (index < window_end).then(|| (index - window_start) as u32))
            .collect()
    }

    /// The sorted list of the records' indices in the window, relative to
    /// its start: what the snippet returns.
    pub(crate) fn sorted_window_indices(
        removal_records: &[RemovalRecord],
        window_start: u128,
    ) -> Vec<u32> {
        let mut indices = Self::window_indices(removal_records, window_start)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        indices.sort_unstable();
        indices
    }

    /// The tokens the prover supplies: the length of the sorted list, its
    /// entries, then the position of each index in the window. An index
    /// beyond the window gets a position the snippet then rejects, if it
    /// reads one.
    pub(crate) fn divined_tokens(
        removal_records: &[RemovalRecord],
        window_start: u128,
    ) -> Vec<BFieldElement> {
        let sorted = Self::sorted_window_indices(removal_records, window_start);
        let mut next_position_of: HashMap<u32, usize> = HashMap::new();
        let positions = Self::window_indices(removal_records, window_start)
            .into_iter()
            .map(|index| {
                let Some(index) = index else {
                    return bfe!(0);
                };
                let position = next_position_of
                    .entry(index)
                    .or_insert_with(|| sorted.partition_point(|&sorted| sorted < index));
                *position += 1;
                bfe!(*position as u64 - 1)
            })
            .collect::<Vec<_>>();

        [
            vec![bfe!(sorted.len() as u64)],
            sorted.iter().map(|&index| bfe!(index)).collect(),
            positions,
        ]
        .concat()
    }
}

impl BasicSnippet for SortedWindowIndices {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*removal_records".to_string()),
            (DataType::U128, "window_start".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(
            DataType::List(Box::new(DataType::U32)),
            "*sorted_indices".to_string(),
        )]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_sorted_window_indices".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_list = library.import(Box::new(New));
        let u128_lt = library.import(Box::new(U128Lt));
        let u128_sub = library.import(Box::new(U128Sub));

        let entrypoint = self.entrypoint();
        let read_loop = format!("{entrypoint}_read_loop");
        let records_loop = format!("{entrypoint}_records_loop");
        let below = format!("{entrypoint}_minimum_below_window");
        let above = format!("{entrypoint}_minimum_in_window");
        let indices_loop = format!("{entrypoint}_indices_loop");
        let add_mode = format!("{entrypoint}_add_mode");
        let sub_mode = format!("{entrypoint}_sub_mode");
        let sub_mode_in_window = format!("{entrypoint}_sub_mode_in_window");
        let process = format!("{entrypoint}_process_index");

        let error_id = Self::error_id();
        let beyond_window_error_id = Self::beyond_window_error_id();
        let read_u128 = triton_asm!(addi 3 read_mem 4 pop 1);

        // The context: the window start, the sorted list and its length,
        // the flags of the positions pointed at, and their number.
        let window_start_offset = 0;
        let sorted_offset = 4;
        let length_offset = 5;
        let taken_offset = 6;
        let consumed_offset = 7;

        triton_asm!(
            {entrypoint}:
                // _ *removal_records [window_start]
                call {new_list} write_mem 4
                // _ *removal_records *context[4]

                divine 1
                // Crashes unless the length is a u32.
                dup 0 pop_count pop 1
                // _ *removal_records *context[4] length

                call {new_list}
                dup 1 dup 1 write_mem 1 pop 1
                // _ *removal_records *context[4] length *sorted

                dup 0 addi 1 push 0 push 0
                // _ *removal_records *context[4] length *sorted *sorted[0] 0 0

                call {read_loop}
                pop 3
                // _ *removal_records *context[4] length *sorted

                call {new_list}
                dup 2 dup 1 write_mem 1 pop 1
                // _ *removal_records *context[4] length *sorted *taken

                push 0 swap 1 pick 3 pick 3 pick 4
                // _ *removal_records 0 *taken length *sorted *context[4]

                write_mem 4 addi -8
                // _ *removal_records *context

                swap 1 read_mem 1 addi 2 place 1 push 0
                // _ *context *record[0]_si num_records 0

                call {records_loop}
                pop 3
                // _ *context

                dup 0 addi {consumed_offset} read_mem 1 pop 1
                dup 1 addi {length_offset} read_mem 1 pop 1
                eq assert error_id {error_id}
                // _ *context

                addi {sorted_offset} read_mem 1 pop 1
                // _ *sorted

                return

            // Reads the sorted list: each entry is at least the previous
            // one and inside the window.
            // INVARIANT: _ length *sorted *sorted[i] previous i
            {read_loop}:
                dup 4 dup 1 eq skiz return
                // _ length *sorted *sorted[i] previous i

                divine 1
                // _ length *sorted *sorted[i] previous i entry

                dup 2 dup 1 lt push 0 eq assert error_id {error_id}
                push {WINDOW_SIZE} dup 1 lt assert error_id {error_id}
                // _ length *sorted *sorted[i] previous i entry

                dup 0 pick 4 write_mem 1 place 3
                // _ length *sorted *sorted[i + 1] previous i entry

                place 2 pick 1 pop 1 addi 1
                // _ length *sorted *sorted[i + 1] entry (i + 1)

                recurse

            // INVARIANT: _ *context *record[i]_si num_records i
            {records_loop}:
                dup 1 dup 1 eq skiz return
                // _ *context *record[i]_si num_records i

                dup 2 addi 1 {&field!(RemovalRecord::absolute_indices)}
                // _ *context *record[i]_si num_records i *index_set

                dup 0 {&field!(AbsoluteIndexSet::minimum)} {&read_u128}
                // _ *context *record[i]_si num_records i *index_set [minimum]

                dup 8 addi {window_start_offset + 3} read_mem 4 pop 1
                dup 7 dup 7 dup 7 dup 7
                call {u128_lt}
                // _ *context *record[i]_si num_records i *index_set [minimum] (minimum < window_start)

                dup 0 skiz call {below}
                push 0 eq skiz call {above}
                // _ *context *record[i]_si num_records i *index_set mode value

                pick 2 {&field!(AbsoluteIndexSet::distances)} push 0
                // _ *context *record[i]_si num_records i mode value *distances[0] 0

                call {indices_loop}
                pop 4
                // _ *context *record[i]_si num_records i

                pick 2 read_mem 1
                // _ *context num_records i record_size (*record[i]_si - 1)

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1

                addi 2 add place 2 addi 1
                // _ *context *record[i + 1]_si num_records (i + 1)

                recurse

            // The minimum lies below the window: an index lies in the window
            // if its distance reaches the threshold, the window start's
            // distance to the minimum, and its relative index is the excess.
            // A threshold beyond any distance stands for a window start
            // beyond every index.
            // BEFORE: _ *context *record_si num_records i *index_set [minimum] 1
            // AFTER:  _ *context *record_si num_records i *index_set 0 threshold 1
            {below}:
                pop 1
                dup 8 addi {window_start_offset + 3} read_mem 4 pop 1
                call {u128_sub}
                // _ *context *record_si num_records i *index_set [window_start - minimum]

                place 3 add add push 0 eq
                // _ *context *record_si num_records i *index_set d0 (d3 + d2 + d1 == 0)

                dup 0 push -1 mul addi 1 push {u32::MAX} mul
                // _ *context *record_si num_records i *index_set d0 fits ((1 - fits) * u32::MAX)

                place 2 mul add
                // _ *context *record_si num_records i *index_set threshold

                push 0 swap 1 push 1
                // _ *context *record_si num_records i *index_set 0 threshold 1

                return

            // The minimum lies in the window: every index does, and the
            // relative index is the distance plus the minimum's.
            // BEFORE: _ *context *record_si num_records i *index_set [minimum]
            // AFTER:  _ *context *record_si num_records i *index_set 1 base
            {above}:
                dup 8 addi {window_start_offset + 3} read_mem 4 pop 1
                pick 7 pick 7 pick 7 pick 7
                call {u128_sub}
                // _ *context *record_si num_records i *index_set [minimum - window_start]

                place 3 add add push 0 eq assert error_id {beyond_window_error_id}
                push {WINDOW_SIZE} dup 1 lt assert error_id {beyond_window_error_id}
                // _ *context *record_si num_records i *index_set base

                push 1 swap 1
                // _ *context *record_si num_records i *index_set 1 base

                return

            // INVARIANT: _ *context *record_si num_records i mode value *distances[k] k
            {indices_loop}:
                dup 0 push {NUM_TRIALS} eq skiz return
                // _ *context *record_si num_records i mode value *distances[k] k

                dup 1 read_mem 1 pop 1 dup 4
                // _ *context *record_si num_records i mode value *distances[k] k distance mode

                dup 0 skiz call {add_mode}
                push 0 eq skiz call {sub_mode}
                // _ *context *record_si num_records i mode value *distances[k] k

                pick 1 addi 1 place 1 addi 1
                // _ *context *record_si num_records i mode value *distances[k + 1] (k + 1)

                recurse

            // BEFORE: _ *context *record_si num_records i 1 base *distances[k] k distance 1
            // AFTER:  _ *context *record_si num_records i 1 base *distances[k] k 1
            {add_mode}:
                pop 1 dup 3 add
                push {WINDOW_SIZE} dup 1 lt assert error_id {beyond_window_error_id}
                // _ *context *record_si num_records i 1 base *distances[k] k relative_index

                call {process}
                push 1
                return

            // BEFORE: _ *context *record_si num_records i 0 threshold *distances[k] k distance
            // AFTER:  _ *context *record_si num_records i 0 threshold *distances[k] k
            {sub_mode}:
                dup 3 dup 1 lt push 0 eq
                // _ *context *record_si num_records i 0 threshold *distances[k] k distance (distance >= threshold)

                skiz call {sub_mode_in_window}
                pop 1
                return

            // BEFORE: _ *context *record_si num_records i 0 threshold *distances[k] k distance
            // AFTER:  _ *context *record_si num_records i 0 threshold *distances[k] k 0
            {sub_mode_in_window}:
                dup 3 push -1 mul add
                // _ *context *record_si num_records i 0 threshold *distances[k] k relative_index

                call {process}
                push 0
                return

            // The index must sit at the divined position of the sorted list,
            // which no index sat at before.
            // BEFORE: _ *context *record_si num_records i mode value *distances[k] k relative_index
            // AFTER:  _ *context *record_si num_records i mode value *distances[k] k
            {process}:
                divine 1
                // _ ... relative_index position

                dup 9 addi {length_offset} read_mem 1 pop 1
                dup 1 lt assert error_id {error_id}
                // _ ... relative_index position

                dup 9 addi {sorted_offset} read_mem 1 pop 1
                dup 1 add addi 1 read_mem 1 pop 1
                // _ ... relative_index position sorted[position]

                dup 2 eq assert error_id {error_id}
                // _ ... relative_index position

                dup 9 addi {taken_offset} read_mem 1 pop 1
                dup 1 add addi 1
                // _ ... relative_index position *taken[position]

                dup 0 read_mem 1 pop 1 push 0 eq assert error_id {error_id}
                push 1 swap 1 write_mem 1 pop 1
                // _ ... relative_index position

                pop 2
                // _ *context *record_si num_records i mode value *distances[k] k

                dup 7 addi {consumed_offset} read_mem 1
                // _ ... consumed *context[consumed - 1]

                swap 1 addi 1 swap 1 addi 1 write_mem 1 pop 1
                // _ *context *record_si num_records i mode value *distances[k] k

                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::VecDeque;

    use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
    use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
    use neptune_mutator_set::shared::CHUNK_SIZE;
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

    impl Procedure for SortedWindowIndices {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
            nondeterminism: &NonDeterminism,
            _public_input: &[BFieldElement],
            _sponge: &mut Option<Tip5>,
        ) -> Result<Vec<BFieldElement>, RustShadowError> {
            let fail = || RustShadowError::AssertionError(Self::error_id());
            let beyond = || RustShadowError::AssertionError(Self::beyond_window_error_id());
            let window_start = {
                let limbs: [BFieldElement; 4] = core::array::from_fn(|_| stack.pop().unwrap());
                *u128::decode(&limbs).unwrap()
            };
            let records_pointer = stack.pop().unwrap();
            let removal_records =
                *Vec::<RemovalRecord>::decode_from_memory(memory, records_pointer).unwrap();

            let mut tokens: VecDeque<_> = nondeterminism.individual_tokens.clone().into();
            let mut next = || tokens.pop_front().unwrap().value();

            let context = dynamic_allocator(memory);
            for (i, limb) in window_start.encode().into_iter().enumerate() {
                memory.insert(context + bfe!(i as u64), limb);
            }
            let length = next();
            let sorted = dynamic_allocator(memory);
            memory.insert(sorted, bfe!(length));
            let mut entries = vec![];
            for i in 0..length {
                let entry = next();
                if entries.last().is_some_and(|&previous| entry < previous)
                    || entry >= u64::from(WINDOW_SIZE)
                {
                    return Err(fail());
                }
                entries.push(entry);
                memory.insert(sorted + bfe!(1 + i), bfe!(entry));
            }
            let taken = dynamic_allocator(memory);
            memory.insert(taken, bfe!(length));
            memory.insert(context + bfe!(4), sorted);
            memory.insert(context + bfe!(5), bfe!(length));
            memory.insert(context + bfe!(6), taken);
            memory.insert(context + bfe!(7), bfe!(0));

            let mut consumed = 0_u64;
            for record in &removal_records {
                let minimum = record.absolute_indices.minimum();
                for distance in record.absolute_indices.distances() {
                    let relative_index = if minimum < window_start {
                        let threshold = window_start - minimum;
                        if u128::from(distance) < threshold {
                            continue;
                        }
                        distance - threshold as u32
                    } else {
                        let base = minimum - window_start;
                        if base >= u128::from(WINDOW_SIZE) {
                            return Err(beyond());
                        }
                        let relative_index = base as u32 + distance;
                        if relative_index >= WINDOW_SIZE {
                            return Err(beyond());
                        }
                        relative_index
                    };
                    let position = next();
                    if position >= length || entries[position as usize] != u64::from(relative_index)
                    {
                        return Err(fail());
                    }
                    let flag = taken + bfe!(1 + position);
                    if memory.get(&flag).is_some_and(|flag| flag.value() != 0) {
                        return Err(fail());
                    }
                    memory.insert(flag, bfe!(1));
                    consumed += 1;
                    memory.insert(context + bfe!(7), bfe!(consumed));
                }
            }
            if consumed != length {
                return Err(fail());
            }

            stack.push(sorted);
            Ok(vec![])
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            bench_case: Option<BenchmarkCase>,
        ) -> ProcedureInitialState {
            let mut rng = StdRng::from_seed(seed);
            match bench_case {
                Some(BenchmarkCase::CommonCase) => {
                    self.honest_state_of_fixture(&mut rng, 10, 1 << 20)
                }
                Some(BenchmarkCase::WorstCase) => {
                    self.honest_state_of_fixture(&mut rng, 100, 1 << 30)
                }
                None => {
                    if rng.random_bool(0.5) {
                        let log_max_aocl_size = rng.random_range(4..40);
                        let num_records = rng.random_range(1..8);
                        let aocl_size = rng.random_range(8..(1_u64 << log_max_aocl_size));
                        self.honest_state_of_fixture(&mut rng, num_records, aocl_size)
                    } else {
                        let num_records = rng.random_range(0..8);
                        let window_start = rng.random_range(0..(1_u128 << 70));
                        let records = random_records_around(&mut rng, num_records, window_start);
                        self.honest_state(&records, window_start)
                    }
                }
            }
        }

        fn corner_case_initial_states(&self) -> Vec<ProcedureInitialState> {
            let mut rng = StdRng::seed_from_u64(0);
            let mut states = vec![
                self.honest_state(&[], 0),
                self.honest_state(&[], u128::MAX),
                self.honest_state(&[record_with_indices([0; NUM_TRIALS as usize])], 0),
                self.honest_state(
                    &[record_with_indices(core::array::from_fn(|i| i as u128))],
                    0,
                ),
                self.honest_state(
                    &[record_with_indices(
                        [u128::from(WINDOW_SIZE) - 1; NUM_TRIALS as usize],
                    )],
                    0,
                ),
                // Every index just below the window.
                self.honest_state(&[record_with_indices([999; NUM_TRIALS as usize])], 1000),
                // Every index just at the window start.
                self.honest_state(&[record_with_indices([1000; NUM_TRIALS as usize])], 1000),
                // Indices on both sides of the window start.
                self.honest_state(
                    &[record_with_indices(core::array::from_fn(|i| {
                        980 + i as u128
                    }))],
                    1000,
                ),
                // The window start is further from the minimum than a u32
                // can express: no index in the window.
                self.honest_state(
                    &[record_with_indices(core::array::from_fn(|i| i as u128))],
                    1 << 40,
                ),
            ];
            for (num_records, aocl_size) in [(1, 1), (1, 9), (2, 17), (3, 1 << 12), (5, 1 << 45)] {
                states.push(self.honest_state_of_fixture(&mut rng, num_records, aocl_size));
            }
            states
        }
    }

    /// A removal record with these indices and no chunks.
    fn record_with_indices(indices: [u128; NUM_TRIALS as usize]) -> RemovalRecord {
        RemovalRecord {
            absolute_indices: AbsoluteIndexSet::new(indices),
            target_chunks: ChunkDictionary::default(),
        }
    }

    /// Random records with index sets spread around the window start: some
    /// entirely below, some entirely in the window, some straddling it.
    fn random_records_around(
        rng: &mut StdRng,
        num_records: usize,
        window_start: u128,
    ) -> Vec<RemovalRecord> {
        (0..num_records)
            .map(|_| {
                let spread = rng.random_range(1..u128::from(WINDOW_SIZE));
                let offset = rng.random_range(0..(u128::from(2 * WINDOW_SIZE) - spread));
                let minimum = (window_start + offset).saturating_sub(u128::from(WINDOW_SIZE));
                record_with_indices(core::array::from_fn(|_| {
                    minimum + rng.random_range(0..spread)
                }))
            })
            .collect()
    }

    impl SortedWindowIndices {
        fn honest_state_of_fixture(
            &self,
            rng: &mut StdRng,
            num_records: usize,
            aocl_size: u64,
        ) -> ProcedureInitialState {
            let msa_and_records = random_msa_and_records(rng, num_records, aocl_size);
            let packed = RemovalRecordList::pack(msa_and_records.unpacked_removal_records(), true);
            let leaf_count = msa_and_records
                .mutator_set_accumulator
                .swbf_inactive
                .num_leafs();
            let window_start = u128::from(leaf_count) << CHUNK_SIZE.ilog2();
            self.honest_state(&packed, window_start)
        }

        fn honest_state(
            &self,
            removal_records: &[RemovalRecord],
            window_start: u128,
        ) -> ProcedureInitialState {
            self.initial_state(
                removal_records,
                window_start,
                Self::divined_tokens(removal_records, window_start),
            )
        }

        fn initial_state(
            &self,
            removal_records: &[RemovalRecord],
            window_start: u128,
            tokens: Vec<BFieldElement>,
        ) -> ProcedureInitialState {
            let mut memory = HashMap::new();
            encode_to_memory(&mut memory, RECORDS_POINTER, &removal_records.to_vec());
            let stack = [
                self.init_stack_for_isolated_run(),
                vec![RECORDS_POINTER],
                window_start.encode().into_iter().rev().collect(),
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

    fn assert_accepts(removal_records: &[RemovalRecord], window_start: u128) {
        test_rust_equivalence_given_execution_state(
            &ShadowedProcedure::new(SortedWindowIndices),
            SortedWindowIndices
                .honest_state(removal_records, window_start)
                .into(),
        );
    }

    fn assert_rejects_with_tokens(
        removal_records: &[RemovalRecord],
        window_start: u128,
        tokens: Vec<BFieldElement>,
        error_id: i128,
    ) {
        test_assertion_failure(
            &ShadowedProcedure::new(SortedWindowIndices),
            SortedWindowIndices
                .initial_state(removal_records, window_start, tokens)
                .into(),
            &[error_id],
        );
    }

    #[test]
    fn rust_shadow_agrees_with_tasm() {
        ShadowedProcedure::new(SortedWindowIndices).test();
    }

    #[test]
    fn sorted_indices_are_those_in_the_window() {
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..20 {
            let window_start = rng.random_range(0..(1_u128 << 70));
            let num_records = rng.random_range(0..6);
            let records = random_records_around(&mut rng, num_records, window_start);
            let sorted = SortedWindowIndices::sorted_window_indices(&records, window_start);
            let mut expected = records
                .iter()
                .flat_map(|record| record.absolute_indices.to_array())
                .filter(|&index| index >= window_start)
                .map(|index| (index - window_start) as u32)
                .collect::<Vec<_>>();
            expected.sort_unstable();
            assert_eq!(expected, sorted);
            assert!(sorted.iter().all(|&index| index < WINDOW_SIZE));
            assert_accepts(&records, window_start);
        }
    }

    /// The index at the window start is the window's first, the one just
    /// below it is not in the window at all.
    #[test]
    fn indices_at_the_window_start_split_at_it() {
        let chunk_size = u128::from(CHUNK_SIZE);
        for window_start in [chunk_size, 1 << 40, 1 << 70] {
            let mut indices = [window_start - 1; NUM_TRIALS as usize];
            indices[1] = window_start;
            indices[2] = window_start + 1;
            for (i, index) in indices.iter_mut().enumerate().skip(3) {
                *index = window_start - chunk_size + (i as u128 * 97) % (2 * chunk_size);
            }
            let records = vec![record_with_indices(indices)];
            let sorted = SortedWindowIndices::sorted_window_indices(&records, window_start);
            assert_eq!(Some(&0), sorted.first());
            assert!(sorted.contains(&1));
            assert_eq!(
                indices
                    .iter()
                    .filter(|&&index| index >= window_start)
                    .count(),
                sorted.len()
            );
            assert_accepts(&records, window_start);
        }
    }

    #[test]
    fn empty_list_is_accepted() {
        assert_accepts(&[], 0);
        assert_accepts(&[], 1 << 100);
    }

    #[test]
    fn index_beyond_the_window_is_rejected() {
        let error_id = SortedWindowIndices::beyond_window_error_id();
        let window_start = 5000;
        // The minimum lies in the window, an index does not.
        let mut indices = [window_start + 10; NUM_TRIALS as usize];
        indices[7] = window_start + u128::from(WINDOW_SIZE) - 1;
        assert_accepts(&[record_with_indices(indices)], window_start);
        indices[7] += 1;
        let records = [record_with_indices(indices)];
        let tokens = SortedWindowIndices::divined_tokens(&records, window_start);
        assert_rejects_with_tokens(&records, window_start, tokens, error_id);

        // The minimum lies beyond the window.
        let records = [record_with_indices(
            [window_start + u128::from(WINDOW_SIZE); NUM_TRIALS as usize],
        )];
        let tokens = SortedWindowIndices::divined_tokens(&records, window_start);
        assert_rejects_with_tokens(&records, window_start, tokens, error_id);

        // The minimum lies below the window, an index beyond it. Such an
        // index set is not one the mutator set makes, so it is built raw.
        let mut distances = [0; NUM_TRIALS as usize];
        distances[3] = WINDOW_SIZE + 10;
        let records = [RemovalRecord {
            absolute_indices: AbsoluteIndexSet::new_raw(window_start - 10, distances),
            target_chunks: ChunkDictionary::default(),
        }];
        let tokens = SortedWindowIndices::divined_tokens(&records, window_start);
        assert_rejects_with_tokens(
            &records,
            window_start,
            tokens,
            SortedWindowIndices::error_id(),
        );
    }

    #[test]
    fn tampered_tokens_are_rejected() {
        let error_id = SortedWindowIndices::error_id();
        let mut rng = StdRng::seed_from_u64(2);
        let window_start = 1 << 50;
        let records = random_records_around(&mut rng, 3, window_start);
        let honest = SortedWindowIndices::divined_tokens(&records, window_start);
        let length = honest[0].value() as usize;
        assert!(length >= 2, "the fixture must have indices in the window");
        let sorted = SortedWindowIndices::sorted_window_indices(&records, window_start);
        let positions = &honest[1 + length..];
        assert_eq!(length, positions.len());

        // One entry too many, and one too few.
        for delta in [1_i64, -1] {
            let mut tokens = honest.clone();
            tokens[0] = bfe!((length as i64 + delta) as u64);
            if delta > 0 {
                tokens.insert(1 + length, bfe!(WINDOW_SIZE - 1));
            } else {
                tokens.remove(length);
            }
            assert_rejects_with_tokens(&records, window_start, tokens, error_id);
        }

        // An entry out of order, and one beyond the window.
        if let Some(at) = (1..length).find(|&at| sorted[at - 1] < sorted[at]) {
            let mut tokens = honest.clone();
            tokens.swap(at, 1 + at);
            assert_rejects_with_tokens(&records, window_start, tokens, error_id);
        }
        let mut tokens = honest.clone();
        tokens[length] = bfe!(WINDOW_SIZE);
        assert_rejects_with_tokens(&records, window_start, tokens, error_id);

        // A position out of range.
        let mut tokens = honest.clone();
        tokens[1 + length] = bfe!(length as u64);
        assert_rejects_with_tokens(&records, window_start, tokens, error_id);

        // A position holding another index.
        let first_position = positions[0].value() as usize;
        if let Some(other) = (0..length).find(|&other| sorted[other] != sorted[first_position]) {
            let mut tokens = honest.clone();
            tokens[1 + length] = bfe!(other as u64);
            assert_rejects_with_tokens(&records, window_start, tokens, error_id);
        }

        // A position pointed at twice: the second index must then be the
        // same, so a duplicate index is needed.
        let mut records = records;
        let mut indices = records[0].absolute_indices.to_array();
        indices[1] = indices[0];
        records[0].absolute_indices = AbsoluteIndexSet::new(indices);
        let honest = SortedWindowIndices::divined_tokens(&records, window_start);
        let length = honest[0].value() as usize;
        let positions = honest[1 + length..].to_vec();
        if indices[0] >= window_start {
            assert_eq!(positions[0].value() + 1, positions[1].value());
            let mut tokens = honest.clone();
            tokens[1 + length + 1] = positions[0];
            assert_rejects_with_tokens(&records, window_start, tokens, error_id);
        }
        assert_accepts(&records, window_start);
    }

    #[test]
    fn records_below_the_window_contribute_nothing() {
        let window_start = 1 << 60;
        let records = [
            record_with_indices([window_start - 1; NUM_TRIALS as usize]),
            record_with_indices(core::array::from_fn(|i| window_start - 100 + i as u128)),
            record_with_indices([0; NUM_TRIALS as usize]),
        ];
        assert!(SortedWindowIndices::sorted_window_indices(&records, window_start).is_empty());
        assert_eq!(
            vec![bfe!(0)],
            SortedWindowIndices::divined_tokens(&records, window_start)
        );
        assert_accepts(&records, window_start);
    }

    #[test]
    fn fixture_records_are_accepted() {
        let mut rng = StdRng::seed_from_u64(3);
        for (num_records, aocl_size) in [(1, 1), (2, 8), (3, 1 << 20), (4, 1 << 50)] {
            let state =
                SortedWindowIndices.honest_state_of_fixture(&mut rng, num_records, aocl_size);
            test_rust_equivalence_given_execution_state(
                &ShadowedProcedure::new(SortedWindowIndices),
                state.into(),
            );
        }
    }
}
