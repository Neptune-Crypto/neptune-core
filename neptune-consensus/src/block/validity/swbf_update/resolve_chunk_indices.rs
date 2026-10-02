use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::shared::CHUNK_SIZE;
use neptune_mutator_set::shared::NUM_TRIALS;
use neptune_mutator_set::shared::WINDOW_SIZE;
use tasm_lib::arithmetic::u128::lt::Lt as U128Lt;
use tasm_lib::arithmetic::u128::shift_left_static::ShiftLeftStatic;
use tasm_lib::arithmetic::u128::sub::Sub as U128Sub;
use tasm_lib::field;
use tasm_lib::list::new::New;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::block::block_validation_error::BlockValidationRule;

/// Resolves every absolute index of every removal record that lies in the
/// inactive part of the sliding-window Bloom filter to its chunk, and
/// checks that the chunks are exactly those such indices need.
///
/// Two window starts are given: the one of the true mutator set, below
/// which every index must have its chunk, as the archival validity check
/// demands; and the one of the inactive SWBF the witness describes, below
/// which the indices must use every chunk, so that the witness holds no
/// chunk nothing needs. For an honest witness the two agree.
///
/// The prover supplies, for each index below either window start, the
/// position of its chunk in the list of chunk indices, in record order and
/// index order.
///
/// ```text
/// BEFORE: _ *removal_records *chunk_indices [swbfi_leaf_count_estimate: u64] [swbfi_leaf_count: u64]
/// AFTER:  _
/// ```
///
/// Crashes if an index below either window start has no chunk at the
/// divined position, or if a chunk is used by no index below the estimate's
/// window start.
#[derive(Debug, Copy, Clone)]
pub(super) struct ResolveChunkIndices;

impl ResolveChunkIndices {
    const LOG2_CHUNK_SIZE: u8 = CHUNK_SIZE.ilog2() as u8;

    fn no_chunk_error_id() -> i128 {
        BlockValidationRule::RemovalRecordsValidity.error_id()
    }

    fn unused_chunk_error_id() -> i128 {
        BlockValidationRule::RemovalRecordsUnpackFailure.error_id()
    }

    /// The first absolute index of the active window for this many leafs in
    /// the inactive SWBF.
    fn window_start(swbfi_leaf_count: u64) -> u128 {
        u128::from(swbfi_leaf_count) << Self::LOG2_CHUNK_SIZE
    }

    /// The distinct chunk indices of the indices below the window start,
    /// ascending: the chunks an honest witness carries.
    pub(crate) fn chunk_indices_below(
        removal_records: &[RemovalRecord],
        swbfi_leaf_count: u64,
    ) -> Vec<u64> {
        let window_start = Self::window_start(swbfi_leaf_count);
        let mut chunk_indices = removal_records
            .iter()
            .flat_map(|record| record.absolute_indices.to_array())
            .filter(|index| *index < window_start)
            .map(|index| (index >> Self::LOG2_CHUNK_SIZE) as u64)
            .collect::<Vec<_>>();
        chunk_indices.sort_unstable();
        chunk_indices.dedup();
        chunk_indices
    }

    /// The tokens the prover supplies: for each index below either window
    /// start, the position of its chunk among the chunk indices. An index
    /// whose chunk is missing gets the position where the chunk would be,
    /// which the snippet then rejects.
    pub(crate) fn divined_tokens(
        removal_records: &[RemovalRecord],
        chunk_indices: &[u64],
        swbfi_leaf_count_estimate: u64,
        swbfi_leaf_count: u64,
    ) -> Vec<BFieldElement> {
        let resolve_start =
            Self::window_start(swbfi_leaf_count_estimate).max(Self::window_start(swbfi_leaf_count));
        removal_records
            .iter()
            .flat_map(|record| record.absolute_indices.to_array())
            .filter(|index| *index < resolve_start)
            .map(|index| {
                let chunk_index = (index >> Self::LOG2_CHUNK_SIZE) as u64;
                let position = chunk_indices
                    .binary_search(&chunk_index)
                    .unwrap_or_else(|insertion_point| insertion_point);
                bfe!(position as u64)
            })
            .collect()
    }
}

impl BasicSnippet for ResolveChunkIndices {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*removal_records".to_string()),
            (
                DataType::List(Box::new(DataType::U64)),
                "*chunk_indices".to_string(),
            ),
            (DataType::U64, "swbfi_leaf_count_estimate".to_string()),
            (DataType::U64, "swbfi_leaf_count".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_resolve_chunk_indices".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_list = library.import(Box::new(New));
        let u128_lt = library.import(Box::new(U128Lt));
        let u128_sub = library.import(Box::new(U128Sub));
        let to_window_start =
            library.import(Box::new(ShiftLeftStatic::<{ Self::LOG2_CHUNK_SIZE }>));

        let entrypoint = self.entrypoint();
        let records_loop = format!("{entrypoint}_records_loop");
        let indices_loop = format!("{entrypoint}_indices_loop");
        let resolve = format!("{entrypoint}_resolve");
        let count_use = format!("{entrypoint}_count_use");
        let every_chunk_used = format!("{entrypoint}_every_chunk_used");
        let mode_below = format!("{entrypoint}_mode_below");
        let mode_not_below = format!("{entrypoint}_mode_not_below");
        let raise_resolve_start = format!("{entrypoint}_raise_resolve_start");

        // The context, in memory: the chunk indices, their number, the use
        // flags of the chunks and a spare word; the two window
        // starts; and, per record, how its indices relate to each window
        // start and the chunk index and offset of its minimum.
        let chunk_indices_offset = 0;
        let num_chunks_offset = 1;
        let uses_offset = 2;
        let resolve_start_offset = 4;
        let use_start_offset = 8;
        let resolve_mode_offset = 12;
        let use_mode_offset = 14;
        let base_chunk_offset = 16;
        let base_offset_offset = 18;

        let chunk_size = CHUNK_SIZE;
        let no_chunk = Self::no_chunk_error_id();

        // Whether an index of the record, given by its distance to the
        // record's minimum, lies below a window start: the record's mode
        // for that window start says all do, none do, or those with a
        // distance below a bound do.
        // BEFORE: _ ... distance
        // AFTER:  _ ... distance is_below
        let is_below = |mode_offset: usize, context_depth: usize| {
            triton_asm!(
                dup {context_depth} addi {mode_offset} read_mem 1 pop 1
                dup 1 lt
                // _ ... distance (distance < bound)

                dup {context_depth + 1} addi {mode_offset + 1} read_mem 1 pop 1
                add
                // _ ... distance is_below
            )
        };

        // The record's mode for a window start, from the window start and
        // the record's minimum. Any of the record's indices is at most
        // the window size beyond the minimum.
        // BEFORE: _ *context *record_si num_records i *minimum
        // AFTER:  _ *context *record_si num_records i *minimum bound all
        let record_mode = |window_start_offset: usize| {
            triton_asm!(
                dup 0 addi 3 read_mem 4 pop 1
                // _ ... *minimum [minimum]

                dup 8 addi {window_start_offset + 3} read_mem 4 pop 1
                // _ ... *minimum [minimum] [window_start]

                dup 3 dup 3 dup 3 dup 3
                dup 11 dup 11 dup 11 dup 11
                call {u128_lt}
                // _ ... *minimum [minimum] [window_start] (minimum < window_start)

                dup 0 skiz call {mode_below}
                push 0 eq skiz call {mode_not_below}
                // _ ... *minimum bound all
            )
        };

        triton_asm!(
            {entrypoint}:
                // _ *removal_records *chunk_indices [estimate] [leaf_count]
                call {new_list}
                call {new_list}
                // _ *removal_records *chunk_indices [estimate] [leaf_count] *uses *context

                place 7
                // _ *context *removal_records *chunk_indices [estimate] [leaf_count] *uses

                push 0 swap 1 dup 6 read_mem 1 pop 1 dup 7
                // _ *context *removal_records *chunk_indices [estimate] [leaf_count] 0 *uses num_chunks *chunk_indices

                dup 10 addi {chunk_indices_offset} write_mem 4 pop 1
                // _ *context *removal_records *chunk_indices [estimate] [leaf_count]

                push 0 push 0 pick 3 pick 3 call {to_window_start}
                // _ *context *removal_records *chunk_indices [estimate] [leaf_count_window_start]

                dup 8 addi {resolve_start_offset} write_mem 4 pop 1
                // _ *context *removal_records *chunk_indices [estimate]

                push 0 push 0 pick 3 pick 3 call {to_window_start}
                // _ *context *removal_records *chunk_indices [estimate_window_start]

                dup 6 addi {use_start_offset} write_mem 4 pop 1
                // _ *context *removal_records *chunk_indices

                // Indices below the larger of the two window starts must
                // resolve.
                dup 2 addi {use_start_offset + 3} read_mem 4 pop 1
                dup 6 addi {resolve_start_offset + 3} read_mem 4 pop 1
                call {u128_lt}
                // _ *context *removal_records *chunk_indices (leaf_count_window_start < estimate_window_start)

                skiz call {raise_resolve_start}
                pop 1
                // _ *context *removal_records

                read_mem 1 addi 2 place 1 push 0
                // _ *context *record[0]_si num_records 0

                call {records_loop}
                pop 3
                // _ *context

                dup 0 addi {num_chunks_offset} read_mem 1 pop 1
                swap 1 addi {uses_offset} read_mem 1 pop 1
                addi 1 push 0
                // _ num_chunks *uses[0] 0

                call {every_chunk_used}
                pop 3
                // _

                return

            // INVARIANT: _ num_chunks *uses[i] i
            {every_chunk_used}:
                dup 2 dup 1 eq skiz return
                pick 1 read_mem 1 addi 2 place 2
                // _ num_chunks *uses[i + 1] i used

                assert error_id {Self::unused_chunk_error_id()}
                addi 1
                recurse

            // BEFORE: _ *context *removal_records *chunk_indices
            // AFTER:  _ *context *removal_records *chunk_indices
            {raise_resolve_start}:
                dup 2 addi {use_start_offset + 3} read_mem 4 pop 1
                dup 6 addi {resolve_start_offset} write_mem 4 pop 1
                return

            // INVARIANT: _ *context *record[i]_si num_records i
            {records_loop}:
                dup 1 dup 1 eq skiz return
                // _ *context *record[i]_si num_records i

                dup 2 addi 1
                {&field!(RemovalRecord::absolute_indices)}
                {&field!(AbsoluteIndexSet::minimum)}
                // _ *context *record[i]_si num_records i *minimum

                {&record_mode(resolve_start_offset)}
                swap 1 dup 6 addi {resolve_mode_offset} write_mem 2 pop 1
                {&record_mode(use_start_offset)}
                swap 1 dup 6 addi {use_mode_offset} write_mem 2 pop 1
                // _ *context *record[i]_si num_records i *minimum

                // The chunk index of the minimum and the minimum's offset
                // in its chunk. Only meaningful for a minimum below a window
                // start, which then lies far below 2^76.
                dup 0 addi 3 read_mem 4 pop 1
                // _ ... *minimum m3 m2 m1 m0

                push {chunk_size} swap 1 div_mod
                // _ ... *minimum m3 m2 m1 q0 r0

                pick 2 push {chunk_size} swap 1 div_mod
                // _ ... *minimum m3 m2 q0 r0 q1 r1

                push {1_u64 << (32 - Self::LOG2_CHUNK_SIZE)} mul
                pick 3 add
                // _ ... *minimum m3 m2 r0 q1 base_chunk_lo

                pick 3 push {chunk_size} swap 1 div_mod swap 1 pop 1
                push {1_u64 << (32 - Self::LOG2_CHUNK_SIZE)} mul
                pick 2 add
                // _ ... *minimum m3 r0 base_chunk_lo base_chunk_hi

                swap 1
                dup 8 addi {base_chunk_offset} write_mem 3 pop 1
                pop 1
                // _ *context *record[i]_si num_records i *minimum

                pop 1
                dup 2 addi 1
                {&field!(RemovalRecord::absolute_indices)}
                {&field!(AbsoluteIndexSet::distances)}
                push 0
                // _ *context *record[i]_si num_records i *distance[0] 0

                call {indices_loop}
                pop 2
                // _ *context *record[i]_si num_records i

                pick 2 read_mem 1
                // _ *context num_records i record_size (*record[i]_si - 1)

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1

                addi 2 add place 2 addi 1
                // _ *context *record[i + 1]_si num_records (i + 1)

                recurse

            // Computes the bound and flag of a record whose minimum lies
            // below the window start: all of its indices do if the window
            // start is at least a window beyond the minimum.
            // BEFORE: _ ... *minimum [minimum] [window_start] 1
            // AFTER:  _ ... *minimum bound all 1
            {mode_below}:
                pop 1
                call {u128_sub}
                // _ ... *minimum [window_start - minimum]

                place 3
                // _ ... *minimum d0 d3 d2 d1

                add add push 0 eq push 0 eq
                // _ ... *minimum d0 (higher_limbs != 0)

                dup 1 push {WINDOW_SIZE} swap 1 lt push 0 eq
                add push 0 eq push 0 eq
                // _ ... *minimum d0 all

                dup 0 push -1 mul addi 1 pick 2 mul
                // _ ... *minimum all bound

                swap 1 push 1
                // _ ... *minimum bound all 1

                return

            // A record whose minimum is not below the window start has no
            // index below it.
            // BEFORE: _ ... *minimum [minimum] [window_start]
            // AFTER:  _ ... *minimum 0 0
            {mode_not_below}:
                pop 5 pop 3 push 0 push 0
                return

            // INVARIANT: _ *context *record_si num_records i *distance[k] k
            {indices_loop}:
                dup 0 push {NUM_TRIALS} eq skiz return
                // _ *context *record_si num_records i *distance[k] k

                dup 1 read_mem 1 pop 1
                // _ *context *record_si num_records i *distance[k] k distance

                {&is_below(resolve_mode_offset, 6)}
                skiz call {resolve}
                pop 1
                // _ *context *record_si num_records i *distance[k] k

                pick 1 addi 1 place 1 addi 1
                // _ *context *record_si num_records i *distance[k + 1] (k + 1)

                recurse

            // Resolves the index to its chunk at the divined position, and
            // counts the chunk's use if the index lies below the window
            // start of the estimate.
            // BEFORE: _ *context *record_si num_records i *distance[k] k distance
            // AFTER:  _ *context *record_si num_records i *distance[k] k distance
            {resolve}:
                dup 0 push {chunk_size} swap 1 div_mod
                // _ ... distance q r

                dup 8 addi {base_offset_offset} read_mem 1 pop 1 add
                push {chunk_size} swap 1 div_mod pop 1
                add
                // _ ... distance chunks_past_base

                dup 7 addi {base_chunk_offset + 1} read_mem 2 pop 1
                pick 2 add split place 2 add swap 1
                // _ ... distance [chunk_index]

                divine 1
                // _ ... distance [chunk_index] position

                dup 9 addi {num_chunks_offset} read_mem 1 pop 1
                dup 1 lt assert error_id {no_chunk}
                // _ ... distance [chunk_index] position

                dup 9 addi {chunk_indices_offset} read_mem 1 pop 1
                dup 1 push 2 mul add addi 2 read_mem 2 pop 1
                // _ ... distance [chunk_index] position [listed_chunk_index]

                pick 3 eq
                place 2 pick 3 eq
                // _ ... distance lo_agree position hi_agree

                swap 1 place 2 mul assert error_id {no_chunk}
                // _ ... distance position

                dup 1
                {&is_below(use_mode_offset, 8)}
                place 1 pop 1
                // _ ... distance position is_below_use_start

                skiz call {count_use}
                pop 1
                // _ ... distance

                return

            // Marks the chunk at the position used.
            // BEFORE: _ ... distance position
            // AFTER:  _ ... distance position
            {count_use}:
                dup 7 addi {uses_offset} read_mem 1 pop 1
                dup 1 add addi 1
                // _ ... distance position *uses[position]

                push 1 swap 1 write_mem 1 pop 1
                // _ ... distance position

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

    use super::super::chunk_witness::tests::packed_entries;
    use super::super::chunk_witness::tests::random_msa_and_records;
    use super::super::chunk_witness::tests::PackedEntry;
    use super::*;

    const RECORDS_POINTER: BFieldElement = BFieldElement::new(1 << 20);
    const CHUNK_INDICES_POINTER: BFieldElement = BFieldElement::new(1 << 21);

    fn chunk_indices_below(removal_records: &[RemovalRecord], swbfi_leaf_count: u64) -> Vec<u64> {
        ResolveChunkIndices::chunk_indices_below(removal_records, swbfi_leaf_count)
    }

    /// The leaf count estimate of the packed list.
    fn estimate_of(packed: &[RemovalRecord]) -> u64 {
        packed_entries(packed)
            .unwrap()
            .into_iter()
            .filter_map(|entry| match entry {
                PackedEntry::Tree { height, .. } => Some(1_u64 << height),
                PackedEntry::ChunkOnly => None,
            })
            .sum()
    }

    /// A record's mode for a window start, as the snippet computes it: the
    /// bound on distances, and whether all indices lie below.
    fn record_mode(minimum: u128, window_start: u128) -> (u32, u32) {
        if minimum >= window_start {
            return (0, 0);
        }
        let delta = window_start - minimum;
        let all = delta >= u128::from(WINDOW_SIZE);
        let bound = if all { 0 } else { delta as u32 };
        (bound, u32::from(all))
    }

    /// The chunk index and in-chunk offset of the minimum, as the snippet
    /// computes them from the low limbs.
    fn base_of(minimum: u128) -> (u64, u32) {
        let limbs = minimum.encode();
        let m: Vec<u64> = limbs.iter().map(|limb| limb.value()).collect();
        let chunk_size = u64::from(CHUNK_SIZE);
        let shift = 32 - ResolveChunkIndices::LOG2_CHUNK_SIZE;
        let lo = (m[0] / chunk_size + (m[1] % chunk_size) * (1 << shift)) as u32;
        let hi = (m[1] / chunk_size + (m[2] % chunk_size) * (1 << shift)) as u32;
        (
            (u64::from(hi) << 32) | u64::from(lo),
            (m[0] % chunk_size) as u32,
        )
    }

    impl Procedure for ResolveChunkIndices {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
            nondeterminism: &NonDeterminism,
            _public_input: &[BFieldElement],
            _sponge: &mut Option<Tip5>,
        ) -> Result<Vec<BFieldElement>, RustShadowError> {
            let no_chunk = || RustShadowError::AssertionError(Self::no_chunk_error_id());
            let pop_u64 = |stack: &mut Vec<BFieldElement>| {
                let lo: u32 = stack.pop().unwrap().try_into().unwrap();
                let hi: u32 = stack.pop().unwrap().try_into().unwrap();
                (u64::from(hi) << 32) | u64::from(lo)
            };
            let leaf_count = pop_u64(stack);
            let estimate = pop_u64(stack);
            let chunk_indices_pointer = stack.pop().unwrap();
            let records_pointer = stack.pop().unwrap();
            let removal_records =
                *Vec::<RemovalRecord>::decode_from_memory(memory, records_pointer).unwrap();
            let chunk_indices =
                *Vec::<u64>::decode_from_memory(memory, chunk_indices_pointer).unwrap();

            let uses = dynamic_allocator(memory);
            let context = dynamic_allocator(memory);
            memory.insert(uses, bfe!(0));
            let use_start = Self::window_start(estimate);
            let resolve_start = use_start.max(Self::window_start(leaf_count));
            let write = |memory: &mut HashMap<_, _>, offset: u64, words: Vec<BFieldElement>| {
                for (i, word) in words.into_iter().enumerate() {
                    memory.insert(context + bfe!(offset + i as u64), word);
                }
            };
            write(
                memory,
                0,
                vec![
                    chunk_indices_pointer,
                    bfe!(chunk_indices.len() as u64),
                    uses,
                    bfe!(0),
                ],
            );
            write(memory, 4, resolve_start.encode());
            write(memory, 8, use_start.encode());

            let mut tokens: VecDeque<_> = nondeterminism.individual_tokens.clone().into();
            for record in &removal_records {
                let minimum = record.absolute_indices.minimum();
                let (resolve_bound, resolve_all) = record_mode(minimum, resolve_start);
                let (use_bound, use_all) = record_mode(minimum, use_start);
                let (base_chunk, base_offset) = base_of(minimum);
                write(
                    memory,
                    12,
                    vec![
                        bfe!(resolve_bound),
                        bfe!(resolve_all),
                        bfe!(use_bound),
                        bfe!(use_all),
                    ],
                );
                write(
                    memory,
                    16,
                    [base_chunk.encode(), vec![bfe!(base_offset)]].concat(),
                );
                for distance in record.absolute_indices.distances() {
                    let is_below = |bound: u32, all: u32| all == 1 || distance < bound;
                    if !is_below(resolve_bound, resolve_all) {
                        continue;
                    }
                    let chunks_past_base =
                        distance / CHUNK_SIZE + (distance % CHUNK_SIZE + base_offset) / CHUNK_SIZE;
                    let chunk_index = base_chunk + u64::from(chunks_past_base);
                    let position = tokens.pop_front().unwrap().value() as usize;
                    if position >= chunk_indices.len() || chunk_indices[position] != chunk_index {
                        return Err(no_chunk());
                    }
                    if is_below(use_bound, use_all) {
                        memory.insert(uses + bfe!(position as u64 + 1), bfe!(1));
                    }
                }
            }
            for position in 0..chunk_indices.len() {
                let flag = uses + bfe!(position as u64 + 1);
                if memory.get(&flag).copied().unwrap_or_default() != bfe!(1) {
                    return Err(RustShadowError::AssertionError(
                        Self::unused_chunk_error_id(),
                    ));
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
            let mut states = vec![self.initial_state(&[], &[], 0, 0, vec![])];
            for (num_records, aocl_size) in [(1, 1), (1, 9), (2, 17), (3, 1 << 12), (5, 1 << 45)] {
                let msa_and_records = random_msa_and_records(&mut rng, num_records, aocl_size);
                states.push(self.honest_initial_state(&msa_and_records));
            }
            states
        }
    }

    impl ResolveChunkIndices {
        fn honest_initial_state(&self, msa_and_records: &MsaAndRecords) -> ProcedureInitialState {
            let packed = RemovalRecordList::pack(msa_and_records.unpacked_removal_records(), true);
            let leaf_count = msa_and_records
                .mutator_set_accumulator
                .swbf_inactive
                .num_leafs();
            let estimate = estimate_of(&packed);
            let chunk_indices = chunk_indices_below(&packed, leaf_count);
            let tokens = Self::divined_tokens(&packed, &chunk_indices, estimate, leaf_count);
            self.initial_state(&packed, &chunk_indices, estimate, leaf_count, tokens)
        }

        fn initial_state(
            &self,
            packed_records: &[RemovalRecord],
            chunk_indices: &[u64],
            estimate: u64,
            leaf_count: u64,
            tokens: Vec<BFieldElement>,
        ) -> ProcedureInitialState {
            let mut memory = HashMap::new();
            encode_to_memory(&mut memory, RECORDS_POINTER, &packed_records.to_vec());
            encode_to_memory(&mut memory, CHUNK_INDICES_POINTER, &chunk_indices.to_vec());
            let stack = [
                self.init_stack_for_isolated_run(),
                vec![RECORDS_POINTER, CHUNK_INDICES_POINTER],
                estimate.encode().into_iter().rev().collect(),
                leaf_count.encode().into_iter().rev().collect(),
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

    /// An honest fixture whose records have indices in the inactive part.
    fn fixture_with_chunks(seed: u64) -> (Vec<RemovalRecord>, Vec<u64>, u64, u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let msa_and_records = random_msa_and_records(&mut rng, 4, 1 << 24);
        let packed = RemovalRecordList::pack(msa_and_records.unpacked_removal_records(), true);
        let leaf_count = msa_and_records
            .mutator_set_accumulator
            .swbf_inactive
            .num_leafs();
        let estimate = estimate_of(&packed);
        let chunk_indices = chunk_indices_below(&packed, leaf_count);
        assert!(!chunk_indices.is_empty(), "fixture must have chunks");
        (packed, chunk_indices, estimate, leaf_count)
    }

    fn assert_accepts(
        packed: &[RemovalRecord],
        chunk_indices: &[u64],
        estimate: u64,
        leaf_count: u64,
    ) {
        let tokens =
            ResolveChunkIndices::divined_tokens(packed, chunk_indices, estimate, leaf_count);
        test_rust_equivalence_given_execution_state(
            &ShadowedProcedure::new(ResolveChunkIndices),
            ResolveChunkIndices
                .initial_state(packed, chunk_indices, estimate, leaf_count, tokens)
                .into(),
        );
    }

    fn assert_rejects(
        packed: &[RemovalRecord],
        chunk_indices: &[u64],
        estimate: u64,
        leaf_count: u64,
        error_id: i128,
    ) {
        let tokens =
            ResolveChunkIndices::divined_tokens(packed, chunk_indices, estimate, leaf_count);
        test_assertion_failure(
            &ShadowedProcedure::new(ResolveChunkIndices),
            ResolveChunkIndices
                .initial_state(packed, chunk_indices, estimate, leaf_count, tokens)
                .into(),
            &[error_id],
        );
    }

    /// A record with exactly these indices and no chunks.
    fn record_with(indices: [u128; NUM_TRIALS as usize]) -> RemovalRecord {
        RemovalRecord {
            absolute_indices: AbsoluteIndexSet::new(indices),
            target_chunks: ChunkDictionary::default(),
        }
    }

    /// Indices around a chunk boundary: the last of a chunk, the first of
    /// the next, and the same a chunk further, with the minimum a chunk
    /// below.
    fn indices_around(boundary: u128) -> [u128; NUM_TRIALS as usize] {
        let chunk_size = u128::from(CHUNK_SIZE);
        let mut indices = [boundary - 1; NUM_TRIALS as usize];
        indices[1] = boundary;
        indices[2] = boundary + chunk_size - 1;
        indices[3] = boundary + chunk_size;
        indices[4] = boundary - chunk_size;
        for (i, index) in indices.iter_mut().enumerate().skip(5) {
            *index = boundary - chunk_size + (i as u128 * 97) % (3 * chunk_size);
        }
        indices
    }

    /// Indices at chunk boundaries, at limb edges of the index and of the
    /// chunk index too, resolve to their own chunks: the chunks the host
    /// derives by shifting are accepted, and no one of them can go.
    #[test]
    fn indices_at_chunk_boundaries_resolve_to_their_own_chunks() {
        let chunk_size = u128::from(CHUNK_SIZE);
        for leaf_count in [1_u64 << 28, 1 << 58] {
            let window_start = ResolveChunkIndices::window_start(leaf_count);
            for boundary in [
                3 * chunk_size,
                window_start - 3 * chunk_size,
                1 << 32,
                1 << 44,
                1 << 64,
            ] {
                if boundary + 2 * chunk_size > window_start {
                    continue;
                }
                let packed = vec![record_with(indices_around(boundary))];
                let chunk_indices = chunk_indices_below(&packed, leaf_count);
                assert!(chunk_indices.len() >= 3, "boundary {boundary}");
                assert_accepts(&packed, &chunk_indices, leaf_count, leaf_count);
                for position in 0..chunk_indices.len() {
                    let mut fewer = chunk_indices.clone();
                    fewer.remove(position);
                    assert_rejects(
                        &packed,
                        &fewer,
                        leaf_count,
                        leaf_count,
                        ResolveChunkIndices::no_chunk_error_id(),
                    );
                }
            }
        }
    }

    /// The index just below the window start needs the last chunk; the one
    /// at the window start needs none, and its chunk is superfluous.
    #[test]
    fn indices_at_the_window_start_need_chunks_below_it_only() {
        let chunk_size = u128::from(CHUNK_SIZE);
        for leaf_count in [2_u64, 1 << 28, 1 << 58] {
            let window_start = ResolveChunkIndices::window_start(leaf_count);
            let mut indices = [window_start - 1; NUM_TRIALS as usize];
            indices[1] = window_start;
            indices[2] = window_start + 1;
            indices[3] = window_start - chunk_size;
            let packed = vec![record_with(indices)];
            let chunk_indices = chunk_indices_below(&packed, leaf_count);
            assert_eq!(vec![leaf_count - 1], chunk_indices);
            assert_accepts(&packed, &chunk_indices, leaf_count, leaf_count);

            let mut with_the_windows_chunk = chunk_indices.clone();
            with_the_windows_chunk.push(leaf_count);
            assert_rejects(
                &packed,
                &with_the_windows_chunk,
                leaf_count,
                leaf_count,
                ResolveChunkIndices::unused_chunk_error_id(),
            );
            assert_rejects(
                &packed,
                &[],
                leaf_count,
                leaf_count,
                ResolveChunkIndices::no_chunk_error_id(),
            );
        }
    }

    #[test]
    fn index_resolved_to_a_neighbouring_chunk_is_rejected() {
        let (packed, chunk_indices, estimate, leaf_count) = fixture_with_chunks(7);
        assert!(chunk_indices.len() > 1);
        let honest =
            ResolveChunkIndices::divined_tokens(&packed, &chunk_indices, estimate, leaf_count);
        let mut checked = 0;
        for token in [0, honest.len() / 2, honest.len() - 1] {
            let position = honest[token].value();
            for other in [position + 1, position.wrapping_sub(1)] {
                if other >= chunk_indices.len() as u64 {
                    continue;
                }
                let mut tokens = honest.clone();
                tokens[token] = bfe!(other);
                test_assertion_failure(
                    &ShadowedProcedure::new(ResolveChunkIndices),
                    ResolveChunkIndices
                        .initial_state(&packed, &chunk_indices, estimate, leaf_count, tokens)
                        .into(),
                    &[ResolveChunkIndices::no_chunk_error_id()],
                );
                checked += 1;
            }
        }
        assert!(checked > 0);
    }

    #[test]
    fn rust_shadow_agrees_with_tasm() {
        ShadowedProcedure::new(ResolveChunkIndices).test();
    }

    #[test]
    fn honest_lists_are_accepted() {
        let mut rng = StdRng::seed_from_u64(0);
        for (num_records, aocl_size) in [(1, 1), (1, 100), (2, 1 << 10), (4, 1 << 20), (6, 1 << 50)]
        {
            let msa_and_records = random_msa_and_records(&mut rng, num_records, aocl_size);
            test_rust_equivalence_given_execution_state(
                &ShadowedProcedure::new(ResolveChunkIndices),
                ResolveChunkIndices
                    .honest_initial_state(&msa_and_records)
                    .into(),
            );
        }
    }

    #[test]
    fn missing_chunk_is_rejected() {
        let (packed, chunk_indices, estimate, leaf_count) = fixture_with_chunks(1);
        for position in [0, chunk_indices.len() / 2, chunk_indices.len() - 1] {
            let mut fewer = chunk_indices.clone();
            fewer.remove(position);
            assert_rejects(
                &packed,
                &fewer,
                estimate,
                leaf_count,
                ResolveChunkIndices::no_chunk_error_id(),
            );
        }
        assert_rejects(
            &packed,
            &[],
            estimate,
            leaf_count,
            ResolveChunkIndices::no_chunk_error_id(),
        );
    }

    #[test]
    fn unused_chunk_is_rejected() {
        let (packed, chunk_indices, estimate, leaf_count) = fixture_with_chunks(2);
        let unused = chunk_indices.iter().max().unwrap() + 1;
        let mut more = chunk_indices.clone();
        more.push(unused);
        assert_rejects(
            &packed,
            &more,
            estimate,
            leaf_count,
            ResolveChunkIndices::unused_chunk_error_id(),
        );
    }

    #[test]
    fn chunk_index_off_by_one_is_rejected() {
        let (packed, chunk_indices, estimate, leaf_count) = fixture_with_chunks(3);
        let mut shifted = chunk_indices.clone();
        shifted[0] += 1;
        if shifted.len() > 1 && shifted[0] == shifted[1] {
            return;
        }
        assert_rejects(
            &packed,
            &shifted,
            estimate,
            leaf_count,
            ResolveChunkIndices::no_chunk_error_id(),
        );
    }

    #[test]
    fn indices_in_the_gap_between_window_starts_need_chunks_but_do_not_use_them() {
        let (packed, chunk_indices, estimate, leaf_count) = fixture_with_chunks(4);
        assert!(estimate <= leaf_count);

        // A smaller estimate: chunks beyond its window start count as unused.
        let smaller = estimate / 2;
        let used = chunk_indices_below(&packed, smaller);
        if used.len() < chunk_indices.len() {
            assert_rejects(
                &packed,
                &chunk_indices,
                smaller,
                leaf_count,
                ResolveChunkIndices::unused_chunk_error_id(),
            );
        }

        // A larger estimate: indices beyond the true window start need
        // chunks too.
        let larger = leaf_count * 2 + 1;
        let needed = chunk_indices_below(&packed, larger);
        if needed.len() > chunk_indices.len() {
            assert_rejects(
                &packed,
                &chunk_indices,
                larger,
                leaf_count,
                ResolveChunkIndices::no_chunk_error_id(),
            );
            assert_accepts(&packed, &needed, larger, leaf_count);
        }
    }

    #[test]
    fn empty_list_with_no_chunks_is_accepted() {
        for (estimate, leaf_count) in [(0, 0), (0, 1 << 40), (5, 5)] {
            assert_accepts(&[], &[], estimate, leaf_count);
        }
    }

    #[test]
    fn empty_list_with_chunks_is_rejected() {
        assert_rejects(
            &[],
            &[3],
            1 << 10,
            1 << 10,
            ResolveChunkIndices::unused_chunk_error_id(),
        );
    }

    #[test]
    fn records_entirely_in_the_active_window_need_no_chunks() {
        let mut rng = StdRng::seed_from_u64(5);
        // Few AOCL leafs: nothing is inactive yet.
        let msa_and_records = random_msa_and_records(&mut rng, 3, 8);
        let packed = RemovalRecordList::pack(msa_and_records.unpacked_removal_records(), true);
        let leaf_count = msa_and_records
            .mutator_set_accumulator
            .swbf_inactive
            .num_leafs();
        assert_eq!(0, leaf_count);
        assert_accepts(&packed, &[], 0, 0);
    }
}
